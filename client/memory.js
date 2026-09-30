// Memory objects behind addresses, and the pure parts of the memory and access views
// (features/pointers.js, memory-pane.js, access-history.js).
import { NONE } from './format.js';

const PAGE = 4096;
const LARGE_PAGES = 64; // blocks spanning more pages than this are scanned from a short list

// Which live block or region holds an address at event i. Blocks are bucketed by page over their
// whole lifetime, so a lookup checks only the blocks that ever touched that page (TimeModel.blockAt
// scans every live block).
export class AddressIndex {
  constructor(data, time) {
    this.data = data;
    this.time = time;
    const { blocks } = data;
    this.pages = new Map();
    this.large = [];
    for (let b = 0; b < blocks.count; b++) {
      const size = Math.max(1, blocks.size[b]);
      const first = Math.floor(blocks.addr[b] / PAGE), last = Math.floor((blocks.addr[b] + size - 1) / PAGE);
      if (last - first >= LARGE_PAGES) { this.large.push(b); continue; }
      for (let p = first; p <= last; p++) {
        const list = this.pages.get(p);
        if (list) list.push(b); else this.pages.set(p, [b]);
      }
    }
  }

  // The live block containing addr at event i (the smallest, if a stale record overlaps), or NONE.
  blockAt(addr, i) {
    const { addr: a, size } = this.data.blocks;
    let best = NONE;
    const check = b => {
      if (addr >= a[b] && addr < a[b] + Math.max(1, size[b]) && this.time.isLive(b, i) && (best === NONE || size[b] < size[best])) best = b;
    };
    for (const b of this.pages.get(Math.floor(addr / PAGE)) ?? []) check(b);
    for (const b of this.large) check(b);
    return best;
  }

  // { kind: 'block', b, offset } | { kind: 'region', r, offset } | null.
  objectAt(addr, i) {
    if (!(addr >= 0x10000) || !Number.isSafeInteger(addr)) return null;
    const b = this.blockAt(addr, i);
    if (b !== NONE) return { kind: 'block', b, offset: addr - this.data.blocks.addr[b] };
    const r = this.time.regionAt(addr, i);
    if (r !== NONE) return { kind: 'region', r, offset: addr - this.data.regions.base[r] };
    return null;
  }
}

const parseHex = text => {
  if (typeof text !== 'string' || !/^0x[0-9a-f]{1,13}$/i.test(text)) return null;
  return Number.parseInt(text.slice(2), 16);
};

// Candidate pointers in a call's decoded arguments (call-args.js keys): each parameter's raw value
// (for a string, where it lives) and pointee, and the return value. [{ param, which: 'v' | 'd' |
// 'ret', addr, atReturn }]. Values below 64 KiB are never pointers on Windows.
export function pointerCandidates(args) {
  const out = [];
  const add = (param, which, text, atReturn) => {
    const addr = parseHex(text);
    if (addr !== null && addr >= 0x10000) out.push({ param, which, addr, atReturn });
  };
  (args?.p ?? []).forEach((p, k) => {
    if (p.fl?.length || p.f !== undefined) return; // flags or floats
    add(k, 'v', p.v, !!p.r);
    if (p.d !== undefined && !p.dfl?.length) add(k, 'd', p.d, !!p.r);
  });
  if (args?.ret !== undefined) add(-1, 'ret', args.ret, true);
  return out;
}

export function decodeBase64(text) {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Per byte of a memory.read result: the event its recorded data belongs to (from the provenance
// ranges [offset, length, seq, evt]), or -1 when unknown.
export function byteEvents(size, ranges) {
  const out = new Int32Array(size).fill(-1);
  for (const [offset, length, , evt] of ranges ?? []) {
    for (let k = Math.max(0, offset); k < Math.min(size, offset + length); k++) out[k] = evt;
  }
  return out;
}

const printable = c => c >= 0x20 && c < 0x7f;

// Runs of at least `min` printable characters, ASCII or UTF-16LE, among known bytes:
// [{ offset, length (bytes), text, wide }], by offset.
export function findStrings(bytes, known, min = 5) {
  const out = [];
  const ok = k => !known || known[k] >= 0;
  for (let k = 0; k < bytes.length;) {
    let e = k;
    while (e < bytes.length && ok(e) && printable(bytes[e])) e++;
    if (e - k >= min) { out.push({ offset: k, length: e - k, text: String.fromCharCode(...bytes.subarray(k, e)), wide: false }); k = e; continue; }
    k = e + 1;
  }
  for (let start = 0; start < 2; start++) {
    for (let k = start; k + 1 < bytes.length;) {
      let e = k;
      while (e + 1 < bytes.length && ok(e) && ok(e + 1) && printable(bytes[e]) && bytes[e + 1] === 0) e += 2;
      const chars = (e - k) / 2;
      if (chars >= min) {
        let text = '';
        for (let x = k; x < e; x += 2) text += String.fromCharCode(bytes[x]);
        out.push({ offset: k, length: e - k, text, wide: true });
        k = e;
        continue;
      }
      k = e + 2;
    }
  }
  return out.sort((a, b) => a.offset - b.offset || b.length - a.length);
}

// Writes over time from activity.bin (analyze --activity): per block, per region (its pages, summed)
// and in total, by series bucket. heat() is the recent write rate at time T, decaying by half per
// bucket, which colours blocks and pages in "Color blocks by: Activity".
export class ActivityModel {
  constructor(cells, { buckets, eventsPerBucket }) {
    this.buckets = Math.max(1, buckets);
    this.eventsPerBucket = Math.max(1, eventsPerBucket);
    this.total = new Float64Array(this.buckets);
    this.blocks = new Map();   // block -> { bucket: Uint32Array, writes: Uint32Array }, by bucket
    this.regions = new Map();  // region -> Float64Array per bucket (page writes)
    const perBlock = new Map();
    for (let i = 0; i < cells.count; i++) {
      const bucket = Math.min(this.buckets - 1, cells.bucket[i]), w = cells.writes[i];
      this.total[bucket] += w;
      if (cells.block[i] !== NONE) {
        let list = perBlock.get(cells.block[i]);
        if (!list) perBlock.set(cells.block[i], list = []);
        list.push([bucket, w]);
      } else if (cells.region[i] !== NONE) {
        let series = this.regions.get(cells.region[i]);
        if (!series) this.regions.set(cells.region[i], series = new Float64Array(this.buckets));
        series[bucket] += w;
      }
    }
    for (const [b, list] of perBlock) {
      list.sort((x, y) => x[0] - y[0]);
      this.blocks.set(b, { bucket: Uint32Array.from(list, x => x[0]), writes: Uint32Array.from(list, x => x[1]) });
    }
  }

  bucketOf(T) { return Math.max(0, Math.min(this.buckets - 1, Math.floor(T / this.eventsPerBucket))); }

  // Writes to block b in the bucket holding T and the `span` buckets before it, halving per bucket.
  heat(b, T, span = 4) {
    const s = this.blocks.get(b);
    if (!s) return 0;
    const at = this.bucketOf(T);
    let lo = 0, hi = s.bucket.length;
    while (lo < hi) { const mid = (lo + hi) >>> 1; if (s.bucket[mid] <= at) lo = mid + 1; else hi = mid; }
    let h = 0;
    for (let k = lo - 1; k >= 0 && at - s.bucket[k] <= span; k--) h += s.writes[k] / 2 ** (at - s.bucket[k]);
    return h;
  }

  regionHeat(r, T, span = 4) {
    const s = this.regions.get(r);
    if (!s) return 0;
    const at = this.bucketOf(T);
    let h = 0;
    for (let k = 0; k <= span && at - k >= 0; k++) h += s[at - k] / 2 ** k;
    return h;
  }
}

// Writes between regions over time (flows.bin), for straight beams from the writing code's region
// to the region written. A flow spans its bucket's events: [bucket * epb, (bucket + 1) * epb).
export class FlowModel {
  constructor(flows, { buckets, eventsPerBucket }) {
    this.flows = flows;
    this.eventsPerBucket = Math.max(1, eventsPerBucket);
    this.start = new Uint32Array(Math.max(1, buckets) + 1); // first flow index of each bucket
    let i = 0;
    for (let b = 0; b <= Math.max(1, buckets); b++) {
      while (i < flows.count && flows.bucket[i] < b) i++;
      this.start[b] = i;
    }
    this.start[this.start.length - 1] = flows.count;
  }

  span(i) { const b = this.flows.bucket[i]; return [b * this.eventsPerBucket, (b + 1) * this.eventsPerBucket]; }

  // Indexes of flows whose span overlaps [lo, hi], between two regions (not within one).
  between(lo, hi) {
    const n = this.start.length - 1;
    const b0 = Math.max(0, Math.min(n, Math.floor(lo / this.eventsPerBucket))), b1 = Math.max(0, Math.min(n - 1, Math.floor(hi / this.eventsPerBucket)));
    const out = [];
    for (let i = this.start[b0]; i < this.start[b1 + 1]; i++)
      if (this.flows.from[i] !== this.flows.to[i] && this.flows.from[i] !== NONE && this.flows.to[i] !== NONE) out.push(i);
    return out;
  }
}

// Access hits grouped by who made them: [{ key, label, kinds: { w, r, m }, count, first, last,
// threads: Set }], most frequent first. label(hit) names the code (symbol or region).
export function groupAccesses(hits, label) {
  const groups = new Map();
  for (const h of hits) {
    const text = label(h);
    let g = groups.get(text);
    if (!g) groups.set(text, g = { key: text, label: text, kinds: { w: 0, r: 0, m: 0 }, count: 0, first: h.evt, last: h.evt, threads: new Set() });
    g.kinds[h.kind] = (g.kinds[h.kind] ?? 0) + 1;
    g.count++;
    g.first = Math.min(g.first, h.evt);
    g.last = Math.max(g.last, h.evt);
    g.threads.add(h.utid);
  }
  return [...groups.values()].sort((a, b) => b.count - a.count || a.first - b.first);
}
