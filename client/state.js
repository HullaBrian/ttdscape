import { NONE } from './format.js';

const EV = { Alloc: 1, Free: 2, ReAlloc: 3, HeapDestroy: 5 };

// Upper bound: first index in sorted[] whose key(idx) > value.
function upperBound(order, key, value) {
  let lo = 0, hi = order.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (key[order[mid]] <= value) lo = mid + 1; else hi = mid;
  }
  return lo;
}

// Time-indexed queries over the analysis. "Event i" means: the state right after event i was applied
// (i = -1 is the state at the start of the trace).
export class TimeModel {
  constructor(data, { checkpointEvery = 8192 } = {}) {
    this.data = data;
    const { blocks, regions, spans, events } = data;
    this.eventCount = events.count;
    this.checkpointEvery = checkpointEvery;

    // Alloc / free keys with NONE mapped to -1 (before the trace) / +inf (never freed).
    const n = blocks.count;
    this.allocKey = new Float64Array(n);
    this.freeKey = new Float64Array(n);
    for (let b = 0; b < n; b++) {
      this.allocKey[b] = blocks.allocEvt[b] === NONE ? -1 : blocks.allocEvt[b];
      this.freeKey[b] = blocks.freeEvt[b] === NONE ? Infinity : blocks.freeEvt[b];
    }
    this.byAlloc = Uint32Array.from({ length: n }, (_, i) => i).sort((a, b) => this.allocKey[a] - this.allocKey[b]);
    this.checkpoints = new Map();

    // Spans grouped per region.
    this.spansByRegion = Array.from({ length: regions.count }, () => []);
    for (let s = 0; s < spans.count; s++) if (spans.region[s] < regions.count) this.spansByRegion[spans.region[s]].push(s);

    // Blocks grouped by address for "address history".
    this.blocksByAddr = new Map();
    for (let b = 0; b < n; b++) {
      const list = this.blocksByAddr.get(blocks.addr[b]);
      if (list) list.push(b); else this.blocksByAddr.set(blocks.addr[b], [b]);
    }

    this.buildCurves();
  }

  // Per-event curves: live heap bytes and committed bytes after each event (for the timeline).
  buildCurves() {
    const { events, blocks, spans } = this.data;
    const n = events.count;
    const heapDelta = new Float64Array(n + 1), commitDelta = new Float64Array(n + 1);
    let heapStart = 0, commitStart = 0;
    for (let b = 0; b < blocks.count; b++) {
      const size = blocks.size[b];
      if (blocks.allocEvt[b] === NONE) heapStart += size; else heapDelta[blocks.allocEvt[b]] += size;
      if (blocks.freeEvt[b] !== NONE) heapDelta[blocks.freeEvt[b]] -= size;
    }
    for (let s = 0; s < spans.count; s++) {
      if (spans.state[s] !== 2) continue;
      const size = spans.end[s] - spans.start[s];
      if (spans.startEvt[s] === NONE) commitStart += size; else commitDelta[spans.startEvt[s]] += size;
      if (spans.endEvt[s] !== NONE) commitDelta[spans.endEvt[s]] -= size;
    }
    this.heapLive = new Float64Array(n);
    this.committed = new Float64Array(n);
    let h = heapStart, c = commitStart;
    for (let i = 0; i < n; i++) {
      h += heapDelta[i]; c += commitDelta[i];
      this.heapLive[i] = h; this.committed[i] = c;
    }
    this.heapStart = heapStart;
    this.commitStart = commitStart;
  }

  isLive(b, i) { return this.allocKey[b] <= i && this.freeKey[b] > i; }

  // Live block ids at event i (sorted by block id).
  liveBlocksAt(i) {
    if (i < 0) return this.liveFromScratch(-1);
    const k = this.checkpointEvery;
    const c = Math.floor(i / k) * k - 1; // checkpoints at k-1, 2k-1, ...
    const base = c < 0 ? this.liveFromScratch(-1) : this.checkpoint(c);
    return this.advance(base, c, i);
  }

  liveFromScratch(i) {
    const out = [];
    const end = upperBound(this.byAlloc, this.allocKey, i);
    for (let j = 0; j < end; j++) {
      const b = this.byAlloc[j];
      if (this.freeKey[b] > i) out.push(b);
    }
    return Uint32Array.from(out).sort();
  }

  checkpoint(c) {
    let cp = this.checkpoints.get(c);
    if (cp) return cp;
    const k = this.checkpointEvery;
    const prev = c - k;
    const base = prev < 0 ? this.liveFromScratch(-1) : this.checkpoint(prev);
    cp = this.advance(base, prev, c);
    this.checkpoints.set(c, cp);
    return cp;
  }

  // live(to) from live(from): drop the freed, add blocks allocated in (from, to] still live at 'to'.
  advance(live, from, to) {
    if (to === from) return live;
    const out = [];
    for (const b of live) if (this.freeKey[b] > to) out.push(b);
    const lo = upperBound(this.byAlloc, this.allocKey, from), hi = upperBound(this.byAlloc, this.allocKey, to);
    for (let j = lo; j < hi; j++) {
      const b = this.byAlloc[j];
      if (this.freeKey[b] > to) out.push(b);
    }
    return Uint32Array.from(out).sort();
  }

  // Blocks freed in (i - window, i]: drawn as fading ghosts.
  recentlyFreed(i, window) {
    const out = [];
    const lo = upperBound(this.byAlloc, this.allocKey, -2);
    const hiAlloc = upperBound(this.byAlloc, this.allocKey, i);
    for (let j = lo; j < hiAlloc; j++) {
      const b = this.byAlloc[j];
      const f = this.freeKey[b];
      if (f <= i && f > i - window) out.push(b);
    }
    return out;
  }

  regionLive(r, i) {
    const { createEvt, releaseEvt } = this.data.regions;
    return (createEvt[r] === NONE || createEvt[r] <= i) && (releaseEvt[r] === NONE || releaseEvt[r] > i);
  }

  liveRegionsAt(i) {
    const out = [];
    for (let r = 0; r < this.data.regions.count; r++) if (this.regionLive(r, i)) out.push(r);
    return out;
  }

  spanLive(s, i) {
    const { startEvt, endEvt } = this.data.spans;
    return (startEvt[s] === NONE || startEvt[s] <= i) && (endEvt[s] === NONE || endEvt[s] > i);
  }

  spansAt(r, i) {
    return this.spansByRegion[r].filter(s => this.spanLive(s, i)).sort((a, b) => this.data.spans.start[a] - this.data.spans.start[b]);
  }

  // Innermost region containing an address at event i (regions can overlap across time only).
  regionAt(addr, i) {
    const { base, size } = this.data.regions;
    let best = NONE;
    for (let r = 0; r < this.data.regions.count; r++)
      if (addr >= base[r] && addr < base[r] + size[r] && this.regionLive(r, i) && (best === NONE || size[r] < size[best])) best = r;
    return best;
  }

  blockAt(addr, i) {
    for (const b of this.liveBlocksAt(i)) {
      const { addr: a, size } = this.data.blocks;
      if (addr >= a[b] && addr < a[b] + Math.max(1, size[b])) return b;
    }
    return NONE;
  }

  addressHistory(addr) {
    return this.blocksByAddr.get(addr) ?? [];
  }

  // Realloc chain through 'prev' links (oldest first) plus successors.
  reallocChain(b) {
    const { prev } = this.data.blocks;
    const chain = [];
    for (let x = b; x !== NONE && chain.length < 10000; x = prev[x]) chain.unshift(x);
    if (!this.successors) {
      this.successors = new Map();
      for (let y = 0; y < prev.length; y++) if (prev[y] !== NONE) this.successors.set(prev[y], y);
    }
    for (let x = this.successors.get(b); x !== undefined && chain.length < 20000; x = this.successors.get(x)) chain.push(x);
    return chain;
  }

  // Blocks still live at the end of the trace, allocated inside it, grouped by allocation site.
  leaks(stacks) {
    const { blocks } = this.data;
    const groups = new Map();
    for (let b = 0; b < blocks.count; b++) {
      if (blocks.freeEvt[b] !== NONE || blocks.allocEvt[b] === NONE) continue;
      const site = stacks.siteFrame(blocks.allocStack[b]);
      let g = groups.get(site);
      if (!g) groups.set(site, g = { site, text: stacks.siteText(blocks.allocStack[b]), blocks: [], bytes: 0 });
      g.blocks.push(b);
      g.bytes += blocks.size[b];
    }
    return [...groups.values()].sort((a, b) => b.bytes - a.bytes || b.blocks.length - a.blocks.length);
  }

  // Next/previous event index of a given kind set (Set of kind numbers) from i.
  seek(i, direction, predicate) {
    const n = this.eventCount;
    for (let j = i + direction; j >= 0 && j < n; j += direction) if (predicate(j)) return j;
    return i;
  }
}

export { EV };
