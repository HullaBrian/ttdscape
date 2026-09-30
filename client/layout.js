// Spatial layout. Adapted from Heapscape's spatial.js: volumes are proportional to bytes and
// items are packed in address order along x, then z rows, then y floors.
import { NONE } from './format.js';

export const BYTES_PER_CUBIC_UNIT = 32;
export const MIN_BOX_SIDE = 0.9;
export const MIN_GAP_BYTES = 256;   // heap headers and alignment slack between blocks are not drawn

export function boxSide(bytes) {
  return Math.max(MIN_BOX_SIDE, Math.cbrt(Number(bytes) / BYTES_PER_CUBIC_UNIT));
}

export function gapSide(bytes) {
  return Math.cbrt(Number(bytes) / BYTES_PER_CUBIC_UNIT);
}

// Address order follows x, then z shelves, then y floors. Sizes never change to fit.
export function packBoxes(items, gap = 0.25) {
  const volume = items.reduce((sum, item) => sum + item.size.reduce((v, side) => v * (side + gap), 1), 0);
  const largest = items.reduce((max, item) => Math.max(max, item.size[0], item.size[2]), 1);
  return packInto(items, Math.max(Math.cbrt(volume) * 1.4, largest), gap);
}

// Same shelf packing with a fixed footprint width (floors grow upward as needed).
export function packInto(items, width, gap = 0.25) {
  const slots = new Map();
  let x = 0, y = 0, z = 0, rowDepth = 0, floorHeight = 0;
  const extent = [0, 0, 0];
  for (const item of items) {
    const [w, h, d] = item.size;
    if (x > 0 && x + w > width) { x = 0; z += rowDepth + gap; rowDepth = 0; }
    if (z > 0 && z + d > width) { x = 0; y += floorHeight + gap; z = 0; rowDepth = 0; floorHeight = 0; }
    slots.set(item.id, { position: [x + w / 2, y + h / 2, z + d / 2], size: [...item.size] });
    extent[0] = Math.max(extent[0], x + w);
    extent[1] = Math.max(extent[1], y + h);
    extent[2] = Math.max(extent[2], z + d);
    x += w + gap; rowDepth = Math.max(rowDepth, d); floorHeight = Math.max(floorHeight, h);
  }
  return { slots, size: extent };
}

function mergedLength(intervals) {
  intervals.sort((a, b) => a[0] - b[0]);
  let total = 0, curStart = -1, curEnd = -1;
  for (const [s, e] of intervals) {
    if (s > curEnd) { if (curEnd > curStart) total += curEnd - curStart; curStart = s; curEnd = e; }
    else curEnd = Math.max(curEnd, e);
  }
  if (curEnd > curStart) total += curEnd - curStart;
  return total;
}

// Assigns each block to the smallest region that contains it and overlaps its lifetime.
export function assignBlocks(data) {
  const { blocks, regions } = data;
  const order = Uint32Array.from({ length: regions.count }, (_, i) => i).sort((a, b) => regions.base[a] - regions.base[b]);
  const bases = Float64Array.from(order, r => regions.base[r]);
  let maxSize = 0;
  for (let r = 0; r < regions.count; r++) maxSize = Math.max(maxSize, regions.size[r]);
  const out = new Uint32Array(blocks.count).fill(NONE);
  for (let b = 0; b < blocks.count; b++) {
    const a = blocks.addr[b];
    const alloc = blocks.allocEvt[b] === NONE ? -1 : blocks.allocEvt[b];
    const free = blocks.freeEvt[b] === NONE ? Infinity : blocks.freeEvt[b];
    // Candidates: regions with base <= a (scan back while they could still reach a).
    let lo = 0, hi = bases.length;
    while (lo < hi) { const mid = (lo + hi) >>> 1; if (bases[mid] <= a) lo = mid + 1; else hi = mid; }
    let best = NONE;
    for (let j = lo - 1; j >= 0 && a - bases[j] < maxSize; j--) {
      const r = order[j];
      if (a >= regions.base[r] + regions.size[r]) continue;
      const create = regions.createEvt[r] === NONE ? -1 : regions.createEvt[r];
      const release = regions.releaseEvt[r] === NONE ? Infinity : regions.releaseEvt[r];
      if (create >= free || release <= alloc) continue;
      if (best === NONE || regions.size[r] < regions.size[best]) best = r;
    }
    out[b] = best;
  }
  return out;
}

// Region spacing presets: the gap between region boxes is 4 units plus this fraction of the median
// box side, so traces of big regions spread out as much as traces of small ones.
export const REGION_SPACING = { compact: 0, normal: 0.8, wide: 1.6 };

// Static top-level layout: every region that ever exists gets a fixed box, in address order.
export function regionLayout(data, time, { reserved = false, spacing = REGION_SPACING.normal } = {}) {
  const { regions, spans } = data;
  const items = [];
  for (let r = 0; r < regions.count; r++) {
    const committed = [];
    for (const s of time.spansByRegion[r]) if (spans.state[s] === 2) committed.push([spans.start[s], spans.end[s]]);
    const committedBytes = mergedLength(committed);
    const displayBytes = Math.max(4096, reserved ? regions.size[r] : committedBytes);
    const side = boxSide(displayBytes) * 1.3 + 1.5;
    items.push({ id: r, r, base: regions.base[r], end: regions.base[r] + regions.size[r], kind: regions.kind[r],
      committedBytes, displayBytes, size: [side, side, side], reserveOnly: committedBytes === 0 });
  }
  items.sort((a, b) => a.base - b.base || (data.regions.createEvt[a.r] >>> 0) - (data.regions.createEvt[b.r] >>> 0));
  const sides = items.map(item => item.size[0]).sort((a, b) => a - b);
  const median = sides.length ? sides[sides.length >> 1] : 0;
  const packed = packBoxes(items, 4 + spacing * median);
  const origin = [packed.size[0] / 2, 0, packed.size[2] / 2];
  const byRegion = new Array(regions.count);
  for (const item of items) {
    item.position = packed.slots.get(item.id).position.map((v, axis) => v - origin[axis]);
    item.top = item.position[1] + item.size[1] / 2;
    byRegion[item.r] = item;
  }
  return { items, byRegion, size: packed.size, gap: 4 + spacing * median };
}

// Pieces of one region at an instant: live blocks and the gaps between them, or page spans when
// the region holds no blocks. Pure function of its inputs so it can be cached / run in a worker.
export function regionPieces(region, blockIds, blocks, spanIds, spans, { reserved = false } = {}) {
  const pieces = [];
  if (blockIds.length) {
    const sorted = [...blockIds].sort((a, b) => blocks.addr[a] - blocks.addr[b]);
    const spanOrder = [...spanIds].sort((a, b) => spans.start[a] - spans.start[b]);
    let cursor = region.base;
    const emitGap = (from, to, kind) => {
      const len = to - from;
      if (len < MIN_GAP_BYTES || (kind === 'reserved' && !reserved)) return;
      pieces.push({ kind, start: from, end: to, bytes: len, id: `g${from}` });
    };
    // A gap is split where the page state changes: committed-but-unused vs reserved/unknown.
    const addGap = (from, to) => {
      let at = from, runStart = from, runKind = null;
      const flush = end => { if (runKind && end > runStart) emitGap(runStart, end, runKind); };
      while (at < to) {
        const s = spanOrder.find(x => spans.start[x] <= at && at < spans.end[x]);
        const next = s === undefined
          ? Math.min(to, ...spanOrder.map(x => spans.start[x]).filter(v => v > at), to)
          : Math.min(to, spans.end[s]);
        const kind = s !== undefined && spans.state[s] === 2 ? 'free' : 'reserved';
        if (kind !== runKind) { flush(at); runStart = at; runKind = kind; }
        at = next;
      }
      flush(to);
    };
    for (const b of sorted) {
      const start = blocks.addr[b], end = start + Math.max(1, blocks.size[b]);
      if (start > cursor) addGap(cursor, start);
      pieces.push({ kind: 'block', b, start, end, bytes: blocks.size[b], id: `b${b}` });
      cursor = Math.max(cursor, end);
    }
    if (cursor < region.end) addGap(cursor, region.end);
  } else {
    for (const s of spanIds) {
      const committed = spans.state[s] === 2;
      if (!committed && !reserved) continue;
      pieces.push({ kind: committed ? 'pages' : 'reserved', s, start: spans.start[s], end: spans.end[s],
        bytes: spans.end[s] - spans.start[s], protect: spans.protect[s], id: `s${s}` });
    }
  }
  return pieces;
}

// Places pieces inside a region box; returns world-space positions and sides.
export function placePieces(region, pieces) {
  const boxes = pieces.map(p => {
    const side = p.kind === 'block' ? boxSide(p.bytes) : Math.max(0.3, gapSide(p.bytes));
    return { id: p.id, size: [side, side, side] };
  });
  const width = region.size[0] - 1;
  const packed = packInto(boxes, width, 0.18);
  const low = region.position.map((v, axis) => v - region.size[axis] / 2 + 0.5);
  for (const p of pieces) {
    const slot = packed.slots.get(p.id);
    p.position = slot.position.map((v, axis) => v + low[axis]);
    p.side = slot.size[0];
  }
  return { pieces, overflow: packed.size[1] > region.size[1] - 1 };
}

// Hashable signature of a region's content at an instant (to skip re-packing unchanged regions).
export function contentSignature(blockIds, spanIds) {
  let h = 2166136261 ^ blockIds.length;
  for (const b of blockIds) h = Math.imul(h ^ b, 16777619);
  h = Math.imul(h ^ 0x9e3779b9, 16777619);
  for (const s of spanIds) h = Math.imul(h ^ s, 16777619);
  return `${blockIds.length}:${spanIds.length}:${h >>> 0}`;
}

// A point inside a region box for an address, from Heapscape's addressPosition: the byte offset is
// folded into a 16x16x16 Morton lattice, so nearby addresses land near each other and the whole
// box is used. item: a regionLayout item ({ base, end, position, size }).
export function addressPosition(address, item, out = [0, 0, 0]) {
  const span = item.end - item.base;
  const cell = span > 0 ? Math.min(4095, Math.max(0, Math.floor((address - item.base) / span * 4096))) : 0;
  for (let axis = 0; axis < 3; axis++) {
    let v = 0;
    for (let bit = 0; bit < 4; bit++) v |= ((cell >> (bit * 3 + axis)) & 1) << bit;
    // Keep points off the frame so beams visibly enter the box.
    out[axis] = item.position[axis] + ((v + 0.5) / 16 - 0.5) * item.size[axis] * 0.9;
  }
  return out;
}
