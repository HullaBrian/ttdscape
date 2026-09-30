// Filtering and sorting regions for the region browser (pure; tested in tests/client).
import { NONE, parseAddress } from './format.js';

const IMAGE = 2, COMMITTED = 2, EXECUTE = 0xF0; // PAGE_EXECUTE, _READ, _READWRITE, _WRITECOPY

// Regions that are not a loaded module's image but have committed executable pages: code that
// no module on disk accounts for (JIT, shellcode, unpacked or manually mapped payloads).
// At event i when given, otherwise at any point of the trace.
export function unbackedExecutable(data, time, i = null) {
  const { regions, spans } = data;
  const out = new Set();
  for (let r = 0; r < regions.count; r++) {
    if (regions.kind[r] === IMAGE) continue;
    if (i !== null && !time.regionLive(r, i)) continue;
    for (const s of time.spansByRegion[r]) {
      if (spans.state[s] !== COMMITTED || !(spans.protect[s] & EXECUTE)) continue;
      if (i !== null && !time.spanLive(s, i)) continue;
      out.add(r);
      break;
    }
  }
  return out;
}

export const REGION_KINDS = [[2, 'Image'], [4, 'Heap'], [6, 'Heap (inferred)'], [3, 'Stack'], [0, 'Private'], [1, 'Mapped'], [5, 'Pre-trace']];

// data: the analysis; name(r): display name; opts: { text, kinds: Set | null, liveAt: event | null,
// isLive(r, i), only: Set | null (restrict to these regions), sort: 'address' | 'size' | 'name' | 'created' }. Text matches the name
// (case-insensitive) or, when it parses as an address, the regions containing it.
export function regionRows(data, name, { text = '', kinds = null, liveAt = null, isLive = null, only = null, sort = 'address' } = {}) {
  const { regions } = data;
  const q = text.trim().toLowerCase();
  const addr = q ? parseAddress(q) : null;
  const out = [];
  for (let r = 0; r < regions.count; r++) {
    if (kinds && !kinds.has(regions.kind[r])) continue;
    if (only && !only.has(r)) continue;
    if (liveAt !== null && isLive && !isLive(r, liveAt)) continue;
    if (q) {
      const inRange = addr !== null && addr >= regions.base[r] && addr < regions.base[r] + regions.size[r];
      if (!inRange && !name(r).toLowerCase().includes(q)) continue;
    }
    out.push(r);
  }
  const created = r => regions.createEvt[r] === NONE ? -1 : regions.createEvt[r];
  const cmp = {
    address: (a, b) => regions.base[a] - regions.base[b] || created(a) - created(b),
    size: (a, b) => regions.size[b] - regions.size[a] || regions.base[a] - regions.base[b],
    name: (a, b) => name(a).localeCompare(name(b)) || regions.base[a] - regions.base[b],
    created: (a, b) => created(a) - created(b) || regions.base[a] - regions.base[b],
  }[sort] ?? ((a, b) => a - b);
  return out.sort(cmp);
}
