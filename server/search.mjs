// Content search over block snapshots (contents.bin + contents.idx, analyze --snapshots): which
// blocks held a string, some bytes or a pointer value when they were last seen. Runs on the server
// so the viewer never downloads every snapshot.
import fs from 'node:fs/promises';
import path from 'node:path';

const fail = (status, message) => Object.assign(new Error(message), { status });
const CHUNK = 16 << 20; // bytes of contents.bin read at a time

// The byte patterns a query means: text (ASCII and UTF-16LE, ASCII letters in any case), hex bytes,
// or a pointer (little-endian, pointer-sized). [{ bytes: Uint8Array, fold: bool, label }]
export function patterns(query, mode, pointerSize = 8) {
  if (typeof query !== 'string' || !query.length || query.length > 256) throw fail(400, 'the query must be 1 to 256 characters');
  if (mode === 'hex') {
    const clean = query.replace(/\s+/g, '').replace(/^0x/i, '');
    if (!/^([0-9a-f]{2})+$/i.test(clean)) throw fail(400, 'hex bytes must be pairs of hex digits');
    return [{ bytes: Uint8Array.from(clean.match(/../g), h => Number.parseInt(h, 16)), fold: false, label: 'bytes' }];
  }
  if (mode === 'pointer') {
    if (!/^(0x)?[0-9a-f]{1,16}$/i.test(query)) throw fail(400, 'a pointer is a hex address');
    let v = BigInt(query.startsWith('0x') || query.startsWith('0X') ? query : `0x${query}`);
    const bytes = new Uint8Array(pointerSize);
    for (let k = 0; k < pointerSize; k++) { bytes[k] = Number(v & 0xffn); v >>= 8n; }
    if (v) throw fail(400, 'the address does not fit in a pointer');
    return [{ bytes, fold: false, label: 'pointer' }];
  }
  if (mode !== 'text') throw fail(400, 'mode must be text, hex or pointer');
  const chars = [...query].map(c => c.charCodeAt(0));
  if (chars.some(c => c > 0xff)) throw fail(400, 'text search is ASCII / Latin-1');
  const wide = new Uint8Array(chars.length * 2);
  chars.forEach((c, k) => { wide[k * 2] = c; });
  return [{ bytes: Uint8Array.from(chars), fold: true, label: 'ascii' }, { bytes: wide, fold: true, label: 'utf16' }];
}

const lower = c => (c >= 0x41 && c <= 0x5a ? c | 0x20 : c);

// Offsets of pattern p in bytes[lo, hi).
function find(bytes, lo, hi, p, out, max) {
  const n = p.bytes.length, first = p.fold ? lower(p.bytes[0]) : p.bytes[0];
  for (let i = lo; i + n <= hi && out.length < max; i++) {
    if ((p.fold ? lower(bytes[i]) : bytes[i]) !== first) continue;
    let k = 1;
    if (p.fold) { while (k < n && lower(bytes[i + k]) === lower(p.bytes[k])) k++; }
    else { while (k < n && bytes[i + k] === p.bytes[k]) k++; }
    if (k === n) out.push(i - lo);
  }
}

// Decodes contents.idx: per block { offset, length, unknown }.
export function decodeContentIndex(buf) {
  const view = new DataView(buf.buffer ?? buf, buf.byteOffset ?? 0, buf.byteLength);
  const out = [];
  for (let o = 0; o + 16 <= view.byteLength; o += 16)
    out.push({ offset: view.getUint32(o, true) + view.getUint32(o + 4, true) * 4294967296, length: view.getUint32(o + 8, true), unknown: view.getUint32(o + 12, true) });
  return out;
}

// Pure search over an index and a reader of contents.bin ranges. Returns
// { matches: [{ block, offset, pattern, preview }], truncated }.
export async function searchContents(index, readRange, pats, { limit = 500 } = {}) {
  const matches = [];
  const order = index.map((x, b) => ({ ...x, b })).filter(x => x.length).sort((a, b) => a.offset - b.offset);
  let k = 0;
  while (k < order.length && matches.length < limit) {
    // A chunk of whole blocks.
    const start = order[k].offset;
    let end = k;
    while (end < order.length && (order[end].offset + order[end].length - start <= CHUNK || end === k)) end++;
    const hiOff = order[end - 1].offset + order[end - 1].length;
    const bytes = await readRange(start, hiOff);
    for (let j = k; j < end && matches.length < limit; j++) {
      const x = order[j], lo = x.offset - start, hi = lo + x.length;
      for (const p of pats) {
        const found = [];
        find(bytes, lo, hi, p, found, limit - matches.length);
        for (const off of found) {
          const a = Math.max(lo, lo + off - 8), b = Math.min(hi, lo + off + p.bytes.length + 24);
          matches.push({ block: x.b, offset: off, pattern: p.label, preview: Buffer.from(bytes.subarray(a, b)).toString('hex'), previewOffset: a - lo });
          if (matches.length >= limit) break;
        }
      }
    }
    k = end;
  }
  return { matches, truncated: matches.length >= limit };
}

// Searches an analysis directory.
export async function searchAnalysis(dir, { q, mode = 'text', limit = 500 }, pointerSize) {
  let idxBuf;
  try { idxBuf = await fs.readFile(path.join(dir, 'contents.idx')); }
  catch { throw fail(409, 'this analysis has no block snapshots; analyze the trace again with "Snapshot block contents"'); }
  const pats = patterns(q, mode, pointerSize);
  const fh = await fs.open(path.join(dir, 'contents.bin'), 'r');
  try {
    const readRange = async (lo, hi) => {
      const buf = Buffer.alloc(hi - lo);
      await fh.read(buf, 0, buf.length, lo);
      return buf;
    };
    return await searchContents(decodeContentIndex(idxBuf), readRange, pats, { limit: Math.min(2000, Math.max(1, limit)) });
  } finally {
    await fh.close();
  }
}
