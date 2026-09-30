// Decoded API arguments of recorded calls (analyzer: replay/call_args.cpp).
//
// callargs.jsonl holds one JSON object per call, in calls.bin order; callargs.bin holds the u64
// byte offset of each line plus the end offset. Parameters: n name, t type, v raw value, s string,
// tr truncated, d pointee, fl / dfl flag names of the value / pointee, f float, b bytes, o [Out],
// r read at the return.

export const ARG_BLOCK = 64; // calls fetched together

// Offsets of calls [lo, lo + count] from a slice of callargs.bin that starts at call lo.
export function decodeOffsets(buffer, count) {
  const view = new DataView(buffer);
  const out = new Float64Array(count + 1);
  for (let k = 0; k <= count; k++) out[k] = view.getUint32(k * 8, true) + view.getUint32(k * 8 + 4, true) * 4294967296;
  return out;
}

// Parses the text of consecutive lines (bytes starting at offsets[0]) into one object per call.
export function parseArgLines(bytes, offsets) {
  const decoder = new TextDecoder();
  const out = [];
  for (let k = 0; k + 1 < offsets.length; k++) {
    const line = decoder.decode(bytes.subarray(offsets[k] - offsets[0], offsets[k + 1] - offsets[0])).trim();
    try { out.push(line ? JSON.parse(line) : null); } catch { out.push(null); }
  }
  return out;
}

// callpos.bin records (call seq, steps, ret seq, steps as u64) -> [{ call, ret }] as "SEQ:STEPS"
// strings (ret null when the call never returned).
export function decodeCallPositions(buffer) {
  const view = new DataView(buffer), out = [];
  const u64 = o => view.getUint32(o, true) + view.getUint32(o + 4, true) * 4294967296;
  const text = o => view.getUint32(o, true) === 0xFFFFFFFF && view.getUint32(o + 4, true) === 0xFFFFFFFF ? null
    : `${u64(o).toString(16).toUpperCase()}:${u64(o + 8).toString(16).toUpperCase()}`;
  for (let o = 0; o + 32 <= view.byteLength; o += 32) out.push({ call: text(o), ret: text(o + 16) });
  return out;
}

const quote = s => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r/g, '\\r').replace(/\n/g, '\\n')}"`;

// One parameter for display: { name, type, value, out, atReturn }. value prefers the most
// informative rendering: text, then flag names, then a float, then raw -> pointee.
export function formatParam(p) {
  let value;
  if (p.s !== undefined) value = `${quote(p.s)}${p.tr ? '…' : ''}`;
  else if (p.fl?.length) value = p.fl.join(' | ');
  else if (p.f !== undefined) value = String(p.f);
  else {
    value = p.v;
    if (p.d !== undefined) value += ` → ${p.dfl?.length ? p.dfl.join(' | ') : p.d}`;
  }
  return { name: p.n ?? '', type: p.t ?? '', value, out: !!p.o, atReturn: !!p.r };
}

// "name=value, ..." (compact, for one-line summaries).
export function formatArgList(args, max = 6) {
  if (!args?.p) return '';
  const parts = args.p.slice(0, max).map(p => {
    const f = formatParam(p);
    return `${f.name ? `${f.name}=` : ''}${f.value}${f.atReturn ? '@ret' : ''}`;
  });
  if (args.p.length > max) parts.push('…');
  return parts.join(', ');
}
