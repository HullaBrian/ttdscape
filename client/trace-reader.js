// Decodes the analyzer's binary tables (little-endian, fixed records; see analyzer/src/model/types.h)
// into struct-of-arrays columns. Addresses and sizes become doubles (exact below 2^53).

function reader(buffer, recordSize, count) {
  const view = new DataView(buffer instanceof ArrayBuffer ? buffer : buffer.buffer, buffer.byteOffset ?? 0, buffer.byteLength);
  if (count === undefined) count = Math.floor(view.byteLength / recordSize);
  if (view.byteLength < count * recordSize) throw new RangeError(`table truncated: ${view.byteLength} < ${count} x ${recordSize}`);
  const u64 = (o) => view.getUint32(o, true) + view.getUint32(o + 4, true) * 4294967296;
  return { view, count, u64 };
}

export function decodeEvents(buffer, count) {
  const { view, count: n, u64 } = reader(buffer, 32, count);
  const t = { count: n, kind: new Uint8Array(n), flags: new Uint8Array(n), thread: new Uint16Array(n), id: new Uint32Array(n),
    addr: new Float64Array(n), size: new Float64Array(n), stack: new Uint32Array(n), aux: new Uint32Array(n) };
  for (let i = 0, o = 0; i < n; i++, o += 32) {
    t.kind[i] = view.getUint8(o); t.flags[i] = view.getUint8(o + 1); t.thread[i] = view.getUint16(o + 2, true);
    t.id[i] = view.getUint32(o + 4, true); t.addr[i] = u64(o + 8); t.size[i] = u64(o + 16);
    t.stack[i] = view.getUint32(o + 24, true); t.aux[i] = view.getUint32(o + 28, true);
  }
  return t;
}

export function decodeBlocks(buffer, count) {
  const { view, count: n, u64 } = reader(buffer, 48, count);
  const t = { count: n, addr: new Float64Array(n), size: new Float64Array(n), heap: new Uint32Array(n),
    allocEvt: new Uint32Array(n), freeEvt: new Uint32Array(n), allocStack: new Uint32Array(n), freeStack: new Uint32Array(n),
    prev: new Uint32Array(n), flags: new Uint32Array(n), allocThread: new Uint16Array(n), freeThread: new Uint16Array(n) };
  for (let i = 0, o = 0; i < n; i++, o += 48) {
    t.addr[i] = u64(o); t.size[i] = u64(o + 8); t.heap[i] = view.getUint32(o + 16, true);
    t.allocEvt[i] = view.getUint32(o + 20, true); t.freeEvt[i] = view.getUint32(o + 24, true);
    t.allocStack[i] = view.getUint32(o + 28, true); t.freeStack[i] = view.getUint32(o + 32, true);
    t.prev[i] = view.getUint32(o + 36, true); t.flags[i] = view.getUint32(o + 40, true);
    t.allocThread[i] = view.getUint16(o + 44, true); t.freeThread[i] = view.getUint16(o + 46, true);
  }
  return t;
}

export function decodeRegions(buffer, count) {
  const { view, count: n, u64 } = reader(buffer, 48, count);
  const t = { count: n, base: new Float64Array(n), size: new Float64Array(n), kind: new Uint32Array(n),
    createEvt: new Uint32Array(n), releaseEvt: new Uint32Array(n), heap: new Uint32Array(n),
    createStack: new Uint32Array(n), releaseStack: new Uint32Array(n), flags: new Uint32Array(n) };
  for (let i = 0, o = 0; i < n; i++, o += 48) {
    t.base[i] = u64(o); t.size[i] = u64(o + 8); t.kind[i] = view.getUint32(o + 16, true);
    t.createEvt[i] = view.getUint32(o + 20, true); t.releaseEvt[i] = view.getUint32(o + 24, true);
    t.heap[i] = view.getUint32(o + 28, true); t.createStack[i] = view.getUint32(o + 32, true);
    t.releaseStack[i] = view.getUint32(o + 36, true); t.flags[i] = view.getUint32(o + 40, true);
  }
  return t;
}

export function decodeSpans(buffer, count) {
  const { view, count: n, u64 } = reader(buffer, 40, count);
  const t = { count: n, start: new Float64Array(n), end: new Float64Array(n), region: new Uint32Array(n),
    state: new Uint16Array(n), flags: new Uint16Array(n), protect: new Uint32Array(n),
    startEvt: new Uint32Array(n), endEvt: new Uint32Array(n) };
  for (let i = 0, o = 0; i < n; i++, o += 40) {
    t.start[i] = u64(o); t.end[i] = u64(o + 8); t.region[i] = view.getUint32(o + 16, true);
    t.state[i] = view.getUint16(o + 20, true); t.flags[i] = view.getUint16(o + 22, true);
    t.protect[i] = view.getUint32(o + 24, true); t.startEvt[i] = view.getUint32(o + 28, true);
    t.endEvt[i] = view.getUint32(o + 32, true);
  }
  return t;
}

export function decodeStacks(buffer, count) {
  const { view, count: n } = reader(buffer, 8, count);
  const t = { count: n, parent: new Uint32Array(n), frame: new Uint32Array(n) };
  for (let i = 0, o = 0; i < n; i++, o += 8) { t.parent[i] = view.getUint32(o, true); t.frame[i] = view.getUint32(o + 4, true); }
  return t;
}

export function decodeFrames(buffer, count) {
  const { view, count: n, u64 } = reader(buffer, 16, count);
  const t = { count: n, addr: new Float64Array(n), module: new Uint32Array(n), rva: new Uint32Array(n) };
  for (let i = 0, o = 0; i < n; i++, o += 16) {
    t.addr[i] = u64(o); t.module[i] = view.getUint32(o + 8, true); t.rva[i] = view.getUint32(o + 12, true);
  }
  return t;
}

export function decodePositions(buffer) {
  const { view, count: n, u64 } = reader(buffer, 16);
  const out = new Array(n);
  for (let i = 0, o = 0; i < n; i++, o += 16) out[i] = `${u64(o).toString(16).toUpperCase()}:${u64(o + 8).toString(16).toUpperCase()}`;
  return out;
}

// calls.bin: calls into module exports, sorted by start time (see CallRec in types.h).
export function decodeCalls(buffer, count) {
  const { view, count: n } = reader(buffer, 32, count);
  const t = { count: n, thread: new Uint16Array(n), flags: new Uint8Array(n), depth: new Uint8Array(n),
    callerFrame: new Uint32Array(n), callee: new Uint32Array(n), startEvt: new Uint32Array(n), endEvt: new Uint32Array(n),
    startFrac: new Float32Array(n), endFrac: new Float32Array(n), via: new Uint32Array(n) };
  for (let i = 0, o = 0; i < n; i++, o += 32) {
    t.thread[i] = view.getUint16(o, true); t.flags[i] = view.getUint8(o + 2); t.depth[i] = view.getUint8(o + 3);
    t.callerFrame[i] = view.getUint32(o + 4, true); t.callee[i] = view.getUint32(o + 8, true);
    t.startEvt[i] = view.getUint32(o + 12, true); t.endEvt[i] = view.getUint32(o + 16, true);
    t.startFrac[i] = view.getFloat32(o + 20, true); t.endFrac[i] = view.getFloat32(o + 24, true);
    t.via[i] = view.getUint32(o + 28, true);
  }
  return t;
}

// activity.bin: writes per object (a block, or a page of a region) per series bucket (ActivityCell).
export function decodeActivity(buffer) {
  const { view, count: n } = reader(buffer, 20);
  const t = { count: n, block: new Uint32Array(n), region: new Uint32Array(n), page: new Uint32Array(n), bucket: new Uint32Array(n), writes: new Uint32Array(n) };
  for (let i = 0, o = 0; i < n; i++, o += 20) {
    t.block[i] = view.getUint32(o, true); t.region[i] = view.getUint32(o + 4, true); t.page[i] = view.getUint32(o + 8, true);
    t.bucket[i] = view.getUint32(o + 12, true); t.writes[i] = view.getUint32(o + 16, true);
  }
  return t;
}

// writers.bin: who wrote each object over the whole trace (WriterRec). Frames are frames.bin ids
// of PC + 1 (frames are return addresses, symbolized at address - 1).
export function decodeWriters(buffer) {
  const { view, count: n } = reader(buffer, 40);
  const t = { count: n, block: new Uint32Array(n), region: new Uint32Array(n), page: new Uint32Array(n),
    firstFrame: new Uint32Array(n), lastFrame: new Uint32Array(n), firstEvt: new Uint32Array(n), lastEvt: new Uint32Array(n),
    firstThread: new Uint16Array(n), lastThread: new Uint16Array(n), writes: new Uint32Array(n), flags: new Uint32Array(n) };
  for (let i = 0, o = 0; i < n; i++, o += 40) {
    t.block[i] = view.getUint32(o, true); t.region[i] = view.getUint32(o + 4, true); t.page[i] = view.getUint32(o + 8, true);
    t.firstFrame[i] = view.getUint32(o + 12, true); t.lastFrame[i] = view.getUint32(o + 16, true);
    t.firstEvt[i] = view.getUint32(o + 20, true); t.lastEvt[i] = view.getUint32(o + 24, true);
    t.firstThread[i] = view.getUint16(o + 28, true); t.lastThread[i] = view.getUint16(o + 30, true);
    t.writes[i] = view.getUint32(o + 32, true); t.flags[i] = view.getUint32(o + 36, true);
  }
  return t;
}

// flows.bin: writes from code in one region to memory in another, per series bucket (FlowRec),
// sorted by bucket.
export function decodeFlows(buffer) {
  const { view, count: n } = reader(buffer, 16);
  const t = { count: n, bucket: new Uint32Array(n), from: new Uint32Array(n), to: new Uint32Array(n), writes: new Uint32Array(n) };
  for (let i = 0, o = 0; i < n; i++, o += 16) {
    t.bucket[i] = view.getUint32(o, true); t.from[i] = view.getUint32(o + 4, true);
    t.to[i] = view.getUint32(o + 8, true); t.writes[i] = view.getUint32(o + 12, true);
  }
  return t;
}

// Call beams data, fetched only when beams are shown. Null when the analysis recorded no calls.
export async function loadCalls(fetchFile, manifest) {
  const f = manifest.files;
  if (!f.calls || !f.callees) return null;
  const [buffer, callees] = await Promise.all([
    fetchFile(f.calls.file).then(r => r.arrayBuffer()),
    fetchFile(f.callees.file).then(r => r.json()),
  ]);
  const list = callees.callees;
  return { ...decodeCalls(buffer, f.calls.count),
    callees: { count: list.length, module: Uint32Array.from(list, c => c[0] ?? 0xFFFFFFFF),
      name: list.map(c => c[1]), addr: Float64Array.from(list, c => Number.parseInt(c[2].slice(2), 16)) } };
}

// series.bin: u32 buckets, u32 columns, f64 eventsPerBucket, then column-major f64.
export function decodeSeries(buffer, names) {
  const view = new DataView(buffer instanceof ArrayBuffer ? buffer : buffer.buffer, buffer.byteOffset ?? 0, buffer.byteLength);
  const buckets = view.getUint32(0, true), columns = view.getUint32(4, true), eventsPerBucket = view.getFloat64(8, true);
  const out = { buckets, eventsPerBucket, columns: {} };
  for (let c = 0; c < columns; c++) {
    const values = new Float64Array(buckets);
    for (let b = 0; b < buckets; b++) values[b] = view.getFloat64(16 + (c * buckets + b) * 8, true);
    out.columns[names?.[c] ?? `c${c}`] = values;
  }
  return out;
}

// Loads a whole analysis from the server. fetchFile(name) -> Response.
export async function loadAnalysis(fetchFile, onProgress = () => {}) {
  const manifest = await (await fetchFile('manifest.json')).json();
  if (manifest.schema !== 'ttdscape/1') throw new Error(`unsupported analysis schema: ${manifest.schema}`);
  const f = manifest.files;
  const names = ['events', 'blocks', 'regions', 'spans', 'stacks', 'frames'];
  const buffers = {};
  let done = 0;
  await Promise.all([...names, 'series'].map(async name => {
    buffers[name] = await (await fetchFile(f[name].file)).arrayBuffer();
    onProgress(++done / (names.length + 2));
  }));
  let symbols = null;
  try {
    const res = await fetchFile('symbols.json');
    if (res.ok) symbols = await res.json();
  } catch { /* symbols are optional */ }
  onProgress(1);
  return {
    manifest,
    events: decodeEvents(buffers.events, f.events.count),
    blocks: decodeBlocks(buffers.blocks, f.blocks.count),
    regions: decodeRegions(buffers.regions, f.regions.count),
    spans: decodeSpans(buffers.spans, f.spans.count),
    stacks: decodeStacks(buffers.stacks, f.stacks.count),
    frames: decodeFrames(buffers.frames, f.frames.count),
    series: decodeSeries(buffers.series, f.series.columns),
    symbols: symbols?.frames ?? null,
  };
}
