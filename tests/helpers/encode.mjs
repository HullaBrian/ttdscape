// Encodes synthetic tables with the analyzer's binary layouts (analyzer/src/model/types.h).
export const NONE = 0xFFFFFFFF;

function writer(recordSize, records, fill) {
  const buf = new ArrayBuffer(recordSize * records.length);
  const v = new DataView(buf);
  const u64 = (o, x) => { v.setUint32(o, x % 4294967296, true); v.setUint32(o + 4, Math.floor(x / 4294967296), true); };
  records.forEach((r, i) => fill(v, i * recordSize, r, u64));
  return buf;
}

export const encodeEvents = recs => writer(32, recs, (v, o, r, u64) => {
  v.setUint8(o, r.kind); v.setUint8(o + 1, r.flags ?? 0); v.setUint16(o + 2, r.thread ?? 0, true);
  v.setUint32(o + 4, r.id ?? NONE, true); u64(o + 8, r.addr ?? 0); u64(o + 16, r.size ?? 0);
  v.setUint32(o + 24, r.stack ?? NONE, true); v.setUint32(o + 28, r.aux ?? 0, true);
});

export const encodeBlocks = recs => writer(48, recs, (v, o, r, u64) => {
  u64(o, r.addr); u64(o + 8, r.size); v.setUint32(o + 16, r.heap ?? 0, true);
  v.setUint32(o + 20, r.allocEvt ?? NONE, true); v.setUint32(o + 24, r.freeEvt ?? NONE, true);
  v.setUint32(o + 28, r.allocStack ?? NONE, true); v.setUint32(o + 32, r.freeStack ?? NONE, true);
  v.setUint32(o + 36, r.prev ?? NONE, true); v.setUint32(o + 40, r.flags ?? 0, true);
  v.setUint16(o + 44, r.allocThread ?? 0, true); v.setUint16(o + 46, r.freeThread ?? 0xFFFF, true);
});

export const encodeRegions = recs => writer(48, recs, (v, o, r, u64) => {
  u64(o, r.base); u64(o + 8, r.size); v.setUint32(o + 16, r.kind ?? 0, true);
  v.setUint32(o + 20, r.createEvt ?? NONE, true); v.setUint32(o + 24, r.releaseEvt ?? NONE, true);
  v.setUint32(o + 28, r.heap ?? NONE, true); v.setUint32(o + 32, NONE, true); v.setUint32(o + 36, NONE, true);
  v.setUint32(o + 40, r.flags ?? 0, true);
});

export const encodeSpans = recs => writer(40, recs, (v, o, r, u64) => {
  u64(o, r.start); u64(o + 8, r.end); v.setUint32(o + 16, r.region, true);
  v.setUint16(o + 20, r.state ?? 2, true); v.setUint16(o + 22, 0, true); v.setUint32(o + 24, r.protect ?? 4, true);
  v.setUint32(o + 28, r.startEvt ?? NONE, true); v.setUint32(o + 32, r.endEvt ?? NONE, true);
});

export const encodeStacks = recs => writer(8, recs, (v, o, r) => { v.setUint32(o, r.parent, true); v.setUint32(o + 4, r.frame, true); });
export const encodeFrames = recs => writer(16, recs, (v, o, r, u64) => { u64(o, r.addr); v.setUint32(o + 8, r.module ?? NONE, true); v.setUint32(o + 12, r.rva ?? 0, true); });

export const encodeCalls = recs => writer(32, recs, (v, o, r) => {
  v.setUint16(o, r.thread ?? 0, true); v.setUint8(o + 2, r.flags ?? 1); v.setUint8(o + 3, r.depth ?? 0);
  v.setUint32(o + 4, r.callerFrame ?? 0, true); v.setUint32(o + 8, r.callee ?? 0, true);
  v.setUint32(o + 12, r.startEvt, true); v.setUint32(o + 16, r.endEvt ?? NONE, true);
  v.setFloat32(o + 20, r.startFrac ?? 0.5, true); v.setFloat32(o + 24, r.endFrac ?? 0.5, true);
  v.setUint32(o + 28, r.via ?? NONE, true);
});
