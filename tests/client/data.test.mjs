import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeEvents, decodeBlocks, decodeRegions, decodeSpans, decodeStacks, decodeFrames, decodeSeries, decodeCalls } from '../../client/trace-reader.js';
import { CallModel, beamPhase, CALL } from '../../client/calls.js';
import { TimeModel } from '../../client/state.js';
import { Stacks } from '../../client/stacks.js';
import { assignBlocks, regionLayout, regionPieces, placePieces, packInto, boxSide, addressPosition } from '../../client/layout.js';
import { protectName, parseAddress, hex } from '../../client/format.js';
import { AddressIndex, ActivityModel, FlowModel, pointerCandidates, byteEvents, findStrings, groupAccesses, decodeBase64 } from '../../client/memory.js';
import { decodeActivity, decodeWriters, decodeFlows } from '../../client/trace-reader.js';
import { NONE, encodeEvents, encodeBlocks, encodeRegions, encodeSpans, encodeStacks, encodeFrames, encodeCalls } from '../helpers/encode.mjs';

test('decodes 64-bit addresses exactly', () => {
  const addr = 0x7ffa6b260000 + 0x1234;
  const ev = decodeEvents(encodeEvents([{ kind: 1, flags: 3, thread: 7, id: 42, addr, size: 64, stack: 5, aux: 9 }]));
  assert.equal(ev.count, 1);
  assert.equal(ev.addr[0], addr);
  assert.equal(hex(ev.addr[0]), '0x7ffa6b261234');
  assert.deepEqual([ev.kind[0], ev.flags[0], ev.thread[0], ev.id[0], ev.size[0], ev.stack[0], ev.aux[0]], [1, 3, 7, 42, 64, 5, 9]);
  assert.throws(() => decodeEvents(new ArrayBuffer(31), 1), RangeError);
});

test('decodes series', () => {
  const buf = new ArrayBuffer(16 + 2 * 3 * 8);
  const v = new DataView(buf);
  v.setUint32(0, 3, true); v.setUint32(4, 2, true); v.setFloat64(8, 10, true);
  [1, 2, 3, 10, 20, 30].forEach((x, i) => v.setFloat64(16 + i * 8, x, true));
  const s = decodeSeries(buf, ['a', 'b']);
  assert.equal(s.eventsPerBucket, 10);
  assert.deepEqual([...s.columns.b], [10, 20, 30]);
});

// A small synthetic history: two regions, a heap region with blocks that come and go.
function synthetic() {
  const blocks = [
    { addr: 0x10000, size: 32, allocEvt: 0, freeEvt: 3, allocStack: 1 },
    { addr: 0x10100, size: 64, allocEvt: 1, freeEvt: NONE, allocStack: 1 },
    { addr: 0x10000, size: 48, allocEvt: 4, freeEvt: NONE, prev: NONE, allocStack: 2 },
    { addr: 0x20000, size: 16, allocEvt: NONE, freeEvt: 2 },           // pre-trace
    { addr: 0x10400, size: 8, allocEvt: 5, freeEvt: 6, prev: 1 },
  ];
  const regions = [
    { base: 0x10000, size: 0x10000, kind: 4, createEvt: NONE },
    { base: 0x20000, size: 0x1000, kind: 6, createEvt: NONE },
    { base: 0x30000, size: 0x2000, kind: 0, createEvt: 2, releaseEvt: 5 },
  ];
  const spans = [
    { start: 0x10000, end: 0x14000, region: 0, state: 2 },
    { start: 0x14000, end: 0x20000, region: 0, state: 1 },
    { start: 0x20000, end: 0x21000, region: 1, state: 2 },
    { start: 0x30000, end: 0x32000, region: 2, state: 2, protect: 0x20, startEvt: 2, endEvt: 5 },
  ];
  const events = Array.from({ length: 7 }, () => ({ kind: 1 }));
  const data = {
    manifest: { modules: [{ name: 'app.exe' }, { name: 'ntdll.dll' }] },
    events: decodeEvents(encodeEvents(events)),
    blocks: decodeBlocks(encodeBlocks(blocks)),
    regions: decodeRegions(encodeRegions(regions)),
    spans: decodeSpans(encodeSpans(spans)),
    stacks: decodeStacks(encodeStacks([{ parent: NONE, frame: 0 }, { parent: 0, frame: 1 }, { parent: 0, frame: 2 }])),
    frames: decodeFrames(encodeFrames([{ addr: 0x401000, module: 0, rva: 0x1000 }, { addr: 0x7ff0, module: 1, rva: 0x10 }, { addr: 0x401200, module: 0, rva: 0x1200 }])),
    symbols: [['app!main+0x10', 'main.cpp', 12], ['ntdll!RtlAllocateHeap', '', 0], ['app!helper+0x4', '', 0]],
  };
  return data;
}

function bruteLive(data, i) {
  const out = [];
  for (let b = 0; b < data.blocks.count; b++) {
    const a = data.blocks.allocEvt[b] === NONE ? -1 : data.blocks.allocEvt[b];
    const f = data.blocks.freeEvt[b] === NONE ? Infinity : data.blocks.freeEvt[b];
    if (a <= i && f > i) out.push(b);
  }
  return out;
}

test('live blocks at every event match brute force, with and without checkpoints', () => {
  const data = synthetic();
  for (const every of [1, 2, 3, 100]) {
    const time = new TimeModel(data, { checkpointEvery: every });
    for (let i = -1; i < 7; i++) assert.deepEqual([...time.liveBlocksAt(i)], bruteLive(data, i), `i=${i} every=${every}`);
  }
});

test('randomized histories agree with brute force', () => {
  let seed = 12345;
  const rand = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
  const n = 400, events = 300;
  const blocks = Array.from({ length: n }, () => {
    const a = rand() < 0.1 ? NONE : Math.floor(rand() * events);
    const f = rand() < 0.3 ? NONE : (a === NONE ? 0 : a) + 1 + Math.floor(rand() * 50);
    return { addr: Math.floor(rand() * 1e6), size: 16, allocEvt: a, freeEvt: f >= events ? NONE : f };
  });
  const data = synthetic();
  data.blocks = decodeBlocks(encodeBlocks(blocks));
  data.events = decodeEvents(encodeEvents(Array.from({ length: events }, () => ({ kind: 1 }))));
  const time = new TimeModel(data, { checkpointEvery: 17 });
  for (const i of [-1, 0, 5, 16, 17, 33, 100, 150, 299]) assert.deepEqual([...time.liveBlocksAt(i)], bruteLive(data, i), `i=${i}`);
});

test('curves, regions, spans and realloc chains', () => {
  const data = synthetic();
  const time = new TimeModel(data);
  assert.equal(time.heapStart, 16);          // the pre-trace block
  assert.equal(time.heapLive[0], 48);
  assert.equal(time.heapLive[2], 32 + 64);   // pre-trace freed at 2
  assert.deepEqual(time.liveRegionsAt(1), [0, 1]);
  assert.deepEqual(time.liveRegionsAt(2), [0, 1, 2]);
  assert.deepEqual(time.liveRegionsAt(5), [0, 1]);
  assert.equal(time.committed[2] - time.committed[1], 0x2000);
  assert.deepEqual(time.spansAt(2, 3), [3]);
  assert.equal(time.regionAt(0x10123, 3), 0);
  assert.equal(time.blockAt(0x10120, 3), 1);
  assert.deepEqual(time.reallocChain(4), [1, 4]);
  assert.deepEqual(time.addressHistory(0x10000), [0, 2]);
});

test('stacks collapse allocator frames and leaks group by site', () => {
  const data = synthetic();
  const stacks = new Stacks(data);
  assert.deepEqual(stacks.describe(1).map(f => f.text), ['ntdll!RtlAllocateHeap', 'app!main+0x10']);
  assert.equal(stacks.siteText(1), 'app!main+0x10');
  assert.equal(stacks.siteText(2), 'app!helper+0x4');
  assert.equal(stacks.describe(1)[1].source, 'main.cpp:12');
  const leaks = new TimeModel(data).leaks(stacks);
  assert.deepEqual(leaks.map(g => [g.text, g.blocks.length, g.bytes]), [['app!main+0x10', 1, 64], ['app!helper+0x4', 1, 48]]);
});

test('layout: stable regions, no overlaps, byte-proportional pieces', () => {
  const data = synthetic();
  const time = new TimeModel(data);
  const assignment = assignBlocks(data);
  assert.deepEqual([...assignment], [0, 0, 0, 1, 0]);
  const layout = regionLayout(data, time);
  assert.equal(layout.items.length, 3);
  // Region boxes never overlap.
  const boxes = layout.items;
  for (let a = 0; a < boxes.length; a++) for (let b = a + 1; b < boxes.length; b++) {
    const overlap = [0, 1, 2].every(k => Math.abs(boxes[a].position[k] - boxes[b].position[k]) < (boxes[a].size[k] + boxes[b].size[k]) / 2);
    assert.equal(overlap, false);
  }
  // Spacing: boxes keep at least the layout's gap apart on some axis, and the gap grows with spacing.
  for (const spacing of [0, 0.8, 1.6]) {
    const l = regionLayout(data, time, { spacing });
    for (let a = 0; a < l.items.length; a++) for (let b = a + 1; b < l.items.length; b++) {
      const [x, y] = [l.items[a], l.items[b]];
      const apart = Math.max(...[0, 1, 2].map(k => Math.abs(x.position[k] - y.position[k]) - (x.size[k] + y.size[k]) / 2));
      assert.ok(apart >= l.gap - 1e-9, `spacing ${spacing}: ${apart} < ${l.gap}`);
    }
  }
  assert.ok(regionLayout(data, time, { spacing: 1.6 }).gap > regionLayout(data, time, { spacing: 0 }).gap);
  const region = layout.byRegion[0];
  const live = [...time.liveBlocksAt(1)].filter(b => assignment[b] === 0);
  const pieces = regionPieces(region, live, data.blocks, time.spansAt(0, 1), data.spans);
  assert.deepEqual(pieces.map(p => p.kind), ['block', 'block', 'free']); // the 224-byte gap is below MIN_GAP_BYTES
  const { pieces: placed } = placePieces(region, pieces);
  for (let a = 0; a < placed.length; a++) for (let b = a + 1; b < placed.length; b++) {
    const overlap = [0, 1, 2].every(k => Math.abs(placed[a].position[k] - placed[b].position[k]) < (placed[a].side + placed[b].side) / 2 - 1e-9);
    assert.equal(overlap, false);
  }
  assert.equal(placed[0].side, boxSide(32));
  // Reserved tail appears only when requested.
  assert.equal(regionPieces(region, live, data.blocks, time.spansAt(0, 1), data.spans, { reserved: true }).at(-1).kind, 'reserved');
  // Region without blocks shows its page spans.
  const pages = regionPieces(layout.byRegion[2], [], data.blocks, time.spansAt(2, 3), data.spans);
  assert.deepEqual(pages.map(p => [p.kind, p.protect]), [['pages', 0x20]]);
});

test('packInto keeps a fixed footprint', () => {
  const items = Array.from({ length: 50 }, (_, i) => ({ id: i, size: [1, 1, 1] }));
  const { size } = packInto(items, 5, 0);
  assert.ok(size[0] <= 5 && size[2] <= 5);
  assert.equal(size[1], 2);
});

test('formatting helpers', () => {
  assert.equal(protectName(0x20), 'RX');
  assert.equal(protectName(0x104), 'RW+GUARD');
  assert.equal(parseAddress('0x7ffa`6b260000'), 0x7ffa6b260000);
  assert.equal(parseAddress('zz'), null);
});

test('decodes calls', () => {
  const c = decodeCalls(encodeCalls([{ thread: 3, flags: 5, depth: 9, callerFrame: 7, callee: 2, startEvt: 10, endEvt: 12, startFrac: 0.25, endFrac: 0.75, via: 4 },
    { startEvt: 11 }]));
  assert.equal(c.count, 2);
  assert.deepEqual([c.thread[0], c.flags[0], c.depth[0], c.callerFrame[0], c.callee[0], c.startEvt[0], c.endEvt[0], c.startFrac[0], c.endFrac[0], c.via[0]],
    [3, 5, 9, 7, 2, 10, 12, 0.25, 0.75, 4]);
  assert.equal(c.endEvt[1], NONE);
  assert.equal(c.via[1], NONE);
});

test('beam phases: travel, hold while active, fade after return', () => {
  assert.equal(beamPhase(10, 10.1, 9.9, 4), null);           // not started
  assert.equal(beamPhase(10, 10.1, 11, 4).progress, 0.5);     // half way after W/4... travel is W/2 = 2
  assert.equal(beamPhase(10, 10.1, 11, 4).alpha, 1);
  const held = beamPhase(10, 50, 20, 4);                      // arrived, still active
  assert.equal(held.progress, 1); assert.ok(held.held);
  const fading = beamPhase(10, 50, 51, 4);                    // returned 1 ago, fades over 2
  assert.ok(fading.alpha > 0 && fading.alpha < 0.55 && !fading.held);
  assert.equal(beamPhase(10, 50, 52, 4), null);
  assert.equal(beamPhase(10, Infinity, 1e9, 4).held, true);   // never returned
});

test('visible calls at every time match brute force', () => {
  // Deterministic pseudo-random calls over 200 events: most short, some long, some never returned or unwound.
  let seed = 7;
  const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
  const recs = [];
  for (let k = 0; k < 600; k++) {
    const startEvt = Math.floor(rnd() * 200), startFrac = (Math.floor(rnd() * 9) + 1) / 10;
    const r = rnd();
    const rec = { thread: k % 3, startEvt, startFrac, callerFrame: k % 17, callee: k % 5 };
    if (r < 0.05) rec.flags = 0;                                    // never returned
    else if (r < 0.1) rec.flags = CALL.Unwound;
    else { rec.endEvt = startEvt + (r < 0.3 ? Math.floor(rnd() * 40) : 0); rec.endFrac = rec.endEvt === startEvt ? Math.min(0.95, startFrac + 0.05) : 0.5; }
    recs.push(rec);
  }
  recs.sort((a, b) => a.startEvt - 1 + a.startFrac - (b.startEvt - 1 + b.startFrac));
  const model = new CallModel(decodeCalls(encodeCalls(recs)));
  for (const W of [0.5, 3, 25]) {
    for (let T = -1; T <= 201; T += 0.37) {
      const got = model.visible(T, W, { budget: Infinity }).beams.map(b => b.i).sort((a, b) => a - b);
      const want = [];
      for (let i = 0; i < recs.length; i++) if (beamPhase(model.t0[i], model.t1[i], T, W)) want.push(i);
      assert.deepEqual(got, want, `T=${T} W=${W}`);
    }
  }
  // Merging by key keeps one beam per key with the total count; the budget caps distinct beams.
  const T = 120, W = 25;
  const all = model.visible(T, W, { budget: Infinity }).beams.length;
  const merged = model.visible(T, W, { budget: Infinity, key: i => model.calls.callee[i] });
  assert.ok(merged.beams.length <= 5);
  assert.equal(merged.beams.reduce((s, b) => s + b.count, 0), all);
  const capped = model.visible(T, W, { budget: 3 });
  assert.equal(capped.beams.length, 3); assert.ok(capped.truncated);
  const only = model.visible(T, W, { budget: Infinity, accept: i => model.calls.thread[i] === 1 }).beams;
  assert.ok(only.length > 0 && only.every(b => model.calls.thread[b.i] === 1));
});

test('addressPosition stays inside the box and is deterministic', () => {
  const item = { base: 0x10000, end: 0x20000, position: [5, 6, 7], size: [4, 4, 4] };
  for (const a of [0x10000, 0x12345, 0x1ffff, 0x5, 0x99999]) {
    const p = addressPosition(a, item);
    for (let k = 0; k < 3; k++) assert.ok(Math.abs(p[k] - item.position[k]) < item.size[k] / 2, `${a.toString(16)} axis ${k}`);
    assert.deepEqual(p, addressPosition(a, item));
  }
  assert.notDeepEqual(addressPosition(0x10000, item), addressPosition(0x1ffff, item));
});

test('region browser filters by kind, liveness, name and address, and sorts', async () => {
  const { regionRows } = await import('../../client/region-list.js');
  const data = synthetic();
  const names = ['heap seg', 'inferred', 'private one'];
  const name = r => names[r];
  const time = new TimeModel(data);
  assert.deepEqual(regionRows(data, name), [0, 1, 2]);
  assert.deepEqual(regionRows(data, name, { kinds: new Set([0]) }), [2]);
  assert.deepEqual(regionRows(data, name, { text: 'PRIV' }), [2]);
  assert.deepEqual(regionRows(data, name, { text: '0x20010' }), [1]);           // address inside region 1
  assert.deepEqual(regionRows(data, name, { liveAt: 6, isLive: (r, i) => time.regionLive(r, i) }), [0, 1]); // region 2 released at 5
  assert.deepEqual(regionRows(data, name, { sort: 'size' }), [0, 2, 1]);
  assert.deepEqual(regionRows(data, name, { sort: 'name' }), [0, 1, 2]);
});

test('call arguments: offsets, line ranges and display formatting', async () => {
  const { decodeOffsets, parseArgLines, formatParam, formatArgList } = await import('../../client/call-args.js');
  const lines = ['{"sig":1,"p":[{"n":"lpFileName","t":"PWSTR","v":"0x10","s":"C:\\\\a \\"b\\""}],"ret":"0x1"}',
    '{"sig":0,"p":[{"v":"0x5"}]}', ''];
  const text = new TextEncoder().encode(lines.map(l => `${l}\n`).join(''));
  const offs = [0];
  for (const l of lines) offs.push(offs.at(-1) + new TextEncoder().encode(`${l}\n`).length);
  const buf = new ArrayBuffer(offs.length * 8);
  offs.forEach((o, k) => new DataView(buf).setUint32(k * 8, o, true));
  const decoded = decodeOffsets(buf, lines.length);
  assert.deepEqual([...decoded], offs);
  // A range that starts at the second call: bytes are relative to its offset.
  const parsed = parseArgLines(text.subarray(offs[1]), decoded.subarray(1));
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].sig, 0);
  assert.equal(parsed[1], null);                                   // empty line: nothing decoded
  const all = parseArgLines(text, decoded);
  assert.equal(all[0].p[0].s, 'C:\\a "b"');
  assert.equal(formatParam(all[0].p[0]).value, '"C:\\\\a \\"b\\""');
  assert.equal(formatParam({ n: 'flNewProtect', v: '0x40', fl: ['PAGE_EXECUTE_READWRITE'] }).value, 'PAGE_EXECUTE_READWRITE');
  assert.equal(formatParam({ n: 'lpflOldProtect', v: '0x14fe00', d: '0x4', dfl: ['PAGE_READWRITE'], o: 1, r: 1 }).value, '0x14fe00 → PAGE_READWRITE');
  assert.equal(formatParam({ n: 'p', v: '0x14fe00', d: '0x7' }).value, '0x14fe00 → 0x7');
  assert.ok(formatParam({ n: 'o', v: '0x1', o: 1, r: 1 }).out);
  assert.equal(formatParam({ v: '0x1', s: 'abc', tr: 1 }).value, '"abc"…');
  assert.equal(formatArgList({ p: [{ n: 'a', v: '0x1' }, { n: 'b', v: '0x2', r: 1 }] }), 'a=0x1, b=0x2@ret');
  assert.equal(formatArgList({ p: [1, 2, 3].map(k => ({ v: `0x${k}` })) }, 2), '0x1, 0x2, …');
});

test('pacing by calls maps call index and time both ways', async () => {
  const { timeAtIndex, indexAtTime } = await import('../../client/calls.js');
  const times = Float64Array.from([2, 2.5, 10, 10, 40]);
  assert.equal(timeAtIndex(times, 0), 2);
  assert.equal(timeAtIndex(times, 1.5), 6.25);
  assert.equal(timeAtIndex(times, 99), 40);
  assert.equal(timeAtIndex(times, -3), 2);
  assert.equal(indexAtTime(times, 1), 0);
  assert.equal(indexAtTime(times, 100), 4);
  assert.equal(indexAtTime(times, 25), 3.5);
  for (const k of [0, 0.5, 1.25, 3.5, 4]) assert.ok(Math.abs(indexAtTime(times, timeAtIndex(times, k)) - k) < 1e-9 || times[Math.floor(k)] === times[Math.ceil(k)], `k=${k}`);
  assert.equal(timeAtIndex(new Float64Array(0), 3), 0);
  assert.equal(indexAtTime(new Float64Array(0), 3), 0);
});

test('app events reach every handler and can be removed', async () => {
  const { Emitter } = await import('../../client/app/events.js');
  const e = new Emitter(), got = [];
  const off = e.on('x', v => got.push(['a', v]));
  e.on('x', () => { throw new Error('a failing handler does not stop the others'); });
  e.on('x', v => got.push(['b', v]));
  const err = console.error; console.error = () => {};
  try { e.emit('x', 1); off(); e.emit('x', 2); } finally { console.error = err; }
  assert.deepEqual(got, [['a', 1], ['b', 1], ['b', 2]]);
});

test('executable memory outside modules is found at an event and over the trace', async () => {
  const { unbackedExecutable } = await import('../../client/region-list.js');
  const data = synthetic();
  const time = new TimeModel(data);
  // Region 2 (private) holds PAGE_EXECUTE_READ pages from event 2 until event 5.
  assert.deepEqual([...unbackedExecutable(data, time, 1)], []);
  assert.deepEqual([...unbackedExecutable(data, time, 3)], [2]);
  assert.deepEqual([...unbackedExecutable(data, time, 5)], []);
  assert.deepEqual([...unbackedExecutable(data, time)], [2]);
  // A module image with executable pages is backed: never flagged.
  const image = { ...data, regions: decodeRegions(encodeRegions([{ base: 0x10000, size: 0x10000, kind: 4 }, { base: 0x20000, size: 0x1000, kind: 6 }, { base: 0x30000, size: 0x2000, kind: 2, createEvt: 2, releaseEvt: 5 }])) };
  assert.deepEqual([...unbackedExecutable(image, new TimeModel(image))], []);
});

test('active calls at every time match brute force', () => {
  let seed = 99;
  const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
  const recs = [];
  for (let k = 0; k < 500; k++) {
    const startEvt = Math.floor(rnd() * 200), startFrac = (Math.floor(rnd() * 9) + 1) / 10, r = rnd();
    const rec = { thread: k % 4, startEvt, startFrac };
    if (r < 0.05) rec.flags = 0;
    else if (r < 0.1) rec.flags = CALL.Unwound;
    else { rec.endEvt = startEvt + (r < 0.4 ? Math.floor(rnd() * 60) : 0); rec.endFrac = rec.endEvt === startEvt ? Math.min(0.95, startFrac + 0.05) : 0.5; }
    recs.push(rec);
  }
  recs.sort((a, b) => a.startEvt - 1 + a.startFrac - (b.startEvt - 1 + b.startFrac));
  const model = new CallModel(decodeCalls(encodeCalls(recs)));
  for (const span of [0.5, 4, 1000]) {
    for (let T = -1; T <= 201; T += 0.41) {
      const want = [];
      for (let i = 0; i < recs.length; i++) if (model.t0[i] <= T && model.t1[i] > T) want.push(i);
      want.sort((a, b) => model.t0[a] - model.t0[b] || a - b);
      assert.deepEqual(model.activeAt(T, span), want, `T=${T} span=${span}`);
    }
  }
});

test('address index finds the live block or region holding an address, like brute force', () => {
  let seed = 4242;
  const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
  const events = 200;
  // Blocks reuse addresses over time inside one heap region; a few are huge (the large list).
  const blocks = Array.from({ length: 600 }, () => {
    const a = rnd() < 0.1 ? NONE : Math.floor(rnd() * events);
    const f = rnd() < 0.3 ? NONE : (a === NONE ? 0 : a) + 1 + Math.floor(rnd() * 40);
    const huge = rnd() < 0.02;
    return { addr: 0x10000 + Math.floor(rnd() * 0x40) * 0x100, size: huge ? 0x80000 : 1 + Math.floor(rnd() * 0x300), allocEvt: a, freeEvt: f >= events ? NONE : f };
  });
  const data = synthetic();
  data.blocks = decodeBlocks(encodeBlocks(blocks));
  data.events = decodeEvents(encodeEvents(Array.from({ length: events }, () => ({ kind: 1 }))));
  const time = new TimeModel(data, { checkpointEvery: 32 });
  const index = new AddressIndex(data, time);
  for (let i = -1; i < events; i += 7) {
    const live = time.liveBlocksAt(i);
    for (let addr = 0xff00; addr < 0x21000; addr += 0x61) {
      let want = NONE;
      for (const b of live)
        if (addr >= data.blocks.addr[b] && addr < data.blocks.addr[b] + data.blocks.size[b] && (want === NONE || data.blocks.size[b] < data.blocks.size[want])) want = b;
      assert.equal(index.blockAt(addr, i), want, `addr=${addr.toString(16)} i=${i}`);
      const obj = index.objectAt(addr, i);
      if (want !== NONE) assert.deepEqual(obj, { kind: 'block', b: want, offset: addr - data.blocks.addr[want] });
      else if (time.regionAt(addr, i) !== NONE) assert.equal(obj.kind, 'region');
      else assert.equal(obj, null);
    }
  }
  assert.equal(index.objectAt(0x100, 0), null);
});

test('pointer candidates come from raw values, pointees and the return value', () => {
  const args = { sig: 1, p: [
    { n: 'hHeap', v: '0x2a0000' }, { n: 'dwFlags', v: '0x8', fl: ['HEAP_ZERO_MEMORY'] }, { n: 'lpMem', v: '0xcdbc10' },
    { n: 'lpszServerName', v: '0x1166fc0', s: '192.168.81.129' }, { n: 'BaseAddress', v: '0x65f4c8', d: '0x1110000', o: 1, r: 1 },
    { n: 'Small', v: '0x1000' }, { n: 'Unknown', v: '?' }, { n: 'F', v: '0x40490fdb', f: 3.14 },
  ], ret: '0x1' };
  assert.deepEqual(pointerCandidates(args).map(c => [c.param, c.which, c.addr.toString(16), c.atReturn]), [
    [0, 'v', '2a0000', false], [2, 'v', 'cdbc10', false], [3, 'v', '1166fc0', false],
    [4, 'v', '65f4c8', true], [4, 'd', '1110000', true]]);
  assert.deepEqual(pointerCandidates({ p: [], ret: '0x7ffa6a154980' }).map(c => c.which), ['ret']);
  assert.deepEqual(pointerCandidates(null), []);
});

test('memory view helpers: provenance per byte, strings, access groups', () => {
  assert.deepEqual([...decodeBase64('AAEC/w==')], [0, 1, 2, 255]);
  assert.deepEqual([...byteEvents(6, [[0, 2, 10, 3], [4, 9, 12, 5]])], [3, 3, -1, -1, 5, 5]);
  const text = [...Buffer.from('xxhello world\0'), 1, 2, ...Buffer.from('w\0i\0d\0e\0s\0!\0'), 0, 0, ...Buffer.from('abcd')];
  const bytes = Uint8Array.from(text);
  const found = findStrings(bytes, null);
  assert.deepEqual(found.map(s => [s.offset, s.text, s.wide]), [[0, 'xxhello world', false], [16, 'wides!', true]]);
  // Unknown bytes break a run.
  const known = new Int32Array(bytes.length).fill(1);
  known[5] = -1;
  assert.deepEqual(findStrings(bytes, known).map(s => s.text), ['xxhel', 'o world', 'wides!']);
  const hits = [{ evt: 5, kind: 'w', utid: 1, sym: 'a' }, { evt: 2, kind: 'w', utid: 2, sym: 'a' }, { evt: 9, kind: 'r', utid: 1, sym: 'b' }];
  const groups = groupAccesses(hits, h => h.sym);
  assert.deepEqual(groups.map(g => [g.label, g.count, g.first, g.last, g.kinds.w, g.threads.size]), [['a', 2, 2, 5, 2, 2], ['b', 1, 9, 9, 0, 1]]);
});

test('content search: patterns and matches across chunk-sized reads', async () => {
  const { patterns, searchContents, decodeContentIndex } = await import('../../server/search.mjs');
  const [ascii, wide] = patterns('Ab', 'text');
  assert.deepEqual([...ascii.bytes], [0x41, 0x62]);
  assert.deepEqual([...wide.bytes], [0x41, 0, 0x62, 0]);
  assert.deepEqual([...patterns('0x1122', 'pointer', 4)[0].bytes], [0x22, 0x11, 0, 0]);
  assert.throws(() => patterns('\u4e2d', 'text'), /ASCII/);
  // Blocks: "xxabyy", nothing, "a\0B\0" (wide), "ab" split from the first by the index order.
  const bin = Buffer.concat([Buffer.from('xxabyy'), Buffer.from('a\0B\0'), Buffer.from('AB')]);
  const idx = Buffer.alloc(64);
  const put = (k, off, len) => { idx.writeUInt32LE(off, k * 16); idx.writeUInt32LE(len, k * 16 + 8); };
  put(0, 0, 6); put(2, 6, 4); put(3, 10, 2);
  const index = decodeContentIndex(idx);
  const found = await searchContents(index, async (lo, hi) => bin.subarray(lo, hi), patterns('ab', 'text'));
  assert.deepEqual(found.matches.map(m => [m.block, m.offset, m.pattern]), [[0, 2, 'ascii'], [2, 0, 'utf16'], [3, 0, 'ascii']]);
  assert.equal(found.truncated, false);
  const capped = await searchContents(index, async (lo, hi) => bin.subarray(lo, hi), patterns('ab', 'text'), { limit: 2 });
  assert.equal(capped.matches.length, 2);
  assert.equal(capped.truncated, true);
});

test('activity cells decode and give write heat per block and region over time', () => {
  // Cells: block 3 in buckets 2 and 5; page 7 of region 1 in bucket 5; a block-less cell of no region.
  const rows = [[3, NONE, NONE, 2, 8], [3, NONE, NONE, 5, 4], [NONE, 1, 7, 5, 10], [NONE, NONE, NONE, 6, 1]];
  const buf = new ArrayBuffer(rows.length * 20), v = new DataView(buf);
  rows.forEach((r, i) => r.forEach((x, k) => v.setUint32(i * 20 + k * 4, x, true)));
  const cells = decodeActivity(buf);
  assert.equal(cells.count, 4);
  const m = new ActivityModel(cells, { buckets: 8, eventsPerBucket: 10 });
  assert.deepEqual([...m.total], [0, 0, 8, 0, 0, 14, 1, 0]);
  assert.equal(m.heat(3, 19), 0);                 // before its first write
  assert.equal(m.heat(3, 25), 8);                 // bucket 2
  assert.equal(m.heat(3, 45), 8 / 4);             // two buckets later, halved twice
  assert.equal(m.heat(3, 55), 4 + 8 / 8);
  assert.equal(m.heat(3, 79), 4 / 4);             // bucket 7 (clamped)
  assert.equal(m.heat(9, 55), 0);
  assert.equal(m.regionHeat(1, 55), 10);
  assert.equal(m.regionHeat(1, 65), 5);
  // writers.bin records.
  const w = new ArrayBuffer(40), wv = new DataView(w);
  [3, NONE, NONE, 11, 12, 20, 55].forEach((x, k) => wv.setUint32(k * 4, x, true));
  wv.setUint16(28, 1, true); wv.setUint16(30, 2, true); wv.setUint32(32, 12, true); wv.setUint32(36, 1, true);
  const d = decodeWriters(w);
  assert.deepEqual([d.block[0], d.firstFrame[0], d.lastFrame[0], d.firstEvt[0], d.lastEvt[0], d.firstThread[0], d.lastThread[0], d.writes[0], d.flags[0]], [3, 11, 12, 20, 55, 1, 2, 12, 1]);
});

test('flows between regions decode and are found by time window', () => {
  // bucket, from, to, writes: two flows in bucket 1, one within a region (skipped), one in bucket 4.
  const rows = [[1, 2, 5, 10], [1, 3, 3, 7], [1, NONE, 5, 1], [4, 2, 6, 3]];
  const buf = new ArrayBuffer(rows.length * 16), v = new DataView(buf);
  rows.forEach((r, i) => r.forEach((x, k) => v.setUint32(i * 16 + k * 4, x, true)));
  const flows = decodeFlows(buf);
  const m = new FlowModel(flows, { buckets: 6, eventsPerBucket: 10 });
  assert.deepEqual(m.span(0), [10, 20]);
  assert.deepEqual(m.between(0, 9), []);
  assert.deepEqual(m.between(12, 15), [0]);
  assert.deepEqual(m.between(15, 45), [0, 3]);
  assert.deepEqual(m.between(40, 1000), [3]);
});

test('cinematic tour: prominent, spread-out regions, circled in order, cameras outside the boxes', async () => {
  const { cinematicTour } = await import('../../client/cinematic.js');
  assert.equal(cinematicTour([]), null);
  // A ring of 12 regions around the origin, with sizes 1..12, plus one big central region.
  const items = Array.from({ length: 12 }, (_, k) => {
    const a = k / 12 * Math.PI * 2, s = 2 + k;
    return { r: k, position: [Math.cos(a) * 100, s / 2, Math.sin(a) * 100], size: [s, s, s], displayBytes: 1000 * (k + 1) };
  });
  items.push({ r: 12, position: [0, 20, 0], size: [40, 40, 40], displayBytes: 1e6 });
  const tour = cinematicTour(items, { stops: 6 });
  assert.equal(tour.cameras.length, tour.targets.length);
  assert.equal(tour.regions.length, 6);
  assert.ok(tour.regions.includes(12), 'the biggest region is a stop');
  assert.equal(new Set(tour.regions).size, 6);
  // Stops circle once: their angles around the centre increase.
  const angles = tour.regions.map(r => items[r]).map(b => Math.atan2(b.position[2] - tour.center[2], b.position[0] - tour.center[0]));
  for (let k = 1; k < angles.length; k++) assert.ok(angles[k] >= angles[k - 1]);
  // Every camera is outside every box, and above the scene's floor.
  for (const c of tour.cameras) {
    assert.ok(c[1] > 0);
    for (const b of items) assert.ok([0, 1, 2].some(k => Math.abs(c[k] - b.position[k]) > b.size[k] / 2), 'camera outside the box');
  }
  // A big neighbour right where a stop's camera would stand pushes it back, clear of that box too.
  const crowded = [{ r: 0, position: [100, 5, 0], size: [10, 10, 10], displayBytes: 10 }, { r: 1, position: [-100, 5, 0], size: [10, 10, 10], displayBytes: 9 },
    { r: 2, position: [135, 20, 0], size: [40, 40, 40], displayBytes: 1 }];
  const t2 = cinematicTour(crowded, { stops: 2 });
  for (const c of t2.cameras) for (const b of crowded) assert.ok([0, 1, 2].some(k => Math.abs(c[k] - b.position[k]) > b.size[k] / 2), 'clear of the neighbour');
  // It starts wide: the first camera is the farthest from the centre.
  const far = c => Math.hypot(c[0] - tour.center[0], c[1] - tour.center[1], c[2] - tour.center[2]);
  assert.ok(tour.cameras.slice(1).every(c => far(c) < far(tour.cameras[0])));
});

test('aerial orbit: every region box stays in frame all the way round', async () => {
  const { cinematicOrbit } = await import('../../client/cinematic.js');
  assert.equal(cinematicOrbit([]), null);
  let seed = 3;
  const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
  const items = Array.from({ length: 60 }, (_, r) => {
    const s = 2 + rnd() * 30;
    return { r, position: [rnd() * 400 - 150, rnd() * 80, rnd() * 300 - 100], size: [s, s, s] };
  });
  for (const [fov, aspect, visible, visibleX] of [[55, 1.7, 0.85, 1], [55, 0.6, 1, 1], [40, 2.4, 0.7, 0.6]]) {
    const orbit = cinematicOrbit(items, { fov, aspect, visible, visibleX });
    const tanV = Math.tan(fov * Math.PI / 360) * visible, tanH = Math.tan(fov * Math.PI / 360) * aspect * visibleX;
    for (const cam of orbit.cameras) {
      // Camera basis looking at the centre.
      const f = orbit.center.map((c, k) => c - cam[k]), fl = Math.hypot(...f), fw = f.map(v => v / fl);
      const right = [fw[2], 0, -fw[0]], rl = Math.hypot(...right), rt = right.map(v => v / rl);
      const up = [rt[1] * fw[2] - rt[2] * fw[1], rt[2] * fw[0] - rt[0] * fw[2], rt[0] * fw[1] - rt[1] * fw[0]];
      for (const b of items) for (const corner of [[-1, -1, -1], [1, 1, 1], [-1, 1, -1], [1, -1, 1], [1, 1, -1], [-1, -1, 1], [1, -1, -1], [-1, 1, 1]]) {
        const p = b.position.map((v, k) => v + corner[k] * b.size[k] / 2 - cam[k]);
        const z = p[0] * fw[0] + p[1] * fw[1] + p[2] * fw[2];
        const x = p[0] * rt[0] + p[1] * rt[1] + p[2] * rt[2], y = p[0] * up[0] + p[1] * up[1] + p[2] * up[2];
        assert.ok(z > 0 && Math.abs(x / z) <= tanH + 1e-9 && Math.abs(y / z) <= tanV + 1e-9, `fov ${fov} aspect ${aspect}: a corner is out of frame`);
      }
    }
    // Tight: from 10% closer, something would leave the frame from some point of the circle.
    const closer = cinematicOrbit(items, { fov, aspect, visible, visibleX, margin: 1.06 * 0.9 });
    const outOfFrame = closer.cameras.some(cam => {
      const f = closer.center.map((c, k) => c - cam[k]), fl = Math.hypot(...f), fw = f.map(v => v / fl);
      const rl = Math.hypot(fw[2], fw[0]), rt = [fw[2] / rl, 0, -fw[0] / rl];
      const up = [rt[1] * fw[2] - rt[2] * fw[1], rt[2] * fw[0] - rt[0] * fw[2], rt[0] * fw[1] - rt[1] * fw[0]];
      return items.some(b => [[-1, -1, -1], [1, 1, 1], [-1, 1, -1], [1, -1, 1], [1, 1, -1], [-1, -1, 1], [1, -1, -1], [-1, 1, 1]].some(corner => {
        const p = b.position.map((v, k) => v + corner[k] * b.size[k] / 2 - cam[k]);
        const z = p[0] * fw[0] + p[1] * fw[1] + p[2] * fw[2];
        const x = p[0] * rt[0] + p[1] * rt[1] + p[2] * rt[2], y = p[0] * up[0] + p[1] * up[1] + p[2] * up[2];
        return Math.abs(x / z) > tanH || Math.abs(y / z) > tanV;
      }));
    });
    assert.ok(outOfFrame, 'the orbit is framed tightly');
    // Above the scene, each camera at its own distance, and the distance changes gently.
    const d = c => Math.hypot(...c.map((v, k) => v - orbit.center[k]));
    orbit.cameras.forEach((c, k) => { assert.ok(c[1] > orbit.center[1]); assert.ok(Math.abs(d(c) - orbit.distances[k]) < 1e-6); });
    for (let k = 0; k < orbit.distances.length; k++) {
      const next = orbit.distances[(k + 1) % orbit.distances.length];
      assert.ok(Math.abs(next - orbit.distances[k]) / orbit.distance < 0.15, 'no lurches');
    }
  }
});
