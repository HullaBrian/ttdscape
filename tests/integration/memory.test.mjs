// Memory contents and accesses through `ttdscape-analyzer serve`, checked against the fixture's own
// ground truth (fixtures/app/fixture.cpp).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { repo, analyzer, exists, analyzeTrace, startServe } from './analyze.mjs';
import { TimeModel } from '../../client/state.js';
import { AddressIndex, ActivityModel, byteEvents } from '../../client/memory.js';
import { decodeActivity, decodeWriters, decodeFlows } from '../../client/trace-reader.js';
import { decodeContentIndex, searchAnalysis } from '../../server/search.mjs';

const NONE = 0xFFFFFFFF;
const hexNum = h => Number.parseInt(h.slice(2), 16);
const hex = v => `0x${v.toString(16)}`;

for (const name of ['fixture01', 'fixture86']) {
const trace = path.join(repo, 'fixtures', 'traces', `${name}.run`);
const truthFile = path.join(repo, 'fixtures', 'traces', `${name}.truth.json`);
const ready = await exists(trace) && await exists(truthFile) && await exists(analyzer);
const skip = ready ? false : `${name} not recorded or analyzer not built`;
let data, truth, serve, fixtureModule;

// Block of a truth allocation (by address and size; the first one allocated inside the trace).
function block(label) {
  const a = truth.allocs.find(x => x.label === label);
  for (let b = 0; b < data.blocks.count; b++)
    if (data.blocks.addr[b] === hexNum(a.address) && data.blocks.size[b] === a.size && data.blocks.allocEvt[b] !== NONE) return b;
  return NONE;
}

before(async () => {
  if (!ready) return;
  truth = JSON.parse(await fs.readFile(truthFile, 'utf8'));
  data = await analyzeTrace(trace, ['--no-symbols']);
  serve = await startServe(trace, data.dir);
  fixtureModule = data.manifest.modules.findIndex(m => /ttdscape-fixture/i.test(m.name));
});

after(async () => {
  serve?.close();
  if (data) await fs.rm(data.dir, { recursive: true, force: true });
});

test(`${name}: memory at an event holds what the program wrote`, { skip }, async () => {
  // leak_b(77) memsets its block to 0xB2 after HeapAlloc returns: by the next allocation it is done.
  for (let i = 0; i < 9; i++) {
    const b = block(`p4.leak_b.${i}`), next = data.blocks.allocEvt[block(`p4.leak_b.${i + 1}`)];
    assert.notEqual(b, NONE);
    const r = await serve.call('memory.read', { evt: next, addr: hex(data.blocks.addr[b]), size: 77 });
    assert.deepEqual(r.unknown, [], `leak_b.${i} fully recorded`);
    assert.deepEqual([...Buffer.from(r.data, 'base64')], Array(77).fill(0xB2), `leak_b.${i}`);
    // Provenance ranges cover the block and point at events up to the one read.
    const known = byteEvents(77, r.ranges);
    assert.ok(known.every(e => e >= 0 && e <= next), `leak_b.${i} provenance`);
  }
  // Right at the allocation (its RET) the memset has not run yet.
  const b0 = block('p4.leak_b.0');
  const early = await serve.call('memory.read', { evt: data.blocks.allocEvt[b0], addr: hex(data.blocks.addr[b0]), size: 77 });
  assert.notDeepEqual([...Buffer.from(early.data, 'base64')], Array(77).fill(0xB2));
  // Reading at a block's free and after it (the heap reuses the memory) works, and unknown bytes
  // are reported as spans inside the window.
  const freed = block('p3.realloc');
  for (const evt of [data.blocks.freeEvt[freed], data.blocks.freeEvt[freed] + 1, data.events.count - 1]) {
    const r = await serve.call('memory.read', { evt, addr: hex(data.blocks.addr[freed]), size: 5000 });
    assert.equal(Buffer.from(r.data, 'base64').length, 5000);
    for (const [o, n] of r.unknown) assert.ok(o >= 0 && n > 0 && o + n <= 5000);
  }
  // Unmapped memory is unknown; a position can be given directly.
  const low = await serve.call('memory.read', { evt: 0, addr: '0x10000', size: 64 });
  assert.deepEqual(low.unknown, [[0, 64]]);
  const byPos = await serve.call('memory.read', { pos: low.pos, addr: '0x10000', size: 16 });
  assert.equal(byPos.pos, low.pos);
  await assert.rejects(serve.call('memory.read', { evt: 1 }), /addr/);
  await assert.rejects(serve.call('nope', {}), /unknown method/);
});

test(`${name}: accesses show the heap's zeroing and the program's writes, by the right code and thread`, { skip }, async () => {
  const utidOf = t => data.manifest.threads[t].utid;
  const ntdll = data.manifest.modules.map((m, i) => /^ntdll/i.test(m.name) ? i : -1).filter(i => i >= 0);
  // HEAP_ZERO_MEMORY: ntdll zeroes p1.h100 inside the allocating call, on the allocating thread.
  const h100 = block('p1.h100'), lo = data.blocks.addr[h100], alloc = data.blocks.allocEvt[h100];
  const z = await serve.call('accesses.query', { lo: hex(lo), hi: hex(lo + 100), from: alloc - 1, to: data.blocks.freeEvt[h100] + 1 });
  assert.equal(z.truncated, false);
  const zeroing = z.hits.filter(h => h.kind === 'w' && h.evt <= alloc && /^(00)+$/.test(h.new ?? 'x'));
  assert.ok(zeroing.length > 0, 'zeroing writes');
  for (const h of zeroing) {
    assert.ok(ntdll.includes(h.module), `zeroed by ntdll, not module ${h.module}`);
    assert.equal(h.utid, utidOf(data.blocks.allocThread[h100]));
  }
  const covered = new Uint8Array(100);
  for (const h of zeroing) for (let a = hexNum(h.addr); a < hexNum(h.addr) + h.size; a++) if (a >= lo && a < lo + 100) covered[a - lo] = 1;
  assert.ok(covered.every(Boolean), 'all 100 bytes zeroed');

  // leak_b's memset: writes of 0xB2 by the fixture's own code, after the allocation, in order.
  const b = block('p4.leak_b.3'), blo = data.blocks.addr[b];
  const m = await serve.call('accesses.query', { lo: hex(blo), hi: hex(blo + 77), from: data.blocks.allocEvt[b] - 1 });
  const fill = m.hits.filter(h => h.kind === 'w' && /^(b2)+$/.test(h.new ?? ''));
  assert.ok(fill.length > 0, 'memset writes');
  for (const h of fill) {
    assert.equal(h.module, fixtureModule, `memset from the fixture module, not module ${h.module}`);
    assert.ok(h.evt >= data.blocks.allocEvt[b]);
    assert.equal(h.utid, utidOf(data.blocks.allocThread[b]));
    // The old value is what was there before (Overwrite), as long as the new one.
    assert.equal(h.old?.length, h.new.length);
  }
  const pos = fill.map(h => h.pos.split(':').map(x => BigInt(`0x${x}`)));
  for (let k = 1; k < pos.length; k++) assert.ok(pos[k][0] > pos[k - 1][0] || (pos[k][0] === pos[k - 1][0] && pos[k][1] >= pos[k - 1][1]), 'chronological');

  // Reads are opt-in, capped, and flagged.
  const capped = await serve.call('accesses.query', { lo: hex(blo), hi: hex(blo + 77), reads: true, limit: 5 });
  assert.equal(capped.hits.length, 5);
  assert.equal(capped.truncated, true);
  await assert.rejects(serve.call('accesses.query', { lo: hex(blo), hi: hex(blo + 0x200000) }), /1 MiB/);
});

test(`${name}: pointer arguments resolve to the blocks they name`, { skip }, () => {
  // HeapFree(heap, 0, p): lpMem links to the block being freed.
  const time = new TimeModel(data), index = new AddressIndex(data, time);
  const calls = data.exportCalls;
  let checked = 0;
  for (let i = 0; i < calls.count; i++) {
    if (!/^(HeapFree|RtlFreeHeap)$/.test(calls.callees.name[calls.callee[i]])) continue;
    const mem = data.callArgs[i]?.p?.[2];
    if (!mem || !/^0x/.test(mem.v)) continue;
    const addr = hexNum(mem.v);
    if (!truth.allocs.some(x => hexNum(x.address) === addr && x.freed)) continue;
    const obj = index.objectAt(addr, calls.startEvt[i] - 1);
    assert.equal(obj?.kind, 'block', `HeapFree(${mem.v})`);
    assert.equal(data.blocks.addr[obj.b], addr);
    assert.equal(obj.offset, 0);
    checked++;
  }
  assert.ok(checked >= 3, `HeapFree calls checked: ${checked}`);
});
}

for (const name of ['fixture01', 'fixture86']) {
const trace = path.join(repo, 'fixtures', 'traces', `${name}.run`);
const truthFile = path.join(repo, 'fixtures', 'traces', `${name}.truth.json`);
const ready = await exists(trace) && await exists(truthFile) && await exists(analyzer);
const skip = ready ? false : `${name} not recorded or analyzer not built`;
let data, truth;
const buf = async file => { const b = await fs.readFile(path.join(data.dir, file)); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); };
function block(label) {
  const a = truth.allocs.find(x => x.label === label);
  for (let b = 0; b < data.blocks.count; b++)
    if (data.blocks.addr[b] === hexNum(a.address) && data.blocks.size[b] === a.size && data.blocks.allocEvt[b] !== NONE) return b;
  return NONE;
}

before(async () => {
  if (!ready) return;
  truth = JSON.parse(await fs.readFile(truthFile, 'utf8'));
  data = await analyzeTrace(trace, ['--no-symbols', '--activity', 'codefetch', '--snapshots', 'on']);
});
after(async () => { if (data) await fs.rm(data.dir, { recursive: true, force: true }); });

test(`${name}: the activity pass credits each block's writes to the code that made them`, { skip }, async () => {
  const m = data.manifest;
  assert.equal(m.activity.exec, 'codefetch');
  const cells = decodeActivity(await buf(m.files.activity.file)), writers = decodeWriters(await buf(m.files.writers.file));
  assert.equal(writers.count, m.activity.objects);
  let total = 0;
  for (let i = 0; i < cells.count; i++) total += cells.writes[i];
  let perObject = 0;
  for (let i = 0; i < writers.count; i++) perObject += writers.writes[i];
  assert.equal(total, m.activity.writes);
  assert.equal(perObject, m.activity.writes);
  const model = new ActivityModel(cells, data.series);
  const fixtureModule = m.modules.findIndex(x => /ttdscape-fixture/i.test(x.name));
  for (let i = 0; i < 10; i++) {
    const b = block(`p4.leak_b.${i}`);
    const w = [...writers.block].indexOf(b);
    assert.ok(w >= 0, `leak_b.${i} was written`);
    // memset is the last writer: the fixture's code, on the allocating thread, after the allocation.
    assert.equal(data.frames.module[writers.lastFrame[w]], fixtureModule, `leak_b.${i} last writer`);
    assert.equal(writers.lastThread[w], data.blocks.allocThread[b]);
    assert.ok(writers.lastEvt[w] >= data.blocks.allocEvt[b]);
    assert.equal(writers.flags[w] & 1, 0, 'written from inside modules');
    assert.ok(model.heat(b, writers.lastEvt[w]) > 0, 'glows when written');
  }
  // Flows between regions add up to the same writes, sorted by bucket.
  const flows = decodeFlows(await buf(m.files.flows.file));
  let flowWrites = 0;
  for (let i = 0; i < flows.count; i++) {
    flowWrites += flows.writes[i];
    if (i) assert.ok(flows.bucket[i] >= flows.bucket[i - 1]);
  }
  assert.equal(flowWrites, m.activity.writes);
  // leak_b's memset: flows from the fixture image into the process heap's region.
  const exeRegion = m.modules[fixtureModule].region;
  assert.ok([...Array(flows.count).keys()].some(i => flows.from[i] === exeRegion && flows.to[i] !== exeRegion), 'the fixture writes into other regions');
  // The fixture never runs code it wrote.
  const wx = JSON.parse(await fs.readFile(path.join(data.dir, 'wx.json'), 'utf8')).findings;
  assert.equal(wx.length, m.activity.findings);
  for (const f of wx) assert.ok(f.region === null || data.regions.kind[f.region] !== 4, 'no heap page ran');
});

test(`${name}: block snapshots hold the last contents and are searchable`, { skip }, async () => {
  const m = data.manifest;
  assert.equal(m.snapshots.cap, 4096);
  const index = decodeContentIndex(Buffer.from(await buf(m.files.contentsIdx.file)));
  const bytes = Buffer.from(await buf(m.files.contents.file));
  assert.equal(index.length, data.blocks.count);
  for (let i = 0; i < 10; i++) {
    const x = index[block(`p4.leak_b.${i}`)];
    assert.equal(x.length, 77);
    assert.equal(x.unknown, 0);
    assert.deepEqual([...bytes.subarray(x.offset, x.offset + 77)], Array(77).fill(0xB2), `leak_b.${i}`);
  }
  // HEAP_ZERO_MEMORY, never written after: zeros, all known.
  const z = index[block('p1.h100')];
  assert.equal(z.unknown, 0);
  assert.ok(bytes.subarray(z.offset, z.offset + 100).every(v => v === 0));
  // Capped at 4 KiB.
  assert.equal(index[block('p1.h1m')].length, 4096);
  // Search: the memset pattern finds exactly the ten leak_b blocks (plus leak_a's 0xA1 does not match).
  const found = await searchAnalysis(data.dir, { q: 'b2'.repeat(77), mode: 'hex' }, m.trace.arch === 'x86' ? 4 : 8);
  const blocks = new Set(found.matches.map(x => x.block));
  for (let i = 0; i < 10; i++) assert.ok(blocks.has(block(`p4.leak_b.${i}`)), `search finds leak_b.${i}`);
  assert.ok(!blocks.has(block('p4.leak_a')));
});
}
