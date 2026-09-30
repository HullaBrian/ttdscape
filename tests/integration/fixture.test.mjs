// Exact comparison of the analyzer's model with the fixture's own ground truth.
// Record the fixture first:  pwsh -File fixtures/record-fixture.ps1
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { repo, analyzer, exists, analyzeTrace } from './analyze.mjs';
import { TimeModel } from '../../client/state.js';
import { Stacks } from '../../client/stacks.js';
import { CallModel, CALL } from '../../client/calls.js';

const NONE = 0xFFFFFFFF;
const hexNum = h => Number.parseInt(h.slice(2), 16);

// fixture01 = x64 build, fixture86 = x86 (WoW64) build.
for (const name of ['fixture01', 'fixture86']) {
const trace = path.join(repo, 'fixtures', 'traces', `${name}.run`);
const truthFile = path.join(repo, 'fixtures', 'traces', `${name}.truth.json`);
const ready = await exists(trace) && await exists(truthFile) && await exists(analyzer);
const skip = ready ? false : `${name} not recorded (fixtures/record-fixture.ps1${name === 'fixture86' ? ' -Arch x86' : ''}) or analyzer not built`;
let data, truth, time, stacks, matched;

before(async () => {
  if (!ready) return;
  truth = JSON.parse(await fs.readFile(truthFile, 'utf8'));
  // Symbols for the fixture come from its own PDB next to the exe (local; no symbol server needed).
  data = await analyzeTrace(trace);
  time = new TimeModel(data);
  stacks = new Stacks(data);
  // Match each truth allocation to a block, in order: same address and size, earliest unused.
  const used = new Set();
  const order = [...Array(data.blocks.count).keys()].sort((a, b) => (data.blocks.allocEvt[a] >>> 0) - (data.blocks.allocEvt[b] >>> 0));
  matched = new Map();
  let lastEvt = -1;
  for (const a of truth.allocs) {
    const addr = hexNum(a.address);
    const b = order.find(x => !used.has(x) && data.blocks.addr[x] === addr && data.blocks.size[x] === a.size &&
      data.blocks.allocEvt[x] !== NONE && data.blocks.allocEvt[x] > lastEvt - 1000000);
    if (b !== undefined) { used.add(b); matched.set(a.label, b); }
  }
});

after(async () => { if (data) await fs.rm(data.dir, { recursive: true, force: true }); });

test(`${name}: every scripted allocation is found with its exact address and size`, { skip }, () => {
  const missing = truth.allocs.filter(a => !matched.has(a.label)).map(a => a.label);
  assert.deepEqual(missing, []);
});

test(`${name}: frees and the leak set match`, { skip }, () => {
  for (const a of truth.allocs) {
    const b = matched.get(a.label);
    assert.equal(data.blocks.freeEvt[b] !== NONE, a.freed, `${a.label} freed=${a.freed}`);
  }
  const leakedTruth = truth.allocs.filter(a => !a.freed).map(a => matched.get(a.label)).sort();
  const leakedModel = new Set();
  for (const g of time.leaks(stacks)) for (const b of g.blocks) leakedModel.add(b);
  for (const b of leakedTruth) assert.ok(leakedModel.has(b), `block ${b} should be outstanding at the end`);
});

test(`${name}: realloc chains, heap identity and destroy semantics`, { skip }, () => {
  for (const a of truth.allocs.filter(x => x.prev)) {
    assert.equal(data.blocks.prev[matched.get(a.label)], matched.get(a.prev), `${a.label}.prev`);
  }
  const heapOf = l => data.manifest.heaps[data.blocks.heap[matched.get(l)]];
  assert.equal(heapOf('p1.h16').kind, 'created');
  assert.equal(heapOf('p4.leak_b.0').kind, 'process');
  assert.equal(heapOf('p4.leak_b.0').handle, truth.processHeap);
  for (const l of ['p1.h100', 'p1.h4k', 'p2.blocker', 'p2.a.grown'])
    assert.ok(data.blocks.flags[matched.get(l)] & 0x04, `${l} freed by HeapDestroy`);
  assert.ok(data.blocks.flags[matched.get('p7.cross')] & 0x40, 'cross-thread free');
});

test(`${name}: virtual memory regions and views`, { skip }, () => {
  const { regions, spans } = data;
  // Addresses are reused after a release, so a region is identified by base, kind and size.
  const regionAt = (base, kind, size) => [...Array(regions.count).keys()].filter(r => regions.base[r] === base &&
    (kind === undefined || regions.kind[r] === kind) && (size === undefined || regions.size[r] === size));
  const r = x => truth.regions.find(g => g.label === x);

  const reserve = regionAt(hexNum(r('p5.reserve').base), 0, 1 << 20);
  assert.equal(reserve.length, 1, 'p5.reserve region');
  assert.equal(regions.size[reserve[0]], 1 << 20);
  assert.notEqual(regions.releaseEvt[reserve[0]], NONE);
  const inRegion = s => spans.region[s] === reserve[0];
  const com = hexNum(r('p5.commit').base);
  const commitSpans = [...Array(spans.count).keys()].filter(s => inRegion(s) && spans.start[s] === com && spans.end[s] === com + 0x10000 && spans.state[s] === 2);
  assert.deepEqual(commitSpans.map(s => spans.protect[s]).sort(), [0x02, 0x04], 'RW commit, then READONLY');
  const odd = hexNum(r('p5.odd').base);
  assert.ok([...Array(spans.count).keys()].some(s => inRegion(s) && spans.start[s] === odd && spans.end[s] === odd + 0x1000 && spans.state[s] === 2), 'odd commit rounded to its page');

  const rc = regionAt(hexNum(r('p5.rc').base), 0, 0x3000);
  assert.equal(rc.length, 1, 'p5.rc region');
  assert.equal(regions.size[rc[0]], 0x3000);
  assert.equal(regions.releaseEvt[rc[0]], NONE);

  const v1 = regionAt(hexNum(r('p6.view1').base), 1, 256 * 1024);
  assert.equal(v1.length, 1, 'p6.view1');
  assert.equal(regions.size[v1[0]], 256 * 1024);
  assert.notEqual(regions.releaseEvt[v1[0]], NONE);
  const v2 = regionAt(hexNum(r('p6.view2').base), 1, 64 * 1024);
  assert.equal(v2.length, 1, 'p6.view2');
  assert.equal(regions.size[v2[0]], 64 * 1024);
  assert.equal(regions.releaseEvt[v2[0]], NONE);
});

test(`${name}: OldProtect is recovered or consistent with the model`, { skip }, () => {
  const com = hexNum(truth.regions.find(g => g.label === 'p5.commit').base);
  const call = data.calls.find(c => c.kind === 'NtProtectVirtualMemory' && c.out?.base && hexNum(c.out.base.value) === com);
  assert.ok(call, 'NtProtectVirtualMemory call for p5.commit');
  const expected = truth.oldProtects.find(o => o.label === 'p5.protect').value;
  if (call.out.oldProtect.src !== 'unknown') assert.equal(hexNum(call.out.oldProtect.value), expected);
});

test(`${name}: allocation stacks are symbolized and survive exception unwinds`, { skip }, () => {
  const site = l => stacks.siteText(data.blocks.allocStack[matched.get(l)]);
  assert.match(site('p4.leak_b.3'), /leak_b/);
  assert.match(site('p4.leak_a'), /leak_a/);
  const after = stacks.describe(data.blocks.allocStack[matched.get('p8.after')]).map(f => f.text).join(' | ');
  assert.match(after, /after_unwind_alloc/);
  assert.doesNotMatch(after, /throw_after_alloc|middle_frame/, 'frames unwound by the exception must be gone');
  const thrown = stacks.describe(data.blocks.allocStack[matched.get('p8.thrown')]).map(f => f.text).join(' | ');
  assert.match(thrown, /throw_after_alloc/);
});

test(`${name}: phase markers and capture quality`, { skip }, () => {
  const phases = data.manifest.markers.map(m => m.text).filter(t => t.startsWith('TTDSCAPE:PHASE'));
  assert.equal(phases.length, 10);
  assert.ok(phases[0].includes('PHASE 1'));
  const q = data.manifest.quality;
  assert.equal(q.outParams.unknown, 0);
  assert.equal(q.superseded, 0);
  assert.equal(q.doubleFree, 0);
  // Markers are ordered in the timeline.
  const evts = data.manifest.markers.map(m => m.evt);
  assert.deepEqual(evts, [...evts].sort((a, b) => a - b));
});

test(`${name}: calls into exports (call beams)`, { skip }, () => {
  const calls = data.exportCalls;
  assert.ok(calls && calls.count > 0, 'calls recorded');
  const { modules, markers } = data.manifest;
  const exe = modules.findIndex(m => /ttdscape-fixture/i.test(m.name));
  assert.ok(exe >= 0);
  const phase = n => markers.find(m => m.text.includes(`PHASE ${n}`));
  // Calls between two markers: started after the first marker event, before the next one.
  const within = (n, next) => [...Array(calls.count).keys()].filter(i => calls.startEvt[i] > phase(n).evt && calls.startEvt[i] <= phase(next).evt);
  const fromExe = i => calls.via[i] === NONE && data.frames.module[calls.callerFrame[i]] === exe;
  const to = (i, fn) => modules[calls.callees.module[calls.callee[i]]].name.toLowerCase() === 'ntdll.dll' && calls.callees.name[calls.callee[i]] === fn;

  // Phase 1: the fixture's four HeapAlloc calls reach ntdll!RtlAllocateHeap (kernel32 forwards the export).
  const p1 = within(1, 2).filter(i => fromExe(i) && to(i, 'RtlAllocateHeap'));
  assert.equal(p1.length, 4, 'phase 1 exe -> RtlAllocateHeap');
  assert.ok(p1.every(i => !(calls.flags[i] & CALL.SameModule) && calls.flags[i] & CALL.Returned));
  // Caller frames share the stack symbolization.
  assert.match(stacks.frameText(calls.callerFrame[p1[0]]), /fixture|main|phase/i);

  // Phase 7: the worker thread's allocation is a call on another thread than the marker's.
  const p7 = within(7, 8).filter(i => fromExe(i) && to(i, 'RtlAllocateHeap'));
  const mainThread = phase(7).thread;
  assert.ok(p7.some(i => calls.thread[i] !== mainThread), 'worker-thread call');
  assert.ok(p7.some(i => calls.thread[i] === mainThread) || within(7, 8).some(i => calls.thread[i] === mainThread));

  // Phase 9: on x64 tail_alloc jumps through the import table (a tail call from main's code); the
  // x86 build cannot tail-call a stdcall import from a cdecl function and CALLs it.
  const p9 = within(9, 'END').filter(i => to(i, 'RtlAllocateHeap') && fromExe(i));
  assert.equal(p9.length, 1, 'phase 9 call into RtlAllocateHeap');
  assert.equal(Boolean(calls.flags[p9[0]] & CALL.Tail), name === 'fixture01', 'entered by a jump on x64 only');
  // kernel32!HeapFree reaches ntdll!RtlFreeHeap: directly (IAT forwarder) or by a jump chained to the kernel32 call.
  const frees = within(9, 'END').filter(i => to(i, 'RtlFreeHeap'));
  assert.ok(frees.length >= 1 && frees.every(i => calls.via[i] === NONE ? fromExe(i) : calls.flags[i] & CALL.Tail));

  // Arguments are decoded from the API signature: HeapAlloc(heap, flags, size) reaches
  // RtlAllocateHeap(HeapHandle, Flags, Size), and each call returned the address the fixture saw.
  assert.equal(data.callArgs.length, calls.count);
  const labels = ['p1.h16', 'p1.h100', 'p1.h4k', 'p1.h1m'];
  const flags = [0, 8, 0, 0]; // HEAP_ZERO_MEMORY for the 100-byte block
  p1.forEach((i, k) => {
    const a = data.callArgs[i];
    assert.equal(a.sig, 1, 'RtlAllocateHeap has a signature (phnt)');
    assert.deepEqual(a.p.map(p => p.n), ['HeapHandle', 'Flags', 'Size']);
    const truthAlloc = truth.allocs.find(x => x.label === labels[k]);
    assert.equal(hexNum(a.p[2].v), truthAlloc.size, `${labels[k]} size`);
    assert.equal(hexNum(a.p[1].v), flags[k], `${labels[k]} flags`);
    assert.equal(hexNum(a.ret), hexNum(truthAlloc.address), `${labels[k]} returned its block`);
  });
  // The four calls use the heap HeapCreate returned.
  assert.equal(new Set(p1.map(i => data.callArgs[i].p[0].v)).size, 1);

  // Time is consistent: sorted by start, and no call returns before it starts.
  const model = new CallModel(calls);
  for (let i = 1; i < calls.count; i++) assert.ok(model.t0[i] >= model.t0[i - 1], `order at ${i}`);
  for (let i = 0; i < calls.count; i++) assert.ok(model.t1[i] >= model.t0[i], `call ${i} returns before it starts`);
  for (let i = 0; i < calls.count; i++) if (calls.via[i] !== NONE) assert.ok(calls.via[i] < calls.count && calls.flags[i] & CALL.Tail);
});
}
