import { test } from 'node:test';
import assert from 'node:assert/strict';
import { capaRows, eventAt, parsePosition, formatReportCall } from '../../server/capa.mjs';

function positions(list) {
  const buf = Buffer.alloc(list.length * 16);
  list.forEach(([seq, steps], i) => { buf.writeBigUInt64LE(BigInt(seq), i * 16); buf.writeBigUInt64LE(BigInt(steps), i * 16 + 8); });
  return buf;
}

test('positions parse and map to the first event at or after them', () => {
  assert.deepEqual(parsePosition('1EA:6F8'), [0x1ea, 0x6f8]);
  assert.equal(parsePosition(''), null);
  const p = positions([[1, 10], [1, 20], [2, 0]]);
  assert.equal(eventAt(p, [0, 5]), 0);
  assert.equal(eventAt(p, [1, 10]), 0);
  assert.equal(eventAt(p, [1, 11]), 1);
  assert.equal(eventAt(p, [1, 0xffff]), 2);
  assert.equal(eventAt(p, [3, 0]), 3);
});

test('calls are formatted like ttd-timeline', () => {
  assert.equal(formatReportCall({ module: 'wininet', api: 'InternetConnectA', ret: 12,
    params: [{ name: 'lpszServerName', value: 5, str: '10.0.0.1' }, { name: 'dwFlags', value: 0, flags: ['A', 'B'] }, { name: 'p', value: 16, deref: 1, at_return: true }] }),
  'wininet.InternetConnectA(lpszServerName="10.0.0.1", dwFlags=A|B, p=0x10->0x1@ret) -> 0xc');
  assert.equal(formatReportCall({ api: 'X', args: [-2, 'a'] }), 'X(0xfffffffffffffffe, "a")');
});

test('capa matches become positioned rows, with code hits and scope-level rules', () => {
  const report = { processes: [{ ppid: 0, pid: 9, calls: [
    { tid: 2, seq: 5, position: '1:30', api: 'B', module: 'm' },
    { tid: 2, seq: 1, position: '1:10', api: 'A', module: 'm' },
    { tid: 3, seq: 2, position: '1:20', api: 'C', module: 'n' },
  ] }] };
  const doc = { rules: {
    'rule one': { meta: { namespace: 'ns/one', attack: [{ id: 'T1', tactic: 'x', technique: 'y' }], mbc: [{ id: 'B1' }] },
      matches: [[{ type: 'call', value: [0, 9, 2, 0] }, {}], [{ type: 'call', value: [0, 9, 2, 1] }, {}], [{ type: 'call', value: [0, 9, 2, 7] }, {}]] },
    'rule two': { meta: { namespace: 'ns/two' }, matches: [[{ type: 'process', value: [0, 9] }, {}]] },
    'helper': { meta: { namespace: 'internal/x' }, matches: [[{ type: 'call', value: [0, 9, 3, 0] }, {}]] },
    'lib rule': { meta: { lib: true }, matches: [[{ type: 'call', value: [0, 9, 3, 0] }, {}]] },
  } };
  const codeRecords = [{ rule: 'code rule', namespace: 'ns/code', vas: [0x401000], base: 0x400000, position: '0:1' },
    { rule: 'data rule', namespace: 'ns/data', vas: [], base: 0x400000, offset: 0x10, position: '0:2' },
    { rule: 'data rule', namespace: 'ns/data', vas: [], base: 0x500000, offset: null, position: '0:3' }];
  const codeHits = [{ va: 0x401000, position: '1:15', tid: 3, hits: 4 }];
  const out = capaRows({ report, doc, codeRecords, codeHits, eventOf: ([s, t]) => s * 100 + t, threadOf: utid => utid - 1 });
  assert.deepEqual(out.rules.map(r => r.name), ['rule one', 'rule two', 'code rule', 'data rule']);
  assert.deepEqual(out.rules[0].attack.map(a => a.id), ['T1']);
  assert.deepEqual(out.scope, [1]);
  // Sorted by position; calls addressed by per-thread seq order; the out-of-range id is dropped.
  assert.deepEqual(out.rows.map(r => [r.pos, r.src, out.rules[r.r].name]), [
    ['0:2', 'code', 'data rule'], ['0:3', 'code', 'data rule'], ['1:10', 'call', 'rule one'], ['1:15', 'code', 'code rule'], ['1:30', 'call', 'rule one']]);
  const call = out.rows[2];
  assert.equal(call.site, 'm.A()');
  assert.equal(call.evt, 116); // positions are hex: 1:10 = [1, 0x10]
  assert.equal(call.thread, 1);
  assert.equal(out.rows[3].site, 'code@0x401000 (4x)');
  assert.equal(out.rows[1].site, 'code@0x500000 (region)'); // offset may be null
  assert.equal(out.rows[0].site, 'code@0x400000+0x10 (region)');
});
