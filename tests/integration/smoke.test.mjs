// Model invariants on real traces in traces/ (whatever is there).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { repo, analyzer, exists, analyzeTrace, startServe } from './analyze.mjs';
import { TimeModel } from '../../client/state.js';
import { CallModel, CALL } from '../../client/calls.js';
import { AddressIndex } from '../../client/memory.js';
import { searchAnalysis } from '../../server/search.mjs';
import { decodeFlows } from '../../client/trace-reader.js';

const NONE = 0xFFFFFFFF;
const hexNum = h => Number.parseInt(h.slice(2), 16);
const dir = path.join(repo, 'traces');
const traces = (await exists(dir)) ? (await fs.readdir(dir)).filter(f => f.endsWith('.run')) : [];
const haveAnalyzer = await exists(analyzer);

for (const name of traces) {
  test(`invariants: ${name}`, { skip: haveAnalyzer ? false : 'analyzer not built' }, async () => {
    const data = await analyzeTrace(path.join(dir, name), ['--no-symbols', '--activity', 'codefetch', '--snapshots', 'on']);
    try {
      const { blocks, spans, regions, events, manifest } = data;
      assert.equal(events.count, manifest.counts.events);
      assert.ok(manifest.hooks.sites.length >= 10, 'hooks resolved');

      // Lifetimes are well-formed.
      for (let b = 0; b < blocks.count; b++) {
        if (blocks.allocEvt[b] !== NONE && blocks.freeEvt[b] !== NONE) assert.ok(blocks.allocEvt[b] <= blocks.freeEvt[b], `block ${b}`);
        if (blocks.allocEvt[b] !== NONE) assert.ok(blocks.allocEvt[b] < events.count);
      }
      for (let s = 0; s < spans.count; s++) {
        assert.ok(spans.start[s] < spans.end[s]);
        if (spans.startEvt[s] !== NONE && spans.endEvt[s] !== NONE) assert.ok(spans.startEvt[s] <= spans.endEvt[s]);
        assert.ok(spans.region[s] < regions.count);
      }

      // No two live heap blocks overlap at the end of the trace (or at the middle).
      const time = new TimeModel(data);
      for (const i of [Math.floor(events.count / 2), events.count - 1]) {
        const live = [...time.liveBlocksAt(i)].sort((a, b) => blocks.addr[a] - blocks.addr[b]);
        for (let k = 1; k < live.length; k++)
          assert.ok(blocks.addr[live[k]] >= blocks.addr[live[k - 1]] + blocks.size[live[k - 1]], `overlap at event ${i}`);
        // Spans of a live region never overlap at one instant.
        for (const r of time.liveRegionsAt(i)) {
          const ss = time.spansAt(r, i);
          for (let k = 1; k < ss.length; k++) assert.ok(spans.start[ss[k]] >= spans.end[ss[k - 1]], `span overlap in region ${r} at ${i}`);
        }
      }
      // The per-event live-bytes curve agrees with the analyzer's own series at the end.
      const series = data.series.columns.heapLive;
      assert.equal(time.heapLive[events.count - 1], series[series.length - 1]);
      assert.equal(manifest.quality.superseded, 0);

      // Calls into exports: ordered, and every endpoint resolves.
      const calls = data.exportCalls;
      assert.ok(calls && calls.count > 0, 'calls recorded');
      assert.equal(calls.count, manifest.calls.count);
      const model = new CallModel(calls);
      for (let i = 0; i < calls.count; i++) {
        if (i) assert.ok(model.t0[i] >= model.t0[i - 1], `call order at ${i}`);
        assert.ok(model.t1[i] >= model.t0[i], `call ${i}`);
        assert.ok(calls.callerFrame[i] < data.frames.count && calls.callee[i] < calls.callees.count);
        assert.ok(calls.callees.module[calls.callee[i]] < manifest.modules.length);
      }
      // The beacon's payload runs from unbacked memory and calls into system DLLs.
      if (name.startsWith('beacon')) {
        let unbacked = 0;
        for (let i = 0; i < calls.count; i++)
          if (calls.via[i] === NONE && data.frames.module[calls.callerFrame[i]] === NONE && !(calls.flags[i] & CALL.SameModule)) unbacked++;
        assert.ok(unbacked > 100, `cross-module calls from unbacked code: ${unbacked}`);
        // Its C2 connection, with arguments decoded from the WinINet signature.
        const connect = [...Array(calls.count).keys()].find(i => calls.callees.name[calls.callee[i]] === 'InternetConnectA');
        assert.ok(connect !== undefined, 'InternetConnectA called');
        const args = data.callArgs[connect];
        assert.equal(args.sig, 1);
        assert.equal(args.p.find(p => p.n === 'lpszServerName')?.s, '192.168.81.129');
        assert.equal(hexNum(args.p.find(p => p.n === 'nServerPort').v), 80);

        // The server name lives in memory the payload (unbacked code) wrote, and the query service
        // reads it back at the call.
        const server = hexNum(args.p.find(p => p.n === 'lpszServerName').v), at = calls.startEvt[connect] - 1;
        const obj = new AddressIndex(data, time).objectAt(server, at);
        assert.ok(obj, 'lpszServerName points into a block or region');
        const serve = await startServe(path.join(dir, name), data.dir);
        try {
          const mem = await serve.call('memory.read', { evt: at, addr: `0x${server.toString(16)}`, size: 15 });
          assert.equal(Buffer.from(mem.data, 'base64').toString('latin1'), '192.168.81.129\0');
          const lo = obj.kind === 'block' ? blocks.addr[obj.b] : server, hi = obj.kind === 'block' ? lo + blocks.size[obj.b] : server + 15;
          const from = obj.kind === 'block' && blocks.allocEvt[obj.b] !== NONE ? blocks.allocEvt[obj.b] - 1 : undefined;
          const acc = await serve.call('accesses.query', { lo: `0x${lo.toString(16)}`, hi: `0x${hi.toString(16)}`, from, to: at + 1 });
          const writes = acc.hits.filter(h => h.kind === 'w' && hexNum(h.addr) < server + 15 && hexNum(h.addr) + h.size > server);
          assert.ok(writes.length > 0, 'the server name was written during the trace');
          assert.ok(writes.some(h => h.module === null), `a writer runs from unbacked memory: ${JSON.stringify(writes.slice(0, 3))}`);
        } finally {
          serve.close();
        }

        // The payload region (0x1110000) ran code the loader stub (0x10c0000) wrote.
        const wx = JSON.parse(await fs.readFile(path.join(data.dir, 'wx.json'), 'utf8')).findings;
        const base = r => (r === null ? NaN : regions.base[r]);
        const payload = wx.filter(f => base(f.region) === 0x1110000);
        assert.ok(payload.length >= 40, `write-then-execute pages in the payload: ${payload.length}`);
        assert.ok(payload.every(f => base(f.write.region) === 0x10c0000), 'written by the loader stub');
        // Write flows: the loader stub writes the payload region.
        const fb = await fs.readFile(path.join(data.dir, 'flows.bin'));
        const flows = decodeFlows(fb.buffer.slice(fb.byteOffset, fb.byteOffset + fb.byteLength));
        let stubToPayload = 0;
        for (let i = 0; i < flows.count; i++) if (base(flows.from[i]) === 0x10c0000 && base(flows.to[i]) === 0x1110000) stubToPayload += flows.writes[i];
        assert.ok(stubToPayload > 100000, `writes from the stub into the payload: ${stubToPayload}`);
        // Content search finds the C2 address in the block lpszServerName points into.
        const found = await searchAnalysis(data.dir, { q: '192.168.81.129', mode: 'text' }, 8);
        assert.ok(found.matches.some(m => m.block === obj.b), 'the server-name block holds the C2 address');
      }
      // Activity totals are consistent on every trace.
      assert.equal(manifest.activity.findings, JSON.parse(await fs.readFile(path.join(data.dir, 'wx.json'), 'utf8')).findings.length);
      assert.ok(manifest.snapshots.blocks > 0);
    } finally {
      await fs.rm(data.dir, { recursive: true, force: true });
    }
  });
}
