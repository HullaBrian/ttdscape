// The CAPA pass (server/capa.mjs) on real analyzer output. Needs a built ttd-capa-cpp checkout
// (TTDSCAPE_TTDCAPA, default ../ttd-capa-cpp); skipped otherwise. Memory snapshots are written to
// TTDSCAPE_CAPA_WORK (default build/capa-work, the directory to exclude from antivirus) and removed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { repo, analyzer, exists, analyzeTrace } from './analyze.mjs';
import { locateTools, runCapa } from '../../server/capa.mjs';

const root = path.resolve(process.env.TTDSCAPE_TTDCAPA ?? path.join(repo, '..', 'ttd-capa-cpp'));
const tools = await locateTools(root);
const trace = path.join(repo, 'traces', 'beacon_x6401.run');
const skip = tools.missing ? `ttd-capa-cpp not built: ${tools.missing.join('; ')}` : !(await exists(trace)) || !(await exists(analyzer)) ? 'beacon trace or analyzer missing' : false;

test('CAPA matches on beacon are positioned on the event axis', { skip }, async () => {
  const data = await analyzeTrace(trace, ['--no-symbols']);
  const work = path.resolve(process.env.TTDSCAPE_CAPA_WORK ?? path.join(repo, 'build', 'capa-work'));
  await fs.mkdir(work, { recursive: true });
  const before = new Set(await fs.readdir(work));
  try {
    const stages = [];
    await runCapa({ trace, dir: data.dir, root, workRoot: work, onStage: s => stages.push(s) });
    const capa = JSON.parse(await fs.readFile(path.join(data.dir, 'capa.json'), 'utf8'));
    assert.equal(capa.available, true, capa.reason);
    assert.deepEqual(stages, ['capa: calls', 'capa: match', 'capa: code', 'capa: code match', 'capa: code hits', 'capa: timeline']);
    assert.ok(capa.counts.callRows > 100 && capa.counts.codeRows > 0, JSON.stringify(capa.counts));
    for (let k = 0; k < capa.rows.length; k++) {
      const row = capa.rows[k];
      assert.ok(capa.rules[row.r], 'rule index');
      if (row.src === 'call') {
        assert.ok(row.evt >= 0 && row.evt <= data.events.count, `row ${k} event`);
        assert.ok(row.thread !== null && row.thread < data.manifest.threads.length, `row ${k} thread`);
      }
    }
    // The C2 connection: rule, call, arguments and thread line up.
    const names = capa.rules.map(r => r.name);
    const connect = capa.rows.find(r => r.src === 'call' && names[r.r] === 'connect to HTTP server' && r.api === 'InternetConnectA');
    assert.ok(connect, 'connect to HTTP server on InternetConnectA');
    assert.match(connect.site, /lpszServerName="192\.168\.81\.129"/);
    // Executed-code matches from the unpacked payload, and the snapshots are cleaned up.
    assert.ok(capa.rows.some(r => r.src === 'code' && names[r.r] === 'create HTTP request'));
    assert.deepEqual((await fs.readdir(work)).filter(f => !before.has(f)), []);
  } finally {
    await fs.rm(data.dir, { recursive: true, force: true });
  }
});
