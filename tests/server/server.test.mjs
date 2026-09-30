import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from '../../server/index.mjs';
import { loadConfig } from '../../server/config.mjs';
import { parseRange } from '../../server/static.mjs';
import { cacheKey, normalizeOptions } from '../../server/jobs.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
let tmp, base, server, jobs;

async function api(p, init = {}) {
  const res = await fetch(base + p, { ...init, headers: { 'X-TTDscape': '1', 'Content-Type': 'application/json', ...init.headers } });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, body, headers: res.headers };
}

async function waitFor(id, states) {
  for (let i = 0; i < 200; i++) {
    const { body } = await api(`/api/analyses/${id}`);
    if (states.includes(body.state)) return body;
    await new Promise(r => setTimeout(r, 25));
  }
  throw new Error(`analysis ${id} never reached ${states}`);
}

before(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ttdscape-server-'));
  await fs.mkdir(path.join(tmp, 'traces'));
  await fs.mkdir(path.join(tmp, 'static'));
  await fs.writeFile(path.join(tmp, 'static', 'index.html'), '<!doctype html><title>t</title>');
  for (const [name, content] of [['ok.run', 'ok'], ['bad.run', 'fail'], ['slow.run', 'slow'], ['notes.txt', 'x']])
    await fs.writeFile(path.join(tmp, 'traces', name), content);
  const config = loadConfig({
    TTDSCAPE_PORT: '0', TTDSCAPE_CACHE: path.join(tmp, 'cache'), TTDSCAPE_STATIC: path.join(tmp, 'static'),
    TTDSCAPE_ANALYZER: `${process.execPath}|${path.join(here, '..', 'fake-analyzer.mjs')}`,
    TTDSCAPE_TRACE_ROOTS: path.join(tmp, 'traces'),
    TTDSCAPE_TTDCAPA: path.join(tmp, 'no-ttd-capa'), TTDSCAPE_CAPA_WORK: path.join(tmp, 'capa-work'),
  });
  ({ server, jobs } = await startServer(config));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  server?.close();
  server?.closeAllConnections?.();
  await fs.rm(tmp, { recursive: true, force: true });
});

test('health and static fallback', async () => {
  assert.equal((await api('/api/health')).status, 200);
  const page = await fetch(`${base}/some/client/route`);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /<title>t<\/title>/);
  assert.match(page.headers.get('content-security-policy'), /default-src 'self'/);
});

test('rejects state changes without the custom header or with a foreign origin', async () => {
  const noHeader = await fetch(`${base}/api/analyses`, { method: 'POST', body: '{}' });
  assert.equal(noHeader.status, 403);
  const foreign = await api('/api/analyses', { method: 'POST', body: '{}', headers: { Origin: 'http://evil.example' } });
  assert.equal(foreign.status, 403);
});

test('lists traces under the configured roots only', async () => {
  const { body } = await api('/api/traces');
  assert.deepEqual(body.traces.map(t => t.name).sort(), ['bad.run', 'ok.run', 'slow.run']);
  assert.equal((await api(`/api/traces?dir=${encodeURIComponent(os.tmpdir())}`)).status, 403);
});

test('validates trace paths', async () => {
  const post = trace => api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace }) });
  assert.equal((await post('relative.run')).status, 400);
  assert.equal((await post(path.join(tmp, 'traces', 'notes.txt'))).status, 400);
  assert.equal((await post(path.join(tmp, 'traces', 'missing.run'))).status, 404);
  const outside = path.join(tmp, 'outside.run');
  await fs.writeFile(outside, 'ok');
  assert.equal((await post(outside)).status, 403);
});

test('analyzes, caches, serves files with ranges, and deletes', async () => {
  const trace = path.join(tmp, 'traces', 'ok.run');
  const first = await api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace, options: { stackDepth: 12 } }) });
  assert.equal(first.status, 202);
  const done = await waitFor(first.body.id, ['ready', 'failed']);
  assert.equal(done.state, 'ready', done.error);
  assert.equal(done.summary.arch, 'x64');

  const again = await api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace, options: { stackDepth: 12 } }) });
  assert.equal(again.status, 200);
  assert.equal(again.body.id, first.body.id);

  const events = await fetch(`${base}/api/analyses/${done.id}/files/events.bin`);
  assert.equal(events.status, 200);
  assert.equal((await events.arrayBuffer()).byteLength, 96);
  const part = await fetch(`${base}/api/analyses/${done.id}/files/events.bin`, { headers: { Range: 'bytes=32-63' } });
  assert.equal(part.status, 206);
  assert.equal(part.headers.get('content-range'), 'bytes 32-63/96');
  assert.equal((await part.arrayBuffer()).byteLength, 32);
  const etag = events.headers.get('etag');
  assert.equal((await fetch(`${base}/api/analyses/${done.id}/files/events.bin`, { headers: { 'If-None-Match': etag } })).status, 304);
  assert.equal((await fetch(`${base}/api/analyses/${done.id}/files/job.json`)).status, 404);

  const args = JSON.parse(await fs.readFile(path.join(tmp, 'cache', done.id, 'args.json'), 'utf8'));
  assert.deepEqual(args.slice(3, 5), ['--stack-depth', '12']);
  // Without ttd-capa-cpp the CAPA pass records why, and the analysis is still ready.
  const capa = await api(`/api/analyses/${done.id}/files/capa.json`);
  assert.equal(capa.status, 200);
  assert.equal(capa.body.available, false);
  assert.match(capa.body.reason, /not found/);
  assert.deepEqual(args.slice(args.indexOf('--calls'), args.indexOf('--calls') + 2), ['--calls', 'exports']);

  // A different option set is a different analysis.
  const other = await api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace, options: { stackDepth: 13 } }) });
  assert.notEqual(other.body.id, first.body.id);
  await waitFor(other.body.id, ['ready']);

  assert.equal((await api(`/api/analyses/${done.id}`, { method: 'DELETE' })).status, 200);
  assert.equal((await api(`/api/analyses/${done.id}`)).status, 404);
  await assert.rejects(fs.access(path.join(tmp, 'cache', done.id)));
});

test('reports analyzer failures', async () => {
  const res = await api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace: path.join(tmp, 'traces', 'bad.run') }) });
  const done = await waitFor(res.body.id, ['failed', 'ready']);
  assert.equal(done.state, 'failed');
  assert.equal(done.error, 'synthetic failure');
  // A failed analysis can be retried.
  const retry = await api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace: path.join(tmp, 'traces', 'bad.run') }) });
  assert.equal(retry.status, 202);
  await waitFor(retry.body.id, ['failed']);
});

test('streams progress and cancels a running analysis', async () => {
  const res = await api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace: path.join(tmp, 'traces', 'slow.run') }) });
  const id = res.body.id;
  const controller = new AbortController();
  const stream = await fetch(`${base}/api/analyses/${id}/progress`, { signal: controller.signal });
  assert.equal(stream.headers.get('content-type'), 'text/event-stream');
  const reader = stream.body.getReader();
  let text = '';
  while (!text.includes('"fraction"') && !text.includes('"progress":0.6')) {
    const { value, done } = await reader.read();
    if (done) break;
    text += new TextDecoder().decode(value);
  }
  assert.match(text, /"stage":"capture"/);
  controller.abort();
  assert.equal((await api(`/api/analyses/${id}`, { method: 'DELETE' })).status, 200);
  assert.equal(jobs.running?.id === id, false);
});

test('cache survives a restart', async () => {
  const trace = path.join(tmp, 'traces', 'ok.run');
  const res = await api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace }) });
  const done = await waitFor(res.body.id, ['ready']);
  const { JobManager } = await import('../../server/jobs.mjs');
  const fresh = new JobManager({ ...jobs.config });
  await fresh.init();
  assert.equal(fresh.get(done.id)?.state, 'ready');
});

test('range parsing and cache keys', () => {
  assert.deepEqual(parseRange('bytes=0-9', 100), { start: 0, end: 9 });
  assert.deepEqual(parseRange('bytes=90-', 100), { start: 90, end: 99 });
  assert.deepEqual(parseRange('bytes=-10', 100), { start: 90, end: 99 });
  assert.equal(parseRange('bytes=200-300', 100).invalid, true);
  assert.equal(parseRange(undefined, 100), null);
  const stat = { size: 10, mtimeMs: 1000 };
  const a = cacheKey('C:\\T\\a.run', stat, '1', normalizeOptions({}));
  assert.equal(a, cacheKey('c:\\t\\A.RUN', stat, '1', normalizeOptions({})));
  assert.notEqual(a, cacheKey('C:\\T\\a.run', { ...stat, mtimeMs: 2000 }, '1', normalizeOptions({})));
  assert.equal(normalizeOptions({ stackDepth: 9999 }).stackDepth, 256);
  // The recorded call scope changes the output, so it is part of the key.
  assert.equal(normalizeOptions({}).calls, 'exports');
  assert.equal(normalizeOptions({ calls: 'bogus' }).calls, 'exports');
  assert.equal(normalizeOptions({}).callArgs, true);
  assert.equal(normalizeOptions({ calls: 'none' }).callArgs, false);
  assert.notEqual(a, cacheKey('C:\\T\\a.run', stat, '1', normalizeOptions({ callArgs: false })));
  assert.notEqual(a, cacheKey('C:\\T\\a.run', stat, '1', normalizeOptions({ calls: 'none' })));
});

test('memory and access queries go through one query process per analysis', async () => {
  const trace = path.join(tmp, 'traces', 'ok.run');
  const res = await api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace, options: { stackDepth: 20 } }) });
  const { id } = await waitFor(res.body.id, ['ready']);
  const dir = path.join(tmp, 'cache', id);

  const mem = await api(`/api/analyses/${id}/memory?evt=5&addr=0x1010&size=4`);
  assert.equal(mem.status, 200, JSON.stringify(mem.body));
  assert.deepEqual([...Buffer.from(mem.body.data, 'base64')], [0x10, 0x11, 0x12, 0x13]);
  assert.equal((await api(`/api/analyses/${id}/memory?pos=1A:2&addr=0x20&size=2`)).status, 200);
  for (const bad of ['evt=1&addr=1234', 'evt=1&addr=0x10&size=0', 'evt=1&addr=0x10&size=70000', 'evt=x&addr=0x10', 'pos=zz&addr=0x10'])
    assert.equal((await api(`/api/analyses/${id}/memory?${bad}`)).status, 400, bad);

  // Accesses: validated, progress on the analysis's event stream, cached by parameters.
  const post = body => api(`/api/analyses/${id}/accesses`, { method: 'POST', body: JSON.stringify(body) });
  for (const bad of [{ lo: '0x20', hi: '0x10' }, { lo: '0x0', hi: '0x200000' }, { lo: 10, hi: 20 }, { lo: '0x0', hi: '0x10', from: 5, to: 2 }])
    assert.equal((await post(bad)).status, 400, JSON.stringify(bad));
  const controller = new AbortController();
  const stream = await fetch(`${base}/api/analyses/${id}/progress`, { signal: controller.signal });
  const first = await post({ lo: '0x1000', hi: '0x1040', from: 0 });
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(first.body.cached, false);
  assert.equal(first.body.hits.length, 4);
  const reader = stream.body.getReader();
  let text = '';
  while (!text.includes('"type":"accesses"')) text += new TextDecoder().decode((await reader.read()).value);
  controller.abort();
  const again = await post({ lo: '0x1000', hi: '0x1040', from: 0 });
  assert.equal(again.body.cached, true);
  assert.equal(again.body.key, first.body.key);
  assert.deepEqual(again.body.hits, first.body.hits);
  // A memory lane and an accesses lane.
  assert.equal(await fs.readFile(path.join(dir, 'serve-starts.txt'), 'utf8'), 'xx');

  // A client that gives up stops the replay; the next query starts a new process.
  const abort = new AbortController();
  const pending = fetch(`${base}/api/analyses/${id}/accesses`, { method: 'POST', signal: abort.signal,
    headers: { 'X-TTDscape': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ lo: '0xdead', hi: '0xdeaf' }) });
  await new Promise(r => setTimeout(r, 200));
  abort.abort();
  await assert.rejects(pending);
  await new Promise(r => setTimeout(r, 200));
  assert.equal([...jobs.queries.processes.keys()].some(k => k === `${id}|accesses`), false);
  assert.equal((await post({ lo: '0x2000', hi: '0x2010' })).body.hits.length, 1);

  // Deleting the analysis stops its query processes.
  assert.equal((await api(`/api/analyses/${id}`, { method: 'DELETE' })).status, 200);
  assert.equal([...jobs.queries.processes.keys()].some(k => k.startsWith(id)), false);
  assert.equal((await api(`/api/analyses/${id}/memory?evt=1&addr=0x10`)).status, 404);
});

test('activity and snapshots are opt-in analysis options, and snapshots are searchable', async () => {
  assert.equal(normalizeOptions({}).activity, false);
  assert.equal(normalizeOptions({}).snapshots, false);
  const stat = { size: 10, mtimeMs: 1000 };
  assert.notEqual(cacheKey('C:\T\a.run', stat, '1', normalizeOptions({})), cacheKey('C:\T\a.run', stat, '1', normalizeOptions({ snapshots: true })));
  assert.notEqual(cacheKey('C:\T\a.run', stat, '1', normalizeOptions({})), cacheKey('C:\T\a.run', stat, '1', normalizeOptions({ activity: true })));

  const trace = path.join(tmp, 'traces', 'ok.run');
  const plain = await waitFor((await api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace, options: { stackDepth: 30 } }) })).body.id, ['ready']);
  const args = JSON.parse(await fs.readFile(path.join(tmp, 'cache', plain.id, 'args.json'), 'utf8'));
  assert.deepEqual(args.slice(args.indexOf('--activity'), args.indexOf('--activity') + 4), ['--activity', 'off', '--snapshots', 'off']);
  assert.equal((await api(`/api/analyses/${plain.id}/search?q=hello`)).status, 409);

  const res = await api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace, options: { stackDepth: 30, activity: true, snapshots: true } }) });
  const { id } = await waitFor(res.body.id, ['ready']);
  const search = async q => (await api(`/api/analyses/${id}/search?${q}`)).body;
  assert.deepEqual((await search('q=C2%20192.168.1.1')).matches.map(m => [m.block, m.offset, m.pattern]), [[0, 6, 'ascii']]);
  assert.deepEqual((await search('q=HELLO')).matches.map(m => m.block), [0]);
  assert.deepEqual((await search('q=0x401000&mode=pointer')).matches.map(m => [m.block, m.offset]), [[1, 4]]);
  assert.deepEqual((await search('q=00104000&mode=hex')).matches.map(m => [m.block, m.offset]), [[1, 4]]);
  assert.deepEqual((await search('q=absent')).matches, []);
  for (const bad of ['q=', 'q=zz&mode=hex', 'q=x&mode=regex', 'q=0x1ffffffffffffffff&mode=pointer'])
    assert.equal((await api(`/api/analyses/${id}/search?${bad}`)).status, 400, bad);
  const files = await fetch(`${base}/api/analyses/${id}/files/contents.idx`);
  assert.equal(files.status, 200);
});
