// CAPA results for an analysis, using a ttd-capa-cpp checkout (https://github.com/ - see its README):
//   1. ttdcapa-extract <trace> -o report.json        API calls with decoded arguments
//   2. capa-cpp report.json -r rules -j                 capabilities matched on those calls
//   3. ttdcapa-extract --scan-code, capa-cpp --scan-code-manifest, ttdcapa-extract --trace-code-hits
//                                                       capabilities in code the program created and
//                                                       ran, positioned where the matched code executed
// Every match is written to capa.json with its TTD position and the event index it precedes.
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

export const CAPA_VERSION = 1;

async function newest(paths) {
  let best = null;
  for (const p of paths) {
    try {
      const st = await fs.stat(p);
      if (st.isFile() && (!best || st.mtimeMs > best.mtime)) best = { p, mtime: st.mtimeMs };
    } catch { /* missing */ }
  }
  return best?.p ?? null;
}

// Locates the built tools in a ttd-capa-cpp checkout. Returns { extractor, capaCpp, rules } or
// { missing: [...] }.
export async function locateTools(root) {
  const extractor = await newest(['Release', 'Debug'].map(c => path.join(root, 'ttd', 'bin', 'x64', c, 'ttdcapa-extract.exe')));
  const capaCpp = await newest(['build', 'x64'].flatMap(d => ['Release', 'Debug'].flatMap(c =>
    [path.join(root, 'capa-cpp', d, c, 'capa-cpp.exe'), path.join(root, 'capa-cpp', 'capa-cpp', d, c, 'capa-cpp.exe')])));
  const rules = path.join(root, 'rules');
  const haveRules = await fs.stat(rules).then(s => s.isDirectory(), () => false);
  const missing = [];
  if (!extractor) missing.push(`ttdcapa-extract.exe (build ${path.join(root, 'ttd')})`);
  if (!capaCpp) missing.push(`capa-cpp.exe (build ${path.join(root, 'capa-cpp')})`);
  if (!haveRules) missing.push(`capa rules (${rules})`);
  return missing.length ? { missing } : { extractor, capaCpp, rules };
}

// ---- pure mapping (tested in tests/server) ----

export function parsePosition(text) {
  if (!text || !text.includes(':')) return null;
  const [seq, steps] = text.split(':');
  const s = Number.parseInt(seq, 16), t = Number.parseInt(steps, 16);
  return Number.isFinite(s) && Number.isFinite(t) ? [s, t] : null;
}

const posLess = (a, b) => a[0] !== b[0] ? a[0] < b[0] : a[1] < b[1];

// First event at or after a position, from positions.bin (u64 seq, u64 steps per event).
export function eventAt(positionsBuf, pos) {
  const view = new DataView(positionsBuf.buffer ?? positionsBuf, positionsBuf.byteOffset ?? 0, positionsBuf.byteLength);
  const n = Math.floor(view.byteLength / 16);
  const at = i => [view.getUint32(i * 16, true) + view.getUint32(i * 16 + 4, true) * 4294967296,
    view.getUint32(i * 16 + 8, true) + view.getUint32(i * 16 + 12, true) * 4294967296];
  let lo = 0, hi = n;
  while (lo < hi) { const mid = (lo + hi) >>> 1; if (posLess(at(mid), pos)) lo = mid + 1; else hi = mid; }
  return lo;
}

const hex = v => typeof v === 'number' ? `0x${(v < 0 ? BigInt.asUintN(64, BigInt(v)) : BigInt(v)).toString(16)}` : JSON.stringify(v);

function formatParam(p) {
  let value;
  if (p.str !== undefined && p.str !== null) value = JSON.stringify(p.str);
  else if (p.flags?.length) value = p.flags.join('|');
  else if (p.float !== undefined) value = String(p.float);
  else {
    value = hex(p.value);
    if (p.deref !== undefined) value += `->${hex(p.deref)}`;
  }
  if (p.at_return) value += '@ret';
  return p.name ? `${p.name}=${value}` : value;
}

// "module.api(args) -> ret", as ttd-timeline prints a triggering call.
export function formatReportCall(call, max = 400) {
  const args = call.params ? call.params.map(formatParam) : (call.args ?? []).map(hex);
  const text = `${call.module ? `${call.module}.` : ''}${call.api ?? ''}(${args.join(', ')})${call.ret !== undefined && call.ret !== null ? ` -> ${hex(call.ret)}` : ''}`;
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

// Rows of capa.json from the tool outputs. calls are addressed by capa-cpp as
// [ppid, pid, tid, id], where id indexes the thread's calls sorted by seq (ttd-timeline.py).
// eventOf(pos) maps a [seq, steps] position to an event index; threadOf(utid) to a thread index.
export function capaRows({ report, doc, codeRecords = null, codeHits = null, eventOf = () => null, threadOf = () => null }) {
  const lookup = new Map();
  for (const proc of report?.processes ?? []) {
    const byTid = new Map();
    for (const call of proc.calls ?? []) {
      const tid = call.tid ?? 0;
      if (!byTid.has(tid)) byTid.set(tid, []);
      byTid.get(tid).push(call);
    }
    for (const [tid, calls] of byTid) lookup.set(`${proc.ppid ?? 0}|${proc.pid ?? 0}|${tid}`, calls.sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0)));
  }

  const rules = [], ruleIndex = new Map(), rows = [], scope = new Set();
  const ruleOf = (name, meta = {}) => {
    let r = ruleIndex.get(name);
    if (r === undefined) {
      r = rules.length;
      ruleIndex.set(name, r);
      rules.push({ name, ns: meta.namespace ?? '',
        attack: (meta.attack ?? []).map(a => ({ id: a.id ?? '', tactic: a.tactic ?? '', technique: a.technique ?? '', subtechnique: a.subtechnique ?? '' })),
        mbc: (meta.mbc ?? []).map(m => ({ id: m.id ?? '', objective: m.objective ?? '', behavior: m.behavior ?? '', method: m.method ?? '' })) });
    }
    return r;
  };
  const place = (posText, tid) => {
    const pos = parsePosition(posText);
    return { pos: posText ? posText.toUpperCase() : null, evt: pos ? eventOf(pos) : null, utid: tid ?? null, thread: tid === undefined || tid === null ? null : threadOf(tid) };
  };

  for (const [name, entry] of Object.entries(doc?.rules ?? {})) {
    const meta = entry.meta ?? {};
    if (meta.is_subscope_rule || meta.lib || (meta.namespace ?? '').startsWith('internal/')) continue;
    const r = ruleOf(name, meta);
    for (const [addr] of entry.matches ?? []) {
      if (addr?.type !== 'call') { scope.add(r); continue; }
      const [ppid, pid, tid, id] = addr.value;
      const call = lookup.get(`${ppid}|${pid}|${tid}`)?.[id];
      if (!call) continue;
      rows.push({ r, src: 'call', ...place(call.position, tid), api: call.api ?? '', module: call.module ?? '', site: formatReportCall(call) });
    }
  }

  // Capabilities in reconstructed code: at the positions where their matched code ran, or at the
  // region's reconstruction position for matches with no executed site.
  const records = codeRecords ?? [];
  const byVa = new Map();
  for (const rec of records) for (const va of rec.vas ?? []) {
    if (!byVa.has(va)) byVa.set(va, []);
    byVa.get(va).push(rec);
  }
  const hitRules = new Set();
  for (const h of codeHits ?? []) {
    for (const rec of byVa.get(h.va) ?? []) {
      const r = ruleOf(rec.rule, { namespace: rec.namespace });
      hitRules.add(rec.rule);
      rows.push({ r, src: 'code', ...place(h.position, h.tid), site: `code@0x${h.va.toString(16)}${h.hits > 1 ? ` (${h.hits}x)` : ''}`, va: h.va, hits: h.hits ?? 1 });
    }
  }
  for (const rec of records) {
    if (hitRules.has(rec.rule)) continue;
    const r = ruleOf(rec.rule, { namespace: rec.namespace });
    rows.push({ r, src: 'code', ...place(rec.position, null), site: `code@0x${(rec.base ?? 0).toString(16)}${rec.offset != null ? `+0x${rec.offset.toString(16)}` : ''} (region)` });
  }

  const key = row => parsePosition(row.pos) ?? [Infinity, Infinity];
  rows.sort((a, b) => { const x = key(a), y = key(b); return x[0] - y[0] || x[1] - y[1]; });
  return { rules, rows, scope: [...scope] };
}

// ---- runner ----

function run(command, args, { onChild, stdoutFile = null } = {}) {
  return new Promise(resolve => {
    let child;
    try { child = spawn(command, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch (error) { resolve({ code: -1, stderr: error.message }); return; }
    onChild?.(child);
    const out = [];
    let stderr = '';
    child.stdout.on('data', c => { if (stdoutFile) out.push(c); });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', c => { stderr = (stderr + c).slice(-4000); });
    child.on('error', e => { stderr += e.message; });
    child.on('close', async code => {
      if (stdoutFile) await fs.writeFile(stdoutFile, Buffer.concat(out));
      resolve({ code: code ?? -1, stderr });
    });
  });
}

// Runs the CAPA passes for the analysis in `dir` and writes dir/capa.json. Never throws for tool
// failures: capa.json then says what went wrong, and the analysis stays usable.
// Code-scan snapshots are raw memory of the traced process (often malware), which antivirus
// flags; they are written under workRoot only (one directory to exclude) and deleted after the pass.
export async function runCapa({ trace, dir, root, workRoot, onStage = () => {}, onChild }) {
  const t0 = Date.now();
  const write = doc => fs.writeFile(path.join(dir, 'capa.json'), JSON.stringify({ version: CAPA_VERSION, generatedAt: new Date().toISOString(), ...doc }));
  const tools = await locateTools(root);
  if (tools.missing) { await write({ available: false, reason: `ttd-capa-cpp tools not found: ${tools.missing.join('; ')}` }); return; }

  const work = path.join(workRoot ?? path.join(dir, 'capa-work'), `${path.basename(dir)}-${process.pid}`);
  await fs.rm(work, { recursive: true, force: true });
  await fs.mkdir(work, { recursive: true });
  const warnings = [], timings = {};
  const step = async (stage, command, args, opts) => {
    onStage(stage);
    const t = Date.now();
    const r = await run(command, args, { onChild, ...opts });
    timings[stage] = Date.now() - t;
    return r;
  };
  try {
    const reportPath = path.join(work, 'report.ttd.json');
    let r = await step('capa: calls', tools.extractor, [trace, '-o', reportPath]);
    if (r.code !== 0) { await write({ available: false, reason: `ttdcapa-extract failed (${r.code}): ${r.stderr.trim().split('\n').at(-1) ?? ''}` }); return; }
    const docPath = path.join(work, 'doc.json');
    r = await step('capa: match', tools.capaCpp, [reportPath, '-r', tools.rules, '-j'], { stdoutFile: docPath });
    if (r.code !== 0) { await write({ available: false, reason: `capa-cpp failed (${r.code}): ${r.stderr.trim().split('\n').at(-1) ?? ''}` }); return; }

    // Code created at runtime; optional, so failures only warn.
    let codeRecords = null, codeHits = null;
    const manifest = path.join(work, 'code-manifest.json'), caps = path.join(work, 'code-caps.json'), hits = path.join(work, 'hits.json');
    r = await step('capa: code', tools.extractor, [trace, '--scan-code', '--dump-dir', work, '--code-manifest', manifest]);
    if (r.code === 0 && await fs.stat(manifest).then(() => true, () => false)) {
      r = await step('capa: code match', tools.capaCpp, ['--scan-code-manifest', manifest, '-r', tools.rules, '--dumps-dir', work, '-o', caps, '--quiet']);
      if (await fs.stat(caps).then(() => true, () => false)) {
        codeRecords = JSON.parse(await fs.readFile(caps, 'utf8'));
        r = await step('capa: code hits', tools.extractor, [trace, '--trace-code-hits', caps, '--hits-output', hits]);
        if (r.code === 0) codeHits = JSON.parse(await fs.readFile(hits, 'utf8'));
        else warnings.push('code execution positions unavailable; code capabilities are placed at their region');
      } else warnings.push(`code scan matching failed: ${r.stderr.trim().split('\n').at(-1) ?? ''}`);
    } else warnings.push('no code created at runtime was reconstructed');

    onStage('capa: timeline');
    const report = JSON.parse(await fs.readFile(reportPath, 'utf8'));
    const doc = JSON.parse(await fs.readFile(docPath, 'utf8'));
    const manifestJson = JSON.parse(await fs.readFile(path.join(dir, 'manifest.json'), 'utf8'));
    const positions = await fs.readFile(path.join(dir, 'positions.bin'));
    const threadIndex = new Map((manifestJson.threads ?? []).map(t => [t.utid, t.index]));
    const result = capaRows({ report, doc, codeRecords, codeHits, eventOf: pos => eventAt(positions, pos), threadOf: utid => threadIndex.get(utid) ?? null });
    const calls = result.rows.filter(x => x.src === 'call').length;
    await write({ available: true, tools: { rules: tools.rules, capaCpp: tools.capaCpp, extractor: tools.extractor },
      counts: { rules: result.rules.length, rows: result.rows.length, callRows: calls, codeRows: result.rows.length - calls, scope: result.scope.length,
        reportCalls: (report.processes ?? []).reduce((s, p) => s + (p.calls?.length ?? 0), 0), codeRegions: codeRecords ? new Set(codeRecords.map(c => c.base)).size : 0 },
      timings: { ...timings, totalMs: Date.now() - t0 }, warnings, ...result });
  } catch (error) {
    await write({ available: false, reason: `CAPA pass failed: ${error.message}` });
  } finally {
    await fs.rm(work, { recursive: true, force: true });
  }
}
