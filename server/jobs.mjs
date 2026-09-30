// Analysis jobs: one analyzer child process at a time, results cached by content key.
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import path from 'node:path';
import { runCapa } from './capa.mjs';
import { QueryService } from './query.mjs';
import { searchAnalysis } from './search.mjs';

export const RESULT_FILES = ['manifest.json', 'events.bin', 'positions.bin', 'blocks.bin', 'regions.bin',
  'spans.bin', 'series.bin', 'stacks.bin', 'frames.bin', 'symbols.json', 'calls.bin', 'callees.json',
  'callargs.bin', 'callargs.jsonl', 'callpos.bin', 'callstacks.bin', 'capa.json',
  'activity.bin', 'writers.bin', 'flows.bin', 'wx.json', 'contents.idx', 'contents.bin'];

export const CALL_SCOPES = ['exports', 'none'];

const TRACE_EXTENSIONS = new Set(['.run', '.ttd']);

export function normalizeOptions(options = {}) {
  const stackDepth = Math.min(256, Math.max(1, Number.parseInt(options.stackDepth ?? 48, 10) || 48));
  // Which calls the analyzer records for call beams; part of the cache key.
  const calls = CALL_SCOPES.includes(options.calls) ? options.calls : 'exports';
  // API argument decoding for recorded calls (ttd-capa signatures).
  const callArgs = calls !== 'none' && options.callArgs !== false;
  // CAPA capabilities (ttd-capa-cpp) for the calls and the code the program created.
  const capa = options.capa !== false;
  // The activity pass (writes per block and page, write-then-execute): one more replay, off by
  // default because it can add more than half the analysis time on unpacking samples.
  const activity = options.activity === true;
  // Block snapshots for content search (sample memory in the cache): opt-in; rebuilt in the
  // activity replay.
  const snapshots = options.snapshots === true;
  return { stackDepth, symbols: options.symbols !== false, calls, callArgs, capa, activity, snapshots };
}

export function isWithin(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

// Validates a user-supplied trace path. Returns { path, stat } or throws with .status.
export async function validateTrace(tracePath, roots = []) {
  const fail = (status, message) => Object.assign(new Error(message), { status });
  if (typeof tracePath !== 'string' || !tracePath.trim()) throw fail(400, 'trace path is required');
  if (!path.isAbsolute(tracePath)) throw fail(400, 'trace path must be absolute');
  if (!TRACE_EXTENSIONS.has(path.extname(tracePath).toLowerCase())) throw fail(400, 'trace must be a .run or .ttd file');
  let real;
  try { real = await fs.realpath(tracePath); } catch { throw fail(404, 'trace file not found'); }
  const stat = await fs.stat(real);
  if (!stat.isFile()) throw fail(400, 'trace path is not a file');
  if (roots.length && !roots.some(root => isWithin(real, root))) throw fail(403, 'trace is outside the allowed trace roots');
  return { path: real, stat };
}

export function cacheKey(realPath, stat, analyzerVersion, options) {
  return createHash('sha256')
    .update(JSON.stringify([realPath.toLowerCase(), stat.size, Math.floor(stat.mtimeMs), analyzerVersion, options]))
    .digest('hex').slice(0, 32);
}

export class JobManager extends EventEmitter {
  constructor(config) {
    super();
    this.config = config;
    this.jobs = new Map();
    this.queue = [];
    this.running = null;
    this.queries = new QueryService(config);
  }

  async init() {
    await fs.mkdir(this.config.cacheDir, { recursive: true });
    for (const entry of await fs.readdir(this.config.cacheDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const dir = path.join(this.config.cacheDir, entry.name);
      if (entry.name.startsWith('tmp-')) { await fs.rm(dir, { recursive: true, force: true }); continue; }
      try {
        const meta = JSON.parse(await fs.readFile(path.join(dir, 'job.json'), 'utf8'));
        await fs.access(path.join(dir, 'manifest.json'));
        this.jobs.set(entry.name, { ...meta, id: entry.name, state: 'ready', dir });
      } catch { /* incomplete or foreign directory: ignore */ }
    }
  }

  list() {
    return [...this.jobs.values()].map(job => this.describe(job))
      .sort((a, b) => (b.finishedAt ?? b.createdAt ?? 0) - (a.finishedAt ?? a.createdAt ?? 0));
  }

  get(id) { return this.jobs.get(id) ?? null; }

  describe(job) {
    const { id, trace, name, options, state, stage, progress, error, createdAt, finishedAt, traceSize, summary } = job;
    return { id, trace, name, options, state, stage, progress, error, createdAt, finishedAt, traceSize, summary };
  }

  async submit(tracePath, rawOptions) {
    const { path: real, stat } = await validateTrace(tracePath, this.config.traceRoots);
    const options = normalizeOptions(rawOptions);
    const id = cacheKey(real, stat, this.config.analyzerVersion, options);
    const existing = this.jobs.get(id);
    if (existing && existing.state !== 'failed' && existing.state !== 'cancelled') return { job: existing, cached: existing.state === 'ready' };
    this.queries.stop(id); // a re-run replaces the directory the query service reads
    const job = {
      id, trace: real, name: path.basename(real), options, traceSize: stat.size,
      state: 'queued', stage: null, progress: 0, error: null, createdAt: Date.now(), finishedAt: null,
      dir: path.join(this.config.cacheDir, id),
    };
    this.jobs.set(id, job);
    this.queue.push(job);
    this.update(job);
    this.pump();
    return { job, cached: false };
  }

  update(job, event = {}) {
    this.emit('update', job.id, { type: 'state', ...this.describe(job), ...event });
  }

  pump() {
    if (this.running || !this.queue.length) return;
    const job = this.queue.shift();
    if (job.state !== 'queued') return this.pump();
    this.running = job;
    job.done = this.run(job).catch(error => {
      job.state = 'failed'; job.error = error.message;
    }).finally(() => {
      job.finishedAt = Date.now();
      job.child = null;
      this.running = null;
      this.update(job);
      this.pump();
    });
  }

  async run(job) {
    const tmp = path.join(this.config.cacheDir, `tmp-${randomUUID()}`);
    await fs.mkdir(tmp, { recursive: true });
    job.state = 'running';
    this.update(job);
    const args = ['analyze', job.trace, tmp, '--stack-depth', String(job.options.stackDepth)];
    if (!job.options.symbols) args.push('--no-symbols');
    args.push('--calls', job.options.calls ?? 'exports');
    args.push('--call-args', job.options.callArgs === false ? 'off' : 'on');
    args.push('--activity', job.options.activity ? 'codefetch' : 'off');
    args.push('--snapshots', job.options.snapshots ? 'on' : 'off');
    if (this.config.symbolPath) args.push('--symbol-path', this.config.symbolPath);
    const { code, lastError, stderr } = await this.spawnAnalyzer(job, args);
    if (job.state === 'cancelled') { await fs.rm(tmp, { recursive: true, force: true }); return; }
    if (code !== 0) {
      await fs.rm(tmp, { recursive: true, force: true });
      job.state = 'failed';
      job.error = lastError ?? (stderr.trim().split('\n').at(-1) || `analyzer exited with code ${code}`);
      return;
    }
    if (job.options.capa !== false) await this.capaPass(job, job.trace, tmp);
    if (job.state === 'cancelled') { await fs.rm(tmp, { recursive: true, force: true }); return; }
    job.summary = await summarize(tmp);
    const meta = { trace: job.trace, name: job.name, options: job.options, traceSize: job.traceSize,
      createdAt: job.createdAt, finishedAt: Date.now(), summary: job.summary };
    await fs.writeFile(path.join(tmp, 'job.json'), JSON.stringify(meta));
    await fs.rm(job.dir, { recursive: true, force: true });
    await fs.rename(tmp, job.dir);
    job.state = 'ready';
    job.progress = 1;
  }

  spawnAnalyzer(job, args) {
    const [command, ...prefix] = this.config.analyzer;
    return new Promise((resolve) => {
      let child;
      try {
        child = spawn(command, [...prefix, ...args], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      } catch (error) {
        resolve({ code: -1, lastError: `cannot start analyzer: ${error.message}`, stderr: '' });
        return;
      }
      job.child = child;
      let buffer = '', stderr = '', lastError = null;
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', chunk => {
        buffer += chunk;
        let nl;
        while ((nl = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, nl).trim();
          buffer = buffer.slice(nl + 1);
          if (!line) continue;
          let msg;
          try { msg = JSON.parse(line); } catch { continue; }
          if (msg.type === 'stage') { job.stage = msg.stage; job.progress = 0; this.update(job); }
          else if (msg.type === 'progress') { job.stage = msg.stage; job.progress = msg.fraction; this.update(job); }
          else if (msg.type === 'error') lastError = msg.message;
        }
      });
      child.stderr.setEncoding('utf8');
      child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
      child.on('error', error => { lastError ??= `cannot start analyzer: ${error.message}`; });
      child.on('close', code => resolve({ code: code ?? -1, lastError, stderr }));
    });
  }

  async cancel(id) {
    const job = this.jobs.get(id);
    if (!job) return false;
    if (job.state === 'queued') job.state = 'cancelled';
    if (job.state === 'running') {
      job.state = 'cancelled';
      job.child?.kill();
      await job.done;
    }
    this.jobs.delete(id);
    this.queue = this.queue.filter(j => j !== job);
    this.queries.stop(id);
    await fs.rm(job.dir, { recursive: true, force: true });
    this.emit('update', id, { type: 'state', id, state: 'deleted' });
    return true;
  }

  // An analysis whose results exist (ready, or re-running CAPA or symbols over them).
  async analyzed(id) {
    const job = this.jobs.get(id);
    const done = job && (job.state === 'ready' || job.state === 'running') &&
      await fs.access(path.join(job.dir, 'manifest.json')).then(() => true, () => false);
    if (!done) throw Object.assign(new Error('analysis is not ready'), { status: 409 });
    return job;
  }

  // Memory at an event (query service; see server/query.mjs).
  async memory(id, params) {
    return this.queries.memory(await this.analyzed(id), params);
  }

  // Accesses to a range, cached in the analysis directory by their parameters. Progress goes out
  // as 'update' events: { type: 'accesses', key, fraction }.
  async accesses(id, params) {
    const job = await this.analyzed(id);
    const key = createHash('sha256').update(JSON.stringify(params)).digest('hex').slice(0, 24);
    const file = path.join(job.dir, 'queries', `accesses-${key}.json`);
    try {
      return { key, cached: true, ...JSON.parse(await fs.readFile(file, 'utf8')) };
    } catch { /* not cached */ }
    const result = await this.queries.accesses(job, params, fraction => this.emit('update', id, { type: 'accesses', key, fraction }));
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, JSON.stringify(result));
    return { key, cached: false, ...result };
  }

  // Content search over block snapshots (server/search.mjs).
  async search(id, params) {
    const job = await this.analyzed(id);
    let pointerSize = 8;
    try { pointerSize = JSON.parse(await fs.readFile(path.join(job.dir, 'manifest.json'), 'utf8')).trace?.arch === 'x86' ? 4 : 8; } catch { /* default */ }
    return searchAnalysis(job.dir, params, pointerSize);
  }

  // The CAPA pass over an analysis directory (failures are recorded in capa.json, not thrown).
  async capaPass(job, trace, dir) {
    await runCapa({
      trace, dir, root: this.config.ttdcapa, workRoot: this.config.capaWork,
      onStage: stage => { job.stage = stage; job.progress = 0; this.update(job); },
      onChild: child => { job.child = child; },
    });
  }

  // Runs (or re-runs) the CAPA pass for a ready analysis.
  async capa(id) {
    const job = this.jobs.get(id);
    if (!job || job.state !== 'ready') throw Object.assign(new Error('analysis is not ready'), { status: 409 });
    if (this.running) throw Object.assign(new Error('another analysis is running'), { status: 409 });
    this.running = job;
    job.state = 'running'; job.stage = 'capa'; job.progress = 0;
    this.update(job);
    try {
      await this.capaPass(job, job.trace, job.dir);
    } finally {
      job.state = 'ready'; job.stage = null; job.progress = 1; job.child = null;
      this.running = null;
      this.update(job);
      this.pump();
    }
  }

  async symbolize(id, symbolPath) {
    const job = this.jobs.get(id);
    if (!job || job.state !== 'ready') throw Object.assign(new Error('analysis is not ready'), { status: 409 });
    if (this.running) throw Object.assign(new Error('another analysis is running'), { status: 409 });
    this.running = job;
    job.state = 'running'; job.stage = 'symbols'; job.progress = 0;
    this.update(job);
    try {
      const args = ['symbolize', job.dir];
      const sp = symbolPath ?? this.config.symbolPath;
      if (sp) args.push('--symbol-path', sp);
      const { code, lastError, stderr } = await this.spawnAnalyzer(job, args);
      if (code !== 0) throw Object.assign(new Error(lastError ?? (stderr.trim() || 'symbolize failed')), { status: 500 });
    } finally {
      job.state = 'ready'; job.stage = null; job.progress = 1; job.child = null;
      this.running = null;
      this.update(job);
      this.pump();
    }
  }
}

async function summarize(dir) {
  try {
    const m = JSON.parse(await fs.readFile(path.join(dir, 'manifest.json'), 'utf8'));
    return { arch: m.trace?.arch, events: m.counts?.events, blocks: m.counts?.blocks, regions: m.counts?.regions,
      threads: m.counts?.threads, modules: m.counts?.modules };
  } catch { return null; }
}
