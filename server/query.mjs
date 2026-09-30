// On-demand memory queries: `ttdscape-analyzer serve <trace> <dir>` processes that keep a trace open
// and answer NDJSON requests (memory.read, accesses.query; see analyzer/src/serve/serve.cpp).
//
// Two lanes, so a slow access replay never stalls the hex view:
//   memory    one process per analysis, for memory.read (a seek and a read: milliseconds)
//   accesses  at most one process in total, for accesses.query (a replay: seconds). Only one replay
//             runs at a time, whatever the number of open analyses.
// Processes start on first use and exit after an idle timeout. Memory contents are sample data: they
// are passed through, never logged.
import { spawn } from 'node:child_process';
import readline from 'node:readline';

export const MEMORY_MAX = 64 * 1024;
export const ACCESS_RANGE_MAX = 1 << 20;
export const ACCESS_LIMIT_MAX = 50000;

const ADDRESS = /^0x[0-9a-f]{1,16}$/i;
const POSITION = /^[0-9a-f]{1,16}:[0-9a-f]{1,16}$/i;

const fail = (status, message) => Object.assign(new Error(message), { status });

// Validates GET .../memory query parameters. Returns the request params or throws with .status.
export function memoryParams(search) {
  const addr = search.get('addr') ?? '';
  if (!ADDRESS.test(addr)) throw fail(400, 'addr must be a hex address (0x...)');
  const size = Number(search.get('size') ?? 256);
  if (!Number.isInteger(size) || size < 1 || size > MEMORY_MAX) throw fail(400, `size must be 1..${MEMORY_MAX}`);
  const pos = search.get('pos');
  if (pos !== null) {
    if (!POSITION.test(pos)) throw fail(400, 'pos must be SEQ:STEPS in hex');
    return { pos, addr, size };
  }
  const evt = Number(search.get('evt'));
  if (!Number.isInteger(evt) || evt < -1) throw fail(400, 'evt must be an event index (or -1 for the start)');
  return { evt, addr, size };
}

// Validates a POST .../accesses body. Returns the request params (normalized, so they can key a cache).
export function accessParams(body) {
  const { lo, hi } = body ?? {};
  if (typeof lo !== 'string' || typeof hi !== 'string' || !ADDRESS.test(lo) || !ADDRESS.test(hi)) throw fail(400, 'lo and hi must be hex addresses');
  const span = BigInt(hi) - BigInt(lo);
  if (span <= 0n) throw fail(400, 'lo must be below hi');
  if (span > BigInt(ACCESS_RANGE_MAX)) throw fail(400, 'the range is larger than 1 MiB');
  const params = { lo: `0x${BigInt(lo).toString(16)}`, hi: `0x${BigInt(hi).toString(16)}`, reads: body.reads === true,
    limit: Math.min(ACCESS_LIMIT_MAX, Math.max(1, Number.parseInt(body.limit ?? 5000, 10) || 5000)) };
  for (const k of ['from', 'to']) {
    if (body[k] === undefined || body[k] === null) continue;
    if (!Number.isInteger(body[k]) || body[k] < -1) throw fail(400, `${k} must be an event index`);
    params[k] = body[k];
  }
  if (params.from !== undefined && params.to !== undefined && params.to < params.from) throw fail(400, 'to is before from');
  return params;
}

class ServeProcess {
  constructor(command, args, onExit) {
    this.pending = new Map();
    this.nextId = 1;
    this.busy = 0;
    this.lastUsed = Date.now();
    this.exited = false;
    this.stderr = '';
    const [cmd, ...prefix] = command;
    this.child = spawn(cmd, [...prefix, ...args], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    this.ready = new Promise((resolve, reject) => { this.onReady = resolve; this.onFail = reject; });
    this.ready.catch(() => {});
    readline.createInterface({ input: this.child.stdout }).on('line', line => this.receive(line));
    this.child.stderr.setEncoding('utf8');
    this.child.stderr.on('data', chunk => { this.stderr = (this.stderr + chunk).slice(-4096); });
    this.child.stdin.on('error', () => {});
    const end = message => {
      if (this.exited) return;
      this.exited = true;
      const error = fail(500, message);
      this.onFail(error);
      for (const p of this.pending.values()) p.reject(error);
      this.pending.clear();
      onExit(this);
    };
    this.child.on('error', err => end(`cannot start the query service: ${err.message}`));
    this.child.on('close', code => end(this.killed ? 'cancelled' : `the query service exited (${code})${this.lastError ? `: ${this.lastError}` : ''}`));
  }

  receive(line) {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    if (msg.type === 'ready') { this.onReady(); return; }
    if (msg.type === 'error') { this.lastError = msg.message; return; }
    const p = this.pending.get(msg.id);
    if (!p) return;
    if (msg.progress !== undefined) { p.onProgress?.(msg.progress); return; }
    this.pending.delete(msg.id);
    this.busy--;
    this.lastUsed = Date.now();
    if (msg.error !== undefined) p.reject(fail(400, msg.error));
    else p.resolve(msg.result);
  }

  async request(method, params, onProgress) {
    await this.ready;
    const id = this.nextId++;
    this.busy++;
    this.lastUsed = Date.now();
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, onProgress });
      this.child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
    });
  }

  kill() {
    this.killed = true;
    this.child.kill();
  }
}

export class QueryService {
  constructor(config, { idleMs = 5 * 60 * 1000, maxProcesses = 3 } = {}) {
    this.config = config;
    this.idleMs = idleMs;
    this.maxProcesses = maxProcesses;
    this.processes = new Map(); // `${id}|${lane}` -> ServeProcess
    this.timer = setInterval(() => this.reap(), Math.min(idleMs, 30000));
    this.timer.unref();
  }

  process(job, lane) {
    const key = `${job.id}|${lane}`;
    let p = this.processes.get(key);
    if (p && !p.exited) return p;
    // One replay at a time: an access query for another analysis replaces the idle one.
    if (lane === 'accesses') for (const [k, other] of this.processes) if (k.endsWith('|accesses') && !other.busy) this.stopKey(k);
    this.evict();
    const args = ['serve', job.trace, job.dir];
    if (this.config.symbolPath) args.push('--symbol-path', this.config.symbolPath);
    p = new ServeProcess(this.config.analyzer, args, dead => { if (this.processes.get(key) === dead) this.processes.delete(key); });
    this.processes.set(key, p);
    return p;
  }

  // Keeps at most maxProcesses alive, stopping the least recently used idle ones.
  evict() {
    const idle = [...this.processes].filter(([, p]) => !p.busy).sort((a, b) => a[1].lastUsed - b[1].lastUsed);
    while (this.processes.size >= this.maxProcesses && idle.length) this.stopKey(idle.shift()[0]);
  }

  reap() {
    const now = Date.now();
    for (const [k, p] of this.processes) if (!p.busy && now - p.lastUsed > this.idleMs) this.stopKey(k);
  }

  memory(job, params) {
    return this.process(job, 'memory').request('memory.read', params);
  }

  accesses(job, params, onProgress) {
    return this.process(job, 'accesses').request('accesses.query', params, onProgress);
  }

  // Abandons a running access query (a replay cannot be interrupted over the protocol).
  cancelAccesses(id) { this.stopKey(`${id}|accesses`); }

  stop(id) {
    for (const k of [...this.processes.keys()]) if (k.startsWith(`${id}|`)) this.stopKey(k);
  }

  stopKey(k) {
    const p = this.processes.get(k);
    this.processes.delete(k);
    p?.kill();
  }

  close() {
    clearInterval(this.timer);
    for (const k of [...this.processes.keys()]) this.stopKey(k);
  }
}
