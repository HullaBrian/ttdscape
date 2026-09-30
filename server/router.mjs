import fs from 'node:fs/promises';
import path from 'node:path';
import { RESULT_FILES, isWithin } from './jobs.mjs';
import { memoryParams, accessParams } from './query.mjs';
import { sendFile, serveStatic } from './static.mjs';

const MAX_BODY = 64 * 1024;

function json(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(text);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('request body too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(Object.assign(new Error('invalid JSON body'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}

async function listTraces(dir) {
  const out = [];
  let entries;
  try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (!e.isFile() || !/\.(run|ttd)$/i.test(e.name)) continue;
    const full = path.join(dir, e.name);
    try {
      const st = await fs.stat(full);
      out.push({ path: full, name: e.name, size: st.size, mtime: st.mtimeMs });
    } catch { /* raced with deletion */ }
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

export function createHandler(config, jobs) {
  const allowed = () => {
    const port = config.actualPort ?? config.port;
    return new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
  };

  return async function handle(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const { pathname } = url;
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    // DNS-rebinding defense: only answer to our own loopback host names.
    if (!allowed().has(req.headers.host ?? '')) return json(res, 421, { error: 'unexpected Host header' });

    if (!pathname.startsWith('/api/')) {
      if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { error: 'method not allowed' });
      res.setHeader('Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'");
      return serveStatic(req, res, config.staticDir, pathname);
    }

    // State-changing requests must carry the custom header (a cross-site form cannot set it) and,
    // if the browser sends an Origin, it must be ours.
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      if (req.headers['x-ttdscape'] !== '1') return json(res, 403, { error: 'missing X-TTDscape header' });
      const origin = req.headers.origin;
      if (origin && !allowed().has(origin.replace(/^https?:\/\//, ''))) return json(res, 403, { error: 'cross-origin request' });
    }

    try {
      const parts = pathname.split('/').filter(Boolean); // ['api', ...]
      if (pathname === '/api/health' && req.method === 'GET') return json(res, 200, { ok: true, analyzer: config.analyzer[0] });

      if (pathname === '/api/traces' && req.method === 'GET') {
        const dir = url.searchParams.get('dir');
        const dirs = dir ? [path.resolve(dir)] : (config.traceRoots.length ? config.traceRoots : config.browseDirs);
        if (dir && config.traceRoots.length && !config.traceRoots.some(r => isWithin(path.resolve(dir), r)))
          return json(res, 403, { error: 'directory is outside the allowed trace roots' });
        const traces = (await Promise.all(dirs.map(listTraces))).flat();
        return json(res, 200, { dirs, traces });
      }

      if (pathname === '/api/analyses' && req.method === 'GET') return json(res, 200, jobs.list());

      if (pathname === '/api/analyses' && req.method === 'POST') {
        const body = await readBody(req);
        const { job, cached } = await jobs.submit(body.trace, body.options);
        return json(res, cached ? 200 : 202, jobs.describe(job));
      }

      if (parts[1] === 'analyses' && parts[2]) {
        const job = jobs.get(parts[2]);
        if (!job) return json(res, 404, { error: 'unknown analysis' });

        if (parts.length === 3 && req.method === 'GET') return json(res, 200, jobs.describe(job));
        if (parts.length === 3 && req.method === 'DELETE') { await jobs.cancel(job.id); return json(res, 200, { deleted: job.id }); }

        if (parts[3] === 'progress' && parts.length === 4 && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', 'Connection': 'keep-alive' });
          const send = event => res.write(`data: ${JSON.stringify(event)}\n\n`);
          send({ type: 'state', ...jobs.describe(job) });
          const listener = (id, event) => { if (id === job.id) send(event); };
          jobs.on('update', listener);
          const ping = setInterval(() => res.write(': ping\n\n'), 15000);
          req.on('close', () => { jobs.off('update', listener); clearInterval(ping); });
          return;
        }

        if (parts[3] === 'files' && parts.length === 5 && (req.method === 'GET' || req.method === 'HEAD')) {
          if (job.state !== 'ready') return json(res, 409, { error: `analysis is ${job.state}` });
          const name = parts[4];
          if (!RESULT_FILES.includes(name)) return json(res, 404, { error: 'unknown file' });
          return sendFile(req, res, path.join(job.dir, name), { immutable: name !== 'symbols.json' && name !== 'capa.json' });
        }

        // Memory contents are sample data: returned to the local viewer only, never logged.
        if (parts[3] === 'memory' && parts.length === 4 && req.method === 'GET')
          return json(res, 200, await jobs.memory(job.id, memoryParams(url.searchParams)));
        if (parts[3] === 'search' && parts.length === 4 && req.method === 'GET') {
          const q = url.searchParams;
          return json(res, 200, await jobs.search(job.id, { q: q.get('q') ?? '', mode: q.get('mode') ?? 'text', limit: Number(q.get('limit') ?? 500) || 500 }));
        }
        if (parts[3] === 'accesses' && parts.length === 4 && req.method === 'POST') {
          const params = accessParams(await readBody(req));
          // A client that gives up (or cancels) stops the replay: it cannot be interrupted otherwise.
          res.on('close', () => { if (!res.writableEnded) jobs.queries.cancelAccesses(job.id); });
          const result = await jobs.accesses(job.id, params);
          if (res.destroyed) return;
          return json(res, 200, result);
        }

        if (parts[3] === 'capa' && parts.length === 4 && req.method === 'POST') {
          jobs.capa(job.id).catch(() => { /* reported through job state */ });
          return json(res, 202, jobs.describe(job));
        }
        if (parts[3] === 'symbolize' && parts.length === 4 && req.method === 'POST') {
          const body = await readBody(req);
          const symbolPath = typeof body.symbolPath === 'string' ? body.symbolPath : undefined;
          jobs.symbolize(job.id, symbolPath).catch(() => { /* reported through job state */ });
          return json(res, 202, jobs.describe(job));
        }
      }
      return json(res, 404, { error: 'not found' });
    } catch (error) {
      return json(res, error.status ?? 500, { error: error.message });
    }
  };
}
