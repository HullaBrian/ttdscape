import fs from 'node:fs';
import path from 'node:path';

export const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.map': 'application/json',
  '.bin': 'application/octet-stream',
};

// Parses a single "bytes=a-b" range. Returns null for none/unsatisfiable-as-whole, or {start,end} inclusive.
export function parseRange(header, size) {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m || (m[1] === '' && m[2] === '')) return { invalid: true };
  let start, end;
  if (m[1] === '') { const n = Number(m[2]); start = Math.max(0, size - n); end = size - 1; }
  else { start = Number(m[1]); end = m[2] === '' ? size - 1 : Math.min(Number(m[2]), size - 1); }
  if (!(start <= end) || start >= size) return { invalid: true };
  return { start, end };
}

// Streams a file with ETag / Range support.
export async function sendFile(req, res, file, { immutable = false, contentType } = {}) {
  let stat;
  try { stat = await fs.promises.stat(file); } catch { res.writeHead(404).end(); return; }
  if (!stat.isFile()) { res.writeHead(404).end(); return; }
  const etag = `"${stat.size.toString(16)}-${Math.floor(stat.mtimeMs).toString(16)}"`;
  const headers = {
    'Content-Type': contentType ?? CONTENT_TYPES[path.extname(file).toLowerCase()] ?? 'application/octet-stream',
    'ETag': etag, 'Accept-Ranges': 'bytes',
    'Cache-Control': immutable ? 'private, max-age=31536000, immutable' : 'no-cache',
  };
  if (req.headers['if-none-match'] === etag) { res.writeHead(304, headers).end(); return; }
  const range = parseRange(req.headers.range, stat.size);
  if (range?.invalid) { res.writeHead(416, { 'Content-Range': `bytes */${stat.size}` }).end(); return; }
  if (range) {
    res.writeHead(206, { ...headers, 'Content-Range': `bytes ${range.start}-${range.end}/${stat.size}`, 'Content-Length': range.end - range.start + 1 });
    if (req.method === 'HEAD') { res.end(); return; }
    fs.createReadStream(file, { start: range.start, end: range.end }).pipe(res);
    return;
  }
  res.writeHead(200, { ...headers, 'Content-Length': stat.size });
  if (req.method === 'HEAD') { res.end(); return; }
  fs.createReadStream(file).pipe(res);
}

export async function serveStatic(req, res, root, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { res.writeHead(400).end(); return; }
  const file = path.resolve(root, '.' + path.posix.normalize(rel));
  if (!file.startsWith(root)) { res.writeHead(403).end(); return; }
  const target = await fs.promises.stat(file).then(s => s.isFile() ? file : null, () => null)
    ?? path.join(root, 'index.html');
  const immutable = target.includes(`${path.sep}assets${path.sep}`);
  await sendFile(req, res, target, { immutable });
}
