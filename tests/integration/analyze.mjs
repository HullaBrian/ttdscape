// Shared helper: runs the real analyzer on a trace and decodes its output with the client reader.
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { decodeEvents, decodeBlocks, decodeRegions, decodeSpans, decodeStacks, decodeFrames, decodeSeries, loadCalls } from '../../client/trace-reader.js';

export const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const analyzer = process.env.TTDSCAPE_ANALYZER ?? path.join(repo, 'build', 'analyzer', 'RelWithDebInfo', 'ttdscape-analyzer.exe');

export async function exists(p) { return fs.access(p).then(() => true, () => false); }

export async function analyzeTrace(trace, extraArgs = []) {
  const out = await fs.mkdtemp(path.join(os.tmpdir(), 'ttdscape-it-'));
  const { stdout } = await promisify(execFile)(analyzer, ['analyze', trace, out, '--debug-ndjson', ...extraArgs],
    { maxBuffer: 64 << 20, timeout: 20 * 60 * 1000 });
  const lines = stdout.trim().split('\n').map(l => JSON.parse(l));
  if (!lines.some(l => l.type === 'done')) throw new Error(`analyzer did not finish: ${stdout.slice(-500)}`);
  const read = name => fs.readFile(path.join(out, name));
  const manifest = JSON.parse(await read('manifest.json'));
  const f = manifest.files;
  const buf = async name => { const b = await read(f[name].file); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); };
  const data = {
    dir: out, manifest,
    events: decodeEvents(await buf('events'), f.events.count),
    blocks: decodeBlocks(await buf('blocks'), f.blocks.count),
    regions: decodeRegions(await buf('regions'), f.regions.count),
    spans: decodeSpans(await buf('spans'), f.spans.count),
    stacks: decodeStacks(await buf('stacks'), f.stacks.count),
    frames: decodeFrames(await buf('frames'), f.frames.count),
    series: decodeSeries(await buf('series'), f.series.columns),
    calls: (await read('calls.ndjson')).toString('utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l)),
  };
  // Call beams data, through the viewer's own loader.
  data.exportCalls = await loadCalls(async name => {
    const b = await read(name);
    return { arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength), json: async () => JSON.parse(b.toString('utf8')) };
  }, manifest);
  // Decoded arguments, one parsed object per call (in calls.bin order).
  if (manifest.files.callargs) {
    data.callArgs = (await read(manifest.files.callargs.file)).toString('utf8').split('\n').slice(0, -1).map(l => JSON.parse(l));
  }
  data.symbols = (await exists(path.join(out, 'symbols.json'))) ? JSON.parse(await read('symbols.json')).frames : null;
  return data;
}

// Starts `ttdscape-analyzer serve` on an analysis directory. Returns { call(method, params), close() };
// call resolves with the result (progress lines are skipped) and rejects on an error response.
export async function startServe(trace, dir) {
  const { spawn } = await import('node:child_process');
  const readline = await import('node:readline');
  const child = spawn(analyzer, ['serve', trace, dir], { stdio: ['pipe', 'pipe', 'ignore'] });
  const waiting = new Map();
  let next = 1;
  await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', code => reject(new Error(`serve exited (${code})`)));
    readline.createInterface({ input: child.stdout }).on('line', line => {
      const msg = JSON.parse(line);
      if (msg.type === 'ready') return resolve();
      if (msg.progress !== undefined) return;
      const w = waiting.get(msg.id);
      waiting.delete(msg.id);
      if (msg.error !== undefined) w?.reject(new Error(msg.error)); else w?.resolve(msg.result);
    });
  });
  return {
    call: (method, params) => new Promise((resolve, reject) => {
      const id = next++;
      waiting.set(id, { resolve, reject });
      child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
    }),
    close: () => { child.stdin.end(); child.kill(); },
  };
}
