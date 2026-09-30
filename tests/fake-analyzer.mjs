// Stands in for ttdscape-analyzer.exe in server tests.
//   node fake-analyzer.mjs analyze <trace> <outDir> [...]
// Behaviour is controlled by the trace file's contents: "fail" -> error, "slow" -> waits for kill.
import fs from 'node:fs';
import path from 'node:path';

const [cmd, trace, out] = process.argv.slice(2);
const line = obj => process.stdout.write(JSON.stringify(obj) + '\n');

if (cmd === 'symbolize') {
  fs.writeFileSync(path.join(trace, 'symbols.json'), JSON.stringify({ frames: [['resymbolized', '', 0]], modulesWithSymbols: 1 }));
  line({ type: 'done', ms: 1 });
  process.exit(0);
}

if (cmd === 'serve') {
  // Query service: memory.read returns bytes equal to the low address byte + offset; accesses.query
  // reports progress, then one write per 16 bytes. lo 0xdead never answers (for cancellation).
  fs.appendFileSync(path.join(out, 'serve-starts.txt'), 'x');
  line({ type: 'ready' });
  let buffer = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => {
    buffer += chunk;
    let nl;
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const { id, method, params } = JSON.parse(buffer.slice(0, nl));
      buffer = buffer.slice(nl + 1);
      if (method === 'memory.read') {
        const base = Number(BigInt(params.addr) & 0xffn);
        const data = Buffer.from(Array.from({ length: params.size }, (_, i) => (base + i) & 0xff)).toString('base64');
        line({ id, result: { addr: params.addr, size: params.size, pos: '10:0', seq: 16, data, ranges: [[0, params.size, 16, params.evt ?? 0]], unknown: [] } });
      } else if (method === 'accesses.query') {
        if (params.lo === '0xdead') continue;
        line({ id, progress: 0.5 });
        const hits = [];
        for (let a = BigInt(params.lo); a < BigInt(params.hi); a += 16n)
          hits.push({ pos: '11:2', evt: 1, utid: 2, pc: '0x401000', module: null, sym: '', addr: `0x${a.toString(16)}`, size: 8, kind: 'w', old: '00', new: 'ff' });
        line({ id, result: { lo: params.lo, hi: params.hi, reads: params.reads, truncated: false, ms: 1, hits } });
      } else {
        line({ id, error: `unknown method: ${method}` });
      }
    }
  });
  process.stdin.on('end', () => process.exit(0));
} else {
const content = fs.readFileSync(trace, 'utf8');
line({ type: 'stage', stage: 'capture' });
line({ type: 'progress', stage: 'capture', fraction: 0.5 });
if (content.includes('fail')) {
  line({ type: 'error', message: 'synthetic failure' });
  process.exit(1);
}
if (content.includes('slow')) {
  setInterval(() => line({ type: 'progress', stage: 'capture', fraction: 0.6 }), 50);
} else {
  fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify({ schema: 'ttdscape/1', trace: { arch: 'x64' }, counts: { events: 3 } }));
  fs.writeFileSync(path.join(out, 'events.bin'), Buffer.alloc(96, 7));
  fs.writeFileSync(path.join(out, 'args.json'), JSON.stringify(process.argv.slice(2)));
  // Snapshots of two blocks: "hello C2 192.168.1.1" and 16 bytes holding the pointer 0x401000.
  if (process.argv.includes('--snapshots') && process.argv[process.argv.indexOf('--snapshots') + 1] === 'on') {
    const a = Buffer.from('hello C2 192.168.1.1'), b = Buffer.alloc(16);
    b.writeBigUInt64LE(0x401000n, 4);
    const idx = Buffer.alloc(48);
    idx.writeUInt32LE(0, 0); idx.writeUInt32LE(a.length, 8);
    idx.writeUInt32LE(a.length, 16); idx.writeUInt32LE(b.length, 24);
    fs.writeFileSync(path.join(out, 'contents.idx'), idx);
    fs.writeFileSync(path.join(out, 'contents.bin'), Buffer.concat([a, b]));
  }
  line({ type: 'done', ms: 5 });
}
}
