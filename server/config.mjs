import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function list(value) {
  return (value ?? '').split(';').map(s => s.trim()).filter(Boolean).map(p => path.resolve(p));
}

// All settings come from the environment so tests can run isolated instances.
export function loadConfig(env = process.env) {
  const cacheDir = env.TTDSCAPE_CACHE
    ? path.resolve(env.TTDSCAPE_CACHE)
    : path.join(env.LOCALAPPDATA ?? path.join(os.homedir(), '.cache'), 'TTDscape', 'cache');
  const analyzer = env.TTDSCAPE_ANALYZER
    ? env.TTDSCAPE_ANALYZER.split('|')
    : [path.join(repoRoot, 'build', 'analyzer', 'RelWithDebInfo', 'ttdscape-analyzer.exe')];
  return {
    host: '127.0.0.1',
    port: Number(env.TTDSCAPE_PORT ?? 5177),
    cacheDir,
    // The analyzer command; extra elements are leading arguments (used by tests: node fake-analyzer.mjs).
    analyzer,
    // Part of the cache key: bump it (with kAnalyzerVersion in analyzer/src/out/writer.h) whenever
    // the analyzer's output changes, or re-analyzing silently reopens stale cached results.
    analyzerVersion: env.TTDSCAPE_ANALYZER_VERSION ?? '0.3.1',
    staticDir: path.resolve(env.TTDSCAPE_STATIC ?? path.join(repoRoot, 'client', 'dist')),
    // When set, traces must live under one of these directories.
    traceRoots: list(env.TTDSCAPE_TRACE_ROOTS),
    // Directories offered in the trace picker when no roots are configured.
    browseDirs: list(env.TTDSCAPE_BROWSE) .length ? list(env.TTDSCAPE_BROWSE)
      : [path.join(repoRoot, 'traces'), path.join(repoRoot, 'fixtures', 'traces')],
    symbolPath: env.TTDSCAPE_SYMBOL_PATH ?? env._NT_SYMBOL_PATH ?? '',
    // Root of a ttd-capa-cpp checkout (built extractor + capa-cpp + rules) for the CAPA pass;
    // defaults to a sibling of this repository. Missing tools just disable CAPA results.
    // Scratch space for the CAPA pass (memory snapshots of the traced process): the one directory
    // to exclude from antivirus scanning. Emptied after each pass.
    capaWork: path.resolve(env.TTDSCAPE_CAPA_WORK ?? path.join(cacheDir, '..', 'capa-work')),
    ttdcapa: path.resolve(env.TTDSCAPE_TTDCAPA ?? path.join(repoRoot, '..', 'ttd-capa-cpp')),
  };
}
