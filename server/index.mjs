// TTDscape local server: analyzes TTD traces on this machine and serves the 3D viewer.
// Binds to loopback only. Traces are referenced by local path (they are often gigabytes).
import http from 'node:http';
import { loadConfig } from './config.mjs';
import { JobManager } from './jobs.mjs';
import { createHandler } from './router.mjs';

export async function startServer(config = loadConfig()) {
  const jobs = new JobManager(config);
  await jobs.init();
  const server = http.createServer(createHandler(config, jobs));
  server.on('close', () => jobs.queries.close());
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port, config.host, resolve);
  });
  config.actualPort = server.address().port;
  return { server, jobs, port: config.actualPort };
}

if (import.meta.url === `file:///${process.argv[1]?.replace(/\\/g, '/')}` || process.argv[1]?.endsWith('index.mjs')) {
  const config = loadConfig();
  startServer(config).then(({ port }) => {
    console.log(`TTDscape listening on http://127.0.0.1:${port}`);
    console.log(`  analyzer: ${config.analyzer.join(' ')}`);
    console.log(`  cache:    ${config.cacheDir}`);
  }).catch(error => {
    console.error(`failed to start: ${error.message}`);
    process.exit(1);
  });
}
