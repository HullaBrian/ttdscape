# Contributing

Issues and pull requests are welcome.

## Getting set up

1. Install the requirements listed in `README.md`: Visual Studio with the C++ workload, Node.js
   22.12+, TTD, and the `Microsoft.TimeTravelDebugging.Apis` NuGet package.
2. `powershell -ExecutionPolicy Bypass -File .\Start.ps1` builds the analyzer and the viewer, then
   starts the server.
3. Optional: record the test fixture (`fixtures/traces/README.md`) and build
   [ttd-capa-cpp](https://github.com/HullaBrian/ttd-capa-cpp) next to this repository, so the
   integration tests and CAPA results work.

## Before sending a change

```powershell
ctest --test-dir build\analyzer -C RelWithDebInfo   # analyzer unit tests
npm test                                            # viewer data layer + server
npm run test:integration                            # real analyzer (skips what is not recorded or built)
npm run build
```

- Read `docs/viewer-architecture.md` before changing the viewer. New capabilities are features in
  `client/features/`, not additions to `main.js`.
- If the analyzer's output changes, bump the version in `server/config.mjs` and
  `analyzer/src/out/writer.h`, so cached analyses are not reused.
- Match the surrounding style. C++ builds warning-free at `/W4`.
- Never add traces, memory dumps or analysis caches to the repository (see `SECURITY.md`).

`CLAUDE.md` is a denser version of this guide, written for coding agents; it is useful to humans too.
