# TTDscape: notes for agents

A local 3D explorer of a process's heap, virtual memory and calls over time, built from a Microsoft
TTD trace (`.run`). Three parts:

- `analyzer/`: a C++20 command-line tool on the TTD Replay API. It runs one replay pass and
  writes binary tables plus `manifest.json`.
- `server/`: Node with `node:http` only. It runs the analyzer and the CAPA pass, caches the
  results, and serves them.
- `client/`: a Three.js viewer bundled by Vite, with an app core plus features.

Read `README.md` first for the pipeline, the output format and the viewer controls. Then read
`docs/viewer-architecture.md` before touching the client, and `docs/calls.md` for how calls,
arguments and CAPA work and what is still open. `docs/memory.md` covers memory contents and
accesses: the `serve` query service, the Memory tab, access history, the optional activity pass
(write-then-execute) and block snapshots (content search). Their design history is in
`docs/handoff-memory-access.md`.

## Build, run, test (Windows)

Tools may not be on PATH in an agent's shell:
- CMake and ctest ship with Visual Studio, under
  `<VS install>\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\`. `Start.ps1` finds them
  with `vswhere`.
- Node is usually at `C:\Program Files\nodejs`. In Git Bash, `export PATH="/c/Program Files/nodejs:$PATH"`.
- First build: `cmake -S analyzer --preset x64` (Visual Studio 2026) or `--preset vs2022-x64`, or
  just run `Start.ps1`.

```powershell
cmake --build build\analyzer --config RelWithDebInfo        # analyzer + unit tests
ctest --test-dir build\analyzer -C RelWithDebInfo           # 8 C++ unit tests
npm run build                                               # client -> client/dist (the server serves dist, so rebuild after client edits)
npm test                                                    # 41 tests: client data layer + server (fake analyzer)
npm run test:integration                                    # 29 tests: real analyzer on traces/ and fixtures/traces, serve, activity, and the CAPA pass
node tests\e2e\screenshot.mjs <analysisId> [outDir] [baseUrl]   # headless Edge screenshots
node tests\e2e\features.mjs  <analysisId> [outDir] [baseUrl]    # regions, pacing, live calls, arguments, CAPA
node tests\e2e\memory.mjs    <analysisId> [outDir] [baseUrl]    # threads, pointer links, Memory tab, accesses
node tests\e2e\activity.mjs  <analysisId> [outDir] [baseUrl]    # activity colours, write-then-execute, content search
```

Keep all of these green. Integration tests skip the traces and tools that are missing, so on a
fresh clone most of them report as skipped. After a new test file is added under `analyzer/tests`,
reconfigure CMake once (`cmake build\analyzer`), because it is picked up by a glob.

**Dev server:** `TTDSCAPE_PORT=5178 TTDSCAPE_CACHE=build/cache node server/index.mjs`.
- Use a port other than 5177, because a developer may be running their own server there. Do not
  stop a server you did not start.
- A running server must be restarted after server or analyzer changes. One started before an update
  keeps running the old code (its file whitelist and cache key), so new files return 404.
- **When the analyzer's output changes, bump the version** in `server/config.mjs`
  (`analyzerVersion`) and `analyzer/src/out/writer.h` (`kAnalyzerVersion`). Otherwise "Analyze"
  reopens stale cached results.
- Analyses are cached by trace, options and analyzer version. New analysis options change the cache
  key, so old analyses lack new files, and the viewer must handle that.

**Analyzing through the API:** `POST /api/analyses {trace, options}`. Any request needs the header
`X-TTDscape: 1`. Other endpoints: `GET /api/analyses`,
`GET /api/analyses/:id/files/<name>` (Range supported), `POST /api/analyses/:id/capa`,
`POST /api/analyses/:id/symbolize`, `GET /api/analyses/:id/memory?evt=&addr=&size=`, and
`POST /api/analyses/:id/accesses {lo, hi, reads, from, to, limit}`, and
`GET /api/analyses/:id/search?q=&mode=text|hex|pointer` (block snapshots). Memory and accesses go through
`ttdscape-analyzer serve` processes (`server/query.mjs`) that the server starts on demand and stops
when idle. A server restart picks up a rebuilt analyzer. With curl in Git Bash, JSON bodies with Windows paths are
mangled, so use `node -e "fetch(...)"`.

**Test data** is not in the repository: traces embed the recording machine's environment, and
samples may be malware. Integration tests skip whatever is missing.
- `traces/*.run`: any recordings you have. The smoke test checks model invariants on each. It has
  extra checks for a trace named `beacon*`: a Cobalt Strike sample whose payload runs from unbacked
  memory and connects to 192.168.81.129:80.
- `fixtures/traces/fixture01.run` (x64) and `fixture86.run` (x86 WoW64), each with a `.truth.json`
  that the integration tests match exactly. Record them with `fixtures/record-fixture.ps1` (admin);
  the fixture source is `fixtures/app/fixture.cpp`.

## Where things are

| Area | Files |
|---|---|
| Replay pass: CALL/RET shadow stack, hooked heap/VM entries, calls into exports, argument decoding | `analyzer/src/replay/capture.cpp`, `shadow_stack.h`, `call_args.*` |
| Export tables of all modules | `analyzer/src/exports.cpp` |
| Ordering by position, heap/VM models, mapping calls to the event axis | `analyzer/src/model/build.cpp`, `call_times.h`, `heap_model.*`, `vm_model.*` |
| Record layouts (binary contract with the client) | `analyzer/src/model/types.h`, `analyzer/src/out/writer.cpp`, `client/trace-reader.js` |
| API argument decoder vendored from ttd-capa-cpp (Apache-2.0, unmodified except `ttdutils.*`) | `analyzer/third_party/ttdcapa/` |
| Jobs, cache key, result file whitelist | `server/jobs.mjs` (`RESULT_FILES`, `normalizeOptions`) |
| CAPA pass (ttdcapa-extract + capa-cpp, rows positioned on the event axis) | `server/capa.mjs` → `capa.json` |
| Query service: `serve` command, `memory.read`, `accesses.query` (Write+Overwrite, DataMismatch, Read) | `analyzer/src/serve/`, `server/query.mjs` |
| Activity pass (writes per object, write-then-execute, rebuilt block snapshots), content search | `analyzer/src/replay/activity.*`, `server/search.mjs` |
| Viewer core and rails | `client/app/app.js`, `rails.js`, `events.js`, `prefs.js` |
| Viewer features | `client/features/*.js`, listed in order in `client/main.js` |
| Pure client logic (unit-tested) | `client/calls.js`, `call-args.js`, `memory.js`, `region-list.js`, `layout.js`, `state.js` |
| Scene | `client/atlas.js` (static region layer, dynamic layer, beams, emphasis, alerts), `client/beams.js` |

## Conventions and pitfalls

- **The timeline axis is the event index, not a TTD position.** "Event i" is the state after event
  i. A call between events e-1 and e sits at time `e - 1 + frac`. `app.now()` is continuous time.
- **Adding analyzer output:**
  1. Add it to `manifest.files` (writer).
  2. Add it to `RESULT_FILES` in `server/jobs.mjs`, otherwise it is not served.
  3. Load it lazily in the client; use `app.range()` for large tables.
  4. Bump the analyzer version (above).
- **Adding viewer capability:** write a new `client/features/<name>.js` exporting `install(app)`
  and use the registries: tabs, `hoverText`, `inspectors`, timeline lanes, `services`. Do not grow
  `main.js`. Recompute on events (`seek`, `select`, `frame`) and keep a key string of the inputs so
  work runs only when something changed.
- **Measured TTD Replay behaviour:** `ReplayAPI.md` has corrections to the official docs
  (landmines 30–37). The important ones:
  - A callback-only cursor needs `ReplayAllSegmentsWithoutFiltering`.
  - Pair a RET with its CALL by `target == retAddr && SP == SP at the CALL`, never by "the next RET".
  - Tail calls need execute watchpoints or the indirect-jump callback.
- **Antivirus and hygiene:** the CAPA code scan writes memory snapshots of the traced process,
  which may be malware. Snapshots go only to `TTDSCAPE_CAPA_WORK`:
  - default `%LOCALAPPDATA%\TTDscape\capa-work`;
  - `build\capa-work` for the dev server and integration tests.

  These are the directories to exclude from antivirus scanning. Never write dumps anywhere else,
  and never add traces, dumps or analysis caches to the repository.
- **CAPA tools** come from a [ttd-capa-cpp](https://github.com/HullaBrian/ttd-capa-cpp) checkout,
  `TTDSCAPE_TTDCAPA` (default `..\ttd-capa-cpp`):
  - `ttd\bin\x64\Release\ttdcapa-extract.exe`;
  - `capa-cpp\build\Release\capa-cpp.exe`, built with `capa-cpp\build.sh Release` after
    `vcpkg install --triplet x64-windows-static --x-manifest-root=capa-cpp` (Visual Studio's bundled
    vcpkg at `<VS install>\VC\vcpkg` works);
  - `rules\`.

  If any is missing, `capa.json` says so and the rest still works.
- **Encoding on Windows:**
  - Python needs `PYTHONUTF8=1`.
  - PowerShell 5.1 `Set-Content -Encoding utf8` adds a BOM, which breaks `package.json`.
  - Editing through a Bash heredoc into Python mangles backslash escapes (`\n`, `\f`, `\\`, `\s`).
    Use the Edit/Write tools for anything with escapes, then check with
    `grep -rlP "[\x00-\x08\x0b\x0c\x0e-\x1f]"`.
- **Code style:** match the surrounding code, with its comment density, naming and short
  why-comments. C++ builds at `/W4` with no warnings (vendored code at `/W3`). Client code is ES
  modules and plain DOM, with no framework.
