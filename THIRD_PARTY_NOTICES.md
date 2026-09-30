# Third-party notices

TTDscape is MIT-licensed (see `LICENSE`). It includes or adapts the following third-party work,
each under its own license.

## Included in this repository

| Component | Where | License |
|---|---|---|
| [Heapscape](https://github.com/kkokosa/heapspace) by Konrad Kokosa: viewer code adapted from it (camera and flight controls, labels, packing layout, themes, the address lattice and the beam effect) | `client/atlas.js`, `client/layout.js`, `client/themes.js`, `client/rendering.js`, `client/beams.js`, `client/style.css` | MIT, `THIRD_PARTY_HEAPSCAPE_LICENSE.txt` |
| [ttd-capa-cpp](https://github.com/HullaBrian/ttd-capa-cpp): API argument decoder (signature index loader, calling-convention decoding, guest string readers) | `analyzer/third_party/ttdcapa/` | Apache-2.0, `analyzer/third_party/ttdcapa/LICENSE` |
| Win32 API signature index, built by ttd-capa-cpp from [win32json](https://github.com/marlersoft/win32json), a JSON form of Microsoft's win32metadata | `analyzer/third_party/ttdcapa/data/win32-index.bin` | MIT, `analyzer/third_party/ttdcapa/data/LICENSE.win32json` |
| Native API signature index, built by ttd-capa-cpp from [phnt](https://github.com/winsiderss/phnt) | `analyzer/third_party/ttdcapa/data/phnt-index.bin` | MIT, `analyzer/third_party/ttdcapa/data/LICENSE.phnt` |

## Used but not included

| Component | How it is obtained | License |
|---|---|---|
| [three.js](https://threejs.org) | npm | MIT |
| [Vite](https://vite.dev), [Playwright](https://playwright.dev) (development only) | npm | MIT, Apache-2.0 |
| Microsoft Time Travel Debugging Replay API (`Microsoft.TimeTravelDebugging.Apis`) and runtime (`TTDReplay.dll`, `TTDReplayCPU.dll`) | NuGet and the TTD installation; the build copies the DLLs next to the analyzer | Microsoft license terms of those packages |
| [capa-cpp](https://github.com/HullaBrian/capa-cpp), [capa rules](https://github.com/mandiant/capa-rules) | Optional ttd-capa-cpp checkout, run as external tools | See each project |
