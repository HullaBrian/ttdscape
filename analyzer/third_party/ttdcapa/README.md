# Vendored from ttd-capa-cpp

API argument decoding for recorded calls, copied from
[ttd-capa-cpp](https://github.com/HullaBrian/ttd-capa-cpp) `ttd/src` (Apache-2.0, see `LICENSE`):

- `abi.*`: maps a signature onto registers and stack slots (x64 and x86), decodes each parameter
  and defers `[Out]` reads to the return.
- `win32meta.*`, `builtinsigs.*`: the signature index loader. `data/win32-index.bin` is built from
  [win32json](https://github.com/marlersoft/win32json) (MIT, `data/LICENSE.win32json`) and
  `data/phnt-index.bin` from [phnt](https://github.com/winsiderss/phnt) (MIT, `data/LICENSE.phnt`).
  Both are copied next to the analyzer at build time.
- `log.*`: the diagnostics sink these files write to.
- `ttdutils.*`: trimmed to the types and the memory and string readers used above.

Files are unchanged except `ttdutils.*`. To update, re-copy them from ttd-capa-cpp and rebuild.
