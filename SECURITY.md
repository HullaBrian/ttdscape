# Security

## Model

TTDscape is a local tool. The server binds to `127.0.0.1` only. It accepts API calls only with the
`X-TTDscape` header, a local `Host`, and a same-origin `Origin`, which blocks DNS rebinding and
cross-site requests. It serves pages with a strict Content-Security-Policy. Nothing is uploaded, and
traces are read in place.

The analyzer **replays** a recording; it never executes the traced program. The optional CAPA pass
runs [ttd-capa-cpp](https://github.com/HullaBrian/ttd-capa-cpp)'s tools, which also only read the
trace.

## Handling traces of malware

- A trace contains the recorded process's memory, and the recording machine's user name, paths and
  environment variables. Treat traces and analysis caches as sensitive. Do not commit or share them.
- The CAPA code scan writes **memory snapshots** of the traced process to `TTDSCAPE_CAPA_WORK`
  (default `%LOCALAPPDATA%\TTDscape\capa-work`) and deletes them when the pass ends. Antivirus
  products flag these snapshots when the sample is malware. Exclude that directory, and only that
  directory, from scanning. Better still, analyze malware in an isolated VM.
- The Memory tab and access history read the traced process's memory through a local query
  process (`ttdscape-analyzer serve`). Bytes are returned only to the local viewer and never logged.
  Access results, which include up to 32 bytes of each written value, are cached in the analysis
  directory (`queries/`) and deleted with it. Hex views are not stored.
- **Block snapshots** (the "Snapshot block contents" option, off by default) store the first 4 KiB
  of every heap block in the analysis directory (`contents.bin`) for content search. For a malware
  sample, that can include decrypted configuration and staged payload data. Antivirus products may
  flag the file. Leave the option off unless you need content search, and treat the cache as
  sensitive.
- The server exposes any `.run` file the user can read. To restrict it, set `TTDSCAPE_TRACE_ROOTS` to
  a `;`-separated list of directories.

## Reporting a vulnerability

Please open a private security advisory on the repository, or an issue without exploit details and
ask for a contact. Include the version (`manifest.json` → `analyzer.version`) and steps to
reproduce.
