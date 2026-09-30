# Memory contents and accesses

How TTDscape answers "what is in this memory, and who wrote it":
- **on demand**, through a query service, with nothing added to the analysis pass;
- **for the whole trace**, from an optional activity pass (writes over time, write-then-execute)
  and optional block snapshots (content search). These are described in
  [the second part](#the-activity-pass-and-block-snapshots).

For the design this implements, see
[handoff-memory-access.md](handoff-memory-access.md). For the viewer's structure, see
[viewer-architecture.md](viewer-architecture.md).

## What the analyst gets

| Feature | Where |
|---|---|
| **Pointer links**: call arguments (and return values) that point into a heap block or a private or mapped region link to it | Live calls rows, the call Inspector's argument table, and "Memory this call touched" below a call |
| **Threads at the playhead**: each thread's calls into exports in progress, innermost first, with arguments | Threads tab |
| **Hex view** of the selected block, region or page range (or a typed address) at the playhead, tinted by how long ago each byte was recorded, with changed bytes flashing and strings listed | Memory tab |
| **Access history**: every write (old → new value), every change made from outside the thread (the kernel, another thread or process), and reads on request, grouped by the code that made them | Inspector, below a block, region, page range or bytes selected in the Memory tab |
| **Access ticks** of the selection on the timeline; `[` and `]` step between them | Timeline lane |
| **Activity**: blocks and committed pages glow with recent writes; the write rate over the trace | *Color blocks by → Activity*, a timeline lane (analysis option) |
| **Who wrote a block or page over the whole trace**: first and last writer, without a replay | Inspector, "Writes over the trace" (analysis option) |
| **Write-then-execute**: pages that ran code after being written, and who wrote them | Notes, the region Inspector, red ticks on the timeline (analysis option) |
| **Content search**: blocks that held a string, some bytes or a pointer, as last seen | Find tab, "Contents" (analysis option, stores sample memory) |
| **Memory beams**: straight lights for writes from the writing code's region into the region written (activity), and for the selection's loaded accesses, from code address to byte | 3D view; View tab, "Memory beams" |

## Pieces

```
viewer ──GET /api/analyses/:id/memory?evt=&addr=&size=──▶ server/query.mjs ──NDJSON──▶ ttdscape-analyzer serve
       ──POST /api/analyses/:id/accesses {lo,hi,...}──▶  (lanes: memory, accesses)       <trace> <analysisDir>
```

- **`ttdscape-analyzer serve <trace> <analysisDir>`** (`analyzer/src/serve/`) keeps the trace and its
  index open. It reads `positions.bin` (event → position) and `symbol-input.tsv` (modules, for
  naming the code behind an access) from the analysis directory. Requests are one JSON object per
  line on stdin, `{id, method, params}`; each gets `{id, result}` or `{id, error}` on stdout,
  preceded by any number of `{id, progress}` lines. EOF ends it.
- **`server/query.mjs`** starts these processes on first use. There are two lanes, so a slow access
  replay never stalls the hex view:
  - `memory`: one process per analysis;
  - `accesses`: at most one process in total, so only one replay runs at a time.

  Processes exit after 5 idle minutes and are stopped when their analysis is deleted or re-run. A
  client that disconnects during an access query stops that replay.
- **Access results are cached** in the analysis directory, `queries/accesses-<key>.json`, keyed by
  the normalized request. Memory reads are not cached.

## `memory.read`

Params: `evt` (the state after that event; `-1` is the start of the trace) or `pos` (`SEQ:STEPS`),
`addr`, `size` (≤ 64 KiB).

The cursor is placed at the position and the bytes are read with `QueryMemoryBufferWithRanges` and
the conservative policy, page by page across unmapped holes. The result has:
- `data` (base64);
- `ranges`: `[offset, length, sequence, event]`, where each byte's value was recorded, merged when
  adjacent;
- `unknown`: `[offset, length]` spans no range covers. They are blanked, never shown as zeros
  (ReplayAPI.md landmine 18).

Measured on the fixture:
- At an allocation event (the allocator's RET), the block still holds whatever was there before.
  The caller's memset shows at the next event.
- Freshly committed pages read as recorded zeros (demand-zero), not as unknown.
- Provenance is by TTD **sequence**, which is coarse: a whole memset shares one sequence. The age
  tint says "recorded around event N", no finer.

## `accesses.query`

Params: `lo`, `hi` (a range of at most 1 MiB), `reads` (default false), `from` and `to` (events;
the default is the whole trace), and `limit` (default 5000, at most 50000).

One replay from `from` to `to`, on a fresh cursor (landmine 28), with `ReplaySegmentsSequentially`
and one watchpoint on `[lo, hi)`:
- **`Write | Overwrite`**: `Overwrite` fires just before its `Write` on the same thread and
  position, and carries the **old** value. The `Write` callback sees the **new** one. They are paired
  by thread, address and position.
- **`DataMismatch`** (kind `m`): bytes that changed outside the replaying thread's view, by the
  kernel, another thread or another process. The callback sees the bytes before the change
  (landmine 27), so the new value is read one step later on a fresh cursor.
- **`Read`**, only when asked. Reads are often many times more numerous than writes.

Each hit has:
- `pos` and `evt` (the first event at or after it);
- `utid`, `pc`, `module` (manifest index, or null outside every module) and `sym`;
- `addr`, `size`, `kind`;
- `old` and `new`, as hex of the first 32 bytes.

A query stops at `limit` hits and says `truncated`. Order across threads is only approximate within
a sequence (landmine 30).

Measured (x64 fixture):
- a 77-byte block over the whole trace: 131 writes in 85 ms;
- a 64 KiB committed range: 2,048 writes in 32 ms.

### Scope in the viewer

A block's history defaults to its **lifetime**: from the event before its allocation (so the
allocator's own zeroing is included) through the event after its free. The same address range
usually held other blocks earlier, and a whole-trace query mixes their writes in. "The whole
trace" is one click away. Regions use their creation and release events. A byte range picked in the
Memory tab uses the whole trace.

## Tests

- `analyzer/tests/test_serve.cpp`: request parsing, unknown spans, positions.
- `tests/client/data.test.mjs`: `AddressIndex` and `CallModel.activeAt` against brute force, pointer
  candidates, strings, grouping.
- `tests/server/server.test.mjs`: the endpoints, validation, the cache, lanes, cancellation and
  cleanup, against a fake `serve`.
- `tests/integration/memory.test.mjs` (fixtures, x64 and x86), which checks that:
  - `leak_b`'s block holds `0xB2` after its memset but not at its allocation;
  - `p1.h100` is zeroed by ntdll on the allocating thread;
  - the memset writes come from the fixture module, in order, with old values;
  - reads are capped;
  - `HeapFree` arguments link to their blocks.
- `tests/integration/smoke.test.mjs` (beacon): `lpszServerName` reads back as `192.168.81.129`, and
  a writer of those bytes runs from unbacked memory.
- `tests/e2e/memory.mjs <analysisId>`: Threads, a pointer link, the Memory tab, access history,
  and `]`.

## The activity pass and block snapshots

Two analysis options, both **off by default** (Open dialog; server options `activity` and
`snapshots`; analyzer `--activity codefetch|execute|off` and `--snapshots on|off|BYTES`):

- **Record memory activity.** The pass costs one more replay. Measured on the samples:
  - beacon: +18% analysis time;
  - regsvr32: +60%, because its unpacker makes 16.7 M writes to one region.

  That is above the 50% the default was allowed to add, so it is opt-in.
- **Snapshot block contents.** Opt-in because it puts memory of the traced process (possibly
  malware) in the analysis cache (SECURITY.md). It adds almost nothing to the activity pass, which
  it implies.

### The pass (`analyzer/src/replay/activity.cpp`, stage `activity`)

It runs after the model is built, because it needs the blocks and regions. It is one sequential
replay (`ReplaySegmentsSequentially`) with one watchpoint per merged range of every region that is
not an image or a thread stack.
- A stack's addresses stay out even when another region covers them at another time. Stack writes
  are most of a trace's writes.
- Everything is aggregated inside the callback, which runs millions of times, with the last event,
  object and page cached.

**Writes.** Each write is credited to the object it lands in:
- the smallest heap block holding the address, with `allocEvt ≤ evt ≤ freeEvt`, where `evt` is the
  first event at or after the write;
- otherwise the page of the region holding it.

Per object and series bucket, the pass counts writes (`activity.bin`). Per object, it keeps the first
and last writer: their frame (PC + 1 interned in `frames.bin`, so symbolization at `address - 1`
names the PC), event and thread, and whether any writer ran outside every module (`writers.bin`).

**Write-then-execute.** `CodeFetch` watchpoints on the same ranges report code running there:
- A page that runs after being written (since its last execution) is a finding, reported once per
  page, with its last write before the run (`wx.json`).
- `Execute` watchpoints find exactly the same pages, but deliver one hit per instruction: 9 M on
  beacon and 119 M on regsvr32 (+0.4 s and +5.7 s). `--activity execute` keeps them available.

On beacon, 44 pages of the payload region `0x1110000` ran after being written by the loader stub
`0x10c0000`, and 3 pages of the stub were written by `beacon_x64.exe`.

**Snapshots.** A block's first 4 KiB, as it was when last seen: at its free, or at the end of the
trace.
- **Rebuilt from the writes** into it (last write wins; ReplayAPI.md §6). The Write callback's
  thread view holds the new bytes, including stores that run on into the next block.
- **Bytes the kernel or another process wrote** (a `recv` buffer) never arrive as a Write. They
  show as `DataMismatch`, whose callback still sees the old bytes (landmine 27), so they are read
  from the same thread's view at its next callback. Any left pending at the end are read back with a
  seek at the block's free, at most 256 blocks.
- **Bytes never written** during the trace are unknown, counted in `contents.idx`, and stored as 0.

The first design read each block at its free with a seek. That took about 10 ms per block (15.7 s
on beacon, 7.5 s on regsvr32), and replaying forward from stop to stop was no faster. The rebuild
costs nothing measurable.

Checked against the seek-based reads on beacon, where the two differ (6% of blocks, 0.3% of bytes),
an access query shows the last write agrees with the rebuild in 39 of 40 sampled bytes. The seek
returned a stale recorded value.

| File | Record |
|---|---|
| `activity.bin` | 20 B: block u32 (or none), region u32, page u32 (index in the region, or none for a block), bucket u32 (series buckets), writes u32 |
| `writers.bin` | 40 B per object: block, region, page, first and last writer frame, first and last event, first and last thread (u16), writes, flags (1 = a writer outside every module) |
| `flows.bin` | 16 B: bucket u32, from u32 (region holding the writing code, an image region for module code), to u32 (region written), writes u32; sorted by bucket |
| `wx.json` | `{findings: [{region, page, exec: {pos, evt, thread, pc}, write: {pos, evt, thread, pc, frame, region}, writes}]}` |
| `contents.idx` / `contents.bin` | 16 B per block (offset u64, length u32, unknown bytes u32), parallel to `blocks.bin` / the bytes |

`manifest.json` has `activity` (writes, execute hits, ranges, objects, findings) and `snapshots`
(cap, blocks, bytes, bytes changed outside their thread, blocks read back).

### Memory beams

`features/memory-beams.js` draws straight beams (`beams.js` `straightRoute`) in a second beam layer
of the atlas (`atlas.memoryBeams`), separate from the arcing call beams:
- **Writes between regions** come from `flows.bin`. The pass adds the writing code's region to each
  write, cached over that region's extent and lifetime, so this costs nothing measurable. Each
  region pair is one beam between the region boxes' centres, lit over its bucket's events and
  brighter with more writes. Writes within one region are not drawn.
- **The selection's loaded accesses** (after "Load writes") go from the exact code address to the
  exact byte, one beam per code address and 16-byte granule. An access is an instant, so its whole
  line is drawn at once and fades over the beam window. Writes are orange, reads blue, and changes
  from outside the thread violet.

Reads exist only in on-demand access queries: the activity pass records writes.

### Content search

`GET /api/analyses/:id/search?q=&mode=text|hex|pointer` (`server/search.mjs`) scans the snapshots
in 16 MiB chunks of whole blocks and returns up to 500 matches with a preview:
- `text` matches ASCII and UTF-16LE, ignoring the case of ASCII letters;
- `pointer` matches the little-endian, pointer-sized value (4 bytes on x86).

On beacon, `192.168.81.129` finds 95 blocks, including the C2 profile
`192.168.81.129,/jquery-3.3.1.min.js`, written by the payload.

### Tests

- `analyzer/tests/test_activity.cpp`: watch ranges (images out, stacks subtracted), the object
  index, and the page-level cache condition.
- `tests/client/data.test.mjs`: `ActivityModel` heat, the record decoders, search patterns and
  chunked matching.
- `tests/server/server.test.mjs`: the options in the cache key and the analyzer arguments, and the
  search endpoint.
- `tests/integration/memory.test.mjs` (fixtures), which checks that:
  - write totals are consistent;
  - `leak_b`'s last writer is the fixture's memset, on the allocating thread;
  - its snapshot is `0xB2` with nothing unknown, and `p1.h100` is zero;
  - the 4 KiB cap holds;
  - a hex search finds all ten `leak_b` blocks.
- `tests/integration/smoke.test.mjs` (beacon): at least 40 write-then-execute pages in `0x1110000`,
  all written by `0x10c0000`, and the `lpszServerName` block among the search matches.
- `tests/e2e/activity.mjs <analysisId>`: the Notes, the Activity colours, a region's findings, the
  content search, and a block's writers.
