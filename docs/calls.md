# Calls, arguments and CAPA

How TTDscape records the calls a traced process makes, places them on the timeline, and shows them:
as beams in the 3D atlas, in the live calls list with decoded arguments, and as CAPA
capabilities. For the viewer's structure, see [viewer-architecture.md](viewer-architecture.md).

## What is recorded

A **call** is a CALL instruction whose target is an **export** of a loaded module, or a jump into
an export that continues the caller's frame. Import thunks (`jmp [__imp_X]`), CFG dispatch
(`jmp rax`) and exports that forward by jumping (`kernel32!HeapFree` → `ntdll!RtlFreeHeap`) are
included. Calls between non-exported functions are not recorded. Recording every call is open work
(below): large traces make 10⁸ or more calls.

Everything happens in the analyzer's single replay pass (`analyzer/src/replay/capture.cpp`):

1. Before the replay, `exports.cpp` reads the export table of every module loaded during the trace.
   It uses the file on disk when its timestamp and size match the recorded module, otherwise the
   image in trace memory. Entry addresses go into an open-addressing `AddressMap` for O(1) lookup in
   the callback.
2. In the CALL/RET callback, a CALL whose target is an export starts a record on the shadow-stack
   frame it pushes (`ShadowStack::Frame::xcall`). An indirect jump whose SP is at the top frame's
   return-address slot and whose target is an export starts a *tail* record chained to the frame's
   previous one (`via`).
3. The RET that pops the frame completes every record in its chain. Pairing uses the
   measured rule `target == retAddr && SP == SP at the CALL`; see
   [ReplayAPI.md](../ReplayAPI.md) §10. A frame discarded without a RET (exception, longjmp) marks
   its records *unwound*.
4. Each record keeps the caller's return address, interned into the stack trie's frame table so it
   is symbolized with the heap stacks. It also keeps the caller's full stack (`callstacks.bin`), its
   depth, and the CALL and RET positions.
5. **Arguments** are decoded at the export's entry by ttd-capa-cpp's decoder, vendored in
   `analyzer/third_party/ttdcapa` and wrapped by `replay/call_args.*`:
   - signatures from win32json and phnt;
   - x64 or x86 layout, chosen by the owning module's bitness (WoW64 runs both);
   - enum and flag names and strings.

   `[Out]` parameters and strings the entry could not see yet are read again at the RET, together
   with the return value.

Cost on the `beacon_x6401` sample trace: 101k calls, about 0.4 s to read the export tables, and
about 300 ms more capture with arguments and stacks.

## Time

The timeline axis is the **event index** (heap, virtual-memory, module, thread and marker events),
not a TTD position. `model/call_times.h` places each call and each return between the two events
that surround it:
- A call belongs before the first event at or after its CALL position.
- A return belongs after an event recorded at the same position.

Calls and returns that fall between the same two events are ranked together by position and spread
evenly, so a call at `e - 1 + frac` never returns before it starts. `calls.bin` is sorted by start
time.

## Files

| File | Contents |
|---|---|
| `calls.bin` | 32 B per call: thread, flags (returned / unwound / tail / same-module), depth, caller frame, callee, start and end event with fractions, `via` |
| `callees.json` | The exports that were called: module, name, address |
| `callpos.bin` | TTD positions of each call and its return |
| `callstacks.bin` | `stacks.bin` node of each call's stack |
| `callargs.bin` + `callargs.jsonl` | Byte offsets, then one JSON object per call with its decoded arguments (keys in `replay/call_args.h`) |
| `capa.json` | CAPA results (below) |

The viewer loads `calls.bin` and `callees.json` when beams or the calls list first need them. It
fetches positions, stacks and arguments in blocks of 64 calls with HTTP range requests, so large
traces cost only what is on screen.

## Beams

`features/call-beams.js`, rendered by `client/beams.js`:
- A call is a light that travels from the caller's code to the export on a cubic Bezier arcing over
  the boxes. It stays lit while the call is active and fades after it returns.
- Endpoints are points inside region boxes: `addressPosition` maps an address into a 16×16×16
  Morton lattice of its region, so nearby code lands nearby.
- Colour is per thread. Repeated calls from one site to one export on one thread merge into one
  brighter beam.
- Allocation calls (`RtlAllocateHeap`, `RtlReAllocateHeap`) send a second light to the block they
  returned.
- Which calls are drawn at time T is `CallModel.visible` (`client/calls.js`). It scans calls that
  started within the beam window, plus a list of long-running calls, and is tested against brute
  force.
- The beam window is expressed in seconds of playback. Pacing playback **by calls**
  (`features/playback.js`) advances a fixed number of filtered calls per second, however unevenly
  they are spread over events.

## CAPA

`server/capa.mjs` runs after the analyzer, using a [ttd-capa-cpp](https://github.com/HullaBrian/ttd-capa-cpp)
checkout (`TTDSCAPE_TTDCAPA`):

1. `ttdcapa-extract <trace> -o report.json` records API calls with decoded arguments (its own replay).
2. `capa-cpp report.json -r rules -j` matches the capa rules on those calls.
3. `ttdcapa-extract --scan-code`, then `capa-cpp --scan-code-manifest`, then `ttdcapa-extract
   --trace-code-hits`. Together they reconstruct code the program created and ran, match the rules
   statically, and find where each matched site executed.

Every match becomes a row with its TTD position, the event it precedes and its thread. `capaRows` is
pure and unit-tested. The code-scan snapshots are raw memory of the traced process. They are written
only under `TTDSCAPE_CAPA_WORK` and deleted after the pass.

## Open work

- **All calls, not only exports**, with a depth limit or sampling, and aggregate buckets (time ×
  thread × caller module × callee module) for zoomed-out views and bundled routes. The timeline's
  call-rate lane and per-site merging cover traces up to about 10⁶ calls.
- **WoW64 transitions:** classify calls into `wow64cpu` as kernel transitions rather than ordinary
  export calls.
- **Arguments:** structures and COM interfaces are not expanded (a limit of the decoder).
- **Cross-thread order:** within one sequence window, positions on different threads may be
  misordered (ReplayAPI.md landmine 30). This is harmless for visuals; tests must not assert strict
  cross-thread order.
