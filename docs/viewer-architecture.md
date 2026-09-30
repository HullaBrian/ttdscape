# Viewer architecture

The viewer is built from an **App core** (`client/app/`) and **features** (`client/features/`).
A feature is a module that exports `install(app)`. `client/main.js` lists the features in order,
and each feature adds its UI and behaviour through the app. Features share nothing except the
`app` object: its state, its events, its services and its registries.

## The core (`client/app/app.js`)

| Member | What it is |
|---|---|
| `data`, `time`, `stacks`, `assignment`, `layout` | The loaded analysis (`trace-reader.js`), time queries (`state.js`), stack naming (`stacks.js`), block→region assignment and region boxes (`layout.js`) |
| `current`, `now()`, `playing`, `playTime` | The playhead: `current` is the event index; `now()` is continuous time on the event axis (between events while playing) |
| `selection`, `highlight`, `regionHighlight`, `regionDim` | The selected item (`{ kind, ... }`), highlighted blocks, and highlighted regions |
| `seek(i)`, `select(item, { focus, reveal })`, `setHighlight(set, title)`, `setRegionHighlight(set, dim)`, `relayout()`, `queueRender()` | State changes; each emits an event |
| `api(path)`, `file(name)`, `range(name, start, end)`, `position(i)` | Server access; `range` reads part of an analysis file (used for lazily loaded tables) |
| `threadName`, `heapName`, `regionName`, `regionLabel`, `selectedRegion(item)` | Naming shared by every panel |

Events (subscribe with `app.on(type, fn)`; the return value unsubscribes):

| Event | When |
|---|---|
| `open` | A new analysis was loaded |
| `seek` | `current` changed (`{ current, fromPlay }`) |
| `select`, `highlight`, `layout`, `theme` | The selection, block/region highlights, region boxes or visual theme changed |
| `render` | The scene should be rebuilt for `current` (batched once per animation frame) |
| `frame` | Every animation frame, before drawing (`{ T }`). Use it for animation, and keep the handler cheap |
| `calls`, `call-filter` | Call data finished loading; the shared call filter changed |

Registries that features extend:

| Registry | Use |
|---|---|
| `app.services.*` | Shared services, for example `services.calls` (`CallService`), `services.playback` (`window()`, `toggle()`), `services.legend.add()`, `services.blockPosition(b)`, `services.pointers` (`targets(i, args)`, `objectAt(addr, evt)`, `link(target)`), `services.memory` (`focus(addr)`, `show(addr)`), `services.blockColors.add(value, text, { block(b, c), page(p, c) })` (colour modes) and `services.activity` (`model`, `findings`, `codeText(frame, evt)`) |
| `app.hoverText.push(item => text \| null)` | Tooltip text for items picked in the 3D view |
| `app.inspectors.set(kind, item => …)` | Inspector content for a selection kind (render with `app.inspector.show(nodes)`) |
| `app.inspectorSections.push(item => Node \| null)` | A section added to any selection's Inspector view (blocks, regions and calls included), above its stack lists. Used by the access history and "Memory this call touched" |
| `app.selectionRegion.set(kind, item => r)` | The region a custom selection refers to (used for marks and "touching the selection" filters) |
| `app.notes.push(() => [lines])` | Lines for the Notes tab |
| `app.keys.push(event => handled)` | Keyboard shortcuts, checked before the built-in ones |
| `app.rails.left/right.panel(id).addTab({ id, title, order, onShow })` | A tab in a side panel; returns its element. Rails are resizable, and the last tab shown is remembered |
| `app.timeline.addLane({ height, draw(ctx, geometry) })` | A track on the timeline |
| `app.atlas` | The Three.js scene. Beams (`atlas.beams`) and region emphasis live outside the per-frame dynamic layer |
| Panels | Each panel's element has `data-panel="<rail>.<id>"` (e.g. `right.calls`), so styles can single one out |

## Features

| Feature | File |
|---|---|
| Memory scene (blocks, pages, gaps), View tab, hover, selection marks, footer | `features/memory-view.js` |
| Playback, keyboard navigation, pacing by events or by calls, beam window, time HUD | `features/playback.js` |
| Call data service: lazy `calls.bin`, argument ranges, shared filter, naming | `features/call-data.js` |
| Call beams and allocation legs | `features/call-beams.js` |
| Call-rate lane on the timeline | `features/call-lane.js` |
| Live calls tab (TTD positions, arguments) and the call Inspector view | `features/live-calls.js` |
| CAPA tab and timeline lane (reads `capa.json` from `server/capa.mjs`; Run CAPA) | `features/capa.js` |
| Pointer links from call arguments to blocks and regions; "Memory this call touched" | `features/pointers.js` |
| Threads tab: each thread's calls in progress at the playhead | `features/threads.js` |
| Memory tab: hex view at the playhead (query service), strings, byte selection | `features/memory-pane.js` |
| Access history in the Inspector, the `bytes` selection kind, access lane, `[` / `]` | `features/access-history.js` |
| Activity colour mode, write lane, writers and write-then-execute in the Inspector and Notes | `features/activity.js` |
| "Contents" search in the Find tab (block snapshots) | `features/content-search.js` |
| Memory beams: straight writes between regions and the selection's accesses (`atlas.memoryBeams`) | `features/memory-beams.js` |
| Cinematic menu: region tour and aerial orbit, optionally keeping the calls panel (paths: `cinematic.js`; camera: `atlas.startCinematic` / `stopCinematic`, `atlas.setFraming` to centre the view in the space panels leave) | `features/cinematic.js` |
| Region browser and highlights | `features/regions.js` |
| Inspector, Legend and Notes tabs; Leaks; Find | `features/panels.js` |
| Open-trace dialog | `features/open-dialog.js` |

Pure logic stays out of features so `tests/client` can test it without a browser:
`calls.js` (visible window, pacing, active calls), `call-args.js` (argument ranges and formatting),
`memory.js` (address index, activity heat, pointer candidates, byte provenance, strings, access
groups),
`region-list.js`, `layout.js` and `state.js`. [memory.md](memory.md) describes the memory features
and the query service behind them.

## Adding something

1. Write `client/features/<name>.js` exporting `install(app)`.
2. Put its controls in a tab (`app.rails.*.panel(...).addTab`) or a group in `app.viewTab`, and
   store user preferences with the `prefKey` option of the `ui.js` field builders.
3. React to `seek`, `select` or `frame` rather than polling, and recompute only when an input
   changes (the beams and the calls pane compare a key string built from their inputs).
4. If it needs new analyzer output, add the file to `manifest.files`, to `RESULT_FILES` in
   `server/jobs.mjs`, and to the loader (lazily, with `app.range` for large tables).
5. List it in `client/main.js` after the services it uses.
