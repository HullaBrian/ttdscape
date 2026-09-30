// The viewer's core: the loaded analysis, the current time, selection and highlights, and the
// registries features extend. Features (client/features/*.js) export install(app) and talk to
// each other only through this object: its state, its events and its registries.
//
// Events (app.on(type, fn)):
//   open      an analysis was loaded (app.data etc. are set)
//   seek      the current event changed               { current, fromPlay }
//   select    the selection changed                   { selection }
//   highlight block or region highlights changed
//   layout    region boxes were (re)laid out
//   render    the scene should be rebuilt for app.current
//   frame     every animation frame, before drawing   { T }
//   theme     the visual theme changed
import { Emitter } from './events.js';
import { loadAnalysis, decodePositions } from '../trace-reader.js';
import { TimeModel } from '../state.js';
import { Stacks } from '../stacks.js';
import { assignBlocks, regionLayout } from '../layout.js';
import { NONE, bytes, hex, REGION_KIND } from '../format.js';

export class App extends Emitter {
  constructor({ atlas, timeline, inspector, rails }) {
    super();
    this.atlas = atlas; this.timeline = timeline; this.inspector = inspector; this.rails = rails;
    this.analysisId = null; this.data = null; this.time = null; this.stacks = null; this.assignment = null; this.layout = null;
    this.current = 0;
    this.playing = false;
    this.playTime = 0;                 // continuous time while playing (event units)
    this.selection = null;
    this.highlight = null;             // { blocks: Set, title }
    this.regionHighlight = new Set();  // regions emphasized in the atlas
    this.regionDim = false;            // dim every region that is not highlighted
    this.reserved = false;             // layout includes reserved address space
    this.spacing = undefined;          // region spacing (layout.js REGION_SPACING); the default when unset
    this.services = {};                // shared services features provide (e.g. services.calls)
    this.hoverText = [];               // (item) => string | null
    this.inspectors = new Map();       // selection kind -> (item) => void (renders into app.inspector)
    this.inspectorSections = [];       // (item) => Node | null, appended below any selection's view
    this.selectionRegion = new Map();  // selection kind -> (item) => region index
    this.notes = [];                   // () => string[] for the analysis notes
    this.keys = [];                    // (KeyboardEvent) => boolean (handled)
    this.positionChunks = new Map();
    this.renderQueued = false;
    atlas.onBeforeRender = () => this.emit('frame', { T: this.now() });
  }

  // ---- server ----
  async api(path, init = {}) {
    const response = await fetch(path, { ...init, headers: { 'X-TTDscape': '1', 'Content-Type': 'application/json', ...init.headers } });
    if (!response.ok) {
      const text = await response.text();
      let message = text;
      try { message = JSON.parse(text).error ?? text; } catch { /* plain text */ }
      throw new Error(`${response.status}: ${message || response.statusText}`);
    }
    return response;
  }

  file(name, init) { return this.api(`/api/analyses/${this.analysisId}/files/${name}`, init); }

  // Bytes [start, end] of an analysis file.
  async range(name, start, end) {
    return (await this.file(name, { headers: { Range: `bytes=${start}-${end}` } })).arrayBuffer();
  }

  // ---- naming ----
  threadName(t) {
    const th = this.data?.manifest.threads[t];
    return th ? `T${th.osTid}` : t === 0xFFFF ? '' : `thread ${t}`;
  }
  heapName(h) {
    const heap = this.data?.manifest.heaps[h];
    return heap ? `Heap ${h} (${heap.kind}) ${heap.handle}` : h === NONE ? '' : `heap ${h}`;
  }
  regionName(r) {
    const { regions } = this.data;
    const kind = regions.kind[r], owner = regions.heap[r];
    switch (kind) {
      case 2: return this.data.manifest.modules[owner]?.name ?? 'Image';
      case 3: return `Stack ${this.threadName(owner)}`;
      case 4: case 6: return owner === NONE ? 'Heap segment' : `Heap ${owner} ${kind === 6 ? '(inferred)' : 'segment'}`;
      case 5: return 'Committed before the trace';
      default: return REGION_KIND[kind] ?? 'Region';
    }
  }
  regionLabel(r) { return `${this.regionName(r)}\n${hex(this.data.regions.base[r])}  ${bytes(this.data.regions.size[r])}`; }

  // TTD position (Seq:Steps) of an event, fetched lazily in chunks.
  async position(i) {
    const CHUNK = 4096;
    if (!this.analysisId || i < 0 || i >= (this.data?.events.count ?? 0)) return null;
    const chunk = Math.floor(i / CHUNK);
    if (!this.positionChunks.has(chunk)) {
      const start = chunk * CHUNK * 16, end = Math.min(this.data.events.count, (chunk + 1) * CHUNK) * 16 - 1;
      this.positionChunks.set(chunk, this.range('positions.bin', start, end).then(decodePositions).catch(() => null));
    }
    const list = await this.positionChunks.get(chunk);
    return list?.[i - chunk * CHUNK] ?? null;
  }

  // ---- analysis ----
  async open(id, { initialEvent, onProgress } = {}) {
    const loaded = await loadAnalysis(name => this.api(`/api/analyses/${id}/files/${name}`), onProgress);
    this.analysisId = id;
    this.data = loaded;
    this.time = new TimeModel(loaded);
    this.stacks = new Stacks(loaded);
    this.assignment = assignBlocks(loaded);
    this.positionChunks = new Map();
    this.selection = null; this.highlight = null;
    this.regionHighlight = new Set(); this.regionDim = false;
    this.playing = false;
    this.relayout();
    this.timeline.setData({ time: this.time, events: loaded.events, markers: loaded.manifest.markers, modules: loaded.manifest.modules });
    this.inspector.clear();
    this.current = Number.isInteger(initialEvent) ? Math.max(0, Math.min(loaded.events.count - 1, initialEvent)) : loaded.events.count - 1;
    this.playTime = this.current;
    this.emit('open');
    this.seek(this.current);
    this.emit('highlight');
    this.atlas.overview();
  }

  relayout() {
    this.layout = regionLayout(this.data, this.time, { reserved: this.reserved, spacing: this.spacing });
    this.atlas.buildStatic(this.layout, r => this.regionLabel(r));
    this.emit('layout');
    this.queueRender();
  }

  // Continuous time on the event axis: the playhead, between events while playing.
  now() { return this.playing ? this.playTime : this.current; }

  // ---- navigation ----
  seek(i, { fromPlay = false } = {}) {
    if (!this.data) return;
    this.current = Math.max(0, Math.min(this.data.events.count - 1, Math.round(i)));
    if (!fromPlay) this.playTime = this.current;
    this.emit('seek', { current: this.current, fromPlay });
    this.queueRender();
  }

  select(item, { focus = false, reveal = false } = {}) {
    this.selection = item;
    this.emit('select', { selection: item, focus, reveal });
    this.refreshInspector(reveal);
    this.queueRender();
  }

  setHighlight(blocks, title = '') {
    this.highlight = blocks?.size ? { blocks, title } : null;
    this.emit('highlight');
    this.refreshInspector();
    this.queueRender();
  }

  setRegionHighlight(regions, dim = this.regionDim) {
    this.regionHighlight = new Set(regions);
    this.regionDim = dim && this.regionHighlight.size > 0;
    this.emit('highlight');
    this.queueRender();
  }

  // The region a selection refers to (for filters such as "calls touching the selection").
  selectedRegion(item = this.selection) {
    if (!item) return NONE;
    if (item.kind === 'region') return item.r;
    if (item.kind === 'span') return this.data.spans.region[item.s];
    if (item.kind === 'block') return this.assignment[item.b];
    return this.selectionRegion.get(item.kind)?.(item) ?? NONE;
  }

  refreshInspector(reveal = false) {
    if (!this.data) return;
    const s = this.selection;
    if (reveal) this.rails.right.panel('main').show('inspector');
    if (!s) {
      if (this.highlight) this.inspector.showBlocks([...this.highlight.blocks], this.highlight.title);
      else this.inspector.clear();
      return;
    }
    if (s.kind === 'block') this.inspector.showBlock(s.b);
    else if (s.kind === 'region') this.inspector.showRegion(s.r);
    else if (s.kind === 'span') this.inspector.showSpan(s.s);
    else this.inspectors.get(s.kind)?.(s);
    // Sections go above the (long) stack lists, where there are any.
    const stacks = this.inspector.root.querySelector(':scope > .stack');
    for (const fn of this.inspectorSections) {
      const node = fn(s);
      if (node) this.inspector.root.insertBefore(node, stacks);
    }
  }

  describeHover(item) {
    for (const fn of this.hoverText) {
      const text = fn(item);
      if (text) return text;
    }
    return null;
  }

  queueRender() {
    if (this.renderQueued) return;
    this.renderQueued = true;
    requestAnimationFrame(() => {
      this.renderQueued = false;
      if (this.data) this.emit('render', { current: this.current });
    });
  }
}
