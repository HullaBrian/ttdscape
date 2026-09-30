// Shared call data: calls.bin / callees.json loaded on first use, decoded arguments fetched by
// range on demand, naming, thread colors and the call filter shared by beams and the calls pane.
// Provides app.services.calls and emits 'calls' when the data is available.
import { loadCalls } from '../trace-reader.js';
import { CallModel, CALL } from '../calls.js';
import { ARG_BLOCK, decodeOffsets, parseArgLines, decodeCallPositions } from '../call-args.js';
import { NONE } from '../format.js';
import { indexColor } from '../themes.js';

export class CallService {
  constructor(app) {
    this.app = app;
    // Filter shared by beams and the calls pane. scope: 'modules' | 'all'; thread: -1 = all;
    // touching: 'any' | 'selection' | 'highlighted'.
    this.filter = { scope: 'modules', thread: -1, touching: 'any' };
    this.reset();
    app.on('open', () => this.reset());
    app.on('layout', () => { this.callerRegions = new Map(); });
    app.on('theme', () => { this.colors = new Map(); });
  }

  reset() {
    this.calls = null; this.model = null; this.loading = null; this.error = null;
    this.argBlocks = new Map();
    this.posBlocks = new Map();
    this.stackBlocks = new Map();
    this.callerRegions = new Map();
    this.colors = new Map();
    this.pace = null;
  }

  get available() { return !!this.app.data?.manifest.files.calls; }
  get hasArgs() { return !!this.app.data?.manifest.files.callargs; }
  get hasPositions() { return !!this.app.data?.manifest.files.callpos; }

  // TTD positions of call i: { call: "SEQ:STEPS", ret } (null when not recorded), fetched by block.
  async positions(i) {
    if (!this.hasPositions || i < 0 || i >= this.calls.count) return null;
    const block = Math.floor(i / ARG_BLOCK);
    let p = this.posBlocks.get(block);
    if (!p) {
      const lo = block * ARG_BLOCK, count = Math.min(ARG_BLOCK, this.calls.count - lo);
      p = this.app.range(this.app.data.manifest.files.callpos.file, lo * 32, (lo + count) * 32 - 1).then(decodeCallPositions).catch(() => []);
      this.posBlocks.set(block, p);
      if (this.posBlocks.size > 512) this.posBlocks.delete(this.posBlocks.keys().next().value);
    }
    return (await p)[i - block * ARG_BLOCK] ?? null;
  }

  // Loads the calls once per analysis. A failure is kept in this.error (not retried every frame)
  // so panels can say what went wrong.
  // stacks.bin node of call i's call stack (the caller's return address first), or NONE.
  async stack(i) {
    const f = this.app.data?.manifest.files.callstacks;
    if (!f || i < 0 || i >= this.calls.count) return NONE;
    const block = Math.floor(i / ARG_BLOCK);
    let p = this.stackBlocks.get(block);
    if (!p) {
      const lo = block * ARG_BLOCK, count = Math.min(ARG_BLOCK, this.calls.count - lo);
      p = this.app.range(f.file, lo * 4, (lo + count) * 4 - 1).then(b => new Uint32Array(b)).catch(() => new Uint32Array(0));
      this.stackBlocks.set(block, p);
      if (this.stackBlocks.size > 512) this.stackBlocks.delete(this.stackBlocks.keys().next().value);
    }
    return (await p)[i - block * ARG_BLOCK] ?? NONE;
  }

  load() {
    if (this.calls || this.error || !this.available) return Promise.resolve(this.calls);
    if (!this.loading) {
      const id = this.app.analysisId;
      this.loading = loadCalls(name => this.app.file(name), this.app.data.manifest).then(calls => {
        if (id !== this.app.analysisId) return null;
        this.calls = calls;
        this.model = calls ? new CallModel(calls) : null;
        this.app.emit('calls');
        return calls;
      }, err => {
        if (id !== this.app.analysisId) return null;
        // A 404 on a file the manifest lists means the server predates it (its whitelist).
        this.error = /^404/.test(err.message)
          ? 'the server does not serve this analysis\'s call files; it is older than the analyzer, so restart it'
          : err.message;
        this.app.emit('calls');
        return null;
      }).finally(() => { this.loading = null; });
    }
    return this.loading;
  }

  // ---- naming ----
  moduleShort(m) { return this.app.data.manifest.modules[m]?.name.replace(/\.[^.]*$/, '').toLowerCase() ?? '?'; }
  calleeText(c) { return `${this.moduleShort(this.calls.callees.module[c])}!${this.calls.callees.name[c]}`; }
  calleeName(c) { return this.calls.callees.name[c]; }
  callerText(i) {
    const via = this.calls.via[i];
    return via !== NONE ? `${this.calleeText(this.calls.callee[via])} (by jump)` : this.app.stacks.frameText(this.calls.callerFrame[i]);
  }
  threadColor(t) {
    let c = this.colors.get(t);
    if (!c) this.colors.set(t, c = indexColor(t, this.app.atlas.theme));
    return c;
  }

  // ---- endpoints ----
  calleeRegion(c) { return this.app.data.manifest.modules[this.calls.callees.module[c]]?.region ?? NONE; }

  // Region of the caller's code (the calling export for a tail jump). Unbacked code is placed by
  // the region live at the call.
  callerRegion(i) {
    const via = this.calls.via[i];
    if (via !== NONE) return this.calleeRegion(this.calls.callee[via]);
    const f = this.calls.callerFrame[i];
    let r = this.callerRegions.get(f);
    if (r === undefined) {
      const { frames, manifest } = this.app.data;
      const m = frames.module[f];
      r = m !== NONE ? manifest.modules[m]?.region ?? NONE : this.app.time.regionAt(frames.addr[f], Math.max(0, this.calls.startEvt[i] - 1));
      this.callerRegions.set(f, r);
    }
    return r;
  }

  callerAddress(i) {
    const via = this.calls.via[i];
    return via !== NONE ? this.calls.callees.addr[this.calls.callee[via]] : this.app.data.frames.addr[this.calls.callerFrame[i]];
  }

  // ---- filter ----
  // Returns accept(i) for the current filter, selection and highlights.
  acceptor() {
    const { scope, thread, touching } = this.filter, calls = this.calls, app = this.app;
    const regions = touching === 'selection' ? new Set([app.selectedRegion()].filter(r => r !== NONE))
      : touching === 'highlighted' ? app.regionHighlight : null;
    return i => {
      if (scope === 'modules' && (calls.flags[i] & CALL.SameModule)) return false;
      if (thread >= 0 && calls.thread[i] !== thread) return false;
      if (!regions) return true;
      return regions.has(this.callerRegion(i)) || regions.has(this.calleeRegion(calls.callee[i]));
    };
  }

  filterKey() {
    const { scope, thread, touching } = this.filter;
    const sel = touching === 'selection' ? this.app.selectedRegion() : touching === 'highlighted' ? [...this.app.regionHighlight].join(',') : '';
    return `${scope}|${thread}|${touching}|${sel}`;
  }

  // Start times of the calls the filter accepts, sorted (for pacing playback by calls).
  paceTimes() {
    const key = this.filterKey();
    if (this.pace?.key !== key) {
      const accept = this.acceptor(), t0 = this.model.t0, out = [];
      for (let i = 0; i < t0.length; i++) if (accept(i)) out.push(t0[i]);
      this.pace = { key, times: Float64Array.from(out) };
    }
    return this.pace.times;
  }

  // ---- decoded arguments ----
  // Arguments of call i (null if not decoded), fetched with the rest of its block.
  async args(i) {
    if (!this.hasArgs || i < 0 || i >= this.calls.count) return null;
    const block = Math.floor(i / ARG_BLOCK);
    let p = this.argBlocks.get(block);
    if (!p) {
      p = this.fetchBlock(block).catch(() => []);
      this.argBlocks.set(block, p);
      if (this.argBlocks.size > 256) this.argBlocks.delete(this.argBlocks.keys().next().value);
    }
    return (await p)[i - block * ARG_BLOCK] ?? null;
  }

  async fetchBlock(block) {
    const f = this.app.data.manifest.files.callargs;
    const lo = block * ARG_BLOCK, count = Math.min(ARG_BLOCK, this.calls.count - lo);
    const offsets = decodeOffsets(await this.app.range(f.index, lo * 8, (lo + count) * 8 + 7), count);
    if (offsets[count] <= offsets[0]) return [];
    const text = new Uint8Array(await this.app.range(f.file, offsets[0], offsets[count] - 1));
    return parseArgLines(text, offsets);
  }
}

export function install(app) {
  app.services.calls = new CallService(app);
}
