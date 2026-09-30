// The memory atlas at the current event: heap blocks, committed pages and gaps inside the fixed
// region boxes, the View tab that styles them, hover text, selection marks and the footer.
import { regionPieces, placePieces, contentSignature, REGION_SPACING } from '../layout.js';
import { NONE, bytes, hex } from '../format.js';
import { hashColor, indexColor, sizeColor, ageColor, protectColor } from '../themes.js';
import { describeEvent } from '../inspector.js';
import { selectField, checkField, element } from '../ui.js';
import { load } from '../app/prefs.js';
import { unbackedExecutable } from '../region-list.js';

const $ = id => document.getElementById(id);

export function install(app) {
  const { atlas } = app;
  let pieceCache = new Map(), lastPos = new Map();

  // ---- View tab ----
  const tab = app.rails.left.panel('main').addTab({ id: 'view', title: 'View', order: 10 });
  const color = selectField('color', 'Color blocks by', [['heap', 'Heap'], ['site', 'Allocation site'], ['thread', 'Allocating thread'], ['age', 'Age'], ['size', 'Size']], 'heap', { prefKey: 'view.color' });
  const leaks = checkField('leaks', 'Mark blocks never freed');
  const ghosts = checkField('ghosts', 'Show recently freed blocks', true, { prefKey: 'view.ghosts' });
  const ghostRegions = checkField('ghost-regions', 'Show regions not yet created / released', true, { prefKey: 'view.ghostRegions' });
  const reserved = checkField('reserved', 'Include reserved address space');
  const spacing = selectField('spacing', 'Region spacing', [['compact', 'Compact'], ['normal', 'Normal'], ['wide', 'Wide']], 'normal',
    { prefKey: 'view.spacing', title: 'Room between region boxes, relative to their typical size' });
  app.spacing = REGION_SPACING[spacing.input.value];
  const alerts = checkField('exec-alerts', 'Flag executable memory outside modules', true,
    { prefKey: 'view.execAlerts', title: 'Regions that are not a module image but have executable pages at the playhead: shellcode, JIT, unpacked or manually mapped code' });
  const theme = selectField('theme', 'Visual theme', [['atlas', 'Atlas'], ['matrix', 'Matrix'], ['neon', 'Neon Circuit'], ['prism', 'Prism']], 'prism', { prefKey: 'view.theme' });
  const memory = element('div', '', 'group');
  memory.append(element('h2', 'Memory'), color.label, leaks.label, ghosts.label, ghostRegions.label, reserved.label, spacing.label, alerts.label, theme.label);
  tab.append(memory);
  app.viewTab = tab; // other features append their own groups (call beams, playback)

  for (const c of [color, leaks, ghosts, ghostRegions, alerts]) c.input.addEventListener('change', () => app.queueRender());

  // Colour modes features add: { block(b, c), page(p, c) } by value (e.g. Activity).
  const colorModes = new Map();
  app.services.blockColors = {
    add(value, text, mode) {
      colorModes.set(value, mode);
      const o = element('option', text);
      o.value = value;
      color.input.append(o);
      if (load('view.color') === value) color.input.value = value; // the stored choice, now that it exists
    },
    mode: () => color.input.value,
  };

  // Executable memory outside any module, at the playhead and over the whole trace.
  let everExec = null;
  app.services.unbackedExec = {
    at: i => unbackedExecutable(app.data, app.time, i),
    ever: () => (everExec ??= unbackedExecutable(app.data, app.time)),
  };
  app.on('open', () => { everExec = null; });
  app.services.legend?.add('Pulsing red regions', 'Executable pages outside any module image at the playhead (shellcode, JIT, unpacked or manually mapped code). Toggle in the View tab; list them in the Regions tab.');
  spacing.input.addEventListener('change', () => {
    app.spacing = REGION_SPACING[spacing.input.value];
    if (app.data) { app.relayout(); atlas.overview(); }
  });
  reserved.input.addEventListener('change', () => {
    app.reserved = reserved.input.checked;
    if (app.data) { app.relayout(); atlas.overview(); }
  });
  const applyTheme = () => {
    document.documentElement.dataset.theme = theme.input.value;
    atlas.setTheme(theme.input.value);
    if (app.data) { atlas.buildStatic(app.layout, r => app.regionLabel(r)); app.queueRender(); }
    app.timeline.draw();
    app.emit('theme');
  };
  theme.input.addEventListener('change', applyTheme);
  if (theme.input.value !== 'prism') applyTheme();

  app.on('open', () => { pieceCache = new Map(); lastPos = new Map(); });
  // Where a block was last drawn ({ position, side }), for features that point at blocks.
  app.services.blockPosition = b => lastPos.get(b) ?? null;
  app.on('layout', () => { pieceCache = new Map(); });
  app.on('highlight', () => atlas.setRegionEmphasis(app.regionHighlight, app.regionDim));

  function blockColor(p, c) {
    const { blocks } = app.data, b = p.b;
    if (leaks.input.checked && blocks.freeEvt[b] === NONE && blocks.allocEvt[b] !== NONE) return c.set(atlas.theme.leak);
    const extra = colorModes.get(color.input.value);
    if (extra) return extra.block(b, c);
    switch (color.input.value) {
      case 'thread': return indexColor(blocks.allocThread[b] === 0xFFFF ? 0 : blocks.allocThread[b], atlas.theme, c);
      case 'site': return hashColor(app.stacks.siteFrame(blocks.allocStack[b]), atlas.theme, c);
      case 'size': return sizeColor(blocks.size[b], c);
      case 'age': {
        const age = blocks.allocEvt[b] === NONE ? app.current + 1 : app.current - blocks.allocEvt[b];
        return ageColor(Math.log2(1 + age) / Math.log2(2 + Math.max(1, app.data.events.count)), c);
      }
      default: return indexColor(blocks.heap[b], atlas.theme, c);
    }
  }
  const pageColor = (p, c) => colorModes.get(color.input.value)?.page?.(p, c) ?? protectColor(p.protect, atlas.theme, c);

  function computeFrame(i) {
    const { time, data, layout, assignment } = app;
    const withReserved = reserved.input.checked;
    const live = time.liveBlocksAt(i);
    const byRegion = new Map();
    let unplaced = 0;
    for (const b of live) {
      const r = assignment[b];
      if (r === NONE || !time.regionLive(r, i)) { unplaced++; continue; }
      let list = byRegion.get(r);
      if (!list) byRegion.set(r, list = []);
      list.push(b);
    }
    const frame = { blocks: [], pages: [], gaps: [], ghosts: [], blockColor, pageColor, unplaced, liveCount: live.length };
    for (const r of time.liveRegionsAt(i)) {
      const item = layout.byRegion[r];
      const blockIds = byRegion.get(r) ?? [];
      const spanIds = time.spansAt(r, i);
      const sig = `${contentSignature(blockIds, spanIds)}:${withReserved}`;
      let cached = pieceCache.get(r);
      if (!cached || cached.sig !== sig) {
        cached = { sig, pieces: placePieces(item, regionPieces(item, blockIds, data.blocks, spanIds, data.spans, { reserved: withReserved })).pieces };
        pieceCache.set(r, cached);
      }
      for (const p of cached.pieces) {
        if (p.kind === 'block') { frame.blocks.push(p); lastPos.set(p.b, p); }
        else if (p.kind === 'pages') frame.pages.push({ ...p, r });
        else frame.gaps.push(p);
      }
    }
    if (ghosts.input.checked) {
      for (const b of time.recentlyFreed(i, Math.max(20, Math.round(data.events.count / 200)))) {
        const p = lastPos.get(b);
        if (p) frame.ghosts.push({ b, position: p.position, side: p.side });
      }
    }
    const regionDim = app.regionDim ? r => !app.regionHighlight.has(r) : null;
    if (app.highlight || regionDim) {
      const hl = app.highlight?.blocks;
      frame.dimmed = p => (hl && !hl.has(p.b)) || (regionDim && regionDim(assignment[p.b]));
    }
    return frame;
  }

  function mark(frame) {
    atlas.mark(null);
    if (app.highlight) atlas.markMany(frame.blocks.filter(p => app.highlight.blocks.has(p.b)).slice(0, 5000));
    const s = app.selection;
    if (!s) return;
    if (s.kind === 'block') {
      const p = frame.blocks.find(x => x.b === s.b) ?? lastPos.get(s.b);
      if (p) atlas.mark(p.position, [p.side, p.side, p.side]);
      return;
    }
    const r = app.selectedRegion(s);
    if (r !== NONE && app.layout.byRegion[r]) atlas.mark(app.layout.byRegion[r].position, app.layout.byRegion[r].size);
  }

  app.on('render', ({ current }) => {
    const { time, data } = app;
    const frame = computeFrame(current);
    atlas.showFrame(frame);
    atlas.setRegionLiveness(r => time.regionLive(r, current), ghostRegions.input.checked);
    app.timeline.setCurrent(current);
    atlas.setRegionAlerts(alerts.input.checked ? app.services.unbackedExec.at(current) : new Set());
    mark(frame);
    const heapLive = time.heapLive[current] ?? time.heapStart;
    $('counts').textContent = `${frame.liveCount.toLocaleString()} live blocks (${bytes(heapLive)})  ·  ` +
      `${time.liveRegionsAt(current).length} regions, ${bytes(time.committed[current] ?? 0)} committed` +
      (frame.unplaced ? `  ·  ${frame.unplaced} blocks outside known regions` : '');
    $('event').textContent = describeEvent(current, { data, stacks: app.stacks, threadName: t => app.threadName(t), heapName: h => app.heapName(h) });
  });

  app.on('select', ({ selection, focus }) => {
    if (!focus || !selection) return;
    if (selection.kind === 'block') {
      const p = lastPos.get(selection.b);
      if (p) atlas.focus(p.position, [p.side, p.side, p.side]);
    } else {
      const r = app.selectedRegion(selection);
      const item = r === NONE ? null : app.layout.byRegion[r];
      if (item) atlas.focus(item.position, item.size);
    }
  });

  app.hoverText.push(item => {
    const { data } = app;
    if (item.kind === 'block') {
      const b = item.b;
      return `${item.ghost ? 'freed ' : ''}block ${hex(data.blocks.addr[b])}  ${bytes(data.blocks.size[b])}\n${app.heapName(data.blocks.heap[b])}\n${app.stacks.siteText(data.blocks.allocStack[b])}`;
    }
    if (item.kind === 'span') {
      const s = item.s;
      return `${app.regionName(data.spans.region[s])}\n${hex(data.spans.start[s])} +${bytes(data.spans.end[s] - data.spans.start[s])}  ${data.spans.state[s] === 2 ? 'committed' : 'reserved'}`;
    }
    if (item.kind === 'region') {
      const exec = app.services.unbackedExec.at(app.current).has(item.r);
      return `${app.regionLabel(item.r)}${exec ? '\n⚠ executable pages outside any module' : ''}`;
    }
    return null;
  });
}
