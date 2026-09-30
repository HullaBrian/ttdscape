// Memory beams: reads and writes as straight lights between regions (renderer: client/beams.js,
// atlas.memoryBeams), separate from the arcing call beams.
//   - Writes between regions, from the activity pass (flows.bin: per time bucket, the region of the
//     writing code -> the region written). A beam per region pair, brighter with more writes.
//   - The selection's loaded access history (access-history.js): each write, read or outside change
//     travels from the exact code address to the exact byte, at its moment.
// Colors: writes orange, reads blue, changes from outside the thread violet.
import { Color } from 'three';
import { beamPhase } from '../calls.js';
import { straightRoute } from '../beams.js';
import { addressPosition } from '../layout.js';
import { decodeFlows } from '../trace-reader.js';
import { FlowModel } from '../memory.js';
import { NONE, evtLabel, hex } from '../format.js';
import { element, selectField, checkField } from '../ui.js';
import { facts, button } from '../inspector.js';

const COLOR = { w: new Color('#ff8a3d'), r: new Color('#5aa9f2'), m: new Color('#c084fc') };
const KIND = { w: 'writes', r: 'reads', m: 'changes from outside the thread' };

export function install(app) {
  const { atlas } = app;
  const group = element('div', '', 'group');
  const flowsField = selectField('memory-beams', 'Show writes as beams', [['regions', 'Between regions (activity)'], ['off', 'Off']], 'regions',
    { prefKey: 'beams.memory', title: 'Straight beams from the region of the writing code to the region written (analyses with "Record memory activity")' });
  const accessField = checkField('access-beams', "The selection's loaded accesses", true,
    { prefKey: 'beams.accesses', title: 'After "Load writes" in the Inspector: each access as a beam from its code to its byte' });
  const note = element('p', '', 'muted');
  group.append(element('h2', 'Memory beams'), flowsField.label, accessField.label, note);
  app.viewTab.append(group);

  let flows = null, lastKey = '';
  const points = new Map(), routes = new Map(), regionOfPc = new Map();

  app.on('open', async () => {
    flows = null; lastKey = ''; points.clear(); routes.clear(); regionOfPc.clear();
    atlas.memoryBeams.update([]);
    const f = app.data.manifest.files.flows;
    note.textContent = f ? '' : 'This analysis has no write flows; analyze again with "Record memory activity" (the selection\'s accesses still show).';
    if (!f) return;
    const id = app.analysisId;
    try {
      const buf = await (await app.file(f.file)).arrayBuffer();
      if (id === app.analysisId) flows = new FlowModel(decodeFlows(buf), app.data.series);
    } catch (err) {
      if (id === app.analysisId) note.textContent = `Could not load the write flows: ${err.message}.`;
    }
    lastKey = '';
  });
  app.on('layout', () => { points.clear(); routes.clear(); lastKey = ''; });
  app.on('accesses', () => { lastKey = ''; });
  app.on('select', () => { lastKey = ''; });
  for (const f of [flowsField, accessField]) f.input.addEventListener('change', () => { lastKey = ''; });

  // A region's anchor: its box's centre (flows are per region).
  function center(r) {
    const item = r === NONE ? null : app.layout.byRegion[r];
    return item ? item.position : null;
  }
  // A point for an address inside the region live at evt (cached per address and region).
  function pointAt(addr, evt) {
    let r = regionOfPc.get(addr);
    if (r === undefined || !app.time.regionLive(r, evt)) regionOfPc.set(addr, r = app.time.regionAt(addr, Math.min(evt, app.data.events.count - 1)));
    const item = r === NONE ? null : app.layout.byRegion[r];
    if (!item) return null;
    const key = `${r}|${addr}`;
    let p = points.get(key);
    if (!p) points.set(key, p = addressPosition(addr, item));
    return { r, p };
  }
  function route(key, from, to) {
    let rt = routes.get(key);
    if (!rt) routes.set(key, rt = straightRoute(from, to));
    return rt;
  }

  app.on('frame', ({ T }) => {
    const showFlows = flowsField.input.value === 'regions' && flows, showAccess = accessField.input.checked;
    atlas.memoryBeams.visible = !!(app.data && (showFlows || showAccess));
    if (!app.data || !atlas.memoryBeams.group.visible) return;
    const W = app.services.playback.window();
    const hits = showAccess ? app.services.accesses?.selected()?.hits : null;
    const key = `${T}|${W}|${!!showFlows}|${hits ? hits.length : 0}|${app.selection?.kind}|${app.layout.items.length}`;
    if (key === lastKey) return;
    lastKey = key;
    const beams = [], cap = atlas.memoryBeams.capacity;

    // The selection's accesses: exact code address -> exact byte, drawn whole and fading.
    if (hits) {
      const merged = new Map();
      for (const h of hits) {
        const t0 = h.evt - 0.5;
        if (t0 > T || t0 < T - W) continue;
        // An access is an instant: the whole line at once, fading over the beam window.
        const phase = { progress: 1, alpha: Math.max(0.2, 1 - (T - t0) / Math.max(W, 1e-9)), held: true };
        const pc = Number.parseInt(h.pc.slice(2), 16), addr = Number.parseInt(h.addr.slice(2), 16);
        const from = pointAt(pc, h.evt), to = pointAt(addr, h.evt);
        if (!from || !to) continue;
        // One beam per code address and 16-byte granule: a memcpy is a handful of beams, not one per byte.
        const k = `${h.kind}|${pc}|${Math.floor(addr / 16)}`;
        const b = merged.get(k);
        if (b) { b.count++; if (t0 > b.t0) { b.t0 = t0; b.phase = phase; b.item.hit = h; } continue; }
        merged.set(k, { t0, count: 1, phase, color: COLOR[h.kind], route: route(`a${k}`, from.p, to.p),
          item: { kind: 'access-beam', hit: h, from: from.r, to: to.r } });
      }
      beams.push(...[...merged.values()].sort((a, b) => b.t0 - a.t0).slice(0, cap));
    }

    // Writes between regions: one beam per region pair, the newest bucket's phase, counts summed.
    if (showFlows && beams.length < cap) {
      const f = flows.flows, pairs = new Map();
      for (const i of flows.between(T - W, T)) {
        const [t0, t1] = flows.span(i);
        const phase = beamPhase(t0, t1, T, W);
        if (!phase) continue;
        const from = center(f.from[i]), to = center(f.to[i]);
        if (!from || !to) continue;
        const k = `${f.from[i]}>${f.to[i]}`, b = pairs.get(k);
        if (b) { b.count += f.writes[i]; if (t0 > b.t0) { b.t0 = t0; b.phase = phase; } continue; }
        pairs.set(k, { t0, count: f.writes[i], phase, color: COLOR.w, route: route(`f${k}`, from, to),
          item: { kind: 'flow', from: f.from[i], to: f.to[i], bucket: f.bucket[i] } });
      }
      for (const b of pairs.values()) b.item.writes = b.count;
      beams.push(...[...pairs.values()].sort((a, b) => b.count - a.count).slice(0, cap - beams.length));
    }
    atlas.memoryBeams.update(beams);
  });

  // ---- hover and selection ----
  const regionText = r => (r === NONE || r === undefined ? 'unknown memory' : `${app.regionName(r)} ${hex(app.data.regions.base[r])}`);
  app.hoverText.push(item => {
    if (item.kind === 'flow') {
      const [t0, t1] = [item.bucket, item.bucket + 1].map(b => b * flows.eventsPerBucket);
      return `${item.writes.toLocaleString()} writes around events ${evtLabel(Math.round(t0))}–${evtLabel(Math.round(t1))}\n` +
        `from code in ${regionText(item.from)}\ninto ${regionText(item.to)}\nClick to inspect`;
    }
    if (item.kind === 'access-beam') {
      const h = item.hit;
      return `${KIND[h.kind].replace(/s$/, '')} at ${evtLabel(h.evt)} (TTD ${h.pos})\n${app.services.accesses.writer(h)}\n→ ${h.addr} (${h.size} B)` +
        `${h.new ? `  ${h.old ? `${h.old} → ` : ''}${h.new}` : ''}`;
    }
    return null;
  });
  app.selectionRegion.set('flow', item => item.to);
  app.selectionRegion.set('access-beam', item => item.to);
  app.inspectors.set('flow', item => {
    const [t0, t1] = [item.bucket, item.bucket + 1].map(b => b * flows.eventsPerBucket);
    const actions = element('div', '', 'actions');
    if (item.from !== NONE) actions.append(button('Writing code\'s region', () => app.select({ kind: 'region', r: item.from }, { focus: true })));
    if (item.to !== NONE) actions.append(button('Region written', () => app.select({ kind: 'region', r: item.to }, { focus: true })));
    app.inspector.show([element('h3', 'Writes between regions'),
      facts([['From code in', regionText(item.from)], ['Into', regionText(item.to)], ['Writes', item.writes.toLocaleString()],
        ['Around', `events ${evtLabel(Math.round(t0))} – ${evtLabel(Math.round(t1))}`]]), actions]);
  });
  app.inspectors.set('access-beam', item => {
    const h = item.hit;
    const actions = element('div', '', 'actions');
    actions.append(button('Go to the event after it', () => app.seek(Math.min(app.data.events.count - 1, h.evt))));
    if (item.to !== NONE) actions.append(button('Region accessed', () => app.select({ kind: 'region', r: item.to }, { focus: true })));
    app.inspector.show([element('h3', `${KIND[h.kind].replace(/s$/, '')} ${h.addr}`),
      facts([['Code', app.services.accesses.writer(h)], ['PC', h.pc], ['Thread', app.threadName(app.data.manifest.threads.findIndex(t => t.utid === h.utid))],
        ['TTD position', h.pos], ['Size', `${h.size} B`], ['Old', h.old], ['New', h.new]]), actions]);
  });
  app.services.legend?.add('Memory beams', 'Straight lights: writes (orange) from the region of the writing code into the region written, brighter with more writes (activity analyses); and the selection\'s loaded accesses from code to byte: writes orange, reads blue, outside changes violet.');
}
