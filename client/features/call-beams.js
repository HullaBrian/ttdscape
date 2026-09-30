// Call beams: calls into module exports drawn as lights travelling from the caller's code to the
// called export, one color per thread (renderer: client/beams.js). Controls live in the View tab;
// the filter they set is shared with the calls pane (app.services.calls.filter).
import { Color } from 'three';
import { CALL, beamPhase } from '../calls.js';
import { beamRoute } from '../beams.js';
import { addressPosition } from '../layout.js';
import { NONE, evtLabel, hex, bytes } from '../format.js';
import { selectField, checkField, element, swatch } from '../ui.js';

const WHITE = new Color('#ffffff');

// Calls whose return creates a heap block: their beam continues from the allocator to the block.
const ALLOCATORS = new Set(['RtlAllocateHeap', 'RtlReAllocateHeap']);
const EV_ALLOC = 1, EV_REALLOC = 3;

export function install(app) {
  const { atlas } = app, svc = app.services.calls;

  const group = element('div', '', 'group');
  const show = selectField('calls', 'Show calls', [['off', 'Off'], ['modules', "Into other modules' exports"], ['all', 'Into any export']], 'modules', { prefKey: 'beams.show' });
  const thread = selectField('call-thread', 'Calls on thread', [['', 'All threads']], '');
  const touching = selectField('call-touching', 'Calls touching', [['any', 'Any region'], ['selection', 'The selected region'], ['highlighted', 'Highlighted regions']], 'any',
    { title: 'Keep only calls whose caller or callee is in these regions' });
  const follow = checkField('call-alloc', 'Follow allocations to their blocks', true,
    { prefKey: 'beams.alloc', title: 'When RtlAllocateHeap / RtlReAllocateHeap returns, a second light travels to the block it created' });
  group.append(element('h2', 'Call beams'), show.label, thread.label, touching.label, follow.label);
  app.viewTab.append(group);

  const syncFilter = () => {
    svc.filter.scope = show.input.value === 'all' ? 'all' : 'modules';
    svc.filter.thread = thread.input.value === '' ? -1 : Number(thread.input.value);
    svc.filter.touching = touching.input.value;
    app.emit('call-filter');
  };
  syncFilter();
  show.input.addEventListener('change', () => { syncFilter(); if (show.input.value !== 'off') svc.load(); });
  thread.input.addEventListener('change', syncFilter);
  touching.input.addEventListener('change', syncFilter);

  // Legend entry, filled per analysis.
  const legend = element('span');
  app.services.legend?.add('Call beams', 'A light travels from the calling code to the export it calls, one color per thread; the path stays lit while the call is active. Repeated calls from one site are one brighter beam.', legend);
  legend.id = 'beam-legend';

  function renderThreads() {
    legend.replaceChildren();
    const keep = thread.input.value;
    thread.input.replaceChildren(Object.assign(element('option', 'All threads'), { value: '' }));
    if (!app.data) return;
    if (!svc.available) { legend.append(element('span', 'Not recorded in this analysis; analyze the trace again.', 'muted')); return; }
    if (svc.error) { legend.append(element('span', `Could not load the calls: ${svc.error}.`, 'muted')); return; }
    if (!svc.calls) return;
    const per = new Map();
    for (let i = 0; i < svc.calls.count; i++) per.set(svc.calls.thread[i], (per.get(svc.calls.thread[i]) ?? 0) + 1);
    for (const [t, n] of [...per].sort((a, b) => a[0] - b[0])) {
      legend.append(swatch(app.threadName(t), `#${svc.threadColor(t).getHexString()}`, `${n.toLocaleString()} calls`));
      thread.input.append(Object.assign(element('option', `${app.threadName(t)} (${n.toLocaleString()} calls)`), { value: String(t) }));
    }
    thread.input.value = [...thread.input.options].some(o => o.value === keep) ? keep : '';
    syncFilter();
  }

  // Beam endpoints and routes, cached per layout.
  let points = new Map(), routes = new Map(), lastKey = '', allocBlocks = new Map();
  const reset = () => { points = new Map(); routes = new Map(); lastKey = ''; };
  app.on('open', () => { allocBlocks = new Map(); });
  follow.input.addEventListener('change', () => { lastKey = ''; });
  // Allocation legs point at blocks where the scene last drew them: recompute after each render.
  app.on('render', () => { if (follow.input.checked) lastKey = ''; });

  // The block an allocation call created: the Alloc/ReAlloc event its RET produced, on its thread.
  function allocatedBlock(i) {
    let b = allocBlocks.get(i);
    if (b !== undefined) return b;
    b = NONE;
    const c = calls(), { events } = app.data;
    if (c.endEvt[i] !== NONE && ALLOCATORS.has(svc.calleeName(c.callee[i]))) {
      for (let e = Math.min(events.count - 1, c.endEvt[i] - 1); e >= Math.max(0, c.endEvt[i] - 3); e--) {
        if ((events.kind[e] === EV_ALLOC || events.kind[e] === EV_REALLOC) && events.thread[e] === c.thread[i]) { b = events.id[e]; break; }
      }
    }
    allocBlocks.set(i, b);
    return b;
  }
  app.on('layout', reset);
  app.on('open', () => { reset(); atlas.beams.update([]); renderThreads(); if (show.input.value !== 'off') svc.load(); });
  app.on('calls', renderThreads);
  app.on('theme', () => { lastKey = ''; renderThreads(); });

  function point(key, region, addr) {
    let p = points.get(key);
    if (p === undefined) {
      const item = region === NONE ? null : app.layout.byRegion[region];
      points.set(key, p = item ? addressPosition(addr, item) : null);
    }
    return p;
  }
  const calls = () => svc.calls;
  const fromKey = i => calls().via[i] !== NONE ? `x${calls().callee[calls().via[i]]}` : `f${calls().callerFrame[i]}`;
  const fromPoint = i => point(fromKey(i), svc.callerRegion(i), svc.callerAddress(i));
  const toPoint = c => point(`x${c}`, svc.calleeRegion(c), calls().callees.addr[c]);

  app.on('frame', ({ T }) => {
    const on = show.input.value !== 'off' && !!svc.model;
    atlas.beams.visible = on;
    if (!on || !app.data) return;
    const W = app.services.playback.window();
    const key = `${T}|${W}|${svc.filterKey()}|${atlas.theme.name}|${follow.input.checked}`;
    if (key === lastKey) return;
    lastKey = key;
    const filter = svc.acceptor();
    const accept = i => filter(i) && !!fromPoint(i) && !!toPoint(calls().callee[i]);
    // Repeated calls from one site to one export on one thread are one beam (brighter with count).
    const merge = i => `${calls().thread[i]}|${fromKey(i)}>${calls().callee[i]}`;
    const { beams } = svc.model.visible(T, W, { accept, key: merge, budget: atlas.beams.capacity });
    for (const b of beams) {
      const c = calls().callee[b.i], rk = `${fromKey(b.i)}>${c}`;
      let route = routes.get(rk);
      if (!route) routes.set(rk, route = beamRoute(fromPoint(b.i), toPoint(c)));
      b.route = route;
      b.color = svc.threadColor(calls().thread[b.i]);
    }
    // Allocation legs: from the allocator to the new block, starting when the call returns.
    if (follow.input.checked) {
      const legs = [];
      for (const b of beams) {
        if (beams.length + legs.length >= atlas.beams.capacity) break;
        const blk = allocatedBlock(b.i);
        if (blk === NONE) continue;
        const t1 = svc.model.t1[b.i], phase = beamPhase(t1, t1, T, W);
        const at = phase && app.services.blockPosition(blk);
        if (!at) continue;
        const c = calls().callee[b.i];
        legs.push({ i: b.i, count: 1, phase, leg: blk, route: beamRoute(toPoint(c), at.position), color: b.color.clone().lerp(WHITE, 0.35) });
      }
      beams.push(...legs);
    }
    atlas.beams.update(beams);
  });

  // A beam selects its call; the call's region (for marks and filters) is the callee's module.
  app.selectionRegion.set('call', item => svc.calls ? svc.calleeRegion(svc.calls.callee[item.i]) : NONE);
  app.hoverText.push(item => {
    if (item.kind !== 'call' || !svc.calls) return null;
    const i = item.i, c = svc.calls;
    if (item.leg !== undefined) {
      const { blocks } = app.data;
      return `${svc.calleeText(c.callee[i])} returned block ${hex(blocks.addr[item.leg])}  ${bytes(blocks.size[item.leg])}\n` +
        `${app.heapName(blocks.heap[item.leg])}  ·  ${app.threadName(c.thread[i])}\nClick for the call's arguments`;
    }
    const state = c.endEvt[i] !== NONE ? '' : c.flags[i] & CALL.Unwound ? '  ·  unwound' : '  ·  never returned';
    return `${svc.callerText(i)}\n→ ${svc.calleeText(c.callee[i])}\n${app.threadName(c.thread[i])}  ·  depth ${c.depth[i]}  ·  before event ${evtLabel(c.startEvt[i])}` +
      `${item.phase?.held ? '  ·  active' : ''}${state}${item.count > 1 ? `\n×${item.count.toLocaleString()} from this site in the beam window` : ''}\nClick for arguments`;
  });
}
