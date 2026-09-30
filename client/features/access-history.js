// Access history: every write to a block, region or selected byte range (old → new value), bytes
// changed from outside the thread (the kernel, another thread or process), and reads on request,
// each with its TTD position, thread and code. One replay with a memory watchpoint per query
// (POST .../accesses; analyzer accesses.query), cached by the server.
//
// Shown in the Inspector below the selection, grouped by the code that made the accesses, with a
// timeline lane of the loaded accesses. [ and ] step to the previous / next access.
import { groupAccesses } from '../memory.js';
import { NONE, bytes as sizeText, evtLabel, hex } from '../format.js';
import { element, selectField, checkField } from '../ui.js';
import { facts, button } from '../inspector.js';

const RANGE_MAX = 1 << 20;   // the server's limit per query
const LIMIT = 5000;
const ROWS = 300;
const KIND = { w: 'write', r: 'read', m: 'changed outside the thread' };
const KIND_SHORT = { w: 'W', r: 'R', m: 'K' };
const KIND_COLOR = { w: '#f59e0b', r: '#60a5fa', m: '#c084fc' };

export function install(app) {
  const results = new Map();  // query key -> result (or { error })
  let running = null;         // { key, controller, fraction }
  let utids = new Map();      // utid -> thread index
  const filters = new Map();  // query key -> writer label shown alone
  // Controls are shared by every selection (and remembered).
  const scope = selectField('access-scope', 'Over', [['life', 'its lifetime'], ['all', 'the whole trace']], 'life', { prefKey: 'accesses.scope' });
  const reads = checkField('access-reads', 'Include reads (slower)', false, { title: 'Reads can be many times more numerous than writes; they are capped at 5000 accesses per query.' });

  app.on('open', () => {
    results.clear(); filters.clear();
    running?.controller.abort();
    running = null;
    utids = new Map(app.data.manifest.threads.map(t => [t.utid, t.index]));
  });

  // The byte range and event span a selection's history covers, or null.
  function query(item) {
    if (!item || !app.data) return null;
    const { blocks, regions, spans } = app.data, n = app.data.events.count;
    let lo, hi, from, to, label;
    if (item.kind === 'block') {
      lo = blocks.addr[item.b]; hi = lo + Math.max(1, blocks.flags[item.b] & 0x02 ? 16 : blocks.size[item.b]);
      // From just before the allocating call (its zeroing is part of the story) through its free.
      from = blocks.allocEvt[item.b] === NONE ? undefined : blocks.allocEvt[item.b] - 1;
      to = blocks.freeEvt[item.b] === NONE ? undefined : Math.min(n - 1, blocks.freeEvt[item.b] + 1);
      label = 'block';
    } else if (item.kind === 'region') {
      lo = regions.base[item.r]; hi = lo + regions.size[item.r];
      from = regions.createEvt[item.r] === NONE ? undefined : regions.createEvt[item.r] - 1;
      to = regions.releaseEvt[item.r] === NONE ? undefined : Math.min(n - 1, regions.releaseEvt[item.r] + 1);
      label = 'region';
    } else if (item.kind === 'span') {
      lo = spans.start[item.s]; hi = spans.end[item.s];
      from = spans.startEvt[item.s] === NONE ? undefined : spans.startEvt[item.s] - 1;
      to = spans.endEvt[item.s] === NONE ? undefined : Math.min(n - 1, spans.endEvt[item.s] + 1);
      label = 'pages';
    } else if (item.kind === 'bytes') {
      ({ lo, hi } = item);
      label = 'bytes';
    } else return null;
    const clipped = hi - lo > RANGE_MAX;
    if (clipped) hi = lo + RANGE_MAX;
    if (scope.input.value === 'all' || item.kind === 'bytes') { from = undefined; to = undefined; }
    if (from !== undefined && from < -1) from = -1;
    const params = { lo: hex(lo), hi: hex(hi), reads: reads.input.checked, limit: LIMIT };
    if (from !== undefined) params.from = from;
    if (to !== undefined) params.to = to;
    return { params, key: JSON.stringify(params), lo, hi, clipped, label };
  }

  // The code behind an access: its symbol, or the region of unbacked code. writerGroup is the
  // function (or region) without the offset, which is what "who wrote this" means.
  function writerGroup(h) {
    return writer(h).replace(/ ?\+0x[0-9a-f]+$/, '');
  }

  function writer(h) {
    if (h.module !== null && h.sym) return h.sym;
    const pc = Number.parseInt(h.pc.slice(2), 16);
    const r = app.time.regionAt(pc, Math.min(h.evt, app.data.events.count - 1));
    return r === NONE ? `(unbacked) ${h.pc}` : `(unbacked) ${app.regionName(r)} ${hex(app.data.regions.base[r])} +0x${(pc - app.data.regions.base[r]).toString(16)}`;
  }

  async function load(q) {
    if (running) return;
    const id = app.analysisId, controller = new AbortController();
    running = { key: q.key, controller, fraction: 0 };
    app.refreshInspector();
    // Progress arrives on the analysis's event stream (one access replay runs at a time).
    const source = new EventSource(`/api/analyses/${id}/progress`);
    source.onmessage = e => {
      const m = JSON.parse(e.data);
      if (m.type !== 'accesses' || !running) return;
      running.fraction = m.fraction;
      const bar = document.querySelector('#access-progress');
      if (bar) bar.value = m.fraction * 100;
    };
    try {
      const res = await app.api(`/api/analyses/${id}/accesses`, { method: 'POST', body: JSON.stringify(q.params), signal: controller.signal });
      const body = await res.json();
      if (id === app.analysisId) results.set(q.key, body);
    } catch (err) {
      if (id === app.analysisId && !controller.signal.aborted)
        results.set(q.key, { error: /^404/.test(err.message) ? 'the server does not answer access queries; it is older than the viewer, so restart it' : err.message });
    } finally {
      source.close();
      if (running?.controller === controller) running = null;
      if (id === app.analysisId) { app.refreshInspector(); app.timeline.draw(); app.emit('accesses'); }
    }
  }

  function hitRow(h, q) {
    const row = element('button', '', `access-row k-${h.kind}${h.module === null ? ' unbacked' : ''}`);
    const head = element('span', '', 'access-head');
    const t = utids.get(h.utid);
    const color = t !== undefined && app.services.calls ? `#${app.services.calls.threadColor(t).getHexString()}` : '';
    const who = element('span', t !== undefined ? app.threadName(t) : `utid ${h.utid}`, 'access-thread');
    if (color) who.style.borderColor = color;
    head.append(element('span', KIND_SHORT[h.kind], 'access-kind'), element('span', evtLabel(h.evt), 'call-evt'), who, element('span', writer(h), 'access-code'));
    const addr = Number.parseInt(h.addr.slice(2), 16);
    const value = h.kind === 'r' ? (h.new ?? '?') : `${h.old ?? '?'} → ${h.new ?? '?'}`;
    const body = element('span', `+0x${(addr - q.lo).toString(16)} (${h.size} B)  ${value}`, 'access-value');
    row.append(head, body);
    row.title = `${KIND[h.kind]} at TTD ${h.pos} (WinDbg: !tt ${h.pos})\nPC ${h.pc}${h.sym ? `  ${h.sym}` : ''}\n${h.addr}, ${h.size} bytes` +
      `${h.size > 32 ? ' (values show the first 32)' : ''}\nClick to go to the event after it`;
    row.addEventListener('click', () => app.seek(Math.min(app.data.events.count - 1, h.evt)));
    return row;
  }

  // The section below a block, region, page range or byte selection.
  function section(item) {
    const q = query(item);
    if (!q) return null;
    const box = element('div', '', 'access-history');
    box.append(element('h4', 'Accesses'));
    const controls = element('div', '', 'access-controls');
    controls.append(scope.label, reads.label);
    box.append(controls);
    const result = results.get(q.key);
    const actions = element('div', '', 'actions');
    if (running?.key === q.key) {
      const bar = element('progress');
      bar.id = 'access-progress';
      bar.max = 100; bar.value = running.fraction * 100;
      actions.append(element('span', 'Replaying the trace for accesses…', 'muted'), bar, button('Cancel', () => running?.controller.abort()));
    } else if (!result || result.error) {
      const b = button(`Load ${reads.input.checked ? 'writes and reads' : 'writes'}`, () => load(q),
        `One replay with a watchpoint on ${hex(q.lo)} – ${hex(q.hi)}`);
      b.disabled = !!running;
      actions.append(b);
      if (running) actions.append(element('span', 'Another access query is running.', 'muted'));
    }
    box.append(actions);
    const notes = [];
    if (q.clipped) notes.push(`Only the first ${sizeText(RANGE_MAX)} of this ${q.label} are watched.`);
    if (result?.error) notes.push(`Could not load the accesses: ${result.error}.`);
    for (const n of notes) box.append(element('p', n, 'muted'));
    if (!result || result.error) return box;

    const hits = result.hits;
    box.append(element('p', `${hits.length.toLocaleString()} accesses${result.truncated ? ` (the first ${hits.length.toLocaleString()}: truncated)` : ''}` +
      ` · ${result.cached ? 'cached' : result.ms < 1000 ? `${result.ms} ms` : `${(result.ms / 1000).toFixed(1)} s`}`, result.truncated ? 'badge' : 'muted'));
    if (!hits.length) { box.append(element('p', 'No accesses in this span.', 'muted')); return box; }

    // Who: accesses grouped by code, the answer to "who wrote this". Clicking one filters the rows.
    const groups = groupAccesses(hits, writerGroup);
    const only = filters.get(q.key);
    const who = element('div', '', 'access-groups');
    for (const g of groups.slice(0, 12)) {
      const kinds = Object.entries(g.kinds).filter(([, n]) => n).map(([k, n]) => `${n} ${KIND_SHORT[k]}`).join(' ');
      const b = element('button', '', `result access-group${only === g.key ? ' selected' : ''}`);
      b.append(element('span', g.label), element('small', `${kinds} · ${evtLabel(g.first)} – ${evtLabel(g.last)} · ${g.threads.size} thread${g.threads.size > 1 ? 's' : ''}`));
      b.addEventListener('click', () => { if (only === g.key) filters.delete(q.key); else filters.set(q.key, g.key); app.refreshInspector(); });
      who.append(b);
    }
    box.append(element('h4', 'By code'), who);
    const shown = only ? hits.filter(h => writerGroup(h) === only) : hits;
    const list = element('div', '', 'access-list');
    for (const h of shown.slice(0, ROWS)) list.append(hitRow(h, q));
    box.append(element('h4', only ? `Accesses by ${only}` : 'In order'), list);
    if (shown.length > ROWS) box.append(element('p', `… ${(shown.length - ROWS).toLocaleString()} more (use [ and ] on the timeline).`, 'muted'));
    box.append(element('p', 'Order across threads is approximate within a TTD sequence.', 'muted small'));
    return box;
  }

  app.inspectorSections.push(section);
  scope.input.addEventListener('change', () => app.refreshInspector());
  reads.input.addEventListener('change', () => app.refreshInspector());

  // A byte range picked in the Memory tab.
  app.inspectors.set('bytes', item => {
    const nodes = [element('h3', `Bytes ${hex(item.lo)} – ${hex(item.hi)}`)];
    const obj = app.services.pointers?.objectAt(item.lo, app.current);
    const where = obj ? button(obj.kind === 'block' ? `Heap block ${hex(app.data.blocks.addr[obj.b])} +0x${obj.offset.toString(16)}` : `${app.regionName(obj.r)} +0x${obj.offset.toString(16)}`,
      () => app.select(obj.kind === 'block' ? { kind: 'block', b: obj.b } : { kind: 'region', r: obj.r }, { focus: true })) : 'no block or region at the current event';
    nodes.push(facts([['Size', `${(item.hi - item.lo).toLocaleString()} B`], ['In', where]]));
    app.inspector.show(nodes);
  });
  app.selectionRegion.set('bytes', item => app.time.regionAt(item.lo, app.current));

  // The loaded accesses of the selection on the timeline.
  const selected = () => { const q = query(app.selection); const r = q && results.get(q.key); return r && !r.error ? r : null; };
  app.timeline.addLane({
    height: 8,
    draw(ctx, { top, height, view, columns }) {
      const r = selected();
      if (!r?.hits.length) return;
      const span = Math.max(1, view[1] - view[0]);
      const counts = { w: new Float64Array(columns), r: new Float64Array(columns), m: new Float64Array(columns) };
      for (const h of r.hits) {
        const col = Math.floor((h.evt - 0.5 - view[0]) / span * columns);
        if (col >= 0 && col < columns) counts[h.kind][col]++;
      }
      for (const kind of ['r', 'w', 'm']) {
        ctx.fillStyle = KIND_COLOR[kind];
        for (let col = 0; col < columns; col++) {
          if (!counts[kind][col]) continue;
          const f = Math.min(1, 0.4 + Math.log2(1 + counts[kind][col]) / 8);
          ctx.globalAlpha = 0.9;
          ctx.fillRect(col, top + height * (1 - f), 1, Math.max(1, height * f));
        }
      }
      ctx.globalAlpha = 1;
    },
  });
  app.on('select', () => app.timeline.draw());
  // The selection's loaded accesses, for other views (memory beams).
  app.services.accesses = { selected, writer };

  // [ and ]: previous / next access of the selection.
  app.keys.push(e => {
    if ((e.key !== '[' && e.key !== ']') || e.ctrlKey || e.altKey || e.metaKey) return false;
    const r = selected();
    if (!r?.hits.length) return false;
    const events = [...new Set(r.hits.map(h => Math.min(app.data.events.count - 1, h.evt)))].sort((a, b) => a - b);
    const target = e.key === ']' ? events.find(x => x > app.current) : events.reverse().find(x => x < app.current);
    if (target !== undefined) app.seek(target);
    return true;
  });

  app.services.legend?.add('Accesses', 'Timeline ticks for the loaded accesses of the selection: writes (orange), reads (blue), changed outside the thread (violet, the kernel or another thread). [ and ] step between them.');
}
