// The Memory tab: the bytes of the selected block, region or page range (or a typed address) at the
// playhead, read on demand from the analyzer's query service (GET .../memory; server/query.mjs).
//   - Bytes whose value the trace did not record are shown as ·· (never as zeros; ReplayAPI.md
//     landmine 18).
//   - Each byte is tinted by how long ago its value was recorded, and bytes that changed since the
//     previous view flash.
//   - Strings (ASCII and UTF-16) are listed below; clicking one highlights it.
//   - Click a byte and shift-click another to select a range, then load its access history.
// Provides app.services.memory: focus(addr) shows addr on the next selection, show(addr).
import { byteEvents, decodeBase64, findStrings } from '../memory.js';
import { bytes as sizeText, evtLabel, hex, parseAddress } from '../format.js';
import { element, textField } from '../ui.js';
import { button } from '../inspector.js';

const ROW = 16;
const WINDOW = 512;         // bytes fetched and shown at once
const PLAYING_GAP_MS = 200; // at most ~5 requests per second while playing

// Age classes by how many events ago a byte's value was recorded (sequence granularity).
function ageClass(age) {
  if (age <= 0) return 'a0';
  if (age <= 16) return 'a1';
  if (age <= 1024) return 'a2';
  return 'a3';
}

export function install(app) {
  const panel = app.rails.right.panel('calls');
  const tab = panel.addTab({ id: 'memory', title: 'Memory', order: 30, onShow: () => refresh(true) });
  const field = textField('memory-address', '', 'Address (0x…), or select a block or region');
  field.label.classList.add('compact');
  const target = element('p', 'Select a heap block, region or page range, or type an address.', 'muted memory-target');
  const nav = element('div', '', 'memory-nav');
  const prev = button('◀', () => move(-WINDOW), 'Previous bytes');
  const next = button('▶', () => move(WINDOW), 'Next bytes');
  const where = element('span', '', 'muted');
  nav.append(prev, where, next);
  const grid = element('div', '', 'hex');
  grid.setAttribute('role', 'grid');
  const status = element('p', '', 'muted memory-status');
  const legend = element('p', '', 'memory-legend');
  legend.innerHTML = 'Recorded: <span class="b a0">now</span> <span class="b a1">≤16 events</span> <span class="b a2">earlier</span> <span class="b a3">long ago</span> <span class="b unk">··</span> unknown';
  legend.title = 'Age of each byte\'s recorded value, by TTD sequence (coarse: a sequence spans many instructions). Unknown bytes were not recorded at this point of the trace.';
  const strings = element('div', '', 'memory-strings');
  const actions = element('div', '', 'actions');
  const history = button('Accesses to the selected bytes', () => {
    if (sel) app.select({ kind: 'bytes', lo: sel.lo, hi: sel.hi }, { reveal: true });
  }, 'Who wrote (and optionally read) these bytes, over the trace');
  const clear = button('Clear selection', () => { sel = null; paint(); });
  actions.append(history, clear);
  tab.append(field.label, target, nav, grid, status, legend, strings, actions);

  // What is shown: an object (or typed address), the window start, and the last result.
  let view = null;          // { addr, size, label, kind: 'block' | 'region' | 'span' | 'bytes' | 'address', b?, r? }
  let start = 0;            // first address of the window (row-aligned)
  let result = null;        // { start, evt, bytes, known (byteEvents), res }
  let previous = null;      // the result before, for change detection
  let sel = null, anchor = null, mark = null; // selected bytes, selection anchor, highlighted string
  let pendingFocus = null;
  let inFlight = false, lastFetch = 0, lastKey = '', timer = null;

  const align = a => a - (a % ROW);

  function viewFor(item) {
    if (!item || !app.data) return null;
    const { blocks, regions, spans } = app.data;
    if (item.kind === 'block') {
      const unknownSize = blocks.flags[item.b] & 0x02;
      return { kind: 'block', b: item.b, addr: blocks.addr[item.b], size: unknownSize ? 256 : Math.max(1, blocks.size[item.b]), label: `Heap block ${hex(blocks.addr[item.b])}` };
    }
    if (item.kind === 'region') return { kind: 'region', r: item.r, addr: regions.base[item.r], size: regions.size[item.r], label: app.regionName(item.r) };
    if (item.kind === 'span') return { kind: 'span', addr: spans.start[item.s], size: spans.end[item.s] - spans.start[item.s], label: `Pages of ${app.regionName(spans.region[item.s])}` };
    if (item.kind === 'bytes') return { kind: 'bytes', addr: item.lo, size: item.hi - item.lo, label: 'Selected bytes' };
    return null;
  }

  function setView(v, focusAddr = null) {
    view = v;
    const inside = focusAddr !== null && focusAddr >= v.addr && focusAddr < v.addr + v.size;
    start = align(inside ? Math.max(v.addr, focusAddr - 2 * ROW) : v.addr);
    result = null; previous = null; sel = null; mark = null;
    refresh(true);
  }

  function move(delta) {
    if (!view) return;
    const lo = align(view.addr), hi = view.addr + view.size;
    start = Math.max(lo, Math.min(align(Math.max(lo, hi - 1)), start + delta));
    refresh(true);
  }

  field.input.addEventListener('keydown', e => {
    if (e.key !== 'Enter') return;
    const addr = parseAddress(field.input.value);
    if (addr === null) { status.textContent = 'Type an address such as 0x1d8c2a0.'; return; }
    // Show the block or region that holds it, if any; otherwise just the address.
    const obj = app.data ? app.services.pointers?.objectAt(addr, app.current) : null;
    if (obj) {
      pendingFocus = addr;
      app.select(obj.kind === 'block' ? { kind: 'block', b: obj.b } : { kind: 'region', r: obj.r }, { reveal: true });
      return;
    }
    setView({ kind: 'address', addr: align(addr), size: 64 * 1024, label: `Address ${hex(addr)}` }, addr);
  });

  // ---- fetching ----
  function refresh(force = false) {
    if (!app.data || !panel.isShown('memory')) return;
    if (!view) { grid.replaceChildren(); where.textContent = ''; status.textContent = ''; strings.replaceChildren(); return; }
    const evt = app.current;
    const end = Math.min(view.addr + view.size, start + WINDOW);
    const size = Math.max(1, end - start);
    const key = `${app.analysisId}|${evt}|${start}|${size}`;
    if (!force && key === lastKey) return;
    // One request at a time; while playing, at most one per PLAYING_GAP_MS.
    const wait = app.playing ? PLAYING_GAP_MS - (performance.now() - lastFetch) : 0;
    if (inFlight || wait > 0) {
      clearTimeout(timer);
      timer = setTimeout(() => refresh(force), Math.max(20, wait));
      return;
    }
    lastKey = key;
    inFlight = true;
    lastFetch = performance.now();
    const id = app.analysisId, shown = view;
    app.api(`/api/analyses/${id}/memory?evt=${evt}&addr=${hex(start)}&size=${size}`).then(r => r.json()).then(res => {
      if (id !== app.analysisId || shown !== view) return;
      const data = decodeBase64(res.data);
      if (result && result.start === start) previous = result;
      else previous = null;
      result = { start, evt, bytes: data, known: byteEvents(data.length, res.ranges), res };
      render();
    }, err => {
      if (id !== app.analysisId) return;
      lastKey = '';
      status.textContent = /^404/.test(err.message)
        ? 'The server does not answer memory queries; it is older than the viewer, so restart it.'
        : `Could not read memory: ${err.message}`;
    }).finally(() => { inFlight = false; });
  }

  // ---- rendering ----
  function render() {
    const { bytes: data, known, evt, res } = result;
    const inView = a => a >= view.addr && a < view.addr + view.size;
    let live = '';
    if (view.kind === 'block') live = app.time.isLive(view.b, evt) ? ' · live' : ' · not live at this event: the bytes may belong to something else';
    if (view.kind === 'region') live = app.time.regionLive(view.r, evt) ? '' : ' · not present at this event';
    target.textContent = `${view.label} · ${sizeText(view.size)}${live}`;
    target.classList.toggle('muted', false);
    where.textContent = `${hex(start)} – ${hex(start + data.length)}`;
    prev.disabled = start <= align(view.addr);
    next.disabled = start + data.length >= view.addr + view.size;
    const rows = [];
    const unknownCount = known.reduce((n, e) => n + (e < 0 ? 1 : 0), 0);
    for (let o = 0; o < data.length; o += ROW) {
      const row = element('div', '', 'hex-row');
      row.append(element('span', hex(start + o).slice(2).padStart(12, '0'), 'hex-addr'));
      const cells = element('span', '', 'hex-bytes');
      let ascii = '';
      for (let k = o; k < o + ROW; k++) {
        if (k >= data.length) { cells.append(element('span', '  ', 'b pad')); ascii += ' '; continue; }
        const a = start + k, e = known[k];
        const cell = element('span', e < 0 ? '··' : data[k].toString(16).padStart(2, '0'), `b ${e < 0 ? 'unk' : ageClass(evt - e)}`);
        cell.dataset.o = String(k);
        if (!inView(a)) cell.classList.add('out');
        if (previous && e >= 0 && previous.known[k] >= 0 && previous.bytes[k] !== data[k]) cell.classList.add('chg');
        cells.append(cell);
        ascii += e < 0 ? '·' : data[k] >= 0x20 && data[k] < 0x7f ? String.fromCharCode(data[k]) : '.';
      }
      row.append(cells, element('span', ascii, 'hex-ascii'));
      rows.push(row);
    }
    grid.replaceChildren(...rows);
    const at = res.pos ? `TTD ${res.pos}` : '';
    status.textContent = `At event ${evtLabel(evt)} (${at})${unknownCount ? ` · ${unknownCount} bytes not recorded here` : ''}`;
    const found = findStrings(data, known).slice(0, 40);
    strings.replaceChildren(...(found.length ? [element('h4', 'Strings')] : []), ...found.map(s => {
      const b = element('button', `+0x${(start + s.offset - view.addr).toString(16)}  ${s.wide ? 'L' : ''}"${s.text.length > 60 ? `${s.text.slice(0, 60)}…` : s.text}"`, 'result memory-string');
      b.addEventListener('click', () => { mark = { lo: start + s.offset, hi: start + s.offset + s.length }; paint(); });
      return b;
    }));
    paint();
  }

  // Selection and string highlight, without re-rendering the rows.
  function paint() {
    for (const cell of grid.querySelectorAll('.b[data-o]')) {
      const a = start + Number(cell.dataset.o);
      cell.classList.toggle('sel', !!sel && a >= sel.lo && a < sel.hi);
      cell.classList.toggle('hl', !!mark && a >= mark.lo && a < mark.hi);
    }
    history.disabled = !sel;
    clear.disabled = !sel;
    history.textContent = sel ? `Accesses to ${sizeText(sel.hi - sel.lo)} at ${hex(sel.lo)}` : 'Select bytes to see their accesses';
  }

  grid.addEventListener('click', e => {
    const cell = e.target.closest('.b[data-o]');
    if (!cell || !result) return;
    const a = start + Number(cell.dataset.o);
    if (e.shiftKey && anchor !== null) sel = { lo: Math.min(anchor, a), hi: Math.max(anchor, a) + 1 };
    else { anchor = a; sel = { lo: a, hi: a + 1 }; }
    paint();
  });
  grid.addEventListener('mouseover', e => {
    const cell = e.target.closest('.b[data-o]');
    if (!cell || !result || cell.title) return;
    const k = Number(cell.dataset.o), ev = result.known[k];
    cell.title = `${hex(start + k)}  (+0x${(start + k - view.addr).toString(16)})\n` +
      (ev < 0 ? 'Not recorded at this point of the trace' : `Value recorded around event ${evtLabel(Math.min(ev, app.data.events.count - 1))}`);
  });

  // ---- following the app ----
  app.on('select', ({ selection }) => {
    const v = viewFor(selection);
    const focusAddr = pendingFocus;
    pendingFocus = null;
    if (!v) return;
    // Selecting bytes inside what is shown keeps the view.
    if (selection.kind === 'bytes' && view && selection.lo >= view.addr && selection.hi <= view.addr + view.size) return;
    setView(v, focusAddr);
  });
  app.on('seek', () => refresh());
  app.on('open', () => { view = null; result = null; previous = null; lastKey = ''; grid.replaceChildren(); strings.replaceChildren();
    target.textContent = 'Select a heap block, region or page range, or type an address.'; target.classList.add('muted'); status.textContent = ''; where.textContent = ''; });

  app.services.memory = {
    // The next selection's view starts at addr (pointer links).
    focus(addr) { pendingFocus = addr; },
    // Shows addr now, and brings the tab forward.
    show(addr, size = 64 * 1024) {
      setView({ kind: 'address', addr: align(addr), size, label: `Address ${hex(addr)}` }, addr);
      panel.show('memory');
    },
  };
}
