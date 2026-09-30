// The calls pane: calls into exports up to the playhead, newest first, with their decoded
// arguments (ttd-capa signatures). Rows follow the beam filter; a search narrows them further.
// Selecting a call shows its details in the Inspector.
import { CALL } from '../calls.js';
import { formatParam } from '../call-args.js';
import { NONE, evtLabel, hex } from '../format.js';
import { element, textField, checkField, swatch } from '../ui.js';
import { facts, button } from '../inspector.js';

const ROWS = 150;

export function install(app) {
  const svc = app.services.calls;
  const panel = app.rails.right.panel('calls', { grow: 1.3 });
  const tab = panel.addTab({ id: 'live-calls', title: 'Live calls', order: 10, onShow: () => refresh(true) });

  const search = textField('call-search', '', 'Filter: module!function, caller or argument text');
  search.label.classList.add('compact');
  const follow = checkField('call-follow', 'Follow the playhead', true, { prefKey: 'calls.follow' });
  const showArgs = checkField('call-show-args', 'Show arguments', true, { prefKey: 'calls.args' });
  const status = element('p', '', 'muted calls-status');
  const list = element('div', '', 'call-list');
  list.setAttribute('role', 'list');
  const options = element('div', '', 'call-options');
  options.append(follow.label, showArgs.label);
  tab.append(search.label, options, status, list);

  let rows = new Map();   // call index -> row element (reused across refreshes)
  let lastKey = '', lastRefresh = 0, anchorT = null;
  const searchCache = new Map();

  function haystack(i) {
    const c = svc.calls.callee[i], f = svc.calls.via[i] === NONE ? svc.calls.callerFrame[i] : -1;
    const key = `${c}|${f}`;
    let h = searchCache.get(key);
    if (h === undefined) searchCache.set(key, h = `${svc.calleeText(c)} ${svc.callerText(i)}`.toLowerCase());
    return h;
  }

  function valueNode(p) {
    const f = formatParam(p);
    const span = element('span', '', 'arg');
    if (f.name) span.append(element('span', f.name, 'arg-name'), document.createTextNode(' = '));
    const v = element('span', f.value, `arg-value${p.s !== undefined ? ' str' : p.fl?.length || p.dfl?.length ? ' flags' : ''}`);
    span.append(v);
    if (f.atReturn) span.append(element('span', ' @ret', 'arg-note'));
    if (f.out) span.classList.add('out');
    span.title = `${f.type}${f.out ? ' [out]' : ''}${f.atReturn ? ' (read at the return)' : ''}`;
    return span;
  }

  function fillArgs(row, i) {
    if (!showArgs.input.checked || !svc.hasArgs || row.dataset.args) return;
    row.dataset.args = 'pending';
    svc.args(i).then(a => {
      const box = row.querySelector('.call-args');
      box.replaceChildren();
      if (!a) { box.append(element('span', 'arguments not decoded', 'muted')); return; }
      if (!a.sig) box.append(element('span', 'no signature: first arguments', 'arg-note'));
      const nodes = a.p.map(valueNode);
      box.append(...nodes);
      const ret = a.ret !== undefined ? element('span', `→ ${a.ret}`, 'call-ret') : null;
      if (ret) box.append(ret);
      // Arguments pointing into a block (or a private or mapped region) link to it.
      const ptr = app.services.pointers;
      for (const t of ptr?.targets(i, a) ?? []) if (ptr.inRows(t)) (t.which === 'ret' ? ret : nodes[t.param])?.append(ptr.link(t));
      row.dataset.args = 'done';
    });
  }

  function makeRow(i) {
    const c = svc.calls;
    const row = element('div', '', 'call-row');
    row.setAttribute('role', 'listitem');
    row.tabIndex = 0;
    const head = element('div', '', 'call-head');
    head.append(swatch(app.threadName(c.thread[i]), `#${svc.threadColor(c.thread[i]).getHexString()}`),
      element('span', svc.calleeText(c.callee[i]), 'call-callee'), element('span', evtLabel(c.startEvt[i]), 'call-evt'));
    // The call's TTD position (Sequence:Steps), usable in WinDbg: !tt <position>.
    const when = element('div', '', 'call-when');
    svc.positions(i).then(p => {
      if (!p?.call) return;
      when.textContent = `TTD ${p.call}${p.ret ? `  →  ${p.ret}` : ''}`;
      when.title = `Called at ${p.call}${p.ret ? `, returned at ${p.ret}` : ', never returned'} (WinDbg: !tt ${p.call})`;
    });
    const from = element('div', `← ${svc.callerText(i)}`, 'call-from');
    row.append(head, when, from, element('div', '', 'call-args'));
    if (c.flags[i] & CALL.Tail) from.title = 'Entered by a jump (import thunk, CFG dispatch or export forwarding)';
    // Hover previews the call stack (the Inspector shows it in full).
    row.addEventListener('mouseenter', () => {
      if (row.title) return;
      row.title = 'Loading call stack…';
      svc.stack(i).then(node => {
        const frames = node === NONE ? [] : app.stacks.describe(node);
        row.title = frames.length
          ? `Call stack:\n${frames.slice(0, 12).map((f, k) => `${k + 1}. ${f.text}`).join('\n')}${frames.length > 12 ? `\n… ${frames.length - 12} more` : ''}\n\nClick for arguments and the full stack`
          : 'No call stack recorded (analyze the trace again).';
      });
    }, { once: false });
    const open = () => app.select({ kind: 'call', i }, { reveal: true });
    row.addEventListener('click', open);
    row.addEventListener('keydown', e => { if (e.key === 'Enter') open(); });
    return row;
  }

  // Rebuilds the list for the playhead (or keeps it when nothing relevant changed).
  function refresh(force = false) {
    if (!app.data) return;
    if (!svc.available) { status.textContent = 'This analysis recorded no calls; analyze the trace again.'; list.replaceChildren(); return; }
    if (svc.error) { status.textContent = `Could not load the calls: ${svc.error}.`; list.replaceChildren(); return; }
    if (!svc.model) { status.textContent = 'Loading calls…'; svc.load(); return; }
    if (!panel.isShown('live-calls')) return;
    const T = follow.input.checked || anchorT === null ? app.now() : anchorT;
    const query = search.input.value.trim().toLowerCase();
    const key = `${T}|${svc.filterKey()}|${query}|${showArgs.input.checked}|${app.selection?.kind === 'call' ? app.selection.i : ''}`;
    if (!force && key === lastKey) return;
    lastKey = key;
    anchorT = T;
    const accept = svc.acceptor(), model = svc.model, c = svc.calls;
    const picked = [];
    let active = 0, scanned = 0;
    for (let i = model.upper(T) - 1; i >= 0 && picked.length < ROWS && scanned < 400000; i--, scanned++) {
      if (!accept(i)) continue;
      if (query && !haystack(i).includes(query)) continue;
      picked.push(i);
      if (model.t1[i] > T) active++;
    }
    const next = new Map();
    const nodes = picked.map(i => {
      let row = rows.get(i);
      if (!row) row = makeRow(i);
      next.set(i, row);
      const live = model.t1[i] > T;
      row.classList.toggle('active', live);
      row.classList.toggle('returned', !live && (c.flags[i] & CALL.Returned) !== 0);
      row.classList.toggle('selected', app.selection?.kind === 'call' && app.selection.i === i);
      if (!showArgs.input.checked) { row.querySelector('.call-args').replaceChildren(); delete row.dataset.args; }
      return row;
    });
    rows = next;
    list.replaceChildren(...nodes);
    for (const i of picked.slice(0, 60)) fillArgs(rows.get(i), i);
    status.textContent = picked.length
      ? `${picked.length === ROWS ? `latest ${ROWS}` : picked.length} calls up to t = ${T.toFixed(1)}${active ? `, ${active} still active` : ''}`
      : query ? `No call matches “${search.input.value.trim()}” before this point.` : 'No calls before this point.';
  }

  // Lazily fill arguments of rows scrolled into view.
  list.addEventListener('scroll', () => {
    const top = list.scrollTop, bottom = top + list.clientHeight;
    for (const [i, row] of rows) if (row.offsetTop < bottom + 200 && row.offsetTop + row.offsetHeight > top - 200) fillArgs(row, i);
  });

  app.on('frame', () => {
    const now = performance.now();
    if (app.playing && now - lastRefresh < 120) return;
    lastRefresh = now;
    refresh();
  });
  app.on('open', () => { rows = new Map(); searchCache.clear(); lastKey = ''; anchorT = null; list.replaceChildren(); status.textContent = ''; });
  app.on('calls', () => refresh(true));
  app.on('call-filter', () => refresh(true));
  search.input.addEventListener('input', () => refresh(true));
  showArgs.input.addEventListener('change', () => refresh(true));
  follow.input.addEventListener('change', () => { anchorT = null; refresh(true); });

  // ---- call details in the Inspector ----
  app.inspectors.set('call', async item => {
    const i = item.i, c = svc.calls;
    if (!c) return;
    const nodes = [element('h3', svc.calleeText(c.callee[i]))];
    // Arguments first: they are what a call is opened for.
    const argsBox = element('div');
    argsBox.append(element('p', svc.hasArgs ? 'Loading arguments…' : 'Arguments were not decoded for this analysis.', 'muted'));
    nodes.push(argsBox);
    // Then who made it: the caller's stack at the call (symbolized like allocation stacks).
    const stackBox = element('div');
    nodes.push(stackBox);
    const returned = c.endEvt[i] !== NONE;
    nodes.push(facts([
      ['Thread', app.threadName(c.thread[i])],
      ['Called from', svc.callerText(i)],
      ['Caller address', hex(svc.callerAddress(i))],
      ['Export', `${hex(c.callees.addr[c.callee[i]])} in ${app.data.manifest.modules[c.callees.module[c.callee[i]]]?.path ?? '?'}`],
      ['Entered', c.flags[i] & CALL.Tail ? 'by a jump (thunk, CFG dispatch or forwarding)' : 'by a CALL'],
      ['Depth', String(c.depth[i])],
      ['Called', `before event ${evtLabel(c.startEvt[i])}`],
      ['Returned', returned ? `before event ${evtLabel(c.endEvt[i])}` : c.flags[i] & CALL.Unwound ? 'unwound (exception or longjmp)' : 'never (active at the end of the trace)'],
    ]));
    const ttd = element('p', '', 'badge');
    svc.positions(i).then(p => { if (p?.call) ttd.textContent = `TTD ${p.call}${p.ret ? ` → ${p.ret}` : ''}`; else ttd.remove(); });
    nodes.splice(1, 0, ttd);
    const actions = element('div', '', 'actions');
    actions.append(button('Jump to the call', () => app.seek(Math.max(0, c.startEvt[i] - 1))));
    if (returned) actions.append(button('Jump to the return', () => app.seek(Math.min(app.data.events.count - 1, c.endEvt[i]))));
    const callee = svc.calleeRegion(c.callee[i]), caller = svc.callerRegion(i);
    if (callee !== NONE) actions.append(button('Callee module', () => app.select({ kind: 'region', r: callee }, { focus: true })));
    if (caller !== NONE) actions.append(button('Caller region', () => app.select({ kind: 'region', r: caller }, { focus: true })));
    nodes.push(actions);
    app.inspector.show(nodes);
    svc.stack(i).then(node => {
      if (app.selection === item && node !== NONE) stackBox.replaceChildren(app.inspector.stackList('Call stack', node));
    });
    if (!svc.hasArgs) return;
    const a = await svc.args(i);
    if (app.selection !== item) return;
    const table = element('table', '', 'spans args');
    table.append(Object.assign(element('tr'), { innerHTML: '<th>Parameter</th><th>Value</th>' }));
    const cells = [];
    for (const p of a?.p ?? []) {
      const f = formatParam(p);
      const tr = element('tr');
      const name = element('td', f.name || '?');
      if (f.type) name.append(element('small', f.type));
      const value = element('td', f.value);
      if (p.d !== undefined || p.fl) value.append(element('small', `raw ${p.v}${p.d !== undefined ? ` → ${p.d}` : ''}`));
      if (p.b) value.append(element('small', `bytes ${p.b.match(/../g).join(' ')}`));
      if (f.out || f.atReturn) value.append(element('small', `${f.out ? '[out]' : ''}${f.atReturn ? ' read at the return' : ''}`));
      tr.append(name, value);
      table.append(tr);
      cells.push(value);
    }
    for (const t of app.services.pointers?.targets(i, a) ?? []) if (t.which !== 'ret') cells[t.param]?.append(app.services.pointers.link(t));
    const body = [element('h4', a?.sig ? 'Arguments' : 'Arguments (no signature: first integer arguments)'), table];
    if (a?.ret !== undefined) body.push(element('p', `Returned ${a.ret}`, 'badge live'));
    argsBox.replaceChildren(...body);
  });
}
