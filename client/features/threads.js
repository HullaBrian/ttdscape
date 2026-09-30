// The Threads tab: what each thread is doing at the playhead. Calls into exports in progress at
// time T are each thread's export-call stack (CallModel.activeAt); a card per thread shows the
// innermost call with its arguments, and the stack above it. Clicking a call opens it.
import { formatArgList } from '../call-args.js';
import { evtLabel } from '../format.js';
import { element, swatch } from '../ui.js';

const STACK_SHOWN = 6;

export function install(app) {
  const svc = app.services.calls;
  const panel = app.rails.right.panel('calls');
  const tab = panel.addTab({ id: 'threads', title: 'Threads', order: 15, onShow: () => refresh(true) });
  const status = element('p', '', 'muted calls-status');
  const list = element('div', '', 'thread-list');
  tab.append(status, list);

  let lastKey = '', lastRefresh = 0;

  // Threads alive at event i (created before it, not exited yet).
  function aliveAt(i) {
    return app.data.manifest.threads.filter(t => (t.createEvt === null || t.createEvt <= i) && (t.exitEvt === null || t.exitEvt > i));
  }

  function callLine(i, cls) {
    const c = svc.calls;
    const b = element('button', svc.calleeText(c.callee[i]), `thread-call ${cls}`);
    b.title = `← ${svc.callerText(i)}\nCalled before event ${evtLabel(c.startEvt[i])}; depth ${c.depth[i]}. Click to open the call.`;
    b.addEventListener('click', () => app.select({ kind: 'call', i }, { reveal: true }));
    return b;
  }

  function card(t, stack) {
    const c = svc.calls;
    const box = element('div', '', 'thread-card');
    const head = element('div', '', 'thread-head');
    head.append(swatch(app.threadName(t.index), `#${svc.threadColor(t.index).getHexString()}`),
      element('span', stack.length ? `${stack.length} call${stack.length > 1 ? 's' : ''} in progress` : 'no export call in progress', 'muted'));
    box.append(head);
    if (!stack.length) { box.classList.add('idle'); return box; }
    const inner = stack[stack.length - 1];
    box.append(callLine(inner, 'inner'));
    const args = element('div', '', 'thread-args muted');
    box.append(args);
    if (svc.hasArgs) svc.args(inner).then(a => { args.textContent = a ? formatArgList(a, 5) : ''; });
    const outer = stack.slice(0, -1).reverse();
    if (outer.length) {
      const wrap = element('div', '', 'thread-stack');
      for (const i of outer.slice(0, STACK_SHOWN)) wrap.append(callLine(i, 'outer'));
      if (outer.length > STACK_SHOWN) wrap.append(element('span', `… ${outer.length - STACK_SHOWN} more`, 'muted'));
      box.append(wrap);
    }
    if (app.selection?.kind === 'call' && stack.includes(app.selection.i)) box.classList.add('selected');
    return box;
  }

  function refresh(force = false) {
    if (!app.data || !panel.isShown('threads')) return;
    if (!svc.available) { status.textContent = 'This analysis recorded no calls; analyze the trace again.'; list.replaceChildren(); return; }
    if (svc.error) { status.textContent = `Could not load the calls: ${svc.error}.`; list.replaceChildren(); return; }
    if (!svc.model) { status.textContent = 'Loading calls…'; svc.load(); return; }
    const T = app.now();
    const key = `${T}|${app.selection?.kind === 'call' ? app.selection.i : ''}|${app.atlas.theme.name}`;
    if (!force && key === lastKey) return;
    lastKey = key;
    // Calls longer than 1/512 of the trace come from a short cached list; the rest are near T.
    const active = svc.model.activeAt(T, Math.max(1, app.data.events.count / 512));
    const byThread = new Map();
    for (const i of active) {
      const t = svc.calls.thread[i];
      if (!byThread.has(t)) byThread.set(t, []);
      byThread.get(t).push(i);
    }
    const threads = aliveAt(Math.floor(T));
    for (const t of byThread.keys()) if (!threads.some(x => x.index === t)) threads.push(app.data.manifest.threads[t] ?? { index: t });
    // Busy threads first, then by thread order.
    threads.sort((a, b) => Number(byThread.has(b.index)) - Number(byThread.has(a.index)) || a.index - b.index);
    list.replaceChildren(...threads.map(t => card(t, byThread.get(t.index) ?? [])));
    status.textContent = `${threads.length} thread${threads.length === 1 ? '' : 's'} at t = ${T.toFixed(1)}; ${byThread.size} in a call into an export.`;
  }

  app.on('frame', () => {
    const now = performance.now();
    if (app.playing && now - lastRefresh < 200) return;
    lastRefresh = now;
    refresh();
  });
  app.on('open', () => { lastKey = ''; list.replaceChildren(); status.textContent = ''; });
  app.on('calls', () => refresh(true));
  app.on('select', () => refresh(true));
  app.on('theme', () => refresh(true));
}
