// CAPA tab: capabilities that ttd-capa-cpp matched on the recorded API calls and on code the
// program created and ran (server/capa.mjs writes capa.json), each at its TTD position. Shown as a
// timeline that follows the playhead or grouped by capability; a lane marks them on the timeline.
import { NONE } from '../format.js';
import { element, textField, checkField, selectField, swatch } from '../ui.js';

const MAX_ROWS = 400;
const SRC_COLOR = { call: '#8eebf5', code: '#f2a65a' };

export function install(app) {
  const svc = app.services.calls;
  const panel = app.rails.right.panel('calls');
  const tab = panel.addTab({ id: 'capa', title: 'CAPA', order: 20, onShow: () => { load(); render(true); } });

  const search = textField('capa-search', '', 'Filter: capability, namespace, ATT&CK / MBC id, call');
  search.label.classList.add('compact');
  const source = selectField('capa-source', '', [['all', 'Calls and code'], ['call', 'API calls'], ['code', 'Executed code']], 'all');
  const view = selectField('capa-view', '', [['timeline', 'Timeline'], ['rules', 'By capability']], 'timeline', { prefKey: 'capa.view' });
  source.label.classList.add('compact'); view.label.classList.add('compact');
  const follow = checkField('capa-follow', 'Follow the playhead', true, { prefKey: 'capa.follow' });
  const options = element('div', '', 'capa-options');
  options.append(source.label, view.label);
  const status = element('p', '', 'muted calls-status');
  // Re-running is rare: a small control on the status line, accented only when there are no results.
  const statusRow = element('div', '', 'capa-status');
  const runButton = element('button', 'Run CAPA', 'mini');
  runButton.title = 'Match capa rules against this trace with ttd-capa-cpp (about 10 s for a small trace)';
  statusRow.append(status, runButton);
  const list = element('div', '', 'call-list capa-list');
  tab.append(search.label, options, follow.label, statusRow, list);

  let capa = null, loading = null, lastKey = '';

  function load(force = false) {
    if (!app.data || (capa && !force) || loading) return loading;
    const id = app.analysisId;
    status.textContent = 'Loading CAPA results…';
    loading = app.file('capa.json').then(r => r.json()).catch(() => ({ available: false, missing: true,
      reason: 'No CAPA results for this analysis yet.' })).then(doc => {
      if (id !== app.analysisId) return;
      capa = doc;
      lastKey = '';
      app.timeline.draw();
      render(true);
    }).finally(() => { loading = null; });
    return loading;
  }

  const text = row => {
    const rule = capa.rules[row.r];
    return row.text ??= `${rule.name} ${rule.ns} ${rule.attack.map(a => a.id).join(' ')} ${rule.mbc.map(m => m.id).join(' ')} ${row.site}`.toLowerCase();
  };

  function tags(rule) {
    const box = element('span', '', 'capa-tags');
    for (const a of rule.attack) {
      const t = element('span', a.id, 'capa-tag attack');
      t.title = `ATT&CK ${a.id}: ${[a.tactic, a.technique, a.subtechnique].filter(Boolean).join(' / ')}`;
      box.append(t);
    }
    for (const m of rule.mbc) {
      const t = element('span', m.id, 'capa-tag mbc');
      t.title = `MBC ${m.id}: ${[m.objective, m.behavior, m.method].filter(Boolean).join(' / ')}`;
      box.append(t);
    }
    return box;
  }

  // The recorded call behind a CAPA call row: same thread, same API, preceding the same event.
  function matchingCall(row) {
    if (row.src !== 'call' || row.evt === null || row.thread === null || !svc.model) return NONE;
    const c = svc.calls, model = svc.model;
    for (let i = model.upper(row.evt - 1) - 1; i >= 0 && c.startEvt[i] >= row.evt - 1; i--) {
      if (c.thread[i] === row.thread && svc.calleeName(c.callee[i]) === row.api) return i;
    }
    for (let i = model.upper(row.evt - 1); i < c.count && c.startEvt[i] <= row.evt; i++) {
      if (c.thread[i] === row.thread && svc.calleeName(c.callee[i]) === row.api) return i;
    }
    return NONE;
  }

  function open(row) {
    if (row.evt !== null) app.seek(Math.max(0, row.evt - 1));
    const i = matchingCall(row);
    if (i !== NONE) app.select({ kind: 'call', i }, { reveal: true });
  }

  function rowNode(row, T) {
    const rule = capa.rules[row.r];
    const el = element('div', '', `call-row capa-row ${row.src}`);
    el.tabIndex = 0;
    const head = element('div', '', 'call-head');
    const thread = row.thread !== null ? swatch(app.threadName(row.thread), svc.calls ? `#${svc.threadColor(row.thread).getHexString()}` : '#9aa7b8') : element('span', row.src === 'code' ? 'code' : '', 'sw capa-src');
    head.append(thread, element('span', rule.name, 'call-callee'), tags(rule));
    const when = element('div', `TTD ${row.pos ?? '?'}${row.evt !== null ? `  ·  before event #${(row.evt + 1).toLocaleString()}` : ''}`, 'call-when');
    when.title = row.pos ? `WinDbg: !tt ${row.pos}` : 'No position recorded';
    el.append(head, when, element('div', rule.ns, 'call-from'), element('div', row.site, 'capa-site'));
    if (row.evt !== null && row.evt - 1 > T) el.classList.add('future');
    el.addEventListener('click', () => open(row));
    el.addEventListener('keydown', e => { if (e.key === 'Enter') open(row); });
    return el;
  }

  function render(force = false) {
    if (!app.data || !panel.isShown('capa')) return;
    if (!capa) { load(); return; }
    const none = !capa.available;
    runButton.textContent = none ? 'Run CAPA' : '↻ Re-run';
    runButton.classList.toggle('cta', none);
    runButton.setAttribute('aria-label', none ? 'Run CAPA' : 'Run CAPA again');
    if (!capa.available) {
      status.textContent = capa.reason ?? 'CAPA results unavailable.';
      list.replaceChildren();
      return;
    }
    const T = app.now(), q = search.input.value.trim().toLowerCase(), src = source.input.value;
    const key = `${view.input.value}|${q}|${src}|${follow.input.checked ? Math.floor(T) : ''}`;
    if (!force && key === lastKey) return;
    lastKey = key;
    const rows = capa.rows.filter(r => (src === 'all' || r.src === src) && (!q || text(r).includes(q)));

    if (view.input.value === 'rules') {
      const groups = new Map();
      for (const row of rows) {
        let g = groups.get(row.r);
        if (!g) groups.set(row.r, g = { r: row.r, rows: [], past: 0 });
        g.rows.push(row);
        if (row.evt !== null && row.evt - 1 <= T) g.past++;
      }
      const sorted = [...groups.values()].sort((a, b) => capa.rules[a.r].ns.localeCompare(capa.rules[b.r].ns) || capa.rules[a.r].name.localeCompare(capa.rules[b.r].name));
      list.replaceChildren(...sorted.map(g => {
        const rule = capa.rules[g.r];
        const d = element('details', '', 'capa-group');
        const s = element('summary');
        s.append(element('span', rule.name, 'call-callee'), element('span', ` ${g.rows.length}×`, 'call-evt'), tags(rule));
        d.append(s, element('div', `${rule.ns}  ·  first at TTD ${g.rows[0].pos ?? '?'}  ·  ${g.past} before the playhead`, 'call-from'));
        d.addEventListener('toggle', () => { if (d.open && d.children.length < 3) d.append(...g.rows.slice(0, 200).map(row => rowNode(row, T))); }, { once: false });
        return d;
      }));
      const scope = capa.scope.filter(r => !q || capa.rules[r].name.toLowerCase().includes(q));
      if (scope.length) {
        const d = element('details', '', 'capa-group');
        d.append(element('summary', `Process- or thread-wide (no single position): ${scope.length}`), ...scope.map(r => {
          const line = element('div', '', 'call-from');
          line.append(`${capa.rules[r].name}  ·  ${capa.rules[r].ns} `, tags(capa.rules[r]));
          return line;
        }));
        list.append(d);
      }
      status.textContent = `${groups.size} capabilities in ${rows.length.toLocaleString()} matches` + (capa.counts ? `  ·  ${capa.counts.codeRegions} code regions scanned` : '');
      return;
    }

    // Timeline: a window of rows around the playhead (or from the start when not following).
    let at = 0;
    if (follow.input.checked) {
      while (at < rows.length && (rows[at].evt === null || rows[at].evt - 1 <= T)) at++;
    }
    const start = follow.input.checked ? Math.max(0, at - MAX_ROWS + 20) : 0;
    const shown = rows.slice(start, start + MAX_ROWS);
    list.replaceChildren(...shown.map(row => rowNode(row, T)));
    if (follow.input.checked) {
      const current = list.children[Math.max(0, at - start - 1)];
      current?.classList.add('current');
      current?.scrollIntoView({ block: 'center' });
    }
    status.textContent = `${rows.length.toLocaleString()} matches of ${new Set(rows.map(r => r.r)).size} capabilities` +
      (follow.input.checked ? `, ${at.toLocaleString()} up to the playhead` : '') + (rows.length > MAX_ROWS ? ` (${MAX_ROWS} listed)` : '');
  }

  runButton.addEventListener('click', async () => {
    runButton.disabled = true;
    status.textContent = 'Running CAPA…';
    try {
      await app.api(`/api/analyses/${app.analysisId}/capa`, { method: 'POST' });
      const source = new EventSource(`/api/analyses/${app.analysisId}/progress`);
      source.onmessage = msg => {
        const e = JSON.parse(msg.data);
        if (e.state === 'running') status.textContent = `Running CAPA: ${e.stage ?? ''}`;
        else if (e.state === 'ready') { source.close(); capa = null; runButton.disabled = false; load(true); }
        else if (e.state !== 'queued') { source.close(); runButton.disabled = false; status.textContent = `CAPA failed: ${e.error ?? e.state}`; }
      };
    } catch (err) { status.textContent = err.message; runButton.disabled = false; }
  });

  search.input.addEventListener('input', () => render(true));
  for (const c of [source, view, follow]) c.input.addEventListener('change', () => render(true));
  // Loaded with the analysis (not only when the tab opens) so the timeline lane shows.
  app.on('open', () => { capa = null; lastKey = ''; list.replaceChildren(); status.textContent = ''; load(); });
  app.on('seek', () => { if (follow.input.checked) render(); });

  // Timeline lane: one tick per match (cyan: API call, orange: executed code).
  app.timeline.addLane({
    height: 7,
    draw(ctx, { top, height, width, view: v }) {
      if (!capa?.available) return;
      const span = Math.max(1, v[1] - v[0]);
      for (const row of capa.rows) {
        if (row.evt === null || row.evt < v[0] || row.evt > v[1]) continue;
        ctx.fillStyle = SRC_COLOR[row.src];
        ctx.globalAlpha = 0.8;
        ctx.fillRect((row.evt - v[0]) / span * width, top, 1, height);
      }
    },
  });
  app.services.legend?.add('CAPA', 'Capabilities matched by capa rules (ttd-capa-cpp) at their TTD positions: the timeline lane below the calls lane marks them,',
    Object.assign(element('span'), { innerHTML: '<span class="sw" style="background:#8eebf5">API calls</span> <span class="sw" style="background:#f2a65a">executed code</span>' }));
}
