// The stock panels: Leaks and Find (left rail), Inspector, Legend and Notes (right rail).
import { NONE, bytes, hex, parseAddress, evtLabel } from '../format.js';
import { element, textField } from '../ui.js';

export function installInspectorTabs(app, detailsRoot) {
  const main = app.rails.right.panel('main', { grow: 1 });
  main.addTab({ id: 'inspector', title: 'Inspector', order: 10 }).append(detailsRoot);

  // Legend: static entries plus whatever features add (app.services.legend.add).
  const dl = element('dl', '', 'legend');
  dl.innerHTML = `
    <dt>Solid cubes</dt><dd>Live heap blocks; volume is proportional to bytes.</dd>
    <dt>Wire cubes</dt><dd>Blocks freed in the last few events.</dd>
    <dt>Translucent boxes</dt><dd>Committed pages of regions without heap blocks: <span class="sw exec">exec</span> <span class="sw write">writable</span> <span class="sw read">read-only</span> <span class="sw guard">guard</span></dd>
    <dt>Grey outlines</dt><dd>Committed but unused space inside a heap region; dashed = reserved.</dd>
    <dt>Region frames</dt><dd><span class="sw r0">private</span> <span class="sw r1">mapped</span> <span class="sw r2">image</span> <span class="sw r3">stack</span> <span class="sw r4">heap</span> <span class="sw r5">pre-trace</span>; glowing = highlighted in the Regions tab.</dd>
    <dt>Timeline</dt><dd>Live heap (pink) and committed memory (cyan); the colored lane is the rate of calls shown as beams, by busiest thread; the bottom strip is event density.</dd>
    <dt>Keys</dt><dd>← → step one event (Ctrl ×100), Shift+← → previous/next event on the selection, Home/End, P play, F flight, G focus, X clear.</dd>`;
  main.addTab({ id: 'legend', title: 'Legend', order: 20 }).append(dl);
  app.services.legend = {
    add(title, text, node) {
      const dd = element('dd', text);
      if (node) dd.append(' ', node);
      dl.insertBefore(dd, dl.querySelector('dt:last-of-type'));
      dl.insertBefore(element('dt', title), dd);
    },
  };

  const notes = element('div', '', 'muted notes');
  notes.id = 'notes';
  main.addTab({ id: 'notes', title: 'Notes', order: 30, onShow: () => renderNotes() }).append(notes);
  function renderNotes() {
    if (!app.data) return;
    const m = app.data.manifest, q = m.quality;
    const a = m.calls?.args;
    const lines = [
      `Hooks from ${m.hooks.ntdll} (${m.hooks.source} exports): ${m.hooks.sites.map(s => `${s.name.replace(/^(Rtl|Nt)/, '')} ${s.calls}`).join(', ')}.`,
      `Out-params: ${q.outParams.computed} computed, ${q.outParams.atReturn + q.outParams.readback} read back, ${q.outParams.seek} by seek, ${q.outParams.unknown} unknown.`,
      `${q.tailCalls} calls entered by tail jump; ${q.unwound} unwound by exceptions; ${q.nestedSkipped} heap-internal nested calls folded.`,
      q.preTraceFrees ? `${q.preTraceFrees} frees of blocks allocated before the trace started.` : '',
      q.superseded ? `${q.superseded} blocks were overwritten while live (a free was missed).` : '',
      q.doubleFree ? `${q.doubleFree} double frees.` : '',
      q.remoteCalls ? `${q.remoteCalls} virtual-memory calls targeted another process (shown in the timeline only).` : '',
      m.calls ? `${m.calls.count.toLocaleString()} calls into ${m.calls.callees.toLocaleString()} exports of ${m.calls.exportModules} modules ` +
        `(${m.calls.tail.toLocaleString()} by jump, ${m.calls.sameModule.toLocaleString()} within one module)` +
        (m.calls.modulesWithoutExports.length ? `; no export table read for ${m.calls.modulesWithoutExports.join(', ')}.` : '.') : '',
      a ? `Arguments: ${a.withSignature.toLocaleString()} calls decoded from ${a.signatures.toLocaleString()} API signatures (win32json + phnt, via ttd-capa), ${a.heuristic.toLocaleString()} without a signature.` : '',
      q.directSyscalls ? `${q.directSyscalls} syscalls were issued from outside ntdll/win32u (direct syscalls) — their effects are not modelled.` : '',
      ...app.notes.flatMap(fn => fn()),
      ...m.warnings,
    ].filter(Boolean);
    notes.replaceChildren(...lines.map(l => element('p', l)));
  }
  app.on('open', renderNotes);
  app.on('highlight', () => { if (main.isShown('notes')) renderNotes(); });
}

export function installLeaks(app) {
  const tab = app.rails.left.panel('main').addTab({ id: 'leaks', title: 'Leaks', order: 30 });
  const summary = element('p', 'Open a trace to see blocks that were never freed.', 'muted');
  summary.id = 'leak-summary';
  const list = element('div', '', 'results');
  list.id = 'leak-list';
  tab.append(element('h2', 'Outstanding at end of trace'), summary, list);
  app.on('open', () => {
    const groups = app.time.leaks(app.stacks);
    const total = groups.reduce((s, g) => s + g.blocks.length, 0);
    summary.textContent = total
      ? `${total.toLocaleString()} blocks allocated during the trace are still live at its end, from ${groups.length} sites.`
      : 'Every block allocated during the trace was freed.';
    list.replaceChildren(...groups.slice(0, 80).map(g => {
      const b = element('button', '', 'result');
      b.append(element('span', g.text), element('small', `${g.blocks.length.toLocaleString()} blocks · ${bytes(g.bytes)}`));
      b.addEventListener('click', () => {
        app.selection = null;
        app.seek(app.data.events.count - 1);
        app.setHighlight(new Set(g.blocks), `Outstanding at end of trace: ${g.text}`);
        app.refreshInspector(true);
      });
      return b;
    }));
  });
}

export function installFind(app) {
  const tab = app.rails.left.panel('main').addTab({ id: 'find', title: 'Find', order: 40 });
  const field = textField('search', 'Find an address, or a function on allocation stacks', '0x1d8c2a0 or leak_b');
  const status = element('p', '', 'muted');
  status.id = 'search-status';
  status.setAttribute('role', 'status');
  tab.append(field.label, status);
  field.input.addEventListener('keydown', e => { if (e.key === 'Enter') search(); });

  function search() {
    if (!app.data) return;
    const { data, time, stacks } = app;
    const q = field.input.value.trim();
    if (!q) { app.setHighlight(null); app.select(null); return; }
    const addr = parseAddress(q);
    if (addr !== null) {
      const b = time.blockAt(addr, app.current);
      if (b !== NONE) { app.setHighlight(null); app.select({ kind: 'block', b }, { focus: true, reveal: true }); status.textContent = `Block ${hex(data.blocks.addr[b])} contains ${hex(addr)}.`; return; }
      const history = time.addressHistory(addr);
      if (history.length) { app.selection = null; app.setHighlight(new Set(history), `Blocks ever at ${hex(addr)}`); status.textContent = `${history.length} blocks were at ${hex(addr)} at some point.`; return; }
      const r = time.regionAt(addr, app.current);
      if (r !== NONE) { app.setHighlight(null); app.select({ kind: 'region', r }, { focus: true, reveal: true }); status.textContent = `${hex(addr)} is in ${app.regionName(r)}.`; return; }
      status.textContent = `Nothing known at ${hex(addr)} at event ${evtLabel(app.current)}.`;
      return;
    }
    const query = q.toLowerCase(), matches = [], nodeHit = new Map();
    for (let b = 0; b < data.blocks.count; b++) {
      const node = data.blocks.allocStack[b];
      if (node === NONE) continue;
      let hit = nodeHit.get(node);
      if (hit === undefined) nodeHit.set(node, hit = stacks.matches(node, query));
      if (hit) matches.push(b);
    }
    app.selection = null;
    app.setHighlight(matches.length ? new Set(matches) : null, `Allocated with “${q}” on the stack`);
    status.textContent = matches.length ? `${matches.length.toLocaleString()} blocks allocated with “${q}” on the stack (live ones are outlined).` : `No allocation stack contains “${q}”.`;
  }
}
