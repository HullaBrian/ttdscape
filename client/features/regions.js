// Region browser: every region of the trace, filterable by name, address and kind, with
// checkboxes that highlight regions in the atlas (optionally dimming the rest). Highlights are
// remembered per analysis in this browser.
import { REGION_KINDS, regionRows } from '../region-list.js';
import { NONE, bytes, hex, evtLabel } from '../format.js';
import { element, textField, checkField, selectField } from '../ui.js';
import { loadJson, saveJson } from '../app/prefs.js';

const MAX_ROWS = 600;

export function install(app) {
  const tab = app.rails.left.panel('main').addTab({ id: 'regions', title: 'Regions', order: 20, onShow: () => render() });

  const search = textField('region-search', '', 'Name or address (e.g. ntdll, 0x7ffa6b260000)');
  search.label.classList.add('compact');
  const chips = element('div', '', 'chips');
  const kinds = new Set(REGION_KINDS.map(([k]) => k));
  for (const [k, text] of REGION_KINDS) {
    const chip = element('button', text, `chip r${k}`);
    chip.setAttribute('aria-pressed', 'true');
    chip.addEventListener('click', () => {
      if (kinds.has(k)) kinds.delete(k); else kinds.add(k);
      chip.setAttribute('aria-pressed', String(kinds.has(k)));
      render();
    });
    chips.append(chip);
  }
  const liveOnly = checkField('region-live', 'Only regions that exist at the playhead', false, { prefKey: 'regions.live' });
  const execOnly = checkField('region-exec', '⚠ Only executable memory outside modules', false,
    { title: 'Regions that are not a module image but had executable pages at some point of the trace' });
  const sort = selectField('region-sort', 'Sort by', [['address', 'Address'], ['size', 'Size'], ['name', 'Name'], ['created', 'Creation']], 'address', { prefKey: 'regions.sort' });
  sort.label.classList.add('compact');
  const dim = checkField('region-dim', 'Dim regions that are not highlighted', false);
  const actions = element('div', '', 'actions');
  const highlightAll = element('button', 'Highlight all listed', 'ref');
  const clear = element('button', 'Clear highlights', 'ref');
  actions.append(highlightAll, clear);
  const status = element('p', '', 'muted');
  const list = element('div', '', 'region-list');
  tab.append(search.label, chips, liveOnly.label, execOnly.label, sort.label, dim.label, actions, status, list);

  let shown = [];
  const key = () => `regions.highlight.${app.analysisId}`;
  const persist = () => saveJson(key(), { regions: [...app.regionHighlight], dim: app.regionDim });

  function setHighlight(set) {
    app.setRegionHighlight(set, dim.input.checked);
    persist();
  }

  function row(r) {
    const { regions } = app.data;
    const el = element('div', '', 'region-row');
    el.dataset.r = r;
    const box = element('input');
    box.type = 'checkbox';
    box.checked = app.regionHighlight.has(r);
    box.title = 'Highlight in the atlas';
    box.addEventListener('click', e => {
      e.stopPropagation();
      const next = new Set(app.regionHighlight);
      if (box.checked) next.add(r); else next.delete(r);
      setHighlight(next);
    });
    const kind = element('span', '', `sw r${regions.kind[r]}`);
    kind.textContent = ' ';
    const text = element('div', '', 'region-text');
    const lifetime = `${regions.createEvt[r] === NONE ? 'before the trace' : evtLabel(regions.createEvt[r])} → ${regions.releaseEvt[r] === NONE ? 'end' : evtLabel(regions.releaseEvt[r])}`;
    text.append(element('span', app.regionName(r), 'region-name'), element('small', `${hex(regions.base[r])}  ${bytes(regions.size[r])}  ·  ${lifetime}`));
    el.append(box, kind, text);
    if (app.services.unbackedExec.ever().has(r)) {
      el.classList.add('exec');
      const warn = element('span', '⚠', 'region-warn');
      warn.title = 'Executable pages outside any module during the trace';
      el.append(warn);
    }
    el.classList.toggle('dead', !app.time.regionLive(r, app.current));
    el.classList.toggle('selected', app.selectedRegion() === r);
    el.addEventListener('click', () => app.select({ kind: 'region', r }, { focus: true, reveal: true }));
    return el;
  }

  function render() {
    if (!app.data || !app.rails.left.panel('main').isShown('regions')) return;
    shown = regionRows(app.data, r => app.regionName(r), {
      text: search.input.value, kinds, liveAt: liveOnly.input.checked ? app.current : null,
      isLive: (r, i) => app.time.regionLive(r, i), sort: sort.input.value,
      only: execOnly.input.checked ? app.services.unbackedExec.ever() : null,
    });
    list.replaceChildren(...shown.slice(0, MAX_ROWS).map(row));
    const hl = app.regionHighlight.size;
    status.textContent = `${shown.length.toLocaleString()} of ${app.data.regions.count.toLocaleString()} regions` +
      (shown.length > MAX_ROWS ? ` (first ${MAX_ROWS} listed)` : '') + (hl ? `  ·  ${hl} highlighted` : '');
    highlightAll.disabled = !shown.length;
    clear.disabled = !hl;
  }

  search.input.addEventListener('input', render);
  for (const c of [liveOnly, execOnly, sort]) c.input.addEventListener('change', render);
  dim.input.addEventListener('change', () => setHighlight(app.regionHighlight));
  highlightAll.addEventListener('click', () => setHighlight(new Set([...app.regionHighlight, ...shown])));
  clear.addEventListener('click', () => setHighlight(new Set()));

  app.on('open', () => {
    const saved = loadJson(key(), null);
    if (saved?.regions?.length) {
      dim.input.checked = !!saved.dim;
      app.setRegionHighlight(saved.regions.filter(r => r < app.data.regions.count), dim.input.checked);
    } else dim.input.checked = false;
    render();
  });
  app.on('highlight', render);
  app.on('select', render);
  let lastLive = -1;
  app.on('seek', ({ current }) => {
    // Liveness only changes the list when "live only" is on or rows show dead regions.
    if (Math.abs(current - lastLive) < 1) return;
    lastLive = current;
    if (liveOnly.input.checked) render();
    else for (const el of list.children) el.classList.toggle('dead', !app.time.regionLive(Number(el.dataset.r), current));
  });

  app.notes.push(() => app.regionHighlight.size ? [`${app.regionHighlight.size} regions highlighted (Regions tab).`] : []);
  app.notes.push(() => {
    const n = app.services.unbackedExec.ever().size;
    return n ? [`${n} regions outside any module had executable pages during the trace (⚠ in the Regions tab).`] : [];
  });
}
