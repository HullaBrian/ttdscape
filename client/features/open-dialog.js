// The "Open trace" dialog: trace picker, analysis options, progress, and saved analyses.
import { bytes } from '../format.js';
import { element } from '../ui.js';

const $ = id => document.getElementById(id);

export function install(app) {
  let watchSource = null;
  const status = (message, error = false) => { $('status').textContent = message; $('status').classList.toggle('error', error); };

  async function open(id, initialEvent) {
    status('Loading analysis...');
    watchSource?.close();
    await app.open(id, { initialEvent, onProgress: f => status(`Loading analysis... ${Math.round(f * 100)}%`) });
    $('welcome').hidden = true;
    const m = app.data.manifest;
    $('trace-name').textContent = `${m.trace.path.split(/[\\/]/).pop()}  ·  ${m.trace.arch}  ·  pid ${m.trace.pid}`;
    status(`Loaded ${m.counts.events.toLocaleString()} events.`);
    $('open-dialog').close();
  }
  app.openAnalysis = open;

  async function refreshAnalyses() {
    const list = await (await app.api('/api/analyses')).json();
    const box = $('analyses');
    box.replaceChildren();
    if (!list.length) box.append(element('p', 'No analyses yet.', 'muted'));
    for (const a of list) {
      const row = element('div', '', 'saved-job');
      if (a.state === 'ready') {
        const b = element('button', '', 'result');
        b.append(element('span', a.name), element('small', `${a.summary?.events?.toLocaleString() ?? '?'} events · ${a.summary?.arch ?? ''} · stack depth ${a.options.stackDepth}` +
          `${a.options.calls === 'none' ? ' · no calls' : a.options.callArgs === false ? ' · calls without arguments' : a.options.calls ? '' : ' · no calls (older analysis)'}`));
        b.addEventListener('click', () => open(a.id).catch(err => status(err.message, true)));
        row.append(b);
      } else {
        row.append(element('p', `${a.name}: ${a.state}${a.stage ? ` (${a.stage} ${Math.round((a.progress ?? 0) * 100)}%)` : ''}${a.error ? ` — ${a.error}` : ''}`, 'muted'));
      }
      const remove = element('button', a.state === 'running' || a.state === 'queued' ? 'Cancel' : 'Remove', 'result');
      remove.addEventListener('click', async () => {
        await app.api(`/api/analyses/${a.id}`, { method: 'DELETE' }).catch(err => status(err.message, true));
        refreshAnalyses();
      });
      row.append(remove);
      box.append(row);
    }
  }

  async function refreshTraces() {
    try {
      const { dirs, traces } = await (await app.api('/api/traces')).json();
      const box = $('trace-list');
      box.replaceChildren();
      if (!traces.length) box.append(element('p', `No .run files in ${dirs.join(', ')}.`, 'muted'));
      for (const t of traces) {
        const b = element('button', '', 'result');
        b.append(element('span', t.name), element('small', `${bytes(t.size)} · ${t.path}`));
        b.addEventListener('click', () => { $('trace-path').value = t.path; });
        box.append(b);
      }
    } catch (err) { status(err.message, true); }
  }

  async function analyze() {
    const trace = $('trace-path').value.trim();
    if (!trace) { status('Enter the full path of a .run trace.', true); return; }
    try {
      const res = await app.api('/api/analyses', { method: 'POST', body: JSON.stringify({ trace, options: {
        stackDepth: Number($('stack-depth').value), symbols: $('symbols').checked,
        calls: $('record-calls').checked ? 'exports' : 'none', callArgs: $('record-args').checked, capa: $('record-capa').checked,
        activity: $('record-activity').checked || $('record-snapshots').checked, snapshots: $('record-snapshots').checked } }) });
      const job = await res.json();
      if (job.state === 'ready') { await open(job.id); return; }
      watch(job.id);
    } catch (err) { status(err.message, true); }
  }

  function watch(id) {
    watchSource?.close();
    $('progress').hidden = false;
    watchSource = new EventSource(`/api/analyses/${id}/progress`);
    watchSource.onmessage = async msg => {
      const e = JSON.parse(msg.data);
      if (e.state === 'running' || e.state === 'queued') {
        status(`${e.state === 'queued' ? 'Queued' : 'Analyzing'}${e.stage ? `: ${e.stage}` : ''} ${e.progress ? `${Math.round(e.progress * 100)}%` : ''}`);
        $('progress').value = (e.progress ?? 0) * 100;
      } else if (e.state === 'ready') {
        watchSource.close(); $('progress').hidden = true;
        await open(id).catch(err => status(err.message, true));
      } else if (e.state === 'failed') {
        watchSource.close(); $('progress').hidden = true;
        status(`Analysis failed: ${e.error}`, true);
        refreshAnalyses();
      }
    };
  }

  $('open').addEventListener('click', () => { $('open-dialog').showModal(); refreshTraces(); refreshAnalyses(); });
  $('close-open').addEventListener('click', () => $('open-dialog').close());
  $('analyze').addEventListener('click', analyze);
  $('trace-path').addEventListener('keydown', e => { if (e.key === 'Enter') analyze(); });
  $('record-calls').addEventListener('change', () => { $('record-args').disabled = !$('record-calls').checked; });
}
