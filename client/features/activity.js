// Memory activity from the analysis's activity pass (analyze --activity; analyzer
// replay/activity.cpp): writes per block and per region page over time, who wrote each object, and
// code that ran after being written (write-then-execute).
//   - "Color blocks by → Activity": blocks and committed pages glow orange with recent writes.
//   - A timeline lane: the write rate, with write-then-execute findings as red ticks.
//   - Inspector: "Writes over the trace" for a block (first and last writer, no replay needed) and a
//     region (its pages), and a region's write-then-execute pages.
//   - Notes: a summary of the findings.
// Analyses made without the pass have none of these files; the viewer says so where it matters.
import { Color } from 'three';
import { decodeActivity, decodeWriters } from '../trace-reader.js';
import { ActivityModel } from '../memory.js';
import { NONE, evtLabel, hex } from '../format.js';
import { element } from '../ui.js';
import { facts, button } from '../inspector.js';

const QUIET = new Color('#34404f'), HOT = new Color('#ff8a3d');
const FULL = 12; // log2 of the write heat that colours fully

export function install(app) {
  let model = null, writers = null, byBlock = null, wx = [], error = null;
  const available = () => !!app.data?.manifest.files.activity;

  async function load() {
    const id = app.analysisId;
    try {
      const [a, w, x] = await Promise.all([
        app.file(app.data.manifest.files.activity.file).then(r => r.arrayBuffer()),
        app.file(app.data.manifest.files.writers.file).then(r => r.arrayBuffer()),
        app.file(app.data.manifest.files.wx.file).then(r => r.json()),
      ]);
      if (id !== app.analysisId) return;
      model = new ActivityModel(decodeActivity(a), app.data.series);
      writers = decodeWriters(w);
      byBlock = new Map();
      for (let i = 0; i < writers.count; i++) if (writers.block[i] !== NONE) byBlock.set(writers.block[i], i);
      wx = x.findings ?? [];
    } catch (err) {
      if (id !== app.analysisId) return;
      error = /^404/.test(err.message) ? 'the server does not serve activity files; it is older than the analyzer, so restart it' : err.message;
    }
    app.queueRender();
    app.timeline.draw();
    app.refreshInspector();
    app.emit('activity');
  }

  app.on('open', () => {
    model = writers = byBlock = null; wx = []; error = null;
    if (available()) load();
    note.hidden = true;
  });

  // ---- colour mode ----
  const tone = (heat, c) => c.copy(QUIET).lerp(HOT, Math.min(1, Math.log2(1 + heat) / FULL));
  app.services.blockColors.add('activity', 'Activity (recent writes)', {
    block: (b, c) => tone(model ? model.heat(b, app.current) : 0, c),
    page: (p, c) => (model && p.r !== undefined ? tone(model.regionHeat(p.r, app.current), c) : undefined),
  });
  const note = element('p', 'This analysis has no activity data. Analyze the trace again with "Record memory activity".', 'muted');
  note.hidden = true;
  app.viewTab.querySelector('.group')?.append(note);
  const syncNote = () => { note.hidden = !(app.data && app.services.blockColors.mode() === 'activity' && !available()); };
  document.getElementById('color')?.addEventListener('change', syncNote);
  app.on('open', syncNote);
  app.services.legend?.add('Activity', 'With "Color blocks by: Activity", blocks and committed pages glow orange with recent writes (analyses with "Record memory activity"). The timeline lane shows the write rate; red ticks are code that ran after being written.');

  // ---- naming ----
  // Writer frames hold PC + 1 (frames are return addresses): unbacked code is named by its region.
  function codeText(frame, evt) {
    const { frames } = app.data;
    if (frame === NONE || frame >= frames.count) return '?';
    if (frames.module[frame] !== NONE) return app.stacks.frameText(frame);
    const pc = frames.addr[frame] - 1;
    const r = app.time.regionAt(pc, Math.min(evt, app.data.events.count - 1));
    return r === NONE ? `(unbacked) ${hex(pc)}` : `(unbacked) ${app.regionName(r)} ${hex(app.data.regions.base[r])} +0x${(pc - app.data.regions.base[r]).toString(16)}`;
  }

  // ---- timeline lane ----
  app.timeline.addLane({
    height: 8,
    draw(ctx, { top, height, view, columns }) {
      if (!model) return;
      const span = Math.max(1, view[1] - view[0]), counts = new Float64Array(columns);
      let max = 0;
      for (let col = 0; col < columns; col++) {
        const lo = model.bucketOf(view[0] + col / columns * span), hi = model.bucketOf(view[0] + (col + 1) / columns * span);
        let n = 0;
        for (let b = lo; b <= hi; b++) n += model.total[b] / Math.max(1, hi - lo + 1);
        counts[col] = n; max = Math.max(max, n);
      }
      ctx.fillStyle = '#ff8a3d';
      for (let col = 0; col < columns && max; col++) {
        if (!counts[col]) continue;
        const f = Math.log2(1 + counts[col]) / Math.log2(1 + max);
        ctx.globalAlpha = 0.25 + 0.6 * f;
        ctx.fillRect(col, top + height * (1 - f), 1, Math.max(1, height * f));
      }
      ctx.globalAlpha = 1;
      ctx.fillStyle = '#ff5a4f';
      for (const f of wx) {
        const x = Math.floor((f.exec.evt - 0.5 - view[0]) / span * columns);
        if (x >= 0 && x < columns) ctx.fillRect(x, top, 2, height);
      }
    },
  });

  // ---- Inspector ----
  function writerFacts(i) {
    const t = th => (th === 0xFFFF ? '' : ` · ${app.threadName(th)}`);
    return facts([
      ['Writes', writers.writes[i].toLocaleString()],
      ['First written', `${evtLabel(writers.firstEvt[i])} by ${codeText(writers.firstFrame[i], writers.firstEvt[i])}${t(writers.firstThread[i])}`],
      ['Last written', `${evtLabel(writers.lastEvt[i])} by ${codeText(writers.lastFrame[i], writers.lastEvt[i])}${t(writers.lastThread[i])}`],
    ]);
  }

  function blockSection(b) {
    const box = element('div', '', 'activity-section');
    box.append(element('h4', 'Writes over the trace'));
    const i = byBlock?.get(b);
    if (i === undefined) { box.append(element('p', 'No writes to this block were recorded while it was live.', 'muted')); return box; }
    if (writers.flags[i] & 1) box.append(element('p', 'Written by code outside every module', 'badge'));
    box.append(writerFacts(i));
    const actions = element('div', '', 'actions');
    actions.append(button('First write', () => app.seek(writers.firstEvt[i])), button('Last write', () => app.seek(writers.lastEvt[i])));
    box.append(actions);
    return box;
  }

  function regionSection(r) {
    const box = element('div', '', 'activity-section');
    const findings = wx.filter(f => f.region === r);
    // Pages of this region, most written first.
    const pages = [];
    for (let i = 0; i < (writers?.count ?? 0); i++) if (writers.block[i] === NONE && writers.region[i] === r) pages.push(i);
    pages.sort((a, b) => writers.writes[b] - writers.writes[a]);
    if (findings.length) {
      box.append(element('h4', `Code that ran after being written (${findings.length} page${findings.length > 1 ? 's' : ''})`));
      const list = element('div', '', 'results');
      for (const f of findings.slice(0, 100)) {
        const b = element('button', '', 'result wx-row');
        const page = Number.parseInt(f.page.slice(2), 16);
        const writer = f.write.frame === null ? f.write.pc : codeText(f.write.frame, f.write.evt);
        b.append(element('span', `${f.page} +0x${(page - app.data.regions.base[r]).toString(16)} ran at ${evtLabel(f.exec.evt)} (${app.threadName(f.exec.thread)})`),
          element('small', `last written at ${evtLabel(f.write.evt)} by ${writer} (${app.threadName(f.write.thread)}); ${f.writes.toLocaleString()} writes before`));
        b.title = `First execution at TTD ${f.exec.pos}, PC ${f.exec.pc}\nLast write before it at TTD ${f.write.pos}\nClick to go to the execution`;
        b.addEventListener('click', () => app.seek(Math.max(0, f.exec.evt)));
        list.append(b);
      }
      box.append(list);
      const writerRegions = [...new Set(findings.map(f => f.write.region).filter(x => x !== null && x !== r))];
      if (writerRegions.length) {
        const actions = element('div', '', 'actions');
        for (const w of writerRegions.slice(0, 4))
          actions.append(button(`Writer: ${app.regionName(w)} ${hex(app.data.regions.base[w])}`, () => app.select({ kind: 'region', r: w }, { focus: true })));
        box.append(actions);
      }
    }
    if (pages.length) {
      const total = pages.reduce((s, i) => s + writers.writes[i], 0);
      box.append(element('h4', `Writes over the trace (outside blocks): ${total.toLocaleString()}`));
      const top = element('div', '', 'results');
      for (const i of pages.slice(0, 8)) {
        const base = app.data.regions.base[r] + writers.page[i] * 4096;
        const b = element('button', '', 'result');
        b.append(element('span', `page ${hex(base)}: ${writers.writes[i].toLocaleString()} writes`),
          element('small', `${evtLabel(writers.firstEvt[i])} – ${evtLabel(writers.lastEvt[i])} · last by ${codeText(writers.lastFrame[i], writers.lastEvt[i])}`));
        b.addEventListener('click', () => { app.services.memory?.show(base, 4096); });
        top.append(b);
      }
      box.append(top);
    }
    return box.childElementCount ? box : null;
  }

  app.inspectorSections.push(item => {
    if (!app.data || !(item.kind === 'block' || item.kind === 'region' || item.kind === 'span')) return null;
    if (!available()) return null;
    if (!model) return error ? element('p', `Could not load the activity data: ${error}.`, 'muted') : null;
    if (item.kind === 'block') return blockSection(item.b);
    return regionSection(item.kind === 'region' ? item.r : app.data.spans.region[item.s]);
  });

  // ---- Notes ----
  app.notes.push(() => {
    const a = app.data?.manifest.activity;
    if (!a) return ['Memory activity was not recorded (analyze again with "Record memory activity").'];
    const lines = [`Memory activity: ${a.writes.toLocaleString()} writes to ${a.objects.toLocaleString()} blocks and pages outside images and stacks.`];
    if (!wx.length) return [...lines, 'No code ran from memory written during the trace.'];
    const groups = new Map();
    for (const f of wx) {
      const k = `${f.region}|${f.write.region}`;
      groups.set(k, (groups.get(k) ?? 0) + 1);
    }
    lines.push(`Write-then-execute: ${wx.length} pages ran after being written:`);
    for (const [k, n] of [...groups].sort((x, y) => y[1] - x[1]).slice(0, 6)) {
      const [r, w] = k.split('|').map(x => (x === 'null' ? NONE : Number(x)));
      const name = x => (x === NONE || Number.isNaN(x) ? 'unknown memory' : `${app.regionName(x)} ${hex(app.data.regions.base[x])}`);
      lines.push(`  ${n} page${n > 1 ? 's' : ''} of ${name(r)}, written by code in ${name(w)}.`);
    }
    return lines;
  });

  app.services.activity = { get model() { return model; }, get findings() { return wx; }, codeText };
}
