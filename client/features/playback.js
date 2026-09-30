// Playback and navigation: play/pause, keyboard stepping, pacing by events or by calls, the beam
// window derived from it, and the time HUD that says where the playhead is.
//
// Pacing by events plays the whole trace in 10 s at 1x, so dense call bursts fly by. Pacing by
// calls advances through the calls the beam filter shows at a fixed number per second, whatever
// their spacing on the event axis, so each arc can be followed.
import { timeAtIndex, indexAtTime } from '../calls.js';
import { EVENT_KIND } from '../format.js';
import { selectField, element } from '../ui.js';
import { load, save } from '../app/prefs.js';

const $ = id => document.getElementById(id);

const EVENT_SPEEDS = [['0.002', 'Glacial (trace in 83 min)'], ['0.01', 'Crawl (trace in 17 min)'], ['0.05', 'Very slow (trace in 3 min)'],
  ['0.25', 'Slow (trace in 40 s)'], ['1', 'Normal (trace in 10 s)'], ['4', 'Fast (trace in 2.5 s)']];
const CALL_SPEEDS = [['0.5', '1 call every 2 s'], ['1', '1 call/s'], ['3', '3 calls/s'], ['10', '10 calls/s'], ['30', '30 calls/s'],
  ['100', '100 calls/s'], ['400', '400 calls/s']];

export function install(app) {
  const calls = app.services.calls;
  const group = element('div', '', 'group');
  const pace = selectField('pace', 'Pace playback by', [['events', 'Events (whole trace in fixed time)'], ['calls', 'Calls (fixed calls per second)']], 'events',
    { prefKey: 'play.pace', title: 'Pacing by calls follows the calls the beam filter shows, one arc at a time' });
  const speed = selectField('speed', 'Playback speed', EVENT_SPEEDS, '1');
  const length = selectField('beam-length', 'Beam length', [['0.3', 'Short (0.3 s)'], ['1', 'Normal (1 s)'], ['3', 'Long (3 s)'], ['8', 'Very long (8 s)']], '1',
    { prefKey: 'play.beamLength', title: 'How long a call beam takes to travel and fade, in seconds of playback' });
  group.append(element('h2', 'Playback'), pace.label, speed.label, length.label);
  app.viewTab.append(group);

  const speeds = () => pace.input.value === 'calls' ? CALL_SPEEDS : EVENT_SPEEDS;
  const fillSpeeds = () => {
    const key = `play.speed.${pace.input.value}`, list = speeds();
    const want = load(key, pace.input.value === 'calls' ? '3' : '1');
    speed.input.replaceChildren(...list.map(([v, t]) => Object.assign(element('option', t), { value: v })));
    speed.input.value = list.some(([v]) => v === want) ? want : list[0][0];
  };
  fillSpeeds();
  pace.input.addEventListener('change', () => { fillSpeeds(); if (pace.input.value === 'calls') calls.load(); resync(); });
  speed.input.addEventListener('change', () => save(`play.speed.${pace.input.value}`, speed.input.value));

  // Pacing by calls needs the call data; without it, events pace.
  const byCalls = () => pace.input.value === 'calls' && calls.model && calls.calls.count > 0;
  let cursor = 0; // continuous index into calls.paceTimes() while pacing by calls
  const resync = () => { if (byCalls()) cursor = indexAtTime(calls.paceTimes(), app.now()); };
  app.on('seek', ({ fromPlay }) => { if (!fromPlay) resync(); });
  app.on('calls', resync);

  // The beam window on the event axis: how far back a call that is still drawn can have started.
  app.services.playback = {
    window() {
      const seconds = Number(length.input.value);
      if (byCalls()) {
        const times = calls.paceTimes(), T = app.now();
        const k = indexAtTime(times, T), back = k - Number(speed.input.value) * seconds;
        // A call `seconds` of playback ago is at the end of its beam; before the first call, all of them are shown.
        return Math.max(1e-3, back >= 0 ? T - timeAtIndex(times, back) : T - times[0] + 1);
      }
      return Math.max(0.5, app.data.events.count / 10 * Number(speed.input.value) * seconds);
    },
    get byCalls() { return byCalls(); },
  };

  function toggle() {
    if (!app.data) return;
    app.playing = !app.playing;
    $('play').textContent = app.playing ? 'Pause [P]' : 'Play [P]';
    const end = app.data.events.count - 1;
    if (app.playing && app.current >= end) app.seek(0);
    app.playTime = app.current;
    resync();
    let last = performance.now();
    const step = now => {
      if (!app.playing || !app.data) return;
      const dt = Math.min(0.1, Math.max(0, now - last) / 1000);
      last = now;
      if (byCalls()) {
        const times = calls.paceTimes();
        cursor += dt * Number(speed.input.value);
        if (cursor >= times.length - 1) { app.playTime = end; app.seek(end); toggle(); return; }
        app.playTime = Math.max(app.playTime, timeAtIndex(times, cursor));
      } else {
        app.playTime += dt * app.data.events.count / 10 * Number(speed.input.value);
      }
      if (app.playTime >= end) { app.seek(end); toggle(); return; }
      const i = Math.max(0, Math.floor(app.playTime));
      if (i !== app.current) app.seek(i, { fromPlay: true });
      updateClock();
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
    updateClock();
  }
  app.services.playback.toggle = toggle;
  $('play').addEventListener('click', toggle);

  // Next/previous event touching the selection (or next marker when nothing is selected).
  function related(direction) {
    const { events, blocks, spans } = app.data, s = app.selection, t = app.time;
    if (s?.kind === 'block') {
      const addr = blocks.addr[s.b];
      return t.seek(app.current, direction, j => events.kind[j] <= 8 && events.addr[j] === addr);
    }
    if (s?.kind === 'region' || s?.kind === 'span') {
      const r = s.kind === 'region' ? s.r : spans.region[s.s];
      return t.seek(app.current, direction, j => events.kind[j] >= 16 && events.kind[j] <= 22 && events.id[j] === r);
    }
    return t.seek(app.current, direction, j => events.kind[j] === 36);
  }

  addEventListener('keydown', e => {
    if (!app.data || ['INPUT', 'SELECT', 'TEXTAREA'].includes(e.target?.tagName)) return;
    for (const handler of app.keys) if (handler(e)) { e.preventDefault(); return; }
    if (e.code === 'ArrowRight' || e.code === 'ArrowLeft') {
      e.preventDefault();
      const dir = e.code === 'ArrowRight' ? 1 : -1;
      app.seek(e.shiftKey ? related(dir) : app.current + dir * (e.ctrlKey ? 100 : 1));
    } else if (e.code === 'Home') { e.preventDefault(); app.seek(0); }
    else if (e.code === 'End') { e.preventDefault(); app.seek(app.data.events.count - 1); }
    else if (e.code === 'KeyP' && !e.ctrlKey) { e.preventDefault(); toggle(); }
  });

  // ---- time HUD ----
  const clock = $('clock');
  let positionFor = -1;
  function updateClock() {
    if (!app.data) { clock.hidden = true; return; }
    clock.hidden = false;
    const { events } = app.data, i = app.current, n = events.count;
    const T = app.now();
    clock.querySelector('.evt').textContent = `Event ${(i + 1).toLocaleString()} / ${n.toLocaleString()}`;
    clock.querySelector('.pct').textContent = `${(n > 1 ? i / (n - 1) * 100 : 100).toFixed(1)}%`;
    clock.querySelector('.kind').textContent = `${EVENT_KIND[events.kind[i]] ?? ''} · ${app.threadName(events.thread[i])}`;
    const speedText = speed.input.selectedOptions[0]?.textContent ?? '';
    clock.querySelector('.play').textContent = app.playing
      ? `▶ ${speedText}  ·  t = ${T.toFixed(2)}`
      : `⏸ paused  ·  t = ${T.toFixed(0)}`;
    if (positionFor !== i) {
      positionFor = i;
      const pos = clock.querySelector('.pos');
      pos.textContent = 'TTD …';
      app.position(i).then(p => { if (positionFor === i) pos.textContent = p ? `TTD ${p}` : ''; });
    }
  }
  app.on('seek', updateClock);
  app.on('open', () => { positionFor = -1; updateClock(); });

  // Keep the URL pointing at the current event (without flooding history while playing).
  let hashTimer = null;
  app.on('seek', () => {
    clearTimeout(hashTimer);
    hashTimer = setTimeout(() => history.replaceState(null, '', `#a=${app.analysisId}&e=${app.current}`), 300);
  });
}
