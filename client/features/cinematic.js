// The "Cinematic" toolbar menu: slow looping camera moves (client/cinematic.js plans them;
// atlas.startCinematic flies them). The side panels fade out while one runs, except, if chosen, the
// calls panel (Live calls, Threads, CAPA, Memory); the view is then centred in the space it and the
// timeline leave (atlas.setFraming).
//   - Tour the regions: glides from a wide shot past the most prominent region boxes and back.
//   - Aerial orbit: a slow circle high above the atlas, far enough to keep every region in view.
// A click or drag on the view, the wheel, a camera key (WASD QE F G), Escape, Overview or "Stop" in
// the menu hands the camera back where it is; the kept panel stays usable. Playback keeps running,
// so P shows the trace unfolding.
import { cinematicTour, cinematicOrbit } from '../cinematic.js';
import { element, checkField } from '../ui.js';

const MODES = [
  { id: 'tour', text: 'Tour the regions', title: 'Glide past the most prominent regions, from a wide shot and back' },
  { id: 'aerial', text: 'Aerial orbit', title: 'Circle slowly above the atlas with every region in view' },
];
const ORBIT_SECONDS = 90; // one full turn

export function install(app) {
  const { atlas } = app;
  const wrap = element('div', '', 'cinematic-menu-wrap');
  const buttonEl = element('button', 'Cinematic ▾');
  buttonEl.id = 'cinematic';
  buttonEl.setAttribute('aria-haspopup', 'menu');
  buttonEl.title = 'Slow camera moves around the memory regions (click the view or press Esc to stop)';
  const menu = element('div', '', 'cinematic-menu');
  menu.setAttribute('role', 'menu');
  menu.hidden = true;
  const stop = element('button', '■ Stop');
  stop.setAttribute('role', 'menuitem');
  stop.hidden = true;
  stop.addEventListener('click', () => { menu.hidden = true; atlas.stopCinematic(); });
  menu.append(stop);
  for (const m of MODES) {
    const item = element('button', m.text);
    item.dataset.mode = m.id;
    item.title = m.title;
    item.setAttribute('role', 'menuitem');
    item.addEventListener('click', () => { menu.hidden = true; start(m.id); });
    menu.append(item);
  }
  const keep = checkField('cinematic-calls', 'Keep calls, CAPA and threads', true,
    { prefKey: 'cinematic.calls', title: 'Keep the calls panel (Live calls, Threads, CAPA, Memory) on screen during cinematic moves' });
  menu.append(keep.label);
  const syncKeep = () => document.body.classList.toggle('cinematic-calls', keep.input.checked);
  syncKeep();
  keep.input.addEventListener('change', () => { syncKeep(); if (atlas.cinematic && mode) start(mode); });
  wrap.append(buttonEl, menu);
  document.getElementById('home').after(wrap);
  const hint = element('div', '', 'cinematic-hint');
  hint.hidden = true;
  document.body.append(hint);

  let mode = null;
  const onChange = on => {
    buttonEl.textContent = on ? 'Cinematic ● ▾' : 'Cinematic ▾';
    stop.hidden = !on;
    buttonEl.classList.toggle('active', on);
    document.body.classList.toggle('cinematic', on);
    hint.hidden = !on;
    if (!on) mode = null;
  };

  function start(which) {
    if (!app.data) return;
    hint.textContent = `${which === 'aerial' ? 'Aerial orbit' : 'Cinematic tour'} · click the view or press Esc to stop · P plays the trace`;
    // Replay the fade-out of the hint.
    hint.style.animation = 'none'; void hint.offsetWidth; hint.style.animation = '';
    // Screen space to keep clear: the timeline, and the calls panel when it stays.
    const W = innerWidth, H = innerHeight;
    const timelineTop = document.getElementById('timeline')?.getBoundingClientRect().top ?? H;
    const calls = keep.input.checked ? document.querySelector('.rail>.panel[data-panel="right.calls"]') : null;
    const framing = { right: calls ? Math.max(0, W - calls.getBoundingClientRect().left + 12) : 0, bottom: Math.max(0, H - timelineTop) };
    if (which === 'aerial') {
      // The framed view is the centre of a (W + right) x (H + bottom) virtual frame.
      const orbit = cinematicOrbit(app.layout.items, { fov: atlas.camera.fov, aspect: (W + framing.right) / (H + framing.bottom),
        visible: (H - framing.bottom) / (H + framing.bottom), visibleX: (W - framing.right) / (W + framing.right) });
      atlas.startCinematic(orbit, { secondsPerStop: ORBIT_SECONDS / (orbit?.cameras.length ?? 1), onChange });
    } else {
      atlas.startCinematic(cinematicTour(app.layout.items), { onChange });
    }
    // After starting: starting stops any running move, which clears the mode.
    if (atlas.cinematic) { mode = which; atlas.setFraming(framing); }
  }

  buttonEl.addEventListener('click', () => { menu.hidden = !menu.hidden; });
  // Close the menu on any click elsewhere or Escape.
  addEventListener('pointerdown', e => { if (!wrap.contains(e.target)) menu.hidden = true; });
  addEventListener('keydown', e => { if (e.key === 'Escape') menu.hidden = true; });
  // A new layout (spacing, reserved space) or window size changes the path: re-plan it.
  app.on('layout', () => { if (atlas.cinematic && mode) start(mode); });
  addEventListener('resize', () => { if (atlas.cinematic && mode) start(mode); });
  app.on('open', () => atlas.stopCinematic());
}
