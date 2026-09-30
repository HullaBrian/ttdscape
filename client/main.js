// Composition root. The viewer is an App core (app/app.js) plus features that install
// themselves into it: each adds panels, scene layers, timeline lanes, hover text or inspector
// views through the app's registries. To add a capability, write a feature module and list it
// below; see docs/viewer-architecture.md.
import { Atlas } from './atlas.js';
import { Timeline } from './timeline.js';
import { Inspector, describeEvent } from './inspector.js';
import { App } from './app/app.js';
import { Rail } from './app/rails.js';
import { element } from './ui.js';
import * as callData from './features/call-data.js';
import * as memoryView from './features/memory-view.js';
import * as playback from './features/playback.js';
import * as callBeams from './features/call-beams.js';
import * as callLane from './features/call-lane.js';
import * as liveCalls from './features/live-calls.js';
import * as capa from './features/capa.js';
import * as pointers from './features/pointers.js';
import * as threads from './features/threads.js';
import * as memoryPane from './features/memory-pane.js';
import * as accessHistory from './features/access-history.js';
import * as activity from './features/activity.js';
import * as contentSearch from './features/content-search.js';
import * as memoryBeams from './features/memory-beams.js';
import * as cinematic from './features/cinematic.js';
import * as regions from './features/regions.js';
import * as openDialog from './features/open-dialog.js';
import { installInspectorTabs, installLeaks, installFind } from './features/panels.js';

const $ = id => document.getElementById(id);

let app = null;
const atlas = new Atlas($('viewport'), {
  onSelect: item => app.select(item.kind === 'call' ? { kind: 'call', i: item.i } : item, { reveal: true }),
  onHover: (item, e) => {
    const tip = $('tooltip');
    const text = item && app.data ? app.describeHover(item) : null;
    if (!text) { tip.hidden = true; return; }
    tip.textContent = text;
    tip.hidden = false;
    tip.style.left = `${Math.min(innerWidth - 440, e.clientX + 14)}px`; tip.style.top = `${e.clientY + 14}px`;
  },
  onFlight: locked => {
    $('fly').textContent = locked ? 'Exit flight [F]' : 'Enter flight [F]';
    $('crosshair').hidden = !locked; $('flight-hint').hidden = !locked;
  },
  onDeselect: () => app.select(null),
  onFlightSpeed: mode => { $('flight-hint').dataset.speed = mode; },
});

const timeline = new Timeline($('timeline'), {
  onSeek: i => app.seek(i),
  onHover: (i, e) => {
    const tip = $('timeline-tip');
    if (i === null || !app.data) { tip.hidden = true; return; }
    tip.textContent = describeEvent(i, { data: app.data, stacks: app.stacks, threadName: t => app.threadName(t), heapName: h => app.heapName(h) });
    tip.hidden = false;
    tip.style.left = `${Math.min(innerWidth - 420, Math.max(8, e.clientX - 100))}px`;
  },
});

const details = element('div');
details.id = 'details';
const inspector = new Inspector(details, {
  get data() { return app.data; }, get time() { return app.time; }, get stacks() { return app.stacks; },
  threadName: t => app.threadName(t), heapName: h => app.heapName(h), regionName: r => app.regionName(r),
  position: i => app.position(i),
  current: () => app.current,
  seek: i => app.seek(i),
  select: (item, focus) => app.select(item, { focus }),
});
inspector.clear('Open a trace to begin.');

const rails = { left: new Rail($('left-rail'), { side: 'left', defaultWidth: 290 }), right: new Rail($('right-rail'), { side: 'right', defaultWidth: 380 }) };
app = new App({ atlas, timeline, inspector, rails });

// Order matters where features build on each other: services first, then the tabs they fill.
installInspectorTabs(app, details);
callData.install(app);
memoryView.install(app);
playback.install(app);
callBeams.install(app);
callLane.install(app);
regions.install(app);
installLeaks(app);
installFind(app);
pointers.install(app);
liveCalls.install(app);
threads.install(app);
capa.install(app);
memoryPane.install(app);
activity.install(app);
accessHistory.install(app);
contentSearch.install(app);
memoryBeams.install(app);
cinematic.install(app);
openDialog.install(app);

$('home').addEventListener('click', () => atlas.overview());
$('fly').addEventListener('click', () => atlas.toggleFlight());

(async function start() {
  const params = new URLSearchParams(location.hash.slice(1));
  try {
    await app.api('/api/health');
    const id = params.get('a');
    if (id) await app.openAnalysis(id, params.has('e') ? Number(params.get('e')) : undefined);
  } catch (err) {
    $('app-error').textContent = `Could not reach the TTDscape server: ${err.message}`;
    $('app-error').hidden = false;
  }
})();

// For debugging and end-to-end tests.
window.ttdscape = app;
