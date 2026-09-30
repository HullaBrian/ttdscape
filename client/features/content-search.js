// Content search in the Find tab: which heap blocks held a string, some bytes or a pointer, from the
// block snapshots of analyses made with "Snapshot block contents" (GET .../search; server/search.mjs).
// A snapshot is a block's first 4 KiB as it was last seen (at its free, or at the end of the trace).
// Clicking a match selects the block while it is live and shows the bytes in the Memory tab.
import { NONE, bytes, evtLabel, hex } from '../format.js';
import { element, textField, selectField } from '../ui.js';

const printable = c => (c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '.');

export function install(app) {
  const tab = document.getElementById('tab-find');
  const group = element('div', '', 'group');
  const field = textField('content-search', 'Find in block contents', '192.168.81.129');
  const mode = selectField('content-mode', 'as', [['text', 'Text (ASCII or UTF-16, any case)'], ['hex', 'Hex bytes'], ['pointer', 'A pointer value']], 'text');
  const status = element('p', '', 'muted');
  status.setAttribute('role', 'status');
  const list = element('div', '', 'results');
  group.append(element('h2', 'Contents'), field.label, mode.label, status, list);
  tab.append(group);

  const available = () => !!app.data?.manifest.files.contentsIdx;
  function syncAvailability() {
    field.input.disabled = !available();
    status.textContent = !app.data ? '' : available()
      ? `${(app.data.manifest.snapshots?.blocks ?? 0).toLocaleString()} blocks were snapshotted (first ${bytes(app.data.manifest.snapshots?.cap ?? 4096)} each, as last seen).`
      : 'This analysis has no block snapshots. Analyze the trace again with "Snapshot block contents".';
    list.replaceChildren();
  }
  app.on('open', syncAvailability);

  // An event at which the block is live: the playhead if it is, else just before its free.
  function liveEvent(b) {
    const { blocks } = app.data;
    if (app.time.isLive(b, app.current)) return app.current;
    return blocks.freeEvt[b] !== NONE ? Math.max(0, blocks.freeEvt[b] - 1) : app.data.events.count - 1;
  }

  async function search() {
    if (!available()) return;
    const q = field.input.value.trim();
    if (!q) { list.replaceChildren(); return; }
    status.textContent = 'Searching…';
    const id = app.analysisId;
    try {
      const res = await (await app.api(`/api/analyses/${id}/search?q=${encodeURIComponent(q)}&mode=${mode.input.value}`)).json();
      if (id !== app.analysisId) return;
      const { blocks } = app.data;
      const seen = new Set();
      list.replaceChildren(...res.matches.map(m => {
        const b = m.block, addr = blocks.addr[b] + m.offset;
        const preview = m.preview.match(/../g).map(h => Number.parseInt(h, 16));
        const row = element('button', '', 'result content-match');
        row.append(element('span', `${hex(blocks.addr[b])} +0x${m.offset.toString(16)}  (${bytes(blocks.size[b])}, ${app.heapName(blocks.heap[b]).split(' (')[0]})`),
          element('small', `${evtLabel(blocks.allocEvt[b])} – ${evtLabel(blocks.freeEvt[b])}  ·  ${m.pattern === 'utf16' ? 'UTF-16' : m.pattern}  ·  ${preview.map(printable).join('')}`));
        row.title = `${app.stacks.siteText(blocks.allocStack[b])}\nClick to select the block (while live) and show these bytes`;
        row.addEventListener('click', () => {
          app.seek(liveEvent(b));
          app.services.memory?.focus(addr);
          app.select({ kind: 'block', b }, { focus: true, reveal: true });
        });
        seen.add(b);
        return row;
      }));
      status.textContent = res.matches.length
        ? `${res.matches.length.toLocaleString()} match${res.matches.length > 1 ? 'es' : ''} in ${seen.size} block${seen.size > 1 ? 's' : ''}${res.truncated ? ' (the first ones)' : ''}. Blocks are as last seen: at their free, or at the end of the trace.`
        : `No block contains “${q}” as last seen.`;
    } catch (err) {
      status.textContent = /^404/.test(err.message) ? 'The server cannot search contents; it is older than the viewer, so restart it.' : `Search failed: ${err.message}`;
    }
  }
  field.input.addEventListener('keydown', e => { if (e.key === 'Enter') search(); });
  mode.input.addEventListener('change', search);
}
