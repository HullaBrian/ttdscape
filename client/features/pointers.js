// Pointer links: call arguments that point into a heap block or a region, resolved at the call
// (or at its return, for values read there). The calls pane and the call Inspector show them as
// links that select the object and open its bytes in the Memory tab.
import { AddressIndex, pointerCandidates } from '../memory.js';
import { NONE, bytes, hex } from '../format.js';
import { element } from '../ui.js';

// Region kinds worth a link in the (dense) calls list: private, mapped, committed before the
// trace. Images, stacks and heap segments without a block are everywhere and are listed only in
// the Inspector.
const ROW_REGION_KINDS = new Set([0, 1, 5]);

export function install(app) {
  const svc = app.services.calls;
  let index = null;
  app.on('open', () => { index = null; });
  const addressIndex = () => index ??= new AddressIndex(app.data, app.time);

  // The event a candidate is resolved at: the state before the call, or before its return.
  function eventFor(i, cand) {
    const c = svc.calls;
    return cand.atReturn && c.endEvt[i] !== NONE ? c.endEvt[i] - 1 : c.startEvt[i] - 1;
  }

  // [{ param, which, addr, evt, obj }] for call i's decoded arguments.
  function targets(i, args) {
    const out = [];
    for (const cand of pointerCandidates(args)) {
      const evt = eventFor(i, cand);
      const obj = addressIndex().objectAt(cand.addr, evt);
      if (obj) out.push({ ...cand, evt, obj });
    }
    return out;
  }

  function describe(t) {
    const off = t.obj.offset ? ` +0x${t.obj.offset.toString(16)}` : '';
    if (t.obj.kind === 'block') {
      const { blocks } = app.data, b = t.obj.b;
      const heap = blocks.heap[b] === NONE ? 'heap' : `Heap ${blocks.heap[b]}`;
      return `block ${hex(blocks.addr[b])}${off} (${heap}, ${bytes(blocks.size[b])})`;
    }
    return `${app.regionName(t.obj.r)} ${hex(app.data.regions.base[t.obj.r])}${off}`;
  }

  const inRows = t => t.obj.kind === 'block' || ROW_REGION_KINDS.has(app.data.regions.kind[t.obj.r]);

  // Selects the object and shows the pointed-to bytes in the Memory tab.
  function open(t) {
    app.services.memory?.focus(t.addr);
    app.select(t.obj.kind === 'block' ? { kind: 'block', b: t.obj.b } : { kind: 'region', r: t.obj.r }, { focus: true, reveal: true });
  }

  function link(t) {
    const a = element('button', `→ ${describe(t)}`, 'ptr');
    a.title = `${hex(t.addr)} points into this ${t.obj.kind} at ${t.atReturn ? 'the return' : 'the call'}. Click to select it and show its bytes.`;
    a.addEventListener('click', e => { e.stopPropagation(); open(t); });
    return a;
  }

  app.services.pointers = { targets, describe, link, inRows, objectAt: (addr, evt) => addressIndex().objectAt(addr, evt) };

  // "Memory this call touched", below the call's details.
  app.inspectorSections.push(item => {
    if (item.kind !== 'call' || !svc.calls || !svc.hasArgs) return null;
    const box = element('div', '', 'pointers');
    svc.args(item.i).then(a => {
      if (app.selection !== item) return;
      const list = targets(item.i, a);
      if (!list.length) return;
      box.append(element('h4', 'Memory this call touched'));
      for (const t of list) {
        const name = t.which === 'ret' ? 'return value' : a.p[t.param]?.n ?? `argument ${t.param + 1}`;
        const row = element('div', '', 'pointer-row');
        row.append(element('span', `${name}${t.which === 'd' ? ' (pointee)' : ''}`, 'muted'), link(t));
        box.append(row);
      }
    });
    return box;
  });
}
