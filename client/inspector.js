// Detail panel for the selected block / region / page span / event.
import { NONE, bytes, hex, evtLabel, protectName, flagNames, BLOCK_FLAGS, REGION_KIND, EVENT_KIND } from './format.js';

export { facts, button };

export function element(tag, text = '', className = '') {
  const e = document.createElement(tag);
  if (text) e.textContent = text;
  if (className) e.className = className;
  return e;
}

function facts(pairs) {
  const dl = element('dl');
  for (const [k, v] of pairs) {
    if (v === undefined || v === null || v === '') continue;
    dl.append(element('dt', k));
    const dd = element('dd');
    if (v instanceof Node) dd.append(v); else dd.textContent = String(v);
    dl.append(dd);
  }
  return dl;
}

function button(text, onClick, title = '') {
  const b = element('button', text, 'ref');
  if (title) b.title = title;
  b.addEventListener('click', onClick);
  return b;
}

export class Inspector {
  constructor(root, ctx) {
    this.root = root;
    this.ctx = ctx; // { data, time, stacks, threadName(t), heapName(h), regionName(r), seek(i), select(item), position(i) -> Promise<string> }
  }

  clear(message = 'Click a block, page range or region. Drag the timeline to move through time.') {
    this.root.replaceChildren(element('p', message, 'muted'));
  }

  // Arbitrary content from a feature (e.g. a call's details).
  show(nodes) { this.root.replaceChildren(...nodes); }

  stackList(title, node) {
    const wrap = element('div', '', 'stack');
    wrap.append(element('h4', title));
    if (node === NONE) { wrap.append(element('p', 'No stack captured.', 'muted')); return wrap; }
    const list = element('ol', '', 'frames');
    for (const f of this.ctx.stacks.describe(node)) {
      const li = element('li', f.text, f.allocator ? 'allocator' : '');
      if (f.source) li.append(element('small', f.source));
      li.title = hex(f.address);
      list.append(li);
    }
    wrap.append(list);
    return wrap;
  }

  // Seq:Steps positions are fetched lazily (positions.bin is not loaded up front).
  positionNode(evt) {
    const span = element('span', evtLabel(evt));
    if (evt !== NONE) this.ctx.position(evt).then(p => { if (p) span.textContent = `${evtLabel(evt)}  (${p})`; });
    return span;
  }

  showBlock(b) {
    const { blocks } = this.ctx.data, t = this.ctx.time;
    const nodes = [element('h3', `Heap block ${hex(blocks.addr[b])}`)];
    const flags = flagNames(blocks.flags[b], BLOCK_FLAGS);
    const alive = t.isLive(b, this.ctx.current());
    nodes.push(element('p', alive ? 'Live at the current event.' : 'Not live at the current event.', alive ? 'badge live' : 'badge'));
    nodes.push(facts([
      ['Address', `${hex(blocks.addr[b])} – ${hex(blocks.addr[b] + blocks.size[b])}`],
      ['Size', blocks.flags[b] & 0x02 ? 'unknown (allocated before the trace)' : `${blocks.size[b].toLocaleString()} B (${bytes(blocks.size[b])})`],
      ['Heap', this.ctx.heapName(blocks.heap[b])],
      ['Allocated', blocks.allocEvt[b] === NONE ? 'before the trace' : this.positionNode(blocks.allocEvt[b])],
      ['Allocating thread', blocks.allocThread[b] === 0xFFFF ? '' : this.ctx.threadName(blocks.allocThread[b])],
      ['Freed', blocks.freeEvt[b] === NONE ? 'never (live at the end of the trace)' : this.positionNode(blocks.freeEvt[b])],
      ['Freeing thread', blocks.freeThread[b] === 0xFFFF ? '' : this.ctx.threadName(blocks.freeThread[b])],
      ['Notes', flags.join(', ')],
    ]));
    const actions = element('div', '', 'actions');
    if (blocks.allocEvt[b] !== NONE) actions.append(button('Jump to allocation', () => this.ctx.seek(blocks.allocEvt[b])));
    if (blocks.freeEvt[b] !== NONE) actions.append(button('Jump to free', () => this.ctx.seek(blocks.freeEvt[b])),
      button('Just before the free', () => this.ctx.seek(blocks.freeEvt[b] - 1)));
    nodes.push(actions);
    const chain = t.reallocChain(b);
    if (chain.length > 1) {
      const wrap = element('div', '', 'chain');
      wrap.append(element('h4', `Realloc chain (${chain.length})`));
      for (const x of chain) {
        const btn = button(`${hex(blocks.addr[x])}  ${bytes(blocks.size[x])}${x === b ? '  ◀' : ''}`, () => this.ctx.select({ kind: 'block', b: x }, true));
        wrap.append(btn);
      }
      nodes.push(wrap);
    }
    const history = t.addressHistory(blocks.addr[b]).filter(x => x !== b);
    if (history.length) {
      const wrap = element('details', '', 'history');
      wrap.append(element('summary', `Other blocks at this address (${history.length})`));
      for (const x of history.slice(0, 200))
        wrap.append(button(`${evtLabel(blocks.allocEvt[x])} → ${evtLabel(blocks.freeEvt[x])}  ${bytes(blocks.size[x])}`,
          () => this.ctx.select({ kind: 'block', b: x }, true)));
      nodes.push(wrap);
    }
    nodes.push(this.stackList('Allocation stack', blocks.allocStack[b]));
    if (blocks.freeEvt[b] !== NONE) nodes.push(this.stackList('Free stack', blocks.freeStack[b]));
    this.root.replaceChildren(...nodes);
  }

  showRegion(r) {
    const { regions, spans } = this.ctx.data, t = this.ctx.time;
    const i = this.ctx.current();
    const nodes = [element('h3', this.ctx.regionName(r))];
    nodes.push(facts([
      ['Kind', REGION_KIND[regions.kind[r]] ?? regions.kind[r]],
      ['Range', `${hex(regions.base[r])} – ${hex(regions.base[r] + regions.size[r])}`],
      ['Size', `${regions.size[r].toLocaleString()} B (${bytes(regions.size[r])})`],
      ['Created', regions.createEvt[r] === NONE ? 'before the trace' : this.positionNode(regions.createEvt[r])],
      ['Released', regions.releaseEvt[r] === NONE ? 'never' : this.positionNode(regions.releaseEvt[r])],
      ['Notes', [regions.flags[r] & 1 ? 'existed before the recording (inferred)' : '', regions.flags[r] & 2 ? 'grown' : ''].filter(Boolean).join(', ')],
    ]));
    const actions = element('div', '', 'actions');
    if (regions.createEvt[r] !== NONE) actions.append(button('Jump to creation', () => this.ctx.seek(regions.createEvt[r])));
    if (regions.releaseEvt[r] !== NONE) actions.append(button('Jump to release', () => this.ctx.seek(regions.releaseEvt[r])));
    nodes.push(actions);
    const live = t.spansAt(r, i);
    if (live.length) {
      const table = element('table', '', 'spans');
      table.append(Object.assign(element('tr'), { innerHTML: '<th>Range</th><th>State</th><th>Protect</th>' }));
      for (const s of live.slice(0, 300)) {
        const tr = element('tr');
        tr.append(element('td', `${hex(spans.start[s])} +${bytes(spans.end[s] - spans.start[s])}`),
          element('td', spans.state[s] === 2 ? 'committed' : 'reserved'), element('td', protectName(spans.protect[s])));
        table.append(tr);
      }
      const wrap = element('div'); wrap.append(element('h4', 'Pages at the current event'), table);
      nodes.push(wrap);
    }
    if (regions.createStack[r] !== NONE) nodes.push(this.stackList('Creating stack', regions.createStack[r]));
    if (regions.releaseStack[r] !== NONE) nodes.push(this.stackList('Releasing stack', regions.releaseStack[r]));
    this.root.replaceChildren(...nodes);
  }

  showSpan(s) {
    const { spans } = this.ctx.data;
    const r = spans.region[s];
    this.showRegion(r);
    this.root.prepend(element('p', `Page range ${hex(spans.start[s])} – ${hex(spans.end[s])}: ${spans.state[s] === 2 ? 'committed' : 'reserved'}, ${protectName(spans.protect[s])}, since ${evtLabel(spans.startEvt[s])}`, 'badge'));
  }

  showBlocks(ids, title) {
    const { blocks } = this.ctx.data;
    const total = ids.reduce((sum, b) => sum + blocks.size[b], 0);
    const nodes = [element('h3', title), element('p', `${ids.length.toLocaleString()} blocks, ${bytes(total)}`, 'muted')];
    const list = element('div', '', 'results');
    for (const b of ids.slice(0, 300))
      list.append(button(`${hex(blocks.addr[b])}  ${bytes(blocks.size[b])}  ${evtLabel(blocks.allocEvt[b])}`, () => this.ctx.select({ kind: 'block', b }, true)));
    nodes.push(list);
    if (ids.length) nodes.push(this.stackList('Allocation stack (first block)', blocks.allocStack[ids[0]]));
    this.root.replaceChildren(...nodes);
  }
}

// One-line description of an event (footer / tooltip).
export function describeEvent(i, ctx) {
  const { events } = ctx.data;
  if (i < 0 || i >= events.count) return 'Start of trace';
  const kind = EVENT_KIND[events.kind[i]] ?? `kind ${events.kind[i]}`;
  const parts = [`${evtLabel(i)} ${kind}`];
  const k = events.kind[i];
  if (k <= 8) {
    if (events.addr[i]) parts.push(hex(events.addr[i]));
    if (events.size[i]) parts.push(bytes(events.size[i]));
    if (events.aux[i] !== NONE) parts.push(ctx.heapName(events.aux[i]));
  } else if (k <= 22) {
    parts.push(`${hex(events.addr[i])} +${bytes(events.size[i])}`);
    if (k !== 19 && k !== 22 && k !== 18 && events.aux[i]) parts.push(protectName(events.aux[i]));
  } else if (k === 32 || k === 33) {
    parts.push(ctx.data.manifest.modules[events.id[i]]?.name ?? '');
  } else if (k === 36) {
    parts.push(ctx.data.manifest.markers[events.id[i]]?.text ?? '');
  } else if (k === 37) {
    parts.push(`syscall from ${hex(events.addr[i])}`);
  }
  parts.push(ctx.threadName(events.thread[i]));
  if (events.stack[i] !== NONE) parts.push(`@ ${ctx.stacks.siteText(events.stack[i])}`);
  return parts.filter(Boolean).join('  ');
}
