// Side rails made of stacked panels, each panel holding tabs. Features add tabs with
// rail.addTab({ id, title, panel, order }); the panel's element is created here and handed back.
import { element } from '../inspector.js';
import { load, save } from './prefs.js';

export class TabPanel {
  constructor(host, { id, grow = 1 }) {
    this.id = id;
    this.root = element('section', '', 'panel tabbed');
    this.root.dataset.panel = id; // e.g. right.calls (styles can single a panel out)
    this.root.style.flexGrow = String(grow);
    this.nav = element('nav', '', 'tabs');
    this.nav.setAttribute('role', 'tablist');
    this.body = element('div', '', 'tab-body');
    this.root.append(this.nav, this.body);
    host.append(this.root);
    this.tabs = [];
    this.active = null;
  }

  addTab({ id, title, order = 100, onShow = null }) {
    const button = element('button', title, 'tab');
    button.setAttribute('role', 'tab');
    button.dataset.tab = id;
    const body = element('div', '', 'tab-content');
    body.id = `tab-${id}`;
    body.hidden = true;
    const tab = { id, title, order, button, body, onShow };
    this.tabs.push(tab);
    this.tabs.sort((a, b) => a.order - b.order);
    this.nav.replaceChildren(...this.tabs.map(t => t.button));
    this.body.append(body);
    button.addEventListener('click', () => this.show(id));
    const remembered = load(`tab.${this.id}`);
    if (!this.active || remembered === id) this.show(remembered === id ? id : this.tabs[0].id);
    return body;
  }

  show(id) {
    const tab = this.tabs.find(t => t.id === id);
    if (!tab) return;
    for (const t of this.tabs) {
      t.body.hidden = t !== tab;
      t.button.classList.toggle('active', t === tab);
      t.button.setAttribute('aria-selected', String(t === tab));
    }
    this.active = tab;
    save(`tab.${this.id}`, id);
    tab.onShow?.();
  }

  isShown(id) { return this.active?.id === id; }
}

// A rail is a column of TabPanels; its width can be dragged from its inner edge.
export class Rail {
  constructor(root, { side, defaultWidth }) {
    this.root = root;
    this.side = side;
    this.panels = new Map();
    const handle = element('div', '', 'rail-handle');
    handle.title = 'Drag to resize';
    root.append(handle);
    const width = Number(load(`rail.${side}.width`)) || defaultWidth;
    this.setWidth(width);
    handle.addEventListener('pointerdown', e => {
      handle.setPointerCapture(e.pointerId);
      const move = ev => this.setWidth(side === 'left' ? ev.clientX - root.getBoundingClientRect().left : root.getBoundingClientRect().right - ev.clientX);
      const up = () => { handle.removeEventListener('pointermove', move); handle.removeEventListener('pointerup', up); save(`rail.${side}.width`, this.width); };
      handle.addEventListener('pointermove', move);
      handle.addEventListener('pointerup', up);
    });
  }

  setWidth(w) {
    this.width = Math.round(Math.min(Math.max(220, w), innerWidth * 0.45));
    this.root.style.width = `${this.width}px`;
  }

  panel(id, options = {}) {
    let p = this.panels.get(id);
    if (!p) this.panels.set(id, p = new TabPanel(this.root, { id: `${this.side}.${id}`, ...options }));
    return p;
  }
}
