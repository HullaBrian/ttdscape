// Canvas timeline scrubber: live heap bytes and committed bytes over the event axis, an event
// density strip, and markers. Drag to scrub, wheel to zoom around the pointer, double-click resets.
// Features add lanes (thin tracks above the density strip) with addLane.
import { bytes } from './format.js';

const CATEGORY_COLORS = { heap: '#ed83e7', vm: '#59dbf0', other: '#f2c46d' };

export function pixelToEvent(x, width, view) {
  const t = Math.min(1, Math.max(0, x / Math.max(1, width)));
  return Math.round(view[0] + t * (view[1] - view[0]));
}

export function eventToPixel(i, width, view) {
  return (i - view[0]) / Math.max(1, view[1] - view[0]) * width;
}

// Per-column max of values[] over [view0, view1] into 'columns' buckets.
export function columnMax(values, view, columns) {
  const out = new Float64Array(columns);
  const span = Math.max(1, view[1] - view[0]);
  for (let c = 0; c < columns; c++) {
    const lo = Math.max(0, Math.floor(view[0] + c / columns * span));
    const hi = Math.min(values.length - 1, Math.floor(view[0] + (c + 1) / columns * span));
    let m = lo <= hi ? values[lo] : 0;
    for (let i = lo + 1; i <= hi; i++) if (values[i] > m) m = values[i];
    out[c] = m;
  }
  return out;
}

export class Timeline {
  constructor(container, { onSeek, onHover }) {
    this.container = container;
    this.onSeek = onSeek; this.onHover = onHover;
    this.canvas = document.createElement('canvas');
    this.canvas.setAttribute('aria-label', 'Timeline: drag to move through the trace, wheel to zoom');
    this.canvas.tabIndex = 0;
    container.append(this.canvas);
    this.ctx = this.canvas.getContext('2d');
    this.current = 0;
    this.view = [0, 1];
    this.dragging = false;
    this.lanes = [];
    this.canvas.addEventListener('pointerdown', e => {
      this.dragging = true; this.canvas.setPointerCapture(e.pointerId); this.seekTo(e);
    });
    this.canvas.addEventListener('pointermove', e => {
      if (this.dragging) this.seekTo(e);
      else this.hover(e);
    });
    this.canvas.addEventListener('pointerup', e => { this.dragging = false; this.canvas.releasePointerCapture(e.pointerId); this.onSeek?.(this.current, true); });
    this.canvas.addEventListener('pointerleave', () => { this.hoverX = null; this.onHover?.(null); this.draw(); });
    this.canvas.addEventListener('wheel', e => { e.preventDefault(); this.zoom(e); }, { passive: false });
    this.canvas.addEventListener('dblclick', () => { this.view = [0, Math.max(1, this.count - 1)]; this.draw(); });
    new ResizeObserver(() => this.resize()).observe(container);
  }

  setData({ time, events, markers, modules }) {
    this.time = time;
    this.events = events;
    this.count = events.count;
    this.markers = markers ?? [];
    this.moduleEvents = (modules ?? []).map(m => m.loadEvt).filter(e => e !== null && e !== undefined);
    this.view = [0, Math.max(1, this.count - 1)];
    this.buildDensity();
    this.resize();
  }

  // lane: { height, draw(ctx, { top, height, width, view, columns, count }) }.
  addLane(lane) { this.lanes.push(lane); this.draw(); }

  buildDensity() {
    const { kind } = this.events;
    this.category = new Uint8Array(this.count);
    for (let i = 0; i < this.count; i++) this.category[i] = kind[i] <= 8 ? 0 : kind[i] <= 22 ? 1 : 2;
  }

  resize() {
    const rect = this.container.getBoundingClientRect();
    const dpr = Math.min(devicePixelRatio, 2);
    this.width = Math.max(10, rect.width); this.height = Math.max(40, rect.height);
    this.canvas.width = Math.round(this.width * dpr); this.canvas.height = Math.round(this.height * dpr);
    this.canvas.style.width = `${this.width}px`; this.canvas.style.height = `${this.height}px`;
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.draw();
  }

  setCurrent(i) {
    this.current = i;
    // Keep the playhead visible when zoomed.
    if (i < this.view[0] || i > this.view[1]) {
      const span = this.view[1] - this.view[0];
      this.view = [Math.max(0, i - span / 2), Math.min(this.count - 1, i + span / 2)];
    }
    this.draw();
  }

  eventAt(e) {
    const rect = this.canvas.getBoundingClientRect();
    return pixelToEvent(e.clientX - rect.left, this.width, this.view);
  }

  seekTo(e) {
    if (!this.count) return;
    this.current = Math.min(this.count - 1, Math.max(0, this.eventAt(e)));
    this.draw();
    this.onSeek?.(this.current, false);
  }

  hover(e) {
    if (!this.count) return;
    const rect = this.canvas.getBoundingClientRect();
    this.hoverX = e.clientX - rect.left;
    const i = Math.min(this.count - 1, Math.max(0, this.eventAt(e)));
    this.onHover?.(i, e);
    this.draw();
  }

  zoom(e) {
    if (!this.count) return;
    const anchor = this.eventAt(e);
    const factor = e.deltaY > 0 ? 1.25 : 0.8;
    const span = Math.max(20, (this.view[1] - this.view[0]) * factor);
    const t = (anchor - this.view[0]) / Math.max(1, this.view[1] - this.view[0]);
    let v0 = anchor - t * span, v1 = v0 + span;
    if (v0 < 0) { v1 -= v0; v0 = 0; }
    if (v1 > this.count - 1) { v0 -= v1 - (this.count - 1); v1 = this.count - 1; }
    this.view = [Math.max(0, v0), v1];
    this.draw();
  }

  draw() {
    const { ctx, width: w, height: h } = this;
    if (!ctx) return;
    ctx.clearRect(0, 0, w, h);
    const style = getComputedStyle(document.documentElement);
    ctx.fillStyle = style.getPropertyValue('--timeline-bg').trim() || '#0b0b20';
    ctx.fillRect(0, 0, w, h);
    if (!this.count || !this.time) {
      ctx.fillStyle = '#8b86a8'; ctx.font = '11px ui-monospace, monospace';
      ctx.fillText('Open a trace analysis to see its timeline.', 12, h / 2 + 4);
      return;
    }
    const columns = Math.max(1, Math.floor(w));
    const laneH = this.lanes.reduce((s, l) => s + l.height + 2, 0);
    const chartTop = 16, chartBottom = h - 14 - laneH, chartH = chartBottom - chartTop;

    const drawArea = (values, color, alpha) => {
      const cols = columnMax(values, this.view, columns);
      let max = 0;
      for (const v of cols) max = Math.max(max, v);
      if (max <= 0) return 0;
      ctx.beginPath(); ctx.moveTo(0, chartBottom);
      for (let c = 0; c < columns; c++) ctx.lineTo(c, chartBottom - cols[c] / max * chartH);
      ctx.lineTo(columns, chartBottom); ctx.closePath();
      ctx.globalAlpha = alpha; ctx.fillStyle = color; ctx.fill();
      ctx.globalAlpha = 1; ctx.strokeStyle = color; ctx.lineWidth = 1;
      ctx.beginPath();
      for (let c = 0; c < columns; c++) { const y = chartBottom - cols[c] / max * chartH; if (c) ctx.lineTo(c, y); else ctx.moveTo(c, y); }
      ctx.stroke();
      return max;
    };
    const commitMax = drawArea(this.time.committed, '#59dbf0', 0.12);
    const heapMax = drawArea(this.time.heapLive, '#ed83e7', 0.28);

    // Event density strip, colored by the dominant category of each column.
    const span = Math.max(1, this.view[1] - this.view[0]);
    for (let c = 0; c < columns; c++) {
      const lo = Math.floor(this.view[0] + c / columns * span), hi = Math.floor(this.view[0] + (c + 1) / columns * span);
      const counts = [0, 0, 0];
      for (let i = Math.max(0, lo); i <= Math.min(this.count - 1, hi); i++) counts[this.category[i]]++;
      const total = counts[0] + counts[1] + counts[2];
      if (!total) continue;
      const cat = counts[1] >= counts[0] && counts[1] >= counts[2] ? 'vm' : counts[0] >= counts[2] ? 'heap' : 'other';
      ctx.globalAlpha = Math.min(1, 0.35 + Math.log2(1 + total) / 8);
      ctx.fillStyle = CATEGORY_COLORS[cat];
      ctx.fillRect(c, h - 10, 1, 8);
    }
    ctx.globalAlpha = 1;

    let laneTop = chartBottom + 2;
    for (const lane of this.lanes) {
      ctx.save();
      lane.draw(ctx, { top: laneTop, height: lane.height, width: w, view: this.view, columns, count: this.count });
      ctx.restore();
      laneTop += lane.height + 2;
    }

    // Markers (TTDSCAPE:/OutputDebugString) and module loads.
    ctx.font = '10px ui-monospace, monospace';
    for (const e of this.moduleEvents) {
      if (e < this.view[0] || e > this.view[1]) continue;
      const x = eventToPixel(e, w, this.view);
      ctx.fillStyle = '#f2c46d55'; ctx.fillRect(x, chartTop, 1, 4);
    }
    let lastLabelX = -Infinity;
    for (const m of this.markers) {
      if (m.evt === null || m.evt < this.view[0] || m.evt > this.view[1]) continue;
      const x = eventToPixel(m.evt, w, this.view);
      ctx.fillStyle = '#f2c46d'; ctx.fillRect(x, chartTop - 4, 1, chartH + 4);
      if (x - lastLabelX > 90) {
        ctx.fillText(m.text.replace(/^TTDSCAPE:/, '').slice(0, 22), x + 3, chartTop + 6);
        lastLabelX = x;
      }
    }

    // Playhead and hover line.
    const px = eventToPixel(this.current, w, this.view);
    ctx.fillStyle = '#ffffff'; ctx.fillRect(px - 1, 0, 2, h);
    if (this.hoverX !== null && this.hoverX !== undefined) { ctx.fillStyle = '#ffffff44'; ctx.fillRect(this.hoverX, 0, 1, h); }

    // Legend.
    ctx.fillStyle = '#ed83e7';
    ctx.fillText(`heap live ${bytes(this.time.heapLive[this.current] ?? 0)} (max ${bytes(heapMax)})`, 8, 11);
    ctx.fillStyle = '#59dbf0';
    ctx.fillText(`committed ${bytes(this.time.committed[this.current] ?? 0)} (max ${bytes(commitMax)})`, 250, 11);
    ctx.fillStyle = '#b2a8cc';
    const zoomed = this.view[0] > 0 || this.view[1] < this.count - 1;
    ctx.fillText(`${zoomed ? `view #${Math.round(this.view[0]).toLocaleString()}–#${Math.round(this.view[1]).toLocaleString()}  ` : ''}${this.count.toLocaleString()} events`, Math.max(480, w - 300), 11);
  }
}
