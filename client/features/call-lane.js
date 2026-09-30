// A timeline lane with the rate of calls the beam filter shows, colored by the busiest thread of
// each column. Makes call bursts findable before scrubbing to them.
export function install(app) {
  const svc = app.services.calls;
  let prefix = null, key = '';

  // Per-event prefix sums of accepted calls, total and for the busiest threads.
  function build() {
    const k = svc.filterKey();
    if (!svc.model || key === k) return;
    key = k;
    const n = app.data.events.count, c = svc.calls, accept = svc.acceptor();
    const perThread = new Map();
    for (let i = 0; i < c.count; i++) if (accept(i)) perThread.set(c.thread[i], (perThread.get(c.thread[i]) ?? 0) + 1);
    const top = [...perThread].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([t]) => t);
    const slot = new Map(top.map((t, s) => [t, s]));
    const total = new Float64Array(n + 2), threads = top.map(() => new Float64Array(n + 2));
    for (let i = 0; i < c.count; i++) {
      if (!accept(i)) continue;
      const e = Math.min(n, c.startEvt[i]) + 1; // bucket = the event the call precedes
      total[e]++;
      const s = slot.get(c.thread[i]);
      if (s !== undefined) threads[s][e]++;
    }
    for (let e = 1; e < total.length; e++) {
      total[e] += total[e - 1];
      for (const a of threads) a[e] += a[e - 1];
    }
    prefix = { total, threads, top };
    app.timeline.draw();
  }

  app.timeline.addLane({
    height: 10,
    draw(ctx, { top, height, view, columns }) {
      if (!prefix) return;
      const span = Math.max(1, view[1] - view[0]), counts = new Float64Array(columns), who = new Int16Array(columns).fill(-1);
      let max = 0;
      for (let col = 0; col < columns; col++) {
        const lo = Math.max(0, Math.floor(view[0] + col / columns * span)), hi = Math.min(prefix.total.length - 2, Math.floor(view[0] + (col + 1) / columns * span));
        const count = prefix.total[hi + 1] - prefix.total[lo];
        counts[col] = count; max = Math.max(max, count);
        let best = 0;
        prefix.threads.forEach((a, s) => { const v = a[hi + 1] - a[lo]; if (v > best) { best = v; who[col] = s; } });
      }
      if (!max) return;
      for (let col = 0; col < columns; col++) {
        if (!counts[col]) continue;
        const f = Math.log2(1 + counts[col]) / Math.log2(1 + max);
        ctx.globalAlpha = 0.35 + 0.65 * f;
        ctx.fillStyle = who[col] >= 0 ? `#${svc.threadColor(prefix.top[who[col]]).getHexString()}` : '#9aa7b8';
        ctx.fillRect(col, top + height * (1 - f), 1, Math.max(1, height * f));
      }
    },
  });

  app.on('open', () => { prefix = null; key = ''; });
  app.on('calls', build);
  app.on('call-filter', build);
  app.on('highlight', () => { if (svc.filter.touching === 'highlighted') build(); });
  app.on('select', () => { if (svc.filter.touching === 'selection') build(); });
  app.on('theme', () => app.timeline.draw());
}
