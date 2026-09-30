// Calls into module exports on the event axis, and which of them are drawn as beams at a time T.
//
// Time: the state after event i is at time i; a call recorded between events e-1 and e happens at
// e - 1 + frac. A beam travels from caller to callee in W/2, stays lit while the call is active,
// and fades over W/2 after the call returns (or after it arrives, whichever is later).
import { NONE } from './format.js';

export const CALL = { Returned: 1, Unwound: 2, Tail: 4, SameModule: 8 };

// Phase of a beam at time T: null when not drawn, else { progress 0..1 along the curve,
// alpha 0..1, held: arrived and the call is still active }.
export function beamPhase(t0, t1, T, W) {
  if (T < t0) return null;
  const travel = W / 2, fade = W / 2;
  const release = Math.max(t1, t0 + travel);
  if (T >= release + fade) return null;
  const progress = travel > 0 ? Math.min(1, (T - t0) / travel) : 1;
  if (T < release) return { progress, alpha: progress < 1 ? 1 : 0.55, held: progress >= 1 };
  return { progress, alpha: 0.55 * (1 - (T - release) / fade), held: false };
}

// Pacing by calls: a continuous index k into sorted start times <-> time on the event axis.
export function timeAtIndex(times, k) {
  const n = times.length;
  if (!n) return 0;
  if (k <= 0) return times[0];
  if (k >= n - 1) return times[n - 1];
  const lo = Math.floor(k);
  return times[lo] + (k - lo) * (times[lo + 1] - times[lo]);
}

export function indexAtTime(times, T) {
  const n = times.length;
  if (!n) return 0;
  let lo = 0, hi = n;
  while (lo < hi) { const mid = (lo + hi) >>> 1; if (times[mid] <= T) lo = mid + 1; else hi = mid; }
  if (lo === 0) return 0;
  if (lo === n) return n - 1;
  const a = times[lo - 1], b = times[lo];
  return lo - 1 + (b > a ? (T - a) / (b - a) : 0);
}

export class CallModel {
  constructor(calls) {
    this.calls = calls;
    const n = calls.count;
    this.t0 = new Float64Array(n);
    this.t1 = new Float64Array(n);
    for (let i = 0; i < n; i++) {
      this.t0[i] = calls.startEvt[i] - 1 + calls.startFrac[i];
      // Unwound frames have no known end: they end where they began. Calls still active at the
      // end of the trace never end.
      this.t1[i] = calls.endEvt[i] !== NONE ? calls.endEvt[i] - 1 + calls.endFrac[i]
        : calls.flags[i] & CALL.Unwound ? this.t0[i] : Infinity;
    }
    this.longCache = { W: NaN, list: null };
  }

  // Calls whose beam can outlive the [t0, t0 + W] window: active for longer than the travel time.
  longCalls(W) {
    if (this.longCache.W === W) return this.longCache.list;
    const out = [];
    for (let i = 0; i < this.t0.length; i++) if (this.t1[i] > this.t0[i] + W / 2) out.push(i);
    this.longCache = { W, list: Uint32Array.from(out) };
    return this.longCache.list;
  }

  // Calls in progress at T (t0 <= T < t1), by start time. Calls longer than `span` come from a
  // cached list; shorter ones can only have started in (T - span, T], so only those are scanned.
  activeAt(T, span) {
    if (this.activeCache?.span !== span) {
      const long = [];
      for (let i = 0; i < this.t0.length; i++) if (this.t1[i] - this.t0[i] > span) long.push(i);
      this.activeCache = { span, long: Uint32Array.from(long) };
    }
    const out = [];
    for (const i of this.activeCache.long) if (this.t0[i] <= T && this.t1[i] > T) out.push(i);
    for (let i = this.upper(T) - 1; i >= 0 && this.t0[i] > T - span; i--)
      if (this.t1[i] - this.t0[i] <= span && this.t1[i] > T) out.push(i);
    return out.sort((a, b) => this.t0[a] - this.t0[b] || a - b);
  }

  // First index with t0 > value.
  upper(value) {
    let lo = 0, hi = this.t0.length;
    while (lo < hi) { const mid = (lo + hi) >>> 1; if (this.t0[mid] <= value) lo = mid + 1; else hi = mid; }
    return lo;
  }

  // Beams at time T: [{ i, count, phase }], newest first after the long-running calls. accept(i)
  // filters calls; key(i) merges calls into one beam (the newest is drawn, count says how many);
  // at most `budget` beams, scanning at most `scanLimit` calls.
  visible(T, W, { accept = () => true, key = null, budget = 3000, scanLimit = 500000 } = {}) {
    const out = [], byKey = key ? new Map() : null;
    let truncated = false;
    const add = (i, phase) => {
      if (!accept(i)) return true;
      if (byKey) {
        const k = key(i), beam = byKey.get(k);
        if (beam) { beam.count++; return true; }
        if (out.length >= budget) { truncated = true; return false; }
        const b = { i, count: 1, phase };
        byKey.set(k, b); out.push(b);
        return true;
      }
      if (out.length >= budget) { truncated = true; return false; }
      out.push({ i, count: 1, phase });
      return true;
    };
    const long = this.longCalls(W);
    const isLong = i => this.t1[i] > this.t0[i] + W / 2;
    // Long calls, newest first.
    for (let k = long.length - 1; k >= 0; k--) {
      const i = long[k];
      if (this.t0[i] > T) continue;
      const phase = beamPhase(this.t0[i], this.t1[i], T, W);
      if (phase && !add(i, phase)) break;
    }
    // Short calls can only be visible when they started in (T - W, T].
    const hi = this.upper(T), first = this.upper(T - W), lo = Math.max(first, hi - scanLimit);
    for (let i = hi - 1; i >= lo && !truncated; i--) {
      if (isLong(i)) continue;
      const phase = beamPhase(this.t0[i], this.t1[i], T, W);
      if (phase && !add(i, phase)) break;
    }
    return { beams: out, truncated: truncated || lo > first };
  }
}
