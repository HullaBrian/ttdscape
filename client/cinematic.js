// A slow cinematic tour of the atlas: a closed path that starts wide, glides past the most prominent
// region boxes in order around the scene, and comes back. Pure: it returns camera positions and
// look-at targets (arrays of [x, y, z]); the atlas turns them into smooth curves.
//
// Stops are the largest regions, spread out (each next stop is the largest region not already close
// to a chosen one), ordered by angle around the scene's centre so the camera circles once. The
// camera stands outside each stop: out from the centre, above it, at a distance scaled to its box.

export function cinematicTour(items, { stops = 10 } = {}) {
  const boxes = items.filter(item => item.position && item.size);
  if (!boxes.length) return null;
  const lo = [0, 1, 2].map(k => Math.min(...boxes.map(b => b.position[k] - b.size[k] / 2)));
  const hi = [0, 1, 2].map(k => Math.max(...boxes.map(b => b.position[k] + b.size[k] / 2)));
  const center = [0, 1, 2].map(k => (lo[k] + hi[k]) / 2);
  const extent = Math.max(20, Math.hypot(hi[0] - lo[0], hi[1] - lo[1], hi[2] - lo[2]));

  // Prominent and spread out.
  const bySize = [...boxes].sort((a, b) => (b.displayBytes ?? b.size[0]) - (a.displayBytes ?? a.size[0]) || a.size[0] - b.size[0]);
  const chosen = [];
  const minApart = extent / (stops * 1.5);
  for (const b of bySize) {
    if (chosen.length >= stops) break;
    if (chosen.some(c => dist(c.position, b.position) < minApart + (c.size[0] + b.size[0]) / 2)) continue;
    chosen.push(b);
  }
  for (const b of bySize) { if (chosen.length >= Math.min(stops, 3)) break; if (!chosen.includes(b)) chosen.push(b); }

  const angle = b => Math.atan2(b.position[2] - center[2], b.position[0] - center[0]);
  chosen.sort((a, b) => angle(a) - angle(b));

  // The establishing shot: high and wide, on the side of the first stop.
  const wideDistance = extent * 0.95;
  const a0 = chosen.length ? angle(chosen[0]) - 0.6 : 0;
  const cameras = [[center[0] + Math.cos(a0) * wideDistance, center[1] + wideDistance * 0.55, center[2] + Math.sin(a0) * wideDistance]];
  const targets = [[...center]];
  for (const b of chosen) {
    const side = Math.max(...b.size);
    const out = [b.position[0] - center[0], 0, b.position[2] - center[2]];
    const len = Math.hypot(out[0], out[2]);
    // Regions at the centre are approached from their own angle in the circle.
    const dir = len > 1e-6 ? [out[0] / len, 0, out[2] / len] : [Math.cos(angle(b)), 0, Math.sin(angle(b))];
    // Step back (and up) until the camera stands clear of every box, neighbours included.
    let distance = side * 1.9 + 18, camera;
    for (let tries = 0; tries < 12; tries++, distance *= 1.25) {
      camera = [b.position[0] + dir[0] * distance, b.position[1] + side * 0.7 + 10 + distance * 0.15 * tries, b.position[2] + dir[2] * distance];
      if (!boxes.some(x => inside(camera, x))) break;
    }
    cameras.push(camera);
    targets.push([...b.position]);
  }
  return { cameras, targets, center, extent, regions: chosen.map(b => b.r) };
}

// An aerial orbit: a slow circle above the atlas, looking at its centre, far enough that every
// region box stays in frame all the way round. The camera's field of view (vertical, degrees) and
// aspect decide the distance; `visible` / `visibleX` are the fractions of the frame's half-height /
// half-width, around its centre, left for the scene (the rest is under the timeline or a panel).
// points: cameras on the circle (the atlas smooths them).
export function cinematicOrbit(items, { fov = 55, aspect = 16 / 9, visible = 1, visibleX = 1, elevation = 38, points = 48, margin = 1.06 } = {}) {
  const boxes = items.filter(item => item.position && item.size);
  if (!boxes.length) return null;
  const lo = [0, 1, 2].map(k => Math.min(...boxes.map(b => b.position[k] - b.size[k] / 2)));
  const hi = [0, 1, 2].map(k => Math.max(...boxes.map(b => b.position[k] + b.size[k] / 2)));
  const center = [0, 1, 2].map(k => (lo[k] + hi[k]) / 2);
  // Every corner lies within this sphere; a sphere in view from any direction keeps all boxes in view.
  const radius = Math.max(10, Math.hypot(hi[0] - lo[0], hi[1] - lo[1], hi[2] - lo[2]) / 2);
  const tan = Math.tan(fov * Math.PI / 360);
  const tanV = tan * Math.min(1, Math.max(0.2, visible)), tanH = tan * aspect * Math.min(1, Math.max(0.2, visibleX));
  const half = Math.min(Math.atan(tanV), Math.atan(tanH)); // the narrower half-angle
  const up = elevation * Math.PI / 180;
  const at = (a, d) => [center[0] + Math.cos(a) * Math.cos(up) * d, center[1] + Math.sin(up) * d, center[2] + Math.sin(a) * Math.cos(up) * d];
  const corners = [];
  for (const b of boxes) for (let c = 0; c < 8; c++)
    corners.push([0, 1, 2].map(k => b.position[k] + ((c >> k) & 1 ? 0.5 : -0.5) * b.size[k]));
  // The closest distance from direction a with every corner in frame (a boxy scene fits much closer
  // than its bounding sphere, which is only the upper bound).
  const fits = (a, d) => {
    const cam = at(a, d), f = center.map((v, k) => v - cam[k]), fl = Math.hypot(...f), fw = f.map(v => v / fl);
    const rl = Math.hypot(fw[2], fw[0]), rt = [fw[2] / rl, 0, -fw[0] / rl];
    const upv = [rt[1] * fw[2] - rt[2] * fw[1], rt[2] * fw[0] - rt[0] * fw[2], rt[0] * fw[1] - rt[1] * fw[0]];
    return corners.every(p => {
      const q = [p[0] - cam[0], p[1] - cam[1], p[2] - cam[2]];
      const z = q[0] * fw[0] + q[1] * fw[1] + q[2] * fw[2];
      if (z <= 0) return false;
      const x = q[0] * rt[0] + q[1] * rt[1] + q[2] * rt[2], y = q[0] * upv[0] + q[1] * upv[1] + q[2] * upv[2];
      return Math.abs(x) <= tanH * z && Math.abs(y) <= tanV * z;
    });
  };
  const sphere = radius / Math.sin(half);
  const fitted = [];
  for (let k = 0; k < points; k++) {
    const a = k / points * Math.PI * 2;
    let lo = 0, hi = sphere;
    for (let i = 0; i < 30; i++) { const mid = (lo + hi) / 2; if (fits(a, mid)) hi = mid; else lo = mid; }
    fitted.push(hi);
  }
  // The orbit breathes: each angle at its own fitted distance, never below its neighbours' (the path
  // between samples stays safe), then lightly smoothed so the motion stays calm.
  const n = points, wrap = k => (k + n) % n;
  const safe = fitted.map((_, k) => Math.max(fitted[wrap(k - 1)], fitted[k], fitted[wrap(k + 1)]));
  const distances = safe.map((d, k) => Math.max(d, (safe[wrap(k - 2)] + safe[wrap(k - 1)] + d + safe[wrap(k + 1)] + safe[wrap(k + 2)]) / 5) * margin);
  const cameras = [], targets = [];
  for (let k = 0; k < points; k++) {
    cameras.push(at(k / points * Math.PI * 2, distances[k]));
    targets.push([...center]);
  }
  return { cameras, targets, center, radius, distance: Math.max(...distances), distances };
}

// Inside a box, with a small margin so the camera is not on its frame.
function inside(p, box, margin = 2) {
  return [0, 1, 2].every(k => Math.abs(p[k] - box.position[k]) < box.size[k] / 2 + margin);
}

function dist(a, b) {
  return Math.hypot(a[0] - b[0], a[1] - b[1], a[2] - b[2]);
}
