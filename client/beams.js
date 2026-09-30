// Call beams: a glowing head per call travelling along a curve from the caller's code to the
// called export, with a fading trail. Modelled on Heapscape's GoldenSignals (golden-signals.js), with
// a color per beam. Buffers are allocated once for `capacity` beams and rewritten in place.
import * as THREE from 'three';
import { LineSegments2 } from 'three/addons/lines/LineSegments2.js';
import { LineSegmentsGeometry } from 'three/addons/lines/LineSegmentsGeometry.js';
import { LineMaterial } from 'three/addons/lines/LineMaterial.js';
import { renderLayers, transparentSurface } from './rendering.js';

// Soft round glow (Heapscape themes.js signalPixels('glow')).
function glowTexture(size = 32) {
  const pixels = new Uint8Array(size * size * 4);
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    const u = (x + 0.5) / size, v = (y + 0.5) / size, r = Math.hypot(u - 0.5, v - 0.5);
    const i = (y * size + x) * 4;
    pixels[i] = pixels[i + 1] = pixels[i + 2] = 255;
    pixels[i + 3] = Math.round(Math.max(0, Math.exp(-r * r * 22) - 0.01) * 255);
  }
  const texture = new THREE.DataTexture(pixels, size, size);
  texture.needsUpdate = true;
  return texture;
}

// Cubic Bezier from start to end arcing above both (Heapscape spatial.js directReferenceRoute).
export function beamRoute(start, end, out = new Float32Array(12)) {
  const dx = end[0] - start[0], dy = end[1] - start[1], dz = end[2] - start[2];
  const distance = Math.hypot(dx, dy, dz);
  const rise = Math.max(2, Math.min(160, distance * 0.35));
  const height = Math.max(start[1], end[1]) + rise;
  out.set(start, 0);
  if (distance < 0.001) {
    out.set([start[0] + rise / 2, height, start[2]], 3);
    out.set([end[0] - rise / 2, height, end[2]], 6);
  } else {
    out.set([start[0] + dx * 0.25, height, start[2] + dz * 0.25], 3);
    out.set([end[0] - dx * 0.25, height, end[2] - dz * 0.25], 6);
  }
  out.set(end, 9);
  return out;
}

// A straight segment in the same cubic form: control points a third of the way from each end
// (memory beams: reads and writes between regions).
export function straightRoute(start, end, out = new Float32Array(12)) {
  out.set(start, 0);
  for (let k = 0; k < 3; k++) {
    out[3 + k] = start[k] + (end[k] - start[k]) / 3;
    out[6 + k] = start[k] + (end[k] - start[k]) * 2 / 3;
  }
  out.set(end, 9);
  return out;
}

export function bezierPoint(route, t, out, offset = 0) {
  const u = 1 - t, a = u * u * u, b = 3 * u * u * t, c = 3 * u * t * t, d = t * t * t;
  for (let k = 0; k < 3; k++) out[offset + k] = a * route[k] + b * route[3 + k] + c * route[6 + k] + d * route[9 + k];
  return out;
}

export class Beams {
  constructor({ capacity = 3000, segments = 12, tail = 0.3 } = {}) {
    this.capacity = capacity; this.segments = segments; this.tail = tail;
    this.group = new THREE.Group();
    this.headPositions = new Float32Array(capacity * 3);
    this.headColors = new Float32Array(capacity * 3);
    const heads = new THREE.BufferGeometry();
    heads.setAttribute('position', new THREE.BufferAttribute(this.headPositions, 3).setUsage(THREE.DynamicDrawUsage));
    heads.setAttribute('color', new THREE.BufferAttribute(this.headColors, 3).setUsage(THREE.DynamicDrawUsage));
    heads.setDrawRange(0, 0);
    this.heads = new THREE.Points(heads, new THREE.PointsMaterial({
      ...transparentSurface, size: 13, sizeAttenuation: false, map: glowTexture(), vertexColors: true,
      alphaTest: 0.01, blending: THREE.AdditiveBlending, toneMapped: false,
    }));
    this.trailPositions = new Float32Array(capacity * segments * 6);
    this.trailColors = new Float32Array(capacity * segments * 6);
    const trails = new LineSegmentsGeometry().setPositions(this.trailPositions).setColors(this.trailColors);
    trails.instanceCount = 0;
    this.trails = new LineSegments2(trails, new LineMaterial({
      ...transparentSurface, color: '#ffffff', vertexColors: true, linewidth: 2,
      blending: THREE.AdditiveBlending, toneMapped: false,
    }));
    for (const object of [this.heads, this.trails]) {
      object.frustumCulled = false; object.renderOrder = renderLayers.signals;
      this.group.add(object);
    }
    this.drawn = [];     // beams drawn last update, parallel to the heads
    this.point = new Float32Array(3);
  }

  setResolution(width, height) { this.trails.material.resolution.set(width, height); }

  // beams: [{ route: Float32Array(12), color: THREE.Color, phase: { progress, alpha, held }, count, ... }]
  update(beams) {
    const n = Math.min(beams.length, this.capacity), S = this.segments;
    const hp = this.headPositions, hc = this.headColors, tp = this.trailPositions, tc = this.trailColors;
    let seg = 0;
    for (let k = 0; k < n; k++) {
      const { route, color, phase, count } = beams[k];
      const boost = 1.5 * (1 + Math.min(1.5, Math.log2(count) * 0.3)) * phase.alpha;
      bezierPoint(route, phase.progress, hp, k * 3);
      const head = phase.held ? 0.45 : 1;
      hc[k * 3] = color.r * boost * head; hc[k * 3 + 1] = color.g * boost * head; hc[k * 3 + 2] = color.b * boost * head;
      // Trail: behind the head while travelling; the whole route, dimmer, while the call is held.
      const from = phase.progress, to = phase.held ? 0 : Math.max(0, phase.progress - this.tail);
      if (from <= to) continue;
      for (let s = 0; s < S; s++) {
        const o = seg * 6;
        bezierPoint(route, from + (to - from) * s / S, tp, o);
        bezierPoint(route, from + (to - from) * (s + 1) / S, tp, o + 3);
        for (let end = 0; end < 2; end++) {
          const f = (phase.held ? 0.55 - 0.25 * (s + end) / S : (1 - (s + end) / S) ** 1.5) * boost * 0.8;
          tc[o + end * 3] = color.r * f; tc[o + end * 3 + 1] = color.g * f; tc[o + end * 3 + 2] = color.b * f;
        }
        seg++;
      }
    }
    this.drawn = beams.slice(0, n);
    this.heads.geometry.setDrawRange(0, n);
    this.heads.geometry.attributes.position.needsUpdate = true;
    this.heads.geometry.attributes.color.needsUpdate = true;
    const g = this.trails.geometry;
    g.instanceCount = seg;
    g.attributes.instanceStart.data.needsUpdate = true;
    g.attributes.instanceColorStart.data.needsUpdate = true;
  }

  // The drawn beam whose head is nearest to a screen point (within radius px), or null.
  pick(camera, clientX, clientY, width, height, radius = 9) {
    let best = null, bestD = radius * radius;
    const v = new THREE.Vector3();
    for (let k = 0; k < this.drawn.length; k++) {
      v.fromArray(this.headPositions, k * 3).project(camera);
      if (v.z < -1 || v.z > 1) continue;
      const dx = (v.x + 1) * width / 2 - clientX, dy = (1 - v.y) * height / 2 - clientY, d = dx * dx + dy * dy;
      if (d < bestD) { bestD = d; best = this.drawn[k]; }
    }
    return best;
  }

  set visible(value) { this.group.visible = value; }
}
