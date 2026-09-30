// The 3D scene. Camera, orbit/flight controls, picking, labels and the render loop are adapted
// from Heapscape's Atlas (scene.js). Content is split into a static layer (region frames and labels,
// built once per analysis) and a dynamic layer (blocks, pages and gaps at the current event). Call
// beams live in their own group, updated in place every animation frame (onBeforeRender).
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { PointerLockControls } from 'three/addons/controls/PointerLockControls.js';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { getTheme } from './themes.js';
import { Beams } from './beams.js';
import { renderLayers, transparentSurface, labelOpacity, labelsOverlap } from './rendering.js';

const unitBox = new THREE.BoxGeometry(1, 1, 1);

export class Atlas {
  constructor(container, { onSelect, onHover, onFlight, onDeselect, onFlightSpeed, onBeforeRender }) {
    this.container = container;
    this.onBeforeRender = onBeforeRender;
    this.onSelect = onSelect; this.onHover = onHover; this.onDeselect = onDeselect; this.onFlightSpeed = onFlightSpeed;
    this.slowFlight = false;
    this.theme = getTheme();
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(this.theme.background);
    this.camera = new THREE.PerspectiveCamera(55, innerWidth / innerHeight, 0.1, 200000);
    this.camera.layers.enable(1);
    this.camera.position.set(400, 460, 760);
    this.renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: 'high-performance' });
    this.renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    this.renderer.setSize(innerWidth, innerHeight);
    this.renderer.domElement.tabIndex = 0;
    container.append(this.renderer.domElement);
    this.orbit = new OrbitControls(this.camera, this.renderer.domElement);
    this.orbit.enableDamping = true;
    this.orbit.dampingFactor = 0.08;
    this.flight = new PointerLockControls(this.camera, this.renderer.domElement);
    this.flight.addEventListener('lock', () => {
      this.renderer.domElement.focus({ preventScroll: true });
      this.orbit.enabled = false; this.lastHover = -Infinity; onFlight(true);
    });
    this.flight.addEventListener('unlock', () => {
      this.orbit.target.copy(this.camera.position).add(this.camera.getWorldDirection(new THREE.Vector3()).multiplyScalar(80));
      this.orbit.enabled = true; this.keys.clear(); onFlight(false);
    });
    this.scene.add(new THREE.AmbientLight('#c7dfee', 2.2));
    const sun = new THREE.DirectionalLight('#e3fff8', 2.6);
    sun.position.set(200, 600, 400); this.scene.add(sun);
    this.grid = new THREE.GridHelper(8000, 320, ...this.theme.grid);
    this.grid.position.y = -6; this.scene.add(this.grid);
    this.staticContent = new THREE.Group(); this.scene.add(this.staticContent);
    this.dynamicContent = new THREE.Group(); this.scene.add(this.dynamicContent);
    this.selection = new THREE.Group(); this.scene.add(this.selection);
    this.beams = new Beams(); this.scene.add(this.beams.group);
    // Reads and writes between regions (features/memory-beams.js): straight, and picked separately.
    this.memoryBeams = new Beams({ capacity: 2000, segments: 4 }); this.scene.add(this.memoryBeams.group);
    this.emphasisGroup = new THREE.Group(); this.scene.add(this.emphasisGroup);
    this.emphasis = { set: new Set(), dim: false };
    this.alertGroup = new THREE.Group(); this.scene.add(this.alertGroup);
    this.alerts = { set: new Set(), key: '' };
    this.beams.setResolution(innerWidth, innerHeight);
    this.memoryBeams.setResolution(innerWidth, innerHeight);
    this.keys = new Set(); this.speed = 130; this.pickables = []; this.lastHover = 0;
    this.labels = []; this.lastLabels = -Infinity; this.regionFrames = new Map();
    this.raycaster = new THREE.Raycaster();
    const canvas = this.renderer.domElement;
    canvas.addEventListener('pointerdown', e => { this.stopCinematic(); if (e.button === 0) this.down = [e.clientX, e.clientY]; });
    canvas.addEventListener('click', e => {
      if (e.button !== 0 || (!this.flight.isLocked && (!this.down || Math.hypot(e.clientX - this.down[0], e.clientY - this.down[1]) > 5))) return;
      const item = this.pick(e);
      if (item) this.onSelect(item); else this.onDeselect();
    });
    canvas.addEventListener('contextmenu', e => e.preventDefault());
    canvas.addEventListener('pointermove', e => {
      this.lastCursor = { clientX: e.clientX, clientY: e.clientY };
      if (this.flight.isLocked || performance.now() - this.lastHover < 90) return;
      this.lastHover = performance.now(); this.onHover(this.pick(e), e);
    });
    canvas.addEventListener('pointerleave', e => { if (!this.flight.isLocked) this.onHover(null, e); });
    canvas.addEventListener('wheel', e => {
      this.stopCinematic();
      if (this.flight.isLocked) this.speed = THREE.MathUtils.clamp(this.speed * (e.deltaY > 0 ? 0.8 : 1.25), 5, 40000);
    });
    addEventListener('keydown', e => this.handleKeyDown(e));
    addEventListener('keyup', e => this.handleKeyUp(e));
    addEventListener('blur', () => { this.keys.clear(); this.onFlightSpeed?.(this.flightSpeedMode()); });
    addEventListener('resize', () => {
      this.applyFraming(); // aspect and projection, around any screen space kept clear
      this.renderer.setSize(innerWidth, innerHeight);
      this.composer?.setSize(innerWidth, innerHeight);
      this.beams.setResolution(innerWidth, innerHeight);
      this.memoryBeams.setResolution(innerWidth, innerHeight);
    });
    this.clock = new THREE.Timer();
    this.setBloom(true);
    this.renderer.setAnimationLoop(() => this.frame());
  }

  // ---- input (from Heapscape) ----

  handleKeyDown(event) {
    // Camera keys (and Escape) hand the camera back from a cinematic tour; others (P: play) do not.
    if (this.cinematic && ['Escape', 'KeyW', 'KeyA', 'KeyS', 'KeyD', 'KeyQ', 'KeyE', 'KeyF', 'KeyG'].includes(event.code)) {
      this.stopCinematic();
      if (event.code === 'Escape') return;
    }
    if (event.code === 'Escape') {
      if (this.flight.isLocked) this.flight.unlock();
      this.keys.clear(); this.onDeselect(); return;
    }
    const target = event.target;
    const textEntry = target?.isContentEditable || target?.tagName === 'TEXTAREA' || target?.tagName === 'SELECT' ||
      target?.tagName === 'INPUT' && !['checkbox', 'radio', 'range', 'button', 'submit', 'reset', 'file', 'color'].includes(target.type);
    if (event.code === 'KeyF' && !event.ctrlKey && !event.metaKey && !event.altKey && !event.repeat && (this.flight.isLocked || !textEntry)) {
      event.preventDefault(); this.toggleFlight(); return;
    }
    if (!this.flight.isLocked && textEntry) return;
    if (['KeyW', 'KeyA', 'KeyS', 'KeyD', 'KeyQ', 'KeyE'].includes(event.code)) {
      if (event.ctrlKey || event.metaKey || event.altKey) return;
      event.preventDefault();
    }
    if (event.code === 'KeyG' && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      if (!event.repeat && this.selectedPosition) this.focus(this.selectedPosition);
      return;
    }
    if (event.code === 'Space' && this.flight.isLocked) {
      event.preventDefault();
      if (!event.repeat) { this.slowFlight = !this.slowFlight; this.onFlightSpeed?.(this.flightSpeedMode()); }
      return;
    }
    if (event.code === 'KeyX') { event.preventDefault(); if (!event.repeat) this.onDeselect(); return; }
    this.keys.add(event.code);
    if (this.flight.isLocked && (event.code === 'ShiftLeft' || event.code === 'ShiftRight')) this.onFlightSpeed?.(this.flightSpeedMode());
  }

  handleKeyUp(event) {
    this.keys.delete(event.code);
    if (this.flight.isLocked && (event.code === 'ShiftLeft' || event.code === 'ShiftRight')) this.onFlightSpeed?.(this.flightSpeedMode());
  }

  flightSpeedMode() {
    return this.keys.has('ShiftLeft') || this.keys.has('ShiftRight') ? 'fast' : this.slowFlight ? 'slow' : 'normal';
  }

  toggleFlight() { this.stopCinematic(); if (this.flight.isLocked) this.flight.unlock(); else this.flight.lock(); }

  // ---- cinematic tour (client/cinematic.js plans it) ----

  // tour: { cameras: [[x, y, z]], targets: [[x, y, z]] }, a closed loop; each stop takes
  // secondsPerStop. The camera eases in from where it is.
  startCinematic(tour, { secondsPerStop = 7, onChange = null } = {}) {
    this.stopCinematic();
    if (!tour || tour.cameras.length < 2) return;
    if (this.flight.isLocked) this.flight.unlock();
    const v = p => new THREE.Vector3(...p);
    this.cinematic = {
      cameras: new THREE.CatmullRomCurve3(tour.cameras.map(v), true, 'centripetal'),
      targets: new THREE.CatmullRomCurve3(tour.targets.map(v), true, 'centripetal'),
      duration: secondsPerStop * tour.cameras.length, t: 0, easeIn: 3,
      fromPosition: this.camera.position.clone(), fromTarget: this.orbit.target.clone(), look: this.orbit.target.clone(),
      onChange,
    };
    this.orbit.enabled = false;
    onChange?.(true);
  }

  // Screen space (px) the scene should leave clear: a panel on the right, the timeline at the bottom.
  // The projection is shifted (a larger virtual frame, setViewOffset) so the view centres in the rest.
  setFraming(framing) { this.framing = framing; this.applyFraming(); }

  applyFraming() {
    const f = this.framing, W = innerWidth, H = innerHeight;
    if (f && (f.right > 0 || f.bottom > 0)) {
      this.camera.aspect = (W + f.right) / (H + f.bottom);
      this.camera.setViewOffset(W + f.right, H + f.bottom, f.right, f.bottom, W, H);
    } else {
      this.camera.aspect = W / H;
      this.camera.clearViewOffset();
    }
    this.camera.updateProjectionMatrix();
  }

  stopCinematic() {
    const c = this.cinematic;
    if (!c) return;
    this.cinematic = null;
    this.setFraming(null);
    this.orbit.target.copy(c.look);
    this.orbit.enabled = true;
    this.lastLabels = -Infinity;
    c.onChange?.(false);
  }

  advanceCinematic(delta) {
    const c = this.cinematic;
    c.t += Math.min(delta, 0.1); // a stalled frame does not jump the camera
    // Uniform in the curve parameter: every stop gets the same time, the camera slows near close ones.
    const u = (c.t / c.duration) % 1;
    const position = c.cameras.getPoint(u), target = c.targets.getPoint(u);
    const k = Math.min(1, c.t / c.easeIn), ease = k * k * (3 - 2 * k);
    if (ease < 1) { position.lerpVectors(c.fromPosition, position, ease); target.lerpVectors(c.fromTarget, target, ease); }
    this.camera.position.copy(position);
    this.camera.lookAt(target);
    c.look.copy(target);
  }

  setTheme(id) {
    const theme = getTheme(id);
    if (this.theme === theme) return;
    this.theme = theme;
    this.scene.background = new THREE.Color(theme.background);
    this.scene.remove(this.grid); this.grid.geometry.dispose(); this.grid.material.dispose();
    this.grid = new THREE.GridHelper(8000, 320, ...theme.grid);
    this.grid.position.y = -6; this.scene.add(this.grid);
    if (this.composer) { for (const pass of this.composer.passes) pass.dispose?.(); this.composer.dispose(); this.composer = null; }
    this.setBloom(true);
  }

  setBloom(enabled) {
    const bloom = enabled ? this.theme.bloom : null;
    if (!bloom) { this.renderer.toneMapping = THREE.NoToneMapping; return; }
    this.renderer.toneMapping = THREE.ReinhardToneMapping;
    const composer = new EffectComposer(this.renderer);
    composer.setPixelRatio(1);
    composer.setSize(innerWidth, innerHeight);
    composer.addPass(new RenderPass(this.scene, this.camera));
    composer.addPass(new UnrealBloomPass(new THREE.Vector2(innerWidth, innerHeight), bloom.strength, bloom.radius, bloom.threshold));
    composer.addPass(new OutputPass());
    this.composer = composer;
  }

  pick(event) {
    this.camera.updateMatrixWorld();
    const x = this.flight.isLocked ? 0 : event.clientX / innerWidth * 2 - 1;
    const y = this.flight.isLocked ? 0 : 1 - event.clientY / innerHeight * 2;
    // Beam heads are small and drawn over everything: they win within a few pixels.
    if (this.beams.group.visible) {
      const beam = this.beams.pick(this.camera, (x + 1) * innerWidth / 2, (1 - y) * innerHeight / 2, innerWidth, innerHeight);
      if (beam) return { kind: 'call', i: beam.i, count: beam.count, phase: beam.phase, leg: beam.leg };
    }
    if (this.memoryBeams.group.visible) {
      const beam = this.memoryBeams.pick(this.camera, (x + 1) * innerWidth / 2, (1 - y) * innerHeight / 2, innerWidth, innerHeight);
      if (beam) return beam.item;
    }
    this.raycaster.setFromCamera(new THREE.Vector2(x, y), this.camera);
    // Region boxes enclose their content, so content wins; regions are the fallback.
    const content = this.pickables.filter(mesh => mesh.visible && !mesh.userData.regionPick);
    const regions = this.pickables.filter(mesh => mesh.visible && mesh.userData.regionPick);
    const hit = this.raycaster.intersectObjects(content, false)[0] ?? this.raycaster.intersectObjects(regions, false)[0];
    if (!hit) return null;
    return hit.instanceId === undefined ? hit.object.userData.item : hit.object.userData.items[hit.instanceId];
  }

  // ---- content ----

  static dispose(group) {
    const disposable = new Set();
    group.traverse(o => {
      if (o.geometry && o.geometry !== unitBox) disposable.add(o.geometry);
      for (const m of o.material ? (Array.isArray(o.material) ? o.material : [o.material]) : []) {
        disposable.add(m); if (m.map) disposable.add(m.map);
      }
    });
    for (const item of disposable) item.dispose();
    group.clear();
  }

  clear() {
    Atlas.dispose(this.staticContent);
    Atlas.dispose(this.dynamicContent);
    this.pickables = []; this.labels = []; this.regionFrames = new Map(); this.regionPickables = [];
    this.mark(null);
  }

  label(text, position, color, width = 36, opacity = 1, options = {}) {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    const font = '600 28px "Segoe UI", sans-serif';
    const lines = text.split('\n');
    context.font = font;
    canvas.width = Math.ceil(Math.min(1024, Math.max(...lines.map(line => context.measureText(line).width)) + 48));
    canvas.height = 68 + (lines.length - 1) * 34;
    context.font = font;
    context.fillStyle = this.theme.background; context.strokeStyle = color; context.lineWidth = 2;
    context.beginPath(); context.roundRect(2, 2, canvas.width - 4, canvas.height - 4, 11); context.fill(); context.stroke();
    context.fillStyle = color; context.fillRect(12, 15, 4, canvas.height - 30);
    context.fillStyle = '#f1fbff';
    lines.forEach((line, i) => context.fillText(line, 26, 44 + i * 34));
    const texture = new THREE.CanvasTexture(canvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ ...transparentSurface, map: texture,
      depthTest: false, sizeAttenuation: false, toneMapped: false, opacity }));
    sprite.renderOrder = renderLayers.labels;
    sprite.layers.set(1);
    sprite.position.set(...position);
    sprite.userData.label = { text, width, aspect: canvas.width / canvas.height, baseOpacity: opacity, ...options };
    this.staticContent.add(sprite); this.labels.push(sprite);
    return sprite;
  }

  // Region frames + labels for every region that ever exists (positions never change).
  buildStatic(layout, describeRegion) {
    this.clear();
    this.layout = layout;
    const box = new THREE.EdgesGeometry(unitBox);
    for (const item of layout.items) {
      const color = this.theme.regions[item.kind] ?? '#8797a9';
      const material = new THREE.LineBasicMaterial({ ...transparentSurface, color, opacity: 0.4 });
      const outline = new THREE.LineSegments(box, material);
      outline.scale.set(...item.size);
      outline.position.set(...item.position);
      outline.renderOrder = renderLayers.guides;
      this.staticContent.add(outline);
      const pick = new THREE.Mesh(unitBox, new THREE.MeshBasicMaterial({ ...transparentSurface, opacity: 0.02, color }));
      pick.scale.set(...item.size); pick.position.set(...item.position);
      pick.userData.item = { kind: 'region', r: item.r };
      pick.userData.regionPick = true;
      pick.renderOrder = renderLayers.glass;
      this.staticContent.add(pick);
      const text = describeRegion(item.r);
      const label = this.label(text, [item.position[0], item.top + 2, item.position[2]], color,
        Math.max(14, Math.min(48, item.size[0] * 1.5)), 0.9, { minPixels: 90, maxPixels: 220 });
      label.userData.regionId = item.r;
      this.regionFrames.set(item.r, { outline, material, label, pick, item });
    }
    this.bounds = new THREE.Box3();
    for (const item of layout.items) {
      const c = new THREE.Vector3(...item.position), h = new THREE.Vector3(...item.size).multiplyScalar(0.5);
      this.bounds.expandByPoint(c.clone().sub(h)); this.bounds.expandByPoint(c.clone().add(h));
    }
    this.grid.position.y = this.bounds.isEmpty() ? -6 : this.bounds.min.y - 2;
    this.buildEmphasis();
    this.alerts.key = '';
    this.setRegionAlerts(this.alerts.set);
  }

  // Regions that need attention (e.g. executable memory outside any module): a pulsing red fill
  // and outline. Rebuilt only when the set changes.
  setRegionAlerts(set) {
    const key = [...set].sort((a, b) => a - b).join(',');
    this.alerts.set = new Set(set);
    if (key === this.alerts.key) return;
    this.alerts.key = key;
    Atlas.dispose(this.alertGroup);
    if (!this.layout) return;
    const edges = new THREE.EdgesGeometry(unitBox);
    for (const r of this.alerts.set) {
      const item = this.layout.byRegion[r];
      if (!item) continue;
      const color = this.theme.leak;
      const glow = new THREE.Mesh(unitBox, new THREE.MeshBasicMaterial({ ...transparentSurface, color, opacity: 0.12, blending: THREE.AdditiveBlending, toneMapped: false }));
      glow.scale.set(...item.size.map(v => v + 0.6)); glow.position.set(...item.position);
      glow.renderOrder = renderLayers.glass;
      glow.userData.pulse = 0.22;
      const outline = new THREE.LineSegments(edges, new THREE.LineBasicMaterial({ ...transparentSurface, color, opacity: 1, toneMapped: false }));
      outline.scale.set(...item.size.map(v => v + 0.6)); outline.position.set(...item.position);
      outline.renderOrder = renderLayers.guides;
      outline.userData.pulse = 1;
      this.alertGroup.add(glow, outline);
    }
  }

  // Highlighted regions glow and keep their labels; with dim, every other region fades.
  setRegionEmphasis(set, dim) {
    this.emphasis = { set: new Set(set), dim: !!dim && set.size > 0 };
    this.buildEmphasis();
    if (this.liveness) this.setRegionLiveness(...this.liveness);
  }

  buildEmphasis() {
    Atlas.dispose(this.emphasisGroup);
    if (!this.layout) return;
    const edges = new THREE.EdgesGeometry(unitBox);
    for (const r of this.emphasis.set) {
      const item = this.layout.byRegion[r];
      if (!item) continue;
      const color = this.theme.regions[item.kind] ?? '#ffffff';
      const glow = new THREE.Mesh(unitBox, new THREE.MeshBasicMaterial({ ...transparentSurface, color, opacity: 0.09, blending: THREE.AdditiveBlending, toneMapped: false }));
      glow.scale.set(...item.size); glow.position.set(...item.position);
      glow.renderOrder = renderLayers.glass;
      const outline = new THREE.LineSegments(edges, new THREE.LineBasicMaterial({ ...transparentSurface, color: '#ffffff', opacity: 0.9, toneMapped: false }));
      outline.scale.set(...item.size.map(v => v + 0.4)); outline.position.set(...item.position);
      outline.renderOrder = renderLayers.guides;
      this.emphasisGroup.add(glow, outline);
    }
    this.lastLabels = -Infinity;
  }

  // Dims regions that do not exist at the current event.
  setRegionLiveness(isLive, showGhostRegions) {
    this.liveness = [isLive, showGhostRegions];
    const { set, dim } = this.emphasis;
    for (const [r, f] of this.regionFrames) {
      const live = isLive(r), faded = dim && !set.has(r);
      f.material.opacity = live ? (faded ? 0.1 : 0.42) : showGhostRegions ? 0.06 : 0;
      f.outline.visible = live || showGhostRegions;
      f.label.userData.hidden = !live || faded;
      f.label.userData.emphasis = set.has(r);
      f.pick.visible = live;
    }
    this.pickables = [...this.dynamicPickables ?? [], ...[...this.regionFrames.values()].filter(f => f.pick.visible).map(f => f.pick)];
    this.lastLabels = -Infinity;
  }

  instanced(items, colorOf, material, sideScale = 0.94) {
    const mesh = new THREE.InstancedMesh(unitBox, material, items.length);
    const m = new THREE.Matrix4(), color = new THREE.Color();
    items.forEach((p, i) => {
      const s = p.side * sideScale;
      m.makeScale(s, s, s).setPosition(p.position[0], p.position[1], p.position[2]);
      mesh.setMatrixAt(i, m);
      mesh.setColorAt(i, colorOf(p, color));
    });
    mesh.instanceMatrix.needsUpdate = true;
    if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
    mesh.computeBoundingSphere();
    return mesh;
  }

  outlines(items, color, opacity, dashed) {
    if (!items.length) return;
    const template = new THREE.EdgesGeometry(unitBox).attributes.position.array;
    const positions = new Float32Array(items.length * template.length);
    let k = 0;
    for (const p of items) for (let i = 0; i < template.length; i += 3) {
      positions[k++] = p.position[0] + template[i] * p.side;
      positions[k++] = p.position[1] + template[i + 1] * p.side;
      positions[k++] = p.position[2] + template[i + 2] * p.side;
    }
    const geometry = new THREE.BufferGeometry().setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const material = dashed
      ? new THREE.LineDashedMaterial({ ...transparentSurface, color, opacity, dashSize: 0.35, gapSize: 0.25 })
      : new THREE.LineBasicMaterial({ ...transparentSurface, color, opacity });
    const lines = new THREE.LineSegments(geometry, material);
    if (dashed) lines.computeLineDistances();
    lines.renderOrder = renderLayers.guides;
    this.dynamicContent.add(lines);
  }

  // frame: { blocks: [{b, position, side}], ghosts: [...], pages: [{s, r, protect, position, side}],
  //          gaps: [{kind, position, side}], blockColor(p, color), pageColor(p, color), dimmed(p) }
  showFrame(frame) {
    Atlas.dispose(this.dynamicContent);
    this.dynamicPickables = [];
    const theme = this.theme;
    if (frame.blocks.length) {
      const bright = frame.blocks.filter(p => !frame.dimmed?.(p)), dim = frame.blocks.filter(p => frame.dimmed?.(p));
      for (const [list, opacity] of [[bright, 1], [dim, 0.14]]) {
        if (!list.length) continue;
        const material = opacity < 1
          ? new THREE.MeshStandardMaterial({ ...transparentSurface, opacity, roughness: 0.6, metalness: 0.1, wireframe: !!theme.wireframe })
          : new THREE.MeshStandardMaterial({ roughness: 0.55, metalness: 0.15, emissive: '#101018', wireframe: !!theme.wireframe });
        const mesh = this.instanced(list, frame.blockColor, material);
        mesh.userData.items = list.map(p => ({ kind: 'block', b: p.b, position: p.position, side: p.side }));
        mesh.renderOrder = opacity < 1 ? renderLayers.glass : 0;
        this.dynamicContent.add(mesh); this.dynamicPickables.push(mesh);
      }
    }
    if (frame.ghosts?.length) {
      const material = new THREE.MeshBasicMaterial({ ...transparentSurface, opacity: 0.16, color: theme.ghost, wireframe: true });
      const mesh = this.instanced(frame.ghosts, (p, c) => c.set(theme.ghost), material, 0.9);
      mesh.userData.items = frame.ghosts.map(p => ({ kind: 'block', b: p.b, position: p.position, side: p.side, ghost: true }));
      this.dynamicContent.add(mesh); this.dynamicPickables.push(mesh);
    }
    if (frame.pages.length) {
      const material = new THREE.MeshStandardMaterial({ ...transparentSurface, opacity: 0.38, roughness: 0.8 });
      const mesh = this.instanced(frame.pages, frame.pageColor, material, 0.97);
      mesh.userData.items = frame.pages.map(p => ({ kind: 'span', s: p.s, r: p.r, position: p.position, side: p.side }));
      mesh.renderOrder = renderLayers.glass;
      this.dynamicContent.add(mesh); this.dynamicPickables.push(mesh);
    }
    this.outlines(frame.gaps.filter(g => g.kind === 'free'), theme.free, 0.3, false);
    this.outlines(frame.gaps.filter(g => g.kind === 'reserved'), theme.reserved, 0.18, true);
    this.pickables = [...this.dynamicPickables, ...[...this.regionFrames.values()].filter(f => f.pick.visible).map(f => f.pick)];
  }

  mark(position, size = [1, 1, 1]) {
    for (const child of this.selection.children) { child.geometry.dispose(); child.material.dispose(); }
    this.selection.clear();
    this.selectedPosition = position; this.selectedSize = size;
    if (!position) return;
    const box = new THREE.BoxGeometry(...size.map(v => v + 0.25));
    const geometry = new THREE.EdgesGeometry(box); box.dispose();
    const outline = new THREE.LineSegments(geometry, new THREE.LineBasicMaterial({ color: '#ffffff', transparent: true, depthTest: false, depthWrite: false, toneMapped: false }));
    outline.renderOrder = renderLayers.selection;
    outline.layers.set(1);
    outline.position.set(...position); this.selection.add(outline);
  }

  // Extra outline markers (e.g. all blocks of a selected group).
  markMany(items) {
    if (!items.length) return;
    const template = new THREE.EdgesGeometry(unitBox).attributes.position.array;
    const positions = new Float32Array(items.length * template.length);
    let k = 0;
    for (const p of items) for (let i = 0; i < template.length; i += 3) {
      positions[k++] = p.position[0] + template[i] * (p.side + 0.2);
      positions[k++] = p.position[1] + template[i + 1] * (p.side + 0.2);
      positions[k++] = p.position[2] + template[i + 2] * (p.side + 0.2);
    }
    const lines = new THREE.LineSegments(new THREE.BufferGeometry().setAttribute('position', new THREE.BufferAttribute(positions, 3)),
      new THREE.LineBasicMaterial({ color: '#ffffff', transparent: true, depthTest: false, depthWrite: false, toneMapped: false }));
    lines.renderOrder = renderLayers.selection; lines.layers.set(1);
    this.selection.add(lines);
  }

  updateLabels(now = performance.now()) {
    if (!this.labels.length || now - this.lastLabels < 100) return;
    this.lastLabels = now;
    this.camera.updateMatrixWorld();
    const pixelsPerUnit = innerHeight / (2 * Math.tan(THREE.MathUtils.degToRad(this.camera.fov / 2)));
    const candidates = [];
    for (const sprite of this.labels) {
      sprite.visible = false;
      if (sprite.userData.hidden) continue;
      const view = sprite.position.clone().applyMatrix4(this.camera.matrixWorldInverse);
      const projected = sprite.position.clone().project(this.camera);
      if (view.z >= -this.camera.near || projected.z < -1 || projected.z > 1 || Math.abs(projected.x) > 1.1 || Math.abs(projected.y) > 1.1) continue;
      const label = sprite.userData.label;
      const width = THREE.MathUtils.clamp(label.width * pixelsPerUnit / -view.z, label.minPixels ?? 110, label.maxPixels ?? 230);
      const height = width / label.aspect;
      sprite.scale.set(width / pixelsPerUnit, height / pixelsPerUnit, 1);
      const x = (projected.x + 1) * innerWidth / 2, y = (1 - projected.y) * innerHeight / 2;
      candidates.push({ sprite, depth: -view.z, distance: view.length(), x: x - width / 2, y: y - height / 2, width, height });
    }
    const priority = c => Number(c.sprite.userData.regionId === this.activeRegion || !!c.sprite.userData.emphasis);
    candidates.sort((a, b) => priority(b) - priority(a) || a.depth - b.depth);
    const placed = [];
    const nearest = candidates.reduce((m, c) => Math.min(m, c.distance), Infinity);
    const extent = Math.hypot(...(this.layout?.size ?? [200, 200, 200]));
    for (const c of candidates) {
      if (placed.some(other => labelsOverlap(c, other))) continue;
      c.sprite.material.opacity = labelOpacity(c.distance, nearest, extent, c.sprite.userData.label.baseOpacity, c.sprite.userData.regionId === this.activeRegion);
      c.sprite.visible = true; placed.push(c);
    }
  }

  overview(bounds = this.bounds) {
    this.stopCinematic();
    if (!bounds || bounds.isEmpty()) return;
    const center = bounds.getCenter(new THREE.Vector3());
    const size = bounds.getSize(new THREE.Vector3());
    const distance = Math.max(35, size.length() * 0.85);
    this.orbit.target.copy(center);
    this.camera.position.copy(center).add(new THREE.Vector3(distance * 0.38, distance * 0.8, distance));
    this.camera.lookAt(center);
    this.lastLabels = -Infinity;
  }

  focus(position, size = this.selectedSize ?? [1, 1, 1]) {
    this.stopCinematic();
    const distance = Math.max(7, ...size) * 2;
    this.orbit.target.set(...position);
    this.camera.position.set(position[0] + distance * 0.5, position[1] + distance * 0.6, position[2] + distance);
    this.camera.lookAt(this.orbit.target);
    this.speed = Math.max(8, distance * 1.5);
    this.lastLabels = -Infinity;
  }

  advanceFlight(delta) {
    const mode = this.flightSpeedMode();
    const step = delta * this.speed * (mode === 'fast' ? 4 : mode === 'slow' ? 0.1 : 1);
    const forward = this.camera.getWorldDirection(new THREE.Vector3());
    const right = new THREE.Vector3(1, 0, 0).applyQuaternion(this.camera.quaternion);
    const movement = forward.multiplyScalar(Number(this.keys.has('KeyW')) - Number(this.keys.has('KeyS')))
      .addScaledVector(right, Number(this.keys.has('KeyD')) - Number(this.keys.has('KeyA')));
    movement.y += Number(this.keys.has('KeyE')) - Number(this.keys.has('KeyQ'));
    if (movement.lengthSq() > 1) movement.normalize();
    this.camera.position.addScaledVector(movement, step);
  }

  advanceOrbit(delta) {
    const horizontal = Number(this.keys.has('KeyD')) - Number(this.keys.has('KeyA'));
    const vertical = Number(this.keys.has('KeyW')) - Number(this.keys.has('KeyS'));
    const rotation = Number(this.keys.has('KeyQ')) - Number(this.keys.has('KeyE'));
    if (!horizontal && !vertical && !rotation) return false;
    const distance = this.camera.position.distanceTo(this.orbit.target);
    const pan = new THREE.Vector3(horizontal, vertical, 0);
    if (pan.lengthSq() > 1) pan.normalize();
    pan.applyQuaternion(this.camera.quaternion).multiplyScalar(Math.max(1, distance) * delta * 0.5);
    this.camera.position.add(pan); this.orbit.target.add(pan);
    if (rotation) {
      const offset = this.camera.position.clone().sub(this.orbit.target).applyAxisAngle(new THREE.Vector3(0, 1, 0), rotation * delta * 0.9);
      this.camera.position.copy(this.orbit.target).add(offset); this.camera.lookAt(this.orbit.target);
    }
    return true;
  }

  frame() {
    this.clock.update();
    const delta = Math.min(this.clock.getDelta(), 0.08);
    if (this.flight.isLocked) {
      this.advanceFlight(delta);
      if (performance.now() - this.lastHover > 100) {
        this.lastHover = performance.now();
        const cursor = { clientX: innerWidth / 2, clientY: innerHeight / 2 };
        this.onHover(this.pick(cursor), cursor);
      }
    } else if (this.cinematic) {
      this.advanceCinematic(delta);
    } else {
      this.advanceOrbit(delta);
      this.orbit.update();
    }
    this.updateLabels();
    if (this.alertGroup.children.length) {
      // userData.pulse is the peak opacity of an alert object.
      const k = 0.35 + 0.65 * (0.5 + 0.5 * Math.sin(performance.now() / 260));
      for (const o of this.alertGroup.children) if (o.userData.pulse) o.material.opacity = o.userData.pulse * k;
    }
    this.onBeforeRender?.();
    if (this.composer) {
      const mask = this.camera.layers.mask, clear = this.renderer.autoClear, background = this.scene.background;
      try {
        this.camera.layers.set(0);
        this.composer.render(delta);
        this.camera.layers.set(1); this.renderer.autoClear = false; this.scene.background = null;
        this.renderer.render(this.scene, this.camera);
      } finally {
        this.camera.layers.mask = mask; this.renderer.autoClear = clear; this.scene.background = background;
      }
    } else this.renderer.render(this.scene, this.camera);
  }
}
