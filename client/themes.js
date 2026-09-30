// Visual themes (adapted from Heapscape). Colors are grouped by what TTDscape draws: heap blocks,
// page protections, and region kinds.
import { Color } from 'three';

const base = {
  // Region frame colors by RegionKind: Private, Mapped, Image, Stack, Heap, Inferred, HeapInferred.
  regions: ['#7bb6ff', '#c58cff', '#f2c46d', '#66d8c7', '#ed83e7', '#8797a9', '#b07fc0'],
  protect: { exec: '#f2a65a', write: '#5aa9f2', read: '#9aa7b8', none: '#4c5260', guard: '#b77cf2' },
  leak: '#ff5a4f', ghost: '#8a93a6', free: '#a5adb8', reserved: '#606a78',
};

export const themes = {
  atlas: {
    ...base, name: 'Atlas', background: '#071019', grid: ['#244453', '#122633'],
    blockColors: ['#69c9be', '#7eace0', '#a393dd', '#cb96bb', '#cfb181', '#94bd95', '#e39a7a', '#8fd0e8'],
    wireframe: false,
  },
  matrix: {
    ...base, name: 'Matrix', background: '#010904', grid: ['#268946', '#0b3019'],
    blockColors: ['#42f58a', '#8bdd63', '#25c999', '#bfdc75', '#66d6b3', '#66ac54', '#b8ff9e', '#3fae7c'],
    regions: ['#49ff82', '#9dff73', '#daff62', '#2ee6a0', '#74ff9b', '#5c8f6c', '#8bd6a2'],
    wireframe: true,
  },
  neon: {
    ...base, name: 'Neon Circuit', background: '#08051b', grid: ['#753997', '#21153c'],
    blockColors: ['#55e9f4', '#7cafff', '#a987ff', '#d289f4', '#f075c1', '#99cff4', '#ffc36b', '#53fff2'],
    bloom: { strength: 0.35, radius: 0.35, threshold: 0.8 },
  },
  prism: {
    ...base, name: 'Prism', background: '#060719', grid: ['#454273', '#17172f'],
    blockColors: ['#ed83e7', '#59dbf0', '#a78bed', '#779eee', '#f2c46d', '#66d8c7', '#ff9d7a', '#b8e986'],
    bloom: { strength: 0.3, radius: 0.35, threshold: 0.85 },
  },
};

export function getTheme(id = 'prism') {
  if (!Object.hasOwn(themes, id)) throw new RangeError(`Unknown theme: ${id}`);
  return themes[id];
}

export function hashColor(key, theme, color = new Color()) {
  let hash = 2166136261;
  const text = String(key);
  for (let i = 0; i < text.length; i++) hash = Math.imul(hash ^ text.charCodeAt(i), 16777619) >>> 0;
  color.set(theme.blockColors[hash % theme.blockColors.length]);
  const shade = 0.8 + ((hash >>> 12) & 255) / 255 * 0.3;
  return color.multiplyScalar(shade);
}

export function indexColor(i, theme, color = new Color()) {
  return color.set(theme.blockColors[((i % theme.blockColors.length) + theme.blockColors.length) % theme.blockColors.length]);
}

export function sizeColor(size, color = new Color()) {
  return color.setHSL(Math.max(0, 0.6 - Math.log2(size + 1) / 40), 0.7, 0.6);
}

// Recency: 0 = just allocated (hot), 1 = old (cool).
export function ageColor(age01, color = new Color()) {
  return color.setHSL(0.02 + 0.55 * Math.min(1, Math.max(0, age01)), 0.75, 0.58);
}

export function protectColor(protect, theme, color = new Color()) {
  if (protect & 0x100) return color.set(theme.protect.guard);
  if (protect & 0xF0) return color.set(theme.protect.exec);
  if (protect & 0xCC) return color.set(theme.protect.write);
  if (protect & 0x02) return color.set(theme.protect.read);
  return color.set(theme.protect.none);
}
