// Per-viewer preferences in localStorage (UI conveniences only; storage may be unavailable).
const PREFIX = 'ttdscape.';

export function load(key, fallback = null) {
  try {
    const v = localStorage.getItem(PREFIX + key);
    return v === null ? fallback : v;
  } catch { return fallback; }
}

export function save(key, value) {
  try { localStorage.setItem(PREFIX + key, String(value)); } catch { /* unavailable */ }
}

export function loadJson(key, fallback = null) {
  try { return JSON.parse(load(key)) ?? fallback; } catch { return fallback; }
}

export function saveJson(key, value) { save(key, JSON.stringify(value)); }
