export const NONE = 0xFFFFFFFF;

export function bytes(value) {
  if (!Number.isFinite(value)) return '?';
  if (value < 1024) return `${value} B`;
  const power = Math.min(4, Math.floor(Math.log(value) / Math.log(1024)));
  return `${(value / 1024 ** power).toFixed(1)} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][power]}`;
}

export function percentage(part, total) {
  if (total === 0) return 'n/a';
  const value = part / total * 100;
  if (part > 0 && value < 0.1) return '<0.1%';
  if (part < total && value >= 99.95) return '>99.9%';
  return `${value.toFixed(1)}%`;
}

// User-mode addresses are < 2^47 and are exact as doubles.
export function hex(value) {
  return `0x${Math.round(value).toString(16)}`;
}

export function parseAddress(text) {
  const t = text.trim().toLowerCase().replace(/`/g, '');
  if (!/^(0x)?[0-9a-f]+$/.test(t)) return null;
  const v = Number.parseInt(t.startsWith('0x') ? t.slice(2) : t, 16);
  return Number.isSafeInteger(v) ? v : null;
}

export function evtLabel(i) {
  return i === NONE ? '—' : `#${i.toLocaleString()}`;
}

const PROTECT_BASE = { 0x01: 'NOACCESS', 0x02: 'R', 0x04: 'RW', 0x08: 'WC', 0x10: 'X', 0x20: 'RX', 0x40: 'RWX', 0x80: 'WCX' };

export function protectName(p) {
  if (!p) return '—';
  const base = PROTECT_BASE[p & 0xFF] ?? `0x${(p & 0xFF).toString(16)}`;
  const mods = [p & 0x100 ? 'GUARD' : '', p & 0x200 ? 'NOCACHE' : '', p & 0x400 ? 'WRITECOMBINE' : ''].filter(Boolean);
  return [base, ...mods].join('+');
}

export function isExecutable(p) { return (p & 0xF0) !== 0; }
export function isWritable(p) { return (p & 0xCC) !== 0; }

export const EVENT_KIND = {
  1: 'Alloc', 2: 'Free', 3: 'ReAlloc', 4: 'HeapCreate', 5: 'HeapDestroy', 7: 'FreeUnknown', 8: 'AllocFailed',
  16: 'Reserve', 17: 'Commit', 18: 'Decommit', 19: 'Release', 20: 'Protect', 21: 'MapView', 22: 'UnmapView',
  32: 'ModuleLoad', 33: 'ModuleUnload', 34: 'ThreadCreate', 35: 'ThreadExit', 36: 'Marker', 37: 'DirectSyscall',
};

export const EVENT_FLAGS = {
  0x01: 'nested', 0x02: 'out-param read back', 0x04: 'out-param unknown', 0x08: 'unwound',
  0x10: 'failed', 0x20: 'cross-thread', 0x40: 'remote process', 0x80: 'extra',
};

export function flagNames(flags, table = EVENT_FLAGS) {
  return Object.entries(table).filter(([bit]) => flags & Number(bit)).map(([, name]) => name);
}

export const BLOCK_FLAGS = {
  0x01: 'allocated before the trace', 0x02: 'size unknown', 0x04: 'freed by HeapDestroy', 0x08: 'superseded (free missed)',
  0x10: 'realloc in place', 0x20: 'ended by realloc', 0x40: 'freed on another thread', 0x80: 'free unwound',
};

export const REGION_KIND = ['Private', 'Mapped', 'Image', 'Stack', 'Heap segment', 'Inferred', 'Heap (inferred)'];

export function eventCategory(kind) {
  if (kind <= 8) return 'heap';
  if (kind <= 22) return 'vm';
  return 'other';
}
