// Minimal event emitter for the app core and features.
export class Emitter {
  constructor() { this.handlers = new Map(); }

  // Returns a function that removes the handler.
  on(type, fn) {
    let set = this.handlers.get(type);
    if (!set) this.handlers.set(type, set = new Set());
    set.add(fn);
    return () => set.delete(fn);
  }

  emit(type, payload) {
    for (const fn of this.handlers.get(type) ?? []) {
      try { fn(payload); } catch (err) { console.error(`handler for "${type}" failed`, err); }
    }
  }
}
