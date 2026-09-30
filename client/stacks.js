import { NONE, hex } from './format.js';

// Frames belonging to the allocator machinery; collapsed so the "site" is the caller's code.
export const ALLOCATOR_MODULES = new Set(['ntdll', 'kernelbase', 'kernel32', 'ucrtbase', 'ucrtbased', 'vcruntime140',
  'vcruntime140d', 'vcruntime140_1', 'msvcrt', 'msvcp_win', 'msvcp140', 'msvcp140d', 'combase', 'rpcrt4']);

// Allocator entry points that can live inside any module (e.g. a statically linked CRT).
export const ALLOCATOR_FUNCTIONS = /!(_?(malloc|calloc|realloc|recalloc|free|expand)(_base|_dbg|_impl|_crt)?|_aligned_\w+|operator new(\[\])?|operator delete(\[\])?|_?(Heap|Local|Global)(Alloc|ReAlloc|Free)|Rtl(Allocate|ReAllocate|Free)Heap|std::_Allocate\w*|std::allocator<.*>::allocate)(\+0x[0-9a-f]+)?$/i;

export class Stacks {
  constructor(data) {
    this.stacks = data.stacks;
    this.frames = data.frames;
    this.symbols = data.symbols;
    this.modules = data.manifest.modules;
    this.moduleShort = this.modules.map(m => m.name.replace(/\.[^.]*$/, '').toLowerCase());
    this.siteCache = new Map();
  }

  // Frame indexes, innermost first.
  frameIds(node) {
    const out = [];
    for (let n = node; n !== NONE && n < this.stacks.count; n = this.stacks.parent[n]) out.push(this.stacks.frame[n]);
    return out;
  }

  moduleOf(frame) {
    const m = this.frames.module[frame];
    return m === NONE ? null : this.moduleShort[m];
  }

  frameText(frame) {
    const sym = this.symbols?.[frame];
    if (sym?.[0]) return sym[0];
    const m = this.frames.module[frame];
    // Code outside every loaded module (JIT, shellcode, manually mapped images) is flagged.
    return m === NONE ? `${hex(this.frames.addr[frame])} (unbacked)` : `${this.moduleShort[m]}+0x${this.frames.rva[frame].toString(16)}`;
  }

  frameSource(frame) {
    const sym = this.symbols?.[frame];
    return sym?.[1] ? `${sym[1].split(/[\\/]/).pop()}:${sym[2]}` : '';
  }

  isAllocatorFrame(f) {
    return ALLOCATOR_MODULES.has(this.moduleOf(f) ?? '') || ALLOCATOR_FUNCTIONS.test(this.frameText(f));
  }

  describe(node) {
    return this.frameIds(node).map(f => ({
      frame: f, address: this.frames.addr[f], text: this.frameText(f), source: this.frameSource(f),
      allocator: this.isAllocatorFrame(f),
    }));
  }

  // The first frame outside the allocator modules: where the application asked for memory.
  siteFrame(node) {
    if (node === NONE) return NONE;
    if (this.siteCache.has(node)) return this.siteCache.get(node);
    const ids = this.frameIds(node);
    const site = ids.find(f => !this.isAllocatorFrame(f)) ?? ids.at(-1) ?? NONE;
    this.siteCache.set(node, site);
    return site;
  }

  siteText(node) {
    const f = this.siteFrame(node);
    return f === NONE ? '(no stack)' : this.frameText(f);
  }

  // Whether any frame of the stack matches a lower-case query.
  matches(node, query) {
    return this.frameIds(node).some(f => this.frameText(f).toLowerCase().includes(query));
  }
}
