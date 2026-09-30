#include "model/vm_model.h"
#include "replay/outparams.h"

#include <algorithm>
#include <tuple>

namespace ttds {

uint32_t VmModel::Emit(EventKind k, Ctx const& c, uint32_t id, uint64_t addr, uint64_t size, uint32_t aux, uint8_t extra)
{
    uint32_t const idx = static_cast<uint32_t>(m_model.events.size());
    m_model.events.push_back({ static_cast<uint8_t>(k), static_cast<uint8_t>(c.flags | extra), c.thread, id, addr, size, c.stack, aux });
    return idx;
}

void VmModel::Account(Span const& s, int sign)
{
    uint64_t const bytes = s.end - s.start;
    auto add = [&](uint64_t& v) { v = sign > 0 ? v + bytes : v - std::min(v, bytes); };
    add(m_reserved);
    if (s.state == static_cast<uint16_t>(SpanState::Committed)) {
        add(m_committed);
        RegionKind const k = static_cast<RegionKind>(m_model.regions[s.region].kind);
        if (k == RegionKind::Mapped || k == RegionKind::Image) add(m_mapped);
    }
}

uint32_t VmModel::NewSpan(uint32_t region, uint64_t start, uint64_t end, SpanState st, uint32_t protect, uint32_t evt)
{
    uint32_t const id = static_cast<uint32_t>(m_model.spans.size());
    if (st == SpanState::Reserved) protect = 0;
    m_model.spans.push_back({ start, end, region, static_cast<uint16_t>(st), 0, protect, evt, kNone, 0 });
    m_live[region].pieces[start] = { end, id };
    Account(m_model.spans.back(), +1);
    return id;
}

void VmModel::CloseSpan(uint32_t span, uint32_t evt)
{
    Span& s = m_model.spans[span];
    if (s.endEvt != kNone) return;
    s.endEvt = evt;
    Account(s, -1);
}

uint32_t VmModel::RegionAt(uint64_t addr) const
{
    auto it = m_liveRegions.upper_bound(addr);
    if (it == m_liveRegions.begin()) return kNone;
    --it;
    Region const& r = m_model.regions[it->second];
    return addr - r.base < r.size ? it->second : kNone;
}

void VmModel::CloseRegion(uint32_t region, uint32_t evt)
{
    auto it = m_live.find(region);
    if (it == m_live.end()) return;
    for (auto const& [start, piece] : it->second.pieces) CloseSpan(piece.span, evt);
    m_live.erase(it);
    Region& r = m_model.regions[region];
    r.releaseEvt = evt;
    auto lr = m_liveRegions.find(r.base);
    if (lr != m_liveRegions.end() && lr->second == region) m_liveRegions.erase(lr);
}

uint32_t VmModel::NewRegion(uint64_t base, uint64_t size, RegionKind kind, uint32_t evt, Ctx const& c, uint32_t flags)
{
    // Any live region overlapping the new one must have been released without us seeing it.
    for (;;) {
        auto it = m_liveRegions.lower_bound(base + size);
        if (it == m_liveRegions.begin()) break;
        --it;
        Region const& o = m_model.regions[it->second];
        if (o.base + o.size <= base) break;
        CloseRegion(it->second, evt);
    }
    uint32_t const id = static_cast<uint32_t>(m_model.regions.size());
    Region r{};
    r.base = base;
    r.size = size;
    r.kind = static_cast<uint32_t>(kind);
    r.createEvt = evt;
    r.releaseEvt = kNone;
    r.heap = kNone;
    r.createStack = c.stack;
    r.releaseStack = kNone;
    r.flags = flags;
    m_model.regions.push_back(r);
    m_liveRegions[base] = id;
    m_live[id];
    return id;
}

void VmModel::Change(uint32_t region, uint64_t a, uint64_t b, uint16_t state, uint32_t protect, uint32_t evt)
{
    Region const& r = m_model.regions[region];
    a = std::max(a, r.base);
    b = std::min(b, r.base + r.size);
    if (a >= b) return;
    auto& pieces = m_live[region].pieces;

    struct NewPiece { uint64_t s, e; uint16_t st; uint32_t prot; };
    std::vector<NewPiece> out;
    auto it = pieces.upper_bound(a);
    if (it != pieces.begin()) --it;
    while (it != pieces.end() && it->first < b) {
        uint64_t const s = it->first, e = it->second.end;
        uint32_t const spanId = it->second.span;
        if (e <= a) { ++it; continue; }
        Span const old = m_model.spans[spanId];
        CloseSpan(spanId, evt);
        it = pieces.erase(it);
        if (s < a) out.push_back({ s, a, old.state, old.protect });
        uint16_t const st = state ? state : old.state;
        // Protection is meaningless on reserved pages; normalize so equal pages coalesce.
        uint32_t const pr = st == static_cast<uint16_t>(SpanState::Reserved) ? 0 : (protect != ~0u ? protect : old.protect);
        out.push_back({ std::max(s, a), std::min(e, b), st, pr });
        if (e > b) out.push_back({ b, e, old.state, old.protect });
    }
    // Coalesce adjacent pieces with identical attributes, then open their spans.
    std::sort(out.begin(), out.end(), [](NewPiece const& x, NewPiece const& y) { return x.s < y.s; });
    std::vector<NewPiece> merged;
    for (auto const& p : out) {
        if (!merged.empty() && merged.back().e == p.s && merged.back().st == p.st && merged.back().prot == p.prot) merged.back().e = p.e;
        else merged.push_back(p);
    }
    // Absorb untouched neighbours that now have identical attributes, so a decommit after a commit
    // (for example) restores a single span instead of leaving three.
    if (!merged.empty()) {
        auto left = pieces.find(merged.front().s);
        if (left == pieces.end()) {
            auto l = pieces.lower_bound(merged.front().s);
            if (l != pieces.begin()) {
                --l;
                Span const& ls = m_model.spans[l->second.span];
                if (l->second.end == merged.front().s && ls.state == merged.front().st && ls.protect == merged.front().prot) {
                    merged.front().s = l->first;
                    CloseSpan(l->second.span, evt);
                    pieces.erase(l);
                }
            }
        }
        auto right = pieces.find(merged.back().e);
        if (right != pieces.end()) {
            Span const& rs = m_model.spans[right->second.span];
            if (rs.state == merged.back().st && rs.protect == merged.back().prot) {
                merged.back().e = right->second.end;
                CloseSpan(right->second.span, evt);
                pieces.erase(right);
            }
        }
    }
    for (auto const& p : merged) NewSpan(region, p.s, p.e, static_cast<SpanState>(p.st), p.prot, evt);
}

uint32_t VmModel::EnsureRegionFor(uint64_t a, uint64_t b, Ctx const& c, SpanState initial, uint32_t initialProtect)
{
    uint32_t r = RegionAt(a);
    if (r != kNone) {
        Region& reg = m_model.regions[r];
        if (b > reg.base + reg.size && reg.kind == static_cast<uint32_t>(RegionKind::Inferred)) {
            uint64_t const oldEnd = reg.base + reg.size;
            reg.size = b - reg.base;
            reg.flags |= RgnGrown;
            NewSpan(r, oldEnd, b, initial, initialProtect, kNone);
        }
        return r;
    }
    // Contiguous with an inferred region just below? Extend it.
    if (uint32_t below = a ? RegionAt(a - 1) : kNone; below != kNone && m_model.regions[below].kind == static_cast<uint32_t>(RegionKind::Inferred)) {
        Region& reg = m_model.regions[below];
        uint64_t const oldEnd = reg.base + reg.size;
        reg.size = b - reg.base;
        reg.flags |= RgnGrown;
        NewSpan(below, oldEnd, b, initial, initialProtect, kNone);
        return below;
    }
    // A reservation made before the recording (e.g. a heap segment growing its commit).
    r = NewRegion(a, b - a, c.heap != kNone ? RegionKind::Heap : RegionKind::Inferred, kNone, c, RgnPreTrace);
    m_model.regions[r].heap = c.heap;
    m_model.regions[r].createStack = kNone;
    NewSpan(r, a, b, initial, initialProtect, kNone);
    return r;
}

uint32_t VmModel::Allocate(Ctx const& c, uint64_t base, uint64_t size, uint32_t type, uint32_t protect)
{
    uint32_t const evt = static_cast<uint32_t>(m_model.events.size());
    if (size == 0) return Unplaced(EventKind::Reserve, c, base, size, protect);
    if (type & kMemReserve) {
        uint32_t const r = NewRegion(base, size, c.heap != kNone ? RegionKind::Heap : RegionKind::Private, evt, c, 0);
        m_model.regions[r].heap = c.heap;
        bool const commit = (type & kMemCommit) != 0;
        NewSpan(r, base, base + size, commit ? SpanState::Committed : SpanState::Reserved, protect, evt);
        return Emit(EventKind::Reserve, c, r, base, size, protect, commit ? EvExtra : 0);
    }
    if (type & kMemCommit) {
        uint32_t const r = EnsureRegionFor(base, base + size, c, SpanState::Reserved, 0);
        Change(r, base, base + size, static_cast<uint16_t>(SpanState::Committed), protect, evt);
        return Emit(EventKind::Commit, c, r, base, size, protect);
    }
    return kNone; // MEM_RESET and friends: no state change we model
}

uint32_t VmModel::Free(Ctx const& c, uint64_t base, uint64_t size, uint32_t type)
{
    uint32_t const evt = static_cast<uint32_t>(m_model.events.size());
    uint32_t r = RegionAt(base);
    if (type & kMemRelease) {
        if (r == kNone) {
            ++m_model.quality.releaseUnknownRegion;
            return Emit(EventKind::Release, c, kNone, base, size, 0);
        }
        Region const reg = m_model.regions[r];
        CloseRegion(r, evt);
        m_model.regions[r].releaseStack = c.stack;
        return Emit(EventKind::Release, c, r, reg.base, reg.size, 0);
    }
    if (type & kMemDecommit) {
        if (r == kNone) {
            if (size == 0) return Unplaced(EventKind::Decommit, c, base, size, 0);
            r = EnsureRegionFor(base, base + size, c, SpanState::Committed, 0);
        }
        Region const& reg = m_model.regions[r];
        uint64_t const end = size ? base + size : reg.base + reg.size;
        Change(r, base, end, static_cast<uint16_t>(SpanState::Reserved), 0, evt);
        return Emit(EventKind::Decommit, c, r, base, end - base, 0);
    }
    return kNone;
}

uint32_t VmModel::Protect(Ctx const& c, uint64_t base, uint64_t size, uint32_t protect, uint32_t oldProtect)
{
    uint32_t const evt = static_cast<uint32_t>(m_model.events.size());
    if (size == 0) return Unplaced(EventKind::Protect, c, base, size, protect);
    uint32_t r = RegionAt(base);
    if (r == kNone) {
        // Protecting pages we never saw committed: they were committed before the recording.
        r = EnsureRegionFor(base, base + size, c, SpanState::Committed, oldProtect);
    }
    Change(r, base, base + size, 0, protect, evt);
    return Emit(EventKind::Protect, c, r, base, size, protect);
}

uint32_t VmModel::MapView(Ctx const& c, uint64_t base, uint64_t size, uint32_t protect)
{
    uint32_t const evt = static_cast<uint32_t>(m_model.events.size());
    if (size == 0) return Unplaced(EventKind::MapView, c, base, size, protect);
    uint32_t const r = NewRegion(base, size, RegionKind::Mapped, evt, c, 0);
    NewSpan(r, base, base + size, SpanState::Committed, protect, evt);
    return Emit(EventKind::MapView, c, r, base, size, protect);
}

uint32_t VmModel::UnmapView(Ctx const& c, uint64_t base)
{
    uint32_t const evt = static_cast<uint32_t>(m_model.events.size());
    uint32_t const r = RegionAt(base);
    if (r == kNone) {
        ++m_model.quality.releaseUnknownRegion;
        return Emit(EventKind::UnmapView, c, kNone, base, 0, 0);
    }
    Region const reg = m_model.regions[r];
    CloseRegion(r, evt);
    m_model.regions[r].releaseStack = c.stack;
    return Emit(EventKind::UnmapView, c, r, reg.base, reg.size, 0);
}

uint32_t VmModel::Unplaced(EventKind k, Ctx const& c, uint64_t base, uint64_t size, uint32_t aux)
{
    ++m_model.quality.unplacedVm;
    return Emit(k, c, kNone, base, size, aux, EvOutUnknown);
}

uint32_t VmModel::AddImage(uint64_t base, uint64_t size, uint32_t moduleIndex, uint32_t loadEvt)
{
    uint32_t r = RegionAt(base);
    if (r != kNone && m_model.regions[r].base == base && m_model.regions[r].kind == static_cast<uint32_t>(RegionKind::Mapped)) {
        // The loader's NtMapViewOfSection of the image section: relabel it.
        Account(m_model.spans[m_live[r].pieces.begin()->second.span], -1);
        m_model.regions[r].kind = static_cast<uint32_t>(RegionKind::Image);
        Account(m_model.spans[m_live[r].pieces.begin()->second.span], +1);
        m_model.regions[r].heap = moduleIndex;
        return r;
    }
    Ctx const c{ 0, kNone, 0, kNone };
    r = NewRegion(base, size, RegionKind::Image, loadEvt, c, loadEvt == kNone ? RgnPreTrace : 0);
    m_model.regions[r].heap = moduleIndex;
    NewSpan(r, base, base + size, SpanState::Committed, 0, loadEvt);
    return r;
}

void VmModel::RemoveImage(uint32_t region, uint32_t unloadEvt)
{
    if (region != kNone && m_live.count(region)) CloseRegion(region, unloadEvt);
}

uint32_t VmModel::AddStack(uint64_t low, uint64_t high, uint32_t threadIndex, uint32_t createEvt)
{
    Ctx const c{ 0, kNone, 0, kNone };
    uint32_t const r = NewRegion(low, high - low, RegionKind::Stack, createEvt, c, createEvt == kNone ? RgnPreTrace : 0);
    m_model.regions[r].heap = threadIndex;
    NewSpan(r, low, high, SpanState::Committed, 0x04 /* PAGE_READWRITE */, createEvt);
    return r;
}

uint32_t VmModel::AddStaticRegion(uint64_t base, uint64_t size, RegionKind kind, uint32_t heap, uint32_t createEvt, uint32_t releaseEvt, uint32_t flags)
{
    uint32_t const id = static_cast<uint32_t>(m_model.regions.size());
    Region r{};
    r.base = base;
    r.size = size;
    r.kind = static_cast<uint32_t>(kind);
    r.createEvt = createEvt;
    r.releaseEvt = releaseEvt;
    r.heap = heap;
    r.createStack = kNone;
    r.releaseStack = kNone;
    r.flags = flags;
    m_model.regions.push_back(r);
    m_model.spans.push_back({ base, base + size, id, static_cast<uint16_t>(SpanState::Committed), 0, 0x04, createEvt, releaseEvt, 0 });
    return id;
}

} // namespace ttds
