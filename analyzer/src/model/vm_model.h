#pragma once
#include "model/types.h"

#include <map>

namespace ttds {

// Replays virtual-memory operations into regions (reservations / views / images / stacks) and
// spans: [start,end) page ranges with a constant (state, protect) over [startEvt, endEvt).
// The client answers "what did the address space look like at event i" with a stabbing query.
class VmModel
{
public:
    explicit VmModel(Model& model) : m_model(model) {}

    struct Ctx { uint16_t thread; uint32_t stack; uint8_t flags; uint32_t heap; /* heap id if nested in a heap call */ };

    // Each returns the emitted event index.
    uint32_t Allocate(Ctx const& c, uint64_t base, uint64_t size, uint32_t type, uint32_t protect);
    uint32_t Free(Ctx const& c, uint64_t base, uint64_t size, uint32_t type);
    uint32_t Protect(Ctx const& c, uint64_t base, uint64_t size, uint32_t protect, uint32_t oldProtect);
    uint32_t MapView(Ctx const& c, uint64_t base, uint64_t size, uint32_t protect);
    uint32_t UnmapView(Ctx const& c, uint64_t base);
    // Emits an event for a call whose placement is unknown (kept in the timeline, not in the model).
    uint32_t Unplaced(EventKind k, Ctx const& c, uint64_t base, uint64_t size, uint32_t aux);

    // Non-syscall regions (no event of their own; they use the given event indexes).
    uint32_t AddImage(uint64_t base, uint64_t size, uint32_t moduleIndex, uint32_t loadEvt);
    void     RemoveImage(uint32_t region, uint32_t unloadEvt);
    uint32_t AddStack(uint64_t low, uint64_t high, uint32_t threadIndex, uint32_t createEvt);
    void     CloseRegion(uint32_t region, uint32_t evt);
    // Region with its own span over its whole lifetime (used for inferred heap regions).
    uint32_t AddStaticRegion(uint64_t base, uint64_t size, RegionKind kind, uint32_t heap, uint32_t createEvt, uint32_t releaseEvt, uint32_t flags);

    // Region live at 'addr' now, or kNone.
    uint32_t RegionAt(uint64_t addr) const;

    uint64_t Reserved() const noexcept { return m_reserved; }
    uint64_t Committed() const noexcept { return m_committed; }
    uint64_t Mapped() const noexcept { return m_mapped; }

private:
    struct Piece { uint64_t end; uint32_t span; };
    struct Live { std::map<uint64_t, Piece> pieces; };

    uint32_t Emit(EventKind k, Ctx const& c, uint32_t id, uint64_t addr, uint64_t size, uint32_t aux, uint8_t extra = 0);
    uint32_t NewRegion(uint64_t base, uint64_t size, RegionKind kind, uint32_t evt, Ctx const& c, uint32_t flags);
    uint32_t NewSpan(uint32_t region, uint64_t start, uint64_t end, SpanState st, uint32_t protect, uint32_t evt);
    void     CloseSpan(uint32_t span, uint32_t evt);
    // Sets [a,b) of a live region to a new state/protect (state 0 = keep, protect ~0 = keep).
    void     Change(uint32_t region, uint64_t a, uint64_t b, uint16_t state, uint32_t protect, uint32_t evt);
    void     Account(Span const& s, int sign);
    uint32_t EnsureRegionFor(uint64_t a, uint64_t b, Ctx const& c, SpanState initial, uint32_t initialProtect);

    Model& m_model;
    std::map<uint64_t, uint32_t> m_liveRegions;   // base -> region id
    std::map<uint32_t, Live>     m_live;          // region id -> live pieces
    uint64_t m_reserved = 0, m_committed = 0, m_mapped = 0;
};

} // namespace ttds
