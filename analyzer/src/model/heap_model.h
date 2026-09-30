#pragma once
#include "model/types.h"

#include <map>
#include <unordered_map>
#include <unordered_set>

namespace ttds {

// Replays heap operations (in timeline order) into block lifetimes.
// Every method takes the index of the event it is emitting; it appends that event to 'events'.
class HeapModel
{
public:
    HeapModel(Model& model) : m_model(model) {}

    // Heaps known at the start of the trace (PEB.ProcessHeap and PEB.ProcessHeaps[]).
    void SeedHeaps(uint64_t processHeap, std::vector<uint64_t> const& heaps);

    struct Ctx { uint16_t thread; uint32_t stack; uint8_t flags; };

    void Alloc(Ctx const& c, uint64_t heap, uint64_t size, uint64_t result);
    void Free(Ctx const& c, uint64_t heap, uint64_t ptr, bool succeeded);
    void ReAlloc(Ctx const& c, uint64_t heap, uint64_t oldPtr, uint64_t size, uint64_t result);
    void Create(Ctx const& c, uint64_t handle, uint32_t flags);
    void Destroy(Ctx const& c, uint64_t handle);

    // Current live bytes / blocks (for the time series).
    bool IsLive(uint64_t ptr) const { return m_live.count(ptr) != 0; }
    uint64_t LiveBytes() const noexcept { return m_liveBytes; }
    uint64_t LiveBlocks() const noexcept { return m_live.size(); }
    uint64_t Allocs() const noexcept { return m_allocs; }
    uint64_t Frees() const noexcept { return m_frees; }

    // Blocks never freed are left with freeEvt == kNone.
    void Finish() {}

private:
    uint32_t HeapId(uint64_t handle, uint32_t evt);
    uint32_t NewBlock(uint64_t addr, uint64_t size, uint32_t heap, uint32_t evt, Ctx const& c, uint32_t flags);
    void     CloseBlock(uint32_t id, uint32_t evt, Ctx const& c, uint32_t flags);
    void     CloseOverlapping(uint64_t addr, uint64_t size, uint32_t evt, Ctx const& c);
    uint32_t Emit(EventKind k, Ctx const& c, uint32_t id, uint64_t addr, uint64_t size, uint32_t heap, uint8_t extraFlags = 0);

    Model& m_model;
    std::unordered_map<uint64_t, uint32_t> m_heapByHandle;     // live heaps
    std::map<uint64_t, uint32_t>           m_live;             // addr -> block id (live)
    std::unordered_map<uint32_t, std::unordered_set<uint32_t>> m_liveByHeap;
    std::unordered_set<uint64_t>           m_freedAddrs;       // addresses whose last block was freed
    uint64_t m_liveBytes = 0, m_allocs = 0, m_frees = 0;
};

} // namespace ttds
