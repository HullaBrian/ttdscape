#include "model/heap_model.h"

namespace ttds {

void HeapModel::SeedHeaps(uint64_t processHeap, std::vector<uint64_t> const& heaps)
{
    auto add = [&](uint64_t h, HeapKind k) {
        if (h == 0 || m_heapByHandle.count(h)) return;
        HeapInfo info;
        info.handle = h;
        info.kind = k;
        m_heapByHandle[h] = static_cast<uint32_t>(m_model.heaps.size());
        m_model.heaps.push_back(info);
    };
    add(processHeap, HeapKind::Process);
    for (uint64_t h : heaps) add(h, HeapKind::PreExisting);
}

uint32_t HeapModel::HeapId(uint64_t handle, uint32_t)
{
    auto it = m_heapByHandle.find(handle);
    if (it != m_heapByHandle.end()) return it->second;
    HeapInfo info;
    info.handle = handle;
    info.kind = HeapKind::Discovered;
    uint32_t const id = static_cast<uint32_t>(m_model.heaps.size());
    m_model.heaps.push_back(info);
    m_heapByHandle[handle] = id;
    return id;
}

uint32_t HeapModel::Emit(EventKind k, Ctx const& c, uint32_t id, uint64_t addr, uint64_t size, uint32_t heap, uint8_t extra)
{
    uint32_t const idx = static_cast<uint32_t>(m_model.events.size());
    m_model.events.push_back({ static_cast<uint8_t>(k), static_cast<uint8_t>(c.flags | extra), c.thread, id, addr, size, c.stack, heap });
    return idx;
}

uint32_t HeapModel::NewBlock(uint64_t addr, uint64_t size, uint32_t heap, uint32_t evt, Ctx const& c, uint32_t flags)
{
    uint32_t const id = static_cast<uint32_t>(m_model.blocks.size());
    Block b{};
    b.addr = addr;
    b.size = size;
    b.heap = heap;
    b.allocEvt = evt;
    b.freeEvt = kNone;
    b.allocStack = c.stack;
    b.freeStack = kNone;
    b.prev = kNone;
    b.flags = flags;
    b.allocThread = c.thread;
    b.freeThread = 0xFFFF;
    m_model.blocks.push_back(b);
    m_live[addr] = id;
    m_liveByHeap[heap].insert(id);
    m_liveBytes += size;
    m_freedAddrs.erase(addr);
    return id;
}

void HeapModel::CloseBlock(uint32_t id, uint32_t evt, Ctx const& c, uint32_t flags)
{
    Block& b = m_model.blocks[id];
    b.freeEvt = evt;
    b.freeStack = c.stack;
    b.freeThread = c.thread;
    b.flags |= flags;
    if (b.allocEvt != kNone && b.allocThread != c.thread && !(flags & BlkImplicitFree)) b.flags |= BlkCrossThread;
    auto it = m_live.find(b.addr);
    if (it != m_live.end() && it->second == id) m_live.erase(it);
    m_liveByHeap[b.heap].erase(id);
    m_liveBytes -= std::min(m_liveBytes, b.size);
    m_freedAddrs.insert(b.addr);
}

void HeapModel::CloseOverlapping(uint64_t addr, uint64_t size, uint32_t evt, Ctx const& c)
{
    uint64_t const end = addr + std::max<uint64_t>(size, 1);
    auto it = m_live.upper_bound(addr);
    if (it != m_live.begin()) --it;
    while (it != m_live.end() && it->first < end) {
        Block const& b = m_model.blocks[it->second];
        uint64_t const bEnd = b.addr + std::max<uint64_t>(b.size, 1);
        uint32_t const id = it->second;
        ++it;
        if (bEnd > addr) {
            CloseBlock(id, evt, c, BlkSuperseded);
            ++m_model.quality.superseded;
        }
    }
}

void HeapModel::Alloc(Ctx const& c, uint64_t heap, uint64_t size, uint64_t result)
{
    uint32_t const h = HeapId(heap, 0);
    uint32_t const evt = static_cast<uint32_t>(m_model.events.size());
    if (result == 0) {
        Emit(EventKind::AllocFailed, c, kNone, 0, size, h, EvFailed);
        return;
    }
    size_t const supersededBefore = m_model.quality.superseded;
    CloseOverlapping(result, size, evt, c);
    uint32_t const id = NewBlock(result, size, h, evt, c, 0);
    Emit(EventKind::Alloc, c, id, result, size, h, m_model.quality.superseded != supersededBefore ? EvExtra : 0);
    ++m_allocs;
}

void HeapModel::Free(Ctx const& c, uint64_t heap, uint64_t ptr, bool succeeded)
{
    if (ptr == 0) return;
    uint32_t const h = HeapId(heap, 0);
    uint32_t const evt = static_cast<uint32_t>(m_model.events.size());
    if (!succeeded) {
        Emit(EventKind::Free, c, kNone, ptr, 0, h, EvFailed);
        return;
    }
    auto it = m_live.find(ptr);
    if (it != m_live.end()) {
        uint32_t const id = it->second;
        uint32_t const crossFlag = m_model.blocks[id].allocThread != c.thread && m_model.blocks[id].allocEvt != kNone ? EvCrossThread : 0;
        uint64_t const size = m_model.blocks[id].size;
        CloseBlock(id, evt, c, (c.flags & EvUnwound) ? BlkFreeUnwound : 0);
        Emit(EventKind::Free, c, id, ptr, size, m_model.blocks[id].heap, static_cast<uint8_t>(crossFlag));
        ++m_frees;
        return;
    }
    if (m_freedAddrs.count(ptr)) {
        ++m_model.quality.doubleFree;
        Emit(EventKind::FreeUnknown, c, kNone, ptr, 0, h, EvExtra);
        return;
    }
    // A block allocated before the recording started.
    ++m_model.quality.preTraceFrees;
    uint32_t const id = static_cast<uint32_t>(m_model.blocks.size());
    Block b{};
    b.addr = ptr;
    b.size = 0;
    b.heap = h;
    b.allocEvt = kNone;
    b.freeEvt = evt;
    b.allocStack = kNone;
    b.freeStack = c.stack;
    b.prev = kNone;
    b.flags = BlkPreTrace | BlkSizeUnknown;
    b.allocThread = 0xFFFF;
    b.freeThread = c.thread;
    m_model.blocks.push_back(b);
    m_freedAddrs.insert(ptr);
    Emit(EventKind::FreeUnknown, c, id, ptr, 0, h);
    ++m_frees;
}

void HeapModel::ReAlloc(Ctx const& c, uint64_t heap, uint64_t oldPtr, uint64_t size, uint64_t result)
{
    uint32_t const h = HeapId(heap, 0);
    uint32_t const evt = static_cast<uint32_t>(m_model.events.size());
    if (result == 0) {
        Emit(EventKind::ReAlloc, c, kNone, oldPtr, size, h, EvFailed);
        return;
    }
    uint32_t prev = kNone;
    if (oldPtr != 0) {
        auto it = m_live.find(oldPtr);
        if (it != m_live.end()) {
            prev = it->second;
            CloseBlock(prev, evt, c, BlkRealloced);
        } else {
            // Predecessor allocated before the recording.
            ++m_model.quality.preTraceFrees;
            prev = static_cast<uint32_t>(m_model.blocks.size());
            Block b{};
            b.addr = oldPtr;
            b.heap = h;
            b.allocEvt = kNone;
            b.freeEvt = evt;
            b.allocStack = kNone;
            b.freeStack = c.stack;
            b.prev = kNone;
            b.flags = BlkPreTrace | BlkSizeUnknown | BlkRealloced;
            b.allocThread = 0xFFFF;
            b.freeThread = c.thread;
            m_model.blocks.push_back(b);
        }
    }
    CloseOverlapping(result, size, evt, c);
    uint32_t const id = NewBlock(result, size, h, evt, c, result == oldPtr ? BlkInPlace : 0);
    m_model.blocks[id].prev = prev;
    Emit(EventKind::ReAlloc, c, id, result, size, h);
    ++m_allocs;
    ++m_frees;
}

void HeapModel::Create(Ctx const& c, uint64_t handle, uint32_t flags)
{
    uint32_t const evt = static_cast<uint32_t>(m_model.events.size());
    if (handle == 0) {
        Emit(EventKind::HeapCreate, c, kNone, 0, 0, kNone, EvFailed);
        return;
    }
    HeapInfo info;
    info.handle = handle;
    info.kind = HeapKind::Created;
    info.createEvt = evt;
    info.createFlags = flags;
    info.createStack = c.stack;
    uint32_t const id = static_cast<uint32_t>(m_model.heaps.size());
    m_model.heaps.push_back(info);
    m_heapByHandle[handle] = id; // a reused handle starts a new heap identity
    Emit(EventKind::HeapCreate, c, id, handle, 0, id);
}

void HeapModel::Destroy(Ctx const& c, uint64_t handle)
{
    uint32_t const h = HeapId(handle, 0);
    uint32_t const evt = static_cast<uint32_t>(m_model.events.size());
    uint64_t freedBytes = 0;
    auto it = m_liveByHeap.find(h);
    if (it != m_liveByHeap.end()) {
        std::vector<uint32_t> ids(it->second.begin(), it->second.end());
        for (uint32_t id : ids) {
            freedBytes += m_model.blocks[id].size;
            CloseBlock(id, evt, c, BlkImplicitFree);
        }
    }
    m_model.heaps[h].destroyEvt = evt;
    m_heapByHandle.erase(handle);
    Emit(EventKind::HeapDestroy, c, h, handle, freedBytes, h);
}

} // namespace ttds
