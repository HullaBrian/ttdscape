#include "model/build.h"
#include "model/call_times.h"
#include "model/heap_model.h"
#include "model/vm_model.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <unordered_map>

namespace ttds {

namespace {

enum class ItemType : uint8_t { CallStart, CallEnd, ModuleLoad, ModuleUnload, ThreadCreate, ThreadExit, Marker, DirectSyscall };

struct Item
{
    Position pos;
    uint64_t order;
    ItemType type;
    uint32_t ref;
};

bool IsCurrentProcess(uint64_t h, bool is64) noexcept
{
    return is64 ? h == ~0ull : (h & 0xFFFFFFFFull) == 0xFFFFFFFFull;
}

std::vector<uint64_t> ReadPebHeaps(Trace const& trace, uint64_t& processHeap)
{
    std::vector<uint64_t> heaps;
    processHeap = 0;
    uint64_t const peb = A(trace.Engine().GetPebAddress());
    if (!peb) return heaps;
    UniqueCursor cur = trace.NewCursor();
    // The PEB fields are stable; read them where the main thread first runs.
    Threads(&trace.Engine()).empty() ? cur->SetPosition(Position::Min)
        : cur->SetPosition(trace.Engine().GetThreadList()[0].ActiveTime.Min);
    bool const x64 = trace.Is64();
    auto rdPtr = [&](uint64_t a) -> uint64_t {
        if (x64) return ReadValue<uint64_t>(*cur, a, QueryMemoryPolicy::GloballyAggressive).value_or(0);
        return ReadValue<uint32_t>(*cur, a, QueryMemoryPolicy::GloballyAggressive).value_or(0);
    };
    processHeap = rdPtr(peb + (x64 ? 0x30 : 0x18));
    uint32_t const n = ReadValue<uint32_t>(*cur, peb + (x64 ? 0xE8 : 0x88), QueryMemoryPolicy::GloballyAggressive).value_or(0);
    uint64_t const list = rdPtr(peb + (x64 ? 0xF0 : 0x90));
    for (uint32_t i = 0; list && i < std::min<uint32_t>(n, 256); ++i) {
        uint64_t const h = rdPtr(list + uint64_t{ i } * trace.PtrSize());
        if (h) heaps.push_back(h);
    }
    return heaps;
}

std::vector<MarkerOut> ReadMarkers(Trace const& trace, size_t max, std::vector<Position>& positions)
{
    std::vector<MarkerOut> out;
    UniqueCursor cur = trace.NewCursor();
    for (ExceptionEvent const& ex : ExceptionEvents(&trace.Engine())) {
        if (out.size() >= max) break;
        if (ex.Type != ExceptionType::DebugPrint || ex.ParameterCount < 2) continue;
        bool const wide = ex.Code == 0x4001000A;
        uint64_t const len = std::min<uint64_t>(ex.Parameters[0], 1024);
        uint64_t const addr = ex.Parameters[1];
        if (!len || !addr) continue;
        cur->SetPosition(ex.Position);
        std::string text;
        if (wide) {
            std::wstring w(static_cast<size_t>(len), L'\0');
            size_t const got = ReadGuest(*cur, addr, { reinterpret_cast<uint8_t*>(w.data()), w.size() * 2 }, QueryMemoryPolicy::GloballyAggressive);
            w.resize(got / 2);
            text = Narrow(w);
        } else {
            text.resize(static_cast<size_t>(len));
            size_t const got = ReadGuest(*cur, addr, { reinterpret_cast<uint8_t*>(text.data()), text.size() }, QueryMemoryPolicy::GloballyAggressive);
            text.resize(got);
        }
        while (!text.empty() && (text.back() == '\0' || text.back() == '\n' || text.back() == '\r')) text.pop_back();
        if (auto z = text.find('\0'); z != std::string::npos) text.resize(z);
        MarkerOut m;
        m.thread = 0;
        for (size_t i = 0; i < trace.Engine().GetThreadCount(); ++i)
            if (&trace.Engine().GetThreadList()[i] == ex.pThreadInfo) m.thread = static_cast<uint16_t>(i);
        // OutputDebugStringA raises DBG_PRINTEXCEPTION_WIDE_C and then, if nobody handled it,
        // DBG_PRINTEXCEPTION_C with the same text: keep one.
        if (!out.empty() && out.back().thread == m.thread && out.back().text == text) continue;
        m.text = std::move(text);
        out.push_back(std::move(m));
        positions.push_back(ex.Position);
    }
    return out;
}

class Builder
{
public:
    Builder(Trace const& trace, CaptureResult const& cap, BuildOptions const& opts)
        : m_trace(trace), m_cap(cap), m_opts(opts), m_heap(m_model), m_vm(m_model) {}

    Model Run()
    {
        uint64_t processHeap = 0;
        auto const heaps = ReadPebHeaps(m_trace, processHeap);
        m_heap.SeedHeaps(processHeap, heaps);
        if (!processHeap) m_model.warnings.push_back("could not read PEB.ProcessHeap");

        CollectModules();
        CollectThreads();
        std::vector<Position> markerPos;
        m_model.markers = ReadMarkers(m_trace, m_opts.maxMarkers, markerPos);

        std::vector<Item> items;
        items.reserve(m_cap.calls.size() + m_model.modules.size() * 2 + m_model.threads.size() * 2 + m_model.markers.size());
        for (uint32_t i = 0; i < m_cap.calls.size(); ++i) {
            RawCall const& c = m_cap.calls[i];
            bool const atStart = c.kind == HookKind::RtlFreeHeap || c.kind == HookKind::RtlDestroyHeap;
            if (atStart) items.push_back({ c.callPos, uint64_t{ i } * 2 + 1, ItemType::CallStart, i });
            else if (c.flags & CallReturned) items.push_back({ c.retPos, uint64_t{ i } * 2 + 1, ItemType::CallEnd, i });
            else ++m_model.quality.neverReturned;
        }
        for (uint32_t i = 0; i < m_model.modules.size(); ++i) {
            items.push_back({ m_moduleLoadPos[i], 0, ItemType::ModuleLoad, i });
            if (m_moduleUnloadPos[i].IsValid()) items.push_back({ m_moduleUnloadPos[i], 0, ItemType::ModuleUnload, i });
        }
        for (uint32_t i = 0; i < m_model.threads.size(); ++i) {
            items.push_back({ m_threadCreatePos[i], 0, ItemType::ThreadCreate, i });
            if (m_threadExitPos[i].IsValid()) items.push_back({ m_threadExitPos[i], ~0ull, ItemType::ThreadExit, i });
        }
        for (uint32_t i = 0; i < m_model.markers.size(); ++i) items.push_back({ markerPos[i], 0, ItemType::Marker, i });
        for (uint32_t i = 0; i < m_cap.directSyscalls.size(); ++i)
            items.push_back({ m_cap.directSyscalls[i].pos, 0, ItemType::DirectSyscall, i });

        std::stable_sort(items.begin(), items.end(), [](Item const& a, Item const& b) {
            return a.pos != b.pos ? a.pos < b.pos : a.order < b.order;
        });

        // Capture order vs position order (informational; see ReplayAPI.md landmine 30).
        {
            Position last = Position::Min;
            for (auto const& c : m_cap.calls) {
                if (c.callPos < last) ++m_model.quality.positionOrderViolations;
                last = c.callPos;
            }
        }

        InitSeries(items.size());
        for (Item const& it : items) {
            size_t const before = m_model.events.size();
            Apply(it);
            for (size_t e = before; e < m_model.events.size(); ++e) {
                m_model.positions.push_back({ U(it.pos.Sequence), U(it.pos.Steps) });
                Sample();
            }
        }
        FinishSeries();
        InferHeapRegions();
        MapExportCalls();

        auto const& st = m_cap.stats;
        QualityOut& q = m_model.quality;
        q.unwound = st.unwound;
        q.unmatchedRets = st.unmatchedRets;
        q.tailCalls = st.tailCalls;
        q.kernelCalls = st.kernelCalls;
        q.directSyscalls = st.kernelCallsOutsideNtdll;
        for (auto const& c : m_cap.calls) {
            if (c.out.oldProt.slot && c.out.oldProt.src == OutSrc::Unknown) ++q.oldProtectFromModel;
            for (OutField const* f : { &c.out.base, &c.out.size, &c.out.oldProt }) {
                if (!f->slot && f->src == OutSrc::None) continue;
                if (f == &c.out.oldProt && f->src == OutSrc::Unknown) continue;
                switch (f->src) {
                case OutSrc::Computed: ++q.outComputed; break;
                case OutSrc::AtReturn: ++q.outAtReturn; break;
                case OutSrc::Readback: ++q.outReadback; break;
                case OutSrc::Seek: ++q.outSeek; break;
                case OutSrc::Unknown: ++q.outUnknown; break;
                default: break;
                }
            }
        }
        return std::move(m_model);
    }

private:
    void CollectModules()
    {
        IReplayEngine const& e = m_trace.Engine();
        PositionRange const life = e.GetLifetime();
        for (ModuleInstance const& mi : ModuleInstances(&e)) {
            Module const& m = *mi.pModule;
            ModuleOut mo;
            mo.path = Narrow(ModuleName(m));
            while (!mo.path.empty() && mo.path.back() == '\0') mo.path.pop_back();
            mo.name = Narrow(ModuleBaseName(m));
            mo.base = A(m.Address);
            mo.size = m.Size;
            mo.timestamp = m.Timestamp;
            mo.checksum = m.Checksum;
            m_model.modules.push_back(mo);
            Position load{ mi.LoadTime };
            if (!load.IsValid() || load < life.Min) load = life.Min;
            m_moduleLoadPos.push_back(load);
            Position unload{ mi.UnloadTime };
            if (!unload.IsValid() || unload >= life.Max || U(mi.UnloadTime) >= kAliveSentinelSeq) unload = Position::Invalid;
            m_moduleUnloadPos.push_back(unload);
        }
    }

    void CollectThreads()
    {
        IReplayEngine const& e = m_trace.Engine();
        PositionRange const life = e.GetLifetime();
        for (auto const& tr : m_cap.threads) {
            ThreadOut to;
            to.utid = tr.utid;
            to.osTid = tr.osTid;
            if (tr.stackBase && tr.deallocStack && tr.stackBase > tr.deallocStack) {
                to.stackLow = tr.deallocStack;
                to.stackHigh = tr.stackBase;
                to.stackSource = "teb";
            } else if (tr.spMax) {
                to.stackLow = PageDown(tr.spMin);
                to.stackHigh = PageUp(tr.spMax + 1);
                to.stackSource = "observed";
            }
            m_model.threads.push_back(to);
            ThreadInfo const& info = e.GetThreadInfo(UniqueThreadId{ tr.utid });
            Position create = info.Lifetime.Min;
            if (!create.IsValid() || create < life.Min) create = life.Min;
            m_threadCreatePos.push_back(create);
            Position exit = info.Lifetime.Max;
            if (!exit.IsValid() || U(exit.Sequence) >= kAliveSentinelSeq || exit >= life.Max) exit = Position::Invalid;
            m_threadExitPos.push_back(exit);
        }
        m_threadStackRegion.assign(m_model.threads.size(), kNone);
    }

    uint32_t EmitRaw(EventKind k, uint16_t thread, uint32_t id, uint64_t addr, uint64_t size, uint32_t stack, uint32_t aux, uint8_t flags)
    {
        uint32_t const idx = static_cast<uint32_t>(m_model.events.size());
        m_model.events.push_back({ static_cast<uint8_t>(k), flags, thread, id, addr, size, stack, aux });
        return idx;
    }

    uint32_t HeapOfOuter(RawCall const& c)
    {
        if (c.outer == kNone) return kNone;
        RawCall const& o = m_cap.calls[c.outer];
        if (!IsHeapHook(o.kind)) return kNone;
        // RtlCreateHeap's first argument is flags, not a heap; its segments belong to the result.
        uint64_t const handle = o.kind == HookKind::RtlCreateHeap ? o.ret : o.args[0];
        if (!handle) return kNone;
        for (uint32_t i = static_cast<uint32_t>(m_model.heaps.size()); i-- > 0;)
            if (m_model.heaps[i].handle == handle) return i;
        return kNone;
    }

    void Apply(Item const& it)
    {
        switch (it.type) {
        case ItemType::CallStart:
        case ItemType::CallEnd:
            ApplyCall(m_cap.calls[it.ref]);
            break;
        case ItemType::ModuleLoad: {
            ModuleOut& m = m_model.modules[it.ref];
            uint32_t const evt = EmitRaw(EventKind::ModuleLoad, 0, it.ref, m.base, m.size, kNone, 0, 0);
            m.loadEvt = evt;
            m.region = m_vm.AddImage(m.base, m.size, it.ref, evt);
            break;
        }
        case ItemType::ModuleUnload: {
            ModuleOut& m = m_model.modules[it.ref];
            uint32_t const evt = EmitRaw(EventKind::ModuleUnload, 0, it.ref, m.base, m.size, kNone, 0, 0);
            m.unloadEvt = evt;
            m_vm.RemoveImage(m.region, evt);
            break;
        }
        case ItemType::ThreadCreate: {
            ThreadOut& t = m_model.threads[it.ref];
            uint32_t const evt = EmitRaw(EventKind::ThreadCreate, static_cast<uint16_t>(it.ref), it.ref, t.stackLow, t.stackHigh - t.stackLow, kNone, 0, 0);
            t.createEvt = evt;
            if (t.stackHigh > t.stackLow) m_threadStackRegion[it.ref] = m_vm.AddStack(t.stackLow, t.stackHigh, it.ref, evt);
            break;
        }
        case ItemType::ThreadExit: {
            ThreadOut& t = m_model.threads[it.ref];
            uint32_t const evt = EmitRaw(EventKind::ThreadExit, static_cast<uint16_t>(it.ref), it.ref, t.stackLow, t.stackHigh - t.stackLow, kNone, 0, 0);
            t.exitEvt = evt;
            if (m_threadStackRegion[it.ref] != kNone) m_vm.CloseRegion(m_threadStackRegion[it.ref], evt);
            break;
        }
        case ItemType::Marker: {
            MarkerOut& m = m_model.markers[it.ref];
            m.evt = EmitRaw(EventKind::Marker, m.thread, it.ref, 0, 0, kNone, 0, 0);
            break;
        }
        case ItemType::DirectSyscall: {
            auto const& d = m_cap.directSyscalls[it.ref];
            EmitRaw(EventKind::DirectSyscall, d.thread, it.ref, d.pc, 0, kNone, 0, 0);
            break;
        }
        }
    }

    void ApplyCall(RawCall const& c)
    {
        uint8_t flags = 0;
        if (c.outer != kNone) flags |= EvNested;
        if (c.flags & CallUnwound) flags |= EvUnwound;
        bool const is64 = m_trace.Is64();

        if (IsHeapHook(c.kind)) {
            // Heap-internal calls. Measured on real traces: the LFH allocates its subsegments and
            // RtlCreateHeap its own bookkeeping from the heap itself with the internal flag
            // 0x800000; user blocks are later carved out of those allocations.
            constexpr uint64_t kHeapInternal = 0x800000;
            bool const allocLike = c.kind == HookKind::RtlAllocateHeap || c.kind == HookKind::RtlReAllocateHeap;
            if (allocLike && (c.args[1] & kHeapInternal)) { ++m_model.quality.nestedSkipped; return; }
            if (c.outer != kNone) {
                RawCall const& o = m_cap.calls[c.outer];
                bool const sameHeap = IsHeapHook(o.kind) && o.kind != HookKind::RtlCreateHeap && c.kind != HookKind::RtlCreateHeap &&
                                      o.args[0] == c.args[0];
                // ReAlloc implemented through Alloc/Free on the same heap, or Alloc re-entering
                // itself: the outer call is the operation.
                if (sameHeap && (o.kind == HookKind::RtlReAllocateHeap || (o.kind == HookKind::RtlAllocateHeap && allocLike))) {
                    ++m_model.quality.nestedSkipped;
                    return;
                }
                // Other nested frees release heap-internal blocks we never tracked; apply them only
                // when they free a block we know.
                if (c.kind == HookKind::RtlFreeHeap && IsHeapHook(o.kind) && !m_heap.IsLive(c.args[2])) {
                    ++m_model.quality.nestedSkipped;
                    return;
                }
            }
            HeapModel::Ctx const hc{ c.thread, c.stack, flags };
            bool const returned = (c.flags & CallReturned) != 0;
            switch (c.kind) {
            case HookKind::RtlAllocateHeap:   m_heap.Alloc(hc, c.args[0], c.args[2], c.ret); break;
            case HookKind::RtlFreeHeap:       m_heap.Free(hc, c.args[0], c.args[2], !returned || (c.ret & 0xFF) != 0); break;
            case HookKind::RtlReAllocateHeap: m_heap.ReAlloc(hc, c.args[0], c.args[2], c.args[3], c.ret); break;
            case HookKind::RtlCreateHeap: {
                m_heap.Create(hc, c.ret, static_cast<uint32_t>(c.args[0]));
                uint32_t const self = static_cast<uint32_t>(&c - m_cap.calls.data());
                if (c.ret) for (uint32_t r : m_createHeapRegions[self]) {
                    m_model.regions[r].kind = static_cast<uint32_t>(RegionKind::Heap);
                    m_model.regions[r].heap = static_cast<uint32_t>(m_model.heaps.size() - 1);
                }
                break;
            }
            case HookKind::RtlDestroyHeap:    m_heap.Destroy(hc, c.args[0]); break;
            default: break;
            }
            if ((c.flags & CallReturned) && c.kind == HookKind::RtlFreeHeap && (c.ret & 0xFF) == 0) ++m_model.quality.failedCalls;
            return;
        }

        // Virtual memory syscalls.
        if (!NtSuccess(c.ret)) { ++m_model.quality.failedCalls; return; }
        // NtMapViewOfSection(Section, Process, ...) is the only one with the process handle second.
        bool const mapKind = c.kind == HookKind::NtMapViewOfSection || c.kind == HookKind::NtMapViewOfSectionEx;
        uint64_t const proc = mapKind ? c.args[1] : c.args[0];
        auto const& o = c.out;
        auto outFlags = [&](std::initializer_list<OutField const*> fs) {
            uint8_t f = 0;
            for (auto const* x : fs) {
                if (x->src == OutSrc::AtReturn || x->src == OutSrc::Readback || x->src == OutSrc::Seek) f |= EvOutReadback;
                if (x->src == OutSrc::Unknown) f |= EvOutUnknown;
            }
            return f;
        };
        if (!IsCurrentProcess(proc, is64)) {
            ++m_model.quality.remoteCalls;
            EventKind k = EventKind::Reserve;
            switch (c.kind) {
            case HookKind::NtFreeVirtualMemory: k = EventKind::Release; break;
            case HookKind::NtProtectVirtualMemory: k = EventKind::Protect; break;
            case HookKind::NtMapViewOfSection: case HookKind::NtMapViewOfSectionEx: k = EventKind::MapView; break;
            case HookKind::NtUnmapViewOfSection: case HookKind::NtUnmapViewOfSectionEx: k = EventKind::UnmapView; break;
            default: break;
            }
            EmitRaw(k, c.thread, kNone, o.base.value ? o.base.value : o.base.pre, o.size.value ? o.size.value : o.size.pre,
                    c.stack, static_cast<uint32_t>(proc), static_cast<uint8_t>(flags | EvRemote | outFlags({ &o.base, &o.size })));
            return;
        }

        VmModel::Ctx vc{ c.thread, c.stack, flags, HeapOfOuter(c) };
        size_t const eventsBefore = m_model.events.size();
        struct Attribute {
            Builder& b; RawCall const& c; size_t before;
            ~Attribute() {
                // The heap handle does not exist until RtlCreateHeap returns: remember the regions it
                // reserved and label them when the create event is applied.
                if (c.outer == kNone || b.m_cap.calls[c.outer].kind != HookKind::RtlCreateHeap) return;
                for (size_t e = before; e < b.m_model.events.size(); ++e)
                    if (b.m_model.events[e].id != kNone && b.m_model.events[e].kind == static_cast<uint8_t>(EventKind::Reserve))
                        b.m_createHeapRegions[c.outer].push_back(b.m_model.events[e].id);
            }
        } attribute{ *this, c, eventsBefore };
        switch (c.kind) {
        case HookKind::NtAllocateVirtualMemory:
        case HookKind::NtAllocateVirtualMemoryEx: {
            uint32_t const type = static_cast<uint32_t>(c.kind == HookKind::NtAllocateVirtualMemory ? c.args[4] : c.args[3]);
            uint32_t const prot = static_cast<uint32_t>(c.kind == HookKind::NtAllocateVirtualMemory ? c.args[5] : c.args[4]);
            vc.flags |= outFlags({ &o.base, &o.size });
            if (!o.base.Resolved() || !o.size.Resolved())
                m_vm.Unplaced((type & kMemReserve) ? EventKind::Reserve : EventKind::Commit, vc, o.base.value, o.size.value, prot);
            else
                m_vm.Allocate(vc, o.base.value, o.size.value, type, prot);
            break;
        }
        case HookKind::NtFreeVirtualMemory: {
            uint32_t const type = static_cast<uint32_t>(c.args[3]);
            vc.flags |= outFlags({ &o.base, &o.size });
            if (!o.base.Resolved() || !o.base.value || !o.size.Resolved())
                m_vm.Unplaced((type & kMemRelease) ? EventKind::Release : EventKind::Decommit, vc, o.base.value, o.size.value, 0);
            else
                m_vm.Free(vc, o.base.value, o.size.value, type);
            break;
        }
        case HookKind::NtProtectVirtualMemory: {
            if (!o.base.Resolved() || !o.base.value || !o.size.Resolved()) {
                vc.flags |= outFlags({ &o.base, &o.size });
                m_vm.Unplaced(EventKind::Protect, vc, o.base.value, o.size.value, static_cast<uint32_t>(c.args[3]));
                break;
            }
            uint32_t const oldProt = o.oldProt.Resolved() ? static_cast<uint32_t>(o.oldProt.value) : 0;
            m_vm.Protect(vc, o.base.value, o.size.value, static_cast<uint32_t>(c.args[3]), oldProt);
            break;
        }
        case HookKind::NtMapViewOfSection:
        case HookKind::NtMapViewOfSectionEx: {
            uint32_t const prot = static_cast<uint32_t>(c.kind == HookKind::NtMapViewOfSection ? c.args[9] : c.args[6]);
            vc.flags |= outFlags({ &o.base, &o.size });
            if (!o.base.Resolved() || !o.size.Resolved()) m_vm.Unplaced(EventKind::MapView, vc, o.base.value, o.size.value, prot);
            else m_vm.MapView(vc, o.base.value, o.size.value, prot);
            break;
        }
        case HookKind::NtUnmapViewOfSection:
        case HookKind::NtUnmapViewOfSectionEx:
            m_vm.UnmapView(vc, c.args[1]);
            break;
        default:
            break;
        }
    }

    // ---- time series ----

    void InitSeries(size_t expectedEvents)
    {
        uint32_t const buckets = static_cast<uint32_t>(std::max<size_t>(1, std::min<size_t>(m_opts.seriesBuckets, expectedEvents)));
        m_epb = std::max<double>(1.0, std::ceil(static_cast<double>(expectedEvents) / buckets));
        for (char const* name : { "heapLive", "heapPeak", "heapBlocks", "committed", "reserved", "mapped", "allocs", "frees" })
            m_model.series.columns.push_back({ name, {} });
    }

    void Sample()
    {
        uint64_t const live = m_heap.LiveBytes();
        m_bucketPeak = std::max(m_bucketPeak, live);
        size_t const n = m_model.events.size();
        if (static_cast<double>(n) >= m_epb * static_cast<double>(m_bucketsDone + 1)) PushBucket();
    }

    void PushBucket()
    {
        auto& cols = m_model.series.columns;
        cols[0].second.push_back(static_cast<double>(m_heap.LiveBytes()));
        cols[1].second.push_back(static_cast<double>(m_bucketPeak));
        cols[2].second.push_back(static_cast<double>(m_heap.LiveBlocks()));
        cols[3].second.push_back(static_cast<double>(m_vm.Committed()));
        cols[4].second.push_back(static_cast<double>(m_vm.Reserved()));
        cols[5].second.push_back(static_cast<double>(m_vm.Mapped()));
        cols[6].second.push_back(static_cast<double>(m_heap.Allocs() - m_lastAllocs));
        cols[7].second.push_back(static_cast<double>(m_heap.Frees() - m_lastFrees));
        m_lastAllocs = m_heap.Allocs();
        m_lastFrees = m_heap.Frees();
        m_bucketPeak = m_heap.LiveBytes();
        ++m_bucketsDone;
    }

    void FinishSeries()
    {
        if (m_model.events.size() > static_cast<size_t>(m_epb * m_bucketsDone) || m_bucketsDone == 0) PushBucket();
        m_model.series.buckets = m_bucketsDone;
        m_model.series.eventsPerBucket = m_epb;
    }

    // ---- calls into module exports, placed on the event axis ----

    void MapExportCalls()
    {
        ExportSet const* exports = m_opts.exports;
        if (!exports) return;
        CallsOut& out = m_model.calls;
        out.recorded = true;
        out.exportModules = exports->modulesRead;
        out.exportModulesFromDisk = exports->modulesFromDisk;
        out.modulesWithoutExports = exports->unreadable;
        auto const& xs = m_cap.exportCalls;
        size_t const n = xs.size();
        auto pos16 = [](Position const& p) { return Position16{ U(p.Sequence), U(p.Steps) }; };

        // Output order: by CALL position (capture order breaks ties), which is also start-time order.
        std::vector<uint32_t> order(n);
        std::iota(order.begin(), order.end(), 0u);
        std::stable_sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) { return xs[a].callPos < xs[b].callPos; });

        // Keys: every CALL (indices [0, n)), then every RET ([n, n + returned)), ranked together.
        std::vector<Position16> keys(n);
        std::vector<uint8_t> after(n, 0);
        std::vector<uint32_t> retKey(n, kNone);
        for (uint32_t i = 0; i < n; ++i) keys[i] = pos16(xs[i].callPos);
        for (uint32_t i = 0; i < n; ++i) {
            if (!(xs[i].flags & CallReturned)) continue;
            retKey[i] = static_cast<uint32_t>(keys.size());
            keys.push_back(pos16(xs[i].retPos));
            after.push_back(1);
        }
        std::vector<uint32_t> evt(keys.size());
        std::vector<float> frac(keys.size());
        AssignEventTimes(m_model.positions, keys, after, evt.data(), frac.data());

        // Module of a code address, compared by base so reloaded instances count as one module.
        std::vector<uint32_t> byBase(m_model.modules.size());
        std::iota(byBase.begin(), byBase.end(), 0u);
        std::sort(byBase.begin(), byBase.end(), [&](uint32_t a, uint32_t b) { return m_model.modules[a].base < m_model.modules[b].base; });
        auto moduleBase = [&](uint64_t addr) -> uint64_t {
            auto it = std::upper_bound(byBase.begin(), byBase.end(), addr, [&](uint64_t a, uint32_t m) { return a < m_model.modules[m].base; });
            while (it != byBase.begin()) {
                ModuleOut const& m = m_model.modules[*--it];
                if (addr - m.base < m.size) return m.base;
                if (addr - m.base > (1ull << 32)) break;
            }
            return 0;
        };

        std::vector<uint32_t> newIndex(n), calleeIndex(exports->symbols.size(), kNone);
        for (uint32_t i = 0; i < n; ++i) newIndex[order[i]] = i;
        out.records.reserve(n);
        out.source.assign(order.begin(), order.end());
        for (uint32_t i = 0; i < n; ++i) {
            uint32_t const c = order[i];
            ExportCall const& x = xs[c];
            uint32_t& callee = calleeIndex[x.callee];
            if (callee == kNone) {
                ExportSym const& sym = exports->symbols[x.callee];
                callee = static_cast<uint32_t>(out.callees.size());
                out.callees.push_back({ sym.address, sym.module, sym.name });
            }
            uint64_t const from = x.via != kNone ? exports->symbols[xs[x.via].callee].address : x.caller;
            uint64_t const fromBase = moduleBase(from);
            uint8_t flags = x.flags & (CrReturned | CrUnwound | CrTail);
            if (fromBase && fromBase == moduleBase(exports->symbols[x.callee].address)) { flags |= CrSameModule; ++out.sameModule; }
            if (flags & CrTail) ++out.tailCalls;
            if (flags & CrUnwound) ++out.unwound;
            else if (!(flags & CrReturned)) ++out.neverReturned;
            out.stacks.push_back(x.stack);
            out.positions.push_back(pos16(x.callPos));
            out.positions.push_back(x.flags & CallReturned ? pos16(x.retPos) : Position16{ ~0ull, ~0ull });
            uint32_t const r = retKey[c];
            out.records.push_back({ x.thread, flags, x.depth, x.callerFrame, callee, evt[c], r == kNone ? kNone : evt[r],
                                    frac[c], r == kNone ? 0.0f : frac[r], x.via == kNone ? kNone : newIndex[x.via] });
        }
    }

    // ---- heap blocks outside any known region: pre-trace heap segments ----

    void InferHeapRegions()
    {
        // Sorted region extents (all time).
        std::vector<std::pair<uint64_t, uint64_t>> extents;
        for (auto const& r : m_model.regions) extents.push_back({ r.base, r.base + r.size });
        std::sort(extents.begin(), extents.end());
        // Prefix max of ends for containment tests.
        std::vector<uint64_t> maxEnd(extents.size());
        for (size_t i = 0; i < extents.size(); ++i) maxEnd[i] = std::max(extents[i].second, i ? maxEnd[i - 1] : 0);
        auto covered = [&](uint64_t a) {
            auto it = std::upper_bound(extents.begin(), extents.end(), std::make_pair(a, ~0ull));
            if (it == extents.begin()) return false;
            size_t const i = static_cast<size_t>(it - extents.begin()) - 1;
            return maxEnd[i] > a;
        };

        std::map<uint32_t, std::vector<std::pair<uint64_t, uint64_t>>> byHeap;
        for (auto const& b : m_model.blocks)
            if (!covered(b.addr)) byHeap[b.heap].push_back({ b.addr, b.addr + std::max<uint64_t>(b.size, 16) });

        constexpr uint64_t kGap = 1ull << 20;
        for (auto& [heap, v] : byHeap) {
            std::sort(v.begin(), v.end());
            uint64_t lo = v[0].first, hi = v[0].second;
            auto flush = [&] {
                HeapInfo const& h = m_model.heaps[heap];
                m_vm.AddStaticRegion(PageDown(lo), PageUp(hi) - PageDown(lo), RegionKind::HeapInferred, heap,
                                     h.createEvt, h.destroyEvt, RgnPreTrace);
            };
            for (size_t i = 1; i < v.size(); ++i) {
                if (v[i].first > hi + kGap) { flush(); lo = v[i].first; hi = v[i].second; }
                else hi = std::max(hi, v[i].second);
            }
            flush();
        }
    }

    Trace const&          m_trace;
    CaptureResult const&  m_cap;
    BuildOptions const&   m_opts;
    Model                 m_model;
    HeapModel             m_heap;
    VmModel               m_vm;
    std::vector<Position> m_moduleLoadPos, m_moduleUnloadPos, m_threadCreatePos, m_threadExitPos;
    std::vector<uint32_t> m_threadStackRegion;
    std::unordered_map<uint32_t, std::vector<uint32_t>> m_createHeapRegions;
    double   m_epb = 1;
    uint32_t m_bucketsDone = 0;
    uint64_t m_bucketPeak = 0, m_lastAllocs = 0, m_lastFrees = 0;
};

} // namespace

Model BuildModel(Trace const& trace, HookResolution const&, CaptureResult const& cap, BuildOptions const& opts)
{
    Builder b(trace, cap, opts);
    return b.Run();
}

} // namespace ttds
