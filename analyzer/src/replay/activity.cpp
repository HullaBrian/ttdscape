#include "replay/activity.h"
#include "serve/memory_query.h"

#include <algorithm>
#include <stdexcept>
#include <tuple>
#include <unordered_map>

namespace ttds {

namespace {

constexpr uint64_t kPage = 0x1000;
constexpr uint64_t kLargePages = 64;    // blocks spanning more pages go to a short list
constexpr uint64_t kMaxExecPages = 16;  // pages credited per execute hit (CodeFetch ranges can be long)
constexpr size_t kMaxSnapshotReads = 256; // blocks read back after a DataMismatch (a seek each)

bool Less(Position16 const& a, Position16 const& b) { return a.seq != b.seq ? a.seq < b.seq : a.steps < b.steps; }
Position16 Pos16(Position const& p) { return { U(p.Sequence), U(p.Steps) }; }

// Module lookup by address, over a sorted index with the last hit cached (writes cluster).
class ModuleLookup
{
public:
    explicit ModuleLookup(std::vector<ModuleOut> const& modules)
    {
        for (auto const& m : modules) m_ranges.push_back({ m.base, m.base + m.size });
        std::sort(m_ranges.begin(), m_ranges.end());
    }
    bool Inside(uint64_t a)
    {
        if (m_last < m_ranges.size() && a >= m_ranges[m_last].first && a < m_ranges[m_last].second) return true;
        auto it = std::upper_bound(m_ranges.begin(), m_ranges.end(), std::pair<uint64_t, uint64_t>{ a, UINT64_MAX });
        while (it != m_ranges.begin()) {
            --it;
            if (a >= it->first && a < it->second) { m_last = static_cast<size_t>(it - m_ranges.begin()); return true; }
            if (a - it->first > (1ull << 32)) break;
        }
        return false;
    }
private:
    std::vector<std::pair<uint64_t, uint64_t>> m_ranges;
    size_t m_last = SIZE_MAX;
};

} // namespace

bool WatchedRegion(Region const& r)
{
    auto const k = static_cast<RegionKind>(r.kind);
    return k != RegionKind::Image && k != RegionKind::Stack && r.size > 0;
}

namespace {

std::vector<std::pair<uint64_t, uint64_t>> Union(std::vector<std::pair<uint64_t, uint64_t>> r)
{
    std::sort(r.begin(), r.end());
    std::vector<std::pair<uint64_t, uint64_t>> out;
    for (auto const& [s, e] : r) {
        if (!out.empty() && s <= out.back().second) out.back().second = std::max(out.back().second, e);
        else out.push_back({ s, e });
    }
    return out;
}

} // namespace

std::vector<std::pair<uint64_t, uint64_t>> WatchRanges(std::vector<Region> const& regions)
{
    std::vector<std::pair<uint64_t, uint64_t>> watched, stacks;
    for (auto const& x : regions) {
        if (WatchedRegion(x)) watched.push_back({ x.base, x.base + x.size });
        else if (static_cast<RegionKind>(x.kind) == RegionKind::Stack) stacks.push_back({ x.base, x.base + x.size });
    }
    // A stack's addresses stay out even when another region covers them at another time (an
    // inferred region, or a reuse): stack writes are most of a trace's writes and rarely interesting.
    watched = Union(std::move(watched));
    stacks = Union(std::move(stacks));
    std::vector<std::pair<uint64_t, uint64_t>> out;
    size_t k = 0;
    for (auto [s, e] : watched) {
        while (k < stacks.size() && stacks[k].second <= s) ++k;
        for (size_t j = k; j < stacks.size() && stacks[j].first < e && s < e; ++j) {
            if (stacks[j].first > s) out.push_back({ s, stacks[j].first });
            s = std::max(s, stacks[j].second);
        }
        if (s < e) out.push_back({ s, e });
    }
    return out;
}

ObjectIndex::ObjectIndex(Model const& model) : m_model(model)
{
    for (uint32_t b = 0; b < model.blocks.size(); ++b) {
        Block const& k = model.blocks[b];
        uint64_t const first = k.addr / kPage, last = (k.addr + std::max<uint64_t>(1, k.size) - 1) / kPage;
        if (last - first >= kLargePages) { m_large.push_back(b); continue; }
        for (uint64_t p = first; p <= last; ++p) m_pages[p].push_back(b);
    }
    for (uint32_t r = 0; r < model.regions.size(); ++r) m_regionsByBase.push_back(r);
    std::sort(m_regionsByBase.begin(), m_regionsByBase.end(), [&](uint32_t a, uint32_t b) { return model.regions[a].base < model.regions[b].base; });
}

uint32_t ObjectIndex::BlockAt(uint64_t addr, uint32_t evt) const
{
    uint32_t best = kNone;
    auto check = [&](uint32_t b) {
        Block const& k = m_model.blocks[b];
        if (addr < k.addr || addr - k.addr >= std::max<uint64_t>(1, k.size)) return;
        if (k.allocEvt != kNone && k.allocEvt > evt) return;
        if (k.freeEvt != kNone && k.freeEvt < evt) return;
        if (best == kNone || k.size < m_model.blocks[best].size) best = b;
    };
    if (auto it = m_pages.find(addr / kPage); it != m_pages.end()) for (uint32_t b : it->second) check(b);
    for (uint32_t b : m_large) check(b);
    return best;
}

bool ObjectIndex::PageHasBlocks(uint64_t addr) const
{
    if (m_pages.count(addr / kPage)) return true;
    for (uint32_t b : m_large) {
        Block const& k = m_model.blocks[b];
        if (addr / kPage >= k.addr / kPage && addr / kPage <= (k.addr + k.size - 1) / kPage) return true;
    }
    return false;
}

uint32_t ObjectIndex::RegionAt(uint64_t addr, uint32_t evt) const
{
    auto fits = [&](uint32_t r) {
        Region const& x = m_model.regions[r];
        return addr >= x.base && addr - x.base < x.size && (x.createEvt == kNone || x.createEvt <= evt) && (x.releaseEvt == kNone || x.releaseEvt >= evt);
    };
    if (m_lastRegion != kNone && fits(m_lastRegion)) return m_lastRegion;
    // Innermost (smallest) region; regions overlap only across time, so this is usually one match.
    uint32_t best = kNone;
    auto it = std::upper_bound(m_regionsByBase.begin(), m_regionsByBase.end(), addr,
                               [&](uint64_t a, uint32_t r) { return a < m_model.regions[r].base; });
    for (auto k = m_regionsByBase.begin(); k != it; ++k)
        if (fits(*k) && (best == kNone || m_model.regions[*k].size < m_model.regions[best].size)) best = *k;
    m_lastRegion = best;
    return best;
}

ActivityOut RunActivity(Trace const& trace, Model const& model, StackTrie& stacks, ActivityOptions const& opts, SnapshotOut* snapshots)
{
    ULONGLONG const t0 = GetTickCount64();
    ActivityOut out;
    out.recorded = true;
    out.exec = opts.exec == ExecDetect::Execute ? "execute" : opts.exec == ExecDetect::CodeFetch ? "codefetch" : "none";
    if (model.positions.empty()) return out;

    ObjectIndex const index(model);
    ModuleLookup modules(model.modules);
    std::unordered_map<uint32_t, uint16_t> threadOf;
    for (size_t i = 0; i < model.threads.size(); ++i) threadOf[model.threads[i].utid] = static_cast<uint16_t>(i);
    uint32_t const buckets = std::max<uint32_t>(1, model.series.buckets);
    double const epb = std::max(1.0, model.series.eventsPerBucket);
    uint32_t const lastEvt = static_cast<uint32_t>(model.events.size() - 1);

    // Per written object: key = block, or (1 << 63) | region << 32 | page.
    struct Obj
    {
        uint32_t block = kNone, region = kNone, page = kNone;
        uint32_t home = kNone; // the region holding the object (for flows)
        Position16 firstPos{ UINT64_MAX, UINT64_MAX }, lastPos{};
        uint64_t firstPc = 0, lastPc = 0;
        uint32_t firstEvt = 0, lastEvt = 0, writes = 0;
        uint16_t firstThread = 0xFFFF, lastThread = 0xFFFF;
        bool unbacked = false;
        std::vector<std::pair<uint32_t, uint32_t>> cells; // (bucket, writes), mostly in order
    };
    std::unordered_map<uint64_t, Obj> objects;
    // Per page address: the last write, for write-then-execute.
    struct PageState
    {
        uint64_t writes = 0, lastPc = 0;
        Position16 lastPos{};
        uint32_t lastEvt = 0;
        uint16_t lastThread = 0xFFFF;
        bool writtenSinceExec = false, reported = false;
    };
    std::unordered_map<uint64_t, PageState> pages;
    std::vector<WxFinding> wx;
    // Snapshots: each block's first `cap` bytes rebuilt from the writes into it (last write wins),
    // and the blocks whose bytes changed outside the thread's view (the kernel: a recv buffer).
    struct Snap { std::vector<uint8_t> bytes, known; };
    std::unordered_map<uint32_t, Snap> snaps;
    uint32_t const cap = snapshots ? std::max<uint32_t>(1, opts.snapshotCap) : 0;
    // A DataMismatch callback still sees the old bytes (landmine 27); the thread's view has the new
    // ones by its next callback, where they are taken. Those left pending at the end are read back.
    struct Pending { uint32_t block; uint64_t addr, size; Position16 pos; };
    std::unordered_map<uint32_t, std::vector<Pending>> pending; // by utid
    size_t pendingCount = 0;
    std::vector<uint32_t> mismatched;
    auto snapOf = [&](uint32_t block) -> Snap& {
        Snap& snap = snaps[block];
        size_t const len = static_cast<size_t>(std::min<uint64_t>(model.blocks[block].size, cap));
        if (snap.bytes.size() != len) { snap.bytes.assign(len, 0); snap.known.assign(len, 0); }
        return snap;
    };
    auto take = [&](IThreadView const* t, Snap& snap, uint64_t base, uint64_t a, uint64_t size) {
        uint64_t const off = a - base;
        if (a < base || off >= snap.bytes.size()) return;
        size_t const n = static_cast<size_t>(std::min<uint64_t>(std::max<uint64_t>(1, size), snap.bytes.size() - off));
        MemoryBuffer const mb = t->QueryMemoryBuffer(GuestAddress{ a }, BufferView{ snap.bytes.data() + off, n });
        std::fill_n(snap.known.data() + off, mb.Memory.Size, uint8_t{ 1 });
    };

    auto ranges = WatchRanges(model.regions);
    UniqueCursor cursor = trace.NewCursor();
    DataAccessMask mask = DataAccessMask::Write;
    if (opts.exec == ExecDetect::CodeFetch) mask = mask | DataAccessMask::CodeFetch;
    if (opts.exec == ExecDetect::Execute) mask = mask | DataAccessMask::Execute;
    if (snapshots) mask = mask | DataAccessMask::DataMismatch;
    for (auto const& [s, e] : ranges) {
        if (!cursor->AddMemoryWatchpoint(MemoryWatchpointData{ GuestAddress{ s }, e - s, mask })) // landmine 22
            throw std::runtime_error(std::format("AddMemoryWatchpoint failed for {}", Hex(s)));
        out.bytesWatched += e - s;
    }
    out.ranges = ranges.size();

    // Writes cluster by position, object and page: the last answer of each lookup is kept with the
    // span it holds for (the callback runs millions of times on unpacking code).
    auto const& P = model.positions;
    uint32_t cachedEvt = 0;
    auto eventOf = [&](Position16 const& pos) {
        size_t const n = P.size();
        bool const hit = (cachedEvt == 0 || Less(P[cachedEvt - 1], pos)) && (cachedEvt == n || !Less(P[cachedEvt], pos));
        if (!hit) cachedEvt = EventAtOrAfter(P, pos);
        return std::min(lastEvt, cachedEvt);
    };
    struct { uint64_t lo = 1, hi = 0; uint32_t evtLo = 1, evtHi = 0; Obj* obj = nullptr; Snap* snap = nullptr; } oc;
    struct { uint64_t lo = 1, hi = 0; uint32_t evtLo = 1, evtHi = 0; uint32_t region = kNone; } cc; // code region cache
    std::unordered_map<uint64_t, uint32_t> flows; // bucket << 40 | from << 20 | to (20 bits each; kNone -> 0xFFFFF)
    uint64_t lastFlowKey = UINT64_MAX;
    uint32_t* lastFlow = nullptr;
    uint64_t cachedPage = UINT64_MAX;
    PageState* cachedState = nullptr;

    auto onHit = [&](ICursorView::MemoryWatchpointResult const& hit, IThreadView const* t) noexcept -> bool {
        Position16 const pos = Pos16(t->GetPosition());
        uint32_t const evt = eventOf(pos);
        auto const th = threadOf.find(U(t->GetThreadInfo().UniqueId));
        uint16_t const thread = th == threadOf.end() ? 0xFFFF : th->second;
        uint64_t const a = A(hit.Address);
        if (pendingCount) {
            auto it = pending.find(U(t->GetThreadInfo().UniqueId));
            if (it != pending.end() && !it->second.empty() && Less(it->second.back().pos, pos)) {
                for (Pending const& p : it->second) take(t, snapOf(p.block), model.blocks[p.block].addr, p.addr, p.size);
                pendingCount -= it->second.size();
                it->second.clear();
            }
        }

        if (hit.AccessType == DataAccessType::Write) {
            ++out.writes;
            uint64_t const pc = A(t->GetProgramCounter());
            if (!(a >= oc.lo && a < oc.hi && evt >= oc.evtLo && evt <= oc.evtHi)) {
                uint32_t const block = index.BlockAt(a, evt);
                uint32_t const region = block != kNone ? kNone : index.RegionAt(a, evt);
                uint32_t const page = block != kNone || region == kNone ? kNone : static_cast<uint32_t>((a - model.regions[region].base) / kPage);
                uint64_t const key = block != kNone ? block : (1ull << 63) | (static_cast<uint64_t>(region) << 32) | page;
                Obj& o = objects[key];
                if (!o.writes) { o.block = block; o.region = region; o.page = page; o.home = block != kNone ? index.RegionAt(a, evt) : region; }
                // A block's answer holds over its extent and lifetime. "No block here" holds for the
                // whole page at this event only on a page no block ever touches (unpacked code,
                // mapped views); on a heap page it holds for this address alone.
                if (block != kNone) {
                    Block const& k = model.blocks[block];
                    Snap* snap = nullptr;
                    if (cap && !(k.flags & BlkSizeUnknown)) snap = &snapOf(block);
                    oc = { k.addr, k.addr + std::max<uint64_t>(1, k.size), k.allocEvt == kNone ? 0 : k.allocEvt, k.freeEvt == kNone ? UINT32_MAX : k.freeEvt, &o, snap };
                } else if (!index.PageHasBlocks(a)) {
                    oc = { a & ~(kPage - 1), (a & ~(kPage - 1)) + kPage, evt, evt, &o, nullptr };
                } else {
                    oc = { a, a + 1, evt, evt, &o, nullptr };
                }
            }
            Obj& o = *oc.obj;
            ++o.writes;
            if (Less(pos, o.firstPos)) { o.firstPos = pos; o.firstPc = pc; o.firstEvt = evt; o.firstThread = thread; }
            if (!Less(pos, o.lastPos)) { o.lastPos = pos; o.lastPc = pc; o.lastEvt = evt; o.lastThread = thread; }
            if (!modules.Inside(pc)) o.unbacked = true;
            uint32_t const bucket = std::min(buckets - 1, static_cast<uint32_t>(evt / epb));
            // Flow: the region of the writing code (cached over its extent and lifetime) -> the object's.
            if (!(pc >= cc.lo && pc < cc.hi && evt >= cc.evtLo && evt <= cc.evtHi)) {
                uint32_t const r = index.RegionAt(pc, evt);
                if (r != kNone) {
                    Region const& x = model.regions[r];
                    cc = { x.base, x.base + x.size, x.createEvt == kNone ? 0 : x.createEvt, x.releaseEvt == kNone ? UINT32_MAX : x.releaseEvt, r };
                } else {
                    cc = { pc, pc + 1, evt, evt, kNone };
                }
            }
            uint64_t const flowKey = (static_cast<uint64_t>(bucket) << 40) | (static_cast<uint64_t>(cc.region & 0xFFFFF) << 20) | (o.home & 0xFFFFF);
            if (flowKey != lastFlowKey) { lastFlowKey = flowKey; lastFlow = &flows[flowKey]; }
            ++*lastFlow;
            if (!o.cells.empty() && o.cells.back().first == bucket) ++o.cells.back().second;
            else o.cells.push_back({ bucket, 1 });
            // A Write callback sees the new bytes (ReplayAPI.md §8), on the writing thread.
            if (oc.snap) take(t, *oc.snap, oc.lo, a, hit.Size);
            // A wide store can run into the next block (vector memset, memcpy): its bytes too.
            if (cap && a + hit.Size > oc.hi) {
                for (uint64_t r = oc.hi; r < a + hit.Size;) {
                    uint32_t const next = index.BlockAt(r, evt);
                    if (next == kNone || (model.blocks[next].flags & BlkSizeUnknown)) { ++r; continue; }
                    Block const& k = model.blocks[next];
                    take(t, snapOf(next), k.addr, r, a + hit.Size - r);
                    r = std::max(r + 1, k.addr + k.size);
                }
            }
            if (opts.exec != ExecDetect::None) {
                for (uint64_t p = a / kPage; p <= (a + std::max<uint64_t>(1, hit.Size) - 1) / kPage; ++p) {
                    if (p != cachedPage) { cachedPage = p; cachedState = &pages[p * kPage]; }
                    PageState& ps = *cachedState;
                    ++ps.writes; ps.lastPc = pc; ps.lastPos = pos; ps.lastEvt = evt; ps.lastThread = thread;
                    ps.writtenSinceExec = true;
                }
            }
            return false;
        }

        if (hit.AccessType == DataAccessType::DataMismatch) {
            uint32_t const block = index.BlockAt(a, evt);
            if (block != kNone && cap && !(model.blocks[block].flags & BlkSizeUnknown)) {
                pending[U(t->GetThreadInfo().UniqueId)].push_back({ block, a, hit.Size, pos });
                ++pendingCount;
                ++out.mismatches;
            }
            return false;
        }

        // Code running from a watched page: was the page written before it ran?
        ++out.execHits;
        uint64_t const first = a / kPage, last = std::min((a + std::max<uint64_t>(1, hit.Size) - 1) / kPage, first + kMaxExecPages - 1);
        for (uint64_t p = first; p <= last; ++p) {
            auto it = pages.find(p * kPage);
            if (it == pages.end()) continue;
            PageState& ps = it->second;
            if (!ps.writtenSinceExec) continue;
            ps.writtenSinceExec = false;
            if (ps.reported) continue;
            ps.reported = true;
            WxFinding f;
            f.page = p * kPage;
            f.region = index.RegionAt(f.page, evt);
            f.execPos = pos; f.execEvt = evt; f.execThread = thread;
            f.execPc = std::max(a, f.page);
            f.writePos = ps.lastPos; f.writeEvt = ps.lastEvt; f.writeThread = ps.lastThread; f.writerPc = ps.lastPc;
            f.writerRegion = index.RegionAt(ps.lastPc, ps.lastEvt);
            f.writesBefore = ps.writes;
            wx.push_back(f);
        }
        return false;
    };

    PositionRange const life = trace.Engine().GetLifetime();
    double const span = static_cast<double>(std::max<uint64_t>(1, U(life.Max.Sequence) - U(life.Min.Sequence)));
    ULONGLONG lastProgress = 0;
    auto onProgress = [&](Position const& p) {
        ULONGLONG const now = GetTickCount64();
        if (!opts.progress || now - lastProgress < 200) return;
        lastProgress = now;
        opts.progress(std::clamp((static_cast<double>(U(p.Sequence)) - static_cast<double>(U(life.Min.Sequence))) / span, 0.0, 1.0));
    };
    cursor->SetMemoryWatchpointCallback(onHit);
    cursor->SetReplayProgressCallback(onProgress);
    cursor->SetEventMask(EventMask::MemoryWatchpoint);
    cursor->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially); // chronological, single-threaded callbacks
    cursor->SetPosition(Position::Min);
    for (;;) {
        auto const r = cursor->ReplayForward();
        if (r.StopReason == EventType::MemoryWatchpoint) continue;
        break;
    }
    cursor->SetMemoryWatchpointCallback(nullptr, 0);
    cursor->SetReplayProgressCallback(nullptr, 0);

    // Flows by bucket, then from, then to.
    out.flows.reserve(flows.size());
    auto region20 = [](uint64_t v) { return v == 0xFFFFF ? kNone : static_cast<uint32_t>(v); };
    for (auto const& [k, n] : flows)
        out.flows.push_back({ static_cast<uint32_t>(k >> 40), region20((k >> 20) & 0xFFFFF), region20(k & 0xFFFFF), n });
    std::sort(out.flows.begin(), out.flows.end(), [](FlowRec const& a, FlowRec const& b) {
        return std::tie(a.bucket, a.from, a.to) < std::tie(b.bucket, b.from, b.to);
    });

    // Output, in a stable order: blocks first (by id), then region pages.
    std::vector<Obj*> order;
    order.reserve(objects.size());
    for (auto& [k, o] : objects) order.push_back(&o);
    auto rank = [](Obj const* o) { return o->block != kNone ? std::tuple{ 0u, o->block, 0u } : std::tuple{ 1u, o->region, o->page }; };
    std::sort(order.begin(), order.end(), [&](Obj const* a, Obj const* b) { return rank(a) < rank(b); });
    for (Obj* o : order) {
        std::sort(o->cells.begin(), o->cells.end());
        for (size_t i = 0; i < o->cells.size();) {
            uint32_t const bucket = o->cells[i].first;
            uint32_t n = 0;
            for (; i < o->cells.size() && o->cells[i].first == bucket; ++i) n += o->cells[i].second;
            out.cells.push_back({ o->block, o->region, o->page, bucket, n });
        }
        // Frames are return addresses (symbolized at address - 1): intern PC + 1 to name the PC.
        out.writers.push_back({ o->block, o->region, o->page, stacks.FrameId(o->firstPc + 1), stacks.FrameId(o->lastPc + 1),
                                o->firstEvt, o->lastEvt, o->firstThread, o->lastThread, o->writes, o->unbacked ? WrUnbacked : 0u });
    }
    std::sort(wx.begin(), wx.end(), [](WxFinding const& a, WxFinding const& b) { return Less(a.execPos, b.execPos); });
    for (auto& f : wx) f.writerFrame = stacks.FrameId(f.writerPc + 1);
    out.wx = std::move(wx);

    if (snapshots) {
        SnapshotOut& s = *snapshots;
        s = {};
        s.recorded = true;
        s.cap = cap;
        s.index.assign(model.blocks.size(), ContentIdx{ 0, 0, 0 });
        for (uint32_t b = 0; b < model.blocks.size(); ++b) {
            Block const& k = model.blocks[b];
            if (!k.size || (k.flags & BlkSizeUnknown)) continue;
            size_t const len = static_cast<size_t>(std::min<uint64_t>(k.size, cap));
            auto it = snaps.find(b);
            uint32_t unknown = static_cast<uint32_t>(len);
            size_t const at = s.bytes.size();
            if (it != snaps.end()) {
                s.bytes.insert(s.bytes.end(), it->second.bytes.begin(), it->second.bytes.end());
                unknown = static_cast<uint32_t>(std::count(it->second.known.begin(), it->second.known.end(), uint8_t{ 0 }));
            } else {
                s.bytes.resize(at + len, 0);
            }
            s.index[b] = { at, static_cast<uint32_t>(len), unknown };
        }
        // Blocks the kernel (or another process) wrote into: their bytes never came through a
        // Write, so read them where the block ends. Each read is a seek (~10 ms), hence the bound.
        for (auto const& [utid, list] : pending) for (Pending const& p : list) mismatched.push_back(p.block);
        std::sort(mismatched.begin(), mismatched.end());
        mismatched.erase(std::unique(mismatched.begin(), mismatched.end()), mismatched.end());
        s.mismatched = static_cast<uint32_t>(mismatched.size());
        if (mismatched.size() > kMaxSnapshotReads) mismatched.resize(kMaxSnapshotReads);
        s.readBack = static_cast<uint32_t>(mismatched.size());
        ReadSnapshots(trace, model, mismatched, s);
    }
    if (opts.progress) opts.progress(1.0);
    out.ms = GetTickCount64() - t0;
    return out;
}

void ReadSnapshots(Trace const& trace, Model const& model, std::vector<uint32_t> const& blocks, SnapshotOut& s)
{
    Position const end = trace.Engine().GetLifetime().Max;
    auto posOf = [&](uint32_t b) {
        uint32_t const f = model.blocks[b].freeEvt;
        return f == kNone || f >= model.positions.size() ? end : Position{ SequenceId{ model.positions[f].seq }, StepCount{ model.positions[f].steps } };
    };
    std::vector<uint32_t> order(blocks);
    std::stable_sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) { return posOf(a) < posOf(b); });
    UniqueCursor cursor = trace.NewCursor();
    Position at = Position::Invalid;
    for (uint32_t b : order) {
        ContentIdx& x = s.index[b];
        if (!x.length) continue;
        Position const p = posOf(b);
        if (!(p == at)) { cursor->SetPosition(p); at = p; }
        // At the free's CALL the block still holds its last contents; recorded bytes win.
        MemoryRead const r = ReadMemory(*cursor, model.blocks[b].addr, x.length);
        std::vector<uint8_t> unknown(x.length, 0);
        for (auto const& [o, n] : r.unknown) std::fill_n(unknown.data() + o, n, uint8_t{ 1 });
        for (uint32_t k = 0; k < x.length; ++k) if (!unknown[k]) s.bytes[x.offset + k] = r.bytes[k];
        x.unknown = std::min<uint32_t>(x.unknown, static_cast<uint32_t>(std::count(unknown.begin(), unknown.end(), uint8_t{ 1 })));
    }
}

} // namespace ttds
