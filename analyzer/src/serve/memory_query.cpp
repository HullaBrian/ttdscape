#include "serve/memory_query.h"

#include <algorithm>
#include <charconv>
#include <stdexcept>
#include <unordered_map>

namespace ttds {

namespace {

Position16 Pos16(Position const& p) { return { U(p.Sequence), U(p.Steps) }; }
bool Less(Position16 const& a, Position16 const& b) { return a.seq != b.seq ? a.seq < b.seq : a.steps < b.steps; }

} // namespace

std::vector<std::pair<uint64_t, uint64_t>> UnknownSpans(uint64_t addr, uint64_t size, std::vector<RecordedRange> const& ranges)
{
    std::vector<std::pair<uint64_t, uint64_t>> covered; // [start, end) offsets
    for (auto const& r : ranges) {
        uint64_t const s = std::max(r.addr, addr), e = std::min(r.addr + r.size, addr + size);
        if (s < e) covered.push_back({ s - addr, e - addr });
    }
    std::sort(covered.begin(), covered.end());
    std::vector<std::pair<uint64_t, uint64_t>> out;
    uint64_t at = 0;
    for (auto const& [s, e] : covered) {
        if (s > at) out.push_back({ at, s - at });
        at = std::max(at, e);
    }
    if (at < size) out.push_back({ at, size - at });
    return out;
}

uint32_t EventAtOrAfter(std::vector<Position16> const& positions, Position16 p)
{
    auto it = std::lower_bound(positions.begin(), positions.end(), p, Less);
    return static_cast<uint32_t>(it - positions.begin());
}

std::optional<Position16> ParsePosition(std::string_view text)
{
    size_t const colon = text.find(':');
    if (colon == std::string_view::npos) return std::nullopt;
    Position16 p{};
    auto const a = std::from_chars(text.data(), text.data() + colon, p.seq, 16);
    auto const b = std::from_chars(text.data() + colon + 1, text.data() + text.size(), p.steps, 16);
    if (a.ec != std::errc{} || a.ptr != text.data() + colon || b.ec != std::errc{} || b.ptr != text.data() + text.size() || colon == 0)
        return std::nullopt;
    return p;
}

MemoryRead ReadMemory(ICursorView& cursor, uint64_t addr, size_t size)
{
    MemoryRead r;
    r.bytes.assign(size, 0);
    std::vector<MemoryRange> found(256);
    size_t off = 0;
    while (off < size) {
        MemoryBufferWithRanges const q = cursor.QueryMemoryBufferWithRanges(GuestAddress{ addr + off },
            BufferView{ r.bytes.data() + off, size - off }, found.size(), found.data(), QueryMemoryPolicy::GloballyConservative);
        if (q.Memory.Size == 0 || A(q.Address) != addr + off) {
            // Not mapped here (landmine 19: a read stops at the first hole). Skip to the next page.
            size_t const skip = std::min<size_t>(0x1000 - ((addr + off) & 0xFFF), size - off);
            std::fill_n(r.bytes.data() + off, skip, uint8_t{ 0 });
            off += skip;
            continue;
        }
        size_t const n = std::min(q.RangeCount, found.size());
        uint64_t reach = addr + off;
        for (size_t i = 0; i < n; ++i) {
            uint64_t const s = A(found[i].Address), e = s + found[i].Memory.Size;
            reach = std::max(reach, e);
            r.ranges.push_back({ s, found[i].Memory.Size, U(found[i].Sequence) });
        }
        size_t done = q.Memory.Size;
        // More ranges than we asked for: continue after the last one reported.
        if (q.RangeCount > found.size() && reach > addr + off) done = std::min<size_t>(done, reach - (addr + off));
        off += std::max<size_t>(done, 1);
    }
    // Clip provenance to the window, in address order.
    std::vector<RecordedRange> clipped;
    for (auto const& x : r.ranges) {
        uint64_t const s = std::max(x.addr, addr), e = std::min(x.addr + x.size, addr + size);
        if (s < e) clipped.push_back({ s, e - s, x.seq });
    }
    std::sort(clipped.begin(), clipped.end(), [](auto const& a, auto const& b) { return a.addr < b.addr; });
    r.ranges = std::move(clipped);
    r.unknown = UnknownSpans(addr, size, r.ranges);
    // Zero-fill placeholders are not data: blank them so nothing downstream mistakes them for it.
    for (auto const& [o, len] : r.unknown) std::fill_n(r.bytes.data() + o, len, uint8_t{ 0 });
    return r;
}

AccessResult QueryAccesses(Trace const& trace, AccessQuery const& q, std::function<void(double)> const& progress)
{
    ULONGLONG const t0 = GetTickCount64();
    AccessResult result;
    if (q.hi <= q.lo) return result;

    // A fresh cursor per query: a cursor that keeps its watchpoints re-fires them (landmine 28).
    UniqueCursor cursor = trace.NewCursor();
    DataAccessMask mask = DataAccessMask::Write | DataAccessMask::Overwrite | DataAccessMask::DataMismatch;
    if (q.reads) mask = mask | DataAccessMask::Read;
    if (!cursor->AddMemoryWatchpoint(MemoryWatchpointData{ GuestAddress{ q.lo }, q.hi - q.lo, mask })) // landmine 22
        throw std::runtime_error("AddMemoryWatchpoint failed");

    // Overwrite fires just before the Write (or DataMismatch) it belongs to, on the same thread.
    struct Pending { uint64_t addr = 0; Position16 pos{}; std::vector<uint8_t> bytes; bool known = false; };
    std::unordered_map<uint32_t, Pending> overwrite;
    std::vector<size_t> mismatches;

    auto read = [](IThreadView const* t, uint64_t a, uint64_t size, std::vector<uint8_t>& out) {
        out.resize(static_cast<size_t>(std::min<uint64_t>(size, kValueBytes)));
        MemoryBuffer const mb = t->QueryMemoryBuffer(GuestAddress{ a }, BufferView{ out.data(), out.size() });
        if (mb.Memory.Size == out.size()) return true;
        out.clear();
        return false;
    };

    auto onHit = [&](ICursorView::MemoryWatchpointResult const& hit, IThreadView const* t) noexcept -> bool {
        Position16 const pos = Pos16(t->GetPosition());
        uint32_t const utid = U(t->GetThreadInfo().UniqueId);
        uint64_t const a = A(hit.Address);
        if (hit.AccessType == DataAccessType::Overwrite) {
            Pending& p = overwrite[utid];
            p.addr = a; p.pos = pos;
            p.known = read(t, a, hit.Size, p.bytes);
            return false;
        }
        if (hit.AccessType != DataAccessType::Write && hit.AccessType != DataAccessType::Read && hit.AccessType != DataAccessType::DataMismatch)
            return false;
        AccessHit h;
        h.pos = pos; h.utid = utid; h.pc = A(t->GetProgramCounter()); h.addr = a; h.size = hit.Size;
        auto takeOld = [&] {
            auto it = overwrite.find(utid);
            if (it == overwrite.end() || it->second.addr != a || it->second.pos.seq != pos.seq || it->second.pos.steps != pos.steps) return false;
            h.oldValue = std::move(it->second.bytes);
            h.oldKnown = it->second.known;
            overwrite.erase(it);
            return true;
        };
        if (hit.AccessType == DataAccessType::Write) {
            h.kind = AccessKind::Write;
            h.newKnown = read(t, a, hit.Size, h.newValue); // a Write callback sees the new value (§8)
            takeOld();
        } else if (hit.AccessType == DataAccessType::Read) {
            h.kind = AccessKind::Read;
            h.newKnown = read(t, a, hit.Size, h.newValue);
        } else {
            // The thread's view still holds the bytes before the change (landmine 27); the new ones
            // are read one step later, after the replay.
            h.kind = AccessKind::Mismatch;
            if (!takeOld()) h.oldKnown = read(t, a, hit.Size, h.oldValue);
            mismatches.push_back(result.hits.size());
        }
        result.hits.push_back(std::move(h));
        if (result.hits.size() >= q.limit) { result.truncated = true; return true; } // stop the replay here
        return false;
    };

    double const span = static_cast<double>(std::max<uint64_t>(1, U(q.to.Sequence) - std::min(U(q.to.Sequence), U(q.from.Sequence))));
    ULONGLONG lastProgress = 0;
    auto onProgress = [&](Position const& p) {
        ULONGLONG const now = GetTickCount64();
        if (!progress || now - lastProgress < 200) return;
        lastProgress = now;
        progress(std::clamp((static_cast<double>(U(p.Sequence)) - static_cast<double>(U(q.from.Sequence))) / span, 0.0, 1.0));
    };

    cursor->SetMemoryWatchpointCallback(onHit);
    cursor->SetReplayProgressCallback(onProgress);
    cursor->SetEventMask(EventMask::MemoryWatchpoint);
    cursor->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially); // chronological, single-threaded callbacks
    cursor->SetPosition(q.from);
    for (;;) {
        auto const r = cursor->ReplayForward(q.to);
        if (r.StopReason == EventType::MemoryWatchpoint && !result.truncated) continue;
        break;
    }
    cursor->SetMemoryWatchpointCallback(nullptr, 0);
    cursor->SetReplayProgressCallback(nullptr, 0);

    // New bytes of each mismatch, one step past it on a fresh cursor (landmines 27 and 28).
    if (!mismatches.empty()) {
        UniqueCursor reader = trace.NewCursor();
        for (size_t i : mismatches) {
            AccessHit& h = result.hits[i];
            reader->SetPositionOnThread(UniqueThreadId{ h.utid }, Position{ SequenceId{ h.pos.seq }, StepCount{ h.pos.steps } } + StepCount{ 1 });
            h.newValue.resize(static_cast<size_t>(std::min<uint64_t>(h.size, kValueBytes)));
            for (QueryMemoryPolicy policy : { QueryMemoryPolicy::ThreadLocal, QueryMemoryPolicy::GloballyConservative }) {
                if (ReadGuest(*reader, h.addr, h.newValue, policy) == h.newValue.size()) { h.newKnown = true; break; }
            }
            if (!h.newKnown) h.newValue.clear();
        }
    }
    if (progress) progress(1.0);
    result.ms = GetTickCount64() - t0;
    return result;
}

} // namespace ttds
