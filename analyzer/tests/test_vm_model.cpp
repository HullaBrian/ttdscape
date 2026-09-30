#include "check.h"
#include "model/vm_model.h"
#include "replay/outparams.h"

using namespace ttds;

namespace {
VmModel::Ctx C() { return { 0, kNone, 0, kNone }; }

// Spans of a region that are open at event index i.
std::vector<Span> SpansAt(Model const& m, uint32_t region, uint32_t i)
{
    std::vector<Span> out;
    for (auto const& s : m.spans) {
        bool const started = s.startEvt == kNone || s.startEvt <= i;
        bool const ended = s.endEvt != kNone && s.endEvt <= i;
        if (s.region == region && started && !ended) out.push_back(s);
    }
    std::sort(out.begin(), out.end(), [](Span const& a, Span const& b) { return a.start < b.start; });
    return out;
}

bool NoOverlap(std::vector<Span> const& v)
{
    for (size_t i = 1; i < v.size(); ++i) if (v[i].start < v[i - 1].end) return false;
    return true;
}
} // namespace

TEST(reserve_commit_protect_decommit_release)
{
    Model m;
    VmModel vm(m);
    uint64_t const base = 0x10000000;
    uint32_t const e0 = vm.Allocate(C(), base, 0x100000, kMemReserve, 0x01);
    uint32_t const r = m.events[e0].id;
    CHECK_EQ(vm.Reserved(), 0x100000u);
    CHECK_EQ(vm.Committed(), 0u);

    uint32_t const e1 = vm.Allocate(C(), base + 0x40000, 0x10000, kMemCommit, 0x04);
    CHECK_EQ(m.events[e1].id, r);
    CHECK_EQ(vm.Committed(), 0x10000u);
    auto s1 = SpansAt(m, r, e1);
    CHECK_EQ(s1.size(), 3u);
    CHECK(NoOverlap(s1));
    CHECK_EQ(s1[1].state, static_cast<uint16_t>(SpanState::Committed));
    CHECK_EQ(s1[1].protect, 0x04u);

    uint32_t const e2 = vm.Protect(C(), base + 0x40000, 0x10000, 0x02, 0x04);
    auto s2 = SpansAt(m, r, e2);
    CHECK_EQ(s2[1].protect, 0x02u);
    // History is preserved: at e1 the protection was still RW.
    CHECK_EQ(SpansAt(m, r, e1)[1].protect, 0x04u);

    uint32_t const e3 = vm.Free(C(), base + 0x40000, 0x10000, kMemDecommit);
    CHECK_EQ(vm.Committed(), 0u);
    auto s3 = SpansAt(m, r, e3);
    CHECK(NoOverlap(s3));
    // Coalesced back into a single reserved span.
    CHECK_EQ(s3.size(), 1u);

    uint32_t const e4 = vm.Free(C(), base, 0, kMemRelease);
    CHECK_EQ(m.regions[r].releaseEvt, e4);
    CHECK_EQ(vm.Reserved(), 0u);
    CHECK_EQ(SpansAt(m, r, e4).size(), 0u);
    CHECK_EQ(vm.RegionAt(base), kNone);
}

TEST(commit_outside_known_region_infers_a_pretrace_reservation)
{
    Model m;
    VmModel vm(m);
    uint32_t const e = vm.Allocate(C(), 0x20000000, 0x2000, kMemCommit, 0x04);
    uint32_t const r = m.events[e].id;
    CHECK_EQ(m.regions[r].kind, static_cast<uint32_t>(RegionKind::Inferred));
    CHECK(m.regions[r].flags & RgnPreTrace);
    CHECK_EQ(m.regions[r].createEvt, kNone);
    // Contiguous commit extends the inferred region instead of creating another.
    uint32_t const e2 = vm.Allocate(C(), 0x20002000, 0x1000, kMemCommit, 0x04);
    CHECK_EQ(m.events[e2].id, r);
    CHECK_EQ(m.regions[r].size, 0x3000u);
}

TEST(views_and_images)
{
    Model m;
    VmModel vm(m);
    uint32_t const e = vm.MapView(C(), 0x30000000, 0x40000, 0x04);
    uint32_t const r = m.events[e].id;
    CHECK_EQ(vm.Mapped(), 0x40000u);
    uint32_t const img = vm.AddImage(0x30000000, 0x40000, 7, e + 1);
    CHECK_EQ(img, r); // the loader's view is relabelled as the image
    CHECK_EQ(m.regions[r].kind, static_cast<uint32_t>(RegionKind::Image));
    CHECK_EQ(m.regions[r].heap, 7u);
    vm.UnmapView(C(), 0x30000000);
    CHECK_EQ(vm.Mapped(), 0u);
    CHECK_EQ(vm.UnmapView(C(), 0x30000000) != kNone, true);
    CHECK_EQ(m.quality.releaseUnknownRegion, 1u);
}

TEST(reserve_over_live_region_closes_it)
{
    Model m;
    VmModel vm(m);
    uint32_t const e0 = vm.Allocate(C(), 0x40000000, 0x10000, kMemReserve | kMemCommit, 0x04);
    uint32_t const e1 = vm.Allocate(C(), 0x40000000, 0x10000, kMemReserve, 0x01);
    CHECK_EQ(m.regions[m.events[e0].id].releaseEvt, e1);
    CHECK_EQ(vm.Reserved(), 0x10000u);
}

TEST_MAIN
