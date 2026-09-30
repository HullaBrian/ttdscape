#include "check.h"
#include "replay/activity.h"

using namespace ttds;

namespace {

Region MakeRegion(uint64_t base, uint64_t size, RegionKind kind, uint32_t create = kNone, uint32_t release = kNone)
{
    Region r{};
    r.base = base; r.size = size; r.kind = static_cast<uint32_t>(kind);
    r.createEvt = create; r.releaseEvt = release;
    r.heap = kNone; r.createStack = kNone; r.releaseStack = kNone;
    return r;
}

Block MakeBlock(uint64_t addr, uint64_t size, uint32_t alloc, uint32_t free)
{
    Block b{};
    b.addr = addr; b.size = size; b.allocEvt = alloc; b.freeEvt = free;
    b.heap = 0; b.allocStack = kNone; b.freeStack = kNone; b.prev = kNone;
    return b;
}

} // namespace

TEST(watch_ranges_merge_regions_and_leave_out_images_and_stacks)
{
    std::vector<Region> const regions = {
        MakeRegion(0x10000, 0x10000, RegionKind::Private),
        MakeRegion(0x18000, 0x10000, RegionKind::Heap),        // overlaps the first: merged
        MakeRegion(0x400000, 0x5000, RegionKind::Image),       // images are not watched
        MakeRegion(0x100000, 0x100000, RegionKind::Inferred),  // covers a stack at another time
        MakeRegion(0x140000, 0x20000, RegionKind::Stack),      // ...whose addresses stay out
        MakeRegion(0x300000, 0x1000, RegionKind::Stack),
    };
    auto const r = WatchRanges(regions);
    CHECK_EQ(r.size(), 3u);
    CHECK(r[0] == std::make_pair(uint64_t{ 0x10000 }, uint64_t{ 0x28000 }));
    CHECK(r[1] == std::make_pair(uint64_t{ 0x100000 }, uint64_t{ 0x140000 }));
    CHECK(r[2] == std::make_pair(uint64_t{ 0x160000 }, uint64_t{ 0x200000 }));
}

TEST(object_index_attributes_writes_to_the_live_block_or_region)
{
    Model m;
    m.regions = { MakeRegion(0x10000, 0x4000, RegionKind::Heap), MakeRegion(0x20000, 0x2000, RegionKind::Private, 5, 9),
                  MakeRegion(0x20000, 0x1000, RegionKind::Private, 12) };
    m.blocks = {
        MakeBlock(0x10100, 0x20, 2, 6),        // freed at 6
        MakeBlock(0x10100, 0x10, 7, kNone),    // reuses the address
        MakeBlock(0x10000, 0x3000, kNone, 3),  // pre-trace, spans pages
        MakeBlock(0x40000, 0x100000, 50, 51),  // large: the short list
    };
    ObjectIndex const index(m);
    CHECK_EQ(index.BlockAt(0x10110, 2), 0u);          // smallest live block wins over the pre-trace one
    CHECK_EQ(index.BlockAt(0x10110, 6), 0u);          // the free's event still belongs to the block
    CHECK_EQ(index.BlockAt(0x10108, 7), 1u);
    CHECK_EQ(index.BlockAt(0x10110, 7), kNone);       // past the reused block's end
    CHECK_EQ(index.BlockAt(0x12000, 1), 2u);
    CHECK_EQ(index.BlockAt(0x12000, 4), kNone);
    CHECK_EQ(index.BlockAt(0x50000, 50), 3u);
    CHECK_EQ(index.RegionAt(0x10118, 7), 0u);
    CHECK_EQ(index.RegionAt(0x20800, 6), 1u);
    CHECK_EQ(index.RegionAt(0x20800, 10), kNone);
    CHECK_EQ(index.RegionAt(0x20800, 12), 2u);
    CHECK_EQ(index.RegionAt(0x21800, 12), kNone);
    // "No block here" may cover a whole page only if no block ever touches it.
    CHECK(index.PageHasBlocks(0x10ff0));
    CHECK(index.PageHasBlocks(0x60000));              // inside the large block's pages
    CHECK(!index.PageHasBlocks(0x20800));
}

TEST_MAIN
