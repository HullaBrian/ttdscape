#include "check.h"
#include "model/heap_model.h"

using namespace ttds;

namespace {
HeapModel::Ctx C(uint16_t thread = 0, uint32_t stack = kNone) { return { thread, stack, 0 }; }
}

TEST(alloc_free_lifetime)
{
    Model m;
    HeapModel h(m);
    h.SeedHeaps(0x1000, {});
    h.Alloc(C(), 0x1000, 32, 0xA000);
    CHECK_EQ(h.LiveBytes(), 32u);
    h.Free(C(), 0x1000, 0xA000, true);
    CHECK_EQ(h.LiveBytes(), 0u);
    CHECK_EQ(m.blocks.size(), 1u);
    CHECK_EQ(m.blocks[0].allocEvt, 0u);
    CHECK_EQ(m.blocks[0].freeEvt, 1u);
    CHECK_EQ(m.events.size(), 2u);
    CHECK_EQ(m.events[1].kind, static_cast<uint8_t>(EventKind::Free));
    CHECK_EQ(m.heaps[m.blocks[0].heap].kind == HeapKind::Process, true);
}

TEST(free_null_is_ignored_and_failed_free_keeps_block)
{
    Model m;
    HeapModel h(m);
    h.Free(C(), 0x1000, 0, true);
    CHECK_EQ(m.events.size(), 0u);
    h.Alloc(C(), 0x1000, 16, 0xB000);
    h.Free(C(), 0x1000, 0xB000, false);
    CHECK_EQ(m.blocks[0].freeEvt, kNone);
    CHECK_EQ(m.events.back().flags & EvFailed, EvFailed);
}

TEST(realloc_moves_and_chains)
{
    Model m;
    HeapModel h(m);
    h.Alloc(C(), 0x1000, 64, 0xA000);
    h.ReAlloc(C(), 0x1000, 0xA000, 32, 0xA000);   // in place
    h.ReAlloc(C(), 0x1000, 0xA000, 8192, 0xC000); // moves
    CHECK_EQ(m.blocks.size(), 3u);
    CHECK_EQ(m.blocks[1].prev, 0u);
    CHECK(m.blocks[1].flags & BlkInPlace);
    CHECK_EQ(m.blocks[2].prev, 1u);
    CHECK(m.blocks[0].flags & BlkRealloced);
    CHECK_EQ(m.blocks[0].freeEvt, 1u);
    CHECK_EQ(m.blocks[1].freeEvt, 2u);
    CHECK_EQ(h.LiveBytes(), 8192u);
    // Failed realloc changes nothing.
    h.ReAlloc(C(), 0x1000, 0xC000, 1 << 30, 0);
    CHECK_EQ(m.blocks[2].freeEvt, kNone);
    CHECK_EQ(h.LiveBytes(), 8192u);
}

TEST(pretrace_and_double_free)
{
    Model m;
    HeapModel h(m);
    h.Free(C(), 0x1000, 0xD000, true); // allocated before the trace
    CHECK_EQ(m.blocks.size(), 1u);
    CHECK(m.blocks[0].flags & BlkPreTrace);
    CHECK_EQ(m.blocks[0].allocEvt, kNone);
    CHECK_EQ(m.quality.preTraceFrees, 1u);
    h.Free(C(), 0x1000, 0xD000, true); // again: double free
    CHECK_EQ(m.quality.doubleFree, 1u);
    CHECK_EQ(m.events.back().kind, static_cast<uint8_t>(EventKind::FreeUnknown));
    CHECK(m.events.back().flags & EvExtra);
}

TEST(destroy_frees_live_blocks_of_that_heap_only)
{
    Model m;
    HeapModel h(m);
    h.SeedHeaps(0x1000, {});
    h.Create(C(), 0x2000, 0);
    h.Alloc(C(), 0x2000, 10, 0x2100);
    h.Alloc(C(), 0x2000, 20, 0x2200);
    h.Alloc(C(), 0x1000, 30, 0x1100);
    h.Free(C(), 0x2000, 0x2100, true);
    h.Destroy(C(), 0x2000);
    CHECK_EQ(m.blocks[1].freeEvt, static_cast<uint32_t>(m.events.size() - 1));
    CHECK(m.blocks[1].flags & BlkImplicitFree);
    CHECK_EQ(m.blocks[2].freeEvt, kNone);
    CHECK_EQ(m.events.back().size, 20u); // bytes freed implicitly
    CHECK_EQ(h.LiveBytes(), 30u);
    // A new heap reusing the handle is a new identity.
    h.Create(C(), 0x2000, 0);
    h.Alloc(C(), 0x2000, 5, 0x2300);
    CHECK(m.blocks.back().heap != m.blocks[1].heap);
}

TEST(overlapping_alloc_supersedes_live_block)
{
    Model m;
    HeapModel h(m);
    h.Alloc(C(), 0x1000, 0x100, 0xA000);
    h.Alloc(C(), 0x1000, 0x10, 0xA080); // inside the live block: its free was missed
    CHECK(m.blocks[0].flags & BlkSuperseded);
    CHECK_EQ(m.quality.superseded, 1u);
    CHECK_EQ(h.LiveBytes(), 0x10u);
}

TEST(cross_thread_free_is_flagged)
{
    Model m;
    HeapModel h(m);
    h.Alloc(C(1), 0x1000, 8, 0xA000);
    h.Free(C(2), 0x1000, 0xA000, true);
    CHECK(m.blocks[0].flags & BlkCrossThread);
    CHECK(m.events.back().flags & EvCrossThread);
}

TEST_MAIN
