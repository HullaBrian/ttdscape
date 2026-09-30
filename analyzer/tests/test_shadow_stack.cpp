#include "check.h"
#include "replay/shadow_stack.h"

using namespace ttds;

namespace {
auto Ignore() { return [](ShadowStack::Frame const&) {}; }
}

TEST(call_ret_pairs_on_slot_and_target)
{
    ShadowStack s;
    s.Push(0x401005, 0x1000, 0x500000, Ignore());
    s.Top()->call = 7;
    s.Push(0x500010, 0x0FF0, 0x600000, Ignore());
    ShadowStack::Frame f{};
    CHECK(s.Pop(0x500010, 0x0FF0, f, Ignore()));
    CHECK_EQ(f.retAddr, 0x500010u);
    CHECK(s.Pop(0x401005, 0x1000, f, Ignore()));
    CHECK_EQ(f.call, 7u);
    CHECK(s.Frames().empty());
}

TEST(unwound_frames_are_reported_dead)
{
    ShadowStack s;
    std::vector<uint32_t> dead;
    auto onDead = [&](ShadowStack::Frame const& f) { dead.push_back(f.call); };
    s.Push(0x401005, 0x1000, 0, onDead);
    s.Push(0x402005, 0x0F00, 0, onDead);
    s.Top()->call = 1;
    s.Push(0x403005, 0x0E00, 0, onDead);
    s.Top()->call = 2;
    // An exception unwinds straight back to the outermost frame, which then returns.
    ShadowStack::Frame f{};
    CHECK(s.Pop(0x401005, 0x1000, f, onDead));
    CHECK_EQ(dead.size(), 2u);
    CHECK_EQ(dead[0], 2u);
    CHECK_EQ(dead[1], 1u);
}

TEST(call_at_same_or_higher_slot_kills_stale_frames)
{
    ShadowStack s;
    int dead = 0;
    auto onDead = [&](ShadowStack::Frame const&) { ++dead; };
    s.Push(0x401005, 0x1000, 0, onDead);
    s.Push(0x402005, 0x0F00, 0, onDead); // never returns (longjmp)
    s.Push(0x403005, 0x0F00, 0, onDead); // a new call reusing the same slot
    CHECK_EQ(dead, 1);
    CHECK_EQ(s.Frames().size(), 2u);
}

TEST(unknown_ret_is_counted_not_popped)
{
    ShadowStack s;
    s.Push(0x401005, 0x1000, 0, Ignore());
    ShadowStack::Frame f{};
    CHECK(!s.Pop(0x999999, 0x0800, f, Ignore())); // deeper than anything we track
    CHECK_EQ(s.Unmatched(), 1u);
    CHECK_EQ(s.Frames().size(), 1u);
}

TEST(collect_innermost_first)
{
    ShadowStack s;
    s.Push(1, 0x1000, 0, Ignore());
    s.Push(2, 0x0F00, 0, Ignore());
    s.Push(3, 0x0E00, 0, Ignore());
    uint64_t buf[2];
    CHECK_EQ(s.Collect(buf, 2), 2u);
    CHECK_EQ(buf[0], 3u);
    CHECK_EQ(buf[1], 2u);
}

TEST(stack_trie_shares_prefixes)
{
    StackTrie t;
    uint64_t a[] = { 3, 2, 1 };
    uint64_t b[] = { 4, 2, 1 };
    uint32_t const na = t.Intern(a), nb = t.Intern(b);
    CHECK(na != nb);
    CHECK_EQ(t.Nodes().size(), 4u); // 1, 1>2, 1>2>3, 1>2>4
    CHECK_EQ(t.Intern(a), na);
    auto const fa = t.Frames(na);
    CHECK_EQ(fa.size(), 3u);
    CHECK_EQ(fa[0], 3u);
    CHECK_EQ(t.Intern({}), kNone);
}

TEST_MAIN
