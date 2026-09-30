#include "check.h"
#include "model/address_map.h"
#include "model/call_times.h"
#include "replay/shadow_stack.h"

using namespace ttds;

TEST(address_map_finds_what_was_added_and_nothing_else)
{
    AddressMap m;
    CHECK_EQ(m.Find(0x401000), kNone);
    for (uint32_t i = 0; i < 5000; ++i) m.Add(0x7ff800000000ull + i * 16ull, i);
    CHECK_EQ(m.Size(), 5000u);
    CHECK_EQ(m.Find(0x7ff800000000ull), 0u);
    CHECK_EQ(m.Find(0x7ff800000000ull + 4999 * 16ull), 4999u);
    CHECK_EQ(m.Find(0x7ff800000000ull + 8), kNone);   // between two entries
    CHECK_EQ(m.Find(0), kNone);
    m.Add(0x7ff800000000ull, 77);                      // first value wins
    CHECK_EQ(m.Find(0x7ff800000000ull), 0u);
    CHECK_EQ(m.Size(), 5000u);
}

TEST(event_times_place_calls_before_the_next_event_and_spread_ties)
{
    // Events at 10, 20, 20, 30.
    Position16 const events[] = { { 1, 10 }, { 1, 20 }, { 1, 20 }, { 1, 30 } };
    // Calls at 5 (before everything), 12, 20 (same as an event), 31 (after everything); returns at 15 and 20.
    Position16 const keys[] = { { 1, 5 }, { 1, 12 }, { 1, 20 }, { 1, 31 }, { 1, 15 }, { 1, 20 } };
    uint8_t const after[] = { 0, 0, 0, 0, 1, 1 };
    uint32_t evt[6];
    float frac[6];
    AssignEventTimes(events, keys, after, evt, frac);
    CHECK_EQ(evt[0], 0u);
    CHECK_EQ(evt[1], 1u);
    CHECK_EQ(evt[2], 1u);   // a call at an event's position: before it
    CHECK_EQ(evt[3], 4u);   // after the last event
    CHECK_EQ(evt[4], 1u);
    CHECK_EQ(evt[5], 3u);   // a return at an event's position: after it
    CHECK(frac[0] == 0.5f && frac[3] == 0.5f && frac[5] == 0.5f);
    // Between events 0 and 1: call@12, ret@15, call@20, ranked together.
    CHECK(frac[1] == 0.25f && frac[4] == 0.5f && frac[2] == 0.75f);
}

TEST(event_times_with_no_events)
{
    Position16 const keys[] = { { 3, 0 }, { 2, 0 } };
    uint8_t const after[] = { 0, 0 };
    uint32_t evt[2];
    float frac[2];
    AssignEventTimes({}, keys, after, evt, frac);
    CHECK_EQ(evt[0], 0u);
    CHECK_EQ(evt[1], 0u);
    CHECK(frac[1] < frac[0]);
}

TEST(shadow_frames_carry_an_export_call_until_popped_or_unwound)
{
    ShadowStack s;
    std::vector<uint32_t> dead;
    auto onDead = [&](ShadowStack::Frame const& f) { dead.push_back(f.xcall); };
    s.Push(0x401005, 0x1000, 0x7ff00010, onDead).xcall = 3;
    CHECK_EQ(s.Top()->call, kNone);
    s.Push(0x7ff00020, 0x0F00, 0x7ff10000, onDead).xcall = 4;
    CHECK_EQ(s.Depth(), 2u);
    ShadowStack::Frame f{};
    // An exception unwinds the inner frame; the outer returns normally.
    CHECK(s.Pop(0x401005, 0x1000, f, onDead));
    CHECK_EQ(f.xcall, 3u);
    CHECK_EQ(dead.size(), 1u);
    CHECK_EQ(dead[0], 4u);
}

TEST_MAIN
