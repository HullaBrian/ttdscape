#include "check.h"
#include "serve/json_in.h"
#include "serve/memory_query.h"

using namespace ttds;

TEST(json_reads_requests)
{
    auto const v = JsonValue::Parse(R"( {"id":7,"method":"memory.read","params":{"evt":-1,"addr":"0x7ffa6b261234","size":256,
        "reads":true,"s":"a\"\\\né","list":[1,2,{}],"n":null}} )");
    CHECK(v.has_value());
    CHECK_EQ((*v)["id"].Number().value_or(0), 7.0);
    CHECK((*v)["method"].String().value_or("") == "memory.read");
    JsonValue const& p = (*v)["params"];
    CHECK_EQ(p["evt"].Number().value_or(0), -1.0);
    CHECK_EQ(p["addr"].Address().value_or(0), 0x7ffa6b261234ull);
    CHECK_EQ(p["size"].Address().value_or(0), 256u);
    CHECK(p["reads"].Bool().value_or(false));
    CHECK(p["s"].String().value_or("") == "a\"\\\n\xc3\xa9");
    CHECK_EQ(p["list"].Items().size(), 3u);
    CHECK(p["n"].IsNull() && p.Has("n") && !p.Has("missing") && p["missing"].IsNull());
    CHECK(!p["evt"].Address().has_value()); // negative
    CHECK(!p["method"].Number().has_value());
}

TEST(json_rejects_malformed_input)
{
    for (char const* bad : { "", "{", "{\"a\":}", "{\"a\":1,}", "[1 2]", "{\"a\":1} x", "\"\x01\"", "{\"a\":nul}", "1e999" })
        CHECK(!JsonValue::Parse(bad).has_value());
    std::string deep(100, '[');
    deep += std::string(100, ']');
    CHECK(!JsonValue::Parse(deep).has_value());
    CHECK(!JsonValue::Parse(R"({"a":"0xZZ"})")->operator[]("a").Address().has_value());
}

TEST(unknown_spans_are_the_uncovered_bytes)
{
    using V = std::vector<std::pair<uint64_t, uint64_t>>;
    CHECK(UnknownSpans(0x1000, 0x40, {}) == V({ { 0, 0x40 } }));
    // Overlapping and out-of-window ranges; a gap in the middle and at the end.
    std::vector<RecordedRange> const r = { { 0xff0, 0x20, 1 }, { 0x1008, 0x10, 2 }, { 0x1020, 0x10, 3 }, { 0x2000, 8, 4 } };
    CHECK(UnknownSpans(0x1000, 0x40, r) == V({ { 0x18, 0x8 }, { 0x30, 0x10 } }));
    CHECK(UnknownSpans(0x1000, 0x10, { { 0x1000, 0x10, 1 } }).empty());
}

TEST(events_and_positions)
{
    std::vector<Position16> const pos = { { 1, 0 }, { 1, 5 }, { 3, 0 }, { 3, 2 } };
    CHECK_EQ(EventAtOrAfter(pos, { 0, 9 }), 0u);
    CHECK_EQ(EventAtOrAfter(pos, { 1, 5 }), 1u);
    CHECK_EQ(EventAtOrAfter(pos, { 1, 6 }), 2u);
    CHECK_EQ(EventAtOrAfter(pos, { 3, 3 }), 4u);
    auto const p = ParsePosition("1A2:3F");
    CHECK(p.has_value() && p->seq == 0x1a2 && p->steps == 0x3f);
    CHECK(!ParsePosition("12").has_value());
    CHECK(!ParsePosition(":5").has_value());
    CHECK(!ParsePosition("5:x").has_value());
}

TEST_MAIN
