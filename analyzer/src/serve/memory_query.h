#pragma once
#include "engine.h"
#include "model/types.h"

#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ttds {

// On-demand memory queries for the `serve` command: the bytes at an address at one position, and
// the accesses to an address range over a span of the trace.

// ---- pure helpers (unit-tested) ----

struct RecordedRange { uint64_t addr = 0, size = 0, seq = 0; };

// The parts of [addr, addr + size) no range covers, as merged (offset, length) pairs. Ranges may
// overlap each other or extend past the window.
std::vector<std::pair<uint64_t, uint64_t>> UnknownSpans(uint64_t addr, uint64_t size, std::vector<RecordedRange> const& ranges);

// First event whose position is at or after p (events.count when none): the event an access
// precedes, like CAPA rows. positions is positions.bin (sorted).
uint32_t EventAtOrAfter(std::vector<Position16> const& positions, Position16 p);

// "SEQ:STEPS" in hex, as PosStr prints it.
std::optional<Position16> ParsePosition(std::string_view text);

// ---- replay-backed queries ----

// Bytes at [addr, addr + size) at the cursor's position, read with the conservative policy.
// Memory the engine only zero-fills (mapped, no recorded value; landmine 18) is reported unknown:
// only bytes some provenance range covers are known.
struct MemoryRead
{
    std::vector<uint8_t>                       bytes;   // size bytes; unknown ones are 0
    std::vector<RecordedRange>                 ranges;  // provenance, clipped to the window, by address
    std::vector<std::pair<uint64_t, uint64_t>> unknown; // (offset, length)
};
MemoryRead ReadMemory(ICursorView& cursor, uint64_t addr, size_t size);

enum class AccessKind : uint8_t { Write, Read, Mismatch };

struct AccessHit
{
    Position16  pos{};
    uint32_t    utid = 0;
    uint64_t    pc = 0;
    uint64_t    addr = 0, size = 0;
    AccessKind  kind = AccessKind::Write;
    std::vector<uint8_t> oldValue, newValue; // capped at kValueBytes; empty when unavailable
    bool        oldKnown = false, newKnown = false;
};

struct AccessQuery
{
    uint64_t lo = 0, hi = 0;
    bool     reads = false;
    Position from = Position::Min, to = Position::Max;
    size_t   limit = 5000;
};

struct AccessResult
{
    std::vector<AccessHit> hits;       // in replay order (chronological per thread; landmine 30 across threads)
    bool                   truncated = false;
    uint64_t               ms = 0;
};

constexpr size_t kValueBytes = 32;

// One sequential replay with a watchpoint on [lo, hi): Write (paired with Overwrite for the old
// value), DataMismatch (bytes that changed outside the thread's view: the kernel, another thread or
// process), and Read when asked. progress gets 0..1.
AccessResult QueryAccesses(Trace const& trace, AccessQuery const& q, std::function<void(double)> const& progress);

} // namespace ttds
