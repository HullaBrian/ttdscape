#pragma once
#include "engine.h"
#include "model/types.h"

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ttds {

// The activity pass (analyze stage "activity"): one sequential replay with watchpoints on every
// region that is not an image or a stack (heaps, private, mapped). Writes are aggregated in the
// callback per object (the heap block written, or the page of a region when no block holds the
// address) x time bucket (the series buckets), with the first and last writer. Code executing in
// those regions is matched with the last write to its page: code that was written, then run.
// See docs/memory.md.

enum class ExecDetect { None, CodeFetch, Execute };

struct ActivityOptions
{
    ExecDetect exec = ExecDetect::CodeFetch;
    uint32_t   snapshotCap = 4096; // bytes per block kept when snapshots are asked for
    std::function<void(double)> progress;
};

// A pure lookup of the object a write belongs to (unit-tested): the smallest block holding addr
// with allocEvt <= evt <= freeEvt, else the region page. Blocks are bucketed by page over their
// whole lifetime, so a lookup checks only the blocks that ever touched that page.
class ObjectIndex
{
public:
    explicit ObjectIndex(Model const& model);
    uint32_t BlockAt(uint64_t addr, uint32_t evt) const;
    // Whether any block, at any time, covers part of addr's page.
    bool PageHasBlocks(uint64_t addr) const;
    // Region holding addr at evt (created at or before evt, released at or after it), or kNone.
    uint32_t RegionAt(uint64_t addr, uint32_t evt) const;

private:
    Model const& m_model;
    std::unordered_map<uint64_t, std::vector<uint32_t>> m_pages;
    std::vector<uint32_t> m_large;
    std::vector<uint32_t> m_regionsByBase;
    mutable uint32_t m_lastRegion = kNone;
};

// Whether the pass watches a region: not an image, not a thread stack.
bool WatchedRegion(Region const& r);

// Sorted, merged [start, end) address ranges of the watched regions (regions reuse addresses over
// time; one watchpoint per address range).
std::vector<std::pair<uint64_t, uint64_t>> WatchRanges(std::vector<Region> const& regions);

// Records and results are in model/types.h (ActivityOut, SnapshotOut).
// With `snapshots`, also rebuilds each block's first snapshotCap bytes as they were at its free (or
// the end of the trace) from the writes into it (last write wins; ReplayAPI.md §6), and reads back
// the few blocks whose bytes the kernel wrote (DataMismatch). Bytes never written in the trace
// are unknown.
ActivityOut RunActivity(Trace const& trace, Model const& model, StackTrie& stacks, ActivityOptions const& opts,
                        SnapshotOut* snapshots = nullptr);

// Reads the snapshots of `blocks` at their free (or the end of the trace), keeping what the trace
// recorded there over the rebuilt bytes. Each block is a seek: use it for a few blocks only.
void ReadSnapshots(Trace const& trace, Model const& model, std::vector<uint32_t> const& blocks, SnapshotOut& s);

} // namespace ttds
