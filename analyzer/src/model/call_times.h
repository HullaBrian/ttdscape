#pragma once
#include "model/types.h"

#include <algorithm>
#include <numeric>
#include <span>
#include <vector>

namespace ttds {

inline bool PosLess(Position16 const& a, Position16 const& b) noexcept
{
    return a.seq != b.seq ? a.seq < b.seq : a.steps < b.steps;
}

// Places positions on the event axis. events: the position of every event (nondecreasing).
// For each key, evt is the first event at or after it (strictly after it when after[i] is set, so a
// RET lands after an event recorded at the same position), or events.size() if none. All keys that
// share an evt are ranked together by position (then by index) and get fractions (rank+1)/(k+1),
// so a call and its return between the same two events stay in order.
inline void AssignEventTimes(std::span<Position16 const> events, std::span<Position16 const> keys,
                             std::span<uint8_t const> after, uint32_t* evt, float* frac)
{
    for (size_t i = 0; i < keys.size(); ++i) {
        auto const it = after[i] ? std::upper_bound(events.begin(), events.end(), keys[i], PosLess)
                                 : std::lower_bound(events.begin(), events.end(), keys[i], PosLess);
        evt[i] = static_cast<uint32_t>(it - events.begin());
    }
    std::vector<uint32_t> order(keys.size());
    std::iota(order.begin(), order.end(), 0u);
    std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
        if (evt[a] != evt[b]) return evt[a] < evt[b];
        if (PosLess(keys[a], keys[b])) return true;
        if (PosLess(keys[b], keys[a])) return false;
        return a < b;
    });
    for (size_t g = 0; g < order.size();) {
        size_t end = g + 1;
        while (end < order.size() && evt[order[end]] == evt[order[g]]) ++end;
        for (size_t i = g; i < end; ++i) frac[order[i]] = static_cast<float>(i - g + 1) / static_cast<float>(end - g + 1);
        g = end;
    }
}

} // namespace ttds
