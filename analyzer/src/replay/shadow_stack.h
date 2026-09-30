#pragma once
#include "model/stack_trie.h"

#include <cstdint>
#include <vector>

namespace ttds {

// Per-thread shadow call stack rebuilt from CALL/RET callbacks.
//
// Pairing rule (measured with `probe`): at a CALL callback the return address is already pushed,
// so the frame's SP is the address of its return-address slot; at the matching RET, SP is the same
// value and the RET target equals the saved return address. Because the stack grows down, any frame
// whose slot lies below the current SP can no longer return normally (it was unwound by an
// exception, longjmp, or a stack switch); such frames are discarded and reported through onDead.
class ShadowStack
{
public:
    // call: hooked call attached to the frame; xcall: call into a module export made by this frame.
    struct Frame { uint64_t retAddr; uint64_t sp; uint64_t callee; uint32_t call; uint32_t xcall = kNone; };

    static constexpr size_t kMaxDepth = 8192;

    // CALL with the return address already pushed at sp.
    template <typename OnDead>
    Frame& Push(uint64_t retAddr, uint64_t sp, uint64_t callee, OnDead&& onDead)
    {
        // The new return address overwrote the slot at sp: frames at or below it are dead.
        while (!m_frames.empty() && m_frames.back().sp <= sp) { onDead(m_frames.back()); m_frames.pop_back(); }
        if (m_frames.size() >= kMaxDepth) {
            // Runaway recursion or a missed stack switch: keep the newest half.
            size_t const drop = kMaxDepth / 2;
            for (size_t i = 0; i < drop; ++i) onDead(m_frames[i]);
            m_frames.erase(m_frames.begin(), m_frames.begin() + drop);
            ++m_overflows;
        }
        m_frames.push_back({ retAddr, sp, callee, kNone, kNone });
        return m_frames.back();
    }

    // RET to 'target' with SP at the return-address slot. Returns the matched frame (valid until the
    // next mutation) or nullptr when this RET does not belong to any tracked frame.
    template <typename OnDead>
    bool Pop(uint64_t target, uint64_t sp, Frame& matched, OnDead&& onDead)
    {
        while (!m_frames.empty() && m_frames.back().sp < sp) { onDead(m_frames.back()); m_frames.pop_back(); }
        if (m_frames.empty() || m_frames.back().sp != sp) { ++m_unmatched; return false; }
        matched = m_frames.back();
        m_frames.pop_back();
        if (matched.retAddr != target) {
            // Same slot but a different target: the return address was modified (e.g. a
            // return-address-overwriting stub). Treat the frame as returned anyway.
            ++m_retargeted;
        }
        return true;
    }

    Frame* Top() noexcept { return m_frames.empty() ? nullptr : &m_frames.back(); }
    size_t Depth() const noexcept { return m_frames.size(); }
    std::vector<Frame> const& Frames() const noexcept { return m_frames; }

    // Collects up to 'max' return addresses, innermost first.
    size_t Collect(uint64_t* out, size_t max) const noexcept
    {
        size_t n = 0;
        for (size_t i = m_frames.size(); i-- > 0 && n < max;) out[n++] = m_frames[i].retAddr;
        return n;
    }

    // Innermost frame with an attached hooked call, if any.
    uint32_t InnermostCall() const noexcept
    {
        for (size_t i = m_frames.size(); i-- > 0;) if (m_frames[i].call != kNone) return m_frames[i].call;
        return kNone;
    }

    uint64_t Unmatched() const noexcept { return m_unmatched; }
    uint64_t Retargeted() const noexcept { return m_retargeted; }
    uint64_t Overflows() const noexcept { return m_overflows; }

private:
    std::vector<Frame> m_frames;
    uint64_t m_unmatched = 0, m_retargeted = 0, m_overflows = 0;
};

} // namespace ttds
