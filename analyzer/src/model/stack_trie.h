#pragma once
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

namespace ttds {

constexpr uint32_t kNone = 0xFFFFFFFFu;

// Interns call stacks as paths in a trie. A node id identifies a whole stack: the path from the
// root (outermost frame) to the node (innermost frame). Frames are return addresses.
class StackTrie
{
public:
    struct Node { uint32_t parent; uint32_t frame; };

    // frames: innermost first (as collected from a shadow stack top-down). Returns kNone if empty.
    uint32_t Intern(std::span<uint64_t const> innermostFirst)
    {
        uint32_t node = kNone;
        for (size_t i = innermostFirst.size(); i-- > 0;) node = Child(node, FrameId(innermostFirst[i]));
        return node;
    }

    uint32_t FrameId(uint64_t address)
    {
        auto [it, inserted] = m_frameIds.try_emplace(address, static_cast<uint32_t>(m_frames.size()));
        if (inserted) m_frames.push_back(address);
        return it->second;
    }

    uint32_t Child(uint32_t parent, uint32_t frame)
    {
        uint64_t const key = (static_cast<uint64_t>(parent) << 32) | frame;
        auto [it, inserted] = m_children.try_emplace(key, static_cast<uint32_t>(m_nodes.size()));
        if (inserted) m_nodes.push_back({ parent, frame });
        return it->second;
    }

    // Innermost-first frame addresses of a node.
    std::vector<uint64_t> Frames(uint32_t node) const
    {
        std::vector<uint64_t> out;
        for (; node != kNone; node = m_nodes[node].parent) out.push_back(m_frames[m_nodes[node].frame]);
        return out;
    }

    std::vector<Node> const& Nodes() const noexcept { return m_nodes; }
    std::vector<uint64_t> const& FrameAddresses() const noexcept { return m_frames; }

private:
    std::vector<Node> m_nodes;
    std::vector<uint64_t> m_frames;
    std::unordered_map<uint64_t, uint32_t> m_frameIds;
    std::unordered_map<uint64_t, uint32_t> m_children;
};

} // namespace ttds
