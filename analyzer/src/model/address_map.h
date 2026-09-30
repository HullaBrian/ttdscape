#pragma once
#include "model/stack_trie.h"

#include <cstdint>
#include <vector>

namespace ttds {

// Open-addressing map from a guest address to a 32-bit value, for lookups inside replay callbacks
// (one multiply and usually one probe; no allocation). Address 0 is reserved as the empty slot.
class AddressMap
{
public:
    // Keeps the first value added for an address.
    void Add(uint64_t address, uint32_t value)
    {
        if (address == 0) return;
        if ((m_count + 1) * 2 > m_slots.size()) Grow();
        size_t i = Hash(address) & m_mask;
        while (m_slots[i].address != 0) {
            if (m_slots[i].address == address) return;
            i = (i + 1) & m_mask;
        }
        m_slots[i] = { address, value };
        ++m_count;
    }

    // The value for an address, or kNone.
    uint32_t Find(uint64_t address) const noexcept
    {
        if (m_count == 0) return kNone;
        size_t i = Hash(address) & m_mask;
        for (;;) {
            Slot const& s = m_slots[i];
            if (s.address == address) return s.value;
            if (s.address == 0) return kNone;
            i = (i + 1) & m_mask;
        }
    }

    size_t Size() const noexcept { return m_count; }

private:
    struct Slot { uint64_t address = 0; uint32_t value = kNone; };

    static size_t Hash(uint64_t a) noexcept { return static_cast<size_t>((a * 0x9E3779B97F4A7C15ull) >> 24); }

    void Grow()
    {
        std::vector<Slot> old = std::move(m_slots);
        m_slots.assign(old.empty() ? 1024 : old.size() * 2, Slot{});
        m_mask = m_slots.size() - 1;
        m_count = 0;
        for (Slot const& s : old) if (s.address) Add(s.address, s.value);
    }

    std::vector<Slot> m_slots;
    size_t m_mask = 0;
    size_t m_count = 0;
};

} // namespace ttds
