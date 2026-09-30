#pragma once
#include "engine.h"
#include "pe/recorded_pe.h"

#include <array>
#include <string>
#include <unordered_map>
#include <vector>

namespace ttds {

enum class HookKind : uint8_t
{
    RtlAllocateHeap,
    RtlFreeHeap,
    RtlReAllocateHeap,
    RtlCreateHeap,
    RtlDestroyHeap,
    NtAllocateVirtualMemory,
    NtAllocateVirtualMemoryEx,
    NtFreeVirtualMemory,
    NtProtectVirtualMemory,
    NtMapViewOfSection,
    NtMapViewOfSectionEx,
    NtUnmapViewOfSection,
    NtUnmapViewOfSectionEx,
    Count
};

constexpr size_t kHookCount = static_cast<size_t>(HookKind::Count);
char const* HookName(HookKind k) noexcept;
bool IsHeapHook(HookKind k) noexcept;
// Number of arguments captured at CALL time for each hook.
unsigned HookArgCount(HookKind k) noexcept;

struct HookSite
{
    HookKind    kind;
    uint64_t    address;
    std::string source; // "recorded" | "disk" | "symsrv"
};

struct HookResolution
{
    std::vector<HookSite> sites;
    std::string           ntdllPath;       // guest path of the ntdll the hooks were taken from
    uint64_t              ntdllBase = 0;
    std::string           exportSource;    // where the export table came from
    std::vector<std::string> warnings;
    std::unordered_map<uint32_t, std::string> ssnNames; // syscall number -> Nt* name (when known)
};

// Resolves hook addresses in the guest's ntdll (the native one matching the guest architecture).
// symPath is used for SymFindFileInPath if neither recorded memory nor disk yields the export table.
HookResolution ResolveHooks(Trace const& trace, std::wstring const& symPath);

// Reads a mapped image in guest memory by RVA (GloballyAggressive; all-zero reads count as unrecorded).
RvaReader GuestImageReader(ICursorView const& cursor, uint64_t base);
// Strips \??\ and \\?\ prefixes from a guest path so it can be opened on the host.
std::wstring GuestPathToHost(std::wstring p);

// Small open-addressing set of hooked entry addresses for the hot path.
class HookTable
{
public:
    void Add(uint64_t address, HookKind kind);
    // Returns kind or HookKind::Count if not hooked.
    HookKind Find(uint64_t address) const noexcept
    {
        if (m_slots.empty()) return HookKind::Count;
        size_t i = Hash(address) & m_mask;
        for (;;) {
            auto const& s = m_slots[i];
            if (s.address == address) return s.kind;
            if (s.address == 0) return HookKind::Count;
            i = (i + 1) & m_mask;
        }
    }
private:
    static size_t Hash(uint64_t a) noexcept { return static_cast<size_t>((a * 0x9E3779B97F4A7C15ull) >> 20); }
    struct Slot { uint64_t address = 0; HookKind kind = HookKind::Count; };
    std::vector<Slot> m_slots;
    size_t m_mask = 0;
    size_t m_count = 0;
};

} // namespace ttds
