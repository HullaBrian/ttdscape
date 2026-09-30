#include "hooks.h"
#include "symbols/symbolizer.h"

#include <algorithm>

namespace ttds {

namespace {

struct HookSpec { HookKind kind; char const* name; bool heap; unsigned args; };

// Argument counts follow the native prototypes (x64 ABI: >4 are on the stack).
constexpr HookSpec kSpecs[] = {
    { HookKind::RtlAllocateHeap,           "RtlAllocateHeap",           true,  3 }, // heap, flags, size
    { HookKind::RtlFreeHeap,               "RtlFreeHeap",               true,  3 }, // heap, flags, ptr
    { HookKind::RtlReAllocateHeap,         "RtlReAllocateHeap",         true,  4 }, // heap, flags, ptr, size
    { HookKind::RtlCreateHeap,             "RtlCreateHeap",             true,  6 }, // flags, base, reserve, commit, lock, params
    { HookKind::RtlDestroyHeap,            "RtlDestroyHeap",            true,  1 }, // heap
    { HookKind::NtAllocateVirtualMemory,   "NtAllocateVirtualMemory",   false, 6 }, // proc, *base, zerobits, *size, type, protect
    { HookKind::NtAllocateVirtualMemoryEx, "NtAllocateVirtualMemoryEx", false, 7 }, // proc, *base, *size, type, protect, params, count
    { HookKind::NtFreeVirtualMemory,       "NtFreeVirtualMemory",       false, 4 }, // proc, *base, *size, type
    { HookKind::NtProtectVirtualMemory,    "NtProtectVirtualMemory",    false, 5 }, // proc, *base, *size, newProt, *oldProt
    { HookKind::NtMapViewOfSection,        "NtMapViewOfSection",        false, 10 }, // section, proc, *base, zerobits, commit, *offset, *viewsize, inherit, type, protect
    { HookKind::NtMapViewOfSectionEx,      "NtMapViewOfSectionEx",      false, 9 }, // section, proc, *base, *offset, *viewsize, type, protect, params, count
    { HookKind::NtUnmapViewOfSection,      "NtUnmapViewOfSection",      false, 2 }, // proc, base
    { HookKind::NtUnmapViewOfSectionEx,    "NtUnmapViewOfSectionEx",    false, 3 }, // proc, base, flags
};
static_assert(std::size(kSpecs) == kHookCount);

} // namespace

// Reader over guest memory at a given cursor position.
RvaReader GuestImageReader(ICursorView const& cursor, uint64_t base)
{
    return [&cursor, base](uint32_t rva, std::span<uint8_t> out) {
        if (ReadGuest(cursor, base + rva, out, QueryMemoryPolicy::GloballyAggressive) != out.size()) return false;
        // Aggressive policies zero-fill unrecorded-but-mapped memory (landmine 18). An all-zero
        // read of more than a few bytes is treated as "not recorded".
        if (out.size() >= 8 && std::all_of(out.begin(), out.end(), [](uint8_t b) { return b == 0; })) return false;
        return true;
    };
}

std::wstring GuestPathToHost(std::wstring p)
{
    // Guest paths may be NT paths (\??\C:\... or \Device\HarddiskVolumeN\...).
    if (p.rfind(L"\\??\\", 0) == 0) p = p.substr(4);
    if (p.rfind(L"\\\\?\\", 0) == 0) p = p.substr(4);
    return p;
}

char const* HookName(HookKind k) noexcept { return k < HookKind::Count ? kSpecs[static_cast<size_t>(k)].name : "?"; }
bool IsHeapHook(HookKind k) noexcept { return k < HookKind::Count && kSpecs[static_cast<size_t>(k)].heap; }
unsigned HookArgCount(HookKind k) noexcept { return k < HookKind::Count ? kSpecs[static_cast<size_t>(k)].args : 0; }

void HookTable::Add(uint64_t address, HookKind kind)
{
    if ((m_count + 1) * 2 > m_slots.size()) {
        auto old = std::move(m_slots);
        m_slots.assign(std::max<size_t>(64, old.size() * 2), Slot{});
        m_mask = m_slots.size() - 1;
        m_count = 0;
        for (auto const& s : old) if (s.address) Add(s.address, s.kind);
    }
    size_t i = Hash(address) & m_mask;
    while (m_slots[i].address != 0 && m_slots[i].address != address) i = (i + 1) & m_mask;
    if (m_slots[i].address == 0) ++m_count;
    m_slots[i] = { address, kind };
}

HookResolution ResolveHooks(Trace const& trace, std::wstring const& symPath)
{
    HookResolution res;
    bool const want64 = trace.Is64();

    // Candidate ntdll modules; a WoW64 trace sees both the 64-bit and the 32-bit ntdll.
    std::vector<Module const*> candidates;
    for (Module const& m : Modules(&trace.Engine()))
        if (IEquals(ModuleBaseName(m), L"ntdll.dll")) candidates.push_back(&m);
    if (candidates.empty()) {
        res.warnings.push_back("ntdll.dll not found in the module list; no hooks installed");
        return res;
    }

    UniqueCursor cursor = trace.NewCursor();
    PositionRange const life = trace.Engine().GetLifetime();

    for (Module const* m : candidates) {
        uint64_t const base = A(m->Address);
        std::wstring const guestPath(m->pName, m->NameLength);
        std::optional<PeInfo> pe;
        std::string source;

        // 1. Recorded image in trace memory. Try a couple of positions: memory the loader or
        //    GetProcAddress touched may only be visible late in the trace.
        for (Position const& p : { life.Min, life.Max }) {
            cursor->SetPosition(p);
            auto parsed = ParsePe(GuestImageReader(*cursor, base));
            if (parsed && parsed->timeDateStamp == m->Timestamp && parsed->exports.size() > 100) {
                pe = std::move(parsed);
                source = "recorded";
                break;
            }
        }

        // 2. The file on disk at the recorded path, only if timestamp and size match.
        std::unique_ptr<PeFile> file;
        if (!pe) {
            file = std::make_unique<PeFile>(GuestPathToHost(guestPath));
            if (file->Ok()) {
                auto parsed = ParsePe(file->Reader());
                if (parsed && parsed->timeDateStamp == m->Timestamp && parsed->sizeOfImage == m->Size) {
                    pe = std::move(parsed);
                    source = "disk";
                } else {
                    res.warnings.push_back(std::format("{}: disk image does not match the recorded build (timestamp {:08x} vs {:08x})",
                        Narrow(guestPath), parsed ? parsed->timeDateStamp : 0, m->Timestamp));
                }
            }
        }

        // 3. Symbol server image (exact build) via SymFindFileInPath.
        if (!pe) {
            if (auto found = FindImageOnSymbolPath(symPath, L"ntdll.dll", m->Timestamp, static_cast<uint32_t>(m->Size))) {
                file = std::make_unique<PeFile>(*found);
                if (file->Ok()) {
                    auto parsed = ParsePe(file->Reader());
                    if (parsed && parsed->timeDateStamp == m->Timestamp) { pe = std::move(parsed); source = "symsrv"; }
                }
            }
        }

        if (!pe) {
            res.warnings.push_back("could not read the export table of " + Narrow(guestPath));
            continue;
        }
        if (pe->is64 != want64) continue; // the other-bitness ntdll in a WoW64 trace

        res.ntdllPath = Narrow(guestPath);
        res.ntdllBase = base;
        res.exportSource = source;
        for (auto const& spec : kSpecs) {
            auto it = pe->exports.find(spec.name);
            if (it == pe->exports.end()) {
                if (spec.kind != HookKind::NtMapViewOfSectionEx && spec.kind != HookKind::NtUnmapViewOfSectionEx &&
                    spec.kind != HookKind::NtAllocateVirtualMemoryEx)
                    res.warnings.push_back(std::string("export not found: ") + spec.name);
                continue;
            }
            res.sites.push_back({ spec.kind, base + it->second, source });
        }

        // Syscall number -> name map (for the gap census), from stub bytes of Nt* exports.
        RvaReader reader = file ? file->Reader() : GuestImageReader(*cursor, base);
        for (auto const& [name, rva] : pe->exports) {
            if (name.rfind("Nt", 0) != 0) continue;
            uint8_t stub[12]{};
            if (!reader(rva, stub)) continue;
            auto const stubs = ScanSyscallStubs(stub, rva, want64);
            if (!stubs.empty() && stubs.begin()->first == rva) res.ssnNames.emplace(stubs.begin()->second, name);
        }
        break;
    }

    if (res.sites.empty() && res.warnings.empty())
        res.warnings.push_back("no ntdll matching the guest architecture was found");
    return res;
}

} // namespace ttds
