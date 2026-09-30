#include "replay/outparams.h"

namespace ttds {

char const* OutSrcName(OutSrc s) noexcept
{
    switch (s) {
    case OutSrc::None: return "none";
    case OutSrc::Computed: return "computed";
    case OutSrc::AtReturn: return "atReturn";
    case OutSrc::Readback: return "readback";
    case OutSrc::Seek: return "seek";
    case OutSrc::Unknown: return "unknown";
    }
    return "?";
}

bool IsValidProtect(uint64_t v) noexcept
{
    if (v > 0xFFFFFFFFull) return false;
    uint32_t const base = static_cast<uint32_t>(v) & 0xFF;
    uint32_t const mods = static_cast<uint32_t>(v) & ~0xFFu;
    bool const oneBit = base != 0 && (base & (base - 1)) == 0;
    // PAGE_GUARD 0x100, PAGE_NOCACHE 0x200, PAGE_WRITECOMBINE 0x400, PAGE_TARGETS_* 0x40000000.
    return oneBit && (mods & ~(0x100u | 0x200u | 0x400u | 0x40000000u)) == 0;
}

OutParams OutParamSlots(HookKind kind, uint64_t const* a) noexcept
{
    OutParams p;
    switch (kind) {
    case HookKind::NtAllocateVirtualMemory:   p.base.slot = a[1]; p.size.slot = a[3]; break;
    case HookKind::NtAllocateVirtualMemoryEx: p.base.slot = a[1]; p.size.slot = a[2]; break;
    case HookKind::NtFreeVirtualMemory:       p.base.slot = a[1]; p.size.slot = a[2]; break;
    case HookKind::NtProtectVirtualMemory:    p.base.slot = a[1]; p.size.slot = a[2]; p.oldProt.slot = a[4]; break;
    case HookKind::NtMapViewOfSection:        p.base.slot = a[2]; p.size.slot = a[6]; break;
    case HookKind::NtMapViewOfSectionEx:      p.base.slot = a[2]; p.size.slot = a[4]; break;
    default: break;
    }
    return p;
}

namespace {

void Set(OutField& f, uint64_t v) noexcept { f.value = v; f.src = OutSrc::Computed; f.wanted = false; }
void Want(OutField& f) noexcept { f.wanted = f.slot != 0; f.src = f.slot ? OutSrc::None : OutSrc::Unknown; }

} // namespace

void PlanOutParams(HookKind kind, uint64_t const* a, OutParams& p) noexcept
{
    switch (kind) {
    case HookKind::NtAllocateVirtualMemory:
    case HookKind::NtAllocateVirtualMemoryEx: {
        uint32_t const type = static_cast<uint32_t>(kind == HookKind::NtAllocateVirtualMemory ? a[4] : a[3]);
        uint64_t const reqBase = p.base.pre, reqSize = p.size.pre;
        if (p.base.stalePre || p.size.stalePre) { Want(p.base); Want(p.size); break; }
        if (reqBase != 0) {
            // Reserving rounds the base down to the allocation granularity, otherwise to a page;
            // the end is rounded up to a page (measured 2,262 / 2,262, ReplayAPI.md §9).
            uint64_t const base = (type & kMemReserve) ? (reqBase & ~(kAllocGranularity - 1)) : PageDown(reqBase);
            Set(p.base, base);
            Set(p.size, PageUp(reqBase + reqSize) - base);
        } else {
            Want(p.base);
            if (reqSize != 0) Set(p.size, PageUp(reqSize)); else Want(p.size);
        }
        break;
    }
    case HookKind::NtFreeVirtualMemory:
    case HookKind::NtProtectVirtualMemory: {
        uint64_t const reqBase = p.base.pre, reqSize = p.size.pre;
        // The kernel writes the rounded range back, so an input we could not see (a stale slot
        // still holding an unresolved kernel write) is recovered by reading the slot afterwards.
        if (p.base.stalePre || reqBase == 0) {
            Want(p.base);
            Want(p.size);
        } else {
            uint64_t const base = PageDown(reqBase);
            Set(p.base, base);
            // Size 0 on a free means "the whole region" (release) or "to the end of the region"
            // (decommit); the region model resolves it.
            if (p.size.stalePre) Want(p.size);
            else if (reqSize != 0) Set(p.size, PageUp(reqBase + reqSize) - base);
            else { p.size.value = 0; p.size.src = OutSrc::Computed; p.size.wanted = false; }
        }
        if (kind == HookKind::NtProtectVirtualMemory) Want(p.oldProt);
        break;
    }
    case HookKind::NtMapViewOfSection:
    case HookKind::NtMapViewOfSectionEx: {
        if (p.base.pre != 0 && !p.base.stalePre) Set(p.base, PageDown(p.base.pre)); else Want(p.base);
        if (p.size.pre != 0 && !p.size.stalePre) Set(p.size, PageUp(p.size.pre)); else Want(p.size);
        break;
    }
    default:
        break;
    }
}

bool AcceptOutValue(OutFieldKind f, uint64_t v, uint64_t pre) noexcept
{
    switch (f) {
    case OutFieldKind::Base:       return IsPageGranular(v) && v != pre;
    case OutFieldKind::Size:       return IsPageGranular(v) && (v != pre || IsPageGranular(pre));
    case OutFieldKind::OldProtect: return IsValidProtect(v) && v != pre;
    }
    return false;
}

} // namespace ttds
