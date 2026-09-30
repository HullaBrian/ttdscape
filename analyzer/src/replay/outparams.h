#pragma once
#include "hooks.h"

#include <cstdint>

namespace ttds {

// Syscall out-parameters (ReplayAPI.md §9, "the kernel-write gap").
// The kernel's write to *BaseAddress / *RegionSize / *OldProtect is often not visible to the
// thread-local view at the RET. Each field is therefore resolved in this order:
//   Computed  - derived from the request by the kernel's fixed rounding rules (non-zero base)
//   AtReturn  - thread-local value at the RET that passes the field's invariant
//   Readback  - retried on later callbacks of the same thread until the guest reads it back
//   Seek      - post-pass query with InFragmentAggressive at the return position
//   Unknown   - never resolved; the call is kept but not placed in the region model
// A value is never taken from the caller's pre-call contents.
enum class OutSrc : uint8_t { None, Computed, AtReturn, Readback, Seek, Unknown };
char const* OutSrcName(OutSrc s) noexcept;

enum class OutFieldKind : uint8_t { Base, Size, OldProtect };

struct OutField
{
    uint64_t slot = 0;   // guest address of the out-param (0 = not applicable)
    uint64_t pre = 0;    // value in the slot at CALL time
    uint64_t value = 0;  // resolved value
    OutSrc   src = OutSrc::None;
    bool     wanted = false; // needs a value read from memory
    bool     stalePre = false; // the slot still held an unresolved kernel write from an earlier call

    bool Resolved() const noexcept { return src == OutSrc::Computed || src == OutSrc::AtReturn || src == OutSrc::Readback || src == OutSrc::Seek; }
};

struct OutParams
{
    OutField base, size, oldProt;
};

constexpr uint64_t kPage = 0x1000, kAllocGranularity = 0x10000;
constexpr uint64_t PageDown(uint64_t v) noexcept { return v & ~(kPage - 1); }
constexpr uint64_t PageUp(uint64_t v) noexcept { return (v + kPage - 1) & ~(kPage - 1); }
constexpr bool IsPageGranular(uint64_t v) noexcept { return v != 0 && (v % kPage) == 0; }
bool IsValidProtect(uint64_t v) noexcept;

// Windows memory constants (avoid depending on winnt.h in tests).
constexpr uint32_t kMemCommit = 0x1000, kMemReserve = 0x2000, kMemDecommit = 0x4000, kMemRelease = 0x8000;

// Guest-address slots of the out-params for a call, from its entry arguments.
OutParams OutParamSlots(HookKind kind, uint64_t const* args) noexcept;

// Applies the rounding rules after a successful call. Fills Computed fields and marks the rest
// 'wanted'. 'regionSizeUnknown' fields (size 0 on free) stay unwanted with value 0: the region
// model supplies them.
void PlanOutParams(HookKind kind, uint64_t const* args, OutParams& p) noexcept;

// Whether a candidate value read from memory is acceptable as the kernel's answer.
bool AcceptOutValue(OutFieldKind f, uint64_t value, uint64_t pre) noexcept;

// Whether an NTSTATUS return value (in the low 32 bits) indicates success.
constexpr bool NtSuccess(uint64_t ret) noexcept { return static_cast<int32_t>(static_cast<uint32_t>(ret)) >= 0; }

} // namespace ttds
