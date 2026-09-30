#include "check.h"
#include "replay/outparams.h"

using namespace ttds;

TEST(allocate_with_nonzero_base_is_computed_by_rounding)
{
    uint64_t args[10] = { ~0ull, 0x5000, 0, 0x5008, kMemReserve | kMemCommit, 4 };
    OutParams p = OutParamSlots(HookKind::NtAllocateVirtualMemory, args);
    CHECK_EQ(p.base.slot, 0x5000u);
    CHECK_EQ(p.size.slot, 0x5008u);
    p.base.pre = 0x12345678;
    p.size.pre = 0x100;
    PlanOutParams(HookKind::NtAllocateVirtualMemory, args, p);
    CHECK(p.base.src == OutSrc::Computed);
    CHECK_EQ(p.base.value, 0x12340000u);                  // reserve: 64 KB granularity
    CHECK_EQ(p.size.value, 0x12346000u - 0x12340000u);    // end rounded up to a page
    CHECK(!p.base.wanted && !p.size.wanted);
}

TEST(commit_only_rounds_base_to_page)
{
    uint64_t args[10] = { ~0ull, 0x5000, 0, 0x5008, kMemCommit, 4 };
    OutParams p = OutParamSlots(HookKind::NtAllocateVirtualMemory, args);
    p.base.pre = 0x10081234;
    p.size.pre = 0x100;
    PlanOutParams(HookKind::NtAllocateVirtualMemory, args, p);
    CHECK_EQ(p.base.value, 0x10081000u);
    CHECK_EQ(p.size.value, 0x1000u);
}

TEST(zero_base_needs_a_readback_and_size_is_rounded)
{
    uint64_t args[10] = { ~0ull, 0x5000, 0, 0x5008, kMemReserve, 1 };
    OutParams p = OutParamSlots(HookKind::NtAllocateVirtualMemory, args);
    p.base.pre = 0;
    p.size.pre = 0x15cb48;
    PlanOutParams(HookKind::NtAllocateVirtualMemory, args, p);
    CHECK(p.base.wanted);
    CHECK_EQ(p.size.value, 0x15d000u); // the example from ReplayAPI.md §9
}

TEST(acceptance_rejects_stale_and_unaligned_values)
{
    CHECK(!AcceptOutValue(OutFieldKind::Base, 0, 0));
    CHECK(!AcceptOutValue(OutFieldKind::Base, 0x2e0034002d0041ull, 0)); // UTF-16 junk from §9
    CHECK(AcceptOutValue(OutFieldKind::Base, 0x1710000, 0));
    CHECK(!AcceptOutValue(OutFieldKind::Size, 0x15cb48, 0x15cb48));      // the caller's request
    CHECK(AcceptOutValue(OutFieldKind::Size, 0x15d000, 0x15cb48));
    CHECK(AcceptOutValue(OutFieldKind::OldProtect, 0x02, 0));
    CHECK(!AcceptOutValue(OutFieldKind::OldProtect, 0x02, 0x02));
    CHECK(!AcceptOutValue(OutFieldKind::OldProtect, 0x06, 0));           // two base bits
    CHECK(AcceptOutValue(OutFieldKind::OldProtect, 0x104, 0));           // RW | GUARD
}

TEST(protect_and_free_rules)
{
    uint64_t args[10] = { ~0ull, 0x5000, 0x5008, 0x20, 0x5010 };
    OutParams p = OutParamSlots(HookKind::NtProtectVirtualMemory, args);
    CHECK_EQ(p.oldProt.slot, 0x5010u);
    p.base.pre = 0x7000123;
    p.size.pre = 0x2000;
    PlanOutParams(HookKind::NtProtectVirtualMemory, args, p);
    CHECK_EQ(p.base.value, 0x7000000u);
    CHECK_EQ(p.size.value, 0x3000u);
    CHECK(p.oldProt.wanted);

    uint64_t fargs[10] = { ~0ull, 0x5000, 0x5008, kMemRelease };
    OutParams f = OutParamSlots(HookKind::NtFreeVirtualMemory, fargs);
    f.base.pre = 0x7000000;
    f.size.pre = 0;
    PlanOutParams(HookKind::NtFreeVirtualMemory, fargs, f);
    CHECK_EQ(f.size.value, 0u); // whole region: the model resolves it
    CHECK(!f.size.wanted);
}

TEST(ntstatus)
{
    CHECK(NtSuccess(0));
    CHECK(NtSuccess(0x103)); // STATUS_PENDING is a success code
    CHECK(!NtSuccess(0xC0000018));
    CHECK(!NtSuccess(0xFFFFFFFFC0000018ull));
}

TEST_MAIN
