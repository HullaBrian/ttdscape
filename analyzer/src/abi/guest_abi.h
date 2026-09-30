#pragma once
#include "engine.h"

namespace ttds {

// Guest calling-convention access from inside execution callbacks.
//
// Measured on real x64 traces (analyzer `probe`): at the CallReturnCallback for a CALL, PC is the
// CALL instruction but the return address has ALREADY been pushed ([SP] == fallThrough for 100% of
// calls), i.e. SP equals the callee's entry SP. At the matching RET, SP is identical to that value.
// So x64 stack arguments are at [SP + 0x28 + 8k] and x86 stdcall arguments at [SP + 4 + 4k].
class GuestAbi
{
public:
    explicit GuestAbi(bool is64) : m_is64(is64) {}
    bool Is64() const noexcept { return m_is64; }
    uint32_t Ptr() const noexcept { return m_is64 ? 8u : 4u; }

    // Reads the first n (<= 10) integer arguments at function entry. Unreadable stack args are 0.
    void ReadArgs(IThreadView const* t, unsigned n, uint64_t* out) const noexcept
    {
        uint64_t const sp = A(t->GetStackPointer());
        if (m_is64) {
            RegisterContext const blob = t->GetCrossPlatformContext(); // by value: bind first (landmine 2)
            auto const* ctx = reinterpret_cast<AMD64_CONTEXT const*>(&blob);
            uint64_t const regs[4] = { ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9 };
            for (unsigned i = 0; i < n; ++i) {
                if (i < 4) { out[i] = regs[i]; continue; }
                out[i] = 0;
                ReadThreadLocal(t, sp + 0x28 + 8ull * (i - 4), out[i]);
            }
        } else {
            for (unsigned i = 0; i < n; ++i) {
                uint32_t v = 0;
                ReadThreadLocal(t, sp + 4 + 4ull * i, v);
                out[i] = v;
            }
        }
    }

    // Reads a pointer-sized value (SIZE_T / PVOID) through the thread view.
    bool ReadPtr(IThreadView const* t, uint64_t address, uint64_t& out) const noexcept
    {
        if (m_is64) return ReadThreadLocal(t, address, out);
        uint32_t v = 0;
        if (!ReadThreadLocal(t, address, v)) return false;
        out = v;
        return true;
    }

    bool ReadU32(IThreadView const* t, uint64_t address, uint64_t& out) const noexcept
    {
        uint32_t v = 0;
        if (!ReadThreadLocal(t, address, v)) return false;
        out = v;
        return true;
    }

    // Return value at the RET (RAX / EAX), truncated to the guest width.
    uint64_t Ret(IThreadView const* t) const noexcept
    {
        uint64_t const v = t->GetBasicReturnValue();
        return m_is64 ? v : (v & 0xFFFFFFFFull);
    }

private:
    bool m_is64;
};

} // namespace ttds
