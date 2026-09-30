// `probe`: measures the register/stack conventions of the call/return callback on a real trace
// (milestone M1). The capture pass's pairing rule depends on these numbers, so they are measured
// rather than assumed.
#include "probe.h"
#include "hooks.h"

#include <iostream>
#include <map>
#include <unordered_map>

namespace ttds {

int RunProbe(Trace const& trace, std::wstring const& symPath)
{
    HookResolution hooks = ResolveHooks(trace, symPath);
    for (auto const& w : hooks.warnings) std::cout << "warning: " << w << "\n";
    std::cout << std::format("ntdll {} @ {} (exports: {})\n", hooks.ntdllPath, Hex(hooks.ntdllBase), hooks.exportSource);
    HookTable table;
    for (auto const& s : hooks.sites) {
        std::cout << std::format("  {:<28} {}\n", HookName(s.kind), Hex(s.address));
        table.Add(s.address, s.kind);
    }

    struct Pending { uint64_t retAddr, spAtCall; HookKind kind; };
    struct State {
        HookTable const* table;
        uint32_t ptr;
        std::unordered_map<uint32_t, std::vector<Pending>> inflight;
        std::map<int64_t, size_t> retSpDelta;     // SP(ret) - SP(call)
        std::map<int64_t, size_t> pcVsFall;       // fallThrough - PC at call
        size_t topIsRetAddr = 0, topIsNotRetAddr = 0, calls = 0, rets = 0;
        std::map<int64_t, size_t> retPcDelta;     // PC at ret vs target (should be != 0)
        size_t totalCallbacks = 0;
    } st{ &table, trace.PtrSize() };

    auto cb = [&st](GuestAddress target, GuestAddress fallThrough, IThreadView const* t) noexcept {
        ++st.totalCallbacks;
        uint32_t const utid = U(t->GetThreadInfo().UniqueId);
        uint64_t const sp = A(t->GetStackPointer());
        if (fallThrough != GuestAddress::Null) {
            HookKind const k = st.table->Find(A(target));
            if (k == HookKind::Count) return;
            ++st.calls;
            ++st.pcVsFall[static_cast<int64_t>(A(fallThrough) - A(t->GetProgramCounter()))];
            uint64_t top = 0;
            if (t->QueryMemoryBuffer(GuestAddress{ sp }, BufferView{ &top, st.ptr }).Memory.Size == st.ptr) {
                if (top == A(fallThrough)) ++st.topIsRetAddr; else ++st.topIsNotRetAddr;
            }
            st.inflight[utid].push_back({ A(fallThrough), sp, k });
            return;
        }
        auto it = st.inflight.find(utid);
        if (it == st.inflight.end() || it->second.empty()) return;
        auto& v = it->second;
        for (size_t i = v.size(); i-- > 0;) {
            if (v[i].retAddr == A(target)) {
                ++st.rets;
                ++st.retSpDelta[static_cast<int64_t>(sp - v[i].spAtCall)];
                ++st.retPcDelta[static_cast<int64_t>(A(target) - A(t->GetProgramCounter()))];
                v.resize(i);
                return;
            }
        }
    };

    UniqueCursor cursor = trace.NewCursor();
    cursor->SetCallReturnCallback(cb);
    // Without ReplayAllSegmentsWithoutFiltering a cursor with no maskable events replays nothing
    // (measured: 0 callbacks in 47 ms on beacon_x6401).
    cursor->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially | ReplayFlags::ReplayAllSegmentsWithoutFiltering);
    cursor->SetPosition(Position::Min);
    auto const t0 = GetTickCount64();
    auto const r = cursor->ReplayForward();
    std::cout << std::format("replay: {} in {} ms, {} call/ret callbacks\n", GetEventTypeName(r.StopReason),
                             GetTickCount64() - t0, st.totalCallbacks);
    std::cout << std::format("hooked calls {}, paired rets {}\n", st.calls, st.rets);
    std::cout << std::format("[SP] at CALL == return address: {} yes / {} no\n", st.topIsRetAddr, st.topIsNotRetAddr);
    std::cout << "fallThrough - PC at CALL:\n";
    for (auto [d, n] : st.pcVsFall) std::cout << std::format("  {:+}: {}\n", d, n);
    std::cout << "SP(ret) - SP(call):\n";
    for (auto [d, n] : st.retSpDelta) std::cout << std::format("  {:+}: {}\n", d, n);
    std::cout << "target - PC at RET:\n";
    for (auto [d, n] : st.retPcDelta) std::cout << std::format("  {:+}: {}\n", d, n);
    return 0;
}

} // namespace ttds
