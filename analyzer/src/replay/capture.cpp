#include "replay/capture.h"
#include "replay/shadow_stack.h"

#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>
#include <unordered_map>

namespace ttds {

namespace {

struct PendingRead
{
    uint32_t     call;
    OutFieldKind field;
    uint64_t     slot;
    uint64_t     pre;
    uint32_t     attemptsLeft;
};

struct ThreadState
{
    ShadowStack              stack;
    std::vector<PendingRead> pending;
};

OutField& FieldOf(OutParams& p, OutFieldKind k) noexcept
{
    switch (k) {
    case OutFieldKind::Base: return p.base;
    case OutFieldKind::Size: return p.size;
    default: return p.oldProt;
    }
}

bool IsNtHook(HookKind k) noexcept { return !IsHeapHook(k); }

class Capturer
{
public:
    Capturer(Trace const& trace, HookResolution const& hooks, CaptureOptions const& opts)
        : m_trace(trace), m_abi(trace.Is64()), m_opts(opts)
    {
        for (auto const& s : hooks.sites) {
            m_table.Add(s.address, s.kind);
            m_sites.push_back(s.address);
        }

        IReplayEngine const& e = trace.Engine();
        uint32_t maxUtid = 0;
        for (ThreadInfo const& t : Threads(&e)) maxUtid = std::max(maxUtid, U(t.UniqueId));
        m_utidToIndex.assign(size_t{ maxUtid } + 1, 0xFFFF);
        for (ThreadInfo const& t : Threads(&e)) {
            m_utidToIndex[U(t.UniqueId)] = static_cast<uint16_t>(m_result.threads.size());
            ThreadRecord r;
            r.utid = U(t.UniqueId);
            r.osTid = U(t.Id);
            m_result.threads.push_back(r);
        }
        m_states.resize(m_result.threads.size());
        if (opts.exports && opts.exports->byAddress.Size()) m_exports = &opts.exports->byAddress;

        // Syscalls are expected from ntdll and win32u stubs; anything else is a direct syscall.
        for (Module const& m : Modules(&e)) {
            std::wstring const name = ModuleBaseName(m);
            if (IEquals(name, L"ntdll.dll") || IEquals(name, L"win32u.dll"))
                m_syscallModules.push_back({ A(m.Address), A(m.Address) + m.Size });
        }
    }

    CaptureResult Run()
    {
        UniqueCursor cursor = m_trace.NewCursor();

        auto onCallRet = [this](GuestAddress target, GuestAddress fallThrough, IThreadView const* t) noexcept {
            OnCallRet(A(target), A(fallThrough), t);
        };
        auto onEntry = [this](ICursorView::MemoryWatchpointResult const& wp, IThreadView const* t) noexcept -> bool {
            OnEntry(A(wp.Address), t);
            return false;
        };
        auto onJump = [this](GuestAddress target, IThreadView const* t) noexcept { OnIndirectJump(A(target), t); };
        auto onGap = [this](GapKind, GapEventType ev, IThreadView const* t) noexcept -> bool {
            if (ev == GapEventType::KernelCall) OnKernelCall(t);
            return false;
        };
        PositionRange const life = m_trace.Engine().GetLifetime();
        auto onProgress = [this, &life](Position const& p) noexcept {
            if (!m_opts.progress) return;
            uint64_t const lo = U(life.Min.Sequence), hi = U(life.Max.Sequence);
            uint64_t const cur = std::clamp<uint64_t>(U(p.Sequence), lo, hi);
            m_opts.progress(hi > lo ? static_cast<double>(cur - lo) / static_cast<double>(hi - lo) : 1.0);
        };

        // The lambda adapters store a pointer to the lambda: they must outlive ReplayForward (landmine 16).
        cursor->SetCallReturnCallback(onCallRet);
        cursor->SetMemoryWatchpointCallback(onEntry);
        cursor->SetGapEventCallback(onGap);
        // Tail jumps into exports: import thunks (`jmp [__imp_X]`), CFG dispatch (`jmp rax`), and
        // exports that forward to another module's export by jumping.
        if (m_exports) cursor->SetIndirectJumpCallback(onJump);
        cursor->SetReplayProgressCallback(onProgress);
        cursor->SetGapKindMask(GapKindMask::All);
        cursor->SetGapEventMask(GapEventMask::KernelCall);
        // Hooked entries are detected with execute watchpoints rather than by matching CALL
        // targets: that also catches direct `jmp rel32` and indirect tail jumps into them.
        for (auto const& site : m_sites) {
            if (!cursor->AddMemoryWatchpoint(MemoryWatchpointData{ GuestAddress{ site }, 1, DataAccessMask::Execute }))
                throw std::runtime_error(std::format("AddMemoryWatchpoint failed at {}", Hex(site)));
        }
        cursor->SetEventMask(EventMask::Gap | EventMask::MemoryWatchpoint);
        // Sequential: the shadow stacks and pending lists are order-dependent and not thread-safe.
        // Without filtering disabled, a cursor with no watchpoints replays nothing (measured).
        cursor->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially | ReplayFlags::ReplayAllSegmentsWithoutFiltering);
        cursor->SetPosition(Position::Min);

        ULONGLONG const t0 = GetTickCount64();
        for (;;) {
            auto const r = cursor->ReplayForward();
            if (r.StopReason == EventType::Gap || r.StopReason == EventType::MemoryWatchpoint) continue; // defensive
            break;
        }
        m_result.stats.replayMs = GetTickCount64() - t0;
        if (m_opts.progress) m_opts.progress(1.0);

        Finish();
        ReadThreadStacks(*cursor);
        return std::move(m_result);
    }

private:
    ThreadState& State(IThreadView const* t, uint16_t& index) noexcept
    {
        uint32_t const utid = U(t->GetThreadInfo().UniqueId);
        index = utid < m_utidToIndex.size() ? m_utidToIndex[utid] : 0xFFFF;
        if (index == 0xFFFF) {
            // A thread not in the engine list (should not happen); give it a record.
            index = static_cast<uint16_t>(m_result.threads.size());
            if (utid >= m_utidToIndex.size()) m_utidToIndex.resize(size_t{ utid } + 1, 0xFFFF);
            m_utidToIndex[utid] = index;
            ThreadRecord r;
            r.utid = utid;
            r.osTid = U(t->GetThreadInfo().Id);
            m_result.threads.push_back(r);
            m_states.emplace_back();
        }
        return m_states[index];
    }

    auto DeadFrameHandler()
    {
        return [this](ShadowStack::Frame const& f) {
            for (uint32_t c = f.call; c != kNone; c = m_chain[c]) {
                RawCall& rc = m_result.calls[c];
                if (!(rc.flags & CallReturned)) { rc.flags |= CallUnwound; ++m_result.stats.unwound; }
            }
            for (uint32_t x = f.xcall; x != kNone; x = m_result.exportCalls[x].via) {
                m_result.exportCalls[x].flags |= CallUnwound;
                FinishArgs(x, nullptr);
            }
        };
    }

    void OnCallRet(uint64_t target, uint64_t fallThrough, IThreadView const* t) noexcept
    {
        ++m_result.stats.callbacks;
        uint16_t ti;
        ThreadState& ts = State(t, ti);
        uint64_t const sp = A(t->GetStackPointer());
        ThreadRecord& tr = m_result.threads[ti];
        tr.spMin = std::min(tr.spMin, sp);
        tr.spMax = std::max(tr.spMax, sp);

        if (!ts.pending.empty()) RetryPending(ts, t, sp);

        if (fallThrough != 0) {
            ShadowStack::Frame& f = ts.stack.Push(fallThrough, sp, target, DeadFrameHandler());
            if (m_exports) {
                uint32_t const x = m_exports->Find(target);
                if (x != kNone) f.xcall = BeginExportCall(x, fallThrough, kNone, ti, ts, t, 0);
            }
            return;
        }
        ShadowStack::Frame matched{};
        if (!ts.stack.Pop(target, sp, matched, DeadFrameHandler())) return;
        if (matched.call != kNone) EndCall(matched.call, t);
        if (matched.xcall != kNone) {
            Position const pos = t->GetPosition();
            for (uint32_t x = matched.xcall; x != kNone; x = m_result.exportCalls[x].via) {
                ExportCall& xc = m_result.exportCalls[x];
                xc.retPos = pos;
                xc.flags |= CallReturned;
                FinishArgs(x, t);
            }
        }
    }

    // A jump into an export with SP at the top frame's return-address slot continues that frame:
    // the export will return to the frame's caller. Jumps from deeper inside a function (switch
    // tables, jumps within the export itself) do not match the slot and are ignored.
    void OnIndirectJump(uint64_t target, IThreadView const* t) noexcept
    {
        ++m_result.stats.indirectJumps;
        uint32_t const x = m_exports->Find(target);
        if (x == kNone) return;
        uint16_t ti;
        ThreadState& ts = State(t, ti);
        ShadowStack::Frame* top = ts.stack.Top();
        if (!top || top->sp != A(t->GetStackPointer())) return;
        if (top->xcall != kNone && m_result.exportCalls[top->xcall].callee == x) return;
        top->xcall = BeginExportCall(x, top->retAddr, top->xcall, ti, ts, t, CallTail);
        ++m_result.stats.exportTailCalls;
    }

    uint32_t BeginExportCall(uint32_t callee, uint64_t caller, uint32_t via, uint16_t ti, ThreadState& ts, IThreadView const* t, uint8_t flags) noexcept
    {
        ExportCall c;
        c.callPos = t->GetPosition();
        c.caller = caller;
        c.callee = callee;
        c.via = via;
        c.thread = ti;
        c.flags = flags;
        c.depth = static_cast<uint8_t>(std::min<size_t>(ts.stack.Depth() - 1, 255));
        // The shadow stack's top frame returns to the caller, so it is the caller's call stack.
        std::array<uint64_t, 256> buf;
        size_t const n = ts.stack.Collect(buf.data(), std::min<size_t>(m_opts.stackDepth, buf.size()));
        c.stack = m_result.stacks.Intern({ buf.data(), n });
        m_result.exportCalls.push_back(c);
        ++m_result.stats.exportCalls;
        uint32_t const idx = static_cast<uint32_t>(m_result.exportCalls.size() - 1);
        if (m_opts.args) {
            ExportSym const& sym = m_opts.exports->symbols[callee];
            m_result.exportArgs.emplace_back();
            m_activeArgs.emplace(idx, m_opts.args->Begin(sym.name.c_str(), sym.is64, t));
        }
        return idx;
    }

    // Renders a call's arguments at its RET (t) or when its frame dies without one (t null).
    void FinishArgs(uint32_t x, IThreadView const* t)
    {
        auto it = m_activeArgs.find(x);
        if (it == m_activeArgs.end()) return;
        m_result.exportArgs[x] = t ? m_opts.args->End(*it->second, t) : m_opts.args->Abandon(*it->second);
        m_activeArgs.erase(it);
    }

    // Execute watchpoint on a hooked entry. SP points at the return address, which belongs to the
    // top shadow frame: pushed by the CALL that targeted this entry, or (for a tail jump) by the
    // CALL of the function that jumped here.
    void OnEntry(uint64_t address, IThreadView const* t) noexcept
    {
        HookKind const kind = m_table.Find(address);
        if (kind == HookKind::Count) return;
        uint16_t ti;
        ThreadState& ts = State(t, ti);
        uint64_t const sp = A(t->GetStackPointer());
        ShadowStack::Frame* top = ts.stack.Top();
        if (!top || top->sp != sp) {
            // Entered from a frame we never saw called: synthesize it from the return address.
            uint64_t ret = 0;
            m_abi.ReadPtr(t, sp, ret);
            top = &ts.stack.Push(ret, sp, 0, DeadFrameHandler());
        }
        bool const tail = top->callee != address;
        if (tail) ++m_result.stats.tailCalls;
        BeginCall(kind, t, ti, ts, *top, tail);
    }

    void OnKernelCall(IThreadView const* t) noexcept
    {
        ++m_result.stats.kernelCalls;
        uint64_t pc = A(t->GetProgramCounter());
        if (!m_abi.Is64()) {
            // WoW64: the gap's PC is the transition target, outside every module (ReplayAPI.md
            // landmine 31). The syscall came from the stub that called it: [ESP] is its return address.
            uint64_t ret = 0;
            if (m_abi.ReadPtr(t, A(t->GetStackPointer()), ret)) pc = ret;
        }
        for (auto const& [lo, hi] : m_syscallModules) if (pc >= lo && pc < hi) return;
        ++m_result.stats.kernelCallsOutsideNtdll;
        if (m_result.directSyscalls.size() < 100000) {
            uint16_t ti;
            State(t, ti);
            m_result.directSyscalls.push_back({ t->GetPosition(), ti, pc });
        }
    }

    void BeginCall(HookKind kind, IThreadView const* t, uint16_t ti, ThreadState& ts, ShadowStack::Frame& frame, bool tail)
    {
        uint32_t const idx = static_cast<uint32_t>(m_result.calls.size());
        RawCall c;
        c.kind = kind;
        c.thread = ti;
        c.callPos = t->GetPosition();
        m_abi.ReadArgs(t, HookArgCount(kind), c.args);

        // Enclosing hooked call: the frame's own call (tail chain) or any deeper frame's.
        uint32_t chainPrev = kNone;
        if (tail && frame.call != kNone) chainPrev = frame.call;
        uint32_t const saved = frame.call;
        frame.call = kNone;
        c.outer = chainPrev != kNone ? chainPrev : ts.stack.InnermostCall();
        frame.call = saved;
        if (c.outer != kNone) c.flags |= CallNested;
        if (tail) c.flags |= CallTail;

        std::array<uint64_t, 256> buf;
        size_t const n = ts.stack.Collect(buf.data(), std::min<size_t>(m_opts.stackDepth, buf.size()));
        c.stack = m_result.stacks.Intern({ buf.data(), n });

        if (IsNtHook(kind)) {
            c.out = OutParamSlots(kind, c.args);
            if (c.out.base.slot) m_abi.ReadPtr(t, c.out.base.slot, c.out.base.pre);
            if (c.out.size.slot) m_abi.ReadPtr(t, c.out.size.slot, c.out.size.pre);
            if (c.out.oldProt.slot) m_abi.ReadU32(t, c.out.oldProt.slot, c.out.oldProt.pre);
            // A newer call claiming the same slot retires older pending reads of it (§9).
            if (!ts.pending.empty()) {
                for (auto it = ts.pending.begin(); it != ts.pending.end();) {
                    uint64_t const s = it->slot;
                    if (s == c.out.base.slot || s == c.out.size.slot || s == c.out.oldProt.slot) {
                        // The slot still holds an earlier kernel write we never saw: what we just
                        // read as this call's input is stale, not what the kernel will see.
                        if (s == c.out.base.slot && c.out.base.pre == it->pre) c.out.base.stalePre = true;
                        if (s == c.out.size.slot && c.out.size.pre == it->pre) c.out.size.stalePre = true;
                        ++m_result.stats.outExpired;
                        it = ts.pending.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
        }

        frame.call = idx;
        m_chain.push_back(chainPrev);
        m_result.calls.push_back(c);
        ++m_result.stats.hookedCalls;
    }

    void EndCall(uint32_t idx, IThreadView const* t)
    {
        Position const pos = t->GetPosition();
        uint64_t const ret = m_abi.Ret(t);
        uint16_t ti;
        ThreadState& ts = State(t, ti);
        for (uint32_t c = idx; c != kNone; c = m_chain[c]) {
            RawCall& rc = m_result.calls[c];
            if (rc.flags & CallReturned) continue;
            rc.retPos = pos;
            rc.ret = ret;
            rc.flags |= CallReturned;
            if (IsNtHook(rc.kind) && NtSuccess(ret)) {
                PlanOutParams(rc.kind, rc.args, rc.out);
                TryField(rc, c, OutFieldKind::Base, t, ts);
                TryField(rc, c, OutFieldKind::Size, t, ts);
                TryField(rc, c, OutFieldKind::OldProtect, t, ts);
            }
        }
    }

    bool ReadField(IThreadView const* t, OutFieldKind k, uint64_t slot, uint64_t& v) const noexcept
    {
        return k == OutFieldKind::OldProtect ? m_abi.ReadU32(t, slot, v) : m_abi.ReadPtr(t, slot, v);
    }

    void TryField(RawCall& rc, uint32_t idx, OutFieldKind k, IThreadView const* t, ThreadState& ts)
    {
        OutField& f = FieldOf(rc.out, k);
        if (!f.wanted) return;
        uint64_t v = 0;
        if (ReadField(t, k, f.slot, v) && AcceptOutValue(k, v, f.pre)) {
            f.value = v;
            f.src = OutSrc::AtReturn;
            f.wanted = false;
            ++m_result.stats.outAtReturn;
            return;
        }
        ts.pending.push_back({ idx, k, f.slot, f.pre, m_opts.readbackAttempts });
    }

    // Workaround B (ReplayAPI.md §9): the kernel's value becomes thread-local-visible once the
    // guest reads it back, so retry on subsequent callbacks of the same thread.
    void RetryPending(ThreadState& ts, IThreadView const* t, uint64_t sp)
    {
        for (size_t i = ts.pending.size(); i-- > 0;) {
            PendingRead& p = ts.pending[i];
            OutField& f = FieldOf(m_result.calls[p.call].out, p.field);
            uint64_t v = 0;
            bool done = false;
            if (ReadField(t, p.field, p.slot, v) && AcceptOutValue(p.field, v, p.pre)) {
                f.value = v;
                f.src = OutSrc::Readback;
                f.wanted = false;
                ++m_result.stats.outReadback;
                done = true;
            } else if (--p.attemptsLeft == 0 || (p.slot < sp && sp - p.slot < (16ull << 20))) {
                // Out of attempts, or the slot is in a popped stack frame (below SP).
                ++m_result.stats.outExpired;
                done = true;
            }
            if (done) {
                ts.pending[i] = ts.pending.back();
                ts.pending.pop_back();
            }
        }
    }

    void Finish()
    {
        for (auto& ts : m_states) {
            m_result.stats.unmatchedRets += ts.stack.Unmatched();
            m_result.stats.retargeted += ts.stack.Retargeted();
            m_result.stats.stackOverflows += ts.stack.Overflows();
            m_result.stats.outExpired += ts.pending.size();
            ts.pending.clear();
        }
        for (auto const& c : m_result.calls)
            if (!(c.flags & (CallReturned | CallUnwound))) ++m_result.stats.neverReturned;
        for (auto& [x, active] : m_activeArgs) m_result.exportArgs[x] = m_opts.args->Abandon(*active);
        m_activeArgs.clear();
        // Caller return addresses share the stack frame table (and its symbolization).
        for (auto& x : m_result.exportCalls) x.callerFrame = m_result.stacks.FrameId(x.caller);
    }

    void ReadThreadStacks(ICursor& cursor)
    {
        cursor.SetCallReturnCallback(nullptr, 0);
        cursor.SetIndirectJumpCallback(nullptr, 0);
        cursor.SetGapEventCallback(nullptr, 0);
        cursor.SetReplayProgressCallback(nullptr, 0);
        bool const x64 = m_trace.Is64();
        for (auto& tr : m_result.threads) {
            ThreadInfo const& info = m_trace.Engine().GetThreadInfo(UniqueThreadId{ tr.utid });
            if (!info.ActiveTime.Min.IsValid()) continue;
            cursor.SetPositionOnThread(UniqueThreadId{ tr.utid }, info.ActiveTime.Min);
            tr.teb = A(cursor.GetTebAddress());
            if (!tr.teb) continue;
            auto rd = [&](uint64_t off) -> uint64_t {
                if (x64) return ReadValue<uint64_t>(cursor, tr.teb + off, QueryMemoryPolicy::GloballyAggressive).value_or(0);
                return ReadValue<uint32_t>(cursor, tr.teb + off, QueryMemoryPolicy::GloballyAggressive).value_or(0);
            };
            tr.stackBase = rd(x64 ? 0x08 : 0x04);
            tr.stackLimit = rd(x64 ? 0x10 : 0x08);
            tr.deallocStack = rd(x64 ? 0x1478 : 0xE0C);
            // Sanity: the observed SP range must lie inside the claimed stack.
            if (tr.spMax != 0 && (tr.spMax > tr.stackBase || (tr.deallocStack && tr.spMin < tr.deallocStack))) {
                tr.stackBase = tr.stackLimit = tr.deallocStack = 0;
            }
        }
    }

    Trace const&                m_trace;
    GuestAbi                    m_abi;
    CaptureOptions const&       m_opts;
    HookTable                   m_table;
    std::vector<uint64_t>       m_sites;
    CaptureResult               m_result;
    std::vector<ThreadState>    m_states;
    std::vector<uint16_t>       m_utidToIndex;
    std::vector<uint32_t>       m_chain; // per call: previous call in a tail chain sharing one frame
    std::vector<std::pair<uint64_t, uint64_t>> m_syscallModules;
    AddressMap const*           m_exports = nullptr;
    std::unordered_map<uint32_t, ArgDecoder::ActivePtr> m_activeArgs; // export calls in flight
};

} // namespace

CaptureResult Capture(Trace const& trace, HookResolution const& hooks, CaptureOptions const& opts)
{
    Capturer c(trace, hooks, opts);
    return c.Run();
}

void ResolveRemainingOutParams(Trace const& trace, CaptureResult& cap, size_t seekBudget)
{
    std::vector<uint32_t> todo;
    for (uint32_t i = 0; i < cap.calls.size(); ++i) {
        auto const& o = cap.calls[i].out;
        if (o.base.wanted || o.size.wanted || o.oldProt.wanted) todo.push_back(i);
    }
    if (todo.empty()) return;
    std::sort(todo.begin(), todo.end(), [&](uint32_t a, uint32_t b) { return cap.calls[a].retPos < cap.calls[b].retPos; });

    UniqueCursor cursor = trace.NewCursor();
    bool const x64 = trace.Is64();
    size_t seeks = 0;
    for (uint32_t i : todo) {
        RawCall& c = cap.calls[i];
        bool const needSeek = c.out.base.wanted || c.out.size.wanted;
        bool const canSeek = needSeek && seeks < seekBudget && c.retPos.IsValid();
        if (canSeek) {
            ++seeks;
            cursor->SetPositionOnThread(UniqueThreadId{ cap.threads[c.thread].utid }, c.retPos);
        }
        auto resolve = [&](OutField& f, OutFieldKind k) {
            if (!f.wanted) return;
            f.wanted = false;
            if (canSeek) {
                uint64_t v = 0;
                bool ok;
                if (k == OutFieldKind::OldProtect || !x64) {
                    auto r = ReadValue<uint32_t>(*cursor, f.slot, QueryMemoryPolicy::InFragmentAggressive);
                    ok = r.has_value();
                    v = r.value_or(0);
                } else {
                    auto r = ReadValue<uint64_t>(*cursor, f.slot, QueryMemoryPolicy::InFragmentAggressive);
                    ok = r.has_value();
                    v = r.value_or(0);
                }
                if (ok && AcceptOutValue(k, v, f.pre)) { f.value = v; f.src = OutSrc::Seek; return; }
            }
            f.src = OutSrc::Unknown;
        };
        resolve(c.out.base, OutFieldKind::Base);
        resolve(c.out.size, OutFieldKind::Size);
        // OldProtect is not worth a seek: the region model knows the previous protection of every
        // page it tracks, and the value is only used to seed pages committed before the trace.
        if (c.out.oldProt.wanted) { c.out.oldProt.wanted = false; c.out.oldProt.src = OutSrc::Unknown; }
    }
}

} // namespace ttds

namespace ttds {

size_t ResolveByWatchpoints(Trace const& trace, CaptureResult& cap)
{
    struct Want
    {
        uint32_t     call;
        OutFieldKind field;
        uint64_t     slot;
        uint32_t     utid;
        Position     from, to;
        uint32_t     nextCall;           // the call that next claims the slot (ends the window), or kNone
        bool         done = false, followup = false, guestWrote = false;
    };
    std::vector<Want> wants;
    auto fieldOf = [&](RawCall& c, OutFieldKind k) -> OutField& {
        return k == OutFieldKind::Base ? c.out.base : k == OutFieldKind::Size ? c.out.size : c.out.oldProt;
    };

    // Next call on the same thread claiming each slot bounds the window in which a hit belongs to us.
    std::unordered_map<uint64_t, std::vector<std::pair<Position, uint32_t>>> claims; // (utid<<48 ^ slot) -> (callPos, call)
    auto key = [](uint32_t utid, uint64_t slot) { return (static_cast<uint64_t>(utid) << 48) ^ slot; };
    for (uint32_t i = 0; i < cap.calls.size(); ++i) {
        RawCall const& c = cap.calls[i];
        uint32_t const utid = cap.threads[c.thread].utid;
        for (OutField const* f : { &c.out.base, &c.out.size, &c.out.oldProt })
            if (f->slot) claims[key(utid, f->slot)].push_back({ c.callPos, i });
    }
    for (auto& [k, v] : claims) std::sort(v.begin(), v.end());

    for (uint32_t i = 0; i < cap.calls.size(); ++i) {
        RawCall& c = cap.calls[i];
        if (!c.retPos.IsValid()) continue;
        uint32_t const utid = cap.threads[c.thread].utid;
        for (OutFieldKind k : { OutFieldKind::Base, OutFieldKind::Size }) {
            OutField const& f = fieldOf(c, k);
            if (!f.wanted) continue;
            Position to = Position::Max;
            uint32_t next = kNone;
            for (auto const& [pos, j] : claims[key(utid, f.slot)])
                if (j != i && c.retPos < pos) { to = pos; next = j; break; }
            wants.push_back({ i, k, f.slot, utid, c.retPos, to, next });
        }
    }
    if (wants.empty()) return 0;

    uint32_t const ptr = trace.PtrSize();
    UniqueCursor cursor = trace.NewCursor();
    std::set<std::pair<uint64_t, uint32_t>> added;
    for (auto const& w : wants) {
        if (!added.insert({ w.slot, w.utid }).second) continue;
        MemoryWatchpointData const wp{ GuestAddress{ w.slot }, ptr,
            DataAccessMask::Read | DataAccessMask::Write | DataAccessMask::DataMismatch | DataAccessMask::NewData, UniqueThreadId{ w.utid } };
        if (!cursor->AddMemoryWatchpoint(wp)) // landmine 22: a silently missing watchpoint looks like "no hits"
            throw std::runtime_error(std::format("AddMemoryWatchpoint failed for out-param slot {}", Hex(w.slot)));
    }

    struct Followup { size_t want; Position pos; };
    std::vector<Followup> followups;
    size_t resolved = 0;
    auto onHit = [&](ICursorView::MemoryWatchpointResult const& hit, IThreadView const* t) noexcept -> bool {
        Position const pos = t->GetPosition();
        uint32_t const utid = U(t->GetThreadInfo().UniqueId);
        // The latest pending call whose window contains this access owns it.
        size_t best = SIZE_MAX;
        for (size_t i = 0; i < wants.size(); ++i) {
            Want const& w = wants[i];
            if (w.done || w.followup || w.utid != utid) continue;
            if (w.slot + ptr <= A(hit.Address) || A(hit.Address) + hit.Size <= w.slot) continue;
            if (!(w.from < pos) || !(pos < w.to)) continue;
            if (best == SIZE_MAX || wants[best].from < w.from) best = i;
        }
        if (best == SIZE_MAX) return false;
        Want& w = wants[best];
        OutField& f = fieldOf(cap.calls[w.call], w.field);
        if (hit.AccessType == DataAccessType::Write) {
            // The guest overwrote the slot before anyone read the kernel's value: it is gone.
            w.guestWrote = true;
            w.done = true;
            return false;
        }
        if (hit.AccessType == DataAccessType::Read) {
            uint64_t v = 0;
            bool ok = false;
            if (ptr == 8) ok = ReadThreadLocal(t, w.slot, v);
            else { uint32_t v32 = 0; ok = ReadThreadLocal(t, w.slot, v32); v = v32; }
            if (ok && AcceptOutValue(w.field, v, f.pre)) {
                f.value = v; f.src = OutSrc::Readback; f.wanted = false; w.done = true; ++resolved;
            }
            return false;
        }
        // DataMismatch / NewData: the new bytes are not visible yet; read them one step later.
        w.followup = true;
        followups.push_back({ best, pos });
        return false;
    };
    cursor->SetMemoryWatchpointCallback(onHit);
    cursor->SetEventMask(EventMask::MemoryWatchpoint);
    cursor->SetReplayFlags(ReplayFlags::ReplaySegmentsSequentially);
    cursor->SetPosition(Position::Min);
    for (;;) {
        auto const r = cursor->ReplayForward();
        if (r.StopReason == EventType::MemoryWatchpoint) continue;
        break;
    }

    // Follow-ups on a fresh cursor (a cursor with watchpoints would re-fire them: landmine 28).
    UniqueCursor reader = trace.NewCursor();
    for (auto const& fu : followups) {
        Want& w = wants[fu.want];
        OutField& f = fieldOf(cap.calls[w.call], w.field);
        reader->SetPositionOnThread(UniqueThreadId{ w.utid }, fu.pos + StepCount{ 1 });
        for (QueryMemoryPolicy policy : { QueryMemoryPolicy::ThreadLocal, QueryMemoryPolicy::InFragmentAggressive }) {
            uint64_t v = 0;
            bool ok;
            if (ptr == 8) { auto r = ReadValue<uint64_t>(*reader, w.slot, policy); ok = r.has_value(); v = r.value_or(0); }
            else { auto r = ReadValue<uint32_t>(*reader, w.slot, policy); ok = r.has_value(); v = r.value_or(0); }
            if (ok && AcceptOutValue(w.field, v, f.pre)) {
                f.value = v; f.src = OutSrc::Readback; f.wanted = false; w.done = true; ++resolved;
                break;
            }
        }
    }

    // Inference: the kernel's value was consumed, unread, as the input of the next syscall on the
    // same slot (e.g. the heap's large-block path passes *BaseAddress straight from
    // NtAllocateVirtualMemory to NtFreeVirtualMemory). With no guest write in between, that call's
    // input is our output; free/protect/map round a page-aligned base to itself, so their recovered
    // base equals ours.
    for (auto& w : wants) {
        if (w.done || w.guestWrote || w.nextCall == kNone || w.field != OutFieldKind::Base) continue;
        RawCall const& next = cap.calls[w.nextCall];
        bool const pageRounding = next.kind == HookKind::NtFreeVirtualMemory || next.kind == HookKind::NtProtectVirtualMemory ||
                                  next.kind == HookKind::NtMapViewOfSection || next.kind == HookKind::NtMapViewOfSectionEx;
        OutField const& nf = next.out.base;
        if (!pageRounding || nf.slot != w.slot || !nf.stalePre || !nf.Resolved() || !IsPageGranular(nf.value)) continue;
        OutField& f = fieldOf(cap.calls[w.call], w.field);
        if (!AcceptOutValue(w.field, nf.value, f.pre)) continue;
        f.value = nf.value; f.src = OutSrc::Readback; f.wanted = false; w.done = true; ++resolved;
    }
    return resolved;
}

} // namespace ttds
