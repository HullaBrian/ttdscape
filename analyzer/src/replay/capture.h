#pragma once
#include "abi/guest_abi.h"
#include "exports.h"
#include "hooks.h"
#include "model/stack_trie.h"
#include "replay/call_args.h"
#include "replay/outparams.h"

#include <functional>
#include <string>
#include <vector>

namespace ttds {

enum CallFlags : uint8_t
{
    CallReturned = 0x01, // the matching RET was seen
    CallUnwound  = 0x02, // the frame was discarded without a RET (exception / longjmp)
    CallTail     = 0x04, // entered by an indirect tail jump rather than a CALL
    CallNested   = 0x08, // another hooked call was active on the same thread
};

struct RawCall
{
    HookKind  kind{};
    uint8_t   flags = 0;
    uint16_t  thread = 0;      // index into CaptureResult::threads
    uint32_t  stack = kNone;   // StackTrie node (innermost frame = caller's return address)
    uint32_t  outer = kNone;   // innermost enclosing hooked call on the same thread
    Position  callPos;
    Position  retPos;
    uint64_t  args[10]{};
    uint64_t  ret = 0;
    OutParams out;
};

// A CALL (or a tail jump) whose target is a module export. Flags are CallFlags (Returned, Unwound, Tail).
struct ExportCall
{
    Position callPos;
    Position retPos;
    uint64_t caller = 0;          // return address pushed by the CALL (the caller's code)
    uint32_t callerFrame = kNone; // StackTrie frame id of 'caller' (interned after the replay)
    uint32_t callee = 0;          // index in ExportSet::symbols
    uint32_t via = kNone;         // tail jump out of another export call on the same frame
    uint32_t stack = kNone;       // StackTrie node: the caller's return address, then its callers
    uint16_t thread = 0;
    uint8_t  flags = 0;
    uint8_t  depth = 0;           // shadow-stack depth of the caller (clamped to 255)
};

struct ThreadRecord
{
    uint32_t utid = 0;
    uint32_t osTid = 0;
    uint64_t teb = 0;
    uint64_t stackBase = 0;      // from the TEB (NT_TIB.StackBase), 0 if unreadable
    uint64_t stackLimit = 0;     // NT_TIB.StackLimit (committed low end at first read)
    uint64_t deallocStack = 0;   // TEB.DeallocationStack (reservation base), 0 if unknown
    uint64_t spMin = ~0ull, spMax = 0;
};

struct DirectSyscall
{
    Position pos;
    uint16_t thread;
    uint64_t pc;
};

struct CaptureStats
{
    uint64_t callbacks = 0;
    uint64_t hookedCalls = 0;
    uint64_t tailCalls = 0;
    uint64_t unwound = 0;
    uint64_t neverReturned = 0;
    uint64_t unmatchedRets = 0;
    uint64_t retargeted = 0;
    uint64_t stackOverflows = 0;
    uint64_t kernelCalls = 0;
    uint64_t kernelCallsOutsideNtdll = 0;
    uint64_t outAtReturn = 0, outReadback = 0, outExpired = 0;
    uint64_t exportCalls = 0, exportTailCalls = 0, indirectJumps = 0;
    uint64_t replayMs = 0;
};

struct CaptureOptions
{
    unsigned stackDepth = 48;
    unsigned readbackAttempts = 512;
    ExportSet const* exports = nullptr; // record calls into these exports (null: none)
    ArgDecoder const* args = nullptr;   // decode their arguments (null: none)
    std::function<void(double)> progress;
};

struct CaptureResult
{
    std::vector<RawCall>       calls;
    std::vector<ExportCall>    exportCalls; // in capture order
    std::vector<std::string>   exportArgs;  // decoded arguments as JSON, parallel to exportCalls (empty without a decoder)
    std::vector<ThreadRecord>  threads;
    std::vector<DirectSyscall> directSyscalls;
    StackTrie                  stacks;
    CaptureStats               stats;
};

// The single replay pass: CALL/RET + entry watchpoints + gap callbacks (+ indirect jumps when
// export calls are recorded) over the whole trace.
CaptureResult Capture(Trace const& trace, HookResolution const& hooks, CaptureOptions const& opts);

// Pass 1b (ReplayAPI.md §9): one replay with Read | DataMismatch | NewData watchpoints on every
// still-unresolved out-param slot (filtered to its thread). The first access after a call's RET and
// before the next call claiming the slot yields the kernel's value: a Read carries it directly, a
// mismatch is re-read one step later on a fresh cursor (landmines 27/28). Returns fields resolved.
size_t ResolveByWatchpoints(Trace const& trace, CaptureResult& cap);

// Resolves out-params still unknown after the capture pass by seeking to each call's return
// position and querying with InFragmentAggressive (Workaround A), subject to the same invariants.
void ResolveRemainingOutParams(Trace const& trace, CaptureResult& cap, size_t seekBudget);

} // namespace ttds
