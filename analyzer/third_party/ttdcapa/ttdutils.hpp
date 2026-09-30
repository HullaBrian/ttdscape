#ifndef TTDUITLS_HPP
#define TTDUITLS_HPP

#include <windows.h>
#include <iostream>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <string>
#include <variant>
#include <vector>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>

#include "log.hpp"
#include "win32meta.hpp"

namespace ttdcapa {
    // One call argument: either an integer or a dereferenced string
    using ArgValue = std::variant<int64_t, std::string>;

    // One parameter decoded with the help of the Win32 metadata index. `name` and
    // `type` point into the index blob, which outlives every record, so they cost
    // nothing to copy. Enum values keep their index rather than their decoded flag
    // names so millions of in-memory calls stay cheap; names are resolved once at
    // report-write time.
    struct DecodedArg {
        const char* name = nullptr;
        const char* type = nullptr;
        win32meta::ArgKind kind = win32meta::ArgKind::Unknown;
        uint32_t enum_index = 0xFFFFFFFFu;
        uint64_t raw = 0;             // the register/stack value as captured
        uint64_t deref = 0;           // pointee, for PtrToInt and friends
        double fval = 0.0;            // for Float/Double params (read from XMM)
        std::string str;              // decoded string contents
        std::vector<uint8_t> bytes;   // bounded buffer preview
        bool has_str = false;
        bool has_deref = false;
        bool has_fval = false;
        bool is_out = false;
        bool from_return = false;     // contents were read at the return position
        bool str_truncated = false;   // `str` stopped short of its NUL terminator
    };

    // A dereference deferred until the call returns, so [Out] parameters can be
    // rendered filled in -- something only a time-travel trace makes easy.
    struct PendingOut {
        uint16_t param_index = 0;
        win32meta::ArgKind kind = win32meta::ArgKind::Unknown;
        uint64_t ptr = 0;
        uint16_t pointee_size = 0;
        win32meta::AuxKind aux_kind = win32meta::AuxKind::None;
        int32_t aux_value = 0;
        uint64_t in_cap = 0;  // caller-supplied upper bound on length, 0 if unknown
    };

    // An address below the first 64 KiB is never a valid user-mode string pointer, and
    // treating one as such is how a flags DWORD ends up rendered as text. The readers
    // enforce this; the recovery pass checks it first so it does not pay for a trace
    // seek to re-read something that will be rejected on arrival.
    constexpr uint64_t kMinStringAddr = 0x10000;

    // Where a bounded memory read is answered from, and at what fidelity.
    //
    // The IThreadView handed to a call/return callback can only answer at ThreadLocal
    // fidelity -- IReplayEngine.h:1440, "this is the policy used when querying memory
    // from the IThreadView interface as provided to a callback" -- and ThreadLocal
    // "concentrates on the current position and current thread, possibly ignoring some
    // of the memory observed by other threads, along with memory observed by the current
    // thread in the past or future". So a heap buffer the caller filled long before the
    // call reads back as nothing at all, even though the trace holds it and a cursor at
    // any other policy returns it. That is not a limit of the recording; it is a limit of
    // where we are standing when we ask. A cursor can be asked at a stronger policy,
    // which is what the string-recovery pass does with the misses the sweep collects.
    //
    // Implicitly constructible from IThreadView const*, so every existing call site keeps
    // reading exactly as it did.
    struct MemorySource {
        MemorySource(TTD::Replay::IThreadView const* view) : thread(view) {}
        MemorySource(TTD::Replay::ICursorView const* view, TTD::Replay::QueryMemoryPolicy p)
            : cursor(view), policy(p) {}

        TTD::Replay::IThreadView const* thread = nullptr;
        TTD::Replay::ICursorView const* cursor = nullptr;
        TTD::Replay::QueryMemoryPolicy policy = TTD::Replay::QueryMemoryPolicy::Default;

        // One QueryMemoryBuffer against whichever view this is. Returns bytes filled.
        size_t query(uint64_t addr, void* dst, size_t size) const;
    };

    // Fill `dst` with up to `size` bytes of guest memory recorded at `addr`, crossing
    // recorded-range seams, and return how many bytes were actually filled. A single
    // QueryMemoryBuffer stops at the end of one contiguous recorded range, so anything
    // the guest touched in more than one piece reads short; this keeps asking until the
    // buffer is full or a query returns nothing. Prefer it to a bare QueryMemoryBuffer
    // anywhere a short read would be mistaken for the end of the data.
    size_t readRecordedRun(MemorySource const& src, uint64_t addr, void* dst, size_t size);

    // UTF-16 -> UTF-8
    std::string convertWstringToString(const std::wstring& ws);

    // All three readers below take an optional `truncated` out-parameter, set when the
    // returned text stopped before its NUL terminator -- because the trace recorded no
    // further bytes, or because maxChars was reached. That distinction has to travel
    // with the string: a name cut to 'WakeAllC' is otherwise indistinguishable from a
    // genuine 8-character export, and the report would look complete while being wrong.

    // Attempts to interpret the memory at a certain address as a string. If not a string, will return null
    std::optional<std::string> tryReadString(MemorySource const& src, uint64_t addr,
                                             bool* truncated = nullptr);

    // Read a NUL-terminated string the metadata told us is really there. Unlike
    // tryReadString these do not guess: no minimum length, and the wide reader
    // converts real UTF-16 (not just its ASCII subset) to UTF-8. Returns nullopt
    // only when the memory is unreadable or the bytes aren't a plausible string.
    std::optional<std::string> readAnsiString(MemorySource const& src, uint64_t addr,
                                              size_t maxChars = 512, bool* truncated = nullptr);
    std::optional<std::string> readWideString(MemorySource const& src, uint64_t addr,
                                              size_t maxChars = 512, bool* truncated = nullptr);

    // Read exactly `count` characters, stopping early only at a NUL. The native API
    // carries text in counted descriptors -- UNICODE_STRING and ANSI_STRING hold a
    // byte length beside the buffer -- and those are not required to be terminated,
    // so scanning for a terminator would run off the end of the string and into
    // whatever follows it. `truncated` means the trace recorded fewer characters
    // than the descriptor claimed, not that a terminator was missing.
    std::optional<std::string> readAnsiChars(MemorySource const& src, uint64_t addr,
                                             size_t count, bool* truncated = nullptr);
    std::optional<std::string> readWideChars(MemorySource const& src, uint64_t addr,
                                             size_t count, bool* truncated = nullptr);

    // Attempts to capture an argument as a string. If it doesn't look like a valid string, this function will return the same argument value
    ArgValue captureCallArg(MemorySource const& src, uint64_t value);
}

#endif