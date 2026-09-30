#pragma once
#include "engine.h"

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace ttds {

// API argument decoding for calls into exports, on top of ttd-capa-cpp's decoder (vendored in
// third_party/ttdcapa): Win32 (win32json) and native (phnt) signatures, x64 and x86 layouts, enum
// and flag names, strings, and [Out] values read back at the return.
//
// Use from the replay callbacks: Begin at the export's entry (a CALL, or a jump into it), End at
// the matching RET. Each call is rendered to one compact JSON object:
//   {"sig":1,"p":[{"n":name,"t":type,"v":"0x..", ...}, ...],"ret":"0x.."}
// Parameter keys, all optional except v: s string, tr string truncated, d pointee, fl flag names
// of the value, dfl flag names of the pointee, f float, b bytes (hex), o [Out], r read at return.
// Without a signature, sig is 0 and p holds the first four integer arguments (strings when they
// look like one).
class ArgDecoder
{
public:
    ArgDecoder();
    ~ArgDecoder();

    // Loads win32-index.bin (and phnt-index.bin beside it). False with 'error' set when unusable.
    bool Load(std::filesystem::path const& win32Index, std::string& error);
    size_t Signatures() const;

    struct Active; // one call between its entry and its return
    struct ActiveDeleter { void operator()(Active* a) const noexcept; };
    using ActivePtr = std::unique_ptr<Active, ActiveDeleter>;

    // Decodes the arguments at the export's entry. is64: bitness of the module that owns the
    // export (a WoW64 process runs both).
    ActivePtr Begin(char const* api, bool is64, IThreadView const* t) const;
    // Resolves [Out] parameters and unread strings at the RET, reads the return value, renders.
    std::string End(Active& call, IThreadView const* t) const;
    // Renders a call that never returned (no [Out] values, no return value).
    std::string Abandon(Active& call) const;

    struct Stats { uint64_t withSignature = 0, heuristic = 0, stringsAtReturn = 0; };
    Stats const& GetStats() const noexcept { return m_stats; }

private:
    std::string Render(Active const& call, bool returned, uint64_t ret) const;
    mutable Stats m_stats;
};

// The default index location: next to the analyzer executable.
std::filesystem::path DefaultWin32IndexPath();

} // namespace ttds
