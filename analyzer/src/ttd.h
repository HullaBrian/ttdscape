// Common TTD include wrapper. Every translation unit that touches the Replay API includes this
// instead of the SDK headers directly, so DBG_ASSERT is always defined first (ReplayAPI.md §0).
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cassert>
#ifndef DBG_ASSERT
#define DBG_ASSERT(cond) assert(cond)
#endif
#ifndef DBG_ASSERT_MSG
#define DBG_ASSERT_MSG(cond, ...) assert(cond)
#endif

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>
#include <TTD/ErrorReporting.h>

#include <cstdint>
#include <format>
#include <string>
#include <type_traits>

namespace ttds {

using namespace TTD;
using namespace TTD::Replay;

// Every TTD strong type has a scalar underlying type; std::format has no formatter for them (landmine 7).
template <typename E>
constexpr auto U(E e) noexcept { return static_cast<std::underlying_type_t<E>>(e); }

inline uint64_t A(GuestAddress a) noexcept { return static_cast<uint64_t>(a); }

// Lifetime.Max of a thread still alive at the end of the recording (landmine 29).
constexpr uint64_t kAliveSentinelSeq = 0xFFFFFFFFFFFFFFFEull;

inline std::string PosStr(Position const& p)
{
    if (p == Position::Invalid) return "Invalid";
    if (p == Position::Min) return "Min";
    if (p == Position::Max) return "Max";
    return std::format("{:X}:{:X}", U(p.Sequence), U(p.Steps));
}

// Landmine 1: never subtract a StepCount from a Position. Only use this helper.
inline Position PosMinus(Position const& p, uint64_t n) noexcept { return p - n; }

// SystemInfo::System::ProcessorArchitecture is a Win32 value, not the TTD enum (landmine 3).
inline ProcessorArchitecture GuestArch(SystemInfo const& sys) noexcept
{
    switch (sys.System.ProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_INTEL: return ProcessorArchitecture::x86;
    case PROCESSOR_ARCHITECTURE_ARM:   return ProcessorArchitecture::ARM32;
    case PROCESSOR_ARCHITECTURE_AMD64: return ProcessorArchitecture::x64;
    case PROCESSOR_ARCHITECTURE_ARM64: return ProcessorArchitecture::Arm64;
    default:                           return ProcessorArchitecture::Invalid;
    }
}

inline std::string Narrow(std::wstring_view w)
{
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

inline std::wstring Widen(std::string_view s)
{
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

inline std::string Hex(uint64_t v) { return std::format("0x{:x}", v); }

} // namespace ttds
