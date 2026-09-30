#pragma once
#include "ttd.h"

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ttds {

class StderrErrorReporting : public ErrorReporting
{
public:
    void __fastcall VPrintError(char const* fmt, va_list args) override;
    size_t Count() const noexcept { return m_count; }
private:
    size_t m_count = 0;
};

enum class IndexMode { Keep, Temporary, Rebuild };

// Owns the replay engine (and its error reporter, which must outlive it).
class Trace
{
public:
    // Throws std::runtime_error on failure.
    Trace(std::filesystem::path const& path, IndexMode mode,
          std::function<void(double)> const& indexProgress = {});
    ~Trace();

    IReplayEngine& Engine() const noexcept { return *m_engine; }
    UniqueCursor NewCursor() const;

    ProcessorArchitecture Arch() const noexcept { return m_arch; }
    bool Is64() const noexcept { return m_arch == ProcessorArchitecture::x64 || m_arch == ProcessorArchitecture::Arm64; }
    uint32_t PtrSize() const noexcept { return Is64() ? 8u : 4u; }
    std::filesystem::path const& Path() const noexcept { return m_path; }
    size_t Errors() const noexcept { return m_reporter ? m_reporter->Count() : 0; }

    // Module lookup helpers over the whole-trace module list.
    Module const* FindModule(std::wstring_view baseName) const;
    Module const* ModuleAt(uint64_t address) const;

private:
    std::filesystem::path                 m_path;
    std::unique_ptr<StderrErrorReporting> m_reporter;
    UniqueReplayEngine                    m_engine;
    ProcessorArchitecture                 m_arch = ProcessorArchitecture::Invalid;
};

std::wstring ModuleBaseName(Module const& m);
bool IEquals(std::wstring_view a, std::wstring_view b);

// Reads guest memory into buf, looping over holes (landmine 19). Returns the number of bytes filled
// contiguously from the start (stops at the first hole when stopAtHole, otherwise zero-fills holes
// and returns buf.size() if anything at all was read).
size_t ReadGuest(ICursorView const& cursor, uint64_t address, std::span<uint8_t> buf,
                 QueryMemoryPolicy policy, bool stopAtHole = true);

template <typename T>
std::optional<T> ReadValue(ICursorView const& cursor, uint64_t address, QueryMemoryPolicy policy)
{
    T v{};
    if (ReadGuest(cursor, address, { reinterpret_cast<uint8_t*>(&v), sizeof(T) }, policy) != sizeof(T))
        return std::nullopt;
    return v;
}

template <typename T>
bool ReadThreadLocal(IThreadView const* thread, uint64_t address, T& out)
{
    auto const r = thread->QueryMemoryBuffer(GuestAddress{ address }, BufferView{ &out, sizeof(T) });
    return r.Memory.Size == sizeof(T);
}

} // namespace ttds
