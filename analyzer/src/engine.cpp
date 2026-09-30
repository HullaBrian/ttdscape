#include "engine.h"

#include <algorithm>
#include <cstdio>
#include <stdexcept>

#pragma comment(lib, "TTDReplay.lib")

namespace ttds {

void __fastcall StderrErrorReporting::VPrintError(char const* fmt, va_list args)
{
    ++m_count;
    if (m_count > 200) return; // avoid flooding on damaged traces
    char buf[2048];
    vsnprintf_s(buf, _TRUNCATE, fmt, args);
    std::fprintf(stderr, "[TTD] %s\n", buf);
}

Trace::Trace(std::filesystem::path const& path, IndexMode mode, std::function<void(double)> const& indexProgress)
    : m_path(path), m_reporter(std::make_unique<StderrErrorReporting>())
{
    auto [engine, hr] = MakeReplayEngine();
    if (hr != 0 || !engine)
        throw std::runtime_error(std::format("CreateReplayEngine failed: 0x{:08X} (TTDReplay.dll version mismatch?)", hr));
    m_engine = std::move(engine);
    m_engine->RegisterDebugModeAndLogging(DebugModeType::None, m_reporter.get());

    if (!m_engine->Initialize(path.wstring().c_str()))
        throw std::runtime_error("Failed to open trace file: " + path.string());

    if (m_engine->GetIndexStatus() != IndexStatus::IndexFileLoaded || mode == IndexMode::Rebuild) {
        struct Ctx { std::function<void(double)> const* fn; } ctx{ &indexProgress };
        auto cb = [](void const* pCtx, IndexBuildProgressType const* p) noexcept {
            auto const* c = static_cast<Ctx const*>(pCtx);
            if (c->fn && *c->fn && p->KeyframeCount > 0)
                (*c->fn)(static_cast<double>(p->KeyframesProcessed) / p->KeyframeCount);
        };
        IndexBuildFlags flags = IndexBuildFlags::DeleteExistingUnloadableIndexFile;
        if (mode == IndexMode::Temporary) flags = flags | IndexBuildFlags::TemporaryIndexFile;
        // GetIndexStatus() reflects the on-disk file only; an in-memory index is still used (§3).
        (void)m_engine->BuildIndex(cb, &ctx, flags);
    }

    m_arch = GuestArch(m_engine->GetSystemInfo());
}

Trace::~Trace() = default;

UniqueCursor Trace::NewCursor() const
{
    UniqueCursor c{ m_engine->NewCursor() };
    if (!c) throw std::runtime_error("NewCursor failed");
    return c;
}

std::wstring ModuleBaseName(Module const& m)
{
    wchar_t const* base = GetModuleBaseName(m.pName, m.NameLength);
    size_t const len = m.NameLength - static_cast<size_t>(base - m.pName);
    std::wstring s(base, len);
    while (!s.empty() && s.back() == L'\0') s.pop_back();
    return s;
}

bool IEquals(std::wstring_view a, std::wstring_view b)
{
    return a.size() == b.size() &&
        std::equal(a.begin(), a.end(), b.begin(), [](wchar_t x, wchar_t y) { return towlower(x) == towlower(y); });
}

Module const* Trace::FindModule(std::wstring_view baseName) const
{
    for (Module const& m : Modules(m_engine.get()))
        if (IEquals(ModuleBaseName(m), baseName)) return &m;
    return nullptr;
}

Module const* Trace::ModuleAt(uint64_t address) const
{
    for (Module const& m : Modules(m_engine.get()))
        if (address >= A(m.Address) && address - A(m.Address) < m.Size) return &m;
    return nullptr;
}

size_t ReadGuest(ICursorView const& cursor, uint64_t address, std::span<uint8_t> buf,
                 QueryMemoryPolicy policy, bool stopAtHole)
{
    size_t done = 0;
    bool any = false;
    while (done < buf.size()) {
        auto const r = cursor.QueryMemoryBuffer(GuestAddress{ address + done },
                                                BufferView{ buf.data() + done, buf.size() - done }, policy);
        if (r.Memory.Size == 0) {
            if (stopAtHole) return done;
            // Skip to the next page and zero-fill the hole.
            size_t const pageRest = 0x1000 - ((address + done) & 0xFFF);
            size_t const skip = std::min(pageRest, buf.size() - done);
            std::fill_n(buf.data() + done, skip, uint8_t{ 0 });
            done += skip;
            continue;
        }
        any = true;
        done += r.Memory.Size;
    }
    return (stopAtHole || any) ? done : 0;
}

} // namespace ttds
