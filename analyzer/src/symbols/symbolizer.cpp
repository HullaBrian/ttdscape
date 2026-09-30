#include "symbols/symbolizer.h"
#include "pe/recorded_pe.h"
#include "ttd.h"

#include <DbgHelp.h>
#include <atomic>
#include <fstream>
#include <mutex>
#include <sstream>

#pragma comment(lib, "dbghelp.lib")

namespace ttds {

namespace {

// DbgHelp identifies a "process" by an opaque handle; any unique value works for offline use.
std::atomic<uintptr_t> g_nextFakeProcess{ 0x7751'0000 };
std::mutex g_dbghelpLock; // DbgHelp is single-threaded

std::string ShortModuleName(std::wstring const& path)
{
    std::wstring name = path;
    if (auto p = name.find_last_of(L"\\/:"); p != std::wstring::npos) name = name.substr(p + 1);
    if (auto d = name.find_last_of(L'.'); d != std::wstring::npos) name = name.substr(0, d);
    return Narrow(name);
}

std::wstring HostPath(std::wstring p)
{
    if (p.rfind(L"\\??\\", 0) == 0) p = p.substr(4);
    if (p.rfind(L"\\\\?\\", 0) == 0) p = p.substr(4);
    return p;
}

bool ImageMatches(std::filesystem::path const& path, uint32_t timestamp, uint64_t size)
{
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) return false;
    PeFile f(path);
    if (!f.Ok()) return false;
    auto pe = ParsePe(f.Reader());
    return pe && pe->timeDateStamp == timestamp && (size == 0 || pe->sizeOfImage == size);
}

} // namespace

std::wstring DefaultSymbolPath()
{
    wchar_t buf[4096];
    DWORD const n = GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", buf, static_cast<DWORD>(std::size(buf)));
    if (n > 0 && n < std::size(buf)) return std::wstring(buf, n);
    return {};
}

std::optional<std::filesystem::path> FindImageOnSymbolPath(std::wstring const& symPath, std::wstring const& fileName,
                                                           uint32_t timestamp, uint32_t sizeOfImage)
{
    if (symPath.empty()) return std::nullopt;
    std::lock_guard lock(g_dbghelpLock);
    HANDLE const h = reinterpret_cast<HANDLE>(g_nextFakeProcess.fetch_add(4));
    SymSetOptions(SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
    if (!SymInitializeW(h, symPath.c_str(), FALSE)) return std::nullopt;
    wchar_t found[MAX_PATH * 2]{};
    DWORD ts = timestamp;
    BOOL const ok = SymFindFileInPathW(h, symPath.c_str(), fileName.c_str(), &ts, sizeOfImage, 0,
                                       SSRVOPT_DWORDPTR, found, nullptr, nullptr);
    SymCleanup(h);
    if (!ok) return std::nullopt;
    return std::filesystem::path(found);
}

Symbolizer::Symbolizer(std::wstring symPath)
    : m_process(reinterpret_cast<void*>(g_nextFakeProcess.fetch_add(4))), m_symPath(std::move(symPath))
{
    std::lock_guard lock(g_dbghelpLock);
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_NO_PROMPTS |
                  SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_OMAP_FIND_NEAREST);
    m_ok = SymInitializeW(m_process, m_symPath.empty() ? nullptr : m_symPath.c_str(), FALSE) != FALSE;
}

Symbolizer::~Symbolizer()
{
    std::lock_guard lock(g_dbghelpLock);
    if (m_ok) SymCleanup(m_process);
}

void Symbolizer::AddModule(ModuleDesc const& m)
{
    m_mods.push_back({ m, ShortModuleName(m.guestPath) });
}

size_t Symbolizer::ModulesWithSymbols() const noexcept
{
    size_t n = 0;
    for (auto const& m : m_mods) n += m.hasSymbols;
    return n;
}

void Symbolizer::EnsureLoaded(Mod& m)
{
    if (m.attempted) return;
    m.attempted = true;
    if (!m_ok) return;

    std::filesystem::path image = HostPath(m.desc.guestPath);
    if (!ImageMatches(image, m.desc.timestamp, m.desc.size)) {
        std::wstring const file = image.filename().wstring();
        auto found = FindImageOnSymbolPath(m_symPath, file, m.desc.timestamp, static_cast<uint32_t>(m.desc.size));
        image = found ? *found : std::filesystem::path(file);
    }

    std::lock_guard lock(g_dbghelpLock);
    DWORD64 const base = SymLoadModuleExW(m_process, nullptr, image.c_str(), nullptr, m.desc.base,
                                          static_cast<DWORD>(m.desc.size), nullptr, 0);
    m.loaded = base != 0 || GetLastError() == ERROR_SUCCESS;
    if (m.loaded) {
        IMAGEHLP_MODULEW64 info{ sizeof(info) };
        if (SymGetModuleInfoW64(m_process, m.desc.base, &info))
            m.hasSymbols = info.SymType == SymPdb || info.SymType == SymDia || info.SymType == SymCoff ||
                           info.SymType == SymCv || info.SymType == SymExport;
    }
}

ResolvedFrame Symbolizer::Resolve(uint64_t address, int moduleIndex)
{
    ResolvedFrame r;
    if (moduleIndex < 0 || static_cast<size_t>(moduleIndex) >= m_mods.size()) {
        return r; // outside every module: the viewer labels it as unbacked code
    }
    Mod& m = m_mods[static_cast<size_t>(moduleIndex)];
    EnsureLoaded(m);
    r.symbol = std::format("{}+0x{:x}", m.shortName, address - m.desc.base);
    if (!m.loaded) return r;

    std::lock_guard lock(g_dbghelpLock);
    alignas(SYMBOL_INFOW) uint8_t buf[sizeof(SYMBOL_INFOW) + 512 * sizeof(wchar_t)]{};
    auto* sym = reinterpret_cast<SYMBOL_INFOW*>(buf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFOW);
    sym->MaxNameLen = 512;
    DWORD64 disp = 0;
    if (SymFromAddrW(m_process, address, &disp, sym)) {
        std::string const name = Narrow(std::wstring_view(sym->Name, sym->NameLen));
        r.symbol = disp ? std::format("{}!{}+0x{:x}", m.shortName, name, disp) : std::format("{}!{}", m.shortName, name);
    }
    IMAGEHLP_LINEW64 line{ sizeof(line) };
    DWORD lineDisp = 0;
    if (SymGetLineFromAddrW64(m_process, address, &lineDisp, &line) && line.FileName) {
        r.file = Narrow(line.FileName);
        r.line = line.LineNumber;
    }
    return r;
}

std::vector<SymModule> ReadSymbolInput(std::filesystem::path const& dir)
{
    std::vector<SymModule> mods;
    std::ifstream f(dir / "symbol-input.tsv");
    std::string line;
    while (std::getline(f, line)) {
        std::vector<std::string> parts;
        std::stringstream ss(line);
        std::string p;
        while (std::getline(ss, p, '\t')) parts.push_back(p);
        if (parts.size() != 4) continue;
        mods.push_back({ parts[0], std::stoull(parts[1], nullptr, 16), std::stoull(parts[2], nullptr, 16),
                         static_cast<uint32_t>(std::stoul(parts[3], nullptr, 16)) });
    }
    return mods;
}

} // namespace ttds
