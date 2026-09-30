#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace ttds {

// Default symbol path: _NT_SYMBOL_PATH if set, otherwise empty (local-only; DbgHelp still checks the
// image's own directory and the PDB path embedded in the image).
std::wstring DefaultSymbolPath();

// Finds an exact image build (timestamp + SizeOfImage) on the symbol path, downloading it through
// symsrv when the path contains a srv* element. Returns nullopt if not found or the path is empty.
std::optional<std::filesystem::path> FindImageOnSymbolPath(std::wstring const& symPath, std::wstring const& fileName,
                                                           uint32_t timestamp, uint32_t sizeOfImage);

struct ModuleDesc
{
    std::wstring guestPath;   // as recorded
    uint64_t     base = 0;
    uint64_t     size = 0;
    uint32_t     timestamp = 0;
};

struct ResolvedFrame
{
    std::string symbol; // "module!function+0x12" or "module+0x1234"
    std::string file;
    uint32_t    line = 0;
};

// A module as listed in an analysis directory's symbol-input.tsv (model.modules order, which is the
// manifest's module order): path, base, size, timestamp.
struct SymModule { std::string path; uint64_t base = 0, size = 0; uint32_t timestamp = 0; };
std::vector<SymModule> ReadSymbolInput(std::filesystem::path const& dir);

// Thin DbgHelp wrapper. Not thread-safe (DbgHelp itself is not). One instance per process at a time.
class Symbolizer
{
public:
    explicit Symbolizer(std::wstring symPath);
    ~Symbolizer();
    Symbolizer(Symbolizer const&) = delete;
    Symbolizer& operator=(Symbolizer const&) = delete;

    // Registers a module at its recorded base. Loads lazily on first lookup.
    void AddModule(ModuleDesc const& m);
    // Resolves an address that lies inside module 'moduleIndex' (index in AddModule order), or
    // outside any module when moduleIndex is -1.
    ResolvedFrame Resolve(uint64_t address, int moduleIndex);
    size_t ModulesWithSymbols() const noexcept;

private:
    struct Mod { ModuleDesc desc; std::string shortName; bool attempted = false; bool loaded = false; bool hasSymbols = false; };
    void EnsureLoaded(Mod& m);

    void*              m_process;
    std::wstring       m_symPath;
    std::vector<Mod>   m_mods;
    bool               m_ok = false;
};

} // namespace ttds
