#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ttds {

// Reads bytes of a mapped PE image by RVA. Returns false if any byte is unavailable.
using RvaReader = std::function<bool(uint32_t rva, std::span<uint8_t> out)>;

struct PeInfo
{
    bool     is64 = false;
    uint32_t timeDateStamp = 0;
    uint32_t sizeOfImage = 0;
    uint32_t checksum = 0;
    std::map<std::string, uint32_t, std::less<>> exports; // name -> RVA (forwarders omitted)
};

// Parses headers + export directory. Returns nullopt if headers are unreadable or not a PE.
std::optional<PeInfo> ParsePe(RvaReader const& read);

// An RvaReader over a PE file on disk (maps sections RVA -> file offset). Empty file => nullptr reader.
class PeFile
{
public:
    explicit PeFile(std::filesystem::path const& path);
    bool Ok() const noexcept { return !m_bytes.empty(); }
    RvaReader Reader() const;
    // Raw bytes of the image at RVA (via section mapping); false if not backed by the file.
    bool Read(uint32_t rva, std::span<uint8_t> out) const;
    // [rva, size] of executable sections.
    std::vector<std::pair<uint32_t, uint32_t>> CodeSections() const;
private:
    std::vector<uint8_t> m_bytes;
    struct Section { uint32_t va, vsize, raw, rawSize, characteristics; };
    std::vector<Section> m_sections;
    uint32_t m_headersSize = 0;
};

// x64 syscall stubs: 4C 8B D1 B8 <ssn32>  (mov r10,rcx; mov eax,ssn).
// x86 stubs:        B8 <ssn32> BA <imm32> FF D2 (mov eax,ssn; mov edx,imm; call edx)
//                   or B8 <ssn32> E8/BA ... (WoW64 variants). Returns rva -> ssn.
std::map<uint32_t, uint32_t> ScanSyscallStubs(std::span<uint8_t const> code, uint32_t codeRva, bool is64);

} // namespace ttds
