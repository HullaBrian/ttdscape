#include "pe/recorded_pe.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <fstream>

namespace ttds {

namespace {

template <typename T>
bool Get(RvaReader const& read, uint32_t rva, T& out)
{
    return read(rva, { reinterpret_cast<uint8_t*>(&out), sizeof(T) });
}

bool GetString(RvaReader const& read, uint32_t rva, std::string& out, size_t maxLen = 256)
{
    out.clear();
    char chunk[32];
    while (out.size() < maxLen) {
        // Read byte by byte near page ends to avoid failing on an unrecorded next page.
        size_t const toPage = 0x1000 - (rva & 0xFFF);
        size_t const n = std::min(sizeof(chunk), toPage);
        if (!read(rva, { reinterpret_cast<uint8_t*>(chunk), n })) return false;
        for (size_t i = 0; i < n; ++i) {
            if (chunk[i] == '\0') return true;
            out.push_back(chunk[i]);
        }
        rva += static_cast<uint32_t>(n);
    }
    return false;
}

} // namespace

std::optional<PeInfo> ParsePe(RvaReader const& read)
{
    IMAGE_DOS_HEADER dos{};
    if (!Get(read, 0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000)
        return std::nullopt;

    uint32_t const nt = static_cast<uint32_t>(dos.e_lfanew);
    uint32_t sig = 0;
    IMAGE_FILE_HEADER fh{};
    if (!Get(read, nt, sig) || sig != IMAGE_NT_SIGNATURE || !Get(read, nt + 4, fh)) return std::nullopt;

    PeInfo info;
    info.timeDateStamp = fh.TimeDateStamp;
    uint32_t const opt = nt + 4 + sizeof(IMAGE_FILE_HEADER);
    uint16_t magic = 0;
    if (!Get(read, opt, magic)) return std::nullopt;

    IMAGE_DATA_DIRECTORY exportDir{};
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 oh{};
        if (!Get(read, opt, oh)) return std::nullopt;
        info.is64 = true;
        info.sizeOfImage = oh.SizeOfImage;
        info.checksum = oh.CheckSum;
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) exportDir = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 oh{};
        if (!Get(read, opt, oh)) return std::nullopt;
        info.sizeOfImage = oh.SizeOfImage;
        info.checksum = oh.CheckSum;
        if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) exportDir = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else {
        return std::nullopt;
    }

    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) return info;
    IMAGE_EXPORT_DIRECTORY ed{};
    if (!Get(read, exportDir.VirtualAddress, ed)) return info;
    if (ed.NumberOfNames > 0x10000 || ed.NumberOfFunctions > 0x10000) return info;

    std::vector<uint32_t> names(ed.NumberOfNames), funcs(ed.NumberOfFunctions);
    std::vector<uint16_t> ords(ed.NumberOfNames);
    auto span8 = [](auto& v) { return std::span<uint8_t>(reinterpret_cast<uint8_t*>(v.data()), v.size() * sizeof(v[0])); };
    if (!read(ed.AddressOfNames, span8(names)) || !read(ed.AddressOfNameOrdinals, span8(ords)) ||
        !read(ed.AddressOfFunctions, span8(funcs)))
        return info;

    uint32_t const expLo = exportDir.VirtualAddress, expHi = exportDir.VirtualAddress + exportDir.Size;
    std::vector<bool> named(funcs.size());
    std::string name;
    for (size_t i = 0; i < names.size(); ++i) {
        if (ords[i] >= funcs.size()) continue;
        uint32_t const rva = funcs[ords[i]];
        if (rva >= expLo && rva < expHi) continue; // forwarder string
        if (!GetString(read, names[i], name)) continue;
        info.exports.emplace(name, rva);
        named[ords[i]] = true;
    }
    // Exports reachable by ordinal only are named "#<ordinal>".
    for (size_t i = 0; i < funcs.size(); ++i) {
        uint32_t const rva = funcs[i];
        if (named[i] || rva == 0 || (rva >= expLo && rva < expHi)) continue;
        info.exports.emplace("#" + std::to_string(ed.Base + i), rva);
    }
    return info;
}

PeFile::PeFile(std::filesystem::path const& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return;
    m_bytes.assign(std::istreambuf_iterator<char>(f), {});
    if (m_bytes.size() < sizeof(IMAGE_DOS_HEADER)) { m_bytes.clear(); return; }
    auto const* dos = reinterpret_cast<IMAGE_DOS_HEADER const*>(m_bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || static_cast<size_t>(dos->e_lfanew) + 0x200 > m_bytes.size()) { m_bytes.clear(); return; }
    auto const* fh = reinterpret_cast<IMAGE_FILE_HEADER const*>(m_bytes.data() + dos->e_lfanew + 4);
    size_t const secOff = dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + fh->SizeOfOptionalHeader;
    auto const* opt = m_bytes.data() + dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER);
    uint16_t const magic = *reinterpret_cast<uint16_t const*>(opt);
    m_headersSize = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
        ? reinterpret_cast<IMAGE_OPTIONAL_HEADER64 const*>(opt)->SizeOfHeaders
        : reinterpret_cast<IMAGE_OPTIONAL_HEADER32 const*>(opt)->SizeOfHeaders;
    for (unsigned i = 0; i < fh->NumberOfSections; ++i) {
        size_t const o = secOff + i * sizeof(IMAGE_SECTION_HEADER);
        if (o + sizeof(IMAGE_SECTION_HEADER) > m_bytes.size()) break;
        auto const* s = reinterpret_cast<IMAGE_SECTION_HEADER const*>(m_bytes.data() + o);
        m_sections.push_back({ s->VirtualAddress, s->Misc.VirtualSize, s->PointerToRawData, s->SizeOfRawData, s->Characteristics });
    }
}

bool PeFile::Read(uint32_t rva, std::span<uint8_t> out) const
{
    auto copyFrom = [&](size_t fileOff, size_t avail) {
        if (out.size() > avail || fileOff + out.size() > m_bytes.size()) return false;
        std::memcpy(out.data(), m_bytes.data() + fileOff, out.size());
        return true;
    };
    if (rva < m_headersSize) return copyFrom(rva, m_headersSize - rva);
    for (auto const& s : m_sections) {
        uint32_t const vsize = std::max(s.vsize, s.rawSize);
        if (rva >= s.va && rva < s.va + vsize) {
            uint32_t const off = rva - s.va;
            if (off >= s.rawSize) { // zero-filled tail (bss)
                std::memset(out.data(), 0, out.size());
                return off + out.size() <= vsize;
            }
            return copyFrom(size_t{ s.raw } + off, s.rawSize - off);
        }
    }
    return false;
}

RvaReader PeFile::Reader() const
{
    return [this](uint32_t rva, std::span<uint8_t> out) { return Read(rva, out); };
}

std::vector<std::pair<uint32_t, uint32_t>> PeFile::CodeSections() const
{
    std::vector<std::pair<uint32_t, uint32_t>> r;
    for (auto const& s : m_sections)
        if (s.characteristics & IMAGE_SCN_MEM_EXECUTE) r.emplace_back(s.va, std::min(s.vsize ? s.vsize : s.rawSize, s.rawSize));
    return r;
}

std::map<uint32_t, uint32_t> ScanSyscallStubs(std::span<uint8_t const> code, uint32_t codeRva, bool is64)
{
    std::map<uint32_t, uint32_t> stubs;
    auto rd32 = [&](size_t i) { uint32_t v; std::memcpy(&v, &code[i], 4); return v; };
    if (is64) {
        for (size_t i = 0; i + 8 <= code.size(); ++i) {
            if (code[i] == 0x4C && code[i + 1] == 0x8B && code[i + 2] == 0xD1 && code[i + 3] == 0xB8) {
                uint32_t const ssn = rd32(i + 4);
                if (ssn < 0x2000) stubs.emplace(codeRva + static_cast<uint32_t>(i), ssn);
            }
        }
    } else {
        for (size_t i = 0; i + 12 <= code.size(); ++i) {
            if (code[i] == 0xB8 && code[i + 5] == 0xBA && code[i + 10] == 0xFF && code[i + 11] == 0xD2) {
                uint32_t const ssn = rd32(i + 1);
                if (ssn < 0x10000) stubs.emplace(codeRva + static_cast<uint32_t>(i), ssn);
            }
        }
    }
    return stubs;
}

} // namespace ttds
