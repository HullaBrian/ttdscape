#include "check.h"
#include "out/json.h"
#include "out/writer.h"
#include "pe/recorded_pe.h"

#include <cstring>
#include <fstream>

using namespace ttds;

TEST(json_writer_commas_escaping_and_hex)
{
    JsonWriter j;
    j.BeginObject();
    j.Key("a").Number(uint64_t{ 1 });
    j.Key("s").String("q\"\\\n\x01");
    j.Key("h").Hex(0x7ffa6b260000ull);
    j.Key("n").Index(kNone);
    j.Key("arr").BeginArray().Number(uint64_t{ 1 }).Number(uint64_t{ 2 }).BeginObject().EndObject().EndArray();
    j.EndObject();
    CHECK(j.Str() == R"({"a":1,"s":"q\"\\\n\u0001","h":"0x7ffa6b260000","n":null,"arr":[1,2,{}]})");
}

TEST(binary_records_round_trip)
{
    auto const dir = std::filesystem::temp_directory_path() / "ttdscape-test-writer";
    std::filesystem::create_directories(dir);
    std::vector<Event> ev = { { 1, EvNested, 3, 42, 0x7ffa00001000ull, 64, 5, 9 } };
    WriteFile(dir / "e.bin", ev.data(), ev.size() * sizeof(Event));
    std::vector<char> raw;
    {
        std::ifstream f(dir / "e.bin", std::ios::binary);
        raw.assign(std::istreambuf_iterator<char>(f), {});
    }
    CHECK_EQ(raw.size(), 32u);
    uint64_t addr;
    std::memcpy(&addr, raw.data() + 8, 8);
    CHECK_EQ(addr, 0x7ffa00001000ull);
    CHECK_EQ(static_cast<uint8_t>(raw[0]), 1u);
    CHECK_EQ(static_cast<uint8_t>(raw[2]), 3u); // thread, little endian
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST(pe_parser_reads_exports_of_disk_ntdll)
{
    wchar_t sys[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    PeFile f(std::filesystem::path(sys) / L"ntdll.dll");
    CHECK(f.Ok());
    auto pe = ParsePe(f.Reader());
    CHECK(pe.has_value());
    if (!pe) return;
    CHECK(pe->is64);
    CHECK(pe->exports.count("RtlAllocateHeap") == 1);
    CHECK(pe->exports.count("NtAllocateVirtualMemory") == 1);
    // The stub at NtAllocateVirtualMemory is a syscall stub.
    uint8_t stub[16]{};
    CHECK(f.Read(pe->exports.at("NtAllocateVirtualMemory"), stub));
    auto stubs = ScanSyscallStubs(stub, pe->exports.at("NtAllocateVirtualMemory"), true);
    CHECK_EQ(stubs.size(), 1u);
}

TEST_MAIN
