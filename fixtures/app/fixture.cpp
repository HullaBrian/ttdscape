// TTDscape test fixture. Record it with fixtures/record-fixture.ps1.
//
// It performs a scripted sequence of heap and virtual-memory operations and writes the ground truth
// (every address it got back, and what it expects to be alive at the end) to the JSON file named on
// the command line. The integration test compares the analyzer's model against that file.
// Phases are delimited with OutputDebugStringA("TTDSCAPE:PHASE n ...") markers.
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <malloc.h>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

struct Alloc
{
    std::string label;
    std::string heap;      // "process", "private", "crt"
    void*       address;
    size_t      size;
    bool        freed;
    std::string prev;      // label of the block this one was reallocated from
};

struct Region
{
    std::string label;
    void*       base;
    size_t      size;
    std::string finalState; // "released", "reserved", "committed", "mapped", "unmapped"
    DWORD       protect;
};

std::vector<Alloc>  g_allocs;
std::vector<Region> g_regions;
std::vector<std::pair<std::string, DWORD>> g_oldProtects;
volatile void* g_sink; // defeats dead-store elimination of allocations

void Marker(char const* text)
{
    char buf[256];
    std::snprintf(buf, sizeof(buf), "TTDSCAPE:%s", text);
    OutputDebugStringA(buf);
}

Alloc* Track(char const* label, char const* heap, void* p, size_t size)
{
    g_sink = p;
    g_allocs.push_back({ label, heap, p, size, false, {} });
    return &g_allocs.back();
}

Alloc* Find(char const* label)
{
    for (auto& a : g_allocs) if (a.label == label) return &a;
    return nullptr;
}

void Freed(char const* label) { if (Alloc* a = Find(label)) a->freed = true; }

// ---- Phase helpers; noinline keeps them as distinct frames in allocation stacks. -------------

__declspec(noinline) void* leak_a(size_t n) { void* p = malloc(n); std::memset(p, 0xA1, n); return p; }
__declspec(noinline) void* leak_b(size_t n) { void* p = HeapAlloc(GetProcessHeap(), 0, n); std::memset(p, 0xB2, n); return p; }

// Compiles to `jmp qword ptr [__imp_HeapAlloc]` (a tail call through the IAT, which points
// straight at ntdll!RtlAllocateHeap), exercising the indirect-jump path of the capture pass.
__declspec(noinline) void* tail_alloc(HANDLE heap, size_t n) { return HeapAlloc(heap, 0, n); }

__declspec(noinline) void throw_after_alloc(void** out)
{
    *out = HeapAlloc(GetProcessHeap(), 0, 333);
    throw std::runtime_error("unwind through frames");
}

__declspec(noinline) void middle_frame(void** out) { throw_after_alloc(out); g_sink = out; }

__declspec(noinline) void after_unwind_alloc(void** out) { *out = HeapAlloc(GetProcessHeap(), 0, 444); }

std::string Hex(void const* p) { char b[32]; std::snprintf(b, sizeof(b), "0x%llx", (unsigned long long)(uintptr_t)p); return b; }

void WriteTruth(char const* path)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path, "w") != 0 || !f) return;
    std::fprintf(f, "{\n  \"pid\": %lu,\n  \"processHeap\": \"%s\",\n  \"allocs\": [\n", GetCurrentProcessId(), Hex(GetProcessHeap()).c_str());
    for (size_t i = 0; i < g_allocs.size(); ++i) {
        auto const& a = g_allocs[i];
        std::fprintf(f, "    {\"label\": \"%s\", \"heap\": \"%s\", \"address\": \"%s\", \"size\": %zu, \"freed\": %s, \"prev\": \"%s\"}%s\n",
            a.label.c_str(), a.heap.c_str(), Hex(a.address).c_str(), a.size, a.freed ? "true" : "false", a.prev.c_str(),
            i + 1 < g_allocs.size() ? "," : "");
    }
    std::fprintf(f, "  ],\n  \"regions\": [\n");
    for (size_t i = 0; i < g_regions.size(); ++i) {
        auto const& r = g_regions[i];
        std::fprintf(f, "    {\"label\": \"%s\", \"base\": \"%s\", \"size\": %zu, \"finalState\": \"%s\", \"protect\": %lu}%s\n",
            r.label.c_str(), Hex(r.base).c_str(), r.size, r.finalState.c_str(), r.protect, i + 1 < g_regions.size() ? "," : "");
    }
    std::fprintf(f, "  ],\n  \"oldProtects\": [\n");
    for (size_t i = 0; i < g_oldProtects.size(); ++i)
        std::fprintf(f, "    {\"label\": \"%s\", \"value\": %lu}%s\n", g_oldProtects[i].first.c_str(), g_oldProtects[i].second,
            i + 1 < g_oldProtects.size() ? "," : "");
    std::fprintf(f, "  ]\n}\n");
    std::fclose(f);
}

} // namespace

int main(int argc, char** argv)
{
    char const* truthPath = argc > 1 ? argv[1] : "truth.json";
    g_allocs.reserve(256);
    g_regions.reserve(32);
    HANDLE const ph = GetProcessHeap();

    // ---- Phase 1: private heap, assorted sizes (the 1 MB block is a large, VM-backed block). --
    Marker("PHASE 1 private heap");
    HANDLE const heap = HeapCreate(0, 0, 0);
    Track("p1.h16", "private", HeapAlloc(heap, 0, 16), 16);
    Track("p1.h100", "private", HeapAlloc(heap, HEAP_ZERO_MEMORY, 100), 100);
    Track("p1.h4k", "private", HeapAlloc(heap, 0, 4096), 4096);
    Track("p1.h1m", "private", HeapAlloc(heap, 0, 1 << 20), 1 << 20);

    // ---- Phase 2: realloc variants, frees, destroy with live blocks. --------------------------
    Marker("PHASE 2 realloc and destroy");
    {
        void* a = HeapAlloc(heap, 0, 64);
        Track("p2.a", "private", a, 64);
        void* blocker = HeapAlloc(heap, 0, 64);
        Track("p2.blocker", "private", blocker, 64);
        // Shrink: stays in place.
        void* a2 = HeapReAlloc(heap, 0, a, 32);
        Freed("p2.a");
        Track("p2.a.shrunk", "private", a2, 32)->prev = "p2.a";
        // Grow past the blocker: moves.
        void* a3 = HeapReAlloc(heap, 0, a2, 8192);
        Freed("p2.a.shrunk");
        Track("p2.a.grown", "private", a3, 8192)->prev = "p2.a.shrunk";
        // In-place-only growth of the blocker by a lot: fails and changes nothing.
        void* fail = HeapReAlloc(heap, HEAP_REALLOC_IN_PLACE_ONLY, blocker, 1 << 22);
        g_sink = fail;
        HeapFree(heap, 0, Find("p1.h16")->address);
        Freed("p1.h16");
        HeapFree(heap, 0, Find("p1.h1m")->address);
        Freed("p1.h1m");
        // Destroy with p1.h100, p1.h4k, p2.blocker, p2.a.grown still live.
        HeapDestroy(heap);
        for (char const* l : { "p1.h100", "p1.h4k", "p2.blocker", "p2.a.grown" }) Freed(l);
    }

    // ---- Phase 3: CRT allocators. ------------------------------------------------------------
    Marker("PHASE 3 crt");
    {
        void* m = malloc(200);
        Track("p3.malloc", "crt", m, 200);
        void* c = calloc(10, 30);
        Track("p3.calloc", "crt", c, 300);
        void* r = realloc(m, 5000);
        Freed("p3.malloc");
        Track("p3.realloc", "crt", r, 5000)->prev = "p3.malloc";
        free(r);
        Freed("p3.realloc");
        free(c);
        Freed("p3.calloc");
        int* n = new int[50];
        Track("p3.new", "crt", n, 200);
        delete[] n;
        Freed("p3.new");
        void* al = _aligned_malloc(100, 64);
        g_sink = al;
        _aligned_free(al);
    }

    // ---- Phase 4: leaks from two distinct functions. -----------------------------------------
    Marker("PHASE 4 leaks");
    Track("p4.leak_a", "crt", leak_a(123), 123);
    for (int i = 0; i < 10; ++i) {
        char label[32];
        std::snprintf(label, sizeof(label), "p4.leak_b.%d", i);
        Track(label, "process", leak_b(77), 77);
    }

    // ---- Phase 5: virtual memory lifecycle. ---------------------------------------------------
    Marker("PHASE 5 virtual memory");
    {
        char* res = static_cast<char*>(VirtualAlloc(nullptr, 1 << 20, MEM_RESERVE, PAGE_NOACCESS));
        g_regions.push_back({ "p5.reserve", res, 1 << 20, "released", PAGE_NOACCESS });
        char* com = static_cast<char*>(VirtualAlloc(res + 0x40000, 0x10000, MEM_COMMIT, PAGE_READWRITE));
        g_regions.push_back({ "p5.commit", com, 0x10000, "released", PAGE_READWRITE });
        std::memset(com, 1, 0x10000);
        DWORD old = 0;
        VirtualProtect(com, 0x10000, PAGE_READONLY, &old);
        g_oldProtects.push_back({ "p5.protect", old });
        // Unaligned non-zero base: commits the single page containing it.
        char* odd = static_cast<char*>(VirtualAlloc(res + 0x81234, 0x100, MEM_COMMIT, PAGE_READWRITE));
        g_regions.push_back({ "p5.odd", odd, 0x1000, "released", PAGE_READWRITE });
        VirtualFree(com, 0x10000, MEM_DECOMMIT);
        VirtualFree(res, 0, MEM_RELEASE);

        char* rc = static_cast<char*>(VirtualAlloc(nullptr, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        g_regions.push_back({ "p5.rc", rc, 0x3000, "committed", PAGE_READWRITE });
        rc[0] = 1;
    }

    // ---- Phase 6: section views. --------------------------------------------------------------
    Marker("PHASE 6 views");
    {
        HANDLE const sec = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 256 * 1024, nullptr);
        void* v1 = MapViewOfFile(sec, FILE_MAP_WRITE, 0, 0, 0);
        g_regions.push_back({ "p6.view1", v1, 256 * 1024, "unmapped", PAGE_READWRITE });
        static_cast<char*>(v1)[0] = 1;
        UnmapViewOfFile(v1);
        void* v2 = MapViewOfFile(sec, FILE_MAP_READ, 0, 0, 64 * 1024);
        g_regions.push_back({ "p6.view2", v2, 64 * 1024, "mapped", PAGE_READONLY });
        g_sink = v2;
        CloseHandle(sec);
    }

    // ---- Phase 7: allocate on a worker thread, free on the main thread. -----------------------
    Marker("PHASE 7 cross-thread");
    {
        void* p = nullptr;
        std::thread t([&p] { p = HeapAlloc(GetProcessHeap(), 0, 555); });
        t.join();
        Track("p7.cross", "process", p, 555);
        HeapFree(ph, 0, p);
        Freed("p7.cross");
    }

    // ---- Phase 8: allocation inside a frame unwound by a C++ exception. -----------------------
    Marker("PHASE 8 unwind");
    {
        void* thrown = nullptr;
        try { middle_frame(&thrown); } catch (std::exception const&) {}
        Track("p8.thrown", "process", thrown, 333);
        void* after = nullptr;
        after_unwind_alloc(&after);
        Track("p8.after", "process", after, 444);
        HeapFree(ph, 0, thrown);
        Freed("p8.thrown");
        HeapFree(ph, 0, after);
        Freed("p8.after");
    }

    // ---- Phase 9: tail call into RtlAllocateHeap through the import table. ---------------------
    Marker("PHASE 9 tail call");
    {
        void* t = tail_alloc(ph, 999);
        Track("p9.tail", "process", t, 999);
        HeapFree(ph, 0, t);
        Freed("p9.tail");
    }

    Marker("PHASE END");
    WriteTruth(truthPath);
    return 0;
}
