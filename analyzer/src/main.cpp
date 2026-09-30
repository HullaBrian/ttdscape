// ttdscape-analyzer: builds a time-indexed model of native heap + virtual memory from a TTD trace.
//
//   ttdscape-analyzer info    <trace.run>
//   ttdscape-analyzer probe   <trace.run>
//   ttdscape-analyzer analyze <trace.run> <outDir> [options]
//   ttdscape-analyzer symbolize <outDir> [--symbol-path P]
//   ttdscape-analyzer serve   <trace.run> <outDir> [--symbol-path P]   (NDJSON queries on stdin)
#include "engine.h"
#include "out/json.h"
#include "probe.h"
#include "symbols/symbolizer.h"

#include <cstdio>
#include <iostream>
#include <map>

using namespace ttds;

namespace ttds {
int RunAnalyze(std::filesystem::path const& trace, std::filesystem::path const& out,
               std::map<std::string, std::string> const& opts);
int RunSymbolize(std::filesystem::path const& out, std::map<std::string, std::string> const& opts);
int RunServe(std::filesystem::path const& trace, std::filesystem::path const& out,
             std::map<std::string, std::string> const& opts);
}

namespace {

void Usage()
{
    std::fprintf(stderr,
        "usage:\n"
        "  ttdscape-analyzer info      <trace.run>\n"
        "  ttdscape-analyzer probe     <trace.run>\n"
        "  ttdscape-analyzer analyze   <trace.run> <outDir> [--stack-depth N] [--no-symbols]\n"
        "                              [--symbol-path P] [--index keep|temp] [--calls exports|none]\n"
        "                              [--call-args on|off] [--win32-index P]\n"
        "                              [--activity codefetch|execute|off] [--snapshots on|off|BYTES]\n"
        "                              [--debug-ndjson]\n"
        "  ttdscape-analyzer symbolize <outDir> [--symbol-path P]\n");
}

int RunInfo(Trace const& trace)
{
    IReplayEngine const& e = trace.Engine();
    SystemInfo const& sys = e.GetSystemInfo();
    PositionRange const& life = e.GetLifetime();
    std::cout << std::format("trace     : {}\n", trace.Path().string());
    std::cout << std::format("pid       : {}\n", sys.ProcessId);
    std::cout << std::format("os        : {}.{}.{}\n", sys.System.MajorVersion, sys.System.MinorVersion, sys.System.BuildNumber);
    std::cout << std::format("arch      : {}\n", GetProcessorArchitectureName(trace.Arch()));
    std::cout << std::format("recording : {}\n", GetRecordingTypeName(e.GetRecordingType()));
    std::cout << std::format("lifetime  : {} - {}\n", PosStr(life.Min), PosStr(life.Max));
    std::cout << std::format("peb       : {}\n", Hex(A(e.GetPebAddress())));
    std::cout << std::format("threads   : {}\n", e.GetThreadCount());
    for (ThreadInfo const& t : Threads(&e))
        std::cout << std::format("  utid {:3} tid {:6} life {} - {}\n", U(t.UniqueId), U(t.Id),
                                 PosStr(t.Lifetime.Min), PosStr(t.Lifetime.Max));
    std::cout << std::format("modules   : {}\n", e.GetModuleCount());
    for (Module const& m : Modules(&e))
        std::cout << std::format("  {:016x} {:9x} {:08x} {}\n", A(m.Address), m.Size, m.Timestamp, Narrow(ModuleName(m)));
    std::cout << std::format("exceptions: {}\n", e.GetExceptionEventCount());
    std::cout << std::format("keyframes : {}\n", e.GetKeyframeCount());
    return 0;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3) { Usage(); return 2; }
    std::string const cmd = Narrow(argv[1]);
    std::vector<std::string> pos;
    std::map<std::string, std::string> opts;
    for (int i = 2; i < argc; ++i) {
        std::string a = Narrow(argv[i]);
        if (a.rfind("--", 0) == 0) {
            std::string key = a.substr(2), val = "1";
            if (auto eq = key.find('='); eq != std::string::npos) { val = key.substr(eq + 1); key = key.substr(0, eq); }
            else if (i + 1 < argc && std::wstring_view(argv[i + 1]).rfind(L"--", 0) != 0 &&
                     (key == "stack-depth" || key == "symbol-path" || key == "index" || key == "calls" || key == "call-args" || key == "win32-index" ||
                      key == "activity" || key == "snapshots")) val = Narrow(argv[++i]);
            opts[key] = val;
        } else {
            pos.push_back(a);
        }
    }

    try {
        if (cmd == "analyze") {
            if (pos.size() != 2) { Usage(); return 2; }
            return RunAnalyze(Widen(pos[0]), Widen(pos[1]), opts);
        }
        if (cmd == "symbolize") {
            if (pos.size() != 1) { Usage(); return 2; }
            return RunSymbolize(Widen(pos[0]), opts);
        }
        if (cmd == "serve") {
            if (pos.size() != 2) { Usage(); return 2; }
            return RunServe(Widen(pos[0]), Widen(pos[1]), opts);
        }
        if (pos.size() != 1) { Usage(); return 2; }
        IndexMode const im = opts.count("index") && opts["index"] == "temp" ? IndexMode::Temporary : IndexMode::Keep;
        Trace trace(Widen(pos[0]), im, [](double f) { std::fprintf(stderr, "\rindexing %5.1f%%", f * 100); });
        std::fprintf(stderr, "\n");
        std::wstring const symPath = opts.count("symbol-path") ? Widen(opts["symbol-path"]) : DefaultSymbolPath();
        if (cmd == "info") return RunInfo(trace);
        if (cmd == "probe") return RunProbe(trace, symPath);
        Usage();
        return 2;
    } catch (std::exception const& ex) {
        std::fprintf(stderr, "error: %s\n", ex.what());
        if (cmd == "analyze" || cmd == "symbolize" || cmd == "serve") {
            std::string msg;
            JsonWriter::EscapeTo(msg, ex.what());
            std::printf("{\"type\":\"error\",\"message\":%s}\n", msg.c_str());
            std::fflush(stdout);
        }
        return 1;
    }
}
