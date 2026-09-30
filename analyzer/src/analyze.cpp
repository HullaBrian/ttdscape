// The `analyze` and `symbolize` commands.
//
// Progress and results are reported on stdout as NDJSON lines so the server can relay them:
//   {"type":"stage","stage":"capture"}
//   {"type":"progress","stage":"capture","fraction":0.42}
//   {"type":"done","ms":1234}
// Human-readable diagnostics go to stderr.
#include "engine.h"
#include "exports.h"
#include "hooks.h"
#include "model/build.h"
#include "out/json.h"
#include "out/writer.h"
#include "replay/activity.h"
#include "replay/capture.h"
#include "symbols/symbolizer.h"

#include <cstdio>
#include <fstream>
#include <map>

namespace ttds {

namespace {

void Emit(std::string const& line)
{
    std::fwrite(line.data(), 1, line.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

void Stage(char const* s)
{
    JsonWriter j;
    j.BeginObject().Key("type").String("stage").Key("stage").String(s).EndObject();
    Emit(j.Str());
}

class ProgressReporter
{
public:
    explicit ProgressReporter(char const* stage) : m_stage(stage) {}
    void operator()(double f)
    {
        f = std::clamp(f, 0.0, 1.0);
        ULONGLONG const now = GetTickCount64();
        if (f < 1.0 && now - m_last < 200) return;
        m_last = now;
        Emit(std::format(R"({{"type":"progress","stage":"{}","fraction":{:.4f}}})", m_stage, f));
    }
private:
    char const* m_stage;
    ULONGLONG m_last = 0;
};

std::wstring SymPathFrom(std::map<std::string, std::string> const& opts)
{
    auto it = opts.find("symbol-path");
    return it != opts.end() ? Widen(it->second) : DefaultSymbolPath();
}

// symbols.json: {"frames":[[symbol,file,line],...],"modulesWithSymbols":n}
void Symbolize(std::filesystem::path const& dir, std::vector<SymModule> const& mods, std::wstring const& symPath)
{
    std::ifstream f(dir / "frames.bin", std::ios::binary);
    std::vector<char> raw((std::istreambuf_iterator<char>(f)), {});
    size_t const n = raw.size() / 16;

    Symbolizer sym(symPath);
    for (auto const& m : mods) sym.AddModule({ Widen(m.path), m.base, m.size, m.timestamp });

    ProgressReporter progress("symbols");
    std::string out = R"({"frames":[)";
    for (size_t i = 0; i < n; ++i) {
        uint64_t addr;
        uint32_t module;
        std::memcpy(&addr, raw.data() + i * 16, 8);
        std::memcpy(&module, raw.data() + i * 16 + 8, 4);
        // Frames are return addresses: the call site is the instruction before.
        int const mi = module == kNone ? -1 : static_cast<int>(module);
        ResolvedFrame const r = sym.Resolve(addr > 0 ? addr - 1 : addr, mi);
        if (i) out += ',';
        out += '[';
        JsonWriter::EscapeTo(out, r.symbol);
        out += ',';
        JsonWriter::EscapeTo(out, r.file);
        out += std::format(",{}]", r.line);
        if ((i & 255) == 0) progress(static_cast<double>(i) / std::max<size_t>(n, 1));
    }
    out += std::format(R"(],"modulesWithSymbols":{}}})", sym.ModulesWithSymbols());
    progress(1.0);
    WriteFile(dir / "symbols.json", out.data(), out.size());
}

void WriteSymbolInput(std::filesystem::path const& dir, Model const& model)
{
    std::string s;
    for (auto const& m : model.modules) s += std::format("{}\t{:x}\t{:x}\t{:x}\n", m.path, m.base, m.size, m.timestamp);
    WriteFile(dir / "symbol-input.tsv", s.data(), s.size());
}

} // namespace

int RunAnalyze(std::filesystem::path const& tracePath, std::filesystem::path const& out,
               std::map<std::string, std::string> const& opts)
{
    ULONGLONG const t0 = GetTickCount64();
    Timings timings;
    std::filesystem::create_directories(out);

    Stage("index");
    ProgressReporter indexProgress("index");
    IndexMode const im = opts.count("index") && opts.at("index") == "temp" ? IndexMode::Temporary : IndexMode::Keep;
    Trace trace(tracePath, im, [&](double f) { indexProgress(f); });
    timings.indexMs = GetTickCount64() - t0;

    if (trace.Arch() != ProcessorArchitecture::x64 && trace.Arch() != ProcessorArchitecture::x86)
        throw std::runtime_error(std::format("unsupported guest architecture: {}", GetProcessorArchitectureName(trace.Arch())));

    Stage("hooks");
    ULONGLONG t = GetTickCount64();
    std::wstring const symPath = SymPathFrom(opts);
    HookResolution const hooks = ResolveHooks(trace, symPath);
    for (auto const& w : hooks.warnings) std::fprintf(stderr, "warning: %s\n", w.c_str());
    if (hooks.sites.empty()) throw std::runtime_error("no hooks could be resolved (see warnings)");
    timings.hooksMs = GetTickCount64() - t;

    // --calls exports (default) | none
    std::string const callsScope = opts.count("calls") ? opts.at("calls") : "exports";
    if (callsScope != "exports" && callsScope != "none")
        throw std::runtime_error("--calls must be 'exports' or 'none'");
    ExportSet exports;
    if (callsScope == "exports") {
        Stage("exports");
        t = GetTickCount64();
        exports = CollectExports(trace);
        std::fprintf(stderr, "exports: %zu from %u modules (%u from disk), %zu modules without\n", exports.symbols.size(),
                     exports.modulesRead, exports.modulesFromDisk, exports.unreadable.size());
        timings.hooksMs += GetTickCount64() - t;
    }

    Stage("capture");
    t = GetTickCount64();
    CaptureOptions copts;
    if (callsScope == "exports") copts.exports = &exports;
    // --call-args on (default) | off: decode API arguments of the recorded calls.
    ArgDecoder argDecoder;
    bool const decodeArgs = callsScope == "exports" && !(opts.count("call-args") && opts.at("call-args") == "off");
    if (decodeArgs) {
        std::string err;
        std::filesystem::path const index = opts.count("win32-index") ? std::filesystem::path(Widen(opts.at("win32-index"))) : DefaultWin32IndexPath();
        if (argDecoder.Load(index, err)) copts.args = &argDecoder;
        else std::fprintf(stderr, "warning: API signatures unavailable (%s); arguments are not decoded\n", err.c_str());
    }
    if (opts.count("stack-depth")) copts.stackDepth = std::clamp(std::stoul(opts.at("stack-depth")), 1ul, 256ul);
    ProgressReporter captureProgress("capture");
    copts.progress = [&](double f) { captureProgress(f); };
    CaptureResult cap = Capture(trace, hooks, copts);
    timings.captureMs = GetTickCount64() - t;

    Stage("resolve");
    t = GetTickCount64();
    size_t const byWatch = ResolveByWatchpoints(trace, cap);
    if (byWatch) std::fprintf(stderr, "resolved %zu out-params with the watchpoint pass\n", byWatch);
    ResolveRemainingOutParams(trace, cap, opts.count("seek-budget") ? std::stoull(opts.at("seek-budget")) : 2000);
    timings.resolveMs = GetTickCount64() - t;

    Stage("model");
    t = GetTickCount64();
    BuildOptions bopts;
    if (callsScope == "exports") bopts.exports = &exports;
    Model model = BuildModel(trace, hooks, cap, bopts);
    if (copts.args) {
        auto const& st = argDecoder.GetStats();
        model.calls.args = true;
        model.calls.signatures = argDecoder.Signatures();
        model.calls.argsWithSignature = st.withSignature;
        model.calls.argsHeuristic = st.heuristic;
        model.calls.argStringsAtReturn = st.stringsAtReturn;
    }
    timings.modelMs = GetTickCount64() - t;

    // --activity off (default) | codefetch | execute: writes per object and write-then-execute.
    // --snapshots off (default) | on | BYTES: block contents for content search, rebuilt in the same
    // replay (so they imply it).
    std::string const activity = opts.count("activity") ? opts.at("activity") : "off";
    if (activity != "codefetch" && activity != "execute" && activity != "off")
        throw std::runtime_error("--activity must be 'codefetch', 'execute' or 'off'");
    std::string const snap = opts.count("snapshots") ? opts.at("snapshots") : "off";
    uint32_t const snapBytes = snap == "off" || snap == "0" ? 0u : snap == "on" ? 4096u
        : static_cast<uint32_t>(std::clamp(std::stoul(snap), 16ul, 65536ul));
    if (activity != "off" || snapBytes) {
        Stage("activity");
        t = GetTickCount64();
        ProgressReporter activityProgress("activity");
        ActivityOptions aopts;
        aopts.exec = activity == "execute" ? ExecDetect::Execute : activity == "codefetch" ? ExecDetect::CodeFetch : ExecDetect::None;
        aopts.snapshotCap = snapBytes;
        aopts.progress = [&](double f) { activityProgress(f); };
        model.activity = RunActivity(trace, model, cap.stacks, aopts, snapBytes ? &model.snapshots : nullptr);
        timings.activityMs = GetTickCount64() - t;
        std::fprintf(stderr, "activity: %llu writes, %llu exec hits over %llu ranges, %zu objects, %zu write-then-execute pages, %llu ms\n",
                     static_cast<unsigned long long>(model.activity.writes), static_cast<unsigned long long>(model.activity.execHits),
                     static_cast<unsigned long long>(model.activity.ranges), model.activity.writers.size(), model.activity.wx.size(),
                     static_cast<unsigned long long>(timings.activityMs));
        if (snapBytes)
            std::fprintf(stderr, "snapshots: %zu bytes, %llu bytes changed outside their thread, %u blocks read back (of %u)\n",
                         model.snapshots.bytes.size(), static_cast<unsigned long long>(model.activity.mismatches),
                         model.snapshots.readBack, model.snapshots.mismatched);
    }
    Stage("write");
    IReplayEngine const& e = trace.Engine();
    SystemInfo const& sys = e.GetSystemInfo();
    TraceMeta meta;
    meta.path = trace.Path().string();
    std::error_code ec;
    meta.fileSize = std::filesystem::file_size(tracePath, ec);
    meta.arch = trace.Arch() == ProcessorArchitecture::x64 ? "x64" : "x86";
    meta.pid = sys.ProcessId;
    meta.os = std::format("{}.{}.{}", sys.System.MajorVersion, sys.System.MinorVersion, sys.System.BuildNumber);
    meta.recording = GetRecordingTypeName(e.GetRecordingType());
    meta.lifetimeMin = PosStr(e.GetLifetime().Min);
    meta.lifetimeMax = PosStr(e.GetLifetime().Max);
    meta.peb = A(e.GetPebAddress());

    WriteSymbolInput(out, model);
    if (opts.count("debug-ndjson")) WriteDebugCalls(out / "calls.ndjson", cap, trace);

    t = GetTickCount64();
    WriteModel(out, meta, hooks, cap, model, timings); // stacks/frames first: symbolize reads frames.bin
    if (!opts.count("no-symbols")) {
        Stage("symbols");
        std::vector<SymModule> mods;
        for (auto const& m : model.modules) mods.push_back({ m.path, m.base, m.size, m.timestamp });
        Symbolize(out, mods, symPath);
        timings.symbolsMs = GetTickCount64() - t;
        WriteModel(out, meta, hooks, cap, model, timings); // refresh timings in the manifest
    }

    std::fprintf(stderr, "events %zu, blocks %zu, regions %zu, spans %zu, calls %zu, export calls %zu (capture %llu ms), %llu ms\n",
                 model.events.size(), model.blocks.size(), model.regions.size(), model.spans.size(), cap.calls.size(),
                 model.calls.records.size(), static_cast<unsigned long long>(timings.captureMs),
                 static_cast<unsigned long long>(GetTickCount64() - t0));
    Emit(std::format(R"({{"type":"done","ms":{}}})", GetTickCount64() - t0));
    return 0;
}

int RunSymbolize(std::filesystem::path const& out, std::map<std::string, std::string> const& opts)
{
    Stage("symbols");
    ULONGLONG const t0 = GetTickCount64();
    Symbolize(out, ReadSymbolInput(out), SymPathFrom(opts));
    Emit(std::format(R"({{"type":"done","ms":{}}})", GetTickCount64() - t0));
    return 0;
}

} // namespace ttds
