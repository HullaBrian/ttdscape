#include "json/writer.h"

#include "json/json.h"

#include <cstring>
#include <fstream>
#include <map>

namespace ttds {

namespace {

template <typename T>
void WriteTable(std::filesystem::path const& path, std::vector<T> const& v)
{
    WriteFile(path, v.data(), v.size() * sizeof(T));
}

void WriteText(std::filesystem::path const& path, std::string const& s) { WriteFile(path, s.data(), s.size()); }

// series.bin: u32 buckets, u32 columns, f64 eventsPerBucket, then the columns, one after another.
void WriteSeries(std::filesystem::path const& path, SeriesOut const& s)
{
    std::string out;
    uint32_t const buckets = s.buckets, columns = static_cast<uint32_t>(s.columns.size());
    out.append(reinterpret_cast<char const*>(&buckets), 4);
    out.append(reinterpret_cast<char const*>(&columns), 4);
    out.append(reinterpret_cast<char const*>(&s.eventsPerBucket), 8);
    for (auto const& [name, values] : s.columns) {
        for (uint32_t b = 0; b < buckets; ++b) {
            double const v = b < values.size() ? values[b] : 0.0;
            out.append(reinterpret_cast<char const*>(&v), 8);
        }
    }
    WriteText(path, out);
}

// frames.bin: address u64, module u32 (kNone: unbacked), rva u32. Frames are return addresses, so
// the module is the one holding the call site (address - 1). Of several modules that held the
// address over time, the one loaded last wins.
std::vector<uint8_t> BuildFrames(StackTrie const& stacks, std::vector<ModuleOut> const& modules)
{
    auto const loaded = [](ModuleOut const& m) { return m.loadEvt == kNone ? 0ull : m.loadEvt + 1ull; };
    auto const& addrs = stacks.FrameAddresses();
    std::vector<uint8_t> out(addrs.size() * 16);
    for (size_t i = 0; i < addrs.size(); ++i) {
        uint64_t const a = addrs[i], site = a > 0 ? a - 1 : a;
        uint32_t module = kNone, rva = 0;
        for (uint32_t m = 0; m < modules.size(); ++m) {
            ModuleOut const& x = modules[m];
            if (site < x.base || site >= x.base + x.size) continue;
            if (module != kNone && loaded(modules[module]) > loaded(x)) continue;
            module = m;
            rva = static_cast<uint32_t>(a - x.base);
        }
        std::memcpy(out.data() + i * 16, &a, 8);
        std::memcpy(out.data() + i * 16 + 8, &module, 4);
        std::memcpy(out.data() + i * 16 + 12, &rva, 4);
    }
    return out;
}

char const* HeapKindName(HeapKind k)
{
    switch (k) {
    case HeapKind::Process: return "process";
    case HeapKind::Created: return "created";
    case HeapKind::PreExisting: return "preexisting";
    case HeapKind::Discovered: return "discovered";
    }
    return "?";
}

std::string PosText(Position16 p) { return std::format("{:X}:{:X}", p.seq, p.steps); }

void WriteWx(std::filesystem::path const& path, ActivityOut const& a)
{
    JsonWriter j;
    j.BeginObject().Key("findings").BeginArray();
    for (WxFinding const& f : a.wx) {
        j.BeginObject();
        j.Key("region").Index(f.region).Key("page").Hex(f.page);
        j.Key("exec").BeginObject().Key("pos").String(PosText(f.execPos)).Key("evt").Number(f.execEvt)
            .Key("thread").Number(f.execThread).Key("pc").Hex(f.execPc).EndObject();
        j.Key("write").BeginObject().Key("pos").String(PosText(f.writePos)).Key("evt").Number(f.writeEvt)
            .Key("thread").Number(f.writeThread).Key("pc").Hex(f.writerPc).Key("frame").Index(f.writerFrame)
            .Key("region").Index(f.writerRegion).EndObject();
        j.Key("writes").Number(f.writesBefore);
        j.EndObject();
    }
    j.EndArray().EndObject();
    WriteText(path, j.Str());
}

void WriteCallees(std::filesystem::path const& path, CallsOut const& c)
{
    JsonWriter j;
    j.BeginObject().Key("callees").BeginArray();
    for (CalleeOut const& x : c.callees) j.BeginArray().Index(x.module).String(x.name).Hex(x.address).EndArray();
    j.EndArray().EndObject();
    WriteText(path, j.Str());
}

// callargs.jsonl: one line per call in calls.bin order. callargs.bin: the u64 byte offset of each
// line, plus the end.
void WriteCallArgs(std::filesystem::path const& dir, CaptureResult const& cap, CallsOut const& c)
{
    std::string text;
    std::vector<uint64_t> offsets;
    offsets.reserve(c.records.size() + 1);
    for (size_t i = 0; i < c.records.size(); ++i) {
        offsets.push_back(text.size());
        uint32_t const src = i < c.source.size() ? c.source[i] : kNone;
        if (src < cap.exportArgs.size()) text += cap.exportArgs[src];
        text += '\n';
    }
    offsets.push_back(text.size());
    WriteText(dir / "callargs.jsonl", text);
    WriteTable(dir / "callargs.bin", offsets);
}

void WriteOutField(JsonWriter& j, char const* key, OutField const& f)
{
    j.Key(key).BeginObject().Key("slot").Hex(f.slot).Key("pre").Hex(f.pre).Key("value").Hex(f.value)
        .Key("src").String(OutSrcName(f.src)).EndObject();
}

// ---- manifest.json ----

struct FileEntry
{
    char const* key;
    char const* file;
    uint64_t    count;
};

void Quality(JsonWriter& j, QualityOut const& q, CaptureStats const& s)
{
    j.Key("quality").BeginObject();
    j.Key("outParams").BeginObject().Key("computed").Number(q.outComputed).Key("atReturn").Number(q.outAtReturn)
        .Key("readback").Number(q.outReadback).Key("seek").Number(q.outSeek).Key("unknown").Number(q.outUnknown)
        .Key("oldProtectFromModel").Number(q.oldProtectFromModel).EndObject();
    j.Key("unwound").Number(q.unwound).Key("neverReturned").Number(q.neverReturned).Key("unmatchedRets").Number(q.unmatchedRets);
    j.Key("tailCalls").Number(q.tailCalls).Key("superseded").Number(q.superseded).Key("doubleFree").Number(q.doubleFree);
    j.Key("preTraceFrees").Number(q.preTraceFrees).Key("nestedSkipped").Number(q.nestedSkipped);
    j.Key("failedCalls").Number(q.failedCalls).Key("remoteCalls").Number(q.remoteCalls).Key("unplacedVm").Number(q.unplacedVm);
    j.Key("releaseUnknownRegion").Number(q.releaseUnknownRegion).Key("kernelCalls").Number(q.kernelCalls);
    j.Key("directSyscalls").Number(q.directSyscalls).Key("positionOrderViolations").Number(q.positionOrderViolations);
    j.Key("capture").BeginObject().Key("callbacks").Number(s.callbacks).Key("hookedCalls").Number(s.hookedCalls)
        .Key("retargeted").Number(s.retargeted).Key("stackOverflows").Number(s.stackOverflows)
        .Key("kernelCallsOutsideNtdll").Number(s.kernelCallsOutsideNtdll).EndObject();
    j.EndObject();
}

} // namespace

void WriteFile(std::filesystem::path const& path, void const* data, size_t size)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (f) f.write(static_cast<char const*>(data), static_cast<std::streamsize>(size));
    if (!f) throw std::runtime_error(std::format("cannot write {}", path.string()));
}

void WriteModel(std::filesystem::path const& dir, TraceMeta const& meta, HookResolution const& hooks,
                CaptureResult const& cap, Model const& model, Timings const& timings)
{
    std::filesystem::create_directories(dir);
    std::vector<FileEntry> files;
    auto const table = [&](char const* key, char const* name, auto const& v) {
        WriteTable(dir / name, v);
        files.push_back({ key, name, v.size() });
    };

    table("events", "events.bin", model.events);
    table("positions", "positions.bin", model.positions);
    table("blocks", "blocks.bin", model.blocks);
    table("regions", "regions.bin", model.regions);
    table("spans", "spans.bin", model.spans);
    table("stacks", "stacks.bin", cap.stacks.Nodes());
    std::vector<uint8_t> const frames = BuildFrames(cap.stacks, model.modules);
    WriteTable(dir / "frames.bin", frames);
    files.push_back({ "frames", "frames.bin", frames.size() / 16 });
    WriteSeries(dir / "series.bin", model.series);

    CallsOut const& calls = model.calls;
    bool const haveArgs = calls.recorded && calls.args;
    if (calls.recorded) {
        table("calls", "calls.bin", calls.records);
        table("callpos", "callpos.bin", calls.positions);
        table("callstacks", "callstacks.bin", calls.stacks);
        WriteCallees(dir / "callees.json", calls);
        files.push_back({ "callees", "callees.json", calls.callees.size() });
        if (haveArgs) WriteCallArgs(dir, cap, calls);
    }
    ActivityOut const& act = model.activity;
    if (act.recorded) {
        table("activity", "activity.bin", act.cells);
        table("writers", "writers.bin", act.writers);
        table("flows", "flows.bin", act.flows);
        WriteWx(dir / "wx.json", act);
        files.push_back({ "wx", "wx.json", act.wx.size() });
    }
    SnapshotOut const& snap = model.snapshots;
    if (snap.recorded) {
        table("contentsIdx", "contents.idx", snap.index);
        table("contents", "contents.bin", snap.bytes);
    }

    JsonWriter j;
    j.BeginObject();
    j.Key("schema").String("ttdscape/1").Key("analyzer").String(kAnalyzerVersion);

    j.Key("trace").BeginObject().Key("path").String(meta.path).Key("fileSize").Number(meta.fileSize).Key("arch").String(meta.arch)
        .Key("pid").Number(meta.pid).Key("os").String(meta.os).Key("recording").String(meta.recording)
        .Key("lifetimeMin").String(meta.lifetimeMin).Key("lifetimeMax").String(meta.lifetimeMax).Key("peb").Hex(meta.peb).EndObject();

    j.Key("counts").BeginObject();
    j.Key("events").Number(model.events.size()).Key("blocks").Number(model.blocks.size()).Key("regions").Number(model.regions.size());
    j.Key("spans").Number(model.spans.size()).Key("stacks").Number(cap.stacks.Nodes().size()).Key("frames").Number(frames.size() / 16);
    j.Key("threads").Number(model.threads.size()).Key("heaps").Number(model.heaps.size()).Key("modules").Number(model.modules.size());
    j.Key("markers").Number(model.markers.size());
    j.EndObject();

    j.Key("files").BeginObject();
    for (FileEntry const& f : files)
        j.Key(f.key).BeginObject().Key("file").String(f.file).Key("count").Number(f.count).EndObject();
    j.Key("series").BeginObject().Key("file").String("series.bin").Key("buckets").Number(model.series.buckets)
        .Key("eventsPerBucket").Number(model.series.eventsPerBucket).Key("columns").BeginArray();
    for (auto const& col : model.series.columns) j.String(col.first);
    j.EndArray().EndObject();
    if (haveArgs)
        j.Key("callargs").BeginObject().Key("file").String("callargs.jsonl").Key("index").String("callargs.bin")
            .Key("count").Number(calls.records.size()).EndObject();
    j.EndObject();

    j.Key("threads").BeginArray();
    for (uint32_t i = 0; i < model.threads.size(); ++i) {
        ThreadOut const& t = model.threads[i];
        j.BeginObject().Key("index").Number(i).Key("utid").Number(t.utid).Key("osTid").Number(t.osTid)
            .Key("createEvt").Index(t.createEvt).Key("exitEvt").Index(t.exitEvt)
            .Key("stackLow").Hex(t.stackLow).Key("stackHigh").Hex(t.stackHigh).Key("stackSource").String(t.stackSource).EndObject();
    }
    j.EndArray();

    j.Key("heaps").BeginArray();
    for (uint32_t i = 0; i < model.heaps.size(); ++i) {
        HeapInfo const& h = model.heaps[i];
        j.BeginObject().Key("index").Number(i).Key("handle").Hex(h.handle).Key("kind").String(HeapKindName(h.kind))
            .Key("createEvt").Index(h.createEvt).Key("destroyEvt").Index(h.destroyEvt)
            .Key("createFlags").Number(h.createFlags).Key("createStack").Index(h.createStack).EndObject();
    }
    j.EndArray();

    j.Key("modules").BeginArray();
    for (uint32_t i = 0; i < model.modules.size(); ++i) {
        ModuleOut const& m = model.modules[i];
        j.BeginObject().Key("index").Number(i).Key("name").String(m.name).Key("path").String(m.path)
            .Key("base").Hex(m.base).Key("size").Hex(m.size).Key("timestamp").Number(m.timestamp).Key("checksum").Number(m.checksum)
            .Key("loadEvt").Index(m.loadEvt).Key("unloadEvt").Index(m.unloadEvt).Key("region").Index(m.region).EndObject();
    }
    j.EndArray();

    j.Key("markers").BeginArray();
    for (MarkerOut const& m : model.markers)
        j.BeginObject().Key("evt").Index(m.evt).Key("thread").Number(m.thread).Key("text").String(m.text).EndObject();
    j.EndArray();

    std::map<HookKind, uint64_t> perHook;
    for (RawCall const& c : cap.calls) ++perHook[c.kind];
    j.Key("hooks").BeginObject().Key("ntdll").String(hooks.ntdllPath).Key("ntdllBase").Hex(hooks.ntdllBase)
        .Key("source").String(hooks.exportSource).Key("sites").BeginArray();
    for (HookSite const& s : hooks.sites)
        j.BeginObject().Key("name").String(HookName(s.kind)).Key("address").Hex(s.address).Key("source").String(s.source)
            .Key("calls").Number(perHook[s.kind]).EndObject();
    j.EndArray().EndObject();

    Quality(j, model.quality, cap.stats);

    if (calls.recorded) {
        j.Key("calls").BeginObject().Key("count").Number(calls.records.size()).Key("callees").Number(calls.callees.size())
            .Key("tail").Number(calls.tailCalls).Key("unwound").Number(calls.unwound).Key("neverReturned").Number(calls.neverReturned)
            .Key("sameModule").Number(calls.sameModule).Key("exportModules").Number(calls.exportModules)
            .Key("exportModulesFromDisk").Number(calls.exportModulesFromDisk).Key("modulesWithoutExports").BeginArray();
        for (auto const& n : calls.modulesWithoutExports) j.String(n);
        j.EndArray();
        if (haveArgs)
            j.Key("args").BeginObject().Key("withSignature").Number(calls.argsWithSignature).Key("heuristic").Number(calls.argsHeuristic)
                .Key("stringsAtReturn").Number(calls.argStringsAtReturn).Key("signatures").Number(calls.signatures).EndObject();
        j.EndObject();
    }

    if (act.recorded) {
        j.Key("activity").BeginObject().Key("exec").String(act.exec).Key("writes").Number(act.writes)
            .Key("execHits").Number(act.execHits).Key("mismatches").Number(act.mismatches).Key("ranges").Number(act.ranges)
            .Key("bytesWatched").Number(act.bytesWatched).Key("objects").Number(act.writers.size())
            .Key("findings").Number(act.wx.size()).Key("ms").Number(act.ms).EndObject();
    }
    if (snap.recorded) {
        uint64_t withBytes = 0;
        for (ContentIdx const& c : snap.index) withBytes += c.length > 0;
        j.Key("snapshots").BeginObject().Key("blocks").Number(withBytes).Key("cap").Number(snap.cap)
            .Key("bytes").Number(snap.bytes.size()).Key("mismatched").Number(snap.mismatched).Key("readBack").Number(snap.readBack).EndObject();
    }

    j.Key("timings").BeginObject().Key("indexMs").Number(timings.indexMs).Key("hooksMs").Number(timings.hooksMs)
        .Key("captureMs").Number(timings.captureMs).Key("resolveMs").Number(timings.resolveMs).Key("modelMs").Number(timings.modelMs)
        .Key("activityMs").Number(timings.activityMs).Key("symbolsMs").Number(timings.symbolsMs).EndObject();

    j.Key("warnings").BeginArray();
    for (auto const& w : model.warnings) j.String(w);
    for (auto const& w : hooks.warnings) j.String(w);
    j.EndArray();
    j.EndObject();
    WriteText(dir / "manifest.json", j.Str());
}

void WriteDebugCalls(std::filesystem::path const& path, CaptureResult const& cap, Trace const&)
{
    std::string out;
    for (RawCall const& c : cap.calls) {
        JsonWriter j;
        j.BeginObject().Key("kind").String(HookName(c.kind)).Key("thread").Number(c.thread).Key("flags").Number(c.flags)
            .Key("stack").Index(c.stack).Key("outer").Index(c.outer)
            .Key("callPos").String(PosStr(c.callPos)).Key("retPos").String(PosStr(c.retPos));
        j.Key("args").BeginArray();
        for (unsigned i = 0; i < HookArgCount(c.kind); ++i) j.Hex(c.args[i]);
        j.EndArray().Key("ret").Hex(c.ret);
        j.Key("out").BeginObject();
        WriteOutField(j, "base", c.out.base);
        WriteOutField(j, "size", c.out.size);
        WriteOutField(j, "oldProtect", c.out.oldProt);
        j.EndObject().EndObject();
        out += j.Str();
        out += '\n';
    }
    WriteText(path, out);
}

} // namespace ttds
