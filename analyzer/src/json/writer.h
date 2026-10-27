#pragma once
#include "engine.h"
#include "hooks.h"
#include "model/types.h"
#include "replay/capture.h"

#include <cstdint>
#include <filesystem>
#include <string>

namespace ttds {

// Part of the cache key on the server: bump it (with analyzerVersion in server/config.mjs) whenever
// the analyzer's output changes, otherwise "Analyze" reopens stale cached results.
inline constexpr char const* kAnalyzerVersion = "0.3.1";

// Writes a binary table (or any bytes) to path, replacing it. Throws on failure.
void WriteFile(std::filesystem::path const& path, void const* data, size_t size);

struct Timings
{
    uint64_t indexMs = 0, hooksMs = 0, captureMs = 0, resolveMs = 0, modelMs = 0, activityMs = 0, symbolsMs = 0;
};

// Facts about the recording, for manifest.json "trace".
struct TraceMeta
{
    std::string path;
    uint64_t    fileSize = 0;
    std::string arch;       // "x64" | "x86"
    uint64_t    pid = 0;
    std::string os;         // major.minor.build
    std::string recording;
    std::string lifetimeMin, lifetimeMax;
    uint64_t    peb = 0;
};

// Writes every table of an analysis into dir (layouts in model/types.h, read by
// client/trace-reader.js) and manifest.json last, so a directory with a manifest is complete.
// symbols.json is not part of it: the symbolize step writes that from frames.bin.
void WriteModel(std::filesystem::path const& dir, TraceMeta const& meta, HookResolution const& hooks,
                CaptureResult const& cap, Model const& model, Timings const& timings);

// --debug-ndjson: one JSON line per hooked call, with its resolved out-params (calls.ndjson).
void WriteDebugCalls(std::filesystem::path const& path, CaptureResult const& cap, Trace const& trace);

} // namespace ttds
