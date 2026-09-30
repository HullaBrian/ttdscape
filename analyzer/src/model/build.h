#pragma once
#include "engine.h"
#include "exports.h"
#include "hooks.h"
#include "model/types.h"
#include "replay/capture.h"

namespace ttds {

struct BuildOptions
{
    uint32_t seriesBuckets = 4096;
    size_t   maxMarkers = 20000;
    ExportSet const* exports = nullptr; // the exports CaptureResult::exportCalls refer to
};

// Pass 2: orders every captured call and engine event by position and replays them into the heap
// and VM models. No trace replay happens here (only a few memory reads for PEB/markers).
Model BuildModel(Trace const& trace, HookResolution const& hooks, CaptureResult const& cap, BuildOptions const& opts);

} // namespace ttds
