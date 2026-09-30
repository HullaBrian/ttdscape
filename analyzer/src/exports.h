#pragma once
#include "engine.h"
#include "model/address_map.h"

#include <string>
#include <vector>

namespace ttds {

struct ExportSym
{
    uint64_t    address = 0;
    uint32_t    module = 0;   // index in the module-instance list (= Model::modules)
    std::string name;         // "#<ordinal>" for exports without a name
    bool        is64 = true;  // bitness of the owning module (a WoW64 process runs both)
};

struct ExportSet
{
    std::vector<ExportSym> symbols;
    AddressMap             byAddress;  // entry address -> index in symbols
    uint32_t modulesRead = 0;          // modules whose export table was read
    uint32_t modulesFromDisk = 0;      // ... of which from the matching file on disk
    std::vector<std::string> unreadable; // modules with an export directory we could not read
};

// Export tables of every module loaded during the trace: from the file on disk when its timestamp
// and size match the recorded module, otherwise from the recorded image in trace memory. Aliases
// (several names at one address) keep the first name in name order.
ExportSet CollectExports(Trace const& trace);

} // namespace ttds
