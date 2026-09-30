#include "exports.h"
#include "hooks.h"
#include "pe/recorded_pe.h"

#include <map>

namespace ttds {

ExportSet CollectExports(Trace const& trace)
{
    ExportSet set;
    IReplayEngine const& e = trace.Engine();
    PositionRange const life = e.GetLifetime();
    UniqueCursor cursor = trace.NewCursor();

    // A module loaded several times (or listed once per instance) is parsed once.
    std::map<std::pair<uint64_t, uint32_t>, std::optional<PeInfo>> parsed;
    uint32_t index = 0;
    for (ModuleInstance const& mi : ModuleInstances(&e)) {
        uint32_t const module = index++;
        Module const& m = *mi.pModule;
        uint64_t const base = A(m.Address);
        auto [it, fresh] = parsed.try_emplace({ base, m.Timestamp });
        if (fresh) {
            PeFile const file(GuestPathToHost(std::wstring(m.pName, m.NameLength)));
            if (file.Ok()) {
                auto pe = ParsePe(file.Reader());
                if (pe && pe->timeDateStamp == m.Timestamp && pe->sizeOfImage == m.Size) {
                    it->second = std::move(pe);
                    ++set.modulesFromDisk;
                }
            }
            // Memory the loader or GetProcAddress touched may only be visible late in the trace.
            for (Position const& p : { life.Max, life.Min }) {
                if (it->second) break;
                cursor->SetPosition(p);
                auto pe = ParsePe(GuestImageReader(*cursor, base));
                if (pe && pe->timeDateStamp == m.Timestamp && !pe->exports.empty()) it->second = std::move(pe);
            }
            if (it->second) ++set.modulesRead;
            else set.unreadable.push_back(Narrow(ModuleBaseName(m)));
        }
        if (!it->second) continue;
        for (bool const ordinalOnly : { false, true }) {
            for (auto const& [name, rva] : it->second->exports) {
                if ((name[0] == '#') != ordinalOnly) continue;
                uint64_t const address = base + rva;
                if (set.byAddress.Find(address) != kNone) continue;
                set.byAddress.Add(address, static_cast<uint32_t>(set.symbols.size()));
                set.symbols.push_back({ address, module, name, it->second->is64 });
            }
        }
    }
    return set;
}

} // namespace ttds
