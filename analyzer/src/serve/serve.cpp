// The `serve` command: a long-running query service over one analysis, so the viewer can ask what
// was in memory at an event and who accessed it.
//
// It speaks NDJSON on stdin/stdout. After {"type":"ready"}, each request line
//   {"id":1,"method":"memory.read","params":{...}}
// gets exactly one response line, {"id":1,"result":{...}} or {"id":1,"error":"..."}, preceded by any
// number of {"id":1,"progress":0.42} lines. Requests run one at a time, in order. EOF ends it.
//
//   memory.read    {evt | pos, addr, size}                    bytes, provenance ranges, unknown spans
//   accesses.query {lo, hi, reads, from, to, limit}           writes (old -> new), kernel/other-thread
//                                                             changes, reads when asked
//
// Memory contents are sample data: never log them. Diagnostics go to stderr without bytes.
#include "engine.h"
#include "out/json.h"
#include "serve/json_in.h"
#include "serve/memory_query.h"
#include "symbols/symbolizer.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <unordered_map>

namespace ttds {

namespace {

constexpr size_t kMaxRead = 64 * 1024;
constexpr uint64_t kMaxAccessRange = 1 << 20;
constexpr size_t kMaxAccessHits = 50000;

void Emit(std::string const& line)
{
    std::fwrite(line.data(), 1, line.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

struct BadRequest : std::runtime_error { using std::runtime_error::runtime_error; };

std::string Base64(std::vector<uint8_t> const& data)
{
    static char const* const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < data.size()) v |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < data.size()) v |= data[i + 2];
        out += alphabet[(v >> 18) & 63];
        out += alphabet[(v >> 12) & 63];
        out += i + 1 < data.size() ? alphabet[(v >> 6) & 63] : '=';
        out += i + 2 < data.size() ? alphabet[v & 63] : '=';
    }
    return out;
}

std::string HexBytes(std::vector<uint8_t> const& v)
{
    std::string s;
    s.reserve(v.size() * 2);
    for (uint8_t b : v) s += std::format("{:02x}", b);
    return s;
}

std::string Pos(Position16 p) { return std::format("{:X}:{:X}", p.seq, p.steps); }

class Server
{
public:
    Server(Trace& trace, std::filesystem::path const& dir, std::wstring symPath)
        : m_trace(trace), m_symPath(std::move(symPath)), m_modules(ReadSymbolInput(dir)), m_cursor(trace.NewCursor())
    {
        std::ifstream f(dir / "positions.bin", std::ios::binary);
        if (!f) throw std::runtime_error("positions.bin not found in the analysis directory");
        std::vector<char> raw((std::istreambuf_iterator<char>(f)), {});
        m_positions.resize(raw.size() / sizeof(Position16));
        std::memcpy(m_positions.data(), raw.data(), m_positions.size() * sizeof(Position16));
    }

    void Handle(std::string const& line)
    {
        auto const req = JsonValue::Parse(line);
        if (!req) { Emit(R"({"id":null,"error":"invalid JSON"})"); return; }
        double const idNum = (*req)["id"].Number().value_or(-1);
        m_id = idNum >= 0 ? static_cast<int64_t>(idNum) : -1;
        std::string const method = (*req)["method"].String().value_or("");
        try {
            JsonWriter j;
            j.BeginObject().Key("id").Number(m_id).Key("result");
            JsonValue const& params = (*req)["params"];
            if (method == "memory.read") MemoryReadMethod(params, j);
            else if (method == "accesses.query") AccessesMethod(params, j);
            else if (method == "ping") j.BeginObject().Key("events").Number(static_cast<uint64_t>(m_positions.size())).EndObject();
            else throw BadRequest("unknown method: " + method);
            j.EndObject();
            Emit(j.Str());
        } catch (std::exception const& ex) {
            JsonWriter j;
            j.BeginObject().Key("id").Number(m_id).Key("error").String(ex.what()).EndObject();
            Emit(j.Str());
        }
    }

private:
    // The position of the state after event evt (-1: the start of the trace), or of a "SEQ:STEPS".
    Position PositionOf(JsonValue const& params)
    {
        if (auto p = params["pos"].String()) {
            auto const parsed = ParsePosition(*p);
            if (!parsed) throw BadRequest("pos must be SEQ:STEPS in hex");
            return Position{ SequenceId{ parsed->seq }, StepCount{ parsed->steps } };
        }
        auto const evt = params["evt"].Number();
        if (!evt) throw BadRequest("evt or pos is required");
        return EventPosition(*evt);
    }

    Position EventPosition(double evt)
    {
        if (evt < 0) return m_trace.Engine().GetLifetime().Min;
        size_t const i = static_cast<size_t>(evt);
        if (i >= m_positions.size()) return m_trace.Engine().GetLifetime().Max;
        return Position{ SequenceId{ m_positions[i].seq }, StepCount{ m_positions[i].steps } };
    }

    uint32_t EventOfSequence(uint64_t seq) const { return EventAtOrAfter(m_positions, { seq, 0 }); }

    void MemoryReadMethod(JsonValue const& params, JsonWriter& j)
    {
        auto const addr = params["addr"].Address();
        if (!addr) throw BadRequest("addr is required");
        size_t const size = static_cast<size_t>(std::clamp(params["size"].Number().value_or(256), 1.0, static_cast<double>(kMaxRead)));
        if (*addr + size < *addr) throw BadRequest("address range wraps");
        Position const pos = PositionOf(params);
        m_cursor->SetPosition(pos);
        Position const at = m_cursor->GetPosition(); // SetPosition rounds up (landmine 14)
        MemoryRead const r = ReadMemory(*m_cursor, *addr, size);

        j.BeginObject();
        j.Key("addr").Hex(*addr).Key("size").Number(static_cast<uint64_t>(size));
        j.Key("pos").String(PosStr(at)).Key("seq").Number(U(at.Sequence));
        j.Key("data").String(Base64(r.bytes));
        // Provenance: [offset, length, sequence, event]; adjacent ranges of one sequence are merged.
        j.Key("ranges").BeginArray();
        size_t k = 0;
        while (k < r.ranges.size()) {
            RecordedRange x = r.ranges[k++];
            while (k < r.ranges.size() && r.ranges[k].seq == x.seq && r.ranges[k].addr == x.addr + x.size) x.size += r.ranges[k++].size;
            j.BeginArray().Number(x.addr - *addr).Number(x.size).Number(x.seq).Number(EventOfSequence(x.seq)).EndArray();
        }
        j.EndArray();
        j.Key("unknown").BeginArray();
        for (auto const& [o, len] : r.unknown) j.BeginArray().Number(o).Number(len).EndArray();
        j.EndArray();
        j.EndObject();
    }

    void AccessesMethod(JsonValue const& params, JsonWriter& j)
    {
        AccessQuery q;
        auto const lo = params["lo"].Address(), hi = params["hi"].Address();
        if (!lo || !hi || *hi <= *lo) throw BadRequest("lo < hi is required");
        if (*hi - *lo > kMaxAccessRange) throw BadRequest("the range is larger than 1 MiB");
        q.lo = *lo; q.hi = *hi;
        q.reads = params["reads"].Bool().value_or(false);
        q.limit = static_cast<size_t>(std::clamp(params["limit"].Number().value_or(5000), 1.0, static_cast<double>(kMaxAccessHits)));
        if (auto f = params["from"].Number()) q.from = EventPosition(*f);
        else q.from = m_trace.Engine().GetLifetime().Min;
        if (auto t = params["to"].Number()) q.to = EventPosition(*t);
        else q.to = m_trace.Engine().GetLifetime().Max;
        if (q.to < q.from) throw BadRequest("to is before from");

        int64_t const id = m_id;
        AccessResult const r = QueryAccesses(m_trace, q, [id](double f) {
            Emit(std::format(R"({{"id":{},"progress":{:.3f}}})", id, f));
        });

        j.BeginObject();
        j.Key("lo").Hex(q.lo).Key("hi").Hex(q.hi).Key("reads").Bool(q.reads);
        j.Key("truncated").Bool(r.truncated).Key("ms").Number(r.ms);
        j.Key("hits").BeginArray();
        static char const* const kinds[] = { "w", "r", "m" };
        for (AccessHit const& h : r.hits) {
            int const mi = ModuleIndex(h.pc);
            j.BeginObject();
            j.Key("pos").String(Pos(h.pos)).Key("evt").Number(EventAtOrAfter(m_positions, h.pos));
            j.Key("utid").Number(h.utid).Key("pc").Hex(h.pc);
            j.Key("module").Index(mi < 0 ? kNone : static_cast<uint32_t>(mi));
            j.Key("sym").String(Symbol(h.pc, mi));
            j.Key("addr").Hex(h.addr).Key("size").Number(h.size);
            j.Key("kind").String(kinds[static_cast<int>(h.kind)]);
            if (h.oldKnown) j.Key("old").String(HexBytes(h.oldValue));
            if (h.newKnown) j.Key("new").String(HexBytes(h.newValue));
            j.EndObject();
        }
        j.EndArray();
        j.EndObject();
    }

    // Index in the manifest's module list (modules can reuse a base over time: any match will do for
    // naming), or -1 outside every module.
    int ModuleIndex(uint64_t pc) const
    {
        for (size_t i = 0; i < m_modules.size(); ++i)
            if (pc >= m_modules[i].base && pc - m_modules[i].base < m_modules[i].size) return static_cast<int>(i);
        return -1;
    }

    std::string Symbol(uint64_t pc, int mi)
    {
        if (mi < 0) return {};
        auto it = m_symbols.find(pc);
        if (it != m_symbols.end()) return it->second;
        if (!m_symbolizer) {
            // Symbols were fetched into the local cache by the analysis, so this is usually quick.
            m_symbolizer = std::make_unique<Symbolizer>(m_symPath);
            for (auto const& m : m_modules) m_symbolizer->AddModule({ Widen(m.path), m.base, m.size, m.timestamp });
        }
        return m_symbols[pc] = m_symbolizer->Resolve(pc, mi).symbol;
    }

    Trace&                                  m_trace;
    std::wstring                            m_symPath;
    std::vector<SymModule>                  m_modules;
    std::vector<Position16>                 m_positions;
    UniqueCursor                            m_cursor;
    std::unique_ptr<Symbolizer>             m_symbolizer;
    std::unordered_map<uint64_t, std::string> m_symbols;
    int64_t                                 m_id = -1;
};

} // namespace

int RunServe(std::filesystem::path const& tracePath, std::filesystem::path const& dir,
             std::map<std::string, std::string> const& opts)
{
    Trace trace(tracePath, IndexMode::Keep);
    std::wstring const symPath = opts.count("symbol-path") ? Widen(opts.at("symbol-path")) : DefaultSymbolPath();
    Server server(trace, dir, symPath);
    Emit(R"({"type":"ready"})");
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        server.Handle(line);
    }
    return 0;
}

} // namespace ttds
