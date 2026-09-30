#include "replay/call_args.h"
#include "out/json.h"

#include "abi.hpp"
#include "win32meta.hpp"

namespace ttds {

namespace tc = ttdcapa;
using tc::win32meta::ArgKind;
namespace win32meta = tc::win32meta;

struct ArgDecoder::Active
{
    tc::GuestArch arch = tc::GuestArch::X64;
    bool metadata = false;
    std::vector<tc::DecodedArg> params;       // with a signature
    std::vector<tc::PendingOut> pending;      // [Out] reads deferred to the return
    std::vector<uint16_t> unread;         // [In] strings the entry could not see yet
    std::vector<tc::ArgValue> heuristic;      // without one
};

namespace {

tc::DecodeOptions const kDecode{ 48, 260 }; // bytes of a buffer preview, characters of a string

tc::CallFrame FrameOf(tc::GuestArch arch, IThreadView const* t, RegisterContext const& regs)
{
    tc::CallFrame f;
    f.arch = arch;
    f.thread = t;
    if (arch == tc::GuestArch::X64) f.x64 = reinterpret_cast<AMD64_CONTEXT const*>(&regs);
    else f.x86 = reinterpret_cast<X86_NT5_CONTEXT const*>(&regs);
    return f;
}

void Hex(std::string& out, uint64_t v) { out += std::format("\"0x{:x}\"", v); }

void Names(std::string& out, char const* key, std::vector<std::string> const& names)
{
    out += std::format(",\"{}\":[", key);
    for (size_t i = 0; i < names.size(); ++i) {
        if (i) out += ',';
        JsonWriter::EscapeTo(out, names[i]);
    }
    out += ']';
}

} // namespace

void ArgDecoder::ActiveDeleter::operator()(Active* a) const noexcept { delete a; }

ArgDecoder::ArgDecoder() = default;
ArgDecoder::~ArgDecoder() = default;

bool ArgDecoder::Load(std::filesystem::path const& win32Index, std::string& error)
{
    if (win32meta::index().loaded()) return true;
    return win32meta::loadIndex(win32Index, error);
}

size_t ArgDecoder::Signatures() const { return win32meta::index().functionCount(); }

ArgDecoder::ActivePtr ArgDecoder::Begin(char const* api, bool is64, IThreadView const* t) const
{
    ActivePtr call(new Active);
    call->arch = is64 ? tc::GuestArch::X64 : tc::GuestArch::X86;
    RegisterContext const regs = t->GetCrossPlatformContext(); // by value: bind first (landmine 2)
    tc::CallFrame const frame = FrameOf(call->arch, t, regs);

    win32meta::FuncSig const* sig = win32meta::index().loaded() ? win32meta::index().lookup(api) : nullptr;
    // decodeArgs declines a signature it cannot lay out for this architecture; the heuristic is
    // then better than parameters read from the wrong offsets.
    if (sig && !sig->unsupported() && tc::decodeArgs(*sig, frame, kDecode, call->params, call->pending)) {
        call->metadata = true;
        ++m_stats.withSignature;
        for (size_t i = 0; i < call->params.size(); ++i) {
            tc::DecodedArg const& p = call->params[i];
            if (tc::isPlainStringKind(p.kind) && !p.has_str && !p.is_out && p.raw >= tc::kMinStringAddr)
                call->unread.push_back(static_cast<uint16_t>(i));
        }
        return call;
    }
    call->params.clear();
    call->pending.clear();
    ++m_stats.heuristic;
    tc::MemorySource const src(t);
    if (call->arch == tc::GuestArch::X86) {
        for (uint64_t k = 0; k < 4; ++k) {
            uint32_t v = 0;
            if (ReadThreadLocal(t, uint64_t{ frame.x86->Esp } + 4 + k * 4, v)) call->heuristic.push_back(tc::captureCallArg(src, v));
        }
    } else {
        for (uint64_t v : { frame.x64->Rcx, frame.x64->Rdx, frame.x64->R8, frame.x64->R9 }) call->heuristic.push_back(tc::captureCallArg(src, v));
    }
    return call;
}

std::string ArgDecoder::End(Active& call, IThreadView const* t) const
{
    RegisterContext const regs = t->GetCrossPlatformContext();
    tc::CallFrame const frame = FrameOf(call.arch, t, regs);
    // Strings the entry could not see are usually readable once the callee has touched them.
    // They are [In] values, so they are not marked as read at the return.
    for (uint16_t i : call.unread)
        if (tc::recoverString(tc::MemorySource(t), kDecode, call.params[i], /*accept_truncated=*/false)) ++m_stats.stringsAtReturn;
    if (!call.pending.empty()) tc::resolvePendingOuts(call.pending, frame, kDecode, call.params);
    uint64_t const ret = call.arch == tc::GuestArch::X64 ? frame.x64->Rax : frame.x86->Eax;
    return Render(call, true, ret);
}

std::string ArgDecoder::Abandon(Active& call) const { return Render(call, false, 0); }

std::string ArgDecoder::Render(Active const& call, bool returned, uint64_t ret) const
{
    std::string out = std::format("{{\"sig\":{},\"p\":[", call.metadata ? 1 : 0);
    if (call.metadata) {
        for (size_t i = 0; i < call.params.size(); ++i) {
            tc::DecodedArg const& p = call.params[i];
            if (i) out += ',';
            out += "{\"n\":";
            JsonWriter::EscapeTo(out, p.name ? p.name : "");
            out += ",\"t\":";
            JsonWriter::EscapeTo(out, p.type ? p.type : "");
            out += ",\"v\":";
            Hex(out, p.raw);
            if (p.has_str) {
                out += ",\"s\":";
                JsonWriter::EscapeTo(out, p.str);
                if (p.str_truncated) out += ",\"tr\":1";
            }
            if (p.has_deref) { out += ",\"d\":"; Hex(out, p.deref); }
            if (p.has_fval) out += std::format(",\"f\":{}", p.fval);
            if (p.enum_index != 0xFFFFFFFFu) {
                // For a scalar the enum describes the value; for a pointer, its pointee.
                if (p.kind == ArgKind::Enum) {
                    auto const names = win32meta::index().decodeEnum(p.enum_index, p.raw);
                    if (!names.empty()) Names(out, "fl", names);
                } else if (tc::isPointerKind(p.kind) && p.has_deref) {
                    auto const names = win32meta::index().decodeEnum(p.enum_index, p.deref);
                    if (!names.empty()) Names(out, "dfl", names);
                }
            }
            if (!p.bytes.empty()) {
                out += ",\"b\":\"";
                for (uint8_t b : p.bytes) out += std::format("{:02x}", b);
                out += '"';
            }
            if (p.is_out) out += ",\"o\":1";
            if (p.from_return) out += ",\"r\":1";
            out += '}';
        }
    } else {
        for (size_t i = 0; i < call.heuristic.size(); ++i) {
            if (i) out += ',';
            if (auto const* s = std::get_if<std::string>(&call.heuristic[i])) {
                out += "{\"v\":\"?\",\"s\":";
                JsonWriter::EscapeTo(out, *s);
                out += '}';
            } else {
                out += "{\"v\":";
                Hex(out, static_cast<uint64_t>(std::get<int64_t>(call.heuristic[i])));
                out += '}';
            }
        }
    }
    out += ']';
    if (returned) {
        out += ",\"ret\":";
        Hex(out, call.arch == tc::GuestArch::X64 ? ret : (ret & 0xFFFFFFFFull));
    }
    out += '}';
    return out;
}

std::filesystem::path DefaultWin32IndexPath()
{
    wchar_t buf[MAX_PATH];
    DWORD const n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return std::filesystem::path(std::wstring(buf, n)).parent_path() / L"win32-index.bin";
}

} // namespace ttds
