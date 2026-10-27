#pragma once
#include "model/stack_trie.h"

#include <charconv>
#include <cmath>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ttds {

// Streaming JSON writer producing compact output. Commas are inserted automatically; the caller
// pairs Begin/End calls and writes Key() before each value inside an object. 64-bit addresses are
// written as "0x..." strings (JSON numbers are doubles on the client side).
class JsonWriter
{
public:
    JsonWriter& BeginObject() { return Open('{'); }
    JsonWriter& EndObject() { return Close('}'); }
    JsonWriter& BeginArray() { return Open('['); }
    JsonWriter& EndArray() { return Close(']'); }

    JsonWriter& Key(std::string_view name)
    {
        Separate();
        EscapeTo(m_out, name);
        m_out += ':';
        m_afterKey = true;
        return *this;
    }

    JsonWriter& String(std::string_view s)
    {
        Separate();
        EscapeTo(m_out, s);
        return *this;
    }

    JsonWriter& Bool(bool b)
    {
        Separate();
        m_out += b ? "true" : "false";
        return *this;
    }

    JsonWriter& Null()
    {
        Separate();
        m_out += "null";
        return *this;
    }

    template <typename T>
        requires std::is_arithmetic_v<T> && (!std::is_same_v<T, bool>)
    JsonWriter& Number(T v)
    {
        Separate();
        if constexpr (std::is_floating_point_v<T>) {
            if (!std::isfinite(v)) { m_out += "null"; return *this; }
            char buf[40];
            auto const r = std::to_chars(buf, buf + sizeof buf, v);
            m_out.append(buf, r.ptr);
        } else {
            m_out += std::format("{}", v);
        }
        return *this;
    }

    // "0x..." lowercase, no padding.
    JsonWriter& Hex(uint64_t v)
    {
        Separate();
        m_out += std::format("\"0x{:x}\"", v);
        return *this;
    }

    // A table index: kNone becomes null.
    JsonWriter& Index(uint32_t v) { return v == kNone ? Null() : Number(v); }

    std::string const& Str() const noexcept { return m_out; }

    // Appends s as a quoted, escaped JSON string.
    static void EscapeTo(std::string& out, std::string_view s)
    {
        out += '"';
        for (char const ch : s) {
            auto const c = static_cast<unsigned char>(ch);
            switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (c < 0x20) out += std::format("\\u{:04x}", c);
                else out += ch;
            }
        }
        out += '"';
    }

private:
    JsonWriter& Open(char c)
    {
        Separate();
        m_out += c;
        m_first.push_back(true);
        return *this;
    }

    JsonWriter& Close(char c)
    {
        m_out += c;
        if (!m_first.empty()) m_first.pop_back();
        return *this;
    }

    // Writes the comma owed before a new element; a value right after a key needs none.
    void Separate()
    {
        if (m_afterKey) { m_afterKey = false; return; }
        if (m_first.empty()) return;
        if (m_first.back()) m_first.back() = false;
        else m_out += ',';
    }

    std::string       m_out;
    std::vector<bool> m_first;  // per open container: nothing written yet
    bool              m_afterKey = false;
};

} // namespace ttds
