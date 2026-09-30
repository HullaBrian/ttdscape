#include "serve/json_in.h"

#include <cctype>
#include <charconv>
#include <cmath>

namespace ttds {

class JsonParser
{
public:
    explicit JsonParser(std::string_view s) : m_s(s) {}

    bool Document(JsonValue& out)
    {
        if (!Value(out, 0)) return false;
        Space();
        return m_i == m_s.size();
    }

private:
    static constexpr int kMaxDepth = 32;

    void Space() { while (m_i < m_s.size() && (m_s[m_i] == ' ' || m_s[m_i] == '\t' || m_s[m_i] == '\r' || m_s[m_i] == '\n')) ++m_i; }
    bool Eat(char c) { Space(); if (m_i < m_s.size() && m_s[m_i] == c) { ++m_i; return true; } return false; }
    bool Word(std::string_view w) { if (m_s.substr(m_i, w.size()) != w) return false; m_i += w.size(); return true; }

    bool Value(JsonValue& v, int depth)
    {
        if (depth > kMaxDepth) return false;
        Space();
        if (m_i >= m_s.size()) return false;
        char const c = m_s[m_i];
        if (c == '{') return Object(v, depth);
        if (c == '[') return Array(v, depth);
        if (c == '"') { v.m_type = JsonValue::Type::String; return Str(v.m_string); }
        if (Word("true")) { v.m_type = JsonValue::Type::Bool; v.m_bool = true; return true; }
        if (Word("false")) { v.m_type = JsonValue::Type::Bool; v.m_bool = false; return true; }
        if (Word("null")) { v.m_type = JsonValue::Type::Null; return true; }
        return Num(v);
    }

    bool Object(JsonValue& v, int depth)
    {
        ++m_i;
        v.m_type = JsonValue::Type::Object;
        v.m_members = std::make_shared<std::map<std::string, JsonValue, std::less<>>>();
        if (Eat('}')) return true;
        do {
            Space();
            std::string key;
            if (m_i >= m_s.size() || m_s[m_i] != '"' || !Str(key) || !Eat(':')) return false;
            JsonValue member;
            if (!Value(member, depth + 1)) return false;
            (*v.m_members)[std::move(key)] = std::move(member);
        } while (Eat(','));
        return Eat('}');
    }

    bool Array(JsonValue& v, int depth)
    {
        ++m_i;
        v.m_type = JsonValue::Type::Array;
        if (Eat(']')) return true;
        do {
            JsonValue item;
            if (!Value(item, depth + 1)) return false;
            v.m_items.push_back(std::move(item));
        } while (Eat(','));
        return Eat(']');
    }

    // Strings: escapes are decoded; \u escapes outside ASCII become UTF-8.
    bool Str(std::string& out)
    {
        ++m_i;
        while (m_i < m_s.size()) {
            char const c = m_s[m_i++];
            if (c == '"') return true;
            if (static_cast<unsigned char>(c) < 0x20) return false;
            if (c != '\\') { out += c; continue; }
            if (m_i >= m_s.size()) return false;
            char const e = m_s[m_i++];
            switch (e) {
            case '"': case '\\': case '/': out += e; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                if (m_i + 4 > m_s.size()) return false;
                unsigned cp = 0;
                auto const r = std::from_chars(m_s.data() + m_i, m_s.data() + m_i + 4, cp, 16);
                if (r.ptr != m_s.data() + m_i + 4) return false;
                m_i += 4;
                if (cp < 0x80) out += static_cast<char>(cp);
                else if (cp < 0x800) { out += static_cast<char>(0xC0 | (cp >> 6)); out += static_cast<char>(0x80 | (cp & 0x3F)); }
                else { out += static_cast<char>(0xE0 | (cp >> 12)); out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); out += static_cast<char>(0x80 | (cp & 0x3F)); }
                break;
            }
            default: return false;
            }
        }
        return false;
    }

    bool Num(JsonValue& v)
    {
        size_t const start = m_i;
        while (m_i < m_s.size() && (std::isdigit(static_cast<unsigned char>(m_s[m_i])) || m_s[m_i] == '-' || m_s[m_i] == '+' ||
                                    m_s[m_i] == '.' || m_s[m_i] == 'e' || m_s[m_i] == 'E')) ++m_i;
        if (m_i == start) return false;
        double d = 0;
        auto const r = std::from_chars(m_s.data() + start, m_s.data() + m_i, d);
        if (r.ec != std::errc{} || r.ptr != m_s.data() + m_i || !std::isfinite(d)) return false;
        v.m_type = JsonValue::Type::Number;
        v.m_number = d;
        return true;
    }

    std::string_view m_s;
    size_t           m_i = 0;
};

std::optional<JsonValue> JsonValue::Parse(std::string_view text)
{
    JsonValue v;
    JsonParser p(text);
    if (!p.Document(v)) return std::nullopt;
    return v;
}

JsonValue const& JsonValue::operator[](std::string_view key) const
{
    static JsonValue const null;
    if (m_type != Type::Object || !m_members) return null;
    auto it = m_members->find(key);
    return it == m_members->end() ? null : it->second;
}

bool JsonValue::Has(std::string_view key) const
{
    return m_type == Type::Object && m_members && m_members->find(key) != m_members->end();
}

std::optional<double> JsonValue::Number() const
{
    if (m_type != Type::Number) return std::nullopt;
    return m_number;
}

std::optional<std::string> JsonValue::String() const
{
    if (m_type != Type::String) return std::nullopt;
    return m_string;
}

std::optional<bool> JsonValue::Bool() const
{
    if (m_type != Type::Bool) return std::nullopt;
    return m_bool;
}

std::optional<uint64_t> JsonValue::Address() const
{
    if (m_type == Type::Number) {
        if (m_number < 0 || m_number > 9007199254740992.0 || std::floor(m_number) != m_number) return std::nullopt;
        return static_cast<uint64_t>(m_number);
    }
    if (m_type != Type::String || m_string.empty()) return std::nullopt;
    std::string_view s = m_string;
    int base = 10;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { s.remove_prefix(2); base = 16; }
    uint64_t v = 0;
    auto const r = std::from_chars(s.data(), s.data() + s.size(), v, base);
    if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) return std::nullopt;
    return v;
}

} // namespace ttds
