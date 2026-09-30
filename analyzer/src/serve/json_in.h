#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ttds {

// Minimal JSON reader for the `serve` protocol's requests (one small object per line). Numbers are
// kept as doubles; 64-bit addresses travel as "0x..." strings (see JsonValue::Address).
class JsonValue
{
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    // Parses a complete document; nullopt on any syntax error or trailing garbage.
    static std::optional<JsonValue> Parse(std::string_view text);

    Type GetType() const noexcept { return m_type; }
    bool IsNull() const noexcept { return m_type == Type::Null; }

    // Member of an object (a shared Null value when missing or not an object).
    JsonValue const& operator[](std::string_view key) const;
    bool Has(std::string_view key) const;

    std::optional<double>      Number() const;
    std::optional<std::string> String() const;
    std::optional<bool>        Bool() const;
    // An unsigned 64-bit value from a "0x..." or decimal string, or from a non-negative integral number.
    std::optional<uint64_t>    Address() const;
    std::vector<JsonValue> const& Items() const noexcept { return m_items; }

private:
    friend class JsonParser;
    Type                                                  m_type = Type::Null;
    bool                                                  m_bool = false;
    double                                                m_number = 0;
    std::string                                           m_string;
    std::vector<JsonValue>                                m_items;
    std::shared_ptr<std::map<std::string, JsonValue, std::less<>>> m_members;
};

} // namespace ttds
