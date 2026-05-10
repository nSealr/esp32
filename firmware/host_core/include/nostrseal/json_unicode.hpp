#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "nostrseal/utf8.hpp"

namespace nostrseal {

inline int json_hex_value(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

template <typename Error>
std::uint32_t parse_json_unicode_code_unit(
    std::string_view json,
    std::size_t& offset,
    const std::string& truncated_message,
    const std::string& invalid_message) {
    if (offset + 4U > json.size()) {
        throw Error(truncated_message);
    }
    std::uint32_t code_unit = 0;
    for (int index = 0; index < 4; ++index) {
        const int nibble = json_hex_value(json[offset++]);
        if (nibble < 0) {
            throw Error(invalid_message);
        }
        code_unit = (code_unit << 4U) | static_cast<std::uint32_t>(nibble);
    }
    return code_unit;
}

template <typename Error>
void append_json_unicode_escape(
    std::string& out,
    std::string_view json,
    std::size_t& offset,
    const std::string& truncated_message,
    const std::string& invalid_message) {
    std::uint32_t codepoint =
        parse_json_unicode_code_unit<Error>(json, offset, truncated_message, invalid_message);

    if (codepoint >= 0xd800U && codepoint <= 0xdbffU) {
        if (offset + 2U > json.size() || json[offset] != '\\' || json[offset + 1U] != 'u') {
            throw Error(invalid_message);
        }
        offset += 2U;
        const std::uint32_t low =
            parse_json_unicode_code_unit<Error>(json, offset, truncated_message, invalid_message);
        if (low < 0xdc00U || low > 0xdfffU) {
            throw Error(invalid_message);
        }
        codepoint = 0x10000U + (((codepoint - 0xd800U) << 10U) | (low - 0xdc00U));
    } else if (codepoint >= 0xdc00U && codepoint <= 0xdfffU) {
        throw Error(invalid_message);
    }

    if (!append_utf8_codepoint(out, codepoint)) {
        throw Error(invalid_message);
    }
}

}  // namespace nostrseal
