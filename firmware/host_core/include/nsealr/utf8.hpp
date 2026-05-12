#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace nsealr {

constexpr std::uint32_t kReplacementCodepoint = 0xfffdU;

inline bool is_valid_unicode_scalar(std::uint32_t codepoint) {
    return codepoint <= 0x10ffffU && !(codepoint >= 0xd800U && codepoint <= 0xdfffU);
}

inline bool append_utf8_codepoint(std::string& out, std::uint32_t codepoint) {
    if (!is_valid_unicode_scalar(codepoint)) {
        return false;
    }
    if (codepoint <= 0x7fU) {
        out.push_back(static_cast<char>(codepoint));
        return true;
    }
    if (codepoint <= 0x7ffU) {
        out.push_back(static_cast<char>(0xc0U | (codepoint >> 6U)));
        out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        return true;
    }
    if (codepoint <= 0xffffU) {
        out.push_back(static_cast<char>(0xe0U | (codepoint >> 12U)));
        out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
        return true;
    }
    out.push_back(static_cast<char>(0xf0U | (codepoint >> 18U)));
    out.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
    out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
    out.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    return true;
}

inline bool decode_next_utf8_codepoint(std::string_view text, std::size_t& offset, std::uint32_t& codepoint) {
    if (offset >= text.size()) {
        return false;
    }

    const std::size_t start = offset;
    const auto first = static_cast<unsigned char>(text[offset++]);
    if (first <= 0x7fU) {
        codepoint = first;
        return true;
    }

    std::size_t continuations = 0;
    std::uint32_t value = 0;
    std::uint32_t minimum = 0;
    if (first >= 0xc2U && first <= 0xdfU) {
        continuations = 1;
        value = first & 0x1fU;
        minimum = 0x80U;
    } else if (first >= 0xe0U && first <= 0xefU) {
        continuations = 2;
        value = first & 0x0fU;
        minimum = 0x800U;
    } else if (first >= 0xf0U && first <= 0xf4U) {
        continuations = 3;
        value = first & 0x07U;
        minimum = 0x10000U;
    } else {
        codepoint = kReplacementCodepoint;
        offset = start + 1U;
        return false;
    }

    if (offset + continuations > text.size()) {
        codepoint = kReplacementCodepoint;
        offset = text.size();
        return false;
    }
    for (std::size_t index = 0; index < continuations; ++index) {
        const auto continuation = static_cast<unsigned char>(text[offset++]);
        if ((continuation & 0xc0U) != 0x80U) {
            codepoint = kReplacementCodepoint;
            return false;
        }
        value = (value << 6U) | (continuation & 0x3fU);
    }

    if (value < minimum || !is_valid_unicode_scalar(value)) {
        codepoint = kReplacementCodepoint;
        return false;
    }
    codepoint = value;
    return true;
}

inline bool is_valid_utf8(std::string_view value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        std::uint32_t codepoint = 0;
        if (!decode_next_utf8_codepoint(value, offset, codepoint)) {
            return false;
        }
    }
    return true;
}

}  // namespace nsealr
