#include "nsealr/base64url.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

namespace nsealr {
namespace {

constexpr char kInvalidBase64 = static_cast<char>(-1);

std::array<char, 64> base64url_encode_alphabet() {
    return {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '-', '_',
    };
}

std::array<char, 256> base64url_decode_table() {
    std::array<char, 256> table{};
    table.fill(kInvalidBase64);
    for (int index = 0; index < 26; ++index) {
        table[static_cast<std::size_t>('A' + index)] = static_cast<char>(index);
        table[static_cast<std::size_t>('a' + index)] = static_cast<char>(26 + index);
    }
    for (int index = 0; index < 10; ++index) {
        table[static_cast<std::size_t>('0' + index)] = static_cast<char>(52 + index);
    }
    table[static_cast<std::size_t>('-')] = 62;
    table[static_cast<std::size_t>('_')] = 63;
    return table;
}

}  // namespace

Base64UrlError::Base64UrlError(Base64UrlErrorCode code, const char* message)
    : std::runtime_error(message), code_(code) {}

Base64UrlErrorCode Base64UrlError::code() const noexcept {
    return code_;
}

bool is_base64url_payload(std::string_view value) {
    if (value.empty()) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' ||
               ch == '-';
    });
}

std::string encode_base64url(std::string_view value) {
    static const std::array<char, 64> alphabet = base64url_encode_alphabet();
    std::string encoded;
    int accumulator = 0;
    int bits = 0;
    for (const unsigned char ch : value) {
        accumulator = (accumulator << 8) | ch;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            encoded.push_back(alphabet[static_cast<std::size_t>((accumulator >> bits) & 0x3f)]);
        }
    }
    if (bits > 0) {
        encoded.push_back(alphabet[static_cast<std::size_t>((accumulator << (6 - bits)) & 0x3f)]);
    }
    return encoded;
}

std::string decode_base64url(std::string_view payload) {
    static const std::array<char, 256> table = base64url_decode_table();
    std::uint32_t accumulator = 0;
    int bits = 0;
    std::vector<char> decoded;
    decoded.reserve((payload.size() * 3U) / 4U);

    for (const unsigned char ch : payload) {
        const char value = table[ch];
        if (value == kInvalidBase64) {
            throw Base64UrlError(Base64UrlErrorCode::InvalidCharacter, "invalid base64url character");
        }
        accumulator = (accumulator << 6U) | static_cast<unsigned char>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(static_cast<char>((accumulator >> static_cast<unsigned>(bits)) & 0xffU));
        }
    }
    if (bits > 0 && ((accumulator << static_cast<unsigned>(8 - bits)) & 0xffU) != 0U) {
        throw Base64UrlError(Base64UrlErrorCode::InvalidTrailingBits, "invalid base64url trailing bits");
    }
    return std::string(decoded.begin(), decoded.end());
}

}  // namespace nsealr
