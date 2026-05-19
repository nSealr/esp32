#include "nsealr/nip19_nsec.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace nsealr {
namespace {

constexpr std::string_view kBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr NsecSecretKey kSecp256k1Order{
    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xfeU,
    0xbaU, 0xaeU, 0xdcU, 0xe6U, 0xafU, 0x48U, 0xa0U, 0x3bU,
    0xbfU, 0xd2U, 0x5eU, 0x8cU, 0xd0U, 0x36U, 0x41U, 0x41U,
};

std::string trim_ascii(const std::string& value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
        return ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t';
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
                          return ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t';
                      }).base();
    if (first >= last) {
        return "";
    }
    return std::string(first, last);
}

int bech32_value(char ch) {
    const std::size_t index = kBech32Charset.find(ch);
    if (index == std::string_view::npos) {
        return -1;
    }
    return static_cast<int>(index);
}

std::uint32_t bech32_polymod(const std::vector<int>& values) {
    constexpr std::array<std::uint32_t, 5> generators{
        0x3B6A57B2U,
        0x26508E6DU,
        0x1EA119FAU,
        0x3D4233DDU,
        0x2A1462B3U,
    };
    std::uint32_t checksum = 1;
    for (const int value : values) {
        const std::uint32_t top = checksum >> 25U;
        checksum = ((checksum & 0x1FFFFFFU) << 5U) ^ static_cast<std::uint32_t>(value);
        for (std::size_t index = 0; index < generators.size(); ++index) {
            if (((top >> index) & 1U) != 0U) {
                checksum ^= generators[index];
            }
        }
    }
    return checksum;
}

std::vector<int> bech32_hrp_expand(const std::string& hrp) {
    std::vector<int> expanded;
    expanded.reserve((hrp.size() * 2U) + 1U);
    for (const unsigned char ch : hrp) {
        expanded.push_back(static_cast<int>(ch >> 5U));
    }
    expanded.push_back(0);
    for (const unsigned char ch : hrp) {
        expanded.push_back(static_cast<int>(ch & 31U));
    }
    return expanded;
}

struct Bech32Payload {
    std::string hrp;
    std::vector<int> words;
};

Bech32Payload decode_lower_bech32(const std::string& value) {
    const std::string candidate = trim_ascii(value);
    const bool has_uppercase = std::any_of(candidate.begin(), candidate.end(), [](unsigned char ch) {
        return ch >= 'A' && ch <= 'Z';
    });
    if (candidate != value || has_uppercase) {
        throw NsecDecodeError("nsec must be canonical lowercase bech32");
    }
    const std::size_t separator = candidate.rfind('1');
    if (separator == std::string::npos || separator == 0 || separator + 7U > candidate.size()) {
        throw NsecDecodeError("nsec bech32 payload is malformed");
    }
    const std::string hrp = candidate.substr(0, separator);
    const std::string payload = candidate.substr(separator + 1U);
    std::vector<int> data;
    data.reserve(payload.size());
    for (const char ch : payload) {
        const int value_index = bech32_value(ch);
        if (value_index < 0) {
            throw NsecDecodeError("nsec bech32 payload contains unsupported characters");
        }
        data.push_back(value_index);
    }
    std::vector<int> checksum_values = bech32_hrp_expand(hrp);
    checksum_values.insert(checksum_values.end(), data.begin(), data.end());
    if (bech32_polymod(checksum_values) != 1U) {
        throw NsecDecodeError("nsec bech32 checksum is invalid");
    }
    data.resize(data.size() - 6U);
    return Bech32Payload{hrp, data};
}

std::vector<std::uint8_t> convert_5bit_words_to_bytes(const std::vector<int>& words) {
    std::uint32_t accumulator = 0;
    int bit_count = 0;
    std::vector<std::uint8_t> out;
    out.reserve((words.size() * 5U) / 8U);
    for (const int word : words) {
        if (word < 0 || word > 31) {
            throw NsecDecodeError("nsec bech32 word is out of range");
        }
        accumulator = (accumulator << 5U) | static_cast<std::uint32_t>(word);
        bit_count += 5;
        while (bit_count >= 8) {
            bit_count -= 8;
            out.push_back(static_cast<std::uint8_t>((accumulator >> static_cast<unsigned>(bit_count)) & 0xffU));
        }
        if (bit_count > 0) {
            accumulator &= (1U << static_cast<unsigned>(bit_count)) - 1U;
        } else {
            accumulator = 0;
        }
    }
    if (bit_count >= 5 || ((accumulator << static_cast<unsigned>(8 - bit_count)) & 0xffU) != 0U) {
        throw NsecDecodeError("nsec bech32 payload has invalid padding");
    }
    return out;
}

std::vector<int> convert_bytes_to_5bit_words(const NsecSecretKey& secret_key) {
    std::uint32_t accumulator = 0;
    int bit_count = 0;
    std::vector<int> out;
    out.reserve((secret_key.size() * 8U + 4U) / 5U);
    for (const std::uint8_t byte : secret_key) {
        accumulator = (accumulator << 8U) | byte;
        bit_count += 8;
        while (bit_count >= 5) {
            bit_count -= 5;
            out.push_back(static_cast<int>((accumulator >> static_cast<unsigned>(bit_count)) & 31U));
        }
        if (bit_count > 0) {
            accumulator &= (1U << static_cast<unsigned>(bit_count)) - 1U;
        } else {
            accumulator = 0;
        }
    }
    if (bit_count > 0) {
        out.push_back(static_cast<int>((accumulator << static_cast<unsigned>(5 - bit_count)) & 31U));
    }
    return out;
}

std::vector<int> bech32_checksum(const std::string& hrp, const std::vector<int>& words) {
    std::vector<int> values = bech32_hrp_expand(hrp);
    values.insert(values.end(), words.begin(), words.end());
    values.insert(values.end(), 6U, 0);
    const std::uint32_t polymod = bech32_polymod(values) ^ 1U;
    std::vector<int> checksum;
    checksum.reserve(6U);
    for (std::size_t index = 0; index < 6U; ++index) {
        checksum.push_back(static_cast<int>((polymod >> static_cast<unsigned>(5U * (5U - index))) & 31U));
    }
    return checksum;
}

char lowercase_hex_nibble(std::uint8_t value) {
    return static_cast<char>(value < 10U ? ('0' + value) : ('a' + (value - 10U)));
}

}  // namespace

bool is_valid_nsec_secret_key(const NsecSecretKey& secret_key) {
    const bool all_zero = std::all_of(secret_key.begin(), secret_key.end(), [](std::uint8_t byte) {
        return byte == 0U;
    });
    if (all_zero) {
        return false;
    }
    return std::lexicographical_compare(secret_key.begin(), secret_key.end(), kSecp256k1Order.begin(), kSecp256k1Order.end());
}

NsecSecretKey decode_nsec_secret_key(const std::string& nsec) {
    const Bech32Payload decoded = decode_lower_bech32(nsec);
    if (decoded.hrp != "nsec") {
        throw NsecDecodeError("nsec bech32 prefix must be nsec");
    }
    const std::vector<std::uint8_t> secret = convert_5bit_words_to_bytes(decoded.words);
    if (secret.size() != 32U) {
        throw NsecDecodeError("nsec payload must decode to a 32-byte secret key");
    }
    NsecSecretKey out{};
    std::copy(secret.begin(), secret.end(), out.begin());
    if (!is_valid_nsec_secret_key(out)) {
        throw NsecDecodeError("nsec payload must be a valid secp256k1 scalar");
    }
    return out;
}

std::string decode_nsec_secret_key_hex(const std::string& nsec) {
    const NsecSecretKey secret = decode_nsec_secret_key(nsec);
    std::string out;
    out.reserve(secret.size() * 2U);
    for (const std::uint8_t byte : secret) {
        out.push_back(lowercase_hex_nibble(static_cast<std::uint8_t>(byte >> 4U)));
        out.push_back(lowercase_hex_nibble(static_cast<std::uint8_t>(byte & 0x0fU)));
    }
    return out;
}

std::string encode_nsec_secret_key(const NsecSecretKey& secret_key) {
    if (!is_valid_nsec_secret_key(secret_key)) {
        throw NsecDecodeError("nsec secret key must be a valid secp256k1 scalar");
    }
    std::vector<int> words = convert_bytes_to_5bit_words(secret_key);
    const std::vector<int> checksum = bech32_checksum("nsec", words);
    words.insert(words.end(), checksum.begin(), checksum.end());
    std::string out = "nsec1";
    out.reserve(5U + words.size());
    for (const int word : words) {
        out.push_back(kBech32Charset[static_cast<std::size_t>(word)]);
    }
    return out;
}

}  // namespace nsealr
