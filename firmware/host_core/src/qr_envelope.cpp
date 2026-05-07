#include "nostrseal/qr_envelope.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

namespace nostrseal {
namespace {

constexpr const char* kPrefix = "nseal1:";
constexpr char kInvalidBase64 = static_cast<char>(-1);

bool is_base64url_payload(const std::string& value) {
    if (value.empty()) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' ||
               ch == '-';
    });
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

std::string decode_base64url(std::string_view payload) {
    static const std::array<char, 256> table = base64url_decode_table();
    std::uint32_t accumulator = 0;
    int bits = 0;
    std::vector<char> decoded;
    decoded.reserve((payload.size() * 3U) / 4U);

    for (const unsigned char ch : payload) {
        const char value = table[ch];
        if (value == kInvalidBase64) {
            throw QrEnvelopeError("QR envelope payload must be unpadded base64url");
        }
        accumulator = (accumulator << 6U) | static_cast<unsigned char>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(static_cast<char>((accumulator >> static_cast<unsigned>(bits)) & 0xffU));
        }
    }
    if (bits > 0 && ((accumulator << static_cast<unsigned>(8 - bits)) & 0xffU) != 0U) {
        throw QrEnvelopeError("QR envelope payload has invalid trailing bits");
    }
    return std::string(decoded.begin(), decoded.end());
}

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

void require_json_container(const std::string& decoded) {
    const std::string trimmed = trim_ascii(decoded);
    if (trimmed.size() < 2) {
        throw QrEnvelopeError("QR envelope payload is not valid JSON");
    }
    const char first = trimmed.front();
    const char last = trimmed.back();
    if (!((first == '{' && last == '}') || (first == '[' && last == ']'))) {
        throw QrEnvelopeError("QR envelope payload is not valid JSON");
    }
}

}  // namespace

QrEnvelope decode_qr_envelope(const std::string& envelope) {
    if (envelope.rfind(kPrefix, 0) != 0) {
        throw QrEnvelopeError("QR envelope must start with nseal1:");
    }
    const std::string payload = envelope.substr(std::string(kPrefix).size());
    if (!is_base64url_payload(payload)) {
        throw QrEnvelopeError("QR envelope payload must be unpadded base64url");
    }
    if ((payload.size() % 4U) == 1U) {
        throw QrEnvelopeError("QR envelope payload has invalid base64url length");
    }
    const std::string decoded = decode_base64url(payload);
    require_json_container(decoded);
    return QrEnvelope{payload, decoded};
}

}  // namespace nostrseal
