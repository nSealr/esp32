#include "nostrseal/device_protocol.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

#include "nostrseal/limits.hpp"
#include "nostrseal/qr_envelope.hpp"
#include "nostrseal/serial_frame.hpp"
#include "nostrseal/serial_review.hpp"

namespace nostrseal {
namespace {

constexpr char kInvalidBase64 = static_cast<char>(-1);

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
            throw SerialFrameError("serial frame payload must be unpadded base64url");
        }
        accumulator = (accumulator << 6U) | static_cast<unsigned char>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(static_cast<char>((accumulator >> static_cast<unsigned>(bits)) & 0xffU));
        }
    }
    if (bits > 0 && ((accumulator << static_cast<unsigned>(8 - bits)) & 0xffU) != 0U) {
        throw SerialFrameError("serial frame payload has invalid trailing bits");
    }
    return std::string(decoded.begin(), decoded.end());
}

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

void skip_ws(const std::string& json, std::size_t& offset) {
    while (offset < json.size()) {
        const char ch = json[offset];
        if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
            return;
        }
        ++offset;
    }
}

std::string parse_json_string(const std::string& json, std::size_t& offset) {
    if (offset >= json.size() || json[offset] != '"') {
        throw SerialFrameError("request JSON string is required");
    }
    ++offset;
    std::string value;
    while (offset < json.size()) {
        const char ch = json[offset++];
        if (ch == '"') {
            return value;
        }
        if (ch == '\\') {
            if (offset >= json.size()) {
                throw SerialFrameError("request JSON string escape is truncated");
            }
            const char escaped = json[offset++];
            switch (escaped) {
                case '"':
                case '\\':
                case '/':
                    value.push_back(escaped);
                    break;
                case 'b':
                    value.push_back('\b');
                    break;
                case 'f':
                    value.push_back('\f');
                    break;
                case 'n':
                    value.push_back('\n');
                    break;
                case 'r':
                    value.push_back('\r');
                    break;
                case 't':
                    value.push_back('\t');
                    break;
                case 'u':
                    if (offset + 4U > json.size()) {
                        throw SerialFrameError("request JSON unicode escape is truncated");
                    }
                    offset += 4U;
                    value.push_back('?');
                    break;
                default:
                    throw SerialFrameError("request JSON string escape is invalid");
            }
        } else {
            value.push_back(ch);
        }
    }
    throw SerialFrameError("request JSON string is unterminated");
}

void skip_json_value(const std::string& json, std::size_t& offset) {
    skip_ws(json, offset);
    if (offset >= json.size()) {
        throw SerialFrameError("request JSON value is required");
    }
    if (json[offset] == '"') {
        (void)parse_json_string(json, offset);
        return;
    }
    if (json[offset] == '{') {
        ++offset;
        while (true) {
            skip_ws(json, offset);
            if (offset >= json.size()) {
                throw SerialFrameError("request JSON container is unterminated");
            }
            if (json[offset] == '}') {
                ++offset;
                return;
            }
            (void)parse_json_string(json, offset);
            skip_ws(json, offset);
            if (offset >= json.size() || json[offset++] != ':') {
                throw SerialFrameError("request JSON object is malformed");
            }
            skip_json_value(json, offset);
            skip_ws(json, offset);
            if (offset < json.size() && json[offset] == ',') {
                ++offset;
                continue;
            }
            if (offset < json.size() && json[offset] == '}') {
                ++offset;
                return;
            }
            throw SerialFrameError("request JSON object is malformed");
        }
    }
    if (json[offset] == '[') {
        ++offset;
        while (true) {
            skip_ws(json, offset);
            if (offset >= json.size()) {
                throw SerialFrameError("request JSON container is unterminated");
            }
            if (json[offset] == ']') {
                ++offset;
                return;
            }
            skip_json_value(json, offset);
            skip_ws(json, offset);
            if (offset < json.size() && json[offset] == ',') {
                ++offset;
                continue;
            }
            if (offset < json.size() && json[offset] == ']') {
                ++offset;
                return;
            }
            throw SerialFrameError("request JSON array is malformed");
        }
    }
    while (offset < json.size()) {
        const char ch = json[offset];
        if (ch == ',' || ch == '}' || ch == ']' || ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
            return;
        }
        ++offset;
    }
}

struct RequestMetadata {
    bool version_one = false;
    bool has_unknown_top_level_field = false;
    bool has_params = false;
    std::string request_id;
    std::string method;
};

RequestMetadata parse_request_metadata(const std::string& json) {
    std::size_t offset = 0;
    skip_ws(json, offset);
    if (offset >= json.size() || json[offset++] != '{') {
        throw SerialFrameError("request JSON object is required");
    }

    RequestMetadata metadata;
    while (true) {
        skip_ws(json, offset);
        if (offset >= json.size()) {
            throw SerialFrameError("request JSON object is unterminated");
        }
        if (json[offset] == '}') {
            ++offset;
            break;
        }
        const std::string key = parse_json_string(json, offset);
        skip_ws(json, offset);
        if (offset >= json.size() || json[offset++] != ':') {
            throw SerialFrameError("request JSON object is malformed");
        }
        skip_ws(json, offset);
        if (key == "request_id") {
            metadata.request_id = parse_json_string(json, offset);
        } else if (key == "method") {
            metadata.method = parse_json_string(json, offset);
        } else if (key == "version") {
            const std::size_t token_start = offset;
            skip_json_value(json, offset);
            metadata.version_one = json.substr(token_start, offset - token_start) == "1";
        } else if (key == "params") {
            metadata.has_params = true;
            skip_json_value(json, offset);
        } else {
            metadata.has_unknown_top_level_field = true;
            skip_json_value(json, offset);
        }
        skip_ws(json, offset);
        if (offset < json.size() && json[offset] == ',') {
            ++offset;
        }
    }
    return metadata;
}

bool is_request_id(const std::string& value) {
    if (value.empty() || value.size() > kMaxRequestIdLength) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' ||
               ch == '_' || ch == ':' || ch == '-';
    });
}

SerialFrame response_frame(const std::string& response_json) {
    return SerialFrame{FrameType::Response, encode_base64url(response_json)};
}

SerialFrame unsupported_request_frame() {
    return SerialFrame{FrameType::Error, "eyJlcnJvciI6InVuc3VwcG9ydGVkX3JlcXVlc3QifQ"};
}

std::string capability_response_json(const std::string& request_id) {
    return std::string(R"({"version":1,"request_id":")") + request_id +
           R"(","ok":true,"result":{"capabilities":{"device":{"name":"NostrSeal ESP32-S3 USB Signer Scaffold","firmware":"nostrseal-esp32-s3-usb-signer","hardware":"esp32-s3-devkitc-1"},"protocols":["nseal.signing.v0","nseal.serial-frame.v0"],"methods":["get_capabilities","get_public_key","sign_event"],"transports":["usb-serial-jtag"],"signing_enabled":false,"requires_physical_approval":true}}})";
}

std::string public_key_response_json(const std::string& request_id) {
    return std::string(R"({"version":1,"request_id":")") + request_id +
           R"(","ok":true,"result":{"public_key":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"}})";
}

std::string signing_disabled_response_json(const std::string& request_id) {
    return std::string(R"({"version":1,"request_id":")") + request_id +
           R"(","ok":false,"error":{"code":"signing_disabled","message":"Signing is disabled until trusted review and physical approval are implemented.","retryable":false}})";
}

}  // namespace

std::string handle_serial_frame(const std::string& line) {
    return handle_serial_frame_with_review_preview(line).response_frame;
}

SerialFrameHandlingResult handle_serial_frame_with_review_preview(
    const std::string& line,
    ReviewDisplayLimits limits) {
    const SerialFrame request = decode_serial_frame(line);
    if (request.type != FrameType::Request) {
        return SerialFrameHandlingResult{encode_serial_frame(unsupported_request_frame()), std::nullopt};
    }

    const std::string request_json = decode_base64url(request.payload_base64url);
    if (request_json.size() > kMaxDecodedRequestJsonBytes) {
        return SerialFrameHandlingResult{encode_serial_frame(unsupported_request_frame()), std::nullopt};
    }
    const RequestMetadata metadata = parse_request_metadata(request_json);
    if (!metadata.version_one || !is_request_id(metadata.request_id) || metadata.has_unknown_top_level_field) {
        return SerialFrameHandlingResult{encode_serial_frame(unsupported_request_frame()), std::nullopt};
    }
    if (metadata.method == "get_capabilities") {
        if (metadata.has_params) {
            return SerialFrameHandlingResult{encode_serial_frame(unsupported_request_frame()), std::nullopt};
        }
        return SerialFrameHandlingResult{
            encode_serial_frame(response_frame(capability_response_json(metadata.request_id))),
            std::nullopt};
    }
    if (metadata.method == "get_public_key") {
        if (metadata.has_params) {
            return SerialFrameHandlingResult{encode_serial_frame(unsupported_request_frame()), std::nullopt};
        }
        return SerialFrameHandlingResult{
            encode_serial_frame(response_frame(public_key_response_json(metadata.request_id))),
            std::nullopt};
    }
    if (metadata.method == "sign_event") {
        std::optional<ReviewDisplayFrame> review_frame;
        std::optional<TrustedReviewSession> review_session;
        try {
            TrustedReviewSession session = begin_serial_sign_event_trusted_review(request_json, limits);
            review_frame = session.current_frame();
            review_session = std::move(session);
        } catch (const QrEnvelopeError&) {
            return SerialFrameHandlingResult{encode_serial_frame(unsupported_request_frame()), std::nullopt};
        }
        return SerialFrameHandlingResult{
            encode_serial_frame(response_frame(signing_disabled_response_json(metadata.request_id))),
            std::move(review_frame),
            std::move(review_session)};
    }
    return SerialFrameHandlingResult{encode_serial_frame(unsupported_request_frame()), std::nullopt};
}

}  // namespace nostrseal
