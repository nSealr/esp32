#include "nsealr/qr_response_display.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include "nsealr/qr_envelope.hpp"

namespace nsealr {
namespace {

struct ResponseJsonMetadata {
    bool version_one = false;
    bool ok_seen = false;
    bool ok = false;
    bool has_result = false;
    bool result_is_object = false;
    bool has_error = false;
    bool error_is_object = false;
    bool has_unknown_top_level_field = false;
    std::string request_id;
};

void skip_ws(const std::string& json, std::size_t& offset) {
    while (offset < json.size()) {
        const char ch = json[offset];
        if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
            return;
        }
        ++offset;
    }
}

bool is_hex_digit(char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

bool is_digit(char ch) {
    return ch >= '0' && ch <= '9';
}

bool is_valid_json_number_token(const std::string& token) {
    std::size_t offset = 0;
    if (offset < token.size() && token[offset] == '-') {
        ++offset;
    }
    if (offset >= token.size()) {
        return false;
    }
    if (token[offset] == '0') {
        ++offset;
    } else if (token[offset] >= '1' && token[offset] <= '9') {
        while (offset < token.size() && is_digit(token[offset])) {
            ++offset;
        }
    } else {
        return false;
    }
    if (offset < token.size() && token[offset] == '.') {
        ++offset;
        const std::size_t fraction_start = offset;
        while (offset < token.size() && is_digit(token[offset])) {
            ++offset;
        }
        if (offset == fraction_start) {
            return false;
        }
    }
    if (offset < token.size() && (token[offset] == 'e' || token[offset] == 'E')) {
        ++offset;
        if (offset < token.size() && (token[offset] == '+' || token[offset] == '-')) {
            ++offset;
        }
        const std::size_t exponent_start = offset;
        while (offset < token.size() && is_digit(token[offset])) {
            ++offset;
        }
        if (offset == exponent_start) {
            return false;
        }
    }
    return offset == token.size();
}

std::string parse_json_string(const std::string& json, std::size_t& offset) {
    if (offset >= json.size() || json[offset] != '"') {
        throw std::invalid_argument("QR response display response JSON string is required");
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
                throw std::invalid_argument("QR response display response JSON string escape is truncated");
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
                    if (offset + 4U > json.size() || !is_hex_digit(json[offset]) || !is_hex_digit(json[offset + 1U]) ||
                        !is_hex_digit(json[offset + 2U]) || !is_hex_digit(json[offset + 3U])) {
                        throw std::invalid_argument("QR response display response JSON unicode escape is invalid");
                    }
                    offset += 4U;
                    value.push_back('?');
                    break;
                default:
                    throw std::invalid_argument("QR response display response JSON string escape is unsupported");
            }
            continue;
        }
        if (static_cast<unsigned char>(ch) < 0x20U) {
            throw std::invalid_argument("QR response display response JSON string contains control character");
        }
        value.push_back(ch);
    }
    throw std::invalid_argument("QR response display response JSON string is unterminated");
}

void skip_json_value(const std::string& json, std::size_t& offset);

void skip_json_object(const std::string& json, std::size_t& offset) {
    if (offset >= json.size() || json[offset] != '{') {
        throw std::invalid_argument("QR response display response JSON object is required");
    }
    ++offset;
    skip_ws(json, offset);
    if (offset < json.size() && json[offset] == '}') {
        ++offset;
        return;
    }
    while (offset < json.size()) {
        (void)parse_json_string(json, offset);
        skip_ws(json, offset);
        if (offset >= json.size() || json[offset] != ':') {
            throw std::invalid_argument("QR response display response JSON object is malformed");
        }
        ++offset;
        skip_json_value(json, offset);
        skip_ws(json, offset);
        if (offset < json.size() && json[offset] == ',') {
            ++offset;
            skip_ws(json, offset);
            continue;
        }
        if (offset < json.size() && json[offset] == '}') {
            ++offset;
            return;
        }
        throw std::invalid_argument("QR response display response JSON object is malformed");
    }
    throw std::invalid_argument("QR response display response JSON object is unterminated");
}

void skip_json_array(const std::string& json, std::size_t& offset) {
    if (offset >= json.size() || json[offset] != '[') {
        throw std::invalid_argument("QR response display response JSON array is required");
    }
    ++offset;
    skip_ws(json, offset);
    if (offset < json.size() && json[offset] == ']') {
        ++offset;
        return;
    }
    while (offset < json.size()) {
        skip_json_value(json, offset);
        skip_ws(json, offset);
        if (offset < json.size() && json[offset] == ',') {
            ++offset;
            skip_ws(json, offset);
            continue;
        }
        if (offset < json.size() && json[offset] == ']') {
            ++offset;
            return;
        }
        throw std::invalid_argument("QR response display response JSON array is malformed");
    }
    throw std::invalid_argument("QR response display response JSON array is unterminated");
}

void skip_json_scalar(const std::string& json, std::size_t& offset) {
    const std::size_t start = offset;
    while (offset < json.size()) {
        const char ch = json[offset];
        if (ch == ',' || ch == '}' || ch == ']' || ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
            break;
        }
        ++offset;
    }
    if (offset == start) {
        throw std::invalid_argument("QR response display response JSON value is required");
    }
    const std::string token = json.substr(start, offset - start);
    if (token != "true" && token != "false" && token != "null" && !is_valid_json_number_token(token)) {
        throw std::invalid_argument("QR response display response JSON scalar is invalid");
    }
}

void skip_json_value(const std::string& json, std::size_t& offset) {
    skip_ws(json, offset);
    if (offset >= json.size()) {
        throw std::invalid_argument("QR response display response JSON value is required");
    }
    if (json[offset] == '"') {
        (void)parse_json_string(json, offset);
        return;
    }
    if (json[offset] == '{') {
        skip_json_object(json, offset);
        return;
    }
    if (json[offset] == '[') {
        skip_json_array(json, offset);
        return;
    }
    skip_json_scalar(json, offset);
}

bool parse_json_boolean(const std::string& json, std::size_t& offset, bool& output) {
    if (json.compare(offset, 4U, "true") == 0) {
        offset += 4U;
        output = true;
        return true;
    }
    if (json.compare(offset, 5U, "false") == 0) {
        offset += 5U;
        output = false;
        return true;
    }
    skip_json_value(json, offset);
    return false;
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

ResponseJsonMetadata parse_response_json_metadata(const std::string& json) {
    std::size_t offset = 0;
    skip_ws(json, offset);
    if (offset >= json.size() || json[offset] != '{') {
        throw std::invalid_argument("QR response display response must be a JSON object");
    }
    ++offset;
    ResponseJsonMetadata metadata;
    skip_ws(json, offset);
    if (offset < json.size() && json[offset] == '}') {
        ++offset;
    } else {
        while (offset < json.size()) {
            const std::string key = parse_json_string(json, offset);
            skip_ws(json, offset);
            if (offset >= json.size() || json[offset] != ':') {
                throw std::invalid_argument("QR response display response JSON object is malformed");
            }
            ++offset;
            skip_ws(json, offset);
            if (key == "version") {
                const std::size_t start = offset;
                skip_json_value(json, offset);
                metadata.version_one = json.substr(start, offset - start) == "1";
            } else if (key == "request_id") {
                metadata.request_id = parse_json_string(json, offset);
            } else if (key == "ok") {
                metadata.ok_seen = parse_json_boolean(json, offset, metadata.ok);
            } else if (key == "result") {
                metadata.has_result = true;
                metadata.result_is_object = offset < json.size() && json[offset] == '{';
                skip_json_value(json, offset);
            } else if (key == "error") {
                metadata.has_error = true;
                metadata.error_is_object = offset < json.size() && json[offset] == '{';
                skip_json_value(json, offset);
            } else {
                metadata.has_unknown_top_level_field = true;
                skip_json_value(json, offset);
            }
            skip_ws(json, offset);
            if (offset < json.size() && json[offset] == ',') {
                ++offset;
                skip_ws(json, offset);
                continue;
            }
            if (offset < json.size() && json[offset] == '}') {
                ++offset;
                break;
            }
            throw std::invalid_argument("QR response display response JSON object is malformed");
        }
    }
    skip_ws(json, offset);
    if (offset != json.size()) {
        throw std::invalid_argument("QR response display response JSON has trailing data");
    }
    return metadata;
}

void require_response_json_for_display(const std::string& response_json) {
    const ResponseJsonMetadata metadata = parse_response_json_metadata(response_json);
    if (metadata.has_unknown_top_level_field) {
        throw std::invalid_argument("QR response display response contains unknown top-level field");
    }
    if (!metadata.version_one) {
        throw std::invalid_argument("QR response display response version must be 1");
    }
    if (!is_request_id(metadata.request_id)) {
        throw std::invalid_argument("QR response display response request_id is invalid");
    }
    if (!metadata.ok_seen) {
        throw std::invalid_argument("QR response display response ok must be true or false");
    }
    if (metadata.ok) {
        if (metadata.has_error) {
            throw std::invalid_argument("QR response display successful response must not include error");
        }
        if (!metadata.has_result || !metadata.result_is_object) {
            throw std::invalid_argument("QR response display successful response requires result object");
        }
        return;
    }
    if (metadata.has_result) {
        throw std::invalid_argument("QR response display error response must not include result");
    }
    if (!metadata.has_error || !metadata.error_is_object) {
        throw std::invalid_argument("QR response display error response requires error object");
    }
}

std::vector<QrResponseDisplayFrame> wrap_static_response_frame(const std::string& payload) {
    return std::vector<QrResponseDisplayFrame>{QrResponseDisplayFrame{
        payload,
        1U,
        1U,
        false,
    }};
}

std::vector<QrResponseDisplayFrame> wrap_animated_response_frames(std::vector<std::string> payloads) {
    std::vector<QrResponseDisplayFrame> frames;
    frames.reserve(payloads.size());
    const std::size_t total = payloads.size();
    for (std::size_t offset = 0; offset < payloads.size(); ++offset) {
        frames.push_back(QrResponseDisplayFrame{
            std::move(payloads[offset]),
            offset + 1U,
            total,
            true,
        });
    }
    return frames;
}

}  // namespace

std::vector<QrResponseDisplayFrame> build_qr_response_display_frames(
    const std::string& response_json,
    std::size_t animated_chunk_size_chars) {
    require_response_json_for_display(response_json);
    if (response_json.size() <= kMaxStaticQrDecodedJsonBytes) {
        return wrap_static_response_frame(encode_qr_envelope_json(response_json));
    }
    return wrap_animated_response_frames(encode_animated_qr_envelope_json(response_json, animated_chunk_size_chars));
}

QrResponseDisplayResult run_qr_response_display_io(
    QrResponseDisplayIo& io,
    const std::string& response_json,
    std::size_t animated_chunk_size_chars,
    std::size_t animated_cycles) {
    if (animated_cycles == 0U) {
        throw std::invalid_argument("QR response display animated cycles must be non-zero");
    }
    if (animated_cycles > kMaxQrResponseDisplayCycles) {
        throw std::invalid_argument("QR response display animated cycles exceed max_qr_response_display_cycles");
    }

    const std::vector<QrResponseDisplayFrame> frames =
        build_qr_response_display_frames(response_json, animated_chunk_size_chars);
    const std::size_t cycles = frames.size() > 1U ? animated_cycles : 1U;
    std::vector<QrResponseDisplayFrame> displayed;
    displayed.reserve(frames.size() * cycles);
    for (std::size_t cycle = 0; cycle < cycles; ++cycle) {
        for (const QrResponseDisplayFrame& frame : frames) {
            io.show_response_qr_frame(frame);
            displayed.push_back(frame);
        }
    }
    return QrResponseDisplayResult{std::move(displayed)};
}

}  // namespace nsealr
