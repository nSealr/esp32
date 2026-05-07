#include "nostrseal/qr_envelope.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <string_view>
#include <vector>

namespace nostrseal {
namespace {

constexpr const char* kPrefix = "nseal1:";
constexpr char kInvalidBase64 = static_cast<char>(-1);

enum class JsonValueKind {
    String,
    Number,
    Object,
    Array,
    Literal,
};

struct JsonTopLevelValue {
    JsonValueKind kind;
    std::string value;
};

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

bool is_request_id(const std::string& value) {
    if (value.empty() || value.size() > 128U) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' ||
               ch == '_' || ch == ':' || ch == '-';
    });
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

std::string parse_simple_json_string(const std::string& json, std::size_t& offset) {
    if (offset >= json.size() || json[offset] != '"') {
        throw QrEnvelopeError("QR signing request JSON string is required");
    }
    ++offset;
    std::string value;
    while (offset < json.size()) {
        const char ch = json[offset++];
        if (ch == '"') {
            return value;
        }
        if (ch == '\\') {
            throw QrEnvelopeError("QR signing request JSON string escapes are not supported");
        }
        if (static_cast<unsigned char>(ch) < 0x20U) {
            throw QrEnvelopeError("QR signing request JSON string contains control character");
        }
        value.push_back(ch);
    }
    throw QrEnvelopeError("QR signing request JSON string is unterminated");
}

std::string parse_json_number_token(const std::string& json, std::size_t& offset) {
    const std::size_t start = offset;
    if (offset < json.size() && json[offset] == '-') {
        ++offset;
    }
    while (offset < json.size() && json[offset] >= '0' && json[offset] <= '9') {
        ++offset;
    }
    if (offset == start || (offset == start + 1U && json[start] == '-')) {
        throw QrEnvelopeError("QR signing request JSON number is invalid");
    }
    return json.substr(start, offset - start);
}

void skip_json_string(const std::string& json, std::size_t& offset) {
    (void)parse_simple_json_string(json, offset);
}

void skip_json_container(const std::string& json, std::size_t& offset, char open_ch, char close_ch) {
    if (offset >= json.size() || json[offset] != open_ch) {
        throw QrEnvelopeError("QR signing request JSON container is invalid");
    }
    int depth = 0;
    while (offset < json.size()) {
        const char ch = json[offset];
        if (ch == '"') {
            skip_json_string(json, offset);
            continue;
        }
        if (ch == open_ch) {
            ++depth;
        } else if (ch == close_ch) {
            --depth;
            ++offset;
            if (depth == 0) {
                return;
            }
            continue;
        }
        ++offset;
    }
    throw QrEnvelopeError("QR signing request JSON container is unterminated");
}

std::string parse_json_literal_token(const std::string& json, std::size_t& offset) {
    for (const char* literal : {"true", "false", "null"}) {
        const std::string_view literal_view{literal};
        if (json.compare(offset, literal_view.size(), literal_view) == 0) {
            offset += literal_view.size();
            return literal;
        }
    }
    throw QrEnvelopeError("QR signing request JSON value is invalid");
}

JsonTopLevelValue parse_json_value_token(const std::string& json, std::size_t& offset) {
    skip_ws(json, offset);
    if (offset >= json.size()) {
        throw QrEnvelopeError("QR signing request JSON value is missing");
    }
    const char ch = json[offset];
    if (ch == '"') {
        return JsonTopLevelValue{JsonValueKind::String, parse_simple_json_string(json, offset)};
    }
    if (ch == '{') {
        const std::size_t start = offset;
        skip_json_container(json, offset, '{', '}');
        return JsonTopLevelValue{JsonValueKind::Object, json.substr(start, offset - start)};
    }
    if (ch == '[') {
        const std::size_t start = offset;
        skip_json_container(json, offset, '[', ']');
        return JsonTopLevelValue{JsonValueKind::Array, json.substr(start, offset - start)};
    }
    if ((ch >= '0' && ch <= '9') || ch == '-') {
        return JsonTopLevelValue{JsonValueKind::Number, parse_json_number_token(json, offset)};
    }
    return JsonTopLevelValue{JsonValueKind::Literal, parse_json_literal_token(json, offset)};
}

std::map<std::string, JsonTopLevelValue> parse_top_level_object(const std::string& json) {
    std::size_t offset = 0;
    skip_ws(json, offset);
    if (offset >= json.size() || json[offset] != '{') {
        throw QrEnvelopeError("QR signing request must be a JSON object");
    }
    ++offset;
    std::map<std::string, JsonTopLevelValue> values;
    skip_ws(json, offset);
    if (offset < json.size() && json[offset] == '}') {
        ++offset;
    } else {
        while (offset < json.size()) {
            skip_ws(json, offset);
            const std::string key = parse_simple_json_string(json, offset);
            skip_ws(json, offset);
            if (offset >= json.size() || json[offset] != ':') {
                throw QrEnvelopeError("QR signing request JSON object member is missing ':'");
            }
            ++offset;
            values[key] = parse_json_value_token(json, offset);
            skip_ws(json, offset);
            if (offset < json.size() && json[offset] == ',') {
                ++offset;
                continue;
            }
            if (offset < json.size() && json[offset] == '}') {
                ++offset;
                break;
            }
            throw QrEnvelopeError("QR signing request JSON object separator is invalid");
        }
    }
    skip_ws(json, offset);
    if (offset != json.size()) {
        throw QrEnvelopeError("QR signing request JSON has trailing data");
    }
    return values;
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

QrSigningRequest parse_qr_signing_request(const QrEnvelope& envelope) {
    const auto values = parse_top_level_object(envelope.payload_json);
    const auto version = values.find("version");
    if (version == values.end() || version->second.kind != JsonValueKind::Number || version->second.value != "1") {
        throw QrEnvelopeError("QR signing request version must be 1");
    }
    const auto request_id = values.find("request_id");
    if (request_id == values.end() || request_id->second.kind != JsonValueKind::String ||
        !is_request_id(request_id->second.value)) {
        throw QrEnvelopeError("QR signing request request_id is invalid");
    }
    const auto method = values.find("method");
    if (method == values.end() || method->second.kind != JsonValueKind::String || method->second.value != "sign_event") {
        throw QrEnvelopeError("QR signing request method must be sign_event");
    }
    const auto params = values.find("params");
    if (params == values.end() || params->second.kind != JsonValueKind::Object) {
        throw QrEnvelopeError("QR signing request params object is required");
    }
    return QrSigningRequest{1, request_id->second.value, method->second.value, true};
}

}  // namespace nostrseal
