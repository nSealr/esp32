#include "nostrseal/qr_envelope.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <map>
#include <string_view>
#include <utility>
#include <vector>

#include "nostrseal/limits.hpp"

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

bool is_valid_utf8(const std::string& value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto byte = static_cast<unsigned char>(value[offset]);
        if (byte <= 0x7fU) {
            ++offset;
            continue;
        }

        std::size_t expected_continuations = 0;
        std::uint32_t codepoint = 0;
        if ((byte & 0xe0U) == 0xc0U) {
            expected_continuations = 1;
            codepoint = byte & 0x1fU;
            if (codepoint == 0U) {
                return false;
            }
        } else if ((byte & 0xf0U) == 0xe0U) {
            expected_continuations = 2;
            codepoint = byte & 0x0fU;
        } else if ((byte & 0xf8U) == 0xf0U) {
            expected_continuations = 3;
            codepoint = byte & 0x07U;
        } else {
            return false;
        }

        if (offset + expected_continuations >= value.size()) {
            return false;
        }
        for (std::size_t index = 0; index < expected_continuations; ++index) {
            const auto continuation = static_cast<unsigned char>(value[++offset]);
            if ((continuation & 0xc0U) != 0x80U) {
                return false;
            }
            codepoint = (codepoint << 6U) | (continuation & 0x3fU);
        }
        if ((expected_continuations == 2U && codepoint < 0x800U) ||
            (expected_continuations == 3U && codepoint < 0x10000U) ||
            codepoint > 0x10ffffU ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
            return false;
        }
        ++offset;
    }
    return true;
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
    if (value.empty() || value.size() > kMaxRequestIdLength) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' ||
               ch == '_' || ch == ':' || ch == '-';
    });
}

bool is_allowed_key(const std::string& key, std::initializer_list<std::string_view> allowed) {
    return std::any_of(allowed.begin(), allowed.end(), [&](std::string_view candidate) {
        return key == candidate;
    });
}

void require_only_known_fields(
    const std::map<std::string, JsonTopLevelValue>& values,
    std::initializer_list<std::string_view> allowed,
    const char* message) {
    for (const auto& [key, _] : values) {
        if (!is_allowed_key(key, allowed)) {
            throw QrEnvelopeError(message);
        }
    }
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

int hex_value(char ch) {
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

char parse_json_ascii_unicode_escape(const std::string& json, std::size_t& offset) {
    if (offset + 4U > json.size()) {
        throw QrEnvelopeError("QR signing request JSON unicode escape is truncated");
    }
    int codepoint = 0;
    for (int index = 0; index < 4; ++index) {
        const int nibble = hex_value(json[offset++]);
        if (nibble < 0) {
            throw QrEnvelopeError("QR signing request JSON unicode escape is invalid");
        }
        codepoint = (codepoint << 4) | nibble;
    }
    if (codepoint > 0x7f) {
        return '?';
    }
    return static_cast<char>(codepoint);
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
            if (offset >= json.size()) {
                throw QrEnvelopeError("QR signing request JSON string escape is truncated");
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
                    value.push_back(parse_json_ascii_unicode_escape(json, offset));
                    break;
                default:
                    throw QrEnvelopeError("QR signing request JSON string escape is invalid");
            }
            continue;
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

std::uint64_t parse_unsigned_decimal(std::string_view token, const char* field_name) {
    if (token.empty() || token.front() == '-') {
        throw QrEnvelopeError(std::string{"QR signing request event_template "} + field_name + " is required");
    }
    std::uint64_t value = 0;
    for (const char ch : token) {
        if (ch < '0' || ch > '9') {
            throw QrEnvelopeError(std::string{"QR signing request event_template "} + field_name + " is required");
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
            throw QrEnvelopeError(std::string{"QR signing request event_template "} + field_name + " is invalid");
        }
        value = (value * 10U) + digit;
    }
    if (value > kMaxSafeInteger) {
        throw QrEnvelopeError(std::string{"QR signing request event_template "} + field_name + " exceeds max_safe_integer");
    }
    return value;
}

std::vector<std::vector<std::string>> parse_tags_array(const std::string& tags_json) {
    std::size_t offset = 0;
    skip_ws(tags_json, offset);
    if (offset >= tags_json.size() || tags_json[offset] != '[') {
        throw QrEnvelopeError("QR signing request event_template tags array is required");
    }
    ++offset;
    std::vector<std::vector<std::string>> tags;
    skip_ws(tags_json, offset);
    if (offset < tags_json.size() && tags_json[offset] == ']') {
        ++offset;
    } else {
        while (offset < tags_json.size()) {
            skip_ws(tags_json, offset);
            if (offset >= tags_json.size() || tags_json[offset] != '[') {
                throw QrEnvelopeError("QR signing request event_template tags must be string arrays");
            }
            ++offset;
            std::vector<std::string> tag;
            skip_ws(tags_json, offset);
            if (offset < tags_json.size() && tags_json[offset] == ']') {
                ++offset;
            } else {
                while (offset < tags_json.size()) {
                    skip_ws(tags_json, offset);
                    std::string field = parse_simple_json_string(tags_json, offset);
                    if (field.size() > kMaxTagFieldUtf8Bytes) {
                        throw QrEnvelopeError(
                            "QR signing request event_template tag field exceeds max_tag_field_utf8_bytes");
                    }
                    tag.push_back(std::move(field));
                    skip_ws(tags_json, offset);
                    if (offset < tags_json.size() && tags_json[offset] == ',') {
                        ++offset;
                        continue;
                    }
                    if (offset < tags_json.size() && tags_json[offset] == ']') {
                        ++offset;
                        break;
                    }
                    throw QrEnvelopeError("QR signing request event_template tags must be string arrays");
                }
            }
            if (tag.size() > kMaxTagFieldsPerTag) {
                throw QrEnvelopeError("QR signing request event_template tag exceeds max_tag_fields_per_tag");
            }
            tags.push_back(tag);
            if (tags.size() > kMaxTagCount) {
                throw QrEnvelopeError("QR signing request event_template tags exceed max_tag_count");
            }
            skip_ws(tags_json, offset);
            if (offset < tags_json.size() && tags_json[offset] == ',') {
                ++offset;
                continue;
            }
            if (offset < tags_json.size() && tags_json[offset] == ']') {
                ++offset;
                break;
            }
            throw QrEnvelopeError("QR signing request event_template tags array separator is invalid");
        }
    }
    skip_ws(tags_json, offset);
    if (offset != tags_json.size()) {
        throw QrEnvelopeError("QR signing request event_template tags array has trailing data");
    }
    std::size_t total_tag_bytes = 0;
    for (const auto& tag : tags) {
        for (const auto& field : tag) {
            total_tag_bytes += field.size();
            if (total_tag_bytes > kMaxTotalTagUtf8Bytes) {
                throw QrEnvelopeError("QR signing request event_template tags exceed max_total_tag_utf8_bytes");
            }
        }
    }
    return tags;
}

QrEventTemplate parse_event_template_fields(const std::string& event_template_json) {
    const auto event_template = parse_top_level_object(event_template_json);
    for (const char* field : {"id", "pubkey", "sig"}) {
        if (event_template.find(field) != event_template.end()) {
            throw QrEnvelopeError(std::string{"QR signing request event_template must not include "} + field);
        }
    }
    require_only_known_fields(
        event_template,
        {"created_at", "kind", "tags", "content"},
        "QR signing request event_template contains unknown field");

    const auto created_at = event_template.find("created_at");
    if (created_at == event_template.end() || created_at->second.kind != JsonValueKind::Number) {
        throw QrEnvelopeError("QR signing request event_template created_at is required");
    }
    const auto kind = event_template.find("kind");
    if (kind == event_template.end() || kind->second.kind != JsonValueKind::Number) {
        throw QrEnvelopeError("QR signing request event_template kind is required");
    }
    const auto tags = event_template.find("tags");
    if (tags == event_template.end() || tags->second.kind != JsonValueKind::Array) {
        throw QrEnvelopeError("QR signing request event_template tags array is required");
    }
    const auto content = event_template.find("content");
    if (content == event_template.end() || content->second.kind != JsonValueKind::String) {
        throw QrEnvelopeError("QR signing request event_template content is required");
    }
    if (content->second.value.size() > kMaxContentUtf8Bytes) {
        throw QrEnvelopeError("QR signing request event_template content exceeds max_content_utf8_bytes");
    }

    const std::uint64_t kind_value = parse_unsigned_decimal(kind->second.value, "kind");
    if (kind_value > static_cast<std::uint64_t>(std::numeric_limits<int>::max())) {
        throw QrEnvelopeError("QR signing request event_template kind is invalid");
    }

    return QrEventTemplate{
        parse_unsigned_decimal(created_at->second.value, "created_at"),
        static_cast<int>(kind_value),
        tags->second.value,
        parse_tags_array(tags->second.value),
        content->second.value,
    };
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
    if (decoded.size() > kMaxStaticQrDecodedJsonBytes) {
        throw QrEnvelopeError("QR decoded JSON exceeds max_static_qr_decoded_json_bytes");
    }
    if (!is_valid_utf8(decoded)) {
        throw QrEnvelopeError("QR envelope payload must be valid UTF-8");
    }
    require_json_container(decoded);
    return QrEnvelope{payload, decoded};
}

QrSigningRequest parse_qr_signing_request(const QrEnvelope& envelope) {
    if (envelope.payload_json.size() > kMaxDecodedRequestJsonBytes) {
        throw QrEnvelopeError("QR signing request decoded JSON exceeds max_decoded_request_json_bytes");
    }
    const auto values = parse_top_level_object(envelope.payload_json);
    require_only_known_fields(
        values,
        {"version", "request_id", "method", "params"},
        "QR signing request contains unknown top-level field");
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
    const auto params_values = parse_top_level_object(params->second.value);
    require_only_known_fields(
        params_values,
        {"event_template"},
        "QR signing request params contains unknown field");
    const auto event_template = params_values.find("event_template");
    if (event_template == params_values.end() || event_template->second.kind != JsonValueKind::Object) {
        throw QrEnvelopeError("QR signing request event_template object is required");
    }
    const QrEventTemplate parsed_event_template = parse_event_template_fields(event_template->second.value);
    return QrSigningRequest{
        1, request_id->second.value, method->second.value, true, true, event_template->second.value, parsed_event_template};
}

}  // namespace nostrseal
