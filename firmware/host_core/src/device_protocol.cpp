#include "nsealr/device_protocol.hpp"

#include <algorithm>
#include <utility>
#include <vector>

#include "nsealr/base64url.hpp"
#include "nsealr/json_unicode.hpp"
#include "nsealr/limits.hpp"
#include "nsealr/qr_envelope.hpp"
#include "nsealr/serial_frame.hpp"
#include "nsealr/serial_review.hpp"
#include "nsealr/signing_policy.hpp"
#include "nsealr/utf8.hpp"

namespace nsealr {
namespace {

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
                    append_json_unicode_escape<SerialFrameError>(
                        value,
                        json,
                        offset,
                        "request JSON unicode escape is truncated",
                        "request JSON unicode escape is invalid");
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

std::string decode_serial_payload_base64url(const std::string& payload) {
    try {
        return decode_base64url(payload);
    } catch (const Base64UrlError& error) {
        if (error.code() == Base64UrlErrorCode::InvalidTrailingBits) {
            throw SerialFrameError("serial frame payload has invalid trailing bits");
        }
        throw SerialFrameError("serial frame payload must be unpadded base64url");
    }
}

SerialFrame unsupported_request_frame() {
    return SerialFrame{FrameType::Error, "eyJlcnJvciI6InVuc3VwcG9ydGVkX3JlcXVlc3QifQ"};
}

std::string capability_response_json(const std::string& request_id) {
    return std::string(R"({"version":1,"request_id":")") + request_id +
           R"(","ok":true,"result":{"capabilities":{"device":{"name":"nSealr ESP32-S3 USB Signer Scaffold","firmware":"nsealr-esp32-s3-usb-signer","hardware":"esp32-s3-devkitc-1"},"protocols":["nsealr.signing.v0","nsealr.serial-frame.v0"],"methods":["get_capabilities","get_signing_status","get_public_key","sign_event"],"transports":["usb-serial-jtag"],"signing_enabled":false,"requires_physical_approval":true}}})";
}

std::string public_key_response_json(const std::string& request_id, const SignerIdentity& identity) {
    require_valid_signer_identity(identity);
    return std::string(R"({"version":1,"request_id":")") + request_id +
           R"(","ok":true,"result":{"public_key":")" + identity.public_key + R"("}})";
}

std::string signing_disabled_response_json(const std::string& request_id) {
    return std::string(R"({"version":1,"request_id":")") + request_id +
           R"(","ok":false,"error":{"code":"signing_disabled","message":"Signing is disabled until trusted review and physical approval are implemented.","retryable":false}})";
}

SigningReadiness scaffold_signing_readiness() {
    SigningReadiness readiness;
    readiness.parser_limits_enforced = true;
    readiness.approval_digest_binding_verified = true;
    readiness.development_accepted_gates = {
        "parser_limits",
        "trusted_review_display",
        "physical_approval_controls",
        "approval_digest_binding",
    };
    return readiness;
}

std::string gates_json(const std::vector<std::string>& gates) {
    std::string output;
    for (std::size_t index = 0; index < gates.size(); ++index) {
        if (index > 0) {
            output += ",";
        }
        output += "\"";
        output += gates[index];
        output += "\"";
    }
    return output;
}

std::string signing_status_response_json(const std::string& request_id) {
    const SigningReadinessStatus status = evaluate_signing_readiness(scaffold_signing_readiness());
    return std::string(R"({"version":1,"request_id":")") + request_id +
           R"(","ok":true,"result":{"signing_status":{"signing_enabled":false,"missing_gates":[)" +
           gates_json(status.missing_gates) + R"(],"development_accepted_gates":[)" +
           gates_json(status.development_accepted_gates) + R"(]}}})";
}

}  // namespace

DeviceProtocolContext development_device_protocol_context() {
    return DeviceProtocolContext{development_fixture_signer_identity()};
}

std::string handle_serial_frame(const std::string& line) {
    return handle_serial_frame(line, development_device_protocol_context());
}

std::string handle_serial_frame(const std::string& line, const DeviceProtocolContext& context) {
    return handle_serial_frame_with_review_preview(line, context).response_frame;
}

SerialFrameHandlingResult handle_serial_frame_with_review_preview(
    const std::string& line,
    ReviewDisplayLimits limits) {
    return handle_serial_frame_with_review_preview(line, development_device_protocol_context(), limits);
}

SerialFrameHandlingResult handle_serial_frame_with_review_preview(
    const std::string& line,
    const DeviceProtocolContext& context,
    ReviewDisplayLimits limits) {
    require_valid_signer_identity(context.signer_identity);
    const SerialFrame request = decode_serial_frame(line);
    if (request.type != FrameType::Request) {
        return SerialFrameHandlingResult{encode_serial_frame(unsupported_request_frame()), std::nullopt};
    }

    const std::string request_json = decode_serial_payload_base64url(request.payload_base64url);
    if (request_json.size() > kMaxDecodedRequestJsonBytes) {
        return SerialFrameHandlingResult{encode_serial_frame(unsupported_request_frame()), std::nullopt};
    }
    if (!is_valid_utf8(request_json)) {
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
            encode_serial_frame(response_frame(public_key_response_json(metadata.request_id, context.signer_identity))),
            std::nullopt};
    }
    if (metadata.method == "get_signing_status") {
        if (metadata.has_params) {
            return SerialFrameHandlingResult{encode_serial_frame(unsupported_request_frame()), std::nullopt};
        }
        return SerialFrameHandlingResult{
            encode_serial_frame(response_frame(signing_status_response_json(metadata.request_id))),
            std::nullopt};
    }
    if (metadata.method == "sign_event") {
        std::optional<ReviewDisplayFrame> review_frame;
        std::optional<TrustedReviewSession> review_session;
        try {
            TrustedReviewSession session =
                begin_serial_sign_event_trusted_review(request_json, context.signer_identity, limits);
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

}  // namespace nsealr
