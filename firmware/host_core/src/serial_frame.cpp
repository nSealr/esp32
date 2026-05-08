#include "nostrseal/serial_frame.hpp"

#include <algorithm>
#include <array>

#include "nostrseal/limits.hpp"
#include "nostrseal/sha256.hpp"

namespace nostrseal {
namespace {

constexpr const char* kPrefix = "nseal1f:";

bool is_base64url_payload(const std::string& value) {
    if (value.empty()) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' ||
               ch == '-';
    });
}

std::string checksum(FrameType type, const std::string& payload) {
    const std::string input = frame_type_to_string(type) + ":" + payload;
    return sha256_hex(input).substr(0, 16);
}

std::array<std::string, 3> split_frame_body(const std::string& body) {
    std::array<std::string, 3> parts;
    std::size_t start = 0;
    for (std::size_t index = 0; index < parts.size(); ++index) {
        const std::size_t end = body.find(':', start);
        if (index < parts.size() - 1 && end == std::string::npos) {
            throw SerialFrameError("serial frame must contain type, payload, and checksum");
        }
        if (index == parts.size() - 1) {
            parts[index] = body.substr(start);
            if (parts[index].find(':') != std::string::npos) {
                throw SerialFrameError("serial frame must contain type, payload, and checksum");
            }
        } else {
            parts[index] = body.substr(start, end - start);
            start = end + 1;
        }
    }
    return parts;
}

}  // namespace

std::string frame_type_to_string(FrameType type) {
    switch (type) {
        case FrameType::Request:
            return "request";
        case FrameType::Response:
            return "response";
        case FrameType::Error:
            return "error";
    }
    throw SerialFrameError("unsupported serial frame type");
}

FrameType parse_frame_type(const std::string& value) {
    if (value == "request") {
        return FrameType::Request;
    }
    if (value == "response") {
        return FrameType::Response;
    }
    if (value == "error") {
        return FrameType::Error;
    }
    throw SerialFrameError("unsupported serial frame type");
}

std::string encode_serial_frame(const SerialFrame& frame) {
    if (!is_base64url_payload(frame.payload_base64url)) {
        throw SerialFrameError("serial frame payload must be unpadded base64url");
    }
    return std::string(kPrefix) + frame_type_to_string(frame.type) + ":" + frame.payload_base64url + ":" +
           checksum(frame.type, frame.payload_base64url) + "\n";
}

SerialFrame decode_serial_frame(const std::string& line) {
    if (line.size() > kMaxSerialFrameBytes) {
        throw SerialFrameError("serial frame exceeds max_serial_frame_bytes");
    }
    std::string normalized = line;
    if (!normalized.empty() && normalized.back() == '\n') {
        normalized.pop_back();
    }
    if (normalized.rfind(kPrefix, 0) != 0) {
        throw SerialFrameError("serial frame must start with nseal1f:");
    }
    const auto [type_text, payload, frame_checksum] = split_frame_body(normalized.substr(std::string(kPrefix).size()));
    const FrameType type = parse_frame_type(type_text);
    if (!is_base64url_payload(payload)) {
        throw SerialFrameError("serial frame payload must be unpadded base64url");
    }
    if (frame_checksum != checksum(type, payload)) {
        throw SerialFrameError("serial frame checksum mismatch");
    }
    return SerialFrame{type, payload};
}

}  // namespace nostrseal
