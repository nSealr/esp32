#pragma once

#include <stdexcept>
#include <string>

namespace nsealr {

enum class FrameType {
    Request,
    Response,
    Error,
};

struct SerialFrame {
    FrameType type;
    std::string payload_base64url;
};

class SerialFrameError final : public std::runtime_error {
public:
    explicit SerialFrameError(const std::string& message) : std::runtime_error(message) {}
};

std::string frame_type_to_string(FrameType type);
FrameType parse_frame_type(const std::string& value);
std::string encode_serial_frame(const SerialFrame& frame);
SerialFrame decode_serial_frame(const std::string& line);

}  // namespace nsealr
