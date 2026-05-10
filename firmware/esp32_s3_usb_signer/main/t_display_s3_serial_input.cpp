#include "t_display_s3_serial_input.hpp"

#include <stdexcept>
#include <utility>

namespace nostrseal_esp32 {

TDisplayS3SerialInputEvent update_t_display_s3_serial_input(
    TDisplayS3SerialInput& input,
    char ch,
    std::size_t max_frame_bytes) {
    if (max_frame_bytes == 0U) {
        throw std::invalid_argument("serial input max frame bytes must be non-zero");
    }

    if (input.draining_overlong) {
        if (ch == '\n') {
            input.draining_overlong = false;
            input.line.clear();
        }
        return {};
    }

    if (ch == '\r') {
        return {};
    }

    input.line.push_back(ch);
    if (input.line.size() > max_frame_bytes) {
        input.line.clear();
        input.draining_overlong = true;
        return TDisplayS3SerialInputEvent{TDisplayS3SerialInputEventKind::OverlongFrame, {}};
    }

    if (ch == '\n') {
        std::string line = std::move(input.line);
        input.line.clear();
        return TDisplayS3SerialInputEvent{TDisplayS3SerialInputEventKind::FrameReady, std::move(line)};
    }

    return {};
}

}  // namespace nostrseal_esp32
