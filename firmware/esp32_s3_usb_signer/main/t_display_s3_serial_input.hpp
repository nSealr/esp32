#pragma once

#include <cstddef>
#include <string>

namespace nostrseal_esp32 {

enum class TDisplayS3SerialInputEventKind {
    None,
    FrameReady,
    OverlongFrame,
};

struct TDisplayS3SerialInputEvent {
    TDisplayS3SerialInputEventKind kind = TDisplayS3SerialInputEventKind::None;
    std::string line;
};

struct TDisplayS3SerialInput {
    std::string line;
    bool draining_overlong = false;
};

TDisplayS3SerialInputEvent update_t_display_s3_serial_input(
    TDisplayS3SerialInput& input,
    char ch,
    std::size_t max_frame_bytes);

}  // namespace nostrseal_esp32
