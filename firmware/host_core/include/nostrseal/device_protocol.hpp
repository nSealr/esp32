#pragma once

#include <optional>
#include <string>

#include "nostrseal/review_display.hpp"

namespace nostrseal {

struct SerialFrameHandlingResult {
    std::string response_frame;
    std::optional<ReviewDisplayFrame> review_frame;
};

std::string handle_serial_frame(const std::string& line);
SerialFrameHandlingResult handle_serial_frame_with_review_preview(
    const std::string& line,
    ReviewDisplayLimits limits = {});

}  // namespace nostrseal
