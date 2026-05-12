#pragma once

#include <optional>
#include <string>

#include "nsealr/review_display.hpp"
#include "nsealr/trusted_review.hpp"

namespace nsealr {

struct SerialFrameHandlingResult {
    std::string response_frame;
    std::optional<ReviewDisplayFrame> review_frame = std::nullopt;
    std::optional<TrustedReviewSession> review_session = std::nullopt;
};

std::string handle_serial_frame(const std::string& line);
SerialFrameHandlingResult handle_serial_frame_with_review_preview(
    const std::string& line,
    ReviewDisplayLimits limits = {});

}  // namespace nsealr
