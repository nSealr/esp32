#pragma once

#include <optional>
#include <string>

#include "nsealr/review_display.hpp"
#include "nsealr/signer_identity.hpp"
#include "nsealr/trusted_review.hpp"

namespace nsealr {

struct DeviceProtocolContext {
    SignerIdentity signer_identity;
};

struct SerialFrameHandlingResult {
    std::string response_frame;
    std::optional<ReviewDisplayFrame> review_frame = std::nullopt;
    std::optional<TrustedReviewSession> review_session = std::nullopt;
};

DeviceProtocolContext development_device_protocol_context();
std::string handle_serial_frame(const std::string& line);
std::string handle_serial_frame(const std::string& line, const DeviceProtocolContext& context);
SerialFrameHandlingResult handle_serial_frame_with_review_preview(
    const std::string& line,
    ReviewDisplayLimits limits = {});
SerialFrameHandlingResult handle_serial_frame_with_review_preview(
    const std::string& line,
    const DeviceProtocolContext& context,
    ReviewDisplayLimits limits = {});

}  // namespace nsealr
