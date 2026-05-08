#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "nostrseal/trusted_review.hpp"

namespace nostrseal {

TrustedReviewRequest build_serial_sign_event_trusted_review_request(const std::string& request_json);
TrustedReviewSession begin_serial_sign_event_trusted_review(
    const std::string& request_json,
    ReviewDisplayLimits limits = {});

class SerialReviewFlow {
public:
    explicit SerialReviewFlow(const std::string& request_json, ReviewDisplayLimits limits = {});

    [[nodiscard]] const std::string& request_id() const;
    [[nodiscard]] const std::string& approval_digest() const;
    [[nodiscard]] ReviewDisplayFrame current_frame() const;
    [[nodiscard]] ApprovalDecision decision() const;
    [[nodiscard]] bool approved_for_signing() const;

    std::optional<bool> handle_button(ReviewButton button);

private:
    TrustedReviewRequest review_request_;
    TrustedReviewSession session_;
};

class SerialReviewIo {
public:
    virtual ~SerialReviewIo() = default;

    virtual std::string read_request_json() = 0;
    virtual void show_review_frame(const ReviewDisplayFrame& frame) = 0;
    virtual ReviewButton read_review_button() = 0;
};

struct SerialReviewTranscriptStep {
    ReviewDisplayFrame frame;
    ReviewButton button;
    std::optional<bool> decision;
    bool approved_for_signing;
};

struct SerialReviewIoFlowResult {
    std::string request_id;
    std::string approval_digest;
    std::optional<bool> decision;
    bool approved_for_signing;
    std::vector<SerialReviewTranscriptStep> transcript;
};

SerialReviewIoFlowResult run_serial_review_io_flow(
    SerialReviewIo& io,
    ReviewDisplayLimits limits = {},
    std::size_t max_steps = 32);

}  // namespace nostrseal
