#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "nsealr/qr_review.hpp"
#include "nsealr/review_controls.hpp"
#include "nsealr/review_display.hpp"
#include "nsealr/trusted_review.hpp"

namespace nsealr {

class QrReviewFlow {
public:
    explicit QrReviewFlow(const std::string& qr_envelope, ReviewDisplayLimits limits = {});

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

class QrReviewIo {
public:
    virtual ~QrReviewIo() = default;

    virtual std::string scan_request_qr() = 0;
    virtual void show_review_frame(const ReviewDisplayFrame& frame) = 0;
    virtual ReviewButton read_review_button() = 0;
};

struct QrReviewTranscriptStep {
    ReviewDisplayFrame frame;
    ReviewButton button;
    std::optional<bool> decision;
    bool approved_for_signing;
};

struct QrReviewIoFlowResult {
    std::string request_id;
    std::string approval_digest;
    std::optional<bool> decision;
    bool approved_for_signing;
    std::vector<QrReviewTranscriptStep> transcript;
};

QrReviewIoFlowResult run_qr_review_io_flow(
    QrReviewIo& io,
    ReviewDisplayLimits limits = {},
    std::size_t max_steps = 32);

std::vector<QrReviewTranscriptStep> run_qr_review_transcript(
    const std::string& qr_envelope,
    const std::vector<ReviewButton>& buttons,
    ReviewDisplayLimits limits = {});

}  // namespace nsealr
