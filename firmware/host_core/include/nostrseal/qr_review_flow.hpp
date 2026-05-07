#pragma once

#include <optional>
#include <string>
#include <vector>

#include "nostrseal/qr_review.hpp"
#include "nostrseal/review_controls.hpp"
#include "nostrseal/review_display.hpp"
#include "nostrseal/trusted_review.hpp"

namespace nostrseal {

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

struct QrReviewTranscriptStep {
    ReviewDisplayFrame frame;
    ReviewButton button;
    std::optional<bool> decision;
    bool approved_for_signing;
};

std::vector<QrReviewTranscriptStep> run_qr_review_transcript(
    const std::string& qr_envelope,
    const std::vector<ReviewButton>& buttons,
    ReviewDisplayLimits limits = {});

}  // namespace nostrseal
