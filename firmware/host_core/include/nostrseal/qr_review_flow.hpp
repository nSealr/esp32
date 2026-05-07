#pragma once

#include <optional>
#include <string>

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

}  // namespace nostrseal
