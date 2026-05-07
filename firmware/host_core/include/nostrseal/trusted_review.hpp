#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "nostrseal/approval_gate.hpp"
#include "nostrseal/review_controls.hpp"
#include "nostrseal/review_display.hpp"

namespace nostrseal {

struct TrustedReviewPage {
    std::string title;
    std::vector<std::string> lines;
    ReviewPageAction action;
};

struct TrustedReviewRequest {
    std::string request_id;
    std::string approval_digest;
    std::vector<TrustedReviewPage> pages;
};

class TrustedReviewSession {
public:
    explicit TrustedReviewSession(TrustedReviewRequest request, ReviewDisplayLimits limits = {});

    [[nodiscard]] ReviewDisplayFrame current_frame() const;
    [[nodiscard]] bool can_sign() const;
    [[nodiscard]] ApprovalDecision decision() const;
    [[nodiscard]] std::size_t current_page_index() const;

    std::optional<bool> handle_button(ReviewButton button);

private:
    TrustedReviewRequest request_;
    ReviewControlSession controls_;
    ApprovalGate approval_gate_;
    ReviewDisplayLimits limits_;
};

}  // namespace nostrseal
