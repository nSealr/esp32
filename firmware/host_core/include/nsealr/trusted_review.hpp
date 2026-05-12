#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "nsealr/approval_gate.hpp"
#include "nsealr/review_controls.hpp"
#include "nsealr/review_display.hpp"

namespace nsealr {

struct TrustedReviewPage {
    std::string title;
    std::vector<std::string> lines;
    ReviewPageAction action;
    std::string page_indicator{};
    std::vector<ReviewBodyLineStyle> body_line_styles{};
    std::string logical_page_id{};
};

struct TrustedReviewRequest {
    std::string request_id;
    std::string approval_digest;
    std::vector<TrustedReviewPage> pages;
};

struct TrustedReviewLogicalPageRange {
    std::size_t start_index;
    std::size_t page_count;
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
    [[nodiscard]] bool using_logical_navigation() const;
    [[nodiscard]] std::size_t active_flat_page_index() const;
    [[nodiscard]] bool terminal_decision_recorded() const;

    TrustedReviewRequest request_;
    ReviewControlSession controls_;
    ApprovalGate approval_gate_;
    ReviewDisplayLimits limits_;
    std::vector<TrustedReviewLogicalPageRange> logical_page_ranges_;
    std::size_t current_logical_page_index_ = 0;
    std::size_t current_scroll_page_offset_ = 0;
};

}  // namespace nsealr
