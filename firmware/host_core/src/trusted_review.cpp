#include "nostrseal/trusted_review.hpp"

#include <stdexcept>
#include <string_view>
#include <utility>

namespace nostrseal {

namespace {

void validate_request_metadata(const TrustedReviewRequest& request) {
    if (request.request_id.empty()) {
        throw std::invalid_argument("trusted review request id must be non-empty");
    }
    if (request.approval_digest.empty()) {
        throw std::invalid_argument("trusted review approval digest must be non-empty");
    }
}

ReviewPage as_review_page(const TrustedReviewPage& page) {
    std::vector<std::string_view> lines;
    lines.reserve(page.lines.size());
    for (const std::string& line : page.lines) {
        lines.push_back(line);
    }

    return ReviewPage{
        page.title,
        std::move(lines),
        page.action,
        page.page_indicator,
        page.body_line_styles,
    };
}

}  // namespace

TrustedReviewSession::TrustedReviewSession(TrustedReviewRequest request, ReviewDisplayLimits limits)
    : request_(std::move(request)), controls_(request_.pages.size()), limits_(limits) {
    validate_request_metadata(request_);
    approval_gate_.begin_review(request_.request_id, request_.approval_digest);
}

ReviewDisplayFrame TrustedReviewSession::current_frame() const {
    const std::size_t page_index = controls_.current_page_index();
    return render_review_page(as_review_page(request_.pages.at(page_index)), page_index, request_.pages.size(), limits_);
}

bool TrustedReviewSession::can_sign() const {
    return approval_gate_.can_sign(request_.request_id, request_.approval_digest);
}

ApprovalDecision TrustedReviewSession::decision() const {
    return approval_gate_.decision();
}

std::size_t TrustedReviewSession::current_page_index() const {
    return controls_.current_page_index();
}

std::optional<bool> TrustedReviewSession::handle_button(ReviewButton button) {
    const std::optional<bool> decision = controls_.handle_button(button);
    if (!decision.has_value()) {
        return std::nullopt;
    }

    if (decision.value()) {
        approval_gate_.approve(request_.request_id, request_.approval_digest);
    } else {
        approval_gate_.reject(request_.request_id);
    }
    return decision;
}

}  // namespace nostrseal
