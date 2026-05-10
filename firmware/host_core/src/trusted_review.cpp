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

std::vector<TrustedReviewLogicalPageRange> logical_page_ranges_for(
    const std::vector<TrustedReviewPage>& pages) {
    bool has_logical_ids = false;
    for (const TrustedReviewPage& page : pages) {
        has_logical_ids = has_logical_ids || !page.logical_page_id.empty();
    }
    if (!has_logical_ids) {
        return {};
    }

    std::vector<TrustedReviewLogicalPageRange> ranges;
    std::string current_id;
    for (std::size_t index = 0; index < pages.size(); ++index) {
        const std::string page_id = pages[index].logical_page_id.empty()
                                        ? "__page_" + std::to_string(index)
                                        : pages[index].logical_page_id;
        if (ranges.empty() || page_id != current_id) {
            ranges.push_back(TrustedReviewLogicalPageRange{
                index,
                1,
            });
            current_id = page_id;
        } else {
            ++ranges.back().page_count;
        }
    }
    return ranges;
}

}  // namespace

TrustedReviewSession::TrustedReviewSession(TrustedReviewRequest request, ReviewDisplayLimits limits)
    : request_(std::move(request)),
      controls_(request_.pages.size()),
      limits_(limits),
      logical_page_ranges_(logical_page_ranges_for(request_.pages)) {
    validate_request_metadata(request_);
    approval_gate_.begin_review(request_.request_id, request_.approval_digest);
}

ReviewDisplayFrame TrustedReviewSession::current_frame() const {
    const std::size_t page_index = active_flat_page_index();
    ReviewDisplayFrame frame =
        render_review_page(as_review_page(request_.pages.at(page_index)), page_index, request_.pages.size(), limits_);
    if (using_logical_navigation() &&
        request_.pages.at(page_index).action == ReviewPageAction::Next &&
        logical_page_ranges_.at(current_logical_page_index_).page_count > 1U) {
        frame.action_hint = "Next/Scroll";
    }
    return frame;
}

bool TrustedReviewSession::can_sign() const {
    return approval_gate_.can_sign(request_.request_id, request_.approval_digest);
}

ApprovalDecision TrustedReviewSession::decision() const {
    return approval_gate_.decision();
}

std::size_t TrustedReviewSession::current_page_index() const {
    return active_flat_page_index();
}

std::optional<bool> TrustedReviewSession::handle_button(ReviewButton button) {
    if (using_logical_navigation()) {
        if (terminal_decision_recorded()) {
            throw std::logic_error("review decision is already terminal");
        }

        if (button == ReviewButton::Reject) {
            approval_gate_.reject(request_.request_id);
            return false;
        }

        if (button == ReviewButton::Next) {
            current_logical_page_index_ = (current_logical_page_index_ + 1U) % logical_page_ranges_.size();
            current_scroll_page_offset_ = 0;
            return std::nullopt;
        }

        if (button == ReviewButton::Back) {
            const TrustedReviewLogicalPageRange& range = logical_page_ranges_.at(current_logical_page_index_);
            if (range.page_count > 1U) {
                current_scroll_page_offset_ = (current_scroll_page_offset_ + 1U) % range.page_count;
            }
            return std::nullopt;
        }

        const TrustedReviewPage& active_page = request_.pages.at(active_flat_page_index());
        if (active_page.action != ReviewPageAction::ApproveOrReject) {
            throw std::logic_error("approval requires decision review page");
        }
        approval_gate_.approve(request_.request_id, request_.approval_digest);
        return true;
    }

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

bool TrustedReviewSession::using_logical_navigation() const {
    return !logical_page_ranges_.empty();
}

std::size_t TrustedReviewSession::active_flat_page_index() const {
    if (!using_logical_navigation()) {
        return controls_.current_page_index();
    }
    const TrustedReviewLogicalPageRange& range = logical_page_ranges_.at(current_logical_page_index_);
    return range.start_index + current_scroll_page_offset_;
}

bool TrustedReviewSession::terminal_decision_recorded() const {
    return approval_gate_.decision() == ApprovalDecision::Approved ||
           approval_gate_.decision() == ApprovalDecision::Rejected;
}

}  // namespace nostrseal
