#include "nostrseal/review_display.hpp"

#include <stdexcept>

namespace nostrseal {

namespace {

std::string action_hint_for(ReviewPageAction action) {
    if (action == ReviewPageAction::Next) {
        return "Next";
    }
    return "Approve / Reject";
}

void validate_display_bounds(const ReviewPage& page, std::size_t page_index, std::size_t total_pages,
                             ReviewDisplayLimits limits) {
    if (total_pages == 0) {
        throw std::invalid_argument("review display total pages must be non-zero");
    }
    if (page_index >= total_pages) {
        throw std::out_of_range("review display page index out of range");
    }
    if (page.title.empty()) {
        throw std::invalid_argument("review display title must be non-empty");
    }
    if (page.title.size() > limits.max_title_chars) {
        throw std::length_error("review display title exceeds configured width");
    }
    if (page.lines.size() > limits.max_body_lines) {
        throw std::length_error("review display page exceeds configured line count");
    }
    for (const std::string_view line : page.lines) {
        if (line.size() > limits.max_line_chars) {
            throw std::length_error("review display line exceeds configured width");
        }
    }
}

}  // namespace

ReviewDisplayFrame render_review_page(const ReviewPage& page, std::size_t page_index, std::size_t total_pages,
                                      ReviewDisplayLimits limits) {
    validate_display_bounds(page, page_index, total_pages, limits);

    ReviewDisplayFrame frame;
    frame.title = std::string{page.title};
    frame.page_indicator = "Page " + std::to_string(page_index + 1) + "/" + std::to_string(total_pages);
    frame.body_lines.reserve(page.lines.size());
    for (const std::string_view line : page.lines) {
        frame.body_lines.emplace_back(line);
    }
    frame.action_hint = action_hint_for(page.action);
    return frame;
}

}  // namespace nostrseal
