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

void validate_display_limits(ReviewDisplayLimits limits) {
    if (limits.max_title_chars == 0 || limits.max_body_lines == 0 || limits.max_line_chars == 0) {
        throw std::invalid_argument("review display limits must be non-zero");
    }
}

std::string truncate_for_display(const std::string& text, std::size_t max_chars, bool force_ellipsis = false) {
    if (text.size() <= max_chars && !force_ellipsis) {
        return text;
    }
    if (max_chars <= 3) {
        return std::string(max_chars, '.');
    }
    return text.substr(0, max_chars - 3) + "...";
}

std::vector<std::string> wrap_line(std::string_view line, std::size_t width) {
    if (line.empty()) {
        return {""};
    }

    std::string text{line};
    std::vector<std::string> wrapped;
    std::size_t position = 0;
    while (position < text.size()) {
        const std::size_t remaining = text.size() - position;
        if (remaining <= width) {
            wrapped.push_back(text.substr(position));
            break;
        }

        std::size_t cut = width;
        const std::size_t space = text.rfind(' ', position + width - 1);
        if (space != std::string::npos && space >= position) {
            cut = space - position;
            if (cut == 0) {
                cut = width;
            }
        }
        wrapped.push_back(text.substr(position, cut));
        position += cut;
        while (position < text.size() && text[position] == ' ') {
            ++position;
        }
    }
    return wrapped;
}

std::vector<std::string> bounded_body_lines(const ReviewPage& page, ReviewDisplayLimits limits) {
    std::vector<std::string> wrapped;
    for (const std::string_view line : page.lines) {
        std::vector<std::string> line_parts = wrap_line(line, limits.max_line_chars);
        wrapped.insert(wrapped.end(), line_parts.begin(), line_parts.end());
    }

    if (wrapped.size() > limits.max_body_lines) {
        wrapped.resize(limits.max_body_lines);
        wrapped.back() = truncate_for_display(wrapped.back(), limits.max_line_chars, true);
    }
    for (std::string& line : wrapped) {
        line = truncate_for_display(line, limits.max_line_chars);
    }
    return wrapped;
}

void validate_display_bounds(const ReviewPage& page, std::size_t page_index, std::size_t total_pages,
                             ReviewDisplayLimits limits) {
    validate_display_limits(limits);
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
}

}  // namespace

ReviewDisplayFrame render_review_page(const ReviewPage& page, std::size_t page_index, std::size_t total_pages,
                                      ReviewDisplayLimits limits) {
    validate_display_bounds(page, page_index, total_pages, limits);

    ReviewDisplayFrame frame;
    frame.title = std::string{page.title};
    frame.page_indicator = "Page " + std::to_string(page_index + 1) + "/" + std::to_string(total_pages);
    frame.body_lines = bounded_body_lines(page, limits);
    frame.action_hint = action_hint_for(page.action);
    return frame;
}

}  // namespace nostrseal
