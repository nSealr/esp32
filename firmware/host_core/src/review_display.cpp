#include "nostrseal/review_display.hpp"

#include "nostrseal/utf8.hpp"

#include <stdexcept>
#include <utility>

namespace nostrseal {

namespace {

std::string action_hint_for(ReviewPageAction action) {
    if (action == ReviewPageAction::Next) {
        return "Next";
    }
    return "Approve / Reject";
}

void validate_display_limits(ReviewDisplayLimits limits) {
    if (limits.max_title_chars == 0 || limits.max_body_lines == 0 || limits.max_line_chars == 0 ||
        limits.max_compact_body_lines == 0 || limits.max_compact_line_chars == 0) {
        throw std::invalid_argument("review display limits must be non-zero");
    }
}

bool compact_style(ReviewBodyLineStyle style) {
    return style == ReviewBodyLineStyle::Meta ||
           style == ReviewBodyLineStyle::Value;
}

std::string truncate_for_display(const std::string& text, std::size_t max_chars, bool force_ellipsis = false) {
    auto display_char_count = [](std::string_view value) {
        std::size_t count = 0;
        std::size_t offset = 0;
        while (offset < value.size()) {
            std::uint32_t codepoint = 0;
            const std::size_t before = offset;
            (void)decode_next_utf8_codepoint(value, offset, codepoint);
            if (offset == before) {
                ++offset;
            }
            ++count;
        }
        return count;
    };

    if (display_char_count(text) <= max_chars && !force_ellipsis) {
        return text;
    }
    if (max_chars <= 3) {
        return std::string(max_chars, '.');
    }
    std::string out;
    std::size_t copied = 0;
    std::size_t offset = 0;
    while (offset < text.size() && copied < max_chars - 3U) {
        const std::size_t start = offset;
        std::uint32_t codepoint = 0;
        (void)decode_next_utf8_codepoint(text, offset, codepoint);
        if (offset == start) {
            ++offset;
        }
        out += text.substr(start, offset - start);
        ++copied;
    }
    out += "...";
    return out;
}

std::vector<std::string> wrap_line(std::string_view line, std::size_t width) {
    if (line.empty()) {
        return {""};
    }

    std::vector<std::string> wrapped;
    std::size_t position = 0;
    std::string current;
    std::size_t current_chars = 0;
    while (position < line.size()) {
        const std::size_t start = position;
        std::uint32_t codepoint = 0;
        (void)decode_next_utf8_codepoint(line, position, codepoint);
        if (position == start) {
            ++position;
        }
        if (current_chars == width) {
            wrapped.push_back(std::move(current));
            current.clear();
            current_chars = 0;
        }
        current += line.substr(start, position - start);
        ++current_chars;
    }
    if (!current.empty()) {
        wrapped.push_back(std::move(current));
    }
    return wrapped;
}

struct BoundedBodyLines {
    std::vector<std::string> lines;
    std::vector<ReviewBodyLineStyle> styles;
};

BoundedBodyLines bounded_body_lines(const ReviewPage& page, ReviewDisplayLimits limits) {
    std::vector<std::string> wrapped;
    std::vector<ReviewBodyLineStyle> styles;
    bool has_compact_style = false;
    for (std::size_t index = 0; index < page.lines.size(); ++index) {
        const ReviewBodyLineStyle style =
            index < page.body_line_styles.size() ? page.body_line_styles[index] : ReviewBodyLineStyle::Normal;
        has_compact_style = has_compact_style || compact_style(style);
        const std::size_t width = compact_style(style) ? limits.max_compact_line_chars : limits.max_line_chars;
        std::vector<std::string> line_parts = wrap_line(page.lines[index], width);
        styles.insert(styles.end(), line_parts.size(), style);
        wrapped.insert(wrapped.end(), line_parts.begin(), line_parts.end());
    }

    const std::size_t max_body_lines = has_compact_style ? limits.max_compact_body_lines : limits.max_body_lines;
    if (wrapped.size() > max_body_lines) {
        wrapped.resize(max_body_lines);
        styles.resize(max_body_lines);
        const ReviewBodyLineStyle style = styles.empty() ? ReviewBodyLineStyle::Normal : styles.back();
        const std::size_t width = compact_style(style) ? limits.max_compact_line_chars : limits.max_line_chars;
        wrapped.back() = truncate_for_display(wrapped.back(), width, true);
    }
    for (std::size_t index = 0; index < wrapped.size(); ++index) {
        const ReviewBodyLineStyle style = index < styles.size() ? styles[index] : ReviewBodyLineStyle::Normal;
        const std::size_t width = compact_style(style) ? limits.max_compact_line_chars : limits.max_line_chars;
        wrapped[index] = truncate_for_display(wrapped[index], width);
    }
    return BoundedBodyLines{std::move(wrapped), std::move(styles)};
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
    frame.page_indicator = page.page_indicator.empty()
                               ? "Page " + std::to_string(page_index + 1) + "/" + std::to_string(total_pages)
                               : std::string{page.page_indicator};
    BoundedBodyLines body = bounded_body_lines(page, limits);
    frame.body_lines = std::move(body.lines);
    frame.action_hint = action_hint_for(page.action);
    frame.body_line_styles = std::move(body.styles);
    return frame;
}

}  // namespace nostrseal
