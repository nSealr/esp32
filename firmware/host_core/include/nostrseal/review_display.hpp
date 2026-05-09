#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace nostrseal {

enum class ReviewPageAction {
    Next,
    ApproveOrReject,
};

enum class ReviewBodyLineStyle {
    Normal,
    Meta,
    Label,
    Value,
};

struct ReviewPage {
    std::string_view title;
    std::vector<std::string_view> lines;
    ReviewPageAction action;
    std::string_view page_indicator{};
    std::vector<ReviewBodyLineStyle> body_line_styles{};
};

struct ReviewDisplayLimits {
    std::size_t max_title_chars = 24;
    std::size_t max_body_lines = 6;
    std::size_t max_line_chars = 64;
    std::size_t max_compact_body_lines = 9;
    std::size_t max_compact_line_chars = 48;
};

struct ReviewDisplayFrame {
    std::string title;
    std::string page_indicator;
    std::vector<std::string> body_lines;
    std::string action_hint;
    std::vector<ReviewBodyLineStyle> body_line_styles{};
};

ReviewDisplayFrame render_review_page(
    const ReviewPage& page,
    std::size_t page_index,
    std::size_t total_pages,
    ReviewDisplayLimits limits = {});

}  // namespace nostrseal
