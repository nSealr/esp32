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

struct ReviewPage {
    std::string_view title;
    std::vector<std::string_view> lines;
    ReviewPageAction action;
};

struct ReviewDisplayLimits {
    std::size_t max_title_chars = 24;
    std::size_t max_body_lines = 6;
    std::size_t max_line_chars = 64;
};

struct ReviewDisplayFrame {
    std::string title;
    std::string page_indicator;
    std::vector<std::string> body_lines;
    std::string action_hint;
};

ReviewDisplayFrame render_review_page(
    const ReviewPage& page,
    std::size_t page_index,
    std::size_t total_pages,
    ReviewDisplayLimits limits = {});

}  // namespace nostrseal
