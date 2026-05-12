#pragma once

#include <cstddef>
#include <optional>

namespace nsealr {

enum class ReviewButton {
    Next,
    Back,
    Approve,
    Reject,
};

class ReviewControlSession {
public:
    explicit ReviewControlSession(std::size_t page_count);

    [[nodiscard]] std::size_t current_page_index() const;
    [[nodiscard]] bool can_approve() const;
    [[nodiscard]] bool approved() const;
    [[nodiscard]] bool rejected() const;

    std::optional<bool> handle_button(ReviewButton button);

private:
    std::size_t page_count_;
    std::size_t current_page_index_ = 0;
    bool approved_ = false;
    bool rejected_ = false;
};

}  // namespace nsealr
