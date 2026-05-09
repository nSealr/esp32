#include "nostrseal/review_controls.hpp"

#include <stdexcept>

namespace nostrseal {

ReviewControlSession::ReviewControlSession(std::size_t page_count) : page_count_(page_count) {
    if (page_count_ == 0) {
        throw std::invalid_argument("review control session requires at least one page");
    }
}

std::size_t ReviewControlSession::current_page_index() const {
    return current_page_index_;
}

bool ReviewControlSession::can_approve() const {
    return current_page_index_ == page_count_ - 1;
}

bool ReviewControlSession::approved() const {
    return approved_;
}

bool ReviewControlSession::rejected() const {
    return rejected_;
}

std::optional<bool> ReviewControlSession::handle_button(ReviewButton button) {
    if (approved_ || rejected_) {
        throw std::logic_error("review decision is already terminal");
    }

    if (button == ReviewButton::Next) {
        if (current_page_index_ + 1 < page_count_) {
            ++current_page_index_;
        }
        return std::nullopt;
    }

    if (button == ReviewButton::Back) {
        if (current_page_index_ > 0) {
            --current_page_index_;
        }
        return std::nullopt;
    }

    if (button == ReviewButton::Reject) {
        rejected_ = true;
        return false;
    }

    if (!can_approve()) {
        throw std::logic_error("approval requires viewing every review page");
    }
    approved_ = true;
    return true;
}

}  // namespace nostrseal
