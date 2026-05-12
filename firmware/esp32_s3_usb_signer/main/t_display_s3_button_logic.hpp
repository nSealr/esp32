#pragma once

#include <cstdint>
#include <optional>

#include "nsealr/review_controls.hpp"

namespace nsealr_esp32 {

constexpr int64_t kTDisplayS3ButtonDebounceMs = 40;
constexpr int64_t kTDisplayS3ButtonLongPressMs = 800;

struct TDisplayS3ButtonEvent {
    nsealr::ReviewButton button;
    int gpio;
    bool long_press;
};

struct TDisplayS3ButtonState {
    bool pressed = false;
    int64_t pressed_at_ms = 0;
};

std::optional<TDisplayS3ButtonEvent> update_t_display_s3_button_state(
    TDisplayS3ButtonState& state,
    bool pressed,
    int64_t now_ms,
    int gpio,
    nsealr::ReviewButton short_press_button,
    nsealr::ReviewButton long_press_button);

}  // namespace nsealr_esp32
