#pragma once

#include <cstdint>
#include <optional>

#include "nostrseal/review_controls.hpp"

namespace nostrseal_esp32 {

constexpr int64_t kTDisplayS3ButtonDebounceMs = 40;
constexpr int64_t kTDisplayS3ButtonLongPressMs = 800;

struct TDisplayS3ButtonEvent {
    nostrseal::ReviewButton button;
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
    nostrseal::ReviewButton short_press_button,
    nostrseal::ReviewButton long_press_button);

}  // namespace nostrseal_esp32
