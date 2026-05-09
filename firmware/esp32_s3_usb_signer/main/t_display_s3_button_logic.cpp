#include "t_display_s3_button_logic.hpp"

namespace nostrseal_esp32 {

std::optional<TDisplayS3ButtonEvent> update_t_display_s3_button_state(
    TDisplayS3ButtonState& state,
    bool pressed,
    int64_t now_ms,
    int gpio,
    nostrseal::ReviewButton short_press_button,
    nostrseal::ReviewButton long_press_button) {
    if (pressed && !state.pressed) {
        state.pressed = true;
        state.pressed_at_ms = now_ms;
        return std::nullopt;
    }

    if (!pressed && state.pressed) {
        const int64_t duration_ms = now_ms - state.pressed_at_ms;
        state.pressed = false;
        state.pressed_at_ms = 0;
        if (duration_ms < kTDisplayS3ButtonDebounceMs) {
            return std::nullopt;
        }
        const bool long_press = duration_ms >= kTDisplayS3ButtonLongPressMs;
        return TDisplayS3ButtonEvent{
            .button = long_press ? long_press_button : short_press_button,
            .gpio = gpio,
            .long_press = long_press,
        };
    }

    return std::nullopt;
}

}  // namespace nostrseal_esp32
