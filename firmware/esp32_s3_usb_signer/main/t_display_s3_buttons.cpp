#include "t_display_s3_buttons.hpp"

#include "driver/gpio.h"
#include "esp_timer.h"

#include <cstdint>
#include <optional>

#include "t_display_s3_board.hpp"

namespace nostrseal_esp32 {
namespace {

constexpr int kTDisplayS3ButtonActiveLevel = 0;
constexpr int64_t kTDisplayS3ButtonDebounceMs = 40;
constexpr int64_t kTDisplayS3ButtonLongPressMs = 800;

int64_t monotonic_ms() {
    return esp_timer_get_time() / 1000;
}

bool gpio_pressed(int gpio) {
    return gpio_get_level(static_cast<gpio_num_t>(gpio)) == kTDisplayS3ButtonActiveLevel;
}

std::optional<TDisplayS3ButtonEvent> poll_button(
    TDisplayS3ButtonState& state,
    int gpio,
    nostrseal::ReviewButton short_press_button,
    nostrseal::ReviewButton long_press_button) {
    const bool pressed = gpio_pressed(gpio);
    const int64_t now_ms = monotonic_ms();

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

}  // namespace

esp_err_t initialize_t_display_s3_buttons(TDisplayS3Buttons& buttons) {
    const gpio_config_t input_config = {
        .pin_bit_mask = (1ULL << kTDisplayS3Button1Gpio) | (1ULL << kTDisplayS3Button2Gpio),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    const esp_err_t err = gpio_config(&input_config);
    if (err == ESP_OK) {
        buttons.initialized = true;
    }
    return err;
}

std::optional<TDisplayS3ButtonEvent> poll_t_display_s3_button_event(TDisplayS3Buttons& buttons) {
    if (!buttons.initialized) {
        return std::nullopt;
    }

    if (std::optional<TDisplayS3ButtonEvent> event = poll_button(
            buttons.button1,
            kTDisplayS3Button1Gpio,
            nostrseal::ReviewButton::Back,
            nostrseal::ReviewButton::Reject)) {
        return event;
    }
    return poll_button(
        buttons.button2,
        kTDisplayS3Button2Gpio,
        nostrseal::ReviewButton::Next,
        nostrseal::ReviewButton::Approve);
}

std::optional<nostrseal::ReviewButton> poll_t_display_s3_review_button(TDisplayS3Buttons& buttons) {
    const std::optional<TDisplayS3ButtonEvent> event = poll_t_display_s3_button_event(buttons);
    if (!event.has_value()) {
        return std::nullopt;
    }
    return event->button;
}

}  // namespace nostrseal_esp32
