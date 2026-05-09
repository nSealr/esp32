#pragma once

#include "esp_err.h"

#include "t_display_s3_button_logic.hpp"

namespace nostrseal_esp32 {

struct TDisplayS3Buttons {
    TDisplayS3ButtonState button1;
    TDisplayS3ButtonState button2;
    bool initialized = false;
};

esp_err_t initialize_t_display_s3_buttons(TDisplayS3Buttons& buttons);
std::optional<TDisplayS3ButtonEvent> poll_t_display_s3_button_event(TDisplayS3Buttons& buttons);
std::optional<nostrseal::ReviewButton> poll_t_display_s3_review_button(TDisplayS3Buttons& buttons);

}  // namespace nostrseal_esp32
