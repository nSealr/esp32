#include "t_display_s3_board.hpp"

namespace nostrseal_esp32 {

namespace {
constexpr TDisplayS3BoardProfile kProfile{
    .name = "LILYGO T-Display S3",
    .display_driver = "ST7789",
    .display_width = kTDisplayS3DisplayWidth,
    .display_height = kTDisplayS3DisplayHeight,
    .backlight_gpio = kTDisplayS3BacklightGpio,
    .display_power_gpio = kTDisplayS3DisplayPowerGpio,
    .touch_approval_allowed = false,
    .camera_present = false,
};
}  // namespace

const TDisplayS3BoardProfile& t_display_s3_board_profile() {
    return kProfile;
}

}  // namespace nostrseal_esp32
