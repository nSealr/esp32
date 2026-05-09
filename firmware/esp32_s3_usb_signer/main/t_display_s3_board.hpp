#pragma once

namespace nostrseal_esp32 {

constexpr int kTDisplayS3DisplayWidth = 170;
constexpr int kTDisplayS3DisplayHeight = 320;
constexpr int kTDisplayS3BacklightGpio = 38;
constexpr int kTDisplayS3DisplayPowerGpio = 15;

struct TDisplayS3BoardProfile {
    const char* name;
    const char* display_driver;
    int display_width;
    int display_height;
    int backlight_gpio;
    int display_power_gpio;
    bool touch_approval_allowed;
    bool camera_present;
};

const TDisplayS3BoardProfile& t_display_s3_board_profile();

}  // namespace nostrseal_esp32
