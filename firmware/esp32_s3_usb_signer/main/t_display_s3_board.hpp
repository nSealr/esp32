#pragma once

namespace nsealr_esp32 {

constexpr int kTDisplayS3DisplayWidth = 170;
constexpr int kTDisplayS3DisplayHeight = 320;
constexpr int kTDisplayS3BacklightGpio = 38;
constexpr int kTDisplayS3DisplayPowerGpio = 15;
constexpr int kTDisplayS3DisplayResetGpio = 5;
constexpr int kTDisplayS3DisplayCsGpio = 6;
constexpr int kTDisplayS3DisplayDcGpio = 7;
constexpr int kTDisplayS3DisplayWriteGpio = 8;
constexpr int kTDisplayS3DisplayReadGpio = 9;
constexpr int kTDisplayS3DisplayData0Gpio = 39;
constexpr int kTDisplayS3DisplayData1Gpio = 40;
constexpr int kTDisplayS3DisplayData2Gpio = 41;
constexpr int kTDisplayS3DisplayData3Gpio = 42;
constexpr int kTDisplayS3DisplayData4Gpio = 45;
constexpr int kTDisplayS3DisplayData5Gpio = 46;
constexpr int kTDisplayS3DisplayData6Gpio = 47;
constexpr int kTDisplayS3DisplayData7Gpio = 48;
constexpr int kTDisplayS3Button1Gpio = 0;
constexpr int kTDisplayS3Button2Gpio = 14;
constexpr int kTDisplayS3DisplayXGap = 35;
constexpr int kTDisplayS3DisplayYGap = 0;
constexpr int kTDisplayS3LogicalDisplayWidth = 320;
constexpr int kTDisplayS3LogicalDisplayHeight = 170;
constexpr int kTDisplayS3LogicalDisplayXGap = 0;
constexpr int kTDisplayS3LogicalDisplayYGap = 35;

struct TDisplayS3BoardProfile {
    const char* name;
    const char* display_driver;
    int display_width;
    int display_height;
    int backlight_gpio;
    int display_power_gpio;
    int button1_gpio;
    int button2_gpio;
    bool touch_approval_allowed;
    bool camera_present;
};

const TDisplayS3BoardProfile& t_display_s3_board_profile();

}  // namespace nsealr_esp32
