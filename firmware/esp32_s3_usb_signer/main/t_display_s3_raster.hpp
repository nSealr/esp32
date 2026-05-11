#pragma once

#include <cstdint>

#include "nostrseal/review_display.hpp"

namespace nostrseal_esp32 {

constexpr uint16_t kTDisplayS3ColorBlack = 0x0000;
constexpr uint16_t kTDisplayS3ColorWhite = 0xFFFF;
constexpr uint16_t kTDisplayS3ColorBlue = 0x001F;
constexpr uint16_t kTDisplayS3ColorDarkBlue = 0x0008;
constexpr uint16_t kTDisplayS3ColorGreen = 0x07E0;
constexpr uint16_t kTDisplayS3ColorYellow = 0xFFE0;
constexpr uint16_t kTDisplayS3ColorAmber = 0xFEA0;

uint16_t t_display_s3_boot_frame_color_for(int x, int y);
nostrseal::ReviewDisplayLimits t_display_s3_review_limits();
uint16_t t_display_s3_review_frame_color_for(const nostrseal::ReviewDisplayFrame& frame, int x, int y);

}  // namespace nostrseal_esp32
