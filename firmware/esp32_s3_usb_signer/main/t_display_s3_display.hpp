#pragma once

#include "esp_err.h"
#include "esp_lcd_io_i80.h"
#include "esp_lcd_types.h"

#include "t_display_s3_raster.hpp"

namespace nostrseal_esp32 {

struct TDisplayS3Display {
    esp_lcd_i80_bus_handle_t i80_bus = nullptr;
    esp_lcd_panel_io_handle_t io = nullptr;
    esp_lcd_panel_handle_t panel = nullptr;
    bool display_driver_active = false;
};

esp_err_t initialize_t_display_s3_display(TDisplayS3Display& display);
esp_err_t draw_t_display_s3_boot_frame(TDisplayS3Display& display);
esp_err_t draw_t_display_s3_review_frame(
    TDisplayS3Display& display,
    const nostrseal::ReviewDisplayFrame& frame);

}  // namespace nostrseal_esp32
