#include "t_display_s3_display.hpp"

#include "driver/gpio.h"
#include "esp_heap_caps.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_io_i80.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_st7789.h"
#include "esp_log.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "t_display_s3_board.hpp"
#include "t_display_s3_raster.hpp"

namespace nsealr_esp32 {
namespace {

constexpr const char* kTag = "nsealr-display";
constexpr int kTDisplayS3PixelClockHz = 8 * 1000 * 1000;
constexpr int kTDisplayS3TransferRows = 16;
constexpr int kTDisplayS3CommandBits = 8;
constexpr int kTDisplayS3ParameterBits = 8;
constexpr int kTDisplayS3DataBusWidth = 8;
constexpr int kSt7789NoOpCommand = 0x00;

esp_err_t configure_display_power_pins() {
    const gpio_config_t output_config = {
        .pin_bit_mask = (1ULL << kTDisplayS3DisplayPowerGpio) |
                        (1ULL << kTDisplayS3BacklightGpio) |
                        (1ULL << kTDisplayS3DisplayReadGpio),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&output_config);
    if (err != ESP_OK) {
        return err;
    }
    if ((err = gpio_set_level(static_cast<gpio_num_t>(kTDisplayS3DisplayPowerGpio), 1)) != ESP_OK) {
        return err;
    }
    if ((err = gpio_set_level(static_cast<gpio_num_t>(kTDisplayS3DisplayReadGpio), 1)) != ESP_OK) {
        return err;
    }
    return gpio_set_level(static_cast<gpio_num_t>(kTDisplayS3BacklightGpio), 0);
}

void set_backlight(bool enabled) {
    const int level = enabled ? 1 : 0;
    (void)gpio_set_level(static_cast<gpio_num_t>(kTDisplayS3BacklightGpio), level);
}

esp_err_t wait_for_t_display_s3_color_transfer(TDisplayS3Display& display) {
    return esp_lcd_panel_io_tx_param(display.io, kSt7789NoOpCommand, nullptr, 0);
}

}  // namespace

esp_err_t initialize_t_display_s3_display(TDisplayS3Display& display) {
    if (display.display_driver_active) {
        return ESP_OK;
    }

    esp_err_t err = configure_display_power_pins();
    if (err != ESP_OK) {
        ESP_LOGW(kTag, "display power pin setup failed: %s", esp_err_to_name(err));
        return err;
    }

    esp_lcd_i80_bus_config_t bus_config = {
        .dc_gpio_num = kTDisplayS3DisplayDcGpio,
        .wr_gpio_num = kTDisplayS3DisplayWriteGpio,
        .clk_src = LCD_CLK_SRC_DEFAULT,
        .data_gpio_nums = {
            kTDisplayS3DisplayData0Gpio,
            kTDisplayS3DisplayData1Gpio,
            kTDisplayS3DisplayData2Gpio,
            kTDisplayS3DisplayData3Gpio,
            kTDisplayS3DisplayData4Gpio,
            kTDisplayS3DisplayData5Gpio,
            kTDisplayS3DisplayData6Gpio,
            kTDisplayS3DisplayData7Gpio,
        },
        .bus_width = kTDisplayS3DataBusWidth,
        .max_transfer_bytes = kTDisplayS3LogicalDisplayWidth * kTDisplayS3TransferRows * sizeof(uint16_t),
        .dma_burst_size = 64,
        .sram_trans_align = 0,
    };
    if ((err = esp_lcd_new_i80_bus(&bus_config, &display.i80_bus)) != ESP_OK) {
        ESP_LOGW(kTag, "i80 bus setup failed: %s", esp_err_to_name(err));
        return err;
    }

    esp_lcd_panel_io_i80_config_t io_config = {
        .cs_gpio_num = kTDisplayS3DisplayCsGpio,
        .pclk_hz = kTDisplayS3PixelClockHz,
        .trans_queue_depth = 10,
        .on_color_trans_done = nullptr,
        .user_ctx = nullptr,
        .lcd_cmd_bits = kTDisplayS3CommandBits,
        .lcd_param_bits = kTDisplayS3ParameterBits,
        .dc_levels = {
            .dc_idle_level = 0,
            .dc_cmd_level = 0,
            .dc_dummy_level = 0,
            .dc_data_level = 1,
        },
        .flags = {
            .cs_active_high = 0,
            .reverse_color_bits = 0,
            .swap_color_bytes = 1,
            .pclk_active_neg = 0,
            .pclk_idle_low = 0,
        },
    };
    if ((err = esp_lcd_new_panel_io_i80(display.i80_bus, &io_config, &display.io)) != ESP_OK) {
        ESP_LOGW(kTag, "i80 panel IO setup failed: %s", esp_err_to_name(err));
        return err;
    }

    esp_lcd_panel_dev_config_t panel_config = {
        .reset_gpio_num = kTDisplayS3DisplayResetGpio,
        .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_RGB,
        .data_endian = LCD_RGB_DATA_ENDIAN_BIG,
        .bits_per_pixel = 16,
        .flags = {
            .reset_active_high = 0,
        },
        .vendor_config = nullptr,
    };
    if ((err = esp_lcd_new_panel_st7789(display.io, &panel_config, &display.panel)) != ESP_OK) {
        ESP_LOGW(kTag, "ST7789 panel setup failed: %s", esp_err_to_name(err));
        return err;
    }
    if ((err = esp_lcd_panel_reset(display.panel)) != ESP_OK) {
        return err;
    }
    if ((err = esp_lcd_panel_init(display.panel)) != ESP_OK) {
        return err;
    }
    if ((err = esp_lcd_panel_invert_color(display.panel, true)) != ESP_OK) {
        return err;
    }
    if ((err = esp_lcd_panel_swap_xy(display.panel, true)) != ESP_OK) {
        return err;
    }
    if ((err = esp_lcd_panel_mirror(display.panel, true, false)) != ESP_OK) {
        return err;
    }
    if ((err = esp_lcd_panel_set_gap(
             display.panel,
             kTDisplayS3LogicalDisplayXGap,
             kTDisplayS3LogicalDisplayYGap)) != ESP_OK) {
        return err;
    }
    if ((err = esp_lcd_panel_disp_on_off(display.panel, true)) != ESP_OK) {
        return err;
    }

    set_backlight(true);
    display.display_driver_active = true;
    ESP_LOGI(kTag, "T-Display S3 ST7789 display driver active");
    return ESP_OK;
}

esp_err_t draw_t_display_s3_boot_frame(TDisplayS3Display& display) {
    if (!display.display_driver_active || display.panel == nullptr || display.io == nullptr) {
        return ESP_ERR_INVALID_STATE;
    }

    const size_t pixels_per_chunk = kTDisplayS3LogicalDisplayWidth * kTDisplayS3TransferRows;
    auto* draw_buffer = static_cast<uint16_t*>(esp_lcd_i80_alloc_draw_buffer(
        display.io,
        pixels_per_chunk * sizeof(uint16_t),
        MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL));
    if (draw_buffer == nullptr) {
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = ESP_OK;
    for (int y = 0; y < kTDisplayS3LogicalDisplayHeight && err == ESP_OK; y += kTDisplayS3TransferRows) {
        const int rows = std::min(kTDisplayS3TransferRows, kTDisplayS3LogicalDisplayHeight - y);
        for (int row = 0; row < rows; ++row) {
            for (int x = 0; x < kTDisplayS3LogicalDisplayWidth; ++x) {
                draw_buffer[(row * kTDisplayS3LogicalDisplayWidth) + x] =
                    t_display_s3_boot_frame_color_for(x, y + row);
            }
        }
        err = esp_lcd_panel_draw_bitmap(
            display.panel,
            0,
            y,
            kTDisplayS3LogicalDisplayWidth,
            y + rows,
            draw_buffer);
        if (err == ESP_OK) {
            err = wait_for_t_display_s3_color_transfer(display);
        }
    }

    heap_caps_free(draw_buffer);
    return err;
}

esp_err_t draw_t_display_s3_review_frame(TDisplayS3Display& display, const nsealr::ReviewDisplayFrame& frame) {
    if (!display.display_driver_active || display.panel == nullptr || display.io == nullptr) {
        return ESP_ERR_INVALID_STATE;
    }

    const size_t pixels_per_chunk = kTDisplayS3LogicalDisplayWidth * kTDisplayS3TransferRows;
    auto* draw_buffer = static_cast<uint16_t*>(esp_lcd_i80_alloc_draw_buffer(
        display.io,
        pixels_per_chunk * sizeof(uint16_t),
        MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL));
    if (draw_buffer == nullptr) {
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = ESP_OK;
    for (int y = 0; y < kTDisplayS3LogicalDisplayHeight && err == ESP_OK; y += kTDisplayS3TransferRows) {
        const int rows = std::min(kTDisplayS3TransferRows, kTDisplayS3LogicalDisplayHeight - y);
        for (int row = 0; row < rows; ++row) {
            for (int x = 0; x < kTDisplayS3LogicalDisplayWidth; ++x) {
                draw_buffer[(row * kTDisplayS3LogicalDisplayWidth) + x] =
                    t_display_s3_review_frame_color_for(frame, x, y + row);
            }
        }
        err = esp_lcd_panel_draw_bitmap(
            display.panel,
            0,
            y,
            kTDisplayS3LogicalDisplayWidth,
            y + rows,
            draw_buffer);
        if (err == ESP_OK) {
            err = wait_for_t_display_s3_color_transfer(display);
        }
    }

    heap_caps_free(draw_buffer);
    return err;
}

}  // namespace nsealr_esp32
