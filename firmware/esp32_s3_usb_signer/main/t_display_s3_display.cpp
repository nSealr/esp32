#include "t_display_s3_display.hpp"

#include "driver/gpio.h"
#include "esp_heap_caps.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_io_i80.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_st7789.h"
#include "esp_log.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "t_display_s3_board.hpp"

namespace nostrseal_esp32 {
namespace {

constexpr const char* kTag = "nostrseal-display";
constexpr int kTDisplayS3PixelClockHz = 8 * 1000 * 1000;
constexpr int kTDisplayS3TransferRows = 16;
constexpr int kTDisplayS3CommandBits = 8;
constexpr int kTDisplayS3ParameterBits = 8;
constexpr int kTDisplayS3DataBusWidth = 8;
constexpr uint16_t kColorBlack = 0x0000;
constexpr uint16_t kColorWhite = 0xFFFF;
constexpr uint16_t kColorBlue = 0x001F;
constexpr uint16_t kColorDarkBlue = 0x0008;
constexpr uint16_t kColorGreen = 0x07E0;
constexpr uint16_t kColorAmber = 0xFEA0;
constexpr int kSt7789NoOpCommand = 0x00;
constexpr std::size_t kTDisplayS3ReviewTitleChars = 18;
constexpr std::size_t kTDisplayS3ReviewBodyLines = 5;
constexpr std::size_t kTDisplayS3ReviewLineChars = 26;
constexpr int kGlyphWidth = 5;
constexpr int kGlyphHeight = 7;
constexpr int kGlyphSpacing = 1;
constexpr int kHeaderHeight = 30;
constexpr int kHeaderRightMargin = 10;
constexpr int kFooterY = 148;
constexpr int kFooterActionScale = 2;
constexpr int kBodyY = 42;
constexpr int kBodyLineHeight = 20;

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

uint16_t boot_frame_color_for(int x, int y) {
    if (x < 4 || x >= kTDisplayS3LogicalDisplayWidth - 4 || y < 4 ||
        y >= kTDisplayS3LogicalDisplayHeight - 4) {
        return kColorWhite;
    }
    if (y < 56) {
        return kColorBlue;
    }
    if (((x / 16) + (y / 16)) % 2 == 0) {
        return kColorGreen;
    }
    return kColorBlack;
}

std::array<uint8_t, kGlyphHeight> glyph_rows_for(char ch) {
    if (ch >= 'a' && ch <= 'z') {
        ch = static_cast<char>(ch - ('a' - 'A'));
    }

    switch (ch) {
        case 'A': return {0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11};
        case 'B': return {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E};
        case 'C': return {0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E};
        case 'D': return {0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E};
        case 'E': return {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F};
        case 'F': return {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10};
        case 'G': return {0x0E, 0x11, 0x10, 0x13, 0x11, 0x11, 0x0F};
        case 'H': return {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11};
        case 'I': return {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1F};
        case 'J': return {0x01, 0x01, 0x01, 0x01, 0x11, 0x11, 0x0E};
        case 'K': return {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11};
        case 'L': return {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F};
        case 'M': return {0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11};
        case 'N': return {0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11};
        case 'O': return {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E};
        case 'P': return {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10};
        case 'Q': return {0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D};
        case 'R': return {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11};
        case 'S': return {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E};
        case 'T': return {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
        case 'U': return {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E};
        case 'V': return {0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04};
        case 'W': return {0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0A};
        case 'X': return {0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11};
        case 'Y': return {0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04};
        case 'Z': return {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F};
        case '0': return {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E};
        case '1': return {0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E};
        case '2': return {0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F};
        case '3': return {0x1E, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1E};
        case '4': return {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02};
        case '5': return {0x1F, 0x10, 0x10, 0x1E, 0x01, 0x01, 0x1E};
        case '6': return {0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E};
        case '7': return {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08};
        case '8': return {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E};
        case '9': return {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C};
        case '/': return {0x01, 0x01, 0x02, 0x04, 0x08, 0x10, 0x10};
        case ':': return {0x00, 0x04, 0x04, 0x00, 0x04, 0x04, 0x00};
        case '-': return {0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00};
        case '.': return {0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C};
        case ' ': return {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        default: return {0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04};
    }
}

bool text_pixel_active(std::string_view text, int origin_x, int origin_y, int scale, int x, int y) {
    if (x < origin_x || y < origin_y) {
        return false;
    }
    const int rel_x = x - origin_x;
    const int rel_y = y - origin_y;
    const int text_height = kGlyphHeight * scale;
    if (rel_y >= text_height) {
        return false;
    }

    const int cell_width = (kGlyphWidth + kGlyphSpacing) * scale;
    const int char_index = rel_x / cell_width;
    if (char_index < 0 || static_cast<std::size_t>(char_index) >= text.size()) {
        return false;
    }
    const int local_x = (rel_x % cell_width) / scale;
    if (local_x >= kGlyphWidth) {
        return false;
    }
    const int local_y = rel_y / scale;
    const auto rows = glyph_rows_for(text[static_cast<std::size_t>(char_index)]);
    return ((rows[static_cast<std::size_t>(local_y)] >> (kGlyphWidth - 1 - local_x)) & 0x01) != 0;
}

bool draw_text(std::string_view text, int origin_x, int origin_y, int scale, int x, int y) {
    return text_pixel_active(text, origin_x, origin_y, scale, x, y);
}

int text_width_px(std::string_view text, int scale) {
    if (text.empty()) {
        return 0;
    }
    return static_cast<int>(text.size()) * (kGlyphWidth + kGlyphSpacing) * scale;
}

int right_aligned_text_x(std::string_view text, int scale, int right_margin) {
    return std::max(0, kTDisplayS3LogicalDisplayWidth - right_margin - text_width_px(text, scale));
}

uint16_t review_frame_color_for(const nostrseal::ReviewDisplayFrame& frame, int x, int y) {
    if (y < kHeaderHeight) {
        if (draw_text(frame.title, 10, 7, 2, x, y)) {
            return kColorWhite;
        }
        if (draw_text(
                frame.page_indicator,
                right_aligned_text_x(frame.page_indicator, 1, kHeaderRightMargin),
                9,
                1,
                x,
                y)) {
            return kColorGreen;
        }
        return kColorDarkBlue;
    }

    for (std::size_t line = 0; line < frame.body_lines.size(); ++line) {
        if (line >= kTDisplayS3ReviewBodyLines) {
            break;
        }
        if (draw_text(frame.body_lines[line], 10, kBodyY + (static_cast<int>(line) * kBodyLineHeight), 2, x, y)) {
            return kColorWhite;
        }
    }

    if (y >= kFooterY) {
        if (draw_text(frame.action_hint, 10, kFooterY + 4, kFooterActionScale, x, y)) {
            return kColorBlack;
        }
        return kColorAmber;
    }

    return kColorBlack;
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
                draw_buffer[(row * kTDisplayS3LogicalDisplayWidth) + x] = boot_frame_color_for(x, y + row);
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

nostrseal::ReviewDisplayLimits t_display_s3_review_limits() {
    return nostrseal::ReviewDisplayLimits{
        .max_title_chars = kTDisplayS3ReviewTitleChars,
        .max_body_lines = kTDisplayS3ReviewBodyLines,
        .max_line_chars = kTDisplayS3ReviewLineChars,
    };
}

esp_err_t draw_t_display_s3_review_frame(TDisplayS3Display& display, const nostrseal::ReviewDisplayFrame& frame) {
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
                    review_frame_color_for(frame, x, y + row);
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

}  // namespace nostrseal_esp32
