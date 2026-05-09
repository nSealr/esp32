#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <cstdio>
#include <exception>
#include <string>
#include <string_view>
#include <vector>

#include "nostrseal/device_protocol.hpp"
#include "nostrseal/limits.hpp"
#include "nostrseal/review_display.hpp"
#include "nostrseal/serial_frame.hpp"
#include "t_display_s3_board.hpp"
#include "t_display_s3_display.hpp"

namespace {
constexpr const char* kTag = "nostrseal";

void write_transport_error(const char* payload_base64url) {
    const std::string response = nostrseal::encode_serial_frame(
        nostrseal::SerialFrame{nostrseal::FrameType::Error, payload_base64url});
    std::printf("%s", response.c_str());
    std::fflush(stdout);
}

void display_sign_event_review_preview(
    nostrseal_esp32::TDisplayS3Display& display,
    const nostrseal::SerialFrameHandlingResult& result) {
    if (!result.review_frame.has_value()) {
        return;
    }
    const esp_err_t display_status = nostrseal_esp32::draw_t_display_s3_review_frame(
        display,
        result.review_frame.value());
    if (display_status != ESP_OK) {
        ESP_LOGW(kTag, "T-Display S3 request review preview unavailable: %s", esp_err_to_name(display_status));
    }
}

void process_frame_line(const std::string& line, nostrseal_esp32::TDisplayS3Display& display) {
    try {
        const nostrseal::SerialFrameHandlingResult result = nostrseal::handle_serial_frame_with_review_preview(
            line,
            nostrseal_esp32::t_display_s3_review_limits());
        display_sign_event_review_preview(display, result);
        std::printf("%s", result.response_frame.c_str());
        std::fflush(stdout);
    } catch (const std::exception& exc) {
        ESP_LOGW(kTag, "Rejected serial frame: %s", exc.what());
        write_transport_error("eyJlcnJvciI6Im1hbGZvcm1lZF9mcmFtZSJ9");
    }
}

nostrseal::ReviewDisplayFrame build_display_smoke_review_frame() {
    nostrseal::ReviewPage page;
    page.title = "Event review";
    page.lines = std::vector<std::string_view>{
        "Kind 1",
        "Short text note",
        "Created 1710000000",
        "Content: display test",
    };
    page.action = nostrseal::ReviewPageAction::Next;

    return nostrseal::render_review_page(
        page,
        0,
        3,
        nostrseal_esp32::t_display_s3_review_limits());
}
}

extern "C" void app_main(void) {
    ESP_LOGI(kTag, "NostrSeal ESP32-S3 USB signer scaffold booted");
    ESP_LOGW(kTag, "Signing is disabled in this scaffold until storage, review, approval, and tests are implemented");
    ESP_LOGI(kTag, "USB serial frame handler ready for get_capabilities, get_public_key, and disabled sign_event");
    const auto& board = nostrseal_esp32::t_display_s3_board_profile();
    ESP_LOGI(kTag, "%s %dx%d %s profile compiled",
             board.name,
             board.display_width,
             board.display_height,
             board.display_driver);
    nostrseal_esp32::TDisplayS3Display display;
    esp_err_t display_status = nostrseal_esp32::initialize_t_display_s3_display(display);
    if (display_status == ESP_OK) {
        display_status = nostrseal_esp32::draw_t_display_s3_boot_frame(display);
    }
    if (display_status == ESP_OK) {
        vTaskDelay(pdMS_TO_TICKS(250));
        display_status = nostrseal_esp32::draw_t_display_s3_review_frame(
            display,
            build_display_smoke_review_frame());
    }
    if (display_status != ESP_OK) {
        ESP_LOGW(kTag, "T-Display S3 display review frame unavailable: %s", esp_err_to_name(display_status));
    }

    std::string line;
    line.reserve(512);

    while (true) {
        const int ch = std::getchar();
        if (ch == EOF) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        if (ch == '\r') {
            continue;
        }
        line.push_back(static_cast<char>(ch));
        if (line.size() > nostrseal::kMaxSerialFrameBytes) {
            ESP_LOGW(kTag, "Rejected overlong serial frame");
            line.clear();
            write_transport_error("eyJlcnJvciI6Im92ZXJsb25nX2ZyYW1lIn0");
            continue;
        }
        if (ch == '\n') {
            process_frame_line(line, display);
            line.clear();
        }
    }
}
