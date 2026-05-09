#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <cstdio>
#include <exception>
#include <string>

#include "nostrseal/device_protocol.hpp"
#include "nostrseal/limits.hpp"
#include "nostrseal/serial_frame.hpp"
#include "t_display_s3_board.hpp"

namespace {
constexpr const char* kTag = "nostrseal";

void write_transport_error(const char* payload_base64url) {
    const std::string response = nostrseal::encode_serial_frame(
        nostrseal::SerialFrame{nostrseal::FrameType::Error, payload_base64url});
    std::printf("%s", response.c_str());
    std::fflush(stdout);
}

void process_frame_line(const std::string& line) {
    try {
        const std::string response = nostrseal::handle_serial_frame(line);
        std::printf("%s", response.c_str());
        std::fflush(stdout);
    } catch (const std::exception& exc) {
        ESP_LOGW(kTag, "Rejected serial frame: %s", exc.what());
        write_transport_error("eyJlcnJvciI6Im1hbGZvcm1lZF9mcmFtZSJ9");
    }
}
}

extern "C" void app_main(void) {
    ESP_LOGI(kTag, "NostrSeal ESP32-S3 USB signer scaffold booted");
    ESP_LOGW(kTag, "Signing is disabled in this scaffold until storage, review, approval, and tests are implemented");
    ESP_LOGI(kTag, "USB serial frame handler ready for get_capabilities, get_public_key, and disabled sign_event");
    const auto& board = nostrseal_esp32::t_display_s3_board_profile();
    ESP_LOGI(kTag, "%s %dx%d %s profile compiled; display and GPIO drivers disabled",
             board.name,
             board.display_width,
             board.display_height,
             board.display_driver);

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
            process_frame_line(line);
            line.clear();
        }
    }
}
