#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <cstdio>
#include <exception>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "nostrseal/device_protocol.hpp"
#include "nostrseal/limits.hpp"
#include "nostrseal/review_display.hpp"
#include "nostrseal/serial_frame.hpp"
#include "nostrseal/trusted_review.hpp"
#include "t_display_s3_board.hpp"
#include "t_display_s3_buttons.hpp"
#include "t_display_s3_display.hpp"

namespace {
constexpr const char* kTag = "nostrseal";

void write_transport_error(const char* payload_base64url) {
    const std::string response = nostrseal::encode_serial_frame(
        nostrseal::SerialFrame{nostrseal::FrameType::Error, payload_base64url});
    std::printf("%s", response.c_str());
    std::fflush(stdout);
}

void display_review_frame(
    nostrseal_esp32::TDisplayS3Display& display,
    const nostrseal::ReviewDisplayFrame& frame) {
    const esp_err_t display_status = nostrseal_esp32::draw_t_display_s3_review_frame(display, frame);
    if (display_status != ESP_OK) {
        ESP_LOGW(kTag, "T-Display S3 request review preview unavailable: %s", esp_err_to_name(display_status));
    }
}

void display_sign_event_review_preview(
    nostrseal_esp32::TDisplayS3Display& display,
    nostrseal::SerialFrameHandlingResult& result,
    std::optional<nostrseal::TrustedReviewSession>& active_review_session) {
    if (result.review_session.has_value()) {
        active_review_session = std::move(result.review_session);
        display_review_frame(display, active_review_session->current_frame());
        return;
    }
    if (result.review_frame.has_value()) {
        display_review_frame(display, result.review_frame.value());
    }
}

nostrseal::ReviewDisplayFrame build_review_decision_frame(bool approved) {
    nostrseal::ReviewDisplayFrame frame;
    frame.title = approved ? "Review OK" : "Rejected";
    frame.page_indicator = "Closed";
    frame.body_lines = std::vector<std::string>{
        "Not signed",
        "Signing disabled",
        "Send new request",
    };
    frame.action_hint = "Waiting";
    return frame;
}

void process_review_button(
    nostrseal_esp32::TDisplayS3Display& display,
    std::optional<nostrseal::TrustedReviewSession>& active_review_session,
    nostrseal::ReviewButton button) {
    if (!active_review_session.has_value()) {
        return;
    }
    try {
        const std::optional<bool> decision = active_review_session->handle_button(button);
        if (decision.has_value()) {
            display_review_frame(display, build_review_decision_frame(decision.value()));
            ESP_LOGW(kTag, "Review decision recorded. Signing remains disabled in this scaffold.");
            active_review_session.reset();
            return;
        }
        display_review_frame(display, active_review_session->current_frame());
    } catch (const std::exception& exc) {
        ESP_LOGW(kTag, "Rejected review button input: %s", exc.what());
        display_review_frame(display, active_review_session->current_frame());
    }
}

void poll_review_buttons(
    nostrseal_esp32::TDisplayS3Display& display,
    nostrseal_esp32::TDisplayS3Buttons& buttons,
    std::optional<nostrseal::TrustedReviewSession>& active_review_session) {
    const std::optional<nostrseal::ReviewButton> button =
        nostrseal_esp32::poll_t_display_s3_review_button(buttons);
    if (button.has_value()) {
        process_review_button(display, active_review_session, button.value());
    }
}

void process_frame_line(
    const std::string& line,
    nostrseal_esp32::TDisplayS3Display& display,
    std::optional<nostrseal::TrustedReviewSession>& active_review_session) {
    try {
        nostrseal::SerialFrameHandlingResult result = nostrseal::handle_serial_frame_with_review_preview(
            line,
            nostrseal_esp32::t_display_s3_review_limits());
        display_sign_event_review_preview(display, result, active_review_session);
        std::printf("%s", result.response_frame.c_str());
        std::fflush(stdout);
    } catch (const std::exception& exc) {
        ESP_LOGW(kTag, "Rejected serial frame: %s", exc.what());
        write_transport_error("eyJlcnJvciI6Im1hbGZvcm1lZF9mcmFtZSJ9");
    }
}

nostrseal::ReviewDisplayFrame build_display_ready_frame() {
    nostrseal::ReviewDisplayFrame frame;
    frame.title = "Ready";
    frame.page_indicator = "No request";
    frame.body_lines = std::vector<std::string>{
        "USB signer",
        "Send sign_event",
        "Signing disabled",
    };
    frame.action_hint = "Waiting";
    return frame;
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
            build_display_ready_frame());
    }
    if (display_status != ESP_OK) {
        ESP_LOGW(kTag, "T-Display S3 display review frame unavailable: %s", esp_err_to_name(display_status));
    }
    nostrseal_esp32::TDisplayS3Buttons buttons;
    const esp_err_t button_status = nostrseal_esp32::initialize_t_display_s3_buttons(buttons);
    if (button_status != ESP_OK) {
        ESP_LOGW(kTag, "T-Display S3 button input unavailable: %s", esp_err_to_name(button_status));
    }

    std::string line;
    line.reserve(512);
    std::optional<nostrseal::TrustedReviewSession> active_review_session;

    while (true) {
        poll_review_buttons(display, buttons, active_review_session);
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
            process_frame_line(line, display, active_review_session);
            line.clear();
        }
    }
}
