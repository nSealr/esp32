#include "esp_log.h"

namespace {
constexpr const char* kTag = "nostrseal";
}

extern "C" void app_main(void) {
    ESP_LOGI(kTag, "NostrSeal ESP32-S3 USB signer scaffold booted");
    ESP_LOGW(kTag, "Signing is disabled in this scaffold until storage, review, approval, and tests are implemented");
}
