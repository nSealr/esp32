#pragma once

#include <cstdint>

namespace nostrseal_esp32 {

struct TDisplayS3ReviewActivity {
    bool active = false;
    std::uint32_t last_activity_tick = 0;
};

void start_t_display_s3_review_activity(TDisplayS3ReviewActivity& activity, std::uint32_t now_tick);
void record_t_display_s3_review_activity(TDisplayS3ReviewActivity& activity, std::uint32_t now_tick);
void clear_t_display_s3_review_activity(TDisplayS3ReviewActivity& activity);
bool t_display_s3_review_activity_active(const TDisplayS3ReviewActivity& activity);
bool t_display_s3_review_activity_expired(
    const TDisplayS3ReviewActivity& activity,
    std::uint32_t now_tick,
    std::uint32_t timeout_ticks);

}
