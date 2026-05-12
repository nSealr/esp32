#include "t_display_s3_review_state.hpp"

namespace nsealr_esp32 {

void start_t_display_s3_review_activity(TDisplayS3ReviewActivity& activity, std::uint32_t now_tick) {
    activity.active = true;
    activity.last_activity_tick = now_tick;
}

void record_t_display_s3_review_activity(TDisplayS3ReviewActivity& activity, std::uint32_t now_tick) {
    if (!activity.active) {
        return;
    }
    activity.last_activity_tick = now_tick;
}

void clear_t_display_s3_review_activity(TDisplayS3ReviewActivity& activity) {
    activity.active = false;
    activity.last_activity_tick = 0;
}

bool t_display_s3_review_activity_active(const TDisplayS3ReviewActivity& activity) {
    return activity.active;
}

bool t_display_s3_review_activity_expired(
    const TDisplayS3ReviewActivity& activity,
    std::uint32_t now_tick,
    std::uint32_t timeout_ticks) {
    if (!activity.active) {
        return false;
    }
    return (now_tick - activity.last_activity_tick) >= timeout_ticks;
}

}
