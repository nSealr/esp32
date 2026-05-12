#pragma once

#include "nsealr/review_display.hpp"

namespace nsealr_esp32 {

nsealr::ReviewDisplayFrame build_t_display_s3_ready_frame();
nsealr::ReviewDisplayFrame build_t_display_s3_review_decision_frame(bool approved);
nsealr::ReviewDisplayFrame build_t_display_s3_review_timeout_frame();
nsealr::ReviewDisplayFrame build_t_display_s3_request_error_frame();

}  // namespace nsealr_esp32
