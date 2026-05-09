#pragma once

#include "nostrseal/review_display.hpp"

namespace nostrseal_esp32 {

nostrseal::ReviewDisplayFrame build_t_display_s3_ready_frame();
nostrseal::ReviewDisplayFrame build_t_display_s3_review_decision_frame(bool approved);
nostrseal::ReviewDisplayFrame build_t_display_s3_review_timeout_frame();
nostrseal::ReviewDisplayFrame build_t_display_s3_request_error_frame();

}  // namespace nostrseal_esp32
