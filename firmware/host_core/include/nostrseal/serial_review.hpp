#pragma once

#include <string>

#include "nostrseal/trusted_review.hpp"

namespace nostrseal {

TrustedReviewRequest build_serial_sign_event_trusted_review_request(const std::string& request_json);
TrustedReviewSession begin_serial_sign_event_trusted_review(
    const std::string& request_json,
    ReviewDisplayLimits limits = {});

}  // namespace nostrseal
