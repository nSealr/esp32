#pragma once

#include <vector>

#include "nostrseal/qr_envelope.hpp"
#include "nostrseal/trusted_review.hpp"

namespace nostrseal {

std::vector<TrustedReviewPage> build_qr_review_pages(const QrSigningRequest& request);

}  // namespace nostrseal
