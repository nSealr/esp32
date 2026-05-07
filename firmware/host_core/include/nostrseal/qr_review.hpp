#pragma once

#include <vector>

#include "nostrseal/qr_envelope.hpp"
#include "nostrseal/trusted_review.hpp"

namespace nostrseal {

std::vector<TrustedReviewPage> build_qr_review_pages(const QrSigningRequest& request);
TrustedReviewRequest build_qr_trusted_review_request(const QrSigningRequest& request);
TrustedReviewSession begin_qr_trusted_review(const QrSigningRequest& request, ReviewDisplayLimits limits = {});

}  // namespace nostrseal
