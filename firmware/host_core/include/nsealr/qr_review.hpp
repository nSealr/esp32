#pragma once

#include <vector>

#include "nsealr/qr_envelope.hpp"
#include "nsealr/trusted_review.hpp"

namespace nsealr {

std::vector<TrustedReviewPage> build_qr_review_pages(const QrSigningRequest& request);
std::vector<TrustedReviewPage> build_qr_display_review_pages(
    const QrSigningRequest& request,
    ReviewDisplayLimits limits = {});
TrustedReviewRequest build_qr_trusted_review_request(const QrSigningRequest& request);
TrustedReviewRequest build_qr_display_review_request(
    const QrSigningRequest& request,
    ReviewDisplayLimits limits = {});
TrustedReviewSession begin_qr_trusted_review(const QrSigningRequest& request, ReviewDisplayLimits limits = {});

}  // namespace nsealr
