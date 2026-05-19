#pragma once

#include <vector>

#include "nsealr/qr_envelope.hpp"
#include "nsealr/signer_identity.hpp"
#include "nsealr/trusted_review.hpp"

namespace nsealr {

std::vector<TrustedReviewPage> build_qr_review_pages(const QrSigningRequest& request);
std::vector<TrustedReviewPage> build_qr_review_pages(
    const QrSigningRequest& request,
    const SignerIdentity& identity);
std::vector<TrustedReviewPage> build_qr_display_review_pages(
    const QrSigningRequest& request,
    ReviewDisplayLimits limits = {});
std::vector<TrustedReviewPage> build_qr_display_review_pages(
    const QrSigningRequest& request,
    const SignerIdentity& identity,
    ReviewDisplayLimits limits = {});
TrustedReviewRequest build_qr_trusted_review_request(const QrSigningRequest& request);
TrustedReviewRequest build_qr_trusted_review_request(
    const QrSigningRequest& request,
    const SignerIdentity& identity);
TrustedReviewRequest build_qr_display_review_request(
    const QrSigningRequest& request,
    ReviewDisplayLimits limits = {});
TrustedReviewRequest build_qr_display_review_request(
    const QrSigningRequest& request,
    const SignerIdentity& identity,
    ReviewDisplayLimits limits = {});
TrustedReviewSession begin_qr_trusted_review(const QrSigningRequest& request, ReviewDisplayLimits limits = {});
TrustedReviewSession begin_qr_trusted_review(
    const QrSigningRequest& request,
    const SignerIdentity& identity,
    ReviewDisplayLimits limits = {});

}  // namespace nsealr
