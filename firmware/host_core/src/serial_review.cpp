#include "nostrseal/serial_review.hpp"

#include "nostrseal/qr_envelope.hpp"
#include "nostrseal/qr_review.hpp"

namespace nostrseal {

TrustedReviewRequest build_serial_sign_event_trusted_review_request(const std::string& request_json) {
    const QrSigningRequest request = parse_qr_signing_request(QrEnvelope{"serial", request_json});
    return build_qr_trusted_review_request(request);
}

TrustedReviewSession begin_serial_sign_event_trusted_review(
    const std::string& request_json,
    ReviewDisplayLimits limits) {
    return TrustedReviewSession{build_serial_sign_event_trusted_review_request(request_json), limits};
}

}  // namespace nostrseal
