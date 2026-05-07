#include "nostrseal/qr_review_flow.hpp"

#include <utility>

#include "nostrseal/qr_envelope.hpp"

namespace nostrseal {
namespace {

TrustedReviewRequest review_request_from_qr(const std::string& qr_envelope) {
    const QrEnvelope envelope = decode_qr_envelope(qr_envelope);
    const QrSigningRequest request = parse_qr_signing_request(envelope);
    return build_qr_trusted_review_request(request);
}

}  // namespace

QrReviewFlow::QrReviewFlow(const std::string& qr_envelope, ReviewDisplayLimits limits)
    : review_request_(review_request_from_qr(qr_envelope)), session_(TrustedReviewRequest{review_request_}, limits) {}

const std::string& QrReviewFlow::request_id() const {
    return review_request_.request_id;
}

const std::string& QrReviewFlow::approval_digest() const {
    return review_request_.approval_digest;
}

ReviewDisplayFrame QrReviewFlow::current_frame() const {
    return session_.current_frame();
}

ApprovalDecision QrReviewFlow::decision() const {
    return session_.decision();
}

bool QrReviewFlow::approved_for_signing() const {
    return session_.can_sign();
}

std::optional<bool> QrReviewFlow::handle_button(ReviewButton button) {
    return session_.handle_button(button);
}

std::vector<QrReviewTranscriptStep> run_qr_review_transcript(
    const std::string& qr_envelope,
    const std::vector<ReviewButton>& buttons,
    ReviewDisplayLimits limits) {
    QrReviewFlow flow{qr_envelope, limits};
    std::vector<QrReviewTranscriptStep> transcript;
    transcript.reserve(buttons.size());
    for (const ReviewButton button : buttons) {
        ReviewDisplayFrame frame = flow.current_frame();
        std::optional<bool> decision = flow.handle_button(button);
        transcript.push_back(QrReviewTranscriptStep{
            std::move(frame),
            button,
            decision,
            flow.approved_for_signing(),
        });
    }
    return transcript;
}

}  // namespace nostrseal
