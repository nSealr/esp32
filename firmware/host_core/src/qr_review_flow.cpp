#include "nsealr/qr_review_flow.hpp"

#include <stdexcept>
#include <utility>

#include "nsealr/qr_envelope.hpp"

namespace nsealr {
namespace {

TrustedReviewRequest review_request_from_qr(const std::string& qr_envelope, ReviewDisplayLimits limits) {
    const QrEnvelope envelope = decode_qr_envelope(qr_envelope);
    const QrSigningRequest request = parse_qr_signing_request(envelope);
    return build_qr_display_review_request(request, limits);
}

}  // namespace

QrReviewFlow::QrReviewFlow(const std::string& qr_envelope, ReviewDisplayLimits limits)
    : review_request_(review_request_from_qr(qr_envelope, limits)), session_(TrustedReviewRequest{review_request_}, limits) {}

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

QrReviewIoFlowResult run_qr_review_io_flow(QrReviewIo& io, ReviewDisplayLimits limits, std::size_t max_steps) {
    if (max_steps == 0) {
        throw std::invalid_argument("QR review IO max steps must be non-zero");
    }

    QrReviewFlow flow{io.scan_request_qr(), limits};
    std::optional<bool> decision;
    std::vector<QrReviewTranscriptStep> transcript;
    transcript.reserve(max_steps);
    for (std::size_t step = 0; step < max_steps && !decision.has_value(); ++step) {
        ReviewDisplayFrame frame = flow.current_frame();
        io.show_review_frame(frame);
        const ReviewButton button = io.read_review_button();
        decision = flow.handle_button(button);
        transcript.push_back(QrReviewTranscriptStep{
            std::move(frame),
            button,
            decision,
            flow.approved_for_signing(),
        });
    }
    if (!decision.has_value()) {
        throw std::logic_error("QR review IO did not reach a terminal decision");
    }
    return QrReviewIoFlowResult{
        flow.request_id(),
        flow.approval_digest(),
        decision,
        flow.approved_for_signing(),
        std::move(transcript),
    };
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

}  // namespace nsealr
