#include "nsealr/serial_review.hpp"

#include <stdexcept>
#include <utility>

#include "nsealr/qr_envelope.hpp"
#include "nsealr/qr_review.hpp"

namespace nsealr {
namespace {

TrustedReviewRequest build_serial_display_review_request(
    const std::string& request_json,
    const SignerIdentity& identity,
    ReviewDisplayLimits limits) {
    const QrSigningRequest request = parse_qr_signing_request(QrEnvelope{"serial", request_json});
    return build_qr_display_review_request(request, identity, limits);
}

}  // namespace

TrustedReviewRequest build_serial_sign_event_trusted_review_request(const std::string& request_json) {
    return build_serial_sign_event_trusted_review_request(request_json, development_fixture_signer_identity());
}

TrustedReviewRequest build_serial_sign_event_trusted_review_request(
    const std::string& request_json,
    const SignerIdentity& identity) {
    const QrSigningRequest request = parse_qr_signing_request(QrEnvelope{"serial", request_json});
    return build_qr_trusted_review_request(request, identity);
}

TrustedReviewSession begin_serial_sign_event_trusted_review(
    const std::string& request_json,
    ReviewDisplayLimits limits) {
    return begin_serial_sign_event_trusted_review(request_json, development_fixture_signer_identity(), limits);
}

TrustedReviewSession begin_serial_sign_event_trusted_review(
    const std::string& request_json,
    const SignerIdentity& identity,
    ReviewDisplayLimits limits) {
    return TrustedReviewSession{build_serial_display_review_request(request_json, identity, limits), limits};
}

SerialReviewFlow::SerialReviewFlow(const std::string& request_json, ReviewDisplayLimits limits)
    : SerialReviewFlow(request_json, development_fixture_signer_identity(), limits) {}

SerialReviewFlow::SerialReviewFlow(
    const std::string& request_json,
    const SignerIdentity& identity,
    ReviewDisplayLimits limits)
    : review_request_(build_serial_display_review_request(request_json, identity, limits)),
      session_(TrustedReviewRequest{review_request_}, limits) {}

const std::string& SerialReviewFlow::request_id() const {
    return review_request_.request_id;
}

const std::string& SerialReviewFlow::approval_digest() const {
    return review_request_.approval_digest;
}

ReviewDisplayFrame SerialReviewFlow::current_frame() const {
    return session_.current_frame();
}

ApprovalDecision SerialReviewFlow::decision() const {
    return session_.decision();
}

bool SerialReviewFlow::approved_for_signing() const {
    return session_.can_sign();
}

std::optional<bool> SerialReviewFlow::handle_button(ReviewButton button) {
    return session_.handle_button(button);
}

SerialReviewIoFlowResult run_serial_review_io_flow(
    SerialReviewIo& io,
    ReviewDisplayLimits limits,
    std::size_t max_steps) {
    return run_serial_review_io_flow(io, development_fixture_signer_identity(), limits, max_steps);
}

SerialReviewIoFlowResult run_serial_review_io_flow(
    SerialReviewIo& io,
    const SignerIdentity& identity,
    ReviewDisplayLimits limits,
    std::size_t max_steps) {
    if (max_steps == 0) {
        throw std::invalid_argument("serial review IO max steps must be non-zero");
    }

    SerialReviewFlow flow{io.read_request_json(), identity, limits};
    std::optional<bool> decision;
    std::vector<SerialReviewTranscriptStep> transcript;
    transcript.reserve(max_steps);
    for (std::size_t step = 0; step < max_steps && !decision.has_value(); ++step) {
        ReviewDisplayFrame frame = flow.current_frame();
        io.show_review_frame(frame);
        const ReviewButton button = io.read_review_button();
        decision = flow.handle_button(button);
        transcript.push_back(SerialReviewTranscriptStep{
            std::move(frame),
            button,
            decision,
            flow.approved_for_signing(),
        });
    }
    if (!decision.has_value()) {
        throw std::logic_error("serial review IO did not reach a terminal decision");
    }
    return SerialReviewIoFlowResult{
        flow.request_id(),
        flow.approval_digest(),
        decision,
        flow.approved_for_signing(),
        std::move(transcript),
    };
}

}  // namespace nsealr
