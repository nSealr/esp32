#include "nsealr/qr_review_flow.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

#include "nsealr/qr_envelope.hpp"

namespace nsealr {
namespace {

constexpr const char* kStaticQrPrefix = "nsealr1:";
constexpr const char* kAnimatedQrPrefix = "nsealr1a:";

bool starts_with(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
}

std::string trim_ascii(std::string_view value) {
    std::size_t start = 0;
    while (start < value.size()) {
        const char ch = value[start];
        if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
            break;
        }
        ++start;
    }
    std::size_t end = value.size();
    while (end > start) {
        const char ch = value[end - 1U];
        if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
            break;
        }
        --end;
    }
    return std::string(value.substr(start, end - start));
}

std::vector<std::string> non_empty_qr_lines(const std::string& scanned_qr) {
    std::vector<std::string> frames;
    std::size_t start = 0;
    while (start <= scanned_qr.size()) {
        const std::size_t end = scanned_qr.find('\n', start);
        const std::string_view raw_line = end == std::string::npos
            ? std::string_view(scanned_qr).substr(start)
            : std::string_view(scanned_qr).substr(start, end - start);
        const std::string line = trim_ascii(raw_line);
        if (!line.empty()) {
            frames.push_back(line);
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1U;
    }
    return frames;
}

QrEnvelope decode_scanned_request_qr(const std::string& scanned_qr) {
    const std::vector<std::string> frames = non_empty_qr_lines(scanned_qr);
    if (frames.empty()) {
        throw QrEnvelopeError("QR review flow requires a scanned request QR");
    }
    if (frames.size() == 1U && starts_with(frames[0], kStaticQrPrefix)) {
        return decode_qr_envelope(frames[0]);
    }
    if (std::all_of(frames.begin(), frames.end(), [](const std::string& frame) {
            return starts_with(frame, kAnimatedQrPrefix);
        })) {
        return decode_animated_qr_envelope_frames(frames);
    }
    if (frames.size() == 1U) {
        return decode_qr_envelope(frames[0]);
    }
    throw QrEnvelopeError("QR review flow requires static nsealr1 or animated nsealr1a request QR");
}

TrustedReviewRequest review_request_from_qr(
    const std::string& qr_envelope,
    const SignerIdentity& signer_identity,
    ReviewDisplayLimits limits) {
    const QrEnvelope envelope = decode_scanned_request_qr(qr_envelope);
    const QrSigningRequest request = parse_qr_signing_request(envelope);
    return build_qr_display_review_request(request, signer_identity, limits);
}

}  // namespace

QrReviewFlow::QrReviewFlow(const std::string& qr_envelope, ReviewDisplayLimits limits)
    : QrReviewFlow(qr_envelope, development_fixture_signer_identity(), limits) {}

QrReviewFlow::QrReviewFlow(
    const std::string& qr_envelope,
    const SignerIdentity& signer_identity,
    ReviewDisplayLimits limits)
    : review_request_(review_request_from_qr(qr_envelope, signer_identity, limits)),
      session_(TrustedReviewRequest{review_request_}, limits) {}

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
    return run_qr_review_io_flow(io, development_fixture_signer_identity(), limits, max_steps);
}

QrReviewIoFlowResult run_qr_review_io_flow(
    QrReviewIo& io,
    const SignerIdentity& signer_identity,
    ReviewDisplayLimits limits,
    std::size_t max_steps) {
    if (max_steps == 0) {
        throw std::invalid_argument("QR review IO max steps must be non-zero");
    }

    QrReviewFlow flow{io.scan_request_qr(), signer_identity, limits};
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
    return run_qr_review_transcript(qr_envelope, buttons, development_fixture_signer_identity(), limits);
}

std::vector<QrReviewTranscriptStep> run_qr_review_transcript(
    const std::string& qr_envelope,
    const std::vector<ReviewButton>& buttons,
    const SignerIdentity& signer_identity,
    ReviewDisplayLimits limits) {
    QrReviewFlow flow{qr_envelope, signer_identity, limits};
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
