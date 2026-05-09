#include <cassert>
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "nostrseal/approval_gate.hpp"
#include "nostrseal/device_protocol.hpp"
#include "nostrseal/limits.hpp"
#include "nostrseal/qr_envelope.hpp"
#include "nostrseal/qr_review.hpp"
#include "nostrseal/qr_review_flow.hpp"
#include "nostrseal/review_controls.hpp"
#include "nostrseal/review_display.hpp"
#include "nostrseal/serial_frame.hpp"
#include "nostrseal/serial_review.hpp"
#include "nostrseal/signing_policy.hpp"
#include "nostrseal/trusted_review.hpp"
#include "transport_vector.hpp"

namespace {

std::string base64url_encode_for_test(const std::string& value) {
    constexpr std::array<char, 64> alphabet{
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '-', '_',
    };
    std::string encoded;
    int accumulator = 0;
    int bits = 0;
    for (const unsigned char ch : value) {
        accumulator = (accumulator << 8) | ch;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            encoded.push_back(alphabet[static_cast<std::size_t>((accumulator >> bits) & 0x3f)]);
        }
    }
    if (bits > 0) {
        encoded.push_back(alphabet[static_cast<std::size_t>((accumulator << (6 - bits)) & 0x3f)]);
    }
    return encoded;
}

std::string request_frame_for_test(const std::string& request_json) {
    return nostrseal::encode_serial_frame(
        nostrseal::SerialFrame{nostrseal::FrameType::Request, base64url_encode_for_test(request_json)});
}

std::string response_frame_for_test(const std::string& response_json) {
    return nostrseal::encode_serial_frame(
        nostrseal::SerialFrame{nostrseal::FrameType::Response, base64url_encode_for_test(response_json)});
}

std::string error_frame_for_test(const std::string& error_json) {
    return nostrseal::encode_serial_frame(
        nostrseal::SerialFrame{nostrseal::FrameType::Error, base64url_encode_for_test(error_json)});
}

void expect_throw(const std::string& expected, const auto& fn) {
    try {
        fn();
    } catch (const std::exception& exc) {
        assert(std::string(exc.what()).find(expected) != std::string::npos);
        return;
    }
    assert(false && "expected exception");
}

void assert_trusted_review_pages(
    const std::vector<nostrseal::TrustedReviewPage>& actual,
    const std::vector<nostrseal::TrustedReviewPage>& expected) {
    assert(actual.size() == expected.size());
    for (std::size_t index = 0; index < actual.size(); ++index) {
        assert(actual[index].title == expected[index].title);
        assert(actual[index].lines == expected[index].lines);
        assert(actual[index].action == expected[index].action);
    }
}

void assert_qr_review_transcript(
    const std::vector<nostrseal::QrReviewTranscriptStep>& actual,
    const std::vector<nostrseal::QrReviewTranscriptStep>& expected) {
    assert(actual.size() == expected.size());
    for (std::size_t index = 0; index < actual.size(); ++index) {
        assert(actual[index].frame.title == expected[index].frame.title);
        assert(actual[index].frame.page_indicator == expected[index].frame.page_indicator);
        assert(actual[index].frame.body_lines == expected[index].frame.body_lines);
        assert(actual[index].frame.action_hint == expected[index].frame.action_hint);
        assert(actual[index].button == expected[index].button);
        assert(actual[index].decision == expected[index].decision);
        assert(actual[index].approved_for_signing == expected[index].approved_for_signing);
    }
}

class RecordingQrReviewIo : public nostrseal::QrReviewIo {
public:
    explicit RecordingQrReviewIo(std::vector<nostrseal::ReviewButton> buttons) : buttons_(std::move(buttons)) {}

    std::string scan_request_qr() override {
        return nostrseal::test_vectors::kQrEnvelopeKind1Basic;
    }

    void show_review_frame(const nostrseal::ReviewDisplayFrame& frame) override {
        frames.push_back(frame);
    }

    nostrseal::ReviewButton read_review_button() override {
        assert(!buttons_.empty());
        const nostrseal::ReviewButton button = buttons_.front();
        buttons_.erase(buttons_.begin());
        return button;
    }

    std::vector<nostrseal::ReviewDisplayFrame> frames;

private:
    std::vector<nostrseal::ReviewButton> buttons_;
};

class NextOnlyQrReviewIo : public nostrseal::QrReviewIo {
public:
    std::string scan_request_qr() override {
        return nostrseal::test_vectors::kQrEnvelopeKind1Basic;
    }

    void show_review_frame(const nostrseal::ReviewDisplayFrame& frame) override {
        frames.push_back(frame);
    }

    nostrseal::ReviewButton read_review_button() override {
        return nostrseal::ReviewButton::Next;
    }

    std::vector<nostrseal::ReviewDisplayFrame> frames;
};

class RecordingSerialReviewIo : public nostrseal::SerialReviewIo {
public:
    explicit RecordingSerialReviewIo(std::vector<nostrseal::ReviewButton> buttons) : buttons_(std::move(buttons)) {}

    std::string read_request_json() override {
        return R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"NostrSeal fixture: basic kind 1 event."}}})";
    }

    void show_review_frame(const nostrseal::ReviewDisplayFrame& frame) override {
        frames.push_back(frame);
    }

    nostrseal::ReviewButton read_review_button() override {
        assert(!buttons_.empty());
        const nostrseal::ReviewButton button = buttons_.front();
        buttons_.erase(buttons_.begin());
        return button;
    }

    std::vector<nostrseal::ReviewDisplayFrame> frames;

private:
    std::vector<nostrseal::ReviewButton> buttons_;
};

void test_serial_frame_round_trip() {
    const nostrseal::SerialFrame frame{
        nostrseal::FrameType::Request,
        nostrseal::test_vectors::kSerialFramePayloadBase64Url,
    };

    const std::string encoded = nostrseal::encode_serial_frame(frame);
    assert(encoded == nostrseal::test_vectors::kSerialFrame);

    const nostrseal::SerialFrame decoded = nostrseal::decode_serial_frame(encoded);
    assert(decoded.type == nostrseal::FrameType::Request);
    assert(decoded.payload_base64url == frame.payload_base64url);

    const nostrseal::SerialFrame decoded_crlf =
        nostrseal::decode_serial_frame(encoded.substr(0, encoded.size() - 1) + "\r\n");
    assert(decoded_crlf.type == nostrseal::FrameType::Request);
    assert(decoded_crlf.payload_base64url == frame.payload_base64url);
}

void test_serial_frame_rejections() {
    expect_throw("unsupported serial frame type", [] {
        (void)nostrseal::decode_serial_frame("nseal1f:pubkey:eyJ2ZXJzaW9uIjoxfQ:d78075380263956b\n");
    });
    expect_throw("serial frame checksum mismatch", [] {
        (void)nostrseal::decode_serial_frame("nseal1f:request:eyJ2ZXJzaW9uIjoxfQ:0000000000000000\n");
    });
    expect_throw("serial frame payload", [] {
        (void)nostrseal::decode_serial_frame("nseal1f:request:not+base64url:d78075380263956b\n");
    });
}

void test_serial_frame_rejects_shared_invalid_vectors() {
    expect_throw("serial frame exceeds max_serial_frame_bytes", [] {
        (void)nostrseal::decode_serial_frame(nostrseal::test_vectors::kInvalidSerialFrameOversized);
    });
    expect_throw("serial frame checksum mismatch", [] {
        (void)nostrseal::decode_serial_frame(nostrseal::test_vectors::kInvalidSerialFrameChecksumMismatch);
    });
    expect_throw("serial frame payload", [] {
        (void)nostrseal::decode_serial_frame(nostrseal::test_vectors::kInvalidSerialFrameMalformedPayload);
    });
}

void test_qr_envelope_decodes_shared_vector() {
    const nostrseal::QrEnvelope envelope =
        nostrseal::decode_qr_envelope(nostrseal::test_vectors::kQrEnvelopeKind1Basic);

    assert(envelope.payload_base64url == nostrseal::test_vectors::kQrEnvelopeKind1BasicPayloadBase64Url);
    assert(envelope.payload_json.find("\"request_id\":\"req-kind-1-basic\"") != std::string::npos);
    assert(envelope.payload_json.find("\"method\":\"sign_event\"") != std::string::npos);
}

void test_qr_envelope_parses_sign_event_request_metadata() {
    const nostrseal::QrEnvelope envelope =
        nostrseal::decode_qr_envelope(nostrseal::test_vectors::kQrEnvelopeKind1Basic);
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(envelope);

    assert(request.version == 1);
    assert(request.request_id == "req-kind-1-basic");
    assert(request.method == "sign_event");
    assert(request.has_params);
}

void test_qr_envelope_extracts_event_template_boundary() {
    const nostrseal::QrEnvelope envelope =
        nostrseal::decode_qr_envelope(nostrseal::test_vectors::kQrEnvelopeKind1Basic);
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(envelope);

    assert(request.has_event_template);
    assert(request.event_template_json.find("\"kind\":1") != std::string::npos);
    assert(request.event_template_json.find("\"content\":\"NostrSeal fixture: basic kind 1 event.\"") !=
           std::string::npos);
}

void test_qr_envelope_parses_event_template_fields() {
    const nostrseal::QrEnvelope envelope =
        nostrseal::decode_qr_envelope(nostrseal::test_vectors::kQrEnvelopeKind1Basic);
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(envelope);

    assert(request.event_template.created_at == 1710000000U);
    assert(request.event_template.kind == 1);
    assert(request.event_template.content == "NostrSeal fixture: basic kind 1 event.");
    assert(request.event_template.tags_json == "[]");
}

void test_qr_signing_request_tolerates_escaped_event_content() {
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(
        nostrseal::QrEnvelope{"ignored",
                              R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"Quote: \"nostr\"\nNext line"}}})"});

    assert(request.has_event_template);
    assert(request.event_template.content == "Quote: \"nostr\"\nNext line");
    assert(request.event_template_json.find(R"("content":"Quote: \"nostr\"\nNext line")") != std::string::npos);
}

void test_qr_envelope_rejections() {
    expect_throw("QR envelope must start with nseal1:", [] {
        (void)nostrseal::decode_qr_envelope("nostr:abc");
    });
    expect_throw("QR envelope payload must be unpadded base64url", [] {
        (void)nostrseal::decode_qr_envelope("nseal1:abc=");
    });
    expect_throw("QR envelope payload must be unpadded base64url", [] {
        (void)nostrseal::decode_qr_envelope("nseal1:not+base64url");
    });
    expect_throw("QR envelope payload has invalid base64url length", [] {
        (void)nostrseal::decode_qr_envelope("nseal1:A");
    });
    expect_throw("QR envelope payload is not valid JSON", [] {
        (void)nostrseal::decode_qr_envelope("nseal1:bm90LWpzb24");
    });
}

void test_qr_envelope_rejects_shared_invalid_qr_vectors() {
    expect_throw("QR decoded JSON exceeds max_static_qr_decoded_json_bytes", [] {
        (void)nostrseal::decode_qr_envelope(nostrseal::test_vectors::kInvalidQrEnvelopeOversized);
    });
    expect_throw("QR envelope payload must be unpadded base64url", [] {
        (void)nostrseal::decode_qr_envelope(nostrseal::test_vectors::kInvalidQrEnvelopePadded);
    });
    expect_throw("QR envelope must start with nseal1:", [] {
        (void)nostrseal::decode_qr_envelope(nostrseal::test_vectors::kInvalidQrEnvelopeMalformed);
    });
    expect_throw("QR envelope payload must be valid UTF-8", [] {
        (void)nostrseal::decode_qr_envelope(nostrseal::test_vectors::kInvalidQrEnvelopeInvalidUtf8);
    });
}

void test_qr_limits_match_shared_profile() {
    assert(nostrseal::kMaxRequestIdLength == nostrseal::test_vectors::kMaxRequestIdLength);
    assert(nostrseal::kMaxDecodedRequestJsonBytes == nostrseal::test_vectors::kMaxDecodedRequestJsonBytes);
    assert(nostrseal::kMaxStaticQrDecodedJsonBytes == nostrseal::test_vectors::kMaxStaticQrDecodedJsonBytes);
    assert(nostrseal::kMaxSerialFrameBytes == nostrseal::test_vectors::kMaxSerialFrameBytes);
    assert(nostrseal::kMaxContentUtf8Bytes == nostrseal::test_vectors::kMaxContentUtf8Bytes);
    assert(nostrseal::kMaxTagCount == nostrseal::test_vectors::kMaxTagCount);
    assert(nostrseal::kMaxTagFieldsPerTag == nostrseal::test_vectors::kMaxTagFieldsPerTag);
    assert(nostrseal::kMaxTagFieldUtf8Bytes == nostrseal::test_vectors::kMaxTagFieldUtf8Bytes);
    assert(nostrseal::kMaxTotalTagUtf8Bytes == nostrseal::test_vectors::kMaxTotalTagUtf8Bytes);
    assert(nostrseal::kMaxSafeInteger == nostrseal::test_vectors::kMaxSafeInteger);
}

void test_qr_signing_request_rejections() {
    expect_throw("QR signing request version must be 1", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{"ignored", R"({"version":2,"request_id":"req-kind-1-basic","method":"sign_event","params":{}})"});
    });
    expect_throw("QR signing request request_id is invalid", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{"ignored", R"({"version":1,"request_id":"bad id","method":"sign_event","params":{}})"});
    });
    expect_throw("QR signing request method must be sign_event", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{"ignored", R"({"version":1,"request_id":"req-kind-1-basic","method":"get_public_key"})"});
    });
    expect_throw("QR signing request params object is required", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{"ignored", R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event"})"});
    });
    expect_throw("QR signing request event_template object is required", [] {
        (void)nostrseal::parse_qr_signing_request(
            nostrseal::QrEnvelope{"ignored", R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{}})"});
    });
    expect_throw("QR signing request event_template object is required", [] {
        (void)nostrseal::parse_qr_signing_request(
            nostrseal::QrEnvelope{"ignored", R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":[]}})"});
    });
    expect_throw("QR signing request event_template must not include id", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"","id":"00"}}})"});
    });
    expect_throw("QR signing request event_template must not include pubkey", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"","pubkey":"00"}}})"});
    });
    expect_throw("QR signing request event_template must not include sig", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"","sig":"00"}}})"});
    });
    expect_throw("QR signing request event_template created_at is required", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"kind":1,"tags":[],"content":""}}})"});
    });
    expect_throw("QR signing request event_template kind is required", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":"1","tags":[],"content":""}}})"});
    });
    expect_throw("QR signing request event_template tags array is required", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":{},"content":""}}})"});
    });
    expect_throw("QR signing request event_template content is required", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[]}}})"});
    });
}

void test_qr_signing_request_rejects_shared_invalid_request_vectors() {
    for (const auto& vector : nostrseal::test_vectors::invalid_signing_request_vectors()) {
        bool rejected = false;
        try {
            (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{"ignored", vector.request_json});
        } catch (const nostrseal::QrEnvelopeError&) {
            rejected = true;
        }
        if (!rejected) {
            std::cerr << "unexpectedly accepted invalid request vector: " << vector.name << "\n";
        }
        assert(rejected);
    }
}

void test_qr_review_pages_match_shared_basic_vector() {
    const nostrseal::QrEnvelope envelope =
        nostrseal::decode_qr_envelope(nostrseal::test_vectors::kQrEnvelopeKind1Basic);
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(envelope);

    assert_trusted_review_pages(
        nostrseal::build_qr_review_pages(request),
        nostrseal::test_vectors::basic_trusted_review_request().pages);
}

void test_qr_trusted_review_request_matches_shared_basic_vector() {
    const nostrseal::QrEnvelope envelope =
        nostrseal::decode_qr_envelope(nostrseal::test_vectors::kQrEnvelopeKind1Basic);
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(envelope);
    const nostrseal::TrustedReviewRequest review_request = nostrseal::build_qr_trusted_review_request(request);
    const nostrseal::TrustedReviewRequest expected = nostrseal::test_vectors::basic_trusted_review_request();

    assert(review_request.request_id == expected.request_id);
    assert(review_request.approval_digest == expected.approval_digest);
    assert_trusted_review_pages(review_request.pages, expected.pages);
}

void test_qr_review_pages_match_shared_tagged_vector() {
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
        "ignored",
        R"({"version":1,"request_id":"req-kind-1-tags","method":"sign_event","params":{"event_template":{"created_at":1710000060,"kind":1,"tags":[["p","4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","","mention"],["t","nostrseal"]],"content":"NostrSeal fixture: tagged kind 1 event."}}})"});

    assert_trusted_review_pages(
        nostrseal::build_qr_review_pages(request),
        nostrseal::test_vectors::tagged_trusted_review_request().pages);
}

void test_qr_trusted_review_request_matches_shared_tagged_vector() {
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
        "ignored",
        R"({"version":1,"request_id":"req-kind-1-tags","method":"sign_event","params":{"event_template":{"created_at":1710000060,"kind":1,"tags":[["p","4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","","mention"],["t","nostrseal"]],"content":"NostrSeal fixture: tagged kind 1 event."}}})"});
    const nostrseal::TrustedReviewRequest review_request = nostrseal::build_qr_trusted_review_request(request);
    const nostrseal::TrustedReviewRequest expected = nostrseal::test_vectors::tagged_trusted_review_request();

    assert(review_request.request_id == expected.request_id);
    assert(review_request.approval_digest == expected.approval_digest);
    assert_trusted_review_pages(review_request.pages, expected.pages);
}

void test_qr_trusted_review_session_binds_qr_digest_and_navigation() {
    const nostrseal::QrEnvelope envelope =
        nostrseal::decode_qr_envelope(nostrseal::test_vectors::kQrEnvelopeKind1Basic);
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(envelope);
    nostrseal::TrustedReviewSession session = nostrseal::begin_qr_trusted_review(request);

    const nostrseal::ReviewDisplayFrame first_frame = session.current_frame();
    assert(first_frame.title == "Event");
    assert(first_frame.page_indicator == "Page 1/4");
    assert(!session.can_sign());

    expect_throw("approval requires viewing every review page", [&] {
        (void)session.handle_button(nostrseal::ReviewButton::Approve);
    });

    (void)session.handle_button(nostrseal::ReviewButton::Next);
    (void)session.handle_button(nostrseal::ReviewButton::Next);
    (void)session.handle_button(nostrseal::ReviewButton::Next);

    const nostrseal::ReviewDisplayFrame decision_frame = session.current_frame();
    assert(decision_frame.title == "Decision");
    assert(!session.can_sign());

    const auto approval = session.handle_button(nostrseal::ReviewButton::Approve);
    assert(approval.has_value());
    assert(approval.value());
    assert(session.can_sign());
}

void test_qr_review_flow_drives_scanned_qr_without_signing_backend() {
    nostrseal::QrReviewFlow flow{nostrseal::test_vectors::kQrEnvelopeKind1Basic};
    const nostrseal::TrustedReviewRequest expected = nostrseal::test_vectors::basic_trusted_review_request();

    assert(flow.request_id() == expected.request_id);
    assert(flow.approval_digest() == expected.approval_digest);
    assert(!flow.approved_for_signing());

    const nostrseal::ReviewDisplayFrame first_frame = flow.current_frame();
    assert(first_frame.title == "Event");
    assert(first_frame.page_indicator == "Page 1/4");

    expect_throw("approval requires viewing every review page", [&] {
        (void)flow.handle_button(nostrseal::ReviewButton::Approve);
    });

    (void)flow.handle_button(nostrseal::ReviewButton::Next);
    (void)flow.handle_button(nostrseal::ReviewButton::Next);
    (void)flow.handle_button(nostrseal::ReviewButton::Next);

    const nostrseal::ReviewDisplayFrame decision_frame = flow.current_frame();
    assert(decision_frame.title == "Decision");
    assert(!flow.approved_for_signing());

    const auto approval = flow.handle_button(nostrseal::ReviewButton::Approve);
    assert(approval.has_value());
    assert(approval.value());
    assert(flow.approved_for_signing());
    assert(flow.decision() == nostrseal::ApprovalDecision::Approved);
}

void test_qr_review_flow_rejects_unsafe_scanned_qr() {
    expect_throw("QR signing request event_template must not include sig", [] {
        nostrseal::QrReviewFlow flow{
            R"(nseal1:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm1ldGhvZCI6InNpZ25fZXZlbnQiLCJwYXJhbXMiOnsiZXZlbnRfdGVtcGxhdGUiOnsiY3JlYXRlZF9hdCI6MTcxMDAwMDAwMCwia2luZCI6MSwidGFncyI6W10sImNvbnRlbnQiOiIiLCJzaWciOiIwMCJ9fX0)"};
        (void)flow;
    });
}

void test_qr_review_flow_transcript_records_display_and_approval_steps() {
    const std::vector<nostrseal::QrReviewTranscriptStep> transcript = nostrseal::run_qr_review_transcript(
        nostrseal::test_vectors::kQrEnvelopeKind1Basic,
        nostrseal::test_vectors::basic_qr_review_approve_buttons());

    assert_qr_review_transcript(
        transcript,
        nostrseal::test_vectors::basic_qr_review_approve_transcript());
}

void test_qr_review_flow_transcript_records_early_rejection() {
    const std::vector<nostrseal::QrReviewTranscriptStep> transcript = nostrseal::run_qr_review_transcript(
        nostrseal::test_vectors::kQrEnvelopeKind1Basic,
        nostrseal::test_vectors::basic_qr_review_reject_buttons());

    assert_qr_review_transcript(
        transcript,
        nostrseal::test_vectors::basic_qr_review_reject_transcript());
}

void test_qr_review_io_flow_drives_scanner_display_and_buttons_without_signing() {
    RecordingQrReviewIo io{{nostrseal::ReviewButton::Next,
                            nostrseal::ReviewButton::Next,
                            nostrseal::ReviewButton::Next,
                            nostrseal::ReviewButton::Approve}};

    const nostrseal::QrReviewIoFlowResult result = nostrseal::run_qr_review_io_flow(io);

    assert(result.request_id == "req-kind-1-basic");
    assert(result.approval_digest == nostrseal::test_vectors::kBasicReviewScreenApprovalDigest);
    assert(result.decision.has_value());
    assert(result.decision.value());
    assert(result.approved_for_signing);
    assert_qr_review_transcript(
        result.transcript,
        nostrseal::test_vectors::basic_qr_review_approve_transcript());
    assert(io.frames.size() == 4);
    assert(io.frames.front().title == "Event");
    assert(io.frames.front().page_indicator == "Page 1/4");
    assert(io.frames.back().title == "Decision");
    assert(io.frames.back().action_hint == "Approve / Reject");
}

void test_qr_review_io_flow_rejects_non_terminal_button_stream() {
    NextOnlyQrReviewIo io;

    expect_throw("QR review IO did not reach a terminal decision", [&] {
        (void)nostrseal::run_qr_review_io_flow(io, {}, 5);
    });

    assert(io.frames.size() == 5);
    assert(io.frames.back().title == "Decision");
}

void test_qr_review_io_flow_requires_nonzero_step_limit() {
    RecordingQrReviewIo io{{nostrseal::ReviewButton::Approve}};

    expect_throw("QR review IO max steps must be non-zero", [&] {
        (void)nostrseal::run_qr_review_io_flow(io, {}, 0);
    });

    assert(io.frames.empty());
}

void test_approval_gate_requires_matching_approval() {
    nostrseal::ApprovalGate gate;
    gate.begin_review("req-kind-1-basic", nostrseal::test_vectors::kBasicReviewScreenApprovalDigest);

    assert(!gate.can_sign("req-kind-1-basic", nostrseal::test_vectors::kBasicReviewScreenApprovalDigest));
    assert(!gate.can_sign("different", nostrseal::test_vectors::kBasicReviewScreenApprovalDigest));

    gate.approve("req-kind-1-basic", "00");
    assert(!gate.can_sign("req-kind-1-basic", nostrseal::test_vectors::kBasicReviewScreenApprovalDigest));

    gate.approve("different", nostrseal::test_vectors::kBasicReviewScreenApprovalDigest);
    assert(!gate.can_sign("req-kind-1-basic", nostrseal::test_vectors::kBasicReviewScreenApprovalDigest));

    gate.approve("req-kind-1-basic", nostrseal::test_vectors::kBasicReviewScreenApprovalDigest);
    assert(gate.can_sign("req-kind-1-basic", nostrseal::test_vectors::kBasicReviewScreenApprovalDigest));
    assert(!gate.can_sign("req-kind-1-basic", nostrseal::test_vectors::kTaggedReviewScreenApprovalDigest));

    gate.begin_review("req-kind-1-tags", nostrseal::test_vectors::kTaggedReviewScreenApprovalDigest);
    gate.reject("req-kind-1-tags");
    assert(!gate.can_sign("req-kind-1-tags", nostrseal::test_vectors::kTaggedReviewScreenApprovalDigest));
    assert(gate.decision() == nostrseal::ApprovalDecision::Rejected);
}

void test_review_controls_require_page_traversal_before_approval() {
    nostrseal::ReviewControlSession session{4};

    assert(session.current_page_index() == 0);
    assert(!session.can_approve());
    expect_throw("approval requires viewing every review page", [&] {
        (void)session.handle_button(nostrseal::ReviewButton::Approve);
    });

    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_page_index() == 1);
    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_page_index() == 2);
    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_page_index() == 3);
    assert(session.can_approve());

    const auto result = session.handle_button(nostrseal::ReviewButton::Approve);
    assert(result.has_value());
    assert(result.value());
    assert(session.approved());
    assert(!session.rejected());
}

void test_review_controls_allow_early_rejection() {
    nostrseal::ReviewControlSession session{4};

    const auto result = session.handle_button(nostrseal::ReviewButton::Reject);

    assert(result.has_value());
    assert(!result.value());
    assert(session.rejected());
    assert(!session.approved());
}

void test_review_controls_are_terminal_after_decision() {
    nostrseal::ReviewControlSession rejected_session{2};
    (void)rejected_session.handle_button(nostrseal::ReviewButton::Reject);
    expect_throw("review decision is already terminal", [&] {
        (void)rejected_session.handle_button(nostrseal::ReviewButton::Next);
    });

    nostrseal::ReviewControlSession approved_session{1};
    const auto approved = approved_session.handle_button(nostrseal::ReviewButton::Approve);
    assert(approved.has_value());
    assert(approved.value());
    expect_throw("review decision is already terminal", [&] {
        (void)approved_session.handle_button(nostrseal::ReviewButton::Approve);
    });
}

void test_review_display_renders_navigation_frame() {
    const nostrseal::ReviewPage page{
        "Event",
        {"Kind 1", "Short Text Note", "Created 1710000000"},
        nostrseal::ReviewPageAction::Next,
    };

    const nostrseal::ReviewDisplayFrame frame = nostrseal::render_review_page(page, 0, 4);

    assert(frame.title == "Event");
    assert(frame.page_indicator == "Page 1/4");
    assert((frame.body_lines == std::vector<std::string>{"Kind 1", "Short Text Note", "Created 1710000000"}));
    assert(frame.action_hint == "Next");
}

void test_review_display_renders_decision_frame() {
    const nostrseal::ReviewPage page{
        "Decision",
        {"Approve signing only if all pages match."},
        nostrseal::ReviewPageAction::ApproveOrReject,
    };

    const nostrseal::ReviewDisplayFrame frame = nostrseal::render_review_page(page, 3, 4);

    assert(frame.title == "Decision");
    assert(frame.page_indicator == "Page 4/4");
    assert((frame.body_lines == std::vector<std::string>{"Approve signing only if all pages match."}));
    assert(frame.action_hint == "Approve / Reject");
}

void test_review_display_wraps_and_truncates_long_body_lines() {
    const nostrseal::ReviewPage page{
        "Content",
        {"0123456789abcdef0123456789abcdef0123456789abcdef"},
        nostrseal::ReviewPageAction::Next,
    };

    const nostrseal::ReviewDisplayFrame frame = nostrseal::render_review_page(
        page,
        1,
        4,
        nostrseal::ReviewDisplayLimits{.max_title_chars = 12, .max_body_lines = 2, .max_line_chars = 16});

    assert(frame.title == "Content");
    assert(frame.page_indicator == "Page 2/4");
    assert(frame.body_lines.size() == 2);
    assert(frame.body_lines[0].size() <= 16);
    assert(frame.body_lines[1].size() <= 16);
    assert(frame.body_lines[1].rfind("...") == frame.body_lines[1].size() - 3);
    assert(frame.action_hint == "Next");
}

void test_review_display_matches_shared_long_content_frame_vector() {
    const std::string long_preview = std::string(120, 'x') + "...";
    const nostrseal::ReviewPage page{
        "Content",
        {long_preview},
        nostrseal::ReviewPageAction::Next,
    };

    const nostrseal::ReviewDisplayFrame frame = nostrseal::render_review_page(
        page,
        1,
        4,
        nostrseal::test_vectors::long_content_display_limits_20x3());
    const nostrseal::ReviewDisplayFrame expected = nostrseal::test_vectors::long_content_display_frame_20x3();

    assert(frame.title == expected.title);
    assert(frame.page_indicator == expected.page_indicator);
    assert(frame.body_lines == expected.body_lines);
    assert(frame.action_hint == expected.action_hint);
}

void test_review_display_rejects_unsafe_frame_bounds() {
    const nostrseal::ReviewPage page{
        "Event",
        {"Kind 1"},
        nostrseal::ReviewPageAction::Next,
    };

    expect_throw("review display page index out of range", [&] {
        (void)nostrseal::render_review_page(page, 4, 4);
    });

    expect_throw("review display total pages must be non-zero", [&] {
        (void)nostrseal::render_review_page(page, 0, 0);
    });

    expect_throw("review display title exceeds configured width", [&] {
        const nostrseal::ReviewPage unsafe_page{
            "This title is too long for a tiny trusted display",
            {"Kind 1"},
            nostrseal::ReviewPageAction::Next,
        };
        (void)nostrseal::render_review_page(
            unsafe_page,
            0,
            1,
            nostrseal::ReviewDisplayLimits{.max_title_chars = 12, .max_body_lines = 4, .max_line_chars = 32});
    });
}

void test_trusted_review_session_binds_display_navigation_and_approval() {
    nostrseal::TrustedReviewSession session{nostrseal::test_vectors::basic_trusted_review_request()};

    const nostrseal::ReviewDisplayFrame first_frame = session.current_frame();
    assert(first_frame.title == "Event");
    assert(first_frame.page_indicator == "Page 1/4");
    assert(first_frame.action_hint == "Next");
    assert(!session.can_sign());

    expect_throw("approval requires viewing every review page", [&] {
        (void)session.handle_button(nostrseal::ReviewButton::Approve);
    });

    (void)session.handle_button(nostrseal::ReviewButton::Next);
    (void)session.handle_button(nostrseal::ReviewButton::Next);
    (void)session.handle_button(nostrseal::ReviewButton::Next);

    const nostrseal::ReviewDisplayFrame decision_frame = session.current_frame();
    assert(decision_frame.title == "Decision");
    assert(decision_frame.page_indicator == "Page 4/4");
    assert(decision_frame.action_hint == "Approve / Reject");
    assert(!session.can_sign());

    const auto approval = session.handle_button(nostrseal::ReviewButton::Approve);
    assert(approval.has_value());
    assert(approval.value());
    assert(session.can_sign());
}

void test_trusted_review_session_keeps_rejection_terminal() {
    nostrseal::TrustedReviewSession session{nostrseal::test_vectors::tagged_trusted_review_request()};

    const nostrseal::ReviewDisplayFrame first_frame = session.current_frame();
    assert(first_frame.title == "Event");
    assert(first_frame.page_indicator == "Page 1/4");

    (void)session.handle_button(nostrseal::ReviewButton::Next);
    (void)session.handle_button(nostrseal::ReviewButton::Next);
    const nostrseal::ReviewDisplayFrame tags_frame = session.current_frame();
    assert(tags_frame.title == "Tags");
    assert((tags_frame.body_lines == std::vector<std::string>{"2 tags", "p: 4f355bdc...", "t: nostrseal"}));

    (void)session.handle_button(nostrseal::ReviewButton::Next);
    const nostrseal::ReviewDisplayFrame warnings_frame = session.current_frame();
    assert(warnings_frame.title == "Warnings");
    assert((warnings_frame.body_lines == std::vector<std::string>{"Event includes pubkey mentions."}));

    const auto rejection = session.handle_button(nostrseal::ReviewButton::Reject);

    assert(rejection.has_value());
    assert(!rejection.value());
    assert(!session.can_sign());
    assert(session.decision() == nostrseal::ApprovalDecision::Rejected);
}

void test_serial_sign_event_review_matches_shared_review_contract() {
    const nostrseal::TrustedReviewRequest serial_review =
        nostrseal::build_serial_sign_event_trusted_review_request(
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"NostrSeal fixture: basic kind 1 event."}}})");
    const nostrseal::TrustedReviewRequest expected = nostrseal::test_vectors::basic_trusted_review_request();

    assert(serial_review.request_id == expected.request_id);
    assert(serial_review.approval_digest == expected.approval_digest);
    assert_trusted_review_pages(serial_review.pages, expected.pages);

    nostrseal::TrustedReviewSession session = nostrseal::begin_serial_sign_event_trusted_review(
        R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"NostrSeal fixture: basic kind 1 event."}}})");
    assert(session.current_frame().title == "Event");
    assert(!session.can_sign());
}

void test_serial_review_io_flow_drives_request_display_and_buttons_without_signing() {
    RecordingSerialReviewIo io{{nostrseal::ReviewButton::Next,
                                nostrseal::ReviewButton::Next,
                                nostrseal::ReviewButton::Next,
                                nostrseal::ReviewButton::Approve}};

    const nostrseal::SerialReviewIoFlowResult result = nostrseal::run_serial_review_io_flow(io);

    assert(result.request_id == "req-kind-1-basic");
    assert(result.approval_digest == nostrseal::test_vectors::kBasicReviewScreenApprovalDigest);
    assert(result.decision.has_value());
    assert(result.decision.value());
    assert(result.approved_for_signing);
    assert(result.transcript.size() == nostrseal::test_vectors::basic_qr_review_approve_transcript().size());
    assert(result.transcript.front().frame.title == "Event");
    assert(result.transcript.front().frame.page_indicator == "Page 1/4");
    assert(result.transcript.back().frame.title == "Decision");
    assert(result.transcript.back().decision.has_value());
    assert(result.transcript.back().decision.value());
    assert(io.frames.size() == 4);
    assert(io.frames.front().title == "Event");
    assert(io.frames.back().action_hint == "Approve / Reject");
}

void test_signing_policy_requires_every_runtime_gate_before_enablement() {
    const nostrseal::SigningReadiness default_readiness{};
    const nostrseal::SigningReadinessStatus default_status =
        nostrseal::evaluate_signing_readiness(default_readiness);

    assert(!default_status.signing_enabled);
    assert((default_status.missing_gates == std::vector<std::string>{
                                               "runtime_signing_feature",
                                               "parser_limits",
                                               "trusted_review_display",
                                               "physical_approval_controls",
                                               "approval_digest_binding",
                                               "key_provisioning",
                                               "secure_boot",
                                               "debug_lock",
                                               "companion_signed_output_verification",
                                           }));

    nostrseal::SigningReadiness safety_gates{
        .runtime_signing_feature_enabled = false,
        .parser_limits_enforced = true,
        .trusted_review_display_accepted = true,
        .physical_approval_controls_accepted = true,
        .approval_digest_binding_verified = true,
        .key_provisioning_ready = true,
        .secure_boot_enabled = true,
        .debug_locked = true,
        .companion_signed_output_verification_ready = true,
    };
    const nostrseal::SigningReadinessStatus safety_status =
        nostrseal::evaluate_signing_readiness(safety_gates);

    assert(!safety_status.signing_enabled);
    assert((safety_status.missing_gates == std::vector<std::string>{"runtime_signing_feature"}));

    safety_gates.runtime_signing_feature_enabled = true;
    const nostrseal::SigningReadinessStatus ready_status =
        nostrseal::evaluate_signing_readiness(safety_gates);

    assert(ready_status.signing_enabled);
    assert(ready_status.missing_gates.empty());
}

void test_device_protocol_reports_scaffold_capabilities() {
    const std::string response = nostrseal::handle_serial_frame(nostrseal::test_vectors::kCapabilityRequestFrame);

    assert(response == nostrseal::test_vectors::kCapabilityResponseFrame);
    const nostrseal::SerialFrame decoded = nostrseal::decode_serial_frame(response);
    assert(decoded.type == nostrseal::FrameType::Response);
    assert(decoded.payload_base64url == nostrseal::test_vectors::kCapabilityResponsePayloadBase64Url);
}

void test_device_protocol_rejects_signing_while_disabled() {
    const std::string response = nostrseal::handle_serial_frame(nostrseal::test_vectors::kSignEventRequestFrame);

    assert(response == nostrseal::test_vectors::kSignEventDisabledResponseFrame);
    const nostrseal::SerialFrame decoded = nostrseal::decode_serial_frame(response);
    assert(decoded.type == nostrseal::FrameType::Response);
    assert(decoded.payload_base64url == nostrseal::test_vectors::kSignEventDisabledResponsePayloadBase64Url);
}

void test_device_protocol_reports_development_public_key() {
    const std::string response = nostrseal::handle_serial_frame(nostrseal::test_vectors::kPublicKeyRequestFrame);

    assert(response == nostrseal::test_vectors::kPublicKeyResponseFrame);
    const nostrseal::SerialFrame decoded = nostrseal::decode_serial_frame(response);
    assert(decoded.type == nostrseal::FrameType::Response);
    assert(decoded.payload_base64url == nostrseal::test_vectors::kPublicKeyResponsePayloadBase64Url);
}

void test_device_protocol_echoes_dynamic_request_ids() {
    const std::string capability_response = nostrseal::handle_serial_frame(
        request_frame_for_test(R"({"version":1,"request_id":"req-alt-capabilities","method":"get_capabilities"})"));

    assert(capability_response == response_frame_for_test(
        R"({"version":1,"request_id":"req-alt-capabilities","ok":true,"result":{"capabilities":{"device":{"name":"NostrSeal ESP32-S3 USB Signer Scaffold","firmware":"nostrseal-esp32-s3-usb-signer","hardware":"esp32-s3-devkitc-1"},"protocols":["nseal.signing.v0","nseal.serial-frame.v0"],"methods":["get_capabilities","get_public_key","sign_event"],"transports":["usb-serial-jtag"],"signing_enabled":false,"requires_physical_approval":true}}})"));

    const std::string public_key_response = nostrseal::handle_serial_frame(
        request_frame_for_test(R"({"version":1,"request_id":"req-alt-pubkey","method":"get_public_key"})"));

    assert(public_key_response == response_frame_for_test(
        R"({"version":1,"request_id":"req-alt-pubkey","ok":true,"result":{"public_key":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"}})"));

    const std::string disabled_response = nostrseal::handle_serial_frame(
        request_frame_for_test(R"({"version":1,"request_id":"req-alt-sign","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"alt"}}})"));

    assert(disabled_response == response_frame_for_test(
        R"({"version":1,"request_id":"req-alt-sign","ok":false,"error":{"code":"signing_disabled","message":"Signing is disabled until trusted review and physical approval are implemented.","retryable":false}})"));
}

void test_device_protocol_rejects_invalid_dynamic_request_metadata() {
    assert(nostrseal::handle_serial_frame(
               request_frame_for_test(R"({"version":10,"request_id":"req-version-10","method":"get_public_key"})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));

    assert(nostrseal::handle_serial_frame(
               request_frame_for_test(R"({"version":1,"request_id":"bad id","method":"get_public_key"})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));
}

void test_device_protocol_rejects_unknown_top_level_request_fields() {
    assert(nostrseal::handle_serial_frame(
               request_frame_for_test(
                   R"({"version":1,"request_id":"invalid-top-level","method":"get_public_key","unexpected":true})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));
}

void test_device_protocol_rejects_params_for_parameterless_methods() {
    assert(nostrseal::handle_serial_frame(
               request_frame_for_test(
                   R"({"version":1,"request_id":"invalid-capabilities-params","method":"get_capabilities","params":{}})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));

    assert(nostrseal::handle_serial_frame(
               request_frame_for_test(
                   R"({"version":1,"request_id":"invalid-public-key-params","method":"get_public_key","params":{}})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));
}

void test_device_protocol_rejects_invalid_sign_event_request_shape() {
    assert(nostrseal::handle_serial_frame(
               request_frame_for_test(R"({"version":1,"request_id":"invalid-template-pubkey","method":"sign_event","params":{"event_template":{"pubkey":"0000000000000000000000000000000000000000000000000000000000000000","created_at":1710000000,"kind":1,"tags":[],"content":"unsafe template"}}})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));
}

}  // namespace

int main() {
    test_serial_frame_round_trip();
    test_serial_frame_rejections();
    test_serial_frame_rejects_shared_invalid_vectors();
    test_qr_envelope_decodes_shared_vector();
    test_qr_envelope_parses_sign_event_request_metadata();
    test_qr_envelope_extracts_event_template_boundary();
    test_qr_envelope_parses_event_template_fields();
    test_qr_signing_request_tolerates_escaped_event_content();
    test_qr_envelope_rejections();
    test_qr_envelope_rejects_shared_invalid_qr_vectors();
    test_qr_limits_match_shared_profile();
    test_qr_signing_request_rejections();
    test_qr_signing_request_rejects_shared_invalid_request_vectors();
    test_qr_review_pages_match_shared_basic_vector();
    test_qr_trusted_review_request_matches_shared_basic_vector();
    test_qr_review_pages_match_shared_tagged_vector();
    test_qr_trusted_review_request_matches_shared_tagged_vector();
    test_qr_trusted_review_session_binds_qr_digest_and_navigation();
    test_qr_review_flow_drives_scanned_qr_without_signing_backend();
    test_qr_review_flow_rejects_unsafe_scanned_qr();
    test_qr_review_flow_transcript_records_display_and_approval_steps();
    test_qr_review_flow_transcript_records_early_rejection();
    test_qr_review_io_flow_drives_scanner_display_and_buttons_without_signing();
    test_qr_review_io_flow_rejects_non_terminal_button_stream();
    test_qr_review_io_flow_requires_nonzero_step_limit();
    test_approval_gate_requires_matching_approval();
    test_review_controls_require_page_traversal_before_approval();
    test_review_controls_allow_early_rejection();
    test_review_controls_are_terminal_after_decision();
    test_review_display_renders_navigation_frame();
    test_review_display_renders_decision_frame();
    test_review_display_wraps_and_truncates_long_body_lines();
    test_review_display_matches_shared_long_content_frame_vector();
    test_review_display_rejects_unsafe_frame_bounds();
    test_trusted_review_session_binds_display_navigation_and_approval();
    test_trusted_review_session_keeps_rejection_terminal();
    test_serial_sign_event_review_matches_shared_review_contract();
    test_serial_review_io_flow_drives_request_display_and_buttons_without_signing();
    test_signing_policy_requires_every_runtime_gate_before_enablement();
    test_device_protocol_reports_scaffold_capabilities();
    test_device_protocol_rejects_signing_while_disabled();
    test_device_protocol_reports_development_public_key();
    test_device_protocol_echoes_dynamic_request_ids();
    test_device_protocol_rejects_invalid_dynamic_request_metadata();
    test_device_protocol_rejects_unknown_top_level_request_fields();
    test_device_protocol_rejects_params_for_parameterless_methods();
    test_device_protocol_rejects_invalid_sign_event_request_shape();
    std::cout << "host core tests passed\n";
    return 0;
}
