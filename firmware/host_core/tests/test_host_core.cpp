#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "nostrseal/approval_gate.hpp"
#include "nostrseal/device_protocol.hpp"
#include "nostrseal/qr_envelope.hpp"
#include "nostrseal/qr_review.hpp"
#include "nostrseal/review_controls.hpp"
#include "nostrseal/review_display.hpp"
#include "nostrseal/serial_frame.hpp"
#include "nostrseal/trusted_review.hpp"
#include "transport_vector.hpp"

namespace {

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

}  // namespace

int main() {
    test_serial_frame_round_trip();
    test_serial_frame_rejections();
    test_qr_envelope_decodes_shared_vector();
    test_qr_envelope_parses_sign_event_request_metadata();
    test_qr_envelope_extracts_event_template_boundary();
    test_qr_envelope_parses_event_template_fields();
    test_qr_signing_request_tolerates_escaped_event_content();
    test_qr_envelope_rejections();
    test_qr_signing_request_rejections();
    test_qr_review_pages_match_shared_basic_vector();
    test_qr_trusted_review_request_matches_shared_basic_vector();
    test_qr_review_pages_match_shared_tagged_vector();
    test_qr_trusted_review_request_matches_shared_tagged_vector();
    test_qr_trusted_review_session_binds_qr_digest_and_navigation();
    test_approval_gate_requires_matching_approval();
    test_review_controls_require_page_traversal_before_approval();
    test_review_controls_allow_early_rejection();
    test_review_controls_are_terminal_after_decision();
    test_review_display_renders_navigation_frame();
    test_review_display_renders_decision_frame();
    test_review_display_rejects_unsafe_frame_bounds();
    test_trusted_review_session_binds_display_navigation_and_approval();
    test_trusted_review_session_keeps_rejection_terminal();
    test_device_protocol_reports_scaffold_capabilities();
    test_device_protocol_rejects_signing_while_disabled();
    test_device_protocol_reports_development_public_key();
    std::cout << "host core tests passed\n";
    return 0;
}
