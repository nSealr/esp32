#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>

#include "nostrseal/approval_gate.hpp"
#include "nostrseal/device_protocol.hpp"
#include "nostrseal/review_controls.hpp"
#include "nostrseal/serial_frame.hpp"
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
    test_approval_gate_requires_matching_approval();
    test_review_controls_require_page_traversal_before_approval();
    test_review_controls_allow_early_rejection();
    test_review_controls_are_terminal_after_decision();
    test_device_protocol_reports_scaffold_capabilities();
    test_device_protocol_rejects_signing_while_disabled();
    test_device_protocol_reports_development_public_key();
    std::cout << "host core tests passed\n";
    return 0;
}
