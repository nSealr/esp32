#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>

#include "nostrseal/approval_gate.hpp"
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
    gate.begin_review("req-kind-1-basic");

    assert(!gate.can_sign("req-kind-1-basic"));
    assert(!gate.can_sign("different"));

    gate.approve("different");
    assert(!gate.can_sign("req-kind-1-basic"));

    gate.approve("req-kind-1-basic");
    assert(gate.can_sign("req-kind-1-basic"));

    gate.begin_review("req-kind-1-tags");
    gate.reject("req-kind-1-tags");
    assert(!gate.can_sign("req-kind-1-tags"));
    assert(gate.decision() == nostrseal::ApprovalDecision::Rejected);
}

}  // namespace

int main() {
    test_serial_frame_round_trip();
    test_serial_frame_rejections();
    test_approval_gate_requires_matching_approval();
    std::cout << "host core tests passed\n";
    return 0;
}
