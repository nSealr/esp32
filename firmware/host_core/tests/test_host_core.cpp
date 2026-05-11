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
#include "nostrseal/utf8.hpp"
#include "t_display_s3_button_logic.hpp"
#include "t_display_s3_raster.hpp"
#include "t_display_s3_serial_input.hpp"
#include "t_display_s3_status_frames.hpp"
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

void assert_detailed_trusted_review_pages(
    const std::vector<nostrseal::TrustedReviewPage>& actual,
    const std::vector<nostrseal::TrustedReviewPage>& expected) {
    assert_trusted_review_pages(actual, expected);
    for (std::size_t index = 0; index < actual.size(); ++index) {
        assert(actual[index].page_indicator == expected[index].page_indicator);
        assert(actual[index].body_line_styles == expected[index].body_line_styles);
        assert(actual[index].logical_page_id == expected[index].logical_page_id);
    }
}

std::size_t page_count_with_title(
    const std::vector<nostrseal::TrustedReviewPage>& pages,
    const std::string& title) {
    std::size_t count = 0;
    for (const nostrseal::TrustedReviewPage& page : pages) {
        if (page.title == title) {
            ++count;
        }
    }
    return count;
}

std::string joined_lines_for_title(
    const std::vector<nostrseal::TrustedReviewPage>& pages,
    const std::string& title) {
    std::string joined;
    for (const nostrseal::TrustedReviewPage& page : pages) {
        if (page.title != title) {
            continue;
        }
        for (const std::string& line : page.lines) {
            joined += line;
        }
    }
    return joined;
}

bool lines_contain(const std::vector<std::string>& lines, const std::string& needle) {
    for (const std::string& line : lines) {
        if (line.find(needle) != std::string::npos) {
            return true;
        }
    }
    return false;
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

void test_animated_qr_envelope_decodes_shared_vector() {
    const nostrseal::QrEnvelope envelope =
        nostrseal::decode_animated_qr_envelope_frames(nostrseal::test_vectors::animated_qr_response_kind_1_basic_frames());

    assert(envelope.payload_base64url == nostrseal::test_vectors::kAnimatedQrResponseKind1BasicPayloadBase64Url);
    assert(envelope.payload_json == nostrseal::test_vectors::kAnimatedQrResponseKind1BasicJson);
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

void test_qr_signing_request_preserves_json_unicode_escapes() {
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(
        nostrseal::QrEnvelope{"ignored",
                              R"({"version":1,"request_id":"req-unicode-escapes","method":"sign_event","params":{"event_template":{"created_at":1710000400,"kind":1,"tags":[["t","caf\u00e8"],["emoji","\uD83D\uDE00"]],"content":"caf\u00e8 \uD83D\uDE00"}}})"});

    assert(request.event_template.content == std::string("caf") + "\xC3\xA8" + " " + "\xF0\x9F\x98\x80");
    assert(request.event_template.tags.size() == 2);
    assert(request.event_template.tags[0][1] == std::string("caf") + "\xC3\xA8");
    assert(request.event_template.tags[1][1] == std::string("\xF0\x9F\x98\x80"));

    const std::vector<nostrseal::TrustedReviewPage> pages =
        nostrseal::build_qr_display_review_pages(request, nostrseal_esp32::t_display_s3_review_limits());
    assert(joined_lines_for_title(pages, "Content").find("U+00E8") != std::string::npos);
    assert(joined_lines_for_title(pages, "Content").find("U+1F600") != std::string::npos);
    assert(joined_lines_for_title(pages, "Tags").find("U+00E8") != std::string::npos);
    assert(joined_lines_for_title(pages, "Tags").find("U+1F600") != std::string::npos);
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

void test_animated_qr_envelope_rejections() {
    expect_throw("animated QR requires at least one frame", [] {
        (void)nostrseal::decode_animated_qr_envelope_frames({});
    });
    expect_throw("animated QR frames must be unique and contiguous", [] {
        std::vector<std::string> frames = nostrseal::test_vectors::animated_qr_response_kind_1_basic_frames();
        frames.erase(frames.begin());
        (void)nostrseal::decode_animated_qr_envelope_frames(frames);
    });
    expect_throw("animated QR frame checksum mismatch", [] {
        std::vector<std::string> frames = nostrseal::test_vectors::animated_qr_response_kind_1_basic_frames();
        char& last = frames[0].back();
        last = last == '0' ? '1' : '0';
        (void)nostrseal::decode_animated_qr_envelope_frames(frames);
    });
    expect_throw("animated QR frame count exceeds max_animated_qr_frame_count", [] {
        const std::string frame =
            "nseal1a:0000000000000000000000000000000000000000000000000000000000000000:"
            "1/65:AA:0000000000000000";
        (void)nostrseal::decode_animated_qr_envelope_frames({frame});
    });
    expect_throw("animated QR chunk exceeds max_animated_qr_frame_payload_chars", [] {
        const std::string oversized_chunk(nostrseal::kMaxAnimatedQrFramePayloadChars + 1U, 'A');
        const std::string frame =
            "nseal1a:0000000000000000000000000000000000000000000000000000000000000000:"
            "1/1:" +
            oversized_chunk + ":0000000000000000";
        (void)nostrseal::decode_animated_qr_envelope_frames({frame});
    });
    expect_throw("animated QR index and total must be decimal", [] {
        const std::string frame =
            "nseal1a:0000000000000000000000000000000000000000000000000000000000000000:"
            "184467440737095516160/1:AA:0000000000000000";
        (void)nostrseal::decode_animated_qr_envelope_frames({frame});
    });
}

void test_qr_limits_match_shared_profile() {
    assert(nostrseal::kMaxRequestIdLength == nostrseal::test_vectors::kMaxRequestIdLength);
    assert(nostrseal::kMaxDecodedRequestJsonBytes == nostrseal::test_vectors::kMaxDecodedRequestJsonBytes);
    assert(nostrseal::kMaxStaticQrDecodedJsonBytes == nostrseal::test_vectors::kMaxStaticQrDecodedJsonBytes);
    assert(nostrseal::kMaxAnimatedQrDecodedJsonBytes == nostrseal::test_vectors::kMaxAnimatedQrDecodedJsonBytes);
    assert(nostrseal::kMaxAnimatedQrFramePayloadChars == nostrseal::test_vectors::kMaxAnimatedQrFramePayloadChars);
    assert(nostrseal::kMaxAnimatedQrFrameCount == nostrseal::test_vectors::kMaxAnimatedQrFrameCount);
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
    expect_throw("QR signing request JSON unicode escape is invalid", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-invalid-unicode","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"\uD83D"}}})"});
    });
    expect_throw("QR signing request JSON unicode escape is invalid", [] {
        (void)nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-invalid-unicode","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"\uDE00"}}})"});
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

void test_qr_display_review_pages_show_full_tag_values_without_ellipsis() {
    const std::string pubkey = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
        "ignored",
        R"({"version":1,"request_id":"req-kind-1-tags","method":"sign_event","params":{"event_template":{"created_at":1710000060,"kind":1,"tags":[["p","4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","","mention"],["t","nostrseal"]],"content":"NostrSeal fixture: tagged kind 1 event."}}})"});

    const std::vector<nostrseal::TrustedReviewPage> pages =
        nostrseal::build_qr_display_review_pages(request, nostrseal_esp32::t_display_s3_review_limits());
    const std::string tag_text = joined_lines_for_title(pages, "Tags");

    assert(page_count_with_title(pages, "Tags") == 1);
    assert(tag_text.find("...") == std::string::npos);
    assert(tag_text.find(pubkey.substr(0, 48)) != std::string::npos);
    assert(tag_text.find(pubkey.substr(48)) != std::string::npos);
    assert(tag_text.find("nostrseal") != std::string::npos);
    assert(pages.back().title == "Decision");
    assert(!lines_contain(pages.back().lines, "warning"));
    assert(!lines_contain(pages.back().lines, "Warning"));
}

void test_qr_display_review_pages_group_logical_sections_with_compact_styles() {
    const std::string pubkey = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    const nostrseal::QrSigningRequest request = nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{
        "ignored",
        R"({"version":1,"request_id":"req-kind-1-tags","method":"sign_event","params":{"event_template":{"created_at":1710000060,"kind":1,"tags":[["p","4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","","mention"],["t","nostrseal"]],"content":"NostrSeal fixture: tagged kind 1 event."}}})"});

    const std::vector<nostrseal::TrustedReviewPage> pages =
        nostrseal::build_qr_display_review_pages(request, nostrseal_esp32::t_display_s3_review_limits());

    assert(pages.size() == 4);
    assert(pages[0].title == "Event");
    assert(pages[0].page_indicator == "Page 1/4");
    assert((pages[0].lines == std::vector<std::string>{
                                "Kind 1",
                                "Created 1710000060",
                                "Author",
                                "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a",
                                "  b0f0b704075871aa",
                            }));
    assert(pages[0].body_line_styles.size() == pages[0].lines.size());
    assert(pages[0].body_line_styles[2] == nostrseal::ReviewBodyLineStyle::Meta);
    assert(pages[0].body_line_styles[3] == nostrseal::ReviewBodyLineStyle::Value);
    assert(!lines_contain(pages[0].lines, "Short Text Note"));
    assert(pages[1].title == "Content");
    assert(pages[1].page_indicator == "Page 2/4");
    assert(pages[2].title == "Tags");
    assert(pages[2].page_indicator == "Page 3/4");
    assert(pages[3].title == "Decision");
    assert(pages[3].page_indicator == "Page 4/4");
    assert(pages[2].body_line_styles.size() == pages[2].lines.size());
    assert(pages[2].body_line_styles.front() == nostrseal::ReviewBodyLineStyle::Meta);
    const std::string tag_text = joined_lines_for_title(pages, "Tags");
    assert((pages[2].lines == std::vector<std::string>{
                                "Tag 1/2",
                                "p",
                                "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a",
                                "  b0f0b704075871aa",
                                "mention",
                                "Tag 2/2",
                                "t",
                                "nostrseal",
                            }));
    assert(pages[2].body_line_styles[2] == nostrseal::ReviewBodyLineStyle::Value);
    assert(pages[2].body_line_styles[3] == nostrseal::ReviewBodyLineStyle::Value);
    assert(pages[2].lines[3].rfind("  ", 0) == 0);
    assert(!lines_contain(pages[2].lines, "[0]"));
    assert(!lines_contain(pages[2].lines, "\""));
    assert(!lines_contain(pages[2].lines, "raw tags JSON"));
    assert(tag_text.find(pubkey.substr(0, 48)) != std::string::npos);
    assert(tag_text.find(pubkey.substr(48)) != std::string::npos);
}

void test_qr_display_review_pages_match_shared_detail_page_vectors() {
    for (const nostrseal::test_vectors::ReviewDetailPageVector& vector :
         nostrseal::test_vectors::review_detail_page_vectors()) {
        const nostrseal::QrSigningRequest request =
            nostrseal::parse_qr_signing_request(nostrseal::QrEnvelope{"ignored", vector.request_json});

        const std::vector<nostrseal::TrustedReviewPage> pages =
            nostrseal::build_qr_display_review_pages(request, vector.limits);
        const nostrseal::TrustedReviewRequest review_request =
            nostrseal::build_qr_display_review_request(request, vector.limits);

        assert(review_request.approval_digest == vector.approval_digest);
        assert_detailed_trusted_review_pages(pages, vector.pages);
    }
}

void test_qr_display_review_pages_escape_non_ascii_for_display_safety() {
    const std::string content = std::string("cafe ") + "\xC3\xA8" + " " + "\xF0\x9F\x98\x80";
    const std::string tag_value = std::string("topic-") + "\xC3\xA8";
    const nostrseal::QrSigningRequest request{
        .version = 1,
        .request_id = "req-unicode-display",
        .method = "sign_event",
        .has_params = true,
        .has_event_template = true,
        .event_template_json = "",
        .event_template = nostrseal::QrEventTemplate{
            .created_at = 1710000300,
            .kind = 1,
            .tags_json = "",
            .tags = {{"t", tag_value}, {"emoji", std::string("\xF0\x9F\x98\x80")}},
            .content = content,
        },
    };

    const std::vector<nostrseal::TrustedReviewPage> pages =
        nostrseal::build_qr_display_review_pages(request, nostrseal_esp32::t_display_s3_review_limits());
    const std::string content_text = joined_lines_for_title(pages, "Content");
    const std::string tag_text = joined_lines_for_title(pages, "Tags");

    assert(content_text.find("U+00E8") != std::string::npos);
    assert(content_text.find("U+1F600") != std::string::npos);
    assert(tag_text.find("U+00E8") != std::string::npos);
    assert(tag_text.find("U+1F600") != std::string::npos);
}

void test_qr_display_review_pages_preserve_supported_ascii_punctuation() {
    const std::string content = "hello, nostr! #tag? @alice & key=value `code` ^caret";
    const nostrseal::QrSigningRequest request{
        .version = 1,
        .request_id = "req-ascii-punctuation-display",
        .method = "sign_event",
        .has_params = true,
        .has_event_template = true,
        .event_template_json = "",
        .event_template = nostrseal::QrEventTemplate{
            .created_at = 1710000360,
            .kind = 1,
            .tags_json = "",
            .tags = {{"client", "nseal/esp32-v0"}, {"subject", "a+b=c?"}},
            .content = content,
        },
    };

    const std::vector<nostrseal::TrustedReviewPage> pages =
        nostrseal::build_qr_display_review_pages(request, nostrseal_esp32::t_display_s3_review_limits());
    const std::string content_text = joined_lines_for_title(pages, "Content");
    const std::string tag_text = joined_lines_for_title(pages, "Tags");

    assert(content_text.find(content) != std::string::npos);
    assert(content_text.find("U+002C") == std::string::npos);
    assert(content_text.find("U+0021") == std::string::npos);
    assert(content_text.find("U+003F") == std::string::npos);
    assert(content_text.find("U+005E") == std::string::npos);
    assert(content_text.find("U+0060") == std::string::npos);
    assert(tag_text.find("nseal/esp32-v0") != std::string::npos);
    assert(tag_text.find("a+b=c?") != std::string::npos);
}

void test_qr_display_review_pages_split_full_long_content_without_ellipsis() {
    const std::string long_content(281, 'x');
    const nostrseal::QrSigningRequest request{
        .version = 1,
        .request_id = "req-long-display",
        .method = "sign_event",
        .has_params = true,
        .has_event_template = true,
        .event_template_json = "",
        .event_template = nostrseal::QrEventTemplate{
            .created_at = 1710000120,
            .kind = 1,
            .tags_json = "[]",
            .tags = {},
            .content = long_content,
        },
    };

    const std::vector<nostrseal::TrustedReviewPage> pages =
        nostrseal::build_qr_display_review_pages(request, nostrseal_esp32::t_display_s3_review_limits());
    const std::string content_text = joined_lines_for_title(pages, "Content");

    assert(page_count_with_title(pages, "Content") == 1);
    assert(content_text.find(long_content) != std::string::npos);
    assert(content_text.find("...") == std::string::npos);
    assert(pages.back().title == "Decision");
    assert(!lines_contain(pages.back().lines, "Long content"));
    assert(!lines_contain(pages.back().lines, "Many tags"));
}

void test_qr_display_review_pages_use_scroll_line_indicators_for_long_sections() {
    std::string long_content;
    for (std::size_t index = 0; index < 448U; ++index) {
        long_content.push_back(static_cast<char>('a' + (index % 26U)));
    }
    const nostrseal::QrSigningRequest request{
        .version = 1,
        .request_id = "req-scroll-display",
        .method = "sign_event",
        .has_params = true,
        .has_event_template = true,
        .event_template_json = "",
        .event_template = nostrseal::QrEventTemplate{
            .created_at = 1710000240,
            .kind = 1,
            .tags_json = R"([["t","tag0"],["t","tag1"],["t","tag2"],["t","tag3"],["t","tag4"],["t","tag5"]])",
            .tags = {{"t", "tag0"}, {"t", "tag1"}, {"t", "tag2"}, {"t", "tag3"}, {"t", "tag4"}, {"t", "tag5"}},
            .content = long_content,
        },
    };

    const std::vector<nostrseal::TrustedReviewPage> pages =
        nostrseal::build_qr_display_review_pages(request, nostrseal_esp32::t_display_s3_review_limits());

    assert(page_count_with_title(pages, "Content") > 1);
    assert(page_count_with_title(pages, "Tags") > 1);
    assert(pages[1].title == "Content");
    assert(pages[1].page_indicator.rfind("Page 2/4 Lines 1-9/", 0) == 0);
    assert(pages[2].title == "Content");
    assert(pages[2].page_indicator.rfind("Page 2/4 Lines 10-", 0) == 0);
    assert(!pages[1].lines.empty());
    assert(!pages[2].lines.empty());
    assert(pages[1].lines.back() != pages[2].lines.front());

    bool saw_tag_scroll_indicator = false;
    bool saw_tag_second_window_without_overlap = false;
    for (const nostrseal::TrustedReviewPage& page : pages) {
        if (page.title == "Tags" && page.page_indicator.rfind("Page 3/4 Lines ", 0) == 0) {
            saw_tag_scroll_indicator = true;
        }
        if (page.title == "Tags" && page.page_indicator.rfind("Page 3/4 Lines 10-", 0) == 0) {
            saw_tag_second_window_without_overlap = true;
        }
    }
    assert(saw_tag_scroll_indicator);
    assert(saw_tag_second_window_without_overlap);
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

    expect_throw("approval requires decision review page", [&] {
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

    expect_throw("approval requires decision review page", [&] {
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

    assert(transcript.size() == 4);
    assert(transcript[0].frame.title == "Event");
    assert((transcript[0].frame.body_lines == std::vector<std::string>{
                                                 "Kind 1",
                                                 "Created 1710000000",
                                                 "Author",
                                                 "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a",
                                                 "  b0f0b704075871aa",
                                             }));
    assert(transcript[1].frame.title == "Content");
    assert(transcript[1].frame.body_lines == nostrseal::test_vectors::basic_qr_review_approve_transcript()[1].frame.body_lines);
    assert(transcript[2].frame.title == "Tags");
    assert((transcript[2].frame.body_lines == std::vector<std::string>{"No tags"}));
    assert(transcript[3].frame.title == "Decision");
    assert(transcript[3].frame.action_hint == "Approve / Reject");
    assert(transcript[3].decision.has_value());
    assert(transcript[3].decision.value());
    assert(transcript[3].approved_for_signing);
}

void test_qr_review_flow_transcript_records_early_rejection() {
    const std::vector<nostrseal::QrReviewTranscriptStep> transcript = nostrseal::run_qr_review_transcript(
        nostrseal::test_vectors::kQrEnvelopeKind1Basic,
        nostrseal::test_vectors::basic_qr_review_reject_buttons());

    assert(transcript.size() == 1);
    assert(transcript[0].frame.title == "Event");
    assert(lines_contain(transcript[0].frame.body_lines, "Author"));
    assert(!lines_contain(transcript[0].frame.body_lines, "Short Text Note"));
    assert(transcript[0].decision.has_value());
    assert(!transcript[0].decision.value());
    assert(!transcript[0].approved_for_signing);
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
    assert(result.transcript.size() == 4);
    assert(result.transcript[2].frame.title == "Tags");
    assert((result.transcript[2].frame.body_lines == std::vector<std::string>{"No tags"}));
    assert(result.transcript.back().decision.has_value());
    assert(result.transcript.back().decision.value());
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
    assert(io.frames[3].title == "Decision");
    assert(io.frames.back().title == "Event");
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

void test_review_controls_allow_backward_navigation_before_terminal_decision() {
    nostrseal::ReviewControlSession session{4};

    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_page_index() == 2);
    assert(!session.can_approve());

    assert(!session.handle_button(nostrseal::ReviewButton::Back).has_value());
    assert(session.current_page_index() == 1);
    assert(!session.can_approve());

    assert(!session.handle_button(nostrseal::ReviewButton::Back).has_value());
    assert(session.current_page_index() == 0);
    assert(!session.handle_button(nostrseal::ReviewButton::Back).has_value());
    assert(session.current_page_index() == 0);

    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_page_index() == 3);
    assert(session.can_approve());
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
        {"Kind 1", "Created 1710000000", "Author"},
        nostrseal::ReviewPageAction::Next,
    };

    const nostrseal::ReviewDisplayFrame frame = nostrseal::render_review_page(page, 0, 4);

    assert(frame.title == "Event");
    assert(frame.page_indicator == "Page 1/4");
    assert((frame.body_lines == std::vector<std::string>{"Kind 1", "Created 1710000000", "Author"}));
    assert(frame.action_hint == "Next");
}

void test_review_display_preserves_logical_page_indicator_and_body_styles() {
    const nostrseal::ReviewPage page{
        "Content",
        {"bytes: 281", "abcdef"},
        nostrseal::ReviewPageAction::Next,
        "Page 2/4",
        {nostrseal::ReviewBodyLineStyle::Meta, nostrseal::ReviewBodyLineStyle::Value},
    };

    const nostrseal::ReviewDisplayFrame frame = nostrseal::render_review_page(
        page,
        4,
        12,
        nostrseal::ReviewDisplayLimits{
            .max_title_chars = 18,
            .max_body_lines = 5,
            .max_line_chars = 26,
            .max_compact_body_lines = 9,
            .max_compact_line_chars = 48,
        });

    assert(frame.title == "Content");
    assert(frame.page_indicator == "Page 2/4");
    assert((frame.body_lines == std::vector<std::string>{"bytes: 281", "abcdef"}));
    assert((frame.body_line_styles == std::vector<nostrseal::ReviewBodyLineStyle>{
                                          nostrseal::ReviewBodyLineStyle::Meta,
                                          nostrseal::ReviewBodyLineStyle::Value,
                                      }));
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

void test_review_display_wraps_utf8_without_splitting_codepoints() {
    const std::string text = std::string("abc") + "\xC3\xA8" + "def";
    const nostrseal::ReviewPage page{
        "Content",
        {text},
        nostrseal::ReviewPageAction::Next,
    };

    const nostrseal::ReviewDisplayFrame frame = nostrseal::render_review_page(
        page,
        0,
        1,
        nostrseal::ReviewDisplayLimits{.max_title_chars = 12, .max_body_lines = 3, .max_line_chars = 4});

    assert((frame.body_lines == std::vector<std::string>{std::string("abc") + "\xC3\xA8", "def"}));
    assert(nostrseal::is_valid_utf8(frame.body_lines[0]));
    assert(nostrseal::is_valid_utf8(frame.body_lines[1]));
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

void test_review_display_matches_shared_utf8_boundary_frame_vector() {
    const std::string text = std::string("abc") + "\xC3\xA8" + "def";
    const nostrseal::ReviewPage page{
        "Content",
        {text},
        nostrseal::ReviewPageAction::Next,
    };

    const nostrseal::ReviewDisplayFrame frame = nostrseal::render_review_page(
        page,
        1,
        4,
        nostrseal::test_vectors::kind_1_unicode_boundary_content_4x3_display_limits());
    const nostrseal::ReviewDisplayFrame expected =
        nostrseal::test_vectors::kind_1_unicode_boundary_content_4x3_display_frame();

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
    assert(lines_contain(tags_frame.body_lines, "Tag 1/2"));
    assert(lines_contain(tags_frame.body_lines, "p"));

    (void)session.handle_button(nostrseal::ReviewButton::Next);
    const nostrseal::ReviewDisplayFrame decision_frame = session.current_frame();
    assert(decision_frame.title == "Decision");
    assert((decision_frame.body_lines == std::vector<std::string>{"Approve signing only if all pages match."}));

    const auto rejection = session.handle_button(nostrseal::ReviewButton::Reject);

    assert(rejection.has_value());
    assert(!rejection.value());
    assert(!session.can_sign());
    assert(session.decision() == nostrseal::ApprovalDecision::Rejected);
}

void test_trusted_review_session_allows_backward_review_before_approval() {
    nostrseal::TrustedReviewSession session{nostrseal::test_vectors::basic_trusted_review_request()};

    assert(session.current_frame().title == "Event");
    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Content");
    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Tags");
    assert(!session.handle_button(nostrseal::ReviewButton::Back).has_value());
    assert(session.current_frame().title == "Content");
    assert(!session.can_sign());

    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Decision");

    const auto approval = session.handle_button(nostrseal::ReviewButton::Approve);
    assert(approval.has_value());
    assert(approval.value());
    assert(session.can_sign());
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

void test_serial_review_session_uses_full_scroll_display_pages() {
    const std::string pubkey = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    nostrseal::TrustedReviewSession session = nostrseal::begin_serial_sign_event_trusted_review(
        R"({"version":1,"request_id":"req-kind-1-tags","method":"sign_event","params":{"event_template":{"created_at":1710000060,"kind":1,"tags":[["p","4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","","mention"],["t","nostrseal"]],"content":"NostrSeal fixture: tagged kind 1 event."}}})",
        nostrseal::ReviewDisplayLimits{.max_title_chars = 18, .max_body_lines = 3, .max_line_chars = 20});

    std::string tag_text;
    bool saw_tags = false;
    bool saw_warnings = false;
    for (std::size_t step = 0; step < 16U && session.current_frame().title != "Decision"; ++step) {
        const nostrseal::ReviewDisplayFrame frame = session.current_frame();
        if (frame.title == "Tags") {
            saw_tags = true;
            for (const std::string& line : frame.body_lines) {
                tag_text += line;
            }
        }
        if (frame.title == "Warnings") {
            saw_warnings = true;
        }
        assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    }

    assert(session.current_frame().title == "Decision");
    assert(saw_tags);
    assert(!saw_warnings);
    assert(tag_text.find("...") == std::string::npos);
    assert(tag_text.find(pubkey.substr(0, 48)) != std::string::npos);
    assert(tag_text.find(pubkey.substr(48)) != std::string::npos);
    assert(tag_text.find("mention") != std::string::npos);
    assert(tag_text.find("nostrseal") != std::string::npos);
}

void test_serial_review_session_uses_two_axis_navigation_for_scroll_windows() {
    std::string tags_json;
    for (int index = 0; index < 16; ++index) {
        if (!tags_json.empty()) {
            tags_json += ",";
        }
        tags_json += R"(["t","tagvalue)";
        tags_json += std::to_string(index);
        tags_json += R"(000000000000"])";
    }
    const std::string request_json =
        R"({"version":1,"request_id":"req-many-tags-nav","method":"sign_event","params":{"event_template":{"created_at":1710000180,"kind":1,"tags":[)" +
        tags_json +
        R"(],"content":"many tags navigation"}}})";

    nostrseal::TrustedReviewSession session = nostrseal::begin_serial_sign_event_trusted_review(
        request_json,
        nostrseal_esp32::t_display_s3_review_limits());

    assert(session.current_frame().title == "Event");
    assert(session.current_frame().page_indicator == "Page 1/4");
    expect_throw("approval requires decision review page", [&] {
        (void)session.handle_button(nostrseal::ReviewButton::Approve);
    });

    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Content");
    assert(session.current_frame().page_indicator == "Page 2/4");
    assert(session.current_frame().action_hint == "Next");

    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Tags");
    const std::string first_tag_page_indicator = session.current_frame().page_indicator;
    assert(first_tag_page_indicator.rfind("Page 3/4 Lines 1-9/", 0) == 0);
    assert(session.current_frame().action_hint == "Next/Scroll");

    assert(!session.handle_button(nostrseal::ReviewButton::Back).has_value());
    assert(session.current_frame().title == "Tags");
    assert(session.current_frame().page_indicator.rfind("Page 3/4 Lines 10-", 0) == 0);
    assert(session.current_frame().page_indicator != first_tag_page_indicator);
    assert(session.current_frame().action_hint == "Next/Scroll");

    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Decision");
    assert(session.current_frame().page_indicator == "Page 4/4");
    assert(!session.can_sign());

    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Event");
    assert(session.current_frame().page_indicator == "Page 1/4");

    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(!session.handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Decision");

    const auto approval = session.handle_button(nostrseal::ReviewButton::Approve);
    assert(approval.has_value());
    assert(approval.value());
    assert(session.can_sign());
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
    assert(default_status.development_accepted_gates.empty());
    assert((default_status.missing_gates == std::vector<std::string>{
                                               "runtime_signing_feature",
                                               "parser_limits",
                                               "trusted_review_display",
                                               "physical_approval_controls",
                                               "approval_digest_binding",
                                               "unicode_review_rendering",
                                               "key_provisioning",
                                               "secure_boot",
                                               "flash_encryption",
                                               "debug_lock",
                                               "companion_signed_output_verification",
                                           }));

    nostrseal::SigningReadiness safety_gates{
        .runtime_signing_feature_enabled = false,
        .parser_limits_enforced = true,
        .trusted_review_display_accepted = true,
        .physical_approval_controls_accepted = true,
        .approval_digest_binding_verified = true,
        .unicode_review_rendering_accepted = true,
        .key_provisioning_ready = true,
        .secure_boot_enabled = true,
        .flash_encryption_enabled = true,
        .debug_locked = true,
        .companion_signed_output_verification_ready = true,
        .development_accepted_gates = {
            "parser_limits",
            "trusted_review_display",
            "physical_approval_controls",
            "approval_digest_binding",
        },
    };
    const nostrseal::SigningReadinessStatus safety_status =
        nostrseal::evaluate_signing_readiness(safety_gates);

    assert(!safety_status.signing_enabled);
    assert((safety_status.missing_gates == std::vector<std::string>{"runtime_signing_feature"}));
    assert((safety_status.development_accepted_gates == std::vector<std::string>{
                                                        "parser_limits",
                                                        "trusted_review_display",
                                                        "physical_approval_controls",
                                                        "approval_digest_binding",
                                                    }));

    safety_gates.runtime_signing_feature_enabled = true;
    const nostrseal::SigningReadinessStatus ready_status =
        nostrseal::evaluate_signing_readiness(safety_gates);

    assert(ready_status.signing_enabled);
    assert(ready_status.missing_gates.empty());
    assert((ready_status.development_accepted_gates == safety_status.development_accepted_gates));

    safety_gates.development_accepted_gates.push_back("parser_limits");
    const nostrseal::SigningReadinessStatus duplicate_gate_status =
        nostrseal::evaluate_signing_readiness(safety_gates);

    assert((duplicate_gate_status.development_accepted_gates == safety_status.development_accepted_gates));
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

void test_device_protocol_exposes_review_frame_before_disabled_signing_response() {
    const nostrseal::SerialFrameHandlingResult result = nostrseal::handle_serial_frame_with_review_preview(
        nostrseal::test_vectors::kSignEventRequestFrame,
        nostrseal::ReviewDisplayLimits{
            .max_title_chars = 18,
            .max_body_lines = 5,
            .max_line_chars = 26,
        });

    assert(result.response_frame == nostrseal::test_vectors::kSignEventDisabledResponseFrame);
    assert(result.review_frame.has_value());
    assert(result.review_frame->title == "Event");
    assert(result.review_frame->page_indicator == "Page 1/4");
    assert(!result.review_frame->body_lines.empty());
    assert(result.review_frame->body_lines.front() == "Kind 1");
    assert(result.review_frame->action_hint == "Next");
}

void test_device_protocol_exposes_review_session_for_manual_display_navigation() {
    nostrseal::SerialFrameHandlingResult result = nostrseal::handle_serial_frame_with_review_preview(
        nostrseal::test_vectors::kSignEventRequestFrame,
        nostrseal::ReviewDisplayLimits{
            .max_title_chars = 18,
            .max_body_lines = 5,
            .max_line_chars = 26,
        });

    assert(result.response_frame == nostrseal::test_vectors::kSignEventDisabledResponseFrame);
    assert(result.review_session.has_value());
    assert(result.review_session->current_frame().title == "Event");
    assert(!result.review_session->handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(result.review_session->current_frame().title == "Content");
    assert(!result.review_session->handle_button(nostrseal::ReviewButton::Back).has_value());
    assert(result.review_session->current_frame().title == "Content");
    assert(!result.review_session->handle_button(nostrseal::ReviewButton::Next).has_value());
    assert(result.review_session->current_frame().title == "Tags");
    assert(!result.review_session->can_sign());
}

void test_device_protocol_reports_development_public_key() {
    const std::string response = nostrseal::handle_serial_frame(nostrseal::test_vectors::kPublicKeyRequestFrame);

    assert(response == nostrseal::test_vectors::kPublicKeyResponseFrame);
    const nostrseal::SerialFrame decoded = nostrseal::decode_serial_frame(response);
    assert(decoded.type == nostrseal::FrameType::Response);
    assert(decoded.payload_base64url == nostrseal::test_vectors::kPublicKeyResponsePayloadBase64Url);
}

void test_device_protocol_reports_signing_status_gates() {
    const std::string response = nostrseal::handle_serial_frame(nostrseal::test_vectors::kSigningStatusRequestFrame);

    assert(response == nostrseal::test_vectors::kSigningStatusResponseFrame);
    const nostrseal::SerialFrame decoded = nostrseal::decode_serial_frame(response);
    assert(decoded.type == nostrseal::FrameType::Response);
    assert(decoded.payload_base64url == nostrseal::test_vectors::kSigningStatusResponsePayloadBase64Url);
}

void test_device_protocol_echoes_dynamic_request_ids() {
    const std::string capability_response = nostrseal::handle_serial_frame(
        request_frame_for_test(R"({"version":1,"request_id":"req-alt-capabilities","method":"get_capabilities"})"));

    assert(capability_response == response_frame_for_test(
        R"({"version":1,"request_id":"req-alt-capabilities","ok":true,"result":{"capabilities":{"device":{"name":"NostrSeal ESP32-S3 USB Signer Scaffold","firmware":"nostrseal-esp32-s3-usb-signer","hardware":"esp32-s3-devkitc-1"},"protocols":["nseal.signing.v0","nseal.serial-frame.v0"],"methods":["get_capabilities","get_signing_status","get_public_key","sign_event"],"transports":["usb-serial-jtag"],"signing_enabled":false,"requires_physical_approval":true}}})"));

    const std::string signing_status_response = nostrseal::handle_serial_frame(
        request_frame_for_test(R"({"version":1,"request_id":"req-alt-signing-status","method":"get_signing_status"})"));

    assert(signing_status_response == response_frame_for_test(
        R"({"version":1,"request_id":"req-alt-signing-status","ok":true,"result":{"signing_status":{"signing_enabled":false,"missing_gates":["runtime_signing_feature","trusted_review_display","physical_approval_controls","unicode_review_rendering","key_provisioning","secure_boot","flash_encryption","debug_lock","companion_signed_output_verification"],"development_accepted_gates":["parser_limits","trusted_review_display","physical_approval_controls","approval_digest_binding"]}}})"));

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

    assert(nostrseal::handle_serial_frame(
               request_frame_for_test(
                   R"({"version":1,"request_id":"invalid-signing-status-params","method":"get_signing_status","params":{}})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));
}

void test_device_protocol_rejects_invalid_sign_event_request_shape() {
    assert(nostrseal::handle_serial_frame(
               request_frame_for_test(R"({"version":1,"request_id":"invalid-template-pubkey","method":"sign_event","params":{"event_template":{"pubkey":"0000000000000000000000000000000000000000000000000000000000000000","created_at":1710000000,"kind":1,"tags":[],"content":"unsafe template"}}})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));
}

void test_device_protocol_review_preserves_json_unicode_escapes() {
    nostrseal::SerialFrameHandlingResult result = nostrseal::handle_serial_frame_with_review_preview(
        request_frame_for_test(
            R"({"version":1,"request_id":"req-unicode-serial","method":"sign_event","params":{"event_template":{"created_at":1710000400,"kind":1,"tags":[["t","caf\u00e8"],["emoji","\uD83D\uDE00"]],"content":"caf\u00e8 \uD83D\uDE00"}}})"),
        nostrseal_esp32::t_display_s3_review_limits());

    assert(result.response_frame == response_frame_for_test(
                                      R"({"version":1,"request_id":"req-unicode-serial","ok":false,"error":{"code":"signing_disabled","message":"Signing is disabled until trusted review and physical approval are implemented.","retryable":false}})"));
    assert(result.review_session.has_value());
    assert(result.review_session->current_frame().title == "Event");
    assert(!result.review_session->handle_button(nostrseal::ReviewButton::Next).has_value());
    const nostrseal::ReviewDisplayFrame content = result.review_session->current_frame();
    assert(content.title == "Content");
    assert(lines_contain(content.body_lines, "U+00E8"));
    assert(lines_contain(content.body_lines, "U+1F600"));
}

void test_t_display_s3_raster_has_stable_boot_and_review_pixels() {
    using namespace nostrseal_esp32;

    assert(t_display_s3_boot_frame_color_for(0, 0) == kTDisplayS3ColorWhite);
    assert(t_display_s3_boot_frame_color_for(10, 10) == kTDisplayS3ColorBlue);
    assert(t_display_s3_boot_frame_color_for(20, 60) == kTDisplayS3ColorGreen);
    assert(t_display_s3_boot_frame_color_for(10, 60) == kTDisplayS3ColorBlack);

    nostrseal::ReviewDisplayFrame frame;
    frame.title = "Ready";
    frame.page_indicator = "Page 1/3";
    frame.body_lines = std::vector<std::string>{
        "USB signer",
        "Send sign_event",
        "Signing disabled",
    };
    frame.action_hint = "Waiting";

    assert(t_display_s3_review_limits().max_title_chars == 18);
    assert(t_display_s3_review_limits().max_body_lines == 5);
    assert(t_display_s3_review_limits().max_line_chars == 26);
    assert(t_display_s3_review_limits().max_compact_body_lines == 9);
    assert(t_display_s3_review_limits().max_compact_line_chars == 48);
    assert(t_display_s3_review_frame_color_for(frame, 0, 0) == kTDisplayS3ColorDarkBlue);
    assert(t_display_s3_review_frame_color_for(frame, 10, 7) == kTDisplayS3ColorWhite);
    assert(t_display_s3_review_frame_color_for(frame, 262, 9) == kTDisplayS3ColorGreen);
    assert(t_display_s3_review_frame_color_for(frame, 10, 42) == kTDisplayS3ColorWhite);
    assert(t_display_s3_review_frame_color_for(frame, 0, 160) == kTDisplayS3ColorAmber);
    assert(t_display_s3_review_frame_color_for(frame, 10, 152) == kTDisplayS3ColorBlack);

    nostrseal::ReviewDisplayFrame compact_frame;
    compact_frame.title = "Content";
    compact_frame.page_indicator = "Page 2/4";
    compact_frame.body_lines = std::vector<std::string>{"bytes: 281", "abcdef"};
    compact_frame.action_hint = "Next";
    compact_frame.body_line_styles = std::vector<nostrseal::ReviewBodyLineStyle>{
        nostrseal::ReviewBodyLineStyle::Meta,
        nostrseal::ReviewBodyLineStyle::Value,
    };

    assert(t_display_s3_review_frame_color_for(compact_frame, 10, 42) == kTDisplayS3ColorGreen);
    assert(t_display_s3_review_frame_color_for(compact_frame, 11, 55) == kTDisplayS3ColorWhite);

    nostrseal::ReviewDisplayFrame lowercase_frame;
    lowercase_frame.title = "Content";
    lowercase_frame.page_indicator = "Page 2/4";
    lowercase_frame.body_lines = std::vector<std::string>{"a"};
    lowercase_frame.action_hint = "Next";
    lowercase_frame.body_line_styles = std::vector<nostrseal::ReviewBodyLineStyle>{
        nostrseal::ReviewBodyLineStyle::Value,
    };

    assert(t_display_s3_review_frame_color_for(lowercase_frame, 11, 44) == kTDisplayS3ColorWhite);

    nostrseal::ReviewDisplayFrame comma_frame;
    comma_frame.title = "Content";
    comma_frame.page_indicator = "Page 2/4";
    comma_frame.body_lines = std::vector<std::string>{","};
    comma_frame.action_hint = "Next";
    comma_frame.body_line_styles = std::vector<nostrseal::ReviewBodyLineStyle>{
        nostrseal::ReviewBodyLineStyle::Value,
    };

    assert(t_display_s3_review_frame_color_for(comma_frame, 12, 47) == kTDisplayS3ColorWhite);

    nostrseal::ReviewDisplayFrame ascii_frame;
    ascii_frame.title = "ASCII";
    ascii_frame.page_indicator = "Page 1/1";
    ascii_frame.body_lines = {"^`"};
    ascii_frame.action_hint = "Next";
    assert(t_display_s3_review_frame_color_for(ascii_frame, 12, 44) == kTDisplayS3ColorWhite);
    assert(t_display_s3_review_frame_color_for(ascii_frame, 28, 46) == kTDisplayS3ColorWhite);
}

void test_t_display_s3_button_logic_classifies_debounced_short_and_long_presses() {
    nostrseal_esp32::TDisplayS3ButtonState state;

    assert(!nostrseal_esp32::update_t_display_s3_button_state(
                state,
                true,
                1000,
                14,
                nostrseal::ReviewButton::Next,
                nostrseal::ReviewButton::Approve)
                .has_value());
    assert(!nostrseal_esp32::update_t_display_s3_button_state(
                state,
                false,
                1010,
                14,
                nostrseal::ReviewButton::Next,
                nostrseal::ReviewButton::Approve)
                .has_value());

    assert(!nostrseal_esp32::update_t_display_s3_button_state(
                state,
                true,
                2000,
                14,
                nostrseal::ReviewButton::Next,
                nostrseal::ReviewButton::Approve)
                .has_value());
    const auto short_press = nostrseal_esp32::update_t_display_s3_button_state(
        state,
        false,
        2040,
        14,
        nostrseal::ReviewButton::Next,
        nostrseal::ReviewButton::Approve);
    assert(short_press.has_value());
    assert(short_press->button == nostrseal::ReviewButton::Next);
    assert(short_press->gpio == 14);
    assert(!short_press->long_press);

    nostrseal_esp32::TDisplayS3ButtonState back_state;
    assert(!nostrseal_esp32::update_t_display_s3_button_state(
                back_state,
                true,
                4000,
                0,
                nostrseal::ReviewButton::Back,
                nostrseal::ReviewButton::Reject)
                .has_value());
    const auto back_press = nostrseal_esp32::update_t_display_s3_button_state(
        back_state,
        false,
        4040,
        0,
        nostrseal::ReviewButton::Back,
        nostrseal::ReviewButton::Reject);
    assert(back_press.has_value());
    assert(back_press->button == nostrseal::ReviewButton::Back);
    assert(back_press->gpio == 0);
    assert(!back_press->long_press);

    assert(!nostrseal_esp32::update_t_display_s3_button_state(
                state,
                true,
                3000,
                0,
                nostrseal::ReviewButton::Back,
                nostrseal::ReviewButton::Reject)
                .has_value());
    const auto long_press = nostrseal_esp32::update_t_display_s3_button_state(
        state,
        false,
        3800,
        0,
        nostrseal::ReviewButton::Back,
        nostrseal::ReviewButton::Reject);
    assert(long_press.has_value());
    assert(long_press->button == nostrseal::ReviewButton::Reject);
    assert(long_press->gpio == 0);
    assert(long_press->long_press);

    nostrseal_esp32::TDisplayS3ButtonState approve_state;
    assert(!nostrseal_esp32::update_t_display_s3_button_state(
                approve_state,
                true,
                5000,
                14,
                nostrseal::ReviewButton::Next,
                nostrseal::ReviewButton::Approve)
                .has_value());
    const auto approve_press = nostrseal_esp32::update_t_display_s3_button_state(
        approve_state,
        false,
        5800,
        14,
        nostrseal::ReviewButton::Next,
        nostrseal::ReviewButton::Approve);
    assert(approve_press.has_value());
    assert(approve_press->button == nostrseal::ReviewButton::Approve);
    assert(approve_press->gpio == 14);
    assert(approve_press->long_press);
}

void test_t_display_s3_status_frames_keep_non_signing_copy_stable() {
    const nostrseal::ReviewDisplayFrame ready = nostrseal_esp32::build_t_display_s3_ready_frame();
    assert(ready.title == "Ready");
    assert(ready.page_indicator == "No request");
    assert(ready.body_lines == std::vector<std::string>({
                                   "USB signer",
                                   "Send sign_event",
                                   "Signing disabled",
                               }));
    assert(ready.action_hint == "Waiting");

    const nostrseal::ReviewDisplayFrame approved =
        nostrseal_esp32::build_t_display_s3_review_decision_frame(true);
    assert(approved.title == "Review OK");
    assert(approved.page_indicator == "Closed");
    assert(approved.body_lines == std::vector<std::string>({
                                      "Not signed",
                                      "Signing disabled",
                                      "Send new request",
                                  }));
    assert(approved.action_hint == "Waiting");

    const nostrseal::ReviewDisplayFrame rejected =
        nostrseal_esp32::build_t_display_s3_review_decision_frame(false);
    assert(rejected.title == "Rejected");
    assert(rejected.page_indicator == "Closed");
    assert(rejected.body_lines == approved.body_lines);
    assert(rejected.action_hint == "Waiting");

    const nostrseal::ReviewDisplayFrame timeout = nostrseal_esp32::build_t_display_s3_review_timeout_frame();
    assert(timeout.title == "Review Timeout");
    assert(timeout.page_indicator == "Expired");
    assert(timeout.body_lines == approved.body_lines);
    assert(timeout.action_hint == "Waiting");

    const nostrseal::ReviewDisplayFrame error = nostrseal_esp32::build_t_display_s3_request_error_frame();
    assert(error.title == "Request Error");
    assert(error.page_indicator == "Rejected");
    assert(error.body_lines == approved.body_lines);
    assert(error.action_hint == "Waiting");
}

void test_t_display_s3_serial_input_drains_after_overlong_frame() {
    nostrseal_esp32::TDisplayS3SerialInput input;
    for (char ch : std::string("12345678")) {
        const nostrseal_esp32::TDisplayS3SerialInputEvent event =
            nostrseal_esp32::update_t_display_s3_serial_input(input, ch, 8);
        assert(event.kind == nostrseal_esp32::TDisplayS3SerialInputEventKind::None);
    }

    const nostrseal_esp32::TDisplayS3SerialInputEvent overlong =
        nostrseal_esp32::update_t_display_s3_serial_input(input, '9', 8);
    assert(overlong.kind == nostrseal_esp32::TDisplayS3SerialInputEventKind::OverlongFrame);
    assert(overlong.line.empty());

    for (char ch : std::string("tail")) {
        const nostrseal_esp32::TDisplayS3SerialInputEvent event =
            nostrseal_esp32::update_t_display_s3_serial_input(input, ch, 8);
        assert(event.kind == nostrseal_esp32::TDisplayS3SerialInputEventKind::None);
    }
    const nostrseal_esp32::TDisplayS3SerialInputEvent drained =
        nostrseal_esp32::update_t_display_s3_serial_input(input, '\n', 8);
    assert(drained.kind == nostrseal_esp32::TDisplayS3SerialInputEventKind::None);

    nostrseal_esp32::TDisplayS3SerialInputEvent ready;
    for (char ch : std::string("ok\r\n")) {
        ready = nostrseal_esp32::update_t_display_s3_serial_input(input, ch, 8);
    }
    assert(ready.kind == nostrseal_esp32::TDisplayS3SerialInputEventKind::FrameReady);
    assert(ready.line == "ok\n");
}

}  // namespace

int main() {
    test_serial_frame_round_trip();
    test_serial_frame_rejections();
    test_serial_frame_rejects_shared_invalid_vectors();
    test_qr_envelope_decodes_shared_vector();
    test_animated_qr_envelope_decodes_shared_vector();
    test_qr_envelope_parses_sign_event_request_metadata();
    test_qr_envelope_extracts_event_template_boundary();
    test_qr_envelope_parses_event_template_fields();
    test_qr_signing_request_tolerates_escaped_event_content();
    test_qr_signing_request_preserves_json_unicode_escapes();
    test_qr_envelope_rejections();
    test_qr_envelope_rejects_shared_invalid_qr_vectors();
    test_animated_qr_envelope_rejections();
    test_qr_limits_match_shared_profile();
    test_qr_signing_request_rejections();
    test_qr_signing_request_rejects_shared_invalid_request_vectors();
    test_qr_review_pages_match_shared_basic_vector();
    test_qr_trusted_review_request_matches_shared_basic_vector();
    test_qr_review_pages_match_shared_tagged_vector();
    test_qr_trusted_review_request_matches_shared_tagged_vector();
    test_qr_display_review_pages_show_full_tag_values_without_ellipsis();
    test_qr_display_review_pages_group_logical_sections_with_compact_styles();
    test_qr_display_review_pages_match_shared_detail_page_vectors();
    test_qr_display_review_pages_escape_non_ascii_for_display_safety();
    test_qr_display_review_pages_preserve_supported_ascii_punctuation();
    test_qr_display_review_pages_split_full_long_content_without_ellipsis();
    test_qr_display_review_pages_use_scroll_line_indicators_for_long_sections();
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
    test_review_controls_allow_backward_navigation_before_terminal_decision();
    test_review_controls_allow_early_rejection();
    test_review_controls_are_terminal_after_decision();
    test_review_display_renders_navigation_frame();
    test_review_display_preserves_logical_page_indicator_and_body_styles();
    test_review_display_renders_decision_frame();
    test_review_display_wraps_and_truncates_long_body_lines();
    test_review_display_wraps_utf8_without_splitting_codepoints();
    test_review_display_matches_shared_long_content_frame_vector();
    test_review_display_matches_shared_utf8_boundary_frame_vector();
    test_review_display_rejects_unsafe_frame_bounds();
    test_trusted_review_session_binds_display_navigation_and_approval();
    test_trusted_review_session_keeps_rejection_terminal();
    test_trusted_review_session_allows_backward_review_before_approval();
    test_serial_sign_event_review_matches_shared_review_contract();
    test_serial_review_session_uses_full_scroll_display_pages();
    test_serial_review_session_uses_two_axis_navigation_for_scroll_windows();
    test_serial_review_io_flow_drives_request_display_and_buttons_without_signing();
    test_signing_policy_requires_every_runtime_gate_before_enablement();
    test_device_protocol_reports_scaffold_capabilities();
    test_device_protocol_rejects_signing_while_disabled();
    test_device_protocol_exposes_review_frame_before_disabled_signing_response();
    test_device_protocol_exposes_review_session_for_manual_display_navigation();
    test_device_protocol_reports_development_public_key();
    test_device_protocol_reports_signing_status_gates();
    test_device_protocol_echoes_dynamic_request_ids();
    test_device_protocol_rejects_invalid_dynamic_request_metadata();
    test_device_protocol_rejects_unknown_top_level_request_fields();
    test_device_protocol_rejects_params_for_parameterless_methods();
    test_device_protocol_rejects_invalid_sign_event_request_shape();
    test_device_protocol_review_preserves_json_unicode_escapes();
    test_t_display_s3_raster_has_stable_boot_and_review_pixels();
    test_t_display_s3_button_logic_classifies_debounced_short_and_long_presses();
    test_t_display_s3_status_frames_keep_non_signing_copy_stable();
    test_t_display_s3_serial_input_drains_after_overlong_frame();
    std::cout << "host core tests passed\n";
    return 0;
}
