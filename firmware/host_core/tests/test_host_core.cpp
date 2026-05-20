#include <cassert>
#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "nsealr/approval_gate.hpp"
#include "nsealr/bip39_english.hpp"
#include "nsealr/device_protocol.hpp"
#include "nsealr/limits.hpp"
#include "nsealr/nip19_nsec.hpp"
#include "nsealr/policy_change_review.hpp"
#include "nsealr/qr_envelope.hpp"
#include "nsealr/qr_review.hpp"
#include "nsealr/qr_review_flow.hpp"
#include "nsealr/review_controls.hpp"
#include "nsealr/review_display.hpp"
#include "nsealr/serial_frame.hpp"
#include "nsealr/serial_review.hpp"
#include "nsealr/seedqr.hpp"
#include "nsealr/session_account.hpp"
#include "nsealr/session_import_flow.hpp"
#include "nsealr/session_import_review.hpp"
#include "nsealr/session_keyring.hpp"
#include "nsealr/session_source_backup.hpp"
#include "nsealr/session_source_generation.hpp"
#include "nsealr/session_source_qr.hpp"
#include "nsealr/session_source_qr_import_flow.hpp"
#include "nsealr/signing_policy.hpp"
#include "nsealr/trusted_review.hpp"
#include "nsealr/utf8.hpp"
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
    return nsealr::encode_serial_frame(
        nsealr::SerialFrame{nsealr::FrameType::Request, base64url_encode_for_test(request_json)});
}

std::string response_frame_for_test(const std::string& response_json) {
    return nsealr::encode_serial_frame(
        nsealr::SerialFrame{nsealr::FrameType::Response, base64url_encode_for_test(response_json)});
}

std::string error_frame_for_test(const std::string& error_json) {
    return nsealr::encode_serial_frame(
        nsealr::SerialFrame{nsealr::FrameType::Error, base64url_encode_for_test(error_json)});
}

void expect_throw(const std::string& expected, const auto& fn) {
    try {
        fn();
    } catch (const std::exception& exc) {
        const std::string actual = exc.what();
        if (actual.find(expected) == std::string::npos) {
            std::cerr << "expected exception containing '" << expected << "' but got '" << actual << "'\n";
        }
        assert(actual.find(expected) != std::string::npos);
        return;
    }
    assert(false && "expected exception");
}

template <typename T, std::size_t N>
bool all_zero(const std::array<T, N>& values) {
    return std::all_of(values.begin(), values.end(), [](const T& value) {
        return value == 0;
    });
}

int hex_nibble_for_test(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    assert(false && "invalid hex");
    return 0;
}

std::vector<std::uint8_t> bytes_from_hex_for_test(const std::string& hex) {
    assert((hex.size() % 2U) == 0U);
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2U);
    for (std::size_t offset = 0; offset < hex.size(); offset += 2U) {
        out.push_back(static_cast<std::uint8_t>(
            (hex_nibble_for_test(hex[offset]) << 4) | hex_nibble_for_test(hex[offset + 1U])));
    }
    return out;
}

void assert_trusted_review_pages(
    const std::vector<nsealr::TrustedReviewPage>& actual,
    const std::vector<nsealr::TrustedReviewPage>& expected) {
    assert(actual.size() == expected.size());
    for (std::size_t index = 0; index < actual.size(); ++index) {
        assert(actual[index].title == expected[index].title);
        assert(actual[index].lines == expected[index].lines);
        assert(actual[index].action == expected[index].action);
    }
}

void assert_detailed_trusted_review_pages(
    const std::vector<nsealr::TrustedReviewPage>& actual,
    const std::vector<nsealr::TrustedReviewPage>& expected) {
    assert_trusted_review_pages(actual, expected);
    for (std::size_t index = 0; index < actual.size(); ++index) {
        assert(actual[index].page_indicator == expected[index].page_indicator);
        assert(actual[index].body_line_styles == expected[index].body_line_styles);
        assert(actual[index].logical_page_id == expected[index].logical_page_id);
    }
}

nsealr::test_vectors::SessionImportReviewVector session_import_review_vector_by_name(
    const std::string& name) {
    for (const nsealr::test_vectors::SessionImportReviewVector& vector :
         nsealr::test_vectors::session_import_review_vectors()) {
        if (std::string(vector.name) == name) {
            return vector;
        }
    }
    assert(false && "missing session import review vector");
    return {};
}

nsealr::test_vectors::SessionSourceBackupVector session_source_backup_vector_by_name(
    const std::string& name) {
    for (const nsealr::test_vectors::SessionSourceBackupVector& vector :
         nsealr::test_vectors::session_source_backup_vectors()) {
        if (std::string(vector.name) == name) {
            return vector;
        }
    }
    assert(false && "missing session source backup vector");
    return {};
}

nsealr::test_vectors::SourcePublicKeyProofVector source_public_key_proof_vector_by_name(
    const std::string& name) {
    for (const nsealr::test_vectors::SourcePublicKeyProofVector& vector :
         nsealr::test_vectors::source_public_key_proof_vectors()) {
        if (std::string(vector.name) == name) {
            return vector;
        }
    }
    assert(false && "missing source public-key proof vector");
    return {};
}

nsealr::test_vectors::PolicyChangeReviewVector policy_change_review_vector_by_name(
    const std::string& name) {
    for (const nsealr::test_vectors::PolicyChangeReviewVector& vector :
         nsealr::test_vectors::policy_change_review_vectors()) {
        if (std::string(vector.name) == name) {
            return vector;
        }
    }
    assert(false && "missing policy change review vector");
    return {};
}

void assert_qr_review_transcript_equals(
    const std::vector<nsealr::QrReviewTranscriptStep>& actual,
    const std::vector<nsealr::QrReviewTranscriptStep>& expected) {
    assert(actual.size() == expected.size());
    for (std::size_t index = 0; index < actual.size(); ++index) {
        assert(actual[index].frame.title == expected[index].frame.title);
        assert(actual[index].frame.page_indicator == expected[index].frame.page_indicator);
        assert(actual[index].frame.body_lines == expected[index].frame.body_lines);
        assert(actual[index].frame.action_hint == expected[index].frame.action_hint);
        assert(actual[index].frame.body_line_styles == expected[index].frame.body_line_styles);
        assert(actual[index].button == expected[index].button);
        assert(actual[index].decision == expected[index].decision);
        assert(actual[index].approved_for_signing == expected[index].approved_for_signing);
    }
}

std::size_t page_count_with_title(
    const std::vector<nsealr::TrustedReviewPage>& pages,
    const std::string& title) {
    std::size_t count = 0;
    for (const nsealr::TrustedReviewPage& page : pages) {
        if (page.title == title) {
            ++count;
        }
    }
    return count;
}

std::string joined_lines_for_title(
    const std::vector<nsealr::TrustedReviewPage>& pages,
    const std::string& title) {
    std::string joined;
    for (const nsealr::TrustedReviewPage& page : pages) {
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

void assert_session_seed_words_equal(
    const nsealr::SessionSeedWordIndexes& actual,
    const std::vector<std::uint16_t>& expected) {
    assert(actual.count == expected.size());
    for (std::size_t index = 0; index < expected.size(); ++index) {
        assert(actual.values[index] == expected[index]);
    }
}

class RecordingQrReviewIo : public nsealr::QrReviewIo {
public:
    explicit RecordingQrReviewIo(std::vector<nsealr::ReviewButton> buttons) : buttons_(std::move(buttons)) {}

    std::string scan_request_qr() override {
        return nsealr::test_vectors::kQrEnvelopeKind1Basic;
    }

    void show_review_frame(const nsealr::ReviewDisplayFrame& frame) override {
        frames.push_back(frame);
    }

    nsealr::ReviewButton read_review_button() override {
        assert(!buttons_.empty());
        const nsealr::ReviewButton button = buttons_.front();
        buttons_.erase(buttons_.begin());
        return button;
    }

    std::vector<nsealr::ReviewDisplayFrame> frames;

private:
    std::vector<nsealr::ReviewButton> buttons_;
};

class NextOnlyQrReviewIo : public nsealr::QrReviewIo {
public:
    std::string scan_request_qr() override {
        return nsealr::test_vectors::kQrEnvelopeKind1Basic;
    }

    void show_review_frame(const nsealr::ReviewDisplayFrame& frame) override {
        frames.push_back(frame);
    }

    nsealr::ReviewButton read_review_button() override {
        return nsealr::ReviewButton::Next;
    }

    std::vector<nsealr::ReviewDisplayFrame> frames;
};

class RecordingSerialReviewIo : public nsealr::SerialReviewIo {
public:
    explicit RecordingSerialReviewIo(std::vector<nsealr::ReviewButton> buttons) : buttons_(std::move(buttons)) {}

    std::string read_request_json() override {
        return R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"nSealr fixture: basic kind 1 event."}}})";
    }

    void show_review_frame(const nsealr::ReviewDisplayFrame& frame) override {
        frames.push_back(frame);
    }

    nsealr::ReviewButton read_review_button() override {
        assert(!buttons_.empty());
        const nsealr::ReviewButton button = buttons_.front();
        buttons_.erase(buttons_.begin());
        return button;
    }

    std::vector<nsealr::ReviewDisplayFrame> frames;

private:
    std::vector<nsealr::ReviewButton> buttons_;
};

void test_serial_frame_round_trip() {
    const nsealr::SerialFrame frame{
        nsealr::FrameType::Request,
        nsealr::test_vectors::kSerialFramePayloadBase64Url,
    };

    const std::string encoded = nsealr::encode_serial_frame(frame);
    assert(encoded == nsealr::test_vectors::kSerialFrame);

    const nsealr::SerialFrame decoded = nsealr::decode_serial_frame(encoded);
    assert(decoded.type == nsealr::FrameType::Request);
    assert(decoded.payload_base64url == frame.payload_base64url);

    const nsealr::SerialFrame decoded_crlf =
        nsealr::decode_serial_frame(encoded.substr(0, encoded.size() - 1) + "\r\n");
    assert(decoded_crlf.type == nsealr::FrameType::Request);
    assert(decoded_crlf.payload_base64url == frame.payload_base64url);
}

void test_serial_frame_rejections() {
    expect_throw("unsupported serial frame type", [] {
        (void)nsealr::decode_serial_frame("nsealr1f:pubkey:eyJ2ZXJzaW9uIjoxfQ:d78075380263956b\n");
    });
    expect_throw("serial frame checksum mismatch", [] {
        (void)nsealr::decode_serial_frame("nsealr1f:request:eyJ2ZXJzaW9uIjoxfQ:0000000000000000\n");
    });
    expect_throw("serial frame payload", [] {
        (void)nsealr::decode_serial_frame("nsealr1f:request:not+base64url:d78075380263956b\n");
    });
}

void test_serial_frame_rejects_shared_invalid_vectors() {
    expect_throw("serial frame exceeds max_serial_frame_bytes", [] {
        (void)nsealr::decode_serial_frame(nsealr::test_vectors::kInvalidSerialFrameOversized);
    });
    expect_throw("serial frame checksum mismatch", [] {
        (void)nsealr::decode_serial_frame(nsealr::test_vectors::kInvalidSerialFrameChecksumMismatch);
    });
    expect_throw("serial frame payload", [] {
        (void)nsealr::decode_serial_frame(nsealr::test_vectors::kInvalidSerialFrameMalformedPayload);
    });
    expect_throw("unsupported serial frame type", [] {
        (void)nsealr::decode_serial_frame(nsealr::test_vectors::kInvalidSerialFrameUnsupportedType);
    });
}

void test_qr_envelope_decodes_shared_vector() {
    const nsealr::QrEnvelope envelope =
        nsealr::decode_qr_envelope(nsealr::test_vectors::kQrEnvelopeKind1Basic);

    assert(envelope.payload_base64url == nsealr::test_vectors::kQrEnvelopeKind1BasicPayloadBase64Url);
    assert(envelope.payload_json.find("\"request_id\":\"req-kind-1-basic\"") != std::string::npos);
    assert(envelope.payload_json.find("\"method\":\"sign_event\"") != std::string::npos);
}

void test_animated_qr_envelope_decodes_shared_vector() {
    const nsealr::QrEnvelope envelope =
        nsealr::decode_animated_qr_envelope_frames(nsealr::test_vectors::animated_qr_response_kind_1_basic_frames());

    assert(envelope.payload_base64url == nsealr::test_vectors::kAnimatedQrResponseKind1BasicPayloadBase64Url);
    assert(envelope.payload_json == nsealr::test_vectors::kAnimatedQrResponseKind1BasicJson);
}

void test_qr_envelope_encodes_signed_response_vectors_without_signing() {
    const std::string static_envelope =
        nsealr::encode_qr_envelope_json(nsealr::test_vectors::kAnimatedQrResponseKind1BasicJson);
    const std::vector<std::string> animated_frames = nsealr::encode_animated_qr_envelope_json(
        nsealr::test_vectors::kAnimatedQrResponseKind1BasicJson,
        nsealr::kMaxAnimatedQrFramePayloadChars);

    assert(static_envelope ==
           std::string("nsealr1:") + nsealr::test_vectors::kAnimatedQrResponseKind1BasicPayloadBase64Url);
    assert(animated_frames == nsealr::test_vectors::animated_qr_response_kind_1_basic_frames());
    assert(nsealr::decode_qr_envelope(static_envelope).payload_json ==
           nsealr::test_vectors::kAnimatedQrResponseKind1BasicJson);
    assert(nsealr::decode_animated_qr_envelope_frames(animated_frames).payload_json ==
           nsealr::test_vectors::kAnimatedQrResponseKind1BasicJson);
}

void test_qr_envelope_parses_sign_event_request_metadata() {
    const nsealr::QrEnvelope envelope =
        nsealr::decode_qr_envelope(nsealr::test_vectors::kQrEnvelopeKind1Basic);
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(envelope);

    assert(request.version == 1);
    assert(request.request_id == "req-kind-1-basic");
    assert(request.method == "sign_event");
    assert(request.has_params);
}

void test_qr_envelope_extracts_event_template_boundary() {
    const nsealr::QrEnvelope envelope =
        nsealr::decode_qr_envelope(nsealr::test_vectors::kQrEnvelopeKind1Basic);
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(envelope);

    assert(request.has_event_template);
    assert(request.event_template_json.find("\"kind\":1") != std::string::npos);
    assert(request.event_template_json.find("\"content\":\"nSealr fixture: basic kind 1 event.\"") !=
           std::string::npos);
}

void test_qr_envelope_parses_event_template_fields() {
    const nsealr::QrEnvelope envelope =
        nsealr::decode_qr_envelope(nsealr::test_vectors::kQrEnvelopeKind1Basic);
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(envelope);

    assert(request.event_template.created_at == 1710000000U);
    assert(request.event_template.kind == 1);
    assert(request.event_template.content == "nSealr fixture: basic kind 1 event.");
    assert(request.event_template.tags_json == "[]");
}

void test_qr_signing_request_tolerates_escaped_event_content() {
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(
        nsealr::QrEnvelope{"ignored",
                              R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"Quote: \"nostr\"\nNext line"}}})"});

    assert(request.has_event_template);
    assert(request.event_template.content == "Quote: \"nostr\"\nNext line");
    assert(request.event_template_json.find(R"("content":"Quote: \"nostr\"\nNext line")") != std::string::npos);
}

void test_qr_signing_request_preserves_json_unicode_escapes() {
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(
        nsealr::QrEnvelope{"ignored",
                              R"({"version":1,"request_id":"req-unicode-escapes","method":"sign_event","params":{"event_template":{"created_at":1710000400,"kind":1,"tags":[["t","caf\u00e8"],["emoji","\uD83D\uDE00"]],"content":"caf\u00e8 \uD83D\uDE00"}}})"});

    assert(request.event_template.content == std::string("caf") + "\xC3\xA8" + " " + "\xF0\x9F\x98\x80");
    assert(request.event_template.tags.size() == 2);
    assert(request.event_template.tags[0][1] == std::string("caf") + "\xC3\xA8");
    assert(request.event_template.tags[1][1] == std::string("\xF0\x9F\x98\x80"));

    const std::vector<nsealr::TrustedReviewPage> pages =
        nsealr::build_qr_display_review_pages(request, nsealr_esp32::t_display_s3_review_limits());
    assert(joined_lines_for_title(pages, "Content").find("U+00E8") != std::string::npos);
    assert(joined_lines_for_title(pages, "Content").find("U+1F600") != std::string::npos);
    assert(joined_lines_for_title(pages, "Tags").find("U+00E8") != std::string::npos);
    assert(joined_lines_for_title(pages, "Tags").find("U+1F600") != std::string::npos);
}

void test_qr_envelope_rejections() {
    expect_throw("QR envelope must start with nsealr1:", [] {
        (void)nsealr::decode_qr_envelope("nostr:abc");
    });
    expect_throw("QR envelope payload must be unpadded base64url", [] {
        (void)nsealr::decode_qr_envelope("nsealr1:abc=");
    });
    expect_throw("QR envelope payload must be unpadded base64url", [] {
        (void)nsealr::decode_qr_envelope("nsealr1:not+base64url");
    });
    expect_throw("QR envelope payload has invalid base64url length", [] {
        (void)nsealr::decode_qr_envelope("nsealr1:A");
    });
    expect_throw("QR envelope payload is not valid JSON", [] {
        (void)nsealr::decode_qr_envelope("nsealr1:bm90LWpzb24");
    });
}

void test_qr_envelope_rejects_shared_invalid_qr_vectors() {
    expect_throw("QR decoded JSON exceeds max_static_qr_decoded_json_bytes", [] {
        (void)nsealr::decode_qr_envelope(nsealr::test_vectors::kInvalidQrEnvelopeOversized);
    });
    expect_throw("QR envelope payload must be unpadded base64url", [] {
        (void)nsealr::decode_qr_envelope(nsealr::test_vectors::kInvalidQrEnvelopePadded);
    });
    expect_throw("QR envelope must start with nsealr1:", [] {
        (void)nsealr::decode_qr_envelope(nsealr::test_vectors::kInvalidQrEnvelopeMalformed);
    });
    expect_throw("QR envelope payload must be valid UTF-8", [] {
        (void)nsealr::decode_qr_envelope(nsealr::test_vectors::kInvalidQrEnvelopeInvalidUtf8);
    });
}

void test_animated_qr_envelope_rejections() {
    expect_throw("animated QR requires at least one frame", [] {
        (void)nsealr::decode_animated_qr_envelope_frames({});
    });
    expect_throw("animated QR frames must be unique and contiguous", [] {
        std::vector<std::string> frames = nsealr::test_vectors::animated_qr_response_kind_1_basic_frames();
        frames.erase(frames.begin());
        (void)nsealr::decode_animated_qr_envelope_frames(frames);
    });
    expect_throw("animated QR frame checksum mismatch", [] {
        std::vector<std::string> frames = nsealr::test_vectors::animated_qr_response_kind_1_basic_frames();
        char& last = frames[0].back();
        last = last == '0' ? '1' : '0';
        (void)nsealr::decode_animated_qr_envelope_frames(frames);
    });
    expect_throw("animated QR frame count exceeds max_animated_qr_frame_count", [] {
        const std::string frame =
            "nsealr1a:0000000000000000000000000000000000000000000000000000000000000000:"
            "1/65:AA:0000000000000000";
        (void)nsealr::decode_animated_qr_envelope_frames({frame});
    });
    expect_throw("animated QR chunk exceeds max_animated_qr_frame_payload_chars", [] {
        const std::string oversized_chunk(nsealr::kMaxAnimatedQrFramePayloadChars + 1U, 'A');
        const std::string frame =
            "nsealr1a:0000000000000000000000000000000000000000000000000000000000000000:"
            "1/1:" +
            oversized_chunk + ":0000000000000000";
        (void)nsealr::decode_animated_qr_envelope_frames({frame});
    });
    expect_throw("animated QR index and total must be decimal", [] {
        const std::string frame =
            "nsealr1a:0000000000000000000000000000000000000000000000000000000000000000:"
            "184467440737095516160/1:AA:0000000000000000";
        (void)nsealr::decode_animated_qr_envelope_frames({frame});
    });
}

void test_qr_envelope_encoder_rejections() {
    expect_throw("QR decoded JSON exceeds max_static_qr_decoded_json_bytes", [] {
        (void)nsealr::encode_qr_envelope_json(std::string("{\"x\":\"") +
                                              std::string(nsealr::kMaxStaticQrDecodedJsonBytes, 'x') + "\"}");
    });
    expect_throw("animated QR decoded JSON exceeds max_animated_qr_decoded_json_bytes", [] {
        (void)nsealr::encode_animated_qr_envelope_json(
            std::string("{\"x\":\"") + std::string(nsealr::kMaxAnimatedQrDecodedJsonBytes, 'x') + "\"}",
            nsealr::kMaxAnimatedQrFramePayloadChars);
    });
    expect_throw("animated QR chunk size must be a positive integer", [] {
        (void)nsealr::encode_animated_qr_envelope_json("{}", 0U);
    });
    expect_throw("animated QR chunk exceeds max_animated_qr_frame_payload_chars", [] {
        (void)nsealr::encode_animated_qr_envelope_json("{}", nsealr::kMaxAnimatedQrFramePayloadChars + 1U);
    });
    expect_throw("QR envelope payload must be valid UTF-8", [] {
        std::string invalid = "{\"x\":\"";
        invalid.push_back(static_cast<char>(0xff));
        invalid += "\"}";
        (void)nsealr::encode_qr_envelope_json(invalid);
    });
}

void test_qr_limits_match_shared_profile() {
    assert(nsealr::kMaxRequestIdLength == nsealr::test_vectors::kMaxRequestIdLength);
    assert(nsealr::kMaxDecodedRequestJsonBytes == nsealr::test_vectors::kMaxDecodedRequestJsonBytes);
    assert(nsealr::kMaxStaticQrDecodedJsonBytes == nsealr::test_vectors::kMaxStaticQrDecodedJsonBytes);
    assert(nsealr::kMaxAnimatedQrDecodedJsonBytes == nsealr::test_vectors::kMaxAnimatedQrDecodedJsonBytes);
    assert(nsealr::kMaxAnimatedQrFramePayloadChars == nsealr::test_vectors::kMaxAnimatedQrFramePayloadChars);
    assert(nsealr::kMaxAnimatedQrFrameCount == nsealr::test_vectors::kMaxAnimatedQrFrameCount);
    assert(nsealr::kMaxSerialFrameBytes == nsealr::test_vectors::kMaxSerialFrameBytes);
    assert(nsealr::kMaxContentUtf8Bytes == nsealr::test_vectors::kMaxContentUtf8Bytes);
    assert(nsealr::kMaxTagCount == nsealr::test_vectors::kMaxTagCount);
    assert(nsealr::kMaxTagFieldsPerTag == nsealr::test_vectors::kMaxTagFieldsPerTag);
    assert(nsealr::kMaxTagFieldUtf8Bytes == nsealr::test_vectors::kMaxTagFieldUtf8Bytes);
    assert(nsealr::kMaxTotalTagUtf8Bytes == nsealr::test_vectors::kMaxTotalTagUtf8Bytes);
    assert(nsealr::kMaxSafeInteger == nsealr::test_vectors::kMaxSafeInteger);
}

void test_nip19_nsec_decoder_matches_shared_vector() {
    const nsealr::NsecSecretKey secret =
        nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1);

    assert(nsealr::decode_nsec_secret_key_hex(nsealr::test_vectors::kNip19NsecTestKey1) ==
           nsealr::test_vectors::kNip19NsecTestKey1SecretKey);
    assert(secret.front() == 0x11U);
    assert(secret.back() == 0x11U);
    assert(std::string(nsealr::test_vectors::kNip19NsecTestKey1PublicKey).size() == 64U);

    expect_throw("checksum", [] {
        (void)nsealr::decode_nsec_secret_key_hex("nsec1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygqqqqqq");
    });
    expect_throw("prefix", [] {
        (void)nsealr::decode_nsec_secret_key_hex("npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9");
    });
    expect_throw("lowercase", [] {
        (void)nsealr::decode_nsec_secret_key_hex("NSEC1ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYGS4RM7HZ");
    });
    expect_throw("unsupported characters", [] {
        (void)nsealr::decode_nsec_secret_key_hex("nsec1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygi4rm7hz");
    });
    expect_throw("invalid padding", [] {
        (void)nsealr::decode_nsec_secret_key_hex("nsec1py3nlzd");
    });
    expect_throw("32-byte secret key", [] {
        (void)nsealr::decode_nsec_secret_key_hex("nsec1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zypf0r0t");
    });
    expect_throw("malformed", [] {
        (void)nsealr::decode_nsec_secret_key_hex("nsec1short");
    });
}

void test_seedqr_decoders_match_shared_vector() {
    const std::vector<std::uint16_t> expected = nsealr::test_vectors::seedqr_vector_1_word_indexes();
    const std::vector<std::uint8_t> compact =
        bytes_from_hex_for_test(nsealr::test_vectors::kSeedQrVector1CompactHex);

    assert(nsealr::decode_standard_seedqr_indexes(nsealr::test_vectors::kSeedQrVector1StandardDigits) == expected);
    assert(nsealr::decode_compact_seedqr_indexes(compact) == expected);
    assert(nsealr::bip39_english_mnemonic_from_indexes(expected) ==
           nsealr::test_vectors::kSeedQrVector1Mnemonic);

    std::string spaced = nsealr::test_vectors::kSeedQrVector1StandardDigits;
    spaced.insert(8, "\n");
    spaced.insert(4, " ");
    assert(nsealr::decode_standard_seedqr_indexes(spaced) == expected);

    expect_throw("must contain only digits", [] {
        (void)nsealr::decode_standard_seedqr_indexes("000a");
    });
    expect_throw("four digits per word", [] {
        (void)nsealr::decode_standard_seedqr_indexes("000");
    });
    expect_throw("word count must be 12 or 24", [] {
        (void)nsealr::decode_standard_seedqr_indexes("0000000000000000");
    });
    expect_throw("outside the BIP-39 English wordlist", [] {
        (void)nsealr::decode_standard_seedqr_indexes(
            "2048"
            "1325"
            "1154"
            "0127"
            "1190"
            "0771"
            "0415"
            "0742"
            "1289"
            "1906"
            "2008"
            "0870"
            "0266"
            "1343"
            "1420"
            "2016"
            "1792"
            "0614"
            "0896"
            "1929"
            "0300"
            "1524"
            "0801"
            "0643");
    });
    expect_throw("checksum", [] {
        std::string mutated = nsealr::test_vectors::kSeedQrVector1StandardDigits;
        mutated.back() = mutated.back() == '0' ? '1' : '0';
        (void)nsealr::decode_standard_seedqr_indexes(mutated);
    });
    expect_throw("byte length", [] {
        (void)nsealr::decode_compact_seedqr_indexes({0x01U, 0x02U, 0x03U});
    });
}

void test_bip39_english_mnemonic_parser_matches_shared_vector() {
    const nsealr::Bip39WordIndexes indexes =
        nsealr::parse_bip39_english_mnemonic_indexes(nsealr::test_vectors::kNip06Account0Mnemonic);

    assert(indexes.size() == 12U);
    assert(nsealr::bip39_english_word_at(indexes[0]) == std::string("leader"));
    assert(nsealr::bip39_english_word_at(indexes[11]) == std::string("bean"));
    assert(nsealr::bip39_english_mnemonic_from_indexes(indexes) ==
           nsealr::test_vectors::kNip06Account0Mnemonic);
    assert(std::string(nsealr::test_vectors::kNip06Account0SecretKey).size() == 64U);
    assert(std::string(nsealr::test_vectors::kNip06Account0PublicKey).size() == 64U);

    const nsealr::Bip39WordIndexes normalized =
        nsealr::parse_bip39_english_mnemonic_indexes(
            "  Leader\nMONKEY  parrot ring guide accident before fence cannon height naive bean\t");
    assert(normalized == indexes);

    expect_throw("word count", [] {
        (void)nsealr::parse_bip39_english_mnemonic_indexes("abandon abandon abandon");
    });
    expect_throw("English wordlist", [] {
        (void)nsealr::parse_bip39_english_mnemonic_indexes(
            "notaword monkey parrot ring guide accident before fence cannon height naive bean");
    });
    expect_throw("ASCII English words", [] {
        (void)nsealr::parse_bip39_english_mnemonic_indexes(
            "leader monkey parrot ring guide accident before fence cannon height naive bean!");
    });
    expect_throw("checksum", [] {
        (void)nsealr::parse_bip39_english_mnemonic_indexes(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon");
    });
    expect_throw("outside the English wordlist", [] {
        (void)nsealr::bip39_english_word_at(2048U);
    });
}

void test_stateless_session_keyring_accepts_parsed_key_sources() {
    nsealr::StatelessSessionKeyring keyring;
    const nsealr::NsecSecretKey secret = nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1);
    const std::vector<std::uint16_t> seed_indexes = nsealr::test_vectors::seedqr_vector_1_word_indexes();

    assert(keyring.empty());
    keyring.add_nsec("nsec test vector", secret);
    keyring.add_bip39_seed("SeedQR vector 1", seed_indexes);

    assert(keyring.size() == 2U);
    assert(keyring.source_at(0).kind == nsealr::SessionKeySourceKind::NsecSecretKey);
    assert(keyring.source_at(0).label == "nsec test vector");
    assert(keyring.source_at(0).nsec_secret_key == secret);
    assert(keyring.source_at(0).bip39_word_indexes.count == 0U);
    assert(keyring.source_at(1).kind == nsealr::SessionKeySourceKind::Bip39WordIndexes);
    assert(keyring.source_at(1).label == "SeedQR vector 1");
    assert_session_seed_words_equal(keyring.source_at(1).bip39_word_indexes, seed_indexes);
    expect_throw("index is out of range", [&] {
        (void)keyring.source_at(2);
    });

    keyring.clear();
    assert(keyring.empty());
}

void test_stateless_session_keyring_clear_wipes_active_sources() {
    nsealr::StatelessSessionKeyring keyring;
    const nsealr::NsecSecretKey secret = nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1);
    const std::vector<std::uint16_t> seed_indexes = nsealr::test_vectors::seedqr_vector_1_word_indexes();

    keyring.add_nsec("nsec test vector", secret);
    keyring.add_bip39_seed("SeedQR vector 1", seed_indexes);
    const nsealr::SessionKeySource& nsec_source = keyring.source_at(0);
    const nsealr::SessionKeySource& seed_source = keyring.source_at(1);

    assert(!all_zero(nsec_source.nsec_secret_key));
    assert(seed_source.bip39_word_indexes.count == seed_indexes.size());
    assert(!all_zero(seed_source.bip39_word_indexes.values));

    keyring.clear();

    assert(keyring.empty());
    assert(nsec_source.label.empty());
    assert(all_zero(nsec_source.nsec_secret_key));
    assert(nsec_source.bip39_word_indexes.count == 0U);
    assert(all_zero(nsec_source.bip39_word_indexes.values));
    assert(seed_source.label.empty());
    assert(all_zero(seed_source.nsec_secret_key));
    assert(seed_source.bip39_word_indexes.count == 0U);
    assert(all_zero(seed_source.bip39_word_indexes.values));
    expect_throw("index is out of range", [&] {
        (void)keyring.source_at(0);
    });
}

void test_session_key_source_value_semantics_wipe_sensitive_material() {
    const nsealr::NsecSecretKey secret = nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1);
    nsealr::SessionKeySource original;
    original.kind = nsealr::SessionKeySourceKind::NsecSecretKey;
    original.label = "temporary nsec";
    original.nsec_secret_key = secret;

    nsealr::SessionKeySource moved(std::move(original));

    assert(moved.kind == nsealr::SessionKeySourceKind::NsecSecretKey);
    assert(moved.label == "temporary nsec");
    assert(moved.nsec_secret_key == secret);
    assert(original.label.empty());
    assert(all_zero(original.nsec_secret_key));
    assert(original.bip39_word_indexes.count == 0U);
    assert(all_zero(original.bip39_word_indexes.values));

    nsealr::SessionKeySource assigned;
    assigned = moved;
    assert(assigned.kind == nsealr::SessionKeySourceKind::NsecSecretKey);
    assert(assigned.nsec_secret_key == secret);

    nsealr::SessionKeySource seed = nsealr::parse_session_source_qr_text(
        "SeedQR vector 1",
        nsealr::test_vectors::kSeedQrVector1StandardDigits);
    assigned = seed;
    assert(assigned.kind == nsealr::SessionKeySourceKind::Bip39WordIndexes);
    assert(all_zero(assigned.nsec_secret_key));
    assert_session_seed_words_equal(
        assigned.bip39_word_indexes,
        nsealr::test_vectors::seedqr_vector_1_word_indexes());

    nsealr::SessionKeySource moved_seed;
    moved_seed = std::move(seed);
    assert(moved_seed.kind == nsealr::SessionKeySourceKind::Bip39WordIndexes);
    assert(moved_seed.label == "SeedQR vector 1");
    assert(seed.label.empty());
    assert(seed.bip39_word_indexes.count == 0U);
    assert(all_zero(seed.bip39_word_indexes.values));
}

void test_stateless_session_keyring_rejects_invalid_sources() {
    nsealr::StatelessSessionKeyring keyring;
    const nsealr::NsecSecretKey secret = nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1);

    expect_throw("label must not be empty", [&] {
        keyring.add_nsec("", secret);
    });
    expect_throw("label exceeds max length", [&] {
        keyring.add_nsec(std::string(nsealr::kMaxSessionKeySourceLabelLength + 1U, 'x'), secret);
    });
    expect_throw("valid secp256k1 scalar", [&] {
        keyring.add_nsec("zero nsec", nsealr::NsecSecretKey{});
    });
    expect_throw("12, 15, 18, 21, or 24 word indexes", [&] {
        keyring.add_bip39_seed("short seed", {0U, 1U, 2U});
    });
    expect_throw("outside the English wordlist", [&] {
        nsealr::SeedQrWordIndexes indexes(12U, 0U);
        indexes[11] = 2048U;
        keyring.add_bip39_seed("bad seed index", indexes);
    });

    for (std::size_t index = 0; index < nsealr::kMaxStatelessSessionKeySources; ++index) {
        keyring.add_nsec("nsec source " + std::to_string(index), secret);
    }
    expect_throw("keyring is full", [&] {
        keyring.add_nsec("overflow", secret);
    });
}

bool lines_contain_text(const std::vector<nsealr::TrustedReviewPage>& pages, const std::string& needle) {
    for (const nsealr::TrustedReviewPage& page : pages) {
        for (const std::string& line : page.lines) {
            if (line.find(needle) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

void test_session_source_generation_uses_ram_only_source_boundary() {
    const nsealr::SessionKeySource seed_source =
        nsealr::generate_bip39_session_source("Generated seed", std::vector<std::uint8_t>(16U, 0U));
    nsealr::NsecSecretKey generated_secret{};
    generated_secret.back() = 1U;
    const nsealr::SessionKeySource nsec_source =
        nsealr::generate_nsec_session_source("Generated nsec", generated_secret);

    assert(seed_source.kind == nsealr::SessionKeySourceKind::Bip39WordIndexes);
    assert(seed_source.label == "Generated seed");
    assert(seed_source.bip39_word_indexes.count == 12U);
    const nsealr::Bip39WordIndexes seed_indexes(
        seed_source.bip39_word_indexes.values.begin(),
        seed_source.bip39_word_indexes.values.begin() + seed_source.bip39_word_indexes.count);
    assert(nsealr::bip39_english_mnemonic_from_indexes(seed_indexes) ==
           "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    assert(all_zero(seed_source.nsec_secret_key));

    assert(nsec_source.kind == nsealr::SessionKeySourceKind::NsecSecretKey);
    assert(nsec_source.label == "Generated nsec");
    assert(nsec_source.nsec_secret_key == generated_secret);
    assert(nsec_source.bip39_word_indexes.count == 0U);

    const nsealr::SessionImportReview seed_review = nsealr::build_session_import_review(seed_source);
    const nsealr::SessionImportReview nsec_review = nsealr::build_session_import_review(nsec_source);
    assert(lines_contain_text(seed_review.pages, "Secret: hidden"));
    assert(lines_contain_text(nsec_review.pages, "Secret: hidden"));
    assert(!lines_contain_text(seed_review.pages, "abandon"));
    assert(!lines_contain_text(nsec_review.pages, "0000000000000000000000000000000000000000000000000000000000000001"));
}

void test_session_source_generation_rejects_invalid_entropy() {
    expect_throw("16 or 32 bytes", [] {
        (void)nsealr::generate_bip39_session_source("Generated seed", std::vector<std::uint8_t>{0x00U, 0x01U});
    });
    expect_throw("valid secp256k1 scalar", [] {
        (void)nsealr::generate_nsec_session_source("Generated nsec", nsealr::NsecSecretKey{});
    });
    expect_throw("label must not be empty", [] {
        nsealr::NsecSecretKey generated_secret{};
        generated_secret.back() = 1U;
        (void)nsealr::generate_nsec_session_source("", generated_secret);
    });
}

void test_session_source_backup_review_matches_shared_danger_zone_vectors() {
    nsealr::StatelessSessionKeyring keyring;
    keyring.add_bip39_seed("SeedQR vector 1", nsealr::test_vectors::seedqr_vector_1_word_indexes());
    keyring.add_nsec("nsec test vector", nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1));

    const nsealr::SessionSourceBackupReview seed_review =
        nsealr::build_session_source_backup_review(keyring.source_at(0));
    const nsealr::SessionSourceBackupReview nsec_review =
        nsealr::build_session_source_backup_review(keyring.source_at(1));
    const nsealr::test_vectors::SessionSourceBackupVector seed_vector =
        session_source_backup_vector_by_name("seedqr-vector-1-backup");
    const nsealr::test_vectors::SessionSourceBackupVector nsec_vector =
        session_source_backup_vector_by_name("nsec-test-key-1-backup");

    assert(seed_review.review_id == std::string(seed_vector.review_id));
    assert(seed_review.approval_digest == std::string(seed_vector.approval_digest));
    assert_detailed_trusted_review_pages(seed_review.pages, seed_vector.pages);
    assert(nsec_review.review_id == std::string(nsec_vector.review_id));
    assert(nsec_review.approval_digest == std::string(nsec_vector.approval_digest));
    assert_detailed_trusted_review_pages(nsec_review.pages, nsec_vector.pages);

    assert(lines_contain_text(seed_review.pages, "Danger: secret export"));
    assert(lines_contain_text(seed_review.pages, "Approve to reveal"));
    assert(!lines_contain_text(seed_review.pages, "attack"));
    assert(!lines_contain_text(seed_review.pages, "expire"));
    assert(!lines_contain_text(nsec_review.pages, nsealr::test_vectors::kNip19NsecTestKey1));
    assert(!lines_contain_text(nsec_review.pages, nsealr::test_vectors::kNip19NsecTestKey1SecretKey));
}

void test_session_source_backup_payload_matches_shared_secret_payloads() {
    nsealr::StatelessSessionKeyring keyring;
    keyring.add_bip39_seed("SeedQR vector 1", nsealr::test_vectors::seedqr_vector_1_word_indexes());
    keyring.add_nsec("nsec test vector", nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1));
    const nsealr::test_vectors::SessionSourceBackupVector seed_vector =
        session_source_backup_vector_by_name("seedqr-vector-1-backup");
    const nsealr::test_vectors::SessionSourceBackupVector nsec_vector =
        session_source_backup_vector_by_name("nsec-test-key-1-backup");

    const nsealr::SessionSourceBackupPayload seed_payload =
        nsealr::session_source_backup_payload(keyring.source_at(0));
    const nsealr::SessionSourceBackupPayload nsec_payload =
        nsealr::session_source_backup_payload(keyring.source_at(1));

    assert(seed_payload.backup_format == std::string(seed_vector.backup_format));
    assert(seed_payload.mnemonic == std::string(seed_vector.backup_mnemonic));
    assert(seed_payload.standard_seedqr_digits == std::string(seed_vector.backup_standard_seedqr_digits));
    assert(seed_payload.compact_seedqr_hex == std::string(seed_vector.backup_compact_seedqr_hex));
    assert(seed_payload.nsec.empty());
    assert(nsec_payload.backup_format == std::string(nsec_vector.backup_format));
    assert(nsec_payload.nsec == std::string(nsec_vector.backup_nsec));
    assert(nsec_payload.mnemonic.empty());
}

void test_session_source_backup_flow_reveals_only_after_local_approval() {
    nsealr::StatelessSessionKeyring keyring;
    keyring.add_nsec("nsec test vector", nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1));

    const nsealr::SessionSourceBackupFlowResult approved =
        nsealr::run_session_source_backup_flow(keyring.source_at(0), {nsealr::ReviewButton::Next, nsealr::ReviewButton::Approve});

    assert(approved.approved);
    assert(approved.revealed);
    assert(approved.backup_payload.has_value());
    assert(approved.backup_payload->nsec == std::string(nsealr::test_vectors::kNip19NsecTestKey1));
    assert(approved.transcript.size() == 2U);
    assert(approved.transcript[0].page_index == 0U);
    assert(approved.transcript[0].button == nsealr::ReviewButton::Next);
    assert(!approved.transcript[0].decision.has_value());
    assert(!approved.transcript[0].revealed);
    assert(approved.transcript[1].page_index == 1U);
    assert(approved.transcript[1].button == nsealr::ReviewButton::Approve);
    assert(approved.transcript[1].decision.has_value() && *approved.transcript[1].decision);
    assert(approved.transcript[1].revealed);

    const nsealr::SessionSourceBackupFlowResult rejected =
        nsealr::run_session_source_backup_flow(keyring.source_at(0), {nsealr::ReviewButton::Reject});
    assert(!rejected.approved);
    assert(!rejected.revealed);
    assert(!rejected.backup_payload.has_value());
    expect_throw("approval requires viewing every review page", [&] {
        (void)nsealr::run_session_source_backup_flow(keyring.source_at(0), {nsealr::ReviewButton::Approve});
    });
}

void test_policy_change_review_matches_shared_vector() {
    const nsealr::test_vectors::PolicyChangeReviewVector vector =
        policy_change_review_vector_by_name("esp32-usb-enable-kind-1-automation");

    const nsealr::PolicyChangeReview review = nsealr::build_policy_change_review(vector.proposal);
    assert(review.proposal_id == std::string(vector.review.proposal_id));
    assert(review.approval_digest == std::string(vector.review.approval_digest));
    assert_trusted_review_pages(review.pages, vector.review.pages);

    const nsealr::TrustedReviewRequest trusted_request =
        nsealr::build_policy_change_trusted_review_request(vector.proposal);
    assert(trusted_request.request_id == vector.proposal.proposal_id);
    assert(trusted_request.approval_digest == review.approval_digest);
    assert_trusted_review_pages(trusted_request.pages, vector.review.pages);

    assert(lines_contain_text(review.pages, "Review on device"));
    assert(lines_contain_text(review.pages, "Physical approval required"));
    assert(lines_contain_text(review.pages, "Companion cannot approve alone"));
}

void test_policy_change_review_flow_requires_device_approval() {
    const nsealr::test_vectors::PolicyChangeReviewVector vector =
        policy_change_review_vector_by_name("esp32-usb-enable-kind-1-automation");

    const nsealr::PolicyChangeReviewFlowResult approved =
        nsealr::run_policy_change_review_flow(vector.proposal,
                                              {
                                                  nsealr::ReviewButton::Next,
                                                  nsealr::ReviewButton::Next,
                                                  nsealr::ReviewButton::Next,
                                                  nsealr::ReviewButton::Approve,
                                              });
    assert(approved.approved);
    assert(approved.review.approval_digest == std::string(vector.review.approval_digest));
    assert(approved.transcript.size() == 4U);
    assert(approved.transcript.front().page_index == 0U);
    assert(!approved.transcript.front().decision.has_value());
    assert(!approved.transcript.front().approved_for_policy_change);
    assert(approved.transcript.back().page_index == 3U);
    assert(approved.transcript.back().decision.has_value() && *approved.transcript.back().decision);
    assert(approved.transcript.back().approved_for_policy_change);

    const nsealr::PolicyChangeReviewFlowResult rejected =
        nsealr::run_policy_change_review_flow(vector.proposal, {nsealr::ReviewButton::Reject});
    assert(!rejected.approved);
    assert(rejected.transcript.size() == 1U);
    assert(rejected.transcript.front().decision.has_value() && !*rejected.transcript.front().decision);
    assert(!rejected.transcript.front().approved_for_policy_change);

    expect_throw("approval requires viewing every review page", [&] {
        (void)nsealr::run_policy_change_review_flow(vector.proposal, {nsealr::ReviewButton::Approve});
    });
    expect_throw("did not reach approval or rejection", [&] {
        (void)nsealr::run_policy_change_review_flow(vector.proposal, {nsealr::ReviewButton::Next});
    });
}

void test_policy_change_review_rejects_companion_authority_or_secret_material() {
    nsealr::PolicyChangeProposal unsafe = policy_change_review_vector_by_name(
        "esp32-usb-enable-kind-1-automation").proposal;

    unsafe.companion_authoritative = true;
    expect_throw("companion_authoritative must be false", [&] {
        (void)nsealr::build_policy_change_review(unsafe);
    });

    unsafe = policy_change_review_vector_by_name("esp32-usb-enable-kind-1-automation").proposal;
    unsafe.contains_secret_material = true;
    expect_throw("contains_secret_material must be false", [&] {
        (void)nsealr::build_policy_change_review(unsafe);
    });

    unsafe = policy_change_review_vector_by_name("esp32-usb-enable-kind-1-automation").proposal;
    unsafe.physical_approval_required = false;
    expect_throw("physical_approval_required must be true", [&] {
        (void)nsealr::build_policy_change_review(unsafe);
    });
}

void test_session_source_qr_parses_ram_only_sources() {
    const nsealr::SessionKeySource nsec_source = nsealr::parse_session_source_qr_text(
        "nsec QR",
        std::string("\n") + nsealr::test_vectors::kNip19NsecTestKey1 + "\t");
    const nsealr::SessionKeySource mnemonic_source = nsealr::parse_session_source_qr_text(
        "plain mnemonic QR",
        nsealr::test_vectors::kNip06Account0Mnemonic);
    const nsealr::SessionKeySource standard_seedqr_source = nsealr::parse_session_source_qr_text(
        "Standard SeedQR",
        nsealr::test_vectors::kSeedQrVector1StandardDigits);
    const nsealr::SessionKeySource compact_seedqr_source = nsealr::parse_compact_seedqr_session_source(
        "CompactSeedQR",
        bytes_from_hex_for_test(nsealr::test_vectors::kSeedQrVector1CompactHex));

    assert(nsec_source.kind == nsealr::SessionKeySourceKind::NsecSecretKey);
    assert(nsec_source.label == "nsec QR");
    assert(nsec_source.nsec_secret_key == nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1));
    assert(nsec_source.bip39_word_indexes.count == 0U);

    assert(mnemonic_source.kind == nsealr::SessionKeySourceKind::Bip39WordIndexes);
    assert(mnemonic_source.label == "plain mnemonic QR");
    assert_session_seed_words_equal(
        mnemonic_source.bip39_word_indexes,
        nsealr::parse_bip39_english_mnemonic_indexes(nsealr::test_vectors::kNip06Account0Mnemonic));

    const std::vector<std::uint16_t> seedqr_indexes = nsealr::test_vectors::seedqr_vector_1_word_indexes();
    assert(standard_seedqr_source.kind == nsealr::SessionKeySourceKind::Bip39WordIndexes);
    assert(standard_seedqr_source.label == "Standard SeedQR");
    assert_session_seed_words_equal(standard_seedqr_source.bip39_word_indexes, seedqr_indexes);
    assert(compact_seedqr_source.kind == nsealr::SessionKeySourceKind::Bip39WordIndexes);
    assert(compact_seedqr_source.label == "CompactSeedQR");
    assert_session_seed_words_equal(compact_seedqr_source.bip39_word_indexes, seedqr_indexes);

    const nsealr::SessionImportReview nsec_review = nsealr::build_session_import_review(nsec_source);
    const nsealr::SessionImportReview mnemonic_review = nsealr::build_session_import_review(mnemonic_source);
    assert(lines_contain_text(nsec_review.pages, "Secret: hidden"));
    assert(lines_contain_text(mnemonic_review.pages, "Secret: hidden"));
    assert(!lines_contain_text(nsec_review.pages, nsealr::test_vectors::kNip19NsecTestKey1SecretKey));
    assert(!lines_contain_text(mnemonic_review.pages, "leader"));
}

void test_session_source_qr_rejects_invalid_inputs() {
    expect_throw("must not be empty", [] {
        (void)nsealr::parse_session_source_qr_text("empty QR", " \n\t");
    });
    expect_throw("label must not be empty", [] {
        (void)nsealr::parse_session_source_qr_text("", nsealr::test_vectors::kNip19NsecTestKey1);
    });
    expect_throw("malformed", [] {
        (void)nsealr::parse_session_source_qr_text("bad nsec QR", "nsec1short");
    });
    expect_throw("four digits per word", [] {
        (void)nsealr::parse_session_source_qr_text("bad Standard SeedQR", "000");
    });
    expect_throw("ASCII English words", [] {
        (void)nsealr::parse_session_source_qr_text("bad mnemonic QR", "not a valid session source!");
    });
    expect_throw("16 or 32", [] {
        (void)nsealr::parse_compact_seedqr_session_source("bad CompactSeedQR", {0x00U, 0x01U});
    });
}

void test_session_source_qr_import_flow_loads_only_after_review_approval() {
    nsealr::StatelessSessionKeyring keyring;
    const nsealr::SessionImportFlowResult result = nsealr::run_session_source_qr_text_import_flow(
        keyring,
        "nsec QR",
        nsealr::test_vectors::kNip19NsecTestKey1,
        {nsealr::ReviewButton::Next, nsealr::ReviewButton::Approve});

    assert(result.approved);
    assert(result.loaded);
    assert(result.review.review_id ==
           std::string(session_import_review_vector_by_name("nsec-test-key-1").review_id));
    assert(result.transcript.size() == 2U);
    assert(!result.transcript[0].loaded);
    assert(result.transcript[1].loaded);
    assert(keyring.size() == 1U);
    assert(keyring.source_at(0).kind == nsealr::SessionKeySourceKind::NsecSecretKey);
    assert(keyring.source_at(0).nsec_secret_key ==
           nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1));
}

void test_session_source_qr_import_flow_rejects_without_keyring_load() {
    nsealr::StatelessSessionKeyring keyring;
    const nsealr::SessionImportFlowResult rejected = nsealr::run_session_source_qr_text_import_flow(
        keyring,
        "SeedQR vector 1",
        nsealr::test_vectors::kSeedQrVector1StandardDigits,
        {nsealr::ReviewButton::Reject});

    assert(!rejected.approved);
    assert(!rejected.loaded);
    assert(keyring.empty());

    expect_throw("four digits per word", [&] {
        (void)nsealr::run_session_source_qr_text_import_flow(
            keyring,
            "bad Standard SeedQR",
            "000",
            {nsealr::ReviewButton::Next, nsealr::ReviewButton::Approve});
    });
    assert(keyring.empty());
}

void test_compact_seedqr_import_flow_loads_after_review_approval() {
    nsealr::StatelessSessionKeyring keyring;
    const nsealr::SessionImportFlowResult result = nsealr::run_compact_seedqr_session_import_flow(
        keyring,
        "CompactSeedQR",
        bytes_from_hex_for_test(nsealr::test_vectors::kSeedQrVector1CompactHex),
        {nsealr::ReviewButton::Next, nsealr::ReviewButton::Approve});

    assert(result.approved);
    assert(result.loaded);
    assert(keyring.size() == 1U);
    assert(keyring.source_at(0).kind == nsealr::SessionKeySourceKind::Bip39WordIndexes);
    assert_session_seed_words_equal(
        keyring.source_at(0).bip39_word_indexes,
        nsealr::test_vectors::seedqr_vector_1_word_indexes());
}

void test_session_import_review_hides_secret_material() {
    nsealr::StatelessSessionKeyring keyring;
    const nsealr::NsecSecretKey secret = nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1);
    const std::vector<std::uint16_t> seed_indexes = nsealr::test_vectors::seedqr_vector_1_word_indexes();
    keyring.add_nsec("nsec test vector", secret);
    keyring.add_bip39_seed("SeedQR vector 1", seed_indexes);

    const nsealr::SessionImportReview nsec_review =
        nsealr::build_session_import_review(keyring.source_at(0));
    const nsealr::SessionImportReview seed_review =
        nsealr::build_session_import_review(keyring.source_at(1));
    const nsealr::test_vectors::SessionImportReviewVector nsec_vector =
        session_import_review_vector_by_name("nsec-test-key-1");
    const nsealr::test_vectors::SessionImportReviewVector seed_vector =
        session_import_review_vector_by_name("seedqr-vector-1");

    assert(nsec_review.review_id == std::string(nsec_vector.review_id));
    assert(nsec_review.approval_digest == std::string(nsec_vector.approval_digest));
    assert(nsealr::session_key_source_fingerprint(keyring.source_at(0)) == std::string(nsec_vector.fingerprint));
    assert_detailed_trusted_review_pages(nsec_review.pages, nsec_vector.pages);
    assert(lines_contain_text(nsec_review.pages, "Type: NIP-19 nsec"));
    assert(lines_contain_text(nsec_review.pages, "Secret: hidden"));
    assert(!lines_contain_text(nsec_review.pages, nsealr::test_vectors::kNip19NsecTestKey1SecretKey));

    assert(seed_review.review_id != nsec_review.review_id);
    assert(seed_review.approval_digest != nsec_review.approval_digest);
    assert(seed_review.review_id == std::string(seed_vector.review_id));
    assert(seed_review.approval_digest == std::string(seed_vector.approval_digest));
    assert(nsealr::session_key_source_fingerprint(keyring.source_at(1)) == std::string(seed_vector.fingerprint));
    assert_detailed_trusted_review_pages(seed_review.pages, seed_vector.pages);
    assert(lines_contain_text(seed_review.pages, "Type: BIP-39 seed"));
    assert(lines_contain_text(seed_review.pages, "Words: 24"));
    assert(lines_contain_text(seed_review.pages, "Secret: hidden"));
    assert(!lines_contain_text(seed_review.pages, "attack"));
    assert(!lines_contain_text(seed_review.pages, "expire"));

    assert(seed_review.pages.front().title == "Import source");
    assert(seed_review.pages.front().action == nsealr::ReviewPageAction::Next);
    assert(seed_review.pages.back().title == "Import?");
    assert(seed_review.pages.back().action == nsealr::ReviewPageAction::ApproveOrReject);
}

void test_session_import_flow_requires_local_approval_before_loading_keyring() {
    nsealr::StatelessSessionKeyring pending_sources;
    nsealr::StatelessSessionKeyring session_keyring;
    const nsealr::NsecSecretKey secret = nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1);
    pending_sources.add_nsec("nsec test vector", secret);

    const nsealr::SessionImportFlowResult result = nsealr::run_session_import_flow(
        session_keyring,
        pending_sources.source_at(0),
        {nsealr::ReviewButton::Next, nsealr::ReviewButton::Approve});

    assert(result.approved);
    assert(result.loaded);
    assert(result.review.review_id == std::string(session_import_review_vector_by_name("nsec-test-key-1").review_id));
    assert(result.transcript.size() == 2U);
    assert(result.transcript[0].page_index == 0U);
    assert(result.transcript[0].button == nsealr::ReviewButton::Next);
    assert(!result.transcript[0].decision.has_value());
    assert(!result.transcript[0].loaded);
    assert(result.transcript[1].page_index == 1U);
    assert(result.transcript[1].button == nsealr::ReviewButton::Approve);
    assert(result.transcript[1].decision.has_value() && *result.transcript[1].decision);
    assert(result.transcript[1].loaded);
    assert(session_keyring.size() == 1U);
    assert(session_keyring.source_at(0).label == "nsec test vector");
    assert(session_keyring.source_at(0).nsec_secret_key == secret);
}

void test_session_import_flow_rejection_does_not_load_keyring() {
    nsealr::StatelessSessionKeyring pending_sources;
    nsealr::StatelessSessionKeyring session_keyring;
    pending_sources.add_bip39_seed("SeedQR vector 1", nsealr::test_vectors::seedqr_vector_1_word_indexes());

    const nsealr::SessionImportFlowResult result = nsealr::run_session_import_flow(
        session_keyring,
        pending_sources.source_at(0),
        {nsealr::ReviewButton::Reject});

    assert(!result.approved);
    assert(!result.loaded);
    assert(result.transcript.size() == 1U);
    assert(result.transcript[0].decision.has_value() && !*result.transcript[0].decision);
    assert(!result.transcript[0].loaded);
    assert(session_keyring.empty());
}

void test_session_import_flow_blocks_early_or_nonterminal_approval() {
    nsealr::StatelessSessionKeyring pending_sources;
    nsealr::StatelessSessionKeyring session_keyring;
    pending_sources.add_nsec(
        "nsec test vector",
        nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1));

    expect_throw("approval requires viewing every review page", [&] {
        (void)nsealr::run_session_import_flow(
            session_keyring,
            pending_sources.source_at(0),
            {nsealr::ReviewButton::Approve});
    });
    assert(session_keyring.empty());

    expect_throw("did not reach approval or rejection", [&] {
        (void)nsealr::run_session_import_flow(
            session_keyring,
            pending_sources.source_at(0),
            {nsealr::ReviewButton::Next});
    });
    assert(session_keyring.empty());

    expect_throw("max button steps", [&] {
        (void)nsealr::run_session_import_flow(
            session_keyring,
            pending_sources.source_at(0),
            {nsealr::ReviewButton::Next, nsealr::ReviewButton::Back},
            1U);
    });
    assert(session_keyring.empty());
}

void test_session_account_selection_binds_qr_review_identity_without_derivation() {
    nsealr::StatelessSessionKeyring keyring;
    keyring.add_bip39_seed(
        "NIP-06 account 0",
        nsealr::parse_bip39_english_mnemonic_indexes(nsealr::test_vectors::kNip06Account0Mnemonic));

    const nsealr::SessionAccountDescriptor descriptor =
        nsealr::test_vectors::esp32_qr_nip06_account_0_descriptor();
    const nsealr::SelectedSessionAccount selected =
        nsealr::select_session_account(keyring, descriptor);

    assert(selected.account_id == descriptor.account_id);
    assert(selected.route_type == descriptor.route_type);
    assert(selected.public_key == nsealr::test_vectors::kNip06Account0PublicKey);
    assert(selected.source_index == 0U);
    assert(selected.source_fingerprint == descriptor.source_fingerprint);
    assert(selected.source_kind == nsealr::SessionKeySourceKind::Bip39WordIndexes);
    assert(selected.source_label == "NIP-06 account 0");
    assert(!selected.source_public_key_proof_verified);
    assert(selected.signer_identity.public_key == nsealr::test_vectors::kNip06Account0PublicKey);

    const nsealr::DeviceProtocolContext context =
        nsealr::device_protocol_context_for_session_account(selected);
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(
        nsealr::decode_qr_envelope(nsealr::test_vectors::kQrEnvelopeKind1Basic));
    const nsealr::TrustedReviewRequest review =
        nsealr::build_qr_trusted_review_request(request, context.signer_identity);

    assert(lines_contain_text(review.pages, nsealr::test_vectors::kNip06Account0PublicKey));
    assert(!lines_contain_text(review.pages, std::string(nsealr::kDevelopmentFixturePublicKey)));
}

void test_session_account_selection_validates_source_route_and_recovery_shape() {
    nsealr::StatelessSessionKeyring keyring;
    keyring.add_nsec("standalone nsec", nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1));

    const nsealr::SessionAccountDescriptor standalone{
        "acct-esp32-qr-nsec-0",
        "esp32_qr_vault",
        nsealr::test_vectors::kNip19NsecTestKey1PublicKey,
        0U,
        session_import_review_vector_by_name("nsec-test-key-1").fingerprint,
        nsealr::SessionAccountRecoveryKind::StandaloneNsec,
        "",
        0U,
    };
    const nsealr::SelectedSessionAccount selected = nsealr::select_session_account(keyring, standalone);
    assert(selected.source_kind == nsealr::SessionKeySourceKind::NsecSecretKey);
    assert(!selected.source_public_key_proof_verified);
    assert(selected.signer_identity.public_key == nsealr::test_vectors::kNip19NsecTestKey1PublicKey);

    expect_throw("requires a BIP-39 source", [&] {
        (void)nsealr::select_session_account(
            keyring,
            nsealr::test_vectors::esp32_qr_nip06_account_0_descriptor());
    });
    expect_throw("source index is out of range", [&] {
        nsealr::SessionAccountDescriptor invalid = standalone;
        invalid.source_index = 1U;
        (void)nsealr::select_session_account(keyring, invalid);
    });
    expect_throw("route_type must be esp32_qr_vault", [&] {
        nsealr::SessionAccountDescriptor invalid = standalone;
        invalid.route_type = "esp32_usb_nip46";
        (void)nsealr::select_session_account(keyring, invalid);
    });
    expect_throw("account_id must be a stable string id", [&] {
        nsealr::SessionAccountDescriptor invalid = standalone;
        invalid.account_id = "not stable";
        (void)nsealr::select_session_account(keyring, invalid);
    });
    expect_throw("public_key must be 32-byte lowercase hex", [&] {
        nsealr::SessionAccountDescriptor invalid = standalone;
        invalid.public_key = "not-a-public-key";
        (void)nsealr::select_session_account(keyring, invalid);
    });
    expect_throw("source_fingerprint must be 8-byte lowercase hex", [&] {
        nsealr::SessionAccountDescriptor invalid = standalone;
        invalid.source_fingerprint = "not-a-fingerprint";
        (void)nsealr::select_session_account(keyring, invalid);
    });
    expect_throw("source_fingerprint does not match selected source", [&] {
        nsealr::SessionAccountDescriptor invalid = standalone;
        invalid.source_fingerprint = "0000000000000000";
        (void)nsealr::select_session_account(keyring, invalid);
    });
    expect_throw("must not carry a derivation path", [&] {
        nsealr::SessionAccountDescriptor invalid = standalone;
        invalid.derivation_path = "m/44'/1237'/0'/0/0";
        (void)nsealr::select_session_account(keyring, invalid);
    });

    nsealr::StatelessSessionKeyring mnemonic_keyring;
    mnemonic_keyring.add_bip39_seed(
        "NIP-06 account 0",
        nsealr::parse_bip39_english_mnemonic_indexes(nsealr::test_vectors::kNip06Account0Mnemonic));
    expect_throw("path does not match account index", [&] {
        nsealr::SessionAccountDescriptor invalid =
            nsealr::test_vectors::esp32_qr_nip06_account_0_descriptor();
        invalid.derivation_path = "m/44'/1237'/1'/0/0";
        (void)nsealr::select_session_account(mnemonic_keyring, invalid);
    });
}

void test_session_account_selection_does_not_satisfy_public_key_proof_gate() {
    nsealr::StatelessSessionKeyring keyring;
    keyring.add_bip39_seed(
        "NIP-06 account 0",
        nsealr::parse_bip39_english_mnemonic_indexes(nsealr::test_vectors::kNip06Account0Mnemonic));

    const nsealr::SelectedSessionAccount selected = nsealr::select_session_account(
        keyring,
        nsealr::test_vectors::esp32_qr_nip06_account_0_descriptor());

    nsealr::SigningReadiness readiness{
        .runtime_signing_feature_enabled = true,
        .parser_limits_enforced = true,
        .trusted_review_display_accepted = true,
        .physical_approval_controls_accepted = true,
        .approval_digest_binding_verified = true,
        .unicode_review_rendering_accepted = true,
        .key_provisioning_ready = true,
        .source_public_key_proof_ready = selected.source_public_key_proof_verified,
        .secure_boot_enabled = true,
        .flash_encryption_enabled = true,
        .debug_locked = true,
        .companion_signed_output_verification_ready = true,
        .development_accepted_gates = {},
    };

    const nsealr::SigningReadinessStatus status =
        nsealr::evaluate_signing_readiness(readiness);

    assert(!status.signing_enabled);
    assert((status.missing_gates == std::vector<std::string>{"source_public_key_proof"}));
}

void test_session_account_selection_consumes_shared_source_public_key_proof_metadata_without_derivation() {
    const nsealr::test_vectors::SourcePublicKeyProofVector nip06_proof =
        source_public_key_proof_vector_by_name("nip06-account-0-leader");
    const nsealr::test_vectors::SourcePublicKeyProofVector nsec_proof =
        source_public_key_proof_vector_by_name("nsec-test-key-1");

    assert(std::string(nip06_proof.proof_type) == "nip06");
    assert(std::string(nip06_proof.source_type) == "bip39_seed");
    assert(nip06_proof.account.has_value());
    assert(nip06_proof.account.value() == 0U);
    assert(std::string(nip06_proof.path) == "m/44'/1237'/0'/0/0");
    assert(std::string(nip06_proof.passphrase).empty());
    assert(std::string(nip06_proof.security_scope).find("before signing") != std::string::npos);

    nsealr::StatelessSessionKeyring nip06_keyring;
    nip06_keyring.add_bip39_seed(
        "NIP-06 account 0",
        nsealr::parse_bip39_english_mnemonic_indexes(nsealr::test_vectors::kNip06Account0Mnemonic));
    const nsealr::SessionAccountDescriptor nip06_descriptor =
        nsealr::test_vectors::esp32_qr_nip06_account_0_descriptor();

    assert(nip06_descriptor.public_key == std::string(nip06_proof.expected_public_key));
    assert(nip06_descriptor.source_fingerprint == std::string(nip06_proof.source_fingerprint));
    assert(nip06_descriptor.derivation_path == std::string(nip06_proof.path));
    assert(nip06_descriptor.account_index == nip06_proof.account.value());

    const nsealr::SelectedSessionAccount nip06_selected =
        nsealr::select_session_account(nip06_keyring, nip06_descriptor);
    assert(nip06_selected.public_key == std::string(nip06_proof.expected_public_key));
    assert(nip06_selected.source_fingerprint == std::string(nip06_proof.source_fingerprint));
    assert(!nip06_selected.source_public_key_proof_verified);

    assert(std::string(nsec_proof.proof_type) == "nip19_nsec");
    assert(std::string(nsec_proof.source_type) == "nsec");
    assert(!nsec_proof.account.has_value());
    assert(std::string(nsec_proof.path).empty());
    assert(std::string(nsec_proof.passphrase).empty());

    nsealr::StatelessSessionKeyring nsec_keyring;
    nsec_keyring.add_nsec(
        "nsec test vector",
        nsealr::decode_nsec_secret_key(nsealr::test_vectors::kNip19NsecTestKey1));
    const nsealr::SessionAccountDescriptor nsec_descriptor{
        "acct-esp32-qr-nsec-0",
        "esp32_qr_vault",
        nsec_proof.expected_public_key,
        0U,
        nsec_proof.source_fingerprint,
        nsealr::SessionAccountRecoveryKind::StandaloneNsec,
        "",
        0U,
    };
    const nsealr::SelectedSessionAccount nsec_selected =
        nsealr::select_session_account(nsec_keyring, nsec_descriptor);
    assert(nsec_selected.public_key == std::string(nsec_proof.expected_public_key));
    assert(nsec_selected.source_fingerprint == std::string(nsec_proof.source_fingerprint));
    assert(!nsec_selected.source_public_key_proof_verified);
}

void test_qr_signing_request_rejections() {
    expect_throw("QR signing request version must be 1", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{"ignored", R"({"version":2,"request_id":"req-kind-1-basic","method":"sign_event","params":{}})"});
    });
    expect_throw("QR signing request request_id is invalid", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{"ignored", R"({"version":1,"request_id":"bad id","method":"sign_event","params":{}})"});
    });
    expect_throw("QR signing request method must be sign_event", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{"ignored", R"({"version":1,"request_id":"req-kind-1-basic","method":"get_public_key"})"});
    });
    expect_throw("QR signing request params object is required", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{"ignored", R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event"})"});
    });
    expect_throw("QR signing request event_template object is required", [] {
        (void)nsealr::parse_qr_signing_request(
            nsealr::QrEnvelope{"ignored", R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{}})"});
    });
    expect_throw("QR signing request event_template object is required", [] {
        (void)nsealr::parse_qr_signing_request(
            nsealr::QrEnvelope{"ignored", R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":[]}})"});
    });
    expect_throw("QR signing request event_template must not include id", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"","id":"00"}}})"});
    });
    expect_throw("QR signing request event_template must not include pubkey", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"","pubkey":"00"}}})"});
    });
    expect_throw("QR signing request event_template must not include sig", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"","sig":"00"}}})"});
    });
    expect_throw("QR signing request event_template created_at is required", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"kind":1,"tags":[],"content":""}}})"});
    });
    expect_throw("QR signing request event_template kind is required", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":"1","tags":[],"content":""}}})"});
    });
    expect_throw("QR signing request event_template tags array is required", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":{},"content":""}}})"});
    });
    expect_throw("QR signing request event_template content is required", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[]}}})"});
    });
    expect_throw("QR signing request JSON unicode escape is invalid", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-invalid-unicode","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"\uD83D"}}})"});
    });
    expect_throw("QR signing request JSON unicode escape is invalid", [] {
        (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
            "ignored",
            R"({"version":1,"request_id":"req-invalid-unicode","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"\uDE00"}}})"});
    });
}

void test_qr_signing_request_rejects_shared_invalid_request_vectors() {
    for (const auto& vector : nsealr::test_vectors::invalid_signing_request_vectors()) {
        bool rejected = false;
        try {
            (void)nsealr::parse_qr_signing_request(nsealr::QrEnvelope{"ignored", vector.request_json});
        } catch (const nsealr::QrEnvelopeError&) {
            rejected = true;
        }
        if (!rejected) {
            std::cerr << "unexpectedly accepted invalid request vector: " << vector.name << "\n";
        }
        assert(rejected);
    }
}

void test_qr_review_pages_match_shared_basic_vector() {
    const nsealr::QrEnvelope envelope =
        nsealr::decode_qr_envelope(nsealr::test_vectors::kQrEnvelopeKind1Basic);
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(envelope);

    assert_trusted_review_pages(
        nsealr::build_qr_review_pages(request),
        nsealr::test_vectors::basic_trusted_review_request().pages);
}

void test_qr_trusted_review_request_matches_shared_basic_vector() {
    const nsealr::QrEnvelope envelope =
        nsealr::decode_qr_envelope(nsealr::test_vectors::kQrEnvelopeKind1Basic);
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(envelope);
    const nsealr::TrustedReviewRequest review_request = nsealr::build_qr_trusted_review_request(request);
    const nsealr::TrustedReviewRequest expected = nsealr::test_vectors::basic_trusted_review_request();

    assert(review_request.request_id == expected.request_id);
    assert(review_request.approval_digest == expected.approval_digest);
    assert_trusted_review_pages(review_request.pages, expected.pages);
}

void test_qr_review_pages_match_shared_tagged_vector() {
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
        "ignored",
        R"({"version":1,"request_id":"req-kind-1-tags","method":"sign_event","params":{"event_template":{"created_at":1710000060,"kind":1,"tags":[["p","4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","","mention"],["t","nsealr"]],"content":"nSealr fixture: tagged kind 1 event."}}})"});

    assert_trusted_review_pages(
        nsealr::build_qr_review_pages(request),
        nsealr::test_vectors::tagged_trusted_review_request().pages);
}

void test_qr_trusted_review_request_matches_shared_tagged_vector() {
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
        "ignored",
        R"({"version":1,"request_id":"req-kind-1-tags","method":"sign_event","params":{"event_template":{"created_at":1710000060,"kind":1,"tags":[["p","4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","","mention"],["t","nsealr"]],"content":"nSealr fixture: tagged kind 1 event."}}})"});
    const nsealr::TrustedReviewRequest review_request = nsealr::build_qr_trusted_review_request(request);
    const nsealr::TrustedReviewRequest expected = nsealr::test_vectors::tagged_trusted_review_request();

    assert(review_request.request_id == expected.request_id);
    assert(review_request.approval_digest == expected.approval_digest);
    assert_trusted_review_pages(review_request.pages, expected.pages);
}

void test_qr_review_binds_configured_signer_identity() {
    const std::string alternate_pubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const nsealr::SignerIdentity alternate_identity{alternate_pubkey};
    const nsealr::QrEnvelope envelope =
        nsealr::decode_qr_envelope(nsealr::test_vectors::kQrEnvelopeKind1Basic);
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(envelope);

    const nsealr::TrustedReviewRequest default_review =
        nsealr::build_qr_trusted_review_request(request);
    const nsealr::TrustedReviewRequest alternate_review =
        nsealr::build_qr_trusted_review_request(request, alternate_identity);

    assert(alternate_review.request_id == default_review.request_id);
    assert(alternate_review.approval_digest != default_review.approval_digest);
    assert(lines_contain(alternate_review.pages.front().lines, alternate_pubkey));
    assert(!lines_contain(alternate_review.pages.front().lines, std::string{nsealr::kDevelopmentFixturePublicKey}));

    const std::vector<nsealr::TrustedReviewPage> display_pages =
        nsealr::build_qr_display_review_pages(
            request,
            alternate_identity,
            nsealr_esp32::t_display_s3_review_limits());
    const std::string event_text = joined_lines_for_title(display_pages, "Event");

    assert(event_text.find(alternate_pubkey.substr(0, 48)) != std::string::npos);
    assert(event_text.find(alternate_pubkey.substr(48)) != std::string::npos);
    assert(event_text.find(std::string{nsealr::kDevelopmentFixturePublicKey}.substr(0, 48)) == std::string::npos);

    expect_throw("signer public key", [&] {
        (void)nsealr::build_qr_trusted_review_request(request, nsealr::SignerIdentity{"not-a-pubkey"});
    });
}

void test_qr_display_review_pages_show_full_tag_values_without_ellipsis() {
    const std::string pubkey = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
        "ignored",
        R"({"version":1,"request_id":"req-kind-1-tags","method":"sign_event","params":{"event_template":{"created_at":1710000060,"kind":1,"tags":[["p","4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","","mention"],["t","nsealr"]],"content":"nSealr fixture: tagged kind 1 event."}}})"});

    const std::vector<nsealr::TrustedReviewPage> pages =
        nsealr::build_qr_display_review_pages(request, nsealr_esp32::t_display_s3_review_limits());
    const std::string tag_text = joined_lines_for_title(pages, "Tags");

    assert(page_count_with_title(pages, "Tags") == 1);
    assert(tag_text.find("...") == std::string::npos);
    assert(tag_text.find(pubkey.substr(0, 48)) != std::string::npos);
    assert(tag_text.find(pubkey.substr(48)) != std::string::npos);
    assert(tag_text.find("nsealr") != std::string::npos);
    assert(pages.back().title == "Decision");
    assert(!lines_contain(pages.back().lines, "warning"));
    assert(!lines_contain(pages.back().lines, "Warning"));
}

void test_qr_display_review_pages_group_logical_sections_with_compact_styles() {
    const std::string pubkey = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(nsealr::QrEnvelope{
        "ignored",
        R"({"version":1,"request_id":"req-kind-1-tags","method":"sign_event","params":{"event_template":{"created_at":1710000060,"kind":1,"tags":[["p","4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","","mention"],["t","nsealr"]],"content":"nSealr fixture: tagged kind 1 event."}}})"});

    const std::vector<nsealr::TrustedReviewPage> pages =
        nsealr::build_qr_display_review_pages(request, nsealr_esp32::t_display_s3_review_limits());

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
    assert(pages[0].body_line_styles[2] == nsealr::ReviewBodyLineStyle::Meta);
    assert(pages[0].body_line_styles[3] == nsealr::ReviewBodyLineStyle::Value);
    assert(!lines_contain(pages[0].lines, "Short Text Note"));
    assert(pages[1].title == "Content");
    assert(pages[1].page_indicator == "Page 2/4");
    assert(pages[2].title == "Tags");
    assert(pages[2].page_indicator == "Page 3/4");
    assert(pages[3].title == "Decision");
    assert(pages[3].page_indicator == "Page 4/4");
    assert(pages[2].body_line_styles.size() == pages[2].lines.size());
    assert(pages[2].body_line_styles.front() == nsealr::ReviewBodyLineStyle::Meta);
    const std::string tag_text = joined_lines_for_title(pages, "Tags");
    assert((pages[2].lines == std::vector<std::string>{
                                "Tag 1/2",
                                "p",
                                "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a",
                                "  b0f0b704075871aa",
                                "mention",
                                "Tag 2/2",
                                "t",
                                "nsealr",
                            }));
    assert(pages[2].body_line_styles[2] == nsealr::ReviewBodyLineStyle::Value);
    assert(pages[2].body_line_styles[3] == nsealr::ReviewBodyLineStyle::Value);
    assert(pages[2].lines[3].rfind("  ", 0) == 0);
    assert(!lines_contain(pages[2].lines, "[0]"));
    assert(!lines_contain(pages[2].lines, "\""));
    assert(!lines_contain(pages[2].lines, "raw tags JSON"));
    assert(tag_text.find(pubkey.substr(0, 48)) != std::string::npos);
    assert(tag_text.find(pubkey.substr(48)) != std::string::npos);
}

void test_qr_display_review_pages_match_shared_detail_page_vectors() {
    for (const nsealr::test_vectors::ReviewDetailPageVector& vector :
         nsealr::test_vectors::review_detail_page_vectors()) {
        const nsealr::QrSigningRequest request =
            nsealr::parse_qr_signing_request(nsealr::QrEnvelope{"ignored", vector.request_json});

        const std::vector<nsealr::TrustedReviewPage> pages =
            nsealr::build_qr_display_review_pages(request, vector.limits);
        const nsealr::TrustedReviewRequest review_request =
            nsealr::build_qr_display_review_request(request, vector.limits);

        assert(review_request.approval_digest == vector.approval_digest);
        assert_detailed_trusted_review_pages(pages, vector.pages);
    }
}

void test_qr_display_review_pages_escape_non_ascii_for_display_safety() {
    const std::string content = std::string("cafe ") + "\xC3\xA8" + " " + "\xF0\x9F\x98\x80";
    const std::string tag_value = std::string("topic-") + "\xC3\xA8";
    const nsealr::QrSigningRequest request{
        .version = 1,
        .request_id = "req-unicode-display",
        .method = "sign_event",
        .has_params = true,
        .has_event_template = true,
        .event_template_json = "",
        .event_template = nsealr::QrEventTemplate{
            .created_at = 1710000300,
            .kind = 1,
            .tags_json = "",
            .tags = {{"t", tag_value}, {"emoji", std::string("\xF0\x9F\x98\x80")}},
            .content = content,
        },
    };

    const std::vector<nsealr::TrustedReviewPage> pages =
        nsealr::build_qr_display_review_pages(request, nsealr_esp32::t_display_s3_review_limits());
    const std::string content_text = joined_lines_for_title(pages, "Content");
    const std::string tag_text = joined_lines_for_title(pages, "Tags");

    assert(content_text.find("U+00E8") != std::string::npos);
    assert(content_text.find("U+1F600") != std::string::npos);
    assert(tag_text.find("U+00E8") != std::string::npos);
    assert(tag_text.find("U+1F600") != std::string::npos);
}

void test_qr_display_review_pages_render_control_escapes_visibly() {
    const std::string content = "line 1\nline 2\tTabbed\rCarriage\bBackspace\fFormfeed";
    const nsealr::QrSigningRequest request{
        .version = 1,
        .request_id = "req-control-escapes-display",
        .method = "sign_event",
        .has_params = true,
        .has_event_template = true,
        .event_template_json = "",
        .event_template = nsealr::QrEventTemplate{
            .created_at = 1710000480,
            .kind = 1,
            .tags_json = "",
            .tags = {{"t", "line\nbreak"}, {"subject", "tab\tvalue", "carriage\rreturn"}},
            .content = content,
        },
    };

    const std::vector<nsealr::TrustedReviewPage> pages =
        nsealr::build_qr_display_review_pages(request, nsealr_esp32::t_display_s3_review_limits());
    const std::string content_text = joined_lines_for_title(pages, "Content");
    const std::string tag_text = joined_lines_for_title(pages, "Tags");

    assert(content_text.find("\\n") != std::string::npos);
    assert(content_text.find("\\t") != std::string::npos);
    assert(content_text.find("\\r") != std::string::npos);
    assert(content_text.find("\\b") != std::string::npos);
    assert(content_text.find("\\f") != std::string::npos);
    assert(tag_text.find("line\\nbreak") != std::string::npos);
    assert(tag_text.find("tab\\tvalue") != std::string::npos);
    assert(tag_text.find("carriage\\rreturn") != std::string::npos);
    assert(content_text.find("U+000A") == std::string::npos);
    assert(tag_text.find("U+0009") == std::string::npos);
}

void test_qr_display_review_pages_preserve_supported_ascii_punctuation() {
    const std::string content = "hello, nostr! #tag? @alice & key=value `code` ^caret";
    const nsealr::QrSigningRequest request{
        .version = 1,
        .request_id = "req-ascii-punctuation-display",
        .method = "sign_event",
        .has_params = true,
        .has_event_template = true,
        .event_template_json = "",
        .event_template = nsealr::QrEventTemplate{
            .created_at = 1710000360,
            .kind = 1,
            .tags_json = "",
            .tags = {{"client", "nsealr/esp32-v0"}, {"subject", "a+b=c?"}},
            .content = content,
        },
    };

    const std::vector<nsealr::TrustedReviewPage> pages =
        nsealr::build_qr_display_review_pages(request, nsealr_esp32::t_display_s3_review_limits());
    const std::string content_text = joined_lines_for_title(pages, "Content");
    const std::string tag_text = joined_lines_for_title(pages, "Tags");

    assert(content_text.find(content) != std::string::npos);
    assert(content_text.find("U+002C") == std::string::npos);
    assert(content_text.find("U+0021") == std::string::npos);
    assert(content_text.find("U+003F") == std::string::npos);
    assert(content_text.find("U+005E") == std::string::npos);
    assert(content_text.find("U+0060") == std::string::npos);
    assert(tag_text.find("nsealr/esp32-v0") != std::string::npos);
    assert(tag_text.find("a+b=c?") != std::string::npos);
}

void test_qr_display_review_pages_split_full_long_content_without_ellipsis() {
    const std::string long_content(281, 'x');
    const nsealr::QrSigningRequest request{
        .version = 1,
        .request_id = "req-long-display",
        .method = "sign_event",
        .has_params = true,
        .has_event_template = true,
        .event_template_json = "",
        .event_template = nsealr::QrEventTemplate{
            .created_at = 1710000120,
            .kind = 1,
            .tags_json = "[]",
            .tags = {},
            .content = long_content,
        },
    };

    const std::vector<nsealr::TrustedReviewPage> pages =
        nsealr::build_qr_display_review_pages(request, nsealr_esp32::t_display_s3_review_limits());
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
    const nsealr::QrSigningRequest request{
        .version = 1,
        .request_id = "req-scroll-display",
        .method = "sign_event",
        .has_params = true,
        .has_event_template = true,
        .event_template_json = "",
        .event_template = nsealr::QrEventTemplate{
            .created_at = 1710000240,
            .kind = 1,
            .tags_json = R"([["t","tag0"],["t","tag1"],["t","tag2"],["t","tag3"],["t","tag4"],["t","tag5"]])",
            .tags = {{"t", "tag0"}, {"t", "tag1"}, {"t", "tag2"}, {"t", "tag3"}, {"t", "tag4"}, {"t", "tag5"}},
            .content = long_content,
        },
    };

    const std::vector<nsealr::TrustedReviewPage> pages =
        nsealr::build_qr_display_review_pages(request, nsealr_esp32::t_display_s3_review_limits());

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
    for (const nsealr::TrustedReviewPage& page : pages) {
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
    const nsealr::QrEnvelope envelope =
        nsealr::decode_qr_envelope(nsealr::test_vectors::kQrEnvelopeKind1Basic);
    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(envelope);
    nsealr::TrustedReviewSession session = nsealr::begin_qr_trusted_review(request);

    const nsealr::ReviewDisplayFrame first_frame = session.current_frame();
    assert(first_frame.title == "Event");
    assert(first_frame.page_indicator == "Page 1/4");
    assert(!session.can_sign());

    expect_throw("approval requires decision review page", [&] {
        (void)session.handle_button(nsealr::ReviewButton::Approve);
    });

    (void)session.handle_button(nsealr::ReviewButton::Next);
    (void)session.handle_button(nsealr::ReviewButton::Next);
    (void)session.handle_button(nsealr::ReviewButton::Next);

    const nsealr::ReviewDisplayFrame decision_frame = session.current_frame();
    assert(decision_frame.title == "Decision");
    assert(!session.can_sign());

    const auto approval = session.handle_button(nsealr::ReviewButton::Approve);
    assert(approval.has_value());
    assert(approval.value());
    assert(session.can_sign());
}

void test_qr_review_flow_drives_scanned_qr_without_signing_backend() {
    nsealr::QrReviewFlow flow{nsealr::test_vectors::kQrEnvelopeKind1Basic};
    const nsealr::TrustedReviewRequest expected = nsealr::test_vectors::basic_trusted_review_request();

    assert(flow.request_id() == expected.request_id);
    assert(flow.approval_digest() == expected.approval_digest);
    assert(!flow.approved_for_signing());

    const nsealr::ReviewDisplayFrame first_frame = flow.current_frame();
    assert(first_frame.title == "Event");
    assert(first_frame.page_indicator == "Page 1/4");

    expect_throw("approval requires decision review page", [&] {
        (void)flow.handle_button(nsealr::ReviewButton::Approve);
    });

    (void)flow.handle_button(nsealr::ReviewButton::Next);
    (void)flow.handle_button(nsealr::ReviewButton::Next);
    (void)flow.handle_button(nsealr::ReviewButton::Next);

    const nsealr::ReviewDisplayFrame decision_frame = flow.current_frame();
    assert(decision_frame.title == "Decision");
    assert(!flow.approved_for_signing());

    const auto approval = flow.handle_button(nsealr::ReviewButton::Approve);
    assert(approval.has_value());
    assert(approval.value());
    assert(flow.approved_for_signing());
    assert(flow.decision() == nsealr::ApprovalDecision::Approved);
}

void test_qr_review_flow_binds_selected_session_account_identity() {
    nsealr::StatelessSessionKeyring keyring;
    keyring.add_bip39_seed(
        "NIP-06 account 0",
        nsealr::parse_bip39_english_mnemonic_indexes(nsealr::test_vectors::kNip06Account0Mnemonic));
    const nsealr::SelectedSessionAccount selected = nsealr::select_session_account(
        keyring,
        nsealr::test_vectors::esp32_qr_nip06_account_0_descriptor());

    const nsealr::QrSigningRequest request = nsealr::parse_qr_signing_request(
        nsealr::decode_qr_envelope(nsealr::test_vectors::kQrEnvelopeKind1Basic));
    const nsealr::TrustedReviewRequest expected =
        nsealr::build_qr_display_review_request(request, selected.signer_identity);

    nsealr::QrReviewFlow flow{nsealr::test_vectors::kQrEnvelopeKind1Basic, selected.signer_identity};
    assert(flow.approval_digest() == expected.approval_digest);
    assert(flow.approval_digest() != nsealr::test_vectors::basic_trusted_review_request().approval_digest);

    const nsealr::ReviewDisplayFrame first_frame = flow.current_frame();
    const std::string selected_pubkey_prefix =
        std::string(nsealr::test_vectors::kNip06Account0PublicKey).substr(0, 32);
    const std::string development_pubkey_prefix =
        std::string(nsealr::kDevelopmentFixturePublicKey).substr(0, 32);
    assert(first_frame.title == "Event");
    assert(lines_contain(first_frame.body_lines, selected_pubkey_prefix));
    assert(!lines_contain(first_frame.body_lines, development_pubkey_prefix));

    RecordingQrReviewIo io{{nsealr::ReviewButton::Next,
                            nsealr::ReviewButton::Next,
                            nsealr::ReviewButton::Next,
                            nsealr::ReviewButton::Approve}};
    const nsealr::QrReviewIoFlowResult result =
        nsealr::run_qr_review_io_flow(io, selected.signer_identity);
    assert(result.approval_digest == expected.approval_digest);
    assert(result.approved_for_signing);
    assert(!io.frames.empty());
    assert(lines_contain(io.frames.front().body_lines, selected_pubkey_prefix));
    assert(!lines_contain(io.frames.front().body_lines, development_pubkey_prefix));
}

void test_qr_review_flow_rejects_unsafe_scanned_qr() {
    expect_throw("QR signing request event_template must not include sig", [] {
        nsealr::QrReviewFlow flow{
            R"(nsealr1:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm1ldGhvZCI6InNpZ25fZXZlbnQiLCJwYXJhbXMiOnsiZXZlbnRfdGVtcGxhdGUiOnsiY3JlYXRlZF9hdCI6MTcxMDAwMDAwMCwia2luZCI6MSwidGFncyI6W10sImNvbnRlbnQiOiIiLCJzaWciOiIwMCJ9fX0)"};
        (void)flow;
    });
}

void test_qr_review_flow_transcript_records_display_and_approval_steps() {
    const std::vector<nsealr::QrReviewTranscriptStep> transcript = nsealr::run_qr_review_transcript(
        nsealr::test_vectors::kQrEnvelopeKind1Basic,
        nsealr::test_vectors::basic_qr_review_approve_buttons());

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
    assert(transcript[1].frame.body_lines == nsealr::test_vectors::basic_qr_review_approve_transcript()[1].frame.body_lines);
    assert(transcript[2].frame.title == "Tags");
    assert((transcript[2].frame.body_lines == std::vector<std::string>{"No tags"}));
    assert(transcript[3].frame.title == "Decision");
    assert(transcript[3].frame.action_hint == "Approve / Reject");
    assert(transcript[3].decision.has_value());
    assert(transcript[3].decision.value());
    assert(transcript[3].approved_for_signing);
}

void test_qr_review_flow_transcript_records_early_rejection() {
    const std::vector<nsealr::QrReviewTranscriptStep> transcript = nsealr::run_qr_review_transcript(
        nsealr::test_vectors::kQrEnvelopeKind1Basic,
        nsealr::test_vectors::basic_qr_review_reject_buttons());

    assert(transcript.size() == 1);
    assert(transcript[0].frame.title == "Event");
    assert(lines_contain(transcript[0].frame.body_lines, "Author"));
    assert(!lines_contain(transcript[0].frame.body_lines, "Short Text Note"));
    assert(transcript[0].decision.has_value());
    assert(!transcript[0].decision.value());
    assert(!transcript[0].approved_for_signing);
}

void test_qr_review_flow_transcript_matches_shared_detail_scroll_vector() {
    const std::vector<nsealr::QrReviewTranscriptStep> transcript = nsealr::run_qr_review_transcript(
        nsealr::test_vectors::kQrEnvelopeKind1LongEventsManyTags,
        nsealr::test_vectors::long_events_many_tags_detail_scroll_approve_buttons(),
        nsealr::test_vectors::long_events_many_tags_detail_scroll_approve_display_limits());

    assert_qr_review_transcript_equals(
        transcript,
        nsealr::test_vectors::long_events_many_tags_detail_scroll_approve_transcript());
    assert(transcript[2].frame.action_hint == "Next/Scroll");
    assert(transcript[2].button == nsealr::ReviewButton::Back);
    assert(transcript.back().approved_for_signing);
}

void test_qr_review_io_flow_drives_scanner_display_and_buttons_without_signing() {
    RecordingQrReviewIo io{{nsealr::ReviewButton::Next,
                            nsealr::ReviewButton::Next,
                            nsealr::ReviewButton::Next,
                            nsealr::ReviewButton::Approve}};

    const nsealr::QrReviewIoFlowResult result = nsealr::run_qr_review_io_flow(io);

    assert(result.request_id == "req-kind-1-basic");
    assert(result.approval_digest == nsealr::test_vectors::kBasicReviewScreenApprovalDigest);
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
        (void)nsealr::run_qr_review_io_flow(io, {}, 5);
    });

    assert(io.frames.size() == 5);
    assert(io.frames[3].title == "Decision");
    assert(io.frames.back().title == "Event");
}

void test_qr_review_io_flow_requires_nonzero_step_limit() {
    RecordingQrReviewIo io{{nsealr::ReviewButton::Approve}};

    expect_throw("QR review IO max steps must be non-zero", [&] {
        (void)nsealr::run_qr_review_io_flow(io, {}, 0);
    });

    assert(io.frames.empty());
}

void test_approval_gate_requires_matching_approval() {
    nsealr::ApprovalGate gate;
    gate.begin_review("req-kind-1-basic", nsealr::test_vectors::kBasicReviewScreenApprovalDigest);

    assert(!gate.can_sign("req-kind-1-basic", nsealr::test_vectors::kBasicReviewScreenApprovalDigest));
    assert(!gate.can_sign("different", nsealr::test_vectors::kBasicReviewScreenApprovalDigest));

    gate.approve("req-kind-1-basic", "00");
    assert(!gate.can_sign("req-kind-1-basic", nsealr::test_vectors::kBasicReviewScreenApprovalDigest));

    gate.approve("different", nsealr::test_vectors::kBasicReviewScreenApprovalDigest);
    assert(!gate.can_sign("req-kind-1-basic", nsealr::test_vectors::kBasicReviewScreenApprovalDigest));

    gate.approve("req-kind-1-basic", nsealr::test_vectors::kBasicReviewScreenApprovalDigest);
    assert(gate.can_sign("req-kind-1-basic", nsealr::test_vectors::kBasicReviewScreenApprovalDigest));
    assert(!gate.can_sign("req-kind-1-basic", nsealr::test_vectors::kTaggedReviewScreenApprovalDigest));

    gate.begin_review("req-kind-1-tags", nsealr::test_vectors::kTaggedReviewScreenApprovalDigest);
    gate.reject("req-kind-1-tags");
    assert(!gate.can_sign("req-kind-1-tags", nsealr::test_vectors::kTaggedReviewScreenApprovalDigest));
    assert(gate.decision() == nsealr::ApprovalDecision::Rejected);
}

void test_review_controls_require_page_traversal_before_approval() {
    nsealr::ReviewControlSession session{4};

    assert(session.current_page_index() == 0);
    assert(!session.can_approve());
    expect_throw("approval requires viewing every review page", [&] {
        (void)session.handle_button(nsealr::ReviewButton::Approve);
    });

    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_page_index() == 1);
    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_page_index() == 2);
    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_page_index() == 3);
    assert(session.can_approve());

    const auto result = session.handle_button(nsealr::ReviewButton::Approve);
    assert(result.has_value());
    assert(result.value());
    assert(session.approved());
    assert(!session.rejected());
}

void test_review_controls_allow_backward_navigation_before_terminal_decision() {
    nsealr::ReviewControlSession session{4};

    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_page_index() == 2);
    assert(!session.can_approve());

    assert(!session.handle_button(nsealr::ReviewButton::Back).has_value());
    assert(session.current_page_index() == 1);
    assert(!session.can_approve());

    assert(!session.handle_button(nsealr::ReviewButton::Back).has_value());
    assert(session.current_page_index() == 0);
    assert(!session.handle_button(nsealr::ReviewButton::Back).has_value());
    assert(session.current_page_index() == 0);

    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_page_index() == 3);
    assert(session.can_approve());
}

void test_review_controls_allow_early_rejection() {
    nsealr::ReviewControlSession session{4};

    const auto result = session.handle_button(nsealr::ReviewButton::Reject);

    assert(result.has_value());
    assert(!result.value());
    assert(session.rejected());
    assert(!session.approved());
}

void test_review_controls_are_terminal_after_decision() {
    nsealr::ReviewControlSession rejected_session{2};
    (void)rejected_session.handle_button(nsealr::ReviewButton::Reject);
    expect_throw("review decision is already terminal", [&] {
        (void)rejected_session.handle_button(nsealr::ReviewButton::Next);
    });

    nsealr::ReviewControlSession approved_session{1};
    const auto approved = approved_session.handle_button(nsealr::ReviewButton::Approve);
    assert(approved.has_value());
    assert(approved.value());
    expect_throw("review decision is already terminal", [&] {
        (void)approved_session.handle_button(nsealr::ReviewButton::Approve);
    });
}

void test_review_display_renders_navigation_frame() {
    const nsealr::ReviewPage page{
        "Event",
        {"Kind 1", "Created 1710000000", "Author"},
        nsealr::ReviewPageAction::Next,
    };

    const nsealr::ReviewDisplayFrame frame = nsealr::render_review_page(page, 0, 4);

    assert(frame.title == "Event");
    assert(frame.page_indicator == "Page 1/4");
    assert((frame.body_lines == std::vector<std::string>{"Kind 1", "Created 1710000000", "Author"}));
    assert(frame.action_hint == "Next");
}

void test_review_display_preserves_logical_page_indicator_and_body_styles() {
    const nsealr::ReviewPage page{
        "Content",
        {"bytes: 281", "abcdef"},
        nsealr::ReviewPageAction::Next,
        "Page 2/4",
        {nsealr::ReviewBodyLineStyle::Meta, nsealr::ReviewBodyLineStyle::Value},
    };

    const nsealr::ReviewDisplayFrame frame = nsealr::render_review_page(
        page,
        4,
        12,
        nsealr::ReviewDisplayLimits{
            .max_title_chars = 18,
            .max_body_lines = 5,
            .max_line_chars = 26,
            .max_compact_body_lines = 9,
            .max_compact_line_chars = 48,
        });

    assert(frame.title == "Content");
    assert(frame.page_indicator == "Page 2/4");
    assert((frame.body_lines == std::vector<std::string>{"bytes: 281", "abcdef"}));
    assert((frame.body_line_styles == std::vector<nsealr::ReviewBodyLineStyle>{
                                          nsealr::ReviewBodyLineStyle::Meta,
                                          nsealr::ReviewBodyLineStyle::Value,
                                      }));
    assert(frame.action_hint == "Next");
}

void test_review_display_renders_decision_frame() {
    const nsealr::ReviewPage page{
        "Decision",
        {"Approve signing only if all pages match."},
        nsealr::ReviewPageAction::ApproveOrReject,
    };

    const nsealr::ReviewDisplayFrame frame = nsealr::render_review_page(page, 3, 4);

    assert(frame.title == "Decision");
    assert(frame.page_indicator == "Page 4/4");
    assert((frame.body_lines == std::vector<std::string>{"Approve signing only if all pages match."}));
    assert(frame.action_hint == "Approve / Reject");
}

void test_review_display_wraps_and_truncates_long_body_lines() {
    const nsealr::ReviewPage page{
        "Content",
        {"0123456789abcdef0123456789abcdef0123456789abcdef"},
        nsealr::ReviewPageAction::Next,
    };

    const nsealr::ReviewDisplayFrame frame = nsealr::render_review_page(
        page,
        1,
        4,
        nsealr::ReviewDisplayLimits{.max_title_chars = 12, .max_body_lines = 2, .max_line_chars = 16});

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
    const nsealr::ReviewPage page{
        "Content",
        {text},
        nsealr::ReviewPageAction::Next,
    };

    const nsealr::ReviewDisplayFrame frame = nsealr::render_review_page(
        page,
        0,
        1,
        nsealr::ReviewDisplayLimits{.max_title_chars = 12, .max_body_lines = 3, .max_line_chars = 4});

    assert((frame.body_lines == std::vector<std::string>{std::string("abc") + "\xC3\xA8", "def"}));
    assert(nsealr::is_valid_utf8(frame.body_lines[0]));
    assert(nsealr::is_valid_utf8(frame.body_lines[1]));
}

void test_review_display_matches_shared_long_content_frame_vector() {
    const std::string long_preview = std::string(120, 'x') + "...";
    const nsealr::ReviewPage page{
        "Content",
        {long_preview},
        nsealr::ReviewPageAction::Next,
    };

    const nsealr::ReviewDisplayFrame frame = nsealr::render_review_page(
        page,
        1,
        4,
        nsealr::test_vectors::long_content_display_limits_20x3());
    const nsealr::ReviewDisplayFrame expected = nsealr::test_vectors::long_content_display_frame_20x3();

    assert(frame.title == expected.title);
    assert(frame.page_indicator == expected.page_indicator);
    assert(frame.body_lines == expected.body_lines);
    assert(frame.action_hint == expected.action_hint);
}

void test_review_display_matches_shared_utf8_boundary_frame_vector() {
    const std::string text = std::string("abc") + "\xC3\xA8" + "def";
    const nsealr::ReviewPage page{
        "Content",
        {text},
        nsealr::ReviewPageAction::Next,
    };

    const nsealr::ReviewDisplayFrame frame = nsealr::render_review_page(
        page,
        1,
        4,
        nsealr::test_vectors::kind_1_unicode_boundary_content_4x3_display_limits());
    const nsealr::ReviewDisplayFrame expected =
        nsealr::test_vectors::kind_1_unicode_boundary_content_4x3_display_frame();

    assert(frame.title == expected.title);
    assert(frame.page_indicator == expected.page_indicator);
    assert(frame.body_lines == expected.body_lines);
    assert(frame.action_hint == expected.action_hint);
}

void test_review_display_rejects_unsafe_frame_bounds() {
    const nsealr::ReviewPage page{
        "Event",
        {"Kind 1"},
        nsealr::ReviewPageAction::Next,
    };

    expect_throw("review display page index out of range", [&] {
        (void)nsealr::render_review_page(page, 4, 4);
    });

    expect_throw("review display total pages must be non-zero", [&] {
        (void)nsealr::render_review_page(page, 0, 0);
    });

    expect_throw("review display title exceeds configured width", [&] {
        const nsealr::ReviewPage unsafe_page{
            "This title is too long for a tiny trusted display",
            {"Kind 1"},
            nsealr::ReviewPageAction::Next,
        };
        (void)nsealr::render_review_page(
            unsafe_page,
            0,
            1,
            nsealr::ReviewDisplayLimits{.max_title_chars = 12, .max_body_lines = 4, .max_line_chars = 32});
    });
}

void test_trusted_review_session_binds_display_navigation_and_approval() {
    nsealr::TrustedReviewSession session{nsealr::test_vectors::basic_trusted_review_request()};

    const nsealr::ReviewDisplayFrame first_frame = session.current_frame();
    assert(first_frame.title == "Event");
    assert(first_frame.page_indicator == "Page 1/4");
    assert(first_frame.action_hint == "Next");
    assert(!session.can_sign());

    expect_throw("approval requires viewing every review page", [&] {
        (void)session.handle_button(nsealr::ReviewButton::Approve);
    });

    (void)session.handle_button(nsealr::ReviewButton::Next);
    (void)session.handle_button(nsealr::ReviewButton::Next);
    (void)session.handle_button(nsealr::ReviewButton::Next);

    const nsealr::ReviewDisplayFrame decision_frame = session.current_frame();
    assert(decision_frame.title == "Decision");
    assert(decision_frame.page_indicator == "Page 4/4");
    assert(decision_frame.action_hint == "Approve / Reject");
    assert(!session.can_sign());

    const auto approval = session.handle_button(nsealr::ReviewButton::Approve);
    assert(approval.has_value());
    assert(approval.value());
    assert(session.can_sign());
}

void test_trusted_review_session_keeps_rejection_terminal() {
    nsealr::TrustedReviewSession session{nsealr::test_vectors::tagged_trusted_review_request()};

    const nsealr::ReviewDisplayFrame first_frame = session.current_frame();
    assert(first_frame.title == "Event");
    assert(first_frame.page_indicator == "Page 1/4");

    (void)session.handle_button(nsealr::ReviewButton::Next);
    (void)session.handle_button(nsealr::ReviewButton::Next);
    const nsealr::ReviewDisplayFrame tags_frame = session.current_frame();
    assert(tags_frame.title == "Tags");
    assert(lines_contain(tags_frame.body_lines, "Tag 1/2"));
    assert(lines_contain(tags_frame.body_lines, "p"));

    (void)session.handle_button(nsealr::ReviewButton::Next);
    const nsealr::ReviewDisplayFrame decision_frame = session.current_frame();
    assert(decision_frame.title == "Decision");
    assert((decision_frame.body_lines == std::vector<std::string>{"Approve signing only if all pages match."}));

    const auto rejection = session.handle_button(nsealr::ReviewButton::Reject);

    assert(rejection.has_value());
    assert(!rejection.value());
    assert(!session.can_sign());
    assert(session.decision() == nsealr::ApprovalDecision::Rejected);
}

void test_trusted_review_session_allows_backward_review_before_approval() {
    nsealr::TrustedReviewSession session{nsealr::test_vectors::basic_trusted_review_request()};

    assert(session.current_frame().title == "Event");
    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Content");
    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Tags");
    assert(!session.handle_button(nsealr::ReviewButton::Back).has_value());
    assert(session.current_frame().title == "Content");
    assert(!session.can_sign());

    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Decision");

    const auto approval = session.handle_button(nsealr::ReviewButton::Approve);
    assert(approval.has_value());
    assert(approval.value());
    assert(session.can_sign());
}

void test_serial_sign_event_review_matches_shared_review_contract() {
    const nsealr::TrustedReviewRequest serial_review =
        nsealr::build_serial_sign_event_trusted_review_request(
            R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"nSealr fixture: basic kind 1 event."}}})");
    const nsealr::TrustedReviewRequest expected = nsealr::test_vectors::basic_trusted_review_request();

    assert(serial_review.request_id == expected.request_id);
    assert(serial_review.approval_digest == expected.approval_digest);
    assert_trusted_review_pages(serial_review.pages, expected.pages);

    nsealr::TrustedReviewSession session = nsealr::begin_serial_sign_event_trusted_review(
        R"({"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"nSealr fixture: basic kind 1 event."}}})");
    assert(session.current_frame().title == "Event");
    assert(!session.can_sign());
}

void test_serial_review_session_uses_full_scroll_display_pages() {
    const std::string pubkey = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    nsealr::TrustedReviewSession session = nsealr::begin_serial_sign_event_trusted_review(
        R"({"version":1,"request_id":"req-kind-1-tags","method":"sign_event","params":{"event_template":{"created_at":1710000060,"kind":1,"tags":[["p","4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","","mention"],["t","nsealr"]],"content":"nSealr fixture: tagged kind 1 event."}}})",
        nsealr::ReviewDisplayLimits{.max_title_chars = 18, .max_body_lines = 3, .max_line_chars = 20});

    std::string tag_text;
    bool saw_tags = false;
    bool saw_warnings = false;
    for (std::size_t step = 0; step < 16U && session.current_frame().title != "Decision"; ++step) {
        const nsealr::ReviewDisplayFrame frame = session.current_frame();
        if (frame.title == "Tags") {
            saw_tags = true;
            for (const std::string& line : frame.body_lines) {
                tag_text += line;
            }
        }
        if (frame.title == "Warnings") {
            saw_warnings = true;
        }
        assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    }

    assert(session.current_frame().title == "Decision");
    assert(saw_tags);
    assert(!saw_warnings);
    assert(tag_text.find("...") == std::string::npos);
    assert(tag_text.find(pubkey.substr(0, 48)) != std::string::npos);
    assert(tag_text.find(pubkey.substr(48)) != std::string::npos);
    assert(tag_text.find("mention") != std::string::npos);
    assert(tag_text.find("nsealr") != std::string::npos);
}

void test_serial_review_binds_configured_signer_identity() {
    const std::string alternate_pubkey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const nsealr::SignerIdentity alternate_identity{alternate_pubkey};
    const std::string request_json =
        R"({"version":1,"request_id":"req-alt-author","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"alternate author"}}})";

    const nsealr::TrustedReviewRequest default_review =
        nsealr::build_serial_sign_event_trusted_review_request(request_json);
    const nsealr::TrustedReviewRequest alternate_review =
        nsealr::build_serial_sign_event_trusted_review_request(request_json, alternate_identity);

    assert(alternate_review.approval_digest != default_review.approval_digest);
    assert(lines_contain(alternate_review.pages.front().lines, alternate_pubkey));

    nsealr::TrustedReviewSession session = nsealr::begin_serial_sign_event_trusted_review(
        request_json,
        alternate_identity,
        nsealr_esp32::t_display_s3_review_limits());
    const std::string event_text = joined_lines_for_title(
        nsealr::build_qr_display_review_pages(
            nsealr::parse_qr_signing_request(nsealr::QrEnvelope{"serial", request_json}),
            alternate_identity,
            nsealr_esp32::t_display_s3_review_limits()),
        "Event");

    assert(session.current_frame().title == "Event");
    assert(event_text.find(alternate_pubkey.substr(0, 48)) != std::string::npos);
    assert(event_text.find(alternate_pubkey.substr(48)) != std::string::npos);
    assert(!session.can_sign());
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

    nsealr::TrustedReviewSession session = nsealr::begin_serial_sign_event_trusted_review(
        request_json,
        nsealr_esp32::t_display_s3_review_limits());

    assert(session.current_frame().title == "Event");
    assert(session.current_frame().page_indicator == "Page 1/4");
    expect_throw("approval requires decision review page", [&] {
        (void)session.handle_button(nsealr::ReviewButton::Approve);
    });

    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Content");
    assert(session.current_frame().page_indicator == "Page 2/4");
    assert(session.current_frame().action_hint == "Next");

    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Tags");
    const std::string first_tag_page_indicator = session.current_frame().page_indicator;
    assert(first_tag_page_indicator.rfind("Page 3/4 Lines 1-9/", 0) == 0);
    assert(session.current_frame().action_hint == "Next/Scroll");

    assert(!session.handle_button(nsealr::ReviewButton::Back).has_value());
    assert(session.current_frame().title == "Tags");
    assert(session.current_frame().page_indicator.rfind("Page 3/4 Lines 10-", 0) == 0);
    assert(session.current_frame().page_indicator != first_tag_page_indicator);
    assert(session.current_frame().action_hint == "Next/Scroll");

    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Decision");
    assert(session.current_frame().page_indicator == "Page 4/4");
    assert(!session.can_sign());

    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Event");
    assert(session.current_frame().page_indicator == "Page 1/4");

    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(!session.handle_button(nsealr::ReviewButton::Next).has_value());
    assert(session.current_frame().title == "Decision");

    const auto approval = session.handle_button(nsealr::ReviewButton::Approve);
    assert(approval.has_value());
    assert(approval.value());
    assert(session.can_sign());
}

void test_serial_review_io_flow_drives_request_display_and_buttons_without_signing() {
    RecordingSerialReviewIo io{{nsealr::ReviewButton::Next,
                                nsealr::ReviewButton::Next,
                                nsealr::ReviewButton::Next,
                                nsealr::ReviewButton::Approve}};

    const nsealr::SerialReviewIoFlowResult result = nsealr::run_serial_review_io_flow(io);

    assert(result.request_id == "req-kind-1-basic");
    assert(result.approval_digest == nsealr::test_vectors::kBasicReviewScreenApprovalDigest);
    assert(result.decision.has_value());
    assert(result.decision.value());
    assert(result.approved_for_signing);
    assert(result.transcript.size() == nsealr::test_vectors::basic_qr_review_approve_transcript().size());
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
    const nsealr::SigningReadiness default_readiness{};
    const nsealr::SigningReadinessStatus default_status =
        nsealr::evaluate_signing_readiness(default_readiness);

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
                                               "source_public_key_proof",
                                               "secure_boot",
                                               "flash_encryption",
                                               "debug_lock",
                                               "companion_signed_output_verification",
                                           }));

    nsealr::SigningReadiness safety_gates{
        .runtime_signing_feature_enabled = false,
        .parser_limits_enforced = true,
        .trusted_review_display_accepted = true,
        .physical_approval_controls_accepted = true,
        .approval_digest_binding_verified = true,
        .unicode_review_rendering_accepted = true,
        .key_provisioning_ready = true,
        .source_public_key_proof_ready = true,
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
    const nsealr::SigningReadinessStatus safety_status =
        nsealr::evaluate_signing_readiness(safety_gates);

    assert(!safety_status.signing_enabled);
    assert((safety_status.missing_gates == std::vector<std::string>{"runtime_signing_feature"}));
    assert((safety_status.development_accepted_gates == std::vector<std::string>{
                                                        "parser_limits",
                                                        "trusted_review_display",
                                                        "physical_approval_controls",
                                                        "approval_digest_binding",
                                                    }));

    safety_gates.runtime_signing_feature_enabled = true;
    const nsealr::SigningReadinessStatus ready_status =
        nsealr::evaluate_signing_readiness(safety_gates);

    assert(ready_status.signing_enabled);
    assert(ready_status.missing_gates.empty());
    assert((ready_status.development_accepted_gates == safety_status.development_accepted_gates));

    safety_gates.development_accepted_gates.push_back("parser_limits");
    const nsealr::SigningReadinessStatus duplicate_gate_status =
        nsealr::evaluate_signing_readiness(safety_gates);

    assert((duplicate_gate_status.development_accepted_gates == safety_status.development_accepted_gates));
}

void test_device_protocol_reports_scaffold_capabilities() {
    const std::string response = nsealr::handle_serial_frame(nsealr::test_vectors::kCapabilityRequestFrame);

    assert(response == nsealr::test_vectors::kCapabilityResponseFrame);
    const nsealr::SerialFrame decoded = nsealr::decode_serial_frame(response);
    assert(decoded.type == nsealr::FrameType::Response);
    assert(decoded.payload_base64url == nsealr::test_vectors::kCapabilityResponsePayloadBase64Url);
}

void test_device_protocol_rejects_signing_while_disabled() {
    const std::string response = nsealr::handle_serial_frame(nsealr::test_vectors::kSignEventRequestFrame);

    assert(response == nsealr::test_vectors::kSignEventDisabledResponseFrame);
    const nsealr::SerialFrame decoded = nsealr::decode_serial_frame(response);
    assert(decoded.type == nsealr::FrameType::Response);
    assert(decoded.payload_base64url == nsealr::test_vectors::kSignEventDisabledResponsePayloadBase64Url);
}

void test_device_protocol_exposes_review_frame_before_disabled_signing_response() {
    const nsealr::SerialFrameHandlingResult result = nsealr::handle_serial_frame_with_review_preview(
        nsealr::test_vectors::kSignEventRequestFrame,
        nsealr::ReviewDisplayLimits{
            .max_title_chars = 18,
            .max_body_lines = 5,
            .max_line_chars = 26,
        });

    assert(result.response_frame == nsealr::test_vectors::kSignEventDisabledResponseFrame);
    assert(result.review_frame.has_value());
    assert(result.review_frame->title == "Event");
    assert(result.review_frame->page_indicator == "Page 1/4");
    assert(!result.review_frame->body_lines.empty());
    assert(result.review_frame->body_lines.front() == "Kind 1");
    assert(result.review_frame->action_hint == "Next");
}

void test_device_protocol_exposes_review_session_for_manual_display_navigation() {
    nsealr::SerialFrameHandlingResult result = nsealr::handle_serial_frame_with_review_preview(
        nsealr::test_vectors::kSignEventRequestFrame,
        nsealr::ReviewDisplayLimits{
            .max_title_chars = 18,
            .max_body_lines = 5,
            .max_line_chars = 26,
        });

    assert(result.response_frame == nsealr::test_vectors::kSignEventDisabledResponseFrame);
    assert(result.review_session.has_value());
    assert(result.review_session->current_frame().title == "Event");
    assert(!result.review_session->handle_button(nsealr::ReviewButton::Next).has_value());
    assert(result.review_session->current_frame().title == "Content");
    assert(!result.review_session->handle_button(nsealr::ReviewButton::Back).has_value());
    assert(result.review_session->current_frame().title == "Content");
    assert(!result.review_session->handle_button(nsealr::ReviewButton::Next).has_value());
    assert(result.review_session->current_frame().title == "Tags");
    assert(!result.review_session->can_sign());
}

void test_device_protocol_reports_development_public_key() {
    const std::string response = nsealr::handle_serial_frame(nsealr::test_vectors::kPublicKeyRequestFrame);

    assert(response == nsealr::test_vectors::kPublicKeyResponseFrame);
    const nsealr::SerialFrame decoded = nsealr::decode_serial_frame(response);
    assert(decoded.type == nsealr::FrameType::Response);
    assert(decoded.payload_base64url == nsealr::test_vectors::kPublicKeyResponsePayloadBase64Url);
}

void test_device_protocol_binds_configured_signer_identity() {
    const std::string alternate_pubkey = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const nsealr::DeviceProtocolContext context{nsealr::SignerIdentity{alternate_pubkey}};

    const std::string public_key_response = nsealr::handle_serial_frame(
        request_frame_for_test(R"({"version":1,"request_id":"req-context-pubkey","method":"get_public_key"})"),
        context);

    assert(public_key_response == response_frame_for_test(
                                      R"({"version":1,"request_id":"req-context-pubkey","ok":true,"result":{"public_key":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}})"));

    const nsealr::SerialFrameHandlingResult result = nsealr::handle_serial_frame_with_review_preview(
        request_frame_for_test(
            R"({"version":1,"request_id":"req-context-sign","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"context identity"}}})"),
        context,
        nsealr_esp32::t_display_s3_review_limits());

    assert(result.review_session.has_value());
    const nsealr::ReviewDisplayFrame event_frame = result.review_session->current_frame();
    assert(event_frame.title == "Event");
    assert(lines_contain(event_frame.body_lines, alternate_pubkey.substr(0, 48)));
    assert(lines_contain(event_frame.body_lines, alternate_pubkey.substr(48)));

    expect_throw("signer public key", [&] {
        (void)nsealr::handle_serial_frame(
            request_frame_for_test(R"({"version":1,"request_id":"req-bad-context","method":"get_public_key"})"),
            nsealr::DeviceProtocolContext{nsealr::SignerIdentity{"bad"}});
    });
}

void test_device_protocol_reports_signing_status_gates() {
    const std::string response = nsealr::handle_serial_frame(nsealr::test_vectors::kSigningStatusRequestFrame);

    assert(response == nsealr::test_vectors::kSigningStatusResponseFrame);
    const nsealr::SerialFrame decoded = nsealr::decode_serial_frame(response);
    assert(decoded.type == nsealr::FrameType::Response);
    assert(decoded.payload_base64url == nsealr::test_vectors::kSigningStatusResponsePayloadBase64Url);
}

void test_device_protocol_echoes_dynamic_request_ids() {
    const std::string capability_response = nsealr::handle_serial_frame(
        request_frame_for_test(R"({"version":1,"request_id":"req-alt-capabilities","method":"get_capabilities"})"));

    assert(capability_response == response_frame_for_test(
        R"({"version":1,"request_id":"req-alt-capabilities","ok":true,"result":{"capabilities":{"device":{"name":"nSealr ESP32-S3 USB Signer Scaffold","firmware":"nsealr-esp32-s3-usb-signer","hardware":"esp32-s3-devkitc-1"},"protocols":["nsealr.signing.v0","nsealr.serial-frame.v0"],"methods":["get_capabilities","get_signing_status","get_public_key","sign_event"],"transports":["usb-serial-jtag"],"signing_enabled":false,"requires_physical_approval":true}}})"));

    const std::string signing_status_response = nsealr::handle_serial_frame(
        request_frame_for_test(R"({"version":1,"request_id":"req-alt-signing-status","method":"get_signing_status"})"));

    assert(signing_status_response == response_frame_for_test(
        R"({"version":1,"request_id":"req-alt-signing-status","ok":true,"result":{"signing_status":{"signing_enabled":false,"missing_gates":["runtime_signing_feature","trusted_review_display","physical_approval_controls","unicode_review_rendering","key_provisioning","source_public_key_proof","secure_boot","flash_encryption","debug_lock","companion_signed_output_verification"],"development_accepted_gates":["parser_limits","trusted_review_display","physical_approval_controls","approval_digest_binding"]}}})"));

    const std::string public_key_response = nsealr::handle_serial_frame(
        request_frame_for_test(R"({"version":1,"request_id":"req-alt-pubkey","method":"get_public_key"})"));

    assert(public_key_response == response_frame_for_test(
        R"({"version":1,"request_id":"req-alt-pubkey","ok":true,"result":{"public_key":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"}})"));

    const std::string disabled_response = nsealr::handle_serial_frame(
        request_frame_for_test(R"({"version":1,"request_id":"req-alt-sign","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"alt"}}})"));

    assert(disabled_response == response_frame_for_test(
        R"({"version":1,"request_id":"req-alt-sign","ok":false,"error":{"code":"signing_disabled","message":"Signing is disabled until trusted review and physical approval are implemented.","retryable":false}})"));
}

void test_device_protocol_rejects_invalid_dynamic_request_metadata() {
    assert(nsealr::handle_serial_frame(
               request_frame_for_test(R"({"version":10,"request_id":"req-version-10","method":"get_public_key"})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));

    assert(nsealr::handle_serial_frame(
               request_frame_for_test(R"({"version":1,"request_id":"bad id","method":"get_public_key"})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));
}

void test_device_protocol_rejects_unknown_top_level_request_fields() {
    assert(nsealr::handle_serial_frame(
               request_frame_for_test(
                   R"({"version":1,"request_id":"invalid-top-level","method":"get_public_key","unexpected":true})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));
}

void test_device_protocol_rejects_params_for_parameterless_methods() {
    assert(nsealr::handle_serial_frame(
               request_frame_for_test(
                   R"({"version":1,"request_id":"invalid-capabilities-params","method":"get_capabilities","params":{}})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));

    assert(nsealr::handle_serial_frame(
               request_frame_for_test(
                   R"({"version":1,"request_id":"invalid-public-key-params","method":"get_public_key","params":{}})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));

    assert(nsealr::handle_serial_frame(
               request_frame_for_test(
                   R"({"version":1,"request_id":"invalid-signing-status-params","method":"get_signing_status","params":{}})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));
}

void test_device_protocol_rejects_invalid_sign_event_request_shape() {
    assert(nsealr::handle_serial_frame(
               request_frame_for_test(R"({"version":1,"request_id":"invalid-template-pubkey","method":"sign_event","params":{"event_template":{"pubkey":"0000000000000000000000000000000000000000000000000000000000000000","created_at":1710000000,"kind":1,"tags":[],"content":"unsafe template"}}})")) ==
           error_frame_for_test(R"({"error":"unsupported_request"})"));
}

void test_device_protocol_review_preserves_json_unicode_escapes() {
    nsealr::SerialFrameHandlingResult result = nsealr::handle_serial_frame_with_review_preview(
        request_frame_for_test(
            R"({"version":1,"request_id":"req-unicode-serial","method":"sign_event","params":{"event_template":{"created_at":1710000400,"kind":1,"tags":[["t","caf\u00e8"],["emoji","\uD83D\uDE00"]],"content":"caf\u00e8 \uD83D\uDE00"}}})"),
        nsealr_esp32::t_display_s3_review_limits());

    assert(result.response_frame == response_frame_for_test(
                                      R"({"version":1,"request_id":"req-unicode-serial","ok":false,"error":{"code":"signing_disabled","message":"Signing is disabled until trusted review and physical approval are implemented.","retryable":false}})"));
    assert(result.review_session.has_value());
    assert(result.review_session->current_frame().title == "Event");
    assert(!result.review_session->handle_button(nsealr::ReviewButton::Next).has_value());
    const nsealr::ReviewDisplayFrame content = result.review_session->current_frame();
    assert(content.title == "Content");
    assert(lines_contain(content.body_lines, "U+00E8"));
    assert(lines_contain(content.body_lines, "U+1F600"));
}

void test_t_display_s3_raster_has_stable_boot_and_review_pixels() {
    using namespace nsealr_esp32;

    assert(t_display_s3_boot_frame_color_for(0, 0) == kTDisplayS3ColorWhite);
    assert(t_display_s3_boot_frame_color_for(10, 10) == kTDisplayS3ColorBlue);
    assert(t_display_s3_boot_frame_color_for(20, 60) == kTDisplayS3ColorGreen);
    assert(t_display_s3_boot_frame_color_for(10, 60) == kTDisplayS3ColorBlack);

    nsealr::ReviewDisplayFrame frame;
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

    nsealr::ReviewDisplayFrame compact_frame;
    compact_frame.title = "Content";
    compact_frame.page_indicator = "Page 2/4";
    compact_frame.body_lines = std::vector<std::string>{"bytes: 281", "abcdef"};
    compact_frame.action_hint = "Next";
    compact_frame.body_line_styles = std::vector<nsealr::ReviewBodyLineStyle>{
        nsealr::ReviewBodyLineStyle::Meta,
        nsealr::ReviewBodyLineStyle::Value,
    };

    assert(t_display_s3_review_frame_color_for(compact_frame, 10, 42) == kTDisplayS3ColorGreen);
    assert(t_display_s3_review_frame_color_for(compact_frame, 11, 55) == kTDisplayS3ColorYellow);

    nsealr::ReviewDisplayFrame lowercase_frame;
    lowercase_frame.title = "Content";
    lowercase_frame.page_indicator = "Page 2/4";
    lowercase_frame.body_lines = std::vector<std::string>{"a"};
    lowercase_frame.action_hint = "Next";
    lowercase_frame.body_line_styles = std::vector<nsealr::ReviewBodyLineStyle>{
        nsealr::ReviewBodyLineStyle::Value,
    };

    assert(t_display_s3_review_frame_color_for(lowercase_frame, 11, 44) == kTDisplayS3ColorYellow);

    nsealr::ReviewDisplayFrame comma_frame;
    comma_frame.title = "Content";
    comma_frame.page_indicator = "Page 2/4";
    comma_frame.body_lines = std::vector<std::string>{","};
    comma_frame.action_hint = "Next";
    comma_frame.body_line_styles = std::vector<nsealr::ReviewBodyLineStyle>{
        nsealr::ReviewBodyLineStyle::Value,
    };

    assert(t_display_s3_review_frame_color_for(comma_frame, 12, 47) == kTDisplayS3ColorYellow);

    nsealr::ReviewDisplayFrame ascii_frame;
    ascii_frame.title = "ASCII";
    ascii_frame.page_indicator = "Page 1/1";
    ascii_frame.body_lines = {"^`"};
    ascii_frame.action_hint = "Next";
    assert(t_display_s3_review_frame_color_for(ascii_frame, 12, 44) == kTDisplayS3ColorWhite);
    assert(t_display_s3_review_frame_color_for(ascii_frame, 28, 46) == kTDisplayS3ColorWhite);
}

void test_t_display_s3_button_logic_classifies_debounced_short_and_long_presses() {
    nsealr_esp32::TDisplayS3ButtonState state;

    assert(!nsealr_esp32::update_t_display_s3_button_state(
                state,
                true,
                1000,
                14,
                nsealr::ReviewButton::Next,
                nsealr::ReviewButton::Approve)
                .has_value());
    assert(!nsealr_esp32::update_t_display_s3_button_state(
                state,
                false,
                1010,
                14,
                nsealr::ReviewButton::Next,
                nsealr::ReviewButton::Approve)
                .has_value());

    assert(!nsealr_esp32::update_t_display_s3_button_state(
                state,
                true,
                2000,
                14,
                nsealr::ReviewButton::Next,
                nsealr::ReviewButton::Approve)
                .has_value());
    const auto short_press = nsealr_esp32::update_t_display_s3_button_state(
        state,
        false,
        2040,
        14,
        nsealr::ReviewButton::Next,
        nsealr::ReviewButton::Approve);
    assert(short_press.has_value());
    assert(short_press->button == nsealr::ReviewButton::Next);
    assert(short_press->gpio == 14);
    assert(!short_press->long_press);

    nsealr_esp32::TDisplayS3ButtonState back_state;
    assert(!nsealr_esp32::update_t_display_s3_button_state(
                back_state,
                true,
                4000,
                0,
                nsealr::ReviewButton::Back,
                nsealr::ReviewButton::Reject)
                .has_value());
    const auto back_press = nsealr_esp32::update_t_display_s3_button_state(
        back_state,
        false,
        4040,
        0,
        nsealr::ReviewButton::Back,
        nsealr::ReviewButton::Reject);
    assert(back_press.has_value());
    assert(back_press->button == nsealr::ReviewButton::Back);
    assert(back_press->gpio == 0);
    assert(!back_press->long_press);

    assert(!nsealr_esp32::update_t_display_s3_button_state(
                state,
                true,
                3000,
                0,
                nsealr::ReviewButton::Back,
                nsealr::ReviewButton::Reject)
                .has_value());
    const auto long_press = nsealr_esp32::update_t_display_s3_button_state(
        state,
        false,
        3800,
        0,
        nsealr::ReviewButton::Back,
        nsealr::ReviewButton::Reject);
    assert(long_press.has_value());
    assert(long_press->button == nsealr::ReviewButton::Reject);
    assert(long_press->gpio == 0);
    assert(long_press->long_press);

    nsealr_esp32::TDisplayS3ButtonState approve_state;
    assert(!nsealr_esp32::update_t_display_s3_button_state(
                approve_state,
                true,
                5000,
                14,
                nsealr::ReviewButton::Next,
                nsealr::ReviewButton::Approve)
                .has_value());
    const auto approve_press = nsealr_esp32::update_t_display_s3_button_state(
        approve_state,
        false,
        5800,
        14,
        nsealr::ReviewButton::Next,
        nsealr::ReviewButton::Approve);
    assert(approve_press.has_value());
    assert(approve_press->button == nsealr::ReviewButton::Approve);
    assert(approve_press->gpio == 14);
    assert(approve_press->long_press);
}

void test_t_display_s3_status_frames_keep_non_signing_copy_stable() {
    const nsealr::ReviewDisplayFrame ready = nsealr_esp32::build_t_display_s3_ready_frame();
    assert(ready.title == "Ready");
    assert(ready.page_indicator == "No request");
    assert(ready.body_lines == std::vector<std::string>({
                                   "USB signer",
                                   "Send sign_event",
                                   "Signing disabled",
                               }));
    assert(ready.action_hint == "Waiting");

    const nsealr::ReviewDisplayFrame approved =
        nsealr_esp32::build_t_display_s3_review_decision_frame(true);
    assert(approved.title == "Review OK");
    assert(approved.page_indicator == "Closed");
    assert(approved.body_lines == std::vector<std::string>({
                                      "Not signed",
                                      "Signing disabled",
                                      "Send new request",
                                  }));
    assert(approved.action_hint == "Waiting");

    const nsealr::ReviewDisplayFrame rejected =
        nsealr_esp32::build_t_display_s3_review_decision_frame(false);
    assert(rejected.title == "Rejected");
    assert(rejected.page_indicator == "Closed");
    assert(rejected.body_lines == approved.body_lines);
    assert(rejected.action_hint == "Waiting");

    const nsealr::ReviewDisplayFrame timeout = nsealr_esp32::build_t_display_s3_review_timeout_frame();
    assert(timeout.title == "Review Timeout");
    assert(timeout.page_indicator == "Expired");
    assert(timeout.body_lines == approved.body_lines);
    assert(timeout.action_hint == "Waiting");

    const nsealr::ReviewDisplayFrame error = nsealr_esp32::build_t_display_s3_request_error_frame();
    assert(error.title == "Request Error");
    assert(error.page_indicator == "Rejected");
    assert(error.body_lines == approved.body_lines);
    assert(error.action_hint == "Waiting");
}

void test_t_display_s3_serial_input_drains_after_overlong_frame() {
    nsealr_esp32::TDisplayS3SerialInput input;
    for (char ch : std::string("12345678")) {
        const nsealr_esp32::TDisplayS3SerialInputEvent event =
            nsealr_esp32::update_t_display_s3_serial_input(input, ch, 8);
        assert(event.kind == nsealr_esp32::TDisplayS3SerialInputEventKind::None);
    }

    const nsealr_esp32::TDisplayS3SerialInputEvent overlong =
        nsealr_esp32::update_t_display_s3_serial_input(input, '9', 8);
    assert(overlong.kind == nsealr_esp32::TDisplayS3SerialInputEventKind::OverlongFrame);
    assert(overlong.line.empty());

    for (char ch : std::string("tail")) {
        const nsealr_esp32::TDisplayS3SerialInputEvent event =
            nsealr_esp32::update_t_display_s3_serial_input(input, ch, 8);
        assert(event.kind == nsealr_esp32::TDisplayS3SerialInputEventKind::None);
    }
    const nsealr_esp32::TDisplayS3SerialInputEvent drained =
        nsealr_esp32::update_t_display_s3_serial_input(input, '\n', 8);
    assert(drained.kind == nsealr_esp32::TDisplayS3SerialInputEventKind::None);

    nsealr_esp32::TDisplayS3SerialInputEvent ready;
    for (char ch : std::string("ok\r\n")) {
        ready = nsealr_esp32::update_t_display_s3_serial_input(input, ch, 8);
    }
    assert(ready.kind == nsealr_esp32::TDisplayS3SerialInputEventKind::FrameReady);
    assert(ready.line == "ok\n");
}

}  // namespace

int main() {
    test_serial_frame_round_trip();
    test_serial_frame_rejections();
    test_serial_frame_rejects_shared_invalid_vectors();
    test_qr_envelope_decodes_shared_vector();
    test_animated_qr_envelope_decodes_shared_vector();
    test_qr_envelope_encodes_signed_response_vectors_without_signing();
    test_qr_envelope_parses_sign_event_request_metadata();
    test_qr_envelope_extracts_event_template_boundary();
    test_qr_envelope_parses_event_template_fields();
    test_qr_signing_request_tolerates_escaped_event_content();
    test_qr_signing_request_preserves_json_unicode_escapes();
    test_qr_envelope_rejections();
    test_qr_envelope_rejects_shared_invalid_qr_vectors();
    test_animated_qr_envelope_rejections();
    test_qr_envelope_encoder_rejections();
    test_qr_limits_match_shared_profile();
    test_nip19_nsec_decoder_matches_shared_vector();
    test_seedqr_decoders_match_shared_vector();
    test_bip39_english_mnemonic_parser_matches_shared_vector();
    test_stateless_session_keyring_accepts_parsed_key_sources();
    test_stateless_session_keyring_clear_wipes_active_sources();
    test_session_key_source_value_semantics_wipe_sensitive_material();
    test_stateless_session_keyring_rejects_invalid_sources();
    test_session_source_generation_uses_ram_only_source_boundary();
    test_session_source_generation_rejects_invalid_entropy();
    test_session_source_backup_review_matches_shared_danger_zone_vectors();
    test_session_source_backup_payload_matches_shared_secret_payloads();
    test_session_source_backup_flow_reveals_only_after_local_approval();
    test_policy_change_review_matches_shared_vector();
    test_policy_change_review_flow_requires_device_approval();
    test_policy_change_review_rejects_companion_authority_or_secret_material();
    test_session_source_qr_parses_ram_only_sources();
    test_session_source_qr_rejects_invalid_inputs();
    test_session_source_qr_import_flow_loads_only_after_review_approval();
    test_session_source_qr_import_flow_rejects_without_keyring_load();
    test_compact_seedqr_import_flow_loads_after_review_approval();
    test_session_import_review_hides_secret_material();
    test_session_import_flow_requires_local_approval_before_loading_keyring();
    test_session_import_flow_rejection_does_not_load_keyring();
    test_session_import_flow_blocks_early_or_nonterminal_approval();
    test_session_account_selection_binds_qr_review_identity_without_derivation();
    test_session_account_selection_validates_source_route_and_recovery_shape();
    test_session_account_selection_does_not_satisfy_public_key_proof_gate();
    test_session_account_selection_consumes_shared_source_public_key_proof_metadata_without_derivation();
    test_qr_signing_request_rejections();
    test_qr_signing_request_rejects_shared_invalid_request_vectors();
    test_qr_review_pages_match_shared_basic_vector();
    test_qr_trusted_review_request_matches_shared_basic_vector();
    test_qr_review_pages_match_shared_tagged_vector();
    test_qr_trusted_review_request_matches_shared_tagged_vector();
    test_qr_review_binds_configured_signer_identity();
    test_qr_display_review_pages_show_full_tag_values_without_ellipsis();
    test_qr_display_review_pages_group_logical_sections_with_compact_styles();
    test_qr_display_review_pages_match_shared_detail_page_vectors();
    test_qr_display_review_pages_escape_non_ascii_for_display_safety();
    test_qr_display_review_pages_render_control_escapes_visibly();
    test_qr_display_review_pages_preserve_supported_ascii_punctuation();
    test_qr_display_review_pages_split_full_long_content_without_ellipsis();
    test_qr_display_review_pages_use_scroll_line_indicators_for_long_sections();
    test_qr_trusted_review_session_binds_qr_digest_and_navigation();
    test_qr_review_flow_drives_scanned_qr_without_signing_backend();
    test_qr_review_flow_binds_selected_session_account_identity();
    test_qr_review_flow_rejects_unsafe_scanned_qr();
    test_qr_review_flow_transcript_records_display_and_approval_steps();
    test_qr_review_flow_transcript_records_early_rejection();
    test_qr_review_flow_transcript_matches_shared_detail_scroll_vector();
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
    test_serial_review_binds_configured_signer_identity();
    test_serial_review_session_uses_two_axis_navigation_for_scroll_windows();
    test_serial_review_io_flow_drives_request_display_and_buttons_without_signing();
    test_signing_policy_requires_every_runtime_gate_before_enablement();
    test_device_protocol_reports_scaffold_capabilities();
    test_device_protocol_rejects_signing_while_disabled();
    test_device_protocol_exposes_review_frame_before_disabled_signing_response();
    test_device_protocol_exposes_review_session_for_manual_display_navigation();
    test_device_protocol_reports_development_public_key();
    test_device_protocol_binds_configured_signer_identity();
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
