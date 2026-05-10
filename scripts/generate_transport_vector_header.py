#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/host_core/transport_vector.hpp"


def default_specs_dir() -> Path:
    sibling = ROOT.parent / "specs"
    if sibling.exists():
        return sibling
    return ROOT / "tests/fixtures/specs"


def cpp_string(value: str) -> str:
    return json.dumps(value)


def cpp_identifier(value: str) -> str:
    identifier = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not identifier or identifier[0].isdigit():
        identifier = f"_{identifier}"
    return identifier


def base64url_json(value: dict) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return encoded.rstrip("=")


def compact_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def serial_frame(frame_type: str, payload_base64url: str) -> str:
    checksum = hashlib.sha256(f"{frame_type}:{payload_base64url}".encode("utf-8")).hexdigest()[:16]
    return f"nseal1f:{frame_type}:{payload_base64url}:{checksum}\n"


def cpp_review_action(action: str) -> str:
    if action == "next":
        return "nostrseal::ReviewPageAction::Next"
    if action == "approve_or_reject":
        return "nostrseal::ReviewPageAction::ApproveOrReject"
    raise ValueError(f"unsupported review page action: {action}")


def cpp_review_button(button: str) -> str:
    if button == "next":
        return "nostrseal::ReviewButton::Next"
    if button == "approve":
        return "nostrseal::ReviewButton::Approve"
    if button == "reject":
        return "nostrseal::ReviewButton::Reject"
    raise ValueError(f"unsupported review button: {button}")


def cpp_review_body_style(style: str) -> str:
    if style == "normal":
        return "nostrseal::ReviewBodyLineStyle::Normal"
    if style == "meta":
        return "nostrseal::ReviewBodyLineStyle::Meta"
    if style == "value":
        return "nostrseal::ReviewBodyLineStyle::Value"
    raise ValueError(f"unsupported review body line style: {style}")


def cpp_optional_bool(value: bool | None) -> str:
    if value is None:
        return "std::nullopt"
    if value is True:
        return "true"
    return "false"


def trusted_review_factory(name: str, screen_review: dict) -> list[str]:
    lines = [
        f"inline nostrseal::TrustedReviewRequest {name}() {{",
        "    return nostrseal::TrustedReviewRequest{",
        f"        {cpp_string(screen_review['request_id'])},",
        f"        {cpp_string(screen_review['approval_digest'])},",
        "        {",
    ]
    for page in screen_review["pages"]:
        body_lines = ", ".join(cpp_string(line) for line in page["lines"])
        lines.extend(
            [
                "            nostrseal::TrustedReviewPage{",
                f"                {cpp_string(page['title'])},",
                f"                {{{body_lines}}},",
                f"                {cpp_review_action(page['action'])},",
                "            },",
            ]
        )
    lines.extend(
        [
            "        },",
            "    };",
            "}",
        ]
    )
    return lines


def qr_review_buttons_factory(name: str, buttons: list[str]) -> list[str]:
    button_values = ", ".join(cpp_review_button(button) for button in buttons)
    return [
        f"inline std::vector<nostrseal::ReviewButton> {name}() {{",
        f"    return {{{button_values}}};",
        "}",
    ]


def qr_review_transcript_factory(name: str, transcript: list[dict]) -> list[str]:
    lines = [
        f"inline std::vector<nostrseal::QrReviewTranscriptStep> {name}() {{",
        "    return {",
    ]
    for step in transcript:
        frame = step["frame"]
        body_lines = ", ".join(cpp_string(line) for line in frame["body_lines"])
        lines.extend(
            [
                "        nostrseal::QrReviewTranscriptStep{",
                "            nostrseal::ReviewDisplayFrame{",
                f"                {cpp_string(frame['title'])},",
                f"                {cpp_string(frame['page_indicator'])},",
                f"                {{{body_lines}}},",
                f"                {cpp_string(frame['action_hint'])},",
                "            },",
                f"            {cpp_review_button(step['button'])},",
                f"            {cpp_optional_bool(step['decision'])},",
                f"            {str(step['approved_for_signing']).lower()},",
                "        },",
            ]
        )
    lines.extend(
        [
            "    };",
            "}",
        ]
    )
    return lines


def review_display_limits_factory(name: str, limits: dict) -> list[str]:
    return [
        f"inline nostrseal::ReviewDisplayLimits {name}() {{",
        "    return nostrseal::ReviewDisplayLimits{",
        f"        .max_title_chars = {limits['max_title_chars']},",
        f"        .max_body_lines = {limits['max_body_lines']},",
        f"        .max_line_chars = {limits['max_line_chars']},",
        f"        .max_compact_body_lines = {limits.get('max_compact_body_lines', 9)},",
        f"        .max_compact_line_chars = {limits.get('max_compact_line_chars', 48)},",
        "    };",
        "}",
    ]


def review_display_frame_factory(name: str, frame: dict) -> list[str]:
    body_lines = ", ".join(cpp_string(line) for line in frame["body_lines"])
    return [
        f"inline nostrseal::ReviewDisplayFrame {name}() {{",
        "    return nostrseal::ReviewDisplayFrame{",
        f"        {cpp_string(frame['title'])},",
        f"        {cpp_string(frame['page_indicator'])},",
        f"        {{{body_lines}}},",
        f"        {cpp_string(frame['action_hint'])},",
        "    };",
        "}",
    ]


def review_display_vector_factories(vectors: list[dict]) -> list[str]:
    lines: list[str] = []
    for vector in vectors:
        base_name = cpp_identifier(vector["name"])
        lines.extend(review_display_limits_factory(f"{base_name}_display_limits", vector["limits"]))
        lines.append("")
        lines.extend(review_display_frame_factory(f"{base_name}_display_frame", vector["frame"]))
        lines.append("")
    return lines


def trusted_review_page_initializer(page: dict) -> list[str]:
    body_lines = ", ".join(cpp_string(line) for line in page["lines"])
    styles = ", ".join(cpp_review_body_style(style) for style in page.get("body_line_styles", []))
    return [
        "            nostrseal::TrustedReviewPage{",
        f"                {cpp_string(page['title'])},",
        f"                {{{body_lines}}},",
        f"                {cpp_review_action(page['action'])},",
        f"                {cpp_string(page.get('page_indicator', ''))},",
        f"                {{{styles}}},",
        f"                {cpp_string(page.get('logical_page_id', ''))},",
        "            },",
    ]


def review_detail_page_vector_factories(vectors: list[dict], reviews_by_name: dict[str, dict]) -> list[str]:
    lines = [
        "struct ReviewDetailPageVector {",
        "    const char* name;",
        "    const char* request_json;",
        "    const char* approval_digest;",
        "    nostrseal::ReviewDisplayLimits limits;",
        "    std::vector<nostrseal::TrustedReviewPage> pages;",
        "};",
        "",
        "inline std::vector<ReviewDetailPageVector> review_detail_page_vectors() {",
        "    return {",
    ]
    for vector in vectors:
        source = reviews_by_name[vector["source_review_vector"]]
        lines.extend(
            [
                "        ReviewDetailPageVector{",
                f"            {cpp_string(vector['name'])},",
                f"            {cpp_string(compact_json(source['request']))},",
                f"            {cpp_string(vector['approval_digest'])},",
                "            nostrseal::ReviewDisplayLimits{",
                f"                .max_title_chars = {vector['limits']['max_title_chars']},",
                f"                .max_body_lines = {vector['limits']['max_body_lines']},",
                f"                .max_line_chars = {vector['limits']['max_line_chars']},",
                f"                .max_compact_body_lines = {vector['limits']['max_compact_body_lines']},",
                f"                .max_compact_line_chars = {vector['limits']['max_compact_line_chars']},",
                "            },",
                "            {",
            ]
        )
        for page in vector["pages"]:
            lines.extend(trusted_review_page_initializer(page))
        lines.extend(
            [
                "            },",
                "        },",
            ]
        )
    lines.extend(
        [
            "    };",
            "}",
        ]
    )
    return lines


def limit_constants_factory(limits: dict) -> list[str]:
    return [
        f"constexpr std::size_t kMaxRequestIdLength = {limits['max_request_id_length']};",
        f"constexpr std::size_t kMaxDecodedRequestJsonBytes = {limits['max_decoded_request_json_bytes']};",
        f"constexpr std::size_t kMaxStaticQrDecodedJsonBytes = {limits['max_static_qr_decoded_json_bytes']};",
        f"constexpr std::size_t kMaxSerialFrameBytes = {limits['max_serial_frame_bytes']};",
        f"constexpr std::size_t kMaxContentUtf8Bytes = {limits['max_content_utf8_bytes']};",
        f"constexpr std::size_t kMaxTagCount = {limits['max_tag_count']};",
        f"constexpr std::size_t kMaxTagFieldsPerTag = {limits['max_tag_fields_per_tag']};",
        f"constexpr std::size_t kMaxTagFieldUtf8Bytes = {limits['max_tag_field_utf8_bytes']};",
        f"constexpr std::size_t kMaxTotalTagUtf8Bytes = {limits['max_total_tag_utf8_bytes']};",
        f"constexpr std::uint64_t kMaxSafeInteger = {limits['max_safe_integer']}ULL;",
    ]


def invalid_signing_request_factory(vectors: list[dict]) -> list[str]:
    lines = [
        "struct InvalidSigningRequestVector {",
        "    const char* name;",
        "    const char* request_json;",
        "};",
        "",
        "inline std::vector<InvalidSigningRequestVector> invalid_signing_request_vectors() {",
        "    return {",
    ]
    for vector in vectors:
        lines.append(
            f"        InvalidSigningRequestVector{{{cpp_string(vector['name'])}, {cpp_string(compact_json(vector['request']))}}},"
        )
    lines.extend(
        [
            "    };",
            "}",
        ]
    )
    return lines


def main() -> int:
    specs = default_specs_dir()
    limits = json.loads((specs / "vectors/limits/nseal-v0.json").read_text(encoding="utf-8"))["limits"]
    vector = json.loads(
        (specs / "vectors/transports/serial-frame-request-kind-1-basic.json").read_text(encoding="utf-8")
    )
    qr_vector = json.loads((specs / "vectors/transports/qr-envelope-kind-1-basic.json").read_text(encoding="utf-8"))
    capability_vector = json.loads(
        (specs / "vectors/devices/esp32-s3-capabilities-scaffold.json").read_text(encoding="utf-8")
    )
    sign_event_disabled_vector = json.loads(
        (specs / "vectors/devices/esp32-s3-sign-event-disabled.json").read_text(encoding="utf-8")
    )
    signing_status_vector = json.loads(
        (specs / "vectors/devices/esp32-s3-signing-status-disabled.json").read_text(encoding="utf-8")
    )
    public_key_vector = json.loads(
        (specs / "vectors/devices/esp32-s3-get-public-key-dev.json").read_text(encoding="utf-8")
    )
    basic_review_screen = json.loads(
        (specs / "vectors/review-screens/kind-1-basic.json").read_text(encoding="utf-8")
    )
    tagged_review_screen = json.loads(
        (specs / "vectors/review-screens/kind-1-tags.json").read_text(encoding="utf-8")
    )
    basic_review_approve_transcript = json.loads(
        (specs / "vectors/review-transcripts/kind-1-basic-approve.json").read_text(encoding="utf-8")
    )
    basic_review_reject_transcript = json.loads(
        (specs / "vectors/review-transcripts/kind-1-basic-reject.json").read_text(encoding="utf-8")
    )
    review_display_frame_vectors = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((specs / "vectors/review-display-frames").glob("*.json"))
    ]
    review_detail_page_vectors = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((specs / "vectors/review-detail-pages").glob("*.json"))
    ]
    review_vectors = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((specs / "vectors/review").glob("*.json"))
    ]
    reviews_by_name = {vector["name"]: vector for vector in review_vectors}
    display_frames_by_name = {vector["name"]: vector for vector in review_display_frame_vectors}
    long_content_display_frame = display_frames_by_name["kind-1-long-content-page-1-20x3"]
    invalid_vectors = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((specs / "vectors/invalid").glob("*.json"))
    ]
    invalid_by_name = {vector["name"]: vector for vector in invalid_vectors}
    invalid_signing_requests = [
        vector for vector in invalid_vectors if vector.get("category") == "signing-request"
    ]
    capability_request_payload = base64url_json(capability_vector["request"])
    capability_response_payload = base64url_json(capability_vector["response"])
    sign_event_request_payload = base64url_json(sign_event_disabled_vector["request"])
    sign_event_disabled_response_payload = base64url_json(sign_event_disabled_vector["response"])
    signing_status_request_payload = base64url_json(signing_status_vector["request"])
    signing_status_response_payload = base64url_json(signing_status_vector["response"])
    public_key_request_payload = base64url_json(public_key_vector["request"])
    public_key_response_payload = base64url_json(public_key_vector["response"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        "\n".join(
            [
                "#pragma once",
                "",
                "#include <cstddef>",
                "#include <cstdint>",
                "#include <optional>",
                "#include <string>",
                "#include <vector>",
                "",
                '#include "nostrseal/qr_review_flow.hpp"',
                '#include "nostrseal/trusted_review.hpp"',
                "",
                "namespace nostrseal::test_vectors {",
                *limit_constants_factory(limits),
                "",
                f"constexpr const char* kSerialFrameType = {cpp_string(vector['type'])};",
                f"constexpr const char* kSerialFramePayloadBase64Url = {cpp_string(vector['payload_base64url'])};",
                f"constexpr const char* kSerialFrame = {cpp_string(vector['frame'])};",
                f"constexpr const char* kQrEnvelopeKind1BasicPayloadBase64Url = {cpp_string(qr_vector['payload_base64url'])};",
                f"constexpr const char* kQrEnvelopeKind1Basic = {cpp_string(qr_vector['envelope'])};",
                f"constexpr const char* kCapabilityRequestPayloadBase64Url = {cpp_string(capability_request_payload)};",
                f"constexpr const char* kCapabilityRequestFrame = {cpp_string(serial_frame('request', capability_request_payload))};",
                f"constexpr const char* kCapabilityResponsePayloadBase64Url = {cpp_string(capability_response_payload)};",
                f"constexpr const char* kCapabilityResponseFrame = {cpp_string(serial_frame('response', capability_response_payload))};",
                f"constexpr const char* kSignEventRequestPayloadBase64Url = {cpp_string(sign_event_request_payload)};",
                f"constexpr const char* kSignEventRequestFrame = {cpp_string(serial_frame('request', sign_event_request_payload))};",
                f"constexpr const char* kSignEventDisabledResponsePayloadBase64Url = {cpp_string(sign_event_disabled_response_payload)};",
                f"constexpr const char* kSignEventDisabledResponseFrame = {cpp_string(serial_frame('response', sign_event_disabled_response_payload))};",
                f"constexpr const char* kSigningStatusRequestPayloadBase64Url = {cpp_string(signing_status_request_payload)};",
                f"constexpr const char* kSigningStatusRequestFrame = {cpp_string(serial_frame('request', signing_status_request_payload))};",
                f"constexpr const char* kSigningStatusResponsePayloadBase64Url = {cpp_string(signing_status_response_payload)};",
                f"constexpr const char* kSigningStatusResponseFrame = {cpp_string(serial_frame('response', signing_status_response_payload))};",
                f"constexpr const char* kPublicKeyRequestPayloadBase64Url = {cpp_string(public_key_request_payload)};",
                f"constexpr const char* kPublicKeyRequestFrame = {cpp_string(serial_frame('request', public_key_request_payload))};",
                f"constexpr const char* kPublicKeyResponsePayloadBase64Url = {cpp_string(public_key_response_payload)};",
                f"constexpr const char* kPublicKeyResponseFrame = {cpp_string(serial_frame('response', public_key_response_payload))};",
                f"constexpr const char* kBasicReviewScreenApprovalDigest = {cpp_string(basic_review_screen['screen_review']['approval_digest'])};",
                f"constexpr const char* kTaggedReviewScreenApprovalDigest = {cpp_string(tagged_review_screen['screen_review']['approval_digest'])};",
                f"constexpr const char* kInvalidQrEnvelopeMalformed = {cpp_string(invalid_by_name['qr-envelope-malformed']['envelope'])};",
                f"constexpr const char* kInvalidQrEnvelopeOversized = {cpp_string(invalid_by_name['qr-envelope-oversized']['envelope'])};",
                f"constexpr const char* kInvalidQrEnvelopePadded = {cpp_string(invalid_by_name['qr-envelope-padded']['envelope'])};",
                f"constexpr const char* kInvalidQrEnvelopeInvalidUtf8 = {cpp_string(invalid_by_name['qr-envelope-invalid-utf8']['envelope'])};",
                f"constexpr const char* kInvalidSerialFrameOversized = {cpp_string(invalid_by_name['serial-frame-oversized']['frame'])};",
                f"constexpr const char* kInvalidSerialFrameChecksumMismatch = {cpp_string(invalid_by_name['serial-frame-checksum-mismatch']['frame'])};",
                f"constexpr const char* kInvalidSerialFrameMalformedPayload = {cpp_string(invalid_by_name['serial-frame-malformed-payload']['frame'])};",
                "",
                *invalid_signing_request_factory(invalid_signing_requests),
                "",
                *review_display_limits_factory(
                    "long_content_display_limits_20x3",
                    long_content_display_frame["limits"],
                ),
                "",
                *review_display_frame_factory(
                    "long_content_display_frame_20x3",
                    long_content_display_frame["frame"],
                ),
                "",
                *review_display_vector_factories(review_display_frame_vectors),
                *review_detail_page_vector_factories(review_detail_page_vectors, reviews_by_name),
                "",
                *trusted_review_factory("basic_trusted_review_request", basic_review_screen["screen_review"]),
                "",
                *trusted_review_factory("tagged_trusted_review_request", tagged_review_screen["screen_review"]),
                "",
                *qr_review_buttons_factory(
                    "basic_qr_review_approve_buttons",
                    basic_review_approve_transcript["buttons"],
                ),
                "",
                *qr_review_transcript_factory(
                    "basic_qr_review_approve_transcript",
                    basic_review_approve_transcript["transcript"],
                ),
                "",
                *qr_review_buttons_factory(
                    "basic_qr_review_reject_buttons",
                    basic_review_reject_transcript["buttons"],
                ),
                "",
                *qr_review_transcript_factory(
                    "basic_qr_review_reject_transcript",
                    basic_review_reject_transcript["transcript"],
                ),
                "}  // namespace nostrseal::test_vectors",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
