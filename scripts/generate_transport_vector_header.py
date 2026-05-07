#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import hashlib
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


def base64url_json(value: dict) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return encoded.rstrip("=")


def serial_frame(frame_type: str, payload_base64url: str) -> str:
    checksum = hashlib.sha256(f"{frame_type}:{payload_base64url}".encode("utf-8")).hexdigest()[:16]
    return f"nseal1f:{frame_type}:{payload_base64url}:{checksum}\n"


def cpp_review_action(action: str) -> str:
    if action == "next":
        return "nostrseal::ReviewPageAction::Next"
    if action == "approve_or_reject":
        return "nostrseal::ReviewPageAction::ApproveOrReject"
    raise ValueError(f"unsupported review page action: {action}")


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


def main() -> int:
    specs = default_specs_dir()
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
    public_key_vector = json.loads(
        (specs / "vectors/devices/esp32-s3-get-public-key-dev.json").read_text(encoding="utf-8")
    )
    basic_review_screen = json.loads(
        (specs / "vectors/review-screens/kind-1-basic.json").read_text(encoding="utf-8")
    )
    tagged_review_screen = json.loads(
        (specs / "vectors/review-screens/kind-1-tags.json").read_text(encoding="utf-8")
    )
    capability_request_payload = base64url_json(capability_vector["request"])
    capability_response_payload = base64url_json(capability_vector["response"])
    sign_event_request_payload = base64url_json(sign_event_disabled_vector["request"])
    sign_event_disabled_response_payload = base64url_json(sign_event_disabled_vector["response"])
    public_key_request_payload = base64url_json(public_key_vector["request"])
    public_key_response_payload = base64url_json(public_key_vector["response"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        "\n".join(
            [
                "#pragma once",
                "",
                '#include "nostrseal/trusted_review.hpp"',
                "",
                "namespace nostrseal::test_vectors {",
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
                f"constexpr const char* kPublicKeyRequestPayloadBase64Url = {cpp_string(public_key_request_payload)};",
                f"constexpr const char* kPublicKeyRequestFrame = {cpp_string(serial_frame('request', public_key_request_payload))};",
                f"constexpr const char* kPublicKeyResponsePayloadBase64Url = {cpp_string(public_key_response_payload)};",
                f"constexpr const char* kPublicKeyResponseFrame = {cpp_string(serial_frame('response', public_key_response_payload))};",
                f"constexpr const char* kBasicReviewScreenApprovalDigest = {cpp_string(basic_review_screen['screen_review']['approval_digest'])};",
                f"constexpr const char* kTaggedReviewScreenApprovalDigest = {cpp_string(tagged_review_screen['screen_review']['approval_digest'])};",
                "",
                *trusted_review_factory("basic_trusted_review_request", basic_review_screen["screen_review"]),
                "",
                *trusted_review_factory("tagged_trusted_review_request", tagged_review_screen["screen_review"]),
                "}  // namespace nostrseal::test_vectors",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
