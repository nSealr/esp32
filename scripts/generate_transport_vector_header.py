#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPECS = ROOT.parent / "specs"
OUT = ROOT / "build/host_core/transport_vector.hpp"


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


def main() -> int:
    vector = json.loads(
        (SPECS / "vectors/transports/serial-frame-request-kind-1-basic.json").read_text(encoding="utf-8")
    )
    capability_vector = json.loads(
        (SPECS / "vectors/devices/esp32-s3-capabilities-scaffold.json").read_text(encoding="utf-8")
    )
    capability_request_payload = base64url_json(capability_vector["request"])
    capability_response_payload = base64url_json(capability_vector["response"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        "\n".join(
            [
                "#pragma once",
                "",
                "namespace nostrseal::test_vectors {",
                f"constexpr const char* kSerialFrameType = {cpp_string(vector['type'])};",
                f"constexpr const char* kSerialFramePayloadBase64Url = {cpp_string(vector['payload_base64url'])};",
                f"constexpr const char* kSerialFrame = {cpp_string(vector['frame'])};",
                f"constexpr const char* kCapabilityRequestPayloadBase64Url = {cpp_string(capability_request_payload)};",
                f"constexpr const char* kCapabilityRequestFrame = {cpp_string(serial_frame('request', capability_request_payload))};",
                f"constexpr const char* kCapabilityResponsePayloadBase64Url = {cpp_string(capability_response_payload)};",
                f"constexpr const char* kCapabilityResponseFrame = {cpp_string(serial_frame('response', capability_response_payload))};",
                "}  // namespace nostrseal::test_vectors",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
