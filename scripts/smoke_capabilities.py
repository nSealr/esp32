#!/usr/bin/env python3
"""ESP32-S3 serial capability smoke test.

This script is intentionally hardware-only. Unit tests cover frame generation
and log filtering; the serial dependency is imported only when the smoke test
actually opens a board port.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "nseal1f:"


def default_specs_dir() -> Path:
    sibling = ROOT.parent / "specs"
    if sibling.exists():
        return sibling
    return ROOT / "tests/fixtures/specs"


DEFAULT_SPECS = default_specs_dir()
DYNAMIC_SMOKE_REQUEST_IDS = {
    "capabilities": "dynamic-smoke-capabilities",
    "signing_status": "dynamic-smoke-signing-status",
    "public_key": "dynamic-smoke-public-key",
    "signing_disabled": "dynamic-smoke-sign-event-disabled",
    "post_overlong_recovery": "post-overlong-recovery",
}
INVALID_METADATA_VECTOR_NAMES = (
    "serial-frame-request-invalid-version",
    "serial-frame-request-invalid-request-id",
)
MALFORMED_TRANSPORT_VECTOR_NAMES = (
    "serial-frame-checksum-mismatch",
    "serial-frame-malformed-payload",
    "serial-frame-unsupported-type",
)
OVERLONG_TRANSPORT_VECTOR_NAMES = ("serial-frame-oversized",)
UNSUPPORTED_REQUEST_ERROR = {"error": "unsupported_request"}
MALFORMED_FRAME_ERROR = {"error": "malformed_frame"}
OVERLONG_FRAME_ERROR = {"error": "overlong_frame"}


def base64url_json(value: dict) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return encoded.rstrip("=")


def encode_serial_frame(frame_type: str, payload_base64url: str) -> str:
    checksum = hashlib.sha256(f"{frame_type}:{payload_base64url}".encode("utf-8")).hexdigest()[:16]
    return f"{PREFIX}{frame_type}:{payload_base64url}:{checksum}\n"


def load_capability_frames(specs_dir: Path = DEFAULT_SPECS) -> tuple[str, str]:
    vector = load_capability_vector(specs_dir)
    return vector_frames(vector)


def load_signing_disabled_frames(specs_dir: Path = DEFAULT_SPECS) -> tuple[str, str]:
    vector = load_signing_disabled_vector(specs_dir)
    return vector_frames(vector)


def load_public_key_frames(specs_dir: Path = DEFAULT_SPECS) -> tuple[str, str]:
    vector = load_public_key_vector(specs_dir)
    return vector_frames(vector)


def load_signing_status_frames(specs_dir: Path = DEFAULT_SPECS) -> tuple[str, str]:
    vector = load_signing_status_vector(specs_dir)
    return vector_frames(vector)


def load_capability_vector(specs_dir: Path = DEFAULT_SPECS) -> dict:
    return json.loads(
        (specs_dir / "vectors/devices/esp32-s3-capabilities-scaffold.json").read_text(encoding="utf-8")
    )


def load_signing_disabled_vector(specs_dir: Path = DEFAULT_SPECS) -> dict:
    return json.loads(
        (specs_dir / "vectors/devices/esp32-s3-sign-event-disabled.json").read_text(encoding="utf-8")
    )


def load_public_key_vector(specs_dir: Path = DEFAULT_SPECS) -> dict:
    return json.loads(
        (specs_dir / "vectors/devices/esp32-s3-get-public-key-dev.json").read_text(encoding="utf-8")
    )


def load_signing_status_vector(specs_dir: Path = DEFAULT_SPECS) -> dict:
    return json.loads(
        (specs_dir / "vectors/devices/esp32-s3-signing-status-disabled.json").read_text(encoding="utf-8")
    )


def vector_with_request_id(vector: dict, request_id: str) -> dict:
    updated = copy.deepcopy(vector)
    updated["request"]["request_id"] = request_id
    updated["response"]["request_id"] = request_id
    return updated


def load_dynamic_request_id_frames(specs_dir: Path = DEFAULT_SPECS) -> list[tuple[str, str]]:
    vectors = [
        vector_with_request_id(load_capability_vector(specs_dir), DYNAMIC_SMOKE_REQUEST_IDS["capabilities"]),
        vector_with_request_id(load_signing_status_vector(specs_dir), DYNAMIC_SMOKE_REQUEST_IDS["signing_status"]),
        vector_with_request_id(load_public_key_vector(specs_dir), DYNAMIC_SMOKE_REQUEST_IDS["public_key"]),
        vector_with_request_id(load_signing_disabled_vector(specs_dir), DYNAMIC_SMOKE_REQUEST_IDS["signing_disabled"]),
    ]
    return [vector_frames(vector) for vector in vectors]


def load_post_overlong_recovery_frames(specs_dir: Path = DEFAULT_SPECS) -> tuple[str, str]:
    vector = vector_with_request_id(
        load_capability_vector(specs_dir),
        DYNAMIC_SMOKE_REQUEST_IDS["post_overlong_recovery"],
    )
    return vector_frames(vector)


def load_invalid_metadata_frames(specs_dir: Path = DEFAULT_SPECS) -> list[tuple[str, str]]:
    error_payload = base64url_json(UNSUPPORTED_REQUEST_ERROR)
    expected_error_frame = encode_serial_frame("error", error_payload)
    invalid_dir = specs_dir / "vectors" / "invalid"
    frames: list[tuple[str, str]] = []
    for vector_name in INVALID_METADATA_VECTOR_NAMES:
        vector = json.loads((invalid_dir / f"{vector_name}.json").read_text(encoding="utf-8"))
        frames.append((vector["frame"], expected_error_frame))
    return frames


def _load_invalid_serial_frame_vector(specs_dir: Path, vector_name: str) -> dict:
    vector = json.loads((specs_dir / "vectors" / "invalid" / f"{vector_name}.json").read_text(encoding="utf-8"))
    if vector.get("category") != "serial-frame":
        raise ValueError(f"{vector_name} is not a serial-frame invalid vector")
    frame = vector.get("frame")
    if not isinstance(frame, str):
        raise ValueError(f"{vector_name} does not contain a frame")
    return vector


def load_malformed_transport_frame_exchanges(specs_dir: Path = DEFAULT_SPECS) -> list[tuple[str, str]]:
    expected_error_frame = encode_serial_frame("error", base64url_json(MALFORMED_FRAME_ERROR))
    return [
        (_load_invalid_serial_frame_vector(specs_dir, vector_name)["frame"], expected_error_frame)
        for vector_name in MALFORMED_TRANSPORT_VECTOR_NAMES
    ]


def load_overlong_transport_frame_exchanges(specs_dir: Path = DEFAULT_SPECS) -> list[tuple[str, str]]:
    expected_error_frame = encode_serial_frame("error", base64url_json(OVERLONG_FRAME_ERROR))
    frames: list[tuple[str, str]] = []
    for vector_name in OVERLONG_TRANSPORT_VECTOR_NAMES:
        frame = _load_invalid_serial_frame_vector(specs_dir, vector_name)["frame"]
        if not frame.endswith("\n"):
            frame += "\n"
        frames.append((frame, expected_error_frame))
    return frames


def load_invalid_signing_request_frames(specs_dir: Path = DEFAULT_SPECS) -> list[tuple[str, str]]:
    error_payload = base64url_json(UNSUPPORTED_REQUEST_ERROR)
    expected_error_frame = encode_serial_frame("error", error_payload)
    invalid_dir = specs_dir / "vectors" / "invalid"
    frames: list[tuple[str, str]] = []
    for vector_path in sorted(invalid_dir.glob("request-*.json")):
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        request = vector.get("request")
        if not isinstance(request, dict) or vector.get("category") != "signing-request":
            continue
        frames.append((encode_serial_frame("request", base64url_json(request)), expected_error_frame))
    return frames


def load_invalid_sign_event_request_frames(specs_dir: Path = DEFAULT_SPECS) -> list[tuple[str, str]]:
    return load_invalid_signing_request_frames(specs_dir)


def vector_frames(vector: dict) -> tuple[str, str]:
    request_payload = base64url_json(vector["request"])
    response_payload = base64url_json(vector["response"])
    return encode_serial_frame("request", request_payload), encode_serial_frame("response", response_payload)


def extract_first_protocol_frame(text: str) -> str | None:
    for line in text.splitlines(keepends=True):
        if not line.endswith("\n"):
            continue
        if line.startswith(PREFIX):
            return line.removesuffix("\r\n") + "\n" if line.endswith("\r\n") else line
    return None


def read_expected_frame(device: object, expected_response_frame: str, deadline: float) -> str:
    buffer = ""
    while time.monotonic() < deadline:
        chunk = device.read(512)
        if not chunk:
            continue
        buffer += chunk.decode("utf-8", errors="replace")
        frame = extract_first_protocol_frame(buffer)
        if frame is None:
            continue
        if frame != expected_response_frame:
            raise RuntimeError(f"unexpected response frame: {frame.strip()}")
        return frame
    raise TimeoutError("no expected protocol response received before timeout")


def format_smoke_summary(frames: list[str]) -> str:
    response_count = sum(1 for frame in frames if frame.startswith(f"{PREFIX}response:"))
    rejection_count = sum(1 for frame in frames if frame.startswith(f"{PREFIX}error:"))
    return "\n".join(
        [
            "ESP32 hardware smoke passed",
            f"verified exchanges: {len(frames)}",
            f"response frames: {response_count}",
            f"expected rejection frames: {rejection_count}",
            "",
        ]
    )


def build_hardware_smoke_exchanges(specs_dir: Path = DEFAULT_SPECS) -> list[tuple[str, str]]:
    return [
        load_capability_frames(specs_dir),
        load_signing_status_frames(specs_dir),
        load_public_key_frames(specs_dir),
        load_signing_disabled_frames(specs_dir),
        *load_dynamic_request_id_frames(specs_dir),
        *load_invalid_metadata_frames(specs_dir),
        *load_invalid_signing_request_frames(specs_dir),
        *load_malformed_transport_frame_exchanges(specs_dir),
        *load_overlong_transport_frame_exchanges(specs_dir),
        load_post_overlong_recovery_frames(specs_dir),
    ]


def run_serial_exchanges(device: object, exchanges: list[tuple[str, str]], timeout: float) -> list[str]:
    responses: list[str] = []
    exchange_count = len(exchanges)
    for exchange_index, (request_frame, expected_response_frame) in enumerate(exchanges, start=1):
        device.write(request_frame.encode("ascii"))
        device.flush()
        try:
            responses.append(read_expected_frame(device, expected_response_frame, time.monotonic() + timeout))
        except (RuntimeError, TimeoutError) as exc:
            raise RuntimeError(f"exchange {exchange_index}/{exchange_count} failed: {exc}") from exc
    return responses


def run_smoke(port: str, timeout: float, baudrate: int, specs_dir: Path = DEFAULT_SPECS) -> list[str]:
    try:
        import serial  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("pyserial is required; export ESP-IDF before running this smoke test") from exc

    exchanges = build_hardware_smoke_exchanges(specs_dir)

    with serial.Serial(port, baudrate=baudrate, timeout=0.1) as device:
        device.reset_input_buffer()
        return run_serial_exchanges(device, exchanges, timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbmodem1101")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--baudrate", type=int, default=115200)
    parser.add_argument(
        "--verbose-frames",
        action="store_true",
        help="print raw protocol response frames instead of the clean smoke summary",
    )
    args = parser.parse_args()

    frames = run_smoke(args.port, args.timeout, args.baudrate)
    if args.verbose_frames:
        for frame in frames:
            print(frame, end="")
    else:
        print(format_smoke_summary(frames), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
