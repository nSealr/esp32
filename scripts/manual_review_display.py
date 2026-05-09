#!/usr/bin/env python3
"""Manual T-Display S3 review-display exerciser.

This helper sends deterministic serial requests to a flashed NostrSeal ESP32
device so a human can inspect the physical trusted-review display state. It
does not enable signing and expects the firmware to keep returning
``signing_disabled`` for valid ``sign_event`` requests.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

try:
    from scripts import smoke_capabilities
except ImportError:  # pragma: no cover - used when executed as scripts/foo.py
    import smoke_capabilities  # type: ignore[no-redef]


DEFAULT_REVIEW_REQUEST_ID = "manual-review-display"
DEFAULT_TIMEOUT = 5.0
DEFAULT_BAUDRATE = 115200


def _expected_unsupported_request_frame() -> str:
    return smoke_capabilities.encode_serial_frame(
        "error",
        smoke_capabilities.base64url_json(smoke_capabilities.UNSUPPORTED_REQUEST_ERROR),
    )


def _load_invalid_event_template_request(specs_dir: Path) -> dict:
    vector_path = specs_dir / "vectors/invalid/request-event-template-pubkey.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    request = vector.get("request")
    if not isinstance(request, dict):
        raise ValueError(f"{vector_path} does not contain a request object")
    return copy.deepcopy(request)


def build_display_review_exchange(
    request_id: str = DEFAULT_REVIEW_REQUEST_ID,
    specs_dir: Path = smoke_capabilities.DEFAULT_SPECS,
) -> tuple[str, str]:
    vector = smoke_capabilities.vector_with_request_id(
        smoke_capabilities.load_signing_disabled_vector(specs_dir),
        request_id,
    )
    return smoke_capabilities.vector_frames(vector)


def build_request_error_exchange(
    request_id: str = f"{DEFAULT_REVIEW_REQUEST_ID}-invalid",
    specs_dir: Path = smoke_capabilities.DEFAULT_SPECS,
) -> tuple[str, str]:
    request = _load_invalid_event_template_request(specs_dir)
    request["request_id"] = request_id
    request_frame = smoke_capabilities.encode_serial_frame(
        "request",
        smoke_capabilities.base64url_json(request),
    )
    return request_frame, _expected_unsupported_request_frame()


def build_manual_review_exchanges(
    scenario: str,
    request_id: str = DEFAULT_REVIEW_REQUEST_ID,
    specs_dir: Path = smoke_capabilities.DEFAULT_SPECS,
) -> list[tuple[str, str]]:
    review_exchange = build_display_review_exchange(request_id=request_id, specs_dir=specs_dir)
    if scenario == "show-review":
        return [review_exchange]
    if scenario == "show-request-error":
        return [
            review_exchange,
            build_request_error_exchange(request_id=f"{request_id}-invalid", specs_dir=specs_dir),
        ]
    raise ValueError(f"unsupported manual review scenario: {scenario}")


def run_manual_review_exchanges(
    device: object,
    exchanges: list[tuple[str, str]],
    timeout: float,
) -> list[str]:
    return smoke_capabilities.run_serial_exchanges(device, exchanges, timeout)


def run_manual_review_scenario(
    port: str,
    scenario: str,
    request_id: str,
    timeout: float,
    baudrate: int,
    specs_dir: Path = smoke_capabilities.DEFAULT_SPECS,
) -> list[str]:
    try:
        import serial  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("pyserial is required; export ESP-IDF before opening the board port") from exc

    exchanges = build_manual_review_exchanges(
        scenario=scenario,
        request_id=request_id,
        specs_dir=specs_dir,
    )
    with serial.Serial(port, baudrate=baudrate, timeout=0.1) as device:
        device.reset_input_buffer()
        return run_manual_review_exchanges(device, exchanges, timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "scenario",
        choices=("show-review", "show-request-error"),
        help=(
            "show-review leaves a valid sign_event review on the display; "
            "show-request-error first shows that review and then sends an invalid request"
        ),
    )
    parser.add_argument("--port", default="/dev/cu.usbmodem1101")
    parser.add_argument("--request-id", default=DEFAULT_REVIEW_REQUEST_ID)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--baudrate", type=int, default=DEFAULT_BAUDRATE)
    args = parser.parse_args()

    frames = run_manual_review_scenario(
        port=args.port,
        scenario=args.scenario,
        request_id=args.request_id,
        timeout=args.timeout,
        baudrate=args.baudrate,
    )
    print(
        smoke_capabilities.format_smoke_summary(frames),
        end="",
    )
    print(f"manual display scenario: {args.scenario}")
    print(f"request id: {args.request_id}")
    print("real signing expected: disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
