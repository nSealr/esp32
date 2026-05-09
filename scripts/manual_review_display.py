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
MANUAL_REVIEW_SCENARIOS = (
    "show-review",
    "show-tags",
    "show-long-content",
    "show-request-error",
    "button-approve",
    "button-reject",
)


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


def _load_review_request(specs_dir: Path, relative_path: str) -> dict:
    vector_path = specs_dir / relative_path
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    request = vector.get("request")
    if not isinstance(request, dict):
        raise ValueError(f"{vector_path} does not contain a request object")
    return copy.deepcopy(request)


def _signing_disabled_response_for_request(request: dict, specs_dir: Path) -> dict:
    response = copy.deepcopy(smoke_capabilities.load_signing_disabled_vector(specs_dir)["response"])
    response["request_id"] = request["request_id"]
    return response


def _review_exchange_from_request(request: dict, request_id: str, specs_dir: Path) -> tuple[str, str]:
    updated_request = copy.deepcopy(request)
    updated_request["request_id"] = request_id
    response = _signing_disabled_response_for_request(updated_request, specs_dir)
    return (
        smoke_capabilities.encode_serial_frame(
            "request",
            smoke_capabilities.base64url_json(updated_request),
        ),
        smoke_capabilities.encode_serial_frame(
            "response",
            smoke_capabilities.base64url_json(response),
        ),
    )


def build_display_review_exchange(
    request_id: str = DEFAULT_REVIEW_REQUEST_ID,
    specs_dir: Path = smoke_capabilities.DEFAULT_SPECS,
) -> tuple[str, str]:
    vector = smoke_capabilities.vector_with_request_id(
        smoke_capabilities.load_signing_disabled_vector(specs_dir),
        request_id,
    )
    return smoke_capabilities.vector_frames(vector)


def build_tagged_review_exchange(
    request_id: str = f"{DEFAULT_REVIEW_REQUEST_ID}-tags",
    specs_dir: Path = smoke_capabilities.DEFAULT_SPECS,
) -> tuple[str, str]:
    return _review_exchange_from_request(
        _load_review_request(specs_dir, "vectors/review-screens/kind-1-tags.json"),
        request_id,
        specs_dir,
    )


def build_long_content_review_exchange(
    request_id: str = f"{DEFAULT_REVIEW_REQUEST_ID}-long-content",
    specs_dir: Path = smoke_capabilities.DEFAULT_SPECS,
) -> tuple[str, str]:
    return _review_exchange_from_request(
        _load_review_request(specs_dir, "vectors/review/kind-1-long-events-many-tags.json"),
        request_id,
        specs_dir,
    )


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
    if scenario in {"show-review", "button-approve", "button-reject"}:
        return [review_exchange]
    if scenario == "show-tags":
        return [build_tagged_review_exchange(request_id=request_id, specs_dir=specs_dir)]
    if scenario == "show-long-content":
        return [build_long_content_review_exchange(request_id=request_id, specs_dir=specs_dir)]
    if scenario == "show-request-error":
        return [
            review_exchange,
            build_request_error_exchange(request_id=f"{request_id}-invalid", specs_dir=specs_dir),
        ]
    raise ValueError(f"unsupported manual review scenario: {scenario}")


def build_manual_observation_checklist(scenario: str) -> str:
    common = [
        "Confirm the display starts on Event / Page 1/4.",
        "Confirm real signing remains disabled in the serial response.",
    ]
    if scenario == "show-review":
        lines = [
            *common,
            "Inspect the review page text for readable kind, type, and created_at fields.",
        ]
    elif scenario == "show-tags":
        lines = [
            "Confirm the display starts on Event / Page 1/N.",
            "Confirm real signing remains disabled in the serial response.",
            "Press short KEY/GPIO14 until the Tags pages are shown.",
            "Confirm the Tags pages show 2 tags without ellipses.",
            "Confirm the p tag shows the full 64-character pubkey across pages.",
            "Confirm the p tag marker mention and t tag nostrseal are visible.",
            "Continue with short KEY/GPIO14 until the final Decision page.",
        ]
    elif scenario == "show-long-content":
        lines = [
            "Confirm the display starts on Event / Page 1/N.",
            "Confirm real signing remains disabled in the serial response.",
            "Press short KEY/GPIO14 until the Content pages are shown.",
            "Confirm the Content pages show the full long content without ellipses.",
            "Continue with short KEY/GPIO14 through the Tags pages.",
            "Confirm every tag field is readable without ellipses.",
            "Continue with short KEY/GPIO14 until the final Decision page.",
        ]
    elif scenario == "show-request-error":
        lines = [
            *common,
            "Confirm the invalid request clears the active review.",
            "Expected final display: Request Error / Rejected / Not signed / Signing disabled / Send new request.",
        ]
    elif scenario == "button-approve":
        lines = [
            *common,
            "Press short KEY/GPIO14 three times to reach the final page.",
            "Press long KEY/GPIO14 to approve.",
            "Expected final display: Review OK / Closed / Not signed / Signing disabled / Send new request.",
        ]
    elif scenario == "button-reject":
        lines = [
            *common,
            "Press long BOOT/GPIO0 to reject.",
            "Expected final display: Rejected / Closed / Not signed / Signing disabled / Send new request.",
        ]
    else:
        raise ValueError(f"unsupported manual review scenario: {scenario}")
    return "\n".join(f"- {line}" for line in lines)


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
        choices=MANUAL_REVIEW_SCENARIOS,
        help=(
            "show-review leaves a valid sign_event review on the display; "
            "show-tags shows a tagged event with unabridged tag review; "
            "show-long-content shows paginated full content plus many tags; "
            "show-request-error first shows that review and then sends an invalid request; "
            "button-approve and button-reject print physical-control acceptance steps"
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
    print("manual observation checklist:")
    print(build_manual_observation_checklist(args.scenario))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
