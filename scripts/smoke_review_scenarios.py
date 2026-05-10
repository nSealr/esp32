#!/usr/bin/env python3
"""ESP32-S3 non-interactive review-scenario serial smoke test."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable

try:
    from scripts import manual_review_display
    from scripts import smoke_capabilities
except ImportError:  # pragma: no cover - used when executed as scripts/foo.py
    import manual_review_display  # type: ignore[no-redef]
    import smoke_capabilities  # type: ignore[no-redef]


DEFAULT_REVIEW_SMOKE_SCENARIOS = (
    "show-review",
    "show-tags",
    "show-long-content",
    "show-scroll-review",
    "show-unicode-review",
    "show-request-error",
)
DEFAULT_REQUEST_ID_PREFIX = "review-smoke"
DEFAULT_TIMEOUT = 5.0
DEFAULT_BAUDRATE = 115200


def request_id_for_scenario(prefix: str, scenario: str) -> str:
    return f"{prefix}-{scenario}"


def build_review_smoke_exchanges(
    *,
    scenarios: Iterable[str] = DEFAULT_REVIEW_SMOKE_SCENARIOS,
    request_id_prefix: str = DEFAULT_REQUEST_ID_PREFIX,
    specs_dir: Path = smoke_capabilities.DEFAULT_SPECS,
) -> list[tuple[str, str]]:
    exchanges: list[tuple[str, str]] = []
    for scenario in scenarios:
        exchanges.extend(
            manual_review_display.build_manual_review_exchanges(
                scenario=scenario,
                request_id=request_id_for_scenario(request_id_prefix, scenario),
                specs_dir=specs_dir,
            )
        )
    return exchanges


def format_review_smoke_summary(frames: list[str], *, scenarios: Iterable[str]) -> str:
    response_count = sum(1 for frame in frames if frame.startswith(f"{smoke_capabilities.PREFIX}response:"))
    rejection_count = sum(1 for frame in frames if frame.startswith(f"{smoke_capabilities.PREFIX}error:"))
    scenario_count = len(tuple(scenarios))
    return "\n".join(
        [
            "ESP32 review scenario smoke passed",
            f"scenarios: {scenario_count}",
            f"verified exchanges: {len(frames)}",
            f"response frames: {response_count}",
            f"expected rejection frames: {rejection_count}",
            "",
        ]
    )


def run_review_smoke(
    *,
    port: str,
    scenarios: Iterable[str] = DEFAULT_REVIEW_SMOKE_SCENARIOS,
    request_id_prefix: str = DEFAULT_REQUEST_ID_PREFIX,
    timeout: float = DEFAULT_TIMEOUT,
    baudrate: int = DEFAULT_BAUDRATE,
    specs_dir: Path = smoke_capabilities.DEFAULT_SPECS,
) -> tuple[list[str], tuple[str, ...]]:
    try:
        import serial  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("pyserial is required; export ESP-IDF before running this smoke test") from exc

    scenario_tuple = tuple(scenarios)
    exchanges = build_review_smoke_exchanges(
        scenarios=scenario_tuple,
        request_id_prefix=request_id_prefix,
        specs_dir=specs_dir,
    )
    with serial.Serial(port, baudrate=baudrate, timeout=0.1) as device:
        device.reset_input_buffer()
        return smoke_capabilities.run_serial_exchanges(device, exchanges, timeout), scenario_tuple


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbmodem1101")
    parser.add_argument("--request-id-prefix", default=DEFAULT_REQUEST_ID_PREFIX)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--baudrate", type=int, default=DEFAULT_BAUDRATE)
    parser.add_argument(
        "--scenario",
        action="append",
        choices=DEFAULT_REVIEW_SMOKE_SCENARIOS,
        help="review scenario to run; may be passed multiple times; defaults to all non-interactive scenarios",
    )
    parser.add_argument(
        "--verbose-frames",
        action="store_true",
        help="print raw protocol response frames instead of the clean smoke summary",
    )
    args = parser.parse_args()

    scenarios = tuple(args.scenario) if args.scenario else DEFAULT_REVIEW_SMOKE_SCENARIOS
    frames, ran_scenarios = run_review_smoke(
        port=args.port,
        scenarios=scenarios,
        request_id_prefix=args.request_id_prefix,
        timeout=args.timeout,
        baudrate=args.baudrate,
    )
    if args.verbose_frames:
        for frame in frames:
            print(frame, end="")
    else:
        print(format_review_smoke_summary(frames, scenarios=ran_scenarios), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
