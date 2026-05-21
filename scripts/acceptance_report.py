#!/usr/bin/env python3
"""Build a repeatable ESP32 T-Display S3 hardware acceptance report.

The report is development evidence only. It exercises the current serial
protocol, review-scenario smoke path, and read-only security-fuse audit while
keeping real signing disabled.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

try:
    from scripts import audit_security_fuses
    from scripts import detect_esp32_s3
    from scripts import manual_review_display
    from scripts import smoke_capabilities
    from scripts import smoke_review_scenarios
except ImportError:  # pragma: no cover - used when executed as scripts/foo.py
    import audit_security_fuses  # type: ignore[no-redef]
    import detect_esp32_s3  # type: ignore[no-redef]
    import manual_review_display  # type: ignore[no-redef]
    import smoke_capabilities  # type: ignore[no-redef]
    import smoke_review_scenarios  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "nsealr-esp32-t-display-s3-acceptance-report-v0"
TARGET = "t-display-s3-usb-display-signer"
MANUAL_OBSERVATION_CHOICES = ("not-recorded", "passed", "failed")


def count_protocol_frames(frames: Sequence[str]) -> dict[str, int]:
    return {
        "verified_exchanges": len(frames),
        "response_frames": sum(1 for frame in frames if frame.startswith(f"{smoke_capabilities.PREFIX}response:")),
        "expected_rejection_frames": sum(
            1 for frame in frames if frame.startswith(f"{smoke_capabilities.PREFIX}error:")
        ),
    }


def git_revision() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "unknown"
    return completed.stdout.strip() or "unknown"


def build_hard_reset_command(port: str) -> list[str]:
    return [
        "esptool.py",
        "--chip",
        "esp32s3",
        "-p",
        port,
        "--before",
        "default_reset",
        "--after",
        "hard_reset",
        "chip_id",
    ]


def run_hard_reset(port: str) -> None:
    subprocess.run(
        build_hard_reset_command(port),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(2.0)


def build_acceptance_report(
    *,
    port: str,
    source_revision: str,
    firmware_revision: str,
    board_detection: dict,
    capability_frames: Sequence[str],
    review_frames: Sequence[str],
    review_scenarios: Sequence[str],
    fuse_audit: dict,
    manual_observation: str,
    hard_reset_after_fuse_audit: bool,
    post_fuse_recovery_frames: Sequence[str] | None,
) -> dict[str, object]:
    if manual_observation not in MANUAL_OBSERVATION_CHOICES:
        raise ValueError(f"manual observation must be one of: {', '.join(MANUAL_OBSERVATION_CHOICES)}")

    fuse_blockers = list(fuse_audit.get("production_blockers", []))
    manual_blockers = [] if manual_observation == "passed" else ["manual_display_button_observation"]
    if post_fuse_recovery_frames is None:
        post_fuse_recovery = {
            "status": "not-run",
            "verified_exchanges": 0,
            "response_frames": 0,
            "expected_rejection_frames": 0,
        }
    else:
        post_fuse_recovery = {
            "status": "passed",
            **count_protocol_frames(post_fuse_recovery_frames),
        }
    recovery_blockers = (
        ["post_fuse_audit_protocol_recovery"]
        if hard_reset_after_fuse_audit and post_fuse_recovery["status"] != "passed"
        else []
    )
    production_blockers = [*fuse_blockers, *manual_blockers, *recovery_blockers, "runtime_signing_disabled"]

    return {
        "schema": SCHEMA,
        "target": TARGET,
        "port": port,
        "source_revision": source_revision,
        "firmware_revision": firmware_revision,
        "board_detection": board_detection,
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "signing_enabled": False,
        "production_signing_ready": False,
        "development_acceptance_ready": not manual_blockers and not recovery_blockers,
        "capability_smoke": {
            "status": "passed",
            **count_protocol_frames(capability_frames),
        },
        "review_scenario_smoke": {
            "status": "passed",
            "scenarios": list(review_scenarios),
            **count_protocol_frames(review_frames),
        },
        "manual_display_button_observation": {
            "status": manual_observation,
            "required_scenarios": list(manual_review_display.MANUAL_REVIEW_SCENARIOS),
            "note": "Human visual/button evidence only; it does not enable signing.",
        },
        "security_fuse_audit": fuse_audit,
        "post_fuse_audit_hard_reset_performed": hard_reset_after_fuse_audit,
        "post_fuse_audit_protocol_recovery": post_fuse_recovery,
        "production_blockers": production_blockers,
    }


def run_acceptance(
    *,
    port: str,
    timeout: float,
    baudrate: int,
    manual_observation: str,
    firmware_revision: str,
    hard_reset_after_fuse_audit: bool,
) -> dict[str, object]:
    board_detection = detect_esp32_s3.build_detection_report()
    capability_frames = smoke_capabilities.run_smoke(port=port, timeout=timeout, baudrate=baudrate)
    review_frames, review_scenarios = smoke_review_scenarios.run_review_smoke(
        port=port,
        timeout=timeout,
        baudrate=baudrate,
    )
    fuse_summary = audit_security_fuses.run_espefuse_summary(port)
    fuse_audit = audit_security_fuses.parse_espefuse_summary(fuse_summary, port=port)
    post_fuse_recovery_frames = None
    if hard_reset_after_fuse_audit:
        run_hard_reset(port)
        post_fuse_recovery_frames = smoke_capabilities.run_smoke(port=port, timeout=timeout, baudrate=baudrate)

    return build_acceptance_report(
        port=port,
        source_revision=git_revision(),
        firmware_revision=firmware_revision,
        board_detection=board_detection,
        capability_frames=capability_frames,
        review_frames=review_frames,
        review_scenarios=review_scenarios,
        fuse_audit=fuse_audit,
        manual_observation=manual_observation,
        hard_reset_after_fuse_audit=hard_reset_after_fuse_audit,
        post_fuse_recovery_frames=post_fuse_recovery_frames,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbmodem1101")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--baudrate", type=int, default=115200)
    parser.add_argument("--out", type=Path, required=True, help="Write acceptance report JSON to this file.")
    parser.add_argument(
        "--firmware-revision",
        default="not-recorded",
        help="Revision of the firmware image currently flashed on the device, if known.",
    )
    parser.add_argument(
        "--manual-observation",
        choices=MANUAL_OBSERVATION_CHOICES,
        default="not-recorded",
        help="Record whether the human display/button observation checklist passed in this session.",
    )
    parser.add_argument(
        "--no-hard-reset-after-fuse-audit",
        action="store_true",
        help="Do not run the non-destructive esptool hard reset after the read-only fuse audit.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    report = run_acceptance(
        port=args.port,
        timeout=args.timeout,
        baudrate=args.baudrate,
        manual_observation=args.manual_observation,
        firmware_revision=args.firmware_revision,
        hard_reset_after_fuse_audit=not args.no_hard_reset_after_fuse_audit,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"ESP32 acceptance report written: {args.out}")
    print(f"production signing ready: {str(report['production_signing_ready']).lower()}")
    print(f"manual observation: {report['manual_display_button_observation']['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
