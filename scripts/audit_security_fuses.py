#!/usr/bin/env python3
"""Read-only ESP32-S3 security eFuse audit.

The script intentionally calls only `espefuse.py summary`. It is a reporting
tool for the M9 hardening gap, not a provisioning or eFuse-burning helper.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Sequence


SCHEMA = "nsealr-esp32-security-fuse-audit-v0"
TARGET = "esp32s3"
READ_ONLY_COMMAND = ("espefuse.py", "--chip", TARGET, "--port")

FUSE_NAMES = (
    "SECURE_BOOT_EN",
    "SPI_BOOT_CRYPT_CNT",
    "DIS_PAD_JTAG",
    "DIS_USB_JTAG",
    "DIS_USB_SERIAL_JTAG",
    "DIS_DOWNLOAD_MODE",
    "DIS_DOWNLOAD_MANUAL_ENCRYPT",
    "ENABLE_SECURITY_DOWNLOAD",
)


def build_espefuse_summary_command(port: str) -> list[str]:
    return [*READ_ONLY_COMMAND, port, "summary"]


def _extract_meaningful_value(summary: str, fuse_name: str) -> str:
    pattern = re.compile(
        rf"^{re.escape(fuse_name)}\s+\([^)]*\).*?=\s*(?P<value>.*?)\s+[R-]/[W-]\s+\(",
        re.MULTILINE,
    )
    match = pattern.search(summary)
    if match is None:
        raise ValueError(f"missing eFuse summary value for {fuse_name}")
    return match.group("value").strip()


def _parse_bool(value: str, fuse_name: str) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    raise ValueError(f"{fuse_name} must be True or False in eFuse summary, got {value!r}")


def _flash_encryption_enabled(value: str) -> bool:
    return value != "Disable"


def parse_espefuse_summary(summary: str, port: str) -> dict:
    raw_values = {name: _extract_meaningful_value(summary, name) for name in FUSE_NAMES}

    secure_boot_enabled = _parse_bool(raw_values["SECURE_BOOT_EN"], "SECURE_BOOT_EN")
    flash_encryption_enabled = _flash_encryption_enabled(raw_values["SPI_BOOT_CRYPT_CNT"])
    download_mode_disabled = _parse_bool(raw_values["DIS_DOWNLOAD_MODE"], "DIS_DOWNLOAD_MODE")
    manual_flash_encryption_download_disabled = _parse_bool(
        raw_values["DIS_DOWNLOAD_MANUAL_ENCRYPT"],
        "DIS_DOWNLOAD_MANUAL_ENCRYPT",
    )
    pad_jtag_disabled = _parse_bool(raw_values["DIS_PAD_JTAG"], "DIS_PAD_JTAG")
    usb_jtag_disabled = _parse_bool(raw_values["DIS_USB_JTAG"], "DIS_USB_JTAG")
    usb_serial_jtag_disabled = _parse_bool(raw_values["DIS_USB_SERIAL_JTAG"], "DIS_USB_SERIAL_JTAG")
    secure_download_enabled = _parse_bool(raw_values["ENABLE_SECURITY_DOWNLOAD"], "ENABLE_SECURITY_DOWNLOAD")
    debug_access_locked = pad_jtag_disabled and usb_jtag_disabled and usb_serial_jtag_disabled

    blockers: list[str] = []
    if not secure_boot_enabled:
        blockers.append("secure_boot")
    if not flash_encryption_enabled:
        blockers.append("flash_encryption")
    if not debug_access_locked:
        blockers.append("debug_lock")
    if not download_mode_disabled:
        blockers.append("download_mode")
    if not manual_flash_encryption_download_disabled:
        blockers.append("manual_flash_encryption_download")

    return {
        "schema": SCHEMA,
        "target": TARGET,
        "port": port,
        "tool": "espefuse.py summary",
        "read_only": True,
        "raw_summary_sha256": hashlib.sha256(summary.encode("utf-8")).hexdigest(),
        "secure_boot_enabled": secure_boot_enabled,
        "flash_encryption_enabled": flash_encryption_enabled,
        "download_mode_disabled": download_mode_disabled,
        "manual_flash_encryption_download_disabled": manual_flash_encryption_download_disabled,
        "secure_download_enabled": secure_download_enabled,
        "debug_access_locked": debug_access_locked,
        "development_usb_jtag_available": not debug_access_locked,
        "debug_fuses": {
            "pad_jtag_disabled": pad_jtag_disabled,
            "usb_jtag_disabled": usb_jtag_disabled,
            "usb_serial_jtag_disabled": usb_serial_jtag_disabled,
        },
        "raw_fuse_values": raw_values,
        "production_blockers": blockers,
        "production_signing_ready": not blockers,
    }


def run_espefuse_summary(port: str) -> str:
    completed = subprocess.run(
        build_espefuse_summary_command(port),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return completed.stdout


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="ESP32-S3 serial port, for example /dev/cu.usbmodem1101")
    parser.add_argument(
        "--summary-file",
        type=Path,
        help="Read a previously captured espefuse.py summary instead of opening the board.",
    )
    parser.add_argument("--out", type=Path, help="Write audit JSON to this file instead of stdout.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.summary_file is not None:
        summary = args.summary_file.read_text(encoding="utf-8")
    else:
        summary = run_espefuse_summary(args.port)
    audit = parse_espefuse_summary(summary, port=args.port)
    output = json.dumps(audit, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        args.out.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
