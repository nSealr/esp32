#!/usr/bin/env python3
"""Validate the nSealr firmware board profiles.

The C++ `host_core` and the ESP-IDF `esp32_s3_usb_signer` app were retired in
Phase 03 Task 05 (their protocol/review/session logic now lives in the Rust
`crates/nsealr-core` crate, proven at parity by `apps/desktop-simulator`). What
remains here is the toolchain-agnostic validation of the `boards/*.json`
registry: the signer-board profiles and the custom-wallet display-panel
registry that every firmware target consumes regardless of implementation
language.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


# Supported MCU build targets for the ESP32 signer board line. esp32s3 is the
# universal USB wallet / custom host + the legacy dev boards; esp32p4 is the
# radio-less QR-vault MCU (decision spec 2/3).
SIGNER_BOARD_TARGETS = ("esp32s3", "esp32p4")
# Curated display driver family for the custom-wallet display-agnostic FPC
# (decision spec 5).
CURATED_DISPLAY_PANEL_DRIVERS = ("ST7789", "ST7789V2", "ST7796")


def validate_board_profile(path: Path) -> None:
    profile = json.loads(path.read_text(encoding="utf-8"))
    for field in ("name", "status"):
        if not profile.get(field):
            raise ValueError(f"{path}: missing {field}")
    # A profile with an MCU build target is a signer board; a profile without one
    # is a display-panel registry entry (custom-wallet display-agnostic FPC).
    if "target" in profile:
        _validate_signer_board_profile(path, profile)
    else:
        _validate_display_panel_registry(path, profile)


def _validate_signer_board_profile(path: Path, profile: dict) -> None:
    if profile.get("target") not in SIGNER_BOARD_TARGETS:
        raise ValueError(f"{path}: target must be one of {SIGNER_BOARD_TARGETS}")
    if profile.get("native_usb") is not True:
        raise ValueError(f"{path}: native_usb must be true for the ESP32 signer line")
    for field in ("display", "approval_inputs", "debug_policy"):
        if field not in profile:
            raise ValueError(f"{path}: missing {field}")
    display = profile["display"]
    if not isinstance(display, dict):
        raise ValueError(f"{path}: display must be an object")
    if display.get("required_for_signing") is not True:
        raise ValueError(f"{path}: display.required_for_signing must be true")
    touch = display.get("touch")
    if isinstance(touch, dict) and touch.get("approval_allowed") is not False:
        raise ValueError(f"{path}: touch approval must be explicitly disallowed")

    approval_inputs = profile["approval_inputs"]
    if not isinstance(approval_inputs, list):
        raise ValueError(f"{path}: approval_inputs must be a list")
    approval_names = {entry.get("name") for entry in approval_inputs if isinstance(entry, dict)}
    if {"approve", "reject"} - approval_names:
        raise ValueError(f"{path}: approval_inputs must include separate approve and reject controls")

    camera = profile.get("camera")
    if camera is not None:
        if not isinstance(camera, dict):
            raise ValueError(f"{path}: camera must be an object")
        for field in ("module", "connection"):
            if not camera.get(field):
                raise ValueError(f"{path}: camera missing {field}")
        if camera.get("required_for_qr") is not True:
            raise ValueError(f"{path}: camera.required_for_qr must be true for camera profiles")
        if "Wireless must be disabled" not in profile.get("wireless_policy", ""):
            raise ValueError(f"{path}: camera QR profiles must document disabled wireless policy")

    if not isinstance(profile["debug_policy"], str) or not profile["debug_policy"].strip():
        raise ValueError(f"{path}: debug_policy must be a non-empty string")


def _validate_curated_driver(path: Path, driver: object) -> None:
    if driver not in CURATED_DISPLAY_PANEL_DRIVERS:
        raise ValueError(
            f"{path}: panel display driver must be in the curated family {CURATED_DISPLAY_PANEL_DRIVERS}"
        )


def _validate_reference_panel(path: Path, panel: object) -> None:
    if not isinstance(panel, dict):
        raise ValueError(f"{path}: reference_panel must be an object")
    display = panel.get("display")
    if not isinstance(display, dict):
        raise ValueError(f"{path}: reference_panel missing display object")
    _validate_curated_driver(path, display.get("driver"))
    touch = panel.get("touch")
    if isinstance(touch, dict) and touch.get("approval_allowed") is not False:
        raise ValueError(f"{path}: reference_panel touch approval must be explicitly disallowed")


def _validate_display_panel_registry(path: Path, profile: dict) -> None:
    firmware_targets = profile.get("firmware_targets")
    if not isinstance(firmware_targets, list) or "custom_hardware_wallet" not in firmware_targets:
        raise ValueError(f"{path}: display panel registry must set firmware_targets to custom_hardware_wallet")
    _validate_reference_panel(path, profile.get("reference_panel"))
    driver_family = profile.get("driver_family")
    if not isinstance(driver_family, list) or not driver_family:
        raise ValueError(f"{path}: display panel registry must list a non-empty driver_family")
    for entry in driver_family:
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: driver_family entry must be an object")
        _validate_curated_driver(path, entry.get("driver"))
    physical_confirm = profile.get("physical_confirm")
    if not isinstance(physical_confirm, str) or not physical_confirm.strip():
        raise ValueError(f"{path}: display panel registry must document the on-board physical_confirm control")


def validate_board_profiles(board_dir: Path) -> None:
    profiles = sorted(board_dir.glob("*.json"))
    if not profiles:
        raise ValueError(f"{board_dir}: missing board profiles")
    for profile in profiles:
        validate_board_profile(profile)


def main() -> int:
    validate_board_profiles(ROOT / "boards")
    print("nSealr firmware board-profile validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
