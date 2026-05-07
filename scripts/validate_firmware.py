#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_PROJECT_FILES = [
    "CMakeLists.txt",
    "main/CMakeLists.txt",
    "main/main.cpp",
    "sdkconfig.defaults",
]

FORBIDDEN_CLAIMS = [
    "production ready",
    "secure by default",
    "real key signing enabled",
]


def validate_firmware_project(project: Path) -> None:
    for rel in REQUIRED_PROJECT_FILES:
        path = project / rel
        if not path.exists():
            raise ValueError(f"{project}: missing required ESP-IDF file {rel}")
        if not path.read_text(encoding="utf-8").strip():
            raise ValueError(f"{project}: empty required ESP-IDF file {rel}")

    root_cmake = (project / "CMakeLists.txt").read_text(encoding="utf-8")
    if "project.cmake" not in root_cmake or "project(" not in root_cmake:
        raise ValueError(f"{project}: root CMakeLists.txt must include ESP-IDF project.cmake and project()")

    sdkconfig = (project / "sdkconfig.defaults").read_text(encoding="utf-8")
    if "CONFIG_IDF_TARGET=\"esp32s3\"" not in sdkconfig:
        raise ValueError(f"{project}: sdkconfig.defaults must target esp32s3")

    main = (project / "main/main.cpp").read_text(encoding="utf-8")
    if "app_main" not in main:
        raise ValueError(f"{project}: main.cpp must define app_main")
    lowered = main.lower()
    for claim in FORBIDDEN_CLAIMS:
        if claim in lowered:
            raise ValueError(f"{project}: forbidden unsupported firmware claim: {claim}")


def validate_board_profile(path: Path) -> None:
    profile = json.loads(path.read_text(encoding="utf-8"))
    if profile.get("target") != "esp32s3":
        raise ValueError(f"{path}: target must be esp32s3")
    if profile.get("native_usb") is not True:
        raise ValueError(f"{path}: native_usb must be true for the S3 USB signer line")
    for field in ("display", "approval_inputs", "debug_policy"):
        if field not in profile:
            raise ValueError(f"{path}: missing {field}")
    if len(profile["approval_inputs"]) < 2:
        raise ValueError(f"{path}: approval_inputs must include separate approve and reject controls")


def main() -> int:
    validate_firmware_project(ROOT / "firmware/esp32_s3_usb_signer")
    validate_board_profile(ROOT / "boards/esp32_s3_devkitc_1.json")
    print("NostrSeal ESP32 firmware validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
