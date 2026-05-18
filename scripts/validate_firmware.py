#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_PROJECT_FILES = [
    "CMakeLists.txt",
    "main/CMakeLists.txt",
    "main/main.cpp",
    "security_profile.json",
    "sdkconfig.defaults",
]

FORBIDDEN_CLAIMS = [
    "production ready",
    "secure by default",
    "real key signing enabled",
]

REQUIRED_SECURITY_BLOCKERS = {
    "runtime_signing_feature",
    "trusted_review_display",
    "physical_approval_controls",
    "unicode_review_rendering",
    "key_provisioning",
    "secure_boot",
    "flash_encryption",
    "debug_lock",
    "companion_signed_output_verification",
}

ACCEPTANCE_STATUSES = {"manual_development_acceptance_passed"}


def _require_non_empty_string_list(value: object, path: Path, field: str) -> None:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{path}: {field} must be a non-empty list")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{path}: {field} must contain non-empty strings")


def _validate_manual_acceptance_evidence(path: Path, profile: dict, field: str) -> dict:
    value = profile.get(field)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: {field} must be an object")
    if value.get("status") not in ACCEPTANCE_STATUSES:
        allowed = ", ".join(sorted(ACCEPTANCE_STATUSES))
        raise ValueError(f"{path}: {field}.status must be one of {allowed}")
    if value.get("required_before_signing") is not True:
        raise ValueError(f"{path}: {field}.required_before_signing must be true")
    if value.get("production_claim") != "blocked_until_production_acceptance":
        raise ValueError(f"{path}: {field}.production_claim must remain blocked_until_production_acceptance")
    _require_non_empty_string_list(value.get("evidence_reports"), path, f"{field}.evidence_reports")
    return value


def _validate_unicode_review_rendering(path: Path, profile: dict) -> None:
    value = profile.get("unicode_review_rendering")
    if not isinstance(value, dict):
        raise ValueError(f"{path}: unicode_review_rendering must be an object")
    if value.get("status") != "ascii_safe_codepoint_fallback_only":
        raise ValueError(f"{path}: unicode_review_rendering.status must be ascii_safe_codepoint_fallback_only")
    if value.get("required_before_signing") is not True:
        raise ValueError(f"{path}: unicode_review_rendering.required_before_signing must be true")
    if value.get("production_claim") != "blocked_until_full_unicode_review_acceptance":
        raise ValueError(
            f"{path}: unicode_review_rendering.production_claim must remain blocked_until_full_unicode_review_acceptance"
        )
    _require_non_empty_string_list(
        value.get("evidence_reports"),
        path,
        "unicode_review_rendering.evidence_reports",
    )


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
    if "CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y" not in sdkconfig:
        raise ValueError(f"{project}: sdkconfig.defaults must match the observed 16MB ESP32-S3 flash")

    main = (project / "main/main.cpp").read_text(encoding="utf-8")
    if "app_main" not in main:
        raise ValueError(f"{project}: main.cpp must define app_main")
    component_cmake = (project / "main/CMakeLists.txt").read_text(encoding="utf-8")
    for required_source in (
        "main.cpp",
        "t_display_s3_board.cpp",
        "t_display_s3_button_logic.cpp",
        "t_display_s3_buttons.cpp",
        "t_display_s3_display.cpp",
        "t_display_s3_raster.cpp",
        "t_display_s3_review_state.cpp",
        "t_display_s3_status_frames.cpp",
        "approval_gate.cpp",
        "device_protocol.cpp",
        "nip19_nsec.cpp",
        "qr_envelope.cpp",
        "qr_review.cpp",
        "qr_review_flow.cpp",
        "review_controls.cpp",
        "review_display.cpp",
        "serial_frame.cpp",
        "serial_review.cpp",
        "sha256.cpp",
        "signing_policy.cpp",
        "trusted_review.cpp",
    ):
        if required_source not in component_cmake:
            raise ValueError(f"{project}: ESP-IDF component must compile {required_source}")
    lowered = main.lower()
    for claim in FORBIDDEN_CLAIMS:
        if claim in lowered:
            raise ValueError(f"{project}: forbidden unsupported firmware claim: {claim}")
    validate_security_profile(project / "security_profile.json")


def validate_security_profile(path: Path) -> None:
    profile = json.loads(path.read_text(encoding="utf-8"))
    if profile.get("schema") != "nsealr-esp32-security-profile-v0":
        raise ValueError(f"{path}: schema must be nsealr-esp32-security-profile-v0")
    if profile.get("target") != "esp32_s3_usb_signer":
        raise ValueError(f"{path}: target must be esp32_s3_usb_signer")
    if profile.get("production_signing_allowed") is not False:
        raise ValueError(f"{path}: production signing cannot be allowed by the v0 security profile")
    if profile.get("profile") != "development_scaffold":
        raise ValueError(f"{path}: v0 profile must remain development_scaffold")
    if profile.get("runtime_signing_feature_enabled") is not False:
        raise ValueError(f"{path}: runtime signing feature must remain disabled")

    secure_boot = profile.get("secure_boot")
    if not isinstance(secure_boot, dict) or secure_boot.get("enabled") is not False:
        raise ValueError(f"{path}: secure_boot.enabled must be false until production hardening")
    flash_encryption = profile.get("flash_encryption")
    if not isinstance(flash_encryption, dict) or flash_encryption.get("enabled") is not False:
        raise ValueError(f"{path}: flash_encryption.enabled must be false until production hardening")
    debug_access = profile.get("debug_access")
    if not isinstance(debug_access, dict) or debug_access.get("locked") is not False:
        raise ValueError(f"{path}: debug_access.locked must be false for the development scaffold")

    key_provisioning = profile.get("key_provisioning")
    if not isinstance(key_provisioning, dict) or not key_provisioning.get("status"):
        raise ValueError(f"{path}: key_provisioning.status is required")
    if key_provisioning.get("persistent_secret_storage") != "not_implemented":
        raise ValueError(f"{path}: persistent secret storage must remain not_implemented")

    blockers = profile.get("production_blockers")
    if not isinstance(blockers, list):
        raise ValueError(f"{path}: production_blockers must be a list")
    missing_blockers = REQUIRED_SECURITY_BLOCKERS - set(blockers)
    if missing_blockers:
        missing = ", ".join(sorted(missing_blockers))
        raise ValueError(f"{path}: missing production blockers: {missing}")

    _validate_manual_acceptance_evidence(path, profile, "trusted_review_display")
    _require_non_empty_string_list(
        profile.get("display_review_protocol_evidence"),
        path,
        "display_review_protocol_evidence",
    )
    _validate_unicode_review_rendering(path, profile)
    _require_non_empty_string_list(
        profile.get("companion_transport_evidence"),
        path,
        "companion_transport_evidence",
    )
    _require_non_empty_string_list(
        profile.get("firmware_protocol_evidence"),
        path,
        "firmware_protocol_evidence",
    )
    _require_non_empty_string_list(
        profile.get("security_fuse_audit_evidence"),
        path,
        "security_fuse_audit_evidence",
    )
    physical_controls = _validate_manual_acceptance_evidence(path, profile, "physical_approval_controls")
    if physical_controls.get("touch_approval_allowed") is not False:
        raise ValueError(f"{path}: physical_approval_controls.touch_approval_allowed must be false")


def validate_board_profile(path: Path) -> None:
    profile = json.loads(path.read_text(encoding="utf-8"))
    for field in ("name", "status"):
        if not profile.get(field):
            raise ValueError(f"{path}: missing {field}")
    if profile.get("target") != "esp32s3":
        raise ValueError(f"{path}: target must be esp32s3")
    if profile.get("native_usb") is not True:
        raise ValueError(f"{path}: native_usb must be true for the S3 USB signer line")
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


def validate_board_profiles(board_dir: Path) -> None:
    profiles = sorted(board_dir.glob("*.json"))
    if not profiles:
        raise ValueError(f"{board_dir}: missing board profiles")
    for profile in profiles:
        validate_board_profile(profile)


def main() -> int:
    validate_firmware_project(ROOT / "firmware/esp32_s3_usb_signer")
    validate_board_profiles(ROOT / "boards")
    print("nSealr ESP32 firmware validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
