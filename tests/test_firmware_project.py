import base64
import json
import shutil
import subprocess
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts import detect_esp32_s3
from scripts import manual_review_display
from scripts import smoke_capabilities
from scripts import smoke_review_scenarios
from scripts import validate_firmware
from scripts.validate_firmware import validate_firmware_project


ROOT = Path(__file__).resolve().parents[1]


def specs_dir() -> Path:
    sibling = ROOT.parent / "specs"
    if sibling.exists():
        return sibling
    return ROOT / "tests/fixtures/specs"


def decode_serial_frame_payload(frame: str) -> dict:
    payload = frame.strip().split(":")[2]
    padded = payload + ("=" * ((4 - len(payload) % 4) % 4))
    return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))


class FirmwareProjectValidationTests(unittest.TestCase):
    def test_esp32_s3_usb_signer_project_is_valid(self) -> None:
        validate_firmware_project(ROOT / "firmware/esp32_s3_usb_signer")

    def test_esp32_s3_usb_signer_defaults_match_observed_flash_size(self) -> None:
        sdkconfig_defaults = (ROOT / "firmware/esp32_s3_usb_signer/sdkconfig.defaults").read_text(
            encoding="utf-8"
        )

        self.assertIn("CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y", sdkconfig_defaults)
        self.assertNotIn("CONFIG_ESPTOOLPY_FLASHSIZE_8MB=y", sdkconfig_defaults)

    def test_esp32_s3_usb_signer_console_uses_native_usb_serial_jtag(self) -> None:
        sdkconfig_defaults = (ROOT / "firmware/esp32_s3_usb_signer/sdkconfig.defaults").read_text(
            encoding="utf-8"
        )

        self.assertIn("CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y", sdkconfig_defaults)
        self.assertNotIn("CONFIG_ESP_CONSOLE_UART_DEFAULT=y", sdkconfig_defaults)

    def test_makefile_exposes_repeatable_idf_hardware_targets(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertIn("idf-build:", makefile)
        self.assertIn("idf-flash:", makefile)
        self.assertIn("idf-monitor:", makefile)
        self.assertIn("idf-smoke-capabilities:", makefile)
        self.assertIn("idf-smoke-review-scenarios:", makefile)
        self.assertIn("idf-audit-security-fuses:", makefile)
        self.assertIn("idf-env-check:", makefile)

    def test_identity_policy_docs_pin_esp32_route_split(self) -> None:
        specs = specs_dir()
        qr_account = json.loads(
            (specs / "vectors/accounts/esp32-qr-nip06-account-0.json").read_text(encoding="utf-8")
        )
        qr_policy = json.loads((specs / "vectors/policies/manual-only-qr-vault.json").read_text(encoding="utf-8"))
        qr_selection = json.loads(
            (specs / "vectors/route-selections/esp32-qr-sign-event-account-0.json").read_text(encoding="utf-8")
        )
        qr_recovery_source = json.loads(
            (specs / qr_account["recovery"]["source_vector"]).read_text(encoding="utf-8")
        )
        usb_account = json.loads(
            (specs / "vectors/accounts/esp32-usb-device-slot-0.json").read_text(encoding="utf-8")
        )
        usb_default_policy = json.loads(
            (specs / "vectors/policies/manual-only-persistent-device.json").read_text(encoding="utf-8")
        )
        usb_scoped_policy = json.loads(
            (specs / "vectors/policies/scoped-automation-daily-use.json").read_text(encoding="utf-8")
        )
        usb_selection = json.loads(
            (specs / "vectors/route-selections/esp32-usb-sign-event-slot-0.json").read_text(encoding="utf-8")
        )
        usb_policy_change = json.loads(
            (specs / "vectors/policy-changes/esp32-usb-enable-kind-1-automation.json").read_text(
                encoding="utf-8"
            )
        )
        grant = json.loads((specs / "vectors/grants/esp32-usb-kind-1-session.json").read_text(encoding="utf-8"))

        self.assertEqual(qr_account["signer_route"]["type"], "esp32_qr_vault")
        self.assertEqual(qr_account["signer_route"]["repository"], "esp32")
        self.assertEqual(qr_account["signer_route"]["transport"], "qr")
        self.assertEqual(qr_account["signer_route"]["custody"], "stateless_session")
        self.assertEqual(qr_account["signer_route"]["trusted_review"], "device_display")
        self.assertEqual(qr_account["signer_route"]["policy_support"], "manual_only")
        self.assertEqual(qr_account["recovery"]["type"], "nip06")
        self.assertEqual(qr_account["recovery"]["source_vector"], "vectors/keys/nip06-account-0-leader.json")
        self.assertEqual(qr_account["public_key"], qr_recovery_source["public_key"])
        self.assertEqual(qr_account["recovery"]["source_fingerprint"], "cd64b58daca009b9")
        self.assertFalse(qr_account["capabilities"]["persistent_grants"])
        self.assertEqual(qr_policy["policy_id"], qr_account["policy_profile_id"])
        self.assertEqual(qr_selection["selection"]["account_id"], qr_account["account_id"])
        self.assertEqual(qr_selection["selection"]["public_key"], qr_account["public_key"])
        self.assertEqual(qr_selection["selection"]["route_type"], qr_account["signer_route"]["type"])
        self.assertEqual(qr_selection["selection"]["transport"], qr_account["signer_route"]["transport"])
        self.assertEqual(qr_selection["selection"]["custody"], qr_account["signer_route"]["custody"])
        self.assertFalse(qr_selection["selection"]["persistent_grants"])
        self.assertFalse(qr_selection["selection"]["contains_secret_material"])

        self.assertEqual(usb_account["signer_route"]["type"], "esp32_usb_nip46")
        self.assertEqual(usb_account["signer_route"]["repository"], "esp32")
        self.assertEqual(usb_account["signer_route"]["transport"], "usb")
        self.assertEqual(usb_account["signer_route"]["custody"], "device_persistent")
        self.assertEqual(usb_account["signer_route"]["trusted_review"], "device_display")
        self.assertEqual(usb_account["signer_route"]["policy_support"], "scoped_automation")
        self.assertTrue(usb_account["capabilities"]["persistent_grants"])
        self.assertEqual(usb_default_policy["policy_id"], usb_account["policy_profile_id"])
        self.assertEqual(usb_default_policy["mode"], "manual_only")
        self.assertFalse(usb_default_policy["grants_allowed"])
        self.assertIn("policy_change", usb_default_policy["manual_review_required"])
        self.assertNotIn("smartcard", usb_default_policy["route_types"])
        self.assertNotIn("smartcard", usb_scoped_policy["route_types"])
        self.assertEqual(usb_selection["selection"]["account_id"], usb_account["account_id"])
        self.assertEqual(usb_selection["selection"]["route_type"], usb_account["signer_route"]["type"])
        self.assertEqual(usb_selection["selection"]["transport"], usb_account["signer_route"]["transport"])
        self.assertEqual(usb_selection["selection"]["custody"], usb_account["signer_route"]["custody"])
        self.assertEqual(usb_selection["selection"]["policy_profile_id"], usb_default_policy["policy_id"])
        self.assertTrue(usb_selection["selection"]["persistent_grants"])
        self.assertFalse(usb_selection["selection"]["contains_secret_material"])
        self.assertEqual(grant["route_type"], "esp32_usb_nip46")
        self.assertEqual(grant["permission"], {"method": "sign_event", "parameter": "1", "event_kind": 1})
        self.assertEqual(usb_policy_change["proposal"]["account_id"], usb_account["account_id"])
        self.assertEqual(usb_policy_change["proposal"]["route_type"], usb_account["signer_route"]["type"])
        self.assertEqual(usb_policy_change["proposal"]["current_policy_id"], usb_default_policy["policy_id"])
        self.assertEqual(usb_policy_change["proposal"]["proposed_policy_id"], usb_scoped_policy["policy_id"])
        self.assertFalse(usb_policy_change["proposal"]["companion_authoritative"])
        self.assertTrue(usb_policy_change["proposal"]["device_review_required"])
        self.assertTrue(usb_policy_change["proposal"]["physical_approval_required"])

        docs = "\n".join(
            [
                (ROOT / "README.md").read_text(encoding="utf-8"),
                (ROOT / "docs/architecture.md").read_text(encoding="utf-8"),
                (ROOT / "docs/roadmap.md").read_text(encoding="utf-8"),
                (ROOT / "docs/security.md").read_text(encoding="utf-8"),
                (ROOT / "docs/testing.md").read_text(encoding="utf-8"),
            ]
        )
        self.assertIn("nsealr-account-descriptor-v0", docs)
        self.assertIn("esp32-qr-nip06-account-0", docs)
        self.assertIn("esp32-qr-sign-event-account-0", docs)
        self.assertIn("policy-manual-only-qr-vault", docs)
        self.assertIn("esp32_usb_nip46", docs)
        self.assertIn("esp32-usb-device-slot-0", docs)
        self.assertIn("esp32-usb-sign-event-slot-0", docs)
        self.assertIn("policy-manual-only-persistent-device", docs)
        self.assertIn("esp32-usb-enable-kind-1-automation", docs)
        self.assertIn("policy-scoped-automation-daily-use", docs)
        self.assertIn("grant-esp32-usb-kind-1-session", docs)
        self.assertIn("esp32_qr_vault", docs)
        self.assertIn("persistent_grants: false", docs)
        self.assertIn("signing remains disabled", docs)
        self.assertNotIn("legacy backward review", docs)

    def test_security_fuse_audit_parses_development_board_state(self) -> None:
        from scripts import audit_security_fuses

        sample_summary = """
SECURE_BOOT_EN (BLOCK0)                            Set this bit to enable secure boot                 = False R/W (0b0)
SPI_BOOT_CRYPT_CNT (BLOCK0)                        Enables flash encryption when 1 or 3 bits are set  = Disable R/W (0b000)
DIS_PAD_JTAG (BLOCK0)                              Set this bit to disable JTAG in the hard way. JTAG = False R/W (0b0)
DIS_USB_JTAG (BLOCK0)                              Set this bit to disable function of usb switch to  = False R/W (0b0)
DIS_USB_SERIAL_JTAG (BLOCK0)                       Set this bit to disable usb device                 = False R/W (0b0)
DIS_DOWNLOAD_MODE (BLOCK0)                         Set this bit to disable download mode              = False R/W (0b0)
DIS_DOWNLOAD_MANUAL_ENCRYPT (BLOCK0)               Set this bit to disable flash encryption when in d = False R/W (0b0)
ENABLE_SECURITY_DOWNLOAD (BLOCK0)                  Set this bit to enable secure UART download mode   = False R/W (0b0)
"""

        audit = audit_security_fuses.parse_espefuse_summary(sample_summary, port="/dev/cu.usbmodem1101")

        self.assertEqual(audit["schema"], "nsealr-esp32-security-fuse-audit-v0")
        self.assertEqual(audit["target"], "esp32s3")
        self.assertEqual(audit["port"], "/dev/cu.usbmodem1101")
        self.assertFalse(audit["secure_boot_enabled"])
        self.assertFalse(audit["flash_encryption_enabled"])
        self.assertFalse(audit["download_mode_disabled"])
        self.assertFalse(audit["manual_flash_encryption_download_disabled"])
        self.assertFalse(audit["debug_access_locked"])
        self.assertTrue(audit["development_usb_jtag_available"])
        self.assertIn("secure_boot", audit["production_blockers"])
        self.assertIn("flash_encryption", audit["production_blockers"])
        self.assertIn("debug_lock", audit["production_blockers"])

    def test_security_fuse_audit_uses_read_only_espefuse_summary(self) -> None:
        from scripts import audit_security_fuses

        command = audit_security_fuses.build_espefuse_summary_command("/dev/cu.usbmodem1101")

        self.assertEqual(command, ["espefuse.py", "--chip", "esp32s3", "--port", "/dev/cu.usbmodem1101", "summary"])
        self.assertNotIn("burn_efuse", command)
        self.assertNotIn("burn_key", command)

    def test_acceptance_report_builds_non_production_hardware_evidence(self) -> None:
        self.assertTrue((ROOT / "scripts/acceptance_report.py").exists())
        from scripts import acceptance_report

        capability_response = smoke_capabilities.load_capability_frames()[1]
        review_response = smoke_capabilities.load_signing_disabled_frames()[1]
        rejection_frame = smoke_capabilities.encode_serial_frame(
            "error",
            smoke_capabilities.base64url_json(smoke_capabilities.UNSUPPORTED_REQUEST_ERROR),
        )
        fuse_audit = {
            "schema": "nsealr-esp32-security-fuse-audit-v0",
            "target": "esp32s3",
            "port": "/dev/cu.usbmodem1101",
            "read_only": True,
            "production_blockers": ["secure_boot", "flash_encryption", "debug_lock"],
            "production_signing_ready": False,
        }

        report = acceptance_report.build_acceptance_report(
            port="/dev/cu.usbmodem1101",
            source_revision="981ca56",
            firmware_revision="3a67803",
            capability_frames=[capability_response, rejection_frame],
            review_frames=[review_response, rejection_frame],
            review_scenarios=("show-review", "show-request-error"),
            fuse_audit=fuse_audit,
            manual_observation="passed",
            hard_reset_after_fuse_audit=True,
        )

        self.assertEqual(report["schema"], "nsealr-esp32-t-display-s3-acceptance-report-v0")
        self.assertEqual(report["target"], "t-display-s3-usb-display-signer")
        self.assertEqual(report["port"], "/dev/cu.usbmodem1101")
        self.assertEqual(report["source_revision"], "981ca56")
        self.assertEqual(report["firmware_revision"], "3a67803")
        self.assertEqual(report["capability_smoke"]["verified_exchanges"], 2)
        self.assertEqual(report["capability_smoke"]["response_frames"], 1)
        self.assertEqual(report["capability_smoke"]["expected_rejection_frames"], 1)
        self.assertEqual(report["review_scenario_smoke"]["scenarios"], ["show-review", "show-request-error"])
        self.assertEqual(report["review_scenario_smoke"]["verified_exchanges"], 2)
        self.assertEqual(report["manual_display_button_observation"]["status"], "passed")
        self.assertIn("show-dense-tags", report["manual_display_button_observation"]["required_scenarios"])
        self.assertIs(report["security_fuse_audit"]["read_only"], True)
        self.assertEqual(report["security_fuse_audit"]["production_blockers"], ["secure_boot", "flash_encryption", "debug_lock"])
        self.assertFalse(report["production_signing_ready"])
        self.assertFalse(report["signing_enabled"])
        self.assertTrue(report["post_fuse_audit_hard_reset_performed"])

    def test_makefile_exposes_repeatable_acceptance_report_target(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertIn("idf-acceptance-report:", makefile)
        self.assertIn("scripts/acceptance_report.py", makefile)
        self.assertIn("IDF_ACCEPTANCE_MANUAL", makefile)
        self.assertIn("IDF_FIRMWARE_REVISION", makefile)

    def test_esp32_s3_usb_signer_builds_host_core_protocol(self) -> None:
        cmake = (ROOT / "firmware/esp32_s3_usb_signer/main/CMakeLists.txt").read_text(encoding="utf-8")
        main = (ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp").read_text(encoding="utf-8")

        self.assertTrue((ROOT / "tests/fixtures/specs/vectors/keys/nip06-account-0-leader.json").exists())
        self.assertTrue(
            (ROOT / "tests/fixtures/specs/vectors/source-public-key-proofs/nip06-account-0-leader.json").exists()
        )
        self.assertTrue(
            (ROOT / "tests/fixtures/specs/vectors/source-public-key-proofs/nsec-test-key-1.json").exists()
        )
        self.assertIn("device_protocol.cpp", cmake)
        self.assertIn("approval_gate.cpp", cmake)
        self.assertIn("bip39_english.cpp", cmake)
        self.assertIn("nip19_nsec.cpp", cmake)
        self.assertIn("qr_envelope.cpp", cmake)
        self.assertIn("serial_frame.cpp", cmake)
        self.assertIn("serial_review.cpp", cmake)
        self.assertIn("seedqr.cpp", cmake)
        self.assertIn("session_import_flow.cpp", cmake)
        self.assertIn("session_import_review.cpp", cmake)
        self.assertIn("session_keyring.cpp", cmake)
        self.assertIn("session_source_generation.cpp", cmake)
        self.assertIn("review_display.cpp", cmake)
        self.assertIn("signing_policy.cpp", cmake)
        self.assertIn("trusted_review.cpp", cmake)
        self.assertIn("sha256.cpp", cmake)
        self.assertIn("handle_serial_frame", main)
        self.assertIn("Signing is disabled", main)

    def test_esp32_s3_usb_signer_security_profile_is_development_only(self) -> None:
        profile_path = ROOT / "firmware/esp32_s3_usb_signer/security_profile.json"

        self.assertTrue(profile_path.exists(), "missing ESP32-S3 USB signer security profile")
        validate_firmware.validate_security_profile(profile_path)

        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        self.assertEqual(profile["schema"], "nsealr-esp32-security-profile-v0")
        self.assertFalse(profile["runtime_signing_feature_enabled"])
        self.assertFalse(profile["production_signing_allowed"])
        self.assertFalse(profile["secure_boot"]["enabled"])
        self.assertFalse(profile["flash_encryption"]["enabled"])
        self.assertFalse(profile["debug_access"]["locked"])
        self.assertIn("secure_boot", profile["production_blockers"])
        self.assertIn("debug_lock", profile["production_blockers"])
        self.assertIn("key_provisioning", profile["production_blockers"])
        self.assertIn("trusted_review_display", profile["production_blockers"])
        self.assertIn("physical_approval_controls", profile["production_blockers"])
        self.assertIn("unicode_review_rendering", profile["production_blockers"])
        self.assertIn("source_public_key_proof", profile["production_blockers"])
        self.assertEqual(profile["source_public_key_proof"]["status"], "not_implemented")
        self.assertTrue(profile["source_public_key_proof"]["required_before_signing"])
        self.assertEqual(profile["unicode_review_rendering"]["status"], "ascii_safe_codepoint_fallback_only")
        self.assertTrue(profile["unicode_review_rendering"]["required_before_signing"])
        self.assertEqual(
            profile["unicode_review_rendering"]["production_claim"],
            "blocked_until_full_unicode_review_acceptance",
        )
        self.assertTrue(profile["unicode_review_rendering"]["evidence_reports"])
        self.assertEqual(
            profile["trusted_review_display"]["status"],
            "manual_development_acceptance_passed",
        )
        self.assertEqual(
            profile["trusted_review_display"]["production_claim"],
            "blocked_until_production_acceptance",
        )
        self.assertTrue(profile["trusted_review_display"]["evidence_reports"])
        self.assertEqual(
            profile["display_review_protocol_evidence"],
            [
                "nSealr/hardware/reports/t-display-s3-review-detail-pages-smoke-2026-05-10.json",
                "nSealr/hardware/reports/t-display-s3-utf8-review-renderer-smoke-2026-05-10.json",
                "nSealr/hardware/reports/t-display-s3-ascii-punctuation-renderer-smoke-2026-05-10.json",
                "nSealr/hardware/reports/t-display-s3-ascii-punctuation-glyph-smoke-2026-05-11.json",
                "nSealr/hardware/reports/t-display-s3-dense-tags-review-smoke-2026-05-10.json",
                "nSealr/hardware/reports/t-display-s3-current-head-smoke-2026-05-10.json",
                "nSealr/hardware/reports/t-display-s3-value-line-color-smoke-2026-05-11.json",
                "nSealr/hardware/reports/t-display-s3-control-escape-renderer-smoke-2026-05-11.json",
                "nSealr/hardware/reports/t-display-s3-control-escape-scenario-smoke-2026-05-11.json",
            ],
        )
        self.assertEqual(
            profile["companion_transport_evidence"],
            [
                "nSealr/hardware/reports/t-display-s3-companion-serial-line-smoke-2026-05-11.json",
                "nSealr/hardware/reports/t-display-s3-companion-serial-line-refactor-smoke-2026-05-11.json",
            ],
        )
        self.assertEqual(
            profile["firmware_protocol_evidence"],
            [
                "nSealr/hardware/reports/t-display-s3-disabled-copy-smoke-2026-05-11.json",
                "nSealr/hardware/reports/t-display-s3-unicode-signing-gate-smoke-2026-05-11.json",
                "nSealr/hardware/reports/t-display-s3-signing-status-dedup-smoke-2026-05-11.json",
                "nSealr/hardware/reports/t-display-s3-ascii-punctuation-glyph-smoke-2026-05-11.json",
                "nSealr/hardware/reports/t-display-s3-unsupported-serial-type-smoke-2026-05-11.json",
                "nSealr/hardware/reports/t-display-s3-detail-scroll-contract-smoke-2026-05-11.json",
                "nSealr/hardware/reports/t-display-s3-value-line-color-smoke-2026-05-11.json",
            ],
        )
        self.assertEqual(
            profile["security_fuse_audit_evidence"],
            ["nSealr/hardware/reports/t-display-s3-security-fuse-audit-2026-05-11.json"],
        )
        self.assertEqual(
            profile["physical_approval_controls"]["status"],
            "manual_development_acceptance_passed",
        )
        self.assertEqual(
            profile["physical_approval_controls"]["production_claim"],
            "blocked_until_production_acceptance",
        )
        self.assertIs(profile["physical_approval_controls"]["touch_approval_allowed"], False)
        self.assertTrue(profile["physical_approval_controls"]["evidence_reports"])

    def test_security_profile_matches_shared_hardening_vector(self) -> None:
        vector = json.loads(
            (specs_dir() / "vectors/devices/esp32-s3-security-profile-development.json").read_text(
                encoding="utf-8"
            )
        )
        profile = json.loads(
            (ROOT / "firmware/esp32_s3_usb_signer/security_profile.json").read_text(encoding="utf-8")
        )
        boundary = vector["current_boundary"]

        self.assertEqual(profile["schema"], boundary["schema"])
        self.assertEqual(profile["target"], vector["target"])
        self.assertEqual(profile["profile"], vector["profile"])
        self.assertEqual(profile["runtime_signing_feature_enabled"], boundary["runtime_signing_feature_enabled"])
        self.assertEqual(profile["production_signing_allowed"], boundary["production_signing_allowed"])
        self.assertEqual(profile["secure_boot"]["enabled"], boundary["secure_boot_enabled"])
        self.assertEqual(profile["flash_encryption"]["enabled"], boundary["flash_encryption_enabled"])
        self.assertEqual(profile["debug_access"]["locked"], boundary["debug_access_locked"])
        self.assertEqual(
            profile["key_provisioning"]["persistent_secret_storage"],
            boundary["persistent_secret_storage"],
        )

        for section in vector["required_profile_sections"]:
            self.assertIn(section, profile)
        for blocker in vector["required_production_blockers"]:
            self.assertIn(blocker, profile["production_blockers"])

        self.assertIn("validated_development_security_profile", vector["implemented_controls"])
        self.assertIn("read_only_efuse_audit_report", vector["implemented_controls"])
        self.assertIn("production_signing", vector["not_implemented_controls"])
        self.assertIn("source_public_key_proof", vector["not_implemented_controls"])
        self.assertIn("secure_boot_enabled", vector["not_implemented_controls"])

    def test_security_profile_validator_rejects_production_signing_without_hardening(self) -> None:
        with TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "security_profile.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "schema": "nsealr-esp32-security-profile-v0",
                        "target": "esp32_s3_usb_signer",
                        "profile": "production",
                        "runtime_signing_feature_enabled": True,
                        "production_signing_allowed": True,
                        "secure_boot": {"enabled": False},
                        "flash_encryption": {"enabled": False},
                        "debug_access": {"locked": False},
                        "key_provisioning": {"status": "development_fixed_key"},
                        "production_blockers": [],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "production signing cannot be allowed"):
                validate_firmware.validate_security_profile(profile_path)

    def test_security_profile_validator_requires_display_and_control_acceptance_evidence(self) -> None:
        profile = json.loads((ROOT / "firmware/esp32_s3_usb_signer/security_profile.json").read_text(encoding="utf-8"))

        with TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "security_profile.json"
            missing_display = dict(profile)
            missing_display.pop("trusted_review_display", None)
            profile_path.write_text(json.dumps(missing_display), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "trusted_review_display"):
                validate_firmware.validate_security_profile(profile_path)

        with TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "security_profile.json"
            missing_controls = dict(profile)
            missing_controls.pop("physical_approval_controls", None)
            profile_path.write_text(json.dumps(missing_controls), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "physical_approval_controls"):
                validate_firmware.validate_security_profile(profile_path)

        with TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "security_profile.json"
            missing_protocol_evidence = dict(profile)
            missing_protocol_evidence.pop("display_review_protocol_evidence", None)
            profile_path.write_text(json.dumps(missing_protocol_evidence), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "display_review_protocol_evidence"):
                validate_firmware.validate_security_profile(profile_path)

        with TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "security_profile.json"
            missing_companion_transport_evidence = dict(profile)
            missing_companion_transport_evidence.pop("companion_transport_evidence", None)
            profile_path.write_text(json.dumps(missing_companion_transport_evidence), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "companion_transport_evidence"):
                validate_firmware.validate_security_profile(profile_path)

        with TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "security_profile.json"
            missing_firmware_protocol_evidence = dict(profile)
            missing_firmware_protocol_evidence.pop("firmware_protocol_evidence", None)
            profile_path.write_text(json.dumps(missing_firmware_protocol_evidence), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "firmware_protocol_evidence"):
                validate_firmware.validate_security_profile(profile_path)

        with TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "security_profile.json"
            missing_security_fuse_audit_evidence = dict(profile)
            missing_security_fuse_audit_evidence.pop("security_fuse_audit_evidence", None)
            profile_path.write_text(json.dumps(missing_security_fuse_audit_evidence), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "security_fuse_audit_evidence"):
                validate_firmware.validate_security_profile(profile_path)

        with TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "security_profile.json"
            missing_unicode_rendering = dict(profile)
            missing_unicode_rendering.pop("unicode_review_rendering", None)
            profile_path.write_text(json.dumps(missing_unicode_rendering), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "unicode_review_rendering"):
                validate_firmware.validate_security_profile(profile_path)

        with TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "security_profile.json"
            missing_source_key_proof = dict(profile)
            missing_source_key_proof.pop("source_public_key_proof", None)
            profile_path.write_text(json.dumps(missing_source_key_proof), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "source_public_key_proof"):
                validate_firmware.validate_security_profile(profile_path)

    def test_firmware_validator_requires_serial_review_component(self) -> None:
        with TemporaryDirectory() as tmp:
            project = Path(tmp) / "esp32_s3_usb_signer"
            shutil.copytree(
                ROOT / "firmware/esp32_s3_usb_signer",
                project,
                ignore=shutil.ignore_patterns("build"),
            )
            cmake_path = project / "main/CMakeLists.txt"
            cmake_path.write_text(
                cmake_path.read_text(encoding="utf-8").replace(
                    '        "../../host_core/src/serial_review.cpp"\n',
                    "",
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "serial_review.cpp"):
                validate_firmware_project(project)

    def test_lilygo_t_display_s3_pro_ov5640_board_profile_documents_qr_constraints(self) -> None:
        profile_path = ROOT / "boards/lilygo_t_display_s3_pro_ov5640.json"

        self.assertTrue(profile_path.exists(), "missing T-Display S3 Pro OV5640 board profile")
        validate_firmware.validate_board_profile(profile_path)

        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        self.assertEqual(profile["target"], "esp32s3")
        self.assertEqual(profile["status"], "primary_qr_vault_candidate")
        self.assertEqual(profile["camera"]["module"], "OV5640")
        self.assertTrue(profile["camera"]["required_for_qr"])
        self.assertEqual(profile["display"]["driver"], "ST7796U")
        self.assertFalse(profile["display"]["touch"]["approval_allowed"])
        self.assertIn("Wireless must be disabled", profile["wireless_policy"])
        self.assertEqual(
            {approval_input["name"] for approval_input in profile["approval_inputs"]},
            {"approve", "reject"},
        )

    def test_waveshare_esp32_s3_touch_lcd_3_5b_c_board_profile_documents_qr_constraints(self) -> None:
        profile_path = ROOT / "boards/waveshare_esp32_s3_touch_lcd_3_5b_c.json"

        self.assertTrue(profile_path.exists(), "missing Waveshare ESP32-S3 Touch LCD 3.5B-C board profile")
        validate_firmware.validate_board_profile(profile_path)

        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        self.assertEqual(profile["target"], "esp32s3")
        self.assertEqual(profile["status"], "secondary_qr_vault_candidate")
        self.assertEqual(profile["variant"], "case_with_ov5640_camera")
        self.assertEqual(profile["accepted_skus"], ["ESP32-S3-Touch-LCD-3.5B-C"])
        self.assertEqual(profile["camera"]["module"], "OV5640")
        self.assertTrue(profile["camera"]["required_for_qr"])
        self.assertEqual(profile["display"]["resolution"]["short_edge"], 320)
        self.assertEqual(profile["display"]["resolution"]["long_edge"], 480)
        self.assertEqual(profile["display"]["driver"], "AXS15231B")
        self.assertEqual(profile["display"]["connection"], "QSPI")
        self.assertFalse(profile["display"]["touch"]["approval_allowed"])
        self.assertIn("Wireless must be disabled", profile["wireless_policy"])
        self.assertEqual(
            {approval_input["name"] for approval_input in profile["approval_inputs"]},
            {"approve", "reject"},
        )

    def test_lilygo_t_display_s3_board_profile_documents_usb_display_constraints(self) -> None:
        profile_path = ROOT / "boards/lilygo_t_display_s3.json"

        self.assertTrue(profile_path.exists(), "missing T-Display S3 board profile")
        validate_firmware.validate_board_profile(profile_path)

        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        self.assertEqual(profile["target"], "esp32s3")
        self.assertEqual(profile["status"], "usb_display_signer_candidate")
        self.assertEqual(profile["display"]["driver"], "ST7789")
        self.assertEqual(profile["display"]["connection"], "integrated_8_bit_parallel_tft")
        self.assertEqual(profile["display"]["resolution"]["short_edge"], 170)
        self.assertEqual(profile["display"]["resolution"]["long_edge"], 320)
        self.assertEqual(profile["display"]["backlight"]["gpio"], 38)
        self.assertEqual(profile["display"]["display_power"]["gpio"], 15)
        self.assertNotIn("camera", profile)
        self.assertEqual(
            {approval_input["name"] for approval_input in profile["approval_inputs"]},
            {"approve", "reject"},
        )

    def test_t_display_s3_firmware_board_config_matches_profile(self) -> None:
        profile = json.loads((ROOT / "boards/lilygo_t_display_s3.json").read_text(encoding="utf-8"))
        header_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_board.hpp"
        source_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_board.cpp"
        cmake = (ROOT / "firmware/esp32_s3_usb_signer/main/CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        main = (ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp").read_text(encoding="utf-8")

        self.assertTrue(header_path.exists(), "missing T-Display S3 firmware board config header")
        self.assertTrue(source_path.exists(), "missing T-Display S3 firmware board config source")
        self.assertIn("t_display_s3_board.cpp", cmake)
        self.assertIn("t_display_s3_board_profile", main)

        header = header_path.read_text(encoding="utf-8")
        source = source_path.read_text(encoding="utf-8")
        self.assertIn(f"kTDisplayS3DisplayWidth = {profile['display']['resolution']['short_edge']}", header)
        self.assertIn(f"kTDisplayS3DisplayHeight = {profile['display']['resolution']['long_edge']}", header)
        self.assertIn(f"kTDisplayS3BacklightGpio = {profile['display']['backlight']['gpio']}", header)
        self.assertIn(f"kTDisplayS3DisplayPowerGpio = {profile['display']['display_power']['gpio']}", header)
        self.assertIn('"LILYGO T-Display S3"', source)
        self.assertIn('"ST7789"', source)
        self.assertIn("touch_approval_allowed = false", source)
        self.assertIn("camera_present = false", source)

    def test_t_display_s3_firmware_initializes_real_display_driver(self) -> None:
        display_header_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_display.hpp"
        display_source_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_display.cpp"
        board_header = (ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_board.hpp").read_text(
            encoding="utf-8"
        )
        cmake = (ROOT / "firmware/esp32_s3_usb_signer/main/CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        main = (ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp").read_text(encoding="utf-8")

        self.assertTrue(display_header_path.exists(), "missing T-Display S3 display driver header")
        self.assertTrue(display_source_path.exists(), "missing T-Display S3 display driver source")
        self.assertIn("t_display_s3_display.cpp", cmake)
        self.assertIn("PRIV_REQUIRES", cmake)
        self.assertIn("esp_lcd", cmake)
        self.assertIn("esp_driver_gpio", cmake)
        self.assertIn("t_display_s3_display.hpp", main)
        self.assertIn("initialize_t_display_s3_display", main)
        self.assertIn("draw_t_display_s3_boot_frame", main)
        self.assertIn("Signing is disabled", main)

        for pin_constant in (
            "kTDisplayS3DisplayResetGpio = 5",
            "kTDisplayS3DisplayCsGpio = 6",
            "kTDisplayS3DisplayDcGpio = 7",
            "kTDisplayS3DisplayWriteGpio = 8",
            "kTDisplayS3DisplayReadGpio = 9",
            "kTDisplayS3DisplayData0Gpio = 39",
            "kTDisplayS3DisplayData7Gpio = 48",
            "kTDisplayS3LogicalDisplayWidth = 320",
            "kTDisplayS3LogicalDisplayHeight = 170",
            "kTDisplayS3LogicalDisplayXGap = 0",
            "kTDisplayS3LogicalDisplayYGap = 35",
        ):
            self.assertIn(pin_constant, board_header)

        display_header = display_header_path.read_text(encoding="utf-8")
        display_source = display_source_path.read_text(encoding="utf-8")
        self.assertIn("display_driver_active", display_header)
        self.assertIn("initialize_t_display_s3_display", display_header)
        self.assertIn("draw_t_display_s3_boot_frame", display_header)
        self.assertIn("esp_lcd_new_i80_bus", display_source)
        self.assertIn("esp_lcd_new_panel_io_i80", display_source)
        self.assertIn("esp_lcd_new_panel_st7789", display_source)
        self.assertIn("esp_lcd_panel_reset", display_source)
        self.assertIn("esp_lcd_panel_init", display_source)
        self.assertIn("esp_lcd_panel_swap_xy(display.panel, true)", display_source)
        self.assertIn("esp_lcd_panel_mirror(display.panel, true, false)", display_source)
        self.assertIn("esp_lcd_panel_disp_on_off", display_source)
        self.assertIn("esp_lcd_panel_draw_bitmap", display_source)
        self.assertIn("wait_for_t_display_s3_color_transfer", display_source)
        self.assertIn("esp_lcd_panel_io_tx_param", display_source)
        self.assertIn("kTDisplayS3LogicalDisplayWidth", display_source)
        self.assertIn("kTDisplayS3LogicalDisplayHeight", display_source)
        self.assertIn("kTDisplayS3BacklightGpio", display_source)
        self.assertIn("kTDisplayS3DisplayPowerGpio", display_source)

    def test_t_display_s3_firmware_renders_host_core_review_frames(self) -> None:
        display_header_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_display.hpp"
        display_source_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_display.cpp"
        raster_header_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_raster.hpp"
        raster_source_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_raster.cpp"
        status_header_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_status_frames.hpp"
        status_source_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_status_frames.cpp"
        main_path = ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp"

        display_header = display_header_path.read_text(encoding="utf-8")
        display_source = display_source_path.read_text(encoding="utf-8")
        raster_header = raster_header_path.read_text(encoding="utf-8")
        raster_source = raster_source_path.read_text(encoding="utf-8")
        status_header = status_header_path.read_text(encoding="utf-8")
        status_source = status_source_path.read_text(encoding="utf-8")
        main = main_path.read_text(encoding="utf-8")

        self.assertIn("t_display_s3_raster.hpp", display_header)
        self.assertIn("draw_t_display_s3_review_frame", display_header)
        self.assertIn("ReviewDisplayFrame", display_header)

        self.assertIn("t_display_s3_boot_frame_color_for", display_source)
        self.assertIn("t_display_s3_review_frame_color_for", display_source)
        self.assertIn("wait_for_t_display_s3_color_transfer", display_source)
        self.assertIn("esp_lcd_panel_draw_bitmap", display_source)

        self.assertIn("nsealr/review_display.hpp", raster_header)
        self.assertIn("t_display_s3_review_limits", raster_header)
        self.assertIn("t_display_s3_review_frame_color_for", raster_header)
        self.assertIn("kTDisplayS3ReviewTitleChars", raster_source)
        self.assertIn("kTDisplayS3ReviewBodyLines", raster_source)
        self.assertIn("kTDisplayS3ReviewLineChars", raster_source)
        self.assertIn("kFooterActionScale = 2", raster_source)
        self.assertIn("kHeaderRightMargin", raster_source)
        self.assertIn("text_width_px", raster_source)
        self.assertIn("right_aligned_text_x", raster_source)
        self.assertNotIn("draw_text(frame.page_indicator, 230", raster_source)
        self.assertIn("text_pixel_active", raster_source)
        self.assertIn("glyph_rows_for", raster_source)

        self.assertIn("nsealr/review_display.hpp", main)
        self.assertIn("handle_serial_frame_with_review_preview", main)
        self.assertIn("display_sign_event_review_preview", main)
        self.assertIn("review_frame", main)
        self.assertIn("t_display_s3_review_limits", main)
        self.assertIn("draw_t_display_s3_review_frame", main)
        self.assertIn("t_display_s3_status_frames.hpp", main)
        self.assertIn("build_t_display_s3_ready_frame", main)
        self.assertIn("build_t_display_s3_ready_frame", status_header)
        self.assertIn('frame.page_indicator = "No request"', status_source)
        self.assertIn('"Send sign_event"', status_source)
        self.assertIn('frame.action_hint = "Waiting"', status_source)
        self.assertNotIn("Content: display test", main)
        self.assertIn("case '_'", raster_source)
        self.assertIn("Signing is disabled", main)

    def test_t_display_s3_firmware_maps_onboard_buttons_without_touch_approval(self) -> None:
        profile = json.loads((ROOT / "boards/lilygo_t_display_s3.json").read_text(encoding="utf-8"))
        board_header = (ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_board.hpp").read_text(
            encoding="utf-8"
        )
        board_source = (ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_board.cpp").read_text(
            encoding="utf-8"
        )
        buttons_header_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_buttons.hpp"
        buttons_source_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_buttons.cpp"
        logic_header_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_button_logic.hpp"
        logic_source_path = ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_button_logic.cpp"
        cmake = (ROOT / "firmware/esp32_s3_usb_signer/main/CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        main = (ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp").read_text(encoding="utf-8")

        self.assertFalse(profile["display"]["touch"]["approval_allowed"])
        self.assertEqual(
            {(entry["name"], entry["gpio"], entry["press"]) for entry in profile["navigation_inputs"]},
            {("back", 0, "short"), ("next", 14, "short")},
        )
        self.assertEqual(
            {(entry["name"], entry["gpio"], entry["press"]) for entry in profile["approval_inputs"]},
            {("reject", 0, "long"), ("approve", 14, "long")},
        )

        self.assertTrue(buttons_header_path.exists(), "missing T-Display S3 button driver header")
        self.assertTrue(buttons_source_path.exists(), "missing T-Display S3 button driver source")
        self.assertTrue(logic_header_path.exists(), "missing T-Display S3 button logic header")
        self.assertTrue(logic_source_path.exists(), "missing T-Display S3 button logic source")
        self.assertIn("t_display_s3_button_logic.cpp", cmake)
        self.assertIn("t_display_s3_buttons.cpp", cmake)
        self.assertIn("esp_timer", cmake)
        self.assertIn("kTDisplayS3Button1Gpio = 0", board_header)
        self.assertIn("kTDisplayS3Button2Gpio = 14", board_header)
        self.assertIn("button1_gpio", board_header)
        self.assertIn("button2_gpio", board_header)
        self.assertIn(".button1_gpio = kTDisplayS3Button1Gpio", board_source)
        self.assertIn(".button2_gpio = kTDisplayS3Button2Gpio", board_source)

        buttons_header = buttons_header_path.read_text(encoding="utf-8")
        buttons_source = buttons_source_path.read_text(encoding="utf-8")
        logic_header = logic_header_path.read_text(encoding="utf-8")
        logic_source = logic_source_path.read_text(encoding="utf-8")
        self.assertIn("t_display_s3_button_logic.hpp", buttons_header)
        self.assertIn("initialize_t_display_s3_buttons", buttons_header)
        self.assertIn("poll_t_display_s3_review_button", buttons_header)
        self.assertIn("TDisplayS3ButtonEvent", logic_header)
        self.assertIn("kTDisplayS3ButtonDebounceMs", logic_header)
        self.assertIn("kTDisplayS3ButtonLongPressMs", logic_header)
        self.assertIn("update_t_display_s3_button_state", logic_header)
        self.assertIn("duration_ms < kTDisplayS3ButtonDebounceMs", logic_source)
        self.assertIn("duration_ms >= kTDisplayS3ButtonLongPressMs", logic_source)
        self.assertIn("update_t_display_s3_button_state", buttons_source)
        self.assertIn("ReviewButton::Back", buttons_source)
        self.assertIn("ReviewButton::Next", buttons_source)
        self.assertIn("ReviewButton::Reject", buttons_source)
        self.assertIn("ReviewButton::Approve", buttons_source)
        self.assertIn("GPIO_PULLUP_ENABLE", buttons_source)
        self.assertIn("gpio_get_level", buttons_source)

        self.assertIn("t_display_s3_buttons.hpp", main)
        self.assertIn("initialize_t_display_s3_buttons", main)
        self.assertIn("poll_t_display_s3_review_button", main)
        self.assertIn("ActiveReviewState active_review", main)
        self.assertIn("Signing remains disabled", main)

    def test_t_display_s3_review_state_helper_expires_activity(self) -> None:
        main_dir = ROOT / "firmware/esp32_s3_usb_signer/main"
        header_path = main_dir / "t_display_s3_review_state.hpp"
        source_path = main_dir / "t_display_s3_review_state.cpp"
        cmake = (main_dir / "CMakeLists.txt").read_text(encoding="utf-8")

        self.assertTrue(header_path.exists(), "missing T-Display S3 review-state helper header")
        self.assertTrue(source_path.exists(), "missing T-Display S3 review-state helper source")
        self.assertIn("t_display_s3_review_state.cpp", cmake)

        with TemporaryDirectory() as tmp:
            program_path = Path(tmp) / "test_review_state.cpp"
            binary_path = Path(tmp) / "test_review_state"
            program_path.write_text(
                """
                #include "t_display_s3_review_state.hpp"

                #include <cassert>
                #include <cstdint>
                #include <limits>

                int main() {
                    nsealr_esp32::TDisplayS3ReviewActivity activity;
                    assert(!nsealr_esp32::t_display_s3_review_activity_active(activity));

                    nsealr_esp32::start_t_display_s3_review_activity(activity, 100);
                    assert(nsealr_esp32::t_display_s3_review_activity_active(activity));
                    assert(!nsealr_esp32::t_display_s3_review_activity_expired(activity, 159, 60));
                    assert(nsealr_esp32::t_display_s3_review_activity_expired(activity, 160, 60));

                    nsealr_esp32::record_t_display_s3_review_activity(activity, 170);
                    assert(!nsealr_esp32::t_display_s3_review_activity_expired(activity, 229, 60));
                    assert(nsealr_esp32::t_display_s3_review_activity_expired(activity, 230, 60));

                    nsealr_esp32::start_t_display_s3_review_activity(
                        activity,
                        std::numeric_limits<std::uint32_t>::max() - 5
                    );
                    assert(!nsealr_esp32::t_display_s3_review_activity_expired(activity, 3, 10));
                    assert(nsealr_esp32::t_display_s3_review_activity_expired(activity, 5, 10));

                    nsealr_esp32::clear_t_display_s3_review_activity(activity);
                    assert(!nsealr_esp32::t_display_s3_review_activity_active(activity));
                    assert(!nsealr_esp32::t_display_s3_review_activity_expired(activity, 1000, 60));
                    return 0;
                }
                """,
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "c++",
                    "-std=c++20",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    f"-I{main_dir}",
                    str(source_path),
                    str(program_path),
                    "-o",
                    str(binary_path),
                ],
                check=True,
            )
            subprocess.run([str(binary_path)], check=True)

    def test_t_display_s3_firmware_displays_terminal_review_decisions_without_signing(self) -> None:
        main = (ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp").read_text(encoding="utf-8")
        status_source = (
            ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_status_frames.cpp"
        ).read_text(encoding="utf-8")

        self.assertIn("build_t_display_s3_review_decision_frame", main)
        self.assertIn('frame.title = approved ? "Review OK" : "Rejected"', status_source)
        self.assertIn('frame.page_indicator = "Closed"', status_source)
        self.assertIn('"Not signed"', status_source)
        self.assertIn('"Signing disabled"', status_source)
        self.assertIn('"Send new request"', status_source)
        self.assertIn("build_t_display_s3_review_decision_frame(decision.value())", main)
        self.assertIn("clear_active_review(active_review)", main)

    def test_t_display_s3_firmware_closes_review_on_rejected_serial_requests(self) -> None:
        main = (ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp").read_text(encoding="utf-8")
        status_source = (
            ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_status_frames.cpp"
        ).read_text(encoding="utf-8")

        self.assertIn("build_t_display_s3_request_error_frame", main)
        self.assertIn('frame.title = "Request Error"', status_source)
        self.assertIn('frame.page_indicator = "Rejected"', status_source)
        self.assertIn("response_frame_is_error", main)
        self.assertIn("decode_serial_frame(response_frame)", main)
        self.assertIn("display_review_frame(display, nsealr_esp32::build_t_display_s3_request_error_frame())", main)
        self.assertIn("clear_active_review(active_review)", main)

    def test_t_display_s3_firmware_expires_stale_review_sessions_without_signing(self) -> None:
        main = (ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp").read_text(encoding="utf-8")
        status_source = (
            ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_status_frames.cpp"
        ).read_text(encoding="utf-8")

        self.assertIn("kActiveReviewSessionTimeoutTicks", main)
        self.assertIn("ActiveReviewState", main)
        self.assertIn("build_t_display_s3_review_timeout_frame", main)
        self.assertIn('frame.title = "Review Timeout"', status_source)
        self.assertIn('frame.page_indicator = "Expired"', status_source)
        self.assertIn("expire_active_review_if_needed", main)
        self.assertIn("active_review_expired", main)
        self.assertIn("xTaskGetTickCount()", main)
        self.assertIn("active_review.session.reset()", main)
        self.assertIn("Signing disabled", status_source)

    def test_board_profile_validator_discovers_every_profile(self) -> None:
        validate_board_profiles = getattr(validate_firmware, "validate_board_profiles", None)

        self.assertTrue(callable(validate_board_profiles), "validate_board_profiles must exist")
        with TemporaryDirectory() as tmp:
            board_dir = Path(tmp)
            (board_dir / "valid.json").write_text(
                (ROOT / "boards/esp32_s3_devkitc_1.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (board_dir / "bad.json").write_text(
                json.dumps(
                    {
                        "name": "Bad board",
                        "target": "esp32s3",
                        "native_usb": True,
                        "display": {"required_for_signing": True},
                        "approval_inputs": [{"name": "approve"}, {"name": "reject"}],
                        "debug_policy": "debug only",
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "bad.json"):
                validate_board_profiles(board_dir)


class Esp32S3DetectionTests(unittest.TestCase):
    def test_serial_port_detection_prefers_cu_usbmodem_devices(self) -> None:
        with TemporaryDirectory() as tmp:
            dev_dir = Path(tmp)
            (dev_dir / "tty.usbmodem1101").touch()
            (dev_dir / "cu.usbmodem1101").touch()
            (dev_dir / "cu.Bluetooth-Incoming-Port").touch()

            ports = detect_esp32_s3.find_serial_ports(dev_dir)

        self.assertEqual([port.name for port in ports], ["cu.usbmodem1101"])

    def test_usb_report_parser_detects_native_espressif_jtag_serial_device(self) -> None:
        report = """
        | +-o USB JTAG/serial debug unit@01100000  <class IOUSBHostDevice>
        |       "USB Vendor Name" = "Espressif"
        |       "USB Product Name" = "USB JTAG/serial debug unit"
        |       "USB Serial Number" = "EC:DA:3B:95:32:98"
        """

        summary = detect_esp32_s3.parse_usb_report(report)

        self.assertEqual(summary["vendor"], "Espressif")
        self.assertEqual(summary["product"], "USB JTAG/serial debug unit")
        self.assertEqual(summary["serial_number"], "EC:DA:3B:95:32:98")
        self.assertTrue(summary["native_usb_jtag_serial"])

    def test_usb_report_parser_accepts_apple_product_name_variant(self) -> None:
        report = """
        |       "USB Vendor Name" = "Espressif"
        |       "USB Product Name" = "USB JTAG_serial debug unit"
        """

        summary = detect_esp32_s3.parse_usb_report(report)

        self.assertTrue(summary["native_usb_jtag_serial"])

    def test_detection_report_includes_port_usb_summary_and_toolchain_status(self) -> None:
        with TemporaryDirectory() as tmp:
            dev_dir = Path(tmp)
            (dev_dir / "cu.usbmodem1101").touch()

            report = detect_esp32_s3.build_detection_report(
                dev_dir=dev_dir,
                usb_report='"USB Vendor Name" = "Espressif"\n"USB Product Name" = "USB JTAG/serial debug unit"',
                tool_lookup=lambda _tool: None,
            )

        self.assertTrue(report["connected"])
        self.assertEqual(report["ports"], [str(dev_dir / "cu.usbmodem1101")])
        self.assertEqual(report["usb"]["vendor"], "Espressif")
        self.assertIsNone(report["toolchain"]["idf.py"])
        self.assertIsNone(report["toolchain"]["esptool.py"])


class Esp32S3CapabilitySmokeTests(unittest.TestCase):
    def test_smoke_script_builds_capability_frames_from_specs(self) -> None:
        request_frame, response_frame = smoke_capabilities.load_capability_frames()

        self.assertTrue(request_frame.startswith("nsealr1f:request:"))
        self.assertTrue(response_frame.startswith("nsealr1f:response:"))
        self.assertTrue(request_frame.endswith("\n"))
        self.assertTrue(response_frame.endswith("\n"))

    def test_smoke_script_builds_signing_disabled_frames_from_specs(self) -> None:
        request_frame, response_frame = smoke_capabilities.load_signing_disabled_frames()

        self.assertTrue(request_frame.startswith("nsealr1f:request:"))
        self.assertTrue(response_frame.startswith("nsealr1f:response:"))
        self.assertIn("response", response_frame)
        self.assertTrue(request_frame.endswith("\n"))
        self.assertTrue(response_frame.endswith("\n"))

    def test_smoke_script_builds_public_key_frames_from_specs(self) -> None:
        request_frame, response_frame = smoke_capabilities.load_public_key_frames()

        self.assertTrue(request_frame.startswith("nsealr1f:request:"))
        self.assertTrue(response_frame.startswith("nsealr1f:response:"))
        self.assertIn("response", response_frame)
        self.assertTrue(request_frame.endswith("\n"))
        self.assertTrue(response_frame.endswith("\n"))

    def test_smoke_script_builds_signing_status_frames_from_specs(self) -> None:
        request_frame, response_frame = smoke_capabilities.load_signing_status_frames()

        self.assertTrue(request_frame.startswith("nsealr1f:request:"))
        self.assertTrue(response_frame.startswith("nsealr1f:response:"))
        self.assertIn("response", response_frame)
        self.assertTrue(request_frame.endswith("\n"))
        self.assertTrue(response_frame.endswith("\n"))

    def test_smoke_script_builds_dynamic_request_id_exchanges(self) -> None:
        exchanges = smoke_capabilities.load_dynamic_request_id_frames()

        self.assertEqual(len(exchanges), 4)
        for request_frame, response_frame in exchanges:
            request = decode_serial_frame_payload(request_frame)
            response = decode_serial_frame_payload(response_frame)

            self.assertTrue(request["request_id"].startswith("dynamic-smoke-"))
            self.assertEqual(response["request_id"], request["request_id"])

        signing_status_response = decode_serial_frame_payload(exchanges[1][1])
        signing_status = signing_status_response["result"]["signing_status"]
        self.assertFalse(signing_status["signing_enabled"])
        self.assertIn(
            "flash_encryption",
            signing_status["missing_gates"],
        )
        self.assertIn(
            "unicode_review_rendering",
            signing_status["missing_gates"],
        )
        self.assertIn("trusted_review_display", signing_status["development_accepted_gates"])
        self.assertIn("physical_approval_controls", signing_status["development_accepted_gates"])

        sign_response = decode_serial_frame_payload(exchanges[3][1])
        self.assertFalse(sign_response["ok"])
        self.assertEqual(sign_response["error"]["code"], "signing_disabled")

    def test_smoke_script_builds_invalid_metadata_exchanges(self) -> None:
        with TemporaryDirectory() as temp_root:
            specs_dir = Path(temp_root)
            invalid_dir = specs_dir / "vectors" / "invalid"
            invalid_dir.mkdir(parents=True)
            invalid_dir.joinpath("serial-frame-request-invalid-version.json").write_text(
                json.dumps(
                    {
                        "frame": "nsealr1f:request:test-version:0000000000000000\n",
                    }
                ),
                encoding="utf-8",
            )
            invalid_dir.joinpath("serial-frame-request-invalid-request-id.json").write_text(
                json.dumps(
                    {
                        "frame": "nsealr1f:request:test-request-id:0000000000000000\n",
                    }
                ),
                encoding="utf-8",
            )

            exchanges = smoke_capabilities.load_invalid_metadata_frames(specs_dir)

        self.assertEqual(len(exchanges), 2)
        self.assertEqual(exchanges[0][0], "nsealr1f:request:test-version:0000000000000000\n")
        self.assertEqual(exchanges[1][0], "nsealr1f:request:test-request-id:0000000000000000\n")
        for _, error_frame in exchanges:
            self.assertEqual(decode_serial_frame_payload(error_frame), {"error": "unsupported_request"})
            self.assertTrue(error_frame.startswith("nsealr1f:error:"))

    def test_smoke_script_wraps_invalid_transport_frame_vectors(self) -> None:
        with TemporaryDirectory() as temp_root:
            specs_dir = Path(temp_root)
            invalid_dir = specs_dir / "vectors" / "invalid"
            invalid_dir.mkdir(parents=True)
            invalid_dir.joinpath("serial-frame-checksum-mismatch.json").write_text(
                json.dumps(
                    {
                        "name": "serial-frame-checksum-mismatch",
                        "category": "serial-frame",
                        "frame": "nsealr1f:request:payload:0000000000000000\n",
                    }
                ),
                encoding="utf-8",
            )
            invalid_dir.joinpath("serial-frame-malformed-payload.json").write_text(
                json.dumps(
                    {
                        "name": "serial-frame-malformed-payload",
                        "category": "serial-frame",
                        "frame": "nsealr1f:request:not-valid-base64!:0000000000000000\n",
                    }
                ),
                encoding="utf-8",
            )
            invalid_dir.joinpath("serial-frame-unsupported-type.json").write_text(
                json.dumps(
                    {
                        "name": "serial-frame-unsupported-type",
                        "category": "serial-frame",
                        "frame": "nsealr1f:command:payload:0000000000000000\n",
                    }
                ),
                encoding="utf-8",
            )
            invalid_dir.joinpath("serial-frame-oversized.json").write_text(
                json.dumps(
                    {
                        "name": "serial-frame-oversized",
                        "category": "serial-frame",
                        "frame": "nsealr1f:" + ("x" * 1100),
                    }
                ),
                encoding="utf-8",
            )

            malformed_exchanges = smoke_capabilities.load_malformed_transport_frame_exchanges(specs_dir)
            overlong_exchanges = smoke_capabilities.load_overlong_transport_frame_exchanges(specs_dir)

        self.assertEqual(len(malformed_exchanges), 3)
        self.assertEqual(len(overlong_exchanges), 1)
        for request_frame, error_frame in malformed_exchanges:
            self.assertTrue(request_frame.startswith("nsealr1f:"))
            self.assertEqual(decode_serial_frame_payload(error_frame), {"error": "malformed_frame"})
        self.assertEqual(decode_serial_frame_payload(overlong_exchanges[0][1]), {"error": "overlong_frame"})
        self.assertTrue(overlong_exchanges[0][0].endswith("\n"))

    def test_smoke_script_verifies_recovery_after_overlong_transport_frame(self) -> None:
        exchanges = smoke_capabilities.build_hardware_smoke_exchanges()
        overlong_frame = json.loads(
            (smoke_capabilities.DEFAULT_SPECS / "vectors/invalid/serial-frame-oversized.json").read_text(
                encoding="utf-8"
            )
        )["frame"]
        overlong_index = next(
            index
            for index, exchange in enumerate(exchanges)
            if exchange[0] == f"{overlong_frame}\n"
        )
        recovery_request = decode_serial_frame_payload(exchanges[overlong_index + 1][0])
        recovery_response = decode_serial_frame_payload(exchanges[overlong_index + 1][1])

        self.assertEqual(decode_serial_frame_payload(exchanges[overlong_index][1]), {"error": "overlong_frame"})
        self.assertEqual(recovery_request["request_id"], "post-overlong-recovery")
        self.assertEqual(recovery_response["request_id"], "post-overlong-recovery")
        self.assertTrue(recovery_response["ok"])

    def test_smoke_script_wraps_invalid_signing_request_vectors(self) -> None:
        with TemporaryDirectory() as temp_root:
            specs_dir = Path(temp_root)
            invalid_dir = specs_dir / "vectors" / "invalid"
            invalid_dir.mkdir(parents=True)
            invalid_dir.joinpath("request-event-template-pubkey.json").write_text(
                json.dumps(
                    {
                        "name": "request-event-template-pubkey",
                        "category": "signing-request",
                        "request": {
                            "version": 1,
                            "request_id": "invalid-template-pubkey",
                            "method": "sign_event",
                            "params": {
                                "event_template": {
                                    "pubkey": "0" * 64,
                                    "created_at": 1710000000,
                                    "kind": 1,
                                    "tags": [],
                                    "content": "unsafe template",
                                }
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            invalid_dir.joinpath("request-unknown-top-level-field.json").write_text(
                json.dumps(
                    {
                        "name": "request-unknown-top-level-field",
                        "category": "signing-request",
                        "request": {
                            "version": 1,
                            "request_id": "invalid-top-level",
                            "method": "get_public_key",
                            "unexpected": True,
                        },
                    }
                ),
                encoding="utf-8",
            )
            invalid_dir.joinpath("request-get-public-key-params.json").write_text(
                json.dumps(
                    {
                        "name": "request-get-public-key-params",
                        "category": "signing-request",
                        "request": {
                            "version": 1,
                            "request_id": "invalid-public-key-params",
                            "method": "get_public_key",
                            "params": {},
                        },
                    }
                ),
                encoding="utf-8",
            )

            exchanges = smoke_capabilities.load_invalid_signing_request_frames(specs_dir)

        self.assertEqual(len(exchanges), 3)
        requests = [decode_serial_frame_payload(exchange[0]) for exchange in exchanges]
        self.assertEqual(
            [request["request_id"] for request in requests],
            ["invalid-template-pubkey", "invalid-public-key-params", "invalid-top-level"],
        )
        for request_frame, error_frame in exchanges:
            self.assertEqual(decode_serial_frame_payload(error_frame), {"error": "unsupported_request"})
            self.assertTrue(request_frame.startswith("nsealr1f:request:"))
            self.assertTrue(error_frame.startswith("nsealr1f:error:"))

    def test_smoke_script_extracts_first_protocol_frame_after_logs(self) -> None:
        frame = "nsealr1f:response:eyJvayI6dHJ1ZX0:44b87362ee86689d\n"

        self.assertEqual(
            smoke_capabilities.extract_first_protocol_frame(f"I boot: log line\n{frame}ignored"),
            frame,
        )

    def test_smoke_script_waits_for_newline_terminated_protocol_frame(self) -> None:
        self.assertIsNone(smoke_capabilities.extract_first_protocol_frame("nsealr1f:response:partial"))

    def test_smoke_script_normalizes_serial_crlf_frames(self) -> None:
        self.assertEqual(
            smoke_capabilities.extract_first_protocol_frame("nsealr1f:response:payload:checksum\r\n"),
            "nsealr1f:response:payload:checksum\n",
        )

    def test_smoke_script_summarizes_expected_rejections_without_raw_error_frames(self) -> None:
        summary = smoke_capabilities.format_smoke_summary(
            [
                "nsealr1f:response:payload:checksum\n",
                "nsealr1f:error:payload:checksum\n",
                "nsealr1f:error:payload:checksum\n",
            ]
        )

        self.assertIn("ESP32 hardware smoke passed", summary)
        self.assertIn("verified exchanges: 3", summary)
        self.assertIn("response frames: 1", summary)
        self.assertIn("expected rejection frames: 2", summary)
        self.assertNotIn("nsealr1f:error", summary)

    def test_smoke_script_applies_timeout_per_exchange(self) -> None:
        responses = [
            "nsealr1f:response:first:1111111111111111\n",
            "nsealr1f:error:second:2222222222222222\n",
            "nsealr1f:response:third:3333333333333333\n",
        ]

        class SlowExchangeDevice:
            def __init__(self) -> None:
                self._responses = list(responses)
                self._pending = ""
                self._empty_reads_remaining = 0

            def write(self, request: bytes) -> None:
                self.assert_request = request
                self._pending = self._responses.pop(0)
                self._empty_reads_remaining = 1

            def flush(self) -> None:
                return None

            def read(self, _size: int) -> bytes:
                if self._empty_reads_remaining > 0:
                    self._empty_reads_remaining -= 1
                    time.sleep(0.04)
                    return b""
                return self._pending.encode("ascii")

        frames = smoke_capabilities.run_serial_exchanges(
            SlowExchangeDevice(),
            [
                ("request-1\n", responses[0]),
                ("request-2\n", responses[1]),
                ("request-3\n", responses[2]),
            ],
            timeout=0.07,
        )

        self.assertEqual(frames, responses)

    def test_smoke_script_reports_exchange_index_on_failure(self) -> None:
        class WrongFrameDevice:
            def __init__(self) -> None:
                self._responses = [
                    "nsealr1f:response:first:1111111111111111\n",
                    "nsealr1f:error:wrong:2222222222222222\n",
                ]

            def write(self, _request: bytes) -> None:
                return None

            def flush(self) -> None:
                return None

            def read(self, _size: int) -> bytes:
                if not self._responses:
                    return b""
                return self._responses.pop(0).encode("ascii")

        with self.assertRaisesRegex(RuntimeError, "exchange 2/3 failed"):
            smoke_capabilities.run_serial_exchanges(
                WrongFrameDevice(),
                [
                    ("request-1\n", "nsealr1f:response:first:1111111111111111\n"),
                    ("request-2\n", "nsealr1f:error:expected:2222222222222222\n"),
                    ("request-3\n", "nsealr1f:response:third:3333333333333333\n"),
                ],
                timeout=0.1,
            )


class Esp32S3ManualReviewDisplayTests(unittest.TestCase):
    def assert_no_duplicate_checklist_lines(self, checklist: str) -> None:
        lines = [line for line in checklist.splitlines() if line.strip()]
        self.assertEqual(len(lines), len(set(lines)))

    def test_manual_review_display_builds_dynamic_sign_event_exchange(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="show-review",
            request_id="manual-review-test",
        )
        checklist = manual_review_display.build_manual_observation_checklist("show-review")

        self.assertEqual(len(exchanges), 1)
        request = decode_serial_frame_payload(exchanges[0][0])
        response = decode_serial_frame_payload(exchanges[0][1])

        self.assertEqual(request["method"], "sign_event")
        self.assertEqual(request["request_id"], "manual-review-test")
        self.assertEqual(response["request_id"], "manual-review-test")
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "signing_disabled")
        self.assertIn("raw kind", checklist)
        self.assertIn("Author", checklist)
        self.assertNotIn("type", checklist)
        self.assertNotIn("Short Text Note", checklist)

    def test_manual_review_display_builds_request_error_scenario(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="show-request-error",
            request_id="manual-error-test",
        )
        checklist = manual_review_display.build_manual_observation_checklist("show-request-error")

        self.assertEqual(len(exchanges), 2)
        valid_request = decode_serial_frame_payload(exchanges[0][0])
        invalid_request = decode_serial_frame_payload(exchanges[1][0])
        invalid_response = decode_serial_frame_payload(exchanges[1][1])

        self.assertEqual(valid_request["request_id"], "manual-error-test")
        self.assertEqual(invalid_request["request_id"], "manual-error-test-invalid")
        self.assertIn("pubkey", invalid_request["params"]["event_template"])
        self.assertEqual(invalid_response, {"error": "unsupported_request"})
        self.assertIn(
            "Request Error / Rejected / Not signed / Signing disabled / Send new request",
            checklist,
        )

    def test_manual_review_display_builds_tagged_event_review_scenario(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="show-tags",
            request_id="manual-tags-test",
        )
        checklist = manual_review_display.build_manual_observation_checklist("show-tags")

        self.assertEqual(len(exchanges), 1)
        request = decode_serial_frame_payload(exchanges[0][0])
        response = decode_serial_frame_payload(exchanges[0][1])
        event_template = request["params"]["event_template"]

        self.assertEqual(request["method"], "sign_event")
        self.assertEqual(request["request_id"], "manual-tags-test")
        self.assertEqual(response["request_id"], "manual-tags-test")
        self.assertEqual(response["error"]["code"], "signing_disabled")
        self.assertEqual(event_template["tags"][0][0], "p")
        self.assertEqual(event_template["tags"][1], ["t", "nsealr"])
        self.assertIn("tag content grouped by tag, not interpreted tag labels", checklist)
        self.assertIn("Tag 1/2 and Tag 2/2 on one compact Tags screen", checklist)
        self.assertIn("Tag 1/2 shows p, the full 64-character pubkey, and mention", checklist)
        self.assertIn("pubkey continuation line is indented", checklist)
        self.assertIn("Tag 2/2 shows t and nsealr", checklist)
        self.assertIn("short BOOT/GPIO0 to scroll only within Tags", checklist)
        self.assertNotIn("Warnings", checklist)

    def test_manual_review_display_builds_long_content_review_scenario(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="show-long-content",
            request_id="manual-long-content-test",
        )
        checklist = manual_review_display.build_manual_observation_checklist("show-long-content")

        self.assertEqual(len(exchanges), 1)
        request = decode_serial_frame_payload(exchanges[0][0])
        response = decode_serial_frame_payload(exchanges[0][1])
        event_template = request["params"]["event_template"]

        self.assertEqual(request["method"], "sign_event")
        self.assertEqual(request["request_id"], "manual-long-content-test")
        self.assertEqual(response["request_id"], "manual-long-content-test")
        self.assertEqual(response["error"]["code"], "signing_disabled")
        self.assertGreater(len(event_template["content"]), 280)
        self.assertEqual(len(event_template["tags"]), 9)
        self.assertIn("Confirm the Content body uses compact text", checklist)
        self.assertIn("shown as Page 3/4 or Page 3/4 Lines X-Y/N", checklist)
        self.assertIn("short BOOT/GPIO0 to scroll only within Content", checklist)
        self.assertIn("from any Tags scroll window to reach the final Decision page", checklist)
        self.assertIn("every visible tag item is readable without ellipses", checklist)
        self.assertNotIn("Warnings", checklist)

    def test_manual_review_display_builds_scroll_review_scenario(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="show-scroll-review",
            request_id="manual-scroll",
        )
        checklist = manual_review_display.build_manual_observation_checklist("show-scroll-review")

        self.assertEqual(len(exchanges), 1)
        request = decode_serial_frame_payload(exchanges[0][0])
        response = decode_serial_frame_payload(exchanges[0][1])
        event_template = request["params"]["event_template"]

        self.assertEqual(request["method"], "sign_event")
        self.assertEqual(request["request_id"], "manual-scroll")
        self.assertEqual(response["request_id"], "manual-scroll")
        self.assertEqual(response["error"]["code"], "signing_disabled")
        self.assertGreaterEqual(len(event_template["content"].encode("utf-8")), 420)
        self.assertGreaterEqual(len(event_template["tags"]), 6)
        self.assertLessEqual(
            len(json.dumps(request, separators=(",", ":")).encode("utf-8")),
            704,
        )
        self.assertIn("Page 2/4 Lines 1-9/", checklist)
        self.assertIn("Page 3/4 Lines 1-9/", checklist)
        self.assertIn("short BOOT/GPIO0 to scroll within Content", checklist)
        self.assertIn("short BOOT/GPIO0 to scroll within Tags", checklist)
        self.assertIn("without repeating the last line", checklist)
        self.assertIn("short KEY/GPIO14 from any scroll window to Decision", checklist)
        self.assertNotIn("detail screen", checklist)
        self.assertNotIn("...", checklist)
        self.assertNotIn("Warnings", checklist)
        self.assert_no_duplicate_checklist_lines(checklist)

    def test_manual_review_display_builds_dense_tags_scroll_scenario(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="show-dense-tags",
            request_id="manual-dense-tags",
        )
        checklist = manual_review_display.build_manual_observation_checklist("show-dense-tags")

        self.assertEqual(len(exchanges), 1)
        request = decode_serial_frame_payload(exchanges[0][0])
        response = decode_serial_frame_payload(exchanges[0][1])
        event_template = request["params"]["event_template"]

        self.assertEqual(request["method"], "sign_event")
        self.assertEqual(request["request_id"], "manual-dense-tags")
        self.assertEqual(response["request_id"], "manual-dense-tags")
        self.assertEqual(response["error"]["code"], "signing_disabled")
        self.assertGreaterEqual(len(event_template["tags"]), 12)
        self.assertLessEqual(
            len(json.dumps(request, separators=(",", ":")).encode("utf-8")),
            704,
        )
        self.assertIn("Page 3/4 Lines 1-9/", checklist)
        self.assertIn("multiple Tags scroll windows", checklist)
        self.assertIn("short BOOT/GPIO0 to scroll within Tags", checklist)
        self.assertIn("no inferred tag meaning", checklist)
        self.assertNotIn("...", checklist)
        self.assertNotIn("Warnings", checklist)

    def test_manual_review_display_builds_unicode_review_scenario(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="show-unicode-review",
            request_id="manual-unicode",
        )
        checklist = manual_review_display.build_manual_observation_checklist("show-unicode-review")

        self.assertEqual(len(exchanges), 1)
        request = decode_serial_frame_payload(exchanges[0][0])
        response = decode_serial_frame_payload(exchanges[0][1])
        event_template = request["params"]["event_template"]

        self.assertEqual(request["method"], "sign_event")
        self.assertEqual(request["request_id"], "manual-unicode")
        self.assertEqual(response["request_id"], "manual-unicode")
        self.assertEqual(response["error"]["code"], "signing_disabled")
        self.assertIn("\u00e8", event_template["content"])
        self.assertIn("\U0001f600", event_template["content"])
        self.assertIn("Author", checklist)
        self.assertIn("no inferred kind label", checklist)
        self.assertIn("U+00E8", checklist)
        self.assertIn("U+1F600", checklist)

    def test_manual_review_display_builds_control_escape_review_scenario(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="show-control-escapes",
            request_id="manual-control-escapes",
        )
        checklist = manual_review_display.build_manual_observation_checklist("show-control-escapes")

        self.assertEqual(len(exchanges), 1)
        request = decode_serial_frame_payload(exchanges[0][0])
        response = decode_serial_frame_payload(exchanges[0][1])
        event_template = request["params"]["event_template"]

        self.assertEqual(request["method"], "sign_event")
        self.assertEqual(request["request_id"], "manual-control-escapes")
        self.assertEqual(response["request_id"], "manual-control-escapes")
        self.assertEqual(response["error"]["code"], "signing_disabled")
        self.assertIn("\n", event_template["content"])
        self.assertIn("\t", event_template["content"])
        self.assertIn(["t", "line\nbreak"], event_template["tags"])
        self.assertIn("\\n", checklist)
        self.assertIn("\\t", checklist)
        self.assertIn("not as actual spacing", checklist)

    def test_review_detail_styles_do_not_keep_obsolete_label_style(self) -> None:
        header = (ROOT / "firmware/host_core/include/nsealr/review_display.hpp").read_text()
        renderer = (ROOT / "firmware/host_core/src/review_display.cpp").read_text()
        raster = (ROOT / "firmware/esp32_s3_usb_signer/main/t_display_s3_raster.cpp").read_text()
        vector_generator = (ROOT / "scripts/generate_transport_vector_header.py").read_text()

        self.assertNotIn("ReviewBodyLineStyle::Label", renderer)
        self.assertNotIn("ReviewBodyLineStyle::Label", raster)
        self.assertNotIn("ReviewBodyLineStyle::Label", vector_generator)
        self.assertNotIn("Label,", header)
        self.assertNotIn('style == "label"', vector_generator)

    def test_review_scenario_smoke_builds_noninteractive_review_exchanges(self) -> None:
        exchanges = smoke_review_scenarios.build_review_smoke_exchanges(
            scenarios=(
                "show-tags",
                "show-dense-tags",
                "show-unicode-review",
                "show-control-escapes",
                "show-request-error",
            ),
            request_id_prefix="unit-review",
        )
        decoded_requests = [decode_serial_frame_payload(request_frame) for request_frame, _ in exchanges]
        decoded_responses = [decode_serial_frame_payload(response_frame) for _, response_frame in exchanges]

        self.assertEqual(len(exchanges), 6)
        self.assertEqual(decoded_requests[0]["request_id"], "unit-review-show-tags")
        self.assertEqual(decoded_requests[1]["request_id"], "unit-review-show-dense-tags")
        self.assertEqual(decoded_requests[2]["request_id"], "unit-review-show-unicode-review")
        self.assertEqual(decoded_requests[3]["request_id"], "unit-review-show-control-escapes")
        self.assertEqual(decoded_requests[4]["request_id"], "unit-review-show-request-error")
        self.assertEqual(decoded_requests[5]["request_id"], "unit-review-show-request-error-invalid")
        self.assertEqual(decoded_responses[0]["error"]["code"], "signing_disabled")
        self.assertEqual(decoded_responses[1]["error"]["code"], "signing_disabled")
        self.assertEqual(decoded_responses[2]["error"]["code"], "signing_disabled")
        self.assertEqual(decoded_responses[3]["error"]["code"], "signing_disabled")
        self.assertEqual(decoded_responses[4]["error"]["code"], "signing_disabled")
        self.assertEqual(decoded_responses[5]["error"], "unsupported_request")

    def test_review_scenario_smoke_summary_counts_protocol_outcomes(self) -> None:
        response_frame = smoke_capabilities.load_signing_disabled_frames()[1]
        rejection_frame = smoke_capabilities.encode_serial_frame(
            "error",
            smoke_capabilities.base64url_json(smoke_capabilities.UNSUPPORTED_REQUEST_ERROR),
        )

        summary = smoke_review_scenarios.format_review_smoke_summary(
            [response_frame, rejection_frame],
            scenarios=("show-review", "show-request-error"),
        )

        self.assertIn("ESP32 review scenario smoke passed", summary)
        self.assertIn("scenarios: 2", summary)
        self.assertIn("verified exchanges: 2", summary)
        self.assertIn("response frames: 1", summary)
        self.assertIn("expected rejection frames: 1", summary)

    def test_manual_review_display_builds_button_approval_acceptance_scenario(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="button-approve",
            request_id="manual-approve-test",
        )
        checklist = manual_review_display.build_manual_observation_checklist("button-approve")

        self.assertEqual(len(exchanges), 1)
        request = decode_serial_frame_payload(exchanges[0][0])
        response = decode_serial_frame_payload(exchanges[0][1])

        self.assertEqual(request["method"], "sign_event")
        self.assertEqual(request["request_id"], "manual-approve-test")
        self.assertEqual(response["error"]["code"], "signing_disabled")
        self.assertIn("short KEY/GPIO14 three times to reach the final page", checklist)
        self.assertIn("Optional Content/Tags scroll windows use short BOOT/GPIO0", checklist)
        self.assertIn("long KEY/GPIO14 to approve", checklist)
        self.assertIn(
            "Review OK / Closed / Not signed / Signing disabled / Send new request",
            checklist,
        )

    def test_manual_review_display_builds_button_rejection_acceptance_scenario(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="button-reject",
            request_id="manual-reject-test",
        )
        checklist = manual_review_display.build_manual_observation_checklist("button-reject")

        self.assertEqual(len(exchanges), 1)
        request = decode_serial_frame_payload(exchanges[0][0])
        response = decode_serial_frame_payload(exchanges[0][1])

        self.assertEqual(request["method"], "sign_event")
        self.assertEqual(request["request_id"], "manual-reject-test")
        self.assertEqual(response["error"]["code"], "signing_disabled")
        self.assertIn("long BOOT/GPIO0 to reject", checklist)
        self.assertIn(
            "Rejected / Closed / Not signed / Signing disabled / Send new request",
            checklist,
        )

    def test_manual_review_display_runs_exchanges_with_fake_serial_device(self) -> None:
        responses = [
            "nsealr1f:response:manual:1111111111111111\n",
            "nsealr1f:error:manual:2222222222222222\n",
        ]

        class ManualDisplayDevice:
            def __init__(self) -> None:
                self.written: list[bytes] = []
                self._responses = list(responses)
                self._pending = ""

            def write(self, request: bytes) -> None:
                self.written.append(request)
                self._pending = self._responses.pop(0)

            def flush(self) -> None:
                return None

            def read(self, _size: int) -> bytes:
                return self._pending.encode("ascii")

        device = ManualDisplayDevice()
        frames = manual_review_display.run_manual_review_exchanges(
            device,
            [("request-1\n", responses[0]), ("request-2\n", responses[1])],
            timeout=0.01,
        )

        self.assertEqual(frames, responses)
        self.assertEqual(device.written, [b"request-1\n", b"request-2\n"])


if __name__ == "__main__":
    unittest.main()
