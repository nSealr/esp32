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
from scripts import validate_firmware
from scripts.validate_firmware import validate_firmware_project


ROOT = Path(__file__).resolve().parents[1]


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
        self.assertIn("idf-env-check:", makefile)

    def test_esp32_s3_usb_signer_builds_host_core_protocol(self) -> None:
        cmake = (ROOT / "firmware/esp32_s3_usb_signer/main/CMakeLists.txt").read_text(encoding="utf-8")
        main = (ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp").read_text(encoding="utf-8")

        self.assertIn("device_protocol.cpp", cmake)
        self.assertIn("approval_gate.cpp", cmake)
        self.assertIn("qr_envelope.cpp", cmake)
        self.assertIn("serial_frame.cpp", cmake)
        self.assertIn("serial_review.cpp", cmake)
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
        self.assertEqual(profile["schema"], "nseal-esp32-security-profile-v0")
        self.assertFalse(profile["runtime_signing_feature_enabled"])
        self.assertFalse(profile["production_signing_allowed"])
        self.assertFalse(profile["secure_boot"]["enabled"])
        self.assertFalse(profile["flash_encryption"]["enabled"])
        self.assertFalse(profile["debug_access"]["locked"])
        self.assertIn("secure_boot", profile["production_blockers"])
        self.assertIn("debug_lock", profile["production_blockers"])
        self.assertIn("key_provisioning", profile["production_blockers"])

    def test_security_profile_validator_rejects_production_signing_without_hardening(self) -> None:
        with TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "security_profile.json"
            profile_path.write_text(
                json.dumps(
                    {
                        "schema": "nseal-esp32-security-profile-v0",
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

    def test_firmware_validator_requires_serial_review_component(self) -> None:
        with TemporaryDirectory() as tmp:
            project = Path(tmp) / "esp32_s3_usb_signer"
            shutil.copytree(ROOT / "firmware/esp32_s3_usb_signer", project)
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
        main_path = ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp"

        display_header = display_header_path.read_text(encoding="utf-8")
        display_source = display_source_path.read_text(encoding="utf-8")
        main = main_path.read_text(encoding="utf-8")

        self.assertIn("nostrseal/review_display.hpp", display_header)
        self.assertIn("t_display_s3_review_limits", display_header)
        self.assertIn("draw_t_display_s3_review_frame", display_header)
        self.assertIn("ReviewDisplayFrame", display_header)

        self.assertIn("kTDisplayS3ReviewTitleChars", display_source)
        self.assertIn("kTDisplayS3ReviewBodyLines", display_source)
        self.assertIn("kTDisplayS3ReviewLineChars", display_source)
        self.assertIn("kFooterActionScale = 2", display_source)
        self.assertIn("kHeaderRightMargin", display_source)
        self.assertIn("text_width_px", display_source)
        self.assertIn("right_aligned_text_x", display_source)
        self.assertNotIn("draw_text(frame.page_indicator, 230", display_source)
        self.assertIn("draw_text", display_source)
        self.assertIn("glyph_rows_for", display_source)
        self.assertIn("wait_for_t_display_s3_color_transfer", display_source)
        self.assertIn("esp_lcd_panel_draw_bitmap", display_source)

        self.assertIn("nostrseal/review_display.hpp", main)
        self.assertIn("handle_serial_frame_with_review_preview", main)
        self.assertIn("display_sign_event_review_preview", main)
        self.assertIn("review_frame", main)
        self.assertIn("t_display_s3_review_limits", main)
        self.assertIn("draw_t_display_s3_review_frame", main)
        self.assertIn("build_display_ready_frame", main)
        self.assertIn('frame.page_indicator = "No request"', main)
        self.assertIn('"Send sign_event"', main)
        self.assertIn('frame.action_hint = "Waiting"', main)
        self.assertNotIn("Content: display test", main)
        self.assertIn("case '_'", display_source)
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
        self.assertIn("TDisplayS3ButtonEvent", buttons_header)
        self.assertIn("initialize_t_display_s3_buttons", buttons_header)
        self.assertIn("poll_t_display_s3_review_button", buttons_header)
        self.assertIn("kTDisplayS3ButtonLongPressMs", buttons_source)
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
                    nostrseal_esp32::TDisplayS3ReviewActivity activity;
                    assert(!nostrseal_esp32::t_display_s3_review_activity_active(activity));

                    nostrseal_esp32::start_t_display_s3_review_activity(activity, 100);
                    assert(nostrseal_esp32::t_display_s3_review_activity_active(activity));
                    assert(!nostrseal_esp32::t_display_s3_review_activity_expired(activity, 159, 60));
                    assert(nostrseal_esp32::t_display_s3_review_activity_expired(activity, 160, 60));

                    nostrseal_esp32::record_t_display_s3_review_activity(activity, 170);
                    assert(!nostrseal_esp32::t_display_s3_review_activity_expired(activity, 229, 60));
                    assert(nostrseal_esp32::t_display_s3_review_activity_expired(activity, 230, 60));

                    nostrseal_esp32::start_t_display_s3_review_activity(
                        activity,
                        std::numeric_limits<std::uint32_t>::max() - 5
                    );
                    assert(!nostrseal_esp32::t_display_s3_review_activity_expired(activity, 3, 10));
                    assert(nostrseal_esp32::t_display_s3_review_activity_expired(activity, 5, 10));

                    nostrseal_esp32::clear_t_display_s3_review_activity(activity);
                    assert(!nostrseal_esp32::t_display_s3_review_activity_active(activity));
                    assert(!nostrseal_esp32::t_display_s3_review_activity_expired(activity, 1000, 60));
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

        self.assertIn("build_review_decision_frame", main)
        self.assertIn('frame.title = approved ? "Review OK" : "Rejected"', main)
        self.assertIn('frame.page_indicator = "Closed"', main)
        self.assertIn('"Not signed"', main)
        self.assertIn('"Signing disabled"', main)
        self.assertIn('"Send new request"', main)
        self.assertIn("build_review_decision_frame(decision.value())", main)
        self.assertIn("clear_active_review(active_review)", main)

    def test_t_display_s3_firmware_closes_review_on_rejected_serial_requests(self) -> None:
        main = (ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp").read_text(encoding="utf-8")

        self.assertIn("build_request_error_frame", main)
        self.assertIn('frame.title = "Request Error"', main)
        self.assertIn('frame.page_indicator = "Rejected"', main)
        self.assertIn("response_frame_is_error", main)
        self.assertIn("decode_serial_frame(response_frame)", main)
        self.assertIn("display_review_frame(display, build_request_error_frame())", main)
        self.assertIn("clear_active_review(active_review)", main)

    def test_t_display_s3_firmware_expires_stale_review_sessions_without_signing(self) -> None:
        main = (ROOT / "firmware/esp32_s3_usb_signer/main/main.cpp").read_text(encoding="utf-8")

        self.assertIn("kActiveReviewSessionTimeoutTicks", main)
        self.assertIn("ActiveReviewState", main)
        self.assertIn("build_review_timeout_frame", main)
        self.assertIn('frame.title = "Review Timeout"', main)
        self.assertIn('frame.page_indicator = "Expired"', main)
        self.assertIn("expire_active_review_if_needed", main)
        self.assertIn("active_review_expired", main)
        self.assertIn("xTaskGetTickCount()", main)
        self.assertIn("active_review.session.reset()", main)
        self.assertIn("Signing disabled", main)

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

        self.assertTrue(request_frame.startswith("nseal1f:request:"))
        self.assertTrue(response_frame.startswith("nseal1f:response:"))
        self.assertTrue(request_frame.endswith("\n"))
        self.assertTrue(response_frame.endswith("\n"))

    def test_smoke_script_builds_signing_disabled_frames_from_specs(self) -> None:
        request_frame, response_frame = smoke_capabilities.load_signing_disabled_frames()

        self.assertTrue(request_frame.startswith("nseal1f:request:"))
        self.assertTrue(response_frame.startswith("nseal1f:response:"))
        self.assertIn("response", response_frame)
        self.assertTrue(request_frame.endswith("\n"))
        self.assertTrue(response_frame.endswith("\n"))

    def test_smoke_script_builds_public_key_frames_from_specs(self) -> None:
        request_frame, response_frame = smoke_capabilities.load_public_key_frames()

        self.assertTrue(request_frame.startswith("nseal1f:request:"))
        self.assertTrue(response_frame.startswith("nseal1f:response:"))
        self.assertIn("response", response_frame)
        self.assertTrue(request_frame.endswith("\n"))
        self.assertTrue(response_frame.endswith("\n"))

    def test_smoke_script_builds_dynamic_request_id_exchanges(self) -> None:
        exchanges = smoke_capabilities.load_dynamic_request_id_frames()

        self.assertEqual(len(exchanges), 3)
        for request_frame, response_frame in exchanges:
            request = decode_serial_frame_payload(request_frame)
            response = decode_serial_frame_payload(response_frame)

            self.assertTrue(request["request_id"].startswith("dynamic-smoke-"))
            self.assertEqual(response["request_id"], request["request_id"])

        sign_response = decode_serial_frame_payload(exchanges[2][1])
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
                        "frame": "nseal1f:request:test-version:0000000000000000\n",
                    }
                ),
                encoding="utf-8",
            )
            invalid_dir.joinpath("serial-frame-request-invalid-request-id.json").write_text(
                json.dumps(
                    {
                        "frame": "nseal1f:request:test-request-id:0000000000000000\n",
                    }
                ),
                encoding="utf-8",
            )

            exchanges = smoke_capabilities.load_invalid_metadata_frames(specs_dir)

        self.assertEqual(len(exchanges), 2)
        self.assertEqual(exchanges[0][0], "nseal1f:request:test-version:0000000000000000\n")
        self.assertEqual(exchanges[1][0], "nseal1f:request:test-request-id:0000000000000000\n")
        for _, error_frame in exchanges:
            self.assertEqual(decode_serial_frame_payload(error_frame), {"error": "unsupported_request"})
            self.assertTrue(error_frame.startswith("nseal1f:error:"))

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
            self.assertTrue(request_frame.startswith("nseal1f:request:"))
            self.assertTrue(error_frame.startswith("nseal1f:error:"))

    def test_smoke_script_extracts_first_protocol_frame_after_logs(self) -> None:
        frame = "nseal1f:response:eyJvayI6dHJ1ZX0:44b87362ee86689d\n"

        self.assertEqual(
            smoke_capabilities.extract_first_protocol_frame(f"I boot: log line\n{frame}ignored"),
            frame,
        )

    def test_smoke_script_waits_for_newline_terminated_protocol_frame(self) -> None:
        self.assertIsNone(smoke_capabilities.extract_first_protocol_frame("nseal1f:response:partial"))

    def test_smoke_script_normalizes_serial_crlf_frames(self) -> None:
        self.assertEqual(
            smoke_capabilities.extract_first_protocol_frame("nseal1f:response:payload:checksum\r\n"),
            "nseal1f:response:payload:checksum\n",
        )

    def test_smoke_script_summarizes_expected_rejections_without_raw_error_frames(self) -> None:
        summary = smoke_capabilities.format_smoke_summary(
            [
                "nseal1f:response:payload:checksum\n",
                "nseal1f:error:payload:checksum\n",
                "nseal1f:error:payload:checksum\n",
            ]
        )

        self.assertIn("ESP32 hardware smoke passed", summary)
        self.assertIn("verified exchanges: 3", summary)
        self.assertIn("response frames: 1", summary)
        self.assertIn("expected rejection frames: 2", summary)
        self.assertNotIn("nseal1f:error", summary)

    def test_smoke_script_applies_timeout_per_exchange(self) -> None:
        responses = [
            "nseal1f:response:first:1111111111111111\n",
            "nseal1f:error:second:2222222222222222\n",
            "nseal1f:response:third:3333333333333333\n",
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


class Esp32S3ManualReviewDisplayTests(unittest.TestCase):
    def test_manual_review_display_builds_dynamic_sign_event_exchange(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="show-review",
            request_id="manual-review-test",
        )

        self.assertEqual(len(exchanges), 1)
        request = decode_serial_frame_payload(exchanges[0][0])
        response = decode_serial_frame_payload(exchanges[0][1])

        self.assertEqual(request["method"], "sign_event")
        self.assertEqual(request["request_id"], "manual-review-test")
        self.assertEqual(response["request_id"], "manual-review-test")
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "signing_disabled")

    def test_manual_review_display_builds_request_error_scenario(self) -> None:
        exchanges = manual_review_display.build_manual_review_exchanges(
            scenario="show-request-error",
            request_id="manual-error-test",
        )

        self.assertEqual(len(exchanges), 2)
        valid_request = decode_serial_frame_payload(exchanges[0][0])
        invalid_request = decode_serial_frame_payload(exchanges[1][0])
        invalid_response = decode_serial_frame_payload(exchanges[1][1])

        self.assertEqual(valid_request["request_id"], "manual-error-test")
        self.assertEqual(invalid_request["request_id"], "manual-error-test-invalid")
        self.assertIn("pubkey", invalid_request["params"]["event_template"])
        self.assertEqual(invalid_response, {"error": "unsupported_request"})

    def test_manual_review_display_runs_exchanges_with_fake_serial_device(self) -> None:
        responses = [
            "nseal1f:response:manual:1111111111111111\n",
            "nseal1f:error:manual:2222222222222222\n",
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
