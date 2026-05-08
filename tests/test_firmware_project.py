import base64
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts import detect_esp32_s3
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
        self.assertIn("review_display.cpp", cmake)
        self.assertIn("trusted_review.cpp", cmake)
        self.assertIn("sha256.cpp", cmake)
        self.assertIn("handle_serial_frame", main)
        self.assertIn("Signing is disabled", main)

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


if __name__ == "__main__":
    unittest.main()
