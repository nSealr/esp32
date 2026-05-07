import unittest
from pathlib import Path

from scripts.validate_firmware import validate_firmware_project


ROOT = Path(__file__).resolve().parents[1]


class FirmwareProjectValidationTests(unittest.TestCase):
    def test_esp32_s3_usb_signer_project_is_valid(self) -> None:
        validate_firmware_project(ROOT / "firmware/esp32_s3_usb_signer")


if __name__ == "__main__":
    unittest.main()
