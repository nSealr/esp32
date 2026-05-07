#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable


SERIAL_GLOBS = (
    "cu.usbmodem*",
    "cu.usbserial*",
    "cu.SLAB_USBtoUART*",
    "cu.wchusbserial*",
)

USB_FIELD_NAMES = {
    "vendor": ("USB Vendor Name", "kUSBVendorString"),
    "product": ("USB Product Name", "kUSBProductString"),
    "serial_number": ("USB Serial Number", "kUSBSerialNumberString"),
}

NATIVE_USB_JTAG_SERIAL_PRODUCTS = (
    "USB JTAG/serial debug unit",
    "USB JTAG_serial debug unit",
)


def find_serial_ports(dev_dir: Path = Path("/dev")) -> list[Path]:
    ports: list[Path] = []
    for pattern in SERIAL_GLOBS:
        ports.extend(dev_dir.glob(pattern))
    return sorted(dict.fromkeys(ports))


def _extract_usb_field(report: str, field_names: tuple[str, ...]) -> str | None:
    for field_name in field_names:
        pattern = rf'"{re.escape(field_name)}"\s*=\s*"([^"]+)"'
        match = re.search(pattern, report)
        if match:
            return match.group(1)
    return None


def parse_usb_report(report: str) -> dict[str, object]:
    vendor = _extract_usb_field(report, USB_FIELD_NAMES["vendor"])
    product = _extract_usb_field(report, USB_FIELD_NAMES["product"])
    serial_number = _extract_usb_field(report, USB_FIELD_NAMES["serial_number"])
    native_usb_jtag_serial = "Espressif" in report and any(
        product_name in report for product_name in NATIVE_USB_JTAG_SERIAL_PRODUCTS
    )
    return {
        "vendor": vendor,
        "product": product,
        "serial_number": serial_number,
        "native_usb_jtag_serial": native_usb_jtag_serial,
    }


def read_usb_report() -> str:
    try:
        result = subprocess.run(
            ["ioreg", "-p", "IOUSB", "-l", "-w", "0"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except FileNotFoundError:
        return ""
    return result.stdout if result.returncode == 0 else ""


def build_detection_report(
    *,
    dev_dir: Path = Path("/dev"),
    usb_report: str | None = None,
    tool_lookup: Callable[[str], str | None] = shutil.which,
) -> dict[str, object]:
    ports = [str(port) for port in find_serial_ports(dev_dir)]
    usb = parse_usb_report(read_usb_report() if usb_report is None else usb_report)
    toolchain = {
        "idf.py": tool_lookup("idf.py"),
        "esptool.py": tool_lookup("esptool.py"),
        "esptool": tool_lookup("esptool"),
    }
    return {
        "connected": bool(ports) or bool(usb["native_usb_jtag_serial"]),
        "ports": ports,
        "usb": usb,
        "toolchain": toolchain,
        "ready_for_idf_build": toolchain["idf.py"] is not None,
        "ready_for_flash": bool(ports) and toolchain["idf.py"] is not None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect an attached ESP32-S3 development board.")
    parser.add_argument("--dev-dir", default="/dev", help="device directory to scan")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()

    report = build_detection_report(dev_dir=Path(args.dev_dir))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["connected"] else 1

    if report["connected"]:
        print("ESP32-S3 candidate detected")
        for port in report["ports"]:
            print(f"port: {port}")
    else:
        print("No ESP32-S3 candidate detected")

    usb = report["usb"]
    if usb["vendor"] or usb["product"] or usb["serial_number"]:
        print(f"usb_vendor: {usb['vendor']}")
        print(f"usb_product: {usb['product']}")
        print(f"usb_serial: {usb['serial_number']}")
        print(f"native_usb_jtag_serial: {usb['native_usb_jtag_serial']}")

    toolchain = report["toolchain"]
    print(f"idf.py: {toolchain['idf.py'] or 'missing'}")
    print(f"esptool.py: {toolchain['esptool.py'] or 'missing'}")
    print(f"esptool: {toolchain['esptool'] or 'missing'}")
    return 0 if report["connected"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
