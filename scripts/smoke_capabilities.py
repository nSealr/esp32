#!/usr/bin/env python3
"""ESP32-S3 serial capability smoke test.

This script is intentionally hardware-only. Unit tests cover frame generation
and log filtering; the serial dependency is imported only when the smoke test
actually opens a board port.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPECS = ROOT.parent / "specs"
PREFIX = "nseal1f:"


def base64url_json(value: dict) -> str:
    encoded = base64.urlsafe_b64encode(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return encoded.rstrip("=")


def encode_serial_frame(frame_type: str, payload_base64url: str) -> str:
    checksum = hashlib.sha256(f"{frame_type}:{payload_base64url}".encode("utf-8")).hexdigest()[:16]
    return f"{PREFIX}{frame_type}:{payload_base64url}:{checksum}\n"


def load_capability_frames(specs_dir: Path = DEFAULT_SPECS) -> tuple[str, str]:
    vector = json.loads(
        (specs_dir / "vectors/devices/esp32-s3-capabilities-scaffold.json").read_text(encoding="utf-8")
    )
    request_payload = base64url_json(vector["request"])
    response_payload = base64url_json(vector["response"])
    return encode_serial_frame("request", request_payload), encode_serial_frame("response", response_payload)


def extract_first_protocol_frame(text: str) -> str | None:
    for line in text.splitlines(keepends=True):
        if not line.endswith("\n"):
            continue
        if line.startswith(PREFIX):
            return line.removesuffix("\r\n") + "\n" if line.endswith("\r\n") else line
    return None


def run_smoke(port: str, timeout: float, baudrate: int, specs_dir: Path = DEFAULT_SPECS) -> str:
    try:
        import serial  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("pyserial is required; export ESP-IDF before running this smoke test") from exc

    request_frame, expected_response_frame = load_capability_frames(specs_dir)
    deadline = time.monotonic() + timeout
    buffer = ""

    with serial.Serial(port, baudrate=baudrate, timeout=0.1) as device:
        device.reset_input_buffer()
        device.write(request_frame.encode("ascii"))
        device.flush()
        while time.monotonic() < deadline:
            chunk = device.read(512)
            if not chunk:
                continue
            buffer += chunk.decode("utf-8", errors="replace")
            frame = extract_first_protocol_frame(buffer)
            if frame is None:
                continue
            if frame != expected_response_frame:
                raise RuntimeError(f"unexpected capability response frame: {frame.strip()}")
            return frame

    raise TimeoutError(f"no capability response received from {port} within {timeout:.1f}s")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbmodem1101")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--baudrate", type=int, default=115200)
    args = parser.parse_args()

    frame = run_smoke(args.port, args.timeout, args.baudrate)
    print(frame, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
