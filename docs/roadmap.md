# Roadmap

## Foundation: Host-Buildable Firmware Core

- C++ serial frame encode/decode.
- Portable SHA-256 checksum helper.
- Approval gate state machine.
- Host test binary with strict warnings.
- ESP-IDF project scaffold.
- ESP32-S3 DevKitC-1 board profile.
- Physical ESP32-S3 detection gate for native USB/JTAG serial boards.
- Local ESP-IDF `v5.5.4` build, flash, and boot-log smoke test.

Status: implemented as the first firmware-core, ESP-IDF scaffold, hardware
detection, and local hardware smoke-test foundation.

## M7: Firmware Foundation

- Board profiles.
- Protocol parser.
- Display/button abstraction.
- Repeatable ESP-IDF build and flash command wrappers.
- Add display/button acceptance tests before enabling any real signing path.

## M8: ESP32-S3 USB Signer MVP

- USB transport.
- `get_public_key`.
- `sign_event`.
- Approval loop.
- Companion integration.

## M9: Security Hardening

- Secure boot.
- Flash encryption.
- Firmware update policy.
- Debug lock policy.
