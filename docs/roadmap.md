# Roadmap

## Foundation: Host-Buildable Firmware Core

- C++ serial frame encode/decode.
- Portable SHA-256 checksum helper.
- Approval gate state machine.
- Host test binary with strict warnings.
- ESP-IDF project scaffold.
- ESP32-S3 DevKitC-1 board profile.

Status: implemented as the first firmware-core and ESP-IDF scaffold foundation.

## M7: Firmware Foundation

- Board profiles.
- Protocol parser.
- Display/button abstraction.
- Build smoke test.

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
