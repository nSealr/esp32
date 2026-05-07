# NostrSeal ESP32

Firmware for ESP32-based NostrSeal signer targets.

This repository groups the ESP32 firmware family instead of splitting every
board into a separate repository.

## Planned Targets

- ESP32-S3 USB/NIP-46 signer with display and buttons.
- ESP32-S3 QR signer with camera/display research boards.
- Classic ESP32/TTGO compatibility signer.
- ESP32-S3 plus TROPIC01 embedded variant.
- Custom ESP32-S3 product PCB firmware.

## Current Capabilities

- Host-buildable C++ firmware core foundation.
- ESP-IDF scaffold for the ESP32-S3 USB signer target.
- Host-side ESP32-S3 detection gate for native USB/JTAG serial boards.
- Local ESP-IDF `v5.5.4` build and flash smoke test on an attached ESP32-S3.
- `nseal1f:` serial frame encode/decode compatible with the companion serial
  framing draft.
- Portable SHA-256 checksum helper for frame corruption detection.
- Approval gate state machine requiring request-id-matched approval before a
  request can be signed.

The current flashed firmware is only a boot scaffold. It logs startup and
explicitly keeps signing disabled until storage, trusted review, approval
controls, and protocol tests are implemented.

## Initial Layout

- `firmware/`: ESP-IDF firmware projects and shared modules.
- `boards/`: board profiles, pinouts, displays, buttons, and hardware configs.
- `docs/`: build, flash, provisioning, and security notes.

## Quality Baseline

Run the repository verification loop with:

```sh
make ci
```

Build/flash prerequisites and commands are documented in `docs/flash.md`.
Physical board detection can be checked with:

```sh
make detect-board
```

## License

Firmware and tooling are released under the MIT License unless a file says
otherwise. Third-party SDK and component licenses must be preserved.
