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
- `nseal1f:` serial frame encode/decode compatible with the companion serial
  framing draft.
- Portable SHA-256 checksum helper for frame corruption detection.
- Approval gate state machine requiring request-id-matched approval before a
  request can be signed.

## Initial Layout

- `firmware/`: ESP-IDF firmware projects and shared modules.
- `boards/`: board profiles, pinouts, displays, buttons, and hardware configs.
- `docs/`: build, flash, provisioning, and security notes.

## Quality Baseline

Run the repository verification loop with:

```sh
make ci
```

## License

Firmware and tooling are released under the MIT License unless a file says
otherwise. Third-party SDK and component licenses must be preserved.
