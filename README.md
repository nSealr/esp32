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

## Initial Layout

- `firmware/`: ESP-IDF firmware projects and shared modules.
- `boards/`: board profiles, pinouts, displays, buttons, and hardware configs.
- `docs/`: build, flash, provisioning, and security notes.

## License Plan

Firmware should use GPL-3.0 or another strong copyleft license compatible with
the chosen ESP-IDF dependencies and bundled crypto libraries.

