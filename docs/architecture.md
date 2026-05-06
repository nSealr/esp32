# Architecture

`NostrSeal/esp32` contains firmware for ESP32-based signer targets.

## Targets

- ESP32-S3 USB signer.
- ESP32-S3 QR signer.
- Classic ESP32/TTGO compatibility signer.
- Optional ESP32-S3 plus TROPIC01 variant.

## Responsibilities

- Parse NostrSeal signing requests.
- Render trusted review on local display where available.
- Require physical approval or rejection.
- Sign only after approval.
- Return verifiable responses to the companion.
- Document secure boot, flash encryption, provisioning, and recovery.

ESP-IDF is the default firmware framework for serious ESP32-S3 work.

