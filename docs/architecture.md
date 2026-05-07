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

## Implemented Host Core

The first firmware foundation is host-buildable C++ under
`firmware/host_core`.

- `serial_frame`: encodes and decodes newline-terminated `nseal1f:` frames with
  type, base64url JSON payload, and checksum.
- `sha256`: portable SHA-256 helper used for the frame checksum.
- `approval_gate`: request-id-bound approval state machine.

This code is intentionally independent of ESP-IDF so protocol and approval
logic can be tested on desktop before it is wrapped by USB CDC, UART, display,
button, secure storage, and signing components.

Host tests generate their transport-vector header from `NostrSeal/specs` so the
firmware core is checked against the same serial frame vector used by the
companion.
