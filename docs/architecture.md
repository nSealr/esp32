# Architecture

`NostrSeal/esp32` contains firmware for ESP32-based signer targets.

## Targets

- ESP32-S3 USB signer.
- ESP32-S3 QR vault target.
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

The ESP32-S3 QR vault target is part of this repository, not the Raspberry
repository. It should reuse shared `NostrSeal/specs` contracts for the QR
envelope, trusted-review model, review-screen vectors, `approval_digest`, and
signing vectors while implementing camera/display/button handling with ESP32
firmware components.

## Implemented Host Core

The first firmware foundation is host-buildable C++ under
`firmware/host_core`.

- `serial_frame`: encodes and decodes newline-terminated `nseal1f:` frames with
  type, base64url JSON payload, and checksum.
- `sha256`: portable SHA-256 helper used for the frame checksum.
- `approval_gate`: request-id and approval-digest bound approval state
  machine, checked against shared `NostrSeal/specs` review-screen vectors.
- `review_controls`: page-by-page review button state machine for future
  display/button adapters. It refuses approval until the final review page is
  reached, keeps rejection available before signing, and treats approval or
  rejection as terminal.
- `device_protocol`: scaffold request dispatcher for shared-spec capability,
  development public-key, and disabled-signing responses. It does not sign
  events.

This code is intentionally independent of ESP-IDF so protocol and approval
logic can be tested on desktop before it is wrapped by USB CDC, UART, display,
button, secure storage, and signing components.

Host tests generate their transport-vector header from `NostrSeal/specs` so the
firmware core is checked against the same serial frame vector used by the
companion.
The same generated header now includes review-screen approval digests, allowing
the host-core approval gate to reject request/review swaps before any future
signing backend is connected.

The review-control state machine is intentionally separate from
`approval_gate`: `review_controls` models local user navigation, while
`approval_gate` binds the final approval to the request id and
`approval_digest`. The future display/button adapter must satisfy both before a
real signing backend can be connected.

## ESP-IDF Scaffold

`firmware/esp32_s3_usb_signer` is the first ESP-IDF project scaffold for the
ESP32-S3 USB signer. It currently boots, uses native USB Serial/JTAG as the
primary ESP-IDF console, reads newline-terminated `nseal1f:` frames from that
console, answers the shared `get_capabilities` request, returns the shared
development public key for `get_public_key`, returns the shared
`signing_disabled` response for the basic `sign_event` fixture, and logs that
signing is disabled. It does not yet include storage, production key
provisioning, display review, button approval, or signing components.
