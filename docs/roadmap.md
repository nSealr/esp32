# Roadmap

## Foundation: Host-Buildable Firmware Core

- C++ serial frame encode/decode.
- Portable SHA-256 checksum helper.
- Approval gate state machine.
- Host test binary with strict warnings.
- ESP-IDF project scaffold.
- ESP32-S3 DevKitC-1 board profile.
- LILYGO T-Display S3 Pro OV5640 board profile for the future ESP32-S3 QR
  vault target.
- Physical ESP32-S3 detection gate for native USB/JTAG serial boards.
- Local ESP-IDF `v5.5.4` build, flash, and boot-log smoke test.
- Shared-spec `get_capabilities` response through host-core protocol handling.
- Shared-spec `get_public_key` development response through host-core protocol
  handling.
- Shared-spec `sign_event` disabled response through host-core protocol
  handling.
- Shared-spec QR envelope decode boundary for future ESP32-S3 QR vault camera
  input.
- QR `sign_event` request metadata parser for decoded envelopes, including the
  raw `params.event_template` object boundary.
- Shared-spec review-screen approval digest binding in the host approval gate.
- Host-buildable review button state machine for page traversal before
  approval and terminal approve/reject decisions.
- Host-buildable trusted display frame renderer with bounded title, body-line,
  page-indicator, and action-hint fields.
- Host-buildable trusted review session combining display frames, button
  navigation, terminal approve/reject decisions, and request/digest-bound
  approval.

Status: implemented as the first firmware-core, ESP-IDF scaffold, hardware
detection, capability-response, development public-key response, and local
hardware smoke-test foundation. The QR envelope decoder, QR request metadata
parser, event-template object boundary extraction, review button state machine,
and display frame renderer are implemented in host-core only. The trusted
review session now ties review controls and display frames to approval-digest
binding for future adapters; real camera, display, and GPIO drivers remain
pending.

## M7: Firmware Foundation

- Board profiles.
- Protocol parser.
- `get_capabilities`, development `get_public_key`, and disabled `sign_event`
  USB serial smoke tests.
- Display/button abstraction.
- Host-rendered review frame contract for display drivers.
- Repeatable ESP-IDF build and flash command wrappers.
- Add display/button acceptance tests before enabling any real signing path.

## M8: ESP32-S3 USB Signer MVP

- USB transport.
- Production key generation/import and `get_public_key`.
- `sign_event` behind display review and physical approval.
- Approval loop.
- Companion integration.

## M8.5: ESP32-S3 QR Vault Target

- Camera/display board selection. Status: LILYGO T-Display S3 Pro with OV5640
  camera is the primary board-profile candidate; T-Camera Plus S3 remains
  secondary evaluation hardware in `NostrSeal/lab`.
- QR request scanner using shared `NostrSeal/specs` QR envelope vectors.
  Status: host-core `nseal1:` envelope decoding, top-level `sign_event`
  metadata parsing, and raw `params.event_template` object boundary extraction
  are implemented; camera capture, animated-frame reconstruction, full
  event-template parsing, review generation, and signing-vector consumption
  remain pending.
- Trusted review pages using shared review-screen vectors and `approval_digest`.
- Physical approve/reject loop.
- Signed-event QR output verified by the companion.

Status: future target in this repository. It must not be moved into
`NostrSeal/raspberry`.

## M9: Security Hardening

- Secure boot.
- Flash encryption.
- Firmware update policy.
- Debug lock policy.
