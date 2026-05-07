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
- QR event-template safety gate rejecting host-supplied `id`, `pubkey`, or
  `sig` fields before any future review or signing path.
- Minimal QR event-template field parser for `created_at`, `kind`, `tags`, and
  `content`.
- QR trusted-review builder checked against shared review-screen page and
  `approval_digest` vectors.
- Shared-spec review-screen approval digest binding in the host approval gate.
- Host-buildable review button state machine for page traversal before
  approval and terminal approve/reject decisions.
- Host-buildable trusted display frame renderer with bounded title, body-line,
  page-indicator, and action-hint fields.
- Host-buildable trusted review session combining display frames, button
  navigation, terminal approve/reject decisions, and request/digest-bound
  approval.
- QR-derived trusted-review session creation from parsed request data.
- `QrReviewFlow` host-core boundary from raw scanned QR envelope to trusted
  review frames and approval state, without signing.
- Deterministic QR review transcript helper for future display/button adapter
  acceptance tests.

Status: implemented as the first firmware-core, ESP-IDF scaffold, hardware
detection, capability-response, development public-key response, and local
hardware smoke-test foundation. The QR envelope decoder, QR request metadata
parser, event-template object boundary extraction, review button state machine,
host-supplied signed-field rejection, review page generation, and display frame
renderer are implemented in host-core only. The QR path also validates the
minimal unsigned event-template fields needed by future review generation. The
trusted review session now ties review controls and display frames to
approval-digest binding for future adapters, and QR-derived requests can enter
that same session boundary through a raw-QR review flow. Real camera, display,
and GPIO drivers remain pending. QR review transcripts provide a deterministic
host-side oracle for those adapters.

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
  are implemented. It also rejects host-supplied `id`, `pubkey`, or `sig`
  fields and parses the minimal unsigned event fields `created_at`, `kind`,
  `tags`, and `content`. QR review pages now match shared basic/tagged
  review-screen page and `approval_digest` vectors; camera capture,
  animated-frame reconstruction, hardware display output, and signing-vector
  consumption remain pending. Raw QR review flow is available in host-core for
  future camera/display/GPIO adapters.
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
