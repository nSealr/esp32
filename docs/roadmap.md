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
- Local ESP-IDF `v5.5.4` build, flash, boot-log smoke test, and
  capability/public-key/signing-disabled protocol smoke test.
- Shared v0 serial-frame byte limit and invalid serial-frame vector rejection
  for oversized frames, checksum mismatch, and malformed payloads.
- Shared-spec `get_capabilities` response through host-core protocol handling.
- Shared-spec `get_public_key` development response through host-core protocol
  handling.
- Shared-spec `sign_event` disabled response through host-core protocol
  handling.
- Dynamic serial request-id echo for valid `get_capabilities`, `get_public_key`,
  and disabled `sign_event` requests instead of only recognizing exact fixture
  payloads.
- Shared-spec QR envelope decode boundary for future ESP32-S3 QR vault camera
  input.
- QR `sign_event` request metadata parser for decoded envelopes, including the
  raw `params.event_template` object boundary.
- QR event-template safety gate rejecting host-supplied `id`, `pubkey`, or
  `sig` fields before any future review or signing path.
- Minimal QR event-template field parser for `created_at`, `kind`, `tags`, and
  `content`.
- Shared v0 parser/resource limits and applicable invalid hardening-vector
  rejection for QR envelopes and QR signing requests before review/signing.
- QR trusted-review builder checked against shared review-screen page and
  `approval_digest` vectors.
- Shared-spec review-screen approval digest binding in the host approval gate.
- Host-buildable review button state machine for page traversal before
  approval and terminal approve/reject decisions.
- Host-buildable trusted display frame renderer with bounded title, body-line,
  page-indicator, and action-hint fields.
- Host-buildable body-line wrapping/truncation for trusted display frames.
- Host-buildable trusted review session combining display frames, button
  navigation, terminal approve/reject decisions, and request/digest-bound
  approval.
- QR-derived trusted-review session creation from parsed request data.
- `QrReviewFlow` host-core boundary from raw scanned QR envelope to trusted
  review frames and approval state, without signing.
- `QrReviewIo` host-core adapter harness for future scanner, display, and
  physical-button drivers, without signing.
- Bounded `QrReviewIo` loop that fails on non-terminal button streams instead
  of hanging a future adapter.
- Deterministic QR review transcript helper for future display/button adapter
  acceptance tests, checked against shared `NostrSeal/specs` transcript
  vectors.
- Shared review-display-frame vector consumption for bounded long-content
  display rendering.

Status: implemented as the first firmware-core, ESP-IDF scaffold, hardware
detection, capability-response, development public-key response, and local
hardware smoke-test foundation. The QR envelope decoder, QR request metadata
parser, event-template object boundary extraction, review button state machine,
host-supplied signed-field rejection, review page generation, and display frame
renderer are implemented in host-core only. The QR path also validates the
minimal unsigned event-template fields needed by future review generation. The
trusted review session now ties review controls and display frames to
approval-digest binding for future adapters, and QR-derived requests can enter
that same session boundary through a raw-QR review flow. Display frames now
wrap and truncate body text to configured limits. The host-core now also has a
scanner/display/button I/O harness that shows every trusted frame before
reading physical-style input, rejects non-terminal input streams after a bounded
number of steps, and returns only the terminal approval state. Real camera,
display, and GPIO drivers remain pending. QR review transcripts provide a
deterministic host-side oracle for those adapters and are now checked against
shared `NostrSeal/specs` vectors. The host-core QR parser also mirrors the
shared v0 limit profile and rejects applicable invalid QR-envelope and
signing-request vectors before trusted review can begin.

Status note, 2026-05-08: the host-core serial decoder now mirrors the shared v0
`max_serial_frame_bytes` limit and rejects the shared invalid serial-frame
vectors for oversized frames, checksum mismatch, and malformed base64url
payloads. The ESP-IDF input loop uses the same limit before dispatching a frame
to host-core.

Status note, 2026-05-08: the host-core device protocol now decodes serial-frame
request payloads, validates the v0 `request_id` profile, and echoes dynamic
request ids in `get_capabilities`, development `get_public_key`, and disabled
`sign_event` responses. `sign_event` still returns `signing_disabled`; no
signing backend, storage, display driver, or GPIO approval path is connected.

Status note, 2026-05-08: `make idf-smoke-capabilities` now sends both the
shared fixture requests and dynamic `request_id` variants for capabilities,
development public-key, and disabled `sign_event` handling. This makes the
hardware smoke catch regressions where the ESP-IDF app only recognizes exact
fixture payloads.

Status note, 2026-05-08: the same hardware smoke now sends invalid dynamic
request metadata from shared `NostrSeal/specs` serial-frame vectors for
unsupported version and invalid `request_id` syntax. The expected device
behavior is a deterministic `nseal1f:error` frame with `unsupported_request`,
preserving the signing-disabled boundary.

Status note, 2026-05-08: invalid signing-request vectors from `NostrSeal/specs`
are now wrapped as serial frames in the hardware smoke, including invalid
`sign_event` request shapes and unknown top-level request fields. The device
protocol catches parser rejections inside the request boundary and returns
deterministic `unsupported_request` frames instead of surfacing parser
exceptions to the ESP-IDF console loop.

Hardware note, 2026-05-08: revision `dd2d5d1` was built with local ESP-IDF
`v5.5.4`, flashed to the attached ESP32-S3 DevKitC-1 on `/dev/cu.usbmodem101`,
and smoke-tested with `make IDF_PORT=/dev/cu.usbmodem101
idf-smoke-capabilities`. The device returned capability and deterministic
development public-key frames, then rejected the shared `sign_event` request
with `signing_disabled`. Real signing remains disabled.

## M7: Firmware Foundation

- Board profiles.
- Protocol parser.
- `get_capabilities`, development `get_public_key`, and disabled `sign_event`
  USB serial smoke tests.
- Display/button abstraction.
  Status: host-core `QrReviewIo` now defines the scanner/display/button
  adapter boundary for the QR review loop, while real ESP-IDF drivers remain
  pending.
- Host-rendered review frame contract for display drivers.
- Repeatable ESP-IDF build and flash command wrappers.
- Add display/button acceptance tests before enabling any real signing path.

## M8: ESP32-S3 USB Signer MVP

- USB transport.
- Production key generation/import and `get_public_key`.
- `sign_event` behind display review and physical approval.
- Approval loop.
- Companion integration.

Hard blocker before real `sign_event`: the M7.5 pre-signing hardening gate
must pass. That means host-core parser/resource limits, shared malicious-vector
rejection where feasible, display review driver acceptance, physical button
acceptance, `approval_digest` binding, key provisioning/storage design, secure
boot/debug policy, and companion verification of signed output are all tested.
Until then runtime signing remains disabled.

## M8.5: ESP32-S3 QR Vault Target

- Camera/display board selection. Status: LILYGO T-Display S3 Pro with OV5640
  camera is the primary board-profile candidate; T-Camera Plus S3 remains
  secondary evaluation hardware in `NostrSeal/lab`.
- QR request scanner using shared `NostrSeal/specs` QR envelope vectors.
  Status: host-core `nseal1:` envelope decoding, top-level `sign_event`
  metadata parsing, and raw `params.event_template` object boundary extraction
  are implemented. It also rejects host-supplied `id`, `pubkey`, or `sig`
  fields, applies shared v0 parser/resource limits, rejects applicable invalid
  hardening vectors, and parses the minimal unsigned event fields `created_at`,
  `kind`, `tags`, and `content`. QR review pages now match shared basic/tagged
  review-screen page and `approval_digest` vectors; camera capture,
  animated-frame reconstruction, hardware display output, and signing-vector
  consumption remain pending. Raw QR review flow is available in host-core for
  future camera/display/GPIO adapters.
- Trusted review pages using shared review-screen vectors and `approval_digest`.
- Physical approve/reject loop.
- Signed-event QR output verified by the companion.

Status: future target in this repository. It must not be moved into
`NostrSeal/raspberry`. It also must not sign real QR requests until the shared
pre-signing hardening vectors are consumed where feasible and the camera,
display, GPIO, and review acceptance gates are complete.

## M9: Security Hardening

- Secure boot.
- Flash encryption.
- Firmware update policy.
- Debug lock policy.
