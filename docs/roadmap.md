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
- Serial/USB `sign_event` trusted-review request creation from decoded request
  JSON, using the same review pages and `approval_digest` contract as QR.
- `SerialReviewIo` host-core adapter harness for future USB signer display and
  physical-button drivers, without signing.
- `QrReviewFlow` host-core boundary from raw scanned QR envelope to trusted
  review frames and approval state, without signing.
- `QrReviewIo` host-core adapter harness for future scanner, display, and
  physical-button drivers, without signing.
- Bounded `QrReviewIo` loop that fails on non-terminal button streams instead
  of hanging a future adapter.
- `QrReviewIo` result transcript covering the exact frame/button sequence shown
  by the driver-facing harness, checked against shared review-transcript
  vectors.
- Deterministic QR review transcript helper for future display/button adapter
  acceptance tests, checked against shared `NostrSeal/specs` transcript
  vectors.
- Shared review-display-frame vector consumption for bounded long-content
  display rendering.
- Host-buildable runtime signing-readiness gate covering runtime feature flag,
  parser limits, trusted display acceptance, physical controls,
  approval-digest binding, key provisioning, secure boot, debug lock, and
  companion signed-output verification.
- Machine-readable development security profile for the ESP32-S3 USB signer,
  explicitly blocking production signing until runtime signing, trusted
  display, physical controls, key provisioning, secure boot, flash encryption,
  debug lock, and companion signed-output verification are complete.

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
number of steps, and returns the terminal approval state plus the exact
displayed frame/button transcript. Real camera, display, and GPIO drivers remain
pending. QR review transcripts provide a deterministic host-side oracle for
those adapters and are now checked against shared `NostrSeal/specs` vectors. The
host-core QR parser also mirrors the shared v0 limit profile and rejects
applicable invalid QR-envelope and signing-request vectors before trusted review
can begin.

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

Status note, 2026-05-08: valid serial/USB `sign_event` requests now pass
through a host-core trusted-review boundary before the disabled-signing
response is returned. The boundary builds the same review pages and
`approval_digest` as the QR path from decoded request JSON, so the USB signer
cannot drift from shared review semantics before real display/GPIO drivers or a
signing backend are connected. Runtime signing remains disabled.

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

Hardware note, 2026-05-08: revision `351d693` was built and flashed to the
same attached ESP32-S3 DevKitC-1. The expanded hardware smoke verified six
valid static/dynamic responses plus 20 deterministic `unsupported_request`
error frames for invalid metadata and 18 serial-wrapped invalid signing-request
vectors, including the shared unknown top-level request-field vector. Real
signing remains disabled.

Hardware note, 2026-05-08: revision `c47b655` was built and flashed to the
same attached ESP32-S3 DevKitC-1. The expanded hardware smoke verified six
valid static/dynamic responses plus 22 deterministic `unsupported_request`
error frames for invalid metadata and 20 serial-wrapped invalid signing-request
vectors, including `params` misuse on the parameterless `get_capabilities` and
`get_public_key` methods. Real signing remains disabled.

Hardware note, 2026-05-08: revision `9ae6e7a` was built and flashed to the
same attached ESP32-S3 DevKitC-1. The expanded hardware smoke verified six
valid static/dynamic responses plus 27 deterministic `unsupported_request`
error frames for invalid metadata and 25 serial-wrapped invalid signing-request
vectors, including structurally invalid `sign_event` `params` and
`event_template` shapes. Real signing remains disabled.

Hardware note, 2026-05-08: revision `b7aa30a` was built with local ESP-IDF
`v5.5.4`, flashed to the attached ESP32-S3 DevKitC-1 on
`/dev/cu.usbmodem1101`, and smoke-tested with `make
IDF_PORT=/dev/cu.usbmodem1101 idf-smoke-capabilities`. This run verifies that
the firmware still builds, flashes, and preserves the USB serial scaffold
contract after compiling the QR review I/O transcript helper into host-core:
capability and development public-key requests succeed, `sign_event` returns
`signing_disabled`, and invalid requests return deterministic
`unsupported_request` frames. Real camera, display, GPIO, storage, secure boot,
debug-lock, and signing acceptance remain pending.

Hardware note, 2026-05-08: revision `f307b41` was rebuilt and reflashed on the
attached ESP32-S3 DevKitC-1 on `/dev/cu.usbmodem1101` after a diagnostic
protocol-smoke timeout exposed repeated bootloader `Checksum failed` and
`Factory app partition is not bootable` messages. The recovery reflash used
ESP-IDF `v5.5.4`; esptool verified bootloader, app, and partition-table image
hashes, and the follow-up `make IDF_PORT=/dev/cu.usbmodem1101
idf-smoke-capabilities` passed. The result is recorded as a manual
`NostrSeal/hardware` protocol-smoke report and does not change the disabled
signing boundary.

Hardware note, 2026-05-08: revision `dfdeec9` was built with local ESP-IDF
`v5.5.4`, flashed to the attached ESP32-S3 DevKitC-1 on
`/dev/cu.usbmodem1101`, and smoke-tested with `make
IDF_PORT=/dev/cu.usbmodem1101 idf-smoke-capabilities`. This run verifies that
the serial `sign_event` trusted-review boundary compiles into the ESP-IDF
component while the USB serial scaffold still answers capability and
development public-key requests, returns `signing_disabled` for `sign_event`,
and rejects invalid requests with deterministic `unsupported_request` frames.
Real display, GPIO, camera, storage, secure boot, debug lock, and signing
acceptance remain pending.

## M7: Firmware Foundation

- Board profiles.
- Protocol parser.
- `get_capabilities`, development `get_public_key`, and disabled `sign_event`
  USB serial smoke tests.
- Display/button abstraction.
  Status: host-core `QrReviewIo` now defines the scanner/display/button
  adapter boundary for the QR review loop, and revision `b7aa30a` confirms that
  transcript-producing host-core still builds and flashes inside the ESP-IDF
  component. Real ESP-IDF drivers remain pending.
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

Status note, 2026-05-08: the host-core serial/USB path now builds a
trusted-review request for valid `sign_event` frames and verifies that its
pages and `approval_digest` match the shared review-screen vectors. The
dispatcher still returns `signing_disabled`, so this is review-boundary
alignment only, not signing enablement.

Status note, 2026-05-08: `SerialReviewIo` now gives the USB signer path the
same host-core display/button adapter harness shape as the QR path. Decoded
serial `sign_event` JSON is rendered into bounded trusted frames, physical-style
button input advances the review session, and the resulting frame/button
transcript is returned for future adapter acceptance tests. No signing backend
is connected.

Status note, 2026-05-08: `signing_policy` now makes the M8 runtime signing gate
explicit in host-core. The default state remains disabled and reports missing
runtime feature, parser limits, trusted display, physical controls,
approval-digest binding, key provisioning, secure boot, debug lock, and
companion signed-output verification gates. This compiles into the ESP-IDF
component but does not enable signing.

Status note, 2026-05-08: the ESP32-S3 USB signer scaffold now includes a
validated `security_profile.json`. The v0 profile is `development_scaffold`,
keeps runtime and production signing disabled, records secure boot, flash
encryption, debug lock, key provisioning, trusted display, physical controls,
and signed-output verification as production blockers, and is enforced by
`make ci`.

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
