# Testing

## Current Baseline

```sh
make ci
```

The baseline runs repository verification and the host-buildable firmware core
tests with strict C++ warnings.

## Implemented Tests

- Serial frame round-trip test against the companion-compatible known frame.
- Serial frame line-ending test proving the host-core decoder accepts common
  `LF`/`CRLF` serial input without weakening checksum validation.
- Serial frame rejection tests for unsupported types, checksum mismatch, and
  invalid base64url payloads.
- Shared invalid serial-frame vector tests for oversized frames, checksum
  mismatch, and malformed payloads, plus a host-core assertion that
  `kMaxSerialFrameBytes` matches the shared v0 limit profile.
- QR envelope tests covering the shared `nseal1:` vector, prefix rejection,
  unpadded base64url rejection, invalid UTF-8 rejection, oversized decoded
  payload rejection, and non-JSON payload rejection.
- QR `sign_event` request metadata tests covering version, `request_id`,
  method, `params` presence, and the raw `params.event_template` object
  boundary without parsing event-template fields or enabling signing.
- QR event-template safety tests covering escaped content tolerance and
  rejection of host-supplied `id`, `pubkey`, and `sig` fields.
- QR event-template field tests covering `created_at`, `kind`, `tags`, and
  `content` extraction plus missing or wrong-type field rejection.
- QR parser hardening tests proving host-core constants mirror the shared v0
  limit profile and applicable shared invalid signing-request vectors are
  rejected before review/signing.
- QR trusted-review tests comparing ESP32-generated pages and
  `approval_digest` values with shared basic and tagged review-screen vectors.
- Serial/USB `sign_event` trusted-review tests proving decoded request JSON
  produces the same review pages and `approval_digest` as the shared QR review
  contract, while the device protocol still returns `signing_disabled`.
- Serial/USB review I/O harness tests proving future USB signer display and
  physical-button adapters can drive the same trusted review session from
  decoded request JSON without adding a signing backend.
- Signing-policy tests proving runtime signing remains disabled until every M8
  gate is present: runtime feature flag, parser limits, trusted display,
  physical controls, approval-digest binding, key provisioning, secure boot,
  flash encryption, debug lock, and companion signed-output verification.
- Security-profile validation proving the ESP32-S3 USB signer scaffold remains
  development-only, with production signing disabled and secure boot, flash
  encryption, debug lock, key provisioning, trusted display, physical controls,
  and signed-output verification listed as blockers.
- Board-profile validation for the no-camera LILYGO T-Display S3 USB/display
  signer candidate, keeping it separate from the T-Display S3 Pro OV5640 QR
  vault camera target.
- Firmware board-config tests proving the compiled T-Display S3 constants match
  the JSON board profile and are included by the ESP-IDF scaffold.
- Firmware display-driver tests proving the T-Display S3 ESP-IDF scaffold
  compiles an ST7789/i80 adapter and boot-frame path while keeping physical
  GPIO approval and signing disabled.
- Firmware button-driver tests proving the T-Display S3 scaffold maps vendor
  documented GPIO0/GPIO14 physical controls to Back/Next short presses and
  Reject/Approve long presses, while keeping touch disallowed for approval and
  signing disabled.
- QR trusted-review session tests proving parsed QR requests drive bounded
  display frames, final-page traversal, and request/digest-bound approval.
- QR review-flow tests proving raw scanned QR envelopes drive trusted review
  without a signing backend and unsafe QR requests are rejected before display.
- QR review I/O harness tests proving scanner, display, and physical-button
  adapter boundaries can drive the host-core review loop without adding a
  signing backend, and that non-terminal button streams fail within a bounded
  number of steps instead of hanging the adapter loop. The same tests now assert
  the returned I/O transcript matches the shared review-transcript vector, so
  future drivers can prove what they actually displayed and accepted.
- QR review transcript tests covering full approval traversal and early
  rejection as deterministic frame/button/decision records from shared
  `NostrSeal/specs` review-transcript vectors.
- Host test header generation from the shared `NostrSeal/specs` serial,
  review-screen, review-display-frame, review-transcript, limits, and invalid
  hardening vectors.
- Single-repo CI falls back to fixture snapshots under `tests/fixtures/specs`
  when the sibling `NostrSeal/specs` checkout is not present. Cross-repo drift
  is still guarded by `NostrSeal/lab` integration checks.
- Approval gate tests requiring request-id and shared review-screen
  approval-digest matched approval before signing is permitted.
- Review button state-machine tests requiring traversal to the final review page
  before approval, allowing backward navigation during review, allowing early
  rejection, and rejecting additional input after a terminal decision.
- Review display-frame tests requiring deterministic title, page indicator,
  body lines, action hints, body-line wrapping/truncation, and rejection of
  unsafe display bounds.
- Trusted review-session tests requiring display navigation, backward review,
  final-page approval, request/digest-bound `can_sign`, and rejection as a
  terminal non-signing decision. These tests consume generated trusted review
  requests from the shared review-screen vectors instead of duplicating page
  content by hand.
- Firmware scaffold tests requiring T-Display S3 terminal review decisions to
  show closed non-signing status frames with `Not signed` and
  `Signing disabled` after approve/reject UI input.
- Firmware scaffold tests requiring rejected serial requests to clear active
  T-Display S3 review state and show an explicit non-signing request-error
  frame instead of leaving stale review content visible.
- Firmware scaffold tests requiring stale active T-Display S3 review sessions
  to expire after a bounded inactivity window, clear RAM-only review state, and
  show `Review Timeout` / `Expired` / `Not signed` without enabling signing.
- Host-compiled T-Display S3 review-state helper tests proving timeout math,
  activity refresh, clear behavior, and unsigned tick wraparound outside the
  ESP-IDF runtime loop.
- Device protocol tests proving the shared ESP32-S3 scaffold capability request
  returns the shared scaffold capability response.
- Device protocol tests proving the shared ESP32-S3 scaffold
  `get_signing_status` request returns `signing_enabled: false` plus the
  remaining real-signing readiness gates for the current scaffold profile,
  while omitting parser limits and approval-digest binding because those gates
  are already implemented and tested in host-core.
- Device protocol tests proving the shared ESP32-S3 scaffold `get_public_key`
  request returns the shared deterministic development public key response.
- Device protocol tests proving the shared `sign_event` fixture returns the
  shared `signing_disabled` scaffold response.
- Device protocol tests proving valid serial-frame request payloads with
  non-fixture `request_id` values receive matching dynamic responses for
  `get_capabilities`, `get_signing_status`, development `get_public_key`, and
  disabled `sign_event`.
- ESP-IDF scaffold validation for required project files, ESP32-S3 target, board
  profile, and unsupported-claim rejection.
- ESP32-S3 board detection tests for serial-port discovery, native USB/JTAG
  report parsing, and missing-toolchain reporting.
- Manual ESP-IDF `v5.5.4` build, flash, boot-log smoke test, and
  capability/public-key/signing-disabled protocol smoke test on the attached
  ESP32-S3 board.
- Optional hardware capability/public-key/signing-disabled smoke test with
  `make idf-smoke-capabilities` after exporting ESP-IDF and flashing the current
  firmware. The smoke sends both shared fixture request frames and dynamic
  `request_id` variants, including `get_signing_status`, so parser changes
  cannot silently fall back to exact fixture matching. It also sends invalid dynamic metadata requests from shared
  `NostrSeal/specs` invalid serial-frame vectors plus serial-wrapped invalid
  signing-request vectors, including unknown top-level request fields,
  expecting deterministic `unsupported_request` rejections. By default the
  smoke prints a clean summary; raw protocol frames are available with
  `scripts/smoke_capabilities.py --verbose-frames`.
- Manual T-Display S3 display exerciser tests proving
  `scripts/manual_review_display.py` builds dynamic disabled `sign_event`
  exchanges, composes the request-error scenario from shared invalid vectors,
  and runs exchanges through a fake serial device without opening hardware.
- Hardened firmware smoke evidence recorded for revision `dd2d5d1` on
  `/dev/cu.usbmodem101`; this confirms only scaffold protocol behavior and the
  expected `signing_disabled` refusal path.
- QR review I/O transcript firmware smoke evidence recorded for revision
  `b7aa30a` on `/dev/cu.usbmodem1101`; this confirms the transcript-producing
  host-core compiles into the ESP-IDF component while the attached-board smoke
  still exercises only the USB serial scaffold, development public-key fixture,
  `signing_disabled` refusal path, and deterministic invalid-request errors.
- Serial review-boundary firmware smoke evidence recorded for revision
  `dfdeec9` on `/dev/cu.usbmodem1101`; this confirms the serial `sign_event`
  trusted-review boundary compiles into the ESP-IDF component while the
  attached-board smoke still preserves the USB serial scaffold,
  `signing_disabled` refusal path, and deterministic invalid-request errors.
- Regression tests require the ESP-IDF console defaults to use native USB
  Serial/JTAG as the primary console; secondary USB logging is not enough for
  input-driven protocol smoke tests.

## Required Tests

- ESP32-S3 QR vault camera/display tests must consume the shared QR envelope,
  review-screen, `approval_digest`, and signing vectors from `NostrSeal/specs`.
- Expand pre-signing hardening tests as host-core gains more JSON/schema
  coverage. The current host-core already consumes the shared invalid vectors
  where the QR parser owns the boundary, but richer schema diagnostics can be
  added without enabling signing.
- Automated ESP-IDF build smoke tests in CI or a hardware-capable runner.
- Repeatable flash smoke tests with recorded device port and board identity.
- Transport frame rejection tests.
- Companion integration tests for signed responses.
- Hardware validation reports for every physical board.

No device security claim is valid until firmware build, provisioning, parser
limits, trusted review, physical approval, approval-digest binding, companion
verification, and deterministic rejection behavior are verified. Runtime
signing remains disabled until those gates pass.
