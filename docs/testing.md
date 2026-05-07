# Testing

## Current Baseline

```sh
make ci
```

The baseline runs repository verification and the host-buildable firmware core
tests with strict C++ warnings.

## Implemented Tests

- Serial frame round-trip test against the companion-compatible known frame.
- Serial frame rejection tests for unsupported types, checksum mismatch, and
  invalid base64url payloads.
- QR envelope tests covering the shared `nseal1:` vector, prefix rejection,
  unpadded base64url rejection, and non-JSON payload rejection.
- QR `sign_event` request metadata tests covering version, `request_id`,
  method, `params` presence, and the raw `params.event_template` object
  boundary without parsing event-template fields or enabling signing.
- QR event-template safety tests covering escaped content tolerance and
  rejection of host-supplied `id`, `pubkey`, and `sig` fields.
- QR event-template field tests covering `created_at`, `kind`, `tags`, and
  `content` extraction plus missing or wrong-type field rejection.
- QR trusted-review tests comparing ESP32-generated pages and
  `approval_digest` values with shared basic and tagged review-screen vectors.
- QR trusted-review session tests proving parsed QR requests drive bounded
  display frames, final-page traversal, and request/digest-bound approval.
- QR review-flow tests proving raw scanned QR envelopes drive trusted review
  without a signing backend and unsafe QR requests are rejected before display.
- QR review I/O harness tests proving scanner, display, and physical-button
  adapter boundaries can drive the host-core review loop without adding a
  signing backend.
- QR review transcript tests covering full approval traversal and early
  rejection as deterministic frame/button/decision records from shared
  `NostrSeal/specs` review-transcript vectors.
- Host test header generation from the shared `NostrSeal/specs` serial,
  review-screen, review-display-frame, and review-transcript vectors.
- Single-repo CI falls back to fixture snapshots under `tests/fixtures/specs`
  when the sibling `NostrSeal/specs` checkout is not present. Cross-repo drift
  is still guarded by `NostrSeal/lab` integration checks.
- Approval gate tests requiring request-id and shared review-screen
  approval-digest matched approval before signing is permitted.
- Review button state-machine tests requiring traversal to the final review page
  before approval, allowing early rejection, and rejecting additional input after
  a terminal decision.
- Review display-frame tests requiring deterministic title, page indicator,
  body lines, action hints, body-line wrapping/truncation, and rejection of
  unsafe display bounds.
- Trusted review-session tests requiring display navigation, final-page
  approval, request/digest-bound `can_sign`, and rejection as a terminal
  non-signing decision. These tests consume generated trusted review requests
  from the shared review-screen vectors instead of duplicating page content by
  hand.
- Device protocol tests proving the shared ESP32-S3 scaffold capability request
  returns the shared scaffold capability response.
- Device protocol tests proving the shared ESP32-S3 scaffold `get_public_key`
  request returns the shared deterministic development public key response.
- Device protocol tests proving the shared `sign_event` fixture returns the
  shared `signing_disabled` scaffold response.
- ESP-IDF scaffold validation for required project files, ESP32-S3 target, board
  profile, and unsupported-claim rejection.
- ESP32-S3 board detection tests for serial-port discovery, native USB/JTAG
  report parsing, and missing-toolchain reporting.
- Manual ESP-IDF `v5.5.4` build, flash, and boot-log smoke test on the attached
  ESP32-S3 board.
- Optional hardware capability/public-key/signing-disabled smoke test with
  `make idf-smoke-capabilities` after exporting ESP-IDF and flashing the current
  firmware.
- Regression tests require the ESP-IDF console defaults to use native USB
  Serial/JTAG as the primary console; secondary USB logging is not enough for
  input-driven protocol smoke tests.

## Required Tests

- ESP32-S3 QR vault camera/display tests must consume the shared QR envelope,
  review-screen, `approval_digest`, and signing vectors from `NostrSeal/specs`.
- Automated ESP-IDF build smoke tests in CI or a hardware-capable runner.
- Repeatable flash smoke tests with recorded device port and board identity.
- Transport frame rejection tests.
- Companion integration tests for signed responses.
- Hardware validation reports for every physical board.

No device security claim is valid until firmware build, provisioning, approval,
and rejection behavior are verified.
