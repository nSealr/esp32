# nSealr ESP32

Firmware for ESP32-based nSealr signer targets.

This repository groups the ESP32 firmware family instead of splitting every
board into a separate repository.

## Planned Targets

- ESP32 USB/NIP-46 signer with ESP32-S3 as the primary display/button target.
  The no-camera LILYGO T-Display S3 is tracked as an integrated display-board
  candidate for this line.
- ESP32 stateless QR vault with T-Display S3 Pro OV5640 as the primary
  camera/display target.
- Classic ESP32/TTGO compatibility target under the USB/NIP-46 family.
- Future ESP32-S3 plus TROPIC01 prototype only under the custom
  persistent-secret hardware-wallet research family.

The shared identity/policy route split is explicit: `esp32_qr_vault` remains a
stateless, manual-only QR route with `persistent_grants: false`, while
`esp32_usb_nip46` is the future persistent daily-use route described by
`nsealr-account-descriptor-v0`, `policy-scoped-automation-daily-use`, and the
test grant `grant-esp32-usb-kind-1-session`. The USB route does not clear any
production signing gate yet; signing remains disabled until provisioning,
storage, review, hardening, and signed-output verification are accepted.

The final account/custody split is also explicit. `esp32_qr_vault` should
match the Raspberry QR vault behavior for shared features: RAM-only session
keyring, manual approval for every signature, SeedSigner
SeedQR/CompactSeedQR-compatible BIP-39 import, plain mnemonic QR, `nsec` QR,
local generation, no persistent policy, no persistent secret, and no TROPIC01.
`esp32_usb_nip46` should become a persistent encrypted device vault with seed
profiles, passphrase namespaces, NIP-06 accounts, standalone key slots, and
per-public-key policy state after production gates pass. The current policy
vectors are conformance scaffolds, not the final policy UX.

Feature targets and current status are tracked in `nSealr/specs`
`vectors/features/signer-feature-matrix-v0.json`. ESP32 may implement both QR
vault and USB/NIP-46 features, but each shared feature must keep the same
behavior as other implementations by using the shared `contract_id`. The ESP32
stateless QR vault is a parity target with the Raspberry QR vault; current
hardware readiness can differ, final vault behavior must converge.

## Current Capabilities

- Host-buildable C++ firmware core foundation.
- ESP-IDF scaffold for the ESP32-S3 USB signer target.
- Host-side ESP32-S3 detection gate for native USB/JTAG serial boards.
- Local ESP-IDF `v5.5.4` build, flash, and capability/public-key/signing-disabled
  smoke test on an attached ESP32-S3.
- `nsealr1f:` serial frame encode/decode compatible with the companion serial
  framing draft. The decoder mirrors the shared v0 `max_serial_frame_bytes`
  limit, accepts common serial line endings, and rejects shared invalid
  serial-frame vectors for unsupported frame types, oversized frames, checksum
  mismatch, and malformed base64url payloads.
- `nsealr1:` static QR envelope decode boundary plus `nsealr1a:` animated QR
  frame reconstruction compatible with the shared transport vectors. The host
  core rejects malformed, padded, invalid UTF-8, oversized, missing-frame, and
  checksum-mismatched QR inputs before any future camera/display adapter can
  review them; camera capture, animated scan timing, and signing remain future
  work.
- QR `sign_event` request metadata parsing for decoded envelopes. It extracts
  version, `request_id`, method, `params` presence, and the raw
  `params.event_template` object boundary. The minimal field parser is
  described below; signing remains disabled.
- QR event-template safety gate rejecting host-supplied `id`, `pubkey`, or
  `sig` fields before any future review/signing path. The parser tolerates
  normal JSON string escapes while keeping full event semantics pending.
- Minimal QR event-template field parsing for `created_at`, `kind`, `tags`, and
  `content`. This prepares trusted review generation without enabling tag
  semantics, key storage, or signing.
- Host-core NIP-19 `nsec` decoder checked against the shared
  `nSealr/specs` vector. This is a RAM-only key-source parser for the future
  ESP32 QR vault; it does not add persistent key slots, storage, policies, or a
  signing backend.
- Shared nSealr v0 implementation limits for constrained firmware parsing,
  with host-core rejection of applicable invalid QR-envelope and signing-request
  hardening vectors before review or signing can be reached.
- QR trusted-review page generation from parsed event templates, checked
  against shared `nSealr/specs` review-screen vectors. QR-derived
  `approval_digest` now matches shared basic/tagged vectors, while camera
  input, display/GPIO drivers, key storage, and signing remain disabled.
- T-Display S3 sized QR review detail pages checked against shared
  `nSealr/specs` review-detail-page vectors. These pin complete
  Event/Content/Tags/Decision pages, scroll windows, compact line styles, long
  value continuations, visible JSON-style escapes for decoded control
  characters, and explicit `U+XXXX` fallback for unsupported display glyphs
  without changing the `approval_digest` contract. Supported printable ASCII
  punctuation remains literal in review text.
- QR-derived trusted-review session creation that drives the existing bounded
  display-frame and approval-gate state machines. It is still host-core only
  and has no signing backend.
- `QrReviewFlow` host-core boundary from raw scanned `nsealr1:` QR envelope to
  trusted review frames and physical approval state. It rejects unsafe QR
  requests before a future camera/display adapter can display them.
- `QrReviewIo` host-core adapter harness for future scanner, display, and
  physical-button drivers. It scans one QR request, shows each trusted frame
  before reading a button, bounds non-terminal button streams, and returns the
  terminal approval state plus the exact displayed frame/button transcript; it
  still has no signing backend.
- Serial/USB `sign_event` trusted-review boundary for decoded request JSON.
  It builds the same review pages and `approval_digest` as the QR path before
  the runtime dispatcher returns `signing_disabled`.
- `SerialReviewIo` host-core adapter harness for future USB signer display and
  physical-button drivers. It reads one decoded serial request, shows each
  trusted frame before reading a button, and returns a frame/button transcript;
  it still has no signing backend.
- Deterministic QR review transcripts for display/button adapter tests. A
  transcript records each displayed frame, input button, decision, and approval
  state without exposing any signing output, and the host-core tests consume the
  shared `nSealr/specs` review-transcript vectors.
- ESP32-S3 scaffold capability response over the same `nsealr1f:` frame
  contract used by the companion.
- ESP32-S3 scaffold `get_public_key` response using the shared deterministic
  development-only fixture key.
- ESP32-S3 scaffold request dispatcher that parses valid serial-frame request
  payloads and echoes dynamic `request_id` values for `get_capabilities`,
  `get_signing_status`, `get_public_key`, and disabled `sign_event` responses.
- Primary ESP-IDF console configured on native USB Serial/JTAG so the scaffold
  can receive hardware smoke-test requests over the attached USB-C cable.
- Portable SHA-256 checksum helper for frame corruption detection.
- Approval gate state machine requiring request-id and approval-digest matched
  approval before a request can be signed.
- Host-buildable review controls, display frames, and trusted review session
  that model the future display/button approval loop without enabling signing.
- Host-buildable signing-readiness policy that keeps runtime signing disabled
  until parser limits, trusted display, physical controls, approval-digest
  binding, Unicode review rendering acceptance, key provisioning, secure boot,
  flash encryption, debug lock, companion verification, and an explicit runtime
  feature flag are all present.
- Shared identity/policy descriptors are tracked without enabling signing:
  `esp32_usb_nip46` is a persistent-slot route for future scoped automation,
  and `esp32_qr_vault` remains manual-only/stateless with
  `persistent_grants: false` and no TROPIC01 dependency.
- Machine-readable ESP32-S3 USB signer security profile that records the
  current development-only hardening state and production blockers before any
  persistent-secret or real-signing path can be claimed.
- The security profile now also records manual development acceptance evidence
  for T-Display S3 trusted display and physical approve/reject controls, while
  keeping those gates as production blockers. Display-review protocol smoke
  reports are tracked separately for review-rendering traceability and do not
  replace production trusted-display acceptance.
- Unicode review rendering is tracked as its own blocker: the development
  display path uses explicit `U+XXXX` fallback for unsupported non-ASCII glyphs,
  renders decoded control characters as visible JSON-style escapes, and this
  does not count as full production Unicode review acceptance.
- Companion transport evidence is tracked separately from companion
  signed-output verification. Direct serial-line smokes prove request-bound
  USB host/device exchange and the expected `signing_disabled` refusal; they do
  not clear the signed-output production blocker.
- Firmware protocol evidence is tracked separately from display/control
  acceptance and signed-output verification. Current T-Display S3 hardware
  smokes prove the flashed firmware still answers valid protocol requests,
  rejects invalid protocol input deterministically, exposes the Unicode review
  rendering gate, normalizes duplicate signing-status development gates, and
  refuses valid `sign_event` requests with `signing_disabled`; they do not
  clear real-signing blockers.
- Read-only ESP32-S3 security eFuse audit support through
  `make idf-audit-security-fuses`. The audit reports secure boot, flash
  encryption, download-mode, and debug-lock fuse state without burning or
  modifying eFuses; it measures the M9 hardening gap and does not clear any
  production signing blocker. The security profile tracks these reports in a
  separate `security_fuse_audit_evidence` field.
- Trusted display frames wrap and truncate long body text to configured display
  limits, giving small ESP32 screens and display adapters a deterministic
  rendering oracle.
- Generated host test fixtures from shared serial, review-screen,
  review-display-frame, review-detail-page, review-transcript, limits, and invalid hardening
  vectors in `nSealr/specs`.
- Board profile for the no-camera LILYGO T-Display S3 as an ESP32-S3
  USB/display signer candidate. The profile documents integrated ST7789
  display constraints, GPIO0/GPIO14 onboard button mapping, touch-not-approval,
  wireless policy, debug-lock policy, and disabled production signing.
- Initial T-Display S3 ST7789/i80 ESP-IDF display bring-up for the USB/display
  signer scaffold. It pins the display dimensions, bus pins, GPIO38 backlight,
  GPIO15 display-power line, no-camera status, and touch-not-approval rule,
  then draws a Ready/No request frame while keeping storage and signing
  disabled.
- Host-buildable T-Display S3 raster tests cover the same boot and review-frame
  pixel-color function used by the ESP-IDF ST7789/i80 draw path, including
  border, boot pattern, title, page indicator, body, footer samples, and
  representative printable ASCII punctuation glyphs. Value/continuation lines
  use a dedicated yellow display color so long pubkeys, content chunks, and tag
  items remain visually grouped after wrapping.
- T-Display S3 onboard button polling for manual review navigation after a live
  `sign_event` request. Short GPIO14 cycles the stable Event, Content, Tags,
  and Decision pages; short GPIO0 scrolls within Content or Tags when that
  page has more display windows; long GPIO14 maps Approve on the Decision
  page; and long GPIO0 maps Reject from any page. The runtime still returns
  `signing_disabled`, shows a terminal non-signing review screen after
  approve/reject, expires stale active review sessions into a terminal
  non-signing timeout frame, and never signs.
- Host-buildable T-Display S3 button logic tests cover debounce filtering,
  short-press classification, long-press classification, and the GPIO0/GPIO14
  review-button mapping used by the ESP-IDF GPIO polling adapter.
- Host-buildable T-Display S3 status-frame tests cover the non-signing Ready,
  approve/reject-closed, timeout, and request-error frames shown by the runtime
  display loop, keeping user-visible safety copy out of untested `main.cpp`
  branches.
- Host-buildable T-Display S3 serial-input tests cover overlong-frame refusal
  and drain-until-newline behavior so a rejected transport frame cannot leave
  tail bytes to contaminate the next request line.
- Board profile for the LILYGO T-Display S3 Pro with OV5640 camera as the
  primary ESP32 stateless QR vault candidate. The profile documents display, camera,
  touch, physical-approval, wireless-disabled, and debug-lock constraints; it
  does not add real camera/display/GPIO drivers.

The current firmware is still a scaffold. It logs startup, answers
`get_capabilities`, returns the deterministic development public key for
`get_public_key`, returns explicit signing-readiness diagnostics through
`get_signing_status`, returns an explicit `signing_disabled` protocol response
for valid `sign_event` requests, initializes the T-Display S3 display only far
enough to draw a Ready/No request frame and live trusted-review pages, polls the
two onboard physical buttons for local review navigation, shows closed review
decisions as `Not signed`, clears active review state on rejected serial
requests, drains overlong serial input until the next newline, and keeps real
signing disabled until storage, production hardening, and signing tests are
implemented.
An active T-Display S3 review session is RAM-only and expires after five
minutes of inactivity; expiry clears the session and shows `Review Timeout` /
`Expired` / `Not signed` rather than leaving stale event content on screen.

The ESP32 stateless QR vault target belongs in this repository as ESP32
firmware. It must reuse the shared QR envelope, review model, review-screen
vectors, `approval_digest`, and signing vectors from `nSealr/specs`; it
should not depend on Raspberry implementation code. It has no persistent secret
and no TROPIC01 dependency.

## Initial Layout

- `firmware/`: ESP-IDF firmware projects and shared modules.
- `boards/`: board profiles, pinouts, displays, buttons, and hardware configs.
- `docs/`: build, flash, provisioning, and security notes.

## Quality Baseline

Run the repository verification loop with:

```sh
make ci
```

Build/flash prerequisites and commands are documented in `docs/flash.md`.
Physical board detection can be checked with:

```sh
make detect-board
make idf-smoke-capabilities
make idf-audit-security-fuses
```

The hardware smoke sends the shared fixture requests and additional dynamic
`request_id` variants for capabilities, signing status, development public-key,
and disabled `sign_event` handling. It also sends invalid dynamic metadata requests from
shared specs vectors plus serial-wrapped invalid signing-request vectors,
including unknown top-level request fields, and expects deterministic
`unsupported_request` rejections. It also exercises shared malformed serial
transport vectors for checksum mismatch, malformed base64url payload,
unsupported frame type, and overlong frame handling, expecting deterministic
`malformed_frame` or `overlong_frame` errors, then sends a fresh valid
capability request to prove the runtime drained the overlong line and recovered
before the next request.
The default smoke output summarizes expected rejections instead of printing raw
protocol error frames; use
`scripts/smoke_capabilities.py --verbose-frames` when raw frames are needed.
Real signing is still expected to return `signing_disabled`.
The security-fuse audit is read-only. It calls `espefuse.py summary` and prints
JSON describing current secure boot, flash encryption, download-mode, and
debug-lock state.

For manual T-Display S3 display inspection after flashing, use:

```sh
python3 scripts/manual_review_display.py show-review --port /dev/cu.<device>
python3 scripts/manual_review_display.py show-dense-tags --port /dev/cu.<device>
python3 scripts/manual_review_display.py show-request-error --port /dev/cu.<device>
python3 scripts/manual_review_display.py button-approve --port /dev/cu.<device>
python3 scripts/manual_review_display.py button-reject --port /dev/cu.<device>
```

`show-review` leaves a valid disabled `sign_event` review on the physical
display. `show-dense-tags` stresses a valid event with enough structured tags
to require Tags scroll windows without interpreting tag meaning or abbreviating
values. `show-request-error` first shows that review and then sends an invalid
request so the firmware should clear the active review and display the
non-signing request-error state. `button-approve` and `button-reject` send the
same valid review request and print the physical-control checklist for manual
approval/rejection acceptance. Terminal request-error, approve, and reject
screens include the final `Send new request` prompt. All modes still expect
signing to remain disabled.

## License

Firmware and tooling are released under the MIT License unless a file says
otherwise. Third-party SDK and component licenses must be preserved.
