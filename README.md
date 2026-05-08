# NostrSeal ESP32

Firmware for ESP32-based NostrSeal signer targets.

This repository groups the ESP32 firmware family instead of splitting every
board into a separate repository.

## Planned Targets

- ESP32 USB/NIP-46 signer with ESP32-S3 as the primary display/button target.
- ESP32 stateless QR vault with T-Display S3 Pro OV5640 as the primary
  camera/display target.
- Classic ESP32/TTGO compatibility target under the USB/NIP-46 family.
- Future ESP32-S3 plus TROPIC01 prototype only under the custom
  persistent-secret hardware-wallet research family.

## Current Capabilities

- Host-buildable C++ firmware core foundation.
- ESP-IDF scaffold for the ESP32-S3 USB signer target.
- Host-side ESP32-S3 detection gate for native USB/JTAG serial boards.
- Local ESP-IDF `v5.5.4` build, flash, and capability/public-key/signing-disabled
  smoke test on an attached ESP32-S3.
- `nseal1f:` serial frame encode/decode compatible with the companion serial
  framing draft. The decoder mirrors the shared v0 `max_serial_frame_bytes`
  limit and rejects shared invalid serial-frame vectors for oversized frames,
  checksum mismatch, and malformed base64url payloads.
- `nseal1:` QR envelope decode boundary compatible with the shared QR
  transport vector. It rejects malformed, padded, invalid UTF-8, and oversized
  envelopes before any future camera/display adapter can review them; camera
  capture, animated QR reconstruction, and signing remain future work.
- QR `sign_event` request metadata parsing for decoded envelopes. It extracts
  version, `request_id`, method, `params` presence, and the raw
  `params.event_template` object boundary. It does not parse event-template
  fields or enable signing.
- QR event-template safety gate rejecting host-supplied `id`, `pubkey`, or
  `sig` fields before any future review/signing path. The parser tolerates
  normal JSON string escapes while keeping full event semantics pending.
- Minimal QR event-template field parsing for `created_at`, `kind`, `tags`, and
  `content`. This prepares trusted review generation without enabling tag
  semantics, key storage, or signing.
- Shared NostrSeal v0 implementation limits for constrained firmware parsing,
  with host-core rejection of applicable invalid QR-envelope and signing-request
  hardening vectors before review or signing can be reached.
- QR trusted-review page generation from parsed event templates, checked
  against shared `NostrSeal/specs` review-screen vectors. QR-derived
  `approval_digest` now matches shared basic/tagged vectors, while camera
  input, display/GPIO drivers, key storage, and signing remain disabled.
- QR-derived trusted-review session creation that drives the existing bounded
  display-frame and approval-gate state machines. It is still host-core only
  and has no signing backend.
- `QrReviewFlow` host-core boundary from raw scanned `nseal1:` QR envelope to
  trusted review frames and physical approval state. It rejects unsafe QR
  requests before a future camera/display adapter can display them.
- `QrReviewIo` host-core adapter harness for future scanner, display, and
  physical-button drivers. It scans one QR request, shows each trusted frame
  before reading a button, bounds non-terminal button streams, and returns only
  the approval state; it still has no signing backend.
- Deterministic QR review transcripts for display/button adapter tests. A
  transcript records each displayed frame, input button, decision, and approval
  state without exposing any signing output, and the host-core tests consume the
  shared `NostrSeal/specs` review-transcript vectors.
- ESP32-S3 scaffold capability response over the same `nseal1f:` frame
  contract used by the companion.
- ESP32-S3 scaffold `get_public_key` response using the shared deterministic
  development-only fixture key.
- ESP32-S3 scaffold request dispatcher that parses valid serial-frame request
  payloads and echoes dynamic `request_id` values for `get_capabilities`,
  `get_public_key`, and disabled `sign_event` responses.
- Primary ESP-IDF console configured on native USB Serial/JTAG so the scaffold
  can receive hardware smoke-test requests over the attached USB-C cable.
- Portable SHA-256 checksum helper for frame corruption detection.
- Approval gate state machine requiring request-id and approval-digest matched
  approval before a request can be signed.
- Host-buildable review controls, display frames, and trusted review session
  that model the future display/button approval loop without enabling signing.
- Trusted display frames wrap and truncate long body text to configured display
  limits, giving small ESP32 screens a deterministic pre-driver rendering
  oracle.
- Generated host test fixtures from shared serial, review-screen,
  review-display-frame, review-transcript, limits, and invalid hardening
  vectors in `NostrSeal/specs`.
- Board profile for the LILYGO T-Display S3 Pro with OV5640 camera as the
  primary ESP32 stateless QR vault candidate. The profile documents display, camera,
  touch, physical-approval, wireless-disabled, and debug-lock constraints; it
  does not add real camera/display/GPIO drivers.

The current firmware is still a scaffold. It logs startup, answers
`get_capabilities`, returns the deterministic development public key for
`get_public_key`, returns an explicit `signing_disabled` protocol response for
valid `sign_event` requests, and keeps real signing disabled until storage,
trusted review, approval controls, and signing tests are implemented.

The ESP32 stateless QR vault target belongs in this repository as ESP32
firmware. It must reuse the shared QR envelope, review model, review-screen
vectors, `approval_digest`, and signing vectors from `NostrSeal/specs`; it
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
```

The hardware smoke sends the shared fixture requests and additional dynamic
`request_id` variants for capabilities, development public-key, and disabled
`sign_event` handling. It also sends invalid dynamic metadata requests from
shared specs vectors and expects deterministic `unsupported_request` error
frames. Real signing is still expected to return `signing_disabled`.

## License

Firmware and tooling are released under the MIT License unless a file says
otherwise. Third-party SDK and component licenses must be preserved.
