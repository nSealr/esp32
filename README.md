# NostrSeal ESP32

Firmware for ESP32-based NostrSeal signer targets.

This repository groups the ESP32 firmware family instead of splitting every
board into a separate repository.

## Planned Targets

- ESP32-S3 USB/NIP-46 signer with display and buttons.
- ESP32-S3 QR vault with camera/display research boards.
- Classic ESP32/TTGO compatibility signer.
- ESP32-S3 plus TROPIC01 embedded variant.
- Custom ESP32-S3 product PCB firmware.

## Current Capabilities

- Host-buildable C++ firmware core foundation.
- ESP-IDF scaffold for the ESP32-S3 USB signer target.
- Host-side ESP32-S3 detection gate for native USB/JTAG serial boards.
- Local ESP-IDF `v5.5.4` build and flash smoke test on an attached ESP32-S3.
- `nseal1f:` serial frame encode/decode compatible with the companion serial
  framing draft.
- `nseal1:` QR envelope decode boundary compatible with the shared QR
  transport vector. It validates envelope framing only; camera capture,
  animated QR reconstruction, full event parsing, and signing remain future
  work.
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
- QR trusted-review page generation from parsed event templates, checked
  against shared `NostrSeal/specs` review-screen vectors. QR-derived
  `approval_digest`, camera input, display/GPIO drivers, key storage, and
  signing remain disabled.
- ESP32-S3 scaffold capability response over the same `nseal1f:` frame
  contract used by the companion.
- ESP32-S3 scaffold `get_public_key` response using the shared deterministic
  development-only fixture key.
- Primary ESP-IDF console configured on native USB Serial/JTAG so the scaffold
  can receive hardware smoke-test requests over the attached USB-C cable.
- Portable SHA-256 checksum helper for frame corruption detection.
- Approval gate state machine requiring request-id and approval-digest matched
  approval before a request can be signed.
- Host-buildable review controls, display frames, and trusted review session
  that model the future display/button approval loop without enabling signing.
- Generated host test fixtures from shared serial and review-screen vectors in
  `NostrSeal/specs`.
- Board profile for the LILYGO T-Display S3 Pro with OV5640 camera as the
  primary ESP32-S3 QR vault candidate. The profile documents display, camera,
  touch, physical-approval, wireless-disabled, and debug-lock constraints; it
  does not add real camera/display/GPIO drivers.

The current firmware is still a scaffold. It logs startup, answers
`get_capabilities`, returns the deterministic development public key for
`get_public_key`, returns an explicit `signing_disabled` protocol response for
the shared `sign_event` fixture, and keeps real signing disabled until storage,
trusted review, approval controls, and signing tests are implemented.

The future ESP32-S3 QR vault target belongs in this repository as ESP32
firmware. It must reuse the shared QR envelope, review model, review-screen
vectors, `approval_digest`, and signing vectors from `NostrSeal/specs`; it
should not depend on Raspberry implementation code.

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

## License

Firmware and tooling are released under the MIT License unless a file says
otherwise. Third-party SDK and component licenses must be preserved.
