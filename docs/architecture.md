# Architecture

`nSealr/firmware` is the all-Rust cargo workspace for every nSealr signer
target. The signing logic is toolchain-independent and lives in one shared,
`#![no_std]` crate; each device is a thin Rust binary that wraps that crate with
board bring-up (display, buttons/camera, storage, USB/QR transport) on
`esp-hal` + Embassy.

> The C++ `host_core` and the ESP-IDF `esp32_s3_usb_signer` app were retired in
> Phase 03 Task 05. Their protocol, review, session/custody, and policy logic
> was ported into `crates/nsealr-core` and is proven at byte-for-byte parity by
> the `apps/desktop-simulator` vector oracle. This document describes the
> post-retirement all-Rust structure; the retired trees are history, not current
> architecture.

## Workspace layout

- `crates/nsealr-core` — the shared `#![no_std]` signer backbone. It builds
  bare-metal by default (verified against `riscv32imafc-unknown-none-elf`) and
  exposes an opt-in, default-off `std` feature for host/desktop consumers and
  tests. It owns: serial (`nsealr1f:`) and QR (`nsealr1:` / `nsealr1a:`)
  transport codecs, the key-source parsers (BIP-39 English, SeedSigner Standard
  SeedQR / CompactSeedQR, NIP-19 `nsec`), the RAM-only session keyring and
  import/generation/backup flows, trusted-review page/frame/control/approval-gate
  state machines, the signing-readiness policy and policy-change review, and the
  device-protocol request dispatcher. It has **no signing backend**: valid
  `sign_event` requests are reviewed and then answered `signing_disabled`.
- `apps/desktop-simulator` — the permanent `std` vector-replay harness and the
  CI-enforced parity oracle. It exhaustively replays every in-scope
  `nSealr/specs` `vectors/<category>/*.json` file through `nsealr-core`'s public
  API and enforces a completeness rule so no vector category can silently escape
  coverage. Every Rust device app must pass this gate before claiming vector
  compliance.
- `apps/*` — the per-target device binaries land in later phases:
  `vault-esp32` (Phase 04 stateless QR vault), `key` (Phase 05 USB/NIP-46
  signer), `one` (custom persistent-secret wallet), `vault-pi` (Raspberry Pi QR
  vault port). Each links `nsealr-core` and must pass the parity oracle.
- `boards/` — toolchain-agnostic board/display-panel profiles (targets, display,
  approval inputs, camera, wireless/debug policy), validated by
  `scripts/validate_firmware.py`.
- `ci/` — the Rust coverage-ratchet baseline (`ratchet.json`) and its checker.
- `docs/` — this documentation set.

## Targets

- ESP32 USB/NIP-46 signer, with ESP32-S3 as the primary target. The no-camera
  LILYGO T-Display S3 is tracked as an integrated display candidate for the
  USB/display signer line.
- ESP32 stateless QR vault target, with T-Display S3 Pro OV5640 as the primary
  camera/display target and Waveshare ESP32-S3 Touch LCD 3.5B-C as the confirmed
  secondary case-plus-OV5640 target.
- Classic ESP32/TTGO compatibility target under the USB/NIP-46 family.
- ESP32-S3 plus TROPIC01 prototype under the custom persistent-secret
  hardware-wallet research family.

## Responsibilities

- Parse nSealr signing requests.
- Render trusted review on the local display where available.
- Require physical approval or rejection.
- Sign only after approval (no signing backend exists yet).
- Return verifiable responses to the companion.
- Document secure boot, flash encryption, provisioning, and recovery per target.

The ESP32 stateless QR vault target is part of this repository, not the
Raspberry repository. It reuses the shared `nSealr/specs` contracts for the QR
envelope, trusted-review model, review-screen vectors, `approval_digest`, and
signing vectors while implementing camera/display/button handling in its own
Rust app. It must not add persistent-secret storage or TROPIC01 dependencies.

## Identity and policy boundary

The shared identity contracts split the ESP32 family into two route types:

- `esp32_qr_vault`: stateless QR route, transport `qr`, custody
  `stateless_session`, manual-only policy support, no persistent key-at-rest, no
  policy automation, no TROPIC01 dependency, `persistent_grants: false`. The
  shared descriptor is `esp32-qr-nip06-account-0`, bound to
  `policy-manual-only-qr-vault`, with request routing pinned by
  `esp32-qr-sign-event-account-0`.
- `esp32_usb_nip46`: future persistent daily-use route, transport `usb`, custody
  `device_persistent`, trusted review `device_display`, default
  `policy-manual-only-persistent-device`, with request routing pinned by
  `esp32-usb-sign-event-slot-0`. The `policy-scoped-automation-daily-use`
  profile is entered only through the device-reviewed
  `esp32-usb-enable-kind-1-automation` policy-change proposal.

The `nsealr-account-descriptor-v0` USB vector `esp32-usb-device-slot-0`, the
policy-change vector `esp32-usb-enable-kind-1-automation`, and the grant vector
`grant-esp32-usb-kind-1-session` are conformance contracts only. They do not
authorize persistent grants or enable real signing. The firmware keeps runtime
signing disabled until provisioning/storage, display review, physical controls,
Unicode review rendering, secure boot, flash encryption, debug lock, and
companion signed-output verification are accepted.

`nsealr-core`'s device-protocol layer carries a signer-identity context: the
`get_public_key` response, the Event review author field, and the
`approval_digest` signer-author binding all use one identity. The development
scaffold context uses the deterministic fixture public key from the shared
vectors, while the QR session-account boundary can inject a selected RAM-only
account identity before trusted review. Persistent USB provisioning must reuse
that same identity-context boundary instead of a global development key.

For the QR route, the key-source behavior mirrors the Raspberry QR vault: a
RAM-only session keyring fed by manual BIP-39 words, SeedSigner Standard SeedQR,
CompactSeedQR, plain mnemonic QR, `nsec` QR, or local generation, persisting no
policy state or secret material. For the USB/NIP-46 route, the target is a
persistent encrypted device vault after production gates pass (seed profiles,
BIP-39 passphrase namespaces, NIP-06 account selections, standalone key slots,
per-public-key policy) behind one device-level unlock ceremony. Policy changes
must be locally reviewed and physically approved on the device; companion
proposals are not authoritative by themselves.

Feature target and status are tracked in `nSealr/specs`
`vectors/features/signer-feature-matrix-v0.json`. Device apps may have
board-specific drivers, but any shared feature — request validation, trusted
review, approval-digest binding, QR/serial transport, response verification —
must match the shared `contract_id` rather than becoming a board-local behavior.

## The `nsealr-core` backbone

`nsealr-core` is the single home for all protocol and approval logic, kept
independent of any board HAL so it can be exhaustively tested on desktop before
a device app wraps it with USB CDC, UART, display, buttons, secure storage, and
(eventually) a signing backend. The crate is organised as:

- **Transport** — `serial` encodes/decodes newline-terminated `nsealr1f:` frames
  (type, base64url JSON payload, checksum) and mirrors the shared v0
  `max_serial_frame_bytes` limit; `qr` decodes `nsealr1:` static and `nsealr1a:`
  animated QR envelopes (unpadded base64url, UTF-8, size limits, frame-set
  reconstruction) and encodes already-produced response JSON into static and
  animated response envelopes. Both reject the shared invalid transport vectors.
- **Key sources** — `bip39`, `seedqr`, and `nip19` decode manual mnemonics,
  Standard/CompactSeedQR, and canonical NIP-19 `nsec` into RAM-only session
  sources with BIP-39 checksum validation. None derive NIP-06 keys, persist
  material, or sign.
- **Session / custody** — `session` holds a bounded RAM-only keyring that wipes
  active source material on clear/drop/move, plus secret-hidden import review,
  import flow (approval only on the final page), local source generation, the
  separate danger-zone backup/reveal ceremony, and the decoded-QR import path.
- **Trusted review** — `review` builds renderer-neutral review pages, bounded
  display frames (UTF-8-boundary-safe wrapping, `U+XXXX` fallback for
  unsupported glyphs, visible JSON-style control escapes), a page-traversal
  control state machine, and a request-id + `approval_digest`-bound approval
  gate. Approval is reachable only after the user has traversed the displayed
  pages. Pages and digests are checked against the shared review-screen,
  review-detail-page, review-display-frame, and review-transcript vectors.
- **Policy** — `policy` holds the signing-readiness gate (every condition that
  must hold before a signing backend may be wired in) and the policy-change
  review boundary for future persistent-device policy updates. The default
  readiness state is disabled and reports every missing gate.
- **Protocol** — `protocol` dispatches shared-spec `get_capabilities`,
  `get_signing_status`, development `get_public_key`, and `sign_event` requests.
  Valid `sign_event` frames are forced through the trusted-review request
  builder and then answered `signing_disabled`; there is no signing backend.

Because the review renderer is hardware-neutral it never drives a concrete
display controller directly; it produces bounded frames that a device app's
`esp-hal` display driver paints without changing review, approval, or signing
semantics. The review-control state machine is intentionally separate from the
approval gate: controls model local navigation, while the gate binds the final
approval to the request id and `approval_digest`. A device app must satisfy both
before any real signing backend can be connected.
