# nSealr firmware

The all-Rust cargo workspace for ESP32-based nSealr signer targets. This
repository groups the ESP32 firmware family instead of splitting every board
into a separate repository, and shares one `#![no_std]` signer backbone across
every target.

> The C++ `host_core` and the ESP-IDF `esp32_s3_usb_signer` app were retired in
> Phase 03 Task 05, once the `apps/desktop-simulator` harness proved
> `crates/nsealr-core` had full vector parity. All signer logic now lives in
> `nsealr-core`; per-target device apps (`esp-hal` + Embassy) land in later
> phases.

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
`nsealr-account-descriptor-v0`. The ESP32 QR route is pinned by
`esp32-qr-nip06-account-0`, `policy-manual-only-qr-vault`, and
`esp32-qr-sign-event-account-0`; the USB route is pinned by
`esp32-usb-device-slot-0`, `policy-manual-only-persistent-device`, and
`esp32-usb-sign-event-slot-0`. The scoped automation profile
`policy-scoped-automation-daily-use` and test grant
`grant-esp32-usb-kind-1-session` are reachable only through the device-reviewed
`esp32-usb-enable-kind-1-automation` policy-change proposal. The USB route does
not clear any production signing gate yet; signing remains disabled until
provisioning, storage, review, hardening, and signed-output verification are
accepted.

The final account/custody split is also explicit. `esp32_qr_vault` should match
the Raspberry QR vault behavior for shared features: RAM-only session keyring,
manual approval for every signature, SeedSigner SeedQR/CompactSeedQR-compatible
BIP-39 import, plain mnemonic QR, `nsec` QR, local generation, no persistent
policy, no persistent secret, and no TROPIC01. `esp32_usb_nip46` should become a
persistent encrypted device vault with seed profiles, passphrase namespaces,
NIP-06 accounts, standalone key slots, and per-public-key policy state after
production gates pass. The current policy vectors are conformance scaffolds, not
the final policy UX.

Feature targets and current status are tracked in `nSealr/specs`
`vectors/features/signer-feature-matrix-v0.json`. ESP32 may implement both QR
vault and USB/NIP-46 features, but each shared feature must keep the same
behavior as other implementations by using the shared `contract_id`. The ESP32
stateless QR vault is a parity target with the Raspberry QR vault; current
hardware readiness can differ, final vault behavior must converge.

## Current Capabilities

All protocol and approval logic lives in `crates/nsealr-core` (`#![no_std]`,
opt-in `std` facade) and is proven at parity against `nSealr/specs` by the
`apps/desktop-simulator` vector oracle. `nsealr-core` provides:

- **Transport** — `nsealr1f:` serial frame encode/decode compatible with the
  companion serial framing (shared v0 `max_serial_frame_bytes` limit, common
  line-ending tolerance, rejection of the shared invalid serial-frame vectors);
  `nsealr1:` static and `nsealr1a:` animated QR envelope decode with frame-set
  reconstruction (rejecting malformed, padded, invalid-UTF-8, oversized,
  missing-frame, and checksum-mismatched inputs); and response-envelope encoding
  of already-produced response JSON against the shared signed-response vector,
  with a response-display selector for static vs. animated output.
- **Request parsing** — QR/serial `sign_event` metadata (version, `request_id`,
  method, `params`, raw `params.event_template` boundary), minimal
  event-template fields (`created_at`, `kind`, `tags`, `content`), rejection of
  host-supplied `id`/`pubkey`/`sig`, and the shared v0 limit profile with
  applicable invalid hardening-vector rejection — before any review or signing.
- **Key sources** — canonical NIP-19 `nsec`, SeedSigner Standard SeedQR /
  CompactSeedQR, and BIP-39 English mnemonic parsing/rendering checked against
  the shared `nip19`, `seedqr`, and NIP-06 vectors. These are RAM-only
  key-source parsers; they do not derive NIP-06 keys, persist material, or sign.
- **Session / custody** — a bounded RAM-only session keyring that wipes active
  `nsec`/BIP-39 material on clear, drop, assignment, and move; secret-hidden
  import review (type, label, word count, deterministic fingerprint — never raw
  bytes); an import flow that loads the keyring only after final-page approval;
  local source generation from explicit entropy; the separate danger-zone
  backup/reveal ceremony (recovery payload emitted only after final-page
  approval); decoded-QR import; and secretless QR session-account selection that
  binds a source to account metadata and reports
  `source_public_key_proof_verified: false`.
- **Trusted review** — renderer-neutral review pages and `approval_digest`
  values checked against the shared review-screen, review-detail-page, and
  review-display-frame vectors (scroll windows, compact line styles,
  UTF-8-boundary-safe wrapping, `U+XXXX` fallback for unsupported glyphs, visible
  JSON-style control escapes); a page-traversal control state machine; a
  request-id + `approval_digest`-bound approval gate; and scanner/display/button
  I/O harnesses whose transcripts match the shared review-transcript vectors.
- **Policy** — a signing-readiness gate that keeps runtime signing disabled until
  every condition is present (runtime feature flag, parser limits, trusted
  display, physical controls, approval-digest binding, Unicode review rendering
  acceptance, key provisioning, source public-key proof, secure boot, flash
  encryption, debug lock, companion signed-output verification); and a
  policy-change review for the future persistent USB/NIP-46 route that requires
  local traversal plus physical approval and rejects companion-authoritative or
  secret-bearing proposals.
- **Protocol** — a device dispatcher answering shared-spec `get_capabilities`,
  `get_signing_status` (`signing_enabled: false` plus `development_accepted_gates`
  and the remaining missing gates), development `get_public_key`, and — after
  forcing valid `sign_event` frames through trusted review — `signing_disabled`.
  A signer-identity context binds `get_public_key`, the Event review author, and
  the `approval_digest` to one public key. There is no signing backend.

Board profiles for the no-camera LILYGO T-Display S3 (USB/display signer
candidate) and the LILYGO T-Display S3 Pro OV5640 (QR vault candidate) live in
`boards/` and are validated by `scripts/validate_firmware.py`. Concrete display,
camera, button, storage, and USB/QR drivers are built per target in later phases
(`esp-hal` + Embassy), not in this shared crate.

## Layout

- `Cargo.toml`, `crates/`, `apps/`: the Rust workspace (see below) — the home
  for all firmware logic.
- `boards/`: board and display-panel profiles, pinouts, displays, buttons, and
  hardware configs.
- `ci/`: the coverage-ratchet baseline (`ratchet.json`) and its checker.
- `scripts/`: `verify_repo.py` (repo structure) and `validate_firmware.py`
  (board profiles).
- `docs/`: architecture, testing, roadmap, audit-checklist, and security notes.

## Rust workspace

The Rust cargo workspace is the backbone for every nSealr target:

- `crates/nsealr-core`: the shared, `#![no_std]` signer core. It builds
  bare-metal by default (verified against `riscv32imafc-unknown-none-elf`) and
  exposes an opt-in `std` feature (default-off) for host/desktop consumers and
  tests. The full C++ `host_core` logic (transports, key sources,
  session/custody, trusted review, policy, device protocol) was ported into it
  in Phase 03.
- `apps/desktop-simulator`: the permanent `std` vector-replay harness — **the
  parity oracle every Rust app in this workspace must pass** before it may claim
  vector compliance (`apps/vault-esp32`, `apps/key`, `apps/one`, `apps/vault-pi`
  as they land). Its test suite exhaustively replays every in-scope
  `specs/vectors/<category>/*.json` file (glob-driven over the sibling `specs`
  checkout; root overridable via `NSEALR_VECTORS_ROOT`) end-to-end through
  `nsealr-core`'s public API and asserts each vector's own expected outcome; a
  completeness rule fails the suite if a `specs/vectors/` directory is neither
  in-scope nor on the documented exclusion list. The same loader backs a CLI for
  ad hoc debugging: `cargo run -p desktop-simulator -- transports/qr-envelope-kind-1-basic.json`.
  Run it via `make vector-harness` (wired into `rust-ci`/`ci`).
- `apps/`: the remaining per-target Rust binaries land in later phases
  (`vault-esp32`, `key`, `one`, `vault-pi`) — see `apps/README.md`.
  `crates/board-registry` is likewise reserved, not scaffolded.

The toolchain is pinned in `rust-toolchain.toml` (explicit stable channel +
the `riscv32imafc-unknown-none-elf` target). The Xtensa ESP32-S3 is not a rustup
target; its `esp` toolchain is set up in Phase 05 Task 00, not here.

The full Rust gate set (`cargo fmt --check`, `cargo clippy -- -D warnings
-D dead_code`, `cargo test` on both the default `no_std` and the `std` feature
plus a `riscv32imafc` `no_std` build, the `vector-harness` parity oracle,
`cargo deny check`, the `cargo-llvm-cov` coverage ratchet against
`ci/ratchet.json`, and the `repro-build` byte-identity gate) runs as the
`rust-ci` target and is wired into `make ci`. Run just the Rust gates with
`make rust-ci`.

The workspace's release artifacts are **reproducible and CI-verified**: the
toolchain is fully pinned, the dependency closure is committed (`Cargo.lock`)
and vendored (`vendor/`, built offline via `.cargo/config.toml`), and
`make repro-build` proves — with an actual double build, never an assertion —
that two clean builds produce byte-identical artifacts and that the
`nsealr-core` device backbone reproduces byte-for-byte from an independent
checkout at a different path. Follow the published recipe in
[`docs/reproducible-build.md`](docs/reproducible-build.md) to reproduce the
artifacts and confirm the recorded hashes. (The offline release-key signing
ceremony is Phase 11, not here.)

## Quality Baseline

Run the repository verification loop with:

```sh
make ci
```

`make ci` is a single Rust gate set plus the generic Python validators
(`verify_repo.py` for repo structure, `validate_firmware.py` for the
`boards/*.json` profiles). There is no board-flashing or hardware-smoke target in
this repository yet: on-device build/flash/smoke tooling returns with the Rust
device apps (`apps/vault-esp32` in Phase 04, `apps/key` in Phase 05). See
`docs/testing.md` for the full gate breakdown and `docs/architecture.md` for the
workspace structure.

## License

Firmware and tooling are released under the MIT License unless a file says
otherwise. Third-party SDK and component licenses must be preserved.
