# Testing

## Baseline

```sh
make ci
```

`make ci` is a single-toolchain (Rust) gate set plus the generic Python
repo/board validators — the C++ and ESP-IDF gates were removed with the retired
`host_core`/ESP-IDF app in Phase 03 Task 05. It runs, in order:

- `scripts/verify_repo.py` — baseline repo structure (required files and the
  post-retirement Rust directory set: `crates`, `apps`, `ci`, `boards`, `docs`,
  `scripts`).
- `scripts/validate_firmware.py` — the `boards/*.json` signer-board and
  display-panel registry profiles.
- `python -m compileall scripts` — the remaining Python tooling compiles.
- `rust-ci` — the Rust workspace gate set:
  - `cargo fmt --all --check`
  - `cargo clippy --all-targets [--all-features] -- -D warnings -D dead_code`
  - `cargo test --workspace`, plus `cargo test -p nsealr-core --features std`
    (proves the `std` facade is never inert) and a
    `cargo build -p nsealr-core --target riscv32imafc-unknown-none-elf` bare-metal
    build
  - `vector-harness` (`cargo test -p desktop-simulator`) — the parity oracle
  - `cargo deny check`
  - `coverage-ratchet` — `cargo llvm-cov` measured against `ci/ratchet.json`
    (the ratchet only tightens)

Run just the Rust gates with `make rust-ci`.

## The vector-parity oracle

`apps/desktop-simulator` is the permanent parity oracle. Its test suite
glob-discovers every in-scope `nSealr/specs` `vectors/<category>/*.json` file
(over the sibling `specs` checkout, root overridable via `NSEALR_VECTORS_ROOT`),
replays each one end-to-end through `nsealr-core`'s public API, and asserts the
vector's own expected outcome. A completeness rule fails the suite if a
`vectors/` category is neither in-scope nor on the documented exclusion list, so
new shared vectors cannot silently escape firmware coverage. The same loader
backs a CLI for ad-hoc debugging:

```sh
cargo run -p desktop-simulator -- transports/qr-envelope-kind-1-basic.json
```

## `nsealr-core` coverage

`cargo test --workspace` exercises the backbone directly. Coverage spans, at a
high level:

- **Transport** — `nsealr1f:` serial frame round-trip, line-ending tolerance,
  and rejection of the shared invalid serial-frame vectors (unsupported type,
  checksum mismatch, malformed payload, oversized); `nsealr1:` / `nsealr1a:` QR
  envelope decode and animated frame-set reconstruction, plus rejection of
  malformed, padded, invalid-UTF-8, oversized, missing-frame, and
  checksum-mismatched inputs; response-envelope encoding against the shared
  signed-response vector.
- **Request parsing** — `sign_event` metadata (version, `request_id`, method,
  `params`, the raw `params.event_template` boundary), event-template field
  extraction (`created_at`, `kind`, `tags`, `content`), rejection of
  host-supplied `id`/`pubkey`/`sig`, and the shared v0 limit profile with
  applicable invalid hardening vectors.
- **Key sources** — NIP-19 `nsec`, Standard SeedQR / CompactSeedQR, and BIP-39
  English parsing/rendering against the shared `nip19`, `seedqr`, and NIP-06
  mnemonic vectors, including checksum and canonicalisation rejections.
- **Session / custody** — RAM-only keyring wipe-on-clear/drop/move, secret-hidden
  import review against `session-import-reviews`, import flow (final-page-only
  approval), source generation, danger-zone backup reveal against
  `session-source-backups`, decoded-QR import, and secretless account selection
  (which keeps `source_public_key_proof_verified: false`).
- **Trusted review** — review-screen page and `approval_digest` parity,
  review-detail-page and review-display-frame parity (scroll windows, compact
  line styles, `U+XXXX` fallback, visible control escapes, UTF-8-boundary-safe
  wrapping), review-control traversal (final-page approval, early rejection,
  terminal decisions), approval-gate request-id/digest binding, and
  review-transcript parity for the display/button I/O harnesses.
- **Policy** — signing-readiness stays disabled until every gate is present
  (runtime feature flag, parser limits, trusted display, physical controls,
  approval-digest binding, Unicode review rendering acceptance, key
  provisioning, source public-key proof, secure boot, flash encryption, debug
  lock, companion signed-output verification), and the
  `esp32-usb-enable-kind-1-automation` policy-change review requires local
  traversal plus physical approval and rejects companion-authoritative or
  secret-bearing proposals.
- **Protocol** — `get_capabilities`, `get_signing_status` (reports
  `signing_enabled: false` plus `development_accepted_gates` and the remaining
  missing gates), development `get_public_key`, dynamic `request_id` echo, and
  the `signing_disabled` response for valid `sign_event` frames.
- **Identity/policy contracts** — the `esp32_qr_vault` / `esp32_usb_nip46` route
  split, account descriptors, route-selection vectors, and the boot-hardening
  security-profile vector stay aligned with `nSealr/specs`.
- **Board profiles** — `scripts/validate_firmware.py` and the crate's
  `board_profile_tests` keep the `boards/*.json` registry consistent.

## Required (future-phase) tests

Each device app added in a later phase must, before it may claim vector
compliance, pass the `desktop-simulator` oracle and add its measured coverage
floor to `ci/ratchet.json`. Device-specific acceptance — camera/display/GPIO
bring-up, secure boot / flash encryption provisioning, on-hardware smoke and
flash smoke, and companion verification of real signed output — is owned by the
phase that builds each app (Phase 04 `vault-esp32`, Phase 05 `key`, later
`one` / `vault-pi`). No device security claim is valid until firmware build,
provisioning, parser limits, trusted review, physical approval, approval-digest
binding, companion verification, and deterministic rejection behavior are
verified on the real target. Runtime signing remains disabled until those gates
pass.
