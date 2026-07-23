# `apps/` — reserved for the Rust firmware binaries

This directory is a placeholder. No app crates are created here yet, and none
are workspace members until the phase that owns each one scaffolds it. Reserving
the layout now (without empty crates) avoids speculative scaffolding ahead of
the phases that own the work.

Planned occupants:

- `apps/vault-esp32` — ESP32 stateless QR vault (Phase 04).
- `apps/key` — ESP32 USB/NIP-46 signer (Phase 05).
- `apps/one` — custom persistent-secret hardware wallet board.
- `apps/vault-pi` — Raspberry Pi QR vault Rust port (Phase 08).

Each app links the shared `crates/nsealr-core` backbone. A second infra crate,
`crates/board-registry`, is likewise reserved as future infrastructure alongside
`crates/nsealr-core`; it is intentionally **not** scaffolded here.

When a phase adds one of these crates it must: add it to the root `Cargo.toml`
`members`, and record its measured coverage floor in `ci/ratchet.json` (the
coverage-ratchet gate fails on any workspace package that has no floor).
