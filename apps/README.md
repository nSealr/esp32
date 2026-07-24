# `apps/` — the Rust firmware binaries

First tenant:

- `apps/desktop-simulator` — the permanent `std` vector-replay harness (Phase 03
  Task 04): the CI-enforced parity oracle every Rust app below must pass before
  claiming vector compliance. See the root `README.md` ("Rust workspace").

Planned occupants (each added by the phase that owns it):

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
