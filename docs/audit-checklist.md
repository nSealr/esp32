# Audit Checklist

## Workspace (current)

- [x] One toolchain: `make ci` is Rust-only plus the generic `verify_repo.py` /
      `validate_firmware.py` validators (C++/ESP-IDF gates retired in Phase 03
      Task 05).
- [x] `nsealr-core` builds bare-metal for `riscv32imafc-unknown-none-elf` and
      the `std` facade is proven non-inert.
- [x] Protocol/review/session/policy logic matches `nSealr/specs` — enforced by
      the `desktop-simulator` vector-parity oracle with a category completeness
      rule.
- [x] `boards/*.json` profiles validate.
- [x] Coverage ratchet holds against `ci/ratchet.json`.

## Per device app (each future phase must satisfy before real signing)

- [ ] App builds and flashes for its declared target.
- [ ] App passes the `desktop-simulator` vector oracle and records a coverage
      floor in `ci/ratchet.json`.
- [ ] Trusted review renders on the physical display; separate physical
      approve/reject controls, no touch approval.
- [ ] Device rejects unapproved signing; request + `approval_digest` binding
      verified on hardware.
- [ ] Key provisioning/storage and recovery policy designed and tested.
- [ ] Source public-key proof for each selected account/source.
- [ ] Secure boot, flash encryption (or equivalent persistent-secret policy),
      and locked debug access provisioned per target.
- [ ] Companion verifies signed output.
- [ ] Deterministic refusal for unsafe or unapproved requests.
