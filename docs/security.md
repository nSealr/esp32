# Security Posture

nSealr firmware is pre-signing. `crates/nsealr-core` implements the full request,
trusted-review, session-custody, and policy logic but **has no signing backend**:
every valid `sign_event` request is reviewed and then answered `signing_disabled`.
No device app that can produce a real signature exists yet.

> The retired ESP-IDF app carried a machine-readable `security_profile.json`
> development posture (validated by the old `make ci`). That app — and its
> profile — were removed in Phase 03 Task 05. The per-device hardening posture
> is re-established from scratch by the phase that builds each Rust device app
> (`apps/vault-esp32`, `apps/key`, …), and `nSealr/specs`
> `vectors/devices/esp32-s3-security-profile-development.json` /
> `firmware-boot-hardening-v0` are re-pointed at the Rust `apps/key` in Phase 05
> Task 00.

## Signing-readiness gate (`nsealr-core::policy`)

The signing-readiness policy is the runtime gate that any future device app must
satisfy before a signing backend may be wired in. Its default state is disabled
and it reports every missing condition:

- runtime signing feature flag
- parser / resource limits
- trusted display acceptance
- separate physical approve/reject controls (touch approval disallowed)
- request and `approval_digest` binding
- full Unicode review rendering acceptance (or a reviewed equivalent policy)
- key provisioning and recovery policy
- source public-key proof for each selected account/source
- secure boot
- flash encryption (or an equivalent persistent-secret policy)
- locked debug access
- companion verification of signed output

The QR session-account selector performs descriptor-shape checks plus reviewed
source-fingerprint binding only; selected accounts keep
`source_public_key_proof_verified: false`, so that metadata path can never clear
the `source_public_key_proof` blocker.

## Custody boundaries

- `esp32_qr_vault` stays stateless and RAM-only: a session keyring fed by manual
  BIP-39 words, SeedQR/CompactSeedQR, plain mnemonic QR, `nsec` QR, or local
  generation, wiped on clear/drop/move. No persistent secret, no persistent
  policy, no TROPIC01 dependency.
- `esp32_usb_nip46` targets a persistent encrypted device vault (seed profiles,
  passphrase namespaces, NIP-06 accounts, standalone key slots, per-public-key
  policy) behind one device-level unlock ceremony, only after production
  provisioning/storage and hardening gates pass. Policy changes must be locally
  reviewed and physically approved; companion proposals are not authoritative.

The identity/policy descriptors (`esp32-usb-device-slot-0`,
`policy-manual-only-persistent-device`, `esp32-usb-enable-kind-1-automation`,
`policy-scoped-automation-daily-use`, `grant-esp32-usb-kind-1-session`) are
shared conformance contracts only; they enable no grants or signatures on the
current code, and scoped automation still requires device review plus physical
approval.

## Production hardening (per target, future)

Secure boot, flash encryption, firmware-update policy, and debug-lock policy are
irreversible eFuse-provisioning steps owned by each device app's phase (M9 for
`apps/key`). This is not a production custody profile and must not be used to
claim a finished hardware wallet. QR vault targets remain stateless and RAM-only
regardless of the persistent-secret work on the USB/NIP-46 line.
