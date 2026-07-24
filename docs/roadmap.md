# Roadmap

## Foundation: the Rust workspace (done)

The firmware foundation is the all-Rust cargo workspace:

- `crates/nsealr-core` — the `#![no_std]` signer backbone: `nsealr1f:` serial
  and `nsealr1:` / `nsealr1a:` QR transports, BIP-39 / SeedQR / NIP-19 key-source
  parsers, the RAM-only session keyring with import / generation / backup flows,
  the trusted-review page/frame/control/approval-gate state machines, the
  signing-readiness policy and policy-change review, and the device-protocol
  request dispatcher (`get_capabilities`, `get_signing_status`, development
  `get_public_key`, disabled `sign_event`). It builds bare-metal against
  `riscv32imafc-unknown-none-elf` and exposes an opt-in `std` facade for hosts.
- `apps/desktop-simulator` — the permanent `std` vector-replay oracle that
  proves `nsealr-core` matches every in-scope `nSealr/specs` vector, with a
  completeness rule guarding new categories.
- `boards/` — the toolchain-agnostic signer-board and display-panel profiles.

The signing-readiness policy keeps runtime signing disabled until every gate is
present: runtime feature flag, parser limits, trusted display acceptance,
physical controls, approval-digest binding, Unicode review rendering acceptance,
key provisioning, source public-key proof, secure boot, flash encryption, debug
lock, and companion signed-output verification. There is no signing backend.

### Historical note — C++ / ESP-IDF retirement (Phase 03 Task 05)

The original firmware foundation was a host-buildable C++ `host_core` plus an
ESP-IDF `esp32_s3_usb_signer` app (T-Display S3 ST7789/i80 display bring-up,
onboard-button review, `espefuse.py` fuse audit, ESP-IDF `v5.5.4`
build/flash/monitor smokes, and a `security_profile.json` development posture).
That entire tree was **retired in Phase 03 Task 05** once the Rust
`desktop-simulator` harness proved `nsealr-core` had full vector parity. The C++
logic was ported into `nsealr-core`; the ESP-IDF app is not continued — its Rust
replacement (`apps/key`) is a from-scratch Phase 05 build. The retired app's
board bring-up, hardware smokes, and eFuse audit are recreated as Rust-era
tooling by the phases that own each device app, not inherited.

## Next phases

- **Phase 04 — `apps/vault-esp32`**: the ESP32 stateless QR vault Rust app on
  `esp-hal` + Embassy. Camera/display board bring-up (LILYGO T-Display S3 Pro
  OV5640 primary; Waveshare ESP32-S3 Touch LCD 3.5B-C secondary), the QR request
  scanner and response QR output, RAM-only session-account selection, trusted
  review with physical approve/reject, and companion-verified signed-event QR
  output. Must pass the `desktop-simulator` oracle and record a coverage floor.
- **Phase 05 — `apps/key`**: the ESP32 USB/NIP-46 signer Rust app. Task 00 sets
  up the Xtensa `esp` toolchain and re-points the `firmware-boot-hardening-v0`
  contract at this app; later tasks add USB transport, production key
  generation/import, `sign_event` behind display review and physical approval,
  and companion integration. The persistent encrypted device vault (seed
  profiles, passphrase namespaces, standalone key slots, per-public-key policy)
  and M9 security hardening (secure boot, flash encryption, firmware-update and
  debug-lock policy via irreversible eFuse provisioning) are gated here.
- **Later**: `apps/one` (custom persistent-secret wallet, ESP32-S3 + TROPIC01)
  and `apps/vault-pi` (Raspberry Pi QR vault port).

Hard blocker before any real `sign_event` on any app: the pre-signing hardening
gate — parser/resource limits, shared malicious-vector rejection, display-review
driver acceptance, physical-button acceptance, `approval_digest` binding, key
provisioning/storage design, source public-key proof, secure boot / debug
policy, and companion verification of signed output — must all be tested on the
real target. Until then runtime signing remains disabled.
