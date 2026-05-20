# Security Posture

The ESP32-S3 USB signer firmware is still a development scaffold. The
machine-readable posture is tracked in
`firmware/esp32_s3_usb_signer/security_profile.json` and validated by
`make ci`.

The current profile is `development_scaffold`:

- runtime signing feature flag: disabled
- production signing: not allowed
- secure boot: disabled
- flash encryption: disabled
- USB/JTAG debug access: unlocked for bring-up
- security eFuse audit: read-only `espefuse.py summary` reporting is available
  through `make idf-audit-security-fuses` and tracked separately as
  `security_fuse_audit_evidence`
- key provisioning: not implemented
- source public-key proof: not implemented
- persistent secret storage: not implemented
- companion signed-output verification gate: not ready
- trusted review display: manual development acceptance passed on T-Display S3,
  but production claim remains blocked
- display review protocol evidence: recorded separately for detail-page,
  UTF-8 fallback, ASCII punctuation, dense-tags, control-escape, and
  historical head-smoke runs; these reports support development traceability
  for the firmware revision they name but do not replace production
  trusted-display acceptance
- Unicode review rendering: development uses explicit `U+XXXX` fallback for
  unsupported non-ASCII glyphs and visible JSON-style escapes for decoded
  control characters; production remains blocked until full Unicode review
  acceptance or a reviewed equivalent policy exists
- companion transport evidence: recorded separately for direct serial-line
  capability and `signing_disabled` smokes; these reports prove request-bound
  host/device exchange only and do not replace companion signed-output
  verification for real signatures
- firmware protocol evidence: recorded separately for current T-Display S3
  firmware revisions that build, flash, answer capability/status/public-key
  requests, reject invalid frames deterministically, and still return
  `signing_disabled` for valid `sign_event` requests; the current evidence now
  includes the Unicode review signing-gate smoke and signing-status gate
  de-duplication smoke
- physical approval controls: manual development acceptance passed on
  T-Display S3, touch approval remains disallowed, and production claim remains
  blocked
- identity/policy descriptors: `esp32_usb_nip46`,
  `policy-manual-only-persistent-device`,
  `esp32-usb-enable-kind-1-automation`,
  `policy-scoped-automation-daily-use`, and
  `grant-esp32-usb-kind-1-session` are shared conformance contracts only;
  they do not enable persistent grants or signatures on this development
  scaffold, and scoped automation still requires device review plus physical
  approval
- policy-change review: host-core can review the future
  `esp32-usb-enable-kind-1-automation` proposal locally and bind approval to
  the shared `approval_digest`, but the result is not persisted and cannot
  enable scoped automation until storage, provisioning, and production signing
  gates exist
- future persistent-device vault: seed profiles, BIP-39 passphrase namespaces,
  NIP-06 accounts, standalone key slots, and per-public-key policy remain a
  production design target, not current firmware behavior; v0 uses one
  device-level unlock ceremony when that vault exists

`nSealr/specs` pins this development-only boundary in
`vectors/devices/esp32-s3-security-profile-development.json`. ESP32 tests
compare `security_profile.json` against that vector so secure boot, flash
encryption, debug lock, persistent-secret storage, and production signing
cannot silently drift into enabled or claimed states.

This is intentional for development. It is not a production custody profile and
must not be used to claim a finished hardware wallet.

The eFuse audit target is intentionally observational. It does not burn keys,
enable secure boot, enable flash encryption, disable download mode, or lock
debug access. It reports whether those irreversible production-hardening steps
are still blockers.

Before any real signing path can be enabled, the production profile must prove:

- trusted display acceptance
- full Unicode review rendering acceptance or a reviewed equivalent display
  policy
- separate physical approve/reject controls
- request and `approval_digest` binding
- production key provisioning and recovery policy
- source public-key proof for each selected account/source
- secure boot policy
- flash encryption or equivalent persistent-secret policy
- locked debug access
- companion verification of signed output
- deterministic refusal for unsafe or unapproved requests

QR vault targets remain stateless and RAM-only. The security profile above is
for the ESP32-S3 USB signer scaffold and future persistent-secret work, not a
reason to add persistent storage to stateless QR vaults.

The ESP32 QR vault session-account selector currently performs descriptor shape
checks plus reviewed source-fingerprint binding only. Selected accounts carry
`source_public_key_proof_verified: false`, so that metadata path cannot clear
the production `source_public_key_proof` blocker.
