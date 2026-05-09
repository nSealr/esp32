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
- key provisioning: not implemented
- persistent secret storage: not implemented
- companion signed-output verification gate: not ready
- trusted review display: manual development acceptance passed on T-Display S3,
  but production claim remains blocked
- physical approval controls: manual development acceptance passed on
  T-Display S3, touch approval remains disallowed, and production claim remains
  blocked

This is intentional for development. It is not a production custody profile and
must not be used to claim a finished hardware wallet.

Before any real signing path can be enabled, the production profile must prove:

- trusted display acceptance
- separate physical approve/reject controls
- request and `approval_digest` binding
- production key provisioning and recovery policy
- secure boot policy
- flash encryption or equivalent persistent-secret policy
- locked debug access
- companion verification of signed output
- deterministic refusal for unsafe or unapproved requests

QR vault targets remain stateless and RAM-only. The security profile above is
for the ESP32-S3 USB signer scaffold and future persistent-secret work, not a
reason to add persistent storage to stateless QR vaults.
