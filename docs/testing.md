# Testing

## Current Baseline

```sh
make ci
```

The baseline runs repository verification and the host-buildable firmware core
tests with strict C++ warnings.

## Implemented Tests

- Serial frame round-trip test against the companion-compatible known frame.
- Serial frame rejection tests for unsupported types, checksum mismatch, and
  invalid base64url payloads.
- Host test header generation from the shared `NostrSeal/specs` serial vector.
- Approval gate tests requiring request-id-matched approval before signing is
  permitted.
- Device protocol tests proving the shared ESP32-S3 scaffold capability request
  returns the shared scaffold capability response.
- Device protocol tests proving the shared `sign_event` fixture returns the
  shared `signing_disabled` scaffold response.
- ESP-IDF scaffold validation for required project files, ESP32-S3 target, board
  profile, and unsupported-claim rejection.
- ESP32-S3 board detection tests for serial-port discovery, native USB/JTAG
  report parsing, and missing-toolchain reporting.
- Manual ESP-IDF `v5.5.4` build, flash, and boot-log smoke test on the attached
  ESP32-S3 board.
- Optional hardware capability/signing-disabled smoke test with
  `make idf-smoke-capabilities` after exporting ESP-IDF and flashing the current
  firmware.
- Regression tests require the ESP-IDF console defaults to use native USB
  Serial/JTAG as the primary console; secondary USB logging is not enough for
  input-driven protocol smoke tests.

## Required Tests

- Automated ESP-IDF build smoke tests in CI or a hardware-capable runner.
- Repeatable flash smoke tests with recorded device port and board identity.
- Transport frame rejection tests.
- Companion integration tests for signed responses.
- Hardware validation reports for every physical board.

No device security claim is valid until firmware build, provisioning, approval,
and rejection behavior are verified.
