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
- ESP-IDF scaffold validation for required project files, ESP32-S3 target, board
  profile, and unsupported-claim rejection.
- ESP32-S3 board detection tests for serial-port discovery, native USB/JTAG
  report parsing, and missing-toolchain reporting.

## Required Tests

- ESP-IDF build smoke tests.
- Flash smoke tests with recorded device port and board identity.
- Transport frame rejection tests.
- Companion integration tests for signed responses.
- Hardware validation reports for every physical board.

No device security claim is valid until firmware build, provisioning, approval,
and rejection behavior are verified.
