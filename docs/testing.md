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
- Approval gate tests requiring request-id-matched approval before signing is
  permitted.

## Required Tests

- ESP-IDF build smoke tests.
- Transport frame rejection tests.
- Companion integration tests for signed responses.
- Hardware validation reports for every physical board.

No device security claim is valid until firmware build, provisioning, approval,
and rejection behavior are verified.
