# Testing

## Current Baseline

```sh
make ci
```

## Required Tests

- Host-side parser tests where firmware code can be built for host.
- ESP-IDF build smoke tests.
- Transport frame rejection tests.
- Companion integration tests for signed responses.
- Hardware validation reports for every physical board.

No device security claim is valid until firmware build, provisioning, approval,
and rejection behavior are verified.

