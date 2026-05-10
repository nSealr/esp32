# ESP32-S3 Build And Flash Notes

The repository now contains an ESP-IDF project scaffold at
`firmware/esp32_s3_usb_signer`.

## Current Local Tool Status

On the workstation used for this implementation pass, ESP-IDF `v5.5.4` was
installed outside this repository at:

```text
/Users/vincenzo/esp/esp-idf-v5.5.4
```

The current verified export uses the system Python `3.9.6` and created the
ESP-IDF Python environment:

```text
/Users/vincenzo/.espressif/python_env/idf5.5_py3.9_env
```

A previous local export used a Python 3.12 ESP-IDF environment. If an existing
`firmware/esp32_s3_usb_signer/build` directory was configured with a different
ESP-IDF Python environment, run `idf.py fullclean` inside the ESP-IDF project
before rebuilding.

The attached ESP32-S3 board is visible:

- serial port: `/dev/cu.usbmodem1101` in the latest smoke run; earlier sessions
  also used `/dev/cu.usbmodem101`, so rerun `make detect-board` or
  `ls -1 /dev/cu.usbmodem*` if the path changes
- USB vendor: `Espressif`
- USB product: `USB JTAG_serial debug unit`
- USB serial number: `EC:DA:3B:95:32:98`
- native USB JTAG/serial: detected

Export ESP-IDF before build, flash, monitor, or hardware smoke commands:

```sh
. /Users/vincenzo/esp/esp-idf-v5.5.4/export.sh
```

If a specific ESP-IDF Python environment must be reused, point ESP-IDF at that
environment before exporting:

```sh
export IDF_PYTHON_ENV_PATH=/Users/vincenzo/.espressif/python_env/idf5.5_py3.9_env
. /Users/vincenzo/esp/esp-idf-v5.5.4/export.sh
```

## Detection Command

Run the host-side detection gate with:

```sh
make detect-board
```

This command is intentionally separate from `make ci` because CI and most
developer machines will not have a physical board attached.

After exporting ESP-IDF with Python 3.9, detection reported
`ready_for_idf_build: true` and `ready_for_flash: true`.

## Verified Build Command

The scaffold was built successfully with:

```sh
make idf-build
```

Build result:

```text
ESP-IDF v5.5.4
nostrseal_esp32_s3_usb_signer.bin size: 0x7ab70 bytes after adding the
host-core QR review I/O transcript helper to the ESP-IDF component
smallest app partition: 0x100000 bytes
free app partition space: 0x85490 bytes, about 52%
```

The firmware defaults set native USB Serial/JTAG as the primary ESP-IDF console:

```text
CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y
```

Using USB Serial/JTAG only as a secondary console mirrors logs but does not
provide input for `getchar()`, so `make idf-smoke-capabilities` would time out.

## Verified Flash Command

The scaffold was flashed successfully with:

```sh
make idf-flash
```

Flash evidence:

```text
chip: ESP32-S3 QFN56 revision v0.2
features: WiFi, BLE, embedded PSRAM 8MB
USB mode: USB-Serial/JTAG
MAC: ec:da:3b:95:32:98
flash writes: bootloader, app, partition table
hash verification: passed
```

## Verified Boot Log

A short monitor session confirmed that the scaffold boots:

```text
I boot.esp32s3: SPI Flash Size : 16MB
I nostrseal: NostrSeal ESP32-S3 USB signer scaffold booted
W nostrseal: Signing is disabled in this scaffold until storage, review, approval, and tests are implemented
I nostrseal: USB serial frame handler ready for get_capabilities, get_signing_status, get_public_key, and disabled sign_event
```

The first flash smoke test reported a hardware/config mismatch:

```text
Detected size(16384k) larger than the size in the binary image header(8192k).
```

This was fixed by changing `sdkconfig.defaults` to
`CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y`, rebuilding, reflashing, and confirming the
boot log reports `SPI Flash Size : 16MB`.

## Reusable Build Command

After installing ESP-IDF and exporting the environment:

```sh
idf.py set-target esp32s3
make idf-build
```

## Reusable Flash Command

Use the actual ESP32-S3 serial device path:

```sh
make IDF_PORT=/dev/cu.<device> idf-flash
make IDF_PORT=/dev/cu.<device> idf-monitor
```

## Reusable Capability Smoke Command

After flashing the current firmware and exporting ESP-IDF:

```sh
make IDF_PORT=/dev/cu.<device> idf-smoke-capabilities
```

The smoke command sends the shared `get_capabilities` request frame, the shared
`get_signing_status` diagnostic request frame, the shared `get_public_key`
development request frame, the shared basic `sign_event` request frame, and
dynamic `request_id` variants for the same four methods. It expects the ESP32-S3
scaffold capability response, signing-readiness diagnostic response,
deterministic development public-key response, and explicit `signing_disabled`
response in both static and dynamic-request cases. It also sends invalid dynamic request metadata and
serial-wrapped invalid signing-request vectors, including unknown top-level
request fields, and expects deterministic `unsupported_request` error frames.
On 2026-05-08, revision `b7aa30a` was built with ESP-IDF `v5.5.4`, flashed to
`/dev/cu.usbmodem1101`, and passed `make IDF_PORT=/dev/cu.usbmodem1101
idf-smoke-capabilities`. This confirms the QR review I/O transcript helper can
be compiled into the ESP-IDF component while the attached-device smoke still
exercises only the USB serial scaffold: capability and development public-key
requests succeed, `sign_event` returns `signing_disabled`, and invalid requests
return deterministic `unsupported_request` frames. Real signing is
intentionally disabled until storage, review UI, approval controls, and
response verification tests are implemented.

On 2026-05-08, revision `dfdeec9` was built with ESP-IDF `v5.5.4`, flashed to
`/dev/cu.usbmodem1101`, and passed `make IDF_PORT=/dev/cu.usbmodem1101
idf-smoke-capabilities`. This confirms the serial `sign_event` trusted-review
boundary compiles into the ESP-IDF component while runtime protocol behavior
stays conservative: capability and development public-key requests succeed,
`sign_event` returns `signing_disabled`, and invalid requests return
deterministic `unsupported_request` frames.

## Manual T-Display S3 Review Display Exercise

After flashing the current T-Display S3 firmware, a deterministic review screen
can be sent to the device for human inspection:

```sh
python3 scripts/manual_review_display.py show-review --port /dev/cu.<device>
```

To inspect the compact grouped tag-content review section, send:

```sh
python3 scripts/manual_review_display.py show-tags --port /dev/cu.<device>
```

To inspect compact full-content and many-tag review behavior, send:

```sh
python3 scripts/manual_review_display.py show-long-content --port /dev/cu.<device>
```

To inspect the scroll-window behavior for both Content and Tags, use a short
request id so the test request stays under the v0 decoded-request limit:

```sh
python3 scripts/manual_review_display.py show-scroll-review --port /dev/cu.<device> --request-id manual-scroll
```

To inspect a dense structured tag list that should require multiple Tags scroll
windows without inferred tag meaning or ellipses, send:

```sh
python3 scripts/manual_review_display.py show-dense-tags --port /dev/cu.<device> --request-id manual-dense-tags
```

To inspect the display-safe UTF-8 fallback path, send:

```sh
python3 scripts/manual_review_display.py show-unicode-review --port /dev/cu.<device> --request-id manual-unicode
```

To exercise the request-error display state, send a valid review request
followed by an invalid signing-request vector:

```sh
python3 scripts/manual_review_display.py show-request-error --port /dev/cu.<device>
```

To run the non-interactive protocol smoke for all review-display scenarios
without requiring button input, use:

```sh
make IDF_PORT=/dev/cu.<device> idf-smoke-review-scenarios
```

This verifies the serial responses for the same basic, tagged, long-content,
scroll-window, dense-tags, Unicode fallback, and request-error review requests.
It does not replace visual inspection of the physical display.

To exercise the physical-control acceptance path with a human observer, send a
valid review request and follow the printed checklist:

```sh
python3 scripts/manual_review_display.py button-approve --port /dev/cu.<device>
python3 scripts/manual_review_display.py button-reject --port /dev/cu.<device>
```

These helpers are manual display bring-up tools. They do not approve requests,
do not persist keys, and still expect the serial protocol to return
`signing_disabled` for valid `sign_event` requests. Terminal request-error,
approve, and reject screens should also show `Send new request` as the final
prompt after `Signing disabled`.
