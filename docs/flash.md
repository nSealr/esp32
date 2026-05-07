# ESP32-S3 Build And Flash Notes

The repository now contains an ESP-IDF project scaffold at
`firmware/esp32_s3_usb_signer`.

## Current Local Tool Status

On the workstation used for this implementation pass, ESP-IDF `v5.5.4` was
installed outside this repository at:

```text
/Users/vincenzo/esp/esp-idf-v5.5.4
```

The install used Homebrew Python `3.12.12` and created the ESP-IDF Python
environment:

```text
/Users/vincenzo/.espressif/python_env/idf5.5_py3.12_env
```

The attached ESP32-S3 board is visible:

- serial port: `/dev/cu.usbmodem1101`
- USB vendor: `Espressif`
- USB product: `USB JTAG_serial debug unit`
- USB serial number: `EC:DA:3B:95:32:98`
- native USB JTAG/serial: detected

The current shell must use Python 3.12 when exporting ESP-IDF. On this machine,
the default `/usr/bin/python3` is Python 3.9, so put Homebrew Python 3.12 first
for ESP-IDF commands:

```sh
export PATH=/opt/homebrew/opt/python@3.12/libexec/bin:/opt/homebrew/bin:$PATH
. /Users/vincenzo/esp/esp-idf-v5.5.4/export.sh
```

## Detection Command

Run the host-side detection gate with:

```sh
make detect-board
```

This command is intentionally separate from `make ci` because CI and most
developer machines will not have a physical board attached.

After exporting ESP-IDF with Python 3.12, detection reported
`ready_for_idf_build: true` and `ready_for_flash: true`.

## Verified Build Command

The scaffold was built successfully with:

```sh
make idf-build
```

Build result:

```text
ESP-IDF v5.5.4
nostrseal_esp32_s3_usb_signer.bin size: 0x779a0 bytes after adding the
host-core capability protocol path
smallest app partition: 0x100000 bytes
free app partition space: 0x88660 bytes, about 53%
```

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
I nostrseal: USB serial frame handler ready for get_capabilities
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

The smoke command sends the shared `get_capabilities` request frame and expects
the shared ESP32-S3 scaffold capability response. Signing is intentionally
disabled until storage, review UI, approval controls, and response verification
tests are implemented.
