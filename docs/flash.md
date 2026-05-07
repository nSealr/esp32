# ESP32-S3 Build And Flash Notes

The repository now contains an ESP-IDF project scaffold at
`firmware/esp32_s3_usb_signer`.

## Current Local Tool Status

On the workstation used for this implementation pass, the ESP32-S3 board is now
visible:

- serial port: `/dev/cu.usbmodem1101`
- USB vendor: `Espressif`
- USB product: `USB JTAG_serial debug unit`
- USB serial number: `EC:DA:3B:95:32:98`
- native USB JTAG/serial: detected

The firmware toolchain is still missing from the current shell:

- `idf.py`: missing
- `esptool.py`: missing
- `esptool`: missing

Therefore no firmware build or flash was attempted.

## Detection Command

Run the host-side detection gate with:

```sh
make detect-board
```

This command is intentionally separate from `make ci` because CI and most
developer machines will not have a physical board attached.

## Expected Build Command

After installing ESP-IDF and exporting the environment:

```sh
cd firmware/esp32_s3_usb_signer
idf.py set-target esp32s3
idf.py build
```

## Expected Flash Command

Use the actual ESP32-S3 serial device path:

```sh
idf.py -p /dev/cu.<device> flash monitor
```

The current scaffold logs boot status only. Signing is intentionally disabled
until storage, review UI, approval controls, and response verification tests are
implemented.
