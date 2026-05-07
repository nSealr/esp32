# ESP32-S3 Build And Flash Notes

The repository now contains an ESP-IDF project scaffold at
`firmware/esp32_s3_usb_signer`.

## Current Local Tool Status

On the workstation used for this implementation pass:

- `idf.py` was not installed.
- `esptool.py` / `esptool` was not installed.
- No ESP32-S3 serial device was visible under `/dev/cu.*`.

Therefore no firmware build or flash was attempted.

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
