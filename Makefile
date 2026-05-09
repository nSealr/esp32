IDF_PROJECT := firmware/esp32_s3_usb_signer
IDF_PORT ?= /dev/cu.usbmodem1101

.PHONY: setup test lint audit docs ci generate-host-vectors host-core-test detect-board idf-env-check idf-build idf-flash idf-monitor idf-smoke-capabilities

setup:
	@echo "Run '. /path/to/esp-idf/export.sh' before ESP-IDF build, flash, or monitor targets."

generate-host-vectors:
	mkdir -p build/host_core
	python3 scripts/generate_transport_vector_header.py

host-core-test: generate-host-vectors
	c++ -std=c++20 -Wall -Wextra -Werror \
		-Ifirmware/host_core/include \
		-Ifirmware/esp32_s3_usb_signer/main \
		-Ibuild/host_core \
		firmware/esp32_s3_usb_signer/main/t_display_s3_button_logic.cpp \
		firmware/esp32_s3_usb_signer/main/t_display_s3_raster.cpp \
		firmware/host_core/src/approval_gate.cpp \
		firmware/host_core/src/device_protocol.cpp \
		firmware/host_core/src/qr_envelope.cpp \
		firmware/host_core/src/qr_review.cpp \
		firmware/host_core/src/qr_review_flow.cpp \
		firmware/host_core/src/review_controls.cpp \
		firmware/host_core/src/review_display.cpp \
		firmware/host_core/src/serial_frame.cpp \
		firmware/host_core/src/serial_review.cpp \
		firmware/host_core/src/sha256.cpp \
		firmware/host_core/src/signing_policy.cpp \
		firmware/host_core/src/trusted_review.cpp \
		firmware/host_core/tests/test_host_core.cpp \
		-o build/host_core/test_host_core
	build/host_core/test_host_core

detect-board:
	python3 scripts/detect_esp32_s3.py --json

idf-env-check:
	@command -v idf.py >/dev/null || (echo "ERROR: idf.py not found. Export ESP-IDF before running this target." && exit 1)

idf-build: idf-env-check generate-host-vectors
	cd $(IDF_PROJECT) && idf.py build

idf-flash: idf-build
	cd $(IDF_PROJECT) && idf.py -p $(IDF_PORT) flash

idf-monitor: idf-env-check
	cd $(IDF_PROJECT) && idf.py -p $(IDF_PORT) monitor

idf-smoke-capabilities: idf-env-check
	python scripts/smoke_capabilities.py --port $(IDF_PORT)

test:
	python3 scripts/verify_repo.py
	python3 -m unittest discover -s tests
	$(MAKE) host-core-test

lint:
	python3 scripts/verify_repo.py
	python3 -m compileall -q scripts tests

audit:
	python3 scripts/verify_repo.py
	python3 scripts/validate_firmware.py

docs:
	python3 scripts/verify_repo.py
	python3 scripts/validate_firmware.py

ci: setup test lint audit docs
