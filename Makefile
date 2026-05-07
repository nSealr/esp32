.PHONY: setup test lint audit docs ci host-core-test

setup:
	@echo "No setup required until the ESP-IDF project is introduced."

host-core-test:
	mkdir -p build/host_core
	python3 scripts/generate_transport_vector_header.py
	c++ -std=c++20 -Wall -Wextra -Werror \
		-Ifirmware/host_core/include \
		-Ibuild/host_core \
		firmware/host_core/src/approval_gate.cpp \
		firmware/host_core/src/serial_frame.cpp \
		firmware/host_core/src/sha256.cpp \
		firmware/host_core/tests/test_host_core.cpp \
		-o build/host_core/test_host_core
	build/host_core/test_host_core

test:
	python3 scripts/verify_repo.py
	$(MAKE) host-core-test

lint:
	python3 scripts/verify_repo.py

audit:
	python3 scripts/verify_repo.py

docs:
	python3 scripts/verify_repo.py

ci: setup test lint audit docs
