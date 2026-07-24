# nSealr firmware — all-Rust workspace gates.
#
# The C++ `host_core` and the ESP-IDF `esp32_s3_usb_signer` app were retired in
# Phase 03 Task 05; `crates/nsealr-core` is the sole signer backbone and
# `apps/desktop-simulator` is its vector-parity oracle. Only one toolchain (Rust)
# remains, so `make ci` is a single Rust gate set plus the generic Python
# repo/board validators.

.PHONY: test lint audit docs ci cargo-fmt cargo-clippy cargo-test cargo-deny \
	coverage-ratchet vector-harness rust-ci

RISCV_TARGET := riscv32imafc-unknown-none-elf
RUST_COVERAGE_JSON := build/rust-coverage.json

# ---------------------------------------------------------------------------
# Generic (toolchain-agnostic) Python gates.
# ---------------------------------------------------------------------------
test:
	python3 scripts/verify_repo.py

lint:
	python3 scripts/verify_repo.py
	python3 -m compileall -q scripts

audit:
	python3 scripts/verify_repo.py
	python3 scripts/validate_firmware.py

docs:
	python3 scripts/verify_repo.py
	python3 scripts/validate_firmware.py

# ---------------------------------------------------------------------------
# Rust workspace gates (EXECUTION-ETHICS.md Section C). The `std` cargo feature
# is proven non-inert by the std-gated test in `cargo-test`.
# ---------------------------------------------------------------------------
cargo-fmt:
	cargo fmt --all --check

cargo-clippy:
	cargo clippy --all-targets -- -D warnings -D dead_code
	cargo clippy --all-targets --all-features -- -D warnings -D dead_code

cargo-test:
	cargo test --workspace
	cargo test -p nsealr-core --features std
	cargo build -p nsealr-core --target $(RISCV_TARGET)

cargo-deny:
	cargo deny check

# The desktop-simulator parity oracle: exhaustively replays every in-scope
# specs/vectors/<category>/*.json file through nsealr-core's public API and
# enforces the category completeness rule (Phase 03 Task 04). Every Rust app in
# this workspace must pass this gate before claiming vector compliance.
vector-harness:
	cargo test -p desktop-simulator

coverage-ratchet:
	@mkdir -p build
	cargo llvm-cov --workspace --all-features --summary-only --json --output-path $(RUST_COVERAGE_JSON)
	python3 ci/check_coverage_ratchet.py $(RUST_COVERAGE_JSON) ci/ratchet.json

rust-ci: cargo-fmt cargo-clippy cargo-test vector-harness cargo-deny coverage-ratchet

ci: test lint audit docs rust-ci
