#!/usr/bin/env bash
#
# Reproducible-build byte-identity gate for the nSealr firmware workspace.
#
# Proves — with an ACTUAL double build, never an assertion — that the pinned
# toolchain (rust-toolchain.toml) + committed Cargo.lock + vendored `vendor/`
# tree produce byte-identical release artifacts. Two independent properties are
# checked; both must hold:
#
#   1. Same-tree determinism. Two clean release builds of the workspace into
#      separate target dirs are byte-identical. Guards against embedded build
#      timestamps, non-deterministic build-ids, codegen-order/parallelism
#      variance, and future regressions (a new dep or build script that bakes in
#      a clock/random value would break this).
#
#   2. Cross-path path-independence (the device backbone). The `nsealr-core`
#      rlib for the real device target (riscv32imafc-unknown-none-elf, release)
#      built from a SECOND copy of the tree at a DIFFERENT filesystem path is
#      byte-identical to the in-tree build. This is the property a third party
#      relies on to independently reproduce the device artifact; it holds only
#      because `--remap-path-prefix` strips the absolute build path and the
#      dependency set is vendored (no `~/.cargo/registry` path leak). Remove the
#      remap or the vendored set and this comparison fails — that is the check
#      doing real work, not a green no-op.
#
# The `desktop-simulator` host harness binary is asserted byte-identical
# same-tree only. It embeds its own build directory as the runtime
# `NSEALR_VECTORS_ROOT` fallback via `env!("CARGO_MANIFEST_DIR")` (decision spec
# §6.5); `--remap-path-prefix` does not rewrite `env!`, so its cross-path hash
# is path-specific by design. See docs/reproducible-build.md "Known limits".
set -euo pipefail

TRIPLE="riscv32imafc-unknown-none-elf"
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
cd "$ROOT"

# Portable SHA-256 (bare hex): coreutils `sha256sum` on Linux CI, `shasum` on macOS.
sha() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

# Clean release build of both artifacts, offline against the vendored set, on the
# pinned toolchain, with the build path remapped to a fixed token so the emitted
# code is independent of where the tree lives. $1 = source root (remap prefix),
# $2 = cargo target dir.
build_release() {
	local src="$1" td="$2" flags
	flags="--remap-path-prefix=${src}=/nsealr"
	RUSTFLAGS="$flags" cargo build --release --offline --locked \
		-p desktop-simulator --target-dir "$td" >/dev/null
	RUSTFLAGS="$flags" cargo build --release --offline --locked \
		-p nsealr-core --target "$TRIPLE" --target-dir "$td" >/dev/null
}

DS_REL="release/desktop-simulator"
RLIB_REL="${TRIPLE}/release/libnsealr_core.rlib"

echo "repro-build: same-tree clean build A"
rm -rf "$ROOT/target/repro-a" "$ROOT/target/repro-b"
build_release "$ROOT" "$ROOT/target/repro-a"

echo "repro-build: same-tree clean build B"
build_release "$ROOT" "$ROOT/target/repro-b"

A_DS="$(sha "$ROOT/target/repro-a/$DS_REL")"
B_DS="$(sha "$ROOT/target/repro-b/$DS_REL")"
A_RLIB="$(sha "$ROOT/target/repro-a/$RLIB_REL")"
B_RLIB="$(sha "$ROOT/target/repro-b/$RLIB_REL")"

echo "repro-build: cross-path clean build X (second checkout at a different path)"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/nsealr-repro.XXXXXX")"
# Physical path: rustc sees the resolved path, so the remap prefix must too.
SCRATCH="$(cd "$SCRATCH" && pwd -P)"
trap 'rm -rf "$SCRATCH"' EXIT
rsync -a --exclude='/target' --exclude='/.git' "$ROOT/" "$SCRATCH/"
(cd "$SCRATCH" && build_release "$SCRATCH" "$SCRATCH/target/repro-x")
X_RLIB="$(sha "$SCRATCH/target/repro-x/$RLIB_REL")"

fail=0
check() { # label expected actual
	if [ "$2" = "$3" ]; then
		printf '  OK   %-42s %s\n' "$1" "$2"
	else
		printf '  FAIL %-42s %s != %s\n' "$1" "$2" "$3"
		fail=1
	fi
}

echo "repro-build: byte-identity results"
check "desktop-simulator (same-tree A==B)" "$A_DS" "$B_DS"
check "nsealr-core rlib (same-tree A==B)" "$A_RLIB" "$B_RLIB"
check "nsealr-core rlib (cross-path A==X)" "$A_RLIB" "$X_RLIB"

if [ "$fail" -ne 0 ]; then
	echo "repro-build: FAILED — release artifacts are not byte-identical" >&2
	exit 1
fi

echo "repro-build: PASS"
echo "  path-independent device artifact:"
echo "    nsealr-core ${TRIPLE} release rlib  sha256 = ${A_RLIB}"
echo "  desktop-simulator release binary (same-tree) sha256 = ${A_DS}"
