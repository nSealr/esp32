# Reproducible build recipe — `firmware`

The `firmware` cargo workspace builds **reproducibly**: the same source tree,
built twice from clean on the pinned toolchain, produces **byte-identical**
release artifacts, and the shared device backbone (`nsealr-core`) reproduces
byte-for-byte from an independent checkout at a different filesystem path. This
is the founding phase's last guarantee — every device app that later builds on
`nsealr-core` inherits a build a third party can independently verify.

This document is the published recipe: follow it verbatim to reproduce the
artifacts and confirm the recorded hashes. Reproducibility is proven by an
actual double build in CI (`make repro-build`), never asserted.

> **Scope.** This establishes that the *artifact* is reproducible. It does **not**
> cover how a release is signed — the offline release-key signing ceremony (key
> custody, air-gapped signing, signature publication) is Phase 11 (termination).

## What makes the build deterministic

| Control | Where | Why |
| --- | --- | --- |
| Fully-pinned toolchain (`1.95.0`, not a floating channel) + `riscv32imafc-unknown-none-elf` target | `rust-toolchain.toml` | Same compiler → same codegen. A floating channel would drift. |
| Committed, authoritative lockfile | `Cargo.lock` | Freezes the exact dependency versions + checksums for the whole workspace. |
| Vendored dependency tree | `vendor/` (via `cargo vendor`) | A clean build needs no network and cannot silently drift with the crates.io registry; no `~/.cargo/registry` absolute path leaks into the artifact. |
| Offline source replacement | `.cargo/config.toml` (`[source.crates-io] replace-with = "vendored-sources"`) | Forces every crates.io dependency to resolve from `vendor/`. |
| `codegen-units = 1` | `[profile.release]` in `Cargo.toml` | Removes codegen parallelism as a variance source across differing host core counts. |
| Build-path remap (`--remap-path-prefix=<root>=/nsealr`) | applied by `ci/repro_build.sh` at build time | Strips the absolute build directory (and, because `vendor/` lives under it, the vendored-dep source paths) out of `file!()`/panic locations, so the emitted code is independent of where the tree is checked out. |

The Rust sysroot (`core`/`std`) source paths are already remapped to
`/rustc/<commit>/…` by the compiler, so they are constant for a given toolchain
version and do not need handling here.

## Prerequisites

- `rustup` (it reads `rust-toolchain.toml` and installs the pinned toolchain on
  first use), plus `rsync` and a SHA-256 tool (`sha256sum` on Linux, `shasum` on
  macOS). No network is needed for the build itself once the toolchain is
  installed — dependencies come from the committed `vendor/` tree.

## Reproduce the artifacts

From a clean checkout of `firmware/`:

```sh
# 1. Install the exact pinned toolchain (channel + components + riscv target).
rustup toolchain install                     # reads rust-toolchain.toml

# 2. Reproduce + byte-compare in one step (this is the CI gate itself).
make repro-build
```

`make repro-build` runs `ci/repro_build.sh`, which:

1. builds the workspace release **twice** from the current tree into separate
   target dirs (`target/repro-a`, `target/repro-b`), offline against `vendor/`,
   on the pinned toolchain, with the build path remapped;
2. builds `nsealr-core` for `riscv32imafc-unknown-none-elf` a **third** time from
   a copy of the tree at a different filesystem path; and
3. SHA-256-hashes each artifact and **fails on any mismatch**.

### Reproduce a single artifact by hand

The build command the gate uses, for a maker who wants to reproduce one artifact
directly (run from the workspace root):

```sh
ROOT="$(pwd -P)"
# Device backbone rlib (the path-independent, third-party-reproducible artifact):
RUSTFLAGS="--remap-path-prefix=${ROOT}=/nsealr" \
  cargo build --release --offline --locked \
  -p nsealr-core --target riscv32imafc-unknown-none-elf

# Host vector-replay harness binary:
RUSTFLAGS="--remap-path-prefix=${ROOT}=/nsealr" \
  cargo build --release --offline --locked -p desktop-simulator
```

## Artifact paths and expected hashes

| Artifact | Path (relative to a target dir) | Reproducibility |
| --- | --- | --- |
| `nsealr-core` device rlib | `riscv32imafc-unknown-none-elf/release/libnsealr_core.rlib` | Byte-identical **same-tree and cross-path** (path-independent). |
| `desktop-simulator` host binary | `release/desktop-simulator` | Byte-identical **same-tree**; cross-path differs by the §6.5 default only (see Known limits). |

Recorded reference hashes on the pinned toolchain (`rustc 1.95.0`,
`aarch64-apple-darwin` host), for the tree at the commit that introduced this
recipe:

```
nsealr-core riscv32imafc-unknown-none-elf release rlib
  sha256 = bc2c4cfb3886f976aa19e8d812b653fc3cfa36f2fc1c42ad54dba4251ac3c369

desktop-simulator release binary (same-tree)
  sha256 = 4f2f1a21f2c9f93aab03a18eaacd22e63a5412d240a31a5e4249130902772f82
```

The `nsealr-core` rlib hash is path-independent: a third party who installs the
same pinned toolchain and follows this recipe reproduces `bc2c4cfb…` regardless
of where they clone the tree. The `desktop-simulator` hash is host- and
checkout-path-specific (see Known limits); verify it with a same-tree double
build rather than against this literal value on a different host.

To hash an artifact manually (note: the by-hand build above outputs into the
default `target/`; the `target/repro-a` path below is where the `repro-build`
gate places its first build — adjust the path to whichever build you ran):

```sh
shasum -a 256 target/repro-a/riscv32imafc-unknown-none-elf/release/libnsealr_core.rlib
```

## Regenerating the vendored set

When `Cargo.lock` changes (a dependency is added, removed, or bumped), refresh
the vendored tree so it stays exactly the locked closure — no more, no less:

```sh
cargo vendor --locked vendor          # rewrites vendor/ from Cargo.lock
cargo deny check                       # the vendored set must still pass policy
make repro-build                       # re-prove byte-identity
```

Keep the printed `[source …]` stanza in sync with `.cargo/config.toml`. The
vendored set must never contain a crate that is not in the locked dependency
closure.

## Known limits

- **`desktop-simulator` is cross-path-reproducible only up to one embedded
  string.** The harness binary bakes its own build directory into itself as the
  `NSEALR_VECTORS_ROOT` fallback, via `env!("CARGO_MANIFEST_DIR")` (decision
  spec §6.5 — the single configurable vector-source root, repointed at a pinned
  released artifact in Phase 07). `--remap-path-prefix` remaps source-file
  paths but **not** `env!`, so two builds of this binary at different absolute
  paths differ solely in that one embedded default path. This is a deliberate
  developer-convenience default, not a determinism defect: the CI gate asserts
  the harness binary is byte-identical for **same-tree** double builds, which
  fully covers timestamp/build-id/codegen non-determinism. The device backbone
  `nsealr-core`, which every shipped app is built from, has no such default and
  is fully path-independent.
- **`trim-paths` is not used.** The cleaner `[profile] trim-paths` Cargo option
  is not stabilized on the pinned stable toolchain (`1.95.0`); enabling it would
  require nightly, which the reproducibility pin forbids. The stable
  `--remap-path-prefix` rustflag achieves the same path-stripping for source
  paths and is applied by `ci/repro_build.sh`. Revisit `trim-paths` when the
  pinned toolchain is deliberately bumped to a version that stabilizes it.
