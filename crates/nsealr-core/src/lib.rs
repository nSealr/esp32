//! `nsealr-core` — the shared, `no_std` backbone crate for the nSealr firmware family.
//!
//! This crate is the single Rust home for the device-independent signer core
//! (transport framing, QR/serial review model, approval-digest binding, policy
//! state) that every nSealr target — the ESP32 QR vault, the USB/NIP-46 signer,
//! the custom board, and the Raspberry Pi vault — links against. The C++
//! `host_core` semantics are a decided rewrite into this crate; none of that
//! logic lives here yet (it is ported task by task in Phase 03).
//!
//! # Build configuration
//!
//! The crate is `#![no_std]` so it links on bare-metal firmware targets (for
//! example `riscv32imafc-unknown-none-elf`). The opt-in `std` feature links the
//! [`std`] facade for host/desktop consumers and test tooling; it is off by
//! default and pulls in nothing on-device.
//!
//! Phase 03 ports the C++ `host_core` logic into this crate one milestone at a
//! time. Ported so far: the low-level primitives [`hash`] (SHA-256) and
//! [`base64url`] (URL-safe unpadded Base64), and the encoding layer [`bip39`]
//! (English mnemonic parsing), [`nip19`] (`nsec` Bech32), [`seedqr`]
//! (Standard/Compact SeedQR), and [`unicode`] (UTF-8 + JSON `\uXXXX` helpers).
#![no_std]
#![deny(missing_docs)]

// The `std` feature links the standard library facade for host/desktop
// consumers. It is opt-in and off by default; on-device builds never pull it in.
#[cfg(feature = "std")]
extern crate std;

pub mod base64url;
pub mod bip39;
pub mod hash;
pub mod nip19;
pub mod seedqr;
pub mod unicode;

#[cfg(test)]
mod tests {
    // Proves the libtest harness compiles and runs for this `no_std` crate using
    // only `core` (`assert_eq!` is a `core` macro). Runs under every feature set.
    #[test]
    fn harness_runs() {
        assert_eq!(2 + 2, 4);
    }

    // Exercises the `std` feature so it is never an inert flag: with `std`
    // enabled the standard-library facade must be linked and usable from crate
    // code. `HashMap` is std-only (absent from `core`/`alloc`), so this only
    // compiles when the facade is actually present (EXECUTION-ETHICS.md §C,
    // zero inert surface).
    #[cfg(feature = "std")]
    #[test]
    fn std_feature_links_std_facade() {
        let mut counts = std::collections::HashMap::new();
        for byte in std::vec![0xA5u8, 0x5Au8, 0xA5u8] {
            *counts.entry(byte).or_insert(0u32) += 1;
        }
        assert_eq!(counts.get(&0xA5u8), Some(&2u32));
        assert_eq!(counts.get(&0x5Au8), Some(&1u32));
    }
}
