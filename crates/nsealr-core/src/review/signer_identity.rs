//! Signer identity — the reviewed 64-hex Nostr public key bound into a review.
//!
//! Ported from the C++ reference `host_core` header-only helper
//! `include/nsealr/signer_identity.hpp` for behaviour parity: the same
//! `is_valid_nostr_public_key` rule (exactly 64 lowercase-hex characters), the
//! same development-fixture public key, and the same "require valid identity"
//! guard the review/protocol layer applies before it renders or hashes an
//! author public key.
//!
//! This is the **definitive home** for [`SignerIdentity`] and
//! [`is_valid_nostr_public_key`]. Milestone M-T3.4a hosted them temporarily in
//! `session/account.rs` (recorded in that module and the LEDGER); M-T3.6 moves
//! them here — where the C++ layering places `signer_identity.hpp`, included by
//! `qr_review`/`serial_review`/`device_protocol` — and `session/account.rs`
//! re-uses them (no duplication).
//!
//! The C++ `SignerIdentity` owned a `std::string public_key`; this port borrows
//! the caller's public-key text (`&'a str`) to stay `no_std` and allocation-free
//! and to keep [`crate::session::account::SelectedSessionAccount`] `Copy`. The
//! development fixture returns a `'static` borrow of the shared test key.

/// Development fixture public key (shared test identity). Mirrors the C++
/// `kDevelopmentFixturePublicKey` (`signer_identity.hpp`); the same 64-hex key as
/// the READ-ONLY specs/vectors/nip19/nsec-test-key-1.json (`public_key`).
pub const DEVELOPMENT_FIXTURE_PUBLIC_KEY: &str =
    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

/// The signer identity bound to a review. Mirrors the C++ `SignerIdentity`
/// (`signer_identity.hpp`); the public key borrows the caller's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerIdentity<'a> {
    /// The 64-lowercase-hex Nostr public key.
    pub public_key: &'a str,
}

impl SignerIdentity<'static> {
    /// Returns the development fixture signer identity. Mirrors the C++
    /// `development_fixture_signer_identity`.
    #[must_use]
    pub const fn development_fixture() -> Self {
        Self {
            public_key: DEVELOPMENT_FIXTURE_PUBLIC_KEY,
        }
    }
}

/// The failure of [`require_valid_signer_identity`]. Mirrors the C++
/// `SignerIdentityError` (one message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerIdentityError;

impl SignerIdentityError {
    /// The exact message the C++ `SignerIdentityError` carried.
    #[must_use]
    pub const fn message(self) -> &'static str {
        "signer public key must be 64 lowercase hex characters"
    }
}

impl core::fmt::Display for SignerIdentityError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.message())
    }
}

/// Mirrors the C++ `is_lowercase_hex` (`signer_identity.hpp`).
const fn is_lowercase_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f')
}

/// Returns `true` for a 64-lowercase-hex Nostr public key. Mirrors the C++
/// `is_valid_nostr_public_key` (`signer_identity.hpp`).
#[must_use]
pub fn is_valid_nostr_public_key(public_key: &str) -> bool {
    public_key.len() == 64 && public_key.bytes().all(is_lowercase_hex)
}

/// Requires `identity` to carry a valid Nostr public key. Mirrors the C++
/// `require_valid_signer_identity`.
///
/// # Errors
///
/// [`SignerIdentityError`] if [`is_valid_nostr_public_key`] rejects the key.
pub fn require_valid_signer_identity(
    identity: SignerIdentity<'_>,
) -> Result<(), SignerIdentityError> {
    if is_valid_nostr_public_key(identity.public_key) {
        Ok(())
    } else {
        Err(SignerIdentityError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    #[test]
    fn validates_lowercase_hex_public_key() {
        assert!(is_valid_nostr_public_key(DEVELOPMENT_FIXTURE_PUBLIC_KEY));
        // 64 lowercase hex.
        assert!(is_valid_nostr_public_key(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        // Wrong length (63 / 65).
        assert!(!is_valid_nostr_public_key(
            "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a"
        ));
        assert!(!is_valid_nostr_public_key(
            "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaa"
        ));
        // Uppercase hex rejected.
        assert!(!is_valid_nostr_public_key(
            "4F355BDCB7CC0AF728EF3CCEB9615D90684BB5B2CA5F859AB0F0B704075871AA"
        ));
        // Non-hex character rejected.
        assert!(!is_valid_nostr_public_key("not-a-pubkey"));
    }

    #[test]
    fn development_fixture_is_valid_and_matches_constant() {
        let identity = SignerIdentity::development_fixture();
        assert_eq!(identity.public_key, DEVELOPMENT_FIXTURE_PUBLIC_KEY);
        assert!(require_valid_signer_identity(identity).is_ok());
        assert_eq!(identity, SignerIdentity::development_fixture());
    }

    #[test]
    fn require_valid_rejects_bad_key_with_cpp_message() {
        let error = require_valid_signer_identity(SignerIdentity {
            public_key: "not-a-pubkey",
        })
        .unwrap_err();
        assert_eq!(
            error.message(),
            "signer public key must be 64 lowercase hex characters"
        );
        assert_eq!(
            format!("{error}"),
            "signer public key must be 64 lowercase hex characters"
        );
    }
}
