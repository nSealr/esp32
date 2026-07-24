//! RAM-only session source generation from caller-supplied entropy.
//!
//! Ported from the C++ reference `host_core` sources
//! `src/session_source_generation.cpp` +
//! `include/nsealr/session_source_generation.hpp` for behaviour parity. Like
//! the C++, generation routes through a temporary [`StatelessSessionKeyring`]
//! so a generated source passes exactly the RAM-only boundary validation an
//! imported one does (the temporary keyring wipes itself on drop).

use crate::nip19::{self, SecretKey};
use crate::seedqr::{self, SeedQrError};
use crate::session::keyring::{SessionKeySource, SessionKeyringError, StatelessSessionKeyring};

/// Errors reported by session source generation. Each variant corresponds to a
/// distinct C++ `SessionSourceGenerationError` throw site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSourceGenerationError {
    /// The BIP-39 entropy length was not 16 or 32 bytes. C++: "generated BIP-39
    /// entropy must be 16 or 32 bytes".
    InvalidEntropyLength,
    /// The nsec entropy was not a valid secp256k1 scalar. C++: "generated nsec
    /// entropy must be a valid secp256k1 scalar".
    InvalidNsecScalar,
    /// The entropy failed SeedQR/BIP-39 reconstruction. The C++ rethrew the
    /// `SeedQrError` message under `SessionSourceGenerationError`.
    SeedQr(SeedQrError),
    /// The temporary keyring rejected the source (for example an invalid
    /// label). The C++ rethrew the `SessionKeyringError` message.
    Keyring(SessionKeyringError),
}

/// Generates a BIP-39 session source from 16 or 32 bytes of entropy. Mirrors
/// the C++ `generate_bip39_session_source` (the entropy-to-indexes step is the
/// CompactSeedQR reconstruction).
///
/// # Errors
///
/// [`SessionSourceGenerationError::InvalidEntropyLength`],
/// [`SessionSourceGenerationError::SeedQr`] or
/// [`SessionSourceGenerationError::Keyring`].
pub fn generate_bip39_session_source(
    label: &str,
    entropy: &[u8],
) -> Result<SessionKeySource, SessionSourceGenerationError> {
    if entropy.len() != 16 && entropy.len() != 32 {
        return Err(SessionSourceGenerationError::InvalidEntropyLength);
    }
    let indexes =
        seedqr::decode_compact_indexes(entropy).map_err(SessionSourceGenerationError::SeedQr)?;
    let mut keyring = StatelessSessionKeyring::new();
    keyring
        .add_bip39_seed(label, indexes.as_slice())
        .map_err(SessionSourceGenerationError::Keyring)?;
    source_from_single_entry_keyring(&keyring)
}

/// Clones the single source out of the temporary boundary keyring (the C++
/// `source_from_single_entry_keyring`; the keyring wipes itself on drop).
fn source_from_single_entry_keyring(
    keyring: &StatelessSessionKeyring,
) -> Result<SessionKeySource, SessionSourceGenerationError> {
    Ok(keyring
        .source_at(0)
        .map_err(SessionSourceGenerationError::Keyring)?
        .clone())
}

/// Generates an nsec session source from a caller-supplied 32-byte scalar.
/// Mirrors the C++ `generate_nsec_session_source`.
///
/// # Errors
///
/// [`SessionSourceGenerationError::InvalidNsecScalar`] or
/// [`SessionSourceGenerationError::Keyring`].
pub fn generate_nsec_session_source(
    label: &str,
    entropy: &SecretKey,
) -> Result<SessionKeySource, SessionSourceGenerationError> {
    if !nip19::is_valid_secret_key(entropy) {
        return Err(SessionSourceGenerationError::InvalidNsecScalar);
    }
    let mut keyring = StatelessSessionKeyring::new();
    keyring
        .add_nsec(label, entropy)
        .map_err(SessionSourceGenerationError::Keyring)?;
    source_from_single_entry_keyring(&keyring)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39;
    use crate::session::import_review::build_session_import_review;
    use crate::session::import_review::tests::pages_contain_text;
    use crate::session::keyring::SessionKeySourceKind;

    // Port of the C++ `test_session_source_generation_uses_ram_only_source_boundary`.
    #[test]
    fn uses_ram_only_source_boundary() {
        let seed_source = generate_bip39_session_source("Generated seed", &[0u8; 16]).unwrap();
        let mut generated_secret = [0u8; 32];
        generated_secret[31] = 1;
        let nsec_source =
            generate_nsec_session_source("Generated nsec", &generated_secret).unwrap();

        assert_eq!(seed_source.kind, SessionKeySourceKind::Bip39WordIndexes);
        assert_eq!(seed_source.label, "Generated seed");
        assert_eq!(seed_source.bip39_word_indexes.count, 12);
        let mut mnemonic_buf = [0u8; 256];
        assert_eq!(
            bip39::mnemonic_from_indexes(
                seed_source.bip39_word_indexes.as_slice(),
                &mut mnemonic_buf,
            )
            .unwrap(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        );
        assert!(seed_source.nsec_secret_key.iter().all(|&byte| byte == 0));

        assert_eq!(nsec_source.kind, SessionKeySourceKind::NsecSecretKey);
        assert_eq!(nsec_source.label, "Generated nsec");
        assert_eq!(nsec_source.nsec_secret_key, generated_secret);
        assert_eq!(nsec_source.bip39_word_indexes.count, 0);

        let seed_review = build_session_import_review(&seed_source);
        let nsec_review = build_session_import_review(&nsec_source);
        assert!(pages_contain_text(&seed_review.pages, "Secret: hidden"));
        assert!(pages_contain_text(&nsec_review.pages, "Secret: hidden"));
        assert!(!pages_contain_text(&seed_review.pages, "abandon"));
        assert!(!pages_contain_text(
            &nsec_review.pages,
            "0000000000000000000000000000000000000000000000000000000000000001",
        ));
    }

    // Port of the C++ `test_session_source_generation_rejects_invalid_entropy`.
    #[test]
    fn rejects_invalid_entropy() {
        assert_eq!(
            generate_bip39_session_source("Generated seed", &[0x00, 0x01]),
            Err(SessionSourceGenerationError::InvalidEntropyLength),
        );
        assert_eq!(
            generate_nsec_session_source("Generated nsec", &[0u8; 32]),
            Err(SessionSourceGenerationError::InvalidNsecScalar),
        );
        let mut generated_secret = [0u8; 32];
        generated_secret[31] = 1;
        assert_eq!(
            generate_nsec_session_source("", &generated_secret),
            Err(SessionSourceGenerationError::Keyring(
                crate::session::keyring::SessionKeyringError::EmptyLabel,
            )),
        );
    }
}
