//! RAM-only session source parsing from decoded QR text / CompactSeedQR bytes.
//!
//! Ported from the C++ reference `host_core` sources `src/session_source_qr.cpp`
//! and `include/nsealr/session_source_qr.hpp` for behaviour parity. Decoded text
//! dispatches to NIP-19 `nsec`, Standard SeedQR digits, or a plain BIP-39
//! mnemonic; every parsed source is loaded through a temporary RAM-only
//! [`StatelessSessionKeyring`](crate::session::keyring::StatelessSessionKeyring)
//! so it passes exactly the boundary validation an imported source does.
//!
//! The QR-driven *import flows* the C++ layered on top
//! (`session_source_qr_import_flow.cpp`) need the M-T3.6 review-controls
//! substrate and are deferred to milestone M-T3.4b.

use crate::bip39::{self, Bip39Error};
use crate::nip19::{self, NsecError};
use crate::seedqr::{self, SeedQrError};
use crate::session::keyring::{SessionKeySource, SessionKeyringError};

/// Errors reported by session source QR parsing. Each variant corresponds to a
/// distinct C++ `SessionSourceQrError` throw site (the C++ rethrew the wrapped
/// error's message under `SessionSourceQrError`; this port carries the
/// underlying error value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSourceQrError {
    /// The decoded text was empty after trimming ASCII whitespace. C++:
    /// "decoded session QR text must not be empty".
    EmptyText,
    /// The `nsec1...` branch failed NIP-19 decoding.
    Nsec(NsecError),
    /// The digit-stream branch failed Standard SeedQR decoding, or the compact
    /// entry point failed CompactSeedQR decoding.
    SeedQr(SeedQrError),
    /// The mnemonic branch failed BIP-39 parsing.
    Bip39(Bip39Error),
    /// The RAM-only keyring boundary rejected the parsed source (for example an
    /// invalid label).
    Keyring(SessionKeyringError),
}

/// Parses decoded QR text into a RAM-only session source. Mirrors the C++
/// `parse_session_source_qr_text` (trim, then dispatch on `nsec1` prefix /
/// digit stream / mnemonic).
///
/// # Errors
///
/// [`SessionSourceQrError::EmptyText`], or the wrapped decoder/keyring error
/// for the dispatched branch.
pub fn parse_session_source_qr_text(
    label: &str,
    decoded_text: &str,
) -> Result<SessionKeySource, SessionSourceQrError> {
    let text = decoded_text.trim_matches(is_session_qr_whitespace);
    if text.is_empty() {
        return Err(SessionSourceQrError::EmptyText);
    }

    if text.starts_with("nsec1") {
        let secret = nip19::decode_nsec(text).map_err(SessionSourceQrError::Nsec)?;
        return source_from_nsec(label, &secret);
    }
    if is_standard_seedqr_digit_stream(text) {
        let indexes =
            seedqr::decode_standard_indexes(text).map_err(SessionSourceQrError::SeedQr)?;
        return source_from_bip39_indexes(label, indexes.as_slice());
    }
    let indexes = bip39::parse_mnemonic_indexes(text).map_err(SessionSourceQrError::Bip39)?;
    source_from_bip39_indexes(label, indexes.as_slice())
}

/// ASCII whitespace as recognised by the C++ `is_ascii_whitespace`: space,
/// `\n`, `\r`, `\t` only.
fn is_session_qr_whitespace(ch: char) -> bool {
    matches!(ch, ' ' | '\n' | '\r' | '\t')
}

/// Mirrors the C++ `is_standard_seedqr_digit_stream`: at least one decimal
/// digit and nothing but digits and ASCII whitespace.
fn is_standard_seedqr_digit_stream(text: &str) -> bool {
    let mut saw_digit = false;
    for ch in text.chars() {
        if is_session_qr_whitespace(ch) {
            continue;
        }
        if !ch.is_ascii_digit() {
            return false;
        }
        saw_digit = true;
    }
    saw_digit
}

/// Mirrors the C++ `source_from_nsec` (temporary boundary keyring).
fn source_from_nsec(
    label: &str,
    secret: &crate::nip19::SecretKey,
) -> Result<SessionKeySource, SessionSourceQrError> {
    let mut keyring = crate::session::keyring::StatelessSessionKeyring::new();
    keyring
        .add_nsec(label, secret)
        .map_err(SessionSourceQrError::Keyring)?;
    source_from_single_entry_keyring(&keyring)
}

/// Mirrors the C++ `source_from_bip39_indexes` (temporary boundary keyring).
fn source_from_bip39_indexes(
    label: &str,
    indexes: &[u16],
) -> Result<SessionKeySource, SessionSourceQrError> {
    let mut keyring = crate::session::keyring::StatelessSessionKeyring::new();
    keyring
        .add_bip39_seed(label, indexes)
        .map_err(SessionSourceQrError::Keyring)?;
    source_from_single_entry_keyring(&keyring)
}

/// Clones the single source out of the temporary boundary keyring (the C++
/// `source_from_single_entry_keyring`; the keyring wipes itself on drop).
fn source_from_single_entry_keyring(
    keyring: &crate::session::keyring::StatelessSessionKeyring,
) -> Result<SessionKeySource, SessionSourceQrError> {
    Ok(keyring
        .source_at(0)
        .map_err(SessionSourceQrError::Keyring)?
        .clone())
}

/// Parses CompactSeedQR entropy bytes into a RAM-only session source. Mirrors
/// the C++ `parse_compact_seedqr_session_source`.
///
/// # Errors
///
/// [`SessionSourceQrError::SeedQr`] or [`SessionSourceQrError::Keyring`].
pub fn parse_compact_seedqr_session_source(
    label: &str,
    entropy: &[u8],
) -> Result<SessionKeySource, SessionSourceQrError> {
    let indexes = seedqr::decode_compact_indexes(entropy).map_err(SessionSourceQrError::SeedQr)?;
    source_from_bip39_indexes(label, indexes.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::import_review::build_session_import_review;
    use crate::session::import_review::tests::{pages_contain_text, NSEC_TEST_KEY_1_SECRET_HEX};
    use crate::session::keyring::tests::{NSEC_TEST_KEY_1, SEEDQR_VECTOR_1_INDEXES};
    use crate::session::keyring::SessionKeySourceKind;

    // Mnemonic copied from the READ-ONLY
    // specs/vectors/keys/nip06-account-0-leader.json (`mnemonic`).
    const NIP06_ACCOUNT_0_MNEMONIC: &str =
        "leader monkey parrot ring guide accident before fence cannon height naive bean";
    // Standard digits + compact hex copied from the READ-ONLY
    // specs/vectors/seedqr/seedsigner-vector-1.json (`standard_seedqr_digits`,
    // `compact_seedqr_hex`).
    const SEEDQR_VECTOR_1_DIGITS: &str =
        "011513251154012711900771041507421289190620080870026613431420201617920614089619290300152408010643";
    pub(crate) const SEEDQR_VECTOR_1_COMPACT: [u8; 32] = [
        0x0e, 0x74, 0xb6, 0x41, 0x07, 0xf9, 0x4c, 0xc0, 0xcc, 0xfa, 0xe6, 0xa1, 0x3d, 0xcb, 0xec,
        0x36, 0x62, 0x15, 0x4f, 0xec, 0x67, 0xe0, 0xe0, 0x09, 0x99, 0xc0, 0x78, 0x92, 0x59, 0x7d,
        0x19, 0x0a,
    ];

    // Port of the C++ `test_session_source_qr_parses_ram_only_sources`.
    #[test]
    fn parses_ram_only_sources() {
        let mut wrapped_nsec = std::string::String::from("\n");
        wrapped_nsec.push_str(NSEC_TEST_KEY_1);
        wrapped_nsec.push('\t');
        let nsec_source = parse_session_source_qr_text("nsec QR", &wrapped_nsec).unwrap();
        let mnemonic_source =
            parse_session_source_qr_text("plain mnemonic QR", NIP06_ACCOUNT_0_MNEMONIC).unwrap();
        // Whitespace inside the digit stream is skipped by the dispatch check
        // and by the Standard SeedQR decoder (C++ parity).
        let mut spaced_digits = std::string::String::from(&SEEDQR_VECTOR_1_DIGITS[..4]);
        spaced_digits.push(' ');
        spaced_digits.push_str(&SEEDQR_VECTOR_1_DIGITS[4..8]);
        spaced_digits.push('\n');
        spaced_digits.push_str(&SEEDQR_VECTOR_1_DIGITS[8..]);
        let standard_seedqr_source =
            parse_session_source_qr_text("Standard SeedQR", &spaced_digits).unwrap();
        let compact_seedqr_source =
            parse_compact_seedqr_session_source("CompactSeedQR", &SEEDQR_VECTOR_1_COMPACT).unwrap();

        assert_eq!(nsec_source.kind, SessionKeySourceKind::NsecSecretKey);
        assert_eq!(nsec_source.label, "nsec QR");
        assert_eq!(
            nsec_source.nsec_secret_key,
            crate::nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap(),
        );
        assert_eq!(nsec_source.bip39_word_indexes.count, 0);

        assert_eq!(mnemonic_source.kind, SessionKeySourceKind::Bip39WordIndexes);
        assert_eq!(mnemonic_source.label, "plain mnemonic QR");
        assert_eq!(
            mnemonic_source.bip39_word_indexes.as_slice(),
            crate::bip39::parse_mnemonic_indexes(NIP06_ACCOUNT_0_MNEMONIC)
                .unwrap()
                .as_slice(),
        );

        assert_eq!(
            standard_seedqr_source.kind,
            SessionKeySourceKind::Bip39WordIndexes,
        );
        assert_eq!(standard_seedqr_source.label, "Standard SeedQR");
        assert_eq!(
            standard_seedqr_source.bip39_word_indexes.as_slice(),
            &SEEDQR_VECTOR_1_INDEXES,
        );
        assert_eq!(
            compact_seedqr_source.kind,
            SessionKeySourceKind::Bip39WordIndexes,
        );
        assert_eq!(compact_seedqr_source.label, "CompactSeedQR");
        assert_eq!(
            compact_seedqr_source.bip39_word_indexes.as_slice(),
            &SEEDQR_VECTOR_1_INDEXES,
        );

        let nsec_review = build_session_import_review(&nsec_source);
        let mnemonic_review = build_session_import_review(&mnemonic_source);
        assert!(pages_contain_text(&nsec_review.pages, "Secret: hidden"));
        assert!(pages_contain_text(&mnemonic_review.pages, "Secret: hidden"));
        assert!(!pages_contain_text(
            &nsec_review.pages,
            NSEC_TEST_KEY_1_SECRET_HEX,
        ));
        assert!(!pages_contain_text(&mnemonic_review.pages, "leader"));
    }

    // Port of the C++ `test_session_source_qr_rejects_invalid_inputs`.
    #[test]
    fn rejects_invalid_inputs() {
        assert_eq!(
            parse_session_source_qr_text("empty QR", " \n\t"),
            Err(SessionSourceQrError::EmptyText),
        );
        assert_eq!(
            parse_session_source_qr_text("", NSEC_TEST_KEY_1),
            Err(SessionSourceQrError::Keyring(
                SessionKeyringError::EmptyLabel,
            )),
        );
        assert_eq!(
            parse_session_source_qr_text("bad nsec QR", "nsec1short"),
            Err(SessionSourceQrError::Nsec(NsecError::Malformed)),
        );
        assert_eq!(
            parse_session_source_qr_text("bad Standard SeedQR", "000"),
            Err(SessionSourceQrError::SeedQr(SeedQrError::NotFourPerWord)),
        );
        assert_eq!(
            parse_session_source_qr_text("bad mnemonic QR", "not a valid session source!"),
            Err(SessionSourceQrError::Bip39(Bip39Error::NonAsciiWord)),
        );
        assert_eq!(
            parse_compact_seedqr_session_source("bad CompactSeedQR", &[0x00, 0x01]),
            Err(SessionSourceQrError::SeedQr(SeedQrError::InvalidByteLength)),
        );
    }
}
