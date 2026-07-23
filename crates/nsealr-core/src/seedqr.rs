//! SeedQR decoding — Standard (4-digit-per-word) and Compact (raw entropy).
//!
//! Ported from the C++ reference `host_core` sources `src/seedqr.cpp` +
//! `include/nsealr/seedqr.hpp` for behaviour parity. Both decoders reuse the BIP-39
//! layer ([`crate::bip39`]): the Standard decoder validates the final BIP-39
//! checksum, while the Compact decoder reconstructs the word indexes from the raw
//! entropy plus its SHA-256 checksum bits exactly as the C++ did.
//!
//! Decoded word indexes are returned by value as a [`crate::bip39::WordIndexes`]
//! (at most 24 entries), keeping the crate `no_std` and allocation-free.

use crate::bip39::{self, Bip39Error, WordIndexes};
use crate::hash::sha256;

/// Errors reported by the SeedQR decoders. Each variant corresponds to a distinct
/// C++ `SeedQrError` throw site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedQrError {
    /// The Standard digit stream contained a non-digit character. C++: "Standard
    /// SeedQR digit stream must contain only digits".
    NonDigit,
    /// The Standard digit stream was empty after stripping whitespace. C++:
    /// "Standard SeedQR digit stream must not be empty".
    Empty,
    /// The Standard digit count was not a multiple of four. C++: "Standard SeedQR
    /// digit stream length must contain four digits per word".
    NotFourPerWord,
    /// The Standard word count was not 12 or 24. C++: "SeedQR word count must be 12
    /// or 24".
    InvalidWordCount,
    /// A Standard 4-digit group exceeded 2047. C++: "Standard SeedQR word index is
    /// outside the BIP-39 English wordlist".
    IndexOutOfRange,
    /// The Compact entropy length was not 16 or 32 bytes. C++: "CompactSeedQR byte
    /// length must be 16 or 32".
    InvalidByteLength,
    /// The reconstructed indexes failed BIP-39 validation/checksum. The C++ wrapped
    /// the `Bip39Error` message as `"SeedQR " + what()`; this port carries the
    /// underlying [`Bip39Error`].
    Bip39(Bip39Error),
}

const fn is_seedqr_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t')
}

/// Extracts the `bit_index`-th entropy bit (MSB-first within each byte). Mirrors the
/// C++ `entropy_bit`.
fn entropy_bit(entropy: &[u8], bit_index: usize) -> u8 {
    (entropy[bit_index / 8] >> (7 - (bit_index % 8))) & 1
}

/// Extracts the `bit_index`-th digest bit (MSB-first within each byte). The C++
/// `digest_bit` read the hex digest string; reading the raw digest byte is
/// bit-for-bit identical.
fn digest_bit(digest: &[u8; 32], bit_index: usize) -> u8 {
    (digest[bit_index / 8] >> (7 - (bit_index % 8))) & 1
}

/// Decodes a Standard SeedQR digit stream (four decimal digits per word) into its
/// validated word indexes. Mirrors the C++ `decode_standard_seedqr_indexes`.
///
/// Whitespace is ignored. Requires a non-empty stream whose digit count is a
/// multiple of four and whose word count is 12 or 24, each group in `0..=2047`,
/// with a valid BIP-39 checksum.
///
/// # Errors
///
/// [`SeedQrError::NonDigit`], [`SeedQrError::Empty`], [`SeedQrError::NotFourPerWord`],
/// [`SeedQrError::InvalidWordCount`], [`SeedQrError::IndexOutOfRange`] or
/// [`SeedQrError::Bip39`], in the same precedence order as the C++.
pub fn decode_standard_indexes(digits: &str) -> Result<WordIndexes, SeedQrError> {
    let bytes = digits.as_bytes();

    // Pass 1: reject non-digits (whitespace ignored) and count the digits — the C++
    // built the normalized string here, throwing on the first stray character.
    let mut digit_count = 0usize;
    for &byte in bytes {
        if is_seedqr_whitespace(byte) {
            continue;
        }
        if !byte.is_ascii_digit() {
            return Err(SeedQrError::NonDigit);
        }
        digit_count += 1;
    }
    if digit_count == 0 {
        return Err(SeedQrError::Empty);
    }
    if !digit_count.is_multiple_of(4) {
        return Err(SeedQrError::NotFourPerWord);
    }
    let word_count = digit_count / 4;
    if word_count != 12 && word_count != 24 {
        return Err(SeedQrError::InvalidWordCount);
    }

    // Pass 2: fold every four digits into a word index.
    let mut indexes = WordIndexes::new();
    let mut group = [0u16; 4];
    let mut in_group = 0usize;
    for &byte in bytes {
        if is_seedqr_whitespace(byte) {
            continue;
        }
        group[in_group] = u16::from(byte - b'0');
        in_group += 1;
        if in_group == 4 {
            let index = group[0] * 1000 + group[1] * 100 + group[2] * 10 + group[3];
            if index > 2047 {
                return Err(SeedQrError::IndexOutOfRange);
            }
            indexes.push(index);
            in_group = 0;
        }
    }

    bip39::require_valid_checksum(indexes.as_slice()).map_err(SeedQrError::Bip39)?;
    Ok(indexes)
}

/// Decodes a CompactSeedQR entropy blob (16 or 32 raw bytes) into its word indexes.
/// Mirrors the C++ `decode_compact_seedqr_indexes`: the entropy bits followed by the
/// leading bits of its SHA-256 form the 11-bit word indexes; no separate checksum
/// check is needed because the checksum is reconstructed here.
///
/// # Errors
///
/// [`SeedQrError::InvalidByteLength`] if `entropy` is not 16 or 32 bytes.
pub fn decode_compact_indexes(entropy: &[u8]) -> Result<WordIndexes, SeedQrError> {
    let checksum_bits = match entropy.len() {
        16 => 4usize,
        32 => 8usize,
        _ => return Err(SeedQrError::InvalidByteLength),
    };
    let entropy_bits = entropy.len() * 8;
    let word_count = (entropy_bits + checksum_bits) / 11;
    let digest = sha256(entropy);

    let mut indexes = WordIndexes::new();
    for word in 0..word_count {
        let mut value = 0u16;
        for bit in 0..11 {
            let global_bit = word * 11 + bit;
            let bit_value = if global_bit < entropy_bits {
                entropy_bit(entropy, global_bit)
            } else {
                digest_bit(&digest, global_bit - entropy_bits)
            };
            value = (value << 1) | u16::from(bit_value);
        }
        indexes.push(value);
    }
    Ok(indexes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_length_rules() {
        assert_eq!(
            decode_compact_indexes(&[0u8; 3]),
            Err(SeedQrError::InvalidByteLength),
        );
        // 16-byte entropy yields a 12-word index list.
        assert_eq!(decode_compact_indexes(&[0u8; 16]).unwrap().len(), 12);
        // 32-byte entropy yields a 24-word index list.
        assert_eq!(decode_compact_indexes(&[0u8; 32]).unwrap().len(), 24);
    }

    #[test]
    fn standard_empty_and_shape_errors() {
        assert_eq!(decode_standard_indexes("   "), Err(SeedQrError::Empty));
        assert_eq!(decode_standard_indexes(""), Err(SeedQrError::Empty));
        assert_eq!(
            decode_standard_indexes("00000"),
            Err(SeedQrError::NotFourPerWord)
        );
    }

    fn hex32(hex: &str) -> [u8; 32] {
        let bytes = hex.as_bytes();
        assert_eq!(bytes.len(), 64);
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = (bytes[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            *slot = (hi << 4) | lo;
        }
        out
    }

    // Port of the C++ `test_seedqr_decoders_match_shared_vector`. Fixture fields
    // copied from the READ-ONLY specs/vectors/seedqr/seedsigner-vector-1.json.
    #[test]
    fn decoders_match_shared_vector() {
        const DIGITS: &str = "011513251154012711900771041507421289190620080870026613431420201617920614089619290300152408010643";
        const COMPACT_HEX: &str =
            "0e74b64107f94cc0ccfae6a13dcbec3662154fec67e0e00999c07892597d190a";
        const MNEMONIC: &str = "attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony ranch winter theme error hybrid van cereal salon goddess expire";
        const IDX: [u16; 24] = [
            115, 1325, 1154, 127, 1190, 771, 415, 742, 1289, 1906, 2008, 870, 266, 1343, 1420,
            2016, 1792, 614, 896, 1929, 300, 1524, 801, 643,
        ];
        let compact = hex32(COMPACT_HEX);

        assert_eq!(decode_standard_indexes(DIGITS).unwrap().as_slice(), &IDX);
        assert_eq!(decode_compact_indexes(&compact).unwrap().as_slice(), &IDX);

        // Both decoders round-trip to the published mnemonic, and the 24-word
        // BIP-39 entropy equals the CompactSeedQR bytes.
        let mut buf = [0u8; 256];
        assert_eq!(
            bip39::mnemonic_from_indexes(&IDX, &mut buf).unwrap(),
            MNEMONIC
        );
        let mut ent = [0u8; 32];
        assert_eq!(
            bip39::entropy_from_indexes(&IDX, &mut ent).unwrap(),
            &compact,
        );

        // Whitespace inside the standard digit stream is ignored.
        let mut spaced = [0u8; DIGITS.len() + 2];
        spaced[0..4].copy_from_slice(&DIGITS.as_bytes()[0..4]);
        spaced[4] = b' ';
        spaced[5..9].copy_from_slice(&DIGITS.as_bytes()[4..8]);
        spaced[9] = b'\n';
        spaced[10..].copy_from_slice(&DIGITS.as_bytes()[8..]);
        assert_eq!(
            decode_standard_indexes(core::str::from_utf8(&spaced).unwrap())
                .unwrap()
                .as_slice(),
            &IDX,
        );

        // must contain only digits
        assert_eq!(decode_standard_indexes("000a"), Err(SeedQrError::NonDigit),);
        // four digits per word
        assert_eq!(
            decode_standard_indexes("000"),
            Err(SeedQrError::NotFourPerWord),
        );
        // word count must be 12 or 24
        assert_eq!(
            decode_standard_indexes("0000000000000000"),
            Err(SeedQrError::InvalidWordCount),
        );
        // word index outside the BIP-39 English wordlist (first group 2048 > 2047)
        assert_eq!(
            decode_standard_indexes(
                "204813251154012711900771041507421289190620080870026613431420201617920614089619290300152408010643"
            ),
            Err(SeedQrError::IndexOutOfRange),
        );
        // checksum: flip the last digit
        let mut mutated = [0u8; DIGITS.len()];
        mutated.copy_from_slice(DIGITS.as_bytes());
        let last = mutated.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        assert_eq!(
            decode_standard_indexes(core::str::from_utf8(&mutated).unwrap()),
            Err(SeedQrError::Bip39(Bip39Error::InvalidChecksum)),
        );
        // compact byte length
        assert_eq!(
            decode_compact_indexes(&[0x01, 0x02, 0x03]),
            Err(SeedQrError::InvalidByteLength),
        );
    }
}
