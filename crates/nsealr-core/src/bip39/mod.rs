//! BIP-39 English mnemonic parsing, checksum validation and entropy extraction.
//!
//! Ported from the C++ reference `host_core` sources `src/bip39_english.cpp` +
//! `include/nsealr/bip39_english.hpp` for behaviour parity. The 2048-word English
//! wordlist lives in the generated [`wordlist`] submodule (extracted once from the
//! same C++ table, then frozen and integrity-checked in tests). Every semantic —
//! ASCII-letter-only word validation, whitespace-insensitive splitting,
//! case-folding, `std::lower_bound` word lookup, the `{12,15,18,21,24}` word-count
//! rule, and the SHA-256 checksum over the entropy bits — matches the C++ exactly.
//!
//! The C++ surface returned heap `std::vector`/`std::string` values. To stay
//! `no_std` and allocation-free this port returns the fixed-capacity [`WordIndexes`]
//! value (at most [`MAX_MNEMONIC_WORDS`] entries) and writes mnemonic/entropy output
//! into caller-provided buffers, exactly as the M-T3.1 primitives port did.

mod wordlist;

use crate::hash::sha256;

/// Number of words in the BIP-39 English wordlist. Mirrors the C++
/// `kBip39EnglishWordCount`.
pub const WORD_COUNT: usize = 2048;

/// Maximum number of words in a BIP-39 mnemonic (a 24-word seed). Mirrors the C++
/// `kMaxBip39MnemonicWords` and bounds the [`WordIndexes`] capacity.
pub const MAX_MNEMONIC_WORDS: usize = 24;

/// Longest word in the English wordlist is 8 bytes; a candidate token longer than
/// this cannot be a wordlist word, so lookup can reject it without allocating.
const MAX_WORD_LEN: usize = 8;

/// Errors reported by the BIP-39 functions. Each variant corresponds to a distinct
/// C++ `Bip39Error` throw site (the C++ carried a message string; the offending
/// word is not echoed here because this port is allocation-free).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip39Error {
    /// The mnemonic contained no words. C++: "BIP-39 mnemonic must not be empty".
    Empty,
    /// The word count was not one of `{12, 15, 18, 21, 24}`. C++: "BIP-39 mnemonic
    /// word count must be one of 12, 15, 18, 21, 24".
    InvalidWordCount,
    /// A word contained a byte that is not an ASCII letter. C++: "BIP-39 mnemonic
    /// words must be ASCII English words".
    NonAsciiWord,
    /// A word was not present in the English wordlist. C++: "BIP-39 mnemonic word
    /// is not in the English wordlist".
    UnknownWord,
    /// A supplied word index was `>= WORD_COUNT`. C++: "BIP-39 mnemonic word index
    /// is outside the English wordlist".
    IndexOutOfRange,
    /// The checksum bits did not match the SHA-256 of the entropy. C++: "BIP-39
    /// mnemonic checksum is invalid".
    InvalidChecksum,
    /// A caller-provided output buffer was too small. This variant has no C++
    /// analogue (the C++ returned a growable `std::string`); size buffers with the
    /// documented bounds to avoid it.
    BufferTooSmall,
}

/// A fixed-capacity list of BIP-39 word indexes — the allocation-free stand-in for
/// the C++ `Bip39WordIndexes` (`std::vector<std::uint16_t>`). Holds at most
/// [`MAX_MNEMONIC_WORDS`] entries; unused slots are kept zeroed so equality
/// compares only the active prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WordIndexes {
    words: [u16; MAX_MNEMONIC_WORDS],
    len: usize,
}

impl WordIndexes {
    /// Creates an empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            words: [0; MAX_MNEMONIC_WORDS],
            len: 0,
        }
    }

    /// Returns the active word indexes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u16] {
        &self.words[..self.len]
    }

    /// Returns the number of word indexes held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the list holds no indexes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Builds a [`WordIndexes`] from a slice, rejecting counts above
    /// [`MAX_MNEMONIC_WORDS`]. Values are not range-checked here (the decoders and
    /// validators enforce `< WORD_COUNT` where the C++ did).
    ///
    /// # Errors
    ///
    /// Returns [`Bip39Error::InvalidWordCount`] if `indexes.len() > MAX_MNEMONIC_WORDS`.
    pub fn from_slice(indexes: &[u16]) -> Result<Self, Bip39Error> {
        if indexes.len() > MAX_MNEMONIC_WORDS {
            return Err(Bip39Error::InvalidWordCount);
        }
        let mut out = Self::new();
        for &index in indexes {
            out.push(index);
        }
        Ok(out)
    }

    /// Appends an index. Callers guarantee `len < MAX_MNEMONIC_WORDS` before calling
    /// (every call site validates the word count first), so this never overflows.
    pub(crate) fn push(&mut self, index: u16) {
        self.words[self.len] = index;
        self.len += 1;
    }
}

impl Default for WordIndexes {
    fn default() -> Self {
        Self::new()
    }
}

/// ASCII whitespace as recognised by the C++ `is_ascii_whitespace`: space, `\n`,
/// `\r`, `\t` only (deliberately *not* the form-feed that Rust's
/// `u8::is_ascii_whitespace` also accepts).
const fn is_bip39_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t')
}

/// Returns `true` for the valid BIP-39 mnemonic word counts. Mirrors the C++
/// `is_valid_bip39_word_count`.
#[must_use]
pub const fn is_valid_word_count(word_count: usize) -> bool {
    matches!(word_count, 12 | 15 | 18 | 21 | 24)
}

/// Returns the English wordlist word at `index`. Mirrors the C++
/// `bip39_english_word_at`.
///
/// # Errors
///
/// Returns [`Bip39Error::IndexOutOfRange`] if `index >= WORD_COUNT`.
pub fn word_at(index: u16) -> Result<&'static str, Bip39Error> {
    wordlist::WORDS
        .get(usize::from(index))
        .copied()
        .ok_or(Bip39Error::IndexOutOfRange)
}

/// Looks up a candidate token (any ASCII case) in the sorted wordlist, returning
/// its index. Mirrors the C++ `word_index` (`std::lower_bound` over the sorted
/// table). Tokens longer than the longest wordlist word cannot match.
fn word_index(token: &[u8]) -> Option<u16> {
    if token.len() > MAX_WORD_LEN {
        return None;
    }
    let mut lowered = [0u8; MAX_WORD_LEN];
    for (slot, &byte) in lowered.iter_mut().zip(token) {
        *slot = byte.to_ascii_lowercase();
    }
    let needle = &lowered[..token.len()];
    wordlist::WORDS
        .binary_search_by(|candidate| candidate.as_bytes().cmp(needle))
        .ok()
        .map(|index| index as u16)
}

/// Parses a BIP-39 English mnemonic into its validated word indexes. Mirrors the
/// C++ `parse_bip39_english_mnemonic_indexes`: whitespace-insensitive splitting,
/// ASCII-letter validation over the whole string, case-folding, wordlist lookup,
/// then a full checksum check.
///
/// # Errors
///
/// [`Bip39Error::NonAsciiWord`], [`Bip39Error::Empty`],
/// [`Bip39Error::InvalidWordCount`], [`Bip39Error::UnknownWord`] or
/// [`Bip39Error::InvalidChecksum`], in the same precedence order as the C++.
pub fn parse_mnemonic_indexes(mnemonic: &str) -> Result<WordIndexes, Bip39Error> {
    let bytes = mnemonic.as_bytes();

    // Pass 1: validate every byte is an ASCII letter or whitespace and count the
    // words — exactly what the C++ `split_mnemonic_words` did before any count or
    // lookup check, so a stray non-letter is reported first.
    let mut word_count = 0usize;
    let mut in_word = false;
    for &byte in bytes {
        if is_bip39_whitespace(byte) {
            in_word = false;
        } else if byte.is_ascii_alphabetic() {
            if !in_word {
                word_count += 1;
                in_word = true;
            }
        } else {
            return Err(Bip39Error::NonAsciiWord);
        }
    }
    if word_count == 0 {
        return Err(Bip39Error::Empty);
    }
    if !is_valid_word_count(word_count) {
        return Err(Bip39Error::InvalidWordCount);
    }

    // Pass 2: split again, folding and looking up each word.
    let mut indexes = WordIndexes::new();
    let mut start = 0usize;
    for i in 0..=bytes.len() {
        let at_boundary = i == bytes.len() || is_bip39_whitespace(bytes[i]);
        if at_boundary {
            if i > start {
                let index = word_index(&bytes[start..i]).ok_or(Bip39Error::UnknownWord)?;
                indexes.push(index);
            }
            start = i + 1;
        }
    }

    require_valid_checksum(indexes.as_slice())?;
    Ok(indexes)
}

/// Validates word-count and per-index range. Mirrors the C++
/// `require_valid_bip39_indexes`.
fn require_valid_indexes(indexes: &[u16]) -> Result<(), Bip39Error> {
    if !is_valid_word_count(indexes.len()) {
        return Err(Bip39Error::InvalidWordCount);
    }
    for &index in indexes {
        if usize::from(index) >= WORD_COUNT {
            return Err(Bip39Error::IndexOutOfRange);
        }
    }
    Ok(())
}

/// Extracts the `bit_index`-th mnemonic bit (MSB-first within each 11-bit word).
/// Mirrors the C++ `index_bit`.
fn index_bit(indexes: &[u16], bit_index: usize) -> u8 {
    let word = bit_index / 11;
    let bit = bit_index % 11;
    ((indexes[word] >> (10 - bit)) & 1) as u8
}

/// Extracts the `bit_index`-th digest bit (MSB-first within each byte). The C++
/// `digest_bit` read the hex string of the digest; reading the raw digest byte is
/// bit-for-bit identical and drops the redundant hex round-trip.
fn digest_bit(digest: &[u8; 32], bit_index: usize) -> u8 {
    (digest[bit_index / 8] >> (7 - (bit_index % 8))) & 1
}

/// Writes the entropy bytes reconstructed from the mnemonic bits into `out`,
/// returning the written length. Mirrors the C++ `entropy_from_indexes` (word count
/// already validated by the caller).
fn write_entropy(indexes: &[u16], out: &mut [u8]) -> usize {
    let checksum_bits = indexes.len() / 3;
    let entropy_bits = (indexes.len() * 11) - checksum_bits;
    let entropy_len = entropy_bits / 8;
    for slot in out[..entropy_len].iter_mut() {
        *slot = 0;
    }
    for bit_index in 0..entropy_bits {
        if index_bit(indexes, bit_index) != 0 {
            out[bit_index / 8] |= 1 << (7 - (bit_index % 8));
        }
    }
    entropy_len
}

/// Validates the BIP-39 checksum of `indexes`. Mirrors the C++
/// `require_valid_bip39_checksum`.
///
/// # Errors
///
/// [`Bip39Error::InvalidWordCount`] / [`Bip39Error::IndexOutOfRange`] if the shape
/// is wrong, or [`Bip39Error::InvalidChecksum`] if the trailing checksum bits do
/// not match the SHA-256 of the entropy.
pub fn require_valid_checksum(indexes: &[u16]) -> Result<(), Bip39Error> {
    require_valid_indexes(indexes)?;
    let checksum_bits = indexes.len() / 3;
    let entropy_bits = (indexes.len() * 11) - checksum_bits;
    let mut entropy = [0u8; 32];
    let entropy_len = write_entropy(indexes, &mut entropy);
    let digest = sha256(&entropy[..entropy_len]);
    for bit in 0..checksum_bits {
        let actual = index_bit(indexes, entropy_bits + bit);
        let expected = digest_bit(&digest, bit);
        if actual != expected {
            return Err(Bip39Error::InvalidChecksum);
        }
    }
    Ok(())
}

/// Reconstructs the BIP-39 entropy bytes for `indexes`, writing them into `out` and
/// returning the written prefix. Mirrors the C++ `bip39_entropy_from_indexes`
/// (validates indexes and checksum first).
///
/// # Errors
///
/// Propagates [`require_valid_checksum`] errors, or [`Bip39Error::BufferTooSmall`]
/// if `out` is shorter than the entropy length (16, 20, 24, 28 or 32 bytes).
pub fn entropy_from_indexes<'a>(
    indexes: &[u16],
    out: &'a mut [u8],
) -> Result<&'a [u8], Bip39Error> {
    // `require_valid_checksum` already validates the count and per-index range (it
    // calls `require_valid_indexes`), so a second explicit call would be redundant.
    require_valid_checksum(indexes)?;
    let checksum_bits = indexes.len() / 3;
    let entropy_len = ((indexes.len() * 11) - checksum_bits) / 8;
    if out.len() < entropy_len {
        return Err(Bip39Error::BufferTooSmall);
    }
    let written = write_entropy(indexes, out);
    Ok(&out[..written])
}

/// Renders `indexes` back to a space-separated English mnemonic, writing it into
/// `out` and returning it as a string slice. Mirrors the C++
/// `bip39_english_mnemonic_from_indexes` (validates indexes and checksum first).
///
/// # Errors
///
/// Propagates [`require_valid_checksum`] errors, or [`Bip39Error::BufferTooSmall`]
/// if `out` cannot hold the rendered mnemonic.
pub fn mnemonic_from_indexes<'a>(
    indexes: &[u16],
    out: &'a mut [u8],
) -> Result<&'a str, Bip39Error> {
    // `require_valid_checksum` validates count and per-index range too, so every
    // index below is guaranteed in-bounds and the wordlist lookup is infallible.
    require_valid_checksum(indexes)?;
    let mut pos = 0usize;
    for (n, &index) in indexes.iter().enumerate() {
        if n > 0 {
            *out.get_mut(pos).ok_or(Bip39Error::BufferTooSmall)? = b' ';
            pos += 1;
        }
        let word = wordlist::WORDS[usize::from(index)].as_bytes();
        let end = pos + word.len();
        out.get_mut(pos..end)
            .ok_or(Bip39Error::BufferTooSmall)?
            .copy_from_slice(word);
        pos = end;
    }
    // The rendered bytes are all ASCII letters and spaces, so this never fails.
    core::str::from_utf8(&out[..pos]).map_err(|_| Bip39Error::BufferTooSmall)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    #[test]
    fn wordlist_integrity_count_order_and_digest() {
        // Count matches the frozen constant.
        assert_eq!(wordlist::WORDS.len(), WORD_COUNT);
        // Sorted lexicographically (required by the binary search).
        assert!(wordlist::WORDS.windows(2).all(|pair| pair[0] < pair[1]));
        // Spot-check first/last and the known indices used by the shared vectors.
        assert_eq!(wordlist::WORDS[0], "abandon");
        assert_eq!(wordlist::WORDS[WORD_COUNT - 1], "zoo");
        assert_eq!(wordlist::WORDS[1012], "leader");
        assert_eq!(wordlist::WORDS[156], "bean");
        assert_eq!(wordlist::WORDS[115], "attack");
        assert_eq!(wordlist::WORDS[643], "expire");

        // SHA-256 of the newline-joined list (with a trailing newline) equals the
        // canonical BIP-39 English wordlist digest — proving the extracted table
        // matches the C++ source byte-for-byte. Computed here without alloc.
        let mut joined = [0u8; 2048 * 9];
        let mut pos = 0usize;
        for word in wordlist::WORDS {
            joined[pos..pos + word.len()].copy_from_slice(word.as_bytes());
            pos += word.len();
            joined[pos] = b'\n';
            pos += 1;
        }
        let digest = sha256(&joined[..pos]);
        let mut hex = [0u8; 64];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (byte, slot) in digest.iter().zip(hex.chunks_exact_mut(2)) {
            slot[0] = HEX[usize::from(byte >> 4)];
            slot[1] = HEX[usize::from(byte & 0x0f)];
        }
        assert_eq!(
            core::str::from_utf8(&hex).unwrap(),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
        );
    }

    #[test]
    fn is_valid_word_count_matches_cpp() {
        for n in [12usize, 15, 18, 21, 24] {
            assert!(is_valid_word_count(n));
        }
        for n in [0usize, 3, 11, 13, 23, 25] {
            assert!(!is_valid_word_count(n));
        }
    }

    #[test]
    fn word_at_bounds() {
        assert_eq!(word_at(0).unwrap(), "abandon");
        assert_eq!(word_at(2047).unwrap(), "zoo");
        assert_eq!(word_at(2048), Err(Bip39Error::IndexOutOfRange));
    }

    #[test]
    fn word_index_rejects_overlong_and_unknown() {
        assert_eq!(word_index(b"abandon"), Some(0));
        assert_eq!(word_index(b"ABANDON"), Some(0));
        assert_eq!(word_index(b"notaword"), None);
        // Longer than the longest wordlist word: rejected without a lookup.
        assert_eq!(word_index(b"supercalifragilistic"), None);
    }

    #[test]
    fn parse_rejects_empty_and_whitespace_only() {
        assert_eq!(parse_mnemonic_indexes(""), Err(Bip39Error::Empty));
        assert_eq!(parse_mnemonic_indexes("   \n\t "), Err(Bip39Error::Empty));
    }

    #[test]
    fn from_slice_bounds() {
        assert!(WordIndexes::from_slice(&[0u16; 24]).is_ok());
        assert_eq!(
            WordIndexes::from_slice(&[0u16; 25]),
            Err(Bip39Error::InvalidWordCount),
        );
        let empty = WordIndexes::default();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn require_valid_indexes_paths() {
        // Bad word count.
        assert_eq!(
            require_valid_checksum(&[0u16; 13]),
            Err(Bip39Error::InvalidWordCount),
        );
        // Index out of range (valid count of 12, one index == WORD_COUNT).
        let mut idx = [0u16; 12];
        idx[0] = WORD_COUNT as u16;
        assert_eq!(
            require_valid_checksum(&idx),
            Err(Bip39Error::IndexOutOfRange)
        );
    }

    #[test]
    fn entropy_and_mnemonic_propagate_validation_errors() {
        let mut buf = [0u8; 256];
        // Bad word count propagates from `require_valid_checksum`.
        assert_eq!(
            entropy_from_indexes(&[0u16; 13], &mut buf),
            Err(Bip39Error::InvalidWordCount),
        );
        assert_eq!(
            mnemonic_from_indexes(&[0u16; 13], &mut buf),
            Err(Bip39Error::InvalidWordCount),
        );
        // Valid count but a bad checksum also propagates.
        let mut bad_checksum = [0u16; 12];
        bad_checksum[11] = 1; // "abandon"*11 + "ability": invalid checksum.
        assert_eq!(
            entropy_from_indexes(&bad_checksum, &mut buf),
            Err(Bip39Error::InvalidChecksum),
        );
        assert_eq!(
            mnemonic_from_indexes(&bad_checksum, &mut buf),
            Err(Bip39Error::InvalidChecksum),
        );
    }

    #[test]
    fn all_zero_twelve_words_is_valid_checksum() {
        // "abandon" * 11 + "about": the canonical all-zero-entropy 12-word seed.
        let indexes = parse_mnemonic_indexes(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let mut ent = [0u8; 32];
        let entropy = entropy_from_indexes(indexes.as_slice(), &mut ent).unwrap();
        assert_eq!(entropy, [0u8; 16]);
    }

    #[test]
    fn buffer_too_small_paths() {
        let indexes = parse_mnemonic_indexes(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let mut tiny = [0u8; 4];
        assert_eq!(
            mnemonic_from_indexes(indexes.as_slice(), &mut tiny),
            Err(Bip39Error::BufferTooSmall),
        );
        // Space separator into a buffer that fits only the first word.
        let mut just_first = [0u8; 7];
        assert_eq!(
            mnemonic_from_indexes(indexes.as_slice(), &mut just_first),
            Err(Bip39Error::BufferTooSmall),
        );
        let mut ent_tiny = [0u8; 1];
        assert_eq!(
            entropy_from_indexes(indexes.as_slice(), &mut ent_tiny),
            Err(Bip39Error::BufferTooSmall),
        );
    }

    // Port of the C++ `test_bip39_english_mnemonic_parser_matches_shared_vector`.
    // Fixture fields copied from the READ-ONLY
    // specs/vectors/keys/nip06-account-0-leader.json (specs is a sibling repo with
    // no stable relative include path; literals keep `cargo test` green standalone,
    // as the M-T3.1 primitives port did).
    #[test]
    fn parser_matches_shared_nip06_vector() {
        const MNEMONIC: &str =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        const SECRET_HEX: &str = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
        const PUBLIC_HEX: &str = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";

        let indexes = parse_mnemonic_indexes(MNEMONIC).unwrap();
        assert_eq!(indexes.len(), 12);
        assert_eq!(word_at(indexes.as_slice()[0]).unwrap(), "leader");
        assert_eq!(word_at(indexes.as_slice()[11]).unwrap(), "bean");

        let mut buf = [0u8; 128];
        assert_eq!(
            mnemonic_from_indexes(indexes.as_slice(), &mut buf).unwrap(),
            MNEMONIC,
        );
        assert_eq!(SECRET_HEX.len(), 64);
        assert_eq!(PUBLIC_HEX.len(), 64);

        // Mixed case and surrounding/uneven whitespace normalize to the same indexes.
        let normalized = parse_mnemonic_indexes(
            "  Leader\nMONKEY  parrot ring guide accident before fence cannon height naive bean\t",
        )
        .unwrap();
        assert_eq!(normalized, indexes);

        assert_eq!(
            parse_mnemonic_indexes("abandon abandon abandon"),
            Err(Bip39Error::InvalidWordCount),
        );
        assert_eq!(
            parse_mnemonic_indexes(
                "notaword monkey parrot ring guide accident before fence cannon height naive bean"
            ),
            Err(Bip39Error::UnknownWord),
        );
        assert_eq!(
            parse_mnemonic_indexes(
                "leader monkey parrot ring guide accident before fence cannon height naive bean!"
            ),
            Err(Bip39Error::NonAsciiWord),
        );
        assert_eq!(
            parse_mnemonic_indexes(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            ),
            Err(Bip39Error::InvalidChecksum),
        );
        assert_eq!(word_at(2048), Err(Bip39Error::IndexOutOfRange));
    }
}
