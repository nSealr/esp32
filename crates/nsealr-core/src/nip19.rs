//! NIP-19 `nsec` (Bech32) secret-key decoding and encoding.
//!
//! Ported from the C++ reference `host_core` sources `src/nip19_nsec.cpp` +
//! `include/nsealr/nip19_nsec.hpp` for behaviour parity. The Bech32 layer matches
//! the C++ exactly: the `qpzry9x8gf2tvdw0s3jn54khce6mua7l` charset, the same
//! polymod generator constants, canonical-lowercase enforcement (no surrounding
//! whitespace, no uppercase), the `1` separator rule, the 5-bit↔8-bit regrouping
//! with padding validation, the `nsec` HRP requirement, the 32-byte length rule,
//! and the secp256k1 scalar range check (`1 <= key < n`).
//!
//! The C++ surface returned heap `std::string`/`std::array` values. This port
//! returns the 32-byte key by value, writes the hex form into a fixed 64-byte ASCII
//! array, and encodes into a caller buffer — keeping the crate `no_std` and
//! allocation-free.

/// The Bech32 character set, indexed by 5-bit symbol value. Mirrors the C++
/// `kBech32Charset`.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The secp256k1 group order `n`, big-endian. A valid secret key is a non-zero
/// scalar strictly below this. Mirrors the C++ `kSecp256k1Order`.
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// BIP-0173 caps a Bech32 string at 90 characters. Inputs beyond this are rejected
/// as malformed; it also bounds the fixed word/byte scratch buffers.
const MAX_BECH32_LEN: usize = 90;

/// A 32-byte secp256k1 secret key. Mirrors the C++ `NsecSecretKey`.
pub type SecretKey = [u8; 32];

/// Errors reported by the `nsec` functions. Each variant corresponds to a distinct
/// C++ `NsecDecodeError` throw site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsecError {
    /// The string had surrounding whitespace or uppercase letters. C++: "nsec must
    /// be canonical lowercase bech32".
    NotCanonicalLowercase,
    /// The `1` separator was missing/misplaced or the string is too short (or longer
    /// than the Bech32 maximum). C++: "nsec bech32 payload is malformed".
    Malformed,
    /// A payload character was outside the Bech32 charset. C++: "nsec bech32 payload
    /// contains unsupported characters".
    UnsupportedCharacter,
    /// The Bech32 checksum did not verify. C++: "nsec bech32 checksum is invalid".
    InvalidChecksum,
    /// The human-readable prefix was not `nsec`. C++: "nsec bech32 prefix must be
    /// nsec".
    WrongPrefix,
    /// The 5-bit→8-bit regrouping left non-zero padding bits. C++: "nsec bech32
    /// payload has invalid padding".
    InvalidPadding,
    /// The payload did not decode to exactly 32 bytes. C++: "nsec payload must
    /// decode to a 32-byte secret key".
    WrongLength,
    /// The key was zero or not below the secp256k1 order. C++: "nsec payload must be
    /// a valid secp256k1 scalar" (and the encode-side scalar check).
    InvalidScalar,
    /// A caller-provided output buffer was too small (encode only). No C++ analogue
    /// (the C++ returned a growable `std::string`).
    BufferTooSmall,
}

const fn is_bech32_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t')
}

/// Maps a Bech32 character to its 5-bit value. Mirrors the C++ `bech32_value`.
fn bech32_value(byte: u8) -> Option<u8> {
    CHARSET.iter().position(|&c| c == byte).map(|i| i as u8)
}

/// One Bech32 polymod step over a 5-bit value. Mirrors the inner loop of the C++
/// `bech32_polymod`.
fn polymod_step(checksum: u32, value: u8) -> u32 {
    const GENERATORS: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let top = checksum >> 25;
    let mut checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(value);
    for (index, generator) in GENERATORS.iter().enumerate() {
        if (top >> index) & 1 != 0 {
            checksum ^= generator;
        }
    }
    checksum
}

/// Folds the HRP expansion (`ch >> 5` for each byte, a `0`, then `ch & 31` for each
/// byte) into a running polymod. Mirrors the C++ `bech32_hrp_expand` feeding
/// `bech32_polymod`.
fn fold_hrp(mut checksum: u32, hrp: &[u8]) -> u32 {
    for &byte in hrp {
        checksum = polymod_step(checksum, byte >> 5);
    }
    checksum = polymod_step(checksum, 0);
    for &byte in hrp {
        checksum = polymod_step(checksum, byte & 31);
    }
    checksum
}

/// A decoded Bech32 string: its HRP and the data 5-bit words (checksum stripped).
struct Bech32<'a> {
    hrp: &'a [u8],
    words: [u8; MAX_BECH32_LEN],
    words_len: usize,
}

/// Decodes a canonical-lowercase Bech32 string. Mirrors the C++
/// `decode_lower_bech32`.
fn decode_lower_bech32(value: &str) -> Result<Bech32<'_>, NsecError> {
    let bytes = value.as_bytes();

    // Canonical lowercase: no surrounding whitespace, no uppercase (C++ trims then
    // requires the trimmed value to equal the input, and rejects any A-Z).
    let trimmed_len = {
        let start = bytes.iter().position(|&b| !is_bech32_whitespace(b));
        match start {
            None => 0,
            Some(s) => {
                bytes.len()
                    - s
                    - bytes
                        .iter()
                        .rev()
                        .take_while(|&&b| is_bech32_whitespace(b))
                        .count()
            }
        }
    };
    let has_uppercase = bytes.iter().any(|&b| b.is_ascii_uppercase());
    if trimmed_len != bytes.len() || has_uppercase {
        return Err(NsecError::NotCanonicalLowercase);
    }
    if bytes.len() > MAX_BECH32_LEN {
        return Err(NsecError::Malformed);
    }

    // Separator: last '1', not at index 0, leaving room for a >=6-char checksum.
    let separator = match bytes.iter().rposition(|&b| b == b'1') {
        Some(s) if s != 0 && s + 7 <= bytes.len() => s,
        _ => return Err(NsecError::Malformed),
    };
    let hrp = &bytes[..separator];
    let payload = &bytes[separator + 1..];

    let mut words = [0u8; MAX_BECH32_LEN];
    for (slot, &ch) in words.iter_mut().zip(payload) {
        *slot = bech32_value(ch).ok_or(NsecError::UnsupportedCharacter)?;
    }
    let payload_len = payload.len();

    // Checksum over hrp-expansion ++ all payload words must equal 1.
    let mut checksum = fold_hrp(1, hrp);
    for &word in &words[..payload_len] {
        checksum = polymod_step(checksum, word);
    }
    if checksum != 1 {
        return Err(NsecError::InvalidChecksum);
    }

    Ok(Bech32 {
        hrp,
        words,
        words_len: payload_len - 6,
    })
}

/// Regroups 5-bit words into bytes, validating padding. Mirrors the C++
/// `convert_5bit_words_to_bytes`.
fn words_to_bytes(words: &[u8], out: &mut [u8]) -> Result<usize, NsecError> {
    let mut accumulator = 0u32;
    let mut bits = 0i32;
    let mut written = 0usize;
    for &word in words {
        accumulator = (accumulator << 5) | u32::from(word);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out[written] = ((accumulator >> bits) & 0xff) as u8;
            written += 1;
        }
        accumulator &= (1u32 << bits) - 1;
    }
    if bits >= 5 || ((accumulator << (8 - bits)) & 0xff) != 0 {
        return Err(NsecError::InvalidPadding);
    }
    Ok(written)
}

/// Regroups bytes into 5-bit words. Mirrors the C++ `convert_bytes_to_5bit_words`.
fn bytes_to_words(secret: &SecretKey, out: &mut [u8]) -> usize {
    let mut accumulator = 0u32;
    let mut bits = 0i32;
    let mut written = 0usize;
    for &byte in secret {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[written] = ((accumulator >> bits) & 31) as u8;
            written += 1;
        }
        accumulator &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out[written] = ((accumulator << (5 - bits)) & 31) as u8;
        written += 1;
    }
    written
}

/// Returns `true` if `secret` is a valid secp256k1 scalar (`1 <= key < n`). Mirrors
/// the C++ `is_valid_nsec_secret_key`.
#[must_use]
pub fn is_valid_secret_key(secret: &SecretKey) -> bool {
    let non_zero = secret.iter().any(|&byte| byte != 0);
    non_zero && *secret < SECP256K1_ORDER
}

/// Decodes an `nsec` Bech32 string into its 32-byte secret key. Mirrors the C++
/// `decode_nsec_secret_key`.
///
/// # Errors
///
/// Any [`NsecError`] variant, in the same precedence order as the C++
/// (canonical-lowercase → malformed → charset → checksum → prefix → padding →
/// length → scalar).
pub fn decode_nsec(nsec: &str) -> Result<SecretKey, NsecError> {
    let decoded = decode_lower_bech32(nsec)?;
    if decoded.hrp != b"nsec" {
        return Err(NsecError::WrongPrefix);
    }
    let mut bytes = [0u8; MAX_BECH32_LEN];
    let written = words_to_bytes(&decoded.words[..decoded.words_len], &mut bytes)?;
    if written != 32 {
        return Err(NsecError::WrongLength);
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes[..32]);
    if !is_valid_secret_key(&secret) {
        return Err(NsecError::InvalidScalar);
    }
    Ok(secret)
}

/// Decodes an `nsec` string and returns the secret key as 64 lowercase ASCII hex
/// bytes. Mirrors the C++ `decode_nsec_secret_key_hex`.
///
/// # Errors
///
/// Propagates every [`decode_nsec`] error.
pub fn decode_nsec_hex(nsec: &str) -> Result<[u8; 64], NsecError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let secret = decode_nsec(nsec)?;
    let mut out = [0u8; 64];
    for (byte, slot) in secret.iter().zip(out.chunks_exact_mut(2)) {
        slot[0] = HEX[usize::from(byte >> 4)];
        slot[1] = HEX[usize::from(byte & 0x0f)];
    }
    Ok(out)
}

/// Encodes a 32-byte secret key as a canonical `nsec` Bech32 string, writing it into
/// `out` and returning it as a string slice. Mirrors the C++
/// `encode_nsec_secret_key`.
///
/// # Errors
///
/// [`NsecError::InvalidScalar`] if the key is not a valid secp256k1 scalar, or
/// [`NsecError::BufferTooSmall`] if `out` is shorter than 63 bytes.
pub fn encode_nsec<'a>(secret: &SecretKey, out: &'a mut [u8]) -> Result<&'a str, NsecError> {
    if !is_valid_secret_key(secret) {
        return Err(NsecError::InvalidScalar);
    }
    // 32 bytes -> 52 data words; +6 checksum words; "nsec1" prefix => 63 chars.
    let mut words = [0u8; 58];
    let data_len = bytes_to_words(secret, &mut words);

    // Checksum: polymod over hrp-expansion ++ data words ++ six zero words, ^ 1.
    let mut checksum = fold_hrp(1, b"nsec");
    for &word in &words[..data_len] {
        checksum = polymod_step(checksum, word);
    }
    for _ in 0..6 {
        checksum = polymod_step(checksum, 0);
    }
    let polymod = checksum ^ 1;
    for (index, slot) in words[data_len..data_len + 6].iter_mut().enumerate() {
        *slot = ((polymod >> (5 * (5 - index))) & 31) as u8;
    }
    let total_words = data_len + 6;

    let output_len = 5 + total_words;
    if out.len() < output_len {
        return Err(NsecError::BufferTooSmall);
    }
    out[..5].copy_from_slice(b"nsec1");
    for (slot, &word) in out[5..output_len].iter_mut().zip(&words[..total_words]) {
        *slot = CHARSET[usize::from(word)];
    }
    // All bytes are Bech32 charset ASCII, so this never fails.
    core::str::from_utf8(&out[..output_len]).map_err(|_| NsecError::BufferTooSmall)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_secret_key_bounds() {
        assert!(!is_valid_secret_key(&[0u8; 32]));
        // The order itself is not below the order.
        assert!(!is_valid_secret_key(&SECP256K1_ORDER));
        // All-0xFF is above the order.
        assert!(!is_valid_secret_key(&[0xff; 32]));
        // 1 is valid.
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(is_valid_secret_key(&one));
        // order - 1 is valid.
        let mut order_minus_one = SECP256K1_ORDER;
        order_minus_one[31] -= 1;
        assert!(is_valid_secret_key(&order_minus_one));
    }

    #[test]
    fn encode_rejects_invalid_scalar_and_small_buffer() {
        let mut buf = [0u8; 63];
        assert_eq!(
            encode_nsec(&[0u8; 32], &mut buf),
            Err(NsecError::InvalidScalar),
        );
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut small = [0u8; 10];
        assert_eq!(
            encode_nsec(&one, &mut small),
            Err(NsecError::BufferTooSmall),
        );
    }

    #[test]
    fn decode_rejects_non_canonical_and_invalid_scalar() {
        // All-whitespace input: the trim finds no non-whitespace start.
        assert_eq!(decode_nsec("    "), Err(NsecError::NotCanonicalLowercase));
        assert_eq!(
            decode_nsec(" nsec1x "),
            Err(NsecError::NotCanonicalLowercase)
        );

        // Valid-checksum nsec strings that decode to 32 bytes but are not valid
        // secp256k1 scalars (computed with a reference bech32 encoder): the all-zero
        // key and the group order itself both fail the scalar range check.
        assert_eq!(
            decode_nsec("nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqwkhnav"),
            Err(NsecError::InvalidScalar),
        );
        assert_eq!(
            decode_nsec("nsec1lllllllllllllllllllllllll6a2ah8x4ay2qwal6f0ge5pkg9qstu3zum"),
            Err(NsecError::InvalidScalar),
        );
    }

    #[test]
    fn decode_rejects_wrong_length() {
        // A valid-checksum nsec whose payload decodes to fewer than 32 bytes.
        assert_eq!(
            decode_nsec("nsec1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zypf0r0t"),
            Err(NsecError::WrongLength),
        );
    }

    #[test]
    fn oversized_input_is_malformed() {
        // 100 lowercase chars (with a separator): exceeds the Bech32 maximum length.
        // C++ would attempt the checksum and almost certainly fail it; this
        // allocation-free port bounds its scratch buffers and rejects earlier as
        // Malformed. No tested/spec vector reaches this length.
        let mut long = [b'q'; 100];
        long[0] = b'1';
        let text = core::str::from_utf8(&long).unwrap();
        assert_eq!(decode_nsec(text), Err(NsecError::Malformed));
    }

    // Port of the C++ `test_nip19_nsec_decoder_matches_shared_vector`. Fixture
    // fields copied from the READ-ONLY specs/vectors/nip19/nsec-test-key-1.json.
    #[test]
    fn decoder_matches_shared_vector() {
        const NSEC: &str = "nsec1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs4rm7hz";
        const SECRET_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
        const PUBLIC_HEX: &str = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

        let secret = decode_nsec(NSEC).unwrap();
        let hex = decode_nsec_hex(NSEC).unwrap();
        assert_eq!(core::str::from_utf8(&hex).unwrap(), SECRET_HEX);
        assert_eq!(secret[0], 0x11);
        assert_eq!(secret[31], 0x11);
        assert_eq!(PUBLIC_HEX.len(), 64);

        // Re-encode reproduces the canonical fixture nsec (bech32 encode parity).
        let mut buf = [0u8; 63];
        assert_eq!(encode_nsec(&secret, &mut buf).unwrap(), NSEC);
        assert!(is_valid_secret_key(&secret));

        // checksum
        assert_eq!(
            decode_nsec_hex("nsec1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygqqqqqq"),
            Err(NsecError::InvalidChecksum),
        );
        // prefix
        assert_eq!(
            decode_nsec_hex("npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9"),
            Err(NsecError::WrongPrefix),
        );
        // lowercase
        assert_eq!(
            decode_nsec_hex("NSEC1ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYG3ZYGS4RM7HZ"),
            Err(NsecError::NotCanonicalLowercase),
        );
        // unsupported characters ('i' is outside the bech32 charset)
        assert_eq!(
            decode_nsec_hex("nsec1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygi4rm7hz"),
            Err(NsecError::UnsupportedCharacter),
        );
        // invalid padding
        assert_eq!(
            decode_nsec_hex("nsec1py3nlzd"),
            Err(NsecError::InvalidPadding),
        );
        // 32-byte secret key
        assert_eq!(
            decode_nsec_hex("nsec1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zypf0r0t"),
            Err(NsecError::WrongLength),
        );
        // malformed
        assert_eq!(decode_nsec_hex("nsec1short"), Err(NsecError::Malformed),);
    }
}
