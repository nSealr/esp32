//! URL-safe, unpadded Base64 ("base64url") encoding and decoding.
//!
//! Ported from the C++ reference `host_core` sources `src/base64url.cpp` +
//! `include/nsealr/base64url.hpp` for behaviour parity: the same alphabet
//! (`A`–`Z`, `a`–`z`, `0`–`9`, `-`, `_`; index 62 = `-`, 63 = `_`), the same
//! *unpadded* output (no `=` padding is ever produced, and `=` is rejected on
//! decode), and the same strict decode rejection rules
//! ([`Base64UrlError::InvalidCharacter`], [`Base64UrlError::InvalidTrailingBits`]).
//!
//! The C++ surface returns heap `std::string`s; this port writes into
//! caller-provided buffers so the crate stays `no_std` and allocation-free. Size
//! the buffers with [`encoded_len`] / [`decoded_len_max`]; a buffer that is too
//! short is reported as [`Base64UrlError::OutputTooSmall`] — the one variant with
//! no C++ analogue, because the growable C++ string cannot run out of space.

/// The base64url alphabet, indexed by 6-bit symbol value (`0..=63`).
///
/// Mirrors the C++ `base64url_encode_alphabet()` table exactly.
const ENCODE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Errors reported by [`decode_base64url`] and [`encode_base64url`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64UrlError {
    /// A byte outside the base64url alphabet was encountered while decoding
    /// (this includes the `=` padding byte). Parity with the C++
    /// `Base64UrlErrorCode::InvalidCharacter`.
    InvalidCharacter,
    /// The payload ended with leftover bits whose value is non-zero, i.e. it is
    /// not a canonical unpadded base64url encoding of any byte string. Parity
    /// with the C++ `Base64UrlErrorCode::InvalidTrailingBits`.
    InvalidTrailingBits,
    /// The caller-provided output buffer was too small to hold the result. This
    /// variant has no C++ counterpart (the C++ code returns a growable string);
    /// size buffers with [`encoded_len`] / [`decoded_len_max`] to avoid it.
    OutputTooSmall,
}

/// Maps an ASCII byte to its 6-bit base64url symbol value, or [`None`] if the
/// byte is not part of the alphabet. Mirrors the C++ `base64url_decode_table()`.
fn symbol(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Returns the exact number of characters [`encode_base64url`] produces for an
/// input of `input_len` bytes (unpadded base64url).
pub const fn encoded_len(input_len: usize) -> usize {
    (input_len * 8).div_ceil(6)
}

/// Returns the maximum number of bytes [`decode_base64url`] can produce for a
/// payload of `payload_len` characters.
pub const fn decoded_len_max(payload_len: usize) -> usize {
    (payload_len * 6) / 8
}

/// Returns `true` iff `value` is a non-empty string made up solely of base64url
/// alphabet characters. Mirrors the C++ `is_base64url_payload`: an empty input
/// is **not** a valid payload, and no length or trailing-bit validation is done.
pub fn is_base64url_payload(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(|&b| symbol(b).is_some())
}

/// Encodes `input` as unpadded base64url into `out`, returning the written
/// prefix of `out`. Mirrors the C++ `encode_base64url`.
///
/// # Errors
///
/// Returns [`Base64UrlError::OutputTooSmall`] if `out` is shorter than
/// [`encoded_len`]`(input.len())`.
pub fn encode_base64url<'a>(input: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], Base64UrlError> {
    let mut written = 0usize;
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut push = |symbol: u32| -> Result<(), Base64UrlError> {
        let byte = ENCODE[(symbol & 0x3f) as usize];
        *out.get_mut(written).ok_or(Base64UrlError::OutputTooSmall)? = byte;
        written += 1;
        Ok(())
    };
    for &byte in input {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            push(accumulator >> bits)?;
        }
    }
    if bits > 0 {
        push(accumulator << (6 - bits))?;
    }
    Ok(&out[..written])
}

/// Decodes the unpadded base64url `payload` into `out`, returning the written
/// prefix of `out`. Mirrors the C++ `decode_base64url`.
///
/// # Errors
///
/// - [`Base64UrlError::InvalidCharacter`] if `payload` contains a byte outside
///   the alphabet (including `=`).
/// - [`Base64UrlError::InvalidTrailingBits`] if `payload` has trailing bits with
///   a non-zero value (a non-canonical encoding).
/// - [`Base64UrlError::OutputTooSmall`] if `out` cannot hold the decoded bytes.
pub fn decode_base64url<'a>(payload: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], Base64UrlError> {
    let mut written = 0usize;
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in payload {
        let value = symbol(byte).ok_or(Base64UrlError::InvalidCharacter)?;
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let decoded = ((accumulator >> bits) & 0xff) as u8;
            *out.get_mut(written).ok_or(Base64UrlError::OutputTooSmall)? = decoded;
            written += 1;
        }
    }
    if bits > 0 && ((accumulator << (8 - bits)) & 0xff) != 0 {
        return Err(Base64UrlError::InvalidTrailingBits);
    }
    Ok(&out[..written])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_known_pairs() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"f", b"Zg"),
            (b"fo", b"Zm8"),
            (b"foo", b"Zm9v"),
            (b"foob", b"Zm9vYg"),
            (b"fooba", b"Zm9vYmE"),
            (b"foobar", b"Zm9vYmFy"),
            (b"\x00", b"AA"),
            (b"\xff", b"_w"),
            (b"\xff\xff", b"__8"),
        ];
        for &(input, expected) in cases {
            let mut buf = [0u8; 16];
            let out = encode_base64url(input, &mut buf).expect("encode fits");
            assert_eq!(out, expected, "encode {input:?}");
        }
    }

    #[test]
    fn decode_known_pairs_and_canonical_edges() {
        let mut buf = [0u8; 16];
        assert_eq!(decode_base64url(b"", &mut buf).unwrap(), b"");
        // A single "A" is 6 zero bits: canonical, decodes to the empty string.
        assert_eq!(decode_base64url(b"A", &mut buf).unwrap(), b"");
        assert_eq!(decode_base64url(b"AA", &mut buf).unwrap(), b"\x00");
        assert_eq!(decode_base64url(b"QUJD", &mut buf).unwrap(), b"ABC");
        assert_eq!(decode_base64url(b"Zm9vYmFy", &mut buf).unwrap(), b"foobar");
        assert_eq!(
            decode_base64url(b"eyJ2ZXJzaW9uIjoxfQ", &mut buf).unwrap(),
            br#"{"version":1}"#,
        );
    }

    #[test]
    fn decode_rejects_invalid_characters() {
        let mut buf = [0u8; 16];
        assert_eq!(
            decode_base64url(b"eyJ2ZXJzaW9uIjoxfQ==", &mut buf),
            Err(Base64UrlError::InvalidCharacter),
        );
        assert_eq!(
            decode_base64url(b"not-valid-base64!", &mut buf),
            Err(Base64UrlError::InvalidCharacter),
        );
        assert_eq!(
            decode_base64url(b"aa=", &mut buf),
            Err(Base64UrlError::InvalidCharacter),
        );
        assert_eq!(
            decode_base64url(b"plus+slash/", &mut buf),
            Err(Base64UrlError::InvalidCharacter),
        );
    }

    #[test]
    fn decode_rejects_non_zero_trailing_bits() {
        let mut buf = [0u8; 16];
        assert_eq!(
            decode_base64url(b"B", &mut buf),
            Err(Base64UrlError::InvalidTrailingBits),
        );
        assert_eq!(
            decode_base64url(b"AB", &mut buf),
            Err(Base64UrlError::InvalidTrailingBits),
        );
        assert_eq!(
            decode_base64url(b"-_", &mut buf),
            Err(Base64UrlError::InvalidTrailingBits),
        );
    }

    #[test]
    fn round_trips_across_all_tail_lengths() {
        let data: [u8; 33] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        for len in 0..=data.len() {
            let input = &data[..len];
            let mut enc = [0u8; 64];
            let encoded = encode_base64url(input, &mut enc).expect("encode fits");
            assert_eq!(encoded.len(), encoded_len(len));
            let mut dec = [0u8; 33];
            let decoded = decode_base64url(encoded, &mut dec).expect("decode fits");
            assert_eq!(decoded, input, "round trip at len {len}");
        }
    }

    #[test]
    fn reports_output_too_small() {
        let mut small = [0u8; 3];
        assert_eq!(
            encode_base64url(b"foo", &mut small),
            Err(Base64UrlError::OutputTooSmall),
        );
        let mut small2 = [0u8; 2];
        assert_eq!(
            decode_base64url(b"QUJD", &mut small2),
            Err(Base64UrlError::OutputTooSmall),
        );
    }

    #[test]
    fn is_payload_matches_cpp_predicate() {
        assert!(!is_base64url_payload(b""));
        assert!(is_base64url_payload(b"Zm9vYmFy"));
        assert!(is_base64url_payload(b"-_09AZaz"));
        assert!(!is_base64url_payload(b"has=pad"));
        assert!(!is_base64url_payload(b"has space"));
        assert!(!is_base64url_payload(b"plus+slash/"));
    }

    #[test]
    fn length_helpers_are_exact() {
        assert_eq!(encoded_len(0), 0);
        assert_eq!(encoded_len(1), 2);
        assert_eq!(encoded_len(2), 3);
        assert_eq!(encoded_len(3), 4);
        assert_eq!(encoded_len(6), 8);
        assert_eq!(decoded_len_max(0), 0);
        assert_eq!(decoded_len_max(2), 1);
        assert_eq!(decoded_len_max(3), 2);
        assert_eq!(decoded_len_max(4), 3);
    }

    // Byte-for-byte parity with a READ-ONLY specs/vectors fixture; the literal is
    // copied from specs/vectors/transports/qr-envelope-kind-1-basic.json
    // (`payload_base64url`). Proves canonical, unpadded encode/decode parity.
    #[test]
    fn specs_vector_basic_envelope_canonical_round_trip() {
        const PAYLOAD: &[u8] = b"eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm1ldGhvZCI6InNpZ25fZXZlbnQiLCJwYXJhbXMiOnsiZXZlbnRfdGVtcGxhdGUiOnsiY3JlYXRlZF9hdCI6MTcxMDAwMDAwMCwia2luZCI6MSwidGFncyI6W10sImNvbnRlbnQiOiJuU2VhbHIgZml4dHVyZTogYmFzaWMga2luZCAxIGV2ZW50LiJ9fX0";
        let mut raw = [0u8; 256];
        let decoded = decode_base64url(PAYLOAD, &mut raw).expect("decode fits");
        assert!(decoded.starts_with(br#"{"version":1,"#));
        let mut re = [0u8; 320];
        let reencoded = encode_base64url(decoded, &mut re).expect("encode fits");
        assert_eq!(reencoded, PAYLOAD);
    }

    // The padded envelope from specs/vectors/invalid/qr-envelope-padded.json
    // (`envelope` with the `nsealr1:` prefix stripped) must be rejected at this
    // layer: `=` is outside the alphabet.
    #[test]
    fn specs_vector_padded_payload_is_rejected() {
        const PADDED: &[u8] = b"eyJ2ZXJzaW9uIjoxfQ==";
        let mut buf = [0u8; 32];
        assert_eq!(
            decode_base64url(PADDED, &mut buf),
            Err(Base64UrlError::InvalidCharacter),
        );
        assert!(!is_base64url_payload(PADDED));
    }
}
