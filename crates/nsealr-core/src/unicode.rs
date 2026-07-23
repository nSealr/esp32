//! UTF-8 codec and JSON `\uXXXX` escape decoding helpers.
//!
//! Ported from the C++ reference `host_core` header-only helpers
//! `include/nsealr/utf8.hpp` and `include/nsealr/json_unicode.hpp` for behaviour
//! parity: the same Unicode-scalar rule (`<= 0x10FFFF`, excluding the
//! `0xD800..=0xDFFF` surrogate range), the same manual UTF-8 encoder, the same
//! streaming decoder (lead-byte ranges `0xC2..=0xDF`, `0xE0..=0xEF`, `0xF0..=0xF4`,
//! continuation `10xxxxxx`, overlong/out-of-range rejection), and the same JSON
//! `\uXXXX` code-unit parsing with surrogate-pair combination.
//!
//! `core::char` offers equivalent primitives, but this port keeps the manual codec
//! so the C++ origin stays traceable and the exact streaming/error semantics the
//! higher-layer JSON parser depends on are preserved byte-for-byte. The C++ helpers
//! appended to a growing `std::string`; this port encodes into a caller `[u8; 4]`
//! buffer to stay `no_std` and allocation-free.

/// The Unicode replacement character `U+FFFD`. Mirrors the C++
/// `kReplacementCodepoint`.
pub const REPLACEMENT_CODEPOINT: u32 = 0xfffd;

/// Errors reported by the JSON `\uXXXX` helpers. The C++ took two caller-supplied
/// message strings (truncated / invalid); this port maps them to two variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicodeError {
    /// The escape ran off the end of the input (fewer than four hex digits, or a
    /// missing low surrogate). C++: the `truncated_message`.
    Truncated,
    /// The escape was structurally invalid (non-hex digit, unpaired or malformed
    /// surrogate). C++: the `invalid_message`.
    Invalid,
}

/// Returns `true` if `codepoint` is a Unicode scalar value (encodable as UTF-8).
/// Mirrors the C++ `is_valid_unicode_scalar`.
#[must_use]
pub const fn is_valid_scalar(codepoint: u32) -> bool {
    codepoint <= 0x10_ffff && !(codepoint >= 0xd800 && codepoint <= 0xdfff)
}

/// Encodes `codepoint` as UTF-8 into `out`, returning the written 1–4 byte prefix.
/// Mirrors the C++ `append_utf8_codepoint` (which returned `false` for non-scalars).
///
/// Returns [`None`] if `codepoint` is not a Unicode scalar value.
pub fn encode_utf8(codepoint: u32, out: &mut [u8; 4]) -> Option<&[u8]> {
    if !is_valid_scalar(codepoint) {
        return None;
    }
    let len = if codepoint <= 0x7f {
        out[0] = codepoint as u8;
        1
    } else if codepoint <= 0x7ff {
        out[0] = 0xc0 | (codepoint >> 6) as u8;
        out[1] = 0x80 | (codepoint & 0x3f) as u8;
        2
    } else if codepoint <= 0xffff {
        out[0] = 0xe0 | (codepoint >> 12) as u8;
        out[1] = 0x80 | ((codepoint >> 6) & 0x3f) as u8;
        out[2] = 0x80 | (codepoint & 0x3f) as u8;
        3
    } else {
        out[0] = 0xf0 | (codepoint >> 18) as u8;
        out[1] = 0x80 | ((codepoint >> 12) & 0x3f) as u8;
        out[2] = 0x80 | ((codepoint >> 6) & 0x3f) as u8;
        out[3] = 0x80 | (codepoint & 0x3f) as u8;
        4
    };
    Some(&out[..len])
}

/// Decodes the next UTF-8 codepoint from `text` starting at `*offset`, advancing
/// `*offset` past the consumed bytes. Mirrors the C++ `decode_next_utf8_codepoint`.
///
/// Returns [`Some`] with the scalar on success, or [`None`] on an invalid or
/// truncated sequence. (The C++ also produced a replacement-codepoint out-param on
/// failure; no ported consumer reads it — [`is_valid_utf8`] only checks success — so
/// this port drops it. The offset is still advanced exactly as the C++ did.)
pub fn decode_next_codepoint(text: &[u8], offset: &mut usize) -> Option<u32> {
    if *offset >= text.len() {
        return None;
    }

    let start = *offset;
    let first = text[*offset];
    *offset += 1;
    if first <= 0x7f {
        return Some(u32::from(first));
    }

    let (continuations, mut value, minimum) = if (0xc2..=0xdf).contains(&first) {
        (1usize, u32::from(first & 0x1f), 0x80u32)
    } else if (0xe0..=0xef).contains(&first) {
        (2, u32::from(first & 0x0f), 0x800)
    } else if (0xf0..=0xf4).contains(&first) {
        (3, u32::from(first & 0x07), 0x10000)
    } else {
        *offset = start + 1;
        return None;
    };

    if *offset + continuations > text.len() {
        *offset = text.len();
        return None;
    }
    for _ in 0..continuations {
        let continuation = text[*offset];
        *offset += 1;
        if continuation & 0xc0 != 0x80 {
            return None;
        }
        value = (value << 6) | u32::from(continuation & 0x3f);
    }

    if value < minimum || !is_valid_scalar(value) {
        return None;
    }
    Some(value)
}

/// Returns `true` if `value` is well-formed UTF-8. Mirrors the C++ `is_valid_utf8`.
#[must_use]
pub fn is_valid_utf8(value: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < value.len() {
        if decode_next_codepoint(value, &mut offset).is_none() {
            return false;
        }
    }
    true
}

/// Maps a hex digit to its value. Mirrors the C++ `json_hex_value` (which returned
/// `-1` for non-hex).
fn json_hex_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a' + 10)),
        b'A'..=b'F' => Some(u32::from(byte - b'A' + 10)),
        _ => None,
    }
}

/// Reads four hex digits at `*offset`, advancing past them, and returns the 16-bit
/// code unit. Mirrors the C++ `parse_json_unicode_code_unit`.
///
/// # Errors
///
/// [`UnicodeError::Truncated`] if fewer than four bytes remain, or
/// [`UnicodeError::Invalid`] if any of the four is not a hex digit.
pub fn parse_json_unicode_code_unit(json: &[u8], offset: &mut usize) -> Result<u32, UnicodeError> {
    if *offset + 4 > json.len() {
        return Err(UnicodeError::Truncated);
    }
    let mut code_unit = 0u32;
    for _ in 0..4 {
        let nibble = json_hex_value(json[*offset]).ok_or(UnicodeError::Invalid)?;
        *offset += 1;
        code_unit = (code_unit << 4) | nibble;
    }
    Ok(code_unit)
}

/// Decodes one JSON `\uXXXX` escape body at `*offset` (the leading `\u` already
/// consumed by the caller), combining a surrogate pair if present, and writes the
/// UTF-8 bytes into `out`. Mirrors the C++ `append_json_unicode_escape` — instead of
/// appending to a string it returns the bytes to append.
///
/// # Errors
///
/// [`UnicodeError::Truncated`] on a missing low surrogate or short input, or
/// [`UnicodeError::Invalid`] on an unpaired/malformed surrogate.
pub fn append_json_unicode_escape<'a>(
    json: &[u8],
    offset: &mut usize,
    out: &'a mut [u8; 4],
) -> Result<&'a [u8], UnicodeError> {
    let mut codepoint = parse_json_unicode_code_unit(json, offset)?;

    if (0xd800..=0xdbff).contains(&codepoint) {
        if *offset + 2 > json.len() || json[*offset] != b'\\' || json[*offset + 1] != b'u' {
            return Err(UnicodeError::Invalid);
        }
        *offset += 2;
        let low = parse_json_unicode_code_unit(json, offset)?;
        if !(0xdc00..=0xdfff).contains(&low) {
            return Err(UnicodeError::Invalid);
        }
        codepoint = 0x10000 + (((codepoint - 0xd800) << 10) | (low - 0xdc00));
    } else if (0xdc00..=0xdfff).contains(&codepoint) {
        return Err(UnicodeError::Invalid);
    }

    encode_utf8(codepoint, out).ok_or(UnicodeError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_boundaries() {
        assert!(is_valid_scalar(0x41));
        assert!(is_valid_scalar(0x10_ffff));
        assert!(!is_valid_scalar(0x11_0000));
        assert!(is_valid_scalar(0xd7ff));
        assert!(!is_valid_scalar(0xd800));
        assert!(!is_valid_scalar(0xdfff));
        assert!(is_valid_scalar(0xe000));
    }

    #[test]
    fn encode_utf8_widths_and_rejection() {
        let mut buf = [0u8; 4];
        assert_eq!(encode_utf8(0x41, &mut buf).unwrap(), b"A"); // 1 byte
        assert_eq!(encode_utf8(0xe9, &mut buf).unwrap(), &[0xc3, 0xa9]); // 'é'
        assert_eq!(encode_utf8(0x20ac, &mut buf).unwrap(), &[0xe2, 0x82, 0xac]); // '€'
        assert_eq!(
            encode_utf8(0x1_f600, &mut buf).unwrap(),
            &[0xf0, 0x9f, 0x98, 0x80]
        ); // '😀'
        assert_eq!(encode_utf8(0xd800, &mut buf), None); // surrogate
    }

    #[test]
    fn is_valid_utf8_accepts_and_rejects() {
        assert!(is_valid_utf8(b""));
        assert!(is_valid_utf8("héllo€😀".as_bytes()));
        // Overlong two-byte encoding of NUL.
        assert!(!is_valid_utf8(&[0xc0, 0x80]));
        // Truncated three-byte sequence.
        assert!(!is_valid_utf8(&[0xe2, 0x82]));
        // Lone continuation byte.
        assert!(!is_valid_utf8(&[0x80]));
        // Surrogate encoded as CESU-8 (0xED 0xA0 0x80 = U+D800).
        assert!(!is_valid_utf8(&[0xed, 0xa0, 0x80]));
        // 5-byte lead byte.
        assert!(!is_valid_utf8(&[0xf8, 0x80, 0x80, 0x80, 0x80]));
        // Out of range (U+140000 via 0xF5 lead is rejected by the lead range).
        assert!(!is_valid_utf8(&[0xf5, 0x80, 0x80, 0x80]));
        // In-range 0xF4 lead but codepoint > 0x10FFFF (0xF4 0x90 -> 0x110000).
        assert!(!is_valid_utf8(&[0xf4, 0x90, 0x80, 0x80]));
        // Bad continuation in the middle.
        assert!(!is_valid_utf8(&[0xe2, 0x28, 0xa1]));
    }

    #[test]
    fn decode_next_codepoint_direct() {
        // Empty input / offset at end returns None without advancing.
        let mut offset = 0usize;
        assert_eq!(decode_next_codepoint(b"", &mut offset), None);
        assert_eq!(offset, 0);
        let text = "A€".as_bytes();
        let mut at_end = text.len();
        assert_eq!(decode_next_codepoint(text, &mut at_end), None);

        // Successful ASCII then 3-byte decode, advancing the offset each time.
        offset = 0;
        assert_eq!(
            decode_next_codepoint(text, &mut offset),
            Some(u32::from(b'A'))
        );
        assert_eq!(offset, 1);
        assert_eq!(decode_next_codepoint(text, &mut offset), Some(0x20ac));
        assert_eq!(offset, text.len());
    }

    #[test]
    fn parse_code_unit_paths() {
        let mut offset = 0usize;
        assert_eq!(parse_json_unicode_code_unit(b"0041", &mut offset), Ok(0x41));
        assert_eq!(offset, 4);
        // Lowercase hex digits (the `a..=f` arm) and uppercase (`A..=F`).
        offset = 0;
        assert_eq!(parse_json_unicode_code_unit(b"00ab", &mut offset), Ok(0xab));
        offset = 0;
        assert_eq!(parse_json_unicode_code_unit(b"00CD", &mut offset), Ok(0xcd));
        offset = 0;
        assert_eq!(
            parse_json_unicode_code_unit(b"00", &mut offset),
            Err(UnicodeError::Truncated),
        );
        offset = 0;
        assert_eq!(
            parse_json_unicode_code_unit(b"00zz", &mut offset),
            Err(UnicodeError::Invalid),
        );
    }

    #[test]
    fn json_escape_bmp_and_surrogate_pairs() {
        let mut out = [0u8; 4];

        // BMP character.
        let mut offset = 0usize;
        assert_eq!(
            append_json_unicode_escape(b"0041", &mut offset, &mut out).unwrap(),
            b"A",
        );

        // Surrogate pair for U+1F600 (😀): D83D followed by \uDE00.
        offset = 0;
        assert_eq!(
            append_json_unicode_escape(b"D83D\\uDE00", &mut offset, &mut out).unwrap(),
            &[0xf0, 0x9f, 0x98, 0x80],
        );

        // High surrogate not followed by another escape.
        offset = 0;
        assert_eq!(
            append_json_unicode_escape(b"D83Dxx", &mut offset, &mut out),
            Err(UnicodeError::Invalid),
        );

        // Lone low surrogate.
        offset = 0;
        assert_eq!(
            append_json_unicode_escape(b"DC00", &mut offset, &mut out),
            Err(UnicodeError::Invalid),
        );

        // High surrogate followed by a non-low-surrogate escape.
        offset = 0;
        assert_eq!(
            append_json_unicode_escape(b"D83D\\u0041", &mut offset, &mut out),
            Err(UnicodeError::Invalid),
        );

        // High surrogate with a truncated second unit.
        offset = 0;
        assert_eq!(
            append_json_unicode_escape(b"D83D\\uDE", &mut offset, &mut out),
            Err(UnicodeError::Truncated),
        );

        // A truncated/invalid *first* code unit propagates from the initial parse.
        offset = 0;
        assert_eq!(
            append_json_unicode_escape(b"00", &mut offset, &mut out),
            Err(UnicodeError::Truncated),
        );
        offset = 0;
        assert_eq!(
            append_json_unicode_escape(b"00zz", &mut offset, &mut out),
            Err(UnicodeError::Invalid),
        );
    }
}
