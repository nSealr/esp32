//! `nsealr1f:` serial-line frame encoding and decoding.
//!
//! Ported from the C++ reference `host_core` sources `src/serial_frame.cpp` +
//! `include/nsealr/serial_frame.hpp` for behaviour parity: the same
//! `nsealr1f:<type>:<payload>:<checksum>\n` wire shape, the same
//! `sha256_hex(type + ":" + payload)[..16]` truncated checksum, the same
//! `request`/`response`/`error` frame types, the same CR/LF/CRLF line-ending
//! tolerance on decode, and the same rejection order (length → prefix → structure
//! → type → base64url payload → checksum).
//!
//! The C++ surface returned/accepted heap `std::string`s; this port encodes into a
//! caller buffer and decodes into borrowed slices, keeping the crate `no_std` and
//! allocation-free. The checksum pre-image is assembled in a
//! [`MAX_SERIAL_FRAME_BYTES`]-sized stack scratch buffer, which bounds an encoded
//! payload to what could ever appear inside a valid (`<= MAX_SERIAL_FRAME_BYTES`)
//! frame; an over-long payload is reported as [`SerialFrameError::OutputTooSmall`].

use crate::base64url::is_base64url_payload;
use crate::hash::sha256_hex;
use crate::qr::limits::MAX_SERIAL_FRAME_BYTES;

/// The serial frame prefix. Mirrors the C++ `kPrefix`.
const PREFIX: &[u8] = b"nsealr1f:";

/// Number of hex characters in the truncated frame checksum (first 8 bytes of the
/// SHA-256 digest). Mirrors the C++ `sha256_hex(...).substr(0, 16)`.
const CHECKSUM_HEX_LEN: usize = 16;

/// The frame direction/type. Mirrors the C++ `FrameType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// A request frame (`request`).
    Request,
    /// A response frame (`response`).
    Response,
    /// An error frame (`error`).
    Error,
}

/// Errors reported by the serial-frame functions. Each variant corresponds to a
/// distinct C++ `SerialFrameError` throw site, except [`Self::OutputTooSmall`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialFrameError {
    /// The payload was not non-empty unpadded base64url. C++: "serial frame payload
    /// must be unpadded base64url".
    PayloadNotBase64Url,
    /// The line exceeded [`MAX_SERIAL_FRAME_BYTES`]. C++: "serial frame exceeds
    /// max_serial_frame_bytes".
    ExceedsMaxBytes,
    /// The line did not start with the `nsealr1f:` prefix. C++: "serial frame must
    /// start with nsealr1f:".
    MissingPrefix,
    /// The frame body did not split into exactly type, payload and checksum. C++:
    /// "serial frame must contain type, payload, and checksum".
    Malformed,
    /// The type token was not `request`/`response`/`error`. C++: "unsupported serial
    /// frame type".
    UnsupportedType,
    /// The frame checksum did not match. C++: "serial frame checksum mismatch".
    ChecksumMismatch,
    /// A caller-provided output buffer (encode), or the checksum scratch, was too
    /// small. No C++ analogue (the C++ returned a growable `std::string`).
    OutputTooSmall,
}

/// A decoded serial frame. Mirrors the C++ `SerialFrame`, but the payload borrows
/// the decoded input instead of owning a `std::string`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialFrame<'a> {
    /// The frame type.
    pub frame_type: FrameType,
    /// The unpadded base64url payload.
    pub payload_base64url: &'a [u8],
}

/// Returns the wire token for a frame type. Mirrors the C++ `frame_type_to_string`.
#[must_use]
pub const fn frame_type_str(frame_type: FrameType) -> &'static str {
    match frame_type {
        FrameType::Request => "request",
        FrameType::Response => "response",
        FrameType::Error => "error",
    }
}

/// Parses a wire token into a [`FrameType`]. Mirrors the C++ `parse_frame_type`.
///
/// # Errors
///
/// [`SerialFrameError::UnsupportedType`] for any token other than
/// `request`/`response`/`error`.
pub fn parse_frame_type(value: &[u8]) -> Result<FrameType, SerialFrameError> {
    match value {
        b"request" => Ok(FrameType::Request),
        b"response" => Ok(FrameType::Response),
        b"error" => Ok(FrameType::Error),
        _ => Err(SerialFrameError::UnsupportedType),
    }
}

/// Assembles `type + ":" + payload` in a stack scratch and returns the truncated
/// (first-16-hex-char) SHA-256 checksum. Mirrors the C++ `checksum` helper.
fn frame_checksum(
    frame_type: FrameType,
    payload: &[u8],
) -> Result<[u8; CHECKSUM_HEX_LEN], SerialFrameError> {
    let type_bytes = frame_type_str(frame_type).as_bytes();
    let needed = type_bytes.len() + 1 + payload.len();
    let mut scratch = [0u8; MAX_SERIAL_FRAME_BYTES];
    if needed > scratch.len() {
        return Err(SerialFrameError::OutputTooSmall);
    }
    scratch[..type_bytes.len()].copy_from_slice(type_bytes);
    scratch[type_bytes.len()] = b':';
    scratch[type_bytes.len() + 1..needed].copy_from_slice(payload);
    let hex = sha256_hex(&scratch[..needed]);
    let mut checksum = [0u8; CHECKSUM_HEX_LEN];
    checksum.copy_from_slice(&hex[..CHECKSUM_HEX_LEN]);
    Ok(checksum)
}

/// Strips a single trailing CRLF, LF, or CR. Mirrors the C++ `strip_line_ending`.
fn strip_line_ending(line: &[u8]) -> &[u8] {
    if line.len() >= 2 && line[line.len() - 2] == b'\r' && line[line.len() - 1] == b'\n' {
        return &line[..line.len() - 2];
    }
    if let [rest @ .., last] = line {
        if *last == b'\n' || *last == b'\r' {
            return rest;
        }
    }
    line
}

/// The three fields of a frame body: (type, payload, checksum).
type FrameParts<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// Splits the frame body into exactly (type, payload, checksum). Mirrors the C++
/// `split_frame_body`: the first two fields must be `:`-terminated and the final
/// field must contain no further `:`.
fn split_frame_body(body: &[u8]) -> Result<FrameParts<'_>, SerialFrameError> {
    let first = body
        .iter()
        .position(|&b| b == b':')
        .ok_or(SerialFrameError::Malformed)?;
    let (type_text, after_type) = (&body[..first], &body[first + 1..]);
    let second = after_type
        .iter()
        .position(|&b| b == b':')
        .ok_or(SerialFrameError::Malformed)?;
    let (payload, checksum) = (&after_type[..second], &after_type[second + 1..]);
    if checksum.contains(&b':') {
        return Err(SerialFrameError::Malformed);
    }
    Ok((type_text, payload, checksum))
}

/// Encodes a serial frame into `out`, returning the written prefix (including the
/// trailing `\n`). Mirrors the C++ `encode_serial_frame`.
///
/// # Errors
///
/// [`SerialFrameError::PayloadNotBase64Url`], [`SerialFrameError::OutputTooSmall`].
pub fn encode_serial_frame<'o>(
    frame_type: FrameType,
    payload_base64url: &[u8],
    out: &'o mut [u8],
) -> Result<&'o [u8], SerialFrameError> {
    if !is_base64url_payload(payload_base64url) {
        return Err(SerialFrameError::PayloadNotBase64Url);
    }
    let checksum = frame_checksum(frame_type, payload_base64url)?;
    let type_bytes = frame_type_str(frame_type).as_bytes();
    let total =
        PREFIX.len() + type_bytes.len() + 1 + payload_base64url.len() + 1 + CHECKSUM_HEX_LEN + 1;
    if out.len() < total {
        return Err(SerialFrameError::OutputTooSmall);
    }
    let mut at = 0usize;
    let mut push = |bytes: &[u8]| {
        out[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    push(PREFIX);
    push(type_bytes);
    push(b":");
    push(payload_base64url);
    push(b":");
    push(&checksum);
    push(b"\n");
    Ok(&out[..total])
}

/// Decodes a serial frame line (with or without a trailing CR/LF/CRLF). Mirrors the
/// C++ `decode_serial_frame`.
///
/// # Errors
///
/// See [`SerialFrameError`]; the rejection order matches the C++ (length → prefix →
/// structure → type → base64url payload → checksum).
pub fn decode_serial_frame(line: &[u8]) -> Result<SerialFrame<'_>, SerialFrameError> {
    if line.len() > MAX_SERIAL_FRAME_BYTES {
        return Err(SerialFrameError::ExceedsMaxBytes);
    }
    let normalized = strip_line_ending(line);
    let body = normalized
        .strip_prefix(PREFIX)
        .ok_or(SerialFrameError::MissingPrefix)?;
    let (type_text, payload, checksum) = split_frame_body(body)?;
    let frame_type = parse_frame_type(type_text)?;
    if !is_base64url_payload(payload) {
        return Err(SerialFrameError::PayloadNotBase64Url);
    }
    if checksum != frame_checksum(frame_type, payload)? {
        return Err(SerialFrameError::ChecksumMismatch);
    }
    Ok(SerialFrame {
        frame_type,
        payload_base64url: payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte-for-byte fixtures copied from
    // specs/vectors/transports/serial-frame-request-kind-1-basic.json
    // (`payload_base64url` and `frame`).
    const PAYLOAD: &[u8] = b"eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm1ldGhvZCI6InNpZ25fZXZlbnQiLCJwYXJhbXMiOnsiZXZlbnRfdGVtcGxhdGUiOnsiY3JlYXRlZF9hdCI6MTcxMDAwMDAwMCwia2luZCI6MSwidGFncyI6W10sImNvbnRlbnQiOiJuU2VhbHIgZml4dHVyZTogYmFzaWMga2luZCAxIGV2ZW50LiJ9fX0";
    const FRAME: &[u8] = b"nsealr1f:request:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm1ldGhvZCI6InNpZ25fZXZlbnQiLCJwYXJhbXMiOnsiZXZlbnRfdGVtcGxhdGUiOnsiY3JlYXRlZF9hdCI6MTcxMDAwMDAwMCwia2luZCI6MSwidGFncyI6W10sImNvbnRlbnQiOiJuU2VhbHIgZml4dHVyZTogYmFzaWMga2luZCAxIGV2ZW50LiJ9fX0:37f84b248fa1afb6\n";

    // Shared-invalid serial-frame fixtures copied from specs/vectors/invalid/
    // serial-frame-{checksum-mismatch,malformed-payload,unsupported-type}.json
    // (`frame`); the oversized fixture is rebuilt byte-identically below.
    const INVALID_CHECKSUM_MISMATCH: &[u8] = b"nsealr1f:request:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLXNlcmlhbC1tYWxmb3JtZWQiLCJtZXRob2QiOiJzaWduX2V2ZW50IiwicGFyYW1zIjp7ImV2ZW50X3RlbXBsYXRlIjp7ImNyZWF0ZWRfYXQiOjE3MTAwMDAwMDAsImtpbmQiOjEsInRhZ3MiOltdLCJjb250ZW50Ijoib2sifX19:0000000000000000\n";
    const INVALID_MALFORMED_PAYLOAD: &[u8] =
        b"nsealr1f:request:not-valid-base64!:0000000000000000\n";
    const INVALID_UNSUPPORTED_TYPE: &[u8] =
        b"nsealr1f:command:eyJub29wIjp0cnVlfQ:224b8206979b2488\n";

    /// The oversized fixture from specs/vectors/invalid/serial-frame-oversized.json
    /// (`frame`): `nsealr1f:` + 1100 'x' characters (1109 bytes), rebuilt
    /// programmatically, byte-identical to the fixture.
    fn oversized_frame() -> std::vec::Vec<u8> {
        let mut frame = std::vec::Vec::from(&b"nsealr1f:"[..]);
        frame.extend(core::iter::repeat_n(b'x', 1100));
        assert_eq!(frame.len(), 1109); // matches the fixture byte count
        frame
    }

    #[test]
    fn serial_frame_round_trip() {
        let mut buf = [0u8; MAX_SERIAL_FRAME_BYTES];
        let encoded = encode_serial_frame(FrameType::Request, PAYLOAD, &mut buf).unwrap();
        assert_eq!(encoded, FRAME);

        let decoded = decode_serial_frame(encoded).unwrap();
        assert_eq!(decoded.frame_type, FrameType::Request);
        assert_eq!(decoded.payload_base64url, PAYLOAD);

        // CRLF line ending is tolerated: replace the trailing '\n' with "\r\n".
        let mut crlf = [0u8; MAX_SERIAL_FRAME_BYTES + 1];
        let body = &encoded[..encoded.len() - 1];
        crlf[..body.len()].copy_from_slice(body);
        crlf[body.len()] = b'\r';
        crlf[body.len() + 1] = b'\n';
        let decoded_crlf = decode_serial_frame(&crlf[..body.len() + 2]).unwrap();
        assert_eq!(decoded_crlf.frame_type, FrameType::Request);
        assert_eq!(decoded_crlf.payload_base64url, PAYLOAD);
    }

    #[test]
    fn serial_frame_rejections() {
        assert_eq!(
            decode_serial_frame(b"nsealr1f:pubkey:eyJ2ZXJzaW9uIjoxfQ:d78075380263956b\n"),
            Err(SerialFrameError::UnsupportedType),
        );
        assert_eq!(
            decode_serial_frame(b"nsealr1f:request:eyJ2ZXJzaW9uIjoxfQ:0000000000000000\n"),
            Err(SerialFrameError::ChecksumMismatch),
        );
        assert_eq!(
            decode_serial_frame(b"nsealr1f:request:not+base64url:d78075380263956b\n"),
            Err(SerialFrameError::PayloadNotBase64Url),
        );
    }

    #[test]
    fn serial_frame_rejects_shared_invalid_vectors() {
        let oversized = oversized_frame();
        assert_eq!(
            decode_serial_frame(&oversized),
            Err(SerialFrameError::ExceedsMaxBytes),
        );
        assert_eq!(
            decode_serial_frame(INVALID_CHECKSUM_MISMATCH),
            Err(SerialFrameError::ChecksumMismatch),
        );
        assert_eq!(
            decode_serial_frame(INVALID_MALFORMED_PAYLOAD),
            Err(SerialFrameError::PayloadNotBase64Url),
        );
        assert_eq!(
            decode_serial_frame(INVALID_UNSUPPORTED_TYPE),
            Err(SerialFrameError::UnsupportedType),
        );
    }

    // --- Supplementary direct tests (coverage of every branch/variant) ---

    #[test]
    fn frame_type_tokens_round_trip_all_variants() {
        assert_eq!(frame_type_str(FrameType::Request), "request");
        assert_eq!(frame_type_str(FrameType::Response), "response");
        assert_eq!(frame_type_str(FrameType::Error), "error");
        assert_eq!(parse_frame_type(b"request"), Ok(FrameType::Request));
        assert_eq!(parse_frame_type(b"response"), Ok(FrameType::Response));
        assert_eq!(parse_frame_type(b"error"), Ok(FrameType::Error));
        assert_eq!(
            parse_frame_type(b"bogus"),
            Err(SerialFrameError::UnsupportedType),
        );
    }

    #[test]
    fn encodes_response_and_error_frames_that_round_trip() {
        for frame_type in [FrameType::Response, FrameType::Error] {
            let mut buf = [0u8; MAX_SERIAL_FRAME_BYTES];
            let encoded = encode_serial_frame(frame_type, PAYLOAD, &mut buf).unwrap();
            let decoded = decode_serial_frame(encoded).unwrap();
            assert_eq!(decoded.frame_type, frame_type);
            assert_eq!(decoded.payload_base64url, PAYLOAD);
        }
    }

    #[test]
    fn encode_rejects_bad_payload_and_small_buffer() {
        let mut buf = [0u8; MAX_SERIAL_FRAME_BYTES];
        assert_eq!(
            encode_serial_frame(FrameType::Request, b"", &mut buf),
            Err(SerialFrameError::PayloadNotBase64Url),
        );
        assert_eq!(
            encode_serial_frame(FrameType::Request, b"has space", &mut buf),
            Err(SerialFrameError::PayloadNotBase64Url),
        );
        let mut tiny = [0u8; 4];
        assert_eq!(
            encode_serial_frame(FrameType::Request, PAYLOAD, &mut tiny),
            Err(SerialFrameError::OutputTooSmall),
        );
    }

    #[test]
    fn encode_rejects_payload_that_overflows_checksum_scratch() {
        // A base64url payload longer than the checksum scratch can never fit inside a
        // valid frame; it is reported as OutputTooSmall.
        let payload = [b'A'; MAX_SERIAL_FRAME_BYTES];
        let mut buf = [0u8; 4 * MAX_SERIAL_FRAME_BYTES];
        assert_eq!(
            encode_serial_frame(FrameType::Request, &payload, &mut buf),
            Err(SerialFrameError::OutputTooSmall),
        );
    }

    #[test]
    fn decode_line_ending_variants() {
        let mut buf = [0u8; MAX_SERIAL_FRAME_BYTES];
        let encoded = encode_serial_frame(FrameType::Request, PAYLOAD, &mut buf).unwrap();
        let body = &encoded[..encoded.len() - 1]; // strip the '\n'

        // No trailing line ending at all.
        assert_eq!(
            decode_serial_frame(body).unwrap().payload_base64url,
            PAYLOAD
        );

        // Bare '\r' line ending.
        let mut cr = [0u8; MAX_SERIAL_FRAME_BYTES];
        cr[..body.len()].copy_from_slice(body);
        cr[body.len()] = b'\r';
        assert_eq!(
            decode_serial_frame(&cr[..body.len() + 1])
                .unwrap()
                .payload_base64url,
            PAYLOAD,
        );
    }

    #[test]
    fn decode_structural_rejections() {
        // Empty line (no line ending to strip at all).
        assert_eq!(
            decode_serial_frame(b""),
            Err(SerialFrameError::MissingPrefix)
        );
        assert_eq!(
            decode_serial_frame(b"nostr:abc\n"),
            Err(SerialFrameError::MissingPrefix),
        );
        // Body with no ':' at all -> cannot split into three parts.
        assert_eq!(
            decode_serial_frame(b"nsealr1f:onlyonepart\n"),
            Err(SerialFrameError::Malformed),
        );
        // Body with only one ':' -> missing checksum separator.
        assert_eq!(
            decode_serial_frame(b"nsealr1f:request:payload\n"),
            Err(SerialFrameError::Malformed),
        );
        // A stray ':' inside the checksum field -> too many parts.
        assert_eq!(
            decode_serial_frame(b"nsealr1f:request:AA:dead:beef\n"),
            Err(SerialFrameError::Malformed),
        );
    }
}
