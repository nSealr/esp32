//! `nsealr1:` QR envelope framing, `nsealr1a:` animated envelopes, and the
//! sign-event signing-request parser.
//!
//! Ported from the C++ reference `host_core` sources `src/qr_envelope.cpp` +
//! `include/nsealr/qr_envelope.hpp` for behaviour parity:
//!
//! - **Static envelope** — `nsealr1:` + unpadded base64url; decode enforces the
//!   base64url alphabet, `len % 4 != 1`, canonical trailing bits, the decoded-size
//!   limit [`MAX_STATIC_QR_DECODED_JSON_BYTES`], valid UTF-8, and a trimmed
//!   `{...}`/`[...]` JSON container shape.
//! - **Animated envelope** — frames shaped
//!   `nsealr1a:<sha256hex(json)>:<index>/<total>:<chunk>:<checksum16>` where the
//!   checksum is `sha256_hex("nsealr1a:" + digest + ":" + index + "/" + total +
//!   ":" + chunk)[..16]`; decode requires one frame per index `1..=total` (any
//!   order, no duplicates), a common digest/total, per-frame chunk limits, then
//!   validates the reassembled payload like the static path plus the whole-JSON
//!   digest, against [`MAX_ANIMATED_QR_DECODED_JSON_BYTES`].
//! - **Signing request** — a hand-rolled, non-recursive JSON top-level-object
//!   scanner (mirroring the C++ `parse_top_level_object`): strings decode the
//!   standard two-character escapes plus `\uXXXX` (via [`crate::unicode`], with
//!   surrogate-pair combination), numbers are integer-only tokens (`-?[0-9]+`),
//!   nested containers are skipped by depth counting **without** validating their
//!   internal grammar (only strings inside them are parsed). The top level
//!   tolerates *no* unknown fields (`version`/`request_id`/`method`/`params`
//!   only, and `params` only `event_template`); the event template requires
//!   exactly `created_at`/`kind`/`tags`/`content`, bans `id`/`pubkey`/`sig`, and
//!   enforces every `limits` maximum. The raw `event_template`/`tags` JSON text
//!   is preserved by byte range so escape sequences survive verbatim (the C++
//!   kept `std::string` copies; this port keeps offsets into the envelope JSON).
//!
//! The C++ returned heap strings/vectors. This port writes envelope output into
//! caller buffers, hands animated frames to a callback one at a time, and returns
//! parsed requests as a fixed-capacity struct sized by [`crate::qr::limits`] —
//! keeping the crate `no_std` and allocation-free. Buffer-size errors are
//! reported as [`QrEnvelopeError::OutputTooSmall`] (no C++ analogue).

use crate::base64url::{
    decode_base64url, decoded_len_max, encode_base64url, encoded_len, is_base64url_payload,
    Base64UrlError,
};
use crate::hash::sha256_hex;
use crate::qr::limits::{
    MAX_ANIMATED_QR_DECODED_JSON_BYTES, MAX_ANIMATED_QR_FRAME_COUNT,
    MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS, MAX_CONTENT_UTF8_BYTES, MAX_DECODED_REQUEST_JSON_BYTES,
    MAX_REQUEST_ID_LENGTH, MAX_SAFE_INTEGER, MAX_STATIC_QR_DECODED_JSON_BYTES, MAX_TAG_COUNT,
    MAX_TAG_FIELDS_PER_TAG, MAX_TAG_FIELD_UTF8_BYTES,
};
use crate::unicode::{append_json_unicode_escape, is_valid_utf8, UnicodeError};

/// The static envelope prefix. Mirrors the C++ `kPrefix`.
pub const PREFIX: &[u8] = b"nsealr1:";
/// The animated envelope frame prefix. Mirrors the C++ `kAnimatedPrefix`.
pub const ANIMATED_PREFIX: &[u8] = b"nsealr1a:";

/// Hex characters in a full SHA-256 digest (the animated frame digest field).
const DIGEST_HEX_LEN: usize = 64;
/// Hex characters in the truncated animated-frame checksum.
const CHECKSUM_HEX_LEN: usize = 16;

/// Errors reported by the QR envelope functions. Each variant corresponds to one
/// or more distinct C++ `QrEnvelopeError` messages (named in the doc comments),
/// except [`Self::OutputTooSmall`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrEnvelopeError {
    /// C++: "QR envelope must start with nsealr1:".
    MissingPrefix,
    /// C++: "QR envelope payload must be unpadded base64url".
    PayloadNotBase64Url,
    /// C++: "QR envelope payload has invalid base64url length" / "animated QR
    /// payload has invalid base64url length" (`len % 4 == 1`).
    InvalidBase64UrlLength,
    /// C++: "QR envelope payload has invalid trailing bits".
    InvalidTrailingBits,
    /// C++: "QR decoded JSON exceeds max_static_qr_decoded_json_bytes".
    ExceedsStaticJsonBytes,
    /// C++: "animated QR decoded JSON exceeds max_animated_qr_decoded_json_bytes".
    ExceedsAnimatedJsonBytes,
    /// C++: "QR envelope payload must be valid UTF-8" / "animated QR payload must
    /// be valid UTF-8".
    InvalidUtf8,
    /// C++: "QR envelope payload is not valid JSON" (not a `{...}`/`[...]`
    /// container after ASCII-whitespace trim).
    NotJsonContainer,
    /// C++: "animated QR requires at least one frame".
    NoFrames,
    /// C++: "animated QR frame requires nsealr1a prefix".
    AnimatedMissingPrefix,
    /// C++: "animated QR frame is malformed" (not exactly five `:`-fields).
    AnimatedMalformed,
    /// C++: "animated QR digest must be 32-byte lowercase hex".
    AnimatedBadDigest,
    /// C++: "animated QR checksum must be 8-byte lowercase hex".
    AnimatedBadChecksumFormat,
    /// C++: "animated QR index must use index/total".
    AnimatedBadIndexShape,
    /// C++: "animated QR index and total must be decimal" (zero, leading zero,
    /// non-digit, or overflow).
    AnimatedBadIndexValue,
    /// C++: "animated QR frame index is out of range" (`index > total`).
    AnimatedIndexOutOfRange,
    /// C++: "animated QR frame count exceeds max_animated_qr_frame_count".
    AnimatedTooManyFrames,
    /// C++: "animated QR chunk must be unpadded base64url".
    AnimatedChunkNotBase64Url,
    /// C++: "animated QR chunk exceeds max_animated_qr_frame_payload_chars".
    AnimatedChunkTooLong,
    /// C++: "animated QR frame checksum mismatch".
    AnimatedChecksumMismatch,
    /// C++: "animated QR frames must be unique and contiguous" (count != total,
    /// duplicate index, or missing index).
    AnimatedFramesNotContiguous,
    /// C++: "animated QR frame set mismatch" (digest or total differs between
    /// frames).
    AnimatedFrameSetMismatch,
    /// C++: "animated QR decoded digest mismatch".
    AnimatedDigestMismatch,
    /// C++: "animated QR chunk size must be a positive integer".
    AnimatedChunkSizeZero,
    /// C++: "animated QR payload is empty" (encoding an empty payload).
    AnimatedPayloadEmpty,
    /// C++: "QR signing request decoded JSON exceeds max_decoded_request_json_bytes".
    ExceedsRequestJsonBytes,
    /// C++: "QR signing request must be a JSON object".
    RequestNotObject,
    /// C++: the JSON scanner errors — "... JSON string is required" /
    /// "... escape is truncated/invalid" / "... unicode escape is
    /// truncated/invalid" / "... contains control character" / "... string is
    /// unterminated" / "... number is invalid" / "... container is
    /// invalid/unterminated" / "... value is invalid/missing" / "... object member
    /// is missing ':'" / "... object separator is invalid" / "... has trailing
    /// data".
    RequestJsonMalformed,
    /// C++: "QR signing request contains unknown top-level field".
    RequestUnknownField,
    /// C++: "QR signing request version must be 1".
    RequestBadVersion,
    /// C++: "QR signing request request_id is invalid".
    RequestBadRequestId,
    /// C++: "QR signing request method must be sign_event".
    RequestBadMethod,
    /// C++: "QR signing request params object is required".
    RequestParamsRequired,
    /// C++: "QR signing request params contains unknown field".
    RequestParamsUnknownField,
    /// C++: "QR signing request event_template object is required".
    RequestEventTemplateRequired,
    /// C++: "QR signing request event_template must not include id/pubkey/sig".
    RequestEventTemplateForbiddenField,
    /// C++: "QR signing request event_template contains unknown field".
    RequestEventTemplateUnknownField,
    /// C++: "QR signing request event_template created_at is
    /// required/invalid/exceeds max_safe_integer".
    RequestBadCreatedAt,
    /// C++: "QR signing request event_template kind is required/invalid/exceeds
    /// max_safe_integer".
    RequestBadKind,
    /// C++: "QR signing request event_template tags array is required" and the
    /// tags-grammar errors ("tags must be string arrays", "tags array separator is
    /// invalid", "tags array has trailing data").
    RequestBadTags,
    /// C++: "QR signing request event_template content is required".
    RequestBadContent,
    /// C++: "QR signing request event_template content exceeds
    /// max_content_utf8_bytes".
    ContentTooLong,
    /// C++: "QR signing request event_template tag field exceeds
    /// max_tag_field_utf8_bytes".
    TagFieldTooLong,
    /// C++: "QR signing request event_template tag exceeds max_tag_fields_per_tag".
    TooManyTagFields,
    /// C++: "QR signing request event_template tags exceed max_tag_count". (The
    /// C++ also had a "max_total_tag_utf8_bytes" sweep, unreachable behind the
    /// 704-byte request-JSON guard; this port omits that dead check.)
    TooManyTags,
    /// A caller-provided output buffer was too small. No C++ analogue.
    OutputTooSmall,
}

/// A decoded QR envelope: the raw base64url payload text and the decoded JSON.
/// Mirrors the C++ `QrEnvelope` (which owned two `std::string`s); this port
/// borrows the input and the caller's decode buffer.
#[derive(Debug, Clone, Copy)]
pub struct QrEnvelope<'a> {
    /// The unpadded base64url payload (without the `nsealr1:` prefix).
    pub payload_base64url: &'a [u8],
    /// The decoded JSON payload bytes.
    pub payload_json: &'a [u8],
}

/// One field of one tag: which tag it belongs to plus the byte range of its
/// decoded text inside the request's packed tag-field buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TagField {
    /// Index of the tag this field belongs to (0-based).
    tag: usize,
    /// Byte range `start..end` of the decoded field text.
    start: usize,
    /// End of the byte range.
    end: usize,
}

/// The parsed `event_template`. Mirrors the C++ `QrEventTemplate`, with the heap
/// `tags_json`/`content` strings replaced by a byte range into the request JSON
/// (raw span) and accessors on [`QrSigningRequest`] (decoded text).
#[derive(Debug, Clone, Copy)]
pub struct QrEventTemplate {
    /// The `created_at` value.
    pub created_at: u64,
    /// The `kind` value. The C++ stored an `int` after a `<= INT_MAX` check; this
    /// port keeps the same accepted range (`0..=i32::MAX`).
    pub kind: i32,
    /// Raw byte range of the `tags` array inside the request JSON.
    pub tags_json: (usize, usize),
    /// Number of tags.
    pub tag_count: usize,
}

/// A parsed QR signing request. Mirrors the C++ `QrSigningRequest`; the
/// `request_id`/`content`/tag-field texts live in fixed internal buffers exposed
/// through accessors, and the raw `event_template` JSON is exposed as a byte
/// range into the request JSON.
#[derive(Debug, Clone, Copy)]
pub struct QrSigningRequest {
    /// Always 1 on success. Mirrors the C++ field.
    pub version: i32,
    request_id: [u8; MAX_REQUEST_ID_LENGTH],
    request_id_len: usize,
    /// `true` when `params` was present (always, on success). Mirrors the C++.
    pub has_params: bool,
    /// `true` when `params.event_template` was present (always, on success).
    pub has_event_template: bool,
    /// Raw byte range of the `event_template` object inside the request JSON.
    pub event_template_json: (usize, usize),
    /// The parsed event template.
    pub event_template: QrEventTemplate,
    content: [u8; MAX_CONTENT_UTF8_BYTES],
    content_len: usize,
    // Sized by the request-JSON limit, not MAX_TOTAL_TAG_UTF8_BYTES: decoded tag
    // text never exceeds its JSON source, which is bounded to 704 bytes here.
    tag_fields_text: [u8; MAX_DECODED_REQUEST_JSON_BYTES],
    tag_fields_text_len: usize,
    tag_fields: [TagField; MAX_TAG_COUNT * MAX_TAG_FIELDS_PER_TAG],
    tag_field_count: usize,
}

impl QrSigningRequest {
    /// The decoded `request_id`.
    #[must_use]
    pub fn request_id(&self) -> &[u8] {
        &self.request_id[..self.request_id_len]
    }

    /// The method. Only `sign_event` is accepted, so this is constant on success.
    /// Mirrors the C++ `method` field.
    #[must_use]
    pub fn method(&self) -> &'static str {
        "sign_event"
    }

    /// The decoded `content` text (escapes resolved to UTF-8).
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content[..self.content_len]
    }

    /// Iterates the decoded fields of tag `tag` (0-based), in order.
    pub fn tag(&self, tag: usize) -> impl Iterator<Item = &[u8]> {
        self.tag_fields[..self.tag_field_count]
            .iter()
            .filter(move |field| field.tag == tag)
            .map(|field| &self.tag_fields_text[field.start..field.end])
    }
}

/// Strips leading/trailing ASCII whitespace (space, LF, CR, tab). Mirrors the
/// C++ `trim_ascii`.
fn trim_ascii(value: &[u8]) -> &[u8] {
    let is_ws = |b: &u8| matches!(*b, b' ' | b'\n' | b'\r' | b'\t');
    let start = value.iter().position(|b| !is_ws(b));
    match start {
        None => &[],
        Some(start) => {
            let end = value.len() - value.iter().rev().position(|b| !is_ws(b)).unwrap();
            &value[start..end]
        }
    }
}

/// Requires the trimmed payload to be a `{...}` or `[...]` container. Mirrors
/// the C++ `require_json_container`.
fn require_json_container(decoded: &[u8]) -> Result<(), QrEnvelopeError> {
    let trimmed = trim_ascii(decoded);
    if trimmed.len() < 2 {
        return Err(QrEnvelopeError::NotJsonContainer);
    }
    let (first, last) = (trimmed[0], trimmed[trimmed.len() - 1]);
    if !((first == b'{' && last == b'}') || (first == b'[' && last == b']')) {
        return Err(QrEnvelopeError::NotJsonContainer);
    }
    Ok(())
}

/// The shared request-id rule (1..=[`MAX_REQUEST_ID_LENGTH`] bytes of
/// `A-Z a-z 0-9 . _ : -`). Mirrors the C++ `is_request_id`, duplicated verbatim
/// in `qr_envelope.cpp` and `qr_response_display.cpp`; shared here.
pub(crate) fn is_request_id(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > MAX_REQUEST_ID_LENGTH {
        return false;
    }
    value.iter().all(|&b| {
        b.is_ascii_uppercase()
            || b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b'.' | b'_' | b':' | b'-')
    })
}

/// Maps a payload base64url decode failure. Mirrors the C++
/// `decode_qr_payload_base64url` catch clause (trailing bits get their own
/// message; anything else is "must be unpadded base64url"), plus the
/// buffer-size case this port adds.
fn map_payload_decode_error(error: Base64UrlError) -> QrEnvelopeError {
    match error {
        Base64UrlError::InvalidTrailingBits => QrEnvelopeError::InvalidTrailingBits,
        Base64UrlError::InvalidCharacter => QrEnvelopeError::PayloadNotBase64Url,
        Base64UrlError::OutputTooSmall => QrEnvelopeError::OutputTooSmall,
    }
}

/// True iff `value` is exactly `size` lowercase-hex characters. Mirrors the C++
/// `is_lower_hex`.
fn is_lower_hex(value: &[u8], size: usize) -> bool {
    value.len() == size
        && value
            .iter()
            .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parses a positive decimal with no leading zeros. Mirrors the C++
/// `parse_positive_decimal` (which also rejected values overflowing `size_t`).
fn parse_positive_decimal(value: &[u8]) -> Result<usize, QrEnvelopeError> {
    if value.is_empty() || value[0] == b'0' {
        return Err(QrEnvelopeError::AnimatedBadIndexValue);
    }
    let mut parsed = 0usize;
    for &byte in value {
        if !byte.is_ascii_digit() {
            return Err(QrEnvelopeError::AnimatedBadIndexValue);
        }
        parsed = parsed
            .checked_mul(10)
            .and_then(|v| v.checked_add(usize::from(byte - b'0')))
            .ok_or(QrEnvelopeError::AnimatedBadIndexValue)?;
    }
    Ok(parsed)
}

/// Formats `value` as decimal into `buf`, returning the written text.
fn write_decimal(buf: &mut [u8; 20], value: usize) -> &[u8] {
    let mut at = buf.len();
    let mut rest = value;
    loop {
        at -= 1;
        buf[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    &buf[at..]
}

/// One parsed animated frame header, borrowing the frame line. (The chunk text
/// is re-sliced from the raw frame during reassembly, so it is not stored.)
struct AnimatedFrame<'f> {
    digest: &'f [u8],
    index: usize,
    total: usize,
}

/// Parses and validates one animated frame line. Mirrors the C++
/// `parse_animated_qr_frame`, including the validation order (prefix → shape →
/// digest → checksum format → index shape → decimal → range → frame count →
/// chunk alphabet → chunk size → checksum).
fn parse_animated_qr_frame(frame: &[u8]) -> Result<AnimatedFrame<'_>, QrEnvelopeError> {
    let body = frame
        .strip_prefix(ANIMATED_PREFIX)
        .ok_or(QrEnvelopeError::AnimatedMissingPrefix)?;
    // The C++ split the whole frame into five ':'-fields (parts[0] is the
    // prefix text itself); an equivalent split of the post-prefix body must
    // yield exactly four fields.
    let mut parts = [&[][..]; 4];
    let mut count = 0usize;
    for part in body.split(|&b| b == b':') {
        if count == parts.len() {
            return Err(QrEnvelopeError::AnimatedMalformed);
        }
        parts[count] = part;
        count += 1;
    }
    if count != parts.len() {
        return Err(QrEnvelopeError::AnimatedMalformed);
    }
    let [digest, index_total, chunk, checksum] = parts;
    if !is_lower_hex(digest, DIGEST_HEX_LEN) {
        return Err(QrEnvelopeError::AnimatedBadDigest);
    }
    if !is_lower_hex(checksum, CHECKSUM_HEX_LEN) {
        return Err(QrEnvelopeError::AnimatedBadChecksumFormat);
    }
    let slash = index_total
        .iter()
        .position(|&b| b == b'/')
        .ok_or(QrEnvelopeError::AnimatedBadIndexShape)?;
    if index_total[slash + 1..].contains(&b'/') {
        return Err(QrEnvelopeError::AnimatedBadIndexShape);
    }
    let index = parse_positive_decimal(&index_total[..slash])?;
    let total = parse_positive_decimal(&index_total[slash + 1..])?;
    if index > total {
        return Err(QrEnvelopeError::AnimatedIndexOutOfRange);
    }
    if total > MAX_ANIMATED_QR_FRAME_COUNT {
        return Err(QrEnvelopeError::AnimatedTooManyFrames);
    }
    if !is_base64url_payload(chunk) {
        return Err(QrEnvelopeError::AnimatedChunkNotBase64Url);
    }
    if chunk.len() > MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS {
        return Err(QrEnvelopeError::AnimatedChunkTooLong);
    }
    // The checksum pre-image ("nsealr1a:" + digest + ":" + index + "/" + total +
    // ":" + chunk) is exactly the frame minus its ":checksum" suffix, because
    // parse_positive_decimal only accepts the canonical decimal spelling.
    let preimage = &frame[..frame.len() - (CHECKSUM_HEX_LEN + 1)];
    if checksum != &sha256_hex(preimage)[..CHECKSUM_HEX_LEN] {
        return Err(QrEnvelopeError::AnimatedChecksumMismatch);
    }
    Ok(AnimatedFrame {
        digest,
        index,
        total,
    })
}

/// Decodes a static `nsealr1:` envelope. Mirrors the C++ `decode_qr_envelope`.
/// `json_out` receives the decoded JSON (size it with
/// [`MAX_STATIC_QR_DECODED_JSON_BYTES`]).
///
/// # Errors
///
/// See [`QrEnvelopeError`]. The accept/reject *sets* are identical to the C++;
/// the error-variant precedence can differ on multi-fault inputs (this port
/// checks the exact decoded size before decoding, so e.g. an oversized payload
/// with non-canonical trailing bits reports [`QrEnvelopeError::ExceedsStaticJsonBytes`]
/// where the C++ reported the trailing-bits error).
pub fn decode_qr_envelope<'a>(
    envelope: &'a [u8],
    json_out: &'a mut [u8],
) -> Result<QrEnvelope<'a>, QrEnvelopeError> {
    let payload = envelope
        .strip_prefix(PREFIX)
        .ok_or(QrEnvelopeError::MissingPrefix)?;
    if !is_base64url_payload(payload) {
        return Err(QrEnvelopeError::PayloadNotBase64Url);
    }
    if payload.len() % 4 == 1 {
        return Err(QrEnvelopeError::InvalidBase64UrlLength);
    }
    // For unpadded base64url the decoded size is exact, so the size limit can be
    // enforced before decoding (the C++ decoded into a growable string first;
    // same accept/reject set).
    if decoded_len_max(payload.len()) > MAX_STATIC_QR_DECODED_JSON_BYTES {
        return Err(QrEnvelopeError::ExceedsStaticJsonBytes);
    }
    let decoded = decode_base64url(payload, json_out).map_err(map_payload_decode_error)?;
    if !is_valid_utf8(decoded) {
        return Err(QrEnvelopeError::InvalidUtf8);
    }
    require_json_container(decoded)?;
    Ok(QrEnvelope {
        payload_base64url: payload,
        payload_json: decoded,
    })
}

/// Reassembles and decodes an animated `nsealr1a:` frame set. Mirrors the C++
/// `decode_animated_qr_envelope_frames`. `frames` yields each scanned frame line;
/// `payload_out` receives the concatenated base64url payload and `json_out` the
/// decoded JSON (size with `encoded_len(MAX_ANIMATED_QR_DECODED_JSON_BYTES)` and
/// [`MAX_ANIMATED_QR_DECODED_JSON_BYTES`]).
///
/// # Errors
///
/// See [`QrEnvelopeError`]. The accept/reject *sets* are identical to the C++
/// (including the unique-and-contiguous index rule and the whole-payload digest
/// check); the error-variant precedence can differ on multi-fault frame sets
/// (e.g. a wrong frame count combined with a digest mismatch reports
/// [`QrEnvelopeError::AnimatedFrameSetMismatch`] — this port's in-loop mismatch
/// check runs before its count check — where the C++ checked the count first and
/// reported the not-contiguous error; the exact-size guard runs before decoding
/// as in the static path).
pub fn decode_animated_qr_envelope_frames<'a>(
    frames: &[&[u8]],
    payload_out: &'a mut [u8],
    json_out: &'a mut [u8],
) -> Result<QrEnvelope<'a>, QrEnvelopeError> {
    if frames.is_empty() {
        return Err(QrEnvelopeError::NoFrames);
    }
    // First pass: per-frame validation, in input order (C++ parsed every frame
    // into a vector before any set-level check).
    let first = parse_animated_qr_frame(frames[0])?;
    let (digest, total) = (first.digest, first.total);
    // Frame position holding each 1-based index (usize::MAX = not seen yet).
    let mut position_of_index = [usize::MAX; MAX_ANIMATED_QR_FRAME_COUNT];
    for (position, frame) in frames.iter().enumerate() {
        let parsed = parse_animated_qr_frame(frame)?;
        if parsed.digest != digest || parsed.total != total {
            return Err(QrEnvelopeError::AnimatedFrameSetMismatch);
        }
        if position_of_index[parsed.index - 1] != usize::MAX {
            return Err(QrEnvelopeError::AnimatedFramesNotContiguous);
        }
        position_of_index[parsed.index - 1] = position;
    }
    if frames.len() != total {
        return Err(QrEnvelopeError::AnimatedFramesNotContiguous);
    }
    // With exactly `total` distinct indexes in 1..=total, every index is present.
    // Second pass: locate each chunk (between the third ':' and the ":checksum"
    // suffix of its already-validated frame) and run the whole-payload length
    // checks before any copying.
    let chunk_of = |frame: &'_ [u8]| -> core::ops::Range<usize> {
        let chunk_end = frame.len() - (CHECKSUM_HEX_LEN + 1);
        let index_total_end = ANIMATED_PREFIX.len() + DIGEST_HEX_LEN + 1;
        let chunk_start = index_total_end
            + frame[index_total_end..chunk_end]
                .iter()
                .position(|&b| b == b':')
                .expect("frame shape validated above")
            + 1;
        chunk_start..chunk_end
    };
    let total_payload_len: usize = position_of_index[..total]
        .iter()
        .map(|&position| chunk_of(frames[position]).len())
        .sum();
    if total_payload_len % 4 == 1 {
        return Err(QrEnvelopeError::InvalidBase64UrlLength);
    }
    // Exact-size guard before decoding, as in the static path.
    if decoded_len_max(total_payload_len) > MAX_ANIMATED_QR_DECODED_JSON_BYTES {
        return Err(QrEnvelopeError::ExceedsAnimatedJsonBytes);
    }
    if total_payload_len > payload_out.len() {
        return Err(QrEnvelopeError::OutputTooSmall);
    }
    let mut payload_len = 0usize;
    for &position in &position_of_index[..total] {
        let chunk = &frames[position][chunk_of(frames[position])];
        payload_out[payload_len..payload_len + chunk.len()].copy_from_slice(chunk);
        payload_len += chunk.len();
    }
    let payload = &payload_out[..payload_len];
    let decoded = decode_base64url(payload, json_out).map_err(map_payload_decode_error)?;
    if sha256_hex(decoded).as_slice() != digest {
        return Err(QrEnvelopeError::AnimatedDigestMismatch);
    }
    if !is_valid_utf8(decoded) {
        return Err(QrEnvelopeError::InvalidUtf8);
    }
    require_json_container(decoded)?;
    Ok(QrEnvelope {
        payload_base64url: payload,
        payload_json: decoded,
    })
}

/// Encodes `payload_json` as a static `nsealr1:` envelope into `out`, returning
/// the written prefix. Mirrors the C++ `encode_qr_envelope_json`.
///
/// # Errors
///
/// [`QrEnvelopeError::ExceedsStaticJsonBytes`], [`QrEnvelopeError::InvalidUtf8`],
/// [`QrEnvelopeError::NotJsonContainer`], [`QrEnvelopeError::OutputTooSmall`].
pub fn encode_qr_envelope_json<'o>(
    payload_json: &[u8],
    out: &'o mut [u8],
) -> Result<&'o [u8], QrEnvelopeError> {
    if payload_json.len() > MAX_STATIC_QR_DECODED_JSON_BYTES {
        return Err(QrEnvelopeError::ExceedsStaticJsonBytes);
    }
    if !is_valid_utf8(payload_json) {
        return Err(QrEnvelopeError::InvalidUtf8);
    }
    require_json_container(payload_json)?;
    let total = PREFIX.len() + encoded_len(payload_json.len());
    if out.len() < total {
        return Err(QrEnvelopeError::OutputTooSmall);
    }
    out[..PREFIX.len()].copy_from_slice(PREFIX);
    encode_base64url(payload_json, &mut out[PREFIX.len()..total])
        .map_err(map_payload_decode_error)?;
    Ok(&out[..total])
}

/// Encodes `payload_json` as animated `nsealr1a:` frames, invoking `emit` once
/// per frame with (frame bytes, 0-based frame index, total frame count). Mirrors
/// the C++ `encode_animated_qr_envelope_json`, which returned a
/// `std::vector<std::string>`; the callback keeps this port allocation-free.
///
/// # Errors
///
/// See [`QrEnvelopeError`]; parity with the C++ rejection order (chunk size →
/// json size → UTF-8 → container → empty payload → frame count).
pub fn encode_animated_qr_envelope_json(
    payload_json: &[u8],
    chunk_size_chars: usize,
    emit: &mut dyn FnMut(&[u8], usize, usize),
) -> Result<(), QrEnvelopeError> {
    if chunk_size_chars == 0 {
        return Err(QrEnvelopeError::AnimatedChunkSizeZero);
    }
    if chunk_size_chars > MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS {
        return Err(QrEnvelopeError::AnimatedChunkTooLong);
    }
    if payload_json.len() > MAX_ANIMATED_QR_DECODED_JSON_BYTES {
        return Err(QrEnvelopeError::ExceedsAnimatedJsonBytes);
    }
    if !is_valid_utf8(payload_json) {
        return Err(QrEnvelopeError::InvalidUtf8);
    }
    require_json_container(payload_json)?;

    // The C++ heap-allocated the full base64url payload; this port stack-buffers
    // it (5.4 KiB, bounded by the animated JSON limit). The container check above
    // guarantees a non-empty JSON, so the payload is never empty (the C++ had a
    // dead "animated QR payload is empty" guard here; omitted as unreachable).
    let mut payload_buf = [0u8; encoded_len(MAX_ANIMATED_QR_DECODED_JSON_BYTES)];
    let payload =
        encode_base64url(payload_json, &mut payload_buf).map_err(map_payload_decode_error)?;
    let chunk_count = payload.len().div_ceil(chunk_size_chars);
    if chunk_count > MAX_ANIMATED_QR_FRAME_COUNT {
        return Err(QrEnvelopeError::AnimatedTooManyFrames);
    }

    let digest = sha256_hex(payload_json);
    // Frame scratch: prefix + digest + ":index/total:" + chunk + ":" + checksum.
    let mut frame = [0u8; ANIMATED_PREFIX.len()
        + DIGEST_HEX_LEN
        + 1
        + 20
        + 1
        + 20
        + 1
        + MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS
        + 1
        + CHECKSUM_HEX_LEN];
    for (offset, chunk) in payload.chunks(chunk_size_chars).enumerate() {
        let mut at = 0usize;
        let push = |frame: &mut [u8], at: &mut usize, bytes: &[u8]| {
            frame[*at..*at + bytes.len()].copy_from_slice(bytes);
            *at += bytes.len();
        };
        let mut decimal = [0u8; 20];
        push(&mut frame, &mut at, ANIMATED_PREFIX);
        push(&mut frame, &mut at, &digest);
        push(&mut frame, &mut at, b":");
        let index_text_len = write_decimal(&mut decimal, offset + 1).len();
        push(&mut frame, &mut at, &decimal[20 - index_text_len..]);
        push(&mut frame, &mut at, b"/");
        let total_text_len = write_decimal(&mut decimal, chunk_count).len();
        push(&mut frame, &mut at, &decimal[20 - total_text_len..]);
        push(&mut frame, &mut at, b":");
        push(&mut frame, &mut at, chunk);
        // Checksum over everything so far (the pre-image is the frame minus its
        // ":checksum" suffix; see parse_animated_qr_frame).
        let checksum_hex = sha256_hex(&frame[..at]);
        push(&mut frame, &mut at, b":");
        push(&mut frame, &mut at, &checksum_hex[..CHECKSUM_HEX_LEN]);
        emit(&frame[..at], offset, chunk_count);
    }
    Ok(())
}

/// Kinds of JSON values the request scanner distinguishes. Mirrors the C++
/// `JsonValueKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonKind {
    String,
    Number,
    Object,
    Array,
    Literal,
}

/// A scanned member value: its kind and byte span within the scanned slice.
/// Mirrors the C++ `JsonTopLevelValue` (which copied the text; this keeps spans).
#[derive(Clone, Copy)]
struct ValueSpan {
    kind: JsonKind,
    start: usize,
    end: usize,
}

/// Longest known member key is `event_template` (14 bytes); keys that decode
/// longer than this buffer cannot match any known name and are treated as
/// unknown fields.
const MAX_MEMBER_KEY_LEN: usize = 16;

/// The hand-rolled, non-recursive JSON scanner. Mirrors the helper functions in
/// the C++ `qr_envelope.cpp` anonymous namespace (`skip_ws`,
/// `parse_simple_json_string`, `parse_json_number_token`, `skip_json_container`,
/// `parse_json_literal_token`, `parse_json_value_token`,
/// `parse_top_level_object`).
struct Scanner<'j> {
    json: &'j [u8],
    offset: usize,
}

/// Member callback for [`Scanner::for_each_member`]: receives the scanner
/// (positioned at the member value) and the decoded key.
type OnMember<'s, 'j> = dyn FnMut(&mut Scanner<'j>, &[u8]) -> Result<(), QrEnvelopeError> + 's;

impl<'j> Scanner<'j> {
    fn new(json: &'j [u8]) -> Self {
        Self { json, offset: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.json.get(self.offset).copied()
    }

    /// Mirrors the C++ `skip_ws`.
    fn skip_ws(&mut self) {
        while let Some(byte) = self.peek() {
            if !matches!(byte, b' ' | b'\n' | b'\r' | b'\t') {
                return;
            }
            self.offset += 1;
        }
    }

    /// Mirrors the C++ `parse_simple_json_string`; decoded bytes go to `sink`.
    /// All grammar failures (missing quote, bad/truncated escape, bad `\uXXXX`,
    /// control character, unterminated) map to
    /// [`QrEnvelopeError::RequestJsonMalformed`] (distinct messages in the C++).
    fn parse_string(&mut self, sink: &mut dyn FnMut(&[u8])) -> Result<(), QrEnvelopeError> {
        if self.peek() != Some(b'"') {
            return Err(QrEnvelopeError::RequestJsonMalformed);
        }
        self.offset += 1;
        while self.offset < self.json.len() {
            let ch = self.json[self.offset];
            self.offset += 1;
            if ch == b'"' {
                return Ok(());
            }
            if ch == b'\\' {
                let escaped = self.peek().ok_or(QrEnvelopeError::RequestJsonMalformed)?;
                self.offset += 1;
                match escaped {
                    b'"' | b'\\' | b'/' => sink(&[escaped]),
                    b'b' => sink(b"\x08"),
                    b'f' => sink(b"\x0c"),
                    b'n' => sink(b"\n"),
                    b'r' => sink(b"\r"),
                    b't' => sink(b"\t"),
                    b'u' => {
                        let mut utf8 = [0u8; 4];
                        let fragment =
                            append_json_unicode_escape(self.json, &mut self.offset, &mut utf8)
                                .map_err(|_: UnicodeError| QrEnvelopeError::RequestJsonMalformed)?;
                        sink(fragment);
                    }
                    _ => return Err(QrEnvelopeError::RequestJsonMalformed),
                }
                continue;
            }
            if ch < 0x20 {
                return Err(QrEnvelopeError::RequestJsonMalformed);
            }
            sink(&[ch]);
        }
        Err(QrEnvelopeError::RequestJsonMalformed)
    }

    /// Mirrors the C++ `parse_json_number_token`: integer-only (`-?[0-9]+`).
    fn parse_number_token(&mut self) -> Result<(usize, usize), QrEnvelopeError> {
        let start = self.offset;
        if self.peek() == Some(b'-') {
            self.offset += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.offset += 1;
        }
        if self.offset == start || (self.offset == start + 1 && self.json[start] == b'-') {
            return Err(QrEnvelopeError::RequestJsonMalformed);
        }
        Ok((start, self.offset))
    }

    /// Mirrors the C++ `skip_json_container`: depth-counts only the given
    /// open/close pair, skipping (and escape-validating) strings; the interior
    /// grammar is otherwise not validated. The caller guarantees the scanner
    /// sits on `open` (the C++ re-checked it; dead branch, omitted).
    fn skip_container(&mut self, open: u8, close: u8) -> Result<(), QrEnvelopeError> {
        let mut depth = 0usize;
        while self.offset < self.json.len() {
            let ch = self.json[self.offset];
            if ch == b'"' {
                self.parse_string(&mut |_| {})?;
                continue;
            }
            if ch == open {
                depth += 1;
            } else if ch == close {
                depth -= 1;
                self.offset += 1;
                if depth == 0 {
                    return Ok(());
                }
                continue;
            }
            self.offset += 1;
        }
        Err(QrEnvelopeError::RequestJsonMalformed)
    }

    /// Mirrors the C++ `parse_json_literal_token` (`true`/`false`/`null`).
    fn parse_literal(&mut self) -> Result<(), QrEnvelopeError> {
        for literal in [&b"true"[..], b"false", b"null"] {
            if self.json[self.offset..].starts_with(literal) {
                self.offset += literal.len();
                return Ok(());
            }
        }
        Err(QrEnvelopeError::RequestJsonMalformed)
    }

    /// Mirrors the C++ `parse_json_value_token`; string content goes to `sink`.
    fn parse_value(&mut self, sink: &mut dyn FnMut(&[u8])) -> Result<ValueSpan, QrEnvelopeError> {
        self.skip_ws();
        let Some(ch) = self.peek() else {
            return Err(QrEnvelopeError::RequestJsonMalformed);
        };
        let start = self.offset;
        let kind = match ch {
            b'"' => {
                self.parse_string(sink)?;
                JsonKind::String
            }
            b'{' => {
                self.skip_container(b'{', b'}')?;
                JsonKind::Object
            }
            b'[' => {
                self.skip_container(b'[', b']')?;
                JsonKind::Array
            }
            b'0'..=b'9' | b'-' => {
                self.parse_number_token()?;
                JsonKind::Number
            }
            _ => {
                self.parse_literal()?;
                JsonKind::Literal
            }
        };
        Ok(ValueSpan {
            kind,
            start,
            end: self.offset,
        })
    }

    /// Walks a JSON object member by member, mirroring the C++
    /// `parse_top_level_object` loop structure exactly (including its lenient
    /// acceptance of a trailing comma at end of input). `on_member` receives the
    /// scanner (positioned at the value) and the decoded key (truncated to
    /// [`MAX_MEMBER_KEY_LEN`] — no known key is that long, so a truncated key
    /// simply matches nothing).
    fn for_each_member(&mut self, on_member: &mut OnMember<'_, 'j>) -> Result<(), QrEnvelopeError> {
        self.skip_ws();
        if self.peek() != Some(b'{') {
            return Err(QrEnvelopeError::RequestNotObject);
        }
        self.offset += 1;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.offset += 1;
        } else {
            while self.offset < self.json.len() {
                self.skip_ws();
                let mut key = [0u8; MAX_MEMBER_KEY_LEN];
                let mut key_len = 0usize;
                self.parse_string(&mut |fragment| {
                    for &byte in fragment {
                        if key_len < key.len() {
                            key[key_len] = byte;
                        }
                        key_len += 1;
                    }
                })?;
                self.skip_ws();
                if self.peek() != Some(b':') {
                    return Err(QrEnvelopeError::RequestJsonMalformed);
                }
                self.offset += 1;
                on_member(self, &key[..key_len.min(key.len())])?;
                self.skip_ws();
                match self.peek() {
                    Some(b',') => {
                        self.offset += 1;
                        continue;
                    }
                    Some(b'}') => {
                        self.offset += 1;
                        break;
                    }
                    _ => return Err(QrEnvelopeError::RequestJsonMalformed),
                }
            }
        }
        self.skip_ws();
        if self.offset != self.json.len() {
            return Err(QrEnvelopeError::RequestJsonMalformed);
        }
        Ok(())
    }
}

/// Parses a canonical unsigned decimal within the JSON safe-integer range.
/// Mirrors the C++ `parse_unsigned_decimal`; `field_error` is the per-field
/// variant (the C++ took the field name for its message).
fn parse_unsigned_decimal(
    token: &[u8],
    field_error: QrEnvelopeError,
) -> Result<u64, QrEnvelopeError> {
    if token.is_empty() || token[0] == b'-' {
        return Err(field_error);
    }
    let mut value = 0u64;
    for &byte in token {
        if !byte.is_ascii_digit() {
            return Err(field_error);
        }
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(byte - b'0')))
            .ok_or(field_error)?;
    }
    if value > MAX_SAFE_INTEGER {
        return Err(field_error);
    }
    Ok(value)
}

/// Parses the `tags` array span into `request`, mirroring the C++
/// `parse_tags_array`: every element must be an array of strings, each decoded
/// field at most [`MAX_TAG_FIELD_UTF8_BYTES`] bytes, at most
/// [`MAX_TAG_FIELDS_PER_TAG`] fields per tag and [`MAX_TAG_COUNT`] tags.
///
/// The span is the exact `[...]` container text (guaranteed by the caller's
/// kind check), so the C++ leading-`[` and trailing-data guards are unreachable
/// and omitted. The C++ `max_total_tag_utf8_bytes` sweep is likewise
/// unreachable here: decoded text never exceeds its JSON source, which the
/// request guard bounds to [`MAX_DECODED_REQUEST_JSON_BYTES`] (704) — far below
/// the 4096-byte tag-total limit — so that dead check is omitted too.
fn parse_tags_array(
    tags_json: &[u8],
    request: &mut QrSigningRequest,
) -> Result<usize, QrEnvelopeError> {
    let mut scanner = Scanner::new(tags_json);
    scanner.offset = 1; // Past the '[' the kind check guarantees.
    let mut tag_count = 0usize;
    scanner.skip_ws();
    if scanner.peek() == Some(b']') {
        // Empty tags array. (The C++ advanced past the ']' for its trailing-data
        // check; that check is unreachable on this exact span and omitted.)
    } else {
        while scanner.offset < tags_json.len() {
            scanner.skip_ws();
            if scanner.peek() != Some(b'[') {
                return Err(QrEnvelopeError::RequestBadTags);
            }
            scanner.offset += 1;
            let mut fields_in_tag = 0usize;
            scanner.skip_ws();
            if scanner.peek() == Some(b']') {
                scanner.offset += 1;
            } else {
                while scanner.offset < tags_json.len() {
                    scanner.skip_ws();
                    let field_start = request.tag_fields_text_len;
                    let mut decoded = 0usize;
                    {
                        let text = &mut request.tag_fields_text;
                        scanner.parse_string(&mut |fragment| {
                            for &byte in fragment {
                                // In-bounds by construction: stored bytes plus
                                // this field's decoded bytes never exceed the
                                // total decoded tag text, which is strictly
                                // smaller than its (<= 704-byte) JSON source.
                                text[field_start + decoded] = byte;
                                decoded += 1;
                            }
                        })?;
                    }
                    if decoded > MAX_TAG_FIELD_UTF8_BYTES {
                        return Err(QrEnvelopeError::TagFieldTooLong);
                    }
                    // Store the field if it is within both capacity limits; the
                    // C++ enforced those limits only after the tag closed, so
                    // over-limit fields are counted (for the later checks) but
                    // not stored. Decoded text is always shorter than its JSON
                    // source (quotes and escapes only shrink), so the packed
                    // buffer, sized MAX_DECODED_REQUEST_JSON_BYTES, never fills.
                    if fields_in_tag < MAX_TAG_FIELDS_PER_TAG && tag_count < MAX_TAG_COUNT {
                        request.tag_fields[request.tag_field_count] = TagField {
                            tag: tag_count,
                            start: field_start,
                            end: field_start + decoded,
                        };
                        request.tag_field_count += 1;
                        request.tag_fields_text_len = field_start + decoded;
                    }
                    fields_in_tag += 1;
                    scanner.skip_ws();
                    match scanner.peek() {
                        Some(b',') => {
                            scanner.offset += 1;
                            continue;
                        }
                        Some(b']') => {
                            scanner.offset += 1;
                            break;
                        }
                        _ => return Err(QrEnvelopeError::RequestBadTags),
                    }
                }
            }
            if fields_in_tag > MAX_TAG_FIELDS_PER_TAG {
                return Err(QrEnvelopeError::TooManyTagFields);
            }
            tag_count += 1;
            if tag_count > MAX_TAG_COUNT {
                return Err(QrEnvelopeError::TooManyTags);
            }
            scanner.skip_ws();
            match scanner.peek() {
                Some(b',') => {
                    scanner.offset += 1;
                    continue;
                }
                // Closing ']' of the whole array; nothing follows on this exact
                // span (see the trailing-data note above).
                Some(b']') => break,
                _ => return Err(QrEnvelopeError::RequestBadTags),
            }
        }
    }
    Ok(tag_count)
}

/// Parses a decoded envelope's JSON as a sign-event signing request. Mirrors the
/// C++ `parse_qr_signing_request` (which took a `QrEnvelope`; only the JSON is
/// read, so this port takes the JSON bytes directly).
///
/// # Errors
///
/// See [`QrEnvelopeError`]; full parity with the C++ field/tolerance rules and
/// check order (size guard → grammar → unknown field → version → request_id →
/// method → params → params unknown → event_template → forbidden → unknown →
/// required kinds → content size → kind value → created_at value → tags array).
pub fn parse_qr_signing_request(payload_json: &[u8]) -> Result<QrSigningRequest, QrEnvelopeError> {
    if payload_json.len() > MAX_DECODED_REQUEST_JSON_BYTES {
        return Err(QrEnvelopeError::ExceedsRequestJsonBytes);
    }

    // --- Top level ---
    let mut unknown = false;
    let mut version_val: Option<ValueSpan> = None;
    let mut rid_buf = [0u8; MAX_REQUEST_ID_LENGTH];
    let mut rid: Option<(JsonKind, usize, bool)> = None; // kind, decoded len, overflow
    let mut method_val: Option<(JsonKind, bool)> = None; // kind, equals "sign_event"
    let mut params_val: Option<ValueSpan> = None;
    let mut scanner = Scanner::new(payload_json);
    scanner.for_each_member(&mut |sc, key| {
        match key {
            b"version" => version_val = Some(sc.parse_value(&mut |_| {})?),
            b"request_id" => {
                let mut len = 0usize;
                let mut overflow = false;
                let span = sc.parse_value(&mut |fragment| {
                    for &byte in fragment {
                        if len < rid_buf.len() {
                            rid_buf[len] = byte;
                            len += 1;
                        } else {
                            overflow = true;
                        }
                    }
                })?;
                rid = Some((span.kind, len, overflow));
            }
            b"method" => {
                let mut buf = [0u8; 16];
                let mut len = 0usize;
                let span = sc.parse_value(&mut |fragment| {
                    for &byte in fragment {
                        if len < buf.len() {
                            buf[len] = byte;
                        }
                        len += 1;
                    }
                })?;
                method_val = Some((span.kind, &buf[..len.min(buf.len())] == b"sign_event"));
            }
            b"params" => params_val = Some(sc.parse_value(&mut |_| {})?),
            _ => {
                unknown = true;
                sc.parse_value(&mut |_| {})?;
            }
        }
        Ok(())
    })?;
    if unknown {
        return Err(QrEnvelopeError::RequestUnknownField);
    }
    let version_ok = version_val.is_some_and(|value| {
        value.kind == JsonKind::Number && &payload_json[value.start..value.end] == b"1"
    });
    if !version_ok {
        return Err(QrEnvelopeError::RequestBadVersion);
    }
    let (rid_kind, rid_len, rid_overflow) = rid.ok_or(QrEnvelopeError::RequestBadRequestId)?;
    if rid_kind != JsonKind::String || rid_overflow || !is_request_id(&rid_buf[..rid_len]) {
        return Err(QrEnvelopeError::RequestBadRequestId);
    }
    let method_ok = method_val.is_some_and(|(kind, matches)| kind == JsonKind::String && matches);
    if !method_ok {
        return Err(QrEnvelopeError::RequestBadMethod);
    }
    let params = params_val.ok_or(QrEnvelopeError::RequestParamsRequired)?;
    if params.kind != JsonKind::Object {
        return Err(QrEnvelopeError::RequestParamsRequired);
    }

    // --- params ---
    let mut params_unknown = false;
    let mut template_val: Option<ValueSpan> = None;
    let mut params_scanner = Scanner::new(&payload_json[params.start..params.end]);
    params_scanner.for_each_member(&mut |sc, key| {
        if key == b"event_template" {
            template_val = Some(sc.parse_value(&mut |_| {})?);
        } else {
            params_unknown = true;
            sc.parse_value(&mut |_| {})?;
        }
        Ok(())
    })?;
    if params_unknown {
        return Err(QrEnvelopeError::RequestParamsUnknownField);
    }
    let template = template_val.ok_or(QrEnvelopeError::RequestEventTemplateRequired)?;
    if template.kind != JsonKind::Object {
        return Err(QrEnvelopeError::RequestEventTemplateRequired);
    }
    let template_abs = (params.start + template.start, params.start + template.end);

    // --- event_template ---
    let template_json = &payload_json[template_abs.0..template_abs.1];
    let mut forbidden = false;
    let mut template_unknown = false;
    let mut created_at_val: Option<ValueSpan> = None;
    let mut kind_val: Option<ValueSpan> = None;
    let mut tags_val: Option<ValueSpan> = None;
    let mut content_buf = [0u8; MAX_CONTENT_UTF8_BYTES];
    let mut content_state: Option<(JsonKind, usize)> = None; // kind, decoded len
    let mut template_scanner = Scanner::new(template_json);
    template_scanner.for_each_member(&mut |sc, key| {
        match key {
            b"id" | b"pubkey" | b"sig" => {
                forbidden = true;
                sc.parse_value(&mut |_| {})?;
            }
            b"created_at" => created_at_val = Some(sc.parse_value(&mut |_| {})?),
            b"kind" => kind_val = Some(sc.parse_value(&mut |_| {})?),
            b"tags" => tags_val = Some(sc.parse_value(&mut |_| {})?),
            b"content" => {
                let mut len = 0usize;
                let span = sc.parse_value(&mut |fragment| {
                    for &byte in fragment {
                        if len < content_buf.len() {
                            content_buf[len] = byte;
                        }
                        len += 1;
                    }
                })?;
                content_state = Some((span.kind, len));
            }
            _ => {
                template_unknown = true;
                sc.parse_value(&mut |_| {})?;
            }
        }
        Ok(())
    })?;
    if forbidden {
        return Err(QrEnvelopeError::RequestEventTemplateForbiddenField);
    }
    if template_unknown {
        return Err(QrEnvelopeError::RequestEventTemplateUnknownField);
    }
    let created_at = created_at_val
        .filter(|value| value.kind == JsonKind::Number)
        .ok_or(QrEnvelopeError::RequestBadCreatedAt)?;
    let kind = kind_val
        .filter(|value| value.kind == JsonKind::Number)
        .ok_or(QrEnvelopeError::RequestBadKind)?;
    let tags = tags_val
        .filter(|value| value.kind == JsonKind::Array)
        .ok_or(QrEnvelopeError::RequestBadTags)?;
    let (content_kind, content_len) = content_state.ok_or(QrEnvelopeError::RequestBadContent)?;
    if content_kind != JsonKind::String {
        return Err(QrEnvelopeError::RequestBadContent);
    }
    if content_len > MAX_CONTENT_UTF8_BYTES {
        return Err(QrEnvelopeError::ContentTooLong);
    }
    let kind_value = parse_unsigned_decimal(
        &template_json[kind.start..kind.end],
        QrEnvelopeError::RequestBadKind,
    )?;
    if kind_value > i32::MAX as u64 {
        return Err(QrEnvelopeError::RequestBadKind);
    }
    let created_at_value = parse_unsigned_decimal(
        &template_json[created_at.start..created_at.end],
        QrEnvelopeError::RequestBadCreatedAt,
    )?;
    let tags_abs = (template_abs.0 + tags.start, template_abs.0 + tags.end);

    let mut request = QrSigningRequest {
        version: 1,
        request_id: rid_buf,
        request_id_len: rid_len,
        has_params: true,
        has_event_template: true,
        event_template_json: template_abs,
        event_template: QrEventTemplate {
            created_at: created_at_value,
            kind: kind_value as i32,
            tags_json: tags_abs,
            tag_count: 0,
        },
        content: content_buf,
        content_len,
        tag_fields_text: [0; MAX_DECODED_REQUEST_JSON_BYTES],
        tag_fields_text_len: 0,
        tag_fields: [TagField {
            tag: 0,
            start: 0,
            end: 0,
        }; MAX_TAG_COUNT * MAX_TAG_FIELDS_PER_TAG],
        tag_field_count: 0,
    };
    request.event_template.tag_count =
        parse_tags_array(&payload_json[tags_abs.0..tags_abs.1], &mut request)?;
    Ok(request)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::qr::limits::{
        MAX_QR_RESPONSE_DISPLAY_CYCLES, MAX_SERIAL_FRAME_BYTES, MAX_TOTAL_TAG_UTF8_BYTES,
    };
    use std::string::String;
    use std::vec::Vec;

    // Byte-for-byte fixtures copied from
    // specs/vectors/transports/qr-envelope-kind-1-basic.json (`envelope`,
    // `payload_base64url`).
    pub(crate) const KIND1_BASIC_ENVELOPE: &[u8] = b"nsealr1:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm1ldGhvZCI6InNpZ25fZXZlbnQiLCJwYXJhbXMiOnsiZXZlbnRfdGVtcGxhdGUiOnsiY3JlYXRlZF9hdCI6MTcxMDAwMDAwMCwia2luZCI6MSwidGFncyI6W10sImNvbnRlbnQiOiJuU2VhbHIgZml4dHVyZTogYmFzaWMga2luZCAxIGV2ZW50LiJ9fX0";
    const KIND1_BASIC_PAYLOAD: &[u8] = b"eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm1ldGhvZCI6InNpZ25fZXZlbnQiLCJwYXJhbXMiOnsiZXZlbnRfdGVtcGxhdGUiOnsiY3JlYXRlZF9hdCI6MTcxMDAwMDAwMCwia2luZCI6MSwidGFncyI6W10sImNvbnRlbnQiOiJuU2VhbHIgZml4dHVyZTogYmFzaWMga2luZCAxIGV2ZW50LiJ9fX0";

    // Byte-for-byte fixture copied from
    // specs/vectors/transports/qr-envelope-kind-1-long-events-many-tags.json
    // (`envelope`): a maximal valid request (nine tags, 281-byte content).
    const KIND1_LONG_MANY_TAGS_ENVELOPE: &[u8] = b"nsealr1:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1sb25nLWV2ZW50cy1tYW55LXRhZ3MiLCJtZXRob2QiOiJzaWduX2V2ZW50IiwicGFyYW1zIjp7ImV2ZW50X3RlbXBsYXRlIjp7ImNyZWF0ZWRfYXQiOjE3MTAwMDAxMjAsImtpbmQiOjEsInRhZ3MiOltbImUiLCJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwiIiwicm9vdCJdLFsidCIsIm5zZWFsciJdLFsidCIsImhhcmR3YXJlIl0sWyJ0IiwicmV2aWV3Il0sWyJ0Iiwic2VjdXJpdHkiXSxbInQiLCJxciJdLFsidCIsInZhdWx0Il0sWyJ0IiwiY29tcGFuaW9uIl0sWyJ0IiwidGVzdCJdXSwiY29udGVudCI6Inh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4In19fQ";

    // Animated fixture copied from
    // specs/vectors/transports/qr-animated-response-kind-1-basic.json (`frames`,
    // `payload_base64url`; ANIMATED_JSON is the same fixture's `decoded` in the
    // canonical serialization pinned by the C++ kAnimatedQrResponseKind1BasicJson).
    pub(crate) const ANIMATED_FRAME_1: &[u8] = b"nsealr1a:e4ed45466ba40f9e902bf988eb5aab58082b17586b0da47f45f67ce0a4211ec3:1/3:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm9rIjp0cnVlLCJyZXN1bHQiOnsiZXZlbnQiOnsiaWQiOiIyOTc3ZjEwN2FkMjY2OGRiZDlmMDliODU5NGVmZjNiNTI3NmUyMWJmZTA5OGU2MGFlM2U5MDVlM2M4NjFlNGQzIiwicHVia2V5IjoiNGYzNTViZGNiN2NjMGFmNzI4ZWYzY2NlYjk2MTVkOTA2ODRi:1fa03ed6e4432e25";
    pub(crate) const ANIMATED_FRAME_2: &[u8] = b"nsealr1a:e4ed45466ba40f9e902bf988eb5aab58082b17586b0da47f45f67ce0a4211ec3:2/3:YjViMmNhNWY4NTlhYjBmMGI3MDQwNzU4NzFhYSIsImNyZWF0ZWRfYXQiOjE3MTAwMDAwMDAsImtpbmQiOjEsInRhZ3MiOltdLCJjb250ZW50IjoiblNlYWxyIGZpeHR1cmU6IGJhc2ljIGtpbmQgMSBldmVudC4iLCJzaWciOiIyZWVjMDM1MWViMWQ2NTExNDA5MjJkNGIxZjFiZDgxMzVmNDQ3NGFhYmY0MmVjNWJkYTcwMTEwODdjMWEwNzJk:88908749e68c83f7";
    pub(crate) const ANIMATED_FRAME_3: &[u8] = b"nsealr1a:e4ed45466ba40f9e902bf988eb5aab58082b17586b0da47f45f67ce0a4211ec3:3/3:NzFiZTg2MzY0NmRjMTYyZTRkOTZlYWNmMTRhZmVlZDI2MThhNGFjYjBlMTEzNGEyNzNhMmI4ZTczMDM5ZTY1NCJ9fX0:95d312093442c4d6";
    pub(crate) const ANIMATED_PAYLOAD: &[u8] = b"eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm9rIjp0cnVlLCJyZXN1bHQiOnsiZXZlbnQiOnsiaWQiOiIyOTc3ZjEwN2FkMjY2OGRiZDlmMDliODU5NGVmZjNiNTI3NmUyMWJmZTA5OGU2MGFlM2U5MDVlM2M4NjFlNGQzIiwicHVia2V5IjoiNGYzNTViZGNiN2NjMGFmNzI4ZWYzY2NlYjk2MTVkOTA2ODRiYjViMmNhNWY4NTlhYjBmMGI3MDQwNzU4NzFhYSIsImNyZWF0ZWRfYXQiOjE3MTAwMDAwMDAsImtpbmQiOjEsInRhZ3MiOltdLCJjb250ZW50IjoiblNlYWxyIGZpeHR1cmU6IGJhc2ljIGtpbmQgMSBldmVudC4iLCJzaWciOiIyZWVjMDM1MWViMWQ2NTExNDA5MjJkNGIxZjFiZDgxMzVmNDQ3NGFhYmY0MmVjNWJkYTcwMTEwODdjMWEwNzJkNzFiZTg2MzY0NmRjMTYyZTRkOTZlYWNmMTRhZmVlZDI2MThhNGFjYjBlMTEzNGEyNzNhMmI4ZTczMDM5ZTY1NCJ9fX0";
    pub(crate) const ANIMATED_JSON: &[u8] = br#"{"version":1,"request_id":"req-kind-1-basic","ok":true,"result":{"event":{"id":"2977f107ad2668dbd9f09b8594eff3b5276e21bfe098e60ae3e905e3c861e4d3","pubkey":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","created_at":1710000000,"kind":1,"tags":[],"content":"nSealr fixture: basic kind 1 event.","sig":"2eec0351eb1d651140922d4b1f1bd8135f4474aabf42ec5bda7011087c1a072d71be863646dc162e4d96eacf14afeed2618a4acb0e1134a273a2b8e73039e654"}}}"#;

    // Shared-invalid QR-envelope fixtures copied from specs/vectors/invalid/
    // qr-envelope-{padded,malformed,invalid-utf8}.json (`envelope`); the oversized
    // fixture (qr-envelope-oversized.json) is `nsealr1:` + 940 'A's (948 bytes),
    // rebuilt programmatically below, byte-identical to the fixture.
    const INVALID_PADDED: &[u8] = b"nsealr1:eyJ2ZXJzaW9uIjoxfQ==";
    const INVALID_MALFORMED: &[u8] = b"nsealr:abc";
    const INVALID_UTF8: &[u8] = b"nsealr1:_w";

    fn oversized_envelope() -> Vec<u8> {
        let mut envelope = Vec::from(PREFIX);
        envelope.extend(core::iter::repeat_n(b'A', 940));
        assert_eq!(envelope.len(), 948); // matches the fixture byte count
        envelope
    }

    pub(crate) fn decode_static(envelope: &[u8]) -> Result<(Vec<u8>, Vec<u8>), QrEnvelopeError> {
        let mut json = [0u8; MAX_STATIC_QR_DECODED_JSON_BYTES];
        let decoded = decode_qr_envelope(envelope, &mut json)?;
        Ok((
            Vec::from(decoded.payload_base64url),
            Vec::from(decoded.payload_json),
        ))
    }

    pub(crate) fn decode_animated(frames: &[&[u8]]) -> Result<(Vec<u8>, Vec<u8>), QrEnvelopeError> {
        let mut payload = [0u8; encoded_len(MAX_ANIMATED_QR_DECODED_JSON_BYTES)];
        let mut json = [0u8; MAX_ANIMATED_QR_DECODED_JSON_BYTES];
        let decoded = decode_animated_qr_envelope_frames(frames, &mut payload, &mut json)?;
        Ok((
            Vec::from(decoded.payload_base64url),
            Vec::from(decoded.payload_json),
        ))
    }

    pub(crate) fn encode_animated_to_vec(
        payload_json: &[u8],
        chunk_size_chars: usize,
    ) -> Result<Vec<Vec<u8>>, QrEnvelopeError> {
        let mut frames = Vec::new();
        encode_animated_qr_envelope_json(payload_json, chunk_size_chars, &mut |frame, _, _| {
            frames.push(Vec::from(frame));
        })?;
        Ok(frames)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Builds a syntactically valid animated frame (correct per-frame checksum)
    /// from a digest field, an `index/total` text, and a chunk.
    fn build_frame(digest: &[u8], index_total: &[u8], chunk: &[u8]) -> Vec<u8> {
        let mut preimage = Vec::from(ANIMATED_PREFIX);
        preimage.extend_from_slice(digest);
        preimage.push(b':');
        preimage.extend_from_slice(index_total);
        preimage.push(b':');
        preimage.extend_from_slice(chunk);
        let hex = sha256_hex(&preimage);
        let mut frame = preimage;
        frame.push(b':');
        frame.extend_from_slice(&hex[..CHECKSUM_HEX_LEN]);
        frame
    }

    // C++ test_qr_envelope_decodes_shared_vector.
    #[test]
    fn qr_envelope_decodes_shared_vector() {
        let (payload, json) = decode_static(KIND1_BASIC_ENVELOPE).unwrap();
        assert_eq!(payload, KIND1_BASIC_PAYLOAD);
        assert!(contains(&json, br#""request_id":"req-kind-1-basic""#));
        assert!(contains(&json, br#""method":"sign_event""#));
    }

    // C++ test_animated_qr_envelope_decodes_shared_vector.
    #[test]
    fn animated_qr_envelope_decodes_shared_vector() {
        let (payload, json) =
            decode_animated(&[ANIMATED_FRAME_1, ANIMATED_FRAME_2, ANIMATED_FRAME_3]).unwrap();
        assert_eq!(payload, ANIMATED_PAYLOAD);
        assert_eq!(json, ANIMATED_JSON);
    }

    // C++ test_qr_envelope_encodes_signed_response_vectors_without_signing.
    #[test]
    fn qr_envelope_encodes_signed_response_vectors_without_signing() {
        let mut buf = [0u8; PREFIX.len() + encoded_len(MAX_ANIMATED_QR_DECODED_JSON_BYTES)];
        let static_envelope = encode_qr_envelope_json(ANIMATED_JSON, &mut buf).unwrap();
        let mut expected = Vec::from(PREFIX);
        expected.extend_from_slice(ANIMATED_PAYLOAD);
        assert_eq!(static_envelope, expected);

        let frames =
            encode_animated_to_vec(ANIMATED_JSON, MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS).unwrap();
        assert_eq!(
            frames,
            [
                Vec::from(ANIMATED_FRAME_1),
                Vec::from(ANIMATED_FRAME_2),
                Vec::from(ANIMATED_FRAME_3)
            ],
        );

        let static_envelope = Vec::from(static_envelope);
        let (_, json) = decode_static(&static_envelope).unwrap();
        assert_eq!(json, ANIMATED_JSON);
        let (_, json) =
            decode_animated(&frames.iter().map(Vec::as_slice).collect::<Vec<_>>()).unwrap();
        assert_eq!(json, ANIMATED_JSON);
    }

    // C++ test_qr_envelope_parses_sign_event_request_metadata.
    #[test]
    fn qr_envelope_parses_sign_event_request_metadata() {
        let (_, json) = decode_static(KIND1_BASIC_ENVELOPE).unwrap();
        let request = parse_qr_signing_request(&json).unwrap();
        assert_eq!(request.version, 1);
        assert_eq!(request.request_id(), b"req-kind-1-basic");
        assert_eq!(request.method(), "sign_event");
        assert!(request.has_params);
    }

    // C++ test_qr_envelope_extracts_event_template_boundary.
    #[test]
    fn qr_envelope_extracts_event_template_boundary() {
        let (_, json) = decode_static(KIND1_BASIC_ENVELOPE).unwrap();
        let request = parse_qr_signing_request(&json).unwrap();
        assert!(request.has_event_template);
        let (start, end) = request.event_template_json;
        let template = &json[start..end];
        assert!(contains(template, br#""kind":1"#));
        assert!(contains(
            template,
            br#""content":"nSealr fixture: basic kind 1 event.""#
        ));
    }

    // C++ test_qr_envelope_parses_event_template_fields.
    #[test]
    fn qr_envelope_parses_event_template_fields() {
        let (_, json) = decode_static(KIND1_BASIC_ENVELOPE).unwrap();
        let request = parse_qr_signing_request(&json).unwrap();
        assert_eq!(request.event_template.created_at, 1_710_000_000);
        assert_eq!(request.event_template.kind, 1);
        assert_eq!(request.content(), b"nSealr fixture: basic kind 1 event.");
        let (start, end) = request.event_template.tags_json;
        assert_eq!(&json[start..end], b"[]");
    }

    // C++ test_qr_signing_request_tolerates_escaped_event_content.
    #[test]
    fn qr_signing_request_tolerates_escaped_event_content() {
        let json = br#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"Quote: \"nostr\"\nNext line"}}}"#;
        let request = parse_qr_signing_request(json).unwrap();
        assert!(request.has_event_template);
        assert_eq!(request.content(), b"Quote: \"nostr\"\nNext line");
        let (start, end) = request.event_template_json;
        assert!(contains(
            &json[start..end],
            br#""content":"Quote: \"nostr\"\nNext line""#,
        ));
    }

    // C++ test_qr_signing_request_preserves_json_unicode_escapes (the
    // request-level assertions; the review-pages half of the C++ case drives
    // qr_review.cpp, which is M-T3.6 surface — deferred to that milestone).
    #[test]
    fn qr_signing_request_preserves_json_unicode_escapes() {
        // The C++ fed a raw string, so the JSON carries the *escape sequences*
        // (backslash-u00e8, backslash-uD83D backslash-uDE00) literally; the
        // parser decodes them to UTF-8.
        let json = br#"{"version":1,"request_id":"req-unicode-escapes","method":"sign_event","params":{"event_template":{"created_at":1710000400,"kind":1,"tags":[["t","caf\u00e8"],["emoji","\uD83D\uDE00"]],"content":"caf\u00e8 \uD83D\uDE00"}}}"#;
        let request = parse_qr_signing_request(json).unwrap();
        assert_eq!(request.content(), "caf\u{e8} \u{1f600}".as_bytes());
        assert_eq!(request.event_template.tag_count, 2);
        let tag0: Vec<&[u8]> = request.tag(0).collect();
        assert_eq!(tag0, [&b"t"[..], "caf\u{e8}".as_bytes()]);
        let tag1: Vec<&[u8]> = request.tag(1).collect();
        assert_eq!(tag1, [&b"emoji"[..], "\u{1f600}".as_bytes()]);
    }

    // C++ test_qr_envelope_rejections.
    #[test]
    fn qr_envelope_rejections() {
        assert_eq!(
            decode_static(b"nostr:abc").unwrap_err(),
            QrEnvelopeError::MissingPrefix,
        );
        assert_eq!(
            decode_static(b"nsealr1:abc=").unwrap_err(),
            QrEnvelopeError::PayloadNotBase64Url,
        );
        assert_eq!(
            decode_static(b"nsealr1:not+base64url").unwrap_err(),
            QrEnvelopeError::PayloadNotBase64Url,
        );
        assert_eq!(
            decode_static(b"nsealr1:A").unwrap_err(),
            QrEnvelopeError::InvalidBase64UrlLength,
        );
        assert_eq!(
            decode_static(b"nsealr1:bm90LWpzb24").unwrap_err(),
            QrEnvelopeError::NotJsonContainer,
        );
    }

    // C++ test_qr_envelope_rejects_shared_invalid_qr_vectors.
    #[test]
    fn qr_envelope_rejects_shared_invalid_qr_vectors() {
        assert_eq!(
            decode_static(&oversized_envelope()).unwrap_err(),
            QrEnvelopeError::ExceedsStaticJsonBytes,
        );
        assert_eq!(
            decode_static(INVALID_PADDED).unwrap_err(),
            QrEnvelopeError::PayloadNotBase64Url,
        );
        assert_eq!(
            decode_static(INVALID_MALFORMED).unwrap_err(),
            QrEnvelopeError::MissingPrefix,
        );
        assert_eq!(
            decode_static(INVALID_UTF8).unwrap_err(),
            QrEnvelopeError::InvalidUtf8,
        );
    }

    // C++ test_animated_qr_envelope_rejections.
    #[test]
    fn animated_qr_envelope_rejections() {
        assert_eq!(decode_animated(&[]).unwrap_err(), QrEnvelopeError::NoFrames);
        assert_eq!(
            decode_animated(&[ANIMATED_FRAME_2, ANIMATED_FRAME_3]).unwrap_err(),
            QrEnvelopeError::AnimatedFramesNotContiguous,
        );
        let mut tampered = Vec::from(ANIMATED_FRAME_1);
        let last = tampered.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        assert_eq!(
            decode_animated(&[tampered.as_slice(), ANIMATED_FRAME_2, ANIMATED_FRAME_3])
                .unwrap_err(),
            QrEnvelopeError::AnimatedChecksumMismatch,
        );
        let frame: &[u8] = b"nsealr1a:0000000000000000000000000000000000000000000000000000000000000000:1/65:AA:0000000000000000";
        assert_eq!(
            decode_animated(&[frame]).unwrap_err(),
            QrEnvelopeError::AnimatedTooManyFrames,
        );
        let mut oversized_chunk_frame = Vec::from(
            &b"nsealr1a:0000000000000000000000000000000000000000000000000000000000000000:1/1:"[..],
        );
        oversized_chunk_frame.extend(core::iter::repeat_n(
            b'A',
            MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS + 1,
        ));
        oversized_chunk_frame.extend_from_slice(b":0000000000000000");
        assert_eq!(
            decode_animated(&[oversized_chunk_frame.as_slice()]).unwrap_err(),
            QrEnvelopeError::AnimatedChunkTooLong,
        );
        let frame: &[u8] = b"nsealr1a:0000000000000000000000000000000000000000000000000000000000000000:184467440737095516160/1:AA:0000000000000000";
        assert_eq!(
            decode_animated(&[frame]).unwrap_err(),
            QrEnvelopeError::AnimatedBadIndexValue,
        );
    }

    // C++ test_qr_envelope_encoder_rejections.
    #[test]
    fn qr_envelope_encoder_rejections() {
        let mut big = [0u8; 8 * 1024];
        let mut oversized_static = Vec::from(&br#"{"x":""#[..]);
        oversized_static.extend(core::iter::repeat_n(b'x', MAX_STATIC_QR_DECODED_JSON_BYTES));
        oversized_static.extend_from_slice(br#""}"#);
        assert_eq!(
            encode_qr_envelope_json(&oversized_static, &mut big).unwrap_err(),
            QrEnvelopeError::ExceedsStaticJsonBytes,
        );

        let mut oversized_animated = Vec::from(&br#"{"x":""#[..]);
        oversized_animated.extend(core::iter::repeat_n(
            b'x',
            MAX_ANIMATED_QR_DECODED_JSON_BYTES,
        ));
        oversized_animated.extend_from_slice(br#""}"#);
        assert_eq!(
            encode_animated_to_vec(&oversized_animated, MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS)
                .unwrap_err(),
            QrEnvelopeError::ExceedsAnimatedJsonBytes,
        );

        assert_eq!(
            encode_animated_to_vec(b"{}", 0).unwrap_err(),
            QrEnvelopeError::AnimatedChunkSizeZero,
        );
        assert_eq!(
            encode_animated_to_vec(b"{}", MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS + 1).unwrap_err(),
            QrEnvelopeError::AnimatedChunkTooLong,
        );
        assert_eq!(
            encode_qr_envelope_json(b"{\"x\":\"\xff\"}", &mut big).unwrap_err(),
            QrEnvelopeError::InvalidUtf8,
        );
    }

    // C++ test_qr_limits_match_shared_profile: every constant pinned against the
    // shared limits profile specs/vectors/limits/nsealr-v0.json (`limits`), plus
    // the display-cycles constant from qr_response_display.hpp.
    #[test]
    fn qr_limits_match_shared_profile() {
        assert_eq!(MAX_REQUEST_ID_LENGTH, 128);
        assert_eq!(MAX_DECODED_REQUEST_JSON_BYTES, 704);
        assert_eq!(MAX_STATIC_QR_DECODED_JSON_BYTES, 704);
        assert_eq!(MAX_ANIMATED_QR_DECODED_JSON_BYTES, 4096);
        assert_eq!(MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS, 256);
        assert_eq!(MAX_ANIMATED_QR_FRAME_COUNT, 64);
        assert_eq!(MAX_SERIAL_FRAME_BYTES, 1024);
        assert_eq!(MAX_CONTENT_UTF8_BYTES, 512);
        assert_eq!(MAX_TAG_COUNT, 16);
        assert_eq!(MAX_TAG_FIELDS_PER_TAG, 8);
        assert_eq!(MAX_TAG_FIELD_UTF8_BYTES, 64);
        assert_eq!(MAX_TOTAL_TAG_UTF8_BYTES, 4096);
        assert_eq!(MAX_SAFE_INTEGER, 9_007_199_254_740_991);
        assert_eq!(MAX_QR_RESPONSE_DISPLAY_CYCLES, 16);
    }

    // C++ test_qr_signing_request_rejections.
    #[test]
    fn qr_signing_request_rejections() {
        let cases: &[(&[u8], QrEnvelopeError)] = &[
            (
                br#"{"version":2,"request_id":"req-kind-1-basic","method":"sign_event","params":{}}"#,
                QrEnvelopeError::RequestBadVersion,
            ),
            (
                br#"{"version":1,"request_id":"bad id","method":"sign_event","params":{}}"#,
                QrEnvelopeError::RequestBadRequestId,
            ),
            (
                br#"{"version":1,"request_id":"req-kind-1-basic","method":"get_public_key"}"#,
                QrEnvelopeError::RequestBadMethod,
            ),
            (
                br#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event"}"#,
                QrEnvelopeError::RequestParamsRequired,
            ),
            (
                br#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{}}"#,
                QrEnvelopeError::RequestEventTemplateRequired,
            ),
            (
                br#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":[]}}"#,
                QrEnvelopeError::RequestEventTemplateRequired,
            ),
            (
                br#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"","id":"00"}}}"#,
                QrEnvelopeError::RequestEventTemplateForbiddenField,
            ),
            (
                br#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"","pubkey":"00"}}}"#,
                QrEnvelopeError::RequestEventTemplateForbiddenField,
            ),
            (
                br#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"","sig":"00"}}}"#,
                QrEnvelopeError::RequestEventTemplateForbiddenField,
            ),
            (
                br#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"kind":1,"tags":[],"content":""}}}"#,
                QrEnvelopeError::RequestBadCreatedAt,
            ),
            (
                br#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":"1","tags":[],"content":""}}}"#,
                QrEnvelopeError::RequestBadKind,
            ),
            (
                br#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":{},"content":""}}}"#,
                QrEnvelopeError::RequestBadTags,
            ),
            (
                br#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[]}}}"#,
                QrEnvelopeError::RequestBadContent,
            ),
            (
                br#"{"version":1,"request_id":"req-invalid-unicode","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"\uD83D"}}}"#,
                QrEnvelopeError::RequestJsonMalformed,
            ),
            (
                br#"{"version":1,"request_id":"req-invalid-unicode","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"\uDE00"}}}"#,
                QrEnvelopeError::RequestJsonMalformed,
            ),
        ];
        for (index, (json, expected)) in cases.iter().enumerate() {
            assert_eq!(
                parse_qr_signing_request(json).unwrap_err(),
                *expected,
                "case {index}",
            );
        }
    }

    // C++ test_qr_signing_request_rejects_shared_invalid_request_vectors. Each
    // request_json literal is copied byte-for-byte from the matching
    // specs/vectors/invalid/<name>.json fixture (`request`, canonical
    // serialization as pinned by the C++ generated vector header).
    #[test]
    fn qr_signing_request_rejects_shared_invalid_request_vectors() {
        let vectors: &[(&str, &[u8])] = &[
            ("request-content-over-limit", br#"{"version":1,"request_id":"invalid-content-over-limit","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}}"#),
            ("request-created-at-float", br#"{"version":1,"request_id":"invalid-created-at-float","method":"sign_event","params":{"event_template":{"created_at":1710000000.5,"kind":1,"tags":[],"content":"invalid created_at"}}}"#),
            ("request-created-at-negative", br#"{"version":1,"request_id":"invalid-created-at-negative","method":"sign_event","params":{"event_template":{"created_at":-1,"kind":1,"tags":[],"content":"invalid created_at"}}}"#),
            ("request-created-at-string", br#"{"version":1,"request_id":"invalid-created-at-string","method":"sign_event","params":{"event_template":{"created_at":"1710000000","kind":1,"tags":[],"content":"invalid created_at"}}}"#),
            ("request-created-at-unsafe-integer", br#"{"version":1,"request_id":"invalid-created-at-unsafe","method":"sign_event","params":{"event_template":{"created_at":9007199254740992,"kind":1,"tags":[],"content":"invalid created_at"}}}"#),
            ("request-event-template-id", br#"{"version":1,"request_id":"invalid-template-id","method":"sign_event","params":{"event_template":{"id":"0000000000000000000000000000000000000000000000000000000000000000","created_at":1710000000,"kind":1,"tags":[],"content":"unsafe template"}}}"#),
            ("request-event-template-missing", br#"{"version":1,"request_id":"invalid-template-missing","method":"sign_event","params":{}}"#),
            ("request-event-template-not-object", br#"{"version":1,"request_id":"invalid-template-not-object","method":"sign_event","params":{"event_template":"not an object"}}"#),
            ("request-event-template-pubkey", br#"{"version":1,"request_id":"invalid-template-pubkey","method":"sign_event","params":{"event_template":{"pubkey":"0000000000000000000000000000000000000000000000000000000000000000","created_at":1710000000,"kind":1,"tags":[],"content":"unsafe template"}}}"#),
            ("request-event-template-sig", br#"{"version":1,"request_id":"invalid-template-sig","method":"sign_event","params":{"event_template":{"sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","created_at":1710000000,"kind":1,"tags":[],"content":"unsafe template"}}}"#),
            ("request-get-capabilities-params", br#"{"version":1,"request_id":"invalid-capabilities-params","method":"get_capabilities","params":{}}"#),
            ("request-get-public-key-params", br#"{"version":1,"request_id":"invalid-public-key-params","method":"get_public_key","params":{}}"#),
            ("request-json-over-limit", br#"{"version":1,"request_id":"invalid-request-json-over-limit","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}}"#),
            ("request-kind-float", br#"{"version":1,"request_id":"invalid-kind-float","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1.5,"tags":[],"content":"invalid kind"}}}"#),
            ("request-kind-negative", br#"{"version":1,"request_id":"invalid-kind-negative","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":-1,"tags":[],"content":"invalid kind"}}}"#),
            ("request-kind-string", br#"{"version":1,"request_id":"invalid-kind-string","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":"1","tags":[],"content":"invalid kind"}}}"#),
            ("request-kind-unsafe-integer", br#"{"version":1,"request_id":"invalid-kind-unsafe","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":9007199254740992,"tags":[],"content":"invalid kind"}}}"#),
            ("request-sign-event-missing-params", br#"{"version":1,"request_id":"invalid-sign-event-missing-params","method":"sign_event"}"#),
            ("request-sign-event-params-not-object", br#"{"version":1,"request_id":"invalid-sign-event-params-not-object","method":"sign_event","params":[]}"#),
            ("request-sign-event-unknown-param", br#"{"version":1,"request_id":"invalid-sign-event-unknown-param","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"valid event template"},"policy_hint":"unsafe host-supplied hint"}}"#),
            ("request-tag-field-too-long", br#"{"version":1,"request_id":"invalid-tag-field-too-long","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[["t","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]],"content":"tag field too long"}}}"#),
            ("request-tag-item-not-string", br#"{"version":1,"request_id":"invalid-tag-item-not-string","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[["p",7]],"content":"invalid tag item"}}}"#),
            ("request-tags-not-array", br#"{"version":1,"request_id":"invalid-tags-not-array","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":"not-an-array","content":"invalid tags"}}}"#),
            ("request-too-many-tags", br#"{"version":1,"request_id":"invalid-too-many-tags","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]],"content":"too many tags"}}}"#),
            ("request-unknown-top-level-field", br#"{"version":1,"request_id":"invalid-top-level","method":"get_public_key","unexpected":true}"#),
        ];
        for (name, json) in vectors {
            assert!(
                parse_qr_signing_request(json).is_err(),
                "unexpectedly accepted invalid request vector: {name}",
            );
        }
    }

    // --- Supplementary direct tests (fixture replay + branch coverage) ---

    // Replays specs/vectors/transports/qr-envelope-kind-1-long-events-many-tags.json
    // end to end: decode + full signing-request parse of a maximal valid request.
    #[test]
    fn long_events_many_tags_shared_vector_parses() {
        let (_, json) = decode_static(KIND1_LONG_MANY_TAGS_ENVELOPE).unwrap();
        let request = parse_qr_signing_request(&json).unwrap();
        assert_eq!(request.request_id(), b"req-kind-1-long-events-many-tags");
        assert_eq!(request.event_template.created_at, 1_710_000_120);
        assert_eq!(request.event_template.tag_count, 9);
        let tag0: Vec<&[u8]> = request.tag(0).collect();
        assert_eq!(tag0.len(), 4);
        assert_eq!(tag0[0], b"e");
        assert_eq!(tag0[2], b"");
        assert_eq!(tag0[3], b"root");
        let tag8: Vec<&[u8]> = request.tag(8).collect();
        assert_eq!(tag8, [&b"t"[..], &b"test"[..]]);
        assert_eq!(request.content().len(), 281);
    }

    #[test]
    fn animated_frames_accepted_out_of_order() {
        let (payload, json) =
            decode_animated(&[ANIMATED_FRAME_3, ANIMATED_FRAME_1, ANIMATED_FRAME_2]).unwrap();
        assert_eq!(payload, ANIMATED_PAYLOAD);
        assert_eq!(json, ANIMATED_JSON);
    }

    #[test]
    fn animated_structural_rejections() {
        let zero_digest = [b'0'; DIGEST_HEX_LEN];
        // Wrong prefix.
        assert_eq!(
            decode_animated(&[&b"nsealr1:AA"[..]]).unwrap_err(),
            QrEnvelopeError::AnimatedMissingPrefix,
        );
        // Not five fields.
        assert_eq!(
            decode_animated(&[&b"nsealr1a:00:1/1:AA"[..]]).unwrap_err(),
            QrEnvelopeError::AnimatedMalformed,
        );
        assert_eq!(
            decode_animated(&[&b"nsealr1a:00:1/1:AA:00:extra"[..]]).unwrap_err(),
            QrEnvelopeError::AnimatedMalformed,
        );
        // Bad digest (short / uppercase).
        assert_eq!(
            decode_animated(&[&b"nsealr1a:0000:1/1:AA:0000000000000000"[..]]).unwrap_err(),
            QrEnvelopeError::AnimatedBadDigest,
        );
        let mut upper_digest = Vec::from(ANIMATED_FRAME_1);
        upper_digest[ANIMATED_PREFIX.len()] = b'E';
        assert_eq!(
            decode_animated(&[upper_digest.as_slice()]).unwrap_err(),
            QrEnvelopeError::AnimatedBadDigest,
        );
        // Bad checksum format.
        let mut frame = Vec::from(&b"nsealr1a:"[..]);
        frame.extend_from_slice(&zero_digest);
        frame.extend_from_slice(b":1/1:AA:00");
        assert_eq!(
            decode_animated(&[frame.as_slice()]).unwrap_err(),
            QrEnvelopeError::AnimatedBadChecksumFormat,
        );
        // Index/total shape errors: no slash, two slashes.
        for index_total in [&b"11"[..], &b"1/1/1"[..]] {
            let mut frame = Vec::from(&b"nsealr1a:"[..]);
            frame.extend_from_slice(&zero_digest);
            frame.push(b':');
            frame.extend_from_slice(index_total);
            frame.extend_from_slice(b":AA:0000000000000000");
            assert_eq!(
                decode_animated(&[frame.as_slice()]).unwrap_err(),
                QrEnvelopeError::AnimatedBadIndexShape,
                "index_total {index_total:?}",
            );
        }
        // Decimal errors: empty, leading zero, non-digit.
        for index_total in [&b"/1"[..], &b"01/1"[..], &b"1/x"[..]] {
            let mut frame = Vec::from(&b"nsealr1a:"[..]);
            frame.extend_from_slice(&zero_digest);
            frame.push(b':');
            frame.extend_from_slice(index_total);
            frame.extend_from_slice(b":AA:0000000000000000");
            assert_eq!(
                decode_animated(&[frame.as_slice()]).unwrap_err(),
                QrEnvelopeError::AnimatedBadIndexValue,
                "index_total {index_total:?}",
            );
        }
        // index > total.
        let mut frame = Vec::from(&b"nsealr1a:"[..]);
        frame.extend_from_slice(&zero_digest);
        frame.extend_from_slice(b":2/1:AA:0000000000000000");
        assert_eq!(
            decode_animated(&[frame.as_slice()]).unwrap_err(),
            QrEnvelopeError::AnimatedIndexOutOfRange,
        );
        // Chunk not base64url.
        let mut frame = Vec::from(&b"nsealr1a:"[..]);
        frame.extend_from_slice(&zero_digest);
        frame.extend_from_slice(b":1/1:A+:0000000000000000");
        assert_eq!(
            decode_animated(&[frame.as_slice()]).unwrap_err(),
            QrEnvelopeError::AnimatedChunkNotBase64Url,
        );
    }

    #[test]
    fn animated_frame_set_rejections() {
        // Duplicate index (frame 1 twice, total 3): count==total but duplicate.
        assert_eq!(
            decode_animated(&[ANIMATED_FRAME_1, ANIMATED_FRAME_1, ANIMATED_FRAME_2]).unwrap_err(),
            QrEnvelopeError::AnimatedFramesNotContiguous,
        );
        // Mixed digest: a self-consistent frame 2 with a different digest.
        let other_digest = [b'f'; DIGEST_HEX_LEN];
        let mixed = build_frame(&other_digest, b"2/3", b"AA");
        assert_eq!(
            decode_animated(&[ANIMATED_FRAME_1, mixed.as_slice(), ANIMATED_FRAME_3]).unwrap_err(),
            QrEnvelopeError::AnimatedFrameSetMismatch,
        );
    }

    #[test]
    fn animated_digest_and_length_rejections() {
        // "e30" decodes to "{}"; digest field is all zeros (valid hex, wrong value).
        let zero_digest = [b'0'; DIGEST_HEX_LEN];
        let frame = build_frame(&zero_digest, b"1/1", b"e30");
        assert_eq!(
            decode_animated(&[frame.as_slice()]).unwrap_err(),
            QrEnvelopeError::AnimatedDigestMismatch,
        );

        // Reassembled payload with len % 4 == 1 (chunks "e3" + "0aa" -> "e30aa").
        let f1 = build_frame(&zero_digest, b"1/2", b"e3");
        let f2 = build_frame(&zero_digest, b"2/2", b"0aa");
        assert_eq!(
            decode_animated(&[f1.as_slice(), f2.as_slice()]).unwrap_err(),
            QrEnvelopeError::InvalidBase64UrlLength,
        );
    }

    #[test]
    fn animated_payload_content_rejections() {
        // Non-UTF-8 payload: "_w" decodes to [0xFF]; use the real digest of [0xFF]
        // so the digest check passes and the UTF-8 check is reached.
        let real_digest = sha256_hex(&[0xffu8]);
        let frame = build_frame(&real_digest, b"1/1", b"_w");
        assert_eq!(
            decode_animated(&[frame.as_slice()]).unwrap_err(),
            QrEnvelopeError::InvalidUtf8,
        );

        // Valid UTF-8 but not a JSON container: "ok" -> "b2s".
        let real_digest = sha256_hex(b"ok");
        let frame = build_frame(&real_digest, b"1/1", b"b2s");
        assert_eq!(
            decode_animated(&[frame.as_slice()]).unwrap_err(),
            QrEnvelopeError::NotJsonContainer,
        );

        // Non-canonical trailing bits: "e3" + "1" would be len 3 (ok%4) — use "e31"
        // whose final char has non-zero trailing bits ('1' = 53 -> bits 110101,
        // 3 chars = 18 bits, 2 bytes + 2 leftover bits = 01 != 0).
        let real_digest = sha256_hex(b"{}"); // digest never reached
        let frame = build_frame(&real_digest, b"1/1", b"e31");
        assert_eq!(
            decode_animated(&[frame.as_slice()]).unwrap_err(),
            QrEnvelopeError::InvalidTrailingBits,
        );

        // Oversized decoded JSON via many max-size chunks of 'A's: 4096+ decoded
        // bytes from 5464 payload chars (22 chunks of 256 -> 5632 chars -> 4224
        // bytes decoded > 4096).
        let chunk = [b'A'; MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS];
        let zero_digest = [b'0'; DIGEST_HEX_LEN];
        let mut frames = Vec::new();
        for index in 1..=22usize {
            let index_total = std::format!("{index}/22");
            frames.push(build_frame(&zero_digest, index_total.as_bytes(), &chunk));
        }
        assert_eq!(
            decode_animated(&frames.iter().map(Vec::as_slice).collect::<Vec<_>>()).unwrap_err(),
            QrEnvelopeError::ExceedsAnimatedJsonBytes,
        );

        // Round-trip sanity for the frame builder used above.
        let frames = encode_animated_to_vec(b"{}", 64).unwrap();
        let (_, json) =
            decode_animated(&frames.iter().map(Vec::as_slice).collect::<Vec<_>>()).unwrap();
        assert_eq!(json, b"{}");
    }

    #[test]
    fn animated_encoder_rejects_too_many_frames_and_bad_payloads() {
        // 102-byte JSON at chunk size 1 -> 136 chunks > 64 frames.
        let mut json = Vec::from(&b"["[..]);
        json.extend(core::iter::repeat_n(b'1', 100));
        json.push(b']');
        assert_eq!(
            encode_animated_to_vec(&json, 1).unwrap_err(),
            QrEnvelopeError::AnimatedTooManyFrames,
        );
        assert_eq!(
            encode_animated_to_vec(b"not json", 64).unwrap_err(),
            QrEnvelopeError::NotJsonContainer,
        );
        assert_eq!(
            encode_animated_to_vec(b"{\"x\":\"\xff\"}", 64).unwrap_err(),
            QrEnvelopeError::InvalidUtf8,
        );
    }

    #[test]
    fn static_encoder_and_container_shapes() {
        // Arrays are accepted; leading/trailing ASCII whitespace tolerated.
        let mut buf = [0u8; 1024];
        let envelope = encode_qr_envelope_json(b" [1,2] \n", &mut buf).unwrap();
        assert!(envelope.starts_with(b"nsealr1:"));
        // Too-short (< 2 chars trimmed) is not a container.
        assert_eq!(
            encode_qr_envelope_json(b" { ", &mut buf).unwrap_err(),
            QrEnvelopeError::NotJsonContainer,
        );
        // Trailing-bits canonicality is enforced on static decode.
        assert_eq!(
            decode_static(b"nsealr1:AB").unwrap_err(),
            QrEnvelopeError::InvalidTrailingBits,
        );
        // OutputTooSmall from the static encoder.
        let mut tiny = [0u8; 4];
        assert_eq!(
            encode_qr_envelope_json(b"{}", &mut tiny).unwrap_err(),
            QrEnvelopeError::OutputTooSmall,
        );
    }

    // Direct coverage of the request-parser tolerance rules the C++ exercises via
    // its JSON scanner: whitespace, the full escape set, nested containers skipped
    // without grammar validation.
    #[test]
    fn request_parser_tolerances() {
        // Whitespace everywhere; escape set \" \\ \/ \b \f \n \r \t in content.
        let json = b" { \"version\" : 1 , \"request_id\" : \"req-ws\" , \"method\" : \"sign_event\" , \"params\" : { \"event_template\" : { \"created_at\" : 1 , \"kind\" : 0 , \"tags\" : [ ] , \"content\" : \"q\\\"b\\\\s\\/f\\bg\\fh\\nn\\rr\\tt\" } } } ";
        let request = parse_qr_signing_request(json).unwrap();
        assert_eq!(request.content(), b"q\"b\\s/f\x08g\x0ch\nn\rr\tt");
        assert_eq!(request.event_template.kind, 0);

        // Nested containers inside strings are data; a nested object inside content
        // passes untouched (C++ parse_simple_json_string semantics).
        let json = br#"{"version":1,"request_id":"req-nested","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[["a","{[not json}"]],"content":"{\"nested\":[1,2,{}]}"}}}"#;
        let request = parse_qr_signing_request(json).unwrap();
        assert_eq!(request.event_template.tag_count, 1);

        // Empty top-level object -> version required.
        assert_eq!(
            parse_qr_signing_request(b"{}").unwrap_err(),
            QrEnvelopeError::RequestBadVersion,
        );

        // Literals (true/false/null) parse as top-level value tokens; the
        // unknown-field check still fires.
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"sign_event","params":{},"extra":null}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestUnknownField,
        );

        // A key longer than any known member name is an unknown field (the
        // decoder truncates it past the known-key buffer).
        assert_eq!(
            parse_qr_signing_request(br#"{"version":1,"a_key_longer_than_any_known_member":1}"#)
                .unwrap_err(),
            QrEnvelopeError::RequestUnknownField,
        );

        // String values everywhere a non-string is expected: version as a string
        // is a version mismatch, params as a string is a missing params object,
        // and string-valued unknown members (top-level and template) are still
        // unknown-field errors.
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":"1","request_id":"r","method":"sign_event","params":{}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestBadVersion,
        );
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"sign_event","params":"x"}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestParamsRequired,
        );
        assert_eq!(
            parse_qr_signing_request(br#"{"version":1,"extra":"v"}"#).unwrap_err(),
            QrEnvelopeError::RequestUnknownField,
        );
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":1,"tags":[],"content":"","extra":"v"}}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestEventTemplateUnknownField,
        );

        // A method value longer than the comparison buffer is just a mismatch.
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"a_method_longer_than_the_buffer","params":{}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestBadMethod,
        );

        // params with an unknown member (event_template present too).
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":1,"tags":[],"content":""},"other":1}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestParamsUnknownField,
        );

        // event_template with an unknown (non-forbidden) member.
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":1,"tags":[],"content":"","extra":1}}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestEventTemplateUnknownField,
        );
    }

    #[test]
    fn request_parser_grammar_rejections() {
        let cases: &[&[u8]] = &[
            b"[]",                          // not an object
            b"",                            // empty
            b"{\"version\"1}",              // missing ':'
            b"{\"version\":1 \"x\":2}",     // bad separator
            b"{\"version\":}",              // missing value
            b"{\"version\":either}",        // bad literal
            b"{\"version\":-}",             // bad number
            b"{\"version\":1}extra",        // trailing data
            b"{\"unterminated",             // unterminated key string
            b"{\"bad\\escape\":1}",         // invalid escape
            b"{\"trunc\\",                  // truncated escape
            b"{\"ctl\x01\":1}",             // control character in string
            b"{\"k\":{\"unterminated\":1}", // unterminated container
            b"{\"k\":[1",                   // unterminated array container
            b"{\"k\":",                     // value missing at end of input
            b"{\"version\":1,\"request_id\":\"r\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":18446744073709551616,\"kind\":1,\"tags\":[],\"content\":\"\"}}}", // u64 overflow
        ];
        for (index, json) in cases.iter().enumerate() {
            assert!(
                parse_qr_signing_request(json).is_err(),
                "case {index} unexpectedly accepted",
            );
        }
        // Grammar failures inside specific member values, exercising each
        // scanner error edge: bad escape in request_id / method values, and a
        // missing ':' inside params and event_template sub-objects (their outer
        // container skip only depth-checks, so the sub-parse reports it).
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"\q","method":"sign_event","params":{}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestJsonMalformed,
        );
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"\q","params":{}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestJsonMalformed,
        );
        assert_eq!(
            parse_qr_signing_request(br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template" 1}}"#)
                .unwrap_err(),
            QrEnvelopeError::RequestJsonMalformed,
        );
        assert_eq!(
            parse_qr_signing_request(br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at" 1}}}"#)
                .unwrap_err(),
            QrEnvelopeError::RequestJsonMalformed,
        );
        // A bad literal as the content value: invisible to the outer container
        // skip (which only validates strings/depth), caught by the sub-parse.
        assert_eq!(
            parse_qr_signing_request(br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":1,"tags":[],"content":nope}}}"#)
                .unwrap_err(),
            QrEnvelopeError::RequestJsonMalformed,
        );

        // Tag element that is not an array, and a bad separator between fields.
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":1,"tags":["x"],"content":""}}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestBadTags,
        );
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":1,"tags":[["a" "b"]],"content":""}}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestBadTags,
        );
        // content that is not a string.
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":1,"tags":[],"content":7}}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestBadContent,
        );
        // kind fits u64 and MAX_SAFE_INTEGER but exceeds i32::MAX -> kind invalid.
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":2147483648,"tags":[],"content":""}}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestBadKind,
        );
        // Tags-array grammar: separator junk between tags (C++ "tags array
        // separator is invalid").
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":1,"tags":[["a"];["b"]],"content":""}}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::RequestBadTags,
        );
    }

    #[test]
    fn request_limit_rejections() {
        // request_id over MAX_REQUEST_ID_LENGTH.
        let mut long_id = String::from(r#"{"version":1,"request_id":""#);
        long_id.extend(core::iter::repeat_n('a', MAX_REQUEST_ID_LENGTH + 1));
        long_id.push_str(r#"","method":"sign_event","params":{}}"#);
        assert_eq!(
            parse_qr_signing_request(long_id.as_bytes()).unwrap_err(),
            QrEnvelopeError::RequestBadRequestId,
        );

        // Request JSON over MAX_DECODED_REQUEST_JSON_BYTES (checked before parsing).
        let mut over = String::from(
            r#"{"version":1,"request_id":"r","method":"sign_event","params":{"filler":""#,
        );
        over.extend(core::iter::repeat_n('x', MAX_DECODED_REQUEST_JSON_BYTES));
        over.push_str(r#""}}"#);
        assert_eq!(
            parse_qr_signing_request(over.as_bytes()).unwrap_err(),
            QrEnvelopeError::ExceedsRequestJsonBytes,
        );

        // Tag fields per tag over the limit (9 fields).
        assert_eq!(
            parse_qr_signing_request(
                br#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":1,"tags":[["1","2","3","4","5","6","7","8","9"]],"content":""}}}"#
            )
            .unwrap_err(),
            QrEnvelopeError::TooManyTagFields,
        );
    }

    // Content over MAX_CONTENT_UTF8_BYTES *within* the request-JSON budget (the
    // shared "request-content-over-limit" vector is also over the total budget, so
    // it exercises whichever guard fires first; this exercises ContentTooLong
    // specifically, like the C++ event-template content check).
    #[test]
    fn content_over_limit_within_request_budget() {
        let mut json = String::from(
            r#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":1,"tags":[],"content":""#,
        );
        json.extend(core::iter::repeat_n('x', MAX_CONTENT_UTF8_BYTES + 1));
        json.push_str(r#""}}}"#);
        assert!(json.len() <= MAX_DECODED_REQUEST_JSON_BYTES);
        assert_eq!(
            parse_qr_signing_request(json.as_bytes()).unwrap_err(),
            QrEnvelopeError::ContentTooLong,
        );
    }

    // Direct contract tests for private helpers whose remaining branches are
    // unreachable through the public surface but part of the ported C++ contract.
    #[test]
    fn helper_contracts() {
        // trim_ascii on all-whitespace input (C++ returned "").
        let mut buf = [0u8; 64];
        assert_eq!(
            encode_qr_envelope_json(b" \n\r\t ", &mut buf).unwrap_err(),
            QrEnvelopeError::NotJsonContainer,
        );
        // map_payload_decode_error covers every base64url decode failure (the
        // InvalidCharacter arm is pre-empted by is_base64url_payload on the
        // public paths, as in the C++ catch clause).
        assert_eq!(
            map_payload_decode_error(Base64UrlError::InvalidCharacter),
            QrEnvelopeError::PayloadNotBase64Url,
        );
        assert_eq!(
            map_payload_decode_error(Base64UrlError::InvalidTrailingBits),
            QrEnvelopeError::InvalidTrailingBits,
        );
        assert_eq!(
            map_payload_decode_error(Base64UrlError::OutputTooSmall),
            QrEnvelopeError::OutputTooSmall,
        );
        // parse_unsigned_decimal rejects non-digits (the C++ shared this helper
        // contract; the tokenizer pre-filters digits on the public paths).
        assert_eq!(
            parse_unsigned_decimal(b"12x", QrEnvelopeError::RequestBadKind),
            Err(QrEnvelopeError::RequestBadKind),
        );
        assert_eq!(
            parse_unsigned_decimal(b"17", QrEnvelopeError::RequestBadKind),
            Ok(17),
        );
    }

    // Undersized caller buffers surface OutputTooSmall (no C++ analogue; the
    // C++ used growable strings).
    #[test]
    fn undersized_output_buffers() {
        let mut tiny_json = [0u8; 4];
        assert_eq!(
            decode_qr_envelope(KIND1_BASIC_ENVELOPE, &mut tiny_json).unwrap_err(),
            QrEnvelopeError::OutputTooSmall,
        );
        let mut tiny_payload = [0u8; 8];
        let mut json = [0u8; MAX_ANIMATED_QR_DECODED_JSON_BYTES];
        assert_eq!(
            decode_animated_qr_envelope_frames(
                &[ANIMATED_FRAME_1, ANIMATED_FRAME_2, ANIMATED_FRAME_3],
                &mut tiny_payload,
                &mut json,
            )
            .unwrap_err(),
            QrEnvelopeError::OutputTooSmall,
        );
    }

    // Tag-field byte limit uses *decoded* bytes (escapes resolved), like the C++
    // which checked field.size() after unescaping: 33 'è' escapes -> 66 bytes > 64.
    #[test]
    fn tag_field_limit_uses_decoded_bytes() {
        let mut json = String::from(
            r#"{"version":1,"request_id":"r","method":"sign_event","params":{"event_template":{"created_at":1,"kind":1,"tags":[["t",""#,
        );
        for _ in 0..33 {
            json.push_str("\\u00e8");
        }
        json.push_str(r#""]],"content":""}}}"#);
        assert_eq!(
            parse_qr_signing_request(json.as_bytes()).unwrap_err(),
            QrEnvelopeError::TagFieldTooLong,
        );
    }
}
