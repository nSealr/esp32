//! QR response-display frame builder and display-loop driver.
//!
//! Ported from the C++ reference `host_core` sources `src/qr_response_display.cpp` +
//! `include/nsealr/qr_response_display.hpp` for behaviour parity:
//!
//! - **Response validation** — a dedicated single-pass JSON object scanner
//!   (deliberately *different* from the envelope parser, matching the C++): every
//!   `\uXXXX` escape is validated as four hex digits but collapsed to a literal
//!   `?` (the parsed text is only inspected, never displayed), skipped scalar
//!   tokens accept full JSON numbers (fraction/exponent), and nested
//!   objects/arrays are structurally walked (`skip_json_value`). The top level
//!   must be an object with only `version`/`request_id`/`ok`/`result`/`error`;
//!   `version` must be the token `1`, `request_id` must match the shared
//!   request-id charset/length rule, `ok` must be a boolean; `ok:true` requires a
//!   `result` object and no `error`, `ok:false` requires an `error` object and no
//!   `result`.
//! - **Frame building** — a response up to [`MAX_STATIC_QR_DECODED_JSON_BYTES`]
//!   becomes one static [`crate::qr::envelope`] frame
//!   (`index=1,total=1,animated=false`); a larger one becomes animated
//!   `nsealr1a:` frames (`animated=true`).
//! - **Display loop** — [`run_qr_response_display_io`] validates the cycle count
//!   (`1..=`[`MAX_QR_RESPONSE_DISPLAY_CYCLES`]), then shows the frame sequence
//!   once for a static frame and `animated_cycles` times for a multi-frame
//!   animated response.
//!
//! The C++ returned `std::vector<QrResponseDisplayFrame>` with owned payload
//! strings; this port hands each frame to a callback/`Io` sink as it is produced,
//! keeping the crate `no_std` and allocation-free.

use crate::qr::envelope::{
    encode_animated_qr_envelope_json, encode_qr_envelope_json, is_request_id, QrEnvelopeError,
    PREFIX,
};
use crate::qr::limits::{
    MAX_QR_RESPONSE_DISPLAY_CYCLES, MAX_REQUEST_ID_LENGTH, MAX_STATIC_QR_DECODED_JSON_BYTES,
};

/// Errors reported by the response-display functions. Each variant corresponds
/// to one or more distinct C++ `std::invalid_argument` messages (named in the
/// doc comments).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrResponseDisplayError {
    /// C++: "QR response display response must be a JSON object".
    NotJsonObject,
    /// C++: the scanner's structural errors — "... JSON string is
    /// required/unterminated" / "... string escape is truncated/unsupported" /
    /// "... unicode escape is invalid" / "... contains control character" /
    /// "... JSON object is malformed/unterminated/required" / "... JSON array is
    /// malformed/unterminated/required" / "... JSON value is required" /
    /// "... JSON scalar is invalid" / "... JSON has trailing data".
    ResponseJsonMalformed,
    /// C++: "QR response display response contains unknown top-level field".
    UnknownTopLevelField,
    /// C++: "QR response display response version must be 1".
    BadVersion,
    /// C++: "QR response display response request_id is invalid".
    BadRequestId,
    /// C++: "QR response display response ok must be true or false".
    OkNotBoolean,
    /// C++: "QR response display successful response must not include error".
    SuccessWithError,
    /// C++: "QR response display successful response requires result object".
    SuccessWithoutResultObject,
    /// C++: "QR response display error response must not include result".
    ErrorWithResult,
    /// C++: "QR response display error response requires error object".
    ErrorWithoutErrorObject,
    /// C++: "QR response display animated cycles must be non-zero".
    ZeroCycles,
    /// C++: "QR response display animated cycles exceed
    /// max_qr_response_display_cycles".
    TooManyCycles,
    /// The underlying envelope encoder rejected the payload (size/UTF-8/frame
    /// limits). The C++ let the `QrEnvelopeError` propagate; this port wraps it.
    Envelope(QrEnvelopeError),
}

impl From<QrEnvelopeError> for QrResponseDisplayError {
    fn from(error: QrEnvelopeError) -> Self {
        Self::Envelope(error)
    }
}

/// One display frame. Mirrors the C++ `QrResponseDisplayFrame`, with the owned
/// payload string replaced by a borrowed slice valid for the callback's duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrResponseDisplayFrame<'a> {
    /// The full QR payload text (`nsealr1:...` or `nsealr1a:...`).
    pub payload: &'a [u8],
    /// 1-based frame index.
    pub index: usize,
    /// Total frame count.
    pub total: usize,
    /// `true` for animated (`nsealr1a:`) frames.
    pub animated: bool,
}

/// The display sink. Mirrors the C++ `QrResponseDisplayIo` interface.
pub trait QrResponseDisplayIo {
    /// Presents one response QR frame.
    fn show_response_qr_frame(&mut self, frame: &QrResponseDisplayFrame<'_>);
}

/// The response scanner. Mirrors the helper functions in the C++
/// `qr_response_display.cpp` anonymous namespace (`skip_ws`, `parse_json_string`,
/// `skip_json_value`/`_object`/`_array`/`_scalar`, `parse_json_boolean`,
/// `is_valid_json_number_token`, `parse_response_json_metadata`). Deliberately
/// separate from the request scanner in [`crate::qr::envelope`]: this one
/// collapses `\uXXXX` to `?`, accepts full JSON numbers, and walks nested
/// containers structurally.
struct Scanner<'j> {
    json: &'j [u8],
    offset: usize,
}

/// Mirrors the C++ `is_valid_json_number_token` (full JSON number grammar).
fn is_valid_number_token(token: &[u8]) -> bool {
    let mut offset = 0usize;
    if token.first() == Some(&b'-') {
        offset += 1;
    }
    match token.get(offset) {
        Some(b'0') => offset += 1,
        Some(b'1'..=b'9') => {
            while matches!(token.get(offset), Some(b'0'..=b'9')) {
                offset += 1;
            }
        }
        _ => return false,
    }
    if token.get(offset) == Some(&b'.') {
        offset += 1;
        let fraction_start = offset;
        while matches!(token.get(offset), Some(b'0'..=b'9')) {
            offset += 1;
        }
        if offset == fraction_start {
            return false;
        }
    }
    if matches!(token.get(offset), Some(b'e' | b'E')) {
        offset += 1;
        if matches!(token.get(offset), Some(b'+' | b'-')) {
            offset += 1;
        }
        let exponent_start = offset;
        while matches!(token.get(offset), Some(b'0'..=b'9')) {
            offset += 1;
        }
        if offset == exponent_start {
            return false;
        }
    }
    offset == token.len()
}

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

    /// Mirrors the C++ `parse_json_string`: standard escapes decode, `\uXXXX`
    /// is validated as four hex digits but yields a literal `?`, control
    /// characters and unsupported escapes reject.
    fn parse_string(&mut self, sink: &mut dyn FnMut(u8)) -> Result<(), QrResponseDisplayError> {
        if self.peek() != Some(b'"') {
            return Err(QrResponseDisplayError::ResponseJsonMalformed);
        }
        self.offset += 1;
        while self.offset < self.json.len() {
            let ch = self.json[self.offset];
            self.offset += 1;
            if ch == b'"' {
                return Ok(());
            }
            if ch == b'\\' {
                let escaped = self
                    .peek()
                    .ok_or(QrResponseDisplayError::ResponseJsonMalformed)?;
                self.offset += 1;
                match escaped {
                    b'"' | b'\\' | b'/' => sink(escaped),
                    b'b' => sink(0x08),
                    b'f' => sink(0x0c),
                    b'n' => sink(b'\n'),
                    b'r' => sink(b'\r'),
                    b't' => sink(b'\t'),
                    b'u' => {
                        let hex = self
                            .json
                            .get(self.offset..self.offset + 4)
                            .ok_or(QrResponseDisplayError::ResponseJsonMalformed)?;
                        if !hex.iter().all(u8::is_ascii_hexdigit) {
                            return Err(QrResponseDisplayError::ResponseJsonMalformed);
                        }
                        self.offset += 4;
                        sink(b'?');
                    }
                    _ => return Err(QrResponseDisplayError::ResponseJsonMalformed),
                }
                continue;
            }
            if ch < 0x20 {
                return Err(QrResponseDisplayError::ResponseJsonMalformed);
            }
            sink(ch);
        }
        Err(QrResponseDisplayError::ResponseJsonMalformed)
    }

    /// Mirrors the C++ `skip_json_object`. The caller guarantees the scanner
    /// sits on `{` (the C++ re-checked; dead branch, omitted).
    fn skip_object(&mut self) -> Result<(), QrResponseDisplayError> {
        self.offset += 1;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.offset += 1;
            return Ok(());
        }
        while self.offset < self.json.len() {
            self.parse_string(&mut |_| {})?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(QrResponseDisplayError::ResponseJsonMalformed);
            }
            self.offset += 1;
            self.skip_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.offset += 1;
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.offset += 1;
                    return Ok(());
                }
                _ => return Err(QrResponseDisplayError::ResponseJsonMalformed),
            }
        }
        Err(QrResponseDisplayError::ResponseJsonMalformed)
    }

    /// Mirrors the C++ `skip_json_array` (same caller guarantee as
    /// [`Self::skip_object`]).
    fn skip_array(&mut self) -> Result<(), QrResponseDisplayError> {
        self.offset += 1;
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.offset += 1;
            return Ok(());
        }
        while self.offset < self.json.len() {
            self.skip_value()?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.offset += 1;
                    self.skip_ws();
                }
                Some(b']') => {
                    self.offset += 1;
                    return Ok(());
                }
                _ => return Err(QrResponseDisplayError::ResponseJsonMalformed),
            }
        }
        Err(QrResponseDisplayError::ResponseJsonMalformed)
    }

    /// Mirrors the C++ `skip_json_scalar` (`true`/`false`/`null` or a full JSON
    /// number token).
    fn skip_scalar(&mut self) -> Result<(), QrResponseDisplayError> {
        let start = self.offset;
        while let Some(ch) = self.peek() {
            if matches!(ch, b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t') {
                break;
            }
            self.offset += 1;
        }
        if self.offset == start {
            return Err(QrResponseDisplayError::ResponseJsonMalformed);
        }
        let token = &self.json[start..self.offset];
        if token != b"true"
            && token != b"false"
            && token != b"null"
            && !is_valid_number_token(token)
        {
            return Err(QrResponseDisplayError::ResponseJsonMalformed);
        }
        Ok(())
    }

    /// Mirrors the C++ `skip_json_value`.
    fn skip_value(&mut self) -> Result<(), QrResponseDisplayError> {
        self.skip_ws();
        match self.peek() {
            None => Err(QrResponseDisplayError::ResponseJsonMalformed),
            Some(b'"') => self.parse_string(&mut |_| {}),
            Some(b'{') => self.skip_object(),
            Some(b'[') => self.skip_array(),
            Some(_) => self.skip_scalar(),
        }
    }

    /// Mirrors the C++ `parse_json_boolean`: returns `Some(bool)` for a literal
    /// `true`/`false`, otherwise skips the value and returns `None`.
    fn parse_boolean(&mut self) -> Result<Option<bool>, QrResponseDisplayError> {
        if self.json[self.offset..].starts_with(b"true") {
            self.offset += 4;
            return Ok(Some(true));
        }
        if self.json[self.offset..].starts_with(b"false") {
            self.offset += 5;
            return Ok(Some(false));
        }
        self.skip_value()?;
        Ok(None)
    }
}

/// The scanned top-level response shape. Mirrors the C++ `ResponseJsonMetadata`.
struct ResponseMetadata {
    version_one: bool,
    ok_seen: bool,
    ok: bool,
    has_result: bool,
    result_is_object: bool,
    has_error: bool,
    error_is_object: bool,
    has_unknown_top_level_field: bool,
    request_id: [u8; MAX_REQUEST_ID_LENGTH],
    request_id_len: usize,
    request_id_overflow: bool,
}

/// Mirrors the C++ `parse_response_json_metadata`.
fn parse_response_json_metadata(json: &[u8]) -> Result<ResponseMetadata, QrResponseDisplayError> {
    let mut scanner = Scanner::new(json);
    scanner.skip_ws();
    if scanner.peek() != Some(b'{') {
        return Err(QrResponseDisplayError::NotJsonObject);
    }
    scanner.offset += 1;
    let mut metadata = ResponseMetadata {
        version_one: false,
        ok_seen: false,
        ok: false,
        has_result: false,
        result_is_object: false,
        has_error: false,
        error_is_object: false,
        has_unknown_top_level_field: false,
        request_id: [0; MAX_REQUEST_ID_LENGTH],
        request_id_len: 0,
        request_id_overflow: false,
    };
    scanner.skip_ws();
    if scanner.peek() == Some(b'}') {
        scanner.offset += 1;
    } else {
        while scanner.offset < json.len() {
            let mut key = [0u8; 16];
            let mut key_len = 0usize;
            scanner.parse_string(&mut |byte| {
                if key_len < key.len() {
                    key[key_len] = byte;
                }
                key_len += 1;
            })?;
            scanner.skip_ws();
            if scanner.peek() != Some(b':') {
                return Err(QrResponseDisplayError::ResponseJsonMalformed);
            }
            scanner.offset += 1;
            scanner.skip_ws();
            match &key[..key_len.min(key.len())] {
                b"version" => {
                    let start = scanner.offset;
                    scanner.skip_value()?;
                    metadata.version_one = &json[start..scanner.offset] == b"1";
                }
                b"request_id" => {
                    let mut len = 0usize;
                    let mut overflow = false;
                    let rid = &mut metadata.request_id;
                    scanner.parse_string(&mut |byte| {
                        if len < rid.len() {
                            rid[len] = byte;
                            len += 1;
                        } else {
                            overflow = true;
                        }
                    })?;
                    metadata.request_id_len = len;
                    metadata.request_id_overflow = overflow;
                }
                b"ok" => match scanner.parse_boolean()? {
                    Some(value) => {
                        metadata.ok_seen = true;
                        metadata.ok = value;
                    }
                    None => metadata.ok_seen = false,
                },
                b"result" => {
                    metadata.has_result = true;
                    metadata.result_is_object = scanner.peek() == Some(b'{');
                    scanner.skip_value()?;
                }
                b"error" => {
                    metadata.has_error = true;
                    metadata.error_is_object = scanner.peek() == Some(b'{');
                    scanner.skip_value()?;
                }
                _ => {
                    metadata.has_unknown_top_level_field = true;
                    scanner.skip_value()?;
                }
            }
            scanner.skip_ws();
            match scanner.peek() {
                Some(b',') => {
                    scanner.offset += 1;
                    scanner.skip_ws();
                }
                Some(b'}') => {
                    scanner.offset += 1;
                    break;
                }
                _ => return Err(QrResponseDisplayError::ResponseJsonMalformed),
            }
        }
    }
    scanner.skip_ws();
    if scanner.offset != json.len() {
        return Err(QrResponseDisplayError::ResponseJsonMalformed);
    }
    Ok(metadata)
}

/// Mirrors the C++ `require_response_json_for_display`.
fn require_response_json_for_display(response_json: &[u8]) -> Result<(), QrResponseDisplayError> {
    let metadata = parse_response_json_metadata(response_json)?;
    if metadata.has_unknown_top_level_field {
        return Err(QrResponseDisplayError::UnknownTopLevelField);
    }
    if !metadata.version_one {
        return Err(QrResponseDisplayError::BadVersion);
    }
    if metadata.request_id_overflow
        || !is_request_id(&metadata.request_id[..metadata.request_id_len])
    {
        return Err(QrResponseDisplayError::BadRequestId);
    }
    if !metadata.ok_seen {
        return Err(QrResponseDisplayError::OkNotBoolean);
    }
    if metadata.ok {
        if metadata.has_error {
            return Err(QrResponseDisplayError::SuccessWithError);
        }
        if !metadata.has_result || !metadata.result_is_object {
            return Err(QrResponseDisplayError::SuccessWithoutResultObject);
        }
        return Ok(());
    }
    if metadata.has_result {
        return Err(QrResponseDisplayError::ErrorWithResult);
    }
    if !metadata.has_error || !metadata.error_is_object {
        return Err(QrResponseDisplayError::ErrorWithoutErrorObject);
    }
    Ok(())
}

/// Builds the response display frames for `response_json`, handing each to
/// `emit`. Mirrors the C++ `build_qr_response_display_frames` (which returned a
/// `std::vector`; the callback keeps this port allocation-free). A response that
/// fits [`MAX_STATIC_QR_DECODED_JSON_BYTES`] produces exactly one static frame;
/// larger responses produce animated frames chunked at
/// `animated_chunk_size_chars` (the C++ default argument was
/// `MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS`; Rust has no default arguments, so the
/// caller always passes it).
///
/// # Errors
///
/// See [`QrResponseDisplayError`]; validation parity with the C++
/// `require_response_json_for_display`.
pub fn build_qr_response_display_frames(
    response_json: &[u8],
    animated_chunk_size_chars: usize,
    emit: &mut dyn FnMut(&QrResponseDisplayFrame<'_>),
) -> Result<(), QrResponseDisplayError> {
    require_response_json_for_display(response_json)?;
    if response_json.len() <= MAX_STATIC_QR_DECODED_JSON_BYTES {
        let mut buf =
            [0u8; PREFIX.len() + crate::base64url::encoded_len(MAX_STATIC_QR_DECODED_JSON_BYTES)];
        let payload = encode_qr_envelope_json(response_json, &mut buf)?;
        emit(&QrResponseDisplayFrame {
            payload,
            index: 1,
            total: 1,
            animated: false,
        });
        return Ok(());
    }
    encode_animated_qr_envelope_json(
        response_json,
        animated_chunk_size_chars,
        &mut |frame, offset, total| {
            emit(&QrResponseDisplayFrame {
                payload: frame,
                index: offset + 1,
                total,
                animated: true,
            });
        },
    )?;
    Ok(())
}

/// Validates the cycle count, builds the frames, and drives `io` through
/// `animated_cycles` repetitions (one repetition for a single static frame).
/// Mirrors the C++ `run_qr_response_display_io`; the C++ also returned the
/// displayed frames as a vector, which callers can reconstruct from the `io`
/// callbacks, so this port returns only the total displayed-frame count.
///
/// # Errors
///
/// [`QrResponseDisplayError::ZeroCycles`],
/// [`QrResponseDisplayError::TooManyCycles`], plus everything from
/// [`build_qr_response_display_frames`].
pub fn run_qr_response_display_io(
    io: &mut dyn QrResponseDisplayIo,
    response_json: &[u8],
    animated_chunk_size_chars: usize,
    animated_cycles: usize,
) -> Result<usize, QrResponseDisplayError> {
    if animated_cycles == 0 {
        return Err(QrResponseDisplayError::ZeroCycles);
    }
    if animated_cycles > MAX_QR_RESPONSE_DISPLAY_CYCLES {
        return Err(QrResponseDisplayError::TooManyCycles);
    }
    // First cycle also counts the frames (the C++ built a frame vector once and
    // replayed it; the builder is pure, so later cycles rebuild identically).
    let mut frame_count = 0usize;
    build_qr_response_display_frames(response_json, animated_chunk_size_chars, &mut |frame| {
        io.show_response_qr_frame(frame);
        frame_count += 1;
    })?;
    let cycles = if frame_count > 1 { animated_cycles } else { 1 };
    for _ in 1..cycles {
        // The rebuild cannot fail: the same pure inputs just built successfully.
        let rebuilt = build_qr_response_display_frames(
            response_json,
            animated_chunk_size_chars,
            &mut |frame| {
                io.show_response_qr_frame(frame);
            },
        );
        debug_assert!(rebuilt.is_ok());
    }
    Ok(frame_count * cycles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qr::envelope::tests::{
        decode_animated, decode_static, ANIMATED_FRAME_1, ANIMATED_FRAME_2, ANIMATED_FRAME_3,
    };
    use crate::qr::limits::{
        MAX_ANIMATED_QR_DECODED_JSON_BYTES, MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS,
    };
    use std::string::String;
    use std::vec::Vec;

    /// An owned frame record: (payload, index, total, animated).
    type FrameRecord = (Vec<u8>, usize, usize, bool);

    /// Collects frames as owned tuples (payload, index, total, animated).
    fn build_to_vec(
        response_json: &[u8],
        chunk: usize,
    ) -> Result<Vec<FrameRecord>, QrResponseDisplayError> {
        let mut frames = Vec::new();
        build_qr_response_display_frames(response_json, chunk, &mut |frame| {
            frames.push((
                Vec::from(frame.payload),
                frame.index,
                frame.total,
                frame.animated,
            ));
        })?;
        Ok(frames)
    }

    struct RecordingIo {
        frames: Vec<FrameRecord>,
    }

    impl QrResponseDisplayIo for RecordingIo {
        fn show_response_qr_frame(&mut self, frame: &QrResponseDisplayFrame<'_>) {
            self.frames.push((
                Vec::from(frame.payload),
                frame.index,
                frame.total,
                frame.animated,
            ));
        }
    }

    /// The C++ test helper response_json_with_content_bytes.
    fn response_json_with_content_bytes(content_bytes: usize) -> Vec<u8> {
        let mut json = Vec::from(
            &br#"{"version":1,"request_id":"req-response-display","ok":true,"result":{"content":""#
                [..],
        );
        json.extend(core::iter::repeat_n(b'a', content_bytes));
        json.extend_from_slice(br#""}}"#);
        json
    }

    // C++ test_qr_response_display_builds_static_frame_for_small_response.
    #[test]
    fn builds_static_frame_for_small_response() {
        let response_json =
            br#"{"version":1,"request_id":"req-static-response","ok":true,"result":{}}"#;
        let frames = build_to_vec(response_json, MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS).unwrap();
        assert_eq!(frames.len(), 1);
        let mut buf = [0u8; 2048];
        let expected = encode_qr_envelope_json(response_json, &mut buf).unwrap();
        assert_eq!(frames[0].0, expected);
        assert_eq!(frames[0].1, 1);
        assert_eq!(frames[0].2, 1);
        assert!(!frames[0].3);
    }

    // C++ test_qr_response_display_cycles_animated_frames_for_large_response.
    #[test]
    fn cycles_animated_frames_for_large_response() {
        let response_json = response_json_with_content_bytes(900);
        let frames = build_to_vec(&response_json, 48).unwrap();
        assert!(frames.len() > 1);
        for (offset, (payload, index, total, animated)) in frames.iter().enumerate() {
            assert!(payload.starts_with(b"nsealr1a:"));
            assert_eq!(*index, offset + 1);
            assert_eq!(*total, frames.len());
            assert!(*animated);
        }

        let encoded: Vec<&[u8]> = frames
            .iter()
            .map(|(payload, ..)| payload.as_slice())
            .collect();
        let (_, json) = decode_animated(&encoded).unwrap();
        assert_eq!(json, response_json);

        let mut io = RecordingIo { frames: Vec::new() };
        let displayed = run_qr_response_display_io(&mut io, &response_json, 48, 2).unwrap();
        assert_eq!(displayed, frames.len() * 2);
        assert_eq!(io.frames.len(), frames.len() * 2);
        assert_eq!(io.frames[0].0, frames[0].0);
        assert_eq!(io.frames[frames.len()].0, frames[0].0);
        assert_eq!(io.frames.last().unwrap().0, frames.last().unwrap().0);
    }

    // C++ test_qr_response_display_shows_static_frame_once.
    #[test]
    fn shows_static_frame_once() {
        let response_json = br#"{"version":1,"request_id":"req-static-response","ok":false,"error":{"code":"signing_disabled","message":"Signing is disabled.","retryable":false}}"#;
        let mut io = RecordingIo { frames: Vec::new() };
        let displayed = run_qr_response_display_io(
            &mut io,
            response_json,
            MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS,
            5,
        )
        .unwrap();
        assert_eq!(displayed, 1);
        assert_eq!(io.frames.len(), 1);
        assert!(!io.frames[0].3);
    }

    // C++ test_qr_response_display_rejects_invalid_json_and_bad_cycles.
    #[test]
    fn rejects_invalid_json_and_bad_cycles() {
        assert_eq!(
            build_to_vec(b"not json", MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS).unwrap_err(),
            QrResponseDisplayError::NotJsonObject,
        );
        assert_eq!(
            build_to_vec(&response_json_with_content_bytes(5000), 64).unwrap_err(),
            QrResponseDisplayError::Envelope(QrEnvelopeError::ExceedsAnimatedJsonBytes),
        );
        let ok = br#"{"version":1,"request_id":"req","ok":true,"result":{}}"#;
        let mut io = RecordingIo { frames: Vec::new() };
        assert_eq!(
            run_qr_response_display_io(&mut io, b"not json", 64, 1).unwrap_err(),
            QrResponseDisplayError::NotJsonObject,
        );
        assert_eq!(
            run_qr_response_display_io(&mut io, ok, 64, 0).unwrap_err(),
            QrResponseDisplayError::ZeroCycles,
        );
        assert_eq!(
            run_qr_response_display_io(&mut io, ok, 64, MAX_QR_RESPONSE_DISPLAY_CYCLES + 1)
                .unwrap_err(),
            QrResponseDisplayError::TooManyCycles,
        );
    }

    // C++ test_qr_response_display_rejects_non_response_payload_shapes.
    #[test]
    fn rejects_non_response_payload_shapes() {
        let chunk = MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS;
        assert_eq!(
            build_to_vec(br#"["not-a-response"]"#, chunk).unwrap_err(),
            QrResponseDisplayError::NotJsonObject,
        );
        assert_eq!(
            build_to_vec(
                br#"{"version":1,"request_id":"req-response-display","ok":true,"result":{},"extra":true}"#,
                chunk,
            )
            .unwrap_err(),
            QrResponseDisplayError::UnknownTopLevelField,
        );
        assert_eq!(
            build_to_vec(
                br#"{"version":1,"request_id":"req-response-display","ok":true}"#,
                chunk,
            )
            .unwrap_err(),
            QrResponseDisplayError::SuccessWithoutResultObject,
        );
        assert_eq!(
            build_to_vec(
                br#"{"version":1,"request_id":"req-response-display","ok":false,"result":{},"error":{}}"#,
                chunk,
            )
            .unwrap_err(),
            QrResponseDisplayError::ErrorWithResult,
        );
        assert_eq!(
            build_to_vec(
                br#"{"version":1,"request_id":"req-response-display","ok":true,"result":{"bad":?}}"#,
                chunk,
            )
            .unwrap_err(),
            QrResponseDisplayError::ResponseJsonMalformed,
        );
    }

    // C++ test_qr_response_display_rejects_shared_top_level_invalid_response_vectors.
    // Each response_json literal is copied byte-for-byte from the matching
    // specs/vectors/invalid/<name>.json fixture (`response`, canonical
    // serialization as pinned by the C++ generated vector header).
    #[test]
    fn rejects_shared_top_level_invalid_response_vectors() {
        let vectors: &[(&str, &[u8])] = &[
            ("response-error-with-result", br#"{"version":1,"request_id":"req-invalid-response-error-with-result","ok":false,"error":{"code":"user_rejected","message":"Rejected","retryable":false},"result":{"public_key":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"}}"#),
            ("response-request-id-invalid", br#"{"version":1,"request_id":"invalid response id","ok":true,"result":{"public_key":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"}}"#),
            ("response-unknown-top-level-field", br#"{"version":1,"request_id":"req-invalid-response-unknown-field","ok":false,"error":{"code":"user_rejected","message":"Rejected","retryable":false},"debug":"host-injected"}"#),
        ];
        for (name, response_json) in vectors {
            assert!(
                build_to_vec(response_json, MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS).is_err(),
                "unexpectedly accepted invalid QR response display vector: {name}",
            );
        }
    }

    // C++ test_qr_response_display_allows_nested_json_unicode_escapes.
    #[test]
    fn allows_nested_json_unicode_escapes() {
        // The C++ fed a raw string: the JSON carries the escape sequence
        // backslash-u2603 literally; the scanner validates it (collapsing to `?`
        // internally) and the encoded envelope preserves it byte-for-byte.
        let response_json = br#"{"version":1,"request_id":"req-response-display","ok":true,"result":{"content":"snowman \u2603"}}"#;
        let frames = build_to_vec(response_json, MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS).unwrap();
        assert_eq!(frames.len(), 1);
        let (_, json) = decode_static(&frames[0].0).unwrap();
        assert_eq!(json, response_json);
    }

    // --- Supplementary direct tests (fixture replay + branch coverage) ---

    // Replays specs/vectors/transports/qr-animated-response-kind-1-basic.json
    // through the display builder: the fixture's decoded JSON is 655 bytes
    // (< 704), so it builds as a *static* display frame (the animated encoding of
    // this fixture is pinned byte-for-byte by the envelope encoder test). Verify
    // the static frame round-trips to the fixture JSON.
    #[test]
    fn animated_response_fixture_replay() {
        let (_, json) =
            decode_animated(&[ANIMATED_FRAME_1, ANIMATED_FRAME_2, ANIMATED_FRAME_3]).unwrap();
        let frames = build_to_vec(&json, MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS).unwrap();
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].3);
        let (_, round_tripped) = decode_static(&frames[0].0).unwrap();
        assert_eq!(round_tripped, json);
    }

    #[test]
    fn scanner_tolerances_and_rejections() {
        let chunk = MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS;
        // Whitespace + nested arrays/objects/numbers with fraction+exponent +
        // literals inside result are all fine.
        let ok = br#" { "version" : 1 , "request_id" : "req-ws" , "ok" : true , "result" : { "nested" : [ 1.5e-3 , { "deep" : [ true , null , "s" ] } , -0.25E+2 ] } } "#;
        assert_eq!(build_to_vec(ok, chunk).unwrap().len(), 1);

        // Escapes in skipped strings: standard escapes ok, bad \u rejected.
        let ok = br#"{"version":1,"request_id":"req-esc","ok":true,"result":{"s":"a\"b\\c\/d\be\ff\ng\rh\ti"}}"#;
        assert_eq!(build_to_vec(ok, chunk).unwrap().len(), 1);
        let bad = br#"{"version":1,"request_id":"req-esc","ok":true,"result":{"s":"\uZZZZ"}}"#;
        assert_eq!(
            build_to_vec(bad, chunk).unwrap_err(),
            QrResponseDisplayError::ResponseJsonMalformed,
        );

        // version token other than exactly `1`.
        assert_eq!(
            build_to_vec(
                br#"{"version":"1","request_id":"r","ok":true,"result":{}}"#,
                chunk
            )
            .unwrap_err(),
            QrResponseDisplayError::BadVersion,
        );
        // Missing version entirely.
        assert_eq!(
            build_to_vec(br#"{"request_id":"r","ok":true,"result":{}}"#, chunk).unwrap_err(),
            QrResponseDisplayError::BadVersion,
        );
        // ok not a boolean.
        assert_eq!(
            build_to_vec(
                br#"{"version":1,"request_id":"r","ok":"yes","result":{}}"#,
                chunk
            )
            .unwrap_err(),
            QrResponseDisplayError::OkNotBoolean,
        );
        // ok:false shapes.
        assert_eq!(
            build_to_vec(br#"{"version":1,"request_id":"r","ok":false}"#, chunk).unwrap_err(),
            QrResponseDisplayError::ErrorWithoutErrorObject,
        );
        assert_eq!(
            build_to_vec(
                br#"{"version":1,"request_id":"r","ok":false,"error":[]}"#,
                chunk
            )
            .unwrap_err(),
            QrResponseDisplayError::ErrorWithoutErrorObject,
        );
        // ok:true with error present.
        assert_eq!(
            build_to_vec(
                br#"{"version":1,"request_id":"r","ok":true,"result":{},"error":{}}"#,
                chunk,
            )
            .unwrap_err(),
            QrResponseDisplayError::SuccessWithError,
        );
        // ok:true with non-object result.
        assert_eq!(
            build_to_vec(
                br#"{"version":1,"request_id":"r","ok":true,"result":[]}"#,
                chunk
            )
            .unwrap_err(),
            QrResponseDisplayError::SuccessWithoutResultObject,
        );
        // Empty object -> version required (empty-object branch).
        assert_eq!(
            build_to_vec(b"{}", chunk).unwrap_err(),
            QrResponseDisplayError::BadVersion,
        );
        // A key longer than any known member name is an unknown field (the
        // decoder truncates it past the known-key buffer).
        assert_eq!(
            build_to_vec(
                br#"{"version":1,"request_id":"r","ok":true,"result":{},"a_key_longer_than_any_known":1}"#,
                chunk,
            )
            .unwrap_err(),
            QrResponseDisplayError::UnknownTopLevelField,
        );
        // ok:false with a well-formed error object is a valid error shape.
        let ok = br#"{"version":1,"request_id":"r","ok":false,"error":{"code":"user_rejected","message":"no","retryable":false}}"#;
        assert_eq!(build_to_vec(ok, chunk).unwrap().len(), 1);
    }

    #[test]
    fn scanner_structural_rejections() {
        let chunk = MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS;
        let cases: &[&[u8]] = &[
            b"",                         // empty -> not an object
            b"{\"version\":1",           // unterminated object
            b"{\"version\"1}",           // missing ':'
            b"{\"version\":1 \"x\":2}",  // bad member separator
            b"{\"version\":1}trailing",  // trailing data
            b"{\"k\":\"unterminated}",   // unterminated string
            b"{\"k\":\"bad\\zescape\"}", // unsupported escape
            b"{\"k\":\"trunc\\",         // truncated escape
            b"{\"k\":\"ctl\x01\"}",      // control character
            b"{\"k\":[1,2}",             // malformed array
            b"{\"k\":[1,2",              // unterminated array
            b"{\"k\":[1,",               // array cut after comma
            b"{\"k\":{\"a\":1,}}",       // object trailing comma junk
            b"{\"k\":{\"a\" 1}}",        // nested object missing ':'
            b"{\"k\":{\"a\":1;}}",       // scalar token swallows ';' -> invalid
            b"{\"k\":{\"a\":\"v\";}}",   // nested object bad member separator
            b"{\"k\":{\"a\":1,",         // nested object cut after comma
            b"{\"k\":",                  // value missing at end of input
            b"{123:1}",                  // non-string top-level key
            b"{\"request_id\":123}",     // request_id that is not a string
            b"{\"k\":00}",               // invalid number (leading zero)
            b"{\"k\":1.}",               // invalid fraction
            b"{\"k\":1e}",               // invalid exponent
            b"{\"k\":-}",                // bare minus
            b"{\"k\":nope}",             // invalid literal
            b"{\"k\":}",                 // missing value
        ];
        for (index, json) in cases.iter().enumerate() {
            assert_eq!(
                build_to_vec(json, chunk).unwrap_err(),
                if index == 0 {
                    QrResponseDisplayError::NotJsonObject
                } else {
                    QrResponseDisplayError::ResponseJsonMalformed
                },
                "case {index}",
            );
        }
    }

    #[test]
    fn request_id_rule_matches_shared_charset() {
        let chunk = MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS;
        // Allowed charset: A-Z a-z 0-9 . _ : -
        let ok = br#"{"version":1,"request_id":"AZaz09._:-","ok":true,"result":{}}"#;
        assert_eq!(build_to_vec(ok, chunk).unwrap().len(), 1);
        // Empty and over-long are invalid.
        assert_eq!(
            build_to_vec(
                br#"{"version":1,"request_id":"","ok":true,"result":{}}"#,
                chunk
            )
            .unwrap_err(),
            QrResponseDisplayError::BadRequestId,
        );
        let mut long_id = String::from(r#"{"version":1,"request_id":""#);
        long_id.extend(core::iter::repeat_n('a', MAX_REQUEST_ID_LENGTH + 1));
        long_id.push_str(r#"","ok":true,"result":{}}"#);
        assert_eq!(
            build_to_vec(long_id.as_bytes(), chunk).unwrap_err(),
            QrResponseDisplayError::BadRequestId,
        );
    }

    // The animated threshold boundary: exactly MAX_STATIC bytes stays static; one
    // byte over goes animated. Chunk them and decode back.
    #[test]
    fn static_animated_threshold_boundary() {
        let scaffold_len = response_json_with_content_bytes(0).len();

        // Exactly 704-byte JSON: static.
        let at_limit =
            response_json_with_content_bytes(MAX_STATIC_QR_DECODED_JSON_BYTES - scaffold_len);
        assert_eq!(at_limit.len(), MAX_STATIC_QR_DECODED_JSON_BYTES);
        let frames = build_to_vec(&at_limit, MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS).unwrap();
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].3);

        // 705-byte JSON: animated.
        let over_limit =
            response_json_with_content_bytes(MAX_STATIC_QR_DECODED_JSON_BYTES + 1 - scaffold_len);
        assert_eq!(over_limit.len(), MAX_STATIC_QR_DECODED_JSON_BYTES + 1);
        let frames = build_to_vec(&over_limit, MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS).unwrap();
        assert!(frames.len() > 1);
        assert!(frames.iter().all(|(.., animated)| *animated));
        let encoded: Vec<&[u8]> = frames.iter().map(|(p, ..)| p.as_slice()).collect();
        let (_, json) = decode_animated(&encoded).unwrap();
        assert_eq!(json, over_limit);
        assert!(json.len() <= MAX_ANIMATED_QR_DECODED_JSON_BYTES);
    }

    // io loop with cycles=1 on an animated response shows each frame exactly once.
    #[test]
    fn io_single_cycle_animated() {
        let response_json = response_json_with_content_bytes(900);
        let mut io = RecordingIo { frames: Vec::new() };
        let displayed = run_qr_response_display_io(&mut io, &response_json, 48, 1).unwrap();
        assert_eq!(displayed, io.frames.len());
        assert!(displayed > 1);
        for (offset, (_, index, total, animated)) in io.frames.iter().enumerate() {
            assert_eq!(*index, offset + 1);
            assert_eq!(*total, io.frames.len());
            assert!(*animated);
        }
    }
}
