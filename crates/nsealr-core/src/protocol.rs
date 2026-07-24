//! Device serial protocol — frame in, response frame out, review preview.
//!
//! Ported from the C++ reference `host_core` sources `src/device_protocol.cpp` +
//! `include/nsealr/device_protocol.hpp` for behaviour parity: the same
//! signer-identity gate at entry, the same request-frame decode, the same
//! lenient metadata JSON scanner (`version`/`request_id`/`method`/`params`,
//! unknown top-level fields flagged), the same
//! `get_capabilities`/`get_public_key`/`get_signing_status`/`sign_event`
//! dispatch with byte-identical response JSON, the same
//! `{"error":"unsupported_request"}` error frame for every rejected request,
//! and the same trusted-review preview (frame + session) on `sign_event`.
//!
//! The C++ default-context overloads map to passing
//! [`development_device_protocol_context`] explicitly. The C++ returned heap
//! strings; this port renders the response frame into the fixed
//! [`ResponseFrame`] buffer. The C++ threw `SerialFrameError` for transport
//! and metadata-JSON faults; this port returns [`DeviceProtocolError`] values
//! (the metadata scanner's distinct C++ messages collapse into
//! [`DeviceProtocolError::RequestJsonMalformed`], like the envelope parser's
//! `RequestJsonMalformed` in M-T3.3).
//!
//! `\uXXXX` offset-on-error semantics (M-T3.2 carried note): on an invalid or
//! truncated `\uXXXX` escape [`crate::unicode::append_json_unicode_escape`]
//! leaves the offset **on** the offending byte where the C++ helper advanced
//! past it. This scanner (like the envelope parser) fails the whole parse on
//! that error, so the divergence is unobservable in any output.

use crate::base64url::{decode_base64url, encode_base64url, encoded_len, Base64UrlError};
use crate::policy::signing_policy::{
    evaluate_signing_readiness, SigningGateNames, SigningReadiness,
};
use crate::qr::envelope::is_request_id;
use crate::qr::limits::{MAX_DECODED_REQUEST_JSON_BYTES, MAX_SERIAL_FRAME_BYTES};
use crate::review::display::{ReviewDisplayFrame, ReviewDisplayLimits};
use crate::review::serial::{begin_serial_sign_event_trusted_review, SerialReviewError};
use crate::review::signer_identity::{is_valid_nostr_public_key, SignerIdentity};
use crate::review::trusted::TrustedReviewSession;
use crate::serial::frame::{decode_serial_frame, encode_serial_frame, FrameType, SerialFrameError};
use crate::unicode::{append_json_unicode_escape, is_valid_utf8};
use core::fmt;

/// Maximum decoded `request_id` bytes the metadata scanner keeps (the shared
/// request-id length rule; longer ids can never validate).
const MAX_METADATA_REQUEST_ID: usize = 128;
/// Maximum decoded `method` bytes kept (the longest supported method is
/// `get_signing_status`, 18 bytes; longer methods can never match).
const MAX_METADATA_METHOD: usize = 24;
/// Maximum rendered response JSON bytes (capability response with a maximum
/// request id is ~590 bytes; 768 leaves headroom).
const MAX_RESPONSE_JSON_BYTES: usize = 768;

/// The pre-encoded `{"error":"unsupported_request"}` payload (the C++
/// `unsupported_request_frame` literal).
const UNSUPPORTED_PAYLOAD: &[u8] = b"eyJlcnJvciI6InVuc3VwcG9ydGVkX3JlcXVlc3QifQ";

/// The device protocol context. Mirrors the C++ `DeviceProtocolContext`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceProtocolContext<'a> {
    /// The signer identity responses and reviews are bound to.
    pub signer_identity: SignerIdentity<'a>,
}

/// Returns the development context. Mirrors the C++
/// `development_device_protocol_context`.
#[must_use]
pub const fn development_device_protocol_context() -> DeviceProtocolContext<'static> {
    DeviceProtocolContext {
        signer_identity: SignerIdentity::development_fixture(),
    }
}

/// Errors reported by the protocol handler. Every variant corresponds to a C++
/// throw site (the C++ returned the unsupported-request *frame*, not an error,
/// for malformed request semantics — this port does the same).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceProtocolError {
    /// The context signer identity is invalid. C++ `SignerIdentityError`.
    InvalidSignerIdentity,
    /// A serial-frame decode failure. C++ `SerialFrameError` (transport).
    Frame(SerialFrameError),
    /// The frame payload was not decodable base64url. C++ `SerialFrameError`
    /// ("serial frame payload has invalid trailing bits" / "… must be unpadded
    /// base64url").
    Payload(Base64UrlError),
    /// The request metadata JSON failed the scanner grammar. C++: the distinct
    /// `SerialFrameError` messages of `parse_json_string`/`skip_json_value`/
    /// `parse_request_metadata`, collapsed into one variant.
    RequestJsonMalformed,
    /// A `sign_event` review failure that is not a request-shape rejection
    /// (the C++ caught only `QrEnvelopeError`; anything else propagated).
    Review(SerialReviewError),
    /// A rendered response exceeded the fixed buffers. No C++ analogue.
    Capacity,
}

impl fmt::Display for DeviceProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSignerIdentity => "signer public key must be 64 lowercase hex characters",
            Self::Frame(_) => "serial frame rejected",
            Self::Payload(_) => "serial frame payload must be unpadded base64url",
            Self::RequestJsonMalformed => "request JSON is malformed",
            Self::Review(inner) => inner.message(),
            Self::Capacity => "device protocol response exceeds fixed capacity",
        })
    }
}

/// A rendered serial response frame (single line, `\n`-terminated), bounded by
/// [`MAX_SERIAL_FRAME_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseFrame {
    bytes: [u8; MAX_SERIAL_FRAME_BYTES],
    len: usize,
}

impl ResponseFrame {
    /// The frame bytes (including the trailing `\n`).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The frame as text (serial frames are ASCII).
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }
}

impl PartialEq<&[u8]> for ResponseFrame {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_bytes() == *other
    }
}

/// The handler result. Mirrors the C++ `SerialFrameHandlingResult`.
#[derive(Debug, Clone)]
pub struct SerialFrameHandlingResult {
    /// The response frame to send back.
    pub response_frame: ResponseFrame,
    /// The first review frame, when the request opened a trusted review.
    pub review_frame: Option<ReviewDisplayFrame>,
    /// The live review session, when the request opened a trusted review.
    pub review_session: Option<TrustedReviewSession>,
}

/// Handles one serial line, returning only the response frame. Mirrors the C++
/// two-argument `handle_serial_frame` (the default-context C++ overload maps
/// to passing [`development_device_protocol_context`]).
///
/// # Errors
///
/// See [`DeviceProtocolError`].
pub fn handle_serial_frame(
    line: &[u8],
    context: &DeviceProtocolContext<'_>,
) -> Result<ResponseFrame, DeviceProtocolError> {
    Ok(
        handle_serial_frame_with_review_preview(line, context, ReviewDisplayLimits::default())?
            .response_frame,
    )
}

/// Handles one serial line with a trusted-review preview on `sign_event`.
/// Mirrors the C++ `handle_serial_frame_with_review_preview`.
///
/// # Errors
///
/// See [`DeviceProtocolError`].
pub fn handle_serial_frame_with_review_preview(
    line: &[u8],
    context: &DeviceProtocolContext<'_>,
    limits: ReviewDisplayLimits,
) -> Result<SerialFrameHandlingResult, DeviceProtocolError> {
    if !is_valid_nostr_public_key(context.signer_identity.public_key) {
        return Err(DeviceProtocolError::InvalidSignerIdentity);
    }
    let request = decode_serial_frame(line).map_err(DeviceProtocolError::Frame)?;
    if request.frame_type != FrameType::Request {
        return unsupported();
    }

    let mut json_buf = [0u8; MAX_SERIAL_FRAME_BYTES];
    let request_json = decode_base64url(request.payload_base64url, &mut json_buf)
        .map_err(DeviceProtocolError::Payload)?;
    if request_json.len() > MAX_DECODED_REQUEST_JSON_BYTES {
        return unsupported();
    }
    if !is_valid_utf8(request_json) {
        return unsupported();
    }
    let metadata = parse_request_metadata(request_json)?;
    if !metadata.version_one
        || !is_request_id(metadata.request_id())
        || metadata.has_unknown_top_level_field
    {
        return unsupported();
    }
    match metadata.method() {
        b"get_capabilities" => {
            if metadata.has_params {
                return unsupported();
            }
            let mut json = ResponseJson::new();
            json.push(r#"{"version":1,"request_id":""#);
            json.push_bytes(metadata.request_id());
            json.push(r#"","ok":true,"result":{"capabilities":{"device":{"name":"nSealr ESP32-S3 USB Signer Scaffold","firmware":"nsealr-esp32-s3-usb-signer","hardware":"esp32-s3-devkitc-1"},"protocols":["nsealr.signing.v0","nsealr.serial-frame.v0"],"methods":["get_capabilities","get_signing_status","get_public_key","sign_event"],"transports":["usb-serial-jtag"],"signing_enabled":false,"requires_physical_approval":true}}}"#);
            respond(&json)
        }
        b"get_public_key" => {
            if metadata.has_params {
                return unsupported();
            }
            // The C++ re-validated the identity inside
            // `public_key_response_json`; the entry gate above already proved
            // the same property for the same identity.
            let mut json = ResponseJson::new();
            json.push(r#"{"version":1,"request_id":""#);
            json.push_bytes(metadata.request_id());
            json.push(r#"","ok":true,"result":{"public_key":""#);
            json.push(context.signer_identity.public_key);
            json.push(r#""}}"#);
            respond(&json)
        }
        b"get_signing_status" => {
            if metadata.has_params {
                return unsupported();
            }
            let status = evaluate_signing_readiness(&scaffold_signing_readiness());
            let mut json = ResponseJson::new();
            json.push(r#"{"version":1,"request_id":""#);
            json.push_bytes(metadata.request_id());
            json.push(r#"","ok":true,"result":{"signing_status":{"signing_enabled":false,"missing_gates":["#);
            push_gates_json(&mut json, &status.missing_gates);
            json.push(r#"],"development_accepted_gates":["#);
            push_gates_json(&mut json, &status.development_accepted_gates);
            json.push(r#"]}}}"#);
            respond(&json)
        }
        b"sign_event" => {
            let request_text =
                core::str::from_utf8(request_json).map_err(|_| DeviceProtocolError::Capacity)?;
            let session = match begin_serial_sign_event_trusted_review(
                request_text,
                context.signer_identity,
                limits,
            ) {
                Ok(session) => session,
                // The C++ caught QrEnvelopeError only; any other failure
                // propagated as an exception.
                Err(SerialReviewError::Envelope(_)) => return unsupported(),
                Err(error) => return Err(DeviceProtocolError::Review(error)),
            };
            let review_frame = session
                .current_frame()
                .map_err(|error| DeviceProtocolError::Review(SerialReviewError::Display(error)))?;
            let mut json = ResponseJson::new();
            json.push(r#"{"version":1,"request_id":""#);
            json.push_bytes(metadata.request_id());
            json.push(r#"","ok":false,"error":{"code":"signing_disabled","message":"Signing is disabled until trusted review and physical approval are implemented.","retryable":false}}"#);
            let mut result = respond(&json)?;
            result.review_frame = Some(review_frame);
            result.review_session = Some(session);
            Ok(result)
        }
        _ => unsupported(),
    }
}

/// The scaffold signing readiness (parser limits + digest binding satisfied,
/// four development-accepted gates). Mirrors the C++
/// `scaffold_signing_readiness`.
fn scaffold_signing_readiness() -> SigningReadiness {
    let mut development_accepted_gates = SigningGateNames::new();
    for gate in [
        "parser_limits",
        "trusted_review_display",
        "physical_approval_controls",
        "approval_digest_binding",
    ] {
        development_accepted_gates
            .try_push(gate)
            .expect("four fixed gates fit the list");
    }
    SigningReadiness {
        parser_limits_enforced: true,
        approval_digest_binding_verified: true,
        development_accepted_gates,
        ..SigningReadiness::default()
    }
}

/// Appends the `"a","b"` gate list body. Mirrors the C++ `gates_json`.
fn push_gates_json(json: &mut ResponseJson, gates: &SigningGateNames) {
    for (index, gate) in gates.as_slice().iter().enumerate() {
        if index > 0 {
            json.push(",");
        }
        json.push("\"");
        json.push(gate.as_str());
        json.push("\"");
    }
}

/// A bounded response-JSON writer (request ids and gate names contain no JSON
/// specials, so the C++ concatenated them unescaped — same here).
struct ResponseJson {
    bytes: [u8; MAX_RESPONSE_JSON_BYTES],
    len: usize,
}

impl ResponseJson {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_RESPONSE_JSON_BYTES],
            len: 0,
        }
    }

    fn push(&mut self, text: &str) {
        self.push_bytes(text.as_bytes());
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Renders the unsupported-request error frame result. Mirrors the C++
/// `unsupported_request_frame` + `encode_serial_frame`.
fn unsupported() -> Result<SerialFrameHandlingResult, DeviceProtocolError> {
    let mut frame = ResponseFrame {
        bytes: [0; MAX_SERIAL_FRAME_BYTES],
        len: 0,
    };
    let written = encode_serial_frame(FrameType::Error, UNSUPPORTED_PAYLOAD, &mut frame.bytes)
        .map_err(|_| DeviceProtocolError::Capacity)?
        .len();
    frame.len = written;
    Ok(SerialFrameHandlingResult {
        response_frame: frame,
        review_frame: None,
        review_session: None,
    })
}

/// Renders a response frame from response JSON. Mirrors the C++
/// `response_frame` helper.
fn respond(json: &ResponseJson) -> Result<SerialFrameHandlingResult, DeviceProtocolError> {
    let mut payload = [0u8; encoded_len(MAX_RESPONSE_JSON_BYTES)];
    let payload_len = encode_base64url(json.as_bytes(), &mut payload)
        .map_err(|_| DeviceProtocolError::Capacity)?
        .len();
    let mut frame = ResponseFrame {
        bytes: [0; MAX_SERIAL_FRAME_BYTES],
        len: 0,
    };
    let written = encode_serial_frame(
        FrameType::Response,
        &payload[..payload_len],
        &mut frame.bytes,
    )
    .map_err(|_| DeviceProtocolError::Capacity)?
    .len();
    frame.len = written;
    Ok(SerialFrameHandlingResult {
        response_frame: frame,
        review_frame: None,
        review_session: None,
    })
}

// --- Request metadata scanner -------------------------------------------

/// The scanned top-level request metadata. Mirrors the C++ `RequestMetadata`.
struct RequestMetadata {
    version_one: bool,
    has_unknown_top_level_field: bool,
    has_params: bool,
    request_id: [u8; MAX_METADATA_REQUEST_ID],
    request_id_len: usize,
    request_id_overflow: bool,
    method: [u8; MAX_METADATA_METHOD],
    method_len: usize,
    method_overflow: bool,
}

impl RequestMetadata {
    fn new() -> Self {
        Self {
            version_one: false,
            has_unknown_top_level_field: false,
            has_params: false,
            request_id: [0; MAX_METADATA_REQUEST_ID],
            request_id_len: 0,
            request_id_overflow: false,
            method: [0; MAX_METADATA_METHOD],
            method_len: 0,
            method_overflow: false,
        }
    }

    /// The decoded request id (empty on overflow — an over-long id can never
    /// validate, exactly as the C++ length rule rejected it).
    fn request_id(&self) -> &[u8] {
        if self.request_id_overflow {
            b""
        } else {
            &self.request_id[..self.request_id_len]
        }
    }

    /// The decoded method (empty on overflow — an over-long method can never
    /// match a supported name).
    fn method(&self) -> &[u8] {
        if self.method_overflow {
            b""
        } else {
            &self.method[..self.method_len]
        }
    }
}

/// Mirrors the C++ `skip_ws` in `device_protocol.cpp`.
fn skip_ws(json: &[u8], offset: &mut usize) {
    while *offset < json.len() {
        if !matches!(json[*offset], b' ' | b'\n' | b'\r' | b'\t') {
            return;
        }
        *offset += 1;
    }
}

/// Mirrors the C++ `parse_json_string` in `device_protocol.cpp` (decodes the
/// standard escapes and `\uXXXX`; unlike the envelope parser it does not
/// reject raw control bytes). Decoded bytes go to `sink`.
fn parse_json_string(
    json: &[u8],
    offset: &mut usize,
    sink: &mut dyn FnMut(&[u8]),
) -> Result<(), DeviceProtocolError> {
    if *offset >= json.len() || json[*offset] != b'"' {
        return Err(DeviceProtocolError::RequestJsonMalformed);
    }
    *offset += 1;
    while *offset < json.len() {
        let ch = json[*offset];
        *offset += 1;
        if ch == b'"' {
            return Ok(());
        }
        if ch == b'\\' {
            if *offset >= json.len() {
                return Err(DeviceProtocolError::RequestJsonMalformed);
            }
            let escaped = json[*offset];
            *offset += 1;
            match escaped {
                b'"' | b'\\' | b'/' => sink(&[escaped]),
                b'b' => sink(b"\x08"),
                b'f' => sink(b"\x0c"),
                b'n' => sink(b"\n"),
                b'r' => sink(b"\r"),
                b't' => sink(b"\t"),
                b'u' => {
                    let mut utf8 = [0u8; 4];
                    let fragment = append_json_unicode_escape(json, offset, &mut utf8)
                        .map_err(|_| DeviceProtocolError::RequestJsonMalformed)?;
                    sink(fragment);
                }
                _ => return Err(DeviceProtocolError::RequestJsonMalformed),
            }
            continue;
        }
        sink(&[ch]);
    }
    Err(DeviceProtocolError::RequestJsonMalformed)
}

/// Mirrors the C++ `skip_json_value` in `device_protocol.cpp` (strings and
/// containers parsed structurally; primitive tokens skipped without grammar
/// validation, unlike the envelope parser).
fn skip_json_value(json: &[u8], offset: &mut usize) -> Result<(), DeviceProtocolError> {
    skip_ws(json, offset);
    if *offset >= json.len() {
        return Err(DeviceProtocolError::RequestJsonMalformed);
    }
    if json[*offset] == b'"' {
        return parse_json_string(json, offset, &mut |_| {});
    }
    if json[*offset] == b'{' {
        *offset += 1;
        loop {
            skip_ws(json, offset);
            if *offset >= json.len() {
                return Err(DeviceProtocolError::RequestJsonMalformed);
            }
            if json[*offset] == b'}' {
                *offset += 1;
                return Ok(());
            }
            parse_json_string(json, offset, &mut |_| {})?;
            skip_ws(json, offset);
            if *offset >= json.len() || json[*offset] != b':' {
                return Err(DeviceProtocolError::RequestJsonMalformed);
            }
            *offset += 1;
            skip_json_value(json, offset)?;
            skip_ws(json, offset);
            if *offset < json.len() && json[*offset] == b',' {
                *offset += 1;
                continue;
            }
            if *offset < json.len() && json[*offset] == b'}' {
                *offset += 1;
                return Ok(());
            }
            return Err(DeviceProtocolError::RequestJsonMalformed);
        }
    }
    if json[*offset] == b'[' {
        *offset += 1;
        loop {
            skip_ws(json, offset);
            if *offset >= json.len() {
                return Err(DeviceProtocolError::RequestJsonMalformed);
            }
            if json[*offset] == b']' {
                *offset += 1;
                return Ok(());
            }
            skip_json_value(json, offset)?;
            skip_ws(json, offset);
            if *offset < json.len() && json[*offset] == b',' {
                *offset += 1;
                continue;
            }
            if *offset < json.len() && json[*offset] == b']' {
                *offset += 1;
                return Ok(());
            }
            return Err(DeviceProtocolError::RequestJsonMalformed);
        }
    }
    while *offset < json.len() {
        if matches!(
            json[*offset],
            b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t'
        ) {
            return Ok(());
        }
        *offset += 1;
    }
    Ok(())
}

/// Mirrors the C++ `parse_request_metadata` in `device_protocol.cpp`,
/// including its leniencies (no trailing-data check after the closing brace,
/// missing commas tolerated at end of input).
fn parse_request_metadata(json: &[u8]) -> Result<RequestMetadata, DeviceProtocolError> {
    let mut offset = 0usize;
    skip_ws(json, &mut offset);
    if offset >= json.len() || json[offset] != b'{' {
        return Err(DeviceProtocolError::RequestJsonMalformed);
    }
    offset += 1;

    let mut metadata = RequestMetadata::new();
    loop {
        skip_ws(json, &mut offset);
        if offset >= json.len() {
            return Err(DeviceProtocolError::RequestJsonMalformed);
        }
        if json[offset] == b'}' {
            // The C++ advanced past the brace before breaking; nothing reads
            // the offset afterwards (no trailing-data check, by design).
            break;
        }
        let mut key = [0u8; 16];
        let mut key_len = 0usize;
        parse_json_string(json, &mut offset, &mut |fragment| {
            for &byte in fragment {
                if key_len < key.len() {
                    key[key_len] = byte;
                }
                key_len += 1;
            }
        })?;
        skip_ws(json, &mut offset);
        if offset >= json.len() || json[offset] != b':' {
            return Err(DeviceProtocolError::RequestJsonMalformed);
        }
        offset += 1;
        skip_ws(json, &mut offset);
        match &key[..key_len.min(key.len())] {
            b"request_id" => {
                let request_id = &mut metadata.request_id;
                let request_id_len = &mut metadata.request_id_len;
                let overflow = &mut metadata.request_id_overflow;
                parse_json_string(json, &mut offset, &mut |fragment| {
                    for &byte in fragment {
                        if *request_id_len < request_id.len() {
                            request_id[*request_id_len] = byte;
                            *request_id_len += 1;
                        } else {
                            *overflow = true;
                        }
                    }
                })?;
            }
            b"method" => {
                let method = &mut metadata.method;
                let method_len = &mut metadata.method_len;
                let overflow = &mut metadata.method_overflow;
                parse_json_string(json, &mut offset, &mut |fragment| {
                    for &byte in fragment {
                        if *method_len < method.len() {
                            method[*method_len] = byte;
                            *method_len += 1;
                        } else {
                            *overflow = true;
                        }
                    }
                })?;
            }
            b"version" => {
                let token_start = offset;
                skip_json_value(json, &mut offset)?;
                metadata.version_one = &json[token_start..offset] == b"1";
            }
            b"params" => {
                metadata.has_params = true;
                skip_json_value(json, &mut offset)?;
            }
            _ => {
                metadata.has_unknown_top_level_field = true;
                skip_json_value(json, &mut offset)?;
            }
        }
        skip_ws(json, &mut offset);
        if offset < json.len() && json[offset] == b',' {
            offset += 1;
        }
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::controls::ReviewButton;
    use crate::review::test_fixtures::frame_lines_contain;
    use crate::serial::frame::SerialFrame;
    use std::string::String;
    use std::vec::Vec;

    fn dev() -> DeviceProtocolContext<'static> {
        development_device_protocol_context()
    }

    /// The C++ `request_frame_for_test` (encode a request frame over the
    /// base64url-encoded JSON).
    fn frame_for_test(frame_type: FrameType, json: &str) -> Vec<u8> {
        let mut payload = [0u8; encoded_len(MAX_RESPONSE_JSON_BYTES)];
        let payload = encode_base64url(json.as_bytes(), &mut payload).unwrap();
        let mut out = [0u8; MAX_SERIAL_FRAME_BYTES];
        Vec::from(encode_serial_frame(frame_type, payload, &mut out).unwrap())
    }

    fn request_frame_for_test(json: &str) -> Vec<u8> {
        frame_for_test(FrameType::Request, json)
    }

    fn response_frame_for_test(json: &str) -> Vec<u8> {
        frame_for_test(FrameType::Response, json)
    }

    fn error_frame_for_test(json: &str) -> Vec<u8> {
        frame_for_test(FrameType::Error, json)
    }

    /// Request/response JSON copied from the READ-ONLY
    /// specs/vectors/devices/esp32-s3-capabilities-scaffold.json (the C++
    /// consumed them as kCapabilityRequestFrame/kCapabilityResponseFrame).
    const CAPABILITY_REQUEST_JSON: &str = r#"{"version":1,"request_id":"req-capabilities-esp32-s3-scaffold","method":"get_capabilities"}"#;
    const CAPABILITY_RESPONSE_JSON: &str = r#"{"version":1,"request_id":"req-capabilities-esp32-s3-scaffold","ok":true,"result":{"capabilities":{"device":{"name":"nSealr ESP32-S3 USB Signer Scaffold","firmware":"nsealr-esp32-s3-usb-signer","hardware":"esp32-s3-devkitc-1"},"protocols":["nsealr.signing.v0","nsealr.serial-frame.v0"],"methods":["get_capabilities","get_signing_status","get_public_key","sign_event"],"transports":["usb-serial-jtag"],"signing_enabled":false,"requires_physical_approval":true}}}"#;

    /// Request/response JSON copied from the READ-ONLY
    /// specs/vectors/devices/esp32-s3-sign-event-disabled.json.
    const SIGN_EVENT_REQUEST_JSON: &str = r#"{"version":1,"request_id":"req-kind-1-basic","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"nSealr fixture: basic kind 1 event."}}}"#;
    const SIGN_EVENT_DISABLED_RESPONSE_JSON: &str = r#"{"version":1,"request_id":"req-kind-1-basic","ok":false,"error":{"code":"signing_disabled","message":"Signing is disabled until trusted review and physical approval are implemented.","retryable":false}}"#;

    /// Request/response JSON copied from the READ-ONLY
    /// specs/vectors/devices/esp32-s3-signing-status-disabled.json.
    const SIGNING_STATUS_REQUEST_JSON: &str = r#"{"version":1,"request_id":"req-signing-status-esp32-s3-scaffold","method":"get_signing_status"}"#;
    const SIGNING_STATUS_RESPONSE_JSON: &str = r#"{"version":1,"request_id":"req-signing-status-esp32-s3-scaffold","ok":true,"result":{"signing_status":{"signing_enabled":false,"missing_gates":["runtime_signing_feature","trusted_review_display","physical_approval_controls","unicode_review_rendering","key_provisioning","source_public_key_proof","secure_boot","flash_encryption","debug_lock","companion_signed_output_verification"],"development_accepted_gates":["parser_limits","trusted_review_display","physical_approval_controls","approval_digest_binding"]}}}"#;

    /// Request/response JSON copied from the READ-ONLY
    /// specs/vectors/devices/esp32-s3-get-public-key-dev.json.
    const PUBLIC_KEY_REQUEST_JSON: &str =
        r#"{"version":1,"request_id":"req-pubkey-1","method":"get_public_key"}"#;
    const PUBLIC_KEY_RESPONSE_JSON: &str = r#"{"version":1,"request_id":"req-pubkey-1","ok":true,"result":{"public_key":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"}}"#;

    const UNSUPPORTED_RESPONSE_JSON: &str = r#"{"error":"unsupported_request"}"#;

    /// Decodes a response frame's payload for payload-level assertions.
    fn decoded_frame(frame: &ResponseFrame) -> (FrameType, Vec<u8>) {
        let decoded: SerialFrame<'_> = decode_serial_frame(frame.as_bytes()).unwrap();
        (decoded.frame_type, Vec::from(decoded.payload_base64url))
    }

    // Port of the C++ `test_device_protocol_reports_scaffold_capabilities`.
    #[test]
    fn reports_scaffold_capabilities() {
        let response =
            handle_serial_frame(&request_frame_for_test(CAPABILITY_REQUEST_JSON), &dev()).unwrap();

        assert_eq!(
            response.as_bytes(),
            response_frame_for_test(CAPABILITY_RESPONSE_JSON).as_slice(),
        );
        let (frame_type, payload) = decoded_frame(&response);
        assert_eq!(frame_type, FrameType::Response);
        let mut expected_payload = [0u8; encoded_len(MAX_RESPONSE_JSON_BYTES)];
        let expected_payload =
            encode_base64url(CAPABILITY_RESPONSE_JSON.as_bytes(), &mut expected_payload).unwrap();
        assert_eq!(payload, expected_payload);
    }

    // Port of the C++ `test_device_protocol_rejects_signing_while_disabled`.
    #[test]
    fn rejects_signing_while_disabled() {
        let response =
            handle_serial_frame(&request_frame_for_test(SIGN_EVENT_REQUEST_JSON), &dev()).unwrap();

        assert_eq!(
            response.as_bytes(),
            response_frame_for_test(SIGN_EVENT_DISABLED_RESPONSE_JSON).as_slice(),
        );
        let (frame_type, _) = decoded_frame(&response);
        assert_eq!(frame_type, FrameType::Response);
    }

    // Port of the C++
    // `test_device_protocol_exposes_review_frame_before_disabled_signing_response`.
    #[test]
    fn exposes_review_frame_before_disabled_signing_response() {
        let result = handle_serial_frame_with_review_preview(
            &request_frame_for_test(SIGN_EVENT_REQUEST_JSON),
            &dev(),
            ReviewDisplayLimits {
                max_title_chars: 18,
                max_body_lines: 5,
                max_line_chars: 26,
                ..ReviewDisplayLimits::default()
            },
        )
        .unwrap();

        assert_eq!(
            result.response_frame.as_bytes(),
            response_frame_for_test(SIGN_EVENT_DISABLED_RESPONSE_JSON).as_slice(),
        );
        let review_frame = result.review_frame.unwrap();
        assert_eq!(review_frame.title, "Event");
        assert_eq!(review_frame.page_indicator, "Page 1/4");
        assert!(!review_frame.body_lines.is_empty());
        assert_eq!(review_frame.body_lines.as_slice()[0], "Kind 1");
        assert_eq!(review_frame.action_hint, "Next");
    }

    // Port of the C++
    // `test_device_protocol_exposes_review_session_for_manual_display_navigation`.
    #[test]
    fn exposes_review_session_for_manual_display_navigation() {
        let result = handle_serial_frame_with_review_preview(
            &request_frame_for_test(SIGN_EVENT_REQUEST_JSON),
            &dev(),
            ReviewDisplayLimits {
                max_title_chars: 18,
                max_body_lines: 5,
                max_line_chars: 26,
                ..ReviewDisplayLimits::default()
            },
        )
        .unwrap();

        assert_eq!(
            result.response_frame.as_bytes(),
            response_frame_for_test(SIGN_EVENT_DISABLED_RESPONSE_JSON).as_slice(),
        );
        let mut session = result.review_session.unwrap();
        assert_eq!(session.current_frame().unwrap().title, "Event");
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Content");
        assert_eq!(session.handle_button(ReviewButton::Back), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Content");
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Tags");
        assert!(!session.can_sign());
    }

    // Port of the C++ `test_device_protocol_reports_development_public_key`.
    #[test]
    fn reports_development_public_key() {
        let response =
            handle_serial_frame(&request_frame_for_test(PUBLIC_KEY_REQUEST_JSON), &dev()).unwrap();

        assert_eq!(
            response.as_bytes(),
            response_frame_for_test(PUBLIC_KEY_RESPONSE_JSON).as_slice(),
        );
        let (frame_type, _) = decoded_frame(&response);
        assert_eq!(frame_type, FrameType::Response);
    }

    // Port of the C++ `test_device_protocol_binds_configured_signer_identity`.
    #[test]
    fn binds_configured_signer_identity() {
        let alternate_pubkey = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let context = DeviceProtocolContext {
            signer_identity: SignerIdentity {
                public_key: alternate_pubkey,
            },
        };

        let public_key_response = handle_serial_frame(
            &request_frame_for_test(
                r#"{"version":1,"request_id":"req-context-pubkey","method":"get_public_key"}"#,
            ),
            &context,
        )
        .unwrap();
        assert_eq!(
            public_key_response.as_bytes(),
            response_frame_for_test(
                r#"{"version":1,"request_id":"req-context-pubkey","ok":true,"result":{"public_key":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}"#,
            )
            .as_slice(),
        );

        let result = handle_serial_frame_with_review_preview(
            &request_frame_for_test(
                r#"{"version":1,"request_id":"req-context-sign","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"context identity"}}}"#,
            ),
            &context,
            crate::review::test_fixtures::t_display_s3_review_limits(),
        )
        .unwrap();

        let session = result.review_session.unwrap();
        let event_frame = session.current_frame().unwrap();
        assert_eq!(event_frame.title, "Event");
        assert!(frame_lines_contain(&event_frame, &alternate_pubkey[..48]));
        assert!(frame_lines_contain(&event_frame, &alternate_pubkey[48..]));

        assert_eq!(
            handle_serial_frame(
                &request_frame_for_test(
                    r#"{"version":1,"request_id":"req-bad-context","method":"get_public_key"}"#,
                ),
                &DeviceProtocolContext {
                    signer_identity: SignerIdentity { public_key: "bad" },
                },
            ),
            Err(DeviceProtocolError::InvalidSignerIdentity),
        );
        assert_eq!(
            std::format!("{}", DeviceProtocolError::InvalidSignerIdentity),
            "signer public key must be 64 lowercase hex characters",
        );
    }

    // Port of the C++ `test_device_protocol_reports_signing_status_gates`.
    #[test]
    fn reports_signing_status_gates() {
        let response =
            handle_serial_frame(&request_frame_for_test(SIGNING_STATUS_REQUEST_JSON), &dev())
                .unwrap();

        assert_eq!(
            response.as_bytes(),
            response_frame_for_test(SIGNING_STATUS_RESPONSE_JSON).as_slice(),
        );
        let (frame_type, _) = decoded_frame(&response);
        assert_eq!(frame_type, FrameType::Response);
    }

    // Port of the C++ `test_device_protocol_echoes_dynamic_request_ids`.
    #[test]
    fn echoes_dynamic_request_ids() {
        let capability_response = handle_serial_frame(
            &request_frame_for_test(
                r#"{"version":1,"request_id":"req-alt-capabilities","method":"get_capabilities"}"#,
            ),
            &dev(),
        )
        .unwrap();
        assert_eq!(
            capability_response.as_bytes(),
            response_frame_for_test(
                r#"{"version":1,"request_id":"req-alt-capabilities","ok":true,"result":{"capabilities":{"device":{"name":"nSealr ESP32-S3 USB Signer Scaffold","firmware":"nsealr-esp32-s3-usb-signer","hardware":"esp32-s3-devkitc-1"},"protocols":["nsealr.signing.v0","nsealr.serial-frame.v0"],"methods":["get_capabilities","get_signing_status","get_public_key","sign_event"],"transports":["usb-serial-jtag"],"signing_enabled":false,"requires_physical_approval":true}}}"#,
            )
            .as_slice(),
        );

        let signing_status_response = handle_serial_frame(
            &request_frame_for_test(
                r#"{"version":1,"request_id":"req-alt-signing-status","method":"get_signing_status"}"#,
            ),
            &dev(),
        )
        .unwrap();
        assert_eq!(
            signing_status_response.as_bytes(),
            response_frame_for_test(
                r#"{"version":1,"request_id":"req-alt-signing-status","ok":true,"result":{"signing_status":{"signing_enabled":false,"missing_gates":["runtime_signing_feature","trusted_review_display","physical_approval_controls","unicode_review_rendering","key_provisioning","source_public_key_proof","secure_boot","flash_encryption","debug_lock","companion_signed_output_verification"],"development_accepted_gates":["parser_limits","trusted_review_display","physical_approval_controls","approval_digest_binding"]}}}"#,
            )
            .as_slice(),
        );

        let public_key_response = handle_serial_frame(
            &request_frame_for_test(
                r#"{"version":1,"request_id":"req-alt-pubkey","method":"get_public_key"}"#,
            ),
            &dev(),
        )
        .unwrap();
        assert_eq!(
            public_key_response.as_bytes(),
            response_frame_for_test(
                r#"{"version":1,"request_id":"req-alt-pubkey","ok":true,"result":{"public_key":"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"}}"#,
            )
            .as_slice(),
        );

        let disabled_response = handle_serial_frame(
            &request_frame_for_test(
                r#"{"version":1,"request_id":"req-alt-sign","method":"sign_event","params":{"event_template":{"created_at":1710000000,"kind":1,"tags":[],"content":"alt"}}}"#,
            ),
            &dev(),
        )
        .unwrap();
        assert_eq!(
            disabled_response.as_bytes(),
            response_frame_for_test(
                r#"{"version":1,"request_id":"req-alt-sign","ok":false,"error":{"code":"signing_disabled","message":"Signing is disabled until trusted review and physical approval are implemented.","retryable":false}}"#,
            )
            .as_slice(),
        );
    }

    // Port of the C++ `test_device_protocol_rejects_invalid_dynamic_request_metadata`,
    // extended with the byte-for-byte replay of the two READ-ONLY
    // specs/vectors/invalid fixtures deferred from M-T3.3
    // (serial-frame-request-invalid-{version,request-id}: protocol-level
    // rejections of well-formed frames).
    #[test]
    fn rejects_invalid_dynamic_request_metadata() {
        assert_eq!(
            handle_serial_frame(
                &request_frame_for_test(
                    r#"{"version":10,"request_id":"req-version-10","method":"get_public_key"}"#,
                ),
                &dev(),
            )
            .unwrap()
            .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );

        assert_eq!(
            handle_serial_frame(
                &request_frame_for_test(
                    r#"{"version":1,"request_id":"bad id","method":"get_public_key"}"#,
                ),
                &dev(),
            )
            .unwrap()
            .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );

        // Byte-for-byte frames copied from the READ-ONLY
        // specs/vectors/invalid/serial-frame-request-invalid-version.json and
        // serial-frame-request-invalid-request-id.json (`frame`).
        const INVALID_VERSION_FRAME: &[u8] = b"nsealr1f:request:eyJ2ZXJzaW9uIjoxMCwicmVxdWVzdF9pZCI6ImR5bmFtaWMtc21va2UtaW52YWxpZC12ZXJzaW9uIiwibWV0aG9kIjoiZ2V0X3B1YmxpY19rZXkifQ:54c2eaa943b7931f\n";
        const INVALID_REQUEST_ID_FRAME: &[u8] = b"nsealr1f:request:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoiZHluYW1pYy1zbW9rZS1pbnZhbGlkIGlkIiwibWV0aG9kIjoiZ2V0X3B1YmxpY19rZXkifQ:a4b7a1f708101a5f\n";
        for frame in [INVALID_VERSION_FRAME, INVALID_REQUEST_ID_FRAME] {
            assert_eq!(
                handle_serial_frame(frame, &dev()).unwrap().as_bytes(),
                error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
            );
        }
    }

    // Port of the C++ `test_device_protocol_rejects_unknown_top_level_request_fields`.
    #[test]
    fn rejects_unknown_top_level_request_fields() {
        assert_eq!(
            handle_serial_frame(
                &request_frame_for_test(
                    r#"{"version":1,"request_id":"invalid-top-level","method":"get_public_key","unexpected":true}"#,
                ),
                &dev(),
            )
            .unwrap()
            .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );
    }

    // Port of the C++ `test_device_protocol_rejects_params_for_parameterless_methods`.
    #[test]
    fn rejects_params_for_parameterless_methods() {
        for request_json in [
            r#"{"version":1,"request_id":"invalid-capabilities-params","method":"get_capabilities","params":{}}"#,
            r#"{"version":1,"request_id":"invalid-public-key-params","method":"get_public_key","params":{}}"#,
            r#"{"version":1,"request_id":"invalid-signing-status-params","method":"get_signing_status","params":{}}"#,
        ] {
            assert_eq!(
                handle_serial_frame(&request_frame_for_test(request_json), &dev())
                    .unwrap()
                    .as_bytes(),
                error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
            );
        }
    }

    // Port of the C++ `test_device_protocol_rejects_invalid_sign_event_request_shape`.
    #[test]
    fn rejects_invalid_sign_event_request_shape() {
        assert_eq!(
            handle_serial_frame(
                &request_frame_for_test(
                    r#"{"version":1,"request_id":"invalid-template-pubkey","method":"sign_event","params":{"event_template":{"pubkey":"0000000000000000000000000000000000000000000000000000000000000000","created_at":1710000000,"kind":1,"tags":[],"content":"unsafe template"}}}"#,
                ),
                &dev(),
            )
            .unwrap()
            .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );
    }

    // Port of the C++ `test_device_protocol_review_preserves_json_unicode_escapes`.
    #[test]
    fn review_preserves_json_unicode_escapes() {
        let result = handle_serial_frame_with_review_preview(
            &request_frame_for_test(
                "{\"version\":1,\"request_id\":\"req-unicode-serial\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000400,\"kind\":1,\"tags\":[[\"t\",\"caf\\u00e8\"],[\"emoji\",\"\\uD83D\\uDE00\"]],\"content\":\"caf\\u00e8 \\uD83D\\uDE00\"}}}",
            ),
            &dev(),
            crate::review::test_fixtures::t_display_s3_review_limits(),
        )
        .unwrap();

        assert_eq!(
            result.response_frame.as_bytes(),
            response_frame_for_test(
                r#"{"version":1,"request_id":"req-unicode-serial","ok":false,"error":{"code":"signing_disabled","message":"Signing is disabled until trusted review and physical approval are implemented.","retryable":false}}"#,
            )
            .as_slice(),
        );
        let mut session = result.review_session.unwrap();
        assert_eq!(session.current_frame().unwrap().title, "Event");
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        let content = session.current_frame().unwrap();
        assert_eq!(content.title, "Content");
        assert!(frame_lines_contain(&content, "U+00E8"));
        assert!(frame_lines_contain(&content, "U+1F600"));
    }

    // Beyond the named C++ cases: non-request frames, transport-level decode
    // faults, oversize payload, invalid UTF-8, malformed metadata JSON, and
    // unknown methods.
    #[test]
    fn transport_and_metadata_rejection_branches() {
        // A response-type frame is answered with the unsupported error frame.
        assert_eq!(
            handle_serial_frame(&response_frame_for_test("{\"ok\":true}"), &dev())
                .unwrap()
                .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );
        // A transport-invalid line propagates the frame error (C++ threw).
        assert_eq!(
            handle_serial_frame(b"nsealr1f:request:AA:0000000000000000\n", &dev()),
            Err(DeviceProtocolError::Frame(
                SerialFrameError::ChecksumMismatch
            )),
        );
        // Malformed metadata JSON propagates the scanner error (C++ threw).
        assert_eq!(
            handle_serial_frame(&request_frame_for_test("{\"version\":1,"), &dev()),
            Err(DeviceProtocolError::RequestJsonMalformed),
        );
        // Invalid UTF-8 payload bytes are answered with the error frame.
        let mut payload = [0u8; 8];
        let payload = encode_base64url(&[0xff, 0xfe], &mut payload).unwrap();
        let mut out = [0u8; MAX_SERIAL_FRAME_BYTES];
        let bad_utf8 =
            Vec::from(encode_serial_frame(FrameType::Request, payload, &mut out).unwrap());
        assert_eq!(
            handle_serial_frame(&bad_utf8, &dev()).unwrap().as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );
        // An unknown method is answered with the error frame.
        assert_eq!(
            handle_serial_frame(
                &request_frame_for_test(
                    r#"{"version":1,"request_id":"req-unknown","method":"get_entropy"}"#,
                ),
                &dev(),
            )
            .unwrap()
            .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );
        // An oversized (decoded) request JSON is answered with the error frame.
        let mut big = String::from(
            r#"{"version":1,"request_id":"req-big","method":"get_public_key","pad":""#,
        );
        while big.len() <= MAX_DECODED_REQUEST_JSON_BYTES {
            big.push('x');
        }
        big.push_str("\"}");
        assert_eq!(
            handle_serial_frame(&request_frame_for_test(&big), &dev())
                .unwrap()
                .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );
    }

    // Beyond the named C++ cases: Display for every error variant, the
    // ResponseFrame text/equality helpers, the sign_event review-error
    // propagation (the C++ caught only QrEnvelopeError), metadata field
    // overflow handling, and every metadata-scanner grammar branch (the
    // distinct C++ SerialFrameError throw sites).
    #[test]
    fn error_display_response_frame_and_scanner_grammar() {
        use crate::review::qr::QrReviewError;
        use crate::review::serial::SerialReviewError;

        for (error, expected) in [
            (
                DeviceProtocolError::InvalidSignerIdentity,
                "signer public key must be 64 lowercase hex characters",
            ),
            (
                DeviceProtocolError::Frame(SerialFrameError::ChecksumMismatch),
                "serial frame rejected",
            ),
            (
                DeviceProtocolError::Payload(Base64UrlError::InvalidTrailingBits),
                "serial frame payload must be unpadded base64url",
            ),
            (
                DeviceProtocolError::RequestJsonMalformed,
                "request JSON is malformed",
            ),
            (
                DeviceProtocolError::Review(SerialReviewError::Capacity),
                "serial review flow exceeds fixed capacity",
            ),
            (
                DeviceProtocolError::Capacity,
                "device protocol response exceeds fixed capacity",
            ),
        ] {
            assert_eq!(std::format!("{error}"), expected);
        }

        // ResponseFrame text view and byte-slice equality.
        let response =
            handle_serial_frame(&request_frame_for_test(PUBLIC_KEY_REQUEST_JSON), &dev()).unwrap();
        assert!(response.as_str().starts_with("nsealr1f:response:"));
        assert!(response == response_frame_for_test(PUBLIC_KEY_RESPONSE_JSON).as_slice());

        // A sign_event review failure that is not an envelope rejection
        // propagates (zero display limits reach the review builder).
        assert_eq!(
            handle_serial_frame_with_review_preview(
                &request_frame_for_test(SIGN_EVENT_REQUEST_JSON),
                &dev(),
                ReviewDisplayLimits {
                    max_body_lines: 0,
                    ..ReviewDisplayLimits::default()
                },
            )
            .map(|_| ()),
            Err(DeviceProtocolError::Review(SerialReviewError::Review(
                QrReviewError::Display(crate::review::display::ReviewDisplayError::ZeroLimits),
            ))),
        );

        // An over-long request_id (varies per escape) can never validate; an
        // over-long method can never match — both answered with the error
        // frame (the C++ built unbounded strings and failed the same checks).
        let mut long_id = String::from(r#"{"version":1,"request_id":""#);
        for _ in 0..(MAX_METADATA_REQUEST_ID + 1) {
            long_id.push('a');
        }
        long_id.push_str(r#"","method":"get_public_key"}"#);
        assert_eq!(
            handle_serial_frame(&request_frame_for_test(&long_id), &dev())
                .unwrap()
                .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );
        let mut long_method =
            String::from(r#"{"version":1,"request_id":"req-long-method","method":""#);
        for _ in 0..(MAX_METADATA_METHOD + 1) {
            long_method.push('m');
        }
        long_method.push_str(r#""}"#);
        assert_eq!(
            handle_serial_frame(&request_frame_for_test(&long_method), &dev())
                .unwrap()
                .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );

        // Whitespace-tolerant metadata (skip_ws), decoded string escapes in
        // the request id (rejected by the id charset), and a params array.
        let spaced = " {\n\t\"version\" : 1 , \"request_id\" : \"esc\\\"\\\\\\/\\b\\f\\n\\r\\t\" , \"method\" : \"get_public_key\" , \"params\" : [ 1 , true ] } ";
        assert_eq!(
            handle_serial_frame(&request_frame_for_test(spaced), &dev())
                .unwrap()
                .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );

        // Every scanner grammar failure maps to RequestJsonMalformed (the
        // distinct C++ SerialFrameError messages).
        for bad_json in [
            // Top level is not an object.
            "[1]",
            // Key is not a string.
            "{1:2}",
            // Top-level member missing ':'.
            "{\"version\" 1}",
            // String escape truncated at end of input.
            "{\"request_id\":\"a\\",
            // Invalid string escape.
            "{\"request_id\":\"a\\x\"}",
            // Unterminated string.
            "{\"request_id\":\"abc",
            // Value missing entirely.
            "{\"params\":",
            // Unterminated object container.
            "{\"params\":{",
            // Object member missing ':'.
            "{\"params\":{\"a\" 1}}",
            // Object separator invalid.
            "{\"params\":{\"a\":1 x}}",
            // Unterminated array container.
            "{\"params\":[",
            // Array separator invalid.
            "{\"params\":[1 2]}",
            // Object left unterminated after members.
            "{\"version\":1",
            // Method value is not a string.
            "{\"method\":123}",
        ] {
            assert_eq!(
                handle_serial_frame(&request_frame_for_test(bad_json), &dev()),
                Err(DeviceProtocolError::RequestJsonMalformed),
                "expected malformed: {bad_json}",
            );
        }

        // A review session whose first frame cannot render (title wider than
        // max_title_chars) propagates through the current_frame error path.
        assert_eq!(
            handle_serial_frame_with_review_preview(
                &request_frame_for_test(SIGN_EVENT_REQUEST_JSON),
                &dev(),
                ReviewDisplayLimits {
                    max_title_chars: 4,
                    ..ReviewDisplayLimits::default()
                },
            )
            .map(|_| ()),
            Err(DeviceProtocolError::Review(SerialReviewError::Display(
                crate::review::display::ReviewDisplayError::TitleTooLong,
            ))),
        );

        // A top-level key longer than the 16-byte key buffer is truncated,
        // matches nothing, and flags an unknown field (the C++ compared the
        // full heap string; same rejection).
        assert_eq!(
            handle_serial_frame(
                &request_frame_for_test(
                    r#"{"version":1,"request_id":"req-long-key","method":"get_public_key","this_key_is_longer_than_16_bytes":1}"#,
                ),
                &dev(),
            )
            .unwrap()
            .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );

        // A version that is a string token is not the number 1.
        assert_eq!(
            handle_serial_frame(
                &request_frame_for_test(
                    r#"{"version":"1","request_id":"req-string-version","method":"get_public_key"}"#,
                ),
                &dev(),
            )
            .unwrap()
            .as_bytes(),
            error_frame_for_test(UNSUPPORTED_RESPONSE_JSON).as_slice(),
        );
    }
}
