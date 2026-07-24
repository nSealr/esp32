//! `invalid/` replay (decoder-owned subsets only): each vector's malformed input
//! must be *rejected* by the ported decoder. The `category` field selects the
//! decoder; the `expected_error` string documents the human-readable reason
//! (the ported error variants don't carry the exact C++ message, so rejection —
//! not message equality — is the parity assertion, matching the crate's own
//! `*_rejects_shared_invalid_*` unit tests).

use super::{compact_bytes, obj_field, str_field, ReplayResult};
use nsealr_core::protocol::{development_device_protocol_context, handle_serial_frame};
use nsealr_core::qr::envelope::{decode_qr_envelope, parse_qr_signing_request};
use nsealr_core::qr::limits::MAX_STATIC_QR_DECODED_JSON_BYTES;
use serde_json::Value;
use std::path::Path;

pub(super) fn replay(_path: &Path, value: &Value) -> ReplayResult {
    match str_field(value, "category")? {
        "qr-envelope" => reject_qr_envelope(value),
        "signing-request" => reject_signing_request(value),
        "serial-frame" => reject_serial_frame(value),
        other => Err(format!(
            "invalid vector category '{other}' is outside this harness's decoder-owned \
             subsets (qr-envelope / signing-request / serial-frame)"
        )),
    }
}

fn reject_qr_envelope(value: &Value) -> ReplayResult {
    let envelope = str_field(value, "envelope")?.as_bytes();
    let mut json_buf = [0u8; MAX_STATIC_QR_DECODED_JSON_BYTES];
    match decode_qr_envelope(envelope, &mut json_buf) {
        Err(_) => Ok(()),
        Ok(_) => Err(format!(
            "invalid qr-envelope vector was ACCEPTED by decode_qr_envelope \
             (expected rejection: {})",
            str_field(value, "expected_error").unwrap_or("?")
        )),
    }
}

fn reject_signing_request(value: &Value) -> ReplayResult {
    let request = obj_field(value, "request")?;
    let json = compact_bytes(request);
    match parse_qr_signing_request(&json) {
        Err(_) => Ok(()),
        Ok(_) => Err(format!(
            "invalid signing-request vector was ACCEPTED by parse_qr_signing_request \
             (expected rejection: {})",
            str_field(value, "expected_error").unwrap_or("?")
        )),
    }
}

fn reject_serial_frame(value: &Value) -> ReplayResult {
    let frame = str_field(value, "frame")?.as_bytes();
    // Drive the full serial entry point: frame-level malformed vectors error out;
    // well-formed frames carrying an invalid request are answered with the
    // `unsupported_request` error frame. Either outcome is a rejection; a normal
    // successful response is not.
    match handle_serial_frame(frame, &development_device_protocol_context()) {
        Err(_) => Ok(()),
        Ok(response) => {
            let (_ty, payload) = super::decode_serial_frame_json(response.as_bytes())?;
            let unsupported = payload
                .get("error")
                .and_then(Value::as_str)
                .is_some_and(|e| e == "unsupported_request");
            if unsupported {
                Ok(())
            } else {
                Err(format!(
                    "invalid serial-frame vector was ACCEPTED (got a real response, not \
                     unsupported_request): {payload} (expected rejection: {})",
                    str_field(value, "expected_error").unwrap_or("?")
                ))
            }
        }
    }
}
