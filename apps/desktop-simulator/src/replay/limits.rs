//! `limits/` replay: assert the on-disk shared limits profile equals the limit
//! constants compiled into `nsealr-core::qr::limits`. If specs changes a value
//! without the core following, this fails — the profile and the code cannot
//! drift silently. (`max_nip46_decrypted_message_json_bytes` has no core
//! constant: NIP-46 is companion-owned and excluded from this harness.)

use super::{obj_field, ReplayResult};
use nsealr_core::qr::limits as core_limits;
use serde_json::Value;

pub(super) fn replay(value: &Value) -> ReplayResult {
    let limits = obj_field(value, "limits")?;
    // (JSON key, compiled constant) pairs the ported transport/request surface owns.
    let expected: &[(&str, u64)] = &[
        (
            "max_request_id_length",
            core_limits::MAX_REQUEST_ID_LENGTH as u64,
        ),
        (
            "max_decoded_request_json_bytes",
            core_limits::MAX_DECODED_REQUEST_JSON_BYTES as u64,
        ),
        (
            "max_static_qr_decoded_json_bytes",
            core_limits::MAX_STATIC_QR_DECODED_JSON_BYTES as u64,
        ),
        (
            "max_animated_qr_decoded_json_bytes",
            core_limits::MAX_ANIMATED_QR_DECODED_JSON_BYTES as u64,
        ),
        (
            "max_animated_qr_frame_payload_chars",
            core_limits::MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS as u64,
        ),
        (
            "max_animated_qr_frame_count",
            core_limits::MAX_ANIMATED_QR_FRAME_COUNT as u64,
        ),
        (
            "max_serial_frame_bytes",
            core_limits::MAX_SERIAL_FRAME_BYTES as u64,
        ),
        (
            "max_content_utf8_bytes",
            core_limits::MAX_CONTENT_UTF8_BYTES as u64,
        ),
        ("max_tag_count", core_limits::MAX_TAG_COUNT as u64),
        (
            "max_tag_fields_per_tag",
            core_limits::MAX_TAG_FIELDS_PER_TAG as u64,
        ),
        (
            "max_tag_field_utf8_bytes",
            core_limits::MAX_TAG_FIELD_UTF8_BYTES as u64,
        ),
        (
            "max_total_tag_utf8_bytes",
            core_limits::MAX_TOTAL_TAG_UTF8_BYTES as u64,
        ),
        ("max_safe_integer", core_limits::MAX_SAFE_INTEGER),
    ];
    for (key, want) in expected {
        let got = limits
            .get(*key)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("limits.{key} missing or not an unsigned integer"))?;
        if got != *want {
            return Err(format!(
                "limits.{key} = {got} on disk but nsealr-core compiles {want}"
            ));
        }
    }

    // The declared created_at integer policy must match the safe-integer ceiling.
    let created_at = obj_field(value, "integer_policy")?
        .get("created_at")
        .filter(|v| v.is_object())
        .ok_or("integer_policy.created_at missing")?;
    let max = created_at
        .get("maximum")
        .and_then(Value::as_u64)
        .ok_or("integer_policy.created_at.maximum missing")?;
    let min = created_at
        .get("minimum")
        .and_then(Value::as_u64)
        .ok_or("integer_policy.created_at.minimum missing")?;
    if max != core_limits::MAX_SAFE_INTEGER || min != 0 {
        return Err(format!(
            "integer_policy.created_at bounds [{min}, {max}] != [0, {}]",
            core_limits::MAX_SAFE_INTEGER
        ));
    }
    Ok(())
}
