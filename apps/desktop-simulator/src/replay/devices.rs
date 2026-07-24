//! `devices/` replay: drive each device-protocol `request` through the core and
//! compare its `response`. The directory is heterogeneous, so classification is
//! data-driven (never a hardcoded filename list), mirroring the `invalid/`
//! within-category rule:
//!
//! * request/response vectors the development core reproduces exactly  → **exact
//!   parity** (core response == vector response).
//! * the `signing_enabled: true` target-contract vectors host_core does not
//!   implement (and firmware does not snapshot) → **negative parity**: the
//!   development core must report the *disabled* state, proving it never
//!   prematurely claims the enabled target.
//! * the boot-hardening profile doc (no request/response) → **cross-check**: its
//!   `required_production_blockers` must equal the core's live
//!   `get_signing_status` `missing_gates`.
//!
//! Any other shape fails, forcing a re-triage instead of a silent skip.

use super::{arr_field, assert_json_eq, compact_bytes, str_field, ReplayResult};
use nsealr_core::protocol::{development_device_protocol_context, handle_serial_frame};
use serde_json::Value;

pub(super) fn replay(value: &Value) -> ReplayResult {
    match (value.get("request"), value.get("response")) {
        (Some(request), Some(response)) => replay_request_response(request, response),
        _ => replay_contract_doc(value),
    }
}

/// Run one request through the development device context and return the parsed
/// response JSON.
fn core_response(request: &Value) -> Result<Value, String> {
    let frame = super::encode_serial_request_frame(&compact_bytes(request))?;
    let response = handle_serial_frame(&frame, &development_device_protocol_context())
        .map_err(|e| format!("handle_serial_frame: {e}"))?;
    let (_ty, payload) = super::decode_serial_frame_json(response.as_bytes())?;
    Ok(payload)
}

/// `response.result.capabilities.signing_enabled` or
/// `response.result.signing_status.signing_enabled`, when present.
fn signing_enabled(response: &Value) -> Option<bool> {
    let result = response.get("result")?;
    for holder in ["capabilities", "signing_status"] {
        if let Some(flag) = result
            .get(holder)
            .and_then(|h| h.get("signing_enabled"))
            .and_then(Value::as_bool)
        {
            return Some(flag);
        }
    }
    None
}

fn replay_request_response(request: &Value, response: &Value) -> ReplayResult {
    let got = core_response(request)?;
    if got == *response {
        return Ok(()); // exact parity
    }
    // The only tolerated divergence: an enabled-target vector the core must not
    // reproduce. Assert the core actually reports the disabled state.
    if signing_enabled(response) == Some(true) {
        return match signing_enabled(&got) {
            Some(false) => Ok(()), // negative parity: core stays disabled
            other => Err(format!(
                "enabled-target device vector: core signing_enabled = {other:?}, expected \
                 the development core to report `false` (never prematurely claim enablement); \
                 core response: {got}"
            )),
        };
    }
    assert_json_eq("device response", &got, response)
}

fn replay_contract_doc(value: &Value) -> ReplayResult {
    let format = str_field(value, "format")?;
    if !format.starts_with("firmware-boot-hardening-profile") {
        return Err(format!(
            "unclassified device vector (no request/response, format '{format}') — re-triage"
        ));
    }
    let declared = arr_field(value, "required_production_blockers")?;

    // The core's live signing-status blockers come from a real get_signing_status.
    let status_request: Value = serde_json::json!({
        "version": 1,
        "request_id": "device-profile-crosscheck",
        "method": "get_signing_status",
    });
    let response = core_response(&status_request)?;
    let missing = response
        .get("result")
        .and_then(|r| r.get("signing_status"))
        .and_then(|s| s.get("missing_gates"))
        .and_then(Value::as_array)
        .ok_or("core signing_status.missing_gates missing")?;

    assert_json_eq(
        "boot-hardening profile required_production_blockers vs core missing_gates",
        &Value::Array(declared.clone()),
        &Value::Array(missing.clone()),
    )
}
