//! `policies/` replay: the shared policy-profile contract the device families
//! rely on. Neither `host_core` nor `nsealr-core` executes these profiles (they
//! are consumed as policy *ids* by the policy-change review and the account
//! descriptors), so the replay asserts the fail-closed invariants the ported
//! policy layer assumes of every profile, plus the frozen route-family ids —
//! all measured against the real files, none invented:
//!
//! * modes are exactly `manual_only` / `scoped_automation`, and `grants_allowed`
//!   is `true` iff the mode is `scoped_automation`;
//! * QR-vault routes are always `manual_only` (the RAM-only session core has no
//!   grant machinery);
//! * `unknown_method` always requires manual review and the `unknown` risk tier
//!   is always `manual` (fail-closed on anything unrecognized);
//! * `wildcard` and `export_secret` are forbidden everywhere; device-family
//!   profiles additionally forbid `decrypt_without_review`.

use super::{arr_field, obj_field, str_field, ReplayResult};
use serde_json::Value;

/// The frozen family ids (cross-repo test contract — never rename) plus the
/// companion-owned external route that policy profiles may target.
const KNOWN_ROUTE_TYPES: &[&str] = &[
    "raspberry_qr_vault",
    "esp32_qr_vault",
    "esp32_usb_nip46",
    "smartcard",
    "custom_hardware_wallet",
    "external_nip46",
];

/// The manual-only QR-vault session routes.
const QR_VAULT_ROUTES: &[&str] = &["raspberry_qr_vault", "esp32_qr_vault"];

fn str_list<'a>(value: &'a Value, key: &str) -> Result<Vec<&'a str>, String> {
    arr_field(value, key)?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| format!("{key} contains a non-string entry"))
        })
        .collect()
}

pub(super) fn replay(value: &Value) -> ReplayResult {
    if str_field(value, "format")? != "nsealr-policy-profile-v0" {
        return Err(format!(
            "unknown policies format '{}'",
            str_field(value, "format")?
        ));
    }
    let policy_id = str_field(value, "policy_id")?;
    if !policy_id.starts_with("policy-") {
        return Err(format!(
            "policy_id '{policy_id}' does not start with 'policy-'"
        ));
    }

    let route_types = str_list(value, "route_types")?;
    if route_types.is_empty() {
        return Err("route_types is empty".into());
    }
    for route in &route_types {
        if !KNOWN_ROUTE_TYPES.contains(route) {
            return Err(format!(
                "route_types contains unknown route '{route}' (frozen family ids: \
                 {KNOWN_ROUTE_TYPES:?})"
            ));
        }
    }

    let mode = str_field(value, "mode")?;
    let grants_allowed = value
        .get("grants_allowed")
        .and_then(Value::as_bool)
        .ok_or("grants_allowed missing or not a bool")?;
    match mode {
        "manual_only" => {
            if grants_allowed {
                return Err("manual_only profile with grants_allowed=true (fail-open)".into());
            }
        }
        "scoped_automation" => {
            if !grants_allowed {
                return Err("scoped_automation profile with grants_allowed=false".into());
            }
        }
        other => return Err(format!("unknown policy mode '{other}'")),
    }
    if route_types.iter().any(|r| QR_VAULT_ROUTES.contains(r)) && mode != "manual_only" {
        return Err(format!(
            "QR-vault route profile must be manual_only, got '{mode}' (the RAM-only \
             session core has no grant machinery)"
        ));
    }

    let manual_review = str_list(value, "manual_review_required")?;
    if !manual_review.contains(&"unknown_method") {
        return Err("manual_review_required must fail closed on 'unknown_method'".into());
    }
    if mode == "manual_only" && !manual_review.contains(&"sign_event") {
        return Err("manual_only profile must require manual review for 'sign_event'".into());
    }

    let forbidden = str_list(value, "forbidden_permissions")?;
    for always in ["wildcard", "export_secret"] {
        if !forbidden.contains(&always) {
            return Err(format!("forbidden_permissions must include '{always}'"));
        }
    }
    let device_route = route_types.iter().any(|r| *r != "external_nip46");
    if device_route && !forbidden.contains(&"decrypt_without_review") {
        return Err("device-family profile must forbid 'decrypt_without_review'".into());
    }

    let risk_tiers = obj_field(value, "risk_tiers")?;
    let unknown_tier = risk_tiers.get("unknown").and_then(Value::as_str);
    if unknown_tier != Some("manual") {
        return Err(format!(
            "risk_tiers.unknown must be 'manual' (fail closed), got {unknown_tier:?}"
        ));
    }
    let decrypt_tier = risk_tiers.get("decrypt").and_then(Value::as_str);
    if decrypt_tier != Some("manual") {
        return Err(format!(
            "risk_tiers.decrypt must be 'manual', got {decrypt_tier:?}"
        ));
    }
    Ok(())
}
