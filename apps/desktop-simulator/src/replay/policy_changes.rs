//! `policy-changes/` replay: build the on-device policy-change review from the
//! vector's `proposal` through `nsealr-core`'s validator and assert the vector's
//! `review` (proposal id, approval digest, all four pages) exactly. Also
//! cross-checks that the proposal's current/proposed policy ids resolve to real
//! on-disk `policies/` profiles covering the proposal's route.

use super::{arr_field, assert_review_pages, obj_field, str_field, ReplayResult};
use nsealr_core::policy::policy_change_review::{
    build_policy_change_review, PolicyChangeGrantIds, PolicyChangeProposal, PolicyChangeRequester,
};
use serde_json::Value;

fn proposal_from(value: &Value) -> Result<PolicyChangeProposal, String> {
    let parse_id = |key: &str| -> Result<_, String> {
        str_field(value, key)?
            .parse()
            .map_err(|e| format!("{key}: {e:?}"))
    };
    let flag = |key: &str| -> Result<bool, String> {
        value
            .get(key)
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("{key} missing or not a bool"))
    };

    let mut proposed_grant_ids = PolicyChangeGrantIds::new();
    for grant in arr_field(value, "proposed_grant_ids")? {
        let grant = grant
            .as_str()
            .ok_or("proposed_grant_ids entry not a string")?;
        proposed_grant_ids
            .try_push(grant)
            .map_err(|e| format!("proposed_grant_ids: {e:?}"))?;
    }

    let requested_by = obj_field(value, "requested_by")?;
    let label = match requested_by.get("label") {
        None | Some(Value::Null) => None,
        Some(Value::String(label)) => Some(
            label
                .parse()
                .map_err(|e| format!("requested_by.label: {e:?}"))?,
        ),
        Some(other) => return Err(format!("requested_by.label not a string: {other}")),
    };

    Ok(PolicyChangeProposal {
        proposal_id: parse_id("proposal_id")?,
        account_id: parse_id("account_id")?,
        route_type: str_field(value, "route_type")?
            .parse()
            .map_err(|e| format!("route_type: {e:?}"))?,
        action: str_field(value, "action")?
            .parse()
            .map_err(|e| format!("action: {e:?}"))?,
        current_policy_id: parse_id("current_policy_id")?,
        proposed_policy_id: parse_id("proposed_policy_id")?,
        proposed_grant_ids,
        requested_by: PolicyChangeRequester {
            surface: str_field(requested_by, "surface")?
                .parse()
                .map_err(|e| format!("requested_by.surface: {e:?}"))?,
            client_pubkey: str_field(requested_by, "client_pubkey")?
                .parse()
                .map_err(|e| format!("requested_by.client_pubkey: {e:?}"))?,
            label,
        },
        created_at: value
            .get("created_at")
            .and_then(Value::as_u64)
            .ok_or("created_at missing or not an unsigned integer")?,
        device_review_required: flag("device_review_required")?,
        physical_approval_required: flag("physical_approval_required")?,
        companion_authoritative: flag("companion_authoritative")?,
        contains_secret_material: flag("contains_secret_material")?,
    })
}

/// Assert a `policy-*` id resolves to an on-disk `policies/` profile whose
/// `route_types` cover `route`.
fn assert_policy_resolves(policy_id: &str, route: &str) -> ReplayResult {
    for path in
        crate::category_files("policies", &[]).map_err(|e| format!("enumerate policies/: {e}"))?
    {
        let profile = super::load_value(&path)?;
        if str_field(&profile, "policy_id")? != policy_id {
            continue;
        }
        let routes = arr_field(&profile, "route_types")?;
        if routes.iter().any(|r| r.as_str() == Some(route)) {
            return Ok(());
        }
        return Err(format!(
            "policy '{policy_id}' exists but does not cover route '{route}'"
        ));
    }
    Err(format!(
        "policy id '{policy_id}' resolves to no policies/ profile on disk"
    ))
}

pub(super) fn replay(value: &Value) -> ReplayResult {
    let proposal_json = obj_field(value, "proposal")?;
    let proposal = proposal_from(proposal_json)?;

    let review = build_policy_change_review(&proposal)
        .map_err(|e| format!("build_policy_change_review: {e:?}"))?;

    let want = obj_field(value, "review")?;
    if review.proposal_id.as_str() != str_field(want, "proposal_id")? {
        return Err("review proposal_id != vector.review.proposal_id".into());
    }
    if review.approval_digest.as_str() != str_field(want, "approval_digest")? {
        return Err("approval_digest != vector.review.approval_digest".into());
    }
    assert_review_pages(
        "policy-change review",
        review.pages.as_slice(),
        arr_field(want, "pages")?,
    )?;

    // Both referenced policy ids must resolve to real profiles for this route.
    let route = str_field(proposal_json, "route_type")?;
    assert_policy_resolves(str_field(proposal_json, "current_policy_id")?, route)?;
    assert_policy_resolves(str_field(proposal_json, "proposed_policy_id")?, route)
}
