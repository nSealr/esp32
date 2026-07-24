//! Policy-change review — device-reviewed persistent-policy changes.
//!
//! Ported from the C++ reference `host_core` sources
//! `src/policy_change_review.cpp` + `include/nsealr/policy_change_review.hpp`
//! for behaviour parity. A companion proposes a persistent policy change; the
//! device validates the proposal (rejecting companion authority and secret
//! material outright), builds the four fixed trusted-review pages, and binds
//! them to the proposal with a SHA-256 approval digest over the canonical JSON
//! `{"pages":…,"proposal":…}` material — byte-for-byte the C++ canonical form,
//! proven against the shared `specs/vectors/policy-changes` fixtures.
//!
//! **Deferred to M-T3.4b (after M-T3.6):** the C++ `run_policy_change_review_flow`
//! and its `PolicyChangeReviewTranscriptStep`/`PolicyChangeReviewFlowResult`
//! surface drive a `TrustedReviewSession` with `ReviewButton` presses — review
//! *logic* that arrives with milestone M-T3.6 and is not pulled forward here.
//!
//! The C++ used `std::string`/`std::vector`; this allocation-free port stores
//! bounded inline text ([`FixedStr`]) and fixed-capacity lists. The capacities
//! implement the C++ validation limits structurally: `proposal_id` is
//! `"proposal-"` plus at most 119 id bytes (128 total), policy ids are
//! `"policy-"` plus at most 121 (128 total), grant ids are `"grant-"` plus at
//! most 122 (128 total), and `account_id` is at most 128 bytes — so the C++
//! per-field length checks are enforced by construction and only the
//! prefix/charset checks remain at validation time.

use crate::hash::sha256_hex;
use crate::review::types::{
    ReviewBodyLineStyles, ReviewPageAction, ReviewPageLine, ReviewPageLines, ReviewPageList,
    TrustedReviewApprovalDigest, TrustedReviewPage, TrustedReviewRequest,
};
use crate::text::{FixedStr, TextError};
use core::fmt;

/// Maximum byte length of a stable string id (proposal/account/policy/grant).
pub const MAX_POLICY_CHANGE_ID_CHARS: usize = 128;

/// Maximum number of proposed grant ids. Bounded by the `"Policy"` review page:
/// its three fixed lines plus one line per grant must fit the shared
/// [`crate::review::types::MAX_REVIEW_PAGE_LINES`]-line page.
pub const MAX_POLICY_CHANGE_GRANTS: usize = 4;

/// Maximum byte length of the optional requester label.
pub const MAX_POLICY_CHANGE_LABEL_CHARS: usize = 64;

/// Maximum byte length of a requester surface name (the longest supported
/// surface is `"browser_extension"`, 17 bytes).
pub const MAX_POLICY_CHANGE_SURFACE_CHARS: usize = 32;

/// A stable string id (proposal/account/policy/grant) as bounded inline text.
pub type PolicyChangeId = FixedStr<MAX_POLICY_CHANGE_ID_CHARS>;

/// A requester label as bounded inline text.
pub type PolicyChangeLabel = FixedStr<MAX_POLICY_CHANGE_LABEL_CHARS>;

/// A requester surface name as bounded inline text.
pub type PolicyChangeSurface = FixedStr<MAX_POLICY_CHANGE_SURFACE_CHARS>;

/// A 32-byte lowercase-hex client public key as bounded inline text.
pub type PolicyChangeClientPubkey = FixedStr<64>;

/// Why a policy-change proposal was rejected. Mirrors the C++
/// `PolicyChangeReviewError` (one `std::runtime_error` type; this port names
/// each message as a variant — [`Self::message`] returns the exact C++ text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyChangeReviewError {
    /// `proposal_id` is not a `proposal-*` stable string id.
    InvalidProposalId,
    /// `account_id` is not a stable string id.
    InvalidAccountId,
    /// `route_type` is not a device-display persistent policy route.
    UnsupportedRouteType,
    /// The action is not `set_policy`.
    UnsupportedAction,
    /// `current_policy_id` is not a `policy-*` stable string id.
    InvalidCurrentPolicyId,
    /// `proposed_policy_id` is not a `policy-*` stable string id.
    InvalidProposedPolicyId,
    /// A proposed grant id is not a `grant-*` stable string id.
    InvalidGrantId,
    /// The proposed grant ids contain a duplicate.
    DuplicateGrantIds,
    /// `requested_by.surface` is not a supported companion surface.
    UnsupportedSurface,
    /// `requested_by.client_pubkey` is not 32-byte lowercase hex.
    InvalidClientPubkey,
    /// `requested_by.label` is present but empty.
    EmptyLabel,
    /// `created_at` is zero.
    InvalidCreatedAt,
    /// `device_review_required` is `false`.
    DeviceReviewNotRequired,
    /// `physical_approval_required` is `false`.
    PhysicalApprovalNotRequired,
    /// `companion_authoritative` is `true` — the companion may never be the
    /// policy authority.
    CompanionAuthoritative,
    /// `contains_secret_material` is `true` — policy changes never carry
    /// secret material.
    ContainsSecretMaterial,
}

impl PolicyChangeReviewError {
    /// The exact message the C++ `PolicyChangeReviewError` carried.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidProposalId => "proposal_id must be a proposal-* stable string id",
            Self::InvalidAccountId => "account_id must be a stable string id",
            Self::UnsupportedRouteType => {
                "route_type must be a device-display persistent policy route"
            }
            Self::UnsupportedAction => "policy change action must be set_policy",
            Self::InvalidCurrentPolicyId => "current_policy_id must be a policy-* stable string id",
            Self::InvalidProposedPolicyId => {
                "proposed_policy_id must be a policy-* stable string id"
            }
            Self::InvalidGrantId => "proposed grant id must be a grant-* stable string id",
            Self::DuplicateGrantIds => "proposed_grant_ids must be unique",
            Self::UnsupportedSurface => "requested_by.surface is unsupported",
            Self::InvalidClientPubkey => "requested_by.client_pubkey must be 32-byte lowercase hex",
            Self::EmptyLabel => "requested_by.label must be a non-empty string",
            Self::InvalidCreatedAt => "created_at must be a positive integer",
            Self::DeviceReviewNotRequired => "device_review_required must be true",
            Self::PhysicalApprovalNotRequired => "physical_approval_required must be true",
            Self::CompanionAuthoritative => "companion_authoritative must be false",
            Self::ContainsSecretMaterial => "contains_secret_material must be false",
        }
    }
}

impl fmt::Display for PolicyChangeReviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// A fixed-capacity list of proposed grant ids — the allocation-free stand-in
/// for the C++ `std::vector<std::string>` grant list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChangeGrantIds {
    ids: [PolicyChangeId; MAX_POLICY_CHANGE_GRANTS],
    len: usize,
}

impl PolicyChangeGrantIds {
    /// Creates an empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ids: [const { PolicyChangeId::new() }; MAX_POLICY_CHANGE_GRANTS],
            len: 0,
        }
    }

    /// Appends one grant id.
    ///
    /// # Errors
    ///
    /// [`TextError::TooLong`] if the list already holds
    /// [`MAX_POLICY_CHANGE_GRANTS`] ids or the id exceeds
    /// [`MAX_POLICY_CHANGE_ID_CHARS`] bytes.
    pub fn try_push(&mut self, grant_id: &str) -> Result<(), TextError> {
        if self.len >= MAX_POLICY_CHANGE_GRANTS {
            return Err(TextError::TooLong);
        }
        self.ids[self.len] = grant_id.parse()?;
        self.len += 1;
        Ok(())
    }

    /// Returns the active ids as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[PolicyChangeId] {
        &self.ids[..self.len]
    }

    /// Returns the number of ids held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the list holds no ids.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for PolicyChangeGrantIds {
    fn default() -> Self {
        Self::new()
    }
}

/// The companion surface that requested the change. Mirrors the C++
/// `PolicyChangeRequester` field for field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChangeRequester {
    /// The requesting surface (for example `"browser_extension"`).
    pub surface: PolicyChangeSurface,
    /// The requesting client's 32-byte lowercase-hex public key.
    pub client_pubkey: PolicyChangeClientPubkey,
    /// An optional human-readable client label.
    pub label: Option<PolicyChangeLabel>,
}

/// A proposed persistent policy change. Mirrors the C++ `PolicyChangeProposal`
/// field for field, including the fail-closed defaults: review/approval flags
/// default to `false` (not yet promised) and the danger flags
/// (`companion_authoritative`, `contains_secret_material`) default to `true`
/// (assumed unsafe until the companion explicitly disclaims them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChangeProposal {
    /// Stable `proposal-*` id.
    pub proposal_id: PolicyChangeId,
    /// Stable account id the change applies to.
    pub account_id: PolicyChangeId,
    /// The persistent policy route (`esp32_usb_nip46` or
    /// `custom_hardware_wallet`).
    pub route_type: FixedStr<32>,
    /// The policy action; only `set_policy` is supported.
    pub action: FixedStr<16>,
    /// Stable `policy-*` id of the currently active policy.
    pub current_policy_id: PolicyChangeId,
    /// Stable `policy-*` id of the proposed policy.
    pub proposed_policy_id: PolicyChangeId,
    /// Stable `grant-*` ids the proposed policy grants.
    pub proposed_grant_ids: PolicyChangeGrantIds,
    /// The companion surface that requested the change.
    pub requested_by: PolicyChangeRequester,
    /// Proposal creation time (seconds since the Unix epoch, non-zero).
    pub created_at: u64,
    /// The companion promises the change is device-reviewed.
    pub device_review_required: bool,
    /// The companion promises physical approval is required.
    pub physical_approval_required: bool,
    /// `true` would make the companion the policy authority — always rejected.
    pub companion_authoritative: bool,
    /// `true` would mean the proposal carries secret material — always rejected.
    pub contains_secret_material: bool,
}

/// The validated device review for a policy-change proposal. Mirrors the C++
/// `PolicyChangeReview` field for field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChangeReview {
    /// The proposal id the review binds.
    pub proposal_id: PolicyChangeId,
    /// SHA-256 hex digest over the canonical `{"pages":…,"proposal":…}` JSON.
    pub approval_digest: TrustedReviewApprovalDigest,
    /// The four fixed review pages (Policy change / Requester / Policy /
    /// Decision).
    pub pages: ReviewPageList,
}

/// Builds and validates the device review for a policy-change proposal.
/// Mirrors the C++ `build_policy_change_review` (which threw
/// `PolicyChangeReviewError`; this port returns it as an error value).
///
/// # Errors
///
/// A [`PolicyChangeReviewError`] naming the first C++ validation rule the
/// proposal violates, in the same evaluation order as the C++.
pub fn build_policy_change_review(
    proposal: &PolicyChangeProposal,
) -> Result<PolicyChangeReview, PolicyChangeReviewError> {
    validate_policy_change_proposal(proposal)?;
    let pages = review_pages_for(proposal);
    Ok(PolicyChangeReview {
        proposal_id: proposal.proposal_id.clone(),
        approval_digest: policy_change_approval_digest(proposal, &pages),
        pages,
    })
}

/// Returns `true` if `value` is a non-empty stable string id: ASCII
/// alphanumerics plus `.`, `_`, `:`, `-`. Mirrors the C++ `matches_stable_id`;
/// the C++ per-field maximum sizes are enforced structurally by the
/// [`PolicyChangeId`] capacity (see the module docs).
fn matches_stable_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// Returns `true` for a 32-byte lowercase-hex string. Mirrors the C++
/// `is_lower_hex_32`.
fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Returns `true` for a persistent policy route with a device display. Mirrors
/// the C++ `is_supported_route`.
fn is_supported_route(route_type: &str) -> bool {
    route_type == "esp32_usb_nip46" || route_type == "custom_hardware_wallet"
}

/// Returns `true` for a supported companion surface. Mirrors the C++
/// `is_supported_surface`.
fn is_supported_surface(surface: &str) -> bool {
    matches!(
        surface,
        "browser_extension" | "desktop_app" | "cli" | "sdk" | "native_host_test"
    )
}

/// Returns `true` for a `policy-*` stable string id. Mirrors the C++
/// `require_policy_id` (the caller maps `false` to its field-specific error).
fn is_policy_id(value: &str) -> bool {
    value.strip_prefix("policy-").is_some_and(matches_stable_id)
}

/// Validates a proposal against every C++ rule, in the C++ evaluation order.
/// Mirrors the C++ `validate_policy_change_proposal`.
fn validate_policy_change_proposal(
    proposal: &PolicyChangeProposal,
) -> Result<(), PolicyChangeReviewError> {
    if !proposal
        .proposal_id
        .as_str()
        .strip_prefix("proposal-")
        .is_some_and(matches_stable_id)
    {
        return Err(PolicyChangeReviewError::InvalidProposalId);
    }
    if !matches_stable_id(proposal.account_id.as_str()) {
        return Err(PolicyChangeReviewError::InvalidAccountId);
    }
    if !is_supported_route(proposal.route_type.as_str()) {
        return Err(PolicyChangeReviewError::UnsupportedRouteType);
    }
    if proposal.action != "set_policy" {
        return Err(PolicyChangeReviewError::UnsupportedAction);
    }
    if !is_policy_id(proposal.current_policy_id.as_str()) {
        return Err(PolicyChangeReviewError::InvalidCurrentPolicyId);
    }
    if !is_policy_id(proposal.proposed_policy_id.as_str()) {
        return Err(PolicyChangeReviewError::InvalidProposedPolicyId);
    }
    let grants = proposal.proposed_grant_ids.as_slice();
    for grant_id in grants {
        if !grant_id
            .as_str()
            .strip_prefix("grant-")
            .is_some_and(matches_stable_id)
        {
            return Err(PolicyChangeReviewError::InvalidGrantId);
        }
    }
    // Pairwise duplicate scan over the bounded list (the C++ sorted a copy and
    // used adjacent_find; with at most MAX_POLICY_CHANGE_GRANTS entries the
    // allocation-free quadratic scan is equivalent).
    for (index, grant_id) in grants.iter().enumerate() {
        if grants[index + 1..].contains(grant_id) {
            return Err(PolicyChangeReviewError::DuplicateGrantIds);
        }
    }
    if !is_supported_surface(proposal.requested_by.surface.as_str()) {
        return Err(PolicyChangeReviewError::UnsupportedSurface);
    }
    if !is_lower_hex_32(proposal.requested_by.client_pubkey.as_str()) {
        return Err(PolicyChangeReviewError::InvalidClientPubkey);
    }
    if let Some(label) = &proposal.requested_by.label {
        if label.is_empty() {
            return Err(PolicyChangeReviewError::EmptyLabel);
        }
    }
    if proposal.created_at == 0 {
        return Err(PolicyChangeReviewError::InvalidCreatedAt);
    }
    if !proposal.device_review_required {
        return Err(PolicyChangeReviewError::DeviceReviewNotRequired);
    }
    if !proposal.physical_approval_required {
        return Err(PolicyChangeReviewError::PhysicalApprovalNotRequired);
    }
    if proposal.companion_authoritative {
        return Err(PolicyChangeReviewError::CompanionAuthoritative);
    }
    if proposal.contains_secret_material {
        return Err(PolicyChangeReviewError::ContainsSecretMaterial);
    }
    Ok(())
}

/// Builds one review body line as `prefix` + `value`. Every caller's worst case
/// (`"Account: "` + a 128-byte stable id, 137 bytes) fits the shared
/// [`crate::review::types::MAX_REVIEW_PAGE_LINE_CHARS`] capacity.
fn prefixed_line(prefix: &str, value: &str) -> ReviewPageLine {
    let mut line = ReviewPageLine::new();
    line.try_push_str(prefix)
        .expect("within documented capacity");
    line.try_push_str(value)
        .expect("within documented capacity");
    line
}

/// Builds a review page from its title, lines and action; the policy-change
/// pages leave indicator/styles/logical id empty, as the C++ did.
fn review_page(title: &str, lines: ReviewPageLines, action: ReviewPageAction) -> TrustedReviewPage {
    TrustedReviewPage {
        title: title.parse().expect("within documented capacity"),
        lines,
        action,
        page_indicator: FixedStr::new(),
        body_line_styles: ReviewBodyLineStyles::new(),
        logical_page_id: FixedStr::new(),
    }
}

/// Builds the requester page lines. Mirrors the C++ `requester_lines` (the
/// label line is omitted when no label is present).
fn requester_lines(requester: &PolicyChangeRequester) -> ReviewPageLines {
    let mut lines = ReviewPageLines::new();
    lines
        .try_push(prefixed_line("Surface: ", requester.surface.as_str()).as_str())
        .expect("within documented capacity");
    lines
        .try_push(prefixed_line("Client: ", requester.client_pubkey.as_str()).as_str())
        .expect("within documented capacity");
    if let Some(label) = &requester.label {
        lines
            .try_push(prefixed_line("Label: ", label.as_str()).as_str())
            .expect("within documented capacity");
    }
    lines
}

/// Builds the policy page lines. Mirrors the C++ `policy_lines`; the three
/// fixed lines plus at most [`MAX_POLICY_CHANGE_GRANTS`] grant lines fit the
/// page's line capacity.
fn policy_lines(proposal: &PolicyChangeProposal) -> ReviewPageLines {
    let mut lines = ReviewPageLines::new();
    lines
        .try_push(prefixed_line("From: ", proposal.current_policy_id.as_str()).as_str())
        .expect("within documented capacity");
    lines
        .try_push(prefixed_line("To: ", proposal.proposed_policy_id.as_str()).as_str())
        .expect("within documented capacity");
    let mut grants_line = ReviewPageLine::new();
    grants_line
        .try_push_str("Grants: ")
        .expect("within documented capacity");
    grants_line
        .try_push_usize(proposal.proposed_grant_ids.len())
        .expect("within documented capacity");
    lines
        .try_push(grants_line.as_str())
        .expect("within documented capacity");
    for grant_id in proposal.proposed_grant_ids.as_slice() {
        lines
            .try_push(prefixed_line("Grant: ", grant_id.as_str()).as_str())
            .expect("within documented capacity");
    }
    lines
}

/// Builds the four fixed review pages. Mirrors the C++ `review_pages_for`.
fn review_pages_for(proposal: &PolicyChangeProposal) -> ReviewPageList {
    let mut summary_lines = ReviewPageLines::new();
    summary_lines
        .try_push(prefixed_line("Action: ", proposal.action.as_str()).as_str())
        .expect("within documented capacity");
    summary_lines
        .try_push(prefixed_line("Account: ", proposal.account_id.as_str()).as_str())
        .expect("within documented capacity");
    summary_lines
        .try_push(prefixed_line("Route: ", proposal.route_type.as_str()).as_str())
        .expect("within documented capacity");

    let mut decision_lines = ReviewPageLines::new();
    for line in [
        "Review on device",
        "Physical approval required",
        "Companion cannot approve alone",
    ] {
        decision_lines
            .try_push(line)
            .expect("within documented capacity");
    }

    let mut pages = ReviewPageList::new();
    for page in [
        review_page("Policy change", summary_lines, ReviewPageAction::Next),
        review_page(
            "Requester",
            requester_lines(&proposal.requested_by),
            ReviewPageAction::Next,
        ),
        review_page("Policy", policy_lines(proposal), ReviewPageAction::Next),
        review_page(
            "Decision",
            decision_lines,
            ReviewPageAction::ApproveOrReject,
        ),
    ] {
        pages.try_push(page).expect("exactly four fixed pages");
    }
    pages
}

/// Worst-case canonical JSON length: every bounded proposal field at capacity,
/// every review line at capacity, and a fully escaped label (six bytes per
/// escaped character) still total under ~4.4 KiB; 6 KiB leaves headroom.
const CANONICAL_JSON_CAPACITY: usize = 6144;

/// A bounded byte writer for the canonical digest material — the
/// allocation-free stand-in for the C++ `std::string` concatenation. Pushes
/// panic past capacity; every writer instance stays within the documented
/// [`CANONICAL_JSON_CAPACITY`] worst case.
struct CanonicalJson {
    bytes: [u8; CANONICAL_JSON_CAPACITY],
    len: usize,
}

impl CanonicalJson {
    fn new() -> Self {
        Self {
            bytes: [0; CANONICAL_JSON_CAPACITY],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }

    fn push_str(&mut self, text: &str) {
        self.push_bytes(text.as_bytes());
    }

    /// Appends a JSON string literal with the C++ `json_escape` escaping:
    /// `"`/`\` and the named control escapes, `\u00XX` for other control
    /// bytes, and every other byte verbatim.
    fn push_json_string(&mut self, value: &str) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.push_bytes(b"\"");
        for byte in value.bytes() {
            match byte {
                b'"' => self.push_bytes(b"\\\""),
                b'\\' => self.push_bytes(b"\\\\"),
                0x08 => self.push_bytes(b"\\b"),
                0x0c => self.push_bytes(b"\\f"),
                b'\n' => self.push_bytes(b"\\n"),
                b'\r' => self.push_bytes(b"\\r"),
                b'\t' => self.push_bytes(b"\\t"),
                byte if byte < 0x20 => {
                    self.push_bytes(b"\\u00");
                    self.push_bytes(&[HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]]);
                }
                byte => self.push_bytes(&[byte]),
            }
        }
        self.push_bytes(b"\"");
    }

    /// Appends `"true"`/`"false"` (the C++ `json_bool`).
    fn push_json_bool(&mut self, value: bool) {
        self.push_str(if value { "true" } else { "false" });
    }

    /// Appends the decimal rendering of `value` (the C++ `std::to_string`).
    fn push_u64(&mut self, value: u64) {
        let mut digits = [0u8; 20];
        let mut position = digits.len();
        let mut remaining = value;
        loop {
            position -= 1;
            digits[position] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        let digit_count = digits.len() - position;
        let start = self.len;
        self.bytes[start..start + digit_count].copy_from_slice(&digits[position..]);
        self.len += digit_count;
    }
}

/// Appends the canonical review-pages JSON array (the C++ `review_pages_json`
/// over `review_page_json`/`review_action_json`).
fn push_pages_json(json: &mut CanonicalJson, pages: &ReviewPageList) {
    json.push_str("[");
    for (page_index, page) in pages.as_slice().iter().enumerate() {
        if page_index > 0 {
            json.push_str(",");
        }
        json.push_str("{\"action\":");
        json.push_str(match page.action {
            ReviewPageAction::Next => "\"next\"",
            ReviewPageAction::ApproveOrReject => "\"approve_or_reject\"",
        });
        json.push_str(",\"lines\":[");
        for (line_index, line) in page.lines.as_slice().iter().enumerate() {
            if line_index > 0 {
                json.push_str(",");
            }
            json.push_json_string(line.as_str());
        }
        json.push_str("],\"title\":");
        json.push_json_string(page.title.as_str());
        json.push_str("}");
    }
    json.push_str("]");
}

/// Appends the canonical proposal JSON object (the C++ `proposal_json` +
/// `requester_json`), key for key in the same order.
fn push_proposal_json(json: &mut CanonicalJson, proposal: &PolicyChangeProposal) {
    json.push_str("{\"account_id\":");
    json.push_json_string(proposal.account_id.as_str());
    json.push_str(",\"action\":");
    json.push_json_string(proposal.action.as_str());
    json.push_str(",\"companion_authoritative\":");
    json.push_json_bool(proposal.companion_authoritative);
    json.push_str(",\"contains_secret_material\":");
    json.push_json_bool(proposal.contains_secret_material);
    json.push_str(",\"created_at\":");
    json.push_u64(proposal.created_at);
    json.push_str(",\"current_policy_id\":");
    json.push_json_string(proposal.current_policy_id.as_str());
    json.push_str(",\"device_review_required\":");
    json.push_json_bool(proposal.device_review_required);
    json.push_str(",\"format\":\"nsealr-policy-change-proposal-v0\"");
    json.push_str(",\"physical_approval_required\":");
    json.push_json_bool(proposal.physical_approval_required);
    json.push_str(",\"proposal_id\":");
    json.push_json_string(proposal.proposal_id.as_str());
    json.push_str(",\"proposed_grant_ids\":[");
    for (grant_index, grant_id) in proposal.proposed_grant_ids.as_slice().iter().enumerate() {
        if grant_index > 0 {
            json.push_str(",");
        }
        json.push_json_string(grant_id.as_str());
    }
    json.push_str("],\"proposed_policy_id\":");
    json.push_json_string(proposal.proposed_policy_id.as_str());
    json.push_str(",\"requested_by\":{\"client_pubkey\":");
    json.push_json_string(proposal.requested_by.client_pubkey.as_str());
    if let Some(label) = &proposal.requested_by.label {
        json.push_str(",\"label\":");
        json.push_json_string(label.as_str());
    }
    json.push_str(",\"surface\":");
    json.push_json_string(proposal.requested_by.surface.as_str());
    json.push_str("},\"route_type\":");
    json.push_json_string(proposal.route_type.as_str());
    json.push_str("}");
}

/// Hashes the canonical `{"pages":…,"proposal":…}` material. Mirrors the C++
/// `policy_change_approval_digest`.
fn policy_change_approval_digest(
    proposal: &PolicyChangeProposal,
    pages: &ReviewPageList,
) -> TrustedReviewApprovalDigest {
    let mut json = CanonicalJson::new();
    json.push_str("{\"pages\":");
    push_pages_json(&mut json, pages);
    json.push_str(",\"proposal\":");
    push_proposal_json(&mut json, proposal);
    json.push_str("}");
    let digest_hex = sha256_hex(json.as_bytes());
    // The digest is ASCII hex, so the str view is valid and fits the alias.
    core::str::from_utf8(&digest_hex)
        .unwrap_or("")
        .parse()
        .expect("within documented capacity")
}

/// Builds the trusted-review request for a policy-change proposal. Mirrors the
/// C++ `build_policy_change_trusted_review_request`.
///
/// # Errors
///
/// Propagates the [`PolicyChangeReviewError`] from
/// [`build_policy_change_review`].
pub fn build_policy_change_trusted_review_request(
    proposal: &PolicyChangeProposal,
) -> Result<TrustedReviewRequest, PolicyChangeReviewError> {
    let review = build_policy_change_review(proposal)?;
    Ok(TrustedReviewRequest {
        request_id: review.proposal_id,
        approval_digest: review.approval_digest,
        pages: review.pages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::import_review::tests::pages_contain_text;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    /// One shared policy-change fixture rendered as Rust literals.
    struct PolicyChangeFixture {
        proposal: PolicyChangeProposal,
        proposal_id: &'static str,
        approval_digest: &'static str,
        pages: [(&'static str, &'static [&'static str], ReviewPageAction); 4],
    }

    fn proposal_from_literals(
        proposal_id: &str,
        account_id: &str,
        route_type: &str,
        surface: &str,
        label: Option<&str>,
        grant_ids: &[&str],
        created_at: u64,
    ) -> PolicyChangeProposal {
        let mut proposed_grant_ids = PolicyChangeGrantIds::new();
        for grant_id in grant_ids {
            proposed_grant_ids.try_push(grant_id).unwrap();
        }
        PolicyChangeProposal {
            proposal_id: proposal_id.parse().unwrap(),
            account_id: account_id.parse().unwrap(),
            route_type: route_type.parse().unwrap(),
            action: "set_policy".parse().unwrap(),
            current_policy_id: "policy-manual-only-persistent-device".parse().unwrap(),
            proposed_policy_id: "policy-scoped-automation-daily-use".parse().unwrap(),
            proposed_grant_ids,
            requested_by: PolicyChangeRequester {
                surface: surface.parse().unwrap(),
                client_pubkey: "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
                    .parse()
                    .unwrap(),
                label: label.map(|text| text.parse().unwrap()),
            },
            created_at,
            device_review_required: true,
            physical_approval_required: true,
            companion_authoritative: false,
            contains_secret_material: false,
        }
    }

    // Proposal + expected review copied from the READ-ONLY
    // specs/vectors/policy-changes/esp32-usb-enable-kind-1-automation.json.
    fn esp32_usb_fixture() -> PolicyChangeFixture {
        PolicyChangeFixture {
            proposal: proposal_from_literals(
                "proposal-esp32-usb-enable-kind-1-automation",
                "acct-esp32-usb-slot-0",
                "esp32_usb_nip46",
                "browser_extension",
                Some("local companion test client"),
                &["grant-esp32-usb-kind-1-session"],
                1_710_000_200,
            ),
            proposal_id: "proposal-esp32-usb-enable-kind-1-automation",
            approval_digest: "74859ddf5324181cce3602869f9d91c5d4565d9088c5c672526b1d7b04137aa6",
            pages: [
                (
                    "Policy change",
                    &[
                        "Action: set_policy",
                        "Account: acct-esp32-usb-slot-0",
                        "Route: esp32_usb_nip46",
                    ],
                    ReviewPageAction::Next,
                ),
                (
                    "Requester",
                    &[
                        "Surface: browser_extension",
                        "Client: 4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                        "Label: local companion test client",
                    ],
                    ReviewPageAction::Next,
                ),
                (
                    "Policy",
                    &[
                        "From: policy-manual-only-persistent-device",
                        "To: policy-scoped-automation-daily-use",
                        "Grants: 1",
                        "Grant: grant-esp32-usb-kind-1-session",
                    ],
                    ReviewPageAction::Next,
                ),
                (
                    "Decision",
                    &[
                        "Review on device",
                        "Physical approval required",
                        "Companion cannot approve alone",
                    ],
                    ReviewPageAction::ApproveOrReject,
                ),
            ],
        }
    }

    // Proposal + expected review copied from the READ-ONLY specs/vectors/
    // policy-changes/custom-hardware-wallet-enable-kind-1-automation.json.
    fn custom_hardware_wallet_fixture() -> PolicyChangeFixture {
        PolicyChangeFixture {
            proposal: proposal_from_literals(
                "proposal-custom-hardware-wallet-enable-kind-1-automation",
                "acct-custom-hardware-wallet-slot-0",
                "custom_hardware_wallet",
                "desktop_app",
                Some("local companion test client"),
                &["grant-custom-hardware-wallet-kind-1-session"],
                1_710_000_300,
            ),
            proposal_id: "proposal-custom-hardware-wallet-enable-kind-1-automation",
            approval_digest: "cc06e69fa24fdf2fb5509dc6af208baad7d99bcc1e2798e868eca152e3908bb9",
            pages: [
                (
                    "Policy change",
                    &[
                        "Action: set_policy",
                        "Account: acct-custom-hardware-wallet-slot-0",
                        "Route: custom_hardware_wallet",
                    ],
                    ReviewPageAction::Next,
                ),
                (
                    "Requester",
                    &[
                        "Surface: desktop_app",
                        "Client: 4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                        "Label: local companion test client",
                    ],
                    ReviewPageAction::Next,
                ),
                (
                    "Policy",
                    &[
                        "From: policy-manual-only-persistent-device",
                        "To: policy-scoped-automation-daily-use",
                        "Grants: 1",
                        "Grant: grant-custom-hardware-wallet-kind-1-session",
                    ],
                    ReviewPageAction::Next,
                ),
                (
                    "Decision",
                    &[
                        "Review on device",
                        "Physical approval required",
                        "Companion cannot approve alone",
                    ],
                    ReviewPageAction::ApproveOrReject,
                ),
            ],
        }
    }

    /// The Rust analogue of the C++ `assert_trusted_review_pages` (title, lines,
    /// action; the policy-change builder leaves indicator/styles/logical id
    /// empty, as the C++ did).
    fn assert_fixture_pages(
        actual: &[TrustedReviewPage],
        expected: &[(&str, &[&str], ReviewPageAction)],
    ) {
        assert_eq!(actual.len(), expected.len());
        for (page, (title, lines, action)) in actual.iter().zip(expected) {
            assert_eq!(page.title, *title);
            let actual_lines: Vec<&str> = page
                .lines
                .as_slice()
                .iter()
                .map(|line| line.as_str())
                .collect();
            assert_eq!(&actual_lines, lines);
            assert_eq!(page.action, *action);
            assert!(page.page_indicator.is_empty());
            assert!(page.body_line_styles.is_empty());
            assert!(page.logical_page_id.is_empty());
        }
    }

    fn assert_fixture_replays(fixture: &PolicyChangeFixture) {
        let review = build_policy_change_review(&fixture.proposal).unwrap();
        assert_eq!(review.proposal_id, fixture.proposal_id);
        assert_eq!(review.approval_digest, fixture.approval_digest);
        let expected: Vec<(&str, &[&str], ReviewPageAction)> = fixture
            .pages
            .iter()
            .map(|(title, lines, action)| (*title, *lines, *action))
            .collect();
        assert_fixture_pages(review.pages.as_slice(), &expected);

        let trusted_request =
            build_policy_change_trusted_review_request(&fixture.proposal).unwrap();
        assert_eq!(trusted_request.request_id, fixture.proposal_id);
        assert_eq!(trusted_request.approval_digest, review.approval_digest);
        assert_fixture_pages(trusted_request.pages.as_slice(), &expected);
    }

    // Port of the C++ `test_policy_change_review_matches_shared_vector`.
    #[test]
    fn matches_shared_vector() {
        let fixture = esp32_usb_fixture();
        assert_fixture_replays(&fixture);

        let review = build_policy_change_review(&fixture.proposal).unwrap();
        assert!(pages_contain_text(
            review.pages.as_slice(),
            "Review on device"
        ));
        assert!(pages_contain_text(
            review.pages.as_slice(),
            "Physical approval required",
        ));
        assert!(pages_contain_text(
            review.pages.as_slice(),
            "Companion cannot approve alone",
        ));
    }

    // Fixture replay for the second shared policy-changes vector (the C++
    // loaded every specs/vectors/policy-changes/*.json through the generated
    // vector header; the named case above replays the first).
    #[test]
    fn replays_custom_hardware_wallet_fixture() {
        assert_fixture_replays(&custom_hardware_wallet_fixture());
    }

    // Port of the C++
    // `test_policy_change_review_rejects_companion_authority_or_secret_material`.
    #[test]
    fn rejects_companion_authority_or_secret_material() {
        let mut unsafe_proposal = esp32_usb_fixture().proposal;
        unsafe_proposal.companion_authoritative = true;
        assert_eq!(
            build_policy_change_review(&unsafe_proposal),
            Err(PolicyChangeReviewError::CompanionAuthoritative),
        );

        let mut unsafe_proposal = esp32_usb_fixture().proposal;
        unsafe_proposal.contains_secret_material = true;
        assert_eq!(
            build_policy_change_review(&unsafe_proposal),
            Err(PolicyChangeReviewError::ContainsSecretMaterial),
        );

        let mut unsafe_proposal = esp32_usb_fixture().proposal;
        unsafe_proposal.physical_approval_required = false;
        assert_eq!(
            build_policy_change_review(&unsafe_proposal),
            Err(PolicyChangeReviewError::PhysicalApprovalNotRequired),
        );
    }

    /// One mutation that should invalidate an otherwise valid proposal.
    type ProposalMutation = fn(&mut PolicyChangeProposal);

    // Every remaining C++ validation rule, in evaluation order (the C++
    // exercised these branches through PolicyChangeReviewError throws; the
    // named rejection case above covers the three danger flags).
    #[test]
    fn rejects_each_invalid_proposal_field() {
        let cases: [(ProposalMutation, PolicyChangeReviewError); 14] = [
            (
                |proposal| proposal.proposal_id = "prop-missing-prefix".parse().unwrap(),
                PolicyChangeReviewError::InvalidProposalId,
            ),
            (
                // Empty remainder after the "proposal-" prefix.
                |proposal| proposal.proposal_id = "proposal-".parse().unwrap(),
                PolicyChangeReviewError::InvalidProposalId,
            ),
            (
                // A space is outside the stable-id charset.
                |proposal| proposal.proposal_id = "proposal-bad id".parse().unwrap(),
                PolicyChangeReviewError::InvalidProposalId,
            ),
            (
                |proposal| proposal.account_id = "acct has spaces".parse().unwrap(),
                PolicyChangeReviewError::InvalidAccountId,
            ),
            (
                // QR-only routes have no persistent device policy display.
                |proposal| proposal.route_type = "esp32_qr_vault".parse().unwrap(),
                PolicyChangeReviewError::UnsupportedRouteType,
            ),
            (
                |proposal| proposal.action = "add_grant".parse().unwrap(),
                PolicyChangeReviewError::UnsupportedAction,
            ),
            (
                |proposal| proposal.current_policy_id = "manual-only".parse().unwrap(),
                PolicyChangeReviewError::InvalidCurrentPolicyId,
            ),
            (
                |proposal| proposal.proposed_policy_id = "policy-".parse().unwrap(),
                PolicyChangeReviewError::InvalidProposedPolicyId,
            ),
            (
                |proposal| {
                    proposal.proposed_grant_ids = PolicyChangeGrantIds::new();
                    proposal
                        .proposed_grant_ids
                        .try_push("grants-wrong-prefix")
                        .unwrap();
                },
                PolicyChangeReviewError::InvalidGrantId,
            ),
            (
                |proposal| {
                    proposal.proposed_grant_ids = PolicyChangeGrantIds::new();
                    proposal
                        .proposed_grant_ids
                        .try_push("grant-duplicate")
                        .unwrap();
                    proposal
                        .proposed_grant_ids
                        .try_push("grant-unique")
                        .unwrap();
                    proposal
                        .proposed_grant_ids
                        .try_push("grant-duplicate")
                        .unwrap();
                },
                PolicyChangeReviewError::DuplicateGrantIds,
            ),
            (
                |proposal| proposal.requested_by.surface = "mobile_app".parse().unwrap(),
                PolicyChangeReviewError::UnsupportedSurface,
            ),
            (
                // 63 hex chars: valid charset, wrong length.
                |proposal| {
                    proposal.requested_by.client_pubkey =
                        "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871a"
                            .parse()
                            .unwrap();
                },
                PolicyChangeReviewError::InvalidClientPubkey,
            ),
            (
                |proposal| proposal.requested_by.label = Some(PolicyChangeLabel::new()),
                PolicyChangeReviewError::EmptyLabel,
            ),
            (
                |proposal| proposal.created_at = 0,
                PolicyChangeReviewError::InvalidCreatedAt,
            ),
        ];
        for (mutate, expected) in cases {
            let mut proposal = esp32_usb_fixture().proposal;
            mutate(&mut proposal);
            assert_eq!(build_policy_change_review(&proposal), Err(expected));
        }

        // Uppercase hex is rejected (the C++ lowercase-only check).
        let mut proposal = esp32_usb_fixture().proposal;
        proposal.requested_by.client_pubkey =
            "4F355BDCB7CC0AF728EF3CCEB9615D90684BB5B2CA5F859AB0F0B704075871AA"
                .parse()
                .unwrap();
        assert_eq!(
            build_policy_change_review(&proposal),
            Err(PolicyChangeReviewError::InvalidClientPubkey),
        );

        // device_review_required=false is rejected (the named danger-flag case
        // covers the other three promise flags).
        let mut proposal = esp32_usb_fixture().proposal;
        proposal.device_review_required = false;
        assert_eq!(
            build_policy_change_review(&proposal),
            Err(PolicyChangeReviewError::DeviceReviewNotRequired),
        );

        // The trusted-review builder propagates validation errors.
        let mut proposal = esp32_usb_fixture().proposal;
        proposal.created_at = 0;
        assert_eq!(
            build_policy_change_trusted_review_request(&proposal),
            Err(PolicyChangeReviewError::InvalidCreatedAt),
        );
    }

    // Every error variant renders the exact C++ throw message (Display and
    // message() both).
    #[test]
    fn error_messages_match_cpp_text() {
        let cases = [
            (
                PolicyChangeReviewError::InvalidProposalId,
                "proposal_id must be a proposal-* stable string id",
            ),
            (
                PolicyChangeReviewError::InvalidAccountId,
                "account_id must be a stable string id",
            ),
            (
                PolicyChangeReviewError::UnsupportedRouteType,
                "route_type must be a device-display persistent policy route",
            ),
            (
                PolicyChangeReviewError::UnsupportedAction,
                "policy change action must be set_policy",
            ),
            (
                PolicyChangeReviewError::InvalidCurrentPolicyId,
                "current_policy_id must be a policy-* stable string id",
            ),
            (
                PolicyChangeReviewError::InvalidProposedPolicyId,
                "proposed_policy_id must be a policy-* stable string id",
            ),
            (
                PolicyChangeReviewError::InvalidGrantId,
                "proposed grant id must be a grant-* stable string id",
            ),
            (
                PolicyChangeReviewError::DuplicateGrantIds,
                "proposed_grant_ids must be unique",
            ),
            (
                PolicyChangeReviewError::UnsupportedSurface,
                "requested_by.surface is unsupported",
            ),
            (
                PolicyChangeReviewError::InvalidClientPubkey,
                "requested_by.client_pubkey must be 32-byte lowercase hex",
            ),
            (
                PolicyChangeReviewError::EmptyLabel,
                "requested_by.label must be a non-empty string",
            ),
            (
                PolicyChangeReviewError::InvalidCreatedAt,
                "created_at must be a positive integer",
            ),
            (
                PolicyChangeReviewError::DeviceReviewNotRequired,
                "device_review_required must be true",
            ),
            (
                PolicyChangeReviewError::PhysicalApprovalNotRequired,
                "physical_approval_required must be true",
            ),
            (
                PolicyChangeReviewError::CompanionAuthoritative,
                "companion_authoritative must be false",
            ),
            (
                PolicyChangeReviewError::ContainsSecretMaterial,
                "contains_secret_material must be false",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.message(), expected);
            assert_eq!(format!("{error}"), expected);
        }
    }

    // A label-free requester omits the Label line and the JSON label key (the
    // C++ optional-label branches), and the canonical JSON escapes label
    // characters (the C++ json_escape branches) — digests must be stable,
    // 64-hex, and sensitive to the label bytes.
    #[test]
    fn optional_label_and_label_escaping_shape_the_digest() {
        let mut no_label = esp32_usb_fixture().proposal;
        no_label.requested_by.label = None;
        let review = build_policy_change_review(&no_label).unwrap();
        let requester_lines: Vec<&str> = review.pages.as_slice()[1]
            .lines
            .as_slice()
            .iter()
            .map(|line| line.as_str())
            .collect();
        assert_eq!(
            requester_lines,
            [
                "Surface: browser_extension",
                "Client: 4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
            ],
        );
        assert_ne!(review.approval_digest, esp32_usb_fixture().approval_digest,);

        // One label per C++ json_escape branch: quote, backslash, \b, \f, \n,
        // \r, \t, another control byte (), and plain text.
        let labels = [
            "quote\"label",
            "back\\slash",
            "bell\u{0008}label",
            "feed\u{000c}label",
            "line\nlabel",
            "return\rlabel",
            "tab\tlabel",
            "ctrl\u{0001}label",
            "plain label",
        ];
        let mut digests: Vec<String> = Vec::new();
        for label in labels {
            let mut proposal = esp32_usb_fixture().proposal;
            proposal.requested_by.label = Some(label.parse().unwrap());
            let review = build_policy_change_review(&proposal).unwrap();
            let digest = review.approval_digest.as_str();
            assert_eq!(digest.len(), 64);
            assert!(digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
            digests.push(String::from(digest));
        }
        // Deterministic per label, distinct across labels.
        for (index, label) in labels.iter().enumerate() {
            let mut proposal = esp32_usb_fixture().proposal;
            proposal.requested_by.label = Some(label.parse().unwrap());
            let review = build_policy_change_review(&proposal).unwrap();
            assert_eq!(review.approval_digest.as_str(), digests[index]);
        }
        let mut unique = digests.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), digests.len());
    }

    // Container plumbing for the fixed-capacity grant-id list (no single named
    // C++ case: the C++ used std::vector directly).
    #[test]
    fn grant_id_list_pushes_and_rejects_overflow() {
        let mut grants = PolicyChangeGrantIds::new();
        assert!(grants.is_empty());
        assert_eq!(grants.len(), 0);
        assert_eq!(grants, PolicyChangeGrantIds::default());

        let too_long_body = [b'g'; MAX_POLICY_CHANGE_ID_CHARS + 1];
        let too_long = core::str::from_utf8(&too_long_body).unwrap();
        assert_eq!(grants.try_push(too_long), Err(TextError::TooLong));
        assert!(grants.is_empty());

        for index in 0..MAX_POLICY_CHANGE_GRANTS {
            let mut grant_id = PolicyChangeId::new();
            grant_id.try_push_str("grant-").unwrap();
            grant_id.try_push_usize(index).unwrap();
            grants.try_push(grant_id.as_str()).unwrap();
        }
        assert_eq!(grants.len(), MAX_POLICY_CHANGE_GRANTS);
        assert!(!grants.is_empty());
        assert_eq!(grants.as_slice()[0], "grant-0");
        assert_eq!(grants.clone(), grants);
        assert_eq!(grants.try_push("grant-overflow"), Err(TextError::TooLong));
        assert_eq!(grants.len(), MAX_POLICY_CHANGE_GRANTS);

        // A full grant list still builds: 3 fixed lines + 4 grant lines fit the
        // Policy page, and the digest stays well-formed.
        let mut proposal = esp32_usb_fixture().proposal;
        proposal.proposed_grant_ids = grants;
        let review = build_policy_change_review(&proposal).unwrap();
        let policy_lines: Vec<&str> = review.pages.as_slice()[2]
            .lines
            .as_slice()
            .iter()
            .map(|line| line.as_str())
            .collect();
        assert_eq!(
            policy_lines,
            [
                "From: policy-manual-only-persistent-device",
                "To: policy-scoped-automation-daily-use",
                "Grants: 4",
                "Grant: grant-0",
                "Grant: grant-1",
                "Grant: grant-2",
                "Grant: grant-3",
            ],
        );
    }
}
