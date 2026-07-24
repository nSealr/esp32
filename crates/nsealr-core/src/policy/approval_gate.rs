//! Approval-digest binding gate.
//!
//! Ported from the C++ reference `host_core` sources `src/approval_gate.cpp` +
//! `include/nsealr/approval_gate.hpp` for behaviour parity. The gate binds a
//! signing decision to a specific `(request_id, approval_digest)` pair: signing
//! is only permitted once that exact pair has been explicitly approved, so a
//! companion cannot swap the reviewed material out from under an approval.
//!
//! The C++ used `std::string` for the request id and approval digest; this
//! allocation-free port stores them as bounded inline text ([`FixedStr`]). The
//! capacities cover the policy-change proposal id and the SHA-256 hex digest the
//! review modules feed in.

use crate::text::FixedStr;
use core::str::FromStr;

/// Maximum byte length of a bound request id. Covers the policy-change proposal
/// id (`"proposal-"` + up to 119 id chars) and the shorter QR/serial request
/// ids the review flows bind.
pub const MAX_APPROVAL_REQUEST_ID_CHARS: usize = 128;

/// Maximum byte length of a bound approval digest — a SHA-256 rendered as 64
/// lowercase hex characters.
pub const MAX_APPROVAL_DIGEST_CHARS: usize = 64;

/// A request id bound by the gate.
pub type ApprovalRequestId = FixedStr<MAX_APPROVAL_REQUEST_ID_CHARS>;

/// An approval digest bound by the gate.
pub type ApprovalDigest = FixedStr<MAX_APPROVAL_DIGEST_CHARS>;

/// The current decision recorded by an [`ApprovalGate`]. Mirrors the C++
/// `ApprovalDecision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// No terminal decision has been recorded for the active review yet.
    Pending,
    /// The active `(request_id, approval_digest)` pair was approved.
    Approved,
    /// The active request was rejected.
    Rejected,
}

/// Binds a signing decision to a reviewed `(request_id, approval_digest)` pair.
/// Mirrors the C++ `ApprovalGate` method for method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGate {
    active_request_id: ApprovalRequestId,
    active_approval_digest: ApprovalDigest,
    decision: ApprovalDecision,
}

impl ApprovalGate {
    /// Creates a gate with no active review (the C++ default-constructed state:
    /// empty ids and a [`ApprovalDecision::Pending`] decision).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active_request_id: ApprovalRequestId::new(),
            active_approval_digest: ApprovalDigest::new(),
            decision: ApprovalDecision::Pending,
        }
    }

    /// Begins a review of `request_id`/`approval_digest`, resetting the decision
    /// to [`ApprovalDecision::Pending`]. Mirrors the C++ `begin_review`.
    ///
    /// # Panics
    ///
    /// Panics if `request_id` exceeds [`MAX_APPROVAL_REQUEST_ID_CHARS`] or
    /// `approval_digest` exceeds [`MAX_APPROVAL_DIGEST_CHARS`]; callers bind ids
    /// and digests within those documented bounds.
    pub fn begin_review(&mut self, request_id: &str, approval_digest: &str) {
        self.active_request_id =
            ApprovalRequestId::from_str(request_id).expect("request id within documented capacity");
        self.active_approval_digest = ApprovalDigest::from_str(approval_digest)
            .expect("approval digest within documented capacity");
        self.decision = ApprovalDecision::Pending;
    }

    /// Approves the review iff `request_id`/`approval_digest` exactly match the
    /// active pair; a mismatch is silently ignored (the decision is unchanged).
    /// Mirrors the C++ `approve`.
    pub fn approve(&mut self, request_id: &str, approval_digest: &str) {
        if self.active_request_id == request_id && self.active_approval_digest == approval_digest {
            self.decision = ApprovalDecision::Approved;
        }
    }

    /// Rejects the review iff `request_id` matches the active request. Mirrors
    /// the C++ `reject`.
    pub fn reject(&mut self, request_id: &str) {
        if self.active_request_id == request_id {
            self.decision = ApprovalDecision::Rejected;
        }
    }

    /// Returns `true` iff the active review was approved and `request_id`/
    /// `approval_digest` still exactly match the approved pair. Mirrors the C++
    /// `can_sign`.
    #[must_use]
    pub fn can_sign(&self, request_id: &str, approval_digest: &str) -> bool {
        self.decision == ApprovalDecision::Approved
            && self.active_request_id == request_id
            && self.active_approval_digest == approval_digest
    }

    /// Returns the current decision. Mirrors the C++ `decision`.
    #[must_use]
    pub fn decision(&self) -> ApprovalDecision {
        self.decision
    }

    /// Returns the active request id. Mirrors the C++ `active_request_id`.
    #[must_use]
    pub fn active_request_id(&self) -> &str {
        self.active_request_id.as_str()
    }

    /// Returns the active approval digest. Mirrors the C++
    /// `active_approval_digest`.
    #[must_use]
    pub fn active_approval_digest(&self) -> &str {
        self.active_approval_digest.as_str()
    }
}

impl Default for ApprovalGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Approval digests copied from the READ-ONLY specs/vectors/review-screens/
    // kind-1-basic.json and kind-1-tags.json (`screen_review.approval_digest`);
    // the C++ test consumed them as `kBasicReviewScreenApprovalDigest` /
    // `kTaggedReviewScreenApprovalDigest` from the generated vector header.
    const BASIC_REVIEW_SCREEN_APPROVAL_DIGEST: &str =
        "a09ddd564e439fdd4756da6863156eddcfc50c295af453af1c78c35986c303a5";
    const TAGGED_REVIEW_SCREEN_APPROVAL_DIGEST: &str =
        "b45328f9ef96122900562d161cca5f09e24bfdb66676c46ebbcfe08dd661eb30";

    // Port of the C++ `test_approval_gate_requires_matching_approval`.
    #[test]
    fn requires_matching_approval() {
        let mut gate = ApprovalGate::new();
        gate.begin_review("req-kind-1-basic", BASIC_REVIEW_SCREEN_APPROVAL_DIGEST);

        // begin_review binds the active pair and resets to Pending.
        assert_eq!(gate.decision(), ApprovalDecision::Pending);
        assert_eq!(gate.active_request_id(), "req-kind-1-basic");
        assert_eq!(
            gate.active_approval_digest(),
            BASIC_REVIEW_SCREEN_APPROVAL_DIGEST,
        );

        // Pending never permits signing, even for the exact bound pair.
        assert!(!gate.can_sign("req-kind-1-basic", BASIC_REVIEW_SCREEN_APPROVAL_DIGEST));
        assert!(!gate.can_sign("different", BASIC_REVIEW_SCREEN_APPROVAL_DIGEST));

        // Approving a mismatched digest does not record an approval.
        gate.approve("req-kind-1-basic", "00");
        assert!(!gate.can_sign("req-kind-1-basic", BASIC_REVIEW_SCREEN_APPROVAL_DIGEST));

        // Approving a mismatched request id does not record an approval.
        gate.approve("different", BASIC_REVIEW_SCREEN_APPROVAL_DIGEST);
        assert!(!gate.can_sign("req-kind-1-basic", BASIC_REVIEW_SCREEN_APPROVAL_DIGEST));

        // Approving the exact bound pair permits signing that pair only.
        gate.approve("req-kind-1-basic", BASIC_REVIEW_SCREEN_APPROVAL_DIGEST);
        assert_eq!(gate.decision(), ApprovalDecision::Approved);
        assert!(gate.can_sign("req-kind-1-basic", BASIC_REVIEW_SCREEN_APPROVAL_DIGEST));
        assert!(!gate.can_sign("req-kind-1-basic", TAGGED_REVIEW_SCREEN_APPROVAL_DIGEST));

        // Rejecting the new review is terminal and blocks signing.
        gate.begin_review("req-kind-1-tags", TAGGED_REVIEW_SCREEN_APPROVAL_DIGEST);
        gate.reject("req-kind-1-tags");
        assert!(!gate.can_sign("req-kind-1-tags", TAGGED_REVIEW_SCREEN_APPROVAL_DIGEST));
        assert_eq!(gate.decision(), ApprovalDecision::Rejected);
    }

    // Reject only fires for the active request id (the mismatch branch of
    // `reject`), and Default matches an explicitly `new()` gate.
    #[test]
    fn reject_ignores_mismatched_request_and_default_is_pending() {
        assert_eq!(ApprovalGate::default(), ApprovalGate::new());

        let mut gate = ApprovalGate::new();
        gate.begin_review("req-active", BASIC_REVIEW_SCREEN_APPROVAL_DIGEST);
        gate.reject("req-other");
        assert_eq!(gate.decision(), ApprovalDecision::Pending);
        gate.approve("req-active", BASIC_REVIEW_SCREEN_APPROVAL_DIGEST);
        assert!(gate.can_sign("req-active", BASIC_REVIEW_SCREEN_APPROVAL_DIGEST));
    }
}
