//! Policy and approval — approval-digest binding, signing readiness gates, and
//! device-reviewed policy changes.
//!
//! Ported from the C++ reference `host_core` module pairs. Milestone M-T3.5
//! lands:
//!
//! - [`approval_gate`] ← `approval_gate.cpp/.hpp` (full port)
//! - [`signing_policy`] ← `signing_policy.cpp/.hpp` (full port)
//! - [`policy_change_review`] ← `policy_change_review.cpp/.hpp` (**partial**:
//!   validation + review/trusted-review-request builders; the interactive
//!   `run_policy_change_review_flow` drives a `TrustedReviewSession` from
//!   M-T3.6 and closes in M-T3.4b)

pub mod approval_gate;
pub mod policy_change_review;
pub mod signing_policy;
