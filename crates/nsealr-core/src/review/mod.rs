//! Trusted-review model shared across custody and review flows.
//!
//! M-T3.4 lands only the pure data model ([`types`]) that the session/custody
//! port needs; the review *logic* (`review_controls.cpp`, `review_display.cpp`,
//! `trusted_review.cpp`, `qr_review*.cpp`) arrives with milestone M-T3.6.

pub mod types;
