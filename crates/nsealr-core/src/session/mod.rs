//! RAM-only session custody — keyring, source parsing/generation, import review
//! and flow, backup review and flow, and account selection.
//!
//! Ported from the C++ reference `host_core` `session_*` module pairs.
//! Milestone M-T3.4a landed the custody core; milestone M-T3.4b completed the
//! review-driven flows on the M-T3.5/M-T3.6 substrate:
//!
//! - [`keyring`] ← `session_keyring.cpp/.hpp` (full port)
//! - [`import_review`] ← `session_import_review.cpp/.hpp` (full port)
//! - [`import_flow`] ← `session_import_flow.cpp/.hpp` (full port, M-T3.4b)
//! - [`source_generation`] ← `session_source_generation.cpp/.hpp` (full port)
//! - [`source_qr`] ← `session_source_qr.cpp/.hpp` +
//!   `session_source_qr_import_flow.cpp/.hpp` (full port; the QR-driven import
//!   flows landed in M-T3.4b)
//! - [`source_backup`] ← `session_source_backup.cpp/.hpp` (full port; the
//!   interactive flows landed in M-T3.4b)
//! - [`account`] ← `session_account.cpp/.hpp` (full port;
//!   `device_protocol_context_for_session_account` landed in M-T3.4b)

pub mod account;
pub mod import_flow;
pub mod import_review;
pub mod keyring;
pub mod source_backup;
pub mod source_generation;
pub mod source_qr;
