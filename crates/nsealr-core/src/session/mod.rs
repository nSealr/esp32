//! RAM-only session custody — keyring, source parsing/generation, import review,
//! backup review, and account selection.
//!
//! Ported from the C++ reference `host_core` `session_*` module pairs. Milestone
//! M-T3.4a lands the custody core:
//!
//! - [`keyring`] ← `session_keyring.cpp/.hpp` (full port)
//! - [`import_review`] ← `session_import_review.cpp/.hpp` (full port)
//! - [`source_generation`] ← `session_source_generation.cpp/.hpp` (full port)
//! - [`source_qr`] ← `session_source_qr.cpp/.hpp` (full port)
//! - [`source_backup`] ← `session_source_backup.cpp/.hpp` (**partial**: review
//!   builder + payload; the interactive flows need `ReviewControlSession` /
//!   `render_review_page` from M-T3.6 and close in M-T3.4b)
//! - [`account`] ← `session_account.cpp/.hpp` (**partial**:
//!   `select_session_account`; `device_protocol_context_for_session_account`
//!   needs `DeviceProtocolContext` from M-T3.6 and closes in M-T3.4b)
//!
//! Not yet ported (M-T3.4b, after the M-T3.5/M-T3.6 substrate):
//! `session_import_flow.cpp/.hpp` and `session_source_qr_import_flow.cpp/.hpp`
//! (both are `ReviewControlSession`-driven flows).

pub mod account;
pub mod import_review;
pub mod keyring;
pub mod source_backup;
pub mod source_generation;
pub mod source_qr;
