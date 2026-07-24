//! Trusted review — data model, display rendering, physical controls, review
//! sessions, and the QR/serial review flows.
//!
//! M-T3.4 landed the pure data model ([`types`]); milestone M-T3.6 lands the
//! review logic ported from the C++ reference `host_core` module pairs:
//!
//! - [`signer_identity`] ← `signer_identity.hpp` (migrated out of
//!   `session/account.rs` to its definitive home)
//! - [`buttons`] ← the debounce state machine the C++ board app carried in
//!   `esp32_s3_usb_signer/main/t_display_s3_button_logic.cpp/.hpp`,
//!   generalized over caller-supplied timings (M-T3.7)
//! - [`controls`] ← `review_controls.cpp/.hpp`
//! - [`display`] ← `review_display.cpp/.hpp`
//! - [`trusted`] ← `trusted_review.cpp/.hpp` (session logic; the data model
//!   stays in [`types`])
//! - [`qr`] ← `qr_review.cpp/.hpp`
//! - [`qr_flow`] ← `qr_review_flow.cpp/.hpp`
//! - [`serial`] ← `serial_review.cpp/.hpp`
//!
//! The device protocol on top of this layer (`device_protocol.cpp/.hpp`) lives
//! in [`crate::protocol`].

pub mod buttons;
pub mod controls;
pub mod display;
pub mod qr;
pub mod qr_flow;
pub mod serial;
pub mod signer_identity;
#[cfg(test)]
pub(crate) mod test_fixtures;
pub mod trusted;
pub mod types;
