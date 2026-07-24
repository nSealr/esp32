//! QR transport layer: envelope framing, animated multi-frame envelopes, the
//! signing-request parser, the response-display frame builder, and the shared
//! size limits.
//!
//! Ported from the C++ reference `host_core` sources `src/qr_envelope.cpp` +
//! `src/qr_response_display.cpp` and their headers, plus `include/nsealr/limits.hpp`.
//! The two C++ translation units carry deliberately different JSON handling — the
//! envelope parser decodes `\uXXXX` escapes into real UTF-8 and accepts only
//! integer number tokens, while the response-display parser collapses every
//! `\uXXXX` escape to `?` and accepts JSON floats/exponents when skipping values —
//! so they are ported as two independent parsers here to preserve that parity.

pub mod envelope;
pub mod limits;
pub mod response_display;
