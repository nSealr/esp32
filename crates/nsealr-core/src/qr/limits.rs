//! Shared parser / transport size limits.
//!
//! Ported from the C++ reference `host_core` header `include/nsealr/limits.hpp`
//! (the `kMax*` constants) plus `include/nsealr/qr_response_display.hpp`
//! (`kMaxQrResponseDisplayCycles`). These are the nSealr v0 implementation safety
//! limits shared with the companion/host via the specs profile
//! `specs/vectors/limits/nsealr-v0.json`; the C++ test
//! `test_qr_limits_match_shared_profile` pins each value against that profile and
//! the Rust port reproduces the same pinning in `envelope`'s test module.
//!
//! They are plain `usize`/`u64` constants (not a struct) so callers can size the
//! fixed buffers this crate uses in place of the C++ heap allocations.

/// Maximum accepted `request_id` length in bytes. C++ `kMaxRequestIdLength`.
pub const MAX_REQUEST_ID_LENGTH: usize = 128;
/// Maximum decoded signing-request JSON size in bytes. C++
/// `kMaxDecodedRequestJsonBytes`.
pub const MAX_DECODED_REQUEST_JSON_BYTES: usize = 704;
/// Maximum decoded JSON carried by a single static QR envelope. C++
/// `kMaxStaticQrDecodedJsonBytes`.
pub const MAX_STATIC_QR_DECODED_JSON_BYTES: usize = 704;
/// Maximum decoded JSON carried by an animated QR envelope frame set. C++
/// `kMaxAnimatedQrDecodedJsonBytes`.
pub const MAX_ANIMATED_QR_DECODED_JSON_BYTES: usize = 4096;
/// Maximum base64url characters per animated QR frame chunk. C++
/// `kMaxAnimatedQrFramePayloadChars`.
pub const MAX_ANIMATED_QR_FRAME_PAYLOAD_CHARS: usize = 256;
/// Maximum number of frames in an animated QR envelope. C++
/// `kMaxAnimatedQrFrameCount`.
pub const MAX_ANIMATED_QR_FRAME_COUNT: usize = 64;
/// Maximum serial frame length in bytes (including prefix and checksum). C++
/// `kMaxSerialFrameBytes`.
pub const MAX_SERIAL_FRAME_BYTES: usize = 1024;
/// Maximum event `content` size in bytes. C++ `kMaxContentUtf8Bytes`.
pub const MAX_CONTENT_UTF8_BYTES: usize = 512;
/// Maximum number of tags in an event template. C++ `kMaxTagCount`.
pub const MAX_TAG_COUNT: usize = 16;
/// Maximum number of fields in a single tag. C++ `kMaxTagFieldsPerTag`.
pub const MAX_TAG_FIELDS_PER_TAG: usize = 8;
/// Maximum size in bytes of a single tag field. C++ `kMaxTagFieldUtf8Bytes`.
pub const MAX_TAG_FIELD_UTF8_BYTES: usize = 64;
/// Maximum combined size in bytes of all tag fields. C++ `kMaxTotalTagUtf8Bytes`.
pub const MAX_TOTAL_TAG_UTF8_BYTES: usize = 4096;
/// Maximum JSON-safe integer (`2^53 - 1`). C++ `kMaxSafeInteger`.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Maximum animated-response display cycles. C++ `kMaxQrResponseDisplayCycles`
/// (from `qr_response_display.hpp`).
pub const MAX_QR_RESPONSE_DISPLAY_CYCLES: usize = 16;
