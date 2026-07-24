//! Serial line transport framing (`nsealr1f:` frames) and byte-wise line
//! ingestion.
//!
//! [`frame`] is ported from the C++ reference `host_core` sources
//! `src/serial_frame.cpp` + `include/nsealr/serial_frame.hpp`; [`input`] from
//! the board-app accumulator
//! `esp32_s3_usb_signer/main/t_display_s3_serial_input.cpp/.hpp` (M-T3.7).

pub mod frame;
pub mod input;
