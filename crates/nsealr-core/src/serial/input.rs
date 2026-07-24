//! Byte-wise serial line accumulation with overlong-frame draining.
//!
//! Ported from the C++ reference board app sources
//! `esp32_s3_usb_signer/main/t_display_s3_serial_input.cpp/.hpp` for behaviour
//! parity, generalized in milestone M-T3.7: nothing in the C++ logic was
//! board-specific (the frame bound is a per-call parameter there too), so the
//! accumulator moves into the crate as the ingestion side of the serial
//! transport — it feeds completed lines to
//! [`decode_serial_frame`](crate::serial::frame::decode_serial_frame) and
//! enforces the drain-until-newline recovery after an overlong frame so a
//! flooding peer cannot wedge the reader.
//!
//! The C++ accumulated into a growable `std::string` and returned the line by
//! value; this allocation-free port stores the line in a
//! [`MAX_SERIAL_FRAME_BYTES`]-sized inline buffer and returns it borrowed.
//! Two deviations, both documented: the byte that overflows the bound is not
//! stored (the C++ pushed it and then discarded the whole line — unobservable
//! either way), and `max_frame_bytes` values beyond the fixed capacity are
//! reported as [`SerialInputError::MaxFrameBytesExceedCapacity`] (no C++
//! analogue; the C++ string grew without bound).

use crate::qr::limits::MAX_SERIAL_FRAME_BYTES;
use core::fmt;

/// Errors reported by [`SerialLineInput::push_byte`].
/// [`Self::ZeroMaxFrameBytes`] corresponds to the C++ `std::invalid_argument`
/// throw site; [`Self::message`] returns the exact C++ text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialInputError {
    /// `max_frame_bytes` was zero. C++ `std::invalid_argument`.
    ZeroMaxFrameBytes,
    /// `max_frame_bytes` exceeds the fixed [`MAX_SERIAL_FRAME_BYTES`] line
    /// capacity. No C++ analogue (the C++ heap-allocated unbounded strings).
    MaxFrameBytesExceedCapacity,
}

impl SerialInputError {
    /// The exact message the C++ exception carried (or this port's own text
    /// for [`Self::MaxFrameBytesExceedCapacity`]).
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::ZeroMaxFrameBytes => "serial input max frame bytes must be non-zero",
            Self::MaxFrameBytesExceedCapacity => {
                "serial input max frame bytes exceed fixed line capacity"
            }
        }
    }
}

impl fmt::Display for SerialInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// The outcome of feeding one byte. Mirrors the C++
/// `TDisplayS3SerialInputEvent`/`...EventKind`, with the line carried inside
/// the [`Self::FrameReady`] variant instead of a separate always-present field
/// (the C++ `line` was empty for the other kinds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialInputEvent<'a> {
    /// The byte was consumed without completing a line (C++ `None`).
    None,
    /// A full line (terminated by `\n`, which is included, as in the C++) is
    /// ready for [`decode_serial_frame`](crate::serial::frame::decode_serial_frame).
    FrameReady(&'a [u8]),
    /// The line exceeded `max_frame_bytes`; it was discarded and the
    /// accumulator now drains input until the next `\n` (C++ `OverlongFrame`,
    /// whose `line` was empty).
    OverlongFrame,
}

/// The byte-wise line accumulator. Mirrors the C++ `TDisplayS3SerialInput`
/// (`line` empty, `draining_overlong` false at rest), with the growable
/// `std::string` replaced by a fixed [`MAX_SERIAL_FRAME_BYTES`]-byte buffer.
#[derive(Debug, Clone)]
pub struct SerialLineInput {
    line: [u8; MAX_SERIAL_FRAME_BYTES],
    len: usize,
    draining_overlong: bool,
}

impl SerialLineInput {
    /// Creates an empty, non-draining accumulator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            line: [0u8; MAX_SERIAL_FRAME_BYTES],
            len: 0,
            draining_overlong: false,
        }
    }

    /// Feeds one received byte. Mirrors the C++
    /// `update_t_display_s3_serial_input`: while draining an overlong frame,
    /// bytes are discarded until a `\n` re-arms the accumulator; `\r` is
    /// always skipped; a byte that would grow the line beyond
    /// `max_frame_bytes` discards the line, reports
    /// [`SerialInputEvent::OverlongFrame`] and starts draining; a `\n` within
    /// the bound completes the line (newline included).
    ///
    /// # Errors
    ///
    /// See [`SerialInputError`].
    pub fn push_byte(
        &mut self,
        ch: u8,
        max_frame_bytes: usize,
    ) -> Result<SerialInputEvent<'_>, SerialInputError> {
        if max_frame_bytes == 0 {
            return Err(SerialInputError::ZeroMaxFrameBytes);
        }
        if max_frame_bytes > MAX_SERIAL_FRAME_BYTES {
            return Err(SerialInputError::MaxFrameBytesExceedCapacity);
        }

        if self.draining_overlong {
            if ch == b'\n' {
                self.draining_overlong = false;
                self.len = 0;
            }
            return Ok(SerialInputEvent::None);
        }

        if ch == b'\r' {
            return Ok(SerialInputEvent::None);
        }

        // The C++ pushed the byte first and discarded the whole line once its
        // length exceeded the bound; refusing to store the overflowing byte is
        // observably identical (the line is discarded either way).
        if self.len >= max_frame_bytes {
            self.len = 0;
            self.draining_overlong = true;
            return Ok(SerialInputEvent::OverlongFrame);
        }

        self.line[self.len] = ch;
        self.len += 1;
        if ch == b'\n' {
            let ready = self.len;
            self.len = 0;
            return Ok(SerialInputEvent::FrameReady(&self.line[..ready]));
        }
        Ok(SerialInputEvent::None)
    }
}

impl Default for SerialLineInput {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The named C++ case (`test_t_display_s3_serial_input_drains_...`) is
    // ported in `crate::board_profile_tests`. This covers the error branches
    // it never reached: the C++ zero-bound throw and this port's own fixed
    // capacity bound, with the exact messages, leaving the accumulator
    // unharmed by rejected calls.
    #[test]
    fn rejects_invalid_max_frame_bytes() {
        let mut input = SerialLineInput::default();
        assert_eq!(
            input.push_byte(b'a', 0),
            Err(SerialInputError::ZeroMaxFrameBytes),
        );
        assert_eq!(
            input.push_byte(b'a', MAX_SERIAL_FRAME_BYTES + 1),
            Err(SerialInputError::MaxFrameBytesExceedCapacity),
        );

        for (error, expected) in [
            (
                SerialInputError::ZeroMaxFrameBytes,
                "serial input max frame bytes must be non-zero",
            ),
            (
                SerialInputError::MaxFrameBytesExceedCapacity,
                "serial input max frame bytes exceed fixed line capacity",
            ),
        ] {
            assert_eq!(error.message(), expected);
            assert_eq!(std::format!("{error}"), expected);
        }

        assert_eq!(
            input.push_byte(b'\n', MAX_SERIAL_FRAME_BYTES).unwrap(),
            SerialInputEvent::FrameReady(b"\n"),
        );
    }
}
