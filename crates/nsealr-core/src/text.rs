//! Fixed-capacity UTF-8 text — the allocation-free stand-in for C++ `std::string`.
//!
//! The C++ `host_core` passed `std::string` values freely (labels, review ids,
//! digests, review page lines). This crate is `no_std` and allocation-free, so
//! bounded text is stored inline in a [`FixedStr`] with a compile-time capacity.
//! Unused tail bytes are kept zeroed so derived equality compares only the active
//! prefix (the same invariant as [`crate::bip39::WordIndexes`]).
//!
//! Introduced for the M-T3.4 session/custody port (`session_*.cpp` + the shared
//! review data model); not itself a port of a single C++ module.

/// Errors reported by [`FixedStr`] operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextError {
    /// The input did not fit in the fixed capacity. No C++ analogue (the C++
    /// `std::string` grew on demand); size capacities with the documented bounds
    /// to avoid it.
    TooLong,
}

/// A fixed-capacity UTF-8 string of at most `N` bytes, stored inline.
///
/// Only whole `&str` slices are ever appended, so the contents are always valid
/// UTF-8. The unused tail is kept zeroed, which makes the derived `PartialEq`
/// equivalent to comparing [`FixedStr::as_str`] values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedStr<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> FixedStr<N> {
    /// Creates an empty string.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    /// Appends a whole `&str` to the current contents.
    ///
    /// # Errors
    ///
    /// [`TextError::TooLong`] if the result would exceed `N` bytes (the contents
    /// are unchanged on error).
    pub fn try_push_str(&mut self, text: &str) -> Result<(), TextError> {
        let end = self.len + text.len();
        self.buf
            .get_mut(self.len..end)
            .ok_or(TextError::TooLong)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }

    /// Appends the decimal rendering of `value`.
    ///
    /// # Errors
    ///
    /// [`TextError::TooLong`] if the rendered digits would exceed `N` bytes.
    pub fn try_push_usize(&mut self, value: usize) -> Result<(), TextError> {
        // usize is at most 20 decimal digits (u64); render right-aligned.
        let mut digits = [0u8; 20];
        let mut position = digits.len();
        let mut remaining = value;
        loop {
            position -= 1;
            digits[position] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        // The digits are ASCII by construction, so the str view never fails.
        self.try_push_str(core::str::from_utf8(&digits[position..]).unwrap_or(""))
    }

    /// Returns the contents as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Only whole `&str` slices are ever appended, so this never fails.
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

    /// Returns the length of the contents in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Volatile-zeroes the whole buffer and length, for holders of sensitive
    /// text. Mirrors the C++ `SessionKeySource::wipe()` label wipe (`std::fill`
    /// + `clear()`), strengthened to volatile writes like the C++ `wipe_array`.
    pub fn wipe(&mut self) {
        for byte in &mut self.buf {
            // SAFETY: `byte` is a valid, exclusively-borrowed `u8` location.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        // SAFETY: `self.len` is a valid, exclusively-borrowed `usize` location.
        unsafe { core::ptr::write_volatile(&mut self.len, 0) };
    }
}

impl<const N: usize> Default for FixedStr<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> core::str::FromStr for FixedStr<N> {
    type Err = TextError;

    /// Builds a [`FixedStr`] holding a copy of `text`; fails with
    /// [`TextError::TooLong`] if `text` is longer than `N` bytes.
    fn from_str(text: &str) -> Result<Self, TextError> {
        let mut out = Self::new();
        out.try_push_str(text)?;
        Ok(out)
    }
}

impl<const N: usize> PartialEq<&str> for FixedStr<N> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    // Direct unit tests: `FixedStr` is new allocation-free infrastructure with no
    // single C++ counterpart (it replaces `std::string` across the session port),
    // so it is proven directly, like the M-T3.1 primitives.
    #[test]
    fn builds_appends_and_compares() {
        let mut text: FixedStr<16> = FixedStr::new();
        assert!(text.is_empty());
        assert_eq!(text.len(), 0);
        assert_eq!(text.as_str(), "");
        assert_eq!(text, FixedStr::<16>::default());

        text.try_push_str("Label: ").unwrap();
        text.try_push_str("ok").unwrap();
        text.try_push_usize(24).unwrap();
        assert_eq!(text.as_str(), "Label: ok24");
        assert_eq!(text.len(), 11);
        assert!(!text.is_empty());
        assert_eq!(text, "Label: ok24");

        let copy = FixedStr::<16>::from_str("Label: ok24").unwrap();
        assert_eq!(text, copy);
        assert_eq!(copy.clone(), copy);

        let mut zero: FixedStr<4> = FixedStr::new();
        zero.try_push_usize(0).unwrap();
        assert_eq!(zero, "0");
    }

    #[test]
    fn rejects_overflow_and_keeps_contents() {
        let mut text: FixedStr<4> = FixedStr::from_str("abcd").unwrap();
        assert_eq!(text.try_push_str("e"), Err(TextError::TooLong));
        assert_eq!(text.try_push_usize(12345), Err(TextError::TooLong));
        assert_eq!(text.as_str(), "abcd");
        assert_eq!(FixedStr::<3>::from_str("abcd"), Err(TextError::TooLong));
    }

    #[test]
    fn wipe_zeroes_buffer_and_length() {
        let mut text: FixedStr<8> = FixedStr::from_str("secret").unwrap();
        text.wipe();
        assert_eq!(text.as_str(), "");
        assert_eq!(text.len(), 0);
        assert_eq!(text.buf, [0u8; 8]);
    }
}
