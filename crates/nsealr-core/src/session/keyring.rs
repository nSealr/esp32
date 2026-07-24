//! Stateless RAM-only session keyring with volatile secret wiping.
//!
//! Ported from the C++ reference `host_core` sources `src/session_keyring.cpp` +
//! `include/nsealr/session_keyring.hpp` for behaviour parity.
//!
//! # Secret-wiping model (C++ → Rust mapping)
//!
//! The C++ `SessionKeySource` zeroized itself through *value semantics*: the
//! destructor, both assignment operators, and the move constructor all called
//! `wipe()`, which overwrote the secret arrays through a `volatile` pointer and
//! cleared the label. This port maps that to Rust:
//!
//! - destructor wipe → [`Drop`] for [`SessionKeySource`] (volatile writes via
//!   `core::ptr::write_volatile`, no external zeroize dependency);
//! - copy/move *assignment* wipe-of-the-old-value → Rust assignment drops the
//!   overwritten value, which runs the same [`Drop`] wipe;
//! - move-constructor wipe-of-the-source → Rust moves make the moved-from
//!   binding statically inaccessible, a strictly stronger guarantee; the bytes
//!   of the *final* resting place are still wiped when it is dropped.
//!
//! The C++ wiped the label with a plain `std::fill`; this port wipes it with
//! volatile writes too ([`crate::text::FixedStr::wipe`]), a strict strengthening.

use crate::bip39;
use crate::nip19::{self, SecretKey};
use crate::text::FixedStr;
use core::str::FromStr;

/// Maximum number of sources the stateless keyring holds. Mirrors the C++
/// `kMaxStatelessSessionKeySources`.
pub const MAX_STATELESS_SESSION_KEY_SOURCES: usize = 8;
/// Maximum session key source label length in bytes. Mirrors the C++
/// `kMaxSessionKeySourceLabelLength`.
pub const MAX_SESSION_KEY_SOURCE_LABEL_CHARS: usize = 64;

/// A session key source label, bounded by
/// [`MAX_SESSION_KEY_SOURCE_LABEL_CHARS`].
pub type SessionKeySourceLabel = FixedStr<MAX_SESSION_KEY_SOURCE_LABEL_CHARS>;

/// Errors reported by the session keyring. Each variant corresponds to a
/// distinct C++ `SessionKeyringError` throw site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKeyringError {
    /// The label was empty. C++: "session key source label must not be empty".
    EmptyLabel,
    /// The label exceeded [`MAX_SESSION_KEY_SOURCE_LABEL_CHARS`]. C++: "session
    /// key source label exceeds max length".
    LabelTooLong,
    /// The nsec secret was zero or not below the secp256k1 order. C++: "NIP-19
    /// nsec session source must be a valid secp256k1 scalar".
    InvalidNsecScalar,
    /// The seed word count was not one of `{12, 15, 18, 21, 24}`. C++: "BIP-39
    /// session seed must contain 12, 15, 18, 21, or 24 word indexes".
    InvalidSeedWordCount,
    /// A seed word index was `>= 2048`. C++: "BIP-39 session seed word index is
    /// outside the English wordlist".
    SeedWordIndexOutOfRange,
    /// The keyring already held [`MAX_STATELESS_SESSION_KEY_SOURCES`] sources.
    /// C++: "stateless session keyring is full".
    KeyringFull,
    /// A source index was `>=` the active size. C++: "session key source index
    /// is out of range".
    IndexOutOfRange,
}

/// The kind of key material a session source holds. Mirrors the C++
/// `SessionKeySourceKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKeySourceKind {
    /// A raw 32-byte secret key imported from a NIP-19 `nsec`.
    NsecSecretKey,
    /// A BIP-39 seed held as validated word indexes.
    Bip39WordIndexes,
}

/// Fixed-capacity BIP-39 word indexes held by a session source. Mirrors the C++
/// `SessionSeedWordIndexes` (`values` array + `count`), with public fields so
/// tests can observe the wiped state exactly as the C++ tests did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSeedWordIndexes {
    /// The word index slots; unused slots are kept zeroed.
    pub values: [u16; bip39::MAX_MNEMONIC_WORDS],
    /// The number of active indexes in `values`.
    pub count: usize,
}

impl SessionSeedWordIndexes {
    /// Creates an empty index list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            values: [0; bip39::MAX_MNEMONIC_WORDS],
            count: 0,
        }
    }

    /// Returns the active indexes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u16] {
        &self.values[..self.count]
    }
}

impl Default for SessionSeedWordIndexes {
    fn default() -> Self {
        Self::new()
    }
}

/// One RAM-only session key source. Mirrors the C++ `SessionKeySource` field
/// for field; see the module docs for the secret-wiping model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeySource {
    /// The kind of material held (C++ `kind`).
    pub kind: SessionKeySourceKind,
    /// The user-facing label (C++ `label`).
    pub label: SessionKeySourceLabel,
    /// The raw nsec secret key; all-zero unless `kind` is
    /// [`SessionKeySourceKind::NsecSecretKey`] (C++ `nsec_secret_key`).
    pub nsec_secret_key: SecretKey,
    /// The BIP-39 word indexes; empty unless `kind` is
    /// [`SessionKeySourceKind::Bip39WordIndexes`] (C++ `bip39_word_indexes`).
    pub bip39_word_indexes: SessionSeedWordIndexes,
}

impl SessionKeySource {
    /// Creates an empty nsec-kind source (the C++ default-constructed state).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            kind: SessionKeySourceKind::NsecSecretKey,
            label: SessionKeySourceLabel::new(),
            nsec_secret_key: [0; 32],
            bip39_word_indexes: SessionSeedWordIndexes::new(),
        }
    }

    /// Volatile-zeroes every field back to the default state. Mirrors the C++
    /// `SessionKeySource::wipe()`.
    pub fn wipe(&mut self) {
        for byte in &mut self.nsec_secret_key {
            // SAFETY: `byte` is a valid, exclusively-borrowed `u8` location.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for word in &mut self.bip39_word_indexes.values {
            // SAFETY: `word` is a valid, exclusively-borrowed `u16` location.
            unsafe { core::ptr::write_volatile(word, 0) };
        }
        // SAFETY: `count` is a valid, exclusively-borrowed `usize` location.
        unsafe { core::ptr::write_volatile(&mut self.bip39_word_indexes.count, 0) };
        self.label.wipe();
        self.kind = SessionKeySourceKind::NsecSecretKey;
    }
}

impl Default for SessionKeySource {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SessionKeySource {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// The stateless RAM-only session keyring. Mirrors the C++
/// `StatelessSessionKeyring` (which deleted copy and move; this type is simply
/// not `Clone`). Dropping the keyring wipes every active source.
#[derive(Debug)]
pub struct StatelessSessionKeyring {
    sources: [SessionKeySource; MAX_STATELESS_SESSION_KEY_SOURCES],
    len: usize,
}

impl StatelessSessionKeyring {
    /// Creates an empty keyring.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sources: [const { SessionKeySource::new() }; MAX_STATELESS_SESSION_KEY_SOURCES],
            len: 0,
        }
    }

    /// Adds a raw nsec secret under `label`. Mirrors the C++ `add_nsec`
    /// (validation order: label, scalar, capacity).
    ///
    /// # Errors
    ///
    /// [`SessionKeyringError::EmptyLabel`], [`SessionKeyringError::LabelTooLong`],
    /// [`SessionKeyringError::InvalidNsecScalar`] or
    /// [`SessionKeyringError::KeyringFull`].
    pub fn add_nsec(&mut self, label: &str, secret: &SecretKey) -> Result<(), SessionKeyringError> {
        let label = validated_label(label)?;
        if !nip19::is_valid_secret_key(secret) {
            return Err(SessionKeyringError::InvalidNsecScalar);
        }
        self.require_capacity()?;
        let slot = &mut self.sources[self.len];
        slot.kind = SessionKeySourceKind::NsecSecretKey;
        slot.label = label;
        slot.nsec_secret_key = *secret;
        slot.bip39_word_indexes = SessionSeedWordIndexes::new();
        self.len += 1;
        Ok(())
    }

    /// Adds a BIP-39 seed as word indexes under `label`. Mirrors the C++
    /// `add_bip39_seed` (validation order: label, capacity, indexes; the C++
    /// deliberately did not checksum-validate here and neither does this port).
    ///
    /// # Errors
    ///
    /// [`SessionKeyringError::EmptyLabel`], [`SessionKeyringError::LabelTooLong`],
    /// [`SessionKeyringError::KeyringFull`],
    /// [`SessionKeyringError::InvalidSeedWordCount`] or
    /// [`SessionKeyringError::SeedWordIndexOutOfRange`].
    pub fn add_bip39_seed(
        &mut self,
        label: &str,
        word_indexes: &[u16],
    ) -> Result<(), SessionKeyringError> {
        let label = validated_label(label)?;
        self.require_capacity()?;
        if !bip39::is_valid_word_count(word_indexes.len()) {
            return Err(SessionKeyringError::InvalidSeedWordCount);
        }
        if word_indexes
            .iter()
            .any(|&index| usize::from(index) >= bip39::WORD_COUNT)
        {
            return Err(SessionKeyringError::SeedWordIndexOutOfRange);
        }
        let slot = &mut self.sources[self.len];
        slot.kind = SessionKeySourceKind::Bip39WordIndexes;
        slot.label = label;
        slot.nsec_secret_key = [0; 32];
        slot.bip39_word_indexes = SessionSeedWordIndexes::new();
        slot.bip39_word_indexes.values[..word_indexes.len()].copy_from_slice(word_indexes);
        slot.bip39_word_indexes.count = word_indexes.len();
        self.len += 1;
        Ok(())
    }

    /// Adds a copy of an existing source, re-running the same validation as the
    /// kind-specific adders. Mirrors the C++ `add_source`.
    ///
    /// # Errors
    ///
    /// The same errors as [`Self::add_nsec`] / [`Self::add_bip39_seed`].
    pub fn add_source(&mut self, source: &SessionKeySource) -> Result<(), SessionKeyringError> {
        match source.kind {
            SessionKeySourceKind::NsecSecretKey => {
                self.add_nsec(source.label.as_str(), &source.nsec_secret_key)
            }
            SessionKeySourceKind::Bip39WordIndexes => {
                self.add_bip39_seed(source.label.as_str(), source.bip39_word_indexes.as_slice())
            }
        }
    }

    /// Wipes every active source and empties the keyring. Mirrors the C++
    /// `clear()` (which wiped only the active slots; inactive slots are already
    /// zeroed by construction).
    pub fn clear(&mut self) {
        for slot in &mut self.sources[..self.len] {
            slot.wipe();
        }
        self.len = 0;
    }

    /// Returns `true` if the keyring holds no sources. Mirrors the C++
    /// `empty()`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the number of active sources. Mirrors the C++ `size()`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the source at `index`. Mirrors the C++ `source_at`.
    ///
    /// # Errors
    ///
    /// [`SessionKeyringError::IndexOutOfRange`] if `index >= len()`.
    pub fn source_at(&self, index: usize) -> Result<&SessionKeySource, SessionKeyringError> {
        if index >= self.len {
            return Err(SessionKeyringError::IndexOutOfRange);
        }
        Ok(&self.sources[index])
    }

    /// Mirrors the C++ `require_capacity`.
    fn require_capacity(&self) -> Result<(), SessionKeyringError> {
        if self.len >= MAX_STATELESS_SESSION_KEY_SOURCES {
            return Err(SessionKeyringError::KeyringFull);
        }
        Ok(())
    }
}

/// Mirrors the C++ `require_valid_label` (empty / max-length checks); the
/// length check is the [`FixedStr`] capacity itself.
fn validated_label(label: &str) -> Result<SessionKeySourceLabel, SessionKeyringError> {
    if label.is_empty() {
        return Err(SessionKeyringError::EmptyLabel);
    }
    SessionKeySourceLabel::from_str(label).map_err(|_| SessionKeyringError::LabelTooLong)
}

impl Default for StatelessSessionKeyring {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StatelessSessionKeyring {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::nip19;

    // NIP-19 fixture copied from the READ-ONLY
    // specs/vectors/nip19/nsec-test-key-1.json (`nsec`).
    pub(crate) const NSEC_TEST_KEY_1: &str =
        "nsec1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs4rm7hz";

    // SeedQR fixture copied from the READ-ONLY
    // specs/vectors/seedqr/seedsigner-vector-1.json (`standard_word_indexes`).
    pub(crate) const SEEDQR_VECTOR_1_INDEXES: [u16; 24] = [
        115, 1325, 1154, 127, 1190, 771, 415, 742, 1289, 1906, 2008, 870, 266, 1343, 1420, 2016,
        1792, 614, 896, 1929, 300, 1524, 801, 643,
    ];

    fn all_zero_u8(values: &[u8]) -> bool {
        values.iter().all(|&value| value == 0)
    }

    fn all_zero_u16(values: &[u16]) -> bool {
        values.iter().all(|&value| value == 0)
    }

    // Port of the C++ `test_stateless_session_keyring_accepts_parsed_key_sources`.
    #[test]
    fn accepts_parsed_key_sources() {
        let mut keyring = StatelessSessionKeyring::new();
        let secret = nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap();

        assert!(keyring.is_empty());
        assert!(StatelessSessionKeyring::default().is_empty());
        assert_eq!(SessionKeySource::default(), SessionKeySource::new());
        assert_eq!(
            SessionSeedWordIndexes::default(),
            SessionSeedWordIndexes::new(),
        );
        keyring.add_nsec("nsec test vector", &secret).unwrap();
        keyring
            .add_bip39_seed("SeedQR vector 1", &SEEDQR_VECTOR_1_INDEXES)
            .unwrap();

        assert_eq!(keyring.len(), 2);
        let nsec_source = keyring.source_at(0).unwrap();
        assert_eq!(nsec_source.kind, SessionKeySourceKind::NsecSecretKey);
        assert_eq!(nsec_source.label, "nsec test vector");
        assert_eq!(nsec_source.nsec_secret_key, secret);
        assert_eq!(nsec_source.bip39_word_indexes.count, 0);
        let seed_source = keyring.source_at(1).unwrap();
        assert_eq!(seed_source.kind, SessionKeySourceKind::Bip39WordIndexes);
        assert_eq!(seed_source.label, "SeedQR vector 1");
        assert_eq!(
            seed_source.bip39_word_indexes.as_slice(),
            &SEEDQR_VECTOR_1_INDEXES,
        );
        assert_eq!(
            keyring.source_at(2),
            Err(SessionKeyringError::IndexOutOfRange),
        );

        keyring.clear();
        assert!(keyring.is_empty());
    }

    // Port of the C++ `test_stateless_session_keyring_clear_wipes_active_sources`.
    // The C++ observed the wiped state through retained references; the borrow
    // checker forbids holding `&source` across `clear()`, so this test observes
    // the same post-clear slot state through the private `sources` field.
    #[test]
    fn clear_wipes_active_sources() {
        let mut keyring = StatelessSessionKeyring::new();
        let secret = nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap();

        keyring.add_nsec("nsec test vector", &secret).unwrap();
        keyring
            .add_bip39_seed("SeedQR vector 1", &SEEDQR_VECTOR_1_INDEXES)
            .unwrap();

        assert!(!all_zero_u8(&keyring.sources[0].nsec_secret_key));
        assert_eq!(
            keyring.sources[1].bip39_word_indexes.count,
            SEEDQR_VECTOR_1_INDEXES.len(),
        );
        assert!(!all_zero_u16(&keyring.sources[1].bip39_word_indexes.values));

        keyring.clear();

        assert!(keyring.is_empty());
        for slot in [&keyring.sources[0], &keyring.sources[1]] {
            assert!(slot.label.is_empty());
            assert!(all_zero_u8(&slot.nsec_secret_key));
            assert_eq!(slot.bip39_word_indexes.count, 0);
            assert!(all_zero_u16(&slot.bip39_word_indexes.values));
        }
        assert_eq!(
            keyring.source_at(0),
            Err(SessionKeyringError::IndexOutOfRange),
        );
    }

    // Port of the C++ `test_session_key_source_value_semantics_wipe_sensitive_material`.
    //
    // C++ → Rust assertion mapping (see the module docs): the C++ asserted that
    // moved-from values were wiped; Rust moves make the moved-from binding
    // statically inaccessible (checked at compile time by this very test), and
    // the runtime-observable equivalent — the bytes are wiped when the value's
    // lifetime ends — is asserted through `Drop` below via `drop_in_place` on
    // memory this test still owns.
    #[test]
    fn value_semantics_wipe_sensitive_material() {
        let secret = nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap();
        let mut original = SessionKeySource::new();
        original.kind = SessionKeySourceKind::NsecSecretKey;
        original.label = SessionKeySourceLabel::from_str("temporary nsec").unwrap();
        original.nsec_secret_key = secret;

        // C++: `SessionKeySource moved(std::move(original))` — the move preserves
        // the payload; `original` is statically inaccessible from here on.
        let moved = original;
        assert_eq!(moved.kind, SessionKeySourceKind::NsecSecretKey);
        assert_eq!(moved.label, "temporary nsec");
        assert_eq!(moved.nsec_secret_key, secret);

        // C++: copy assignment `assigned = moved` — Rust explicit clone.
        let mut assigned = moved.clone();
        assert_eq!(assigned.kind, SessionKeySourceKind::NsecSecretKey);
        assert_eq!(assigned.nsec_secret_key, secret);

        // C++: `assigned = seed` (copy assignment over live secret material) —
        // the Rust assignment drops the old value, which wipes it via `Drop`.
        let seed = crate::session::source_qr::parse_session_source_qr_text(
            "SeedQR vector 1",
            "011513251154012711900771041507421289190620080870026613431420201617920614089619290300152408010643",
        )
        .unwrap();
        assigned = seed.clone();
        assert_eq!(assigned.kind, SessionKeySourceKind::Bip39WordIndexes);
        assert!(all_zero_u8(&assigned.nsec_secret_key));
        assert_eq!(
            assigned.bip39_word_indexes.as_slice(),
            &SEEDQR_VECTOR_1_INDEXES,
        );

        // C++: `moved_seed = std::move(seed)` then asserts `seed` is wiped.
        let moved_seed = seed;
        assert_eq!(moved_seed.kind, SessionKeySourceKind::Bip39WordIndexes);
        assert_eq!(moved_seed.label, "SeedQR vector 1");

        // Runtime wipe observation: run `Drop` in place on memory this test
        // still owns, then read the slots back. This is the volatile-wipe
        // equivalent of the C++ post-move `all_zero(original.nsec_secret_key)`
        // (and label/indexes) assertions.
        let mut slot = core::mem::MaybeUninit::new(moved);
        let ptr = slot.as_mut_ptr();
        // SAFETY: `ptr` points to live, exclusively-owned memory; the value is
        // never touched as a `SessionKeySource` again after `drop_in_place`
        // (only its plain-integer field bytes are read back volatilely, which
        // `wipe()` deterministically wrote last).
        unsafe {
            core::ptr::drop_in_place(ptr);
            let wiped_secret = core::ptr::addr_of!((*ptr).nsec_secret_key).read_volatile();
            let wiped_indexes = core::ptr::addr_of!((*ptr).bip39_word_indexes).read_volatile();
            assert!(all_zero_u8(&wiped_secret));
            assert_eq!(wiped_indexes.count, 0);
            assert!(all_zero_u16(&wiped_indexes.values));
            let wiped_label = core::ptr::addr_of!((*ptr).label).read_volatile();
            assert!(wiped_label.is_empty());
        }

        let mut slot = core::mem::MaybeUninit::new(moved_seed);
        let ptr = slot.as_mut_ptr();
        // SAFETY: as above — exclusively-owned memory, dropped exactly once,
        // only plain-integer field bytes read back afterwards.
        unsafe {
            core::ptr::drop_in_place(ptr);
            let wiped_indexes = core::ptr::addr_of!((*ptr).bip39_word_indexes).read_volatile();
            assert_eq!(wiped_indexes.count, 0);
            assert!(all_zero_u16(&wiped_indexes.values));
            let wiped_label = core::ptr::addr_of!((*ptr).label).read_volatile();
            assert!(wiped_label.is_empty());
        }
    }

    // Port of the C++ `test_stateless_session_keyring_rejects_invalid_sources`.
    #[test]
    fn rejects_invalid_sources() {
        let mut keyring = StatelessSessionKeyring::new();
        let secret = nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap();

        assert_eq!(
            keyring.add_nsec("", &secret),
            Err(SessionKeyringError::EmptyLabel),
        );
        let long_label =
            core::str::from_utf8(&[b'x'; MAX_SESSION_KEY_SOURCE_LABEL_CHARS + 1]).unwrap();
        assert_eq!(
            keyring.add_nsec(long_label, &secret),
            Err(SessionKeyringError::LabelTooLong),
        );
        assert_eq!(
            keyring.add_nsec("zero nsec", &[0; 32]),
            Err(SessionKeyringError::InvalidNsecScalar),
        );
        assert_eq!(
            keyring.add_bip39_seed("short seed", &[0, 1, 2]),
            Err(SessionKeyringError::InvalidSeedWordCount),
        );
        let mut bad_indexes = [0u16; 12];
        bad_indexes[11] = 2048;
        assert_eq!(
            keyring.add_bip39_seed("bad seed index", &bad_indexes),
            Err(SessionKeyringError::SeedWordIndexOutOfRange),
        );

        for index in 0..MAX_STATELESS_SESSION_KEY_SOURCES {
            let mut label = SessionKeySourceLabel::from_str("nsec source ").unwrap();
            label.try_push_usize(index).unwrap();
            keyring.add_nsec(label.as_str(), &secret).unwrap();
        }
        assert_eq!(
            keyring.add_nsec("overflow", &secret),
            Err(SessionKeyringError::KeyringFull),
        );
    }

    // Direct port-completeness test for `add_source` (the C++ exercised it only
    // through `run_session_import_flow`, which is deferred to M-T3.4b with the
    // review-controls substrate; the dispatch itself is session-keyring logic).
    #[test]
    fn add_source_revalidates_both_kinds() {
        let mut keyring = StatelessSessionKeyring::new();
        let secret = nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap();
        keyring.add_nsec("nsec test vector", &secret).unwrap();
        keyring
            .add_bip39_seed("SeedQR vector 1", &SEEDQR_VECTOR_1_INDEXES)
            .unwrap();

        let mut copy = StatelessSessionKeyring::new();
        copy.add_source(keyring.source_at(0).unwrap()).unwrap();
        copy.add_source(keyring.source_at(1).unwrap()).unwrap();
        assert_eq!(copy.len(), 2);
        assert_eq!(copy.source_at(0).unwrap(), keyring.source_at(0).unwrap());
        assert_eq!(copy.source_at(1).unwrap(), keyring.source_at(1).unwrap());

        // Re-validation: a hand-built invalid source is rejected, not copied.
        let invalid = SessionKeySource::new();
        assert_eq!(
            copy.add_source(&invalid),
            Err(SessionKeyringError::EmptyLabel),
        );
        let mut zero_scalar = SessionKeySource::new();
        zero_scalar.label = SessionKeySourceLabel::from_str("zero nsec").unwrap();
        assert_eq!(
            copy.add_source(&zero_scalar),
            Err(SessionKeyringError::InvalidNsecScalar),
        );
    }
}
