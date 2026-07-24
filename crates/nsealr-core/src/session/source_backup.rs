//! Danger-zone backup review and secret backup payload for session sources.
//!
//! Ported from the C++ reference `host_core` sources
//! `src/session_source_backup.cpp` + `include/nsealr/session_source_backup.hpp`.
//! Milestone M-T3.4a lands the **data path**: the secret-hiding backup review
//! builder and the secret-revealing backup payload. The interactive flows the
//! C++ layered on top (`run_session_source_backup_flow`,
//! `run_session_source_backup_io_flow`, `SessionSourceBackupIo`) drive a
//! `ReviewControlSession` and `render_review_page` from the M-T3.6 substrate
//! and are deferred to milestone M-T3.4b.
//!
//! The C++ `backup_format_for` also carried an "unsupported source type" throw
//! that was unreachable (the kind enum is exhaustive); the Rust `match` makes
//! that state unrepresentable, so no error variant exists for it.

use crate::bip39::{self, Bip39Error};
use crate::nip19::{self, NsecError};
use crate::review::types::{
    ReviewBodyLineStyles, ReviewPageAction, ReviewPageLine, ReviewPageLines, TrustedReviewPage,
};
use crate::session::import_review::{
    session_key_source_fingerprint, SessionApprovalDigest, SessionReviewId,
};
use crate::session::keyring::{SessionKeySource, SessionKeySourceKind};
use crate::text::FixedStr;
use core::str::FromStr;

/// Maximum byte length of a rendered backup mnemonic (24 words of at most 8
/// bytes plus 23 separators).
pub const MAX_BACKUP_MNEMONIC_CHARS: usize = 216;
/// Maximum byte length of a Standard SeedQR digit stream (4 digits per word,
/// 24 words).
pub const MAX_BACKUP_SEEDQR_DIGIT_CHARS: usize = 96;
/// Byte length of the CompactSeedQR hex for 32-byte entropy.
pub const MAX_BACKUP_COMPACT_HEX_CHARS: usize = 64;
/// Byte length of an encoded `nsec` Bech32 string (63) rounded to capacity.
pub const MAX_BACKUP_NSEC_CHARS: usize = 64;

/// Errors reported by the backup payload builder. Each variant corresponds to
/// a distinct C++ throw site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSourceBackupError {
    /// The seed word count was not 12 or 24. C++: "SeedQR backup word count
    /// must be 12 or 24".
    InvalidBackupWordCount,
    /// The seed indexes failed BIP-39 rendering/entropy reconstruction (for
    /// example an invalid checksum). The C++ let the `Bip39Error` propagate.
    Bip39(Bip39Error),
    /// The nsec secret failed Bech32 encoding. The C++ let the
    /// `NsecDecodeError` propagate.
    Nsec(NsecError),
}

/// The secret-revealing backup payload. Mirrors the C++
/// `SessionSourceBackupPayload` field for field; fields not applicable to the
/// source kind are empty, exactly as in the C++.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSourceBackupPayload {
    /// Backup format id (C++ `backup_format`): `"bip39_words_seedqr"` or
    /// `"nip19_nsec"`.
    pub backup_format: &'static str,
    /// The space-separated English mnemonic (C++ `mnemonic`).
    pub mnemonic: FixedStr<MAX_BACKUP_MNEMONIC_CHARS>,
    /// The Standard SeedQR digit stream (C++ `standard_seedqr_digits`).
    pub standard_seedqr_digits: FixedStr<MAX_BACKUP_SEEDQR_DIGIT_CHARS>,
    /// The CompactSeedQR entropy as lowercase hex (C++ `compact_seedqr_hex`).
    pub compact_seedqr_hex: FixedStr<MAX_BACKUP_COMPACT_HEX_CHARS>,
    /// The NIP-19 `nsec` encoding of the secret key (C++ `nsec`).
    pub nsec: FixedStr<MAX_BACKUP_NSEC_CHARS>,
}

/// The secret-hiding backup review. Mirrors the C++ `SessionSourceBackupReview`
/// (`review_id`, `approval_digest`, `pages`); the C++ page vector always held
/// exactly two pages, so this port stores them inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSourceBackupReview {
    /// Stable review id: `"session-backup-"` + fingerprint (C++ `review_id`).
    pub review_id: SessionReviewId,
    /// SHA-256 approval digest over the domain-separated review material (C++
    /// `approval_digest`).
    pub approval_digest: SessionApprovalDigest,
    /// The danger-zone warning page and the decision page (C++ `pages`).
    pub pages: [TrustedReviewPage; 2],
}

/// Builds the secret-revealing backup payload for a session source. Mirrors
/// the C++ `session_source_backup_payload`.
///
/// # Errors
///
/// [`SessionSourceBackupError::InvalidBackupWordCount`],
/// [`SessionSourceBackupError::Bip39`] or [`SessionSourceBackupError::Nsec`].
pub fn session_source_backup_payload(
    source: &SessionKeySource,
) -> Result<SessionSourceBackupPayload, SessionSourceBackupError> {
    match source.kind {
        SessionKeySourceKind::Bip39WordIndexes => {
            let indexes = source.bip39_word_indexes.as_slice();

            // Mnemonic first (C++ order): 24 words of <= 8 bytes + separators.
            let mut mnemonic_buf = [0u8; MAX_BACKUP_MNEMONIC_CHARS];
            let mnemonic_str = bip39::mnemonic_from_indexes(indexes, &mut mnemonic_buf)
                .map_err(SessionSourceBackupError::Bip39)?;
            // 24 words x <= 8 bytes + 23 separators = 215 <= 216: never truncates.
            let mnemonic = FixedStr::from_str(mnemonic_str).expect("within documented capacity");

            // Standard SeedQR digits (C++ `standard_seedqr_from_indexes`).
            if indexes.len() != 12 && indexes.len() != 24 {
                wipe_bytes(&mut mnemonic_buf);
                return Err(SessionSourceBackupError::InvalidBackupWordCount);
            }
            let mut digits = FixedStr::<MAX_BACKUP_SEEDQR_DIGIT_CHARS>::new();
            for &index in indexes {
                push_four_digits(&mut digits, index);
            }

            // CompactSeedQR entropy as lowercase hex (C++ `hex_from_bytes`).
            let mut entropy_buf = [0u8; 32];
            let entropy = bip39::entropy_from_indexes(indexes, &mut entropy_buf)
                .map_err(SessionSourceBackupError::Bip39)?;
            let mut compact_hex = FixedStr::<MAX_BACKUP_COMPACT_HEX_CHARS>::new();
            push_hex(&mut compact_hex, entropy);

            // The temporary buffers carried secret material; volatile-wipe them
            // (hygiene beyond the C++, which left its locals as-is).
            wipe_bytes(&mut mnemonic_buf);
            wipe_bytes(&mut entropy_buf);

            Ok(SessionSourceBackupPayload {
                backup_format: "bip39_words_seedqr",
                mnemonic,
                standard_seedqr_digits: digits,
                compact_seedqr_hex: compact_hex,
                nsec: FixedStr::new(),
            })
        }
        SessionKeySourceKind::NsecSecretKey => {
            let mut nsec_buf = [0u8; MAX_BACKUP_NSEC_CHARS];
            let nsec_str = nip19::encode_nsec(&source.nsec_secret_key, &mut nsec_buf)
                .map_err(SessionSourceBackupError::Nsec)?;
            // An encoded nsec is exactly 63 chars <= 64: never truncates.
            let nsec = FixedStr::from_str(nsec_str).expect("within documented capacity");
            wipe_bytes(&mut nsec_buf);
            Ok(SessionSourceBackupPayload {
                backup_format: "nip19_nsec",
                mnemonic: FixedStr::new(),
                standard_seedqr_digits: FixedStr::new(),
                compact_seedqr_hex: FixedStr::new(),
                nsec,
            })
        }
    }
}

/// Appends `index` as exactly four decimal digits (zero-padded), mirroring the
/// C++ `std::setw(4) << std::setfill('0')`. Indexes are `< 2048`, so four
/// digits always suffice and the 96-char buffer never overflows for 24 words.
fn push_four_digits(digits: &mut FixedStr<MAX_BACKUP_SEEDQR_DIGIT_CHARS>, index: u16) {
    let value = [
        b'0' + ((index / 1000) % 10) as u8,
        b'0' + ((index / 100) % 10) as u8,
        b'0' + ((index / 10) % 10) as u8,
        b'0' + (index % 10) as u8,
    ];
    digits
        .try_push_str(core::str::from_utf8(&value).unwrap_or(""))
        .expect("within documented capacity");
}

/// Appends `bytes` as lowercase hex, mirroring the C++ `hex_from_bytes`.
fn push_hex(out: &mut FixedStr<MAX_BACKUP_COMPACT_HEX_CHARS>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        let pair = [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]];
        out.try_push_str(core::str::from_utf8(&pair).unwrap_or(""))
            .expect("within documented capacity");
    }
}

/// Volatile-zeroes a scratch buffer that held secret material.
fn wipe_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a valid, exclusively-borrowed `u8` location.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

/// Builds the secret-hiding danger-zone backup review for a session source.
/// Mirrors the C++ `build_session_source_backup_review`.
#[must_use]
pub fn build_session_source_backup_review(source: &SessionKeySource) -> SessionSourceBackupReview {
    let backup_format = backup_format_for(source.kind);
    let fingerprint = session_key_source_fingerprint(source);
    let kind_label = crate::session::import_review::source_kind_label(source.kind);
    let output = match source.kind {
        SessionKeySourceKind::Bip39WordIndexes => "words/SeedQR",
        SessionKeySourceKind::NsecSecretKey => "nsec QR/text",
    };

    let mut review_id = SessionReviewId::new();
    // "session-backup-" (15) + 16 fingerprint chars = 31 <= 32: never truncates.
    review_id
        .try_push_str("session-backup-")
        .expect("within documented capacity");
    review_id
        .try_push_str(fingerprint.as_str())
        .expect("within documented capacity");

    // Approval-digest material (C++ `backup_approval_digest`):
    //   "nsealr.session-source-backup-review.v0\n" (39) + kind label (11)
    //   + "\n" + label (<= 64) + "\n" + fingerprint (16) + "\n"
    //   + backup format (<= 18)  => at most 151 bytes.
    let mut material = [0u8; 160];
    let mut len = push_material(
        &mut material,
        0,
        b"nsealr.session-source-backup-review.v0\n",
    );
    len = push_material(&mut material, len, kind_label.as_bytes());
    len = push_material(&mut material, len, b"\n");
    len = push_material(&mut material, len, source.label.as_str().as_bytes());
    len = push_material(&mut material, len, b"\n");
    len = push_material(&mut material, len, fingerprint.as_str().as_bytes());
    len = push_material(&mut material, len, b"\n");
    len = push_material(&mut material, len, backup_format.as_bytes());
    let digest_hex = crate::hash::sha256_hex(&material[..len]);
    let approval_digest =
        SessionApprovalDigest::from_str(core::str::from_utf8(&digest_hex).unwrap_or(""))
            .expect("within documented capacity");

    let mut warning_lines = ReviewPageLines::new();
    warning_lines
        .try_push("Danger: secret export")
        .expect("within documented capacity");
    let mut type_line = ReviewPageLine::new();
    type_line
        .try_push_str("Type: ")
        .expect("within documented capacity");
    type_line
        .try_push_str(kind_label)
        .expect("within documented capacity");
    warning_lines
        .try_push(type_line.as_str())
        .expect("within documented capacity");
    let mut label_line = ReviewPageLine::new();
    label_line
        .try_push_str("Label: ")
        .expect("within documented capacity");
    label_line
        .try_push_str(source.label.as_str())
        .expect("within documented capacity");
    warning_lines
        .try_push(label_line.as_str())
        .expect("within documented capacity");
    let mut fingerprint_line = ReviewPageLine::new();
    fingerprint_line
        .try_push_str("Fingerprint: ")
        .expect("within documented capacity");
    fingerprint_line
        .try_push_str(fingerprint.as_str())
        .expect("within documented capacity");
    warning_lines
        .try_push(fingerprint_line.as_str())
        .expect("within documented capacity");
    let mut output_line = ReviewPageLine::new();
    output_line
        .try_push_str("Output: ")
        .expect("within documented capacity");
    output_line
        .try_push_str(output)
        .expect("within documented capacity");
    warning_lines
        .try_push(output_line.as_str())
        .expect("within documented capacity");
    warning_lines
        .try_push("Session RAM only")
        .expect("within documented capacity");

    let mut decision_lines = ReviewPageLines::new();
    decision_lines
        .try_push("Anyone can sign")
        .expect("within documented capacity");
    decision_lines
        .try_push("Verify offline copy")
        .expect("within documented capacity");
    decision_lines
        .try_push("Approve to reveal")
        .expect("within documented capacity");

    SessionSourceBackupReview {
        review_id,
        approval_digest,
        pages: [
            TrustedReviewPage {
                title: FixedStr::from_str("Backup source").expect("within documented capacity"),
                lines: warning_lines,
                action: ReviewPageAction::Next,
                page_indicator: FixedStr::from_str("Page 1/2").expect("within documented capacity"),
                body_line_styles: ReviewBodyLineStyles::new(),
                logical_page_id: FixedStr::from_str("session-backup-warning")
                    .expect("within documented capacity"),
            },
            TrustedReviewPage {
                title: FixedStr::from_str("Show secret?").expect("within documented capacity"),
                lines: decision_lines,
                action: ReviewPageAction::ApproveOrReject,
                page_indicator: FixedStr::from_str("Page 2/2").expect("within documented capacity"),
                body_line_styles: ReviewBodyLineStyles::new(),
                logical_page_id: FixedStr::from_str("session-backup-decision")
                    .expect("within documented capacity"),
            },
        ],
    }
}

/// Mirrors the C++ `backup_format_for` (the C++ "unsupported" throw was
/// unreachable; the exhaustive match makes it unrepresentable).
fn backup_format_for(kind: SessionKeySourceKind) -> &'static str {
    match kind {
        SessionKeySourceKind::Bip39WordIndexes => "bip39_words_seedqr",
        SessionKeySourceKind::NsecSecretKey => "nip19_nsec",
    }
}

/// Appends `bytes` at `offset` into the digest material, returning the new
/// offset. The material buffer is sized for the documented worst case.
fn push_material(buf: &mut [u8], offset: usize, bytes: &[u8]) -> usize {
    let end = offset + bytes.len();
    buf[offset..end].copy_from_slice(bytes);
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;
    use crate::nip19;
    use crate::session::import_review::tests::{fixture_page, pages_contain_text};
    use crate::session::keyring::tests::{NSEC_TEST_KEY_1, SEEDQR_VECTOR_1_INDEXES};
    use crate::session::keyring::StatelessSessionKeyring;

    // Secret-key hex copied from the READ-ONLY
    // specs/vectors/nip19/nsec-test-key-1.json (`secret_key`).
    const NSEC_TEST_KEY_1_SECRET_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    fn fixture_keyring() -> StatelessSessionKeyring {
        let mut keyring = StatelessSessionKeyring::new();
        keyring
            .add_bip39_seed("SeedQR vector 1", &SEEDQR_VECTOR_1_INDEXES)
            .unwrap();
        keyring
            .add_nsec(
                "nsec test vector",
                &nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap(),
            )
            .unwrap();
        keyring
    }

    // Port of the C++ `test_session_source_backup_review_matches_shared_danger_zone_vectors`.
    // Fixture fields copied from the READ-ONLY
    // specs/vectors/session-source-backups/seedqr-vector-1-backup.json and
    // specs/vectors/session-source-backups/nsec-test-key-1-backup.json
    // (`review_id`, `approval_digest`, `pages`). The page equality reproduces
    // the C++ `assert_detailed_trusted_review_pages`.
    #[test]
    fn review_matches_shared_danger_zone_vectors() {
        let keyring = fixture_keyring();

        let seed_review = build_session_source_backup_review(keyring.source_at(0).unwrap());
        let nsec_review = build_session_source_backup_review(keyring.source_at(1).unwrap());

        assert_eq!(seed_review.review_id, "session-backup-2813e48dc42eb58b");
        assert_eq!(
            seed_review.approval_digest,
            "cc4221bae51583f385c58cca07f572a4eb3cde9f6abc5cd807da8a08618d6949",
        );
        assert_eq!(
            seed_review.pages,
            [
                fixture_page(
                    "Backup source",
                    &[
                        "Danger: secret export",
                        "Type: BIP-39 seed",
                        "Label: SeedQR vector 1",
                        "Fingerprint: 2813e48dc42eb58b",
                        "Output: words/SeedQR",
                        "Session RAM only",
                    ],
                    ReviewPageAction::Next,
                    "Page 1/2",
                    "session-backup-warning",
                ),
                fixture_page(
                    "Show secret?",
                    &[
                        "Anyone can sign",
                        "Verify offline copy",
                        "Approve to reveal"
                    ],
                    ReviewPageAction::ApproveOrReject,
                    "Page 2/2",
                    "session-backup-decision",
                ),
            ],
        );
        assert_eq!(nsec_review.review_id, "session-backup-dbd1f8666039f02a");
        assert_eq!(
            nsec_review.approval_digest,
            "5078c8d447da94e28362e5163d1068062ab6f39438da1a5a80c9c468cfbe4609",
        );
        assert_eq!(
            nsec_review.pages,
            [
                fixture_page(
                    "Backup source",
                    &[
                        "Danger: secret export",
                        "Type: NIP-19 nsec",
                        "Label: nsec test vector",
                        "Fingerprint: dbd1f8666039f02a",
                        "Output: nsec QR/text",
                        "Session RAM only",
                    ],
                    ReviewPageAction::Next,
                    "Page 1/2",
                    "session-backup-warning",
                ),
                fixture_page(
                    "Show secret?",
                    &[
                        "Anyone can sign",
                        "Verify offline copy",
                        "Approve to reveal"
                    ],
                    ReviewPageAction::ApproveOrReject,
                    "Page 2/2",
                    "session-backup-decision",
                ),
            ],
        );

        assert!(pages_contain_text(
            &seed_review.pages,
            "Danger: secret export"
        ));
        assert!(pages_contain_text(&seed_review.pages, "Approve to reveal"));
        assert!(!pages_contain_text(&seed_review.pages, "attack"));
        assert!(!pages_contain_text(&seed_review.pages, "expire"));
        assert!(!pages_contain_text(&nsec_review.pages, NSEC_TEST_KEY_1));
        assert!(!pages_contain_text(
            &nsec_review.pages,
            NSEC_TEST_KEY_1_SECRET_HEX,
        ));
    }

    // Port of the C++ `test_session_source_backup_payload_matches_shared_secret_payloads`.
    // Fixture fields copied from the READ-ONLY
    // specs/vectors/session-source-backups/*.json (`backup_format`,
    // `backup_payload.{mnemonic,standard_seedqr_digits,compact_seedqr_hex,nsec}`).
    #[test]
    fn payload_matches_shared_secret_payloads() {
        let keyring = fixture_keyring();

        let seed_payload = session_source_backup_payload(keyring.source_at(0).unwrap()).unwrap();
        let nsec_payload = session_source_backup_payload(keyring.source_at(1).unwrap()).unwrap();

        assert_eq!(seed_payload.backup_format, "bip39_words_seedqr");
        assert_eq!(
            seed_payload.mnemonic,
            "attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony ranch winter theme error hybrid van cereal salon goddess expire",
        );
        assert_eq!(
            seed_payload.standard_seedqr_digits,
            "011513251154012711900771041507421289190620080870026613431420201617920614089619290300152408010643",
        );
        assert_eq!(
            seed_payload.compact_seedqr_hex,
            "0e74b64107f94cc0ccfae6a13dcbec3662154fec67e0e00999c07892597d190a",
        );
        assert!(seed_payload.nsec.is_empty());
        assert_eq!(nsec_payload.backup_format, "nip19_nsec");
        assert_eq!(nsec_payload.nsec, NSEC_TEST_KEY_1);
        assert!(nsec_payload.mnemonic.is_empty());
    }

    // Direct error-branch tests (no single named C++ case: the C++ let these
    // propagate as uncaught `Bip39Error` / threw for 15/18/21-word seeds, which
    // no C++ test exercised; the ratchet requires the branches proven).
    #[test]
    fn payload_rejects_unsupported_word_counts_and_bad_checksums() {
        // A checksum-valid 15-word seed (all-zero 160-bit entropy; the last word
        // carries the 5 checksum bits of SHA-256(20 zero bytes)) renders a
        // mnemonic but is not representable as Standard/Compact SeedQR.
        let digest = sha256(&[0u8; 20]);
        let mut fifteen = [0u16; 15];
        fifteen[14] = u16::from(digest[0] >> 3);
        let mut keyring = StatelessSessionKeyring::new();
        keyring.add_bip39_seed("fifteen words", &fifteen).unwrap();
        assert_eq!(
            session_source_backup_payload(keyring.source_at(0).unwrap()),
            Err(SessionSourceBackupError::InvalidBackupWordCount),
        );

        // The keyring deliberately does not checksum-validate (C++ parity), so
        // a checksum-invalid seed fails at mnemonic rendering.
        let mut keyring = StatelessSessionKeyring::new();
        keyring.add_bip39_seed("bad checksum", &[0u16; 12]).unwrap();
        assert_eq!(
            session_source_backup_payload(keyring.source_at(0).unwrap()),
            Err(SessionSourceBackupError::Bip39(Bip39Error::InvalidChecksum)),
        );
    }
}
