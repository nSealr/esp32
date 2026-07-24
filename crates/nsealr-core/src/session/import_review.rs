//! Secret-hiding session import review and source fingerprinting.
//!
//! Ported from the C++ reference `host_core` sources
//! `src/session_import_review.cpp` + `include/nsealr/session_import_review.hpp`
//! for behaviour parity. The review pages never carry secret material — only
//! the source kind, label, fingerprint and word count.

use crate::hash::sha256_hex;
use crate::review::types::{
    ReviewBodyLineStyles, ReviewPageAction, ReviewPageLine, ReviewPageLines, TrustedReviewPage,
};
use crate::session::keyring::{SessionKeySource, SessionKeySourceKind};
use crate::text::FixedStr;
use core::str::FromStr;

/// Length in hex characters of a session key source fingerprint. Mirrors the
/// C++ `kSessionKeySourceFingerprintHexChars`.
pub const SESSION_KEY_SOURCE_FINGERPRINT_CHARS: usize = 16;

/// A session key source fingerprint (16 lowercase hex characters).
pub type SessionKeySourceFingerprint = FixedStr<SESSION_KEY_SOURCE_FINGERPRINT_CHARS>;

/// A session review id such as `"session-import-<fingerprint>"`.
pub type SessionReviewId = FixedStr<32>;

/// A SHA-256 approval digest rendered as 64 lowercase hex characters.
pub type SessionApprovalDigest = FixedStr<64>;

/// The secret-hiding import review for one session source. Mirrors the C++
/// `SessionImportReview` (`review_id`, `approval_digest`, `pages`); the C++
/// page vector always held exactly two pages, so this port stores them inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionImportReview {
    /// Stable review id: `"session-import-"` + fingerprint (C++ `review_id`).
    pub review_id: SessionReviewId,
    /// SHA-256 approval digest over the domain-separated review material (C++
    /// `approval_digest`).
    pub approval_digest: SessionApprovalDigest,
    /// The summary page and the decision page (C++ `pages`).
    pub pages: [TrustedReviewPage; 2],
}

/// The user-facing label for a source kind. Mirrors the C++
/// `source_kind_label` (shared verbatim by the backup review module).
#[must_use]
pub(crate) fn source_kind_label(kind: SessionKeySourceKind) -> &'static str {
    match kind {
        SessionKeySourceKind::NsecSecretKey => "NIP-19 nsec",
        SessionKeySourceKind::Bip39WordIndexes => "BIP-39 seed",
    }
}

/// Computes the 16-hex-char fingerprint of a session key source. Mirrors the
/// C++ `session_key_source_fingerprint` (first 16 chars of the SHA-256 hex of
/// the domain-separated fingerprint material).
#[must_use]
pub fn session_key_source_fingerprint(source: &SessionKeySource) -> SessionKeySourceFingerprint {
    // Fingerprint material layout (C++ `fingerprint_material`):
    //   "nsealr.session-key-source.v0\n" (29) + kind label (11) + "\n" (1)
    //   + either the 32 raw secret bytes, or the decimal word count (<= 2)
    //     + "\n" + big-endian u16 word-index pairs (<= 48)  => at most 92 bytes.
    let mut material = [0u8; 96];
    let mut len = push_bytes(&mut material, 0, b"nsealr.session-key-source.v0\n");
    len = push_bytes(
        &mut material,
        len,
        source_kind_label(source.kind).as_bytes(),
    );
    len = push_bytes(&mut material, len, b"\n");
    match source.kind {
        SessionKeySourceKind::NsecSecretKey => {
            len = push_bytes(&mut material, len, &source.nsec_secret_key);
        }
        SessionKeySourceKind::Bip39WordIndexes => {
            len = push_decimal(&mut material, len, source.bip39_word_indexes.count);
            len = push_bytes(&mut material, len, b"\n");
            for &word_index in source.bip39_word_indexes.as_slice() {
                len = push_bytes(&mut material, len, &word_index.to_be_bytes());
            }
        }
    }
    let digest_hex = sha256_hex(&material[..len]);
    // The material buffer carried raw secret bytes; volatile-wipe it before it
    // leaves scope (hygiene beyond the C++, which left its std::string as-is).
    for byte in &mut material {
        // SAFETY: `byte` is a valid, exclusively-borrowed `u8` location.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    // The digest is ASCII hex, so the str view of its first 16 chars is valid.
    let fingerprint =
        core::str::from_utf8(&digest_hex[..SESSION_KEY_SOURCE_FINGERPRINT_CHARS]).unwrap_or("");
    SessionKeySourceFingerprint::from_str(fingerprint).expect("within documented capacity")
}

/// Appends `bytes` at `offset`, returning the new offset. Every caller sizes
/// its buffer for the documented worst case, so the copy never truncates.
fn push_bytes(buf: &mut [u8], offset: usize, bytes: &[u8]) -> usize {
    let end = offset + bytes.len();
    buf[offset..end].copy_from_slice(bytes);
    end
}

/// Appends the decimal rendering of `value` (word counts, at most two digits)
/// at `offset`, returning the new offset.
fn push_decimal(buf: &mut [u8], offset: usize, value: usize) -> usize {
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
    push_bytes(buf, offset, &digits[position..])
}

/// Builds the secret-hiding import review for a session source. Mirrors the
/// C++ `build_session_import_review`.
#[must_use]
pub fn build_session_import_review(source: &SessionKeySource) -> SessionImportReview {
    let fingerprint = session_key_source_fingerprint(source);

    let mut review_id = SessionReviewId::new();
    // "session-import-" (15) + 16 fingerprint chars = 31 <= 32: never truncates.
    review_id
        .try_push_str("session-import-")
        .expect("within documented capacity");
    review_id
        .try_push_str(fingerprint.as_str())
        .expect("within documented capacity");

    // Approval-digest material (C++ `import_approval_digest`):
    //   "nsealr.session-import-review.v0\n" (32) + kind label (11) + "\n"
    //   + label (<= 64) + "\n" + fingerprint (16)  => at most 125 bytes.
    let mut material = [0u8; 128];
    let mut len = push_bytes(&mut material, 0, b"nsealr.session-import-review.v0\n");
    len = push_bytes(
        &mut material,
        len,
        source_kind_label(source.kind).as_bytes(),
    );
    len = push_bytes(&mut material, len, b"\n");
    len = push_bytes(&mut material, len, source.label.as_str().as_bytes());
    len = push_bytes(&mut material, len, b"\n");
    len = push_bytes(&mut material, len, fingerprint.as_str().as_bytes());
    let digest_hex = sha256_hex(&material[..len]);
    let approval_digest =
        SessionApprovalDigest::from_str(core::str::from_utf8(&digest_hex).unwrap_or(""))
            .expect("within documented capacity");

    SessionImportReview {
        review_id,
        approval_digest,
        pages: [summary_page(source, &fingerprint), decision_page()],
    }
}

/// Builds the C++ `source_summary_lines` page ("Import source", `Page 1/2`).
fn summary_page(
    source: &SessionKeySource,
    fingerprint: &SessionKeySourceFingerprint,
) -> TrustedReviewPage {
    let mut lines = ReviewPageLines::new();
    let mut type_line = ReviewPageLine::new();
    type_line
        .try_push_str("Type: ")
        .expect("within documented capacity");
    type_line
        .try_push_str(source_kind_label(source.kind))
        .expect("within documented capacity");
    lines
        .try_push(type_line.as_str())
        .expect("within documented capacity");
    let mut label_line = ReviewPageLine::new();
    label_line
        .try_push_str("Label: ")
        .expect("within documented capacity");
    label_line
        .try_push_str(source.label.as_str())
        .expect("within documented capacity");
    lines
        .try_push(label_line.as_str())
        .expect("within documented capacity");
    let mut fingerprint_line = ReviewPageLine::new();
    fingerprint_line
        .try_push_str("Fingerprint: ")
        .expect("within documented capacity");
    fingerprint_line
        .try_push_str(fingerprint.as_str())
        .expect("within documented capacity");
    lines
        .try_push(fingerprint_line.as_str())
        .expect("within documented capacity");
    if source.kind == SessionKeySourceKind::Bip39WordIndexes {
        let mut words_line = ReviewPageLine::new();
        words_line
            .try_push_str("Words: ")
            .expect("within documented capacity");
        words_line
            .try_push_usize(source.bip39_word_indexes.count)
            .expect("within documented capacity");
        lines
            .try_push(words_line.as_str())
            .expect("within documented capacity");
    }
    lines
        .try_push("Secret: hidden")
        .expect("within documented capacity");

    TrustedReviewPage {
        title: FixedStr::from_str("Import source").unwrap_or_default(),
        lines,
        action: ReviewPageAction::Next,
        page_indicator: FixedStr::from_str("Page 1/2").unwrap_or_default(),
        body_line_styles: ReviewBodyLineStyles::new(),
        logical_page_id: FixedStr::from_str("session-import-summary").unwrap_or_default(),
    }
}

/// Builds the fixed C++ decision page ("Import?", `Page 2/2`).
fn decision_page() -> TrustedReviewPage {
    let mut lines = ReviewPageLines::new();
    lines
        .try_push("Session RAM only")
        .expect("within documented capacity");
    lines
        .try_push("No signing enabled")
        .expect("within documented capacity");
    lines
        .try_push("Approve to load")
        .expect("within documented capacity");
    TrustedReviewPage {
        title: FixedStr::from_str("Import?").unwrap_or_default(),
        lines,
        action: ReviewPageAction::ApproveOrReject,
        page_indicator: FixedStr::from_str("Page 2/2").unwrap_or_default(),
        body_line_styles: ReviewBodyLineStyles::new(),
        logical_page_id: FixedStr::from_str("session-import-decision").unwrap_or_default(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::nip19;
    use crate::review::types::{ReviewBodyLineStyles, ReviewPageLines};
    use crate::session::keyring::tests::{NSEC_TEST_KEY_1, SEEDQR_VECTOR_1_INDEXES};
    use crate::session::keyring::StatelessSessionKeyring;

    // Secret-key hex copied from the READ-ONLY
    // specs/vectors/nip19/nsec-test-key-1.json (`secret_key`).
    pub(crate) const NSEC_TEST_KEY_1_SECRET_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// Builds an expected page from fixture literals (the Rust analogue of the
    /// C++ generated `TrustedReviewPage` vector initialisers).
    pub(crate) fn fixture_page(
        title: &str,
        lines: &[&str],
        action: ReviewPageAction,
        page_indicator: &str,
        logical_page_id: &str,
    ) -> TrustedReviewPage {
        let mut page_lines = ReviewPageLines::new();
        for line in lines {
            page_lines.try_push(line).unwrap();
        }
        TrustedReviewPage {
            title: FixedStr::from_str(title).unwrap(),
            lines: page_lines,
            action,
            page_indicator: FixedStr::from_str(page_indicator).unwrap(),
            body_line_styles: ReviewBodyLineStyles::new(),
            logical_page_id: FixedStr::from_str(logical_page_id).unwrap(),
        }
    }

    /// The Rust analogue of the C++ `lines_contain_text` test helper.
    pub(crate) fn pages_contain_text(pages: &[TrustedReviewPage], needle: &str) -> bool {
        pages.iter().any(|page| {
            page.lines
                .as_slice()
                .iter()
                .any(|line| line.as_str().contains(needle))
        })
    }

    // Port of the C++ `test_session_import_review_hides_secret_material`.
    // Fixture fields copied from the READ-ONLY
    // specs/vectors/session-import-reviews/nsec-test-key-1.json and
    // specs/vectors/session-import-reviews/seedqr-vector-1.json (`fingerprint`,
    // `review_id`, `approval_digest`, `pages`). The page comparison reproduces
    // the C++ `assert_detailed_trusted_review_pages` (title, lines, action,
    // page_indicator, body_line_styles, logical_page_id).
    #[test]
    fn hides_secret_material() {
        let mut keyring = StatelessSessionKeyring::new();
        let secret = nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap();
        keyring.add_nsec("nsec test vector", &secret).unwrap();
        keyring
            .add_bip39_seed("SeedQR vector 1", &SEEDQR_VECTOR_1_INDEXES)
            .unwrap();

        let nsec_review = build_session_import_review(keyring.source_at(0).unwrap());
        let seed_review = build_session_import_review(keyring.source_at(1).unwrap());

        assert_eq!(nsec_review.review_id, "session-import-dbd1f8666039f02a");
        assert_eq!(
            nsec_review.approval_digest,
            "dcc8851f8c6a15f60b201345205af678489702437b1ce1dae87958b0ecd2abf0",
        );
        assert_eq!(
            session_key_source_fingerprint(keyring.source_at(0).unwrap()),
            "dbd1f8666039f02a",
        );
        assert_eq!(
            nsec_review.pages,
            [
                fixture_page(
                    "Import source",
                    &[
                        "Type: NIP-19 nsec",
                        "Label: nsec test vector",
                        "Fingerprint: dbd1f8666039f02a",
                        "Secret: hidden",
                    ],
                    ReviewPageAction::Next,
                    "Page 1/2",
                    "session-import-summary",
                ),
                fixture_page(
                    "Import?",
                    &["Session RAM only", "No signing enabled", "Approve to load"],
                    ReviewPageAction::ApproveOrReject,
                    "Page 2/2",
                    "session-import-decision",
                ),
            ],
        );
        assert!(pages_contain_text(&nsec_review.pages, "Type: NIP-19 nsec"));
        assert!(pages_contain_text(&nsec_review.pages, "Secret: hidden"));
        assert!(!pages_contain_text(
            &nsec_review.pages,
            NSEC_TEST_KEY_1_SECRET_HEX,
        ));

        assert_ne!(seed_review.review_id, nsec_review.review_id);
        assert_ne!(seed_review.approval_digest, nsec_review.approval_digest);
        assert_eq!(seed_review.review_id, "session-import-2813e48dc42eb58b");
        assert_eq!(
            seed_review.approval_digest,
            "eb8f785367ddacc3fe14353a1ef90bc4271040c2f0790cb11a73601f2c3e389d",
        );
        assert_eq!(
            session_key_source_fingerprint(keyring.source_at(1).unwrap()),
            "2813e48dc42eb58b",
        );
        assert_eq!(
            seed_review.pages,
            [
                fixture_page(
                    "Import source",
                    &[
                        "Type: BIP-39 seed",
                        "Label: SeedQR vector 1",
                        "Fingerprint: 2813e48dc42eb58b",
                        "Words: 24",
                        "Secret: hidden",
                    ],
                    ReviewPageAction::Next,
                    "Page 1/2",
                    "session-import-summary",
                ),
                fixture_page(
                    "Import?",
                    &["Session RAM only", "No signing enabled", "Approve to load"],
                    ReviewPageAction::ApproveOrReject,
                    "Page 2/2",
                    "session-import-decision",
                ),
            ],
        );
        assert!(pages_contain_text(&seed_review.pages, "Type: BIP-39 seed"));
        assert!(pages_contain_text(&seed_review.pages, "Words: 24"));
        assert!(pages_contain_text(&seed_review.pages, "Secret: hidden"));
        assert!(!pages_contain_text(&seed_review.pages, "attack"));
        assert!(!pages_contain_text(&seed_review.pages, "expire"));

        assert_eq!(seed_review.pages[0].title, "Import source");
        assert_eq!(seed_review.pages[0].action, ReviewPageAction::Next);
        assert_eq!(seed_review.pages[1].title, "Import?");
        assert_eq!(
            seed_review.pages[1].action,
            ReviewPageAction::ApproveOrReject
        );
    }

    // Fixture replay for the third session-import-reviews vector (the C++
    // replayed it through `session_import_review_vectors()`; the named cases
    // above cover the other two). Fields copied from the READ-ONLY
    // specs/vectors/session-import-reviews/nip06-account-0-leader.json.
    #[test]
    fn replays_nip06_account_0_leader_fixture() {
        // Mnemonic word indexes copied from the READ-ONLY
        // specs/vectors/keys/nip06-account-0-leader.json (`standard_word_indexes`).
        const NIP06_INDEXES: [u16; 12] = [
            1012, 1145, 1283, 1488, 828, 11, 161, 680, 267, 853, 1173, 156,
        ];
        let mut keyring = StatelessSessionKeyring::new();
        keyring
            .add_bip39_seed("NIP-06 account 0", &NIP06_INDEXES)
            .unwrap();
        let source = keyring.source_at(0).unwrap();

        assert_eq!(session_key_source_fingerprint(source), "cd64b58daca009b9");
        let review = build_session_import_review(source);
        assert_eq!(review.review_id, "session-import-cd64b58daca009b9");
        assert_eq!(
            review.approval_digest,
            "0f93a9d0eae6017d7cf555dfb880e0288c6bc3e767fd9e727a90c5d2d2737a66",
        );
        assert_eq!(
            review.pages,
            [
                fixture_page(
                    "Import source",
                    &[
                        "Type: BIP-39 seed",
                        "Label: NIP-06 account 0",
                        "Fingerprint: cd64b58daca009b9",
                        "Words: 12",
                        "Secret: hidden",
                    ],
                    ReviewPageAction::Next,
                    "Page 1/2",
                    "session-import-summary",
                ),
                fixture_page(
                    "Import?",
                    &["Session RAM only", "No signing enabled", "Approve to load"],
                    ReviewPageAction::ApproveOrReject,
                    "Page 2/2",
                    "session-import-decision",
                ),
            ],
        );
    }
}
