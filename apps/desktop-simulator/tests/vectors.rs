//! The exhaustive, glob-driven parity-oracle replay: every in-scope
//! `specs/vectors/<category>/*.json` file replayed end-to-end through
//! `nsealr-core`'s public API, plus the machine-verifiable completeness rules.
//!
//! There is exactly one test per in-scope category (18) and one completeness
//! test per rule. Every category test globs the REAL files on disk and replays
//! each one — nothing is spot-checked, skipped, or xfail'd. If `specs/vectors`
//! grows a new file in an in-scope category it is replayed automatically; if it
//! grows a new *directory* (or a new `invalid/` prefix) the completeness rules
//! fail until it is consciously classified.

use desktop_simulator::replay::replay_file;
use desktop_simulator::{category_files, check_completeness, check_invalid_completeness};

/// Replay every file in `category` (optionally restricted to `prefixes`),
/// asserting the directory is non-empty (no silent under-coverage) and that
/// every vector's expected outcome matches. Returns the count replayed.
fn replay_category(category: &str, prefixes: &[&str]) -> usize {
    let files =
        category_files(category, prefixes).unwrap_or_else(|e| panic!("enumerate {category}: {e}"));
    assert!(
        !files.is_empty(),
        "category '{category}' matched zero vector files (glob rotted or moved) — \
         an in-scope category must replay at least one file",
    );
    let mut failures = Vec::new();
    for path in &files {
        if let Err(e) = replay_file(path) {
            failures.push(format!("{}: {e}", path.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "{}/{} vectors in '{category}' failed replay:\n{}",
        failures.len(),
        files.len(),
        failures.join("\n"),
    );
    files.len()
}

// --- Completeness rules (machine-verifiable, CI-enforced) ----------------------

#[test]
fn completeness_rule_every_category_is_classified() {
    let report = check_completeness().expect("enumerate specs/vectors directories");
    assert!(report.is_ok(), "{}", report.failure_message());
}

#[test]
fn completeness_rule_every_invalid_file_is_classified() {
    let unclassified = check_invalid_completeness().expect("enumerate specs/vectors/invalid");
    assert!(
        unclassified.is_empty(),
        "completeness rule FAIL: invalid/ files matching neither an owned nor an \
         excluded prefix (re-triage each — add its prefix to INVALID_OWNED_PREFIXES \
         with a replay or INVALID_EXCLUDED_PREFIXES with a rationale): {unclassified:?}",
    );
}

// --- One exhaustive replay test per in-scope category (18) ---------------------

#[test]
fn replay_transports() {
    replay_category("transports", &[]);
}

#[test]
fn replay_invalid() {
    replay_category("invalid", desktop_simulator::INVALID_OWNED_PREFIXES);
}

#[test]
fn replay_limits() {
    replay_category("limits", &[]);
}

#[test]
fn replay_devices() {
    replay_category("devices", &[]);
}

#[test]
fn replay_policies() {
    replay_category("policies", &[]);
}

#[test]
fn replay_policy_changes() {
    replay_category("policy-changes", &[]);
}

#[test]
fn replay_seedqr() {
    replay_category("seedqr", &[]);
}

#[test]
fn replay_nip19() {
    replay_category("nip19", &[]);
}

#[test]
fn replay_keys() {
    replay_category("keys", &[]);
}

#[test]
fn replay_accounts() {
    replay_category("accounts", &[]);
}

#[test]
fn replay_source_public_key_proofs() {
    replay_category("source-public-key-proofs", &[]);
}

#[test]
fn replay_session_import_reviews() {
    replay_category("session-import-reviews", &[]);
}

#[test]
fn replay_session_source_backups() {
    replay_category("session-source-backups", &[]);
}

#[test]
fn replay_review() {
    replay_category("review", &[]);
}

#[test]
fn replay_review_screens() {
    replay_category("review-screens", &[]);
}

#[test]
fn replay_review_detail_pages() {
    replay_category("review-detail-pages", &[]);
}

#[test]
fn replay_review_display_frames() {
    replay_category("review-display-frames", &[]);
}

#[test]
fn replay_review_transcripts() {
    replay_category("review-transcripts", &[]);
}
