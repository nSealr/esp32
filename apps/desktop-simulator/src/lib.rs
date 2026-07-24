//! desktop-simulator — the permanent vector-replay parity oracle for `nsealr-core`.
//!
//! This library replays every in-scope `specs/vectors/<category>/*.json` file
//! end-to-end through `nsealr-core`'s public API and asserts each vector's own
//! expected outcome. Both the CLI binary (`src/main.rs`) and the exhaustive
//! integration test (`tests/vectors.rs`) drive it, so there is exactly one
//! vector-loading + replay code path (no duplicate loaders).
//!
//! # The single configurable vector-source root (decision spec §6.5)
//!
//! [`vectors_root`] is the *one* place that resolves where category directories
//! live. It honours the `NSEALR_VECTORS_ROOT` environment override and otherwise
//! defaults to the sibling `specs` checkout (`<workspace>/../specs/vectors`, the
//! same convention every other integration script in this workspace uses).
//! Phase 07 repoints this single function at a pinned released artifact without
//! touching any replay code.
#![deny(missing_docs)]

use std::path::{Path, PathBuf};

pub mod replay;

/// Environment variable that overrides the vector-source root. When set, its
/// value is used verbatim as the directory that directly contains the
/// `<category>/` subdirectories.
pub const VECTORS_ROOT_ENV: &str = "NSEALR_VECTORS_ROOT";

/// The single configurable point for the vector-source root (decision spec §6.5).
///
/// Returns the directory that directly contains the `specs/vectors/<category>/`
/// subdirectories. Every loader in this crate resolves paths relative to this
/// one function; Phase 07 repoints it at a released artifact.
pub fn vectors_root() -> PathBuf {
    if let Some(overridden) = std::env::var_os(VECTORS_ROOT_ENV) {
        return PathBuf::from(overridden);
    }
    // Default: the sibling `specs` checkout. This crate's manifest dir is
    // `<workspace>/apps/desktop-simulator`; the workspace root is two levels up,
    // and the `specs` repo is its sibling (`ROOT.parent.join("specs")`).
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .ancestors()
        .nth(2)
        .expect("crate manifest dir has a workspace-root ancestor");
    workspace_root
        .parent()
        .expect("workspace root has a parent (the repo org root)")
        .join("specs")
        .join("vectors")
}

/// Categories replayed exhaustively by this harness (18). The names are the real
/// directory names under `specs/vectors/`. Keep in sync with the task's
/// "Vector-category scope" list; the completeness rule ([`check_completeness`])
/// fails CI if a directory on disk is in neither this list nor [`EXCLUDED_CATEGORIES`].
pub const IN_SCOPE_CATEGORIES: &[&str] = &[
    "transports",
    "review",
    "review-screens",
    "review-transcripts",
    "review-display-frames",
    "review-detail-pages",
    "session-import-reviews",
    "session-source-backups",
    "policy-changes",
    "policies",
    "seedqr",
    "nip19",
    "accounts",
    "devices",
    "keys",
    "limits",
    "source-public-key-proofs",
    "invalid",
];

/// Categories explicitly excluded from replay, each for a documented reason (see
/// the task's "Vector-category scope" exclusion list). Enumerated so the
/// completeness rule can prove that every on-disk category is consciously
/// classified, never silently skipped.
pub const EXCLUDED_CATEGORIES: &[&str] = &[
    "access-surfaces", // browser NIP-07 access-surface contract (companion).
    "custody",         // persistent-custody declarations (companion/hardware).
    "events",          // event-template fixtures (companion/specs suites).
    "features",        // signer-feature-matrix registry (verify_specs.py).
    "grants",          // persistent-grant surface, not in host_core (Phase 05/07).
    "nip46",           // companion-side NIP-46 surface; host_core never implemented it.
    "nip46-auth-challenges",
    "nip46-connection-token-responses",
    "nip46-connection-uris",
    "nip46-policy-files",
    "nip46-relay-events",
    "nip46-relay-steps",
    "nip46-session-gates",
    "nip46-sessions",
    "nip46-sessions-active",
    "policy-decisions", // companion policy-engine adjudication outcomes.
    "route-refusals",   // companion routing surface (drift-only snapshots).
    "route-selections", // companion routing surface (drift-only snapshots).
    "smartcard",        // solution-3 applet contract (smartcard/companion, Phase 06).
];

/// The restricted `invalid/` filename prefixes this harness owns: the decoder
/// rejection subsets the ported decoders implement. The `nip46-*` invalid
/// subsets are excluded (companion-owned, per the NIP-46 exclusion).
pub const INVALID_OWNED_PREFIXES: &[&str] = &["qr-envelope-", "request-", "serial-frame"];

/// `invalid/` filename prefixes consciously excluded from replay (companion-owned
/// NIP-46 relay/session surface and the response/relay-step decoders not part of
/// this harness's scope). Every `invalid/*.json` must match an owned OR an
/// excluded prefix; the within-`invalid` completeness rule
/// ([`check_invalid_completeness`]) fails on any file matching neither, so new
/// rejection vectors force an explicit re-triage instead of a silent skip.
pub const INVALID_EXCLUDED_PREFIXES: &[&str] = &["nip46-", "relay-step-", "response-"];

/// Evaluate the within-`invalid/` completeness rule: return the sorted list of
/// `invalid/*.json` filenames that match neither an owned nor an excluded prefix
/// (empty when every file is consciously classified).
pub fn check_invalid_completeness() -> std::io::Result<Vec<String>> {
    let dir = vectors_root().join("invalid");
    let mut unclassified = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if !name.ends_with(".json") {
            continue;
        }
        let owned = INVALID_OWNED_PREFIXES.iter().any(|p| name.starts_with(p));
        let excluded = INVALID_EXCLUDED_PREFIXES
            .iter()
            .any(|p| name.starts_with(p));
        if !owned && !excluded {
            unclassified.push(name);
        }
    }
    unclassified.sort();
    Ok(unclassified)
}

/// Outcome of the machine-verifiable completeness rule.
#[derive(Debug)]
pub struct CompletenessReport {
    /// Directory names found on disk under [`vectors_root`].
    pub on_disk: Vec<String>,
    /// Directories present on disk but in neither classification list.
    pub unclassified: Vec<String>,
    /// Names that appear in both lists (a bug in the lists themselves).
    pub overlap: Vec<String>,
}

impl CompletenessReport {
    /// True when every on-disk category is classified and the lists are disjoint.
    pub fn is_ok(&self) -> bool {
        self.unclassified.is_empty() && self.overlap.is_empty()
    }

    /// Human-readable failure message forcing an explicit re-triage.
    pub fn failure_message(&self) -> String {
        let mut msg = String::new();
        if !self.unclassified.is_empty() {
            msg.push_str(&format!(
                "completeness rule FAIL: specs/vectors directories in NEITHER the in-scope \
                 nor the excluded list: {:?}. Re-triage each: add it to IN_SCOPE_CATEGORIES \
                 (with a replay) or to EXCLUDED_CATEGORIES (with a rationale). Silent skips \
                 are forbidden.",
                self.unclassified
            ));
        }
        if !self.overlap.is_empty() {
            if !msg.is_empty() {
                msg.push('\n');
            }
            msg.push_str(&format!(
                "completeness rule FAIL: categories appear in BOTH lists: {:?}.",
                self.overlap
            ));
        }
        msg
    }
}

/// List the immediate subdirectory names under [`vectors_root`], sorted.
pub fn on_disk_categories() -> std::io::Result<Vec<String>> {
    let mut dirs = Vec::new();
    for entry in std::fs::read_dir(vectors_root())? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                dirs.push(name.to_string());
            }
        }
    }
    dirs.sort();
    Ok(dirs)
}

/// Evaluate the completeness rule against the live `specs/vectors` tree.
pub fn check_completeness() -> std::io::Result<CompletenessReport> {
    let on_disk = on_disk_categories()?;
    let unclassified = on_disk
        .iter()
        .filter(|d| {
            !IN_SCOPE_CATEGORIES.contains(&d.as_str()) && !EXCLUDED_CATEGORIES.contains(&d.as_str())
        })
        .cloned()
        .collect();
    let overlap = IN_SCOPE_CATEGORIES
        .iter()
        .filter(|c| EXCLUDED_CATEGORIES.contains(*c))
        .map(|c| c.to_string())
        .collect();
    Ok(CompletenessReport {
        on_disk,
        unclassified,
        overlap,
    })
}

/// CLI entry point: replay one named vector file for ad hoc debugging, using the
/// same loader + replay path as the exhaustive test suite (no duplicate code).
///
/// `target` may be an existing filesystem path, or a `category/name.json` path
/// relative to [`vectors_root`]. Returns a process exit code: `0` success,
/// `1` replay/assertion failure, `2` usage error.
pub fn run_cli(args: &[String]) -> i32 {
    let target = match args.first() {
        Some(t) => t,
        None => {
            eprintln!(
                "usage: desktop-simulator <vector.json | category/name.json>\n\
                 Replays one specs vector through nsealr-core and asserts its \
                 expected outcome.\n\
                 Vector root: {} (override with {VECTORS_ROOT_ENV}).",
                vectors_root().display()
            );
            return 2;
        }
    };
    let given = Path::new(target);
    let path = if given.exists() {
        given.to_path_buf()
    } else {
        vectors_root().join(target)
    };
    match replay::replay_file(&path) {
        Ok(()) => {
            println!("OK   {}", path.display());
            0
        }
        Err(e) => {
            eprintln!("FAIL {}: {e}", path.display());
            1
        }
    }
}

/// Return the sorted `*.json` file paths for a category directory. When
/// `prefixes` is non-empty, only files whose name starts with one of the
/// prefixes are returned (used to restrict `invalid/` to the decoder-owned
/// subsets).
pub fn category_files(category: &str, prefixes: &[&str]) -> std::io::Result<Vec<PathBuf>> {
    let dir = vectors_root().join(category);
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !name.ends_with(".json") {
            continue;
        }
        if !prefixes.is_empty() && !prefixes.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        files.push(path);
    }
    files.sort();
    Ok(files)
}
