//! Shared test fixtures for the M-T3.6 review/protocol tests (test-only).
//!
//! The C++ suite consumed these through the generated vector header
//! (`generate_transport_vector_header.py` over `specs/vectors`); this port
//! copies the same fixture values as Rust literals, each with its READ-ONLY
//! source file named, and reads them at test time only.

use crate::review::display::ReviewDisplayFrame;
use crate::review::types::{
    ReviewBodyLineStyles, ReviewPageAction, ReviewPageLines, ReviewPageList, TrustedReviewPage,
    TrustedReviewRequest,
};

/// Approval digest copied from the READ-ONLY
/// specs/vectors/review-screens/kind-1-basic.json (`screen_review.approval_digest`).
pub const BASIC_REVIEW_SCREEN_APPROVAL_DIGEST: &str =
    "a09ddd564e439fdd4756da6863156eddcfc50c295af453af1c78c35986c303a5";

/// Approval digest copied from the READ-ONLY
/// specs/vectors/review-screens/kind-1-tags.json (`screen_review.approval_digest`).
pub const TAGGED_REVIEW_SCREEN_APPROVAL_DIGEST: &str =
    "b45328f9ef96122900562d161cca5f09e24bfdb66676c46ebbcfe08dd661eb30";

/// Static QR envelope copied from the READ-ONLY
/// specs/vectors/transports/qr-envelope-kind-1-basic.json (`envelope`).
pub const QR_ENVELOPE_KIND_1_BASIC: &str =
    "nsealr1:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm1ldGhvZCI6InNpZ25fZXZlbnQiLCJwYXJhbXMiOnsiZXZlbnRfdGVtcGxhdGUiOnsiY3JlYXRlZF9hdCI6MTcxMDAwMDAwMCwia2luZCI6MSwidGFncyI6W10sImNvbnRlbnQiOiJuU2VhbHIgZml4dHVyZTogYmFzaWMga2luZCAxIGV2ZW50LiJ9fX0";

/// Builds one review page from plain literals.
pub fn review_page(
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
        title: title.parse().unwrap(),
        lines: page_lines,
        action,
        page_indicator: page_indicator.parse().unwrap(),
        body_line_styles: ReviewBodyLineStyles::new(),
        logical_page_id: logical_page_id.parse().unwrap(),
    }
}

/// Builds a trusted-review request from plain literals (empty
/// indicator/styles/logical ids, as the summary pages carry).
pub fn trusted_review_request(
    request_id: &str,
    approval_digest: &str,
    pages: &[(&str, &[&str], ReviewPageAction)],
) -> TrustedReviewRequest {
    let mut page_list = ReviewPageList::new();
    for (title, lines, action) in pages {
        page_list
            .try_push(review_page(title, lines, *action, "", ""))
            .unwrap();
    }
    TrustedReviewRequest {
        request_id: request_id.parse().unwrap(),
        approval_digest: approval_digest.parse().unwrap(),
        pages: page_list,
    }
}

/// The basic trusted-review request; request id, digest and all four pages
/// copied from the READ-ONLY specs/vectors/review-screens/kind-1-basic.json
/// (`screen_review`). The C++ consumed it as
/// `test_vectors::basic_trusted_review_request()`.
pub fn basic_trusted_review_request() -> TrustedReviewRequest {
    trusted_review_request(
        "req-kind-1-basic",
        BASIC_REVIEW_SCREEN_APPROVAL_DIGEST,
        &[
            (
                "Event",
                &[
                    "Kind 1",
                    "Created 1710000000",
                    "Author",
                    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                ],
                ReviewPageAction::Next,
            ),
            (
                "Content",
                &["nSealr fixture: basic kind 1 event."],
                ReviewPageAction::Next,
            ),
            ("Tags", &["No tags"], ReviewPageAction::Next),
            (
                "Decision",
                &["Approve signing only if all pages match."],
                ReviewPageAction::ApproveOrReject,
            ),
        ],
    )
}

/// The tagged trusted-review request; request id, digest and all four pages
/// copied from the READ-ONLY specs/vectors/review-screens/kind-1-tags.json
/// (`screen_review`). The C++ consumed it as
/// `test_vectors::tagged_trusted_review_request()`.
pub fn tagged_trusted_review_request() -> TrustedReviewRequest {
    trusted_review_request(
        "req-kind-1-tags",
        TAGGED_REVIEW_SCREEN_APPROVAL_DIGEST,
        &[
            (
                "Event",
                &[
                    "Kind 1",
                    "Created 1710000060",
                    "Author",
                    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                ],
                ReviewPageAction::Next,
            ),
            (
                "Content",
                &["nSealr fixture: tagged kind 1 event."],
                ReviewPageAction::Next,
            ),
            (
                "Tags",
                &[
                    "Tag 1/2",
                    "p",
                    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                    "",
                    "mention",
                    "Tag 2/2",
                    "t",
                    "nsealr",
                ],
                ReviewPageAction::Next,
            ),
            (
                "Decision",
                &["Approve signing only if all pages match."],
                ReviewPageAction::ApproveOrReject,
            ),
        ],
    )
}

/// The shared t-display-s3 review display limits. Mirrors the C++
/// `nsealr_esp32::t_display_s3_review_limits()`
/// (`esp32_s3_usb_signer/main/t_display_s3_raster.cpp`), which matches the
/// `limits` field of every READ-ONLY specs/vectors/review-detail-pages fixture.
pub fn t_display_s3_review_limits() -> crate::review::display::ReviewDisplayLimits {
    crate::review::display::ReviewDisplayLimits {
        max_title_chars: 18,
        max_body_lines: 5,
        max_line_chars: 26,
        max_compact_body_lines: 9,
        max_compact_line_chars: 48,
    }
}

/// True if any frame body line contains `needle` (the C++ `lines_contain`).
pub fn frame_lines_contain(frame: &ReviewDisplayFrame, needle: &str) -> bool {
    frame
        .body_lines
        .as_slice()
        .iter()
        .any(|line| line.as_str().contains(needle))
}

/// Joins the lines of every page with `title` (the C++
/// `joined_lines_for_title`).
pub fn joined_lines_for_title(pages: &[TrustedReviewPage], title: &str) -> std::string::String {
    let mut joined = std::string::String::new();
    for page in pages {
        if page.title != title {
            continue;
        }
        for line in page.lines.as_slice() {
            joined.push_str(line.as_str());
        }
    }
    joined
}

/// Counts the pages with `title` (the C++ `page_count_with_title`).
pub fn page_count_with_title(pages: &[TrustedReviewPage], title: &str) -> usize {
    pages.iter().filter(|page| page.title == title).count()
}

/// True if any line of any page contains `needle` (the C++ `lines_contain`
/// applied across pages).
pub fn any_page_line_contains(pages: &[TrustedReviewPage], needle: &str) -> bool {
    pages.iter().any(|page| {
        page.lines
            .as_slice()
            .iter()
            .any(|line| line.as_str().contains(needle))
    })
}
