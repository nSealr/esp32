//! Shared trusted-review page data model — pure data types, no review logic.
//!
//! Ported from the C++ reference `host_core` headers: [`TrustedReviewPage`] from
//! `include/nsealr/trusted_review.hpp`, and the [`ReviewPageAction`] /
//! [`ReviewBodyLineStyle`] enums it embeds from `include/nsealr/review_display.hpp`.
//! The review *logic* those headers also declare (`TrustedReviewSession`,
//! `render_review_page`, `ReviewControlSession`) is **not** ported here — it
//! arrives with milestone M-T3.6. These types land early because the M-T3.4
//! session/custody modules build review pages as plain data.
//!
//! The C++ used `std::string`/`std::vector` fields; this allocation-free port
//! stores bounded inline text ([`FixedStr`]) and fixed-capacity lists. The
//! capacities cover every page the session modules build (line text up to
//! `"Label: "` + a 64-char label) with headroom for the M-T3.6 review pages;
//! M-T3.6 revisits them if its ports need more.

use crate::text::{FixedStr, TextError};
use core::str::FromStr;

/// Maximum byte length of a review page title.
pub const MAX_REVIEW_PAGE_TITLE_CHARS: usize = 32;
/// Maximum byte length of one review body line. Raised from 96 in M-T3.5: the
/// policy-change review renders `"Account: "` + an up-to-128-byte stable id on
/// one line (137 bytes worst case), and the C++ never bounded line length.
pub const MAX_REVIEW_PAGE_LINE_CHARS: usize = 144;
/// Maximum number of body lines on one review page. Raised from 8 in M-T3.6:
/// the display-review builders emit up to `max_compact_body_lines` lines per
/// page (9 in the shared t-display-s3 profile and the
/// `specs/vectors/review-detail-pages` fixtures).
pub const MAX_REVIEW_PAGE_LINES: usize = 10;
/// Maximum byte length of a page indicator. Raised from 16 in M-T3.6: scroll
/// windows render `"Page 3/4 Lines 10-18/48"`-shaped indicators (the C++ never
/// bounded the string).
pub const MAX_REVIEW_PAGE_INDICATOR_CHARS: usize = 32;
/// Maximum byte length of a logical page id (for example
/// `"session-import-summary"`).
pub const MAX_REVIEW_LOGICAL_PAGE_ID_CHARS: usize = 32;

/// The action a review page offers. Mirrors the C++ `ReviewPageAction`
/// (`review_display.hpp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewPageAction {
    /// The page only advances to the next page.
    Next,
    /// The page carries the terminal approve-or-reject decision.
    ApproveOrReject,
}

/// The rendering style of one review body line. Mirrors the C++
/// `ReviewBodyLineStyle` (`review_display.hpp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewBodyLineStyle {
    /// Default body text.
    Normal,
    /// De-emphasised metadata text.
    Meta,
    /// Emphasised value text.
    Value,
}

/// One review body line, bounded by [`MAX_REVIEW_PAGE_LINE_CHARS`].
pub type ReviewPageLine = FixedStr<MAX_REVIEW_PAGE_LINE_CHARS>;

/// A fixed-capacity list of review body lines — the allocation-free stand-in for
/// the C++ `std::vector<std::string>` page lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewPageLines {
    lines: [ReviewPageLine; MAX_REVIEW_PAGE_LINES],
    len: usize,
}

impl ReviewPageLines {
    /// Creates an empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lines: [const { ReviewPageLine::new() }; MAX_REVIEW_PAGE_LINES],
            len: 0,
        }
    }

    /// Appends one line.
    ///
    /// # Errors
    ///
    /// [`TextError::TooLong`] if the list already holds
    /// [`MAX_REVIEW_PAGE_LINES`] lines or the line exceeds
    /// [`MAX_REVIEW_PAGE_LINE_CHARS`] bytes.
    pub fn try_push(&mut self, line: &str) -> Result<(), TextError> {
        if self.len >= MAX_REVIEW_PAGE_LINES {
            return Err(TextError::TooLong);
        }
        self.lines[self.len] = ReviewPageLine::from_str(line)?;
        self.len += 1;
        Ok(())
    }

    /// Returns the active lines as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[ReviewPageLine] {
        &self.lines[..self.len]
    }

    /// Replaces the line at `index` (which must be within [`Self::len`]).
    /// Added in M-T3.6 for the display renderer's last-line ellipsis rewrite.
    ///
    /// # Panics
    ///
    /// Panics if `index >= len` (callers index lines they just pushed).
    pub fn replace(&mut self, index: usize, line: &ReviewPageLine) {
        assert!(index < self.len, "line index within active length");
        self.lines[index] = line.clone();
    }

    /// Returns the number of lines held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the list holds no lines.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for ReviewPageLines {
    fn default() -> Self {
        Self::new()
    }
}

/// A fixed-capacity list of per-line styles — the allocation-free stand-in for
/// the C++ `std::vector<ReviewBodyLineStyle>` (empty on every session page; the
/// M-T3.6 review builders populate it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewBodyLineStyles {
    styles: [ReviewBodyLineStyle; MAX_REVIEW_PAGE_LINES],
    len: usize,
}

impl ReviewBodyLineStyles {
    /// Creates an empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            styles: [ReviewBodyLineStyle::Normal; MAX_REVIEW_PAGE_LINES],
            len: 0,
        }
    }

    /// Appends one style.
    ///
    /// # Errors
    ///
    /// [`TextError::TooLong`] if the list already holds
    /// [`MAX_REVIEW_PAGE_LINES`] styles.
    pub fn try_push(&mut self, style: ReviewBodyLineStyle) -> Result<(), TextError> {
        if self.len >= MAX_REVIEW_PAGE_LINES {
            return Err(TextError::TooLong);
        }
        self.styles[self.len] = style;
        self.len += 1;
        Ok(())
    }

    /// Returns the active styles as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[ReviewBodyLineStyle] {
        &self.styles[..self.len]
    }

    /// Returns the number of styles held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the list holds no styles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for ReviewBodyLineStyles {
    fn default() -> Self {
        Self::new()
    }
}

/// One trusted-review page. Mirrors the C++ `TrustedReviewPage`
/// (`trusted_review.hpp`) field for field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedReviewPage {
    /// Page title (C++ `title`).
    pub title: FixedStr<MAX_REVIEW_PAGE_TITLE_CHARS>,
    /// Body lines (C++ `lines`).
    pub lines: ReviewPageLines,
    /// Page action (C++ `action`).
    pub action: ReviewPageAction,
    /// Page indicator such as `"Page 1/2"` (C++ `page_indicator`).
    pub page_indicator: FixedStr<MAX_REVIEW_PAGE_INDICATOR_CHARS>,
    /// Per-line styles (C++ `body_line_styles`).
    pub body_line_styles: ReviewBodyLineStyles,
    /// Stable logical page id (C++ `logical_page_id`).
    pub logical_page_id: FixedStr<MAX_REVIEW_LOGICAL_PAGE_ID_CHARS>,
}

impl TrustedReviewPage {
    /// Creates an empty page. This is the const seed for fixed-capacity page
    /// lists (analogous to [`ReviewPageLine::new`]); its [`ReviewPageAction`] is
    /// [`ReviewPageAction::Next`], the neutral non-terminal action.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            title: FixedStr::new(),
            lines: ReviewPageLines::new(),
            action: ReviewPageAction::Next,
            page_indicator: FixedStr::new(),
            body_line_styles: ReviewBodyLineStyles::new(),
            logical_page_id: FixedStr::new(),
        }
    }
}

impl Default for TrustedReviewPage {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum byte length of a trusted-review request id. Covers the policy-change
/// proposal id (`"proposal-"` + up to 119 id chars).
pub const MAX_TRUSTED_REVIEW_REQUEST_ID_CHARS: usize = 128;

/// Maximum number of pages a [`TrustedReviewRequest`] carries. Raised from 4 in
/// M-T3.6: the scroll-windowed display reviews split long Content/Tags sections
/// into one flat page per window (the 16-tag serial navigation case needs 9;
/// 12 leaves headroom). The C++ used an unbounded `std::vector`; builders
/// report a capacity error past this bound (documented deviation).
pub const MAX_TRUSTED_REVIEW_PAGES: usize = 12;

/// A trusted-review request id rendered as bounded inline text.
pub type TrustedReviewRequestId = FixedStr<MAX_TRUSTED_REVIEW_REQUEST_ID_CHARS>;

/// A SHA-256 approval digest rendered as 64 lowercase hex characters (C++
/// `approval_digest`).
pub type TrustedReviewApprovalDigest = FixedStr<64>;

/// A fixed-capacity list of trusted-review pages — the allocation-free stand-in
/// for the C++ `std::vector<TrustedReviewPage>` a [`TrustedReviewRequest`]
/// carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewPageList {
    pages: [TrustedReviewPage; MAX_TRUSTED_REVIEW_PAGES],
    len: usize,
}

impl ReviewPageList {
    /// Creates an empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pages: [const { TrustedReviewPage::new() }; MAX_TRUSTED_REVIEW_PAGES],
            len: 0,
        }
    }

    /// Appends one page.
    ///
    /// # Errors
    ///
    /// [`TextError::TooLong`] if the list already holds
    /// [`MAX_TRUSTED_REVIEW_PAGES`] pages.
    pub fn try_push(&mut self, page: TrustedReviewPage) -> Result<(), TextError> {
        if self.len >= MAX_TRUSTED_REVIEW_PAGES {
            return Err(TextError::TooLong);
        }
        self.pages[self.len] = page;
        self.len += 1;
        Ok(())
    }

    /// Returns the active pages as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[TrustedReviewPage] {
        &self.pages[..self.len]
    }

    /// Appends a body line to the page at `page_index` (styles untouched).
    /// Added in M-T3.6 for the streaming QR review builders.
    ///
    /// # Errors
    ///
    /// [`TextError::TooLong`] if the page's line list is full or the line
    /// exceeds [`MAX_REVIEW_PAGE_LINE_CHARS`] bytes.
    ///
    /// # Panics
    ///
    /// Panics if `page_index >= len` (callers index pages they just pushed).
    pub fn line_push(&mut self, page_index: usize, line: &str) -> Result<(), TextError> {
        assert!(page_index < self.len, "page index within active length");
        self.pages[page_index].lines.try_push(line)
    }

    /// Appends a body line and its style to the page at `page_index`. Added in
    /// M-T3.6 for the streaming QR display-review builders.
    ///
    /// # Errors
    ///
    /// [`TextError::TooLong`] if the page's line or style list is full or the
    /// line exceeds [`MAX_REVIEW_PAGE_LINE_CHARS`] bytes.
    ///
    /// # Panics
    ///
    /// Panics if `page_index >= len` (callers index pages they just pushed).
    pub fn line_push_styled(
        &mut self,
        page_index: usize,
        line: &str,
        style: ReviewBodyLineStyle,
    ) -> Result<(), TextError> {
        assert!(page_index < self.len, "page index within active length");
        self.pages[page_index].lines.try_push(line)?;
        self.pages[page_index].body_line_styles.try_push(style)
    }

    /// Returns the number of pages held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the list holds no pages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for ReviewPageList {
    fn default() -> Self {
        Self::new()
    }
}

/// A trusted-review request: an id, its approval digest, and the ordered pages
/// to display. Mirrors the C++ `TrustedReviewRequest` (`trusted_review.hpp`)
/// field for field. This is the pure data model only; the review *session*
/// logic that consumes it (`TrustedReviewSession`) arrives with M-T3.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedReviewRequest {
    /// Stable request id (C++ `request_id`).
    pub request_id: TrustedReviewRequestId,
    /// SHA-256 approval digest binding the pages (C++ `approval_digest`).
    pub approval_digest: TrustedReviewApprovalDigest,
    /// The ordered review pages (C++ `pages`).
    pub pages: ReviewPageList,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Direct unit tests for the container plumbing (no single named C++ case:
    // the C++ used std::vector directly). The session-module tests exercise the
    // types end to end against the specs/vectors session fixtures.
    #[test]
    fn line_list_pushes_and_rejects_overflow() {
        let mut lines = ReviewPageLines::new();
        assert!(lines.is_empty());
        assert_eq!(lines.len(), 0);
        assert_eq!(lines, ReviewPageLines::default());

        lines.try_push("Danger: secret export").unwrap();
        lines.try_push("Session RAM only").unwrap();
        assert_eq!(lines.len(), 2);
        assert!(!lines.is_empty());
        assert_eq!(lines.as_slice()[0], "Danger: secret export");
        assert_eq!(lines.as_slice()[1], "Session RAM only");
        assert_eq!(lines.clone(), lines);

        let long_line = core::str::from_utf8(&[b'x'; MAX_REVIEW_PAGE_LINE_CHARS + 1]).unwrap();
        assert_eq!(lines.try_push(long_line), Err(TextError::TooLong));
        assert_eq!(lines.len(), 2);

        for _ in lines.len()..MAX_REVIEW_PAGE_LINES {
            lines.try_push("filler").unwrap();
        }
        assert_eq!(lines.try_push("overflow"), Err(TextError::TooLong));
        assert_eq!(lines.len(), MAX_REVIEW_PAGE_LINES);
    }

    #[test]
    fn style_list_pushes_and_rejects_overflow() {
        let mut styles = ReviewBodyLineStyles::new();
        assert!(styles.is_empty());
        assert_eq!(styles.len(), 0);
        assert_eq!(styles, ReviewBodyLineStyles::default());

        styles.try_push(ReviewBodyLineStyle::Meta).unwrap();
        styles.try_push(ReviewBodyLineStyle::Value).unwrap();
        assert_eq!(
            styles.as_slice(),
            &[ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value],
        );
        assert!(!styles.is_empty());
        assert_eq!(styles.clone(), styles);

        for _ in styles.len()..MAX_REVIEW_PAGE_LINES {
            styles.try_push(ReviewBodyLineStyle::Normal).unwrap();
        }
        assert_eq!(
            styles.try_push(ReviewBodyLineStyle::Normal),
            Err(TextError::TooLong),
        );
        assert_eq!(styles.len(), MAX_REVIEW_PAGE_LINES);
    }

    // Container plumbing for the trusted-review request page list added for the
    // policy-change review port (M-T3.5). Same shape as the line/style lists;
    // no single named C++ case (the C++ used std::vector directly).
    #[test]
    fn page_list_pushes_and_rejects_overflow() {
        let empty = TrustedReviewPage::new();
        assert_eq!(empty, TrustedReviewPage::default());
        assert_eq!(empty.action, ReviewPageAction::Next);
        assert!(empty.title.is_empty());
        assert!(empty.lines.is_empty());

        let mut pages = ReviewPageList::new();
        assert!(pages.is_empty());
        assert_eq!(pages.len(), 0);
        assert_eq!(pages, ReviewPageList::default());

        let mut page = TrustedReviewPage::new();
        page.title = FixedStr::from_str("Policy change").unwrap();
        page.action = ReviewPageAction::ApproveOrReject;
        for _ in 0..MAX_TRUSTED_REVIEW_PAGES {
            pages.try_push(page.clone()).unwrap();
        }
        assert_eq!(pages.len(), MAX_TRUSTED_REVIEW_PAGES);
        assert!(!pages.is_empty());
        assert_eq!(pages.as_slice()[0], page);
        assert_eq!(pages.clone(), pages);
        assert_eq!(pages.try_push(page), Err(TextError::TooLong));
        assert_eq!(pages.len(), MAX_TRUSTED_REVIEW_PAGES);
    }
}
