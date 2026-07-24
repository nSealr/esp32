//! Trusted review display rendering — bounded frames for a tiny display.
//!
//! Ported from the C++ reference `host_core` sources `src/review_display.cpp` +
//! `include/nsealr/review_display.hpp` for behaviour parity: the same
//! [`ReviewDisplayLimits`] defaults, the same codepoint-aware line wrapping
//! (never splitting a UTF-8 sequence), the same last-line ellipsis when the
//! body overflows, the same `"Page N/M"` fallback indicator, and the same
//! `"Next"` / `"Approve / Reject"` action hints.
//!
//! The C++ returned heap `std::string`s in `ReviewDisplayFrame`; this
//! allocation-free port renders into bounded inline text
//! ([`crate::text::FixedStr`]) sized by the shared review capacities. Limits
//! wider than those capacities are reported as
//! [`ReviewDisplayError::LimitsExceedCapacity`] (no C++ analogue). The C++
//! threw `std::invalid_argument`/`std::out_of_range`/`std::length_error`; this
//! port returns [`ReviewDisplayError`] values with the exact C++ messages.

use crate::review::types::{
    ReviewBodyLineStyle, ReviewBodyLineStyles, ReviewPageAction, ReviewPageLine, ReviewPageLines,
    MAX_REVIEW_PAGE_INDICATOR_CHARS, MAX_REVIEW_PAGE_LINES, MAX_REVIEW_PAGE_LINE_CHARS,
    MAX_REVIEW_PAGE_TITLE_CHARS,
};
use crate::text::FixedStr;
use core::fmt;

/// Maximum byte length of an action hint (`"Approve / Reject"`, 16 bytes).
pub const MAX_REVIEW_ACTION_HINT_CHARS: usize = 16;

/// A review page to render: borrowed title/lines/styles plus the action.
/// Mirrors the C++ `ReviewPage` (`std::string_view` fields).
#[derive(Debug, Clone, Copy)]
pub struct ReviewPage<'a> {
    /// Page title (C++ `title`).
    pub title: &'a str,
    /// Body lines (C++ `lines`).
    pub lines: &'a [ReviewPageLine],
    /// Page action (C++ `action`).
    pub action: ReviewPageAction,
    /// Optional pre-built page indicator (C++ `page_indicator`; empty = build
    /// the `"Page N/M"` fallback).
    pub page_indicator: &'a str,
    /// Per-line styles (C++ `body_line_styles`; missing entries = Normal).
    pub body_line_styles: &'a [ReviewBodyLineStyle],
}

/// Display size limits. Mirrors the C++ `ReviewDisplayLimits` field for field,
/// including the default values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewDisplayLimits {
    /// Maximum title characters (C++ default 24).
    pub max_title_chars: usize,
    /// Maximum body lines for normal-style pages (C++ default 6).
    pub max_body_lines: usize,
    /// Maximum characters per normal-style line (C++ default 64).
    pub max_line_chars: usize,
    /// Maximum body lines when compact styles are present (C++ default 9).
    pub max_compact_body_lines: usize,
    /// Maximum characters per compact-style line (C++ default 48).
    pub max_compact_line_chars: usize,
}

impl Default for ReviewDisplayLimits {
    /// The C++ member-initializer defaults.
    fn default() -> Self {
        Self {
            max_title_chars: 24,
            max_body_lines: 6,
            max_line_chars: 64,
            max_compact_body_lines: 9,
            max_compact_line_chars: 48,
        }
    }
}

/// Errors reported by [`render_review_page`]. Each variant except
/// [`Self::LimitsExceedCapacity`] corresponds to a distinct C++ throw site;
/// [`Self::message`] returns the exact C++ text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewDisplayError {
    /// A limit field is zero. C++ `std::invalid_argument`.
    ZeroLimits,
    /// `total_pages` is zero. C++ `std::invalid_argument`.
    ZeroTotalPages,
    /// `page_index >= total_pages`. C++ `std::out_of_range`.
    PageIndexOutOfRange,
    /// The title is empty. C++ `std::invalid_argument`.
    EmptyTitle,
    /// The title exceeds `max_title_chars` bytes. C++ `std::length_error`.
    TitleTooLong,
    /// The limits exceed this port's fixed frame capacities
    /// ([`MAX_REVIEW_PAGE_LINES`] lines of [`MAX_REVIEW_PAGE_LINE_CHARS`]
    /// bytes, [`MAX_REVIEW_PAGE_TITLE_CHARS`]-byte titles). No C++ analogue
    /// (the C++ heap-allocated unbounded strings).
    LimitsExceedCapacity,
}

impl ReviewDisplayError {
    /// The exact message the C++ exception carried (or this port's own text for
    /// [`Self::LimitsExceedCapacity`]).
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::ZeroLimits => "review display limits must be non-zero",
            Self::ZeroTotalPages => "review display total pages must be non-zero",
            Self::PageIndexOutOfRange => "review display page index out of range",
            Self::EmptyTitle => "review display title must be non-empty",
            Self::TitleTooLong => "review display title exceeds configured width",
            Self::LimitsExceedCapacity => "review display limits exceed fixed frame capacity",
        }
    }
}

impl fmt::Display for ReviewDisplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// A rendered display frame. Mirrors the C++ `ReviewDisplayFrame`, with the
/// heap strings replaced by bounded inline text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewDisplayFrame {
    /// Frame title.
    pub title: FixedStr<MAX_REVIEW_PAGE_TITLE_CHARS>,
    /// Page indicator (given or the `"Page N/M"` fallback).
    pub page_indicator: FixedStr<MAX_REVIEW_PAGE_INDICATOR_CHARS>,
    /// Wrapped, bounded body lines.
    pub body_lines: ReviewPageLines,
    /// `"Next"` or `"Approve / Reject"` (a trusted-review session may override
    /// with `"Next/Scroll"`).
    pub action_hint: FixedStr<MAX_REVIEW_ACTION_HINT_CHARS>,
    /// Per-line styles, parallel to [`Self::body_lines`].
    pub body_line_styles: ReviewBodyLineStyles,
}

/// Renders one review page into a bounded display frame. Mirrors the C++
/// `render_review_page`.
///
/// # Errors
///
/// See [`ReviewDisplayError`]; the validation order matches the C++ (limits →
/// total pages → page index → title empty → title width), with the capacity
/// check first (no C++ analogue).
pub fn render_review_page(
    page: &ReviewPage<'_>,
    page_index: usize,
    total_pages: usize,
    limits: ReviewDisplayLimits,
) -> Result<ReviewDisplayFrame, ReviewDisplayError> {
    validate_display_bounds(page, page_index, total_pages, limits)?;

    let mut frame = ReviewDisplayFrame {
        title: page
            .title
            .parse()
            .map_err(|_| ReviewDisplayError::LimitsExceedCapacity)?,
        page_indicator: FixedStr::new(),
        body_lines: ReviewPageLines::new(),
        action_hint: action_hint_for(page.action)
            .parse()
            .expect("hint within documented capacity"),
        body_line_styles: ReviewBodyLineStyles::new(),
    };
    if page.page_indicator.is_empty() {
        frame.page_indicator = page_indicator_for(page_index, total_pages);
    } else {
        frame.page_indicator = page
            .page_indicator
            .parse()
            .map_err(|_| ReviewDisplayError::LimitsExceedCapacity)?;
    }
    bounded_body_lines(
        page,
        limits,
        &mut frame.body_lines,
        &mut frame.body_line_styles,
    );
    Ok(frame)
}

/// Builds the `"Page N/M"` fallback indicator (1-based). The digits of two
/// usize values plus the fixed text fit the indicator capacity.
pub(crate) fn page_indicator_for(
    page_index: usize,
    total_pages: usize,
) -> FixedStr<MAX_REVIEW_PAGE_INDICATOR_CHARS> {
    let mut indicator = FixedStr::new();
    // 32-char capacity: "Page " (5) + 2×20-digit worst-case + "/" cannot all
    // fit, but real page counts are bounded by MAX_TRUSTED_REVIEW_PAGES (12),
    // so the render is at most "Page 12/12" (10 bytes).
    indicator
        .try_push_str("Page ")
        .expect("within documented capacity");
    indicator
        .try_push_usize(page_index + 1)
        .expect("within documented capacity");
    indicator
        .try_push_str("/")
        .expect("within documented capacity");
    indicator
        .try_push_usize(total_pages)
        .expect("within documented capacity");
    indicator
}

/// Mirrors the C++ `action_hint_for`.
pub(crate) const fn action_hint_for(action: ReviewPageAction) -> &'static str {
    match action {
        ReviewPageAction::Next => "Next",
        ReviewPageAction::ApproveOrReject => "Approve / Reject",
    }
}

/// Mirrors the C++ `compact_style`.
const fn compact_style(style: ReviewBodyLineStyle) -> bool {
    matches!(
        style,
        ReviewBodyLineStyle::Meta | ReviewBodyLineStyle::Value
    )
}

/// Counts display characters. Mirrors the C++ `display_char_count` lambda
/// inside `truncate_for_display` — the C++ counted decoded codepoints and let
/// a stray byte count as one, but every input here is a valid `&str`, so the
/// count is exactly the number of `char`s.
fn display_char_count(text: &str) -> usize {
    text.chars().count()
}

/// Truncates `text` to at most `max_chars` display characters, appending
/// `"..."` when truncation happens (or when `force_ellipsis` demands it).
/// Mirrors the C++ `truncate_for_display` (codepoint-wise copy via
/// `char_indices`; the C++ stray-byte recovery is unreachable on `&str`).
fn truncate_for_display(text: &str, max_chars: usize, force_ellipsis: bool) -> ReviewPageLine {
    let mut out = ReviewPageLine::new();
    if display_char_count(text) <= max_chars && !force_ellipsis {
        out.try_push_str(text).expect("caller-bounded line width");
        return out;
    }
    if max_chars <= 3 {
        for _ in 0..max_chars {
            out.try_push_str(".").expect("caller-bounded line width");
        }
        return out;
    }
    let mut end = text.len();
    for (copied, (offset, _)) in text.char_indices().enumerate() {
        if copied == max_chars - 3 {
            end = offset;
            break;
        }
    }
    out.try_push_str(&text[..end])
        .expect("caller-bounded line width");
    out.try_push_str("...").expect("caller-bounded line width");
    out
}

/// Wraps one line at `width` display characters without splitting UTF-8
/// sequences, invoking `emit` for each wrapped part (an empty line emits one
/// empty part). Mirrors the C++ `wrap_line` (which returned a vector; the C++
/// stray-byte recovery is unreachable on `&str`).
fn wrap_line(line: &str, width: usize, emit: &mut dyn FnMut(&str)) {
    if line.is_empty() {
        emit("");
        return;
    }
    let mut current_start = 0usize;
    let mut current_chars = 0usize;
    for (offset, _) in line.char_indices() {
        if current_chars == width {
            emit(&line[current_start..offset]);
            current_start = offset;
            current_chars = 0;
        }
        current_chars += 1;
    }
    if current_start < line.len() {
        emit(&line[current_start..]);
    }
}

/// Wraps, bounds, and truncates the page body into `lines`/`styles`. Mirrors
/// the C++ `bounded_body_lines`.
fn bounded_body_lines(
    page: &ReviewPage<'_>,
    limits: ReviewDisplayLimits,
    lines: &mut ReviewPageLines,
    styles: &mut ReviewBodyLineStyles,
) {
    let has_compact_style = page
        .lines
        .iter()
        .enumerate()
        .map(|(index, _)| style_at(page, index))
        .any(compact_style);
    let max_body_lines = if has_compact_style {
        limits.max_compact_body_lines
    } else {
        limits.max_body_lines
    };

    // Wrap every source line, stopping once the bounded budget is exhausted
    // (the C++ wrapped everything into a vector then resized; the accept set is
    // identical, and the truncation below only ever inspects the kept lines).
    let mut truncated = false;
    'outer: for (index, line) in page.lines.iter().enumerate() {
        let style = style_at(page, index);
        let width = width_for(style, limits);
        let mut full = false;
        wrap_line(line.as_str(), width, &mut |part| {
            if full {
                truncated = true;
                return;
            }
            if lines.len() == max_body_lines {
                full = true;
                truncated = true;
                return;
            }
            lines.try_push(part).expect("caller-bounded line width");
            styles.try_push(style).expect("bounded alongside lines");
        });
        if full && index + 1 < page.lines.len() {
            truncated = true;
            break 'outer;
        }
    }

    if truncated && !lines.is_empty() {
        let last = lines.len() - 1;
        let style = styles.as_slice()[last];
        let width = width_for(style, limits);
        let replaced = truncate_for_display(lines.as_slice()[last].as_str(), width, true);
        lines.replace(last, &replaced);
    }
    // The C++ ran a final truncation pass over every kept line; wrapping
    // already bounds each kept line to its width and the ellipsis rewrite
    // stays within it, so that pass was a provable no-op and is omitted.
}

/// The style of source line `index` (missing entries are Normal, as in C++).
fn style_at(page: &ReviewPage<'_>, index: usize) -> ReviewBodyLineStyle {
    page.body_line_styles
        .get(index)
        .copied()
        .unwrap_or(ReviewBodyLineStyle::Normal)
}

/// The wrap width for a style. Mirrors the C++ width selection.
const fn width_for(style: ReviewBodyLineStyle, limits: ReviewDisplayLimits) -> usize {
    if compact_style(style) {
        limits.max_compact_line_chars
    } else {
        limits.max_line_chars
    }
}

/// Mirrors the C++ `validate_display_limits` + `validate_display_bounds`, plus
/// this port's capacity check.
fn validate_display_bounds(
    page: &ReviewPage<'_>,
    page_index: usize,
    total_pages: usize,
    limits: ReviewDisplayLimits,
) -> Result<(), ReviewDisplayError> {
    if limits.max_title_chars == 0
        || limits.max_body_lines == 0
        || limits.max_line_chars == 0
        || limits.max_compact_body_lines == 0
        || limits.max_compact_line_chars == 0
    {
        return Err(ReviewDisplayError::ZeroLimits);
    }
    if limits.max_body_lines > MAX_REVIEW_PAGE_LINES
        || limits.max_compact_body_lines > MAX_REVIEW_PAGE_LINES
        || limits.max_line_chars > MAX_REVIEW_PAGE_LINE_CHARS
        || limits.max_compact_line_chars > MAX_REVIEW_PAGE_LINE_CHARS
        || limits.max_title_chars > MAX_REVIEW_PAGE_TITLE_CHARS
    {
        return Err(ReviewDisplayError::LimitsExceedCapacity);
    }
    if total_pages == 0 {
        return Err(ReviewDisplayError::ZeroTotalPages);
    }
    if page_index >= total_pages {
        return Err(ReviewDisplayError::PageIndexOutOfRange);
    }
    if page.title.is_empty() {
        return Err(ReviewDisplayError::EmptyTitle);
    }
    if page.title.len() > limits.max_title_chars {
        return Err(ReviewDisplayError::TitleTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;
    use std::string::String;
    use std::vec::Vec;

    fn lines_of(texts: &[&str]) -> ReviewPageLines {
        let mut lines = ReviewPageLines::new();
        for text in texts {
            lines.try_push(text).unwrap();
        }
        lines
    }

    fn page<'a>(
        title: &'a str,
        lines: &'a ReviewPageLines,
        action: ReviewPageAction,
    ) -> ReviewPage<'a> {
        ReviewPage {
            title,
            lines: lines.as_slice(),
            action,
            page_indicator: "",
            body_line_styles: &[],
        }
    }

    fn body_strs(frame: &ReviewDisplayFrame) -> Vec<String> {
        frame
            .body_lines
            .as_slice()
            .iter()
            .map(|line| String::from(line.as_str()))
            .collect()
    }

    // Port of the C++ `test_review_display_renders_navigation_frame`.
    #[test]
    fn renders_navigation_frame() {
        let lines = lines_of(&["Kind 1", "Created 1710000000", "Author"]);
        let frame = render_review_page(
            &page("Event", &lines, ReviewPageAction::Next),
            0,
            4,
            ReviewDisplayLimits::default(),
        )
        .unwrap();

        assert_eq!(frame.title, "Event");
        assert_eq!(frame.page_indicator, "Page 1/4");
        assert_eq!(
            body_strs(&frame),
            ["Kind 1", "Created 1710000000", "Author"]
        );
        assert_eq!(frame.action_hint, "Next");
    }

    // Port of the C++
    // `test_review_display_preserves_logical_page_indicator_and_body_styles`.
    #[test]
    fn preserves_logical_page_indicator_and_body_styles() {
        let lines = lines_of(&["bytes: 281", "abcdef"]);
        let mut review_page = page("Content", &lines, ReviewPageAction::Next);
        review_page.page_indicator = "Page 2/4";
        review_page.body_line_styles = &[ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value];

        let frame = render_review_page(
            &review_page,
            4,
            12,
            ReviewDisplayLimits {
                max_title_chars: 18,
                max_body_lines: 5,
                max_line_chars: 26,
                max_compact_body_lines: 9,
                max_compact_line_chars: 48,
            },
        )
        .unwrap();

        assert_eq!(frame.title, "Content");
        assert_eq!(frame.page_indicator, "Page 2/4");
        assert_eq!(body_strs(&frame), ["bytes: 281", "abcdef"]);
        assert_eq!(
            frame.body_line_styles.as_slice(),
            &[ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value],
        );
        assert_eq!(frame.action_hint, "Next");
    }

    // Port of the C++ `test_review_display_renders_decision_frame`.
    #[test]
    fn renders_decision_frame() {
        let lines = lines_of(&["Approve signing only if all pages match."]);
        let frame = render_review_page(
            &page("Decision", &lines, ReviewPageAction::ApproveOrReject),
            3,
            4,
            ReviewDisplayLimits::default(),
        )
        .unwrap();

        assert_eq!(frame.title, "Decision");
        assert_eq!(frame.page_indicator, "Page 4/4");
        assert_eq!(
            body_strs(&frame),
            ["Approve signing only if all pages match."]
        );
        assert_eq!(frame.action_hint, "Approve / Reject");
    }

    // Port of the C++ `test_review_display_wraps_and_truncates_long_body_lines`.
    #[test]
    fn wraps_and_truncates_long_body_lines() {
        let lines = lines_of(&["0123456789abcdef0123456789abcdef0123456789abcdef"]);
        let frame = render_review_page(
            &page("Content", &lines, ReviewPageAction::Next),
            1,
            4,
            ReviewDisplayLimits {
                max_title_chars: 12,
                max_body_lines: 2,
                max_line_chars: 16,
                ..ReviewDisplayLimits::default()
            },
        )
        .unwrap();

        assert_eq!(frame.title, "Content");
        assert_eq!(frame.page_indicator, "Page 2/4");
        let body = body_strs(&frame);
        assert_eq!(body.len(), 2);
        assert!(body[0].len() <= 16);
        assert!(body[1].len() <= 16);
        assert!(body[1].ends_with("..."));
        assert_eq!(frame.action_hint, "Next");
    }

    // Port of the C++ `test_review_display_wraps_utf8_without_splitting_codepoints`.
    #[test]
    fn wraps_utf8_without_splitting_codepoints() {
        let lines = lines_of(&["abc\u{e8}def"]);
        let frame = render_review_page(
            &page("Content", &lines, ReviewPageAction::Next),
            0,
            1,
            ReviewDisplayLimits {
                max_title_chars: 12,
                max_body_lines: 3,
                max_line_chars: 4,
                ..ReviewDisplayLimits::default()
            },
        )
        .unwrap();

        assert_eq!(body_strs(&frame), ["abc\u{e8}", "def"]);
        assert!(crate::unicode::is_valid_utf8(
            frame.body_lines.as_slice()[0].as_str().as_bytes()
        ));
        assert!(crate::unicode::is_valid_utf8(
            frame.body_lines.as_slice()[1].as_str().as_bytes()
        ));
    }

    // Port of the C++ `test_review_display_matches_shared_long_content_frame_vector`.
    // Limits + expected frame copied from the READ-ONLY
    // specs/vectors/review-display-frames/kind-1-long-content-page-1-20x3.json
    // (`limits`, `page_index`, `frame`; the omitted compact limits take the C++
    // defaults, exactly as the generated vector header defaulted them).
    #[test]
    fn matches_shared_long_content_frame_vector() {
        let mut long_preview = String::new();
        for _ in 0..120 {
            long_preview.push('x');
        }
        long_preview.push_str("...");
        let lines = lines_of(&[long_preview.as_str()]);

        let frame = render_review_page(
            &page("Content", &lines, ReviewPageAction::Next),
            1,
            4,
            ReviewDisplayLimits {
                max_title_chars: 12,
                max_body_lines: 3,
                max_line_chars: 20,
                ..ReviewDisplayLimits::default()
            },
        )
        .unwrap();

        assert_eq!(frame.title, "Content");
        assert_eq!(frame.page_indicator, "Page 2/4");
        assert_eq!(
            body_strs(&frame),
            [
                "xxxxxxxxxxxxxxxxxxxx",
                "xxxxxxxxxxxxxxxxxxxx",
                "xxxxxxxxxxxxxxxxx...",
            ],
        );
        assert_eq!(frame.action_hint, "Next");
    }

    // Port of the C++ `test_review_display_matches_shared_utf8_boundary_frame_vector`.
    // Limits + expected frame copied from the READ-ONLY
    // specs/vectors/review-display-frames/kind-1-unicode-boundary-content-4x3.json.
    #[test]
    fn matches_shared_utf8_boundary_frame_vector() {
        let lines = lines_of(&["abc\u{e8}def"]);
        let frame = render_review_page(
            &page("Content", &lines, ReviewPageAction::Next),
            1,
            4,
            ReviewDisplayLimits {
                max_title_chars: 12,
                max_body_lines: 3,
                max_line_chars: 4,
                ..ReviewDisplayLimits::default()
            },
        )
        .unwrap();

        assert_eq!(frame.title, "Content");
        assert_eq!(frame.page_indicator, "Page 2/4");
        assert_eq!(body_strs(&frame), ["abc\u{e8}", "def"]);
        assert_eq!(frame.action_hint, "Next");
    }

    // Port of the C++ `test_review_display_rejects_unsafe_frame_bounds`.
    #[test]
    fn rejects_unsafe_frame_bounds() {
        let lines = lines_of(&["Kind 1"]);
        let event_page = page("Event", &lines, ReviewPageAction::Next);

        assert_eq!(
            render_review_page(&event_page, 4, 4, ReviewDisplayLimits::default()),
            Err(ReviewDisplayError::PageIndexOutOfRange),
        );
        assert_eq!(
            render_review_page(&event_page, 0, 0, ReviewDisplayLimits::default()),
            Err(ReviewDisplayError::ZeroTotalPages),
        );
        assert_eq!(
            render_review_page(
                &page(
                    "This title is too long for a tiny trusted display",
                    &lines,
                    ReviewPageAction::Next,
                ),
                0,
                1,
                ReviewDisplayLimits {
                    max_title_chars: 12,
                    max_body_lines: 4,
                    max_line_chars: 32,
                    ..ReviewDisplayLimits::default()
                },
            ),
            Err(ReviewDisplayError::TitleTooLong),
        );
    }

    // Beyond the named C++ cases: the remaining validation/limit branches (zero
    // limits, capacity guard, empty title, empty body line, exact-fit body) and
    // the C++ throw strings.
    #[test]
    fn validation_branches_and_messages() {
        let lines = lines_of(&["Kind 1"]);
        let event_page = page("Event", &lines, ReviewPageAction::Next);

        let zeroed = ReviewDisplayLimits {
            max_body_lines: 0,
            ..ReviewDisplayLimits::default()
        };
        assert_eq!(
            render_review_page(&event_page, 0, 1, zeroed),
            Err(ReviewDisplayError::ZeroLimits),
        );
        let too_wide = ReviewDisplayLimits {
            max_line_chars: MAX_REVIEW_PAGE_LINE_CHARS + 1,
            ..ReviewDisplayLimits::default()
        };
        assert_eq!(
            render_review_page(&event_page, 0, 1, too_wide),
            Err(ReviewDisplayError::LimitsExceedCapacity),
        );
        let empty_title = page("", &lines, ReviewPageAction::Next);
        assert_eq!(
            render_review_page(&empty_title, 0, 1, ReviewDisplayLimits::default()),
            Err(ReviewDisplayError::EmptyTitle),
        );

        // An empty body line survives as one empty wrapped line (C++ wrap_line).
        let with_empty = lines_of(&["", "after"]);
        let frame = render_review_page(
            &page("Event", &with_empty, ReviewPageAction::Next),
            0,
            1,
            ReviewDisplayLimits::default(),
        )
        .unwrap();
        assert_eq!(body_strs(&frame), ["", "after"]);

        // A body that fills the budget exactly is kept without an ellipsis.
        let exact = lines_of(&["0123456789abcdef0123456789abcdef"]);
        let frame = render_review_page(
            &page("Content", &exact, ReviewPageAction::Next),
            0,
            1,
            ReviewDisplayLimits {
                max_title_chars: 12,
                max_body_lines: 2,
                max_line_chars: 16,
                ..ReviewDisplayLimits::default()
            },
        )
        .unwrap();
        assert_eq!(body_strs(&frame), ["0123456789abcdef", "0123456789abcdef"]);

        for (error, expected) in [
            (
                ReviewDisplayError::ZeroLimits,
                "review display limits must be non-zero",
            ),
            (
                ReviewDisplayError::ZeroTotalPages,
                "review display total pages must be non-zero",
            ),
            (
                ReviewDisplayError::PageIndexOutOfRange,
                "review display page index out of range",
            ),
            (
                ReviewDisplayError::EmptyTitle,
                "review display title must be non-empty",
            ),
            (
                ReviewDisplayError::TitleTooLong,
                "review display title exceeds configured width",
            ),
            (
                ReviewDisplayError::LimitsExceedCapacity,
                "review display limits exceed fixed frame capacity",
            ),
        ] {
            assert_eq!(error.message(), expected);
            assert_eq!(std::format!("{error}"), expected);
        }

        // FromStr round-trip for a stored line used by the replace path.
        let line = ReviewPageLine::from_str("abc").unwrap();
        let mut list = ReviewPageLines::new();
        list.try_push("xyz").unwrap();
        list.replace(0, &line);
        assert_eq!(list.as_slice()[0], "abc");
    }

    // Direct branch coverage for the truncation helper: the no-truncation
    // early return and the dots-only path for widths of at most three (the
    // C++ `truncate_for_display` branches the page-level tests do not reach).
    #[test]
    fn truncate_helper_direct_paths() {
        assert_eq!(truncate_for_display("abc", 5, false), "abc");
        assert_eq!(truncate_for_display("abcdef", 3, true), "...");
        assert_eq!(truncate_for_display("abcdef", 2, false), "..");
        assert_eq!(truncate_for_display("abcdefgh", 6, false), "abc...");
    }
}
