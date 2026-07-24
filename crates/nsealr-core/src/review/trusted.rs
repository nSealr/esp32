//! Trusted review session — binds display, navigation, and approval.
//!
//! Ported from the C++ reference `host_core` sources `src/trusted_review.cpp` +
//! `include/nsealr/trusted_review.hpp` for behaviour parity (the shared data
//! model already lives in [`crate::review::types`]): the same approval-gate
//! binding of `(request_id, approval_digest)`, the same flat navigation via
//! [`ReviewControlSession`] when no page carries a logical page id, and the
//! same two-axis logical navigation (Next cycles logical sections, Back scrolls
//! within a multi-window section, `"Next/Scroll"` hint) when logical ids are
//! present.
//!
//! The C++ threw `std::invalid_argument`/`std::logic_error`; this port returns
//! [`TrustedReviewError`] values carrying the exact C++ messages.

use crate::policy::approval_gate::{ApprovalDecision, ApprovalGate};
use crate::review::controls::{ReviewButton, ReviewControlSession, ReviewControlsError};
use crate::review::display::{
    render_review_page, ReviewDisplayError, ReviewDisplayFrame, ReviewDisplayLimits, ReviewPage,
};
use crate::review::types::{
    ReviewPageAction, TrustedReviewPage, TrustedReviewRequest, MAX_TRUSTED_REVIEW_PAGES,
};
use core::fmt;

/// One run of consecutive pages sharing a logical page id. Mirrors the C++
/// `TrustedReviewLogicalPageRange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedReviewLogicalPageRange {
    /// Flat index of the first page in the range.
    pub start_index: usize,
    /// Number of consecutive pages in the range.
    pub page_count: usize,
}

/// Errors reported by [`TrustedReviewSession`]. Each variant corresponds to a
/// distinct C++ throw site; [`Self::message`] returns the exact C++ text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedReviewError {
    /// The request id was empty. C++ `std::invalid_argument`.
    EmptyRequestId,
    /// The approval digest was empty. C++ `std::invalid_argument`.
    EmptyApprovalDigest,
    /// A flat-navigation controls error (zero pages at construction, terminal
    /// decision, approval before the last page). C++ threw the inner exception
    /// directly.
    Controls(ReviewControlsError),
    /// A button arrived after a terminal decision (logical navigation). C++
    /// `std::logic_error` (same text as the controls variant).
    AlreadyTerminal,
    /// Approve was pressed while the active page is not the decision page
    /// (logical navigation). C++ `std::logic_error`.
    ApprovalRequiresDecisionPage,
}

impl TrustedReviewError {
    /// The exact message the C++ exception carried.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::EmptyRequestId => "trusted review request id must be non-empty",
            Self::EmptyApprovalDigest => "trusted review approval digest must be non-empty",
            Self::Controls(inner) => inner.message(),
            Self::AlreadyTerminal => "review decision is already terminal",
            Self::ApprovalRequiresDecisionPage => "approval requires decision review page",
        }
    }
}

impl fmt::Display for TrustedReviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// A fixed-capacity list of logical page ranges (one per page worst case).
#[derive(Debug, Clone, PartialEq, Eq)]
struct LogicalPageRanges {
    ranges: [TrustedReviewLogicalPageRange; MAX_TRUSTED_REVIEW_PAGES],
    len: usize,
}

impl LogicalPageRanges {
    const fn new() -> Self {
        Self {
            ranges: [TrustedReviewLogicalPageRange {
                start_index: 0,
                page_count: 0,
            }; MAX_TRUSTED_REVIEW_PAGES],
            len: 0,
        }
    }

    fn as_slice(&self) -> &[TrustedReviewLogicalPageRange] {
        &self.ranges[..self.len]
    }
}

/// Builds the logical page ranges (empty when no page carries a logical id).
/// Mirrors the C++ `logical_page_ranges_for`: an empty-id page takes a unique
/// synthetic id (`"__page_" + index`), so it always starts a new range and
/// always ends the previous one.
fn logical_page_ranges_for(pages: &[TrustedReviewPage]) -> LogicalPageRanges {
    let mut out = LogicalPageRanges::new();
    if !pages.iter().any(|page| !page.logical_page_id.is_empty()) {
        return out;
    }
    for (index, page) in pages.iter().enumerate() {
        let starts_new_range = index == 0
            || page.logical_page_id.is_empty()
            || pages[index - 1].logical_page_id.is_empty()
            || page.logical_page_id != pages[index - 1].logical_page_id;
        if starts_new_range {
            out.ranges[out.len] = TrustedReviewLogicalPageRange {
                start_index: index,
                page_count: 1,
            };
            out.len += 1;
        } else {
            out.ranges[out.len - 1].page_count += 1;
        }
    }
    out
}

/// A trusted review session over a [`TrustedReviewRequest`]. Mirrors the C++
/// `TrustedReviewSession` method for method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedReviewSession {
    request: TrustedReviewRequest,
    controls: ReviewControlSession,
    approval_gate: ApprovalGate,
    limits: ReviewDisplayLimits,
    logical_page_ranges: LogicalPageRanges,
    current_logical_page_index: usize,
    current_scroll_page_offset: usize,
}

impl TrustedReviewSession {
    /// Creates a session, binding the approval gate to the request's
    /// `(request_id, approval_digest)` pair. Mirrors the C++ constructor.
    ///
    /// # Errors
    ///
    /// [`TrustedReviewError::EmptyRequestId`] /
    /// [`TrustedReviewError::EmptyApprovalDigest`] on missing metadata, or
    /// [`TrustedReviewError::Controls`] ([`ReviewControlsError::ZeroPages`])
    /// on an empty page list. The C++ constructed controls before validating
    /// metadata, so a zero-page request reports the controls error first —
    /// same order here.
    pub fn new(
        request: TrustedReviewRequest,
        limits: ReviewDisplayLimits,
    ) -> Result<Self, TrustedReviewError> {
        let controls =
            ReviewControlSession::new(request.pages.len()).map_err(TrustedReviewError::Controls)?;
        if request.request_id.is_empty() {
            return Err(TrustedReviewError::EmptyRequestId);
        }
        if request.approval_digest.is_empty() {
            return Err(TrustedReviewError::EmptyApprovalDigest);
        }
        let logical_page_ranges = logical_page_ranges_for(request.pages.as_slice());
        let mut approval_gate = ApprovalGate::new();
        approval_gate.begin_review(
            request.request_id.as_str(),
            request.approval_digest.as_str(),
        );
        Ok(Self {
            request,
            controls,
            approval_gate,
            limits,
            logical_page_ranges,
            current_logical_page_index: 0,
            current_scroll_page_offset: 0,
        })
    }

    /// Renders the active page. Mirrors the C++ `current_frame`, including the
    /// `"Next/Scroll"` hint override on multi-window logical sections.
    ///
    /// # Errors
    ///
    /// Propagates [`ReviewDisplayError`] from the renderer.
    pub fn current_frame(&self) -> Result<ReviewDisplayFrame, ReviewDisplayError> {
        let page_index = self.active_flat_page_index();
        let page = &self.request.pages.as_slice()[page_index];
        let mut frame = render_review_page(
            &ReviewPage {
                title: page.title.as_str(),
                lines: page.lines.as_slice(),
                action: page.action,
                page_indicator: page.page_indicator.as_str(),
                body_line_styles: page.body_line_styles.as_slice(),
            },
            page_index,
            self.request.pages.len(),
            self.limits,
        )?;
        if self.using_logical_navigation()
            && page.action == ReviewPageAction::Next
            && self.logical_page_ranges.as_slice()[self.current_logical_page_index].page_count > 1
        {
            frame.action_hint = "Next/Scroll"
                .parse()
                .expect("hint within documented capacity");
        }
        Ok(frame)
    }

    /// Returns `true` iff the bound pair was approved. Mirrors the C++
    /// `can_sign`.
    #[must_use]
    pub fn can_sign(&self) -> bool {
        self.approval_gate.can_sign(
            self.request.request_id.as_str(),
            self.request.approval_digest.as_str(),
        )
    }

    /// Returns the recorded decision. Mirrors the C++ `decision`.
    #[must_use]
    pub fn decision(&self) -> ApprovalDecision {
        self.approval_gate.decision()
    }

    /// Returns the active flat page index. Mirrors the C++
    /// `current_page_index`.
    #[must_use]
    pub fn current_page_index(&self) -> usize {
        self.active_flat_page_index()
    }

    /// Handles one button press. Mirrors the C++ `handle_button` (which threw
    /// where this returns `Err`): flat navigation delegates to the controls;
    /// logical navigation cycles sections on Next, scrolls windows on Back,
    /// rejects from anywhere, and approves only on the decision page.
    ///
    /// # Errors
    ///
    /// See [`TrustedReviewError`].
    pub fn handle_button(
        &mut self,
        button: ReviewButton,
    ) -> Result<Option<bool>, TrustedReviewError> {
        if self.using_logical_navigation() {
            if self.terminal_decision_recorded() {
                return Err(TrustedReviewError::AlreadyTerminal);
            }

            if button == ReviewButton::Reject {
                self.approval_gate.reject(self.request.request_id.as_str());
                return Ok(Some(false));
            }

            if button == ReviewButton::Next {
                self.current_logical_page_index =
                    (self.current_logical_page_index + 1) % self.logical_page_ranges.len;
                self.current_scroll_page_offset = 0;
                return Ok(None);
            }

            if button == ReviewButton::Back {
                let range = self.logical_page_ranges.as_slice()[self.current_logical_page_index];
                if range.page_count > 1 {
                    self.current_scroll_page_offset =
                        (self.current_scroll_page_offset + 1) % range.page_count;
                }
                return Ok(None);
            }

            let active_page = &self.request.pages.as_slice()[self.active_flat_page_index()];
            if active_page.action != ReviewPageAction::ApproveOrReject {
                return Err(TrustedReviewError::ApprovalRequiresDecisionPage);
            }
            self.approval_gate.approve(
                self.request.request_id.as_str(),
                self.request.approval_digest.as_str(),
            );
            return Ok(Some(true));
        }

        let decision = self
            .controls
            .handle_button(button)
            .map_err(TrustedReviewError::Controls)?;
        let Some(decision) = decision else {
            return Ok(None);
        };
        if decision {
            self.approval_gate.approve(
                self.request.request_id.as_str(),
                self.request.approval_digest.as_str(),
            );
        } else {
            self.approval_gate.reject(self.request.request_id.as_str());
        }
        Ok(Some(decision))
    }

    /// Mirrors the C++ `using_logical_navigation`.
    fn using_logical_navigation(&self) -> bool {
        self.logical_page_ranges.len != 0
    }

    /// Mirrors the C++ `active_flat_page_index`.
    fn active_flat_page_index(&self) -> usize {
        if !self.using_logical_navigation() {
            return self.controls.current_page_index();
        }
        let range = self.logical_page_ranges.as_slice()[self.current_logical_page_index];
        range.start_index + self.current_scroll_page_offset
    }

    /// Mirrors the C++ `terminal_decision_recorded`.
    fn terminal_decision_recorded(&self) -> bool {
        matches!(
            self.approval_gate.decision(),
            ApprovalDecision::Approved | ApprovalDecision::Rejected,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::test_fixtures::{
        basic_trusted_review_request, frame_lines_contain, tagged_trusted_review_request,
    };

    // Port of the C++ `test_trusted_review_session_binds_display_navigation_and_approval`.
    #[test]
    fn binds_display_navigation_and_approval() {
        let mut session = TrustedReviewSession::new(
            basic_trusted_review_request(),
            ReviewDisplayLimits::default(),
        )
        .unwrap();

        let first_frame = session.current_frame().unwrap();
        assert_eq!(first_frame.title, "Event");
        assert_eq!(first_frame.page_indicator, "Page 1/4");
        assert_eq!(first_frame.action_hint, "Next");
        assert!(!session.can_sign());

        assert_eq!(
            session.handle_button(ReviewButton::Approve),
            Err(TrustedReviewError::Controls(
                ReviewControlsError::ApprovalRequiresFullTraversal,
            )),
        );

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));

        let decision_frame = session.current_frame().unwrap();
        assert_eq!(decision_frame.title, "Decision");
        assert_eq!(decision_frame.page_indicator, "Page 4/4");
        assert_eq!(decision_frame.action_hint, "Approve / Reject");
        assert!(!session.can_sign());

        let approval = session.handle_button(ReviewButton::Approve);
        assert_eq!(approval, Ok(Some(true)));
        assert!(session.can_sign());
    }

    // Port of the C++ `test_trusted_review_session_keeps_rejection_terminal`.
    #[test]
    fn keeps_rejection_terminal() {
        let mut session = TrustedReviewSession::new(
            tagged_trusted_review_request(),
            ReviewDisplayLimits::default(),
        )
        .unwrap();

        let first_frame = session.current_frame().unwrap();
        assert_eq!(first_frame.title, "Event");
        assert_eq!(first_frame.page_indicator, "Page 1/4");

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        let tags_frame = session.current_frame().unwrap();
        assert_eq!(tags_frame.title, "Tags");
        assert!(frame_lines_contain(&tags_frame, "Tag 1/2"));
        assert!(frame_lines_contain(&tags_frame, "p"));

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        let decision_frame = session.current_frame().unwrap();
        assert_eq!(decision_frame.title, "Decision");
        assert_eq!(decision_frame.body_lines.len(), 1);
        assert_eq!(
            decision_frame.body_lines.as_slice()[0],
            "Approve signing only if all pages match.",
        );

        let rejection = session.handle_button(ReviewButton::Reject);
        assert_eq!(rejection, Ok(Some(false)));
        assert!(!session.can_sign());
        assert_eq!(session.decision(), ApprovalDecision::Rejected);
    }

    // Port of the C++ `test_trusted_review_session_allows_backward_review_before_approval`.
    #[test]
    fn allows_backward_review_before_approval() {
        let mut session = TrustedReviewSession::new(
            basic_trusted_review_request(),
            ReviewDisplayLimits::default(),
        )
        .unwrap();

        assert_eq!(session.current_frame().unwrap().title, "Event");
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Content");
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Tags");
        assert_eq!(session.handle_button(ReviewButton::Back), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Content");
        assert!(!session.can_sign());

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Decision");

        let approval = session.handle_button(ReviewButton::Approve);
        assert_eq!(approval, Ok(Some(true)));
        assert!(session.can_sign());
    }

    // Beyond the named C++ cases: constructor validation branches and the C++
    // throw strings (the logical-navigation branches are exercised by the QR
    // display-review tests, which build logical page ids).
    #[test]
    fn constructor_validation_and_messages() {
        let mut no_id = basic_trusted_review_request();
        no_id.request_id = crate::review::types::TrustedReviewRequestId::new();
        assert_eq!(
            TrustedReviewSession::new(no_id, ReviewDisplayLimits::default()),
            Err(TrustedReviewError::EmptyRequestId),
        );

        let mut no_digest = basic_trusted_review_request();
        no_digest.approval_digest = crate::review::types::TrustedReviewApprovalDigest::new();
        assert_eq!(
            TrustedReviewSession::new(no_digest, ReviewDisplayLimits::default()),
            Err(TrustedReviewError::EmptyApprovalDigest),
        );

        let mut no_pages = basic_trusted_review_request();
        no_pages.pages = crate::review::types::ReviewPageList::new();
        assert_eq!(
            TrustedReviewSession::new(no_pages, ReviewDisplayLimits::default()),
            Err(TrustedReviewError::Controls(ReviewControlsError::ZeroPages)),
        );

        for (error, expected) in [
            (
                TrustedReviewError::EmptyRequestId,
                "trusted review request id must be non-empty",
            ),
            (
                TrustedReviewError::EmptyApprovalDigest,
                "trusted review approval digest must be non-empty",
            ),
            (
                TrustedReviewError::AlreadyTerminal,
                "review decision is already terminal",
            ),
            (
                TrustedReviewError::ApprovalRequiresDecisionPage,
                "approval requires decision review page",
            ),
            (
                TrustedReviewError::Controls(ReviewControlsError::AlreadyTerminal),
                "review decision is already terminal",
            ),
        ] {
            assert_eq!(error.message(), expected);
            assert_eq!(std::format!("{error}"), expected);
        }
    }

    // Beyond the named C++ cases: the flat current_page_index accessor, the
    // render-error propagation from current_frame, and the logical-navigation
    // terminal lock (the C++ threw logic_error on any button after a
    // decision).
    #[test]
    fn accessor_render_error_and_logical_terminal_lock() {
        let mut session = TrustedReviewSession::new(
            basic_trusted_review_request(),
            ReviewDisplayLimits::default(),
        )
        .unwrap();
        assert_eq!(session.current_page_index(), 0);
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_page_index(), 1);

        // A page title wider than the limits propagates the render error.
        let long_title_request = crate::review::test_fixtures::trusted_review_request(
            "req-render-error",
            "a09ddd564e439fdd4756da6863156eddcfc50c295af453af1c78c35986c303a5",
            &[(
                "A title wider than 24 chars",
                &["line"],
                crate::review::types::ReviewPageAction::ApproveOrReject,
            )],
        );
        let session =
            TrustedReviewSession::new(long_title_request, ReviewDisplayLimits::default()).unwrap();
        assert_eq!(
            session.current_frame(),
            Err(ReviewDisplayError::TitleTooLong),
        );

        // Logical navigation locks after a terminal decision.
        let mut logical_request = basic_trusted_review_request();
        let mut pages = crate::review::types::ReviewPageList::new();
        for page in logical_request.pages.as_slice() {
            let mut with_id = page.clone();
            with_id.logical_page_id = with_id.title.as_str().parse().unwrap();
            pages.try_push(with_id).unwrap();
        }
        logical_request.pages = pages;
        let mut session =
            TrustedReviewSession::new(logical_request, ReviewDisplayLimits::default()).unwrap();
        assert_eq!(session.handle_button(ReviewButton::Reject), Ok(Some(false)));
        assert_eq!(
            session.handle_button(ReviewButton::Next),
            Err(TrustedReviewError::AlreadyTerminal),
        );
    }
}
