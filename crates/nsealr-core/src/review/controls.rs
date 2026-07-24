//! Physical review controls — page traversal before approval.
//!
//! Ported from the C++ reference `host_core` sources `src/review_controls.cpp` +
//! `include/nsealr/review_controls.hpp` for behaviour parity: the same
//! [`ReviewButton`] set, the same flat page cursor (Next saturates at the last
//! page, Back at the first), rejection allowed from any page, approval only
//! from the last page, and a terminal decision that locks the session.
//!
//! The C++ threw `std::invalid_argument`/`std::logic_error`; this port returns
//! [`ReviewControlsError`] values carrying the exact C++ messages.

use core::fmt;

/// A physical review button press. Mirrors the C++ `ReviewButton`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewButton {
    /// Advance to the next page.
    Next,
    /// Go back one page.
    Back,
    /// Approve (only from the last page).
    Approve,
    /// Reject (from any page).
    Reject,
}

/// Errors reported by [`ReviewControlSession`]. Each variant corresponds to a
/// distinct C++ throw site; [`Self::message`] returns the exact C++ text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewControlsError {
    /// The session was created with zero pages. C++ `std::invalid_argument`.
    ZeroPages,
    /// A button arrived after a terminal decision. C++ `std::logic_error`.
    AlreadyTerminal,
    /// Approve was pressed before the last page. C++ `std::logic_error`.
    ApprovalRequiresFullTraversal,
}

impl ReviewControlsError {
    /// The exact message the C++ exception carried.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::ZeroPages => "review control session requires at least one page",
            Self::AlreadyTerminal => "review decision is already terminal",
            Self::ApprovalRequiresFullTraversal => "approval requires viewing every review page",
        }
    }
}

impl fmt::Display for ReviewControlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// A flat page-traversal session. Mirrors the C++ `ReviewControlSession` method
/// for method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewControlSession {
    page_count: usize,
    current_page_index: usize,
    approved: bool,
    rejected: bool,
}

impl ReviewControlSession {
    /// Creates a session over `page_count` pages. Mirrors the C++ constructor.
    ///
    /// # Errors
    ///
    /// [`ReviewControlsError::ZeroPages`] if `page_count` is zero.
    pub fn new(page_count: usize) -> Result<Self, ReviewControlsError> {
        if page_count == 0 {
            return Err(ReviewControlsError::ZeroPages);
        }
        Ok(Self {
            page_count,
            current_page_index: 0,
            approved: false,
            rejected: false,
        })
    }

    /// Returns the current page index. Mirrors the C++ `current_page_index`.
    #[must_use]
    pub fn current_page_index(&self) -> usize {
        self.current_page_index
    }

    /// Returns `true` iff the cursor sits on the last page. Mirrors the C++
    /// `can_approve`.
    #[must_use]
    pub fn can_approve(&self) -> bool {
        self.current_page_index == self.page_count - 1
    }

    /// Returns `true` once the session was approved. Mirrors the C++ `approved`.
    #[must_use]
    pub fn approved(&self) -> bool {
        self.approved
    }

    /// Returns `true` once the session was rejected. Mirrors the C++ `rejected`.
    #[must_use]
    pub fn rejected(&self) -> bool {
        self.rejected
    }

    /// Handles one button press. Returns `Ok(None)` for navigation,
    /// `Ok(Some(true))` on approval, `Ok(Some(false))` on rejection. Mirrors
    /// the C++ `handle_button` (which threw where this returns `Err`).
    ///
    /// # Errors
    ///
    /// [`ReviewControlsError::AlreadyTerminal`] after a terminal decision;
    /// [`ReviewControlsError::ApprovalRequiresFullTraversal`] if Approve is
    /// pressed before the last page.
    pub fn handle_button(
        &mut self,
        button: ReviewButton,
    ) -> Result<Option<bool>, ReviewControlsError> {
        if self.approved || self.rejected {
            return Err(ReviewControlsError::AlreadyTerminal);
        }

        match button {
            ReviewButton::Next => {
                if self.current_page_index + 1 < self.page_count {
                    self.current_page_index += 1;
                }
                Ok(None)
            }
            ReviewButton::Back => {
                if self.current_page_index > 0 {
                    self.current_page_index -= 1;
                }
                Ok(None)
            }
            ReviewButton::Reject => {
                self.rejected = true;
                Ok(Some(false))
            }
            ReviewButton::Approve => {
                if !self.can_approve() {
                    return Err(ReviewControlsError::ApprovalRequiresFullTraversal);
                }
                self.approved = true;
                Ok(Some(true))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Port of the C++ `test_review_controls_require_page_traversal_before_approval`.
    #[test]
    fn require_page_traversal_before_approval() {
        let mut session = ReviewControlSession::new(4).unwrap();

        assert_eq!(session.current_page_index(), 0);
        assert!(!session.can_approve());
        assert_eq!(
            session.handle_button(ReviewButton::Approve),
            Err(ReviewControlsError::ApprovalRequiresFullTraversal),
        );

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_page_index(), 1);
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_page_index(), 2);
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_page_index(), 3);
        assert!(session.can_approve());

        let result = session.handle_button(ReviewButton::Approve);
        assert_eq!(result, Ok(Some(true)));
        assert!(session.approved());
        assert!(!session.rejected());
    }

    // Port of the C++
    // `test_review_controls_allow_backward_navigation_before_terminal_decision`.
    #[test]
    fn allow_backward_navigation_before_terminal_decision() {
        let mut session = ReviewControlSession::new(4).unwrap();

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_page_index(), 2);
        assert!(!session.can_approve());

        assert_eq!(session.handle_button(ReviewButton::Back), Ok(None));
        assert_eq!(session.current_page_index(), 1);
        assert!(!session.can_approve());

        assert_eq!(session.handle_button(ReviewButton::Back), Ok(None));
        assert_eq!(session.current_page_index(), 0);
        assert_eq!(session.handle_button(ReviewButton::Back), Ok(None));
        assert_eq!(session.current_page_index(), 0);

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_page_index(), 3);
        assert!(session.can_approve());
    }

    // Port of the C++ `test_review_controls_allow_early_rejection`.
    #[test]
    fn allow_early_rejection() {
        let mut session = ReviewControlSession::new(4).unwrap();

        let result = session.handle_button(ReviewButton::Reject);

        assert_eq!(result, Ok(Some(false)));
        assert!(session.rejected());
        assert!(!session.approved());
    }

    // Port of the C++ `test_review_controls_are_terminal_after_decision`.
    #[test]
    fn are_terminal_after_decision() {
        let mut rejected_session = ReviewControlSession::new(2).unwrap();
        assert_eq!(
            rejected_session.handle_button(ReviewButton::Reject),
            Ok(Some(false)),
        );
        assert_eq!(
            rejected_session.handle_button(ReviewButton::Next),
            Err(ReviewControlsError::AlreadyTerminal),
        );

        let mut approved_session = ReviewControlSession::new(1).unwrap();
        let approved = approved_session.handle_button(ReviewButton::Approve);
        assert_eq!(approved, Ok(Some(true)));
        assert_eq!(
            approved_session.handle_button(ReviewButton::Approve),
            Err(ReviewControlsError::AlreadyTerminal),
        );
    }

    // Constructor rejection + error messages (the C++ throw strings).
    #[test]
    fn zero_pages_rejected_and_messages_match_cpp() {
        assert_eq!(
            ReviewControlSession::new(0),
            Err(ReviewControlsError::ZeroPages),
        );
        for (error, expected) in [
            (
                ReviewControlsError::ZeroPages,
                "review control session requires at least one page",
            ),
            (
                ReviewControlsError::AlreadyTerminal,
                "review decision is already terminal",
            ),
            (
                ReviewControlsError::ApprovalRequiresFullTraversal,
                "approval requires viewing every review page",
            ),
        ] {
            assert_eq!(error.message(), expected);
            assert_eq!(std::format!("{error}"), expected);
        }
    }
}
