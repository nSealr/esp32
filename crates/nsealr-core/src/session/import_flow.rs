//! Session import flow — review-gated loading of a source into the keyring.
//!
//! Ported from the C++ reference `host_core` sources
//! `src/session_import_flow.cpp` and `include/nsealr/session_import_flow.hpp`
//! for behaviour parity (milestone M-T3.4b, on the M-T3.6 review-controls
//! substrate): the same secret-hiding [`build_session_import_review`] pages
//! driven through a [`ReviewControlSession`], the same per-step transcript, and
//! the same hard rule that the source is loaded into the session keyring
//! **only** at the moment of a terminal approval — rejection, early approval, a
//! non-terminal button stream, or an exhausted step budget all leave the
//! keyring untouched.
//!
//! The C++ threw `SessionImportFlowError` (and let the review-controls /
//! keyring exceptions propagate); this port returns
//! [`SessionImportFlowError`] values carrying those causes as typed variants.

use crate::review::controls::{ReviewButton, ReviewControlSession, ReviewControlsError};
use crate::session::import_review::{build_session_import_review, SessionImportReview};
use crate::session::keyring::{SessionKeySource, SessionKeyringError, StatelessSessionKeyring};

/// Default maximum button presses an import flow accepts before it fails
/// closed. Mirrors the C++ default argument (`max_button_steps = 32`).
pub const SESSION_IMPORT_DEFAULT_MAX_BUTTON_STEPS: usize = 32;

/// Maximum recorded transcript steps — the allocation-free stand-in for the C++
/// `std::vector<SessionImportTranscriptStep>`, bounded by the default step
/// budget.
pub const MAX_SESSION_IMPORT_TRANSCRIPT_STEPS: usize = SESSION_IMPORT_DEFAULT_MAX_BUTTON_STEPS;

/// Errors reported by the session import flow. Each variant wraps a distinct
/// C++ throw site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionImportFlowError {
    /// `max_button_steps` was zero. C++: "session import flow max button steps
    /// must be positive".
    ZeroMaxButtonSteps,
    /// The button budget was exhausted before a terminal decision. C++:
    /// "session import review exceeded max button steps".
    ExceededMaxButtonSteps,
    /// The button stream ended without a terminal decision. C++: "session
    /// import review did not reach approval or rejection".
    NoTerminalDecision,
    /// A review-controls error (approval before the last page / a button after
    /// a terminal decision). The C++ let the inner exception propagate.
    Controls(ReviewControlsError),
    /// The approved source failed keyring re-validation on load. The C++ let
    /// the inner `SessionKeyringError` propagate.
    Keyring(SessionKeyringError),
    /// More transcript steps than the fixed capacity holds. No C++ analogue
    /// (the C++ used an unbounded `std::vector`); unreachable while
    /// `max_button_steps <= MAX_SESSION_IMPORT_TRANSCRIPT_STEPS`.
    Capacity,
}

/// One recorded import-review step. Mirrors the C++
/// `SessionImportTranscriptStep`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionImportTranscriptStep {
    /// The page index the button acted on (C++ `page_index`).
    pub page_index: usize,
    /// The button pressed (C++ `button`).
    pub button: ReviewButton,
    /// The terminal decision, if this step produced one (C++ `decision`).
    pub decision: Option<bool>,
    /// Whether the source was loaded into the keyring at this step (C++
    /// `loaded`).
    pub loaded: bool,
}

/// A fixed-capacity import transcript — the allocation-free stand-in for the
/// C++ `std::vector<SessionImportTranscriptStep>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionImportTranscript {
    steps: [Option<SessionImportTranscriptStep>; MAX_SESSION_IMPORT_TRANSCRIPT_STEPS],
    len: usize,
}

impl SessionImportTranscript {
    /// Creates an empty transcript.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            steps: [const { None }; MAX_SESSION_IMPORT_TRANSCRIPT_STEPS],
            len: 0,
        }
    }

    /// Appends one step.
    fn try_push(
        &mut self,
        step: SessionImportTranscriptStep,
    ) -> Result<(), SessionImportFlowError> {
        if self.len >= MAX_SESSION_IMPORT_TRANSCRIPT_STEPS {
            return Err(SessionImportFlowError::Capacity);
        }
        self.steps[self.len] = Some(step);
        self.len += 1;
        Ok(())
    }

    /// Returns the recorded step at `index`.
    #[must_use]
    pub fn step(&self, index: usize) -> &SessionImportTranscriptStep {
        self.steps[index].as_ref().expect("index within len")
    }

    /// Returns the number of recorded steps (C++ `size()`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if no step was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for SessionImportTranscript {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of a session import flow. Mirrors the C++
/// `SessionImportFlowResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionImportFlowResult {
    /// The secret-hiding import review that was displayed (C++ `review`).
    pub review: SessionImportReview,
    /// Whether the import was approved (C++ `approved`).
    pub approved: bool,
    /// Whether the source was loaded into the keyring (C++ `loaded`).
    pub loaded: bool,
    /// The recorded review steps (C++ `transcript`).
    pub transcript: SessionImportTranscript,
}

/// Drives the secret-hiding import review to a terminal decision, loading the
/// source into `keyring` only on approval. Mirrors the C++
/// `run_session_import_flow`.
///
/// # Errors
///
/// See [`SessionImportFlowError`]; on any error the keyring is untouched.
pub fn run_session_import_flow(
    keyring: &mut StatelessSessionKeyring,
    source: &SessionKeySource,
    buttons: &[ReviewButton],
    max_button_steps: usize,
) -> Result<SessionImportFlowResult, SessionImportFlowError> {
    if max_button_steps == 0 {
        return Err(SessionImportFlowError::ZeroMaxButtonSteps);
    }

    let review = build_session_import_review(source);
    let mut controls =
        ReviewControlSession::new(review.pages.len()).map_err(SessionImportFlowError::Controls)?;
    let mut transcript = SessionImportTranscript::new();

    // The C++ kept an explicit step counter; the enumerate index is the same
    // pre-increment count, so the budget check is identical.
    for (step_count, &button) in buttons.iter().enumerate() {
        if step_count >= max_button_steps {
            return Err(SessionImportFlowError::ExceededMaxButtonSteps);
        }

        let page_index = controls.current_page_index();
        let decision = controls
            .handle_button(button)
            .map_err(SessionImportFlowError::Controls)?;
        let loaded = if decision == Some(true) {
            keyring
                .add_source(source)
                .map_err(SessionImportFlowError::Keyring)?;
            true
        } else {
            false
        };
        transcript.try_push(SessionImportTranscriptStep {
            page_index,
            button,
            decision,
            loaded,
        })?;

        if let Some(approved) = decision {
            return Ok(SessionImportFlowResult {
                review,
                approved,
                loaded,
                transcript,
            });
        }
    }

    Err(SessionImportFlowError::NoTerminalDecision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nip19;
    use crate::session::keyring::tests::{NSEC_TEST_KEY_1, SEEDQR_VECTOR_1_INDEXES};
    use crate::session::keyring::SessionKeySourceKind;

    // Port of the C++ `test_session_import_flow_requires_local_approval_before_loading_keyring`.
    // The expected review_id is copied from the READ-ONLY
    // specs/vectors/session-import-reviews/nsec-test-key-1.json (`review_id`).
    #[test]
    fn requires_local_approval_before_loading_keyring() {
        let mut pending_sources = StatelessSessionKeyring::new();
        let mut session_keyring = StatelessSessionKeyring::new();
        let secret = nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap();
        pending_sources
            .add_nsec("nsec test vector", &secret)
            .unwrap();

        let result = run_session_import_flow(
            &mut session_keyring,
            pending_sources.source_at(0).unwrap(),
            &[ReviewButton::Next, ReviewButton::Approve],
            SESSION_IMPORT_DEFAULT_MAX_BUTTON_STEPS,
        )
        .unwrap();

        assert!(result.approved);
        assert!(result.loaded);
        assert_eq!(result.review.review_id, "session-import-dbd1f8666039f02a");
        assert_eq!(result.transcript.len(), 2);
        assert_eq!(result.transcript.step(0).page_index, 0);
        assert_eq!(result.transcript.step(0).button, ReviewButton::Next);
        assert_eq!(result.transcript.step(0).decision, None);
        assert!(!result.transcript.step(0).loaded);
        assert_eq!(result.transcript.step(1).page_index, 1);
        assert_eq!(result.transcript.step(1).button, ReviewButton::Approve);
        assert_eq!(result.transcript.step(1).decision, Some(true));
        assert!(result.transcript.step(1).loaded);
        assert_eq!(session_keyring.len(), 1);
        assert_eq!(
            session_keyring.source_at(0).unwrap().label,
            "nsec test vector"
        );
        assert_eq!(
            session_keyring.source_at(0).unwrap().nsec_secret_key,
            secret
        );
    }

    // Port of the C++ `test_session_import_flow_rejection_does_not_load_keyring`.
    #[test]
    fn rejection_does_not_load_keyring() {
        let mut pending_sources = StatelessSessionKeyring::new();
        let mut session_keyring = StatelessSessionKeyring::new();
        pending_sources
            .add_bip39_seed("SeedQR vector 1", &SEEDQR_VECTOR_1_INDEXES)
            .unwrap();

        let result = run_session_import_flow(
            &mut session_keyring,
            pending_sources.source_at(0).unwrap(),
            &[ReviewButton::Reject],
            SESSION_IMPORT_DEFAULT_MAX_BUTTON_STEPS,
        )
        .unwrap();

        assert!(!result.approved);
        assert!(!result.loaded);
        assert_eq!(result.transcript.len(), 1);
        assert_eq!(result.transcript.step(0).decision, Some(false));
        assert!(!result.transcript.step(0).loaded);
        assert!(session_keyring.is_empty());
    }

    // Port of the C++ `test_session_import_flow_blocks_early_or_nonterminal_approval`.
    #[test]
    fn blocks_early_or_nonterminal_approval() {
        let mut pending_sources = StatelessSessionKeyring::new();
        let mut session_keyring = StatelessSessionKeyring::new();
        pending_sources
            .add_nsec(
                "nsec test vector",
                &nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap(),
            )
            .unwrap();

        assert_eq!(
            run_session_import_flow(
                &mut session_keyring,
                pending_sources.source_at(0).unwrap(),
                &[ReviewButton::Approve],
                SESSION_IMPORT_DEFAULT_MAX_BUTTON_STEPS,
            ),
            Err(SessionImportFlowError::Controls(
                ReviewControlsError::ApprovalRequiresFullTraversal,
            )),
        );
        assert!(session_keyring.is_empty());

        assert_eq!(
            run_session_import_flow(
                &mut session_keyring,
                pending_sources.source_at(0).unwrap(),
                &[ReviewButton::Next],
                SESSION_IMPORT_DEFAULT_MAX_BUTTON_STEPS,
            ),
            Err(SessionImportFlowError::NoTerminalDecision),
        );
        assert!(session_keyring.is_empty());

        assert_eq!(
            run_session_import_flow(
                &mut session_keyring,
                pending_sources.source_at(0).unwrap(),
                &[ReviewButton::Next, ReviewButton::Back],
                1,
            ),
            Err(SessionImportFlowError::ExceededMaxButtonSteps),
        );
        assert!(session_keyring.is_empty());
    }

    // Beyond the named C++ cases: the zero-step guard, the keyring-error path
    // (a full session keyring rejects the approved load), and the bounded
    // transcript container plumbing (the C++ used an unbounded std::vector).
    #[test]
    fn zero_steps_full_keyring_and_transcript_bounds() {
        let mut pending_sources = StatelessSessionKeyring::new();
        let secret = nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap();
        pending_sources
            .add_nsec("nsec test vector", &secret)
            .unwrap();
        let source = pending_sources.source_at(0).unwrap();

        let mut session_keyring = StatelessSessionKeyring::new();
        assert_eq!(
            run_session_import_flow(&mut session_keyring, source, &[], 0),
            Err(SessionImportFlowError::ZeroMaxButtonSteps),
        );

        // Fill the target keyring; the approved load then fails closed with the
        // keyring's own error and the flow reports it.
        let mut full_keyring = StatelessSessionKeyring::new();
        for index in 0..crate::session::keyring::MAX_STATELESS_SESSION_KEY_SOURCES {
            let mut label = crate::session::keyring::SessionKeySourceLabel::new();
            label.try_push_str("filler ").unwrap();
            label.try_push_usize(index).unwrap();
            full_keyring.add_nsec(label.as_str(), &secret).unwrap();
        }
        assert_eq!(
            run_session_import_flow(
                &mut full_keyring,
                source,
                &[ReviewButton::Next, ReviewButton::Approve],
                SESSION_IMPORT_DEFAULT_MAX_BUTTON_STEPS,
            ),
            Err(SessionImportFlowError::Keyring(
                SessionKeyringError::KeyringFull,
            )),
        );
        assert_eq!(source.kind, SessionKeySourceKind::NsecSecretKey);

        let step = SessionImportTranscriptStep {
            page_index: 0,
            button: ReviewButton::Next,
            decision: None,
            loaded: false,
        };
        let mut transcript = SessionImportTranscript::new();
        assert!(transcript.is_empty());
        assert_eq!(
            SessionImportTranscript::default(),
            SessionImportTranscript::new()
        );
        for _ in 0..MAX_SESSION_IMPORT_TRANSCRIPT_STEPS {
            transcript.try_push(step).unwrap();
        }
        assert!(!transcript.is_empty());
        assert_eq!(transcript.len(), MAX_SESSION_IMPORT_TRANSCRIPT_STEPS);
        assert_eq!(transcript.step(0).button, ReviewButton::Next);
        assert_eq!(
            transcript.try_push(step),
            Err(SessionImportFlowError::Capacity)
        );
        assert_eq!(transcript.clone(), transcript);
    }
}
