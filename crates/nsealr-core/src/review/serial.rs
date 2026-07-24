//! Serial sign-event review — request JSON to trusted review decision.
//!
//! Ported from the C++ reference `host_core` sources `src/serial_review.cpp` +
//! `include/nsealr/serial_review.hpp` for behaviour parity: the same
//! request-JSON parsing through the shared signing-request parser, the same
//! summary-page trusted-review request builder, the same display-review
//! session, and the same interactive IO flow driver.
//!
//! The C++ default-identity overloads map to passing
//! [`SignerIdentity::development_fixture`] explicitly. The transcript
//! step/list types are shared with the QR flow ([`QrReviewTranscriptStep`] /
//! [`QrReviewTranscript`]) — the C++ declared structurally identical
//! `SerialReviewTranscriptStep`/vector types; this port re-uses one definition
//! and exposes the serial names as aliases.

use crate::policy::approval_gate::ApprovalDecision;
use crate::qr::envelope::{parse_qr_signing_request, QrEnvelopeError};
use crate::review::controls::ReviewButton;
use crate::review::display::{ReviewDisplayError, ReviewDisplayFrame, ReviewDisplayLimits};
use crate::review::qr::{
    build_qr_display_review_request, build_qr_trusted_review_request, QrReviewError,
};
use crate::review::qr_flow::{QrReviewTranscript, QrReviewTranscriptStep};
use crate::review::signer_identity::SignerIdentity;
use crate::review::trusted::{TrustedReviewError, TrustedReviewSession};
use crate::review::types::{
    TrustedReviewApprovalDigest, TrustedReviewRequest, TrustedReviewRequestId,
};
use core::fmt;

/// One recorded serial review step (shared with the QR flow; the C++
/// `SerialReviewTranscriptStep` was structurally identical).
pub type SerialReviewTranscriptStep = QrReviewTranscriptStep;

/// A bounded serial review transcript (shared with the QR flow).
pub type SerialReviewTranscript = QrReviewTranscript;

/// Errors reported by the serial review flow. [`Self::message`] returns the
/// C++ exception text where one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialReviewError {
    /// A signing-request parse failure. C++ `QrEnvelopeError`.
    Envelope(QrEnvelopeError),
    /// A review-build failure (identity, limits, capacity).
    Review(QrReviewError),
    /// A trusted-review session failure.
    TrustedReview(TrustedReviewError),
    /// A display-render failure.
    Display(ReviewDisplayError),
    /// `max_steps` was zero. C++ `std::invalid_argument`.
    ZeroMaxSteps,
    /// The IO flow ran out of steps without a terminal decision. C++
    /// `std::logic_error`.
    NoTerminalDecision,
    /// The transcript exceeded its fixed capacity. No C++ analogue.
    Capacity,
}

impl SerialReviewError {
    /// The exact C++ exception message where one exists.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Envelope(_) => "serial signing request rejected",
            Self::Review(inner) => inner.message(),
            Self::TrustedReview(inner) => inner.message(),
            Self::Display(inner) => inner.message(),
            Self::ZeroMaxSteps => "serial review IO max steps must be non-zero",
            Self::NoTerminalDecision => "serial review IO did not reach a terminal decision",
            Self::Capacity => "serial review flow exceeds fixed capacity",
        }
    }
}

impl fmt::Display for SerialReviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// Builds the summary trusted-review request from serial request JSON. Mirrors
/// the C++ `build_serial_sign_event_trusted_review_request`.
///
/// # Errors
///
/// See [`SerialReviewError`].
pub fn build_serial_sign_event_trusted_review_request(
    request_json: &str,
    identity: SignerIdentity<'_>,
) -> Result<TrustedReviewRequest, SerialReviewError> {
    let request =
        parse_qr_signing_request(request_json.as_bytes()).map_err(SerialReviewError::Envelope)?;
    build_qr_trusted_review_request(&request, identity).map_err(SerialReviewError::Review)
}

/// Builds the display trusted-review request from serial request JSON. Mirrors
/// the C++ `build_serial_display_review_request` helper.
fn build_serial_display_review_request(
    request_json: &str,
    identity: SignerIdentity<'_>,
    limits: ReviewDisplayLimits,
) -> Result<TrustedReviewRequest, SerialReviewError> {
    let request =
        parse_qr_signing_request(request_json.as_bytes()).map_err(SerialReviewError::Envelope)?;
    build_qr_display_review_request(&request, identity, limits).map_err(SerialReviewError::Review)
}

/// Begins the trusted review session over the display review request. Mirrors
/// the C++ `begin_serial_sign_event_trusted_review`.
///
/// # Errors
///
/// See [`SerialReviewError`].
pub fn begin_serial_sign_event_trusted_review(
    request_json: &str,
    identity: SignerIdentity<'_>,
    limits: ReviewDisplayLimits,
) -> Result<TrustedReviewSession, SerialReviewError> {
    let review_request = build_serial_display_review_request(request_json, identity, limits)?;
    TrustedReviewSession::new(review_request, limits).map_err(SerialReviewError::TrustedReview)
}

/// A serial review flow: request JSON to review session. Mirrors the C++
/// `SerialReviewFlow` method for method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialReviewFlow {
    request_id: TrustedReviewRequestId,
    approval_digest: TrustedReviewApprovalDigest,
    session: TrustedReviewSession,
}

impl SerialReviewFlow {
    /// Builds the flow from serial request JSON. Mirrors the C++ constructor.
    ///
    /// # Errors
    ///
    /// See [`SerialReviewError`].
    pub fn new(
        request_json: &str,
        identity: SignerIdentity<'_>,
        limits: ReviewDisplayLimits,
    ) -> Result<Self, SerialReviewError> {
        let review_request = build_serial_display_review_request(request_json, identity, limits)?;
        let request_id = review_request.request_id.clone();
        let approval_digest = review_request.approval_digest.clone();
        let session = TrustedReviewSession::new(review_request, limits)
            .map_err(SerialReviewError::TrustedReview)?;
        Ok(Self {
            request_id,
            approval_digest,
            session,
        })
    }

    /// The reviewed request id. Mirrors the C++ `request_id`.
    #[must_use]
    pub fn request_id(&self) -> &str {
        self.request_id.as_str()
    }

    /// The bound approval digest. Mirrors the C++ `approval_digest`.
    #[must_use]
    pub fn approval_digest(&self) -> &str {
        self.approval_digest.as_str()
    }

    /// Renders the active review frame. Mirrors the C++ `current_frame`.
    ///
    /// # Errors
    ///
    /// Propagates the display renderer's [`ReviewDisplayError`].
    pub fn current_frame(&self) -> Result<ReviewDisplayFrame, ReviewDisplayError> {
        self.session.current_frame()
    }

    /// The recorded decision. Mirrors the C++ `decision`.
    #[must_use]
    pub fn decision(&self) -> ApprovalDecision {
        self.session.decision()
    }

    /// Whether the review was approved for signing. Mirrors the C++
    /// `approved_for_signing`.
    #[must_use]
    pub fn approved_for_signing(&self) -> bool {
        self.session.can_sign()
    }

    /// Handles one button press. Mirrors the C++ `handle_button`.
    ///
    /// # Errors
    ///
    /// Propagates the session's [`TrustedReviewError`].
    pub fn handle_button(
        &mut self,
        button: ReviewButton,
    ) -> Result<Option<bool>, TrustedReviewError> {
        self.session.handle_button(button)
    }
}

/// A driver for the interactive serial review IO flow. Mirrors the C++
/// `SerialReviewIo` interface.
pub trait SerialReviewIo {
    /// Returns the received request JSON.
    fn read_request_json(&mut self) -> &str;
    /// Shows one review frame.
    fn show_review_frame(&mut self, frame: &ReviewDisplayFrame);
    /// Reads the next physical button press.
    fn read_review_button(&mut self) -> ReviewButton;
}

/// The result of a full serial IO flow run. Mirrors the C++
/// `SerialReviewIoFlowResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialReviewIoFlowResult {
    /// The reviewed request id.
    pub request_id: TrustedReviewRequestId,
    /// The bound approval digest.
    pub approval_digest: TrustedReviewApprovalDigest,
    /// The terminal decision.
    pub decision: Option<bool>,
    /// Whether the flow ended approved for signing.
    pub approved_for_signing: bool,
    /// The recorded steps.
    pub transcript: SerialReviewTranscript,
}

/// Runs the interactive serial IO flow to a terminal decision. Mirrors the C++
/// `run_serial_review_io_flow`.
///
/// # Errors
///
/// [`SerialReviewError::ZeroMaxSteps`],
/// [`SerialReviewError::NoTerminalDecision`], plus any flow-construction or
/// per-step error.
pub fn run_serial_review_io_flow(
    io: &mut dyn SerialReviewIo,
    identity: SignerIdentity<'_>,
    limits: ReviewDisplayLimits,
    max_steps: usize,
) -> Result<SerialReviewIoFlowResult, SerialReviewError> {
    if max_steps == 0 {
        return Err(SerialReviewError::ZeroMaxSteps);
    }

    let mut flow = SerialReviewFlow::new(io.read_request_json(), identity, limits)?;
    let mut decision: Option<bool> = None;
    let mut transcript = SerialReviewTranscript::new();
    let mut step = 0usize;
    while step < max_steps && decision.is_none() {
        let frame = flow.current_frame().map_err(SerialReviewError::Display)?;
        io.show_review_frame(&frame);
        let button = io.read_review_button();
        decision = flow
            .handle_button(button)
            .map_err(SerialReviewError::TrustedReview)?;
        transcript
            .try_push(SerialReviewTranscriptStep {
                frame,
                button,
                decision,
                approved_for_signing: flow.approved_for_signing(),
            })
            .map_err(|_| SerialReviewError::Capacity)?;
        step += 1;
    }
    if decision.is_none() {
        return Err(SerialReviewError::NoTerminalDecision);
    }
    Ok(SerialReviewIoFlowResult {
        request_id: flow.request_id.clone(),
        approval_digest: flow.approval_digest.clone(),
        decision,
        approved_for_signing: flow.approved_for_signing(),
        transcript,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::qr::build_qr_display_review_pages;
    use crate::review::test_fixtures::{
        basic_trusted_review_request, joined_lines_for_title, t_display_s3_review_limits,
        BASIC_REVIEW_SCREEN_APPROVAL_DIGEST,
    };
    use std::string::String;
    use std::vec::Vec;

    /// The basic sign-event request JSON (matches the READ-ONLY
    /// specs/vectors/review-screens/kind-1-basic.json request).
    const BASIC_REQUEST_JSON: &str = "{\"version\":1,\"request_id\":\"req-kind-1-basic\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000000,\"kind\":1,\"tags\":[],\"content\":\"nSealr fixture: basic kind 1 event.\"}}}";

    /// The tagged sign-event request JSON (matches the READ-ONLY
    /// specs/vectors/review-screens/kind-1-tags.json request).
    const TAGGED_REQUEST_JSON: &str = "{\"version\":1,\"request_id\":\"req-kind-1-tags\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000060,\"kind\":1,\"tags\":[[\"p\",\"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa\",\"\",\"mention\"],[\"t\",\"nsealr\"]],\"content\":\"nSealr fixture: tagged kind 1 event.\"}}}";

    fn dev() -> SignerIdentity<'static> {
        SignerIdentity::development_fixture()
    }

    /// The C++ RecordingSerialReviewIo test double.
    struct RecordingSerialReviewIo {
        buttons: Vec<ReviewButton>,
        next_button: usize,
        frames: Vec<ReviewDisplayFrame>,
    }

    impl SerialReviewIo for RecordingSerialReviewIo {
        fn read_request_json(&mut self) -> &str {
            BASIC_REQUEST_JSON
        }

        fn show_review_frame(&mut self, frame: &ReviewDisplayFrame) {
            self.frames.push(frame.clone());
        }

        fn read_review_button(&mut self) -> ReviewButton {
            let button = self.buttons[self.next_button];
            self.next_button += 1;
            button
        }
    }

    // Port of the C++ `test_serial_sign_event_review_matches_shared_review_contract`.
    #[test]
    fn sign_event_review_matches_shared_review_contract() {
        let serial_review =
            build_serial_sign_event_trusted_review_request(BASIC_REQUEST_JSON, dev()).unwrap();
        let expected = basic_trusted_review_request();

        assert_eq!(serial_review.request_id, expected.request_id);
        assert_eq!(serial_review.approval_digest, expected.approval_digest);
        let expected_pages = expected.pages.as_slice();
        assert_eq!(serial_review.pages.len(), expected_pages.len());
        for (page, expected_page) in serial_review.pages.as_slice().iter().zip(expected_pages) {
            assert_eq!(page.title, expected_page.title);
            assert_eq!(page.lines, expected_page.lines);
            assert_eq!(page.action, expected_page.action);
        }

        let session = begin_serial_sign_event_trusted_review(
            BASIC_REQUEST_JSON,
            dev(),
            ReviewDisplayLimits::default(),
        )
        .unwrap();
        assert_eq!(session.current_frame().unwrap().title, "Event");
        assert!(!session.can_sign());
    }

    // Port of the C++ `test_serial_review_session_uses_full_scroll_display_pages`.
    #[test]
    fn review_session_uses_full_scroll_display_pages() {
        let pubkey = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
        let mut session = begin_serial_sign_event_trusted_review(
            TAGGED_REQUEST_JSON,
            dev(),
            ReviewDisplayLimits {
                max_title_chars: 18,
                max_body_lines: 3,
                max_line_chars: 20,
                ..ReviewDisplayLimits::default()
            },
        )
        .unwrap();

        let mut tag_text = String::new();
        let mut saw_tags = false;
        let mut saw_warnings = false;
        let mut step = 0usize;
        while step < 16 && session.current_frame().unwrap().title != "Decision" {
            let frame = session.current_frame().unwrap();
            if frame.title == "Tags" {
                saw_tags = true;
                for line in frame.body_lines.as_slice() {
                    tag_text.push_str(line.as_str());
                }
            }
            saw_warnings = saw_warnings || frame.title == "Warnings";
            assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
            step += 1;
        }

        assert_eq!(session.current_frame().unwrap().title, "Decision");
        assert!(saw_tags);
        assert!(!saw_warnings);
        assert!(!tag_text.contains("..."));
        assert!(tag_text.contains(&pubkey[..48]));
        assert!(tag_text.contains(&pubkey[48..]));
        assert!(tag_text.contains("mention"));
        assert!(tag_text.contains("nsealr"));
    }

    // Port of the C++ `test_serial_review_binds_configured_signer_identity`.
    #[test]
    fn review_binds_configured_signer_identity() {
        let alternate_pubkey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let alternate_identity = SignerIdentity {
            public_key: alternate_pubkey,
        };
        let request_json = "{\"version\":1,\"request_id\":\"req-alt-author\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000000,\"kind\":1,\"tags\":[],\"content\":\"alternate author\"}}}";

        let default_review =
            build_serial_sign_event_trusted_review_request(request_json, dev()).unwrap();
        let alternate_review =
            build_serial_sign_event_trusted_review_request(request_json, alternate_identity)
                .unwrap();

        assert_ne!(
            alternate_review.approval_digest,
            default_review.approval_digest
        );
        assert!(alternate_review.pages.as_slice()[0]
            .lines
            .as_slice()
            .iter()
            .any(|line| line.as_str().contains(alternate_pubkey)));

        let session = begin_serial_sign_event_trusted_review(
            request_json,
            alternate_identity,
            t_display_s3_review_limits(),
        )
        .unwrap();
        let request = parse_qr_signing_request(request_json.as_bytes()).unwrap();
        let display_pages = build_qr_display_review_pages(
            &request,
            alternate_identity,
            t_display_s3_review_limits(),
        )
        .unwrap();
        let event_text = joined_lines_for_title(display_pages.as_slice(), "Event");

        assert_eq!(session.current_frame().unwrap().title, "Event");
        assert!(event_text.contains(&alternate_pubkey[..48]));
        assert!(event_text.contains(&alternate_pubkey[48..]));
        assert!(!session.can_sign());
    }

    // Port of the C++ `test_serial_review_session_uses_two_axis_navigation_for_scroll_windows`.
    #[test]
    fn review_session_uses_two_axis_navigation_for_scroll_windows() {
        let mut tags_json = String::new();
        for index in 0..16 {
            if !tags_json.is_empty() {
                tags_json.push(',');
            }
            tags_json.push_str("[\"t\",\"tagvalue");
            tags_json.push_str(&std::format!("{index}"));
            tags_json.push_str("000000000000\"]");
        }
        let mut request_json = String::from(
            "{\"version\":1,\"request_id\":\"req-many-tags-nav\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000180,\"kind\":1,\"tags\":[",
        );
        request_json.push_str(&tags_json);
        request_json.push_str("],\"content\":\"many tags navigation\"}}}");

        let mut session = begin_serial_sign_event_trusted_review(
            &request_json,
            dev(),
            t_display_s3_review_limits(),
        )
        .unwrap();

        assert_eq!(session.current_frame().unwrap().title, "Event");
        assert_eq!(session.current_frame().unwrap().page_indicator, "Page 1/4");
        assert_eq!(
            session.handle_button(ReviewButton::Approve),
            Err(TrustedReviewError::ApprovalRequiresDecisionPage),
        );

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Content");
        assert_eq!(session.current_frame().unwrap().page_indicator, "Page 2/4");
        assert_eq!(session.current_frame().unwrap().action_hint, "Next");

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Tags");
        let first_tag_page_indicator =
            String::from(session.current_frame().unwrap().page_indicator.as_str());
        assert!(first_tag_page_indicator.starts_with("Page 3/4 Lines 1-9/"));
        assert_eq!(session.current_frame().unwrap().action_hint, "Next/Scroll");

        assert_eq!(session.handle_button(ReviewButton::Back), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Tags");
        assert!(session
            .current_frame()
            .unwrap()
            .page_indicator
            .as_str()
            .starts_with("Page 3/4 Lines 10-"));
        assert_ne!(
            session.current_frame().unwrap().page_indicator.as_str(),
            first_tag_page_indicator,
        );
        assert_eq!(session.current_frame().unwrap().action_hint, "Next/Scroll");

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Decision");
        assert_eq!(session.current_frame().unwrap().page_indicator, "Page 4/4");
        assert!(!session.can_sign());

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Event");
        assert_eq!(session.current_frame().unwrap().page_indicator, "Page 1/4");

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.current_frame().unwrap().title, "Decision");

        let approval = session.handle_button(ReviewButton::Approve);
        assert_eq!(approval, Ok(Some(true)));
        assert!(session.can_sign());
    }

    // Port of the C++ `test_serial_review_io_flow_drives_request_display_and_buttons_without_signing`.
    #[test]
    fn io_flow_drives_request_display_and_buttons_without_signing() {
        let mut io = RecordingSerialReviewIo {
            buttons: std::vec![
                ReviewButton::Next,
                ReviewButton::Next,
                ReviewButton::Next,
                ReviewButton::Approve,
            ],
            next_button: 0,
            frames: Vec::new(),
        };

        let result =
            run_serial_review_io_flow(&mut io, dev(), ReviewDisplayLimits::default(), 32).unwrap();

        assert_eq!(result.request_id, "req-kind-1-basic");
        assert_eq!(result.approval_digest, BASIC_REVIEW_SCREEN_APPROVAL_DIGEST);
        assert_eq!(result.decision, Some(true));
        assert!(result.approved_for_signing);
        // The C++ compared against the basic approve transcript fixture's
        // length (4 steps).
        assert_eq!(result.transcript.len(), 4);
        assert_eq!(result.transcript.step(0).frame.title, "Event");
        assert_eq!(result.transcript.step(0).frame.page_indicator, "Page 1/4");
        assert_eq!(result.transcript.step(3).frame.title, "Decision");
        assert_eq!(result.transcript.step(3).decision, Some(true));
        assert_eq!(io.frames.len(), 4);
        assert_eq!(io.frames[0].title, "Event");
        assert_eq!(io.frames[3].action_hint, "Approve / Reject");
    }

    // Beyond the named C++ cases: the zero-step and non-terminal IO branches
    // with their C++ messages.
    #[test]
    fn io_flow_step_limit_branches() {
        let mut io = RecordingSerialReviewIo {
            buttons: std::vec![ReviewButton::Approve],
            next_button: 0,
            frames: Vec::new(),
        };
        assert_eq!(
            run_serial_review_io_flow(&mut io, dev(), ReviewDisplayLimits::default(), 0),
            Err(SerialReviewError::ZeroMaxSteps),
        );
        assert!(io.frames.is_empty());
        assert_eq!(
            SerialReviewError::ZeroMaxSteps.message(),
            "serial review IO max steps must be non-zero",
        );

        let mut next_only = RecordingSerialReviewIo {
            buttons: std::vec![ReviewButton::Next, ReviewButton::Next],
            next_button: 0,
            frames: Vec::new(),
        };
        assert_eq!(
            run_serial_review_io_flow(&mut next_only, dev(), ReviewDisplayLimits::default(), 2),
            Err(SerialReviewError::NoTerminalDecision),
        );
        assert_eq!(
            SerialReviewError::NoTerminalDecision.message(),
            "serial review IO did not reach a terminal decision",
        );
    }

    // Beyond the named C++ cases: error messages/Display and the
    // SerialReviewFlow facade accessors (request_id/approval_digest/decision/
    // current_frame/handle_button, as the C++ class exposed them).
    #[test]
    fn error_messages_and_flow_accessors() {
        for (error, expected) in [
            (
                SerialReviewError::Envelope(QrEnvelopeError::RequestBadVersion),
                "serial signing request rejected",
            ),
            (
                SerialReviewError::Review(QrReviewError::Capacity),
                "QR review exceeds fixed review page capacity",
            ),
            (
                SerialReviewError::TrustedReview(TrustedReviewError::AlreadyTerminal),
                "review decision is already terminal",
            ),
            (
                SerialReviewError::Display(ReviewDisplayError::ZeroLimits),
                "review display limits must be non-zero",
            ),
            (
                SerialReviewError::ZeroMaxSteps,
                "serial review IO max steps must be non-zero",
            ),
            (
                SerialReviewError::NoTerminalDecision,
                "serial review IO did not reach a terminal decision",
            ),
            (
                SerialReviewError::Capacity,
                "serial review flow exceeds fixed capacity",
            ),
        ] {
            assert_eq!(error.message(), expected);
            assert_eq!(std::format!("{error}"), expected);
        }

        let mut flow =
            SerialReviewFlow::new(BASIC_REQUEST_JSON, dev(), ReviewDisplayLimits::default())
                .unwrap();
        assert_eq!(flow.request_id(), "req-kind-1-basic");
        assert_eq!(flow.approval_digest(), BASIC_REVIEW_SCREEN_APPROVAL_DIGEST);
        assert_eq!(flow.decision(), ApprovalDecision::Pending);
        assert!(!flow.approved_for_signing());
        assert_eq!(flow.current_frame().unwrap().title, "Event");
        assert_eq!(flow.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(flow.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(flow.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(flow.handle_button(ReviewButton::Approve), Ok(Some(true)));
        assert!(flow.approved_for_signing());
        assert_eq!(flow.decision(), ApprovalDecision::Approved);
    }
}
