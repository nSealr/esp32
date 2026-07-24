//! QR review flow — scanned request QR to trusted review decision.
//!
//! Ported from the C++ reference `host_core` sources `src/qr_review_flow.cpp` +
//! `include/nsealr/qr_review_flow.hpp` for behaviour parity: the same
//! scanned-text handling (split on newlines, ASCII-trim each line, drop
//! empties), the same static/animated dispatch (a single `nsealr1:` frame
//! decodes statically, an all-`nsealr1a:` frame set decodes as an animated
//! envelope, a single frame without either prefix still tries the static
//! decoder for its precise error, anything else is rejected), the same
//! [`QrReviewFlow`] session facade, and the same IO/transcript drivers.
//!
//! The C++ default-identity overloads map to passing
//! [`SignerIdentity::development_fixture`] explicitly. The C++ threw
//! exceptions; this port returns [`QrReviewFlowError`] values with the exact
//! C++ messages where they exist. The C++ heap-allocated the scanned frame
//! list and transcript vectors; this port bounds them by the shared limits
//! ([`MAX_ANIMATED_QR_FRAME_COUNT`] scanned frames,
//! [`MAX_QR_REVIEW_TRANSCRIPT_STEPS`] transcript steps).

use crate::base64url::encoded_len;
use crate::policy::approval_gate::ApprovalDecision;
use crate::qr::envelope::{
    decode_animated_qr_envelope_frames, decode_qr_envelope, parse_qr_signing_request,
    QrEnvelopeError,
};
use crate::qr::limits::{
    MAX_ANIMATED_QR_DECODED_JSON_BYTES, MAX_ANIMATED_QR_FRAME_COUNT,
    MAX_STATIC_QR_DECODED_JSON_BYTES,
};
use crate::review::controls::ReviewButton;
use crate::review::display::{ReviewDisplayError, ReviewDisplayFrame, ReviewDisplayLimits};
use crate::review::qr::{build_qr_display_review_request, QrReviewError};
use crate::review::signer_identity::SignerIdentity;
use crate::review::trusted::{TrustedReviewError, TrustedReviewSession};
use crate::review::types::{TrustedReviewApprovalDigest, TrustedReviewRequestId};
use core::fmt;

/// The static QR envelope prefix (the C++ `kStaticQrPrefix`).
const STATIC_QR_PREFIX: &str = "nsealr1:";
/// The animated QR frame prefix (the C++ `kAnimatedQrPrefix`).
const ANIMATED_QR_PREFIX: &str = "nsealr1a:";

/// Maximum recorded transcript steps — the C++ default `max_steps` (32).
pub const MAX_QR_REVIEW_TRANSCRIPT_STEPS: usize = 32;

/// Errors reported by the QR review flow. [`Self::message`] returns the C++
/// exception text where one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrReviewFlowError {
    /// The scanned text held no non-empty frame. C++ `QrEnvelopeError`.
    NoScannedQr,
    /// Multiple frames that are not all `nsealr1a:`. C++ `QrEnvelopeError`.
    MixedScannedFrames,
    /// An envelope decode / signing-request parse failure.
    Envelope(QrEnvelopeError),
    /// A review-build failure (identity, limits, capacity).
    Review(QrReviewError),
    /// A trusted-review session failure (construction or button handling).
    TrustedReview(TrustedReviewError),
    /// A display-render failure from [`QrReviewFlow::current_frame`].
    Display(ReviewDisplayError),
    /// `max_steps` was zero. C++ `std::invalid_argument`.
    ZeroMaxSteps,
    /// The IO flow ran out of steps without a terminal decision. C++
    /// `std::logic_error`.
    NoTerminalDecision,
    /// More scanned frames / transcript steps than the fixed capacities hold.
    /// No C++ analogue (heap vectors); a frame set beyond
    /// [`MAX_ANIMATED_QR_FRAME_COUNT`] could never decode in C++ either.
    Capacity,
}

impl QrReviewFlowError {
    /// The exact C++ exception message where one exists.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::NoScannedQr => "QR review flow requires a scanned request QR",
            Self::MixedScannedFrames => {
                "QR review flow requires static nsealr1 or animated nsealr1a request QR"
            }
            Self::Envelope(_) => "QR envelope rejected",
            Self::Review(inner) => inner.message(),
            Self::TrustedReview(inner) => inner.message(),
            Self::Display(inner) => inner.message(),
            Self::ZeroMaxSteps => "QR review IO max steps must be non-zero",
            Self::NoTerminalDecision => "QR review IO did not reach a terminal decision",
            Self::Capacity => "QR review flow exceeds fixed capacity",
        }
    }
}

impl fmt::Display for QrReviewFlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// Strips leading/trailing ASCII whitespace. Mirrors the C++ `trim_ascii`.
fn trim_ascii(value: &str) -> &str {
    value.trim_matches(|ch| matches!(ch, ' ' | '\n' | '\r' | '\t'))
}

/// A driver for the interactive QR review IO flow. Mirrors the C++
/// `QrReviewIo` interface.
pub trait QrReviewIo {
    /// Returns the scanned request QR text (all frames, newline separated).
    fn scan_request_qr(&mut self) -> &str;
    /// Shows one review frame.
    fn show_review_frame(&mut self, frame: &ReviewDisplayFrame);
    /// Reads the next physical button press.
    fn read_review_button(&mut self) -> ReviewButton;
}

/// One recorded IO/transcript step. Mirrors the C++ `QrReviewTranscriptStep`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrReviewTranscriptStep {
    /// The frame shown before the button was read.
    pub frame: ReviewDisplayFrame,
    /// The button pressed.
    pub button: ReviewButton,
    /// The terminal decision, if this step produced one.
    pub decision: Option<bool>,
    /// Whether the flow was approved for signing after this step.
    pub approved_for_signing: bool,
}

/// A fixed-capacity transcript — the allocation-free stand-in for the C++
/// `std::vector<QrReviewTranscriptStep>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrReviewTranscript {
    steps: [Option<QrReviewTranscriptStep>; MAX_QR_REVIEW_TRANSCRIPT_STEPS],
    len: usize,
}

impl QrReviewTranscript {
    /// Creates an empty transcript.
    #[must_use]
    pub fn new() -> Self {
        Self {
            steps: [const { None }; MAX_QR_REVIEW_TRANSCRIPT_STEPS],
            len: 0,
        }
    }

    /// Appends one step (shared with the serial review flow).
    pub(crate) fn try_push(
        &mut self,
        step: QrReviewTranscriptStep,
    ) -> Result<(), crate::text::TextError> {
        if self.len >= MAX_QR_REVIEW_TRANSCRIPT_STEPS {
            return Err(crate::text::TextError::TooLong);
        }
        self.steps[self.len] = Some(step);
        self.len += 1;
        Ok(())
    }

    /// Returns the recorded step at `index`.
    #[must_use]
    pub fn step(&self, index: usize) -> &QrReviewTranscriptStep {
        self.steps[index].as_ref().expect("index within len")
    }

    /// Returns the number of recorded steps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if no step was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterates the recorded steps in order.
    pub fn iter(&self) -> impl Iterator<Item = &QrReviewTranscriptStep> {
        self.steps[..self.len]
            .iter()
            .map(|step| step.as_ref().expect("within len"))
    }
}

impl Default for QrReviewTranscript {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of a full IO flow run. Mirrors the C++ `QrReviewIoFlowResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrReviewIoFlowResult {
    /// The reviewed request id.
    pub request_id: TrustedReviewRequestId,
    /// The bound approval digest.
    pub approval_digest: TrustedReviewApprovalDigest,
    /// The terminal decision.
    pub decision: Option<bool>,
    /// Whether the flow ended approved for signing.
    pub approved_for_signing: bool,
    /// The recorded steps.
    pub transcript: QrReviewTranscript,
}

/// A QR review flow: scanned envelope text to review session. Mirrors the C++
/// `QrReviewFlow` method for method (the C++ default-identity constructor maps
/// to passing [`SignerIdentity::development_fixture`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrReviewFlow {
    request_id: TrustedReviewRequestId,
    approval_digest: TrustedReviewApprovalDigest,
    session: TrustedReviewSession,
}

impl QrReviewFlow {
    /// Builds the flow from scanned QR text. Mirrors the C++ constructor
    /// (`decode_scanned_request_qr` + `review_request_from_qr`).
    ///
    /// # Errors
    ///
    /// See [`QrReviewFlowError`].
    pub fn new(
        scanned_qr: &str,
        identity: SignerIdentity<'_>,
        limits: ReviewDisplayLimits,
    ) -> Result<Self, QrReviewFlowError> {
        // Collect the trimmed, non-empty scanned lines (the C++
        // `non_empty_qr_lines`).
        let mut frames: [&str; MAX_ANIMATED_QR_FRAME_COUNT] = [""; MAX_ANIMATED_QR_FRAME_COUNT];
        let mut frame_count = 0usize;
        for line in scanned_qr.split('\n') {
            let line = trim_ascii(line);
            if line.is_empty() {
                continue;
            }
            if frame_count == MAX_ANIMATED_QR_FRAME_COUNT {
                // More frames than any animated envelope can carry: the C++
                // collected them and failed the frame-count check inside the
                // animated decoder.
                return Err(QrReviewFlowError::Envelope(
                    QrEnvelopeError::AnimatedTooManyFrames,
                ));
            }
            frames[frame_count] = line;
            frame_count += 1;
        }
        let frames = &frames[..frame_count];
        if frames.is_empty() {
            return Err(QrReviewFlowError::NoScannedQr);
        }

        // Decode buffers for the larger (animated) path; the static path uses
        // a prefix of the JSON buffer.
        let mut payload_buf = [0u8; encoded_len(MAX_ANIMATED_QR_DECODED_JSON_BYTES)];
        let mut json_buf = [0u8; MAX_ANIMATED_QR_DECODED_JSON_BYTES];

        let payload_json: &[u8] = if frames.len() == 1 && frames[0].starts_with(STATIC_QR_PREFIX) {
            decode_qr_envelope(
                frames[0].as_bytes(),
                &mut json_buf[..MAX_STATIC_QR_DECODED_JSON_BYTES],
            )
            .map_err(QrReviewFlowError::Envelope)?
            .payload_json
        } else if frames
            .iter()
            .all(|frame| frame.starts_with(ANIMATED_QR_PREFIX))
        {
            let mut frame_bytes: [&[u8]; MAX_ANIMATED_QR_FRAME_COUNT] =
                [&[]; MAX_ANIMATED_QR_FRAME_COUNT];
            for (slot, frame) in frame_bytes.iter_mut().zip(frames) {
                *slot = frame.as_bytes();
            }
            decode_animated_qr_envelope_frames(
                &frame_bytes[..frames.len()],
                &mut payload_buf,
                &mut json_buf,
            )
            .map_err(QrReviewFlowError::Envelope)?
            .payload_json
        } else if frames.len() == 1 {
            decode_qr_envelope(
                frames[0].as_bytes(),
                &mut json_buf[..MAX_STATIC_QR_DECODED_JSON_BYTES],
            )
            .map_err(QrReviewFlowError::Envelope)?
            .payload_json
        } else {
            return Err(QrReviewFlowError::MixedScannedFrames);
        };

        let request =
            parse_qr_signing_request(payload_json).map_err(QrReviewFlowError::Envelope)?;
        let review_request = build_qr_display_review_request(&request, identity, limits)
            .map_err(QrReviewFlowError::Review)?;
        let request_id = review_request.request_id.clone();
        let approval_digest = review_request.approval_digest.clone();
        let session = TrustedReviewSession::new(review_request, limits)
            .map_err(QrReviewFlowError::TrustedReview)?;
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
    /// `approved_for_signing` (`session.can_sign()`).
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

/// Runs the interactive IO flow to a terminal decision. Mirrors the C++
/// `run_qr_review_io_flow`.
///
/// # Errors
///
/// [`QrReviewFlowError::ZeroMaxSteps`], [`QrReviewFlowError::NoTerminalDecision`],
/// plus any flow-construction or per-step error.
pub fn run_qr_review_io_flow(
    io: &mut dyn QrReviewIo,
    identity: SignerIdentity<'_>,
    limits: ReviewDisplayLimits,
    max_steps: usize,
) -> Result<QrReviewIoFlowResult, QrReviewFlowError> {
    if max_steps == 0 {
        return Err(QrReviewFlowError::ZeroMaxSteps);
    }

    let mut flow = QrReviewFlow::new(io.scan_request_qr(), identity, limits)?;
    let mut decision: Option<bool> = None;
    let mut transcript = QrReviewTranscript::new();
    let mut step = 0usize;
    while step < max_steps && decision.is_none() {
        let frame = flow.current_frame().map_err(QrReviewFlowError::Display)?;
        io.show_review_frame(&frame);
        let button = io.read_review_button();
        decision = flow
            .handle_button(button)
            .map_err(QrReviewFlowError::TrustedReview)?;
        transcript
            .try_push(QrReviewTranscriptStep {
                frame,
                button,
                decision,
                approved_for_signing: flow.approved_for_signing(),
            })
            .map_err(|_| QrReviewFlowError::Capacity)?;
        step += 1;
    }
    if decision.is_none() {
        return Err(QrReviewFlowError::NoTerminalDecision);
    }
    Ok(QrReviewIoFlowResult {
        request_id: flow.request_id.clone(),
        approval_digest: flow.approval_digest.clone(),
        decision,
        approved_for_signing: flow.approved_for_signing(),
        transcript,
    })
}

/// Replays a fixed button sequence, recording every step. Mirrors the C++
/// `run_qr_review_transcript`.
///
/// # Errors
///
/// Any flow-construction or per-step error; [`QrReviewFlowError::Capacity`] if
/// `buttons` exceeds [`MAX_QR_REVIEW_TRANSCRIPT_STEPS`].
pub fn run_qr_review_transcript(
    scanned_qr: &str,
    buttons: &[ReviewButton],
    identity: SignerIdentity<'_>,
    limits: ReviewDisplayLimits,
) -> Result<QrReviewTranscript, QrReviewFlowError> {
    let mut flow = QrReviewFlow::new(scanned_qr, identity, limits)?;
    let mut transcript = QrReviewTranscript::new();
    for &button in buttons {
        let frame = flow.current_frame().map_err(QrReviewFlowError::Display)?;
        let decision = flow
            .handle_button(button)
            .map_err(QrReviewFlowError::TrustedReview)?;
        transcript
            .try_push(QrReviewTranscriptStep {
                frame,
                button,
                decision,
                approved_for_signing: flow.approved_for_signing(),
            })
            .map_err(|_| QrReviewFlowError::Capacity)?;
    }
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39;
    use crate::qr::envelope::encode_animated_qr_envelope_json;
    use crate::review::qr::build_qr_trusted_review_request;
    use crate::review::signer_identity::DEVELOPMENT_FIXTURE_PUBLIC_KEY;
    use crate::review::test_fixtures::{
        basic_trusted_review_request, frame_lines_contain, t_display_s3_review_limits,
        BASIC_REVIEW_SCREEN_APPROVAL_DIGEST, QR_ENVELOPE_KIND_1_BASIC,
    };
    use crate::review::types::{ReviewBodyLineStyle, ReviewPageList};
    use crate::session::account::{
        select_session_account, SessionAccountDescriptor, SessionAccountRecoveryKind,
    };
    use crate::session::keyring::StatelessSessionKeyring;
    use std::string::String;
    use std::vec;
    use std::vec::Vec;

    /// Static QR envelope copied from the READ-ONLY
    /// specs/vectors/transports/qr-envelope-kind-1-long-events-many-tags.json
    /// (`envelope`).
    const QR_ENVELOPE_KIND_1_LONG_EVENTS_MANY_TAGS: &str = "nsealr1:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1sb25nLWV2ZW50cy1tYW55LXRhZ3MiLCJtZXRob2QiOiJzaWduX2V2ZW50IiwicGFyYW1zIjp7ImV2ZW50X3RlbXBsYXRlIjp7ImNyZWF0ZWRfYXQiOjE3MTAwMDAxMjAsImtpbmQiOjEsInRhZ3MiOltbImUiLCJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwiIiwicm9vdCJdLFsidCIsIm5zZWFsciJdLFsidCIsImhhcmR3YXJlIl0sWyJ0IiwicmV2aWV3Il0sWyJ0Iiwic2VjdXJpdHkiXSxbInQiLCJxciJdLFsidCIsInZhdWx0Il0sWyJ0IiwiY29tcGFuaW9uIl0sWyJ0IiwidGVzdCJdXSwiY29udGVudCI6Inh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4In19fQ";

    fn dev() -> SignerIdentity<'static> {
        SignerIdentity::development_fixture()
    }

    /// The C++ RecordingQrReviewIo test double.
    struct RecordingQrReviewIo {
        buttons: Vec<ReviewButton>,
        next_button: usize,
        scanned_request: String,
        frames: Vec<ReviewDisplayFrame>,
    }

    impl RecordingQrReviewIo {
        fn new(buttons: &[ReviewButton], scanned_request: &str) -> Self {
            Self {
                buttons: buttons.to_vec(),
                next_button: 0,
                scanned_request: String::from(scanned_request),
                frames: Vec::new(),
            }
        }
    }

    impl QrReviewIo for RecordingQrReviewIo {
        fn scan_request_qr(&mut self) -> &str {
            &self.scanned_request
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

    /// The C++ NextOnlyQrReviewIo test double.
    struct NextOnlyQrReviewIo {
        frames: Vec<ReviewDisplayFrame>,
    }

    impl QrReviewIo for NextOnlyQrReviewIo {
        fn scan_request_qr(&mut self) -> &str {
            QR_ENVELOPE_KIND_1_BASIC
        }

        fn show_review_frame(&mut self, frame: &ReviewDisplayFrame) {
            self.frames.push(frame.clone());
        }

        fn read_review_button(&mut self) -> ReviewButton {
            ReviewButton::Next
        }
    }

    const APPROVE_BUTTONS: [ReviewButton; 4] = [
        ReviewButton::Next,
        ReviewButton::Next,
        ReviewButton::Next,
        ReviewButton::Approve,
    ];

    // Port of the C++ `test_qr_review_flow_drives_scanned_qr_without_signing_backend`.
    #[test]
    fn flow_drives_scanned_qr_without_signing_backend() {
        let mut flow = QrReviewFlow::new(
            QR_ENVELOPE_KIND_1_BASIC,
            dev(),
            ReviewDisplayLimits::default(),
        )
        .unwrap();
        let expected = basic_trusted_review_request();

        assert_eq!(flow.request_id(), expected.request_id.as_str());
        assert_eq!(flow.approval_digest(), expected.approval_digest.as_str());
        assert!(!flow.approved_for_signing());

        let first_frame = flow.current_frame().unwrap();
        assert_eq!(first_frame.title, "Event");
        assert_eq!(first_frame.page_indicator, "Page 1/4");

        assert_eq!(
            flow.handle_button(ReviewButton::Approve),
            Err(TrustedReviewError::ApprovalRequiresDecisionPage),
        );

        assert_eq!(flow.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(flow.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(flow.handle_button(ReviewButton::Next), Ok(None));

        let decision_frame = flow.current_frame().unwrap();
        assert_eq!(decision_frame.title, "Decision");
        assert!(!flow.approved_for_signing());

        let approval = flow.handle_button(ReviewButton::Approve);
        assert_eq!(approval, Ok(Some(true)));
        assert!(flow.approved_for_signing());
        assert_eq!(flow.decision(), ApprovalDecision::Approved);
    }

    // Port of the C++ `test_qr_review_flow_accepts_animated_scanned_request_frames`.
    #[test]
    fn flow_accepts_animated_scanned_request_frames() {
        let mut json_buf = [0u8; MAX_STATIC_QR_DECODED_JSON_BYTES];
        let static_envelope =
            decode_qr_envelope(QR_ENVELOPE_KIND_1_BASIC.as_bytes(), &mut json_buf).unwrap();
        let mut animated_request = String::new();
        encode_animated_qr_envelope_json(static_envelope.payload_json, 24, &mut |frame, _, _| {
            if !animated_request.is_empty() {
                animated_request.push('\n');
            }
            animated_request.push_str(core::str::from_utf8(frame).unwrap());
        })
        .unwrap();

        let flow =
            QrReviewFlow::new(&animated_request, dev(), ReviewDisplayLimits::default()).unwrap();
        assert_eq!(flow.request_id(), "req-kind-1-basic");
        assert_eq!(flow.approval_digest(), BASIC_REVIEW_SCREEN_APPROVAL_DIGEST);
        assert_eq!(flow.current_frame().unwrap().title, "Event");

        let mut io = RecordingQrReviewIo::new(&APPROVE_BUTTONS, &animated_request);
        let result =
            run_qr_review_io_flow(&mut io, dev(), ReviewDisplayLimits::default(), 32).unwrap();
        assert_eq!(result.request_id, "req-kind-1-basic");
        assert!(result.approved_for_signing);
        assert_eq!(io.frames.len(), 4);
    }

    // Port of the C++ `test_qr_review_flow_rejects_mixed_scanned_request_frames`.
    #[test]
    fn flow_rejects_mixed_scanned_request_frames() {
        let mut mixed = String::from(QR_ENVELOPE_KIND_1_BASIC);
        mixed.push('\n');
        mixed.push_str("nsealr1a:not-a-compatible-frame");
        assert_eq!(
            QrReviewFlow::new(&mixed, dev(), ReviewDisplayLimits::default()),
            Err(QrReviewFlowError::MixedScannedFrames),
        );
        assert_eq!(
            QrReviewFlowError::MixedScannedFrames.message(),
            "QR review flow requires static nsealr1 or animated nsealr1a request QR",
        );
    }

    // Port of the C++ `test_qr_review_flow_binds_selected_session_account_identity`.
    #[test]
    fn flow_binds_selected_session_account_identity() {
        // NIP-06 fixture copied from the READ-ONLY
        // specs/vectors/keys/nip06-account-0-leader.json.
        let mnemonic =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let nip06_public_key = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
        let mut keyring = StatelessSessionKeyring::new();
        keyring
            .add_bip39_seed(
                "NIP-06 account 0",
                bip39::parse_mnemonic_indexes(mnemonic).unwrap().as_slice(),
            )
            .unwrap();
        // Descriptor copied from the READ-ONLY
        // specs/vectors/accounts/esp32-qr-nip06-account-0.json.
        let descriptor = SessionAccountDescriptor {
            account_id: "acct-esp32-qr-nip06-account-0",
            route_type: "esp32_qr_vault",
            public_key: nip06_public_key,
            source_index: 0,
            source_fingerprint: "cd64b58daca009b9",
            recovery_kind: SessionAccountRecoveryKind::Nip06,
            derivation_path: "m/44'/1237'/0'/0/0",
            account_index: 0,
        };
        let selected = select_session_account(&keyring, &descriptor).unwrap();

        let mut json_buf = [0u8; MAX_STATIC_QR_DECODED_JSON_BYTES];
        let envelope =
            decode_qr_envelope(QR_ENVELOPE_KIND_1_BASIC.as_bytes(), &mut json_buf).unwrap();
        let request = parse_qr_signing_request(envelope.payload_json).unwrap();
        let expected = build_qr_display_review_request(
            &request,
            selected.signer_identity,
            ReviewDisplayLimits::default(),
        )
        .unwrap();

        let flow = QrReviewFlow::new(
            QR_ENVELOPE_KIND_1_BASIC,
            selected.signer_identity,
            ReviewDisplayLimits::default(),
        )
        .unwrap();
        assert_eq!(flow.approval_digest(), expected.approval_digest.as_str());
        assert_ne!(
            flow.approval_digest(),
            basic_trusted_review_request().approval_digest.as_str(),
        );

        let first_frame = flow.current_frame().unwrap();
        let selected_pubkey_prefix = &nip06_public_key[..32];
        let development_pubkey_prefix = &DEVELOPMENT_FIXTURE_PUBLIC_KEY[..32];
        assert_eq!(first_frame.title, "Event");
        assert!(frame_lines_contain(&first_frame, selected_pubkey_prefix));
        assert!(!frame_lines_contain(
            &first_frame,
            development_pubkey_prefix
        ));

        let mut io = RecordingQrReviewIo::new(&APPROVE_BUTTONS, QR_ENVELOPE_KIND_1_BASIC);
        let result = run_qr_review_io_flow(
            &mut io,
            selected.signer_identity,
            ReviewDisplayLimits::default(),
            32,
        )
        .unwrap();
        assert_eq!(result.approval_digest, expected.approval_digest);
        assert!(result.approved_for_signing);
        assert!(!io.frames.is_empty());
        assert!(frame_lines_contain(&io.frames[0], selected_pubkey_prefix));
        assert!(!frame_lines_contain(
            &io.frames[0],
            development_pubkey_prefix
        ));
        // The trusted (summary) request under the selected identity also
        // carries the selected key (the C++ asserted through
        // build_qr_display_review_request; the summary builder shares the
        // digest path).
        let trusted = build_qr_trusted_review_request(&request, selected.signer_identity).unwrap();
        assert_eq!(trusted.approval_digest, expected.approval_digest);
    }

    // Port of the C++ `test_qr_review_flow_rejects_unsafe_scanned_qr`.
    #[test]
    fn flow_rejects_unsafe_scanned_qr() {
        // A static envelope whose event template smuggles a "sig" field (the
        // C++ inline literal).
        let unsafe_envelope = "nsealr1:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0X2lkIjoicmVxLWtpbmQtMS1iYXNpYyIsIm1ldGhvZCI6InNpZ25fZXZlbnQiLCJwYXJhbXMiOnsiZXZlbnRfdGVtcGxhdGUiOnsiY3JlYXRlZF9hdCI6MTcxMDAwMDAwMCwia2luZCI6MSwidGFncyI6W10sImNvbnRlbnQiOiIiLCJzaWciOiIwMCJ9fX0";
        assert_eq!(
            QrReviewFlow::new(unsafe_envelope, dev(), ReviewDisplayLimits::default()),
            Err(QrReviewFlowError::Envelope(
                QrEnvelopeError::RequestEventTemplateForbiddenField,
            )),
        );
    }

    /// One expected transcript step from a READ-ONLY review-transcripts
    /// fixture.
    struct TranscriptStepFixture {
        title: &'static str,
        page_indicator: &'static str,
        body_lines: Vec<&'static str>,
        action_hint: &'static str,
        body_line_styles: Vec<ReviewBodyLineStyle>,
        button: ReviewButton,
        decision: Option<bool>,
        approved_for_signing: bool,
    }

    /// The C++ `assert_qr_review_transcript_equals` (every frame field plus
    /// button/decision/approved flags).
    fn assert_transcript_equals(actual: &QrReviewTranscript, expected: &[TranscriptStepFixture]) {
        assert_eq!(actual.len(), expected.len());
        for (step, expected_step) in actual.iter().zip(expected) {
            assert_eq!(step.frame.title, expected_step.title);
            assert_eq!(step.frame.page_indicator, expected_step.page_indicator);
            let body: Vec<&str> = step
                .frame
                .body_lines
                .as_slice()
                .iter()
                .map(|line| line.as_str())
                .collect();
            assert_eq!(body, expected_step.body_lines);
            assert_eq!(step.frame.action_hint, expected_step.action_hint);
            assert_eq!(
                step.frame.body_line_styles.as_slice(),
                expected_step.body_line_styles.as_slice(),
            );
            assert_eq!(step.button, expected_step.button);
            assert_eq!(step.decision, expected_step.decision);
            assert_eq!(
                step.approved_for_signing,
                expected_step.approved_for_signing
            );
        }
    }

    // Port of the C++ `test_qr_review_flow_transcript_records_display_and_approval_steps`.
    #[test]
    fn transcript_records_display_and_approval_steps() {
        let transcript = run_qr_review_transcript(
            QR_ENVELOPE_KIND_1_BASIC,
            &APPROVE_BUTTONS,
            dev(),
            ReviewDisplayLimits::default(),
        )
        .unwrap();

        assert_eq!(transcript.len(), 4);
        assert_eq!(transcript.step(0).frame.title, "Event");
        let event_body: Vec<&str> = transcript
            .step(0)
            .frame
            .body_lines
            .as_slice()
            .iter()
            .map(|line| line.as_str())
            .collect();
        assert_eq!(
            event_body,
            [
                "Kind 1",
                "Created 1710000000",
                "Author",
                "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a",
                "  b0f0b704075871aa",
            ],
        );
        assert_eq!(transcript.step(1).frame.title, "Content");
        let content_body: Vec<&str> = transcript
            .step(1)
            .frame
            .body_lines
            .as_slice()
            .iter()
            .map(|line| line.as_str())
            .collect();
        let expected_content: Vec<&str> = basic_approve_transcript()[1].body_lines.clone();
        assert_eq!(content_body, expected_content);
        assert_eq!(transcript.step(2).frame.title, "Tags");
        let tags_body: Vec<&str> = transcript
            .step(2)
            .frame
            .body_lines
            .as_slice()
            .iter()
            .map(|line| line.as_str())
            .collect();
        assert_eq!(tags_body, ["No tags"]);
        assert_eq!(transcript.step(3).frame.title, "Decision");
        assert_eq!(transcript.step(3).frame.action_hint, "Approve / Reject");
        assert_eq!(transcript.step(3).decision, Some(true));
        assert!(transcript.step(3).approved_for_signing);
    }

    // Port of the C++ `test_qr_review_flow_transcript_records_early_rejection`.
    #[test]
    fn transcript_records_early_rejection() {
        let transcript = run_qr_review_transcript(
            QR_ENVELOPE_KIND_1_BASIC,
            &[ReviewButton::Reject],
            dev(),
            ReviewDisplayLimits::default(),
        )
        .unwrap();

        assert_eq!(transcript.len(), 1);
        assert_eq!(transcript.step(0).frame.title, "Event");
        assert!(frame_lines_contain(&transcript.step(0).frame, "Author"));
        assert!(!frame_lines_contain(
            &transcript.step(0).frame,
            "Short Text Note"
        ));
        assert_eq!(transcript.step(0).decision, Some(false));
        assert!(!transcript.step(0).approved_for_signing);
    }

    // Port of the C++ `test_qr_review_flow_transcript_matches_shared_detail_scroll_vector`.
    #[test]
    fn transcript_matches_shared_detail_scroll_vector() {
        let expected = detail_scroll_approve_transcript();
        let buttons: Vec<ReviewButton> = expected.iter().map(|step| step.button).collect();
        let transcript = run_qr_review_transcript(
            QR_ENVELOPE_KIND_1_LONG_EVENTS_MANY_TAGS,
            &buttons,
            dev(),
            t_display_s3_review_limits(),
        )
        .unwrap();

        assert_transcript_equals(&transcript, &expected);
        assert_eq!(transcript.step(2).frame.action_hint, "Next/Scroll");
        assert_eq!(transcript.step(2).button, ReviewButton::Back);
        assert!(transcript.step(transcript.len() - 1).approved_for_signing);
    }

    // Port of the C++ `test_qr_review_io_flow_drives_scanner_display_and_buttons_without_signing`.
    #[test]
    fn io_flow_drives_scanner_display_and_buttons_without_signing() {
        let mut io = RecordingQrReviewIo::new(&APPROVE_BUTTONS, QR_ENVELOPE_KIND_1_BASIC);

        let result =
            run_qr_review_io_flow(&mut io, dev(), ReviewDisplayLimits::default(), 32).unwrap();

        assert_eq!(result.request_id, "req-kind-1-basic");
        assert_eq!(result.approval_digest, BASIC_REVIEW_SCREEN_APPROVAL_DIGEST);
        assert_eq!(result.decision, Some(true));
        assert!(result.approved_for_signing);
        assert_eq!(result.transcript.len(), 4);
        assert_eq!(result.transcript.step(2).frame.title, "Tags");
        let tags_body: Vec<&str> = result
            .transcript
            .step(2)
            .frame
            .body_lines
            .as_slice()
            .iter()
            .map(|line| line.as_str())
            .collect();
        assert_eq!(tags_body, ["No tags"]);
        assert_eq!(result.transcript.step(3).decision, Some(true));
        assert_eq!(io.frames.len(), 4);
        assert_eq!(io.frames[0].title, "Event");
        assert_eq!(io.frames[0].page_indicator, "Page 1/4");
        assert_eq!(io.frames[3].title, "Decision");
        assert_eq!(io.frames[3].action_hint, "Approve / Reject");
    }

    // Port of the C++ `test_qr_review_io_flow_rejects_non_terminal_button_stream`.
    #[test]
    fn io_flow_rejects_non_terminal_button_stream() {
        let mut io = NextOnlyQrReviewIo { frames: Vec::new() };

        assert_eq!(
            run_qr_review_io_flow(&mut io, dev(), ReviewDisplayLimits::default(), 5),
            Err(QrReviewFlowError::NoTerminalDecision),
        );
        assert_eq!(
            QrReviewFlowError::NoTerminalDecision.message(),
            "QR review IO did not reach a terminal decision",
        );

        assert_eq!(io.frames.len(), 5);
        assert_eq!(io.frames[3].title, "Decision");
        assert_eq!(io.frames[4].title, "Event");
    }

    // Port of the C++ `test_qr_review_io_flow_requires_nonzero_step_limit`.
    #[test]
    fn io_flow_requires_nonzero_step_limit() {
        let mut io = RecordingQrReviewIo::new(&[ReviewButton::Approve], QR_ENVELOPE_KIND_1_BASIC);

        assert_eq!(
            run_qr_review_io_flow(&mut io, dev(), ReviewDisplayLimits::default(), 0),
            Err(QrReviewFlowError::ZeroMaxSteps),
        );
        assert_eq!(
            QrReviewFlowError::ZeroMaxSteps.message(),
            "QR review IO max steps must be non-zero",
        );

        assert!(io.frames.is_empty());
    }

    // Beyond the named C++ cases: the empty-scan branch, its C++ message, and
    // the single-frame fallthrough to the static decoder for a foreign prefix.
    #[test]
    fn empty_and_foreign_scans_report_envelope_errors() {
        assert_eq!(
            QrReviewFlow::new("\n  \n", dev(), ReviewDisplayLimits::default()),
            Err(QrReviewFlowError::NoScannedQr),
        );
        assert_eq!(
            QrReviewFlowError::NoScannedQr.message(),
            "QR review flow requires a scanned request QR",
        );
        // A single frame without either prefix goes to the static decoder for
        // its precise error (the C++ fallthrough branch).
        assert_eq!(
            QrReviewFlow::new("nostr:abc", dev(), ReviewDisplayLimits::default()),
            Err(QrReviewFlowError::Envelope(QrEnvelopeError::MissingPrefix)),
        );
        // Scanned text is ASCII-trimmed per line before decoding.
        let mut padded = String::from("  ");
        padded.push_str(QR_ENVELOPE_KIND_1_BASIC);
        padded.push_str("\t\n");
        let flow = QrReviewFlow::new(&padded, dev(), ReviewDisplayLimits::default()).unwrap();
        assert_eq!(flow.request_id(), "req-kind-1-basic");
        // Transcript container plumbing.
        let empty = QrReviewTranscript::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty, QrReviewTranscript::default());
        let _ = ReviewPageList::new();
    }
    /// The basic approve transcript (buttons next/next/next/approve).
    /// Copied from the READ-ONLY specs/vectors/review-transcripts/kind-1-basic-approve.json.
    /// As in the C++ test, only the Content step's body is compared against
    /// this fixture: its Event step records the flat screen-review layout
    /// (`screen_review_vector`), not the display flow's split author lines.
    fn basic_approve_transcript() -> Vec<TranscriptStepFixture> {
        vec![
            TranscriptStepFixture {
                title: "Event",
                page_indicator: "Page 1/4",
                body_lines: vec![
                    "Kind 1",
                    "Created 1710000000",
                    "Author",
                    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                ],
                action_hint: "Next",
                body_line_styles: vec![],
                button: ReviewButton::Next,
                decision: None,
                approved_for_signing: false,
            },
            TranscriptStepFixture {
                title: "Content",
                page_indicator: "Page 2/4",
                body_lines: vec!["nSealr fixture: basic kind 1 event."],
                action_hint: "Next",
                body_line_styles: vec![],
                button: ReviewButton::Next,
                decision: None,
                approved_for_signing: false,
            },
            TranscriptStepFixture {
                title: "Tags",
                page_indicator: "Page 3/4",
                body_lines: vec!["No tags"],
                action_hint: "Next",
                body_line_styles: vec![],
                button: ReviewButton::Next,
                decision: None,
                approved_for_signing: false,
            },
            TranscriptStepFixture {
                title: "Decision",
                page_indicator: "Page 4/4",
                body_lines: vec!["Approve signing only if all pages match."],
                action_hint: "Approve / Reject",
                body_line_styles: vec![],
                button: ReviewButton::Approve,
                decision: Some(true),
                approved_for_signing: true,
            },
        ]
    }

    /// The detail-scroll approve transcript (buttons next/next/scroll/scroll/scroll/next/approve).
    /// Copied from the READ-ONLY specs/vectors/review-transcripts/kind-1-long-events-many-tags-detail-scroll-approve.json.
    fn detail_scroll_approve_transcript() -> Vec<TranscriptStepFixture> {
        vec![
            TranscriptStepFixture {
                title: "Event",
                page_indicator: "Page 1/4",
                body_lines: vec![
                    "Kind 1",
                    "Created 1710000120",
                    "Author",
                    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a",
                    "  b0f0b704075871aa",
                ],
                action_hint: "Next",
                body_line_styles: vec![
                    ReviewBodyLineStyle::Meta,
                    ReviewBodyLineStyle::Meta,
                    ReviewBodyLineStyle::Meta,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                ],
                button: ReviewButton::Next,
                decision: None,
                approved_for_signing: false,
            },
            TranscriptStepFixture {
                title: "Content",
                page_indicator: "Page 2/4",
                body_lines: vec![
                    "bytes: 281",
                    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                ],
                action_hint: "Next",
                body_line_styles: vec![
                    ReviewBodyLineStyle::Meta,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                ],
                button: ReviewButton::Next,
                decision: None,
                approved_for_signing: false,
            },
            TranscriptStepFixture {
                title: "Tags",
                page_indicator: "Page 3/4 Lines 1-9/29",
                body_lines: vec![
                    "Tag 1/9",
                    "e",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "  aaaaaaaaaaaaaaaa",
                    "root",
                    "Tag 2/9",
                    "t",
                    "nsealr",
                    "Tag 3/9",
                ],
                action_hint: "Next/Scroll",
                body_line_styles: vec![
                    ReviewBodyLineStyle::Meta,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Meta,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Meta,
                ],
                button: ReviewButton::Back,
                decision: None,
                approved_for_signing: false,
            },
            TranscriptStepFixture {
                title: "Tags",
                page_indicator: "Page 3/4 Lines 10-18/29",
                body_lines: vec![
                    "t", "hardware", "Tag 4/9", "t", "review", "Tag 5/9", "t", "security",
                    "Tag 6/9",
                ],
                action_hint: "Next/Scroll",
                body_line_styles: vec![
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Meta,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Meta,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Meta,
                ],
                button: ReviewButton::Back,
                decision: None,
                approved_for_signing: false,
            },
            TranscriptStepFixture {
                title: "Tags",
                page_indicator: "Page 3/4 Lines 19-27/29",
                body_lines: vec![
                    "t",
                    "qr",
                    "Tag 7/9",
                    "t",
                    "vault",
                    "Tag 8/9",
                    "t",
                    "companion",
                    "Tag 9/9",
                ],
                action_hint: "Next/Scroll",
                body_line_styles: vec![
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Meta,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Meta,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Value,
                    ReviewBodyLineStyle::Meta,
                ],
                button: ReviewButton::Back,
                decision: None,
                approved_for_signing: false,
            },
            TranscriptStepFixture {
                title: "Tags",
                page_indicator: "Page 3/4 Lines 28-29/29",
                body_lines: vec!["t", "test"],
                action_hint: "Next/Scroll",
                body_line_styles: vec![ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value],
                button: ReviewButton::Next,
                decision: None,
                approved_for_signing: false,
            },
            TranscriptStepFixture {
                title: "Decision",
                page_indicator: "Page 4/4",
                body_lines: vec!["Approve signing only if al", "l pages match."],
                action_hint: "Approve / Reject",
                body_line_styles: vec![ReviewBodyLineStyle::Normal, ReviewBodyLineStyle::Normal],
                button: ReviewButton::Approve,
                decision: Some(true),
                approved_for_signing: true,
            },
        ]
    }

    // Beyond the named C++ cases: error messages/Display, the bounded
    // transcript capacity, and the over-64-frame scan rejection.
    #[test]
    fn error_messages_capacity_and_frame_bounds() {
        for (error, expected) in [
            (
                QrReviewFlowError::NoScannedQr,
                "QR review flow requires a scanned request QR",
            ),
            (
                QrReviewFlowError::MixedScannedFrames,
                "QR review flow requires static nsealr1 or animated nsealr1a request QR",
            ),
            (
                QrReviewFlowError::Envelope(QrEnvelopeError::MissingPrefix),
                "QR envelope rejected",
            ),
            (
                QrReviewFlowError::Review(QrReviewError::Capacity),
                "QR review exceeds fixed review page capacity",
            ),
            (
                QrReviewFlowError::TrustedReview(TrustedReviewError::AlreadyTerminal),
                "review decision is already terminal",
            ),
            (
                QrReviewFlowError::Display(ReviewDisplayError::ZeroLimits),
                "review display limits must be non-zero",
            ),
            (
                QrReviewFlowError::ZeroMaxSteps,
                "QR review IO max steps must be non-zero",
            ),
            (
                QrReviewFlowError::NoTerminalDecision,
                "QR review IO did not reach a terminal decision",
            ),
            (
                QrReviewFlowError::Capacity,
                "QR review flow exceeds fixed capacity",
            ),
        ] {
            assert_eq!(error.message(), expected);
            assert_eq!(std::format!("{error}"), expected);
        }

        // The bounded transcript rejects a 33rd step.
        let transcript_seed = run_qr_review_transcript(
            QR_ENVELOPE_KIND_1_BASIC,
            &[ReviewButton::Next],
            dev(),
            ReviewDisplayLimits::default(),
        )
        .unwrap();
        let step = transcript_seed.step(0).clone();
        let mut transcript = QrReviewTranscript::new();
        for _ in 0..MAX_QR_REVIEW_TRANSCRIPT_STEPS {
            transcript.try_push(step.clone()).unwrap();
        }
        assert_eq!(
            transcript.try_push(step),
            Err(crate::text::TextError::TooLong),
        );
        assert_eq!(transcript.len(), MAX_QR_REVIEW_TRANSCRIPT_STEPS);
        assert_eq!(transcript.iter().count(), MAX_QR_REVIEW_TRANSCRIPT_STEPS);

        // More scanned frames than any animated envelope can carry (the C++
        // failed the frame-count check inside the animated decoder).
        let mut too_many = String::new();
        for _ in 0..(MAX_ANIMATED_QR_FRAME_COUNT + 1) {
            too_many.push_str("nsealr1a:x\n");
        }
        assert_eq!(
            QrReviewFlow::new(&too_many, dev(), ReviewDisplayLimits::default()),
            Err(QrReviewFlowError::Envelope(
                QrEnvelopeError::AnimatedTooManyFrames,
            )),
        );
    }
}
