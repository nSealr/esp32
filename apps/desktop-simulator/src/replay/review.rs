//! `review*` replay: the trusted-review pipeline over the shared vectors —
//! semantic review model (`review`), screen pages + approval digest
//! (`review-screens`), display-profile detail pages (`review-detail-pages`),
//! bounded display frames (`review-display-frames`), and full button-driven
//! review transcripts (`review-transcripts`).

use super::{
    arr_field, assert_review_pages, compact_bytes, load_value, obj_field, str_field, ReplayResult,
};
use nsealr_core::qr::envelope::{parse_qr_signing_request, QrSigningRequest};
use nsealr_core::review::controls::ReviewButton;
use nsealr_core::review::display::{render_review_page, ReviewDisplayLimits, ReviewPage};
use nsealr_core::review::qr::{
    build_qr_display_review_pages, build_qr_display_review_request, build_qr_review_pages,
    build_qr_trusted_review_request,
};
use nsealr_core::review::qr_flow::run_qr_review_transcript;
use nsealr_core::review::signer_identity::SignerIdentity;
use nsealr_core::review::trusted::TrustedReviewSession;
use serde_json::Value;

fn dev() -> SignerIdentity<'static> {
    SignerIdentity::development_fixture()
}

/// Parse the vector's embedded `request` object through the shared QR
/// signing-request parser (canonical compact serialization).
fn parse_request(value: &Value) -> Result<QrSigningRequest, String> {
    let request = obj_field(value, "request")?;
    parse_qr_signing_request(&compact_bytes(request))
        .map_err(|e| format!("parse_qr_signing_request: {e:?}"))
}

/// Resolve a sibling review-family vector by category + name.
fn sibling_vector(category: &str, name: &str) -> Result<Value, String> {
    load_value(
        &crate::vectors_root()
            .join(category)
            .join(format!("{name}.json")),
    )
}

/// Read a `limits` object into `ReviewDisplayLimits`; absent compact fields take
/// the shared defaults (exactly as the generated C++ vector header defaulted them).
fn limits_from(value: &Value) -> Result<ReviewDisplayLimits, String> {
    let defaults = ReviewDisplayLimits::default();
    let get = |key: &str, fallback: usize| -> Result<usize, String> {
        match value.get(key) {
            None => Ok(fallback),
            Some(v) => v
                .as_u64()
                .map(|n| n as usize)
                .ok_or_else(|| format!("limits.{key} not an unsigned integer")),
        }
    };
    Ok(ReviewDisplayLimits {
        max_title_chars: get("max_title_chars", defaults.max_title_chars)?,
        max_body_lines: get("max_body_lines", defaults.max_body_lines)?,
        max_line_chars: get("max_line_chars", defaults.max_line_chars)?,
        max_compact_body_lines: get("max_compact_body_lines", defaults.max_compact_body_lines)?,
        max_compact_line_chars: get("max_compact_line_chars", defaults.max_compact_line_chars)?,
    })
}

/// Map a vector button token to the physical `ReviewButton` (the on-device
/// mapping the C++ transcripts pinned: `scroll` is the Back button re-purposed
/// as scroll-down on scrollable pages).
fn button_from(token: &str) -> Result<ReviewButton, String> {
    match token {
        "next" => Ok(ReviewButton::Next),
        "back" | "scroll" => Ok(ReviewButton::Back),
        "approve" => Ok(ReviewButton::Approve),
        "reject" => Ok(ReviewButton::Reject),
        other => Err(format!("unknown button token '{other}'")),
    }
}

// --- review ---------------------------------------------------------------------

pub(super) fn replay_review(value: &Value) -> ReplayResult {
    let request = parse_request(value)?;
    let review = obj_field(value, "review")?;

    let kind = review
        .get("kind")
        .and_then(Value::as_i64)
        .ok_or("review.kind missing")?;
    if i64::from(request.event_template.kind) != kind {
        return Err(format!(
            "kind {} != review.kind {kind}",
            request.event_template.kind
        ));
    }
    let created_at = review
        .get("created_at")
        .and_then(Value::as_u64)
        .ok_or("review.created_at missing")?;
    if request.event_template.created_at != created_at {
        return Err("created_at != review.created_at".into());
    }
    // The reviewed author is the bound signer identity (requests never carry a
    // pubkey — the parser rejects them), i.e. the development fixture here.
    let author = str_field(review, "author_pubkey")?;
    if author != dev().public_key {
        return Err(format!(
            "review.author_pubkey {author} != development signer identity"
        ));
    }
    let content = str_field(review, "content")?;
    if request.content() != content.as_bytes() {
        return Err("content != review.content".into());
    }
    let content_bytes = review
        .get("content_utf8_bytes")
        .and_then(Value::as_u64)
        .ok_or("review.content_utf8_bytes missing")?;
    if request.content().len() as u64 != content_bytes {
        return Err("content byte length != review.content_utf8_bytes".into());
    }
    let tag_count = review
        .get("tag_count")
        .and_then(Value::as_u64)
        .ok_or("review.tag_count missing")?;
    if request.event_template.tag_count as u64 != tag_count {
        return Err("tag_count != review.tag_count".into());
    }
    let tags = arr_field(review, "tags")?;
    if tags.len() != request.event_template.tag_count {
        return Err("review.tags length != parsed tag count".into());
    }
    for (tag_index, want_tag) in tags.iter().enumerate() {
        let want_fields = want_tag
            .as_array()
            .ok_or_else(|| format!("review.tags[{tag_index}] not an array"))?;
        let got_fields: Vec<&[u8]> = request.tag(tag_index).collect();
        if got_fields.len() != want_fields.len() {
            return Err(format!("tag {tag_index}: field count mismatch"));
        }
        for (field_index, (got, want)) in got_fields.iter().zip(want_fields).enumerate() {
            let want = want
                .as_str()
                .ok_or_else(|| format!("tag {tag_index} field {field_index} not a string"))?;
            if *got != want.as_bytes() {
                return Err(format!("tag {tag_index} field {field_index} mismatch"));
            }
        }
    }
    Ok(())
}

// --- review-screens -------------------------------------------------------------

pub(super) fn replay_screen(value: &Value) -> ReplayResult {
    // The `review` model must hold for screen vectors too (same embedded request).
    replay_review(value)?;

    let request = parse_request(value)?;
    let screen = obj_field(value, "screen_review")?;
    let review_request = build_qr_trusted_review_request(&request, dev())
        .map_err(|e| format!("build_qr_trusted_review_request: {e:?}"))?;

    if review_request.request_id.as_str() != str_field(screen, "request_id")? {
        return Err("request_id != screen_review.request_id".into());
    }
    if review_request.approval_digest.as_str() != str_field(screen, "approval_digest")? {
        return Err("approval_digest != screen_review.approval_digest".into());
    }
    let pages = arr_field(screen, "pages")?;
    assert_review_pages("screen_review", review_request.pages.as_slice(), pages)
}

// --- review-detail-pages --------------------------------------------------------

pub(super) fn replay_detail_pages(value: &Value) -> ReplayResult {
    let source_name = str_field(value, "source_review_vector")?;
    let source = sibling_vector("review", source_name)?;
    let request = parse_request(&source)?;
    let limits = limits_from(obj_field(value, "limits")?)?;

    let review_request = build_qr_display_review_request(&request, dev(), limits)
        .map_err(|e| format!("build_qr_display_review_request: {e:?}"))?;
    if review_request.approval_digest.as_str() != str_field(value, "approval_digest")? {
        return Err("approval_digest != vector.approval_digest".into());
    }
    let pages = build_qr_display_review_pages(&request, dev(), limits)
        .map_err(|e| format!("build_qr_display_review_pages: {e:?}"))?;
    assert_review_pages("detail pages", pages.as_slice(), arr_field(value, "pages")?)
}

// --- review-display-frames ------------------------------------------------------

pub(super) fn replay_display_frame(value: &Value) -> ReplayResult {
    let source_name = str_field(value, "source_review_vector")?;
    let source = sibling_vector("review", source_name)?;
    let request = parse_request(&source)?;
    let limits = limits_from(obj_field(value, "limits")?)?;
    let page_index = value
        .get("page_index")
        .and_then(Value::as_u64)
        .ok_or("missing 'page_index'")? as usize;

    // Render the screen summary page at the vector's display bounds. When the
    // source exceeds the port's fixed screen-page capacities (the long-content
    // vector: 281-byte content > the 144-char line slot, 9 tags > the 10-line
    // page), fall back to the Content page's single source line — the request
    // content bounded to the line capacity. This mirrors the C++ suite's own
    // replay of this vector (test_host_core.cpp builds a representative long
    // line) and is provably lossless: content beyond the rendered window
    // (`max_body_lines * max_line_chars + 1` chars, far below 144) cannot
    // change the truncated frame.
    let frame = match build_qr_review_pages(&request, dev()) {
        Ok(pages) => {
            let total = pages.len();
            let page = pages
                .as_slice()
                .get(page_index)
                .ok_or_else(|| format!("page_index {page_index} out of range ({total} pages)"))?;
            let view = ReviewPage {
                title: page.title.as_str(),
                lines: page.lines.as_slice(),
                action: page.action,
                page_indicator: page.page_indicator.as_str(),
                body_line_styles: page.body_line_styles.as_slice(),
            };
            render_review_page(&view, page_index, total, limits)
                .map_err(|e| format!("render_review_page: {e:?}"))?
        }
        Err(nsealr_core::review::qr::QrReviewError::Capacity) if page_index == 1 => {
            let window = limits.max_body_lines * limits.max_line_chars + 1;
            let capacity = nsealr_core::review::types::MAX_REVIEW_PAGE_LINE_CHARS;
            if window > capacity {
                return Err(format!(
                    "render window {window} exceeds line capacity {capacity}: the bounded \
                     fallback would be lossy — re-triage this vector"
                ));
            }
            let content = core::str::from_utf8(request.content())
                .map_err(|_| "request content not UTF-8".to_string())?;
            let bounded_end = content
                .char_indices()
                .map(|(at, _)| at)
                .chain([content.len()])
                .take_while(|at| *at <= capacity)
                .last()
                .unwrap_or(0);
            let mut lines = nsealr_core::review::types::ReviewPageLines::new();
            lines
                .try_push(&content[..bounded_end])
                .map_err(|e| format!("push bounded content line: {e:?}"))?;
            let view = ReviewPage {
                title: "Content",
                lines: lines.as_slice(),
                action: nsealr_core::review::types::ReviewPageAction::Next,
                page_indicator: "",
                body_line_styles: &[],
            };
            // The screen layout is fixed at four pages (Event/Content/Tags/Decision).
            render_review_page(&view, page_index, 4, limits)
                .map_err(|e| format!("render_review_page (bounded): {e:?}"))?
        }
        Err(e) => return Err(format!("build_qr_review_pages: {e:?}")),
    };

    let want = obj_field(value, "frame")?;
    assert_display_frame("frame", &frame, want)
}

/// Assert a rendered `ReviewDisplayFrame` equals a vector frame object
/// (title, page_indicator, body_lines, action_hint).
fn assert_display_frame(
    ctx: &str,
    frame: &nsealr_core::review::display::ReviewDisplayFrame,
    want: &Value,
) -> ReplayResult {
    let eq = |field: &str, got: &str| -> ReplayResult {
        let want = str_field(want, field)?;
        if got == want {
            Ok(())
        } else {
            Err(format!("{ctx}: {field} '{got}' != '{want}'"))
        }
    };
    eq("title", frame.title.as_str())?;
    eq("page_indicator", frame.page_indicator.as_str())?;
    eq("action_hint", frame.action_hint.as_str())?;
    let want_lines = arr_field(want, "body_lines")?;
    let got_lines = frame.body_lines.as_slice();
    if got_lines.len() != want_lines.len() {
        return Err(format!(
            "{ctx}: body line count {} != {}",
            got_lines.len(),
            want_lines.len()
        ));
    }
    for (i, (got, want)) in got_lines.iter().zip(want_lines).enumerate() {
        let want = want
            .as_str()
            .ok_or_else(|| format!("{ctx}: body_lines[{i}] not a string"))?;
        if got.as_str() != want {
            return Err(format!(
                "{ctx}: body_lines[{i}] '{}' != '{want}'",
                got.as_str()
            ));
        }
    }
    Ok(())
}

// --- review-transcripts ---------------------------------------------------------

/// One expected transcript step decoded from the vector.
struct WantStep<'a> {
    frame: &'a Value,
    button: ReviewButton,
    decision: Option<bool>,
    approved_for_signing: bool,
}

fn want_steps_of(value: &Value) -> Result<Vec<WantStep<'_>>, String> {
    let steps = arr_field(value, "transcript")?;
    let buttons = arr_field(value, "buttons")?;
    if buttons.len() != steps.len() {
        return Err(format!(
            "vector buttons length {} != transcript length {}",
            buttons.len(),
            steps.len()
        ));
    }
    steps
        .iter()
        .zip(buttons)
        .enumerate()
        .map(|(i, (want, listed))| {
            let ctx = format!("transcript step {i}");
            let button = button_from(str_field(want, "button")?)?;
            let listed = listed
                .as_str()
                .ok_or_else(|| format!("{ctx}: buttons entry not a string"))
                .and_then(button_from)?;
            if button != listed {
                return Err(format!("{ctx}: step button != buttons[] entry"));
            }
            let decision = match want.get("decision") {
                Some(Value::Null) | None => None,
                Some(Value::Bool(b)) => Some(*b),
                Some(other) => return Err(format!("{ctx}: decision not a bool/null: {other}")),
            };
            let approved_for_signing = want
                .get("approved_for_signing")
                .and_then(Value::as_bool)
                .ok_or_else(|| format!("{ctx}: approved_for_signing missing"))?;
            Ok(WantStep {
                frame: obj_field(want, "frame")?,
                button,
                decision,
                approved_for_signing,
            })
        })
        .collect()
}

pub(super) fn replay_transcript(value: &Value) -> ReplayResult {
    let envelope = str_field(value, "qr_envelope")?;

    // The embedded request matches what the envelope decodes to (cross-field
    // consistency inside the vector itself), and parses through the shared parser.
    let request = {
        let mut json_buf = [0u8; nsealr_core::qr::limits::MAX_STATIC_QR_DECODED_JSON_BYTES];
        let decoded =
            nsealr_core::qr::envelope::decode_qr_envelope(envelope.as_bytes(), &mut json_buf)
                .map_err(|e| format!("decode_qr_envelope: {e:?}"))?;
        let got: Value = serde_json::from_slice(decoded.payload_json)
            .map_err(|e| format!("parse decoded envelope json: {e}"))?;
        super::assert_json_eq(
            "transcript qr_envelope decoded",
            &got,
            obj_field(value, "request")?,
        )?;
        parse_qr_signing_request(decoded.payload_json)
            .map_err(|e| format!("parse_qr_signing_request: {e:?}"))?
    };

    let approval_digest = str_field(value, "approval_digest")?;
    let want_steps = want_steps_of(value)?;

    match value.get("review_mode").and_then(Value::as_str) {
        // Screen mode (`review_mode` absent): the trusted session over the flat
        // screen pages (the layout the vector's `screen_review_vector` pins),
        // rendered at the shared default display limits.
        None => {
            let review_request = build_qr_trusted_review_request(&request, dev())
                .map_err(|e| format!("build_qr_trusted_review_request: {e:?}"))?;
            if review_request.approval_digest.as_str() != approval_digest {
                return Err("approval_digest != vector.approval_digest".into());
            }
            let mut session =
                TrustedReviewSession::new(review_request, ReviewDisplayLimits::default())
                    .map_err(|e| format!("TrustedReviewSession::new: {e:?}"))?;
            for (i, want) in want_steps.iter().enumerate() {
                let ctx = format!("transcript step {i}");
                let frame = session
                    .current_frame()
                    .map_err(|e| format!("{ctx}: current_frame: {e:?}"))?;
                assert_display_frame(&ctx, &frame, want.frame)?;
                let decision = session
                    .handle_button(want.button)
                    .map_err(|e| format!("{ctx}: handle_button: {e:?}"))?;
                if decision != want.decision {
                    return Err(format!(
                        "{ctx}: decision {decision:?} != {:?}",
                        want.decision
                    ));
                }
                if session.can_sign() != want.approved_for_signing {
                    return Err(format!("{ctx}: approved_for_signing mismatch"));
                }
            }
        }
        // Detail mode: the QR review flow over the display detail pages, at the
        // limits pinned by the referenced review-detail-pages vector.
        Some("detail") => {
            let detail_name = str_field(value, "detail_review_vector")?;
            let detail = sibling_vector("review-detail-pages", detail_name)?;
            let limits = limits_from(obj_field(&detail, "limits")?)?;

            let buttons: Vec<ReviewButton> = want_steps.iter().map(|w| w.button).collect();
            let transcript = run_qr_review_transcript(envelope, &buttons, dev(), limits)
                .map_err(|e| format!("run_qr_review_transcript: {e:?}"))?;
            let display_request = build_qr_display_review_request(&request, dev(), limits)
                .map_err(|e| format!("build_qr_display_review_request: {e:?}"))?;
            if display_request.approval_digest.as_str() != approval_digest {
                return Err("approval_digest != vector.approval_digest".into());
            }
            if transcript.len() != want_steps.len() {
                return Err(format!(
                    "transcript length {} != {}",
                    transcript.len(),
                    want_steps.len()
                ));
            }
            for (i, (step, want)) in transcript.iter().zip(&want_steps).enumerate() {
                let ctx = format!("transcript step {i}");
                assert_display_frame(&ctx, &step.frame, want.frame)?;
                if step.button != want.button {
                    return Err(format!("{ctx}: button mismatch"));
                }
                if step.decision != want.decision {
                    return Err(format!("{ctx}: decision mismatch"));
                }
                if step.approved_for_signing != want.approved_for_signing {
                    return Err(format!("{ctx}: approved_for_signing mismatch"));
                }
            }
        }
        Some(other) => return Err(format!("unknown review_mode '{other}'")),
    }
    Ok(())
}
