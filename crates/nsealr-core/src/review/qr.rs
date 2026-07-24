//! QR signing-request review builders — summary pages, scroll-windowed display
//! pages, and the SHA-256 approval digest binding them to the request.
//!
//! Ported from the C++ reference `host_core` sources `src/qr_review.cpp` +
//! `include/nsealr/qr_review.hpp` for behaviour parity:
//!
//! - **Summary pages** (`build_qr_review_pages`) — the four fixed
//!   Event/Content/Tags/Decision pages carrying the raw request text.
//! - **Display pages** (`build_qr_display_review_pages`) — the same sections
//!   rendered display-safe (non-ASCII and control codepoints escaped as
//!   `U+XXXX` / `\n`-style sequences), split into exact-width lines with
//!   two-space continuation indents, chunked into scroll windows of
//!   `max_compact_body_lines` lines with `"Page i/4 Lines a-b/t"` indicators
//!   and per-section logical page ids.
//! - **Approval digest** (`build_qr_trusted_review_request`) — SHA-256 over the
//!   canonical `{"event_template":…,"method":…,"pages":…,"request_id":…,
//!   "review":…,"version":…}` JSON. The C++ concatenated that JSON on the heap
//!   and hashed it one-shot; this port streams the identical bytes through the
//!   incremental [`Sha256`] hasher — same digest by construction.
//!
//! The C++ default-identity overloads map to passing
//! [`SignerIdentity::development_fixture`] explicitly. The C++ returned
//! unbounded `std::vector<TrustedReviewPage>`; this allocation-free port fills
//! the fixed-capacity [`ReviewPageList`] and reports inputs that exceed the
//! documented capacities as [`QrReviewError::Capacity`] (no C++ analogue).

use crate::hash::Sha256;
use crate::qr::envelope::QrSigningRequest;
use crate::review::display::{ReviewDisplayError, ReviewDisplayLimits};
use crate::review::signer_identity::{
    is_valid_nostr_public_key, SignerIdentity, SignerIdentityError,
};
use crate::review::trusted::{TrustedReviewError, TrustedReviewSession};
use crate::review::types::{
    ReviewBodyLineStyle, ReviewPageAction, ReviewPageLine, TrustedReviewApprovalDigest,
    TrustedReviewPage, TrustedReviewRequest, MAX_REVIEW_PAGE_LINES, MAX_REVIEW_PAGE_LINE_CHARS,
    MAX_REVIEW_PAGE_TITLE_CHARS,
};
use crate::text::FixedStr;
use core::fmt;

/// The fixed decision-page copy. Mirrors the C++ literal.
const DECISION_LINE: &str = "Approve signing only if all pages match.";

/// Maximum bytes of display-safe text for one escaped value: the 512-byte
/// content bound at the worst 6-bytes-per-source-byte escape ratio
/// (`"U+0001"` for a C0 control byte).
const MAX_SAFE_TEXT_BYTES: usize = 512 * 6;

/// Errors reported by the QR review builders. [`Self::message`] returns the
/// C++ exception text where one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrReviewError {
    /// The signer identity is not 64 lowercase hex characters. C++
    /// `SignerIdentityError`.
    InvalidSignerIdentity,
    /// A display-limits validation failure (zero limits from the C++
    /// `validate_display_page_limits`, or this port's capacity guard).
    Display(ReviewDisplayError),
    /// The request needs more pages/lines than the fixed capacities hold. No
    /// C++ analogue (unbounded heap vectors).
    Capacity,
    /// Request text (request id / content / tag field) was not valid UTF-8.
    /// Unreachable through the QR/serial decode paths, which validate UTF-8
    /// before parsing; no C++ analogue (`std::string` carried raw bytes).
    RequestNotUtf8,
    /// A trusted-review session construction failure (from
    /// [`begin_qr_trusted_review`]).
    TrustedReview(TrustedReviewError),
}

impl QrReviewError {
    /// The exact C++ exception message where one exists, or this port's text.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidSignerIdentity => SignerIdentityError.message(),
            Self::Display(inner) => inner.message(),
            Self::Capacity => "QR review exceeds fixed review page capacity",
            Self::RequestNotUtf8 => "QR review request text must be valid UTF-8",
            Self::TrustedReview(inner) => inner.message(),
        }
    }
}

impl fmt::Display for QrReviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// A fixed-capacity page list under construction (re-exported alias of the
/// shared type for readability).
pub use crate::review::types::ReviewPageList;

/// Requires a valid signer identity. Mirrors the C++
/// `require_valid_signer_identity` call sites.
fn require_identity(identity: SignerIdentity<'_>) -> Result<(), QrReviewError> {
    if is_valid_nostr_public_key(identity.public_key) {
        Ok(())
    } else {
        Err(QrReviewError::InvalidSignerIdentity)
    }
}

/// Mirrors the C++ `validate_display_page_limits` plus this port's capacity
/// guard (widths/line counts must fit the fixed page capacities).
fn validate_display_page_limits(limits: ReviewDisplayLimits) -> Result<(), QrReviewError> {
    if limits.max_title_chars == 0
        || limits.max_body_lines == 0
        || limits.max_line_chars == 0
        || limits.max_compact_body_lines == 0
        || limits.max_compact_line_chars == 0
    {
        return Err(QrReviewError::Display(ReviewDisplayError::ZeroLimits));
    }
    if limits.max_body_lines > MAX_REVIEW_PAGE_LINES
        || limits.max_compact_body_lines > MAX_REVIEW_PAGE_LINES
        || limits.max_line_chars > MAX_REVIEW_PAGE_LINE_CHARS
        || limits.max_compact_line_chars > MAX_REVIEW_PAGE_LINE_CHARS
        || limits.max_title_chars > MAX_REVIEW_PAGE_TITLE_CHARS
    {
        return Err(QrReviewError::Display(
            ReviewDisplayError::LimitsExceedCapacity,
        ));
    }
    Ok(())
}

/// UTF-8 view of request bytes (request id / content / tag fields).
fn str_of(bytes: &[u8]) -> Result<&str, QrReviewError> {
    core::str::from_utf8(bytes).map_err(|_| QrReviewError::RequestNotUtf8)
}

// --- Summary pages ------------------------------------------------------

/// One summary-page enumeration event (page boundaries and body lines).
enum SummaryEvent<'a> {
    /// A page begins.
    PageStart(&'static str, ReviewPageAction),
    /// One body line of the current page.
    Line(&'a str),
}

/// Enumerates the four summary pages line by line. Mirrors the C++
/// `review_pages_for` + `tag_lines` construction order exactly (the digest and
/// the returned pages are both generated from this single enumeration).
fn for_each_summary_event(
    request: &QrSigningRequest,
    identity: SignerIdentity<'_>,
    emit: &mut dyn FnMut(SummaryEvent<'_>) -> Result<(), QrReviewError>,
) -> Result<(), QrReviewError> {
    let mut number = FixedStr::<24>::new();

    emit(SummaryEvent::PageStart("Event", ReviewPageAction::Next))?;
    number.try_push_str("Kind ").expect("within capacity");
    number
        .try_push_usize(request.event_template.kind as usize)
        .expect("within capacity");
    emit(SummaryEvent::Line(number.as_str()))?;
    let mut created = FixedStr::<32>::new();
    created.try_push_str("Created ").expect("within capacity");
    push_u64(&mut created, request.event_template.created_at);
    emit(SummaryEvent::Line(created.as_str()))?;
    emit(SummaryEvent::Line("Author"))?;
    emit(SummaryEvent::Line(identity.public_key))?;

    emit(SummaryEvent::PageStart("Content", ReviewPageAction::Next))?;
    emit(SummaryEvent::Line(str_of(request.content())?))?;

    emit(SummaryEvent::PageStart("Tags", ReviewPageAction::Next))?;
    let tag_count = request.event_template.tag_count;
    if tag_count == 0 {
        emit(SummaryEvent::Line("No tags"))?;
    } else {
        for tag_index in 0..tag_count {
            let mut header = FixedStr::<48>::new();
            header.try_push_str("Tag ").expect("within capacity");
            header
                .try_push_usize(tag_index + 1)
                .expect("within capacity");
            header.try_push_str("/").expect("within capacity");
            header.try_push_usize(tag_count).expect("within capacity");
            emit(SummaryEvent::Line(header.as_str()))?;
            let mut field_count = 0usize;
            for field in request.tag(tag_index) {
                emit(SummaryEvent::Line(str_of(field)?))?;
                field_count += 1;
            }
            if field_count == 0 {
                emit(SummaryEvent::Line("empty tag"))?;
            }
        }
    }

    let decision_start = SummaryEvent::PageStart("Decision", ReviewPageAction::ApproveOrReject);
    emit(decision_start)?;
    emit(SummaryEvent::Line(DECISION_LINE))?;
    Ok(())
}

/// Builds the four summary review pages. Mirrors the C++
/// `build_qr_review_pages` (the C++ default-identity overload maps to passing
/// [`SignerIdentity::development_fixture`]).
///
/// # Errors
///
/// [`QrReviewError::InvalidSignerIdentity`], [`QrReviewError::Capacity`] (a
/// line or page beyond the fixed capacities), [`QrReviewError::RequestNotUtf8`].
pub fn build_qr_review_pages(
    request: &QrSigningRequest,
    identity: SignerIdentity<'_>,
) -> Result<ReviewPageList, QrReviewError> {
    require_identity(identity)?;
    let mut pages = ReviewPageList::new();
    for_each_summary_event(request, identity, &mut |event| match event {
        SummaryEvent::PageStart(title, action) => {
            let mut page = TrustedReviewPage::new();
            page.title = title.parse().expect("fixed titles within capacity");
            page.action = action;
            pages.try_push(page).map_err(|_| QrReviewError::Capacity)
        }
        SummaryEvent::Line(line) => {
            let index = pages.len() - 1;
            pages
                .line_push(index, line)
                .map_err(|_| QrReviewError::Capacity)
        }
    })?;
    Ok(pages)
}

// --- Canonical approval digest ------------------------------------------

/// Streams canonical JSON bytes into the incremental hasher. The escaping
/// mirrors the C++ `json_string` byte for byte.
struct DigestWriter {
    hasher: Sha256,
}

impl DigestWriter {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    fn push_str(&mut self, text: &str) {
        self.hasher.update(text.as_bytes());
    }

    /// Appends a JSON string literal with the C++ `json_string` escaping:
    /// `"`/`\` and the named control escapes, `\u00XX` for other control
    /// bytes, every other byte verbatim.
    fn push_json_string(&mut self, value: &str) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.hasher.update(b"\"");
        for byte in value.bytes() {
            match byte {
                b'"' => self.hasher.update(b"\\\""),
                b'\\' => self.hasher.update(b"\\\\"),
                0x08 => self.hasher.update(b"\\b"),
                0x0c => self.hasher.update(b"\\f"),
                b'\n' => self.hasher.update(b"\\n"),
                b'\r' => self.hasher.update(b"\\r"),
                b'\t' => self.hasher.update(b"\\t"),
                byte if byte < 0x20 => {
                    self.hasher.update(b"\\u00");
                    self.hasher
                        .update(&[HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]]);
                }
                byte => self.hasher.update(&[byte]),
            }
        }
        self.hasher.update(b"\"");
    }

    fn push_decimal(&mut self, value: u64) {
        let mut text = FixedStr::<24>::new();
        push_u64(&mut text, value);
        self.push_str(text.as_str());
    }
}

/// Appends the decimal rendering of a u64 to a `FixedStr` (usize push only
/// covers usize; created_at is u64 on every target).
fn push_u64<const N: usize>(out: &mut FixedStr<N>, value: u64) {
    let mut digits = [0u8; 20];
    let mut position = digits.len();
    let mut remaining = value;
    loop {
        position -= 1;
        digits[position] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    out.try_push_str(core::str::from_utf8(&digits[position..]).unwrap_or(""))
        .expect("within documented capacity");
}

/// Streams the canonical tags JSON array. Mirrors the C++ `json_tags` over
/// `json_string_array`.
fn push_tags_json(
    writer: &mut DigestWriter,
    request: &QrSigningRequest,
) -> Result<(), QrReviewError> {
    writer.push_str("[");
    for tag_index in 0..request.event_template.tag_count {
        if tag_index != 0 {
            writer.push_str(",");
        }
        writer.push_str("[");
        for (field_index, field) in request.tag(tag_index).enumerate() {
            if field_index != 0 {
                writer.push_str(",");
            }
            writer.push_json_string(str_of(field)?);
        }
        writer.push_str("]");
    }
    writer.push_str("]");
    Ok(())
}

/// Streams the canonical pages JSON array from the summary enumeration.
/// Mirrors the C++ `json_pages` over the `review_pages_for` result.
/// Infallible: the digest writer never errors and every request text was
/// UTF-8-validated by the content/tags streaming that precedes this call in
/// [`qr_approval_digest`].
fn push_pages_json(
    writer: &mut DigestWriter,
    request: &QrSigningRequest,
    identity: SignerIdentity<'_>,
) {
    writer.push_str("[");
    let mut page_index = 0usize;
    let mut line_index = 0usize;
    let mut pending_title: Option<(&'static str, ReviewPageAction)> = None;
    // The enumeration is PageStart, Line... — the title comes first but the
    // C++ serialises {"action":…,"lines":[…],"title":…}, so the title is held
    // until the page's lines are closed.
    let close_lines =
        |writer: &mut DigestWriter, pending: &mut Option<(&'static str, ReviewPageAction)>| {
            if let Some((title, _)) = pending.take() {
                writer.push_str("],\"title\":");
                writer.push_json_string(title);
                writer.push_str("}");
            }
        };
    for_each_summary_event(request, identity, &mut |event| {
        match event {
            SummaryEvent::PageStart(title, action) => {
                close_lines(writer, &mut pending_title);
                if page_index != 0 {
                    writer.push_str(",");
                }
                page_index += 1;
                line_index = 0;
                writer.push_str("{\"action\":");
                writer.push_json_string(match action {
                    ReviewPageAction::Next => "next",
                    ReviewPageAction::ApproveOrReject => "approve_or_reject",
                });
                writer.push_str(",\"lines\":[");
                pending_title = Some((title, action));
            }
            SummaryEvent::Line(line) => {
                if line_index != 0 {
                    writer.push_str(",");
                }
                line_index += 1;
                writer.push_json_string(line);
            }
        }
        Ok(())
    })
    .expect("request texts validated by the earlier content/tags streaming");
    close_lines(writer, &mut pending_title);
    writer.push_str("]");
}

/// Computes the canonical approval digest for the request under `identity`.
/// Mirrors the C++ `canonical_approval_payload` + `sha256_hex` byte for byte
/// (key order, escaping, and number rendering identical).
fn qr_approval_digest(
    request: &QrSigningRequest,
    identity: SignerIdentity<'_>,
) -> Result<TrustedReviewApprovalDigest, QrReviewError> {
    let content = str_of(request.content())?;
    let mut writer = DigestWriter::new();
    writer.push_str("{\"event_template\":{");
    writer.push_str("\"content\":");
    writer.push_json_string(content);
    writer.push_str(",\"created_at\":");
    writer.push_decimal(request.event_template.created_at);
    writer.push_str(",\"kind\":");
    writer.push_decimal(request.event_template.kind as u64);
    writer.push_str(",\"tags\":");
    push_tags_json(&mut writer, request)?;
    writer.push_str("},\"method\":");
    writer.push_json_string(request.method());
    writer.push_str(",\"pages\":");
    push_pages_json(&mut writer, request, identity);
    writer.push_str(",\"request_id\":");
    writer.push_json_string(str_of(request.request_id())?);
    writer.push_str(",\"review\":{");
    writer.push_str("\"author_pubkey\":");
    writer.push_json_string(identity.public_key);
    writer.push_str(",\"content\":");
    writer.push_json_string(content);
    writer.push_str(",\"content_utf8_bytes\":");
    writer.push_decimal(request.content().len() as u64);
    writer.push_str(",\"created_at\":");
    writer.push_decimal(request.event_template.created_at);
    writer.push_str(",\"kind\":");
    writer.push_decimal(request.event_template.kind as u64);
    writer.push_str(",\"tag_count\":");
    writer.push_decimal(request.event_template.tag_count as u64);
    writer.push_str(",\"tags\":");
    push_tags_json(&mut writer, request)?;
    writer.push_str("},\"version\":");
    writer.push_decimal(request.version as u64);
    writer.push_str("}");
    let hex = writer.hasher.finalize_hex();
    Ok(core::str::from_utf8(&hex)
        .expect("hex digest is ASCII")
        .parse()
        .expect("64 hex chars fit the digest alias"))
}

/// Builds the trusted-review request (summary pages + approval digest).
/// Mirrors the C++ `build_qr_trusted_review_request`.
///
/// # Errors
///
/// See [`QrReviewError`].
pub fn build_qr_trusted_review_request(
    request: &QrSigningRequest,
    identity: SignerIdentity<'_>,
) -> Result<TrustedReviewRequest, QrReviewError> {
    require_identity(identity)?;
    let pages = build_qr_review_pages(request, identity)?;
    let digest = qr_approval_digest(request, identity)?;
    Ok(TrustedReviewRequest {
        request_id: str_of(request.request_id())?
            .parse()
            .map_err(|_| QrReviewError::Capacity)?,
        approval_digest: digest,
        pages,
    })
}

// --- Display pages ------------------------------------------------------

/// Display-safe escaped text for one value (pure ASCII by construction).
struct SafeText {
    bytes: [u8; MAX_SAFE_TEXT_BYTES],
    len: usize,
}

impl SafeText {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_SAFE_TEXT_BYTES],
            len: 0,
        }
    }

    fn push(&mut self, text: &str) {
        self.bytes[self.len..self.len + text.len()].copy_from_slice(text.as_bytes());
        self.len += text.len();
    }

    fn push_byte(&mut self, byte: u8) {
        self.bytes[self.len] = byte;
        self.len += 1;
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

/// Escapes `text` for display safety. Mirrors the C++ `display_safe_text`:
/// named escapes for the C0 controls with JSON names, printable ASCII
/// verbatim, everything else as an uppercase `U+XXXX` escape (minimum four hex
/// digits). The input is a valid `&str`, so the C++ replacement-codepoint
/// branch for invalid UTF-8 is unreachable here (the decode paths validate
/// UTF-8 before any text reaches the review layer).
fn display_safe_text(text: &str, out: &mut SafeText) {
    out.len = 0;
    for ch in text.chars() {
        match ch {
            '\n' => out.push("\\n"),
            '\t' => out.push("\\t"),
            '\r' => out.push("\\r"),
            '\u{8}' => out.push("\\b"),
            '\u{c}' => out.push("\\f"),
            // The C++ `display_glyph_ascii` case list enumerates exactly the
            // printable ASCII range (letters, digits, space, and all 32
            // punctuation characters).
            ' '..='~' => out.push_byte(ch as u8),
            _ => {
                // The C++ `append_codepoint_escape`: "U+" + uppercase hex,
                // zero-padded to at least four digits.
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                let mut buffer = [0u8; 8];
                let mut size = 0usize;
                let mut value = ch as u32;
                loop {
                    buffer[size] = HEX[(value & 0x0f) as usize];
                    size += 1;
                    value >>= 4;
                    if value == 0 {
                        break;
                    }
                }
                while size < 4 {
                    buffer[size] = b'0';
                    size += 1;
                }
                out.push("U+");
                while size > 0 {
                    size -= 1;
                    out.push_byte(buffer[size]);
                }
            }
        }
    }
}

/// One styled display line for a section.
type OnStyledLine<'c> = dyn FnMut(&str, ReviewBodyLineStyle) -> Result<(), QrReviewError> + 'c;

/// Emits the exact-width splits of `value` (already display-safe ASCII) as
/// Value-styled lines with a two-space continuation indent. Mirrors the C++
/// `append_tag_item_lines` (which skips empty values entirely).
fn emit_tag_item_lines(
    safe_value: &str,
    width: usize,
    emit: &mut OnStyledLine<'_>,
) -> Result<(), QrReviewError> {
    if safe_value.is_empty() {
        return Ok(());
    }
    let continuation_indent = "  ";
    let continuation_width = if width > continuation_indent.len() {
        width - continuation_indent.len()
    } else {
        width
    };
    let bytes = safe_value.as_bytes();
    let mut position = 0usize;
    let mut first_line = true;
    while position < bytes.len() {
        let line_width = if first_line {
            width
        } else {
            continuation_width
        };
        let count = line_width.min(bytes.len() - position);
        let mut line = ReviewPageLine::new();
        if !first_line && width > continuation_indent.len() {
            line.try_push_str(continuation_indent)
                .map_err(|_| QrReviewError::Capacity)?;
        }
        line.try_push_str(&safe_value[position..position + count])
            .map_err(|_| QrReviewError::Capacity)?;
        emit(line.as_str(), ReviewBodyLineStyle::Value)?;
        position += count;
        first_line = false;
    }
    Ok(())
}

/// Emits the exact-width splits of `value` without indent. Mirrors the C++
/// `split_exact_display_lines` + `append_split_value_lines` (an empty value
/// emits one empty line).
fn emit_split_value_lines(
    safe_value: &str,
    width: usize,
    style: ReviewBodyLineStyle,
    emit: &mut OnStyledLine<'_>,
) -> Result<(), QrReviewError> {
    if safe_value.is_empty() {
        return emit("", style);
    }
    let bytes = safe_value.as_bytes();
    let mut position = 0usize;
    while position < bytes.len() {
        let count = width.min(bytes.len() - position);
        emit(&safe_value[position..position + count], style)?;
        position += count;
    }
    Ok(())
}

/// The three scrollable detail sections (Decision is fixed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetailSection {
    Event,
    Content,
    Tags,
}

/// Enumerates one detail section's styled lines. Mirrors the C++
/// `detailed_event_lines` / `detailed_content_lines` / `detailed_tag_lines`.
fn for_each_detail_line(
    section: DetailSection,
    request: &QrSigningRequest,
    identity: SignerIdentity<'_>,
    limits: ReviewDisplayLimits,
    emit: &mut OnStyledLine<'_>,
) -> Result<(), QrReviewError> {
    let width = limits.max_compact_line_chars;
    let mut safe = SafeText::new();
    match section {
        DetailSection::Event => {
            let mut kind = FixedStr::<24>::new();
            kind.try_push_str("Kind ").expect("within capacity");
            kind.try_push_usize(request.event_template.kind as usize)
                .expect("within capacity");
            emit(kind.as_str(), ReviewBodyLineStyle::Meta)?;
            let mut created = FixedStr::<32>::new();
            created.try_push_str("Created ").expect("within capacity");
            push_u64(&mut created, request.event_template.created_at);
            emit(created.as_str(), ReviewBodyLineStyle::Meta)?;
            emit("Author", ReviewBodyLineStyle::Meta)?;
            display_safe_text(identity.public_key, &mut safe);
            emit_tag_item_lines(safe.as_str(), width, emit)?;
        }
        DetailSection::Content => {
            let content = str_of(request.content())?;
            if content.is_empty() {
                emit("empty content", ReviewBodyLineStyle::Meta)?;
                return Ok(());
            }
            display_safe_text(content, &mut safe);
            if safe.len <= width {
                emit(safe.as_str(), ReviewBodyLineStyle::Normal)?;
                return Ok(());
            }
            let mut meta = FixedStr::<32>::new();
            meta.try_push_str("bytes: ").expect("within capacity");
            meta.try_push_usize(request.content().len())
                .expect("within capacity");
            emit(meta.as_str(), ReviewBodyLineStyle::Meta)?;
            emit_split_value_lines(safe.as_str(), width, ReviewBodyLineStyle::Value, emit)?;
        }
        DetailSection::Tags => {
            let tag_count = request.event_template.tag_count;
            if tag_count == 0 {
                emit("No tags", ReviewBodyLineStyle::Normal)?;
                return Ok(());
            }
            for tag_index in 0..tag_count {
                let mut header = FixedStr::<48>::new();
                header.try_push_str("Tag ").expect("within capacity");
                header
                    .try_push_usize(tag_index + 1)
                    .expect("within capacity");
                header.try_push_str("/").expect("within capacity");
                header.try_push_usize(tag_count).expect("within capacity");
                emit(header.as_str(), ReviewBodyLineStyle::Meta)?;
                let mut field_count = 0usize;
                for field in request.tag(tag_index) {
                    display_safe_text(str_of(field)?, &mut safe);
                    emit_tag_item_lines(safe.as_str(), width, emit)?;
                    field_count += 1;
                }
                if field_count == 0 {
                    emit("empty tag", ReviewBodyLineStyle::Value)?;
                }
            }
        }
    }
    Ok(())
}

/// Builds the `"Page i/n"` or `"Page i/n Lines a-b/t"` logical indicator.
/// Mirrors the two C++ `logical_page_indicator` overloads. Infallible: the
/// logical index/count are at most 4, and the line numbers are bounded by the
/// page capacity (at most `MAX_TRUSTED_REVIEW_PAGES * MAX_REVIEW_PAGE_LINES` =
/// 120 lines), so the worst render (`"Page 3/4 Lines 109-117/120"`, 26 bytes)
/// fits the 32-byte indicator capacity.
fn logical_page_indicator(
    page_index: usize,
    page_count: usize,
    lines: Option<(usize, usize, usize)>,
) -> FixedStr<{ crate::review::types::MAX_REVIEW_PAGE_INDICATOR_CHARS }> {
    let mut indicator = FixedStr::new();
    let expectation = "within documented indicator capacity";
    indicator.try_push_str("Page ").expect(expectation);
    indicator.try_push_usize(page_index).expect(expectation);
    indicator.try_push_str("/").expect(expectation);
    indicator.try_push_usize(page_count).expect(expectation);
    if let Some((first_line, last_line, line_count)) = lines {
        if line_count == 0 || (first_line == 1 && last_line >= line_count) {
            return indicator;
        }
        indicator.try_push_str(" Lines ").expect(expectation);
        indicator.try_push_usize(first_line).expect(expectation);
        indicator.try_push_str("-").expect(expectation);
        indicator.try_push_usize(last_line).expect(expectation);
        indicator.try_push_str("/").expect(expectation);
        indicator.try_push_usize(line_count).expect(expectation);
    }
    indicator
}

/// Appends one section's scroll-windowed display pages. Mirrors the C++
/// `append_display_pages` (two passes over the same pure enumeration replace
/// the C++ intermediate `StyledReviewLines` heap vector: pass one counts the
/// lines, pass two chunks them into pages).
fn append_section_pages(
    pages: &mut ReviewPageList,
    section: DetailSection,
    request: &QrSigningRequest,
    identity: SignerIdentity<'_>,
    limits: ReviewDisplayLimits,
) -> Result<(), QrReviewError> {
    let (title, logical_page_index) = match section {
        DetailSection::Event => ("Event", 1),
        DetailSection::Content => ("Content", 2),
        DetailSection::Tags => ("Tags", 3),
    };
    let logical_page_count = 4usize;
    let mut total = 0usize;
    for_each_detail_line(section, request, identity, limits, &mut |_, _| {
        total += 1;
        Ok(())
    })?;
    // Every section enumerator emits at least one line (each has a non-empty
    // fallback), so the C++ empty-body fallback page (a single "" line) is
    // unreachable here and `total` is always positive.
    let lines_per_screen = limits.max_compact_body_lines;

    // Pass two: open a page every `lines_per_screen` lines.
    let mut emitted = 0usize;
    for_each_detail_line(section, request, identity, limits, &mut |line, style| {
        if emitted.is_multiple_of(lines_per_screen) {
            let first_line = emitted + 1;
            let last_line = (emitted + lines_per_screen).min(total);
            let mut page = TrustedReviewPage::new();
            page.title = title.parse().expect("fixed titles within capacity");
            page.action = ReviewPageAction::Next;
            page.page_indicator = logical_page_indicator(
                logical_page_index,
                logical_page_count,
                Some((first_line, last_line, total)),
            );
            page.logical_page_id = title.parse().expect("fixed titles within capacity");
            pages.try_push(page).map_err(|_| QrReviewError::Capacity)?;
        }
        let index = pages.len() - 1;
        pages
            .line_push_styled(index, line, style)
            .map_err(|_| QrReviewError::Capacity)?;
        emitted += 1;
        Ok(())
    })?;
    Ok(())
}

/// Builds the scroll-windowed display review pages. Mirrors the C++
/// `build_qr_display_review_pages` (the C++ default-identity overload maps to
/// passing [`SignerIdentity::development_fixture`]).
///
/// # Errors
///
/// See [`QrReviewError`]; validation order matches the C++ (limits, then
/// identity).
pub fn build_qr_display_review_pages(
    request: &QrSigningRequest,
    identity: SignerIdentity<'_>,
    limits: ReviewDisplayLimits,
) -> Result<ReviewPageList, QrReviewError> {
    validate_display_page_limits(limits)?;
    require_identity(identity)?;

    let mut pages = ReviewPageList::new();
    append_section_pages(&mut pages, DetailSection::Event, request, identity, limits)?;
    append_section_pages(
        &mut pages,
        DetailSection::Content,
        request,
        identity,
        limits,
    )?;
    append_section_pages(&mut pages, DetailSection::Tags, request, identity, limits)?;

    let mut decision = TrustedReviewPage::new();
    decision.title = "Decision".parse().expect("within capacity");
    decision.action = ReviewPageAction::ApproveOrReject;
    decision.page_indicator = logical_page_indicator(4, 4, None);
    decision.logical_page_id = "Decision".parse().expect("within capacity");
    let mut lines = crate::review::types::ReviewPageLines::new();
    lines
        .try_push(DECISION_LINE)
        .map_err(|_| QrReviewError::Capacity)?;
    decision.lines = lines;
    pages
        .try_push(decision)
        .map_err(|_| QrReviewError::Capacity)?;
    Ok(pages)
}

/// Builds the display trusted-review request: the summary-page digest with the
/// display pages swapped in. Mirrors the C++ `build_qr_display_review_request`
/// (which built and then discarded the summary pages; this port streams their
/// canonical JSON straight into the digest without materialising them, so the
/// summary-page storage capacity never constrains the display path).
///
/// # Errors
///
/// See [`QrReviewError`].
pub fn build_qr_display_review_request(
    request: &QrSigningRequest,
    identity: SignerIdentity<'_>,
    limits: ReviewDisplayLimits,
) -> Result<TrustedReviewRequest, QrReviewError> {
    require_identity(identity)?;
    let digest = qr_approval_digest(request, identity)?;
    Ok(TrustedReviewRequest {
        request_id: str_of(request.request_id())?
            .parse()
            .map_err(|_| QrReviewError::Capacity)?,
        approval_digest: digest,
        pages: build_qr_display_review_pages(request, identity, limits)?,
    })
}

/// Begins a trusted review session over the display review request. Mirrors
/// the C++ `begin_qr_trusted_review`.
///
/// # Errors
///
/// See [`QrReviewError`].
pub fn begin_qr_trusted_review(
    request: &QrSigningRequest,
    identity: SignerIdentity<'_>,
    limits: ReviewDisplayLimits,
) -> Result<TrustedReviewSession, QrReviewError> {
    let review_request = build_qr_display_review_request(request, identity, limits)?;
    TrustedReviewSession::new(review_request, limits).map_err(QrReviewError::TrustedReview)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::approval_gate::ApprovalDecision;
    use crate::qr::envelope::{decode_qr_envelope, parse_qr_signing_request};
    use crate::qr::limits::MAX_STATIC_QR_DECODED_JSON_BYTES;
    use crate::review::controls::ReviewButton;
    use crate::review::signer_identity::DEVELOPMENT_FIXTURE_PUBLIC_KEY;
    use crate::review::test_fixtures::{
        any_page_line_contains, basic_trusted_review_request, frame_lines_contain,
        joined_lines_for_title, page_count_with_title, t_display_s3_review_limits,
        tagged_trusted_review_request, QR_ENVELOPE_KIND_1_BASIC,
    };
    use std::string::String;
    use std::vec;
    use std::vec::Vec;

    /// Parses a request from raw JSON (the C++ `QrEnvelope{"ignored", json}`
    /// shortcut; the envelope payload text is unused by the parser).
    fn parse(json: &str) -> QrSigningRequest {
        parse_qr_signing_request(json.as_bytes()).unwrap()
    }

    /// Decodes the shared basic envelope and parses its request (the C++
    /// `parse_qr_signing_request(decode_qr_envelope(kQrEnvelopeKind1Basic))`).
    fn parse_basic_envelope() -> QrSigningRequest {
        let mut json = [0u8; MAX_STATIC_QR_DECODED_JSON_BYTES];
        let envelope = decode_qr_envelope(QR_ENVELOPE_KIND_1_BASIC.as_bytes(), &mut json).unwrap();
        parse_qr_signing_request(envelope.payload_json).unwrap()
    }

    fn dev() -> SignerIdentity<'static> {
        SignerIdentity::development_fixture()
    }

    /// The C++ `assert_trusted_review_pages` (title, lines, action only).
    fn assert_summary_pages(actual: &ReviewPageList, expected: &TrustedReviewRequest) {
        let expected_pages = expected.pages.as_slice();
        assert_eq!(actual.len(), expected_pages.len());
        for (page, expected_page) in actual.as_slice().iter().zip(expected_pages) {
            assert_eq!(page.title, expected_page.title);
            assert_eq!(page.lines, expected_page.lines);
            assert_eq!(page.action, expected_page.action);
        }
    }

    // Port of the C++ `test_qr_review_pages_match_shared_basic_vector`.
    #[test]
    fn review_pages_match_shared_basic_vector() {
        let request = parse_basic_envelope();
        let pages = build_qr_review_pages(&request, dev()).unwrap();
        assert_summary_pages(&pages, &basic_trusted_review_request());
    }

    // Port of the C++ `test_qr_trusted_review_request_matches_shared_basic_vector`.
    #[test]
    fn trusted_review_request_matches_shared_basic_vector() {
        let request = parse_basic_envelope();
        let review_request = build_qr_trusted_review_request(&request, dev()).unwrap();
        let expected = basic_trusted_review_request();

        assert_eq!(review_request.request_id, expected.request_id);
        assert_eq!(review_request.approval_digest, expected.approval_digest);
        assert_summary_pages(&review_request.pages, &expected);
    }

    /// The tagged request JSON the C++ tests embed inline (matching the
    /// READ-ONLY specs/vectors/review-screens/kind-1-tags.json request).
    const TAGGED_REQUEST_JSON: &str = "{\"version\":1,\"request_id\":\"req-kind-1-tags\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000060,\"kind\":1,\"tags\":[[\"p\",\"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa\",\"\",\"mention\"],[\"t\",\"nsealr\"]],\"content\":\"nSealr fixture: tagged kind 1 event.\"}}}";

    // Port of the C++ `test_qr_review_pages_match_shared_tagged_vector`.
    #[test]
    fn review_pages_match_shared_tagged_vector() {
        let request = parse(TAGGED_REQUEST_JSON);
        let pages = build_qr_review_pages(&request, dev()).unwrap();
        assert_summary_pages(&pages, &tagged_trusted_review_request());
    }

    // Port of the C++ `test_qr_trusted_review_request_matches_shared_tagged_vector`.
    #[test]
    fn trusted_review_request_matches_shared_tagged_vector() {
        let request = parse(TAGGED_REQUEST_JSON);
        let review_request = build_qr_trusted_review_request(&request, dev()).unwrap();
        let expected = tagged_trusted_review_request();

        assert_eq!(review_request.request_id, expected.request_id);
        assert_eq!(review_request.approval_digest, expected.approval_digest);
        assert_summary_pages(&review_request.pages, &expected);
    }

    // Port of the C++ `test_qr_review_binds_configured_signer_identity`.
    #[test]
    fn review_binds_configured_signer_identity() {
        let alternate_pubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let alternate_identity = SignerIdentity {
            public_key: alternate_pubkey,
        };
        let request = parse_basic_envelope();

        let default_review = build_qr_trusted_review_request(&request, dev()).unwrap();
        let alternate_review =
            build_qr_trusted_review_request(&request, alternate_identity).unwrap();

        assert_eq!(alternate_review.request_id, default_review.request_id);
        assert_ne!(
            alternate_review.approval_digest,
            default_review.approval_digest
        );
        let front = &alternate_review.pages.as_slice()[0];
        assert!(front
            .lines
            .as_slice()
            .iter()
            .any(|line| line.as_str().contains(alternate_pubkey)));
        assert!(!front
            .lines
            .as_slice()
            .iter()
            .any(|line| line.as_str().contains(DEVELOPMENT_FIXTURE_PUBLIC_KEY)));

        let display_pages = build_qr_display_review_pages(
            &request,
            alternate_identity,
            t_display_s3_review_limits(),
        )
        .unwrap();
        let event_text = joined_lines_for_title(display_pages.as_slice(), "Event");
        assert!(event_text.contains(&alternate_pubkey[..48]));
        assert!(event_text.contains(&alternate_pubkey[48..]));
        assert!(!event_text.contains(&DEVELOPMENT_FIXTURE_PUBLIC_KEY[..48]));

        assert_eq!(
            build_qr_trusted_review_request(
                &request,
                SignerIdentity {
                    public_key: "not-a-pubkey",
                },
            ),
            Err(QrReviewError::InvalidSignerIdentity),
        );
        assert_eq!(
            QrReviewError::InvalidSignerIdentity.message(),
            "signer public key must be 64 lowercase hex characters",
        );
    }

    // Port of the C++ `test_qr_display_review_pages_show_full_tag_values_without_ellipsis`.
    #[test]
    fn display_pages_show_full_tag_values_without_ellipsis() {
        let pubkey = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
        let request = parse(TAGGED_REQUEST_JSON);

        let pages =
            build_qr_display_review_pages(&request, dev(), t_display_s3_review_limits()).unwrap();
        let tag_text = joined_lines_for_title(pages.as_slice(), "Tags");

        assert_eq!(page_count_with_title(pages.as_slice(), "Tags"), 1);
        assert!(!tag_text.contains("..."));
        assert!(tag_text.contains(&pubkey[..48]));
        assert!(tag_text.contains(&pubkey[48..]));
        assert!(tag_text.contains("nsealr"));
        let last = &pages.as_slice()[pages.len() - 1];
        assert_eq!(last.title, "Decision");
        assert!(!last
            .lines
            .as_slice()
            .iter()
            .any(|line| line.as_str().contains("warning")));
        assert!(!last
            .lines
            .as_slice()
            .iter()
            .any(|line| line.as_str().contains("Warning")));
    }

    // Port of the C++ `test_qr_display_review_pages_group_logical_sections_with_compact_styles`.
    #[test]
    fn display_pages_group_logical_sections_with_compact_styles() {
        let pubkey = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
        let request = parse(TAGGED_REQUEST_JSON);

        let pages =
            build_qr_display_review_pages(&request, dev(), t_display_s3_review_limits()).unwrap();
        let pages = pages.as_slice();

        assert_eq!(pages.len(), 4);
        assert_eq!(pages[0].title, "Event");
        assert_eq!(pages[0].page_indicator, "Page 1/4");
        let event_lines: Vec<&str> = pages[0]
            .lines
            .as_slice()
            .iter()
            .map(|line| line.as_str())
            .collect();
        assert_eq!(
            event_lines,
            [
                "Kind 1",
                "Created 1710000060",
                "Author",
                "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a",
                "  b0f0b704075871aa",
            ],
        );
        assert_eq!(pages[0].body_line_styles.len(), pages[0].lines.len());
        assert_eq!(
            pages[0].body_line_styles.as_slice()[2],
            ReviewBodyLineStyle::Meta
        );
        assert_eq!(
            pages[0].body_line_styles.as_slice()[3],
            ReviewBodyLineStyle::Value
        );
        assert!(!any_page_line_contains(&pages[..1], "Short Text Note"));
        assert_eq!(pages[1].title, "Content");
        assert_eq!(pages[1].page_indicator, "Page 2/4");
        assert_eq!(pages[2].title, "Tags");
        assert_eq!(pages[2].page_indicator, "Page 3/4");
        assert_eq!(pages[3].title, "Decision");
        assert_eq!(pages[3].page_indicator, "Page 4/4");
        assert_eq!(pages[2].body_line_styles.len(), pages[2].lines.len());
        assert_eq!(
            pages[2].body_line_styles.as_slice()[0],
            ReviewBodyLineStyle::Meta
        );
        let tag_text = joined_lines_for_title(pages, "Tags");
        let tag_lines: Vec<&str> = pages[2]
            .lines
            .as_slice()
            .iter()
            .map(|line| line.as_str())
            .collect();
        assert_eq!(
            tag_lines,
            [
                "Tag 1/2",
                "p",
                "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a",
                "  b0f0b704075871aa",
                "mention",
                "Tag 2/2",
                "t",
                "nsealr",
            ],
        );
        assert_eq!(
            pages[2].body_line_styles.as_slice()[2],
            ReviewBodyLineStyle::Value
        );
        assert_eq!(
            pages[2].body_line_styles.as_slice()[3],
            ReviewBodyLineStyle::Value
        );
        assert!(pages[2].lines.as_slice()[3].as_str().starts_with("  "));
        assert!(!any_page_line_contains(&pages[2..3], "[0]"));
        assert!(!any_page_line_contains(&pages[2..3], "\""));
        assert!(!any_page_line_contains(&pages[2..3], "raw tags JSON"));
        assert!(tag_text.contains(&pubkey[..48]));
        assert!(tag_text.contains(&pubkey[48..]));
    }

    /// One expected display page from a READ-ONLY review-detail-pages fixture.
    struct ExpectedDetailPage {
        title: &'static str,
        page_indicator: &'static str,
        logical_page_id: &'static str,
        action: ReviewPageAction,
        lines: Vec<&'static str>,
        body_line_styles: Vec<ReviewBodyLineStyle>,
    }

    /// One READ-ONLY review-detail-pages fixture (the C++
    /// `test_vectors::ReviewDetailPageVector`).
    struct ReviewDetailPageVector {
        name: &'static str,
        request_json: &'static str,
        approval_digest: &'static str,
        limits: ReviewDisplayLimits,
        pages: Vec<ExpectedDetailPage>,
    }

    /// The C++ `assert_detailed_trusted_review_pages` (title, lines, action,
    /// indicator, styles, logical page id).
    fn assert_detail_pages(actual: &ReviewPageList, expected: &[ExpectedDetailPage]) {
        assert_eq!(actual.len(), expected.len());
        for (page, expected_page) in actual.as_slice().iter().zip(expected) {
            assert_eq!(page.title, expected_page.title);
            let actual_lines: Vec<&str> = page
                .lines
                .as_slice()
                .iter()
                .map(|line| line.as_str())
                .collect();
            assert_eq!(actual_lines, expected_page.lines);
            assert_eq!(page.action, expected_page.action);
            assert_eq!(page.page_indicator, expected_page.page_indicator);
            assert_eq!(
                page.body_line_styles.as_slice(),
                expected_page.body_line_styles.as_slice(),
            );
            assert_eq!(page.logical_page_id, expected_page.logical_page_id);
        }
    }

    // Port of the C++ `test_qr_display_review_pages_match_shared_detail_page_vectors`.
    #[test]
    fn display_pages_match_shared_detail_page_vectors() {
        for vector in review_detail_page_vectors() {
            let request = parse(vector.request_json);
            let pages = build_qr_display_review_pages(&request, dev(), vector.limits).unwrap();
            let review_request =
                build_qr_display_review_request(&request, dev(), vector.limits).unwrap();

            assert_eq!(
                review_request.approval_digest, vector.approval_digest,
                "digest mismatch for {}",
                vector.name,
            );
            assert_detail_pages(&pages, &vector.pages);
        }
    }

    // Port of the C++ `test_qr_display_review_pages_escape_non_ascii_for_display_safety`.
    // The C++ built the QrSigningRequest struct directly; this port routes the
    // same fields through the parser (identical parsed request by M-T3.3
    // parity), since the Rust request type keeps its fields private.
    #[test]
    fn display_pages_escape_non_ascii_for_display_safety() {
        let request = parse(
            "{\"version\":1,\"request_id\":\"req-unicode-display\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000300,\"kind\":1,\"tags\":[[\"t\",\"topic-\u{e8}\"],[\"emoji\",\"\u{1f600}\"]],\"content\":\"cafe \u{e8} \u{1f600}\"}}}",
        );

        let pages =
            build_qr_display_review_pages(&request, dev(), t_display_s3_review_limits()).unwrap();
        let content_text = joined_lines_for_title(pages.as_slice(), "Content");
        let tag_text = joined_lines_for_title(pages.as_slice(), "Tags");

        assert!(content_text.contains("U+00E8"));
        assert!(content_text.contains("U+1F600"));
        assert!(tag_text.contains("U+00E8"));
        assert!(tag_text.contains("U+1F600"));
    }

    // Port of the C++ `test_qr_display_review_pages_render_control_escapes_visibly`
    // (request routed through the parser, as above).
    #[test]
    fn display_pages_render_control_escapes_visibly() {
        let request = parse(
            "{\"version\":1,\"request_id\":\"req-control-escapes-display\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000480,\"kind\":1,\"tags\":[[\"t\",\"line\\nbreak\"],[\"subject\",\"tab\\tvalue\",\"carriage\\rreturn\"]],\"content\":\"line 1\\nline 2\\tTabbed\\rCarriage\\bBackspace\\fFormfeed\"}}}",
        );

        let pages =
            build_qr_display_review_pages(&request, dev(), t_display_s3_review_limits()).unwrap();
        let content_text = joined_lines_for_title(pages.as_slice(), "Content");
        let tag_text = joined_lines_for_title(pages.as_slice(), "Tags");

        assert!(content_text.contains("\\n"));
        assert!(content_text.contains("\\t"));
        assert!(content_text.contains("\\r"));
        assert!(content_text.contains("\\b"));
        assert!(content_text.contains("\\f"));
        assert!(tag_text.contains("line\\nbreak"));
        assert!(tag_text.contains("tab\\tvalue"));
        assert!(tag_text.contains("carriage\\rreturn"));
        assert!(!content_text.contains("U+000A"));
        assert!(!tag_text.contains("U+0009"));
    }

    // Port of the C++ `test_qr_display_review_pages_preserve_supported_ascii_punctuation`
    // (request routed through the parser, as above).
    #[test]
    fn display_pages_preserve_supported_ascii_punctuation() {
        let content = "hello, nostr! #tag? @alice & key=value `code` ^caret";
        let request = parse(
            "{\"version\":1,\"request_id\":\"req-ascii-punctuation-display\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000360,\"kind\":1,\"tags\":[[\"client\",\"nsealr/esp32-v0\"],[\"subject\",\"a+b=c?\"]],\"content\":\"hello, nostr! #tag? @alice & key=value `code` ^caret\"}}}",
        );

        let pages =
            build_qr_display_review_pages(&request, dev(), t_display_s3_review_limits()).unwrap();
        let content_text = joined_lines_for_title(pages.as_slice(), "Content");
        let tag_text = joined_lines_for_title(pages.as_slice(), "Tags");

        assert!(content_text.contains(content));
        assert!(!content_text.contains("U+002C"));
        assert!(!content_text.contains("U+0021"));
        assert!(!content_text.contains("U+003F"));
        assert!(!content_text.contains("U+005E"));
        assert!(!content_text.contains("U+0060"));
        assert!(tag_text.contains("nsealr/esp32-v0"));
        assert!(tag_text.contains("a+b=c?"));
    }

    // Port of the C++ `test_qr_display_review_pages_split_full_long_content_without_ellipsis`
    // (request routed through the parser, as above).
    #[test]
    fn display_pages_split_full_long_content_without_ellipsis() {
        let mut long_content = String::new();
        for _ in 0..281 {
            long_content.push('x');
        }
        let mut json = String::from(
            "{\"version\":1,\"request_id\":\"req-long-display\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000120,\"kind\":1,\"tags\":[],\"content\":\"",
        );
        json.push_str(&long_content);
        json.push_str("\"}}}");
        let request = parse(&json);

        let pages =
            build_qr_display_review_pages(&request, dev(), t_display_s3_review_limits()).unwrap();
        let content_text = joined_lines_for_title(pages.as_slice(), "Content");

        assert_eq!(page_count_with_title(pages.as_slice(), "Content"), 1);
        assert!(content_text.contains(&long_content));
        assert!(!content_text.contains("..."));
        let last = &pages.as_slice()[pages.len() - 1];
        assert_eq!(last.title, "Decision");
        assert!(!any_page_line_contains(
            core::slice::from_ref(last),
            "Long content"
        ));
        assert!(!any_page_line_contains(
            core::slice::from_ref(last),
            "Many tags"
        ));
    }

    // Port of the C++ `test_qr_display_review_pages_use_scroll_line_indicators_for_long_sections`
    // (request routed through the parser, as above).
    #[test]
    fn display_pages_use_scroll_line_indicators_for_long_sections() {
        let mut long_content = String::new();
        for index in 0..448usize {
            long_content.push((b'a' + (index % 26) as u8) as char);
        }
        let mut json = String::from(
            "{\"version\":1,\"request_id\":\"req-scroll-display\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000240,\"kind\":1,\"tags\":[[\"t\",\"tag0\"],[\"t\",\"tag1\"],[\"t\",\"tag2\"],[\"t\",\"tag3\"],[\"t\",\"tag4\"],[\"t\",\"tag5\"]],\"content\":\"",
        );
        json.push_str(&long_content);
        json.push_str("\"}}}");
        let request = parse(&json);

        let pages =
            build_qr_display_review_pages(&request, dev(), t_display_s3_review_limits()).unwrap();
        let pages = pages.as_slice();

        assert!(page_count_with_title(pages, "Content") > 1);
        assert!(page_count_with_title(pages, "Tags") > 1);
        assert_eq!(pages[1].title, "Content");
        assert!(pages[1]
            .page_indicator
            .as_str()
            .starts_with("Page 2/4 Lines 1-9/"));
        assert_eq!(pages[2].title, "Content");
        assert!(pages[2]
            .page_indicator
            .as_str()
            .starts_with("Page 2/4 Lines 10-"));
        assert!(!pages[1].lines.is_empty());
        assert!(!pages[2].lines.is_empty());
        assert_ne!(
            pages[1].lines.as_slice()[pages[1].lines.len() - 1],
            pages[2].lines.as_slice()[0],
        );

        let mut saw_tag_scroll_indicator = false;
        let mut saw_tag_second_window_without_overlap = false;
        for page in pages {
            if page.title == "Tags" && page.page_indicator.as_str().starts_with("Page 3/4 Lines ") {
                saw_tag_scroll_indicator = true;
            }
            if page.title == "Tags"
                && page
                    .page_indicator
                    .as_str()
                    .starts_with("Page 3/4 Lines 10-")
            {
                saw_tag_second_window_without_overlap = true;
            }
        }
        assert!(saw_tag_scroll_indicator);
        assert!(saw_tag_second_window_without_overlap);
    }

    // Port of the C++ `test_qr_trusted_review_session_binds_qr_digest_and_navigation`.
    #[test]
    fn trusted_review_session_binds_qr_digest_and_navigation() {
        let request = parse_basic_envelope();
        let mut session =
            begin_qr_trusted_review(&request, dev(), ReviewDisplayLimits::default()).unwrap();

        let first_frame = session.current_frame().unwrap();
        assert_eq!(first_frame.title, "Event");
        assert_eq!(first_frame.page_indicator, "Page 1/4");
        assert!(!session.can_sign());

        assert_eq!(
            session.handle_button(ReviewButton::Approve),
            Err(crate::review::trusted::TrustedReviewError::ApprovalRequiresDecisionPage),
        );

        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));
        assert_eq!(session.handle_button(ReviewButton::Next), Ok(None));

        let decision_frame = session.current_frame().unwrap();
        assert_eq!(decision_frame.title, "Decision");
        assert!(!session.can_sign());

        let approval = session.handle_button(ReviewButton::Approve);
        assert_eq!(approval, Ok(Some(true)));
        assert!(session.can_sign());
        assert_eq!(session.decision(), ApprovalDecision::Approved);
        let _ = frame_lines_contain(&decision_frame, "Approve");
    }

    // The review-pages half of the C++
    // `test_qr_signing_request_preserves_json_unicode_escapes` — the parser
    // half was ported in M-T3.3; this closes the recorded M-T3.3 deferral by
    // driving the same `\uXXXX`-escaped request through the display builders.
    #[test]
    fn signing_request_unicode_escapes_render_escaped_review_pages() {
        let request = parse(
            "{\"version\":1,\"request_id\":\"req-unicode-escapes\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000400,\"kind\":1,\"tags\":[[\"t\",\"caf\\u00e8\"],[\"emoji\",\"\\uD83D\\uDE00\"]],\"content\":\"caf\\u00e8 \\uD83D\\uDE00\"}}}",
        );

        // The parser half (asserted again here as the C++ case did).
        assert_eq!(request.content(), "caf\u{e8} \u{1f600}".as_bytes());
        let tag0: Vec<&[u8]> = request.tag(0).collect();
        assert_eq!(tag0[1], "caf\u{e8}".as_bytes());
        let tag1: Vec<&[u8]> = request.tag(1).collect();
        assert_eq!(tag1[1], "\u{1f600}".as_bytes());

        let pages =
            build_qr_display_review_pages(&request, dev(), t_display_s3_review_limits()).unwrap();
        assert!(joined_lines_for_title(pages.as_slice(), "Content").contains("U+00E8"));
        assert!(joined_lines_for_title(pages.as_slice(), "Content").contains("U+1F600"));
        assert!(joined_lines_for_title(pages.as_slice(), "Tags").contains("U+00E8"));
        assert!(joined_lines_for_title(pages.as_slice(), "Tags").contains("U+1F600"));
    }
    /// The four READ-ONLY specs/vectors/review-detail-pages fixtures as Rust
    /// literals (request JSON from the source specs/vectors/review vector,
    /// digest/limits/pages copied verbatim from the fixture file).
    fn review_detail_page_vectors() -> Vec<ReviewDetailPageVector> {
        vec![
            ReviewDetailPageVector {
                name: "kind-1-control-escapes-t-display-s3",
                request_json: "{\"version\":1,\"request_id\":\"req-kind-1-control-escapes\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000480,\"kind\":1,\"tags\":[[\"t\",\"line\\nbreak\"],[\"subject\",\"tab\\tvalue\",\"carriage\\rreturn\"]],\"content\":\"line 1\\nline 2\\tTabbed\\rCarriage\\bBackspace\\fFormfeed\"}}}",
                approval_digest: "cda9c032d45f37c28c70f78541849a7dec1ec488000b8058e9d46d34f588e347",
                limits: ReviewDisplayLimits {
                    max_title_chars: 18,
                    max_body_lines: 5,
                    max_line_chars: 26,
                    max_compact_body_lines: 9,
                    max_compact_line_chars: 48,
                },
                pages: vec![
                    ExpectedDetailPage {
                        title: "Event",
                        page_indicator: "Page 1/4",
                        logical_page_id: "Event",
                        action: ReviewPageAction::Next,
                        lines: vec!["Kind 1", "Created 1710000480", "Author", "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a", "  b0f0b704075871aa"],
                        body_line_styles: vec![ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value],
                    },
                    ExpectedDetailPage {
                        title: "Content",
                        page_indicator: "Page 2/4",
                        logical_page_id: "Content",
                        action: ReviewPageAction::Next,
                        lines: vec!["bytes: 48", "line 1\\nline 2\\tTabbed\\rCarriage\\bBackspace\\fFor", "mfeed"],
                        body_line_styles: vec![ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value],
                    },
                    ExpectedDetailPage {
                        title: "Tags",
                        page_indicator: "Page 3/4",
                        logical_page_id: "Tags",
                        action: ReviewPageAction::Next,
                        lines: vec!["Tag 1/2", "t", "line\\nbreak", "Tag 2/2", "subject", "tab\\tvalue", "carriage\\rreturn"],
                        body_line_styles: vec![ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value],
                    },
                    ExpectedDetailPage {
                        title: "Decision",
                        page_indicator: "Page 4/4",
                        logical_page_id: "Decision",
                        action: ReviewPageAction::ApproveOrReject,
                        lines: vec!["Approve signing only if all pages match."],
                        body_line_styles: vec![],
                    },
                ],
            },
            ReviewDetailPageVector {
                name: "kind-1-long-events-many-tags-t-display-s3",
                request_json: "{\"version\":1,\"request_id\":\"req-kind-1-long-events-many-tags\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000120,\"kind\":1,\"tags\":[[\"e\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"\",\"root\"],[\"t\",\"nsealr\"],[\"t\",\"hardware\"],[\"t\",\"review\"],[\"t\",\"security\"],[\"t\",\"qr\"],[\"t\",\"vault\"],[\"t\",\"companion\"],[\"t\",\"test\"]],\"content\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}}}",
                approval_digest: "7c9ae4d4656c7c9ff296483e410bc6f770bef611ddd81cad7a4f56a2a4019799",
                limits: ReviewDisplayLimits {
                    max_title_chars: 18,
                    max_body_lines: 5,
                    max_line_chars: 26,
                    max_compact_body_lines: 9,
                    max_compact_line_chars: 48,
                },
                pages: vec![
                    ExpectedDetailPage {
                        title: "Event",
                        page_indicator: "Page 1/4",
                        logical_page_id: "Event",
                        action: ReviewPageAction::Next,
                        lines: vec!["Kind 1", "Created 1710000120", "Author", "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a", "  b0f0b704075871aa"],
                        body_line_styles: vec![ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value],
                    },
                    ExpectedDetailPage {
                        title: "Content",
                        page_indicator: "Page 2/4",
                        logical_page_id: "Content",
                        action: ReviewPageAction::Next,
                        lines: vec!["bytes: 281", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
                        body_line_styles: vec![ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value],
                    },
                    ExpectedDetailPage {
                        title: "Tags",
                        page_indicator: "Page 3/4 Lines 1-9/29",
                        logical_page_id: "Tags",
                        action: ReviewPageAction::Next,
                        lines: vec!["Tag 1/9", "e", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "  aaaaaaaaaaaaaaaa", "root", "Tag 2/9", "t", "nsealr", "Tag 3/9"],
                        body_line_styles: vec![ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Meta],
                    },
                    ExpectedDetailPage {
                        title: "Tags",
                        page_indicator: "Page 3/4 Lines 10-18/29",
                        logical_page_id: "Tags",
                        action: ReviewPageAction::Next,
                        lines: vec!["t", "hardware", "Tag 4/9", "t", "review", "Tag 5/9", "t", "security", "Tag 6/9"],
                        body_line_styles: vec![ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Meta],
                    },
                    ExpectedDetailPage {
                        title: "Tags",
                        page_indicator: "Page 3/4 Lines 19-27/29",
                        logical_page_id: "Tags",
                        action: ReviewPageAction::Next,
                        lines: vec!["t", "qr", "Tag 7/9", "t", "vault", "Tag 8/9", "t", "companion", "Tag 9/9"],
                        body_line_styles: vec![ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Meta],
                    },
                    ExpectedDetailPage {
                        title: "Tags",
                        page_indicator: "Page 3/4 Lines 28-29/29",
                        logical_page_id: "Tags",
                        action: ReviewPageAction::Next,
                        lines: vec!["t", "test"],
                        body_line_styles: vec![ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value],
                    },
                    ExpectedDetailPage {
                        title: "Decision",
                        page_indicator: "Page 4/4",
                        logical_page_id: "Decision",
                        action: ReviewPageAction::ApproveOrReject,
                        lines: vec!["Approve signing only if all pages match."],
                        body_line_styles: vec![],
                    },
                ],
            },
            ReviewDetailPageVector {
                name: "kind-1-tags-t-display-s3",
                request_json: "{\"version\":1,\"request_id\":\"req-kind-1-tags\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000060,\"kind\":1,\"tags\":[[\"p\",\"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa\",\"\",\"mention\"],[\"t\",\"nsealr\"]],\"content\":\"nSealr fixture: tagged kind 1 event.\"}}}",
                approval_digest: "b45328f9ef96122900562d161cca5f09e24bfdb66676c46ebbcfe08dd661eb30",
                limits: ReviewDisplayLimits {
                    max_title_chars: 18,
                    max_body_lines: 5,
                    max_line_chars: 26,
                    max_compact_body_lines: 9,
                    max_compact_line_chars: 48,
                },
                pages: vec![
                    ExpectedDetailPage {
                        title: "Event",
                        page_indicator: "Page 1/4",
                        logical_page_id: "Event",
                        action: ReviewPageAction::Next,
                        lines: vec!["Kind 1", "Created 1710000060", "Author", "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a", "  b0f0b704075871aa"],
                        body_line_styles: vec![ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value],
                    },
                    ExpectedDetailPage {
                        title: "Content",
                        page_indicator: "Page 2/4",
                        logical_page_id: "Content",
                        action: ReviewPageAction::Next,
                        lines: vec!["nSealr fixture: tagged kind 1 event."],
                        body_line_styles: vec![ReviewBodyLineStyle::Normal],
                    },
                    ExpectedDetailPage {
                        title: "Tags",
                        page_indicator: "Page 3/4",
                        logical_page_id: "Tags",
                        action: ReviewPageAction::Next,
                        lines: vec!["Tag 1/2", "p", "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a", "  b0f0b704075871aa", "mention", "Tag 2/2", "t", "nsealr"],
                        body_line_styles: vec![ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value],
                    },
                    ExpectedDetailPage {
                        title: "Decision",
                        page_indicator: "Page 4/4",
                        logical_page_id: "Decision",
                        action: ReviewPageAction::ApproveOrReject,
                        lines: vec!["Approve signing only if all pages match."],
                        body_line_styles: vec![],
                    },
                ],
            },
            ReviewDetailPageVector {
                name: "kind-1-unicode-boundary-t-display-s3",
                request_json: "{\"version\":1,\"request_id\":\"req-kind-1-unicode-boundary\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000420,\"kind\":1,\"tags\":[[\"t\",\"caffè\"]],\"content\":\"abcèdef\"}}}",
                approval_digest: "46abebc746f926aa5fd02f577cf72b7222de4c1cbbda226db585eb3165f5bf17",
                limits: ReviewDisplayLimits {
                    max_title_chars: 18,
                    max_body_lines: 5,
                    max_line_chars: 26,
                    max_compact_body_lines: 9,
                    max_compact_line_chars: 48,
                },
                pages: vec![
                    ExpectedDetailPage {
                        title: "Event",
                        page_indicator: "Page 1/4",
                        logical_page_id: "Event",
                        action: ReviewPageAction::Next,
                        lines: vec!["Kind 1", "Created 1710000420", "Author", "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859a", "  b0f0b704075871aa"],
                        body_line_styles: vec![ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value],
                    },
                    ExpectedDetailPage {
                        title: "Content",
                        page_indicator: "Page 2/4",
                        logical_page_id: "Content",
                        action: ReviewPageAction::Next,
                        lines: vec!["abcU+00E8def"],
                        body_line_styles: vec![ReviewBodyLineStyle::Normal],
                    },
                    ExpectedDetailPage {
                        title: "Tags",
                        page_indicator: "Page 3/4",
                        logical_page_id: "Tags",
                        action: ReviewPageAction::Next,
                        lines: vec!["Tag 1/1", "t", "caffU+00E8"],
                        body_line_styles: vec![ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value, ReviewBodyLineStyle::Value],
                    },
                    ExpectedDetailPage {
                        title: "Decision",
                        page_indicator: "Page 4/4",
                        logical_page_id: "Decision",
                        action: ReviewPageAction::ApproveOrReject,
                        lines: vec!["Approve signing only if all pages match."],
                        body_line_styles: vec![],
                    },
                ],
            },
        ]
    }

    // Beyond the named C++ cases: error messages/Display, the limits
    // validation and capacity guards, empty-tag and empty-content rendering,
    // the canonical-digest escaping branches, narrow-width continuation, the
    // direct empty-value split, and the page-capacity error path.
    #[test]
    fn validation_capacity_and_escaping_branches() {
        // Error messages and Display for every variant.
        for (error, expected) in [
            (
                QrReviewError::InvalidSignerIdentity,
                "signer public key must be 64 lowercase hex characters",
            ),
            (
                QrReviewError::Display(ReviewDisplayError::ZeroLimits),
                "review display limits must be non-zero",
            ),
            (
                QrReviewError::Capacity,
                "QR review exceeds fixed review page capacity",
            ),
            (
                QrReviewError::RequestNotUtf8,
                "QR review request text must be valid UTF-8",
            ),
            (
                QrReviewError::TrustedReview(
                    crate::review::trusted::TrustedReviewError::AlreadyTerminal,
                ),
                "review decision is already terminal",
            ),
        ] {
            assert_eq!(error.message(), expected);
            assert_eq!(std::format!("{error}"), expected);
        }

        let request = parse_basic_envelope();
        // Zero display limits are rejected (the C++ validate_display_page_limits).
        assert_eq!(
            build_qr_display_review_pages(
                &request,
                dev(),
                ReviewDisplayLimits {
                    max_compact_line_chars: 0,
                    ..ReviewDisplayLimits::default()
                },
            ),
            Err(QrReviewError::Display(ReviewDisplayError::ZeroLimits)),
        );
        // Limits beyond the fixed page capacities are rejected (no C++ analogue).
        assert_eq!(
            build_qr_display_review_pages(
                &request,
                dev(),
                ReviewDisplayLimits {
                    max_compact_line_chars: MAX_REVIEW_PAGE_LINE_CHARS + 1,
                    ..ReviewDisplayLimits::default()
                },
            ),
            Err(QrReviewError::Display(
                ReviewDisplayError::LimitsExceedCapacity,
            )),
        );

        // An empty tag renders "empty tag" on both the summary and display
        // pages (the C++ tag_lines / detailed_tag_lines fallbacks).
        let empty_tag_request = parse(
            "{\"version\":1,\"request_id\":\"req-empty-tag\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000500,\"kind\":1,\"tags\":[[]],\"content\":\"x\"}}}",
        );
        let summary = build_qr_review_pages(&empty_tag_request, dev()).unwrap();
        let tags_lines: Vec<&str> = summary.as_slice()[2]
            .lines
            .as_slice()
            .iter()
            .map(|line| line.as_str())
            .collect();
        assert_eq!(tags_lines, ["Tag 1/1", "empty tag"]);
        let display =
            build_qr_display_review_pages(&empty_tag_request, dev(), t_display_s3_review_limits())
                .unwrap();
        assert!(joined_lines_for_title(display.as_slice(), "Tags").contains("empty tag"));

        // Empty content renders the "empty content" meta line.
        let empty_content_request = parse(
            "{\"version\":1,\"request_id\":\"req-empty-content\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000520,\"kind\":1,\"tags\":[],\"content\":\"\"}}}",
        );
        let display = build_qr_display_review_pages(
            &empty_content_request,
            dev(),
            t_display_s3_review_limits(),
        )
        .unwrap();
        assert_eq!(
            joined_lines_for_title(display.as_slice(), "Content"),
            "empty content",
        );

        // The canonical digest escapes quotes, backslashes and control bytes
        // (the C++ json_string branches): stable 64-hex digests, distinct from
        // each other and sensitive to the escaped bytes.
        let mut digests: Vec<String> = Vec::new();
        for content in [
            "say \\\"hi\\\"",
            "back\\\\slash",
            "ctrl\\u0001byte",
            "plain",
        ] {
            let mut json = String::from(
                "{\"version\":1,\"request_id\":\"req-escape\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000540,\"kind\":1,\"tags\":[],\"content\":\"",
            );
            json.push_str(content);
            json.push_str("\"}}}");
            let request = parse(&json);
            let review = build_qr_trusted_review_request(&request, dev()).unwrap();
            let digest = String::from(review.approval_digest.as_str());
            assert_eq!(digest.len(), 64);
            assert!(digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
            digests.push(digest);
        }
        let mut unique = digests.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), digests.len());

        // A compact width of two disables the two-space continuation indent
        // (the C++ append_tag_item_lines width<=indent branch).
        let narrow = build_qr_display_review_pages(
            &request,
            dev(),
            ReviewDisplayLimits {
                max_title_chars: 18,
                max_body_lines: 5,
                max_line_chars: 26,
                max_compact_body_lines: MAX_REVIEW_PAGE_LINES,
                max_compact_line_chars: 2,
            },
        )
        .unwrap();
        let event_text = joined_lines_for_title(narrow.as_slice(), "Event");
        assert!(event_text.contains(DEVELOPMENT_FIXTURE_PUBLIC_KEY));
        assert!(narrow.as_slice().iter().any(|page| page.title == "Event"
            && page
                .lines
                .as_slice()
                .iter()
                .any(|line| line.len() == 2 && !line.as_str().starts_with(' '))));

        // The direct empty-value split emits one empty line (the C++
        // split_exact_display_lines({""}) shape; unreachable through the
        // public builders, which guard empty content).
        let mut emitted: Vec<String> = Vec::new();
        emit_split_value_lines("", 8, ReviewBodyLineStyle::Value, &mut |line, _| {
            emitted.push(String::from(line));
            Ok(())
        })
        .unwrap();
        assert_eq!(emitted, [""]);

        // A request that needs more display pages than the fixed capacity
        // reports Capacity (no C++ analogue: unbounded vectors). Twelve tags
        // of eight one-character fields produce 12 nine-line tag windows.
        let mut tags = String::new();
        for index in 0..12 {
            if index > 0 {
                tags.push(',');
            }
            tags.push_str("[\"a\",\"b\",\"c\",\"d\",\"e\",\"f\",\"g\",\"h\"]");
        }
        let mut json = String::from(
            "{\"version\":1,\"request_id\":\"req-too-many-pages\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000560,\"kind\":1,\"tags\":[",
        );
        json.push_str(&tags);
        json.push_str("],\"content\":\"x\"}}}");
        let request = parse(&json);
        assert_eq!(
            build_qr_display_review_pages(&request, dev(), t_display_s3_review_limits()),
            Err(QrReviewError::Capacity),
        );

        // A long content at a two-character compact width overflows inside the
        // Content section (its call-site error propagation).
        let mut long_json = String::from(
            "{\"version\":1,\"request_id\":\"req-narrow-content\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000580,\"kind\":1,\"tags\":[],\"content\":\"",
        );
        for _ in 0..300 {
            long_json.push('y');
        }
        long_json.push_str("\"}}}");
        let request = parse(&long_json);
        assert_eq!(
            build_qr_display_review_pages(
                &request,
                dev(),
                ReviewDisplayLimits {
                    max_title_chars: 18,
                    max_body_lines: 5,
                    max_line_chars: 26,
                    max_compact_body_lines: MAX_REVIEW_PAGE_LINES,
                    max_compact_line_chars: 2,
                },
            ),
            Err(QrReviewError::Capacity),
        );

        // A summary Tags page beyond the fixed line capacity (16 tags need 33
        // lines on the single C++ Tags page) reports Capacity (no C++
        // analogue: unbounded vectors).
        let mut many_tags = String::from(
            "{\"version\":1,\"request_id\":\"req-many-tags-summary\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000600,\"kind\":1,\"tags\":[",
        );
        for index in 0..16 {
            if index > 0 {
                many_tags.push(',');
            }
            many_tags.push_str("[\"t\",\"v\"]");
        }
        many_tags.push_str("],\"content\":\"x\"}}}");
        let request = parse(&many_tags);
        assert_eq!(
            build_qr_review_pages(&request, dev()),
            Err(QrReviewError::Capacity),
        );

        // Raw request bytes with invalid UTF-8 (only reachable outside the
        // envelope decode paths, which validate UTF-8 first) are rejected as
        // RequestNotUtf8 by the summary and display builders.
        let mut invalid_content = Vec::from(
            &b"{\"version\":1,\"request_id\":\"req-bad-utf8\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000620,\"kind\":1,\"tags\":[],\"content\":\""[..],
        );
        invalid_content.push(0xff);
        invalid_content.extend_from_slice(b"\"}}}");
        let request = parse_qr_signing_request(&invalid_content).unwrap();
        assert_eq!(
            build_qr_review_pages(&request, dev()),
            Err(QrReviewError::RequestNotUtf8),
        );
        assert_eq!(
            build_qr_display_review_pages(&request, dev(), t_display_s3_review_limits()),
            Err(QrReviewError::RequestNotUtf8),
        );
        assert_eq!(
            build_qr_trusted_review_request(&request, dev()),
            Err(QrReviewError::RequestNotUtf8),
        );
        let mut invalid_tag = Vec::from(
            &b"{\"version\":1,\"request_id\":\"req-bad-utf8-tag\",\"method\":\"sign_event\",\"params\":{\"event_template\":{\"created_at\":1710000640,\"kind\":1,\"tags\":[[\"t\",\""[..],
        );
        invalid_tag.push(0xfe);
        invalid_tag.extend_from_slice(b"\"]],\"content\":\"ok\"}}}");
        let request = parse_qr_signing_request(&invalid_tag).unwrap();
        assert_eq!(
            build_qr_review_pages(&request, dev()),
            Err(QrReviewError::RequestNotUtf8),
        );
        assert_eq!(
            build_qr_display_review_request(&request, dev(), t_display_s3_review_limits()),
            Err(QrReviewError::RequestNotUtf8),
        );
    }
}
