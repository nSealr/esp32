//! Per-category vector replay: parse a `specs/vectors/<category>/*.json` file and
//! drive it end-to-end through `nsealr-core`'s public API, asserting the vector's
//! own expected outcome exactly.
//!
//! [`replay_file`] infers the category from the file's parent directory name and
//! dispatches to the matching replay. Both the CLI and the exhaustive test suite
//! call [`replay_file`], so there is a single replay code path.

use serde_json::Value;
use std::path::Path;

/// A replay assertion failure, carrying a human-readable description.
pub type ReplayResult = Result<(), String>;

/// Load and parse a vector file into a `serde_json::Value`.
pub fn load_value(path: &Path) -> Result<Value, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Infer the category (parent directory name) for a vector file path.
pub fn category_of(path: &Path) -> Result<String, String> {
    path.parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("cannot infer category from path {}", path.display()))
}

/// Replay a single vector file end-to-end and assert its expected outcome.
pub fn replay_file(path: &Path) -> ReplayResult {
    let category = category_of(path)?;
    let value = load_value(path)?;
    dispatch(&category, path, &value)
}

fn dispatch(category: &str, path: &Path, value: &Value) -> ReplayResult {
    match category {
        "transports" => transports::replay(value),
        "invalid" => invalid::replay(path, value),
        "limits" => limits::replay(value),
        "devices" => devices::replay(value),
        "policies" => policies::replay(value),
        "policy-changes" => policy_changes::replay(value),
        "seedqr" => sources::replay_seedqr(value),
        "nip19" => sources::replay_nip19(value),
        "keys" => sources::replay_keys(value),
        "accounts" => sources::replay_accounts(value),
        "source-public-key-proofs" => sources::replay_proof(value),
        "session-import-reviews" => session_reviews::replay_import(value),
        "session-source-backups" => session_reviews::replay_backup(value),
        "review" => review::replay_review(value),
        "review-screens" => review::replay_screen(value),
        "review-detail-pages" => review::replay_detail_pages(value),
        "review-display-frames" => review::replay_display_frame(value),
        "review-transcripts" => review::replay_transcript(value),
        other => Err(format!(
            "no replay implemented for category '{other}' (path {})",
            path.display()
        )),
    }
}

// --- small shared JSON helpers -------------------------------------------------

/// Serialize a JSON value back to compact bytes (canonical input the on-device
/// parsers consume; whitespace/order are irrelevant to the field-addressed
/// parsers in `nsealr-core`).
pub(crate) fn compact_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serialize JSON value")
}

/// Fetch a required string field.
pub(crate) fn str_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field '{key}'"))
}

/// Fetch a required sub-object.
pub(crate) fn obj_field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, String> {
    value
        .get(key)
        .filter(|v| v.is_object())
        .ok_or_else(|| format!("missing object field '{key}'"))
}

/// Fetch a required array field.
pub(crate) fn arr_field<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array field '{key}'"))
}

/// Assert two JSON values are equal, producing a descriptive diff on mismatch.
pub(crate) fn assert_json_eq(context: &str, got: &Value, want: &Value) -> ReplayResult {
    if got == want {
        Ok(())
    } else {
        Err(format!(
            "{context} mismatch:\n  got:  {got}\n  want: {want}"
        ))
    }
}

/// Decode a lowercase hex string into bytes.
pub(crate) fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length: {hex}"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("invalid hex '{hex}': {e}"))
        })
        .collect()
}

/// Read a JSON array of non-negative integers as `u16`s.
pub(crate) fn u16_array(value: &Value, key: &str) -> Result<Vec<u16>, String> {
    arr_field(value, key)?
        .iter()
        .map(|v| {
            v.as_u64()
                .filter(|n| *n <= u16::MAX as u64)
                .map(|n| n as u16)
                .ok_or_else(|| format!("{key} contains a non-u16 entry: {v}"))
        })
        .collect()
}

/// Map a serial `type` token to the core's `FrameType`.
pub(crate) fn frame_type_from_str(
    token: &str,
) -> Result<nsealr_core::serial::frame::FrameType, String> {
    use nsealr_core::serial::frame::FrameType;
    match token {
        "request" => Ok(FrameType::Request),
        "response" => Ok(FrameType::Response),
        "error" => Ok(FrameType::Error),
        other => Err(format!("unknown serial frame type '{other}'")),
    }
}

/// Encode `json` as a `request` serial frame line (base64url payload + framing),
/// the on-wire input the device protocol consumes.
pub(crate) fn encode_serial_request_frame(json: &[u8]) -> Result<Vec<u8>, String> {
    use nsealr_core::base64url::{encode_base64url, encoded_len};
    use nsealr_core::serial::frame::{encode_serial_frame, FrameType};
    let mut payload_buf = vec![0u8; encoded_len(json.len())];
    let payload = encode_base64url(json, &mut payload_buf)
        .map_err(|e| format!("base64url-encode request json: {e:?}"))?
        .to_vec();
    let mut frame_buf = vec![0u8; nsealr_core::qr::limits::MAX_SERIAL_FRAME_BYTES];
    let frame = encode_serial_frame(FrameType::Request, &payload, &mut frame_buf)
        .map_err(|e| format!("encode serial request frame: {e:?}"))?;
    Ok(frame.to_vec())
}

/// Decode a serial response frame line and return `(frame_type, payload JSON)`.
pub(crate) fn decode_serial_frame_json(
    line: &[u8],
) -> Result<(nsealr_core::serial::frame::FrameType, Value), String> {
    use nsealr_core::base64url::decode_base64url;
    use nsealr_core::serial::frame::decode_serial_frame;
    let frame = decode_serial_frame(line).map_err(|e| format!("decode serial frame: {e:?}"))?;
    let mut json_buf = vec![0u8; frame.payload_base64url.len()];
    let json = decode_base64url(frame.payload_base64url, &mut json_buf)
        .map_err(|e| format!("decode serial frame payload: {e:?}"))?;
    let value = serde_json::from_slice(json)
        .map_err(|e| format!("parse serial frame payload json: {e}"))?;
    Ok((frame.frame_type, value))
}

// --- shared review-page + session-source helpers -------------------------------

/// The vector token for a `ReviewPageAction`.
pub(crate) fn action_token(action: nsealr_core::review::types::ReviewPageAction) -> &'static str {
    use nsealr_core::review::types::ReviewPageAction;
    match action {
        ReviewPageAction::Next => "next",
        ReviewPageAction::ApproveOrReject => "approve_or_reject",
    }
}

/// The vector token for a `ReviewBodyLineStyle`.
pub(crate) fn style_token(style: nsealr_core::review::types::ReviewBodyLineStyle) -> &'static str {
    use nsealr_core::review::types::ReviewBodyLineStyle;
    match style {
        ReviewBodyLineStyle::Normal => "normal",
        ReviewBodyLineStyle::Meta => "meta",
        ReviewBodyLineStyle::Value => "value",
    }
}

/// Assert a rendered `TrustedReviewPage` equals a vector page object exactly
/// (title, page_indicator, logical_page_id, action, lines, and — when the vector
/// carries them — body_line_styles; otherwise the page must have none).
pub(crate) fn assert_trusted_review_page(
    ctx: &str,
    page: &nsealr_core::review::types::TrustedReviewPage,
    want: &Value,
) -> ReplayResult {
    let eq = |field: &str, got: &str, want_key: &str| -> ReplayResult {
        let want = str_field(want, want_key)?;
        if got == want {
            Ok(())
        } else {
            Err(format!("{ctx}: {field} '{got}' != '{want}'"))
        }
    };
    eq("title", page.title.as_str(), "title")?;
    eq("action", action_token(page.action), "action")?;
    // Screen-page vectors omit page_indicator/logical_page_id (the builder leaves
    // them empty); detail-page vectors carry both. When omitted, the built page
    // must actually be empty — never silently unchecked.
    for (field, got) in [
        ("page_indicator", page.page_indicator.as_str()),
        ("logical_page_id", page.logical_page_id.as_str()),
    ] {
        match want.get(field) {
            Some(_) => eq(field, got, field)?,
            None => {
                if !got.is_empty() {
                    return Err(format!(
                        "{ctx}: page has {field} '{got}' but vector omits it"
                    ));
                }
            }
        }
    }

    let want_lines = arr_field(want, "lines")?;
    let got_lines = page.lines.as_slice();
    if got_lines.len() != want_lines.len() {
        return Err(format!(
            "{ctx}: line count {} != {}",
            got_lines.len(),
            want_lines.len()
        ));
    }
    for (i, (got, want)) in got_lines.iter().zip(want_lines).enumerate() {
        let want = want
            .as_str()
            .ok_or_else(|| format!("{ctx}: line {i} not a string"))?;
        if got.as_str() != want {
            return Err(format!("{ctx}: line {i} '{}' != '{want}'", got.as_str()));
        }
    }

    match want.get("body_line_styles") {
        Some(styles) => {
            let styles = styles
                .as_array()
                .ok_or_else(|| format!("{ctx}: body_line_styles not an array"))?;
            let got = page.body_line_styles.as_slice();
            if got.len() != styles.len() {
                return Err(format!(
                    "{ctx}: body_line_styles count {} != {}",
                    got.len(),
                    styles.len()
                ));
            }
            for (i, (g, w)) in got.iter().zip(styles).enumerate() {
                let w = w
                    .as_str()
                    .ok_or_else(|| format!("{ctx}: body_line_styles[{i}] not a string"))?;
                if style_token(*g) != w {
                    return Err(format!(
                        "{ctx}: body_line_styles[{i}] '{}' != '{w}'",
                        style_token(*g)
                    ));
                }
            }
        }
        None => {
            if !page.body_line_styles.is_empty() {
                return Err(format!(
                    "{ctx}: page has body_line_styles but vector omits them"
                ));
            }
        }
    }
    Ok(())
}

/// Assert a rendered page list equals the vector `pages` array, page by page.
pub(crate) fn assert_review_pages(
    ctx: &str,
    pages: &[nsealr_core::review::types::TrustedReviewPage],
    want: &[Value],
) -> ReplayResult {
    if pages.len() != want.len() {
        return Err(format!(
            "{ctx}: page count {} != {}",
            pages.len(),
            want.len()
        ));
    }
    for (i, (page, want)) in pages.iter().zip(want).enumerate() {
        assert_trusted_review_page(&format!("{ctx} page {i}"), page, want)?;
    }
    Ok(())
}

/// Resolve a `source_vector` reference (`"vectors/<cat>/<file>.json"`) against the
/// single configurable vector root, so it follows any Phase 07 repoint.
pub(crate) fn resolve_source_vector(source_vector: &str) -> std::path::PathBuf {
    let rel = source_vector
        .strip_prefix("vectors/")
        .unwrap_or(source_vector);
    crate::vectors_root().join(rel)
}

/// Build a single-source RAM-only keyring from a `source_type` + `source_vector`
/// + `label`, exactly as a signer loads a session source. Source lives at index 0.
pub(crate) fn build_single_source_keyring(
    source_type: &str,
    source_vector: &str,
    label: &str,
) -> Result<nsealr_core::session::keyring::StatelessSessionKeyring, String> {
    use nsealr_core::nip19::decode_nsec;
    use nsealr_core::session::keyring::StatelessSessionKeyring;
    let source_value = load_value(&resolve_source_vector(source_vector))?;
    let mut keyring = StatelessSessionKeyring::new();
    match source_type {
        "nsec" => {
            let nsec = str_field(&source_value, "nsec")?;
            let secret = decode_nsec(nsec).map_err(|e| format!("decode_nsec: {e:?}"))?;
            keyring
                .add_nsec(label, &secret)
                .map_err(|e| format!("add_nsec: {e:?}"))?;
        }
        "bip39_seed" => {
            let indexes = u16_array(&source_value, "standard_word_indexes")?;
            keyring
                .add_bip39_seed(label, &indexes)
                .map_err(|e| format!("add_bip39_seed: {e:?}"))?;
        }
        other => return Err(format!("unknown source_type '{other}'")),
    }
    Ok(keyring)
}

/// Build a RAM-only `SessionKeySource` from a `source_type` + `source_vector` +
/// `label` (a clone of the keyring's index-0 source).
pub(crate) fn build_session_key_source(
    source_type: &str,
    source_vector: &str,
    label: &str,
) -> Result<nsealr_core::session::keyring::SessionKeySource, String> {
    let keyring = build_single_source_keyring(source_type, source_vector, label)?;
    Ok(keyring
        .source_at(0)
        .map_err(|e| format!("source_at(0): {e:?}"))?
        .clone())
}

mod devices;
mod invalid;
mod limits;
mod policies;
mod policy_changes;
mod review;
mod session_reviews;
mod sources;
mod transports;
