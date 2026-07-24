//! M-T3.7 — the four end-to-end `test_t_display_s3_*` C++ suites ported as
//! full-stack integration tests of the crate's public API.
//!
//! Ported from the C++ reference `tests/test_host_core.cpp` (the four
//! `test_t_display_s3_*` functions) and the board-app glue they exercised
//! (`esp32_s3_usb_signer/main/t_display_s3_{raster,button_logic,status_frames,
//! serial_input}.cpp/.hpp` + `t_display_s3_board.hpp`). The board glue is
//! parameterized here over a [`BoardProfile`] — display limits, raster
//! geometry, RGB565 palette, button timings and pins — with the T-Display-S3
//! values as the single profile instance ([`T_DISPLAY_S3`]); nothing
//! board-specific enters the crate's public API. The portable state machines
//! the C++ app carried (button debounce classification, serial line
//! accumulation with overlong drain) were generalized into
//! [`crate::review::buttons`] and [`crate::serial::input`]; the deterministic
//! glyph raster and the status-frame copy are board rendering glue and stay
//! here as test harness over the crate's public [`ReviewDisplayFrame`] type.

use crate::qr::limits::MAX_SERIAL_FRAME_BYTES;
use crate::review::buttons::{update_button_state, ButtonState, ButtonTimings};
use crate::review::controls::ReviewButton;
use crate::review::display::{
    render_review_page, ReviewDisplayFrame, ReviewDisplayLimits, ReviewPage,
};
use crate::review::types::{
    ReviewBodyLineStyle, ReviewBodyLineStyles, ReviewPageAction, ReviewPageLines,
};
use crate::serial::frame::{decode_serial_frame, encode_serial_frame, FrameType};
use crate::serial::input::{SerialInputEvent, SerialLineInput};

/// RGB565 colors of a board display. T-Display-S3 values from the C++
/// `kTDisplayS3Color*` constants (`t_display_s3_raster.hpp`).
struct DisplayPalette {
    black: u16,
    white: u16,
    blue: u16,
    dark_blue: u16,
    green: u16,
    yellow: u16,
    amber: u16,
}

/// Raster geometry of a board display. T-Display-S3 values from the C++
/// constants in `t_display_s3_raster.cpp` + `t_display_s3_board.hpp`.
struct DisplayGeometry {
    /// C++ `kTDisplayS3LogicalDisplayWidth`.
    logical_width: i32,
    /// C++ `kTDisplayS3LogicalDisplayHeight`.
    logical_height: i32,
    /// Boot-frame border thickness (the literal `4` in the C++ raster).
    boot_border_px: i32,
    /// Boot-frame title band height (the literal `56`).
    boot_title_band_height: i32,
    /// Boot-frame checker cell size (the literal `16`).
    boot_checker_px: i32,
    /// C++ `kGlyphWidth`.
    glyph_width: i32,
    /// C++ `kGlyphHeight`.
    glyph_height: i32,
    /// C++ `kGlyphSpacing`.
    glyph_spacing: i32,
    /// C++ `kHeaderHeight`.
    header_height: i32,
    /// C++ `kHeaderRightMargin`.
    header_right_margin: i32,
    /// C++ `kFooterY`.
    footer_y: i32,
    /// C++ `kFooterActionScale`.
    footer_action_scale: i32,
    /// C++ `kBodyY`.
    body_y: i32,
    /// C++ `kBodyLineHeight`.
    body_line_height: i32,
    /// C++ `kCompactBodyLineHeight`.
    compact_body_line_height: i32,
}

/// A display/button board profile: everything the retired C++ board app kept
/// as `nsealr_esp32` constants, as one parameter block.
struct BoardProfile {
    /// C++ `t_display_s3_review_limits()`.
    review_limits: ReviewDisplayLimits,
    /// C++ `kTDisplayS3ButtonDebounceMs` / `kTDisplayS3ButtonLongPressMs`.
    button_timings: ButtonTimings,
    /// C++ `kTDisplayS3Button1Gpio` (Back / long-press Reject).
    back_reject_gpio: i32,
    /// C++ `kTDisplayS3Button2Gpio` (Next / long-press Approve).
    next_approve_gpio: i32,
    geometry: DisplayGeometry,
    palette: DisplayPalette,
}

/// The T-Display-S3 profile instance — the values the retired C++ board app
/// hard-coded.
const T_DISPLAY_S3: BoardProfile = BoardProfile {
    review_limits: ReviewDisplayLimits {
        max_title_chars: 18,
        max_body_lines: 5,
        max_line_chars: 26,
        max_compact_body_lines: 9,
        max_compact_line_chars: 48,
    },
    button_timings: ButtonTimings {
        debounce_ms: 40,
        long_press_ms: 800,
    },
    back_reject_gpio: 0,
    next_approve_gpio: 14,
    geometry: DisplayGeometry {
        logical_width: 320,
        logical_height: 170,
        boot_border_px: 4,
        boot_title_band_height: 56,
        boot_checker_px: 16,
        glyph_width: 5,
        glyph_height: 7,
        glyph_spacing: 1,
        header_height: 30,
        header_right_margin: 10,
        footer_y: 148,
        footer_action_scale: 2,
        body_y: 42,
        body_line_height: 20,
        compact_body_line_height: 11,
    },
    palette: DisplayPalette {
        black: 0x0000,
        white: 0xFFFF,
        blue: 0x001F,
        dark_blue: 0x0008,
        green: 0x07E0,
        yellow: 0xFFE0,
        amber: 0xFEA0,
    },
};

/// Builds a [`ReviewDisplayFrame`] through the crate's public field surface
/// (the C++ tests assigned `std::string` fields directly).
fn make_frame(
    title: &str,
    page_indicator: &str,
    body: &[&str],
    action_hint: &str,
    styles: &[ReviewBodyLineStyle],
) -> ReviewDisplayFrame {
    let mut lines = ReviewPageLines::new();
    for line in body {
        lines.try_push(line).unwrap();
    }
    let mut line_styles = ReviewBodyLineStyles::new();
    for style in styles {
        line_styles.try_push(*style).unwrap();
    }
    ReviewDisplayFrame {
        title: title.parse().unwrap(),
        page_indicator: page_indicator.parse().unwrap(),
        body_lines: lines,
        action_hint: action_hint.parse().unwrap(),
        body_line_styles: line_styles,
    }
}

/// The 5x7 glyph table, transcribed verbatim from the C++ `glyph_rows_for`
/// (`t_display_s3_raster.cpp`); unknown characters fall back to the `?` glyph.
fn glyph_rows(ch: u8) -> [u8; 7] {
    match ch {
        b'A' => [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        b'B' => [0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E],
        b'C' => [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E],
        b'D' => [0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E],
        b'E' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F],
        b'F' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10],
        b'G' => [0x0E, 0x11, 0x10, 0x13, 0x11, 0x11, 0x0F],
        b'H' => [0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        b'I' => [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1F],
        b'J' => [0x01, 0x01, 0x01, 0x01, 0x11, 0x11, 0x0E],
        b'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        b'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F],
        b'M' => [0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11],
        b'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        b'O' => [0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        b'P' => [0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10],
        b'Q' => [0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D],
        b'R' => [0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11],
        b'S' => [0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E],
        b'T' => [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        b'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        b'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04],
        b'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0A],
        b'X' => [0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11],
        b'Y' => [0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04],
        b'Z' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F],
        b'a' => [0x00, 0x00, 0x0E, 0x01, 0x0F, 0x11, 0x0F],
        b'b' => [0x10, 0x10, 0x1E, 0x11, 0x11, 0x11, 0x1E],
        b'c' => [0x00, 0x00, 0x0E, 0x10, 0x10, 0x10, 0x0E],
        b'd' => [0x01, 0x01, 0x0F, 0x11, 0x11, 0x11, 0x0F],
        b'e' => [0x00, 0x00, 0x0E, 0x11, 0x1F, 0x10, 0x0E],
        b'f' => [0x06, 0x08, 0x1E, 0x08, 0x08, 0x08, 0x08],
        b'g' => [0x00, 0x00, 0x0F, 0x11, 0x0F, 0x01, 0x0E],
        b'h' => [0x10, 0x10, 0x1E, 0x11, 0x11, 0x11, 0x11],
        b'i' => [0x04, 0x00, 0x0C, 0x04, 0x04, 0x04, 0x0E],
        b'j' => [0x02, 0x00, 0x02, 0x02, 0x02, 0x12, 0x0C],
        b'k' => [0x10, 0x10, 0x12, 0x14, 0x18, 0x14, 0x12],
        b'l' => [0x0C, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E],
        b'm' => [0x00, 0x00, 0x1A, 0x15, 0x15, 0x15, 0x15],
        b'n' => [0x00, 0x00, 0x1E, 0x11, 0x11, 0x11, 0x11],
        b'o' => [0x00, 0x00, 0x0E, 0x11, 0x11, 0x11, 0x0E],
        b'p' => [0x00, 0x00, 0x1E, 0x11, 0x1E, 0x10, 0x10],
        b'q' => [0x00, 0x00, 0x0F, 0x11, 0x0F, 0x01, 0x01],
        b'r' => [0x00, 0x00, 0x16, 0x18, 0x10, 0x10, 0x10],
        b's' => [0x00, 0x00, 0x0F, 0x10, 0x0E, 0x01, 0x1E],
        b't' => [0x08, 0x08, 0x1E, 0x08, 0x08, 0x09, 0x06],
        b'u' => [0x00, 0x00, 0x11, 0x11, 0x11, 0x11, 0x0F],
        b'v' => [0x00, 0x00, 0x11, 0x11, 0x11, 0x0A, 0x04],
        b'w' => [0x00, 0x00, 0x11, 0x15, 0x15, 0x15, 0x0A],
        b'x' => [0x00, 0x00, 0x11, 0x0A, 0x04, 0x0A, 0x11],
        b'y' => [0x00, 0x00, 0x11, 0x11, 0x0F, 0x01, 0x0E],
        b'z' => [0x00, 0x00, 0x1F, 0x02, 0x04, 0x08, 0x1F],
        b'0' => [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
        b'1' => [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
        b'2' => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F],
        b'3' => [0x1E, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1E],
        b'4' => [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
        b'5' => [0x1F, 0x10, 0x10, 0x1E, 0x01, 0x01, 0x1E],
        b'6' => [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
        b'7' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        b'8' => [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
        b'9' => [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
        b'!' => [0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04],
        b'"' => [0x0A, 0x0A, 0x0A, 0x00, 0x00, 0x00, 0x00],
        b'#' => [0x0A, 0x1F, 0x0A, 0x0A, 0x1F, 0x0A, 0x00],
        b'$' => [0x04, 0x0F, 0x14, 0x0E, 0x05, 0x1E, 0x04],
        b'%' => [0x19, 0x1A, 0x02, 0x04, 0x08, 0x0B, 0x13],
        b'&' => [0x0C, 0x12, 0x14, 0x08, 0x15, 0x12, 0x0D],
        b'\'' => [0x04, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00],
        b'(' => [0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02],
        b')' => [0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08],
        b'*' => [0x00, 0x0A, 0x04, 0x1F, 0x04, 0x0A, 0x00],
        b',' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08],
        b'/' => [0x01, 0x01, 0x02, 0x04, 0x08, 0x10, 0x10],
        b':' => [0x00, 0x04, 0x04, 0x00, 0x04, 0x04, 0x00],
        b';' => [0x00, 0x04, 0x04, 0x00, 0x04, 0x04, 0x08],
        b'<' => [0x02, 0x04, 0x08, 0x10, 0x08, 0x04, 0x02],
        b'=' => [0x00, 0x00, 0x1F, 0x00, 0x1F, 0x00, 0x00],
        b'>' => [0x08, 0x04, 0x02, 0x01, 0x02, 0x04, 0x08],
        b'?' => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
        b'@' => [0x0E, 0x11, 0x17, 0x15, 0x17, 0x10, 0x0E],
        b'[' => [0x0E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x0E],
        b'\\' => [0x10, 0x10, 0x08, 0x04, 0x02, 0x01, 0x01],
        b']' => [0x0E, 0x02, 0x02, 0x02, 0x02, 0x02, 0x0E],
        b'^' => [0x04, 0x0A, 0x11, 0x00, 0x00, 0x00, 0x00],
        b'`' => [0x08, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00],
        b'-' => [0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00],
        b'+' => [0x00, 0x04, 0x04, 0x1F, 0x04, 0x04, 0x00],
        b'_' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F],
        b'{' => [0x02, 0x04, 0x04, 0x08, 0x04, 0x04, 0x02],
        b'|' => [0x04, 0x04, 0x04, 0x00, 0x04, 0x04, 0x04],
        b'}' => [0x08, 0x04, 0x04, 0x02, 0x04, 0x04, 0x08],
        b'~' => [0x00, 0x00, 0x08, 0x15, 0x02, 0x00, 0x00],
        b'.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C],
        b' ' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        _ => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
    }
}

/// Harness port of the C++ `text_pixel_active`: whether pixel `(x, y)` lands
/// on an active glyph bit of `text` drawn at `(origin_x, origin_y)` with
/// `scale`. Byte-indexed, as the C++ `std::string_view` was.
fn text_pixel_active(
    geometry: &DisplayGeometry,
    text: &str,
    origin_x: i32,
    origin_y: i32,
    scale: i32,
    x: i32,
    y: i32,
) -> bool {
    if x < origin_x || y < origin_y {
        return false;
    }
    let rel_x = x - origin_x;
    let rel_y = y - origin_y;
    let text_height = geometry.glyph_height * scale;
    if rel_y >= text_height {
        return false;
    }

    let cell_width = (geometry.glyph_width + geometry.glyph_spacing) * scale;
    let char_index = rel_x / cell_width;
    if char_index < 0 || char_index as usize >= text.len() {
        return false;
    }
    let local_x = (rel_x % cell_width) / scale;
    if local_x >= geometry.glyph_width {
        return false;
    }
    let local_y = (rel_y / scale) as usize;
    let rows = glyph_rows(text.as_bytes()[char_index as usize]);
    (rows[local_y] >> (geometry.glyph_width - 1 - local_x)) & 0x01 != 0
}

/// Harness port of the C++ `text_width_px`.
fn text_width_px(geometry: &DisplayGeometry, text: &str, scale: i32) -> i32 {
    text.len() as i32 * (geometry.glyph_width + geometry.glyph_spacing) * scale
}

/// Harness port of the C++ `right_aligned_text_x`.
fn right_aligned_text_x(
    geometry: &DisplayGeometry,
    text: &str,
    scale: i32,
    right_margin: i32,
) -> i32 {
    (geometry.logical_width - right_margin - text_width_px(geometry, text, scale)).max(0)
}

/// Harness port of the C++ `body_line_style_for` (missing entries = Normal).
fn body_line_style_for(frame: &ReviewDisplayFrame, index: usize) -> ReviewBodyLineStyle {
    frame
        .body_line_styles
        .as_slice()
        .get(index)
        .copied()
        .unwrap_or(ReviewBodyLineStyle::Normal)
}

/// Harness port of the C++ `body_line_scale` (Normal 2, compact 1).
fn body_line_scale(style: ReviewBodyLineStyle) -> i32 {
    if style == ReviewBodyLineStyle::Normal {
        2
    } else {
        1
    }
}

/// Harness port of the C++ `body_line_height`.
fn body_line_height(geometry: &DisplayGeometry, style: ReviewBodyLineStyle) -> i32 {
    if style == ReviewBodyLineStyle::Normal {
        geometry.body_line_height
    } else {
        geometry.compact_body_line_height
    }
}

/// Harness port of the C++ `body_line_color`.
fn body_line_color(palette: &DisplayPalette, style: ReviewBodyLineStyle) -> u16 {
    match style {
        ReviewBodyLineStyle::Meta => palette.green,
        ReviewBodyLineStyle::Value => palette.yellow,
        ReviewBodyLineStyle::Normal => palette.white,
    }
}

/// Harness port of the C++ boot raster `t_display_s3_boot_frame_color_for`,
/// parameterized over the profile.
fn boot_frame_color_for(profile: &BoardProfile, x: i32, y: i32) -> u16 {
    let geometry = &profile.geometry;
    if x < geometry.boot_border_px
        || x >= geometry.logical_width - geometry.boot_border_px
        || y < geometry.boot_border_px
        || y >= geometry.logical_height - geometry.boot_border_px
    {
        return profile.palette.white;
    }
    if y < geometry.boot_title_band_height {
        return profile.palette.blue;
    }
    if ((x / geometry.boot_checker_px) + (y / geometry.boot_checker_px)) % 2 == 0 {
        return profile.palette.green;
    }
    profile.palette.black
}

/// Harness port of the C++ review raster `t_display_s3_review_frame_color_for`,
/// parameterized over the profile, consuming the crate's public
/// [`ReviewDisplayFrame`]. The inline `10`/`7`/`2` title origin+scale and
/// `9`/`1` indicator baseline+scale literals mirror the C++'s own inline
/// literals.
fn review_frame_color_for(
    profile: &BoardProfile,
    frame: &ReviewDisplayFrame,
    x: i32,
    y: i32,
) -> u16 {
    let geometry = &profile.geometry;
    if y < geometry.header_height {
        if text_pixel_active(geometry, frame.title.as_str(), 10, 7, 2, x, y) {
            return profile.palette.white;
        }
        let indicator = frame.page_indicator.as_str();
        if text_pixel_active(
            geometry,
            indicator,
            right_aligned_text_x(geometry, indicator, 1, geometry.header_right_margin),
            9,
            1,
            x,
            y,
        ) {
            return profile.palette.green;
        }
        return profile.palette.dark_blue;
    }

    let mut line_y = geometry.body_y;
    for (index, line) in frame.body_lines.as_slice().iter().enumerate() {
        if index >= profile.review_limits.max_compact_body_lines {
            break;
        }
        let style = body_line_style_for(frame, index);
        if text_pixel_active(
            geometry,
            line.as_str(),
            10,
            line_y,
            body_line_scale(style),
            x,
            y,
        ) {
            return body_line_color(&profile.palette, style);
        }
        line_y += body_line_height(geometry, style);
    }

    if y >= geometry.footer_y {
        if text_pixel_active(
            geometry,
            frame.action_hint.as_str(),
            10,
            geometry.footer_y + 4,
            geometry.footer_action_scale,
            x,
            y,
        ) {
            return profile.palette.black;
        }
        return profile.palette.amber;
    }

    profile.palette.black
}

/// A classified press paired with its board pin — the C++
/// `TDisplayS3ButtonEvent` (the GPIO echo is board glue, so the pairing
/// happens here, not in the crate).
struct BoardButtonEvent {
    button: ReviewButton,
    gpio: i32,
    long_press: bool,
}

/// Harness port of the C++ `update_t_display_s3_button_state` signature: the
/// profile supplies the timings, the GPIO rides along unchanged.
fn update_board_button(
    profile: &BoardProfile,
    state: &mut ButtonState,
    pressed: bool,
    now_ms: i64,
    gpio: i32,
    short_press_button: ReviewButton,
    long_press_button: ReviewButton,
) -> Option<BoardButtonEvent> {
    update_button_state(
        state,
        pressed,
        now_ms,
        profile.button_timings,
        short_press_button,
        long_press_button,
    )
    .map(|event| BoardButtonEvent {
        button: event.button,
        gpio,
        long_press: event.long_press,
    })
}

/// Harness port of the C++ `non_signing_body_lines` (board copy).
const NON_SIGNING_BODY_LINES: [&str; 3] = ["Not signed", "Signing disabled", "Send new request"];

/// Harness port of the C++ `build_t_display_s3_ready_frame` (board copy).
fn ready_frame() -> ReviewDisplayFrame {
    make_frame(
        "Ready",
        "No request",
        &["USB signer", "Send sign_event", "Signing disabled"],
        "Waiting",
        &[],
    )
}

/// Harness port of the C++ `build_t_display_s3_review_decision_frame`.
fn review_decision_frame(approved: bool) -> ReviewDisplayFrame {
    make_frame(
        if approved { "Review OK" } else { "Rejected" },
        "Closed",
        &NON_SIGNING_BODY_LINES,
        "Waiting",
        &[],
    )
}

/// Harness port of the C++ `build_t_display_s3_review_timeout_frame`.
fn review_timeout_frame() -> ReviewDisplayFrame {
    make_frame(
        "Review Timeout",
        "Expired",
        &NON_SIGNING_BODY_LINES,
        "Waiting",
        &[],
    )
}

/// Harness port of the C++ `build_t_display_s3_request_error_frame`.
fn request_error_frame() -> ReviewDisplayFrame {
    make_frame(
        "Request Error",
        "Rejected",
        &NON_SIGNING_BODY_LINES,
        "Waiting",
        &[],
    )
}

/// Asserts a frame's body lines equal `expected`, line for line.
fn assert_body_lines(frame: &ReviewDisplayFrame, expected: &[&str]) {
    assert_eq!(frame.body_lines.len(), expected.len());
    for (line, want) in frame.body_lines.as_slice().iter().zip(expected) {
        assert_eq!(line, want);
    }
}

// Port of the C++ `test_t_display_s3_raster_has_stable_boot_and_review_pixels`:
// the boot and review rasters are deterministic pure functions of the frame and
// the profile, sampled at the same pixels with the same expected colors. The
// compact frame is additionally produced by the crate's public
// `render_review_page` with the profile limits (full stack: renderer output
// drives the raster; the C++ hand-built it, and both must be identical).
#[test]
fn t_display_s3_raster_has_stable_boot_and_review_pixels() {
    let profile = &T_DISPLAY_S3;

    assert_eq!(boot_frame_color_for(profile, 0, 0), profile.palette.white);
    assert_eq!(boot_frame_color_for(profile, 10, 10), profile.palette.blue);
    assert_eq!(boot_frame_color_for(profile, 20, 60), profile.palette.green);
    assert_eq!(boot_frame_color_for(profile, 10, 60), profile.palette.black);

    let frame = make_frame(
        "Ready",
        "Page 1/3",
        &["USB signer", "Send sign_event", "Signing disabled"],
        "Waiting",
        &[],
    );

    assert_eq!(profile.review_limits.max_title_chars, 18);
    assert_eq!(profile.review_limits.max_body_lines, 5);
    assert_eq!(profile.review_limits.max_line_chars, 26);
    assert_eq!(profile.review_limits.max_compact_body_lines, 9);
    assert_eq!(profile.review_limits.max_compact_line_chars, 48);
    assert_eq!(
        review_frame_color_for(profile, &frame, 0, 0),
        profile.palette.dark_blue,
    );
    assert_eq!(
        review_frame_color_for(profile, &frame, 10, 7),
        profile.palette.white,
    );
    assert_eq!(
        review_frame_color_for(profile, &frame, 262, 9),
        profile.palette.green,
    );
    assert_eq!(
        review_frame_color_for(profile, &frame, 10, 42),
        profile.palette.white,
    );
    assert_eq!(
        review_frame_color_for(profile, &frame, 0, 160),
        profile.palette.amber,
    );
    assert_eq!(
        review_frame_color_for(profile, &frame, 10, 152),
        profile.palette.black,
    );

    let compact_frame = make_frame(
        "Content",
        "Page 2/4",
        &["bytes: 281", "abcdef"],
        "Next",
        &[ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value],
    );
    // Full stack: the crate's own renderer, fed the profile limits, produces
    // exactly this frame (beyond the C++ assertions, which hand-built it).
    let mut page_lines = ReviewPageLines::new();
    page_lines.try_push("bytes: 281").unwrap();
    page_lines.try_push("abcdef").unwrap();
    let rendered = render_review_page(
        &ReviewPage {
            title: "Content",
            lines: page_lines.as_slice(),
            action: ReviewPageAction::Next,
            page_indicator: "Page 2/4",
            body_line_styles: &[ReviewBodyLineStyle::Meta, ReviewBodyLineStyle::Value],
        },
        1,
        4,
        profile.review_limits,
    )
    .unwrap();
    assert_eq!(rendered, compact_frame);

    assert_eq!(
        review_frame_color_for(profile, &compact_frame, 10, 42),
        profile.palette.green,
    );
    assert_eq!(
        review_frame_color_for(profile, &compact_frame, 11, 55),
        profile.palette.yellow,
    );

    let lowercase_frame = make_frame(
        "Content",
        "Page 2/4",
        &["a"],
        "Next",
        &[ReviewBodyLineStyle::Value],
    );
    assert_eq!(
        review_frame_color_for(profile, &lowercase_frame, 11, 44),
        profile.palette.yellow,
    );

    let comma_frame = make_frame(
        "Content",
        "Page 2/4",
        &[","],
        "Next",
        &[ReviewBodyLineStyle::Value],
    );
    assert_eq!(
        review_frame_color_for(profile, &comma_frame, 12, 47),
        profile.palette.yellow,
    );

    let ascii_frame = make_frame("ASCII", "Page 1/1", &["^`"], "Next", &[]);
    assert_eq!(
        review_frame_color_for(profile, &ascii_frame, 12, 44),
        profile.palette.white,
    );
    assert_eq!(
        review_frame_color_for(profile, &ascii_frame, 28, 46),
        profile.palette.white,
    );

    // Coverage sweep beyond the C++ assertions: every glyph row in the
    // transcribed table (every arm, including the `?` fallback) stays within
    // the 5-bit glyph width.
    for ch in 0u8..=0x7F {
        for row in glyph_rows(ch) {
            assert!(row <= 0x1F, "glyph 0x{ch:02x} row exceeds 5 bits");
        }
    }
}

// Port of the C++
// `test_t_display_s3_button_logic_classifies_debounced_short_and_long_presses`:
// bounce releases are swallowed, short presses map to the short button, presses
// at/over the long threshold map to the long button, on both board buttons.
#[test]
fn t_display_s3_button_logic_classifies_debounced_short_and_long_presses() {
    let profile = &T_DISPLAY_S3;
    let mut state = ButtonState::new();

    assert!(update_board_button(
        profile,
        &mut state,
        true,
        1000,
        profile.next_approve_gpio,
        ReviewButton::Next,
        ReviewButton::Approve,
    )
    .is_none());
    assert!(update_board_button(
        profile,
        &mut state,
        false,
        1010,
        profile.next_approve_gpio,
        ReviewButton::Next,
        ReviewButton::Approve,
    )
    .is_none());

    assert!(update_board_button(
        profile,
        &mut state,
        true,
        2000,
        profile.next_approve_gpio,
        ReviewButton::Next,
        ReviewButton::Approve,
    )
    .is_none());
    let short_press = update_board_button(
        profile,
        &mut state,
        false,
        2040,
        profile.next_approve_gpio,
        ReviewButton::Next,
        ReviewButton::Approve,
    )
    .unwrap();
    assert_eq!(short_press.button, ReviewButton::Next);
    assert_eq!(short_press.gpio, 14);
    assert!(!short_press.long_press);

    let mut back_state = ButtonState::new();
    assert!(update_board_button(
        profile,
        &mut back_state,
        true,
        4000,
        profile.back_reject_gpio,
        ReviewButton::Back,
        ReviewButton::Reject,
    )
    .is_none());
    let back_press = update_board_button(
        profile,
        &mut back_state,
        false,
        4040,
        profile.back_reject_gpio,
        ReviewButton::Back,
        ReviewButton::Reject,
    )
    .unwrap();
    assert_eq!(back_press.button, ReviewButton::Back);
    assert_eq!(back_press.gpio, 0);
    assert!(!back_press.long_press);

    assert!(update_board_button(
        profile,
        &mut state,
        true,
        3000,
        profile.back_reject_gpio,
        ReviewButton::Back,
        ReviewButton::Reject,
    )
    .is_none());
    let long_press = update_board_button(
        profile,
        &mut state,
        false,
        3800,
        profile.back_reject_gpio,
        ReviewButton::Back,
        ReviewButton::Reject,
    )
    .unwrap();
    assert_eq!(long_press.button, ReviewButton::Reject);
    assert_eq!(long_press.gpio, 0);
    assert!(long_press.long_press);

    let mut approve_state = ButtonState::new();
    assert!(update_board_button(
        profile,
        &mut approve_state,
        true,
        5000,
        profile.next_approve_gpio,
        ReviewButton::Next,
        ReviewButton::Approve,
    )
    .is_none());
    let approve_press = update_board_button(
        profile,
        &mut approve_state,
        false,
        5800,
        profile.next_approve_gpio,
        ReviewButton::Next,
        ReviewButton::Approve,
    )
    .unwrap();
    assert_eq!(approve_press.button, ReviewButton::Approve);
    assert_eq!(approve_press.gpio, 14);
    assert!(approve_press.long_press);
}

// Port of the C++ `test_t_display_s3_status_frames_keep_non_signing_copy_stable`:
// the ready/decision/timeout/request-error status copy is stable, and every
// non-ready frame shares the same non-signing body.
#[test]
fn t_display_s3_status_frames_keep_non_signing_copy_stable() {
    let ready = ready_frame();
    assert_eq!(ready.title, "Ready");
    assert_eq!(ready.page_indicator, "No request");
    assert_body_lines(
        &ready,
        &["USB signer", "Send sign_event", "Signing disabled"],
    );
    assert_eq!(ready.action_hint, "Waiting");

    let approved = review_decision_frame(true);
    assert_eq!(approved.title, "Review OK");
    assert_eq!(approved.page_indicator, "Closed");
    assert_body_lines(
        &approved,
        &["Not signed", "Signing disabled", "Send new request"],
    );
    assert_eq!(approved.action_hint, "Waiting");

    let rejected = review_decision_frame(false);
    assert_eq!(rejected.title, "Rejected");
    assert_eq!(rejected.page_indicator, "Closed");
    assert_eq!(rejected.body_lines, approved.body_lines);
    assert_eq!(rejected.action_hint, "Waiting");

    let timeout = review_timeout_frame();
    assert_eq!(timeout.title, "Review Timeout");
    assert_eq!(timeout.page_indicator, "Expired");
    assert_eq!(timeout.body_lines, approved.body_lines);
    assert_eq!(timeout.action_hint, "Waiting");

    let error = request_error_frame();
    assert_eq!(error.title, "Request Error");
    assert_eq!(error.page_indicator, "Rejected");
    assert_eq!(error.body_lines, approved.body_lines);
    assert_eq!(error.action_hint, "Waiting");
}

// Port of the C++ `test_t_display_s3_serial_input_drains_after_overlong_frame`:
// an overlong line is discarded with one OverlongFrame event (no line — the
// C++ asserted `line.empty()`; here the variant carries none), the drain
// swallows everything up to and including the next newline, and the
// accumulator then delivers the following line intact (newline included, CR
// skipped). The C++ only asserted the final event of the "ok\r\n" replay; the
// per-byte None assertions here are a superset.
#[test]
fn t_display_s3_serial_input_drains_after_overlong_frame() {
    let mut input = SerialLineInput::new();
    for ch in *b"12345678" {
        assert_eq!(input.push_byte(ch, 8).unwrap(), SerialInputEvent::None);
    }

    assert_eq!(
        input.push_byte(b'9', 8).unwrap(),
        SerialInputEvent::OverlongFrame,
    );

    for ch in *b"tail" {
        assert_eq!(input.push_byte(ch, 8).unwrap(), SerialInputEvent::None);
    }
    assert_eq!(input.push_byte(b'\n', 8).unwrap(), SerialInputEvent::None);

    for ch in *b"ok\r" {
        assert_eq!(input.push_byte(ch, 8).unwrap(), SerialInputEvent::None);
    }
    assert_eq!(
        input.push_byte(b'\n', 8).unwrap(),
        SerialInputEvent::FrameReady(b"ok\n"),
    );

    // Full stack (beyond the C++ assertions): a real encoded serial frame fed
    // byte-wise through the accumulator decodes with the crate's own decoder.
    let mut stream = SerialLineInput::new();
    let mut buf = [0u8; MAX_SERIAL_FRAME_BYTES];
    let encoded = encode_serial_frame(FrameType::Request, b"eyJ2ZXJzaW9uIjoxfQ", &mut buf).unwrap();
    let mut delivered = false;
    for &ch in encoded {
        match stream.push_byte(ch, MAX_SERIAL_FRAME_BYTES).unwrap() {
            SerialInputEvent::None => {}
            SerialInputEvent::FrameReady(line) => {
                let decoded = decode_serial_frame(line).unwrap();
                assert_eq!(decoded.frame_type, FrameType::Request);
                assert_eq!(decoded.payload_base64url, b"eyJ2ZXJzaW9uIjoxfQ");
                delivered = true;
            }
            SerialInputEvent::OverlongFrame => panic!("unexpected overlong frame"),
        }
    }
    assert!(delivered);
}
