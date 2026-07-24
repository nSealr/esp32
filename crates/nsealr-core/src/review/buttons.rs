//! Physical button debounce classification — press durations become
//! [`ReviewButton`] events.
//!
//! Ported from the C++ reference board app sources
//! `esp32_s3_usb_signer/main/t_display_s3_button_logic.cpp/.hpp` for behaviour
//! parity, generalized in milestone M-T3.7: the T-Display-S3 timing constants
//! (`kTDisplayS3ButtonDebounceMs` = 40, `kTDisplayS3ButtonLongPressMs` = 800)
//! become the caller-supplied [`ButtonTimings`] board-profile value, and the
//! C++ event's GPIO echo stays in board code (it carried no classification
//! logic — the board pairs its own pin number with the event). This state
//! machine is the shared input side of the physical-approval contract: every
//! board maps debounced presses onto the [`ReviewButton`] values the review
//! sessions ([`crate::review::controls`], [`crate::review::trusted`]) consume.

use crate::review::controls::ReviewButton;

/// Debounce and long-press thresholds for one physical button — a board
/// profile value. Mirrors the C++ `kTDisplayS3ButtonDebounceMs` /
/// `kTDisplayS3ButtonLongPressMs` constants, generalized per board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ButtonTimings {
    /// Releases shorter than this many milliseconds are ignored as switch
    /// bounce (C++ `kTDisplayS3ButtonDebounceMs`, 40 on the T-Display-S3).
    pub debounce_ms: i64,
    /// Presses at least this many milliseconds long classify as a long press
    /// (C++ `kTDisplayS3ButtonLongPressMs`, 800 on the T-Display-S3).
    pub long_press_ms: i64,
}

/// A classified debounced press. Mirrors the C++ `TDisplayS3ButtonEvent`
/// without the board-glue `gpio` echo field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ButtonEvent {
    /// The review button the press maps to (the short-press mapping for a
    /// short press, the long-press mapping for a long press).
    pub button: ReviewButton,
    /// `true` if the press reached the long-press threshold.
    pub long_press: bool,
}

/// Per-button debounce state. Mirrors the C++ `TDisplayS3ButtonState`
/// (`pressed` false, `pressed_at_ms` 0 at rest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ButtonState {
    pressed: bool,
    pressed_at_ms: i64,
}

impl ButtonState {
    /// Creates the released rest state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pressed: false,
            pressed_at_ms: 0,
        }
    }
}

impl Default for ButtonState {
    fn default() -> Self {
        Self::new()
    }
}

/// Advances one button's debounce state with a level sample and classifies the
/// completed press, if any. Mirrors the C++ `update_t_display_s3_button_state`
/// with the timing constants replaced by `timings` and the GPIO echo dropped:
/// a press edge arms the state, a release edge measures the duration, releases
/// shorter than [`ButtonTimings::debounce_ms`] are swallowed as bounce, and
/// completed presses map to `short_press_button` or (at
/// [`ButtonTimings::long_press_ms`] and beyond) `long_press_button`.
pub fn update_button_state(
    state: &mut ButtonState,
    pressed: bool,
    now_ms: i64,
    timings: ButtonTimings,
    short_press_button: ReviewButton,
    long_press_button: ReviewButton,
) -> Option<ButtonEvent> {
    if pressed && !state.pressed {
        state.pressed = true;
        state.pressed_at_ms = now_ms;
        return None;
    }

    if !pressed && state.pressed {
        let duration_ms = now_ms - state.pressed_at_ms;
        state.pressed = false;
        state.pressed_at_ms = 0;
        if duration_ms < timings.debounce_ms {
            return None;
        }
        let long_press = duration_ms >= timings.long_press_ms;
        return Some(ButtonEvent {
            button: if long_press {
                long_press_button
            } else {
                short_press_button
            },
            long_press,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMINGS: ButtonTimings = ButtonTimings {
        debounce_ms: 40,
        long_press_ms: 800,
    };

    // The named C++ case (`test_t_display_s3_button_logic_classifies_...`) is
    // ported in `crate::board_profile_tests`. This covers the branches it
    // never reached: the level-unchanged polls (idle release, held press)
    // fall through eventless without disturbing an armed press.
    #[test]
    fn unchanged_levels_produce_no_event() {
        let mut state = ButtonState::default();
        assert_eq!(state, ButtonState::new());

        assert!(update_button_state(
            &mut state,
            false,
            100,
            TIMINGS,
            ReviewButton::Next,
            ReviewButton::Approve,
        )
        .is_none());
        assert!(update_button_state(
            &mut state,
            true,
            200,
            TIMINGS,
            ReviewButton::Next,
            ReviewButton::Approve,
        )
        .is_none());
        assert!(update_button_state(
            &mut state,
            true,
            600,
            TIMINGS,
            ReviewButton::Next,
            ReviewButton::Approve,
        )
        .is_none());

        let event = update_button_state(
            &mut state,
            false,
            1000,
            TIMINGS,
            ReviewButton::Next,
            ReviewButton::Approve,
        )
        .unwrap();
        assert_eq!(
            event,
            ButtonEvent {
                button: ReviewButton::Approve,
                long_press: true,
            },
        );
    }
}
