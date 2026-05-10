# Detailed Review Pagination

Date: 2026-05-10

## Goal

The ESP32 trusted-review display must let the user inspect the complete event before any approval action is accepted. Long content and long tag values must not be shortened with ellipses in the physical review flow.

## UX Rule

- Short KEY/GPIO14 advances through the stable top-level review pages:
  Event, Content, Tags, Decision, then back to Event.
- Short BOOT/GPIO0 scrolls inside the current top-level page when that page has
  more lines than fit in one display window; on a single-window page it leaves
  the top-level page unchanged.
- Long KEY/GPIO14 can approve only on the Decision page.
- Long BOOT/GPIO0 can reject at any point.
- Event, Content, Tags, and Decision are the stable logical pages.
- Content and Tags may span scroll windows when they do not fit.
- The header keeps the logical page stable, for example `Page 3/4` or
  `Page 3/4 Lines 1-9/18` for the first Tags scroll window.
- The footer shows `Next/Scroll` on top-level pages with additional scroll
  windows.
- Approval does not require forced traversal through every scroll window; the
  user can inspect Content or Tags with BOOT/GPIO0 and move to the next
  top-level page with KEY/GPIO14.
- The body may use compact text so long content and grouped tag content are
  readable without turning every wrapped line into a separate logical page.
- Tags are displayed as grouped content instead of interpreted tag labels or
  raw JSON punctuation. Each tag is shown as `Tag N/M`, followed by its visible
  non-empty items as plain lines, for example `p`, a pubkey value, `mention`,
  `t`, and `nostrseal`. This keeps review behavior universal across all event
  kinds and custom tag semantics while prioritizing the event content on a
  small display.
- If a tag item is longer than one display line, continuation lines are
  indented with two spaces and keep the same body style as the first line of
  that item.
- The final page uses neutral decision/check language, not subjective warnings.

## Safety Rule

The firmware must reject input it cannot parse or represent safely. For valid input that fits the NostrSeal v0 limits, the display path should show the event fields completely instead of relying on heuristic warnings such as "long content" or "many tags".

## Scope

This pass updates ESP32 display pagination only. Real signing remains disabled. The existing shared approval digest contract remains unchanged until the full-review display format is promoted into `specs` and consumed by companion/Raspberry/ESP32 together.

## Acceptance

- Host-core tests prove scroll-window pages contain the complete content and visible
  tag items without `...`.
- Host-core tests prove logical page indicators and body styles survive through
  rendering.
- Serial/manual review sessions use the scroll-window pages.
- Existing shared review vectors still pass.
- Manual T-Display S3 smoke can exercise tagged and long-content events while signing remains disabled.
