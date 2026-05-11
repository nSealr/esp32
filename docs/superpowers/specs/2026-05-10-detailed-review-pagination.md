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
- Event shows raw `kind`, raw `created_at`, and the signer author pubkey. It
  does not display inferred kind labels such as `Short Text Note`.
- Content and Tags may span scroll windows when they do not fit.
- The header keeps the logical page stable, for example `Page 3/4` or
  `Page 3/4 Lines 1-9/18` for the first Tags scroll window.
- The footer shows `Next/Scroll` on top-level pages with additional scroll
  windows.
- Approval does not require forced traversal through every scroll window; the
  user can inspect Content or Tags with BOOT/GPIO0 and move to the next
  top-level page with KEY/GPIO14.
- Scroll windows do not repeat the final visible line from the previous
  window. The next window starts at the next unread line so line ranges are
  clear on the small display.
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
- On the current bitmap-font T-Display S3 path, supported printable ASCII,
  including common event punctuation, is rendered directly by explicit glyphs.
  Unsupported UTF-8 codepoints are rendered explicitly as `U+XXXX`/`U+XXXXX`
  fallback text instead of being silently replaced by `?`. This is a safety
  fallback, not a claim of complete Unicode glyph rendering.
- Decoded JSON control characters in event strings render as visible
  JSON-style escapes such as `\n` and `\t`, not as actual spacing on the
  trusted display.
- QR and serial JSON parsers preserve `\uXXXX` escapes, including surrogate
  pairs, before review display fallback is applied.

## Safety Rule

The firmware must reject input it cannot parse or represent safely. For valid input that fits the NostrSeal v0 limits, the display path should show the event fields completely instead of relying on heuristic warnings such as "long content" or "many tags".

## Scope

This pass updates ESP32 display pagination only. Real signing remains disabled. The existing shared approval digest contract remains unchanged until the full-review display format is promoted into `specs` and consumed by companion/Raspberry/ESP32 together.

## Acceptance

- Host-core tests prove scroll-window pages contain the complete content and visible
  tag items without `...`.
- Host-core tests prove logical page indicators and body styles survive through
  rendering.
- Host-core tests prove Event does not infer the kind meaning and includes the
  signer author pubkey.
- Host-core tests prove non-ASCII UTF-8 content and tag values are represented
  by explicit fallback codepoints on the current bitmap-font display path.
- Host-core tests prove supported printable ASCII punctuation remains readable
  instead of being expanded into fallback codepoints.
- Host-core tests prove escaped JSON Unicode content and tag values are not
  degraded to `?` before review.
- Serial/manual review sessions use the scroll-window pages.
- Existing shared review vectors still pass.
- Manual T-Display S3 smoke can exercise tagged and long-content events while signing remains disabled.
