# Detailed Review Pagination

Date: 2026-05-10

## Goal

The ESP32 trusted-review display must let the user inspect the complete event before any approval action is accepted. Long content and long tag values must not be shortened with ellipses in the physical review flow.

## UX Rule

- Short KEY/GPIO14 advances through review pages.
- Short BOOT/GPIO0 goes back through review pages.
- Long KEY/GPIO14 can approve only on the final decision page.
- Long BOOT/GPIO0 can reject at any point.
- Content and tags may span multiple pages.
- The final page uses neutral decision/check language, not subjective warnings.

## Safety Rule

The firmware must reject input it cannot parse or represent safely. For valid input that fits the NostrSeal v0 limits, the display path should show the event fields completely instead of relying on heuristic warnings such as "long content" or "many tags".

## Scope

This pass updates ESP32 display pagination only. Real signing remains disabled. The existing shared approval digest contract remains unchanged until the full-detail review format is promoted into `specs` and consumed by companion/Raspberry/ESP32 together.

## Acceptance

- Host-core tests prove detailed pages contain the complete content and tag field values without `...`.
- Serial/manual review sessions use the detailed pages.
- Existing shared review vectors still pass.
- Manual T-Display S3 smoke can exercise tagged and long-content events while signing remains disabled.
