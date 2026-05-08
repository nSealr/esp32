# Architecture

`NostrSeal/esp32` contains firmware for ESP32-based signer targets.

## Targets

- ESP32 USB/NIP-46 signer, with ESP32-S3 as the primary target.
- ESP32 stateless QR vault target, with T-Display S3 Pro OV5640 as the primary
  camera/display target.
- Classic ESP32/TTGO compatibility target under the USB/NIP-46 family.
- ESP32-S3 plus TROPIC01 prototype only under the custom persistent-secret
  hardware-wallet research family.

## Responsibilities

- Parse NostrSeal signing requests.
- Render trusted review on local display where available.
- Require physical approval or rejection.
- Sign only after approval.
- Return verifiable responses to the companion.
- Document secure boot, flash encryption, provisioning, and recovery.

ESP-IDF is the default firmware framework for serious ESP32-S3 work.

The ESP32 stateless QR vault target is part of this repository, not the
Raspberry repository. It should reuse shared `NostrSeal/specs` contracts for
the QR envelope, trusted-review model, review-screen vectors, `approval_digest`,
and signing vectors while implementing camera/display/button handling with
ESP32 firmware components. It must not add persistent-secret storage or
TROPIC01 dependencies.

## Implemented Host Core

The first firmware foundation is host-buildable C++ under
`firmware/host_core`.

- `serial_frame`: encodes and decodes newline-terminated `nseal1f:` frames with
  type, base64url JSON payload, and checksum.
- `qr_envelope`: decodes `nseal1:` QR envelopes, validates unpadded base64url
  payloads, validates UTF-8, applies shared v0 QR/request size limits, and
  requires a decoded JSON container for the future ESP32-S3 QR vault target.
  It also classifies decoded `sign_event` requests by top-level metadata,
  rejects unknown request/template fields where host-core owns the boundary,
  extracts the raw `params.event_template` object boundary, and rejects
  host-supplied `id`, `pubkey`, or `sig` fields before review/signing code
  exists. It parses only the minimum unsigned event-template fields:
  `created_at`, `kind`, `tags`, and `content`, with constrained tag/content
  limits mirrored from `NostrSeal/specs`.
- `qr_review`: converts parsed QR signing requests into renderer-neutral
  trusted-review pages and QR-derived `approval_digest` values that match the
  shared review-screen vectors.
- `serial_review`: converts decoded serial/USB `sign_event` request JSON into
  the same renderer-neutral trusted-review request and `approval_digest` used
  by the QR path. This gives the USB signer path a review boundary before a
  display driver, GPIO buttons, storage, or signing backend exists. It also
  defines the serial/display/button I/O harness for future USB signer adapter
  acceptance tests.
- `qr_review_flow`: host-core flow boundary from raw scanned `nseal1:` QR
  envelopes to trusted review frames and approval state. It includes the
  `QrReviewIo` adapter harness for future scanner, display, and GPIO button
  code, returns the displayed frame/button transcript from that harness, and has
  no signing backend.
- `sha256`: portable SHA-256 helper used for the frame checksum.
- `signing_policy`: host-buildable runtime-signing readiness gate. It requires
  the explicit runtime feature flag, parser limits, trusted display acceptance,
  physical approval controls, approval-digest binding, key provisioning, secure
  boot, debug lock, and companion signed-output verification before firmware
  can be considered ready to connect a signing backend.
- `approval_gate`: request-id and approval-digest bound approval state
  machine, checked against shared `NostrSeal/specs` review-screen vectors.
- `review_controls`: page-by-page review button state machine for future
  display/button adapters. It refuses approval until the final review page is
  reached, keeps rejection available before signing, and treats approval or
  rejection as terminal.
- `review_display`: renderer-neutral trusted display frame builder for future
  ESP32-S3 display drivers. It turns a review page into bounded title, page
  indicator, body lines, and action hint fields. Body lines are wrapped and
  truncated to configured limits before any graphical display driver exists.
- `trusted_review`: host-buildable review session boundary that combines owned
  review pages, `review_display` frames, `review_controls` button navigation,
  and `approval_gate` request/digest binding. It is the first firmware-core
  object a future display/button adapter can drive without touching signing
  code.
- `device_protocol`: scaffold request dispatcher for shared-spec capability,
  development public-key, and disabled-signing responses. It parses the serial
  request payload enough to validate v0 request ids and echo dynamic
  `request_id` values. Valid serial/USB `sign_event` requests are also forced
  through the trusted-review request builder before the dispatcher returns
  `signing_disabled`. It does not sign events.

This code is intentionally independent of ESP-IDF so protocol and approval
logic can be tested on desktop before it is wrapped by USB CDC, UART, display,
button, secure storage, and signing components.

Host tests generate their transport-vector header from `NostrSeal/specs` so the
firmware core is checked against the same serial frame vector used by the
companion. The same generated header now includes review-screen approval
digests, trusted review request factories, review-display-frame vectors, QR
review transcripts, the shared v0 limit profile, invalid serial-frame vectors,
and invalid QR/signing-request hardening vectors, allowing the host-core
parser, approval gate, and trusted-review session to reject unsafe input before
any future signing backend is connected.

The review-control state machine is intentionally separate from
`approval_gate`: `review_controls` models local user navigation, while
`approval_gate` binds the final approval to the request id and
`approval_digest`. The future display/button adapter must satisfy both before a
real signing backend can be connected.

The review-display renderer is also intentionally hardware-neutral. It does not
drive ST7789, ILI9341, OLED, or LVGL directly; it produces a small bounded
frame, wraps/truncates body text to the configured limits, and keeps unsafe
title or limit settings out of the driver boundary. A later ESP-IDF display
adapter can paint that frame without changing review, approval, or signing
semantics.

The QR envelope decoder is similarly hardware-neutral. It accepts the same
`nseal1:` envelope contract used by Raspberry and the companion, but it does
not perform camera capture, animated QR reconstruction, review output on real
hardware, or signing. Its request parser extracts version, `request_id`,
method, `params` presence, and the raw `params.event_template` object boundary
before later review code does real request handling. It also tolerates normal
JSON string escapes, applies shared resource limits, and rejects event
templates that already include `id`, `pubkey`, or `sig`. Those layers must be
added behind separate tests and must continue to consume shared vectors from
`NostrSeal/specs`. The current field parser validates only the unsigned
event-template primitives that future review generation needs; tag semantics,
event id computation, key storage, and signing remain absent.

The QR review builder consumes those parsed primitives and emits the same page
order, text, and `approval_digest` as `NostrSeal/specs` review-screen vectors
for basic and tagged kind `1` requests. It can create a `TrustedReviewSession`
from a parsed QR request, so the future QR path can reuse the same bounded
display frames, final-page traversal, and request/digest-bound approval gate as
the USB/display signer line. It still stops before hardware display output or
signing.

The serial review boundary reuses that same request parser, page builder, and
`approval_digest` computation for decoded USB/serial `sign_event` request JSON.
The current device protocol calls this boundary for valid `sign_event` frames,
then still returns `signing_disabled`. This is intentional: it proves the USB
signer path cannot later diverge from the shared trusted-review contract while
keeping real signing blocked until display/GPIO, custody, and provisioning
gates pass.

`SerialReviewFlow` and `SerialReviewIo` extend that boundary to future display
and GPIO drivers for the USB signer. A transport adapter supplies one decoded
request JSON payload, a display adapter paints each bounded trusted frame, and
physical controls provide `next`, `approve`, or `reject`. The harness records
the frame/button transcript and terminal approval state but still has no
signature-producing function.

`QrReviewFlow` packages that sequence for future scanner/display adapters: raw
QR envelope decode, request parsing, trusted-review construction, frame
rendering, and button handling. Rejected QR requests fail before any review
frame is shown. Approval only reaches the host-core approval state; there is no
signature-producing function in this flow.

`QrReviewIo` is the first driver-facing harness for that flow. A future camera
adapter provides one scanned QR envelope, a display adapter paints the bounded
frame supplied by host-core, and physical controls provide `next`, `approve`,
or `reject`. The harness shows the current trusted frame before every button
read, bounds non-terminal button streams, and returns the terminal approval
state together with the exact frame/button transcript produced by the adapter
loop, keeping camera/display/GPIO bring-up separate from key storage and
signing.

The QR review transcript helper and `QrReviewIo` result both record the frame
shown before each physical button input, the optional terminal decision, and
whether the approval gate has been satisfied. This gives display/GPIO adapters a
deterministic host-side oracle for review-loop tests without introducing a
signing backend. ESP32 host-core tests consume the shared `NostrSeal/specs` QR
review-transcript vectors so future firmware adapters stay aligned with the
cross-repository review contract.

The trusted-review session intentionally stops before hardware drivers, key
storage, or Schnorr signing. It proves the local review loop can only reach
`can_sign` after the user has traversed the displayed pages and approved the
request bound to the displayed `approval_digest`.

The signing-policy module is the complementary runtime gate. It does not sign
and it does not provision keys; it records every condition that must be true
before a later signing backend can be wired into the USB or QR flows. The
default readiness state is disabled and reports every missing gate.

## ESP-IDF Scaffold

`firmware/esp32_s3_usb_signer` is the first ESP-IDF project scaffold for the
ESP32-S3 USB signer. It currently boots, uses native USB Serial/JTAG as the
primary ESP-IDF console, reads newline-terminated `nseal1f:` frames from that
console with the shared v0 serial-frame byte limit, answers the shared
`get_capabilities` request and other valid v0 request ids, returns the shared
development public key for `get_public_key`, returns `signing_disabled` for
valid `sign_event` requests, and logs that signing is disabled. It does not
yet include storage, production key provisioning, display review, button
approval, or signing components.
