# Architecture

`nSealr/esp32` contains firmware for ESP32-based signer targets.

## Targets

- ESP32 USB/NIP-46 signer, with ESP32-S3 as the primary target.
  The no-camera LILYGO T-Display S3 is tracked here as an integrated display
  candidate for the USB/display signer line. Its current firmware support
  initializes the ST7789/i80 path, draws boot/ready/review/status frames, and
  maps onboard physical buttons for manual review navigation. The security
  profile records manual development acceptance evidence for trusted display
  and physical controls, while production signing acceptance for those gates
  remains blocked.
- ESP32 stateless QR vault target, with T-Display S3 Pro OV5640 as the primary
  camera/display target and Waveshare ESP32-S3 Touch LCD 3.5B-C as the
  confirmed secondary case-plus-OV5640 target.
- Classic ESP32/TTGO compatibility target under the USB/NIP-46 family.
- ESP32-S3 plus TROPIC01 prototype only under the custom persistent-secret
  hardware-wallet research family.

## Responsibilities

- Parse nSealr signing requests.
- Render trusted review on local display where available.
- Require physical approval or rejection.
- Sign only after approval.
- Return verifiable responses to the companion.
- Document secure boot, flash encryption, provisioning, and recovery.

ESP-IDF is the default firmware framework for serious ESP32-S3 work.

The ESP32 stateless QR vault target is part of this repository, not the
Raspberry repository. It should reuse shared `nSealr/specs` contracts for
the QR envelope, trusted-review model, review-screen vectors, `approval_digest`,
and signing vectors while implementing camera/display/button handling with
ESP32 firmware components. It must not add persistent-secret storage or
TROPIC01 dependencies.

## Identity And Policy Boundary

The shared identity contracts intentionally split the ESP32 family into two
route types:

- `esp32_qr_vault`: stateless QR route, transport `qr`, custody
  `stateless_session`, manual-only policy support, no persistent key-at-rest
  design, no policy automation, no TROPIC01 dependency, and
  `persistent_grants: false`. The shared descriptor is
  `esp32-qr-nip06-account-0`, bound to `policy-manual-only-qr-vault`, with
  request routing pinned by `esp32-qr-sign-event-account-0`.
- `esp32_usb_nip46`: future persistent daily-use route, transport `usb`,
  custody `device_persistent`, trusted review `device_display`, and
  `policy-scoped-automation-daily-use`, with request routing pinned by
  `esp32-usb-sign-event-slot-0`.

The current `nsealr-account-descriptor-v0` USB vector
`esp32-usb-device-slot-0` and grant vector `grant-esp32-usb-kind-1-session`
are conformance contracts only. They do not authorize persistent grants on the
current firmware and do not enable real signing. The firmware must still keep
runtime signing disabled until provisioning/storage, display review,
physical controls, Unicode review rendering, secure boot, flash encryption,
debug lock, and companion signed-output verification are accepted.

The host-core protocol layer now carries a `DeviceProtocolContext` with an
explicit signer identity. `get_public_key`, the Event review author field, and
the `approval_digest` signer-author binding all use that same identity. The
development scaffold context still uses the deterministic fixture public key
from the shared vectors, but future QR session account selection and persistent
USB provisioning must inject the selected account identity instead of relying
on a global development key.

For the QR route, the target key-source behavior is the same as Raspberry QR
vault behavior: a RAM-only session keyring fed by manual BIP-39 words,
SeedSigner Standard SeedQR, CompactSeedQR, plain mnemonic QR, `nsec` QR, or
local generation. It must not persist policy state or secret material.

For the USB/NIP-46 route, the target is a persistent encrypted device vault
after production gates pass. That vault may hold seed profiles, BIP-39
passphrase namespaces, NIP-06 account selections, standalone key slots, and
per-public-key policy. The v0 product decision is one device-level unlock
PIN/ceremony. Policy changes must be locally reviewed and physically approved
on the device; companion proposals are not authoritative by themselves.

Feature target and current status are tracked in `nSealr/specs`
`vectors/features/signer-feature-matrix-v0.json`. ESP32-specific firmware can
have board-specific drivers, but any shared feature such as request validation,
trusted review, approval digest binding, QR transport, serial transport, or
response verification must match the shared `contract_id` instead of becoming a
board-local behavior.

## Implemented Host Core

The first firmware foundation is host-buildable C++ under
`firmware/host_core`.

- `serial_frame`: encodes and decodes newline-terminated `nsealr1f:` frames with
  type, base64url JSON payload, and checksum.
- `qr_envelope`: decodes `nsealr1:` QR envelopes, validates unpadded base64url
  payloads, validates UTF-8, applies shared v0 QR/request size limits, and
  requires a decoded JSON container for the future ESP32-S3 QR vault target.
  It also encodes already-produced response JSON into static `nsealr1:` and
  animated `nsealr1a:` response envelopes for future QR display output; this is
  an output transport boundary, not a signing backend.
  It also classifies decoded `sign_event` requests by top-level metadata,
  rejects unknown request/template fields where host-core owns the boundary,
  extracts the raw `params.event_template` object boundary, and rejects
  host-supplied `id`, `pubkey`, or `sig` fields before review/signing code
  exists. It parses only the minimum unsigned event-template fields:
  `created_at`, `kind`, `tags`, and `content`, with constrained tag/content
  limits mirrored from `nSealr/specs`.
- `nip19_nsec`: decodes canonical lowercase NIP-19 `nsec` Bech32 private-key
  payloads into a 32-byte RAM-only secret-key buffer and lowercase hex for test
  comparison. It exists only as a QR-vault key-source parser; it does not
  provide key storage, public-key derivation, policy state, or signing.
- `seedqr`: decodes SeedSigner Standard SeedQR digit streams and CompactSeedQR
  entropy bytes into BIP-39 word indexes, including BIP-39 checksum validation
  through the shared BIP-39 boundary. It is only a QR-vault key-source parser;
  it does not derive NIP-06 keys, persist seed material, or sign.
- `bip39_english`: validates BIP-39 English mnemonic text, normalizes ASCII
  case/whitespace, maps words to indexes, renders checked indexes back to
  words, and rejects bad word counts, unknown words, invalid characters,
  out-of-range indexes, and checksum mismatches. This supports future manual
  word entry, plain mnemonic QR, and SeedQR review without adding derivation or
  storage.
- `session_keyring`: bounded RAM-only host-core model for already parsed `nsec`
  and BIP-39 key sources. It lets future QR-vault import UX and lifecycle tests
  share one volatile custody boundary, wipes active sources on `clear()` and
  destruction, and disables keyring copy/move operations so RAM-only material
  is not duplicated by ordinary container semantics. It deliberately avoids
  NIP-06 derivation, persistence, policy state, or signing.
- `session_import_review`: builds a secret-hidden import review summary for a
  parsed session key source. It records type, label, word count for BIP-39, and
  a deterministic source fingerprint without exposing raw `nsec` material or
  mnemonic words, and its host tests consume the shared
  `nSealr/specs/vectors/session-import-reviews` contract. It deliberately
  returns review pages and a digest only, not a signing approval session.
- `session_import_flow`: wraps that import review in a local button-control
  loop before loading a parsed source into the stateless session keyring.
  `Next` must reach the final import decision page before `Approve` can load
  RAM-only source material; `Reject`, early approval, and non-terminal input
  streams leave the keyring unchanged. This is import approval only, not
  signing approval, derivation, persistence, or policy automation.
- `session_source_generation`: creates generated BIP-39 and standalone
  `nsec`-equivalent QR-vault session sources from explicit entropy inputs and
  routes them into the same RAM-only source/review boundary as imports. This is
  a host-core contract for future hardware RNG wiring and backup/export UX; it
  does not persist generated material, derive NIP-06 keys, or enable signing.
- `session_source_qr`: normalizes decoded QR session-source inputs for future
  camera adapters. It maps canonical NIP-19 `nsec`, plain BIP-39 English
  mnemonic QR text, SeedSigner Standard SeedQR digit streams, and CompactSeedQR
  entropy bytes into the same RAM-only `SessionKeySource` boundary used by
  import review. It deliberately does not derive NIP-06 keys, persist material,
  select accounts, or enable signing.
- `qr_review`: converts parsed QR signing requests into renderer-neutral
  trusted-review pages and QR-derived `approval_digest` values that match the
  shared review-screen vectors.
- `serial_review`: converts decoded serial/USB `sign_event` request JSON into
  the same renderer-neutral trusted-review request and `approval_digest` used
  by the QR path. This gives the USB signer path a review boundary before
  production display/control acceptance, storage, or a signing backend exists.
  It also defines the serial/display/button I/O harness for USB signer adapter
  acceptance tests.
- `qr_review_flow`: host-core flow boundary from raw scanned `nsealr1:` QR
  envelopes to trusted review frames and approval state. It includes the
  `QrReviewIo` adapter harness for future scanner, display, and GPIO button
  code, returns the displayed frame/button transcript from that harness, and has
  no signing backend.
- `sha256`: portable SHA-256 helper used for the frame checksum.
- `signing_policy`: host-buildable runtime-signing readiness gate. It requires
  the explicit runtime feature flag, parser limits, trusted display acceptance,
  physical approval controls, approval-digest binding, Unicode review rendering
  acceptance, key provisioning, secure boot, flash encryption, debug lock, and
  companion signed-output verification before firmware can be considered ready
  to connect a signing backend.
- `approval_gate`: request-id and approval-digest bound approval state
  machine, checked against shared `nSealr/specs` review-screen vectors.
- `review_controls`: page-by-page review button state machine for future
  display/button adapters. It refuses approval until the final review page is
  reached, keeps rejection available before signing, and treats approval or
  rejection as terminal.
- `review_display`: renderer-neutral trusted display frame builder for future
  ESP32-S3 display drivers. It turns a review page into bounded title, page
  indicator, body lines, body-line styles, and action hint fields. Generic
  frames are bounded at the renderer boundary, while sign-event display
  sessions keep stable logical pages for Event, Content, Tags, and Decision and
  use compact styled body rows for long content and grouped tag content.
- `trusted_review`: host-buildable review session boundary that combines owned
  review pages, `review_display` frames, `review_controls` button navigation,
  and `approval_gate` request/digest binding. It is the first firmware-core
  object a future display/button adapter can drive without touching signing
  code. Sign-event display sessions can opt into logical navigation: KEY/GPIO14
  cycles Event, Content, Tags, and Decision, while BOOT/GPIO0 scrolls inside
  the current Content or Tags page when more lines are available.
- `device_protocol`: scaffold request dispatcher for shared-spec capability,
  development public-key, and disabled-signing responses. It parses the serial
  request payload enough to validate v0 request ids and echo dynamic
  `request_id` values. Valid serial/USB `sign_event` requests are also forced
  through the trusted-review request builder before the dispatcher returns
  `signing_disabled`; the live display session uses logical review pages plus
  compact scroll windows so content and grouped tag content can be inspected
  without abbreviated warning heuristics. The live Event page shows raw kind,
  raw created_at, and the signer author pubkey rather than inferred kind
  labels. It does not sign events.

This code is intentionally independent of ESP-IDF so protocol and approval
logic can be tested on desktop before it is wrapped by USB CDC, UART, display,
button, secure storage, and signing components.

Host tests generate their transport-vector header from `nSealr/specs` so the
firmware core is checked against the same serial frame vector used by the
companion. The same generated header now includes review-screen approval
digests, trusted review request factories, directory-discovered
review-display-frame vectors, QR
review-detail-page vectors, QR review transcripts, the shared v0 limit profile,
invalid serial-frame vectors, and invalid QR/signing-request hardening vectors,
allowing the host-core parser, approval gate, and trusted-review session to
reject unsafe input before any future signing backend is connected.

The review-control state machine is intentionally separate from
`approval_gate`: `review_controls` models local user navigation, while
`approval_gate` binds the final approval to the request id and
`approval_digest`. The display/button adapter path must satisfy both before a
real signing backend can be connected.

The review-display renderer is also intentionally hardware-neutral. It does not
drive ST7789, ILI9341, OLED, or LVGL directly; it produces a small bounded
frame and keeps unsafe title or limit settings out of the driver boundary. For
real sign-event review sessions, content and grouped tag content are
represented as compact styled rows inside stable logical pages; only oversized
sections become scroll windows such as `Page 3/4 Lines 1-9/18`. ESP-IDF
display adapters, such as the T-Display S3 ST7789/i80 path, can paint those
frames without changing review, approval, or signing semantics.
The T-Display S3 sized detail-page output is now pinned by shared
`nSealr/specs` review-detail-page vectors, while the `approval_digest`
continues to come from the older digest-bound `screen-pages` contract.
Frames with additional scroll windows show `Next/Scroll` in the footer so the
physical display exposes both navigation axes. Adjacent scroll windows do not
repeat the boundary line; the next window starts at the next unread line.
The current T-Display S3 bitmap-font path is conservative for Unicode:
supported printable ASCII, including common event punctuation, is rendered
directly by explicit glyphs, while unsupported non-ASCII codepoints are
represented as explicit `U+XXXX` fallback text before wrapping. This keeps the
display from silently turning event content into ambiguous question marks.
Decoded JSON control characters in event strings are rendered as visible
JSON-style escapes such as `\n`, `\t`, and `\r`, never as actual display
spacing.
Complete Unicode glyph rendering remains a separate display-font acceptance
task before production signing. QR and serial request
parsing preserve JSON `\uXXXX` escapes, including surrogate pairs, before the
display fallback is applied. The renderer itself also preserves UTF-8 codepoint
boundaries when wrapping or truncating generic review-frame text, so future
display adapters cannot receive invalid UTF-8 solely because of host-core
pagination.

The T-Display S3 ST7789/i80 adapter now keeps its board-specific rasterization
logic in a host-buildable module. The ESP-IDF draw path and desktop tests share
the same color-per-pixel functions for the boot pattern and review frame, so
layout regressions in title, page indicator, body text, footer text, borders,
lowercase glyphs, and core colors are caught before flashing. Review value
lines use a dedicated yellow color, meta lines remain green, and normal body
text remains white so wrapped pubkeys and tag values stay visually grouped.

The T-Display S3 button adapter follows the same pattern: GPIO polling remains
inside the ESP-IDF wrapper, while debounce timing, short/long press
classification, and emitted review-button events live in a host-buildable state
machine. GPIO14 short press emits the top-level next control, GPIO0 short press
emits the scroll/back control that logical sign-event reviews interpret as
Content/Tags scroll navigation, and long presses remain approve/reject. This
keeps the GPIO0/GPIO14 mapping testable without hardware and keeps touch input
outside the approval path.

The T-Display S3 runtime status frames are also host-buildable. Ready,
approved/rejected, timeout, and request-error frames are constructed by a small
helper used by `main.cpp` and host-core tests, so non-signing safety copy such
as `Signing disabled` and `Not signed` is not buried in untested ESP-IDF loop
branches.

The QR envelope decoder is similarly hardware-neutral. It accepts the same
static `nsealr1:` envelope contract used by Raspberry and the companion, and it
now also reconstructs complete `nsealr1a:` animated QR frame sets in host-core
tests. Animated reconstruction verifies frame digest, one-based ordering,
checksums, frame count, frame payload size, decoded payload size, UTF-8, and
JSON container shape before returning payload JSON. It does not perform camera
capture, animated scan timing, review output on real hardware, or signing. Its
request parser extracts version, `request_id`, method, `params` presence, and
the raw `params.event_template` object boundary before later review code does
real request handling. It also tolerates normal JSON string escapes, applies
shared resource limits, and rejects event templates that already include `id`,
`pubkey`, or `sig`. Those layers must be added behind separate tests and must
continue to consume shared vectors from `nSealr/specs`. The current field
parser validates only the unsigned event-template primitives that future review
generation needs; tag semantics, event id computation, key storage, and signing
remain absent.

The QR review builder consumes those parsed primitives and emits the same page
order, text, and `approval_digest` as `nSealr/specs` review-screen vectors
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
keeping real signing blocked until production display/control acceptance,
custody, and provisioning gates pass.

`SerialReviewFlow` and `SerialReviewIo` extend that boundary to display and GPIO
driver acceptance for the USB signer. A transport adapter supplies one decoded
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
signing backend. ESP32 host-core tests consume the shared `nSealr/specs` QR
review-transcript vectors so future firmware adapters stay aligned with the
cross-repository review contract.

The trusted-review session intentionally stops before hardware drivers, key
storage, or Schnorr signing. It proves the local review loop can only reach
`can_sign` after the user has traversed the displayed pages and approved the
request bound to the displayed `approval_digest`.

The signing-policy module is the complementary runtime gate. It does not sign
and it does not provision keys; it records every condition that must be true
before a later signing backend can be wired into the USB or QR flows. The
default readiness state is disabled and reports every missing gate. The current
device scaffold starts from that policy and exposes
`development_accepted_gates` for parser limits, trusted display, physical
controls, and approval-digest binding. The policy normalizes duplicated
development gate entries before serialization so the `get_signing_status`
diagnostic stays compatible with the shared response contract. Signing still
remains disabled because runtime feature enablement, production acceptance for
trusted display and physical controls, Unicode review rendering acceptance, key
provisioning, secure boot, flash encryption, debug lock, and companion
signed-output verification remain open.

`firmware/esp32_s3_usb_signer/security_profile.json` is the matching
machine-readable security posture for the ESP-IDF scaffold. The v0 profile is
development-only: runtime signing is disabled, production signing is not
allowed, secure boot and flash encryption are not enabled, USB/JTAG debug
access remains unlocked for bring-up, and key provisioning is not implemented.
Trusted display and physical controls have manual development evidence recorded
in the profile, but they remain production blockers. The validator requires
those blockers to stay explicit until a later production profile is designed
and tested.
The profile also tracks Unicode review rendering separately: the current
bitmap-font path is `ascii_safe_codepoint_fallback_only`, so unsupported
non-ASCII glyphs are shown as explicit `U+XXXX` codepoints and decoded control
characters are shown as visible JSON-style escapes. That is acceptable
development traceability, not full production Unicode review acceptance.

`scripts/audit_security_fuses.py` is the read-only bridge between that
machine-readable posture and an attached ESP32-S3 board. It runs only
`espefuse.py --chip esp32s3 --port <port> summary`, parses the relevant secure
boot, flash-encryption, download-mode, and debug-lock fuses, and emits JSON
blockers. It deliberately does not burn eFuses or modify the board, because M9
production hardening needs a separate irreversible provisioning procedure.
Security-fuse reports are linked from the profile through
`security_fuse_audit_evidence` instead of being mixed with firmware protocol or
display-review evidence.

## ESP-IDF Scaffold

`firmware/esp32_s3_usb_signer` is the first ESP-IDF project scaffold for the
ESP32-S3 USB signer. It currently boots, uses native USB Serial/JTAG as the
primary ESP-IDF console, reads newline-terminated `nsealr1f:` frames from that
console with the shared v0 serial-frame byte limit, answers the shared
`get_capabilities` request and other valid v0 request ids, returns the shared
development public key for `get_public_key`, returns `signing_disabled` for
valid `sign_event` requests, and logs that signing is disabled. It does not
yet include storage, production key provisioning, a signing backend, or a
production signing profile. The T-Display S3 development display/button review
loop remains non-signing acceptance evidence only.
