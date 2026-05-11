# Roadmap

## Foundation: Host-Buildable Firmware Core

- C++ serial frame encode/decode.
- Portable SHA-256 checksum helper.
- Approval gate state machine.
- Host test binary with strict warnings.
- ESP-IDF project scaffold.
- ESP32-S3 DevKitC-1 board profile.
- LILYGO T-Display S3 no-camera board profile for the ESP32-S3 USB/display
  signer line.
- LILYGO T-Display S3 Pro OV5640 board profile for the future ESP32-S3 QR
  vault target.
- Physical ESP32-S3 detection gate for native USB/JTAG serial boards.
- Local ESP-IDF `v5.5.4` build, flash, boot-log smoke test, and
  capability/public-key/signing-disabled protocol smoke test.
- Shared v0 serial-frame byte limit and invalid serial-frame vector rejection
  for oversized frames, checksum mismatch, and malformed payloads.
- Shared-spec `get_capabilities` response through host-core protocol handling.
- Shared-spec `get_signing_status` response through host-core protocol
  handling, exposing `signing_enabled: false` and the remaining runtime
  signing-readiness gates for the current scaffold profile.
- Shared-spec `get_public_key` development response through host-core protocol
  handling.
- Shared-spec `sign_event` disabled response through host-core protocol
  handling.
- Dynamic serial request-id echo for valid `get_capabilities`,
  `get_signing_status`, `get_public_key`, and disabled `sign_event` requests
  instead of only recognizing exact fixture payloads.
- Shared-spec QR envelope decode boundary for future ESP32-S3 QR vault camera
  input.
- QR `sign_event` request metadata parser for decoded envelopes, including the
  raw `params.event_template` object boundary.
- QR event-template safety gate rejecting host-supplied `id`, `pubkey`, or
  `sig` fields before any future review or signing path.
- Minimal QR event-template field parser for `created_at`, `kind`, `tags`, and
  `content`.
- Shared v0 parser/resource limits and applicable invalid hardening-vector
  rejection for QR envelopes and QR signing requests before review/signing.
- QR trusted-review builder checked against shared review-screen page and
  `approval_digest` vectors.
- Shared-spec review-screen approval digest binding in the host approval gate.
- Host-buildable review button state machine for page traversal before
  approval and terminal approve/reject decisions.
- Host-buildable trusted display frame renderer with bounded title, body-line,
  page-indicator, and action-hint fields.
- Host-buildable body-line wrapping/truncation for trusted display frames.
- ESP32 display-review logical pages for `Event`, `Content`, `Tags`, and
  `Decision`, with compact styled body rows and scroll windows for valid
  content or grouped tag content that does not fit on one screen. Live logical
  reviews use two-axis navigation: KEY/GPIO14 cycles top-level pages and
  BOOT/GPIO0 scrolls within Content or Tags when more lines are present.
- Host-buildable trusted review session combining display frames, button
  navigation, terminal approve/reject decisions, and request/digest-bound
  approval.
- T-Display S3 onboard button polling for manual review navigation on live
  request-derived pages while signing remains disabled.
- QR-derived trusted-review session creation from parsed request data.
- Serial/USB `sign_event` trusted-review request creation from decoded request
  JSON, using the same shared `approval_digest` contract as QR while live
  display sessions can use compact full-review logical pages.
- `SerialReviewIo` host-core adapter harness for future USB signer display and
  physical-button drivers, without signing.
- `QrReviewFlow` host-core boundary from raw scanned QR envelope to trusted
  review frames and approval state, without signing.
- `QrReviewIo` host-core adapter harness for future scanner, display, and
  physical-button drivers, without signing.
- Bounded `QrReviewIo` loop that fails on non-terminal button streams instead
  of hanging a future adapter.
- `QrReviewIo` result transcript covering the exact frame/button sequence shown
  by the driver-facing harness, checked against shared review-transcript
  vectors.
- Deterministic QR review transcript helper for future display/button adapter
  acceptance tests, checked against shared `NostrSeal/specs` transcript
  vectors.
- Shared review-display-frame vector consumption for bounded long-content
  display rendering.
- Host-buildable runtime signing-readiness gate covering runtime feature flag,
  parser limits, trusted display acceptance, physical controls,
  approval-digest binding, Unicode review rendering acceptance, key
  provisioning, secure boot, flash encryption, debug lock, and companion
  signed-output verification.
- Machine-readable development security profile for the ESP32-S3 USB signer,
  explicitly blocking production signing until runtime signing, trusted
  display, physical controls, key provisioning, secure boot, flash encryption,
  debug lock, and companion signed-output verification are complete.
- Machine-readable firmware protocol evidence in that profile, kept separate
  from display/control acceptance and signed-output verification, so current
  hardware smokes can prove valid protocol handling, deterministic invalid
  input rejection, and continued `signing_disabled` refusal without implying
  production signing readiness.

Status: implemented as the first firmware-core, ESP-IDF scaffold, hardware
detection, capability-response, development public-key response, and local
hardware smoke-test foundation. Board profile validation now covers the
ESP32-S3 DevKitC-1 development reference, the no-camera LILYGO T-Display S3
USB/display signer candidate, and the LILYGO T-Display S3 Pro OV5640 QR vault
candidate. The ESP-IDF scaffold now compiles a T-Display S3 board-configuration
boundary that pins display dimensions, ST7789, GPIO38 backlight, GPIO15
display power, GPIO0/GPIO14 onboard controls, no camera, and
touch-not-approval, and now initializes the ST7789/i80 display path far enough
to draw a Ready/No request frame. Live request-derived review pages can be
manually navigated with onboard physical buttons while the runtime still
returns `signing_disabled`.
The QR envelope decoder, QR request metadata parser,
event-template object boundary extraction, review button state machine,
host-supplied signed-field rejection, review page generation, and display frame
renderer are implemented in host-core only. The QR path also validates the
minimal unsigned event-template fields needed by future review generation. The
trusted review session now ties review controls and display frames to
approval-digest binding for future adapters, and QR-derived requests can enter
that same session boundary through a raw-QR review flow. Display frames remain
bounded to configured limits, and sign-event display sessions now keep stable
logical pages with compact styled body rows; content and grouped tag content
become scroll windows only when they do not fit. Pages with additional scroll
windows expose `Next/Scroll` in the footer. The host-core
now also has a scanner/display/button I/O harness that shows every trusted
frame before reading physical-style input, rejects non-terminal input streams
after a bounded number of steps, and returns the terminal approval state plus
the exact displayed frame/button transcript. The T-Display S3 USB/display
signer has a development runtime for physical display review and onboard
button navigation, but production acceptance for trusted display and physical
controls remains blocked. Camera input for the ESP32 stateless QR vault, the
T-Display S3 Pro target, and any signing backend remain pending. QR review
transcripts provide a deterministic host-side oracle for those adapters and are
now checked against shared `NostrSeal/specs` vectors. The
host-core QR parser also mirrors the shared v0 limit profile and rejects
applicable invalid QR-envelope and signing-request vectors before trusted review
can begin.

Status note, 2026-05-08: the host-core serial decoder now mirrors the shared v0
`max_serial_frame_bytes` limit and rejects the shared invalid serial-frame
vectors for oversized frames, checksum mismatch, and malformed base64url
payloads. The ESP-IDF input loop uses the same limit before dispatching a frame
to host-core.

Status note, 2026-05-09: the host-core serial decoder now accepts common
`LF`/`CRLF`/`CR` line endings before checksum validation, matching the companion
serial framing behavior expected from real USB serial line readers. This does
not change frame payload, checksum, request validation, or the disabled-signing
boundary.

Status note, 2026-05-08: the host-core device protocol now decodes serial-frame
request payloads, validates the v0 `request_id` profile, and echoes dynamic
request ids in `get_capabilities`, `get_signing_status`, development
`get_public_key`, and disabled `sign_event` responses. `sign_event` still
returns `signing_disabled`; at that milestone no signing backend, storage,
display driver, or GPIO approval path was connected. Later T-Display S3 work
added development display/button review adapters while keeping storage and
signing disabled.

Status note, 2026-05-08: valid serial/USB `sign_event` requests now pass
through a host-core trusted-review boundary before the disabled-signing
response is returned. The boundary builds the same shared `approval_digest` as
the QR path from decoded request JSON, and live display sessions use compact
full-review logical pages for physical review. Runtime signing remains disabled.

Status note, 2026-05-08: `make idf-smoke-capabilities` now sends both the
shared fixture requests and dynamic `request_id` variants for capabilities,
signing-status diagnostics, development public-key, and disabled `sign_event`
handling. This makes the
hardware smoke catch regressions where the ESP-IDF app only recognizes exact
fixture payloads.

Status note, 2026-05-08: the same hardware smoke now sends invalid dynamic
request metadata from shared `NostrSeal/specs` serial-frame vectors for
unsupported version and invalid `request_id` syntax. The expected device
behavior is a deterministic `nseal1f:error` frame with `unsupported_request`,
preserving the signing-disabled boundary.

Status note, 2026-05-08: invalid signing-request vectors from `NostrSeal/specs`
are now wrapped as serial frames in the hardware smoke, including invalid
`sign_event` request shapes and unknown top-level request fields. The device
protocol catches parser rejections inside the request boundary and returns
deterministic `unsupported_request` frames instead of surfacing parser
exceptions to the ESP-IDF console loop.

Hardware note, 2026-05-08: revision `dd2d5d1` was built with local ESP-IDF
`v5.5.4`, flashed to the attached ESP32-S3 DevKitC-1 on `/dev/cu.usbmodem101`,
and smoke-tested with `make IDF_PORT=/dev/cu.usbmodem101
idf-smoke-capabilities`. The device returned capability and deterministic
development public-key frames, then rejected the shared `sign_event` request
with `signing_disabled`. Real signing remains disabled.

Hardware note, 2026-05-08: revision `351d693` was built and flashed to the
same attached ESP32-S3 DevKitC-1. The expanded hardware smoke verified six
valid static/dynamic responses plus 20 deterministic `unsupported_request`
error frames for invalid metadata and 18 serial-wrapped invalid signing-request
vectors, including the shared unknown top-level request-field vector. Real
signing remains disabled.

Hardware note, 2026-05-08: revision `c47b655` was built and flashed to the
same attached ESP32-S3 DevKitC-1. The expanded hardware smoke verified six
valid static/dynamic responses plus 22 deterministic `unsupported_request`
error frames for invalid metadata and 20 serial-wrapped invalid signing-request
vectors, including `params` misuse on the parameterless `get_capabilities` and
`get_public_key` methods. Real signing remains disabled.

Hardware note, 2026-05-08: revision `9ae6e7a` was built and flashed to the
same attached ESP32-S3 DevKitC-1. The expanded hardware smoke verified six
valid static/dynamic responses plus 27 deterministic `unsupported_request`
error frames for invalid metadata and 25 serial-wrapped invalid signing-request
vectors, including structurally invalid `sign_event` `params` and
`event_template` shapes. Real signing remains disabled.

Hardware note, 2026-05-08: revision `b7aa30a` was built with local ESP-IDF
`v5.5.4`, flashed to the attached ESP32-S3 DevKitC-1 on
`/dev/cu.usbmodem1101`, and smoke-tested with `make
IDF_PORT=/dev/cu.usbmodem1101 idf-smoke-capabilities`. This run verifies that
the firmware still builds, flashes, and preserves the USB serial scaffold
contract after compiling the QR review I/O transcript helper into host-core:
capability and development public-key requests succeed, `sign_event` returns
`signing_disabled`, and invalid requests return deterministic
`unsupported_request` frames. Real camera, display, GPIO, storage, secure boot,
debug-lock, and signing acceptance remain pending.

Hardware note, 2026-05-08: revision `f307b41` was rebuilt and reflashed on the
attached ESP32-S3 DevKitC-1 on `/dev/cu.usbmodem1101` after a diagnostic
protocol-smoke timeout exposed repeated bootloader `Checksum failed` and
`Factory app partition is not bootable` messages. The recovery reflash used
ESP-IDF `v5.5.4`; esptool verified bootloader, app, and partition-table image
hashes, and the follow-up `make IDF_PORT=/dev/cu.usbmodem1101
idf-smoke-capabilities` passed. The result is recorded as a manual
`NostrSeal/hardware` protocol-smoke report and does not change the disabled
signing boundary.

Hardware note, 2026-05-08: revision `dfdeec9` was built with local ESP-IDF
`v5.5.4`, flashed to the attached ESP32-S3 DevKitC-1 on
`/dev/cu.usbmodem1101`, and smoke-tested with `make
IDF_PORT=/dev/cu.usbmodem1101 idf-smoke-capabilities`. This run verifies that
the serial `sign_event` trusted-review boundary compiles into the ESP-IDF
component while the USB serial scaffold still answers capability and
development public-key requests, returns `signing_disabled` for `sign_event`,
and rejects invalid requests with deterministic `unsupported_request` frames.
Real display, GPIO, camera, storage, secure boot, debug lock, and signing
acceptance remain pending.

Hardware note, 2026-05-09: revision `61b51df` was built with local ESP-IDF
`v5.5.4`, flashed to the attached ESP32-S3 DevKitC-1 on
`/dev/cu.usbmodem1101`, and smoke-tested with `make
IDF_PORT=/dev/cu.usbmodem1101 idf-smoke-capabilities`. The smoke passed 33 USB
serial exchanges: 6 valid response frames and 27 expected rejection frames.
`sign_event` remains disabled with `signing_disabled`; real display, GPIO,
camera, storage, secure boot, debug lock, and signing acceptance remain
pending. The result is recorded as a manual `NostrSeal/hardware`
protocol-smoke report.

Hardware note, 2026-05-09: the host-core device protocol now implements the
shared `get_signing_status` diagnostic response and includes it in the
capability method list and hardware smoke. The attached T-Display S3 build was
compiled with ESP-IDF `v5.5.4`, flashed on `/dev/cu.usbmodem1101`, and passed
35 USB serial exchanges: 8 valid response frames and 27 expected rejection
frames. `get_signing_status` reports `signing_enabled: false` and every missing
runtime signing-readiness gate. `sign_event` remains disabled.

Hardware note, 2026-05-09: the ESP32 scaffold signing-status profile now marks
the already implemented host-core gates as satisfied: parser/resource limits
and approval-digest binding. The diagnostic response still reports
`signing_enabled: false`; remaining blockers are runtime signing feature,
trusted review display acceptance, physical approval controls, Unicode review
rendering acceptance, key provisioning, secure boot, flash encryption, debug
lock, and companion signed-output verification.

Status note, 2026-05-10: the shared `get_signing_status` contract now also
reports `development_accepted_gates`. The T-Display S3 scaffold lists parser
limits, trusted-review display, physical approval controls, and
approval-digest binding there because those gates have host-core coverage or
manual development evidence. `signing_enabled` remains false, and trusted
display plus physical controls still remain production blockers until a later
production acceptance profile exists.

Hardware note, 2026-05-09: the T-Display S3 firmware now includes the first
ST7789/i80 ESP-IDF display adapter for the no-camera USB/display signer target.
It powers GPIO15, configures the 8-bit parallel bus, enables the GPIO38
backlight, and draws a boot/self-test frame. The draw path waits for each
asynchronous i80 color transfer before reusing the DMA buffer. The same flash
and smoke loop on `/dev/cu.usbmodem1101` still passed 33 USB serial exchanges,
and manual visual confirmation showed a single clean blue boot bar with no
stray pixels. At that point this was display bring-up only: review-frame
rendering on the physical display, GPIO approval, camera, storage, secure boot,
debug lock, and signing acceptance still remained pending. Later T-Display S3
runtime work added development review-frame rendering and onboard-button
navigation while keeping production signing disabled.

Status note, 2026-05-09: the T-Display S3 display pixel layout is now factored
into a host-buildable raster module shared by the ESP-IDF ST7789/i80 driver.
Host-core tests sample the same boot and review-frame color functions used by
the physical display path, covering border, boot pattern, title text, page
indicator, body text, footer background, and footer action text. This is a
regression guard for the display calibration work; it does not change the
disabled-signing boundary.

Status note, 2026-05-09: the T-Display S3 button press classifier is now
factored into a host-buildable state machine shared by the ESP-IDF GPIO polling
adapter. Host-core tests cover debounce rejection, short press mapping, long
press mapping, GPIO14 Next/Approve, and GPIO0 scroll-or-back/Reject behavior.
This hardens the physical-review UX boundary without treating button input as
production signing authorization.

Status note, 2026-05-09: the T-Display S3 Ready, approve/reject, timeout, and
request-error frames are now built by a host-buildable status-frame helper used
by the ESP-IDF runtime. Host-core tests pin the non-signing copy for
`Not signed`, `Signing disabled`, and `Send new request`, so display safety
states can be reviewed before flashing. This changes only UI construction;
runtime signing remains disabled.

Status note, 2026-05-09: `scripts/manual_review_display.py` now includes
`button-approve` and `button-reject` scenarios. They send a valid disabled
`sign_event` review request and print the physical-control checklist for a
human observer: short KEY/GPIO14 top-level page traversal, optional short
BOOT/GPIO0 Content/Tags scroll traversal, long KEY/GPIO14 approve, and long BOOT/GPIO0
reject. The terminal checklist now also includes the expected `Send new
request` prompt shown after `Signing disabled`. This makes manual
display/button acceptance runs more repeatable, but it still does not turn
physical input into signing authorization.

Status note, 2026-05-10: the manual T-Display S3 review exerciser now includes
tagged-event and long-content scenarios built from shared `NostrSeal/specs`
vectors. These scenarios let a human inspect grouped tag content, compact
full-content review, many-tag scroll windows, and stable logical page indicators
on the physical display while the serial response still returns
`signing_disabled`.

Status note, 2026-05-10: live T-Display S3 sign-event review now uses two-axis
navigation for full-review display pages. Short KEY/GPIO14 cycles Event,
Content, Tags, and Decision; short BOOT/GPIO0 scrolls within
the current logical page; long KEY/GPIO14 can approve only on Decision; and
long BOOT/GPIO0 can reject from any page. This removes forced traversal through
every content/tag scroll window while still allowing complete inspection
before a non-signing approval UI action.

Status note, 2026-05-10: the live T-Display S3 Event page now shows raw kind,
raw created_at, and the signer author pubkey instead of inferred kind labels.
The display path renders supported printable ASCII punctuation directly and
converts unsupported non-ASCII UTF-8 content and tag values into explicit
`U+XXXX` fallback text before wrapping, avoiding silent `?` substitution while
a complete Unicode font remains a later acceptance task.

Status note, 2026-05-10: `make idf-smoke-review-scenarios` now provides a
non-interactive hardware protocol smoke for the basic, tagged, long-content,
scroll-window, dense-tags, Unicode fallback, and request-error review requests.
It reuses the manual review exerciser scenarios to verify serial response
behavior on a flashed board while keeping visual display inspection and
physical-button acceptance as separate manual evidence.

Status note, 2026-05-10: `make idf-smoke-capabilities` now also sends shared
malformed serial transport vectors for checksum mismatch, malformed base64url
payload, and overlong frames. The expected hardware responses are deterministic
`malformed_frame` or `overlong_frame` errors, while real `sign_event` still
returns `signing_disabled`.

Status note, 2026-05-10: the T-Display S3 runtime serial reader now uses a
host-buildable input helper that emits one overlong-frame event and drains the
rest of that line until newline before accepting new frames. This removes the
tail-byte contamination risk discovered while adding overlong transport smoke;
real signing remains disabled.

Status note, 2026-05-10: the hardware capability smoke now follows the
overlong-frame rejection with a valid `get_capabilities` request using
`request_id: post-overlong-recovery`. This pins the same recovery behavior on
the attached board, not only in host-core unit tests; real signing remains
disabled.

Status note, 2026-05-10: the manual and non-interactive T-Display S3 review
scenario set now includes `show-dense-tags`, a valid disabled `sign_event`
fixture with enough structured tags to exercise multiple Tags scroll windows.
The scenario keeps tag display raw/grouped, avoids inferred tag meaning, avoids
ellipses, and preserves the `signing_disabled` protocol expectation.

Status note, 2026-05-10: `security_profile.json` now separates manual
development acceptance reports from display-review protocol evidence. The
trusted-display and physical-control gates remain production blockers, while
detail-page, UTF-8 fallback, ASCII punctuation, dense-tags, and current-head
smoke reports are tracked as development traceability for the review-rendering
contract.

Status note, 2026-05-11: `security_profile.json` now also tracks Unicode review
rendering as `ascii_safe_codepoint_fallback_only` with
`unicode_review_rendering` kept in the production blocker list. The current
T-Display S3 bitmap-font path renders unsupported non-ASCII glyphs as explicit
`U+XXXX` codepoints, which is safer than silent substitution but is not a full
Unicode review acceptance claim.

Status note, 2026-05-11: `security_profile.json` now also separates companion
transport evidence from companion signed-output verification. The direct
serial-line hardware smokes prove request-bound host/device exchange and the
expected `signing_disabled` refusal on the attached T-Display S3, but the
`companion_signed_output_verification` blocker remains uncleared until real
signing output exists and is verified.

## M7: Firmware Foundation

- Board profiles.
- Protocol parser.
- `get_capabilities`, `get_signing_status`, development `get_public_key`, and
  disabled `sign_event` USB serial smoke tests.
- Display/button abstraction.
  Status: host-core `QrReviewIo` now defines the scanner/display/button
  adapter boundary for the QR review loop, and revision `b7aa30a` confirms that
  transcript-producing host-core still builds and flashes inside the ESP-IDF
  component. The no-camera T-Display S3 now has an ESP-IDF ST7789/i80
  review-frame adapter, onboard button review navigation, and host-buildable
  raster tests for display layout. Production trusted-display and
  physical-control acceptance remain pending before signing can be connected.
- Host-rendered review frame contract for display drivers.
- Repeatable ESP-IDF build and flash command wrappers.
- Add display/button acceptance tests before enabling any real signing path.

## M8: ESP32-S3 USB Signer MVP

- USB transport.
- Production key generation/import and `get_public_key`.
- `sign_event` behind display review and physical approval.
- Approval loop.
- Companion integration.

Hard blocker before real `sign_event`: the M7.5 pre-signing hardening gate
must pass. That means host-core parser/resource limits, shared malicious-vector
rejection where feasible, display review driver acceptance, physical button
acceptance, `approval_digest` binding, key provisioning/storage design, secure
boot/debug policy, and companion verification of signed output are all tested.
Until then runtime signing remains disabled.

Status note, 2026-05-08: the host-core serial/USB path now builds a
trusted-review request for valid `sign_event` frames and verifies that its
pages and `approval_digest` match the shared review-screen vectors. The
dispatcher still returns `signing_disabled`, so this is review-boundary
alignment only, not signing enablement.

Status note, 2026-05-08: `SerialReviewIo` now gives the USB signer path the
same host-core display/button adapter harness shape as the QR path. Decoded
serial `sign_event` JSON is rendered into bounded trusted frames, physical-style
button input advances the review session, and the resulting frame/button
transcript is returned for future adapter acceptance tests. No signing backend
is connected.

Status note, 2026-05-09: the review-control state machine now supports explicit
backward navigation before a terminal decision. Host-core tests cover `Next`,
`Back`, early `Reject`, and final-page `Approve` behavior, including the rule
that returning to prior pages never enables `can_sign`. Logical sign-event
display sessions now reinterpret the same short GPIO0 event as scroll-window
navigation so the user can move across Event, Content, Tags, and Decision
without forced traversal through every scroll window.

Status note, 2026-05-09: the T-Display S3 runtime now maps the vendor-documented
onboard buttons into the manual review loop: short GPIO14 is top-level Next,
short GPIO0 is scroll/back depending on review mode, long GPIO14 is Approve,
and long GPIO0 is Reject. A reboot intentionally clears the RAM-only active
review session and shows a Ready/No request frame; only a new live `sign_event`
request starts the multi-page review again. `sign_event` still returns
`signing_disabled`, so button approval is display UX validation only and not
signing enablement.

Status note, 2026-05-09: terminal T-Display S3 review decisions now render a
closed non-signing status frame instead of leaving the final decision page on
screen. Approve shows `Review OK`, Reject shows `Rejected`, both show
`Not signed`, `Signing disabled`, and `Send new request`, and the active
RAM-only review session is cleared. This is still UI feedback only; it does not
change serial responses or enable a signing backend.

Status note, 2026-05-09: rejected serial requests now also close any active
T-Display S3 review session and render an explicit `Request Error` /
`Rejected` / `Not signed` / `Signing disabled` / `Send new request` frame. This
prevents stale review pages from remaining on screen after malformed,
oversized, or unsupported host input. The serial protocol still returns
deterministic error frames and signing remains disabled.

Status note, 2026-05-09: active T-Display S3 review sessions now have a
five-minute inactivity timeout. Expiry clears the RAM-only review state and
renders `Review Timeout` / `Expired` / `Not signed` / `Signing disabled`, so a
forgotten review cannot remain indefinitely as actionable-looking event
content. This does not alter protocol responses and does not enable signing.

Status note, 2026-05-08: `signing_policy` now makes the M8 runtime signing gate
explicit in host-core. The default state remains disabled and reports missing
runtime feature, parser limits, trusted display, physical controls,
approval-digest binding, Unicode review rendering acceptance, key
provisioning, secure boot, flash encryption, debug lock, and companion
signed-output verification gates. This compiles into the ESP-IDF component but
does not enable signing.

Status note, 2026-05-08: the ESP32-S3 USB signer scaffold now includes a
validated `security_profile.json`. The v0 profile is `development_scaffold`,
keeps runtime and production signing disabled, records secure boot, flash
encryption, debug lock, key provisioning, trusted display, physical controls,
and signed-output verification as production blockers, and is enforced by
`make ci`.

Status note, 2026-05-09: `security_profile.json` now records T-Display S3
manual development acceptance evidence for trusted display and physical
approve/reject controls, including the hardware reports that exercised page
navigation, terminal decisions, approve, and reject. This does not remove
trusted display or physical controls from the production blocker list and does
not enable signing.

Status note, 2026-05-10: `get_signing_status` now mirrors that distinction by
adding `development_accepted_gates` while keeping `signing_enabled: false` and
the production blockers intact. The field is diagnostic evidence for the
development scaffold, not permission to connect a signing backend. The
host-core signing policy now also normalizes duplicate development gate entries
before `get_signing_status` serialization so firmware diagnostics remain
compatible with the shared response contract.

Hardware note, 2026-05-10: revision `8307c4b` was rebuilt with ESP-IDF
`v5.5.4`, flashed on the attached LILYGO T-Display S3 at
`/dev/cu.usbmodem1101`, and smoke-tested as the current repository head.
`idf-smoke-capabilities` passed with 39 verified exchanges, including the
post-overlong recovery check. `idf-smoke-review-scenarios` passed all 7 review
scenarios. A lab companion serial smoke then generated a `sign_event` request
from the shared basic kind `1` fixture and verified the request-matched
`signing_disabled` response. Production signing remains disabled.

## M8.5: ESP32-S3 QR Vault Target

- Camera/display board selection. Status: LILYGO T-Display S3 Pro with OV5640
  camera is the primary board-profile candidate; T-Camera Plus S3 remains
  secondary evaluation hardware in `NostrSeal/lab`.
- QR request scanner using shared `NostrSeal/specs` QR envelope vectors.
  Status: host-core `nseal1:` envelope decoding, `nseal1a:` animated frame
  reconstruction, top-level `sign_event` metadata parsing, and raw
  `params.event_template` object boundary extraction are implemented. It also
  rejects host-supplied `id`, `pubkey`, or `sig` fields, applies shared v0
  parser/resource limits, rejects applicable invalid hardening vectors, and
  parses the minimal unsigned event fields `created_at`, `kind`, `tags`, and
  `content`. QR review pages now match shared basic/tagged review-screen page
  and `approval_digest` vectors, and the T-Display S3 sized complete physical
  pages match shared review-detail-page vectors; camera capture, animated scan
  timing on physical QR frames, hardware display output, and signing-vector
  consumption remain pending. Raw QR review flow is available in host-core for
  future camera/display/GPIO adapters.
- Trusted review pages using shared review-screen vectors and `approval_digest`.
- Physical approve/reject loop.
- Signed-event QR output verified by the companion.

Status: future target in this repository. It must not be moved into
`NostrSeal/raspberry`. It also must not sign real QR requests until the shared
pre-signing hardening vectors are consumed where feasible and the camera,
display, GPIO, and review acceptance gates are complete.

## M9: Security Hardening

- Secure boot.
- Flash encryption.
- Firmware update policy.
- Debug lock policy.
