# Testing

## Current Baseline

```sh
make ci
```

The baseline runs repository verification and the host-buildable firmware core
tests with strict C++ warnings.

## Implemented Tests

- Serial frame round-trip test against the companion-compatible known frame.
- Serial frame line-ending test proving the host-core decoder accepts common
  `LF`/`CRLF` serial input without weakening checksum validation.
- Serial frame rejection tests for unsupported types, checksum mismatch, and
  invalid base64url payloads.
- Shared invalid serial-frame vector tests for oversized frames, checksum
  mismatch, malformed payloads, and unsupported frame types, plus a host-core
  assertion that `kMaxSerialFrameBytes` matches the shared v0 limit profile.
- QR envelope tests covering the shared `nsealr1:` vector, prefix rejection,
  unpadded base64url rejection, invalid UTF-8 rejection, oversized decoded
  payload rejection, and non-JSON payload rejection.
- QR `sign_event` request metadata tests covering version, `request_id`,
  method, `params` presence, and the raw `params.event_template` object
  boundary without parsing event-template fields or enabling signing.
- QR event-template safety tests covering escaped content tolerance and
  rejection of host-supplied `id`, `pubkey`, and `sig` fields.
- QR event-template field tests covering `created_at`, `kind`, `tags`, and
  `content` extraction plus missing or wrong-type field rejection.
- QR parser hardening tests proving host-core constants mirror the shared v0
  limit profile and applicable shared invalid signing-request vectors are
  rejected before review/signing.
- QR trusted-review tests comparing ESP32-generated pages and
  `approval_digest` values with shared basic and tagged review-screen vectors.
- ESP32 display-review pagination tests proving physical review pages can show
  long content and grouped tag content without ellipses, keep stable
  logical page indicators, expose two-axis top-level/scroll navigation, and
  preserve compact body-line styles while the shared approval-digest contract
  remains unchanged and signing stays disabled.
- ESP32 display-review safety tests proving the live Event page shows raw kind,
  raw created_at, and signer author pubkey without inferred kind labels, and
  that supported printable ASCII punctuation, including backtick and caret,
  remains readable while non-ASCII UTF-8 content/tag values are rendered as
  explicit fallback codepoints on the current bitmap-font path. Parser tests
  also cover JSON `\uXXXX` escape preservation, including surrogate pairs, for
  QR and serial review requests.
- Serial/USB `sign_event` trusted-review tests proving decoded request JSON
  produces the same shared review contract and `approval_digest` as QR, while
  physical review sessions can use compact full-review logical pages and the
  device protocol still returns `signing_disabled`.
- Serial/USB review I/O harness tests proving future USB signer display and
  physical-button adapters can drive the same trusted review session from
  decoded request JSON without adding a signing backend.
- Signing-policy tests proving runtime signing remains disabled until every M8
  gate is present: runtime feature flag, parser limits, trusted display,
  physical controls, approval-digest binding, Unicode review rendering
  acceptance, key provisioning, source public-key proof, secure boot, flash
  encryption, debug lock, and companion signed-output verification.
- Identity/policy route-split tests proving shared descriptors keep
  `esp32_qr_vault` stateless/manual-only with `persistent_grants: false`, while
  `esp32-qr-nip06-account-0`, `policy-manual-only-qr-vault`,
  `esp32_usb_nip46`, `esp32-usb-device-slot-0`,
  `policy-manual-only-persistent-device`,
  `esp32-usb-enable-kind-1-automation`,
  `policy-scoped-automation-daily-use`, and
  `grant-esp32-usb-kind-1-session` remain future persistent-route contracts
  that do not enable signing. The same test consumes
  `esp32-qr-sign-event-account-0` and `esp32-usb-sign-event-slot-0` so
  route-selection metadata cannot drift from account descriptors, and it keeps
  scoped automation behind device-reviewed policy change plus physical
  approval.
- Policy-change review tests proving the host-core consumes the shared
  `esp32-usb-enable-kind-1-automation` vector, reproduces its review pages and
  `approval_digest`, requires local review traversal before approval, allows
  rejection, and rejects proposals that try to make the companion authoritative,
  omit physical approval, or carry secret material.
- Security-profile validation proving the ESP32-S3 USB signer scaffold remains
  development-only, with production signing disabled and secure boot, flash
  encryption, debug lock, key provisioning, source public-key proof, trusted
  display, physical controls, and signed-output verification listed as blockers.
- Security-profile validation requiring manual development acceptance evidence
  for trusted display and physical approval controls while keeping both gates as
  production blockers and disallowing touch approval.
- Security-profile validation requiring separate display-review protocol
  evidence for detail-page, UTF-8 fallback, ASCII punctuation, dense-tags, and
  historical head-smoke runs. These reports remain development traceability for
  the firmware revision they name and do not convert the trusted-display gate
  into a production acceptance claim.
- Security-profile validation requiring Unicode review rendering to remain an
  explicit production blocker while the current display path uses
  `ascii_safe_codepoint_fallback_only`.
- Security-profile validation requiring companion transport evidence to remain
  separate from companion signed-output verification. Serial-line capability
  and `signing_disabled` smokes are transport traceability only and do not
  clear the signed-output production blocker.
- Security-profile validation requiring firmware protocol evidence to remain
  separate from display/control acceptance and signed-output verification. The
  current T-Display S3 disabled-copy, Unicode signing-gate, and signing-status
  de-duplication smokes prove the flashed firmware still answers valid protocol
  requests, rejects invalid protocol input deterministically, exposes the
  Unicode review rendering gate, keeps signing-status gate lists
  duplicate-free, and refuses valid `sign_event` requests with
  `signing_disabled`.
- Security eFuse audit parser tests proving the M9 audit target uses only the
  read-only `espefuse.py summary` command and converts development-board fuse
  state into explicit secure boot, flash encryption, download-mode, and
  debug-lock blockers.
- Security-profile validation requiring security eFuse audit evidence to remain
  separate from firmware protocol evidence, display evidence, and companion
  transport evidence.
- Shared security-profile vector tests proving the local development scaffold
  still matches `firmware-boot-hardening-v0`: signing disabled, secure boot and
  flash encryption off, debug access unlocked for bring-up, persistent-secret
  storage not implemented, required sections present, and production blockers
  explicit.
- Board-profile validation for the no-camera LILYGO T-Display S3 USB/display
  signer candidate, keeping it separate from the T-Display S3 Pro OV5640 QR
  vault camera target.
- Board-profile validation for the Waveshare ESP32-S3 Touch LCD 3.5B-C as a
  secondary QR vault candidate, requiring the case-plus-OV5640 SKU and keeping
  real driver work blocked until AXS15231B/QSPI display, camera, and physical
  approval-control acceptance are tested.
- Host-core session-source QR parser tests proving decoded future camera
  payloads for canonical NIP-19 `nsec`, plain BIP-39 mnemonic QR text,
  SeedSigner Standard SeedQR, and CompactSeedQR all become the same RAM-only
  `SessionKeySource` boundary and still hide secret material in import-review
  pages. Invalid decoded QR inputs are rejected before keyring load, derivation,
  persistence, or signing.
- Host-core decoded QR import-flow tests must prove accepted `nsec`, Standard
  SeedQR, and CompactSeedQR inputs load the RAM-only keyring only after local
  import-review final-page approval, while rejection and invalid decoded QR
  inputs leave the keyring empty.
- Host-core session-source backup/output tests prove bounded danger-zone
  review frames are displayed before local button reads, approved flows emit
  the BIP-39/SeedQR or NIP-19 `nsec` recovery payload only after final-page
  approval, and rejection, early approval, or bounded non-terminal button
  streams emit nothing.
- Host-core session-account selection tests prove an ESP32 QR vault account
  descriptor binds a RAM-only BIP-39 or standalone `nsec` source to a public
  signer identity used by trusted review, while rejecting wrong routes,
  malformed public keys, malformed or mismatched reviewed source fingerprints,
  out-of-range source indexes, and mismatched recovery/source shapes. These
  tests also prove the selected account does not satisfy
  `source_public_key_proof`: using its explicit
  `source_public_key_proof_verified: false` value keeps signing-readiness
  disabled with that gate still missing. They deliberately stop before NIP-06
  derivation, persistent policy, or signing. The canonical ESP32 QR NIP-06
  descriptor is generated into the
  host-core fixture header from the shared account vector so tests do not
  hand-maintain duplicate route, path, public-key, or fingerprint constants.
  The same host-core tests now also consume the shared
  `vectors/source-public-key-proofs/*.json` metadata to prove the descriptor
  public key, derivation path, account index, and source fingerprint stay
  aligned with the source-proof contract. That is metadata conformance only;
  it does not derive the public key and must not clear the
  `source_public_key_proof` signing gate.
- Firmware board-config tests proving the compiled T-Display S3 constants match
  the JSON board profile and are included by the ESP-IDF scaffold.
- Firmware display-driver tests proving the T-Display S3 ESP-IDF scaffold
  compiles an ST7789/i80 adapter and boot-frame path while keeping physical
  GPIO approval and signing disabled.
- Host-buildable T-Display S3 raster tests proving the boot and review-frame
  pixel-color functions used by the ESP-IDF display driver keep stable samples
  for the white border, blue boot header, green/black boot checkerboard, review
  title text, page indicator, body text, footer background, and footer action
  text, including lowercase body glyphs, representative printable ASCII
  punctuation glyphs, and yellow value-line coloring for wrapped pubkeys,
  content chunks, and tag items.
- Firmware button-driver tests proving the T-Display S3 scaffold maps vendor
  documented GPIO0/GPIO14 physical controls to Scroll/Next short presses in
  logical sign-event reviews and Reject/Approve long presses, while keeping
  touch disallowed for approval and signing disabled.
- Host-buildable T-Display S3 button-logic tests proving debounce filtering,
  exact-threshold short press handling, long press handling, and GPIO-specific
  review-button mapping before the ESP-IDF GPIO polling wrapper reads physical
  pins.
- Host-buildable T-Display S3 status-frame tests proving Ready,
  approve/reject closed, timeout, and request-error display frames keep stable
  non-signing copy before the ESP-IDF runtime paints them.
- QR trusted-review session tests proving parsed QR requests drive bounded
  display frames, final-page traversal, and request/digest-bound approval.
- QR review-flow tests proving raw scanned static `nsealr1:` envelopes and
  complete animated `nsealr1a:` request frame sets drive trusted review without
  a signing backend, and unsafe or mixed QR requests are rejected before
  display.
- Animated QR host-core tests proving shared `nsealr1a:` frames reconstruct to
  the expected payload JSON and reject empty, missing-frame, and checksum-
  mismatched frame sets before future camera adapters exist.
- QR review I/O harness tests proving scanner, display, and physical-button
  adapter boundaries can drive the host-core review loop without adding a
  signing backend, and that non-terminal button streams fail within a bounded
  number of steps instead of hanging the adapter loop. The same tests now assert
  the returned I/O transcript matches the shared review-transcript vector, so
  future drivers can prove what they actually displayed and accepted.
- QR review-flow identity tests proving a selected ESP32 QR vault session
  account can supply the signer public key used in Event review and
  `approval_digest` binding through both `QrReviewFlow` and `QrReviewIo`,
  rather than falling back to the development fixture identity.
- QR review transcript tests covering full approval traversal and early
  rejection as deterministic frame/button/decision records from shared
  `nSealr/specs` review-transcript vectors.
- Host test header generation from the shared `nSealr/specs` serial,
  review-screen, review-display-frame, review-detail-page, review-transcript,
  source-public-key-proof, limits, and invalid hardening vectors.
  Review-display-frame, review-detail-page, and source-public-key-proof
  generation are directory-driven, so new shared display/proof vectors are
  consumed without adding one-off loader code.
- Single-repo CI falls back to fixture snapshots under `tests/fixtures/specs`
  when the sibling `nSealr/specs` checkout is not present. Cross-repo drift
  is still guarded by `nSealr/lab` integration checks.
- Approval gate tests requiring request-id and shared review-screen
  approval-digest matched approval before signing is permitted.
- Review button state-machine tests requiring traversal to the final review page
  before approval, allowing backward navigation during review, allowing early
  rejection, and rejecting additional input after a terminal decision.
- Review display-frame tests requiring deterministic title, page indicator,
  body lines, action hints, generic frame body-line wrapping/truncation,
  UTF-8 codepoint boundary preservation during wrapping, and rejection of
  unsafe display bounds.
- Trusted review-session tests requiring display navigation, generic backward
  review for generic pages, logical top-level/scroll navigation for sign-event
  display pages, final-page approval, request/digest-bound `can_sign`, and
  rejection as a terminal non-signing decision. These tests consume generated
  trusted review requests from the shared review-screen vectors instead of
  duplicating page content by hand where the shared contract applies.
- QR display-review tests now also consume shared review-detail-page vectors
  for T-Display S3 sized pages, proving complete Event/Content/Tags/Decision
  physical pages, scroll-window indicators, compact line styles, continuation
  indentation, visible JSON-style control escapes, and `U+XXXX` display
  fallback match `nSealr/specs`.
- The control-escape renderer smoke report records that firmware revision
  `294a77e` built, flashed, and preserved capability/review-scenario protocol
  behavior after the host-core renderer change. It is not human visual
  acceptance and does not clear the production Unicode review blocker.
- The control-escape scenario smoke report records that the default
  non-interactive review-scenario smoke now includes `show-control-escapes` and
  passes with 8 scenarios against the already flashed `294a77e` firmware image.
- Firmware scaffold tests requiring T-Display S3 terminal review decisions to
  show closed non-signing status frames with `Not signed` and
  `Signing disabled` after approve/reject UI input.
- Firmware scaffold tests requiring rejected serial requests to clear active
  T-Display S3 review state and show an explicit non-signing request-error
  frame instead of leaving stale review content visible.
- Firmware scaffold tests requiring stale active T-Display S3 review sessions
  to expire after a bounded inactivity window, clear RAM-only review state, and
  show `Review Timeout` / `Expired` / `Not signed` without enabling signing.
- Host-compiled T-Display S3 review-state helper tests proving timeout math,
  activity refresh, clear behavior, and unsigned tick wraparound outside the
  ESP-IDF runtime loop.
- Host-compiled T-Display S3 serial-input helper tests proving overlong input
  emits one `overlong_frame` event, drains bytes until the next newline, and
  then accepts the next complete request line without tail-byte contamination.
- Device protocol tests proving the shared ESP32-S3 scaffold capability request
  returns the shared scaffold capability response.
- Device protocol tests proving the shared ESP32-S3 scaffold
  `get_signing_status` request returns `signing_enabled: false` plus the
  remaining real-signing readiness gates for the current scaffold profile,
  while also exposing `development_accepted_gates` for parser limits,
  trusted-review display, physical approval controls, and approval-digest
  binding. The signing-policy tests also keep those diagnostic gate lists
  duplicate-free before they are serialized. Trusted display, physical
  controls, Unicode review rendering, and source public-key proof still remain
  in `missing_gates` until production acceptance and derivation/proof coverage
  are complete.
- Device protocol tests proving the shared ESP32-S3 scaffold `get_public_key`
  request returns the shared deterministic development public key response.
- Device protocol and review tests proving an explicit signer identity context
  changes `get_public_key`, Event review author display, and the review
  `approval_digest` together, while invalid public-key context is rejected
  before response generation.
- Device protocol tests proving the shared `sign_event` fixture returns the
  shared `signing_disabled` scaffold response.
- Device protocol tests proving valid serial-frame request payloads with
  non-fixture `request_id` values receive matching dynamic responses for
  `get_capabilities`, `get_signing_status`, development `get_public_key`, and
  disabled `sign_event`.
- ESP-IDF scaffold validation for required project files, ESP32-S3 target, board
  profile, and unsupported-claim rejection.
- ESP32-S3 board detection tests for serial-port discovery, native USB/JTAG
  report parsing, and missing-toolchain reporting.
- Manual ESP-IDF `v5.5.4` build, flash, boot-log smoke test, and
  capability/public-key/signing-disabled protocol smoke test on the attached
  ESP32-S3 board.
- Optional hardware capability/public-key/signing-disabled smoke test with
  `make idf-smoke-capabilities` after exporting ESP-IDF and flashing the current
  firmware. The smoke sends both shared fixture request frames and dynamic
  `request_id` variants, including `get_signing_status`, so parser changes
  cannot silently fall back to exact fixture matching. It also sends invalid
  dynamic metadata requests from shared `nSealr/specs` invalid serial-frame
  vectors plus serial-wrapped invalid signing-request vectors, including
  unknown top-level request fields, expecting deterministic
  `unsupported_request` rejections. Shared malformed transport vectors for
  checksum mismatch, malformed base64url payload, unsupported frame type, and
  overlong frame handling must return deterministic `malformed_frame` or
  `overlong_frame` errors. The smoke then sends a fresh valid capability
  request after the overlong frame to prove the runtime drained the rejected
  line and recovered before processing the next request. By default the smoke
  prints a clean summary; raw protocol
  frames are available with `scripts/smoke_capabilities.py --verbose-frames`.
  Failure messages include the failing exchange index so hardware logs can be
  tied back to the smoke sequence without guessing.
- Optional hardware review-scenario smoke test with
  `make idf-smoke-review-scenarios` after exporting ESP-IDF and flashing the
  current firmware. This non-interactive smoke sends the basic, tagged,
  long-content, scroll-window, dense-tags, Unicode fallback, control-escape,
  and request-error review scenarios used by the manual display exerciser and
  verifies the protocol still returns `signing_disabled` or deterministic
  `unsupported_request` frames. It does not replace human visual inspection of
  the display.
- Historical T-Display S3 head-smoke evidence recorded for revision `8307c4b`
  on
  `/dev/cu.usbmodem1101`: ESP-IDF build and flash passed, capability smoke
  passed with 39 exchanges, review-scenario smoke passed with 7 scenarios, and
  lab companion serial smoke verified a request-matched `signing_disabled`
  response for a companion-generated `sign_event`.
- Manual T-Display S3 display exerciser tests proving
  `scripts/manual_review_display.py` builds dynamic disabled `sign_event`
  exchanges, composes tagged-event, long-content, scroll-window, dense-tags,
  and Unicode fallback review scenarios, expects compact content/tag inspection
  without ellipses, composes the request-error scenario from shared invalid
  vectors, prints physical-control checklists for approve/reject acceptance
  scenarios, includes the terminal `Send new request` prompt in request-error
  and closed decision expectations, and runs exchanges through a fake serial
  device without opening hardware.
- Hardened firmware smoke evidence recorded for revision `dd2d5d1` on
  `/dev/cu.usbmodem101`; this confirms only scaffold protocol behavior and the
  expected `signing_disabled` refusal path.
- QR review I/O transcript firmware smoke evidence recorded for revision
  `b7aa30a` on `/dev/cu.usbmodem1101`; this confirms the transcript-producing
  host-core compiles into the ESP-IDF component while the attached-board smoke
  still exercises only the USB serial scaffold, development public-key fixture,
  `signing_disabled` refusal path, and deterministic invalid-request errors.
- Serial review-boundary firmware smoke evidence recorded for revision
  `dfdeec9` on `/dev/cu.usbmodem1101`; this confirms the serial `sign_event`
  trusted-review boundary compiles into the ESP-IDF component while the
  attached-board smoke still preserves the USB serial scaffold,
  `signing_disabled` refusal path, and deterministic invalid-request errors.
- Value-line color firmware smoke evidence recorded for revision `2f21b3b` on
  `/dev/cu.usbmodem1101`: ESP-IDF build and flash passed, capability smoke
  passed with 40 exchanges, and review-scenario smoke passed with 7 scenarios.
  Host-core raster tests verify Value lines use the dedicated yellow color;
  the hardware smoke does not replace human visual color inspection and does
  not enable signing.
- T-Display S3 physical acceptance evidence recorded for revision `3a67803` on
  `/dev/cu.usbmodem1101`: ESP-IDF `v5.5.4` build and flash passed,
  capability smoke passed with 40 exchanges, review-scenario smoke passed with
  8 scenarios, manual visual inspection passed for basic review, dense tags,
  control escapes, Unicode fallback, and request-error screens, and manual
  button observation passed for long-press approve and reject paths. The
  read-only security-fuse audit reported secure boot, flash encryption, debug
  lock, download mode, and manual flash-encryption download as production
  blockers. A hard reset was required after the fuse audit before app-protocol
  smokes resumed.
- Regression tests require the ESP-IDF console defaults to use native USB
  Serial/JTAG as the primary console; secondary USB logging is not enough for
  input-driven protocol smoke tests.

## Required Tests

- ESP32-S3 QR vault camera/display tests must consume the shared QR envelope,
  review-screen, `approval_digest`, and signing vectors from `nSealr/specs`.
- ESP32-S3 QR vault account-source tests must eventually mirror Raspberry QR
  vault behavior for RAM-only manual words, SeedSigner Standard SeedQR,
  CompactSeedQR, plain mnemonic QR, `nsec` QR, local generation, and no
  microSD/file secret transfer.
- Host-core `nsec` tests must consume `nSealr/specs/vectors/nip19` and reject
  non-canonical lowercase Bech32, malformed payloads, invalid checksums,
  wrong prefixes, unsupported characters, bad padding, and non-32-byte
  payloads before the value can become a RAM-only QR-vault session source.
- Host-core SeedQR tests must consume `nSealr/specs/vectors/seedqr` and prove
  Standard SeedQR digits and CompactSeedQR entropy decode to the same BIP-39
  word indexes. They must reject non-digit Standard SeedQR input, bad digit
  grouping, unsupported word counts, out-of-range indexes, bad BIP-39
  checksums, and unsupported CompactSeedQR byte lengths.
- Host-core BIP-39 English tests must consume the shared NIP-06 mnemonic
  vector, normalize ASCII case and whitespace, map words to indexes, render
  checked indexes back to words, reject invalid word counts, unknown words,
  invalid characters, out-of-range indexes, and checksum mismatches, and keep
  this boundary disconnected from NIP-06 derivation and signing.
- Host-core stateless session keyring tests must accept only already parsed
  `nsec` and BIP-39 key sources, enforce bounded source count and labels,
  reject invalid BIP-39 word-index shapes, prove active sources are wiped on
  clear, and prove `SessionKeySource` value operations wipe moved-from and
  assignment-replaced sensitive material. The model must stay disconnected
  from NIP-06 derivation, persistence, policy, and signing.
- Host-core session import review tests must prove parsed `nsec` and BIP-39
  key sources render secret-hidden review pages with deterministic
  fingerprints, `review_id` values, and import approval digests against shared
  `nSealr/specs/vectors/session-import-reviews` snapshots, without leaking raw
  private-key bytes or mnemonic words and without creating a signing approval
  session.
- Host-core session import flow tests must prove import approval requires
  local traversal to the final import decision page before loading the
  stateless session keyring, while rejection, early approval, and non-terminal
  button streams leave the keyring empty.
- Host-core session-source generation tests must prove generated BIP-39 and
  standalone `nsec`-equivalent sources enter the same secret-hidden RAM-only
  source boundary, invalid entropy is rejected, and generated secrets do not
  appear in import-review pages.
- Host-core session-source backup tests must prove BIP-39 words/SeedQR and
  NIP-19 `nsec` recovery payloads match shared backup vectors and are revealed
  only after the separate danger-zone review reaches the final approval page.
- Host-core QR response-envelope tests must prove already-produced response
  JSON can be encoded as static `nsealr1:` and animated `nsealr1a:` output
  against the shared signed-response vector without enabling firmware signing.
- Host-core QR response-display tests must prove small responses display as one
  static frame, larger responses display as animated frame cycles, non-response
  JSON, malformed nested JSON, and top-level response-shape errors are
  rejected, including the applicable shared invalid response vectors, and
  zero/oversized display cycles are impossible before hardware QR rendering or
  scan-back exist.
- ESP32 USB/NIP-46 persistent-vault tests must be added before real signing:
  one device-level unlock ceremony, encrypted storage, seed profiles,
  passphrase namespaces, standalone key slots, per-public-key policy,
  device-reviewed policy updates, wipe behavior, and no companion-side secret
  custody.
- Expand pre-signing hardening tests as host-core gains more JSON/schema
  coverage. The current host-core already consumes the shared invalid vectors
  where the QR parser owns the boundary, but richer schema diagnostics can be
  added without enabling signing.
- Automated ESP-IDF build smoke tests in CI or a hardware-capable runner.
- Repeatable flash smoke tests with recorded device port and board identity.
- Transport frame rejection tests.
- Companion integration tests for signed responses.
- Hardware validation reports for every physical board.

No device security claim is valid until firmware build, provisioning, parser
limits, trusted review, physical approval, approval-digest binding, companion
verification, and deterministic rejection behavior are verified. Runtime
signing remains disabled until those gates pass.
