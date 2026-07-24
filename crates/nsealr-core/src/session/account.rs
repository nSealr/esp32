//! Session account selection — binds a reviewed account descriptor to a
//! RAM-only session source without deriving keys.
//!
//! Ported from the C++ reference `host_core` sources `src/session_account.cpp`
//! and `include/nsealr/session_account.hpp`. Milestone M-T3.4a lands
//! [`select_session_account`]; the C++ `device_protocol_context_for_session_account`
//! needs `DeviceProtocolContext` from the M-T3.6 substrate and is deferred to
//! milestone M-T3.4b.
//!
//! Selection performs shape validation and identity binding **only**: it never
//! derives the public key from the source, and the returned account explicitly
//! records that the source public-key proof gate is *not* satisfied
//! ([`SelectedSessionAccount::source_public_key_proof_verified`] is always
//! `false`; the M-T3.5 signing-policy port consumes that gate).
//!
//! [`SignerIdentity`] and [`is_valid_nostr_public_key`] originate from the C++
//! header-only `include/nsealr/signer_identity.hpp`; they are hosted here until
//! the M-T3.6 review/protocol port lands their permanent home. The C++
//! `require_valid_signer_identity` call inside `select_session_account` was
//! unreachable (the descriptor shape check already validated the same string);
//! this port validates once, so no separate error variant exists for it.

use crate::session::import_review::session_key_source_fingerprint;
use crate::session::keyring::{SessionKeySource, SessionKeySourceKind, StatelessSessionKeyring};
use crate::text::FixedStr;

/// Maximum byte length of a stable session account id. Mirrors the C++
/// `kMaxSessionAccountIdLength`.
pub const MAX_SESSION_ACCOUNT_ID_CHARS: usize = 128;
/// Length in hex characters of a source fingerprint. Mirrors the C++
/// `kSessionSourceFingerprintLength`.
pub const SESSION_SOURCE_FINGERPRINT_CHARS: usize = 16;
/// The only route type the QR-vault session account layer accepts. Mirrors the
/// C++ `kEsp32QrVaultRouteType`.
pub const ESP32_QR_VAULT_ROUTE_TYPE: &str = "esp32_qr_vault";

/// Development fixture public key (shared test identity). Mirrors the C++
/// `kDevelopmentFixturePublicKey` (`signer_identity.hpp`); copied from the
/// READ-ONLY specs/vectors/nip19/nsec-test-key-1.json (`public_key`).
pub const DEVELOPMENT_FIXTURE_PUBLIC_KEY: &str =
    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

/// Errors reported by session account selection. Each variant corresponds to a
/// distinct C++ `SessionAccountError` throw site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAccountError {
    /// The account id was empty, too long, or carried non-stable characters.
    /// C++: "session account_id must be a stable string id".
    UnstableAccountId,
    /// The route type was not [`ESP32_QR_VAULT_ROUTE_TYPE`]. C++: "session
    /// account route_type must be esp32_qr_vault".
    WrongRouteType,
    /// The public key was not 64 lowercase hex characters. C++: "session
    /// account public_key must be 32-byte lowercase hex".
    InvalidPublicKey,
    /// The source fingerprint was not 16 lowercase hex characters. C++:
    /// "session account source_fingerprint must be 8-byte lowercase hex".
    InvalidSourceFingerprint,
    /// The source index was `>=` the keyring size. C++: "session account source
    /// index is out of range".
    SourceIndexOutOfRange,
    /// A NIP-06 descriptor selected a non-BIP-39 source. C++: "NIP-06 session
    /// account requires a BIP-39 source".
    RequiresBip39Source,
    /// A NIP-06 descriptor's path did not match its account index. C++:
    /// "NIP-06 session account path does not match account index".
    PathMismatch,
    /// A standalone-nsec descriptor selected a non-nsec source. C++:
    /// "standalone nsec session account requires an nsec source".
    RequiresNsecSource,
    /// A standalone-nsec descriptor carried a derivation path. C++:
    /// "standalone nsec session account must not carry a derivation path".
    UnexpectedDerivationPath,
    /// The descriptor fingerprint did not match the selected source. C++:
    /// "session account source_fingerprint does not match selected source".
    FingerprintMismatch,
}

/// How the account's key material is recovered. Mirrors the C++
/// `SessionAccountRecoveryKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAccountRecoveryKind {
    /// NIP-06 derivation from a BIP-39 seed.
    Nip06,
    /// A standalone NIP-19 nsec with no derivation.
    StandaloneNsec,
}

/// A reviewed session account descriptor. Mirrors the C++
/// `SessionAccountDescriptor` field for field; string fields borrow from the
/// caller (the C++ copied `std::string`s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionAccountDescriptor<'a> {
    /// Stable account id (C++ `account_id`).
    pub account_id: &'a str,
    /// Signer route type (C++ `route_type`).
    pub route_type: &'a str,
    /// The reviewed 64-hex-char public key (C++ `public_key`).
    pub public_key: &'a str,
    /// Index of the session source in the keyring (C++ `source_index`).
    pub source_index: usize,
    /// The expected source fingerprint (C++ `source_fingerprint`).
    pub source_fingerprint: &'a str,
    /// Recovery kind (C++ `recovery_kind`).
    pub recovery_kind: SessionAccountRecoveryKind,
    /// NIP-06 derivation path, empty for standalone nsec (C++
    /// `derivation_path`).
    pub derivation_path: &'a str,
    /// NIP-06 account index (C++ `account_index`).
    pub account_index: u32,
}

/// The signer identity bound to a selected account. Mirrors the C++
/// `SignerIdentity` (`signer_identity.hpp`, hosted here until M-T3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerIdentity<'a> {
    /// The 64-lowercase-hex Nostr public key.
    pub public_key: &'a str,
}

/// A validated, selected session account. Mirrors the C++
/// `SelectedSessionAccount` field for field; borrowed fields reference the
/// descriptor and keyring the account was selected from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedSessionAccount<'a> {
    /// Stable account id (C++ `account_id`).
    pub account_id: &'a str,
    /// Signer route type (C++ `route_type`).
    pub route_type: &'a str,
    /// The reviewed public key (C++ `public_key`).
    pub public_key: &'a str,
    /// Index of the bound session source (C++ `source_index`).
    pub source_index: usize,
    /// The verified source fingerprint (C++ `source_fingerprint`).
    pub source_fingerprint: &'a str,
    /// Recovery kind (C++ `recovery_kind`).
    pub recovery_kind: SessionAccountRecoveryKind,
    /// The kind of the bound source (C++ `source_kind`).
    pub source_kind: SessionKeySourceKind,
    /// The bound source's label (C++ `source_label`).
    pub source_label: &'a str,
    /// Always `false` here: selection never satisfies the source public-key
    /// proof gate (C++ `source_public_key_proof_verified`).
    pub source_public_key_proof_verified: bool,
    /// The bound signer identity (C++ `signer_identity`).
    pub signer_identity: SignerIdentity<'a>,
}

/// Returns `true` for a 64-lowercase-hex Nostr public key. Mirrors the C++
/// `is_valid_nostr_public_key` (`signer_identity.hpp`).
#[must_use]
pub fn is_valid_nostr_public_key(public_key: &str) -> bool {
    public_key.len() == 64 && public_key.bytes().all(is_lowercase_hex)
}

/// Mirrors the C++ `is_lowercase_hex` (`signer_identity.hpp`).
fn is_lowercase_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// Mirrors the C++ `is_stable_id` (charset `[A-Za-z0-9._:-]`, non-empty, at
/// most [`MAX_SESSION_ACCOUNT_ID_CHARS`]).
fn is_stable_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SESSION_ACCOUNT_ID_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// Mirrors the C++ `is_source_fingerprint` (16 lowercase hex characters).
fn is_source_fingerprint(value: &str) -> bool {
    value.len() == SESSION_SOURCE_FINGERPRINT_CHARS && value.bytes().all(is_lowercase_hex)
}

/// Validates a descriptor against the keyring and binds the reviewed identity
/// to the selected source, without deriving any keys. Mirrors the C++
/// `select_session_account`.
///
/// # Errors
///
/// Any [`SessionAccountError`], in the same precedence order as the C++
/// (descriptor shape, then source lookup, then recovery-shape match, then
/// fingerprint binding).
pub fn select_session_account<'a>(
    keyring: &'a StatelessSessionKeyring,
    descriptor: &SessionAccountDescriptor<'a>,
) -> Result<SelectedSessionAccount<'a>, SessionAccountError> {
    require_descriptor_shape(descriptor)?;

    let source = keyring
        .source_at(descriptor.source_index)
        .map_err(|_| SessionAccountError::SourceIndexOutOfRange)?;
    require_source_matches_recovery(descriptor, source)?;
    if session_key_source_fingerprint(source) != descriptor.source_fingerprint {
        return Err(SessionAccountError::FingerprintMismatch);
    }

    // The C++ re-validated the identity here (`require_valid_signer_identity`);
    // the descriptor shape check above already proved the same property, so the
    // identity is constructed directly.
    Ok(SelectedSessionAccount {
        account_id: descriptor.account_id,
        route_type: descriptor.route_type,
        public_key: descriptor.public_key,
        source_index: descriptor.source_index,
        source_fingerprint: descriptor.source_fingerprint,
        recovery_kind: descriptor.recovery_kind,
        source_kind: source.kind,
        source_label: source.label.as_str(),
        source_public_key_proof_verified: false,
        signer_identity: SignerIdentity {
            public_key: descriptor.public_key,
        },
    })
}

/// Mirrors the C++ `require_descriptor_shape` (same check order).
fn require_descriptor_shape(
    descriptor: &SessionAccountDescriptor<'_>,
) -> Result<(), SessionAccountError> {
    if !is_stable_id(descriptor.account_id) {
        return Err(SessionAccountError::UnstableAccountId);
    }
    if descriptor.route_type != ESP32_QR_VAULT_ROUTE_TYPE {
        return Err(SessionAccountError::WrongRouteType);
    }
    if !is_valid_nostr_public_key(descriptor.public_key) {
        return Err(SessionAccountError::InvalidPublicKey);
    }
    if !is_source_fingerprint(descriptor.source_fingerprint) {
        return Err(SessionAccountError::InvalidSourceFingerprint);
    }
    Ok(())
}

/// Mirrors the C++ `require_source_matches_recovery`.
fn require_source_matches_recovery(
    descriptor: &SessionAccountDescriptor<'_>,
    source: &SessionKeySource,
) -> Result<(), SessionAccountError> {
    match descriptor.recovery_kind {
        SessionAccountRecoveryKind::Nip06 => {
            if source.kind != SessionKeySourceKind::Bip39WordIndexes {
                return Err(SessionAccountError::RequiresBip39Source);
            }
            if expected_nip06_path(descriptor.account_index) != descriptor.derivation_path {
                return Err(SessionAccountError::PathMismatch);
            }
            Ok(())
        }
        SessionAccountRecoveryKind::StandaloneNsec => {
            if source.kind != SessionKeySourceKind::NsecSecretKey {
                return Err(SessionAccountError::RequiresNsecSource);
            }
            if !descriptor.derivation_path.is_empty() {
                return Err(SessionAccountError::UnexpectedDerivationPath);
            }
            Ok(())
        }
    }
}

/// Builds the expected NIP-06 path `m/44'/1237'/<account>'/0/0`. Mirrors the
/// C++ `expected_nip06_path`. The path is at most 12 + 10 + 5 = 27 bytes.
fn expected_nip06_path(account_index: u32) -> FixedStr<32> {
    let mut path = FixedStr::<32>::new();
    path.try_push_str("m/44'/1237'/")
        .expect("within documented capacity");
    path.try_push_usize(account_index as usize)
        .expect("within documented capacity");
    path.try_push_str("'/0/0")
        .expect("within documented capacity");
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39;
    use crate::nip19;
    use crate::session::keyring::tests::NSEC_TEST_KEY_1;

    // NIP-06 fixture copied from the READ-ONLY
    // specs/vectors/keys/nip06-account-0-leader.json (`mnemonic`, `public_key`).
    const NIP06_ACCOUNT_0_MNEMONIC: &str =
        "leader monkey parrot ring guide accident before fence cannon height naive bean";
    const NIP06_ACCOUNT_0_PUBLIC_KEY: &str =
        "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
    // NIP-19 fixture copied from the READ-ONLY
    // specs/vectors/nip19/nsec-test-key-1.json (`public_key`).
    const NSEC_TEST_KEY_1_PUBLIC_KEY: &str =
        "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    // Fingerprint copied from the READ-ONLY
    // specs/vectors/session-import-reviews/nsec-test-key-1.json (`fingerprint`).
    const NSEC_TEST_KEY_1_FINGERPRINT: &str = "dbd1f8666039f02a";

    /// The C++ generated `esp32_qr_nip06_account_0_descriptor()`; fields copied
    /// from the READ-ONLY specs/vectors/accounts/esp32-qr-nip06-account-0.json
    /// (`account_id`, `signer_route.type`, `public_key`,
    /// `recovery.{source_fingerprint,type,path,account}`).
    fn esp32_qr_nip06_account_0_descriptor() -> SessionAccountDescriptor<'static> {
        SessionAccountDescriptor {
            account_id: "acct-esp32-qr-nip06-account-0",
            route_type: "esp32_qr_vault",
            public_key: NIP06_ACCOUNT_0_PUBLIC_KEY,
            source_index: 0,
            source_fingerprint: "cd64b58daca009b9",
            recovery_kind: SessionAccountRecoveryKind::Nip06,
            derivation_path: "m/44'/1237'/0'/0/0",
            account_index: 0,
        }
    }

    fn nip06_keyring() -> StatelessSessionKeyring {
        let mut keyring = StatelessSessionKeyring::new();
        keyring
            .add_bip39_seed(
                "NIP-06 account 0",
                bip39::parse_mnemonic_indexes(NIP06_ACCOUNT_0_MNEMONIC)
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
        keyring
    }

    fn standalone_descriptor() -> SessionAccountDescriptor<'static> {
        SessionAccountDescriptor {
            account_id: "acct-esp32-qr-nsec-0",
            route_type: "esp32_qr_vault",
            public_key: NSEC_TEST_KEY_1_PUBLIC_KEY,
            source_index: 0,
            source_fingerprint: NSEC_TEST_KEY_1_FINGERPRINT,
            recovery_kind: SessionAccountRecoveryKind::StandaloneNsec,
            derivation_path: "",
            account_index: 0,
        }
    }

    // Portable subset of the C++
    // `test_session_account_selection_binds_qr_review_identity_without_derivation`:
    // that named case also asserts through `build_qr_trusted_review_request` +
    // `device_protocol_context_for_session_account` (M-T3.6 substrate) and is
    // counted as DEFERRED; the identity-binding assertions below are exercised
    // here so the selection surface is still fully proven. They are a strict
    // subset re-run — not a claim that the named case is ported.
    #[test]
    fn binds_qr_review_identity_without_derivation() {
        let keyring = nip06_keyring();
        let descriptor = esp32_qr_nip06_account_0_descriptor();
        let selected = select_session_account(&keyring, &descriptor).unwrap();

        assert_eq!(selected.account_id, descriptor.account_id);
        assert_eq!(selected.route_type, descriptor.route_type);
        assert_eq!(selected.public_key, NIP06_ACCOUNT_0_PUBLIC_KEY);
        assert_eq!(selected.source_index, 0);
        assert_eq!(selected.source_fingerprint, descriptor.source_fingerprint);
        assert_eq!(selected.source_kind, SessionKeySourceKind::Bip39WordIndexes);
        assert_eq!(selected.source_label, "NIP-06 account 0");
        assert!(!selected.source_public_key_proof_verified);
        assert_eq!(
            selected.signer_identity.public_key,
            NIP06_ACCOUNT_0_PUBLIC_KEY
        );
        assert_ne!(
            selected.signer_identity.public_key,
            DEVELOPMENT_FIXTURE_PUBLIC_KEY,
        );
    }

    // Port of the C++
    // `test_session_account_selection_validates_source_route_and_recovery_shape`.
    #[test]
    fn validates_source_route_and_recovery_shape() {
        let mut keyring = StatelessSessionKeyring::new();
        keyring
            .add_nsec(
                "standalone nsec",
                &nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap(),
            )
            .unwrap();

        let standalone = standalone_descriptor();
        let selected = select_session_account(&keyring, &standalone).unwrap();
        assert_eq!(selected.source_kind, SessionKeySourceKind::NsecSecretKey);
        assert!(!selected.source_public_key_proof_verified);
        assert_eq!(
            selected.signer_identity.public_key,
            NSEC_TEST_KEY_1_PUBLIC_KEY
        );

        // requires a BIP-39 source
        assert_eq!(
            select_session_account(&keyring, &esp32_qr_nip06_account_0_descriptor()),
            Err(SessionAccountError::RequiresBip39Source),
        );
        // source index is out of range
        let mut invalid = standalone;
        invalid.source_index = 1;
        assert_eq!(
            select_session_account(&keyring, &invalid),
            Err(SessionAccountError::SourceIndexOutOfRange),
        );
        // route_type must be esp32_qr_vault
        let mut invalid = standalone;
        invalid.route_type = "esp32_usb_nip46";
        assert_eq!(
            select_session_account(&keyring, &invalid),
            Err(SessionAccountError::WrongRouteType),
        );
        // account_id must be a stable string id
        let mut invalid = standalone;
        invalid.account_id = "not stable";
        assert_eq!(
            select_session_account(&keyring, &invalid),
            Err(SessionAccountError::UnstableAccountId),
        );
        // public_key must be 32-byte lowercase hex
        let mut invalid = standalone;
        invalid.public_key = "not-a-public-key";
        assert_eq!(
            select_session_account(&keyring, &invalid),
            Err(SessionAccountError::InvalidPublicKey),
        );
        // source_fingerprint must be 8-byte lowercase hex
        let mut invalid = standalone;
        invalid.source_fingerprint = "not-a-fingerprint";
        assert_eq!(
            select_session_account(&keyring, &invalid),
            Err(SessionAccountError::InvalidSourceFingerprint),
        );
        // source_fingerprint does not match selected source
        let mut invalid = standalone;
        invalid.source_fingerprint = "0000000000000000";
        assert_eq!(
            select_session_account(&keyring, &invalid),
            Err(SessionAccountError::FingerprintMismatch),
        );
        // must not carry a derivation path
        let mut invalid = standalone;
        invalid.derivation_path = "m/44'/1237'/0'/0/0";
        assert_eq!(
            select_session_account(&keyring, &invalid),
            Err(SessionAccountError::UnexpectedDerivationPath),
        );

        let mnemonic_keyring = nip06_keyring();
        // path does not match account index
        let mut invalid = esp32_qr_nip06_account_0_descriptor();
        invalid.derivation_path = "m/44'/1237'/1'/0/0";
        assert_eq!(
            select_session_account(&mnemonic_keyring, &invalid),
            Err(SessionAccountError::PathMismatch),
        );
        // Extra branch coverage beyond the C++ case (recorded deviation): a
        // standalone-nsec descriptor over a BIP-39 source.
        let mut invalid = standalone_descriptor();
        invalid.source_fingerprint = "cd64b58daca009b9";
        assert_eq!(
            select_session_account(&mnemonic_keyring, &invalid),
            Err(SessionAccountError::RequiresNsecSource),
        );
    }

    // Port of the C++
    // `test_session_account_selection_consumes_shared_source_public_key_proof_metadata_without_derivation`.
    // Proof fields copied from the READ-ONLY
    // specs/vectors/source-public-key-proofs/nip06-account-0-leader.json and
    // specs/vectors/source-public-key-proofs/nsec-test-key-1.json.
    #[test]
    fn consumes_shared_source_public_key_proof_metadata_without_derivation() {
        struct ProofVector {
            proof_type: &'static str,
            source_type: &'static str,
            source_fingerprint: &'static str,
            account: Option<u32>,
            path: &'static str,
            passphrase: &'static str,
            expected_public_key: &'static str,
            security_scope: &'static str,
        }
        let nip06_proof = ProofVector {
            proof_type: "nip06",
            source_type: "bip39_seed",
            source_fingerprint: "cd64b58daca009b9",
            account: Some(0),
            path: "m/44'/1237'/0'/0/0",
            passphrase: "",
            expected_public_key: NIP06_ACCOUNT_0_PUBLIC_KEY,
            security_scope: "Proof contract for deriving the reviewed NIP-06 account public key from a RAM-only BIP-39 session source before signing. It does not persist material, approve signing, or let descriptors/fingerprints substitute for derivation.",
        };
        let nsec_proof = ProofVector {
            proof_type: "nip19_nsec",
            source_type: "nsec",
            source_fingerprint: NSEC_TEST_KEY_1_FINGERPRINT,
            account: None,
            path: "",
            passphrase: "",
            expected_public_key: NSEC_TEST_KEY_1_PUBLIC_KEY,
            security_scope: "Proof contract for deriving the reviewed public key from a RAM-only NIP-19 nsec session source before signing. It does not persist material, approve signing, or let descriptors/fingerprints substitute for derivation.",
        };

        assert_eq!(nip06_proof.proof_type, "nip06");
        assert_eq!(nip06_proof.source_type, "bip39_seed");
        assert_eq!(nip06_proof.account, Some(0));
        assert_eq!(nip06_proof.path, "m/44'/1237'/0'/0/0");
        assert!(nip06_proof.passphrase.is_empty());
        assert!(nip06_proof.security_scope.contains("before signing"));

        let nip06_keyring = nip06_keyring();
        let nip06_descriptor = esp32_qr_nip06_account_0_descriptor();

        assert_eq!(nip06_descriptor.public_key, nip06_proof.expected_public_key);
        assert_eq!(
            nip06_descriptor.source_fingerprint,
            nip06_proof.source_fingerprint,
        );
        assert_eq!(nip06_descriptor.derivation_path, nip06_proof.path);
        assert_eq!(Some(nip06_descriptor.account_index), nip06_proof.account);

        let nip06_selected = select_session_account(&nip06_keyring, &nip06_descriptor).unwrap();
        assert_eq!(nip06_selected.public_key, nip06_proof.expected_public_key);
        assert_eq!(
            nip06_selected.source_fingerprint,
            nip06_proof.source_fingerprint,
        );
        assert!(!nip06_selected.source_public_key_proof_verified);

        assert_eq!(nsec_proof.proof_type, "nip19_nsec");
        assert_eq!(nsec_proof.source_type, "nsec");
        assert_eq!(nsec_proof.account, None);
        assert!(nsec_proof.path.is_empty());
        assert!(nsec_proof.passphrase.is_empty());

        let mut nsec_keyring = StatelessSessionKeyring::new();
        nsec_keyring
            .add_nsec(
                "nsec test vector",
                &nip19::decode_nsec(NSEC_TEST_KEY_1).unwrap(),
            )
            .unwrap();
        let nsec_descriptor = SessionAccountDescriptor {
            account_id: "acct-esp32-qr-nsec-0",
            route_type: "esp32_qr_vault",
            public_key: nsec_proof.expected_public_key,
            source_index: 0,
            source_fingerprint: nsec_proof.source_fingerprint,
            recovery_kind: SessionAccountRecoveryKind::StandaloneNsec,
            derivation_path: "",
            account_index: 0,
        };
        let nsec_selected = select_session_account(&nsec_keyring, &nsec_descriptor).unwrap();
        assert_eq!(nsec_selected.public_key, nsec_proof.expected_public_key);
        assert_eq!(
            nsec_selected.source_fingerprint,
            nsec_proof.source_fingerprint,
        );
        assert!(!nsec_selected.source_public_key_proof_verified);
    }
}
