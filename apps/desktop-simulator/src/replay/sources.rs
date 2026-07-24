//! `seedqr` / `nip19` / `keys` / `accounts` / `source-public-key-proofs` replay.
//!
//! Key *derivation* (BIP-32 / secp256k1 point multiplication) is intentionally
//! **not** in `nsealr-core` (it is a review/transport/session core with no signing
//! crypto). So `public_key` and derived-`secret_key` fields are asserted for
//! *format/scalar validity* only — never re-derived — and that limitation is
//! recorded honestly. The codecs the core does own (SeedQR, BIP-39 mnemonic,
//! NIP-19 nsec) are asserted exactly.

use super::{hex_to_bytes, str_field, u16_array, ReplayResult};
use nsealr_core::bip39::{
    entropy_from_indexes, mnemonic_from_indexes, parse_mnemonic_indexes, require_valid_checksum,
    WordIndexes,
};
use nsealr_core::nip19::{decode_nsec, decode_nsec_hex, encode_nsec, is_valid_secret_key};
use nsealr_core::review::signer_identity::is_valid_nostr_public_key;
use nsealr_core::seedqr::{decode_compact_indexes, decode_standard_indexes};
use serde_json::Value;

/// Assert a hex string is a canonical 32-byte secp256k1 secret-key scalar.
fn assert_secret_key(hex: &str) -> ReplayResult {
    let bytes = hex_to_bytes(hex)?;
    let secret: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("secret_key is not 32 bytes: {hex}"))?;
    if is_valid_secret_key(&secret) {
        Ok(())
    } else {
        Err(format!("secret_key is not a valid secp256k1 scalar: {hex}"))
    }
}

/// Assert a public key is a well-formed 64-hex Nostr x-only key (format only —
/// the core cannot re-derive it from the secret).
fn assert_public_key(pubkey: &str) -> ReplayResult {
    if is_valid_nostr_public_key(pubkey) {
        Ok(())
    } else {
        Err(format!(
            "public_key is not a valid 64-hex nostr key: {pubkey}"
        ))
    }
}

pub(super) fn replay_seedqr(value: &Value) -> ReplayResult {
    let digits = str_field(value, "standard_seedqr_digits")?;
    let compact_hex = str_field(value, "compact_seedqr_hex")?;
    let mnemonic = str_field(value, "mnemonic")?;
    let expected = u16_array(value, "standard_word_indexes")?;

    let std_idx =
        decode_standard_indexes(digits).map_err(|e| format!("decode_standard_indexes: {e:?}"))?;
    if std_idx.as_slice() != expected.as_slice() {
        return Err("standard SeedQR indexes != standard_word_indexes".into());
    }
    let compact = hex_to_bytes(compact_hex)?;
    let cmp_idx =
        decode_compact_indexes(&compact).map_err(|e| format!("decode_compact_indexes: {e:?}"))?;
    if cmp_idx.as_slice() != expected.as_slice() {
        return Err("compact SeedQR indexes != standard_word_indexes".into());
    }
    // The mnemonic string round-trips to the same indexes, and back to the string.
    let parsed =
        parse_mnemonic_indexes(mnemonic).map_err(|e| format!("parse_mnemonic_indexes: {e:?}"))?;
    if parsed.as_slice() != expected.as_slice() {
        return Err("parse_mnemonic_indexes != standard_word_indexes".into());
    }
    let mut buf = [0u8; 256];
    let re_mnemonic = mnemonic_from_indexes(&expected, &mut buf)
        .map_err(|e| format!("mnemonic_from_indexes: {e:?}"))?;
    if re_mnemonic != mnemonic {
        return Err("mnemonic_from_indexes != vector.mnemonic".into());
    }
    // The 24-word BIP-39 entropy equals the CompactSeedQR bytes.
    let mut ent = [0u8; 32];
    let entropy = entropy_from_indexes(&expected, &mut ent)
        .map_err(|e| format!("entropy_from_indexes: {e:?}"))?;
    if entropy != compact.as_slice() {
        return Err("entropy_from_indexes != compact_seedqr_hex bytes".into());
    }
    Ok(())
}

pub(super) fn replay_nip19(value: &Value) -> ReplayResult {
    let nsec = str_field(value, "nsec")?;
    let secret_hex = str_field(value, "secret_key")?;
    let public_hex = str_field(value, "public_key")?;

    let secret = decode_nsec(nsec).map_err(|e| format!("decode_nsec: {e:?}"))?;
    let expected_secret = hex_to_bytes(secret_hex)?;
    if secret.as_slice() != expected_secret.as_slice() {
        return Err("decode_nsec != vector.secret_key".into());
    }
    let hex = decode_nsec_hex(nsec).map_err(|e| format!("decode_nsec_hex: {e:?}"))?;
    if hex.as_slice() != secret_hex.as_bytes() {
        return Err("decode_nsec_hex != vector.secret_key".into());
    }
    if !is_valid_secret_key(&secret) {
        return Err("decode_nsec produced an invalid secp256k1 scalar".into());
    }
    let mut buf = [0u8; 63];
    let re_nsec = encode_nsec(&secret, &mut buf).map_err(|e| format!("encode_nsec: {e:?}"))?;
    if re_nsec != nsec {
        return Err("encode_nsec != vector.nsec".into());
    }
    assert_public_key(public_hex) // format only (no derivation in-core)
}

pub(super) fn replay_keys(value: &Value) -> ReplayResult {
    // Two shapes: a raw key pair, or a NIP-06 mnemonic-derivation reference.
    if let Some(mnemonic) = value.get("mnemonic").and_then(Value::as_str) {
        let expected = u16_array(value, "standard_word_indexes")?;
        let parsed = parse_mnemonic_indexes(mnemonic)
            .map_err(|e| format!("parse_mnemonic_indexes: {e:?}"))?;
        if parsed.as_slice() != expected.as_slice() {
            return Err("parse_mnemonic_indexes != standard_word_indexes".into());
        }
        let indexes =
            WordIndexes::from_slice(&expected).map_err(|e| format!("WordIndexes: {e:?}"))?;
        require_valid_checksum(indexes.as_slice())
            .map_err(|e| format!("require_valid_checksum: {e:?}"))?;
    }
    // Both shapes carry a secret/public pair (derived key material for the NIP-06
    // shape); the core can only validate scalar range + pubkey format.
    assert_secret_key(str_field(value, "secret_key")?)?;
    assert_public_key(str_field(value, "public_key")?)
}

/// The canonical NIP-06 derivation path for a Nostr account index.
fn nip06_path(account: u64) -> String {
    format!("m/44'/1237'/{account}'/0/0")
}

pub(super) fn replay_accounts(value: &Value) -> ReplayResult {
    use super::{build_session_key_source, build_single_source_keyring, obj_field};
    use nsealr_core::session::account::{
        select_session_account, SessionAccountDescriptor, SessionAccountRecoveryKind,
        ESP32_QR_VAULT_ROUTE_TYPE,
    };
    use nsealr_core::session::import_review::session_key_source_fingerprint;

    // Every account descriptor must carry a valid reviewed public key + stable id.
    let account_id = str_field(value, "account_id")?;
    if account_id.is_empty() {
        return Err("account_id is empty".into());
    }
    let public_key = str_field(value, "public_key")?;
    assert_public_key(public_key)?;

    let route_type = str_field(obj_field(value, "signer_route")?, "type")?;
    let recovery = obj_field(value, "recovery")?;
    let recovery_type = str_field(recovery, "type")?;

    // The account's policy profile must resolve to a real on-disk `policies/`
    // profile that covers this account's route (cross-vector consistency).
    let policy_profile_id = str_field(value, "policy_profile_id")?;
    let mut resolved = false;
    for path in
        crate::category_files("policies", &[]).map_err(|e| format!("enumerate policies/: {e}"))?
    {
        let profile = super::load_value(&path)?;
        if str_field(&profile, "policy_id")? != policy_profile_id {
            continue;
        }
        let routes = super::arr_field(&profile, "route_types")?;
        if !routes.iter().any(|r| r.as_str() == Some(route_type)) {
            return Err(format!(
                "policy_profile_id '{policy_profile_id}' does not cover route '{route_type}'"
            ));
        }
        resolved = true;
        break;
    }
    if !resolved {
        return Err(format!(
            "policy_profile_id '{policy_profile_id}' resolves to no policies/ profile"
        ));
    }

    // NIP-06 accounts bind a reviewed pubkey to a derivable BIP-39 session source:
    // the source fingerprint and derivation path are core-verifiable (the pubkey
    // derivation itself is not — no signing crypto in-core).
    if recovery_type == "nip06" {
        let source_vector = str_field(recovery, "source_vector")?;
        let source_fingerprint = str_field(recovery, "source_fingerprint")?;
        let account = recovery.get("account").and_then(Value::as_u64).unwrap_or(0);
        let path = str_field(recovery, "path")?;
        if path != nip06_path(account) {
            return Err(format!(
                "recovery.path '{path}' != canonical {}",
                nip06_path(account)
            ));
        }
        let source = build_session_key_source("bip39_seed", source_vector, account_id)?;
        let fingerprint = session_key_source_fingerprint(&source);
        if fingerprint.as_str() != source_fingerprint {
            return Err(format!(
                "source fingerprint {} != recovery.source_fingerprint {source_fingerprint}",
                fingerprint.as_str()
            ));
        }
        // The QR-vault route additionally selects end-to-end through the session
        // account layer (the only route that layer accepts).
        if route_type == ESP32_QR_VAULT_ROUTE_TYPE {
            let keyring = build_single_source_keyring("bip39_seed", source_vector, account_id)?;
            let descriptor = SessionAccountDescriptor {
                account_id,
                route_type,
                public_key,
                source_index: 0,
                source_fingerprint,
                recovery_kind: SessionAccountRecoveryKind::Nip06,
                derivation_path: path,
                account_index: account as u32,
            };
            let selected = select_session_account(&keyring, &descriptor)
                .map_err(|e| format!("select_session_account: {e:?}"))?;
            if selected.public_key != public_key
                || selected.route_type != route_type
                || selected.source_fingerprint != source_fingerprint
                || selected.recovery_kind != SessionAccountRecoveryKind::Nip06
            {
                return Err("selected session account fields != descriptor".into());
            }
        }
        return Ok(());
    }

    // Persistent-device / external-signer accounts (device_slot, card_slot,
    // hardware_wallet_slot, external_signer): no RAM-only source to bind — the
    // core validates only the descriptor shape (asserted above). Recorded as a
    // known limit for non-session custody routes.
    Ok(())
}

pub(super) fn replay_proof(value: &Value) -> ReplayResult {
    use super::build_session_key_source;
    use nsealr_core::session::import_review::session_key_source_fingerprint;

    let source_type = str_field(value, "source_type")?;
    let source_vector = str_field(value, "source_vector")?;
    let source_fingerprint = str_field(value, "source_fingerprint")?;
    let expected_public_key = str_field(value, "expected_public_key")?;

    // The source parses and its fingerprint matches (core-verifiable).
    let source = build_session_key_source(source_type, source_vector, "proof source")?;
    let fingerprint = session_key_source_fingerprint(&source);
    if fingerprint.as_str() != source_fingerprint {
        return Err(format!(
            "source fingerprint {} != vector.source_fingerprint {source_fingerprint}",
            fingerprint.as_str()
        ));
    }
    // NIP-06 proofs additionally declare a derivation path that must be canonical.
    if str_field(value, "proof_type")? == "nip06" {
        let account = value.get("account").and_then(Value::as_u64).unwrap_or(0);
        let path = str_field(value, "path")?;
        if path != nip06_path(account) {
            return Err(format!(
                "path '{path}' != canonical {}",
                nip06_path(account)
            ));
        }
    }
    // expected_public_key is format-checked only: BIP-32/secp256k1 derivation is
    // out of `nsealr-core`'s scope, so the harness cannot re-derive it (known limit).
    assert_public_key(expected_public_key)
}
