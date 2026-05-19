#include "nsealr/session_account.hpp"

#include <algorithm>

#include "nsealr/session_import_review.hpp"

namespace nsealr {
namespace {

constexpr std::size_t kMaxSessionAccountIdLength = 128U;
constexpr std::size_t kSessionSourceFingerprintLength = 16U;
constexpr const char* kEsp32QrVaultRouteType = "esp32_qr_vault";

bool is_stable_id_char(char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == ':' || ch == '-';
}

bool is_stable_id(const std::string& value) {
    return !value.empty() && value.size() <= kMaxSessionAccountIdLength &&
           std::all_of(value.begin(), value.end(), is_stable_id_char);
}

bool is_lower_hex(char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
}

bool is_source_fingerprint(const std::string& value) {
    return value.size() == kSessionSourceFingerprintLength &&
           std::all_of(value.begin(), value.end(), is_lower_hex);
}

std::string expected_nip06_path(std::uint32_t account_index) {
    return "m/44'/1237'/" + std::to_string(account_index) + "'/0/0";
}

void require_descriptor_shape(const SessionAccountDescriptor& descriptor) {
    if (!is_stable_id(descriptor.account_id)) {
        throw SessionAccountError("session account_id must be a stable string id");
    }
    if (descriptor.route_type != kEsp32QrVaultRouteType) {
        throw SessionAccountError("session account route_type must be esp32_qr_vault");
    }
    if (!is_valid_nostr_public_key(descriptor.public_key)) {
        throw SessionAccountError("session account public_key must be 32-byte lowercase hex");
    }
    if (!is_source_fingerprint(descriptor.source_fingerprint)) {
        throw SessionAccountError("session account source_fingerprint must be 8-byte lowercase hex");
    }
}

void require_source_matches_recovery(
    const SessionAccountDescriptor& descriptor,
    const SessionKeySource& source) {
    switch (descriptor.recovery_kind) {
        case SessionAccountRecoveryKind::Nip06:
            if (source.kind != SessionKeySourceKind::Bip39WordIndexes) {
                throw SessionAccountError("NIP-06 session account requires a BIP-39 source");
            }
            if (descriptor.derivation_path != expected_nip06_path(descriptor.account_index)) {
                throw SessionAccountError("NIP-06 session account path does not match account index");
            }
            return;
        case SessionAccountRecoveryKind::StandaloneNsec:
            if (source.kind != SessionKeySourceKind::NsecSecretKey) {
                throw SessionAccountError("standalone nsec session account requires an nsec source");
            }
            if (!descriptor.derivation_path.empty()) {
                throw SessionAccountError("standalone nsec session account must not carry a derivation path");
            }
            return;
    }
    throw SessionAccountError("session account recovery kind is unsupported");
}

}  // namespace

SelectedSessionAccount select_session_account(
    const StatelessSessionKeyring& keyring,
    const SessionAccountDescriptor& descriptor) {
    require_descriptor_shape(descriptor);

    const SessionKeySource* source = nullptr;
    try {
        source = &keyring.source_at(descriptor.source_index);
    } catch (const SessionKeyringError&) {
        throw SessionAccountError("session account source index is out of range");
    }
    require_source_matches_recovery(descriptor, *source);
    if (session_key_source_fingerprint(*source) != descriptor.source_fingerprint) {
        throw SessionAccountError("session account source_fingerprint does not match selected source");
    }

    SignerIdentity identity{descriptor.public_key};
    require_valid_signer_identity(identity);
    return SelectedSessionAccount{
        descriptor.account_id,
        descriptor.route_type,
        descriptor.public_key,
        descriptor.source_index,
        descriptor.source_fingerprint,
        descriptor.recovery_kind,
        source->kind,
        source->label,
        identity,
    };
}

DeviceProtocolContext device_protocol_context_for_session_account(
    const SelectedSessionAccount& account) {
    require_valid_signer_identity(account.signer_identity);
    return DeviceProtocolContext{account.signer_identity};
}

}  // namespace nsealr
