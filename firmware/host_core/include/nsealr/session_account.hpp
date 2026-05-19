#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "nsealr/device_protocol.hpp"
#include "nsealr/session_keyring.hpp"
#include "nsealr/signer_identity.hpp"

namespace nsealr {

class SessionAccountError final : public std::runtime_error {
public:
    explicit SessionAccountError(const std::string& message) : std::runtime_error(message) {}
};

enum class SessionAccountRecoveryKind {
    Nip06,
    StandaloneNsec,
};

struct SessionAccountDescriptor {
    std::string account_id;
    std::string route_type;
    std::string public_key;
    std::size_t source_index = 0;
    std::string source_fingerprint;
    SessionAccountRecoveryKind recovery_kind = SessionAccountRecoveryKind::Nip06;
    std::string derivation_path;
    std::uint32_t account_index = 0;
};

struct SelectedSessionAccount {
    std::string account_id;
    std::string route_type;
    std::string public_key;
    std::size_t source_index = 0;
    std::string source_fingerprint;
    SessionAccountRecoveryKind recovery_kind = SessionAccountRecoveryKind::Nip06;
    SessionKeySourceKind source_kind = SessionKeySourceKind::NsecSecretKey;
    std::string source_label;
    SignerIdentity signer_identity;
};

[[nodiscard]] SelectedSessionAccount select_session_account(
    const StatelessSessionKeyring& keyring,
    const SessionAccountDescriptor& descriptor);
[[nodiscard]] DeviceProtocolContext device_protocol_context_for_session_account(
    const SelectedSessionAccount& account);

}  // namespace nsealr
