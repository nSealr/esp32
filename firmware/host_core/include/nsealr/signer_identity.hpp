#pragma once

#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>

namespace nsealr {

constexpr std::string_view kDevelopmentFixturePublicKey =
    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

struct SignerIdentity {
    std::string public_key;
};

class SignerIdentityError final : public std::runtime_error {
public:
    explicit SignerIdentityError(const std::string& message) : std::runtime_error(message) {}
};

inline bool is_lowercase_hex(char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
}

inline bool is_valid_nostr_public_key(std::string_view public_key) {
    return public_key.size() == 64U &&
           std::all_of(public_key.begin(), public_key.end(), is_lowercase_hex);
}

inline void require_valid_signer_identity(const SignerIdentity& identity) {
    if (!is_valid_nostr_public_key(identity.public_key)) {
        throw SignerIdentityError("signer public key must be 64 lowercase hex characters");
    }
}

inline SignerIdentity development_fixture_signer_identity() {
    return SignerIdentity{std::string{kDevelopmentFixturePublicKey}};
}

}  // namespace nsealr
