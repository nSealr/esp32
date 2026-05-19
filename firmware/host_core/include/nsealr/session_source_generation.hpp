#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "nsealr/nip19_nsec.hpp"
#include "nsealr/session_keyring.hpp"

namespace nsealr {

class SessionSourceGenerationError final : public std::runtime_error {
public:
    explicit SessionSourceGenerationError(const std::string& message) : std::runtime_error(message) {}
};

[[nodiscard]] SessionKeySource generate_bip39_session_source(
    std::string label,
    const std::vector<std::uint8_t>& entropy);
[[nodiscard]] SessionKeySource generate_nsec_session_source(
    std::string label,
    const NsecSecretKey& entropy);

}  // namespace nsealr
