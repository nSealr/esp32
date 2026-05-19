#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "nsealr/session_keyring.hpp"

namespace nsealr {

class SessionSourceQrError final : public std::runtime_error {
public:
    explicit SessionSourceQrError(const std::string& message) : std::runtime_error(message) {}
};

[[nodiscard]] SessionKeySource parse_session_source_qr_text(
    std::string label,
    std::string_view decoded_text);
[[nodiscard]] SessionKeySource parse_compact_seedqr_session_source(
    std::string label,
    const std::vector<std::uint8_t>& entropy);

}  // namespace nsealr
