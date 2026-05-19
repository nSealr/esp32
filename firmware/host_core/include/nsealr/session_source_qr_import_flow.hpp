#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "nsealr/session_import_flow.hpp"
#include "nsealr/session_keyring.hpp"

namespace nsealr {

[[nodiscard]] SessionImportFlowResult run_session_source_qr_text_import_flow(
    StatelessSessionKeyring& keyring,
    std::string label,
    std::string_view decoded_text,
    const std::vector<ReviewButton>& buttons,
    std::size_t max_button_steps = 32U);

[[nodiscard]] SessionImportFlowResult run_compact_seedqr_session_import_flow(
    StatelessSessionKeyring& keyring,
    std::string label,
    const std::vector<std::uint8_t>& entropy,
    const std::vector<ReviewButton>& buttons,
    std::size_t max_button_steps = 32U);

}  // namespace nsealr
