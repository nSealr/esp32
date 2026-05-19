#include "nsealr/session_source_qr_import_flow.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "nsealr/session_source_qr.hpp"

namespace nsealr {

SessionImportFlowResult run_session_source_qr_text_import_flow(
    StatelessSessionKeyring& keyring,
    std::string label,
    std::string_view decoded_text,
    const std::vector<ReviewButton>& buttons,
    std::size_t max_button_steps) {
    SessionKeySource source = parse_session_source_qr_text(std::move(label), decoded_text);
    return run_session_import_flow(keyring, source, buttons, max_button_steps);
}

SessionImportFlowResult run_compact_seedqr_session_import_flow(
    StatelessSessionKeyring& keyring,
    std::string label,
    const std::vector<std::uint8_t>& entropy,
    const std::vector<ReviewButton>& buttons,
    std::size_t max_button_steps) {
    SessionKeySource source = parse_compact_seedqr_session_source(std::move(label), entropy);
    return run_session_import_flow(keyring, source, buttons, max_button_steps);
}

}  // namespace nsealr
