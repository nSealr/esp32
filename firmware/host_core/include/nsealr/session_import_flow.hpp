#pragma once

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "nsealr/review_controls.hpp"
#include "nsealr/session_import_review.hpp"
#include "nsealr/session_keyring.hpp"

namespace nsealr {

class SessionImportFlowError final : public std::runtime_error {
public:
    explicit SessionImportFlowError(const std::string& message) : std::runtime_error(message) {}
};

struct SessionImportTranscriptStep {
    std::size_t page_index = 0;
    ReviewButton button = ReviewButton::Next;
    std::optional<bool> decision;
    bool loaded = false;
};

struct SessionImportFlowResult {
    SessionImportReview review;
    bool approved = false;
    bool loaded = false;
    std::vector<SessionImportTranscriptStep> transcript;
};

[[nodiscard]] SessionImportFlowResult run_session_import_flow(
    StatelessSessionKeyring& keyring,
    const SessionKeySource& source,
    const std::vector<ReviewButton>& buttons,
    std::size_t max_button_steps = 32U);

}  // namespace nsealr
