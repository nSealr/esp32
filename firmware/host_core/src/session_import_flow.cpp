#include "nsealr/session_import_flow.hpp"

#include <cstddef>
#include <optional>
#include <vector>

namespace nsealr {

SessionImportFlowResult run_session_import_flow(
    StatelessSessionKeyring& keyring,
    const SessionKeySource& source,
    const std::vector<ReviewButton>& buttons,
    std::size_t max_button_steps) {
    if (max_button_steps == 0U) {
        throw SessionImportFlowError("session import flow max button steps must be positive");
    }

    SessionImportFlowResult result;
    result.review = build_session_import_review(source);
    ReviewControlSession controls(result.review.pages.size());

    std::size_t step_count = 0;
    for (const ReviewButton button : buttons) {
        if (step_count >= max_button_steps) {
            throw SessionImportFlowError("session import review exceeded max button steps");
        }
        ++step_count;

        const std::size_t page_index = controls.current_page_index();
        const std::optional<bool> decision = controls.handle_button(button);
        bool loaded = false;
        if (decision.has_value() && *decision) {
            keyring.add_source(source);
            loaded = true;
        }
        result.transcript.push_back(SessionImportTranscriptStep{
            page_index,
            button,
            decision,
            loaded,
        });

        if (decision.has_value()) {
            result.approved = *decision;
            result.loaded = loaded;
            return result;
        }
    }

    throw SessionImportFlowError("session import review did not reach approval or rejection");
}

}  // namespace nsealr
