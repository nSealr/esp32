#include "t_display_s3_status_frames.hpp"

#include <string>
#include <vector>

namespace nostrseal_esp32 {
namespace {

std::vector<std::string> non_signing_body_lines() {
    return std::vector<std::string>{
        "Not signed",
        "Signing disabled",
        "Send new request",
    };
}

}  // namespace

nostrseal::ReviewDisplayFrame build_t_display_s3_ready_frame() {
    nostrseal::ReviewDisplayFrame frame;
    frame.title = "Ready";
    frame.page_indicator = "No request";
    frame.body_lines = std::vector<std::string>{
        "USB signer",
        "Send sign_event",
        "Signing disabled",
    };
    frame.action_hint = "Waiting";
    return frame;
}

nostrseal::ReviewDisplayFrame build_t_display_s3_review_decision_frame(bool approved) {
    nostrseal::ReviewDisplayFrame frame;
    frame.title = approved ? "Review OK" : "Rejected";
    frame.page_indicator = "Closed";
    frame.body_lines = non_signing_body_lines();
    frame.action_hint = "Waiting";
    return frame;
}

nostrseal::ReviewDisplayFrame build_t_display_s3_review_timeout_frame() {
    nostrseal::ReviewDisplayFrame frame;
    frame.title = "Review Timeout";
    frame.page_indicator = "Expired";
    frame.body_lines = non_signing_body_lines();
    frame.action_hint = "Waiting";
    return frame;
}

nostrseal::ReviewDisplayFrame build_t_display_s3_request_error_frame() {
    nostrseal::ReviewDisplayFrame frame;
    frame.title = "Request Error";
    frame.page_indicator = "Rejected";
    frame.body_lines = non_signing_body_lines();
    frame.action_hint = "Waiting";
    return frame;
}

}  // namespace nostrseal_esp32
