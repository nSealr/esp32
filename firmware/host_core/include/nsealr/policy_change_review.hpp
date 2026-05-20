#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "nsealr/review_controls.hpp"
#include "nsealr/trusted_review.hpp"

namespace nsealr {

class PolicyChangeReviewError final : public std::runtime_error {
public:
    explicit PolicyChangeReviewError(const std::string& message) : std::runtime_error(message) {}
};

struct PolicyChangeRequester {
    std::string surface;
    std::string client_pubkey;
    std::optional<std::string> label;
};

struct PolicyChangeProposal {
    std::string proposal_id;
    std::string account_id;
    std::string route_type;
    std::string action;
    std::string current_policy_id;
    std::string proposed_policy_id;
    std::vector<std::string> proposed_grant_ids;
    PolicyChangeRequester requested_by;
    std::uint64_t created_at = 0;
    bool device_review_required = false;
    bool physical_approval_required = false;
    bool companion_authoritative = true;
    bool contains_secret_material = true;
};

struct PolicyChangeReview {
    std::string proposal_id;
    std::string approval_digest;
    std::vector<TrustedReviewPage> pages;
};

struct PolicyChangeReviewTranscriptStep {
    std::size_t page_index = 0;
    ReviewButton button = ReviewButton::Next;
    std::optional<bool> decision;
    bool approved_for_policy_change = false;
};

struct PolicyChangeReviewFlowResult {
    PolicyChangeReview review;
    bool approved = false;
    std::vector<PolicyChangeReviewTranscriptStep> transcript;
};

[[nodiscard]] PolicyChangeReview build_policy_change_review(const PolicyChangeProposal& proposal);
[[nodiscard]] TrustedReviewRequest build_policy_change_trusted_review_request(
    const PolicyChangeProposal& proposal);
[[nodiscard]] PolicyChangeReviewFlowResult run_policy_change_review_flow(
    const PolicyChangeProposal& proposal,
    const std::vector<ReviewButton>& buttons,
    std::size_t max_button_steps = 32U);

}  // namespace nsealr
