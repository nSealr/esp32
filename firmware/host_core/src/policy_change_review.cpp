#include "nsealr/policy_change_review.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>

#include "nsealr/sha256.hpp"

namespace nsealr {
namespace {

bool matches_stable_id(std::string_view value, std::size_t max_size) {
    if (value.empty() || value.size() > max_size) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char ch) {
        const unsigned char byte = static_cast<unsigned char>(ch);
        return std::isalnum(byte) || ch == '.' || ch == '_' || ch == ':' || ch == '-';
    });
}

bool has_prefix(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
}

bool is_lower_hex_32(std::string_view value) {
    if (value.size() != 64U) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

bool is_supported_route(std::string_view route_type) {
    return route_type == "esp32_usb_nip46" || route_type == "custom_hardware_wallet";
}

bool is_supported_surface(std::string_view surface) {
    return surface == "browser_extension" || surface == "desktop_app" || surface == "cli" ||
           surface == "sdk" || surface == "native_host_test";
}

void require_policy_id(std::string_view value, std::string_view field) {
    if (!has_prefix(value, "policy-") || !matches_stable_id(value.substr(7U), 121U)) {
        throw PolicyChangeReviewError(std::string{field} + " must be a policy-* stable string id");
    }
}

void require_grant_id(std::string_view value) {
    if (!has_prefix(value, "grant-") || !matches_stable_id(value.substr(6U), 122U)) {
        throw PolicyChangeReviewError("proposed grant id must be a grant-* stable string id");
    }
}

void validate_policy_change_proposal(const PolicyChangeProposal& proposal) {
    if (!has_prefix(proposal.proposal_id, "proposal-") ||
        !matches_stable_id(std::string_view{proposal.proposal_id}.substr(9U), 119U)) {
        throw PolicyChangeReviewError("proposal_id must be a proposal-* stable string id");
    }
    if (!matches_stable_id(proposal.account_id, 128U)) {
        throw PolicyChangeReviewError("account_id must be a stable string id");
    }
    if (!is_supported_route(proposal.route_type)) {
        throw PolicyChangeReviewError("route_type must be a device-display persistent policy route");
    }
    if (proposal.action != "set_policy") {
        throw PolicyChangeReviewError("policy change action must be set_policy");
    }
    require_policy_id(proposal.current_policy_id, "current_policy_id");
    require_policy_id(proposal.proposed_policy_id, "proposed_policy_id");
    for (const std::string& grant_id : proposal.proposed_grant_ids) {
        require_grant_id(grant_id);
    }
    std::vector<std::string> sorted_grants = proposal.proposed_grant_ids;
    std::sort(sorted_grants.begin(), sorted_grants.end());
    if (std::adjacent_find(sorted_grants.begin(), sorted_grants.end()) != sorted_grants.end()) {
        throw PolicyChangeReviewError("proposed_grant_ids must be unique");
    }
    if (!is_supported_surface(proposal.requested_by.surface)) {
        throw PolicyChangeReviewError("requested_by.surface is unsupported");
    }
    if (!is_lower_hex_32(proposal.requested_by.client_pubkey)) {
        throw PolicyChangeReviewError("requested_by.client_pubkey must be 32-byte lowercase hex");
    }
    if (proposal.requested_by.label.has_value() && proposal.requested_by.label->empty()) {
        throw PolicyChangeReviewError("requested_by.label must be a non-empty string");
    }
    if (proposal.created_at == 0U) {
        throw PolicyChangeReviewError("created_at must be a positive integer");
    }
    if (!proposal.device_review_required) {
        throw PolicyChangeReviewError("device_review_required must be true");
    }
    if (!proposal.physical_approval_required) {
        throw PolicyChangeReviewError("physical_approval_required must be true");
    }
    if (proposal.companion_authoritative) {
        throw PolicyChangeReviewError("companion_authoritative must be false");
    }
    if (proposal.contains_secret_material) {
        throw PolicyChangeReviewError("contains_secret_material must be false");
    }
}

std::string json_escape(std::string_view value) {
    std::string out;
    for (const char ch : value) {
        switch (ch) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20U) {
                    constexpr char kHex[] = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(kHex[(static_cast<unsigned char>(ch) >> 4U) & 0x0fU]);
                    out.push_back(kHex[static_cast<unsigned char>(ch) & 0x0fU]);
                } else {
                    out.push_back(ch);
                }
                break;
        }
    }
    return out;
}

std::string json_string(std::string_view value) {
    return "\"" + json_escape(value) + "\"";
}

std::string json_string_array(const std::vector<std::string>& values) {
    std::string out = "[";
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0U) {
            out.push_back(',');
        }
        out += json_string(values[index]);
    }
    out.push_back(']');
    return out;
}

std::string json_bool(bool value) {
    return value ? "true" : "false";
}

std::string review_action_json(ReviewPageAction action) {
    switch (action) {
        case ReviewPageAction::Next:
            return "\"next\"";
        case ReviewPageAction::ApproveOrReject:
            return "\"approve_or_reject\"";
    }
    throw PolicyChangeReviewError("unsupported policy-change review action");
}

std::string review_page_json(const TrustedReviewPage& page) {
    return "{\"action\":" + review_action_json(page.action) +
           ",\"lines\":" + json_string_array(page.lines) +
           ",\"title\":" + json_string(page.title) + "}";
}

std::string review_pages_json(const std::vector<TrustedReviewPage>& pages) {
    std::string out = "[";
    for (std::size_t index = 0; index < pages.size(); ++index) {
        if (index > 0U) {
            out.push_back(',');
        }
        out += review_page_json(pages[index]);
    }
    out.push_back(']');
    return out;
}

std::string requester_json(const PolicyChangeRequester& requester) {
    std::string out = "{\"client_pubkey\":" + json_string(requester.client_pubkey);
    if (requester.label.has_value()) {
        out += ",\"label\":" + json_string(*requester.label);
    }
    out += ",\"surface\":" + json_string(requester.surface) + "}";
    return out;
}

std::string proposal_json(const PolicyChangeProposal& proposal) {
    return "{\"account_id\":" + json_string(proposal.account_id) +
           ",\"action\":" + json_string(proposal.action) +
           ",\"companion_authoritative\":" + json_bool(proposal.companion_authoritative) +
           ",\"contains_secret_material\":" + json_bool(proposal.contains_secret_material) +
           ",\"created_at\":" + std::to_string(proposal.created_at) +
           ",\"current_policy_id\":" + json_string(proposal.current_policy_id) +
           ",\"device_review_required\":" + json_bool(proposal.device_review_required) +
           ",\"format\":\"nsealr-policy-change-proposal-v0\"" +
           ",\"physical_approval_required\":" + json_bool(proposal.physical_approval_required) +
           ",\"proposal_id\":" + json_string(proposal.proposal_id) +
           ",\"proposed_grant_ids\":" + json_string_array(proposal.proposed_grant_ids) +
           ",\"proposed_policy_id\":" + json_string(proposal.proposed_policy_id) +
           ",\"requested_by\":" + requester_json(proposal.requested_by) +
           ",\"route_type\":" + json_string(proposal.route_type) + "}";
}

std::vector<std::string> requester_lines(const PolicyChangeRequester& requester) {
    std::vector<std::string> lines{
        "Surface: " + requester.surface,
        "Client: " + requester.client_pubkey,
    };
    if (requester.label.has_value()) {
        lines.push_back("Label: " + *requester.label);
    }
    return lines;
}

std::vector<std::string> policy_lines(const PolicyChangeProposal& proposal) {
    std::vector<std::string> lines{
        "From: " + proposal.current_policy_id,
        "To: " + proposal.proposed_policy_id,
        "Grants: " + std::to_string(proposal.proposed_grant_ids.size()),
    };
    for (const std::string& grant_id : proposal.proposed_grant_ids) {
        lines.push_back("Grant: " + grant_id);
    }
    return lines;
}

std::vector<TrustedReviewPage> review_pages_for(const PolicyChangeProposal& proposal) {
    return {
        TrustedReviewPage{
            "Policy change",
            {
                "Action: " + proposal.action,
                "Account: " + proposal.account_id,
                "Route: " + proposal.route_type,
            },
            ReviewPageAction::Next,
        },
        TrustedReviewPage{
            "Requester",
            requester_lines(proposal.requested_by),
            ReviewPageAction::Next,
        },
        TrustedReviewPage{
            "Policy",
            policy_lines(proposal),
            ReviewPageAction::Next,
        },
        TrustedReviewPage{
            "Decision",
            {
                "Review on device",
                "Physical approval required",
                "Companion cannot approve alone",
            },
            ReviewPageAction::ApproveOrReject,
        },
    };
}

std::string policy_change_approval_digest(
    const PolicyChangeProposal& proposal,
    const std::vector<TrustedReviewPage>& pages) {
    const std::string canonical =
        "{\"pages\":" + review_pages_json(pages) + ",\"proposal\":" + proposal_json(proposal) + "}";
    return sha256_hex(canonical);
}

}  // namespace

PolicyChangeReview build_policy_change_review(const PolicyChangeProposal& proposal) {
    validate_policy_change_proposal(proposal);
    std::vector<TrustedReviewPage> pages = review_pages_for(proposal);
    return PolicyChangeReview{
        proposal.proposal_id,
        policy_change_approval_digest(proposal, pages),
        std::move(pages),
    };
}

TrustedReviewRequest build_policy_change_trusted_review_request(
    const PolicyChangeProposal& proposal) {
    PolicyChangeReview review = build_policy_change_review(proposal);
    return TrustedReviewRequest{
        review.proposal_id,
        review.approval_digest,
        std::move(review.pages),
    };
}

PolicyChangeReviewFlowResult run_policy_change_review_flow(
    const PolicyChangeProposal& proposal,
    const std::vector<ReviewButton>& buttons,
    std::size_t max_button_steps) {
    if (max_button_steps == 0U) {
        throw PolicyChangeReviewError("policy change review flow max button steps must be positive");
    }

    PolicyChangeReviewFlowResult result;
    result.review = build_policy_change_review(proposal);
    TrustedReviewSession session{TrustedReviewRequest{
        result.review.proposal_id,
        result.review.approval_digest,
        result.review.pages,
    }};

    std::size_t step_count = 0;
    for (const ReviewButton button : buttons) {
        if (step_count >= max_button_steps) {
            throw PolicyChangeReviewError("policy change review exceeded max button steps");
        }
        ++step_count;

        const std::size_t page_index = session.current_page_index();
        const std::optional<bool> decision = session.handle_button(button);
        result.transcript.push_back(PolicyChangeReviewTranscriptStep{
            page_index,
            button,
            decision,
            session.can_sign(),
        });

        if (decision.has_value()) {
            result.approved = *decision;
            return result;
        }
    }

    throw PolicyChangeReviewError("policy change review did not reach approval or rejection");
}

}  // namespace nsealr
