#include "nostrseal/qr_review.hpp"

#include <string>
#include <vector>

namespace nostrseal {
namespace {

std::string kind_name(int kind) {
    switch (kind) {
        case 0:
            return "Metadata";
        case 1:
            return "Short Text Note";
        case 3:
            return "Contacts";
        case 6:
            return "Repost";
        case 7:
            return "Reaction";
        case 9735:
            return "Zap Receipt";
        default:
            return "Unknown";
    }
}

std::string content_preview(const std::string& content) {
    constexpr std::size_t kMaxPreview = 120;
    if (content.size() <= kMaxPreview) {
        return content;
    }
    return content.substr(0, kMaxPreview) + "...";
}

std::vector<std::string> tag_summary(const std::vector<std::vector<std::string>>& tags) {
    std::vector<std::string> summary;
    for (const std::vector<std::string>& tag : tags) {
        if (tag.empty()) {
            continue;
        }
        const std::string& name = tag[0];
        std::string value = tag.size() > 1U ? tag[1] : "";
        if ((name == "p" || name == "e") && value.size() > 8U) {
            value = value.substr(0, 8) + "...";
        }
        summary.push_back(value.empty() ? name : name + ": " + value);
    }
    return summary;
}

std::vector<std::string> warnings_for(const QrEventTemplate& event_template) {
    std::vector<std::string> warnings;
    if (kind_name(event_template.kind) == "Unknown") {
        warnings.push_back("Unknown event kind.");
    }
    if (event_template.content.size() > 280U) {
        warnings.push_back("Long content.");
    }
    if (event_template.content.empty()) {
        warnings.push_back("Empty content.");
    }
    bool has_pubkey_mention = false;
    bool has_event_reference = false;
    for (const std::vector<std::string>& tag : event_template.tags) {
        if (!tag.empty() && tag[0] == "p") {
            has_pubkey_mention = true;
        }
        if (!tag.empty() && tag[0] == "e") {
            has_event_reference = true;
        }
    }
    if (has_pubkey_mention) {
        warnings.push_back("Event includes pubkey mentions.");
    }
    if (has_event_reference) {
        warnings.push_back("Event references other events.");
    }
    if (event_template.tags.size() > 8U) {
        warnings.push_back("Many tags.");
    }
    return warnings;
}

std::vector<std::string> tag_lines(const QrEventTemplate& event_template) {
    if (event_template.tags.empty()) {
        return {"No tags"};
    }
    std::vector<std::string> lines{
        event_template.tags.size() == 1U ? "1 tag" : std::to_string(event_template.tags.size()) + " tags"};
    const std::vector<std::string> summary = tag_summary(event_template.tags);
    lines.insert(lines.end(), summary.begin(), summary.end());
    return lines;
}

}  // namespace

std::vector<TrustedReviewPage> build_qr_review_pages(const QrSigningRequest& request) {
    const QrEventTemplate& event_template = request.event_template;
    std::vector<TrustedReviewPage> pages{
        TrustedReviewPage{
            "Event",
            {
                "Kind " + std::to_string(event_template.kind),
                kind_name(event_template.kind),
                "Created " + std::to_string(event_template.created_at),
            },
            ReviewPageAction::Next,
        },
        TrustedReviewPage{
            "Content",
            {content_preview(event_template.content)},
            ReviewPageAction::Next,
        },
        TrustedReviewPage{
            "Tags",
            tag_lines(event_template),
            ReviewPageAction::Next,
        },
    };

    const std::vector<std::string> warnings = warnings_for(event_template);
    if (warnings.empty()) {
        pages.push_back(TrustedReviewPage{
            "Decision",
            {"Approve signing only if all pages match."},
            ReviewPageAction::ApproveOrReject,
        });
    } else {
        pages.push_back(TrustedReviewPage{
            "Warnings",
            warnings,
            ReviewPageAction::ApproveOrReject,
        });
    }
    return pages;
}

}  // namespace nostrseal
