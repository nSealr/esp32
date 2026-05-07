#include "nostrseal/qr_review.hpp"

#include "nostrseal/sha256.hpp"

#include <string>
#include <utility>
#include <vector>

namespace nostrseal {
namespace {

struct QrReviewData {
    int kind;
    std::string kind_name;
    std::uint64_t created_at;
    std::string content_preview;
    std::size_t content_length;
    std::size_t tag_count;
    std::vector<std::string> tag_summary;
    std::vector<std::string> warnings;
};

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

std::vector<std::string> summarize_tags(const std::vector<std::vector<std::string>>& tags) {
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

std::vector<std::string> build_warnings(const QrEventTemplate& event_template) {
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

QrReviewData review_data_for(const QrEventTemplate& event_template) {
    const std::vector<std::string> summary = summarize_tags(event_template.tags);
    return QrReviewData{
        event_template.kind,
        kind_name(event_template.kind),
        event_template.created_at,
        content_preview(event_template.content),
        event_template.content.size(),
        event_template.tags.size(),
        summary,
        build_warnings(event_template),
    };
}

std::vector<std::string> tag_lines(const QrReviewData& review) {
    if (review.tag_count == 0U) {
        return {"No tags"};
    }
    std::vector<std::string> lines{
        review.tag_count == 1U ? "1 tag" : std::to_string(review.tag_count) + " tags"};
    lines.insert(lines.end(), review.tag_summary.begin(), review.tag_summary.end());
    return lines;
}

std::vector<TrustedReviewPage> review_pages_for(const QrReviewData& review) {
    std::vector<TrustedReviewPage> pages{
        TrustedReviewPage{
            "Event",
            {
                "Kind " + std::to_string(review.kind),
                review.kind_name,
                "Created " + std::to_string(review.created_at),
            },
            ReviewPageAction::Next,
        },
        TrustedReviewPage{
            "Content",
            {review.content_preview},
            ReviewPageAction::Next,
        },
        TrustedReviewPage{
            "Tags",
            tag_lines(review),
            ReviewPageAction::Next,
        },
    };

    if (review.warnings.empty()) {
        pages.push_back(TrustedReviewPage{
            "Decision",
            {"Approve signing only if all pages match."},
            ReviewPageAction::ApproveOrReject,
        });
    } else {
        pages.push_back(TrustedReviewPage{
            "Warnings",
            review.warnings,
            ReviewPageAction::ApproveOrReject,
        });
    }
    return pages;
}

std::string json_string(const std::string& value) {
    std::string out = "\"";
    for (const unsigned char ch : value) {
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
                if (ch < 0x20U) {
                    constexpr char kHex[] = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(kHex[(ch >> 4U) & 0x0fU]);
                    out.push_back(kHex[ch & 0x0fU]);
                } else {
                    out.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    out += "\"";
    return out;
}

std::string json_string_array(const std::vector<std::string>& values) {
    std::string out = "[";
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0U) {
            out += ",";
        }
        out += json_string(values[index]);
    }
    out += "]";
    return out;
}

std::string json_tags(const std::vector<std::vector<std::string>>& tags) {
    std::string out = "[";
    for (std::size_t tag_index = 0; tag_index < tags.size(); ++tag_index) {
        if (tag_index != 0U) {
            out += ",";
        }
        out += json_string_array(tags[tag_index]);
    }
    out += "]";
    return out;
}

const char* json_action(ReviewPageAction action) {
    if (action == ReviewPageAction::ApproveOrReject) {
        return "approve_or_reject";
    }
    return "next";
}

std::string json_pages(const std::vector<TrustedReviewPage>& pages) {
    std::string out = "[";
    for (std::size_t index = 0; index < pages.size(); ++index) {
        if (index != 0U) {
            out += ",";
        }
        out += "{\"action\":";
        out += json_string(json_action(pages[index].action));
        out += ",\"lines\":";
        out += json_string_array(pages[index].lines);
        out += ",\"title\":";
        out += json_string(pages[index].title);
        out += "}";
    }
    out += "]";
    return out;
}

std::string canonical_approval_payload(
    const QrSigningRequest& request,
    const QrReviewData& review,
    const std::vector<TrustedReviewPage>& pages) {
    const QrEventTemplate& event_template = request.event_template;
    std::string out = "{\"event_template\":{";
    out += "\"content\":";
    out += json_string(event_template.content);
    out += ",\"created_at\":";
    out += std::to_string(event_template.created_at);
    out += ",\"kind\":";
    out += std::to_string(event_template.kind);
    out += ",\"tags\":";
    out += json_tags(event_template.tags);
    out += "},\"method\":";
    out += json_string(request.method);
    out += ",\"pages\":";
    out += json_pages(pages);
    out += ",\"request_id\":";
    out += json_string(request.request_id);
    out += ",\"review\":{";
    out += "\"content_length\":";
    out += std::to_string(review.content_length);
    out += ",\"content_preview\":";
    out += json_string(review.content_preview);
    out += ",\"created_at\":";
    out += std::to_string(review.created_at);
    out += ",\"kind\":";
    out += std::to_string(review.kind);
    out += ",\"kind_name\":";
    out += json_string(review.kind_name);
    out += ",\"tag_count\":";
    out += std::to_string(review.tag_count);
    out += ",\"tag_summary\":";
    out += json_string_array(review.tag_summary);
    out += ",\"warnings\":";
    out += json_string_array(review.warnings);
    out += "},\"version\":";
    out += std::to_string(request.version);
    out += "}";
    return out;
}

}  // namespace

std::vector<TrustedReviewPage> build_qr_review_pages(const QrSigningRequest& request) {
    return review_pages_for(review_data_for(request.event_template));
}

TrustedReviewRequest build_qr_trusted_review_request(const QrSigningRequest& request) {
    const QrReviewData review = review_data_for(request.event_template);
    std::vector<TrustedReviewPage> pages = review_pages_for(review);
    const std::string digest = sha256_hex(canonical_approval_payload(request, review, pages));
    return TrustedReviewRequest{
        request.request_id,
        digest,
        std::move(pages),
    };
}

}  // namespace nostrseal
