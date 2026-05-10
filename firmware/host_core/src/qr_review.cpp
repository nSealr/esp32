#include "nostrseal/qr_review.hpp"

#include "nostrseal/sha256.hpp"
#include "nostrseal/utf8.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace nostrseal {
namespace {

struct QrReviewData {
    int kind;
    std::uint64_t created_at;
    std::string author_pubkey;
    std::string content;
    std::size_t content_utf8_bytes;
    std::size_t tag_count;
    std::vector<std::vector<std::string>> tags;
};

struct StyledReviewLines {
    std::vector<std::string> lines;
    std::vector<ReviewBodyLineStyle> styles;
};

constexpr std::string_view kDevelopmentReviewAuthorPubkey =
    "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

QrReviewData review_data_for(const QrEventTemplate& event_template) {
    return QrReviewData{
        event_template.kind,
        event_template.created_at,
        std::string{kDevelopmentReviewAuthorPubkey},
        event_template.content,
        event_template.content.size(),
        event_template.tags.size(),
        event_template.tags,
    };
}

std::vector<std::string> tag_lines(const QrReviewData& review) {
    if (review.tag_count == 0U) {
        return {"No tags"};
    }
    std::vector<std::string> lines;
    for (std::size_t tag_index = 0; tag_index < review.tags.size(); ++tag_index) {
        const std::vector<std::string>& tag = review.tags[tag_index];
        lines.push_back("Tag " + std::to_string(tag_index + 1U) + "/" + std::to_string(review.tag_count));
        if (tag.empty()) {
            lines.push_back("empty tag");
            continue;
        }
        lines.insert(lines.end(), tag.begin(), tag.end());
    }
    return lines;
}

void validate_display_page_limits(ReviewDisplayLimits limits) {
    if (limits.max_title_chars == 0U || limits.max_body_lines == 0U || limits.max_line_chars == 0U ||
        limits.max_compact_body_lines == 0U || limits.max_compact_line_chars == 0U) {
        throw std::invalid_argument("review display limits must be non-zero");
    }
}

std::vector<std::string> split_exact_display_lines(std::string_view text, std::size_t width) {
    if (text.empty()) {
        return {""};
    }
    std::vector<std::string> lines;
    std::size_t position = 0;
    while (position < text.size()) {
        const std::size_t count = std::min(width, text.size() - position);
        lines.emplace_back(text.substr(position, count));
        position += count;
    }
    return lines;
}

bool display_glyph_ascii(char ch) {
    return (ch >= 'A' && ch <= 'Z') ||
           (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') ||
           ch == ' ' || ch == '/' || ch == ':' || ch == '-' || ch == '_' || ch == '.' || ch == '+';
}

void append_codepoint_escape(std::string& out, std::uint32_t codepoint) {
    constexpr char kHex[] = "0123456789ABCDEF";
    char buffer[8]{};
    std::size_t size = 0;
    std::uint32_t value = codepoint;
    do {
        buffer[size++] = kHex[value & 0x0fU];
        value >>= 4U;
    } while (value > 0U);
    while (size < 4U) {
        buffer[size++] = '0';
    }
    out += "U+";
    while (size > 0U) {
        out.push_back(buffer[--size]);
    }
}

std::string display_safe_text(std::string_view text) {
    std::string out;
    std::size_t offset = 0;
    while (offset < text.size()) {
        std::uint32_t codepoint = 0;
        if (!decode_next_utf8_codepoint(text, offset, codepoint)) {
            codepoint = kReplacementCodepoint;
        }
        if (codepoint <= 0x7fU && display_glyph_ascii(static_cast<char>(codepoint))) {
            out.push_back(static_cast<char>(codepoint));
        } else {
            append_codepoint_escape(out, codepoint);
        }
    }
    return out;
}

void append_styled_line(StyledReviewLines& out, std::string line, ReviewBodyLineStyle style) {
    out.lines.push_back(std::move(line));
    out.styles.push_back(style);
}

void append_split_value_lines(
    StyledReviewLines& out,
    const std::string& value,
    std::size_t width,
    ReviewBodyLineStyle style = ReviewBodyLineStyle::Value) {
    std::vector<std::string> value_lines = split_exact_display_lines(value, width);
    for (std::string& line : value_lines) {
        append_styled_line(out, std::move(line), style);
    }
}

StyledReviewLines detailed_content_lines(const std::string& content, ReviewDisplayLimits limits) {
    StyledReviewLines out;
    if (content.empty()) {
        append_styled_line(out, "empty content", ReviewBodyLineStyle::Meta);
        return out;
    }
    std::string safe_content = display_safe_text(content);
    if (safe_content.size() <= limits.max_compact_line_chars) {
        append_styled_line(out, std::move(safe_content), ReviewBodyLineStyle::Normal);
        return out;
    }
    append_styled_line(out, "bytes: " + std::to_string(content.size()), ReviewBodyLineStyle::Meta);
    append_split_value_lines(out, safe_content, limits.max_compact_line_chars);
    return out;
}

void append_tag_item_lines(
    StyledReviewLines& out,
    const std::string& value,
    std::size_t width) {
    if (value.empty()) {
        return;
    }

    constexpr std::string_view kContinuationIndent = "  ";
    const std::size_t continuation_width =
        width > kContinuationIndent.size() ? width - kContinuationIndent.size() : width;
    const std::string safe_value = display_safe_text(value);
    std::size_t position = 0;
    bool first_line = true;
    while (position < safe_value.size()) {
        const std::size_t line_width = first_line ? width : continuation_width;
        const std::size_t count = std::min(line_width, safe_value.size() - position);
        std::string line = safe_value.substr(position, count);
        if (!first_line && width > kContinuationIndent.size()) {
            line = std::string{kContinuationIndent} + line;
        }
        append_styled_line(out, std::move(line), ReviewBodyLineStyle::Value);
        position += count;
        first_line = false;
    }
}

StyledReviewLines detailed_event_lines(const QrEventTemplate& event_template, ReviewDisplayLimits limits) {
    StyledReviewLines out;
    append_styled_line(out, "Kind " + std::to_string(event_template.kind), ReviewBodyLineStyle::Meta);
    append_styled_line(out, "Created " + std::to_string(event_template.created_at), ReviewBodyLineStyle::Meta);
    append_styled_line(out, "Author", ReviewBodyLineStyle::Meta);
    append_tag_item_lines(out, std::string{kDevelopmentReviewAuthorPubkey}, limits.max_compact_line_chars);
    return out;
}

StyledReviewLines detailed_tag_lines(
    const std::vector<std::vector<std::string>>& tags,
    ReviewDisplayLimits limits) {
    StyledReviewLines out;
    if (tags.empty()) {
        append_styled_line(out, "No tags", ReviewBodyLineStyle::Normal);
        return out;
    }

    for (std::size_t tag_index = 0; tag_index < tags.size(); ++tag_index) {
        const std::vector<std::string>& tag = tags[tag_index];
        append_styled_line(out,
                           "Tag " + std::to_string(tag_index + 1U) + "/" + std::to_string(tags.size()),
                           ReviewBodyLineStyle::Meta);
        for (std::size_t field_index = 0; field_index < tag.size(); ++field_index) {
            append_tag_item_lines(out, tag[field_index], limits.max_compact_line_chars);
        }
        if (tag.empty()) {
            append_styled_line(out, "empty tag", ReviewBodyLineStyle::Value);
        }
    }
    return out;
}

std::string logical_page_indicator(std::size_t page_index, std::size_t page_count) {
    return "Page " + std::to_string(page_index) + "/" + std::to_string(page_count);
}

std::string logical_page_indicator(
    std::size_t page_index,
    std::size_t page_count,
    std::size_t first_line,
    std::size_t last_line,
    std::size_t line_count) {
    if (line_count == 0U || (first_line == 1U && last_line >= line_count)) {
        return logical_page_indicator(page_index, page_count);
    }
    return logical_page_indicator(page_index, page_count) + " Lines " +
           std::to_string(first_line) + "-" + std::to_string(last_line) + "/" +
           std::to_string(line_count);
}

void append_display_pages(
    std::vector<TrustedReviewPage>& pages,
    const std::string& title,
    const StyledReviewLines& styled,
    ReviewDisplayLimits limits,
    std::size_t logical_page_index,
    std::size_t logical_page_count) {
    const std::size_t lines_per_screen = styled.styles.empty() ? limits.max_body_lines : limits.max_compact_body_lines;
    const std::size_t total = styled.lines.empty() ? 1U : styled.lines.size();
    const std::size_t scroll_step = lines_per_screen;
    std::size_t position = 0;
    while (position < total) {
        std::vector<std::string> body;
        std::vector<ReviewBodyLineStyle> body_styles;
        const std::size_t first_position = position;
        for (std::size_t line = 0; line < lines_per_screen && position < styled.lines.size(); ++line) {
            body.push_back(styled.lines[position]);
            body_styles.push_back(position < styled.styles.size() ? styled.styles[position] : ReviewBodyLineStyle::Normal);
            ++position;
        }
        if (body.empty()) {
            body.push_back("");
            body_styles.push_back(ReviewBodyLineStyle::Normal);
            position = total;
        }
        pages.push_back(TrustedReviewPage{
            title,
            std::move(body),
            ReviewPageAction::Next,
            logical_page_indicator(logical_page_index, logical_page_count, first_position + 1U, position, total),
            std::move(body_styles),
            title,
        });
        if (position >= total) {
            break;
        }
        position = first_position + scroll_step;
    }
}

std::vector<TrustedReviewPage> review_pages_for(const QrReviewData& review) {
    std::vector<TrustedReviewPage> pages{
        TrustedReviewPage{
            "Event",
            {
                "Kind " + std::to_string(review.kind),
                "Created " + std::to_string(review.created_at),
                "Author",
                review.author_pubkey,
            },
            ReviewPageAction::Next,
        },
        TrustedReviewPage{
            "Content",
            {review.content},
            ReviewPageAction::Next,
        },
        TrustedReviewPage{
            "Tags",
            tag_lines(review),
            ReviewPageAction::Next,
        },
    };

    pages.push_back(TrustedReviewPage{
        "Decision",
        {"Approve signing only if all pages match."},
        ReviewPageAction::ApproveOrReject,
    });
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
    out += "\"author_pubkey\":";
    out += json_string(review.author_pubkey);
    out += ",\"content\":";
    out += json_string(review.content);
    out += ",\"content_utf8_bytes\":";
    out += std::to_string(review.content_utf8_bytes);
    out += ",\"created_at\":";
    out += std::to_string(review.created_at);
    out += ",\"kind\":";
    out += std::to_string(review.kind);
    out += ",\"tag_count\":";
    out += std::to_string(review.tag_count);
    out += ",\"tags\":";
    out += json_tags(review.tags);
    out += "},\"version\":";
    out += std::to_string(request.version);
    out += "}";
    return out;
}

}  // namespace

std::vector<TrustedReviewPage> build_qr_review_pages(const QrSigningRequest& request) {
    return review_pages_for(review_data_for(request.event_template));
}

std::vector<TrustedReviewPage> build_qr_display_review_pages(
    const QrSigningRequest& request,
    ReviewDisplayLimits limits) {
    validate_display_page_limits(limits);

    const QrEventTemplate& event_template = request.event_template;
    std::vector<TrustedReviewPage> pages;
    append_display_pages(pages, "Event", detailed_event_lines(event_template, limits), limits, 1, 4);

    append_display_pages(pages, "Content", detailed_content_lines(event_template.content, limits), limits, 2, 4);
    append_display_pages(pages, "Tags", detailed_tag_lines(event_template.tags, limits), limits, 3, 4);
    pages.push_back(TrustedReviewPage{
        "Decision",
        {
            "Approve signing only if all pages match.",
        },
        ReviewPageAction::ApproveOrReject,
        logical_page_indicator(4, 4),
        {},
        "Decision",
    });
    return pages;
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

TrustedReviewRequest build_qr_display_review_request(
    const QrSigningRequest& request,
    ReviewDisplayLimits limits) {
    TrustedReviewRequest review_request = build_qr_trusted_review_request(request);
    review_request.pages = build_qr_display_review_pages(request, limits);
    return review_request;
}

TrustedReviewSession begin_qr_trusted_review(const QrSigningRequest& request, ReviewDisplayLimits limits) {
    return TrustedReviewSession{build_qr_display_review_request(request, limits), limits};
}

}  // namespace nostrseal
