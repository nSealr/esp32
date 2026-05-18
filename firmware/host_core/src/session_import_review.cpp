#include "nsealr/session_import_review.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "nsealr/sha256.hpp"

namespace nsealr {
namespace {

constexpr std::size_t kSessionKeySourceFingerprintHexChars = 16U;

std::string source_kind_label(SessionKeySourceKind kind) {
    switch (kind) {
        case SessionKeySourceKind::NsecSecretKey:
            return "NIP-19 nsec";
        case SessionKeySourceKind::Bip39WordIndexes:
            return "BIP-39 seed";
    }
    return "Unknown";
}

std::string fingerprint_material(const SessionKeySource& source) {
    std::string material = "nsealr.session-key-source.v0\n";
    material += source_kind_label(source.kind);
    material += "\n";
    if (source.kind == SessionKeySourceKind::NsecSecretKey) {
        material.append(
            reinterpret_cast<const char*>(source.nsec_secret_key.data()),
            source.nsec_secret_key.size());
        return material;
    }

    material += std::to_string(source.bip39_word_indexes.count);
    material += "\n";
    for (std::size_t index = 0; index < source.bip39_word_indexes.count; ++index) {
        const std::uint16_t word_index = source.bip39_word_indexes.values[index];
        material.push_back(static_cast<char>((word_index >> 8U) & 0xffU));
        material.push_back(static_cast<char>(word_index & 0xffU));
    }
    return material;
}

std::vector<std::string> source_summary_lines(const SessionKeySource& source, const std::string& fingerprint) {
    std::vector<std::string> lines{
        "Type: " + source_kind_label(source.kind),
        "Label: " + source.label,
        "Fingerprint: " + fingerprint,
    };
    if (source.kind == SessionKeySourceKind::Bip39WordIndexes) {
        lines.push_back("Words: " + std::to_string(source.bip39_word_indexes.count));
    }
    lines.push_back("Secret: hidden");
    return lines;
}

std::string import_approval_digest(const SessionKeySource& source, const std::string& fingerprint) {
    std::string material = "nsealr.session-import-review.v0\n";
    material += source_kind_label(source.kind);
    material += "\n";
    material += source.label;
    material += "\n";
    material += fingerprint;
    return sha256_hex(material);
}

}  // namespace

std::string session_key_source_fingerprint(const SessionKeySource& source) {
    return sha256_hex(fingerprint_material(source)).substr(0U, kSessionKeySourceFingerprintHexChars);
}

SessionImportReview build_session_import_review(const SessionKeySource& source) {
    const std::string fingerprint = session_key_source_fingerprint(source);
    return SessionImportReview{
        "session-import-" + fingerprint,
        import_approval_digest(source, fingerprint),
        {
            TrustedReviewPage{
                "Import source",
                source_summary_lines(source, fingerprint),
                ReviewPageAction::Next,
                "Page 1/2",
                {},
                "session-import-summary",
            },
            TrustedReviewPage{
                "Import?",
                {
                    "Session RAM only",
                    "No signing enabled",
                    "Approve to load",
                },
                ReviewPageAction::ApproveOrReject,
                "Page 2/2",
                {},
                "session-import-decision",
            },
        },
    };
}

}  // namespace nsealr
