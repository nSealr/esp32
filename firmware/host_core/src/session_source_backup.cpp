#include "nsealr/session_source_backup.hpp"

#include <iomanip>
#include <sstream>

#include "nsealr/bip39_english.hpp"
#include "nsealr/nip19_nsec.hpp"
#include "nsealr/session_import_review.hpp"
#include "nsealr/sha256.hpp"

namespace nsealr {
namespace {

std::string backup_format_for(const SessionKeySource& source) {
    switch (source.kind) {
        case SessionKeySourceKind::Bip39WordIndexes:
            return "bip39_words_seedqr";
        case SessionKeySourceKind::NsecSecretKey:
            return "nip19_nsec";
    }
    throw SessionSourceBackupError("session backup source type is unsupported");
}

std::string source_kind_label(SessionKeySourceKind kind) {
    switch (kind) {
        case SessionKeySourceKind::NsecSecretKey:
            return "NIP-19 nsec";
        case SessionKeySourceKind::Bip39WordIndexes:
            return "BIP-39 seed";
    }
    return "Unknown";
}

Bip39WordIndexes bip39_indexes_for(const SessionKeySource& source) {
    Bip39WordIndexes indexes;
    indexes.reserve(source.bip39_word_indexes.count);
    for (std::size_t index = 0; index < source.bip39_word_indexes.count; ++index) {
        indexes.push_back(source.bip39_word_indexes.values[index]);
    }
    return indexes;
}

std::string standard_seedqr_from_indexes(const Bip39WordIndexes& indexes) {
    if (indexes.size() != 12U && indexes.size() != 24U) {
        throw SessionSourceBackupError("SeedQR backup word count must be 12 or 24");
    }
    std::ostringstream out;
    for (const std::uint16_t index : indexes) {
        out << std::setw(4) << std::setfill('0') << index;
    }
    return out.str();
}

std::string hex_from_bytes(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const std::uint8_t byte : bytes) {
        out << std::setw(2) << static_cast<unsigned>(byte);
    }
    return out.str();
}

std::string backup_approval_digest(
    const SessionKeySource& source,
    const std::string& fingerprint,
    const std::string& backup_format) {
    std::string material = "nsealr.session-source-backup-review.v0\n";
    material += source_kind_label(source.kind);
    material += "\n";
    material += source.label;
    material += "\n";
    material += fingerprint;
    material += "\n";
    material += backup_format;
    return sha256_hex(material);
}

}  // namespace

SessionSourceBackupPayload session_source_backup_payload(const SessionKeySource& source) {
    const std::string backup_format = backup_format_for(source);
    if (source.kind == SessionKeySourceKind::Bip39WordIndexes) {
        const Bip39WordIndexes indexes = bip39_indexes_for(source);
        return SessionSourceBackupPayload{
            backup_format,
            bip39_english_mnemonic_from_indexes(indexes),
            standard_seedqr_from_indexes(indexes),
            hex_from_bytes(bip39_entropy_from_indexes(indexes)),
            "",
        };
    }
    return SessionSourceBackupPayload{
        backup_format,
        "",
        "",
        "",
        encode_nsec_secret_key(source.nsec_secret_key),
    };
}

SessionSourceBackupReview build_session_source_backup_review(const SessionKeySource& source) {
    const std::string backup_format = backup_format_for(source);
    const std::string fingerprint = session_key_source_fingerprint(source);
    const std::string output =
        source.kind == SessionKeySourceKind::Bip39WordIndexes ? "words/SeedQR" : "nsec QR/text";
    return SessionSourceBackupReview{
        "session-backup-" + fingerprint,
        backup_approval_digest(source, fingerprint, backup_format),
        {
            TrustedReviewPage{
                "Backup source",
                {
                    "Danger: secret export",
                    "Type: " + source_kind_label(source.kind),
                    "Label: " + source.label,
                    "Fingerprint: " + fingerprint,
                    "Output: " + output,
                    "Session RAM only",
                },
                ReviewPageAction::Next,
                "Page 1/2",
                {},
                "session-backup-warning",
            },
            TrustedReviewPage{
                "Show secret?",
                {
                    "Anyone can sign",
                    "Verify offline copy",
                    "Approve to reveal",
                },
                ReviewPageAction::ApproveOrReject,
                "Page 2/2",
                {},
                "session-backup-decision",
            },
        },
    };
}

SessionSourceBackupFlowResult run_session_source_backup_flow(
    const SessionKeySource& source,
    const std::vector<ReviewButton>& buttons,
    std::size_t max_button_steps) {
    if (max_button_steps == 0U) {
        throw SessionSourceBackupError("session source backup flow max button steps must be positive");
    }

    SessionSourceBackupFlowResult result;
    result.review = build_session_source_backup_review(source);
    ReviewControlSession controls(result.review.pages.size());

    std::size_t step_count = 0;
    for (const ReviewButton button : buttons) {
        if (step_count >= max_button_steps) {
            throw SessionSourceBackupError("session source backup review exceeded max button steps");
        }
        ++step_count;

        const std::size_t page_index = controls.current_page_index();
        const std::optional<bool> decision = controls.handle_button(button);
        const bool revealed = decision.has_value() && *decision;
        result.transcript.push_back(SessionSourceBackupTranscriptStep{
            page_index,
            button,
            decision,
            revealed,
        });

        if (decision.has_value()) {
            result.approved = *decision;
            result.revealed = revealed;
            if (revealed) {
                result.backup_payload = session_source_backup_payload(source);
            }
            return result;
        }
    }

    throw SessionSourceBackupError("session source backup review did not reach approval or rejection");
}

}  // namespace nsealr
