#pragma once

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "nsealr/review_display.hpp"
#include "nsealr/review_controls.hpp"
#include "nsealr/session_keyring.hpp"
#include "nsealr/trusted_review.hpp"

namespace nsealr {

class SessionSourceBackupError final : public std::runtime_error {
public:
    explicit SessionSourceBackupError(const std::string& message) : std::runtime_error(message) {}
};

struct SessionSourceBackupPayload {
    std::string backup_format;
    std::string mnemonic;
    std::string standard_seedqr_digits;
    std::string compact_seedqr_hex;
    std::string nsec;
};

struct SessionSourceBackupReview {
    std::string review_id;
    std::string approval_digest;
    std::vector<TrustedReviewPage> pages;
};

struct SessionSourceBackupTranscriptStep {
    std::size_t page_index = 0;
    ReviewButton button = ReviewButton::Next;
    std::optional<bool> decision;
    bool revealed = false;
};

struct SessionSourceBackupFlowResult {
    SessionSourceBackupReview review;
    bool approved = false;
    bool revealed = false;
    std::optional<SessionSourceBackupPayload> backup_payload;
    std::vector<SessionSourceBackupTranscriptStep> transcript;
};

class SessionSourceBackupIo {
public:
    virtual ~SessionSourceBackupIo() = default;

    virtual void show_backup_review_frame(const ReviewDisplayFrame& frame) = 0;
    virtual ReviewButton read_backup_review_button() = 0;
    virtual void emit_backup_payload(const SessionSourceBackupPayload& payload) = 0;
};

[[nodiscard]] SessionSourceBackupPayload session_source_backup_payload(const SessionKeySource& source);
[[nodiscard]] SessionSourceBackupReview build_session_source_backup_review(const SessionKeySource& source);
[[nodiscard]] SessionSourceBackupFlowResult run_session_source_backup_flow(
    const SessionKeySource& source,
    const std::vector<ReviewButton>& buttons,
    std::size_t max_button_steps = 32U);
[[nodiscard]] SessionSourceBackupFlowResult run_session_source_backup_io_flow(
    const SessionKeySource& source,
    SessionSourceBackupIo& io,
    ReviewDisplayLimits limits = {},
    std::size_t max_button_steps = 32U);

}  // namespace nsealr
