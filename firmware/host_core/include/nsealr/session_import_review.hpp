#pragma once

#include <string>
#include <vector>

#include "nsealr/session_keyring.hpp"
#include "nsealr/trusted_review.hpp"

namespace nsealr {

struct SessionImportReview {
    std::string review_id;
    std::string approval_digest;
    std::vector<TrustedReviewPage> pages;
};

[[nodiscard]] std::string session_key_source_fingerprint(const SessionKeySource& source);
[[nodiscard]] SessionImportReview build_session_import_review(const SessionKeySource& source);

}  // namespace nsealr
