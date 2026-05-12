#pragma once

#include <string>
#include <vector>

namespace nsealr {

struct SigningReadiness {
    bool runtime_signing_feature_enabled = false;
    bool parser_limits_enforced = false;
    bool trusted_review_display_accepted = false;
    bool physical_approval_controls_accepted = false;
    bool approval_digest_binding_verified = false;
    bool unicode_review_rendering_accepted = false;
    bool key_provisioning_ready = false;
    bool secure_boot_enabled = false;
    bool flash_encryption_enabled = false;
    bool debug_locked = false;
    bool companion_signed_output_verification_ready = false;
    std::vector<std::string> development_accepted_gates;
};

struct SigningReadinessStatus {
    bool signing_enabled = false;
    std::vector<std::string> missing_gates;
    std::vector<std::string> development_accepted_gates;
};

SigningReadinessStatus evaluate_signing_readiness(const SigningReadiness& readiness);

}  // namespace nsealr
