#include "nostrseal/signing_policy.hpp"

namespace nostrseal {

SigningReadinessStatus evaluate_signing_readiness(const SigningReadiness& readiness) {
    SigningReadinessStatus status;
    status.development_accepted_gates = readiness.development_accepted_gates;
    if (!readiness.runtime_signing_feature_enabled) {
        status.missing_gates.push_back("runtime_signing_feature");
    }
    if (!readiness.parser_limits_enforced) {
        status.missing_gates.push_back("parser_limits");
    }
    if (!readiness.trusted_review_display_accepted) {
        status.missing_gates.push_back("trusted_review_display");
    }
    if (!readiness.physical_approval_controls_accepted) {
        status.missing_gates.push_back("physical_approval_controls");
    }
    if (!readiness.approval_digest_binding_verified) {
        status.missing_gates.push_back("approval_digest_binding");
    }
    if (!readiness.unicode_review_rendering_accepted) {
        status.missing_gates.push_back("unicode_review_rendering");
    }
    if (!readiness.key_provisioning_ready) {
        status.missing_gates.push_back("key_provisioning");
    }
    if (!readiness.secure_boot_enabled) {
        status.missing_gates.push_back("secure_boot");
    }
    if (!readiness.flash_encryption_enabled) {
        status.missing_gates.push_back("flash_encryption");
    }
    if (!readiness.debug_locked) {
        status.missing_gates.push_back("debug_lock");
    }
    if (!readiness.companion_signed_output_verification_ready) {
        status.missing_gates.push_back("companion_signed_output_verification");
    }
    status.signing_enabled = status.missing_gates.empty();
    return status;
}

}  // namespace nostrseal
