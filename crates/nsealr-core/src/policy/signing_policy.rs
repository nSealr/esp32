//! Signing readiness policy — every runtime gate before enablement.
//!
//! Ported from the C++ reference `host_core` sources `src/signing_policy.cpp` +
//! `include/nsealr/signing_policy.hpp` for behaviour parity. Signing is enabled
//! only when **every** runtime gate is satisfied; the status names each missing
//! gate in the fixed C++ evaluation order and echoes the (deduplicated)
//! development-accepted gate list so a UI can flag gates that were accepted in a
//! development build rather than truly verified.
//!
//! The C++ used `std::vector<std::string>` for the gate-name lists; this
//! allocation-free port stores them in the fixed-capacity [`SigningGateNames`]
//! list (one slot per runtime gate).

use crate::text::{FixedStr, TextError};

/// Maximum byte length of a signing gate name. The longest fixed gate name is
/// `"companion_signed_output_verification"` (36 bytes).
pub const MAX_SIGNING_GATE_NAME_CHARS: usize = 40;

/// The number of runtime signing gates — one list slot per gate.
pub const SIGNING_GATE_COUNT: usize = 12;

/// One signing gate name as bounded inline text.
pub type SigningGateName = FixedStr<MAX_SIGNING_GATE_NAME_CHARS>;

/// A fixed-capacity list of signing gate names — the allocation-free stand-in
/// for the C++ `std::vector<std::string>` gate lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningGateNames {
    names: [SigningGateName; SIGNING_GATE_COUNT],
    len: usize,
}

impl SigningGateNames {
    /// Creates an empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            names: [const { SigningGateName::new() }; SIGNING_GATE_COUNT],
            len: 0,
        }
    }

    /// Appends one gate name.
    ///
    /// # Errors
    ///
    /// [`TextError::TooLong`] if the list already holds [`SIGNING_GATE_COUNT`]
    /// names or the name exceeds [`MAX_SIGNING_GATE_NAME_CHARS`] bytes.
    pub fn try_push(&mut self, name: &str) -> Result<(), TextError> {
        if self.len >= SIGNING_GATE_COUNT {
            return Err(TextError::TooLong);
        }
        self.names[self.len] = name.parse()?;
        self.len += 1;
        Ok(())
    }

    /// Returns the active names as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[SigningGateName] {
        &self.names[..self.len]
    }

    /// Returns the number of names held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the list holds no names.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if the list already contains `name`.
    #[must_use]
    fn contains(&self, name: &str) -> bool {
        self.as_slice().iter().any(|held| held == &name)
    }
}

impl Default for SigningGateNames {
    fn default() -> Self {
        Self::new()
    }
}

/// The runtime signing gates as reported by the device. Mirrors the C++
/// `SigningReadiness` field for field; every flag defaults to `false` (signing
/// stays disabled until each gate is explicitly satisfied).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SigningReadiness {
    /// The runtime signing feature flag itself is enabled.
    pub runtime_signing_feature_enabled: bool,
    /// Parser limits are enforced on every inbound payload.
    pub parser_limits_enforced: bool,
    /// The trusted review display was accepted.
    pub trusted_review_display_accepted: bool,
    /// The physical approval controls were accepted.
    pub physical_approval_controls_accepted: bool,
    /// Approval-digest binding was verified.
    pub approval_digest_binding_verified: bool,
    /// Unicode review rendering was accepted.
    pub unicode_review_rendering_accepted: bool,
    /// Key provisioning is ready.
    pub key_provisioning_ready: bool,
    /// The source public-key proof is ready.
    pub source_public_key_proof_ready: bool,
    /// Secure boot is enabled.
    pub secure_boot_enabled: bool,
    /// Flash encryption is enabled.
    pub flash_encryption_enabled: bool,
    /// Debug access is locked.
    pub debug_locked: bool,
    /// Companion signed-output verification is ready.
    pub companion_signed_output_verification_ready: bool,
    /// Gates that were accepted in a development build rather than verified.
    pub development_accepted_gates: SigningGateNames,
}

/// The evaluated signing readiness status. Mirrors the C++
/// `SigningReadinessStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningReadinessStatus {
    /// `true` only when [`Self::missing_gates`] is empty.
    pub signing_enabled: bool,
    /// Every unsatisfied gate, in the fixed C++ evaluation order.
    pub missing_gates: SigningGateNames,
    /// The deduplicated development-accepted gate list (first occurrence wins).
    pub development_accepted_gates: SigningGateNames,
}

/// Evaluates the signing readiness gates: signing is enabled only when every
/// runtime gate is satisfied. Mirrors the C++ `evaluate_signing_readiness`.
#[must_use]
pub fn evaluate_signing_readiness(readiness: &SigningReadiness) -> SigningReadinessStatus {
    // The (gate satisfied?, gate name) pairs in the exact C++ evaluation order.
    let gates = [
        (
            readiness.runtime_signing_feature_enabled,
            "runtime_signing_feature",
        ),
        (readiness.parser_limits_enforced, "parser_limits"),
        (
            readiness.trusted_review_display_accepted,
            "trusted_review_display",
        ),
        (
            readiness.physical_approval_controls_accepted,
            "physical_approval_controls",
        ),
        (
            readiness.approval_digest_binding_verified,
            "approval_digest_binding",
        ),
        (
            readiness.unicode_review_rendering_accepted,
            "unicode_review_rendering",
        ),
        (readiness.key_provisioning_ready, "key_provisioning"),
        (
            readiness.source_public_key_proof_ready,
            "source_public_key_proof",
        ),
        (readiness.secure_boot_enabled, "secure_boot"),
        (readiness.flash_encryption_enabled, "flash_encryption"),
        (readiness.debug_locked, "debug_lock"),
        (
            readiness.companion_signed_output_verification_ready,
            "companion_signed_output_verification",
        ),
    ];
    let mut missing_gates = SigningGateNames::new();
    for (satisfied, name) in gates {
        if !satisfied {
            missing_gates
                .try_push(name)
                .expect("one list slot per fixed gate");
        }
    }

    // Order-preserving dedup (the C++ `unique_gates`): dropping entries never
    // grows the list, so pushes stay within the input list's capacity.
    let mut development_accepted_gates = SigningGateNames::new();
    for gate in readiness.development_accepted_gates.as_slice() {
        if !development_accepted_gates.contains(gate.as_str()) {
            development_accepted_gates
                .try_push(gate.as_str())
                .expect("dedup never grows the list");
        }
    }

    SigningReadinessStatus {
        signing_enabled: missing_gates.is_empty(),
        missing_gates,
        development_accepted_gates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// Renders the held names as plain strings for whole-list assertions (the
    /// Rust analogue of the C++ `std::vector<std::string>` comparisons).
    fn as_strs(names: &SigningGateNames) -> Vec<&str> {
        names.as_slice().iter().map(FixedStr::as_str).collect()
    }

    // Port of the C++
    // `test_signing_policy_requires_every_runtime_gate_before_enablement`.
    #[test]
    fn requires_every_runtime_gate_before_enablement() {
        let default_readiness = SigningReadiness::default();
        let default_status = evaluate_signing_readiness(&default_readiness);

        assert!(!default_status.signing_enabled);
        assert!(default_status.development_accepted_gates.is_empty());
        assert_eq!(
            as_strs(&default_status.missing_gates),
            [
                "runtime_signing_feature",
                "parser_limits",
                "trusted_review_display",
                "physical_approval_controls",
                "approval_digest_binding",
                "unicode_review_rendering",
                "key_provisioning",
                "source_public_key_proof",
                "secure_boot",
                "flash_encryption",
                "debug_lock",
                "companion_signed_output_verification",
            ],
        );

        let mut development_accepted_gates = SigningGateNames::new();
        for gate in [
            "parser_limits",
            "trusted_review_display",
            "physical_approval_controls",
            "approval_digest_binding",
        ] {
            development_accepted_gates.try_push(gate).unwrap();
        }
        let mut safety_gates = SigningReadiness {
            runtime_signing_feature_enabled: false,
            parser_limits_enforced: true,
            trusted_review_display_accepted: true,
            physical_approval_controls_accepted: true,
            approval_digest_binding_verified: true,
            unicode_review_rendering_accepted: true,
            key_provisioning_ready: true,
            source_public_key_proof_ready: true,
            secure_boot_enabled: true,
            flash_encryption_enabled: true,
            debug_locked: true,
            companion_signed_output_verification_ready: true,
            development_accepted_gates,
        };
        let safety_status = evaluate_signing_readiness(&safety_gates);

        assert!(!safety_status.signing_enabled);
        assert_eq!(
            as_strs(&safety_status.missing_gates),
            ["runtime_signing_feature"],
        );
        assert_eq!(
            as_strs(&safety_status.development_accepted_gates),
            [
                "parser_limits",
                "trusted_review_display",
                "physical_approval_controls",
                "approval_digest_binding",
            ],
        );

        safety_gates.runtime_signing_feature_enabled = true;
        let ready_status = evaluate_signing_readiness(&safety_gates);

        assert!(ready_status.signing_enabled);
        assert!(ready_status.missing_gates.is_empty());
        assert_eq!(
            ready_status.development_accepted_gates,
            safety_status.development_accepted_gates,
        );

        safety_gates
            .development_accepted_gates
            .try_push("parser_limits")
            .unwrap();
        let duplicate_gate_status = evaluate_signing_readiness(&safety_gates);

        assert_eq!(
            duplicate_gate_status.development_accepted_gates,
            safety_status.development_accepted_gates,
        );
    }

    // Container plumbing for the fixed-capacity gate-name list (no single named
    // C++ case: the C++ used std::vector directly).
    #[test]
    fn gate_name_list_pushes_and_rejects_overflow() {
        let mut names = SigningGateNames::new();
        assert!(names.is_empty());
        assert_eq!(names.len(), 0);
        assert_eq!(names, SigningGateNames::default());

        let too_long = core::str::from_utf8(&[b'g'; MAX_SIGNING_GATE_NAME_CHARS + 1]).unwrap();
        assert_eq!(names.try_push(too_long), Err(TextError::TooLong));
        assert!(names.is_empty());

        for index in 0..SIGNING_GATE_COUNT {
            let mut name = SigningGateName::new();
            name.try_push_str("gate-").unwrap();
            name.try_push_usize(index).unwrap();
            names.try_push(name.as_str()).unwrap();
        }
        assert_eq!(names.len(), SIGNING_GATE_COUNT);
        assert!(!names.is_empty());
        assert_eq!(names.as_slice()[0], "gate-0");
        assert_eq!(names.clone(), names);
        assert_eq!(names.try_push("overflow"), Err(TextError::TooLong));
        assert_eq!(names.len(), SIGNING_GATE_COUNT);
    }
}
