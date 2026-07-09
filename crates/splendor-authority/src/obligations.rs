//! AUTH-004a obligation receipt verification.
//!
//! This module verifies that typed obligation receipts exactly match a
//! conditional authority decision before a future gateway/driver path treats that
//! decision as executable. It does not implement a human approval workflow, MFA
//! provider, gate engine, durable evidence store, or gateway invocation wiring.

use splendor_types::{
    AuthorityDecision, AuthorityDecisionStatus, AuthorityObligationId, AuthorityObligationReceipt,
    CapabilityRequest, ContentHash, RevocationStatus, AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION,
};
use thiserror::Error;
use time::OffsetDateTime;

/// Result of verifying obligation receipts against one conditional decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObligationReceiptVerification {
    /// True only when every obligation on the decision has one matching receipt.
    pub allowed: bool,
    /// Stable reason codes. Empty when `allowed` is true.
    pub reasons: Vec<String>,
    /// Obligation IDs satisfied by exact matching receipts.
    pub satisfied_obligation_ids: Vec<AuthorityObligationId>,
}

impl ObligationReceiptVerification {
    fn allow(satisfied_obligation_ids: Vec<AuthorityObligationId>) -> Self {
        Self {
            allowed: true,
            reasons: Vec::new(),
            satisfied_obligation_ids,
        }
    }

    fn deny(reasons: Vec<String>, satisfied_obligation_ids: Vec<AuthorityObligationId>) -> Self {
        Self {
            allowed: false,
            reasons,
            satisfied_obligation_ids,
        }
    }
}

/// Computes the deterministic digest receipts must bind to for this exact
/// authority request. Callers must keep secrets out of `CapabilityRequest`
/// metadata; the helper emits only a content hash and never returns serialized
/// request bytes.
pub fn canonical_authority_request_digest(
    request: &CapabilityRequest,
) -> Result<String, ObligationReceiptError> {
    let bytes = serde_json::to_vec(request).map_err(|error| {
        ObligationReceiptError::RequestDigestUnavailable {
            reason: error.to_string(),
        }
    })?;
    Ok(ContentHash::blake3(bytes).to_string())
}

/// Verifies that receipts satisfy every obligation carried by a conditional
/// authority decision. Any uncertainty fails closed with stable reason codes.
pub fn verify_obligation_receipts(
    decision: &AuthorityDecision,
    receipts: &[AuthorityObligationReceipt],
    now: OffsetDateTime,
) -> ObligationReceiptVerification {
    if decision.status != AuthorityDecisionStatus::Conditional {
        return ObligationReceiptVerification::deny(
            vec!["decision_not_conditional".to_string()],
            Vec::new(),
        );
    }
    if decision.obligations.is_empty() {
        return ObligationReceiptVerification::deny(
            vec!["conditional_decision_missing_obligations".to_string()],
            Vec::new(),
        );
    }

    let expected_request_digest = match canonical_authority_request_digest(&decision.request) {
        Ok(digest) => digest,
        Err(error) => {
            return ObligationReceiptVerification::deny(vec![error.reason_code()], Vec::new());
        }
    };

    let mut reasons = Vec::new();
    let mut satisfied = Vec::new();
    for obligation in &decision.obligations {
        let Some(receipt) = receipts
            .iter()
            .find(|receipt| receipt.obligation_id == obligation.obligation_id)
        else {
            push_unique(
                &mut reasons,
                if receipts.is_empty() {
                    "missing_obligation_receipt"
                } else {
                    "obligation_receipt_id_mismatch"
                },
            );
            continue;
        };

        let mut receipt_reasons = Vec::new();
        validate_receipt(
            receipt,
            decision,
            &expected_request_digest,
            now,
            &mut receipt_reasons,
        );
        if receipt.kind != obligation.kind {
            push_unique(&mut receipt_reasons, "obligation_receipt_kind_mismatch");
        }
        if receipt_reasons.is_empty() {
            satisfied.push(obligation.obligation_id.clone());
        } else {
            for reason in receipt_reasons {
                push_unique_string(&mut reasons, reason);
            }
        }
    }

    if reasons.is_empty() {
        ObligationReceiptVerification::allow(satisfied)
    } else {
        ObligationReceiptVerification::deny(reasons, satisfied)
    }
}

fn validate_receipt(
    receipt: &AuthorityObligationReceipt,
    decision: &AuthorityDecision,
    expected_request_digest: &str,
    now: OffsetDateTime,
    reasons: &mut Vec<String>,
) {
    if receipt.schema_version != AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION {
        push_unique(reasons, "obligation_receipt_schema_unsupported");
    }
    if receipt.subject != decision.request.subject {
        push_unique(reasons, "obligation_receipt_subject_mismatch");
    }
    if receipt.authority_decision_id != decision.decision_id {
        push_unique(reasons, "obligation_receipt_decision_mismatch");
    }
    if !is_supported_digest(&receipt.canonical_request_digest) {
        push_unique(reasons, "obligation_receipt_request_digest_malformed");
    } else if receipt.canonical_request_digest != expected_request_digest {
        push_unique(reasons, "obligation_receipt_request_digest_mismatch");
    }
    if !is_supported_digest(&receipt.evidence_digest) {
        push_unique(reasons, "obligation_receipt_evidence_digest_malformed");
    }
    if receipt
        .evidence_ref
        .as_deref()
        .is_some_and(|value| !is_safe_reference(value))
    {
        push_unique(reasons, "obligation_receipt_evidence_ref_malformed");
    }
    if now < receipt.issued_at {
        push_unique(reasons, "obligation_receipt_not_yet_valid");
    }
    if now >= receipt.expires_at {
        push_unique(reasons, "obligation_receipt_expired");
    }
    if matches!(receipt.revocation, RevocationStatus::Revoked { .. }) {
        push_unique(reasons, "obligation_receipt_revoked");
    }
}

fn is_supported_digest(value: &str) -> bool {
    if value.trim() != value || value.contains('*') {
        return false;
    }
    let Some((algorithm, digest)) = value.split_once(':') else {
        return false;
    };
    matches!(algorithm, "blake3" | "sha256")
        && digest.len() == 64
        && digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn is_safe_reference(value: &str) -> bool {
    !value.trim().is_empty() && value.trim() == value && !value.contains('*')
}

fn push_unique(reasons: &mut Vec<String>, reason: &'static str) {
    if !reasons.iter().any(|existing| existing == reason) {
        reasons.push(reason.to_string());
    }
}

fn push_unique_string(reasons: &mut Vec<String>, reason: String) {
    if !reasons.iter().any(|existing| existing == &reason) {
        reasons.push(reason);
    }
}

/// Errors while preparing deterministic obligation receipt evidence.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ObligationReceiptError {
    /// Authority request serialization failed before hashing.
    #[error("authority request digest unavailable: {reason}")]
    RequestDigestUnavailable {
        /// Stable error detail for debugging without request bytes.
        reason: String,
    },
}

impl ObligationReceiptError {
    /// Stable reason code for fail-closed decisions and tests.
    pub fn reason_code(&self) -> String {
        match self {
            Self::RequestDigestUnavailable { .. } => "request_digest_unavailable".to_string(),
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/obligation_tests.rs"]
mod tests;
