//! AUTH-004a obligation receipt verification.
//!
//! This module validates authority obligation receipts with a trusted local
//! owning-service context before matching them to a conditional authority
//! decision. Raw `AuthorityObligationReceipt` values remain behavior-free
//! contracts and cannot satisfy obligations directly. This bounded slice does not
//! implement a human approval workflow, MFA provider, gate engine, durable
//! evidence store, production PKI, or gateway invocation wiring.

use serde::Serialize;
use splendor_types::{
    AuthorityDecision, AuthorityDecisionStatus, AuthorityObligationId, AuthorityObligationReceipt,
    AuthorityObligationReceiptId, AuthorityObligationReceiptValidationKind, CapabilityRequest,
    ContentHash, PrincipalId, RevocationStatus, AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION,
};
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;

const LOCAL_RECEIPT_VALIDATION_ALGORITHM: &str = "local-obligation-receipt-v1";

/// Trusted owning-service context required to validate behavior-free receipt
/// contracts before matching them to a conditional authority decision.
///
/// The validation secret is local deterministic test material for this bounded
/// slice, not production PKI/IAM. Callers must provide this context from the
/// owning receipt service, not from the requester trying to satisfy obligations.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityObligationReceiptValidationContext {
    issuer: PrincipalId,
    audience: String,
    key_id: String,
    validation_secret: String,
    revocation_ref: String,
    now: OffsetDateTime,
}

impl AuthorityObligationReceiptValidationContext {
    /// Builds trusted local validation context for the receipt owning service.
    ///
    /// This constructor is a configuration seam for the authority-owned receipt
    /// service or a local gateway composition root. It must not be populated from
    /// requester payloads; a caller that supplies its own issuer/secret tuple is
    /// not trusted authority. Future production integrations should replace this
    /// deterministic local context with PKI/IAM-backed validation while keeping
    /// the gateway input behavior-free.
    pub fn trusted_local(
        issuer: PrincipalId,
        audience: impl Into<String>,
        key_id: impl Into<String>,
        validation_secret: impl Into<String>,
        revocation_ref: impl Into<String>,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            issuer,
            audience: audience.into(),
            key_id: key_id.into(),
            validation_secret: validation_secret.into(),
            revocation_ref: revocation_ref.into(),
            now,
        }
    }

    /// Owning-service issuer expected on receipts validated by this context.
    pub fn issuer(&self) -> &PrincipalId {
        &self.issuer
    }

    /// Audience binding expected on receipts validated by this context.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Key identifier expected on local receipt validation material.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Revocation source coordinate expected on receipts validated by this context.
    pub fn revocation_ref(&self) -> &str {
        &self.revocation_ref
    }

    /// Validation time used for expiry/not-before/revocation checks.
    pub fn now(&self) -> OffsetDateTime {
        self.now
    }

    /// Returns a copy of this context with a different validation time.
    pub fn at_time(&self, now: OffsetDateTime) -> Self {
        Self {
            now,
            ..self.clone()
        }
    }
}

impl fmt::Debug for AuthorityObligationReceiptValidationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityObligationReceiptValidationContext")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("key_id", &self.key_id)
            .field("validation_secret", &"<redacted>")
            .field("revocation_ref", &self.revocation_ref)
            .field("now", &self.now)
            .finish()
    }
}

/// Locally validated authority obligation receipt accepted by final receipt
/// matching.
///
/// Raw receipt contracts are intentionally not accepted by
/// `verify_obligation_receipts`; only this wrapper can be passed after trusted
/// owning-service validation succeeds.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedAuthorityObligationReceipt {
    receipt: AuthorityObligationReceipt,
    trust: ValidatedReceiptTrust,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValidatedReceiptTrust {
    LocalSignature,
}

impl ValidatedAuthorityObligationReceipt {
    /// Returns the underlying behavior-free receipt contract for inspection.
    pub fn receipt(&self) -> &AuthorityObligationReceipt {
        &self.receipt
    }
}

/// Result of verifying validated obligation receipts against one conditional
/// decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObligationReceiptVerification {
    /// True only when every obligation on the decision has one exact validated
    /// matching receipt and no duplicates/extras are present.
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

/// Validates a behavior-free receipt using trusted local owning-service context.
///
/// This is a deterministic local validation seam for tests and bounded AUTH-004a
/// evidence. It proves the caller cannot satisfy obligations with raw
/// self-asserted receipt fields, but it does not claim production PKI, external
/// revocation introspection, approval workflow execution, or gateway wiring.
pub fn validate_authority_obligation_receipt(
    receipt: AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> Result<ValidatedAuthorityObligationReceipt, ObligationReceiptError> {
    validate_receipt_trust_shape(&receipt, context)?;
    let expected_digest = obligation_receipt_validation_digest(&receipt)?;
    if receipt.validation.digest != expected_digest {
        return Err(validation_error(
            "obligation_receipt_validation_digest_mismatch",
        ));
    }
    let expected_signature = local_obligation_receipt_signature(&receipt, context)?;
    if receipt.validation.signature != expected_signature {
        return Err(validation_error("obligation_receipt_signature_mismatch"));
    }

    Ok(ValidatedAuthorityObligationReceipt {
        receipt,
        trust: ValidatedReceiptTrust::LocalSignature,
    })
}

/// Adds deterministic local validation material to a raw receipt contract.
///
/// This helper models the authority-owned receipt service issuing local evidence
/// after an obligation has been satisfied. It is intentionally a bounded local
/// seam for tests and embedded gateway configuration; it is not production PKI,
/// does not perform an approval/MFA/gate workflow, and must not be called with a
/// context derived from requester payloads.
pub fn issue_local_authority_obligation_receipt(
    mut receipt: AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> Result<AuthorityObligationReceipt, ObligationReceiptError> {
    receipt.validation.digest = obligation_receipt_validation_digest(&receipt)?;
    receipt.validation.signature = local_obligation_receipt_signature(&receipt, context)?;
    Ok(receipt)
}

/// Verifies that validated receipts satisfy every obligation carried by a
/// conditional decision. Any uncertainty fails closed with stable reason codes.
pub fn verify_obligation_receipts(
    decision: &AuthorityDecision,
    receipts: &[ValidatedAuthorityObligationReceipt],
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

    let mut reasons = Vec::new();
    reject_duplicate_decision_obligations(decision, &mut reasons);

    let expected_request_digest = match canonical_authority_request_digest(&decision.request) {
        Ok(digest) => digest,
        Err(error) => {
            return ObligationReceiptVerification::deny(vec![error.reason_code()], Vec::new());
        }
    };

    let raw_receipts = receipts
        .iter()
        .map(ValidatedAuthorityObligationReceipt::receipt)
        .collect::<Vec<_>>();
    reject_duplicate_and_extra_receipts(decision, &raw_receipts, &mut reasons);

    let mut satisfied = Vec::new();
    for obligation in &decision.obligations {
        let matching = raw_receipts
            .iter()
            .filter(|receipt| receipt.obligation_id == obligation.obligation_id)
            .copied()
            .collect::<Vec<_>>();
        let Some(receipt) = matching.first().copied() else {
            push_unique(
                &mut reasons,
                if raw_receipts.is_empty() {
                    "missing_obligation_receipt"
                } else {
                    "obligation_receipt_id_mismatch"
                },
            );
            continue;
        };

        let mut receipt_reasons = Vec::new();
        validate_receipt_against_decision(
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

    if reasons.is_empty()
        && satisfied.len() == decision.obligations.len()
        && raw_receipts.len() == decision.obligations.len()
    {
        ObligationReceiptVerification::allow(satisfied)
    } else {
        ObligationReceiptVerification::deny(reasons, satisfied)
    }
}

fn validate_receipt_trust_shape(
    receipt: &AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> Result<(), ObligationReceiptError> {
    if receipt.schema_version != AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION {
        return Err(validation_error("obligation_receipt_schema_unsupported"));
    }
    if receipt.receipt_id.is_nil() {
        return Err(validation_error("obligation_receipt_id_invalid"));
    }
    if receipt.issuer.is_nil() {
        return Err(validation_error("obligation_receipt_issuer_invalid"));
    }
    if receipt.issuer != context.issuer {
        return Err(validation_error("obligation_receipt_issuer_mismatch"));
    }
    validate_token("obligation_receipt.audience", &receipt.audience)?;
    validate_token("obligation_receipt_context.audience", &context.audience)?;
    if receipt.audience != context.audience {
        return Err(validation_error("obligation_receipt_audience_mismatch"));
    }
    if receipt.obligation_id.is_nil() {
        return Err(validation_error("obligation_receipt_obligation_id_invalid"));
    }
    if receipt.subject.is_nil() {
        return Err(validation_error("obligation_receipt_subject_invalid"));
    }
    if receipt.authority_decision_id.is_nil() {
        return Err(validation_error("obligation_receipt_decision_id_invalid"));
    }
    validate_supported_digest(
        "obligation_receipt_request_digest_malformed",
        &receipt.canonical_request_digest,
    )?;
    validate_supported_digest(
        "obligation_receipt_evidence_digest_malformed",
        &receipt.evidence_digest,
    )?;
    if receipt
        .evidence_ref
        .as_deref()
        .is_some_and(|value| !is_safe_reference(value))
    {
        return Err(validation_error(
            "obligation_receipt_evidence_ref_malformed",
        ));
    }
    validate_token("obligation_receipt.revocation_ref", &receipt.revocation_ref)?;
    validate_token(
        "obligation_receipt_context.revocation_ref",
        &context.revocation_ref,
    )?;
    if receipt.revocation_ref != context.revocation_ref {
        return Err(validation_error(
            "obligation_receipt_revocation_ref_mismatch",
        ));
    }
    if context.now < receipt.issued_at {
        return Err(validation_error("obligation_receipt_not_yet_valid"));
    }
    if context.now >= receipt.expires_at {
        return Err(validation_error("obligation_receipt_expired"));
    }
    if matches!(receipt.revocation, RevocationStatus::Revoked { .. }) {
        return Err(validation_error("obligation_receipt_revoked"));
    }
    if receipt.validation.validation_kind
        != AuthorityObligationReceiptValidationKind::LocalSignature
    {
        return Err(validation_error(
            "obligation_receipt_validation_kind_unsupported",
        ));
    }
    if receipt.validation.algorithm != LOCAL_RECEIPT_VALIDATION_ALGORITHM {
        return Err(validation_error("obligation_receipt_algorithm_mismatch"));
    }
    validate_token(
        "obligation_receipt.validation.key_id",
        &receipt.validation.key_id,
    )?;
    validate_token("obligation_receipt_context.key_id", &context.key_id)?;
    if receipt.validation.key_id != context.key_id {
        return Err(validation_error("obligation_receipt_key_mismatch"));
    }
    validate_supported_digest(
        "obligation_receipt_validation_digest_malformed",
        &receipt.validation.digest,
    )?;
    validate_supported_digest(
        "obligation_receipt_signature_malformed",
        &receipt.validation.signature,
    )?;
    if context.validation_secret.trim().is_empty() || context.validation_secret.contains('*') {
        return Err(validation_error(
            "obligation_receipt_validation_secret_unavailable",
        ));
    }
    Ok(())
}

fn reject_duplicate_decision_obligations(decision: &AuthorityDecision, reasons: &mut Vec<String>) {
    for (index, obligation) in decision.obligations.iter().enumerate() {
        if decision
            .obligations
            .iter()
            .skip(index + 1)
            .any(|candidate| candidate.obligation_id == obligation.obligation_id)
        {
            push_unique(reasons, "duplicate_authority_obligation_id");
        }
    }
}

fn reject_duplicate_and_extra_receipts(
    decision: &AuthorityDecision,
    receipts: &[&AuthorityObligationReceipt],
    reasons: &mut Vec<String>,
) {
    for (index, receipt) in receipts.iter().enumerate() {
        if receipts
            .iter()
            .skip(index + 1)
            .any(|candidate| candidate.receipt_id == receipt.receipt_id)
        {
            push_unique(reasons, "duplicate_obligation_receipt_id");
        }
        if receipts
            .iter()
            .skip(index + 1)
            .any(|candidate| candidate.obligation_id == receipt.obligation_id)
        {
            push_unique(reasons, "duplicate_obligation_receipt_obligation_id");
        }
        if !decision
            .obligations
            .iter()
            .any(|obligation| obligation.obligation_id == receipt.obligation_id)
        {
            push_unique(reasons, "extra_obligation_receipt");
        }
    }
}

fn validate_receipt_against_decision(
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
    if !decision
        .request
        .scope
        .audiences
        .as_ref()
        .is_some_and(|audiences| {
            audiences
                .iter()
                .any(|audience| audience == &receipt.audience)
        })
    {
        push_unique(reasons, "obligation_receipt_audience_mismatch");
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

fn local_obligation_receipt_signature(
    receipt: &AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> Result<String, ObligationReceiptError> {
    let payload_digest = obligation_receipt_validation_digest(receipt)?;
    let signature_material = format!(
        "{}:{}:{}:{}",
        LOCAL_RECEIPT_VALIDATION_ALGORITHM,
        context.key_id,
        context.validation_secret,
        payload_digest
    );
    Ok(ContentHash::blake3(signature_material.as_bytes()).to_string())
}

fn obligation_receipt_validation_digest(
    receipt: &AuthorityObligationReceipt,
) -> Result<String, ObligationReceiptError> {
    let payload = ReceiptValidationPayload {
        schema_version: &receipt.schema_version,
        receipt_id: &receipt.receipt_id,
        issuer: &receipt.issuer,
        audience: &receipt.audience,
        obligation_id: &receipt.obligation_id,
        kind: receipt.kind,
        subject: &receipt.subject,
        authority_decision_id: &receipt.authority_decision_id,
        canonical_request_digest: &receipt.canonical_request_digest,
        evidence_digest: &receipt.evidence_digest,
        evidence_ref: receipt.evidence_ref.as_deref(),
        issued_at: receipt.issued_at,
        expires_at: receipt.expires_at,
        revocation: &receipt.revocation,
        revocation_ref: &receipt.revocation_ref,
        approval_id: receipt.approval_id.as_ref(),
        approval_trace_event_id: receipt.approval_trace_event_id.as_ref(),
    };
    let bytes = serde_json::to_vec(&payload).map_err(|error| {
        ObligationReceiptError::ReceiptValidationDigestUnavailable {
            reason: error.to_string(),
        }
    })?;
    Ok(ContentHash::blake3(bytes).to_string())
}

#[derive(Serialize)]
struct ReceiptValidationPayload<'a> {
    schema_version: &'a str,
    receipt_id: &'a AuthorityObligationReceiptId,
    issuer: &'a PrincipalId,
    audience: &'a str,
    obligation_id: &'a AuthorityObligationId,
    kind: splendor_types::AuthorityObligationKind,
    subject: &'a PrincipalId,
    authority_decision_id: &'a splendor_types::AuthorityDecisionId,
    canonical_request_digest: &'a str,
    evidence_digest: &'a str,
    evidence_ref: Option<&'a str>,
    #[serde(with = "time::serde::rfc3339")]
    issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    revocation: &'a RevocationStatus,
    revocation_ref: &'a str,
    approval_id: Option<&'a splendor_types::ApprovalId>,
    approval_trace_event_id: Option<&'a splendor_types::TraceEventId>,
}

fn validate_supported_digest(
    reason: &'static str,
    value: &str,
) -> Result<(), ObligationReceiptError> {
    if is_supported_digest(value) {
        Ok(())
    } else {
        Err(validation_error(reason))
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

fn validate_token(_field: &'static str, value: &str) -> Result<(), ObligationReceiptError> {
    if value.trim().is_empty() || value.trim() != value || value.contains('*') {
        return Err(validation_error("obligation_receipt_token_malformed"));
    }
    Ok(())
}

fn is_safe_reference(value: &str) -> bool {
    !value.trim().is_empty() && value.trim() == value && !value.contains('*')
}

fn validation_error(reason: &'static str) -> ObligationReceiptError {
    ObligationReceiptError::ReceiptValidationFailed { reason }
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

/// Errors while preparing or validating deterministic obligation receipt
/// evidence.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ObligationReceiptError {
    /// Authority request serialization failed before hashing.
    #[error("authority request digest unavailable: {reason}")]
    RequestDigestUnavailable {
        /// Stable error detail for debugging without request bytes.
        reason: String,
    },
    /// Receipt canonical validation digest could not be prepared.
    #[error("obligation receipt validation digest unavailable: {reason}")]
    ReceiptValidationDigestUnavailable {
        /// Stable error detail for debugging without receipt bytes.
        reason: String,
    },
    /// Receipt validation failed closed with a stable reason.
    #[error("obligation receipt validation failed: {reason}")]
    ReceiptValidationFailed {
        /// Stable reason code.
        reason: &'static str,
    },
}

impl ObligationReceiptError {
    /// Stable reason code for fail-closed decisions and tests.
    pub fn reason_code(&self) -> String {
        match self {
            Self::RequestDigestUnavailable { .. } => "request_digest_unavailable".to_string(),
            Self::ReceiptValidationDigestUnavailable { .. } => {
                "obligation_receipt_validation_digest_unavailable".to_string()
            }
            Self::ReceiptValidationFailed { reason } => (*reason).to_string(),
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/obligation_tests.rs"]
mod tests;
