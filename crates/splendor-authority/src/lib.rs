//! # Splendor Authority
//!
//! Authority-plane decision logic. This local evidence surface currently covers
//! the Principal Registry lifecycle state machine from IDR-001 plus bounded
//! AUTH-001 capability grammar/evaluator, AUTH-002a work-order grant issuance,
//! AUTH-003 delegation, AUTH-004 obligation receipt, and AUTH-005 local
//! revocation/offline-cache plus bounded renewal preflight slices. AUTH-006a adds
//! local redacted decision evidence and inspect-only comparison. It does not
//! replace daemon authentication, durable evidence/replay services, gateway
//! verification, revocation-watch services, production lease renewal, or adapter
//! execution.

mod capability;
mod delegation;
mod evidence;
mod identity;
mod issuance;
mod obligations;
mod renewal;
mod revocation;

pub use capability::{
    compatibility_permission_operation, ensure_child_grant_narrows, evaluate_capability_request,
    gateway_action_operation, gateway_adapter_operation, grant_from_delegated_authority,
    grant_from_legacy_allowlists, grant_from_work_order, intersect_capability_scopes,
    workload_admit_operation, AuthorityEvaluationError, CompatibilityGrantContext,
    LegacyScopeProfile, ValidatedCapabilityGrant,
};
pub use delegation::{
    issue_delegation_child_grant, DelegationChildGrant, DelegationChildGrantRequest,
    DelegationGrantError, DelegationValidationContext,
};
pub use evidence::{
    authority_decision_evidence, authority_reason_category, compare_authority_evidence,
    evaluate_cached_capability_request_with_evidence, evaluate_capability_request_with_evidence,
    AuthorityCacheEntryEvidence, AuthorityCachedEvaluationEvidence, AuthorityConnectivityEvidence,
    AuthorityDecisionEvidence, AuthorityDecisionExplanation, AuthorityDecisionWithEvidence,
    AuthorityEvidenceComparison, AuthorityEvidenceComparisonLabel, AuthorityEvidenceCompleteness,
    AuthorityEvidenceError, AuthorityEvidenceMissingFact, AuthorityEvidenceWithheldField,
    AuthorityExplanationBranch, AuthorityExplanationCategory, AuthorityFreshnessStatus,
    AuthorityGrantEvidence, AuthorityObligationEvidence, AuthorityRevocationSnapshotEvidence,
    RedactedAuthorityDecisionEvidence, RedactedAuthorityOperation,
    AUTHORITY_DECISION_EVIDENCE_SCHEMA_VERSION,
};
pub use identity::{IdentityMutation, IdentityRegistry, IdentityRegistryError, RegisterPrincipal};
pub use issuance::{
    issue_work_order_capability_grant, WorkOrderGrantIssuance, WorkOrderGrantIssuanceError,
    WorkOrderGrantIssuanceResult,
};
pub use obligations::{
    canonical_authority_request_digest, issue_local_authority_obligation_receipt,
    validate_authority_obligation_receipt, verify_obligation_receipts,
    AuthorityObligationReceiptValidationContext, ObligationReceiptError,
    ObligationReceiptVerification, ValidatedAuthorityObligationReceipt,
};
pub use renewal::{
    renew_cached_authority_grant, AuthorityGrantRenewalContextError, AuthorityGrantRenewalPolicy,
    AuthorityGrantRenewalPolicyError, AuthorityGrantRenewalRequest, AuthorityGrantRenewalResult,
    AuthorityGrantRenewalStatus, TrustedAuthorityRenewalContext,
    REASON_AUTHORITY_RENEWAL_AUDIENCE_CHANGED, REASON_AUTHORITY_RENEWAL_CACHE_OUTLIVES_GRANT,
    REASON_AUTHORITY_RENEWAL_CACHE_WINDOW_INVALID,
    REASON_AUTHORITY_RENEWAL_CURRENT_REVISION_MISMATCH,
    REASON_AUTHORITY_RENEWAL_CURRENT_REVISION_MISSING,
    REASON_AUTHORITY_RENEWAL_DELEGATION_DEPTH_CHANGED, REASON_AUTHORITY_RENEWAL_GRANT_FUTURE_DATED,
    REASON_AUTHORITY_RENEWAL_GRANT_ID_CHANGED, REASON_AUTHORITY_RENEWAL_ISSUER_CHANGED,
    REASON_AUTHORITY_RENEWAL_LIFETIME_EXCEEDED, REASON_AUTHORITY_RENEWAL_NONCE_MISMATCH,
    REASON_AUTHORITY_RENEWAL_NONCE_MISSING, REASON_AUTHORITY_RENEWAL_NON_RENEWABLE,
    REASON_AUTHORITY_RENEWAL_NOT_BEFORE_CHANGED, REASON_AUTHORITY_RENEWAL_OBLIGATIONS_CHANGED,
    REASON_AUTHORITY_RENEWAL_OFFLINE_LIFETIME_EXCEEDED,
    REASON_AUTHORITY_RENEWAL_OPERATIONS_CHANGED, REASON_AUTHORITY_RENEWAL_PARENT_GRANTS_CHANGED,
    REASON_AUTHORITY_RENEWAL_POLICY_MISSING, REASON_AUTHORITY_RENEWAL_RENEWED_GRANT_EXPIRED,
    REASON_AUTHORITY_RENEWAL_REVOCATION_REF_CHANGED,
    REASON_AUTHORITY_RENEWAL_REVOCATION_STATE_CHANGED, REASON_AUTHORITY_RENEWAL_SCOPE_CHANGED,
    REASON_AUTHORITY_RENEWAL_SUBJECT_CHANGED, REASON_AUTHORITY_RENEWAL_VALIDATION_KIND_CHANGED,
};
pub use revocation::{
    evaluate_cached_capability_request, AuthorityConnectivity, AuthorityGrantCache,
    AuthorityGrantCacheError, AuthorityOfflineHighRiskBehavior, AuthorityOfflinePolicyError,
    AuthorityRevocationCheckError, AuthorityRevocationSnapshotError, CachedAuthorityGrant,
    OfflineAuthorityPolicy, RevocationSnapshot, REASON_AUTHORITY_CACHE_EXPIRED,
    REASON_AUTHORITY_CACHE_FUTURE_DATED, REASON_AUTHORITY_CACHE_MISSING,
    REASON_AUTHORITY_CACHE_STALE, REASON_AUTHORITY_GRANT_REVOKED,
    REASON_AUTHORITY_OFFLINE_HIGH_RISK_DENIED,
    REASON_AUTHORITY_OFFLINE_HIGH_RISK_NEEDS_INTERVENTION, REASON_AUTHORITY_OFFLINE_TTL_EXPIRED,
    REASON_AUTHORITY_OFFLINE_UNSUPPORTED_OPERATION, REASON_AUTHORITY_REVOCATION_REF_MISMATCH,
    REASON_AUTHORITY_REVOCATION_SNAPSHOT_FUTURE_DATED,
    REASON_AUTHORITY_REVOCATION_SNAPSHOT_MISSING, REASON_AUTHORITY_REVOCATION_SNAPSHOT_STALE,
    REASON_AUTHORITY_SCOPE_MISMATCH,
};
