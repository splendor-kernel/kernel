//! # Splendor Authority
//!
//! Authority-plane decision logic. This local evidence surface currently covers
//! the Principal Registry lifecycle state machine from IDR-001 plus bounded
//! AUTH-001 capability grammar/evaluator, AUTH-002a work-order grant issuance,
//! AUTH-003 delegation, AUTH-004 obligation receipt, and AUTH-005a local
//! revocation/offline-cache foundation slices. It does not replace daemon
//! authentication, gateway verification, revocation-watch services, lease renewal,
//! or adapter execution.

mod capability;
mod delegation;
mod identity;
mod issuance;
mod obligations;
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
