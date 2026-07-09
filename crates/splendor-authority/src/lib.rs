//! # Splendor Authority
//!
//! Authority-plane decision logic. This local evidence surface currently covers
//! the Principal Registry lifecycle state machine from IDR-001 plus bounded
//! AUTH-001 capability grammar/evaluator and AUTH-002a work-order grant issuance
//! slices. It does not replace daemon authentication, gateway verification, or
//! adapter execution.

mod capability;
mod delegation;
mod identity;
mod issuance;
mod obligations;

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
    canonical_authority_request_digest, verify_obligation_receipts, ObligationReceiptError,
    ObligationReceiptVerification,
};
