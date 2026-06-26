//! # Splendor Authority
//!
//! Authority-plane decision logic. This local evidence surface currently covers
//! the Principal Registry lifecycle state machine from IDR-001 plus a bounded
//! AUTH-001 capability grammar/evaluator slice. It does not replace daemon
//! authentication, signed work orders, gateway verification, or adapter execution.

mod capability;
mod identity;

pub use capability::{
    compatibility_permission_operation, ensure_child_grant_narrows, evaluate_capability_request,
    gateway_action_operation, gateway_adapter_operation, grant_from_delegated_authority,
    grant_from_legacy_allowlists, grant_from_work_order, intersect_capability_scopes,
    AuthorityEvaluationError, CompatibilityGrantContext, LegacyScopeProfile,
};
pub use identity::{IdentityMutation, IdentityRegistry, IdentityRegistryError, RegisterPrincipal};
