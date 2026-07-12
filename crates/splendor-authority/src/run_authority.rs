//! Production-local signed-work-order compatibility authority.
//!
//! This seam exists while daemon admission does not yet receive C01 issuer and
//! subject principal records required by `issue_work_order_capability_grant`.
//! It accepts only `ValidatedWorkOrder`, binds an otherwise unbound work order to
//! the resolved local run, and retains the resulting trusted grant behind an
//! opaque live evaluator. Raw work-order payloads cannot enter this path.

use crate::{
    evaluate_capability_request, grant_from_work_order, AuthorityEvaluationError,
    CompatibilityGrantContext,
};
use splendor_types::{
    AuthorityDecision, AuthorityDecisionId, AuthorityDecisionStatus, AuthorityOperation,
    CapabilityGrantId, CapabilityRequest, CapabilityScope, PrincipalId, RunId, ValidatedWorkOrder,
    AUTHORITY_DECISION_SCHEMA_VERSION, CAPABILITY_REQUEST_SCHEMA_VERSION,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use time::OffsetDateTime;

/// Opaque live run authority admitted from the verified signed-work-order path.
#[derive(Clone)]
pub struct LocalSignedWorkOrderRunAuthority {
    inner: Arc<LocalSignedWorkOrderRunAuthorityInner>,
}

struct LocalSignedWorkOrderRunAuthorityInner {
    grant: crate::ValidatedCapabilityGrant,
    request_scope: CapabilityScope,
    subject: PrincipalId,
    revoked: AtomicBool,
    evaluation_count: AtomicU64,
}

/// Fail-closed compatibility admission errors.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum LocalRunAuthorityAdmissionError {
    /// The signed work order was already bound to another run.
    #[error("validated work order run binding does not match the resolved run")]
    RunBindingMismatch,
    /// The authority-owned verified grant builder rejected the profile.
    #[error("validated work-order capability admission failed: {reason}")]
    GrantRejected { reason: String },
}

impl LocalRunAuthorityAdmissionError {
    /// Stable reason code for daemon/application-service error mapping.
    pub fn reason_code(&self) -> &str {
        match self {
            Self::RunBindingMismatch => "work_order_run_binding_mismatch",
            Self::GrantRejected { .. } => "work_order_authority_grant_rejected",
        }
    }
}

impl LocalSignedWorkOrderRunAuthority {
    /// Admits one live local run grant from an already signature- and
    /// context-validated work order.
    ///
    /// This is an explicitly named compatibility path, not an issuer service.
    /// C01 adoption should replace the synthetic local principal identities with
    /// `issue_work_order_capability_grant` inputs supplied by the principal and
    /// proof provider.
    pub fn admit_compatibility(
        validated: &ValidatedWorkOrder,
        resolved_run_id: RunId,
        audience: String,
    ) -> Result<Self, LocalRunAuthorityAdmissionError> {
        let mut work_order = validated.work_order().clone();
        if work_order
            .run_id
            .as_ref()
            .is_some_and(|bound| bound != &resolved_run_id)
        {
            return Err(LocalRunAuthorityAdmissionError::RunBindingMismatch);
        }
        work_order.run_id = Some(resolved_run_id.clone());

        let issuer = PrincipalId::new();
        let subject = PrincipalId::new();
        let grant = grant_from_work_order(
            CompatibilityGrantContext {
                grant_id: CapabilityGrantId::new(),
                issuer,
                subject: subject.clone(),
                audience: audience.clone(),
                validation_digest: format!(
                    "validated_signed_work_order_compatibility:{}",
                    work_order.work_order_id
                ),
                max_delegation_depth: 0,
                parent_grant_ids: Vec::new(),
            },
            &work_order,
        )
        .map_err(grant_rejected)?;

        let mut request_scope = grant.grant().scope.clone();
        request_scope.tenant_ids = Some(vec![work_order.tenant_id]);
        request_scope.agent_ids = Some(vec![work_order.agent_id]);
        request_scope.run_ids = Some(vec![resolved_run_id]);
        request_scope.audiences = Some(vec![audience]);

        Ok(Self {
            inner: Arc::new(LocalSignedWorkOrderRunAuthorityInner {
                grant,
                request_scope,
                subject,
                revoked: AtomicBool::new(false),
                evaluation_count: AtomicU64::new(0),
            }),
        })
    }

    /// Evaluates one typed operation against current grant expiry and revocation.
    pub fn evaluate_operation(
        &self,
        operation: AuthorityOperation,
        now: OffsetDateTime,
    ) -> AuthorityDecision {
        self.inner.evaluation_count.fetch_add(1, Ordering::SeqCst);
        let request = CapabilityRequest {
            schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
            subject: self.inner.subject.clone(),
            operation,
            scope: self.inner.request_scope.clone(),
            requested_at: now,
            metadata: Default::default(),
        };
        if self.inner.revoked.load(Ordering::SeqCst) {
            return AuthorityDecision {
                schema_version: AUTHORITY_DECISION_SCHEMA_VERSION.to_string(),
                decision_id: AuthorityDecisionId::new(),
                request,
                status: AuthorityDecisionStatus::Denied,
                reasons: vec!["authority_grant_revoked".to_string()],
                matched_grant_ids: Vec::new(),
                obligations: Vec::new(),
                decided_at: now,
            };
        }
        evaluate_capability_request(std::slice::from_ref(&self.inner.grant), &request, now)
    }

    /// Monotonically revokes this live local run grant. Revocation cannot be
    /// cleared or renewed through this bounded compatibility seam.
    pub fn revoke(&self) {
        self.inner.revoked.store(true, Ordering::SeqCst);
    }

    /// Number of typed operation evaluations performed by this handle.
    pub fn evaluation_count(&self) -> u64 {
        self.inner.evaluation_count.load(Ordering::SeqCst)
    }

    /// Opaque grant identity retained for trace/evidence correlation.
    pub fn grant_id(&self) -> &CapabilityGrantId {
        &self.inner.grant.grant().grant_id
    }
}

fn grant_rejected(error: AuthorityEvaluationError) -> LocalRunAuthorityAdmissionError {
    LocalRunAuthorityAdmissionError::GrantRejected {
        reason: error.reason_code(),
    }
}

#[cfg(test)]
#[path = "../tests/unit/run_authority_tests.rs"]
mod tests;
