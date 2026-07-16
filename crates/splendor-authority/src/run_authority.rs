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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
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
    state: Mutex<LocalRunAuthorityState>,
    quiesced: Condvar,
    evaluation_count: AtomicU64,
}

#[derive(Default)]
struct LocalRunAuthorityState {
    revoked: bool,
    expired: bool,
    max_observed_time: Option<OffsetDateTime>,
    generation: u64,
    in_flight_effects: u64,
}

/// Owned linearization guard for one final effect authorization.
///
/// Acquisition atomically checks the exact operation tuple against current grant
/// expiry and revocation. The permit remains valid until dropped. Revocation
/// closes admission first and does not return until all earlier permits drop, so
/// a completed revocation cannot invisibly invalidate an in-flight effect.
pub struct LocalRunAuthorityEffectPermit {
    inner: Arc<LocalSignedWorkOrderRunAuthorityInner>,
    generation: u64,
}

impl LocalRunAuthorityEffectPermit {
    /// Authority generation at which this permit linearized.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for LocalRunAuthorityEffectPermit {
    fn drop(&mut self) {
        let Ok(mut state) = self.inner.state.lock() else {
            return;
        };
        state.in_flight_effects = state.in_flight_effects.saturating_sub(1);
        if state.in_flight_effects == 0 {
            self.inner.quiesced.notify_all();
        }
    }
}

/// Final authority evaluation and optional owned effect permit.
pub struct LocalRunAuthorityPermitEvaluation {
    /// Fresh decisions for the exact requested operation tuple.
    pub decisions: Vec<AuthorityDecision>,
    /// Present only when every operation remains authorized at linearization.
    pub permit: Option<LocalRunAuthorityEffectPermit>,
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
                state: Mutex::new(LocalRunAuthorityState::default()),
                quiesced: Condvar::new(),
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
        let mut state = match self.inner.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return unavailable_decision(
                    &self.inner,
                    operation,
                    now,
                    "authority_state_unavailable",
                )
            }
        };
        match observe_authority_time(&self.inner, &mut state, now) {
            AuthorityTimeObservation::Current(effective_now) => {
                evaluate_operation(&self.inner, operation, effective_now, state.revoked)
            }
            AuthorityTimeObservation::Rollback => {
                unavailable_decision(&self.inner, operation, now, "authority_clock_rollback")
            }
        }
    }

    /// Acquires the final owned effect permit after all other pre-effect checks.
    /// The ordered operation list must contain the exact action, effective
    /// adapter, and trusted permission profile required by the effect.
    pub fn acquire_effect_permit(
        &self,
        operations: Vec<AuthorityOperation>,
        now: OffsetDateTime,
    ) -> LocalRunAuthorityPermitEvaluation {
        if operations.is_empty() {
            return LocalRunAuthorityPermitEvaluation {
                decisions: Vec::new(),
                permit: None,
            };
        }
        let Ok(mut state) = self.inner.state.lock() else {
            return LocalRunAuthorityPermitEvaluation {
                decisions: operations
                    .into_iter()
                    .map(|operation| {
                        unavailable_decision(
                            &self.inner,
                            operation,
                            now,
                            "authority_state_unavailable",
                        )
                    })
                    .collect(),
                permit: None,
            };
        };
        let time = observe_authority_time(&self.inner, &mut state, now);
        let decisions = operations
            .into_iter()
            .map(|operation| match time {
                AuthorityTimeObservation::Current(effective_now) => {
                    evaluate_operation(&self.inner, operation, effective_now, state.revoked)
                }
                AuthorityTimeObservation::Rollback => {
                    unavailable_decision(&self.inner, operation, now, "authority_clock_rollback")
                }
            })
            .collect::<Vec<_>>();
        let allowed = decisions.iter().all(|decision| {
            matches!(
                decision.status,
                AuthorityDecisionStatus::Allowed | AuthorityDecisionStatus::Conditional
            )
        });
        if !allowed {
            return LocalRunAuthorityPermitEvaluation {
                decisions,
                permit: None,
            };
        }
        state.in_flight_effects = state.in_flight_effects.saturating_add(1);
        LocalRunAuthorityPermitEvaluation {
            decisions,
            permit: Some(LocalRunAuthorityEffectPermit {
                inner: Arc::clone(&self.inner),
                generation: state.generation,
            }),
        }
    }

    /// Monotonically closes admission for new effects without waiting for
    /// already-permitted effects to leave the adapter boundary.
    pub fn close_effect_admission(&self) {
        let Ok(mut state) = self.inner.state.lock() else {
            return;
        };
        if !state.revoked {
            state.revoked = true;
            state.generation = state.generation.saturating_add(1);
        }
    }

    /// Waits for effects permitted before admission closed to leave the adapter
    /// boundary. Callers must not retain broad runtime locks while waiting.
    pub fn wait_for_effect_quiescence(&self) {
        let Ok(mut state) = self.inner.state.lock() else {
            return;
        };
        while state.in_flight_effects > 0 {
            let Ok(next) = self.inner.quiesced.wait(state) else {
                return;
            };
            state = next;
        }
    }

    /// Monotonically revokes this live local run grant and waits for effects that
    /// acquired an earlier permit to leave the adapter boundary. New permits are
    /// denied as soon as revocation takes the authority-state lock.
    pub fn revoke(&self) {
        self.close_effect_admission();
        self.wait_for_effect_quiescence();
    }

    /// Current monotonic authority generation.
    pub fn generation(&self) -> Option<u64> {
        self.inner.state.lock().ok().map(|state| state.generation)
    }

    /// Number of typed operation evaluations performed by this handle.
    pub fn evaluation_count(&self) -> u64 {
        self.inner.evaluation_count.load(Ordering::SeqCst)
    }

    /// Opaque grant identity retained for trace/evidence correlation.
    pub fn grant_id(&self) -> &CapabilityGrantId {
        &self.inner.grant.grant().grant_id
    }

    /// Immutable expiry of the admitted run grant.
    pub fn expires_at(&self) -> OffsetDateTime {
        self.inner.grant.grant().expires_at
    }
}

#[derive(Clone, Copy)]
enum AuthorityTimeObservation {
    Current(OffsetDateTime),
    Rollback,
}

fn observe_authority_time(
    inner: &LocalSignedWorkOrderRunAuthorityInner,
    state: &mut LocalRunAuthorityState,
    now: OffsetDateTime,
) -> AuthorityTimeObservation {
    let previous = state.max_observed_time;
    let effective_now = previous.map_or(now, |observed| observed.max(now));
    state.max_observed_time = Some(effective_now);
    if effective_now >= inner.grant.grant().expires_at {
        state.expired = true;
    }
    if state.expired {
        return AuthorityTimeObservation::Current(effective_now);
    }
    if previous.is_some_and(|observed| now < observed) {
        AuthorityTimeObservation::Rollback
    } else {
        AuthorityTimeObservation::Current(effective_now)
    }
}

fn evaluate_operation(
    inner: &LocalSignedWorkOrderRunAuthorityInner,
    operation: AuthorityOperation,
    now: OffsetDateTime,
    revoked: bool,
) -> AuthorityDecision {
    inner.evaluation_count.fetch_add(1, Ordering::SeqCst);
    let request = operation_request(inner, operation, now);
    if revoked {
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
    evaluate_capability_request(std::slice::from_ref(&inner.grant), &request, now)
}

fn unavailable_decision(
    inner: &LocalSignedWorkOrderRunAuthorityInner,
    operation: AuthorityOperation,
    now: OffsetDateTime,
    reason: &str,
) -> AuthorityDecision {
    inner.evaluation_count.fetch_add(1, Ordering::SeqCst);
    AuthorityDecision {
        schema_version: AUTHORITY_DECISION_SCHEMA_VERSION.to_string(),
        decision_id: AuthorityDecisionId::new(),
        request: operation_request(inner, operation, now),
        status: AuthorityDecisionStatus::NeedsIntervention,
        reasons: vec![reason.to_string()],
        matched_grant_ids: Vec::new(),
        obligations: Vec::new(),
        decided_at: now,
    }
}

fn operation_request(
    inner: &LocalSignedWorkOrderRunAuthorityInner,
    operation: AuthorityOperation,
    now: OffsetDateTime,
) -> CapabilityRequest {
    CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject: inner.subject.clone(),
        operation,
        scope: inner.request_scope.clone(),
        requested_at: now,
        metadata: Default::default(),
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
