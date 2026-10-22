//! Kernel composition facade for production-local C02 run authority.

use crate::KernelRuntime;
use splendor_authority::{
    apply_approval_policy_obligation, compatibility_permission_operation, gateway_action_operation,
    gateway_adapter_operation, ApprovalObligationContext, LocalRunAuthorityAdmissionError,
    LocalSignedWorkOrderRunAuthority,
};
use splendor_gateway::{
    canonical_gateway_authority_action_digest, canonical_gateway_authority_action_v1_compat_digest,
    is_physical_action, ActionAuthorityEvaluation, ActionAuthorityEvaluator, ActionRequest,
    AuthorityEffectPermit, FinalEffectAuthorityEvaluation, PreEffectAuthorityDecisionRecorder,
};
use splendor_types::{
    AgentId, ApprovalActionScope, ApprovalChallenge, ApprovalDecision, ApprovalPolicy,
    AuthorityDecision, AuthorityDecisionStatus, NodeId, PhysicalActionResourceCoordinate, RunId,
    TenantId, TraceEventKind, ValidatedWorkOrder, APPROVAL_EVIDENCE_SCHEMA_VERSION,
};
use std::sync::Arc;
use time::OffsetDateTime;

/// Opaque kernel handle for one live C02 run grant.
#[derive(Clone)]
pub struct RunAuthorityHandle {
    authority: LocalSignedWorkOrderRunAuthority,
    approval_policies: Arc<Vec<ApprovalPolicy>>,
    receipt_audience: String,
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
}

impl RunAuthorityHandle {
    /// Admits a run only from the already verified signed-work-order wrapper.
    pub fn admit_signed_work_order_compatibility(
        validated: &ValidatedWorkOrder,
        run_id: RunId,
        audience: String,
    ) -> Result<Self, LocalRunAuthorityAdmissionError> {
        Self::admit_signed_work_order_compatibility_with_approval_policies(
            validated,
            run_id,
            audience,
            Vec::new(),
        )
    }

    /// Admits a run and migrates immutable daemon approval policies into current
    /// authority-owned conditional action decisions.
    pub fn admit_signed_work_order_compatibility_with_approval_policies(
        validated: &ValidatedWorkOrder,
        run_id: RunId,
        audience: String,
        approval_policies: Vec<ApprovalPolicy>,
    ) -> Result<Self, LocalRunAuthorityAdmissionError> {
        let work_order = validated.work_order();
        Ok(Self {
            authority: LocalSignedWorkOrderRunAuthority::admit_compatibility(
                validated,
                run_id.clone(),
                audience.clone(),
            )?,
            approval_policies: Arc::new(approval_policies),
            receipt_audience: audience,
            tenant_id: work_order.tenant_id.clone(),
            agent_id: work_order.agent_id.clone(),
            run_id,
        })
    }

    /// Monotonically revokes the local run grant.
    pub fn revoke(&self) {
        self.authority.revoke();
    }

    /// Closes admission for new effects without waiting for prior permits.
    pub fn close_effect_admission(&self) {
        self.authority.close_effect_admission();
    }

    /// Waits for effects permitted before admission closed to quiesce.
    /// Callers must not hold broad runtime locks while waiting.
    pub fn wait_for_effect_quiescence(&self) {
        self.authority.wait_for_effect_quiescence();
    }

    /// Returns the number of typed C02 operation evaluations.
    pub fn evaluation_count(&self) -> u64 {
        self.authority.evaluation_count()
    }

    /// Returns the opaque grant ID for correlation without exposing grant payloads.
    pub fn grant_id(&self) -> &splendor_types::CapabilityGrantId {
        self.authority.grant_id()
    }

    /// Binds a physical action to one trusted registered-node coordinate after
    /// validating that the action still belongs to this admitted run scope.
    pub fn bind_physical_action_resource(
        &self,
        action: &mut ActionRequest,
        node_id: NodeId,
    ) -> Result<(), RunActionAdmissionError> {
        if node_id.is_nil()
            || action.tenant_id != self.tenant_id
            || action.agent_id != self.agent_id
            || action.run_id != self.run_id
            || !is_physical_action(&action.action)
            || action.physical_action_resource_coordinate.is_some()
        {
            return Err(RunActionAdmissionError::new(
                "physical_action_resource_binding_mismatch",
                "physical action target did not match the admitted run and trusted device path",
            ));
        }
        action.physical_action_resource_coordinate =
            Some(PhysicalActionResourceCoordinate::physical_node(node_id));
        Ok(())
    }

    /// Applies the kernel-owned lifecycle and immutable pending-challenge
    /// admission rules before daemon audit, runtime trace, or gateway mutation.
    pub fn admit_action_request(
        &self,
        state: RunActionAdmissionState,
        pending_challenge: Option<&ApprovalChallenge>,
        action: &mut ActionRequest,
        effective_adapter: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Option<ApprovalChallenge>, RunActionAdmissionError> {
        if action.tenant_id != self.tenant_id
            || action.agent_id != self.agent_id
            || action.run_id != self.run_id
        {
            return Err(RunActionAdmissionError::new(
                "approval_challenge_retry_mismatch",
                "action scope did not match the admitted run",
            ));
        }

        let raw_evidence = action.approval_evidence.as_ref();
        if let Some(evidence) = raw_evidence {
            if evidence.schema_version != APPROVAL_EVIDENCE_SCHEMA_VERSION {
                return Err(RunActionAdmissionError::new(
                    "approval_evidence_schema_unsupported",
                    "raw approval evidence does not use the canonical supported schema",
                ));
            }
            if evidence.issued_at > evidence.expires_at {
                return Err(RunActionAdmissionError::new(
                    "approval_evidence_malformed",
                    "raw approval evidence has an invalid validity interval",
                ));
            }
        }
        if raw_evidence.is_some() && !action.authority_obligation_receipts.is_empty() {
            let code = if raw_evidence
                .is_some_and(|evidence| evidence.decision == ApprovalDecision::Denied)
            {
                "approval_denial_receipt_conflict"
            } else {
                "approval_evidence_receipt_conflict"
            };
            return Err(RunActionAdmissionError::new(
                code,
                "raw approval evidence cannot be mixed with authority obligation receipts",
            ));
        }

        match state {
            RunActionAdmissionState::EffectCapable => {
                if let Some(evidence) = raw_evidence {
                    let code = if evidence.decision == ApprovalDecision::Granted {
                        "legacy_approval_evidence_non_authorizing"
                    } else {
                        "approval_challenge_retry_mismatch"
                    };
                    return Err(RunActionAdmissionError::new(
                        code,
                        "raw approval evidence is accepted only for an exact fail-closed pending challenge retry",
                    ));
                }
                Ok(None)
            }
            RunActionAdmissionState::Closed => Err(RunActionAdmissionError::new(
                "run_not_effect_capable",
                "run lifecycle state does not admit external effects",
            )),
            RunActionAdmissionState::WaitingForApproval => {
                let carries_fail_closed_raw = raw_evidence.is_some_and(|evidence| {
                    evidence.decision == ApprovalDecision::Denied
                        || evidence.revoked
                        || evidence.expires_at <= now
                });
                if raw_evidence.is_some() && !carries_fail_closed_raw {
                    return Err(RunActionAdmissionError::new(
                        "legacy_approval_evidence_non_authorizing",
                        "active raw approval grants cannot authorize or mutate a waiting run",
                    ));
                }
                if raw_evidence.is_none() && action.authority_obligation_receipts.is_empty() {
                    return Err(RunActionAdmissionError::new(
                        "approval_exact_action_retry_required",
                        "waiting_for_approval accepts only an exact receipt retry or fail-closed raw result",
                    ));
                }
                let challenge = pending_challenge.ok_or_else(|| {
                    RunActionAdmissionError::new(
                        "approval_challenge_unavailable",
                        "the full pending approval challenge is unavailable",
                    )
                })?;

                let physical_v1_fail_closed_retry = is_physical_action(&action.action)
                    && carries_fail_closed_raw
                    && challenge.physical_action_resource_coordinate.is_none();

                match (
                    is_physical_action(&action.action),
                    action.physical_action_resource_coordinate.as_ref(),
                    challenge.physical_action_resource_coordinate.as_ref(),
                ) {
                    (true, None, Some(expected)) => {
                        action.physical_action_resource_coordinate = Some(expected.clone())
                    }
                    (true, Some(actual), Some(expected)) if actual == expected => {}
                    (true, Some(_), None) if physical_v1_fail_closed_retry => {}
                    (false, None, None) => {}
                    _ => {
                        let (code, message) = if is_physical_action(&action.action)
                            && challenge.physical_action_resource_coordinate.is_none()
                        {
                            (
                                "physical_approval_challenge_v1_rechallenge_required",
                                "physical-v1 approval challenges cannot authorize an effect and require a physical-v2 re-challenge",
                            )
                        } else {
                            (
                                "approval_challenge_retry_mismatch",
                                "physical action target did not match the immutable pending challenge",
                            )
                        };
                        return Err(RunActionAdmissionError::new(code, message));
                    }
                }

                let digest = if physical_v1_fail_closed_retry {
                    let mut legacy_action = action.clone();
                    legacy_action.physical_action_resource_coordinate = None;
                    canonical_gateway_authority_action_v1_compat_digest(
                        &legacy_action,
                        effective_adapter,
                    )
                } else {
                    canonical_gateway_authority_action_digest(action, effective_adapter)
                }
                .map_err(|_| {
                    RunActionAdmissionError::new(
                        "approval_retry_binding_unavailable",
                        "the exact pending action binding could not be evaluated",
                    )
                })?;
                if challenge.tenant_id != action.tenant_id
                    || challenge.agent_id != action.agent_id
                    || challenge.run_id != action.run_id
                    || challenge.action_id != action.action_id
                    || challenge.action_name != action.action.name
                    || Some(challenge.adapter.as_str()) != effective_adapter
                    || challenge.requested_at != action.requested_at
                    || challenge.gateway_action_request_digest != digest
                {
                    return Err(RunActionAdmissionError::new(
                        "approval_challenge_retry_mismatch",
                        "action did not match the immutable pending approval challenge",
                    ));
                }
                if let Some(evidence) = raw_evidence {
                    if evidence.approval_id != challenge.approval_id
                        || evidence.tenant_id != challenge.tenant_id
                        || evidence.agent_id != challenge.agent_id
                        || evidence.run_id != challenge.run_id
                        || evidence.action_id.as_ref() != Some(&challenge.action_id)
                        || evidence.action_name.as_deref() != Some(challenge.action_name.as_str())
                        || evidence.adapter.as_deref() != Some(challenge.adapter.as_str())
                    {
                        return Err(RunActionAdmissionError::new(
                            "approval_challenge_retry_mismatch",
                            "raw fail-closed approval evidence did not match the pending challenge",
                        ));
                    }
                }
                Ok(Some(challenge.clone()))
            }
        }
    }
}

/// Daemon lifecycle projection accepted by kernel action admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunActionAdmissionState {
    /// Pending or running lifecycle state without raw approval evidence.
    EffectCapable,
    /// Run owns one immutable pending approval challenge.
    WaitingForApproval,
    /// Suspended, resuming, or terminal state.
    Closed,
}

/// Stable kernel admission failure translated by daemon HTTP handlers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunActionAdmissionError {
    reason_code: &'static str,
    message: &'static str,
}

impl RunActionAdmissionError {
    fn new(reason_code: &'static str, message: &'static str) -> Self {
        Self {
            reason_code,
            message,
        }
    }

    /// Stable machine-readable reason code.
    pub fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    /// Bounded public failure message.
    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl ActionAuthorityEvaluator for RunAuthorityHandle {
    fn evaluate_action_authority(
        &self,
        action: &ActionRequest,
        effective_adapter: Option<&str>,
        now: OffsetDateTime,
    ) -> ActionAuthorityEvaluation {
        let decisions = self.evaluate_operations(action, effective_adapter, now);
        ActionAuthorityEvaluation::Evaluated(decisions)
    }

    fn acquire_final_effect_permit(
        &self,
        action: &ActionRequest,
        effective_adapter: Option<&str>,
        _expected_decisions: &[splendor_types::AuthorityDecision],
        now: OffsetDateTime,
    ) -> FinalEffectAuthorityEvaluation {
        let mut evaluation = self
            .authority
            .acquire_effect_permit(effect_operations(action, effective_adapter), now);
        evaluation.decisions =
            self.apply_approval_policies(action, effective_adapter, evaluation.decisions, now);
        match evaluation.permit {
            Some(permit) => FinalEffectAuthorityEvaluation::Permitted {
                decisions: evaluation.decisions,
                permit: AuthorityEffectPermit::new(permit),
            },
            None => FinalEffectAuthorityEvaluation::Denied(evaluation.decisions),
        }
    }
}

impl RunAuthorityHandle {
    fn evaluate_operations(
        &self,
        action: &ActionRequest,
        effective_adapter: Option<&str>,
        now: OffsetDateTime,
    ) -> Vec<AuthorityDecision> {
        let decisions = effect_operations(action, effective_adapter)
            .into_iter()
            .map(|operation| self.authority.evaluate_operation(operation, now))
            .collect();
        self.apply_approval_policies(action, effective_adapter, decisions, now)
    }

    fn apply_approval_policies(
        &self,
        action: &ActionRequest,
        effective_adapter: Option<&str>,
        decisions: Vec<AuthorityDecision>,
        now: OffsetDateTime,
    ) -> Vec<AuthorityDecision> {
        if self.approval_policies.is_empty() {
            return decisions;
        }
        let digest = canonical_gateway_authority_action_digest(action, effective_adapter);
        let scope = ApprovalActionScope {
            tenant_id: &action.tenant_id,
            agent_id: &action.agent_id,
            run_id: &action.run_id,
            action_id: &action.action_id,
            action: &action.action,
            adapter: effective_adapter,
        };
        decisions
            .into_iter()
            .map(|mut decision| match digest.as_deref() {
                Ok(digest) => apply_approval_policy_obligation(
                    decision,
                    self.approval_policies.as_slice(),
                    ApprovalObligationContext {
                        action_scope: scope,
                        gateway_action_request_digest: digest,
                        receipt_audience: &self.receipt_audience,
                        authority_expires_at: self.authority.expires_at(),
                        action_requested_at: action.requested_at,
                        now,
                    },
                ),
                Err(_)
                    if decision.request.operation
                        == gateway_action_operation(&action.action.name) =>
                {
                    decision.status = AuthorityDecisionStatus::NeedsIntervention;
                    decision.reasons = vec!["approval_challenge_binding_unavailable".to_string()];
                    decision.obligations.clear();
                    decision
                }
                Err(_) => decision,
            })
            .collect()
    }
}

fn effect_operations(
    action: &ActionRequest,
    effective_adapter: Option<&str>,
) -> Vec<splendor_types::AuthorityOperation> {
    let mut operations = vec![gateway_action_operation(action.action.name.clone())];
    if let Some(adapter) = effective_adapter {
        operations.push(gateway_adapter_operation(adapter));
    }
    operations.extend(
        action
            .action
            .required_permissions
            .iter()
            .cloned()
            .map(compatibility_permission_operation),
    );
    operations
}

/// Trace-backed recorder sharing the exact runtime cursor used by the loop.
#[derive(Clone)]
pub struct KernelPreEffectAuthorityRecorder {
    runtime: Arc<KernelRuntime>,
    tenant_id: TenantId,
    agent_id: AgentId,
}

impl KernelPreEffectAuthorityRecorder {
    /// Binds the recorder to one run runtime and immutable tenant/agent scope.
    pub fn new(runtime: Arc<KernelRuntime>, tenant_id: TenantId, agent_id: AgentId) -> Self {
        Self {
            runtime,
            tenant_id,
            agent_id,
        }
    }
}

impl PreEffectAuthorityDecisionRecorder for KernelPreEffectAuthorityRecorder {
    fn record_pre_effect_authority_allow(
        &self,
        action: &ActionRequest,
        verification: &splendor_types::VerificationResult,
    ) -> Result<(), String> {
        let mut identity = self
            .runtime
            .trace_identity()
            .with_tenant_agent(self.tenant_id.clone(), self.agent_id.clone())
            .with_action_id(action.action_id.clone());
        if let Some(tick_id) = action.tick_id {
            identity = identity.with_tick_id(tick_id);
        }
        self.runtime
            .record_event_with_identity(
                identity,
                TraceEventKind::ActionVerificationCompleted {
                    action: action.action.clone(),
                    result: verification.clone(),
                },
            )
            .map(|_| ())
            .map_err(|_| "authority_evidence_store_unavailable".to_string())
    }
}

#[cfg(test)]
#[path = "../tests/unit/run_authority_tests.rs"]
mod tests;
