//! Kernel composition facade for production-local C02 run authority.

use crate::KernelRuntime;
use splendor_authority::{
    compatibility_permission_operation, gateway_action_operation, gateway_adapter_operation,
    LocalRunAuthorityAdmissionError, LocalSignedWorkOrderRunAuthority,
};
use splendor_gateway::{
    ActionAuthorityEvaluation, ActionAuthorityEvaluator, ActionRequest, AuthorityEffectPermit,
    FinalEffectAuthorityEvaluation, PreEffectAuthorityDecisionRecorder,
};
use splendor_types::{AgentId, RunId, TenantId, TraceEventKind, ValidatedWorkOrder};
use std::sync::Arc;
use time::OffsetDateTime;

/// Opaque kernel handle for one live C02 run grant.
#[derive(Clone)]
pub struct RunAuthorityHandle {
    authority: LocalSignedWorkOrderRunAuthority,
}

impl RunAuthorityHandle {
    /// Admits a run only from the already verified signed-work-order wrapper.
    pub fn admit_signed_work_order_compatibility(
        validated: &ValidatedWorkOrder,
        run_id: RunId,
        audience: String,
    ) -> Result<Self, LocalRunAuthorityAdmissionError> {
        Ok(Self {
            authority: LocalSignedWorkOrderRunAuthority::admit_compatibility(
                validated, run_id, audience,
            )?,
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
}

impl ActionAuthorityEvaluator for RunAuthorityHandle {
    fn evaluate_action_authority(
        &self,
        action: &ActionRequest,
        effective_adapter: Option<&str>,
        now: OffsetDateTime,
    ) -> ActionAuthorityEvaluation {
        let decisions = effect_operations(action, effective_adapter)
            .into_iter()
            .map(|operation| self.authority.evaluate_operation(operation, now))
            .collect();
        ActionAuthorityEvaluation::Evaluated(decisions)
    }

    fn acquire_final_effect_permit(
        &self,
        action: &ActionRequest,
        effective_adapter: Option<&str>,
        _expected_decisions: &[splendor_types::AuthorityDecision],
        now: OffsetDateTime,
    ) -> FinalEffectAuthorityEvaluation {
        let evaluation = self
            .authority
            .acquire_effect_permit(effect_operations(action, effective_adapter), now);
        match evaluation.permit {
            Some(permit) => FinalEffectAuthorityEvaluation::Permitted {
                decisions: evaluation.decisions,
                permit: AuthorityEffectPermit::new(permit),
            },
            None => FinalEffectAuthorityEvaluation::Denied(evaluation.decisions),
        }
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
