//! Kernel composition facade for production-local C02 run authority.

use crate::KernelRuntime;
use splendor_authority::{
    compatibility_permission_operation, gateway_action_operation, gateway_adapter_operation,
    LocalRunAuthorityAdmissionError, LocalSignedWorkOrderRunAuthority,
};
use splendor_gateway::{
    ActionAuthorityEvaluation, ActionAuthorityEvaluator, ActionRequest,
    PreEffectAuthorityDecisionRecorder,
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
        let mut decisions = vec![self
            .authority
            .evaluate_operation(gateway_action_operation(action.action.name.clone()), now)];
        if let Some(adapter) = effective_adapter {
            decisions.push(
                self.authority
                    .evaluate_operation(gateway_adapter_operation(adapter), now),
            );
        }
        for permission in &action.action.required_permissions {
            decisions.push(
                self.authority.evaluate_operation(
                    compatibility_permission_operation(permission.clone()),
                    now,
                ),
            );
        }
        ActionAuthorityEvaluation::Evaluated(decisions)
    }
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
        self.runtime
            .record_event_with_identity(
                self.runtime
                    .trace_identity()
                    .with_tenant_agent(self.tenant_id.clone(), self.agent_id.clone())
                    .with_action_id(action.action_id.clone()),
                TraceEventKind::ActionVerificationCompleted {
                    action: action.action.clone(),
                    result: verification.clone(),
                },
            )
            .map(|_| ())
            .map_err(|_| "authority_evidence_store_unavailable".to_string())
    }
}
