//! # Local Delegation Model
//!
//! Local-only parent/child run delegation for Sprint 0.02-S4. The manager keeps
//! delegation explicit: parent runs name the target agent, child objective,
//! delegated compatibility authority, and authority-issued parent/child grant
//! refs. Child agent contexts returned by this module are scoped so the loop
//! engine denies actions outside the delegated authority before any adapter can
//! execute.

use crate::{
    AgentContext, LocalMessageRouter, MessageRouter, MessageRouterConfig, MessageRouterError,
    MessageTraceRecorder,
};
use splendor_authority::{
    compatibility_permission_operation, gateway_action_operation, gateway_adapter_operation,
    DelegationCallerHandle, DelegationChildGrantRequest, InMemoryDelegationAuthorityLedger,
    RevocationSnapshot, ValidatedCapabilityGrant, REASON_AUTHORITY_GRANT_REVOKED,
};
use splendor_types::{
    AgentId, AuthorityBudgetScope, AuthorityOperation, CapabilityGrantId, CapabilityScope,
    DelegatedAuthority, DelegationLedgerEvidence, DelegationLedgerTraceSummary,
    DelegationResultContract, DelegationRoleProfile, LocalDelegationAuthorityEvidence,
    LocalDelegationTraceContext, Message, MessageEnvelope, MessageId, MessageTraceContext,
    MessageValidationError, PrincipalId, RunId, TaskFailure, TaskRequest, TaskResponse,
    TaskResponseStatus, TenantId, TraceEvent, TraceEventKind, TraceId,
    DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION, TASK_REQUEST_SCHEMA, TASK_RESPONSE_SCHEMA,
};
use std::collections::HashMap;
use std::sync::Mutex;
use time::OffsetDateTime;

const REASON_MISSING_AUTHORITY_EVIDENCE: &str = "missing_authority_evidence";
/// Stable denial reason when a delegating root run has no trusted grant binding.
pub const REASON_MISSING_PARENT_RUN_GRANT_BINDING: &str = "missing_parent_run_grant_binding";
/// Stable denial reason when child creation supplies a grant other than the run-bound grant.
pub const REASON_PARENT_RUN_GRANT_MISMATCH: &str = "parent_run_grant_mismatch";
/// Stable denial reason when a proposed child grant ID is already bound in this manager.
pub const REASON_CHILD_CAPABILITY_GRANT_ID_COLLISION: &str = "child_capability_grant_id_collision";

/// Lifecycle status for local parent/child runs known to the delegation manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalRunStatus {
    /// Run is active and may create/complete delegated work.
    Running,
    /// Run completed successfully.
    Completed,
    /// Run failed with a structured child failure.
    Failed,
    /// Run was cancelled and cannot create child runs.
    Cancelled,
    /// Delegation was denied before a child run started.
    Denied,
}

impl LocalRunStatus {
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Denied
        )
    }
}

/// Registered agent boundary used for local delegation admission checks.
#[derive(Clone, Debug)]
pub struct LocalAgentRegistration {
    /// Agent runtime context.
    pub agent: AgentContext,
    /// Principal identity bound to this local agent for authority-backed delegation.
    pub principal_id: PrincipalId,
    /// Maximum local authority this agent may exercise when delegated to.
    pub authority: DelegatedAuthority,
}

/// Parent or child run metadata tracked by the local delegation manager.
#[derive(Clone, Debug)]
pub struct LocalRunRecord {
    /// Run identity.
    pub run_id: RunId,
    /// Agent that owns this run.
    pub agent_id: AgentId,
    /// Principal bound to the run when it was registered/created.
    pub principal_id: PrincipalId,
    /// Tenant scope for this run.
    pub tenant_id: TenantId,
    /// Parent run for child records.
    pub parent_run_id: Option<RunId>,
    /// Child runs created by this run.
    pub child_run_ids: Vec<RunId>,
    /// Explicit authority in effect for this run.
    pub authority: DelegatedAuthority,
    /// Capability grant currently backing this local run, when authority evidence is available.
    pub capability_grant_id: Option<CapabilityGrantId>,
    /// Non-authorizing parent/child authority evidence refs for child runs.
    pub authority_evidence: Option<LocalDelegationAuthorityEvidence>,
    /// Redacted digest of the authority-owned complete chain through this run.
    pub delegation_chain_digest: Option<String>,
    /// Scoped objective for child runs.
    pub objective: Option<String>,
    /// Parent trace event that recorded the delegation request.
    pub parent_trace_id: Option<TraceId>,
    /// Current local lifecycle status.
    pub status: LocalRunStatus,
    /// Request message that created this child run.
    pub request_message_id: Option<MessageId>,
    /// Response message sent when this child run completed or failed.
    pub response_message_id: Option<MessageId>,
}

/// Trusted authority input required before a local child run can be created.
///
/// The embedded [`ValidatedCapabilityGrant`] is the only authorizing input. The
/// optional evidence refs are checked for consistency and then copied into trace,
/// message, run-record, and replay surfaces as non-authorizing audit data.
#[derive(Clone, Debug)]
pub struct LocalDelegationAuthority {
    /// Opaque manager/authority-issued parent caller. Raw child grants are never
    /// returned to or accepted from nested callers.
    pub parent_caller: Option<DelegationCallerHandle>,
    #[cfg(test)]
    pub parent_capability_grant: Option<ValidatedCapabilityGrant>,
    #[cfg(test)]
    pub authority_evidence: Option<LocalDelegationAuthorityEvidence>,
    /// Principal requested for the target child agent; must match registration.
    pub child_subject: PrincipalId,
    /// Local authority audience binding.
    pub audience: String,
    /// Child grant validity start.
    pub not_before: OffsetDateTime,
    /// Child grant expiry.
    pub expires_at: OffsetDateTime,
    /// Child role/profile for authority checks.
    pub role_profile: DelegationRoleProfile,
    /// Desired child budget; authority ledger validation/reservation is authoritative.
    pub budget: AuthorityBudgetScope,
    /// Remaining child delegation depth requested for the child grant.
    pub max_delegation_depth: u32,
    /// Legacy requested fan-out projection; the authority ledger ignores it as authority.
    pub max_fan_out: u32,
}

impl LocalDelegationAuthority {
    /// Builds authority input with conservative defaults derived from the parent grant.
    pub fn from_caller(
        parent_caller: DelegationCallerHandle,
        child_subject: PrincipalId,
        audience: impl Into<String>,
        not_before: OffsetDateTime,
    ) -> Self {
        let defaults = parent_caller.child_request_defaults().ok();
        let parent_not_before = defaults.map(|value| value.not_before).unwrap_or(not_before);
        let not_before = not_before.max(parent_not_before);
        Self {
            parent_caller: Some(parent_caller),
            #[cfg(test)]
            parent_capability_grant: None,
            #[cfg(test)]
            authority_evidence: None,
            child_subject,
            audience: audience.into(),
            not_before,
            expires_at: defaults
                .map(|value| value.expires_at)
                .unwrap_or(not_before + time::Duration::minutes(30)),
            role_profile: DelegationRoleProfile::Specialist,
            budget: defaults.map(|value| value.budget).unwrap_or_default(),
            max_delegation_depth: defaults
                .map(|value| value.max_delegation_depth)
                .unwrap_or_default(),
            max_fan_out: 16,
        }
    }

    #[cfg(test)]
    pub fn new(
        parent_capability_grant: ValidatedCapabilityGrant,
        child_subject: PrincipalId,
        audience: impl Into<String>,
        not_before: OffsetDateTime,
    ) -> Self {
        let parent = parent_capability_grant.grant();
        let child_grant_id = CapabilityGrantId::new();
        Self {
            parent_caller: None,
            parent_capability_grant: Some(parent_capability_grant.clone()),
            authority_evidence: Some(LocalDelegationAuthorityEvidence::issued(
                parent.grant_id.clone(),
                child_grant_id,
            )),
            child_subject,
            audience: audience.into(),
            not_before: not_before.max(parent.not_before),
            expires_at: parent.expires_at,
            role_profile: DelegationRoleProfile::Specialist,
            budget: parent.scope.budget,
            max_delegation_depth: parent.max_delegation_depth.saturating_sub(1),
            max_fan_out: 16,
        }
    }
}

/// Request to create a local child run.
#[derive(Clone, Debug)]
pub struct LocalDelegationRequest {
    /// Parent run requesting delegated work.
    pub parent_run_id: RunId,
    /// Child run to create.
    pub child_run_id: RunId,
    /// Parent/orchestrator agent.
    pub source_agent_id: AgentId,
    /// Child/specialist agent.
    pub target_agent_id: AgentId,
    /// Scoped objective for the child run.
    pub objective: String,
    /// Explicit authority granted to the child run.
    pub delegated_authority: DelegatedAuthority,
    /// Optional parent trace event that caused this delegation.
    pub parent_causal_trace_id: Option<TraceId>,
}

impl LocalDelegationRequest {
    /// Builds a local child-run request with a new child run ID.
    pub fn new(
        parent_run_id: RunId,
        source_agent_id: AgentId,
        target_agent_id: AgentId,
        objective: impl Into<String>,
        delegated_authority: DelegatedAuthority,
        parent_causal_trace_id: Option<TraceId>,
    ) -> Self {
        Self {
            parent_run_id,
            child_run_id: RunId::new(),
            source_agent_id,
            target_agent_id,
            objective: objective.into(),
            delegated_authority,
            parent_causal_trace_id,
        }
    }

    fn trace_context(&self) -> LocalDelegationTraceContext {
        LocalDelegationTraceContext {
            parent_run_id: self.parent_run_id.clone(),
            child_run_id: self.child_run_id.clone(),
            parent_trace_id: self.parent_causal_trace_id.clone(),
            request_message_id: None,
            response_message_id: None,
            source_agent_id: self.source_agent_id.clone(),
            target_agent_id: self.target_agent_id.clone(),
            objective: self.objective.clone(),
            authority_evidence: None,
            delegation_ledger: None,
        }
    }
}

/// Result of creating a local child run.
#[derive(Clone, Debug)]
pub struct LocalChildRun {
    /// Child run metadata.
    pub run: LocalRunRecord,
    /// Scoped child agent context to pass to the child loop engine.
    pub child_agent: AgentContext,
    /// Task request message routed from parent to child.
    pub request_message: MessageEnvelope,
    /// Child-run start trace ID.
    pub child_started_trace_id: TraceId,
    /// Opaque manager-issued caller required for nested delegation.
    pub child_caller: DelegationCallerHandle,
}

/// Result of completing or failing a child run.
#[derive(Clone, Debug)]
pub struct LocalTaskResponse {
    /// Structured task response payload.
    pub response: TaskResponse,
    /// Routed response message.
    pub response_message: MessageEnvelope,
    /// Parent trace ID that references the child completion/failure.
    pub parent_trace_id: TraceId,
    /// Child trace ID that recorded completion/failure.
    pub child_trace_id: TraceId,
}

/// Errors returned by local delegation operations.
#[derive(Debug, thiserror::Error)]
pub enum LocalDelegationError {
    /// Delegation state mutex was poisoned.
    #[error("local delegation storage is unavailable")]
    StorageUnavailable,
    /// Parent run was not registered.
    #[error("parent run {0} is not registered")]
    UnknownParentRun(RunId),
    /// Child run was not registered.
    #[error("child run {0} is not registered")]
    UnknownChildRun(RunId),
    /// Child run ID was already registered.
    #[error("child run {0} is already registered")]
    DuplicateChildRun(RunId),
    /// Run ID was already registered as either a root or child run.
    #[error("run {0} is already registered")]
    DuplicateRun(RunId),
    /// Child run was already completed, failed, denied, or cancelled.
    #[error("child run {child_run_id} is already finished with status {status:?}")]
    ChildRunAlreadyFinished {
        /// Child run that already reached a terminal status.
        child_run_id: RunId,
        /// Current terminal status.
        status: LocalRunStatus,
    },
    /// Agent was not registered.
    #[error("agent {0} is not registered for local delegation")]
    UnknownAgent(AgentId),
    /// Recorder is scoped to a different run than the delegation event.
    #[error(
        "trace recorder run {runtime_run_id} cannot record delegation run {delegation_run_id}"
    )]
    TraceRunMismatch {
        /// Run associated with the trace recorder.
        runtime_run_id: RunId,
        /// Run associated with the delegation operation.
        delegation_run_id: RunId,
    },
    /// Parent run cannot create child work while cancelled.
    #[error("parent run {0} is cancelled")]
    ParentCancelled(RunId),
    /// Request source does not match the parent run owner.
    #[error("delegation source agent does not own parent run")]
    SourceAgentMismatch,
    /// Target agent belongs to a different tenant.
    #[error("target agent tenant does not match parent run tenant")]
    TenantMismatch,
    /// Delegated authority exceeds parent or target scope.
    #[error("delegated authority exceeds {scope} scope")]
    DelegatedAuthorityDenied {
        /// Scope that denied the delegation.
        scope: &'static str,
    },
    /// Authority evidence refs were missing, malformed, or inconsistent.
    #[error("local delegation authority evidence denied: {reason}")]
    AuthorityEvidenceDenied {
        /// Stable reason code.
        reason: String,
    },
    /// Authority service refused to issue the child grant.
    #[error("local delegation authority denied child grant: {reason}")]
    AuthorityDenied {
        /// Stable reason code.
        reason: String,
    },
    /// A root-run grant subject did not match the run's immutable principal snapshot.
    #[error("parent run {run_id} capability grant subject does not match run principal")]
    ParentRunGrantSubjectMismatch {
        /// Root run being bound.
        run_id: RunId,
        /// Principal snapshotted on the root run.
        run_principal_id: PrincipalId,
        /// Subject carried by the trusted grant.
        grant_subject_id: PrincipalId,
    },
    /// A root run was already bound to a different immutable grant ID.
    #[error("parent run {run_id} is already bound to capability grant {bound_grant_id}")]
    ParentRunGrantBindingConflict {
        /// Root run whose binding is immutable.
        run_id: RunId,
        /// Existing bound grant ID.
        bound_grant_id: CapabilityGrantId,
        /// Different grant ID supplied by the caller.
        supplied_grant_id: CapabilityGrantId,
    },
    /// A capability grant ID was already bound to a different run.
    #[error("capability grant {grant_id} is already bound to parent run {bound_run_id}")]
    CapabilityGrantRunBindingConflict {
        /// Grant ID whose manager-local run binding is unique.
        grant_id: CapabilityGrantId,
        /// Existing run bound to the grant.
        bound_run_id: RunId,
        /// Different run requested by the caller.
        requested_run_id: RunId,
    },
    /// Explicit trusted grant binding is only valid for a root run.
    #[error("run {0} is not a root run and cannot be explicitly bound")]
    ParentGrantBindingRequiresRootRun(RunId),
    /// Message schema validation failed.
    #[error("message validation failed: {0}")]
    Message(#[from] MessageValidationError),
    /// Message routing failed.
    #[error("message router failed: {0}")]
    Router(#[from] MessageRouterError),
}

/// Local-only delegation manager for parent/child run admission and trace links.
pub struct LocalDelegationManager {
    router: LocalMessageRouter,
    authority_ledger: InMemoryDelegationAuthorityLedger,
    lifecycle: Mutex<()>,
    state: Mutex<LocalDelegationState>,
}

#[derive(Default)]
struct LocalDelegationState {
    agents: HashMap<AgentId, LocalAgentRegistration>,
    runs: HashMap<RunId, LocalRunRecord>,
    run_callers: HashMap<RunId, DelegationCallerHandle>,
    /// Durable process-local fail-safe tombstones for routing/start uncertainty.
    consumed_child_runs: HashMap<RunId, String>,
}

impl std::fmt::Debug for LocalDelegationManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalDelegationManager")
            .field("router", &self.router)
            .field("authority_ledger", &self.authority_ledger)
            .field("lifecycle", &"<mutex>")
            .field("state", &"<redacted trusted grant bindings>")
            .finish()
    }
}

impl LocalDelegationManager {
    /// Creates a manager backed by an in-memory local router.
    pub fn new() -> Self {
        Self::with_router_config(MessageRouterConfig::default())
    }

    /// Creates a manager with explicit local routing limits for deterministic failures.
    pub fn with_router_config(config: MessageRouterConfig) -> Self {
        Self {
            router: LocalMessageRouter::with_config(config),
            authority_ledger: InMemoryDelegationAuthorityLedger::new(),
            lifecycle: Mutex::new(()),
            state: Mutex::new(LocalDelegationState::default()),
        }
    }

    /// Returns the local router used for task request/response messages.
    pub fn router(&self) -> &LocalMessageRouter {
        &self.router
    }

    /// Registers an agent and its maximum local delegation authority.
    pub fn register_agent(
        &self,
        agent: AgentContext,
        authority: DelegatedAuthority,
    ) -> Result<(), LocalDelegationError> {
        self.register_agent_with_principal(agent, PrincipalId::new(), authority)
    }

    /// Registers an agent, principal binding, and maximum local delegation authority.
    pub fn register_agent_with_principal(
        &self,
        agent: AgentContext,
        principal_id: PrincipalId,
        authority: DelegatedAuthority,
    ) -> Result<(), LocalDelegationError> {
        self.router.register_agent_context(&agent)?;
        let mut state = self.lock_state()?;
        state.agents.insert(
            agent.agent_id.clone(),
            LocalAgentRegistration {
                agent,
                principal_id,
                authority,
            },
        );
        Ok(())
    }

    /// Registers an active root/parent run without replacing any existing run.
    pub fn register_root_run(
        &self,
        run_id: RunId,
        agent_id: AgentId,
    ) -> Result<LocalRunRecord, LocalDelegationError> {
        let _lifecycle = self.lock_lifecycle()?;
        let mut state = self.lock_state()?;
        if state.runs.contains_key(&run_id) {
            return Err(LocalDelegationError::DuplicateRun(run_id));
        }
        let agent = state
            .agents
            .get(&agent_id)
            .ok_or_else(|| LocalDelegationError::UnknownAgent(agent_id.clone()))?;
        let record = LocalRunRecord {
            run_id: run_id.clone(),
            agent_id: agent.agent.agent_id.clone(),
            principal_id: agent.principal_id.clone(),
            tenant_id: agent.agent.tenant_id.clone(),
            parent_run_id: None,
            child_run_ids: Vec::new(),
            authority: agent.authority.clone(),
            capability_grant_id: None,
            authority_evidence: None,
            delegation_chain_digest: None,
            objective: None,
            parent_trace_id: None,
            status: LocalRunStatus::Running,
            request_message_id: None,
            response_message_id: None,
        };
        state.runs.insert(run_id, record.clone());
        Ok(record)
    }

    /// Binds a registered root run to one trusted validated capability grant.
    ///
    /// The manager privately retains the exact validated grant, including its
    /// trust marker, while the public run record exposes only the grant ID for
    /// evidence. The grant subject must equal the run's immutable principal
    /// snapshot. A same-run/exact-grant retry is idempotent; different validated
    /// content for the same run or grant-ID reuse by another run fails closed.
    /// Child runs are bound automatically when authority issuance succeeds and
    /// must not call this trusted local run-admission API.
    pub fn bind_root_run_capability_grant(
        &self,
        run_id: &RunId,
        grant: &ValidatedCapabilityGrant,
    ) -> Result<LocalRunRecord, LocalDelegationError> {
        let _lifecycle = self.lock_lifecycle()?;
        let mut state = self.lock_state()?;
        let run = state
            .runs
            .get(run_id)
            .cloned()
            .ok_or_else(|| LocalDelegationError::UnknownParentRun(run_id.clone()))?;
        if run.parent_run_id.is_some() {
            return Err(LocalDelegationError::ParentGrantBindingRequiresRootRun(
                run_id.clone(),
            ));
        }

        let grant_id = grant.grant().grant_id.clone();
        if grant.grant().subject != run.principal_id {
            return Err(LocalDelegationError::ParentRunGrantSubjectMismatch {
                run_id: run_id.clone(),
                run_principal_id: run.principal_id,
                grant_subject_id: grant.grant().subject.clone(),
            });
        }
        if let Some(bound_caller) = state.run_callers.get(run_id) {
            if bound_caller.matches_validated_grant(grant) {
                return Ok(run);
            }
            return Err(LocalDelegationError::ParentRunGrantBindingConflict {
                run_id: run_id.clone(),
                bound_grant_id: bound_caller.grant_id().clone(),
                supplied_grant_id: grant_id,
            });
        }
        if let Some((bound_run_id, _)) =
            state.run_callers.iter().find(|(candidate_run_id, bound)| {
                *candidate_run_id != run_id && bound.grant_id() == &grant_id
            })
        {
            return Err(LocalDelegationError::CapabilityGrantRunBindingConflict {
                grant_id,
                bound_run_id: bound_run_id.clone(),
                requested_run_id: run_id.clone(),
            });
        }

        let child_bindings = exact_child_bindings_from_grant(grant)
            .map_err(|reason| LocalDelegationError::AuthorityDenied { reason })?;
        let caller = self
            .authority_ledger
            .register_root_runtime_with_child_bindings(
                grant,
                run.tenant_id.clone(),
                run.agent_id.clone(),
                run.run_id.clone(),
                child_bindings,
            )
            .map_err(|error| LocalDelegationError::AuthorityDenied {
                reason: error.reason_code(),
            })?;

        let run = state
            .runs
            .get_mut(run_id)
            .ok_or_else(|| LocalDelegationError::UnknownParentRun(run_id.clone()))?;
        run.capability_grant_id = Some(grant_id);
        let run = run.clone();
        state.run_callers.insert(run_id.clone(), caller);
        Ok(run)
    }

    /// Returns the opaque manager-issued caller for one bound active run.
    pub fn delegation_caller_handle(
        &self,
        run_id: &RunId,
    ) -> Result<DelegationCallerHandle, LocalDelegationError> {
        self.lock_state()?
            .run_callers
            .get(run_id)
            .cloned()
            .ok_or_else(|| LocalDelegationError::AuthorityDenied {
                reason: REASON_MISSING_PARENT_RUN_GRANT_BINDING.to_string(),
            })
    }

    /// Creates a child run from an explicit target, objective, and delegated scope.
    pub fn create_child_run(
        &self,
        parent_recorder: &dyn MessageTraceRecorder,
        child_recorder: &dyn MessageTraceRecorder,
        request: LocalDelegationRequest,
        authority: LocalDelegationAuthority,
    ) -> Result<LocalChildRun, LocalDelegationError> {
        let _lifecycle = self.lock_lifecycle()?;
        ensure_recorder_run(parent_recorder, &request.parent_run_id)?;
        ensure_recorder_run(child_recorder, &request.child_run_id)?;
        let mut trace_context = request.trace_context();

        let (parent_run, parent_bound_caller, target_agent, duplicate_child_run) = {
            let state = self.lock_state()?;
            let parent_run = state
                .runs
                .get(&request.parent_run_id)
                .cloned()
                .ok_or_else(|| {
                    LocalDelegationError::UnknownParentRun(request.parent_run_id.clone())
                })?;
            let parent_bound_caller = state.run_callers.get(&request.parent_run_id).cloned();
            let target_agent = state
                .agents
                .get(&request.target_agent_id)
                .cloned()
                .ok_or_else(|| {
                    LocalDelegationError::UnknownAgent(request.target_agent_id.clone())
                })?;
            let duplicate_child_run = state.runs.contains_key(&request.child_run_id)
                || state
                    .consumed_child_runs
                    .contains_key(&request.child_run_id);
            (
                parent_run,
                parent_bound_caller,
                target_agent,
                duplicate_child_run,
            )
        };

        if parent_run.status == LocalRunStatus::Cancelled {
            let reason = "parent_run_cancelled".to_string();
            parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                delegation: trace_context,
                reason,
            })?;
            return Err(LocalDelegationError::ParentCancelled(request.parent_run_id));
        }
        if duplicate_child_run {
            parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                delegation: trace_context,
                reason: "duplicate_child_run_id".to_string(),
            })?;
            return Err(LocalDelegationError::DuplicateChildRun(
                request.child_run_id,
            ));
        }
        if parent_run.agent_id != request.source_agent_id {
            return Err(LocalDelegationError::SourceAgentMismatch);
        }
        if parent_run.tenant_id != target_agent.agent.tenant_id {
            parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                delegation: trace_context,
                reason: "target_agent_tenant_mismatch".to_string(),
            })?;
            return Err(LocalDelegationError::TenantMismatch);
        }
        let effective_parent_caller =
            match resolve_parent_caller(parent_bound_caller.as_ref(), &parent_run, &authority) {
                Ok(caller) => caller,
                Err(reason) => {
                    let reason = reason.to_string();
                    parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                        delegation: trace_context,
                        reason: reason.clone(),
                    })?;
                    return Err(LocalDelegationError::AuthorityDenied { reason });
                }
            };
        if !request
            .delegated_authority
            .is_subset_of(&parent_run.authority)
        {
            parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                delegation: trace_context,
                reason: "delegated_authority_exceeds_parent_scope".to_string(),
            })?;
            return Err(LocalDelegationError::DelegatedAuthorityDenied { scope: "parent" });
        }
        if !request
            .delegated_authority
            .is_subset_of(&target_agent.authority)
        {
            parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                delegation: trace_context,
                reason: "delegated_authority_exceeds_target_scope".to_string(),
            })?;
            return Err(LocalDelegationError::DelegatedAuthorityDenied { scope: "target" });
        }

        let authority_evidence = LocalDelegationAuthorityEvidence::issued(
            effective_parent_caller.grant_id().clone(),
            CapabilityGrantId::new(),
        );
        trace_context = trace_context.with_authority_evidence(authority_evidence.clone());
        // Build and validate every fallible workload/message payload before the
        // authority ledger reserves subtree budget or fan-out.
        let task_request_payload = serde_json::to_value(
            TaskRequest::new_with_grant_ref(
                request.parent_run_id.clone(),
                request.child_run_id.clone(),
                request.target_agent_id.clone(),
                request.objective.clone(),
                request.delegated_authority.clone(),
                authority_evidence.child_capability_grant_id.clone(),
            )?
            .with_authority_evidence(authority_evidence.clone())?,
        )
        .map_err(|error| MessageValidationError::PayloadValidationFailed {
            schema: TASK_REQUEST_SCHEMA.to_string(),
            reason: error.to_string(),
        })?;

        let decision_time = OffsetDateTime::now_utc();

        let reservation = match self.authority_ledger.reserve_child(
            &effective_parent_caller,
            delegation_child_grant_request(
                &parent_run,
                &target_agent,
                &request,
                &authority,
                &authority_evidence,
            ),
            decision_time,
            authority.audience.clone(),
            target_agent.principal_id.clone(),
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                let reason = error.reason_code();
                parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                    delegation: trace_context
                        .clone()
                        .with_authority_evidence(authority_evidence.denied(reason.clone())),
                    reason: reason.clone(),
                })?;
                return Err(LocalDelegationError::AuthorityDenied { reason });
            }
        };
        let issued_child_grant = reservation.delegation_grant();
        if let Some(reason) = child_grant_liveness_denial_raw(
            &issued_child_grant.child_capability_grant,
            decision_time,
        ) {
            let reason = reason.to_string();
            let released = self
                .authority_ledger
                .release(&reservation, reason.clone())
                .map_err(|ledger_error| LocalDelegationError::AuthorityDenied {
                    reason: ledger_error.reason_code(),
                })?;
            parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                delegation: trace_context
                    .clone()
                    .with_authority_evidence(authority_evidence.clone().denied(reason.clone()))
                    .with_delegation_ledger(released.redacted_trace_summary()),
                reason: reason.clone(),
            })?;
            return Err(LocalDelegationError::AuthorityDenied { reason });
        }
        let issued_evidence = LocalDelegationAuthorityEvidence::issued(
            issued_child_grant.parent_grant_id.clone(),
            issued_child_grant.child_capability_grant.grant_id.clone(),
        );
        trace_context = trace_context
            .with_authority_evidence(issued_evidence.clone())
            .with_delegation_ledger(reservation.evidence().redacted_trace_summary());

        let requested_trace =
            match parent_recorder.record_message_event(TraceEventKind::DelegationRequested {
                delegation: trace_context.clone(),
            }) {
                Ok(trace_id) => trace_id,
                Err(error) => {
                    self.authority_ledger
                        .release(&reservation, "delegation_requested_trace_failed")
                        .map_err(|ledger_error| LocalDelegationError::AuthorityDenied {
                            reason: ledger_error.reason_code(),
                        })?;
                    return Err(LocalDelegationError::Router(error));
                }
            };
        trace_context = trace_context.with_parent_trace(requested_trace.clone());

        let request_message = Message::new(
            MessageId::new(),
            request.source_agent_id.clone(),
            request.target_agent_id.clone(),
            request.parent_run_id.clone(),
            TASK_REQUEST_SCHEMA,
            task_request_payload,
            Some(requested_trace.clone()),
            true,
            OffsetDateTime::now_utc(),
        )?;
        let request_message_id = request_message.message_id.clone();
        let request_envelope = MessageEnvelope::new(request_message)?;
        let routed_request = match self.router.send(parent_recorder, request_envelope) {
            Ok(routed) => routed,
            Err(error) => {
                let reason = format!("routing_failed:{error}");
                let consumed = self
                    .authority_ledger
                    .consume_after_routing_failure(&reservation, reason.clone())
                    .map_err(|ledger_error| LocalDelegationError::AuthorityDenied {
                        reason: ledger_error.reason_code(),
                    })?;
                self.mark_child_run_consumed(&request.child_run_id, reason.clone())?;
                parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                    delegation: trace_context
                        .clone()
                        .with_delegation_ledger(consumed.redacted_trace_summary()),
                    reason,
                })?;
                return Err(LocalDelegationError::Router(error));
            }
        };
        trace_context = trace_context.with_request_message(request_message_id.clone());

        let committed = match self.authority_ledger.commit(&reservation) {
            Ok(committed) => committed,
            Err(error) => {
                let reason = error.reason_code();
                let _ = self
                    .authority_ledger
                    .consume_after_routing_failure(&reservation, reason.clone());
                self.mark_child_run_consumed(&request.child_run_id, reason.clone())?;
                return Err(LocalDelegationError::AuthorityDenied { reason });
            }
        };
        trace_context =
            trace_context.with_delegation_ledger(committed.evidence.redacted_trace_summary());

        let child_started_trace =
            match child_recorder.record_message_event(TraceEventKind::ChildRunStarted {
                delegation: trace_context.clone(),
            }) {
                Ok(trace_id) => trace_id,
                Err(error) => {
                    let reason = format!("child_start_trace_failed:{error}");
                    let consumed = self
                        .authority_ledger
                        .consume_after_routing_failure(&reservation, reason.clone())
                        .map_err(|ledger_error| LocalDelegationError::AuthorityDenied {
                            reason: ledger_error.reason_code(),
                        })?;
                    self.mark_child_run_consumed(&request.child_run_id, reason.clone())?;
                    parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                        delegation: trace_context
                            .clone()
                            .with_delegation_ledger(consumed.redacted_trace_summary()),
                        reason,
                    })?;
                    return Err(LocalDelegationError::Router(error));
                }
            };

        let mut child_agent = target_agent.agent.clone();
        child_agent.set_delegated_runtime_authority(
            committed.runtime_authority,
            request.delegated_authority.clone(),
        );
        let child_record = LocalRunRecord {
            run_id: request.child_run_id.clone(),
            agent_id: request.target_agent_id.clone(),
            principal_id: target_agent.principal_id.clone(),
            tenant_id: parent_run.tenant_id.clone(),
            parent_run_id: Some(request.parent_run_id.clone()),
            child_run_ids: Vec::new(),
            authority: request.delegated_authority,
            capability_grant_id: Some(issued_evidence.child_capability_grant_id.clone()),
            authority_evidence: Some(issued_evidence),
            delegation_chain_digest: Some(
                reservation.evidence().redacted_trace_summary().chain_digest,
            ),
            objective: Some(request.objective),
            parent_trace_id: Some(requested_trace),
            status: LocalRunStatus::Running,
            request_message_id: Some(request_message_id),
            response_message_id: None,
        };

        let mut state = self.lock_state()?;
        state
            .runs
            .get_mut(&request.parent_run_id)
            .ok_or_else(|| LocalDelegationError::UnknownParentRun(request.parent_run_id.clone()))?
            .child_run_ids
            .push(request.child_run_id.clone());
        state
            .runs
            .insert(request.child_run_id, child_record.clone());
        state
            .run_callers
            .insert(child_record.run_id.clone(), committed.caller.clone());

        Ok(LocalChildRun {
            run: child_record,
            child_agent,
            request_message: routed_request,
            child_started_trace_id: child_started_trace,
            child_caller: committed.caller,
        })
    }

    /// Completes a child run and sends a structured task response to the parent.
    pub fn complete_child_run(
        &self,
        parent_recorder: &dyn MessageTraceRecorder,
        child_recorder: &dyn MessageTraceRecorder,
        child_run_id: &RunId,
        output: serde_json::Value,
    ) -> Result<LocalTaskResponse, LocalDelegationError> {
        self.finish_child_run(
            parent_recorder,
            child_recorder,
            child_run_id,
            TaskResponseStatus::Completed,
            Some(output),
            None,
        )
    }

    /// Fails a child run and sends a structured task response to the parent.
    pub fn fail_child_run(
        &self,
        parent_recorder: &dyn MessageTraceRecorder,
        child_recorder: &dyn MessageTraceRecorder,
        child_run_id: &RunId,
        failure: TaskFailure,
    ) -> Result<LocalTaskResponse, LocalDelegationError> {
        self.finish_child_run(
            parent_recorder,
            child_recorder,
            child_run_id,
            TaskResponseStatus::Failed,
            None,
            Some(failure),
        )
    }

    /// Cancels an active child run when its recorded parent or child capability
    /// grant has been revoked by the trusted live local authority snapshot, or
    /// when snapshot liveness cannot be established.
    ///
    /// This consumes run-record authority evidence only. Message payloads and
    /// metadata remain non-authorizing and are not inspected. Unrelated
    /// revocations and terminal child runs are deterministic no-ops. Stale or
    /// future-dated snapshots fail closed by cancelling authority-backed active
    /// child runs with the authority-owned snapshot reason code. A record known
    /// to be a child but missing authority evidence also cancels fail-closed.
    pub fn cancel_child_if_authority_revoked(
        &self,
        parent_recorder: &dyn MessageTraceRecorder,
        child_recorder: &dyn MessageTraceRecorder,
        child_run_id: &RunId,
        revocations: &RevocationSnapshot,
    ) -> Result<Option<LocalTaskResponse>, LocalDelegationError> {
        let _lifecycle = self.lock_lifecycle()?;
        let now = OffsetDateTime::now_utc();
        let cancellation = {
            let state = self.lock_state()?;
            let child = state
                .runs
                .get(child_run_id)
                .ok_or_else(|| LocalDelegationError::UnknownChildRun(child_run_id.clone()))?;
            if child.status.is_terminal() || child.response_message_id.is_some() {
                return Ok(None);
            }
            if let Some(evidence) = child.authority_evidence.as_ref() {
                match revocations.revokes_grant_id_at(&evidence.parent_capability_grant_id, now) {
                    Err(error) => Some((
                        error.reason_code().to_string(),
                        evidence.child_capability_grant_id.clone(),
                    )),
                    Ok(true) => Some((
                        REASON_AUTHORITY_GRANT_REVOKED.to_string(),
                        evidence.parent_capability_grant_id.clone(),
                    )),
                    Ok(false) => match revocations
                        .revokes_grant_id_at(&evidence.child_capability_grant_id, now)
                    {
                        Err(error) => Some((
                            error.reason_code().to_string(),
                            evidence.child_capability_grant_id.clone(),
                        )),
                        Ok(true) => Some((
                            REASON_AUTHORITY_GRANT_REVOKED.to_string(),
                            evidence.child_capability_grant_id.clone(),
                        )),
                        Ok(false) => None,
                    },
                }
            } else if child.parent_run_id.is_some() {
                child
                    .capability_grant_id
                    .clone()
                    .map(|grant_id| (REASON_MISSING_AUTHORITY_EVIDENCE.to_string(), grant_id))
            } else {
                None
            }
        };
        let Some((cancellation_reason, revoked_grant_id)) = cancellation else {
            return Ok(None);
        };

        let revoked = self
            .authority_ledger
            .revoke_subtree(&revoked_grant_id, cancellation_reason.clone())
            .map_err(|error| LocalDelegationError::AuthorityDenied {
                reason: error.reason_code(),
            })?;

        let mut descendant_events = Vec::new();
        {
            let mut state = self.lock_state()?;
            for evidence in &revoked {
                if let Some(edge) = evidence.chain.grants.last() {
                    if let Some(run) = state.runs.get_mut(&edge.child_run_id) {
                        if !run.status.is_terminal() {
                            run.status = LocalRunStatus::Cancelled;
                            if edge.child_run_id != *child_run_id {
                                descendant_events.push((run.clone(), evidence.clone()));
                            }
                        }
                    }
                }
            }
        }

        for (descendant, evidence) in descendant_events {
            let parent = self.run(descendant.parent_run_id.as_ref().ok_or_else(|| {
                LocalDelegationError::UnknownParentRun(descendant.run_id.clone())
            })?)?;
            parent_recorder.record_message_event(TraceEventKind::ChildRunFailed {
                delegation: LocalDelegationTraceContext {
                    parent_run_id: parent.run_id,
                    child_run_id: descendant.run_id,
                    parent_trace_id: descendant.parent_trace_id,
                    request_message_id: descendant.request_message_id,
                    response_message_id: None,
                    source_agent_id: parent.agent_id,
                    target_agent_id: descendant.agent_id,
                    objective: descendant.objective.unwrap_or_default(),
                    authority_evidence: descendant.authority_evidence,
                    delegation_ledger: Some(evidence.redacted_trace_summary()),
                },
                failure: revocation_cancellation_failure(cancellation_reason.clone()),
            })?;
        }

        self.cancel_child_run_for_revocation_with_lifecycle(
            parent_recorder,
            child_recorder,
            child_run_id,
            revocation_cancellation_failure(cancellation_reason),
            revoked.into_iter().find(|evidence| {
                evidence
                    .chain
                    .grants
                    .last()
                    .is_some_and(|edge| edge.child_run_id == *child_run_id)
            }),
        )
        .map(Some)
    }

    /// Cancels a parent run and records the cancellation trace event.
    pub fn cancel_parent_run(
        &self,
        parent_recorder: &dyn MessageTraceRecorder,
        parent_run_id: &RunId,
        reason: impl Into<String>,
    ) -> Result<TraceId, LocalDelegationError> {
        let _lifecycle = self.lock_lifecycle()?;
        ensure_recorder_run(parent_recorder, parent_run_id)?;
        let reason = reason.into();
        let mut state = self.lock_state()?;
        let parent = state
            .runs
            .get_mut(parent_run_id)
            .ok_or_else(|| LocalDelegationError::UnknownParentRun(parent_run_id.clone()))?;
        parent.status = LocalRunStatus::Cancelled;
        let agent_id = parent.agent_id.clone();
        let root_grant_id = parent.capability_grant_id.clone();
        let revoked = if let Some(grant_id) = root_grant_id.as_ref() {
            self.authority_ledger
                .revoke_subtree(grant_id, reason.clone())
                .map_err(|error| LocalDelegationError::AuthorityDenied {
                    reason: error.reason_code(),
                })?
        } else {
            Vec::new()
        };
        let mut descendant_events = Vec::new();
        for evidence in revoked {
            let Some(edge) = evidence.chain.grants.last() else {
                continue;
            };
            if let Some(child) = state.runs.get_mut(&edge.child_run_id) {
                if child.status.is_terminal() {
                    continue;
                }
                child.status = LocalRunStatus::Cancelled;
                descendant_events.push((child.clone(), evidence));
            }
        }
        drop(state);
        let cancellation_trace =
            parent_recorder.record_message_event(TraceEventKind::ParentRunCancelled {
                parent_run_id: parent_run_id.clone(),
                agent_id,
                reason: reason.clone(),
            })?;
        for (child, evidence) in descendant_events {
            let parent =
                self.run(child.parent_run_id.as_ref().ok_or_else(|| {
                    LocalDelegationError::UnknownParentRun(child.run_id.clone())
                })?)?;
            parent_recorder.record_message_event(TraceEventKind::ChildRunFailed {
                delegation: LocalDelegationTraceContext {
                    parent_run_id: parent.run_id,
                    child_run_id: child.run_id,
                    parent_trace_id: Some(cancellation_trace.clone()),
                    request_message_id: child.request_message_id,
                    response_message_id: None,
                    source_agent_id: parent.agent_id,
                    target_agent_id: child.agent_id,
                    objective: child.objective.unwrap_or_default(),
                    authority_evidence: child.authority_evidence,
                    delegation_ledger: Some(evidence.redacted_trace_summary()),
                },
                failure: TaskFailure::new("parent_run_cancelled", reason.clone(), false),
            })?;
        }
        Ok(cancellation_trace)
    }

    /// Returns a run record snapshot.
    pub fn run(&self, run_id: &RunId) -> Result<LocalRunRecord, LocalDelegationError> {
        self.lock_state()?
            .runs
            .get(run_id)
            .cloned()
            .ok_or_else(|| LocalDelegationError::UnknownChildRun(run_id.clone()))
    }

    fn finish_child_run(
        &self,
        parent_recorder: &dyn MessageTraceRecorder,
        child_recorder: &dyn MessageTraceRecorder,
        child_run_id: &RunId,
        status: TaskResponseStatus,
        output: Option<serde_json::Value>,
        failure: Option<TaskFailure>,
    ) -> Result<LocalTaskResponse, LocalDelegationError> {
        let _lifecycle = self.lock_lifecycle()?;
        self.finish_child_run_with_lifecycle(
            parent_recorder,
            child_recorder,
            child_run_id,
            status,
            output,
            failure,
        )
    }

    fn finish_child_run_with_lifecycle(
        &self,
        parent_recorder: &dyn MessageTraceRecorder,
        child_recorder: &dyn MessageTraceRecorder,
        child_run_id: &RunId,
        status: TaskResponseStatus,
        output: Option<serde_json::Value>,
        failure: Option<TaskFailure>,
    ) -> Result<LocalTaskResponse, LocalDelegationError> {
        ensure_recorder_run(child_recorder, child_run_id)?;
        let (child, parent) =
            {
                let state = self.lock_state()?;
                let child =
                    state.runs.get(child_run_id).cloned().ok_or_else(|| {
                        LocalDelegationError::UnknownChildRun(child_run_id.clone())
                    })?;
                if child.status.is_terminal() || child.response_message_id.is_some() {
                    return Err(LocalDelegationError::ChildRunAlreadyFinished {
                        child_run_id: child_run_id.clone(),
                        status: child.status,
                    });
                }
                let parent_run_id = child
                    .parent_run_id
                    .clone()
                    .ok_or_else(|| LocalDelegationError::UnknownParentRun(child_run_id.clone()))?;
                let parent =
                    state.runs.get(&parent_run_id).cloned().ok_or_else(|| {
                        LocalDelegationError::UnknownParentRun(parent_run_id.clone())
                    })?;
                (child, parent)
            };
        ensure_recorder_run(parent_recorder, &parent.run_id)?;
        let mut context = LocalDelegationTraceContext {
            parent_run_id: parent.run_id.clone(),
            child_run_id: child.run_id.clone(),
            parent_trace_id: None,
            request_message_id: child.request_message_id.clone(),
            response_message_id: None,
            source_agent_id: parent.agent_id.clone(),
            target_agent_id: child.agent_id.clone(),
            objective: child.objective.clone().unwrap_or_default(),
            authority_evidence: child.authority_evidence.clone(),
            delegation_ledger: None,
        };
        context.parent_trace_id = child.parent_trace_id.clone();
        if let Some(grant_id) = child.capability_grant_id.as_ref() {
            let cleanup = self
                .authority_ledger
                .cleanup(grant_id, format!("child_{status:?}").to_lowercase())
                .map_err(|error| LocalDelegationError::AuthorityDenied {
                    reason: error.reason_code(),
                })?;
            context = context.with_delegation_ledger(cleanup.redacted_trace_summary());
        }

        let child_trace_result = match status {
            TaskResponseStatus::Completed => {
                child_recorder.record_message_event(TraceEventKind::ChildRunCompleted {
                    delegation: context.clone(),
                })
            }
            TaskResponseStatus::Failed
            | TaskResponseStatus::Denied
            | TaskResponseStatus::Cancelled => {
                let failure_for_trace = failure
                    .clone()
                    .unwrap_or_else(|| TaskFailure::new("child_failed", "child run failed", false));
                child_recorder.record_message_event(TraceEventKind::ChildRunFailed {
                    delegation: context.clone(),
                    failure: failure_for_trace,
                })
            }
        };
        let child_trace_id = match child_trace_result {
            Ok(trace_id) => trace_id,
            Err(error) => {
                let reason = format!("child_cleanup_trace_failed:{error}");
                if let Some(grant_id) = child.capability_grant_id.as_ref() {
                    let retained = self
                        .authority_ledger
                        .retain_after_cleanup_trace_failure(grant_id, reason.clone())
                        .map_err(|ledger_error| LocalDelegationError::AuthorityDenied {
                            reason: ledger_error.reason_code(),
                        })?;
                    context = context.with_delegation_ledger(retained.redacted_trace_summary());
                }
                if let Some(child_record) = self.lock_state()?.runs.get_mut(child_run_id) {
                    child_record.status = LocalRunStatus::Cancelled;
                }
                parent_recorder.record_message_event(TraceEventKind::ChildRunFailed {
                    delegation: context,
                    failure: TaskFailure::new("child_cleanup_trace_failed", reason, false),
                })?;
                return Err(LocalDelegationError::Router(error));
            }
        };

        // Cleanup and its child-side trace are durable before response routing.
        // A routing/parent-trace failure therefore cannot leave the child active.
        if let Some(child_record) = self.lock_state()?.runs.get_mut(child_run_id) {
            child_record.status = match status {
                TaskResponseStatus::Completed => LocalRunStatus::Completed,
                TaskResponseStatus::Failed => LocalRunStatus::Failed,
                TaskResponseStatus::Denied => LocalRunStatus::Denied,
                TaskResponseStatus::Cancelled => LocalRunStatus::Cancelled,
            };
        }

        let failure = failure.map(|failure| failure.with_trace_id(child_trace_id.clone()));
        let response = TaskResponse::new(
            parent.run_id.clone(),
            child.run_id.clone(),
            status,
            output,
            failure.clone(),
        )?;
        let response_message = Message::new(
            MessageId::new(),
            child.agent_id.clone(),
            parent.agent_id.clone(),
            parent.run_id.clone(),
            TASK_RESPONSE_SCHEMA,
            serde_json::to_value(response.clone()).map_err(|error| {
                MessageValidationError::PayloadValidationFailed {
                    schema: TASK_RESPONSE_SCHEMA.to_string(),
                    reason: error.to_string(),
                }
            })?,
            Some(child_trace_id.clone()),
            false,
            OffsetDateTime::now_utc(),
        )?;
        let response_message_id = response_message.message_id.clone();
        let routed_response = self
            .router
            .send(parent_recorder, MessageEnvelope::new(response_message)?)?;
        context = context.with_response_message(response_message_id.clone());

        let parent_trace_id = match status {
            TaskResponseStatus::Completed => {
                parent_recorder.record_message_event(TraceEventKind::ChildRunCompleted {
                    delegation: context,
                })?
            }
            TaskResponseStatus::Failed
            | TaskResponseStatus::Denied
            | TaskResponseStatus::Cancelled => {
                parent_recorder.record_message_event(TraceEventKind::ChildRunFailed {
                    delegation: context,
                    failure: failure.clone().unwrap_or_else(|| {
                        TaskFailure::new("child_failed", "child run failed", false)
                    }),
                })?
            }
        };

        let mut state = self.lock_state()?;
        if let Some(child_record) = state.runs.get_mut(child_run_id) {
            child_record.response_message_id = Some(response_message_id);
        }

        Ok(LocalTaskResponse {
            response,
            response_message: routed_response,
            parent_trace_id,
            child_trace_id,
        })
    }

    fn cancel_child_run_for_revocation_with_lifecycle(
        &self,
        parent_recorder: &dyn MessageTraceRecorder,
        child_recorder: &dyn MessageTraceRecorder,
        child_run_id: &RunId,
        failure: TaskFailure,
        ledger_evidence: Option<DelegationLedgerEvidence>,
    ) -> Result<LocalTaskResponse, LocalDelegationError> {
        let (child, parent) =
            {
                let mut state = self.lock_state()?;
                let child =
                    state.runs.get(child_run_id).cloned().ok_or_else(|| {
                        LocalDelegationError::UnknownChildRun(child_run_id.clone())
                    })?;
                if (child.status.is_terminal() && child.status != LocalRunStatus::Cancelled)
                    || child.response_message_id.is_some()
                {
                    return Err(LocalDelegationError::ChildRunAlreadyFinished {
                        child_run_id: child_run_id.clone(),
                        status: child.status,
                    });
                }
                let parent_run_id = child
                    .parent_run_id
                    .clone()
                    .ok_or_else(|| LocalDelegationError::UnknownParentRun(child_run_id.clone()))?;
                let parent =
                    state.runs.get(&parent_run_id).cloned().ok_or_else(|| {
                        LocalDelegationError::UnknownParentRun(parent_run_id.clone())
                    })?;
                if let Some(child_record) = state.runs.get_mut(child_run_id) {
                    child_record.status = LocalRunStatus::Cancelled;
                }
                (child, parent)
            };

        ensure_recorder_run(child_recorder, child_run_id)?;
        ensure_recorder_run(parent_recorder, &parent.run_id)?;
        let mut context = LocalDelegationTraceContext {
            parent_run_id: parent.run_id.clone(),
            child_run_id: child.run_id.clone(),
            parent_trace_id: child.parent_trace_id.clone(),
            request_message_id: child.request_message_id.clone(),
            response_message_id: None,
            source_agent_id: parent.agent_id.clone(),
            target_agent_id: child.agent_id.clone(),
            objective: child.objective.clone().unwrap_or_default(),
            authority_evidence: child.authority_evidence.clone(),
            delegation_ledger: None,
        };
        if let Some(ledger_evidence) = ledger_evidence {
            context = context.with_delegation_ledger(ledger_evidence.redacted_trace_summary());
        }

        let child_trace_id =
            child_recorder.record_message_event(TraceEventKind::ChildRunFailed {
                delegation: context.clone(),
                failure: failure.clone(),
            })?;
        let failure = failure.with_trace_id(child_trace_id.clone());
        let response = TaskResponse::new(
            parent.run_id.clone(),
            child.run_id.clone(),
            TaskResponseStatus::Cancelled,
            None,
            Some(failure.clone()),
        )?;
        let response_message = Message::new(
            MessageId::new(),
            child.agent_id.clone(),
            parent.agent_id.clone(),
            parent.run_id.clone(),
            TASK_RESPONSE_SCHEMA,
            serde_json::to_value(response.clone()).map_err(|error| {
                MessageValidationError::PayloadValidationFailed {
                    schema: TASK_RESPONSE_SCHEMA.to_string(),
                    reason: error.to_string(),
                }
            })?,
            Some(child_trace_id.clone()),
            false,
            OffsetDateTime::now_utc(),
        )?;
        let response_message_id = response_message.message_id.clone();
        let routed_response = self
            .router
            .send(parent_recorder, MessageEnvelope::new(response_message)?)?;

        {
            let mut state = self.lock_state()?;
            if let Some(child_record) = state.runs.get_mut(child_run_id) {
                child_record.response_message_id = Some(response_message_id.clone());
            }
        }
        context = context.with_response_message(response_message_id);

        let parent_trace_id =
            parent_recorder.record_message_event(TraceEventKind::ChildRunFailed {
                delegation: context,
                failure,
            })?;

        Ok(LocalTaskResponse {
            response,
            response_message: routed_response,
            parent_trace_id,
            child_trace_id,
        })
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, LocalDelegationState>, LocalDelegationError> {
        self.state
            .lock()
            .map_err(|_| LocalDelegationError::StorageUnavailable)
    }

    fn mark_child_run_consumed(
        &self,
        child_run_id: &RunId,
        reason: String,
    ) -> Result<(), LocalDelegationError> {
        self.lock_state()?
            .consumed_child_runs
            .entry(child_run_id.clone())
            .or_insert(reason);
        Ok(())
    }

    fn lock_lifecycle(&self) -> Result<std::sync::MutexGuard<'_, ()>, LocalDelegationError> {
        self.lifecycle
            .lock()
            .map_err(|_| LocalDelegationError::StorageUnavailable)
    }
}

fn exact_child_bindings_from_grant(
    grant: &ValidatedCapabilityGrant,
) -> Result<Vec<(AgentId, RunId)>, String> {
    let agents = grant
        .grant()
        .scope
        .agent_ids
        .as_ref()
        .ok_or_else(|| "delegation_child_runtime_binding_denied".to_string())?;
    let runs = grant
        .grant()
        .scope
        .run_ids
        .as_ref()
        .ok_or_else(|| "delegation_child_runtime_binding_denied".to_string())?;
    if agents.is_empty() || agents.len() != runs.len() {
        return Err("delegation_child_runtime_binding_denied".to_string());
    }
    let bindings = agents
        .iter()
        .cloned()
        .zip(runs.iter().cloned())
        .collect::<Vec<_>>();
    let mut seen = std::collections::HashSet::new();
    if bindings.iter().any(|binding| !seen.insert(binding.clone())) {
        return Err("delegation_child_runtime_binding_denied".to_string());
    }
    Ok(bindings)
}

impl Default for LocalDelegationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Replay summary for local delegation relationships and task messages.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LocalDelegationReplay {
    /// Parent/child edges reconstructed from delegation trace events.
    pub delegations: Vec<LocalDelegationTraceContext>,
    /// Task request/response message contexts seen during replay.
    pub messages: Vec<MessageTraceContext>,
    /// Structured child failures seen during replay.
    pub failures: Vec<TaskFailure>,
    /// Rejected delegation contexts with their stable denial reasons.
    pub rejections: Vec<LocalDelegationRejection>,
    /// Ordered authority chain/reservation/cleanup/revocation ledger transitions.
    pub ledger_events: Vec<DelegationLedgerTraceSummary>,
}

/// Inspect-only replay evidence for one rejected local delegation.
#[derive(Clone, Debug, PartialEq)]
pub struct LocalDelegationRejection {
    /// Parent/child and authority-evidence context recorded with the rejection.
    pub delegation: LocalDelegationTraceContext,
    /// Stable fail-closed reason recorded by the manager.
    pub reason: String,
}

/// Reconstructs parent/child causal relationships and task message exchange from
/// trace events without executing policies, adapters, or child runs.
pub fn replay_local_delegations(events: &[TraceEvent]) -> LocalDelegationReplay {
    let mut replay = LocalDelegationReplay::default();
    let mut seen_delegations: Vec<(RunId, RunId)> = Vec::new();
    let mut seen_messages = Vec::new();
    for event in events {
        match &event.kind {
            TraceEventKind::DelegationRequested { delegation }
            | TraceEventKind::ChildRunStarted { delegation }
            | TraceEventKind::ChildRunCompleted { delegation } => {
                if let Some(evidence) = delegation.delegation_ledger.clone() {
                    replay.ledger_events.push(evidence);
                }
                let key = (
                    delegation.parent_run_id.clone(),
                    delegation.child_run_id.clone(),
                );
                if !seen_delegations.contains(&key) {
                    seen_delegations.push(key);
                    replay.delegations.push(delegation.clone());
                } else if let Some(existing) = replay.delegations.iter_mut().find(|existing| {
                    existing.parent_run_id == delegation.parent_run_id
                        && existing.child_run_id == delegation.child_run_id
                }) {
                    *existing = delegation.clone();
                }
            }
            TraceEventKind::DelegationRejected { delegation, reason } => {
                if let Some(evidence) = delegation.delegation_ledger.clone() {
                    replay.ledger_events.push(evidence);
                }
                let key = (
                    delegation.parent_run_id.clone(),
                    delegation.child_run_id.clone(),
                );
                if !seen_delegations.contains(&key) {
                    seen_delegations.push(key);
                    replay.delegations.push(delegation.clone());
                } else if let Some(existing) = replay.delegations.iter_mut().find(|existing| {
                    existing.parent_run_id == delegation.parent_run_id
                        && existing.child_run_id == delegation.child_run_id
                }) {
                    *existing = delegation.clone();
                }
                replay.rejections.push(LocalDelegationRejection {
                    delegation: delegation.clone(),
                    reason: reason.clone(),
                });
            }
            TraceEventKind::ChildRunFailed {
                delegation,
                failure,
            } => {
                if let Some(evidence) = delegation.delegation_ledger.clone() {
                    replay.ledger_events.push(evidence);
                }
                let key = (
                    delegation.parent_run_id.clone(),
                    delegation.child_run_id.clone(),
                );
                if !seen_delegations.contains(&key) {
                    seen_delegations.push(key);
                    replay.delegations.push(delegation.clone());
                } else if let Some(existing) = replay.delegations.iter_mut().find(|existing| {
                    existing.parent_run_id == delegation.parent_run_id
                        && existing.child_run_id == delegation.child_run_id
                }) {
                    *existing = delegation.clone();
                }
                replay.failures.push(failure.clone());
            }
            TraceEventKind::MessageQueued { message }
            | TraceEventKind::MessageDelivered { message }
            | TraceEventKind::MessageConsumed { message }
                if (message.schema == TASK_REQUEST_SCHEMA
                    || message.schema == TASK_RESPONSE_SCHEMA)
                    && !seen_messages.contains(&message.message_id) =>
            {
                seen_messages.push(message.message_id.clone());
                replay.messages.push(message.clone());
            }
            _ => {}
        }
    }
    replay
}

fn child_grant_liveness_denial_raw(
    grant: &splendor_types::CapabilityGrant,
    decision_time: OffsetDateTime,
) -> Option<&'static str> {
    if decision_time < grant.not_before {
        return Some("child_grant_not_yet_valid");
    }
    if decision_time >= grant.expires_at {
        return Some("child_grant_expired");
    }
    None
}

fn resolve_parent_caller(
    bound: Option<&DelegationCallerHandle>,
    parent_run: &LocalRunRecord,
    authority: &LocalDelegationAuthority,
) -> Result<DelegationCallerHandle, &'static str> {
    let bound = bound.ok_or(REASON_MISSING_PARENT_RUN_GRANT_BINDING)?;
    if let Some(supplied) = authority.parent_caller.as_ref() {
        return if bound.is_same_authority(supplied) {
            Ok(bound.clone())
        } else {
            Err(REASON_PARENT_RUN_GRANT_MISMATCH)
        };
    }
    resolve_test_legacy_parent_caller(bound, parent_run, authority)
}

#[cfg(test)]
fn resolve_test_legacy_parent_caller(
    bound: &DelegationCallerHandle,
    parent_run: &LocalRunRecord,
    authority: &LocalDelegationAuthority,
) -> Result<DelegationCallerHandle, &'static str> {
    if parent_run.parent_run_id.is_some()
        || !authority
            .parent_capability_grant
            .as_ref()
            .is_some_and(|grant| bound.matches_validated_grant(grant))
    {
        Err(REASON_PARENT_RUN_GRANT_MISMATCH)
    } else {
        Ok(bound.clone())
    }
}

#[cfg(not(test))]
fn resolve_test_legacy_parent_caller(
    _bound: &DelegationCallerHandle,
    _parent_run: &LocalRunRecord,
    _authority: &LocalDelegationAuthority,
) -> Result<DelegationCallerHandle, &'static str> {
    Err(REASON_PARENT_RUN_GRANT_MISMATCH)
}

fn revocation_cancellation_failure(reason_code: String) -> TaskFailure {
    let reason = if reason_code == REASON_AUTHORITY_GRANT_REVOKED {
        "local delegation authority grant was revoked"
    } else if reason_code == REASON_MISSING_AUTHORITY_EVIDENCE {
        "local delegation child authority evidence was missing"
    } else {
        "local delegation revocation snapshot was not live"
    };
    TaskFailure::new(reason_code, reason, false)
}

fn delegation_child_grant_request(
    parent_run: &LocalRunRecord,
    target_agent: &LocalAgentRegistration,
    request: &LocalDelegationRequest,
    authority: &LocalDelegationAuthority,
    evidence: &LocalDelegationAuthorityEvidence,
) -> DelegationChildGrantRequest {
    DelegationChildGrantRequest {
        parent_grant_id: Some(evidence.parent_capability_grant_id.clone()),
        issuer: parent_run.principal_id.clone(),
        child_subject: Some(authority.child_subject.clone()),
        child_grant_id: evidence.child_capability_grant_id.clone(),
        parent_run_id: request.parent_run_id.clone(),
        parent_agent_id: request.source_agent_id.clone(),
        child_run_id: request.child_run_id.clone(),
        child_agent_id: target_agent.agent.agent_id.clone(),
        objective: request.objective.clone(),
        role_profile: authority.role_profile,
        operations: authority_operations(&request.delegated_authority),
        scope: CapabilityScope {
            tenant_ids: Some(vec![parent_run.tenant_id.clone()]),
            budget: authority.budget,
            ..CapabilityScope::default()
        },
        allowed_message_schemas: vec![TASK_RESPONSE_SCHEMA.to_string()],
        allowed_recipient_agent_ids: vec![request.source_agent_id.clone()],
        result_contract: DelegationResultContract {
            schema_version: DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION.to_string(),
            result_schema: TASK_RESPONSE_SCHEMA.to_string(),
            requires_response: true,
            max_result_bytes: None,
        },
        not_before: authority.not_before,
        expires_at: authority.expires_at,
        max_delegation_depth: authority.max_delegation_depth,
        max_fan_out: authority.max_fan_out,
        validation_digest: format!("local-delegation:{}", evidence.child_capability_grant_id),
    }
}

fn authority_operations(authority: &DelegatedAuthority) -> Vec<AuthorityOperation> {
    let mut operations = Vec::new();
    operations.extend(
        authority
            .allowed_actions
            .iter()
            .cloned()
            .map(gateway_action_operation),
    );
    operations.extend(
        authority
            .allowed_adapters
            .iter()
            .cloned()
            .map(gateway_adapter_operation),
    );
    operations.extend(
        authority
            .allowed_permissions
            .iter()
            .cloned()
            .map(compatibility_permission_operation),
    );
    operations
}

fn ensure_recorder_run(
    recorder: &dyn MessageTraceRecorder,
    run_id: &RunId,
) -> Result<(), LocalDelegationError> {
    if recorder.run_id() != run_id {
        return Err(LocalDelegationError::TraceRunMismatch {
            runtime_run_id: recorder.run_id().clone(),
            delegation_run_id: run_id.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/local_delegation_tests.rs"]
mod tests;
