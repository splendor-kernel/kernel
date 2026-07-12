//! # Local Delegation Model
//!
//! Local-only parent/child run delegation for Sprint 0.02-S4. The manager keeps
//! delegation explicit: parent runs name the target agent, child objective,
//! delegated compatibility authority, and authority-issued parent/child grant
//! refs. Child agent contexts returned by this module are scoped so the loop
//! engine denies actions outside the delegated authority before any adapter can
//! execute.

use crate::{
    AgentContext, LocalMessageRouter, MessageRouter, MessageRouterError, MessageTraceRecorder,
};
use splendor_authority::{
    compatibility_permission_operation, gateway_action_operation, gateway_adapter_operation,
    issue_delegation_child_grant, DelegationChildGrantRequest, DelegationValidationContext,
    RevocationSnapshot, ValidatedCapabilityGrant, REASON_AUTHORITY_GRANT_REVOKED,
};
use splendor_types::{
    AgentId, AuthorityBudgetScope, AuthorityOperation, CapabilityGrantId, CapabilityScope,
    DelegatedAuthority, DelegationResultContract, DelegationRoleProfile,
    LocalDelegationAuthorityEvidence, LocalDelegationTraceContext, Message, MessageEnvelope,
    MessageId, MessageTraceContext, MessageValidationError, PrincipalId, RunId, TaskFailure,
    TaskRequest, TaskResponse, TaskResponseStatus, TenantId, TraceEvent, TraceEventKind, TraceId,
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
    /// Parent grant supplied by the authority/work-order path.
    pub parent_capability_grant: ValidatedCapabilityGrant,
    /// Parent/child grant references to record if authority issuance succeeds.
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
    /// Child budget cap mirrored into the child capability scope.
    pub budget: AuthorityBudgetScope,
    /// Remaining child delegation depth requested for the child grant.
    pub max_delegation_depth: u32,
    /// Authority-owned fan-out limit for this parent edge.
    pub max_fan_out: u32,
    /// Local validation digest for child-grant evidence.
    pub validation_digest: String,
}

impl LocalDelegationAuthority {
    /// Builds authority input with conservative defaults derived from the parent grant.
    pub fn new(
        parent_capability_grant: ValidatedCapabilityGrant,
        child_subject: PrincipalId,
        audience: impl Into<String>,
        not_before: OffsetDateTime,
    ) -> Self {
        let parent = parent_capability_grant.grant();
        let parent_expires_at = parent
            .scope
            .time
            .expires_at
            .unwrap_or(parent.expires_at)
            .min(parent.expires_at);
        let parent_not_before = parent
            .scope
            .time
            .not_before
            .unwrap_or(parent.not_before)
            .max(parent.not_before);
        let not_before = not_before.max(parent_not_before);
        let child_capability_grant_id = CapabilityGrantId::new();
        let authority_evidence = LocalDelegationAuthorityEvidence::issued(
            parent.grant_id.clone(),
            child_capability_grant_id.clone(),
        );
        let budget = parent.scope.budget;
        let max_delegation_depth = parent.max_delegation_depth.saturating_sub(1);
        Self {
            parent_capability_grant,
            authority_evidence: Some(authority_evidence),
            child_subject,
            audience: audience.into(),
            not_before,
            expires_at: parent_expires_at,
            role_profile: DelegationRoleProfile::Specialist,
            budget,
            max_delegation_depth,
            max_fan_out: 16,
            validation_digest: format!("local-delegation:{child_capability_grant_id}"),
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
    lifecycle: Mutex<()>,
    state: Mutex<LocalDelegationState>,
}

#[derive(Default)]
struct LocalDelegationState {
    agents: HashMap<AgentId, LocalAgentRegistration>,
    runs: HashMap<RunId, LocalRunRecord>,
    run_grants: HashMap<RunId, ValidatedCapabilityGrant>,
}

impl std::fmt::Debug for LocalDelegationManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalDelegationManager")
            .field("router", &self.router)
            .field("lifecycle", &"<mutex>")
            .field("state", &"<redacted trusted grant bindings>")
            .finish()
    }
}

impl LocalDelegationManager {
    /// Creates a manager backed by an in-memory local router.
    pub fn new() -> Self {
        Self {
            router: LocalMessageRouter::new(),
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
        if let Some(bound_grant) = state.run_grants.get(run_id) {
            if bound_grant == grant {
                return Ok(run);
            }
            return Err(LocalDelegationError::ParentRunGrantBindingConflict {
                run_id: run_id.clone(),
                bound_grant_id: bound_grant.grant().grant_id.clone(),
                supplied_grant_id: grant_id,
            });
        }
        if let Some((bound_run_id, _)) =
            state.run_grants.iter().find(|(candidate_run_id, bound)| {
                *candidate_run_id != run_id && bound.grant().grant_id == grant_id
            })
        {
            return Err(LocalDelegationError::CapabilityGrantRunBindingConflict {
                grant_id,
                bound_run_id: bound_run_id.clone(),
                requested_run_id: run_id.clone(),
            });
        }

        let run = state
            .runs
            .get_mut(run_id)
            .ok_or_else(|| LocalDelegationError::UnknownParentRun(run_id.clone()))?;
        run.capability_grant_id = Some(grant_id);
        let run = run.clone();
        state.run_grants.insert(run_id.clone(), grant.clone());
        Ok(run)
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

        let (parent_run, parent_bound_grant, target_agent, duplicate_child_run) = {
            let state = self.lock_state()?;
            let parent_run = state
                .runs
                .get(&request.parent_run_id)
                .cloned()
                .ok_or_else(|| {
                    LocalDelegationError::UnknownParentRun(request.parent_run_id.clone())
                })?;
            let parent_bound_grant = state.run_grants.get(&request.parent_run_id).cloned();
            let target_agent = state
                .agents
                .get(&request.target_agent_id)
                .cloned()
                .ok_or_else(|| {
                    LocalDelegationError::UnknownAgent(request.target_agent_id.clone())
                })?;
            let duplicate_child_run = state.runs.contains_key(&request.child_run_id);
            (
                parent_run,
                parent_bound_grant,
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
        let parent_binding_denial = match parent_bound_grant.as_ref() {
            None => Some(REASON_MISSING_PARENT_RUN_GRANT_BINDING),
            Some(bound_grant) if bound_grant != &authority.parent_capability_grant => {
                Some(REASON_PARENT_RUN_GRANT_MISMATCH)
            }
            Some(_) => None,
        };
        if let Some(reason) = parent_binding_denial {
            let reason = reason.to_string();
            parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                delegation: trace_context,
                reason: reason.clone(),
            })?;
            return Err(LocalDelegationError::AuthorityDenied { reason });
        }
        let child_grant_id_collision = if let Some(evidence) = authority.authority_evidence.as_ref()
        {
            self.lock_state()?
                .run_grants
                .values()
                .any(|bound| bound.grant().grant_id == evidence.child_capability_grant_id)
        } else {
            false
        };
        if child_grant_id_collision {
            let reason = REASON_CHILD_CAPABILITY_GRANT_ID_COLLISION.to_string();
            parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                delegation: trace_context,
                reason: reason.clone(),
            })?;
            return Err(LocalDelegationError::AuthorityDenied { reason });
        }
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

        let authority_evidence = match validate_authority_evidence(&authority) {
            Ok(evidence) => evidence,
            Err(reason) => {
                parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                    delegation: trace_context,
                    reason: reason.clone(),
                })?;
                return Err(LocalDelegationError::AuthorityEvidenceDenied { reason });
            }
        };
        trace_context = trace_context.with_authority_evidence(authority_evidence.clone());

        if let Err(reason) = validate_parent_grant_binding(&authority, &parent_run) {
            parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                delegation: trace_context
                    .clone()
                    .with_authority_evidence(authority_evidence.clone().denied(reason.clone())),
                reason: reason.clone(),
            })?;
            return Err(LocalDelegationError::AuthorityDenied { reason });
        }

        let decision_time = OffsetDateTime::now_utc();

        let issued_child_grant = match issue_delegation_child_grant(
            &authority.parent_capability_grant,
            delegation_child_grant_request(
                &parent_run,
                &target_agent,
                &request,
                &authority,
                &authority_evidence,
            ),
            DelegationValidationContext {
                now: decision_time,
                audience: authority.audience.clone(),
                expected_child_subject: target_agent.principal_id.clone(),
                parent_fan_out_limit: authority.max_fan_out,
                current_parent_fan_out: parent_run.child_run_ids.len() as u32,
            },
        ) {
            Ok(issued_child_grant) => issued_child_grant,
            Err(error) => {
                let reason = error.reason_code().to_string();
                parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                    delegation: trace_context
                        .clone()
                        .with_authority_evidence(authority_evidence.denied(reason.clone())),
                    reason: reason.clone(),
                })?;
                return Err(LocalDelegationError::AuthorityDenied { reason });
            }
        };
        if let Some(reason) =
            child_grant_liveness_denial(issued_child_grant.child_grant(), decision_time)
        {
            let reason = reason.to_string();
            parent_recorder.record_message_event(TraceEventKind::DelegationRejected {
                delegation: trace_context
                    .clone()
                    .with_authority_evidence(authority_evidence.clone().denied(reason.clone())),
                reason: reason.clone(),
            })?;
            return Err(LocalDelegationError::AuthorityDenied { reason });
        }
        let issued_evidence = LocalDelegationAuthorityEvidence::issued(
            issued_child_grant
                .delegation_grant()
                .parent_grant_id
                .clone(),
            issued_child_grant.child_grant().grant().grant_id.clone(),
        );
        let child_capability_grant = issued_child_grant.child_grant().clone();
        trace_context = trace_context.with_authority_evidence(issued_evidence.clone());

        let requested_trace =
            parent_recorder.record_message_event(TraceEventKind::DelegationRequested {
                delegation: trace_context.clone(),
            })?;
        trace_context = trace_context.with_parent_trace(requested_trace.clone());

        let task_request = TaskRequest::new(
            request.parent_run_id.clone(),
            request.child_run_id.clone(),
            request.target_agent_id.clone(),
            request.objective.clone(),
            request.delegated_authority.clone(),
        )?
        .with_authority_evidence(issued_evidence.clone())?;
        let request_message = Message::new(
            MessageId::new(),
            request.source_agent_id.clone(),
            request.target_agent_id.clone(),
            request.parent_run_id.clone(),
            TASK_REQUEST_SCHEMA,
            serde_json::to_value(task_request).map_err(|error| {
                MessageValidationError::PayloadValidationFailed {
                    schema: TASK_REQUEST_SCHEMA.to_string(),
                    reason: error.to_string(),
                }
            })?,
            Some(requested_trace.clone()),
            true,
            OffsetDateTime::now_utc(),
        )?;
        let request_message_id = request_message.message_id.clone();
        let request_envelope = MessageEnvelope::new(request_message)?;
        let routed_request = self.router.send(parent_recorder, request_envelope)?;
        trace_context = trace_context.with_request_message(request_message_id.clone());

        let child_started_trace =
            child_recorder.record_message_event(TraceEventKind::ChildRunStarted {
                delegation: trace_context.clone(),
            })?;

        let mut child_agent = target_agent.agent.clone();
        child_agent.set_delegated_authority(request.delegated_authority.clone());
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
            .run_grants
            .insert(child_record.run_id.clone(), child_capability_grant);

        Ok(LocalChildRun {
            run: child_record,
            child_agent,
            request_message: routed_request,
            child_started_trace_id: child_started_trace,
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
        let cancellation_reason = {
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
                    Err(error) => Some(error.reason_code().to_string()),
                    Ok(true) => Some(REASON_AUTHORITY_GRANT_REVOKED.to_string()),
                    Ok(false) => match revocations
                        .revokes_grant_id_at(&evidence.child_capability_grant_id, now)
                    {
                        Err(error) => Some(error.reason_code().to_string()),
                        Ok(true) => Some(REASON_AUTHORITY_GRANT_REVOKED.to_string()),
                        Ok(false) => None,
                    },
                }
            } else if child.parent_run_id.is_some() {
                Some(REASON_MISSING_AUTHORITY_EVIDENCE.to_string())
            } else {
                None
            }
        };
        let Some(cancellation_reason) = cancellation_reason else {
            return Ok(None);
        };

        self.cancel_child_run_for_revocation_with_lifecycle(
            parent_recorder,
            child_recorder,
            child_run_id,
            revocation_cancellation_failure(cancellation_reason),
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
        drop(state);
        Ok(
            parent_recorder.record_message_event(TraceEventKind::ParentRunCancelled {
                parent_run_id: parent_run_id.clone(),
                agent_id,
                reason,
            })?,
        )
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
        };
        context.parent_trace_id = child.parent_trace_id.clone();

        let child_trace_id = match status {
            TaskResponseStatus::Completed => {
                child_recorder.record_message_event(TraceEventKind::ChildRunCompleted {
                    delegation: context.clone(),
                })?
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
                })?
            }
        };

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
            child_record.status = match status {
                TaskResponseStatus::Completed => LocalRunStatus::Completed,
                TaskResponseStatus::Failed => LocalRunStatus::Failed,
                TaskResponseStatus::Denied => LocalRunStatus::Denied,
                TaskResponseStatus::Cancelled => LocalRunStatus::Cancelled,
            };
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
    ) -> Result<LocalTaskResponse, LocalDelegationError> {
        let (child, parent) =
            {
                let mut state = self.lock_state()?;
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
        };

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

    fn lock_lifecycle(&self) -> Result<std::sync::MutexGuard<'_, ()>, LocalDelegationError> {
        self.lifecycle
            .lock()
            .map_err(|_| LocalDelegationError::StorageUnavailable)
    }
}

impl Default for LocalDelegationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Replay summary for local delegation relationships and task messages.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalDelegationReplay {
    /// Parent/child edges reconstructed from delegation trace events.
    pub delegations: Vec<LocalDelegationTraceContext>,
    /// Task request/response message contexts seen during replay.
    pub messages: Vec<MessageTraceContext>,
    /// Structured child failures seen during replay.
    pub failures: Vec<TaskFailure>,
    /// Rejected delegation contexts with their stable denial reasons.
    pub rejections: Vec<LocalDelegationRejection>,
}

/// Inspect-only replay evidence for one rejected local delegation.
#[derive(Clone, Debug, Eq, PartialEq)]
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
                let key = (
                    delegation.parent_run_id.clone(),
                    delegation.child_run_id.clone(),
                );
                if !seen_delegations.contains(&key) {
                    seen_delegations.push(key);
                    replay.delegations.push(delegation.clone());
                }
            }
            TraceEventKind::DelegationRejected { delegation, reason } => {
                let key = (
                    delegation.parent_run_id.clone(),
                    delegation.child_run_id.clone(),
                );
                if !seen_delegations.contains(&key) {
                    seen_delegations.push(key);
                    replay.delegations.push(delegation.clone());
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
                let key = (
                    delegation.parent_run_id.clone(),
                    delegation.child_run_id.clone(),
                );
                if !seen_delegations.contains(&key) {
                    seen_delegations.push(key);
                    replay.delegations.push(delegation.clone());
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

fn validate_authority_evidence(
    authority: &LocalDelegationAuthority,
) -> Result<LocalDelegationAuthorityEvidence, String> {
    let evidence = authority
        .authority_evidence
        .clone()
        .ok_or_else(|| REASON_MISSING_AUTHORITY_EVIDENCE.to_string())?;
    evidence
        .validate()
        .map_err(|_| "invalid_authority_evidence".to_string())?;
    if evidence.parent_capability_grant_id != authority.parent_capability_grant.grant().grant_id {
        return Err("authority_evidence_parent_mismatch".to_string());
    }
    Ok(evidence)
}

fn validate_parent_grant_binding(
    authority: &LocalDelegationAuthority,
    parent_run: &LocalRunRecord,
) -> Result<(), String> {
    if authority.parent_capability_grant.grant().subject != parent_run.principal_id {
        return Err("parent_principal_mismatch".to_string());
    }
    Ok(())
}

fn child_grant_liveness_denial(
    child_grant: &ValidatedCapabilityGrant,
    decision_time: OffsetDateTime,
) -> Option<&'static str> {
    let grant = child_grant.grant();
    if decision_time < grant.not_before {
        return Some("child_grant_not_yet_valid");
    }
    if decision_time >= grant.expires_at {
        return Some("child_grant_expired");
    }
    None
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
        issuer: authority.parent_capability_grant.grant().subject.clone(),
        child_subject: Some(authority.child_subject.clone()),
        child_grant_id: evidence.child_capability_grant_id.clone(),
        parent_run_id: request.parent_run_id.clone(),
        parent_agent_id: request.source_agent_id.clone(),
        child_run_id: request.child_run_id.clone(),
        child_agent_id: target_agent.agent.agent_id.clone(),
        objective: request.objective.clone(),
        role_profile: authority.role_profile,
        operations: authority_operations(&request.delegated_authority),
        scope: child_capability_scope(parent_run, request, authority),
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
        validation_digest: authority.validation_digest.clone(),
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

fn child_capability_scope(
    parent_run: &LocalRunRecord,
    request: &LocalDelegationRequest,
    authority: &LocalDelegationAuthority,
) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![parent_run.tenant_id.clone()]),
        agent_ids: Some(vec![request.target_agent_id.clone()]),
        run_ids: Some(vec![request.child_run_id.clone()]),
        audiences: Some(vec![authority.audience.clone()]),
        budget: authority.budget,
        ..CapabilityScope::default()
    }
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
