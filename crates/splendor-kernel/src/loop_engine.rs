//! # Loop Engine
//!
//! The loop engine executes a single agent tick: collect percepts, invoke the
//! policy, evaluate constraints, verify/execute actions, record outcomes, and
//! commit state. It emits the ordered trace events required for auditability.

use crate::state::RuntimeSnapshotExpectation;
use crate::{
    apply_escalation_to_outcome, escalations_require_intervention, AgentContext,
    EscalationEvaluator, EscalationOutcomeInput, KernelRuntime, KernelRuntimeConfig,
    PolicyRuntimeAuthority, StateCommit, StateGraph, StateGraphError, StateHandoffExportRequest,
    StateHandoffScope, TraceError,
};
use splendor_gateway::{
    authority_pre_effect_evidence_recorded, guard_action_routing_and_receipts,
    guard_persisted_percept, guard_persisted_state, raw_credential_denied_action,
    raw_credential_denied_outcome, ActionGateway, ActionId, ActionOutcome, ActionRequest,
    ActionStatus, GatewayError, RAW_CREDENTIAL_INPUT_DENIED, RAW_CREDENTIAL_OUTPUT_SUPPRESSED,
};
use splendor_store::{StateData, StateMetadata, TraceStore, TraceStoreError};
use splendor_types::{
    Action, ApprovalTraceContext, CapabilityGrantId, Constraint, ContentHash, EffectCertainty,
    EscalationContext, EscalationPolicy, EscalationPolicyError, Feedback, Percept, PolicyBundleId,
    PolicyBundleTraceContext, QuotaUsage, RetryClass, Reward, RunId, SnapshotId, StateHandoff,
    StateNodeId, TickId, TraceEvent, TraceEventId, TraceEventKind, TraceIdentityContext,
    VerificationResult, WorkOrder, WorkOrderEnvelope, WorkOrderKeyring,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use time::OffsetDateTime;

/// Fixed local compatibility reason returned when another tick cannot be
/// attempted until rejected persistence or an uncertain effect is reconciled.
pub(crate) const TICK_RECONCILIATION_REQUIRED: &str = "tick_reconciliation_required";

/// Fixed reason returned when a fresh persisted constructor targets an existing run.
pub(crate) const RUN_ALREADY_EXISTS: &str = "run_already_exists";

/// Fixed reason returned when one decision repeats an explicit action identity.
pub(crate) const DUPLICATE_ACTION_ID: &str = "duplicate_action_id";

/// Fixed reason returned when persisted state does not belong to the exact
/// tenant/agent/run identity selected for resume.
pub(crate) const RESUME_STATE_IDENTITY_MISMATCH: &str = "resume_state_identity_mismatch";

/// Fixed reason returned when the latest completed tick has no matching durable
/// snapshot and therefore cannot be resumed without skipping committed state.
pub(crate) const RESUME_LATEST_COMPLETED_SNAPSHOT_UNAVAILABLE: &str =
    "resume_latest_completed_snapshot_unavailable";

/// Collects percepts for a tick.
pub trait Perceptor: Send + Sync {
    /// Collects percepts for the provided agent context.
    fn collect(&self, agent: &AgentContext) -> Result<Vec<Percept>, LoopError>;
}

/// Policy callback that proposes actions and next state.
pub trait Policy: Send + Sync {
    /// Returns a human-readable policy identifier.
    fn name(&self) -> &str;
    /// Produces the next decision based on the current state and percepts.
    fn decide(&self, state: &StateData, percepts: &[Percept]) -> Result<PolicyDecision, LoopError>;
}

/// Constraint engine result bundle.
#[derive(Clone, Debug)]
pub struct ConstraintEvaluation {
    /// Constraints evaluated during the tick.
    pub constraints: Vec<Constraint>,
    /// Verification outcome for the constraint set.
    pub result: VerificationResult,
}

impl ConstraintEvaluation {
    /// Returns an allow-all evaluation.
    pub fn allow() -> Self {
        Self {
            constraints: Vec::new(),
            result: VerificationResult::allow(),
        }
    }
}

/// Constraint evaluation hook used by the loop engine.
pub trait ConstraintEngine: Send + Sync {
    /// Evaluates constraints for the tick.
    fn evaluate(
        &self,
        state: &StateData,
        percepts: &[Percept],
        actions: &[ActionCandidate],
    ) -> ConstraintEvaluation;
}

/// Constraint engine that always allows execution.
#[derive(Clone, Debug, Default)]
pub struct AllowAllConstraintEngine;

impl ConstraintEngine for AllowAllConstraintEngine {
    fn evaluate(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
        _actions: &[ActionCandidate],
    ) -> ConstraintEvaluation {
        ConstraintEvaluation::allow()
    }
}

/// Optional feedback and reward signals from outcomes.
#[derive(Clone, Debug, Default)]
pub struct OutcomeSignal {
    /// Feedback signal produced by the evaluator.
    pub feedback: Option<Feedback>,
    /// Reward signal produced by the evaluator.
    pub reward: Option<Reward>,
}

/// Evaluates action outcomes into feedback/reward signals.
pub trait OutcomeEvaluator: Send + Sync {
    /// Evaluates the outcome for a single action.
    fn evaluate(&self, action: &Action, outcome: &ActionOutcome) -> OutcomeSignal;
}

/// Outcome evaluator that emits no signals.
#[derive(Clone, Debug, Default)]
pub struct NoopOutcomeEvaluator;

impl OutcomeEvaluator for NoopOutcomeEvaluator {
    fn evaluate(&self, _action: &Action, _outcome: &ActionOutcome) -> OutcomeSignal {
        OutcomeSignal::default()
    }
}

/// Proposed action with quota usage and adapter metadata.
#[derive(Clone, Debug)]
pub struct ActionCandidate {
    /// Stable action identifier when a proposed action must be re-evaluated
    /// across pause/resume boundaries, such as approval-scoped actions.
    pub action_id: Option<ActionId>,
    /// Action to be executed.
    pub action: Action,
    /// Adapter identifier used for policy allowlists.
    pub adapter: Option<String>,
    /// Resource usage estimate for quota enforcement.
    pub usage: QuotaUsage,
    /// Preconditions satisfied for this action.
    pub satisfied_preconditions: Vec<String>,
    /// Stable original request timestamp preserved across policy retries and
    /// approval pause/resume boundaries.
    pub requested_at: Option<OffsetDateTime>,
    /// Optional approval evidence supplied for this action evaluation.
    pub approval_evidence: Option<splendor_types::ApprovalEvidence>,
    /// Raw owning-service receipts for live authority obligations.
    pub authority_obligation_receipts: Vec<splendor_types::AuthorityObligationReceipt>,
    /// Exact issued child grant reference required for delegated actions.
    pub delegated_capability_grant_id: Option<CapabilityGrantId>,
}

struct ScreenedActionCandidate<'a> {
    candidate: &'a ActionCandidate,
    action_id: ActionId,
    trace_action: Action,
    raw_credential_denied: bool,
}

impl ActionCandidate {
    /// Creates a candidate with default usage and no adapter.
    pub fn new(action: Action) -> Self {
        let satisfied_preconditions = action.preconditions.clone();
        Self {
            action_id: None,
            action,
            adapter: None,
            usage: QuotaUsage::single_action(),
            satisfied_preconditions,
            requested_at: None,
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
            delegated_capability_grant_id: None,
        }
    }

    /// Sets the adapter identifier used for allowlist checks.
    pub fn with_adapter(mut self, adapter: impl Into<String>) -> Self {
        self.adapter = Some(adapter.into());
        self
    }

    /// Sets the quota usage estimate.
    pub fn with_usage(mut self, usage: QuotaUsage) -> Self {
        self.usage = usage;
        self
    }

    /// Overrides the satisfied preconditions for this action.
    pub fn with_satisfied_preconditions(mut self, preconditions: Vec<String>) -> Self {
        self.satisfied_preconditions = preconditions;
        self
    }

    /// Preserves the original request timestamp for deterministic obligation binding.
    pub fn with_requested_at(mut self, requested_at: OffsetDateTime) -> Self {
        self.requested_at = Some(requested_at);
        self
    }

    /// Attaches approval evidence for the gateway approval verifier.
    pub fn with_approval_evidence(mut self, evidence: splendor_types::ApprovalEvidence) -> Self {
        self.approval_evidence = Some(evidence);
        self
    }

    /// Attaches raw obligation receipts. Decisions are regenerated by the live
    /// C02 evaluator and cannot be supplied by policy/user space.
    pub fn with_authority_obligation_receipts(
        mut self,
        receipts: Vec<splendor_types::AuthorityObligationReceipt>,
    ) -> Self {
        self.authority_obligation_receipts = receipts;
        self
    }

    /// Sets a stable action identity for repeated evaluations of this candidate.
    pub fn with_action_id(mut self, action_id: ActionId) -> Self {
        self.action_id = Some(action_id);
        self
    }

    /// Carries the exact issued child grant reference for delegated evaluation.
    pub fn with_delegated_capability_grant_id(mut self, grant_id: CapabilityGrantId) -> Self {
        self.delegated_capability_grant_id = Some(grant_id);
        self
    }
}

/// Output from a policy decision.
#[derive(Clone, Debug)]
pub struct PolicyDecision {
    /// Actions proposed by the policy.
    pub actions: Vec<ActionCandidate>,
    /// Next state payload to commit.
    pub next_state: StateData,
    /// Metadata for the state commit.
    pub metadata: StateMetadata,
}

/// Resume metadata discovered from a trace store.
#[derive(Clone, Debug)]
pub struct ResumeInfo {
    /// Snapshot identifier to restore from.
    pub snapshot_id: SnapshotId,
    /// Latest completed tick identifier.
    pub tick_id: u64,
}

#[derive(Clone, Debug)]
struct ResumeSelection {
    info: ResumeInfo,
    state_node_id: StateNodeId,
    state_hash: ContentHash,
    trace_event_id: TraceEventId,
}

/// Optional trace/run metadata supplied when constructing a persisted loop
/// engine.
#[derive(Clone, Debug, Default)]
pub struct RunTraceContext {
    /// Run identifier to bind or resume.
    pub run_id: Option<RunId>,
    /// Validated work order that authorized this run, if present.
    pub work_order: Option<WorkOrder>,
    /// Validated policy bundle metadata governing this run, if present.
    pub policy_bundle: Option<PolicyBundleTraceContext>,
}

impl RunTraceContext {
    /// Builds trace metadata for an optional run id without work-order authority.
    pub fn new(run_id: Option<RunId>) -> Self {
        Self {
            run_id,
            work_order: None,
            policy_bundle: None,
        }
    }

    /// Attaches validated work-order metadata.
    pub fn with_work_order(mut self, work_order: WorkOrder) -> Self {
        self.work_order = Some(work_order);
        self
    }

    /// Attaches validated policy bundle metadata.
    pub fn with_policy_bundle(mut self, policy_bundle: PolicyBundleTraceContext) -> Self {
        self.policy_bundle = Some(policy_bundle);
        self
    }
}

impl PolicyDecision {
    /// Creates a decision with a label applied to the state metadata.
    pub fn new(
        actions: Vec<ActionCandidate>,
        next_state: StateData,
        label: Option<String>,
    ) -> Self {
        Self {
            actions,
            next_state,
            metadata: StateMetadata::new(OffsetDateTime::now_utc(), label),
        }
    }
}

/// Outcome produced by a loop tick.
#[derive(Clone, Debug)]
pub struct TickOutcome {
    /// Tick identifier for this outcome.
    pub tick_id: u64,
    /// Outcomes returned by the action gateway.
    pub action_outcomes: Vec<ActionOutcome>,
    /// State commit recorded for the tick.
    pub state_commit: StateCommit,
    /// Wall-clock duration for the tick in milliseconds.
    pub duration_ms: u64,
    /// Indicates whether the tick requires intervention.
    pub needs_intervention: bool,
    /// Indicates whether the tick paused waiting for approval.
    pub needs_approval: bool,
}

/// Errors raised by the loop engine.
#[derive(Debug, thiserror::Error)]
pub enum LoopError {
    /// Trace emission failed.
    #[error("trace error: {0}")]
    Trace(#[from] crate::TraceError),
    /// State graph commit failed.
    #[error("state graph error: {0}")]
    StateGraph(#[from] StateGraphError),
    /// Trace store access failed.
    #[error("trace store error: {0}")]
    TraceStore(#[from] TraceStoreError),
    /// Trace parsing failed.
    #[error("trace parse error: {0}")]
    TraceParse(#[from] serde_json::Error),
    /// Resume discovery failed.
    #[error("resume error: {0}")]
    Resume(String),
    /// Policy callback failed.
    #[error("policy error: {0}")]
    Policy(String),
    /// Perceptor callback failed.
    #[error("perceptor error: {0}")]
    Perceptor(String),
    /// Escalation policy validation failed.
    #[error("escalation policy error: {0}")]
    EscalationPolicy(#[from] EscalationPolicyError),
}

#[derive(Clone, Copy)]
enum TickReconciliationBlock {
    PersistenceDenied,
    EffectInFlight,
}

#[derive(Clone, Copy)]
struct EffectBoundary {
    effect_certainty: EffectCertainty,
    retry_class: RetryClass,
    reconciliation_required_after_tick: bool,
}

#[derive(Clone, Copy)]
enum PersistedConstructionMode {
    Fresh,
    Resume,
}

/// Kernel loop engine for a single agent.
pub struct LoopEngine {
    agent: AgentContext,
    runtime: Arc<KernelRuntime>,
    state_graph: StateGraph,
    state: StateData,
    perceptors: Vec<Box<dyn Perceptor>>,
    policy: Box<dyn Policy>,
    constraint_engine: Box<dyn ConstraintEngine>,
    gateway: Arc<dyn ActionGateway>,
    outcome_evaluator: Box<dyn OutcomeEvaluator>,
    escalation_evaluator: Option<EscalationEvaluator>,
    policy_authority: Option<Arc<dyn PolicyRuntimeAuthority>>,
    reconciliation_block: Option<TickReconciliationBlock>,
}

impl LoopEngine {
    /// Builds a loop engine with default trace configuration.
    pub fn new(
        agent: AgentContext,
        state_graph: StateGraph,
        state: StateData,
        policy: Box<dyn Policy>,
        gateway: Arc<dyn ActionGateway>,
    ) -> Self {
        Self::with_runtime(
            agent,
            state_graph,
            state,
            policy,
            gateway,
            KernelRuntime::new(KernelRuntimeConfig::default()),
        )
    }

    /// Builds a loop engine with an explicit runtime.
    pub fn with_runtime(
        agent: AgentContext,
        state_graph: StateGraph,
        state: StateData,
        policy: Box<dyn Policy>,
        gateway: Arc<dyn ActionGateway>,
        runtime: KernelRuntime,
    ) -> Self {
        Self::with_shared_runtime(
            agent,
            state_graph,
            state,
            policy,
            gateway,
            Arc::new(runtime),
        )
    }

    /// Builds a loop engine with a runtime shared by pre-effect evidence recorders.
    pub fn with_shared_runtime(
        agent: AgentContext,
        state_graph: StateGraph,
        state: StateData,
        policy: Box<dyn Policy>,
        gateway: Arc<dyn ActionGateway>,
        runtime: Arc<KernelRuntime>,
    ) -> Self {
        let mut agent = agent;
        if let Some(head) = state_graph.head().cloned() {
            agent.set_state_head(head);
        }
        Self {
            agent,
            runtime,
            state_graph,
            state,
            perceptors: Vec::new(),
            policy,
            constraint_engine: Box::new(AllowAllConstraintEngine),
            gateway,
            outcome_evaluator: Box::new(NoopOutcomeEvaluator),
            escalation_evaluator: None,
            policy_authority: None,
            reconciliation_block: None,
        }
    }

    /// Builds a fresh loop engine that records traces in a trace store.
    /// Existing persisted history for the selected run is rejected; use an
    /// explicit `resume_from_*` constructor for recovery.
    pub fn with_trace_store(
        agent: AgentContext,
        state_graph: StateGraph,
        state: StateData,
        policy: Box<dyn Policy>,
        gateway: Arc<dyn ActionGateway>,
        trace_store: Arc<dyn TraceStore>,
        run_id: Option<RunId>,
    ) -> Result<Self, LoopError> {
        Self::with_trace_store_and_work_order(
            agent,
            state_graph,
            state,
            policy,
            gateway,
            trace_store,
            RunTraceContext::new(run_id),
        )
    }

    /// Builds a loop engine that records traces in a trace store and attaches
    /// validated work-order metadata to the run trace stream.
    pub fn with_trace_store_and_work_order(
        agent: AgentContext,
        state_graph: StateGraph,
        state: StateData,
        policy: Box<dyn Policy>,
        gateway: Arc<dyn ActionGateway>,
        trace_store: Arc<dyn TraceStore>,
        context: RunTraceContext,
    ) -> Result<Self, LoopError> {
        let runtime = Arc::new(KernelRuntime::with_trace_store(
            trace_store,
            context.run_id.clone(),
        )?);
        Self::with_shared_trace_runtime_and_work_order(
            agent,
            state_graph,
            state,
            policy,
            gateway,
            runtime,
            context,
        )
    }

    /// Builds a fresh persisted loop with a runtime shared by the gateway's
    /// mandatory pre-effect authority evidence recorder. A runtime reopened over
    /// persisted history, or reused after tick execution begins, is rejected.
    #[allow(clippy::too_many_arguments)]
    pub fn with_shared_trace_runtime_and_work_order(
        agent: AgentContext,
        state_graph: StateGraph,
        state: StateData,
        policy: Box<dyn Policy>,
        gateway: Arc<dyn ActionGateway>,
        runtime: Arc<KernelRuntime>,
        context: RunTraceContext,
    ) -> Result<Self, LoopError> {
        Self::with_shared_trace_runtime_and_work_order_mode(
            agent,
            state_graph,
            state,
            policy,
            gateway,
            runtime,
            context,
            PersistedConstructionMode::Fresh,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_shared_trace_runtime_and_work_order_mode(
        mut agent: AgentContext,
        state_graph: StateGraph,
        state: StateData,
        policy: Box<dyn Policy>,
        gateway: Arc<dyn ActionGateway>,
        runtime: Arc<KernelRuntime>,
        context: RunTraceContext,
        mode: PersistedConstructionMode,
    ) -> Result<Self, LoopError> {
        if matches!(mode, PersistedConstructionMode::Fresh) {
            match runtime.admit_fresh_engine(&agent.tenant_id, &agent.agent_id) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(LoopError::Resume(RUN_ALREADY_EXISTS.to_string()));
                }
                Err(error) if trace_error_is_fresh_admission_conflict(&error) => {
                    return Err(LoopError::Resume(RUN_ALREADY_EXISTS.to_string()));
                }
                Err(error) => return Err(error.into()),
            }
        }
        if let Some(work_order) = context.work_order.as_ref() {
            agent.config.metadata.insert(
                "work_order_id".to_string(),
                work_order.work_order_id.to_string(),
            );
            runtime.record_event(TraceEventKind::WorkOrderAccepted {
                work_order_id: work_order.work_order_id.clone(),
                tenant_id: work_order.tenant_id.clone(),
                agent_id: work_order.agent_id.clone(),
                run_id: work_order.run_id.clone(),
            })?;
        }
        if let Some(policy_bundle) = context.policy_bundle.as_ref() {
            agent.config.metadata.insert(
                "policy_bundle_id".to_string(),
                policy_bundle.policy_bundle_id.to_string(),
            );
            agent.config.metadata.insert(
                "policy_bundle_version".to_string(),
                policy_bundle.version.clone(),
            );
            runtime.record_event(TraceEventKind::PolicyBundleAccepted {
                bundle: policy_bundle.clone(),
            })?;
        }
        Ok(Self::with_shared_runtime(
            agent,
            state_graph,
            state,
            policy,
            gateway,
            runtime,
        ))
    }

    /// Builds a loop engine by resuming from the most recent snapshot in the trace store.
    pub fn resume_from_trace_store(
        agent: AgentContext,
        state_graph: StateGraph,
        policy: Box<dyn Policy>,
        gateway: Arc<dyn ActionGateway>,
        trace_store: Arc<dyn TraceStore>,
        run_id: RunId,
    ) -> Result<Self, LoopError> {
        Self::resume_from_trace_store_with_work_order(
            agent,
            state_graph,
            policy,
            gateway,
            trace_store,
            run_id,
            None,
        )
    }

    /// Resumes from a trace store after validating a work order at the caller
    /// boundary. The work-order event is appended to the existing trace stream.
    pub fn resume_from_trace_store_with_work_order(
        agent: AgentContext,
        mut state_graph: StateGraph,
        policy: Box<dyn Policy>,
        gateway: Arc<dyn ActionGateway>,
        trace_store: Arc<dyn TraceStore>,
        run_id: RunId,
        work_order: Option<&WorkOrder>,
    ) -> Result<Self, LoopError> {
        let context = RunTraceContext::new(Some(run_id.clone()));
        let context = match work_order {
            Some(work_order) => context.with_work_order(work_order.clone()),
            None => context,
        };
        let resume = Self::resume_info(
            trace_store.as_ref(),
            &run_id,
            &agent.tenant_id,
            &agent.agent_id,
        )?;
        let snapshot = state_graph
            .restore_snapshot_for_runtime_identity(
                &resume.info.snapshot_id,
                RuntimeSnapshotExpectation {
                    state_node_id: &resume.state_node_id,
                    state_hash: &resume.state_hash,
                    trace_event_id: &resume.trace_event_id,
                    tenant_id: &agent.tenant_id,
                    agent_id: &agent.agent_id,
                    run_id: &run_id,
                },
            )?
            .ok_or_else(|| LoopError::Resume(RESUME_STATE_IDENTITY_MISMATCH.to_string()))?;
        state_graph.set_tick(resume.info.tick_id);
        let runtime = Arc::new(KernelRuntime::with_trace_store(trace_store, Some(run_id))?);
        Self::with_shared_trace_runtime_and_work_order_mode(
            agent,
            state_graph,
            snapshot.state,
            policy,
            gateway,
            runtime,
            context,
            PersistedConstructionMode::Resume,
        )
    }

    /// Resumes a persisted loop while sharing the exact trace runtime used by a
    /// gateway pre-effect evidence recorder.
    #[allow(clippy::too_many_arguments)]
    pub fn resume_from_shared_trace_runtime_and_work_order(
        agent: AgentContext,
        mut state_graph: StateGraph,
        policy: Box<dyn Policy>,
        gateway: Arc<dyn ActionGateway>,
        trace_store: Arc<dyn TraceStore>,
        runtime: Arc<KernelRuntime>,
        run_id: RunId,
        work_order: Option<&WorkOrder>,
    ) -> Result<Self, LoopError> {
        if runtime.run_id() != &run_id {
            return Err(LoopError::Resume(
                "shared trace runtime run_id does not match resumed run".to_string(),
            ));
        }
        let context = RunTraceContext::new(Some(run_id.clone()));
        let context = match work_order {
            Some(work_order) => context.with_work_order(work_order.clone()),
            None => context,
        };
        let resume = Self::resume_info(
            trace_store.as_ref(),
            &run_id,
            &agent.tenant_id,
            &agent.agent_id,
        )?;
        let snapshot = state_graph
            .restore_snapshot_for_runtime_identity(
                &resume.info.snapshot_id,
                RuntimeSnapshotExpectation {
                    state_node_id: &resume.state_node_id,
                    state_hash: &resume.state_hash,
                    trace_event_id: &resume.trace_event_id,
                    tenant_id: &agent.tenant_id,
                    agent_id: &agent.agent_id,
                    run_id: &run_id,
                },
            )?
            .ok_or_else(|| LoopError::Resume(RESUME_STATE_IDENTITY_MISMATCH.to_string()))?;
        state_graph.set_tick(resume.info.tick_id);
        Self::with_shared_trace_runtime_and_work_order_mode(
            agent,
            state_graph,
            snapshot.state,
            policy,
            gateway,
            runtime,
            context,
            PersistedConstructionMode::Resume,
        )
    }

    /// Returns the agent identifier for this loop.
    pub fn agent_id(&self) -> &splendor_types::AgentId {
        &self.agent.agent_id
    }

    /// Returns the tenant identifier for this loop.
    pub fn tenant_id(&self) -> &splendor_types::TenantId {
        &self.agent.tenant_id
    }

    pub(crate) fn requires_reconciliation(&self) -> bool {
        self.reconciliation_block.is_some()
    }

    fn trace_identity(&self, tick_id: u64) -> TraceIdentityContext {
        self.runtime
            .trace_identity()
            .with_tenant_agent(self.agent.tenant_id.clone(), self.agent.agent_id.clone())
            .with_tick_id(TickId::from(tick_id))
    }

    fn record_tick_event(
        &self,
        tick_id: u64,
        kind: TraceEventKind,
    ) -> Result<TraceEvent, LoopError> {
        Ok(self
            .runtime
            .record_event_with_identity(self.trace_identity(tick_id), kind)?)
    }

    fn record_action_event(
        &self,
        tick_id: u64,
        action_id: &ActionId,
        kind: TraceEventKind,
    ) -> Result<TraceEvent, LoopError> {
        Ok(self.runtime.record_event_with_identity(
            self.trace_identity(tick_id)
                .with_action_id(action_id.clone()),
            kind,
        )?)
    }

    /// Restores state from a snapshot and updates the agent head pointer.
    pub fn restore_snapshot(&mut self, snapshot_id: &SnapshotId) -> Result<(), LoopError> {
        let snapshot = self.state_graph.restore_snapshot(snapshot_id)?;
        self.state = snapshot.state;
        self.agent.set_state_head(snapshot.node_id);
        Ok(())
    }

    /// Exports the current state head and records the source handoff boundary.
    pub fn export_state_handoff(
        &self,
        request: StateHandoffExportRequest,
    ) -> Result<(StateHandoff, TraceEvent), LoopError> {
        let mut handoff = self.state_graph.export_current_handoff(request)?;
        let event = self.runtime.record_state_handoff_exported(&mut handoff)?;
        Ok((handoff, event))
    }

    /// Imports state through the graph owner and records the receiver boundary.
    ///
    /// Trace failure rolls the live graph/agent head back to the previous value;
    /// immutable unreferenced store objects may remain but cannot affect runtime
    /// behavior.
    pub fn import_state_handoff(
        &mut self,
        handoff: &StateHandoff,
        work_order: &WorkOrderEnvelope,
        keyring: &WorkOrderKeyring,
        scope: &StateHandoffScope,
        now: OffsetDateTime,
        metadata: StateMetadata,
    ) -> Result<(StateCommit, TraceEvent), LoopError> {
        let previous_head = self.state_graph.head().cloned();
        let previous_state = self.state.clone();
        let commit = match self
            .state_graph
            .import_handoff(handoff, work_order, keyring, scope, now, metadata)
        {
            Ok(commit) => commit,
            Err(error) => {
                self.runtime
                    .record_state_handoff_import_failed(handoff, error.reason_code())?;
                return Err(error.into());
            }
        };
        let event = match self
            .runtime
            .record_state_handoff_imported(handoff, commit.node_id.to_string())
        {
            Ok(event) => event,
            Err(error) => {
                self.state_graph.set_head(previous_head.clone());
                self.agent.state_head = previous_head;
                self.state = previous_state;
                return Err(error.into());
            }
        };
        self.state = StateData {
            bytes: handoff.snapshot.state_bytes.clone(),
            content_type: handoff.snapshot.content_type.clone(),
        };
        self.agent.set_state_head(commit.node_id.clone());
        Ok((commit, event))
    }

    /// Adds a perceptor to the loop engine.
    pub fn add_perceptor(&mut self, perceptor: impl Perceptor + 'static) {
        self.perceptors.push(Box::new(perceptor));
    }

    /// Replaces the constraint engine.
    pub fn set_constraint_engine(&mut self, engine: impl ConstraintEngine + 'static) {
        self.constraint_engine = Box::new(engine);
    }

    /// Replaces the outcome evaluator.
    pub fn set_outcome_evaluator(&mut self, evaluator: impl OutcomeEvaluator + 'static) {
        self.outcome_evaluator = Box::new(evaluator);
    }

    /// Enables deterministic 0.04-S3 escalation evaluation for this loop. The
    /// evaluator consumes explicit verifier/runtime facts and only emits
    /// escalation trace events when a configured threshold is reached.
    pub fn set_escalation_policy(&mut self, policy: EscalationPolicy) -> Result<(), LoopError> {
        self.escalation_evaluator = Some(EscalationEvaluator::try_new(policy)?);
        Ok(())
    }

    /// Sets a policy runtime authority that can fail closed before policy
    /// invocation when required policy bundles are missing, expired, or revoked.
    pub fn set_policy_runtime_authority(&mut self, authority: Arc<dyn PolicyRuntimeAuthority>) {
        self.policy_authority = Some(authority);
    }

    /// Records a non-tick runtime event through this loop's trace runtime.
    pub fn record_runtime_event(&self, kind: TraceEventKind) -> Result<TraceEvent, LoopError> {
        self.runtime.record_event(kind).map_err(LoopError::Trace)
    }

    /// Records a non-tick action event with the run's tenant/agent/action scope
    /// through the same durable cursor used by scheduler ticks.
    pub fn record_runtime_action_event(
        &self,
        action_id: &ActionId,
        kind: TraceEventKind,
    ) -> Result<TraceEvent, LoopError> {
        let identity = self
            .runtime
            .trace_identity()
            .with_tenant_agent(self.agent.tenant_id.clone(), self.agent.agent_id.clone())
            .with_action_id(action_id.clone());
        self.runtime
            .record_event_with_identity(identity, kind)
            .map_err(LoopError::Trace)
    }

    /// Executes a single tick of the loop engine.
    pub fn tick(&mut self, tick_id: u64) -> Result<TickOutcome, LoopError> {
        if self.reconciliation_block.is_some() {
            return Err(LoopError::Policy(TICK_RECONCILIATION_REQUIRED.to_string()));
        }
        let start = Instant::now();
        self.record_tick_event(tick_id, TraceEventKind::LoopTickStarted { tick_id })?;

        let percepts = match self.collect_percepts() {
            Ok(percepts) => percepts,
            Err(LoopError::Perceptor(reason)) if reason == RAW_CREDENTIAL_INPUT_DENIED => {
                self.reconciliation_block = Some(TickReconciliationBlock::PersistenceDenied);
                return Err(LoopError::Perceptor(reason));
            }
            Err(error) => return Err(error),
        };
        self.record_tick_event(
            tick_id,
            TraceEventKind::PerceptsReceived {
                percepts: percepts.clone(),
            },
        )?;

        self.record_tick_event(
            tick_id,
            TraceEventKind::StateLoaded {
                state_hash: Some(ContentHash::blake3(&self.state.bytes)),
            },
        )?;

        let policy_name = self.policy.name().to_string();
        if let Some(authority) = self.policy_authority.as_ref() {
            let decision =
                authority.verify_policy_invocation(&policy_name, OffsetDateTime::now_utc());
            if let Some(trace_event) = decision.trace_event {
                self.record_tick_event(tick_id, trace_event)?;
            }
            if !decision.verification.allowed {
                return Err(LoopError::Policy(
                    if decision.verification.reasons.is_empty() {
                        "policy_invocation_denied".to_string()
                    } else {
                        decision.verification.reasons.join(", ")
                    },
                ));
            }
        }
        self.record_tick_event(
            tick_id,
            TraceEventKind::PolicyInvoked {
                policy: policy_name.clone(),
            },
        )?;
        let decision = self.policy.decide(&self.state, &percepts)?;
        if guard_persisted_state(
            &decision.next_state.bytes,
            decision.next_state.content_type.as_deref(),
            decision.metadata.label.as_deref(),
        )
        .is_err()
        {
            self.reconciliation_block = Some(TickReconciliationBlock::PersistenceDenied);
            return Err(LoopError::Policy(RAW_CREDENTIAL_INPUT_DENIED.to_string()));
        }
        self.record_tick_event(
            tick_id,
            TraceEventKind::PolicyCompleted {
                policy: policy_name,
            },
        )?;

        if decision
            .actions
            .iter()
            .any(|candidate| candidate.approval_evidence.is_some())
        {
            return Err(LoopError::Policy(
                "policy_raw_approval_evidence_forbidden".to_string(),
            ));
        }

        let mut explicit_action_ids = HashSet::new();
        if decision
            .actions
            .iter()
            .filter_map(|candidate| candidate.action_id.as_ref())
            .any(|action_id| !explicit_action_ids.insert(action_id))
        {
            return Err(LoopError::Policy(DUPLICATE_ACTION_ID.to_string()));
        }

        let screened_actions = decision
            .actions
            .iter()
            .map(|candidate| {
                let raw_credential_denied = guard_action_routing_and_receipts(
                    &candidate.action,
                    candidate.adapter.as_deref(),
                    &candidate.satisfied_preconditions,
                    &candidate.authority_obligation_receipts,
                )
                .is_err();
                ScreenedActionCandidate {
                    candidate,
                    action_id: candidate.action_id.clone().unwrap_or_default(),
                    trace_action: if raw_credential_denied {
                        raw_credential_denied_action()
                    } else {
                        candidate.action.clone()
                    },
                    raw_credential_denied,
                }
            })
            .collect::<Vec<_>>();
        self.record_tick_event(
            tick_id,
            TraceEventKind::CandidatesProposed {
                actions: screened_actions
                    .iter()
                    .map(|candidate| candidate.trace_action.clone())
                    .collect(),
            },
        )?;

        let constraint_candidates = screened_actions
            .iter()
            .filter(|candidate| !candidate.raw_credential_denied)
            .map(|candidate| candidate.candidate.clone())
            .collect::<Vec<_>>();
        let constraint_evaluation =
            self.constraint_engine
                .evaluate(&self.state, &percepts, &constraint_candidates);
        self.record_tick_event(
            tick_id,
            TraceEventKind::ConstraintsEvaluated {
                constraints: constraint_evaluation.constraints.clone(),
                result: constraint_evaluation.result.clone(),
            },
        )?;

        let mut outcomes = Vec::new();
        let mut escalations = Vec::new();
        let mut tick_effect_entered = false;
        let mut tick_requires_reconciliation = false;
        for screened in &screened_actions {
            let candidate = screened.candidate;
            let action = screened.trace_action.clone();
            let action_id = screened.action_id.clone();
            self.record_action_event(
                tick_id,
                &action_id,
                TraceEventKind::ActionVerificationStarted {
                    action: action.clone(),
                },
            )?;

            let mut effect_boundary = None;
            let mut outcome = if screened.raw_credential_denied {
                raw_credential_denied_outcome(action_id.clone())
            } else if !constraint_evaluation.result.allowed {
                ActionOutcome {
                    action_id: action_id.clone(),
                    status: ActionStatus::Denied,
                    verification: constraint_evaluation.result.clone(),
                    post_verification: None,
                    output: None,
                    error: Some(constraint_evaluation.result.reasons.join(", ")),
                    approval_challenge: None,
                    completed_at: OffsetDateTime::now_utc(),
                }
            } else {
                let mut delegated_scope = self.agent.verify_delegated_action_with_grant(
                    &candidate.action,
                    candidate.adapter.as_deref(),
                    self.runtime.run_id(),
                    candidate.delegated_capability_grant_id.as_ref(),
                    candidate.usage,
                    OffsetDateTime::now_utc(),
                    tick_id,
                );
                if !delegated_scope.allowed() {
                    ActionOutcome {
                        action_id: action_id.clone(),
                        status: ActionStatus::Denied,
                        verification: delegated_scope.verification.clone(),
                        post_verification: None,
                        output: None,
                        error: Some(delegated_scope.verification.reasons.join(", ")),
                        approval_challenge: None,
                        completed_at: OffsetDateTime::now_utc(),
                    }
                } else {
                    let request = ActionRequest {
                        action_id: action_id.clone(),
                        tenant_id: self.agent.tenant_id.clone(),
                        agent_id: self.agent.agent_id.clone(),
                        run_id: self.runtime.run_id().clone(),
                        tick_id: Some(TickId::from(tick_id)),
                        action: candidate.action.clone(),
                        adapter: candidate.adapter.clone(),
                        quota_usage: candidate.usage,
                        satisfied_preconditions: candidate.satisfied_preconditions.clone(),
                        requested_at: candidate
                            .requested_at
                            .unwrap_or_else(OffsetDateTime::now_utc),
                        physical_action_resource_coordinate: None,
                        approval_evidence: candidate.approval_evidence.clone(),
                        authority_obligation_evidence: None,
                        authority_obligation_receipts: candidate
                            .authority_obligation_receipts
                            .clone(),
                    };

                    // Keep the live authority permit through gateway entry. The
                    // permit linearizes cleanup/revocation against this effect.
                    let _delegated_permit = delegated_scope.take_permit();
                    // Until the gateway returns a result that proves no adapter
                    // entry, every following failure must conservatively park
                    // this live engine.
                    self.reconciliation_block = Some(TickReconciliationBlock::EffectInFlight);
                    match self.gateway.submit(request) {
                        Ok(mut outcome) => {
                            effect_boundary = effect_boundary_from_outcome(&outcome);
                            if let Some(boundary) = effect_boundary {
                                attach_effect_boundary(&mut outcome, boundary);
                            }
                            outcome
                        }
                        Err(error) => {
                            effect_boundary = effect_boundary_from_gateway_error(&error);
                            let mut outcome = outcome_from_gateway_error(action_id.clone(), error);
                            if let Some(boundary) = effect_boundary {
                                attach_effect_boundary(&mut outcome, boundary);
                            }
                            outcome
                        }
                    }
                }
            };

            if let Some(boundary) = effect_boundary {
                tick_effect_entered = true;
                tick_requires_reconciliation |= boundary.reconciliation_required_after_tick;
                self.reconciliation_block = Some(TickReconciliationBlock::EffectInFlight);
            } else if !tick_effect_entered {
                // The gateway result proved that no adapter was entered, and no
                // earlier action in this tick has an in-flight effect.
                self.reconciliation_block = None;
            }

            let action_escalations = if screened.raw_credential_denied {
                Vec::new()
            } else {
                self.evaluate_escalations(
                    &action_id,
                    &candidate.action,
                    candidate.adapter.as_deref(),
                    &mut outcome,
                )
            };

            if let Some(policy_expired) = (!screened.raw_credential_denied)
                .then(|| action_policy_expired_trace_kind(&candidate.action, &outcome))
                .flatten()
            {
                self.record_action_event(tick_id, &action_id, policy_expired)?;
            }

            if !authority_pre_effect_evidence_recorded(&outcome.verification) {
                self.record_action_event(
                    tick_id,
                    &action_id,
                    TraceEventKind::ActionVerificationCompleted {
                        action: action.clone(),
                        result: outcome.verification.clone(),
                    },
                )?;
            }

            for escalation in &action_escalations {
                self.record_action_event(
                    tick_id,
                    &action_id,
                    TraceEventKind::EscalationTriggered {
                        escalation: escalation.clone(),
                    },
                )?;
            }

            match outcome.status {
                ActionStatus::Executed => {
                    if !screened.raw_credential_denied {
                        self.record_approval_event_if_present(tick_id, &action_id, &outcome)?;
                    }
                    self.record_action_event(
                        tick_id,
                        &action_id,
                        TraceEventKind::ActionExecuted {
                            action: action.clone(),
                            outcome: outcome.output.clone().unwrap_or(serde_json::Value::Null),
                        },
                    )?;
                }
                ActionStatus::Denied => {
                    self.record_approval_event_if_present(tick_id, &action_id, &outcome)?;
                    self.record_action_event(
                        tick_id,
                        &action_id,
                        TraceEventKind::ActionDenied {
                            action: action.clone(),
                            result: outcome.verification.clone(),
                        },
                    )?;
                }
                ActionStatus::NeedsApproval => {
                    self.record_approval_event_if_present(tick_id, &action_id, &outcome)?;
                    self.record_action_event(
                        tick_id,
                        &action_id,
                        TraceEventKind::ActionNeedsApproval {
                            action: action.clone(),
                            result: outcome.verification.clone(),
                        },
                    )?;
                }
                ActionStatus::NeedsIntervention => {
                    self.record_approval_event_if_present(tick_id, &action_id, &outcome)?;
                    self.record_action_event(
                        tick_id,
                        &action_id,
                        TraceEventKind::ActionNeedsIntervention {
                            action: action.clone(),
                            result: outcome.verification.clone(),
                        },
                    )?;
                }
                ActionStatus::Failed => {
                    if outcome.output.is_some() {
                        self.record_action_event(
                            tick_id,
                            &action_id,
                            TraceEventKind::ActionExecuted {
                                action: action.clone(),
                                outcome: outcome.output.clone().unwrap_or(serde_json::Value::Null),
                            },
                        )?;
                    }
                    let denial = outcome
                        .post_verification
                        .clone()
                        .filter(|result| !result.allowed)
                        .unwrap_or_else(|| {
                            VerificationResult::deny(
                                outcome
                                    .error
                                    .clone()
                                    .unwrap_or_else(|| "action_failed".to_string()),
                            )
                        });
                    self.record_action_event(
                        tick_id,
                        &action_id,
                        TraceEventKind::ActionFailed {
                            action: action.clone(),
                            error: outcome
                                .error
                                .clone()
                                .unwrap_or_else(|| "action_failed".to_string()),
                            result: denial,
                        },
                    )?;
                }
            }

            escalations.extend(action_escalations);
            outcomes.push(outcome);
            if effect_boundary.is_some_and(|boundary| boundary.reconciliation_required_after_tick) {
                break;
            }
        }

        let raw_credential_denials = screened_actions
            .iter()
            .map(|candidate| candidate.raw_credential_denied)
            .collect::<Vec<_>>();
        let (feedback, reward) =
            self.evaluate_outcomes(&decision, &outcomes, &raw_credential_denials);
        let duration_ms = start.elapsed().as_millis() as u64;
        let needs_intervention = escalations_require_intervention(&escalations)
            || outcomes.iter().any(|outcome| {
                outcome.status == ActionStatus::NeedsIntervention
                    || outcome
                        .post_verification
                        .as_ref()
                        .map(|result| !result.allowed)
                        .unwrap_or(false)
            });
        let needs_approval = outcomes
            .iter()
            .any(|outcome| outcome.status == ActionStatus::NeedsApproval);
        let outcome_payload = serde_json::json!({
            "tick_id": tick_id,
            "duration_ms": duration_ms,
            "needs_intervention": needs_intervention,
            "needs_approval": needs_approval,
            "escalations": escalations,
            "actions": outcomes
                .iter()
                .map(|outcome| serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null))
                .collect::<Vec<_>>(),
        });

        self.record_tick_event(
            tick_id,
            TraceEventKind::OutcomeRecorded {
                outcome: outcome_payload,
                feedback,
                reward,
            },
        )?;

        let state_trace_event_id =
            TraceEventId::from_run_sequence(self.runtime.run_id(), self.runtime.next_sequence());
        let mut metadata = decision.metadata.clone();
        metadata.tenant_id = Some(self.agent.tenant_id.clone());
        metadata.agent_id = Some(self.agent.agent_id.clone());
        metadata.run_id = Some(self.runtime.run_id().clone());
        metadata.trace_event_id = Some(state_trace_event_id);
        let commit = self
            .state_graph
            .commit(decision.next_state.clone(), metadata)?;
        self.state = decision.next_state;
        self.agent.set_state_head(commit.node_id.clone());

        self.runtime.record_event_with_identity(
            self.trace_identity(tick_id)
                .with_state_node_id(commit.node_id.clone()),
            TraceEventKind::StateCommitted {
                state_hash: commit.node_id.hash().clone(),
                snapshot_id: commit.snapshot_id.clone(),
            },
        )?;

        self.record_tick_event(
            tick_id,
            TraceEventKind::LoopTickCompleted {
                tick_id,
                integrity: None,
            },
        )?;

        if tick_effect_entered && !tick_requires_reconciliation {
            self.reconciliation_block = None;
        }

        Ok(TickOutcome {
            tick_id,
            action_outcomes: outcomes,
            state_commit: commit,
            duration_ms,
            needs_intervention,
            needs_approval,
        })
    }

    fn record_approval_event_if_present(
        &self,
        tick_id: u64,
        action_id: &ActionId,
        outcome: &ActionOutcome,
    ) -> Result<(), LoopError> {
        let Some((status, approval)) = approval_artifact(&outcome.verification) else {
            return Ok(());
        };
        let kind = approval_trace_kind(status.as_str(), approval);
        self.record_action_event(tick_id, action_id, kind)?;
        Ok(())
    }

    fn collect_percepts(&self) -> Result<Vec<Percept>, LoopError> {
        let mut percepts = Vec::new();
        for perceptor in &self.perceptors {
            let mut batch = perceptor.collect(&self.agent)?;
            if batch
                .iter()
                .any(|percept| guard_persisted_percept(percept).is_err())
            {
                return Err(LoopError::Perceptor(
                    RAW_CREDENTIAL_INPUT_DENIED.to_string(),
                ));
            }
            percepts.append(&mut batch);
        }
        Ok(percepts)
    }

    fn evaluate_outcomes(
        &self,
        decision: &PolicyDecision,
        outcomes: &[ActionOutcome],
        raw_credential_denials: &[bool],
    ) -> (Option<Feedback>, Option<Reward>) {
        let mut feedback = None;
        let mut reward = None;
        for ((candidate, outcome), raw_credential_denied) in decision
            .actions
            .iter()
            .zip(outcomes.iter())
            .zip(raw_credential_denials.iter().copied())
        {
            if raw_credential_denied {
                continue;
            }
            let signal = self.outcome_evaluator.evaluate(&candidate.action, outcome);
            if feedback.is_none() {
                feedback = signal.feedback;
            }
            if reward.is_none() {
                reward = signal.reward;
            }
        }
        (feedback, reward)
    }

    fn evaluate_escalations(
        &self,
        action_id: &ActionId,
        action: &Action,
        adapter: Option<&str>,
        outcome: &mut ActionOutcome,
    ) -> Vec<EscalationContext> {
        let Some(evaluator) = &self.escalation_evaluator else {
            return Vec::new();
        };
        let input = EscalationOutcomeInput {
            tenant_id: &self.agent.tenant_id,
            agent_id: &self.agent.agent_id,
            run_id: self.runtime.run_id(),
            action_id,
            action,
            adapter,
            outcome,
        };
        let escalations = evaluator.evaluate_outcome(&input);
        for escalation in &escalations {
            apply_escalation_to_outcome(outcome, escalation);
        }
        escalations
    }

    fn resume_info(
        trace_store: &dyn TraceStore,
        run_id: &RunId,
        tenant_id: &splendor_types::TenantId,
        agent_id: &splendor_types::AgentId,
    ) -> Result<ResumeSelection, LoopError> {
        let records = trace_store.read(&run_id.to_string())?;
        let mut snapshot = None;
        let mut tick_id = None;
        let mut open_tick_attempts = HashMap::<u64, bool>::new();
        let mut pending_snapshots = HashMap::<u64, ResumeSelection>::new();
        for record in records {
            let event: TraceEvent = serde_json::from_value(record.payload)?;
            if !trace_event_matches_runtime_identity(&event, run_id, tenant_id, agent_id) {
                continue;
            }
            if let TraceEventKind::ActionFailed { error, result, .. } = &event.kind {
                if action_failure_requires_reconciliation(error, result) {
                    return Err(LoopError::Resume(TICK_RECONCILIATION_REQUIRED.to_string()));
                }
            }
            match &event.kind {
                TraceEventKind::LoopTickStarted { tick_id: started } => {
                    if open_tick_attempts.get(started).copied().unwrap_or(false) {
                        return Err(LoopError::Resume(TICK_RECONCILIATION_REQUIRED.to_string()));
                    }
                    open_tick_attempts.insert(*started, false);
                }
                TraceEventKind::ActionVerificationStarted { .. } => {
                    let Some(action_tick_id) = event.identity.tick_id else {
                        return Err(LoopError::Resume(TICK_RECONCILIATION_REQUIRED.to_string()));
                    };
                    open_tick_attempts.insert(action_tick_id.get(), true);
                }
                TraceEventKind::LoopTickCompleted {
                    tick_id: completed, ..
                } => {
                    open_tick_attempts.remove(completed);
                    tick_id = Some(*completed);
                    snapshot = pending_snapshots.remove(completed);
                }
                TraceEventKind::StateCommitted {
                    state_hash,
                    snapshot_id: Some(snapshot_id),
                } => {
                    let (Some(state_tick_id), Some(state_node_id)) = (
                        event.identity.tick_id.as_ref(),
                        event.identity.state_node_id.as_ref(),
                    ) else {
                        return Err(LoopError::Resume(
                            RESUME_STATE_IDENTITY_MISMATCH.to_string(),
                        ));
                    };
                    pending_snapshots.insert(
                        state_tick_id.get(),
                        ResumeSelection {
                            info: ResumeInfo {
                                snapshot_id: snapshot_id.clone(),
                                tick_id: state_tick_id.get(),
                            },
                            state_node_id: state_node_id.clone(),
                            state_hash: state_hash.clone(),
                            trace_event_id: event.trace_event_id.clone(),
                        },
                    );
                }
                _ => {}
            }
        }

        if open_tick_attempts
            .values()
            .any(|action_started| *action_started)
        {
            return Err(LoopError::Resume(TICK_RECONCILIATION_REQUIRED.to_string()));
        }

        let snapshot = snapshot.ok_or_else(|| {
            LoopError::Resume(if tick_id.is_some() {
                RESUME_LATEST_COMPLETED_SNAPSHOT_UNAVAILABLE.to_string()
            } else {
                "no snapshot found in trace history".to_string()
            })
        })?;
        Ok(snapshot)
    }
}

fn outcome_from_gateway_error(action_id: ActionId, error: GatewayError) -> ActionOutcome {
    let message = error.to_string();
    ActionOutcome {
        action_id,
        status: ActionStatus::Failed,
        verification: VerificationResult::deny(message.clone()),
        post_verification: None,
        output: None,
        error: Some(message),
        approval_challenge: None,
        completed_at: OffsetDateTime::now_utc(),
    }
}

fn trace_error_is_fresh_admission_conflict(error: &TraceError) -> bool {
    matches!(
        error,
        TraceError::Store(TraceStoreError::SequenceMismatch {
            expected: 0,
            actual: _
        })
    )
}

fn trace_event_matches_runtime_identity(
    event: &TraceEvent,
    run_id: &RunId,
    tenant_id: &splendor_types::TenantId,
    agent_id: &splendor_types::AgentId,
) -> bool {
    &event.run_id == run_id
        && &event.identity.run_id == run_id
        && event.identity.tenant_id.as_ref() == Some(tenant_id)
        && event.identity.agent_id.as_ref() == Some(agent_id)
}

fn effect_boundary_from_gateway_error(error: &GatewayError) -> Option<EffectBoundary> {
    let taxonomy = error.taxonomy();
    (taxonomy.effect_certainty != EffectCertainty::None).then_some(EffectBoundary {
        effect_certainty: taxonomy.effect_certainty,
        retry_class: RetryClass::NotRetryable,
        reconciliation_required_after_tick: true,
    })
}

fn effect_boundary_from_outcome(outcome: &ActionOutcome) -> Option<EffectBoundary> {
    let declared = outcome
        .post_verification
        .as_ref()
        .and_then(effect_boundary_from_verification);
    if let Some(mut boundary) = declared {
        if outcome.status == ActionStatus::Failed {
            boundary.reconciliation_required_after_tick = true;
        }
        return Some(boundary);
    }

    match outcome.status {
        ActionStatus::Executed => Some(EffectBoundary {
            effect_certainty: EffectCertainty::Known,
            retry_class: RetryClass::NotRetryable,
            reconciliation_required_after_tick: false,
        }),
        ActionStatus::Failed => Some(EffectBoundary {
            effect_certainty: if outcome.output.is_some() {
                EffectCertainty::Known
            } else {
                EffectCertainty::Uncertain
            },
            retry_class: RetryClass::NotRetryable,
            reconciliation_required_after_tick: true,
        }),
        ActionStatus::Denied | ActionStatus::NeedsApproval | ActionStatus::NeedsIntervention => {
            None
        }
    }
}

fn effect_boundary_from_verification(result: &VerificationResult) -> Option<EffectBoundary> {
    if result.artifacts.get("adapter_entered")?.as_bool() != Some(true) {
        return None;
    }
    let effect_certainty = match result
        .artifacts
        .get("effect_certainty")
        .and_then(serde_json::Value::as_str)
    {
        Some("known") => EffectCertainty::Known,
        Some("none") => EffectCertainty::None,
        _ => EffectCertainty::Uncertain,
    };
    Some(EffectBoundary {
        effect_certainty,
        retry_class: RetryClass::NotRetryable,
        reconciliation_required_after_tick: result
            .artifacts
            .get("reconciliation_required")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
    })
}

fn attach_effect_boundary(outcome: &mut ActionOutcome, boundary: EffectBoundary) {
    let failed = outcome.status == ActionStatus::Failed;
    let fallback_reason = outcome
        .error
        .clone()
        .unwrap_or_else(|| "action_failed".to_string());
    let result = outcome.post_verification.get_or_insert_with(|| {
        if failed {
            VerificationResult::deny(fallback_reason)
        } else {
            VerificationResult::allow()
        }
    });
    if failed && result.allowed {
        result.allowed = false;
        if result.reasons.is_empty() {
            result.reasons.push("action_failed".to_string());
        }
    }
    if !result.artifacts.is_object() {
        result.artifacts = serde_json::json!({});
    }
    let Some(artifacts) = result.artifacts.as_object_mut() else {
        return;
    };
    artifacts.insert("adapter_entered".to_string(), serde_json::Value::Bool(true));
    artifacts.insert(
        "effect_certainty".to_string(),
        serde_json::Value::String(boundary.effect_certainty.as_str().to_string()),
    );
    artifacts.insert(
        "retry_class".to_string(),
        serde_json::Value::String(boundary.retry_class.as_str().to_string()),
    );
    artifacts.insert(
        "reconciliation_required".to_string(),
        serde_json::Value::Bool(boundary.reconciliation_required_after_tick),
    );
}

fn action_failure_requires_reconciliation(error: &str, result: &VerificationResult) -> bool {
    effect_boundary_from_verification(result)
        .is_some_and(|boundary| boundary.reconciliation_required_after_tick)
        || (error == RAW_CREDENTIAL_OUTPUT_SUPPRESSED
            && !result.allowed
            && result.reasons.len() == 1
            && result.reasons.first().map(String::as_str) == Some(RAW_CREDENTIAL_OUTPUT_SUPPRESSED))
}

fn action_policy_expired_trace_kind(
    action: &Action,
    outcome: &ActionOutcome,
) -> Option<TraceEventKind> {
    if outcome.verification.allowed
        || !outcome
            .verification
            .reasons
            .iter()
            .any(|reason| reason == "policy_expired")
    {
        return None;
    }
    let artifacts = &outcome.verification.artifacts;
    if artifacts.get("source")?.as_str()? != "policy_distribution_cache" {
        return None;
    }
    let policy_bundle_id =
        PolicyBundleId::try_new(artifacts.get("policy_bundle_id")?.as_str()?).ok()?;
    let version = artifacts.get("version")?.as_str()?.to_string();
    let action_name = artifacts
        .get("action")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(action.name.as_str())
        .to_string();
    Some(TraceEventKind::PolicyExpired {
        policy_bundle_id,
        version,
        action: Some(action_name),
    })
}

fn approval_artifact(result: &VerificationResult) -> Option<(String, ApprovalTraceContext)> {
    let artifact = result
        .artifacts
        .get("approval")
        .or_else(|| result.artifacts.get("approval_context"))?;
    let (status, approval_value) = if artifact.get("approval").is_some() {
        (
            artifact
                .get("approval_status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            artifact.get("approval")?,
        )
    } else {
        (
            result
                .artifacts
                .get("approval_status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            artifact,
        )
    };
    serde_json::from_value::<ApprovalTraceContext>(approval_value.clone())
        .ok()
        .map(|approval| (status, approval))
}

fn approval_trace_kind(status: &str, approval: ApprovalTraceContext) -> TraceEventKind {
    match status {
        "required" => TraceEventKind::ApprovalRequested { approval },
        "granted" => TraceEventKind::ApprovalGranted { approval },
        "expired" => TraceEventKind::ApprovalExpired {
            approval,
            reason: "approval_expired".to_string(),
        },
        "revoked" => TraceEventKind::ApprovalRevoked {
            approval,
            reason: "approval_revoked".to_string(),
        },
        "intervention_required" => TraceEventKind::ApprovalDenied {
            approval,
            reason: "approval_policy_expired".to_string(),
        },
        "policy_schema_unsupported" => TraceEventKind::ApprovalDenied {
            approval,
            reason: "approval_policy_schema_unsupported".to_string(),
        },
        "schema_unsupported" => TraceEventKind::ApprovalDenied {
            approval,
            reason: "approval_evidence_schema_unsupported".to_string(),
        },
        _ => TraceEventKind::ApprovalDenied {
            approval,
            reason: "approval_denied".to_string(),
        },
    }
}

#[cfg(test)]
#[path = "../tests/unit/loop_engine_tests.rs"]
mod tests;
