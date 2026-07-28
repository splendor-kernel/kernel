use super::*;
use crate::SnapshotPolicy;
use splendor_store::{
    InMemoryStateStore, InMemoryTraceStore, SqliteTraceStore, StateData, StateDataRef,
    StateMetadata, StateNode, StateNodeId, StateSnapshot, StateStore, StateStoreError,
    TraceStoreError,
};
use splendor_types::{
    validate_policy_bundle, ActionId, AgentId, ApprovalDecision, ApprovalEvidence, ApprovalId,
    ApprovalTraceContext, ConstraintKind, ConstraintScope, DelegatedAuthority, PerceptProvenance,
    PolicyBundle, PolicyBundleEnvelope, PolicyBundleId, PolicyBundleKeyring,
    PolicyBundleTraceContext, PolicyBundleValidationContext, PolicyDegradedMode, QuotaUsage,
    RevocationStatus, RunId, StateHandoffAuthority, TenantId, TickId, TraceEvent, TraceEventId,
    TraceId, WorkOrder, WorkOrderEnvelope, WorkOrderId, WorkOrderKeyring, WorkOrderPlacement,
    WorkOrderQuotaPolicy, WORK_ORDER_SCHEMA_VERSION,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

struct LoopPolicyTraceRecorder;

impl crate::PolicyCacheMutationRecorder for LoopPolicyTraceRecorder {
    fn record_policy_cache_event(
        &self,
        _event: TraceEventKind,
    ) -> Result<(), crate::PolicyCacheTraceError> {
        Ok(())
    }
}

#[derive(Clone)]
struct CapturingTraceSink {
    events: Arc<Mutex<Vec<TraceEvent>>>,
}

impl crate::TraceSink for CapturingTraceSink {
    fn record(&self, event: &TraceEvent) -> Result<(), crate::TraceError> {
        self.events.lock().expect("events lock").push(event.clone());
        Ok(())
    }
}

#[derive(Clone)]
struct FailingActionVerificationTraceSink {
    events: Arc<Mutex<Vec<TraceEvent>>>,
    failed: Arc<Mutex<bool>>,
}

impl crate::TraceSink for FailingActionVerificationTraceSink {
    fn record(&self, event: &TraceEvent) -> Result<(), crate::TraceError> {
        let mut failed = self.failed.lock().expect("failed lock");
        if !*failed
            && matches!(
                &event.kind,
                TraceEventKind::ActionVerificationStarted { .. }
            )
        {
            *failed = true;
            return Err(crate::TraceError::Store(TraceStoreError::Poisoned));
        }
        drop(failed);

        self.events.lock().expect("events lock").push(event.clone());
        Ok(())
    }
}

struct FailingStateHandoffImportedTraceSink;

impl crate::TraceSink for FailingStateHandoffImportedTraceSink {
    fn record(&self, event: &TraceEvent) -> Result<(), crate::TraceError> {
        if matches!(event.kind, TraceEventKind::StateHandoffImported { .. }) {
            return Err(crate::TraceError::Store(TraceStoreError::Poisoned));
        }
        Ok(())
    }
}

struct StaticPerceptor;

impl Perceptor for StaticPerceptor {
    fn collect(&self, _agent: &AgentContext) -> Result<Vec<Percept>, LoopError> {
        Ok(vec![Percept {
            schema: "sensor".to_string(),
            payload: serde_json::json!({"value": 7}),
            provenance: PerceptProvenance {
                source: "unit".to_string(),
                detail: None,
            },
            timestamp: OffsetDateTime::now_utc(),
        }])
    }
}

struct StaticPolicy;

impl Policy for StaticPolicy {
    fn name(&self) -> &str {
        "static-policy"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, LoopError> {
        let action = Action {
            name: "noop".to_string(),
            params: serde_json::json!({"ok": true}),
            side_effect_class: splendor_types::SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        };
        let candidate = ActionCandidate::new(action);
        let next_state = StateData {
            bytes: vec![2],
            content_type: Some("application/octet-stream".to_string()),
        };
        Ok(PolicyDecision::new(
            vec![candidate],
            next_state,
            Some("tick".to_string()),
        ))
    }
}

struct RawApprovalEvidencePolicy {
    evidence: ApprovalEvidence,
}

impl Policy for RawApprovalEvidencePolicy {
    fn name(&self) -> &str {
        "raw-approval-evidence-policy"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, LoopError> {
        let action = Action {
            name: "noop".to_string(),
            params: serde_json::json!({"ok": true}),
            side_effect_class: splendor_types::SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        };
        Ok(PolicyDecision::new(
            vec![ActionCandidate::new(action).with_approval_evidence(self.evidence.clone())],
            StateData {
                bytes: vec![2],
                content_type: None,
            },
            Some("must-not-commit".to_string()),
        ))
    }
}

#[derive(Default)]
struct StubGateway;

impl ActionGateway for StubGateway {
    fn submit(&self, action: ActionRequest) -> Result<ActionOutcome, GatewayError> {
        Ok(ActionOutcome {
            action_id: action.action_id,
            status: ActionStatus::Executed,
            verification: VerificationResult::allow(),
            post_verification: Some(VerificationResult::allow()),
            output: Some(serde_json::json!({"ok": true})),
            error: None,
            approval_challenge: None,
            completed_at: OffsetDateTime::now_utc(),
        })
    }
}

struct StaticAdapterPolicy;

impl Policy for StaticAdapterPolicy {
    fn name(&self) -> &str {
        "static-adapter-policy"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, LoopError> {
        let action = Action {
            name: "noop".to_string(),
            params: serde_json::json!({"ok": true}),
            side_effect_class: splendor_types::SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        };
        let next_state = StateData {
            bytes: vec![2],
            content_type: Some("application/octet-stream".to_string()),
        };
        Ok(PolicyDecision::new(
            vec![ActionCandidate::new(action).with_adapter("stub".to_string())],
            next_state,
            Some("tick".to_string()),
        ))
    }
}

#[derive(Default)]
struct DenyGateway;

impl ActionGateway for DenyGateway {
    fn submit(&self, action: ActionRequest) -> Result<ActionOutcome, GatewayError> {
        Ok(ActionOutcome {
            action_id: action.action_id,
            status: ActionStatus::Denied,
            verification: VerificationResult::deny("denied"),
            post_verification: None,
            output: None,
            error: Some("denied".to_string()),
            approval_challenge: None,
            completed_at: OffsetDateTime::now_utc(),
        })
    }
}

#[derive(Default)]
struct ExpiredPolicyGateway;

impl ActionGateway for ExpiredPolicyGateway {
    fn submit(&self, action: ActionRequest) -> Result<ActionOutcome, GatewayError> {
        Ok(ActionOutcome {
            action_id: action.action_id,
            status: ActionStatus::Denied,
            verification: VerificationResult {
                allowed: false,
                reasons: vec!["policy_expired".to_string()],
                artifacts: serde_json::json!({
                    "source": "policy_distribution_cache",
                    "policy_bundle_id": "policy_unit_expired",
                    "version": "unit.v1",
                    "action": action.action.name,
                }),
            },
            post_verification: None,
            output: None,
            error: Some("policy_expired".to_string()),
            approval_challenge: None,
            completed_at: OffsetDateTime::now_utc(),
        })
    }
}

#[derive(Default)]
struct StaticConstraintEngine;

impl ConstraintEngine for StaticConstraintEngine {
    fn evaluate(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
        _actions: &[ActionCandidate],
    ) -> ConstraintEvaluation {
        ConstraintEvaluation {
            constraints: vec![Constraint {
                id: "c1".to_string(),
                kind: ConstraintKind::Hard,
                scope: ConstraintScope::Action,
                predicate: "always".to_string(),
                obligation: None,
            }],
            result: VerificationResult::allow(),
        }
    }
}

#[derive(Default)]
struct DenyConstraintEngine;

impl ConstraintEngine for DenyConstraintEngine {
    fn evaluate(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
        _actions: &[ActionCandidate],
    ) -> ConstraintEvaluation {
        ConstraintEvaluation {
            constraints: vec![Constraint {
                id: "deny".to_string(),
                kind: ConstraintKind::Hard,
                scope: ConstraintScope::Action,
                predicate: "never".to_string(),
                obligation: None,
            }],
            result: VerificationResult::deny("constraints_denied"),
        }
    }
}

#[derive(Default)]
struct CountingGateway {
    calls: Arc<Mutex<u32>>,
}

impl ActionGateway for CountingGateway {
    fn submit(&self, action: ActionRequest) -> Result<ActionOutcome, GatewayError> {
        *self.calls.lock().expect("calls lock") += 1;
        Ok(ActionOutcome {
            action_id: action.action_id,
            status: ActionStatus::Executed,
            verification: VerificationResult::allow(),
            post_verification: Some(VerificationResult::allow()),
            output: Some(serde_json::json!({"ok": true})),
            error: None,
            approval_challenge: None,
            completed_at: OffsetDateTime::now_utc(),
        })
    }
}

#[derive(Default)]
struct ErrorGateway;

impl ActionGateway for ErrorGateway {
    fn submit(&self, _action: ActionRequest) -> Result<ActionOutcome, GatewayError> {
        Err(GatewayError::AdapterFailed("boom".to_string()))
    }
}

struct MultiActionPolicy;

impl Policy for MultiActionPolicy {
    fn name(&self) -> &str {
        "multi-policy"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, LoopError> {
        let first = Action {
            name: "first".to_string(),
            params: serde_json::json!({}),
            side_effect_class: splendor_types::SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        };
        let second = Action {
            name: "second".to_string(),
            params: serde_json::json!({}),
            side_effect_class: splendor_types::SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        };
        let next_state = StateData {
            bytes: vec![4],
            content_type: None,
        };
        Ok(PolicyDecision::new(
            vec![ActionCandidate::new(first), ActionCandidate::new(second)],
            next_state,
            None,
        ))
    }
}

struct ForgedStateMetadataPolicy {
    tenant_id: splendor_types::TenantId,
    agent_id: splendor_types::AgentId,
    run_id: RunId,
    trace_event_id: splendor_types::TraceEventId,
}

impl Policy for ForgedStateMetadataPolicy {
    fn name(&self) -> &str {
        "forged-state-metadata-policy"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, LoopError> {
        let mut metadata = StateMetadata::new(
            OffsetDateTime::now_utc(),
            Some("policy-supplied-label".to_string()),
        );
        metadata.tenant_id = Some(self.tenant_id.clone());
        metadata.agent_id = Some(self.agent_id.clone());
        metadata.run_id = Some(self.run_id.clone());
        metadata.trace_event_id = Some(self.trace_event_id.clone());
        Ok(PolicyDecision {
            actions: Vec::new(),
            next_state: StateData {
                bytes: vec![9],
                content_type: None,
            },
            metadata,
        })
    }
}

fn work_order_for(agent: &AgentContext, run_id: RunId) -> WorkOrder {
    let now = OffsetDateTime::now_utc();
    WorkOrder {
        schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new("wo_loop").expect("work order id"),
        tenant_id: agent.tenant_id.clone(),
        agent_id: agent.agent_id.clone(),
        run_id: Some(run_id),
        objective: "record work order metadata".to_string(),
        allowed_actions: vec!["noop".to_string()],
        allowed_adapters: vec!["stub".to_string()],
        allowed_permissions: Vec::new(),
        data_refs: Vec::new(),
        quotas: WorkOrderQuotaPolicy::default(),
        placement: WorkOrderPlacement::default(),
        issued_at: now - time::Duration::minutes(1),
        expires_at: now + time::Duration::hours(1),
        revocation: RevocationStatus::Active,
    }
}

fn signed_work_order_for(agent: &AgentContext, run_id: RunId) -> WorkOrderEnvelope {
    WorkOrderEnvelope::signed_with_shared_secret(
        work_order_for(agent, run_id),
        "key_loop_state_handoff",
        b"loop-state-handoff-secret",
    )
    .expect("signed work order")
}

fn state_handoff_keyring() -> WorkOrderKeyring {
    let mut keyring = WorkOrderKeyring::new();
    keyring
        .insert_shared_secret("key_loop_state_handoff", b"loop-state-handoff-secret")
        .expect("state handoff key");
    keyring
}

fn policy_bundle_for(
    agent: &AgentContext,
    expires_at: OffsetDateTime,
    allow_low_risk_cached: bool,
) -> PolicyBundle {
    PolicyBundle {
        schema_version: splendor_types::POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
        policy_bundle_id: PolicyBundleId::try_new("pol_loop").expect("policy bundle id"),
        version: "v1".to_string(),
        tenant_id: agent.tenant_id.clone(),
        agent_id: Some(agent.agent_id.clone()),
        issued_at: expires_at - time::Duration::hours(1),
        expires_at,
        revocation: RevocationStatus::Active,
        degraded_mode: PolicyDegradedMode {
            allow_low_risk_cached,
            ..PolicyDegradedMode::default()
        },
    }
}

struct RecordingOutcomeEvaluator;

impl OutcomeEvaluator for RecordingOutcomeEvaluator {
    fn evaluate(&self, action: &Action, _outcome: &ActionOutcome) -> OutcomeSignal {
        let now = OffsetDateTime::now_utc();
        if action.name == "first" {
            OutcomeSignal {
                feedback: Some(Feedback {
                    kind: "first".to_string(),
                    payload: serde_json::json!({"action": "first"}),
                    recorded_at: now,
                }),
                reward: None,
            }
        } else {
            OutcomeSignal {
                feedback: Some(Feedback {
                    kind: "second".to_string(),
                    payload: serde_json::json!({"action": "second"}),
                    recorded_at: now,
                }),
                reward: Some(Reward {
                    value: 2.0,
                    units: Some("pts".to_string()),
                    recorded_at: now,
                    context: Some(serde_json::json!({"source": "second"})),
                }),
            }
        }
    }
}

struct FailingStateStore;

struct RestoreCountingStateStore {
    inner: Arc<InMemoryStateStore>,
    snapshot_loads: Arc<AtomicUsize>,
}

impl StateStore for FailingStateStore {
    fn put_state(&self, _state: StateData) -> Result<StateDataRef, StateStoreError> {
        Err(StateStoreError::MissingState)
    }

    fn get_state(&self, _data_ref: &StateDataRef) -> Result<StateData, StateStoreError> {
        Err(StateStoreError::MissingState)
    }

    fn commit_node(
        &self,
        _parent_ids: Vec<StateNodeId>,
        _data_ref: StateDataRef,
        _metadata: StateMetadata,
    ) -> Result<StateNodeId, StateStoreError> {
        Err(StateStoreError::MissingState)
    }

    fn get_node(&self, _node_id: &StateNodeId) -> Result<StateNode, StateStoreError> {
        Err(StateStoreError::MissingNode)
    }

    fn snapshot(
        &self,
        _node_id: &StateNodeId,
    ) -> Result<splendor_types::SnapshotId, StateStoreError> {
        Err(StateStoreError::MissingSnapshot)
    }

    fn load_snapshot(
        &self,
        _snapshot_id: &splendor_types::SnapshotId,
    ) -> Result<StateSnapshot, StateStoreError> {
        Err(StateStoreError::MissingSnapshot)
    }
}

impl StateStore for RestoreCountingStateStore {
    fn put_state(&self, state: StateData) -> Result<StateDataRef, StateStoreError> {
        self.inner.put_state(state)
    }

    fn get_state(&self, data_ref: &StateDataRef) -> Result<StateData, StateStoreError> {
        self.inner.get_state(data_ref)
    }

    fn commit_node(
        &self,
        parent_ids: Vec<StateNodeId>,
        data_ref: StateDataRef,
        metadata: StateMetadata,
    ) -> Result<StateNodeId, StateStoreError> {
        self.inner.commit_node(parent_ids, data_ref, metadata)
    }

    fn get_node(&self, node_id: &StateNodeId) -> Result<StateNode, StateStoreError> {
        self.inner.get_node(node_id)
    }

    fn snapshot(&self, node_id: &StateNodeId) -> Result<SnapshotId, StateStoreError> {
        self.inner.snapshot(node_id)
    }

    fn load_snapshot(&self, snapshot_id: &SnapshotId) -> Result<StateSnapshot, StateStoreError> {
        self.snapshot_loads.fetch_add(1, Ordering::SeqCst);
        self.inner.load_snapshot(snapshot_id)
    }
}

#[test]
fn state_handoff_import_trace_failure_restores_live_owner_state() {
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let agent = AgentContext::new(
        agent_id.clone(),
        tenant_id.clone(),
        crate::AgentRuntimeConfig::default(),
    );
    let work_order = signed_work_order_for(&agent, run_id.clone());
    let now = OffsetDateTime::now_utc();

    let mut source = StateGraph::new(
        Arc::new(InMemoryStateStore::default()),
        SnapshotPolicy::default(),
    );
    let mut source_metadata = StateMetadata::new(now, Some("source".to_string()));
    source_metadata.tenant_id = Some(tenant_id.clone());
    source_metadata.agent_id = Some(agent_id.clone());
    source_metadata.run_id = Some(run_id.clone());
    source
        .commit(
            StateData {
                bytes: vec![9],
                content_type: Some("application/octet-stream".to_string()),
            },
            source_metadata,
        )
        .expect("source commit");

    let receiver_state = StateData {
        bytes: vec![1],
        content_type: Some("application/octet-stream".to_string()),
    };
    let mut receiver = StateGraph::new(
        Arc::new(InMemoryStateStore::default()),
        SnapshotPolicy::default(),
    );
    let mut receiver_metadata = StateMetadata::new(now, Some("receiver".to_string()));
    receiver_metadata.tenant_id = Some(tenant_id.clone());
    receiver_metadata.agent_id = Some(agent_id.clone());
    receiver_metadata.run_id = Some(run_id.clone());
    let previous = receiver
        .commit(receiver_state.clone(), receiver_metadata)
        .expect("receiver commit");

    let handoff = source
        .export_current_handoff(StateHandoffExportRequest {
            handoff_id: "handoff_trace_failure".to_string(),
            authority: StateHandoffAuthority {
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                run_id: run_id.clone(),
                work_order_id: work_order.work_order.work_order_id.to_string(),
            },
            source_instance_id: None,
            receiver_instance_id: None,
            previous_state_node_id: Some(previous.node_id.to_string()),
            source_trace_id: Some(TraceId::new()),
            created_at: now,
        })
        .expect("handoff export");

    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(FailingStateHandoffImportedTraceSink),
        run_id: Some(run_id.clone()),
        ..KernelRuntimeConfig::default()
    });
    let mut engine = LoopEngine::with_runtime(
        agent,
        receiver,
        receiver_state.clone(),
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        runtime,
    );
    let mut import_metadata = StateMetadata::new(now, Some("import".to_string()));
    import_metadata.tenant_id = Some(tenant_id.clone());
    import_metadata.agent_id = Some(agent_id.clone());
    import_metadata.run_id = Some(run_id.clone());

    let error = engine
        .import_state_handoff(
            &handoff,
            &work_order,
            &state_handoff_keyring(),
            &StateHandoffScope {
                tenant_id,
                agent_id,
                run_id,
                receiver_instance_id: None,
            },
            now,
            import_metadata,
        )
        .expect_err("trace failure denies imported live state");

    assert!(matches!(
        error,
        LoopError::Trace(crate::TraceError::Store(TraceStoreError::Poisoned))
    ));
    assert_eq!(engine.state_graph.head(), Some(&previous.node_id));
    assert_eq!(engine.agent.state_head.as_ref(), Some(&previous.node_id));
    assert_eq!(engine.state, receiver_state);
}

#[test]
fn loop_engine_emits_ordered_trace_events() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingTraceSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });

    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let agent_id = splendor_types::AgentId::new();
    let tenant_id = splendor_types::TenantId::new();
    let agent = AgentContext::new(
        agent_id.clone(),
        tenant_id.clone(),
        crate::AgentRuntimeConfig::default(),
    );
    let gateway = Arc::new(StubGateway);
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(StaticPolicy),
        gateway,
        runtime,
    );
    engine.add_perceptor(StaticPerceptor);
    engine.set_constraint_engine(StaticConstraintEngine);

    let outcome = engine.tick(1).expect("tick");
    assert_eq!(outcome.tick_id, 1);
    assert_eq!(outcome.action_outcomes.len(), 1);

    let recorded = events.lock().expect("events lock");
    let trace_ids = recorded
        .iter()
        .map(|event| event.trace_event_id.to_string())
        .collect::<HashSet<_>>();
    assert_eq!(trace_ids.len(), recorded.len());
    for (sequence, event) in recorded.iter().enumerate() {
        assert_eq!(event.sequence, sequence as u64);
        assert_eq!(
            event.trace_event_id,
            splendor_types::TraceEventId::from_run_sequence(&event.run_id, event.sequence)
        );
        assert_eq!(event.identity.run_id, event.run_id);
        assert_eq!(event.identity.tenant_id.as_ref(), Some(&tenant_id));
        assert_eq!(event.identity.agent_id.as_ref(), Some(&agent_id));
        assert_eq!(
            event.identity.tick_id,
            Some(splendor_types::TickId::from(1))
        );
    }
    let kinds = recorded
        .iter()
        .map(|event| event_kind_label(&event.kind))
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            "LoopTickStarted",
            "PerceptsReceived",
            "StateLoaded",
            "PolicyInvoked",
            "PolicyCompleted",
            "CandidatesProposed",
            "ConstraintsEvaluated",
            "ActionVerificationStarted",
            "ActionVerificationCompleted",
            "ActionExecuted",
            "OutcomeRecorded",
            "StateCommitted",
            "LoopTickCompleted",
        ]
    );
    let state_event = recorded
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::StateCommitted { .. }))
        .expect("state committed");
    assert_eq!(
        state_event.identity.state_node_id.as_ref(),
        Some(&outcome.state_commit.node_id)
    );
    assert_eq!(
        outcome.state_commit.trace_event_id.as_ref(),
        Some(&state_event.trace_event_id)
    );
    if let TraceEventKind::StateCommitted { state_hash, .. } = &state_event.kind {
        assert_eq!(state_hash, outcome.state_commit.node_id.hash());
    }

    for event in recorded.iter().filter(|event| {
        matches!(
            event.kind,
            TraceEventKind::ActionVerificationStarted { .. }
                | TraceEventKind::ActionVerificationCompleted { .. }
                | TraceEventKind::ActionExecuted { .. }
                | TraceEventKind::ActionDenied { .. }
                | TraceEventKind::ActionFailed { .. }
        )
    }) {
        assert_eq!(
            event.identity.action_id.as_ref(),
            Some(&outcome.action_outcomes[0].action_id)
        );
    }
}

#[test]
fn loop_engine_overwrites_policy_state_metadata_identity() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingTraceSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });
    let runtime_run_id = runtime.run_id().clone();

    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store.clone(), SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let agent_id = splendor_types::AgentId::new();
    let tenant_id = splendor_types::TenantId::new();
    let agent = AgentContext::new(
        agent_id.clone(),
        tenant_id.clone(),
        crate::AgentRuntimeConfig::default(),
    );
    let forged_tenant_id = splendor_types::TenantId::new();
    let forged_agent_id = splendor_types::AgentId::new();
    let forged_run_id = RunId::new();
    let forged_trace_event_id = splendor_types::TraceEventId::new();

    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(ForgedStateMetadataPolicy {
            tenant_id: forged_tenant_id.clone(),
            agent_id: forged_agent_id.clone(),
            run_id: forged_run_id.clone(),
            trace_event_id: forged_trace_event_id.clone(),
        }),
        Arc::new(StubGateway),
        runtime,
    );

    let outcome = engine.tick(1).expect("tick");

    let recorded = events.lock().expect("events lock");
    let state_event = recorded
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::StateCommitted { .. }))
        .expect("state committed");
    assert_eq!(outcome.state_commit.tenant_id.as_ref(), Some(&tenant_id));
    assert_eq!(outcome.state_commit.agent_id.as_ref(), Some(&agent_id));
    assert_eq!(outcome.state_commit.run_id.as_ref(), Some(&runtime_run_id));
    assert_eq!(
        outcome.state_commit.trace_event_id.as_ref(),
        Some(&state_event.trace_event_id)
    );
    assert_ne!(
        outcome.state_commit.tenant_id.as_ref(),
        Some(&forged_tenant_id)
    );
    assert_ne!(
        outcome.state_commit.agent_id.as_ref(),
        Some(&forged_agent_id)
    );
    assert_ne!(outcome.state_commit.run_id.as_ref(), Some(&forged_run_id));
    assert_ne!(
        outcome.state_commit.trace_event_id.as_ref(),
        Some(&forged_trace_event_id)
    );

    let node = store
        .get_node(&outcome.state_commit.node_id)
        .expect("stored state node");
    assert_eq!(node.metadata.tenant_id.as_ref(), Some(&tenant_id));
    assert_eq!(node.metadata.agent_id.as_ref(), Some(&agent_id));
    assert_eq!(node.metadata.run_id.as_ref(), Some(&runtime_run_id));
    assert_eq!(
        node.metadata.trace_event_id.as_ref(),
        Some(&state_event.trace_event_id)
    );
    assert_eq!(
        node.metadata.label.as_deref(),
        Some("policy-supplied-label")
    );
}

#[test]
fn loop_engine_trace_failure_before_action_dispatch_stops_gateway_and_state_advance() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = FailingActionVerificationTraceSink {
        events: Arc::clone(&events),
        failed: Arc::new(Mutex::new(false)),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });

    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_bytes = vec![1];
    let initial_state = StateData {
        bytes: initial_bytes.clone(),
        content_type: None,
    };
    let agent_id = splendor_types::AgentId::new();
    let tenant_id = splendor_types::TenantId::new();
    let agent = AgentContext::new(
        agent_id.clone(),
        tenant_id.clone(),
        crate::AgentRuntimeConfig::default(),
    );
    let calls = Arc::new(Mutex::new(0));
    let gateway = Arc::new(CountingGateway {
        calls: Arc::clone(&calls),
    });
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(StaticPolicy),
        gateway,
        runtime,
    );
    engine.set_constraint_engine(StaticConstraintEngine);

    let error = engine.tick(1).expect_err("trace failure before dispatch");

    assert!(matches!(
        error,
        LoopError::Trace(crate::TraceError::Store(TraceStoreError::Poisoned))
    ));
    assert_eq!(*calls.lock().expect("calls lock"), 0);
    assert_eq!(engine.state.bytes, initial_bytes);
    assert_eq!(engine.state_graph.tick(), 0);
    assert!(engine.state_graph.head().is_none());
    assert!(engine.agent.state_head.is_none());

    let recorded = events.lock().expect("events lock");
    assert_eq!(engine.runtime.next_sequence(), recorded.len() as u64);
    assert!(recorded
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ConstraintsEvaluated { .. })));
    assert!(!recorded.iter().any(|event| matches!(
        event.kind,
        TraceEventKind::ActionVerificationStarted { .. }
            | TraceEventKind::ActionVerificationCompleted { .. }
            | TraceEventKind::ActionExecuted { .. }
            | TraceEventKind::StateCommitted { .. }
            | TraceEventKind::LoopTickCompleted { .. }
    )));
}

#[test]
fn loop_engine_rejects_invalid_escalation_policy_before_installing() {
    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let gateway = Arc::new(StubGateway);
    let mut engine = LoopEngine::new(agent, graph, initial_state, Box::new(StaticPolicy), gateway);
    let mut policy =
        splendor_types::EscalationPolicy::with_rules(vec![splendor_types::EscalationRule::new(
            splendor_types::EscalationTrigger::VerifierUncertainty,
            splendor_types::EscalationScope::Action,
            1,
            splendor_types::EscalationDecision::NeedsIntervention,
        )]);
    policy.schema_version = "future.escalation".to_string();

    let err = engine
        .set_escalation_policy(policy)
        .expect_err("invalid escalation policy must fail closed");
    assert!(matches!(
        err,
        LoopError::EscalationPolicy(
            splendor_types::EscalationPolicyError::UnsupportedSchemaVersion { .. }
        )
    ));

    let zero_threshold =
        splendor_types::EscalationPolicy::with_rules(vec![splendor_types::EscalationRule::new(
            splendor_types::EscalationTrigger::QuotaPressure,
            splendor_types::EscalationScope::Action,
            0,
            splendor_types::EscalationDecision::Deny,
        )]);
    let err = engine
        .set_escalation_policy(zero_threshold)
        .expect_err("zero threshold escalation policy must fail closed");
    assert!(matches!(
        err,
        LoopError::EscalationPolicy(splendor_types::EscalationPolicyError::ZeroThreshold {
            rule_index: 0
        })
    ));
}

#[test]
fn loop_engine_state_commit_failure_does_not_complete_tick() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingTraceSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });

    let graph = StateGraph::new(Arc::new(FailingStateStore), SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        runtime,
    );

    let error = engine.tick(1).expect_err("state commit failure");
    assert!(matches!(error, LoopError::StateGraph(_)));
    assert_eq!(engine.state_graph.tick(), 0);
    assert!(engine.agent.state_head.is_none());

    let recorded = events.lock().expect("events lock");
    assert!(recorded
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::LoopTickStarted { tick_id: 1 })));
    assert!(!recorded
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::StateCommitted { .. })));
    assert!(!recorded
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::LoopTickCompleted { .. })));
}

#[test]
fn loop_engine_denies_actions_when_policy_disallows() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingTraceSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });
    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let gateway = Arc::new(DenyGateway);
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(StaticPolicy),
        gateway,
        runtime,
    );

    let outcome = engine.tick(1).expect("tick");
    assert!(matches!(
        outcome.action_outcomes[0].status,
        ActionStatus::Denied
    ));

    let recorded = events.lock().expect("events lock");
    assert!(recorded
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ActionDenied { .. })));
}

#[test]
fn loop_engine_denies_when_constraints_fail_and_skips_gateway() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingTraceSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });

    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let calls = Arc::new(Mutex::new(0));
    let gateway = Arc::new(CountingGateway {
        calls: Arc::clone(&calls),
    });
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(StaticPolicy),
        gateway,
        runtime,
    );
    engine.set_constraint_engine(DenyConstraintEngine);

    let outcome = engine.tick(1).expect("tick");
    assert!(matches!(
        outcome.action_outcomes[0].status,
        ActionStatus::Denied
    ));
    assert_eq!(*calls.lock().expect("calls lock"), 0);

    let recorded = events.lock().expect("events lock");
    let denied = recorded
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::ActionDenied { .. }))
        .expect("denied");
    if let TraceEventKind::ActionDenied { result, .. } = &denied.kind {
        assert!(result.reasons.contains(&"constraints_denied".to_string()));
    }
}

#[test]
fn loop_engine_denies_child_action_outside_delegated_scope_and_skips_gateway() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingTraceSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });

    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let mut agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    agent.set_delegated_authority(DelegatedAuthority::empty());
    let calls = Arc::new(Mutex::new(0));
    let gateway = Arc::new(CountingGateway {
        calls: Arc::clone(&calls),
    });
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(StaticPolicy),
        gateway,
        runtime,
    );

    let outcome = engine.tick(1).expect("tick");
    assert!(matches!(
        outcome.action_outcomes[0].status,
        ActionStatus::Denied
    ));
    assert_eq!(*calls.lock().expect("calls lock"), 0);

    let recorded = events.lock().expect("events lock");
    let denied = recorded
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::ActionDenied { .. }))
        .expect("delegated scope denial");
    if let TraceEventKind::ActionDenied { result, .. } = &denied.kind {
        assert!(result
            .reasons
            .contains(&"delegated_runtime_authority_missing".to_string()));
    }
}

#[test]
fn loop_engine_denies_delegated_action_without_explicit_adapter_and_skips_gateway() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingTraceSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });

    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let mut agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    agent.set_delegated_authority(DelegatedAuthority {
        allowed_actions: vec!["noop".to_string()],
        allowed_adapters: vec!["stub".to_string()],
        allowed_permissions: Vec::new(),
    });
    let calls = Arc::new(Mutex::new(0));
    let gateway = Arc::new(CountingGateway {
        calls: Arc::clone(&calls),
    });
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(StaticPolicy),
        gateway,
        runtime,
    );

    let outcome = engine.tick(1).expect("tick");
    assert!(matches!(
        outcome.action_outcomes[0].status,
        ActionStatus::Denied
    ));
    assert_eq!(*calls.lock().expect("calls lock"), 0);

    let recorded = events.lock().expect("events lock");
    let denied = recorded
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::ActionDenied { .. }))
        .expect("delegated missing adapter denial");
    if let TraceEventKind::ActionDenied { result, .. } = &denied.kind {
        assert!(result
            .reasons
            .contains(&"delegated_runtime_authority_missing".to_string()));
    }
}

#[test]
fn loop_engine_legacy_delegated_projection_cannot_independently_allow_action() {
    let runtime = KernelRuntime::new(KernelRuntimeConfig::default());
    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let mut agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    agent.set_delegated_authority(DelegatedAuthority {
        allowed_actions: vec!["noop".to_string()],
        allowed_adapters: vec!["stub".to_string()],
        allowed_permissions: Vec::new(),
    });
    let calls = Arc::new(Mutex::new(0));
    let gateway = Arc::new(CountingGateway {
        calls: Arc::clone(&calls),
    });
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(StaticAdapterPolicy),
        gateway,
        runtime,
    );

    let outcome = engine.tick(1).expect("tick");
    assert!(matches!(
        outcome.action_outcomes[0].status,
        ActionStatus::Denied
    ));
    assert_eq!(*calls.lock().expect("calls lock"), 0);
}

#[test]
fn loop_engine_records_gateway_errors_as_failed() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingTraceSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });

    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let gateway = Arc::new(ErrorGateway);
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(StaticPolicy),
        gateway,
        runtime,
    );

    let outcome = engine.tick(1).expect("tick");
    assert!(matches!(
        outcome.action_outcomes[0].status,
        ActionStatus::Failed
    ));

    let recorded = events.lock().expect("events lock");
    assert!(!recorded
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ActionExecuted { .. })));
    let failed = recorded
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::ActionFailed { .. }))
        .expect("failed");
    if let TraceEventKind::ActionFailed { result, .. } = &failed.kind {
        assert!(result
            .reasons
            .iter()
            .any(|reason| reason.contains("adapter execution failed")));
    }
}

#[test]
fn loop_engine_records_outcome_feedback_and_reward() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingTraceSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });

    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let gateway = Arc::new(StubGateway);
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(MultiActionPolicy),
        gateway,
        runtime,
    );
    engine.set_outcome_evaluator(RecordingOutcomeEvaluator);

    engine.tick(1).expect("tick");

    let recorded = events.lock().expect("events lock");
    let outcome = recorded
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::OutcomeRecorded { .. }))
        .expect("outcome event");
    if let TraceEventKind::OutcomeRecorded {
        feedback, reward, ..
    } = &outcome.kind
    {
        let feedback = feedback.as_ref().expect("feedback");
        assert_eq!(feedback.kind, "first");
        let reward = reward.as_ref().expect("reward");
        assert_eq!(reward.value, 2.0);
        assert_eq!(reward.units.as_deref(), Some("pts"));
    }
}

#[test]
fn loop_engine_resumes_from_trace_store() {
    let state_store = Arc::new(InMemoryStateStore::default());
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let snapshot_policy = SnapshotPolicy {
        interval: Some(1),
        important_labels: Vec::new(),
    };
    let graph = StateGraph::new(state_store.clone(), snapshot_policy.clone());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let agent_id = splendor_types::AgentId::new();
    let tenant_id = splendor_types::TenantId::new();
    let agent = AgentContext::new(
        agent_id.clone(),
        tenant_id.clone(),
        crate::AgentRuntimeConfig::default(),
    );
    let gateway = Arc::new(StubGateway);
    let run_id = RunId::new();

    let mut engine = LoopEngine::with_trace_store(
        agent,
        graph,
        initial_state,
        Box::new(StaticPolicy),
        gateway,
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");
    engine.add_perceptor(StaticPerceptor);
    engine.tick(1).expect("tick");
    drop(engine);

    let graph = StateGraph::new(state_store, snapshot_policy);
    let agent = AgentContext::new(agent_id, tenant_id, crate::AgentRuntimeConfig::default());
    let gateway = Arc::new(StubGateway);
    let engine = LoopEngine::resume_from_trace_store(
        agent,
        graph,
        Box::new(StaticPolicy),
        gateway,
        trace_store,
        run_id.clone(),
    )
    .expect("resume");

    assert_eq!(engine.state.bytes, vec![2]);
    assert_eq!(engine.state_graph.tick(), 1);
    assert!(engine.agent.state_head.is_some());
    assert_eq!(engine.runtime.run_id(), &run_id);
}

#[derive(Clone, Copy, Debug)]
enum PersistedTraceCorruption {
    Payload,
    CompletionIntegrity,
    EventHash,
    PriorHash,
    Delete,
    Reorder,
    Insert,
}

fn corrupt_persisted_trace(
    path: &std::path::Path,
    run_id: &RunId,
    corruption: PersistedTraceCorruption,
) {
    let connection = rusqlite::Connection::open(path).expect("corruption connection");
    let run_id = run_id.to_string();
    match corruption {
        PersistedTraceCorruption::Payload => {
            let payload: Vec<u8> = connection
                .query_row(
                    "SELECT payload FROM trace_events WHERE run_id = ?1 AND sequence = 2",
                    rusqlite::params![run_id],
                    |row| row.get(0),
                )
                .expect("payload to corrupt");
            let mut event: TraceEvent =
                serde_json::from_slice(&payload).expect("persisted trace event");
            event.kind = TraceEventKind::PolicyCompleted {
                policy: "attacker-rewritten".to_string(),
            };
            let payload = serde_json::to_vec(&event).expect("corrupt payload bytes");
            connection
                .execute(
                    "UPDATE trace_events SET payload = ?1 WHERE run_id = ?2 AND sequence = 2",
                    rusqlite::params![payload, run_id],
                )
                .expect("mutate payload");
        }
        PersistedTraceCorruption::CompletionIntegrity => {
            let (sequence, payload): (i64, Vec<u8>) = connection
                .query_row(
                    "SELECT sequence, payload FROM trace_events WHERE run_id = ?1 ORDER BY sequence DESC LIMIT 1",
                    rusqlite::params![run_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("completion payload to corrupt");
            let mut event: TraceEvent =
                serde_json::from_slice(&payload).expect("persisted completion event");
            let TraceEventKind::LoopTickCompleted {
                integrity: Some(integrity),
                ..
            } = &mut event.kind
            else {
                panic!("latest event must be a completed tick");
            };
            integrity.event_hash = ContentHash::blake3(b"attacker-completion-integrity");
            let payload = serde_json::to_vec(&event).expect("corrupt completion payload bytes");
            connection
                .execute(
                    "UPDATE trace_events SET payload = ?1 WHERE run_id = ?2 AND sequence = ?3",
                    rusqlite::params![payload, run_id, sequence],
                )
                .expect("mutate completion integrity");
        }
        PersistedTraceCorruption::EventHash => {
            connection
                .execute(
                    "UPDATE trace_events SET event_hash_value = 'attacker-event-hash' WHERE run_id = ?1 AND sequence = 2",
                    rusqlite::params![run_id],
                )
                .expect("mutate event hash");
        }
        PersistedTraceCorruption::PriorHash => {
            connection
                .execute(
                    "UPDATE trace_events SET prev_hash_value = 'attacker-prior-hash' WHERE run_id = ?1 AND sequence = 2",
                    rusqlite::params![run_id],
                )
                .expect("mutate prior hash");
        }
        PersistedTraceCorruption::Delete => {
            connection
                .execute(
                    "DELETE FROM trace_events WHERE run_id = ?1 AND sequence = 2",
                    rusqlite::params![run_id],
                )
                .expect("delete trace event");
        }
        PersistedTraceCorruption::Reorder => {
            connection
                .execute(
                    "UPDATE trace_events SET sequence = -1 WHERE run_id = ?1 AND sequence = 2",
                    rusqlite::params![run_id],
                )
                .expect("move first event");
            connection
                .execute(
                    "UPDATE trace_events SET sequence = 2 WHERE run_id = ?1 AND sequence = 3",
                    rusqlite::params![run_id],
                )
                .expect("move second event");
            connection
                .execute(
                    "UPDATE trace_events SET sequence = 3 WHERE run_id = ?1 AND sequence = -1",
                    rusqlite::params![run_id],
                )
                .expect("finish reorder");
        }
        PersistedTraceCorruption::Insert => {
            connection
                .execute(
                    "INSERT INTO trace_events (run_id, sequence, payload, recorded_at, event_hash_algo, event_hash_value, prev_hash_algo, prev_hash_value) SELECT run_id, 999, payload, recorded_at, event_hash_algo, event_hash_value, prev_hash_algo, prev_hash_value FROM trace_events WHERE run_id = ?1 AND sequence = 2",
                    rusqlite::params![run_id],
                )
                .expect("insert trace event");
        }
    }
}

#[test]
fn resume_rejects_every_persisted_trace_corruption_before_state_restore() {
    for corruption in [
        PersistedTraceCorruption::Payload,
        PersistedTraceCorruption::CompletionIntegrity,
        PersistedTraceCorruption::EventHash,
        PersistedTraceCorruption::PriorHash,
        PersistedTraceCorruption::Delete,
        PersistedTraceCorruption::Reorder,
        PersistedTraceCorruption::Insert,
    ] {
        let directory = tempfile::tempdir().expect("trace directory");
        let path = directory.path().join("trace.sqlite3");
        let trace_store = Arc::new(SqliteTraceStore::open(&path).expect("trace store"));
        let state_store = Arc::new(InMemoryStateStore::default());
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let snapshot_policy = SnapshotPolicy {
            interval: Some(1),
            important_labels: Vec::new(),
        };
        let mut engine = LoopEngine::with_trace_store(
            AgentContext::new(
                agent_id.clone(),
                tenant_id.clone(),
                crate::AgentRuntimeConfig::default(),
            ),
            StateGraph::new(state_store.clone(), snapshot_policy.clone()),
            StateData {
                bytes: vec![0],
                content_type: None,
            },
            Box::new(StaticPolicy),
            Arc::new(StubGateway),
            trace_store,
            Some(run_id.clone()),
        )
        .expect("seed engine");
        engine.tick(1).expect("seed tick");
        drop(engine);

        corrupt_persisted_trace(&path, &run_id, corruption);
        let snapshot_loads = Arc::new(AtomicUsize::new(0));
        let policy_calls = Arc::new(AtomicUsize::new(0));
        let gateway_calls = Arc::new(Mutex::new(0));
        let result = LoopEngine::resume_from_trace_store(
            AgentContext::new(agent_id, tenant_id, crate::AgentRuntimeConfig::default()),
            StateGraph::new(
                Arc::new(RestoreCountingStateStore {
                    inner: state_store,
                    snapshot_loads: Arc::clone(&snapshot_loads),
                }),
                snapshot_policy,
            ),
            Box::new(NeverInvokedResumePolicy {
                calls: Arc::clone(&policy_calls),
            }),
            Arc::new(CountingGateway {
                calls: Arc::clone(&gateway_calls),
            }),
            Arc::new(SqliteTraceStore::open(&path).expect("resume trace store")),
            run_id,
        );

        assert!(
            matches!(
                result,
                Err(LoopError::TraceStore(
                    TraceStoreError::IntegrityRunIdentityMismatch { .. }
                        | TraceStoreError::IntegritySequenceMismatch { .. }
                        | TraceStoreError::IntegrityChainMismatch { .. }
                        | TraceStoreError::IntegrityHashMismatch { .. }
                ) | LoopError::TraceEnvelopeIntegrity { .. })
            ),
            "{corruption:?} did not return a structured integrity error"
        );
        assert_eq!(snapshot_loads.load(Ordering::SeqCst), 0, "{corruption:?}");
        assert_eq!(policy_calls.load(Ordering::SeqCst), 0, "{corruption:?}");
        assert_eq!(*gateway_calls.lock().expect("gateway calls"), 0);
    }
}

struct NeverInvokedResumePolicy {
    calls: Arc<AtomicUsize>,
}

impl Policy for NeverInvokedResumePolicy {
    fn name(&self) -> &str {
        "never-invoked-resume"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, LoopError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(PolicyDecision::new(
            Vec::new(),
            StateData {
                bytes: Vec::new(),
                content_type: None,
            },
            None,
        ))
    }
}

#[test]
fn shared_run_resume_restores_only_exact_tenant_agent_state_and_parent() {
    struct FixedStatePolicy {
        next_state: Vec<u8>,
        observed: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
    }

    impl Policy for FixedStatePolicy {
        fn name(&self) -> &str {
            "fixed-state"
        }

        fn decide(
            &self,
            state: &StateData,
            _percepts: &[Percept],
        ) -> Result<PolicyDecision, LoopError> {
            if let Some(observed) = self.observed.as_ref() {
                observed
                    .lock()
                    .expect("observed state")
                    .push(state.bytes.clone());
            }
            Ok(PolicyDecision::new(
                Vec::new(),
                StateData {
                    bytes: self.next_state.clone(),
                    content_type: None,
                },
                None,
            ))
        }
    }

    let trace_store = Arc::new(InMemoryTraceStore::default());
    let state_store = Arc::new(InMemoryStateStore::default());
    let run_id = RunId::new();
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let agent_a = AgentId::new();
    let agent_b = AgentId::new();
    let snapshot_policy = SnapshotPolicy {
        interval: Some(1),
        important_labels: Vec::new(),
    };
    let runtime = Arc::new(
        KernelRuntime::with_trace_store(trace_store.clone(), Some(run_id.clone()))
            .expect("shared runtime"),
    );

    let mut engine_a = LoopEngine::with_shared_trace_runtime_and_work_order(
        AgentContext::new(
            agent_a.clone(),
            tenant_a.clone(),
            crate::AgentRuntimeConfig::default(),
        ),
        StateGraph::new(state_store.clone(), snapshot_policy.clone()),
        StateData {
            bytes: b"A-initial".to_vec(),
            content_type: None,
        },
        Box::new(FixedStatePolicy {
            next_state: b"A-private-state".to_vec(),
            observed: None,
        }),
        Arc::new(splendor_gateway::UnimplementedGateway),
        runtime.clone(),
        RunTraceContext::new(Some(run_id.clone())),
    )
    .expect("agent A");
    let mut engine_b = LoopEngine::with_shared_trace_runtime_and_work_order(
        AgentContext::new(
            agent_b.clone(),
            tenant_b.clone(),
            crate::AgentRuntimeConfig::default(),
        ),
        StateGraph::new(state_store.clone(), snapshot_policy.clone()),
        StateData {
            bytes: b"B-initial".to_vec(),
            content_type: None,
        },
        Box::new(FixedStatePolicy {
            next_state: b"B-private-state".to_vec(),
            observed: None,
        }),
        Arc::new(splendor_gateway::UnimplementedGateway),
        runtime,
        RunTraceContext::new(Some(run_id.clone())),
    )
    .expect("agent B");

    let committed_a = engine_a.tick(1).expect("agent A tick").state_commit;
    let committed_b = engine_b.tick(2).expect("agent B tick").state_commit;
    drop((engine_a, engine_b));

    let observed_a = Arc::new(Mutex::new(Vec::new()));
    let mut resumed_a = LoopEngine::resume_from_trace_store(
        AgentContext::new(
            agent_a.clone(),
            tenant_a.clone(),
            crate::AgentRuntimeConfig::default(),
        ),
        StateGraph::new(state_store.clone(), snapshot_policy.clone()),
        Box::new(FixedStatePolicy {
            next_state: b"A-next-state".to_vec(),
            observed: Some(observed_a.clone()),
        }),
        Arc::new(splendor_gateway::UnimplementedGateway),
        trace_store.clone(),
        run_id.clone(),
    )
    .expect("resume agent A");
    assert_eq!(resumed_a.state.bytes, b"A-private-state");
    assert_eq!(resumed_a.state_graph.tick(), 1);

    let next_a = resumed_a.tick(3).expect("agent A resumed tick");
    assert_eq!(
        *observed_a.lock().expect("observed A"),
        vec![b"A-private-state".to_vec()]
    );
    let next_a_node = state_store
        .get_node(&next_a.state_commit.node_id)
        .expect("next A node");
    assert_eq!(next_a_node.parent_ids, vec![committed_a.node_id.clone()]);
    assert_ne!(next_a_node.parent_ids, vec![committed_b.node_id.clone()]);
    drop(resumed_a);

    let mut resumed_b = LoopEngine::resume_from_trace_store(
        AgentContext::new(agent_b, tenant_b, crate::AgentRuntimeConfig::default()),
        StateGraph::new(state_store.clone(), snapshot_policy),
        Box::new(FixedStatePolicy {
            next_state: b"B-next-state".to_vec(),
            observed: None,
        }),
        Arc::new(splendor_gateway::UnimplementedGateway),
        trace_store,
        run_id,
    )
    .expect("resume agent B");
    assert_eq!(resumed_b.state.bytes, b"B-private-state");
    assert_eq!(resumed_b.state_graph.tick(), 2);
    let next_b = resumed_b.tick(4).expect("agent B resumed tick");
    let next_b_node = state_store
        .get_node(&next_b.state_commit.node_id)
        .expect("next B node");
    assert_eq!(next_b_node.parent_ids, vec![committed_b.node_id]);
    assert_ne!(next_b_node.parent_ids, vec![next_a.state_commit.node_id]);
}

#[test]
fn resume_rejects_snapshot_with_missing_or_mismatched_store_identity_before_policy() {
    #[derive(Clone, Copy)]
    enum SnapshotMismatch {
        MissingTenantAgent,
        Tenant,
        Agent,
        Run,
        TraceEvent,
        StateHash,
    }

    struct NeverInvokedPolicy {
        calls: Arc<AtomicUsize>,
    }

    impl Policy for NeverInvokedPolicy {
        fn name(&self) -> &str {
            "never-invoked"
        }

        fn decide(
            &self,
            _state: &StateData,
            _percepts: &[Percept],
        ) -> Result<PolicyDecision, LoopError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(PolicyDecision::new(
                Vec::new(),
                StateData {
                    bytes: Vec::new(),
                    content_type: None,
                },
                None,
            ))
        }
    }

    for mismatch in [
        SnapshotMismatch::MissingTenantAgent,
        SnapshotMismatch::Tenant,
        SnapshotMismatch::Agent,
        SnapshotMismatch::Run,
        SnapshotMismatch::TraceEvent,
        SnapshotMismatch::StateHash,
    ] {
        let trace_store = Arc::new(InMemoryTraceStore::default());
        let state_store = Arc::new(InMemoryStateStore::default());
        let run_id = RunId::new();
        let target_tenant = TenantId::new();
        let target_agent = AgentId::new();
        let runtime = KernelRuntime::with_trace_store(trace_store.clone(), Some(run_id.clone()))
            .expect("runtime");
        assert!(runtime
            .admit_fresh_engine(&target_tenant, &target_agent)
            .expect("fresh admission"));
        let state_event_id = TraceEventId::from_run_sequence(&run_id, 2);
        let data_ref = state_store
            .put_state(StateData {
                bytes: b"other-private-state".to_vec(),
                content_type: None,
            })
            .expect("state data");
        let mut metadata = StateMetadata::new(OffsetDateTime::now_utc(), None);
        metadata.tenant_id = Some(target_tenant.clone());
        metadata.agent_id = Some(target_agent.clone());
        metadata.run_id = Some(run_id.clone());
        metadata.trace_event_id = Some(state_event_id.clone());
        match mismatch {
            SnapshotMismatch::MissingTenantAgent => {
                metadata.tenant_id = None;
                metadata.agent_id = None;
            }
            SnapshotMismatch::Tenant => metadata.tenant_id = Some(TenantId::new()),
            SnapshotMismatch::Agent => metadata.agent_id = Some(AgentId::new()),
            SnapshotMismatch::Run => metadata.run_id = Some(RunId::new()),
            SnapshotMismatch::TraceEvent => {
                metadata.trace_event_id = Some(TraceEventId::from_run_sequence(&run_id, 99));
            }
            SnapshotMismatch::StateHash => {}
        }
        let node_id = state_store
            .commit_node(Vec::new(), data_ref, metadata)
            .expect("state node");
        let snapshot_id = state_store.snapshot(&node_id).expect("snapshot");
        let tick_identity = runtime
            .trace_identity()
            .with_tenant_agent(target_tenant.clone(), target_agent.clone())
            .with_tick_id(TickId::from(1));
        runtime
            .record_event_with_identity(
                tick_identity.clone(),
                TraceEventKind::LoopTickStarted { tick_id: 1 },
            )
            .expect("tick start");
        runtime
            .record_event_with_identity(
                tick_identity.clone().with_state_node_id(node_id.clone()),
                TraceEventKind::StateCommitted {
                    state_hash: if matches!(mismatch, SnapshotMismatch::StateHash) {
                        ContentHash::blake3(b"mismatched-state-hash")
                    } else {
                        node_id.hash().clone()
                    },
                    snapshot_id: Some(snapshot_id),
                },
            )
            .expect("state event");
        runtime
            .record_event_with_identity(
                tick_identity,
                TraceEventKind::LoopTickCompleted {
                    tick_id: 1,
                    integrity: None,
                },
            )
            .expect("tick completion");
        let before = trace_store.read(&run_id.to_string()).expect("trace before");
        let policy_calls = Arc::new(AtomicUsize::new(0));

        let resumed = LoopEngine::resume_from_trace_store(
            AgentContext::new(
                target_agent,
                target_tenant,
                crate::AgentRuntimeConfig::default(),
            ),
            StateGraph::new(
                state_store,
                SnapshotPolicy {
                    interval: Some(1),
                    important_labels: Vec::new(),
                },
            ),
            Box::new(NeverInvokedPolicy {
                calls: policy_calls.clone(),
            }),
            Arc::new(splendor_gateway::UnimplementedGateway),
            trace_store.clone(),
            run_id.clone(),
        );

        assert!(matches!(
            resumed,
            Err(LoopError::Resume(reason)) if reason == "resume_state_identity_mismatch"
        ));
        assert_eq!(policy_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            trace_store.read(&run_id.to_string()).expect("trace after"),
            before
        );
    }
}

#[test]
fn concurrent_fresh_sqlite_constructors_have_one_atomic_owner_and_one_no_append_rejection() {
    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("trace.sqlite3");
    let stores = [
        Arc::new(SqliteTraceStore::open(&path).expect("left trace store")),
        Arc::new(SqliteTraceStore::open(&path).expect("right trace store")),
    ];
    let state_store = Arc::new(InMemoryStateStore::default());
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let start = Arc::new(Barrier::new(3));
    let threads = stores
        .into_iter()
        .map(|trace_store| {
            let state_store = state_store.clone();
            let run_id = run_id.clone();
            let tenant_id = tenant_id.clone();
            let agent_id = agent_id.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                LoopEngine::with_trace_store(
                    AgentContext::new(agent_id, tenant_id, crate::AgentRuntimeConfig::default()),
                    StateGraph::new(state_store, SnapshotPolicy::default()),
                    StateData {
                        bytes: vec![1],
                        content_type: None,
                    },
                    Box::new(StaticPolicy),
                    Arc::new(StubGateway),
                    trace_store,
                    Some(run_id),
                )
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().expect("constructor thread"))
        .collect::<Vec<_>>();

    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "one constructor must own the identity"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(LoopError::Resume(reason)) if reason == "run_already_exists"
                )
            })
            .count(),
        1,
        "one constructor must receive a stable admission conflict"
    );
    let records = SqliteTraceStore::open(&path)
        .expect("inspection trace store")
        .read(&run_id.to_string())
        .expect("single run start");
    assert_eq!(records.len(), 1);
    let event: TraceEvent =
        serde_json::from_value(records[0].payload.clone()).expect("run start event");
    assert!(matches!(event.kind, TraceEventKind::RunStarted));
}

#[test]
fn concurrent_shared_fresh_constructors_admit_one_engine_per_exact_identity() {
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let state_store = Arc::new(InMemoryStateStore::default());
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let runtime = Arc::new(
        KernelRuntime::with_trace_store(trace_store.clone(), Some(run_id.clone()))
            .expect("shared runtime"),
    );
    let start = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let trace_store = trace_store.clone();
        let state_store = state_store.clone();
        let run_id = run_id.clone();
        let tenant_id = tenant_id.clone();
        let agent_id = agent_id.clone();
        let runtime = runtime.clone();
        let start = start.clone();
        threads.push(std::thread::spawn(move || {
            start.wait();
            let result = LoopEngine::with_shared_trace_runtime_and_work_order(
                AgentContext::new(agent_id, tenant_id, crate::AgentRuntimeConfig::default()),
                StateGraph::new(state_store, SnapshotPolicy::default()),
                StateData {
                    bytes: vec![1],
                    content_type: None,
                },
                Box::new(StaticPolicy),
                Arc::new(StubGateway),
                runtime,
                RunTraceContext::new(Some(run_id)),
            );
            drop(trace_store);
            result
                .map(|_| "owner".to_string())
                .unwrap_or_else(|error| error.to_string())
        }));
    }
    start.wait();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().expect("constructor thread"))
        .collect::<Vec<_>>();

    assert_eq!(
        results
            .iter()
            .filter(|result| result.as_str() == "owner")
            .count(),
        1,
        "results={results:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.as_str() == "resume error: run_already_exists")
            .count(),
        1,
        "results={results:?}"
    );
    let records = trace_store
        .read(&run_id.to_string())
        .expect("single run start");
    assert_eq!(records.len(), 1);
}

#[test]
fn persisted_shared_constructor_requires_a_store_backed_ownership_boundary() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let run_id = RunId::new();
    let runtime = Arc::new(KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(CapturingTraceSink {
            events: Arc::clone(&events),
        }),
        run_id: Some(run_id.clone()),
        ..KernelRuntimeConfig::default()
    }));

    let result = LoopEngine::with_shared_trace_runtime_and_work_order(
        AgentContext::new(
            AgentId::new(),
            TenantId::new(),
            crate::AgentRuntimeConfig::default(),
        ),
        StateGraph::new(
            Arc::new(InMemoryStateStore::default()),
            SnapshotPolicy::default(),
        ),
        StateData {
            bytes: vec![1],
            content_type: None,
        },
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        runtime,
        RunTraceContext::new(Some(run_id)),
    );

    assert!(matches!(
        result,
        Err(LoopError::Trace(TraceError::Store(
            TraceStoreError::RuntimeIdentityOwnershipUnsupported
        )))
    ));
    assert!(events.lock().expect("events lock").is_empty());
}

#[test]
fn concurrent_resumed_sqlite_constructors_admit_one_exact_live_owner() {
    const RACE_COUNT: usize = 8;

    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("trace.sqlite3");
    let seed_trace_store = Arc::new(SqliteTraceStore::open(&path).expect("seed trace store"));
    let state_store = Arc::new(InMemoryStateStore::default());
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let snapshot_policy = SnapshotPolicy {
        interval: Some(1),
        important_labels: Vec::new(),
    };
    let mut seed = LoopEngine::with_trace_store(
        AgentContext::new(
            agent_id.clone(),
            tenant_id.clone(),
            crate::AgentRuntimeConfig::default(),
        ),
        StateGraph::new(state_store.clone(), snapshot_policy.clone()),
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        seed_trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("seed engine");
    seed.tick(1).expect("seed tick");
    drop(seed);
    let records_before = seed_trace_store
        .read(&run_id.to_string())
        .expect("seed records");

    for race in 0..RACE_COUNT {
        let start = Arc::new(Barrier::new(3));
        let stores = [
            Arc::new(SqliteTraceStore::open(&path).expect("left trace store")),
            Arc::new(SqliteTraceStore::open(&path).expect("right trace store")),
        ];
        let handles = stores
            .into_iter()
            .map(|trace_store| {
                let start = Arc::clone(&start);
                let state_store = Arc::clone(&state_store);
                let run_id = run_id.clone();
                let tenant_id = tenant_id.clone();
                let agent_id = agent_id.clone();
                let snapshot_policy = snapshot_policy.clone();
                std::thread::spawn(move || {
                    start.wait();
                    LoopEngine::resume_from_trace_store(
                        AgentContext::new(
                            agent_id,
                            tenant_id,
                            crate::AgentRuntimeConfig::default(),
                        ),
                        StateGraph::new(state_store, snapshot_policy),
                        Box::new(StaticPolicy),
                        Arc::new(StubGateway),
                        trace_store,
                        run_id,
                    )
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("resume thread"))
            .collect::<Vec<_>>();

        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "race {race} admitted multiple owners"
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(
                        result,
                        Err(LoopError::Trace(TraceError::Store(
                            TraceStoreError::RuntimeIdentityAlreadyOwned {
                                run_id: conflict_run,
                                tenant_id: conflict_tenant,
                                agent_id: conflict_agent,
                            }
                        ))) if conflict_run == &run_id.to_string()
                            && conflict_tenant == &tenant_id.to_string()
                            && conflict_agent == &agent_id.to_string()
                    )
                })
                .count(),
            1,
            "race {race} did not return one admission conflict"
        );
        assert_eq!(
            seed_trace_store
                .read(&run_id.to_string())
                .expect("records after race"),
            records_before,
            "race {race} appended a competing owner event"
        );
        drop(results);
    }
}

#[test]
fn resumed_scheduler_advances_past_an_incomplete_persisted_tick() {
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let state_store = Arc::new(InMemoryStateStore::default());
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let snapshot_policy = SnapshotPolicy {
        interval: Some(1),
        important_labels: Vec::new(),
    };
    let mut seed = LoopEngine::with_trace_store(
        AgentContext::new(
            agent_id.clone(),
            tenant_id.clone(),
            crate::AgentRuntimeConfig::default(),
        ),
        StateGraph::new(state_store.clone(), snapshot_policy.clone()),
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("seed engine");
    seed.tick(1).expect("completed seed tick");
    drop(seed);

    let partial_runtime =
        KernelRuntime::with_trace_store(trace_store.clone(), Some(run_id.clone()))
            .expect("partial tick runtime");
    partial_runtime
        .record_event_with_identity(
            partial_runtime
                .trace_identity()
                .with_tenant_agent(tenant_id.clone(), agent_id.clone())
                .with_tick_id(TickId::from(2)),
            TraceEventKind::LoopTickStarted { tick_id: 2 },
        )
        .expect("persist partial tick identity");
    drop(partial_runtime);

    let mut resumed = LoopEngine::resume_from_trace_store(
        AgentContext::new(
            agent_id,
            tenant_id.clone(),
            crate::AgentRuntimeConfig::default(),
        ),
        StateGraph::new(state_store, snapshot_policy),
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        trace_store,
        run_id,
    )
    .expect("resume from incomplete pre-effect tick");
    assert!(matches!(
        resumed.tick(2),
        Err(LoopError::TickIdentityConflict {
            attempted: 2,
            last_persisted: 2
        })
    ));
    let registry = crate::TenantRegistry::new();
    registry.insert(crate::TenantContext::new(
        tenant_id,
        crate::TenantPolicy::default(),
        crate::QuotaPolicy::default(),
    ));
    let mut scheduler =
        crate::Scheduler::with_registry(crate::SchedulerConfig::default(), registry);
    scheduler.add_agent(resumed);

    let step = scheduler.run_once().expect("next durable tick");
    assert_eq!(step.tick_id, 3);
    assert_eq!(step.outcome.tick_id, 3);
}

#[test]
fn resume_rejects_an_older_snapshot_for_a_newer_completed_tick() {
    struct IncrementingStatePolicy {
        calls: AtomicUsize,
    }

    impl Policy for IncrementingStatePolicy {
        fn name(&self) -> &str {
            "incrementing-state"
        }

        fn decide(
            &self,
            _state: &StateData,
            _percepts: &[Percept],
        ) -> Result<PolicyDecision, LoopError> {
            let next = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(PolicyDecision::new(
                Vec::new(),
                StateData {
                    bytes: vec![u8::try_from(next).expect("small test state")],
                    content_type: None,
                },
                None,
            ))
        }
    }

    let trace_store = Arc::new(InMemoryTraceStore::default());
    let state_store = Arc::new(InMemoryStateStore::default());
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let snapshot_policy = SnapshotPolicy {
        interval: Some(2),
        important_labels: Vec::new(),
    };
    let mut engine = LoopEngine::with_trace_store(
        AgentContext::new(
            agent_id.clone(),
            tenant_id.clone(),
            crate::AgentRuntimeConfig::default(),
        ),
        StateGraph::new(state_store.clone(), snapshot_policy.clone()),
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(IncrementingStatePolicy {
            calls: AtomicUsize::new(0),
        }),
        Arc::new(splendor_gateway::UnimplementedGateway),
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");
    engine.tick(1).expect("first tick without snapshot");
    engine.tick(2).expect("second tick with snapshot");
    engine.tick(3).expect("third tick without snapshot");
    drop(engine);
    let before = trace_store.read(&run_id.to_string()).expect("trace before");

    let resumed = LoopEngine::resume_from_trace_store(
        AgentContext::new(agent_id, tenant_id, crate::AgentRuntimeConfig::default()),
        StateGraph::new(state_store, snapshot_policy),
        Box::new(StaticPolicy),
        Arc::new(splendor_gateway::UnimplementedGateway),
        trace_store.clone(),
        run_id.clone(),
    );

    assert!(matches!(
        resumed,
        Err(LoopError::Resume(reason)) if reason == "resume_latest_completed_snapshot_unavailable"
    ));
    assert_eq!(
        trace_store.read(&run_id.to_string()).expect("trace after"),
        before
    );
}

#[test]
fn fresh_persisted_constructor_rejects_existing_run_without_appending_trace() {
    let state_store = Arc::new(InMemoryStateStore::default());
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let run_id = RunId::new();
    let first_graph = StateGraph::new(state_store.clone(), SnapshotPolicy::default());
    let first_agent = AgentContext::new(
        AgentId::new(),
        TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );

    let _first = LoopEngine::with_trace_store(
        first_agent,
        first_graph,
        StateData {
            bytes: vec![1],
            content_type: None,
        },
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("first fresh engine");
    let before = trace_store
        .read(&run_id.to_string())
        .expect("first run trace");
    assert_eq!(before.len(), 1);

    let second_graph = StateGraph::new(state_store, SnapshotPolicy::default());
    let second_agent = AgentContext::new(
        AgentId::new(),
        TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let result = LoopEngine::with_trace_store(
        second_agent,
        second_graph,
        StateData {
            bytes: vec![2],
            content_type: None,
        },
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        trace_store.clone(),
        Some(run_id.clone()),
    );

    assert!(matches!(
        result,
        Err(LoopError::Resume(message)) if message == "run_already_exists"
    ));
    assert_eq!(
        trace_store
            .read(&run_id.to_string())
            .expect("unchanged run trace"),
        before
    );
}

#[test]
fn shared_fresh_runtime_allows_initial_assembly_but_rejects_construction_after_tick_start() {
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let run_id = RunId::new();
    let runtime = Arc::new(
        KernelRuntime::with_trace_store(trace_store.clone(), Some(run_id.clone()))
            .expect("shared runtime"),
    );
    let tenant_id = TenantId::new();
    let gateway = Arc::new(StubGateway);

    let mut first = LoopEngine::with_shared_trace_runtime_and_work_order(
        AgentContext::new(
            AgentId::new(),
            tenant_id.clone(),
            crate::AgentRuntimeConfig::default(),
        ),
        StateGraph::new(
            Arc::new(InMemoryStateStore::default()),
            SnapshotPolicy::default(),
        ),
        StateData {
            bytes: vec![1],
            content_type: None,
        },
        Box::new(StaticPolicy),
        gateway.clone(),
        runtime.clone(),
        RunTraceContext::new(Some(run_id.clone())),
    )
    .expect("first agent assembly");
    let _second = LoopEngine::with_shared_trace_runtime_and_work_order(
        AgentContext::new(
            AgentId::new(),
            tenant_id.clone(),
            crate::AgentRuntimeConfig::default(),
        ),
        StateGraph::new(
            Arc::new(InMemoryStateStore::default()),
            SnapshotPolicy::default(),
        ),
        StateData {
            bytes: vec![2],
            content_type: None,
        },
        Box::new(StaticPolicy),
        gateway.clone(),
        runtime.clone(),
        RunTraceContext::new(Some(run_id.clone())),
    )
    .expect("second agent initial assembly");

    first.tick(1).expect("first tick");
    let before = trace_store.read(&run_id.to_string()).expect("tick trace");
    let third = LoopEngine::with_shared_trace_runtime_and_work_order(
        AgentContext::new(
            AgentId::new(),
            tenant_id,
            crate::AgentRuntimeConfig::default(),
        ),
        StateGraph::new(
            Arc::new(InMemoryStateStore::default()),
            SnapshotPolicy::default(),
        ),
        StateData {
            bytes: vec![3],
            content_type: None,
        },
        Box::new(StaticPolicy),
        gateway,
        runtime,
        RunTraceContext::new(Some(run_id.clone())),
    );

    assert!(matches!(
        third,
        Err(LoopError::Resume(message)) if message == "run_already_exists"
    ));
    assert_eq!(
        trace_store
            .read(&run_id.to_string())
            .expect("unchanged trace"),
        before
    );
}

#[test]
fn shared_trace_runtime_resume_rejects_mismatched_run() {
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let runtime_run_id = RunId::new();
    let runtime = Arc::new(
        KernelRuntime::with_trace_store(trace_store.clone(), Some(runtime_run_id))
            .expect("runtime"),
    );
    let requested_run_id = RunId::new();
    let graph = StateGraph::new(
        Arc::new(InMemoryStateStore::default()),
        SnapshotPolicy::default(),
    );
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );

    let result = LoopEngine::resume_from_shared_trace_runtime_and_work_order(
        agent,
        graph,
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        trace_store,
        runtime,
        requested_run_id,
        None,
    );

    assert!(matches!(
        result,
        Err(LoopError::Resume(message))
            if message == "shared trace runtime run_id does not match resumed run"
    ));
}

#[test]
fn action_candidate_builder_methods() {
    let action = Action {
        name: "build".to_string(),
        params: serde_json::json!({"ok": true}),
        side_effect_class: splendor_types::SideEffectClass::ReadOnly,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: vec!["ready".to_string()],
        postconditions: Vec::new(),
    };
    let usage = QuotaUsage {
        actions: 2,
        ..QuotaUsage::default()
    };
    let run_id = RunId::new();
    let evidence = ApprovalEvidence::new(
        ApprovalId::new(),
        TenantId::new(),
        splendor_types::AgentId::new(),
        run_id,
        ApprovalDecision::Granted,
        OffsetDateTime::now_utc() + time::Duration::minutes(5),
    )
    .with_action_name("build")
    .with_adapter("adapter");
    let candidate = ActionCandidate::new(action)
        .with_adapter("adapter".to_string())
        .with_usage(usage)
        .with_satisfied_preconditions(vec!["ready".to_string()])
        .with_approval_evidence(evidence.clone());
    assert_eq!(candidate.adapter.as_deref(), Some("adapter"));
    assert_eq!(candidate.usage.actions, 2);
    assert_eq!(candidate.satisfied_preconditions, vec!["ready".to_string()]);
    assert_eq!(candidate.approval_evidence.as_ref(), Some(&evidence));
}

#[test]
fn loop_engine_rejects_every_policy_supplied_raw_approval_evidence_before_action_path() {
    for (decision, expired, revoked) in [
        (ApprovalDecision::Granted, false, false),
        (ApprovalDecision::Denied, false, false),
        (ApprovalDecision::Granted, true, false),
        (ApprovalDecision::Granted, false, true),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let runtime = KernelRuntime::new(KernelRuntimeConfig {
            trace_sink: Arc::new(CapturingTraceSink {
                events: Arc::clone(&events),
            }),
            ..KernelRuntimeConfig::default()
        });
        let initial_state = StateData {
            bytes: vec![1],
            content_type: None,
        };
        let agent = AgentContext::new(
            AgentId::new(),
            TenantId::new(),
            crate::AgentRuntimeConfig::default(),
        );
        let expires_at = if expired {
            OffsetDateTime::now_utc() - time::Duration::seconds(1)
        } else {
            OffsetDateTime::now_utc() + time::Duration::minutes(5)
        };
        let mut evidence = ApprovalEvidence::new(
            ApprovalId::new(),
            agent.tenant_id.clone(),
            agent.agent_id.clone(),
            runtime.run_id().clone(),
            decision.clone(),
            expires_at,
        );
        evidence.revoked = revoked;
        let calls = Arc::new(Mutex::new(0));
        let gateway = Arc::new(CountingGateway {
            calls: Arc::clone(&calls),
        });
        let graph = StateGraph::new(
            Arc::new(InMemoryStateStore::default()),
            SnapshotPolicy::default(),
        );
        let mut engine = LoopEngine::with_runtime(
            agent,
            graph,
            initial_state.clone(),
            Box::new(RawApprovalEvidencePolicy { evidence }),
            gateway,
            runtime,
        );

        let error = engine.tick(1).expect_err("raw policy evidence is rejected");
        assert!(matches!(
            error,
            LoopError::Policy(ref reason) if reason == "policy_raw_approval_evidence_forbidden"
        ));
        assert_eq!(*calls.lock().expect("calls lock"), 0);
        assert_eq!(engine.state, initial_state);
        assert_eq!(engine.state_graph.tick(), 0);
        assert!(engine.state_graph.head().is_none());
        assert!(engine.agent.state_head.is_none());
        let recorded = events.lock().expect("events lock");
        assert!(
            recorded.iter().all(|event| !matches!(
                event.kind,
                TraceEventKind::ActionVerificationStarted { .. }
                    | TraceEventKind::ActionVerificationCompleted { .. }
                    | TraceEventKind::ActionExecuted { .. }
                    | TraceEventKind::ActionDenied { .. }
                    | TraceEventKind::ActionNeedsApproval { .. }
                    | TraceEventKind::ApprovalRequested { .. }
                    | TraceEventKind::ApprovalGranted { .. }
                    | TraceEventKind::ApprovalDenied { .. }
                    | TraceEventKind::ApprovalExpired { .. }
                    | TraceEventKind::ApprovalRevoked { .. }
                    | TraceEventKind::StateCommitted { .. }
            )),
            "decision={decision:?} expired={expired} revoked={revoked}"
        );
    }
}

#[test]
fn approval_artifact_and_trace_kind_cover_lifecycle_variants() {
    let run_id = RunId::new();
    let approval = ApprovalTraceContext {
        approval_id: ApprovalId::new(),
        tenant_id: TenantId::new(),
        agent_id: splendor_types::AgentId::new(),
        run_id: run_id.clone(),
        action_id: Some(ActionId::new()),
        action_name: "artifact.publish".to_string(),
        adapter: Some("artifact-store".to_string()),
        decision: Some(ApprovalDecision::Granted),
        reason: Some("operator decision".to_string()),
        policy_id: Some("publish_policy".to_string()),
        risk_level: Some("external".to_string()),
        issued_at: Some(OffsetDateTime::now_utc()),
        expires_at: Some(OffsetDateTime::now_utc() + time::Duration::minutes(10)),
        revoked: false,
    };

    let direct = VerificationResult {
        allowed: false,
        reasons: vec!["approval_required".to_string()],
        artifacts: serde_json::json!({
            "approval_status": "required",
            "approval_context": approval,
        }),
    };
    let (status, parsed) = approval_artifact(&direct).expect("direct approval artifact");
    assert_eq!(status, "required");
    assert_eq!(parsed.action_name, "artifact.publish");

    let nested = VerificationResult {
        allowed: true,
        reasons: Vec::new(),
        artifacts: serde_json::json!({
            "approval": {
                "approval_status": "granted",
                "approval": parsed,
            }
        }),
    };
    let (status, approval) = approval_artifact(&nested).expect("nested approval artifact");
    assert_eq!(status, "granted");

    for (status, expected) in [
        ("required", "requested"),
        ("granted", "granted"),
        ("expired", "expired"),
        ("revoked", "revoked"),
        ("intervention_required", "policy_expired"),
        ("policy_schema_unsupported", "policy_schema_unsupported"),
        ("schema_unsupported", "evidence_schema_unsupported"),
        ("denied", "denied"),
    ] {
        let kind = approval_trace_kind(status, approval.clone());
        match (expected, kind) {
            ("requested", TraceEventKind::ApprovalRequested { .. }) => {}
            ("granted", TraceEventKind::ApprovalGranted { .. }) => {}
            ("expired", TraceEventKind::ApprovalExpired { reason, .. }) => {
                assert_eq!(reason, "approval_expired")
            }
            ("revoked", TraceEventKind::ApprovalRevoked { reason, .. }) => {
                assert_eq!(reason, "approval_revoked")
            }
            ("policy_expired", TraceEventKind::ApprovalDenied { reason, .. }) => {
                assert_eq!(reason, "approval_policy_expired")
            }
            ("policy_schema_unsupported", TraceEventKind::ApprovalDenied { reason, .. }) => {
                assert_eq!(reason, "approval_policy_schema_unsupported")
            }
            ("evidence_schema_unsupported", TraceEventKind::ApprovalDenied { reason, .. }) => {
                assert_eq!(reason, "approval_evidence_schema_unsupported")
            }
            ("denied", TraceEventKind::ApprovalDenied { reason, .. }) => {
                assert_eq!(reason, "approval_denied")
            }
            (expected, other) => panic!("expected {expected}, got {other:?}"),
        }
    }

    assert!(approval_artifact(&VerificationResult::allow()).is_none());
}

#[test]
fn loop_engine_new_sets_head_from_graph() {
    let store = Arc::new(InMemoryStateStore::default());
    let mut graph = StateGraph::new(store, SnapshotPolicy::default());
    let commit = graph
        .commit(
            StateData {
                bytes: vec![1],
                content_type: None,
            },
            splendor_store::StateMetadata {
                created_at: OffsetDateTime::now_utc(),
                label: None,
                tenant_id: None,
                agent_id: None,
                run_id: None,
                trace_event_id: None,
            },
        )
        .expect("commit");
    let head = commit.node_id.clone();

    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let engine = LoopEngine::new(
        agent,
        graph,
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
    );

    assert_eq!(engine.agent.state_head.as_ref(), Some(&head));
}

#[test]
fn loop_engine_records_validated_work_order_metadata() {
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let run_id = RunId::new();
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let work_order = work_order_for(&agent, run_id.clone());
    let context = RunTraceContext::new(Some(run_id.clone())).with_work_order(work_order.clone());

    let engine = LoopEngine::with_trace_store_and_work_order(
        agent,
        graph,
        StateData {
            bytes: Vec::new(),
            content_type: None,
        },
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        trace_store.clone(),
        context,
    )
    .expect("engine");

    assert_eq!(
        engine.agent.config.metadata.get("work_order_id"),
        Some(&"wo_loop".to_string())
    );
    let records = trace_store.read(&run_id.to_string()).expect("records");
    assert_eq!(records.len(), 2);
    let accepted: TraceEvent = serde_json::from_value(records[1].payload.clone()).unwrap();
    match accepted.kind {
        TraceEventKind::WorkOrderAccepted {
            work_order_id,
            tenant_id,
            agent_id,
            run_id: accepted_run,
        } => {
            assert_eq!(work_order_id.as_str(), "wo_loop");
            assert_eq!(tenant_id, work_order.tenant_id);
            assert_eq!(agent_id, work_order.agent_id);
            assert_eq!(accepted_run, Some(run_id));
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn loop_engine_records_policy_bundle_metadata() {
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let run_id = RunId::new();
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let policy_bundle = PolicyBundleTraceContext::from(&policy_bundle_for(
        &agent,
        OffsetDateTime::now_utc() + time::Duration::hours(1),
        true,
    ));
    let context =
        RunTraceContext::new(Some(run_id.clone())).with_policy_bundle(policy_bundle.clone());

    let engine = LoopEngine::with_trace_store_and_work_order(
        agent,
        graph,
        StateData {
            bytes: Vec::new(),
            content_type: None,
        },
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        trace_store.clone(),
        context,
    )
    .expect("engine");

    assert_eq!(
        engine.agent.config.metadata.get("policy_bundle_id"),
        Some(&"pol_loop".to_string())
    );
    assert_eq!(
        engine.agent.config.metadata.get("policy_bundle_version"),
        Some(&"v1".to_string())
    );
    let records = trace_store.read(&run_id.to_string()).expect("records");
    assert_eq!(records.len(), 2);
    let accepted: TraceEvent = serde_json::from_value(records[1].payload.clone()).unwrap();
    match accepted.kind {
        TraceEventKind::PolicyBundleAccepted { bundle } => {
            assert_eq!(bundle.policy_bundle_id, policy_bundle.policy_bundle_id);
            assert_eq!(bundle.version, policy_bundle.version);
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn loop_engine_rejects_policy_before_policy_invoked_when_bundle_expired() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingTraceSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });
    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let expires_at = OffsetDateTime::now_utc() - time::Duration::minutes(1);
    let bundle = policy_bundle_for(&agent, expires_at, false);
    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(
        bundle.clone(),
        "loop-policy-key",
        b"loop-policy-secret",
    )
    .expect("signed loop policy");
    let mut keyring = PolicyBundleKeyring::new();
    keyring
        .insert_shared_secret("loop-policy-key", b"loop-policy-secret")
        .expect("loop policy key");
    let validated = validate_policy_bundle(
        &envelope,
        &PolicyBundleValidationContext {
            tenant_id: bundle.tenant_id.clone(),
            agent_id: bundle.agent_id.clone(),
            now: expires_at - time::Duration::minutes(1),
        },
        &keyring,
    )
    .expect("policy was valid before expiry");
    let cache = crate::PolicyCache::new(
        crate::PolicyCacheConfig {
            enforcement_required: true,
        },
        crate::PolicyCacheOwner {
            tenant_id: agent.tenant_id.clone(),
            agent_id: agent.agent_id.clone(),
        },
    );
    cache
        .install_validated_traced(validated, false, &LoopPolicyTraceRecorder)
        .expect("trusted loop policy installs");
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(StaticPolicy),
        Arc::new(StubGateway),
        runtime,
    );
    engine.set_policy_runtime_authority(Arc::new(cache));

    let error = engine
        .tick(1)
        .expect_err("expired policy denies invocation");
    assert!(matches!(error, LoopError::Policy(message) if message == "policy_expired"));

    let recorded = events.lock().expect("events lock");
    assert!(recorded
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::PolicyExpired { .. })));
    assert!(!recorded
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::PolicyInvoked { .. })));
}

#[test]
fn loop_engine_records_action_scoped_policy_expired_from_gateway_denial() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingTraceSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    });
    let store = Arc::new(InMemoryStateStore::default());
    let graph = StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        splendor_types::TenantId::new(),
        crate::AgentRuntimeConfig::default(),
    );
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(StaticPolicy),
        Arc::new(ExpiredPolicyGateway),
        runtime,
    );

    let outcome = engine.tick(1).expect("tick records denied action");
    let denied_action_id = outcome.action_outcomes[0].action_id.clone();

    let recorded = events.lock().expect("events lock");
    let policy_expired = recorded
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::PolicyExpired { .. }))
        .expect("action-scoped policy expired trace");
    assert_eq!(
        policy_expired.identity.action_id.as_ref(),
        Some(&denied_action_id)
    );
    match &policy_expired.kind {
        TraceEventKind::PolicyExpired {
            policy_bundle_id,
            version,
            action,
        } => {
            assert_eq!(policy_bundle_id.as_str(), "policy_unit_expired");
            assert_eq!(version, "unit.v1");
            assert_eq!(action.as_deref(), Some("noop"));
        }
        other => panic!("unexpected event: {other:?}"),
    }
    assert!(recorded.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::ActionDenied { result, .. }
            if event.identity.action_id.as_ref() == Some(&denied_action_id)
                && result.reasons.iter().any(|reason| reason == "policy_expired")
    )));
}

fn event_kind_label(kind: &TraceEventKind) -> &'static str {
    match kind {
        TraceEventKind::RunStarted => "RunStarted",
        TraceEventKind::WorkOrderAccepted { .. } => "WorkOrderAccepted",
        TraceEventKind::WorkOrderRejected { .. } => "WorkOrderRejected",
        TraceEventKind::PolicyBundleAccepted { .. } => "PolicyBundleAccepted",
        TraceEventKind::PolicyBundleRejected { .. } => "PolicyBundleRejected",
        TraceEventKind::PolicySyncFailed { .. } => "PolicySyncFailed",
        TraceEventKind::OfflineTraceIntervalStarted { .. } => "OfflineTraceIntervalStarted",
        TraceEventKind::OfflineTraceIntervalEnded { .. } => "OfflineTraceIntervalEnded",
        TraceEventKind::TraceSyncStarted { .. } => "TraceSyncStarted",
        TraceEventKind::TraceSyncCompleted { .. } => "TraceSyncCompleted",
        TraceEventKind::TraceSyncFailed { .. } => "TraceSyncFailed",
        TraceEventKind::PolicyConnectivityChanged { .. } => "PolicyConnectivityChanged",
        TraceEventKind::PolicyExpired { .. } => "PolicyExpired",
        TraceEventKind::PolicyRevoked { .. } => "PolicyRevoked",
        TraceEventKind::RunPaused { .. } => "RunPaused",
        TraceEventKind::RunResumed { .. } => "RunResumed",
        TraceEventKind::RunStopped { .. } => "RunStopped",
        TraceEventKind::PerceptsAppended { .. } => "PerceptsAppended",
        TraceEventKind::DaemonAudit { .. } => "DaemonAudit",
        TraceEventKind::CircuitBreakerTripped { .. } => "CircuitBreakerTripped",
        TraceEventKind::CircuitBreakerCleared { .. } => "CircuitBreakerCleared",
        TraceEventKind::LoopTickStarted { .. } => "LoopTickStarted",
        TraceEventKind::PerceptsReceived { .. } => "PerceptsReceived",
        TraceEventKind::StateLoaded { .. } => "StateLoaded",
        TraceEventKind::PolicyInvoked { .. } => "PolicyInvoked",
        TraceEventKind::PolicyCompleted { .. } => "PolicyCompleted",
        TraceEventKind::CandidatesProposed { .. } => "CandidatesProposed",
        TraceEventKind::ConstraintsEvaluated { .. } => "ConstraintsEvaluated",
        TraceEventKind::ActionVerificationStarted { .. } => "ActionVerificationStarted",
        TraceEventKind::ActionVerificationCompleted { .. } => "ActionVerificationCompleted",
        TraceEventKind::ActionNeedsApproval { .. } => "ActionNeedsApproval",
        TraceEventKind::ActionExecuted { .. } => "ActionExecuted",
        TraceEventKind::ActionDenied { .. } => "ActionDenied",
        TraceEventKind::ActionFailed { .. } => "ActionFailed",
        TraceEventKind::ApprovalRequested { .. } => "ApprovalRequested",
        TraceEventKind::ApprovalGranted { .. } => "ApprovalGranted",
        TraceEventKind::ApprovalDenied { .. } => "ApprovalDenied",
        TraceEventKind::ApprovalExpired { .. } => "ApprovalExpired",
        TraceEventKind::ApprovalRevoked { .. } => "ApprovalRevoked",
        TraceEventKind::ActionNeedsIntervention { .. } => "ActionNeedsIntervention",
        TraceEventKind::EscalationTriggered { .. } => "EscalationTriggered",
        TraceEventKind::OutcomeRecorded { .. } => "OutcomeRecorded",
        TraceEventKind::StateCommitted { .. } => "StateCommitted",
        TraceEventKind::StateHandoffExported { .. } => "StateHandoffExported",
        TraceEventKind::StateHandoffImported { .. } => "StateHandoffImported",
        TraceEventKind::StateHandoffImportFailed { .. } => "StateHandoffImportFailed",
        TraceEventKind::ReadOnlyStateReferenced { .. } => "ReadOnlyStateReferenced",
        TraceEventKind::MessageQueued { .. } => "MessageQueued",
        TraceEventKind::MessageDelivered { .. } => "MessageDelivered",
        TraceEventKind::MessageRejected { .. } => "MessageRejected",
        TraceEventKind::MessageExpired { .. } => "MessageExpired",
        TraceEventKind::MessageConsumed { .. } => "MessageConsumed",
        TraceEventKind::RemoteMessageSent { .. } => "RemoteMessageSent",
        TraceEventKind::RemoteMessageAccepted { .. } => "RemoteMessageAccepted",
        TraceEventKind::RemoteMessageRejected { .. } => "RemoteMessageRejected",
        TraceEventKind::RemoteMessageDelivered { .. } => "RemoteMessageDelivered",
        TraceEventKind::RemoteMessageTimedOut { .. } => "RemoteMessageTimedOut",
        TraceEventKind::RemoteMessageDuplicate { .. } => "RemoteMessageDuplicate",
        TraceEventKind::RemoteMessageTransportFailed { .. } => "RemoteMessageTransportFailed",
        TraceEventKind::DelegationRequested { .. } => "DelegationRequested",
        TraceEventKind::DelegationRejected { .. } => "DelegationRejected",
        TraceEventKind::ParentRunCancelled { .. } => "ParentRunCancelled",
        TraceEventKind::ChildRunStarted { .. } => "ChildRunStarted",
        TraceEventKind::ChildRunCompleted { .. } => "ChildRunCompleted",
        TraceEventKind::ChildRunFailed { .. } => "ChildRunFailed",
        TraceEventKind::ChildRunLinked { .. } => "ChildRunLinked",
        TraceEventKind::GovernanceApprovalRequested { .. } => "GovernanceApprovalRequested",
        TraceEventKind::GovernanceApprovalGranted { .. } => "GovernanceApprovalGranted",
        TraceEventKind::GovernanceApprovalDenied { .. } => "GovernanceApprovalDenied",
        TraceEventKind::GovernanceApprovalExpired { .. } => "GovernanceApprovalExpired",
        TraceEventKind::GovernanceApprovalRevoked { .. } => "GovernanceApprovalRevoked",
        TraceEventKind::EscalationOpened { .. } => "EscalationOpened",
        TraceEventKind::EscalationResolved { .. } => "EscalationResolved",
        TraceEventKind::EscalationExpired { .. } => "EscalationExpired",
        TraceEventKind::EscalationRevoked { .. } => "EscalationRevoked",
        TraceEventKind::InterventionRequested { .. } => "InterventionRequested",
        TraceEventKind::InterventionResolved { .. } => "InterventionResolved",
        TraceEventKind::InterventionCancelled { .. } => "InterventionCancelled",
        TraceEventKind::InterventionExpired { .. } => "InterventionExpired",
        TraceEventKind::InterventionRevoked { .. } => "InterventionRevoked",
        TraceEventKind::GovernanceCircuitBreakerTripped { .. } => "GovernanceCircuitBreakerTripped",
        TraceEventKind::GovernanceCircuitBreakerCleared { .. } => "GovernanceCircuitBreakerCleared",
        TraceEventKind::GovernanceCircuitBreakerExpired { .. } => "GovernanceCircuitBreakerExpired",
        TraceEventKind::GovernanceCircuitBreakerRevoked { .. } => "GovernanceCircuitBreakerRevoked",
        TraceEventKind::KillSwitchActivated { .. } => "KillSwitchActivated",
        TraceEventKind::KillSwitchCleared { .. } => "KillSwitchCleared",
        TraceEventKind::KillSwitchExpired { .. } => "KillSwitchExpired",
        TraceEventKind::KillSwitchRevoked { .. } => "KillSwitchRevoked",
        TraceEventKind::GovernanceTransitionRejected { .. } => "GovernanceTransitionRejected",
        TraceEventKind::LoopTickCompleted { .. } => "LoopTickCompleted",
    }
}
