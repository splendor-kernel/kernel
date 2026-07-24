use splendor_gateway::{
    raw_credential_denied_action, ActionAdapter, ActionOutcome, ActionStatus, AdapterError,
    AdapterResult, VerifiedActionGateway, RAW_CREDENTIAL_INPUT_DENIED,
};
use splendor_kernel::{
    ActionCandidate, AgentContext, AgentRuntimeConfig, ConstraintEngine, ConstraintEvaluation,
    LoopEngine, OutcomeEvaluator, OutcomeSignal, Perceptor, Policy, PolicyDecision, QuotaPolicy,
    RunId, SideEffectClass, SnapshotPolicy, StateGraph, TenantContext, TenantPolicy,
    TenantRegistry, TraceEvent, TraceEventKind,
};
use splendor_store::{InMemoryStateStore, InMemoryTraceStore, StateData, StateStore, TraceStore};
use splendor_types::{Action, Feedback, Percept, PerceptProvenance, VerificationResult};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

struct StaticPerceptor;

impl Perceptor for StaticPerceptor {
    fn collect(&self, _agent: &AgentContext) -> Result<Vec<Percept>, splendor_kernel::LoopError> {
        Ok(vec![Percept {
            schema: "sensor".to_string(),
            payload: serde_json::json!({"value": 7}),
            provenance: PerceptProvenance {
                source: "integration".to_string(),
                detail: None,
            },
            timestamp: OffsetDateTime::now_utc(),
        }])
    }
}

struct StaticPolicy;

impl Policy for StaticPolicy {
    fn name(&self) -> &str {
        "integration-policy"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, splendor_kernel::LoopError> {
        let action = Action {
            name: "noop".to_string(),
            params: serde_json::json!({"ok": true}),
            side_effect_class: SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        };
        let candidate = ActionCandidate::new(action).with_adapter("stub");
        let next_state = StateData {
            bytes: vec![9],
            content_type: Some("application/octet-stream".to_string()),
        };
        Ok(PolicyDecision::new(
            vec![candidate],
            next_state,
            Some("snapshot".to_string()),
        ))
    }
}

#[derive(Default)]
struct StubAdapter;

impl ActionAdapter for StubAdapter {
    fn execute(
        &self,
        _action: &splendor_gateway::ActionRequest,
    ) -> Result<AdapterResult, AdapterError> {
        Ok(AdapterResult {
            output: serde_json::json!({"ok": true}),
            satisfied_postconditions: Vec::new(),
        })
    }
}

struct MixedCredentialPolicy;

impl Policy for MixedCredentialPolicy {
    fn name(&self) -> &str {
        "mixed-credential-policy"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, splendor_kernel::LoopError> {
        let denied = ActionCandidate::new(Action {
            name: "unsafe-input".to_string(),
            params: serde_json::json!({
                "nested": [{"client-secret": "C03_RAW_CREDENTIAL_KERNEL_CANARY"}]
            }),
            side_effect_class: SideEffectClass::Network,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        })
        .with_adapter("stub");
        let allowed = ActionCandidate::new(Action {
            name: "safe-input".to_string(),
            params: serde_json::json!({"resource_ref": "fixture:report"}),
            side_effect_class: SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        })
        .with_adapter("stub");
        Ok(PolicyDecision::new(
            vec![denied, allowed],
            StateData {
                bytes: b"credential-free-state".to_vec(),
                content_type: Some("text/plain".to_string()),
            },
            Some("mixed-screened".to_string()),
        ))
    }
}

struct RecordingConstraintEngine {
    names: Arc<Mutex<Vec<String>>>,
}

impl ConstraintEngine for RecordingConstraintEngine {
    fn evaluate(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
        actions: &[ActionCandidate],
    ) -> ConstraintEvaluation {
        *self.names.lock().expect("constraint names") = actions
            .iter()
            .map(|candidate| candidate.action.name.clone())
            .collect();
        ConstraintEvaluation::allow()
    }
}

struct RecordingOutcomeEvaluator {
    names: Arc<Mutex<Vec<String>>>,
}

impl OutcomeEvaluator for RecordingOutcomeEvaluator {
    fn evaluate(&self, action: &Action, _outcome: &ActionOutcome) -> OutcomeSignal {
        self.names
            .lock()
            .expect("outcome names")
            .push(action.name.clone());
        OutcomeSignal {
            feedback: Some(Feedback {
                kind: "integration".to_string(),
                payload: action.params.clone(),
                recorded_at: OffsetDateTime::now_utc(),
            }),
            reward: None,
        }
    }
}

struct CountingAdapter {
    calls: Arc<AtomicUsize>,
}

impl ActionAdapter for CountingAdapter {
    fn execute(
        &self,
        action: &splendor_gateway::ActionRequest,
    ) -> Result<AdapterResult, AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AdapterResult {
            output: serde_json::json!({"executed": action.action.name}),
            satisfied_postconditions: Vec::new(),
        })
    }
}

struct ForbiddenRawEffectAdapter {
    adapter_calls: Arc<AtomicUsize>,
    provider_calls: Arc<AtomicUsize>,
    network_calls: Arc<AtomicUsize>,
    filesystem_calls: Arc<AtomicUsize>,
}

impl ActionAdapter for ForbiddenRawEffectAdapter {
    fn execute(
        &self,
        _action: &splendor_gateway::ActionRequest,
    ) -> Result<AdapterResult, AdapterError> {
        self.adapter_calls.fetch_add(1, Ordering::SeqCst);
        self.provider_calls.fetch_add(1, Ordering::SeqCst);
        self.network_calls.fetch_add(1, Ordering::SeqCst);
        self.filesystem_calls.fetch_add(1, Ordering::SeqCst);
        Ok(AdapterResult {
            output: serde_json::json!({"unexpected": true}),
            satisfied_postconditions: Vec::new(),
        })
    }
}

#[test]
fn loop_engine_persists_state_and_trace_records() {
    let state_store = Arc::new(InMemoryStateStore::default());
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let snapshot_policy = SnapshotPolicy {
        interval: Some(1),
        important_labels: Vec::new(),
    };
    let state_graph = StateGraph::new(state_store.clone(), snapshot_policy);
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };

    let tenant_id = splendor_kernel::TenantId::new();
    let agent_id = splendor_kernel::AgentId::new();
    let agent = AgentContext::new(agent_id, tenant_id.clone(), AgentRuntimeConfig::default());
    let registry = TenantRegistry::new();
    registry.insert(TenantContext::new(
        tenant_id.clone(),
        TenantPolicy {
            allowed_actions: vec!["noop".to_string()],
            allowed_adapters: vec!["stub".to_string()],
            allowed_permissions: Vec::new(),
        },
        QuotaPolicy::default(),
    ));
    registry.begin_tick(1, OffsetDateTime::now_utc());

    let mut gateway = VerifiedActionGateway::new(Arc::new(registry));
    gateway.register_adapter("noop", "stub", Arc::new(StubAdapter));
    let gateway = Arc::new(gateway);

    let run_id = RunId::new();
    let mut engine = LoopEngine::with_trace_store(
        agent,
        state_graph,
        initial_state,
        Box::new(StaticPolicy),
        gateway,
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");
    engine.add_perceptor(StaticPerceptor);

    let outcome = engine.tick(1).expect("tick");
    assert_eq!(outcome.action_outcomes.len(), 1);
    assert!(matches!(
        outcome.action_outcomes[0].status,
        splendor_gateway::ActionStatus::Executed
    ));

    let snapshot_id = outcome
        .state_commit
        .snapshot_id
        .clone()
        .expect("snapshot id");
    let snapshot = state_store
        .load_snapshot(&snapshot_id)
        .expect("load snapshot");
    assert_eq!(snapshot.state.bytes, vec![9]);

    let records = trace_store
        .read(&run_id.to_string())
        .expect("trace records");
    assert!(!records.is_empty());

    let events = records
        .iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).expect("event"))
        .collect::<Vec<_>>();
    for (record, event) in records.iter().zip(events.iter()) {
        assert_eq!(record.sequence, event.sequence);
        assert_eq!(record.run_id, run_id.to_string());
        assert_eq!(event.run_id, run_id);
    }

    let first = events.first().expect("first event");
    let last = events.last().expect("last event");
    assert!(matches!(first.kind, TraceEventKind::RunStarted));
    assert!(matches!(
        events[1].kind,
        TraceEventKind::LoopTickStarted { tick_id: 1 }
    ));
    assert!(matches!(
        last.kind,
        TraceEventKind::LoopTickCompleted { tick_id: 1, .. }
    ));
    let state_event = events
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::StateCommitted { .. }))
        .expect("state committed");
    if let TraceEventKind::StateCommitted {
        state_hash,
        snapshot_id,
    } = &state_event.kind
    {
        assert_eq!(state_hash, outcome.state_commit.node_id.hash());
        assert_eq!(
            snapshot_id.as_ref(),
            outcome.state_commit.snapshot_id.as_ref()
        );
    }
}

#[test]
fn loop_engine_denies_raw_credentials_before_constraint_gateway_trace_state_and_replay() {
    const CANARY: &str = "C03_RAW_CREDENTIAL_KERNEL_CANARY";

    let state_store = Arc::new(InMemoryStateStore::default());
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let state_graph = StateGraph::new(
        state_store.clone(),
        SnapshotPolicy {
            interval: Some(1),
            important_labels: Vec::new(),
        },
    );
    let tenant_id = splendor_kernel::TenantId::new();
    let agent_id = splendor_kernel::AgentId::new();
    let agent = AgentContext::new(agent_id, tenant_id.clone(), AgentRuntimeConfig::default());
    let registry = TenantRegistry::new();
    registry.insert(TenantContext::new(
        tenant_id,
        TenantPolicy {
            allowed_actions: vec!["unsafe-input".to_string(), "safe-input".to_string()],
            allowed_adapters: vec!["stub".to_string()],
            allowed_permissions: Vec::new(),
        },
        QuotaPolicy::default(),
    ));
    registry.begin_tick(1, OffsetDateTime::now_utc());

    let safe_adapter_calls = Arc::new(AtomicUsize::new(0));
    let raw_adapter_calls = Arc::new(AtomicUsize::new(0));
    let raw_provider_calls = Arc::new(AtomicUsize::new(0));
    let raw_network_calls = Arc::new(AtomicUsize::new(0));
    let raw_filesystem_calls = Arc::new(AtomicUsize::new(0));
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry));
    gateway.register_adapter(
        "unsafe-input",
        "stub",
        Arc::new(ForbiddenRawEffectAdapter {
            adapter_calls: Arc::clone(&raw_adapter_calls),
            provider_calls: Arc::clone(&raw_provider_calls),
            network_calls: Arc::clone(&raw_network_calls),
            filesystem_calls: Arc::clone(&raw_filesystem_calls),
        }),
    );
    gateway.register_adapter(
        "safe-input",
        "stub",
        Arc::new(CountingAdapter {
            calls: Arc::clone(&safe_adapter_calls),
        }),
    );
    let constraint_names = Arc::new(Mutex::new(Vec::new()));
    let outcome_names = Arc::new(Mutex::new(Vec::new()));
    let run_id = RunId::new();
    let mut engine = LoopEngine::with_trace_store(
        agent,
        state_graph,
        StateData {
            bytes: b"initial".to_vec(),
            content_type: None,
        },
        Box::new(MixedCredentialPolicy),
        Arc::new(gateway),
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");
    engine.set_constraint_engine(RecordingConstraintEngine {
        names: Arc::clone(&constraint_names),
    });
    engine.set_outcome_evaluator(RecordingOutcomeEvaluator {
        names: Arc::clone(&outcome_names),
    });

    let outcome = engine.tick(1).expect("mixed tick");

    assert_eq!(outcome.action_outcomes.len(), 2);
    assert_eq!(outcome.action_outcomes[0].status, ActionStatus::Denied);
    assert_eq!(
        outcome.action_outcomes[0].verification,
        VerificationResult::deny(RAW_CREDENTIAL_INPUT_DENIED)
    );
    assert_eq!(outcome.action_outcomes[1].status, ActionStatus::Executed);
    assert_eq!(safe_adapter_calls.load(Ordering::SeqCst), 1);
    assert_eq!(raw_adapter_calls.load(Ordering::SeqCst), 0);
    assert_eq!(raw_provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(raw_network_calls.load(Ordering::SeqCst), 0);
    assert_eq!(raw_filesystem_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        *constraint_names.lock().expect("constraint names"),
        vec!["safe-input".to_string()]
    );
    assert_eq!(
        *outcome_names.lock().expect("outcome names"),
        vec!["safe-input".to_string()]
    );

    let snapshot = state_store
        .load_snapshot(
            outcome
                .state_commit
                .snapshot_id
                .as_ref()
                .expect("snapshot id"),
        )
        .expect("snapshot");
    assert!(!String::from_utf8_lossy(&snapshot.state.bytes).contains(CANARY));

    let records = trace_store
        .read(&run_id.to_string())
        .expect("trace records");
    let encoded_records = serde_json::to_string(&records).expect("records serialize");
    assert!(!encoded_records.contains(CANARY));
    let events = records
        .iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).expect("event"))
        .collect::<Vec<_>>();
    let candidates = events
        .iter()
        .find_map(|event| match &event.kind {
            TraceEventKind::CandidatesProposed { actions } => Some(actions),
            _ => None,
        })
        .expect("candidates");
    assert_eq!(candidates[0], raw_credential_denied_action());
    assert_eq!(candidates[1].name, "safe-input");
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::ActionDenied { action, result }
            if action == &raw_credential_denied_action()
                && result == &VerificationResult::deny(RAW_CREDENTIAL_INPUT_DENIED)
    )));

    // Inspect-only reconstruction reads the sanitized records and cannot call an adapter.
    let replayed = trace_store
        .read(&run_id.to_string())
        .expect("inspect replay");
    assert_eq!(replayed, records);
    assert_eq!(safe_adapter_calls.load(Ordering::SeqCst), 1);
    assert_eq!(raw_adapter_calls.load(Ordering::SeqCst), 0);
    assert_eq!(raw_provider_calls.load(Ordering::SeqCst), 0);
    assert!(!serde_json::to_string(&replayed)
        .expect("replay serializes")
        .contains(CANARY));
}
