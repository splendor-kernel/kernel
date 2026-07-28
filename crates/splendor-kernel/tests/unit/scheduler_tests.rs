use super::*;
use crate::loop_engine::{
    ActionCandidate, AllowAllConstraintEngine, LoopEngine, LoopError, Policy, PolicyDecision,
};
use crate::{
    AgentContext, KernelRuntime, KernelRuntimeConfig, SnapshotPolicy, TenantRegistry, TraceError,
    TraceSink,
};
use splendor_gateway::{
    ActionAdapter, ActionGateway, ActionRequest, ActionStatus, AdapterError, AdapterResult,
    VerifiedActionGateway,
};
use splendor_store::{InMemoryStateStore, StateData, TraceStoreError};
use splendor_types::{
    Action, RevocationStatus, StateHandoff, StateHandoffAuthority, TraceEvent, TraceEventKind,
    TraceId, WorkOrder, WorkOrderEnvelope, WorkOrderId, WorkOrderKeyring, WorkOrderPlacement,
    WorkOrderQuotaPolicy, WORK_ORDER_SCHEMA_VERSION,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

struct StaticPolicy {
    action_name: String,
    next_state: Vec<u8>,
}

impl Policy for StaticPolicy {
    fn name(&self) -> &str {
        "static"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[splendor_types::Percept],
    ) -> Result<PolicyDecision, LoopError> {
        let action = Action {
            name: self.action_name.clone(),
            params: serde_json::json!({}),
            side_effect_class: splendor_types::SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        };
        let candidate = ActionCandidate::new(action);
        let state = StateData {
            bytes: self.next_state.clone(),
            content_type: None,
        };
        Ok(PolicyDecision::new(vec![candidate], state, None))
    }
}

struct SlowPolicy {
    action_name: String,
    next_state: Vec<u8>,
    delay: Duration,
}

impl Policy for SlowPolicy {
    fn name(&self) -> &str {
        "slow"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[splendor_types::Percept],
    ) -> Result<PolicyDecision, LoopError> {
        sleep(self.delay);
        let action = Action {
            name: self.action_name.clone(),
            params: serde_json::json!({}),
            side_effect_class: splendor_types::SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        };
        let candidate = ActionCandidate::new(action);
        let state = StateData {
            bytes: self.next_state.clone(),
            content_type: None,
        };
        Ok(PolicyDecision::new(vec![candidate], state, None))
    }
}

struct FailPolicy;

impl Policy for FailPolicy {
    fn name(&self) -> &str {
        "fail"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[splendor_types::Percept],
    ) -> Result<PolicyDecision, LoopError> {
        Err(LoopError::Policy("failed".to_string()))
    }
}

struct FailOncePolicy {
    calls: Arc<AtomicUsize>,
}

impl Policy for FailOncePolicy {
    fn name(&self) -> &str {
        "fail-once"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[splendor_types::Percept],
    ) -> Result<PolicyDecision, LoopError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(LoopError::Policy("failed-before-effect".to_string()));
        }
        Ok(PolicyDecision::new(
            vec![ActionCandidate::new(Action {
                name: "noop".to_string(),
                params: serde_json::json!({}),
                side_effect_class: splendor_types::SideEffectClass::ReadOnly,
                cost_estimate: None,
                required_permissions: Vec::new(),
                preconditions: Vec::new(),
                postconditions: Vec::new(),
            })],
            StateData {
                bytes: vec![1],
                content_type: None,
            },
            None,
        ))
    }
}

#[derive(Default)]
struct TestAdapter;

impl ActionAdapter for TestAdapter {
    fn execute(&self, action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        Ok(AdapterResult {
            output: serde_json::json!({"ok": true}),
            satisfied_postconditions: action.action.postconditions.clone(),
        })
    }
}

struct CredentialOutputAdapter {
    calls: Arc<AtomicUsize>,
}

struct CountingSuccessAdapter {
    calls: Arc<AtomicUsize>,
}

impl ActionAdapter for CountingSuccessAdapter {
    fn execute(&self, action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AdapterResult {
            output: serde_json::json!({"ok": true}),
            satisfied_postconditions: action.action.postconditions.clone(),
        })
    }
}

struct CountingFailedAdapter {
    calls: Arc<AtomicUsize>,
}

impl ActionAdapter for CountingFailedAdapter {
    fn execute(&self, _action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(AdapterError::Failed(
            "untrusted provider detail".to_string(),
        ))
    }
}

impl ActionAdapter for CredentialOutputAdapter {
    fn execute(&self, _action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AdapterResult {
            output: serde_json::json!({"body": "Basic dTpw"}),
            satisfied_postconditions: Vec::new(),
        })
    }
}

#[derive(Default)]
struct NullTraceSink;

impl TraceSink for NullTraceSink {
    fn record(&self, _event: &TraceEvent) -> Result<(), TraceError> {
        Ok(())
    }
}

struct FailAfterAdapterReturnTraceSink;

impl TraceSink for FailAfterAdapterReturnTraceSink {
    fn record(&self, event: &TraceEvent) -> Result<(), TraceError> {
        if matches!(
            &event.kind,
            TraceEventKind::ActionVerificationCompleted { .. }
        ) {
            return Err(TraceError::Store(TraceStoreError::Poisoned));
        }
        Ok(())
    }
}

struct CapturingTraceSink {
    events: Arc<Mutex<Vec<TraceEvent>>>,
}

impl TraceSink for CapturingTraceSink {
    fn record(&self, event: &TraceEvent) -> Result<(), TraceError> {
        self.events
            .lock()
            .expect("capture trace event")
            .push(event.clone());
        Ok(())
    }
}

fn build_engine(
    tenant_id: TenantId,
    action_name: &str,
    next_state: &[u8],
    gateway: Arc<dyn ActionGateway>,
) -> LoopEngine {
    let policy = StaticPolicy {
        action_name: action_name.to_string(),
        next_state: next_state.to_vec(),
    };
    build_engine_with_policy(tenant_id, Box::new(policy), gateway)
}

fn build_engine_with_policy(
    tenant_id: TenantId,
    policy: Box<dyn Policy>,
    gateway: Arc<dyn ActionGateway>,
) -> LoopEngine {
    build_engine_with_policy_and_trace_sink(tenant_id, policy, gateway, Arc::new(NullTraceSink))
}

fn build_engine_with_policy_and_trace_sink(
    tenant_id: TenantId,
    policy: Box<dyn Policy>,
    gateway: Arc<dyn ActionGateway>,
    trace_sink: Arc<dyn TraceSink>,
) -> LoopEngine {
    let store = Arc::new(InMemoryStateStore::default());
    let graph = crate::StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![0],
        content_type: None,
    };
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        tenant_id,
        crate::AgentRuntimeConfig::default(),
    );
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink,
        ..KernelRuntimeConfig::default()
    });
    let mut engine =
        LoopEngine::with_runtime(agent, graph, initial_state, policy, gateway, runtime);
    engine.set_constraint_engine(AllowAllConstraintEngine);
    engine
}

fn build_exact_engine(
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
    gateway: Arc<dyn ActionGateway>,
    events: Arc<Mutex<Vec<TraceEvent>>>,
) -> LoopEngine {
    let graph = crate::StateGraph::new(
        Arc::new(InMemoryStateStore::default()),
        SnapshotPolicy::default(),
    );
    let agent = AgentContext::new(agent_id, tenant_id, crate::AgentRuntimeConfig::default());
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(CapturingTraceSink { events }),
        run_id: Some(run_id),
        ..KernelRuntimeConfig::default()
    });
    let mut engine = LoopEngine::with_runtime(
        agent,
        graph,
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(StaticPolicy {
            action_name: "noop".to_string(),
            next_state: vec![1],
        }),
        gateway,
        runtime,
    );
    engine.set_constraint_engine(AllowAllConstraintEngine);
    engine
}

fn scheduler_state_handoff(
    tenant_id: &TenantId,
    agent_id: &AgentId,
    run_id: &RunId,
    now: OffsetDateTime,
) -> StateHandoff {
    let store = Arc::new(InMemoryStateStore::default());
    let mut graph = crate::StateGraph::new(
        store,
        SnapshotPolicy {
            interval: Some(1),
            important_labels: Vec::new(),
        },
    );
    let commit = graph
        .commit(
            StateData {
                bytes: b"exact-target-state".to_vec(),
                content_type: Some("application/octet-stream".to_string()),
            },
            StateMetadata::new(now, Some("source".to_string())),
        )
        .expect("source state commit");
    graph
        .export_handoff(
            &commit.snapshot_id.expect("source snapshot"),
            StateHandoffExportRequest {
                handoff_id: "handoff_exact_target".to_string(),
                authority: StateHandoffAuthority {
                    tenant_id: tenant_id.clone(),
                    agent_id: agent_id.clone(),
                    run_id: run_id.clone(),
                    work_order_id: "wo_scheduler_handoff".to_string(),
                },
                source_instance_id: None,
                receiver_instance_id: None,
                previous_state_node_id: None,
                source_trace_id: Some(TraceId::from_run_sequence(run_id, 1)),
                created_at: now,
            },
        )
        .expect("source handoff")
}

fn scheduler_state_handoff_work_order(
    tenant_id: &TenantId,
    agent_id: &AgentId,
    run_id: &RunId,
    now: OffsetDateTime,
) -> (WorkOrderEnvelope, WorkOrderKeyring) {
    let order = WorkOrder {
        schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new("wo_scheduler_handoff").expect("work order id"),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: Some(run_id.clone()),
        objective: "exact scheduler state handoff".to_string(),
        allowed_actions: vec!["state.handoff".to_string()],
        allowed_adapters: vec!["state".to_string()],
        allowed_permissions: vec!["state.read".to_string()],
        data_refs: Vec::new(),
        quotas: WorkOrderQuotaPolicy::default(),
        placement: WorkOrderPlacement::default(),
        issued_at: now - time::Duration::minutes(1),
        expires_at: now + time::Duration::hours(1),
        revocation: RevocationStatus::Active,
    };
    let envelope = WorkOrderEnvelope::signed_with_shared_secret(
        order,
        "key_scheduler_handoff",
        b"scheduler-handoff-secret",
    )
    .expect("signed work order");
    let mut keyring = WorkOrderKeyring::new();
    keyring
        .insert_shared_secret("key_scheduler_handoff", b"scheduler-handoff-secret")
        .expect("work order key");
    (envelope, keyring)
}

#[test]
fn scheduler_runs_agents_in_order_and_keeps_agent_quotas_isolated() {
    let tenant_id = TenantId::new();
    let policy = crate::TenantPolicy {
        allowed_actions: vec!["alpha".to_string(), "beta".to_string()],
        allowed_adapters: vec!["adapter".to_string()],
        ..crate::TenantPolicy::default()
    };
    let quotas = crate::QuotaPolicy {
        max_actions_per_tick: Some(1),
        ..crate::QuotaPolicy::default()
    };
    let tenant = crate::TenantContext::new(tenant_id.clone(), policy, quotas);

    let registry = TenantRegistry::new();
    registry.insert(tenant);

    let tenant_access = Arc::new(registry.clone());
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    gateway.register_adapter("alpha", "adapter", Arc::new(TestAdapter));
    gateway.register_adapter("beta", "adapter", Arc::new(TestAdapter));
    let gateway = Arc::new(gateway);

    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);

    let engine_one = build_engine(tenant_id.clone(), "alpha", &[1], gateway.clone());
    let engine_two = build_engine(tenant_id.clone(), "beta", &[2], gateway);

    scheduler.add_agent(engine_one);
    scheduler.add_agent(engine_two);

    let steps = scheduler.run_cycle().expect("cycle");
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].tick_id, 1);
    assert_eq!(steps[1].tick_id, 1);

    let first_status = &steps[0].outcome.action_outcomes[0].status;
    let second_status = &steps[1].outcome.action_outcomes[0].status;
    assert!(matches!(first_status, ActionStatus::Executed));
    assert!(matches!(second_status, ActionStatus::Executed));

    let usage = scheduler.tenant_usage(&tenant_id).expect("usage");
    assert_eq!(usage.actions, 2);
}

#[test]
fn scheduler_rejects_duplicate_exact_runtime_identity() {
    let tenant_id = TenantId::new();
    let agent_id = splendor_types::AgentId::new();
    let run_id = splendor_types::RunId::new();
    let registry = TenantRegistry::new();
    registry.insert(crate::TenantContext::new(
        tenant_id.clone(),
        crate::TenantPolicy {
            allowed_actions: vec!["noop".to_string()],
            allowed_adapters: vec!["adapter".to_string()],
            ..crate::TenantPolicy::default()
        },
        crate::QuotaPolicy::default(),
    ));
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry.clone()));
    gateway.register_adapter("noop", "adapter", Arc::new(TestAdapter));
    let gateway: Arc<dyn ActionGateway> = Arc::new(gateway);
    let build_duplicate = || {
        let agent = AgentContext::new(
            agent_id.clone(),
            tenant_id.clone(),
            crate::AgentRuntimeConfig::default(),
        );
        let graph = crate::StateGraph::new(
            Arc::new(InMemoryStateStore::default()),
            SnapshotPolicy::default(),
        );
        let runtime = KernelRuntime::new(KernelRuntimeConfig {
            trace_sink: Arc::new(NullTraceSink),
            run_id: Some(run_id.clone()),
            ..KernelRuntimeConfig::default()
        });
        LoopEngine::with_runtime(
            agent,
            graph,
            StateData {
                bytes: vec![0],
                content_type: None,
            },
            Box::new(StaticPolicy {
                action_name: "noop".to_string(),
                next_state: vec![1],
            }),
            gateway.clone(),
            runtime,
        )
    };
    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);

    scheduler
        .try_add_agent(build_duplicate())
        .expect("first exact identity");
    assert!(matches!(
        scheduler.try_add_agent(build_duplicate()),
        Err(SchedulerError::DuplicateRuntimeIdentity {
            run_id: duplicate_run,
            tenant_id: duplicate_tenant,
            agent_id: duplicate_agent,
        }) if duplicate_run == run_id
            && duplicate_tenant == tenant_id
            && duplicate_agent == agent_id
    ));

    let steps = scheduler.run_cycle().expect("single admitted identity");
    assert_eq!(steps.len(), 1);
}

#[test]
fn scheduler_agent_compatibility_denies_ambiguity_and_exact_targets_do_not_cross() {
    let tenant_left = TenantId::new();
    let tenant_right = TenantId::new();
    let agent_id = AgentId::new();
    let run_left = RunId::new();
    let run_right = RunId::new();
    let registry = TenantRegistry::new();
    for tenant_id in [&tenant_left, &tenant_right] {
        registry.insert(crate::TenantContext::new(
            tenant_id.clone(),
            crate::TenantPolicy {
                allowed_actions: vec!["noop".to_string()],
                allowed_adapters: vec!["adapter".to_string()],
                ..crate::TenantPolicy::default()
            },
            crate::QuotaPolicy::default(),
        ));
    }
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry.clone()));
    gateway.register_adapter("noop", "adapter", Arc::new(TestAdapter));
    let gateway: Arc<dyn ActionGateway> = Arc::new(gateway);
    let left_events = Arc::new(Mutex::new(Vec::new()));
    let right_events = Arc::new(Mutex::new(Vec::new()));
    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
    scheduler
        .try_add_agent(build_exact_engine(
            tenant_left.clone(),
            agent_id.clone(),
            run_left.clone(),
            gateway.clone(),
            Arc::clone(&left_events),
        ))
        .expect("left runtime");
    scheduler
        .try_add_agent(build_exact_engine(
            tenant_right.clone(),
            agent_id.clone(),
            run_right.clone(),
            gateway,
            Arc::clone(&right_events),
        ))
        .expect("right runtime");

    assert!(matches!(
        scheduler.record_event_for_agent(
            &agent_id,
            TraceEventKind::RunPaused {
                reason: Some("ambiguous".to_string()),
            },
        ),
        Err(SchedulerError::RuntimeTargetUnavailable)
    ));
    let action_id = ActionId::new();
    assert!(matches!(
        scheduler.record_action_event_for_agent(
            &agent_id,
            &action_id,
            TraceEventKind::ActionVerificationStarted {
                action: Action {
                    name: "noop".to_string(),
                    params: serde_json::json!({}),
                    side_effect_class: splendor_types::SideEffectClass::ReadOnly,
                    cost_estimate: None,
                    required_permissions: Vec::new(),
                    preconditions: Vec::new(),
                    postconditions: Vec::new(),
                },
            },
        ),
        Err(SchedulerError::RuntimeTargetUnavailable)
    ));
    assert!(matches!(
        scheduler.export_state_handoff_for_agent(
            &agent_id,
            StateHandoffExportRequest {
                handoff_id: "ambiguous".to_string(),
                authority: StateHandoffAuthority {
                    tenant_id: tenant_left.clone(),
                    agent_id: agent_id.clone(),
                    run_id: run_left.clone(),
                    work_order_id: "work-order".to_string(),
                },
                source_instance_id: None,
                receiver_instance_id: None,
                previous_state_node_id: None,
                source_trace_id: None,
                created_at: OffsetDateTime::UNIX_EPOCH,
            },
        ),
        Err(SchedulerError::RuntimeTargetUnavailable)
    ));
    assert!(left_events.lock().expect("left events").is_empty());
    assert!(right_events.lock().expect("right events").is_empty());

    let left_target = RuntimeTarget::new(run_left.clone(), tenant_left.clone(), agent_id.clone());
    let right_target =
        RuntimeTarget::new(run_right.clone(), tenant_right.clone(), agent_id.clone());
    let wrong_target = RuntimeTarget::new(run_right.clone(), tenant_left.clone(), agent_id.clone());
    let now = OffsetDateTime::now_utc();
    let handoff = scheduler_state_handoff(&tenant_right, &agent_id, &run_right, now);
    let (work_order, keyring) =
        scheduler_state_handoff_work_order(&tenant_right, &agent_id, &run_right, now);
    let scope = StateHandoffScope {
        tenant_id: tenant_right.clone(),
        agent_id: agent_id.clone(),
        run_id: run_right.clone(),
        receiver_instance_id: None,
    };
    let metadata = StateMetadata::new(now, Some("receiver".to_string()));
    assert!(matches!(
        scheduler.import_state_handoff_for_agent(
            &agent_id,
            &handoff,
            &work_order,
            &keyring,
            &scope,
            now,
            metadata.clone(),
        ),
        Err(SchedulerError::RuntimeTargetUnavailable)
    ));
    assert!(matches!(
        scheduler.import_state_handoff_for_target(
            &wrong_target,
            &handoff,
            &work_order,
            &keyring,
            &scope,
            now,
            metadata.clone(),
        ),
        Err(SchedulerError::RuntimeTargetUnavailable)
    ));
    let (imported, import_event) = scheduler
        .import_state_handoff_for_target(
            &right_target,
            &handoff,
            &work_order,
            &keyring,
            &scope,
            now,
            metadata,
        )
        .expect("exact right import");
    assert_eq!(imported.tenant_id.as_ref(), Some(&tenant_right));
    assert_eq!(imported.agent_id.as_ref(), Some(&agent_id));
    assert_eq!(imported.run_id.as_ref(), Some(&run_right));
    assert_eq!(import_event.run_id, run_right);
    assert_eq!(
        import_event.identity.tenant_id.as_ref(),
        Some(&tenant_right)
    );
    assert!(left_events.lock().expect("left events").is_empty());
    assert_eq!(right_events.lock().expect("right import event").len(), 1);

    let (exported, export_event) = scheduler
        .export_state_handoff_for_target(
            &right_target,
            StateHandoffExportRequest {
                handoff_id: "exact-export".to_string(),
                authority: StateHandoffAuthority {
                    tenant_id: tenant_right.clone(),
                    agent_id: agent_id.clone(),
                    run_id: run_right.clone(),
                    work_order_id: "wo_scheduler_handoff".to_string(),
                },
                source_instance_id: None,
                receiver_instance_id: None,
                previous_state_node_id: None,
                source_trace_id: None,
                created_at: now,
            },
        )
        .expect("exact right export");
    assert_eq!(exported.authority.tenant_id, tenant_right);
    assert_eq!(export_event.run_id, run_right);
    assert_eq!(right_events.lock().expect("right export event").len(), 2);
    assert!(matches!(
        scheduler.export_state_handoff_for_target(
            &wrong_target,
            StateHandoffExportRequest {
                handoff_id: "wrong-export".to_string(),
                authority: exported.authority.clone(),
                source_instance_id: None,
                receiver_instance_id: None,
                previous_state_node_id: None,
                source_trace_id: None,
                created_at: now,
            },
        ),
        Err(SchedulerError::RuntimeTargetUnavailable)
    ));

    let event = scheduler
        .record_event_for_target(
            &left_target,
            TraceEventKind::RunPaused {
                reason: Some("exact".to_string()),
            },
        )
        .expect("exact left event");
    assert_eq!(event.run_id, run_left);
    assert_eq!(event.identity.tenant_id.as_ref(), Some(&tenant_left));
    assert_eq!(event.identity.agent_id.as_ref(), Some(&agent_id));
    assert_eq!(left_events.lock().expect("left event count").len(), 1);
    assert_eq!(right_events.lock().expect("right event count").len(), 2);

    let exact_action_id = ActionId::new();
    let action_event = scheduler
        .record_action_event_for_target(
            &left_target,
            &exact_action_id,
            TraceEventKind::ActionVerificationStarted {
                action: Action {
                    name: "noop".to_string(),
                    params: serde_json::json!({}),
                    side_effect_class: splendor_types::SideEffectClass::ReadOnly,
                    cost_estimate: None,
                    required_permissions: Vec::new(),
                    preconditions: Vec::new(),
                    postconditions: Vec::new(),
                },
            },
        )
        .expect("exact left action event");
    assert_eq!(
        action_event.identity.action_id.as_ref(),
        Some(&exact_action_id)
    );
    assert_eq!(
        left_events.lock().expect("left action event count").len(),
        2
    );
    assert_eq!(
        right_events.lock().expect("right action event count").len(),
        2
    );

    assert!(matches!(
        scheduler.record_event_for_target(
            &wrong_target,
            TraceEventKind::RunPaused {
                reason: Some("wrong".to_string()),
            },
        ),
        Err(SchedulerError::RuntimeTargetUnavailable)
    ));

    let diagnostics = format!(
        "{:?} {}",
        SchedulerError::DuplicateRuntimeIdentity {
            run_id: RunId::new(),
            tenant_id: TenantId::new(),
            agent_id: AgentId::new(),
        },
        SchedulerError::RuntimeTargetUnavailable
    );
    assert_eq!(
        diagnostics,
        "scheduler_runtime_identity_conflict scheduler_runtime_target_unavailable"
    );
}

#[test]
fn scheduler_steps_report_exact_identity_when_agent_ids_repeat() {
    let tenant_left = TenantId::new();
    let tenant_right = TenantId::new();
    let agent_id = AgentId::new();
    let run_left = RunId::new();
    let run_right = RunId::new();
    let registry = TenantRegistry::new();
    for tenant_id in [&tenant_left, &tenant_right] {
        registry.insert(crate::TenantContext::new(
            tenant_id.clone(),
            crate::TenantPolicy {
                allowed_actions: vec!["noop".to_string()],
                allowed_adapters: vec!["adapter".to_string()],
                ..crate::TenantPolicy::default()
            },
            crate::QuotaPolicy::default(),
        ));
    }
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry.clone()));
    gateway.register_adapter("noop", "adapter", Arc::new(TestAdapter));
    let gateway: Arc<dyn ActionGateway> = Arc::new(gateway);
    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
    scheduler.add_agent(build_exact_engine(
        tenant_left.clone(),
        agent_id.clone(),
        run_left.clone(),
        gateway.clone(),
        Arc::new(Mutex::new(Vec::new())),
    ));
    scheduler.add_agent(build_exact_engine(
        tenant_right.clone(),
        agent_id.clone(),
        run_right.clone(),
        gateway,
        Arc::new(Mutex::new(Vec::new())),
    ));

    let steps = scheduler.run_cycle().expect("duplicate-agent cycle");
    assert_eq!(steps.len(), 2);
    assert!(steps.iter().any(|step| {
        step.run_id == run_left && step.tenant_id == tenant_left && step.agent_id == agent_id
    }));
    assert!(steps.iter().any(|step| {
        step.run_id == run_right && step.tenant_id == tenant_right && step.agent_id == agent_id
    }));
}

#[test]
fn scheduler_reports_tick_budget_exceeded() {
    let tenant_id = TenantId::new();
    let policy = crate::TenantPolicy {
        allowed_actions: vec!["slow".to_string()],
        allowed_adapters: vec!["adapter".to_string()],
        ..crate::TenantPolicy::default()
    };
    let tenant =
        crate::TenantContext::new(tenant_id.clone(), policy, crate::QuotaPolicy::default());
    let registry = TenantRegistry::new();
    registry.insert(tenant);

    let tenant_access = Arc::new(registry.clone());
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    gateway.register_adapter("slow", "adapter", Arc::new(TestAdapter));
    let gateway = Arc::new(gateway);

    let config = SchedulerConfig {
        tick_budget: Some(Duration::from_millis(1)),
        ..SchedulerConfig::default()
    };
    let mut scheduler = Scheduler::with_registry(config, registry);

    let policy = SlowPolicy {
        action_name: "slow".to_string(),
        next_state: vec![3],
        delay: Duration::from_millis(5),
    };
    let engine = build_engine_with_policy(tenant_id, Box::new(policy), gateway);
    scheduler.add_agent(engine);

    let error = scheduler.run_once().expect_err("budget exceeded");
    match error {
        SchedulerError::TickBudgetExceeded {
            step,
            budget,
            elapsed,
        } => {
            assert_eq!(step.tick_id, 1);
            assert!(elapsed >= budget);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn scheduler_returns_no_agents_when_empty() {
    let mut scheduler = Scheduler::new(SchedulerConfig::default());
    let error = scheduler.run_once().expect_err("no agents");
    assert!(matches!(error, SchedulerError::NoAgents));
    let error = scheduler.run_cycle().expect_err("no agents");
    assert!(matches!(error, SchedulerError::NoAgents));
}

#[test]
fn scheduler_returns_missing_tenant() {
    let tenant_id = TenantId::new();
    let registry = TenantRegistry::new();

    let tenant_access = Arc::new(registry.clone());
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    gateway.register_adapter("noop", "adapter", Arc::new(TestAdapter));
    let gateway = Arc::new(gateway);

    let engine = build_engine(tenant_id.clone(), "noop", &[1], gateway);
    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
    scheduler.add_agent(engine);

    let error = scheduler.run_once().expect_err("missing tenant");
    match error {
        SchedulerError::MissingTenant(id) => assert_eq!(id, tenant_id),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn scheduler_reports_loop_error() {
    let tenant_id = TenantId::new();
    let policy = crate::TenantPolicy {
        allowed_actions: vec!["noop".to_string()],
        allowed_adapters: vec!["adapter".to_string()],
        ..crate::TenantPolicy::default()
    };
    let tenant =
        crate::TenantContext::new(tenant_id.clone(), policy, crate::QuotaPolicy::default());
    let registry = TenantRegistry::new();
    registry.insert(tenant);

    let tenant_access = Arc::new(registry.clone());
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    gateway.register_adapter("noop", "adapter", Arc::new(TestAdapter));
    let gateway = Arc::new(gateway);

    let store = Arc::new(InMemoryStateStore::default());
    let graph = crate::StateGraph::new(store, SnapshotPolicy::default());
    let initial_state = StateData {
        bytes: vec![0],
        content_type: None,
    };
    let agent = AgentContext::new(
        splendor_types::AgentId::new(),
        tenant_id.clone(),
        crate::AgentRuntimeConfig::default(),
    );
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(NullTraceSink),
        ..KernelRuntimeConfig::default()
    });
    let engine = LoopEngine::with_runtime(
        agent,
        graph,
        initial_state,
        Box::new(FailPolicy),
        gateway,
        runtime,
    );

    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
    scheduler.add_agent(engine);

    let error = scheduler.run_once().expect_err("loop error");
    assert!(matches!(error, SchedulerError::Loop(_)));
}

#[test]
fn scheduler_respects_tick_interval() {
    let tenant_id = TenantId::new();
    let policy = crate::TenantPolicy {
        allowed_actions: vec!["alpha".to_string()],
        allowed_adapters: vec!["adapter".to_string()],
        ..crate::TenantPolicy::default()
    };
    let tenant =
        crate::TenantContext::new(tenant_id.clone(), policy, crate::QuotaPolicy::default());
    let registry = TenantRegistry::new();
    registry.insert(tenant);

    let tenant_access = Arc::new(registry.clone());
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    gateway.register_adapter("alpha", "adapter", Arc::new(TestAdapter));
    let gateway = Arc::new(gateway);

    let mut scheduler = Scheduler::with_registry(
        SchedulerConfig {
            tick_budget: None,
            tick_interval: Some(Duration::from_millis(1)),
        },
        registry,
    );
    scheduler.add_agent(build_engine(tenant_id, "alpha", &[1], gateway));

    let steps = scheduler.run_cycle().expect("cycle");
    assert_eq!(steps.len(), 1);
}

#[test]
fn scheduler_run_cycles_returns_steps() {
    let tenant_id = TenantId::new();
    let policy = crate::TenantPolicy {
        allowed_actions: vec!["alpha".to_string()],
        allowed_adapters: vec!["adapter".to_string()],
        ..crate::TenantPolicy::default()
    };
    let tenant =
        crate::TenantContext::new(tenant_id.clone(), policy, crate::QuotaPolicy::default());
    let registry = TenantRegistry::new();
    registry.insert(tenant);

    let tenant_access = Arc::new(registry.clone());
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    gateway.register_adapter("alpha", "adapter", Arc::new(TestAdapter));
    let gateway = Arc::new(gateway);

    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
    scheduler.add_agent(build_engine(tenant_id, "alpha", &[1], gateway));

    let steps = scheduler.run_cycles(2).expect("cycles");
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].tick_id, 1);
    assert_eq!(steps[1].tick_id, 2);
}

#[test]
fn scheduler_run_forever_returns_error_on_empty_queue() {
    let mut scheduler = Scheduler::new(SchedulerConfig::default());
    let error = scheduler.run_forever().expect_err("no agents");
    assert!(matches!(error, SchedulerError::NoAgents));
}

#[test]
fn scheduler_parks_post_effect_intervention_until_explicit_reconciliation() {
    let tenant_id = TenantId::new();
    let tenant = crate::TenantContext::new(
        tenant_id.clone(),
        crate::TenantPolicy {
            allowed_actions: vec!["noop".to_string()],
            allowed_adapters: vec!["adapter".to_string()],
            ..crate::TenantPolicy::default()
        },
        crate::QuotaPolicy::default(),
    );
    let registry = TenantRegistry::new();
    registry.insert(tenant);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry.clone()));
    gateway.register_adapter(
        "noop",
        "adapter",
        Arc::new(CredentialOutputAdapter {
            calls: Arc::clone(&calls),
        }),
    );
    let engine = build_engine(tenant_id, "noop", &[1], Arc::new(gateway));
    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
    scheduler.add_agent(engine);

    let first = scheduler.run_once().expect("suppression outcome");
    assert!(first.outcome.needs_intervention);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        scheduler.run_once(),
        Err(SchedulerError::Loop(LoopError::Policy(ref reason)))
            if reason == "tick_reconciliation_required"
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn post_effect_trace_failure_still_parks_without_repeating_adapter() {
    let tenant_id = TenantId::new();
    let tenant = crate::TenantContext::new(
        tenant_id.clone(),
        crate::TenantPolicy {
            allowed_actions: vec!["noop".to_string()],
            allowed_adapters: vec!["adapter".to_string()],
            ..crate::TenantPolicy::default()
        },
        crate::QuotaPolicy::default(),
    );
    let registry = TenantRegistry::new();
    registry.insert(tenant);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry.clone()));
    gateway.register_adapter(
        "noop",
        "adapter",
        Arc::new(CountingSuccessAdapter {
            calls: Arc::clone(&calls),
        }),
    );
    let engine = build_engine_with_policy_and_trace_sink(
        tenant_id,
        Box::new(StaticPolicy {
            action_name: "noop".to_string(),
            next_state: vec![1],
        }),
        Arc::new(gateway),
        Arc::new(FailAfterAdapterReturnTraceSink),
    );
    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
    scheduler.add_agent(engine);

    assert!(matches!(
        scheduler.run_once(),
        Err(SchedulerError::Loop(LoopError::Trace(TraceError::Store(
            TraceStoreError::Poisoned
        ))))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        scheduler.run_once(),
        Err(SchedulerError::Loop(LoopError::Policy(ref reason)))
            if reason == "tick_reconciliation_required"
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn generic_adapter_failure_parks_after_completed_scheduler_tick() {
    let tenant_id = TenantId::new();
    let tenant = crate::TenantContext::new(
        tenant_id.clone(),
        crate::TenantPolicy {
            allowed_actions: vec!["noop".to_string()],
            allowed_adapters: vec!["adapter".to_string()],
            ..crate::TenantPolicy::default()
        },
        crate::QuotaPolicy::default(),
    );
    let registry = TenantRegistry::new();
    registry.insert(tenant);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry.clone()));
    gateway.register_adapter(
        "noop",
        "adapter",
        Arc::new(CountingFailedAdapter {
            calls: Arc::clone(&calls),
        }),
    );
    let engine = build_engine(tenant_id, "noop", &[1], Arc::new(gateway));
    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
    scheduler.add_agent(engine);

    let first = scheduler
        .run_once()
        .expect("failed outcome is durably recorded");
    assert_eq!(
        first.outcome.action_outcomes[0].status,
        ActionStatus::Failed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        scheduler.run_once(),
        Err(SchedulerError::Loop(LoopError::Policy(ref reason)))
            if reason == "tick_reconciliation_required"
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn scheduler_requeues_an_ordinary_pre_effect_loop_failure() {
    let tenant_id = TenantId::new();
    let tenant = crate::TenantContext::new(
        tenant_id.clone(),
        crate::TenantPolicy {
            allowed_actions: vec!["noop".to_string()],
            allowed_adapters: vec!["adapter".to_string()],
            ..crate::TenantPolicy::default()
        },
        crate::QuotaPolicy::default(),
    );
    let registry = TenantRegistry::new();
    registry.insert(tenant);
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry.clone()));
    gateway.register_adapter("noop", "adapter", Arc::new(TestAdapter));
    let policy_calls = Arc::new(AtomicUsize::new(0));
    let engine = build_engine_with_policy(
        tenant_id,
        Box::new(FailOncePolicy {
            calls: Arc::clone(&policy_calls),
        }),
        Arc::new(gateway),
    );
    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
    scheduler.add_agent(engine);

    assert!(matches!(
        scheduler.run_once(),
        Err(SchedulerError::Loop(LoopError::Policy(ref reason)))
            if reason == "failed-before-effect"
    ));
    let recovered = scheduler
        .run_once()
        .expect("ordinary retry remains available");
    assert_eq!(
        recovered.outcome.action_outcomes[0].status,
        ActionStatus::Executed
    );
    assert_eq!(policy_calls.load(Ordering::SeqCst), 2);
}

#[test]
fn scheduler_register_tenant_and_registry_access() {
    let tenant_id = TenantId::new();
    let tenant = crate::TenantContext::new(
        tenant_id.clone(),
        crate::TenantPolicy::default(),
        crate::QuotaPolicy::default(),
    );
    let mut scheduler = Scheduler::new(SchedulerConfig::default());
    scheduler.register_tenant(tenant);

    let registry = scheduler.tenant_registry();
    let found = registry.with_tenant(&tenant_id, |tenant| tenant.current_tick());
    assert_eq!(found, Some(0));
}
