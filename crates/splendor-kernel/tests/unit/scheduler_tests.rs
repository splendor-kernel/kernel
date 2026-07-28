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
use splendor_types::{Action, TraceEvent, TraceEventKind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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
