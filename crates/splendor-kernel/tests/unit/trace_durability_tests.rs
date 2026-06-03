use super::*;
use splendor_gateway::{
    ActionGateway, ActionId, ActionOutcome, ActionRequest, ActionStatus, GatewayError,
};
use splendor_store::{
    InMemoryTraceStore, LocalTraceBuffer, LocalTraceBufferConfig, TraceBufferAppendMode,
};
use splendor_types::{
    Action, AgentId, QuotaUsage, RunId, SideEffectClass, TenantId, VerificationResult,
};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

#[derive(Clone)]
struct StaticTraceStatus {
    state: TraceDurabilityState,
}

impl TraceDurabilityStatus for StaticTraceStatus {
    fn trace_durability_state(&self) -> TraceDurabilityState {
        self.state.clone()
    }
}

struct CountingGateway {
    calls: Arc<Mutex<u32>>,
}

impl ActionGateway for CountingGateway {
    fn submit(&self, request: ActionRequest) -> Result<ActionOutcome, GatewayError> {
        let mut calls = self.calls.lock().expect("calls lock");
        *calls += 1;
        Ok(ActionOutcome {
            action_id: request.action_id,
            status: ActionStatus::Executed,
            verification: VerificationResult::allow(),
            post_verification: Some(VerificationResult::allow()),
            output: Some(serde_json::json!({"ok": true})),
            error: None,
            completed_at: OffsetDateTime::now_utc(),
        })
    }
}

fn request(side_effect_class: SideEffectClass) -> ActionRequest {
    ActionRequest {
        action_id: ActionId::new(),
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id: RunId::new(),
        action: Action {
            name: "file.write".to_string(),
            params: serde_json::json!({"path": "out.txt"}),
            side_effect_class,
            cost_estimate: None,
            required_permissions: vec![],
            preconditions: vec![],
            postconditions: vec![],
        },
        adapter: None,
        quota_usage: QuotaUsage::single_action(),
        satisfied_preconditions: vec![],
        requested_at: OffsetDateTime::now_utc(),
        approval_evidence: None,
    }
}

fn gateway_with_state(
    state: TraceDurabilityState,
    require_central_sync_for_side_effects: bool,
    calls: Arc<Mutex<u32>>,
) -> TraceDurabilityGateway {
    TraceDurabilityGateway::new(
        Arc::new(CountingGateway { calls }),
        Arc::new(StaticTraceStatus { state }),
        TraceDurabilityPolicy {
            require_central_sync_for_side_effects,
        },
    )
}

#[test]
fn side_effectful_action_is_denied_when_trace_sync_required_and_stale() {
    let calls = Arc::new(Mutex::new(0));
    let gateway = gateway_with_state(
        TraceDurabilityState {
            local_latest_sequence: Some(5),
            central_latest_sequence: Some(4),
            last_sync_error: Some("central index unavailable".to_string()),
            last_local_buffer_error: None,
        },
        true,
        calls.clone(),
    );

    let outcome = gateway
        .submit(request(SideEffectClass::Filesystem))
        .expect("gateway outcome");

    assert_eq!(outcome.status, ActionStatus::Denied);
    assert_eq!(
        outcome.verification.reasons,
        vec!["trace_durability_required"]
    );
    assert_eq!(*calls.lock().expect("calls lock"), 0);
}

#[test]
fn read_only_action_is_allowed_even_when_sync_is_stale() {
    let calls = Arc::new(Mutex::new(0));
    let gateway = gateway_with_state(
        TraceDurabilityState {
            local_latest_sequence: Some(5),
            central_latest_sequence: Some(4),
            last_sync_error: Some("central index unavailable".to_string()),
            last_local_buffer_error: None,
        },
        true,
        calls.clone(),
    );

    let outcome = gateway
        .submit(request(SideEffectClass::ReadOnly))
        .expect("gateway outcome");

    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(*calls.lock().expect("calls lock"), 1);
}

#[test]
fn side_effectful_action_is_allowed_when_trace_sync_is_current() {
    let calls = Arc::new(Mutex::new(0));
    let gateway = gateway_with_state(
        TraceDurabilityState {
            local_latest_sequence: Some(5),
            central_latest_sequence: Some(5),
            last_sync_error: None,
            last_local_buffer_error: None,
        },
        true,
        calls.clone(),
    );

    let outcome = gateway
        .submit(request(SideEffectClass::Network))
        .expect("gateway outcome");

    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(*calls.lock().expect("calls lock"), 1);
}

#[test]
fn policy_can_leave_central_sync_non_blocking() {
    let calls = Arc::new(Mutex::new(0));
    let gateway = gateway_with_state(
        TraceDurabilityState {
            local_latest_sequence: Some(5),
            central_latest_sequence: None,
            last_sync_error: Some("not synced".to_string()),
            last_local_buffer_error: None,
        },
        false,
        calls.clone(),
    );

    let outcome = gateway
        .submit(request(SideEffectClass::External))
        .expect("gateway outcome");

    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(*calls.lock().expect("calls lock"), 1);
}

#[test]
fn side_effectful_action_is_denied_when_local_trace_buffer_is_full() {
    let calls = Arc::new(Mutex::new(0));
    let run_id = RunId::new();
    let buffer = LocalTraceBuffer::new(
        InMemoryTraceStore::default(),
        LocalTraceBufferConfig {
            max_records_per_run: Some(1),
        },
    );
    buffer
        .append(
            &run_id.to_string(),
            serde_json::json!({"run_id": run_id.to_string(), "event": "already-buffered"}),
            TraceBufferAppendMode::ReadOnly,
        )
        .expect("prime buffer");
    let local_error = buffer
        .append(
            &run_id.to_string(),
            serde_json::json!({"run_id": run_id.to_string(), "event": "side-effect-boundary"}),
            TraceBufferAppendMode::SideEffectful,
        )
        .expect_err("side-effect trace durability cannot be preserved");
    let monitor = Arc::new(TraceDurabilityMonitor::new(TraceDurabilityState {
        local_latest_sequence: Some(0),
        central_latest_sequence: Some(0),
        last_sync_error: None,
        last_local_buffer_error: None,
    }));
    monitor.report_local_buffer_error(&local_error);
    let gateway = TraceDurabilityGateway::new(
        Arc::new(CountingGateway {
            calls: calls.clone(),
        }),
        monitor,
        TraceDurabilityPolicy {
            require_central_sync_for_side_effects: true,
        },
    );

    let outcome = gateway
        .submit(request(SideEffectClass::Filesystem))
        .expect("gateway outcome");

    assert_eq!(outcome.status, ActionStatus::Denied);
    assert_eq!(*calls.lock().expect("calls lock"), 0);
    assert_eq!(
        outcome.verification.artifacts["last_local_buffer_error"],
        serde_json::json!(local_error.to_string())
    );
}

#[test]
fn monitor_can_clear_buffer_error_and_allow_side_effect_when_durable() {
    let calls = Arc::new(Mutex::new(0));
    let monitor = TraceDurabilityMonitor::new(TraceDurabilityState {
        local_latest_sequence: Some(5),
        central_latest_sequence: Some(5),
        last_sync_error: None,
        last_local_buffer_error: Some("local trace buffer full".to_string()),
    });
    monitor.clear_errors();
    let gateway = TraceDurabilityGateway::new(
        Arc::new(CountingGateway {
            calls: calls.clone(),
        }),
        Arc::new(monitor),
        TraceDurabilityPolicy {
            require_central_sync_for_side_effects: true,
        },
    );

    let outcome = gateway
        .submit(request(SideEffectClass::Filesystem))
        .expect("gateway outcome");

    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(*calls.lock().expect("calls lock"), 1);
}
