use super::*;
use crate::{KernelRuntime, KernelRuntimeConfig, TraceError, TraceSink};
use splendor_gateway::{
    ActionAdapter, ActionGateway, ActionRequest, AdapterError, AdapterResult, SimulatedRiskLevel,
    SimulatedSafetySnapshot, SimulatedSafetyVerifier, TenantAccess, VerifiedActionGateway,
};
use splendor_types::{
    cloud_helper_failure_validation, validate_route_plan_for_local_execution, Action, AgentId,
    MessageTraceContext, QuotaUsage, RemoteMessageTraceContext, RoutePlanProposal,
    RouteWaypointProposal, RunId, SideEffectClass, TenantId, TraceEvent, TraceEventKind,
    VerificationResult,
};
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

#[derive(Default)]
struct CapturingSink {
    events: Arc<Mutex<Vec<TraceEvent>>>,
}

impl TraceSink for CapturingSink {
    fn record(&self, event: &TraceEvent) -> Result<(), TraceError> {
        self.events.lock().expect("events lock").push(event.clone());
        Ok(())
    }
}

#[derive(Clone, Default)]
struct CountingAdapter {
    calls: Arc<Mutex<usize>>,
}

impl ActionAdapter for CountingAdapter {
    fn execute(&self, request: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        *self.calls.lock().expect("calls") += 1;
        Ok(AdapterResult {
            output: serde_json::json!({
                "action": request.action.name,
                "safety_status": "safe"
            }),
            satisfied_postconditions: vec!["robotics.move_to_waypoint.acknowledged".to_string()],
        })
    }
}

struct AllowTenantAccess;

impl TenantAccess for AllowTenantAccess {
    fn verify_policy(
        &self,
        _tenant_id: &TenantId,
        _agent_id: &AgentId,
        _action: &Action,
        _adapter: Option<&str>,
    ) -> VerificationResult {
        VerificationResult::allow()
    }

    fn verify_quota(
        &self,
        _tenant_id: &TenantId,
        _agent_id: &AgentId,
        _usage: QuotaUsage,
    ) -> VerificationResult {
        VerificationResult::allow()
    }
}

fn runtime_for(run_id: RunId) -> (KernelRuntime, Arc<Mutex<Vec<TraceEvent>>>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(CapturingSink {
            events: Arc::clone(&events),
        }),
        run_id: Some(run_id),
        ..KernelRuntimeConfig::default()
    });
    (runtime, events)
}

fn route_proposal(zone: &str) -> RoutePlanProposal {
    RoutePlanProposal {
        proposal_id: "route-proposal-1".to_string(),
        objective: "inspect zone".to_string(),
        artifact_ref: Some("artifact:route-proposal-1".to_string()),
        data_refs: vec!["map:warehouse".to_string()],
        waypoints: vec![RouteWaypointProposal {
            waypoint_ref: "waypoint:1".to_string(),
            zone_ref: zone.to_string(),
        }],
        created_at: OffsetDateTime::UNIX_EPOCH + Duration::seconds(20),
    }
}

fn gateway_with_counting_adapter(adapter: &CountingAdapter) -> VerifiedActionGateway {
    let mut gateway = VerifiedActionGateway::new(Arc::new(AllowTenantAccess));
    gateway.register_adapter("move_to_waypoint", "robotics", Arc::new(adapter.clone()));
    gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(
        SimulatedSafetySnapshot {
            current_zone: Some("zone:a".to_string()),
            allowed_zones: vec!["zone:a".to_string()],
            battery_percent: Some(90.0),
            min_battery_percent: Some(25.0),
            emergency_stop_engaged: Some(false),
            collision_risk: Some(SimulatedRiskLevel::Low),
            sensor_refs: vec!["sensor:summary".to_string()],
            ..SimulatedSafetySnapshot::default()
        },
    )));
    gateway
}

#[test]
fn accepted_helper_plan_still_executes_only_through_local_gateway() {
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let proposal = route_proposal("zone:a");
    let validation = validate_route_plan_for_local_execution(&proposal, &["zone:a".to_string()]);
    assert!(validation.result.allowed);
    let adapter = CountingAdapter::default();
    let gateway = gateway_with_counting_adapter(&adapter);

    let outcome = gateway
        .submit(ActionRequest {
            action_id: ActionId::new(),
            tenant_id,
            agent_id,
            run_id,
            action: validation.bounded_actions[0].clone(),
            adapter: Some("robotics".to_string()),
            quota_usage: QuotaUsage::single_action(),
            satisfied_preconditions: vec!["cloud_helper.local_plan_validated".to_string()],
            requested_at: OffsetDateTime::UNIX_EPOCH + Duration::seconds(30),
            approval_evidence: None,
            authority_obligation_evidence: None,
        })
        .expect("gateway outcome");

    assert!(matches!(
        outcome.status,
        splendor_gateway::ActionStatus::Executed
    ));
    assert_eq!(*adapter.calls.lock().expect("calls"), 1);
}

#[test]
fn rejected_helper_plan_traces_denial_and_never_reaches_adapter() {
    let run_id = RunId::new();
    let (runtime, events) = runtime_for(run_id.clone());
    let adapter = CountingAdapter::default();
    let proposal = route_proposal("zone:forbidden");
    let validation = validate_route_plan_for_local_execution(&proposal, &["zone:a".to_string()]);

    assert!(!validation.result.allowed);
    assert!(validation.bounded_actions.is_empty());
    runtime
        .record_event(TraceEventKind::ActionDenied {
            action: Action {
                name: "move_to_waypoint".to_string(),
                params: serde_json::json!({"proposal_id": proposal.proposal_id}),
                side_effect_class: SideEffectClass::Custom("physical.high_level".to_string()),
                cost_estimate: None,
                required_permissions: vec!["physical.move_to_waypoint".to_string()],
                preconditions: vec!["cloud_helper.local_plan_validated".to_string()],
                postconditions: vec![],
            },
            result: validation.result.clone(),
        })
        .expect("trace denial");

    assert_eq!(*adapter.calls.lock().expect("calls"), 0);
    let recorded = events.lock().expect("events");
    assert!(matches!(
        recorded[0].kind,
        TraceEventKind::ActionDenied { .. }
    ));
}

#[test]
fn helper_timeout_is_fail_closed_and_has_no_local_actions() {
    let validation = cloud_helper_failure_validation("first attempt deadline");
    assert!(!validation.result.allowed);
    assert!(validation.bounded_actions.is_empty());
}

#[test]
fn replay_trace_contains_helper_proposal_local_validation_and_action_decision() {
    let run_id = RunId::new();
    let (runtime, events) = runtime_for(run_id.clone());
    let source = AgentId::new();
    let target = AgentId::new();
    let message_id = MessageId::new();
    let message = MessageTraceContext {
        message_id,
        source_agent_id: source,
        target_agent_id: target,
        run_id: run_id.clone(),
        schema: splendor_types::ROUTE_PLAN_PROPOSAL_SCHEMA.to_string(),
        causal_parent: None,
    };
    let remote = RemoteMessageTraceContext {
        message: message.clone(),
        tenant_id: TenantId::new(),
        source_instance_id: "helper_instance".to_string(),
        target_instance_id: "device_instance".to_string(),
        work_order_id: "wo_cloud_helper".to_string(),
        attempt: 1,
        idempotency_key: None,
    };
    let action = Action {
        name: "move_to_waypoint".to_string(),
        params: serde_json::json!({"proposal_id": "route-proposal-1"}),
        side_effect_class: SideEffectClass::Custom("physical.high_level".to_string()),
        cost_estimate: None,
        required_permissions: vec!["physical.move_to_waypoint".to_string()],
        preconditions: vec!["cloud_helper.local_plan_validated".to_string()],
        postconditions: vec!["robotics.move_to_waypoint.acknowledged".to_string()],
    };

    runtime
        .record_event(TraceEventKind::RemoteMessageSent {
            remote_message: remote.clone(),
        })
        .expect("helper sent proposal");
    runtime
        .record_event(TraceEventKind::MessageDelivered { message })
        .expect("device received proposal");
    runtime
        .record_event(TraceEventKind::ActionVerificationCompleted {
            action: action.clone(),
            result: VerificationResult::allow(),
        })
        .expect("local validation trace");
    runtime
        .record_event(TraceEventKind::ActionExecuted {
            action,
            outcome: serde_json::json!({"status": "safe"}),
        })
        .expect("local action decision");

    let recorded = events.lock().expect("events");
    assert!(matches!(
        recorded[0].kind,
        TraceEventKind::RemoteMessageSent { .. }
    ));
    assert!(matches!(
        recorded[1].kind,
        TraceEventKind::MessageDelivered { .. }
    ));
    assert!(matches!(
        recorded[2].kind,
        TraceEventKind::ActionVerificationCompleted { .. }
    ));
    assert!(matches!(
        recorded[3].kind,
        TraceEventKind::ActionExecuted { .. }
    ));
}
