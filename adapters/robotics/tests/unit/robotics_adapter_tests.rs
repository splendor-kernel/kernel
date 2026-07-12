use super::*;
use splendor_gateway::{
    ActionGateway, ActionStatus, SimulatedRiskLevel, SimulatedSafetySnapshot,
    SimulatedSafetyVerifier, VerifiedActionGateway,
};
use splendor_types::{
    Action, ActionId, AgentId, QuotaUsage, RunId, SideEffectClass, TenantId, VerificationResult,
};
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(Clone)]
struct AllowAccess;

impl splendor_gateway::TenantAccess for AllowAccess {
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

fn request(name: &str) -> splendor_gateway::ActionRequest {
    splendor_gateway::ActionRequest {
        action_id: ActionId::new(),
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id: RunId::new(),
        action: Action {
            name: name.to_string(),
            params: serde_json::json!({"physical_action": true, "target_ref": "zone:A"}),
            side_effect_class: SideEffectClass::Custom("physical.high_level".to_string()),
            cost_estimate: None,
            required_permissions: vec![],
            preconditions: vec![],
            postconditions: vec![],
        },
        adapter: Some(ROBOTICS_ADAPTER_ID.to_string()),
        quota_usage: QuotaUsage::single_action(),
        satisfied_preconditions: vec![],
        requested_at: OffsetDateTime::now_utc(),
        approval_evidence: None,
        authority_obligation_evidence: None,
        authority_obligation_receipts: Vec::new(),
    }
}

fn safe_snapshot() -> SimulatedSafetySnapshot {
    SimulatedSafetySnapshot {
        current_zone: Some("zone:A".to_string()),
        allowed_zones: vec!["zone:A".to_string()],
        battery_percent: Some(80.0),
        min_battery_percent: Some(30.0),
        policy_cache_expired: false,
        high_risk: false,
        cloud_helper_direct_authority: false,
        emergency_stop_engaged: Some(false),
        collision_risk: Some(SimulatedRiskLevel::Low),
        altitude_m: Some(10.0),
        max_altitude_m: Some(30.0),
        privacy_zone_active: Some(false),
        proximity_m: Some(5.0),
        min_proximity_m: Some(1.0),
        sensor_refs: vec!["status:safety.latest".to_string()],
    }
}

fn gateway(
    adapter: Arc<SimulatedRoboticsAdapter>,
    snapshot: SimulatedSafetySnapshot,
) -> VerifiedActionGateway {
    let mut gateway = VerifiedActionGateway::new(Arc::new(AllowAccess));
    for action in ALLOWED_PHYSICAL_ACTIONS {
        gateway.register_adapter(*action, ROBOTICS_ADAPTER_ID, adapter.clone());
    }
    gateway.register_adapter("set_motor_pwm", ROBOTICS_ADAPTER_ID, adapter);
    gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(snapshot)));
    gateway
}

#[test]
fn simulated_adapter_outputs_status_evidence_and_postconditions() {
    let adapter = SimulatedRoboticsAdapter::new();
    let result = adapter
        .execute(&request("move_to_waypoint"))
        .expect("adapter output");
    assert_eq!(adapter.call_count(), 1);
    assert_eq!(result.output["status"].as_str(), Some("succeeded"));
    assert!(result.output["evidence"]["command_ref"]
        .as_str()
        .unwrap()
        .starts_with("sim://"));
    assert_eq!(
        result.output["postconditions"]["acknowledged_by"].as_str(),
        Some("simulated_realtime_controller")
    );
    assert_eq!(
        result.satisfied_postconditions,
        vec!["robotics.move_to_waypoint.acknowledged"]
    );
}

#[test]
fn simulated_adapter_rejects_unknown_and_forbidden_actions() {
    let adapter = SimulatedRoboticsAdapter::new();
    assert!(adapter
        .execute(&request("calibrate_unknown_servo"))
        .is_err());
    assert!(adapter.execute(&request("set_motor_pwm")).is_err());
    assert_eq!(adapter.call_count(), 0);
}

#[test]
fn default_adapter_exposes_only_allowed_high_level_actions() {
    let adapter = SimulatedRoboticsAdapter::default();
    assert_eq!(adapter.supported_actions(), ALLOWED_PHYSICAL_ACTIONS);
    assert!(adapter
        .supported_actions()
        .iter()
        .all(|action| is_allowed_physical_action(action)));
}

#[test]
fn gateway_executes_allowed_action_after_safety_allow() {
    let adapter = Arc::new(SimulatedRoboticsAdapter::new());
    let gateway = gateway(adapter.clone(), safe_snapshot());
    let outcome = gateway
        .submit(request("move_to_waypoint"))
        .expect("outcome");
    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(adapter.call_count(), 1);
    assert_eq!(
        outcome.output.unwrap()["status"].as_str(),
        Some("succeeded")
    );
    assert!(outcome.verification.artifacts["safety"].is_object());
}

#[test]
fn gateway_rejects_forbidden_action_before_adapter_execution() {
    let adapter = Arc::new(SimulatedRoboticsAdapter::new());
    let gateway = gateway(adapter.clone(), safe_snapshot());
    let outcome = gateway.submit(request("set_motor_pwm")).expect("outcome");
    assert_eq!(outcome.status, ActionStatus::Denied);
    assert_eq!(adapter.call_count(), 0);
    assert_eq!(outcome.error.as_deref(), Some("forbidden_physical_action"));
}

#[test]
fn safety_denial_prevents_adapter_execution() {
    let adapter = Arc::new(SimulatedRoboticsAdapter::new());
    let mut unsafe_snapshot = safe_snapshot();
    unsafe_snapshot.emergency_stop_engaged = Some(true);
    let gateway = gateway(adapter.clone(), unsafe_snapshot);
    let outcome = gateway.submit(request("inspect_zone")).expect("outcome");
    assert_eq!(outcome.status, ActionStatus::Denied);
    assert_eq!(adapter.call_count(), 0);
    assert_eq!(outcome.error.as_deref(), Some("emergency_stop_engaged"));
}

#[test]
fn adapter_failure_returns_traceable_failed_outcome() {
    let adapter = Arc::new(SimulatedRoboticsAdapter::new().with_fail_actions(["dock"]));
    let gateway = gateway(adapter.clone(), safe_snapshot());
    let outcome = gateway.submit(request("dock")).expect("outcome");
    assert_eq!(outcome.status, ActionStatus::Failed);
    assert_eq!(adapter.call_count(), 1);
    assert!(outcome
        .error
        .unwrap()
        .contains("simulated robotics middleware failure"));
    assert!(outcome.verification.artifacts["safety"].is_object());
}

#[test]
fn request_operator_override_is_output_not_approval_bypass() {
    let adapter = Arc::new(SimulatedRoboticsAdapter::new());
    let gateway = gateway(adapter.clone(), safe_snapshot());
    let outcome = gateway
        .submit(request("request_operator_override"))
        .expect("outcome");
    assert_eq!(outcome.status, ActionStatus::Executed);
    let output = outcome.output.unwrap();
    assert_eq!(
        output["status"].as_str(),
        Some("operator_override_requested")
    );
    assert_eq!(
        output["postconditions"]["acknowledged_by"].as_str(),
        Some("simulated_realtime_controller")
    );
    assert_eq!(adapter.call_count(), 1);
}
