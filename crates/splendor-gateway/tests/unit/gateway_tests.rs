use super::*;
use splendor_types::{
    AgentId, ApprovalDecision, ApprovalEvidence, ApprovalId, ApprovalPolicy, CircuitBreaker,
    CircuitBreakerId, CircuitBreakerScope, EffectCertainty, ErrorCategory, FleetId, InstanceId,
    NodeId, QuotaUsage, RetryClass, RunId, RuntimeIdentityContext, SideEffectClass, TenantId,
    APPROVAL_EVIDENCE_SCHEMA_VERSION, APPROVAL_POLICY_SCHEMA_VERSION,
    UNKNOWN_ADAPTER_FAILURE_REASON,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use super::combine_verifications;
use super::InvariantEvaluator;

fn block_on<F: Future>(mut future: F) -> F::Output {
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut context = Context::from_waker(&waker);
    let mut future = unsafe { Pin::new_unchecked(&mut future) };
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => {}
        }
    }
}

fn raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        raw_waker()
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(std::ptr::null(), &VTABLE)
}

fn sample_action() -> ActionRequest {
    ActionRequest {
        action_id: ActionId::default(),
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id: RunId::new(),
        action: Action {
            name: "noop".to_string(),
            params: serde_json::json!({"ok": true}),
            side_effect_class: SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: vec!["test".to_string()],
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        },
        adapter: None,
        quota_usage: QuotaUsage::single_action(),
        satisfied_preconditions: Vec::new(),
        requested_at: OffsetDateTime::now_utc(),
        approval_evidence: None,
    }
}

#[test]
fn unimplemented_gateway_denies_sync_and_async() {
    let gateway = UnimplementedGateway;
    let result = ActionGateway::submit(&gateway, sample_action());
    assert!(matches!(result, Err(GatewayError::Unimplemented)));

    let async_result = block_on(AsyncActionGateway::submit(&gateway, sample_action()));
    assert!(matches!(async_result, Err(GatewayError::Unimplemented)));
}

#[test]
fn gateway_error_strings_include_details() {
    let verification = GatewayError::VerificationFailed("quota".to_string());
    let adapter = GatewayError::AdapterFailed("timeout".to_string());
    assert!(verification.to_string().contains("quota"));
    assert!(adapter.to_string().contains("timeout"));
}

#[test]
fn gateway_errors_map_to_exact_taxonomy_semantics() {
    let unimplemented = GatewayError::Unimplemented.taxonomy();
    assert_eq!(unimplemented.category, ErrorCategory::Unavailable);
    assert_eq!(unimplemented.reason_code.as_str(), "gateway_unimplemented");
    assert_eq!(unimplemented.retry_class, RetryClass::NotRetryable);
    assert_eq!(unimplemented.effect_certainty, EffectCertainty::None);

    let verification = GatewayError::VerificationFailed("quota".to_string()).taxonomy();
    assert_eq!(verification.category, ErrorCategory::Unauthorized);
    assert_eq!(
        verification.reason_code.as_str(),
        "gateway_verification_failed"
    );
    assert_eq!(
        verification.retry_class,
        RetryClass::RetryWithNewAuthorization
    );
    assert_eq!(verification.effect_certainty, EffectCertainty::None);

    let adapter = GatewayError::AdapterFailed("provider timeout".to_string()).taxonomy();
    assert_eq!(adapter.category, ErrorCategory::DriverFailure);
    assert_eq!(adapter.reason_code.as_str(), UNKNOWN_ADAPTER_FAILURE_REASON);
    assert_eq!(adapter.retry_class, RetryClass::NotRetryable);
    assert_eq!(adapter.effect_certainty, EffectCertainty::Uncertain);
    assert_eq!(
        adapter
            .provider_detail
            .as_ref()
            .map(splendor_types::ProviderDetail::provider),
        Some("gateway_adapter")
    );
}

#[test]
fn adapter_error_unknown_failures_are_uncertain_and_non_retryable() {
    let taxonomy = AdapterError::Failed(
        "provider returned HTTP 500 with Authorization: Bearer secret".to_string(),
    )
    .taxonomy_for_adapter("custom/provider");

    assert_eq!(taxonomy.category, ErrorCategory::DriverFailure);
    assert_eq!(
        taxonomy.reason_code.as_str(),
        UNKNOWN_ADAPTER_FAILURE_REASON
    );
    assert_eq!(taxonomy.retry_class, RetryClass::NotRetryable);
    assert_eq!(taxonomy.effect_certainty, EffectCertainty::Uncertain);
    let detail = taxonomy.provider_detail.as_ref().expect("provider detail");
    assert_eq!(detail.provider(), "custom_provider");
    assert_eq!(detail.safe_summary(), Some("[redacted]"));
}

#[derive(Clone)]
struct TestTenantAccess {
    policy: VerificationResult,
    quota: VerificationResult,
}

#[derive(Clone)]
struct AgentScopedAccess {
    allowed_agent: AgentId,
}

impl TenantAccess for AgentScopedAccess {
    fn verify_policy(
        &self,
        _tenant_id: &TenantId,
        agent_id: &AgentId,
        _action: &Action,
        _adapter: Option<&str>,
    ) -> VerificationResult {
        if agent_id == &self.allowed_agent {
            VerificationResult::allow()
        } else {
            VerificationResult {
                allowed: false,
                reasons: vec!["agent_permission_denied".to_string()],
                artifacts: serde_json::json!({
                    "source": "agent_isolation_ledger",
                    "agent_id": agent_id.to_string(),
                }),
            }
        }
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

#[derive(Clone)]
struct CountingQuotaAccess {
    quota_calls: Arc<AtomicUsize>,
}

impl TenantAccess for CountingQuotaAccess {
    fn verify_policy(
        &self,
        _tenant_id: &TenantId,
        _agent_id: &AgentId,
        _action: &Action,
        _adapter: Option<&str>,
    ) -> VerificationResult {
        VerificationResult::deny("policy")
    }

    fn verify_quota(
        &self,
        _tenant_id: &TenantId,
        _agent_id: &AgentId,
        _usage: QuotaUsage,
    ) -> VerificationResult {
        self.quota_calls.fetch_add(1, Ordering::SeqCst);
        VerificationResult::allow()
    }
}

impl TenantAccess for TestTenantAccess {
    fn verify_policy(
        &self,
        _tenant_id: &TenantId,
        _agent_id: &AgentId,
        _action: &Action,
        _adapter: Option<&str>,
    ) -> VerificationResult {
        self.policy.clone()
    }

    fn verify_quota(
        &self,
        _tenant_id: &TenantId,
        _agent_id: &AgentId,
        _usage: QuotaUsage,
    ) -> VerificationResult {
        self.quota.clone()
    }
}

#[derive(Default)]
struct CountingAdapter {
    calls: std::sync::Mutex<u32>,
    satisfied: Vec<String>,
}

struct DenyResourceVerifier;

impl ResourceBoundaryVerifier for DenyResourceVerifier {
    fn verify_resource_boundary(
        &self,
        _action: &ActionRequest,
        _adapter: Option<&str>,
    ) -> VerificationResult {
        VerificationResult {
            allowed: false,
            reasons: vec!["resource_scope_denied".to_string()],
            artifacts: serde_json::json!({
                "source": "test_resource_verifier",
                "adapter_execution": "not_attempted",
            }),
        }
    }
}

impl ActionAdapter for CountingAdapter {
    fn execute(&self, _action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        *self.calls.lock().expect("calls lock") += 1;
        Ok(AdapterResult {
            output: serde_json::json!({"ok": true}),
            satisfied_postconditions: self.satisfied.clone(),
        })
    }
}

fn base_request() -> ActionRequest {
    ActionRequest {
        action_id: ActionId::default(),
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id: RunId::new(),
        action: Action {
            name: "noop".to_string(),
            params: serde_json::json!({"ok": true}),
            side_effect_class: SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: vec![],
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        },
        adapter: None,
        quota_usage: QuotaUsage::single_action(),
        satisfied_preconditions: Vec::new(),
        requested_at: OffsetDateTime::now_utc(),
        approval_evidence: None,
    }
}

#[test]
fn resource_boundary_denial_prevents_adapter_execution() {
    let adapter = Arc::new(CountingAdapter::default());
    let mut gateway = VerifiedActionGateway::new(Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    }));
    gateway.register_adapter("noop", "test", adapter.clone());
    gateway.set_resource_boundary_verifier(Arc::new(DenyResourceVerifier));

    let mut request = base_request();
    request.adapter = Some("test".to_string());
    let outcome = gateway.submit(request).expect("outcome");

    assert_eq!(outcome.status, ActionStatus::Denied);
    assert!(outcome
        .verification
        .reasons
        .contains(&"resource_scope_denied".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

fn physical_request() -> ActionRequest {
    let mut request = base_request();
    request.action.name = "move_to_waypoint".to_string();
    request.action.side_effect_class = SideEffectClass::Custom("physical.high_level".to_string());
    request.action.params = serde_json::json!({
        "waypoint_ref": "waypoint:A3",
        "physical_action": true,
    });
    request
}

fn safe_safety_snapshot() -> SimulatedSafetySnapshot {
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
        sensor_refs: vec![
            "status:battery.latest".to_string(),
            "status:estop.latest".to_string(),
            "status:collision.summary".to_string(),
        ],
    }
}

fn approval_policy_for(request: &ActionRequest) -> ApprovalPolicy {
    let mut policy = ApprovalPolicy::new(
        "approval_policy_test",
        request.tenant_id.clone(),
        "high risk action requires approval",
    );
    policy.agent_id = Some(request.agent_id.clone());
    policy.action_name = Some(request.action.name.clone());
    policy.adapter = Some("adapter".to_string());
    policy.side_effect_class = Some(request.action.side_effect_class.clone());
    policy.risk_level = Some("high".to_string());
    policy
}

fn approval_evidence_for(request: &ActionRequest) -> ApprovalEvidence {
    ApprovalEvidence::new(
        ApprovalId::new(),
        request.tenant_id.clone(),
        request.agent_id.clone(),
        request.run_id.clone(),
        ApprovalDecision::Granted,
        OffsetDateTime::now_utc() + time::Duration::hours(1),
    )
    .with_action_name(request.action.name.clone())
    .with_adapter("adapter")
}

fn approval_gateway(
    request: &ActionRequest,
    adapter: Arc<CountingAdapter>,
) -> VerifiedActionGateway {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    gateway.register_adapter("noop", "adapter", adapter);
    gateway.set_approval_verifier(Arc::new(PolicyApprovalVerifier::new(vec![
        approval_policy_for(request),
    ])));
    gateway
}

#[test]
fn verified_gateway_denies_on_policy_failure() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::deny("policy"),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());

    let outcome = gateway.submit(base_request()).expect("outcome");
    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(!outcome.verification.allowed);
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn verified_gateway_does_not_consume_quota_when_policy_denies() {
    let quota_calls = Arc::new(AtomicUsize::new(0));
    let tenant_access = Arc::new(CountingQuotaAccess {
        quota_calls: Arc::clone(&quota_calls),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());

    let outcome = gateway.submit(base_request()).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert_eq!(quota_calls.load(Ordering::SeqCst), 0);
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn verified_gateway_passes_agent_id_to_policy_and_denies_laundering() {
    let allowed_agent = AgentId::new();
    let denied_agent = AgentId::new();
    let tenant_access = Arc::new(AgentScopedAccess {
        allowed_agent: allowed_agent.clone(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());

    let mut request = base_request();
    request.agent_id = denied_agent.clone();
    request.action.required_permissions = vec!["agent:allowed".to_string()];
    let outcome = gateway.submit(request).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(outcome
        .verification
        .reasons
        .contains(&"agent_permission_denied".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    assert_eq!(
        outcome.verification.artifacts["policy"]["agent_id"].as_str(),
        Some(denied_agent.to_string().as_str())
    );

    let mut allowed_request = base_request();
    allowed_request.agent_id = allowed_agent;
    let allowed = gateway.submit(allowed_request).expect("allowed outcome");
    assert!(matches!(allowed.status, ActionStatus::Executed));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 1);
}

#[test]
fn verified_gateway_denies_on_quota_failure() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::deny("quota"),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());

    let outcome = gateway.submit(base_request()).expect("outcome");
    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(outcome.verification.reasons.contains(&"quota".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn verified_gateway_denies_on_precondition_failure() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());

    let mut request = base_request();
    request.action.preconditions = vec!["ready".to_string()];
    request.satisfied_preconditions = Vec::new();

    let outcome = gateway.submit(request).expect("outcome");
    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(!outcome.verification.allowed);
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn verified_gateway_denies_adapter_mismatch() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());

    let mut request = base_request();
    request.adapter = Some("different".to_string());

    let outcome = gateway.submit(request).expect("outcome");
    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(outcome
        .verification
        .reasons
        .contains(&"adapter_mismatch".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn verified_gateway_denies_invalid_identity_before_adapter_execution() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());

    let mut request = base_request();
    request.run_id = RunId::from(uuid::Uuid::nil());

    let outcome = gateway.submit(request).expect("outcome");
    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(outcome
        .verification
        .reasons
        .contains(&"identity_invalid".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn verified_gateway_reports_postcondition_failure() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter {
        satisfied: Vec::new(),
        ..CountingAdapter::default()
    });
    gateway.register_adapter("noop", "adapter", adapter);

    let mut request = base_request();
    request.action.postconditions = vec!["done".to_string()];

    let outcome = gateway.submit(request).expect("outcome");
    assert!(matches!(outcome.status, ActionStatus::Failed));
    assert!(outcome.post_verification.is_some());
    assert!(!outcome.post_verification.expect("post").allowed);
}

#[test]
fn safety_geofence_denial_prevents_adapter_execution() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("move_to_waypoint", "robotics", adapter.clone());
    let mut snapshot = safe_safety_snapshot();
    snapshot.current_zone = Some("zone:restricted".to_string());
    gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(snapshot)));

    let outcome = gateway.submit(physical_request()).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(outcome
        .verification
        .reasons
        .contains(&"geofence_violation".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    assert_eq!(
        outcome.verification.artifacts["evidence"]["zone_refs"][0].as_str(),
        Some("zone:restricted")
    );
}

#[test]
fn safety_low_battery_intervention_prevents_adapter_execution_with_trace_safe_evidence() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("move_to_waypoint", "robotics", adapter.clone());
    let mut snapshot = safe_safety_snapshot();
    snapshot.battery_percent = Some(12.0);
    gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(snapshot)));

    let outcome = gateway.submit(physical_request()).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::NeedsIntervention));
    assert!(outcome
        .verification
        .reasons
        .contains(&"battery_below_minimum".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    assert_eq!(
        outcome.verification.artifacts["evidence"]["thresholds"][0]["name"].as_str(),
        Some("min_battery_percent")
    );
    assert!(outcome
        .verification
        .artifacts
        .to_string()
        .contains("status:battery.latest"));
    assert!(!outcome.verification.artifacts.to_string().contains("raw"));
}

#[test]
fn safety_s6_policy_cache_and_cloud_helper_denials_prevent_adapter_execution() {
    for (snapshot, reason) in [
        {
            let mut snapshot = safe_safety_snapshot();
            snapshot.policy_cache_expired = true;
            snapshot.high_risk = true;
            (snapshot, "policy_cache_expired")
        },
        {
            let mut snapshot = safe_safety_snapshot();
            snapshot.cloud_helper_direct_authority = true;
            (snapshot, "cloud_helper_direct_authority_denied")
        },
    ] {
        let tenant_access = Arc::new(TestTenantAccess {
            policy: VerificationResult::allow(),
            quota: VerificationResult::allow(),
        });
        let mut gateway = VerifiedActionGateway::new(tenant_access);
        let adapter = Arc::new(CountingAdapter::default());
        gateway.register_adapter("move_to_waypoint", "robotics", adapter.clone());
        gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(snapshot)));

        let outcome = gateway.submit(physical_request()).expect("outcome");

        assert_eq!(outcome.status, ActionStatus::Denied);
        assert!(outcome.verification.reasons.contains(&reason.to_string()));
        assert_eq!(
            outcome.verification.artifacts["source"].as_str(),
            Some("safety_verifier")
        );
        assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    }
}

#[test]
fn safety_emergency_stop_denial_prevents_adapter_execution() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("move_to_waypoint", "robotics", adapter.clone());
    let mut snapshot = safe_safety_snapshot();
    snapshot.emergency_stop_engaged = Some(true);
    gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(snapshot)));

    let outcome = gateway.submit(physical_request()).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(outcome
        .verification
        .reasons
        .contains(&"emergency_stop_engaged".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn safety_collision_risk_denial_prevents_adapter_execution() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("move_to_waypoint", "robotics", adapter.clone());
    let mut snapshot = safe_safety_snapshot();
    snapshot.collision_risk = Some(SimulatedRiskLevel::High);
    gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(snapshot)));

    let outcome = gateway.submit(physical_request()).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(outcome
        .verification
        .reasons
        .contains(&"collision_risk_high".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn safety_uncertainty_needs_intervention_without_adapter_execution() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("move_to_waypoint", "robotics", adapter.clone());
    let mut snapshot = safe_safety_snapshot();
    snapshot.collision_risk = Some(SimulatedRiskLevel::Unknown);
    gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(snapshot)));

    let outcome = gateway.submit(physical_request()).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::NeedsIntervention));
    assert!(outcome
        .verification
        .reasons
        .contains(&"verifier_uncertainty".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn safety_remaining_denial_branches_prevent_adapter_execution() {
    for (snapshot, reason, threshold_name) in [
        {
            let mut snapshot = safe_safety_snapshot();
            snapshot.altitude_m = Some(40.0);
            (snapshot, "altitude_limit_exceeded", Some("max_altitude_m"))
        },
        {
            let mut snapshot = safe_safety_snapshot();
            snapshot.privacy_zone_active = Some(true);
            (snapshot, "privacy_zone_active", None)
        },
        {
            let mut snapshot = safe_safety_snapshot();
            snapshot.proximity_m = Some(0.5);
            (snapshot, "proximity_below_minimum", Some("min_proximity_m"))
        },
    ] {
        let tenant_access = Arc::new(TestTenantAccess {
            policy: VerificationResult::allow(),
            quota: VerificationResult::allow(),
        });
        let mut gateway = VerifiedActionGateway::new(tenant_access);
        let adapter = Arc::new(CountingAdapter::default());
        gateway.register_adapter("move_to_waypoint", "robotics", adapter.clone());
        gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(snapshot)));

        let outcome = gateway.submit(physical_request()).expect("outcome");

        assert_eq!(outcome.status, ActionStatus::Denied);
        assert!(outcome.verification.reasons.contains(&reason.to_string()));
        if let Some(threshold_name) = threshold_name {
            assert_eq!(
                outcome.verification.artifacts["evidence"]["thresholds"][0]["name"].as_str(),
                Some(threshold_name)
            );
        }
        assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    }
}

#[test]
fn safety_uncertain_battery_and_geofence_fail_closed_before_adapter_execution() {
    for (snapshot, check_name, zone_count) in [
        {
            let mut snapshot = safe_safety_snapshot();
            snapshot.battery_percent = None;
            (snapshot, "battery", 0)
        },
        {
            let mut snapshot = safe_safety_snapshot();
            snapshot.current_zone = None;
            (snapshot, "geofence", 1)
        },
        {
            let mut snapshot = safe_safety_snapshot();
            snapshot.emergency_stop_engaged = None;
            (snapshot, "emergency_stop", 0)
        },
    ] {
        let tenant_access = Arc::new(TestTenantAccess {
            policy: VerificationResult::allow(),
            quota: VerificationResult::allow(),
        });
        let mut gateway = VerifiedActionGateway::new(tenant_access);
        let adapter = Arc::new(CountingAdapter::default());
        gateway.register_adapter("move_to_waypoint", "robotics", adapter.clone());
        gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(snapshot)));

        let outcome = gateway.submit(physical_request()).expect("outcome");

        assert_eq!(outcome.status, ActionStatus::NeedsIntervention);
        assert!(outcome
            .verification
            .reasons
            .contains(&"verifier_uncertainty".to_string()));
        assert_eq!(
            outcome.verification.artifacts["evidence"]["check"].as_str(),
            Some(check_name)
        );
        assert_eq!(
            outcome.verification.artifacts["evidence"]["zone_refs"]
                .as_array()
                .map(Vec::len)
                .unwrap_or_default(),
            zone_count
        );
        assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    }
}

#[test]
fn unknown_high_level_physical_action_is_denied_before_adapter_lookup() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let gateway = VerifiedActionGateway::new(tenant_access);
    let mut request = physical_request();
    request.action.name = "spin_in_place".to_string();

    let outcome = gateway.submit(request).expect("outcome");

    assert_eq!(outcome.status, ActionStatus::Denied);
    assert!(outcome
        .verification
        .reasons
        .contains(&"unknown_physical_action".to_string()));
    assert_eq!(
        outcome.verification.artifacts["matched_policy"].as_str(),
        Some("high_level_physical_actions_only")
    );
}

#[test]
fn missing_required_safety_verifier_fails_closed_without_adapter_execution() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("move_to_waypoint", "robotics", adapter.clone());

    let outcome = gateway.submit(physical_request()).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::NeedsIntervention));
    assert!(outcome
        .verification
        .reasons
        .contains(&"safety_verifier_missing".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn safety_postcondition_failure_marks_physical_outcome_failed() {
    struct UnsafeAdapter;

    impl ActionAdapter for UnsafeAdapter {
        fn execute(&self, _action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
            Ok(AdapterResult {
                output: serde_json::json!({"safety_status": "unsafe", "summary_ref": "status:mission.latest"}),
                satisfied_postconditions: Vec::new(),
            })
        }
    }

    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    gateway.register_adapter("move_to_waypoint", "robotics", Arc::new(UnsafeAdapter));
    gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(
        safe_safety_snapshot(),
    )));

    let outcome = gateway.submit(physical_request()).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::Failed));
    let post = outcome.post_verification.expect("post verification");
    assert!(!post.allowed);
    assert!(post
        .reasons
        .contains(&"safety_postcondition_failed".to_string()));
}

#[test]
fn verified_gateway_executes_when_checks_pass() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());

    let outcome = gateway.submit(base_request()).expect("outcome");
    assert!(matches!(outcome.status, ActionStatus::Executed));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 1);
    assert!(outcome.output.is_some());
}

#[test]
fn approval_required_action_pauses_without_adapter_execution() {
    let request = base_request();
    let adapter = Arc::new(CountingAdapter::default());
    let gateway = approval_gateway(&request, adapter.clone());

    let outcome = gateway.submit(request).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::NeedsApproval));
    assert!(!outcome.verification.allowed);
    assert!(outcome
        .verification
        .reasons
        .contains(&"approval_required".to_string()));
    assert_eq!(
        outcome.verification.artifacts["approval_status"].as_str(),
        Some("required")
    );
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn valid_scoped_approval_grant_allows_execution() {
    let mut request = base_request();
    let adapter = Arc::new(CountingAdapter::default());
    let gateway = approval_gateway(&request, adapter.clone());
    request.approval_evidence = Some(approval_evidence_for(&request));

    let outcome = gateway.submit(request).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::Executed));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 1);
    assert_eq!(
        outcome.verification.artifacts["approval"]["approval_status"].as_str(),
        Some("granted")
    );
}

#[test]
fn approval_policy_expiry_needs_intervention_without_adapter_execution() {
    let request = base_request();
    let mut policy = approval_policy_for(&request);
    policy.expires_at = Some(OffsetDateTime::now_utc() - time::Duration::minutes(1));
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());
    gateway.set_approval_verifier(Arc::new(PolicyApprovalVerifier::new(vec![policy])));

    let outcome = gateway.submit(request).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::NeedsIntervention));
    assert!(outcome
        .verification
        .reasons
        .contains(&"approval_policy_expired".to_string()));
    assert_eq!(
        outcome.verification.artifacts["approval_status"].as_str(),
        Some("intervention_required")
    );
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn approval_policy_permission_and_side_effect_triggers_require_approval() {
    for trigger in ["permission", "side_effect"] {
        let mut request = base_request();
        request.action.required_permissions = vec!["artifact.publish".to_string()];
        request.action.side_effect_class = SideEffectClass::External;
        let mut policy = ApprovalPolicy::new(
            format!("approval_policy_{trigger}"),
            request.tenant_id.clone(),
            format!("{trigger} requires approval"),
        );
        policy.agent_id = Some(request.agent_id.clone());
        if trigger == "permission" {
            policy.required_permission = Some("artifact.publish".to_string());
        } else {
            policy.side_effect_class = Some(SideEffectClass::External);
        }

        let tenant_access = Arc::new(TestTenantAccess {
            policy: VerificationResult::allow(),
            quota: VerificationResult::allow(),
        });
        let mut gateway = VerifiedActionGateway::new(tenant_access);
        let adapter = Arc::new(CountingAdapter::default());
        gateway.register_adapter("noop", "adapter", adapter.clone());
        gateway.set_approval_verifier(Arc::new(PolicyApprovalVerifier::new(vec![policy])));

        let outcome = gateway.submit(request).expect("outcome");

        assert!(matches!(outcome.status, ActionStatus::NeedsApproval));
        assert!(outcome
            .verification
            .reasons
            .contains(&"approval_required".to_string()));
        assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    }
}

#[test]
fn approval_wrong_scope_is_denied_without_adapter_execution() {
    for mut evidence in [
        {
            let request = base_request();
            let mut evidence = approval_evidence_for(&request);
            evidence.tenant_id = TenantId::new();
            evidence
        },
        {
            let request = base_request();
            let mut evidence = approval_evidence_for(&request);
            evidence.agent_id = AgentId::new();
            evidence
        },
        {
            let request = base_request();
            let mut evidence = approval_evidence_for(&request);
            evidence.action_name = Some("different".to_string());
            evidence
        },
        {
            let request = base_request();
            let mut evidence = approval_evidence_for(&request);
            evidence.adapter = Some("different".to_string());
            evidence
        },
    ] {
        let mut request = base_request();
        evidence.run_id = request.run_id.clone();
        let adapter = Arc::new(CountingAdapter::default());
        let gateway = approval_gateway(&request, adapter.clone());
        request.approval_evidence = Some(evidence);

        let outcome = gateway.submit(request).expect("outcome");

        assert!(matches!(outcome.status, ActionStatus::Denied));
        assert!(outcome
            .verification
            .reasons
            .contains(&"approval_scope_mismatch".to_string()));
        assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    }
}

#[test]
fn approval_run_and_action_id_scope_mismatches_are_denied_without_adapter_execution() {
    for (mut evidence, mismatch) in [
        {
            let request = base_request();
            let mut evidence = approval_evidence_for(&request);
            evidence.run_id = RunId::new();
            (evidence, "run_id")
        },
        {
            let request = base_request();
            let mut evidence = approval_evidence_for(&request);
            evidence.action_id = Some(ActionId::new());
            (evidence, "action_id")
        },
    ] {
        let mut request = base_request();
        evidence.tenant_id = request.tenant_id.clone();
        evidence.agent_id = request.agent_id.clone();
        if mismatch != "run_id" {
            evidence.run_id = request.run_id.clone();
        }
        evidence.action_name = Some(request.action.name.clone());
        evidence.adapter = Some("adapter".to_string());
        let adapter = Arc::new(CountingAdapter::default());
        let gateway = approval_gateway(&request, adapter.clone());
        request.approval_evidence = Some(evidence);

        let outcome = gateway.submit(request).expect("outcome");

        assert!(
            matches!(outcome.status, ActionStatus::Denied),
            "{mismatch} mismatch must deny"
        );
        assert!(outcome
            .verification
            .reasons
            .contains(&"approval_scope_mismatch".to_string()));
        assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    }
}

#[test]
fn approval_schema_version_mismatches_fail_closed_without_adapter_execution() {
    assert_eq!(
        APPROVAL_EVIDENCE_SCHEMA_VERSION,
        "splendor.approval_evidence.v1"
    );
    assert_eq!(
        APPROVAL_POLICY_SCHEMA_VERSION,
        "splendor.approval_policy.v1"
    );

    let mut request = base_request();
    let adapter = Arc::new(CountingAdapter::default());
    let gateway = approval_gateway(&request, adapter.clone());
    let mut evidence = approval_evidence_for(&request);
    evidence.schema_version = "splendor.approval_evidence.v0".to_string();
    request.approval_evidence = Some(evidence);

    let outcome = gateway.submit(request).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(outcome
        .verification
        .reasons
        .contains(&"approval_evidence_schema_unsupported".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);

    let request = base_request();
    let mut policy = approval_policy_for(&request);
    policy.schema_version = "splendor.approval_policy.v0".to_string();
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());
    gateway.set_approval_verifier(Arc::new(PolicyApprovalVerifier::new(vec![policy])));

    let outcome = gateway.submit(request).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::NeedsIntervention));
    assert!(outcome
        .verification
        .reasons
        .contains(&"approval_policy_schema_unsupported".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);

    let mut request = base_request();
    let supported_policy = approval_policy_for(&request);
    let mut unsupported_later_policy = approval_policy_for(&request);
    unsupported_later_policy.policy_id = "approval_policy_legacy".to_string();
    unsupported_later_policy.schema_version = "splendor.approval_policy.v0".to_string();
    request.approval_evidence = Some(approval_evidence_for(&request));
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());
    gateway.set_approval_verifier(Arc::new(PolicyApprovalVerifier::new(vec![
        supported_policy,
        unsupported_later_policy,
    ])));

    let outcome = gateway.submit(request).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::NeedsIntervention));
    assert!(outcome
        .verification
        .reasons
        .contains(&"approval_policy_schema_unsupported".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn approval_incomplete_action_or_adapter_scope_is_denied_without_adapter_execution() {
    for (mut evidence, missing_scope) in [
        {
            let request = base_request();
            let mut evidence = approval_evidence_for(&request);
            evidence.action_id = None;
            evidence.action_name = None;
            (evidence, "action")
        },
        {
            let request = base_request();
            let mut evidence = approval_evidence_for(&request);
            evidence.adapter = None;
            (evidence, "adapter")
        },
    ] {
        let mut request = base_request();
        evidence.tenant_id = request.tenant_id.clone();
        evidence.agent_id = request.agent_id.clone();
        evidence.run_id = request.run_id.clone();
        let adapter = Arc::new(CountingAdapter::default());
        let gateway = approval_gateway(&request, adapter.clone());
        request.approval_evidence = Some(evidence);

        let outcome = gateway.submit(request).expect("outcome");

        assert!(
            matches!(outcome.status, ActionStatus::Denied),
            "missing {missing_scope} scope must deny"
        );
        assert!(outcome
            .verification
            .reasons
            .contains(&"approval_scope_incomplete".to_string()));
        assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    }
}

#[test]
fn approval_denial_expiry_and_revocation_fail_closed() {
    for (mut evidence, reason) in [
        {
            let request = base_request();
            let mut evidence = approval_evidence_for(&request);
            evidence.decision = ApprovalDecision::Denied;
            (evidence, "approval_denied")
        },
        {
            let request = base_request();
            let mut evidence = approval_evidence_for(&request);
            evidence.expires_at = OffsetDateTime::now_utc() - time::Duration::minutes(1);
            (evidence, "approval_expired")
        },
        {
            let request = base_request();
            let mut evidence = approval_evidence_for(&request);
            evidence.revoked = true;
            (evidence, "approval_revoked")
        },
    ] {
        let mut request = base_request();
        evidence.tenant_id = request.tenant_id.clone();
        evidence.agent_id = request.agent_id.clone();
        evidence.run_id = request.run_id.clone();
        evidence.action_name = Some(request.action.name.clone());
        let adapter = Arc::new(CountingAdapter::default());
        let gateway = approval_gateway(&request, adapter.clone());
        request.approval_evidence = Some(evidence);

        let outcome = gateway.submit(request).expect("outcome");

        assert!(matches!(outcome.status, ActionStatus::Denied));
        assert!(outcome.verification.reasons.contains(&reason.to_string()));
        assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    }
}

#[test]
fn approval_verifier_uncertainty_needs_intervention_without_adapter_execution() {
    struct UnavailableApprovalVerifier;

    impl ApprovalVerifier for UnavailableApprovalVerifier {
        fn verify_approval(
            &self,
            _action: &ActionRequest,
            _adapter: Option<&str>,
            _now: OffsetDateTime,
        ) -> ApprovalVerification {
            ApprovalVerification::NeedsIntervention(VerificationResult::deny(
                "approval_verifier_unavailable",
            ))
        }
    }

    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());
    gateway.set_approval_verifier(Arc::new(UnavailableApprovalVerifier));

    let outcome = gateway.submit(base_request()).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::NeedsIntervention));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn tripped_adapter_breaker_denies_before_adapter_execution() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());
    let breaker = CircuitBreaker::tripped(
        CircuitBreakerId::try_new("cb_adapter").expect("id"),
        CircuitBreakerScope::Adapter("adapter".to_string()),
        "adapter disabled",
        OffsetDateTime::now_utc(),
    )
    .expect("breaker");
    gateway
        .set_circuit_breaker_evaluator(Arc::new(StaticCircuitBreakerEvaluator::new(vec![breaker])));

    let outcome = gateway.submit(base_request()).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(outcome
        .verification
        .reasons
        .contains(&"circuit_breaker_tripped".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
    assert_eq!(
        outcome.verification.artifacts["circuit_breaker"]["circuit_breaker"]["scope"].as_str(),
        Some("adapter")
    );
}

#[test]
fn tenant_breaker_denies_only_matching_tenant() {
    let denied_tenant = TenantId::new();
    let allowed_tenant = TenantId::new();
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());
    let breaker = CircuitBreaker::tripped(
        CircuitBreakerId::try_new("cb_tenant").expect("id"),
        CircuitBreakerScope::Tenant(denied_tenant.clone()),
        "tenant hold",
        OffsetDateTime::now_utc(),
    )
    .expect("breaker");
    gateway
        .set_circuit_breaker_evaluator(Arc::new(StaticCircuitBreakerEvaluator::new(vec![breaker])));

    let mut denied = base_request();
    denied.tenant_id = denied_tenant;
    let denied_outcome = gateway.submit(denied).expect("denied outcome");
    assert!(matches!(denied_outcome.status, ActionStatus::Denied));

    let mut allowed = base_request();
    allowed.tenant_id = allowed_tenant;
    let allowed_outcome = gateway.submit(allowed).expect("allowed outcome");
    assert!(matches!(allowed_outcome.status, ActionStatus::Executed));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 1);
}

#[test]
fn action_class_breaker_uses_effective_adapter_side_effect_class() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "filesystem", adapter.clone());
    let breaker = CircuitBreaker::tripped(
        CircuitBreakerId::try_new("cb_filesystem_effective").expect("id"),
        CircuitBreakerScope::ActionClass(SideEffectClass::Filesystem),
        "filesystem disabled",
        OffsetDateTime::now_utc(),
    )
    .expect("breaker");
    gateway
        .set_circuit_breaker_evaluator(Arc::new(StaticCircuitBreakerEvaluator::new(vec![breaker])));

    let mut request = base_request();
    request.action.side_effect_class = SideEffectClass::ReadOnly;
    request.adapter = Some("filesystem".to_string());
    let outcome = gateway.submit(request).expect("outcome");

    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert!(outcome
        .verification
        .reasons
        .contains(&"circuit_breaker_tripped".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn static_breaker_evaluator_denies_all_supported_action_scopes() {
    let mut request = base_request();
    request.action.name = "artifact.publish".to_string();
    request.action.side_effect_class = SideEffectClass::External;
    request.adapter = Some("artifact-store".to_string());

    let fleet_id = FleetId::new();
    let node_id = NodeId::new();
    let instance_id = InstanceId::new();
    let identity = RuntimeIdentityContext {
        fleet_id: Some(fleet_id.clone()),
        node_id: Some(node_id.clone()),
        instance_id: Some(instance_id.clone()),
        tenant_id: Some(request.tenant_id.clone()),
        agent_id: Some(request.agent_id.clone()),
    };

    let cases = vec![
        ("global", CircuitBreakerScope::Global),
        ("fleet", CircuitBreakerScope::Fleet(fleet_id)),
        ("node", CircuitBreakerScope::Node(node_id)),
        ("instance", CircuitBreakerScope::Instance(instance_id)),
        (
            "tenant",
            CircuitBreakerScope::Tenant(request.tenant_id.clone()),
        ),
        (
            "agent",
            CircuitBreakerScope::Agent(request.agent_id.clone()),
        ),
        (
            "adapter",
            CircuitBreakerScope::Adapter("artifact-store".to_string()),
        ),
        (
            "action",
            CircuitBreakerScope::Action("artifact.publish".to_string()),
        ),
        (
            "action_class",
            CircuitBreakerScope::ActionClass(SideEffectClass::External),
        ),
    ];

    for (scope_label, scope) in cases {
        let breaker = CircuitBreaker::tripped(
            CircuitBreakerId::try_new(format!("cb_{scope_label}")).expect("id"),
            scope,
            format!("{scope_label} disabled"),
            OffsetDateTime::now_utc(),
        )
        .expect("breaker");
        let evaluator = StaticCircuitBreakerEvaluator::new(vec![breaker]);

        let result = evaluator.verify_action(&request, request.adapter.as_deref(), &identity);

        assert!(
            !result.allowed,
            "scope {scope_label} must deny matching action"
        );
        assert!(result
            .reasons
            .contains(&"circuit_breaker_tripped".to_string()));
        assert_eq!(
            result.artifacts["circuit_breaker"]["scope"].as_str(),
            Some(scope_label),
            "scope artifact should identify {scope_label}"
        );
    }
}

#[test]
fn static_breaker_evaluator_denies_new_work_for_runtime_scopes() {
    let fleet_id = FleetId::new();
    let node_id = NodeId::new();
    let instance_id = InstanceId::new();
    let identity = RuntimeIdentityContext {
        fleet_id: Some(fleet_id.clone()),
        node_id: Some(node_id.clone()),
        instance_id: Some(instance_id.clone()),
        tenant_id: Some(TenantId::new()),
        agent_id: Some(AgentId::new()),
    };

    let runtime_cases = vec![
        ("global", CircuitBreakerScope::Global),
        ("fleet", CircuitBreakerScope::Fleet(fleet_id)),
        ("node", CircuitBreakerScope::Node(node_id)),
        ("instance", CircuitBreakerScope::Instance(instance_id)),
    ];

    for (scope_label, scope) in runtime_cases {
        let breaker = CircuitBreaker::tripped(
            CircuitBreakerId::try_new(format!("cb_admission_{scope_label}")).expect("id"),
            scope,
            format!("{scope_label} admission disabled"),
            OffsetDateTime::now_utc(),
        )
        .expect("breaker");
        let evaluator = StaticCircuitBreakerEvaluator::new(vec![breaker]);

        let result = evaluator.verify_runtime_admission(&identity);

        assert!(
            !result.allowed,
            "runtime scope {scope_label} must deny new work admission"
        );
        assert!(result
            .reasons
            .contains(&"circuit_breaker_tripped".to_string()));
        assert_eq!(
            result.artifacts["circuit_breaker"]["scope"].as_str(),
            Some(scope_label)
        );
    }

    let action_only_breaker = CircuitBreaker::tripped(
        CircuitBreakerId::try_new("cb_action_only_admission").expect("id"),
        CircuitBreakerScope::Action("artifact.publish".to_string()),
        "action disabled",
        OffsetDateTime::now_utc(),
    )
    .expect("breaker");
    let evaluator = StaticCircuitBreakerEvaluator::new(vec![action_only_breaker]);
    assert!(
        evaluator.verify_runtime_admission(&identity).allowed,
        "action-scoped breakers wait for action context and must not reject unrelated new work"
    );
}

#[test]
fn runtime_admission_fails_closed_when_node_scope_identity_is_missing() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let breaker = CircuitBreaker::tripped(
        CircuitBreakerId::try_new("cb_node").expect("id"),
        CircuitBreakerScope::Node(NodeId::new()),
        "node disabled",
        OffsetDateTime::now_utc(),
    )
    .expect("breaker");
    gateway
        .set_circuit_breaker_evaluator(Arc::new(StaticCircuitBreakerEvaluator::new(vec![breaker])));
    gateway.set_runtime_identity(RuntimeIdentityContext::default());

    let admission = gateway.verify_runtime_admission();
    assert!(!admission.allowed);
    assert!(admission
        .reasons
        .contains(&"circuit_breaker_scope_unknown".to_string()));
}

#[test]
fn verified_gateway_returns_error_when_adapter_missing() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let gateway = VerifiedActionGateway::new(tenant_access);
    let error = gateway.submit(base_request()).expect_err("missing adapter");
    assert!(matches!(error, GatewayError::AdapterFailed(_)));
}

#[test]
fn verified_gateway_reports_adapter_failure() {
    struct FailingAdapter;

    impl ActionAdapter for FailingAdapter {
        fn execute(&self, _action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
            Err(AdapterError::Failed("boom".to_string()))
        }
    }

    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    gateway.register_adapter("noop", "adapter", Arc::new(FailingAdapter));

    let outcome = gateway.submit(base_request()).expect("outcome");
    assert!(matches!(outcome.status, ActionStatus::Failed));
    assert!(outcome.error.unwrap_or_default().contains("boom"));
    assert!(outcome.output.is_none());
    assert!(outcome.post_verification.is_none());
}

#[test]
fn verified_gateway_allows_when_preconditions_satisfied() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());

    let mut request = base_request();
    request.action.preconditions = vec!["ready".to_string()];
    request.satisfied_preconditions = vec!["ready".to_string()];

    let outcome = gateway.submit(request).expect("outcome");
    assert!(matches!(outcome.status, ActionStatus::Executed));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 1);
}

#[test]
fn verified_gateway_denies_with_empty_reasons() {
    struct EmptyReasonInvariant;

    impl InvariantEvaluator for EmptyReasonInvariant {
        fn verify_pre(
            &self,
            _action: &Action,
            _satisfied_preconditions: &[String],
        ) -> VerificationResult {
            VerificationResult {
                allowed: false,
                reasons: Vec::new(),
                artifacts: serde_json::json!({"detail": "missing"}),
            }
        }

        fn verify_post(
            &self,
            _action: &Action,
            _satisfied_postconditions: &[String],
        ) -> VerificationResult {
            VerificationResult::allow()
        }
    }

    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("noop", "adapter", adapter.clone());
    gateway.set_invariant_evaluator(Arc::new(EmptyReasonInvariant));

    let outcome = gateway.submit(base_request()).expect("outcome");
    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert_eq!(outcome.error.as_deref(), Some("verification denied"));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn combine_verifications_denies_when_reasons_empty() {
    let result = combine_verifications([
        (
            "policy",
            VerificationResult {
                allowed: false,
                reasons: Vec::new(),
                artifacts: serde_json::json!({"detail": "missing"}),
            },
        ),
        ("quota", VerificationResult::allow()),
    ]);

    assert!(!result.allowed);
    assert!(result.reasons.is_empty());
    assert!(result.artifacts["policy"].is_object());
}

#[test]
fn breaker_scope_matching_covers_identity_action_and_admission_paths() {
    let mut request = base_request();
    request.action.name = "artifact.publish".to_string();
    request.action.side_effect_class = SideEffectClass::External;
    request.adapter = Some("artifact-store".to_string());
    let fleet_id = FleetId::new();
    let node_id = NodeId::new();
    let instance_id = InstanceId::new();
    let identity = RuntimeIdentityContext {
        fleet_id: Some(fleet_id.clone()),
        node_id: Some(node_id.clone()),
        instance_id: Some(instance_id.clone()),
        tenant_id: Some(request.tenant_id.clone()),
        agent_id: Some(request.agent_id.clone()),
    };

    assert_eq!(
        breaker_scope_matches(&CircuitBreakerScope::Global, &identity, None, None, true),
        BreakerScopeMatch::Matches
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Fleet(fleet_id.clone()),
            &identity,
            None,
            None,
            true,
        ),
        BreakerScopeMatch::Matches
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Fleet(FleetId::new()),
            &identity,
            None,
            None,
            true,
        ),
        BreakerScopeMatch::DoesNotMatch
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Fleet(fleet_id),
            &RuntimeIdentityContext::default(),
            None,
            None,
            true,
        ),
        BreakerScopeMatch::Unknown("fleet_id")
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Node(node_id.clone()),
            &identity,
            None,
            None,
            true,
        ),
        BreakerScopeMatch::Matches
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Node(NodeId::new()),
            &identity,
            None,
            None,
            true,
        ),
        BreakerScopeMatch::DoesNotMatch
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Node(node_id),
            &RuntimeIdentityContext::default(),
            None,
            None,
            true,
        ),
        BreakerScopeMatch::Unknown("node_id")
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Instance(instance_id.clone()),
            &identity,
            None,
            None,
            true,
        ),
        BreakerScopeMatch::Matches
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Instance(InstanceId::new()),
            &identity,
            None,
            None,
            true,
        ),
        BreakerScopeMatch::DoesNotMatch
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Instance(instance_id),
            &RuntimeIdentityContext::default(),
            None,
            None,
            true,
        ),
        BreakerScopeMatch::Unknown("instance_id")
    );

    for (scope, adapter, unknown_field) in [
        (
            CircuitBreakerScope::Tenant(request.tenant_id.clone()),
            Some("artifact-store"),
            "tenant_id",
        ),
        (
            CircuitBreakerScope::Agent(request.agent_id.clone()),
            Some("artifact-store"),
            "agent_id",
        ),
        (
            CircuitBreakerScope::Adapter("artifact-store".to_string()),
            Some("artifact-store"),
            "adapter",
        ),
        (
            CircuitBreakerScope::Action("artifact.publish".to_string()),
            Some("artifact-store"),
            "action",
        ),
        (
            CircuitBreakerScope::ActionClass(SideEffectClass::External),
            Some("artifact-store"),
            "action_class",
        ),
    ] {
        assert_eq!(
            breaker_scope_matches(&scope, &identity, Some(&request), adapter, false),
            BreakerScopeMatch::Matches
        );
        assert_eq!(
            breaker_scope_matches(&scope, &identity, None, None, true),
            BreakerScopeMatch::DoesNotMatch
        );
        assert_eq!(
            breaker_scope_matches(&scope, &identity, None, None, false),
            BreakerScopeMatch::Unknown(unknown_field)
        );
    }

    let mut other = request.clone();
    other.tenant_id = TenantId::new();
    other.agent_id = AgentId::new();
    other.action.name = "ticket.create".to_string();
    other.action.side_effect_class = SideEffectClass::Network;
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Tenant(request.tenant_id.clone()),
            &identity,
            Some(&other),
            Some("artifact-store"),
            false,
        ),
        BreakerScopeMatch::DoesNotMatch
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Agent(request.agent_id.clone()),
            &identity,
            Some(&other),
            Some("artifact-store"),
            false,
        ),
        BreakerScopeMatch::DoesNotMatch
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Adapter("filesystem".to_string()),
            &identity,
            Some(&request),
            Some("artifact-store"),
            false,
        ),
        BreakerScopeMatch::DoesNotMatch
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::Action("ticket.create".to_string()),
            &identity,
            Some(&request),
            Some("artifact-store"),
            false,
        ),
        BreakerScopeMatch::DoesNotMatch
    );
    assert_eq!(
        breaker_scope_matches(
            &CircuitBreakerScope::ActionClass(SideEffectClass::Network),
            &identity,
            Some(&request),
            Some("artifact-store"),
            false,
        ),
        BreakerScopeMatch::DoesNotMatch
    );
}

#[test]
fn gateway_effective_side_effect_and_artifact_helpers_cover_edge_shapes() {
    let mut request = base_request();
    request.action.side_effect_class = SideEffectClass::ReadOnly;

    let normalized = action_request_with_effective_side_effect_class(&request, "filesystem");
    assert_eq!(
        normalized.action.side_effect_class,
        SideEffectClass::Filesystem
    );
    let unchanged = action_request_with_effective_side_effect_class(&request, "custom-adapter");
    assert_eq!(
        unchanged.action.side_effect_class,
        SideEffectClass::ReadOnly
    );

    let mismatch = verify_declared_side_effect_class(&request, "filesystem")
        .expect("filesystem mismatch denied");
    assert!(!mismatch.allowed);
    assert_eq!(
        mismatch.artifacts["declared_side_effect_class"].as_str(),
        Some("read_only")
    );
    assert_eq!(
        mismatch.artifacts["effective_side_effect_class"].as_str(),
        Some("filesystem")
    );

    let mut network_request = request.clone();
    network_request.action.side_effect_class = SideEffectClass::Network;
    assert!(verify_declared_side_effect_class(&network_request, "http").is_none());
    assert!(verify_declared_side_effect_class(&network_request, "unknown").is_none());
    assert_eq!(
        side_effect_class_label(&SideEffectClass::External),
        "external"
    );
    assert_eq!(
        side_effect_class_label(&SideEffectClass::Custom("robot.high".to_string())),
        "custom:robot.high"
    );

    let mut allowed = VerificationResult::allow();
    attach_allowed_artifact(&mut allowed, "ignored", serde_json::Value::Null);
    assert!(allowed.artifacts.is_null());
    attach_allowed_artifact(
        &mut allowed,
        "approval",
        serde_json::json!({"status": "granted"}),
    );
    assert_eq!(
        allowed.artifacts["approval"]["status"].as_str(),
        Some("granted")
    );

    let mut non_object = VerificationResult {
        allowed: true,
        reasons: Vec::new(),
        artifacts: serde_json::json!("raw-detail"),
    };
    attach_allowed_artifact(
        &mut non_object,
        "policy",
        serde_json::json!({"bundle": "policy_main"}),
    );
    assert_eq!(non_object.artifacts["detail"].as_str(), Some("raw-detail"));
    assert_eq!(
        non_object.artifacts["policy"]["bundle"].as_str(),
        Some("policy_main")
    );

    let mut denied = VerificationResult::deny("policy");
    attach_request_context(&mut denied, &request);
    assert!(denied.artifacts["context"].is_object());
    let mut denied_with_detail = VerificationResult {
        allowed: false,
        reasons: vec!["policy".to_string()],
        artifacts: serde_json::json!("opaque"),
    };
    attach_request_context(&mut denied_with_detail, &request);
    assert_eq!(
        denied_with_detail.artifacts["detail"].as_str(),
        Some("opaque")
    );
    assert!(denied_with_detail.artifacts["context"].is_object());
}

#[test]
fn verified_gateway_rejects_forbidden_physical_action_before_adapter_execution() {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    let adapter = Arc::new(CountingAdapter::default());
    gateway.register_adapter("disable_firmware_safety", "robotics", adapter.clone());
    gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(
        safe_safety_snapshot(),
    )));

    let mut request = physical_request();
    request.action.name = "disable_firmware_safety".to_string();
    request.adapter = Some("robotics".to_string());

    let outcome = gateway.submit(request).expect("outcome");
    assert!(matches!(outcome.status, ActionStatus::Denied));
    assert_eq!(outcome.error.as_deref(), Some("forbidden_physical_action"));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}
