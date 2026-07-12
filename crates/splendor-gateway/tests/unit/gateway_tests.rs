use super::*;
use splendor_authority::{
    canonical_authority_request_digest, compatibility_permission_operation,
    gateway_action_operation, gateway_adapter_operation, issue_local_authority_obligation_receipt,
    AuthorityObligationReceiptValidationContext,
};
use splendor_types::{
    AgentId, ApprovalDecision, ApprovalEvidence, ApprovalId, ApprovalPolicy, AuthorityDecision,
    AuthorityDecisionId, AuthorityDecisionStatus, AuthorityObligation, AuthorityObligationKind,
    AuthorityObligationReceipt, AuthorityObligationReceiptId, AuthorityObligationReceiptValidation,
    AuthorityObligationReceiptValidationKind, CapabilityGrantId, CapabilityRequest,
    CapabilityScope, CircuitBreaker, CircuitBreakerId, CircuitBreakerScope, EffectCertainty,
    ErrorCategory, FleetId, InstanceId, NodeId, PrincipalId, QuotaUsage, RetryClass,
    RevocationStatus, RunId, RuntimeIdentityContext, SideEffectClass, TenantId,
    APPROVAL_EVIDENCE_SCHEMA_VERSION, APPROVAL_POLICY_SCHEMA_VERSION,
    AUTHORITY_DECISION_SCHEMA_VERSION, AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION,
    AUTHORITY_OBLIGATION_SCHEMA_VERSION, CAPABILITY_REQUEST_SCHEMA_VERSION,
    UNKNOWN_ADAPTER_FAILURE_REASON,
};
use std::collections::BTreeMap;
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
        tick_id: None,
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
        authority_obligation_evidence: None,
        authority_obligation_receipts: Vec::new(),
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

    let adapter = GatewayError::AdapterFailed("X-Api-Key: sk-test-secret".to_string()).taxonomy();
    assert_eq!(adapter.category, ErrorCategory::DriverFailure);
    assert_eq!(adapter.reason_code.as_str(), UNKNOWN_ADAPTER_FAILURE_REASON);
    assert_eq!(adapter.retry_class, RetryClass::NotRetryable);
    assert_eq!(adapter.effect_certainty, EffectCertainty::Uncertain);
    let detail = adapter.provider_detail.as_ref().expect("provider detail");
    assert_eq!(detail.provider(), "gateway_adapter");
    assert_eq!(detail.safe_summary(), None);
    let encoded = serde_json::to_string(&adapter).expect("taxonomy serializes");
    assert!(!encoded.contains("sk-test-secret"));
    assert!(!encoded.contains("X-Api-Key"));
}

#[test]
fn adapter_error_unknown_failures_are_uncertain_and_non_retryable() {
    for raw_detail in [
        "provider returned HTTP 500 with X-Api-Key: sk-test-secret",
        "api-key=sk-test-secret",
        "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
    ] {
        let taxonomy =
            AdapterError::Failed(raw_detail.to_string()).taxonomy_for_adapter("custom/provider");

        assert_eq!(taxonomy.category, ErrorCategory::DriverFailure);
        assert_eq!(
            taxonomy.reason_code.as_str(),
            UNKNOWN_ADAPTER_FAILURE_REASON
        );
        assert_eq!(taxonomy.retry_class, RetryClass::NotRetryable);
        assert_eq!(taxonomy.effect_certainty, EffectCertainty::Uncertain);
        let detail = taxonomy.provider_detail.as_ref().expect("provider detail");
        assert_eq!(detail.provider(), "custom_provider");
        assert_eq!(detail.safe_summary(), None);

        let encoded = serde_json::to_string(&taxonomy).expect("taxonomy serializes");
        assert!(!encoded.contains("sk-test-secret"));
        assert!(!encoded.contains("X-Api-Key"));
        assert!(!encoded.contains("api-key"));
        assert!(!encoded.contains("PRIVATE KEY"));
        assert!(!encoded.contains("abc123"));
    }
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

struct DefaultPostSafetyVerifier;

impl SafetyVerifier for DefaultPostSafetyVerifier {
    fn verify_pre(&self, _action: &ActionRequest, _adapter: Option<&str>) -> SafetyVerification {
        SafetyVerification::Allowed(VerificationResult::allow())
    }
}

struct NotRequiredSafetyVerifier;

impl SafetyVerifier for NotRequiredSafetyVerifier {
    fn verify_pre(&self, _action: &ActionRequest, _adapter: Option<&str>) -> SafetyVerification {
        SafetyVerification::NotRequired
    }
}

struct InconsistentSafetyVerifier;

impl SafetyVerifier for InconsistentSafetyVerifier {
    fn verify_pre(&self, _action: &ActionRequest, _adapter: Option<&str>) -> SafetyVerification {
        SafetyVerification::Allowed(VerificationResult::deny("inconsistent_safety_allow"))
    }
}

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
        tick_id: None,
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
        authority_obligation_evidence: None,
        authority_obligation_receipts: Vec::new(),
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

#[test]
fn gateway_default_trait_helpers_cover_fail_closed_edges() {
    let non_physical = base_request();
    let physical = physical_request();
    let adapter_result = AdapterResult {
        output: serde_json::json!({"ok": true}),
        satisfied_postconditions: Vec::new(),
    };
    let simulated = SimulatedSafetyVerifier::new(safe_safety_snapshot());

    assert!(matches!(
        simulated.verify_pre(&non_physical, Some("adapter")),
        SafetyVerification::NotRequired
    ));
    assert!(matches!(
        simulated.verify_post(&non_physical, Some("adapter"), &adapter_result),
        SafetyVerification::NotRequired
    ));
    assert!(AdapterError::Failed("provider failed".to_string())
        .taxonomy()
        .reason_code
        .as_str()
        .contains("adapter"));
    assert!(
        NoopCircuitBreakerEvaluator
            .verify_runtime_admission(&RuntimeIdentityContext::default())
            .allowed
    );
    assert!(StaticCircuitBreakerEvaluator::new(Vec::new())
        .breakers()
        .is_empty());

    let default_post = Some(Arc::new(DefaultPostSafetyVerifier) as Arc<dyn SafetyVerifier>);
    let post = verify_safety_post(&default_post, &physical, Some("robotics"), &adapter_result);
    assert!(matches!(post, SafetyVerification::NeedsIntervention(_)));

    let not_required = Some(Arc::new(NotRequiredSafetyVerifier) as Arc<dyn SafetyVerifier>);
    let pre = verify_safety_pre(&not_required, &physical, Some("robotics"));
    assert!(matches!(pre, SafetyVerification::NeedsIntervention(_)));

    let inconsistent = Some(Arc::new(InconsistentSafetyVerifier) as Arc<dyn SafetyVerifier>);
    let pre = verify_safety_pre(&inconsistent, &physical, Some("robotics"));
    match pre {
        SafetyVerification::NeedsIntervention(result) => assert!(result
            .reasons
            .contains(&"safety_verifier_inconsistent".to_string())),
        other => panic!("expected inconsistent safety intervention, got {other:?}"),
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

const OBLIGATION_RECEIPT_AUDIENCE: &str = "daemon:local";
const OBLIGATION_RECEIPT_KEY_ID: &str = "gateway-receipt-key-1";
const OBLIGATION_RECEIPT_SECRET: &str = "gateway-owned-receipt-secret";
const OBLIGATION_RECEIPT_REVOCATION_REF: &str = "revocation:gateway-obligation-test";
const OBLIGATION_EVIDENCE_DIGEST: &str =
    "blake3:5555555555555555555555555555555555555555555555555555555555555555";
const PLACEHOLDER_DIGEST: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";

fn gateway_authority_context(
    issuer: PrincipalId,
    now: OffsetDateTime,
) -> AuthorityObligationReceiptValidationContext {
    AuthorityObligationReceiptValidationContext::trusted_local(
        issuer,
        OBLIGATION_RECEIPT_AUDIENCE,
        OBLIGATION_RECEIPT_KEY_ID,
        OBLIGATION_RECEIPT_SECRET,
        OBLIGATION_RECEIPT_REVOCATION_REF,
        now,
    )
}

fn authority_decision_for(
    request: &ActionRequest,
    adapter: &str,
    subject: PrincipalId,
    now: OffsetDateTime,
) -> AuthorityDecision {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        GATEWAY_AUTHORITY_ACTION_DIGEST_METADATA_KEY.to_string(),
        serde_json::Value::String(
            canonical_gateway_authority_action_digest(request, Some(adapter))
                .expect("gateway action digest"),
        ),
    );
    let capability_request = CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject,
        operation: gateway_action_operation(&request.action.name),
        scope: CapabilityScope {
            tenant_ids: Some(vec![request.tenant_id.clone()]),
            agent_ids: Some(vec![request.agent_id.clone()]),
            run_ids: Some(vec![request.run_id.clone()]),
            audiences: Some(vec![OBLIGATION_RECEIPT_AUDIENCE.to_string()]),
            ..Default::default()
        },
        requested_at: request.requested_at,
        metadata,
    };
    let mut decision = AuthorityDecision {
        schema_version: AUTHORITY_DECISION_SCHEMA_VERSION.to_string(),
        decision_id: AuthorityDecisionId::new(),
        request: capability_request,
        status: AuthorityDecisionStatus::Conditional,
        reasons: vec!["capability_conditional".to_string()],
        matched_grant_ids: vec![CapabilityGrantId::new()],
        obligations: vec![AuthorityObligation {
            schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
            obligation_id: splendor_types::AuthorityObligationId::new(),
            kind: AuthorityObligationKind::ApprovalRequired,
            description: "gateway obligation satisfied by authority receipt".to_string(),
            parameters: BTreeMap::new(),
        }],
        decided_at: now,
    };
    bind_gateway_authority_decision_digest(&mut decision);
    decision
}

fn bind_gateway_authority_decision_digest(decision: &mut AuthorityDecision) {
    let decision_digest =
        canonical_gateway_authority_decision_digest(decision).expect("authority decision digest");
    decision.request.metadata.insert(
        GATEWAY_AUTHORITY_DECISION_DIGEST_METADATA_KEY.to_string(),
        serde_json::Value::String(decision_digest),
    );
}

fn unsigned_obligation_receipt(
    decision: &AuthorityDecision,
    issuer: PrincipalId,
    now: OffsetDateTime,
) -> AuthorityObligationReceipt {
    let obligation = decision
        .obligations
        .first()
        .expect("conditional decision obligation");
    AuthorityObligationReceipt {
        schema_version: AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: AuthorityObligationReceiptId::new(),
        issuer,
        audience: OBLIGATION_RECEIPT_AUDIENCE.to_string(),
        obligation_id: obligation.obligation_id.clone(),
        kind: obligation.kind,
        subject: decision.request.subject.clone(),
        authority_decision_id: decision.decision_id.clone(),
        canonical_request_digest: canonical_authority_request_digest(&decision.request)
            .expect("authority request digest"),
        evidence_digest: OBLIGATION_EVIDENCE_DIGEST.to_string(),
        evidence_ref: Some("approval-evidence:gateway-obligation-test".to_string()),
        issued_at: now - time::Duration::seconds(1),
        expires_at: now + time::Duration::minutes(10),
        revocation: RevocationStatus::Active,
        revocation_ref: OBLIGATION_RECEIPT_REVOCATION_REF.to_string(),
        approval_id: None,
        approval_trace_event_id: None,
        validation: AuthorityObligationReceiptValidation {
            validation_kind: AuthorityObligationReceiptValidationKind::LocalSignature,
            algorithm: "local-obligation-receipt-v1".to_string(),
            key_id: OBLIGATION_RECEIPT_KEY_ID.to_string(),
            digest: PLACEHOLDER_DIGEST.to_string(),
            signature: PLACEHOLDER_DIGEST.to_string(),
        },
    }
}

fn issue_obligation_receipt(
    receipt: AuthorityObligationReceipt,
    context: &AuthorityObligationReceiptValidationContext,
) -> AuthorityObligationReceipt {
    issue_local_authority_obligation_receipt(receipt, context).expect("issued receipt")
}

fn authority_evidence_for(
    request: &ActionRequest,
    adapter: &str,
    now: OffsetDateTime,
) -> (
    PrincipalId,
    AuthorityObligationReceiptValidationContext,
    GatewayAuthorityObligationEvidence,
) {
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let context = gateway_authority_context(issuer.clone(), now);
    let decision = authority_decision_for(request, adapter, subject, now);
    let receipt = issue_obligation_receipt(
        unsigned_obligation_receipt(&decision, issuer.clone(), now),
        &context,
    );
    (
        issuer,
        context,
        GatewayAuthorityObligationEvidence {
            decision,
            receipts: vec![receipt],
        },
    )
}

fn hostile_authority_values() -> Vec<String> {
    vec![
        "authority-reason-secret-do-not-export".to_string(),
        "reason-with-crlf\r\nforged-header: allow".to_string(),
        "reason-with-ansi-\u{1b}[31m-and-control-\u{7}".to_string(),
        "capability_allowed\nmisleading-allow".to_string(),
        format!("oversized-secret:{}", "x".repeat(8_192)),
        "decision-schema-secret-do-not-export".to_string(),
        "request-schema-secret-do-not-export".to_string(),
        "operation-schema-secret-do-not-export".to_string(),
        "resource-schema-secret-do-not-export".to_string(),
    ]
}

fn poison_authority_decision(decision: &mut AuthorityDecision, hostile: &[String]) {
    decision.reasons = hostile[..5].to_vec();
    decision.schema_version = hostile[5].clone();
    decision.request.schema_version = hostile[6].clone();
    decision.request.operation.schema_version = hostile[7].clone();
    decision.request.operation.resource_schema_version = Some(hostile[8].clone());
}

fn assert_hostile_authority_values_absent(value: &serde_json::Value, hostile: &[String]) {
    let encoded = serde_json::to_string(value).expect("verification artifact JSON");
    for forbidden in hostile {
        assert!(
            !encoded.contains(forbidden),
            "leaked hostile input: {forbidden}"
        );
    }
}

fn hostile_authority_evidence_for(
    request: &ActionRequest,
    adapter: &str,
    now: OffsetDateTime,
    hostile: &[String],
) -> (
    AuthorityObligationReceiptValidationContext,
    GatewayAuthorityObligationEvidence,
) {
    let issuer = PrincipalId::new();
    let context = gateway_authority_context(issuer.clone(), now);
    let mut decision = authority_decision_for(request, adapter, PrincipalId::new(), now);
    poison_authority_decision(&mut decision, hostile);
    // Exact gateway operation matching is part of the trusted path. Hostile
    // operation/resource schema strings are exercised only on untrusted paths.
    decision.request.operation = gateway_action_operation(&request.action.name);
    bind_gateway_authority_decision_digest(&mut decision);
    let receipt = issue_obligation_receipt(
        unsigned_obligation_receipt(&decision, issuer, now),
        &context,
    );
    (
        context,
        GatewayAuthorityObligationEvidence {
            decision,
            receipts: vec![receipt],
        },
    )
}

fn authority_gateway(
    context: AuthorityObligationReceiptValidationContext,
    adapter: Arc<CountingAdapter>,
) -> VerifiedActionGateway {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    gateway.register_adapter("noop", "adapter", adapter);
    gateway.set_authority_obligation_verifier(Arc::new(
        LocalAuthorityObligationVerifier::require_all(context),
    ));
    gateway
}

fn authority_gateway_with_verifier(
    verifier: Arc<dyn AuthorityObligationVerifier>,
    adapter: Arc<CountingAdapter>,
) -> VerifiedActionGateway {
    let tenant_access = Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    });
    let mut gateway = VerifiedActionGateway::new(tenant_access);
    gateway.register_adapter("noop", "adapter", adapter);
    gateway.set_authority_obligation_verifier(verifier);
    gateway
}

#[derive(Clone)]
struct FixedLiveAuthorityEvaluator {
    decisions: Vec<AuthorityDecision>,
    calls: Arc<AtomicUsize>,
}

impl ActionAuthorityEvaluator for FixedLiveAuthorityEvaluator {
    fn evaluate_action_authority(
        &self,
        _action: &ActionRequest,
        _effective_adapter: Option<&str>,
        _now: OffsetDateTime,
    ) -> ActionAuthorityEvaluation {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ActionAuthorityEvaluation::Evaluated(self.decisions.clone())
    }

    fn acquire_final_effect_permit(
        &self,
        _action: &ActionRequest,
        _effective_adapter: Option<&str>,
        _expected_decisions: &[AuthorityDecision],
        _now: OffsetDateTime,
    ) -> FinalEffectAuthorityEvaluation {
        self.calls.fetch_add(1, Ordering::SeqCst);
        FinalEffectAuthorityEvaluation::Permitted {
            decisions: self.decisions.clone(),
            permit: AuthorityEffectPermit::new(()),
        }
    }
}

#[derive(Clone)]
enum ScriptedFinalAuthority {
    NotRequired,
    Denied(Vec<AuthorityDecision>),
    Permitted(Vec<AuthorityDecision>),
}

#[derive(Clone)]
struct ScriptedAuthorityEvaluator {
    early: Option<Vec<AuthorityDecision>>,
    final_evaluation: ScriptedFinalAuthority,
}

#[derive(Clone)]
struct EarlyOnlyAuthorityEvaluator(Vec<AuthorityDecision>);

impl ActionAuthorityEvaluator for EarlyOnlyAuthorityEvaluator {
    fn evaluate_action_authority(
        &self,
        _action: &ActionRequest,
        _effective_adapter: Option<&str>,
        _now: OffsetDateTime,
    ) -> ActionAuthorityEvaluation {
        ActionAuthorityEvaluation::Evaluated(self.0.clone())
    }
}

impl ActionAuthorityEvaluator for ScriptedAuthorityEvaluator {
    fn evaluate_action_authority(
        &self,
        _action: &ActionRequest,
        _effective_adapter: Option<&str>,
        _now: OffsetDateTime,
    ) -> ActionAuthorityEvaluation {
        self.early
            .clone()
            .map(ActionAuthorityEvaluation::Evaluated)
            .unwrap_or(ActionAuthorityEvaluation::NotRequired)
    }

    fn acquire_final_effect_permit(
        &self,
        _action: &ActionRequest,
        _effective_adapter: Option<&str>,
        _expected_decisions: &[AuthorityDecision],
        _now: OffsetDateTime,
    ) -> FinalEffectAuthorityEvaluation {
        match &self.final_evaluation {
            ScriptedFinalAuthority::NotRequired => FinalEffectAuthorityEvaluation::NotRequired,
            ScriptedFinalAuthority::Denied(decisions) => {
                FinalEffectAuthorityEvaluation::Denied(decisions.clone())
            }
            ScriptedFinalAuthority::Permitted(decisions) => {
                FinalEffectAuthorityEvaluation::Permitted {
                    decisions: decisions.clone(),
                    permit: AuthorityEffectPermit::new(()),
                }
            }
        }
    }
}

struct OrderingAuthorityRecorder {
    calls: Arc<AtomicUsize>,
    adapter: Arc<CountingAdapter>,
}

impl PreEffectAuthorityDecisionRecorder for OrderingAuthorityRecorder {
    fn record_pre_effect_authority_allow(
        &self,
        _action: &ActionRequest,
        verification: &VerificationResult,
    ) -> Result<(), String> {
        assert_eq!(*self.adapter.calls.lock().expect("adapter calls"), 0);
        assert!(authority_pre_effect_evidence_recorded(verification));
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn live_conditional_authority_uses_only_raw_receipts_and_records_before_effect() {
    let now = OffsetDateTime::now_utc();
    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    request.action.required_permissions = vec!["fixture.write".to_string()];
    let (issuer, context, evidence) = authority_evidence_for(&request, "adapter", now);
    let live_decision = evidence.decision;
    let mut receipts = evidence.receipts;
    let mut adapter_decision = live_decision.clone();
    adapter_decision.decision_id = AuthorityDecisionId::new();
    adapter_decision.request.operation = gateway_adapter_operation("adapter");
    bind_gateway_authority_decision_digest(&mut adapter_decision);
    receipts.push(issue_obligation_receipt(
        unsigned_obligation_receipt(&adapter_decision, issuer.clone(), now),
        &context,
    ));
    let mut permission_decision = live_decision.clone();
    permission_decision.decision_id = AuthorityDecisionId::new();
    permission_decision.request.operation = compatibility_permission_operation("fixture.write");
    bind_gateway_authority_decision_digest(&mut permission_decision);
    receipts.push(issue_obligation_receipt(
        unsigned_obligation_receipt(&permission_decision, issuer, now),
        &context,
    ));
    request.authority_obligation_receipts = receipts;
    request.authority_obligation_evidence = None;

    let evaluations = Arc::new(AtomicUsize::new(0));
    let records = Arc::new(AtomicUsize::new(0));
    let adapter = Arc::new(CountingAdapter::default());
    let single_adapter = Arc::new(CountingAdapter::default());
    let mut single_gateway = authority_gateway(context.clone(), single_adapter.clone());
    single_gateway.set_action_authority_evaluator(Arc::new(FixedLiveAuthorityEvaluator {
        decisions: vec![
            live_decision.clone(),
            adapter_decision.clone(),
            permission_decision.clone(),
        ],
        calls: Arc::new(AtomicUsize::new(0)),
    }));
    single_gateway.set_pre_effect_authority_recorder(Arc::new(OrderingAuthorityRecorder {
        calls: Arc::new(AtomicUsize::new(0)),
        adapter: single_adapter.clone(),
    }));
    let mut one_receipt = request.clone();
    one_receipt.authority_obligation_receipts.truncate(1);
    let incomplete = single_gateway
        .submit(one_receipt)
        .expect("operation-bound receipt denial");
    assert_eq!(incomplete.status, ActionStatus::Denied);
    assert_eq!(*single_adapter.calls.lock().expect("adapter calls"), 0);

    let mut gateway = authority_gateway(context, adapter.clone());
    gateway.set_action_authority_evaluator(Arc::new(FixedLiveAuthorityEvaluator {
        decisions: vec![
            live_decision.clone(),
            adapter_decision.clone(),
            permission_decision,
        ],
        calls: Arc::clone(&evaluations),
    }));
    gateway.set_pre_effect_authority_recorder(Arc::new(OrderingAuthorityRecorder {
        calls: Arc::clone(&records),
        adapter: adapter.clone(),
    }));

    let outcome = gateway.submit(request.clone()).expect("outcome");

    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(evaluations.load(Ordering::SeqCst), 2);
    assert_eq!(records.load(Ordering::SeqCst), 1);
    assert_eq!(*adapter.calls.lock().expect("adapter calls"), 1);
    assert!(authority_pre_effect_evidence_recorded(
        &outcome.verification
    ));

    let replayed = gateway
        .submit(request.clone())
        .expect("receipt replay denial");
    assert_eq!(replayed.status, ActionStatus::Denied);
    assert!(replayed
        .verification
        .reasons
        .contains(&"authority_obligation_receipt_replayed".to_string()));
    assert_eq!(*adapter.calls.lock().expect("adapter calls"), 1);

    gateway.set_action_authority_evaluator(Arc::new(FixedLiveAuthorityEvaluator {
        decisions: vec![live_decision, adapter_decision],
        calls: Arc::clone(&evaluations),
    }));
    let missing_permission = gateway.submit(request).expect("fail-closed outcome");
    assert_eq!(missing_permission.status, ActionStatus::NeedsIntervention);
    assert!(missing_permission
        .verification
        .reasons
        .contains(&"authority_decision_request_mismatch".to_string()));
    assert_eq!(*adapter.calls.lock().expect("adapter calls"), 1);
}

#[test]
fn trusted_action_profile_rejects_permission_omission_and_adapter_recombination() {
    let adapter = Arc::new(CountingAdapter::default());
    let mut gateway = basic_live_authority_gateway(adapter.clone());
    gateway
        .set_trusted_action_profiles(vec![TrustedActionProfile {
            action_name: "noop".to_string(),
            adapter: "adapter".to_string(),
            required_permissions: vec!["fixture.read".to_string(), "fixture.write".to_string()],
        }])
        .expect("trusted profile");

    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    for (permissions, adapter_name, expected_reason) in [
        (
            vec!["fixture.read".to_string()],
            "adapter",
            "trusted_action_profile_permission_mismatch",
        ),
        (
            vec!["fixture.read".to_string(), "fixture.admin".to_string()],
            "adapter",
            "trusted_action_profile_permission_mismatch",
        ),
        (
            vec!["fixture.read".to_string(), "fixture.write".to_string()],
            "other-adapter",
            "trusted_action_profile_adapter_mismatch",
        ),
    ] {
        request.action.required_permissions = permissions;
        request.adapter = Some(adapter_name.to_string());
        let outcome = gateway.submit(request.clone()).expect("profile denial");
        assert_eq!(outcome.status, ActionStatus::Denied);
        assert!(outcome
            .verification
            .reasons
            .contains(&expected_reason.to_string()));
    }
    assert_eq!(*adapter.calls.lock().expect("adapter calls"), 0);
}

#[test]
fn live_authority_never_projects_raw_evaluator_reasons() {
    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    request.action.required_permissions = vec!["fixture.write".to_string()];
    let mut decisions = live_decisions_with_status(&request, AuthorityDecisionStatus::Denied);
    for decision in &mut decisions {
        decision.reasons = vec!["raw-secret-evaluator-reason\r\nforged: allow".to_string()];
        bind_gateway_authority_decision_digest(decision);
    }
    let adapter = Arc::new(CountingAdapter::default());
    let mut gateway = basic_live_authority_gateway(adapter.clone());
    gateway.set_action_authority_evaluator(Arc::new(FixedLiveAuthorityEvaluator {
        decisions,
        calls: Arc::new(AtomicUsize::new(0)),
    }));

    let outcome = gateway.submit(request).expect("redacted denial");
    assert_eq!(outcome.status, ActionStatus::Denied);
    let encoded = serde_json::to_string(&outcome).expect("outcome JSON");
    assert!(!encoded.contains("raw-secret-evaluator-reason"));
    assert_eq!(*adapter.calls.lock().expect("adapter calls"), 0);
}

#[test]
fn trusted_profile_receipt_limit_and_final_permit_failures_are_fail_closed() {
    let mut profile_gateway = basic_live_authority_gateway(Arc::new(CountingAdapter::default()));
    assert_eq!(
        profile_gateway
            .set_trusted_action_profiles(vec![TrustedActionProfile {
                action_name: String::new(),
                adapter: "adapter".to_string(),
                required_permissions: Vec::new(),
            }])
            .expect_err("empty action profile"),
        "trusted_action_profile_invalid"
    );
    assert_eq!(
        profile_gateway
            .set_trusted_action_profiles(vec![
                TrustedActionProfile {
                    action_name: "noop".to_string(),
                    adapter: "adapter".to_string(),
                    required_permissions: Vec::new(),
                },
                TrustedActionProfile {
                    action_name: "noop".to_string(),
                    adapter: "adapter.secondary".to_string(),
                    required_permissions: Vec::new(),
                },
            ])
            .expect_err("duplicate action profile"),
        "trusted_action_profile_duplicate"
    );

    let mut receipt_limited = base_request();
    let (_, _, evidence) =
        authority_evidence_for(&receipt_limited, "adapter", OffsetDateTime::now_utc());
    receipt_limited.authority_obligation_receipts = vec![evidence.receipts[0].clone(); 65];
    let outcome = basic_live_authority_gateway(Arc::new(CountingAdapter::default()))
        .submit(receipt_limited)
        .expect("receipt limit outcome");
    assert_eq!(outcome.status, ActionStatus::Denied);
    assert!(outcome
        .verification
        .reasons
        .contains(&"authority_obligation_receipt_limit_exceeded".to_string()));

    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    request.action.required_permissions = vec!["fixture.write".to_string()];
    let allowed = live_decisions_with_status(&request, AuthorityDecisionStatus::Allowed);
    let denied = live_decisions_with_status(&request, AuthorityDecisionStatus::Denied);
    let mut mismatched = allowed.clone();
    mismatched[0]
        .matched_grant_ids
        .push(CapabilityGrantId::new());

    let adapter = Arc::new(CountingAdapter::default());
    let mut legacy_evaluator_gateway = basic_live_authority_gateway(adapter.clone());
    legacy_evaluator_gateway
        .set_action_authority_evaluator(Arc::new(EarlyOnlyAuthorityEvaluator(allowed.clone())));
    let outcome = legacy_evaluator_gateway
        .submit(request.clone())
        .expect("legacy evaluator fails closed");
    assert_eq!(outcome.status, ActionStatus::NeedsIntervention);
    assert!(outcome
        .verification
        .reasons
        .contains(&"final_effect_authority_permit_unavailable".to_string()));
    assert_eq!(*adapter.calls.lock().expect("adapter calls"), 0);

    for (early, final_evaluation, expected_status, expected_reason) in [
        (
            Some(allowed.clone()),
            ScriptedFinalAuthority::NotRequired,
            ActionStatus::NeedsIntervention,
            "final_effect_authority_permit_unavailable",
        ),
        (
            Some(allowed.clone()),
            ScriptedFinalAuthority::Permitted(mismatched),
            ActionStatus::NeedsIntervention,
            "final_effect_authority_generation_mismatch",
        ),
        (
            Some(allowed.clone()),
            ScriptedFinalAuthority::Denied(denied),
            ActionStatus::Denied,
            "action_not_allowed",
        ),
        (
            Some(allowed.clone()),
            ScriptedFinalAuthority::Denied(allowed.clone()),
            ActionStatus::NeedsIntervention,
            "final_effect_authority_permit_missing",
        ),
        (
            None,
            ScriptedFinalAuthority::Permitted(allowed),
            ActionStatus::NeedsIntervention,
            "unexpected_final_effect_authority_permit",
        ),
    ] {
        let adapter = Arc::new(CountingAdapter::default());
        let mut gateway = basic_live_authority_gateway(adapter.clone());
        gateway.set_action_authority_evaluator(Arc::new(ScriptedAuthorityEvaluator {
            early,
            final_evaluation,
        }));
        let outcome = gateway
            .submit(request.clone())
            .expect("final permit outcome");
        assert_eq!(outcome.status, expected_status);
        assert!(
            outcome
                .verification
                .reasons
                .iter()
                .any(|reason| reason == expected_reason),
            "expected {expected_reason}, got {:?}",
            outcome.verification.reasons
        );
        assert_eq!(*adapter.calls.lock().expect("adapter calls"), 0);
    }
}

fn live_decisions_with_status(
    request: &ActionRequest,
    status: AuthorityDecisionStatus,
) -> Vec<AuthorityDecision> {
    let mut action = authority_decision_for(
        request,
        request.adapter.as_deref().unwrap_or("adapter"),
        PrincipalId::new(),
        OffsetDateTime::now_utc(),
    );
    action.status = status;
    if status != AuthorityDecisionStatus::Conditional {
        action.obligations.clear();
    }
    bind_gateway_authority_decision_digest(&mut action);
    let mut adapter = action.clone();
    adapter.request.operation = gateway_adapter_operation("adapter");
    bind_gateway_authority_decision_digest(&mut adapter);
    let mut permission = action.clone();
    permission.request.operation = compatibility_permission_operation("fixture.write");
    bind_gateway_authority_decision_digest(&mut permission);
    vec![action, adapter, permission]
}

fn basic_live_authority_gateway(adapter: Arc<CountingAdapter>) -> VerifiedActionGateway {
    let mut gateway = VerifiedActionGateway::new(Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    }));
    gateway.register_adapter("noop", "adapter", adapter);
    gateway
}

#[test]
fn live_authority_fails_closed_for_incomplete_status_and_evidence_paths() {
    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    request.action.required_permissions = vec!["fixture.write".to_string()];
    let calls = Arc::new(AtomicUsize::new(0));
    let adapter = Arc::new(CountingAdapter::default());
    let mut gateway = basic_live_authority_gateway(adapter.clone());

    for (decisions, expected_status, expected_reason) in [
        (
            Vec::new(),
            ActionStatus::NeedsIntervention,
            "authority_decision_unavailable",
        ),
        (
            live_decisions_with_status(&request, AuthorityDecisionStatus::NeedsApproval),
            ActionStatus::NeedsApproval,
            "capability_conditional",
        ),
        (
            live_decisions_with_status(&request, AuthorityDecisionStatus::NeedsIntervention),
            ActionStatus::NeedsIntervention,
            "capability_conditional",
        ),
    ] {
        gateway.set_action_authority_evaluator(Arc::new(FixedLiveAuthorityEvaluator {
            decisions,
            calls: Arc::clone(&calls),
        }));
        let outcome = gateway.submit(request.clone()).expect("typed outcome");
        assert_eq!(outcome.status, expected_status);
        assert!(outcome
            .verification
            .reasons
            .contains(&expected_reason.to_string()));
    }

    let mut wrong_scope = live_decisions_with_status(&request, AuthorityDecisionStatus::Allowed);
    wrong_scope[0].request.scope.run_ids = None;
    gateway.set_action_authority_evaluator(Arc::new(FixedLiveAuthorityEvaluator {
        decisions: wrong_scope,
        calls: Arc::clone(&calls),
    }));
    let outcome = gateway.submit(request.clone()).expect("scope outcome");
    assert_eq!(outcome.status, ActionStatus::NeedsIntervention);
    assert!(outcome
        .verification
        .reasons
        .contains(&"authority_decision_request_mismatch".to_string()));

    let mut missing_grant = live_decisions_with_status(&request, AuthorityDecisionStatus::Allowed);
    missing_grant[0].matched_grant_ids.clear();
    gateway.set_action_authority_evaluator(Arc::new(FixedLiveAuthorityEvaluator {
        decisions: missing_grant,
        calls: Arc::clone(&calls),
    }));
    let outcome = gateway.submit(request.clone()).expect("grant outcome");
    assert_eq!(outcome.status, ActionStatus::NeedsIntervention);
    assert!(outcome
        .verification
        .reasons
        .contains(&"authority_decision_grant_evidence_missing".to_string()));

    gateway.set_action_authority_evaluator(Arc::new(FixedLiveAuthorityEvaluator {
        decisions: live_decisions_with_status(&request, AuthorityDecisionStatus::Allowed),
        calls: Arc::clone(&calls),
    }));
    let outcome = gateway.submit(request.clone()).expect("recorder outcome");
    assert_eq!(outcome.status, ActionStatus::NeedsIntervention);
    assert!(outcome
        .verification
        .reasons
        .contains(&"authority_evidence_append_failed".to_string()));
    assert_eq!(
        outcome
            .verification
            .artifacts
            .get("recorder_reason")
            .and_then(serde_json::Value::as_str),
        Some("authority_evidence_recorder_unavailable")
    );

    let (_issuer, _context, evidence) = authority_evidence_for(
        &request,
        request.adapter.as_deref().expect("adapter"),
        OffsetDateTime::now_utc(),
    );
    let mut raw_receipt_request = request.clone();
    raw_receipt_request.authority_obligation_receipts = evidence.receipts.clone();
    gateway.set_action_authority_evaluator(Arc::new(FixedLiveAuthorityEvaluator {
        decisions: live_decisions_with_status(&request, AuthorityDecisionStatus::Allowed),
        calls: Arc::clone(&calls),
    }));
    let outcome = gateway
        .submit(raw_receipt_request.clone())
        .expect("unexpected receipt outcome");
    assert_eq!(outcome.status, ActionStatus::Denied);
    assert!(outcome.verification.reasons.contains(
        &"authority_obligation_receipts_without_current_conditional_decision".to_string()
    ));

    gateway.set_action_authority_evaluator(Arc::new(NoActionAuthorityEvaluator));
    let outcome = gateway
        .submit(raw_receipt_request.clone())
        .expect("missing evaluator outcome");
    assert_eq!(outcome.status, ActionStatus::NeedsIntervention);
    assert!(outcome
        .verification
        .reasons
        .contains(&"authority_obligation_current_decision_evaluator_unavailable".to_string()));

    let mut conditional_decisions =
        live_decisions_with_status(&request, AuthorityDecisionStatus::Conditional);
    let representative = conditional_decisions[0].clone();
    for decision in &mut conditional_decisions {
        decision.matched_grant_ids = representative.matched_grant_ids.clone();
        decision.obligations = representative.obligations.clone();
        bind_gateway_authority_decision_digest(decision);
    }
    gateway.set_action_authority_evaluator(Arc::new(FixedLiveAuthorityEvaluator {
        decisions: conditional_decisions,
        calls: Arc::clone(&calls),
    }));
    raw_receipt_request.authority_obligation_evidence = Some(evidence);
    let outcome = gateway
        .submit(raw_receipt_request)
        .expect("ambiguous receipt outcome");
    assert_eq!(outcome.status, ActionStatus::NeedsIntervention);
    assert!(outcome
        .verification
        .reasons
        .contains(&"requester_authority_decision_non_authorizing".to_string()));
    assert_eq!(*adapter.calls.lock().expect("adapter calls"), 0);
}

fn assert_authority_denied(
    mut request: ActionRequest,
    context: AuthorityObligationReceiptValidationContext,
    reason: &str,
    expected_status: ActionStatus,
) {
    let adapter = Arc::new(CountingAdapter::default());
    request.adapter = Some("adapter".to_string());
    let outcome = authority_gateway(context, adapter.clone())
        .submit(request)
        .expect("outcome");
    assert_eq!(outcome.status, expected_status);
    assert!(
        outcome.verification.reasons.contains(&reason.to_string()),
        "expected {reason}, got {:?}",
        outcome.verification.reasons
    );
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn authority_obligation_valid_exact_receipt_allows_adapter_execution() {
    let now = OffsetDateTime::now_utc();
    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    let (_issuer, context, evidence) = authority_evidence_for(&request, "adapter", now);
    request.authority_obligation_evidence = Some(evidence);
    let adapter = Arc::new(CountingAdapter::default());

    let outcome = authority_gateway(context, adapter.clone())
        .submit(request)
        .expect("outcome");

    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 1);
    assert_eq!(
        outcome.verification.artifacts["authority_obligation"]["authority_obligation_status"]
            .as_str(),
        Some("satisfied")
    );
    let authority_artifact = &outcome.verification.artifacts["authority_obligation"];
    assert_eq!(
        authority_artifact["decision_status"].as_str(),
        Some("conditional")
    );
    assert!(authority_artifact["authority_decision_evidence_digest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("blake3:")));
    assert_eq!(
        authority_artifact["authority_decision_evidence_completeness"].as_str(),
        Some("decision_only")
    );
    assert_eq!(
        authority_artifact["authority_decision_explanation"][0]["category"].as_str(),
        Some("obligations_gate")
    );
    assert_eq!(
        authority_artifact["authority_decision_explanation"][0]["reason_codes"][0].as_str(),
        Some("capability_conditional")
    );
    assert!(authority_artifact["authority_decision_evidence_unavailable"].is_null());
    let artifact_json = serde_json::to_string(authority_artifact).expect("artifact JSON");
    assert!(!artifact_json.contains("gateway obligation satisfied by authority receipt"));
}

#[test]
fn authority_obligation_supplied_without_configured_verifier_needs_intervention() {
    let now = OffsetDateTime::now_utc();
    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    let (_issuer, _context, evidence) = authority_evidence_for(&request, "adapter", now);
    request.authority_obligation_evidence = Some(evidence);
    let adapter = Arc::new(CountingAdapter::default());
    let mut gateway = VerifiedActionGateway::new(Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    }));
    gateway.register_adapter("noop", "adapter", adapter.clone());

    let outcome = gateway.submit(request).expect("outcome");

    assert_eq!(outcome.status, ActionStatus::NeedsIntervention);
    assert!(outcome
        .verification
        .reasons
        .contains(&"authority_obligation_verifier_unavailable".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn authority_obligation_untrusted_paths_do_not_project_hostile_decision_details() {
    let now = OffsetDateTime::now_utc();
    let hostile = hostile_authority_values();

    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    let (_issuer, context, mut evidence) = authority_evidence_for(&request, "adapter", now);
    poison_authority_decision(&mut evidence.decision, &hostile);
    let expected_decision_id = evidence.decision.decision_id.to_string();
    let expected_obligation_ids = evidence
        .decision
        .obligations
        .iter()
        .map(|obligation| obligation.obligation_id.to_string())
        .collect::<Vec<_>>();
    let expected_receipt_ids = evidence
        .receipts
        .iter()
        .map(|receipt| receipt.receipt_id.to_string())
        .collect::<Vec<_>>();
    request.authority_obligation_evidence = Some(evidence);

    let assert_safe_denial_coordinates = |artifact: &serde_json::Value| {
        assert_eq!(
            artifact["decision_id"].as_str(),
            Some(expected_decision_id.as_str())
        );
        assert_eq!(artifact["decision_status"].as_str(), Some("conditional"));
        assert_eq!(
            artifact["obligation_ids"],
            serde_json::json!(expected_obligation_ids)
        );
        assert_eq!(
            artifact["receipt_ids"],
            serde_json::json!(expected_receipt_ids)
        );
        assert!(artifact["gateway_action_request_digest"].is_null());
        assert!(artifact["authority_decision_digest"].is_null());
        assert!(artifact["authority_decision_evidence_digest"].is_null());
        assert!(artifact["authority_decision_evidence_completeness"].is_null());
        assert!(artifact["authority_decision_explanation"].is_null());
        assert_eq!(artifact["satisfied_obligation_ids"], serde_json::json!([]));
    };

    let adapter = Arc::new(CountingAdapter::default());
    let mut gateway = VerifiedActionGateway::new(Arc::new(TestTenantAccess {
        policy: VerificationResult::allow(),
        quota: VerificationResult::allow(),
    }));
    gateway.register_adapter("noop", "adapter", adapter.clone());
    let no_verifier = gateway
        .submit(request.clone())
        .expect("no-verifier outcome");
    assert_eq!(no_verifier.status, ActionStatus::NeedsIntervention);
    assert_hostile_authority_values_absent(&no_verifier.verification.artifacts, &hostile);
    assert_safe_denial_coordinates(&no_verifier.verification.artifacts);
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);

    let adapter = Arc::new(CountingAdapter::default());
    let denied = authority_gateway(context, adapter.clone())
        .submit(request)
        .expect("early-denial outcome");
    assert_eq!(denied.status, ActionStatus::Denied);
    assert_hostile_authority_values_absent(&denied.verification.artifacts, &hostile);
    assert_safe_denial_coordinates(&denied.verification.artifacts);
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn authority_obligation_trusted_receipt_projects_only_normalized_explanation() {
    let now = OffsetDateTime::now_utc();
    let hostile = hostile_authority_values();
    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    let (context, evidence) = hostile_authority_evidence_for(&request, "adapter", now, &hostile);
    request.authority_obligation_evidence = Some(evidence);
    let adapter = Arc::new(CountingAdapter::default());

    let outcome = authority_gateway(context, adapter.clone())
        .submit(request)
        .expect("trusted receipt outcome");

    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 1);
    let artifact = &outcome.verification.artifacts["authority_obligation"];
    assert_hostile_authority_values_absent(artifact, &hostile);
    assert_eq!(
        artifact["authority_decision_explanation"],
        serde_json::json!([{
            "category": "provider_unknown",
            "reason_codes": ["authority_reason_unknown"]
        }])
    );
    assert!(artifact["authority_decision_evidence_digest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("blake3:")));
}

#[test]
fn authority_obligation_malformed_decision_identity_is_rejected_before_projection() {
    let now = OffsetDateTime::now_utc();
    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    let (_issuer, context, mut evidence) = authority_evidence_for(&request, "adapter", now);
    evidence.decision.decision_id =
        AuthorityDecisionId::parse("00000000-0000-0000-0000-000000000000")
            .expect("nil decision ID");
    bind_gateway_authority_decision_digest(&mut evidence.decision);
    request.authority_obligation_evidence = Some(evidence);
    let adapter = Arc::new(CountingAdapter::default());

    let outcome = authority_gateway(context, adapter.clone())
        .submit(request)
        .expect("malformed identity outcome");

    assert_eq!(outcome.status, ActionStatus::Denied);
    assert!(outcome
        .verification
        .reasons
        .iter()
        .any(|reason| reason == "obligation_receipt_request_digest_mismatch"));
    assert!(outcome.verification.artifacts["authority_decision_evidence_digest"].is_null());
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn authority_obligation_required_missing_evidence_blocks_adapter_execution() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let context = gateway_authority_context(issuer, now);
    let request = base_request();

    assert_authority_denied(
        request,
        context,
        "authority_obligation_evidence_required",
        ActionStatus::NeedsIntervention,
    );
}

#[test]
fn authority_obligation_requirement_matchers_preserve_optional_default() {
    let now = OffsetDateTime::now_utc();
    let context = gateway_authority_context(PrincipalId::new(), now);

    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    let adapter = Arc::new(CountingAdapter::default());
    let outcome = authority_gateway_with_verifier(
        Arc::new(LocalAuthorityObligationVerifier::new(context.clone())),
        adapter.clone(),
    )
    .submit(request)
    .expect("outcome");
    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 1);

    assert_authority_denied(
        base_request(),
        context.clone(),
        "authority_obligation_evidence_required",
        ActionStatus::NeedsIntervention,
    );

    let mut mismatched_adapter_request = base_request();
    mismatched_adapter_request.adapter = Some("adapter".to_string());
    let adapter = Arc::new(CountingAdapter::default());
    let outcome = authority_gateway_with_verifier(
        Arc::new(LocalAuthorityObligationVerifier::requiring(
            context.clone(),
            vec![AuthorityObligationRequirement::action_adapter(
                "noop", "other",
            )],
        )),
        adapter.clone(),
    )
    .submit(mismatched_adapter_request)
    .expect("outcome");
    assert_eq!(outcome.status, ActionStatus::Executed);
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 1);

    let mut matching_adapter_request = base_request();
    matching_adapter_request.adapter = Some("adapter".to_string());
    let adapter = Arc::new(CountingAdapter::default());
    let outcome = authority_gateway_with_verifier(
        Arc::new(LocalAuthorityObligationVerifier::requiring(
            context,
            vec![
                AuthorityObligationRequirement::action("other_action"),
                AuthorityObligationRequirement::action_adapter("noop", "adapter"),
            ],
        )),
        adapter.clone(),
    )
    .submit(matching_adapter_request)
    .expect("outcome");
    assert_eq!(outcome.status, ActionStatus::NeedsIntervention);
    assert!(outcome
        .verification
        .reasons
        .contains(&"authority_obligation_evidence_required".to_string()));
    assert_eq!(*adapter.calls.lock().expect("calls lock"), 0);
}

#[test]
fn authority_obligation_raw_or_forged_receipt_blocks_adapter_execution() {
    let now = OffsetDateTime::now_utc();
    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let context = gateway_authority_context(issuer.clone(), now);
    let decision = authority_decision_for(&request, "adapter", subject, now);
    request.authority_obligation_evidence = Some(GatewayAuthorityObligationEvidence {
        receipts: vec![unsigned_obligation_receipt(&decision, issuer, now)],
        decision,
    });

    assert_authority_denied(
        request,
        context,
        "obligation_receipt_validation_digest_mismatch",
        ActionStatus::Denied,
    );
}

#[test]
fn authority_obligation_changed_action_digest_blocks_adapter_execution() {
    let now = OffsetDateTime::now_utc();
    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    let (_issuer, context, evidence) = authority_evidence_for(&request, "adapter", now);
    request.action.params = serde_json::json!({"ok": false, "changed": true});
    request.authority_obligation_evidence = Some(evidence);

    assert_authority_denied(
        request,
        context,
        "authority_decision_action_digest_mismatch",
        ActionStatus::Denied,
    );
}

#[test]
fn authority_obligation_tampered_decision_digest_blocks_adapter_execution() {
    let now = OffsetDateTime::now_utc();
    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    let (_issuer, context, mut evidence) = authority_evidence_for(&request, "adapter", now);
    evidence.decision.obligations.push(AuthorityObligation {
        schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
        obligation_id: splendor_types::AuthorityObligationId::new(),
        kind: AuthorityObligationKind::HumanReview,
        description: "tampered obligation added after receipt issuance".to_string(),
        parameters: BTreeMap::new(),
    });
    request.authority_obligation_evidence = Some(evidence);

    assert_authority_denied(
        request,
        context,
        "authority_decision_digest_mismatch",
        ActionStatus::Denied,
    );
}

#[test]
fn authority_obligation_rebound_tampered_decision_fails_receipt_digest() {
    let now = OffsetDateTime::now_utc();
    let mut request = base_request();
    request.adapter = Some("adapter".to_string());
    let (_issuer, context, mut evidence) = authority_evidence_for(&request, "adapter", now);
    evidence.decision.obligations.push(AuthorityObligation {
        schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
        obligation_id: splendor_types::AuthorityObligationId::new(),
        kind: AuthorityObligationKind::HumanReview,
        description: "tampered obligation added and rebound".to_string(),
        parameters: BTreeMap::new(),
    });
    bind_gateway_authority_decision_digest(&mut evidence.decision);
    request.authority_obligation_evidence = Some(evidence);

    assert_authority_denied(
        request,
        context,
        "obligation_receipt_request_digest_mismatch",
        ActionStatus::Denied,
    );
}

#[test]
fn authority_obligation_malformed_decision_metadata_blocks_adapter_execution() {
    let now = OffsetDateTime::now_utc();
    for case in [
        "non_conditional",
        "missing_action_digest",
        "missing_decision_digest",
        "verifier_unavailable",
    ] {
        let mut request = base_request();
        request.adapter = Some("adapter".to_string());
        let (issuer, context, mut evidence) = authority_evidence_for(&request, "adapter", now);
        let (context, reason, status) = match case {
            "non_conditional" => {
                evidence.decision.status = AuthorityDecisionStatus::Allowed;
                (
                    context,
                    "authority_decision_not_conditional",
                    ActionStatus::Denied,
                )
            }
            "missing_action_digest" => {
                evidence
                    .decision
                    .request
                    .metadata
                    .remove(GATEWAY_AUTHORITY_ACTION_DIGEST_METADATA_KEY);
                (
                    context,
                    "authority_decision_action_digest_missing",
                    ActionStatus::Denied,
                )
            }
            "missing_decision_digest" => {
                evidence
                    .decision
                    .request
                    .metadata
                    .remove(GATEWAY_AUTHORITY_DECISION_DIGEST_METADATA_KEY);
                (
                    context,
                    "authority_decision_digest_missing",
                    ActionStatus::Denied,
                )
            }
            "verifier_unavailable" => (
                AuthorityObligationReceiptValidationContext::trusted_local(
                    issuer,
                    OBLIGATION_RECEIPT_AUDIENCE,
                    OBLIGATION_RECEIPT_KEY_ID,
                    "",
                    OBLIGATION_RECEIPT_REVOCATION_REF,
                    now,
                ),
                "obligation_receipt_validation_secret_unavailable",
                ActionStatus::NeedsIntervention,
            ),
            _ => unreachable!("covered cases"),
        };
        request.authority_obligation_evidence = Some(evidence);

        assert_authority_denied(request, context, reason, status);
    }
}

#[test]
fn authority_obligation_operation_and_scope_mismatch_block_adapter_execution() {
    let now = OffsetDateTime::now_utc();
    for case in ["operation", "tenant", "agent", "run"] {
        let mut request = base_request();
        request.adapter = Some("adapter".to_string());
        let (_issuer, context, mut evidence) = authority_evidence_for(&request, "adapter", now);
        let reason = match case {
            "operation" => {
                evidence.decision.request.operation = gateway_action_operation("other_action");
                bind_gateway_authority_decision_digest(&mut evidence.decision);
                "authority_decision_operation_mismatch"
            }
            "tenant" => {
                evidence.decision.request.scope.tenant_ids = Some(vec![TenantId::new()]);
                bind_gateway_authority_decision_digest(&mut evidence.decision);
                "authority_decision_tenant_scope_mismatch"
            }
            "agent" => {
                evidence.decision.request.scope.agent_ids = Some(vec![AgentId::new()]);
                bind_gateway_authority_decision_digest(&mut evidence.decision);
                "authority_decision_agent_scope_mismatch"
            }
            "run" => {
                evidence.decision.request.scope.run_ids = Some(vec![RunId::new()]);
                bind_gateway_authority_decision_digest(&mut evidence.decision);
                "authority_decision_run_scope_mismatch"
            }
            _ => unreachable!("covered cases"),
        };
        request.authority_obligation_evidence = Some(evidence);

        assert_authority_denied(request, context, reason, ActionStatus::Denied);
    }
}

#[test]
fn authority_obligation_bad_receipts_block_adapter_execution() {
    let now = OffsetDateTime::now_utc();
    for case in [
        "expired",
        "revoked",
        "wrong_decision",
        "wrong_kind",
        "duplicate",
        "extra",
    ] {
        let mut request = base_request();
        request.adapter = Some("adapter".to_string());
        let (issuer, context, mut evidence) = authority_evidence_for(&request, "adapter", now);
        let reason = match case {
            "expired" => {
                let mut receipt =
                    unsigned_obligation_receipt(&evidence.decision, issuer.clone(), now);
                receipt.expires_at = now - time::Duration::seconds(1);
                evidence.receipts = vec![issue_obligation_receipt(receipt, &context)];
                "obligation_receipt_expired"
            }
            "revoked" => {
                let mut receipt =
                    unsigned_obligation_receipt(&evidence.decision, issuer.clone(), now);
                receipt.revocation = RevocationStatus::Revoked {
                    reason: "test_revoked".to_string(),
                };
                evidence.receipts = vec![issue_obligation_receipt(receipt, &context)];
                "obligation_receipt_revoked"
            }
            "wrong_decision" => {
                let mut receipt =
                    unsigned_obligation_receipt(&evidence.decision, issuer.clone(), now);
                receipt.authority_decision_id = AuthorityDecisionId::new();
                evidence.receipts = vec![issue_obligation_receipt(receipt, &context)];
                "obligation_receipt_decision_mismatch"
            }
            "wrong_kind" => {
                let mut receipt =
                    unsigned_obligation_receipt(&evidence.decision, issuer.clone(), now);
                receipt.kind = AuthorityObligationKind::HumanReview;
                evidence.receipts = vec![issue_obligation_receipt(receipt, &context)];
                "obligation_receipt_kind_mismatch"
            }
            "duplicate" => {
                let duplicate = evidence.receipts[0].clone();
                evidence.receipts.push(duplicate);
                "duplicate_obligation_receipt_id"
            }
            "extra" => {
                let mut extra =
                    unsigned_obligation_receipt(&evidence.decision, issuer.clone(), now);
                extra.receipt_id = AuthorityObligationReceiptId::new();
                extra.obligation_id = splendor_types::AuthorityObligationId::new();
                evidence
                    .receipts
                    .push(issue_obligation_receipt(extra, &context));
                "extra_obligation_receipt"
            }
            _ => unreachable!("covered cases"),
        };
        request.authority_obligation_evidence = Some(evidence);

        assert_authority_denied(request, context, reason, ActionStatus::Denied);
    }
}

#[test]
fn legacy_approval_evidence_alone_does_not_satisfy_authority_obligations() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let context = gateway_authority_context(issuer, now);
    let mut request = base_request();
    request.approval_evidence = Some(approval_evidence_for(&request));

    assert_authority_denied(
        request,
        context,
        "authority_obligation_evidence_required",
        ActionStatus::NeedsIntervention,
    );
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
fn action_params_cannot_forge_approval_or_outcome_authority() {
    let mut request = base_request();
    request.action.params = serde_json::json!({
        "approved": true,
        "approval_granted": true,
        "approval_evidence": {"decision": "granted"},
        "verification": {"allowed": true},
        "status": "executed",
        "outcome": {"status": "executed", "output": {"ok": true}},
    });
    let adapter = Arc::new(CountingAdapter::default());
    let gateway = approval_gateway(&request, adapter.clone());

    let outcome = gateway.submit(request).expect("outcome");

    assert_eq!(outcome.status, ActionStatus::NeedsApproval);
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
    assert!(outcome.output.is_none());
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
