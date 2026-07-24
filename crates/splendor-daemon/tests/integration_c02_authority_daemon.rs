mod support;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use splendor_daemon::caller_auth::{
    CallerTokenSigner, CallerTokenTrustSnapshot, CallerTokenVerifier,
};
use splendor_daemon::{
    router, ApiErrorBody, ConfiguredActionAdapters, CreateRunRequest, CreateRunResponse,
    DaemonActionCandidate, DaemonConfig, DaemonState, DevicePolicyCacheStatus,
    DeviceRuntimeProfile, DeviceTraceBufferStatus, LifecycleRequest, RegisterDeviceProfileRequest,
    RegisteredAction, ReplayResponse, RunInspectResponse, RunStatus, SafetyContext,
    SubmitActionRequest, SubmitPhysicalActionRequest, TickResponse, TracePageResponse,
};
use splendor_gateway::{
    ActionAdapter, ActionOutcome, ActionRequest, ActionStatus, AdapterError, AdapterResult,
};
use splendor_kernel::LocalAuthorityObligationReceiptConfig;
use splendor_store::{InMemoryTraceStore, TraceRecord, TraceStore, TraceStoreError};
use splendor_types::{
    Action, ActionId, AgentId, ApprovalDecision, ApprovalEvidence, ApprovalId, ApprovalPolicy,
    AuditAttribution, AuthorityDecisionStatus, CallerCredential, ClientPrincipal,
    CredentialAudience, CredentialBinding, EndpointScope, InstanceId, NodeId, PrincipalId,
    QuotaUsage, RevocationStatus, RunId, SideEffectClass, TenantId, TickId, TraceEvent,
    TraceEventId, TraceEventKind, TraceId, WorkOrder, WorkOrderEnvelope, WorkOrderId,
    WorkOrderPlacement, WorkOrderQuotaPolicy, FORBIDDEN_PHYSICAL_ACTION_PATTERNS,
    WORK_ORDER_SCHEMA_VERSION,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

const ACTION: &str = "fixture.write";
const ADAPTER: &str = "fixture.local";
const PERMISSION: &str = "fixture.write";

struct BlockingActionAdapter {
    adapter_id: String,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ActionAdapter for BlockingActionAdapter {
    fn execute(&self, action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        self.entered
            .lock()
            .map_err(|_| AdapterError::Failed("blocking_adapter_poisoned".to_string()))?
            .take()
            .ok_or_else(|| AdapterError::Failed("blocking_adapter_reentered".to_string()))?
            .send(())
            .map_err(|_| AdapterError::Failed("blocking_adapter_signal_failed".to_string()))?;
        self.release
            .lock()
            .map_err(|_| AdapterError::Failed("blocking_adapter_poisoned".to_string()))?
            .recv()
            .map_err(|_| AdapterError::Failed("blocking_adapter_release_failed".to_string()))?;
        Ok(AdapterResult {
            output: json!({
                "schema_version": "splendor.test.provider_receipt.v1",
                "provider_receipt_id": format!("blocking-provider:{}", action.action_id),
                "adapter_id": self.adapter_id,
                "action_id": action.action_id,
                "action_name": action.action.name,
                "accepted": true,
            }),
            satisfied_postconditions: action.action.postconditions.clone(),
        })
    }
}

fn blocking_action_adapters(
    adapter_id: &str,
) -> (
    ConfiguredActionAdapters,
    mpsc::Receiver<()>,
    mpsc::Sender<()>,
) {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let mut adapters = ConfiguredActionAdapters::new();
    adapters
        .insert(
            adapter_id,
            Arc::new(BlockingActionAdapter {
                adapter_id: adapter_id.to_string(),
                entered: Mutex::new(Some(entered_tx)),
                release: Mutex::new(release_rx),
            }),
        )
        .expect("blocking action adapter");
    (adapters, entered_rx, release_tx)
}

#[derive(Default)]
struct FailingAuthorityEvidenceStore {
    inner: InMemoryTraceStore,
    fail_next_authority_allow: AtomicBool,
}

impl FailingAuthorityEvidenceStore {
    fn arm(&self) {
        self.fail_next_authority_allow.store(true, Ordering::SeqCst);
    }
}

fn is_authority_allow(payload: &Value) -> bool {
    serde_json::from_value::<TraceEvent>(payload.clone())
        .ok()
        .is_some_and(|event| match event.kind {
            TraceEventKind::ActionVerificationCompleted { result, .. } => {
                result
                    .artifacts
                    .pointer("/authority/pre_effect_recorded")
                    .and_then(Value::as_bool)
                    == Some(true)
            }
            _ => false,
        })
}

impl TraceStore for FailingAuthorityEvidenceStore {
    fn append(&self, run_id: &str, payload: Value) -> Result<u64, TraceStoreError> {
        if is_authority_allow(&payload)
            && self.fail_next_authority_allow.swap(false, Ordering::SeqCst)
        {
            return Err(TraceStoreError::Poisoned);
        }
        self.inner.append(run_id, payload)
    }

    fn read(&self, run_id: &str) -> Result<Vec<TraceRecord>, TraceStoreError> {
        self.inner.read(run_id)
    }

    fn read_range(
        &self,
        run_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<TraceRecord>, TraceStoreError> {
        self.inner.read_range(run_id, start, end)
    }
}

fn audit() -> AuditAttribution {
    AuditAttribution {
        principal: ClientPrincipal::new("app_c02", "client_c02"),
        credential_id: None,
        requested_at: OffsetDateTime::now_utc(),
    }
}

fn replay_credential(tenant_id: TenantId) -> CallerCredential {
    CallerCredential {
        credential_id: "cred_c02_replay".to_string(),
        principal: ClientPrincipal::new("app_c02", "client_c02"),
        scopes: vec![EndpointScope::ReplayCreate],
        binding: CredentialBinding::Tenant { tenant_id },
        audience: CredentialAudience::Daemon {
            daemon_id: "daemon_local".to_string(),
        },
        expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
        revocation: RevocationStatus::Active,
    }
}

fn credential_audit(credential: &CallerCredential) -> AuditAttribution {
    AuditAttribution {
        principal: credential.principal.clone(),
        credential_id: Some(credential.credential_id.clone()),
        requested_at: OffsetDateTime::now_utc(),
    }
}

fn action(name: &str, adapter_permission: &str) -> Action {
    Action {
        name: name.to_string(),
        params: json!({"fixture": true}),
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: vec![adapter_permission.to_string()],
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    }
}

fn signed_work_order(
    id: &str,
    tenant_id: TenantId,
    agent_id: AgentId,
    expires_at: OffsetDateTime,
) -> WorkOrderEnvelope {
    WorkOrderEnvelope::signed_with_shared_secret(
        WorkOrder {
            schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
            work_order_id: WorkOrderId::try_new(id).expect("work order id"),
            tenant_id,
            agent_id,
            run_id: None,
            objective: "C02 production-local integration".to_string(),
            allowed_actions: vec![ACTION.to_string()],
            allowed_adapters: vec![ADAPTER.to_string()],
            allowed_permissions: vec![PERMISSION.to_string()],
            data_refs: Vec::new(),
            quotas: WorkOrderQuotaPolicy::default(),
            placement: WorkOrderPlacement::default(),
            issued_at: OffsetDateTime::now_utc() - Duration::minutes(1),
            expires_at,
            revocation: RevocationStatus::Active,
        },
        "work-order-local-key",
        b"splendor-local-work-order-secret",
    )
    .expect("signed work order")
}

fn resign_local_work_order(envelope: &mut WorkOrderEnvelope) {
    *envelope = WorkOrderEnvelope::signed_with_shared_secret(
        envelope.work_order.clone(),
        "work-order-local-key",
        b"splendor-local-work-order-secret",
    )
    .expect("re-signed local work order");
}

fn create_request(
    id: &str,
    tenant_id: TenantId,
    agent_id: AgentId,
    expires_at: OffsetDateTime,
    scheduler_action: bool,
) -> CreateRunRequest {
    CreateRunRequest {
        request_id: format!("req_{id}"),
        idempotency_key: format!("idem_{id}"),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        work_order: signed_work_order(id, tenant_id, agent_id, expires_at),
        credential: None,
        audit_attribution: Some(audit()),
        allowed_actions: vec![ACTION.to_string()],
        allowed_adapters: vec![ADAPTER.to_string()],
        allowed_permissions: vec![PERMISSION.to_string()],
        policy_actions: scheduler_action
            .then(|| DaemonActionCandidate {
                action_id: None,
                action: action(ACTION, PERMISSION),
                adapter: Some(ADAPTER.to_string()),
                quota_usage: Some(QuotaUsage::single_action()),
                satisfied_preconditions: Vec::new(),
                requested_at: None,
                authority_obligation_receipts: Vec::new(),
            })
            .into_iter()
            .collect(),
        policy_bundle_required: false,
        policy_bundle: None,
        registered_actions: vec![RegisteredAction {
            name: ACTION.to_string(),
            adapter: ADAPTER.to_string(),
            required_permissions: Some(vec![PERMISSION.to_string()]),
        }],
        approval_policies: Vec::new(),
        circuit_breakers: Vec::new(),
        allowed_percept_schemas: Vec::new(),
        allowed_percept_sources: Vec::new(),
        initial_state: Some(json!({"c02": true})),
        snapshot_interval: Some(1),
    }
}

fn physical_action() -> Action {
    Action {
        name: "move_to_waypoint".to_string(),
        params: json!({"zone_ref": "zone_a"}),
        side_effect_class: SideEffectClass::Custom("physical.high_level".to_string()),
        cost_estimate: None,
        required_permissions: vec!["device.motion".to_string()],
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    }
}

fn physical_create_request(id: &str, tenant_id: TenantId, agent_id: AgentId) -> CreateRunRequest {
    let work_order = WorkOrderEnvelope::signed_with_shared_secret(
        WorkOrder {
            schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
            work_order_id: WorkOrderId::try_new(id).expect("physical work order id"),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: None,
            objective: "C02 physical lifecycle concurrency".to_string(),
            allowed_actions: vec!["move_to_waypoint".to_string()],
            allowed_adapters: vec!["device-sim".to_string()],
            allowed_permissions: vec!["device.motion".to_string()],
            data_refs: vec!["device:c02".to_string()],
            quotas: WorkOrderQuotaPolicy::default(),
            placement: WorkOrderPlacement::default(),
            issued_at: OffsetDateTime::now_utc() - Duration::minutes(1),
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
            revocation: RevocationStatus::Active,
        },
        "work-order-local-key",
        b"splendor-local-work-order-secret",
    )
    .expect("signed physical work order");
    CreateRunRequest {
        request_id: format!("req_{id}"),
        idempotency_key: format!("idem_{id}"),
        tenant_id,
        agent_id,
        work_order,
        credential: None,
        audit_attribution: Some(audit()),
        allowed_actions: vec!["move_to_waypoint".to_string()],
        allowed_adapters: vec!["device-sim".to_string()],
        allowed_permissions: vec!["device.motion".to_string()],
        policy_actions: Vec::new(),
        policy_bundle_required: false,
        policy_bundle: None,
        registered_actions: vec![RegisteredAction {
            name: "move_to_waypoint".to_string(),
            adapter: "device-sim".to_string(),
            required_permissions: Some(vec!["device.motion".to_string()]),
        }],
        approval_policies: Vec::new(),
        circuit_breakers: Vec::new(),
        allowed_percept_schemas: Vec::new(),
        allowed_percept_sources: Vec::new(),
        initial_state: None,
        snapshot_interval: None,
    }
}

fn device_profile(node_id: NodeId, tenant_id: TenantId) -> DeviceRuntimeProfile {
    DeviceRuntimeProfile {
        node_id,
        tenant_id,
        device_kind: "drone_sim".to_string(),
        capabilities: vec!["motion.waypoint".to_string()],
        allowed_physical_actions: vec!["move_to_waypoint".to_string()],
        forbidden_action_classes: FORBIDDEN_PHYSICAL_ACTION_PATTERNS
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        safety_constraints: json!({
            "min_battery_percent": 0.25,
            "max_altitude_m": 30.0,
            "allowed_zones": ["zone_a"]
        }),
        runtime_mode: "resident".to_string(),
        safety_status: json!({
            "battery_percent": 0.80,
            "emergency_stop_clear": true,
            "collision_risk": "low",
            "current_zone": "zone_a",
            "altitude_m": 10.0,
            "privacy_clear": true,
            "human_proximity_clear": true,
            "offline": false,
            "cloud_helper_direct_authority": false
        }),
        policy_cache: DevicePolicyCacheStatus {
            policy_id: "policy_c02_concurrency".to_string(),
            loaded: true,
            ttl_seconds: 300,
            expires_at: (OffsetDateTime::now_utc() + Duration::minutes(5))
                .format(&time::format_description::well_known::Rfc3339)
                .expect("policy cache expiry"),
            expired: false,
        },
        trace_buffer: DeviceTraceBufferStatus {
            enabled: true,
            buffered_records: 0,
            integrity: "hash_chain_v1".to_string(),
        },
        registered_at: "pending".to_string(),
    }
}

fn physical_submit_request(
    created: &CreateRunResponse,
    tenant_id: TenantId,
    agent_id: AgentId,
    causal_trace_id: splendor_types::TraceEventId,
) -> SubmitPhysicalActionRequest {
    SubmitPhysicalActionRequest {
        action_request: SubmitActionRequest {
            action_id: None,
            run_id: created.run_id.clone(),
            tenant_id,
            agent_id,
            credential: None,
            audit_attribution: Some(audit()),
            causal_trace_id: Some(causal_trace_id),
            action: physical_action(),
            adapter: Some("device-sim".to_string()),
            quota_usage: Some(QuotaUsage::single_action()),
            satisfied_preconditions: Vec::new(),
            requested_at: None,
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        },
        safety_context: SafetyContext {
            allowed_zone_refs: vec!["zone_a".to_string()],
            zone_ref: Some("zone_a".to_string()),
            altitude_m: Some(10.0),
            max_altitude_m: Some(30.0),
            battery_percent: Some(0.80),
            privacy_clear: true,
            human_proximity_clear: true,
            emergency_stop_clear: true,
            offline: false,
            policy_cache_expired: false,
            high_risk: false,
            cloud_helper_direct_authority: false,
            cloud_helper_proposal_id: None,
        },
        operator_intervention_evidence: None,
    }
}

fn local_approval_receipt_config() -> LocalAuthorityObligationReceiptConfig {
    LocalAuthorityObligationReceiptConfig::trusted_local(
        PrincipalId::parse("00000000-0000-4000-8000-0000000004c0").expect("local receipt issuer"),
        "splendor.daemon.run",
        "approval-receipt-local-key",
        "splendor-local-approval-receipt-secret-v1",
        "local-approval-receipts",
    )
    .expect("local approval receipt config")
}

async fn call_json<T: DeserializeOwned>(
    app: axum::Router,
    method: Method,
    uri: &str,
    value: impl serde::Serialize,
) -> (StatusCode, T) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&value).expect("request JSON"),
        ))
        .expect("request");
    let response = app.oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response bytes");
    let parsed = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "response JSON failed ({status}): {error}; body={}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, parsed)
}

async fn call_json_with_token<T: DeserializeOwned>(
    app: axum::Router,
    method: Method,
    uri: &str,
    value: impl serde::Serialize,
    token: &str,
) -> (StatusCode, T) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&value).expect("request JSON"),
        ))
        .expect("request");
    let response = app.oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response bytes");
    let parsed = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "response JSON failed ({status}): {error}; body={}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, parsed)
}

async fn call_empty_with_token<T: DeserializeOwned>(
    app: axum::Router,
    method: Method,
    uri: &str,
    credential: &CallerCredential,
    token: &str,
) -> (StatusCode, T) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header(
            "x-splendor-caller-credential",
            serde_json::to_string(credential).expect("credential JSON"),
        )
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response bytes");
    let parsed = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "response JSON ({status}): {error}; body={}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, parsed)
}

async fn traces(app: axum::Router, run_id: &RunId) -> TracePageResponse {
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/runs/{run_id}/traces?redaction_policy=operator"))
        .body(Body::empty())
        .expect("trace request");
    let response = app.oneshot(request).await.expect("trace response");
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("trace bytes"),
    )
    .expect("trace page")
}

async fn submit(
    app: axum::Router,
    created: &CreateRunResponse,
    tenant_id: TenantId,
    agent_id: AgentId,
    requested_action: Action,
    adapter: &str,
) -> ActionOutcome {
    let request = submit_request(
        app.clone(),
        created,
        tenant_id,
        agent_id,
        requested_action,
        adapter,
    )
    .await;
    let (status, outcome) = call_json(app, Method::POST, "/actions", request).await;
    assert_eq!(status, StatusCode::OK);
    outcome
}

async fn submit_request(
    app: axum::Router,
    created: &CreateRunResponse,
    tenant_id: TenantId,
    agent_id: AgentId,
    requested_action: Action,
    adapter: &str,
) -> SubmitActionRequest {
    let causal = traces(app.clone(), &created.run_id)
        .await
        .records
        .first()
        .and_then(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .map(|event| event.trace_event_id)
        .unwrap_or_else(|| TraceId::from_run_sequence(&created.run_id, 0));
    SubmitActionRequest {
        action_id: None,
        run_id: created.run_id.clone(),
        tenant_id,
        agent_id,
        credential: None,
        audit_attribution: Some(audit()),
        causal_trace_id: Some(causal),
        action: requested_action,
        adapter: Some(adapter.to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    }
}

async fn inspect(app: axum::Router, run_id: &RunId) -> RunInspectResponse {
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/runs/{run_id}"))
        .body(Body::empty())
        .expect("inspect request");
    let response = app.oneshot(request).await.expect("inspect response");
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("inspect bytes"),
    )
    .expect("inspect response")
}

async fn assert_direct_action_trace(
    app: axum::Router,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    action_id: &splendor_types::ActionId,
) {
    let events = traces(app, run_id)
        .await
        .records
        .into_iter()
        .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload).ok())
        .filter(|event| event.identity.action_id.as_ref() == Some(action_id))
        .collect::<Vec<_>>();
    assert!(!events.is_empty(), "action-scoped trace events");
    assert!(events.iter().all(|event| {
        event.identity.run_id == *run_id
            && event.identity.tenant_id.as_ref() == Some(tenant_id)
            && event.identity.agent_id.as_ref() == Some(agent_id)
            && event.identity.action_id.as_ref() == Some(action_id)
            && event.identity.tick_id.is_none()
    }));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::ActionVerificationStarted { .. }))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event.kind,
                TraceEventKind::ActionVerificationCompleted { .. }
            ))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event.kind,
                TraceEventKind::ActionExecuted { .. }
                    | TraceEventKind::ActionDenied { .. }
                    | TraceEventKind::ActionNeedsApproval { .. }
                    | TraceEventKind::ActionNeedsIntervention { .. }
                    | TraceEventKind::ActionFailed { .. }
            ))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::OutcomeRecorded { .. }))
            .count(),
        1
    );
}

#[tokio::test]
async fn public_daemon_paths_enforce_live_c02_authority_evidence_and_replay() {
    let state = support::local_state(&[ADAPTER]);
    let app = router(state.clone());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        create_request(
            "wo_c02_live",
            tenant_id.clone(),
            agent_id.clone(),
            OffsetDateTime::now_utc() + Duration::minutes(5),
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, tick): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        LifecycleRequest {
            credential: None,
            work_order: None,
            audit_attribution: Some(audit()),
            reason: Some("C02 scheduler path".to_string()),
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tick.action_outcomes[0].status, ActionStatus::Executed);
    let scheduler_action_id = tick.action_outcomes[0].action_id.clone();
    let scheduler_events = traces(app.clone(), &created.run_id)
        .await
        .records
        .into_iter()
        .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload).ok())
        .filter(|event| event.identity.action_id.as_ref() == Some(&scheduler_action_id))
        .collect::<Vec<_>>();
    assert!(scheduler_events
        .iter()
        .all(|event| { event.identity.tick_id.as_ref() == Some(&TickId::from(tick.tick_id)) }));
    let started = scheduler_events
        .iter()
        .position(|event| matches!(event.kind, TraceEventKind::ActionVerificationStarted { .. }))
        .expect("verification started");
    let completions = scheduler_events
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            matches!(
                event.kind,
                TraceEventKind::ActionVerificationCompleted { .. }
            )
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(completions.len(), 1);
    let terminal = scheduler_events
        .iter()
        .position(|event| matches!(event.kind, TraceEventKind::ActionExecuted { .. }))
        .expect("terminal action event");
    assert!(started < completions[0] && completions[0] < terminal);

    let allowed = submit(
        app.clone(),
        &created,
        tenant_id.clone(),
        agent_id.clone(),
        action(ACTION, PERMISSION),
        ADAPTER,
    )
    .await;
    assert_eq!(allowed.status, ActionStatus::Executed);
    let mut direct_action_ids = vec![allowed.action_id.clone()];
    assert_direct_action_trace(
        app.clone(),
        &created.run_id,
        &tenant_id,
        &agent_id,
        &allowed.action_id,
    )
    .await;
    assert_eq!(
        allowed
            .verification
            .artifacts
            .pointer("/authority/pre_effect_recorded")
            .and_then(Value::as_bool),
        Some(true)
    );

    let mut omitted_permission_action = action(ACTION, PERMISSION);
    omitted_permission_action.required_permissions.clear();
    for (denied, expected_reason) in [
        (
            submit(
                app.clone(),
                &created,
                tenant_id.clone(),
                agent_id.clone(),
                action("fixture.outside", PERMISSION),
                ADAPTER,
            )
            .await,
            "trusted_action_profile_missing",
        ),
        (
            submit(
                app.clone(),
                &created,
                tenant_id.clone(),
                agent_id.clone(),
                action(ACTION, PERMISSION),
                "fixture.outside_adapter",
            )
            .await,
            "trusted_action_profile_adapter_mismatch",
        ),
        (
            submit(
                app.clone(),
                &created,
                tenant_id.clone(),
                agent_id.clone(),
                action(ACTION, "fixture.outside_permission"),
                ADAPTER,
            )
            .await,
            "trusted_action_profile_permission_mismatch",
        ),
        (
            submit(
                app.clone(),
                &created,
                tenant_id.clone(),
                agent_id.clone(),
                omitted_permission_action,
                ADAPTER,
            )
            .await,
            "trusted_action_profile_permission_mismatch",
        ),
    ] {
        assert_eq!(denied.status, ActionStatus::Denied);
        assert!(denied
            .verification
            .reasons
            .iter()
            .any(|reason| reason == expected_reason));
        assert_direct_action_trace(
            app.clone(),
            &created.run_id,
            &tenant_id,
            &agent_id,
            &denied.action_id,
        )
        .await;
        direct_action_ids.push(denied.action_id.clone());
    }
    assert_eq!(
        inspect(app.clone(), &created.run_id)
            .await
            .adapter_executions,
        2
    );

    let evaluations_before_replay = state
        .run_authority_evaluation_count(&created.run_id)
        .expect("evaluation count");
    let executions_before_replay = inspect(app.clone(), &created.run_id)
        .await
        .adapter_executions;
    let replay_caller_credential = replay_credential(tenant_id.clone());
    let replay_audit = AuditAttribution {
        principal: replay_caller_credential.principal.clone(),
        credential_id: Some(replay_caller_credential.credential_id.clone()),
        requested_at: OffsetDateTime::now_utc(),
    };
    let (status, replay): (StatusCode, ReplayResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({
            "mode": "inspect_only",
            "side_effects_allowed": false,
            "credential": replay_caller_credential,
            "audit_attribution": replay_audit,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(replay.authority_decisions.len() >= 2);
    assert!(replay.authority_decisions.iter().all(|event| event
        .decisions
        .iter()
        .all(|decision| !decision.decision_digest.is_empty())));
    assert_eq!(
        state
            .run_authority_evaluation_count(&created.run_id)
            .expect("post-replay evaluation count"),
        evaluations_before_replay
    );
    assert_eq!(
        inspect(app.clone(), &created.run_id)
            .await
            .adapter_executions,
        executions_before_replay
    );
    for action_id in &direct_action_ids {
        assert_direct_action_trace(
            app.clone(),
            &created.run_id,
            &tenant_id,
            &agent_id,
            action_id,
        )
        .await;
    }

    state
        .revoke_run_authority_for_local_control(&created.run_id, audit())
        .expect("local authority revocation");
    let revoked = submit(
        app.clone(),
        &created,
        tenant_id.clone(),
        agent_id.clone(),
        action(ACTION, PERMISSION),
        ADAPTER,
    )
    .await;
    assert_eq!(revoked.status, ActionStatus::Denied);
    assert!(revoked
        .verification
        .reasons
        .contains(&"authority_grant_revoked".to_string()));
    assert_eq!(
        inspect(app.clone(), &created.run_id)
            .await
            .adapter_executions,
        2
    );
    let evaluations_after_revocation = state
        .run_authority_evaluation_count(&created.run_id)
        .expect("revoked evaluation count");
    let revoked_replay_credential = replay_credential(tenant_id.clone());
    let revoked_replay_audit = AuditAttribution {
        principal: revoked_replay_credential.principal.clone(),
        credential_id: Some(revoked_replay_credential.credential_id.clone()),
        requested_at: OffsetDateTime::now_utc(),
    };
    let (status, revoked_replay): (StatusCode, ReplayResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({
            "mode": "inspect_only",
            "side_effects_allowed": false,
            "credential": revoked_replay_credential,
            "audit_attribution": revoked_replay_audit,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(revoked_replay.authority_decisions.iter().any(|event| event
        .decisions
        .iter()
        .any(|decision| decision.status == AuthorityDecisionStatus::Denied)));
    assert_eq!(
        state
            .run_authority_evaluation_count(&created.run_id)
            .expect("post-revoked-replay evaluation count"),
        evaluations_after_revocation
    );

    let expiring_tenant = TenantId::new();
    let expiring_agent = AgentId::new();
    let (status, expiring): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        create_request(
            "wo_c02_expiring",
            expiring_tenant.clone(),
            expiring_agent.clone(),
            OffsetDateTime::now_utc() + Duration::milliseconds(250),
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    std::thread::sleep(std::time::Duration::from_millis(350));
    let expired = submit(
        app.clone(),
        &expiring,
        expiring_tenant,
        expiring_agent,
        action(ACTION, PERMISSION),
        ADAPTER,
    )
    .await;
    assert_eq!(expired.status, ActionStatus::Denied);
    assert!(expired
        .verification
        .reasons
        .contains(&"expired_grant".to_string()));
    assert_eq!(inspect(app, &expiring.run_id).await.adapter_executions, 0);

    let failing_store = Arc::new(FailingAuthorityEvidenceStore::default());
    let failing_state = support::state_with_trace_store(
        DaemonConfig::local_dev(),
        failing_store.clone() as Arc<dyn TraceStore>,
        &[ADAPTER],
    );
    let failing_app = router(failing_state);
    let failing_tenant = TenantId::new();
    let failing_agent = AgentId::new();
    let (status, failing_run): (StatusCode, CreateRunResponse) = call_json(
        failing_app.clone(),
        Method::POST,
        "/runs",
        create_request(
            "wo_c02_evidence_failure",
            failing_tenant.clone(),
            failing_agent.clone(),
            OffsetDateTime::now_utc() + Duration::minutes(5),
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    failing_store.arm();
    let failed_evidence = submit(
        failing_app.clone(),
        &failing_run,
        failing_tenant,
        failing_agent,
        action(ACTION, PERMISSION),
        ADAPTER,
    )
    .await;
    assert_eq!(failed_evidence.status, ActionStatus::NeedsIntervention);
    assert!(failed_evidence
        .verification
        .reasons
        .contains(&"authority_evidence_append_failed".to_string()));
    assert_eq!(
        inspect(failing_app, &failing_run.run_id)
            .await
            .adapter_executions,
        0
    );
}

#[tokio::test]
async fn run_admission_rejects_ambiguous_or_narrowed_compatibility_profiles() {
    let app = router(DaemonState::local_dev());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();

    let mut narrowed = create_request(
        "wo_c02_narrowed_profile",
        tenant_id.clone(),
        agent_id.clone(),
        OffsetDateTime::now_utc() + Duration::minutes(5),
        false,
    );
    narrowed
        .work_order
        .work_order
        .allowed_permissions
        .push("fixture.audit".to_string());
    resign_local_work_order(&mut narrowed.work_order);
    let (status, error): (StatusCode, ApiErrorBody) =
        call_json(app.clone(), Method::POST, "/runs", narrowed).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "work_order_permission_profile_mismatch");

    let mut ambiguous = create_request(
        "wo_c02_ambiguous_adapter",
        tenant_id.clone(),
        agent_id.clone(),
        OffsetDateTime::now_utc() + Duration::minutes(5),
        false,
    );
    ambiguous
        .work_order
        .work_order
        .allowed_adapters
        .push("fixture.secondary".to_string());
    resign_local_work_order(&mut ambiguous.work_order);
    let (status, error): (StatusCode, ApiErrorBody) =
        call_json(app.clone(), Method::POST, "/runs", ambiguous).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "ambiguous_work_order_action_adapter_profile");

    for (label, permissions, expected_code) in [
        (
            "duplicate_permissions",
            vec![PERMISSION.to_string(), PERMISSION.to_string()],
            "registered_action_required_permissions_duplicate",
        ),
        (
            "permission_limit",
            vec![PERMISSION.to_string(); 65],
            "registered_action_required_permissions_limit_exceeded",
        ),
    ] {
        let mut invalid = create_request(
            &format!("wo_c02_{label}"),
            tenant_id.clone(),
            agent_id.clone(),
            OffsetDateTime::now_utc() + Duration::minutes(5),
            false,
        );
        invalid.registered_actions[0].required_permissions = Some(permissions);
        let (status, error): (StatusCode, ApiErrorBody) =
            call_json(app.clone(), Method::POST, "/runs", invalid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
        assert_eq!(error.code, expected_code, "{label}");
    }
}

#[tokio::test]
async fn resident_daemon_verified_caller_preserves_c02_effect_authority() {
    let instance_id = InstanceId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let scopes = vec![
        EndpointScope::RunsCreate,
        EndpointScope::RunsStart,
        EndpointScope::RunsRead,
        EndpointScope::ActionsSubmit,
        EndpointScope::TracesRead,
        EndpointScope::ReplayCreate,
    ];
    let signer = CallerTokenSigner::generate_for_test(
        "urn:splendor:manager:c02-test",
        "app_c02_resident",
        "client_c02_resident",
        "c02-resident-key",
    )
    .expect("signer");
    let trust = CallerTokenTrustSnapshot::single_key(
        signer.issuer(),
        signer.app_principal_id(),
        signer.kid(),
        &signer.public_key_bytes(),
        scopes.clone(),
        OffsetDateTime::now_utc(),
    );
    let verifier = CallerTokenVerifier::new(trust, instance_id.clone()).expect("verifier");
    let local = DaemonConfig::local_dev();
    let state = support::state(
        DaemonConfig::resident(
            instance_id.clone(),
            verifier,
            local.work_order_keyring,
            local.policy_bundle_keyring,
        ),
        &[ADAPTER],
    );
    let app = router(state.clone());
    let signed = signer
        .sign(
            &tenant_id,
            &instance_id,
            scopes,
            OffsetDateTime::now_utc(),
            Duration::minutes(1),
        )
        .expect("caller token");
    let credential = signed.credential.clone();
    let unauthenticated_body = serde_json::to_vec(&json!({
        "credential": credential,
        "audit_attribution": credential_audit(&signed.credential),
    }))
    .expect("unauthenticated body");
    let unauthenticated = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/runs")
                .header("content-type", "application/json")
                .body(Body::from(unauthenticated_body))
                .expect("request"),
        )
        .await
        .expect("router response");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthenticated
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer realm=\"splendor-resident\", error=\"invalid_token\"")
    );
    let unauthenticated_body = to_bytes(unauthenticated.into_body(), usize::MAX)
        .await
        .expect("unauthenticated response body");
    let unauthenticated_error: ApiErrorBody =
        serde_json::from_slice(&unauthenticated_body).expect("api error");
    assert_eq!(unauthenticated_error.code, "missing_caller_token");

    for (label, token) in [
        ("malformed", "not-a-jws".to_string()),
        (
            "oversized",
            "a".repeat(splendor_daemon::caller_auth::MAX_CALLER_TOKEN_BYTES + 1),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{label}");
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("error response");
        let text = String::from_utf8(bytes.to_vec()).expect("utf8 response");
        assert!(!text.contains(&token), "{label} token leaked in response");
        assert!(
            !text.contains(&signed.encoded),
            "valid token leaked in response"
        );
    }

    let wrong_tenant_token = signer
        .sign(
            &TenantId::new(),
            &instance_id,
            vec![EndpointScope::RunsCreate],
            OffsetDateTime::now_utc(),
            Duration::minutes(1),
        )
        .expect("wrong-tenant token remains cryptographically valid");
    let wrong_scope_token = signer
        .sign(
            &tenant_id,
            &instance_id,
            vec![EndpointScope::RunsRead],
            OffsetDateTime::now_utc(),
            Duration::minutes(1),
        )
        .expect("wrong-scope token remains cryptographically valid");
    for (label, token, expected_code) in [
        (
            "wrong_tenant_proof",
            wrong_tenant_token,
            "wrong_credential_binding",
        ),
        ("wrong_scope_proof", wrong_scope_token, "missing_scope"),
    ] {
        let mut denied = create_request(
            &format!("wo_c02_resident_{label}"),
            tenant_id.clone(),
            agent_id.clone(),
            OffsetDateTime::now_utc() + Duration::minutes(10),
            false,
        );
        denied.credential = Some(token.credential.clone());
        denied.audit_attribution = Some(credential_audit(&token.credential));
        let (status, error): (StatusCode, ApiErrorBody) =
            call_json_with_token(app.clone(), Method::POST, "/runs", denied, &token.encoded).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{label}");
        assert_eq!(error.code, expected_code, "{label}");
    }
    let mut create = create_request(
        "wo_c02_resident",
        tenant_id.clone(),
        agent_id.clone(),
        OffsetDateTime::now_utc() + Duration::minutes(5),
        true,
    );
    create.credential = Some(credential.clone());
    create.audit_attribution = Some(credential_audit(&credential));
    let (status, created): (StatusCode, CreateRunResponse) =
        call_json_with_token(app.clone(), Method::POST, "/runs", create, &signed.encoded).await;
    assert_eq!(status, StatusCode::OK);

    let start_signed = signer
        .sign(
            &tenant_id,
            &instance_id,
            vec![EndpointScope::RunsStart],
            OffsetDateTime::now_utc(),
            Duration::minutes(1),
        )
        .expect("fresh start token");
    let lifecycle = LifecycleRequest {
        credential: Some(start_signed.credential.clone()),
        work_order: None,
        audit_attribution: Some(credential_audit(&start_signed.credential)),
        reason: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, tick): (StatusCode, TickResponse) = call_json_with_token(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        lifecycle,
        &start_signed.encoded,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tick.action_outcomes.len(), 1);
    assert_eq!(tick.action_outcomes[0].status, ActionStatus::Executed);

    let (status, trace_page): (StatusCode, TracePageResponse) = call_empty_with_token(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=redacted", created.run_id),
        &credential,
        &signed.encoded,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resident_events = trace_page
        .records
        .iter()
        .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .collect::<Vec<_>>();
    assert!(!resident_events.is_empty());
    assert!(resident_events
        .iter()
        .all(|event| event.identity.instance_id.as_ref() == Some(&instance_id)));
    let causal_trace_id = resident_events
        .iter()
        .map(|event| event.trace_event_id.clone())
        .next()
        .expect("resident run causal trace");

    let action_signed = signer
        .sign(
            &tenant_id,
            &instance_id,
            vec![EndpointScope::ActionsSubmit],
            OffsetDateTime::now_utc(),
            Duration::minutes(1),
        )
        .expect("fresh action token");
    let submit_request = SubmitActionRequest {
        action_id: None,
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: Some(action_signed.credential.clone()),
        audit_attribution: Some(credential_audit(&action_signed.credential)),
        causal_trace_id: Some(causal_trace_id),
        action: action(ACTION, PERMISSION),
        adapter: Some(ADAPTER.to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, direct): (StatusCode, ActionOutcome) = call_json_with_token(
        app.clone(),
        Method::POST,
        "/actions",
        submit_request,
        &action_signed.encoded,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(direct.status, ActionStatus::Executed);
    let evaluations_before_replay = state
        .run_authority_evaluation_count(&created.run_id)
        .expect("resident authority count");

    let replay_signed = signer
        .sign(
            &tenant_id,
            &instance_id,
            vec![EndpointScope::ReplayCreate],
            OffsetDateTime::now_utc(),
            Duration::minutes(1),
        )
        .expect("fresh replay token");
    let replay_audit = credential_audit(&replay_signed.credential);
    let (status, replay): (StatusCode, ReplayResponse) = call_json_with_token(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({
            "mode": "inspect_only",
            "side_effects_allowed": false,
            "credential": replay_signed.credential.clone(),
            "audit_attribution": replay_audit,
        }),
        &replay_signed.encoded,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!replay.authority_decisions.is_empty());
    assert_eq!(
        state
            .run_authority_evaluation_count(&created.run_id)
            .expect("resident replay authority count"),
        evaluations_before_replay
    );
    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty_with_token(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
        &credential,
        &signed.encoded,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.adapter_executions, 2);

    let invalid_cases = {
        let valid = credential.clone();
        let mut wrong_tenant = valid.clone();
        wrong_tenant.binding = CredentialBinding::Tenant {
            tenant_id: TenantId::new(),
        };
        let mut wrong_audience = valid.clone();
        wrong_audience.audience = CredentialAudience::Daemon {
            daemon_id: "daemon_local".to_string(),
        };
        let mut expired = valid.clone();
        expired.expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);
        let mut revoked = valid;
        revoked.revocation = RevocationStatus::Revoked {
            reason: "resident credential revoked".to_string(),
        };
        vec![
            ("wrong_tenant", wrong_tenant),
            ("wrong_audience", wrong_audience),
            ("expired", expired),
            ("revoked", revoked),
        ]
    };
    for (label, invalid) in invalid_cases {
        let valid_bearer = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                OffsetDateTime::now_utc(),
                Duration::minutes(1),
            )
            .expect("fresh mirror-validation token");
        let mut request = create_request(
            &format!("wo_c02_resident_{label}"),
            tenant_id.clone(),
            AgentId::new(),
            OffsetDateTime::now_utc() + Duration::minutes(5),
            false,
        );
        request.credential = Some(invalid.clone());
        request.audit_attribution = Some(credential_audit(&invalid));
        let (status, error): (StatusCode, ApiErrorBody) = call_json_with_token(
            app.clone(),
            Method::POST,
            "/runs",
            request,
            &valid_bearer.encoded,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{label}");
        assert_eq!(error.code, "caller_credential_mirror_mismatch", "{label}");
    }
}

#[tokio::test]
async fn physical_approval_uses_exact_one_use_receipt_and_never_legacy_grant() {
    let app = router(support::local_state(&["device-sim"]));
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let node_id = NodeId::new();
    let mut create = physical_create_request(
        "wo_c02_physical_approval",
        tenant_id.clone(),
        agent_id.clone(),
    );
    let mut approval_policy = ApprovalPolicy::new(
        "physical-waypoint-approval",
        tenant_id.clone(),
        "physical waypoint requires exact approval receipt",
    );
    approval_policy.agent_id = Some(agent_id.clone());
    approval_policy.action_name = Some("move_to_waypoint".to_string());
    approval_policy.adapter = Some("device-sim".to_string());
    approval_policy.required_permission = Some("device.motion".to_string());
    approval_policy.side_effect_class =
        Some(SideEffectClass::Custom("physical.high_level".to_string()));
    approval_policy.risk_level = Some("physical".to_string());
    create.approval_policies = vec![approval_policy];
    let (status, created): (StatusCode, CreateRunResponse) =
        call_json(app.clone(), Method::POST, "/runs", create).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _registered): (StatusCode, Value) = call_json(
        app.clone(),
        Method::POST,
        "/devices/profiles",
        RegisterDeviceProfileRequest {
            credential: None,
            audit_attribution: Some(audit()),
            profile: device_profile(node_id.clone(), tenant_id.clone()),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let causal_trace_id = traces(app.clone(), &created.run_id)
        .await
        .records
        .into_iter()
        .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload).ok())
        .map(|event| event.trace_event_id)
        .next()
        .expect("physical approval causal trace");
    let action_id = ActionId::new();
    let requested_at = OffsetDateTime::now_utc();
    let mut submit = physical_submit_request(
        &created,
        tenant_id.clone(),
        agent_id.clone(),
        causal_trace_id,
    );
    submit.action_request.action_id = Some(action_id.clone());
    submit.action_request.requested_at = Some(requested_at);
    let uri = format!("/devices/{node_id}/actions");
    let (status, required): (StatusCode, ActionOutcome) =
        call_json(app.clone(), Method::POST, &uri, submit.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(required.status, ActionStatus::NeedsApproval);
    let challenge = required
        .approval_challenge
        .clone()
        .expect("physical exact approval challenge");
    assert_eq!(challenge.action_id, action_id);
    assert_eq!(challenge.requested_at, requested_at);
    assert_eq!(
        challenge
            .physical_action_resource_coordinate
            .as_ref()
            .map(|coordinate| &coordinate.node_id),
        Some(&node_id)
    );
    assert_eq!(
        inspect(app.clone(), &created.run_id)
            .await
            .adapter_executions,
        0
    );

    let mut legacy = ApprovalEvidence::new(
        ApprovalId::new(),
        tenant_id,
        agent_id,
        created.run_id.clone(),
        ApprovalDecision::Granted,
        OffsetDateTime::now_utc() + Duration::minutes(5),
    )
    .with_action_name("move_to_waypoint")
    .with_adapter("device-sim");
    legacy.action_id = Some(action_id);
    let mut forged_legacy = submit.clone();
    forged_legacy.action_request.approval_evidence = Some(legacy);
    let trace_count_before_raw_grant = traces(app.clone(), &created.run_id).await.records.len();
    let (status, error): (StatusCode, ApiErrorBody) =
        call_json(app.clone(), Method::POST, &uri, forged_legacy).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "legacy_approval_evidence_non_authorizing");
    let after_raw_grant = inspect(app.clone(), &created.run_id).await;
    assert_eq!(after_raw_grant.status, RunStatus::WaitingForApproval);
    assert_eq!(after_raw_grant.adapter_executions, 0);
    assert_eq!(
        traces(app.clone(), &created.run_id).await.records.len(),
        trace_count_before_raw_grant,
        "transport-rejected raw grant must not append daemon/runtime trace"
    );

    let receipt = local_approval_receipt_config()
        .issue_approval_receipt(&challenge, TraceEventId::new(), OffsetDateTime::now_utc())
        .expect("physical approval receipt");
    let mut altered = submit.clone();
    altered.action_request.action.params = json!({"zone_ref": "zone_b"});
    altered.action_request.authority_obligation_receipts = vec![receipt.clone()];
    let (status, error): (StatusCode, ApiErrorBody) =
        call_json(app.clone(), Method::POST, &uri, altered).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "approval_challenge_retry_mismatch");
    assert_eq!(
        inspect(app.clone(), &created.run_id)
            .await
            .adapter_executions,
        0
    );

    submit.action_request.authority_obligation_receipts = vec![receipt];
    let (status, executed): (StatusCode, ActionOutcome) =
        call_json(app.clone(), Method::POST, &uri, submit.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(executed.status, ActionStatus::Executed);
    let inspected = inspect(app.clone(), &created.run_id).await;
    assert_eq!(inspected.status, RunStatus::Running);
    assert_eq!(inspected.adapter_executions, 1);

    let (status, replayed): (StatusCode, ActionOutcome) =
        call_json(app.clone(), Method::POST, &uri, submit).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replayed.status, ActionStatus::Denied);
    assert!(replayed
        .verification
        .reasons
        .contains(&"authority_obligation_receipt_replayed".to_string()));
    assert_eq!(inspect(app, &created.run_id).await.adapter_executions, 1);
}

async fn assert_blocked_handler_lifecycle_linearization(physical: bool, cancel: bool) {
    let adapter_id = if physical { "device-sim" } else { ADAPTER };
    let (adapters, entered, release) = blocking_action_adapters(adapter_id);
    let state = DaemonState::with_action_adapters(DaemonConfig::local_dev(), adapters);
    let app = router(state);
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let other_tenant_id = TenantId::new();
    let other_agent_id = AgentId::new();

    let primary_create = if physical {
        physical_create_request(
            "wo_c02_physical_concurrency",
            tenant_id.clone(),
            agent_id.clone(),
        )
    } else {
        create_request(
            "wo_c02_direct_concurrency",
            tenant_id.clone(),
            agent_id.clone(),
            OffsetDateTime::now_utc() + Duration::minutes(5),
            false,
        )
    };
    let other_create = if physical {
        physical_create_request("wo_c02_physical_other_run", other_tenant_id, other_agent_id)
    } else {
        create_request(
            "wo_c02_direct_other_run",
            other_tenant_id,
            other_agent_id,
            OffsetDateTime::now_utc() + Duration::minutes(5),
            false,
        )
    };
    let (status, primary): (StatusCode, CreateRunResponse) =
        call_json(app.clone(), Method::POST, "/runs", primary_create).await;
    assert_eq!(status, StatusCode::OK);
    let (status, other): (StatusCode, CreateRunResponse) =
        call_json(app.clone(), Method::POST, "/runs", other_create).await;
    assert_eq!(status, StatusCode::OK);

    let node_id = NodeId::new();
    if physical {
        let (status, _registered): (StatusCode, Value) = call_json(
            app.clone(),
            Method::POST,
            "/devices/profiles",
            RegisterDeviceProfileRequest {
                credential: None,
                audit_attribution: Some(audit()),
                profile: device_profile(node_id.clone(), tenant_id.clone()),
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    let causal_trace_id = traces(app.clone(), &primary.run_id)
        .await
        .records
        .into_iter()
        .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload).ok())
        .map(|event| event.trace_event_id)
        .next()
        .expect("primary causal trace");
    let (action_uri, action_body) = if physical {
        (
            format!("/devices/{node_id}/actions"),
            serde_json::to_value(physical_submit_request(
                &primary,
                tenant_id.clone(),
                agent_id.clone(),
                causal_trace_id,
            ))
            .expect("physical action request"),
        )
    } else {
        (
            "/actions".to_string(),
            serde_json::to_value(SubmitActionRequest {
                action_id: None,
                run_id: primary.run_id.clone(),
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                credential: None,
                audit_attribution: Some(audit()),
                causal_trace_id: Some(causal_trace_id),
                action: action(ACTION, PERMISSION),
                adapter: Some(ADAPTER.to_string()),
                quota_usage: Some(QuotaUsage::single_action()),
                satisfied_preconditions: Vec::new(),
                requested_at: None,
                approval_evidence: None,
                authority_obligation_receipts: Vec::new(),
            })
            .expect("direct action request"),
        )
    };
    let post_close_body = action_body.clone();
    let action_app = app.clone();
    let action_uri_for_task = action_uri.clone();
    let action_task = tokio::spawn(async move {
        call_json::<ActionOutcome>(action_app, Method::POST, &action_uri_for_task, action_body)
            .await
    });
    entered
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("adapter entered after final permit");

    let lifecycle_uri = format!(
        "/runs/{}/{}",
        primary.run_id,
        if cancel { "cancel" } else { "stop" }
    );
    let lifecycle_app = app.clone();
    let lifecycle_task = tokio::spawn(async move {
        call_json::<RunInspectResponse>(
            lifecycle_app,
            Method::POST,
            &lifecycle_uri,
            LifecycleRequest {
                credential: None,
                work_order: None,
                audit_attribution: Some(audit()),
                reason: Some("blocked adapter lifecycle closure".to_string()),
                approval_evidence: None,
                authority_obligation_receipts: Vec::new(),
            },
        )
        .await
    });

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if inspect(app.clone(), &primary.run_id).await.status == RunStatus::Cancelled {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal status becomes inspectable while adapter is blocked");
    assert!(
        !lifecycle_task.is_finished(),
        "stop/cancel must wait for the earlier final permit"
    );
    assert_eq!(
        inspect(app.clone(), &other.run_id).await.status,
        RunStatus::Pending,
        "unrelated run inspection must not wait for blocked effect"
    );

    let (status, error): (StatusCode, ApiErrorBody) =
        call_json(app.clone(), Method::POST, &action_uri, post_close_body).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "run_not_effect_capable");

    release.send(()).expect("release blocking adapter");
    let (status, outcome) = action_task.await.expect("action task");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(outcome.status, ActionStatus::Executed, "{outcome:?}");
    let (status, stopped) = lifecycle_task.await.expect("lifecycle task");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stopped.status, RunStatus::Cancelled);
    let final_inspect = inspect(app, &primary.run_id).await;
    assert_eq!(final_inspect.status, RunStatus::Cancelled);
    assert_eq!(final_inspect.adapter_executions, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_action_handlers_release_run_ownership_during_blocked_effects() {
    assert_blocked_handler_lifecycle_linearization(false, false).await;
    assert_blocked_handler_lifecycle_linearization(true, true).await;
}
