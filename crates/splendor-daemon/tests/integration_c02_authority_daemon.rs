use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use splendor_daemon::{
    router, CreateRunRequest, CreateRunResponse, DaemonActionCandidate, DaemonConfig, DaemonState,
    LifecycleRequest, RegisteredAction, ReplayResponse, RunInspectResponse, SubmitActionRequest,
    TickResponse, TracePageResponse,
};
use splendor_gateway::{ActionOutcome, ActionStatus};
use splendor_store::{InMemoryTraceStore, TraceRecord, TraceStore, TraceStoreError};
use splendor_types::{
    Action, AgentId, AuditAttribution, AuthorityDecisionStatus, CallerCredential, ClientPrincipal,
    CredentialAudience, CredentialBinding, EndpointScope, QuotaUsage, RevocationStatus, RunId,
    SideEffectClass, TenantId, TraceEvent, TraceEventKind, TraceId, WorkOrder, WorkOrderEnvelope,
    WorkOrderId, WorkOrderPlacement, WorkOrderQuotaPolicy, WORK_ORDER_SCHEMA_VERSION,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

const ACTION: &str = "fixture.write";
const ADAPTER: &str = "fixture.local";
const PERMISSION: &str = "fixture.write";

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

impl TraceStore for FailingAuthorityEvidenceStore {
    fn append(&self, run_id: &str, payload: Value) -> Result<u64, TraceStoreError> {
        let is_authority_allow = serde_json::from_value::<TraceEvent>(payload.clone())
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
            });
        if is_authority_allow && self.fail_next_authority_allow.swap(false, Ordering::SeqCst) {
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
                authority_obligation_receipts: Vec::new(),
            })
            .into_iter()
            .collect(),
        policy_bundle_required: false,
        policy_bundle: None,
        registered_actions: vec![RegisteredAction {
            name: ACTION.to_string(),
            adapter: ADAPTER.to_string(),
        }],
        approval_policies: Vec::new(),
        circuit_breakers: Vec::new(),
        allowed_percept_schemas: Vec::new(),
        allowed_percept_sources: Vec::new(),
        initial_state: Some(json!({"c02": true})),
        snapshot_interval: Some(1),
    }
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
    let causal = traces(app.clone(), &created.run_id)
        .await
        .records
        .first()
        .and_then(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .map(|event| event.trace_event_id)
        .unwrap_or_else(|| TraceId::from_run_sequence(&created.run_id, 0));
    let (status, outcome) = call_json(
        app,
        Method::POST,
        "/actions",
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
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    outcome
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

#[tokio::test]
async fn public_daemon_paths_enforce_live_c02_authority_evidence_and_replay() {
    let state = DaemonState::local_dev();
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
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tick.action_outcomes[0].status, ActionStatus::Executed);

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
    assert_eq!(
        allowed
            .verification
            .artifacts
            .pointer("/authority/pre_effect_recorded")
            .and_then(Value::as_bool),
        Some(true)
    );

    for denied in [
        submit(
            app.clone(),
            &created,
            tenant_id.clone(),
            agent_id.clone(),
            action("fixture.outside", PERMISSION),
            ADAPTER,
        )
        .await,
        submit(
            app.clone(),
            &created,
            tenant_id.clone(),
            agent_id.clone(),
            action(ACTION, PERMISSION),
            "fixture.outside_adapter",
        )
        .await,
        submit(
            app.clone(),
            &created,
            tenant_id.clone(),
            agent_id.clone(),
            action(ACTION, "fixture.outside_permission"),
            ADAPTER,
        )
        .await,
    ] {
        assert_eq!(denied.status, ActionStatus::Denied);
        assert!(denied
            .verification
            .reasons
            .iter()
            .any(|reason| reason == "operation_not_granted"));
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
    let replay_credential = replay_credential(tenant_id.clone());
    let replay_audit = AuditAttribution {
        principal: replay_credential.principal.clone(),
        credential_id: Some(replay_credential.credential_id.clone()),
        requested_at: OffsetDateTime::now_utc(),
    };
    let (status, replay): (StatusCode, ReplayResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({
            "mode": "inspect_only",
            "side_effects_allowed": false,
            "credential": replay_credential,
            "audit_attribution": replay_audit,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(replay.authority_decisions.len() >= 2);
    assert!(replay.authority_decisions.iter().any(|event| event
        .decisions
        .iter()
        .any(|decision| decision.status == AuthorityDecisionStatus::Denied)));
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
    let failing_state = DaemonState::with_trace_store(
        DaemonConfig::local_dev(),
        failing_store.clone() as Arc<dyn TraceStore>,
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
