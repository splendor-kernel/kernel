mod support;

use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::{Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use serde::de::DeserializeOwned;
use serde::Serialize;
use splendor_daemon::caller_auth::{
    CallerTokenSigner, CallerTokenTrustSnapshot, CallerTokenVerifier, SignedCallerToken,
};
use splendor_daemon::manager::{
    router as manager_router, ApprovalDecisionRequest, ApprovalRequestPayload, DispatchReport,
    DispatchWorkOrderRequest, GovernanceApprovalRecord, ManagerApiErrorBody, ManagerAuditEvent,
    ManagerReadRequest, ManagerSecurityFields, ManagerState, PlacementEvaluationRequest,
    RegisterInstanceRequest, RegisterNodeRequest, ResidentDispatchOptions, RevokeWorkOrderRequest,
    SubmitWorkOrderRequest, WorkOrderValidationReport,
};
use splendor_daemon::{
    router as resident_router, ApiErrorBody, CreateRunRequest, CreateRunResponse, DaemonConfig,
    DaemonState, LifecycleRequest, RunInspectResponse, StateHeadResponse,
    StateSnapshotExportRequest, StateSnapshotExportResponse, StateSnapshotImportRequest,
    SubmitActionRequest, TickResponse, TracePageResponse,
};
use splendor_kernel::LocalAuthorityObligationReceiptConfig;
use splendor_store::{
    InMemoryTraceStore, RuntimeTraceAppend, RuntimeTraceLimits, RuntimeTracePage,
    RuntimeTracePortError, RuntimeTraceReader, RuntimeTraceReaderHandle, RuntimeTraceStoreIdentity,
    RuntimeTraceTail, RuntimeTraceWriter, RuntimeTraceWriterHandle, RuntimeTraceWriterRequest,
    TraceRecord, TraceStore, TraceStoreError,
};
use splendor_types::{
    Action, ActionId, AgentId, AppPrincipal, ApprovalChallenge, ApprovalId, ApprovalPolicy,
    AuditAttribution, AuthorityDecisionId, AuthorityObligationId, CallerCredential,
    ClientPrincipal, CredentialAudience, CredentialBinding, DataLocality, EndpointScope, FleetId,
    FleetTelemetrySnapshot, InstanceId, InstanceRegistration, NodeId, NodeRegistration,
    PlacementDecision, PlacementExecutionMode, PlacementRequest, PlacementTarget, PrincipalId,
    ResidentApprovalReceiptRevocationAck, ResidentApprovalReceiptRevocationRequest,
    ResidentApprovalReceiptRevocationStatus, RevocationStatus, RunId, SideEffectClass,
    TelemetryAuthority, TenantId, TraceEvent, TraceEventKind, TraceId, WorkOrder,
    WorkOrderEnvelope, WorkOrderId, WorkOrderKeyring, WorkOrderPlacement, WorkOrderQuotaPolicy,
    APPROVAL_CHALLENGE_SCHEMA_VERSION, APPROVAL_POLICY_SCHEMA_VERSION,
    RESIDENT_APPROVAL_RECEIPT_REVOCATION_SCHEMA_VERSION,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::task::JoinHandle;
use tower::ServiceExt;

const FLEET_ID: &str = "00000000-0000-4000-8000-000000000104";
const TENANT_ID: &str = "11111111-1111-4111-8111-111111111111";
const AGENT_ID: &str = "22222222-2222-4222-8222-222222222222";
const WORK_ORDER_KEY_ID: &str = "resident-dispatch-test-key";
const MANAGER_WORK_ORDER_KEY: &[u8] = &[0x5a; 32];
const RESIDENT_TEST_ADAPTER: &str = "resident.test";

fn authority_receipt_config() -> LocalAuthorityObligationReceiptConfig {
    LocalAuthorityObligationReceiptConfig::trusted_local(
        PrincipalId::parse("00000000-0000-4000-8000-0000000004c0").expect("receipt issuer"),
        "splendor.daemon.run",
        "approval-receipt-local-key",
        "splendor-local-approval-receipt-secret-v1",
        "local-approval-receipts",
    )
    .expect("authority receipt config")
}

struct ResidentHarness {
    base_url: String,
    root_ca_pem: Vec<u8>,
    state: DaemonState,
    server: JoinHandle<()>,
}

struct FaultHarness {
    base_url: String,
    start_calls: Arc<AtomicUsize>,
    server: JoinHandle<()>,
}

struct BarrierHarness {
    base_url: String,
    create_calls: Arc<AtomicUsize>,
    start_calls: Arc<AtomicUsize>,
    create_entered: Arc<tokio::sync::Barrier>,
    create_release: Arc<tokio::sync::Barrier>,
    start_entered: Arc<tokio::sync::Barrier>,
    start_release: Arc<tokio::sync::Barrier>,
    server: JoinHandle<()>,
}

#[derive(Default)]
struct ArmableTraceStore {
    inner: InMemoryTraceStore,
    fail_appends: Arc<AtomicBool>,
    failed_append_attempts: Arc<AtomicUsize>,
}

impl ArmableTraceStore {
    fn arm(&self) {
        self.failed_append_attempts.store(0, Ordering::SeqCst);
        self.fail_appends.store(true, Ordering::SeqCst);
    }

    fn record_count(&self, run_id: &RunId) -> usize {
        self.inner
            .read(&run_id.to_string())
            .map(|records| records.len())
            .unwrap_or_default()
    }
}

impl TraceStore for ArmableTraceStore {
    fn append(&self, run_id: &str, payload: serde_json::Value) -> Result<u64, TraceStoreError> {
        if self.fail_appends.load(Ordering::SeqCst) {
            self.failed_append_attempts.fetch_add(1, Ordering::SeqCst);
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

    fn runtime_store_identity(&self) -> Result<RuntimeTraceStoreIdentity, RuntimeTracePortError> {
        self.inner.runtime_store_identity()
    }

    fn open_runtime_reader(
        &self,
        run_id: &str,
        limits: RuntimeTraceLimits,
    ) -> Result<RuntimeTraceReaderHandle, RuntimeTracePortError> {
        self.inner.open_runtime_reader(run_id, limits)
    }

    fn acquire_runtime_writer(
        &self,
        request: RuntimeTraceWriterRequest,
    ) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
        Ok(Arc::new(ArmableRuntimeWriter {
            inner: self.inner.acquire_runtime_writer(request)?,
            fail_appends: Arc::clone(&self.fail_appends),
            failed_append_attempts: Arc::clone(&self.failed_append_attempts),
        }))
    }
}

struct ArmableRuntimeWriter {
    inner: RuntimeTraceWriterHandle,
    fail_appends: Arc<AtomicBool>,
    failed_append_attempts: Arc<AtomicUsize>,
}

impl RuntimeTraceReader for ArmableRuntimeWriter {
    fn store_identity(&self) -> RuntimeTraceStoreIdentity {
        self.inner.store_identity()
    }

    fn run_id(&self) -> &str {
        self.inner.run_id()
    }

    fn limits(&self) -> RuntimeTraceLimits {
        self.inner.limits()
    }

    fn tail(&self) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
        self.inner.tail()
    }

    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError> {
        self.inner.read_page(start)
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        self.inner.confirm_tail(expected)
    }
}

impl RuntimeTraceWriter for ArmableRuntimeWriter {
    fn append(
        &self,
        expected: &RuntimeTraceTail,
        payload: serde_json::Value,
    ) -> Result<RuntimeTraceAppend, RuntimeTracePortError> {
        if self.fail_appends.load(Ordering::SeqCst) {
            self.failed_append_attempts.fetch_add(1, Ordering::SeqCst);
            return Err(RuntimeTracePortError::Unavailable);
        }
        self.inner.append(expected, payload)
    }

    fn close(&self) -> Result<(), RuntimeTracePortError> {
        self.inner.close()
    }
}

impl Drop for FaultHarness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Drop for BarrierHarness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[derive(Clone)]
struct TimeoutFaultState {
    start_calls: Arc<AtomicUsize>,
}

#[derive(Clone, Copy, Debug)]
enum PostSendStartFault {
    ExecuteThenReset,
    Malformed,
    Oversized,
    WrongRunId,
    InternalServerError,
}

#[derive(Clone)]
struct PostSendFaultState {
    start_calls: Arc<AtomicUsize>,
    fault: PostSendStartFault,
}

#[derive(Clone)]
struct BarrierDispatchState {
    create_calls: Arc<AtomicUsize>,
    start_calls: Arc<AtomicUsize>,
    create_entered: Arc<tokio::sync::Barrier>,
    create_release: Arc<tokio::sync::Barrier>,
    start_entered: Arc<tokio::sync::Barrier>,
    start_release: Arc<tokio::sync::Barrier>,
}

async fn fault_create_run(Json(payload): Json<serde_json::Value>) -> Json<CreateRunResponse> {
    let work_order: WorkOrderEnvelope =
        serde_json::from_value(payload["work_order"].clone()).expect("fault work order");
    Json(CreateRunResponse {
        request_id: payload["request_id"]
            .as_str()
            .expect("fault request id")
            .to_string(),
        idempotency_key: payload["idempotency_key"]
            .as_str()
            .expect("fault idempotency key")
            .to_string(),
        idempotency_receipt_id: "fault-create-receipt".to_string(),
        duplicate: false,
        run_id: work_order.work_order.run_id.expect("fault run id"),
        status: splendor_daemon::RunStatus::Pending,
    })
}

async fn fault_timeout_start(
    Path(_run_id): Path<RunId>,
    State(state): State<TimeoutFaultState>,
) -> Json<serde_json::Value> {
    state.start_calls.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(StdDuration::from_secs(2)).await;
    Json(serde_json::json!({"late": true}))
}

async fn spawn_timeout_fault_server() -> FaultHarness {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fault listener");
    let address = listener.local_addr().expect("fault address");
    let start_calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/runs", post(fault_create_run))
        .route("/runs/:run_id/start", post(fault_timeout_start))
        .with_state(TimeoutFaultState {
            start_calls: Arc::clone(&start_calls),
        });
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("fault server remains available");
    });
    FaultHarness {
        base_url: format!("http://{address}"),
        start_calls,
        server,
    }
}

async fn fault_post_send_start(
    Path(_run_id): Path<RunId>,
    State(state): State<PostSendFaultState>,
) -> Response {
    state.start_calls.fetch_add(1, Ordering::SeqCst);
    match state.fault {
        PostSendStartFault::ExecuteThenReset => {
            panic!("fault injection: effect executed before connection reset")
        }
        PostSendStartFault::Malformed => (StatusCode::OK, "not-json").into_response(),
        PostSendStartFault::Oversized => (StatusCode::OK, "x".repeat(4 * 1024)).into_response(),
        PostSendStartFault::WrongRunId => Json(TickResponse {
            run_id: RunId::new(),
            status: splendor_daemon::RunStatus::Running,
            tick_id: 1,
            state_node_id: "state_fault_wrong_run".to_string(),
            action_outcomes: Vec::new(),
        })
        .into_response(),
        PostSendStartFault::InternalServerError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiErrorBody {
                code: "fault_after_start".to_string(),
                message: "fault injected after start processing".to_string(),
                details: serde_json::Value::Null,
            }),
        )
            .into_response(),
    }
}

async fn spawn_post_send_fault_server(fault: PostSendStartFault) -> FaultHarness {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fault listener");
    let address = listener.local_addr().expect("fault address");
    let start_calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/runs", post(fault_create_run))
        .route("/runs/:run_id/start", post(fault_post_send_start))
        .with_state(PostSendFaultState {
            start_calls: Arc::clone(&start_calls),
            fault,
        });
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("fault server remains available");
    });
    FaultHarness {
        base_url: format!("http://{address}"),
        start_calls,
        server,
    }
}

async fn barrier_create_run(
    State(state): State<BarrierDispatchState>,
    Json(payload): Json<serde_json::Value>,
) -> Json<CreateRunResponse> {
    state.create_calls.fetch_add(1, Ordering::SeqCst);
    state.create_entered.wait().await;
    state.create_release.wait().await;
    fault_create_run(Json(payload)).await
}

async fn barrier_start_run(
    Path(run_id): Path<RunId>,
    State(state): State<BarrierDispatchState>,
) -> Json<TickResponse> {
    state.start_calls.fetch_add(1, Ordering::SeqCst);
    state.start_entered.wait().await;
    state.start_release.wait().await;
    Json(TickResponse {
        run_id,
        status: splendor_daemon::RunStatus::Running,
        tick_id: 1,
        state_node_id: "state_barrier_dispatch".to_string(),
        action_outcomes: Vec::new(),
    })
}

async fn spawn_barrier_dispatch_server() -> BarrierHarness {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("barrier listener");
    let address = listener.local_addr().expect("barrier address");
    let create_calls = Arc::new(AtomicUsize::new(0));
    let start_calls = Arc::new(AtomicUsize::new(0));
    let create_entered = Arc::new(tokio::sync::Barrier::new(2));
    let create_release = Arc::new(tokio::sync::Barrier::new(2));
    let start_entered = Arc::new(tokio::sync::Barrier::new(2));
    let start_release = Arc::new(tokio::sync::Barrier::new(2));
    let state = BarrierDispatchState {
        create_calls: Arc::clone(&create_calls),
        start_calls: Arc::clone(&start_calls),
        create_entered: Arc::clone(&create_entered),
        create_release: Arc::clone(&create_release),
        start_entered: Arc::clone(&start_entered),
        start_release: Arc::clone(&start_release),
    };
    let app = Router::new()
        .route("/runs", post(barrier_create_run))
        .route("/runs/:run_id/start", post(barrier_start_run))
        .with_state(state);
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("barrier server remains available");
    });
    BarrierHarness {
        base_url: format!("http://{address}"),
        create_calls,
        start_calls,
        create_entered,
        create_release,
        start_entered,
        start_release,
        server,
    }
}

impl Drop for ResidentHarness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn spawn_resident(
    signer: &CallerTokenSigner,
    instance_id: InstanceId,
    work_order_key: &[u8],
) -> ResidentHarness {
    spawn_resident_with_scopes(
        signer,
        instance_id,
        work_order_key,
        vec![
            EndpointScope::RunsCreate,
            EndpointScope::RunsStart,
            EndpointScope::RunsRead,
            EndpointScope::StateRead,
            EndpointScope::TracesRead,
        ],
    )
    .await
}

async fn spawn_resident_with_scopes(
    signer: &CallerTokenSigner,
    instance_id: InstanceId,
    work_order_key: &[u8],
    allowed_scopes: Vec<EndpointScope>,
) -> ResidentHarness {
    spawn_resident_with_scopes_and_trace_store(
        signer,
        instance_id,
        work_order_key,
        allowed_scopes,
        None,
    )
    .await
}

async fn spawn_resident_with_scopes_and_trace_store(
    signer: &CallerTokenSigner,
    instance_id: InstanceId,
    work_order_key: &[u8],
    allowed_scopes: Vec<EndpointScope>,
    trace_store: Option<Arc<dyn TraceStore>>,
) -> ResidentHarness {
    let trust = CallerTokenTrustSnapshot::single_key(
        signer.issuer(),
        signer.app_principal_id(),
        signer.kid(),
        &signer.public_key_bytes(),
        allowed_scopes,
        OffsetDateTime::now_utc(),
    );
    let verifier = CallerTokenVerifier::new(trust, instance_id.clone()).expect("caller verifier");
    let mut work_order_keyring = WorkOrderKeyring::new();
    work_order_keyring
        .insert_shared_secret(WORK_ORDER_KEY_ID, work_order_key)
        .expect("resident work-order key");
    let mut policy_keyring = splendor_types::PolicyBundleKeyring::new();
    policy_keyring
        .insert_shared_secret("policy-resident-test", [9_u8; 32])
        .expect("resident policy key");
    let config = DaemonConfig::resident(instance_id, verifier, work_order_keyring, policy_keyring)
        .with_authority_obligation_receipt_config(authority_receipt_config());
    let state = match trace_store {
        Some(trace_store) => {
            support::state_with_trace_store(config, trace_store, &[RESIDENT_TEST_ADAPTER])
        }
        None => support::state(config, &[RESIDENT_TEST_ADAPTER]),
    };
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("test TLS certificate");
    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();
    let tls = RustlsConfig::from_pem(cert_pem.clone(), key_pem)
        .await
        .expect("resident TLS config");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("resident listener");
    listener
        .set_nonblocking(true)
        .expect("resident listener nonblocking");
    let address = listener.local_addr().expect("resident address");
    let app = resident_router(state.clone());
    let server = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .expect("resident TLS listener")
            .serve(app.into_make_service())
            .await
            .expect("resident server remains available");
    });
    ResidentHarness {
        base_url: format!("https://localhost:{}", address.port()),
        root_ca_pem: cert_pem,
        state,
        server,
    }
}

fn manager_security(fleet_id: &FleetId) -> ManagerSecurityFields {
    let credential = CallerCredential {
        credential_id: "cred_resident_dispatch_integration".to_string(),
        principal: ClientPrincipal {
            app: AppPrincipal {
                app_principal_id: "app_resident_dispatch_integration".to_string(),
                label: Some("resident dispatch integration".to_string()),
            },
            client_principal_id: "client_resident_dispatch_integration".to_string(),
            label: Some("resident dispatch integration client".to_string()),
        },
        scopes: vec![
            EndpointScope::NodesRegister,
            EndpointScope::InstancesRegister,
            EndpointScope::InstancesHeartbeat,
            EndpointScope::FleetRead,
            EndpointScope::FleetDispatch,
            EndpointScope::WorkOrdersSubmit,
            EndpointScope::WorkOrdersRevoke,
            EndpointScope::TracesRead,
        ],
        binding: CredentialBinding::Fleet {
            fleet_id: fleet_id.clone(),
        },
        audience: CredentialAudience::CentralManager {
            manager_id: "central-manager".to_string(),
        },
        expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
        revocation: RevocationStatus::Active,
    };
    ManagerSecurityFields {
        audit_attribution: AuditAttribution {
            principal: credential.principal.clone(),
            credential_id: Some(credential.credential_id.clone()),
            requested_at: OffsetDateTime::now_utc(),
        },
        credential,
    }
}

fn node_registration(
    fleet_id: &FleetId,
    node_id: &NodeId,
    resident_url: &str,
    capability: &str,
) -> NodeRegistration {
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("timestamp");
    serde_json::from_value(serde_json::json!({
        "node_id": node_id,
        "kind": "vpc.worker",
        "scope": {"fleet_id": fleet_id, "tenant_id": null},
        "capability_document": {
            "schema": "splendor.capabilities.v1",
            "capabilities": ["runtime.resident", capability],
            "constraints": {
                "placement_target": "customer_vpc",
                "data_locality": "vpc",
                "resident_daemon_url": resident_url,
            }
        },
        "runtime_version": "0.1-test",
        "health": {"status": "healthy", "observed_at": now, "metadata": {}},
        "registered_at": now,
    }))
    .expect("node registration")
}

fn instance_registration(
    node_id: &NodeId,
    instance_id: &InstanceId,
    tenant_id: &TenantId,
    capability: &str,
) -> InstanceRegistration {
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("timestamp");
    serde_json::from_value(serde_json::json!({
        "instance_id": instance_id,
        "node_id": node_id,
        "runtime_mode": "resident",
        "hosted_tenants": [tenant_id],
        "supported_features": ["runtime.resident", "gateway.verified", capability],
        "runtime_version": "0.1-test",
        "health": {"status": "healthy", "observed_at": now, "metadata": {}},
        "registered_at": now,
    }))
    .expect("instance registration")
}

fn signed_work_order(
    work_order_id: &str,
    run_id: RunId,
    tenant_id: TenantId,
    agent_id: AgentId,
    capability: &str,
) -> WorkOrderEnvelope {
    let now = OffsetDateTime::now_utc();
    signed_work_order_expiring_at(
        work_order_id,
        run_id,
        tenant_id,
        agent_id,
        capability,
        now + Duration::minutes(10),
    )
}

fn signed_work_order_expiring_at(
    work_order_id: &str,
    run_id: RunId,
    tenant_id: TenantId,
    agent_id: AgentId,
    capability: &str,
    expires_at: OffsetDateTime,
) -> WorkOrderEnvelope {
    let now = OffsetDateTime::now_utc();
    WorkOrderEnvelope::signed_with_shared_secret(
        WorkOrder {
            schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
            work_order_id: WorkOrderId::try_new(work_order_id).expect("work-order id"),
            tenant_id,
            agent_id,
            run_id: Some(run_id),
            objective: "admit and start one resident run through the real daemon".to_string(),
            allowed_actions: vec!["daemon.record".to_string()],
            allowed_adapters: vec![RESIDENT_TEST_ADAPTER.to_string()],
            allowed_permissions: vec!["fixture.execute".to_string()],
            data_refs: Vec::new(),
            quotas: WorkOrderQuotaPolicy::default(),
            placement: WorkOrderPlacement {
                target: "customer_vpc".to_string(),
                data_locality: Some("vpc".to_string()),
                requires_gpu: Some(false),
                dedicated_instance: Some(false),
                required_capabilities: vec![capability.to_string()],
                max_runtime_ms: Some(30_000),
                execution_mode: PlacementExecutionMode::Live,
            },
            issued_at: now - Duration::minutes(1),
            expires_at,
            revocation: RevocationStatus::Active,
        },
        WORK_ORDER_KEY_ID,
        MANAGER_WORK_ORDER_KEY,
    )
    .expect("signed work order")
}

fn resident_dispatch_approval_policy(work_order: &WorkOrderEnvelope) -> ApprovalPolicy {
    ApprovalPolicy {
        schema_version: APPROVAL_POLICY_SCHEMA_VERSION.to_string(),
        policy_id: "resident-dispatch-approval".to_string(),
        tenant_id: work_order.work_order.tenant_id.clone(),
        agent_id: Some(work_order.work_order.agent_id.clone()),
        action_name: Some("daemon.record".to_string()),
        adapter: Some(RESIDENT_TEST_ADAPTER.to_string()),
        required_permission: Some("fixture.execute".to_string()),
        side_effect_class: None,
        risk_level: Some("high".to_string()),
        reason: "resident dispatch action requires approval".to_string(),
        expires_at: Some(work_order.work_order.expires_at - Duration::seconds(1)),
    }
}

fn resident_record_action(name: &str) -> Action {
    Action {
        name: name.to_string(),
        params: serde_json::json!({"source": "resident-manager-integration"}),
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: vec!["fixture.execute".to_string()],
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    }
}

fn resident_create_request(
    tenant_id: TenantId,
    agent_id: AgentId,
    work_order: WorkOrderEnvelope,
    initial_state: serde_json::Value,
) -> CreateRunRequest {
    CreateRunRequest {
        request_id: format!("req_{}", TraceId::new()),
        idempotency_key: format!("idem_{}", TraceId::new()),
        tenant_id,
        agent_id,
        work_order,
        credential: None,
        audit_attribution: None,
        allowed_actions: vec!["daemon.record".to_string()],
        allowed_adapters: vec![RESIDENT_TEST_ADAPTER.to_string()],
        allowed_permissions: vec!["fixture.execute".to_string()],
        policy_actions: Vec::new(),
        policy_bundle_required: false,
        policy_bundle: None,
        registered_actions: Vec::new(),
        approval_policies: Vec::new(),
        circuit_breakers: Vec::new(),
        allowed_percept_schemas: Vec::new(),
        allowed_percept_sources: Vec::new(),
        initial_state: Some(initial_state),
        snapshot_interval: Some(1),
    }
}

fn resident_token(
    signer: &CallerTokenSigner,
    tenant_id: &TenantId,
    instance_id: &InstanceId,
    scope: EndpointScope,
) -> SignedCallerToken {
    signer
        .sign(
            tenant_id,
            instance_id,
            vec![scope],
            OffsetDateTime::now_utc(),
            Duration::seconds(60),
        )
        .expect("resident caller token")
}

async fn call_manager<T: Serialize, R: DeserializeOwned>(
    app: Router,
    method: Method,
    uri: &str,
    body: &T,
) -> (StatusCode, R) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).expect("request JSON")))
                .expect("request"),
        )
        .await
        .expect("manager response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("manager response body");
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "manager response JSON failed ({status}): {error}; body={}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, value)
}

async fn call_manager_with_token<T: Serialize, R: DeserializeOwned>(
    app: Router,
    method: Method,
    uri: &str,
    body: &T,
    token: &str,
) -> (StatusCode, R) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(body).expect("request JSON")))
                .expect("request"),
        )
        .await
        .expect("manager response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("manager response body");
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "manager response JSON failed ({status}): {error}; body={}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, value)
}

struct ResidentPlacementFixture<'a> {
    fleet_id: &'a FleetId,
    node_id: &'a NodeId,
    instance_id: &'a InstanceId,
    tenant_id: &'a TenantId,
    resident_url: &'a str,
    capability: &'a str,
}

async fn register_and_place(
    app: &Router,
    security: &ManagerSecurityFields,
    fixture: ResidentPlacementFixture<'_>,
    work_order: WorkOrderEnvelope,
) {
    register_and_place_with_policies(app, security, fixture, work_order, Vec::new()).await;
}

async fn register_and_place_with_policies(
    app: &Router,
    security: &ManagerSecurityFields,
    fixture: ResidentPlacementFixture<'_>,
    work_order: WorkOrderEnvelope,
    approval_policies: Vec<ApprovalPolicy>,
) {
    let (status, _): (StatusCode, NodeRegistration) = call_manager(
        app.clone(),
        Method::POST,
        "/fleet/nodes",
        &RegisterNodeRequest {
            security: security.clone(),
            registration: node_registration(
                fixture.fleet_id,
                fixture.node_id,
                fixture.resident_url,
                fixture.capability,
            ),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _): (StatusCode, InstanceRegistration) = call_manager(
        app.clone(),
        Method::POST,
        "/fleet/instances",
        &RegisterInstanceRequest {
            security: security.clone(),
            registration: instance_registration(
                fixture.node_id,
                fixture.instance_id,
                fixture.tenant_id,
                fixture.capability,
            ),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let work_order_id = work_order.work_order.work_order_id.to_string();
    let (status, accepted): (StatusCode, WorkOrderValidationReport) = call_manager(
        app.clone(),
        Method::POST,
        "/work-orders",
        &SubmitWorkOrderRequest {
            security: security.clone(),
            work_order,
            expected_audience: "central-manager".to_string(),
            approval_policies,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(accepted.accepted);
    let (status, placement): (StatusCode, PlacementDecision) = call_manager(
        app.clone(),
        Method::POST,
        "/fleet/placement/evaluate",
        &PlacementEvaluationRequest {
            security: security.clone(),
            work_order_id: Some(work_order_id),
            request: PlacementRequest {
                target: PlacementTarget::CustomerVpc,
                required_capabilities: vec![fixture.capability.to_string()],
                data_locality: Some(DataLocality::Vpc),
                dedicated_instance: false,
                required_runtime_version: None,
                max_runtime_ms: Some(30_000),
                execution_mode: PlacementExecutionMode::Live,
            },
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        placement.candidate_id.as_deref(),
        Some(fixture.node_id.to_string().as_str())
    );
}

async fn resident_get<R: DeserializeOwned>(
    base_url: &str,
    root_ca_pem: &[u8],
    path: &str,
    signed: &SignedCallerToken,
) -> (reqwest::StatusCode, R, String) {
    let root = reqwest::Certificate::from_pem(root_ca_pem).expect("test resident root");
    let response = reqwest::Client::builder()
        .add_root_certificate(root)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("resident test client")
        .get(format!("{base_url}{path}"))
        .bearer_auth(&signed.encoded)
        .header(
            "x-splendor-caller-credential",
            serde_json::to_string(&signed.credential).expect("credential projection"),
        )
        .send()
        .await
        .expect("resident request");
    let status = response.status();
    let body = response.text().await.expect("resident response body");
    let parsed = serde_json::from_str(&body).unwrap_or_else(|error| {
        panic!("resident response JSON failed ({status}): {error}; body={body}")
    });
    (status, parsed, body)
}

async fn resident_post<T: Serialize, R: DeserializeOwned>(
    base_url: &str,
    root_ca_pem: &[u8],
    path: &str,
    body: &T,
    signed: &SignedCallerToken,
) -> (reqwest::StatusCode, R, String) {
    let root = reqwest::Certificate::from_pem(root_ca_pem).expect("test resident root");
    let response = reqwest::Client::builder()
        .add_root_certificate(root)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("resident test client")
        .post(format!("{base_url}{path}"))
        .bearer_auth(&signed.encoded)
        .header("content-type", "application/json")
        .header(
            "x-splendor-caller-credential",
            serde_json::to_string(&signed.credential).expect("credential projection"),
        )
        .json(body)
        .send()
        .await
        .expect("resident request");
    let status = response.status();
    let response_body = response.text().await.expect("resident response body");
    let parsed = serde_json::from_str(&response_body).unwrap_or_else(|error| {
        panic!("resident response JSON failed ({status}): {error}; body={response_body}")
    });
    (status, parsed, response_body)
}

fn caller_signer() -> CallerTokenSigner {
    CallerTokenSigner::generate_for_test(
        "urn:splendor:manager:central-manager",
        "central-manager",
        "resident-dispatch-client",
        "manager-resident-integration",
    )
    .expect("caller signer")
}

fn manager_state_with_options(
    signer: CallerTokenSigner,
    options: ResidentDispatchOptions,
) -> ManagerState {
    let mut keyring = WorkOrderKeyring::new();
    keyring
        .insert_shared_secret(WORK_ORDER_KEY_ID, MANAGER_WORK_ORDER_KEY)
        .expect("manager test work-order key");
    ManagerState::acceptance_with_dispatch_config(
        "central-manager",
        FleetId::parse(FLEET_ID).expect("fleet"),
        keyring,
        signer,
        options,
    )
    .expect("manager state")
}

fn manager_state(
    signer: CallerTokenSigner,
    root_ca_pem: Vec<u8>,
    allowed_origin: &str,
) -> ManagerState {
    manager_state_with_options(
        signer,
        ResidentDispatchOptions {
            root_ca_pem: Some(root_ca_pem),
            allowed_origins: vec![allowed_origin.to_string()],
            ..ResidentDispatchOptions::production()
        },
    )
}

fn manager_state_with_approval_auth(
    resident_signer: CallerTokenSigner,
    approval_signer: &CallerTokenSigner,
    root_ca_pem: Vec<u8>,
    allowed_origin: &str,
) -> ManagerState {
    let fleet_id = FleetId::parse(FLEET_ID).expect("fleet");
    let mut keyring = WorkOrderKeyring::new();
    keyring
        .insert_shared_secret(WORK_ORDER_KEY_ID, MANAGER_WORK_ORDER_KEY)
        .expect("manager test work-order key");
    let approval_trust = CallerTokenTrustSnapshot::single_key(
        approval_signer.issuer(),
        approval_signer.app_principal_id(),
        approval_signer.kid(),
        &approval_signer.public_key_bytes(),
        vec![EndpointScope::ApprovalsManage],
        OffsetDateTime::now_utc(),
    )
    .with_expected_client_principal_id("approval-client");
    let approval_verifier =
        CallerTokenVerifier::for_manager(approval_trust, "central-manager", fleet_id.clone())
            .expect("approval caller verifier");
    ManagerState::acceptance_with_dispatch_receipt_and_approval_auth(
        "central-manager",
        fleet_id,
        keyring,
        resident_signer,
        ResidentDispatchOptions {
            root_ca_pem: Some(root_ca_pem),
            allowed_origins: vec![allowed_origin.to_string()],
            ..ResidentDispatchOptions::production()
        },
        authority_receipt_config(),
        approval_verifier,
    )
    .expect("manager state with approval auth")
}

fn approval_token(signer: &CallerTokenSigner, fleet_id: &FleetId) -> SignedCallerToken {
    signer
        .sign_for_manager(
            fleet_id,
            "central-manager",
            vec![EndpointScope::ApprovalsManage],
            OffsetDateTime::now_utc(),
            Duration::seconds(60),
        )
        .expect("approval caller token")
}

fn approval_security(token: &SignedCallerToken) -> ManagerSecurityFields {
    ManagerSecurityFields {
        credential: token.credential.clone(),
        audit_attribution: AuditAttribution {
            principal: token.credential.principal.clone(),
            credential_id: Some(token.credential.credential_id.clone()),
            requested_at: OffsetDateTime::now_utc(),
        },
    }
}

#[tokio::test]
async fn resident_lifecycle_inspect_pause_resume_and_stop_remain_scope_bound() {
    let signer = caller_signer();
    let instance_id = InstanceId::new();
    let tenant_id = TenantId::parse(TENANT_ID).expect("tenant");
    let agent_id = AgentId::parse(AGENT_ID).expect("agent");
    let run_id = RunId::new();
    let resident = spawn_resident_with_scopes(
        &signer,
        instance_id.clone(),
        MANAGER_WORK_ORDER_KEY,
        vec![
            EndpointScope::RunsCreate,
            EndpointScope::RunsRead,
            EndpointScope::RunsPause,
            EndpointScope::RunsResume,
            EndpointScope::RunsStop,
        ],
    )
    .await;
    let work_order = signed_work_order(
        "wo_resident_lifecycle_scope",
        run_id.clone(),
        tenant_id.clone(),
        agent_id.clone(),
        "lifecycle.scope",
    );

    let token = resident_token(&signer, &tenant_id, &instance_id, EndpointScope::RunsCreate);
    let (status, created, _): (reqwest::StatusCode, CreateRunResponse, String) = resident_post(
        &resident.base_url,
        &resident.root_ca_pem,
        "/runs",
        &resident_create_request(
            tenant_id.clone(),
            agent_id,
            work_order.clone(),
            serde_json::json!({"lifecycle": "pending"}),
        ),
        &token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(created.run_id, run_id);

    let token = resident_token(&signer, &tenant_id, &instance_id, EndpointScope::RunsRead);
    let (status, inspected, _): (reqwest::StatusCode, serde_json::Value, String) = resident_get(
        &resident.base_url,
        &resident.root_ca_pem,
        &format!("/runs/{run_id}"),
        &token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(inspected["status"], "pending");

    let pause_request = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: None,
        reason: Some("bounded lifecycle pause".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let token = resident_token(&signer, &tenant_id, &instance_id, EndpointScope::RunsPause);
    let (status, paused, _): (reqwest::StatusCode, serde_json::Value, String) = resident_post(
        &resident.base_url,
        &resident.root_ca_pem,
        &format!("/runs/{run_id}/pause"),
        &pause_request,
        &token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(paused["status"], "paused");

    let token = resident_token(&signer, &tenant_id, &instance_id, EndpointScope::RunsPause);
    let (status, error, _): (reqwest::StatusCode, ApiErrorBody, String) = resident_post(
        &resident.base_url,
        &resident.root_ca_pem,
        &format!("/runs/{run_id}/pause"),
        &pause_request,
        &token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT);
    assert_eq!(error.code, "invalid_run_state");

    let token = resident_token(&signer, &tenant_id, &instance_id, EndpointScope::RunsResume);
    let (status, resumed, _): (reqwest::StatusCode, TickResponse, String) = resident_post(
        &resident.base_url,
        &resident.root_ca_pem,
        &format!("/runs/{run_id}/resume"),
        &LifecycleRequest {
            credential: None,
            work_order: Some(work_order),
            audit_attribution: None,
            reason: Some("bounded lifecycle resume".to_string()),
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        },
        &token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(resumed.status, splendor_daemon::RunStatus::Running);

    let token = resident_token(&signer, &tenant_id, &instance_id, EndpointScope::RunsStop);
    let (status, stopped, _): (reqwest::StatusCode, serde_json::Value, String) = resident_post(
        &resident.base_url,
        &resident.root_ca_pem,
        &format!("/runs/{run_id}/stop"),
        &LifecycleRequest {
            credential: None,
            work_order: None,
            audit_attribution: None,
            reason: Some("bounded lifecycle stop".to_string()),
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        },
        &token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(stopped["status"], "cancelled");
}

#[tokio::test]
async fn resident_state_import_requires_source_authenticated_proof_before_mutation() {
    let tenant_id = TenantId::parse(TENANT_ID).expect("tenant");
    let agent_id = AgentId::parse(AGENT_ID).expect("agent");
    let run_id = RunId::parse("44444444-4444-4444-8444-444444444499").expect("run");
    let source_instance =
        InstanceId::parse("00000000-0000-4000-8000-000000000398").expect("source instance");
    let receiver_instance =
        InstanceId::parse("00000000-0000-4000-8000-000000000399").expect("receiver instance");
    let signer = caller_signer();
    let scopes = vec![
        EndpointScope::RunsCreate,
        EndpointScope::RunsStart,
        EndpointScope::StateRead,
        EndpointScope::StateHandoff,
    ];
    let source = spawn_resident_with_scopes(
        &signer,
        source_instance.clone(),
        MANAGER_WORK_ORDER_KEY,
        scopes.clone(),
    )
    .await;
    let receiver_trace_store = Arc::new(ArmableTraceStore::default());
    let receiver = spawn_resident_with_scopes_and_trace_store(
        &signer,
        receiver_instance.clone(),
        MANAGER_WORK_ORDER_KEY,
        scopes,
        Some(receiver_trace_store.clone()),
    )
    .await;
    tokio::time::sleep(StdDuration::from_millis(20)).await;

    let work_order = signed_work_order(
        "wo_resident_handoff_proof",
        run_id.clone(),
        tenant_id.clone(),
        agent_id.clone(),
        "state.handoff",
    );
    for (resident, instance_id, seed) in [
        (&source, &source_instance, "source"),
        (&receiver, &receiver_instance, "receiver"),
    ] {
        let token = resident_token(&signer, &tenant_id, instance_id, EndpointScope::RunsCreate);
        let (status, created, _): (reqwest::StatusCode, CreateRunResponse, String) = resident_post(
            &resident.base_url,
            &resident.root_ca_pem,
            "/runs",
            &resident_create_request(
                tenant_id.clone(),
                agent_id.clone(),
                work_order.clone(),
                serde_json::json!({"seed": seed}),
            ),
            &token,
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::OK);
        assert_eq!(created.run_id, run_id);

        let token = resident_token(&signer, &tenant_id, instance_id, EndpointScope::RunsStart);
        let (status, tick, _): (reqwest::StatusCode, TickResponse, String) = resident_post(
            &resident.base_url,
            &resident.root_ca_pem,
            &format!("/runs/{run_id}/start"),
            &LifecycleRequest {
                credential: None,
                work_order: None,
                audit_attribution: None,
                reason: Some("prepare state handoff denial fixture".to_string()),
                approval_evidence: None,
                authority_obligation_receipts: Vec::new(),
            },
            &token,
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::OK);
        assert_eq!(tick.run_id, run_id);
    }

    let token = resident_token(
        &signer,
        &tenant_id,
        &receiver_instance,
        EndpointScope::StateRead,
    );
    let (status, receiver_head, _): (reqwest::StatusCode, StateHeadResponse, String) =
        resident_get(
            &receiver.base_url,
            &receiver.root_ca_pem,
            &format!("/runs/{run_id}/state-head"),
            &token,
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);

    let token = resident_token(
        &signer,
        &tenant_id,
        &source_instance,
        EndpointScope::StateHandoff,
    );
    let (status, exported, _): (reqwest::StatusCode, StateSnapshotExportResponse, String) =
        resident_post(
            &source.base_url,
            &source.root_ca_pem,
            "/state-snapshots/export",
            &StateSnapshotExportRequest {
                run_id: run_id.clone(),
                credential: None,
                audit_attribution: None,
                work_order_id: work_order.work_order.work_order_id.to_string(),
                source_instance_id: Some(source_instance.to_string()),
                receiver_instance_id: Some(receiver_instance.to_string()),
                previous_state_node_id: Some(receiver_head.state_node_id.clone()),
            },
            &token,
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        exported.handoff.snapshot.state_node_id,
        exported.state_node_id
    );

    let baseline_trace_count = receiver_trace_store.record_count(&run_id);
    let baseline_security_audit_count = receiver.state.resident_security_audit_events().len();
    let mut fabricated = exported.handoff.clone();
    fabricated.handoff_id = "fabricated-hash-valid-handoff".to_string();
    fabricated.source_trace_id = Some(TraceId::new());
    let mut stale = exported.handoff.clone();
    stale.previous_state_node_id = Some("blake3:stale-receiver-head".to_string());
    let replayed = exported.handoff.clone();

    let mut proof_denial_credentials = Vec::new();
    for (label, handoff) in [
        ("hash-valid fabricated", fabricated),
        ("stale", stale),
        ("first repeated attempt", replayed.clone()),
        ("second repeated attempt", replayed),
    ] {
        let token = resident_token(
            &signer,
            &tenant_id,
            &receiver_instance,
            EndpointScope::StateHandoff,
        );
        proof_denial_credentials.push((
            token.credential.credential_id.clone(),
            token.encoded.clone(),
        ));
        let (status, error, _): (reqwest::StatusCode, ApiErrorBody, String) = resident_post(
            &receiver.base_url,
            &receiver.root_ca_pem,
            "/state-snapshots/import",
            &StateSnapshotImportRequest {
                handoff,
                work_order: work_order.clone(),
                credential: None,
                audit_attribution: None,
            },
            &token,
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE, "{label}");
        assert_eq!(error.code, "state_handoff_proof_unavailable", "{label}");
        assert_eq!(
            error.details["disposition"], "needs_intervention",
            "{label}"
        );
        assert_eq!(
            receiver_trace_store.record_count(&run_id),
            baseline_trace_count,
            "{label} must not append a run trace"
        );
    }
    let proof_denial_audits = receiver.state.resident_security_audit_events();
    let proof_denial_audits = &proof_denial_audits[baseline_security_audit_count..];
    assert_eq!(proof_denial_audits.len(), proof_denial_credentials.len());
    for (event, (credential_id, raw_token)) in proof_denial_audits
        .iter()
        .zip(proof_denial_credentials.iter())
    {
        assert_eq!(event.event_type, "state_handoff.proof_denied");
        assert_eq!(event.method, "POST");
        assert_eq!(event.path, "/state-snapshots/import");
        assert_eq!(&event.credential_correlation, credential_id);
        assert!(event.credential_correlation.starts_with("sha256:"));
        assert!(!serde_json::to_string(event)
            .expect("proof denial audit JSON")
            .contains(raw_token));
    }

    let unknown_run_id =
        RunId::parse("77777777-7777-4777-8777-777777777777").expect("unknown handoff run");
    let unknown_work_order = signed_work_order(
        "wo_resident_handoff_unknown_run",
        unknown_run_id.clone(),
        tenant_id.clone(),
        agent_id.clone(),
        "state.handoff",
    );
    let mut unknown_handoff = exported.handoff.clone();
    unknown_handoff.authority.run_id = unknown_run_id.clone();
    unknown_handoff.authority.work_order_id =
        unknown_work_order.work_order.work_order_id.to_string();
    let token = resident_token(
        &signer,
        &tenant_id,
        &receiver_instance,
        EndpointScope::StateHandoff,
    );
    let unknown_credential_id = token.credential.credential_id.clone();
    let (status, error, _): (reqwest::StatusCode, ApiErrorBody, String) = resident_post(
        &receiver.base_url,
        &receiver.root_ca_pem,
        "/state-snapshots/import",
        &StateSnapshotImportRequest {
            handoff: unknown_handoff,
            work_order: unknown_work_order,
            credential: None,
            audit_attribution: None,
        },
        &token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.code, "state_handoff_proof_unavailable");
    assert_eq!(receiver_trace_store.record_count(&unknown_run_id), 0);
    let security_audits = receiver.state.resident_security_audit_events();
    let unknown_audit = security_audits.last().expect("unknown-run proof audit");
    assert_eq!(unknown_audit.event_type, "state_handoff.proof_denied");
    assert_eq!(unknown_audit.credential_correlation, unknown_credential_id);

    let alternate_work_order = WorkOrderEnvelope::signed_with_shared_secret(
        work_order.work_order.clone(),
        "alternate-resident-handoff-key",
        [0x73; 32],
    )
    .expect("alternate signer envelope");
    let token = resident_token(
        &signer,
        &tenant_id,
        &receiver_instance,
        EndpointScope::StateHandoff,
    );
    let (status, error, _): (reqwest::StatusCode, ApiErrorBody, String) = resident_post(
        &receiver.base_url,
        &receiver.root_ca_pem,
        "/state-snapshots/import",
        &StateSnapshotImportRequest {
            handoff: exported.handoff.clone(),
            work_order: alternate_work_order,
            credential: None,
            audit_attribution: None,
        },
        &token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
    assert_eq!(error.code, "unknown_signature_key");
    assert_eq!(
        receiver_trace_store.record_count(&run_id),
        baseline_trace_count
    );
    assert_eq!(
        receiver.state.resident_security_audit_events().len(),
        baseline_security_audit_count + proof_denial_credentials.len() + 1,
        "invalid work-order signatures must not be recorded as source-proof denials"
    );

    receiver_trace_store.arm();
    let token = resident_token(
        &signer,
        &tenant_id,
        &receiver_instance,
        EndpointScope::StateHandoff,
    );
    let (status, error, _): (reqwest::StatusCode, ApiErrorBody, String) = resident_post(
        &receiver.base_url,
        &receiver.root_ca_pem,
        "/state-snapshots/import",
        &StateSnapshotImportRequest {
            handoff: exported.handoff,
            work_order,
            credential: None,
            audit_attribution: None,
        },
        &token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.code, "state_handoff_proof_unavailable");
    assert_eq!(
        receiver
            .state
            .resident_security_audit_events()
            .last()
            .expect("final proof denial audit")
            .credential_correlation,
        token.credential.credential_id
    );
    assert_eq!(
        receiver_trace_store
            .failed_append_attempts
            .load(Ordering::SeqCst),
        0,
        "resident proof denial must occur before any trace append"
    );
    assert_eq!(
        receiver_trace_store.record_count(&run_id),
        baseline_trace_count
    );

    let token = resident_token(
        &signer,
        &tenant_id,
        &receiver_instance,
        EndpointScope::StateRead,
    );
    let (status, unchanged_head, _): (reqwest::StatusCode, StateHeadResponse, String) =
        resident_get(
            &receiver.base_url,
            &receiver.root_ca_pem,
            &format!("/runs/{run_id}/state-head"),
            &token,
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(unchanged_head.state_node_id, receiver_head.state_node_id);
}

#[tokio::test]
async fn real_manager_dispatch_authenticates_and_real_resident_non_2xx_fails_closed() {
    let fleet_id = FleetId::parse(FLEET_ID).expect("fleet");
    let tenant_id = TenantId::parse(TENANT_ID).expect("tenant");
    let agent_id = AgentId::parse(AGENT_ID).expect("agent");

    let signer = caller_signer();
    let success_instance =
        InstanceId::parse("00000000-0000-4000-8000-000000000302").expect("instance");
    let success_node = NodeId::parse("00000000-0000-4000-8000-000000000204").expect("node");
    let success_run = RunId::parse("44444444-4444-4444-8444-444444444444").expect("run");
    let success_resident =
        spawn_resident(&signer, success_instance.clone(), MANAGER_WORK_ORDER_KEY).await;
    let success_manager = manager_state(
        signer.clone(),
        success_resident.root_ca_pem.clone(),
        &success_resident.base_url,
    );
    let success_app = manager_router(success_manager);
    let security = manager_security(&fleet_id);
    let success_work_order = signed_work_order(
        "wo_real_resident_dispatch",
        success_run.clone(),
        tenant_id.clone(),
        agent_id.clone(),
        "dispatch.success",
    );
    register_and_place(
        &success_app,
        &security,
        ResidentPlacementFixture {
            fleet_id: &fleet_id,
            node_id: &success_node,
            instance_id: &success_instance,
            tenant_id: &tenant_id,
            resident_url: &success_resident.base_url,
            capability: "dispatch.success",
        },
        success_work_order,
    )
    .await;

    let dispatch_request = DispatchWorkOrderRequest {
        security: security.clone(),
        target_node_id: Some(success_node.clone()),
    };
    let (status, report): (StatusCode, DispatchReport) = call_manager(
        success_app.clone(),
        Method::POST,
        "/work-orders/wo_real_resident_dispatch/dispatch",
        &dispatch_request,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(report.run_id, success_run);
    assert_eq!(report.selected_instance_id, success_instance);
    assert_eq!(report.create_run_status, 200);
    assert_eq!(report.start_run_status, 200);
    let tick: TickResponse = serde_json::from_str(
        report
            .start_run_body
            .as_deref()
            .expect("typed start response retained"),
    )
    .expect("tick response");
    assert_eq!(tick.run_id, success_run);
    assert_eq!(tick.status, splendor_daemon::RunStatus::Running);
    assert!(!tick.state_node_id.is_empty());

    let (status, duplicate): (StatusCode, DispatchReport) = call_manager(
        success_app.clone(),
        Method::POST,
        "/work-orders/wo_real_resident_dispatch/dispatch",
        &dispatch_request,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(duplicate.trace_event_id, report.trace_event_id);
    assert_eq!(duplicate.start_run_body, report.start_run_body);

    let state_token = signer
        .sign(
            &tenant_id,
            &success_instance,
            vec![EndpointScope::StateRead],
            OffsetDateTime::now_utc(),
            Duration::seconds(60),
        )
        .expect("state token");
    let (status, state_head, state_body): (reqwest::StatusCode, StateHeadResponse, String) =
        resident_get(
            &success_resident.base_url,
            &success_resident.root_ca_pem,
            &format!("/runs/{success_run}/state-head"),
            &state_token,
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(state_head.state_node_id, tick.state_node_id);
    assert!(!state_body.contains(&state_token.encoded));

    let trace_token = signer
        .sign(
            &tenant_id,
            &success_instance,
            vec![EndpointScope::TracesRead],
            OffsetDateTime::now_utc(),
            Duration::seconds(60),
        )
        .expect("trace token");
    let (status, trace_page, trace_body): (reqwest::StatusCode, TracePageResponse, String) =
        resident_get(
            &success_resident.base_url,
            &success_resident.root_ca_pem,
            &format!("/runs/{success_run}/traces?redaction_policy=resident-test"),
            &trace_token,
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert!(!trace_body.contains(&trace_token.encoded));
    let events = trace_page
        .records
        .iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).expect("event"))
        .collect::<Vec<_>>();
    assert!(events
        .iter()
        .all(|event| event.identity.instance_id.as_ref() == Some(&success_instance)));
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::LoopTickStarted { .. }))
            .count(),
        1,
        "duplicate dispatch must not start a second tick"
    );
    let audit_credentials = events
        .iter()
        .filter_map(|event| match &event.kind {
            TraceEventKind::DaemonAudit { audit, .. } => audit.credential_id.clone(),
            _ => None,
        })
        .collect::<HashSet<_>>();
    assert_eq!(
        audit_credentials.len(),
        2,
        "resident trace export must retain one bounded correlation digest per create/start caller"
    );
    assert!(audit_credentials.iter().all(|credential_id| {
        credential_id.strip_prefix("sha256:").is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    }));
    assert!(events.iter().any(|event| match &event.kind {
        TraceEventKind::DaemonAudit { audit, .. } => {
            audit.principal.app.app_principal_id == "central-manager"
                && audit.principal.client_principal_id == "resident-dispatch-client"
        }
        _ => false,
    }));

    let (status, telemetry): (StatusCode, FleetTelemetrySnapshot) = call_manager(
        success_app.clone(),
        Method::POST,
        "/fleet/telemetry/read",
        &ManagerReadRequest {
            security: security.clone(),
            tenant_id: None,
            agent_id: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(telemetry.authority, TelemetryAuthority::ObservationalOnly);
    let run_telemetry = telemetry
        .runs
        .iter()
        .find(|run| run.run_id == success_run)
        .expect("resident run telemetry");
    assert_eq!(run_telemetry.status, splendor_types::RunStatus::Running);

    let (status, audit): (StatusCode, Vec<ManagerAuditEvent>) = call_manager(
        success_app.clone(),
        Method::POST,
        "/fleet/audit/read",
        &ManagerReadRequest {
            security: security.clone(),
            tenant_id: None,
            agent_id: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        audit
            .iter()
            .filter(|event| event.event_type == "run.dispatched")
            .count(),
        1
    );
    let audit_json = serde_json::to_string(&audit).expect("audit JSON");
    assert!(!audit_json.contains(&trace_token.encoded));
    assert_eq!(
        success_resident
            .state
            .run_authority_evaluation_count(&success_run)
            .expect("authority count"),
        0,
        "empty start tick does not fabricate an action authority evaluation"
    );

    let hostname_instance = success_instance.clone();
    let hostname_node = NodeId::parse("00000000-0000-4000-8000-000000000205").expect("node");
    let hostname_run = RunId::parse("44444444-4444-4444-8444-444444444448").expect("run");
    let hostname_app = manager_router(manager_state(
        signer.clone(),
        success_resident.root_ca_pem.clone(),
        &success_resident.base_url,
    ));
    let hostname_security = manager_security(&fleet_id);
    let hostname_url = success_resident
        .base_url
        .replacen("localhost", "127.0.0.1", 1);
    register_and_place(
        &hostname_app,
        &hostname_security,
        ResidentPlacementFixture {
            fleet_id: &fleet_id,
            node_id: &hostname_node,
            instance_id: &hostname_instance,
            tenant_id: &tenant_id,
            resident_url: &hostname_url,
            capability: "dispatch.hostname-denied",
        },
        signed_work_order(
            "wo_resident_hostname_denied",
            hostname_run,
            tenant_id.clone(),
            agent_id.clone(),
            "dispatch.hostname-denied",
        ),
    )
    .await;
    let (status, hostname_error): (StatusCode, ManagerApiErrorBody) = call_manager(
        hostname_app,
        Method::POST,
        "/work-orders/wo_resident_hostname_denied/dispatch",
        &DispatchWorkOrderRequest {
            security: hostname_security,
            target_node_id: Some(hostname_node),
        },
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(hostname_error.code, "resident_origin_not_allowed");

    let rejection_signer = caller_signer();
    let rejection_instance =
        InstanceId::parse("00000000-0000-4000-8000-000000000312").expect("instance");
    let rejection_node = NodeId::parse("00000000-0000-4000-8000-000000000214").expect("node");
    let rejection_run = RunId::parse("44444444-4444-4444-8444-444444444445").expect("run");
    let rejection_resident =
        spawn_resident(&rejection_signer, rejection_instance.clone(), &[7_u8; 32]).await;
    let rejection_app = manager_router(manager_state(
        rejection_signer.clone(),
        rejection_resident.root_ca_pem.clone(),
        &rejection_resident.base_url,
    ));
    let rejection_security = manager_security(&fleet_id);
    register_and_place(
        &rejection_app,
        &rejection_security,
        ResidentPlacementFixture {
            fleet_id: &fleet_id,
            node_id: &rejection_node,
            instance_id: &rejection_instance,
            tenant_id: &tenant_id,
            resident_url: &rejection_resident.base_url,
            capability: "dispatch.reject",
        },
        signed_work_order(
            "wo_real_resident_rejected",
            rejection_run.clone(),
            tenant_id.clone(),
            agent_id,
            "dispatch.reject",
        ),
    )
    .await;
    let (status, rejected): (StatusCode, ManagerApiErrorBody) = call_manager(
        rejection_app.clone(),
        Method::POST,
        "/work-orders/wo_real_resident_rejected/dispatch",
        &DispatchWorkOrderRequest {
            security: rejection_security.clone(),
            target_node_id: Some(rejection_node),
        },
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(rejected.code, "resident_create_rejected");
    assert!(rejected.message.contains("bad_signature"));

    let inspect_token = rejection_signer
        .sign(
            &tenant_id,
            &rejection_instance,
            vec![EndpointScope::RunsRead],
            OffsetDateTime::now_utc(),
            Duration::seconds(60),
        )
        .expect("inspect token");
    let (status, missing, body): (reqwest::StatusCode, ApiErrorBody, String) = resident_get(
        &rejection_resident.base_url,
        &rejection_resident.root_ca_pem,
        &format!("/runs/{rejection_run}"),
        &inspect_token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
    assert_eq!(missing.code, "invalid_run");
    assert!(!body.contains(&inspect_token.encoded));

    let (status, rejection_telemetry): (StatusCode, FleetTelemetrySnapshot) = call_manager(
        rejection_app.clone(),
        Method::POST,
        "/fleet/telemetry/read",
        &ManagerReadRequest {
            security: rejection_security.clone(),
            tenant_id: None,
            agent_id: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(rejection_telemetry.runs.is_empty());
    let (status, rejection_audit): (StatusCode, Vec<ManagerAuditEvent>) = call_manager(
        rejection_app,
        Method::POST,
        "/fleet/audit/read",
        &ManagerReadRequest {
            security: rejection_security,
            tenant_id: None,
            agent_id: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(rejection_audit
        .iter()
        .any(|event| event.event_type == "dispatch.failed"));
    assert!(!rejection_audit
        .iter()
        .any(|event| event.event_type == "run.dispatched"));
}

#[tokio::test]
async fn manager_admitted_approval_policy_reaches_real_tls_resident_without_broadening_authority() {
    let fleet_id = FleetId::parse(FLEET_ID).expect("fleet");
    let tenant_id = TenantId::parse(TENANT_ID).expect("tenant");
    let agent_id = AgentId::parse(AGENT_ID).expect("agent");
    let instance_id = InstanceId::new();
    let node_id = NodeId::new();
    let run_id = RunId::new();
    let signer = caller_signer();
    let resident = spawn_resident_with_scopes(
        &signer,
        instance_id.clone(),
        MANAGER_WORK_ORDER_KEY,
        vec![
            EndpointScope::RunsCreate,
            EndpointScope::RunsStart,
            EndpointScope::RunsRead,
            EndpointScope::TracesRead,
            EndpointScope::ActionsSubmit,
        ],
    )
    .await;
    let app = manager_router(manager_state(
        signer.clone(),
        resident.root_ca_pem.clone(),
        &resident.base_url,
    ));
    let security = manager_security(&fleet_id);
    let work_order_id = "wo_resident_approval_admission";
    let work_order = signed_work_order(
        work_order_id,
        run_id.clone(),
        tenant_id.clone(),
        agent_id.clone(),
        "approval.admission",
    );
    let approval_policy = resident_dispatch_approval_policy(&work_order);
    register_and_place_with_policies(
        &app,
        &security,
        ResidentPlacementFixture {
            fleet_id: &fleet_id,
            node_id: &node_id,
            instance_id: &instance_id,
            tenant_id: &tenant_id,
            resident_url: &resident.base_url,
            capability: "approval.admission",
        },
        work_order.clone(),
        vec![approval_policy.clone()],
    )
    .await;

    let dispatch_request = DispatchWorkOrderRequest {
        security: security.clone(),
        target_node_id: Some(node_id),
    };
    let (status, dispatch): (StatusCode, DispatchReport) = call_manager(
        app.clone(),
        Method::POST,
        &format!("/work-orders/{work_order_id}/dispatch"),
        &dispatch_request,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dispatch.run_id, run_id);
    let start: TickResponse = serde_json::from_str(
        dispatch
            .start_run_body
            .as_deref()
            .expect("retained resident start response"),
    )
    .expect("typed resident start response");
    assert_eq!(start.status, splendor_daemon::RunStatus::Running);
    assert!(
        start.action_outcomes.is_empty(),
        "policy_actions remain empty"
    );

    let trace_token = resident_token(&signer, &tenant_id, &instance_id, EndpointScope::TracesRead);
    let (trace_status, traces, _): (reqwest::StatusCode, TracePageResponse, String) = resident_get(
        &resident.base_url,
        &resident.root_ca_pem,
        &format!("/runs/{run_id}/traces?redaction_policy=resident-test"),
        &trace_token,
    )
    .await;
    assert_eq!(trace_status, reqwest::StatusCode::OK);
    let causal_trace_id = traces
        .records
        .first()
        .and_then(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .map(|event| event.trace_event_id)
        .expect("resident causal trace");

    let disallowed_token = resident_token(
        &signer,
        &tenant_id,
        &instance_id,
        EndpointScope::ActionsSubmit,
    );
    let (action_status, disallowed, _): (
        reqwest::StatusCode,
        splendor_gateway::ActionOutcome,
        String,
    ) = resident_post(
        &resident.base_url,
        &resident.root_ca_pem,
        "/actions",
        &SubmitActionRequest {
            action_id: Some(ActionId::new()),
            run_id: run_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            credential: None,
            audit_attribution: None,
            causal_trace_id: Some(causal_trace_id.clone()),
            action: resident_record_action("daemon.delete"),
            adapter: Some(RESIDENT_TEST_ADAPTER.to_string()),
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
            requested_at: Some(OffsetDateTime::now_utc()),
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        },
        &disallowed_token,
    )
    .await;
    assert_eq!(action_status, reqwest::StatusCode::OK);
    assert_eq!(disallowed.status, splendor_gateway::ActionStatus::Denied);
    assert!(disallowed
        .verification
        .reasons
        .iter()
        .any(|reason| reason == "trusted_action_profile_missing"));

    let action_id = ActionId::new();
    let requested_at = OffsetDateTime::now_utc();
    let approval_token = resident_token(
        &signer,
        &tenant_id,
        &instance_id,
        EndpointScope::ActionsSubmit,
    );
    let (action_status, outcome, _): (
        reqwest::StatusCode,
        splendor_gateway::ActionOutcome,
        String,
    ) = resident_post(
        &resident.base_url,
        &resident.root_ca_pem,
        "/actions",
        &SubmitActionRequest {
            action_id: Some(action_id.clone()),
            run_id: run_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            credential: None,
            audit_attribution: None,
            causal_trace_id: Some(causal_trace_id),
            action: resident_record_action("daemon.record"),
            adapter: Some(RESIDENT_TEST_ADAPTER.to_string()),
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
            requested_at: Some(requested_at),
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        },
        &approval_token,
    )
    .await;
    assert_eq!(action_status, reqwest::StatusCode::OK);
    assert_eq!(
        outcome.status,
        splendor_gateway::ActionStatus::NeedsApproval
    );
    let challenge = outcome
        .approval_challenge
        .expect("manager-admitted policy creates exact resident challenge");
    assert_eq!(challenge.policy_id, approval_policy.policy_id);
    assert_eq!(challenge.action_id, action_id);
    assert_eq!(challenge.requested_at, requested_at);
    assert_eq!(challenge.tenant_id, tenant_id);
    assert_eq!(challenge.agent_id, agent_id);
    assert_eq!(challenge.run_id, run_id);
    assert_eq!(challenge.adapter, RESIDENT_TEST_ADAPTER);
    assert!(challenge
        .receipt_audience
        .contains(&instance_id.to_string()));

    let inspect_token = resident_token(&signer, &tenant_id, &instance_id, EndpointScope::RunsRead);
    let (inspect_status, inspected, _): (reqwest::StatusCode, RunInspectResponse, String) =
        resident_get(
            &resident.base_url,
            &resident.root_ca_pem,
            &format!("/runs/{run_id}"),
            &inspect_token,
        )
        .await;
    assert_eq!(inspect_status, reqwest::StatusCode::OK);
    assert_eq!(
        inspected.status,
        splendor_daemon::RunStatus::WaitingForApproval
    );
    assert_eq!(inspected.adapter_executions, 0);

    let mut replacement_policy = approval_policy;
    replacement_policy.reason = "attempted post-dispatch policy swap".to_string();
    let (replacement_status, replacement_error): (StatusCode, ManagerApiErrorBody) = call_manager(
        app.clone(),
        Method::POST,
        "/work-orders",
        &SubmitWorkOrderRequest {
            security: security.clone(),
            work_order,
            expected_audience: "central-manager".to_string(),
            approval_policies: vec![replacement_policy],
        },
    )
    .await;
    assert_eq!(replacement_status, StatusCode::CONFLICT);
    assert_eq!(
        replacement_error.code,
        "work_order_approval_policies_replacement"
    );

    let (duplicate_status, duplicate): (StatusCode, DispatchReport) = call_manager(
        app,
        Method::POST,
        &format!("/work-orders/{work_order_id}/dispatch"),
        &dispatch_request,
    )
    .await;
    assert_eq!(duplicate_status, StatusCode::OK);
    assert_eq!(duplicate.trace_event_id, dispatch.trace_event_id);
    assert_eq!(duplicate.start_run_body, dispatch.start_run_body);
}

#[tokio::test]
async fn granted_approval_revocation_requires_exact_resident_acknowledgement() {
    let fleet_id = FleetId::parse(FLEET_ID).expect("fleet");
    let tenant_id = TenantId::parse(TENANT_ID).expect("tenant");
    let agent_id = AgentId::parse(AGENT_ID).expect("agent");
    let instance_id = InstanceId::new();
    let node_id = NodeId::new();
    let run_id = RunId::new();
    let resident_signer = caller_signer();
    let approval_signer = CallerTokenSigner::generate_for_test(
        "urn:splendor:approval-control-plane",
        "approval-control-plane",
        "approval-client",
        "approval-manager-integration",
    )
    .expect("approval signer");
    let resident = spawn_resident_with_scopes(
        &resident_signer,
        instance_id.clone(),
        MANAGER_WORK_ORDER_KEY,
        vec![
            EndpointScope::RunsCreate,
            EndpointScope::RunsStart,
            EndpointScope::ActionsSubmit,
            EndpointScope::ApprovalReceiptsRevoke,
        ],
    )
    .await;
    let manager = manager_state_with_approval_auth(
        resident_signer.clone(),
        &approval_signer,
        resident.root_ca_pem.clone(),
        &resident.base_url,
    );
    let app = manager_router(manager);
    let security = manager_security(&fleet_id);
    let work_order_id = "wo_resident_approval_revocation";
    let work_order = signed_work_order(
        work_order_id,
        run_id.clone(),
        tenant_id.clone(),
        agent_id.clone(),
        "approval.revocation",
    );
    register_and_place(
        &app,
        &security,
        ResidentPlacementFixture {
            fleet_id: &fleet_id,
            node_id: &node_id,
            instance_id: &instance_id,
            tenant_id: &tenant_id,
            resident_url: &resident.base_url,
            capability: "approval.revocation",
        },
        work_order,
    )
    .await;
    let (status, dispatch): (StatusCode, DispatchReport) = call_manager(
        app.clone(),
        Method::POST,
        &format!("/work-orders/{work_order_id}/dispatch"),
        &DispatchWorkOrderRequest {
            security,
            target_node_id: Some(node_id),
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(dispatch.run_id, run_id);
    assert_eq!(dispatch.selected_instance_id, instance_id);

    let now = OffsetDateTime::now_utc();
    let approval_id = ApprovalId::new();
    let action_id = ActionId::new();
    let audience = authority_receipt_config()
        .for_resident_instance(&instance_id)
        .expect("resident receipt config")
        .audience_for_run(&run_id);
    let challenge = ApprovalChallenge {
        schema_version: APPROVAL_CHALLENGE_SCHEMA_VERSION.to_string(),
        approval_id: approval_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: run_id.clone(),
        action_id: action_id.clone(),
        action_name: "daemon.record".to_string(),
        adapter: RESIDENT_TEST_ADAPTER.to_string(),
        policy_id: "resident-approval-revocation".to_string(),
        risk_level: Some("high".to_string()),
        subject: PrincipalId::new(),
        authority_decision_id: AuthorityDecisionId::new(),
        obligation_id: AuthorityObligationId::new(),
        receipt_audience: audience.clone(),
        canonical_request_digest: format!("blake3:{}", "1".repeat(64)),
        gateway_action_request_digest: format!("blake3:{}", "2".repeat(64)),
        physical_action_resource_coordinate: None,
        authority_decision_digest: format!("blake3:{}", "3".repeat(64)),
        requested_at: now,
        expires_at: now + Duration::minutes(5),
    };
    let request_token = approval_token(&approval_signer, &fleet_id);
    let (status, requested): (StatusCode, GovernanceApprovalRecord) = call_manager_with_token(
        app.clone(),
        Method::POST,
        "/approvals",
        &ApprovalRequestPayload {
            security: approval_security(&request_token),
            approval_id: approval_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: run_id.clone(),
            action_id: action_id.clone(),
            action_name: challenge.action_name.clone(),
            adapter: challenge.adapter.clone(),
            policy_id: challenge.policy_id.clone(),
            risk_level: challenge.risk_level.clone(),
            audience: audience.clone(),
            expires_at: challenge.expires_at,
            reason: "resident approval requested".to_string(),
            challenge: Some(challenge),
        },
        &request_token.encoded,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(requested.status, "requested");

    let grant_token = approval_token(&approval_signer, &fleet_id);
    let (status, granted): (StatusCode, GovernanceApprovalRecord) = call_manager_with_token(
        app.clone(),
        Method::POST,
        &format!("/approvals/{approval_id}/grant"),
        &ApprovalDecisionRequest {
            security: approval_security(&grant_token),
            reason: "resident approval granted".to_string(),
            expires_at: None,
        },
        &grant_token.encoded,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let receipt = granted
        .authority_obligation_receipt
        .clone()
        .expect("granted raw receipt retained");
    assert_eq!(receipt.audience, audience);

    let revocation_body = ResidentApprovalReceiptRevocationRequest {
        schema_version: RESIDENT_APPROVAL_RECEIPT_REVOCATION_SCHEMA_VERSION.to_string(),
        authority_obligation_receipt: receipt.clone(),
        reason: "scope isolation".to_string(),
    };
    for (case, path_run_id, token_tenant, scopes) in [
        (
            "existing",
            run_id.clone(),
            tenant_id.clone(),
            vec![EndpointScope::ActionsSubmit],
        ),
        (
            "nonexistent",
            RunId::new(),
            tenant_id.clone(),
            vec![EndpointScope::ActionsSubmit],
        ),
        (
            "cross_tenant",
            run_id.clone(),
            TenantId::new(),
            vec![EndpointScope::ActionsSubmit],
        ),
        (
            "extra_scope",
            run_id.clone(),
            tenant_id.clone(),
            vec![
                EndpointScope::ApprovalReceiptsRevoke,
                EndpointScope::ActionsSubmit,
            ],
        ),
    ] {
        let wrong_scope = resident_signer
            .sign(
                &token_tenant,
                &instance_id,
                scopes,
                OffsetDateTime::now_utc(),
                Duration::seconds(60),
            )
            .expect("wrong-scope resident token remains cryptographically valid");
        let (status, error, _): (reqwest::StatusCode, ApiErrorBody, String) = resident_post(
            &resident.base_url,
            &resident.root_ca_pem,
            &format!(
                "/runs/{path_run_id}/approval-receipts/{}/revoke",
                receipt.receipt_id
            ),
            &revocation_body,
            &wrong_scope,
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "case={case}");
        assert_eq!(error.code, "missing_scope", "case={case}");
    }

    let mut concealed_response = None;
    for (case, path_run_id, token_tenant) in [
        ("nonexistent", RunId::new(), tenant_id.clone()),
        ("cross_tenant", run_id.clone(), TenantId::new()),
    ] {
        let token = resident_token(
            &resident_signer,
            &token_tenant,
            &instance_id,
            EndpointScope::ApprovalReceiptsRevoke,
        );
        let (status, error, _): (reqwest::StatusCode, ApiErrorBody, String) = resident_post(
            &resident.base_url,
            &resident.root_ca_pem,
            &format!(
                "/runs/{path_run_id}/approval-receipts/{}/revoke",
                receipt.receipt_id
            ),
            &revocation_body,
            &token,
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::NOT_FOUND, "case={case}");
        assert_eq!(error.code, "invalid_run", "case={case}");
        assert_eq!(error.details["run_id"], path_run_id.to_string());
        let normalized = (status, error.code, error.message);
        if let Some(expected) = concealed_response.as_ref() {
            assert_eq!(
                &normalized, expected,
                "run existence leaked for case={case}"
            );
        } else {
            concealed_response = Some(normalized);
        }
    }

    let wrong_audience = resident_token(
        &resident_signer,
        &tenant_id,
        &InstanceId::new(),
        EndpointScope::ApprovalReceiptsRevoke,
    );
    let (status, error, _): (reqwest::StatusCode, ApiErrorBody, String) = resident_post(
        &resident.base_url,
        &resident.root_ca_pem,
        &format!(
            "/runs/{run_id}/approval-receipts/{}/revoke",
            receipt.receipt_id
        ),
        &revocation_body,
        &wrong_audience,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "wrong_caller_token_audience");

    let mut wrong_target_body = revocation_body.clone();
    wrong_target_body.authority_obligation_receipt.audience =
        "splendor.daemon.approval_receipt.v2:instance:00000000-0000-4000-8000-000000000999:run:00000000-0000-4000-8000-000000000998".to_string();
    let wrong_target_token = resident_token(
        &resident_signer,
        &tenant_id,
        &instance_id,
        EndpointScope::ApprovalReceiptsRevoke,
    );
    let (status, _error, _): (reqwest::StatusCode, ApiErrorBody, String) = resident_post(
        &resident.base_url,
        &resident.root_ca_pem,
        &format!(
            "/runs/{run_id}/approval-receipts/{}/revoke",
            receipt.receipt_id
        ),
        &wrong_target_body,
        &wrong_target_token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);

    let revoke_token = approval_token(&approval_signer, &fleet_id);
    let (status, revoked): (StatusCode, GovernanceApprovalRecord) = call_manager_with_token(
        app,
        Method::POST,
        &format!("/approvals/{approval_id}/revoke"),
        &ApprovalDecisionRequest {
            security: approval_security(&revoke_token),
            reason: "resident approval revoked".to_string(),
            expires_at: None,
        },
        &revoke_token.encoded,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revoked.status, "revoked");
    assert_eq!(revoked.authority_obligation_receipt, Some(receipt.clone()));
    let ack = revoked
        .resident_receipt_revocation_ack
        .expect("exact resident acknowledgement");
    assert_eq!(ack.receipt_id, receipt.receipt_id);
    assert_eq!(ack.approval_id, approval_id);
    assert_eq!(ack.target_instance_id, instance_id);
    assert_eq!(ack.run_id, run_id);
    assert_eq!(ack.receipt_audience, receipt.audience);
    assert_eq!(ack.status, ResidentApprovalReceiptRevocationStatus::Revoked);

    let duplicate_token = resident_token(
        &resident_signer,
        &tenant_id,
        &instance_id,
        EndpointScope::ApprovalReceiptsRevoke,
    );
    let (status, duplicate, _): (
        reqwest::StatusCode,
        ResidentApprovalReceiptRevocationAck,
        String,
    ) = resident_post(
        &resident.base_url,
        &resident.root_ca_pem,
        &format!(
            "/runs/{run_id}/approval-receipts/{}/revoke",
            receipt.receipt_id
        ),
        &revocation_body,
        &duplicate_token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(
        duplicate.status,
        ResidentApprovalReceiptRevocationStatus::AlreadyRevoked
    );
}

#[tokio::test]
async fn real_resident_start_rejection_is_terminal_effect_unknown_without_running_telemetry() {
    let fleet_id = FleetId::parse(FLEET_ID).expect("fleet");
    let tenant_id = TenantId::parse(TENANT_ID).expect("tenant");
    let agent_id = AgentId::parse(AGENT_ID).expect("agent");
    let instance_id = InstanceId::parse("00000000-0000-4000-8000-000000000322").expect("instance");
    let node_id = NodeId::parse("00000000-0000-4000-8000-000000000224").expect("node");
    let run_id = RunId::parse("44444444-4444-4444-8444-444444444446").expect("run");
    let signer = caller_signer();
    let resident = spawn_resident_with_scopes(
        &signer,
        instance_id.clone(),
        MANAGER_WORK_ORDER_KEY,
        vec![
            EndpointScope::RunsCreate,
            EndpointScope::RunsRead,
            EndpointScope::TracesRead,
        ],
    )
    .await;
    let app = manager_router(manager_state(
        signer.clone(),
        resident.root_ca_pem.clone(),
        &resident.base_url,
    ));
    let security = manager_security(&fleet_id);
    register_and_place(
        &app,
        &security,
        ResidentPlacementFixture {
            fleet_id: &fleet_id,
            node_id: &node_id,
            instance_id: &instance_id,
            tenant_id: &tenant_id,
            resident_url: &resident.base_url,
            capability: "dispatch.partial",
        },
        signed_work_order(
            "wo_real_resident_partial",
            run_id.clone(),
            tenant_id.clone(),
            agent_id,
            "dispatch.partial",
        ),
    )
    .await;
    let request = DispatchWorkOrderRequest {
        security: security.clone(),
        target_node_id: Some(node_id),
    };
    for attempt in 0..2 {
        let (status, error): (StatusCode, ManagerApiErrorBody) = call_manager(
            app.clone(),
            Method::POST,
            "/work-orders/wo_real_resident_partial/dispatch",
            &request,
        )
        .await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "attempt {attempt}");
        assert_eq!(
            error.code, "resident_start_effect_unknown",
            "attempt {attempt}"
        );
        assert!(error.message.contains("automatic retry is forbidden"));
    }

    let inspect_token = signer
        .sign(
            &tenant_id,
            &instance_id,
            vec![EndpointScope::RunsRead],
            OffsetDateTime::now_utc(),
            Duration::seconds(60),
        )
        .expect("inspect token");
    let (status, run, _): (
        reqwest::StatusCode,
        splendor_daemon::RunInspectResponse,
        String,
    ) = resident_get(
        &resident.base_url,
        &resident.root_ca_pem,
        &format!("/runs/{run_id}"),
        &inspect_token,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(run.status, splendor_daemon::RunStatus::Pending);
    assert_eq!(
        run.ticks, 0,
        "duplicate partial dispatch must not retry start"
    );

    let (status, telemetry): (StatusCode, FleetTelemetrySnapshot) = call_manager(
        app.clone(),
        Method::POST,
        "/fleet/telemetry/read",
        &ManagerReadRequest {
            security: security.clone(),
            tenant_id: None,
            agent_id: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(telemetry.runs.is_empty());
    let (status, audit): (StatusCode, Vec<ManagerAuditEvent>) = call_manager(
        app,
        Method::POST,
        "/fleet/audit/read",
        &ManagerReadRequest {
            security,
            tenant_id: None,
            agent_id: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        audit
            .iter()
            .filter(|event| event.event_type == "dispatch.effect_unknown")
            .count(),
        1
    );
    assert!(!audit
        .iter()
        .any(|event| event.event_type == "run.dispatched"));
}

#[tokio::test]
async fn start_timeout_is_effect_unknown_and_duplicate_dispatch_never_retries_it() {
    let fleet_id = FleetId::parse(FLEET_ID).expect("fleet");
    let tenant_id = TenantId::parse(TENANT_ID).expect("tenant");
    let agent_id = AgentId::parse(AGENT_ID).expect("agent");
    let instance_id = InstanceId::parse("00000000-0000-4000-8000-000000000332").expect("instance");
    let node_id = NodeId::parse("00000000-0000-4000-8000-000000000234").expect("node");
    let run_id = RunId::parse("44444444-4444-4444-8444-444444444447").expect("run");
    let signer = caller_signer();
    let fault = spawn_timeout_fault_server().await;
    let app = manager_router(manager_state_with_options(
        signer,
        ResidentDispatchOptions {
            start_timeout: StdDuration::from_millis(500),
            allowed_origins: vec![fault.base_url.clone()],
            ..ResidentDispatchOptions::loopback_test()
        },
    ));
    let security = manager_security(&fleet_id);
    register_and_place(
        &app,
        &security,
        ResidentPlacementFixture {
            fleet_id: &fleet_id,
            node_id: &node_id,
            instance_id: &instance_id,
            tenant_id: &tenant_id,
            resident_url: &fault.base_url,
            capability: "dispatch.timeout",
        },
        signed_work_order(
            "wo_resident_start_timeout",
            run_id,
            tenant_id.clone(),
            agent_id,
            "dispatch.timeout",
        ),
    )
    .await;
    let request = DispatchWorkOrderRequest {
        security: security.clone(),
        target_node_id: Some(node_id),
    };
    let first_app = app.clone();
    let first_request = request.clone();
    let first = tokio::spawn(async move {
        call_manager::<_, ManagerApiErrorBody>(
            first_app,
            Method::POST,
            "/work-orders/wo_resident_start_timeout/dispatch",
            &first_request,
        )
        .await
    });
    tokio::time::timeout(StdDuration::from_millis(250), async {
        while fault.start_calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first dispatch reached start");
    let (concurrent_status, concurrent_error): (StatusCode, ManagerApiErrorBody) = call_manager(
        app.clone(),
        Method::POST,
        "/work-orders/wo_resident_start_timeout/dispatch",
        &request,
    )
    .await;
    assert_eq!(concurrent_status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(concurrent_error.code, "resident_start_effect_unknown");

    let (status, error) = first.await.expect("first dispatch task");
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(error.code, "resident_start_effect_unknown");
    assert!(error.message.contains("automatic retry is forbidden"));

    let (status, error): (StatusCode, ManagerApiErrorBody) = call_manager(
        app.clone(),
        Method::POST,
        "/work-orders/wo_resident_start_timeout/dispatch",
        &request,
    )
    .await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(error.code, "resident_start_effect_unknown");
    assert_eq!(
        fault.start_calls.load(Ordering::SeqCst),
        1,
        "duplicate dispatch reused the terminal unknown-effect result"
    );

    let (status, telemetry): (StatusCode, FleetTelemetrySnapshot) = call_manager(
        app.clone(),
        Method::POST,
        "/fleet/telemetry/read",
        &ManagerReadRequest {
            security: security.clone(),
            tenant_id: None,
            agent_id: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(telemetry.runs.is_empty());
    let (status, audit): (StatusCode, Vec<ManagerAuditEvent>) = call_manager(
        app,
        Method::POST,
        "/fleet/audit/read",
        &ManagerReadRequest {
            security,
            tenant_id: None,
            agent_id: None,
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        audit
            .iter()
            .filter(|event| event.event_type == "dispatch.effect_unknown")
            .count(),
        1
    );
    assert!(!audit
        .iter()
        .any(|event| event.event_type == "run.dispatched"));
}

#[tokio::test]
async fn dispatch_gate_makes_revoke_wait_through_create_and_start_when_dispatch_wins() {
    let fleet_id = FleetId::parse(FLEET_ID).expect("fleet");
    let tenant_id = TenantId::parse(TENANT_ID).expect("tenant");
    let agent_id = AgentId::parse(AGENT_ID).expect("agent");
    let node_id = NodeId::new();
    let instance_id = InstanceId::new();
    let run_id = RunId::new();
    let signer = caller_signer();
    let resident = spawn_barrier_dispatch_server().await;
    let app = manager_router(manager_state_with_options(
        signer,
        ResidentDispatchOptions {
            allowed_origins: vec![resident.base_url.clone()],
            ..ResidentDispatchOptions::loopback_test()
        },
    ));
    let security = manager_security(&fleet_id);
    register_and_place(
        &app,
        &security,
        ResidentPlacementFixture {
            fleet_id: &fleet_id,
            node_id: &node_id,
            instance_id: &instance_id,
            tenant_id: &tenant_id,
            resident_url: &resident.base_url,
            capability: "dispatch.revoke_race",
        },
        signed_work_order(
            "wo_dispatch_wins_revoke_race",
            run_id,
            tenant_id.clone(),
            agent_id,
            "dispatch.revoke_race",
        ),
    )
    .await;

    let dispatch_app = app.clone();
    let dispatch_security = security.clone();
    let dispatch_node = node_id.clone();
    let dispatch = tokio::spawn(async move {
        call_manager::<_, DispatchReport>(
            dispatch_app,
            Method::POST,
            "/work-orders/wo_dispatch_wins_revoke_race/dispatch",
            &DispatchWorkOrderRequest {
                security: dispatch_security,
                target_node_id: Some(dispatch_node),
            },
        )
        .await
    });
    resident.create_entered.wait().await;

    let revoke_app = app.clone();
    let revoke_security = security.clone();
    let mut revoke = tokio::spawn(async move {
        call_manager::<_, serde_json::Value>(
            revoke_app,
            Method::POST,
            "/work-orders/wo_dispatch_wins_revoke_race/revoke",
            &RevokeWorkOrderRequest {
                security: revoke_security,
                reason: "race revocation".to_string(),
            },
        )
        .await
    });
    assert!(
        tokio::time::timeout(StdDuration::from_millis(50), &mut revoke)
            .await
            .is_err()
    );

    resident.create_release.wait().await;
    resident.start_entered.wait().await;
    assert!(
        tokio::time::timeout(StdDuration::from_millis(50), &mut revoke)
            .await
            .is_err()
    );
    resident.start_release.wait().await;

    let (dispatch_status, _) = dispatch.await.expect("dispatch task");
    assert_eq!(dispatch_status, StatusCode::OK);
    let (revoke_status, revoke_body) = revoke.await.expect("revoke task");
    assert_eq!(revoke_status, StatusCode::OK);
    assert_eq!(revoke_body["revoked"], true);
    assert_eq!(resident.create_calls.load(Ordering::SeqCst), 1);
    assert_eq!(resident.start_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dispatch_revalidates_expiry_after_create_and_sends_no_start() {
    let fleet_id = FleetId::parse(FLEET_ID).expect("fleet");
    let tenant_id = TenantId::parse(TENANT_ID).expect("tenant");
    let agent_id = AgentId::parse(AGENT_ID).expect("agent");
    let node_id = NodeId::new();
    let instance_id = InstanceId::new();
    let run_id = RunId::new();
    let signer = caller_signer();
    let resident = spawn_barrier_dispatch_server().await;
    let app = manager_router(manager_state_with_options(
        signer,
        ResidentDispatchOptions {
            allowed_origins: vec![resident.base_url.clone()],
            ..ResidentDispatchOptions::loopback_test()
        },
    ));
    let security = manager_security(&fleet_id);
    register_and_place(
        &app,
        &security,
        ResidentPlacementFixture {
            fleet_id: &fleet_id,
            node_id: &node_id,
            instance_id: &instance_id,
            tenant_id: &tenant_id,
            resident_url: &resident.base_url,
            capability: "dispatch.expiry_revalidation",
        },
        signed_work_order_expiring_at(
            "wo_expiry_between_create_and_start",
            run_id,
            tenant_id.clone(),
            agent_id,
            "dispatch.expiry_revalidation",
            OffsetDateTime::now_utc() + Duration::seconds(1),
        ),
    )
    .await;

    let dispatch = tokio::spawn(async move {
        call_manager::<_, ManagerApiErrorBody>(
            app,
            Method::POST,
            "/work-orders/wo_expiry_between_create_and_start/dispatch",
            &DispatchWorkOrderRequest {
                security,
                target_node_id: Some(node_id),
            },
        )
        .await
    });
    resident.create_entered.wait().await;
    tokio::time::sleep(StdDuration::from_millis(1_100)).await;
    resident.create_release.wait().await;

    let (status, error) = dispatch.await.expect("dispatch task");
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "expired_work_order");
    assert_eq!(resident.create_calls.load(Ordering::SeqCst), 1);
    assert_eq!(resident.start_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn abort_after_start_send_leaves_terminal_effect_unknown_quarantine() {
    let fleet_id = FleetId::parse(FLEET_ID).expect("fleet");
    let tenant_id = TenantId::parse(TENANT_ID).expect("tenant");
    let agent_id = AgentId::parse(AGENT_ID).expect("agent");
    let node_id = NodeId::new();
    let instance_id = InstanceId::new();
    let run_id = RunId::new();
    let signer = caller_signer();
    let resident = spawn_barrier_dispatch_server().await;
    let app = manager_router(manager_state_with_options(
        signer,
        ResidentDispatchOptions {
            allowed_origins: vec![resident.base_url.clone()],
            ..ResidentDispatchOptions::loopback_test()
        },
    ));
    let security = manager_security(&fleet_id);
    register_and_place(
        &app,
        &security,
        ResidentPlacementFixture {
            fleet_id: &fleet_id,
            node_id: &node_id,
            instance_id: &instance_id,
            tenant_id: &tenant_id,
            resident_url: &resident.base_url,
            capability: "dispatch.abort_after_send",
        },
        signed_work_order(
            "wo_abort_after_start_send",
            run_id,
            tenant_id.clone(),
            agent_id,
            "dispatch.abort_after_send",
        ),
    )
    .await;
    let request = DispatchWorkOrderRequest {
        security: security.clone(),
        target_node_id: Some(node_id),
    };

    let first_app = app.clone();
    let first_request = request.clone();
    let dispatch = tokio::spawn(async move {
        call_manager::<_, DispatchReport>(
            first_app,
            Method::POST,
            "/work-orders/wo_abort_after_start_send/dispatch",
            &first_request,
        )
        .await
    });
    resident.create_entered.wait().await;
    resident.create_release.wait().await;
    resident.start_entered.wait().await;
    dispatch.abort();
    assert!(dispatch
        .await
        .expect_err("dispatch cancelled")
        .is_cancelled());

    let (retry_status, retry_error): (StatusCode, ManagerApiErrorBody) = call_manager(
        app,
        Method::POST,
        "/work-orders/wo_abort_after_start_send/dispatch",
        &request,
    )
    .await;
    assert_eq!(retry_status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(retry_error.code, "resident_start_effect_unknown");
    assert!(retry_error.message.contains("automatic retry is forbidden"));
    assert_eq!(resident.create_calls.load(Ordering::SeqCst), 1);
    assert_eq!(resident.start_calls.load(Ordering::SeqCst), 1);
    resident.start_release.wait().await;
}

#[tokio::test]
async fn every_post_send_start_fault_is_terminal_effect_unknown_without_retry_or_telemetry() {
    let fleet_id = FleetId::parse(FLEET_ID).expect("fleet");
    let tenant_id = TenantId::parse(TENANT_ID).expect("tenant");
    let agent_id = AgentId::parse(AGENT_ID).expect("agent");
    for (index, fault_kind) in [
        PostSendStartFault::ExecuteThenReset,
        PostSendStartFault::Malformed,
        PostSendStartFault::Oversized,
        PostSendStartFault::WrongRunId,
        PostSendStartFault::InternalServerError,
    ]
    .into_iter()
    .enumerate()
    {
        let fault = spawn_post_send_fault_server(fault_kind).await;
        let signer = caller_signer();
        let app = manager_router(manager_state_with_options(
            signer,
            ResidentDispatchOptions {
                start_timeout: StdDuration::from_millis(500),
                maximum_response_bytes: 512,
                allowed_origins: vec![fault.base_url.clone()],
                ..ResidentDispatchOptions::loopback_test()
            },
        ));
        let security = manager_security(&fleet_id);
        let node_id = NodeId::new();
        let instance_id = InstanceId::new();
        let run_id = RunId::new();
        let work_order_id = format!("wo_post_send_fault_{index}");
        let capability = format!("dispatch.post_send_fault.{index}");
        register_and_place(
            &app,
            &security,
            ResidentPlacementFixture {
                fleet_id: &fleet_id,
                node_id: &node_id,
                instance_id: &instance_id,
                tenant_id: &tenant_id,
                resident_url: &fault.base_url,
                capability: &capability,
            },
            signed_work_order(
                &work_order_id,
                run_id,
                tenant_id.clone(),
                agent_id.clone(),
                &capability,
            ),
        )
        .await;
        let request = DispatchWorkOrderRequest {
            security: security.clone(),
            target_node_id: Some(node_id),
        };
        let uri = format!("/work-orders/{work_order_id}/dispatch");
        for attempt in 0..2 {
            let (status, error): (StatusCode, ManagerApiErrorBody) =
                call_manager(app.clone(), Method::POST, &uri, &request).await;
            assert_eq!(
                status,
                StatusCode::GATEWAY_TIMEOUT,
                "{fault_kind:?} attempt {attempt}"
            );
            assert_eq!(
                error.code, "resident_start_effect_unknown",
                "{fault_kind:?} attempt {attempt}"
            );
            assert!(error.message.contains("automatic retry is forbidden"));
        }
        assert_eq!(
            fault.start_calls.load(Ordering::SeqCst),
            1,
            "{fault_kind:?} must never be retried"
        );
        let (status, telemetry): (StatusCode, FleetTelemetrySnapshot) = call_manager(
            app.clone(),
            Method::POST,
            "/fleet/telemetry/read",
            &ManagerReadRequest {
                security: security.clone(),
                tenant_id: None,
                agent_id: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(telemetry.runs.is_empty());
        let (status, audit): (StatusCode, Vec<ManagerAuditEvent>) = call_manager(
            app,
            Method::POST,
            "/fleet/audit/read",
            &ManagerReadRequest {
                security,
                tenant_id: None,
                agent_id: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            audit
                .iter()
                .filter(|event| event.event_type == "dispatch.effect_unknown")
                .count(),
            1
        );
        assert!(!audit
            .iter()
            .any(|event| event.event_type == "run.dispatched"));
    }
}
