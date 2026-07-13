use axum::body::{to_bytes, Body};
use axum::extract::{Path, State};
use axum::http::{Method, Request, StatusCode};
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
    router as manager_router, DispatchReport, DispatchWorkOrderRequest, ManagerApiErrorBody,
    ManagerAuditEvent, ManagerReadRequest, ManagerSecurityFields, ManagerState,
    PlacementEvaluationRequest, RegisterInstanceRequest, RegisterNodeRequest,
    ResidentDispatchOptions, SubmitWorkOrderRequest, WorkOrderValidationReport,
};
use splendor_daemon::{
    router as resident_router, ApiErrorBody, CreateRunResponse, DaemonConfig, DaemonState,
    StateHeadResponse, TickResponse, TracePageResponse,
};
use splendor_types::{
    AgentId, AppPrincipal, AuditAttribution, CallerCredential, ClientPrincipal, CredentialAudience,
    CredentialBinding, DataLocality, EndpointScope, FleetId, FleetTelemetrySnapshot, InstanceId,
    InstanceRegistration, NodeId, NodeRegistration, PlacementDecision, PlacementExecutionMode,
    PlacementRequest, PlacementTarget, RevocationStatus, RunId, TelemetryAuthority, TenantId,
    TraceEvent, TraceEventKind, WorkOrder, WorkOrderEnvelope, WorkOrderId, WorkOrderKeyring,
    WorkOrderPlacement, WorkOrderQuotaPolicy,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
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

impl Drop for FaultHarness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[derive(Clone)]
struct TimeoutFaultState {
    start_calls: Arc<AtomicUsize>,
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
    let state = DaemonState::new(DaemonConfig::resident(
        instance_id,
        verifier,
        work_order_keyring,
        policy_keyring,
    ));
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
            EndpointScope::FleetRead,
            EndpointScope::FleetDispatch,
            EndpointScope::WorkOrdersSubmit,
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
) -> InstanceRegistration {
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("timestamp");
    serde_json::from_value(serde_json::json!({
        "instance_id": instance_id,
        "node_id": node_id,
        "runtime_mode": "resident",
        "hosted_tenants": [tenant_id],
        "supported_features": ["runtime.resident", "gateway.verified"],
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
    WorkOrderEnvelope::signed_with_shared_secret(
        WorkOrder {
            schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
            work_order_id: WorkOrderId::try_new(work_order_id).expect("work-order id"),
            tenant_id,
            agent_id,
            run_id: Some(run_id),
            objective: "admit and start one resident run through the real daemon".to_string(),
            allowed_actions: vec!["daemon.record".to_string()],
            allowed_adapters: vec!["daemon.recording".to_string()],
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
            expires_at: now + Duration::minutes(10),
            revocation: RevocationStatus::Active,
        },
        WORK_ORDER_KEY_ID,
        MANAGER_WORK_ORDER_KEY,
    )
    .expect("signed work order")
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

fn manager_state(signer: CallerTokenSigner, root_ca_pem: Vec<u8>) -> ManagerState {
    manager_state_with_options(
        signer,
        ResidentDispatchOptions {
            root_ca_pem: Some(root_ca_pem),
            ..ResidentDispatchOptions::production()
        },
    )
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
    let success_manager = manager_state(signer.clone(), success_resident.root_ca_pem.clone());
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
        1,
        "resident trace export must redact caller JTIs"
    );
    assert_eq!(
        audit_credentials.into_iter().next().as_deref(),
        Some("[REDACTED]")
    );
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
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(hostname_error.code, "resident_create_transport_error");

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
async fn real_resident_start_rejection_is_terminal_partial_failure_without_running_telemetry() {
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
    let app = manager_router(manager_state(signer.clone(), resident.root_ca_pem.clone()));
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
        assert_eq!(status, StatusCode::BAD_GATEWAY, "attempt {attempt}");
        assert_eq!(error.code, "resident_start_rejected", "attempt {attempt}");
        assert!(error.message.contains("invalid_caller_token_scope"));
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
            .filter(|event| event.event_type == "dispatch.partial_failure")
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
    assert_eq!(concurrent_status, StatusCode::CONFLICT);
    assert_eq!(concurrent_error.code, "dispatch_in_progress");

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
