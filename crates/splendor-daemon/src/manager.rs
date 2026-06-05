//! Minimal central manager API for UC-E2E-S4 acceptance.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splendor_kernel::{FleetTelemetryCollector, InMemoryNodeRegistry, NodeRegistry};
use splendor_store::{
    CentralTraceIndex, InMemoryCentralTraceIndex, TraceSyncBatch, TraceSyncReport,
};
use splendor_types::{
    select_placement, AuditAttribution, CallerCredential, CredentialAudience, CredentialBinding,
    DataLocality, EndpointScope, FleetId, FleetTelemetrySnapshot, HealthStatus, InstanceId,
    InstanceRegistration, InstanceTelemetry, MessageEnvelope, MessageId, NodeHeartbeat, NodeId,
    NodeRegistration, PlacementCandidate, PlacementDecision, PlacementDecisionStatus,
    PlacementExecutionMode, PlacementRequest, PlacementTarget, RevocationStatus, RunId, RunStatus,
    RunTelemetry, TelemetryRuntimeMode, TenantId, TraceSyncTelemetry, WorkOrderEnvelope,
    WorkOrderKeyring, WorkOrderValidationContext,
};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

#[derive(Clone)]
pub struct ManagerState {
    inner: Arc<ManagerInner>,
}

struct ManagerInner {
    manager_id: String,
    fleet_id: FleetId,
    registry: InMemoryNodeRegistry,
    work_order_keyring: WorkOrderKeyring,
    work_orders: Mutex<HashMap<String, WorkOrderEnvelope>>,
    revoked_work_orders: Mutex<HashSet<String>>,
    placements: Mutex<HashMap<String, PlacementDecision>>,
    dispatches: Mutex<HashMap<String, DispatchReport>>,
    messages: Mutex<HashMap<String, MessageStatusReport>>,
    trace_index: InMemoryCentralTraceIndex,
    telemetry: Mutex<FleetTelemetryCollector>,
    audit: Mutex<Vec<ManagerAuditEvent>>,
}

impl ManagerState {
    pub fn local_acceptance() -> Self {
        let fleet_id = std::env::var("SPLENDOR_FLEET_ID")
            .ok()
            .and_then(|raw| FleetId::parse(&raw).ok())
            .unwrap_or_default();
        let mut work_order_keyring = WorkOrderKeyring::new();
        work_order_keyring
            .insert_shared_secret("work-order-local-key", b"splendor-local-work-order-secret")
            .expect("local work-order keyring");
        Self {
            inner: Arc::new(ManagerInner {
                manager_id: std::env::var("SPLENDOR_MANAGER_ID")
                    .unwrap_or_else(|_| "central-manager".to_string()),
                fleet_id: fleet_id.clone(),
                registry: InMemoryNodeRegistry::new(),
                work_order_keyring,
                work_orders: Mutex::new(HashMap::new()),
                revoked_work_orders: Mutex::new(HashSet::new()),
                placements: Mutex::new(HashMap::new()),
                dispatches: Mutex::new(HashMap::new()),
                messages: Mutex::new(HashMap::new()),
                trace_index: InMemoryCentralTraceIndex::default(),
                telemetry: Mutex::new(FleetTelemetryCollector::new(fleet_id)),
                audit: Mutex::new(Vec::new()),
            }),
        }
    }

    fn validate_security(
        &self,
        credential: &CallerCredential,
        audit: Option<&AuditAttribution>,
        scope: EndpointScope,
        mutating: bool,
    ) -> Result<(), ManagerApiError> {
        if !credential.scopes.contains(&scope) {
            return Err(ManagerApiError::forbidden("missing_scope", scope.as_str()));
        }
        if credential.expires_at <= OffsetDateTime::now_utc() {
            return Err(ManagerApiError::forbidden(
                "credential_expired",
                "credential expired",
            ));
        }
        if let RevocationStatus::Revoked { .. } = credential.revocation {
            return Err(ManagerApiError::forbidden(
                "credential_revoked",
                "credential revoked",
            ));
        }
        if credential.audience
            != (CredentialAudience::CentralManager {
                manager_id: self.inner.manager_id.clone(),
            })
        {
            return Err(ManagerApiError::forbidden(
                "wrong_audience",
                "wrong caller audience",
            ));
        }
        match &credential.binding {
            CredentialBinding::Fleet { fleet_id } if *fleet_id == self.inner.fleet_id => {}
            _ => {
                return Err(ManagerApiError::forbidden(
                    "wrong_credential_binding",
                    "wrong fleet binding",
                ))
            }
        }
        if mutating {
            let audit = audit.ok_or_else(|| {
                ManagerApiError::forbidden(
                    "missing_audit_attribution",
                    "mutating manager request requires audit attribution",
                )
            })?;
            if audit.credential_id.as_deref() != Some(credential.credential_id.as_str())
                || audit.principal != credential.principal
            {
                return Err(ManagerApiError::forbidden(
                    "attribution_mismatch",
                    "audit attribution mismatch",
                ));
            }
        }
        Ok(())
    }

    fn audit(
        &self,
        event_type: &str,
        details: serde_json::Value,
    ) -> Result<String, ManagerApiError> {
        let event_id = uuid::Uuid::new_v4().to_string();
        self.inner
            .audit
            .lock()
            .map_err(|_| ManagerApiError::internal("audit_lock", "audit lock unavailable"))?
            .push(ManagerAuditEvent {
                trace_event_id: event_id.clone(),
                event_type: event_type.to_string(),
                details,
                timestamp: OffsetDateTime::now_utc(),
            });
        Ok(event_id)
    }
}

pub fn router(state: ManagerState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/fleet/nodes", post(register_node).get(list_nodes))
        .route("/fleet/instances", post(register_instance))
        .route("/fleet/nodes/:node_id/heartbeat", post(heartbeat_node))
        .route(
            "/fleet/nodes/:node_id/capabilities",
            post(advertise_capabilities),
        )
        .route("/fleet/placement/evaluate", post(evaluate_placement))
        .route("/work-orders", post(submit_work_order))
        .route(
            "/work-orders/:work_order_id/revoke",
            post(revoke_work_order),
        )
        .route(
            "/work-orders/:work_order_id/dispatch",
            post(dispatch_work_order),
        )
        .route("/fleet/telemetry", get(get_fleet_telemetry))
        .route("/fleet/traces/sync", post(sync_trace_buffer))
        .route("/messages", post(send_message))
        .route("/messages/:message_id", get(get_message))
        .route("/fleet/audit", get(audit_events))
        .with_state(state)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerSecurityFields {
    pub credential: CallerCredential,
    pub audit_attribution: Option<AuditAttribution>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterNodeRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub registration: NodeRegistration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterInstanceRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub registration: InstanceRegistration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatNodeRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub heartbeat: NodeHeartbeat,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdvertiseCapabilitiesRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub capability_document: splendor_types::CapabilityDocument,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlacementEvaluationRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub work_order_id: Option<String>,
    pub request: PlacementRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitWorkOrderRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub work_order: WorkOrderEnvelope,
    pub expected_audience: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeWorkOrderRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispatchWorkOrderRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub target_node_id: Option<NodeId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncTraceBufferRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub batch: TraceSyncBatch,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub message_envelope: MessageEnvelope,
    pub source_instance_id: String,
    pub target_instance_id: String,
    pub idempotency_key: Option<String>,
    pub simulate_failure: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageStatusReport {
    pub message_id: MessageId,
    pub delivery_status: String,
    pub trace_event_id: String,
    pub duplicate: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerAuditEvent {
    pub trace_event_id: String,
    pub event_type: String,
    pub details: serde_json::Value,
    pub timestamp: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkOrderValidationReport {
    pub work_order_id: String,
    pub accepted: bool,
    pub reasons: Vec<String>,
    pub trace_event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DispatchReport {
    pub work_order_id: String,
    pub selected_node_id: NodeId,
    pub selected_instance_id: InstanceId,
    pub run_id: RunId,
    pub create_run_status: u16,
    pub start_run_status: u16,
    pub create_run_body: Option<String>,
    pub start_run_body: Option<String>,
    pub trace_event_id: String,
    pub resident_daemon_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerApiErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct ManagerApiError {
    status: StatusCode,
    body: ManagerApiErrorBody,
}

impl ManagerApiError {
    fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
            },
        }
    }
    fn forbidden(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
            },
        }
    }
    fn not_found(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
            },
        }
    }
    fn internal(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
            },
        }
    }
}

impl IntoResponse for ManagerApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"ok","component":"splendor-manager"}))
}

async fn register_node(
    State(state): State<ManagerState>,
    Json(request): Json<RegisterNodeRequest>,
) -> Result<Json<NodeRegistration>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        request.security.audit_attribution.as_ref(),
        EndpointScope::NodesRegister,
        true,
    )?;
    let record = state
        .inner
        .registry
        .register_node(request.registration)
        .map_err(|e| ManagerApiError::bad_request("node_registration_rejected", e.to_string()))?;
    state
        .inner
        .telemetry
        .lock()
        .map_err(|_| ManagerApiError::internal("telemetry_lock", "telemetry lock unavailable"))?
        .ingest_node_heartbeat(
            record.registration.node_id.clone(),
            record.last_heartbeat_at,
        );
    state.audit(
        "node.registered",
        serde_json::json!({"node_id": record.registration.node_id}),
    )?;
    Ok(Json(record.registration))
}

async fn register_instance(
    State(state): State<ManagerState>,
    Json(request): Json<RegisterInstanceRequest>,
) -> Result<Json<InstanceRegistration>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        request.security.audit_attribution.as_ref(),
        EndpointScope::InstancesRegister,
        true,
    )?;
    let record = state
        .inner
        .registry
        .register_instance(request.registration)
        .map_err(|e| {
            ManagerApiError::bad_request("instance_registration_rejected", e.to_string())
        })?;
    let mode = TelemetryRuntimeMode::Resident;
    state
        .inner
        .telemetry
        .lock()
        .map_err(|_| ManagerApiError::internal("telemetry_lock", "telemetry lock unavailable"))?
        .upsert_instance(InstanceTelemetry::new(
            record.registration.node_id.clone(),
            record.registration.instance_id.clone(),
            record.registration.runtime_version.clone(),
            mode,
            record.registration.supported_features.clone(),
            record.last_heartbeat_at,
        ));
    state.audit("instance.registered", serde_json::json!({"node_id": record.registration.node_id, "instance_id": record.registration.instance_id}))?;
    Ok(Json(record.registration))
}

async fn heartbeat_node(
    Path(node_id): Path<NodeId>,
    State(state): State<ManagerState>,
    Json(request): Json<HeartbeatNodeRequest>,
) -> Result<Json<serde_json::Value>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        request.security.audit_attribution.as_ref(),
        EndpointScope::NodesHeartbeat,
        true,
    )?;
    if node_id != request.heartbeat.node_id {
        return Err(ManagerApiError::bad_request(
            "node_id_mismatch",
            "path node_id does not match heartbeat",
        ));
    }
    let record = state
        .inner
        .registry
        .record_node_heartbeat(request.heartbeat)
        .map_err(|e| ManagerApiError::bad_request("heartbeat_rejected", e.to_string()))?;
    state
        .inner
        .telemetry
        .lock()
        .map_err(|_| ManagerApiError::internal("telemetry_lock", "telemetry lock unavailable"))?
        .ingest_node_heartbeat(node_id.clone(), record.last_heartbeat_at);
    let trace_event_id = state.audit(
        "heartbeat.received",
        serde_json::json!({"node_id": node_id, "status": record.health.status}),
    )?;
    Ok(Json(
        serde_json::json!({"accepted": true, "trace_event_id": trace_event_id}),
    ))
}

async fn advertise_capabilities(
    Path(node_id): Path<NodeId>,
    State(state): State<ManagerState>,
    Json(request): Json<AdvertiseCapabilitiesRequest>,
) -> Result<Json<serde_json::Value>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        request.security.audit_attribution.as_ref(),
        EndpointScope::NodesRegister,
        true,
    )?;
    request
        .capability_document
        .validate()
        .map_err(|e| ManagerApiError::bad_request("capabilities_rejected", e.to_string()))?;
    let node = state
        .inner
        .registry
        .node(&node_id)
        .map_err(|e| ManagerApiError::not_found("node_not_found", e.to_string()))?;
    state.audit("capabilities.advertised", serde_json::json!({"node_id": node_id, "capabilities": request.capability_document.capabilities}))?;
    Ok(Json(
        serde_json::json!({"accepted": true, "node_id": node.registration.node_id}),
    ))
}

async fn list_nodes(
    State(state): State<ManagerState>,
) -> Result<Json<serde_json::Value>, ManagerApiError> {
    Ok(Json(
        serde_json::json!({"fleet_id": state.inner.fleet_id, "audit_event_count": state.inner.audit.lock().map_err(|_| ManagerApiError::internal("audit_lock", "audit lock unavailable"))?.len()}),
    ))
}

async fn submit_work_order(
    State(state): State<ManagerState>,
    Json(request): Json<SubmitWorkOrderRequest>,
) -> Result<Json<WorkOrderValidationReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        request.security.audit_attribution.as_ref(),
        EndpointScope::WorkOrdersSubmit,
        true,
    )?;
    let work_order_id = request.work_order.work_order.work_order_id.to_string();
    if request.expected_audience != state.inner.manager_id {
        state.audit(
            "work_order.rejected",
            serde_json::json!({"work_order_id": work_order_id, "reason": "wrong_audience"}),
        )?;
        return Err(ManagerApiError::forbidden(
            "wrong_audience",
            "work order audience does not match central manager",
        ));
    }
    let validation = splendor_types::validate_work_order(
        &request.work_order,
        &WorkOrderValidationContext {
            tenant_id: request.work_order.work_order.tenant_id.clone(),
            agent_id: request.work_order.work_order.agent_id.clone(),
            run_id: request.work_order.work_order.run_id.clone(),
            expected_placement_target: None,
            now: OffsetDateTime::now_utc(),
        },
        &state.inner.work_order_keyring,
    );
    match validation {
        Ok(_) => {
            let trace_event_id = state.audit(
                "work_order.accepted",
                serde_json::json!({"work_order_id": work_order_id}),
            )?;
            state
                .inner
                .work_orders
                .lock()
                .map_err(|_| {
                    ManagerApiError::internal("work_order_lock", "work order lock unavailable")
                })?
                .insert(work_order_id.clone(), request.work_order);
            Ok(Json(WorkOrderValidationReport {
                work_order_id,
                accepted: true,
                reasons: vec![
                    "signature_expiry_revocation_audience_compatibility_validated".to_string(),
                ],
                trace_event_id,
            }))
        }
        Err(error) => {
            state.audit(
                "work_order.rejected",
                serde_json::json!({"work_order_id": work_order_id, "reason": error.reason_code()}),
            )?;
            Err(ManagerApiError::forbidden(
                error.reason_code(),
                error.to_string(),
            ))
        }
    }
}

async fn revoke_work_order(
    Path(work_order_id): Path<String>,
    State(state): State<ManagerState>,
    Json(request): Json<RevokeWorkOrderRequest>,
) -> Result<Json<serde_json::Value>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        request.security.audit_attribution.as_ref(),
        EndpointScope::WorkOrdersRevoke,
        true,
    )?;
    state
        .inner
        .revoked_work_orders
        .lock()
        .map_err(|_| ManagerApiError::internal("revocation_lock", "revocation lock unavailable"))?
        .insert(work_order_id.clone());
    let trace_event_id = state.audit(
        "work_order.revoked",
        serde_json::json!({"work_order_id": work_order_id, "reason": request.reason}),
    )?;
    Ok(Json(
        serde_json::json!({"revoked": true, "trace_event_id": trace_event_id}),
    ))
}

async fn evaluate_placement(
    State(state): State<ManagerState>,
    Json(request): Json<PlacementEvaluationRequest>,
) -> Result<Json<PlacementDecision>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        request.security.audit_attribution.as_ref(),
        EndpointScope::FleetRead,
        false,
    )?;
    let candidates = placement_candidates(&state)?;
    let decision = select_placement(&request.request, &candidates);
    if let Some(work_order_id) = request.work_order_id {
        state
            .inner
            .placements
            .lock()
            .map_err(|_| ManagerApiError::internal("placement_lock", "placement lock unavailable"))?
            .insert(work_order_id, decision.clone());
    }
    state.audit("placement.evaluated", serde_json::json!({"status": decision.status, "candidate_id": decision.candidate_id, "reasons": decision.reasons}))?;
    Ok(Json(decision))
}

async fn dispatch_work_order(
    Path(work_order_id): Path<String>,
    State(state): State<ManagerState>,
    Json(request): Json<DispatchWorkOrderRequest>,
) -> Result<Json<DispatchReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        request.security.audit_attribution.as_ref(),
        EndpointScope::FleetDispatch,
        true,
    )?;
    if state
        .inner
        .revoked_work_orders
        .lock()
        .map_err(|_| ManagerApiError::internal("revocation_lock", "revocation lock unavailable"))?
        .contains(&work_order_id)
    {
        state.audit(
            "work_order.rejected",
            serde_json::json!({"work_order_id": work_order_id, "reason": "revoked_work_order"}),
        )?;
        return Err(ManagerApiError::forbidden(
            "revoked_work_order",
            "work order was revoked",
        ));
    }
    let work_order = state
        .inner
        .work_orders
        .lock()
        .map_err(|_| ManagerApiError::internal("work_order_lock", "work order lock unavailable"))?
        .get(&work_order_id)
        .cloned()
        .ok_or_else(|| {
            ManagerApiError::not_found("work_order_not_found", "work order not submitted")
        })?;
    let placement = state
        .inner
        .placements
        .lock()
        .map_err(|_| ManagerApiError::internal("placement_lock", "placement lock unavailable"))?
        .get(&work_order_id)
        .cloned()
        .ok_or_else(|| {
            ManagerApiError::bad_request(
                "placement_required",
                "placement must be evaluated before dispatch",
            )
        })?;
    if placement.status != PlacementDecisionStatus::Selected {
        return Err(ManagerApiError::forbidden(
            "placement_rejected",
            "cannot dispatch rejected placement",
        ));
    }
    let selected_node_id = request
        .target_node_id
        .or_else(|| {
            placement
                .candidate_id
                .as_deref()
                .and_then(|raw| NodeId::parse(raw).ok())
        })
        .ok_or_else(|| {
            ManagerApiError::bad_request("missing_target_node", "dispatch requires selected node")
        })?;
    let node = state
        .inner
        .registry
        .node(&selected_node_id)
        .map_err(|e| ManagerApiError::not_found("node_not_found", e.to_string()))?;
    let instance_id = node.instances.first().cloned().ok_or_else(|| {
        ManagerApiError::bad_request(
            "node_has_no_instance",
            "selected node has no registered instance",
        )
    })?;
    let instance = state
        .inner
        .registry
        .instance(&instance_id)
        .map_err(|e| ManagerApiError::not_found("instance_not_found", e.to_string()))?;
    let daemon_url = node
        .registration
        .capability_document
        .constraints
        .get("resident_daemon_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ManagerApiError::bad_request(
                "missing_resident_daemon_url",
                "node capability constraints must include resident_daemon_url",
            )
        })?
        .to_string();
    let run_id = work_order
        .work_order
        .run_id
        .clone()
        .unwrap_or_else(RunId::new);
    let resident_credential = resident_credential(
        &request.security.credential,
        &work_order_id,
        &instance.registration.instance_id,
        &work_order.work_order.tenant_id,
    );
    let resident_audit = resident_audit(&resident_credential);
    let mut create = serde_json::json!({
        "tenant_id": work_order.work_order.tenant_id,
        "agent_id": work_order.work_order.agent_id,
        "work_order": work_order,
        "credential": resident_credential,
        "audit_attribution": resident_audit,
        "allowed_actions": ["sql.read_fixture", "artifact.create_internal"],
        "allowed_adapters": ["fixture-sql", "artifact-store"],
        "allowed_permissions": ["fixture.sql.read", "artifact.create_internal", "message.remote.proposal"],
        "registered_actions": [
          {"name":"sql.read_fixture", "adapter":"fixture-sql"},
          {"name":"artifact.create_internal", "adapter":"artifact-store"}
        ],
        "policy_actions": [
          {"action":{"name":"sql.read_fixture","params":{"dataset":"fixture.eu_west"},"side_effect_class":"ReadOnly","cost_estimate":null,"required_permissions":["fixture.sql.read"],"preconditions":[],"postconditions":[]},"adapter":"fixture-sql","quota_usage":{"actions":1,"action_duration_ms":0,"filesystem_read_bytes":0,"filesystem_write_bytes":0,"network_read_bytes":0,"network_write_bytes":0,"http_requests":0},"satisfied_preconditions":[]},
          {"action":{"name":"artifact.create_internal","params":{"artifact":"internal-proposal"},"side_effect_class":"External","cost_estimate":null,"required_permissions":["artifact.create_internal"],"preconditions":[],"postconditions":[]},"adapter":"artifact-store","quota_usage":{"actions":1,"action_duration_ms":0,"filesystem_read_bytes":0,"filesystem_write_bytes":0,"network_read_bytes":0,"network_write_bytes":0,"http_requests":0},"satisfied_preconditions":[]}
        ],
        "allowed_percept_schemas": [],
        "allowed_percept_sources": [],
        "initial_state": {"dispatch":"uc-e2e-s4"},
        "snapshot_interval": 1
    });
    create["work_order"]["run_id"] = serde_json::json!(run_id);
    let create_response = post_json(&daemon_url, "/runs", &create)
        .map_err(|e| ManagerApiError::internal("resident_http_error", e))?;
    let start = serde_json::json!({"credential": create["credential"], "audit_attribution": create["audit_attribution"], "reason":"uc_e2e_s4_dispatch"});
    let start_response = post_json(&daemon_url, &format!("/runs/{run_id}/start"), &start)
        .map_err(|e| ManagerApiError::internal("resident_http_error", e))?;
    let trace_event_id = state.audit("run.dispatched", serde_json::json!({"work_order_id": work_order_id, "node_id": selected_node_id, "instance_id": instance_id, "run_id": run_id}))?;
    let report = DispatchReport {
        work_order_id: work_order_id.clone(),
        selected_node_id: selected_node_id.clone(),
        selected_instance_id: instance_id.clone(),
        run_id: run_id.clone(),
        create_run_status: create_response.status,
        start_run_status: start_response.status,
        create_run_body: create_response.body,
        start_run_body: start_response.body,
        trace_event_id,
        resident_daemon_url: daemon_url,
    };
    state
        .inner
        .dispatches
        .lock()
        .map_err(|_| ManagerApiError::internal("dispatch_lock", "dispatch lock unavailable"))?
        .insert(work_order_id, report.clone());
    state
        .inner
        .telemetry
        .lock()
        .map_err(|_| ManagerApiError::internal("telemetry_lock", "telemetry lock unavailable"))?
        .upsert_run(RunTelemetry {
            tenant_id: create["tenant_id"]
                .as_str()
                .and_then(|raw| TenantId::parse(raw).ok())
                .unwrap_or_default(),
            agent_id: create["agent_id"]
                .as_str()
                .and_then(|raw| splendor_types::AgentId::parse(raw).ok())
                .unwrap_or_default(),
            run_id,
            node_id: selected_node_id,
            instance_id,
            status: RunStatus::Running,
            updated_at: OffsetDateTime::now_utc(),
        });
    Ok(Json(report))
}

async fn sync_trace_buffer(
    State(state): State<ManagerState>,
    Json(request): Json<SyncTraceBufferRequest>,
) -> Result<Json<TraceSyncReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        request.security.audit_attribution.as_ref(),
        EndpointScope::TracesRead,
        true,
    )?;
    let report = state
        .inner
        .trace_index
        .sync_batch(request.batch.clone())
        .map_err(|e| ManagerApiError::forbidden("trace_sync_rejected", e.to_string()))?;
    let node_id = request
        .batch
        .scope
        .node_id
        .as_deref()
        .and_then(|raw| NodeId::parse(raw).ok());
    let instance_id = request
        .batch
        .scope
        .instance_id
        .as_deref()
        .and_then(|raw| InstanceId::parse(raw).ok());
    if let (Some(node_id), Some(instance_id)) = (node_id, instance_id) {
        state
            .inner
            .telemetry
            .lock()
            .map_err(|_| ManagerApiError::internal("telemetry_lock", "telemetry lock unavailable"))?
            .upsert_trace_sync(TraceSyncTelemetry::from_watermarks(
                node_id,
                instance_id,
                None,
                report.latest_sequence,
                report.latest_sequence,
                Some(OffsetDateTime::now_utc()),
                None,
            ));
    }
    state.audit("trace.sync.completed", serde_json::json!({"accepted_records": report.accepted_records, "duplicate_records": report.duplicate_records}))?;
    Ok(Json(report))
}

async fn send_message(
    State(state): State<ManagerState>,
    Json(request): Json<SendMessageRequest>,
) -> Result<Json<MessageStatusReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        request.security.audit_attribution.as_ref(),
        EndpointScope::MessagesSend,
        true,
    )?;
    request
        .message_envelope
        .validate()
        .map_err(|e| ManagerApiError::bad_request("message_schema_rejected", e.to_string()))?;
    let message_id = request.message_envelope.message.message_id.clone();
    let mut messages = state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?;
    if let Some(existing) = messages.get(&message_id.to_string()) {
        let trace_event_id = state.audit("remote_message.duplicate", serde_json::json!({"message_id": message_id, "idempotency_key": request.idempotency_key}))?;
        let mut duplicate = existing.clone();
        duplicate.trace_event_id = trace_event_id;
        duplicate.duplicate = true;
        return Ok(Json(duplicate));
    }
    let (event_type, status, reason) = if let Some(reason) = request
        .simulate_failure
        .filter(|value| !value.trim().is_empty())
    {
        ("remote_message.failed", "failed".to_string(), Some(reason))
    } else {
        ("remote_message.delivered", "delivered".to_string(), None)
    };
    let trace_event_id = state.audit(event_type, serde_json::json!({"message_id": message_id, "source_instance_id": request.source_instance_id, "target_instance_id": request.target_instance_id, "schema": request.message_envelope.message.schema, "reason": reason}))?;
    let report = MessageStatusReport {
        message_id: message_id.clone(),
        delivery_status: status,
        trace_event_id,
        duplicate: false,
        reason,
    };
    messages.insert(message_id.to_string(), report.clone());
    Ok(Json(report))
}

async fn get_message(
    Path(message_id): Path<MessageId>,
    State(state): State<ManagerState>,
) -> Result<Json<MessageStatusReport>, ManagerApiError> {
    let report = state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
        .get(&message_id.to_string())
        .cloned()
        .ok_or_else(|| ManagerApiError::not_found("message_not_found", "message not found"))?;
    Ok(Json(report))
}

async fn get_fleet_telemetry(
    State(state): State<ManagerState>,
) -> Result<Json<FleetTelemetrySnapshot>, ManagerApiError> {
    let snapshot = state
        .inner
        .telemetry
        .lock()
        .map_err(|_| ManagerApiError::internal("telemetry_lock", "telemetry lock unavailable"))?
        .snapshot(OffsetDateTime::now_utc());
    state.audit(
        "telemetry.reported",
        serde_json::json!({"authority":"observational_only"}),
    )?;
    Ok(Json(snapshot))
}

async fn audit_events(
    State(state): State<ManagerState>,
) -> Result<Json<Vec<ManagerAuditEvent>>, ManagerApiError> {
    Ok(Json(
        state
            .inner
            .audit
            .lock()
            .map_err(|_| ManagerApiError::internal("audit_lock", "audit lock unavailable"))?
            .clone(),
    ))
}

fn placement_candidates(state: &ManagerState) -> Result<Vec<PlacementCandidate>, ManagerApiError> {
    let audit = state
        .inner
        .audit
        .lock()
        .map_err(|_| ManagerApiError::internal("audit_lock", "audit lock unavailable"))?;
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for event in audit
        .iter()
        .filter(|event| event.event_type == "node.registered")
    {
        let Some(node_id) = event
            .details
            .get("node_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|raw| NodeId::parse(raw).ok())
        else {
            continue;
        };
        if !seen.insert(node_id.clone()) {
            continue;
        }
        let node = state
            .inner
            .registry
            .node(&node_id)
            .map_err(|e| ManagerApiError::not_found("node_not_found", e.to_string()))?;
        let target = match node
            .registration
            .capability_document
            .constraints
            .get("placement_target")
            .and_then(serde_json::Value::as_str)
        {
            Some("customer_vpc") => PlacementTarget::CustomerVpc,
            Some("resident_cloud_pool") => PlacementTarget::ResidentCloudPool,
            Some("edge_device") => PlacementTarget::EdgeDevice,
            _ => PlacementTarget::ResidentCloudPool,
        };
        let data_locality = match node
            .registration
            .capability_document
            .constraints
            .get("data_locality")
            .and_then(serde_json::Value::as_str)
        {
            Some("vpc") => Some(DataLocality::Vpc),
            Some("cloud") => Some(DataLocality::Cloud),
            Some("device") => Some(DataLocality::Device),
            Some("on_prem") => Some(DataLocality::OnPrem),
            _ => None,
        };
        let mut candidate = PlacementCandidate::new(
            node_id.to_string(),
            target,
            node.registration.capability_document.capabilities.clone(),
            node.registration.runtime_version.clone(),
        );
        candidate.data_locality = data_locality;
        candidate.available = node.health.status == HealthStatus::Healthy
            && node.last_heartbeat_at + Duration::seconds(60) > OffsetDateTime::now_utc();
        candidate.supported_execution_modes = vec![
            PlacementExecutionMode::Live,
            PlacementExecutionMode::CloudHelper,
        ];
        candidates.push(candidate);
    }
    Ok(candidates)
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    body: Option<String>,
}

fn post_json(base_url: &str, path: &str, body: &serde_json::Value) -> Result<HttpResponse, String> {
    let base = base_url
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// URLs are supported in local acceptance".to_string())?;
    let (host_port, prefix) = base.split_once('/').unwrap_or((base, ""));
    let full_path = if prefix.is_empty() {
        path.to_string()
    } else {
        format!("/{prefix}{path}")
    };
    let payload = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let mut stream = TcpStream::connect(host_port).map_err(|e| e.to_string())?;
    write!(stream, "POST {full_path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", payload.len()).map_err(|e| e.to_string())?;
    stream.write_all(&payload).map_err(|e| e.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| e.to_string())?;
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(0);
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .filter(|body| !body.trim().is_empty())
        .map(ToString::to_string);
    Ok(HttpResponse { status, body })
}

fn resident_credential(
    manager_credential: &CallerCredential,
    work_order_id: &str,
    instance_id: &InstanceId,
    tenant_id: &TenantId,
) -> serde_json::Value {
    let mut credential = manager_credential.clone();
    credential.credential_id = format!("resident-dispatch-{work_order_id}");
    credential.audience = CredentialAudience::Instance {
        instance_id: instance_id.clone(),
    };
    credential.binding = CredentialBinding::Tenant {
        tenant_id: tenant_id.clone(),
    };
    credential.scopes = vec![
        EndpointScope::RunsCreate,
        EndpointScope::RunsStart,
        EndpointScope::RunsRead,
        EndpointScope::StateRead,
        EndpointScope::TracesRead,
        EndpointScope::ReplayCreate,
    ];
    serde_json::to_value(credential).expect("credential serializes")
}

fn resident_audit(credential: &serde_json::Value) -> serde_json::Value {
    let requested_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current timestamp formats as RFC3339");
    serde_json::json!({
        "principal": credential.get("principal").cloned().unwrap_or(serde_json::Value::Null),
        "credential_id": credential.get("credential_id").and_then(serde_json::Value::as_str),
        "requested_at": requested_at,
    })
}
