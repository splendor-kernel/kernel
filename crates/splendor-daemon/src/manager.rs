//! Minimal central manager API for UC-E2E-S4 acceptance.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splendor_kernel::{
    FleetTelemetryCollector, InMemoryNodeRegistry, NodeRegistry, NodeRegistryError,
};
use splendor_store::{
    CentralTraceIndex, InMemoryCentralTraceIndex, TraceSyncBatch, TraceSyncReport,
};
use splendor_types::{
    select_placement, AgentId, ApprovalDecision, ApprovalEvidence, ApprovalId, AuditAttribution,
    CallerCredential, CircuitBreaker, CircuitBreakerId, CircuitBreakerScope, CredentialAudience,
    CredentialBinding, DataLocality, EndpointScope, FleetId, FleetTelemetrySnapshot, HealthStatus,
    InstanceId, InstanceRegistration, InstanceTelemetry, Message, MessageEnvelope, MessageId,
    NodeHeartbeat, NodeId, NodeRegistration, PlacementCandidate, PlacementDecision,
    PlacementDecisionStatus, PlacementExecutionMode, PlacementRequest, PlacementTarget,
    PolicyBundle, PolicyBundleEnvelope, RevocationStatus, RunId, RunStatus, RunTelemetry,
    TelemetryRuntimeMode, TenantId, TraceSyncTelemetry, WorkOrderEnvelope, WorkOrderKeyring,
    WorkOrderValidationContext,
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
    message_idempotency: Mutex<HashMap<String, String>>,
    trace_index: InMemoryCentralTraceIndex,
    telemetry: Mutex<FleetTelemetryCollector>,
    audit: Mutex<Vec<ManagerAuditEvent>>,
    policies: Mutex<HashMap<String, PolicyBundleEnvelope>>,
    approvals: Mutex<HashMap<String, GovernanceApprovalRecord>>,
    circuit_breakers: Mutex<HashMap<String, GovernanceCircuitBreakerRecord>>,
    kill_switches: Mutex<HashMap<String, KillSwitchReport>>,
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
                message_idempotency: Mutex::new(HashMap::new()),
                trace_index: InMemoryCentralTraceIndex::default(),
                telemetry: Mutex::new(FleetTelemetryCollector::new(fleet_id)),
                audit: Mutex::new(Vec::new()),
                policies: Mutex::new(HashMap::new()),
                approvals: Mutex::new(HashMap::new()),
                circuit_breakers: Mutex::new(HashMap::new()),
                kill_switches: Mutex::new(HashMap::new()),
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
        let audit = audit.ok_or_else(|| {
            ManagerApiError::forbidden(
                "missing_audit_attribution",
                if mutating {
                    "mutating manager request requires audit attribution"
                } else {
                    "manager read request requires audit attribution"
                },
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
        .route("/fleet/nodes", post(register_node))
        .route("/fleet/nodes/list", post(list_nodes))
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
        .route("/fleet/telemetry/read", post(get_fleet_telemetry))
        .route("/fleet/traces/sync", post(sync_trace_buffer))
        .route("/messages", post(send_message))
        .route("/messages/:message_id/read", post(get_message))
        .route("/messages/:message_id/ack", post(ack_message))
        .route("/messages/:message_id/nack", post(nack_message))
        .route("/agents/:agent_id/inbox", get(list_inbox))
        .route("/agents/:agent_id/outbox", get(list_outbox))
        .route(
            "/runs/:run_id/messages/causal-graph",
            get(get_message_causal_graph),
        )
        .route("/message-schemas", get(list_message_schemas))
        .route("/message-schemas/validate", post(validate_message_schema))
        .route("/policies", post(publish_policy_bundle))
        .route("/policies/:policy_id/read", post(get_policy_status))
        .route("/policies/:policy_id/revoke", post(revoke_policy_bundle))
        .route("/approvals", post(request_approval))
        .route("/approvals/:approval_id/grant", post(grant_approval))
        .route("/approvals/:approval_id/deny", post(deny_approval))
        .route("/approvals/:approval_id/revoke", post(revoke_approval))
        .route("/governance/circuit-breakers", post(create_circuit_breaker))
        .route(
            "/governance/circuit-breakers/:breaker_id/sync-payload",
            post(read_circuit_breaker_sync_payload),
        )
        .route(
            "/governance/circuit-breakers/:breaker_id/clear",
            post(clear_circuit_breaker),
        )
        .route("/governance/kill-switches", post(activate_kill_switch))
        .route("/governance/audit/export", post(export_governance_audit))
        .route("/fleet/audit/read", post(audit_events))
        .with_state(state)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerSecurityFields {
    pub credential: CallerCredential,
    pub audit_attribution: AuditAttribution,
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
    pub work_order_id: String,
    pub message_envelope: MessageEnvelope,
    pub source_instance_id: String,
    pub target_instance_id: String,
    pub idempotency_key: Option<String>,
    pub simulate_failure: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagerReadRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    #[serde(default)]
    pub tenant_id: Option<TenantId>,
    #[serde(default)]
    pub agent_id: Option<AgentId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageReadRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    #[serde(default)]
    pub tenant_id: Option<TenantId>,
    #[serde(default)]
    pub run_id: Option<RunId>,
    #[serde(default)]
    pub agent_id: Option<AgentId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageStatusReport {
    pub message_id: MessageId,
    pub work_order_id: String,
    pub tenant_id: TenantId,
    pub run_id: RunId,
    pub source_agent_id: AgentId,
    pub target_agent_id: AgentId,
    pub schema: String,
    pub causal_parent: Option<String>,
    pub delivery_status: String,
    pub trace_event_id: String,
    pub duplicate: bool,
    pub idempotency_key: Option<String>,
    pub source_instance_id: String,
    pub target_instance_id: String,
    pub recipient_validated: bool,
    pub receive_side_validated: bool,
    pub work_order_authority_validated: bool,
    pub route_permission: Option<String>,
    pub remote_state_mutated: bool,
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_trace_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_trace_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nack_trace_event_id: Option<String>,
    pub payload_preserved: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageDeliveryUpdateRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    #[serde(default)]
    pub tenant_id: Option<TenantId>,
    #[serde(default)]
    pub run_id: Option<RunId>,
    #[serde(default)]
    pub agent_id: Option<AgentId>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
    #[serde(default)]
    pub payload_patch: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageListResponse {
    pub agent_id: AgentId,
    pub direction: String,
    pub tenant_id: TenantId,
    pub run_id: RunId,
    pub messages: Vec<MessageStatusReport>,
    pub trace_event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageCausalGraphNode {
    pub message_id: MessageId,
    pub work_order_id: String,
    pub source_agent_id: AgentId,
    pub target_agent_id: AgentId,
    pub schema: String,
    pub delivery_status: String,
    pub trace_event_id: String,
    pub causal_parent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageCausalGraphEdge {
    pub from_trace_event_id: String,
    pub to_message_id: MessageId,
    pub to_trace_event_id: String,
    pub from_message_id: Option<MessageId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageCausalGraphResponse {
    pub run_id: RunId,
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub nodes: Vec<MessageCausalGraphNode>,
    pub edges: Vec<MessageCausalGraphEdge>,
    pub trace_event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageSchemaValidationRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    #[serde(default)]
    pub message_envelope: Option<MessageEnvelope>,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageSchemaValidationReport {
    pub valid: bool,
    pub supported: bool,
    pub schema: String,
    pub schema_version: Option<String>,
    pub reason: Option<String>,
    pub delivery_authority_granted: bool,
    pub trace_event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SupportedMessageSchema {
    pub schema: String,
    pub version: String,
    pub description: String,
    pub delivery_authority_granted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageSchemaListResponse {
    pub schemas: Vec<SupportedMessageSchema>,
    pub delivery_authority_granted: bool,
    pub trace_event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishPolicyBundleRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub policy_bundle: PolicyBundle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokePolicyBundleRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyBundleStatusReport {
    pub policy_bundle_id: String,
    pub status: String,
    pub envelope: PolicyBundleEnvelope,
    pub trace_event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRequestPayload {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub approval_id: ApprovalId,
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub run_id: RunId,
    pub action_id: splendor_types::ActionId,
    pub action_name: String,
    pub adapter: String,
    pub policy_id: String,
    pub risk_level: String,
    pub audience: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalDecisionRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub reason: String,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceApprovalRecord {
    pub approval_id: ApprovalId,
    pub tenant_id: TenantId,
    pub agent_id: AgentId,
    pub run_id: RunId,
    pub action_id: splendor_types::ActionId,
    pub action_name: String,
    pub adapter: String,
    pub policy_id: String,
    pub risk_level: String,
    pub audience: String,
    pub status: String,
    pub reason: String,
    pub issued_by: AuditAttribution,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub trace_event_id: String,
    pub evidence: Option<ApprovalEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitBreakerRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub breaker_id: String,
    pub tenant_id: Option<TenantId>,
    pub adapter: Option<String>,
    pub action: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearCircuitBreakerRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceCircuitBreakerRecord {
    pub breaker_id: String,
    pub status: String,
    pub tenant_id: Option<TenantId>,
    pub adapter: Option<String>,
    pub action: Option<String>,
    pub reason: String,
    pub trace_event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitBreakerSyncPayloadRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub run_id: RunId,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitBreakerSyncPayloadReport {
    pub run_id: RunId,
    pub breaker_record: GovernanceCircuitBreakerRecord,
    pub circuit_breakers: Vec<CircuitBreaker>,
    pub manager_trace_event_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KillSwitchRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub kill_switch_id: String,
    pub run_id: Option<RunId>,
    pub tenant_id: Option<TenantId>,
    pub node_id: Option<NodeId>,
    pub instance_id: Option<InstanceId>,
    pub reason: String,
    pub propagation_ack_required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KillSwitchReport {
    pub kill_switch_id: String,
    pub status: String,
    pub fail_closed: bool,
    pub propagation_acknowledged: bool,
    pub cancel_status: Option<u16>,
    pub target_daemon_url: Option<String>,
    pub target_instance_id: Option<InstanceId>,
    pub target_derived_from_registry: bool,
    pub cancel_payload_schema: Option<String>,
    pub trace_event_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceAuditExportRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub run_id: Option<RunId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceAuditExportReport {
    pub exported: bool,
    pub trace_event_id: String,
    pub events: Vec<ManagerAuditEvent>,
    pub policy_bundle_ids: Vec<String>,
    pub approval_ids: Vec<String>,
    pub circuit_breaker_ids: Vec<String>,
    pub kill_switch_ids: Vec<String>,
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

fn node_registration_matches_existing(
    existing: &NodeRegistration,
    requested: &NodeRegistration,
) -> bool {
    existing.node_id == requested.node_id
        && existing.kind == requested.kind
        && existing.scope == requested.scope
        && existing.capability_document == requested.capability_document
        && existing.runtime_version == requested.runtime_version
        && existing.health.status == requested.health.status
        && existing.health.metadata == requested.health.metadata
}

fn instance_registration_matches_existing(
    existing: &InstanceRegistration,
    requested: &InstanceRegistration,
) -> bool {
    existing.instance_id == requested.instance_id
        && existing.node_id == requested.node_id
        && existing.runtime_mode == requested.runtime_mode
        && existing.hosted_tenants == requested.hosted_tenants
        && existing.supported_features == requested.supported_features
        && existing.runtime_version == requested.runtime_version
        && existing.health.status == requested.health.status
        && existing.health.metadata == requested.health.metadata
}

async fn register_node(
    State(state): State<ManagerState>,
    Json(request): Json<RegisterNodeRequest>,
) -> Result<Json<NodeRegistration>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::NodesRegister,
        true,
    )?;
    let requested = request.registration;
    let (record, registered_new) = match state.inner.registry.register_node(requested.clone()) {
        Ok(record) => (record, true),
        Err(NodeRegistryError::DuplicateNode(node_id)) => {
            let record = state.inner.registry.node(&node_id).map_err(|e| {
                ManagerApiError::bad_request("node_registration_rejected", e.to_string())
            })?;
            if !node_registration_matches_existing(&record.registration, &requested) {
                return Err(ManagerApiError::bad_request(
                    "node_registration_rejected",
                    format!("node {node_id} is already registered with incompatible metadata"),
                ));
            }
            state.audit(
                "node.registration_idempotent",
                serde_json::json!({"node_id": record.registration.node_id, "idempotent": true}),
            )?;
            (record, false)
        }
        Err(error) => {
            return Err(ManagerApiError::bad_request(
                "node_registration_rejected",
                error.to_string(),
            ))
        }
    };
    state
        .inner
        .telemetry
        .lock()
        .map_err(|_| ManagerApiError::internal("telemetry_lock", "telemetry lock unavailable"))?
        .ingest_node_heartbeat(
            record.registration.node_id.clone(),
            record.last_heartbeat_at,
        );
    if registered_new {
        state.audit(
            "node.registered",
            serde_json::json!({"node_id": record.registration.node_id}),
        )?;
    }
    Ok(Json(record.registration))
}

async fn register_instance(
    State(state): State<ManagerState>,
    Json(request): Json<RegisterInstanceRequest>,
) -> Result<Json<InstanceRegistration>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::InstancesRegister,
        true,
    )?;
    let requested = request.registration;
    let (record, registered_new) = match state.inner.registry.register_instance(requested.clone()) {
        Ok(record) => (record, true),
        Err(NodeRegistryError::DuplicateInstance(instance_id)) => {
            let record = state.inner.registry.instance(&instance_id).map_err(|e| {
                ManagerApiError::bad_request("instance_registration_rejected", e.to_string())
            })?;
            if !instance_registration_matches_existing(&record.registration, &requested) {
                return Err(ManagerApiError::bad_request(
                    "instance_registration_rejected",
                    format!(
                        "instance {instance_id} is already registered with incompatible metadata"
                    ),
                ));
            }
            state.audit(
                "instance.registration_idempotent",
                serde_json::json!({"node_id": record.registration.node_id, "instance_id": record.registration.instance_id, "idempotent": true}),
            )?;
            (record, false)
        }
        Err(error) => {
            return Err(ManagerApiError::bad_request(
                "instance_registration_rejected",
                error.to_string(),
            ))
        }
    };
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
    if registered_new {
        state.audit("instance.registered", serde_json::json!({"node_id": record.registration.node_id, "instance_id": record.registration.instance_id}))?;
    }
    Ok(Json(record.registration))
}

async fn heartbeat_node(
    Path(node_id): Path<NodeId>,
    State(state): State<ManagerState>,
    Json(request): Json<HeartbeatNodeRequest>,
) -> Result<Json<serde_json::Value>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
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
        Some(&request.security.audit_attribution),
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
    Json(request): Json<ManagerReadRequest>,
) -> Result<Json<serde_json::Value>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::FleetRead,
        false,
    )?;
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
        Some(&request.security.audit_attribution),
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
        Some(&request.security.audit_attribution),
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
        Some(&request.security.audit_attribution),
        EndpointScope::FleetRead,
        false,
    )?;
    let candidates = placement_candidates(&state)?;
    let decision = select_placement(&request.request, &candidates);
    let work_order_id = request.work_order_id.clone();
    if let Some(work_order_id) = work_order_id.clone() {
        state
            .inner
            .placements
            .lock()
            .map_err(|_| ManagerApiError::internal("placement_lock", "placement lock unavailable"))?
            .insert(work_order_id, decision.clone());
    }
    state.audit("placement.evaluated", serde_json::json!({"work_order_id": work_order_id, "status": decision.status, "candidate_id": decision.candidate_id, "reasons": decision.reasons}))?;
    Ok(Json(decision))
}

async fn dispatch_work_order(
    Path(work_order_id): Path<String>,
    State(state): State<ManagerState>,
    Json(request): Json<DispatchWorkOrderRequest>,
) -> Result<Json<DispatchReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
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
    let run_id = work_order
        .work_order
        .run_id
        .clone()
        .unwrap_or_else(RunId::new);
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
    let expected_target = work_order.work_order.placement.target.clone();
    let dispatch_validation = splendor_types::validate_work_order(
        &work_order,
        &WorkOrderValidationContext {
            tenant_id: work_order.work_order.tenant_id.clone(),
            agent_id: work_order.work_order.agent_id.clone(),
            run_id: Some(run_id.clone()),
            expected_placement_target: Some(expected_target.clone()),
            now: OffsetDateTime::now_utc(),
        },
        &state.inner.work_order_keyring,
    );
    if let Err(error) = dispatch_validation {
        state.audit(
            "work_order.rejected",
            serde_json::json!({"work_order_id": work_order_id, "reason": error.reason_code(), "phase": "dispatch"}),
        )?;
        return Err(ManagerApiError::forbidden(
            error.reason_code(),
            error.to_string(),
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
    let placement_node_id = placement
        .candidate_id
        .as_deref()
        .and_then(|raw| NodeId::parse(raw).ok())
        .ok_or_else(|| {
            ManagerApiError::bad_request(
                "placement_candidate_missing",
                "selected placement is missing a node candidate",
            )
        })?;
    if selected_node_id != placement_node_id {
        state.audit(
            "dispatch.rejected",
            serde_json::json!({"work_order_id": work_order_id, "reason": "dispatch_target_mismatch", "requested_node_id": selected_node_id, "placement_node_id": placement_node_id}),
        )?;
        return Err(ManagerApiError::forbidden(
            "dispatch_target_mismatch",
            "dispatch target does not match evaluated placement",
        ));
    }
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
    if node.health.status != HealthStatus::Healthy
        || node.last_heartbeat_at + Duration::seconds(60) <= OffsetDateTime::now_utc()
    {
        return Err(ManagerApiError::forbidden(
            "stale_or_unhealthy_node",
            "selected node heartbeat is stale or unhealthy",
        ));
    }
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
    let resident_credential = resident_credential(
        &request.security.credential,
        &work_order_id,
        &instance.registration.instance_id,
        &work_order.work_order.tenant_id,
    );
    let resident_audit = resident_audit(&resident_credential);
    let create =
        resident_create_run_payload(&work_order, &run_id, resident_credential, resident_audit)?;
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

fn resident_create_run_payload(
    work_order: &WorkOrderEnvelope,
    run_id: &RunId,
    resident_credential: serde_json::Value,
    resident_audit: serde_json::Value,
) -> Result<serde_json::Value, ManagerApiError> {
    let allowed_actions = &work_order.work_order.allowed_actions;
    let allowed_adapters = &work_order.work_order.allowed_adapters;
    let allowed_permissions = &work_order.work_order.allowed_permissions;
    let mut registered_actions = Vec::new();
    let mut policy_actions = Vec::new();
    let mut approval_policies = Vec::new();
    for (action, adapter, permission, side_effect_class, params) in [
        (
            "data.read_fixture",
            "fixture-data-store",
            "data.read_fixture",
            "ReadOnly",
            serde_json::json!({"data_ref": work_order.work_order.data_refs.first().cloned().unwrap_or_else(|| "dataset:missing".to_string())}),
        ),
        (
            "sql.read_fixture",
            "fixture-sql",
            "fixture.sql.read",
            "ReadOnly",
            serde_json::json!({"dataset":"fixture.eu_west"}),
        ),
        (
            "artifact.create_internal",
            "artifact-store",
            "artifact.create_internal",
            "External",
            serde_json::json!({"artifact":"internal-proposal", "artifact_path": format!("artifact://{}/dispatch/internal-proposal.md", work_order.work_order.tenant_id)}),
        ),
        (
            "artifact.publish_external",
            "artifact-store",
            "artifact.publish_external",
            "External",
            serde_json::json!({"publish_ref": format!("artifact://{}/dispatch/internal-proposal.md", work_order.work_order.tenant_id)}),
        ),
    ] {
        let action_allowed = allowed_actions.iter().any(|item| item == action);
        let adapter_allowed = allowed_adapters.iter().any(|item| item == adapter);
        let permission_allowed = allowed_permissions.iter().any(|item| item == permission);
        if action_allowed || permission_allowed {
            if !(action_allowed && adapter_allowed && permission_allowed) {
                return Err(ManagerApiError::forbidden(
                    "work_order_authority_incomplete",
                    format!(
                        "work order must explicitly authorize action `{action}`, adapter `{adapter}`, and permission `{permission}`"
                    ),
                ));
            }
            registered_actions.push(serde_json::json!({"name": action, "adapter": adapter}));
            policy_actions.push(serde_json::json!({
                "action": {"name": action, "params": params, "side_effect_class": side_effect_class, "cost_estimate": null, "required_permissions": [permission], "preconditions": [], "postconditions": []},
                "adapter": adapter,
                "quota_usage": {"actions": 1, "action_duration_ms": 0, "filesystem_read_bytes": 0, "filesystem_write_bytes": 0, "network_read_bytes": 0, "network_write_bytes": 0, "http_requests": 0},
                "satisfied_preconditions": []
            }));
            if action == "artifact.publish_external" {
                approval_policies.push(serde_json::json!({
                    "schema_version": "splendor.approval_policy.v1",
                    "policy_id": format!("policy_{work_order_id}_artifact_publish_external", work_order_id = work_order.work_order.work_order_id),
                    "tenant_id": work_order.work_order.tenant_id,
                    "agent_id": work_order.work_order.agent_id,
                    "action_name": "artifact.publish_external",
                    "adapter": "artifact-store",
                    "required_permission": "artifact.publish_external",
                    "side_effect_class": "External",
                    "risk_level": "high",
                    "reason": "external artifact publication requires scoped approval",
                    "expires_at": null
                }));
            }
        }
    }
    if allowed_actions
        .iter()
        .any(|item| item == "message.remote.proposal")
    {
        if !allowed_adapters.iter().any(|item| item == "remote-message")
            || !allowed_permissions
                .iter()
                .any(|item| item.starts_with("message.remote.proposal"))
        {
            return Err(ManagerApiError::forbidden(
                "work_order_authority_incomplete",
                "remote proposal action requires remote-message adapter and route permission",
            ));
        }
        registered_actions.push(
            serde_json::json!({"name": "message.remote.proposal", "adapter": "remote-message"}),
        );
    }
    let mut create = serde_json::json!({
        "tenant_id": work_order.work_order.tenant_id,
        "agent_id": work_order.work_order.agent_id,
        "work_order": work_order,
        "credential": resident_credential,
        "audit_attribution": resident_audit,
        "allowed_actions": allowed_actions,
        "allowed_adapters": allowed_adapters,
        "allowed_permissions": allowed_permissions,
        "registered_actions": registered_actions,
        "policy_actions": policy_actions,
        "approval_policies": approval_policies,
        "allowed_percept_schemas": [],
        "allowed_percept_sources": [],
        "initial_state": {"dispatch":"uc-e2e-s4"},
        "snapshot_interval": 1
    });
    create["work_order"]["run_id"] = serde_json::json!(run_id);
    Ok(create)
}

async fn sync_trace_buffer(
    State(state): State<ManagerState>,
    Json(request): Json<SyncTraceBufferRequest>,
) -> Result<Json<TraceSyncReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
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

fn supported_message_schemas() -> Vec<SupportedMessageSchema> {
    vec![
        SupportedMessageSchema {
            schema: "splendor.message.task_request.v1".to_string(),
            version: "v1".to_string(),
            description: "Scoped task/delegation request between agents".to_string(),
            delivery_authority_granted: false,
        },
        SupportedMessageSchema {
            schema: "splendor.message.task_response.v1".to_string(),
            version: "v1".to_string(),
            description: "Scoped task/delegation response between agents".to_string(),
            delivery_authority_granted: false,
        },
        SupportedMessageSchema {
            schema: "splendor.message.proposal_request.v1".to_string(),
            version: "v1".to_string(),
            description: "Non-authoritative remote proposal request".to_string(),
            delivery_authority_granted: false,
        },
    ]
}

fn is_supported_message_schema(schema: &str) -> bool {
    supported_message_schemas()
        .iter()
        .any(|supported| supported.schema == schema)
}

fn ensure_supported_message_schema(schema: &str) -> Result<(), ManagerApiError> {
    if is_supported_message_schema(schema) {
        Ok(())
    } else {
        Err(ManagerApiError::bad_request(
            "unsupported_message_schema",
            "manager transport only accepts stable proposal/task message schemas",
        ))
    }
}

fn ensure_message_visibility(
    report: &MessageStatusReport,
    tenant_id: Option<&TenantId>,
    run_id: Option<&RunId>,
    agent_id: Option<&AgentId>,
) -> Result<(), ManagerApiError> {
    let tenant_id = tenant_id.ok_or_else(|| {
        ManagerApiError::forbidden(
            "missing_message_tenant_scope",
            "message read/update requires tenant_id scope",
        )
    })?;
    if tenant_id != &report.tenant_id {
        return Err(ManagerApiError::forbidden(
            "cross_tenant_message_read_denied",
            "message tenant does not match requested tenant scope",
        ));
    }
    let run_id = run_id.ok_or_else(|| {
        ManagerApiError::forbidden(
            "missing_message_run_scope",
            "message read/update requires run_id scope",
        )
    })?;
    if run_id != &report.run_id {
        return Err(ManagerApiError::forbidden(
            "message_run_scope_denied",
            "message run does not match requested run scope",
        ));
    }
    let agent_id = agent_id.ok_or_else(|| {
        ManagerApiError::forbidden(
            "missing_message_agent_scope",
            "message read/update requires agent_id scope",
        )
    })?;
    if agent_id != &report.source_agent_id && agent_id != &report.target_agent_id {
        return Err(ManagerApiError::forbidden(
            "message_agent_scope_denied",
            "message is outside requested agent scope",
        ));
    }
    Ok(())
}

fn ensure_message_list_scope(
    path_agent_id: &AgentId,
    request: &MessageReadRequest,
) -> Result<(TenantId, RunId, AgentId), ManagerApiError> {
    let tenant_id = request.tenant_id.clone().ok_or_else(|| {
        ManagerApiError::forbidden(
            "missing_message_tenant_scope",
            "message list requires tenant_id scope",
        )
    })?;
    let run_id = request.run_id.clone().ok_or_else(|| {
        ManagerApiError::forbidden(
            "missing_message_run_scope",
            "message list requires run_id scope",
        )
    })?;
    let agent_id = request.agent_id.clone().ok_or_else(|| {
        ManagerApiError::forbidden(
            "missing_message_agent_scope",
            "message list requires agent_id scope",
        )
    })?;
    if &agent_id != path_agent_id {
        return Err(ManagerApiError::forbidden(
            "message_agent_scope_denied",
            "message list request agent does not match path agent",
        ));
    }
    Ok((tenant_id, run_id, agent_id))
}

fn ensure_message_collection_scope(
    reports: &[MessageStatusReport],
    tenant_id: &TenantId,
    run_id: &RunId,
    agent_id: &AgentId,
    context: &str,
) -> Result<(), ManagerApiError> {
    let run_reports = reports
        .iter()
        .filter(|report| &report.run_id == run_id)
        .collect::<Vec<_>>();
    if !run_reports.is_empty()
        && !run_reports
            .iter()
            .any(|report| &report.tenant_id == tenant_id)
    {
        return Err(ManagerApiError::forbidden(
            "cross_tenant_message_read_denied",
            format!("{context} tenant scope does not match run messages"),
        ));
    }
    let scoped_reports = run_reports
        .into_iter()
        .filter(|report| &report.tenant_id == tenant_id)
        .collect::<Vec<_>>();
    if !scoped_reports.is_empty()
        && !scoped_reports.iter().any(|report| {
            &report.source_agent_id == agent_id || &report.target_agent_id == agent_id
        })
    {
        return Err(ManagerApiError::forbidden(
            "message_agent_scope_denied",
            format!("{context} is outside requested agent scope"),
        ));
    }
    Ok(())
}

fn ensure_message_update_scope(
    report: &MessageStatusReport,
    request: &MessageDeliveryUpdateRequest,
) -> Result<(), ManagerApiError> {
    if request.payload.is_some() || request.payload_patch.is_some() {
        return Err(ManagerApiError::bad_request(
            "message_payload_mutation_forbidden",
            "ack/nack records delivery metadata only and cannot mutate message payload",
        ));
    }
    ensure_message_visibility(
        report,
        request.tenant_id.as_ref(),
        request.run_id.as_ref(),
        request.agent_id.as_ref(),
    )?;
    let agent_id = request.agent_id.as_ref().expect("validated agent scope");
    if agent_id != &report.target_agent_id {
        return Err(ManagerApiError::forbidden(
            "message_ack_agent_not_recipient",
            "ack/nack must be scoped to the target agent",
        ));
    }
    Ok(())
}

async fn send_message(
    State(state): State<ManagerState>,
    Json(request): Json<SendMessageRequest>,
) -> Result<Json<MessageStatusReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::MessagesSend,
        true,
    )?;
    request
        .message_envelope
        .validate()
        .map_err(|e| ManagerApiError::bad_request("message_schema_rejected", e.to_string()))?;
    if request
        .idempotency_key
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        return Err(ManagerApiError::bad_request(
            "missing_idempotency_key",
            "remote message requires an explicit idempotency marker",
        ));
    }
    if let Err(error) = ensure_supported_message_schema(&request.message_envelope.message.schema) {
        state.audit(
            "remote_message.rejected",
            serde_json::json!({"message_id": request.message_envelope.message.message_id, "reason": "unsupported_message_schema", "schema": request.message_envelope.message.schema}),
        )?;
        return Err(error);
    }
    let source_instance = InstanceId::parse(&request.source_instance_id)
        .map_err(|e| ManagerApiError::bad_request("invalid_source_instance", e.to_string()))?;
    let target_instance = InstanceId::parse(&request.target_instance_id)
        .map_err(|e| ManagerApiError::bad_request("invalid_target_instance", e.to_string()))?;
    let source_instance_record = state
        .inner
        .registry
        .instance(&source_instance)
        .map_err(|e| ManagerApiError::not_found("source_instance_not_found", e.to_string()))?;
    let target_instance_record = state
        .inner
        .registry
        .instance(&target_instance)
        .map_err(|e| ManagerApiError::not_found("target_instance_not_found", e.to_string()))?;
    let work_order = state
        .inner
        .work_orders
        .lock()
        .map_err(|_| ManagerApiError::internal("work_order_lock", "work order lock unavailable"))?
        .get(&request.work_order_id)
        .cloned()
        .ok_or_else(|| {
            ManagerApiError::not_found("work_order_not_found", "work order not submitted")
        })?;
    validate_remote_message_authority(
        &request,
        &work_order,
        &source_instance_record.registration,
        &target_instance_record.registration,
    )
    .inspect_err(|error| {
        let _ = state.audit(
            "remote_message.rejected",
            serde_json::json!({"message_id": request.message_envelope.message.message_id, "work_order_id": request.work_order_id, "reason": error.body.code}),
        );
    })?;
    let message_id = request.message_envelope.message.message_id.clone();
    let route_permission = Some(format!(
        "message.remote.proposal:{}",
        request.message_envelope.message.target_agent_id
    ));
    let idempotency_key = request
        .idempotency_key
        .clone()
        .expect("validated idempotency key");
    if let Some(existing_message_id) = state
        .inner
        .message_idempotency
        .lock()
        .map_err(|_| {
            ManagerApiError::internal(
                "message_idempotency_lock",
                "message idempotency lock unavailable",
            )
        })?
        .get(&idempotency_key)
        .cloned()
    {
        let existing = state
            .inner
            .messages
            .lock()
            .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
            .get(&existing_message_id)
            .cloned()
            .ok_or_else(|| {
                ManagerApiError::internal(
                    "message_idempotency_dangling",
                    "message idempotency index is stale",
                )
            })?;
        let trace_event_id = state.audit("remote_message.duplicate", serde_json::json!({"message_id": message_id, "existing_message_id": existing_message_id, "idempotency_key": idempotency_key, "remote_state_mutated": false}))?;
        let mut duplicate = existing;
        duplicate.trace_event_id = trace_event_id;
        duplicate.duplicate = true;
        duplicate.message_id = message_id.clone();
        duplicate.run_id = request.message_envelope.message.run_id.clone();
        duplicate.source_agent_id = request.message_envelope.message.source_agent_id.clone();
        duplicate.target_agent_id = request.message_envelope.message.target_agent_id.clone();
        duplicate.schema = request.message_envelope.message.schema.clone();
        duplicate.causal_parent = request
            .message_envelope
            .message
            .causal_parent
            .as_ref()
            .map(ToString::to_string);
        state
            .inner
            .messages
            .lock()
            .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
            .insert(message_id.to_string(), duplicate.clone());
        return Ok(Json(duplicate));
    }
    let mut messages = state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?;
    let (event_type, status, reason) = if let Some(reason) = request
        .simulate_failure
        .filter(|value| !value.trim().is_empty())
    {
        ("remote_message.failed", "failed".to_string(), Some(reason))
    } else {
        ("remote_message.delivered", "delivered".to_string(), None)
    };
    let trace_event_id = state.audit(event_type, serde_json::json!({"message_id": message_id, "work_order_id": request.work_order_id, "source_instance_id": request.source_instance_id, "target_instance_id": request.target_instance_id, "source_agent_id": request.message_envelope.message.source_agent_id, "target_agent_id": request.message_envelope.message.target_agent_id, "schema": request.message_envelope.message.schema, "reason": reason, "remote_state_mutated": false}))?;
    let report = MessageStatusReport {
        message_id: message_id.clone(),
        work_order_id: request.work_order_id,
        tenant_id: work_order.work_order.tenant_id.clone(),
        run_id: request.message_envelope.message.run_id.clone(),
        source_agent_id: request.message_envelope.message.source_agent_id.clone(),
        target_agent_id: request.message_envelope.message.target_agent_id.clone(),
        schema: request.message_envelope.message.schema.clone(),
        causal_parent: request
            .message_envelope
            .message
            .causal_parent
            .as_ref()
            .map(ToString::to_string),
        delivery_status: status,
        trace_event_id,
        duplicate: false,
        idempotency_key: Some(idempotency_key.clone()),
        source_instance_id: request.source_instance_id,
        target_instance_id: request.target_instance_id,
        recipient_validated: true,
        receive_side_validated: reason.is_none(),
        work_order_authority_validated: true,
        route_permission,
        remote_state_mutated: false,
        reason,
        read_trace_event_id: None,
        ack_trace_event_id: None,
        nack_trace_event_id: None,
        payload_preserved: true,
    };
    state
        .inner
        .message_idempotency
        .lock()
        .map_err(|_| {
            ManagerApiError::internal(
                "message_idempotency_lock",
                "message idempotency lock unavailable",
            )
        })?
        .insert(idempotency_key, message_id.to_string());
    messages.insert(message_id.to_string(), report.clone());
    Ok(Json(report))
}

fn validate_remote_message_authority(
    request: &SendMessageRequest,
    work_order: &WorkOrderEnvelope,
    source_instance: &InstanceRegistration,
    target_instance: &InstanceRegistration,
) -> Result<(), ManagerApiError> {
    let message = &request.message_envelope.message;
    let work_order_run_id = work_order.work_order.run_id.as_ref().ok_or_else(|| {
        ManagerApiError::forbidden(
            "message_run_unbound",
            "remote message work order must bind a run id",
        )
    })?;
    let message_run_authorized = message.run_id == *work_order_run_id
        || task_response_child_run_id(message)
            .map(|child_run_id| child_run_id == work_order_run_id.to_string())
            .unwrap_or(false);
    if !message_run_authorized {
        return Err(ManagerApiError::forbidden(
            "message_run_mismatch",
            "message run_id does not match work-order authority",
        ));
    }
    if message.source_agent_id != work_order.work_order.agent_id {
        return Err(ManagerApiError::forbidden(
            "message_source_agent_mismatch",
            "message source agent does not match work-order authority",
        ));
    }
    if !source_instance
        .hosted_tenants
        .contains(&work_order.work_order.tenant_id)
        || !target_instance
            .hosted_tenants
            .contains(&work_order.work_order.tenant_id)
    {
        return Err(ManagerApiError::forbidden(
            "message_tenant_not_hosted",
            "source and target instances must host the work-order tenant",
        ));
    }
    if !work_order
        .work_order
        .allowed_actions
        .iter()
        .any(|item| item == "message.remote.proposal")
    {
        return Err(ManagerApiError::forbidden(
            "message_action_not_allowed",
            "work order does not allow remote proposal messages",
        ));
    }
    if !work_order
        .work_order
        .allowed_adapters
        .iter()
        .any(|item| item == "remote-message")
    {
        return Err(ManagerApiError::forbidden(
            "message_adapter_not_allowed",
            "work order does not allow the remote-message adapter",
        ));
    }
    let route_permission = format!("message.remote.proposal:{}", message.target_agent_id);
    if !work_order
        .work_order
        .allowed_permissions
        .iter()
        .any(|item| item == &route_permission)
    {
        return Err(ManagerApiError::forbidden(
            "unauthorized_recipient",
            "target agent is not authorized by the submitted work order route permission",
        ));
    }
    if message_payload_smuggles_authority(&message.payload, work_order) {
        return Err(ManagerApiError::forbidden(
            "message_payload_scope_smuggling",
            "message payload cannot grant data refs or permissions outside work-order authority",
        ));
    }
    Ok(())
}

fn message_payload_smuggles_authority(
    payload: &serde_json::Value,
    work_order: &WorkOrderEnvelope,
) -> bool {
    let allowed_data_refs = &work_order.work_order.data_refs;
    let allowed_permissions = &work_order.work_order.allowed_permissions;
    let data_refs: Vec<&str> = payload
        .get("data_refs")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect();
    if data_refs
        .iter()
        .any(|data_ref| !allowed_data_refs.iter().any(|allowed| allowed == *data_ref))
    {
        return true;
    }
    let permissions: Vec<&str> = payload
        .get("permissions")
        .or_else(|| payload.get("allowed_permissions"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect();
    permissions.iter().any(|permission| {
        !allowed_permissions
            .iter()
            .any(|allowed| allowed == *permission)
    })
}

fn task_response_child_run_id(message: &Message) -> Option<&str> {
    if message.schema == "splendor.message.task_response.v1" {
        message
            .payload
            .get("child_run_id")
            .and_then(serde_json::Value::as_str)
    } else {
        None
    }
}

async fn get_message(
    Path(message_id): Path<MessageId>,
    State(state): State<ManagerState>,
    Json(request): Json<MessageReadRequest>,
) -> Result<Json<MessageStatusReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::MessagesRead,
        false,
    )?;
    let mut report = state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
        .get(&message_id.to_string())
        .cloned()
        .ok_or_else(|| ManagerApiError::not_found("message_not_found", "message not found"))?;
    ensure_message_visibility(
        &report,
        request.tenant_id.as_ref(),
        request.run_id.as_ref(),
        request.agent_id.as_ref(),
    )?;
    let read_trace_event_id = state.audit(
        "remote_message.received",
        serde_json::json!({
            "message_id": message_id,
            "delivery_trace_event_id": report.trace_event_id,
            "work_order_id": report.work_order_id,
            "tenant_id": report.tenant_id,
            "run_id": report.run_id,
            "source_agent_id": report.source_agent_id,
            "target_agent_id": report.target_agent_id,
            "delivery_status": report.delivery_status,
            "receive_side_validated": report.receive_side_validated,
            "remote_state_mutated": false,
        }),
    )?;
    report.read_trace_event_id = Some(read_trace_event_id.clone());
    state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
        .insert(message_id.to_string(), report.clone());
    Ok(Json(report))
}

async fn ack_message(
    Path(message_id): Path<MessageId>,
    State(state): State<ManagerState>,
    Json(request): Json<MessageDeliveryUpdateRequest>,
) -> Result<Json<MessageStatusReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::MessagesSend,
        true,
    )?;
    let mut report = state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
        .get(&message_id.to_string())
        .cloned()
        .ok_or_else(|| ManagerApiError::not_found("message_not_found", "message not found"))?;
    ensure_message_update_scope(&report, &request)?;
    let trace_event_id = state.audit(
        "message.acknowledged",
        serde_json::json!({
            "message_id": message_id,
            "work_order_id": report.work_order_id,
            "tenant_id": report.tenant_id,
            "run_id": report.run_id,
            "target_agent_id": report.target_agent_id,
            "reason": request.reason,
            "payload_preserved": true,
            "remote_state_mutated": false,
            "authority_granted": false,
        }),
    )?;
    report.delivery_status = "consumed".to_string();
    report.ack_trace_event_id = Some(trace_event_id);
    report.payload_preserved = true;
    state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
        .insert(message_id.to_string(), report.clone());
    Ok(Json(report))
}

async fn nack_message(
    Path(message_id): Path<MessageId>,
    State(state): State<ManagerState>,
    Json(request): Json<MessageDeliveryUpdateRequest>,
) -> Result<Json<MessageStatusReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::MessagesSend,
        true,
    )?;
    let mut report = state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
        .get(&message_id.to_string())
        .cloned()
        .ok_or_else(|| ManagerApiError::not_found("message_not_found", "message not found"))?;
    ensure_message_update_scope(&report, &request)?;
    let trace_event_id = state.audit(
        "message.nacked",
        serde_json::json!({
            "message_id": message_id,
            "work_order_id": report.work_order_id,
            "tenant_id": report.tenant_id,
            "run_id": report.run_id,
            "target_agent_id": report.target_agent_id,
            "reason": request.reason,
            "payload_preserved": true,
            "remote_state_mutated": false,
            "authority_granted": false,
        }),
    )?;
    report.delivery_status = "failed".to_string();
    report.nack_trace_event_id = Some(trace_event_id);
    report.payload_preserved = true;
    if report.reason.is_none() {
        report.reason = request.reason;
    }
    state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
        .insert(message_id.to_string(), report.clone());
    Ok(Json(report))
}

async fn list_inbox(
    Path(agent_id): Path<AgentId>,
    State(state): State<ManagerState>,
    Json(request): Json<MessageReadRequest>,
) -> Result<Json<MessageListResponse>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::MessagesRead,
        false,
    )?;
    let (tenant_id, run_id, scoped_agent_id) = ensure_message_list_scope(&agent_id, &request)?;
    let reports = state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    ensure_message_collection_scope(
        &reports,
        &tenant_id,
        &run_id,
        &scoped_agent_id,
        "message inbox",
    )?;
    let messages = reports
        .into_iter()
        .filter(|report| report.target_agent_id == agent_id)
        .filter(|report| report.tenant_id == tenant_id)
        .filter(|report| report.run_id == run_id)
        .collect::<Vec<_>>();
    let trace_event_id = state.audit(
        "message.inbox.listed",
        serde_json::json!({
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "run_id": run_id,
            "message_count": messages.len(),
            "authority_granted": false,
        }),
    )?;
    Ok(Json(MessageListResponse {
        agent_id,
        direction: "inbox".to_string(),
        tenant_id,
        run_id,
        messages,
        trace_event_id,
    }))
}

async fn list_outbox(
    Path(agent_id): Path<AgentId>,
    State(state): State<ManagerState>,
    Json(request): Json<MessageReadRequest>,
) -> Result<Json<MessageListResponse>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::MessagesRead,
        false,
    )?;
    let (tenant_id, run_id, scoped_agent_id) = ensure_message_list_scope(&agent_id, &request)?;
    let reports = state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    ensure_message_collection_scope(
        &reports,
        &tenant_id,
        &run_id,
        &scoped_agent_id,
        "message outbox",
    )?;
    let messages = reports
        .into_iter()
        .filter(|report| report.source_agent_id == agent_id)
        .filter(|report| report.tenant_id == tenant_id)
        .filter(|report| report.run_id == run_id)
        .collect::<Vec<_>>();
    let trace_event_id = state.audit(
        "message.outbox.listed",
        serde_json::json!({
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "run_id": run_id,
            "message_count": messages.len(),
            "authority_granted": false,
        }),
    )?;
    Ok(Json(MessageListResponse {
        agent_id,
        direction: "outbox".to_string(),
        tenant_id,
        run_id,
        messages,
        trace_event_id,
    }))
}

async fn get_message_causal_graph(
    Path(run_id): Path<RunId>,
    State(state): State<ManagerState>,
    Json(request): Json<MessageReadRequest>,
) -> Result<Json<MessageCausalGraphResponse>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::MessagesRead,
        false,
    )?;
    let tenant_id = request.tenant_id.clone().ok_or_else(|| {
        ManagerApiError::forbidden(
            "missing_message_tenant_scope",
            "message causal graph requires tenant_id scope",
        )
    })?;
    let scoped_run_id = request.run_id.clone().ok_or_else(|| {
        ManagerApiError::forbidden(
            "missing_message_run_scope",
            "message causal graph requires run_id scope",
        )
    })?;
    if scoped_run_id != run_id {
        return Err(ManagerApiError::forbidden(
            "message_run_scope_denied",
            "message causal graph path run does not match requested run scope",
        ));
    }
    let scoped_agent_id = request.agent_id.clone().ok_or_else(|| {
        ManagerApiError::forbidden(
            "missing_message_agent_scope",
            "message causal graph requires agent_id scope",
        )
    })?;
    let reports = state
        .inner
        .messages
        .lock()
        .map_err(|_| ManagerApiError::internal("message_lock", "message lock unavailable"))?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    ensure_message_collection_scope(
        &reports,
        &tenant_id,
        &run_id,
        &scoped_agent_id,
        "message causal graph",
    )?;
    let scoped_reports = reports
        .into_iter()
        .filter(|report| report.run_id == run_id)
        .filter(|report| report.tenant_id == tenant_id)
        .collect::<Vec<_>>();
    if !scoped_reports.is_empty()
        && !scoped_reports.iter().any(|report| {
            report.source_agent_id == scoped_agent_id || report.target_agent_id == scoped_agent_id
        })
    {
        return Err(ManagerApiError::forbidden(
            "message_agent_scope_denied",
            "message causal graph is outside requested agent scope",
        ));
    }
    let reports = scoped_reports
        .into_iter()
        .filter(|report| {
            report.source_agent_id == scoped_agent_id || report.target_agent_id == scoped_agent_id
        })
        .collect::<Vec<_>>();
    let trace_to_message = reports
        .iter()
        .map(|report| (report.trace_event_id.clone(), report.message_id.clone()))
        .collect::<HashMap<_, _>>();
    let nodes = reports
        .iter()
        .map(|report| MessageCausalGraphNode {
            message_id: report.message_id.clone(),
            work_order_id: report.work_order_id.clone(),
            source_agent_id: report.source_agent_id.clone(),
            target_agent_id: report.target_agent_id.clone(),
            schema: report.schema.clone(),
            delivery_status: report.delivery_status.clone(),
            trace_event_id: report.trace_event_id.clone(),
            causal_parent: report.causal_parent.clone(),
        })
        .collect::<Vec<_>>();
    let edges = reports
        .iter()
        .filter_map(|report| {
            report
                .causal_parent
                .as_ref()
                .map(|parent| MessageCausalGraphEdge {
                    from_trace_event_id: parent.clone(),
                    to_message_id: report.message_id.clone(),
                    to_trace_event_id: report.trace_event_id.clone(),
                    from_message_id: trace_to_message.get(parent).cloned(),
                })
        })
        .collect::<Vec<_>>();
    let trace_event_id = state.audit(
        "message.causal_graph.read",
        serde_json::json!({
            "run_id": run_id,
            "tenant_id": tenant_id,
            "agent_id": scoped_agent_id,
            "node_count": nodes.len(),
            "edge_count": edges.len(),
            "authority_granted": false,
        }),
    )?;
    Ok(Json(MessageCausalGraphResponse {
        run_id,
        tenant_id,
        agent_id: scoped_agent_id,
        nodes,
        edges,
        trace_event_id,
    }))
}

async fn list_message_schemas(
    State(state): State<ManagerState>,
    Json(request): Json<ManagerReadRequest>,
) -> Result<Json<MessageSchemaListResponse>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::MessagesRead,
        false,
    )?;
    let trace_event_id = state.audit(
        "message.schemas.listed",
        serde_json::json!({"schema_count": supported_message_schemas().len(), "authority_granted": false}),
    )?;
    Ok(Json(MessageSchemaListResponse {
        schemas: supported_message_schemas(),
        delivery_authority_granted: false,
        trace_event_id,
    }))
}

async fn validate_message_schema(
    State(state): State<ManagerState>,
    Json(request): Json<MessageSchemaValidationRequest>,
) -> Result<Json<MessageSchemaValidationReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::MessagesRead,
        false,
    )?;
    let (schema, validation_result) = if let Some(envelope) = request.message_envelope {
        let schema = envelope.message.schema.clone();
        let result = envelope
            .validate()
            .map_err(|error| error.to_string())
            .and_then(|_| {
                ensure_supported_message_schema(&schema).map_err(|error| error.body.message)
            });
        (schema, result)
    } else if let Some(schema) = request.schema {
        let result = splendor_types::MessageSchemaVersion::from_schema(&schema)
            .map_err(|error| error.to_string())
            .and_then(|_| {
                ensure_supported_message_schema(&schema).map_err(|error| error.body.message)
            });
        if request
            .payload
            .as_ref()
            .is_some_and(serde_json::Value::is_null)
        {
            (schema, Err("message payload is required".to_string()))
        } else {
            (schema, result)
        }
    } else {
        return Err(ManagerApiError::bad_request(
            "missing_message_schema",
            "schema validation requires a message_envelope or schema field",
        ));
    };
    let valid = validation_result.is_ok();
    let reason = validation_result.err();
    let schema_version = splendor_types::MessageSchemaVersion::from_schema(&schema)
        .ok()
        .map(|version| version.suffix().to_string());
    let supported = is_supported_message_schema(&schema);
    let trace_event_id = state.audit(
        "message.schema_validated",
        serde_json::json!({
            "schema": schema,
            "valid": valid,
            "supported": supported,
            "reason": reason,
            "delivery_authority_granted": false,
        }),
    )?;
    Ok(Json(MessageSchemaValidationReport {
        valid,
        supported,
        schema,
        schema_version,
        reason,
        delivery_authority_granted: false,
        trace_event_id,
    }))
}

async fn publish_policy_bundle(
    State(state): State<ManagerState>,
    Json(request): Json<PublishPolicyBundleRequest>,
) -> Result<Json<PolicyBundleStatusReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::PoliciesPublish,
        true,
    )?;
    let policy_bundle_id = request.policy_bundle.policy_bundle_id.to_string();
    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(
        request.policy_bundle,
        "policy-local-key",
        b"splendor-local-policy-secret",
    )
    .map_err(|e| ManagerApiError::bad_request("policy_bundle_rejected", e.to_string()))?;
    let trace_event_id = state.audit(
        "policy.published",
        serde_json::json!({"policy_bundle_id": policy_bundle_id, "tenant_id": envelope.bundle.tenant_id}),
    )?;
    state
        .inner
        .policies
        .lock()
        .map_err(|_| ManagerApiError::internal("policy_lock", "policy lock unavailable"))?
        .insert(policy_bundle_id.clone(), envelope.clone());
    Ok(Json(PolicyBundleStatusReport {
        policy_bundle_id,
        status: "published".to_string(),
        envelope,
        trace_event_id,
    }))
}

async fn get_policy_status(
    Path(policy_id): Path<String>,
    State(state): State<ManagerState>,
    Json(request): Json<ManagerReadRequest>,
) -> Result<Json<PolicyBundleStatusReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::FleetRead,
        false,
    )?;
    let envelope = state
        .inner
        .policies
        .lock()
        .map_err(|_| ManagerApiError::internal("policy_lock", "policy lock unavailable"))?
        .get(&policy_id)
        .cloned()
        .ok_or_else(|| ManagerApiError::not_found("policy_not_found", "policy not found"))?;
    let trace_event_id = state.audit(
        "policy.read",
        serde_json::json!({"policy_bundle_id": policy_id}),
    )?;
    Ok(Json(PolicyBundleStatusReport {
        policy_bundle_id: policy_id,
        status: match envelope.bundle.revocation {
            RevocationStatus::Active => "published".to_string(),
            RevocationStatus::Revoked { .. } => "revoked".to_string(),
        },
        envelope,
        trace_event_id,
    }))
}

async fn revoke_policy_bundle(
    Path(policy_id): Path<String>,
    State(state): State<ManagerState>,
    Json(request): Json<RevokePolicyBundleRequest>,
) -> Result<Json<PolicyBundleStatusReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::PoliciesRevoke,
        true,
    )?;
    let mut policies = state
        .inner
        .policies
        .lock()
        .map_err(|_| ManagerApiError::internal("policy_lock", "policy lock unavailable"))?;
    let mut envelope = policies
        .get(&policy_id)
        .cloned()
        .ok_or_else(|| ManagerApiError::not_found("policy_not_found", "policy not found"))?;
    envelope.bundle.revocation = RevocationStatus::Revoked {
        reason: request.reason.clone(),
    };
    envelope.signature = None;
    let envelope = PolicyBundleEnvelope::signed_with_shared_secret(
        envelope.bundle,
        "policy-local-key",
        b"splendor-local-policy-secret",
    )
    .map_err(|e| ManagerApiError::bad_request("policy_bundle_rejected", e.to_string()))?;
    policies.insert(policy_id.clone(), envelope.clone());
    let trace_event_id = state.audit(
        "policy.revoked",
        serde_json::json!({"policy_bundle_id": policy_id, "reason": request.reason}),
    )?;
    Ok(Json(PolicyBundleStatusReport {
        policy_bundle_id: policy_id,
        status: "revoked".to_string(),
        envelope,
        trace_event_id,
    }))
}

async fn request_approval(
    State(state): State<ManagerState>,
    Json(request): Json<ApprovalRequestPayload>,
) -> Result<Json<GovernanceApprovalRecord>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::ApprovalsManage,
        true,
    )?;
    let trace_event_id = state.audit(
        "approval.requested",
        serde_json::json!({"approval_id": request.approval_id, "run_id": request.run_id, "action_id": request.action_id, "policy_id": request.policy_id}),
    )?;
    let record = GovernanceApprovalRecord {
        approval_id: request.approval_id.clone(),
        tenant_id: request.tenant_id,
        agent_id: request.agent_id,
        run_id: request.run_id,
        action_id: request.action_id,
        action_name: request.action_name,
        adapter: request.adapter,
        policy_id: request.policy_id,
        risk_level: request.risk_level,
        audience: request.audience,
        status: "requested".to_string(),
        reason: request.reason,
        issued_by: request.security.audit_attribution,
        expires_at: request.expires_at,
        trace_event_id,
        evidence: None,
    };
    state
        .inner
        .approvals
        .lock()
        .map_err(|_| ManagerApiError::internal("approval_lock", "approval lock unavailable"))?
        .insert(record.approval_id.to_string(), record.clone());
    Ok(Json(record))
}

async fn grant_approval(
    Path(approval_id): Path<ApprovalId>,
    State(state): State<ManagerState>,
    Json(request): Json<ApprovalDecisionRequest>,
) -> Result<Json<GovernanceApprovalRecord>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::ApprovalsManage,
        true,
    )?;
    let mut approvals = state
        .inner
        .approvals
        .lock()
        .map_err(|_| ManagerApiError::internal("approval_lock", "approval lock unavailable"))?;
    let mut record = approvals
        .get(&approval_id.to_string())
        .cloned()
        .ok_or_else(|| ManagerApiError::not_found("approval_not_found", "approval not found"))?;
    let expires_at = request.expires_at.unwrap_or(record.expires_at);
    let mut evidence = ApprovalEvidence::new(
        approval_id.clone(),
        record.tenant_id.clone(),
        record.agent_id.clone(),
        record.run_id.clone(),
        ApprovalDecision::Granted,
        expires_at,
    )
    .with_action_name(record.action_name.clone())
    .with_adapter(record.adapter.clone());
    evidence.action_id = Some(record.action_id.clone());
    evidence.reason = Some(request.reason.clone());
    let trace_event_id = state.audit(
        "approval.granted",
        serde_json::json!({"approval_id": approval_id, "run_id": record.run_id, "action_id": record.action_id, "audience": record.audience}),
    )?;
    record.status = "granted".to_string();
    record.reason = request.reason;
    record.expires_at = expires_at;
    record.trace_event_id = trace_event_id;
    record.evidence = Some(evidence);
    approvals.insert(approval_id.to_string(), record.clone());
    Ok(Json(record))
}

async fn deny_approval(
    Path(approval_id): Path<ApprovalId>,
    State(state): State<ManagerState>,
    Json(request): Json<ApprovalDecisionRequest>,
) -> Result<Json<GovernanceApprovalRecord>, ManagerApiError> {
    decide_approval(
        state,
        approval_id,
        request,
        "denied",
        ApprovalDecision::Denied,
        false,
    )
    .await
}

async fn revoke_approval(
    Path(approval_id): Path<ApprovalId>,
    State(state): State<ManagerState>,
    Json(request): Json<ApprovalDecisionRequest>,
) -> Result<Json<GovernanceApprovalRecord>, ManagerApiError> {
    decide_approval(
        state,
        approval_id,
        request,
        "revoked",
        ApprovalDecision::Denied,
        true,
    )
    .await
}

async fn decide_approval(
    state: ManagerState,
    approval_id: ApprovalId,
    request: ApprovalDecisionRequest,
    status: &'static str,
    decision: ApprovalDecision,
    revoked: bool,
) -> Result<Json<GovernanceApprovalRecord>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::ApprovalsManage,
        true,
    )?;
    let mut approvals = state
        .inner
        .approvals
        .lock()
        .map_err(|_| ManagerApiError::internal("approval_lock", "approval lock unavailable"))?;
    let mut record = approvals
        .get(&approval_id.to_string())
        .cloned()
        .ok_or_else(|| ManagerApiError::not_found("approval_not_found", "approval not found"))?;
    let mut evidence = ApprovalEvidence::new(
        approval_id.clone(),
        record.tenant_id.clone(),
        record.agent_id.clone(),
        record.run_id.clone(),
        decision,
        request.expires_at.unwrap_or(record.expires_at),
    )
    .with_action_name(record.action_name.clone())
    .with_adapter(record.adapter.clone());
    evidence.action_id = Some(record.action_id.clone());
    evidence.reason = Some(request.reason.clone());
    evidence.revoked = revoked;
    let trace_event_id = state.audit(
        &format!("approval.{status}"),
        serde_json::json!({"approval_id": approval_id, "run_id": record.run_id, "action_id": record.action_id, "reason": request.reason}),
    )?;
    record.status = status.to_string();
    record.reason = request.reason;
    record.trace_event_id = trace_event_id;
    record.evidence = Some(evidence);
    approvals.insert(approval_id.to_string(), record.clone());
    Ok(Json(record))
}

async fn create_circuit_breaker(
    State(state): State<ManagerState>,
    Json(request): Json<CircuitBreakerRequest>,
) -> Result<Json<GovernanceCircuitBreakerRecord>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::GovernanceControl,
        true,
    )?;
    let trace_event_id = state.audit(
        "circuit_breaker.tripped",
        serde_json::json!({"breaker_id": request.breaker_id, "tenant_id": request.tenant_id, "adapter": request.adapter, "action": request.action, "reason": request.reason}),
    )?;
    let record = GovernanceCircuitBreakerRecord {
        breaker_id: request.breaker_id,
        status: "tripped".to_string(),
        tenant_id: request.tenant_id,
        adapter: request.adapter,
        action: request.action,
        reason: request.reason,
        trace_event_id,
    };
    state
        .inner
        .circuit_breakers
        .lock()
        .map_err(|_| ManagerApiError::internal("breaker_lock", "breaker lock unavailable"))?
        .insert(record.breaker_id.clone(), record.clone());
    Ok(Json(record))
}

async fn read_circuit_breaker_sync_payload(
    Path(breaker_id): Path<String>,
    State(state): State<ManagerState>,
    Json(request): Json<CircuitBreakerSyncPayloadRequest>,
) -> Result<Json<CircuitBreakerSyncPayloadReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::GovernanceControl,
        true,
    )?;
    let record = state
        .inner
        .circuit_breakers
        .lock()
        .map_err(|_| ManagerApiError::internal("breaker_lock", "breaker lock unavailable"))?
        .get(&breaker_id)
        .cloned()
        .ok_or_else(|| {
            ManagerApiError::not_found("breaker_not_found", "circuit breaker not found")
        })?;
    if record.status != "tripped" {
        return Err(ManagerApiError::bad_request(
            "breaker_not_tripped",
            "only tripped circuit breakers can be exported for daemon sync",
        ));
    }
    let scope = if let Some(action) = record.action.clone() {
        CircuitBreakerScope::Action(action)
    } else if let Some(adapter) = record.adapter.clone() {
        CircuitBreakerScope::Adapter(adapter)
    } else if let Some(tenant_id) = record.tenant_id.clone() {
        CircuitBreakerScope::Tenant(tenant_id)
    } else {
        CircuitBreakerScope::Global
    };
    let breaker_id = CircuitBreakerId::parse(&record.breaker_id)
        .map_err(|e| ManagerApiError::bad_request("invalid_breaker_id", e.to_string()))?;
    let now = OffsetDateTime::now_utc();
    let circuit_breaker = CircuitBreaker::tripped(breaker_id, scope, record.reason.clone(), now)
        .map_err(|e| ManagerApiError::bad_request("invalid_circuit_breaker", e.to_string()))?;
    let manager_trace_event_id = state.audit(
        "circuit_breaker.sync_payload.exported",
        serde_json::json!({
            "breaker_id": record.breaker_id,
            "run_id": request.run_id,
            "source_trace_event_id": record.trace_event_id,
            "reason": request.reason,
        }),
    )?;
    Ok(Json(CircuitBreakerSyncPayloadReport {
        run_id: request.run_id,
        breaker_record: record,
        circuit_breakers: vec![circuit_breaker],
        manager_trace_event_id,
        reason: request.reason,
    }))
}

async fn clear_circuit_breaker(
    Path(breaker_id): Path<String>,
    State(state): State<ManagerState>,
    Json(request): Json<ClearCircuitBreakerRequest>,
) -> Result<Json<GovernanceCircuitBreakerRecord>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::GovernanceControl,
        true,
    )?;
    let mut breakers = state
        .inner
        .circuit_breakers
        .lock()
        .map_err(|_| ManagerApiError::internal("breaker_lock", "breaker lock unavailable"))?;
    let mut record = breakers.get(&breaker_id).cloned().ok_or_else(|| {
        ManagerApiError::not_found("breaker_not_found", "circuit breaker not found")
    })?;
    let trace_event_id = state.audit(
        "circuit_breaker.cleared",
        serde_json::json!({"breaker_id": breaker_id, "reason": request.reason}),
    )?;
    record.status = "cleared".to_string();
    record.reason = request.reason;
    record.trace_event_id = trace_event_id;
    breakers.insert(breaker_id, record.clone());
    Ok(Json(record))
}

async fn activate_kill_switch(
    State(state): State<ManagerState>,
    Json(request): Json<KillSwitchRequest>,
) -> Result<Json<KillSwitchReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::GovernanceControl,
        true,
    )?;
    let target = resolve_kill_switch_target(&state, &request)?;
    let mut acknowledged = false;
    let mut cancel_status = None;
    let mut cancel_payload_schema = None;
    if let (Some(target), Some(run_id), Some(tenant_id)) =
        (&target, &request.run_id, &request.tenant_id)
    {
        let credential = kill_switch_credential(
            &request.security.credential,
            &request.kill_switch_id,
            &target.instance_id,
            tenant_id,
        );
        let payload = serde_json::json!({
            "credential": credential,
            "audit_attribution": resident_audit(&credential),
            "reason": request.reason,
        });
        cancel_payload_schema = Some("splendor.daemon.lifecycle_request.v1".to_string());
        let response = post_json(
            &target.daemon_url,
            &format!("/runs/{run_id}/cancel"),
            &payload,
        )
        .map_err(|e| ManagerApiError::internal("kill_switch_http_error", e))?;
        cancel_status = Some(response.status);
        acknowledged = (200..300).contains(&response.status);
    }
    let fail_closed = request.propagation_ack_required && !acknowledged;
    let trace_event_id = state.audit(
        "kill_switch.activated",
        serde_json::json!({"kill_switch_id": request.kill_switch_id, "run_id": request.run_id, "node_id": request.node_id, "instance_id": request.instance_id, "target_instance_id": target.as_ref().map(|target| target.instance_id.clone()), "target_derived_from_registry": target.is_some(), "acknowledged": acknowledged, "fail_closed": fail_closed, "reason": request.reason}),
    )?;
    let report = KillSwitchReport {
        kill_switch_id: request.kill_switch_id,
        status: if fail_closed {
            "fail_closed"
        } else {
            "activated"
        }
        .to_string(),
        fail_closed,
        propagation_acknowledged: acknowledged,
        cancel_status,
        target_daemon_url: target.as_ref().map(|target| target.daemon_url.clone()),
        target_instance_id: target.as_ref().map(|target| target.instance_id.clone()),
        target_derived_from_registry: target.is_some(),
        cancel_payload_schema,
        trace_event_id,
        reason: request.reason,
    };
    state
        .inner
        .kill_switches
        .lock()
        .map_err(|_| ManagerApiError::internal("kill_switch_lock", "kill switch lock unavailable"))?
        .insert(report.kill_switch_id.clone(), report.clone());
    Ok(Json(report))
}

#[derive(Clone, Debug)]
struct KillSwitchTarget {
    daemon_url: String,
    instance_id: InstanceId,
}

fn resolve_kill_switch_target(
    state: &ManagerState,
    request: &KillSwitchRequest,
) -> Result<Option<KillSwitchTarget>, ManagerApiError> {
    let Some(run_id) = request.run_id.as_ref() else {
        return Ok(None);
    };
    let telemetry_target = state
        .inner
        .telemetry
        .lock()
        .map_err(|_| ManagerApiError::internal("telemetry_lock", "telemetry lock unavailable"))?
        .snapshot(OffsetDateTime::now_utc())
        .runs
        .into_iter()
        .find(|run| &run.run_id == run_id)
        .map(|run| (run.node_id, run.instance_id));
    let (node_id, instance_id) = match (&request.node_id, &request.instance_id, telemetry_target) {
        (Some(node_id), Some(instance_id), _) => (node_id.clone(), instance_id.clone()),
        (_, _, Some((node_id, instance_id))) => (node_id, instance_id),
        _ => return Ok(None),
    };
    let instance = state
        .inner
        .registry
        .instance(&instance_id)
        .map_err(|e| ManagerApiError::not_found("instance_not_found", e.to_string()))?;
    if instance.registration.node_id != node_id {
        return Err(ManagerApiError::forbidden(
            "kill_switch_target_mismatch",
            "instance is not hosted by requested node",
        ));
    }
    let node = state
        .inner
        .registry
        .node(&node_id)
        .map_err(|e| ManagerApiError::not_found("node_not_found", e.to_string()))?;
    let daemon_url = node
        .registration
        .capability_document
        .constraints
        .get("resident_daemon_url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ManagerApiError::bad_request(
                "missing_resident_daemon_url",
                "registered node does not advertise resident_daemon_url",
            )
        })?
        .to_string();
    Ok(Some(KillSwitchTarget {
        daemon_url,
        instance_id,
    }))
}

async fn export_governance_audit(
    State(state): State<ManagerState>,
    Json(request): Json<GovernanceAuditExportRequest>,
) -> Result<Json<GovernanceAuditExportReport>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::TracesRead,
        false,
    )?;
    let trace_event_id = state.audit(
        "governance.audit.exported",
        serde_json::json!({"run_id": request.run_id}),
    )?;
    let events = state
        .inner
        .audit
        .lock()
        .map_err(|_| ManagerApiError::internal("audit_lock", "audit lock unavailable"))?
        .clone();
    Ok(Json(GovernanceAuditExportReport {
        exported: true,
        trace_event_id,
        events,
        policy_bundle_ids: state
            .inner
            .policies
            .lock()
            .map_err(|_| ManagerApiError::internal("policy_lock", "policy lock unavailable"))?
            .keys()
            .cloned()
            .collect(),
        approval_ids: state
            .inner
            .approvals
            .lock()
            .map_err(|_| ManagerApiError::internal("approval_lock", "approval lock unavailable"))?
            .keys()
            .cloned()
            .collect(),
        circuit_breaker_ids: state
            .inner
            .circuit_breakers
            .lock()
            .map_err(|_| ManagerApiError::internal("breaker_lock", "breaker lock unavailable"))?
            .keys()
            .cloned()
            .collect(),
        kill_switch_ids: state
            .inner
            .kill_switches
            .lock()
            .map_err(|_| {
                ManagerApiError::internal("kill_switch_lock", "kill switch lock unavailable")
            })?
            .keys()
            .cloned()
            .collect(),
    }))
}

async fn get_fleet_telemetry(
    State(state): State<ManagerState>,
    Json(request): Json<ManagerReadRequest>,
) -> Result<Json<FleetTelemetrySnapshot>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::FleetRead,
        false,
    )?;
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
    Json(request): Json<ManagerReadRequest>,
) -> Result<Json<Vec<ManagerAuditEvent>>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::FleetRead,
        false,
    )?;
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

fn kill_switch_credential(
    manager_credential: &CallerCredential,
    kill_switch_id: &str,
    instance_id: &InstanceId,
    tenant_id: &TenantId,
) -> serde_json::Value {
    let mut credential = manager_credential.clone();
    credential.credential_id = format!("kill-switch-{kill_switch_id}");
    credential.audience = CredentialAudience::Instance {
        instance_id: instance_id.clone(),
    };
    credential.binding = CredentialBinding::Tenant {
        tenant_id: tenant_id.clone(),
    };
    credential.scopes = vec![EndpointScope::RunsStop];
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request, StatusCode};
    use splendor_store::{InMemoryTraceStore, TraceStore, TraceSyncScope};
    use splendor_types::{
        AgentId, ClientPrincipal, FleetId, TelemetryAuthority, WorkOrder, WorkOrderId,
        WorkOrderPlacement, WorkOrderQuotaPolicy,
    };
    use tower::ServiceExt;

    fn credential(fleet_id: FleetId, scopes: Vec<EndpointScope>) -> CallerCredential {
        CallerCredential {
            credential_id: "manager-test-credential".to_string(),
            principal: ClientPrincipal::new("app_manager_test", "client_manager_test"),
            scopes,
            binding: CredentialBinding::Fleet { fleet_id },
            audience: CredentialAudience::CentralManager {
                manager_id: "central-manager".to_string(),
            },
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
            revocation: RevocationStatus::Active,
        }
    }

    fn audit_for(credential: &CallerCredential) -> AuditAttribution {
        AuditAttribution {
            principal: credential.principal.clone(),
            credential_id: Some(credential.credential_id.clone()),
            requested_at: OffsetDateTime::now_utc(),
        }
    }

    fn now_rfc3339() -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("timestamp formats")
    }

    fn test_work_order(target_agent: &str) -> WorkOrderEnvelope {
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let agent_id =
            splendor_types::AgentId::parse("22222222-2222-4222-8222-222222222222").expect("agent");
        let run_id = RunId::parse("44444444-4444-4444-8444-444444444444").expect("run");
        WorkOrderEnvelope::signed_with_shared_secret(
            WorkOrder {
                schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
                work_order_id: WorkOrderId::try_new("wo_test_remote").expect("work order id"),
                tenant_id,
                agent_id,
                run_id: Some(run_id),
                objective: "test remote message authority".to_string(),
                allowed_actions: vec![
                    "sql.read_fixture".to_string(),
                    "artifact.create_internal".to_string(),
                    "message.remote.proposal".to_string(),
                ],
                allowed_adapters: vec![
                    "fixture-sql".to_string(),
                    "artifact-store".to_string(),
                    "remote-message".to_string(),
                ],
                allowed_permissions: vec![
                    "fixture.sql.read".to_string(),
                    "artifact.create_internal".to_string(),
                    format!("message.remote.proposal:{target_agent}"),
                ],
                data_refs: vec!["dataset:eu-west.fixture.v1".to_string()],
                quotas: WorkOrderQuotaPolicy::default(),
                placement: WorkOrderPlacement {
                    target: "customer_vpc".to_string(),
                    data_locality: Some("eu-west".to_string()),
                    requires_gpu: Some(false),
                    dedicated_instance: Some(false),
                    required_capabilities: vec!["message.remote.proposal".to_string()],
                    max_runtime_ms: Some(30_000),
                    execution_mode: PlacementExecutionMode::Live,
                },
                issued_at: OffsetDateTime::now_utc() - Duration::minutes(1),
                expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
                revocation: RevocationStatus::Active,
            },
            "work-order-local-key",
            b"splendor-local-work-order-secret",
        )
        .expect("signed work order")
    }

    fn instance(node_id: &str, instance_id: &str, tenant_id: &TenantId) -> InstanceRegistration {
        serde_json::from_value(serde_json::json!({
            "instance_id": instance_id,
            "node_id": node_id,
            "runtime_mode": "resident",
            "hosted_tenants": [tenant_id],
            "supported_features": ["message.remote"],
            "runtime_version": "0.1-test",
            "health": {"status": "healthy", "observed_at": now_rfc3339(), "metadata": {}},
            "registered_at": now_rfc3339()
        }))
        .expect("instance registration")
    }

    fn node(
        fleet_id: &FleetId,
        node_id: &str,
        url: &str,
        target: &str,
        locality: &str,
        capabilities: Vec<&str>,
    ) -> NodeRegistration {
        serde_json::from_value(serde_json::json!({
            "node_id": node_id,
            "kind": "vpc.worker",
            "scope": {"fleet_id": fleet_id, "tenant_id": null},
            "capability_document": {
                "schema": "splendor.capabilities.v1",
                "capabilities": capabilities,
                "constraints": {"placement_target": target, "data_locality": locality, "resident_daemon_url": url}
            },
            "runtime_version": "0.1-test",
            "health": {"status": "healthy", "observed_at": now_rfc3339(), "metadata": {}},
            "registered_at": now_rfc3339()
        }))
        .expect("node registration")
    }

    fn manager_security(state: &ManagerState, scopes: Vec<EndpointScope>) -> ManagerSecurityFields {
        let credential = credential(state.inner.fleet_id.clone(), scopes);
        ManagerSecurityFields {
            audit_attribution: audit_for(&credential),
            credential,
        }
    }

    fn message_read_request(
        security: ManagerSecurityFields,
        tenant_id: Option<TenantId>,
        run_id: Option<RunId>,
        agent_id: Option<AgentId>,
    ) -> MessageReadRequest {
        MessageReadRequest {
            security,
            tenant_id,
            run_id,
            agent_id,
        }
    }

    fn message_update_request(
        security: ManagerSecurityFields,
        tenant_id: Option<TenantId>,
        run_id: Option<RunId>,
        agent_id: Option<AgentId>,
        reason: &str,
    ) -> MessageDeliveryUpdateRequest {
        MessageDeliveryUpdateRequest {
            security,
            tenant_id,
            run_id,
            agent_id,
            reason: Some(reason.to_string()),
            payload: None,
            payload_patch: None,
        }
    }

    fn assert_message_authority_preserved(
        before: &MessageStatusReport,
        after: &MessageStatusReport,
    ) {
        assert_eq!(after.message_id, before.message_id);
        assert_eq!(after.work_order_id, before.work_order_id);
        assert_eq!(after.tenant_id, before.tenant_id);
        assert_eq!(after.run_id, before.run_id);
        assert_eq!(after.source_agent_id, before.source_agent_id);
        assert_eq!(after.target_agent_id, before.target_agent_id);
        assert_eq!(after.schema, before.schema);
        assert_eq!(after.causal_parent, before.causal_parent);
        assert_eq!(after.idempotency_key, before.idempotency_key);
        assert_eq!(after.source_instance_id, before.source_instance_id);
        assert_eq!(after.target_instance_id, before.target_instance_id);
        assert_eq!(after.route_permission, before.route_permission);
        assert_eq!(after.remote_state_mutated, before.remote_state_mutated);
        assert!(after.payload_preserved);
    }

    fn spawn_resident_mock() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind resident mock");
        let addr = listener.local_addr().expect("resident mock addr");
        std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept resident request");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                    .expect("set resident read timeout");
                let mut request = Vec::new();
                let _ = stream.read_to_end(&mut request);
                let body = r#"{"accepted":true}"#;
                write!(
                    stream,
                    "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .expect("write resident response");
            }
        });
        format!("http://{addr}")
    }

    fn send_request(
        credential: CallerCredential,
        target_agent: &str,
        run_id: RunId,
    ) -> SendMessageRequest {
        serde_json::from_value(serde_json::json!({
            "credential": credential,
            "audit_attribution": audit_for(&credential),
            "work_order_id": "wo_test_remote",
            "message_envelope": {
                "message": {
                    "message_id": "55555555-5555-4555-8555-555555555554",
                    "source_agent_id": "22222222-2222-4222-8222-222222222222",
                    "target_agent_id": target_agent,
                    "run_id": run_id,
                    "schema": "splendor.message.proposal_request.v1",
                    "payload": {"request": "proposal_only"},
                    "causal_parent": null,
                    "requires_response": true,
                    "created_at": now_rfc3339()
                },
                "schema_version": "v1",
                "delivery_status": "pending",
                "trace_links": {}
            },
            "source_instance_id": "00000000-0000-4000-8000-000000000302",
            "target_instance_id": "00000000-0000-4000-8000-000000000304",
            "idempotency_key": "proposal-once",
            "simulate_failure": null
        }))
        .expect("send request")
    }

    async fn manager_call<T: serde::de::DeserializeOwned>(
        app: Router,
        method: Method,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, T) {
        let mut builder = Request::builder().method(method).uri(uri);
        let request = if let Some(body) = body {
            builder = builder.header("content-type", "application/json");
            builder
                .body(Body::from(serde_json::to_vec(&body).expect("body")))
                .expect("request")
        } else {
            builder.body(Body::empty()).expect("request")
        };
        let response = app.oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let parsed = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "json response ({status}): {error}; body={}",
                String::from_utf8_lossy(&bytes)
            )
        });
        (status, parsed)
    }

    #[tokio::test]
    async fn manager_health_endpoint_reports_component_without_mutation() {
        let state = ManagerState::local_acceptance();
        let (status, body): (StatusCode, serde_json::Value) =
            manager_call(router(state), Method::GET, "/health", None).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["component"], "splendor-manager");
    }

    #[test]
    fn manager_read_endpoints_require_scope_audience_binding_expiry_and_revocation() {
        let state = ManagerState::local_acceptance();
        let valid = credential(state.inner.fleet_id.clone(), vec![EndpointScope::FleetRead]);
        let error = state
            .validate_security(&valid, None, EndpointScope::FleetRead, false)
            .expect_err("missing read audit rejected");
        assert_eq!(error.body.code, "missing_audit_attribution");
        state
            .validate_security(
                &valid,
                Some(&audit_for(&valid)),
                EndpointScope::FleetRead,
                false,
            )
            .expect("valid fleet read credential");

        let missing_scope = credential(
            state.inner.fleet_id.clone(),
            vec![EndpointScope::MessagesRead],
        );
        let error = state
            .validate_security(&missing_scope, None, EndpointScope::FleetRead, false)
            .expect_err("missing scope rejected");
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(error.body.code, "missing_scope");

        let mut wrong_audience = valid.clone();
        wrong_audience.audience = CredentialAudience::CentralManager {
            manager_id: "other-manager".to_string(),
        };
        let error = state
            .validate_security(&wrong_audience, None, EndpointScope::FleetRead, false)
            .expect_err("wrong audience rejected");
        assert_eq!(error.body.code, "wrong_audience");

        let mut wrong_binding = valid.clone();
        wrong_binding.binding = CredentialBinding::Fleet {
            fleet_id: FleetId::parse("00000000-0000-4000-8000-000000000999").expect("fleet id"),
        };
        let error = state
            .validate_security(&wrong_binding, None, EndpointScope::FleetRead, false)
            .expect_err("wrong fleet binding rejected");
        assert_eq!(error.body.code, "wrong_credential_binding");

        let mut expired = valid.clone();
        expired.expires_at = OffsetDateTime::now_utc() - Duration::minutes(1);
        let error = state
            .validate_security(&expired, None, EndpointScope::FleetRead, false)
            .expect_err("expired credential rejected");
        assert_eq!(error.body.code, "credential_expired");

        let mut revoked = valid;
        revoked.revocation = RevocationStatus::Revoked {
            reason: "test".to_string(),
        };
        let error = state
            .validate_security(&revoked, None, EndpointScope::FleetRead, false)
            .expect_err("revoked credential rejected");
        assert_eq!(error.body.code, "credential_revoked");
    }

    #[tokio::test]
    async fn manager_registry_handlers_fail_closed_without_required_scope() {
        let state = ManagerState::local_acceptance();
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let node = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000504",
            "http://127.0.0.1:1",
            "resident_cloud_pool",
            "cloud",
            vec!["runtime.resident"],
        );
        let missing_scope = manager_security(&state, vec![EndpointScope::FleetRead]);

        let register_node_error = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: missing_scope.clone(),
                registration: node.clone(),
            }),
        )
        .await
        .expect_err("node registration requires node scope");
        assert_eq!(register_node_error.body.code, "missing_scope");

        let register_instance_error = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: missing_scope.clone(),
                registration: instance(
                    "00000000-0000-4000-8000-000000000504",
                    "00000000-0000-4000-8000-000000000604",
                    &tenant_id,
                ),
            }),
        )
        .await
        .expect_err("instance registration requires instance scope");
        assert_eq!(register_instance_error.body.code, "missing_scope");

        let heartbeat_error = heartbeat_node(
            Path(node.node_id.clone()),
            State(state.clone()),
            Json(HeartbeatNodeRequest {
                security: missing_scope.clone(),
                heartbeat: NodeHeartbeat {
                    node_id: node.node_id.clone(),
                    health: node.health.clone(),
                    recorded_at: OffsetDateTime::now_utc(),
                },
            }),
        )
        .await
        .expect_err("heartbeat requires heartbeat scope");
        assert_eq!(heartbeat_error.body.code, "missing_scope");

        let advertise_error = advertise_capabilities(
            Path(node.node_id.clone()),
            State(state.clone()),
            Json(AdvertiseCapabilitiesRequest {
                security: missing_scope,
                capability_document: node.capability_document.clone(),
            }),
        )
        .await
        .expect_err("capability advertisement requires node scope");
        assert_eq!(advertise_error.body.code, "missing_scope");
    }

    #[tokio::test]
    async fn manager_registration_handlers_are_idempotent_for_matching_records() {
        let state = ManagerState::local_acceptance();
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let security = manager_security(
            &state,
            vec![
                EndpointScope::NodesRegister,
                EndpointScope::InstancesRegister,
            ],
        );
        let node = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000704",
            "http://127.0.0.1:1",
            "resident_cloud_pool",
            "cloud",
            vec!["runtime.resident", "message.remote"],
        );
        let first_node = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration: node.clone(),
            }),
        )
        .await
        .expect("initial node registration accepted");
        let second_node = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration: node.clone(),
            }),
        )
        .await
        .expect("matching duplicate node registration accepted idempotently");
        assert_eq!(first_node.0.node_id, second_node.0.node_id);

        let mut incompatible_node = node.clone();
        incompatible_node
            .capability_document
            .capabilities
            .push("different.capability".to_string());
        let error = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration: incompatible_node,
            }),
        )
        .await
        .expect_err("incompatible duplicate node metadata rejected");
        assert_eq!(error.body.code, "node_registration_rejected");

        let instance = instance(
            "00000000-0000-4000-8000-000000000704",
            "00000000-0000-4000-8000-000000000705",
            &tenant_id,
        );
        let first_instance = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance.clone(),
            }),
        )
        .await
        .expect("initial instance registration accepted");
        let second_instance = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance.clone(),
            }),
        )
        .await
        .expect("matching duplicate instance registration accepted idempotently");
        assert_eq!(first_instance.0.instance_id, second_instance.0.instance_id);

        let mut incompatible_instance = instance;
        incompatible_instance
            .supported_features
            .push("different.feature".to_string());
        let error = register_instance(
            State(state),
            Json(RegisterInstanceRequest {
                security,
                registration: incompatible_instance,
            }),
        )
        .await
        .expect_err("incompatible duplicate instance metadata rejected");
        assert_eq!(error.body.code, "instance_registration_rejected");
    }

    #[test]
    fn manager_mutating_endpoints_require_matching_audit_attribution() {
        let state = ManagerState::local_acceptance();
        let valid = credential(
            state.inner.fleet_id.clone(),
            vec![EndpointScope::FleetDispatch],
        );

        let error = state
            .validate_security(&valid, None, EndpointScope::FleetDispatch, true)
            .expect_err("missing audit rejected");
        assert_eq!(error.body.code, "missing_audit_attribution");

        let mut mismatched = audit_for(&valid);
        mismatched.credential_id = Some("other-credential".to_string());
        let error = state
            .validate_security(
                &valid,
                Some(&mismatched),
                EndpointScope::FleetDispatch,
                true,
            )
            .expect_err("mismatched audit rejected");
        assert_eq!(error.body.code, "attribution_mismatch");

        state
            .validate_security(
                &valid,
                Some(&audit_for(&valid)),
                EndpointScope::FleetDispatch,
                true,
            )
            .expect("matching audit accepted");
    }

    #[test]
    fn manager_s5_governance_scopes_are_independently_enforced() {
        let state = ManagerState::local_acceptance();
        let s5_scope_pairs = [
            (
                EndpointScope::PoliciesPublish,
                EndpointScope::PoliciesRevoke,
                "splendor.policies.publish",
            ),
            (
                EndpointScope::PoliciesRevoke,
                EndpointScope::PoliciesPublish,
                "splendor.policies.revoke",
            ),
            (
                EndpointScope::ApprovalsManage,
                EndpointScope::GovernanceControl,
                "splendor.approvals.manage",
            ),
            (
                EndpointScope::GovernanceControl,
                EndpointScope::ApprovalsManage,
                "splendor.governance.control",
            ),
            (
                EndpointScope::TracesRead,
                EndpointScope::FleetRead,
                "splendor.traces.read",
            ),
            (
                EndpointScope::FleetRead,
                EndpointScope::TracesRead,
                "splendor.fleet.read",
            ),
        ];

        for (required_scope, wrong_scope, expected_label) in s5_scope_pairs {
            assert_eq!(required_scope.as_str(), expected_label);
            let credential = credential(state.inner.fleet_id.clone(), vec![required_scope]);
            let audit = audit_for(&credential);
            state
                .validate_security(&credential, Some(&audit), required_scope, true)
                .expect("credential with exact S5 scope is accepted");

            let denied = state
                .validate_security(&credential, Some(&audit), wrong_scope, true)
                .expect_err("credential without required S5 scope is denied");
            assert_eq!(denied.status, StatusCode::FORBIDDEN);
            assert_eq!(denied.body.code, "missing_scope");
        }
    }

    #[tokio::test]
    async fn manager_governance_handlers_cover_s5_authority_and_audit_paths() {
        let state = ManagerState::local_acceptance();
        let security = manager_security(
            &state,
            vec![
                EndpointScope::PoliciesPublish,
                EndpointScope::PoliciesRevoke,
                EndpointScope::ApprovalsManage,
                EndpointScope::GovernanceControl,
                EndpointScope::FleetRead,
                EndpointScope::TracesRead,
                EndpointScope::NodesRegister,
                EndpointScope::InstancesRegister,
            ],
        );
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let agent_id = AgentId::parse("22222222-2222-4222-8222-222222222222").expect("agent");
        let run_id = RunId::parse("44444444-4444-4444-8444-444444444444").expect("run");
        let action_id = splendor_types::ActionId::parse("55555555-5555-4555-8555-555555555555")
            .expect("action");

        let policy_bundle: PolicyBundle = serde_json::from_value(serde_json::json!({
            "schema_version": "splendor.policy_bundle.v1",
            "policy_bundle_id": "policy_s5_unit",
            "version": "unit.v1",
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "issued_at": now_rfc3339(),
            "expires_at": (OffsetDateTime::now_utc() + Duration::minutes(30)).format(&Rfc3339).expect("expiry formats"),
            "revocation": "active",
            "degraded_mode": {
                "allow_low_risk_cached": false,
                "disconnected_low_risk_actions": ["artifact.create_internal"],
                "disconnected_high_risk_actions": ["artifact.publish_external"],
                "high_risk_disconnected_behavior": "deny"
            }
        }))
        .expect("policy bundle parses");
        let published = publish_policy_bundle(
            State(state.clone()),
            Json(PublishPolicyBundleRequest {
                security: security.clone(),
                policy_bundle,
            }),
        )
        .await
        .expect("policy published")
        .0;
        assert_eq!(published.status, "published");
        assert!(published.envelope.signature.is_some());

        let read = get_policy_status(
            Path("policy_s5_unit".to_string()),
            State(state.clone()),
            Json(ManagerReadRequest {
                security: security.clone(),
                tenant_id: None,
                agent_id: None,
            }),
        )
        .await
        .expect("policy read")
        .0;
        assert_eq!(read.status, "published");

        let missing_policy = get_policy_status(
            Path("policy_missing".to_string()),
            State(state.clone()),
            Json(ManagerReadRequest {
                security: security.clone(),
                tenant_id: None,
                agent_id: None,
            }),
        )
        .await
        .expect_err("missing policy rejected");
        assert_eq!(missing_policy.body.code, "policy_not_found");

        let approval_id =
            ApprovalId::parse("66666666-6666-4666-8666-666666666666").expect("approval");
        let requested = request_approval(
            State(state.clone()),
            Json(ApprovalRequestPayload {
                security: security.clone(),
                approval_id: approval_id.clone(),
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                run_id: run_id.clone(),
                action_id: action_id.clone(),
                action_name: "artifact.publish_external".to_string(),
                adapter: "artifact-store".to_string(),
                policy_id: "policy_s5_unit".to_string(),
                risk_level: "high".to_string(),
                audience: "daemon_local".to_string(),
                expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
                reason: "unit approval request".to_string(),
            }),
        )
        .await
        .expect("approval requested")
        .0;
        assert_eq!(requested.status, "requested");

        let granted = grant_approval(
            Path(approval_id.clone()),
            State(state.clone()),
            Json(ApprovalDecisionRequest {
                security: security.clone(),
                reason: "grant unit".to_string(),
                expires_at: Some(OffsetDateTime::now_utc() + Duration::minutes(5)),
            }),
        )
        .await
        .expect("approval granted")
        .0;
        assert_eq!(granted.status, "granted");
        assert_eq!(
            granted.evidence.expect("grant evidence").decision,
            ApprovalDecision::Granted
        );

        let denied = deny_approval(
            Path(approval_id.clone()),
            State(state.clone()),
            Json(ApprovalDecisionRequest {
                security: security.clone(),
                reason: "deny unit".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect("approval denied")
        .0;
        assert_eq!(denied.status, "denied");

        let revoked = revoke_approval(
            Path(approval_id),
            State(state.clone()),
            Json(ApprovalDecisionRequest {
                security: security.clone(),
                reason: "revoke unit".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect("approval revoked")
        .0;
        assert_eq!(revoked.status, "revoked");
        assert!(revoked.evidence.expect("revoked evidence").revoked);

        let breaker = create_circuit_breaker(
            State(state.clone()),
            Json(CircuitBreakerRequest {
                security: security.clone(),
                breaker_id: "77777777-7777-4777-8777-777777777777".to_string(),
                tenant_id: Some(tenant_id.clone()),
                adapter: Some("artifact-store".to_string()),
                action: Some("artifact.publish_external".to_string()),
                reason: "unit breaker".to_string(),
            }),
        )
        .await
        .expect("breaker created")
        .0;
        assert_eq!(breaker.status, "tripped");

        let sync_payload = read_circuit_breaker_sync_payload(
            Path("77777777-7777-4777-8777-777777777777".to_string()),
            State(state.clone()),
            Json(CircuitBreakerSyncPayloadRequest {
                security: security.clone(),
                run_id: run_id.clone(),
                reason: "unit sync".to_string(),
            }),
        )
        .await
        .expect("breaker sync payload exported")
        .0;
        assert_eq!(
            sync_payload.breaker_record.trace_event_id,
            breaker.trace_event_id
        );
        assert_eq!(sync_payload.circuit_breakers.len(), 1);
        assert_eq!(
            sync_payload.circuit_breakers[0].breaker_id.to_string(),
            "77777777-7777-4777-8777-777777777777"
        );

        let cleared = clear_circuit_breaker(
            Path("77777777-7777-4777-8777-777777777777".to_string()),
            State(state.clone()),
            Json(ClearCircuitBreakerRequest {
                security: security.clone(),
                reason: "unit clear".to_string(),
            }),
        )
        .await
        .expect("breaker cleared")
        .0;
        assert_eq!(cleared.status, "cleared");

        let cleared_sync_payload = read_circuit_breaker_sync_payload(
            Path("77777777-7777-4777-8777-777777777777".to_string()),
            State(state.clone()),
            Json(CircuitBreakerSyncPayloadRequest {
                security: security.clone(),
                run_id: run_id.clone(),
                reason: "unit cleared sync".to_string(),
            }),
        )
        .await
        .expect_err("cleared breaker cannot be exported");
        assert_eq!(cleared_sync_payload.body.code, "breaker_not_tripped");

        let tenant_breaker = create_circuit_breaker(
            State(state.clone()),
            Json(CircuitBreakerRequest {
                security: security.clone(),
                breaker_id: "77777777-7777-4777-8777-777777777778".to_string(),
                tenant_id: Some(tenant_id.clone()),
                adapter: None,
                action: None,
                reason: "unit tenant breaker".to_string(),
            }),
        )
        .await
        .expect("tenant breaker created")
        .0;
        let tenant_payload = read_circuit_breaker_sync_payload(
            Path(tenant_breaker.breaker_id.clone()),
            State(state.clone()),
            Json(CircuitBreakerSyncPayloadRequest {
                security: security.clone(),
                run_id: run_id.clone(),
                reason: "unit tenant sync".to_string(),
            }),
        )
        .await
        .expect("tenant breaker sync payload exported")
        .0;
        assert_eq!(tenant_payload.circuit_breakers[0].scope.label(), "tenant");

        let global_breaker = create_circuit_breaker(
            State(state.clone()),
            Json(CircuitBreakerRequest {
                security: security.clone(),
                breaker_id: "77777777-7777-4777-8777-777777777779".to_string(),
                tenant_id: None,
                adapter: None,
                action: None,
                reason: "unit global breaker".to_string(),
            }),
        )
        .await
        .expect("global breaker created")
        .0;
        let global_payload = read_circuit_breaker_sync_payload(
            Path(global_breaker.breaker_id.clone()),
            State(state.clone()),
            Json(CircuitBreakerSyncPayloadRequest {
                security: security.clone(),
                run_id: run_id.clone(),
                reason: "unit global sync".to_string(),
            }),
        )
        .await
        .expect("global breaker sync payload exported")
        .0;
        assert_eq!(global_payload.circuit_breakers[0].scope.label(), "global");

        let invalid_id_breaker = create_circuit_breaker(
            State(state.clone()),
            Json(CircuitBreakerRequest {
                security: security.clone(),
                breaker_id: "breaker_s5_unit_invalid_id".to_string(),
                tenant_id: None,
                adapter: Some("artifact-store".to_string()),
                action: None,
                reason: "unit invalid id breaker".to_string(),
            }),
        )
        .await
        .expect("invalid id breaker stored")
        .0;
        let invalid_id_payload = read_circuit_breaker_sync_payload(
            Path(invalid_id_breaker.breaker_id),
            State(state.clone()),
            Json(CircuitBreakerSyncPayloadRequest {
                security: security.clone(),
                run_id: run_id.clone(),
                reason: "unit invalid id sync".to_string(),
            }),
        )
        .await
        .expect_err("invalid id breaker cannot become daemon sync payload");
        assert_eq!(invalid_id_payload.body.code, "invalid_breaker_id");

        let missing_breaker = clear_circuit_breaker(
            Path("breaker_missing".to_string()),
            State(state.clone()),
            Json(ClearCircuitBreakerRequest {
                security: security.clone(),
                reason: "unit missing clear".to_string(),
            }),
        )
        .await
        .expect_err("missing breaker rejected");
        assert_eq!(missing_breaker.body.code, "breaker_not_found");

        let kill = activate_kill_switch(
            State(state.clone()),
            Json(KillSwitchRequest {
                security: security.clone(),
                kill_switch_id: "kill_s5_unit".to_string(),
                run_id: Some(run_id.clone()),
                tenant_id: Some(tenant_id.clone()),
                node_id: None,
                instance_id: None,
                reason: "unit kill".to_string(),
                propagation_ack_required: true,
            }),
        )
        .await
        .expect("kill switch fail closed")
        .0;
        assert!(kill.fail_closed);
        assert!(!kill.propagation_acknowledged);

        let non_blocking_kill = activate_kill_switch(
            State(state.clone()),
            Json(KillSwitchRequest {
                security: security.clone(),
                kill_switch_id: "kill_s5_unit_nonblocking".to_string(),
                run_id: None,
                tenant_id: Some(tenant_id.clone()),
                node_id: None,
                instance_id: None,
                reason: "unit nonblocking kill".to_string(),
                propagation_ack_required: false,
            }),
        )
        .await
        .expect("nonblocking kill switch activates")
        .0;
        assert_eq!(non_blocking_kill.status, "activated");
        assert!(!non_blocking_kill.fail_closed);

        let target_node_id = "00000000-0000-4000-8000-000000000905";
        let target_instance_id = "00000000-0000-4000-8000-000000000906";
        let resident_url = spawn_resident_mock();
        let registered_node = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration: node(
                    &state.inner.fleet_id,
                    target_node_id,
                    &resident_url,
                    "resident_cloud_pool",
                    "cloud",
                    vec!["runtime.resident"],
                ),
            }),
        )
        .await
        .expect("kill target node registered")
        .0;
        let registered_instance = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance(target_node_id, target_instance_id, &tenant_id),
            }),
        )
        .await
        .expect("kill target instance registered")
        .0;
        let propagated_kill = activate_kill_switch(
            State(state.clone()),
            Json(KillSwitchRequest {
                security: security.clone(),
                kill_switch_id: "kill_s5_unit_propagated".to_string(),
                run_id: Some(run_id.clone()),
                tenant_id: Some(tenant_id.clone()),
                node_id: Some(registered_node.node_id.clone()),
                instance_id: Some(registered_instance.instance_id.clone()),
                reason: "unit propagated kill".to_string(),
                propagation_ack_required: true,
            }),
        )
        .await
        .expect("registry-derived kill switch propagates")
        .0;
        assert_eq!(propagated_kill.status, "activated");
        assert!(propagated_kill.propagation_acknowledged);
        assert!(!propagated_kill.fail_closed);
        assert_eq!(propagated_kill.cancel_status, Some(201));
        assert_eq!(
            propagated_kill.target_daemon_url.as_deref(),
            Some(resident_url.as_str())
        );
        assert_eq!(
            propagated_kill.target_instance_id,
            Some(registered_instance.instance_id.clone())
        );
        assert!(propagated_kill.target_derived_from_registry);
        assert_eq!(
            propagated_kill.cancel_payload_schema.as_deref(),
            Some("splendor.daemon.lifecycle_request.v1")
        );

        let target_mismatch = activate_kill_switch(
            State(state.clone()),
            Json(KillSwitchRequest {
                security: security.clone(),
                kill_switch_id: "kill_s5_unit_target_mismatch".to_string(),
                run_id: Some(run_id.clone()),
                tenant_id: Some(tenant_id.clone()),
                node_id: Some(
                    NodeId::parse("00000000-0000-4000-8000-000000000999").expect("mismatched node"),
                ),
                instance_id: Some(registered_instance.instance_id.clone()),
                reason: "unit mismatched kill target".to_string(),
                propagation_ack_required: true,
            }),
        )
        .await
        .expect_err("mismatched target is denied");
        assert_eq!(target_mismatch.body.code, "kill_switch_target_mismatch");

        let no_url_node: NodeRegistration = serde_json::from_value(serde_json::json!({
            "node_id": "00000000-0000-4000-8000-000000000907",
            "kind": "vpc.worker",
            "scope": {"fleet_id": state.inner.fleet_id, "tenant_id": null},
            "capability_document": {
                "schema": "splendor.capabilities.v1",
                "capabilities": ["runtime.resident"],
                "constraints": {"placement_target": "resident_cloud_pool", "data_locality": "cloud"}
            },
            "runtime_version": "0.1-test",
            "health": {"status": "healthy", "observed_at": now_rfc3339(), "metadata": {}},
            "registered_at": now_rfc3339()
        }))
        .expect("no-url node");
        let registered_no_url_node = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration: no_url_node,
            }),
        )
        .await
        .expect("no-url node registered")
        .0;
        let registered_no_url_instance = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance(
                    &registered_no_url_node.node_id.to_string(),
                    "00000000-0000-4000-8000-000000000908",
                    &tenant_id,
                ),
            }),
        )
        .await
        .expect("no-url instance registered")
        .0;
        let missing_url = activate_kill_switch(
            State(state.clone()),
            Json(KillSwitchRequest {
                security: security.clone(),
                kill_switch_id: "kill_s5_unit_missing_url".to_string(),
                run_id: Some(run_id.clone()),
                tenant_id: Some(tenant_id.clone()),
                node_id: Some(registered_no_url_node.node_id),
                instance_id: Some(registered_no_url_instance.instance_id),
                reason: "unit missing url target".to_string(),
                propagation_ack_required: true,
            }),
        )
        .await
        .expect_err("missing resident daemon url rejected");
        assert_eq!(missing_url.body.code, "missing_resident_daemon_url");

        let revoked_policy = revoke_policy_bundle(
            Path("policy_s5_unit".to_string()),
            State(state.clone()),
            Json(RevokePolicyBundleRequest {
                security: security.clone(),
                reason: "unit revoke".to_string(),
            }),
        )
        .await
        .expect("policy revoked")
        .0;
        assert_eq!(revoked_policy.status, "revoked");

        let revoked_status = get_policy_status(
            Path("policy_s5_unit".to_string()),
            State(state.clone()),
            Json(ManagerReadRequest {
                security: security.clone(),
                tenant_id: None,
                agent_id: None,
            }),
        )
        .await
        .expect("revoked policy read")
        .0;
        assert_eq!(revoked_status.status, "revoked");

        let missing_revoke = revoke_policy_bundle(
            Path("policy_missing".to_string()),
            State(state.clone()),
            Json(RevokePolicyBundleRequest {
                security: security.clone(),
                reason: "missing policy revoke".to_string(),
            }),
        )
        .await
        .expect_err("missing revoke rejected");
        assert_eq!(missing_revoke.body.code, "policy_not_found");

        let missing_approval = grant_approval(
            Path(ApprovalId::parse("77777777-7777-4777-8777-777777777777").expect("approval")),
            State(state.clone()),
            Json(ApprovalDecisionRequest {
                security: security.clone(),
                reason: "missing approval grant".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("missing approval rejected");
        assert_eq!(missing_approval.body.code, "approval_not_found");

        let audit = export_governance_audit(
            State(state.clone()),
            Json(GovernanceAuditExportRequest {
                security: security.clone(),
                run_id: Some(run_id),
            }),
        )
        .await
        .expect("audit exported")
        .0;
        assert!(audit.exported);
        assert!(audit
            .policy_bundle_ids
            .contains(&"policy_s5_unit".to_string()));
        assert!(audit
            .approval_ids
            .contains(&"66666666-6666-4666-8666-666666666666".to_string()));
        assert!(audit
            .circuit_breaker_ids
            .contains(&"77777777-7777-4777-8777-777777777777".to_string()));
        assert!(audit.kill_switch_ids.contains(&"kill_s5_unit".to_string()));

        let missing_scope = create_circuit_breaker(
            State(state.clone()),
            Json(CircuitBreakerRequest {
                security: manager_security(&state, vec![EndpointScope::FleetRead]),
                breaker_id: "breaker_denied".to_string(),
                tenant_id: Some(tenant_id),
                adapter: None,
                action: None,
                reason: "missing governance scope".to_string(),
            }),
        )
        .await
        .expect_err("missing governance scope rejected");
        assert_eq!(missing_scope.body.code, "missing_scope");

        let bad_url = post_json(
            "https://example.invalid",
            "/runs/x/cancel",
            &serde_json::json!({}),
        )
        .expect_err("non-local test post_json rejects unsupported URL schemes");
        assert!(bad_url.contains("only http://"));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind post_json mock");
        let addr = listener.local_addr().expect("mock addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept post_json request");
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .expect("set post_json read timeout");
            let mut request = Vec::new();
            let _ = stream.read_to_end(&mut request);
            let body = r#"{"cancelled":true}"#;
            write!(
                stream,
                "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("write post_json response");
        });
        let response = post_json(
            &format!("http://{addr}"),
            "/runs/unit/cancel",
            &serde_json::json!({"reason":"unit"}),
        )
        .expect("post_json success");
        assert_eq!(response.status, 202);
        assert!(response.body.expect("response body").contains("cancelled"));
        handle.join().expect("post_json mock joined");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind prefixed mock");
        let addr = listener.local_addr().expect("prefixed mock addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept prefixed request");
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .expect("set prefixed read timeout");
            let mut request = Vec::new();
            let _ = stream.read_to_end(&mut request);
            write!(
                stream,
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("write prefixed response");
        });
        let response = post_json(
            &format!("http://{addr}/daemon"),
            "/runs/unit/cancel",
            &serde_json::json!({"reason":"unit"}),
        )
        .expect("post_json prefixed success");
        assert_eq!(response.status, 204);
        assert!(response.body.is_none());
        handle.join().expect("prefixed mock joined");
    }

    #[test]
    fn resident_dispatch_payload_is_derived_from_signed_work_order_authority() {
        let target_agent = "33333333-3333-4333-8333-333333333333";
        let work_order = test_work_order(target_agent);
        let run_id = work_order.work_order.run_id.clone().expect("run id");
        let credential = serde_json::json!({"credential_id":"resident-test"});
        let audit = serde_json::json!({"credential_id":"resident-test"});
        let payload = resident_create_run_payload(&work_order, &run_id, credential, audit)
            .expect("payload derives from work order");

        assert_eq!(
            payload["allowed_actions"],
            serde_json::json!(work_order.work_order.allowed_actions)
        );
        assert_eq!(
            payload["allowed_adapters"],
            serde_json::json!(work_order.work_order.allowed_adapters)
        );
        assert_eq!(
            payload["allowed_permissions"],
            serde_json::json!(work_order.work_order.allowed_permissions)
        );
        assert!(payload["registered_actions"]
            .as_array()
            .expect("registered actions")
            .iter()
            .any(|entry| entry["name"] == "message.remote.proposal"));
        assert!(payload["policy_actions"]
            .as_array()
            .expect("policy actions")
            .iter()
            .all(|entry| work_order.work_order.allowed_actions.contains(
                &entry["action"]["name"]
                    .as_str()
                    .expect("action name")
                    .to_string()
            )));
    }

    #[test]
    fn resident_dispatch_payload_rejects_incomplete_internal_authority() {
        let mut work_order = test_work_order("33333333-3333-4333-8333-333333333333");
        work_order
            .work_order
            .allowed_permissions
            .retain(|permission| permission != "artifact.create_internal");
        let run_id = work_order.work_order.run_id.clone().expect("run id");
        let error = resident_create_run_payload(
            &work_order,
            &run_id,
            serde_json::json!({}),
            serde_json::json!({}),
        )
        .expect_err("incomplete authority rejected");
        assert_eq!(error.body.code, "work_order_authority_incomplete");

        let mut remote_incomplete = test_work_order("33333333-3333-4333-8333-333333333333");
        remote_incomplete
            .work_order
            .allowed_adapters
            .retain(|adapter| adapter != "remote-message");
        let run_id = remote_incomplete.work_order.run_id.clone().expect("run id");
        let error = resident_create_run_payload(
            &remote_incomplete,
            &run_id,
            serde_json::json!({}),
            serde_json::json!({}),
        )
        .expect_err("incomplete remote authority rejected");
        assert_eq!(error.body.code, "work_order_authority_incomplete");
    }

    #[test]
    fn remote_message_authority_validates_work_order_route_and_tenant_binding() {
        let target_agent = "33333333-3333-4333-8333-333333333333";
        let work_order = test_work_order(target_agent);
        let tenant_id = work_order.work_order.tenant_id.clone();
        let source = instance(
            "00000000-0000-4000-8000-000000000204",
            "00000000-0000-4000-8000-000000000302",
            &tenant_id,
        );
        let target = instance(
            "00000000-0000-4000-8000-000000000404",
            "00000000-0000-4000-8000-000000000304",
            &tenant_id,
        );
        let credential = credential(
            FleetId::parse("00000000-0000-4000-8000-000000000104").expect("fleet"),
            vec![EndpointScope::MessagesSend],
        );
        let request = send_request(
            credential.clone(),
            target_agent,
            work_order.work_order.run_id.clone().expect("run id"),
        );
        validate_remote_message_authority(&request, &work_order, &source, &target)
            .expect("valid route accepted");

        let unauthorized = send_request(
            credential.clone(),
            "22222222-2222-4222-8222-222222222222",
            work_order.work_order.run_id.clone().expect("run id"),
        );
        let error = validate_remote_message_authority(&unauthorized, &work_order, &source, &target)
            .expect_err("unauthorized target rejected");
        assert_eq!(error.body.code, "unauthorized_recipient");

        let wrong_run = send_request(
            credential,
            target_agent,
            RunId::parse("77777777-7777-4777-8777-777777777777").expect("wrong run"),
        );
        let error = validate_remote_message_authority(&wrong_run, &work_order, &source, &target)
            .expect_err("wrong run rejected");
        assert_eq!(error.body.code, "message_run_mismatch");

        let other_tenant = TenantId::parse("99999999-9999-4999-8999-999999999999").expect("tenant");
        let wrong_target = instance(
            "00000000-0000-4000-8000-000000000404",
            "00000000-0000-4000-8000-000000000304",
            &other_tenant,
        );
        let error =
            validate_remote_message_authority(&request, &work_order, &source, &wrong_target)
                .expect_err("target tenant mismatch rejected");
        assert_eq!(error.body.code, "message_tenant_not_hosted");

        let mut unbound = work_order.clone();
        unbound.work_order.run_id = None;
        let error = validate_remote_message_authority(&request, &unbound, &source, &target)
            .expect_err("unbound work-order run rejected");
        assert_eq!(error.body.code, "message_run_unbound");

        let mut source_mismatch = request.clone();
        source_mismatch.message_envelope.message.source_agent_id =
            AgentId::parse("99999999-9999-4999-8999-999999999999").expect("agent");
        let error =
            validate_remote_message_authority(&source_mismatch, &work_order, &source, &target)
                .expect_err("source agent mismatch rejected");
        assert_eq!(error.body.code, "message_source_agent_mismatch");

        let mut action_denied = work_order.clone();
        action_denied
            .work_order
            .allowed_actions
            .retain(|action| action != "message.remote.proposal");
        let error = validate_remote_message_authority(&request, &action_denied, &source, &target)
            .expect_err("missing message action rejected");
        assert_eq!(error.body.code, "message_action_not_allowed");

        let mut adapter_denied = work_order;
        adapter_denied
            .work_order
            .allowed_adapters
            .retain(|adapter| adapter != "remote-message");
        let error = validate_remote_message_authority(&request, &adapter_denied, &source, &target)
            .expect_err("missing message adapter rejected");
        assert_eq!(error.body.code, "message_adapter_not_allowed");
    }

    #[tokio::test]
    async fn message_public_api_handlers_fail_closed_and_preserve_payload() {
        let state = ManagerState::local_acceptance();
        let read_security = manager_security(&state, vec![EndpointScope::MessagesRead]);
        let send_security = manager_security(&state, vec![EndpointScope::MessagesSend]);
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let other_tenant = TenantId::parse("99999999-9999-4999-8999-999999999999").expect("tenant");
        let source_agent = AgentId::parse("22222222-2222-4222-8222-222222222222").expect("source");
        let target_agent = AgentId::parse("33333333-3333-4333-8333-333333333333").expect("target");
        let run_id = RunId::parse("44444444-4444-4444-8444-444444444444").expect("run");
        let message_id = MessageId::parse("55555555-5555-4555-8555-555555555554").expect("message");
        let response_message_id =
            MessageId::parse("55555555-5555-4555-8555-555555555555").expect("message");
        let delivery_trace_event_id = uuid::Uuid::new_v4().to_string();
        let response_trace_event_id = uuid::Uuid::new_v4().to_string();
        state.inner.messages.lock().expect("message lock").insert(
            message_id.to_string(),
            MessageStatusReport {
                message_id: message_id.clone(),
                work_order_id: "wo_message_public_api".to_string(),
                tenant_id: tenant_id.clone(),
                run_id: run_id.clone(),
                source_agent_id: source_agent.clone(),
                target_agent_id: target_agent.clone(),
                schema: "splendor.message.task_request.v1".to_string(),
                causal_parent: None,
                delivery_status: "delivered".to_string(),
                trace_event_id: delivery_trace_event_id.clone(),
                duplicate: false,
                idempotency_key: Some("message-public-api-once".to_string()),
                source_instance_id: "00000000-0000-4000-8000-000000000302".to_string(),
                target_instance_id: "00000000-0000-4000-8000-000000000304".to_string(),
                recipient_validated: true,
                receive_side_validated: true,
                work_order_authority_validated: true,
                route_permission: Some(format!("message.remote.proposal:{target_agent}")),
                remote_state_mutated: false,
                reason: None,
                read_trace_event_id: None,
                ack_trace_event_id: None,
                nack_trace_event_id: None,
                payload_preserved: true,
            },
        );
        state.inner.messages.lock().expect("message lock").insert(
            response_message_id.to_string(),
            MessageStatusReport {
                message_id: response_message_id.clone(),
                work_order_id: "wo_message_public_api".to_string(),
                tenant_id: tenant_id.clone(),
                run_id: run_id.clone(),
                source_agent_id: target_agent.clone(),
                target_agent_id: source_agent.clone(),
                schema: "splendor.message.task_response.v1".to_string(),
                causal_parent: Some(delivery_trace_event_id.clone()),
                delivery_status: "delivered".to_string(),
                trace_event_id: response_trace_event_id,
                duplicate: false,
                idempotency_key: Some("message-public-api-response-once".to_string()),
                source_instance_id: "00000000-0000-4000-8000-000000000304".to_string(),
                target_instance_id: "00000000-0000-4000-8000-000000000302".to_string(),
                recipient_validated: true,
                receive_side_validated: true,
                work_order_authority_validated: true,
                route_permission: Some(format!("message.remote.proposal:{source_agent}")),
                remote_state_mutated: false,
                reason: None,
                read_trace_event_id: None,
                ack_trace_event_id: None,
                nack_trace_event_id: None,
                payload_preserved: true,
            },
        );

        let schemas = list_message_schemas(
            State(state.clone()),
            Json(ManagerReadRequest {
                security: read_security.clone(),
                tenant_id: Some(tenant_id.clone()),
                agent_id: None,
            }),
        )
        .await
        .expect("schema list reads")
        .0;
        assert!(!schemas.delivery_authority_granted);
        assert!(schemas
            .schemas
            .iter()
            .any(|schema| schema.schema == "splendor.message.task_request.v1"));

        let envelope: MessageEnvelope = serde_json::from_value(serde_json::json!({
            "message": {
                "message_id": message_id,
                "source_agent_id": source_agent,
                "target_agent_id": target_agent,
                "run_id": run_id,
                "schema": "splendor.message.proposal_request.v1",
                "payload": {"task": "unit public message API"},
                "causal_parent": null,
                "requires_response": true,
                "created_at": now_rfc3339()
            },
            "schema_version": "v1",
            "delivery_status": "pending",
            "trace_links": {}
        }))
        .expect("message envelope parses");
        let validation = validate_message_schema(
            State(state.clone()),
            Json(MessageSchemaValidationRequest {
                security: read_security.clone(),
                message_envelope: Some(envelope),
                schema: None,
                payload: None,
            }),
        )
        .await
        .expect("supported schema validates")
        .0;
        assert!(validation.valid);
        assert!(!validation.delivery_authority_granted);

        let unsupported = validate_message_schema(
            State(state.clone()),
            Json(MessageSchemaValidationRequest {
                security: read_security.clone(),
                message_envelope: None,
                schema: Some("splendor.message.unsupported.v2".to_string()),
                payload: Some(serde_json::json!({"unsupported": true})),
            }),
        )
        .await
        .expect("unsupported schema reports validation failure")
        .0;
        assert!(!unsupported.valid);
        assert!(!unsupported.supported);

        let cross_tenant = get_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                Some(other_tenant.clone()),
                Some(run_id.clone()),
                Some(target_agent.clone()),
            )),
        )
        .await
        .expect_err("cross-tenant read denied");
        assert_eq!(cross_tenant.body.code, "cross_tenant_message_read_denied");

        let omitted_tenant = get_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                None,
                Some(run_id.clone()),
                Some(target_agent.clone()),
            )),
        )
        .await
        .expect_err("omitted tenant scope denied");
        assert_eq!(omitted_tenant.body.code, "missing_message_tenant_scope");

        let omitted_run = get_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                Some(tenant_id.clone()),
                None,
                Some(target_agent.clone()),
            )),
        )
        .await
        .expect_err("omitted run scope denied");
        assert_eq!(omitted_run.body.code, "missing_message_run_scope");

        let omitted_agent = get_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                Some(tenant_id.clone()),
                Some(run_id.clone()),
                None,
            )),
        )
        .await
        .expect_err("omitted agent scope denied");
        assert_eq!(omitted_agent.body.code, "missing_message_agent_scope");

        let unrelated_agent =
            AgentId::parse("99999999-9999-4999-8999-999999999999").expect("agent");
        let unrelated_read = get_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                Some(tenant_id.clone()),
                Some(run_id.clone()),
                Some(unrelated_agent.clone()),
            )),
        )
        .await
        .expect_err("unrelated agent read denied");
        assert_eq!(unrelated_read.body.code, "message_agent_scope_denied");

        let wrong_run = get_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                Some(tenant_id.clone()),
                Some(RunId::parse("77777777-7777-4777-8777-777777777777").expect("run")),
                Some(target_agent.clone()),
            )),
        )
        .await
        .expect_err("wrong run read denied");
        assert_eq!(wrong_run.body.code, "message_run_scope_denied");

        let missing_send_scope = ack_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(message_update_request(
                read_security.clone(),
                Some(tenant_id.clone()),
                Some(run_id.clone()),
                Some(target_agent.clone()),
                "missing send scope",
            )),
        )
        .await
        .expect_err("ack requires messages_send scope");
        assert_eq!(missing_send_scope.body.code, "missing_scope");

        let ack_missing_tenant = ack_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(message_update_request(
                send_security.clone(),
                None,
                Some(run_id.clone()),
                Some(target_agent.clone()),
                "missing tenant scope",
            )),
        )
        .await
        .expect_err("ack requires tenant scope");
        assert_eq!(ack_missing_tenant.body.code, "missing_message_tenant_scope");

        let ack_missing_run = ack_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(message_update_request(
                send_security.clone(),
                Some(tenant_id.clone()),
                None,
                Some(target_agent.clone()),
                "missing run scope",
            )),
        )
        .await
        .expect_err("ack requires run scope");
        assert_eq!(ack_missing_run.body.code, "missing_message_run_scope");

        let ack_source_agent = ack_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(message_update_request(
                send_security.clone(),
                Some(tenant_id.clone()),
                Some(run_id.clone()),
                Some(source_agent.clone()),
                "source cannot consume its own outbound message",
            )),
        )
        .await
        .expect_err("source agent cannot ack target message");
        assert_eq!(
            ack_source_agent.body.code,
            "message_ack_agent_not_recipient"
        );

        let nack_unrelated_agent = nack_message(
            Path(response_message_id.clone()),
            State(state.clone()),
            Json(message_update_request(
                send_security.clone(),
                Some(tenant_id.clone()),
                Some(run_id.clone()),
                Some(unrelated_agent),
                "unrelated agent cannot fail delivery",
            )),
        )
        .await
        .expect_err("unrelated agent cannot nack target message");
        assert_eq!(nack_unrelated_agent.body.code, "message_agent_scope_denied");

        let payload_mutation = nack_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(MessageDeliveryUpdateRequest {
                security: send_security.clone(),
                tenant_id: Some(tenant_id.clone()),
                run_id: Some(run_id.clone()),
                agent_id: Some(target_agent.clone()),
                reason: Some("payload mutation attempt".to_string()),
                payload: Some(serde_json::json!({"mutated": true})),
                payload_patch: None,
            }),
        )
        .await
        .expect_err("nack cannot mutate payload");
        assert_eq!(
            payload_mutation.body.code,
            "message_payload_mutation_forbidden"
        );

        let before_ack = state
            .inner
            .messages
            .lock()
            .expect("message lock")
            .get(&message_id.to_string())
            .cloned()
            .expect("message exists");

        let acked = ack_message(
            Path(message_id.clone()),
            State(state.clone()),
            Json(message_update_request(
                send_security.clone(),
                Some(tenant_id.clone()),
                Some(run_id.clone()),
                Some(target_agent.clone()),
                "target consumed message",
            )),
        )
        .await
        .expect("ack records delivery status only")
        .0;
        assert_eq!(acked.delivery_status, "consumed");
        assert!(acked.payload_preserved);
        assert!(acked.ack_trace_event_id.is_some());
        assert_message_authority_preserved(&before_ack, &acked);

        let before_nack = state
            .inner
            .messages
            .lock()
            .expect("message lock")
            .get(&response_message_id.to_string())
            .cloned()
            .expect("response message exists");
        let nacked = nack_message(
            Path(response_message_id.clone()),
            State(state.clone()),
            Json(message_update_request(
                send_security.clone(),
                Some(tenant_id.clone()),
                Some(run_id.clone()),
                Some(source_agent.clone()),
                "orchestrator records response failure metadata",
            )),
        )
        .await
        .expect("nack records delivery status only")
        .0;
        assert_eq!(nacked.delivery_status, "failed");
        assert!(nacked.payload_preserved);
        assert!(nacked.nack_trace_event_id.is_some());
        assert_message_authority_preserved(&before_nack, &nacked);

        let inbox = list_inbox(
            Path(target_agent.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                Some(tenant_id.clone()),
                Some(run_id.clone()),
                Some(target_agent.clone()),
            )),
        )
        .await
        .expect("inbox read")
        .0;
        assert_eq!(inbox.messages.len(), 1);
        let outbox = list_outbox(
            Path(source_agent.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                Some(tenant_id.clone()),
                Some(run_id.clone()),
                Some(source_agent.clone()),
            )),
        )
        .await
        .expect("outbox read")
        .0;
        assert_eq!(outbox.messages.len(), 1);
        let agent_mismatch = list_inbox(
            Path(target_agent.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                Some(tenant_id.clone()),
                Some(run_id.clone()),
                Some(source_agent.clone()),
            )),
        )
        .await
        .expect_err("path/request agent mismatch denied");
        assert_eq!(agent_mismatch.body.code, "message_agent_scope_denied");

        let cross_tenant_list = list_inbox(
            Path(target_agent.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                Some(other_tenant.clone()),
                Some(run_id.clone()),
                Some(target_agent.clone()),
            )),
        )
        .await
        .expect_err("cross-tenant list denied");
        assert_eq!(
            cross_tenant_list.body.code,
            "cross_tenant_message_read_denied"
        );

        let graph_cross_tenant = get_message_causal_graph(
            Path(run_id.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                Some(other_tenant),
                Some(run_id.clone()),
                Some(source_agent.clone()),
            )),
        )
        .await
        .expect_err("cross-tenant graph denied");
        assert_eq!(
            graph_cross_tenant.body.code,
            "cross_tenant_message_read_denied"
        );

        let graph_unrelated_agent = get_message_causal_graph(
            Path(run_id.clone()),
            State(state.clone()),
            Json(message_read_request(
                read_security.clone(),
                Some(tenant_id.clone()),
                Some(run_id.clone()),
                Some(AgentId::parse("88888888-8888-4888-8888-888888888888").expect("agent")),
            )),
        )
        .await
        .expect_err("unrelated graph denied");
        assert_eq!(
            graph_unrelated_agent.body.code,
            "message_agent_scope_denied"
        );

        let graph = get_message_causal_graph(
            Path(run_id),
            State(state),
            Json(message_read_request(
                read_security,
                Some(tenant_id),
                Some(RunId::parse("44444444-4444-4444-8444-444444444444").expect("run")),
                Some(source_agent),
            )),
        )
        .await
        .expect("causal graph reads")
        .0;
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].from_message_id.as_ref(), Some(&message_id));
    }

    #[tokio::test]
    async fn manager_handlers_enforce_s4_security_authority_and_audit_paths() {
        let state = ManagerState::local_acceptance();
        let all_scopes = vec![
            EndpointScope::NodesRegister,
            EndpointScope::InstancesRegister,
            EndpointScope::NodesHeartbeat,
            EndpointScope::FleetRead,
            EndpointScope::FleetDispatch,
            EndpointScope::WorkOrdersSubmit,
            EndpointScope::WorkOrdersRevoke,
            EndpointScope::TracesRead,
            EndpointScope::MessagesSend,
            EndpointScope::MessagesRead,
        ];
        let security = manager_security(&state, all_scopes);
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let resident_url = spawn_resident_mock();
        let vpc_node = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000204",
            &resident_url,
            "customer_vpc",
            "vpc",
            vec![
                "sql.read_fixture",
                "artifact.create_internal",
                "message.remote.proposal",
                "runtime.resident",
            ],
        );
        let cloud_node = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000404",
            "http://127.0.0.1:1",
            "resident_cloud_pool",
            "cloud",
            vec!["message.remote.proposal", "runtime.resident"],
        );
        let _ = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration: vpc_node.clone(),
            }),
        )
        .await
        .expect("vpc node registered");
        let _ = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration: cloud_node.clone(),
            }),
        )
        .await
        .expect("cloud node registered");
        let _ = list_nodes(
            State(state.clone()),
            Json(ManagerReadRequest {
                security: security.clone(),
                tenant_id: None,
                agent_id: None,
            }),
        )
        .await
        .expect("authenticated node read");
        let _ = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance(
                    "00000000-0000-4000-8000-000000000204",
                    "00000000-0000-4000-8000-000000000302",
                    &tenant_id,
                ),
            }),
        )
        .await
        .expect("vpc instance registered");
        let _ = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance(
                    "00000000-0000-4000-8000-000000000404",
                    "00000000-0000-4000-8000-000000000304",
                    &tenant_id,
                ),
            }),
        )
        .await
        .expect("cloud instance registered");
        let _ = heartbeat_node(
            Path(vpc_node.node_id.clone()),
            State(state.clone()),
            Json(HeartbeatNodeRequest {
                security: security.clone(),
                heartbeat: NodeHeartbeat {
                    node_id: vpc_node.node_id.clone(),
                    health: vpc_node.health.clone(),
                    recorded_at: OffsetDateTime::now_utc(),
                },
            }),
        )
        .await
        .expect("heartbeat accepted");
        let _ = advertise_capabilities(
            Path(vpc_node.node_id.clone()),
            State(state.clone()),
            Json(AdvertiseCapabilitiesRequest {
                security: security.clone(),
                capability_document: vpc_node.capability_document.clone(),
            }),
        )
        .await
        .expect("capabilities accepted");

        let work_order = test_work_order("33333333-3333-4333-8333-333333333333");
        let _ = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security: security.clone(),
                work_order: work_order.clone(),
                expected_audience: "central-manager".to_string(),
            }),
        )
        .await
        .expect("work order accepted");
        let placement_request = PlacementRequest {
            target: PlacementTarget::CustomerVpc,
            required_capabilities: vec![
                "sql.read_fixture".to_string(),
                "artifact.create_internal".to_string(),
                "message.remote.proposal".to_string(),
            ],
            data_locality: Some(DataLocality::Vpc),
            dedicated_instance: false,
            required_runtime_version: None,
            max_runtime_ms: Some(30_000),
            execution_mode: PlacementExecutionMode::Live,
        };
        let _ = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some("wo_test_remote".to_string()),
                request: placement_request,
            }),
        )
        .await
        .expect("placement evaluated");
        let dispatch = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: Some(vpc_node.node_id.clone()),
            }),
        )
        .await
        .expect("dispatch accepted");
        assert_eq!(dispatch.0.create_run_status, 201);
        assert_eq!(dispatch.0.start_run_status, 201);

        let credential = security.credential.clone();
        let run_id = work_order.work_order.run_id.clone().expect("run id");
        let request = send_request(credential, "33333333-3333-4333-8333-333333333333", run_id);
        let delivered = send_message(State(state.clone()), Json(request.clone()))
            .await
            .expect("message delivered");
        assert!(delivered.0.work_order_authority_validated);
        let mut missing_idempotency = request.clone();
        missing_idempotency.idempotency_key = None;
        let error = send_message(State(state.clone()), Json(missing_idempotency))
            .await
            .expect_err("missing idempotency rejected");
        assert_eq!(error.body.code, "missing_idempotency_key");

        let mut missing_work_order = request.clone();
        missing_work_order.work_order_id = "wo_missing".to_string();
        missing_work_order.idempotency_key = Some("missing-work-order".to_string());
        let error = send_message(State(state.clone()), Json(missing_work_order))
            .await
            .expect_err("missing work order rejected");
        assert_eq!(error.body.code, "work_order_not_found");

        let mut failed_delivery = request.clone();
        failed_delivery.message_envelope.message.message_id =
            MessageId::parse("55555555-5555-4555-8555-555555555557").expect("message id");
        failed_delivery.idempotency_key = Some("failed-delivery".to_string());
        failed_delivery.simulate_failure = Some("receiver_offline".to_string());
        let failed = send_message(State(state.clone()), Json(failed_delivery))
            .await
            .expect("simulated failure recorded");
        assert_eq!(failed.0.delivery_status, "failed");
        assert_eq!(failed.0.reason.as_deref(), Some("receiver_offline"));
        let duplicate = send_message(
            State(state.clone()),
            Json(SendMessageRequest {
                message_envelope: MessageEnvelope {
                    message: splendor_types::Message {
                        message_id: MessageId::parse("55555555-5555-4555-8555-555555555556")
                            .expect("message id"),
                        ..request.message_envelope.message.clone()
                    },
                    ..request.message_envelope.clone()
                },
                ..request.clone()
            }),
        )
        .await
        .expect("duplicate detected");
        assert!(duplicate.0.duplicate);
        let read = get_message(
            Path(delivered.0.message_id.clone()),
            State(state.clone()),
            Json(message_read_request(
                security.clone(),
                Some(work_order.work_order.tenant_id.clone()),
                work_order.work_order.run_id.clone(),
                Some(work_order.work_order.agent_id.clone()),
            )),
        )
        .await
        .expect("message read");
        assert!(read.0.receive_side_validated);
        let mut unsupported = request.clone();
        unsupported.message_envelope.message.schema = "splendor.message.unsupported.v1".to_string();
        let error = send_message(State(state.clone()), Json(unsupported))
            .await
            .expect_err("unsupported schema rejected");
        assert_eq!(error.body.code, "unsupported_message_schema");
        let mut unauthorized = request;
        unauthorized.message_envelope.message.target_agent_id =
            work_order.work_order.agent_id.clone();
        unauthorized.idempotency_key = Some("unauthorized-route".to_string());
        let error = send_message(State(state.clone()), Json(unauthorized))
            .await
            .expect_err("unauthorized route rejected");
        assert_eq!(error.body.code, "unauthorized_recipient");

        let telemetry = get_fleet_telemetry(
            State(state.clone()),
            Json(ManagerReadRequest {
                security: security.clone(),
                tenant_id: None,
                agent_id: None,
            }),
        )
        .await
        .expect("telemetry read");
        assert_eq!(telemetry.0.authority, TelemetryAuthority::ObservationalOnly);
        let audit = audit_events(
            State(state.clone()),
            Json(ManagerReadRequest {
                security,
                tenant_id: None,
                agent_id: None,
            }),
        )
        .await
        .expect("audit read");
        assert!(audit
            .0
            .iter()
            .any(|event| event.event_type == "remote_message.rejected"));
    }

    #[tokio::test]
    async fn manager_handlers_fail_closed_for_invalid_s4_authority() {
        let state = ManagerState::local_acceptance();
        let security = manager_security(
            &state,
            vec![
                EndpointScope::NodesRegister,
                EndpointScope::InstancesRegister,
                EndpointScope::NodesHeartbeat,
                EndpointScope::FleetRead,
                EndpointScope::FleetDispatch,
                EndpointScope::WorkOrdersSubmit,
                EndpointScope::WorkOrdersRevoke,
                EndpointScope::MessagesRead,
            ],
        );
        let missing_audit = ManagerSecurityFields {
            credential: security.credential.clone(),
            audit_attribution: AuditAttribution {
                principal: ClientPrincipal::new("other_app", "other_client"),
                credential_id: Some("other".to_string()),
                requested_at: OffsetDateTime::now_utc(),
            },
        };
        let error = list_nodes(
            State(state.clone()),
            Json(ManagerReadRequest {
                security: missing_audit,
                tenant_id: None,
                agent_id: None,
            }),
        )
        .await
        .expect_err("mismatched audit rejected");
        assert_eq!(error.body.code, "attribution_mismatch");

        let bad_heartbeat = heartbeat_node(
            Path(NodeId::parse("00000000-0000-4000-8000-000000000204").expect("node")),
            State(state.clone()),
            Json(HeartbeatNodeRequest {
                security: security.clone(),
                heartbeat: NodeHeartbeat {
                    node_id: NodeId::parse("00000000-0000-4000-8000-000000000404")
                        .expect("node"),
                    health: serde_json::from_value(serde_json::json!({"status":"healthy","observed_at":now_rfc3339(),"metadata":{}})).expect("health"),
                    recorded_at: OffsetDateTime::now_utc(),
                },
            }),
        )
        .await
        .expect_err("mismatched heartbeat rejected");
        assert_eq!(bad_heartbeat.body.code, "node_id_mismatch");

        let wrong_audience = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security: security.clone(),
                work_order: test_work_order("33333333-3333-4333-8333-333333333333"),
                expected_audience: "wrong-manager".to_string(),
            }),
        )
        .await
        .expect_err("wrong audience rejected");
        assert_eq!(wrong_audience.body.code, "wrong_audience");

        let unsigned = {
            let mut envelope = test_work_order("33333333-3333-4333-8333-333333333333");
            envelope.signature = None;
            submit_work_order(
                State(state.clone()),
                Json(SubmitWorkOrderRequest {
                    security: security.clone(),
                    work_order: envelope,
                    expected_audience: "central-manager".to_string(),
                }),
            )
            .await
            .expect_err("unsigned rejected")
        };
        assert_eq!(unsigned.body.code, "unsigned_work_order");

        let rejected_placement = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some("rejected-placement".to_string()),
                request: PlacementRequest {
                    target: PlacementTarget::CustomerVpc,
                    required_capabilities: vec!["missing.capability".to_string()],
                    data_locality: Some(DataLocality::Vpc),
                    dedicated_instance: true,
                    required_runtime_version: Some("99.0".to_string()),
                    max_runtime_ms: Some(1),
                    execution_mode: PlacementExecutionMode::Live,
                },
            }),
        )
        .await
        .expect("rejected placement returned decision");
        assert_eq!(
            rejected_placement.0.status,
            PlacementDecisionStatus::Rejected
        );

        let missing_work_order_dispatch = dispatch_work_order(
            Path("missing-work-order".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("missing work order rejected");
        assert_eq!(
            missing_work_order_dispatch.body.code,
            "work_order_not_found"
        );

        let work_order = test_work_order("33333333-3333-4333-8333-333333333333");
        let _ = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security: security.clone(),
                work_order,
                expected_audience: "central-manager".to_string(),
            }),
        )
        .await
        .expect("work order accepted");
        let no_placement = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("dispatch without placement rejected");
        assert_eq!(no_placement.body.code, "placement_required");

        let _ = revoke_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(RevokeWorkOrderRequest {
                security: security.clone(),
                reason: "test".to_string(),
            }),
        )
        .await
        .expect("revoked");
        let revoked = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("revoked dispatch rejected");
        assert_eq!(revoked.body.code, "revoked_work_order");

        let missing_message = get_message(
            Path(MessageId::parse("55555555-5555-4555-8555-555555555554").expect("message")),
            State(state),
            Json(message_read_request(
                security,
                Some(TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant")),
                Some(RunId::parse("44444444-4444-4444-8444-444444444444").expect("run")),
                Some(AgentId::parse("22222222-2222-4222-8222-222222222222").expect("agent")),
            )),
        )
        .await
        .expect_err("missing message rejected");
        assert_eq!(missing_message.body.code, "message_not_found");

        assert!(post_json("https://example.test", "/runs", &serde_json::json!({})).is_err());
        assert!(post_json("http://127.0.0.1:1", "/runs", &serde_json::json!({})).is_err());
    }

    #[tokio::test]
    async fn manager_router_syncs_trace_batches_and_reports_telemetry() {
        let state = ManagerState::local_acceptance();
        let app = router(state.clone());
        let (status, health): (StatusCode, serde_json::Value) =
            manager_call(app.clone(), Method::GET, "/health", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(health["component"], "splendor-manager");

        let security = manager_security(
            &state,
            vec![EndpointScope::TracesRead, EndpointScope::FleetRead],
        );
        let run_id = RunId::parse("44444444-4444-4444-8444-444444444444").expect("run");
        let node_id = NodeId::parse("00000000-0000-4000-8000-000000000204").expect("node");
        let instance_id =
            InstanceId::parse("00000000-0000-4000-8000-000000000302").expect("instance");
        let local = InMemoryTraceStore::default();
        local
            .append(
                &run_id.to_string(),
                serde_json::json!({"event":"tick.started"}),
            )
            .expect("first trace");
        local
            .append(
                &run_id.to_string(),
                serde_json::json!({"event":"tick.completed"}),
            )
            .expect("second trace");
        let mut scope = TraceSyncScope::new(run_id.to_string());
        scope.fleet_id = Some(state.inner.fleet_id.to_string());
        scope.node_id = Some(node_id.to_string());
        scope.instance_id = Some(instance_id.to_string());
        let batch = TraceSyncBatch::from_store(scope, &local, 0, 2).expect("trace batch");

        let (status, report): (StatusCode, TraceSyncReport) = manager_call(
            app.clone(),
            Method::POST,
            "/fleet/traces/sync",
            Some(
                serde_json::to_value(SyncTraceBufferRequest {
                    security: security.clone(),
                    batch: batch.clone(),
                })
                .expect("sync request"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(report.accepted_records, 2);
        assert_eq!(report.latest_sequence, Some(1));

        let (status, duplicate): (StatusCode, TraceSyncReport) = manager_call(
            app.clone(),
            Method::POST,
            "/fleet/traces/sync",
            Some(
                serde_json::to_value(SyncTraceBufferRequest {
                    security: security.clone(),
                    batch,
                })
                .expect("duplicate sync request"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(duplicate.duplicate_records, 2);

        let (status, telemetry): (StatusCode, FleetTelemetrySnapshot) = manager_call(
            app.clone(),
            Method::POST,
            "/fleet/telemetry/read",
            Some(
                serde_json::to_value(ManagerReadRequest {
                    security: security.clone(),
                    tenant_id: None,
                    agent_id: None,
                })
                .expect("telemetry request"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let sync = telemetry.trace_sync.first().expect("trace sync telemetry");
        assert_eq!(sync.node_id, node_id);
        assert_eq!(sync.instance_id, instance_id);
        assert_eq!(sync.last_synced_sequence, Some(1));

        let empty = TraceSyncBatch {
            scope: TraceSyncScope::new(run_id.to_string()),
            records: Vec::new(),
            offline_interval: None,
            sync_boundary: None,
        };
        let (status, error): (StatusCode, ManagerApiErrorBody) = manager_call(
            app,
            Method::POST,
            "/fleet/traces/sync",
            Some(
                serde_json::to_value(SyncTraceBufferRequest {
                    security,
                    batch: empty,
                })
                .expect("empty sync request"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(error.code, "trace_sync_rejected");
    }

    #[tokio::test]
    async fn manager_dispatch_denials_cover_placement_and_node_boundaries() {
        let state = ManagerState::local_acceptance();
        let security = manager_security(
            &state,
            vec![
                EndpointScope::NodesRegister,
                EndpointScope::InstancesRegister,
                EndpointScope::FleetRead,
                EndpointScope::FleetDispatch,
                EndpointScope::WorkOrdersSubmit,
            ],
        );
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let vpc_node = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000204",
            "http://127.0.0.1:1",
            "customer_vpc",
            "vpc",
            vec![
                "sql.read_fixture",
                "artifact.create_internal",
                "message.remote.proposal",
            ],
        );
        let cloud_node = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000404",
            "http://127.0.0.1:1",
            "resident_cloud_pool",
            "cloud",
            vec!["message.remote.proposal"],
        );
        let edge_node = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000504",
            "http://127.0.0.1:1",
            "edge_device",
            "device",
            vec!["message.remote.proposal"],
        );
        let on_prem_node = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000604",
            "http://127.0.0.1:1",
            "unknown_target_defaults_to_cloud_pool",
            "on_prem",
            vec!["message.remote.proposal"],
        );
        for registration in [
            vpc_node.clone(),
            cloud_node.clone(),
            edge_node.clone(),
            on_prem_node.clone(),
        ] {
            let _ = register_node(
                State(state.clone()),
                Json(RegisterNodeRequest {
                    security: security.clone(),
                    registration,
                }),
            )
            .await
            .expect("node registered");
        }

        let candidates = placement_candidates(&state).expect("placement candidates");
        assert!(candidates.iter().any(|candidate| {
            candidate.candidate_id == edge_node.node_id.to_string()
                && candidate.target == PlacementTarget::EdgeDevice
                && candidate.data_locality == Some(DataLocality::Device)
        }));
        assert!(candidates.iter().any(|candidate| {
            candidate.candidate_id == on_prem_node.node_id.to_string()
                && candidate.target == PlacementTarget::ResidentCloudPool
                && candidate.data_locality == Some(DataLocality::OnPrem)
        }));

        let work_order = test_work_order("33333333-3333-4333-8333-333333333333");
        let _ = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security: security.clone(),
                work_order,
                expected_audience: "central-manager".to_string(),
            }),
        )
        .await
        .expect("work order submitted");

        let rejected = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some("wo_test_remote".to_string()),
                request: PlacementRequest {
                    target: PlacementTarget::CustomerVpc,
                    required_capabilities: vec!["capability.not.present".to_string()],
                    data_locality: Some(DataLocality::Vpc),
                    dedicated_instance: false,
                    required_runtime_version: None,
                    max_runtime_ms: Some(30_000),
                    execution_mode: PlacementExecutionMode::Live,
                },
            }),
        )
        .await
        .expect("rejected placement decision");
        assert_eq!(rejected.0.status, PlacementDecisionStatus::Rejected);
        let error = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("rejected placement cannot dispatch");
        assert_eq!(error.body.code, "placement_rejected");

        let selected = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some("wo_test_remote".to_string()),
                request: PlacementRequest {
                    target: PlacementTarget::CustomerVpc,
                    required_capabilities: vec!["sql.read_fixture".to_string()],
                    data_locality: Some(DataLocality::Vpc),
                    dedicated_instance: false,
                    required_runtime_version: None,
                    max_runtime_ms: Some(30_000),
                    execution_mode: PlacementExecutionMode::Live,
                },
            }),
        )
        .await
        .expect("selected placement decision");
        assert_eq!(selected.0.status, PlacementDecisionStatus::Selected);

        let mismatch = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: Some(cloud_node.node_id.clone()),
            }),
        )
        .await
        .expect_err("target mismatch rejected");
        assert_eq!(mismatch.body.code, "dispatch_target_mismatch");

        let no_instance = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("node without instance rejected");
        assert_eq!(no_instance.body.code, "node_has_no_instance");

        let mut invalid_candidate = selected.0.clone();
        invalid_candidate.candidate_id = Some("not-a-node-id".to_string());
        state
            .inner
            .placements
            .lock()
            .expect("placement lock")
            .insert("wo_test_remote".to_string(), invalid_candidate.clone());
        let missing_target = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("invalid placement candidate cannot infer target");
        assert_eq!(missing_target.body.code, "missing_target_node");

        let missing_candidate = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: Some(vpc_node.node_id.clone()),
            }),
        )
        .await
        .expect_err("invalid placement candidate rejected");
        assert_eq!(missing_candidate.body.code, "placement_candidate_missing");

        state
            .inner
            .placements
            .lock()
            .expect("placement lock")
            .insert("wo_test_remote".to_string(), selected.0.clone());

        let _ = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance(
                    &vpc_node.node_id.to_string(),
                    "00000000-0000-4000-8000-000000000302",
                    &tenant_id,
                ),
            }),
        )
        .await
        .expect("instance registered");

        let no_url_node: NodeRegistration = serde_json::from_value(serde_json::json!({
            "node_id": "00000000-0000-4000-8000-000000000704",
            "kind": "vpc.worker",
            "scope": {"fleet_id": state.inner.fleet_id, "tenant_id": null},
            "capability_document": {
                "schema": "splendor.capabilities.v1",
                "capabilities": ["sql.read_fixture"],
                "constraints": {"placement_target": "customer_vpc", "data_locality": "vpc"}
            },
            "runtime_version": "0.1-test",
            "health": {"status": "healthy", "observed_at": now_rfc3339(), "metadata": {}},
            "registered_at": now_rfc3339()
        }))
        .expect("no url node");
        let _ = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration: no_url_node.clone(),
            }),
        )
        .await
        .expect("no url node registered");
        let _ = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance(
                    &no_url_node.node_id.to_string(),
                    "00000000-0000-4000-8000-000000000704",
                    &tenant_id,
                ),
            }),
        )
        .await
        .expect("no url instance registered");
        let mut no_url_placement = selected.0.clone();
        no_url_placement.candidate_id = Some(no_url_node.node_id.to_string());
        state
            .inner
            .placements
            .lock()
            .expect("placement lock")
            .insert("wo_test_remote".to_string(), no_url_placement);
        let missing_url = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("missing resident url rejected");
        assert_eq!(missing_url.body.code, "missing_resident_daemon_url");

        let offline_node: NodeRegistration = serde_json::from_value(serde_json::json!({
            "node_id": "00000000-0000-4000-8000-000000000804",
            "kind": "vpc.worker",
            "scope": {"fleet_id": state.inner.fleet_id, "tenant_id": null},
            "capability_document": {
                "schema": "splendor.capabilities.v1",
                "capabilities": ["sql.read_fixture"],
                "constraints": {"placement_target": "customer_vpc", "data_locality": "vpc", "resident_daemon_url": "http://127.0.0.1:1"}
            },
            "runtime_version": "0.1-test",
            "health": {"status": "offline", "observed_at": now_rfc3339(), "metadata": {}},
            "registered_at": now_rfc3339()
        }))
        .expect("offline node");
        let _ = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration: offline_node.clone(),
            }),
        )
        .await
        .expect("offline node registered");
        let _ = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance(
                    &offline_node.node_id.to_string(),
                    "00000000-0000-4000-8000-000000000804",
                    &tenant_id,
                ),
            }),
        )
        .await
        .expect("offline instance registered");
        let mut offline_placement = selected.0.clone();
        offline_placement.candidate_id = Some(offline_node.node_id.to_string());
        state
            .inner
            .placements
            .lock()
            .expect("placement lock")
            .insert("wo_test_remote".to_string(), offline_placement);
        let stale = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("offline node rejected");
        assert_eq!(stale.body.code, "stale_or_unhealthy_node");

        state
            .inner
            .placements
            .lock()
            .expect("placement lock")
            .insert("wo_test_remote".to_string(), selected.0);

        state
            .inner
            .work_orders
            .lock()
            .expect("work order lock")
            .get_mut("wo_test_remote")
            .expect("work order")
            .work_order
            .objective = "tampered after signature".to_string();
        let bad_signature = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("tampered dispatch work order rejected");
        assert_eq!(bad_signature.body.code, "bad_signature");

        let refreshed = test_work_order("33333333-3333-4333-8333-333333333333");
        state
            .inner
            .work_orders
            .lock()
            .expect("work order lock")
            .insert("wo_test_remote".to_string(), refreshed);
        let resident_http = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state),
            Json(DispatchWorkOrderRequest {
                security,
                target_node_id: None,
            }),
        )
        .await
        .expect_err("unavailable resident daemon rejected");
        assert_eq!(resident_http.body.code, "resident_http_error");
    }
}
