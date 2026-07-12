//! Local runtime daemon API for Splendor 0.02-S5.
//!
//! This crate exposes the smallest local daemon boundary needed for run control,
//! percept ingestion, trace/state inspection, replay, health, capabilities, and
//! gateway-mediated action submission. It is intentionally local/foundation-only:
//! no fleet registry, remote scheduler, or production auth provider is included.

pub mod manager;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use splendor_gateway::{
    ActionAdapter, ActionGateway, ActionId, ActionOutcome, ActionRequest, ActionStatus,
    AdapterError, AdapterResult, CircuitBreakerEvaluator, PolicyApprovalVerifier,
    ResourceBoundaryVerifier, SimulatedRiskLevel, SimulatedSafetySnapshot, SimulatedSafetyVerifier,
    StaticCircuitBreakerEvaluator, VerifiedActionGateway,
};
use splendor_kernel::{
    Action, ActionCandidate, AgentContext, AgentIsolationPolicy, AgentRuntimeConfig, LoopEngine,
    LoopError, Percept, Perceptor, Policy, PolicyCache, PolicyCacheConfig, PolicyCacheInstallError,
    PolicyCacheMutationError, PolicyCacheMutationRecorder, PolicyCacheOwner, PolicyCacheTraceError,
    PolicyDecision, PolicyDistributionGateway, QuotaPolicy, RunId, RunTraceContext, Scheduler,
    SchedulerConfig, SchedulerError, SnapshotPolicy, StateGraph, TenantContext, TenantPolicy,
    TenantRegistry, TraceEventKind,
};
use splendor_store::{
    InMemoryStateStore, InMemoryTraceStore, StateData, StateNodeId, StateStore, TraceRecord,
    TraceStore, TraceStoreError,
};
use splendor_types::{
    is_allowed_physical_action, validate_policy_bundle, validate_policy_bundle_candidate,
    AppPrincipal, ApprovalEvidence, ApprovalPolicy, ApprovalTraceContext, AuditAttribution,
    CallerCredential, CircuitBreaker, ClientPrincipal, CredentialAudience, CredentialBinding,
    DaemonEndpoint, DaemonSecurityDecision, DaemonSecurityError, DaemonSecurityRequest,
    EndpointScope, GatewayVerificationState, InsecureDevMode, LocalTransportBinding, NodeId,
    PerceptProvenance, PolicyBundleEnvelope, PolicyBundleKeyring, PolicyBundleTraceContext,
    PolicyBundleValidationContext, PolicyBundleValidationError, RevocationStatus, TenantId,
    TraceEvent, TraceEventId, TraceId, WorkOrder, WorkOrderAuthorization, WorkOrderEnvelope,
    WorkOrderKeyring, WorkOrderValidationContext, WorkOrderValidationError,
    FORBIDDEN_PHYSICAL_ACTION_PATTERNS,
};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Local daemon state shared by the HTTP router.
#[derive(Clone)]
pub struct DaemonState {
    inner: Arc<DaemonInner>,
}

struct DaemonInner {
    runs: Mutex<HashMap<RunId, RunSlot>>,
    create_run_idempotency: Mutex<HashMap<String, CreateRunIdempotencyEntry>>,
    expected_audience: CredentialAudience,
    insecure_dev_mode: Option<InsecureDevMode>,
    policy_bundle_keyring: PolicyBundleKeyring,
    work_order_keyring: WorkOrderKeyring,
    trace_store_override: Option<Arc<dyn TraceStore>>,
    runtime_available: AtomicBool,
    device_profiles: Mutex<HashMap<NodeId, DeviceRuntimeProfile>>,
    operator_interventions: Mutex<HashMap<String, OperatorInterventionRecord>>,
    device_audit: Mutex<Vec<DeviceAuditEvent>>,
}

#[derive(Clone, Debug)]
struct CreateRunIdempotencyEntry {
    scope: CreateRunIdempotencyScope,
    response: CreateRunResponse,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
struct CreateRunIdempotencyScope {
    tenant_id: TenantId,
    agent_id: splendor_types::AgentId,
    work_order_id: splendor_types::WorkOrderId,
    resolved_run_id: RunId,
    caller: serde_json::Value,
    request_fingerprint: String,
}

impl DaemonState {
    /// Builds an explicit local-development daemon state.
    ///
    /// The returned state uses loopback-only insecure development mode and is
    /// suitable for integration tests and local examples. Production callers must
    /// provide credentials through `DaemonSecurityRequest`; this crate does not
    /// implement an OAuth/OIDC/PKI server.
    pub fn local_dev() -> Self {
        Self::new(DaemonConfig::local_dev())
    }

    /// Builds daemon state from a config.
    pub fn new(config: DaemonConfig) -> Self {
        Self::new_with_trace_store(config, None)
    }

    /// Builds daemon state with an explicit trace store used by newly created
    /// runs. This supports durable-store composition and deterministic fault
    /// injection without changing daemon wire contracts.
    pub fn with_trace_store(config: DaemonConfig, trace_store: Arc<dyn TraceStore>) -> Self {
        Self::new_with_trace_store(config, Some(trace_store))
    }

    fn new_with_trace_store(
        config: DaemonConfig,
        trace_store_override: Option<Arc<dyn TraceStore>>,
    ) -> Self {
        Self {
            inner: Arc::new(DaemonInner {
                runs: Mutex::new(HashMap::new()),
                create_run_idempotency: Mutex::new(HashMap::new()),
                expected_audience: config.expected_audience,
                insecure_dev_mode: config.insecure_dev_mode,
                policy_bundle_keyring: config.policy_bundle_keyring,
                work_order_keyring: config.work_order_keyring,
                trace_store_override,
                runtime_available: AtomicBool::new(true),
                device_profiles: Mutex::new(HashMap::new()),
                operator_interventions: Mutex::new(HashMap::new()),
                device_audit: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Toggles runtime availability for fail-closed tests and health reporting.
    pub fn set_runtime_available(&self, available: bool) {
        self.inner
            .runtime_available
            .store(available, Ordering::SeqCst);
    }

    fn ensure_runtime_available(&self) -> Result<(), ApiError> {
        if self.inner.runtime_available.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "runtime_unavailable",
                "local runtime is unavailable",
            ))
        }
    }

    fn validate_security(
        &self,
        endpoint: DaemonEndpoint,
        credential: Option<CallerCredential>,
        work_order: Option<WorkOrderAuthorization>,
        audit_attribution: Option<AuditAttribution>,
    ) -> Result<DaemonSecurityDecision, ApiError> {
        let request = DaemonSecurityRequest {
            endpoint,
            credential,
            expected_audience: self.inner.expected_audience.clone(),
            work_order,
            audit_attribution,
            insecure_dev_mode: self.inner.insecure_dev_mode.clone(),
        };
        splendor_types::validate_daemon_request(&request, OffsetDateTime::now_utc())
            .map_err(ApiError::from)
    }
}

/// Daemon construction options.
#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// Expected audience binding for caller credentials.
    pub expected_audience: CredentialAudience,
    /// Explicit local-only insecure development mode, if enabled.
    pub insecure_dev_mode: Option<InsecureDevMode>,
    /// Verification keys for centrally distributed policy bundles.
    pub policy_bundle_keyring: PolicyBundleKeyring,
    /// Verification keys for signed work orders accepted by this daemon.
    pub work_order_keyring: WorkOrderKeyring,
}

impl DaemonConfig {
    /// Local loopback development configuration with an explicit warning marker.
    pub fn local_dev() -> Self {
        let mut policy_bundle_keyring = PolicyBundleKeyring::new();
        policy_bundle_keyring
            .insert_shared_secret("policy-local-key", b"splendor-local-policy-secret")
            .expect("local policy keyring");
        let mut work_order_keyring = WorkOrderKeyring::new();
        work_order_keyring
            .insert_shared_secret("work-order-local-key", b"splendor-local-work-order-secret")
            .expect("local work-order keyring");
        Self {
            expected_audience: CredentialAudience::Daemon {
                daemon_id: "daemon_local".to_string(),
            },
            insecure_dev_mode: Some(InsecureDevMode {
                enabled: true,
                transport: LocalTransportBinding::Tcp {
                    host: "127.0.0.1".to_string(),
                    port: 8077,
                },
                warning_issued: true,
            }),
            policy_bundle_keyring,
            work_order_keyring,
        }
    }

    /// Authenticated resident daemon configuration for acceptance/fleet tests.
    pub fn resident(instance_id: splendor_types::InstanceId) -> Self {
        let mut config = Self::local_dev();
        config.expected_audience = CredentialAudience::Instance { instance_id };
        config.insecure_dev_mode = None;
        config
    }
}

/// Builds the local daemon HTTP router.
pub fn router(state: DaemonState) -> Router {
    Router::new()
        .route("/runs", post(create_run))
        .route("/runs/:run_id", get(inspect_run))
        .route("/runs/:run_id/start", post(start_run))
        .route("/runs/:run_id/pause", post(pause_run))
        .route("/runs/:run_id/resume", post(resume_run))
        .route("/runs/:run_id/stop", post(stop_run))
        .route("/runs/:run_id/cancel", post(cancel_run))
        .route("/runs/:run_id/percepts", post(append_percept))
        .route("/runs/:run_id/policies/sync", post(sync_policy))
        .route(
            "/runs/:run_id/governance/circuit-breakers/sync",
            post(sync_circuit_breakers),
        )
        .route("/runs/:run_id/state-head", get(state_head))
        .route("/state-snapshots/export", post(export_state_snapshot))
        .route("/state-snapshots/import", post(import_state_snapshot))
        .route("/runs/:run_id/traces", get(traces))
        .route("/runs/:run_id/traces/export", post(export_traces))
        .route("/runs/:run_id/replay", post(replay_run))
        .route("/actions", post(submit_action))
        .route("/devices/profiles", post(register_device_profile))
        .route("/devices/:node_id/status", get(get_device_status))
        .route(
            "/devices/:node_id/policy-cache",
            get(get_policy_cache_status),
        )
        .route("/devices/:node_id/actions", post(submit_physical_action))
        .route(
            "/operator/interventions",
            post(request_operator_intervention),
        )
        .route(
            "/operator/interventions/:intervention_id/grant",
            post(grant_operator_intervention),
        )
        .route(
            "/operator/interventions/:intervention_id/deny",
            post(deny_operator_intervention),
        )
        .route(
            "/devices/:node_id/trace-buffer/sync",
            post(sync_device_trace_buffer),
        )
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/capabilities", get(capabilities))
        .with_state(state)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Pending,
    Running,
    Paused,
    WaitingForApproval,
    Interrupted,
    Resuming,
    Completed,
    Failed,
    Cancelled,
    Denied,
    Expired,
}

struct RunSlot {
    run_id: RunId,
    tenant_id: TenantId,
    agent_id: splendor_types::AgentId,
    status: RunStatus,
    scheduler: Scheduler,
    state_store: Arc<dyn StateStore>,
    trace_store: Arc<dyn TraceStore>,
    gateway: Arc<dyn ActionGateway>,
    tenant_registry: TenantRegistry,
    circuit_breakers: SharedCircuitBreakerEvaluator,
    policy_cache: PolicyCache,
    percept_queue: PerceptQueue,
    allowed_percept_schemas: Vec<String>,
    allowed_percept_sources: Vec<String>,
    allowed_actions: Vec<String>,
    state_head: Option<StateNodeId>,
    adapter_executions: Arc<AtomicU64>,
    approval_evidence: ApprovalEvidenceSlot,
    pending_approval: Option<ApprovalTraceContext>,
    tick_count: u64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

struct RunPolicyCacheMutationRecorder<'a> {
    slot: &'a RunSlot,
}

impl PolicyCacheMutationRecorder for RunPolicyCacheMutationRecorder<'_> {
    fn record_policy_cache_event(
        &self,
        event: TraceEventKind,
    ) -> Result<(), PolicyCacheTraceError> {
        record_run_event(self.slot, event).map_err(|_| PolicyCacheTraceError)
    }
}

#[derive(Clone, Default)]
struct SharedCircuitBreakerEvaluator {
    breakers: Arc<Mutex<Vec<CircuitBreaker>>>,
}

impl SharedCircuitBreakerEvaluator {
    fn new(breakers: Vec<CircuitBreaker>) -> Self {
        Self {
            breakers: Arc::new(Mutex::new(breakers)),
        }
    }

    fn set(&self, breakers: Vec<CircuitBreaker>) -> Result<(), ApiError> {
        *self.breakers.lock().map_err(|_| lock_error())? = breakers;
        Ok(())
    }
}

impl CircuitBreakerEvaluator for SharedCircuitBreakerEvaluator {
    fn verify_action(
        &self,
        action: &ActionRequest,
        adapter: Option<&str>,
        runtime_identity: &splendor_types::RuntimeIdentityContext,
    ) -> splendor_types::VerificationResult {
        let Ok(breakers) = self.breakers.lock() else {
            return splendor_types::VerificationResult {
                allowed: false,
                reasons: vec!["circuit_breaker_state_unavailable".to_string()],
                artifacts: serde_json::json!({"source":"circuit_breaker","reason":"state_lock_unavailable"}),
            };
        };
        StaticCircuitBreakerEvaluator::new(breakers.clone()).verify_action(
            action,
            adapter,
            runtime_identity,
        )
    }

    fn verify_runtime_admission(
        &self,
        runtime_identity: &splendor_types::RuntimeIdentityContext,
    ) -> splendor_types::VerificationResult {
        let Ok(breakers) = self.breakers.lock() else {
            return splendor_types::VerificationResult {
                allowed: false,
                reasons: vec!["circuit_breaker_state_unavailable".to_string()],
                artifacts: serde_json::json!({"source":"circuit_breaker","reason":"state_lock_unavailable"}),
            };
        };
        StaticCircuitBreakerEvaluator::new(breakers.clone())
            .verify_runtime_admission(runtime_identity)
    }
}

#[derive(Clone, Default)]
struct ApprovalEvidenceSlot {
    inner: Arc<Mutex<Option<ApprovalEvidence>>>,
}

impl ApprovalEvidenceSlot {
    fn set(&self, evidence: ApprovalEvidence) -> Result<(), LoopError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| LoopError::Policy("approval evidence slot poisoned".to_string()))?;
        *guard = Some(evidence);
        Ok(())
    }

    fn take(&self) -> Result<Option<ApprovalEvidence>, LoopError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| LoopError::Policy("approval evidence slot poisoned".to_string()))?;
        Ok(guard.take())
    }
}

#[derive(Clone, Default)]
struct PerceptQueue {
    inner: Arc<Mutex<VecDeque<Percept>>>,
}

impl PerceptQueue {
    fn push(&self, percept: Percept) -> Result<(), LoopError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| LoopError::Perceptor("percept queue poisoned".to_string()))?;
        guard.push_back(percept);
        Ok(())
    }

    fn drain(&self) -> Result<Vec<Percept>, LoopError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| LoopError::Perceptor("percept queue poisoned".to_string()))?;
        Ok(guard.drain(..).collect())
    }
}

struct QueuedPerceptor {
    queue: PerceptQueue,
}

impl Perceptor for QueuedPerceptor {
    fn collect(&self, _agent: &AgentContext) -> Result<Vec<Percept>, LoopError> {
        self.queue.drain()
    }
}

struct StaticDaemonPolicy {
    actions: Vec<ActionCandidate>,
    approval_evidence: ApprovalEvidenceSlot,
}

impl Policy for StaticDaemonPolicy {
    fn name(&self) -> &str {
        "daemon.static.v1"
    }

    fn decide(&self, state: &StateData, percepts: &[Percept]) -> Result<PolicyDecision, LoopError> {
        let payload = serde_json::json!({
            "policy": self.name(),
            "percepts": percepts,
            "previous_state_bytes": state.bytes.len(),
        });
        let bytes =
            serde_json::to_vec(&payload).map_err(|error| LoopError::Policy(error.to_string()))?;
        let approval_evidence = self.approval_evidence.take()?;
        let actions = self
            .actions
            .clone()
            .into_iter()
            .map(|candidate| match approval_evidence.clone() {
                Some(evidence) => candidate.with_approval_evidence(evidence),
                None => candidate,
            })
            .collect();
        Ok(PolicyDecision::new(
            actions,
            StateData {
                bytes,
                content_type: Some("application/json".to_string()),
            },
            Some("daemon_tick".to_string()),
        ))
    }
}

#[derive(Default)]
struct RecordingAdapter {
    executions: Arc<AtomicU64>,
}

impl ActionAdapter for RecordingAdapter {
    fn execute(&self, action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        // Deterministic local recording-adapter failure hook for daemon tests and
        // examples. Real adapters must implement their own failure semantics
        // behind the same gateway-mediated boundary.
        if action
            .action
            .params
            .get("fail_adapter")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Err(AdapterError::Failed(
                "requested adapter failure".to_string(),
            ));
        }
        let execution = self.executions.fetch_add(1, Ordering::SeqCst) + 1;
        let simulator = submit_device_sim_action(action, execution)?;
        let output = if action.action.name == "data.read_fixture" {
            let data_ref = action
                .action
                .params
                .get("data_ref")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            serde_json::json!({
                "adapter": "fixture-data-store",
                "execution": execution,
                "action": action.action.name,
                "data_ref": data_ref,
                "raw_payload_included": false,
                "analysis_summary": "trace-safe aggregate analysis for scoped data ref",
                "integrity": stable_json_hash(&serde_json::json!({"tenant_id": action.tenant_id, "data_ref": data_ref, "fixture": "uc-e2e-s7"})),
            })
        } else if action.action.name == "artifact.create_internal" {
            let path = action
                .action
                .params
                .get("artifact_path")
                .or_else(|| action.action.params.get("artifact_ref"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("artifact://unknown");
            serde_json::json!({
                "adapter": "artifact-store",
                "execution": execution,
                "action": action.action.name,
                "artifact_path": path,
                "tenant_id": action.tenant_id,
                "raw_payload_included": false,
                "integrity": stable_json_hash(&serde_json::json!({"tenant_id": action.tenant_id, "artifact_path": path, "kind": "internal"})),
            })
        } else if action.action.name == "artifact.publish_external" {
            serde_json::json!({
                "adapter": "artifact-store",
                "execution": execution,
                "action": action.action.name,
                "published": true,
                "external_store": "fake-artifact-store",
                "raw_payload_included": false,
                "integrity": stable_json_hash(&serde_json::json!({"tenant_id": action.tenant_id, "action": action.action.name, "kind": "external_publish"})),
            })
        } else {
            serde_json::json!({
                "adapter": "daemon.recording",
                "execution": execution,
                "action": action.action.name,
                "device_sim": simulator,
            })
        };
        Ok(AdapterResult {
            output,
            satisfied_postconditions: action.action.postconditions.clone(),
        })
    }
}

#[derive(Clone, Debug)]
struct DataArtifactBoundaryVerifier {
    tenant_id: TenantId,
    allowed_data_refs: Vec<String>,
}

impl DataArtifactBoundaryVerifier {
    fn new(tenant_id: TenantId, allowed_data_refs: Vec<String>) -> Self {
        Self {
            tenant_id: tenant_id.clone(),
            allowed_data_refs,
        }
    }

    fn requested_data_refs(action: &ActionRequest) -> Vec<String> {
        let mut refs = Vec::new();
        if let Some(value) = action
            .action
            .params
            .get("data_ref")
            .and_then(serde_json::Value::as_str)
        {
            refs.push(value.to_string());
        }
        if let Some(values) = action
            .action
            .params
            .get("data_refs")
            .and_then(serde_json::Value::as_array)
        {
            refs.extend(
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(ToString::to_string),
            );
        }
        refs
    }
}

impl ResourceBoundaryVerifier for DataArtifactBoundaryVerifier {
    fn verify_resource_boundary(
        &self,
        action: &ActionRequest,
        _adapter: Option<&str>,
    ) -> splendor_types::VerificationResult {
        let requested_refs = Self::requested_data_refs(action);
        for data_ref in &requested_refs {
            if !self
                .allowed_data_refs
                .iter()
                .any(|allowed| allowed == data_ref)
            {
                return splendor_types::VerificationResult {
                    allowed: false,
                    reasons: vec!["data_scope_denied".to_string()],
                    artifacts: serde_json::json!({
                        "source": "data_scope_verifier",
                        "reason_code": "data_scope_denied",
                        "requested_data_ref": data_ref,
                        "allowed_data_refs": self.allowed_data_refs,
                    }),
                };
            }
        }

        if action.action.name.starts_with("artifact.") {
            let tenant_id = self.tenant_id.to_string();
            for field in ["artifact_path", "artifact_ref", "publish_ref"] {
                if let Some(path) = action
                    .action
                    .params
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                {
                    if path.starts_with("artifact://")
                        && !path.starts_with(&format!("artifact://{tenant_id}/"))
                    {
                        return splendor_types::VerificationResult {
                            allowed: false,
                            reasons: vec!["artifact_path_tenant_mismatch".to_string()],
                            artifacts: serde_json::json!({
                                "source": "artifact_scope_verifier",
                                "reason_code": "artifact_path_tenant_mismatch",
                                "field": field,
                                "artifact_path": path,
                                "tenant_id": tenant_id,
                            }),
                        };
                    }
                }
            }
        }

        splendor_types::VerificationResult {
            allowed: true,
            reasons: vec!["data_scope_verified".to_string()],
            artifacts: serde_json::json!({
                "source": "data_scope_verifier",
                "reason_code": "data_scope_verified",
                "data_refs": requested_refs,
            }),
        }
    }
}

fn submit_device_sim_action(
    action: &ActionRequest,
    execution: u64,
) -> Result<Option<serde_json::Value>, AdapterError> {
    let Ok(base_url) = std::env::var("SPLENDOR_DEVICE_SIM_URL") else {
        return Ok(None);
    };
    submit_device_sim_action_to(&base_url, action, execution)
}

fn submit_device_sim_action_to(
    base_url: &str,
    action: &ActionRequest,
    execution: u64,
) -> Result<Option<serde_json::Value>, AdapterError> {
    let (host, port) = parse_http_host_port(base_url)?;
    let body = serde_json::json!({
        "action_id": action.action_id,
        "action_name": action.action.name,
        "tenant_id": action.tenant_id,
        "agent_id": action.agent_id,
        "run_id": action.run_id,
        "adapter_execution": execution,
        "params": action.action.params,
    });
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|error| AdapterError::Failed(format!("device_sim_payload_error:{error}")))?;
    let mut stream = TcpStream::connect((host.as_str(), port))
        .map_err(|error| AdapterError::Failed(format!("device_sim_connect_error:{error}")))?;
    let request = format!(
        "POST /actions HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(&body_bytes))
        .map_err(|error| AdapterError::Failed(format!("device_sim_write_error:{error}")))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| AdapterError::Failed(format!("device_sim_read_error:{error}")))?;
    let status_line = response.lines().next().unwrap_or_default();
    if !status_line.contains(" 200 ") {
        return Err(AdapterError::Failed(format!(
            "device_sim_status_error:{status_line}"
        )));
    }
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| AdapterError::Failed("device_sim_missing_body".to_string()))?;
    let parsed = serde_json::from_str(body)
        .map_err(|error| AdapterError::Failed(format!("device_sim_response_error:{error}")))?;
    Ok(Some(parsed))
}

fn parse_http_host_port(base_url: &str) -> Result<(String, u16), AdapterError> {
    let rest = base_url
        .strip_prefix("http://")
        .ok_or_else(|| AdapterError::Failed("device_sim_url_must_be_http".to_string()))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| AdapterError::Failed("device_sim_url_missing_port".to_string()))?;
    if host.trim().is_empty() {
        return Err(AdapterError::Failed(
            "device_sim_url_missing_host".to_string(),
        ));
    }
    let port = port
        .parse::<u16>()
        .map_err(|error| AdapterError::Failed(format!("device_sim_url_bad_port:{error}")))?;
    Ok((host.to_string(), port))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SecurityFields {
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CreateRunRequest {
    pub request_id: String,
    pub idempotency_key: String,
    pub tenant_id: TenantId,
    pub agent_id: splendor_types::AgentId,
    pub work_order: WorkOrderEnvelope,
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    #[serde(default)]
    pub allowed_adapters: Vec<String>,
    #[serde(default)]
    pub allowed_permissions: Vec<String>,
    #[serde(default)]
    pub policy_actions: Vec<DaemonActionCandidate>,
    #[serde(default)]
    pub policy_bundle_required: bool,
    #[serde(default)]
    pub policy_bundle: Option<PolicyBundleEnvelope>,
    #[serde(default)]
    pub registered_actions: Vec<RegisteredAction>,
    #[serde(default)]
    pub approval_policies: Vec<ApprovalPolicy>,
    #[serde(default)]
    pub circuit_breakers: Vec<CircuitBreaker>,
    #[serde(default)]
    pub allowed_percept_schemas: Vec<String>,
    #[serde(default)]
    pub allowed_percept_sources: Vec<String>,
    pub initial_state: Option<serde_json::Value>,
    pub snapshot_interval: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DaemonActionCandidate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ActionId>,
    pub action: Action,
    pub adapter: Option<String>,
    pub quota_usage: Option<splendor_types::QuotaUsage>,
    #[serde(default)]
    pub satisfied_preconditions: Vec<String>,
}

impl DaemonActionCandidate {
    fn into_candidate(self) -> ActionCandidate {
        let mut candidate = ActionCandidate::new(self.action);
        if let Some(adapter) = self.adapter {
            candidate = candidate.with_adapter(adapter);
        }
        if let Some(usage) = self.quota_usage {
            candidate = candidate.with_usage(usage);
        }
        if !self.satisfied_preconditions.is_empty() {
            candidate = candidate.with_satisfied_preconditions(self.satisfied_preconditions);
        }
        if let Some(action_id) = self.action_id {
            candidate = candidate.with_action_id(action_id);
        }
        candidate
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CircuitBreakerSyncRequest {
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    #[serde(default)]
    pub circuit_breakers: Vec<CircuitBreaker>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CircuitBreakerSyncResponse {
    pub run_id: RunId,
    pub accepted: bool,
    pub breaker_ids: Vec<String>,
    pub trace_event_id: TraceEventId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RegisteredAction {
    pub name: String,
    pub adapter: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CreateRunResponse {
    pub request_id: String,
    pub idempotency_key: String,
    pub idempotency_receipt_id: String,
    pub duplicate: bool,
    pub run_id: RunId,
    pub status: RunStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LifecycleRequest {
    pub credential: Option<CallerCredential>,
    pub work_order: Option<WorkOrderEnvelope>,
    pub audit_attribution: Option<AuditAttribution>,
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_evidence: Option<ApprovalEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RunInspectResponse {
    pub run_id: RunId,
    pub tenant_id: TenantId,
    pub agent_id: splendor_types::AgentId,
    pub status: RunStatus,
    pub state_head: Option<String>,
    pub ticks: u64,
    pub adapter_executions: u64,
    pub policy_bundle: Option<PolicyBundleTraceContext>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TickResponse {
    pub run_id: RunId,
    pub status: RunStatus,
    pub tick_id: u64,
    pub state_node_id: String,
    pub action_outcomes: Vec<ActionOutcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AppendPerceptRequest {
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    pub percept: Option<Percept>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AppendPerceptResponse {
    pub run_id: RunId,
    pub accepted: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicySyncRequest {
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    #[serde(default)]
    pub policy_bundle: Option<PolicyBundleEnvelope>,
    pub sync_error: Option<String>,
    pub disconnected: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicyCacheStatusResponse {
    pub enforcement_required: bool,
    pub disconnected: bool,
    pub policy_bundle: Option<PolicyBundleTraceContext>,
    pub revoked_reason: Option<String>,
    pub last_sync_failure: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicySyncResponse {
    pub run_id: RunId,
    pub accepted: bool,
    pub policy_bundle: Option<PolicyBundleTraceContext>,
    pub cache_status: PolicyCacheStatusResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StateHeadResponse {
    pub run_id: RunId,
    pub state_node_id: String,
    pub parent_state_node_ids: Vec<String>,
    pub data_hash: String,
    pub created_at: OffsetDateTime,
    pub label: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StateSnapshotExportRequest {
    pub run_id: RunId,
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    pub work_order_id: String,
    pub source_instance_id: Option<String>,
    pub receiver_instance_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StateSnapshotExportResponse {
    pub run_id: RunId,
    pub state_node_id: String,
    pub trace_event_id: TraceId,
    pub handoff: splendor_types::StateHandoff,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StateSnapshotImportRequest {
    pub handoff: splendor_types::StateHandoff,
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StateSnapshotImportResponse {
    pub run_id: RunId,
    pub state_node_id: String,
    pub trace_event_id: TraceId,
    pub accepted: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TraceQuery {
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub redaction_policy: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TracePageResponse {
    pub run_id: RunId,
    pub records: Vec<TraceRecord>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TraceExportRequest {
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    pub redaction_policy: Option<String>,
    pub start: Option<u64>,
    pub end: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TraceExportResponse {
    pub run_id: RunId,
    pub records: Vec<TraceRecord>,
    pub record_count: usize,
    pub redaction_policy: String,
    pub integrity_hash: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReplayRequest {
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    #[serde(default = "default_replay_mode")]
    pub mode: String,
    #[serde(default)]
    pub side_effects_allowed: bool,
}

fn default_replay_mode() -> String {
    "inspect_only".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReplayResponse {
    pub replay_id: String,
    pub run_id: RunId,
    pub mode: String,
    pub event_count: usize,
    pub action_event_count: usize,
    pub approval_events: Vec<ApprovalReplayEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApprovalReplayEvent {
    pub lifecycle: String,
    pub approval: ApprovalTraceContext,
    pub reason: Option<String>,
    pub trace_event_id: TraceId,
    pub sequence: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SubmitActionRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ActionId>,
    pub run_id: RunId,
    pub tenant_id: TenantId,
    pub agent_id: splendor_types::AgentId,
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    pub causal_trace_id: Option<TraceId>,
    pub action: Action,
    pub adapter: Option<String>,
    pub quota_usage: Option<splendor_types::QuotaUsage>,
    #[serde(default)]
    pub satisfied_preconditions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_evidence: Option<ApprovalEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceRuntimeProfile {
    pub node_id: NodeId,
    pub tenant_id: TenantId,
    pub device_kind: String,
    pub capabilities: Vec<String>,
    pub allowed_physical_actions: Vec<String>,
    pub forbidden_action_classes: Vec<String>,
    pub safety_constraints: serde_json::Value,
    pub runtime_mode: String,
    pub safety_status: serde_json::Value,
    pub policy_cache: DevicePolicyCacheStatus,
    pub trace_buffer: DeviceTraceBufferStatus,
    pub registered_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DevicePolicyCacheStatus {
    pub policy_id: String,
    pub loaded: bool,
    pub ttl_seconds: u64,
    pub expires_at: String,
    pub expired: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceTraceBufferStatus {
    pub enabled: bool,
    pub buffered_records: usize,
    pub integrity: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RegisterDeviceProfileRequest {
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    pub profile: DeviceRuntimeProfile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RegisterDeviceProfileResponse {
    pub profile: DeviceRuntimeProfile,
    pub trace_event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SafetyContext {
    #[serde(default)]
    pub allowed_zone_refs: Vec<String>,
    pub zone_ref: Option<String>,
    pub altitude_m: Option<f64>,
    pub max_altitude_m: Option<f64>,
    pub battery_percent: Option<f64>,
    #[serde(default)]
    pub privacy_clear: bool,
    #[serde(default)]
    pub human_proximity_clear: bool,
    #[serde(default)]
    pub emergency_stop_clear: bool,
    #[serde(default)]
    pub offline: bool,
    #[serde(default)]
    pub policy_cache_expired: bool,
    #[serde(default)]
    pub high_risk: bool,
    #[serde(default)]
    pub cloud_helper_direct_authority: bool,
    pub cloud_helper_proposal_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SubmitPhysicalActionRequest {
    #[serde(flatten)]
    pub action_request: SubmitActionRequest,
    pub safety_context: SafetyContext,
    pub operator_intervention_evidence: Option<OperatorInterventionEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OperatorInterventionEvidence {
    pub intervention_id: String,
    pub tenant_id: TenantId,
    pub run_id: RunId,
    pub action_name: String,
    pub decision: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OperatorInterventionRequest {
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    pub intervention_id: String,
    pub tenant_id: TenantId,
    pub agent_id: splendor_types::AgentId,
    pub run_id: RunId,
    pub node_id: NodeId,
    pub action_name: String,
    pub reason: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OperatorDecisionRequest {
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    pub reason: String,
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OperatorInterventionRecord {
    pub intervention_id: String,
    pub tenant_id: TenantId,
    pub agent_id: splendor_types::AgentId,
    pub run_id: RunId,
    pub node_id: NodeId,
    pub action_name: String,
    pub status: String,
    pub reason: String,
    pub expires_at: String,
    pub trace_event_id: String,
    pub evidence: Option<OperatorInterventionEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceTraceBufferSyncRequest {
    pub credential: Option<CallerCredential>,
    pub audit_attribution: Option<AuditAttribution>,
    pub run_id: RunId,
    pub records: Vec<TraceRecord>,
    #[serde(default)]
    pub simulate_tamper: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceTraceBufferSyncResponse {
    pub accepted: bool,
    pub accepted_records: usize,
    pub trace_event_id: String,
    pub reason_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceAuditEvent {
    pub trace_event_id: String,
    pub event_type: String,
    pub audit: AuditAttribution,
    pub details: serde_json::Value,
    pub timestamp: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HealthResponse {
    pub status: String,
    pub local_only: bool,
    pub runtime_available: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VersionResponse {
    pub daemon_api_version: String,
    pub compatibility_line: String,
    pub openapi_version: String,
    pub local_only: bool,
    pub schema_versions: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CapabilitiesResponse {
    pub daemon_api_version: String,
    pub local_only: bool,
    pub replay_modes: Vec<String>,
    pub endpoints: Vec<String>,
    pub service_profiles: Vec<ServiceCapabilityProfile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServiceCapabilityProfile {
    pub name: String,
    pub status: String,
    pub maturity: String,
    pub endpoints: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
    pub details: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct ApiError {
    status: StatusCode,
    body: ApiErrorBody,
}

impl ApiError {
    fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            body: ApiErrorBody {
                code: code.into(),
                message: message.into(),
                details: serde_json::Value::Null,
            },
        }
    }

    fn details(mut self, details: serde_json::Value) -> Self {
        self.body.details = details;
        self
    }
}

impl From<DaemonSecurityError> for ApiError {
    fn from(error: DaemonSecurityError) -> Self {
        let status = match error {
            DaemonSecurityError::AnonymousNonDevCall => StatusCode::UNAUTHORIZED,
            _ => StatusCode::FORBIDDEN,
        };
        ApiError::new(status, daemon_security_code(&error), error.to_string())
    }
}

impl From<SchedulerError> for ApiError {
    fn from(error: SchedulerError) -> Self {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "scheduler_error",
            error.to_string(),
        )
    }
}

impl From<LoopError> for ApiError {
    fn from(error: LoopError) -> Self {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "loop_error",
            error.to_string(),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

fn validate_daemon_work_order(
    state: &DaemonState,
    envelope: &WorkOrderEnvelope,
    tenant_id: &TenantId,
    agent_id: &splendor_types::AgentId,
    run_id: Option<RunId>,
    expected_placement_target: Option<String>,
) -> Result<WorkOrder, ApiError> {
    let validated = splendor_types::validate_work_order(
        envelope,
        &WorkOrderValidationContext {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id,
            expected_placement_target,
            now: OffsetDateTime::now_utc(),
        },
        &state.inner.work_order_keyring,
    )
    .map_err(work_order_error)?;
    Ok(validated.into_work_order())
}

fn work_order_authorization_for_endpoint(
    envelope: &WorkOrderEnvelope,
    allowed_scopes: Vec<splendor_types::EndpointScope>,
) -> WorkOrderAuthorization {
    WorkOrderAuthorization {
        work_order_id: envelope.work_order.work_order_id.to_string(),
        tenant_id: envelope.work_order.tenant_id.clone(),
        agent_id: envelope.work_order.agent_id.clone(),
        run_id: envelope.work_order.run_id.clone(),
        allowed_scopes,
        signature: envelope.signature.clone(),
        expires_at: envelope.work_order.expires_at,
        revocation: envelope.work_order.revocation.clone(),
    }
}

fn ensure_request_does_not_widen_work_order(
    request: &CreateRunRequest,
    work_order: &WorkOrder,
) -> Result<(), ApiError> {
    ensure_optional_subset(
        "allowed_actions",
        &request.allowed_actions,
        &work_order.allowed_actions,
    )?;
    ensure_optional_subset(
        "allowed_adapters",
        &request.allowed_adapters,
        &work_order.allowed_adapters,
    )?;
    ensure_optional_subset(
        "allowed_permissions",
        &request.allowed_permissions,
        &work_order.allowed_permissions,
    )?;

    for registration in &request.registered_actions {
        ensure_member(
            "registered_action.name",
            &registration.name,
            &work_order.allowed_actions,
        )?;
        ensure_member(
            "registered_action.adapter",
            &registration.adapter,
            &work_order.allowed_adapters,
        )?;
    }

    for candidate in &request.policy_actions {
        ensure_member(
            "policy_action.name",
            &candidate.action.name,
            &work_order.allowed_actions,
        )?;
        if let Some(adapter) = &candidate.adapter {
            ensure_member(
                "policy_action.adapter",
                adapter,
                &work_order.allowed_adapters,
            )?;
        }
        for permission in &candidate.action.required_permissions {
            ensure_member(
                "policy_action.required_permission",
                permission,
                &work_order.allowed_permissions,
            )?;
        }
    }

    Ok(())
}

fn ensure_optional_subset(
    field: &str,
    requested: &[String],
    allowed: &[String],
) -> Result<(), ApiError> {
    if requested.is_empty() {
        return Ok(());
    }
    for value in requested {
        ensure_member(field, value, allowed)?;
    }
    Ok(())
}

fn ensure_member(field: &str, value: &str, allowed: &[String]) -> Result<(), ApiError> {
    if allowed.iter().any(|item| item == value) {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::FORBIDDEN,
        "work_order_scope_widening",
        format!("{field} `{value}` is not authorized by the signed work order"),
    ))
}

fn work_order_error(error: WorkOrderValidationError) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        error.reason_code(),
        error.to_string(),
    )
}

fn require_create_run_token(value: &str, field: &'static str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("missing_{field}"),
            format!("create_run requires non-blank {field}"),
        ));
    }
    Ok(trimmed.to_string())
}

fn create_run_caller_scope(
    credential: Option<&CallerCredential>,
    security: &DaemonSecurityDecision,
) -> serde_json::Value {
    let principal = security.principal.as_ref().or_else(|| {
        security
            .audit_attribution
            .as_ref()
            .map(|audit| &audit.principal)
    });
    serde_json::json!({
        "principal": principal.map(|principal| serde_json::json!({
            "app_principal_id": &principal.app.app_principal_id,
            "client_principal_id": &principal.client_principal_id,
        })),
        "credential_id": credential
            .map(|credential| credential.credential_id.clone())
            .or_else(|| security.audit_attribution.as_ref().and_then(|audit| audit.credential_id.clone())),
        "insecure_dev_mode": security.insecure_dev_mode,
    })
}

fn create_run_request_fingerprint(request: &CreateRunRequest, work_order: &WorkOrder) -> String {
    stable_json_hash(&serde_json::json!({
        "validated_work_order": work_order,
        "allowed_actions": &request.allowed_actions,
        "allowed_adapters": &request.allowed_adapters,
        "allowed_permissions": &request.allowed_permissions,
        "policy_actions": &request.policy_actions,
        "policy_bundle_required": request.policy_bundle_required,
        "policy_bundle": &request.policy_bundle,
        "registered_actions": &request.registered_actions,
        "approval_policies": &request.approval_policies,
        "circuit_breakers": &request.circuit_breakers,
        "allowed_percept_schemas": &request.allowed_percept_schemas,
        "allowed_percept_sources": &request.allowed_percept_sources,
        "initial_state": &request.initial_state,
        "snapshot_interval": request.snapshot_interval,
    }))
}

fn create_run_idempotency_scope(
    request: &CreateRunRequest,
    work_order: &WorkOrder,
    security: &DaemonSecurityDecision,
    run_id: RunId,
) -> CreateRunIdempotencyScope {
    CreateRunIdempotencyScope {
        tenant_id: request.tenant_id.clone(),
        agent_id: request.agent_id.clone(),
        work_order_id: work_order.work_order_id.clone(),
        resolved_run_id: run_id,
        caller: create_run_caller_scope(request.credential.as_ref(), security),
        request_fingerprint: create_run_request_fingerprint(request, work_order),
    }
}

fn create_run_receipt_id(idempotency_key: &str, scope: &CreateRunIdempotencyScope) -> String {
    let hash = stable_json_hash(&serde_json::json!({
        "idempotency_key": idempotency_key,
        "scope": scope,
    }));
    format!("create_run:{hash}")
}

fn create_run_scope_mismatch_error(
    _attempted: &CreateRunIdempotencyScope,
    _existing: &CreateRunIdempotencyScope,
) -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "create_run_idempotency_scope_mismatch",
        "idempotency key was already used for a different create-run scope",
    )
    .details(serde_json::json!({
        "scope_mismatch": true,
        "category": "create_run_idempotency",
    }))
}

async fn create_run(
    State(state): State<DaemonState>,
    Json(request): Json<CreateRunRequest>,
) -> Result<Json<CreateRunResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let request_id = require_create_run_token(&request.request_id, "request_id")?;
    let idempotency_key = require_create_run_token(&request.idempotency_key, "idempotency_key")?;
    let validated_work_order = validate_daemon_work_order(
        &state,
        &request.work_order,
        &request.tenant_id,
        &request.agent_id,
        request.work_order.work_order.run_id.clone(),
        None,
    )?;
    ensure_request_does_not_widen_work_order(&request, &validated_work_order)?;
    let work_order_authorization = work_order_authorization_for_endpoint(
        &request.work_order,
        vec![splendor_types::EndpointScope::RunsCreate],
    );
    let security = state.validate_security(
        DaemonEndpoint::RunCreate {
            tenant_id: request.tenant_id.clone(),
        },
        request.credential.clone(),
        Some(work_order_authorization),
        request.audit_attribution.clone(),
    )?;

    let existing_run_id_for_scope = {
        let idempotency = state
            .inner
            .create_run_idempotency
            .lock()
            .map_err(|_| lock_error())?;
        idempotency
            .get(&idempotency_key)
            .map(|entry| entry.scope.resolved_run_id.clone())
    };
    let run_id = validated_work_order
        .run_id
        .clone()
        .or(existing_run_id_for_scope)
        .unwrap_or_else(RunId::new);
    let idempotency_scope =
        create_run_idempotency_scope(&request, &validated_work_order, &security, run_id.clone());

    {
        let idempotency = state
            .inner
            .create_run_idempotency
            .lock()
            .map_err(|_| lock_error())?;
        if let Some(existing) = idempotency.get(&idempotency_key) {
            if existing.scope != idempotency_scope {
                return Err(create_run_scope_mismatch_error(
                    &idempotency_scope,
                    &existing.scope,
                ));
            }
            let runs = state.inner.runs.lock().map_err(|_| lock_error())?;
            let slot = runs.get(&existing.response.run_id).ok_or_else(|| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "create_run_idempotency_receipt_missing",
                    "idempotency receipt references a missing local run",
                )
            })?;
            record_daemon_audit(
                slot,
                "splendor.runs.create.idempotent_duplicate",
                security.audit_attribution,
            )?;
            let mut response = existing.response.clone();
            response.duplicate = true;
            return Ok(Json(response));
        }
    }

    let trace_store: Arc<dyn TraceStore> = state
        .inner
        .trace_store_override
        .clone()
        .unwrap_or_else(|| Arc::new(InMemoryTraceStore::default()));
    let state_store: Arc<dyn StateStore> = Arc::new(InMemoryStateStore::default());
    let tenant_registry = TenantRegistry::new();
    let mut tenant_context = TenantContext::new(
        request.tenant_id.clone(),
        TenantPolicy {
            allowed_actions: validated_work_order.allowed_actions.clone(),
            allowed_adapters: validated_work_order.allowed_adapters.clone(),
            allowed_permissions: validated_work_order.allowed_permissions.clone(),
        },
        QuotaPolicy::default().constrain_to_work_order(&validated_work_order),
    );
    tenant_context.register_agent_policy(
        request.agent_id.clone(),
        AgentIsolationPolicy {
            allowed_permissions: validated_work_order.allowed_permissions.clone(),
            ..AgentIsolationPolicy::default()
        },
    );
    tenant_registry.insert(tenant_context);

    let adapter_executions = Arc::new(AtomicU64::new(0));
    let mut gateway = VerifiedActionGateway::new(Arc::new(tenant_registry.clone()));
    gateway.set_resource_boundary_verifier(Arc::new(DataArtifactBoundaryVerifier::new(
        request.tenant_id.clone(),
        validated_work_order.data_refs.clone(),
    )));
    if !request.approval_policies.is_empty() {
        gateway.set_approval_verifier(Arc::new(PolicyApprovalVerifier::new(
            request.approval_policies.clone(),
        )));
    }
    let circuit_breakers = SharedCircuitBreakerEvaluator::new(request.circuit_breakers.clone());
    gateway.set_circuit_breaker_evaluator(Arc::new(circuit_breakers.clone()));
    let registrations = registrations_for_request(&request, &validated_work_order);
    for registration in registrations {
        gateway.register_adapter(
            registration.name,
            registration.adapter,
            Arc::new(RecordingAdapter {
                executions: Arc::clone(&adapter_executions),
            }),
        );
    }

    if request.policy_bundle_required && request.policy_bundle.is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "missing_policy_bundle",
            "missing_policy_bundle",
        ));
    }

    let policy_cache = PolicyCache::new(
        PolicyCacheConfig {
            enforcement_required: request.policy_bundle_required || request.policy_bundle.is_some(),
        },
        PolicyCacheOwner {
            tenant_id: request.tenant_id.clone(),
            agent_id: request.agent_id.clone(),
        },
    );
    let (policy_bundle, initial_policy) = match request.policy_bundle.as_ref() {
        Some(envelope) => {
            let validated = validate_policy_bundle(
                envelope,
                &PolicyBundleValidationContext {
                    tenant_id: request.tenant_id.clone(),
                    agent_id: Some(request.agent_id.clone()),
                    now: OffsetDateTime::now_utc(),
                },
                &state.inner.policy_bundle_keyring,
            )
            .map_err(policy_bundle_error)?;
            (
                Some(PolicyBundleTraceContext::from(validated.bundle())),
                Some(validated),
            )
        }
        None => (None, None),
    };
    let verified_gateway: Arc<dyn ActionGateway> = Arc::new(gateway);
    let gateway: Arc<dyn ActionGateway> = Arc::new(PolicyDistributionGateway::new(
        verified_gateway,
        Arc::new(policy_cache.clone()),
    ));

    let state_graph = StateGraph::new(
        Arc::clone(&state_store),
        SnapshotPolicy {
            interval: Some(request.snapshot_interval.unwrap_or(1)),
            important_labels: Vec::new(),
        },
    );
    let initial_state = encode_initial_state(request.initial_state)?;
    let policy_actions = request
        .policy_actions
        .into_iter()
        .map(DaemonActionCandidate::into_candidate)
        .collect();
    let approval_evidence = ApprovalEvidenceSlot::default();
    let policy = Box::new(StaticDaemonPolicy {
        actions: policy_actions,
        approval_evidence: approval_evidence.clone(),
    });
    let agent = AgentContext::new(
        request.agent_id.clone(),
        request.tenant_id.clone(),
        AgentRuntimeConfig::default(),
    );
    let mut run_context =
        RunTraceContext::new(Some(run_id.clone())).with_work_order(validated_work_order.clone());
    if let Some(policy_bundle) = policy_bundle.clone() {
        run_context = run_context.with_policy_bundle(policy_bundle);
    }
    let mut engine = LoopEngine::with_trace_store_and_work_order(
        agent,
        state_graph,
        initial_state,
        policy,
        Arc::clone(&gateway),
        Arc::clone(&trace_store),
        run_context,
    )
    .map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "loop_error",
            error.to_string(),
        )
    })?;
    let percept_queue = PerceptQueue::default();
    engine.add_perceptor(QueuedPerceptor {
        queue: percept_queue.clone(),
    });
    let mut scheduler =
        Scheduler::with_registry(SchedulerConfig::default(), tenant_registry.clone());
    scheduler.add_agent(engine);

    let slot = RunSlot {
        run_id: run_id.clone(),
        tenant_id: request.tenant_id,
        agent_id: request.agent_id,
        status: RunStatus::Pending,
        scheduler,
        state_store,
        trace_store,
        gateway,
        tenant_registry,
        circuit_breakers,
        policy_cache,
        percept_queue,
        allowed_percept_schemas: request.allowed_percept_schemas,
        allowed_percept_sources: request.allowed_percept_sources,
        allowed_actions: validated_work_order.allowed_actions.clone(),
        state_head: None,
        adapter_executions,
        approval_evidence,
        pending_approval: None,
        tick_count: 0,
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
    };

    if let Some(validated) = initial_policy {
        let recorder = RunPolicyCacheMutationRecorder { slot: &slot };
        slot.policy_cache
            .install_validated_traced(validated, false, &recorder)
            .map_err(policy_cache_mutation_error)?;
    }

    let mut idempotency = state
        .inner
        .create_run_idempotency
        .lock()
        .map_err(|_| lock_error())?;
    if let Some(existing) = idempotency.get(&idempotency_key) {
        if existing.scope != idempotency_scope {
            return Err(create_run_scope_mismatch_error(
                &idempotency_scope,
                &existing.scope,
            ));
        }
        let runs = state.inner.runs.lock().map_err(|_| lock_error())?;
        let slot = runs.get(&existing.response.run_id).ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "create_run_idempotency_receipt_missing",
                "idempotency receipt references a missing local run",
            )
        })?;
        record_daemon_audit(
            slot,
            "splendor.runs.create.idempotent_duplicate",
            security.audit_attribution,
        )?;
        let mut response = existing.response.clone();
        response.duplicate = true;
        return Ok(Json(response));
    }
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    if runs.contains_key(&run_id) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "run_already_exists",
            "run already exists in local daemon",
        ));
    }
    record_daemon_audit(&slot, "splendor.runs.create", security.audit_attribution)?;
    let response = CreateRunResponse {
        request_id,
        idempotency_key: idempotency_key.clone(),
        idempotency_receipt_id: create_run_receipt_id(&idempotency_key, &idempotency_scope),
        duplicate: false,
        run_id: run_id.clone(),
        status: RunStatus::Pending,
    };
    runs.insert(run_id.clone(), slot);
    idempotency.insert(
        idempotency_key,
        CreateRunIdempotencyEntry {
            scope: idempotency_scope,
            response: response.clone(),
        },
    );
    Ok(Json(response))
}

async fn sync_circuit_breakers(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Json(request): Json<CircuitBreakerSyncRequest>,
) -> Result<Json<CircuitBreakerSyncResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get_mut(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    let security = state.validate_security(
        DaemonEndpoint::PolicySync {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    let trace_event_id = record_run_event_returning_id(
        slot,
        TraceEventKind::DaemonAudit {
            endpoint: "splendor.governance.circuit_breakers.sync".to_string(),
            audit: security.audit_attribution.ok_or_else(|| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "missing_audit_attribution",
                    "validated breaker sync did not return audit attribution",
                )
            })?,
        },
    )?;
    let breaker_ids = request
        .circuit_breakers
        .iter()
        .map(|breaker| breaker.breaker_id.to_string())
        .collect::<Vec<_>>();
    slot.circuit_breakers.set(request.circuit_breakers)?;
    slot.updated_at = OffsetDateTime::now_utc();
    Ok(Json(CircuitBreakerSyncResponse {
        run_id,
        accepted: true,
        breaker_ids,
        trace_event_id,
    }))
}

async fn inspect_run(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    headers: HeaderMap,
) -> Result<Json<RunInspectResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let credential = caller_credential_from_headers(&headers)?;
    let runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    state.validate_security(
        DaemonEndpoint::RunInspect {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        credential,
        None,
        None,
    )?;
    Ok(Json(inspect_response(slot)))
}

async fn start_run(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Json(request): Json<LifecycleRequest>,
) -> Result<Json<TickResponse>, ApiError> {
    run_lifecycle_tick(
        state,
        run_id,
        request,
        LifecycleKind::Start,
        RunStatus::Running,
    )
    .await
}

async fn pause_run(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Json(request): Json<LifecycleRequest>,
) -> Result<Json<RunInspectResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get_mut(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    let security = state.validate_security(
        DaemonEndpoint::RunPause {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    record_daemon_audit(slot, "splendor.runs.pause", security.audit_attribution)?;
    record_run_event(
        slot,
        TraceEventKind::RunPaused {
            reason: request.reason,
        },
    )?;
    slot.status = RunStatus::Paused;
    slot.updated_at = OffsetDateTime::now_utc();
    Ok(Json(inspect_response(slot)))
}

async fn resume_run(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Json(request): Json<LifecycleRequest>,
) -> Result<Json<TickResponse>, ApiError> {
    run_lifecycle_tick(
        state,
        run_id,
        request,
        LifecycleKind::Resume,
        RunStatus::Running,
    )
    .await
}

async fn stop_run(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Json(request): Json<LifecycleRequest>,
) -> Result<Json<RunInspectResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get_mut(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    let security = state.validate_security(
        DaemonEndpoint::RunStop {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    record_daemon_audit(slot, "splendor.runs.stop", security.audit_attribution)?;
    record_run_event(
        slot,
        TraceEventKind::RunStopped {
            reason: request.reason,
        },
    )?;
    slot.status = RunStatus::Cancelled;
    slot.updated_at = OffsetDateTime::now_utc();
    Ok(Json(inspect_response(slot)))
}

async fn cancel_run(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Json(request): Json<LifecycleRequest>,
) -> Result<Json<RunInspectResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get_mut(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    let security = state.validate_security(
        DaemonEndpoint::RunStop {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    record_daemon_audit(slot, "splendor.runs.cancel", security.audit_attribution)?;
    record_run_event(
        slot,
        TraceEventKind::RunStopped {
            reason: request.reason,
        },
    )?;
    slot.status = RunStatus::Cancelled;
    slot.updated_at = OffsetDateTime::now_utc();
    Ok(Json(inspect_response(slot)))
}

async fn append_percept(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Json(request): Json<AppendPerceptRequest>,
) -> Result<Json<AppendPerceptResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let percept = request.percept.ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "malformed_percept",
            "percept payload is required",
        )
    })?;
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get_mut(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    let security = state.validate_security(
        DaemonEndpoint::PerceptAppend {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
            schema: percept.schema.clone(),
            provenance_source: percept.provenance.source.clone(),
            allowed_schemas: slot.allowed_percept_schemas.clone(),
            allowed_provenance_sources: slot.allowed_percept_sources.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    record_daemon_audit(slot, "splendor.percepts.append", security.audit_attribution)?;
    slot.percept_queue.push(percept.clone()).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "percept_queue_error",
            error.to_string(),
        )
    })?;
    record_run_event(
        slot,
        TraceEventKind::PerceptsAppended {
            count: 1,
            schemas: vec![percept.schema],
        },
    )?;
    slot.updated_at = OffsetDateTime::now_utc();
    Ok(Json(AppendPerceptResponse {
        run_id,
        accepted: 1,
    }))
}

async fn sync_policy(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Json(request): Json<PolicySyncRequest>,
) -> Result<Json<PolicySyncResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get_mut(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    let security = state.validate_security(
        DaemonEndpoint::PolicySync {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    record_daemon_audit(slot, "splendor.policies.sync", security.audit_attribution)?;

    let now = OffsetDateTime::now_utc();
    let reconnect_requested = request.disconnected == Some(false);
    if request.disconnected == Some(true) {
        if let Some(event) = slot.policy_cache.mark_disconnected_with_trace(now) {
            record_run_event(slot, event)?;
        }
    }

    if let Some(sync_error) = request.sync_error.filter(|value| !value.trim().is_empty()) {
        let failure = slot.policy_cache.record_sync_failure(sync_error, now);
        let snapshot = slot.policy_cache.snapshot();
        record_run_event(
            slot,
            TraceEventKind::PolicySyncFailed {
                policy_bundle_id: snapshot
                    .bundle
                    .as_ref()
                    .map(|bundle| bundle.policy_bundle_id.clone()),
                version: snapshot
                    .bundle
                    .as_ref()
                    .map(|bundle| bundle.version.clone()),
                reason: failure.reason,
            },
        )?;
        return Ok(Json(PolicySyncResponse {
            run_id,
            accepted: false,
            policy_bundle: snapshot.bundle.clone(),
            cache_status: policy_cache_response(&slot.policy_cache),
        }));
    }

    let envelope = request.policy_bundle.ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "missing_policy_bundle",
            "policy sync requires a policy bundle or sync_error",
        )
    })?;
    let policy_bundle_id = Some(envelope.bundle.policy_bundle_id.clone());
    let version = Some(envelope.bundle.version.clone());
    let validation = validate_policy_bundle_candidate(
        &envelope,
        &PolicyBundleValidationContext {
            tenant_id: slot.tenant_id.clone(),
            agent_id: Some(slot.agent_id.clone()),
            now,
        },
        &state.inner.policy_bundle_keyring,
    );

    match validation {
        Ok(candidate) => match candidate.validated().bundle().revocation.clone() {
            RevocationStatus::Active => {
                let recorder = RunPolicyCacheMutationRecorder { slot };
                match slot.policy_cache.install_validated_traced(
                    candidate.into_validated(),
                    reconnect_requested,
                    &recorder,
                ) {
                    Ok(installed) => {
                        slot.updated_at = OffsetDateTime::now_utc();
                        Ok(Json(PolicySyncResponse {
                            run_id,
                            accepted: true,
                            policy_bundle: Some(installed.bundle),
                            cache_status: policy_cache_response(&slot.policy_cache),
                        }))
                    }
                    Err(PolicyCacheMutationError::Policy(error)) => {
                        let reason = error.reason_code().to_string();
                        record_policy_sync_rejection(slot, policy_bundle_id, version, reason, now)?;
                        Err(policy_cache_install_error(error))
                    }
                    Err(error @ PolicyCacheMutationError::Trace(_)) => {
                        Err(policy_cache_mutation_error(error))
                    }
                }
            }
            RevocationStatus::Revoked { reason } => {
                let revocation_reason = reason;
                let recorder = RunPolicyCacheMutationRecorder { slot };
                match slot
                    .policy_cache
                    .apply_validated_revocation_traced(candidate.into_validated(), &recorder)
                {
                    Ok(_) => {
                        let rejection_reason = "revoked_policy_bundle".to_string();
                        slot.policy_cache.record_sync_failure(rejection_reason, now);
                        Err(policy_bundle_error(PolicyBundleValidationError::Revoked {
                            reason: revocation_reason,
                        }))
                    }
                    Err(PolicyCacheMutationError::Policy(error)) => {
                        let rejection_reason = error.reason_code().to_string();
                        record_policy_sync_rejection(
                            slot,
                            policy_bundle_id,
                            version,
                            rejection_reason,
                            now,
                        )?;
                        Err(policy_cache_install_error(error))
                    }
                    Err(error @ PolicyCacheMutationError::Trace(_)) => {
                        Err(policy_cache_mutation_error(error))
                    }
                }
            }
        },
        Err(error) => {
            let reason = error.reason_code().to_string();
            record_policy_sync_rejection(slot, policy_bundle_id, version, reason, now)?;
            Err(policy_bundle_error(error))
        }
    }
}

fn record_policy_sync_rejection(
    slot: &mut RunSlot,
    policy_bundle_id: Option<splendor_types::PolicyBundleId>,
    version: Option<String>,
    reason: String,
    observed_at: OffsetDateTime,
) -> Result<(), ApiError> {
    record_policy_sync_rejection_traces(slot, policy_bundle_id, version, reason.clone())?;
    slot.policy_cache.record_sync_failure(reason, observed_at);
    Ok(())
}

fn record_policy_sync_rejection_traces(
    slot: &mut RunSlot,
    policy_bundle_id: Option<splendor_types::PolicyBundleId>,
    version: Option<String>,
    reason: String,
) -> Result<(), ApiError> {
    record_run_event(
        slot,
        TraceEventKind::PolicyBundleRejected {
            policy_bundle_id: policy_bundle_id.clone(),
            version: version.clone(),
            reason: reason.clone(),
        },
    )?;
    record_run_event(
        slot,
        TraceEventKind::PolicySyncFailed {
            policy_bundle_id,
            version,
            reason,
        },
    )
}

async fn state_head(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    headers: HeaderMap,
) -> Result<Json<StateHeadResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let credential = caller_credential_from_headers(&headers)?;
    let runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    state.validate_security(
        DaemonEndpoint::StateHeadRead {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        credential,
        None,
        None,
    )?;
    let head = slot.state_head.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "state_head_not_found",
            "run has not committed state yet",
        )
    })?;
    let node = slot.state_store.get_node(head).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_store_error",
            error.to_string(),
        )
    })?;
    Ok(Json(StateHeadResponse {
        run_id,
        state_node_id: node.id.to_string(),
        parent_state_node_ids: node.parent_ids.iter().map(ToString::to_string).collect(),
        data_hash: node.data_hash.to_string(),
        created_at: node.metadata.created_at,
        label: node.metadata.label,
    }))
}

async fn export_state_snapshot(
    State(state): State<DaemonState>,
    Json(request): Json<StateSnapshotExportRequest>,
) -> Result<Json<StateSnapshotExportResponse>, ApiError> {
    state.ensure_runtime_available()?;
    require_post_audit_attribution(
        request.credential.as_ref(),
        request.audit_attribution.as_ref(),
    )?;
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs
        .get_mut(&request.run_id)
        .ok_or_else(|| invalid_run(&request.run_id))?;
    state.validate_security(
        DaemonEndpoint::StateHeadRead {
            tenant_id: slot.tenant_id.clone(),
            run_id: request.run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    let state_head = slot.state_head.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "state_head_not_found",
            "run has no state head",
        )
    })?;
    let snapshot_id = slot.state_store.snapshot(state_head).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "state_store_error",
            error.to_string(),
        )
    })?;
    let snapshot = slot
        .state_store
        .export_snapshot(&snapshot_id)
        .map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "state_store_error",
                error.to_string(),
            )
        })?;
    let handoff = splendor_types::StateHandoff {
        schema_version: "splendor.state_handoff.v1".to_string(),
        handoff_id: format!("handoff-{}", snapshot.snapshot_id),
        mode: splendor_types::StateReferenceMode::SnapshotImport,
        authority: splendor_types::StateHandoffAuthority {
            tenant_id: slot.tenant_id.clone(),
            agent_id: slot.agent_id.clone(),
            run_id: request.run_id.clone(),
            work_order_id: request.work_order_id,
        },
        source_instance_id: request.source_instance_id,
        receiver_instance_id: request.receiver_instance_id,
        previous_state_node_id: Some(state_head.to_string()),
        snapshot,
        source_trace_id: None,
        created_at: OffsetDateTime::now_utc(),
    };
    let event_id = record_run_event_returning_id(
        slot,
        TraceEventKind::StateHandoffExported {
            handoff: splendor_types::StateHandoffTraceContext::exported(&handoff),
        },
    )?;
    let mut handoff = handoff;
    handoff.source_trace_id = Some(event_id.clone());
    Ok(Json(StateSnapshotExportResponse {
        run_id: request.run_id,
        state_node_id: state_head.to_string(),
        trace_event_id: event_id,
        handoff,
    }))
}

async fn import_state_snapshot(
    State(state): State<DaemonState>,
    Json(request): Json<StateSnapshotImportRequest>,
) -> Result<Json<StateSnapshotImportResponse>, ApiError> {
    state.ensure_runtime_available()?;
    require_post_audit_attribution(
        request.credential.as_ref(),
        request.audit_attribution.as_ref(),
    )?;
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let run_id = request.handoff.authority.run_id.clone();
    let slot = runs.get_mut(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    state.validate_security(
        DaemonEndpoint::StateHeadRead {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    if request.handoff.authority.tenant_id != slot.tenant_id
        || request.handoff.authority.agent_id != slot.agent_id
    {
        let event_id = record_run_event_returning_id(
            slot,
            TraceEventKind::StateHandoffImportFailed {
                handoff: splendor_types::StateHandoffTraceContext::exported(&request.handoff),
                reason: "authority_mismatch".to_string(),
            },
        )?;
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "state_handoff_authority_mismatch",
            "state handoff tenant/agent binding does not match target run",
        )
        .details(serde_json::json!({"trace_event_id": event_id})));
    }
    let metadata = splendor_store::StateMetadata {
        created_at: OffsetDateTime::now_utc(),
        label: Some("state_handoff_import".to_string()),
        tenant_id: Some(slot.tenant_id.clone()),
        agent_id: Some(slot.agent_id.clone()),
        run_id: Some(run_id.clone()),
        trace_event_id: request.handoff.source_trace_id.clone(),
    };
    let imported = match slot
        .state_store
        .import_handoff_snapshot(&request.handoff.snapshot, metadata)
    {
        Ok(imported) => imported,
        Err(error) => {
            let event_id = record_run_event_returning_id(
                slot,
                TraceEventKind::StateHandoffImportFailed {
                    handoff: splendor_types::StateHandoffTraceContext::exported(&request.handoff),
                    reason: error.to_string(),
                },
            )?;
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "state_handoff_rejected",
                error.to_string(),
            )
            .details(serde_json::json!({"trace_event_id": event_id})));
        }
    };
    slot.state_head = Some(imported.node_id.clone());
    let event_id = record_run_event_returning_id(
        slot,
        TraceEventKind::StateHandoffImported {
            handoff: splendor_types::StateHandoffTraceContext::imported(
                &request.handoff,
                imported.node_id.to_string(),
            ),
        },
    )?;
    Ok(Json(StateSnapshotImportResponse {
        run_id,
        state_node_id: imported.node_id.to_string(),
        trace_event_id: event_id,
        accepted: true,
    }))
}

async fn traces(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Query(query): Query<TraceQuery>,
    headers: HeaderMap,
) -> Result<Json<TracePageResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let credential = caller_credential_from_headers(&headers)?;
    let runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    state.validate_security(
        DaemonEndpoint::TraceRead {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
            redaction_policy: query.redaction_policy,
        },
        credential,
        None,
        None,
    )?;
    let records = match (query.start, query.end) {
        (Some(start), Some(end)) => slot.trace_store.read_range(&run_id.to_string(), start, end),
        _ => slot.trace_store.read(&run_id.to_string()),
    }
    .map_err(trace_error)?;
    let records = redact_trace_records(records);
    Ok(Json(TracePageResponse { run_id, records }))
}

async fn export_traces(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Json(request): Json<TraceExportRequest>,
) -> Result<Json<TraceExportResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let redaction_policy = request.redaction_policy.clone();
    let runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    require_post_audit_attribution(
        request.credential.as_ref(),
        request.audit_attribution.as_ref(),
    )?;
    let security = state.validate_security(
        DaemonEndpoint::TraceRead {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
            redaction_policy: redaction_policy.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    record_daemon_audit(
        slot,
        "splendor.traces.export.redacted",
        security.audit_attribution,
    )?;
    let records = match (request.start, request.end) {
        (Some(start), Some(end)) => slot.trace_store.read_range(&run_id.to_string(), start, end),
        _ => slot.trace_store.read(&run_id.to_string()),
    }
    .map_err(trace_error)?;
    let integrity_hash = trace_export_integrity_hash(&records);
    let records = redact_trace_records(records);
    Ok(Json(TraceExportResponse {
        run_id,
        record_count: records.len(),
        records,
        redaction_policy: redaction_policy.unwrap_or_default(),
        integrity_hash,
    }))
}

async fn replay_run(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Json(request): Json<ReplayRequest>,
) -> Result<Json<ReplayResponse>, ApiError> {
    state.ensure_runtime_available()?;
    if request.mode != "inspect_only" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_replay_mode",
            "local daemon replay only supports inspect_only mode",
        ));
    }
    if request.side_effects_allowed {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "replay_side_effects_forbidden",
            "local daemon replay is inspect-only and must not allow side effects",
        ));
    }
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get_mut(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    require_post_audit_attribution(
        request.credential.as_ref(),
        request.audit_attribution.as_ref(),
    )?;
    let security = state.validate_security(
        DaemonEndpoint::ReplayCreate {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    record_daemon_audit(
        slot,
        "splendor.replay.explained",
        security.audit_attribution,
    )?;
    let records = slot
        .trace_store
        .read(&run_id.to_string())
        .map_err(trace_error)?;
    validate_trace_order(&records, &run_id)?;
    let action_event_count = records
        .iter()
        .filter(|record| {
            serde_json::from_value::<TraceEvent>(record.payload.clone())
                .map(|event| {
                    matches!(
                        event.kind,
                        TraceEventKind::ActionExecuted { .. }
                            | TraceEventKind::ActionDenied { .. }
                            | TraceEventKind::ActionNeedsApproval { .. }
                            | TraceEventKind::ActionFailed { .. }
                    )
                })
                .unwrap_or(false)
        })
        .count();
    let approval_events = records
        .iter()
        .filter_map(|record| {
            serde_json::from_value::<TraceEvent>(record.payload.clone())
                .ok()
                .and_then(approval_replay_event)
        })
        .collect();
    Ok(Json(ReplayResponse {
        replay_id: format!("replay-{run_id}"),
        run_id,
        mode: "inspect_only".to_string(),
        event_count: records.len(),
        action_event_count,
        approval_events,
    }))
}

async fn submit_action(
    State(state): State<DaemonState>,
    Json(request): Json<SubmitActionRequest>,
) -> Result<Json<ActionOutcome>, ApiError> {
    state.ensure_runtime_available()?;
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs
        .get_mut(&request.run_id)
        .ok_or_else(|| invalid_run(&request.run_id))?;
    if request.tenant_id != slot.tenant_id || request.agent_id != slot.agent_id {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "wrong_scope",
            "action tenant or agent does not match the run",
        ));
    }
    let security = state.validate_security(
        DaemonEndpoint::ActionSubmit {
            tenant_id: request.tenant_id.clone(),
            run_id: request.run_id.clone(),
            trace_linked: request.causal_trace_id.is_some(),
            gateway_verification: GatewayVerificationState::Required,
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    record_daemon_audit(slot, "splendor.actions.submit", security.audit_attribution)?;

    record_run_event(
        slot,
        TraceEventKind::ActionVerificationStarted {
            action: request.action.clone(),
        },
    )?;
    let action_request = ActionRequest {
        action_id: request.action_id.unwrap_or_else(ActionId::new),
        tenant_id: request.tenant_id,
        agent_id: request.agent_id,
        run_id: request.run_id,
        action: request.action.clone(),
        adapter: request.adapter,
        quota_usage: request
            .quota_usage
            .unwrap_or_else(splendor_types::QuotaUsage::single_action),
        satisfied_preconditions: request.satisfied_preconditions,
        requested_at: OffsetDateTime::now_utc(),
        approval_evidence: request.approval_evidence,
        authority_obligation_evidence: None,
    };
    if !slot
        .allowed_actions
        .iter()
        .any(|allowed| allowed == &action_request.action.name)
    {
        let verification = splendor_types::VerificationResult {
            allowed: false,
            reasons: vec!["action_not_allowed".to_string()],
            artifacts: serde_json::json!({
                "context": {
                    "source": "signed_work_order_action_scope",
                    "tenant_id": action_request.tenant_id,
                    "agent_id": action_request.agent_id,
                    "run_id": action_request.run_id,
                    "action_id": action_request.action_id,
                    "action": action_request.action.name,
                    "adapter": action_request.adapter,
                }
            }),
        };
        let outcome = ActionOutcome {
            action_id: action_request.action_id,
            status: ActionStatus::Denied,
            verification,
            post_verification: None,
            output: None,
            error: Some("action_not_allowed".to_string()),
            completed_at: OffsetDateTime::now_utc(),
        };
        record_run_event(
            slot,
            TraceEventKind::ActionVerificationCompleted {
                action: request.action.clone(),
                result: outcome.verification.clone(),
            },
        )?;
        record_run_event(
            slot,
            TraceEventKind::ActionDenied {
                action: request.action.clone(),
                result: outcome.verification.clone(),
            },
        )?;
        return Ok(Json(outcome));
    }
    let outcome = slot.gateway.submit(action_request).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_error",
            error.to_string(),
        )
    })?;
    record_run_event(
        slot,
        TraceEventKind::ActionVerificationCompleted {
            action: request.action.clone(),
            result: outcome.verification.clone(),
        },
    )?;
    match outcome.status {
        ActionStatus::Executed => {
            record_approval_event_if_present(slot, &outcome)?;
            record_run_event(
                slot,
                TraceEventKind::ActionExecuted {
                    action: request.action.clone(),
                    outcome: outcome.output.clone().unwrap_or(serde_json::Value::Null),
                },
            )
        }
        ActionStatus::Denied => {
            record_approval_event_if_present(slot, &outcome)?;
            update_status_for_approval_denial(slot, &outcome);
            record_run_event(
                slot,
                TraceEventKind::ActionDenied {
                    action: request.action.clone(),
                    result: outcome.verification.clone(),
                },
            )
        }
        ActionStatus::NeedsApproval => {
            if let Some(approval) =
                approval_artifact(&outcome.verification).map(|(_, approval)| approval)
            {
                slot.pending_approval = Some(approval);
            }
            record_approval_event_if_present(slot, &outcome)?;
            record_run_event(
                slot,
                TraceEventKind::ActionNeedsApproval {
                    action: request.action.clone(),
                    result: outcome.verification.clone(),
                },
            )?;
            record_run_event(
                slot,
                TraceEventKind::RunPaused {
                    reason: Some("waiting_for_approval".to_string()),
                },
            )?;
            slot.status = RunStatus::WaitingForApproval;
            Ok(())
        }
        ActionStatus::NeedsIntervention => {
            record_approval_event_if_present(slot, &outcome)?;
            slot.status = RunStatus::Failed;
            record_run_event(
                slot,
                TraceEventKind::ActionNeedsIntervention {
                    action: request.action.clone(),
                    result: outcome.verification.clone(),
                },
            )
        }
        ActionStatus::Failed => record_run_event(
            slot,
            TraceEventKind::ActionFailed {
                action: request.action.clone(),
                error: outcome
                    .error
                    .clone()
                    .unwrap_or_else(|| "action_failed".to_string()),
                result: outcome
                    .post_verification
                    .clone()
                    .unwrap_or_else(|| outcome.verification.clone()),
            },
        ),
    }?;
    record_run_event(
        slot,
        TraceEventKind::OutcomeRecorded {
            outcome: serde_json::json!({
                "source": "daemon.action",
                "causal_trace_id": request.causal_trace_id,
                "action_outcome": outcome,
            }),
            feedback: None,
            reward: None,
        },
    )?;
    slot.updated_at = OffsetDateTime::now_utc();
    Ok(Json(outcome))
}

async fn register_device_profile(
    State(state): State<DaemonState>,
    Json(request): Json<RegisterDeviceProfileRequest>,
) -> Result<Json<RegisterDeviceProfileResponse>, ApiError> {
    state.ensure_runtime_available()?;
    validate_device_profile_payload(&request.profile)?;
    let security = state.validate_security(
        DaemonEndpoint::DeviceProfileRegister {
            tenant_id: request.profile.tenant_id.clone(),
            node_id: request.profile.node_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution.clone(),
    )?;
    let mut profile = request.profile;
    profile.registered_at = now_rfc3339();
    state
        .inner
        .device_profiles
        .lock()
        .map_err(|_| lock_error())?
        .insert(profile.node_id.clone(), profile.clone());
    let audit_attribution = required_audit(security.audit_attribution)?;
    let trace_event_id = record_device_audit(
        &state,
        "device.profile.registered",
        audit_attribution,
        serde_json::json!({"node_id": profile.node_id, "device_kind": profile.device_kind}),
    )?;
    Ok(Json(RegisterDeviceProfileResponse {
        profile,
        trace_event_id,
    }))
}

async fn get_device_status(
    Path(node_id): Path<NodeId>,
    State(state): State<DaemonState>,
    headers: HeaderMap,
) -> Result<Json<DeviceRuntimeProfile>, ApiError> {
    let credential = caller_credential_from_headers(&headers)?;
    let profile = state
        .inner
        .device_profiles
        .lock()
        .map_err(|_| lock_error())?
        .get(&node_id)
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "device_not_registered",
                "device profile not registered",
            )
        })?;
    state.validate_security(
        DaemonEndpoint::DeviceRead {
            tenant_id: profile.tenant_id.clone(),
            node_id,
        },
        credential,
        None,
        None,
    )?;
    Ok(Json(profile))
}

async fn get_policy_cache_status(
    Path(node_id): Path<NodeId>,
    State(state): State<DaemonState>,
    headers: HeaderMap,
) -> Result<Json<DevicePolicyCacheStatus>, ApiError> {
    let credential = caller_credential_from_headers(&headers)?;
    let profile = state
        .inner
        .device_profiles
        .lock()
        .map_err(|_| lock_error())?
        .get(&node_id)
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "device_not_registered",
                "device profile not registered",
            )
        })?;
    state.validate_security(
        DaemonEndpoint::DeviceRead {
            tenant_id: profile.tenant_id.clone(),
            node_id,
        },
        credential,
        None,
        None,
    )?;
    Ok(Json(profile.policy_cache))
}

async fn submit_physical_action(
    Path(node_id): Path<NodeId>,
    State(state): State<DaemonState>,
    Json(request): Json<SubmitPhysicalActionRequest>,
) -> Result<Json<ActionOutcome>, ApiError> {
    state.ensure_runtime_available()?;
    let profile = state
        .inner
        .device_profiles
        .lock()
        .map_err(|_| lock_error())?
        .get(&node_id)
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "device_not_registered",
                "device profile not registered",
            )
        })?;
    if profile.tenant_id != request.action_request.tenant_id {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "wrong_scope",
            "device tenant does not match action tenant",
        ));
    }
    let action_name = request.action_request.action.name.clone();
    if matches_forbidden_physical_action(&action_name) || !is_allowed_physical_action(&action_name)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "low_level_physical_action_rejected",
            "physical endpoint accepts only bounded high-level actions",
        ));
    }
    if !profile
        .allowed_physical_actions
        .iter()
        .any(|allowed| allowed == &action_name)
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "physical_action_not_profile_allowed",
            "device profile does not allow action",
        ));
    }

    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs
        .get_mut(&request.action_request.run_id)
        .ok_or_else(|| invalid_run(&request.action_request.run_id))?;
    if request.action_request.tenant_id != slot.tenant_id
        || request.action_request.agent_id != slot.agent_id
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "wrong_scope",
            "action tenant or agent does not match the run",
        ));
    }
    let security = state.validate_security(
        DaemonEndpoint::ActionSubmit {
            tenant_id: request.action_request.tenant_id.clone(),
            run_id: request.action_request.run_id.clone(),
            trace_linked: request.action_request.causal_trace_id.is_some(),
            gateway_verification: GatewayVerificationState::Required,
        },
        request.action_request.credential.clone(),
        None,
        request.action_request.audit_attribution.clone(),
    )?;
    record_daemon_audit(
        slot,
        "splendor.devices.actions.submit",
        security.audit_attribution.clone(),
    )?;
    record_physical_run_event(
        slot,
        "safety.verification.started",
        &request.action_request.action,
        serde_json::json!({"node_id": node_id, "action": action_name}),
    )?;
    if let Some(proposal_id) = &request.safety_context.cloud_helper_proposal_id {
        record_physical_run_event(
            slot,
            "cloud_helper.proposal.received",
            &request.action_request.action,
            serde_json::json!({"proposal_id": proposal_id, "direct_authority": request.safety_context.cloud_helper_direct_authority}),
        )?;
    }
    if request.safety_context.offline {
        record_physical_run_event(
            slot,
            "offline.entered",
            &request.action_request.action,
            serde_json::json!({"node_id": node_id}),
        )?;
    }

    if request.safety_context.offline
        && request.safety_context.policy_cache_expired
        && request.safety_context.high_risk
    {
        record_physical_run_event(
            slot,
            "policy.cache.expired",
            &request.action_request.action,
            serde_json::json!({"policy_id": profile.policy_cache.policy_id, "action": action_name}),
        )?;
    }
    if let Some(evidence) = &request.operator_intervention_evidence {
        let expires_at = OffsetDateTime::parse(&evidence.expires_at, &Rfc3339).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "operator_intervention_bad_expiry",
                "operator intervention expiry is invalid",
            )
        })?;
        if expires_at <= OffsetDateTime::now_utc() {
            record_physical_run_event(
                slot,
                "operator.intervention.expired",
                &request.action_request.action,
                serde_json::json!({"intervention_id": evidence.intervention_id, "action": action_name}),
            )?;
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "operator_intervention_expired",
                "operator intervention evidence expired",
            ));
        }
        validate_operator_evidence(
            &state,
            evidence,
            &request.action_request.run_id,
            &action_name,
        )?;
    }

    record_physical_run_event(
        slot,
        "safety.verification.completed",
        &request.action_request.action,
        serde_json::json!({"allowed": true, "node_id": node_id}),
    )?;
    let action_request = ActionRequest {
        action_id: request.action_request.action_id.clone().unwrap_or_default(),
        tenant_id: request.action_request.tenant_id.clone(),
        agent_id: request.action_request.agent_id.clone(),
        run_id: request.action_request.run_id.clone(),
        action: request.action_request.action.clone(),
        adapter: request.action_request.adapter.clone(),
        quota_usage: request
            .action_request
            .quota_usage
            .unwrap_or_else(splendor_types::QuotaUsage::single_action),
        satisfied_preconditions: request.action_request.satisfied_preconditions.clone(),
        requested_at: OffsetDateTime::now_utc(),
        approval_evidence: request.action_request.approval_evidence.clone(),
        authority_obligation_evidence: None,
    };
    let mut physical_gateway = VerifiedActionGateway::new(Arc::new(slot.tenant_registry.clone()));
    physical_gateway.set_circuit_breaker_evaluator(Arc::new(slot.circuit_breakers.clone()));
    physical_gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(
        simulated_safety_snapshot(&request, &profile, &action_name),
    )));
    physical_gateway.register_adapter(
        action_name.clone(),
        action_request
            .adapter
            .clone()
            .unwrap_or_else(|| "device-sim".to_string()),
        Arc::new(RecordingAdapter {
            executions: Arc::clone(&slot.adapter_executions),
        }),
    );
    let physical_gateway: Arc<dyn ActionGateway> = Arc::new(PolicyDistributionGateway::new(
        Arc::new(physical_gateway),
        Arc::new(slot.policy_cache.clone()),
    ));
    let outcome = physical_gateway.submit(action_request).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_error",
            error.to_string(),
        )
    })?;
    if outcome.status == ActionStatus::Executed {
        record_run_event(
            slot,
            TraceEventKind::ActionExecuted {
                action: request.action_request.action.clone(),
                outcome: outcome.output.clone().unwrap_or(serde_json::Value::Null),
            },
        )?;
    } else {
        record_physical_denial(
            slot,
            &request.action_request.action,
            &outcome,
            "safety.verification.denied",
        )?;
    }
    record_run_event(
        slot,
        TraceEventKind::OutcomeRecorded {
            outcome: serde_json::json!({"source": "daemon.physical_action", "action_outcome": outcome}),
            feedback: None,
            reward: None,
        },
    )?;
    if request.safety_context.offline {
        record_physical_run_event(
            slot,
            "trace.buffer.appended",
            &request.action_request.action,
            serde_json::json!({"node_id": node_id, "action": action_name}),
        )?;
        record_physical_run_event(
            slot,
            "offline.exited",
            &request.action_request.action,
            serde_json::json!({"node_id": node_id}),
        )?;
    }
    Ok(Json(outcome))
}

async fn request_operator_intervention(
    State(state): State<DaemonState>,
    Json(request): Json<OperatorInterventionRequest>,
) -> Result<Json<OperatorInterventionRecord>, ApiError> {
    state.ensure_runtime_available()?;
    let security = state.validate_security(
        DaemonEndpoint::OperatorIntervene {
            tenant_id: request.tenant_id.clone(),
            run_id: request.run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution.clone(),
    )?;
    let trace_event_id = record_device_audit(
        &state,
        "operator.intervention.requested",
        required_audit(security.audit_attribution)?,
        serde_json::json!({"intervention_id": request.intervention_id, "run_id": request.run_id, "action": request.action_name, "reason": request.reason}),
    )?;
    let record = OperatorInterventionRecord {
        intervention_id: request.intervention_id.clone(),
        tenant_id: request.tenant_id,
        agent_id: request.agent_id,
        run_id: request.run_id,
        node_id: request.node_id,
        action_name: request.action_name,
        status: "requested".to_string(),
        reason: request.reason,
        expires_at: request.expires_at,
        trace_event_id,
        evidence: None,
    };
    state
        .inner
        .operator_interventions
        .lock()
        .map_err(|_| lock_error())?
        .insert(request.intervention_id, record.clone());
    Ok(Json(record))
}

async fn grant_operator_intervention(
    Path(intervention_id): Path<String>,
    State(state): State<DaemonState>,
    Json(request): Json<OperatorDecisionRequest>,
) -> Result<Json<OperatorInterventionRecord>, ApiError> {
    decide_operator_intervention(state, intervention_id, request, "granted").await
}

async fn deny_operator_intervention(
    Path(intervention_id): Path<String>,
    State(state): State<DaemonState>,
    Json(request): Json<OperatorDecisionRequest>,
) -> Result<Json<OperatorInterventionRecord>, ApiError> {
    decide_operator_intervention(state, intervention_id, request, "denied").await
}

async fn decide_operator_intervention(
    state: DaemonState,
    intervention_id: String,
    request: OperatorDecisionRequest,
    status: &str,
) -> Result<Json<OperatorInterventionRecord>, ApiError> {
    let mut interventions = state
        .inner
        .operator_interventions
        .lock()
        .map_err(|_| lock_error())?;
    let record = interventions.get_mut(&intervention_id).ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "operator_intervention_not_found",
            "operator intervention not found",
        )
    })?;
    let security = state.validate_security(
        DaemonEndpoint::OperatorIntervene {
            tenant_id: record.tenant_id.clone(),
            run_id: record.run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution.clone(),
    )?;
    let event = if status == "granted" {
        "operator.intervention.granted"
    } else {
        "operator.intervention.denied"
    };
    let trace_event_id = record_device_audit(
        &state,
        event,
        required_audit(security.audit_attribution)?,
        serde_json::json!({"intervention_id": intervention_id, "reason": request.reason}),
    )?;
    record.status = status.to_string();
    record.reason = request.reason;
    record.trace_event_id = trace_event_id;
    record.evidence = Some(OperatorInterventionEvidence {
        intervention_id: record.intervention_id.clone(),
        tenant_id: record.tenant_id.clone(),
        run_id: record.run_id.clone(),
        action_name: record.action_name.clone(),
        decision: if status == "granted" {
            "granted"
        } else {
            "denied"
        }
        .to_string(),
        expires_at: request
            .expires_at
            .unwrap_or_else(|| record.expires_at.clone()),
    });
    Ok(Json(record.clone()))
}

async fn sync_device_trace_buffer(
    Path(node_id): Path<NodeId>,
    State(state): State<DaemonState>,
    Json(request): Json<DeviceTraceBufferSyncRequest>,
) -> Result<Json<DeviceTraceBufferSyncResponse>, ApiError> {
    let profile = state
        .inner
        .device_profiles
        .lock()
        .map_err(|_| lock_error())?
        .get(&node_id)
        .cloned()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "device_not_registered",
                "device profile not registered",
            )
        })?;
    let security = state.validate_security(
        DaemonEndpoint::DeviceRead {
            tenant_id: profile.tenant_id,
            node_id: node_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    let audit_attribution = required_audit(security.audit_attribution)?;
    let mut expected = None;
    let mut expected_prev_hash = None;
    for record in &request.records {
        if let Some(prev) = expected {
            if record.sequence <= prev {
                let trace_event_id = record_device_audit(
                    &state,
                    "trace.sync.failed",
                    audit_attribution.clone(),
                    serde_json::json!({"node_id": node_id, "reason": "trace_sync_reordered"}),
                )?;
                return Ok(Json(DeviceTraceBufferSyncResponse {
                    accepted: false,
                    accepted_records: 0,
                    trace_event_id,
                    reason_code: Some("trace_sync_reordered".to_string()),
                }));
            }
        }
        if record.prev_event_hash != expected_prev_hash {
            let trace_event_id = record_device_audit(
                &state,
                "trace.sync.failed",
                audit_attribution.clone(),
                serde_json::json!({"node_id": node_id, "reason": "trace_sync_hash_chain_mismatch"}),
            )?;
            return Ok(Json(DeviceTraceBufferSyncResponse {
                accepted: false,
                accepted_records: 0,
                trace_event_id,
                reason_code: Some("trace_sync_hash_chain_mismatch".to_string()),
            }));
        }
        expected = Some(record.sequence);
        expected_prev_hash = Some(record.event_hash.clone());
    }
    if request.simulate_tamper {
        let trace_event_id = record_device_audit(
            &state,
            "trace.sync.failed",
            audit_attribution,
            serde_json::json!({"node_id": node_id, "reason": "trace_sync_tampered"}),
        )?;
        return Ok(Json(DeviceTraceBufferSyncResponse {
            accepted: false,
            accepted_records: 0,
            trace_event_id,
            reason_code: Some("trace_sync_tampered".to_string()),
        }));
    }
    let trace_event_id = record_device_audit(
        &state,
        "trace.sync.completed",
        audit_attribution,
        serde_json::json!({"node_id": node_id, "accepted_records": request.records.len()}),
    )?;
    Ok(Json(DeviceTraceBufferSyncResponse {
        accepted: true,
        accepted_records: request.records.len(),
        trace_event_id,
        reason_code: None,
    }))
}

fn validate_device_profile_payload(profile: &DeviceRuntimeProfile) -> Result<(), ApiError> {
    if profile.device_kind != "drone_sim" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_device_kind",
            "S6 acceptance supports drone_sim only",
        ));
    }
    if profile.runtime_mode != "resident" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "device_requires_resident_runtime",
            "physical edge acceptance requires resident runtime mode",
        ));
    }
    for action in &profile.allowed_physical_actions {
        if matches_forbidden_physical_action(action) || !is_allowed_physical_action(action) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "low_level_physical_action_rejected",
                "device profile contains unsupported physical action",
            ));
        }
    }
    Ok(())
}

fn matches_forbidden_physical_action(action: &str) -> bool {
    let normalized = action
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    FORBIDDEN_PHYSICAL_ACTION_PATTERNS
        .iter()
        .any(|pattern| normalized.contains(pattern))
}

fn simulated_safety_snapshot(
    request: &SubmitPhysicalActionRequest,
    profile: &DeviceRuntimeProfile,
    action_name: &str,
) -> SimulatedSafetySnapshot {
    let is_safe_low_battery_action = matches!(
        action_name,
        "return_to_base" | "dock" | "read_battery" | "read_sensor_summary"
    );
    let configured_min_battery = profile
        .safety_constraints
        .get("min_battery_percent")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.20);
    SimulatedSafetySnapshot {
        current_zone: request.safety_context.zone_ref.clone(),
        allowed_zones: request.safety_context.allowed_zone_refs.clone(),
        battery_percent: request.safety_context.battery_percent,
        min_battery_percent: Some(if is_safe_low_battery_action {
            0.0
        } else {
            configured_min_battery
        }),
        policy_cache_expired: request.safety_context.policy_cache_expired,
        high_risk: request.safety_context.high_risk,
        cloud_helper_direct_authority: request.safety_context.cloud_helper_direct_authority,
        emergency_stop_engaged: Some(!request.safety_context.emergency_stop_clear),
        collision_risk: Some(SimulatedRiskLevel::Low),
        altitude_m: request.safety_context.altitude_m,
        max_altitude_m: request.safety_context.max_altitude_m,
        privacy_zone_active: Some(!request.safety_context.privacy_clear),
        proximity_m: Some(if request.safety_context.human_proximity_clear {
            2.0
        } else {
            0.0
        }),
        min_proximity_m: Some(1.0),
        sensor_refs: vec![profile.node_id.to_string()],
    }
}

fn record_physical_denial(
    slot: &RunSlot,
    action: &Action,
    outcome: &ActionOutcome,
    event_type: &str,
) -> Result<(), ApiError> {
    record_physical_run_event(
        slot,
        event_type,
        action,
        serde_json::json!({"verification": outcome.verification, "status": outcome.status}),
    )?;
    match outcome.status {
        ActionStatus::NeedsIntervention => record_run_event(
            slot,
            TraceEventKind::ActionNeedsIntervention {
                action: action.clone(),
                result: outcome.verification.clone(),
            },
        ),
        _ => record_run_event(
            slot,
            TraceEventKind::ActionDenied {
                action: action.clone(),
                result: outcome.verification.clone(),
            },
        ),
    }
}

fn record_physical_run_event(
    slot: &RunSlot,
    event_type: &str,
    _action: &Action,
    details: serde_json::Value,
) -> Result<String, ApiError> {
    let _ = details;
    let trace_id = record_run_event_returning_id(
        slot,
        TraceEventKind::DaemonAudit {
            endpoint: event_type.to_string(),
            audit: AuditAttribution {
                principal: ClientPrincipal {
                    app: AppPrincipal {
                        app_principal_id: "runtime_physical_edge".to_string(),
                        label: Some("runtime physical edge".to_string()),
                    },
                    client_principal_id: "runtime_physical_edge".to_string(),
                    label: Some("runtime physical edge".to_string()),
                },
                credential_id: Some("runtime_physical_edge".to_string()),
                requested_at: OffsetDateTime::now_utc(),
            },
        },
    )?;
    Ok(trace_id.to_string())
}

fn record_device_audit(
    state: &DaemonState,
    event_type: &str,
    audit: AuditAttribution,
    details: serde_json::Value,
) -> Result<String, ApiError> {
    let event_id = uuid::Uuid::new_v4().to_string();
    state
        .inner
        .device_audit
        .lock()
        .map_err(|_| lock_error())?
        .push(DeviceAuditEvent {
            trace_event_id: event_id.clone(),
            event_type: event_type.to_string(),
            audit,
            details,
            timestamp: now_rfc3339(),
        });
    Ok(event_id)
}

fn required_audit(audit: Option<AuditAttribution>) -> Result<AuditAttribution, ApiError> {
    audit.ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "missing_audit_attribution",
            "mutating physical/edge request requires audit attribution",
        )
    })
}

fn validate_operator_evidence(
    state: &DaemonState,
    evidence: &OperatorInterventionEvidence,
    run_id: &RunId,
    action_name: &str,
) -> Result<(), ApiError> {
    let interventions = state
        .inner
        .operator_interventions
        .lock()
        .map_err(|_| lock_error())?;
    let record = interventions
        .get(&evidence.intervention_id)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "operator_intervention_unknown",
                "operator intervention evidence is unknown",
            )
        })?;
    if &record.run_id != run_id
        || record.action_name != action_name
        || record.status != "granted"
        || evidence.decision != "granted"
        || evidence.run_id != *run_id
        || evidence.action_name != action_name
        || evidence.tenant_id != record.tenant_id
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "operator_intervention_scope_mismatch",
            "operator intervention evidence is outside scope",
        ));
    }
    let expires_at = OffsetDateTime::parse(&evidence.expires_at, &Rfc3339).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "operator_intervention_bad_expiry",
            "operator intervention expiry is invalid",
        )
    })?;
    if expires_at <= OffsetDateTime::now_utc() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "operator_intervention_expired",
            "operator intervention evidence expired",
        ));
    }
    Ok(())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn caller_credential_from_headers(
    headers: &HeaderMap,
) -> Result<Option<CallerCredential>, ApiError> {
    let Some(value) = headers.get("x-splendor-caller-credential") else {
        return Ok(None);
    };
    let raw = value.to_str().map_err(|_| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_caller_credential_header",
            "x-splendor-caller-credential must be valid UTF-8 JSON",
        )
    })?;
    serde_json::from_str(raw)
        .or_else(|_| caller_credential_from_public_header_json(raw))
        .map(Some)
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_caller_credential_header",
                "x-splendor-caller-credential did not match CallerCredential schema",
            )
        })
}

fn caller_credential_from_public_header_json(
    raw: &str,
) -> Result<CallerCredential, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    let tenant_id = value
        .pointer("/binding/tenant/tenant_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|raw| TenantId::parse(raw).ok())
        .ok_or_else(|| serde_json::Error::custom("missing tenant binding"))?;
    let daemon_id = value
        .pointer("/audience/daemon/daemon_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| serde_json::Error::custom("missing daemon audience"))?
        .to_string();
    let expires_at = value
        .get("expires_at")
        .and_then(serde_json::Value::as_str)
        .and_then(|raw| OffsetDateTime::parse(raw, &Rfc3339).ok())
        .ok_or_else(|| serde_json::Error::custom("invalid expires_at"))?;
    let scopes = value
        .get("scopes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| serde_json::Error::custom("missing scopes"))?
        .iter()
        .map(|scope| {
            scope
                .as_str()
                .and_then(endpoint_scope_from_public_str)
                .ok_or_else(|| serde_json::Error::custom("invalid scope"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let revocation = match value.get("revocation") {
        Some(serde_json::Value::String(status)) if status == "active" => RevocationStatus::Active,
        Some(serde_json::Value::Object(status)) => {
            let reason = status
                .get("revoked")
                .and_then(|revoked| revoked.get("reason"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| serde_json::Error::custom("invalid revocation"))?
                .to_string();
            RevocationStatus::Revoked { reason }
        }
        _ => return Err(serde_json::Error::custom("invalid revocation")),
    };
    Ok(CallerCredential {
        credential_id: value
            .get("credential_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde_json::Error::custom("missing credential_id"))?
            .to_string(),
        principal: ClientPrincipal {
            app: AppPrincipal {
                app_principal_id: value
                    .pointer("/principal/app/app_principal_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| serde_json::Error::custom("missing app principal"))?
                    .to_string(),
                label: value
                    .pointer("/principal/app/label")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string),
            },
            client_principal_id: value
                .pointer("/principal/client_principal_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| serde_json::Error::custom("missing client principal"))?
                .to_string(),
            label: value
                .pointer("/principal/label")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string),
        },
        scopes,
        binding: CredentialBinding::Tenant { tenant_id },
        audience: CredentialAudience::Daemon { daemon_id },
        expires_at,
        revocation,
    })
}

fn endpoint_scope_from_public_str(scope: &str) -> Option<EndpointScope> {
    match scope {
        "runs_create" | "splendor.runs.create" => Some(EndpointScope::RunsCreate),
        "runs_start" | "splendor.runs.start" => Some(EndpointScope::RunsStart),
        "runs_read" | "splendor.runs.read" => Some(EndpointScope::RunsRead),
        "runs_pause" | "splendor.runs.pause" => Some(EndpointScope::RunsPause),
        "runs_resume" | "splendor.runs.resume" => Some(EndpointScope::RunsResume),
        "runs_stop" | "splendor.runs.stop" | "splendor.runs.cancel" => {
            Some(EndpointScope::RunsStop)
        }
        "percepts_append" | "splendor.percepts.append" => Some(EndpointScope::PerceptsAppend),
        "actions_submit" | "splendor.actions.submit" => Some(EndpointScope::ActionsSubmit),
        "traces_read" | "splendor.traces.read" => Some(EndpointScope::TracesRead),
        "state_read" | "splendor.state.read" => Some(EndpointScope::StateRead),
        "replay_create" | "splendor.replay.create" | "splendor.replay.run" => {
            Some(EndpointScope::ReplayCreate)
        }
        "messages_send" | "splendor.messages.send" => Some(EndpointScope::MessagesSend),
        "messages_read" | "splendor.messages.read" => Some(EndpointScope::MessagesRead),
        "work_orders_submit" | "splendor.work_orders.submit" => {
            Some(EndpointScope::WorkOrdersSubmit)
        }
        "work_orders_revoke" | "splendor.work_orders.revoke" => {
            Some(EndpointScope::WorkOrdersRevoke)
        }
        "fleet_read" | "splendor.fleet.read" => Some(EndpointScope::FleetRead),
        "fleet_dispatch" | "splendor.fleet.dispatch" => Some(EndpointScope::FleetDispatch),
        "state_handoff" | "splendor.state.handoff" => Some(EndpointScope::StateHandoff),
        "health_read" | "splendor.health.read" => Some(EndpointScope::HealthRead),
        "capabilities_read" | "splendor.capabilities.read" => Some(EndpointScope::CapabilitiesRead),
        "policies_sync" | "splendor.policies.sync" => Some(EndpointScope::PoliciesSync),
        "nodes_register" | "splendor.nodes.register" | "splendor.fleet.register" => {
            Some(EndpointScope::NodesRegister)
        }
        "instances_register" | "splendor.instances.register" => {
            Some(EndpointScope::InstancesRegister)
        }
        "nodes_heartbeat" | "splendor.nodes.heartbeat" => Some(EndpointScope::NodesHeartbeat),
        "instances_heartbeat" | "splendor.instances.heartbeat" => {
            Some(EndpointScope::InstancesHeartbeat)
        }
        "device_register" | "splendor.device.register" => Some(EndpointScope::DeviceRegister),
        "device_read" | "splendor.device.read" => Some(EndpointScope::DeviceRead),
        "operator_intervene" | "splendor.operator.intervene" => {
            Some(EndpointScope::OperatorIntervene)
        }
        _ => None,
    }
}

async fn health(
    State(state): State<DaemonState>,
    headers: HeaderMap,
) -> Result<Json<HealthResponse>, ApiError> {
    let credential = caller_credential_from_headers(&headers)?;
    state.validate_security(DaemonEndpoint::Health, credential, None, None)?;
    let runtime_available = state.inner.runtime_available.load(Ordering::SeqCst);
    Ok(Json(HealthResponse {
        status: if runtime_available {
            "ok"
        } else {
            "unavailable"
        }
        .to_string(),
        local_only: true,
        runtime_available,
    }))
}

async fn version(
    State(state): State<DaemonState>,
    headers: HeaderMap,
) -> Result<Json<VersionResponse>, ApiError> {
    let credential = caller_credential_from_headers(&headers)?;
    state.validate_security(DaemonEndpoint::Health, credential, None, None)?;
    Ok(Json(VersionResponse {
        daemon_api_version: "0.02-S5".to_string(),
        compatibility_line: "0.1".to_string(),
        openapi_version: "0.03-dev".to_string(),
        local_only: true,
        schema_versions: vec![
            splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
            splendor_types::POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
            splendor_types::APPROVAL_EVIDENCE_SCHEMA_VERSION.to_string(),
        ],
    }))
}

async fn capabilities(
    State(state): State<DaemonState>,
    headers: HeaderMap,
) -> Result<Json<CapabilitiesResponse>, ApiError> {
    let credential = caller_credential_from_headers(&headers)?;
    state.validate_security(DaemonEndpoint::Capabilities, credential, None, None)?;
    let run_endpoints = vec![
        "POST /runs".to_string(),
        "GET /runs/{run_id}".to_string(),
        "POST /runs/{run_id}/start".to_string(),
        "POST /runs/{run_id}/pause".to_string(),
        "POST /runs/{run_id}/resume".to_string(),
        "POST /runs/{run_id}/stop".to_string(),
        "POST /runs/{run_id}/cancel".to_string(),
        "POST /runs/{run_id}/percepts".to_string(),
        "POST /runs/{run_id}/policies/sync".to_string(),
        "GET /runs/{run_id}/state-head".to_string(),
        "GET /runs/{run_id}/traces".to_string(),
        "POST /runs/{run_id}/traces/export".to_string(),
        "POST /runs/{run_id}/replay".to_string(),
        "POST /actions".to_string(),
    ];
    let device_endpoints = vec![
        "POST /devices/profiles".to_string(),
        "GET /devices/{node_id}/status".to_string(),
        "GET /devices/{node_id}/policy-cache".to_string(),
        "POST /devices/{node_id}/actions".to_string(),
        "POST /operator/interventions".to_string(),
        "POST /operator/interventions/{intervention_id}/grant".to_string(),
        "POST /operator/interventions/{intervention_id}/deny".to_string(),
        "POST /devices/{node_id}/trace-buffer/sync".to_string(),
    ];
    let metadata_endpoints = [
        "GET /health".to_string(),
        "GET /version".to_string(),
        "GET /capabilities".to_string(),
    ];
    let endpoints = run_endpoints
        .iter()
        .chain(device_endpoints.iter())
        .chain(metadata_endpoints.iter())
        .cloned()
        .collect();
    Ok(Json(CapabilitiesResponse {
        daemon_api_version: "0.02-S5".to_string(),
        local_only: true,
        replay_modes: vec!["inspect_only".to_string()],
        endpoints,
        service_profiles: vec![
            ServiceCapabilityProfile {
                name: "runtime_daemon_local".to_string(),
                status: "implemented".to_string(),
                maturity: "local_0_1_compat".to_string(),
                endpoints: run_endpoints,
                notes: vec![
                    "current local daemon run/percept/state/trace/replay/action compatibility surface"
                        .to_string(),
                    "POST /runs requires request_id and idempotency_key with bounded create-run idempotency v0"
                        .to_string(),
                ],
            },
            ServiceCapabilityProfile {
                name: "physical_device_simulation".to_string(),
                status: "simulated".to_string(),
                maturity: "local_simulation_only".to_string(),
                endpoints: device_endpoints,
                notes: vec![
                    "high-level physical action simulation and trace-buffer surfaces only".to_string(),
                    "not a production robotics safety certification or low-level controller".to_string(),
                ],
            },
            ServiceCapabilityProfile {
                name: "create_run_idempotency_v0".to_string(),
                status: "experimental".to_string(),
                maturity: "bounded_current_endpoint".to_string(),
                endpoints: vec!["POST /runs".to_string()],
                notes: vec![
                    "partial FND-010 evidence for create-run only; no all-mutating-endpoint rollout"
                        .to_string(),
                ],
            },
            ServiceCapabilityProfile {
                name: "v2_watch_streams".to_string(),
                status: "unavailable".to_string(),
                maturity: "not_implemented".to_string(),
                endpoints: Vec::new(),
                notes: vec![
                    "event/workload/feedback/eval/training/change/deployment watch streams are not implemented in this daemon"
                        .to_string(),
                ],
            },
            ServiceCapabilityProfile {
                name: "gold_g00_g06".to_string(),
                status: "unavailable".to_string(),
                maturity: "not_exercised".to_string(),
                endpoints: Vec::new(),
                notes: vec![
                    "capability reporting is partial evidence only and does not claim G00 or G06 pass"
                        .to_string(),
                ],
            },
        ],
    }))
}

#[derive(Clone, Copy)]
enum LifecycleKind {
    Start,
    Resume,
}

async fn run_lifecycle_tick(
    state: DaemonState,
    run_id: RunId,
    request: LifecycleRequest,
    kind: LifecycleKind,
    success_status: RunStatus,
) -> Result<Json<TickResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let mut runs = state.inner.runs.lock().map_err(|_| lock_error())?;
    let slot = runs.get_mut(&run_id).ok_or_else(|| invalid_run(&run_id))?;
    let endpoint = match kind {
        LifecycleKind::Start => DaemonEndpoint::RunStart {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        LifecycleKind::Resume => DaemonEndpoint::RunResume {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
    };
    let security_work_order = if matches!(kind, LifecycleKind::Resume) {
        let envelope = request.work_order.as_ref().ok_or_else(|| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "missing_work_order",
                "resume requires a signed work order envelope",
            )
        })?;
        validate_daemon_work_order(
            &state,
            envelope,
            &slot.tenant_id,
            &slot.agent_id,
            Some(run_id.clone()),
            None,
        )?;
        Some(work_order_authorization_for_endpoint(
            envelope,
            vec![splendor_types::EndpointScope::RunsResume],
        ))
    } else {
        None
    };
    let security = state.validate_security(
        endpoint,
        request.credential,
        security_work_order,
        request.audit_attribution,
    )?;
    if matches!(kind, LifecycleKind::Resume)
        && !matches!(
            slot.status,
            RunStatus::Paused | RunStatus::WaitingForApproval
        )
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "invalid_run_state",
            "run must be paused or waiting for approval before resume",
        ));
    }
    if matches!(kind, LifecycleKind::Resume)
        && slot.status == RunStatus::WaitingForApproval
        && request.approval_evidence.is_none()
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "approval_required",
            "resume from waiting_for_approval requires approval evidence",
        ));
    }
    if matches!(
        slot.status,
        RunStatus::Completed
            | RunStatus::Cancelled
            | RunStatus::Failed
            | RunStatus::Denied
            | RunStatus::Expired
    ) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "invalid_run_state",
            "terminal runs cannot be started",
        ));
    }
    let endpoint = match kind {
        LifecycleKind::Start => "splendor.runs.start",
        LifecycleKind::Resume => "splendor.runs.resume",
    };
    record_daemon_audit(slot, endpoint, security.audit_attribution)?;
    if matches!(kind, LifecycleKind::Resume) {
        record_run_event(
            slot,
            TraceEventKind::RunResumed {
                reason: request.reason,
            },
        )?;
    }
    if let Some(evidence) = request.approval_evidence {
        slot.approval_evidence
            .set(evidence)
            .map_err(ApiError::from)?;
    }
    let step = match slot.scheduler.run_once() {
        Ok(step) => step,
        Err(error) => {
            slot.status = RunStatus::Failed;
            slot.updated_at = OffsetDateTime::now_utc();
            return Err(ApiError::from(error));
        }
    };
    slot.state_head = Some(step.outcome.state_commit.node_id.clone());
    slot.tick_count = slot.tick_count.saturating_add(1);
    if let Some(outcome) = step
        .outcome
        .action_outcomes
        .iter()
        .find(|outcome| outcome.status == ActionStatus::NeedsApproval)
    {
        slot.pending_approval =
            approval_artifact(&outcome.verification).map(|(_, approval)| approval);
        record_run_event(
            slot,
            TraceEventKind::RunPaused {
                reason: Some("waiting_for_approval".to_string()),
            },
        )?;
        slot.status = RunStatus::WaitingForApproval;
    } else if let Some(outcome) = step.outcome.action_outcomes.iter().find(|outcome| {
        outcome.status == ActionStatus::Denied && approval_artifact(&outcome.verification).is_some()
    }) {
        update_status_for_approval_denial(slot, outcome);
    } else if step.outcome.needs_intervention {
        slot.status = RunStatus::Failed;
    } else {
        slot.pending_approval = None;
        slot.status = success_status;
    }
    slot.updated_at = OffsetDateTime::now_utc();
    Ok(Json(TickResponse {
        run_id,
        status: slot.status.clone(),
        tick_id: step.tick_id,
        state_node_id: step.outcome.state_commit.node_id.to_string(),
        action_outcomes: step.outcome.action_outcomes,
    }))
}

fn registrations_for_request(
    request: &CreateRunRequest,
    work_order: &WorkOrder,
) -> Vec<RegisteredAction> {
    let mut registrations = request.registered_actions.clone();
    let fallback_adapter = work_order
        .allowed_adapters
        .first()
        .cloned()
        .unwrap_or_else(|| "daemon.local".to_string());
    for action_name in &work_order.allowed_actions {
        if registrations.iter().all(|entry| &entry.name != action_name) {
            registrations.push(RegisteredAction {
                name: action_name.clone(),
                adapter: fallback_adapter.clone(),
            });
        }
    }
    for action in &request.policy_actions {
        if registrations
            .iter()
            .all(|entry| entry.name != action.action.name)
        {
            registrations.push(RegisteredAction {
                name: action.action.name.clone(),
                adapter: action
                    .adapter
                    .clone()
                    .unwrap_or_else(|| fallback_adapter.clone()),
            });
        }
    }
    registrations
}

fn encode_initial_state(value: Option<serde_json::Value>) -> Result<StateData, ApiError> {
    let payload = value.unwrap_or_else(|| serde_json::json!({}));
    let bytes = serde_json::to_vec(&payload).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "malformed_initial_state",
            error.to_string(),
        )
    })?;
    Ok(StateData {
        bytes,
        content_type: Some("application/json".to_string()),
    })
}

fn inspect_response(slot: &RunSlot) -> RunInspectResponse {
    RunInspectResponse {
        run_id: slot.run_id.clone(),
        tenant_id: slot.tenant_id.clone(),
        agent_id: slot.agent_id.clone(),
        status: slot.status.clone(),
        state_head: slot.state_head.as_ref().map(ToString::to_string),
        ticks: slot.tick_count,
        adapter_executions: slot.adapter_executions.load(Ordering::SeqCst),
        policy_bundle: slot.policy_cache.snapshot().bundle,
        created_at: slot.created_at,
        updated_at: slot.updated_at,
    }
}

fn policy_cache_response(cache: &PolicyCache) -> PolicyCacheStatusResponse {
    let snapshot = cache.snapshot();
    PolicyCacheStatusResponse {
        enforcement_required: snapshot.enforcement_required,
        disconnected: snapshot.disconnected,
        policy_bundle: snapshot.bundle,
        revoked_reason: snapshot.revoked_reason,
        last_sync_failure: snapshot.last_sync_failure.map(|failure| failure.reason),
    }
}

fn record_run_event(slot: &RunSlot, kind: TraceEventKind) -> Result<(), ApiError> {
    slot.scheduler
        .record_event_for_agent(&slot.agent_id, kind)
        .map(|_| ())
        .map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trace_error",
                error.to_string(),
            )
        })
}

fn record_run_event_returning_id(
    slot: &RunSlot,
    kind: TraceEventKind,
) -> Result<TraceEventId, ApiError> {
    slot.scheduler
        .record_event_for_agent(&slot.agent_id, kind)
        .map(|event| event.trace_event_id)
        .map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trace_error",
                error.to_string(),
            )
        })
}

fn record_approval_event_if_present(
    slot: &RunSlot,
    outcome: &ActionOutcome,
) -> Result<(), ApiError> {
    let Some((status, approval)) = approval_artifact(&outcome.verification) else {
        return Ok(());
    };
    record_run_event(slot, approval_trace_kind(status.as_str(), approval))
}

fn update_status_for_approval_denial(slot: &mut RunSlot, outcome: &ActionOutcome) {
    let Some((status, _approval)) = approval_artifact(&outcome.verification) else {
        return;
    };
    slot.status = match status.as_str() {
        "expired" => RunStatus::Expired,
        "denied" | "revoked" | "schema_unsupported" => RunStatus::Denied,
        _ => slot.status.clone(),
    };
}

fn approval_artifact(
    result: &splendor_types::VerificationResult,
) -> Option<(String, ApprovalTraceContext)> {
    let artifact = result
        .artifacts
        .get("approval")
        .or_else(|| result.artifacts.get("approval_context"))?;
    let (status, approval_value) = if artifact.get("approval").is_some() {
        (
            artifact
                .get("approval_status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            artifact.get("approval")?,
        )
    } else {
        (
            result
                .artifacts
                .get("approval_status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            artifact,
        )
    };
    serde_json::from_value::<ApprovalTraceContext>(approval_value.clone())
        .ok()
        .map(|approval| (status, approval))
}

fn approval_trace_kind(status: &str, approval: ApprovalTraceContext) -> TraceEventKind {
    match status {
        "required" => TraceEventKind::ApprovalRequested { approval },
        "granted" => TraceEventKind::ApprovalGranted { approval },
        "expired" => TraceEventKind::ApprovalExpired {
            approval,
            reason: "approval_expired".to_string(),
        },
        "revoked" => TraceEventKind::ApprovalRevoked {
            approval,
            reason: "approval_revoked".to_string(),
        },
        "intervention_required" => TraceEventKind::ApprovalDenied {
            approval,
            reason: "approval_policy_expired".to_string(),
        },
        "policy_schema_unsupported" => TraceEventKind::ApprovalDenied {
            approval,
            reason: "approval_policy_schema_unsupported".to_string(),
        },
        "schema_unsupported" => TraceEventKind::ApprovalDenied {
            approval,
            reason: "approval_evidence_schema_unsupported".to_string(),
        },
        _ => TraceEventKind::ApprovalDenied {
            approval,
            reason: "approval_denied".to_string(),
        },
    }
}

fn approval_replay_event(event: TraceEvent) -> Option<ApprovalReplayEvent> {
    let (lifecycle, approval, reason) = match event.kind {
        TraceEventKind::ApprovalRequested { approval } => ("requested", approval, None),
        TraceEventKind::ApprovalGranted { approval } => ("granted", approval, None),
        TraceEventKind::ApprovalDenied { approval, reason } => ("denied", approval, Some(reason)),
        TraceEventKind::ApprovalExpired { approval, reason } => ("expired", approval, Some(reason)),
        TraceEventKind::ApprovalRevoked { approval, reason } => ("revoked", approval, Some(reason)),
        _ => return None,
    };
    Some(ApprovalReplayEvent {
        lifecycle: lifecycle.to_string(),
        approval,
        reason,
        trace_event_id: event.trace_event_id,
        sequence: event.sequence,
    })
}

fn record_daemon_audit(
    slot: &RunSlot,
    endpoint: &'static str,
    audit: Option<AuditAttribution>,
) -> Result<(), ApiError> {
    let audit = audit.ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing_audit_attribution",
            "validated mutating daemon call did not return audit attribution",
        )
    })?;
    record_run_event(
        slot,
        TraceEventKind::DaemonAudit {
            endpoint: endpoint.to_string(),
            audit,
        },
    )
}

fn validate_trace_order(records: &[TraceRecord], run_id: &RunId) -> Result<(), ApiError> {
    for (expected, record) in records.iter().enumerate() {
        if record.run_id != run_id.to_string() || record.sequence != expected as u64 {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "trace_order_invalid",
                "trace records are not contiguous for replay",
            ));
        }
    }
    Ok(())
}

fn trace_export_integrity_hash(records: &[TraceRecord]) -> String {
    let last_event_hash = records
        .last()
        .map(|record| record.event_hash.to_string())
        .unwrap_or_else(|| "empty".to_string());
    format!("trace-chain:v1:{}:{last_event_hash}", records.len())
}

fn redact_trace_records(records: Vec<TraceRecord>) -> Vec<TraceRecord> {
    records
        .into_iter()
        .map(|mut record| {
            record.payload = redact_trace_value(record.payload);
            record
        })
        .collect()
}

fn redact_trace_value(value: serde_json::Value) -> serde_json::Value {
    redact_trace_value_inner(value)
}

fn redact_trace_value_inner(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(redact_trace_value_inner).collect())
        }
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, value) in map {
                let redacted_value = if is_trace_sensitive_key(&key) {
                    redact_sensitive_trace_field_value(value)
                } else {
                    redact_trace_value_inner(value)
                };
                redacted.insert(key, redacted_value);
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::String(value) => {
            if let Some(label) = protected_visibility_label(&value) {
                serde_json::Value::String(format!("[REDACTED:{label}]"))
            } else if is_trace_sensitive_text(&value) {
                serde_json::Value::String("[REDACTED]".to_string())
            } else {
                serde_json::Value::String(value)
            }
        }
        other => other,
    }
}

fn redact_sensitive_trace_field_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, value) in map {
                redacted.insert(key, redact_sensitive_trace_field_value(value));
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(_) => serde_json::Value::String("[REDACTED]".to_string()),
        serde_json::Value::String(value) => {
            if let Some(label) = protected_visibility_label(&value) {
                serde_json::Value::String(format!("[REDACTED:{label}]"))
            } else {
                serde_json::Value::String("[REDACTED]".to_string())
            }
        }
        serde_json::Value::Null => serde_json::Value::Null,
        _ => serde_json::Value::String("[REDACTED]".to_string()),
    }
}

fn is_trace_sensitive_key(key: &str) -> bool {
    if is_trace_identity_reason_or_status_key(key) {
        return false;
    }
    let normalized = key.to_ascii_lowercase();
    let compact = compact_trace_match_text(&normalized);
    [
        "secret",
        "token",
        "password",
        "credential",
        "authorization",
        "auth_header",
        "auth_key",
        "auth-key",
        "authz",
        "bearer",
        "jwt",
        "cookie",
        "set-cookie",
        "set_cookie",
        "session",
        "session_id",
        "client_secret",
        "refresh_token",
        "secret_ref",
        "signature",
        "private_key",
        "api_key",
        "access_key",
        "session_key",
        "state_bytes",
        "snapshot_bytes",
        "restricted",
        "protected_eval",
        "protected-eval",
        "safety_local",
        "safety-local",
        "legal_hold",
        "legal-hold",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
        || matches!(normalized.as_str(), "auth")
        || [
            "secret",
            "token",
            "password",
            "credential",
            "authorization",
            "authheader",
            "authkey",
            "authz",
            "bearer",
            "jwt",
            "cookie",
            "setcookie",
            "session",
            "sessionid",
            "clientsecret",
            "refreshtoken",
            "secretref",
            "signature",
            "privatekey",
            "apikey",
            "accesskey",
            "sessionkey",
            "statebytes",
            "snapshotbytes",
            "restricted",
            "protectedeval",
            "safetylocal",
            "legalhold",
        ]
        .iter()
        .any(|needle| compact.contains(needle))
}

fn is_trace_identity_reason_or_status_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "trace_event_id"
            | "trace_id"
            | "event_id"
            | "run_id"
            | "tenant_id"
            | "agent_id"
            | "runtime_context_id"
            | "tick_id"
            | "action_id"
            | "state_node_id"
            | "message_id"
            | "work_order_id"
            | "approval_id"
            | "artifact_id"
            | "sequence"
            | "kind"
            | "type"
            | "endpoint"
            | "schema"
            | "name"
            | "adapter"
            | "source"
            | "status"
            | "reason"
            | "reasons"
            | "reason_code"
            | "code"
            | "allowed"
            | "event_hash"
            | "prev_event_hash"
    )
}

fn is_trace_sensitive_text(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    let compact = compact_trace_match_text(&normalized);
    [
        "authorization:",
        "authorization=",
        "auth:",
        "auth=",
        "authz:",
        "authz=",
        "bearer ",
        "jwt:",
        "jwt=",
        "cookie:",
        "cookie=",
        "set-cookie:",
        "set-cookie=",
        "set_cookie:",
        "set_cookie=",
        "session:",
        "session=",
        "session_id:",
        "session_id=",
        "client_secret:",
        "client_secret=",
        "refresh_token:",
        "refresh_token=",
        "secret_ref:",
        "secret_ref=",
        "token:",
        "token=",
        "secret:",
        "secret=",
        "password:",
        "password=",
        "credential:",
        "credential=",
        "api_key:",
        "api_key=",
        "api-key:",
        "api-key=",
        "apikey:",
        "apikey=",
        "signature:",
        "signature=",
        "private_key:",
        "private_key=",
        "private-key:",
        "private-key=",
        "private key",
        "state_bytes:",
        "state_bytes=",
        "snapshot_bytes:",
        "snapshot_bytes=",
        "restricted:",
        "restricted=",
        "protected-eval:",
        "protected-eval=",
        "safety-local:",
        "safety-local=",
        "legal-hold:",
        "legal-hold=",
        "-----begin",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
        || [
            "authorization",
            "authheader",
            "authkey",
            "authz",
            "bearertoken",
            "jwt",
            "cookie",
            "setcookie",
            "sessionid",
            "accesstoken",
            "refreshtoken",
            "refreshjwt",
            "sessiontoken",
            "clientsecret",
            "secretref",
            "apikey",
            "privatekey",
            "statebytes",
            "snapshotbytes",
            "protectedeval",
            "safetylocal",
            "legalhold",
        ]
        .iter()
        .any(|needle| compact.contains(needle))
        || has_sensitive_plaintext_marker(value)
        || looks_like_trace_jwt(value)
}

fn has_sensitive_plaintext_marker(value: &str) -> bool {
    let words = value
        .split_whitespace()
        .map(|word| {
            word.trim_matches(|character: char| !character.is_ascii_alphanumeric())
                .to_ascii_lowercase()
        })
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    words.iter().any(|word| {
        matches!(
            word.as_str(),
            "authorization"
                | "auth"
                | "authz"
                | "bearer"
                | "token"
                | "secret"
                | "password"
                | "credential"
                | "signature"
                | "jwt"
                | "cookie"
                | "session"
        )
    }) || words.windows(2).any(|window| {
        matches!(
            (window[0].as_str(), window[1].as_str()),
            ("private", "key")
                | ("client", "secret")
                | ("refresh", "token")
                | ("secret", "ref")
                | ("set", "cookie")
                | ("state", "bytes")
                | ("snapshot", "bytes")
                | ("protected", "eval")
                | ("safety", "local")
                | ("legal", "hold")
        )
    })
}

fn protected_visibility_label(value: &str) -> Option<&'static str> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "restricted" => Some("restricted"),
        "secret" => Some("secret"),
        "protected-eval" => Some("protected-eval"),
        "safety-local" => Some("safety-local"),
        "legal-hold" => Some("legal-hold"),
        _ => None,
    }
}

fn looks_like_trace_jwt(value: &str) -> bool {
    let token = value.trim();
    let mut parts = token.split('.');
    let Some(header) = parts.next() else {
        return false;
    };
    let Some(payload) = parts.next() else {
        return false;
    };
    let Some(signature) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    [header, payload, signature].iter().all(|part| {
        part.len() >= 8
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

fn compact_trace_match_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect()
}

fn stable_json_hash(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv64:{hash:016x}")
}

fn trace_error(error: TraceStoreError) -> ApiError {
    match error {
        TraceStoreError::RunNotFound => ApiError::new(
            StatusCode::NOT_FOUND,
            "invalid_run",
            "run was not found in trace store",
        ),
        other => ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trace_store_error",
            other.to_string(),
        ),
    }
}

fn invalid_run(run_id: &RunId) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "invalid_run", "run was not found")
        .details(serde_json::json!({ "run_id": run_id }))
}

fn require_post_audit_attribution(
    credential: Option<&CallerCredential>,
    audit_attribution: Option<&AuditAttribution>,
) -> Result<(), ApiError> {
    let credential = credential.ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "missing_caller_credential",
            "mutating daemon requests require caller credential",
        )
    })?;
    let audit = audit_attribution.ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "missing_audit_attribution",
            "mutating daemon requests require audit attribution",
        )
    })?;
    if audit.credential_id.as_deref() != Some(credential.credential_id.as_str()) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "audit_credential_mismatch",
            "audit attribution credential_id must match caller credential",
        ));
    }
    if audit.principal != credential.principal {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "audit_principal_mismatch",
            "audit attribution principal must match caller credential principal",
        ));
    }
    Ok(())
}

fn lock_error() -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "runtime_lock_error",
        "local runtime lock is unavailable",
    )
}

fn policy_bundle_error(error: PolicyBundleValidationError) -> ApiError {
    let status = match &error {
        PolicyBundleValidationError::Expired
        | PolicyBundleValidationError::FutureIssued
        | PolicyBundleValidationError::Revoked { .. } => StatusCode::FORBIDDEN,
        PolicyBundleValidationError::Unsigned
        | PolicyBundleValidationError::UnknownKey { .. }
        | PolicyBundleValidationError::BadSignature
        | PolicyBundleValidationError::Malformed { .. }
        | PolicyBundleValidationError::Incompatible { .. } => StatusCode::BAD_REQUEST,
    };
    ApiError::new(status, error.reason_code(), error.reason_code())
}

fn policy_cache_install_error(error: PolicyCacheInstallError) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        error.reason_code(),
        error.reason_code(),
    )
}

fn policy_cache_mutation_error(error: PolicyCacheMutationError) -> ApiError {
    match error {
        PolicyCacheMutationError::Policy(error) => policy_cache_install_error(error),
        PolicyCacheMutationError::Trace(_) => ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trace_error",
            "required policy mutation trace evidence is unavailable",
        ),
    }
}

fn daemon_security_code(error: &DaemonSecurityError) -> &'static str {
    match error {
        DaemonSecurityError::AnonymousNonDevCall => "anonymous_non_dev_call",
        DaemonSecurityError::MissingScope { .. } => "missing_scope",
        DaemonSecurityError::WrongCredentialBinding => "wrong_credential_binding",
        DaemonSecurityError::WrongAudience => "wrong_audience",
        DaemonSecurityError::CredentialExpired => "credential_expired",
        DaemonSecurityError::CredentialRevoked { .. } => "credential_revoked",
        DaemonSecurityError::MissingWorkOrder => "missing_work_order",
        DaemonSecurityError::UnsignedWorkOrder => "unsigned_work_order",
        DaemonSecurityError::ExpiredWorkOrder => "expired_work_order",
        DaemonSecurityError::RevokedWorkOrder { .. } => "revoked_work_order",
        DaemonSecurityError::IncompatibleWorkOrder => "incompatible_work_order",
        DaemonSecurityError::MissingAuditAttribution => "missing_audit_attribution",
        DaemonSecurityError::AttributionMismatch => "attribution_mismatch",
        DaemonSecurityError::InvalidDevModeBinding => "invalid_dev_mode_binding",
        DaemonSecurityError::DisallowedPercept => "disallowed_percept",
        DaemonSecurityError::MissingTraceRedactionPolicy => "missing_trace_redaction_policy",
        DaemonSecurityError::ActionMissingTraceLink => "action_missing_trace_link",
        DaemonSecurityError::ActionGatewayBypassed => "action_gateway_bypassed",
        DaemonSecurityError::ClientInsecureFallback => "client_insecure_fallback",
        DaemonSecurityError::InvalidRegistryEndpoint => "invalid_registry_endpoint",
    }
}

/// Helper for docs/examples that builds a simple percept payload.
pub fn local_percept(schema: impl Into<String>, payload: serde_json::Value) -> Percept {
    Percept {
        schema: schema.into(),
        payload,
        provenance: PerceptProvenance {
            source: "daemon-client-local".to_string(),
            detail: None,
        },
        timestamp: OffsetDateTime::now_utc(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Path;
    use splendor_store::{InMemoryTraceStore, TraceStore};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn unit_audit() -> AuditAttribution {
        AuditAttribution {
            principal: ClientPrincipal {
                app: AppPrincipal {
                    app_principal_id: "unit_app".to_string(),
                    label: Some("unit app".to_string()),
                },
                client_principal_id: "unit_client".to_string(),
                label: Some("unit client".to_string()),
            },
            credential_id: Some("unit_credential".to_string()),
            requested_at: OffsetDateTime::now_utc(),
        }
    }

    fn unit_profile(node_id: NodeId, tenant_id: TenantId) -> DeviceRuntimeProfile {
        DeviceRuntimeProfile {
            node_id,
            tenant_id: tenant_id.clone(),
            device_kind: "drone_sim".to_string(),
            capabilities: vec!["motion.waypoint".to_string(), "dock".to_string()],
            allowed_physical_actions: vec![
                "move_to_waypoint".to_string(),
                "return_to_base".to_string(),
                "dock".to_string(),
                "read_battery".to_string(),
            ],
            forbidden_action_classes: FORBIDDEN_PHYSICAL_ACTION_PATTERNS
                .iter()
                .map(|pattern| (*pattern).to_string())
                .collect(),
            safety_constraints: serde_json::json!({"min_battery_percent": 0.25}),
            runtime_mode: "resident".to_string(),
            safety_status: serde_json::json!({"emergency_stop_clear": true}),
            policy_cache: DevicePolicyCacheStatus {
                policy_id: "policy_unit".to_string(),
                loaded: true,
                ttl_seconds: 300,
                expires_at: now_rfc3339(),
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

    fn physical_action(name: &str) -> Action {
        Action {
            name: name.to_string(),
            params: serde_json::json!({"zone_ref": "zone_a"}),
            side_effect_class: splendor_types::SideEffectClass::Custom(
                "physical.high_level".to_string(),
            ),
            cost_estimate: None,
            required_permissions: vec!["device.motion".to_string()],
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        }
    }

    fn safe_context() -> SafetyContext {
        SafetyContext {
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
        }
    }

    async fn create_unit_run(
        state: &DaemonState,
        tenant_id: TenantId,
        agent_id: splendor_types::AgentId,
        run_id: RunId,
    ) {
        let work_order = WorkOrder {
            schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
            work_order_id: splendor_types::WorkOrderId::try_new("wo_unit_physical")
                .expect("work order id"),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: Some(run_id),
            objective: "unit physical run".to_string(),
            allowed_actions: vec![
                "move_to_waypoint".to_string(),
                "return_to_base".to_string(),
                "dock".to_string(),
                "read_battery".to_string(),
            ],
            allowed_adapters: vec!["device-sim".to_string()],
            allowed_permissions: vec!["device.motion".to_string()],
            data_refs: vec!["device:unit".to_string()],
            quotas: splendor_types::WorkOrderQuotaPolicy {
                max_actions_per_tick: Some(10),
                ..splendor_types::WorkOrderQuotaPolicy::default()
            },
            placement: splendor_types::WorkOrderPlacement::default(),
            issued_at: OffsetDateTime::now_utc() - time::Duration::minutes(1),
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            revocation: splendor_types::RevocationStatus::Active,
        };
        let request = CreateRunRequest {
            request_id: format!("req_{}", TraceId::new()),
            idempotency_key: format!("idem_{}", TraceId::new()),
            tenant_id,
            agent_id,
            work_order: WorkOrderEnvelope::signed_with_shared_secret(
                work_order,
                "work-order-local-key",
                b"splendor-local-work-order-secret",
            )
            .expect("signed work order"),
            credential: None,
            audit_attribution: Some(unit_audit()),
            allowed_actions: Vec::new(),
            allowed_adapters: Vec::new(),
            allowed_permissions: Vec::new(),
            policy_actions: Vec::new(),
            policy_bundle_required: false,
            policy_bundle: None,
            registered_actions: Vec::new(),
            approval_policies: Vec::new(),
            circuit_breakers: Vec::new(),
            allowed_percept_schemas: Vec::new(),
            allowed_percept_sources: Vec::new(),
            initial_state: None,
            snapshot_interval: None,
        };
        let _ = create_run(State(state.clone()), Json(request))
            .await
            .expect("create run");
    }

    fn unit_create_run_request(
        tenant_id: TenantId,
        agent_id: splendor_types::AgentId,
        run_id: Option<RunId>,
        work_order_id: &str,
        request_id: &str,
        idempotency_key: &str,
    ) -> CreateRunRequest {
        let work_order = WorkOrder {
            schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
            work_order_id: splendor_types::WorkOrderId::try_new(work_order_id)
                .expect("work order id"),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id,
            objective: "unit idempotent run".to_string(),
            allowed_actions: vec!["daemon.record".to_string()],
            allowed_adapters: vec!["daemon.local".to_string()],
            allowed_permissions: Vec::new(),
            data_refs: Vec::new(),
            quotas: splendor_types::WorkOrderQuotaPolicy::default(),
            placement: splendor_types::WorkOrderPlacement::default(),
            issued_at: OffsetDateTime::now_utc() - time::Duration::minutes(1),
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            revocation: splendor_types::RevocationStatus::Active,
        };
        CreateRunRequest {
            request_id: request_id.to_string(),
            idempotency_key: idempotency_key.to_string(),
            tenant_id,
            agent_id,
            work_order: WorkOrderEnvelope::signed_with_shared_secret(
                work_order,
                "work-order-local-key",
                b"splendor-local-work-order-secret",
            )
            .expect("signed work order"),
            credential: None,
            audit_attribution: Some(unit_audit()),
            allowed_actions: Vec::new(),
            allowed_adapters: Vec::new(),
            allowed_permissions: Vec::new(),
            policy_actions: Vec::new(),
            policy_bundle_required: false,
            policy_bundle: None,
            registered_actions: Vec::new(),
            approval_policies: Vec::new(),
            circuit_breakers: Vec::new(),
            allowed_percept_schemas: Vec::new(),
            allowed_percept_sources: Vec::new(),
            initial_state: None,
            snapshot_interval: None,
        }
    }

    fn physical_request(
        run_id: RunId,
        tenant_id: TenantId,
        agent_id: splendor_types::AgentId,
        action_name: &str,
        safety_context: SafetyContext,
    ) -> SubmitPhysicalActionRequest {
        SubmitPhysicalActionRequest {
            action_request: SubmitActionRequest {
                action_id: Some(ActionId::new()),
                run_id,
                tenant_id,
                agent_id,
                credential: None,
                audit_attribution: Some(unit_audit()),
                causal_trace_id: Some(TraceId::new()),
                action: physical_action(action_name),
                adapter: Some("device-sim".to_string()),
                quota_usage: Some(splendor_types::QuotaUsage::single_action()),
                satisfied_preconditions: Vec::new(),
                approval_evidence: None,
            },
            safety_context,
            operator_intervention_evidence: None,
        }
    }

    fn unit_action_request(action_name: &str) -> ActionRequest {
        ActionRequest {
            action_id: ActionId::new(),
            tenant_id: TenantId::new(),
            agent_id: splendor_types::AgentId::new(),
            run_id: RunId::new(),
            action: physical_action(action_name),
            adapter: Some("device-sim".to_string()),
            quota_usage: splendor_types::QuotaUsage::single_action(),
            satisfied_preconditions: Vec::new(),
            requested_at: OffsetDateTime::now_utc(),
            approval_evidence: None,
            authority_obligation_evidence: None,
        }
    }

    #[tokio::test]
    async fn create_run_idempotency_returns_same_receipt_without_duplicate_state() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let request = unit_create_run_request(
            tenant_id,
            agent_id,
            Some(run_id.clone()),
            "wo_unit_idem",
            "req_unit_idem",
            "idem_unit_create",
        );

        let first = create_run(State(state.clone()), Json(request.clone()))
            .await
            .expect("first create")
            .0;
        assert_eq!(first.run_id, run_id);
        assert!(!first.duplicate);
        assert_eq!(first.request_id, "req_unit_idem");
        assert_eq!(first.idempotency_key, "idem_unit_create");
        assert_eq!(
            state.inner.runs.lock().expect("runs").len(),
            1,
            "first create inserts one run"
        );

        let duplicate = create_run(State(state.clone()), Json(request))
            .await
            .expect("duplicate create")
            .0;
        assert_eq!(duplicate.run_id, first.run_id);
        assert_eq!(duplicate.status, first.status);
        assert_eq!(
            duplicate.idempotency_receipt_id,
            first.idempotency_receipt_id
        );
        assert!(duplicate.duplicate);
        assert_eq!(
            state.inner.runs.lock().expect("runs").len(),
            1,
            "duplicate idempotency request must not insert a second run"
        );
    }

    #[tokio::test]
    async fn create_run_idempotency_scope_mismatch_fails_without_second_run() {
        let state = DaemonState::local_dev();
        let first = unit_create_run_request(
            TenantId::new(),
            splendor_types::AgentId::new(),
            Some(RunId::new()),
            "wo_unit_idem_a",
            "req_unit_idem_a",
            "idem_unit_collision",
        );
        let _ = create_run(State(state.clone()), Json(first))
            .await
            .expect("first create");

        let different_scope = unit_create_run_request(
            TenantId::new(),
            splendor_types::AgentId::new(),
            Some(RunId::new()),
            "wo_unit_idem_b",
            "req_unit_idem_b",
            "idem_unit_collision",
        );
        let error = create_run(State(state.clone()), Json(different_scope))
            .await
            .expect_err("scope mismatch denied");
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.body.code, "create_run_idempotency_scope_mismatch");
        assert_eq!(
            error.body.details,
            serde_json::json!({
                "scope_mismatch": true,
                "category": "create_run_idempotency",
            }),
            "scope mismatch details must not leak attempted/existing scopes"
        );
        assert_eq!(
            state.inner.runs.lock().expect("runs").len(),
            1,
            "scope mismatch must not create a second run"
        );
    }

    #[tokio::test]
    async fn create_run_rejects_blank_idempotency_fields_before_mutation() {
        let state = DaemonState::local_dev();
        let blank_request_id = unit_create_run_request(
            TenantId::new(),
            splendor_types::AgentId::new(),
            Some(RunId::new()),
            "wo_unit_blank_request",
            "   ",
            "idem_blank_request",
        );
        let error = create_run(State(state.clone()), Json(blank_request_id))
            .await
            .expect_err("blank request id rejected");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.body.code, "missing_request_id");

        let blank_idempotency_key = unit_create_run_request(
            TenantId::new(),
            splendor_types::AgentId::new(),
            Some(RunId::new()),
            "wo_unit_blank_idem",
            "req_blank_idem",
            "\t",
        );
        let error = create_run(State(state.clone()), Json(blank_idempotency_key))
            .await
            .expect_err("blank idempotency key rejected");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.body.code, "missing_idempotency_key");
        assert!(
            state.inner.runs.lock().expect("runs").is_empty(),
            "blank idempotency validation must not mutate runs"
        );
        assert!(
            state
                .inner
                .create_run_idempotency
                .lock()
                .expect("idempotency ledger")
                .is_empty(),
            "blank idempotency validation must not poison the ledger"
        );
    }

    fn unit_daemon_action_request(
        tenant_id: TenantId,
        action_name: &str,
        params: serde_json::Value,
    ) -> ActionRequest {
        ActionRequest {
            action_id: ActionId::new(),
            tenant_id,
            agent_id: splendor_types::AgentId::new(),
            run_id: RunId::new(),
            action: Action {
                name: action_name.to_string(),
                params,
                side_effect_class: splendor_types::SideEffectClass::External,
                cost_estimate: None,
                required_permissions: vec![action_name.to_string()],
                preconditions: Vec::new(),
                postconditions: vec!["recorded".to_string()],
            },
            adapter: Some("artifact-store".to_string()),
            quota_usage: splendor_types::QuotaUsage::single_action(),
            satisfied_preconditions: Vec::new(),
            requested_at: OffsetDateTime::now_utc(),
            approval_evidence: None,
            authority_obligation_evidence: None,
        }
    }

    #[test]
    fn data_artifact_boundary_and_recording_adapter_cover_s7_paths() {
        std::env::remove_var("SPLENDOR_DEVICE_SIM_URL");
        let tenant_id = TenantId::new();
        let allowed_ref = "dataset:tenant-a.finance.board_pack.v1".to_string();
        let verifier =
            DataArtifactBoundaryVerifier::new(tenant_id.clone(), vec![allowed_ref.clone()]);

        let data_action = unit_daemon_action_request(
            tenant_id.clone(),
            "data.read_fixture",
            serde_json::json!({"data_ref": allowed_ref, "data_refs": ["dataset:tenant-a.finance.board_pack.v1"]}),
        );
        let allowed = verifier.verify_resource_boundary(&data_action, Some("fixture-data-store"));
        assert!(allowed.allowed);
        assert!(allowed
            .reasons
            .iter()
            .any(|reason| reason == "data_scope_verified"));

        let denied_data = unit_daemon_action_request(
            tenant_id.clone(),
            "data.read_fixture",
            serde_json::json!({"data_refs": ["dataset:tenant-b.finance.board_pack.v1"]}),
        );
        let denied = verifier.verify_resource_boundary(&denied_data, Some("fixture-data-store"));
        assert!(!denied.allowed);
        assert!(denied
            .reasons
            .iter()
            .any(|reason| reason == "data_scope_denied"));

        let artifact_mismatch = unit_daemon_action_request(
            tenant_id.clone(),
            "artifact.create_internal",
            serde_json::json!({"artifact_ref": "artifact://wrong-tenant/board.md"}),
        );
        let denied = verifier.verify_resource_boundary(&artifact_mismatch, Some("artifact-store"));
        assert!(!denied.allowed);
        assert!(denied
            .reasons
            .iter()
            .any(|reason| reason == "artifact_path_tenant_mismatch"));

        let executions = Arc::new(AtomicU64::new(0));
        let adapter = RecordingAdapter {
            executions: Arc::clone(&executions),
        };
        let data_output = adapter.execute(&data_action).expect("data output").output;
        assert_eq!(data_output["adapter"], "fixture-data-store");
        assert_eq!(data_output["raw_payload_included"], false);

        let internal_artifact = unit_daemon_action_request(
            tenant_id.clone(),
            "artifact.create_internal",
            serde_json::json!({"artifact_path": format!("artifact://{tenant_id}/board.md")}),
        );
        let output = adapter
            .execute(&internal_artifact)
            .expect("internal artifact output")
            .output;
        assert_eq!(output["adapter"], "artifact-store");
        assert_eq!(output["tenant_id"], tenant_id.to_string());

        let publish = unit_daemon_action_request(
            tenant_id,
            "artifact.publish_external",
            serde_json::json!({"publish_ref": "artifact://tenant-a/board.md"}),
        );
        let output = adapter.execute(&publish).expect("publish output").output;
        assert_eq!(output["published"], true);
        assert_eq!(output["external_store"], "fake-artifact-store");

        let generic = unit_daemon_action_request(
            TenantId::new(),
            "daemon.record",
            serde_json::json!({"note": "generic"}),
        );
        let output = adapter.execute(&generic).expect("generic output").output;
        assert_eq!(output["adapter"], "daemon.recording");
        assert_eq!(output["device_sim"], serde_json::Value::Null);

        let fail = unit_daemon_action_request(
            TenantId::new(),
            "artifact.create_internal",
            serde_json::json!({"fail_adapter": true}),
        );
        assert!(adapter.execute(&fail).is_err());
        assert_eq!(executions.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn resident_daemon_config_requires_authenticated_caller() {
        let instance_id = splendor_types::InstanceId::new();
        let config = DaemonConfig::resident(instance_id.clone());
        assert!(config.insecure_dev_mode.is_none());
        assert_eq!(
            config.expected_audience,
            CredentialAudience::Instance { instance_id }
        );

        let state = DaemonState::new(config);
        let denied = state
            .validate_security(DaemonEndpoint::Health, None, None, None)
            .expect_err("resident daemon must not accept anonymous requests");
        assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
        assert_eq!(denied.body.code, "anonymous_non_dev_call");
    }

    #[test]
    fn device_sim_url_parser_and_disabled_env_path_are_explicit() {
        assert_eq!(
            parse_http_host_port("http://device-sim:8086/path").expect("valid url"),
            ("device-sim".to_string(), 8086)
        );
        for invalid in [
            "https://device-sim:8086",
            "http://device-sim",
            "http://:8086",
            "http://device-sim:not-a-port",
        ] {
            assert!(parse_http_host_port(invalid).is_err());
        }
        std::env::remove_var("SPLENDOR_DEVICE_SIM_URL");
        assert!(
            submit_device_sim_action(&unit_action_request("read_battery"), 7)
                .expect("disabled simulator is allowed")
                .is_none()
        );
    }

    #[test]
    fn device_sim_submit_posts_gateway_executed_action_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind simulator");
        let addr = listener.local_addr().expect("simulator addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept simulator request");
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("set read timeout");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let bytes = stream.read(&mut buffer).expect("read simulator request");
                if bytes == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..bytes]);
                let text = String::from_utf8_lossy(&request);
                if text.contains("\"action_name\":\"inspect_zone\"")
                    && text.contains("\"adapter_execution\":42")
                {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("POST /actions HTTP/1.1"));
            assert!(request.contains("\"action_name\":\"inspect_zone\""));
            assert!(request.contains("\"adapter_execution\":42"));
            let body = serde_json::json!({"accepted": true, "counter": 1});
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.to_string().len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write simulator response");
        });
        let response = submit_device_sim_action_to(
            &format!("http://{addr}"),
            &unit_action_request("inspect_zone"),
            42,
        )
        .expect("submit to simulator")
        .expect("simulator response");
        assert_eq!(response["accepted"], true);
        assert_eq!(response["counter"], 1);
        handle.join().expect("simulator thread joins");
    }

    #[test]
    fn device_sim_submit_rejects_non_success_status() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind simulator");
        let addr = listener.local_addr().expect("simulator addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept simulator request");
            let mut buffer = [0_u8; 512];
            let _ = stream.read(&mut buffer).expect("read request bytes");
            stream
                .write_all(
                    b"HTTP/1.1 503 Unavailable\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                )
                .expect("write failure response");
        });
        let error = submit_device_sim_action_to(
            &format!("http://{addr}"),
            &unit_action_request("read_battery"),
            1,
        )
        .expect_err("non-200 simulator responses fail closed");
        assert!(error.to_string().contains("device_sim_"));
        handle.join().expect("simulator thread joins");
    }

    #[test]
    fn device_sim_submit_rejects_malformed_success_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind simulator");
        let addr = listener.local_addr().expect("simulator addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept simulator request");
            let mut buffer = [0_u8; 512];
            let _ = stream.read(&mut buffer).expect("read request bytes");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nnot-json",
                )
                .expect("write malformed success response");
        });
        let error = submit_device_sim_action_to(
            &format!("http://{addr}"),
            &unit_action_request("read_battery"),
            1,
        )
        .expect_err("malformed simulator bodies fail closed");
        assert!(error.to_string().contains("device_sim_"));
        handle.join().expect("simulator thread joins");
    }

    #[test]
    fn helper_error_mappings_and_local_percept_are_stable() {
        let security_errors = vec![
            (
                DaemonSecurityError::AnonymousNonDevCall,
                "anonymous_non_dev_call",
            ),
            (
                DaemonSecurityError::MissingScope { scope: "scope" },
                "missing_scope",
            ),
            (
                DaemonSecurityError::WrongCredentialBinding,
                "wrong_credential_binding",
            ),
            (DaemonSecurityError::WrongAudience, "wrong_audience"),
            (DaemonSecurityError::CredentialExpired, "credential_expired"),
            (
                DaemonSecurityError::CredentialRevoked {
                    reason: "test".to_string(),
                },
                "credential_revoked",
            ),
            (DaemonSecurityError::MissingWorkOrder, "missing_work_order"),
            (
                DaemonSecurityError::UnsignedWorkOrder,
                "unsigned_work_order",
            ),
            (DaemonSecurityError::ExpiredWorkOrder, "expired_work_order"),
            (
                DaemonSecurityError::RevokedWorkOrder {
                    reason: "test".to_string(),
                },
                "revoked_work_order",
            ),
            (
                DaemonSecurityError::IncompatibleWorkOrder,
                "incompatible_work_order",
            ),
            (
                DaemonSecurityError::MissingAuditAttribution,
                "missing_audit_attribution",
            ),
            (
                DaemonSecurityError::AttributionMismatch,
                "attribution_mismatch",
            ),
            (
                DaemonSecurityError::InvalidDevModeBinding,
                "invalid_dev_mode_binding",
            ),
            (DaemonSecurityError::DisallowedPercept, "disallowed_percept"),
            (
                DaemonSecurityError::MissingTraceRedactionPolicy,
                "missing_trace_redaction_policy",
            ),
            (
                DaemonSecurityError::ActionMissingTraceLink,
                "action_missing_trace_link",
            ),
            (
                DaemonSecurityError::ActionGatewayBypassed,
                "action_gateway_bypassed",
            ),
            (
                DaemonSecurityError::ClientInsecureFallback,
                "client_insecure_fallback",
            ),
        ];
        for (error, code) in security_errors {
            assert_eq!(daemon_security_code(&error), code);
        }

        let scheduler_error = ApiError::from(SchedulerError::NoAgents);
        assert_eq!(scheduler_error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(scheduler_error.body.code, "scheduler_error");
        let loop_error = ApiError::from(LoopError::Policy("unit policy failure".to_string()));
        assert_eq!(loop_error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(loop_error.body.code, "loop_error");
        assert_eq!(loop_error.body.message, "policy error: unit policy failure");

        let run_not_found = trace_error(TraceStoreError::RunNotFound);
        assert_eq!(run_not_found.status, StatusCode::NOT_FOUND);
        assert_eq!(run_not_found.body.code, "invalid_run");
        let trace_store_error = trace_error(TraceStoreError::Poisoned);
        assert_eq!(trace_store_error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(trace_store_error.body.code, "trace_store_error");

        let percept = local_percept("splendor.percept.test.v1", serde_json::json!({"ok": true}));
        assert_eq!(percept.schema, "splendor.percept.test.v1");
        assert_eq!(percept.provenance.source, "daemon-client-local");
    }

    #[test]
    fn trace_order_validation_accepts_contiguous_run_records_and_rejects_mismatch() {
        let run_id = RunId::new();
        let store = InMemoryTraceStore::default();
        store
            .append(&run_id.to_string(), serde_json::json!({"event": 1}))
            .expect("append first");
        store
            .append(&run_id.to_string(), serde_json::json!({"event": 2}))
            .expect("append second");
        let records = store.read(&run_id.to_string()).expect("read records");
        validate_trace_order(&records, &run_id).expect("contiguous order");

        let wrong_run = RunId::new();
        let error = validate_trace_order(&records, &wrong_run).expect_err("wrong run denied");
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.body.code, "trace_order_invalid");
    }

    #[test]
    fn trace_read_and_export_view_redaction_does_not_mutate_persisted_records() {
        let run_id = RunId::new();
        let store = InMemoryTraceStore::default();
        let reason_canary = "FND009_PERSISTED_REASON_VALUE_NEVER_RETURN";
        let status_canary = "FND009_PERSISTED_STATUS_VALUE_NEVER_RETURN";
        store
            .append(
                &run_id.to_string(),
                serde_json::json!({
                    "trace_event_id": TraceId::from_run_sequence(&run_id, 0),
                    "run_id": run_id.clone(),
                    "sequence": 0,
                    "kind": "unit.redaction_probe",
                    "reason": format!("token={reason_canary}"),
                    "status": format!("authorization={status_canary}"),
                    "source": "safe_source",
                }),
            )
            .expect("append raw trace");

        let persisted_before = store.read(&run_id.to_string()).expect("read raw trace");
        let persisted_json = serde_json::to_string(&persisted_before).expect("raw trace json");
        assert!(persisted_json.contains(reason_canary));
        assert!(persisted_json.contains(status_canary));

        let redacted = redact_trace_records(persisted_before.clone());
        let redacted_json = serde_json::to_string(&redacted).expect("redacted trace json");
        assert!(!redacted_json.contains(reason_canary));
        assert!(!redacted_json.contains(status_canary));
        assert_eq!(
            redacted[0]
                .payload
                .get("reason")
                .and_then(serde_json::Value::as_str),
            Some("[REDACTED]")
        );
        assert_eq!(
            redacted[0]
                .payload
                .get("status")
                .and_then(serde_json::Value::as_str),
            Some("[REDACTED]")
        );
        assert_eq!(redacted[0].event_hash, persisted_before[0].event_hash);
        assert_eq!(
            redacted[0].prev_event_hash,
            persisted_before[0].prev_event_hash
        );

        let persisted_after = store.read(&run_id.to_string()).expect("reread raw trace");
        assert_eq!(persisted_after, persisted_before);
        let persisted_after_json = serde_json::to_string(&persisted_after).expect("raw trace json");
        assert!(persisted_after_json.contains(reason_canary));
        assert!(persisted_after_json.contains(status_canary));
    }

    #[test]
    fn approval_trace_and_replay_helpers_cover_all_lifecycles() {
        let run_id = RunId::new();
        let approval = ApprovalTraceContext {
            approval_id: splendor_types::ApprovalId::new(),
            tenant_id: TenantId::new(),
            agent_id: splendor_types::AgentId::new(),
            run_id: run_id.clone(),
            action_id: Some(ActionId::new()),
            action_name: "artifact.publish".to_string(),
            adapter: Some("artifact-store".to_string()),
            decision: Some(splendor_types::ApprovalDecision::Granted),
            reason: Some("operator decision".to_string()),
            policy_id: Some("publish_policy".to_string()),
            risk_level: Some("external".to_string()),
            issued_at: Some(OffsetDateTime::now_utc()),
            expires_at: Some(OffsetDateTime::now_utc() + time::Duration::minutes(10)),
            revoked: false,
        };

        for (sequence, (status, replay_lifecycle, expected_reason)) in [
            ("required", "requested", None),
            ("granted", "granted", None),
            ("expired", "expired", Some("approval_expired")),
            ("revoked", "revoked", Some("approval_revoked")),
            (
                "intervention_required",
                "denied",
                Some("approval_policy_expired"),
            ),
            (
                "policy_schema_unsupported",
                "denied",
                Some("approval_policy_schema_unsupported"),
            ),
            (
                "schema_unsupported",
                "denied",
                Some("approval_evidence_schema_unsupported"),
            ),
            ("denied", "denied", Some("approval_denied")),
        ]
        .into_iter()
        .enumerate()
        {
            let kind = approval_trace_kind(status, approval.clone());
            let event = TraceEvent::new(
                run_id.clone(),
                sequence as u64,
                OffsetDateTime::now_utc(),
                kind,
            );
            let replay = approval_replay_event(event).expect("approval replay event");
            assert_eq!(replay.lifecycle, replay_lifecycle);
            assert_eq!(replay.reason.as_deref(), expected_reason);
            assert_eq!(replay.sequence, sequence as u64);
        }

        let non_approval = TraceEvent::new(
            run_id,
            99,
            OffsetDateTime::now_utc(),
            TraceEventKind::RunStarted,
        );
        assert!(approval_replay_event(non_approval).is_none());
    }

    #[test]
    fn registration_defaults_and_trace_recording_fail_closed_paths_are_stable() {
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let work_order = WorkOrder {
            schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
            work_order_id: splendor_types::WorkOrderId::try_new("wo_unit").expect("work order id"),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: None,
            objective: "unit registration".to_string(),
            allowed_actions: vec!["policy_only".to_string()],
            allowed_adapters: vec!["daemon.local".to_string()],
            allowed_permissions: Vec::new(),
            data_refs: Vec::new(),
            quotas: splendor_types::WorkOrderQuotaPolicy::default(),
            placement: splendor_types::WorkOrderPlacement::default(),
            issued_at: OffsetDateTime::now_utc() - time::Duration::minutes(1),
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            revocation: splendor_types::RevocationStatus::Active,
        };
        let work_order_envelope = WorkOrderEnvelope::signed_with_shared_secret(
            work_order.clone(),
            "key",
            b"unit-work-order-secret",
        )
        .expect("signed work order");
        let request = CreateRunRequest {
            request_id: format!("req_{}", TraceId::new()),
            idempotency_key: format!("idem_{}", TraceId::new()),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            work_order: work_order_envelope,
            credential: None,
            audit_attribution: None,
            allowed_actions: Vec::new(),
            allowed_adapters: Vec::new(),
            allowed_permissions: Vec::new(),
            policy_actions: vec![DaemonActionCandidate {
                action_id: None,
                action: Action {
                    name: "policy_only".to_string(),
                    params: serde_json::json!({}),
                    side_effect_class: splendor_types::SideEffectClass::External,
                    cost_estimate: None,
                    required_permissions: Vec::new(),
                    preconditions: Vec::new(),
                    postconditions: Vec::new(),
                },
                adapter: None,
                quota_usage: None,
                satisfied_preconditions: Vec::new(),
            }],
            policy_bundle_required: false,
            policy_bundle: None,
            registered_actions: Vec::new(),
            approval_policies: Vec::new(),
            circuit_breakers: Vec::new(),
            allowed_percept_schemas: Vec::new(),
            allowed_percept_sources: Vec::new(),
            initial_state: None,
            snapshot_interval: None,
        };
        let registrations = registrations_for_request(&request, &work_order);
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].name, "policy_only");
        assert_eq!(registrations[0].adapter, "daemon.local");

        let mut direct_registration_request = request.clone();
        direct_registration_request.policy_actions = vec![DaemonActionCandidate {
            action_id: None,
            action: Action {
                name: "policy_fallback".to_string(),
                params: serde_json::json!({}),
                side_effect_class: splendor_types::SideEffectClass::ReadOnly,
                cost_estimate: None,
                required_permissions: Vec::new(),
                preconditions: Vec::new(),
                postconditions: Vec::new(),
            },
            adapter: None,
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
        }];
        let registrations = registrations_for_request(&direct_registration_request, &work_order);
        assert_eq!(registrations.len(), 2);
        assert_eq!(registrations[1].name, "policy_fallback");
        assert_eq!(registrations[1].adapter, "daemon.local");

        let lock = lock_error();
        assert_eq!(lock.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(lock.body.code, "runtime_lock_error");

        let slot = RunSlot {
            run_id: RunId::new(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            status: RunStatus::Pending,
            scheduler: Scheduler::new(SchedulerConfig::default()),
            state_store: Arc::new(InMemoryStateStore::default()),
            trace_store: Arc::new(InMemoryTraceStore::default()),
            gateway: Arc::new(splendor_gateway::UnimplementedGateway),
            tenant_registry: TenantRegistry::new(),
            circuit_breakers: SharedCircuitBreakerEvaluator::default(),
            policy_cache: PolicyCache::new(
                PolicyCacheConfig::default(),
                PolicyCacheOwner {
                    tenant_id,
                    agent_id: agent_id.clone(),
                },
            ),
            percept_queue: PerceptQueue::default(),
            allowed_percept_schemas: Vec::new(),
            allowed_percept_sources: Vec::new(),
            allowed_actions: Vec::new(),
            state_head: None,
            adapter_executions: Arc::new(AtomicU64::new(0)),
            approval_evidence: ApprovalEvidenceSlot::default(),
            pending_approval: None,
            tick_count: 0,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let response = inspect_response(&slot);
        assert_eq!(response.agent_id, agent_id);
        assert!(response.state_head.is_none());
        assert!(response.policy_bundle.is_none());

        let error = record_run_event(
            &slot,
            TraceEventKind::RunStopped {
                reason: Some("unit".to_string()),
            },
        )
        .expect_err("empty scheduler cannot record agent event");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.body.code, "trace_error");
    }

    #[test]
    fn shared_circuit_breaker_evaluator_checks_runtime_admission() {
        let breaker = CircuitBreaker::tripped(
            splendor_types::CircuitBreakerId::try_new("breaker_runtime_unit").expect("breaker id"),
            splendor_types::CircuitBreakerScope::Global,
            "unit_runtime_admission",
            OffsetDateTime::now_utc(),
        )
        .expect("breaker");
        let evaluator = SharedCircuitBreakerEvaluator::new(vec![breaker]);
        let denied =
            evaluator.verify_runtime_admission(&splendor_types::RuntimeIdentityContext::default());
        assert!(!denied.allowed);
        assert!(denied
            .reasons
            .iter()
            .any(|reason| reason == "circuit_breaker_tripped"));

        evaluator.set(Vec::new()).expect("clear breakers");
        let allowed =
            evaluator.verify_runtime_admission(&splendor_types::RuntimeIdentityContext::default());
        assert!(allowed.allowed);

        let poisoned = SharedCircuitBreakerEvaluator::default();
        let poison_handle = poisoned.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poison_handle.breakers.lock().expect("lock breakers");
            panic!("poison circuit breaker lock for fail-closed verification");
        }));

        let denied =
            poisoned.verify_runtime_admission(&splendor_types::RuntimeIdentityContext::default());
        assert!(!denied.allowed);
        assert!(denied
            .reasons
            .iter()
            .any(|reason| reason == "circuit_breaker_state_unavailable"));

        let action = unit_daemon_action_request(
            TenantId::new(),
            "artifact.create_internal",
            serde_json::json!({"artifact_ref":"artifact://tenant/unit.md"}),
        );
        let denied = poisoned.verify_action(
            &action,
            Some("artifact-store"),
            &splendor_types::RuntimeIdentityContext::default(),
        );
        assert!(!denied.allowed);
        assert!(denied
            .reasons
            .iter()
            .any(|reason| reason == "circuit_breaker_state_unavailable"));
    }

    #[tokio::test]
    async fn device_profile_read_and_trace_sync_paths_are_covered() {
        let state = DaemonState::local_dev();
        let node_id = NodeId::new();
        let tenant_id = TenantId::new();
        let profile = unit_profile(node_id.clone(), tenant_id);
        let registered = register_device_profile(
            State(state.clone()),
            Json(RegisterDeviceProfileRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                profile: profile.clone(),
            }),
        )
        .await
        .expect("register device profile")
        .0;
        assert_eq!(registered.profile.node_id, node_id);
        assert!(OffsetDateTime::parse(&registered.profile.registered_at, &Rfc3339).is_ok());

        let status = get_device_status(
            Path(node_id.clone()),
            State(state.clone()),
            HeaderMap::new(),
        )
        .await
        .expect("device status")
        .0;
        assert_eq!(status.device_kind, "drone_sim");
        let policy = get_policy_cache_status(
            Path(node_id.clone()),
            State(state.clone()),
            HeaderMap::new(),
        )
        .await
        .expect("policy cache")
        .0;
        assert!(policy.loaded);

        let missing =
            get_device_status(Path(NodeId::new()), State(state.clone()), HeaderMap::new())
                .await
                .expect_err("unregistered device denied");
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        assert_eq!(missing.body.code, "device_not_registered");

        let missing_policy =
            get_policy_cache_status(Path(NodeId::new()), State(state.clone()), HeaderMap::new())
                .await
                .expect_err("unregistered policy cache denied");
        assert_eq!(missing_policy.status, StatusCode::NOT_FOUND);
        assert_eq!(missing_policy.body.code, "device_not_registered");

        let run_id = RunId::new();
        let trace_store = InMemoryTraceStore::default();
        trace_store
            .append(&run_id.to_string(), serde_json::json!({"event": "first"}))
            .expect("append first");
        trace_store
            .append(&run_id.to_string(), serde_json::json!({"event": "second"}))
            .expect("append second");
        let records = trace_store.read(&run_id.to_string()).expect("read records");
        let first = records[0].clone();
        let second = records[1].clone();
        let synced = sync_device_trace_buffer(
            Path(node_id.clone()),
            State(state.clone()),
            Json(DeviceTraceBufferSyncRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                run_id: run_id.clone(),
                records: vec![first.clone(), second.clone()],
                simulate_tamper: false,
            }),
        )
        .await
        .expect("trace sync")
        .0;
        assert!(synced.accepted);
        assert_eq!(synced.accepted_records, 2);
        assert!(synced.reason_code.is_none());

        let mut reordered = second;
        reordered.sequence = first.sequence;
        let rejected = sync_device_trace_buffer(
            Path(node_id.clone()),
            State(state.clone()),
            Json(DeviceTraceBufferSyncRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                run_id: run_id.clone(),
                records: vec![first.clone(), reordered],
                simulate_tamper: false,
            }),
        )
        .await
        .expect("reordered trace sync returns denial response")
        .0;
        assert!(!rejected.accepted);
        assert_eq!(
            rejected.reason_code.as_deref(),
            Some("trace_sync_reordered")
        );

        let tampered = sync_device_trace_buffer(
            Path(node_id),
            State(state.clone()),
            Json(DeviceTraceBufferSyncRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                run_id: run_id.clone(),
                records: vec![first],
                simulate_tamper: true,
            }),
        )
        .await
        .expect("tampered trace sync returns denial response")
        .0;
        assert!(!tampered.accepted);
        assert_eq!(tampered.reason_code.as_deref(), Some("trace_sync_tampered"));

        let missing_sync = sync_device_trace_buffer(
            Path(NodeId::new()),
            State(state),
            Json(DeviceTraceBufferSyncRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                run_id,
                records: Vec::new(),
                simulate_tamper: false,
            }),
        )
        .await
        .expect_err("unregistered trace sync denied");
        assert_eq!(missing_sync.status, StatusCode::NOT_FOUND);
        assert_eq!(missing_sync.body.code, "device_not_registered");
    }

    #[tokio::test]
    async fn operator_intervention_lifecycle_and_evidence_fail_closed() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let node_id = NodeId::new();
        let expires_at = (OffsetDateTime::now_utc() + time::Duration::minutes(15))
            .format(&Rfc3339)
            .expect("expiry");

        let requested = request_operator_intervention(
            State(state.clone()),
            Json(OperatorInterventionRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                intervention_id: "intervention_unit".to_string(),
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                run_id: run_id.clone(),
                node_id,
                action_name: "move_to_waypoint".to_string(),
                reason: "operator review".to_string(),
                expires_at: expires_at.clone(),
            }),
        )
        .await
        .expect("request intervention")
        .0;
        assert_eq!(requested.status, "requested");
        assert!(requested.evidence.is_none());

        let granted = grant_operator_intervention(
            Path("intervention_unit".to_string()),
            State(state.clone()),
            Json(OperatorDecisionRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                reason: "cleared".to_string(),
                expires_at: Some(expires_at.clone()),
            }),
        )
        .await
        .expect("grant intervention")
        .0;
        assert_eq!(granted.status, "granted");
        let evidence = granted.evidence.clone().expect("grant evidence");
        validate_operator_evidence(&state, &evidence, &run_id, "move_to_waypoint")
            .expect("granted evidence validates");

        let scope_error = validate_operator_evidence(&state, &evidence, &run_id, "dock")
            .expect_err("wrong action denied");
        assert_eq!(scope_error.status, StatusCode::FORBIDDEN);
        assert_eq!(
            scope_error.body.code,
            "operator_intervention_scope_mismatch"
        );

        let unknown = OperatorInterventionEvidence {
            intervention_id: "missing_intervention".to_string(),
            ..evidence.clone()
        };
        let unknown_error =
            validate_operator_evidence(&state, &unknown, &run_id, "move_to_waypoint")
                .expect_err("unknown intervention denied");
        assert_eq!(unknown_error.body.code, "operator_intervention_unknown");

        let denied = deny_operator_intervention(
            Path("intervention_unit".to_string()),
            State(state.clone()),
            Json(OperatorDecisionRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                reason: "operator denied".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect("deny intervention")
        .0;
        assert_eq!(denied.status, "denied");
        let denied_evidence = denied.evidence.expect("denial evidence");
        let denied_error =
            validate_operator_evidence(&state, &denied_evidence, &run_id, "move_to_waypoint")
                .expect_err("denied evidence fails closed");
        assert_eq!(
            denied_error.body.code,
            "operator_intervention_scope_mismatch"
        );

        let missing = grant_operator_intervention(
            Path("intervention_missing".to_string()),
            State(state),
            Json(OperatorDecisionRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                reason: "missing".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("missing intervention denied");
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        assert_eq!(missing.body.code, "operator_intervention_not_found");
    }

    #[tokio::test]
    async fn physical_action_paths_execute_and_deny_safely() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let node_id = NodeId::new();
        create_unit_run(&state, tenant_id.clone(), agent_id.clone(), run_id.clone()).await;
        let _ = register_device_profile(
            State(state.clone()),
            Json(RegisterDeviceProfileRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                profile: unit_profile(node_id.clone(), tenant_id.clone()),
            }),
        )
        .await
        .expect("register profile");

        let executed = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "move_to_waypoint",
                safe_context(),
            )),
        )
        .await
        .expect("execute bounded action")
        .0;
        assert_eq!(executed.status, ActionStatus::Executed);

        let mut geofence = safe_context();
        geofence.zone_ref = Some("zone_b".to_string());
        let denied = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "move_to_waypoint",
                geofence,
            )),
        )
        .await
        .expect("geofence returns denied outcome")
        .0;
        assert_eq!(denied.status, ActionStatus::Denied);
        assert_eq!(denied.verification.reasons, vec!["geofence_violation"]);
        assert_eq!(
            denied.verification.artifacts["source"].as_str(),
            Some("safety_verifier")
        );

        let mut low_battery = safe_context();
        low_battery.battery_percent = Some(0.10);
        let intervention = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "move_to_waypoint",
                low_battery,
            )),
        )
        .await
        .expect("low battery denied by safety verifier")
        .0;
        assert_eq!(intervention.status, ActionStatus::NeedsIntervention);
        assert!(intervention
            .verification
            .reasons
            .contains(&"battery_below_minimum".to_string()));
        assert_eq!(
            intervention.verification.artifacts["source"].as_str(),
            Some("safety_verifier")
        );

        let mut stale_policy = safe_context();
        stale_policy.offline = true;
        stale_policy.policy_cache_expired = true;
        stale_policy.high_risk = true;
        let expired_policy = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "move_to_waypoint",
                stale_policy,
            )),
        )
        .await
        .expect("expired offline policy denies high-risk action")
        .0;
        assert_eq!(expired_policy.status, ActionStatus::Denied);
        assert_eq!(
            expired_policy.verification.reasons,
            vec!["policy_cache_expired"]
        );

        let mut direct_cloud = safe_context();
        direct_cloud.cloud_helper_direct_authority = true;
        direct_cloud.cloud_helper_proposal_id = Some("proposal_unit".to_string());
        let cloud_denied = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "move_to_waypoint",
                direct_cloud,
            )),
        )
        .await
        .expect("cloud helper direct authority denied")
        .0;
        assert_eq!(cloud_denied.status, ActionStatus::Denied);
        assert_eq!(
            cloud_denied.verification.reasons,
            vec!["cloud_helper_direct_authority_denied"]
        );

        let profile_scope_error = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "inspect_zone",
                safe_context(),
            )),
        )
        .await
        .expect_err("profile allowlist denies action");
        assert_eq!(profile_scope_error.status, StatusCode::FORBIDDEN);
        assert_eq!(
            profile_scope_error.body.code,
            "physical_action_not_profile_allowed"
        );

        let mut wrong_tenant = physical_request(
            run_id,
            TenantId::new(),
            agent_id,
            "move_to_waypoint",
            safe_context(),
        );
        wrong_tenant.action_request.audit_attribution = Some(unit_audit());
        let wrong_scope = submit_physical_action(Path(node_id), State(state), Json(wrong_tenant))
            .await
            .expect_err("wrong tenant denied");
        assert_eq!(wrong_scope.status, StatusCode::FORBIDDEN);
        assert_eq!(wrong_scope.body.code, "wrong_scope");
    }

    #[test]
    fn physical_helper_boundaries_fail_closed_and_preserve_safety_snapshot() {
        let tenant_id = TenantId::new();
        let node_id = NodeId::new();
        let mut profile = unit_profile(node_id.clone(), tenant_id.clone());
        validate_device_profile_payload(&profile).expect("valid profile");

        profile.device_kind = "generic_device".to_string();
        let bad_kind = validate_device_profile_payload(&profile).expect_err("kind denied");
        assert_eq!(bad_kind.status, StatusCode::BAD_REQUEST);
        assert_eq!(bad_kind.body.code, "unsupported_device_kind");

        profile = unit_profile(node_id.clone(), tenant_id.clone());
        profile.runtime_mode = "ephemeral".to_string();
        let bad_mode = validate_device_profile_payload(&profile).expect_err("mode denied");
        assert_eq!(bad_mode.body.code, "device_requires_resident_runtime");

        profile = unit_profile(node_id.clone(), tenant_id.clone());
        profile
            .allowed_physical_actions
            .push("inspect_zone".to_string());
        validate_device_profile_payload(&profile).expect("additional bounded action");
        let generated_forbidden = [FORBIDDEN_PHYSICAL_ACTION_PATTERNS[0], "unit"].join("_");
        profile
            .allowed_physical_actions
            .push(generated_forbidden.clone());
        let bad_action = validate_device_profile_payload(&profile).expect_err("action denied");
        assert_eq!(bad_action.body.code, "low_level_physical_action_rejected");
        assert!(matches_forbidden_physical_action(&generated_forbidden));
        assert!(matches_forbidden_physical_action(
            &generated_forbidden.replace('_', "-")
        ));
        assert!(!matches_forbidden_physical_action("move_to_waypoint"));

        let request = physical_request(
            RunId::new(),
            tenant_id,
            splendor_types::AgentId::new(),
            "return_to_base",
            SafetyContext {
                battery_percent: Some(0.05),
                altitude_m: Some(12.0),
                max_altitude_m: Some(40.0),
                privacy_clear: false,
                human_proximity_clear: false,
                emergency_stop_clear: false,
                ..safe_context()
            },
        );
        let snapshot = simulated_safety_snapshot(
            &request,
            &unit_profile(node_id, request.action_request.tenant_id.clone()),
            "return_to_base",
        );
        assert_eq!(snapshot.min_battery_percent, Some(0.0));
        assert_eq!(snapshot.altitude_m, Some(12.0));
        assert_eq!(snapshot.max_altitude_m, Some(40.0));
        assert_eq!(snapshot.emergency_stop_engaged, Some(true));
        assert_eq!(snapshot.privacy_zone_active, Some(true));
        assert_eq!(snapshot.proximity_m, Some(0.0));

        let missing_audit = required_audit(None).expect_err("audit required");
        assert_eq!(missing_audit.status, StatusCode::FORBIDDEN);
        assert_eq!(missing_audit.body.code, "missing_audit_attribution");
    }

    #[tokio::test]
    async fn device_audit_records_details_and_registration_fails_when_runtime_unavailable() {
        let state = DaemonState::local_dev();
        let audit_id = record_device_audit(
            &state,
            "device.audit.unit",
            unit_audit(),
            serde_json::json!({"node_id": "node_unit", "accepted": true}),
        )
        .expect("device audit");
        {
            let audit_events = state.inner.device_audit.lock().expect("audit lock");
            assert_eq!(audit_events.len(), 1);
            assert_eq!(audit_events[0].trace_event_id, audit_id);
            assert_eq!(audit_events[0].event_type, "device.audit.unit");
            assert_eq!(audit_events[0].details["accepted"], serde_json::json!(true));
        }

        state.set_runtime_available(false);
        let denied = register_device_profile(
            State(state),
            Json(RegisterDeviceProfileRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                profile: unit_profile(NodeId::new(), TenantId::new()),
            }),
        )
        .await
        .expect_err("unavailable runtime denies registration");
        assert_eq!(denied.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(denied.body.code, "runtime_unavailable");
    }

    #[tokio::test]
    async fn physical_action_boundary_errors_are_explicit() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let node_id = NodeId::new();

        let unregistered = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "move_to_waypoint",
                safe_context(),
            )),
        )
        .await
        .expect_err("unregistered device denied");
        assert_eq!(unregistered.status, StatusCode::NOT_FOUND);
        assert_eq!(unregistered.body.code, "device_not_registered");

        create_unit_run(&state, tenant_id.clone(), agent_id.clone(), run_id.clone()).await;
        let _ = register_device_profile(
            State(state.clone()),
            Json(RegisterDeviceProfileRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                profile: unit_profile(node_id.clone(), tenant_id.clone()),
            }),
        )
        .await
        .expect("register profile");

        let unsupported_action = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "unknown_physical_action",
                safe_context(),
            )),
        )
        .await
        .expect_err("unsupported action denied");
        assert_eq!(unsupported_action.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            unsupported_action.body.code,
            "low_level_physical_action_rejected"
        );

        let wrong_agent = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(physical_request(
                run_id.clone(),
                tenant_id.clone(),
                splendor_types::AgentId::new(),
                "move_to_waypoint",
                safe_context(),
            )),
        )
        .await
        .expect_err("wrong agent denied");
        assert_eq!(wrong_agent.status, StatusCode::FORBIDDEN);
        assert_eq!(wrong_agent.body.code, "wrong_scope");

        let mut intervention_context = safe_context();
        intervention_context.privacy_clear = false;
        let intervention = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "move_to_waypoint",
                intervention_context,
            )),
        )
        .await
        .expect("privacy risk denied by safety verifier")
        .0;
        assert_eq!(intervention.status, ActionStatus::Denied);
        assert_eq!(
            intervention.verification.reasons,
            vec!["privacy_zone_active"]
        );

        let mut bad_expiry = physical_request(
            run_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
            "move_to_waypoint",
            safe_context(),
        );
        bad_expiry.operator_intervention_evidence = Some(OperatorInterventionEvidence {
            intervention_id: "intervention_bad_expiry".to_string(),
            tenant_id: tenant_id.clone(),
            run_id: run_id.clone(),
            action_name: "move_to_waypoint".to_string(),
            decision: "granted".to_string(),
            expires_at: "not-rfc3339".to_string(),
        });
        let bad_expiry_error = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(bad_expiry),
        )
        .await
        .expect_err("bad expiry denied");
        assert_eq!(bad_expiry_error.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            bad_expiry_error.body.code,
            "operator_intervention_bad_expiry"
        );

        let mut expired = physical_request(
            run_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
            "move_to_waypoint",
            safe_context(),
        );
        expired.operator_intervention_evidence = Some(OperatorInterventionEvidence {
            intervention_id: "intervention_expired".to_string(),
            tenant_id: tenant_id.clone(),
            run_id: run_id.clone(),
            action_name: "move_to_waypoint".to_string(),
            decision: "granted".to_string(),
            expires_at: (OffsetDateTime::now_utc() - time::Duration::minutes(1))
                .format(&Rfc3339)
                .expect("expiry"),
        });
        let expired_error =
            submit_physical_action(Path(node_id.clone()), State(state.clone()), Json(expired))
                .await
                .expect_err("expired intervention denied");
        assert_eq!(expired_error.status, StatusCode::FORBIDDEN);
        assert_eq!(expired_error.body.code, "operator_intervention_expired");

        let mut offline_safe = safe_context();
        offline_safe.offline = true;
        offline_safe.battery_percent = Some(0.05);
        let safe_return = submit_physical_action(
            Path(node_id),
            State(state),
            Json(physical_request(
                run_id,
                tenant_id,
                agent_id,
                "return_to_base",
                offline_safe,
            )),
        )
        .await
        .expect("safe return action executes while offline")
        .0;
        assert_eq!(safe_return.status, ActionStatus::Executed);
    }
}
