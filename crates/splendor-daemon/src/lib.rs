//! Local runtime daemon API for Splendor 0.02-S5.
//!
//! This crate exposes the smallest local daemon boundary needed for run control,
//! percept ingestion, trace/state inspection, replay, health, capabilities, and
//! gateway-mediated action submission. It is intentionally local/foundation-only:
//! no fleet registry, remote scheduler, or production auth provider is included.

pub mod caller_auth;
pub mod manager;

use axum::body::{to_bytes, Body};
use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use splendor_gateway::{
    authority_pre_effect_evidence_recorded, guard_action_request,
    guard_action_routing_and_receipts, guard_credential_capable_strings,
    guard_credential_capable_value, raw_credential_denied_action, raw_credential_denied_outcome,
    ActionAdapter, ActionGateway, ActionId, ActionOutcome, ActionRequest, ActionStatus,
    AdapterError, AdapterResult, AuthorityObligationVerifier, CircuitBreakerEvaluator,
    GatewayAuthorityDecisionSummary, PolicyApprovalVerifier, PreEffectAuthorityDecisionRecorder,
    ResourceBoundaryVerifier, SimulatedRiskLevel, SimulatedSafetySnapshot, SimulatedSafetyVerifier,
    StaticCircuitBreakerEvaluator, VerifiedActionGateway, RAW_CREDENTIAL_INPUT_DENIED,
};
use splendor_kernel::{
    Action, ActionCandidate, AgentContext, AgentIsolationPolicy, AgentRuntimeConfig,
    AuthorityObligationReceiptRevocation, AuthorityObligationReceiptVerifier,
    KernelPreEffectAuthorityRecorder, KernelRuntime, LocalAuthorityObligationReceiptConfig,
    LoopEngine, LoopError, Percept, Perceptor, Policy, PolicyCache, PolicyCacheConfig,
    PolicyCacheInstallError, PolicyCacheMutationError, PolicyCacheMutationRecorder,
    PolicyCacheOwner, PolicyCacheTraceError, PolicyDecision, PolicyDistributionGateway,
    QuotaPolicy, RunActionAdmissionState, RunAuthorityHandle, RunId, RunTraceContext, Scheduler,
    SchedulerConfig, SchedulerError, SnapshotPolicy, StateGraph, TenantContext, TenantPolicy,
    TenantRegistry, TraceEventKind,
};
use splendor_store::{
    compute_trace_event_hash, InMemoryStateStore, InMemoryTraceStore, StateData, StateNodeId,
    StateStore, TraceRecord, TraceStore, TraceStoreError,
};
use splendor_types::{
    is_allowed_physical_action, validate_policy_bundle, validate_policy_bundle_candidate,
    AppPrincipal, ApprovalChallenge, ApprovalEvidence, ApprovalPolicy, ApprovalTraceContext,
    AuditAttribution, AuthorityObligationReceipt, AuthorityObligationReceiptId, CallerCredential,
    CircuitBreaker, ClientPrincipal, ContentHash, CredentialAudience, CredentialBinding,
    DaemonEndpoint, DaemonSecurityDecision, DaemonSecurityError, DaemonSecurityRequest,
    EndpointScope, GatewayVerificationState, InsecureDevMode, LocalTransportBinding, NodeId,
    PerceptProvenance, PolicyBundleEnvelope, PolicyBundleKeyring, PolicyBundleTraceContext,
    PolicyBundleValidationContext, PolicyBundleValidationError,
    ResidentApprovalReceiptRevocationAck, ResidentApprovalReceiptRevocationRequest,
    ResidentApprovalReceiptRevocationStatus, RevocationStatus, RuntimeIdentityContext, TenantId,
    TraceEvent, TraceEventId, TraceId, ValidatedWorkOrder, VerificationResult, WorkOrder,
    WorkOrderAuthorization, WorkOrderEnvelope, WorkOrderId, WorkOrderKeyring,
    WorkOrderValidationContext, WorkOrderValidationError, FORBIDDEN_PHYSICAL_ACTION_PATTERNS,
    RESIDENT_APPROVAL_RECEIPT_REVOCATION_ACK_SCHEMA_VERSION,
    RESIDENT_APPROVAL_RECEIPT_REVOCATION_SCHEMA_VERSION,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use caller_auth::{CallerAuthError, CallerTokenVerifier};

/// Local daemon state shared by the HTTP router.
#[derive(Clone)]
pub struct DaemonState {
    inner: Arc<DaemonInner>,
}

struct DaemonInner {
    runs: Mutex<HashMap<RunId, SharedRunSlot>>,
    create_run_idempotency: Mutex<HashMap<String, CreateRunIdempotencyEntry>>,
    expected_audience: CredentialAudience,
    caller_token_verifier: Option<CallerTokenVerifier>,
    insecure_dev_mode: Option<InsecureDevMode>,
    policy_bundle_keyring: PolicyBundleKeyring,
    work_order_keyring: WorkOrderKeyring,
    authority_obligation_receipt_config: Option<LocalAuthorityObligationReceiptConfig>,
    runtime_identity: RuntimeIdentityContext,
    trace_store_override: Option<Arc<dyn TraceStore>>,
    runtime_available: AtomicBool,
    device_profiles: Mutex<HashMap<NodeId, DeviceRuntimeProfile>>,
    operator_interventions: Mutex<HashMap<String, OperatorInterventionRecord>>,
    device_audit: Mutex<Vec<DeviceAuditEvent>>,
    resident_security_audit: Mutex<Vec<ResidentSecurityAuditEvent>>,
}

type SharedRunSlot = Arc<Mutex<RunSlot>>;

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
        let runtime_identity = match &config.expected_audience {
            CredentialAudience::Instance { instance_id } => RuntimeIdentityContext {
                instance_id: Some(instance_id.clone()),
                ..RuntimeIdentityContext::default()
            },
            _ => RuntimeIdentityContext::default(),
        };
        let authority_obligation_receipt_config = match (
            config.authority_obligation_receipt_config,
            &config.expected_audience,
        ) {
            (Some(receipt_config), CredentialAudience::Instance { instance_id }) => {
                receipt_config.for_resident_instance(instance_id).ok()
            }
            (receipt_config, _) => receipt_config,
        };
        Self {
            inner: Arc::new(DaemonInner {
                runs: Mutex::new(HashMap::new()),
                create_run_idempotency: Mutex::new(HashMap::new()),
                expected_audience: config.expected_audience,
                caller_token_verifier: config.caller_token_verifier,
                insecure_dev_mode: config.insecure_dev_mode,
                policy_bundle_keyring: config.policy_bundle_keyring,
                work_order_keyring: config.work_order_keyring,
                authority_obligation_receipt_config,
                runtime_identity,
                trace_store_override,
                runtime_available: AtomicBool::new(true),
                device_profiles: Mutex::new(HashMap::new()),
                operator_interventions: Mutex::new(HashMap::new()),
                device_audit: Mutex::new(Vec::new()),
                resident_security_audit: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Toggles runtime availability for fail-closed tests and health reporting.
    pub fn set_runtime_available(&self, available: bool) {
        self.inner
            .runtime_available
            .store(available, Ordering::SeqCst);
    }

    /// Applies a monotonic local run-authority revocation from a trusted process
    /// composition/control path. This is not an HTTP endpoint or remote watch.
    /// The caller remains responsible for authenticating the control-plane fact.
    pub fn revoke_run_authority_for_local_control(
        &self,
        run_id: &RunId,
        trusted_audit: AuditAttribution,
    ) -> Result<(), ApiError> {
        let run = self.run_slot(run_id)?;
        let (recorded, authority) = {
            let slot = run.lock().map_err(|_| lock_error())?;
            let recorded = record_run_event(
                &slot,
                TraceEventKind::DaemonAudit {
                    endpoint: "splendor.authority.local.revoke".to_string(),
                    audit: trusted_audit,
                },
            );
            // Revocation uncertainty must never leave the previously live grant
            // usable, even when its audit append fails.
            let authority = slot.run_authority.clone();
            authority.close_effect_admission();
            (recorded, authority)
        };
        authority.wait_for_effect_quiescence();
        recorded
    }

    /// Returns the live handle's typed-operation evaluation count for local
    /// diagnostics and deterministic inspect-only replay assertions.
    pub fn run_authority_evaluation_count(&self, run_id: &RunId) -> Result<u64, ApiError> {
        let run = self.run_slot(run_id)?;
        let slot = run.lock().map_err(|_| lock_error())?;
        Ok(slot.run_authority.evaluation_count())
    }

    fn run_slot(&self, run_id: &RunId) -> Result<SharedRunSlot, ApiError> {
        self.inner
            .runs
            .lock()
            .map_err(|_| lock_error())?
            .get(run_id)
            .cloned()
            .ok_or_else(|| invalid_run(run_id))
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

    fn allows_experimental_local_state_handoff_import(&self) -> bool {
        matches!(
            &self.inner.expected_audience,
            CredentialAudience::Daemon { .. }
        ) && self.inner.caller_token_verifier.is_none()
            && self.inner.insecure_dev_mode.is_some()
    }

    fn record_resident_security_audit(
        &self,
        event_type: &str,
        method: &Method,
        path: &str,
        credential_correlation: &str,
        recorded_at: OffsetDateTime,
    ) {
        if let Ok(mut events) = self.inner.resident_security_audit.lock() {
            if events.len() >= MAX_RESIDENT_SECURITY_AUDIT_EVENTS {
                let remove = events.len() + 1 - MAX_RESIDENT_SECURITY_AUDIT_EVENTS;
                events.drain(..remove);
            }
            events.push(ResidentSecurityAuditEvent {
                event_type: event_type.to_string(),
                method: method.to_string(),
                path: path.to_string(),
                credential_correlation: credential_correlation.to_string(),
                recorded_at,
            });
        }
    }

    /// Returns the bounded resident-boundary security audit facts retained for
    /// local diagnostics and acceptance tests. Raw bearer tokens and JTIs are
    /// never retained here.
    pub fn resident_security_audit_events(&self) -> Vec<ResidentSecurityAuditEvent> {
        self.inner
            .resident_security_audit
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
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

/// Redacted resident authentication audit fact recorded before daemon effects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResidentSecurityAuditEvent {
    pub event_type: String,
    pub method: String,
    pub path: String,
    pub credential_correlation: String,
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct VerifiedCallerContext {
    credential: CallerCredential,
    server_audit: AuditAttribution,
}

/// Daemon construction options.
#[derive(Clone, Debug)]
pub struct DaemonConfig {
    /// Expected audience binding for caller credentials.
    pub expected_audience: CredentialAudience,
    /// Closed-profile caller-token verifier. Required for resident mode.
    pub caller_token_verifier: Option<CallerTokenVerifier>,
    /// Explicit local-only insecure development mode, if enabled.
    pub insecure_dev_mode: Option<InsecureDevMode>,
    /// Verification keys for centrally distributed policy bundles.
    pub policy_bundle_keyring: PolicyBundleKeyring,
    /// Verification keys for signed work orders accepted by this daemon.
    pub work_order_keyring: WorkOrderKeyring,
    /// Trusted local authority-obligation receipt validation configuration.
    /// Request payloads can never populate this field.
    pub authority_obligation_receipt_config: Option<LocalAuthorityObligationReceiptConfig>,
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
            caller_token_verifier: None,
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
            authority_obligation_receipt_config: Some(local_dev_authority_receipt_config()),
        }
    }

    /// Resident-mode daemon configuration with explicit trust material.
    ///
    /// This constructor deliberately cannot inherit local-development signing
    /// keys or insecure transport settings.
    pub fn resident(
        instance_id: splendor_types::InstanceId,
        caller_token_verifier: CallerTokenVerifier,
        work_order_keyring: WorkOrderKeyring,
        policy_bundle_keyring: PolicyBundleKeyring,
    ) -> Self {
        Self {
            expected_audience: CredentialAudience::Instance { instance_id },
            caller_token_verifier: Some(caller_token_verifier),
            insecure_dev_mode: None,
            policy_bundle_keyring,
            work_order_keyring,
            authority_obligation_receipt_config: None,
        }
    }

    /// Installs trusted receipt validation configuration from the process
    /// composition root. This is never derived from a daemon request.
    pub fn with_authority_obligation_receipt_config(
        mut self,
        config: LocalAuthorityObligationReceiptConfig,
    ) -> Self {
        self.authority_obligation_receipt_config = Some(config);
        self
    }
}

fn local_dev_authority_receipt_config() -> LocalAuthorityObligationReceiptConfig {
    LocalAuthorityObligationReceiptConfig::trusted_local(
        splendor_types::PrincipalId::parse("00000000-0000-4000-8000-0000000004c0")
            .expect("local receipt issuer"),
        "splendor.daemon.run",
        "approval-receipt-local-key",
        "splendor-local-approval-receipt-secret-v1",
        "local-approval-receipts",
    )
    .expect("local authority receipt config")
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
        .route(
            "/runs/:run_id/approval-receipts/:receipt_id/revoke",
            post(revoke_approval_receipt),
        )
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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            resident_caller_authentication,
        ))
        .with_state(state)
}

const MAX_DAEMON_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESIDENT_SECURITY_AUDIT_EVENTS: usize = 1024;

async fn resident_caller_authentication(
    State(state): State<DaemonState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let Some(verifier) = state.inner.caller_token_verifier.as_ref() else {
        return Ok(next.run(request).await);
    };

    let token = bearer_token(request.headers())?.to_string();
    let authenticated_at = OffsetDateTime::now_utc();
    let mut credential = verifier
        .verify(&token, authenticated_at)
        .map_err(caller_auth_api_error)?;
    validate_header_credential_mirror(request.headers(), &credential)?;

    let mut body_bytes = None;
    let mutating = request.method() != Method::GET && request.method() != Method::HEAD;
    if mutating {
        let body = std::mem::replace(request.body_mut(), Body::empty());
        let bytes = to_bytes(body, MAX_DAEMON_REQUEST_BODY_BYTES)
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request_body_too_large",
                    "daemon request body exceeded the configured limit",
                )
            })?;
        validate_body_credential_mirror(&bytes, &credential)?;
        body_bytes = Some(bytes);
    }

    if mutating {
        credential = match verifier.verify_and_consume_mutation(&token, authenticated_at) {
            Ok(credential) => credential,
            Err(CallerAuthError::ReplayedToken) => {
                state.record_resident_security_audit(
                    "caller_token.replay_denied",
                    request.method(),
                    request.uri().path(),
                    &credential.credential_id,
                    OffsetDateTime::now_utc(),
                );
                return Err(caller_auth_api_error(CallerAuthError::ReplayedToken));
            }
            Err(error) => return Err(caller_auth_api_error(error)),
        };
    }

    if is_resident_approval_receipt_revocation_path(request.method(), request.uri().path())
        && credential.scopes.as_slice() != [EndpointScope::ApprovalReceiptsRevoke]
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "missing_scope",
            "resident approval receipt revocation requires its exact sole endpoint scope",
        ));
    }

    let server_audit = AuditAttribution {
        principal: credential.principal.clone(),
        credential_id: Some(credential.credential_id.clone()),
        requested_at: OffsetDateTime::now_utc(),
    };
    if let Some(bytes) = body_bytes {
        *request.body_mut() =
            if is_resident_approval_receipt_revocation_path(request.method(), request.uri().path())
            {
                Body::from(bytes)
            } else {
                Body::from(rewrite_verified_body_mirrors(
                    &bytes,
                    &credential,
                    &server_audit,
                )?)
            };
    }
    request.extensions_mut().insert(VerifiedCallerContext {
        credential: credential.clone(),
        server_audit,
    });

    let encoded = serde_json::to_string(&credential).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caller_projection_unavailable",
            "verified caller projection could not be prepared",
        )
    })?;
    request.headers_mut().insert(
        "x-splendor-caller-credential",
        HeaderValue::from_str(&encoded).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "caller_projection_unavailable",
                "verified caller projection could not be prepared",
            )
        })?,
    );
    Ok(next.run(request).await)
}

fn is_resident_approval_receipt_revocation_path(method: &Method, path: &str) -> bool {
    if method != Method::POST {
        return false;
    }
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    matches!(
        segments.as_slice(),
        ["runs", _, "approval-receipts", _, "revoke"]
    )
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values
        .next()
        .ok_or_else(|| caller_auth_api_error(CallerAuthError::MissingToken))?;
    if values.next().is_some() {
        return Err(caller_auth_api_error(CallerAuthError::MalformedToken));
    }
    let value = value
        .to_str()
        .map_err(|_| caller_auth_api_error(CallerAuthError::MalformedToken))?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or_else(|| caller_auth_api_error(CallerAuthError::MalformedToken))?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.contains(char::is_whitespace)
    {
        return Err(caller_auth_api_error(CallerAuthError::MalformedToken));
    }
    Ok(token)
}

fn validate_header_credential_mirror(
    headers: &HeaderMap,
    credential: &CallerCredential,
) -> Result<(), ApiError> {
    if headers.contains_key("x-splendor-caller-credential") {
        let mirror = caller_credential_from_headers(headers)?.ok_or_else(|| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "caller_credential_mirror_mismatch",
                "caller credential mirror did not match the authenticated caller",
            )
        })?;
        if &mirror != credential {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "caller_credential_mirror_mismatch",
                "caller credential mirror did not match the authenticated caller",
            ));
        }
    }
    Ok(())
}

fn validate_body_credential_mirror(
    body: &[u8],
    credential: &CallerCredential,
) -> Result<(), ApiError> {
    if body.is_empty() {
        return Ok(());
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Ok(());
    };
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    if let Some(raw) = object.get("credential").filter(|value| !value.is_null()) {
        let mirror: CallerCredential = serde_json::from_value(raw.clone()).map_err(|_| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "caller_credential_mirror_mismatch",
                "caller credential mirror did not match the authenticated caller",
            )
        })?;
        if &mirror != credential {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "caller_credential_mirror_mismatch",
                "caller credential mirror did not match the authenticated caller",
            ));
        }
    }
    if let Some(raw) = object
        .get("audit_attribution")
        .filter(|value| !value.is_null())
    {
        let audit: AuditAttribution = serde_json::from_value(raw.clone()).map_err(|_| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "caller_audit_mirror_mismatch",
                "audit attribution did not match the authenticated caller",
            )
        })?;
        if audit.principal != credential.principal
            || audit.credential_id.as_deref() != Some(credential.credential_id.as_str())
        {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "caller_audit_mirror_mismatch",
                "audit attribution did not match the authenticated caller",
            ));
        }
    }
    Ok(())
}

fn rewrite_verified_body_mirrors(
    body: &[u8],
    credential: &CallerCredential,
    server_audit: &AuditAttribution,
) -> Result<Vec<u8>, ApiError> {
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Ok(body.to_vec());
    };
    let Some(object) = value.as_object_mut() else {
        return Ok(body.to_vec());
    };
    object.insert(
        "credential".to_string(),
        serde_json::to_value(credential).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "caller_projection_unavailable",
                "verified caller projection could not be prepared",
            )
        })?,
    );
    object.insert(
        "audit_attribution".to_string(),
        serde_json::to_value(server_audit).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "caller_projection_unavailable",
                "verified caller audit projection could not be prepared",
            )
        })?,
    );
    serde_json::to_vec(&value).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caller_projection_unavailable",
            "verified caller projection could not be prepared",
        )
    })
}

fn caller_auth_api_error(error: CallerAuthError) -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        caller_auth_error_code(&error),
        "resident caller authentication failed",
    )
}

fn caller_auth_error_code(error: &CallerAuthError) -> &'static str {
    match error {
        CallerAuthError::MissingToken => "missing_caller_token",
        CallerAuthError::MalformedToken => "invalid_caller_token",
        CallerAuthError::UnsupportedProfile => "unsupported_caller_token_profile",
        CallerAuthError::UntrustedKey => "untrusted_caller_token_key",
        CallerAuthError::InvalidSignature => "invalid_caller_token_signature",
        CallerAuthError::WrongIssuer => "wrong_caller_token_issuer",
        CallerAuthError::WrongAudience => "wrong_caller_token_audience",
        CallerAuthError::WrongSubject => "wrong_caller_token_subject",
        CallerAuthError::InvalidLifetime => "invalid_caller_token_lifetime",
        CallerAuthError::InvalidScope => "invalid_caller_token_scope",
        CallerAuthError::InvalidTenant => "invalid_caller_token_tenant",
        CallerAuthError::InvalidFleet => "invalid_caller_token_fleet",
        CallerAuthError::InvalidBinding => "invalid_caller_token_binding",
        CallerAuthError::RevokedToken => "revoked_caller_token",
        CallerAuthError::ReplayedToken => "caller_token_replayed",
        CallerAuthError::InvalidTrustSnapshot => "caller_trust_unavailable",
        CallerAuthError::ClockRollback => "caller_auth_clock_rollback",
        CallerAuthError::InvalidSigner | CallerAuthError::KeyLoad => "caller_auth_unavailable",
    }
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
    run_authority: RunAuthorityHandle,
    work_order_id: WorkOrderId,
    work_order_envelope: WorkOrderEnvelope,
    bound_work_order_payload_digest: String,
    authority_recorder: Arc<dyn PreEffectAuthorityDecisionRecorder>,
    authority_obligation_verifier: Arc<dyn AuthorityObligationVerifier>,
    authority_obligation_receipt_verifier: Option<Arc<AuthorityObligationReceiptVerifier>>,
    action_profiles: Vec<splendor_gateway::TrustedActionProfile>,
    approval_policies: Vec<ApprovalPolicy>,
    tenant_registry: TenantRegistry,
    circuit_breakers: SharedCircuitBreakerEvaluator,
    policy_cache: PolicyCache,
    percept_queue: PerceptQueue,
    allowed_percept_schemas: Vec<String>,
    allowed_percept_sources: Vec<String>,
    state_head: Option<StateNodeId>,
    adapter_executions: Arc<AtomicU64>,
    pending_approval: Option<ApprovalChallenge>,
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
        Ok(PolicyDecision::new(
            self.actions.clone(),
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
                "integrity": stable_json_fingerprint(b"splendor.daemon.fixture-data-read.v1\0", &serde_json::json!({"tenant_id": action.tenant_id, "data_ref": data_ref, "fixture": "uc-e2e-s7"})),
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
                "integrity": stable_json_fingerprint(b"splendor.daemon.fixture-artifact-create.v1\0", &serde_json::json!({"tenant_id": action.tenant_id, "artifact_path": path, "kind": "internal"})),
            })
        } else if action.action.name == "artifact.publish_external" {
            serde_json::json!({
                "adapter": "artifact-store",
                "execution": execution,
                "action": action.action.name,
                "published": true,
                "external_store": "fake-artifact-store",
                "raw_payload_included": false,
                "integrity": stable_json_fingerprint(b"splendor.daemon.fixture-artifact-publish.v1\0", &serde_json::json!({"tenant_id": action.tenant_id, "action": action.action.name, "kind": "external_publish"})),
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
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub requested_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_obligation_receipts: Vec<AuthorityObligationReceipt>,
}

impl DaemonActionCandidate {
    fn into_candidate(self, default_requested_at: OffsetDateTime) -> ActionCandidate {
        let requested_at = self.requested_at.unwrap_or(default_requested_at);
        let mut candidate = ActionCandidate::new(self.action)
            .with_requested_at(requested_at)
            .with_usage(normalize_untrusted_quota_usage(self.quota_usage));
        if let Some(adapter) = self.adapter {
            candidate = candidate.with_adapter(adapter);
        }
        if !self.satisfied_preconditions.is_empty() {
            candidate = candidate.with_satisfied_preconditions(self.satisfied_preconditions);
        }
        candidate = candidate.with_action_id(self.action_id.unwrap_or_default());
        if !self.authority_obligation_receipts.is_empty() {
            candidate =
                candidate.with_authority_obligation_receipts(self.authority_obligation_receipts);
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RegisteredAction {
    pub name: String,
    pub adapter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_permissions: Option<Vec<String>>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_obligation_receipts: Vec<AuthorityObligationReceipt>,
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
    #[serde(default)]
    pub previous_state_node_id: Option<String>,
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
    pub work_order: WorkOrderEnvelope,
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
    pub authority_decisions: Vec<AuthorityDecisionReplayEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthorityDecisionReplayEvent {
    pub trace_event_id: TraceId,
    pub sequence: u64,
    pub action_id: Option<ActionId>,
    pub decisions: Vec<GatewayAuthorityDecisionSummary>,
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub requested_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_evidence: Option<ApprovalEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_obligation_receipts: Vec<AuthorityObligationReceipt>,
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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
        let mut response = (self.status, Json(self.body)).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(
                    "Bearer realm=\"splendor-resident\", error=\"invalid_token\"",
                ),
            );
        }
        response
    }
}

fn validate_daemon_work_order(
    state: &DaemonState,
    envelope: &WorkOrderEnvelope,
    tenant_id: &TenantId,
    agent_id: &splendor_types::AgentId,
    run_id: Option<RunId>,
    expected_placement_target: Option<String>,
) -> Result<ValidatedWorkOrder, ApiError> {
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
    Ok(validated)
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
    if !request.allowed_permissions.is_empty()
        && normalized_permission_set(request.allowed_permissions.clone())
            != normalized_permission_set(work_order.allowed_permissions.clone())
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "work_order_permission_profile_mismatch",
            "create-run allowed_permissions must exactly match the signed compatibility profile",
        ));
    }

    for registration in &request.registered_actions {
        validate_registered_action_permissions(registration)?;
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
        if let Some(required_permissions) = &registration.required_permissions {
            for permission in required_permissions {
                ensure_member(
                    "registered_action.required_permission",
                    permission,
                    &work_order.allowed_permissions,
                )?;
            }
        }
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

fn effective_work_order_scope(requested: &[String], work_order: &[String]) -> Vec<String> {
    if requested.is_empty() {
        work_order.to_vec()
    } else {
        requested.to_vec()
    }
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

fn validate_registered_action_permissions(registration: &RegisteredAction) -> Result<(), ApiError> {
    let Some(required_permissions) = registration.required_permissions.as_ref() else {
        return Ok(());
    };
    if required_permissions.len() > 64 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "registered_action_required_permissions_limit_exceeded",
            "registered action required_permissions cannot contain more than 64 entries",
        ));
    }
    let unique = required_permissions.iter().collect::<HashSet<_>>();
    if unique.len() != required_permissions.len() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "registered_action_required_permissions_duplicate",
            "registered action required_permissions cannot contain duplicates",
        ));
    }
    Ok(())
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

fn ensure_configured_actions_are_credential_free(
    request: &CreateRunRequest,
) -> Result<(), ApiError> {
    if request.policy_actions.iter().any(|candidate| {
        guard_action_routing_and_receipts(
            &candidate.action,
            candidate.adapter.as_deref(),
            &candidate.satisfied_preconditions,
            &candidate.authority_obligation_receipts,
        )
        .is_err()
    }) {
        return Err(raw_credential_input_api_error());
    }
    Ok(())
}

fn raw_credential_input_api_error() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        RAW_CREDENTIAL_INPUT_DENIED,
        RAW_CREDENTIAL_INPUT_DENIED,
    )
}

fn guard_physical_envelope(
    request: &SubmitPhysicalActionRequest,
) -> Result<(), splendor_gateway::RawCredentialInputDenied> {
    let safety_values = request
        .safety_context
        .allowed_zone_refs
        .iter()
        .map(String::as_str)
        .chain(request.safety_context.zone_ref.as_deref())
        .chain(request.safety_context.cloud_helper_proposal_id.as_deref());
    let intervention_values = request
        .operator_intervention_evidence
        .iter()
        .flat_map(|evidence| {
            [
                evidence.intervention_id.as_str(),
                evidence.action_name.as_str(),
                evidence.decision.as_str(),
                evidence.expires_at.as_str(),
            ]
        });
    guard_credential_capable_strings(safety_values.chain(intervention_values))
}

fn create_run_caller_scope(security: &DaemonSecurityDecision) -> serde_json::Value {
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
        "insecure_dev_mode": security.insecure_dev_mode,
    })
}

fn create_run_request_fingerprint(request: &CreateRunRequest, work_order: &WorkOrder) -> String {
    stable_json_fingerprint(
        b"splendor.daemon.create-run-request.v1\0",
        &serde_json::json!({
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
        }),
    )
}

fn bound_work_order_payload_digest(
    work_order: &WorkOrder,
    run_id: &RunId,
) -> Result<String, ApiError> {
    let mut bound = work_order.clone();
    bound.run_id = Some(run_id.clone());
    let payload = bound.signing_payload_bytes().map_err(work_order_error)?;
    let mut digest_input = b"splendor.daemon.resume-work-order.v1\0".to_vec();
    digest_input.extend_from_slice(&payload);
    Ok(ContentHash::blake3(digest_input).to_string())
}

fn ensure_resume_work_order_matches_original(
    slot: &RunSlot,
    validated: &ValidatedWorkOrder,
) -> Result<(), ApiError> {
    let work_order = validated.work_order();
    if work_order.work_order_id != slot.work_order_id {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "resume_work_order_identity_mismatch",
            "resume work order does not match the originally admitted work order",
        ));
    }
    if bound_work_order_payload_digest(work_order, &slot.run_id)?
        != slot.bound_work_order_payload_digest
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "resume_work_order_payload_mismatch",
            "resume work order payload does not match the originally admitted authority",
        ));
    }
    Ok(())
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
        caller: create_run_caller_scope(security),
        request_fingerprint: create_run_request_fingerprint(request, work_order),
    }
}

fn create_run_receipt_id(idempotency_key: &str, scope: &CreateRunIdempotencyScope) -> String {
    let hash = stable_json_fingerprint(
        b"splendor.daemon.create-run-receipt.v1\0",
        &serde_json::json!({
            "idempotency_key": idempotency_key,
            "scope": scope,
        }),
    );
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
    let validated_authority_work_order = validate_daemon_work_order(
        &state,
        &request.work_order,
        &request.tenant_id,
        &request.agent_id,
        request.work_order.work_order.run_id.clone(),
        None,
    )?;
    let validated_work_order = validated_authority_work_order.work_order().clone();
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
    ensure_configured_actions_are_credential_free(&request)?;
    ensure_request_does_not_widen_work_order(&request, &validated_work_order)?;

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
    let authority_receipt_config = state.inner.authority_obligation_receipt_config.clone();
    if !request.approval_policies.is_empty() && authority_receipt_config.is_none() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "authority_obligation_receipt_config_unavailable",
            "approval-gated run creation requires trusted local receipt configuration",
        ));
    }
    let authority_audience = authority_receipt_config
        .as_ref()
        .map(|config| config.audience_for_run(&run_id))
        .unwrap_or_else(|| format!("splendor.daemon.run:{run_id}"));
    let run_authority =
        RunAuthorityHandle::admit_signed_work_order_compatibility_with_approval_policies(
            &validated_authority_work_order,
            run_id.clone(),
            authority_audience,
            request.approval_policies.clone(),
        )
        .map_err(|error| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                error.reason_code(),
                "validated signed work order could not be admitted as run authority",
            )
        })?;
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
            let run = state.run_slot(&existing.response.run_id).map_err(|_| {
                ApiError::new(
                    StatusCode::CONFLICT,
                    "create_run_idempotency_receipt_missing",
                    "idempotency receipt references a missing local run",
                )
            })?;
            let slot = run.lock().map_err(|_| lock_error())?;
            record_daemon_audit(
                &slot,
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
    let mut runtime_identity = state.inner.runtime_identity.clone();
    runtime_identity.tenant_id = Some(request.tenant_id.clone());
    runtime_identity.agent_id = Some(request.agent_id.clone());
    let trace_runtime = Arc::new(
        KernelRuntime::with_trace_store_and_identity(
            Arc::clone(&trace_store),
            Some(run_id.clone()),
            runtime_identity,
        )
        .map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trace_error",
                error.to_string(),
            )
        })?,
    );
    let authority_recorder: Arc<dyn PreEffectAuthorityDecisionRecorder> =
        Arc::new(KernelPreEffectAuthorityRecorder::new(
            Arc::clone(&trace_runtime),
            request.tenant_id.clone(),
            request.agent_id.clone(),
        ));
    let tenant_registry = TenantRegistry::new();
    let effective_allowed_actions = effective_work_order_scope(
        &request.allowed_actions,
        &validated_work_order.allowed_actions,
    );
    let effective_allowed_adapters = effective_work_order_scope(
        &request.allowed_adapters,
        &validated_work_order.allowed_adapters,
    );
    let effective_allowed_permissions = effective_work_order_scope(
        &request.allowed_permissions,
        &validated_work_order.allowed_permissions,
    );
    let mut tenant_context = TenantContext::new(
        request.tenant_id.clone(),
        TenantPolicy {
            allowed_actions: effective_allowed_actions,
            allowed_adapters: effective_allowed_adapters,
            allowed_permissions: effective_allowed_permissions.clone(),
        },
        QuotaPolicy::default().constrain_to_work_order(&validated_work_order),
    );
    tenant_context.register_agent_policy(
        request.agent_id.clone(),
        AgentIsolationPolicy {
            allowed_permissions: effective_allowed_permissions,
            ..AgentIsolationPolicy::default()
        },
    );
    tenant_registry.insert(tenant_context);

    let adapter_executions = Arc::new(AtomicU64::new(0));
    let action_profiles = action_profiles_for_request(&request, &validated_work_order)?;
    let mut gateway = VerifiedActionGateway::new(Arc::new(tenant_registry.clone()));
    gateway.set_action_authority_evaluator(Arc::new(run_authority.clone()));
    gateway.set_pre_effect_authority_recorder(Arc::clone(&authority_recorder));
    gateway
        .set_trusted_action_profiles(action_profiles.clone())
        .map_err(|reason| ApiError::new(StatusCode::BAD_REQUEST, reason.clone(), reason))?;
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
    for profile in &action_profiles {
        gateway.register_adapter(
            profile.action_name.clone(),
            profile.adapter.clone(),
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
    let authority_obligation_receipt_verifier = authority_receipt_config
        .as_ref()
        .map(|config| config.verifier_for_run(&run_id, OffsetDateTime::now_utc()));
    let authority_obligation_verifier: Arc<dyn AuthorityObligationVerifier> =
        authority_obligation_receipt_verifier
            .as_ref()
            .map(|verifier| Arc::clone(verifier) as Arc<dyn AuthorityObligationVerifier>)
            .unwrap_or_else(|| Arc::new(splendor_gateway::NoAuthorityObligationVerifier));
    gateway.set_authority_obligation_verifier(Arc::clone(&authority_obligation_verifier));

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
    let action_admitted_at = OffsetDateTime::now_utc();
    let policy_actions = request
        .policy_actions
        .into_iter()
        .map(|candidate| candidate.into_candidate(action_admitted_at))
        .collect();
    let policy = Box::new(StaticDaemonPolicy {
        actions: policy_actions,
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
    let mut engine = LoopEngine::with_shared_trace_runtime_and_work_order(
        agent,
        state_graph,
        initial_state,
        policy,
        Arc::clone(&gateway),
        trace_runtime,
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

    let bound_work_order_payload_digest =
        bound_work_order_payload_digest(&validated_work_order, &run_id)?;
    let slot = RunSlot {
        run_id: run_id.clone(),
        tenant_id: request.tenant_id,
        agent_id: request.agent_id,
        status: RunStatus::Pending,
        scheduler,
        state_store,
        trace_store,
        gateway,
        run_authority,
        work_order_id: validated_work_order.work_order_id.clone(),
        work_order_envelope: request.work_order,
        bound_work_order_payload_digest,
        authority_recorder,
        authority_obligation_verifier,
        authority_obligation_receipt_verifier,
        action_profiles,
        approval_policies: request.approval_policies.clone(),
        tenant_registry,
        circuit_breakers,
        policy_cache,
        percept_queue,
        allowed_percept_schemas: request.allowed_percept_schemas,
        allowed_percept_sources: request.allowed_percept_sources,
        state_head: None,
        adapter_executions,
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
        let run = state.run_slot(&existing.response.run_id).map_err(|_| {
            ApiError::new(
                StatusCode::CONFLICT,
                "create_run_idempotency_receipt_missing",
                "idempotency receipt references a missing local run",
            )
        })?;
        let slot = run.lock().map_err(|_| lock_error())?;
        record_daemon_audit(
            &slot,
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
    runs.insert(run_id.clone(), Arc::new(Mutex::new(slot)));
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
    let run = state.run_slot(&run_id)?;
    let mut slot = run.lock().map_err(|_| lock_error())?;
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
        &slot,
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
    let run = state.run_slot(&run_id)?;
    let slot = run.lock().map_err(|_| lock_error())?;
    state.validate_security(
        DaemonEndpoint::RunInspect {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        credential,
        None,
        None,
    )?;
    Ok(Json(inspect_response(&slot)))
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
    let run = state.run_slot(&run_id)?;
    let mut slot = run.lock().map_err(|_| lock_error())?;
    let security = state.validate_security(
        DaemonEndpoint::RunPause {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    record_daemon_audit(&slot, "splendor.runs.pause", security.audit_attribution)?;
    if !matches!(slot.status, RunStatus::Pending | RunStatus::Running) {
        return Err(invalid_lifecycle_transition(
            &slot.status,
            "run must be pending or running before pause",
        ));
    }
    record_run_event(
        &slot,
        TraceEventKind::RunPaused {
            reason: request.reason,
        },
    )?;
    slot.status = RunStatus::Paused;
    slot.updated_at = OffsetDateTime::now_utc();
    Ok(Json(inspect_response(&slot)))
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
    let run = state.run_slot(&run_id)?;
    let (authority, response) = {
        let mut slot = run.lock().map_err(|_| lock_error())?;
        let security = state.validate_security(
            DaemonEndpoint::RunStop {
                tenant_id: slot.tenant_id.clone(),
                run_id: run_id.clone(),
            },
            request.credential,
            None,
            request.audit_attribution,
        )?;
        record_daemon_audit(&slot, "splendor.runs.stop", security.audit_attribution)?;
        let authority = slot.run_authority.clone();
        authority.close_effect_admission();
        record_run_event(
            &slot,
            TraceEventKind::RunStopped {
                reason: request.reason,
            },
        )?;
        slot.status = RunStatus::Cancelled;
        slot.updated_at = OffsetDateTime::now_utc();
        (authority, inspect_response(&slot))
    };
    wait_for_run_authority_quiescence(authority).await?;
    Ok(Json(response))
}

async fn cancel_run(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Json(request): Json<LifecycleRequest>,
) -> Result<Json<RunInspectResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let run = state.run_slot(&run_id)?;
    let (authority, response) = {
        let mut slot = run.lock().map_err(|_| lock_error())?;
        let security = state.validate_security(
            DaemonEndpoint::RunStop {
                tenant_id: slot.tenant_id.clone(),
                run_id: run_id.clone(),
            },
            request.credential,
            None,
            request.audit_attribution,
        )?;
        record_daemon_audit(&slot, "splendor.runs.cancel", security.audit_attribution)?;
        let authority = slot.run_authority.clone();
        authority.close_effect_admission();
        record_run_event(
            &slot,
            TraceEventKind::RunStopped {
                reason: request.reason,
            },
        )?;
        slot.status = RunStatus::Cancelled;
        slot.updated_at = OffsetDateTime::now_utc();
        (authority, inspect_response(&slot))
    };
    wait_for_run_authority_quiescence(authority).await?;
    Ok(Json(response))
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
    let run = state.run_slot(&run_id)?;
    let mut slot = run.lock().map_err(|_| lock_error())?;
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
    record_daemon_audit(
        &slot,
        "splendor.percepts.append",
        security.audit_attribution,
    )?;
    slot.percept_queue.push(percept.clone()).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "percept_queue_error",
            error.to_string(),
        )
    })?;
    record_run_event(
        &slot,
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
    let run = state.run_slot(&run_id)?;
    let mut slot = run.lock().map_err(|_| lock_error())?;
    let security = state.validate_security(
        DaemonEndpoint::PolicySync {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    record_daemon_audit(&slot, "splendor.policies.sync", security.audit_attribution)?;

    let now = OffsetDateTime::now_utc();
    let reconnect_requested = request.disconnected == Some(false);
    if request.disconnected == Some(true) {
        if let Some(event) = slot.policy_cache.mark_disconnected_with_trace(now) {
            record_run_event(&slot, event)?;
        }
    }

    if let Some(sync_error) = request.sync_error.filter(|value| !value.trim().is_empty()) {
        let failure = slot.policy_cache.record_sync_failure(sync_error, now);
        let snapshot = slot.policy_cache.snapshot();
        record_run_event(
            &slot,
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
                let recorder = RunPolicyCacheMutationRecorder { slot: &slot };
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
                        record_policy_sync_rejection(
                            &mut slot,
                            policy_bundle_id,
                            version,
                            reason,
                            now,
                        )?;
                        Err(policy_cache_install_error(error))
                    }
                    Err(error @ PolicyCacheMutationError::Trace(_)) => {
                        Err(policy_cache_mutation_error(error))
                    }
                }
            }
            RevocationStatus::Revoked { reason } => {
                let revocation_reason = reason;
                let recorder = RunPolicyCacheMutationRecorder { slot: &slot };
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
                            &mut slot,
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
            record_policy_sync_rejection(&mut slot, policy_bundle_id, version, reason, now)?;
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
    let run = state.run_slot(&run_id)?;
    let slot = run.lock().map_err(|_| lock_error())?;
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
    let run = state.run_slot(&request.run_id)?;
    let slot = run.lock().map_err(|_| lock_error())?;
    let work_order_authorization = work_order_authorization_for_endpoint(
        &slot.work_order_envelope,
        vec![EndpointScope::StateHandoff],
    );
    state.validate_security(
        DaemonEndpoint::StateHandoff {
            tenant_id: slot.tenant_id.clone(),
            run_id: request.run_id.clone(),
        },
        request.credential,
        Some(work_order_authorization),
        request.audit_attribution,
    )?;
    let validated = validate_daemon_work_order(
        &state,
        &slot.work_order_envelope,
        &slot.tenant_id,
        &slot.agent_id,
        Some(request.run_id.clone()),
        None,
    )?;
    ensure_resume_work_order_matches_original(&slot, &validated)?;
    if request.work_order_id != slot.work_order_id.as_str() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "state_handoff_work_order_mismatch",
            "state handoff export work order does not match the admitted run",
        ));
    }
    let source_instance_id = state
        .inner
        .runtime_identity
        .instance_id
        .as_ref()
        .map(ToString::to_string);
    if source_instance_id.is_some() && request.source_instance_id != source_instance_id {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "state_handoff_source_instance_mismatch",
            "state handoff source instance does not match this runtime",
        ));
    }
    validate_optional_handoff_instance_id(
        "receiver_instance_id",
        request.receiver_instance_id.as_deref(),
    )?;
    let source_instance_id = source_instance_id.or(request.source_instance_id);
    let export = splendor_kernel::StateHandoffExportRequest {
        handoff_id: format!("handoff-{}", TraceId::new()),
        authority: splendor_types::StateHandoffAuthority {
            tenant_id: slot.tenant_id.clone(),
            agent_id: slot.agent_id.clone(),
            run_id: request.run_id.clone(),
            work_order_id: slot.work_order_id.to_string(),
        },
        source_instance_id,
        receiver_instance_id: request.receiver_instance_id,
        previous_state_node_id: request.previous_state_node_id,
        source_trace_id: None,
        created_at: OffsetDateTime::now_utc(),
    };
    let (handoff, event) = slot
        .scheduler
        .export_state_handoff_for_agent(&slot.agent_id, export)
        .map_err(ApiError::from)?;
    Ok(Json(StateSnapshotExportResponse {
        run_id: request.run_id,
        state_node_id: handoff.snapshot.state_node_id.clone(),
        trace_event_id: event.trace_event_id,
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
    let run_id = request.handoff.authority.run_id.clone();
    if !state.allows_experimental_local_state_handoff_import() {
        let credential_correlation = request
            .credential
            .as_ref()
            .map(|credential| credential.credential_id.clone())
            .unwrap_or_else(|| "unattributed_authenticated_caller".to_string());
        let work_order_authorization = work_order_authorization_for_endpoint(
            &request.work_order,
            vec![EndpointScope::StateHandoff],
        );
        state.validate_security(
            DaemonEndpoint::StateHandoff {
                tenant_id: request.handoff.authority.tenant_id.clone(),
                run_id: run_id.clone(),
            },
            request.credential,
            Some(work_order_authorization),
            request.audit_attribution,
        )?;
        let validated = validate_daemon_work_order(
            &state,
            &request.work_order,
            &request.handoff.authority.tenant_id,
            &request.handoff.authority.agent_id,
            Some(run_id.clone()),
            None,
        )?;
        if let Ok(run) = state.run_slot(&run_id) {
            let slot = run.lock().map_err(|_| lock_error())?;
            ensure_resume_work_order_matches_original(&slot, &validated)?;
        }
        state.record_resident_security_audit(
            "state_handoff.proof_denied",
            &Method::POST,
            "/state-snapshots/import",
            &credential_correlation,
            OffsetDateTime::now_utc(),
        );
        return Err(state_handoff_proof_unavailable());
    }

    let run = state.run_slot(&run_id)?;
    let mut slot = run.lock().map_err(|_| lock_error())?;
    let work_order_authorization = work_order_authorization_for_endpoint(
        &request.work_order,
        vec![EndpointScope::StateHandoff],
    );
    state.validate_security(
        DaemonEndpoint::StateHandoff {
            tenant_id: slot.tenant_id.clone(),
            run_id: run_id.clone(),
        },
        request.credential,
        Some(work_order_authorization),
        request.audit_attribution,
    )?;
    let validated = validate_daemon_work_order(
        &state,
        &request.work_order,
        &slot.tenant_id,
        &slot.agent_id,
        Some(run_id.clone()),
        None,
    );
    let validated = match validated {
        Ok(validated) => validated,
        Err(error) => {
            return Err(record_pre_import_handoff_failure(
                &slot,
                &request.handoff,
                error,
            )?)
        }
    };
    if let Err(error) = ensure_resume_work_order_matches_original(&slot, &validated) {
        return Err(record_pre_import_handoff_failure(
            &slot,
            &request.handoff,
            error,
        )?);
    }
    if request.handoff.authority.tenant_id != slot.tenant_id
        || request.handoff.authority.agent_id != slot.agent_id
        || request.handoff.authority.work_order_id != slot.work_order_id.as_str()
    {
        let error = ApiError::new(
            StatusCode::FORBIDDEN,
            "state_handoff_authority_mismatch",
            "state handoff authority does not match the admitted target run",
        );
        return Err(record_pre_import_handoff_failure(
            &slot,
            &request.handoff,
            error,
        )?);
    }
    validate_optional_handoff_instance_id(
        "source_instance_id",
        request.handoff.source_instance_id.as_deref(),
    )?;
    validate_optional_handoff_instance_id(
        "receiver_instance_id",
        request.handoff.receiver_instance_id.as_deref(),
    )?;
    let receiver_instance_id = state
        .inner
        .runtime_identity
        .instance_id
        .as_ref()
        .map(ToString::to_string);
    if let Some(expected_receiver) = receiver_instance_id.as_deref() {
        if request.handoff.receiver_instance_id.as_deref() != Some(expected_receiver) {
            let error = ApiError::new(
                StatusCode::FORBIDDEN,
                "state_handoff_receiver_instance_mismatch",
                "state handoff receiver instance does not match this runtime",
            );
            return Err(record_pre_import_handoff_failure(
                &slot,
                &request.handoff,
                error,
            )?);
        }
    }
    let metadata = splendor_store::StateMetadata {
        created_at: OffsetDateTime::now_utc(),
        label: Some("state_handoff_import".to_string()),
        tenant_id: Some(slot.tenant_id.clone()),
        agent_id: Some(slot.agent_id.clone()),
        run_id: Some(run_id.clone()),
        trace_event_id: request.handoff.source_trace_id.clone(),
    };
    let scope = splendor_kernel::StateHandoffScope {
        tenant_id: slot.tenant_id.clone(),
        agent_id: slot.agent_id.clone(),
        run_id: run_id.clone(),
        receiver_instance_id,
    };
    let agent_id = slot.agent_id.clone();
    let (imported, event) = match slot.scheduler.import_state_handoff_for_agent(
        &agent_id,
        &request.handoff,
        &request.work_order,
        &state.inner.work_order_keyring,
        &scope,
        OffsetDateTime::now_utc(),
        metadata,
    ) {
        Ok(result) => result,
        Err(SchedulerError::Loop(LoopError::StateGraph(error))) => {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "state_handoff_rejected",
                error.reason_code(),
            ));
        }
        Err(error) => return Err(ApiError::from(error)),
    };
    slot.state_head = Some(imported.node_id.clone());
    Ok(Json(StateSnapshotImportResponse {
        run_id,
        state_node_id: imported.node_id.to_string(),
        trace_event_id: event.trace_event_id,
        accepted: true,
    }))
}

fn state_handoff_proof_unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "state_handoff_proof_unavailable",
        "resident state handoff import requires source-authenticated signed handoff proof",
    )
    .details(serde_json::json!({
        "disposition": "needs_intervention",
        "retryable": false,
        "required_proof": "signed_source_handoff_manifest"
    }))
}

fn validate_optional_handoff_instance_id(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ApiError> {
    if value.is_some_and(|value| splendor_types::InstanceId::parse(value).is_err()) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_state_handoff_instance_id",
            format!("{field} must be a valid instance ID"),
        ));
    }
    Ok(())
}

fn record_pre_import_handoff_failure(
    slot: &RunSlot,
    handoff: &splendor_types::StateHandoff,
    error: ApiError,
) -> Result<ApiError, ApiError> {
    let event_id = record_run_event_returning_id(
        slot,
        TraceEventKind::StateHandoffImportFailed {
            handoff: splendor_types::StateHandoffTraceContext::exported(handoff),
            reason: error.body.code.clone(),
        },
    )?;
    Ok(error.details(serde_json::json!({"trace_event_id": event_id})))
}

async fn traces(
    Path(run_id): Path<RunId>,
    State(state): State<DaemonState>,
    Query(query): Query<TraceQuery>,
    headers: HeaderMap,
) -> Result<Json<TracePageResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let credential = caller_credential_from_headers(&headers)?;
    let run = state.run_slot(&run_id)?;
    let slot = run.lock().map_err(|_| lock_error())?;
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
    let run = state.run_slot(&run_id)?;
    let slot = run.lock().map_err(|_| lock_error())?;
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
        &slot,
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
    let run = state.run_slot(&run_id)?;
    let slot = run.lock().map_err(|_| lock_error())?;
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
        &slot,
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
    let authority_decisions = records
        .iter()
        .filter_map(|record| {
            serde_json::from_value::<TraceEvent>(record.payload.clone())
                .ok()
                .and_then(authority_decision_replay_event)
        })
        .collect();
    Ok(Json(ReplayResponse {
        replay_id: format!("replay-{run_id}"),
        run_id,
        mode: "inspect_only".to_string(),
        event_count: records.len(),
        action_event_count,
        approval_events,
        authority_decisions,
    }))
}

async fn submit_action(
    State(state): State<DaemonState>,
    Json(request): Json<SubmitActionRequest>,
) -> Result<Json<ActionOutcome>, ApiError> {
    state.ensure_runtime_available()?;
    let run = state.run_slot(&request.run_id)?;
    let effective_action_id = request.action_id.clone().unwrap_or_else(ActionId::new);
    let mut action_request = ActionRequest {
        action_id: effective_action_id.clone(),
        tenant_id: request.tenant_id.clone(),
        agent_id: request.agent_id.clone(),
        run_id: request.run_id.clone(),
        tick_id: None,
        action: request.action.clone(),
        adapter: request.adapter.clone(),
        quota_usage: normalize_untrusted_quota_usage(request.quota_usage),
        satisfied_preconditions: request.satisfied_preconditions.clone(),
        requested_at: request.requested_at.unwrap_or_else(OffsetDateTime::now_utc),
        physical_action_resource_coordinate: None,
        approval_evidence: request.approval_evidence.clone(),
        authority_obligation_evidence: None,
        authority_obligation_receipts: request.authority_obligation_receipts.clone(),
    };
    let (gateway, pending_approval_retry) = {
        let mut slot = run.lock().map_err(|_| lock_error())?;
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
        if guard_action_request(&action_request).is_err() {
            record_daemon_audit(&slot, "splendor.actions.submit", security.audit_attribution)?;
            let outcome = record_raw_credential_action_denial(
                &slot,
                &effective_action_id,
                RawCredentialIngressSource::Direct {
                    causal_trace_id: request.causal_trace_id.clone(),
                },
            )?;
            slot.updated_at = OffsetDateTime::now_utc();
            return Ok(Json(outcome));
        }
        let effective_adapter = action_request.adapter.clone().or_else(|| {
            slot.action_profiles
                .iter()
                .find(|profile| profile.action_name == action_request.action.name)
                .map(|profile| profile.adapter.clone())
        });
        let pending_approval_retry = slot
            .run_authority
            .admit_action_request(
                run_action_admission_state(&slot.status),
                slot.pending_approval.as_ref(),
                &mut action_request,
                effective_adapter.as_deref(),
                OffsetDateTime::now_utc(),
            )
            .map_err(run_action_admission_error)?;
        record_daemon_audit(&slot, "splendor.actions.submit", security.audit_attribution)?;

        record_run_action_event(
            &slot,
            &effective_action_id,
            TraceEventKind::ActionVerificationStarted {
                action: request.action.clone(),
            },
        )?;
        (Arc::clone(&slot.gateway), pending_approval_retry)
    };
    let mut outcome = gateway.submit(action_request).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_error",
            error.to_string(),
        )
    })?;
    bind_raw_approval_denial_to_pending_challenge(
        &mut outcome,
        pending_approval_retry.as_ref(),
        request.approval_evidence.as_ref(),
    )?;
    let mut slot = run.lock().map_err(|_| lock_error())?;
    if !authority_pre_effect_evidence_recorded(&outcome.verification) {
        record_run_action_event(
            &slot,
            &effective_action_id,
            TraceEventKind::ActionVerificationCompleted {
                action: request.action.clone(),
                result: outcome.verification.clone(),
            },
        )?;
    }
    match outcome.status {
        ActionStatus::Executed => {
            record_approval_event_if_present(&slot, &outcome)?;
            record_run_action_event(
                &slot,
                &effective_action_id,
                TraceEventKind::ActionExecuted {
                    action: request.action.clone(),
                    outcome: outcome.output.clone().unwrap_or(serde_json::Value::Null),
                },
            )
        }
        ActionStatus::Denied => {
            record_approval_event_if_present(&slot, &outcome)?;
            if run_status_allows_external_effects(&slot.status) || pending_approval_retry.is_some()
            {
                update_status_for_approval_denial(&mut slot, &outcome);
            }
            record_run_action_event(
                &slot,
                &effective_action_id,
                TraceEventKind::ActionDenied {
                    action: request.action.clone(),
                    result: outcome.verification.clone(),
                },
            )
        }
        ActionStatus::NeedsApproval => {
            let can_transition = run_status_allows_external_effects(&slot.status);
            if can_transition {
                slot.pending_approval =
                    Some(outcome.approval_challenge.clone().ok_or_else(|| {
                        ApiError::new(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "approval_challenge_unavailable",
                            "approval-required action did not produce a full exact challenge",
                        )
                    })?);
            }
            record_approval_event_if_present(&slot, &outcome)?;
            record_run_action_event(
                &slot,
                &effective_action_id,
                TraceEventKind::ActionNeedsApproval {
                    action: request.action.clone(),
                    result: outcome.verification.clone(),
                },
            )?;
            if can_transition {
                record_run_event(
                    &slot,
                    TraceEventKind::RunPaused {
                        reason: Some("waiting_for_approval".to_string()),
                    },
                )?;
                slot.status = RunStatus::WaitingForApproval;
            }
            Ok(())
        }
        ActionStatus::NeedsIntervention => {
            record_approval_event_if_present(&slot, &outcome)?;
            transition_run_status_from_action(&mut slot, RunStatus::Failed);
            record_run_action_event(
                &slot,
                &effective_action_id,
                TraceEventKind::ActionNeedsIntervention {
                    action: request.action.clone(),
                    result: outcome.verification.clone(),
                },
            )
        }
        ActionStatus::Failed => {
            transition_run_status_from_action(&mut slot, RunStatus::Failed);
            record_run_action_event(
                &slot,
                &effective_action_id,
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
            )
        }
    }?;
    record_run_action_event(
        &slot,
        &effective_action_id,
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
    resume_after_approved_action(&mut slot, pending_approval_retry.as_ref(), &outcome)?;
    slot.updated_at = OffsetDateTime::now_utc();
    Ok(Json(outcome))
}

async fn revoke_approval_receipt(
    Path((run_id, receipt_id)): Path<(RunId, AuthorityObligationReceiptId)>,
    State(state): State<DaemonState>,
    caller: Option<Extension<VerifiedCallerContext>>,
    Json(request): Json<ResidentApprovalReceiptRevocationRequest>,
) -> Result<Json<ResidentApprovalReceiptRevocationAck>, ApiError> {
    state.ensure_runtime_available()?;
    if request.schema_version != RESIDENT_APPROVAL_RECEIPT_REVOCATION_SCHEMA_VERSION {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "approval_receipt_revocation_schema_unsupported",
            "resident approval receipt revocation schema is unsupported",
        ));
    }
    if request.reason.trim().is_empty()
        || request.reason.trim() != request.reason
        || request.reason.len() > 1024
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "approval_receipt_revocation_reason_invalid",
            "resident approval receipt revocation reason is invalid",
        ));
    }
    if request.authority_obligation_receipt.receipt_id != receipt_id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "authority_obligation_receipt_id_mismatch",
            "path receipt identity does not match the retained raw receipt",
        ));
    }
    let caller = caller.map(|Extension(caller)| caller).ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "missing_caller_token",
            "resident approval receipt revocation requires authenticated caller identity",
        )
    })?;
    let target_instance_id = match &state.inner.expected_audience {
        CredentialAudience::Instance { instance_id } => instance_id.clone(),
        _ => {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "approval_receipt_revocation_resident_required",
                "approval receipt revocation is available only at an authenticated resident",
            ))
        }
    };
    let approval_id = request
        .authority_obligation_receipt
        .approval_id
        .clone()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "approval_receipt_approval_id_missing",
                "approval receipt does not carry an approval identity",
            )
        })?;
    let caller_tenant_id = match &caller.credential.binding {
        CredentialBinding::Tenant { tenant_id } => tenant_id.clone(),
        _ => return Err(DaemonSecurityError::WrongCredentialBinding.into()),
    };
    let security = state.validate_security(
        DaemonEndpoint::ApprovalReceiptRevoke {
            tenant_id: caller_tenant_id.clone(),
            run_id: run_id.clone(),
        },
        Some(caller.credential),
        None,
        Some(caller.server_audit),
    )?;
    let run = state.run_slot(&run_id)?;
    let (verifier, audit_attribution) = {
        let slot = run.lock().map_err(|_| lock_error())?;
        if slot.tenant_id != caller_tenant_id {
            return Err(invalid_run(&run_id));
        }
        let verifier = slot
            .authority_obligation_receipt_verifier
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authority_obligation_receipt_ledger_unavailable",
                    "resident authority obligation receipt ledger is unavailable",
                )
            })?;
        (verifier, security.audit_attribution)
    };

    let now = OffsetDateTime::now_utc();
    let status =
        match verifier.revoke_receipt(&receipt_id, &request.authority_obligation_receipt, now) {
            Ok(AuthorityObligationReceiptRevocation::Revoked) => {
                ResidentApprovalReceiptRevocationStatus::Revoked
            }
            Ok(AuthorityObligationReceiptRevocation::AlreadyRevoked) => {
                ResidentApprovalReceiptRevocationStatus::AlreadyRevoked
            }
            Ok(AuthorityObligationReceiptRevocation::AlreadyClaimed) => {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "approval_receipt_revocation_too_late",
                    "authority obligation receipt was already claimed before revocation",
                )
                .details(serde_json::json!({"effect_certainty": "known"})))
            }
            Err(error) => {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    error.reason_code(),
                    "authority obligation receipt revocation was rejected",
                ))
            }
        };

    {
        let slot = run.lock().map_err(|_| lock_error())?;
        record_daemon_audit(
            &slot,
            "splendor.approval_receipts.revoke",
            audit_attribution,
        )?;
    }
    Ok(Json(ResidentApprovalReceiptRevocationAck {
        schema_version: RESIDENT_APPROVAL_RECEIPT_REVOCATION_ACK_SCHEMA_VERSION.to_string(),
        receipt_id,
        approval_id,
        target_instance_id,
        run_id,
        receipt_audience: request.authority_obligation_receipt.audience,
        status,
        effect_certainty: splendor_types::EffectCertainty::Known,
        acknowledged_at: now,
    }))
}

async fn register_device_profile(
    State(state): State<DaemonState>,
    Json(request): Json<RegisterDeviceProfileRequest>,
) -> Result<Json<RegisterDeviceProfileResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let security = state.validate_security(
        DaemonEndpoint::DeviceProfileRegister {
            tenant_id: request.profile.tenant_id.clone(),
            node_id: request.profile.node_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution.clone(),
    )?;
    let profile_envelope =
        serde_json::to_value(&request.profile).map_err(|_| raw_credential_input_api_error())?;
    guard_credential_capable_value(&profile_envelope)
        .map_err(|_| raw_credential_input_api_error())?;
    validate_device_profile_payload(&request.profile)?;
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
    let effective_action_id = request
        .action_request
        .action_id
        .clone()
        .unwrap_or_else(ActionId::new);
    let mut action_request = ActionRequest {
        action_id: effective_action_id.clone(),
        tenant_id: request.action_request.tenant_id.clone(),
        agent_id: request.action_request.agent_id.clone(),
        run_id: request.action_request.run_id.clone(),
        tick_id: None,
        action: request.action_request.action.clone(),
        adapter: request.action_request.adapter.clone(),
        quota_usage: normalize_untrusted_quota_usage(request.action_request.quota_usage),
        satisfied_preconditions: request.action_request.satisfied_preconditions.clone(),
        requested_at: request
            .action_request
            .requested_at
            .unwrap_or_else(OffsetDateTime::now_utc),
        physical_action_resource_coordinate: None,
        approval_evidence: request.action_request.approval_evidence.clone(),
        authority_obligation_evidence: None,
        authority_obligation_receipts: request.action_request.authority_obligation_receipts.clone(),
    };
    let run = state.run_slot(&request.action_request.run_id)?;
    let (physical_gateway, pending_approval_retry, offline): (
        Arc<dyn ActionGateway>,
        Option<ApprovalChallenge>,
        bool,
    ) = {
        let mut slot = run.lock().map_err(|_| lock_error())?;
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
        if guard_action_request(&action_request).is_err()
            || guard_physical_envelope(&request).is_err()
        {
            record_daemon_audit(
                &slot,
                "splendor.devices.actions.submit",
                security.audit_attribution,
            )?;
            let outcome = record_raw_credential_action_denial(
                &slot,
                &effective_action_id,
                RawCredentialIngressSource::Physical,
            )?;
            slot.updated_at = OffsetDateTime::now_utc();
            return Ok(Json(outcome));
        }
        if matches_forbidden_physical_action(&action_name)
            || !is_allowed_physical_action(&action_name)
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
        let safety_snapshot = simulated_safety_snapshot(&request, &profile, &action_name);
        let offline = effective_device_offline(&request.safety_context, &profile);
        slot.run_authority
            .bind_physical_action_resource(&mut action_request, node_id.clone())
            .map_err(run_action_admission_error)?;
        let effective_adapter = action_request.adapter.clone().or_else(|| {
            slot.action_profiles
                .iter()
                .find(|profile| profile.action_name == action_request.action.name)
                .map(|profile| profile.adapter.clone())
        });
        let pending_approval_retry = slot
            .run_authority
            .admit_action_request(
                run_action_admission_state(&slot.status),
                slot.pending_approval.as_ref(),
                &mut action_request,
                effective_adapter.as_deref(),
                OffsetDateTime::now_utc(),
            )
            .map_err(run_action_admission_error)?;
        record_daemon_audit(
            &slot,
            "splendor.devices.actions.submit",
            security.audit_attribution.clone(),
        )?;
        record_run_action_event(
            &slot,
            &effective_action_id,
            TraceEventKind::ActionVerificationStarted {
                action: request.action_request.action.clone(),
            },
        )?;
        record_physical_run_event(
            &slot,
            "safety.verification.started",
            &request.action_request.action,
            serde_json::json!({"node_id": node_id, "action": action_name}),
        )?;
        if let Some(proposal_id) = &request.safety_context.cloud_helper_proposal_id {
            record_physical_run_event(
                &slot,
                "cloud_helper.proposal.received",
                &request.action_request.action,
                serde_json::json!({"proposal_id": proposal_id, "direct_authority": request.safety_context.cloud_helper_direct_authority}),
            )?;
        }
        if offline {
            record_physical_run_event(
                &slot,
                "offline.entered",
                &request.action_request.action,
                serde_json::json!({"node_id": node_id}),
            )?;
        }

        if offline && safety_snapshot.policy_cache_expired && safety_snapshot.high_risk {
            record_physical_run_event(
                &slot,
                "policy.cache.expired",
                &request.action_request.action,
                serde_json::json!({"policy_id": profile.policy_cache.policy_id, "action": action_name}),
            )?;
        }
        if let Some(evidence) = &request.operator_intervention_evidence {
            if let Err(error) = validate_operator_evidence(
                &state,
                evidence,
                &request.action_request.tenant_id,
                &request.action_request.agent_id,
                &request.action_request.run_id,
                &node_id,
                &action_name,
            ) {
                if error.body.code == "operator_intervention_expired" {
                    record_physical_run_event(
                        &slot,
                        "operator.intervention.expired",
                        &request.action_request.action,
                        serde_json::json!({"intervention_id": evidence.intervention_id, "action": action_name}),
                    )?;
                }
                return Err(error);
            }
        }

        let mut physical_gateway =
            VerifiedActionGateway::new(Arc::new(slot.tenant_registry.clone()));
        physical_gateway.set_action_authority_evaluator(Arc::new(slot.run_authority.clone()));
        physical_gateway.set_pre_effect_authority_recorder(Arc::clone(&slot.authority_recorder));
        physical_gateway
            .set_authority_obligation_verifier(Arc::clone(&slot.authority_obligation_verifier));
        if !slot.approval_policies.is_empty() {
            physical_gateway.set_approval_verifier(Arc::new(PolicyApprovalVerifier::new(
                slot.approval_policies.clone(),
            )));
        }
        physical_gateway
            .set_trusted_action_profiles(slot.action_profiles.clone())
            .map_err(|reason| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, reason.clone(), reason)
            })?;
        physical_gateway.set_circuit_breaker_evaluator(Arc::new(slot.circuit_breakers.clone()));
        physical_gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(
            safety_snapshot.clone(),
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
        (
            Arc::new(PolicyDistributionGateway::new(
                Arc::new(physical_gateway),
                Arc::new(slot.policy_cache.clone()),
            )),
            pending_approval_retry,
            offline,
        )
    };
    let mut outcome = physical_gateway.submit(action_request).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_error",
            error.to_string(),
        )
    })?;
    bind_raw_approval_denial_to_pending_challenge(
        &mut outcome,
        pending_approval_retry.as_ref(),
        request.action_request.approval_evidence.as_ref(),
    )?;
    let mut slot = run.lock().map_err(|_| lock_error())?;
    if !authority_pre_effect_evidence_recorded(&outcome.verification) {
        record_run_action_event(
            &slot,
            &effective_action_id,
            TraceEventKind::ActionVerificationCompleted {
                action: request.action_request.action.clone(),
                result: outcome.verification.clone(),
            },
        )?;
    }
    if let Some((allowed, safety_artifact)) = physical_safety_artifact(&outcome) {
        record_physical_run_event(
            &slot,
            "safety.verification.completed",
            &request.action_request.action,
            serde_json::json!({"allowed": allowed, "node_id": node_id, "safety": &safety_artifact}),
        )?;
        if !allowed {
            record_physical_run_event(
                &slot,
                "safety.verification.denied",
                &request.action_request.action,
                serde_json::json!({"node_id": node_id, "safety": &safety_artifact}),
            )?;
        }
    }
    match outcome.status {
        ActionStatus::Executed => {
            record_approval_event_if_present(&slot, &outcome)?;
            record_run_action_event(
                &slot,
                &effective_action_id,
                TraceEventKind::ActionExecuted {
                    action: request.action_request.action.clone(),
                    outcome: outcome.output.clone().unwrap_or(serde_json::Value::Null),
                },
            )?;
        }
        ActionStatus::NeedsApproval => {
            let can_transition = run_status_allows_external_effects(&slot.status);
            if can_transition {
                slot.pending_approval =
                    Some(outcome.approval_challenge.clone().ok_or_else(|| {
                        ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "approval_challenge_unavailable",
                        "approval-required physical action did not produce a full exact challenge",
                    )
                    })?);
            }
            record_approval_event_if_present(&slot, &outcome)?;
            record_run_action_event(
                &slot,
                &effective_action_id,
                TraceEventKind::ActionNeedsApproval {
                    action: request.action_request.action.clone(),
                    result: outcome.verification.clone(),
                },
            )?;
            if can_transition {
                record_run_event(
                    &slot,
                    TraceEventKind::RunPaused {
                        reason: Some("waiting_for_approval".to_string()),
                    },
                )?;
                slot.status = RunStatus::WaitingForApproval;
            }
        }
        _ => {
            record_approval_event_if_present(&slot, &outcome)?;
            if pending_approval_retry.is_some() {
                update_status_for_approval_denial(&mut slot, &outcome);
            }
            record_physical_denial(
                &slot,
                &effective_action_id,
                &request.action_request.action,
                &outcome,
            )?;
        }
    }
    record_run_action_event(
        &slot,
        &effective_action_id,
        TraceEventKind::OutcomeRecorded {
            outcome: serde_json::json!({"source": "daemon.physical_action", "action_outcome": outcome}),
            feedback: None,
            reward: None,
        },
    )?;
    resume_after_approved_action(&mut slot, pending_approval_retry.as_ref(), &outcome)?;
    slot.updated_at = OffsetDateTime::now_utc();
    if offline {
        record_physical_run_event(
            &slot,
            "trace.buffer.appended",
            &request.action_request.action,
            serde_json::json!({"node_id": node_id, "action": action_name}),
        )?;
        record_physical_run_event(
            &slot,
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
    guard_credential_capable_strings([
        request.intervention_id.as_str(),
        request.action_name.as_str(),
        request.reason.as_str(),
        request.expires_at.as_str(),
    ])
    .map_err(|_| raw_credential_input_api_error())?;
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
    let credential_capable_strings = [intervention_id.as_str(), request.reason.as_str()]
        .into_iter()
        .chain(request.expires_at.as_deref());
    guard_credential_capable_strings(credential_capable_strings)
        .map_err(|_| raw_credential_input_api_error())?;
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
        DaemonEndpoint::DeviceTraceSync {
            tenant_id: profile.tenant_id,
            node_id: node_id.clone(),
        },
        request.credential,
        None,
        request.audit_attribution,
    )?;
    let audit_attribution = required_audit(security.audit_attribution)?;
    if request.records.is_empty() {
        return reject_device_trace_sync(
            &state,
            &node_id,
            &audit_attribution,
            "trace_sync_empty_batch",
        );
    }
    let request_run_id = request.run_id.to_string();
    let mut expected_sequence = 0_u64;
    let mut expected_prev_hash = None;
    for record in &request.records {
        let payload_run_mismatch = match record.payload.get("run_id") {
            None => false,
            Some(serde_json::Value::String(run_id)) => run_id != &request_run_id,
            Some(_) => true,
        };
        if record.run_id != request_run_id || payload_run_mismatch {
            return reject_device_trace_sync(
                &state,
                &node_id,
                &audit_attribution,
                "trace_sync_run_mismatch",
            );
        }
        if record.sequence != expected_sequence {
            return reject_device_trace_sync(
                &state,
                &node_id,
                &audit_attribution,
                "trace_sync_sequence_mismatch",
            );
        }
        if record.prev_event_hash != expected_prev_hash {
            return reject_device_trace_sync(
                &state,
                &node_id,
                &audit_attribution,
                "trace_sync_hash_chain_mismatch",
            );
        }
        let Ok(computed_hash) =
            compute_trace_event_hash(record.prev_event_hash.as_ref(), &record.payload)
        else {
            return reject_device_trace_sync(
                &state,
                &node_id,
                &audit_attribution,
                "trace_sync_hash_unavailable",
            );
        };
        if record.event_hash != computed_hash {
            return reject_device_trace_sync(
                &state,
                &node_id,
                &audit_attribution,
                "trace_sync_event_hash_mismatch",
            );
        }
        expected_prev_hash = Some(record.event_hash.clone());
        let Some(next_sequence) = expected_sequence.checked_add(1) else {
            return reject_device_trace_sync(
                &state,
                &node_id,
                &audit_attribution,
                "trace_sync_sequence_overflow",
            );
        };
        expected_sequence = next_sequence;
    }
    if request.simulate_tamper {
        return reject_device_trace_sync(
            &state,
            &node_id,
            &audit_attribution,
            "trace_sync_tampered",
        );
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

fn reject_device_trace_sync(
    state: &DaemonState,
    node_id: &NodeId,
    audit_attribution: &AuditAttribution,
    reason_code: &'static str,
) -> Result<Json<DeviceTraceBufferSyncResponse>, ApiError> {
    let trace_event_id = record_device_audit(
        state,
        "trace.sync.failed",
        audit_attribution.clone(),
        serde_json::json!({"node_id": node_id, "reason": reason_code}),
    )?;
    Ok(Json(DeviceTraceBufferSyncResponse {
        accepted: false,
        accepted_records: 0,
        trace_event_id,
        reason_code: Some(reason_code.to_string()),
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
        .and_then(serde_json::Value::as_f64);
    let process_allowed_zones = profile
        .safety_constraints
        .get("allowed_zones")
        .and_then(serde_json::Value::as_array)
        .map(|zones| {
            zones
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let allowed_zones = if request.safety_context.allowed_zone_refs.is_empty() {
        process_allowed_zones.clone()
    } else {
        process_allowed_zones
            .iter()
            .filter(|zone| request.safety_context.allowed_zone_refs.contains(zone))
            .cloned()
            .collect()
    };
    let process_zone = request
        .action_request
        .action
        .params
        .get("target_zone_ref")
        .or_else(|| request.action_request.action.params.get("zone_ref"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| profile_safety_string(&profile.safety_status, &["current_zone", "zone_ref"]));
    let current_zone = narrow_zone(
        process_zone,
        request.safety_context.zone_ref.as_deref(),
        &process_allowed_zones,
    );
    let process_battery = profile
        .safety_status
        .get("battery_percent")
        .and_then(serde_json::Value::as_f64);
    let battery_percent = conservative_min(process_battery, request.safety_context.battery_percent);
    let process_altitude = request
        .action_request
        .action
        .params
        .get("target_altitude_m")
        .or_else(|| request.action_request.action.params.get("altitude_m"))
        .and_then(serde_json::Value::as_f64)
        .or_else(|| {
            profile
                .safety_status
                .get("altitude_m")
                .and_then(serde_json::Value::as_f64)
        });
    let altitude_m = conservative_max(process_altitude, request.safety_context.altitude_m);
    let configured_max_altitude = profile
        .safety_constraints
        .get("max_altitude_m")
        .and_then(serde_json::Value::as_f64);
    let max_altitude_m = conservative_min(
        configured_max_altitude,
        request.safety_context.max_altitude_m,
    );
    let emergency_stop_clear = profile_clear_status(
        &profile.safety_status,
        "emergency_stop_clear",
        "emergency_stop",
    );
    let privacy_clear = profile_clear_status(&profile.safety_status, "privacy_clear", "privacy");
    let human_proximity_clear = profile_clear_status(
        &profile.safety_status,
        "human_proximity_clear",
        "human_proximity",
    );
    let process_high_risk = !matches!(
        action_name,
        "read_battery" | "read_sensor_summary" | "read_map"
    ) || action_param_bool(&request.action_request.action, "high_risk")
        || profile_safety_bool(&profile.safety_status, "high_risk").unwrap_or(false);
    let policy_cache_expired = profile.policy_cache.expired
        || !profile.policy_cache.loaded
        || profile.policy_cache.ttl_seconds == 0
        || OffsetDateTime::parse(&profile.policy_cache.expires_at, &Rfc3339)
            .map_or(true, |expires_at| expires_at <= OffsetDateTime::now_utc())
        || request.safety_context.policy_cache_expired;
    SimulatedSafetySnapshot {
        current_zone,
        allowed_zones,
        battery_percent,
        min_battery_percent: is_safe_low_battery_action
            .then_some(0.0)
            .or(configured_min_battery),
        policy_cache_expired,
        high_risk: process_high_risk || request.safety_context.high_risk,
        cloud_helper_direct_authority: action_param_bool(
            &request.action_request.action,
            "cloud_helper_direct_authority",
        ) || profile_safety_bool(
            &profile.safety_status,
            "cloud_helper_direct_authority",
        )
        .unwrap_or(false)
            || request.safety_context.cloud_helper_direct_authority,
        emergency_stop_engaged: clear_status_to_unsafe(
            emergency_stop_clear,
            request.safety_context.emergency_stop_clear,
        ),
        collision_risk: profile_collision_risk(&profile.safety_status),
        altitude_m,
        max_altitude_m,
        privacy_zone_active: clear_status_to_unsafe(
            privacy_clear,
            request.safety_context.privacy_clear,
        ),
        proximity_m: clear_status_to_distance(
            human_proximity_clear,
            request.safety_context.human_proximity_clear,
        ),
        min_proximity_m: Some(1.0),
        sensor_refs: vec![profile.node_id.to_string()],
    }
}

fn effective_device_offline(context: &SafetyContext, profile: &DeviceRuntimeProfile) -> bool {
    context.offline
        || profile_safety_bool(&profile.safety_status, "offline").unwrap_or(false)
        || profile
            .safety_status
            .get("network")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|status| status.eq_ignore_ascii_case("offline"))
}

fn action_param_bool(action: &Action, key: &str) -> bool {
    action
        .params
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn profile_safety_bool(status: &serde_json::Value, key: &str) -> Option<bool> {
    status.get(key).and_then(serde_json::Value::as_bool)
}

fn profile_safety_string(status: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        status
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    })
}

fn profile_clear_status(
    status: &serde_json::Value,
    clear_key: &str,
    state_key: &str,
) -> Option<bool> {
    if let Some(clear) = profile_safety_bool(status, clear_key) {
        return Some(clear);
    }
    match status.get(state_key)? {
        serde_json::Value::Bool(active) => Some(!active),
        serde_json::Value::String(value)
            if matches!(
                value.to_ascii_lowercase().as_str(),
                "clear" | "safe" | "ok" | "none"
            ) =>
        {
            Some(true)
        }
        serde_json::Value::String(value)
            if matches!(
                value.to_ascii_lowercase().as_str(),
                "engaged" | "active" | "unsafe" | "detected" | "near"
            ) =>
        {
            Some(false)
        }
        _ => None,
    }
}

fn clear_status_to_unsafe(process_clear: Option<bool>, requester_clear: bool) -> Option<bool> {
    match process_clear {
        Some(clear) => Some(!(clear && requester_clear)),
        None if !requester_clear => Some(true),
        None => None,
    }
}

fn clear_status_to_distance(process_clear: Option<bool>, requester_clear: bool) -> Option<f64> {
    match (process_clear, requester_clear) {
        (_, false) | (Some(false), true) => Some(0.0),
        (Some(true), true) => Some(2.0),
        (None, true) => None,
    }
}

fn profile_collision_risk(status: &serde_json::Value) -> Option<SimulatedRiskLevel> {
    match status
        .get("collision_risk")
        .and_then(serde_json::Value::as_str)?
        .to_ascii_lowercase()
        .as_str()
    {
        "low" => Some(SimulatedRiskLevel::Low),
        "medium" => Some(SimulatedRiskLevel::Medium),
        "high" => Some(SimulatedRiskLevel::High),
        "critical" => Some(SimulatedRiskLevel::Critical),
        "unknown" => Some(SimulatedRiskLevel::Unknown),
        _ => None,
    }
}

fn conservative_min(process: Option<f64>, requester: Option<f64>) -> Option<f64> {
    match (process, requester) {
        (Some(process), Some(requester)) => Some(process.min(requester)),
        (Some(process), None) => Some(process),
        (None, Some(_)) | (None, None) => None,
    }
}

fn conservative_max(process: Option<f64>, requester: Option<f64>) -> Option<f64> {
    match (process, requester) {
        (Some(process), Some(requester)) => Some(process.max(requester)),
        (Some(process), None) => Some(process),
        (None, Some(_)) | (None, None) => None,
    }
}

fn narrow_zone(
    process_zone: Option<String>,
    requester_zone: Option<&str>,
    process_allowed_zones: &[String],
) -> Option<String> {
    let process_zone = process_zone?;
    let Some(requester_zone) = requester_zone else {
        return Some(process_zone);
    };
    if process_zone == requester_zone {
        return Some(process_zone);
    }
    if !process_allowed_zones
        .iter()
        .any(|zone| zone == &process_zone)
    {
        return Some(process_zone);
    }
    if !process_allowed_zones
        .iter()
        .any(|zone| zone == requester_zone)
    {
        return Some(requester_zone.to_string());
    }
    None
}

fn physical_safety_artifact(outcome: &ActionOutcome) -> Option<(bool, serde_json::Value)> {
    outcome
        .post_verification
        .as_ref()
        .and_then(safety_artifact_from_verification)
        .or_else(|| safety_artifact_from_verification(&outcome.verification))
}

fn safety_artifact_from_verification(
    verification: &VerificationResult,
) -> Option<(bool, serde_json::Value)> {
    let artifact = if verification
        .artifacts
        .get("source")
        .and_then(serde_json::Value::as_str)
        == Some("safety_verifier")
    {
        &verification.artifacts
    } else {
        verification.artifacts.get("safety")?
    };
    let allowed = match artifact
        .pointer("/evidence/status")
        .and_then(serde_json::Value::as_str)?
    {
        "Pass" => true,
        "Deny" | "Uncertain" => false,
        _ => return None,
    };
    Some((allowed, artifact.clone()))
}

fn record_physical_denial(
    slot: &RunSlot,
    action_id: &ActionId,
    action: &Action,
    outcome: &ActionOutcome,
) -> Result<(), ApiError> {
    match outcome.status {
        ActionStatus::NeedsIntervention => record_run_action_event(
            slot,
            action_id,
            TraceEventKind::ActionNeedsIntervention {
                action: action.clone(),
                result: outcome.verification.clone(),
            },
        ),
        ActionStatus::Denied => record_run_action_event(
            slot,
            action_id,
            TraceEventKind::ActionDenied {
                action: action.clone(),
                result: outcome.verification.clone(),
            },
        ),
        ActionStatus::Failed => record_run_action_event(
            slot,
            action_id,
            TraceEventKind::ActionFailed {
                action: action.clone(),
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
        ActionStatus::Executed | ActionStatus::NeedsApproval => Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "physical_action_trace_status_invalid",
            "physical non-execution trace helper received an executing action status",
        )),
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
    tenant_id: &TenantId,
    agent_id: &splendor_types::AgentId,
    run_id: &RunId,
    node_id: &NodeId,
    action_name: &str,
) -> Result<(), ApiError> {
    let evidence_expires_at =
        OffsetDateTime::parse(&evidence.expires_at, &Rfc3339).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "operator_intervention_bad_expiry",
                "operator intervention expiry is invalid",
            )
        })?;
    let now = OffsetDateTime::now_utc();
    if evidence_expires_at <= now {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "operator_intervention_expired",
            "operator intervention evidence expired",
        ));
    }
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
    if &record.tenant_id != tenant_id
        || &record.agent_id != agent_id
        || &record.run_id != run_id
        || &record.node_id != node_id
        || record.action_name != action_name
        || record.status != "granted"
        || evidence.decision != "granted"
        || evidence.tenant_id != *tenant_id
        || evidence.run_id != *run_id
        || evidence.action_name != action_name
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "operator_intervention_scope_mismatch",
            "operator intervention evidence is outside scope",
        ));
    }
    let authoritative_expires_at =
        OffsetDateTime::parse(&record.expires_at, &Rfc3339).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "operator_intervention_bad_expiry",
                "operator intervention expiry is invalid",
            )
        })?;
    if authoritative_expires_at <= now {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "operator_intervention_expired",
            "operator intervention evidence expired",
        ));
    }
    if evidence_expires_at > authoritative_expires_at {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "operator_intervention_expiry_mismatch",
            "operator intervention evidence exceeds the authoritative expiry",
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
        "device_trace_sync" | "splendor.device.trace_sync" => Some(EndpointScope::DeviceTraceSync),
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

fn run_status_allows_external_effects(status: &RunStatus) -> bool {
    // Pending remains effect-capable for the stable direct `/actions`
    // compatibility path; all suspended, resuming, and terminal states deny.
    matches!(status, RunStatus::Pending | RunStatus::Running)
}

fn run_status_is_terminal(status: &RunStatus) -> bool {
    matches!(
        status,
        RunStatus::Completed
            | RunStatus::Failed
            | RunStatus::Cancelled
            | RunStatus::Denied
            | RunStatus::Expired
    )
}

fn run_action_admission_state(status: &RunStatus) -> RunActionAdmissionState {
    match status {
        RunStatus::Pending | RunStatus::Running => RunActionAdmissionState::EffectCapable,
        RunStatus::WaitingForApproval => RunActionAdmissionState::WaitingForApproval,
        _ => RunActionAdmissionState::Closed,
    }
}

fn run_action_admission_error(error: splendor_kernel::RunActionAdmissionError) -> ApiError {
    let status = match error.reason_code() {
        "approval_challenge_unavailable" | "approval_retry_binding_unavailable" => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::CONFLICT,
    };
    ApiError::new(status, error.reason_code(), error.message())
}

fn resume_after_approved_action(
    slot: &mut RunSlot,
    expected_pending_approval: Option<&ApprovalChallenge>,
    outcome: &ActionOutcome,
) -> Result<(), ApiError> {
    let Some(expected_pending_approval) = expected_pending_approval else {
        return Ok(());
    };
    if outcome.status != ActionStatus::Executed
        || slot.status != RunStatus::WaitingForApproval
        || slot.pending_approval.as_ref() != Some(expected_pending_approval)
    {
        return Ok(());
    }
    record_run_event(
        slot,
        TraceEventKind::RunResumed {
            reason: Some("exact approved action executed".to_string()),
        },
    )?;
    slot.pending_approval = None;
    slot.status = RunStatus::Running;
    Ok(())
}

fn invalid_lifecycle_transition(status: &RunStatus, message: &str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "invalid_run_state", message)
        .details(serde_json::json!({"status": status}))
}

fn transition_run_status(slot: &mut RunSlot, next: RunStatus) {
    if run_status_is_terminal(&next) {
        slot.run_authority.close_effect_admission();
    }
    slot.status = next;
}

fn transition_run_status_from_action(slot: &mut RunSlot, next: RunStatus) {
    if run_status_allows_external_effects(&slot.status) {
        transition_run_status(slot, next);
    }
}

async fn wait_for_run_authority_quiescence(authority: RunAuthorityHandle) -> Result<(), ApiError> {
    tokio::task::spawn_blocking(move || authority.wait_for_effect_quiescence())
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "authority_quiescence_error",
                format!("run authority quiescence wait failed: {error}"),
            )
        })
}

fn normalize_untrusted_quota_usage(
    usage: Option<splendor_types::QuotaUsage>,
) -> splendor_types::QuotaUsage {
    let mut normalized = usage.unwrap_or_default();
    normalized.actions = normalized.actions.max(1);
    // A completed gateway invocation necessarily consumes non-zero runtime even
    // though this compatibility adapter has no trusted receipt reconciliation.
    normalized.action_duration_ms = normalized.action_duration_ms.max(1);
    normalized
}

async fn run_lifecycle_tick(
    state: DaemonState,
    run_id: RunId,
    request: LifecycleRequest,
    kind: LifecycleKind,
    success_status: RunStatus,
) -> Result<Json<TickResponse>, ApiError> {
    state.ensure_runtime_available()?;
    let run = state.run_slot(&run_id)?;
    let mut slot = run.lock().map_err(|_| lock_error())?;
    let carries_legacy_approval = request.approval_evidence.is_some();
    let carries_receipts = !request.authority_obligation_receipts.is_empty();
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
    let validated_resume_work_order = if matches!(kind, LifecycleKind::Resume) {
        let envelope = request.work_order.as_ref().ok_or_else(|| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "missing_work_order",
                "resume requires a signed work order envelope",
            )
        })?;
        let validated = validate_daemon_work_order(
            &state,
            envelope,
            &slot.tenant_id,
            &slot.agent_id,
            Some(run_id.clone()),
            None,
        )?;
        Some(validated)
    } else {
        None
    };
    let security_work_order = request.work_order.as_ref().and_then(|envelope| {
        matches!(kind, LifecycleKind::Resume).then(|| {
            work_order_authorization_for_endpoint(
                envelope,
                vec![splendor_types::EndpointScope::RunsResume],
            )
        })
    });
    let security = state.validate_security(
        endpoint,
        request.credential,
        security_work_order,
        request.audit_attribution,
    )?;
    match kind {
        LifecycleKind::Start if !matches!(slot.status, RunStatus::Pending | RunStatus::Running) => {
            return Err(invalid_lifecycle_transition(
                &slot.status,
                "run must be pending or running before start",
            ));
        }
        LifecycleKind::Resume
            if !matches!(
                slot.status,
                RunStatus::Paused | RunStatus::WaitingForApproval
            ) =>
        {
            return Err(invalid_lifecycle_transition(
                &slot.status,
                "run must be paused or waiting for approval before resume",
            ));
        }
        _ => {}
    }
    if carries_legacy_approval {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "legacy_approval_evidence_non_authorizing",
            "raw ApprovalEvidence cannot authorize or resume a lifecycle tick; retry the exact pending action through /actions with a trusted authority obligation receipt",
        ));
    }
    if carries_receipts {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "approval_receipt_resume_not_supported",
            "receipt-bearing lifecycle resume cannot execute a tick; retry the exact pending action through /actions",
        ));
    }
    if matches!(kind, LifecycleKind::Resume) && slot.status == RunStatus::WaitingForApproval {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "approval_exact_action_retry_required",
            "waiting_for_approval resumes only after the exact pending action executes through /actions",
        ));
    }
    if let Some(validated) = validated_resume_work_order.as_ref() {
        ensure_resume_work_order_matches_original(&slot, validated)?;
    }
    let endpoint = match kind {
        LifecycleKind::Start => "splendor.runs.start",
        LifecycleKind::Resume => "splendor.runs.resume",
    };
    record_daemon_audit(&slot, endpoint, security.audit_attribution)?;
    if matches!(kind, LifecycleKind::Resume) {
        record_run_event(
            &slot,
            TraceEventKind::RunResumed {
                reason: request.reason,
            },
        )?;
    }
    let step = match slot.scheduler.run_once() {
        Ok(step) => step,
        Err(error) => {
            transition_run_status(&mut slot, RunStatus::Failed);
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
        slot.pending_approval = Some(outcome.approval_challenge.clone().ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "approval_challenge_unavailable",
                "approval-required scheduler action did not produce a full exact challenge",
            )
        })?);
        record_run_event(
            &slot,
            TraceEventKind::RunPaused {
                reason: Some("waiting_for_approval".to_string()),
            },
        )?;
        slot.status = RunStatus::WaitingForApproval;
    } else if let Some(outcome) = step.outcome.action_outcomes.iter().find(|outcome| {
        outcome.status == ActionStatus::Denied && approval_artifact(&outcome.verification).is_some()
    }) {
        update_status_for_approval_denial(&mut slot, outcome);
    } else if step.outcome.needs_intervention {
        transition_run_status(&mut slot, RunStatus::Failed);
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

fn action_profiles_for_request(
    request: &CreateRunRequest,
    work_order: &WorkOrder,
) -> Result<Vec<splendor_gateway::TrustedActionProfile>, ApiError> {
    if work_order.allowed_adapters.len() > 1 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "ambiguous_work_order_action_adapter_profile",
            "signed work orders with multiple adapters require a signed or server-owned exact action pairing",
        ));
    }
    let full_required_permissions =
        normalized_permission_set(work_order.allowed_permissions.clone());
    let mut profiles = HashMap::new();
    for registration in &request.registered_actions {
        validate_registered_action_permissions(registration)?;
        if let Some(required_permissions) = registration.required_permissions.as_ref() {
            if normalized_permission_set(required_permissions.clone()) != full_required_permissions
                || required_permissions.len() != full_required_permissions.len()
            {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "trusted_action_profile_permission_mismatch",
                    "registered action permissions must equal the full signed work-order permission set",
                ));
            }
        }
        let profile = splendor_gateway::TrustedActionProfile {
            action_name: registration.name.clone(),
            adapter: registration.adapter.clone(),
            required_permissions: full_required_permissions.clone(),
        };
        if profiles
            .insert(registration.name.clone(), profile)
            .is_some()
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "duplicate_registered_action_profile",
                "registered action profiles must be unique by action name",
            ));
        }
    }
    let fallback_adapter = match work_order.allowed_adapters.as_slice() {
        [adapter] => adapter.clone(),
        [] => "daemon.local".to_string(),
        _ => unreachable!("multiple adapters rejected above"),
    };
    for action_name in &work_order.allowed_actions {
        if !profiles.contains_key(action_name) {
            profiles.insert(
                action_name.clone(),
                splendor_gateway::TrustedActionProfile {
                    action_name: action_name.clone(),
                    adapter: fallback_adapter.clone(),
                    required_permissions: full_required_permissions.clone(),
                },
            );
        }
    }
    for candidate in &request.policy_actions {
        let Some(profile) = profiles.get(&candidate.action.name) else {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "trusted_action_profile_missing",
                "policy action has no trusted action profile",
            ));
        };
        let effective_adapter = candidate.adapter.as_deref().unwrap_or(&profile.adapter);
        if effective_adapter != profile.adapter {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "trusted_action_profile_adapter_mismatch",
                "policy action adapter does not match its trusted profile",
            ));
        }
        if normalized_permission_set(candidate.action.required_permissions.clone())
            != profile.required_permissions
            || candidate.action.required_permissions.len() != profile.required_permissions.len()
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "trusted_action_profile_permission_mismatch",
                "policy action permissions do not match its trusted profile",
            ));
        }
    }
    let mut profiles = profiles.into_values().collect::<Vec<_>>();
    profiles.sort_by(|left, right| left.action_name.cmp(&right.action_name));
    Ok(profiles)
}

fn normalized_permission_set(mut permissions: Vec<String>) -> Vec<String> {
    permissions.sort();
    permissions.dedup();
    permissions
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

fn record_run_action_event(
    slot: &RunSlot,
    action_id: &ActionId,
    kind: TraceEventKind,
) -> Result<(), ApiError> {
    slot.scheduler
        .record_action_event_for_agent(&slot.agent_id, action_id, kind)
        .map(|_| ())
        .map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trace_error",
                error.to_string(),
            )
        })
}

enum RawCredentialIngressSource {
    Direct { causal_trace_id: Option<TraceId> },
    Physical,
}

fn record_raw_credential_action_denial(
    slot: &RunSlot,
    action_id: &ActionId,
    source: RawCredentialIngressSource,
) -> Result<ActionOutcome, ApiError> {
    let action = raw_credential_denied_action();
    let outcome = raw_credential_denied_outcome(action_id.clone());
    record_run_action_event(
        slot,
        action_id,
        TraceEventKind::ActionVerificationStarted {
            action: action.clone(),
        },
    )?;
    record_run_action_event(
        slot,
        action_id,
        TraceEventKind::ActionVerificationCompleted {
            action: action.clone(),
            result: outcome.verification.clone(),
        },
    )?;
    record_run_action_event(
        slot,
        action_id,
        TraceEventKind::ActionDenied {
            action,
            result: outcome.verification.clone(),
        },
    )?;
    let recorded_outcome = match source {
        RawCredentialIngressSource::Direct { causal_trace_id } => serde_json::json!({
            "source": "daemon.action",
            "causal_trace_id": causal_trace_id,
            "action_outcome": &outcome,
        }),
        RawCredentialIngressSource::Physical => serde_json::json!({
            "source": "daemon.physical_action",
            "action_outcome": &outcome,
        }),
    };
    record_run_action_event(
        slot,
        action_id,
        TraceEventKind::OutcomeRecorded {
            outcome: recorded_outcome,
            feedback: None,
            reward: None,
        },
    )?;
    Ok(outcome)
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

fn bind_raw_approval_denial_to_pending_challenge(
    outcome: &mut ActionOutcome,
    pending_challenge: Option<&ApprovalChallenge>,
    evidence: Option<&ApprovalEvidence>,
) -> Result<(), ApiError> {
    let (Some(challenge), Some(evidence)) = (pending_challenge, evidence) else {
        return Ok(());
    };
    if evidence.decision != splendor_types::ApprovalDecision::Denied {
        return Ok(());
    }
    let Some((_status, mut approval)) = approval_artifact(&outcome.verification) else {
        // Current authority or another earlier verifier may deny before the
        // approval verifier. Preserve that fail-closed gateway result without
        // manufacturing an approval lifecycle fact.
        return Ok(());
    };

    // Scope, policy, and risk are runtime-owned challenge facts. Preserve only
    // the gateway-vetted decision/reason and lifecycle fields from the exact raw
    // denial so replay cannot be rebound to caller-selected identities.
    approval.approval_id = challenge.approval_id.clone();
    approval.tenant_id = challenge.tenant_id.clone();
    approval.agent_id = challenge.agent_id.clone();
    approval.run_id = challenge.run_id.clone();
    approval.action_id = Some(challenge.action_id.clone());
    approval.action_name = challenge.action_name.clone();
    approval.adapter = Some(challenge.adapter.clone());
    approval.policy_id = Some(challenge.policy_id.clone());
    approval.risk_level = challenge.risk_level.clone();

    let approval = serde_json::to_value(approval).map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "approval_trace_context_unavailable",
            "approval denial trace context could not be bound to the pending challenge",
        )
    })?;
    let artifacts = outcome
        .verification
        .artifacts
        .as_object_mut()
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "approval_trace_context_unavailable",
                "approval denial verification artifacts are unavailable",
            )
        })?;
    let artifact = if artifacts.contains_key("approval") {
        artifacts.get_mut("approval")
    } else {
        artifacts.get_mut("approval_context")
    }
    .ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "approval_trace_context_unavailable",
            "approval denial trace context is unavailable",
        )
    })?;
    match artifact {
        serde_json::Value::Object(wrapper) if wrapper.contains_key("approval") => {
            wrapper.insert("approval".to_string(), approval);
        }
        artifact => *artifact = approval,
    }
    Ok(())
}

fn update_status_for_approval_denial(slot: &mut RunSlot, outcome: &ActionOutcome) {
    let Some((status, _approval)) = approval_artifact(&outcome.verification) else {
        return;
    };
    let next = match status.as_str() {
        "expired" => Some(RunStatus::Expired),
        "denied" | "revoked" | "schema_unsupported" => Some(RunStatus::Denied),
        _ => None,
    };
    if let Some(next) = next {
        transition_run_status(slot, next);
    }
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

fn authority_decision_replay_event(event: TraceEvent) -> Option<AuthorityDecisionReplayEvent> {
    let TraceEventKind::ActionVerificationCompleted { result, .. } = event.kind else {
        return None;
    };
    let decisions_value = result
        .artifacts
        .pointer("/authority/decisions")
        .or_else(|| result.artifacts.pointer("/decisions"))?;
    let decisions =
        serde_json::from_value::<Vec<GatewayAuthorityDecisionSummary>>(decisions_value.clone())
            .ok()?;
    Some(AuthorityDecisionReplayEvent {
        trace_event_id: event.trace_event_id,
        sequence: event.sequence,
        action_id: event.identity.action_id,
        decisions,
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
            let audit_correlation = bounded_daemon_audit_correlation(&record.payload);
            record.payload = redact_trace_value(record.payload);
            if let (Some(correlation), Some(value)) = (
                audit_correlation,
                record
                    .payload
                    .pointer_mut("/kind/DaemonAudit/audit/credential_id"),
            ) {
                *value = serde_json::Value::String(correlation);
            }
            record
        })
        .collect()
}

fn bounded_daemon_audit_correlation(payload: &serde_json::Value) -> Option<String> {
    let event = serde_json::from_value::<TraceEvent>(payload.clone()).ok()?;
    let TraceEventKind::DaemonAudit { audit, .. } = event.kind else {
        return None;
    };
    audit
        .credential_id
        .filter(|credential_id| is_bounded_sha256_correlation(credential_id))
}

fn is_bounded_sha256_correlation(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
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

fn stable_json_fingerprint(domain: &[u8], value: &serde_json::Value) -> String {
    let mut input = Vec::with_capacity(domain.len() + 256);
    input.extend_from_slice(domain);
    input.extend_from_slice(&serde_json::to_vec(value).unwrap_or_default());
    ContentHash::blake3(input).to_string()
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
    use base64::Engine as _;
    use splendor_store::{InMemoryTraceStore, TraceStore};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;
    use tower::ServiceExt as _;

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

    fn unit_replay_credential(tenant_id: TenantId) -> CallerCredential {
        CallerCredential {
            credential_id: "unit_credential".to_string(),
            principal: unit_audit().principal,
            scopes: vec![splendor_types::EndpointScope::ReplayCreate],
            binding: splendor_types::CredentialBinding::Tenant { tenant_id },
            audience: splendor_types::CredentialAudience::Daemon {
                daemon_id: "daemon_local".to_string(),
            },
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(5),
            revocation: splendor_types::RevocationStatus::Active,
        }
    }

    fn locked_unit_state() -> DaemonState {
        let mut config = DaemonConfig::local_dev();
        config.insecure_dev_mode = None;
        DaemonState::new(config)
    }

    fn unit_credential(tenant_id: TenantId, scopes: Vec<EndpointScope>) -> CallerCredential {
        CallerCredential {
            credential_id: "unit_credential".to_string(),
            principal: unit_audit().principal,
            scopes,
            binding: CredentialBinding::Tenant { tenant_id },
            audience: CredentialAudience::Daemon {
                daemon_id: "daemon_local".to_string(),
            },
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(5),
            revocation: RevocationStatus::Active,
        }
    }

    fn unit_credential_headers(credential: &CallerCredential) -> HeaderMap {
        let encoded = serde_json::to_vec(credential).expect("credential serializes");
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-splendor-caller-credential",
            HeaderValue::from_bytes(&encoded).expect("credential header"),
        );
        headers
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
            safety_constraints: serde_json::json!({
                "min_battery_percent": 0.25,
                "max_altitude_m": 30.0,
                "allowed_zones": ["zone_a"]
            }),
            runtime_mode: "resident".to_string(),
            safety_status: serde_json::json!({
                "battery_percent": 0.80,
                "emergency_stop_clear": true,
                "collision_risk": "low",
                "altitude_m": 10.0,
                "privacy_clear": true,
                "human_proximity_clear": true,
                "offline": false,
                "cloud_helper_direct_authority": false
            }),
            policy_cache: DevicePolicyCacheStatus {
                policy_id: "policy_unit".to_string(),
                loaded: true,
                ttl_seconds: 300,
                expires_at: (OffsetDateTime::now_utc() + time::Duration::minutes(5))
                    .format(&Rfc3339)
                    .expect("future policy expiry formats"),
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
        max_actions_per_tick: u32,
        max_action_duration_ms: Option<u64>,
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
                "fixture.write".to_string(),
            ],
            allowed_adapters: vec!["device-sim".to_string()],
            allowed_permissions: vec!["device.motion".to_string()],
            data_refs: vec!["device:unit".to_string()],
            quotas: splendor_types::WorkOrderQuotaPolicy {
                max_actions_per_tick: Some(max_actions_per_tick),
                max_action_duration_ms,
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
                requested_at: None,
                approval_evidence: None,
                authority_obligation_receipts: Vec::new(),
            },
            safety_context,
            operator_intervention_evidence: None,
        }
    }

    fn direct_physical_request(
        run_id: RunId,
        tenant_id: TenantId,
        agent_id: splendor_types::AgentId,
        action_name: &str,
        quota_usage: splendor_types::QuotaUsage,
    ) -> SubmitActionRequest {
        let mut request =
            physical_request(run_id, tenant_id, agent_id, action_name, safe_context())
                .action_request;
        request.action.side_effect_class = splendor_types::SideEffectClass::External;
        request.quota_usage = Some(quota_usage);
        request
    }

    fn authority_physical_request(
        run_id: RunId,
        tenant_id: TenantId,
        agent_id: splendor_types::AgentId,
    ) -> ActionRequest {
        ActionRequest {
            action_id: ActionId::new(),
            tenant_id,
            agent_id,
            run_id,
            tick_id: None,
            action: physical_action("move_to_waypoint"),
            adapter: Some("device-sim".to_string()),
            quota_usage: splendor_types::QuotaUsage::single_action(),
            satisfied_preconditions: Vec::new(),
            requested_at: OffsetDateTime::now_utc(),
            physical_action_resource_coordinate: Some(
                splendor_types::PhysicalActionResourceCoordinate::physical_node(NodeId::new()),
            ),
            approval_evidence: None,
            authority_obligation_evidence: None,
            authority_obligation_receipts: Vec::new(),
        }
    }

    fn assert_non_tick_action_trace(state: &DaemonState, run_id: &RunId, action_id: &ActionId) {
        let run = state.run_slot(run_id).expect("run slot");
        let slot = run.lock().expect("run");
        let events = slot
            .trace_store
            .read(&run_id.to_string())
            .expect("trace records")
            .into_iter()
            .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload).ok())
            .filter(|event| event.identity.action_id.as_ref() == Some(action_id))
            .collect::<Vec<_>>();
        assert!(events.iter().all(|event| {
            event.identity.run_id == *run_id
                && event.identity.tenant_id.as_ref() == Some(&slot.tenant_id)
                && event.identity.agent_id.as_ref() == Some(&slot.agent_id)
                && event.identity.action_id.as_ref() == Some(action_id)
        }));
        assert!(events.iter().all(|event| event.identity.tick_id.is_none()));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event.kind,
                    TraceEventKind::ActionVerificationStarted { .. }
                ))
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

    fn unit_adapter_execution_count(state: &DaemonState, run_id: &RunId) -> u64 {
        state
            .run_slot(run_id)
            .expect("run")
            .lock()
            .expect("run")
            .adapter_executions
            .load(Ordering::SeqCst)
    }

    fn unit_action_request(action_name: &str) -> ActionRequest {
        ActionRequest {
            action_id: ActionId::new(),
            tenant_id: TenantId::new(),
            agent_id: splendor_types::AgentId::new(),
            run_id: RunId::new(),
            tick_id: None,
            action: physical_action(action_name),
            adapter: Some("device-sim".to_string()),
            quota_usage: splendor_types::QuotaUsage::single_action(),
            satisfied_preconditions: Vec::new(),
            requested_at: OffsetDateTime::now_utc(),
            physical_action_resource_coordinate: Some(
                splendor_types::PhysicalActionResourceCoordinate::physical_node(NodeId::new()),
            ),
            approval_evidence: None,
            authority_obligation_evidence: None,
            authority_obligation_receipts: Vec::new(),
        }
    }

    #[test]
    fn resident_caller_projection_helpers_cover_fail_closed_profiles() {
        let credential = unit_replay_credential(TenantId::new());
        let audit = unit_audit();

        let empty_headers = HeaderMap::new();
        assert_eq!(
            bearer_token(&empty_headers)
                .expect_err("token required")
                .body
                .code,
            "missing_caller_token"
        );
        for authorization in ["Basic token", "Bearer", "Bearer token with-space"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(authorization).expect("header"),
            );
            assert_eq!(
                bearer_token(&headers)
                    .expect_err("malformed bearer rejected")
                    .body
                    .code,
                "invalid_caller_token"
            );
        }
        let mut duplicate_headers = HeaderMap::new();
        duplicate_headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer first"),
        );
        duplicate_headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second"),
        );
        assert_eq!(
            bearer_token(&duplicate_headers)
                .expect_err("duplicate bearer rejected")
                .body
                .code,
            "invalid_caller_token"
        );
        let mut valid_headers = HeaderMap::new();
        valid_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token"),
        );
        assert_eq!(bearer_token(&valid_headers).expect("bearer"), "token");

        validate_header_credential_mirror(&HeaderMap::new(), &credential).expect("omitted mirror");
        let mut mirrored_headers = HeaderMap::new();
        mirrored_headers.insert(
            "x-splendor-caller-credential",
            HeaderValue::from_str(&serde_json::to_string(&credential).expect("credential JSON"))
                .expect("credential header"),
        );
        validate_header_credential_mirror(&mirrored_headers, &credential).expect("exact mirror");
        let mut other_credential = credential.clone();
        other_credential.credential_id = "other_credential".to_string();
        assert_eq!(
            validate_header_credential_mirror(&mirrored_headers, &other_credential)
                .expect_err("header substitution rejected")
                .body
                .code,
            "caller_credential_mirror_mismatch"
        );

        for body in [b"".as_slice(), b"not-json".as_slice(), b"[]".as_slice()] {
            validate_body_credential_mirror(body, &credential)
                .expect("non-object body has no mirror");
        }
        let exact_body = serde_json::to_vec(&serde_json::json!({
            "credential": credential,
            "audit_attribution": audit,
        }))
        .expect("body JSON");
        validate_body_credential_mirror(&exact_body, &credential).expect("exact body mirrors");
        for (body, expected_code) in [
            (
                serde_json::json!({"credential": {"malformed": true}}),
                "caller_credential_mirror_mismatch",
            ),
            (
                serde_json::json!({"credential": other_credential}),
                "caller_credential_mirror_mismatch",
            ),
            (
                serde_json::json!({"audit_attribution": {"malformed": true}}),
                "caller_audit_mirror_mismatch",
            ),
            (
                serde_json::json!({"audit_attribution": {"principal": unit_audit().principal, "credential_id": "other", "requested_at": OffsetDateTime::now_utc()}}),
                "caller_audit_mirror_mismatch",
            ),
        ] {
            let bytes = serde_json::to_vec(&body).expect("body JSON");
            assert_eq!(
                validate_body_credential_mirror(&bytes, &credential)
                    .expect_err("mirror mismatch rejected")
                    .body
                    .code,
                expected_code
            );
        }

        assert!(
            rewrite_verified_body_mirrors(b"", &credential, &unit_audit())
                .expect("empty rewrite")
                .is_empty()
        );
        assert_eq!(
            rewrite_verified_body_mirrors(b"not-json", &credential, &unit_audit())
                .expect("opaque rewrite"),
            b"not-json"
        );
        assert_eq!(
            rewrite_verified_body_mirrors(b"[]", &credential, &unit_audit())
                .expect("array rewrite"),
            b"[]"
        );
        let rewritten = rewrite_verified_body_mirrors(b"{\"value\":1}", &credential, &unit_audit())
            .expect("object rewrite");
        let rewritten: serde_json::Value =
            serde_json::from_slice(&rewritten).expect("rewritten JSON");
        assert_eq!(
            rewritten["credential"]["credential_id"],
            credential.credential_id
        );
        assert_eq!(
            rewritten["audit_attribution"]["credential_id"],
            "unit_credential"
        );

        let caller_errors = [
            CallerAuthError::MissingToken,
            CallerAuthError::MalformedToken,
            CallerAuthError::UnsupportedProfile,
            CallerAuthError::UntrustedKey,
            CallerAuthError::InvalidSignature,
            CallerAuthError::WrongIssuer,
            CallerAuthError::WrongAudience,
            CallerAuthError::WrongSubject,
            CallerAuthError::InvalidLifetime,
            CallerAuthError::InvalidScope,
            CallerAuthError::InvalidTenant,
            CallerAuthError::InvalidFleet,
            CallerAuthError::InvalidBinding,
            CallerAuthError::RevokedToken,
            CallerAuthError::ReplayedToken,
            CallerAuthError::InvalidTrustSnapshot,
            CallerAuthError::ClockRollback,
            CallerAuthError::InvalidSigner,
            CallerAuthError::KeyLoad,
        ];
        for error in caller_errors {
            assert!(!caller_auth_error_code(&error).is_empty());
            assert_eq!(
                caller_auth_api_error(error).status,
                StatusCode::UNAUTHORIZED
            );
        }

        let security_errors = [
            DaemonSecurityError::AnonymousNonDevCall,
            DaemonSecurityError::MissingScope { scope: "unit" },
            DaemonSecurityError::WrongCredentialBinding,
            DaemonSecurityError::WrongAudience,
            DaemonSecurityError::CredentialExpired,
            DaemonSecurityError::CredentialRevoked {
                reason: "unit".to_string(),
            },
            DaemonSecurityError::MissingWorkOrder,
            DaemonSecurityError::UnsignedWorkOrder,
            DaemonSecurityError::ExpiredWorkOrder,
            DaemonSecurityError::RevokedWorkOrder {
                reason: "unit".to_string(),
            },
            DaemonSecurityError::IncompatibleWorkOrder,
            DaemonSecurityError::MissingAuditAttribution,
            DaemonSecurityError::AttributionMismatch,
            DaemonSecurityError::InvalidDevModeBinding,
            DaemonSecurityError::DisallowedPercept,
            DaemonSecurityError::MissingTraceRedactionPolicy,
            DaemonSecurityError::ActionMissingTraceLink,
            DaemonSecurityError::ActionGatewayBypassed,
            DaemonSecurityError::ClientInsecureFallback,
            DaemonSecurityError::InvalidRegistryEndpoint,
        ];
        for error in security_errors {
            assert!(!daemon_security_code(&error).is_empty());
        }

        for scope in [
            "runs_create",
            "runs_start",
            "runs_read",
            "runs_pause",
            "runs_resume",
            "runs_stop",
            "percepts_append",
            "actions_submit",
            "traces_read",
            "state_read",
            "replay_create",
            "messages_send",
            "messages_read",
            "work_orders_submit",
            "work_orders_revoke",
            "fleet_read",
            "fleet_dispatch",
            "state_handoff",
            "health_read",
            "capabilities_read",
            "policies_sync",
            "nodes_register",
            "instances_register",
            "nodes_heartbeat",
            "instances_heartbeat",
            "device_register",
            "device_read",
            "device_trace_sync",
            "operator_intervene",
        ] {
            assert!(
                endpoint_scope_from_public_str(scope).is_some(),
                "missing scope {scope}"
            );
        }
        assert!(endpoint_scope_from_public_str("unknown_scope").is_none());

        let public = serde_json::json!({
            "credential_id": "public_credential",
            "principal": {"app": {"app_principal_id": "public_app", "label": null}, "client_principal_id": "public_client", "label": null},
            "scopes": ["splendor.runs.create", "splendor.state.handoff"],
            "binding": {"tenant": {"tenant_id": TenantId::new()}},
            "audience": {"daemon": {"daemon_id": "daemon_public"}},
            "expires_at": (OffsetDateTime::now_utc() + time::Duration::minutes(5)).format(&Rfc3339).expect("public expiry"),
            "revocation": "active",
        });
        let parsed = caller_credential_from_public_header_json(&public.to_string())
            .expect("public credential profile");
        assert_eq!(parsed.credential_id, "public_credential");
        assert_eq!(
            parsed.scopes,
            vec![EndpointScope::RunsCreate, EndpointScope::StateHandoff]
        );
        let mut revoked = public;
        revoked["revocation"] = serde_json::json!({"revoked": {"reason": "unit"}});
        assert!(matches!(
            caller_credential_from_public_header_json(&revoked.to_string())
                .expect("revoked public profile")
                .revocation,
            RevocationStatus::Revoked { .. }
        ));
    }

    #[test]
    fn request_fingerprints_use_domain_separated_blake3() {
        let request = unit_create_run_request(
            TenantId::new(),
            splendor_types::AgentId::new(),
            Some(RunId::new()),
            "wo_unit_blake3_fingerprint",
            "req_unit_blake3_fingerprint",
            "idem_unit_blake3_fingerprint",
        );
        let fingerprint = create_run_request_fingerprint(&request, &request.work_order.work_order);
        assert!(fingerprint.starts_with("blake3:"));
        assert_eq!(fingerprint.len(), "blake3:".len() + 64);
        assert_ne!(
            fingerprint,
            stable_json_fingerprint(
                b"splendor.daemon.different-domain.v1\0",
                &serde_json::json!({
                    "validated_work_order": &request.work_order.work_order,
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
                }),
            )
        );
    }

    #[tokio::test]
    async fn approval_gated_run_creation_requires_process_owned_receipt_configuration() {
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let mut config = DaemonConfig::local_dev();
        config.authority_obligation_receipt_config = None;
        let state = DaemonState::new(config);
        let mut request = unit_create_run_request(
            tenant_id.clone(),
            agent_id,
            Some(run_id),
            "wo_missing_receipt_config",
            "request_missing_receipt_config",
            "idempotency_missing_receipt_config",
        );
        request.approval_policies = vec![ApprovalPolicy::new(
            "approval-policy-unit",
            tenant_id,
            "approval required",
        )];

        let error = create_run(State(state), Json(request))
            .await
            .expect_err("approval receipt config required");
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            error.body.code,
            "authority_obligation_receipt_config_unavailable"
        );
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
            tick_id: None,
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
            physical_action_resource_coordinate: None,
            approval_evidence: None,
            authority_obligation_evidence: None,
            authority_obligation_receipts: Vec::new(),
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
        let signer = crate::caller_auth::CallerTokenSigner::generate_for_test(
            "urn:splendor:manager:test",
            "manager-test",
            "resident-test",
            "resident-test-key",
        )
        .expect("signer");
        let trust = crate::caller_auth::CallerTokenTrustSnapshot::single_key(
            signer.issuer(),
            signer.app_principal_id(),
            signer.kid(),
            &signer.public_key_bytes(),
            vec![EndpointScope::HealthRead],
            OffsetDateTime::now_utc(),
        );
        let verifier = CallerTokenVerifier::new(trust, instance_id.clone()).expect("verifier");
        let mut work_order_keyring = WorkOrderKeyring::new();
        work_order_keyring
            .insert_shared_secret("test-work-order", [7_u8; 32])
            .expect("work order key");
        let mut policy_bundle_keyring = PolicyBundleKeyring::new();
        policy_bundle_keyring
            .insert_shared_secret("test-policy", [9_u8; 32])
            .expect("policy key");
        let config = DaemonConfig::resident(
            instance_id.clone(),
            verifier,
            work_order_keyring,
            policy_bundle_keyring,
        );
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

        for index in 0..(MAX_RESIDENT_SECURITY_AUDIT_EVENTS + 5) {
            state.record_resident_security_audit(
                "test.security_event",
                &Method::POST,
                "/test",
                &format!("sha256:{index}"),
                OffsetDateTime::now_utc(),
            );
        }
        let events = state.resident_security_audit_events();
        assert_eq!(events.len(), MAX_RESIDENT_SECURITY_AUDIT_EVENTS);
        assert_eq!(events[0].credential_correlation, "sha256:5");
        assert_eq!(
            events.last().expect("latest audit").credential_correlation,
            format!("sha256:{}", MAX_RESIDENT_SECURITY_AUDIT_EVENTS + 4)
        );
    }

    #[tokio::test]
    async fn resident_mutating_jti_is_one_use_reads_are_reusable_and_create_is_stable_across_jtis()
    {
        let now = OffsetDateTime::now_utc();
        let instance_id = splendor_types::InstanceId::new();
        let signer = crate::caller_auth::CallerTokenSigner::generate_for_test(
            "urn:splendor:manager:test",
            "manager-test",
            "resident-test",
            "resident-test-key",
        )
        .expect("signer");
        let trust = crate::caller_auth::CallerTokenTrustSnapshot::single_key(
            signer.issuer(),
            signer.app_principal_id(),
            signer.kid(),
            &signer.public_key_bytes(),
            vec![EndpointScope::RunsCreate, EndpointScope::HealthRead],
            now,
        );
        let verifier = CallerTokenVerifier::new(trust, instance_id.clone()).expect("verifier");
        let mut work_order_keyring = WorkOrderKeyring::new();
        work_order_keyring
            .insert_shared_secret("work-order-local-key", b"splendor-local-work-order-secret")
            .expect("work-order key");
        let mut policy_bundle_keyring = PolicyBundleKeyring::new();
        policy_bundle_keyring
            .insert_shared_secret("policy-local-key", b"splendor-local-policy-secret")
            .expect("policy key");
        let state = DaemonState::new(DaemonConfig::resident(
            instance_id.clone(),
            verifier,
            work_order_keyring,
            policy_bundle_keyring,
        ));
        let app = router(state.clone());
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let mut create = unit_create_run_request(
            tenant_id.clone(),
            agent_id,
            Some(run_id.clone()),
            "wo_resident_replay",
            "req-resident-replay",
            "idem-resident-replay",
        );
        let first = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                time::Duration::seconds(60),
            )
            .expect("first token");
        let encoded_claims = first.encoded.split('.').nth(1).expect("claims segment");
        let claims: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded_claims)
                .expect("claims encoding"),
        )
        .expect("claims JSON");
        let raw_jti = claims["jti"].as_str().expect("raw JTI").to_string();
        let caller_supplied_time = OffsetDateTime::UNIX_EPOCH;
        create.credential = Some(first.credential.clone());
        create.audit_attribution = Some(AuditAttribution {
            principal: first.credential.principal.clone(),
            credential_id: Some(first.credential.credential_id.clone()),
            requested_at: caller_supplied_time,
        });
        let create_body = serde_json::to_vec(&create).expect("create body");
        let request = || {
            axum::http::Request::builder()
                .method(Method::POST)
                .uri("/runs")
                .header(header::AUTHORIZATION, format!("Bearer {}", first.encoded))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(create_body.clone()))
                .expect("request")
        };
        let first_response = app.clone().oneshot(request()).await.expect("response");
        assert_eq!(first_response.status(), StatusCode::OK);
        let first_body = to_bytes(first_response.into_body(), 1024 * 1024)
            .await
            .expect("first body");
        let first_created: CreateRunResponse =
            serde_json::from_slice(&first_body).expect("first response");
        assert!(!first_created.duplicate);

        let replayed = app.clone().oneshot(request()).await.expect("response");
        assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);
        let replayed_body = to_bytes(replayed.into_body(), 1024 * 1024)
            .await
            .expect("replay body");
        let replayed_error: ApiErrorBody =
            serde_json::from_slice(&replayed_body).expect("replay error");
        assert_eq!(replayed_error.code, "caller_token_replayed");

        let second = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                OffsetDateTime::now_utc(),
                time::Duration::seconds(60),
            )
            .expect("fresh token");
        create.credential = None;
        create.audit_attribution = None;
        let fresh_request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/runs")
            .header(header::AUTHORIZATION, format!("Bearer {}", second.encoded))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&create).expect("fresh create body"),
            ))
            .expect("fresh request");
        let duplicate = app.clone().oneshot(fresh_request).await.expect("response");
        assert_eq!(duplicate.status(), StatusCode::OK);
        let duplicate_body = to_bytes(duplicate.into_body(), 1024 * 1024)
            .await
            .expect("duplicate body");
        let duplicate: CreateRunResponse =
            serde_json::from_slice(&duplicate_body).expect("duplicate response");
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.run_id, first_created.run_id);
        assert_eq!(
            duplicate.idempotency_receipt_id,
            first_created.idempotency_receipt_id
        );

        let read = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::HealthRead],
                OffsetDateTime::now_utc(),
                time::Duration::seconds(60),
            )
            .expect("read token");
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(Method::GET)
                        .uri("/health")
                        .header(header::AUTHORIZATION, format!("Bearer {}", read.encoded))
                        .body(Body::empty())
                        .expect("read request"),
                )
                .await
                .expect("read response");
            assert_eq!(response.status(), StatusCode::OK);
        }

        let events = state.resident_security_audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "caller_token.replay_denied");
        assert_eq!(
            events[0].credential_correlation,
            first.credential.credential_id
        );
        assert!(events[0].credential_correlation.starts_with("sha256:"));
        let event_json = serde_json::to_string(&events).expect("security audit JSON");
        assert!(!event_json.contains(&raw_jti));
        let slot = state.run_slot(&run_id).expect("created run");
        let records = slot
            .lock()
            .expect("run slot")
            .trace_store
            .read(&run_id.to_string())
            .expect("trace records");
        let trace_json = serde_json::to_string(&records).expect("trace JSON");
        let caller_time = caller_supplied_time
            .format(&time::format_description::well_known::Rfc3339)
            .expect("caller time");
        assert!(!trace_json.contains(&caller_time));
        assert!(!trace_json.contains(&first.encoded));
        assert!(!trace_json.contains(&raw_jti));
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
    fn trace_redaction_preserves_only_bounded_credential_correlation_digests() {
        let correlation = format!("sha256:{}", "a".repeat(64));
        let run_id = RunId::new();
        let store = InMemoryTraceStore::default();
        let event = TraceEvent::new(
            run_id.clone(),
            0,
            OffsetDateTime::now_utc(),
            TraceEventKind::DaemonAudit {
                endpoint: "splendor.runs.create".to_string(),
                audit: AuditAttribution {
                    principal: splendor_types::ClientPrincipal::new("app", "client"),
                    credential_id: Some(correlation.clone()),
                    requested_at: OffsetDateTime::now_utc(),
                },
            },
        );
        store
            .append(
                &run_id.to_string(),
                serde_json::to_value(event).expect("audit event"),
            )
            .expect("append audit event");
        let records = store.read(&run_id.to_string()).expect("audit records");
        let redacted = redact_trace_records(records.clone());

        assert_eq!(
            redacted[0]
                .payload
                .pointer("/kind/DaemonAudit/audit/credential_id")
                .and_then(serde_json::Value::as_str),
            Some(correlation.as_str())
        );
        assert_eq!(redacted, records);
        assert!(!is_bounded_sha256_correlation(&format!(
            "sha256:{}",
            "A".repeat(64)
        )));
        assert_eq!(
            redact_trace_value(serde_json::json!({"credential_id": correlation}))["credential_id"],
            "[REDACTED]"
        );
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
                requested_at: None,
                authority_obligation_receipts: Vec::new(),
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
        let registrations =
            action_profiles_for_request(&request, &work_order).expect("trusted action profiles");
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].action_name, "policy_only");
        assert_eq!(registrations[0].adapter, "daemon.local");
        assert!(
            serde_json::from_value::<RegisteredAction>(serde_json::json!({
                "name": "policy_only",
                "adapter": "daemon.local",
                "required_permissions": [],
                "credential": "not-authority"
            }))
            .is_err()
        );

        let mut permission_work_order = work_order.clone();
        permission_work_order.allowed_permissions = vec!["unit.write".to_string()];
        let error = action_profiles_for_request(&request, &permission_work_order)
            .expect_err("policy permission omission must fail admission");
        assert_eq!(
            error.body.code,
            "trusted_action_profile_permission_mismatch"
        );

        let mut narrowed_registration = request.clone();
        narrowed_registration.registered_actions = vec![RegisteredAction {
            name: "policy_only".to_string(),
            adapter: "daemon.local".to_string(),
            required_permissions: Some(Vec::new()),
        }];
        let error = action_profiles_for_request(&narrowed_registration, &permission_work_order)
            .expect_err("registered profile cannot narrow signed permissions");
        assert_eq!(
            error.body.code,
            "trusted_action_profile_permission_mismatch"
        );

        let mut duplicate_permissions = request.clone();
        duplicate_permissions.registered_actions = vec![RegisteredAction {
            name: "policy_only".to_string(),
            adapter: "daemon.local".to_string(),
            required_permissions: Some(vec!["unit.write".to_string(); 2]),
        }];
        let error = action_profiles_for_request(&duplicate_permissions, &permission_work_order)
            .expect_err("duplicate registered permissions must fail admission");
        assert_eq!(
            error.body.code,
            "registered_action_required_permissions_duplicate"
        );

        let mut excessive_permissions = request.clone();
        excessive_permissions.registered_actions = vec![RegisteredAction {
            name: "policy_only".to_string(),
            adapter: "daemon.local".to_string(),
            required_permissions: Some(
                (0..65)
                    .map(|index| format!("unit.permission.{index}"))
                    .collect(),
            ),
        }];
        let error = action_profiles_for_request(&excessive_permissions, &permission_work_order)
            .expect_err("oversized registered permissions must fail admission");
        assert_eq!(
            error.body.code,
            "registered_action_required_permissions_limit_exceeded"
        );

        let mut multi_adapter_work_order = work_order.clone();
        multi_adapter_work_order.allowed_adapters =
            vec!["daemon.local".to_string(), "daemon.secondary".to_string()];
        let error = action_profiles_for_request(&request, &multi_adapter_work_order)
            .expect_err("unsigned action pairing cannot disambiguate multiple adapters");
        assert_eq!(
            error.body.code,
            "ambiguous_work_order_action_adapter_profile"
        );

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
            requested_at: None,
            authority_obligation_receipts: Vec::new(),
        }];
        let error = action_profiles_for_request(&direct_registration_request, &work_order)
            .expect_err("out-of-work-order policy action must fail");
        assert_eq!(error.body.code, "trusted_action_profile_missing");

        let lock = lock_error();
        assert_eq!(lock.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(lock.body.code, "runtime_lock_error");

        let run_id = RunId::new();
        let mut keyring = WorkOrderKeyring::new();
        keyring
            .insert_shared_secret("key", b"unit-work-order-secret")
            .expect("unit work-order key");
        let validated = splendor_types::validate_work_order(
            &request.work_order,
            &WorkOrderValidationContext {
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                run_id: None,
                expected_placement_target: None,
                now: OffsetDateTime::now_utc(),
            },
            &keyring,
        )
        .expect("validated unit work order");
        let run_authority = RunAuthorityHandle::admit_signed_work_order_compatibility(
            &validated,
            run_id.clone(),
            format!("splendor.daemon.run:{run_id}"),
        )
        .expect("unit run authority");
        let bound_work_order_payload_digest =
            bound_work_order_payload_digest(&work_order, &run_id).expect("bound work-order digest");
        let slot = RunSlot {
            run_id,
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            status: RunStatus::Pending,
            scheduler: Scheduler::new(SchedulerConfig::default()),
            state_store: Arc::new(InMemoryStateStore::default()),
            trace_store: Arc::new(InMemoryTraceStore::default()),
            gateway: Arc::new(splendor_gateway::UnimplementedGateway),
            run_authority,
            work_order_id: work_order.work_order_id.clone(),
            work_order_envelope: request.work_order.clone(),
            bound_work_order_payload_digest,
            authority_recorder: Arc::new(splendor_gateway::NoPreEffectAuthorityDecisionRecorder),
            authority_obligation_verifier: Arc::new(
                splendor_gateway::NoAuthorityObligationVerifier,
            ),
            authority_obligation_receipt_verifier: None,
            action_profiles: Vec::new(),
            approval_policies: Vec::new(),
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
            state_head: None,
            adapter_executions: Arc::new(AtomicU64::new(0)),
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

        let duplicate = sync_device_trace_buffer(
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
        .expect("exact reconnect retry is revalidated")
        .0;
        assert!(duplicate.accepted);
        assert_eq!(duplicate.accepted_records, 2);

        let mut reordered = second.clone();
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
            Some("trace_sync_sequence_mismatch")
        );

        let mut hash_mismatch = first.clone();
        hash_mismatch.prev_event_hash = Some(ContentHash::blake3(b"wrong-previous-event"));
        let rejected = sync_device_trace_buffer(
            Path(node_id.clone()),
            State(state.clone()),
            Json(DeviceTraceBufferSyncRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                run_id: run_id.clone(),
                records: vec![hash_mismatch],
                simulate_tamper: false,
            }),
        )
        .await
        .expect("hash-chain mismatch returns denial response")
        .0;
        assert!(!rejected.accepted);
        assert_eq!(
            rejected.reason_code.as_deref(),
            Some("trace_sync_hash_chain_mismatch")
        );

        let mut payload_tampered = second.clone();
        payload_tampered.payload = serde_json::json!({"event": "tampered"});
        let rejected = sync_device_trace_buffer(
            Path(node_id.clone()),
            State(state.clone()),
            Json(DeviceTraceBufferSyncRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                run_id: run_id.clone(),
                records: vec![first.clone(), payload_tampered],
                simulate_tamper: false,
            }),
        )
        .await
        .expect("payload tamper returns denial response")
        .0;
        assert!(!rejected.accepted);
        assert_eq!(rejected.accepted_records, 0);
        assert_eq!(
            rejected.reason_code.as_deref(),
            Some("trace_sync_event_hash_mismatch")
        );

        let mut event_hash_tampered = first.clone();
        event_hash_tampered.event_hash = ContentHash::blake3(b"forged-event-hash");
        let rejected = sync_device_trace_buffer(
            Path(node_id.clone()),
            State(state.clone()),
            Json(DeviceTraceBufferSyncRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                run_id: run_id.clone(),
                records: vec![event_hash_tampered],
                simulate_tamper: false,
            }),
        )
        .await
        .expect("event hash tamper returns denial response")
        .0;
        assert!(!rejected.accepted);
        assert_eq!(rejected.accepted_records, 0);
        assert_eq!(
            rejected.reason_code.as_deref(),
            Some("trace_sync_event_hash_mismatch")
        );

        let mut cross_run = first.clone();
        cross_run.run_id = RunId::new().to_string();
        let rejected = sync_device_trace_buffer(
            Path(node_id.clone()),
            State(state.clone()),
            Json(DeviceTraceBufferSyncRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                run_id: run_id.clone(),
                records: vec![cross_run],
                simulate_tamper: false,
            }),
        )
        .await
        .expect("cross-run trace returns denial response")
        .0;
        assert!(!rejected.accepted);
        assert_eq!(rejected.accepted_records, 0);
        assert_eq!(
            rejected.reason_code.as_deref(),
            Some("trace_sync_run_mismatch")
        );

        let mut mismatched_payload_run = first.clone();
        mismatched_payload_run.payload =
            serde_json::json!({"run_id": RunId::new().to_string(), "event": "first"});
        let rejected = sync_device_trace_buffer(
            Path(node_id.clone()),
            State(state.clone()),
            Json(DeviceTraceBufferSyncRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                run_id: run_id.clone(),
                records: vec![mismatched_payload_run],
                simulate_tamper: false,
            }),
        )
        .await
        .expect("mismatched payload run identity returns denial response")
        .0;
        assert!(!rejected.accepted);
        assert_eq!(
            rejected.reason_code.as_deref(),
            Some("trace_sync_run_mismatch")
        );

        let mut malformed_payload_run = first.clone();
        malformed_payload_run.payload = serde_json::json!({"run_id": 7, "event": "first"});
        let rejected = sync_device_trace_buffer(
            Path(node_id.clone()),
            State(state.clone()),
            Json(DeviceTraceBufferSyncRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                run_id: run_id.clone(),
                records: vec![malformed_payload_run],
                simulate_tamper: false,
            }),
        )
        .await
        .expect("malformed payload run identity returns denial response")
        .0;
        assert!(!rejected.accepted);
        assert_eq!(rejected.accepted_records, 0);
        assert_eq!(
            rejected.reason_code.as_deref(),
            Some("trace_sync_run_mismatch")
        );

        let empty = sync_device_trace_buffer(
            Path(node_id.clone()),
            State(state.clone()),
            Json(DeviceTraceBufferSyncRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                run_id: run_id.clone(),
                records: Vec::new(),
                simulate_tamper: false,
            }),
        )
        .await
        .expect("empty trace sync returns denial response")
        .0;
        assert!(!empty.accepted);
        assert_eq!(empty.accepted_records, 0);
        assert_eq!(empty.reason_code.as_deref(), Some("trace_sync_empty_batch"));

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
    async fn authenticated_device_profile_ingress_denies_before_audit_or_mutation() {
        let state = locked_unit_state();
        let tenant_id = TenantId::new();
        let register_credential =
            unit_credential(tenant_id.clone(), vec![EndpointScope::DeviceRegister]);

        let mut unauthenticated = unit_profile(NodeId::new(), tenant_id.clone());
        unauthenticated.capabilities = vec!["Basic dTpw".to_string()];
        let error = register_device_profile(
            State(state.clone()),
            Json(RegisterDeviceProfileRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                profile: unauthenticated,
            }),
        )
        .await
        .expect_err("authentication must precede profile screening");
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert_eq!(error.body.code, "anonymous_non_dev_call");

        for field in [
            "device_kind",
            "capabilities",
            "allowed_physical_actions",
            "forbidden_action_classes",
            "safety_constraints_value",
            "safety_constraints_key",
            "runtime_mode",
            "safety_status_value",
            "safety_status_key",
            "policy_id",
            "policy_expires_at",
            "trace_integrity",
            "registered_at",
            "safety_constraints_structured_coordinate",
            "safety_status_bom",
            "policy_id_nul",
            "trace_integrity_form",
            "safety_status_percent_bom",
            "trace_integrity_percent_nul",
        ] {
            let node_id = NodeId::new();
            let canary = format!("C03_DEVICE_PROFILE_{}_CANARY", field.to_ascii_uppercase());
            let credential_value =
                format!("https://example.invalid/form?value=Basic+dTpw&label={canary}");
            let mut profile = unit_profile(node_id.clone(), tenant_id.clone());
            match field {
                "device_kind" => profile.device_kind = credential_value.clone(),
                "capabilities" => profile.capabilities = vec![credential_value.clone()],
                "allowed_physical_actions" => {
                    profile.allowed_physical_actions = vec![credential_value.clone()]
                }
                "forbidden_action_classes" => {
                    profile.forbidden_action_classes = vec![credential_value.clone()]
                }
                "safety_constraints_value" => {
                    profile.safety_constraints = serde_json::json!({
                        "allowed_zones": ["zone_a", {"nested": [credential_value.clone()]}]
                    })
                }
                "safety_constraints_key" => {
                    profile.safety_constraints = serde_json::Value::Object(
                        [(credential_value.clone(), serde_json::json!("ordinary"))]
                            .into_iter()
                            .collect(),
                    )
                }
                "runtime_mode" => profile.runtime_mode = credential_value.clone(),
                "safety_status_value" => {
                    profile.safety_status = serde_json::json!({
                        "current_zone": {"nested": [credential_value.clone()]}
                    })
                }
                "safety_status_key" => {
                    profile.safety_status = serde_json::Value::Object(
                        [(credential_value.clone(), serde_json::json!("ordinary"))]
                            .into_iter()
                            .collect(),
                    )
                }
                "policy_id" => profile.policy_cache.policy_id = credential_value.clone(),
                "policy_expires_at" => profile.policy_cache.expires_at = credential_value.clone(),
                "trace_integrity" => profile.trace_buffer.integrity = credential_value.clone(),
                "registered_at" => profile.registered_at = credential_value.clone(),
                "safety_constraints_structured_coordinate" => {
                    profile.safety_constraints = serde_json::json!({
                        "allowed_zones": [{"name": "VAULT_TOKEN", "value": canary.clone()}]
                    })
                }
                "safety_status_bom" => {
                    profile.safety_status = serde_json::json!({
                        "current_zone": format!("\u{feff}Basic dTpw {canary}")
                    })
                }
                "policy_id_nul" => {
                    profile.policy_cache.policy_id = format!("B\0e\0a\0r\0e\0r\0 \0x\0 {canary}")
                }
                "trace_integrity_form" => {
                    profile.trace_buffer.integrity =
                        format!("safe=1&value=Basic+dTpw&label={canary}")
                }
                "safety_status_percent_bom" => {
                    profile.safety_status = serde_json::json!({
                        "current_zone": format!("value=%EF%BB%BFBasic%20dTpw&label={canary}")
                    })
                }
                "trace_integrity_percent_nul" => {
                    profile.trace_buffer.integrity =
                        format!("value=B%00e%00a%00r%00e%00r%00%20x&label={canary}")
                }
                _ => unreachable!("closed device profile field matrix"),
            }

            let error = register_device_profile(
                State(state.clone()),
                Json(RegisterDeviceProfileRequest {
                    credential: Some(register_credential.clone()),
                    audit_attribution: Some(unit_audit()),
                    profile,
                }),
            )
            .await
            .expect_err("raw device profile metadata must deny");
            assert_eq!(error.status, StatusCode::BAD_REQUEST, "{field}");
            assert_eq!(error.body.code, RAW_CREDENTIAL_INPUT_DENIED, "{field}");
            assert_eq!(error.body.message, RAW_CREDENTIAL_INPUT_DENIED, "{field}");
            assert!(error.body.details.is_null(), "{field}");
            assert!(!serde_json::to_string(&error.body)
                .expect("error serializes")
                .contains(&canary));
            assert!(!state
                .inner
                .device_profiles
                .lock()
                .expect("profiles")
                .contains_key(&node_id));
            assert!(state
                .inner
                .device_audit
                .lock()
                .expect("device audit")
                .is_empty());
        }

        let node_id = NodeId::new();
        let mut ordinary_profile = unit_profile(node_id.clone(), tenant_id.clone());
        ordinary_profile.safety_status["descriptor"] = serde_json::json!({
            "name": "token",
            "type": "string"
        });
        let registered = register_device_profile(
            State(state.clone()),
            Json(RegisterDeviceProfileRequest {
                credential: Some(register_credential),
                audit_attribution: Some(unit_audit()),
                profile: ordinary_profile,
            }),
        )
        .await
        .expect("ordinary authenticated device profile remains accepted")
        .0;
        assert_eq!(registered.profile.node_id, node_id);

        let anonymous = get_device_status(
            Path(node_id.clone()),
            State(state.clone()),
            HeaderMap::new(),
        )
        .await
        .expect_err("device read remains authenticated");
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
        assert_eq!(anonymous.body.code, "anonymous_non_dev_call");

        let read_credential = unit_credential(tenant_id, vec![EndpointScope::DeviceRead]);
        let read = get_device_status(
            Path(node_id),
            State(state.clone()),
            unit_credential_headers(&read_credential),
        )
        .await
        .expect("authenticated ordinary device profile read")
        .0;
        assert_eq!(read.device_kind, "drone_sim");
        assert_eq!(read.safety_status["descriptor"]["name"], "token");
        assert!(!serde_json::to_string(&read)
            .expect("profile serializes")
            .contains("C03_DEVICE_PROFILE_"));
        assert_eq!(
            state.inner.device_audit.lock().expect("device audit").len(),
            1
        );
    }

    #[tokio::test]
    async fn operator_intervention_raw_metadata_denies_before_audit_and_persistence() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let node_id = NodeId::new();
        let expires_at = (OffsetDateTime::now_utc() + time::Duration::minutes(15))
            .format(&Rfc3339)
            .expect("expiry");

        for field in ["intervention_id", "action_name", "reason", "expires_at"] {
            let canary = format!("C03_OPERATOR_{}_CANARY", field.to_ascii_uppercase());
            let credential_value =
                format!("https://example.invalid/form?value=Basic+dTpw&label={canary}");
            let mut request = OperatorInterventionRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                intervention_id: format!("intervention_{field}"),
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                run_id: run_id.clone(),
                node_id: node_id.clone(),
                action_name: "move_to_waypoint".to_string(),
                reason: "operator review".to_string(),
                expires_at: expires_at.clone(),
            };
            match field {
                "intervention_id" => request.intervention_id = credential_value.clone(),
                "action_name" => request.action_name = credential_value.clone(),
                "reason" => request.reason = credential_value.clone(),
                "expires_at" => request.expires_at = credential_value.clone(),
                _ => unreachable!("closed operator request field matrix"),
            }

            let error = request_operator_intervention(State(state.clone()), Json(request))
                .await
                .expect_err("raw operator request metadata must deny");
            assert_eq!(error.status, StatusCode::BAD_REQUEST, "{field}");
            assert_eq!(error.body.code, RAW_CREDENTIAL_INPUT_DENIED, "{field}");
            assert_eq!(error.body.message, RAW_CREDENTIAL_INPUT_DENIED, "{field}");
            assert!(error.body.details.is_null(), "{field}");
            assert!(!serde_json::to_string(&error.body)
                .expect("error serializes")
                .contains(&canary));
            assert!(state
                .inner
                .operator_interventions
                .lock()
                .expect("interventions")
                .is_empty());
            assert!(state
                .inner
                .device_audit
                .lock()
                .expect("device audit")
                .is_empty());
        }

        let _ = request_operator_intervention(
            State(state.clone()),
            Json(OperatorInterventionRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                intervention_id: "intervention_screened".to_string(),
                tenant_id,
                agent_id,
                run_id,
                node_id,
                action_name: "move_to_waypoint".to_string(),
                reason: "operator review".to_string(),
                expires_at: expires_at.clone(),
            }),
        )
        .await
        .expect("safe intervention request");
        assert_eq!(
            state
                .inner
                .operator_interventions
                .lock()
                .expect("interventions")
                .len(),
            1
        );
        assert_eq!(
            state.inner.device_audit.lock().expect("device audit").len(),
            1
        );

        for field in ["reason", "expires_at"] {
            let canary = format!(
                "C03_OPERATOR_DECISION_{}_CANARY",
                field.to_ascii_uppercase()
            );
            let credential_value =
                format!("https://example.invalid/form?value=Basic+dTpw&label={canary}");
            let mut request = OperatorDecisionRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                reason: "cleared".to_string(),
                expires_at: Some(expires_at.clone()),
            };
            match field {
                "reason" => request.reason = credential_value.clone(),
                "expires_at" => request.expires_at = Some(credential_value.clone()),
                _ => unreachable!("closed operator decision field matrix"),
            }
            let error = grant_operator_intervention(
                Path("intervention_screened".to_string()),
                State(state.clone()),
                Json(request),
            )
            .await
            .expect_err("raw operator decision metadata must deny");
            assert_eq!(error.status, StatusCode::BAD_REQUEST, "{field}");
            assert_eq!(error.body.code, RAW_CREDENTIAL_INPUT_DENIED, "{field}");
            assert_eq!(error.body.message, RAW_CREDENTIAL_INPUT_DENIED, "{field}");
            assert!(error.body.details.is_null(), "{field}");
            assert!(!serde_json::to_string(&error.body)
                .expect("error serializes")
                .contains(&canary));
            let interventions = state
                .inner
                .operator_interventions
                .lock()
                .expect("interventions");
            let record = interventions
                .get("intervention_screened")
                .expect("safe record retained");
            assert_eq!(record.status, "requested");
            assert_eq!(record.reason, "operator review");
            drop(interventions);
            assert_eq!(
                state.inner.device_audit.lock().expect("device audit").len(),
                1
            );
        }
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
                node_id: node_id.clone(),
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
        validate_operator_evidence(
            &state,
            &evidence,
            &tenant_id,
            &agent_id,
            &run_id,
            &node_id,
            "move_to_waypoint",
        )
        .expect("granted evidence validates");

        let scope_error = validate_operator_evidence(
            &state, &evidence, &tenant_id, &agent_id, &run_id, &node_id, "dock",
        )
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
        let unknown_error = validate_operator_evidence(
            &state,
            &unknown,
            &tenant_id,
            &agent_id,
            &run_id,
            &node_id,
            "move_to_waypoint",
        )
        .expect_err("unknown intervention denied");
        assert_eq!(unknown_error.body.code, "operator_intervention_unknown");

        let mut extended = evidence.clone();
        extended.expires_at = (OffsetDateTime::now_utc() + time::Duration::minutes(30))
            .format(&Rfc3339)
            .expect("extended expiry");
        let extended_error = validate_operator_evidence(
            &state,
            &extended,
            &tenant_id,
            &agent_id,
            &run_id,
            &node_id,
            "move_to_waypoint",
        )
        .expect_err("caller cannot extend authoritative intervention expiry");
        assert_eq!(
            extended_error.body.code,
            "operator_intervention_expiry_mismatch"
        );

        for (label, scoped_tenant, scoped_agent, scoped_run, scoped_node, scoped_action) in [
            (
                "wrong tenant",
                TenantId::new(),
                agent_id.clone(),
                run_id.clone(),
                node_id.clone(),
                "move_to_waypoint",
            ),
            (
                "wrong agent",
                tenant_id.clone(),
                splendor_types::AgentId::new(),
                run_id.clone(),
                node_id.clone(),
                "move_to_waypoint",
            ),
            (
                "wrong run",
                tenant_id.clone(),
                agent_id.clone(),
                RunId::new(),
                node_id.clone(),
                "move_to_waypoint",
            ),
            (
                "wrong node/device reuse",
                tenant_id.clone(),
                agent_id.clone(),
                run_id.clone(),
                NodeId::new(),
                "move_to_waypoint",
            ),
            (
                "wrong action",
                tenant_id.clone(),
                agent_id.clone(),
                run_id.clone(),
                node_id.clone(),
                "dock",
            ),
        ] {
            let error = validate_operator_evidence(
                &state,
                &evidence,
                &scoped_tenant,
                &scoped_agent,
                &scoped_run,
                &scoped_node,
                scoped_action,
            )
            .expect_err(label);
            assert_eq!(error.body.code, "operator_intervention_scope_mismatch");
        }

        {
            let mut interventions = state
                .inner
                .operator_interventions
                .lock()
                .expect("interventions");
            interventions
                .get_mut("intervention_unit")
                .expect("intervention")
                .expires_at = "not-rfc3339".to_string();
        }
        let malformed_authoritative_expiry = validate_operator_evidence(
            &state,
            &evidence,
            &tenant_id,
            &agent_id,
            &run_id,
            &node_id,
            "move_to_waypoint",
        )
        .expect_err("malformed authoritative intervention expiry fails closed");
        assert_eq!(
            malformed_authoritative_expiry.body.code,
            "operator_intervention_bad_expiry"
        );

        {
            let mut interventions = state
                .inner
                .operator_interventions
                .lock()
                .expect("interventions");
            interventions
                .get_mut("intervention_unit")
                .expect("intervention")
                .expires_at = (OffsetDateTime::now_utc() - time::Duration::minutes(1))
                .format(&Rfc3339)
                .expect("expired authoritative record");
        }
        let expired_error = validate_operator_evidence(
            &state,
            &evidence,
            &tenant_id,
            &agent_id,
            &run_id,
            &node_id,
            "move_to_waypoint",
        )
        .expect_err("authoritative intervention expiry controls");
        assert_eq!(expired_error.body.code, "operator_intervention_expired");

        {
            let mut interventions = state
                .inner
                .operator_interventions
                .lock()
                .expect("interventions");
            interventions
                .get_mut("intervention_unit")
                .expect("intervention")
                .expires_at = expires_at.clone();
        }

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
        let denied_error = validate_operator_evidence(
            &state,
            &denied_evidence,
            &tenant_id,
            &agent_id,
            &run_id,
            &node_id,
            "move_to_waypoint",
        )
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
        create_unit_run(
            &state,
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            10,
            None,
        )
        .await;
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

        let other_node_id = NodeId::new();
        let _ = register_device_profile(
            State(state.clone()),
            Json(RegisterDeviceProfileRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                profile: unit_profile(other_node_id.clone(), tenant_id.clone()),
            }),
        )
        .await
        .expect("register second device profile");
        let intervention_expiry = (OffsetDateTime::now_utc() + time::Duration::minutes(15))
            .format(&Rfc3339)
            .expect("intervention expiry");
        let _ = request_operator_intervention(
            State(state.clone()),
            Json(OperatorInterventionRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                intervention_id: "intervention_device_bound".to_string(),
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                run_id: run_id.clone(),
                node_id: node_id.clone(),
                action_name: "move_to_waypoint".to_string(),
                reason: "device-bound operator review".to_string(),
                expires_at: intervention_expiry.clone(),
            }),
        )
        .await
        .expect("request device-bound intervention");
        let grant = grant_operator_intervention(
            Path("intervention_device_bound".to_string()),
            State(state.clone()),
            Json(OperatorDecisionRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                reason: "device one cleared".to_string(),
                expires_at: Some(intervention_expiry),
            }),
        )
        .await
        .expect("grant device-bound intervention")
        .0;
        let mut reused_on_other_device = physical_request(
            run_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
            "move_to_waypoint",
            safe_context(),
        );
        reused_on_other_device.operator_intervention_evidence = grant.evidence;
        let executions_before_reuse = unit_adapter_execution_count(&state, &run_id);
        let reuse_error = submit_physical_action(
            Path(other_node_id),
            State(state.clone()),
            Json(reused_on_other_device),
        )
        .await
        .expect_err("intervention grant cannot be reused on another device");
        assert_eq!(reuse_error.status, StatusCode::FORBIDDEN);
        assert_eq!(
            reuse_error.body.code,
            "operator_intervention_scope_mismatch"
        );
        assert_eq!(
            unit_adapter_execution_count(&state, &run_id),
            executions_before_reuse
        );

        let executed_request = physical_request(
            run_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
            "move_to_waypoint",
            safe_context(),
        );
        let executed_action_id = executed_request
            .action_request
            .action_id
            .clone()
            .expect("physical action id");
        let executed = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(executed_request),
        )
        .await
        .expect("execute bounded action")
        .0;
        assert_eq!(executed.status, ActionStatus::Executed);
        assert_non_tick_action_trace(&state, &run_id, &executed_action_id);

        let mut offline_helper = safe_context();
        offline_helper.offline = true;
        offline_helper.cloud_helper_proposal_id = Some("proposal_advisory_unit".to_string());
        let offline_executed = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "return_to_base",
                offline_helper,
            )),
        )
        .await
        .expect("offline advisory proposal remains locally verified")
        .0;
        assert_eq!(offline_executed.status, ActionStatus::Executed);

        let mut geofence = safe_context();
        geofence.zone_ref = Some("zone_b".to_string());
        let denied_request = physical_request(
            run_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
            "move_to_waypoint",
            geofence,
        );
        let denied_action_id = denied_request
            .action_request
            .action_id
            .clone()
            .expect("physical action id");
        let denied = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(denied_request),
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
        assert_non_tick_action_trace(&state, &run_id, &denied_action_id);

        let mut failed_request = physical_request(
            run_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
            "move_to_waypoint",
            safe_context(),
        );
        failed_request
            .action_request
            .action
            .params
            .as_object_mut()
            .expect("physical action params")
            .insert("fail_adapter".to_string(), serde_json::Value::Bool(true));
        let failed_action_id = failed_request
            .action_request
            .action_id
            .clone()
            .expect("failed physical action id");
        let failed = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(failed_request),
        )
        .await
        .expect("physical adapter failure returns an outcome")
        .0;
        assert_eq!(failed.status, ActionStatus::Failed, "{failed:?}");
        assert_non_tick_action_trace(&state, &run_id, &failed_action_id);
        {
            let run = state.run_slot(&run_id).expect("run");
            let slot = run.lock().expect("run");
            let failed_events = slot
                .trace_store
                .read(&run_id.to_string())
                .expect("physical failure trace records")
                .into_iter()
                .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload).ok())
                .filter(|event| event.identity.action_id.as_ref() == Some(&failed_action_id))
                .collect::<Vec<_>>();
            assert!(!failed_events
                .iter()
                .any(|event| matches!(event.kind, TraceEventKind::ActionDenied { .. })));
            let failed_trace = failed_events
                .iter()
                .find_map(|event| match &event.kind {
                    TraceEventKind::ActionFailed { error, result, .. } => Some((error, result)),
                    _ => None,
                })
                .expect("physical failure is traced as action.failed");
            assert_eq!(
                failed_trace.0,
                failed.error.as_ref().expect("adapter error")
            );
            assert_eq!(failed_trace.1, &failed.verification);
        }

        let executions_before_replay = unit_adapter_execution_count(&state, &run_id);
        let replay = replay_run(
            Path(run_id.clone()),
            State(state.clone()),
            Json(ReplayRequest {
                credential: Some(unit_replay_credential(tenant_id.clone())),
                audit_attribution: Some(unit_audit()),
                mode: "inspect_only".to_string(),
                side_effects_allowed: false,
            }),
        )
        .await
        .expect("inspect-only physical replay")
        .0;
        assert!(replay.action_event_count >= 2);
        assert_non_tick_action_trace(&state, &run_id, &executed_action_id);
        assert_non_tick_action_trace(&state, &run_id, &denied_action_id);
        assert_eq!(
            unit_adapter_execution_count(&state, &run_id),
            executions_before_replay
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

    #[tokio::test]
    async fn requester_safety_fields_cannot_override_unsafe_process_owned_device_state() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let node_id = NodeId::new();
        create_unit_run(
            &state,
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            100,
            None,
        )
        .await;

        let forged_safe_context = SafetyContext {
            allowed_zone_refs: vec!["zone_a".to_string()],
            zone_ref: Some("zone_a".to_string()),
            altitude_m: Some(0.0),
            max_altitude_m: Some(1_000.0),
            battery_percent: Some(1.0),
            privacy_clear: true,
            human_proximity_clear: true,
            emergency_stop_clear: true,
            offline: false,
            policy_cache_expired: false,
            high_risk: false,
            cloud_helper_direct_authority: false,
            cloud_helper_proposal_id: Some("proposal_forged_safe".to_string()),
        };
        let mut unsafe_profiles = Vec::new();

        let mut low_battery = unit_profile(node_id.clone(), tenant_id.clone());
        low_battery.safety_status["battery_percent"] = serde_json::json!(0.01);
        unsafe_profiles.push(("battery", low_battery));

        let mut emergency_stop = unit_profile(node_id.clone(), tenant_id.clone());
        emergency_stop.safety_status["emergency_stop_clear"] = serde_json::json!(false);
        unsafe_profiles.push(("emergency_stop", emergency_stop));

        let mut collision = unit_profile(node_id.clone(), tenant_id.clone());
        collision.safety_status["collision_risk"] = serde_json::json!("critical");
        unsafe_profiles.push(("collision", collision));

        let mut geofence = unit_profile(node_id.clone(), tenant_id.clone());
        geofence.safety_constraints["allowed_zones"] = serde_json::json!(["zone_b"]);
        unsafe_profiles.push(("geofence", geofence));

        let mut altitude = unit_profile(node_id.clone(), tenant_id.clone());
        altitude.safety_status["altitude_m"] = serde_json::json!(100.0);
        unsafe_profiles.push(("altitude", altitude));

        let mut privacy = unit_profile(node_id.clone(), tenant_id.clone());
        privacy.safety_status["privacy_clear"] = serde_json::json!(false);
        unsafe_profiles.push(("privacy", privacy));

        let mut proximity = unit_profile(node_id.clone(), tenant_id.clone());
        proximity.safety_status["human_proximity_clear"] = serde_json::json!(false);
        unsafe_profiles.push(("proximity", proximity));

        let mut stale_offline_policy = unit_profile(node_id.clone(), tenant_id.clone());
        stale_offline_policy.safety_status["offline"] = serde_json::json!(true);
        stale_offline_policy.policy_cache.expired = true;
        stale_offline_policy.policy_cache.expires_at = (OffsetDateTime::now_utc()
            - time::Duration::minutes(1))
        .format(&Rfc3339)
        .expect("expired policy timestamp");
        unsafe_profiles.push(("offline_policy", stale_offline_policy));

        let mut cloud_authority = unit_profile(node_id.clone(), tenant_id.clone());
        cloud_authority.safety_status["cloud_helper_direct_authority"] = serde_json::json!(true);
        unsafe_profiles.push(("cloud_authority", cloud_authority));

        for (scenario, profile) in &unsafe_profiles {
            state
                .inner
                .device_profiles
                .lock()
                .expect("device profiles")
                .insert(node_id.clone(), profile.clone());
            let outcome = submit_physical_action(
                Path(node_id.clone()),
                State(state.clone()),
                Json(physical_request(
                    run_id.clone(),
                    tenant_id.clone(),
                    agent_id.clone(),
                    "move_to_waypoint",
                    forged_safe_context.clone(),
                )),
            )
            .await
            .expect("unsafe process-owned state returns a traced gateway outcome")
            .0;
            assert_ne!(
                outcome.status,
                ActionStatus::Executed,
                "scenario={scenario}"
            );
            assert!(
                physical_safety_artifact(&outcome).is_some(),
                "missing safety evidence for scenario={scenario}: {outcome:?}"
            );
        }
        assert_eq!(unit_adapter_execution_count(&state, &run_id), 0);

        let run = state.run_slot(&run_id).expect("run");
        let slot = run.lock().expect("run");
        let safety_events = slot
            .trace_store
            .read(&run_id.to_string())
            .expect("trace")
            .into_iter()
            .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload).ok())
            .filter_map(|event| match event.kind {
                TraceEventKind::DaemonAudit { endpoint, .. }
                    if endpoint == "safety.verification.completed"
                        || endpoint == "safety.verification.denied" =>
                {
                    Some(endpoint)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            safety_events
                .iter()
                .filter(|event| event.as_str() == "safety.verification.completed")
                .count(),
            unsafe_profiles.len()
        );
        assert_eq!(
            safety_events
                .iter()
                .filter(|event| event.as_str() == "safety.verification.denied")
                .count(),
            unsafe_profiles.len()
        );
    }

    #[tokio::test]
    async fn approved_action_completion_does_not_overwrite_concurrent_cancellation() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        create_unit_run(
            &state,
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            10,
            None,
        )
        .await;
        let now = OffsetDateTime::now_utc();
        let action_id = ActionId::new();
        let challenge = ApprovalChallenge {
            schema_version: splendor_types::APPROVAL_CHALLENGE_SCHEMA_VERSION.to_string(),
            approval_id: splendor_types::ApprovalId::new(),
            tenant_id,
            agent_id,
            run_id: run_id.clone(),
            action_id: action_id.clone(),
            action_name: "move_to_waypoint".to_string(),
            adapter: "device-sim".to_string(),
            policy_id: "policy_race".to_string(),
            risk_level: Some("high".to_string()),
            subject: splendor_types::PrincipalId::new(),
            authority_decision_id: splendor_types::AuthorityDecisionId::new(),
            obligation_id: splendor_types::AuthorityObligationId::new(),
            receipt_audience: format!("splendor.daemon.run:{run_id}"),
            canonical_request_digest: format!("blake3:{}", "1".repeat(64)),
            gateway_action_request_digest: format!("blake3:{}", "2".repeat(64)),
            physical_action_resource_coordinate: Some(
                splendor_types::PhysicalActionResourceCoordinate::physical_node(NodeId::new()),
            ),
            authority_decision_digest: format!("blake3:{}", "3".repeat(64)),
            requested_at: now,
            expires_at: now + time::Duration::minutes(5),
        };
        let outcome = ActionOutcome {
            action_id,
            status: ActionStatus::Executed,
            verification: VerificationResult::allow(),
            post_verification: None,
            output: Some(serde_json::Value::Null),
            error: None,
            approval_challenge: None,
            completed_at: now,
        };
        let run = state.run_slot(&run_id).expect("run");
        let mut slot = run.lock().expect("run");
        slot.pending_approval = Some(challenge.clone());
        slot.status = RunStatus::Cancelled;

        resume_after_approved_action(&mut slot, Some(&challenge), &outcome)
            .expect("stale completion is ignored");

        assert_eq!(slot.status, RunStatus::Cancelled);
        assert_eq!(slot.pending_approval, Some(challenge));
    }

    #[tokio::test]
    async fn waiting_approval_raw_denial_requires_and_uses_the_exact_pending_challenge() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        create_unit_run(
            &state,
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            10,
            None,
        )
        .await;
        let mut action =
            authority_physical_request(run_id.clone(), tenant_id.clone(), agent_id.clone());
        action.adapter = None;
        let mut denial = ApprovalEvidence::new(
            splendor_types::ApprovalId::new(),
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            splendor_types::ApprovalDecision::Denied,
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
        )
        .with_action_name(action.action.name.clone())
        .with_adapter("device-sim");
        denial.action_id = Some(action.action_id.clone());
        action.approval_evidence = Some(denial);

        let run = state.run_slot(&run_id).expect("run");
        let mut slot = run.lock().expect("run");
        slot.status = RunStatus::WaitingForApproval;
        slot.pending_approval = None;
        let missing = slot
            .run_authority
            .admit_action_request(
                RunActionAdmissionState::WaitingForApproval,
                None,
                &mut action,
                Some("device-sim"),
                OffsetDateTime::now_utc(),
            )
            .expect_err("missing challenge fails closed");
        assert_eq!(missing.reason_code(), "approval_challenge_unavailable");

        let digest = splendor_gateway::canonical_gateway_authority_action_digest(
            &action,
            Some("device-sim"),
        )
        .expect("action digest");
        let challenge = ApprovalChallenge {
            schema_version: splendor_types::APPROVAL_CHALLENGE_SCHEMA_VERSION.to_string(),
            approval_id: action
                .approval_evidence
                .as_ref()
                .expect("raw denial")
                .approval_id
                .clone(),
            tenant_id,
            agent_id,
            run_id,
            action_id: action.action_id.clone(),
            action_name: action.action.name.clone(),
            adapter: "device-sim".to_string(),
            policy_id: "policy_raw_denial".to_string(),
            risk_level: None,
            subject: splendor_types::PrincipalId::new(),
            authority_decision_id: splendor_types::AuthorityDecisionId::new(),
            obligation_id: splendor_types::AuthorityObligationId::new(),
            receipt_audience: "splendor.daemon.run:unit".to_string(),
            canonical_request_digest: format!("blake3:{}", "1".repeat(64)),
            gateway_action_request_digest: digest,
            physical_action_resource_coordinate: action.physical_action_resource_coordinate.clone(),
            authority_decision_digest: format!("blake3:{}", "2".repeat(64)),
            requested_at: action.requested_at,
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(5),
        };
        slot.pending_approval = Some(challenge.clone());
        assert_eq!(
            slot.run_authority
                .admit_action_request(
                    RunActionAdmissionState::WaitingForApproval,
                    slot.pending_approval.as_ref(),
                    &mut action,
                    Some("device-sim"),
                    OffsetDateTime::now_utc(),
                )
                .expect("exact denial retry"),
            Some(challenge)
        );
    }

    #[tokio::test]
    async fn physical_v1_challenge_allows_only_exact_raw_fail_closed_closure() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let node_id = NodeId::new();
        create_unit_run(
            &state,
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            10,
            None,
        )
        .await;
        let _ = register_device_profile(
            State(state.clone()),
            Json(RegisterDeviceProfileRequest {
                credential: None,
                audit_attribution: Some(unit_audit()),
                profile: unit_profile(node_id.clone(), tenant_id.clone()),
            }),
        )
        .await
        .expect("register physical profile");

        let requested_at = OffsetDateTime::now_utc();
        let action_id = ActionId::new();
        let mut request = physical_request(
            run_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
            "move_to_waypoint",
            safe_context(),
        );
        request.action_request.action_id = Some(action_id.clone());
        request.action_request.requested_at = Some(requested_at);
        let legacy_action = ActionRequest {
            action_id: action_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: run_id.clone(),
            tick_id: None,
            action: request.action_request.action.clone(),
            adapter: request.action_request.adapter.clone(),
            quota_usage: normalize_untrusted_quota_usage(request.action_request.quota_usage),
            satisfied_preconditions: request.action_request.satisfied_preconditions.clone(),
            requested_at,
            physical_action_resource_coordinate: None,
            approval_evidence: None,
            authority_obligation_evidence: None,
            authority_obligation_receipts: Vec::new(),
        };
        let legacy_digest = splendor_gateway::canonical_gateway_authority_action_v1_compat_digest(
            &legacy_action,
            Some("device-sim"),
        )
        .expect("frozen physical-v1 digest");
        let approval_id = splendor_types::ApprovalId::new();
        let challenge = ApprovalChallenge {
            schema_version: splendor_types::APPROVAL_CHALLENGE_SCHEMA_VERSION.to_string(),
            approval_id: approval_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: run_id.clone(),
            action_id: action_id.clone(),
            action_name: request.action_request.action.name.clone(),
            adapter: "device-sim".to_string(),
            policy_id: "physical-v1-migration".to_string(),
            risk_level: Some("high".to_string()),
            subject: splendor_types::PrincipalId::new(),
            authority_decision_id: splendor_types::AuthorityDecisionId::new(),
            obligation_id: splendor_types::AuthorityObligationId::new(),
            receipt_audience: local_dev_authority_receipt_config().audience_for_run(&run_id),
            canonical_request_digest: format!("blake3:{}", "1".repeat(64)),
            gateway_action_request_digest: legacy_digest,
            physical_action_resource_coordinate: None,
            authority_decision_digest: format!("blake3:{}", "2".repeat(64)),
            requested_at,
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(5),
        };
        let mut policy = ApprovalPolicy::new(
            "physical-v1-migration",
            tenant_id.clone(),
            "physical action requires approval",
        );
        policy.agent_id = Some(agent_id.clone());
        policy.action_name = Some(request.action_request.action.name.clone());
        policy.adapter = Some("device-sim".to_string());
        policy.side_effect_class = Some(request.action_request.action.side_effect_class.clone());
        {
            let run = state.run_slot(&run_id).expect("run");
            let mut slot = run.lock().expect("run");
            slot.status = RunStatus::WaitingForApproval;
            slot.pending_approval = Some(challenge.clone());
            slot.approval_policies = vec![policy];
        }

        let compatibility_now = OffsetDateTime::now_utc();
        for (case, decision, revoked, expires_at) in [
            (
                "denied",
                splendor_types::ApprovalDecision::Denied,
                false,
                compatibility_now + time::Duration::minutes(5),
            ),
            (
                "expired",
                splendor_types::ApprovalDecision::Granted,
                false,
                requested_at,
            ),
            (
                "revoked",
                splendor_types::ApprovalDecision::Granted,
                true,
                compatibility_now + time::Duration::minutes(5),
            ),
        ] {
            let mut evidence = ApprovalEvidence::new(
                approval_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                run_id.clone(),
                decision,
                expires_at,
            )
            .with_action_name(request.action_request.action.name.clone())
            .with_adapter("device-sim");
            evidence.action_id = Some(action_id.clone());
            evidence.issued_at = requested_at - time::Duration::seconds(1);
            evidence.revoked = revoked;
            let mut compatible_action = legacy_action.clone();
            compatible_action.approval_evidence = Some(evidence);
            let run = state.run_slot(&run_id).expect("run");
            let slot = run.lock().expect("run");
            slot.run_authority
                .bind_physical_action_resource(&mut compatible_action, node_id.clone())
                .expect("trusted physical endpoint binds the registered node");
            assert_eq!(
                slot.run_authority
                    .admit_action_request(
                        RunActionAdmissionState::WaitingForApproval,
                        slot.pending_approval.as_ref(),
                        &mut compatible_action,
                        Some("device-sim"),
                        compatibility_now,
                    )
                    .unwrap_or_else(|error| panic!("{case}: {}", error.reason_code())),
                Some(challenge.clone()),
                "case={case}"
            );
        }

        let receipt = local_dev_authority_receipt_config()
            .issue_approval_receipt(
                &challenge,
                splendor_types::TraceEventId::new(),
                OffsetDateTime::now_utc(),
            )
            .expect("legacy challenge receipt remains behavior-free input");
        let mut receipt_retry = request.clone();
        receipt_retry.action_request.authority_obligation_receipts = vec![receipt];
        let error = submit_physical_action(
            Path(node_id.clone()),
            State(state.clone()),
            Json(receipt_retry),
        )
        .await
        .expect_err("physical-v1 receipt cannot authorize");
        assert_eq!(
            error.body.code,
            "physical_approval_challenge_v1_rechallenge_required"
        );
        assert_eq!(unit_adapter_execution_count(&state, &run_id), 0);
        assert_eq!(
            state
                .run_slot(&run_id)
                .expect("run")
                .lock()
                .expect("run")
                .status,
            RunStatus::WaitingForApproval
        );

        let mut denial = ApprovalEvidence::new(
            approval_id,
            tenant_id,
            agent_id,
            run_id.clone(),
            splendor_types::ApprovalDecision::Denied,
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
        )
        .with_action_name(request.action_request.action.name.clone())
        .with_adapter("device-sim");
        denial.action_id = Some(action_id);
        request.action_request.approval_evidence = Some(denial);
        let outcome = submit_physical_action(Path(node_id), State(state.clone()), Json(request))
            .await
            .expect("exact raw physical-v1 denial closes fail-closed")
            .0;
        assert_eq!(outcome.status, ActionStatus::Denied);
        assert!(outcome
            .verification
            .reasons
            .iter()
            .any(|reason| reason == "approval_denied"));
        assert_eq!(unit_adapter_execution_count(&state, &run_id), 0);
        assert_eq!(
            state
                .run_slot(&run_id)
                .expect("run")
                .lock()
                .expect("run")
                .status,
            RunStatus::Denied
        );
    }

    #[tokio::test]
    async fn direct_and_physical_effects_require_explicitly_capable_run_status() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let node_id = NodeId::new();
        create_unit_run(
            &state,
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            10,
            None,
        )
        .await;
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

        let pending = submit_action(
            State(state.clone()),
            Json(direct_physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "fixture.write",
                splendor_types::QuotaUsage::single_action(),
            )),
        )
        .await
        .expect("pending direct action")
        .0;
        assert_eq!(pending.status, ActionStatus::Executed, "{pending:?}");

        state
            .run_slot(&run_id)
            .expect("run")
            .lock()
            .expect("run")
            .status = RunStatus::Running;
        let running = submit_physical_action(
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
        .expect("running physical action")
        .0;
        assert_eq!(running.status, ActionStatus::Executed);

        for denied_status in [
            RunStatus::Paused,
            RunStatus::WaitingForApproval,
            RunStatus::Interrupted,
            RunStatus::Resuming,
            RunStatus::Cancelled,
            RunStatus::Failed,
            RunStatus::Denied,
            RunStatus::Expired,
            RunStatus::Completed,
        ] {
            let (evaluations_before, executions_before) = {
                let run = state.run_slot(&run_id).expect("run");
                let mut slot = run.lock().expect("run");
                slot.status = denied_status.clone();
                (
                    slot.run_authority.evaluation_count(),
                    slot.adapter_executions.load(Ordering::SeqCst),
                )
            };
            let direct = submit_action(
                State(state.clone()),
                Json(direct_physical_request(
                    run_id.clone(),
                    tenant_id.clone(),
                    agent_id.clone(),
                    "fixture.write",
                    splendor_types::QuotaUsage::single_action(),
                )),
            )
            .await
            .expect_err("direct action lifecycle denied");
            assert_eq!(direct.status, StatusCode::CONFLICT, "{denied_status:?}");
            let expected_code = if denied_status == RunStatus::WaitingForApproval {
                "approval_exact_action_retry_required"
            } else {
                "run_not_effect_capable"
            };
            assert_eq!(direct.body.code, expected_code, "{denied_status:?}");

            let physical = submit_physical_action(
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
            .expect_err("physical action lifecycle denied");
            assert_eq!(physical.status, StatusCode::CONFLICT, "{denied_status:?}");
            assert_eq!(physical.body.code, expected_code, "{denied_status:?}");

            let run = state.run_slot(&run_id).expect("run");
            let slot = run.lock().expect("run");
            assert_eq!(
                slot.run_authority.evaluation_count(),
                evaluations_before,
                "gateway authority evaluation must not run for {denied_status:?}"
            );
            assert_eq!(
                slot.adapter_executions.load(Ordering::SeqCst),
                executions_before,
                "adapter must not run for {denied_status:?}"
            );
        }
    }

    #[tokio::test]
    async fn explicit_zero_quota_is_normalized_for_direct_and_physical_actions() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let node_id = NodeId::new();
        create_unit_run(
            &state,
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            0,
            None,
        )
        .await;
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

        let direct = submit_action(
            State(state.clone()),
            Json(direct_physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "fixture.write",
                splendor_types::QuotaUsage::default(),
            )),
        )
        .await
        .expect("direct quota outcome")
        .0;
        assert_eq!(direct.status, ActionStatus::Denied);
        assert!(direct
            .verification
            .reasons
            .contains(&"max_actions_per_tick".to_string()));

        let mut physical_request = physical_request(
            run_id.clone(),
            tenant_id,
            agent_id,
            "move_to_waypoint",
            safe_context(),
        );
        physical_request.action_request.quota_usage = Some(splendor_types::QuotaUsage::default());
        let physical =
            submit_physical_action(Path(node_id), State(state.clone()), Json(physical_request))
                .await
                .expect("physical quota outcome")
                .0;
        assert_eq!(physical.status, ActionStatus::Denied);
        assert!(physical
            .verification
            .reasons
            .contains(&"max_actions_per_tick".to_string()));

        assert_eq!(unit_adapter_execution_count(&state, &run_id), 0);
    }

    #[tokio::test]
    async fn omitted_and_zero_duration_estimates_use_server_floor_on_both_action_endpoints() {
        let state = DaemonState::local_dev();
        let tenant_id = TenantId::new();
        let agent_id = splendor_types::AgentId::new();
        let run_id = RunId::new();
        let node_id = NodeId::new();
        create_unit_run(
            &state,
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            10,
            Some(0),
        )
        .await;
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

        let mut direct_omitted = direct_physical_request(
            run_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
            "fixture.write",
            splendor_types::QuotaUsage::default(),
        );
        direct_omitted.quota_usage = None;
        for request in [
            direct_omitted,
            direct_physical_request(
                run_id.clone(),
                tenant_id.clone(),
                agent_id.clone(),
                "fixture.write",
                splendor_types::QuotaUsage::default(),
            ),
        ] {
            let outcome = submit_action(State(state.clone()), Json(request))
                .await
                .expect("direct duration quota outcome")
                .0;
            assert_eq!(outcome.status, ActionStatus::Denied);
            assert!(outcome
                .verification
                .reasons
                .contains(&"max_action_duration_ms".to_string()));
        }

        let mut physical_omitted = physical_request(
            run_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
            "move_to_waypoint",
            safe_context(),
        );
        physical_omitted.action_request.quota_usage = None;
        let mut physical_zero = physical_request(
            run_id.clone(),
            tenant_id,
            agent_id,
            "move_to_waypoint",
            safe_context(),
        );
        physical_zero.action_request.quota_usage = Some(splendor_types::QuotaUsage::default());
        for request in [physical_omitted, physical_zero] {
            let outcome =
                submit_physical_action(Path(node_id.clone()), State(state.clone()), Json(request))
                    .await
                    .expect("physical duration quota outcome")
                    .0;
            assert_eq!(outcome.status, ActionStatus::Denied);
            assert!(outcome
                .verification
                .reasons
                .contains(&"max_action_duration_ms".to_string()));
        }

        assert_eq!(unit_adapter_execution_count(&state, &run_id), 0);
    }

    #[tokio::test]
    async fn stop_and_cancel_close_admission_before_terminal_visibility_and_wait_without_run_lock()
    {
        for cancel in [false, true] {
            let state = DaemonState::local_dev();
            let tenant_id = TenantId::new();
            let agent_id = splendor_types::AgentId::new();
            let run_id = RunId::new();
            create_unit_run(
                &state,
                tenant_id.clone(),
                agent_id.clone(),
                run_id.clone(),
                10,
                None,
            )
            .await;
            let authority = state
                .run_slot(&run_id)
                .expect("run")
                .lock()
                .expect("run")
                .run_authority
                .clone();
            let authority_request = authority_physical_request(run_id.clone(), tenant_id, agent_id);
            let held_permit =
                match splendor_gateway::ActionAuthorityEvaluator::acquire_final_effect_permit(
                    &authority,
                    &authority_request,
                    Some("device-sim"),
                    &[],
                    OffsetDateTime::now_utc(),
                ) {
                    splendor_gateway::FinalEffectAuthorityEvaluation::Permitted {
                        permit, ..
                    } => permit,
                    splendor_gateway::FinalEffectAuthorityEvaluation::Denied(decisions) => {
                        panic!("initial final permit denied: {decisions:?}")
                    }
                    splendor_gateway::FinalEffectAuthorityEvaluation::NotRequired => {
                        panic!("run authority unexpectedly did not require a final permit")
                    }
                };

            let lifecycle_state = state.clone();
            let lifecycle_run_id = run_id.clone();
            let lifecycle = tokio::spawn(async move {
                let request = Json(LifecycleRequest {
                    credential: None,
                    work_order: None,
                    audit_attribution: Some(unit_audit()),
                    reason: Some(if cancel { "cancel" } else { "stop" }.to_string()),
                    approval_evidence: None,
                    authority_obligation_receipts: Vec::new(),
                });
                if cancel {
                    cancel_run(Path(lifecycle_run_id), State(lifecycle_state), request).await
                } else {
                    stop_run(Path(lifecycle_run_id), State(lifecycle_state), request).await
                }
            });

            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    let inspected =
                        inspect_run(Path(run_id.clone()), State(state.clone()), HeaderMap::new())
                            .await
                            .expect("inspect remains available during quiescence wait")
                            .0;
                    if inspected.status == RunStatus::Cancelled {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("terminal status visible while final permit is held");
            assert!(!lifecycle.is_finished(), "lifecycle waits for held permit");

            let denied = splendor_gateway::ActionAuthorityEvaluator::acquire_final_effect_permit(
                &authority,
                &authority_request,
                Some("device-sim"),
                &[],
                OffsetDateTime::now_utc(),
            );
            assert!(matches!(
                denied,
                splendor_gateway::FinalEffectAuthorityEvaluation::Denied(_)
            ));

            drop(held_permit);
            let response = tokio::time::timeout(Duration::from_secs(1), lifecycle)
                .await
                .expect("lifecycle quiesces")
                .expect("lifecycle task")
                .expect("lifecycle response")
                .0;
            assert_eq!(response.status, RunStatus::Cancelled);
        }
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
        assert_eq!(snapshot.max_altitude_m, Some(30.0));
        assert_eq!(snapshot.emergency_stop_engaged, Some(true));
        assert_eq!(snapshot.privacy_zone_active, Some(true));
        assert_eq!(snapshot.proximity_m, Some(0.0));

        let status = serde_json::json!({
            "current_zone": "zone_a",
            "emergency_stop": "clear",
            "privacy": false,
            "human_proximity": "engaged",
            "collision_risk": "unknown"
        });
        assert_eq!(
            profile_safety_string(&status, &["missing", "current_zone"]),
            Some("zone_a".to_string())
        );
        assert_eq!(
            profile_clear_status(&status, "missing", "emergency_stop"),
            Some(true)
        );
        assert_eq!(
            profile_clear_status(&status, "missing", "privacy"),
            Some(true)
        );
        assert_eq!(
            profile_clear_status(&status, "missing", "human_proximity"),
            Some(false)
        );
        assert_eq!(
            profile_clear_status(&status, "missing", "collision_risk"),
            None
        );
        assert_eq!(
            profile_clear_status(&serde_json::json!({"clear": false}), "clear", "missing"),
            Some(false)
        );
        assert_eq!(clear_status_to_unsafe(Some(true), true), Some(false));
        assert_eq!(clear_status_to_unsafe(None, false), Some(true));
        assert_eq!(clear_status_to_unsafe(None, true), None);
        assert_eq!(clear_status_to_distance(Some(true), true), Some(2.0));
        assert_eq!(clear_status_to_distance(None, true), None);
        assert_eq!(
            profile_collision_risk(&status),
            Some(SimulatedRiskLevel::Unknown)
        );
        assert_eq!(
            profile_collision_risk(&serde_json::json!({"collision_risk": "invalid"})),
            None
        );
        assert_eq!(conservative_min(Some(2.0), None), Some(2.0));
        assert_eq!(conservative_min(None, Some(1.0)), None);
        assert_eq!(conservative_max(Some(2.0), None), Some(2.0));
        assert_eq!(conservative_max(None, Some(3.0)), None);
        assert_eq!(
            narrow_zone(Some("zone_a".to_string()), None, &["zone_a".to_string()]),
            Some("zone_a".to_string())
        );
        assert_eq!(
            narrow_zone(
                Some("outside".to_string()),
                Some("zone_a"),
                &["zone_a".to_string()],
            ),
            Some("outside".to_string())
        );
        assert_eq!(
            narrow_zone(
                Some("zone_a".to_string()),
                Some("outside"),
                &["zone_a".to_string()],
            ),
            Some("outside".to_string())
        );
        assert_eq!(
            narrow_zone(
                Some("zone_a".to_string()),
                Some("zone_b"),
                &["zone_a".to_string(), "zone_b".to_string()],
            ),
            None
        );
        let mut unknown_safety = VerificationResult::allow();
        unknown_safety.artifacts = serde_json::json!({
            "source": "safety_verifier",
            "evidence": {"status": "Unsupported"}
        });
        assert_eq!(safety_artifact_from_verification(&unknown_safety), None);

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

        create_unit_run(
            &state,
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            10,
            None,
        )
        .await;
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
