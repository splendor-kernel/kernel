//! Minimal central manager API for UC-E2E-S4 acceptance.

use crate::caller_auth::{CallerAuthError, CallerTokenSigner, CallerTokenVerifier};
use crate::{ActionOutcome, ApiErrorBody};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use splendor_kernel::{
    FleetTelemetryCollector, InMemoryNodeRegistry, LocalAuthorityObligationReceiptConfig,
    NodeRegistry, NodeRegistryError,
};
use splendor_store::{
    CentralTraceIndex, InMemoryCentralTraceIndex, TraceSyncBatch, TraceSyncReport,
};
use splendor_types::{
    select_placement, AgentId, ApprovalChallenge, ApprovalDecision, ApprovalEvidence, ApprovalId,
    ApprovalPolicy, AuditAttribution, AuthorityObligationReceipt, AuthorityObligationReceiptId,
    CallerCredential, CircuitBreaker, CircuitBreakerId, CircuitBreakerScope, ContentHash,
    CredentialAudience, CredentialBinding, DataLocality, EndpointScope, FleetId,
    FleetTelemetrySnapshot, HealthStatus, InstanceHeartbeat, InstanceId, InstanceRegistration,
    InstanceTelemetry, Message, MessageEnvelope, MessageId, NodeHeartbeat, NodeId,
    NodeRegistration, PlacementCandidate, PlacementDecision, PlacementDecisionStatus,
    PlacementExecutionMode, PlacementRequest, PlacementTarget, PolicyBundle, PolicyBundleEnvelope,
    ResidentApprovalReceiptRevocationAck, ResidentApprovalReceiptRevocationRequest,
    ResidentApprovalReceiptRevocationStatus, RevocationStatus, RunId, RunStatus, RunTelemetry,
    RuntimeMode, TaskRequest, TelemetryRuntimeMode, TenantId, TraceEventId, TraceSyncTelemetry,
    WorkOrderEnvelope, WorkOrderKeyring, WorkOrderValidationContext,
    APPROVAL_POLICY_SCHEMA_VERSION, RESIDENT_APPROVAL_RECEIPT_REVOCATION_ACK_SCHEMA_VERSION,
    RESIDENT_APPROVAL_RECEIPT_REVOCATION_SCHEMA_VERSION, TASK_REQUEST_SCHEMA,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;
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
    authority_obligation_receipt_config: Option<LocalAuthorityObligationReceiptConfig>,
    approval_caller_verifier: Option<CallerTokenVerifier>,
    work_orders: Mutex<HashMap<String, AcceptedWorkOrder>>,
    accepted_work_order_bindings: Mutex<HashMap<String, AcceptedWorkOrderBinding>>,
    revoked_work_orders: Mutex<HashSet<String>>,
    work_order_revocation_gates: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    placements: Mutex<HashMap<String, PlacementDecision>>,
    placement_bindings: Mutex<HashMap<String, BoundPlacementBinding>>,
    dispatch_bindings: Mutex<HashMap<String, DispatchBinding>>,
    dispatch_state: Mutex<DispatchLifecycleState>,
    resident_dispatch: ResidentDispatchClient,
    messages: Mutex<HashMap<String, MessageStatusReport>>,
    message_idempotency: Mutex<HashMap<String, String>>,
    trace_index: InMemoryCentralTraceIndex,
    telemetry: Mutex<FleetTelemetryCollector>,
    audit: Mutex<Vec<ManagerAuditEvent>>,
    policies: Mutex<HashMap<String, PolicyBundleEnvelope>>,
    approvals: Mutex<HashMap<String, GovernanceApprovalRecord>>,
    approval_resident_targets: Mutex<HashMap<String, ApprovalResidentTarget>>,
    approval_revocation_gates: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    circuit_breakers: Mutex<HashMap<String, GovernanceCircuitBreakerRecord>>,
    kill_switches: Mutex<HashMap<String, KillSwitchReport>>,
}

#[derive(Clone)]
struct ResidentDispatchClient {
    http: reqwest::Client,
    signer: CallerTokenSigner,
    allow_loopback_http: bool,
    create_timeout: StdDuration,
    start_timeout: StdDuration,
    maximum_response_bytes: usize,
    allowed_origins: HashSet<String>,
}

#[derive(Clone)]
struct AcceptedWorkOrder {
    envelope: WorkOrderEnvelope,
    approval_policies: Vec<ApprovalPolicy>,
    payload_digest: String,
    envelope_digest: String,
    approval_policies_digest: String,
}

#[derive(Clone)]
struct AcceptedWorkOrderBinding {
    payload_digest: String,
    envelope_digest: String,
    approval_policies_digest: String,
}

#[derive(Clone)]
struct BoundPlacement {
    request: PlacementRequest,
    decision: PlacementDecision,
    decision_digest: String,
}

#[derive(Clone)]
struct BoundPlacementBinding {
    work_order_payload_digest: String,
    request: PlacementRequest,
    decision_digest: String,
}

#[derive(Clone)]
struct DispatchBinding {
    work_order_payload_digest: String,
    placement_decision_digest: String,
    node_id: NodeId,
    instance_id: InstanceId,
    resident_daemon_url: String,
    resident_origin: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApprovalResidentTarget {
    instance_id: InstanceId,
    run_id: RunId,
    resident_daemon_url: String,
    resident_origin: String,
}

struct AcknowledgedApprovalRevocation {
    approval_id: ApprovalId,
    record: GovernanceApprovalRecord,
    receipt: AuthorityObligationReceipt,
    acknowledgement: ResidentApprovalReceiptRevocationAck,
    target: ApprovalResidentTarget,
    reason: String,
    decided_by: AuditAttribution,
}

#[derive(Default)]
struct DispatchLifecycleState {
    completed: HashMap<String, DispatchReport>,
    terminal_failures: HashMap<String, ManagerApiError>,
    in_flight: HashSet<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct ResidentCreateRunResponse {
    request_id: String,
    idempotency_key: String,
    #[serde(rename = "idempotency_receipt_id")]
    _idempotency_receipt_id: String,
    #[serde(rename = "duplicate")]
    _duplicate: bool,
    run_id: RunId,
    #[serde(rename = "status")]
    _status: crate::RunStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct ResidentTickResponse {
    run_id: RunId,
    status: crate::RunStatus,
    #[serde(rename = "tick_id")]
    _tick_id: u64,
    #[serde(rename = "state_node_id")]
    _state_node_id: String,
    #[serde(rename = "action_outcomes")]
    _action_outcomes: Vec<ActionOutcome>,
}

enum ResidentDispatchOperation<'a> {
    CreateRun,
    StartRun {
        run_id: &'a RunId,
    },
    RevokeApprovalReceipt {
        run_id: &'a RunId,
        receipt_id: &'a AuthorityObligationReceiptId,
    },
    CancelRun {
        run_id: &'a RunId,
    },
}

#[derive(Clone, Copy)]
enum ResidentCallerOperation {
    CreateRun,
    StartRun,
    RevokeApprovalReceipt,
    CancelRun,
}

impl ResidentCallerOperation {
    fn endpoint_scope(self) -> EndpointScope {
        match self {
            Self::CreateRun => EndpointScope::RunsCreate,
            Self::StartRun => EndpointScope::RunsStart,
            Self::RevokeApprovalReceipt => EndpointScope::ApprovalReceiptsRevoke,
            Self::CancelRun => EndpointScope::RunsStop,
        }
    }
}

impl ResidentDispatchOperation<'_> {
    fn path(&self) -> String {
        match self {
            Self::CreateRun => "/runs".to_string(),
            Self::StartRun { run_id } => format!("/runs/{run_id}/start"),
            Self::RevokeApprovalReceipt { run_id, receipt_id } => {
                format!("/runs/{run_id}/approval-receipts/{receipt_id}/revoke")
            }
            Self::CancelRun { run_id } => format!("/runs/{run_id}/cancel"),
        }
    }

    fn timeout(&self, client: &ResidentDispatchClient) -> StdDuration {
        match self {
            Self::CreateRun | Self::CancelRun { .. } => client.create_timeout,
            Self::StartRun { .. } | Self::RevokeApprovalReceipt { .. } => client.start_timeout,
        }
    }

    fn expected_status(&self) -> reqwest::StatusCode {
        reqwest::StatusCode::OK
    }
}

#[derive(Clone, Debug)]
pub struct ResidentDispatchOptions {
    pub allow_loopback_http: bool,
    pub connect_timeout: StdDuration,
    pub create_timeout: StdDuration,
    pub start_timeout: StdDuration,
    pub maximum_response_bytes: usize,
    pub root_ca_pem: Option<Vec<u8>>,
    /// Exact resident origins allowed to receive manager bearer credentials.
    /// Values must be origin-only URLs such as `https://resident.example:8443`.
    pub allowed_origins: Vec<String>,
}

impl ResidentDispatchOptions {
    pub fn production() -> Self {
        Self {
            allow_loopback_http: false,
            connect_timeout: StdDuration::from_secs(2),
            create_timeout: StdDuration::from_secs(10),
            start_timeout: StdDuration::from_secs(35),
            maximum_response_bytes: 1024 * 1024,
            root_ca_pem: None,
            allowed_origins: Vec::new(),
        }
    }

    pub fn loopback_test() -> Self {
        Self {
            allow_loopback_http: true,
            ..Self::production()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MessageIdempotencyScope {
    tenant_id: TenantId,
    work_order_id: String,
    run_id: RunId,
    source_agent_id: AgentId,
    target_agent_id: AgentId,
    schema: String,
    source_instance_id: String,
    target_instance_id: String,
    route_permission: Option<String>,
}

impl ManagerState {
    pub fn local_acceptance() -> Self {
        let signer = CallerTokenSigner::generate_for_test(
            "urn:splendor:manager:central-manager",
            "central-manager",
            "resident-dispatch-client",
            "manager-resident-local-acceptance",
        )
        .expect("local acceptance caller signer");
        Self::local_acceptance_with_dispatch(signer, ResidentDispatchOptions::loopback_test())
            .expect("local acceptance dispatch client")
    }

    pub fn local_acceptance_with_dispatch(
        signer: CallerTokenSigner,
        options: ResidentDispatchOptions,
    ) -> Result<Self, String> {
        let fleet_id = std::env::var("SPLENDOR_FLEET_ID")
            .ok()
            .and_then(|raw| FleetId::parse(&raw).ok())
            .unwrap_or_default();
        let mut work_order_keyring = WorkOrderKeyring::new();
        work_order_keyring
            .insert_shared_secret("work-order-local-key", b"splendor-local-work-order-secret")
            .expect("local work-order keyring");
        Self::acceptance_with_dispatch_and_receipt_config(
            std::env::var("SPLENDOR_MANAGER_ID").unwrap_or_else(|_| "central-manager".to_string()),
            fleet_id,
            work_order_keyring,
            signer,
            options,
            local_manager_authority_receipt_config(),
        )
    }

    /// Builds the acceptance manager with explicit outbound resident trust.
    ///
    /// This makes manager-to-resident dispatch production-real, but does not
    /// authenticate callers of the manager's own inbound acceptance API.
    pub fn acceptance_with_dispatch_config(
        manager_id: impl Into<String>,
        fleet_id: FleetId,
        work_order_keyring: WorkOrderKeyring,
        signer: CallerTokenSigner,
        options: ResidentDispatchOptions,
    ) -> Result<Self, String> {
        Self::acceptance_with_dispatch_config_internal(
            manager_id.into(),
            fleet_id,
            work_order_keyring,
            signer,
            options,
            None,
            None,
        )
    }

    /// Builds the manager with explicit trusted local approval receipt issuance
    /// configuration supplied only by process composition.
    pub fn acceptance_with_dispatch_and_receipt_config(
        manager_id: impl Into<String>,
        fleet_id: FleetId,
        work_order_keyring: WorkOrderKeyring,
        signer: CallerTokenSigner,
        options: ResidentDispatchOptions,
        receipt_config: LocalAuthorityObligationReceiptConfig,
    ) -> Result<Self, String> {
        Self::acceptance_with_dispatch_config_internal(
            manager_id.into(),
            fleet_id,
            work_order_keyring,
            signer,
            options,
            Some(receipt_config),
            None,
        )
    }

    /// Builds the acceptance manager with both process-owned receipt issuance
    /// and inbound caller trust for the four approval mutation endpoints.
    pub fn acceptance_with_dispatch_receipt_and_approval_auth(
        manager_id: impl Into<String>,
        fleet_id: FleetId,
        work_order_keyring: WorkOrderKeyring,
        signer: CallerTokenSigner,
        options: ResidentDispatchOptions,
        receipt_config: LocalAuthorityObligationReceiptConfig,
        approval_caller_verifier: CallerTokenVerifier,
    ) -> Result<Self, String> {
        Self::acceptance_with_dispatch_config_internal(
            manager_id.into(),
            fleet_id,
            work_order_keyring,
            signer,
            options,
            Some(receipt_config),
            Some(approval_caller_verifier),
        )
    }

    fn acceptance_with_dispatch_config_internal(
        manager_id: String,
        fleet_id: FleetId,
        work_order_keyring: WorkOrderKeyring,
        signer: CallerTokenSigner,
        options: ResidentDispatchOptions,
        authority_obligation_receipt_config: Option<LocalAuthorityObligationReceiptConfig>,
        approval_caller_verifier: Option<CallerTokenVerifier>,
    ) -> Result<Self, String> {
        if manager_id.trim().is_empty()
            || options.connect_timeout.is_zero()
            || options.create_timeout.is_zero()
            || options.start_timeout.is_zero()
            || options.maximum_response_bytes == 0
        {
            return Err("resident dispatch configuration is invalid".to_string());
        }
        if approval_caller_verifier
            .as_ref()
            .is_some_and(|verifier| verifier.trusts_public_key(&signer.public_key_bytes()))
        {
            return Err(
                "approval caller trust must not include the outbound resident dispatch signing key"
                    .to_string(),
            );
        }
        let mut client = reqwest::Client::builder()
            .connect_timeout(options.connect_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if let Some(root_ca_pem) = options.root_ca_pem.as_ref() {
            let certificate = reqwest::Certificate::from_pem(root_ca_pem)
                .map_err(|_| "resident root CA PEM is invalid".to_string())?;
            client = client.add_root_certificate(certificate);
        }
        let resident_dispatch = ResidentDispatchClient {
            http: client
                .build()
                .map_err(|_| "resident HTTP client could not be built".to_string())?,
            signer,
            allow_loopback_http: options.allow_loopback_http,
            create_timeout: options.create_timeout,
            start_timeout: options.start_timeout,
            maximum_response_bytes: options.maximum_response_bytes,
            allowed_origins: canonical_allowed_origins(
                &options.allowed_origins,
                options.allow_loopback_http,
            )?,
        };
        Ok(Self {
            inner: Arc::new(ManagerInner {
                manager_id,
                fleet_id: fleet_id.clone(),
                registry: InMemoryNodeRegistry::new(),
                work_order_keyring,
                authority_obligation_receipt_config,
                approval_caller_verifier,
                work_orders: Mutex::new(HashMap::new()),
                accepted_work_order_bindings: Mutex::new(HashMap::new()),
                revoked_work_orders: Mutex::new(HashSet::new()),
                work_order_revocation_gates: Mutex::new(HashMap::new()),
                placements: Mutex::new(HashMap::new()),
                placement_bindings: Mutex::new(HashMap::new()),
                dispatch_bindings: Mutex::new(HashMap::new()),
                dispatch_state: Mutex::new(DispatchLifecycleState::default()),
                resident_dispatch,
                messages: Mutex::new(HashMap::new()),
                message_idempotency: Mutex::new(HashMap::new()),
                trace_index: InMemoryCentralTraceIndex::default(),
                telemetry: Mutex::new(FleetTelemetryCollector::new(fleet_id)),
                audit: Mutex::new(Vec::new()),
                policies: Mutex::new(HashMap::new()),
                approvals: Mutex::new(HashMap::new()),
                approval_resident_targets: Mutex::new(HashMap::new()),
                approval_revocation_gates: Mutex::new(HashMap::new()),
                circuit_breakers: Mutex::new(HashMap::new()),
                kill_switches: Mutex::new(HashMap::new()),
            }),
        })
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

    fn verify_approval_caller(
        &self,
        headers: &HeaderMap,
        security: &ManagerSecurityFields,
    ) -> Result<CallerCredential, ManagerApiError> {
        let verifier = self
            .inner
            .approval_caller_verifier
            .as_ref()
            .ok_or_else(|| {
                ManagerApiError::unavailable(
                    "manager_approval_caller_verifier_unavailable",
                    "manager approval caller verification is unavailable",
                )
            })?;
        let token = manager_bearer_token(headers)?;
        let verified = verifier
            .verify_and_consume_mutation(token, OffsetDateTime::now_utc())
            .map_err(manager_caller_auth_error)?;
        if verified.scopes != vec![EndpointScope::ApprovalsManage] {
            return Err(ManagerApiError::forbidden(
                "approval_caller_scope_mismatch",
                "approval caller bearer must contain only the approval management scope",
            ));
        }
        if verified != security.credential {
            return Err(ManagerApiError::forbidden(
                "caller_credential_mirror_mismatch",
                "approval caller credential mirror did not match verified bearer claims",
            ));
        }
        if security.audit_attribution.principal != verified.principal
            || security.audit_attribution.credential_id.as_deref()
                != Some(verified.credential_id.as_str())
        {
            return Err(ManagerApiError::forbidden(
                "caller_audit_mirror_mismatch",
                "approval caller audit mirror did not match verified bearer claims",
            ));
        }
        Ok(verified)
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

    fn accepted_work_order_revocation_gate(
        &self,
        work_order_id: &str,
    ) -> Result<Arc<tokio::sync::Mutex<()>>, ManagerApiError> {
        let gates = self.inner.work_order_revocation_gates.lock().map_err(|_| {
            ManagerApiError::internal(
                "work_order_revocation_gate_unavailable",
                "work-order revocation gate unavailable",
            )
        })?;
        gates.get(work_order_id).cloned().ok_or_else(|| {
            ManagerApiError::not_found(
                "work_order_not_found",
                "work order must be accepted before revocation or dispatch",
            )
        })
    }

    fn approval_revocation_gate(
        &self,
        approval_id: &ApprovalId,
    ) -> Result<Arc<tokio::sync::Mutex<()>>, ManagerApiError> {
        self.inner
            .approval_revocation_gates
            .lock()
            .map_err(|_| {
                ManagerApiError::internal(
                    "approval_revocation_gate_unavailable",
                    "approval revocation gate unavailable",
                )
            })?
            .get(&approval_id.to_string())
            .cloned()
            .ok_or_else(|| ManagerApiError::not_found("approval_not_found", "approval not found"))
    }
}

fn approval_resident_target_for_run(
    state: &ManagerState,
    run_id: &RunId,
) -> Result<Option<ApprovalResidentTarget>, ManagerApiError> {
    let report = {
        let dispatch_state = state.inner.dispatch_state.lock().map_err(|_| {
            ManagerApiError::internal(
                "dispatch_lock",
                "resident approval target could not be resolved",
            )
        })?;
        let mut matches = dispatch_state
            .completed
            .values()
            .filter(|report| &report.run_id == run_id);
        let report = matches.next().cloned();
        if matches.next().is_some() {
            return Err(ManagerApiError::conflict(
                "approval_resident_target_ambiguous",
                "run has more than one completed resident target",
            ));
        }
        report
    };
    let Some(report) = report else {
        return Ok(None);
    };
    let binding = state
        .inner
        .dispatch_bindings
        .lock()
        .map_err(|_| {
            ManagerApiError::internal(
                "dispatch_binding_lock",
                "resident approval target binding is unavailable",
            )
        })?
        .get(&report.work_order_id)
        .cloned()
        .ok_or_else(|| {
            ManagerApiError::unavailable(
                "approval_resident_target_unavailable",
                "completed resident dispatch has no immutable target binding",
            )
        })?;
    if binding.instance_id != report.selected_instance_id
        || binding.resident_daemon_url != report.resident_daemon_url
    {
        return Err(ManagerApiError::conflict(
            "approval_resident_target_mismatch",
            "resident dispatch report did not match its immutable target binding",
        ));
    }
    Ok(Some(ApprovalResidentTarget {
        instance_id: binding.instance_id,
        run_id: run_id.clone(),
        resident_daemon_url: binding.resident_daemon_url,
        resident_origin: binding.resident_origin,
    }))
}

fn receipt_config_for_approval_target(
    config: &LocalAuthorityObligationReceiptConfig,
    target: Option<&ApprovalResidentTarget>,
) -> Result<LocalAuthorityObligationReceiptConfig, ManagerApiError> {
    match target {
        Some(target) => config
            .for_resident_instance(&target.instance_id)
            .map_err(|error| {
                ManagerApiError::unavailable(
                    error.reason_code(),
                    "resident approval receipt audience could not be constructed",
                )
            }),
        None => Ok(config.clone()),
    }
}

fn local_manager_authority_receipt_config() -> LocalAuthorityObligationReceiptConfig {
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

fn manager_bearer_token(headers: &HeaderMap) -> Result<&str, ManagerApiError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values
        .next()
        .ok_or_else(|| manager_caller_auth_error(CallerAuthError::MissingToken))?;
    if values.next().is_some() {
        return Err(manager_caller_auth_error(CallerAuthError::MalformedToken));
    }
    let value = value
        .to_str()
        .map_err(|_| manager_caller_auth_error(CallerAuthError::MalformedToken))?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or_else(|| manager_caller_auth_error(CallerAuthError::MalformedToken))?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.contains(char::is_whitespace)
    {
        return Err(manager_caller_auth_error(CallerAuthError::MalformedToken));
    }
    Ok(token)
}

fn safe_approval_actor(attribution: &AuditAttribution) -> serde_json::Value {
    let credential_correlation = attribution.credential_id.as_deref().filter(|value| {
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    serde_json::json!({
        "principal": &attribution.principal,
        "credential_correlation": credential_correlation,
    })
}

fn manager_caller_auth_error(error: CallerAuthError) -> ManagerApiError {
    let code = match error {
        CallerAuthError::MissingToken => "missing_manager_caller_token",
        CallerAuthError::MalformedToken => "invalid_manager_caller_token",
        CallerAuthError::UnsupportedProfile => "unsupported_manager_caller_token_profile",
        CallerAuthError::UntrustedKey => "untrusted_manager_caller_token_key",
        CallerAuthError::InvalidSignature => "invalid_manager_caller_token_signature",
        CallerAuthError::WrongIssuer => "wrong_manager_caller_token_issuer",
        CallerAuthError::WrongAudience => "wrong_manager_caller_token_audience",
        CallerAuthError::WrongSubject => "wrong_manager_caller_token_subject",
        CallerAuthError::InvalidLifetime => "invalid_manager_caller_token_lifetime",
        CallerAuthError::InvalidScope => "invalid_manager_caller_token_scope",
        CallerAuthError::InvalidTenant
        | CallerAuthError::InvalidFleet
        | CallerAuthError::InvalidBinding => "invalid_manager_caller_token_binding",
        CallerAuthError::RevokedToken => "revoked_manager_caller_token",
        CallerAuthError::ReplayedToken => "manager_caller_token_replayed",
        CallerAuthError::InvalidTrustSnapshot
        | CallerAuthError::ClockRollback
        | CallerAuthError::InvalidSigner
        | CallerAuthError::KeyLoad => "manager_caller_auth_unavailable",
    };
    ManagerApiError::unauthorized(code, "manager approval caller authentication failed")
}

pub fn router(state: ManagerState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/fleet/nodes", post(register_node))
        .route("/fleet/nodes/list", post(list_nodes))
        .route("/fleet/instances", post(register_instance))
        .route(
            "/fleet/instances/:instance_id/heartbeat",
            post(heartbeat_instance),
        )
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
pub struct HeartbeatInstanceRequest {
    #[serde(flatten)]
    pub security: ManagerSecurityFields,
    pub heartbeat: InstanceHeartbeat,
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
    /// Manager-owned, non-authorizing governance configuration admitted with
    /// the signed work order and retained immutably for resident dispatch.
    #[serde(default)]
    pub approval_policies: Vec<ApprovalPolicy>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    pub audience: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub reason: String,
    /// Exact daemon-issued behavior-free challenge. Legacy scalar fields remain
    /// for wire compatibility and must match this object exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<ApprovalChallenge>,
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
    pub risk_level: Option<String>,
    pub audience: String,
    pub status: String,
    pub reason: String,
    /// Compatibility attribution retained for existing clients. Equal to
    /// `requested_by` for newly created records.
    pub issued_by: AuditAttribution,
    pub requested_by: AuditAttribution,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<AuditAttribution>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub trace_event_id: String,
    pub evidence: Option<ApprovalEvidence>,
    /// Exact recorded challenge used for trusted receipt issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<ApprovalChallenge>,
    /// Raw local receipt returned for daemon-side trusted validation. It is not
    /// authorizing by itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_obligation_receipt: Option<AuthorityObligationReceipt>,
    /// Exact resident acknowledgement required before a granted approval can be
    /// reported as revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resident_receipt_revocation_ack: Option<ResidentApprovalReceiptRevocationAck>,
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
    pub details: Option<serde_json::Value>,
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
                details: None,
            },
        }
    }
    fn forbidden(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }
    fn unauthorized(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }
    fn not_found(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }
    fn conflict(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }
    fn bad_gateway(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }
    fn gateway_timeout(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::GATEWAY_TIMEOUT,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }
    fn unavailable(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }
    fn internal(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: ManagerApiErrorBody {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }

    fn details(mut self, details: serde_json::Value) -> Self {
        self.body.details = Some(details);
        self
    }
}

impl IntoResponse for ManagerApiError {
    fn into_response(self) -> Response {
        let unauthorized = self.status == StatusCode::UNAUTHORIZED;
        let mut response = (self.status, Json(self.body)).into_response();
        if unauthorized {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(
                    "Bearer realm=\"splendor-manager-approvals\", error=\"invalid_token\"",
                ),
            );
        }
        response
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
    let received_at = OffsetDateTime::now_utc();
    let (record, registered_new) = match state
        .inner
        .registry
        .register_node_received_at(requested.clone(), received_at)
    {
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
    let received_at = OffsetDateTime::now_utc();
    let (record, registered_new) = match state
        .inner
        .registry
        .register_instance_received_at(requested.clone(), received_at)
    {
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
    let received_at = OffsetDateTime::now_utc();
    let record = state
        .inner
        .registry
        .record_node_heartbeat_received_at(request.heartbeat, received_at)
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

async fn heartbeat_instance(
    Path(instance_id): Path<InstanceId>,
    State(state): State<ManagerState>,
    Json(request): Json<HeartbeatInstanceRequest>,
) -> Result<Json<serde_json::Value>, ManagerApiError> {
    state.validate_security(
        &request.security.credential,
        Some(&request.security.audit_attribution),
        EndpointScope::InstancesHeartbeat,
        true,
    )?;
    if instance_id != request.heartbeat.instance_id {
        return Err(ManagerApiError::bad_request(
            "instance_id_mismatch",
            "path instance_id does not match heartbeat",
        ));
    }
    let received_at = OffsetDateTime::now_utc();
    let record = state
        .inner
        .registry
        .record_instance_heartbeat_received_at(request.heartbeat, received_at)
        .map_err(|error| {
            ManagerApiError::bad_request("instance_heartbeat_rejected", error.to_string())
        })?;
    state
        .inner
        .telemetry
        .lock()
        .map_err(|_| ManagerApiError::internal("telemetry_lock", "telemetry lock unavailable"))?
        .upsert_instance(InstanceTelemetry::new(
            record.registration.node_id.clone(),
            record.registration.instance_id.clone(),
            record.registration.runtime_version.clone(),
            TelemetryRuntimeMode::Resident,
            record.registration.supported_features.clone(),
            record.last_heartbeat_at,
        ));
    let trace_event_id = state.audit(
        "instance.heartbeat_recorded",
        serde_json::json!({
            "node_id": record.registration.node_id,
            "instance_id": record.registration.instance_id,
            "status": record.health.status,
        }),
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
    let now = OffsetDateTime::now_utc();
    let validation = splendor_types::validate_work_order(
        &request.work_order,
        &WorkOrderValidationContext {
            tenant_id: request.work_order.work_order.tenant_id.clone(),
            agent_id: request.work_order.work_order.agent_id.clone(),
            run_id: request.work_order.work_order.run_id.clone(),
            expected_placement_target: None,
            now,
        },
        &state.inner.work_order_keyring,
    );
    match validation {
        Ok(_) => {
            if let Err(error) = validate_work_order_approval_policies(
                &request.work_order,
                &request.approval_policies,
                now,
            ) {
                state.audit(
                    "work_order.rejected",
                    serde_json::json!({"work_order_id": work_order_id, "reason": error.body.code.as_str()}),
                )?;
                return Err(error);
            }
            let accepted = accepted_work_order(
                request.work_order.clone(),
                request.approval_policies.clone(),
            )
            .map_err(|_| {
                ManagerApiError::bad_request(
                    "work_order_digest_unavailable",
                    "work order admission record could not be bound to immutable canonical bytes",
                )
            })?;
            let idempotent = {
                let mut gates = state
                    .inner
                    .work_order_revocation_gates
                    .lock()
                    .map_err(|_| {
                        ManagerApiError::internal(
                            "work_order_revocation_gate_unavailable",
                            "work-order revocation gate unavailable",
                        )
                    })?;
                let mut work_orders = state.inner.work_orders.lock().map_err(|_| {
                    ManagerApiError::internal("work_order_lock", "work order lock unavailable")
                })?;
                let mut bindings =
                    state
                        .inner
                        .accepted_work_order_bindings
                        .lock()
                        .map_err(|_| {
                            ManagerApiError::internal(
                                "work_order_lock",
                                "work order binding unavailable",
                            )
                        })?;
                if let Some(existing) = bindings.get(&work_order_id) {
                    if existing.envelope_digest != accepted.envelope_digest
                        || existing.payload_digest != accepted.payload_digest
                    {
                        state.audit(
                            "work_order.rejected",
                            serde_json::json!({"work_order_id": work_order_id, "reason": "work_order_payload_replacement"}),
                        )?;
                        return Err(ManagerApiError::conflict(
                            "work_order_payload_replacement",
                            "an accepted work-order ID cannot be replaced with different signed bytes",
                        ));
                    }
                    if existing.approval_policies_digest != accepted.approval_policies_digest {
                        state.audit(
                            "work_order.rejected",
                            serde_json::json!({"work_order_id": work_order_id, "reason": "work_order_approval_policies_replacement"}),
                        )?;
                        return Err(ManagerApiError::conflict(
                            "work_order_approval_policies_replacement",
                            "an accepted work-order ID cannot replace its immutable approval policies",
                        ));
                    }
                    if !gates.contains_key(&work_order_id) {
                        return Err(ManagerApiError::conflict(
                            "work_order_gate_missing",
                            "accepted work order is missing its revocation gate",
                        ));
                    }
                    true
                } else {
                    gates.insert(work_order_id.clone(), Arc::new(tokio::sync::Mutex::new(())));
                    work_orders.insert(work_order_id.clone(), accepted.clone());
                    bindings.insert(
                        work_order_id.clone(),
                        AcceptedWorkOrderBinding {
                            payload_digest: accepted.payload_digest.clone(),
                            envelope_digest: accepted.envelope_digest.clone(),
                            approval_policies_digest: accepted.approval_policies_digest.clone(),
                        },
                    );
                    false
                }
            };
            let trace_event_id = state.audit(
                if idempotent {
                    "work_order.acceptance_idempotent"
                } else {
                    "work_order.accepted"
                },
                serde_json::json!({
                    "work_order_id": work_order_id,
                    "payload_digest": accepted.payload_digest,
                    "approval_policy_count": accepted.approval_policies.len(),
                    "approval_policies_digest": accepted.approval_policies_digest,
                    "approval_policies_authority": "non_authorizing_governance_only",
                }),
            )?;
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
    let revocation_gate = state.accepted_work_order_revocation_gate(&work_order_id)?;
    let _revocation_guard = revocation_gate.lock_owned().await;
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
    let bound_work_order = if let Some(work_order_id) = request.work_order_id.as_ref() {
        Some(load_accepted_work_order(&state, work_order_id)?)
    } else {
        None
    };
    if let Some(work_order) = bound_work_order.as_ref() {
        validate_placement_request_against_work_order(&request.request, &work_order.envelope)?;
        if let Some(existing) = state
            .inner
            .placement_bindings
            .lock()
            .map_err(|_| ManagerApiError::internal("placement_lock", "placement lock unavailable"))?
            .get(
                request
                    .work_order_id
                    .as_deref()
                    .expect("bound work-order ID"),
            )
            .cloned()
        {
            if existing.work_order_payload_digest != work_order.payload_digest
                || existing.request != request.request
            {
                return Err(ManagerApiError::conflict(
                    "placement_binding_replacement",
                    "an accepted work order already has a different immutable placement binding",
                ));
            }
            let decision = state
                .inner
                .placements
                .lock()
                .map_err(|_| {
                    ManagerApiError::internal("placement_lock", "placement decision unavailable")
                })?
                .get(
                    request
                        .work_order_id
                        .as_deref()
                        .expect("bound work-order ID"),
                )
                .cloned()
                .ok_or_else(|| {
                    ManagerApiError::conflict(
                        "placement_binding_incomplete",
                        "placement binding is missing its immutable decision",
                    )
                })?;
            if stable_manager_digest(b"splendor.manager.placement-decision.v1\0", &decision)
                .map_err(|_| {
                    ManagerApiError::internal(
                        "placement_digest_unavailable",
                        "placement decision could not be bound to immutable bytes",
                    )
                })?
                != existing.decision_digest
            {
                return Err(ManagerApiError::conflict(
                    "placement_binding_mismatch",
                    "stored placement decision no longer matches its immutable binding",
                ));
            }
            return Ok(Json(decision));
        }
    }
    let candidates = placement_candidates(
        &state,
        bound_work_order
            .as_ref()
            .map(|work_order| &work_order.envelope.work_order.tenant_id),
    )?;
    let decision = select_placement(&request.request, &candidates);
    let work_order_id = request.work_order_id.clone();
    if let Some(work_order_id) = work_order_id.clone() {
        let work_order = bound_work_order.as_ref().expect("bound work order");
        let decision_digest =
            stable_manager_digest(b"splendor.manager.placement-decision.v1\0", &decision).map_err(
                |_| {
                    ManagerApiError::internal(
                        "placement_digest_unavailable",
                        "placement decision could not be bound to immutable bytes",
                    )
                },
            )?;
        let mut placements = state.inner.placements.lock().map_err(|_| {
            ManagerApiError::internal("placement_lock", "placement decision unavailable")
        })?;
        let mut bindings = state.inner.placement_bindings.lock().map_err(|_| {
            ManagerApiError::internal("placement_lock", "placement binding unavailable")
        })?;
        if let Some(existing) = bindings.get(&work_order_id) {
            if existing.work_order_payload_digest != work_order.payload_digest
                || existing.request != request.request
            {
                return Err(ManagerApiError::conflict(
                    "placement_binding_replacement",
                    "an accepted work order was concurrently bound to a different immutable placement",
                ));
            }
            let existing_decision = placements.get(&work_order_id).cloned().ok_or_else(|| {
                ManagerApiError::conflict(
                    "placement_binding_incomplete",
                    "placement binding is missing its immutable decision",
                )
            })?;
            if stable_manager_digest(
                b"splendor.manager.placement-decision.v1\0",
                &existing_decision,
            )
            .map_err(|_| {
                ManagerApiError::internal(
                    "placement_digest_unavailable",
                    "placement decision could not be bound to immutable bytes",
                )
            })? != existing.decision_digest
            {
                return Err(ManagerApiError::conflict(
                    "placement_binding_mismatch",
                    "stored placement decision no longer matches its immutable binding",
                ));
            }
            return Ok(Json(existing_decision));
        }
        placements.insert(work_order_id.clone(), decision.clone());
        bindings.insert(
            work_order_id,
            BoundPlacementBinding {
                work_order_payload_digest: work_order.payload_digest.clone(),
                request: request.request.clone(),
                decision_digest,
            },
        );
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
    let revocation_gate = state.accepted_work_order_revocation_gate(&work_order_id)?;
    let _revocation_guard = revocation_gate.lock_owned().await;
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
    let work_order = load_accepted_work_order(&state, &work_order_id)?;
    let run_id = work_order
        .envelope
        .work_order
        .run_id
        .clone()
        .ok_or_else(|| {
            ManagerApiError::bad_request(
                "resident_dispatch_run_id_required",
                "resident dispatch requires a signed work order bound to a run id",
            )
        })?;
    let placement_decision = state
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
    let placement_binding = state
        .inner
        .placement_bindings
        .lock()
        .map_err(|_| ManagerApiError::internal("placement_lock", "placement binding unavailable"))?
        .get(&work_order_id)
        .cloned()
        .ok_or_else(|| {
            ManagerApiError::conflict(
                "placement_binding_missing",
                "placement is missing its immutable work-order binding",
            )
        })?;
    if placement_binding.work_order_payload_digest != work_order.payload_digest
        || stable_manager_digest(
            b"splendor.manager.placement-decision.v1\0",
            &placement_decision,
        )
        .map_err(|_| {
            ManagerApiError::internal(
                "placement_digest_unavailable",
                "placement decision could not be bound to immutable bytes",
            )
        })? != placement_binding.decision_digest
    {
        return Err(ManagerApiError::conflict(
            "dispatch_work_order_binding_mismatch",
            "placement is not bound to the accepted signed work-order payload",
        ));
    }
    let placement = BoundPlacement {
        request: placement_binding.request,
        decision: placement_decision,
        decision_digest: placement_binding.decision_digest,
    };
    if placement.decision.status != PlacementDecisionStatus::Selected {
        return Err(ManagerApiError::forbidden(
            "placement_rejected",
            "cannot dispatch rejected placement",
        ));
    }
    let expected_target = work_order.envelope.work_order.placement.target.clone();
    let dispatch_validation = splendor_types::validate_work_order(
        &work_order.envelope,
        &WorkOrderValidationContext {
            tenant_id: work_order.envelope.work_order.tenant_id.clone(),
            agent_id: work_order.envelope.work_order.agent_id.clone(),
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
                .decision
                .candidate_id
                .as_deref()
                .and_then(|raw| NodeId::parse(raw).ok())
        })
        .ok_or_else(|| {
            ManagerApiError::bad_request("missing_target_node", "dispatch requires selected node")
        })?;
    let placement_node_id = placement
        .decision
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
    if work_order.envelope.work_order.allowed_adapters.len() != 1 {
        return Err(ManagerApiError::bad_request(
            "resident_dispatch_profile_unsupported",
            "work-order v1 resident dispatch requires exactly one allowed adapter",
        ));
    }
    if let Some(existing) = stored_dispatch_outcome(&state, &work_order_id)? {
        return existing.map(Json);
    }
    let mut reservation = reserve_dispatch(&state, &work_order_id)?;
    // A dispatch may have completed between the optimistic lookup above and
    // reservation acquisition. Recheck while this caller owns the reservation
    // so a delayed concurrent duplicate cannot start a second tick.
    if let Some(existing) = stored_dispatch_outcome(&state, &work_order_id)? {
        return existing.map(Json);
    }
    let dispatch_binding = resolve_dispatch_binding(
        &state,
        &work_order_id,
        &work_order,
        &placement,
        &selected_node_id,
    )?;
    state
        .inner
        .resident_dispatch
        .validate_base_url(&dispatch_binding.resident_daemon_url)?;
    let instance_id = dispatch_binding.instance_id.clone();
    let daemon_url = dispatch_binding.resident_daemon_url.clone();
    let create_auth = state
        .inner
        .resident_dispatch
        .create_run_caller(&work_order.envelope.work_order.tenant_id, &instance_id)?;
    let create_audit = resident_audit(&create_auth.credential);
    let create = resident_create_run_payload(
        &work_order.envelope,
        &work_order.approval_policies,
        &run_id,
        serde_json::to_value(&create_auth.credential).map_err(|_| {
            ManagerApiError::internal(
                "resident_caller_projection_unavailable",
                "resident caller projection could not be serialized",
            )
        })?,
        create_audit,
    )?;
    revalidate_dispatch_authority(&state, &work_order, &run_id, &expected_target, "create")?;
    let create_response: ResidentHttpResponse<ResidentCreateRunResponse> = state
        .inner
        .resident_dispatch
        .create_run(&daemon_url, &create_auth.encoded, &create)
        .await
        .map_err(|error| {
            let _ = state.audit(
                "dispatch.failed",
                serde_json::json!({
                    "work_order_id": work_order_id,
                    "run_id": run_id,
                    "phase": "create",
                    "reason": resident_http_error_reason(&error),
                    "effect_certainty": "not_started_or_idempotently_reconcilable",
                }),
            );
            resident_http_error("create", error, false)
        })?;
    if create_response.value.run_id != run_id
        || create_response.value.request_id != create["request_id"].as_str().unwrap_or_default()
        || create_response.value.idempotency_key
            != create["idempotency_key"].as_str().unwrap_or_default()
    {
        state.audit(
            "dispatch.failed",
            serde_json::json!({"work_order_id": work_order_id, "run_id": run_id, "phase": "create", "reason": "resident_identity_mismatch"}),
        )?;
        return Err(ManagerApiError::bad_gateway(
            "resident_create_identity_mismatch",
            "resident create response did not match dispatched identities",
        ));
    }

    let start_auth = state
        .inner
        .resident_dispatch
        .start_run_caller(&work_order.envelope.work_order.tenant_id, &instance_id)?;
    let start_audit = resident_audit(&start_auth.credential);
    let start = serde_json::json!({
        "credential": &start_auth.credential,
        "audit_attribution": start_audit,
        "reason":"manager_resident_dispatch"
    });
    revalidate_dispatch_authority(&state, &work_order, &run_id, &expected_target, "start")?;
    persist_provisional_start_quarantine(&state, &work_order_id)?;
    let start_result: Result<ResidentHttpResponse<ResidentTickResponse>, ResidentHttpError> = state
        .inner
        .resident_dispatch
        .start_run(&daemon_url, &run_id, &start_auth.encoded, &start)
        .await;
    let start_response = match start_result {
        Ok(response) => response,
        Err(error) => {
            let effect_unknown = error.effect_may_have_occurred();
            let _ = state.audit(
                if effect_unknown {
                    "dispatch.effect_unknown"
                } else {
                    "dispatch.partial_failure"
                },
                serde_json::json!({
                    "work_order_id": work_order_id,
                    "run_id": run_id,
                    "phase": "start",
                    "reason": resident_http_error_reason(&error),
                    "effect_certainty": if effect_unknown { "unknown" } else { "not_started" },
                    "automatic_retry": false,
                }),
            );
            let api_error = resident_http_error("start", error, effect_unknown);
            return Err(persist_terminal_dispatch_failure(
                &state,
                &work_order_id,
                api_error,
                &mut reservation,
            ));
        }
    };
    if start_response.value.run_id != run_id {
        let _ = state.audit(
            "dispatch.effect_unknown",
            serde_json::json!({"work_order_id": work_order_id, "run_id": run_id, "phase": "start", "reason": "resident_identity_mismatch", "effect_certainty": "unknown", "automatic_retry": false}),
        );
        let error = ManagerApiError::gateway_timeout(
            "resident_start_effect_unknown",
            "resident start returned a mismatched run identity after request send; effect certainty is unknown and automatic retry is forbidden",
        );
        return Err(persist_terminal_dispatch_failure(
            &state,
            &work_order_id,
            error,
            &mut reservation,
        ));
    }
    let trace_event_id = match state.audit("run.dispatched", serde_json::json!({"work_order_id": work_order_id, "node_id": selected_node_id, "instance_id": instance_id, "run_id": run_id})) {
        Ok(trace_event_id) => trace_event_id,
        Err(error) => {
            return Err(persist_terminal_dispatch_failure(
                &state,
                &work_order_id,
                error,
                &mut reservation,
            ))
        }
    };
    let report = DispatchReport {
        work_order_id: work_order_id.clone(),
        selected_node_id: selected_node_id.clone(),
        selected_instance_id: instance_id.clone(),
        run_id: run_id.clone(),
        create_run_status: create_response.status,
        start_run_status: start_response.status,
        create_run_body: Some(create_response.body),
        start_run_body: Some(start_response.body),
        trace_event_id,
        resident_daemon_url: daemon_url,
    };
    if let Err(error) = store_authoritative_dispatch_success(&state, &work_order_id, &report) {
        return Err(persist_terminal_dispatch_failure(
            &state,
            &work_order_id,
            error,
            &mut reservation,
        ));
    }
    state
        .inner
        .telemetry
        .lock()
        .map_err(|_| ManagerApiError::internal("telemetry_lock", "telemetry lock unavailable"))?
        .upsert_run(RunTelemetry {
            tenant_id: work_order.envelope.work_order.tenant_id,
            agent_id: work_order.envelope.work_order.agent_id,
            run_id,
            node_id: selected_node_id,
            instance_id,
            status: telemetry_run_status(&start_response.value.status),
            updated_at: OffsetDateTime::now_utc(),
        });
    Ok(Json(report))
}

fn resident_create_run_payload(
    work_order: &WorkOrderEnvelope,
    approval_policies: &[ApprovalPolicy],
    run_id: &RunId,
    resident_credential: serde_json::Value,
    resident_audit: serde_json::Value,
) -> Result<serde_json::Value, ManagerApiError> {
    let allowed_actions = &work_order.work_order.allowed_actions;
    let allowed_adapters = &work_order.work_order.allowed_adapters;
    let allowed_permissions = &work_order.work_order.allowed_permissions;
    let adapter = match allowed_adapters.as_slice() {
        [adapter] if !adapter.trim().is_empty() => adapter,
        _ => {
            return Err(ManagerApiError::bad_request(
                "resident_dispatch_profile_unsupported",
                "work-order v1 resident dispatch requires exactly one allowed adapter",
            ))
        }
    };
    let registered_actions = allowed_actions
        .iter()
        .map(|action| {
            serde_json::json!({
                "name": action,
                "adapter": adapter,
                "required_permissions": allowed_permissions,
            })
        })
        .collect::<Vec<_>>();
    let create = serde_json::json!({
        "request_id": format!("req-manager-dispatch-{work_order_id}-{run_id}", work_order_id = work_order.work_order.work_order_id),
        "idempotency_key": format!("idem-manager-dispatch-{work_order_id}-{run_id}", work_order_id = work_order.work_order.work_order_id),
        "tenant_id": work_order.work_order.tenant_id,
        "agent_id": work_order.work_order.agent_id,
        "work_order": work_order,
        "credential": resident_credential,
        "audit_attribution": resident_audit,
        "allowed_actions": allowed_actions,
        "allowed_adapters": allowed_adapters,
        "allowed_permissions": allowed_permissions,
        "registered_actions": registered_actions,
        "policy_actions": [],
        "approval_policies": approval_policies,
        "allowed_percept_schemas": [],
        "allowed_percept_sources": [],
        "initial_state": {"dispatch":"uc-e2e-s4"},
        "snapshot_interval": 1
    });
    if work_order.work_order.run_id.as_ref() != Some(run_id) {
        return Err(ManagerApiError::bad_request(
            "resident_dispatch_run_id_required",
            "resident dispatch requires a signed work order bound to the run id",
        ));
    }
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
            schema: TASK_REQUEST_SCHEMA.to_string(),
            version: "v2".to_string(),
            description: "Scoped task/delegation request with mandatory grant reference"
                .to_string(),
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
    let work_order = load_current_message_work_order(&state, &request.work_order_id).inspect_err(
        |error| {
            let _ = state.audit(
                "remote_message.rejected",
                serde_json::json!({"message_id": request.message_envelope.message.message_id, "work_order_id": request.work_order_id.clone(), "reason": error.body.code}),
            );
        },
    )?;
    validate_remote_message_authority(
        &request,
        &work_order,
        &source_instance_record.registration,
        &target_instance_record.registration,
    )
    .inspect_err(|error| {
        let _ = state.audit(
            "remote_message.rejected",
            serde_json::json!({"message_id": request.message_envelope.message.message_id, "work_order_id": request.work_order_id.clone(), "reason": error.body.code}),
        );
    })?;
    let message_id = request.message_envelope.message.message_id.clone();
    let route_permission = Some(format!(
        "message.remote.proposal:{}",
        request.message_envelope.message.target_agent_id
    ));
    let requested_idempotency_scope =
        message_idempotency_scope_for_request(&request, &work_order, route_permission.clone());
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
        if message_idempotency_scope_from_report(&existing) != requested_idempotency_scope {
            state.audit(
                "remote_message.rejected",
                serde_json::json!({
                    "message_id": message_id,
                    "existing_message_id": existing_message_id,
                    "idempotency_key": idempotency_key,
                    "work_order_id": request.work_order_id.clone(),
                    "reason": "message_idempotency_scope_mismatch",
                    "remote_state_mutated": false,
                }),
            )?;
            return Err(ManagerApiError::forbidden(
                "message_idempotency_scope_mismatch",
                "idempotency key was already used for a different tenant/work-order/message route",
            ));
        }
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

fn load_current_message_work_order(
    state: &ManagerState,
    work_order_id: &str,
) -> Result<WorkOrderEnvelope, ManagerApiError> {
    if state
        .inner
        .revoked_work_orders
        .lock()
        .map_err(|_| ManagerApiError::internal("revocation_lock", "revocation lock unavailable"))?
        .contains(work_order_id)
    {
        return Err(ManagerApiError::forbidden(
            "revoked_work_order",
            "work order was revoked",
        ));
    }
    let accepted = load_accepted_work_order(state, work_order_id)?;
    let work_order = accepted.envelope;
    splendor_types::validate_work_order(
        &work_order,
        &WorkOrderValidationContext {
            tenant_id: work_order.work_order.tenant_id.clone(),
            agent_id: work_order.work_order.agent_id.clone(),
            run_id: work_order.work_order.run_id.clone(),
            expected_placement_target: None,
            now: OffsetDateTime::now_utc(),
        },
        &state.inner.work_order_keyring,
    )
    .map_err(|error| ManagerApiError::forbidden(error.reason_code(), error.to_string()))?;
    Ok(work_order)
}

fn message_idempotency_scope_for_request(
    request: &SendMessageRequest,
    work_order: &WorkOrderEnvelope,
    route_permission: Option<String>,
) -> MessageIdempotencyScope {
    MessageIdempotencyScope {
        tenant_id: work_order.work_order.tenant_id.clone(),
        work_order_id: request.work_order_id.clone(),
        run_id: request.message_envelope.message.run_id.clone(),
        source_agent_id: request.message_envelope.message.source_agent_id.clone(),
        target_agent_id: request.message_envelope.message.target_agent_id.clone(),
        schema: request.message_envelope.message.schema.clone(),
        source_instance_id: request.source_instance_id.clone(),
        target_instance_id: request.target_instance_id.clone(),
        route_permission,
    }
}

fn message_idempotency_scope_from_report(report: &MessageStatusReport) -> MessageIdempotencyScope {
    MessageIdempotencyScope {
        tenant_id: report.tenant_id.clone(),
        work_order_id: report.work_order_id.clone(),
        run_id: report.run_id.clone(),
        source_agent_id: report.source_agent_id.clone(),
        target_agent_id: report.target_agent_id.clone(),
        schema: report.schema.clone(),
        source_instance_id: report.source_instance_id.clone(),
        target_instance_id: report.target_instance_id.clone(),
        route_permission: report.route_permission.clone(),
    }
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
    if message_payload_smuggles_authority(message, work_order) {
        return Err(ManagerApiError::forbidden(
            "message_payload_scope_smuggling",
            "message payload cannot grant data refs or permissions outside work-order authority",
        ));
    }
    Ok(())
}

fn message_payload_smuggles_authority(message: &Message, work_order: &WorkOrderEnvelope) -> bool {
    let payload = &message.payload;
    let allowed_data_refs = &work_order.work_order.data_refs;
    let allowed_actions = &work_order.work_order.allowed_actions;
    let allowed_adapters = &work_order.work_order.allowed_adapters;
    let allowed_permissions = &work_order.work_order.allowed_permissions;

    if payload_fields_exceed_allowlist(payload, &["data_refs"], allowed_data_refs)
        || payload_fields_exceed_allowlist(
            payload,
            &["permissions", "allowed_permissions"],
            allowed_permissions,
        )
    {
        return true;
    }

    if message.schema != TASK_REQUEST_SCHEMA {
        return false;
    }

    let task_request = match TaskRequest::from_payload(payload) {
        Ok(task_request) => task_request,
        Err(_) => return true,
    };

    payload_fields_exceed_allowlist(
        payload,
        &["data_ref", "data_refs", "input_ref", "input_refs"],
        allowed_data_refs,
    ) || payload_fields_exceed_allowlist(payload, &["allowed_actions"], allowed_actions)
        || payload_fields_exceed_allowlist(payload, &["allowed_adapters"], allowed_adapters)
        || !values_within_allowlist(
            &task_request.delegated_authority.allowed_actions,
            allowed_actions,
        )
        || !values_within_allowlist(
            &task_request.delegated_authority.allowed_adapters,
            allowed_adapters,
        )
        || !values_within_allowlist(
            &task_request.delegated_authority.allowed_permissions,
            allowed_permissions,
        )
}

fn payload_fields_exceed_allowlist(
    payload: &serde_json::Value,
    fields: &[&str],
    allowlist: &[String],
) -> bool {
    fields
        .iter()
        .any(|field| payload_field_exceeds_allowlist(payload, field, allowlist))
}

fn payload_field_exceeds_allowlist(
    payload: &serde_json::Value,
    field: &str,
    allowlist: &[String],
) -> bool {
    let Some(value) = payload.get(field) else {
        return false;
    };
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::String(item) => !string_allowed(allowlist, item),
        serde_json::Value::Array(items) => items.iter().any(|item| match item {
            serde_json::Value::String(value) => !string_allowed(allowlist, value),
            serde_json::Value::Null => false,
            _ => true,
        }),
        _ => true,
    }
}

fn values_within_allowlist(values: &[String], allowlist: &[String]) -> bool {
    values.iter().all(|value| string_allowed(allowlist, value))
}

fn string_allowed(allowlist: &[String], value: &str) -> bool {
    allowlist.iter().any(|allowed| allowed == value)
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
    headers: HeaderMap,
    Json(request): Json<ApprovalRequestPayload>,
) -> Result<Json<GovernanceApprovalRecord>, ManagerApiError> {
    let verified = state.verify_approval_caller(&headers, &request.security)?;
    state.validate_security(
        &verified,
        Some(&request.security.audit_attribution),
        EndpointScope::ApprovalsManage,
        true,
    )?;
    let receipt_config = state
        .inner
        .authority_obligation_receipt_config
        .as_ref()
        .ok_or_else(|| {
            ManagerApiError::unavailable(
                "authority_obligation_receipt_config_unavailable",
                "trusted approval receipt configuration is unavailable",
            )
        })?;
    let challenge = request.challenge.as_ref().ok_or_else(|| {
        ManagerApiError::bad_request(
            "approval_challenge_required",
            "successful approval migration requires the exact daemon approval challenge",
        )
    })?;
    let resident_target = approval_resident_target_for_run(&state, &challenge.run_id)?;
    let receipt_config =
        receipt_config_for_approval_target(receipt_config, resident_target.as_ref())?;
    if request.approval_id != challenge.approval_id
        || request.tenant_id != challenge.tenant_id
        || request.agent_id != challenge.agent_id
        || request.run_id != challenge.run_id
        || request.action_id != challenge.action_id
        || request.action_name != challenge.action_name
        || request.adapter != challenge.adapter
        || request.policy_id != challenge.policy_id
        || request.risk_level != challenge.risk_level
        || request.audience != challenge.receipt_audience
        || request.expires_at != challenge.expires_at
    {
        return Err(ManagerApiError::bad_request(
            "approval_challenge_mismatch",
            "legacy approval request coordinates must exactly match the recorded challenge",
        ));
    }
    let mut approvals = state
        .inner
        .approvals
        .lock()
        .map_err(|_| ManagerApiError::internal("approval_lock", "approval lock unavailable"))?;
    if let Some(existing) = approvals.get(&challenge.approval_id.to_string()) {
        let existing_target = state
            .inner
            .approval_resident_targets
            .lock()
            .map_err(|_| {
                ManagerApiError::internal(
                    "approval_target_lock",
                    "approval resident target lock unavailable",
                )
            })?
            .get(&challenge.approval_id.to_string())
            .cloned();
        let exact_retry = existing.challenge.as_ref() == Some(challenge)
            && existing.reason == request.reason
            && existing.requested_by.principal == request.security.audit_attribution.principal
            && existing.expires_at == challenge.expires_at
            && existing_target == resident_target;
        if !exact_retry {
            return Err(ManagerApiError::conflict(
                "approval_request_conflict",
                "approval identity is already bound to a different challenge or request",
            ));
        }
        if matches!(existing.status.as_str(), "denied" | "revoked") {
            return Err(ManagerApiError::conflict(
                "approval_terminal_conflict",
                "denied or revoked approval state is immutable",
            ));
        }
        return Ok(Json(existing.clone()));
    }
    receipt_config
        .validate_approval_challenge(challenge, OffsetDateTime::now_utc())
        .map_err(|error| {
            ManagerApiError::bad_request(error.reason_code(), "approval challenge is invalid")
        })?;
    let trace_event_id = state.audit(
        "approval.requested",
        serde_json::json!({"approval_id": request.approval_id, "run_id": request.run_id, "action_id": request.action_id, "policy_id": request.policy_id, "requested_by": safe_approval_actor(&request.security.audit_attribution)}),
    )?;
    let requested_by = request.security.audit_attribution;
    let record = GovernanceApprovalRecord {
        approval_id: challenge.approval_id.clone(),
        tenant_id: challenge.tenant_id.clone(),
        agent_id: challenge.agent_id.clone(),
        run_id: challenge.run_id.clone(),
        action_id: challenge.action_id.clone(),
        action_name: challenge.action_name.clone(),
        adapter: challenge.adapter.clone(),
        policy_id: challenge.policy_id.clone(),
        risk_level: challenge.risk_level.clone(),
        audience: challenge.receipt_audience.clone(),
        status: "requested".to_string(),
        reason: request.reason,
        issued_by: requested_by.clone(),
        requested_by,
        decided_by: None,
        expires_at: challenge.expires_at,
        trace_event_id,
        evidence: None,
        challenge: Some(challenge.clone()),
        authority_obligation_receipt: None,
        resident_receipt_revocation_ack: None,
    };
    if let Some(target) = resident_target {
        state
            .inner
            .approval_resident_targets
            .lock()
            .map_err(|_| {
                ManagerApiError::internal(
                    "approval_target_lock",
                    "approval resident target lock unavailable",
                )
            })?
            .insert(record.approval_id.to_string(), target);
    }
    state
        .inner
        .approval_revocation_gates
        .lock()
        .map_err(|_| {
            ManagerApiError::internal(
                "approval_revocation_gate_unavailable",
                "approval revocation gate unavailable",
            )
        })?
        .insert(
            record.approval_id.to_string(),
            Arc::new(tokio::sync::Mutex::new(())),
        );
    approvals.insert(record.approval_id.to_string(), record.clone());
    Ok(Json(record))
}

async fn grant_approval(
    Path(approval_id): Path<ApprovalId>,
    State(state): State<ManagerState>,
    headers: HeaderMap,
    Json(request): Json<ApprovalDecisionRequest>,
) -> Result<Json<GovernanceApprovalRecord>, ManagerApiError> {
    let verified = state.verify_approval_caller(&headers, &request.security)?;
    state.validate_security(
        &verified,
        Some(&request.security.audit_attribution),
        EndpointScope::ApprovalsManage,
        true,
    )?;
    let decided_by = request.security.audit_attribution.clone();
    let receipt_config = state
        .inner
        .authority_obligation_receipt_config
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            ManagerApiError::unavailable(
                "authority_obligation_receipt_config_unavailable",
                "trusted approval receipt configuration is unavailable",
            )
        })?;
    let resident_target = state
        .inner
        .approval_resident_targets
        .lock()
        .map_err(|_| {
            ManagerApiError::internal(
                "approval_target_lock",
                "approval resident target lock unavailable",
            )
        })?
        .get(&approval_id.to_string())
        .cloned();
    let receipt_config =
        receipt_config_for_approval_target(&receipt_config, resident_target.as_ref())?;
    let mut approvals = state
        .inner
        .approvals
        .lock()
        .map_err(|_| ManagerApiError::internal("approval_lock", "approval lock unavailable"))?;
    let mut record = approvals
        .get(&approval_id.to_string())
        .cloned()
        .ok_or_else(|| ManagerApiError::not_found("approval_not_found", "approval not found"))?;
    let challenge = record.challenge.clone().ok_or_else(|| {
        ManagerApiError::forbidden(
            "approval_challenge_required",
            "legacy approval records cannot produce an authorizing receipt",
        )
    })?;
    if record.status == "granted" {
        let exact_retry = request.reason == record.reason
            && request
                .expires_at
                .is_none_or(|expires_at| expires_at == challenge.expires_at)
            && record.authority_obligation_receipt.is_some()
            && record
                .decided_by
                .as_ref()
                .is_some_and(|attribution| attribution.principal == decided_by.principal);
        if exact_retry {
            return Ok(Json(record));
        }
        return Err(ManagerApiError::conflict(
            "approval_grant_conflict",
            "approval was already granted with different immutable grant coordinates",
        ));
    }
    if matches!(record.status.as_str(), "denied" | "revoked") {
        return Err(ManagerApiError::conflict(
            "approval_terminal_conflict",
            "a denied or revoked approval cannot later be granted",
        ));
    }
    if record.status != "requested" {
        return Err(ManagerApiError::conflict(
            "approval_state_conflict",
            "approval is not in a grantable state",
        ));
    }
    if request
        .expires_at
        .is_some_and(|expires_at| expires_at != challenge.expires_at)
    {
        return Err(ManagerApiError::bad_request(
            "approval_challenge_expiry_mismatch",
            "approval expiry cannot differ from the recorded challenge",
        ));
    }
    let expires_at = challenge.expires_at;
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
    let issued_at = OffsetDateTime::now_utc();
    receipt_config
        .validate_approval_challenge(&challenge, issued_at)
        .map_err(|error| {
            ManagerApiError::forbidden(
                error.reason_code(),
                "approval obligation receipt could not be issued",
            )
        })?;
    let trace_event_id = state.audit(
        "approval.granted",
        serde_json::json!({"approval_id": approval_id, "run_id": record.run_id, "action_id": record.action_id, "audience": record.audience, "requested_by": safe_approval_actor(&record.requested_by), "decided_by": safe_approval_actor(&decided_by)}),
    )?;
    let trace_event_id_typed = TraceEventId::parse(&trace_event_id).map_err(|_| {
        ManagerApiError::internal(
            "approval_trace_identity_invalid",
            "approval audit trace identity was invalid",
        )
    })?;
    let receipt = receipt_config
        .issue_approval_receipt(&challenge, trace_event_id_typed, issued_at)
        .map_err(|error| {
            ManagerApiError::forbidden(
                error.reason_code(),
                "approval obligation receipt could not be issued",
            )
        })?;
    record.status = "granted".to_string();
    record.reason = request.reason;
    record.expires_at = expires_at;
    record.trace_event_id = trace_event_id;
    record.evidence = Some(evidence);
    record.decided_by = Some(decided_by);
    record.authority_obligation_receipt = Some(receipt);
    approvals.insert(approval_id.to_string(), record.clone());
    Ok(Json(record))
}

async fn deny_approval(
    Path(approval_id): Path<ApprovalId>,
    State(state): State<ManagerState>,
    headers: HeaderMap,
    Json(request): Json<ApprovalDecisionRequest>,
) -> Result<Json<GovernanceApprovalRecord>, ManagerApiError> {
    decide_approval(
        state,
        approval_id,
        headers,
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
    headers: HeaderMap,
    Json(request): Json<ApprovalDecisionRequest>,
) -> Result<Json<GovernanceApprovalRecord>, ManagerApiError> {
    let verified = state.verify_approval_caller(&headers, &request.security)?;
    state.validate_security(
        &verified,
        Some(&request.security.audit_attribution),
        EndpointScope::ApprovalsManage,
        true,
    )?;
    let decided_by = request.security.audit_attribution.clone();
    let gate = state.approval_revocation_gate(&approval_id)?;
    let _guard = gate.lock().await;
    let record = state
        .inner
        .approvals
        .lock()
        .map_err(|_| ManagerApiError::internal("approval_lock", "approval lock unavailable"))?
        .get(&approval_id.to_string())
        .cloned()
        .ok_or_else(|| ManagerApiError::not_found("approval_not_found", "approval not found"))?;
    let requested_expiry = request.expires_at.unwrap_or(record.expires_at);

    if record.status == "revoked" {
        let exact_retry = record.reason == request.reason
            && record.expires_at == requested_expiry
            && record.resident_receipt_revocation_ack.is_some()
            && record
                .decided_by
                .as_ref()
                .is_some_and(|attribution| attribution.principal == decided_by.principal);
        if exact_retry {
            return Ok(Json(record));
        }
        return Err(ManagerApiError::conflict(
            "approval_decision_conflict",
            "approval revocation is immutable and the repeated decision differs",
        ));
    }

    if record.status == "requested" {
        let mut evidence = ApprovalEvidence::new(
            approval_id.clone(),
            record.tenant_id.clone(),
            record.agent_id.clone(),
            record.run_id.clone(),
            ApprovalDecision::Denied,
            requested_expiry,
        )
        .with_action_name(record.action_name.clone())
        .with_adapter(record.adapter.clone());
        evidence.action_id = Some(record.action_id.clone());
        evidence.reason = Some(request.reason.clone());
        evidence.revoked = true;
        let trace_event_id = state.audit(
            "approval.revoked",
            serde_json::json!({"approval_id": approval_id, "run_id": record.run_id, "action_id": record.action_id, "reason": request.reason, "requested_by": safe_approval_actor(&record.requested_by), "decided_by": safe_approval_actor(&decided_by), "resident_receipt_revocation_required": false}),
        )?;
        let mut updated = record;
        updated.status = "revoked".to_string();
        updated.reason = request.reason;
        updated.expires_at = requested_expiry;
        updated.trace_event_id = trace_event_id;
        updated.evidence = Some(evidence);
        updated.decided_by = Some(decided_by);
        state
            .inner
            .approvals
            .lock()
            .map_err(|_| ManagerApiError::internal("approval_lock", "approval lock unavailable"))?
            .insert(approval_id.to_string(), updated.clone());
        return Ok(Json(updated));
    }

    if record.status != "granted" {
        return Err(ManagerApiError::conflict(
            "approval_terminal_conflict",
            "approval is not in a revocable state",
        ));
    }
    if requested_expiry != record.expires_at {
        return Err(ManagerApiError::bad_request(
            "approval_challenge_expiry_mismatch",
            "approval revocation cannot change the granted receipt expiry",
        ));
    }
    let receipt = record.authority_obligation_receipt.clone().ok_or_else(|| {
        ManagerApiError::unavailable(
            "approval_obligation_receipt_unavailable",
            "granted approval does not retain its exact raw receipt",
        )
    })?;
    let target = state
        .inner
        .approval_resident_targets
        .lock()
        .map_err(|_| {
            ManagerApiError::internal(
                "approval_target_lock",
                "approval resident target lock unavailable",
            )
        })?
        .get(&approval_id.to_string())
        .cloned()
        .ok_or_else(|| {
            ManagerApiError::unavailable(
                "approval_resident_target_unavailable",
                "granted approval has no immutable resident target",
            )
        })?;
    if target.run_id != record.run_id
        || receipt.approval_id.as_ref() != Some(&approval_id)
        || receipt.audience != record.audience
    {
        return Err(ManagerApiError::conflict(
            "approval_resident_target_mismatch",
            "retained approval receipt did not match its immutable resident target",
        ));
    }
    let validated_origin = state
        .inner
        .resident_dispatch
        .validate_base_url(&target.resident_daemon_url)
        .map_err(|_| {
            approval_receipt_revocation_transport_failed(
                "retained resident origin is no longer an allowed transport target",
            )
        })?;
    if validated_origin != target.resident_origin {
        return Err(approval_receipt_revocation_transport_failed(
            "retained resident origin did not match its immutable grant target",
        ));
    }
    let caller = state
        .inner
        .resident_dispatch
        .approval_receipt_revocation_caller(&record.tenant_id, &target.instance_id)?;
    let revocation = ResidentApprovalReceiptRevocationRequest {
        schema_version: RESIDENT_APPROVAL_RECEIPT_REVOCATION_SCHEMA_VERSION.to_string(),
        authority_obligation_receipt: receipt.clone(),
        reason: request.reason.clone(),
    };
    let body = serde_json::to_value(&revocation).map_err(|_| {
        ManagerApiError::internal(
            "approval_receipt_revocation_request_unavailable",
            "resident revocation request could not be serialized",
        )
    })?;
    let response: ResidentHttpResponse<ResidentApprovalReceiptRevocationAck> = match state
        .inner
        .resident_dispatch
        .revoke_approval_receipt(
            &target.resident_daemon_url,
            &record.run_id,
            &receipt.receipt_id,
            &caller.encoded,
            &body,
        )
        .await
    {
        Ok(response) => response,
        Err(ResidentHttpError::UnexpectedStatus {
            status: 409,
            upstream_code: Some(code),
        }) if code == "approval_receipt_revocation_too_late" => {
            return Err(approval_receipt_revocation_too_late())
        }
        Err(error) if error.effect_may_have_occurred() => {
            return Err(approval_receipt_revocation_effect_unknown(
                "resident revocation may have been applied without an exact acknowledgement",
            ))
        }
        Err(_) => {
            return Err(approval_receipt_revocation_transport_failed(
                "resident revocation was not delivered",
            ))
        }
    };
    let ack = response.value;
    if ack.schema_version != RESIDENT_APPROVAL_RECEIPT_REVOCATION_ACK_SCHEMA_VERSION
        || ack.receipt_id != receipt.receipt_id
        || ack.approval_id != approval_id
        || ack.target_instance_id != target.instance_id
        || ack.run_id != target.run_id
        || ack.receipt_audience != receipt.audience
        || ack.effect_certainty != splendor_types::EffectCertainty::Known
        || !matches!(
            ack.status,
            ResidentApprovalReceiptRevocationStatus::Revoked
                | ResidentApprovalReceiptRevocationStatus::AlreadyRevoked
        )
    {
        return Err(approval_receipt_revocation_effect_unknown(
            "resident revocation acknowledgement did not match the retained grant target",
        ));
    }

    let updated = complete_acknowledged_approval_revocation(
        &state,
        &AcknowledgedApprovalRevocation {
            approval_id,
            record,
            receipt,
            acknowledgement: ack,
            target,
            reason: request.reason,
            decided_by,
        },
    )?;
    Ok(Json(updated))
}

fn complete_acknowledged_approval_revocation(
    state: &ManagerState,
    completion: &AcknowledgedApprovalRevocation,
) -> Result<GovernanceApprovalRecord, ManagerApiError> {
    complete_acknowledged_approval_revocation_with_audit(state, completion, |event, details| {
        state.audit(event, details)
    })
}

fn complete_acknowledged_approval_revocation_with_audit<F>(
    state: &ManagerState,
    completion: &AcknowledgedApprovalRevocation,
    audit: F,
) -> Result<GovernanceApprovalRecord, ManagerApiError>
where
    F: FnOnce(&str, serde_json::Value) -> Result<String, ManagerApiError>,
{
    let mut evidence = ApprovalEvidence::new(
        completion.approval_id.clone(),
        completion.record.tenant_id.clone(),
        completion.record.agent_id.clone(),
        completion.record.run_id.clone(),
        ApprovalDecision::Denied,
        completion.record.expires_at,
    )
    .with_action_name(completion.record.action_name.clone())
    .with_adapter(completion.record.adapter.clone());
    evidence.action_id = Some(completion.record.action_id.clone());
    evidence.reason = Some(completion.reason.clone());
    evidence.revoked = true;
    let mut updated = completion.record.clone();
    updated.status = "revoked".to_string();
    updated.reason = completion.reason.clone();
    updated.evidence = Some(evidence);
    updated.decided_by = Some(completion.decided_by.clone());
    updated.authority_obligation_receipt = Some(completion.receipt.clone());
    updated.resident_receipt_revocation_ack = Some(completion.acknowledgement.clone());
    let mut approvals = state
        .inner
        .approvals
        .lock()
        .map_err(|_| ManagerApiError::internal("approval_lock", "approval lock unavailable"))?;
    let current = approvals
        .get(&completion.approval_id.to_string())
        .ok_or_else(|| {
            ManagerApiError::internal(
                "approval_state_unavailable",
                "approval disappeared after resident acknowledgement",
            )
        })?;
    if current.status != "granted"
        || current.authority_obligation_receipt.as_ref()
            != updated.authority_obligation_receipt.as_ref()
    {
        return Err(ManagerApiError::conflict(
            "approval_state_conflict",
            "approval changed while resident revocation was in flight",
        ));
    }
    // Acquire and compare the manager state before the audit append. Once the
    // append succeeds, insertion below is infallible while this lock is held;
    // an audit failure therefore leaves the granted record retryable, and a
    // fresh exact-target retry can converge from resident `already_revoked`.
    let trace_event_id = audit(
        "approval.revoked",
        serde_json::json!({"approval_id": completion.approval_id, "run_id": completion.record.run_id, "action_id": completion.record.action_id, "reason": completion.reason, "target_instance_id": completion.target.instance_id, "receipt_id": completion.receipt.receipt_id, "resident_status": completion.acknowledgement.status, "requested_by": safe_approval_actor(&completion.record.requested_by), "decided_by": safe_approval_actor(&completion.decided_by)}),
    )?;
    updated.trace_event_id = trace_event_id;
    approvals.insert(completion.approval_id.to_string(), updated.clone());
    Ok(updated)
}

fn approval_receipt_revocation_too_late() -> ManagerApiError {
    ManagerApiError::conflict(
        "approval_receipt_revocation_too_late",
        "resident receipt claim completed before revocation",
    )
    .details(serde_json::json!({
        "outcome": "too_late",
        "effect_certainty": "known",
        "revocation_applied": false,
    }))
}

fn approval_receipt_revocation_transport_failed(message: &'static str) -> ManagerApiError {
    ManagerApiError::bad_gateway("approval_receipt_revocation_transport_failed", message).details(
        serde_json::json!({
            "outcome": "transport_failed",
            "effect_certainty": "known",
            "revocation_applied": false,
        }),
    )
}

fn approval_receipt_revocation_effect_unknown(message: &'static str) -> ManagerApiError {
    ManagerApiError::gateway_timeout("approval_receipt_revocation_effect_unknown", message).details(
        serde_json::json!({
            "outcome": "effect_unknown",
            "effect_certainty": "unknown",
            "revocation_applied": serde_json::Value::Null,
        }),
    )
}

async fn decide_approval(
    state: ManagerState,
    approval_id: ApprovalId,
    headers: HeaderMap,
    request: ApprovalDecisionRequest,
    status: &'static str,
    decision: ApprovalDecision,
    revoked: bool,
) -> Result<Json<GovernanceApprovalRecord>, ManagerApiError> {
    let verified = state.verify_approval_caller(&headers, &request.security)?;
    state.validate_security(
        &verified,
        Some(&request.security.audit_attribution),
        EndpointScope::ApprovalsManage,
        true,
    )?;
    let decided_by = request.security.audit_attribution.clone();
    let mut approvals = state
        .inner
        .approvals
        .lock()
        .map_err(|_| ManagerApiError::internal("approval_lock", "approval lock unavailable"))?;
    let mut record = approvals
        .get(&approval_id.to_string())
        .cloned()
        .ok_or_else(|| ManagerApiError::not_found("approval_not_found", "approval not found"))?;
    let requested_expiry = request.expires_at.unwrap_or(record.expires_at);
    if record.status == status {
        let exact_retry = record.reason == request.reason
            && record.expires_at == requested_expiry
            && record.evidence.is_some()
            && record
                .decided_by
                .as_ref()
                .is_some_and(|attribution| attribution.principal == decided_by.principal);
        if exact_retry {
            return Ok(Json(record));
        }
        return Err(ManagerApiError::conflict(
            "approval_decision_conflict",
            "approval decision is immutable and the repeated decision differs",
        ));
    }
    match record.status.as_str() {
        "requested" => {}
        "granted" if status == "revoked" => {}
        "granted" => {
            return Err(ManagerApiError::conflict(
                "approval_decision_conflict",
                "a granted approval may only be revoked, not replaced by another decision",
            ))
        }
        "denied" | "revoked" => {
            return Err(ManagerApiError::conflict(
                "approval_terminal_conflict",
                "denied or revoked approval state is immutable",
            ))
        }
        _ => {
            return Err(ManagerApiError::conflict(
                "approval_state_conflict",
                "approval is not in a mutable decision state",
            ))
        }
    }
    let mut evidence = ApprovalEvidence::new(
        approval_id.clone(),
        record.tenant_id.clone(),
        record.agent_id.clone(),
        record.run_id.clone(),
        decision,
        requested_expiry,
    )
    .with_action_name(record.action_name.clone())
    .with_adapter(record.adapter.clone());
    evidence.action_id = Some(record.action_id.clone());
    evidence.reason = Some(request.reason.clone());
    evidence.revoked = revoked;
    let trace_event_id = state.audit(
        &format!("approval.{status}"),
        serde_json::json!({"approval_id": approval_id, "run_id": record.run_id, "action_id": record.action_id, "reason": request.reason, "requested_by": safe_approval_actor(&record.requested_by), "decided_by": safe_approval_actor(&decided_by)}),
    )?;
    record.status = status.to_string();
    record.reason = request.reason;
    record.expires_at = requested_expiry;
    record.trace_event_id = trace_event_id;
    record.evidence = Some(evidence);
    record.decided_by = Some(decided_by);
    record.authority_obligation_receipt = None;
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
        state
            .inner
            .resident_dispatch
            .validate_base_url(&target.daemon_url)?;
        let caller = state
            .inner
            .resident_dispatch
            .cancel_run_caller(tenant_id, &target.instance_id)?;
        let audit = resident_audit(&caller.credential);
        let payload = serde_json::json!({
            "credential": caller.credential,
            "audit_attribution": audit,
            "reason": request.reason,
        });
        cancel_payload_schema = Some("splendor.daemon.lifecycle_request.v1".to_string());
        let response: ResidentHttpResponse<crate::RunInspectResponse> = state
            .inner
            .resident_dispatch
            .cancel_run(&target.daemon_url, run_id, &caller.encoded, &payload)
            .await
            .map_err(|error| resident_http_error("cancel", error, false))?;
        cancel_status = Some(response.status);
        acknowledged = response.value.run_id == *run_id;
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

const MAX_WORK_ORDER_APPROVAL_POLICIES: usize = 64;
const MAX_APPROVAL_POLICY_ID_BYTES: usize = 128;
const MAX_APPROVAL_POLICY_REASON_BYTES: usize = 1024;
const MAX_APPROVAL_POLICY_RISK_LEVEL_BYTES: usize = 128;

fn validate_work_order_approval_policies(
    envelope: &WorkOrderEnvelope,
    approval_policies: &[ApprovalPolicy],
    now: OffsetDateTime,
) -> Result<(), ManagerApiError> {
    if approval_policies.len() > MAX_WORK_ORDER_APPROVAL_POLICIES {
        return Err(ManagerApiError::bad_request(
            "approval_policy_count_exceeded",
            "work-order admission approval policy count exceeds the supported bound",
        ));
    }
    let work_order = &envelope.work_order;
    let mut policy_ids = HashSet::with_capacity(approval_policies.len());
    for policy in approval_policies {
        if policy.schema_version != APPROVAL_POLICY_SCHEMA_VERSION {
            return Err(ManagerApiError::bad_request(
                "approval_policy_schema_unsupported",
                "work-order admission approval policy schema is unsupported",
            ));
        }
        validate_approval_policy_text(
            &policy.policy_id,
            MAX_APPROVAL_POLICY_ID_BYTES,
            "approval_policy_id_invalid",
            "approval policy ID must be non-empty, bounded, trimmed, and control-free",
        )?;
        if !policy_ids.insert(policy.policy_id.as_str()) {
            return Err(ManagerApiError::bad_request(
                "approval_policy_id_duplicate",
                "work-order admission approval policy IDs must be unique",
            ));
        }
        validate_approval_policy_text(
            &policy.reason,
            MAX_APPROVAL_POLICY_REASON_BYTES,
            "approval_policy_reason_invalid",
            "approval policy reason must be non-empty, bounded, trimmed, and control-free",
        )?;
        if let Some(risk_level) = policy.risk_level.as_deref() {
            validate_approval_policy_text(
                risk_level,
                MAX_APPROVAL_POLICY_RISK_LEVEL_BYTES,
                "approval_policy_risk_level_invalid",
                "approval policy risk level must be non-empty, bounded, trimmed, and control-free",
            )?;
        }
        if policy.tenant_id != work_order.tenant_id {
            return Err(ManagerApiError::bad_request(
                "approval_policy_tenant_mismatch",
                "approval policy tenant must exactly match the signed work-order tenant",
            ));
        }
        if policy
            .agent_id
            .as_ref()
            .is_some_and(|agent_id| agent_id != &work_order.agent_id)
        {
            return Err(ManagerApiError::bad_request(
                "approval_policy_agent_mismatch",
                "approval policy agent must be absent or exactly match the signed work-order agent",
            ));
        }
        if policy.action_name.as_ref().is_some_and(|action| {
            !work_order
                .allowed_actions
                .iter()
                .any(|allowed| allowed == action)
        }) {
            return Err(ManagerApiError::bad_request(
                "approval_policy_action_out_of_scope",
                "approval policy action must be absent or present in signed allowed_actions",
            ));
        }
        if policy.adapter.as_ref().is_some_and(|adapter| {
            !work_order
                .allowed_adapters
                .iter()
                .any(|allowed| allowed == adapter)
        }) {
            return Err(ManagerApiError::bad_request(
                "approval_policy_adapter_out_of_scope",
                "approval policy adapter must be absent or present in signed allowed_adapters",
            ));
        }
        if policy
            .required_permission
            .as_ref()
            .is_some_and(|permission| {
                !work_order
                    .allowed_permissions
                    .iter()
                    .any(|allowed| allowed == permission)
            })
        {
            return Err(ManagerApiError::bad_request(
                "approval_policy_permission_out_of_scope",
                "approval policy permission must be absent or present in signed allowed_permissions",
            ));
        }
        if let Some(expires_at) = policy.expires_at {
            if expires_at <= now {
                return Err(ManagerApiError::bad_request(
                    "approval_policy_expired",
                    "approval policy expiry must be in the future at admission",
                ));
            }
            if expires_at > work_order.expires_at {
                return Err(ManagerApiError::bad_request(
                    "approval_policy_expiry_exceeds_work_order",
                    "approval policy expiry cannot exceed signed work-order expiry",
                ));
            }
        }
    }
    Ok(())
}

fn validate_approval_policy_text(
    value: &str,
    maximum_bytes: usize,
    reason_code: &'static str,
    message: &'static str,
) -> Result<(), ManagerApiError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ManagerApiError::bad_request(reason_code, message));
    }
    Ok(())
}

fn accepted_work_order(
    envelope: WorkOrderEnvelope,
    approval_policies: Vec<ApprovalPolicy>,
) -> Result<AcceptedWorkOrder, ()> {
    let payload = envelope
        .work_order
        .signing_payload_bytes()
        .map_err(|_| ())?;
    let envelope_bytes = serde_json::to_vec(&envelope).map_err(|_| ())?;
    let mut payload_input = b"splendor.manager.accepted-work-order-payload.v1\0".to_vec();
    payload_input.extend_from_slice(&payload);
    let mut envelope_input = b"splendor.manager.accepted-work-order-envelope.v1\0".to_vec();
    envelope_input.extend_from_slice(&envelope_bytes);
    let approval_policies_digest = stable_manager_digest(
        b"splendor.manager.accepted-work-order-approval-policies.v1\0",
        &approval_policies,
    )
    .map_err(|_| ())?;
    Ok(AcceptedWorkOrder {
        envelope,
        approval_policies,
        payload_digest: ContentHash::blake3(payload_input).to_string(),
        envelope_digest: ContentHash::blake3(envelope_input).to_string(),
        approval_policies_digest,
    })
}

fn load_accepted_work_order(
    state: &ManagerState,
    work_order_id: &str,
) -> Result<AcceptedWorkOrder, ManagerApiError> {
    let stored = state
        .inner
        .work_orders
        .lock()
        .map_err(|_| ManagerApiError::internal("work_order_lock", "work order lock unavailable"))?
        .get(work_order_id)
        .cloned()
        .ok_or_else(|| {
            ManagerApiError::not_found("work_order_not_found", "work order not submitted")
        })?;
    let binding = state
        .inner
        .accepted_work_order_bindings
        .lock()
        .map_err(|_| {
            ManagerApiError::internal("work_order_lock", "work order binding unavailable")
        })?
        .get(work_order_id)
        .cloned()
        .ok_or_else(|| {
            ManagerApiError::conflict(
                "work_order_binding_missing",
                "accepted work order is missing its immutable binding",
            )
        })?;
    let reconstructed =
        accepted_work_order(stored.envelope.clone(), stored.approval_policies.clone()).map_err(
            |_| {
                ManagerApiError::internal(
                    "work_order_digest_unavailable",
                    "accepted work-order admission binding could not be reconstructed",
                )
            },
        )?;
    if stored.payload_digest != reconstructed.payload_digest
        || stored.envelope_digest != reconstructed.envelope_digest
        || stored.approval_policies_digest != reconstructed.approval_policies_digest
        || binding.payload_digest != reconstructed.payload_digest
        || binding.envelope_digest != reconstructed.envelope_digest
        || binding.approval_policies_digest != reconstructed.approval_policies_digest
    {
        return Err(ManagerApiError::conflict(
            "work_order_binding_mismatch",
            "accepted work order or its approval policies no longer match their immutable binding",
        ));
    }
    Ok(stored)
}

fn stable_manager_digest(
    domain: &[u8],
    value: &impl Serialize,
) -> Result<String, serde_json::Error> {
    let mut input = domain.to_vec();
    input.extend_from_slice(&serde_json::to_vec(value)?);
    Ok(ContentHash::blake3(input).to_string())
}

fn revalidate_dispatch_authority(
    state: &ManagerState,
    work_order: &AcceptedWorkOrder,
    run_id: &RunId,
    expected_target: &str,
    phase: &str,
) -> Result<(), ManagerApiError> {
    let work_order_id = work_order.envelope.work_order.work_order_id.to_string();
    if state
        .inner
        .revoked_work_orders
        .lock()
        .map_err(|_| ManagerApiError::internal("revocation_lock", "revocation lock unavailable"))?
        .contains(&work_order_id)
    {
        state.audit(
            "work_order.rejected",
            serde_json::json!({
                "work_order_id": work_order_id,
                "reason": "revoked_work_order",
                "phase": phase,
            }),
        )?;
        return Err(ManagerApiError::forbidden(
            "revoked_work_order",
            "work order was revoked before resident dispatch",
        ));
    }
    if let Err(error) = splendor_types::validate_work_order(
        &work_order.envelope,
        &WorkOrderValidationContext {
            tenant_id: work_order.envelope.work_order.tenant_id.clone(),
            agent_id: work_order.envelope.work_order.agent_id.clone(),
            run_id: Some(run_id.clone()),
            expected_placement_target: Some(expected_target.to_string()),
            now: OffsetDateTime::now_utc(),
        },
        &state.inner.work_order_keyring,
    ) {
        state.audit(
            "work_order.rejected",
            serde_json::json!({
                "work_order_id": work_order_id,
                "reason": error.reason_code(),
                "phase": phase,
            }),
        )?;
        return Err(ManagerApiError::forbidden(
            error.reason_code(),
            error.to_string(),
        ));
    }
    Ok(())
}

fn parse_signed_data_locality(
    value: Option<&str>,
) -> Result<Option<DataLocality>, ManagerApiError> {
    value
        .map(|value| match value {
            "cloud" => Ok(DataLocality::Cloud),
            "vpc" => Ok(DataLocality::Vpc),
            "on_prem" => Ok(DataLocality::OnPrem),
            "device" => Ok(DataLocality::Device),
            _ => Err(ManagerApiError::forbidden(
                "unsupported_work_order_data_locality",
                "signed work-order data_locality must use the current typed locality class vocabulary",
            )),
        })
        .transpose()
}

fn validate_placement_request_against_work_order(
    request: &PlacementRequest,
    work_order: &WorkOrderEnvelope,
) -> Result<(), ManagerApiError> {
    let signed = &work_order.work_order.placement;
    let mut requested_capabilities = request.required_capabilities.clone();
    requested_capabilities.sort();
    requested_capabilities.dedup();
    let mut signed_capabilities = signed.required_capabilities.clone();
    signed_capabilities.sort();
    signed_capabilities.dedup();
    let signed_locality = parse_signed_data_locality(signed.data_locality.as_deref())?;
    let gpu_requirement_satisfied = !signed.requires_gpu.unwrap_or(false)
        || requested_capabilities
            .iter()
            .any(|capability| capability == "gpu" || capability.starts_with("gpu."));
    if request.target.as_str() != signed.target
        || requested_capabilities != signed_capabilities
        || signed_locality.is_some_and(|locality| request.data_locality != Some(locality))
        || request.dedicated_instance != signed.dedicated_instance.unwrap_or(false)
        || request.max_runtime_ms != signed.max_runtime_ms
        || request.execution_mode != signed.execution_mode
        || !gpu_requirement_satisfied
    {
        return Err(ManagerApiError::forbidden(
            "placement_request_work_order_mismatch",
            "placement request does not exactly preserve the signed work-order placement constraints",
        ));
    }
    Ok(())
}

fn placement_candidates(
    state: &ManagerState,
    tenant_id: Option<&TenantId>,
) -> Result<Vec<PlacementCandidate>, ManagerApiError> {
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
        if node
            .registration
            .scope
            .fleet_id
            .as_ref()
            .is_some_and(|fleet_id| fleet_id != &state.inner.fleet_id)
            || tenant_id.is_some_and(|tenant_id| {
                node.registration
                    .scope
                    .tenant_id
                    .as_ref()
                    .is_some_and(|node_tenant| node_tenant != tenant_id)
            })
        {
            continue;
        }
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

fn resolve_dispatch_binding(
    state: &ManagerState,
    work_order_id: &str,
    work_order: &AcceptedWorkOrder,
    placement: &BoundPlacement,
    selected_node_id: &NodeId,
) -> Result<DispatchBinding, ManagerApiError> {
    if let Some(existing) = state
        .inner
        .dispatch_bindings
        .lock()
        .map_err(|_| {
            ManagerApiError::internal("dispatch_binding_lock", "dispatch binding unavailable")
        })?
        .get(work_order_id)
        .cloned()
    {
        if existing.work_order_payload_digest != work_order.payload_digest
            || existing.placement_decision_digest != placement.decision_digest
            || &existing.node_id != selected_node_id
        {
            return Err(ManagerApiError::conflict(
                "dispatch_binding_replacement",
                "resident dispatch is already immutably bound to different authority or placement",
            ));
        }
        ensure_bound_instance_eligible(state, work_order, placement, &existing)?;
        return Ok(existing);
    }

    let node = state
        .inner
        .registry
        .node(selected_node_id)
        .map_err(|error| ManagerApiError::not_found("node_not_found", error.to_string()))?;
    let now = OffsetDateTime::now_utc();
    if node.health.status != HealthStatus::Healthy
        || node.last_heartbeat_at + Duration::seconds(60) <= now
    {
        return Err(ManagerApiError::forbidden(
            "stale_or_unhealthy_node",
            "selected node heartbeat is stale or unhealthy",
        ));
    }
    if node
        .registration
        .scope
        .fleet_id
        .as_ref()
        .is_some_and(|fleet_id| fleet_id != &state.inner.fleet_id)
        || node
            .registration
            .scope
            .tenant_id
            .as_ref()
            .is_some_and(|tenant_id| tenant_id != &work_order.envelope.work_order.tenant_id)
    {
        return Err(ManagerApiError::forbidden(
            "resident_node_scope_mismatch",
            "selected node is outside the signed fleet or tenant scope",
        ));
    }

    let mut eligible = Vec::new();
    for instance_id in &node.instances {
        let instance = state
            .inner
            .registry
            .instance(instance_id)
            .map_err(|error| ManagerApiError::not_found("instance_not_found", error.to_string()))?;
        if instance_is_eligible(
            &instance,
            &node.registration.runtime_version,
            &work_order.envelope.work_order.tenant_id,
            &placement.request,
            now,
        ) {
            eligible.push(instance.registration.instance_id);
        }
    }
    let instance_id = match eligible.as_slice() {
        [instance_id] => instance_id.clone(),
        [] => {
            return Err(ManagerApiError::forbidden(
                "no_eligible_resident_instance",
                "selected node has no healthy resident instance supporting the signed tenant and placement requirements",
            ))
        }
        _ => {
            return Err(ManagerApiError::conflict(
                "ambiguous_eligible_resident_instances",
                "selected node has multiple eligible resident instances; exact instance selection is required",
            ))
        }
    };
    let resident_daemon_url = node
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
    let resident_origin = state
        .inner
        .resident_dispatch
        .validate_base_url(&resident_daemon_url)?;
    let binding = DispatchBinding {
        work_order_payload_digest: work_order.payload_digest.clone(),
        placement_decision_digest: placement.decision_digest.clone(),
        node_id: selected_node_id.clone(),
        instance_id,
        resident_daemon_url,
        resident_origin,
    };
    let mut bindings = state.inner.dispatch_bindings.lock().map_err(|_| {
        ManagerApiError::internal("dispatch_binding_lock", "dispatch binding unavailable")
    })?;
    match bindings.get(work_order_id) {
        Some(existing)
            if existing.work_order_payload_digest == binding.work_order_payload_digest
                && existing.placement_decision_digest == binding.placement_decision_digest
                && existing.node_id == binding.node_id
                && existing.instance_id == binding.instance_id
                && existing.resident_daemon_url == binding.resident_daemon_url
                && existing.resident_origin == binding.resident_origin =>
        {
            Ok(existing.clone())
        }
        Some(_) => Err(ManagerApiError::conflict(
            "dispatch_binding_replacement",
            "resident dispatch was concurrently bound to a different instance",
        )),
        None => {
            bindings.insert(work_order_id.to_string(), binding.clone());
            Ok(binding)
        }
    }
}

fn ensure_bound_instance_eligible(
    state: &ManagerState,
    work_order: &AcceptedWorkOrder,
    placement: &BoundPlacement,
    binding: &DispatchBinding,
) -> Result<(), ManagerApiError> {
    let node = state
        .inner
        .registry
        .node(&binding.node_id)
        .map_err(|error| ManagerApiError::not_found("node_not_found", error.to_string()))?;
    let instance = state
        .inner
        .registry
        .instance(&binding.instance_id)
        .map_err(|error| ManagerApiError::not_found("instance_not_found", error.to_string()))?;
    let now = OffsetDateTime::now_utc();
    if node.health.status != HealthStatus::Healthy
        || node.last_heartbeat_at + Duration::seconds(60) <= now
        || !instance_is_eligible(
            &instance,
            &node.registration.runtime_version,
            &work_order.envelope.work_order.tenant_id,
            &placement.request,
            now,
        )
    {
        return Err(ManagerApiError::forbidden(
            "bound_resident_instance_no_longer_eligible",
            "the immutably selected resident instance is no longer healthy or compatible",
        ));
    }
    let current_origin = state
        .inner
        .resident_dispatch
        .validate_base_url(&binding.resident_daemon_url)?;
    if current_origin != binding.resident_origin {
        return Err(ManagerApiError::forbidden(
            "resident_origin_binding_mismatch",
            "resident origin no longer matches the immutable dispatch binding",
        ));
    }
    Ok(())
}

fn instance_is_eligible(
    instance: &splendor_kernel::InstanceRecord,
    node_runtime_version: &str,
    tenant_id: &TenantId,
    placement: &PlacementRequest,
    now: OffsetDateTime,
) -> bool {
    let features = instance
        .registration
        .supported_features
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    instance.registration.runtime_mode == RuntimeMode::Resident
        && instance.health.status == HealthStatus::Healthy
        && instance.last_heartbeat_at + Duration::seconds(60) > now
        && instance.registration.hosted_tenants.contains(tenant_id)
        && instance.registration.runtime_version == node_runtime_version
        && placement
            .required_runtime_version
            .as_ref()
            .is_none_or(|required| required == &instance.registration.runtime_version)
        && features.contains("runtime.resident")
        && features.contains("gateway.verified")
        && placement
            .required_capabilities
            .iter()
            .all(|required| features.contains(required.as_str()))
}

#[derive(Debug)]
struct ResidentHttpResponse<T> {
    status: u16,
    body: String,
    value: T,
}

#[derive(Debug)]
struct ResidentRawHttpResponse {
    status: u16,
    body: Vec<u8>,
}

struct DispatchReservation {
    inner: Arc<ManagerInner>,
    work_order_id: String,
    release_on_drop: bool,
}

impl DispatchReservation {
    fn retain_fail_closed(&mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for DispatchReservation {
    fn drop(&mut self) {
        if !self.release_on_drop {
            return;
        }
        if let Ok(mut state) = self.inner.dispatch_state.lock() {
            state.in_flight.remove(&self.work_order_id);
        }
    }
}

fn stored_dispatch_outcome(
    state: &ManagerState,
    work_order_id: &str,
) -> Result<Option<Result<DispatchReport, ManagerApiError>>, ManagerApiError> {
    let dispatch_state = state
        .inner
        .dispatch_state
        .lock()
        .map_err(|_| ManagerApiError::internal("dispatch_lock", "dispatch lock unavailable"))?;
    if let Some(report) = dispatch_state.completed.get(work_order_id) {
        return Ok(Some(Ok(report.clone())));
    }
    Ok(dispatch_state
        .terminal_failures
        .get(work_order_id)
        .cloned()
        .map(Err))
}

fn reserve_dispatch(
    state: &ManagerState,
    work_order_id: &str,
) -> Result<DispatchReservation, ManagerApiError> {
    let mut dispatch_state = state
        .inner
        .dispatch_state
        .lock()
        .map_err(|_| ManagerApiError::internal("dispatch_lock", "dispatch lock unavailable"))?;
    if !dispatch_state.in_flight.insert(work_order_id.to_string()) {
        return Err(ManagerApiError::conflict(
            "dispatch_in_progress",
            "a resident dispatch is already in progress for this work order",
        ));
    }
    Ok(DispatchReservation {
        inner: Arc::clone(&state.inner),
        work_order_id: work_order_id.to_string(),
        release_on_drop: true,
    })
}

fn persist_provisional_start_quarantine(
    state: &ManagerState,
    work_order_id: &str,
) -> Result<(), ManagerApiError> {
    let mut dispatch_state = state.inner.dispatch_state.lock().map_err(|_| {
        ManagerApiError::internal(
            "dispatch_terminal_state_unavailable",
            "resident start quarantine could not be persisted; start was not sent",
        )
    })?;
    if dispatch_state.completed.contains_key(work_order_id) {
        return Err(ManagerApiError::conflict(
            "dispatch_already_completed",
            "resident dispatch already has an authoritative success report",
        ));
    }
    dispatch_state.terminal_failures.insert(
        work_order_id.to_string(),
        ManagerApiError::gateway_timeout(
            "resident_start_effect_unknown",
            "resident start may have been sent; effect certainty is unknown and automatic retry is forbidden",
        ),
    );
    Ok(())
}

fn store_authoritative_dispatch_success(
    state: &ManagerState,
    work_order_id: &str,
    report: &DispatchReport,
) -> Result<(), ManagerApiError> {
    let mut dispatch_state = state.inner.dispatch_state.lock().map_err(|_| {
        ManagerApiError::internal(
            "dispatch_lock",
            "completed resident dispatch could not be persisted",
        )
    })?;
    dispatch_state
        .completed
        .insert(work_order_id.to_string(), report.clone());
    dispatch_state.terminal_failures.remove(work_order_id);
    Ok(())
}

fn persist_terminal_dispatch_failure(
    state: &ManagerState,
    work_order_id: &str,
    error: ManagerApiError,
    reservation: &mut DispatchReservation,
) -> ManagerApiError {
    match state.inner.dispatch_state.lock() {
        Ok(mut dispatch_state) => {
            dispatch_state
                .terminal_failures
                .insert(work_order_id.to_string(), error.clone());
            error
        }
        Err(_) => {
            reservation.retain_fail_closed();
            ManagerApiError::internal(
                "dispatch_terminal_state_unavailable",
                "resident dispatch result could not be persisted; dispatch remains quarantined",
            )
        }
    }
}

#[derive(Debug)]
enum ResidentHttpError {
    InvalidUrl,
    Transport {
        timeout: bool,
        request_sent: bool,
    },
    ResponseTooLarge,
    UnexpectedStatus {
        status: u16,
        upstream_code: Option<String>,
    },
    InvalidResponse,
}

impl ResidentHttpError {
    fn effect_may_have_occurred(&self) -> bool {
        match self {
            Self::InvalidUrl => false,
            Self::Transport { request_sent, .. } => *request_sent,
            Self::ResponseTooLarge | Self::UnexpectedStatus { .. } | Self::InvalidResponse => true,
        }
    }
}

impl ResidentDispatchClient {
    fn validate_base_url(&self, base_url: &str) -> Result<String, ManagerApiError> {
        let url = reqwest::Url::parse(base_url).map_err(|_| {
            ManagerApiError::bad_request(
                "invalid_resident_daemon_url",
                "resident daemon URL must be an allowlisted exact origin",
            )
        })?;
        validate_resident_url(&url, self.allow_loopback_http, &self.allowed_origins).map_err(|_| {
            ManagerApiError::bad_request(
                "resident_origin_not_allowed",
                "resident daemon URL origin is not in the configured exact-origin allowlist",
            )
        })
    }

    fn create_run_caller(
        &self,
        tenant_id: &TenantId,
        instance_id: &InstanceId,
    ) -> Result<crate::caller_auth::SignedCallerToken, ManagerApiError> {
        self.signed_caller(tenant_id, instance_id, ResidentCallerOperation::CreateRun)
    }

    fn start_run_caller(
        &self,
        tenant_id: &TenantId,
        instance_id: &InstanceId,
    ) -> Result<crate::caller_auth::SignedCallerToken, ManagerApiError> {
        self.signed_caller(tenant_id, instance_id, ResidentCallerOperation::StartRun)
    }

    fn approval_receipt_revocation_caller(
        &self,
        tenant_id: &TenantId,
        instance_id: &InstanceId,
    ) -> Result<crate::caller_auth::SignedCallerToken, ManagerApiError> {
        self.signed_caller(
            tenant_id,
            instance_id,
            ResidentCallerOperation::RevokeApprovalReceipt,
        )
    }

    fn cancel_run_caller(
        &self,
        tenant_id: &TenantId,
        instance_id: &InstanceId,
    ) -> Result<crate::caller_auth::SignedCallerToken, ManagerApiError> {
        self.signed_caller(tenant_id, instance_id, ResidentCallerOperation::CancelRun)
    }

    async fn create_run(
        &self,
        base_url: &str,
        token: &str,
        body: &serde_json::Value,
    ) -> Result<ResidentHttpResponse<ResidentCreateRunResponse>, ResidentHttpError> {
        decode_resident_response(
            self.execute_operation(base_url, token, body, ResidentDispatchOperation::CreateRun)
                .await?,
        )
    }

    async fn start_run(
        &self,
        base_url: &str,
        run_id: &RunId,
        token: &str,
        body: &serde_json::Value,
    ) -> Result<ResidentHttpResponse<ResidentTickResponse>, ResidentHttpError> {
        decode_resident_response(
            self.execute_operation(
                base_url,
                token,
                body,
                ResidentDispatchOperation::StartRun { run_id },
            )
            .await?,
        )
    }

    async fn revoke_approval_receipt(
        &self,
        base_url: &str,
        run_id: &RunId,
        receipt_id: &AuthorityObligationReceiptId,
        token: &str,
        body: &serde_json::Value,
    ) -> Result<ResidentHttpResponse<ResidentApprovalReceiptRevocationAck>, ResidentHttpError> {
        decode_resident_response(
            self.execute_operation(
                base_url,
                token,
                body,
                ResidentDispatchOperation::RevokeApprovalReceipt { run_id, receipt_id },
            )
            .await?,
        )
    }

    async fn cancel_run(
        &self,
        base_url: &str,
        run_id: &RunId,
        token: &str,
        body: &serde_json::Value,
    ) -> Result<ResidentHttpResponse<crate::RunInspectResponse>, ResidentHttpError> {
        decode_resident_response(
            self.execute_operation(
                base_url,
                token,
                body,
                ResidentDispatchOperation::CancelRun { run_id },
            )
            .await?,
        )
    }

    async fn execute_operation(
        &self,
        base_url: &str,
        token: &str,
        body: &serde_json::Value,
        operation: ResidentDispatchOperation<'_>,
    ) -> Result<ResidentRawHttpResponse, ResidentHttpError> {
        let mut url = reqwest::Url::parse(base_url).map_err(|_| ResidentHttpError::InvalidUrl)?;
        validate_resident_url(&url, self.allow_loopback_http, &self.allowed_origins)?;
        let base_path = url.path().trim_end_matches('/');
        url.set_path(&format!("{base_path}{}", operation.path()));
        url.set_query(None);
        url.set_fragment(None);
        tokio::time::timeout(operation.timeout(self), async {
            let response = self
                .http
                .post(url)
                .bearer_auth(token)
                .header("x-splendor-api-version", "0.1")
                .header("x-splendor-client", "splendor-manager")
                .json(body)
                .send()
                .await
                .map_err(|error| ResidentHttpError::Transport {
                    timeout: error.is_timeout(),
                    request_sent: !error.is_connect(),
                })?;
            let status = response.status();
            let bytes = read_bounded_response(response, self.maximum_response_bytes).await?;
            if status != operation.expected_status() {
                let upstream_code = serde_json::from_slice::<ApiErrorBody>(&bytes)
                    .ok()
                    .and_then(|error| bounded_upstream_code(error.code));
                return Err(ResidentHttpError::UnexpectedStatus {
                    status: status.as_u16(),
                    upstream_code,
                });
            }
            Ok(ResidentRawHttpResponse {
                status: status.as_u16(),
                body: bytes,
            })
        })
        .await
        .map_err(|_| ResidentHttpError::Transport {
            timeout: true,
            request_sent: true,
        })?
    }

    fn signed_caller(
        &self,
        tenant_id: &TenantId,
        instance_id: &InstanceId,
        operation: ResidentCallerOperation,
    ) -> Result<crate::caller_auth::SignedCallerToken, ManagerApiError> {
        self.signer
            .sign(
                tenant_id,
                instance_id,
                vec![operation.endpoint_scope()],
                OffsetDateTime::now_utc(),
                Duration::seconds(60),
            )
            .map_err(|_| {
                ManagerApiError::internal(
                    "resident_caller_token_unavailable",
                    "resident caller token could not be issued",
                )
            })
    }
}

fn decode_resident_response<T: for<'de> Deserialize<'de> + Serialize>(
    response: ResidentRawHttpResponse,
) -> Result<ResidentHttpResponse<T>, ResidentHttpError> {
    let value =
        serde_json::from_slice(&response.body).map_err(|_| ResidentHttpError::InvalidResponse)?;
    let body = serde_json::to_string(&value).map_err(|_| ResidentHttpError::InvalidResponse)?;
    Ok(ResidentHttpResponse {
        status: response.status,
        body,
        value,
    })
}

async fn read_bounded_response(
    mut response: reqwest::Response,
    maximum_response_bytes: usize,
) -> Result<Vec<u8>, ResidentHttpError> {
    if maximum_response_bytes == 0
        || response
            .content_length()
            .is_some_and(|length| length > maximum_response_bytes as u64)
    {
        return Err(ResidentHttpError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) =
        response
            .chunk()
            .await
            .map_err(|error| ResidentHttpError::Transport {
                timeout: error.is_timeout(),
                request_sent: true,
            })?
    {
        if body.len().saturating_add(chunk.len()) > maximum_response_bytes {
            return Err(ResidentHttpError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_resident_url(
    url: &reqwest::Url,
    allow_loopback_http: bool,
    allowed_origins: &HashSet<String>,
) -> Result<String, ResidentHttpError> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ResidentHttpError::InvalidUrl);
    }
    if url.scheme() != "https" && (url.scheme() != "http" || !allow_loopback_http) {
        return Err(ResidentHttpError::InvalidUrl);
    }
    if url.scheme() == "http"
        && !url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    {
        return Err(ResidentHttpError::InvalidUrl);
    }
    let origin = url.origin().ascii_serialization();
    if !allowed_origins.contains(&origin) {
        return Err(ResidentHttpError::InvalidUrl);
    }
    Ok(origin)
}

fn canonical_allowed_origins(
    origins: &[String],
    allow_loopback_http: bool,
) -> Result<HashSet<String>, String> {
    let mut canonical = HashSet::new();
    for raw in origins {
        let url = reqwest::Url::parse(raw)
            .map_err(|_| "resident allowed origin is invalid".to_string())?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
            || (url.scheme() != "https" && (url.scheme() != "http" || !allow_loopback_http))
            || (url.scheme() == "http"
                && !url.host_str().is_some_and(|host| {
                    host.eq_ignore_ascii_case("localhost")
                        || host
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|ip| ip.is_loopback())
                }))
        {
            return Err("resident allowed origin is invalid".to_string());
        }
        let origin = url.origin().ascii_serialization();
        if !canonical.insert(origin) {
            return Err("resident allowed origins must be unique".to_string());
        }
    }
    Ok(canonical)
}

fn bounded_upstream_code(code: String) -> Option<String> {
    if !code.is_empty()
        && code.len() <= 128
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Some(code)
    } else {
        None
    }
}

fn resident_http_error_reason(error: &ResidentHttpError) -> &'static str {
    match error {
        ResidentHttpError::InvalidUrl => "invalid_resident_url",
        ResidentHttpError::Transport { timeout: true, .. } => "resident_timeout",
        ResidentHttpError::Transport { timeout: false, .. } => "resident_transport_failure",
        ResidentHttpError::ResponseTooLarge => "resident_response_too_large",
        ResidentHttpError::UnexpectedStatus { .. } => "resident_rejected_request",
        ResidentHttpError::InvalidResponse => "resident_invalid_response",
    }
}

fn resident_http_error(
    phase: &str,
    error: ResidentHttpError,
    effect_unknown: bool,
) -> ManagerApiError {
    if effect_unknown {
        return ManagerApiError::gateway_timeout(
            "resident_start_effect_unknown",
            "resident start completed without authoritative success; effect certainty is unknown and automatic retry is forbidden",
        );
    }
    match error {
        ResidentHttpError::InvalidUrl => ManagerApiError::bad_request(
            "invalid_resident_daemon_url",
            "resident daemon URL must use HTTPS, except explicit loopback tests",
        ),
        ResidentHttpError::Transport { timeout: true, .. } => ManagerApiError::gateway_timeout(
            format!("resident_{phase}_timeout"),
            format!("resident {phase} request timed out"),
        ),
        ResidentHttpError::Transport { timeout: false, .. } => ManagerApiError::bad_gateway(
            format!("resident_{phase}_transport_error"),
            format!("resident {phase} request failed before a valid response"),
        ),
        ResidentHttpError::ResponseTooLarge => ManagerApiError::bad_gateway(
            format!("resident_{phase}_response_too_large"),
            format!("resident {phase} response exceeded the configured limit"),
        ),
        ResidentHttpError::UnexpectedStatus {
            status,
            upstream_code,
        } => ManagerApiError::bad_gateway(
            format!("resident_{phase}_rejected"),
            format!(
                "resident {phase} rejected the request with status {status} and code {}",
                upstream_code.as_deref().unwrap_or("unknown")
            ),
        ),
        ResidentHttpError::InvalidResponse => ManagerApiError::bad_gateway(
            format!("resident_{phase}_invalid_response"),
            format!("resident {phase} returned an invalid success response"),
        ),
    }
}

fn telemetry_run_status(status: &crate::RunStatus) -> RunStatus {
    match status {
        crate::RunStatus::Pending => RunStatus::Pending,
        crate::RunStatus::Running => RunStatus::Running,
        crate::RunStatus::Paused => RunStatus::Paused,
        crate::RunStatus::WaitingForApproval => RunStatus::WaitingForApproval,
        crate::RunStatus::Interrupted => RunStatus::Interrupted,
        crate::RunStatus::Resuming => RunStatus::Resuming,
        crate::RunStatus::Completed => RunStatus::Completed,
        crate::RunStatus::Failed => RunStatus::Failed,
        crate::RunStatus::Cancelled => RunStatus::Cancelled,
        crate::RunStatus::Denied => RunStatus::Denied,
        crate::RunStatus::Expired => RunStatus::Expired,
    }
}

fn resident_audit(credential: &CallerCredential) -> serde_json::Value {
    let requested_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current timestamp formats as RFC3339");
    serde_json::json!({
        "principal": &credential.principal,
        "credential_id": &credential.credential_id,
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
    use std::future::Future;
    use std::io::{Read, Write};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use tower::ServiceExt;

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        future.poll(&mut context)
    }

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

    fn manager_with_allowed_origins(allowed_origins: Vec<String>) -> ManagerState {
        let signer = CallerTokenSigner::generate_for_test(
            "urn:splendor:manager:central-manager",
            "central-manager",
            "resident-dispatch-client",
            "manager-resident-unit-test",
        )
        .expect("unit-test caller signer");
        let mut options = ResidentDispatchOptions::loopback_test();
        options.allowed_origins = allowed_origins;
        ManagerState::local_acceptance_with_dispatch(signer, options).expect("unit-test manager")
    }

    fn manager_with_approval_auth(
        allowed_origins: Vec<String>,
    ) -> (ManagerState, CallerTokenSigner) {
        let mut options = ResidentDispatchOptions::loopback_test();
        options.allowed_origins = allowed_origins;
        manager_with_approval_auth_options(options)
    }

    fn manager_with_approval_auth_options(
        options: ResidentDispatchOptions,
    ) -> (ManagerState, CallerTokenSigner) {
        let outbound_signer = CallerTokenSigner::generate_for_test(
            "urn:splendor:manager:central-manager",
            "central-manager",
            "resident-dispatch-client",
            "manager-resident-unit-test",
        )
        .expect("outbound unit-test signer");
        let approval_signer = CallerTokenSigner::generate_for_test(
            "urn:splendor:manager:approval-test-issuer",
            "approval-control-plane",
            "approval-test-client",
            "manager-approval-unit-test",
        )
        .expect("approval unit-test signer");
        let now = OffsetDateTime::now_utc();
        let trust = crate::caller_auth::CallerTokenTrustSnapshot::single_key(
            approval_signer.issuer(),
            approval_signer.app_principal_id(),
            approval_signer.kid(),
            &approval_signer.public_key_bytes(),
            vec![EndpointScope::ApprovalsManage, EndpointScope::FleetRead],
            now - Duration::seconds(1),
        )
        .with_expected_client_principal_id("approval-test-client");
        let fleet_id = FleetId::parse("00000000-0000-4000-8000-000000000104").expect("test fleet");
        let verifier = CallerTokenVerifier::for_manager(trust, "central-manager", fleet_id.clone())
            .expect("approval unit-test verifier");
        let mut keyring = WorkOrderKeyring::new();
        keyring
            .insert_shared_secret("work-order-local-key", b"splendor-local-work-order-secret")
            .expect("work-order keyring");
        let state = ManagerState::acceptance_with_dispatch_receipt_and_approval_auth(
            "central-manager",
            fleet_id,
            keyring,
            outbound_signer,
            options,
            local_manager_authority_receipt_config(),
            verifier,
        )
        .expect("approval-authenticated unit-test manager");
        (state, approval_signer)
    }

    fn approval_security(
        state: &ManagerState,
        signer: &CallerTokenSigner,
        scopes: Vec<EndpointScope>,
    ) -> (HeaderMap, ManagerSecurityFields) {
        let signed = signer
            .sign_for_manager(
                &state.inner.fleet_id,
                &state.inner.manager_id,
                scopes,
                OffsetDateTime::now_utc(),
                Duration::seconds(60),
            )
            .expect("approval caller token");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", signed.encoded))
                .expect("authorization header"),
        );
        let audit_attribution = audit_for(&signed.credential);
        (
            headers,
            ManagerSecurityFields {
                credential: signed.credential,
                audit_attribution,
            },
        )
    }

    fn approval_request_fixture(security: ManagerSecurityFields) -> ApprovalRequestPayload {
        let approval_id =
            ApprovalId::parse("66666666-6666-4666-8666-666666666661").expect("approval");
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let agent_id = AgentId::parse("22222222-2222-4222-8222-222222222222").expect("agent");
        let run_id = RunId::parse("44444444-4444-4444-8444-444444444441").expect("run");
        let action_id = splendor_types::ActionId::parse("55555555-5555-4555-8555-555555555551")
            .expect("action");
        let requested_at = OffsetDateTime::now_utc() - Duration::seconds(1);
        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
        let receipt_audience = format!("splendor.daemon.run:{run_id}");
        let challenge = ApprovalChallenge {
            schema_version: splendor_types::APPROVAL_CHALLENGE_SCHEMA_VERSION.to_string(),
            approval_id: approval_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: run_id.clone(),
            action_id: action_id.clone(),
            action_name: "artifact.publish_external".to_string(),
            adapter: "artifact-store".to_string(),
            policy_id: "policy_approval_auth_unit".to_string(),
            risk_level: Some("high".to_string()),
            subject: splendor_types::PrincipalId::new(),
            authority_decision_id: splendor_types::AuthorityDecisionId::new(),
            obligation_id: splendor_types::AuthorityObligationId::new(),
            receipt_audience: receipt_audience.clone(),
            canonical_request_digest: format!("blake3:{}", "1".repeat(64)),
            gateway_action_request_digest: format!("blake3:{}", "2".repeat(64)),
            physical_action_resource_coordinate: None,
            authority_decision_digest: format!("blake3:{}", "3".repeat(64)),
            requested_at,
            expires_at,
        };
        ApprovalRequestPayload {
            security,
            approval_id,
            tenant_id,
            agent_id,
            run_id,
            action_id,
            action_name: challenge.action_name.clone(),
            adapter: challenge.adapter.clone(),
            policy_id: challenge.policy_id.clone(),
            risk_level: Some("high".to_string()),
            audience: receipt_audience,
            expires_at,
            reason: "approval auth endpoint fixture".to_string(),
            challenge: Some(challenge),
        }
    }

    fn test_work_order(target_agent: &str) -> WorkOrderEnvelope {
        test_work_order_with(
            "wo_test_remote",
            target_agent,
            RunId::parse("44444444-4444-4444-8444-444444444444").expect("run"),
            OffsetDateTime::now_utc() + Duration::minutes(10),
        )
    }

    fn dispatch_test_work_order() -> WorkOrderEnvelope {
        let now = OffsetDateTime::now_utc();
        WorkOrderEnvelope::signed_with_shared_secret(
            WorkOrder {
                schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
                work_order_id: WorkOrderId::try_new("wo_test_dispatch").expect("work order id"),
                tenant_id: TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant"),
                agent_id: AgentId::parse("22222222-2222-4222-8222-222222222222").expect("agent"),
                run_id: Some(RunId::parse("44444444-4444-4444-8444-444444444445").expect("run")),
                objective: "admit a resident run without synthesizing policy actions".to_string(),
                allowed_actions: vec!["daemon.record".to_string()],
                allowed_adapters: vec!["resident.test".to_string()],
                allowed_permissions: vec!["fixture.execute".to_string()],
                data_refs: Vec::new(),
                quotas: WorkOrderQuotaPolicy::default(),
                placement: WorkOrderPlacement {
                    target: "customer_vpc".to_string(),
                    data_locality: Some("vpc".to_string()),
                    requires_gpu: Some(false),
                    dedicated_instance: Some(false),
                    required_capabilities: vec!["runtime.resident".to_string()],
                    max_runtime_ms: Some(30_000),
                    execution_mode: PlacementExecutionMode::Live,
                },
                issued_at: now - Duration::minutes(1),
                expires_at: now + Duration::minutes(10),
                revocation: RevocationStatus::Active,
            },
            "work-order-local-key",
            b"splendor-local-work-order-secret",
        )
        .expect("signed dispatch work order")
    }

    fn dispatch_approval_policy(work_order: &WorkOrderEnvelope) -> ApprovalPolicy {
        ApprovalPolicy {
            schema_version: APPROVAL_POLICY_SCHEMA_VERSION.to_string(),
            policy_id: "resident-dispatch-approval".to_string(),
            tenant_id: work_order.work_order.tenant_id.clone(),
            agent_id: Some(work_order.work_order.agent_id.clone()),
            action_name: Some("daemon.record".to_string()),
            adapter: Some("resident.test".to_string()),
            required_permission: Some("fixture.execute".to_string()),
            side_effect_class: None,
            risk_level: Some("high".to_string()),
            reason: "resident dispatch requires exact approval".to_string(),
            expires_at: Some(work_order.work_order.expires_at - Duration::seconds(1)),
        }
    }

    fn dispatch_placement_request() -> PlacementRequest {
        PlacementRequest {
            target: PlacementTarget::CustomerVpc,
            required_capabilities: vec!["runtime.resident".to_string()],
            data_locality: Some(DataLocality::Vpc),
            dedicated_instance: false,
            required_runtime_version: None,
            max_runtime_ms: Some(30_000),
            execution_mode: PlacementExecutionMode::Live,
        }
    }

    fn test_work_order_with(
        work_order_id: &str,
        target_agent: &str,
        run_id: RunId,
        expires_at: OffsetDateTime,
    ) -> WorkOrderEnvelope {
        let issued_at = if expires_at > OffsetDateTime::now_utc() {
            OffsetDateTime::now_utc() - Duration::minutes(1)
        } else {
            expires_at - Duration::minutes(1)
        };
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let agent_id =
            splendor_types::AgentId::parse("22222222-2222-4222-8222-222222222222").expect("agent");
        WorkOrderEnvelope::signed_with_shared_secret(
            WorkOrder {
                schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
                work_order_id: WorkOrderId::try_new(work_order_id).expect("work order id"),
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
                    data_locality: Some("vpc".to_string()),
                    requires_gpu: Some(false),
                    dedicated_instance: Some(false),
                    required_capabilities: vec!["message.remote.proposal".to_string()],
                    max_runtime_ms: Some(30_000),
                    execution_mode: PlacementExecutionMode::Live,
                },
                issued_at,
                expires_at,
                revocation: RevocationStatus::Active,
            },
            "work-order-local-key",
            b"splendor-local-work-order-secret",
        )
        .expect("signed work order")
    }

    async fn register_message_route(
        state: &ManagerState,
        security: &ManagerSecurityFields,
        tenant_id: &TenantId,
    ) {
        for registration in [
            node(
                &state.inner.fleet_id,
                "00000000-0000-4000-8000-000000000204",
                "http://127.0.0.1:1",
                "customer_vpc",
                "vpc",
                vec!["message.remote.proposal", "runtime.resident"],
            ),
            node(
                &state.inner.fleet_id,
                "00000000-0000-4000-8000-000000000404",
                "http://127.0.0.1:1",
                "resident_cloud_pool",
                "cloud",
                vec!["message.remote.proposal", "runtime.resident"],
            ),
        ] {
            let _ = register_node(
                State(state.clone()),
                Json(RegisterNodeRequest {
                    security: security.clone(),
                    registration,
                }),
            )
            .await
            .expect("message route node registered");
        }
        for registration in [
            instance(
                "00000000-0000-4000-8000-000000000204",
                "00000000-0000-4000-8000-000000000302",
                tenant_id,
            ),
            instance(
                "00000000-0000-4000-8000-000000000404",
                "00000000-0000-4000-8000-000000000304",
                tenant_id,
            ),
        ] {
            let _ = register_instance(
                State(state.clone()),
                Json(RegisterInstanceRequest {
                    security: security.clone(),
                    registration,
                }),
            )
            .await
            .expect("message route instance registered");
        }
    }

    async fn submit_test_work_order(
        state: &ManagerState,
        security: &ManagerSecurityFields,
        work_order: WorkOrderEnvelope,
    ) {
        let _ = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security: security.clone(),
                work_order,
                expected_audience: "central-manager".to_string(),
                approval_policies: Vec::new(),
            }),
        )
        .await
        .expect("work order accepted");
    }

    fn instance(node_id: &str, instance_id: &str, tenant_id: &TenantId) -> InstanceRegistration {
        serde_json::from_value(serde_json::json!({
            "instance_id": instance_id,
            "node_id": node_id,
            "runtime_mode": "resident",
            "hosted_tenants": [tenant_id],
            "supported_features": [
                "runtime.resident",
                "gateway.verified",
                "message.remote",
                "message.remote.proposal",
                "sql.read_fixture",
                "artifact.create_internal"
            ],
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

    fn spawn_fixed_status_server() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind resident mock");
        let addr = listener.local_addr().expect("resident mock addr");
        std::thread::spawn(move || {
            for _ in 0..1 {
                let (mut stream, _) = listener.accept().expect("accept resident request");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                    .expect("set resident read timeout");
                let mut request = Vec::new();
                let _ = stream.read_to_end(&mut request);
                let request_text = String::from_utf8_lossy(&request);
                let run_id = request_text
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|path| path.strip_prefix("/runs/"))
                    .and_then(|path| path.strip_suffix("/cancel"))
                    .unwrap_or("00000000-0000-4000-8000-000000000001");
                let observed_at = OffsetDateTime::from_unix_timestamp(1_783_900_800)
                    .expect("fixed resident timestamp");
                let body = serde_json::to_string(&crate::RunInspectResponse {
                    run_id: RunId::parse(run_id).expect("cancel request run id"),
                    tenant_id: TenantId::parse("11111111-1111-4111-8111-111111111111")
                        .expect("fixed tenant"),
                    agent_id: AgentId::parse("22222222-2222-4222-8222-222222222222")
                        .expect("fixed agent"),
                    status: crate::RunStatus::Cancelled,
                    state_head: None,
                    ticks: 0,
                    adapter_executions: 0,
                    policy_bundle: None,
                    created_at: observed_at,
                    updated_at: observed_at,
                })
                .expect("fixed resident response serializes");
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .expect("write resident response");
            }
        });
        format!("http://{addr}")
    }

    #[derive(Clone, Copy, Debug)]
    enum ApprovalRevocationFault {
        ExecuteThenReset,
        PostSendTimeout,
        MalformedResponse,
        OversizedResponse,
        WrongTargetAck,
        NonSuccessResponse,
        AlreadyRevoked,
    }

    fn read_complete_http_request(stream: &mut std::net::TcpStream) -> String {
        stream
            .set_read_timeout(Some(StdDuration::from_secs(1)))
            .expect("set fault-server read timeout");
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = stream.read(&mut chunk).expect("read manager request");
            assert_ne!(read, 0, "manager closed before sending the request body");
            bytes.extend_from_slice(&chunk[..read]);
            let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
                .unwrap_or_default();
            if bytes.len() >= header_end + 4 + content_length {
                return String::from_utf8(bytes).expect("manager request is UTF-8");
            }
        }
    }

    fn write_http_response(stream: &mut std::net::TcpStream, status: &str, body: &str) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("write fault-server response");
    }

    fn spawn_approval_revocation_fault_server(
        listener: std::net::TcpListener,
        faults: Vec<ApprovalRevocationFault>,
        acknowledgement: ResidentApprovalReceiptRevocationAck,
    ) -> (
        Arc<AtomicUsize>,
        Arc<Mutex<Vec<String>>>,
        std::thread::JoinHandle<()>,
    ) {
        let request_count = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server_count = Arc::clone(&request_count);
        let server_requests = Arc::clone(&requests);
        let server = std::thread::spawn(move || {
            for fault in faults {
                let (mut stream, _) = listener.accept().expect("accept manager revocation");
                let request = read_complete_http_request(&mut stream);
                server_count.fetch_add(1, Ordering::SeqCst);
                server_requests
                    .lock()
                    .expect("fault requests")
                    .push(request);
                match fault {
                    ApprovalRevocationFault::ExecuteThenReset => {
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 256\r\nConnection: close\r\n\r\n{\"schema_version\":",
                            )
                            .expect("write truncated acknowledgement");
                        stream.flush().expect("flush truncated acknowledgement");
                        stream
                            .shutdown(std::net::Shutdown::Both)
                            .expect("reset fault connection");
                    }
                    ApprovalRevocationFault::PostSendTimeout => {
                        std::thread::sleep(StdDuration::from_millis(250));
                    }
                    ApprovalRevocationFault::MalformedResponse => {
                        write_http_response(&mut stream, "200 OK", "not-json");
                    }
                    ApprovalRevocationFault::OversizedResponse => {
                        write_http_response(&mut stream, "200 OK", &"x".repeat(4096));
                    }
                    ApprovalRevocationFault::WrongTargetAck => {
                        let mut wrong = acknowledgement.clone();
                        wrong.target_instance_id =
                            InstanceId::parse("00000000-0000-4000-8000-000000000999")
                                .expect("wrong target instance");
                        assert_ne!(
                            wrong.target_instance_id, acknowledgement.target_instance_id,
                            "fixture target must differ"
                        );
                        let body = serde_json::to_string(&wrong).expect("wrong ack serializes");
                        write_http_response(&mut stream, "200 OK", &body);
                    }
                    ApprovalRevocationFault::NonSuccessResponse => write_http_response(
                        &mut stream,
                        "503 Service Unavailable",
                        r#"{"code":"resident_revocation_unavailable","message":"injected fault","details":null}"#,
                    ),
                    ApprovalRevocationFault::AlreadyRevoked => {
                        let mut duplicate = acknowledgement.clone();
                        duplicate.status = ResidentApprovalReceiptRevocationStatus::AlreadyRevoked;
                        let body =
                            serde_json::to_string(&duplicate).expect("duplicate ack serializes");
                        write_http_response(&mut stream, "200 OK", &body);
                    }
                }
            }
        });
        (request_count, requests, server)
    }

    async fn grant_resident_targeted_approval(
        state: &ManagerState,
        signer: &CallerTokenSigner,
        resident_origin: &str,
        instance_id: &InstanceId,
    ) -> GovernanceApprovalRecord {
        let (headers, security) =
            approval_security(state, signer, vec![EndpointScope::ApprovalsManage]);
        let mut request = approval_request_fixture(security);
        let run_id = request.run_id.clone();
        let work_order_id = "wo-approval-revocation-fault";
        let node_id = NodeId::new();
        state
            .inner
            .dispatch_state
            .lock()
            .expect("dispatch state")
            .completed
            .insert(
                work_order_id.to_string(),
                DispatchReport {
                    work_order_id: work_order_id.to_string(),
                    selected_node_id: node_id.clone(),
                    selected_instance_id: instance_id.clone(),
                    run_id: run_id.clone(),
                    create_run_status: 201,
                    start_run_status: 200,
                    create_run_body: None,
                    start_run_body: None,
                    trace_event_id: TraceEventId::new().to_string(),
                    resident_daemon_url: resident_origin.to_string(),
                },
            );
        state
            .inner
            .dispatch_bindings
            .lock()
            .expect("dispatch bindings")
            .insert(
                work_order_id.to_string(),
                DispatchBinding {
                    work_order_payload_digest: format!("blake3:{}", "1".repeat(64)),
                    placement_decision_digest: format!("blake3:{}", "2".repeat(64)),
                    node_id,
                    instance_id: instance_id.clone(),
                    resident_daemon_url: resident_origin.to_string(),
                    resident_origin: resident_origin.to_string(),
                },
            );
        let audience = local_manager_authority_receipt_config()
            .for_resident_instance(instance_id)
            .expect("resident receipt config")
            .audience_for_run(&run_id);
        request.audience = audience.clone();
        request
            .challenge
            .as_mut()
            .expect("approval challenge")
            .receipt_audience = audience;
        let requested = request_approval(State(state.clone()), headers, Json(request))
            .await
            .expect("approval requested")
            .0;
        let (headers, security) =
            approval_security(state, signer, vec![EndpointScope::ApprovalsManage]);
        grant_approval(
            Path(requested.approval_id),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "grant before fault-server revocation".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect("approval granted")
        .0
    }

    fn revocation_acknowledgement(
        granted: &GovernanceApprovalRecord,
        instance_id: InstanceId,
        status: ResidentApprovalReceiptRevocationStatus,
    ) -> ResidentApprovalReceiptRevocationAck {
        let receipt = granted
            .authority_obligation_receipt
            .as_ref()
            .expect("granted receipt");
        ResidentApprovalReceiptRevocationAck {
            schema_version: RESIDENT_APPROVAL_RECEIPT_REVOCATION_ACK_SCHEMA_VERSION.to_string(),
            receipt_id: receipt.receipt_id.clone(),
            approval_id: granted.approval_id.clone(),
            target_instance_id: instance_id,
            run_id: granted.run_id.clone(),
            receipt_audience: receipt.audience.clone(),
            status,
            effect_certainty: splendor_types::EffectCertainty::Known,
            acknowledged_at: OffsetDateTime::now_utc(),
        }
    }

    fn assert_exact_revocation_request(request: &str, granted: &GovernanceApprovalRecord) {
        let receipt = granted
            .authority_obligation_receipt
            .as_ref()
            .expect("granted receipt");
        let expected_path = format!(
            "POST /runs/{}/approval-receipts/{}/revoke HTTP/1.1",
            granted.run_id, receipt.receipt_id
        );
        assert_eq!(request.lines().next(), Some(expected_path.as_str()));
        let body = request.split_once("\r\n\r\n").expect("HTTP request body").1;
        let revocation: ResidentApprovalReceiptRevocationRequest =
            serde_json::from_str(body).expect("typed revocation request");
        assert_eq!(revocation.authority_obligation_receipt, receipt.clone());
        assert_eq!(revocation.reason, "revoke through fault server");
    }

    fn assert_no_alternate_target_connection(listener: &std::net::TcpListener) {
        listener
            .set_nonblocking(true)
            .expect("set alternate listener nonblocking");
        let error = listener
            .accept()
            .expect_err("manager must not retarget revocation");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }

    async fn revoke_through_fault_server(
        state: &ManagerState,
        signer: &CallerTokenSigner,
        approval_id: ApprovalId,
    ) -> Result<Json<GovernanceApprovalRecord>, ManagerApiError> {
        let (headers, security) =
            approval_security(state, signer, vec![EndpointScope::ApprovalsManage]);
        revoke_approval(
            Path(approval_id),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "revoke through fault server".to_string(),
                expires_at: None,
            }),
        )
        .await
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

    fn task_request_send_request(
        credential: CallerCredential,
        target_agent: &str,
        run_id: RunId,
        message_id: &str,
        child_run_id: &str,
        idempotency_key: &str,
        delegated_authority: serde_json::Value,
    ) -> SendMessageRequest {
        serde_json::from_value(serde_json::json!({
            "credential": credential,
            "audit_attribution": audit_for(&credential),
            "work_order_id": "wo_test_remote",
            "message_envelope": {
                "message": {
                    "message_id": message_id,
                    "source_agent_id": "22222222-2222-4222-8222-222222222222",
                    "target_agent_id": target_agent,
                    "run_id": run_id,
                    "schema": TASK_REQUEST_SCHEMA,
                    "payload": {
                        "parent_run_id": run_id,
                        "child_run_id": child_run_id,
                        "target_agent_id": target_agent,
                        "objective": "scoped task request",
                        "delegated_authority": delegated_authority,
                        "capability_grant_id": "77777777-7777-4777-8777-777777777777"
                    },
                    "causal_parent": null,
                    "requires_response": true,
                    "created_at": now_rfc3339()
                },
                "schema_version": "v2",
                "delivery_status": "pending",
                "trace_links": {}
            },
            "source_instance_id": "00000000-0000-4000-8000-000000000302",
            "target_instance_id": "00000000-0000-4000-8000-000000000304",
            "idempotency_key": idempotency_key,
            "simulate_failure": null
        }))
        .expect("task request send request")
    }

    async fn manager_call<T: serde::de::DeserializeOwned>(
        app: Router,
        method: Method,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, T) {
        manager_call_with_headers(app, method, uri, body, HeaderMap::new()).await
    }

    async fn manager_call_with_headers<T: serde::de::DeserializeOwned>(
        app: Router,
        method: Method,
        uri: &str,
        body: Option<serde_json::Value>,
        headers: HeaderMap,
    ) -> (StatusCode, T) {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            if let Some(name) = name {
                builder = builder.header(name, value);
            }
        }
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

    #[tokio::test]
    async fn approval_endpoints_require_verified_one_use_manager_bearer_before_mutation() {
        let no_verifier = manager_with_allowed_origins(Vec::new());
        let missing_verifier_payload = approval_request_fixture(manager_security(
            &no_verifier,
            vec![EndpointScope::ApprovalsManage],
        ));
        let (status, error): (StatusCode, ManagerApiErrorBody) = manager_call(
            router(no_verifier.clone()),
            Method::POST,
            "/approvals",
            Some(serde_json::to_value(missing_verifier_payload).expect("request JSON")),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, "manager_approval_caller_verifier_unavailable");
        assert!(no_verifier
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .is_empty());
        assert!(no_verifier.inner.audit.lock().expect("audit").is_empty());

        let (state, signer) = manager_with_approval_auth(Vec::new());
        let app = router(state.clone());

        let (_unused_headers, missing_token_security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let missing_token_payload = approval_request_fixture(missing_token_security);
        let (status, _): (StatusCode, ManagerApiErrorBody) = manager_call(
            app.clone(),
            Method::POST,
            "/approvals",
            Some(serde_json::to_value(missing_token_payload).expect("request JSON")),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(state.inner.approvals.lock().expect("approvals").is_empty());
        assert!(state.inner.audit.lock().expect("audit").is_empty());

        let forged_signer = CallerTokenSigner::generate_for_test(
            signer.issuer(),
            signer.app_principal_id(),
            "forged-approval-client",
            "forged-approval-key",
        )
        .expect("forged signer");
        let (forged_headers, forged_security) =
            approval_security(&state, &forged_signer, vec![EndpointScope::ApprovalsManage]);
        let forged_payload = approval_request_fixture(forged_security);
        let (status, _): (StatusCode, ManagerApiErrorBody) = manager_call_with_headers(
            app.clone(),
            Method::POST,
            "/approvals",
            Some(serde_json::to_value(forged_payload).expect("request JSON")),
            forged_headers,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(state.inner.approvals.lock().expect("approvals").is_empty());
        assert!(state.inner.audit.lock().expect("audit").is_empty());

        let (broad_headers, broad_security) = approval_security(
            &state,
            &signer,
            vec![EndpointScope::ApprovalsManage, EndpointScope::FleetRead],
        );
        let broad_payload = approval_request_fixture(broad_security);
        let (status, error): (StatusCode, ManagerApiErrorBody) = manager_call_with_headers(
            app.clone(),
            Method::POST,
            "/approvals",
            Some(serde_json::to_value(broad_payload).expect("request JSON")),
            broad_headers,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(error.code, "approval_caller_scope_mismatch");
        assert!(state.inner.approvals.lock().expect("approvals").is_empty());
        assert!(state.inner.audit.lock().expect("audit").is_empty());

        let (mismatch_headers, mismatch_security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let mut mismatch_payload = approval_request_fixture(mismatch_security);
        mismatch_payload.security.credential.credential_id = format!("sha256:{}", "0".repeat(64));
        mismatch_payload.security.audit_attribution.credential_id =
            Some(mismatch_payload.security.credential.credential_id.clone());
        let (status, error): (StatusCode, ManagerApiErrorBody) = manager_call_with_headers(
            app.clone(),
            Method::POST,
            "/approvals",
            Some(serde_json::to_value(mismatch_payload).expect("request JSON")),
            mismatch_headers,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(error.code, "caller_credential_mirror_mismatch");
        assert!(state.inner.approvals.lock().expect("approvals").is_empty());
        assert!(state.inner.audit.lock().expect("audit").is_empty());

        let (request_headers, request_security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let request_payload =
            serde_json::to_value(approval_request_fixture(request_security)).expect("request JSON");
        let (status, requested): (StatusCode, GovernanceApprovalRecord) =
            manager_call_with_headers(
                app.clone(),
                Method::POST,
                "/approvals",
                Some(request_payload.clone()),
                request_headers.clone(),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(requested.status, "requested");
        assert_eq!(requested.issued_by, requested.requested_by);
        assert!(requested.decided_by.is_none());
        assert_eq!(state.inner.approvals.lock().expect("approvals").len(), 1);
        assert_eq!(state.inner.audit.lock().expect("audit").len(), 1);

        let (status, replay_error): (StatusCode, ManagerApiErrorBody) = manager_call_with_headers(
            app.clone(),
            Method::POST,
            "/approvals",
            Some(request_payload),
            request_headers,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(replay_error.code, "manager_caller_token_replayed");
        assert_eq!(state.inner.approvals.lock().expect("approvals").len(), 1);
        assert_eq!(state.inner.audit.lock().expect("audit").len(), 1);

        let (grant_headers, grant_security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let grant_payload = serde_json::to_value(ApprovalDecisionRequest {
            security: grant_security,
            reason: "approved through verified manager caller".to_string(),
            expires_at: None,
        })
        .expect("grant JSON");
        let grant_path = format!("/approvals/{}/grant", requested.approval_id);
        let (status, granted): (StatusCode, GovernanceApprovalRecord) = manager_call_with_headers(
            app.clone(),
            Method::POST,
            &grant_path,
            Some(grant_payload.clone()),
            grant_headers.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(granted.status, "granted");
        assert!(granted.authority_obligation_receipt.is_some());
        assert_eq!(granted.requested_by, requested.requested_by);
        assert!(granted.decided_by.is_some());
        assert_eq!(state.inner.audit.lock().expect("audit").len(), 2);
        for event in state.inner.audit.lock().expect("audit").iter() {
            let rendered = serde_json::to_string(&event.details).expect("audit details JSON");
            assert!(rendered.contains("credential_correlation"));
            assert!(!rendered.contains("Bearer "));
            assert!(!rendered.contains("\"jti\""));
        }
        let receipt = granted.authority_obligation_receipt.clone();

        let (status, replay_error): (StatusCode, ManagerApiErrorBody) = manager_call_with_headers(
            app,
            Method::POST,
            &grant_path,
            Some(grant_payload),
            grant_headers,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(replay_error.code, "manager_caller_token_replayed");
        assert_eq!(state.inner.audit.lock().expect("audit").len(), 2);
        let stored = state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .get(&requested.approval_id.to_string())
            .cloned()
            .expect("stored approval");
        assert_eq!(stored.status, "granted");
        assert_eq!(stored.authority_obligation_receipt, receipt);
    }

    #[tokio::test]
    async fn approval_request_risk_is_optional_and_must_match_challenge_exactly() {
        let (state, signer) = manager_with_approval_auth(Vec::new());
        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let mut payload = approval_request_fixture(security);
        payload.risk_level = None;
        payload.challenge.as_mut().expect("challenge").risk_level = None;

        let requested = request_approval(State(state), headers, Json(payload))
            .await
            .expect("risk-less approval request")
            .0;
        assert_eq!(requested.risk_level, None);
        assert_eq!(requested.challenge.expect("challenge").risk_level, None);
    }

    #[test]
    fn manager_approval_auth_helpers_reject_malformed_bearers_and_map_all_failures() {
        let mut missing = HeaderMap::new();
        assert_eq!(
            manager_bearer_token(&missing)
                .expect_err("missing bearer")
                .body
                .code,
            "missing_manager_caller_token"
        );
        missing.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer first"),
        );
        missing.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second"),
        );
        assert_eq!(
            manager_bearer_token(&missing)
                .expect_err("duplicate bearer")
                .body
                .code,
            "invalid_manager_caller_token"
        );
        for raw in ["Basic token", "Bearer", "Bearer token with-space"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(raw).expect("header"),
            );
            assert_eq!(
                manager_bearer_token(&headers)
                    .expect_err("malformed bearer")
                    .body
                    .code,
                "invalid_manager_caller_token"
            );
        }

        for (error, expected) in [
            (
                CallerAuthError::MissingToken,
                "missing_manager_caller_token",
            ),
            (
                CallerAuthError::MalformedToken,
                "invalid_manager_caller_token",
            ),
            (
                CallerAuthError::UnsupportedProfile,
                "unsupported_manager_caller_token_profile",
            ),
            (
                CallerAuthError::UntrustedKey,
                "untrusted_manager_caller_token_key",
            ),
            (
                CallerAuthError::InvalidSignature,
                "invalid_manager_caller_token_signature",
            ),
            (
                CallerAuthError::WrongIssuer,
                "wrong_manager_caller_token_issuer",
            ),
            (
                CallerAuthError::WrongAudience,
                "wrong_manager_caller_token_audience",
            ),
            (
                CallerAuthError::WrongSubject,
                "wrong_manager_caller_token_subject",
            ),
            (
                CallerAuthError::InvalidLifetime,
                "invalid_manager_caller_token_lifetime",
            ),
            (
                CallerAuthError::InvalidScope,
                "invalid_manager_caller_token_scope",
            ),
            (
                CallerAuthError::InvalidTenant,
                "invalid_manager_caller_token_binding",
            ),
            (
                CallerAuthError::InvalidFleet,
                "invalid_manager_caller_token_binding",
            ),
            (
                CallerAuthError::InvalidBinding,
                "invalid_manager_caller_token_binding",
            ),
            (
                CallerAuthError::RevokedToken,
                "revoked_manager_caller_token",
            ),
            (
                CallerAuthError::ReplayedToken,
                "manager_caller_token_replayed",
            ),
            (
                CallerAuthError::InvalidTrustSnapshot,
                "manager_caller_auth_unavailable",
            ),
            (
                CallerAuthError::ClockRollback,
                "manager_caller_auth_unavailable",
            ),
            (
                CallerAuthError::InvalidSigner,
                "manager_caller_auth_unavailable",
            ),
            (CallerAuthError::KeyLoad, "manager_caller_auth_unavailable"),
        ] {
            assert_eq!(manager_caller_auth_error(error).body.code, expected);
        }

        let mut audit = audit_for(&credential(
            FleetId::new(),
            vec![EndpointScope::ApprovalsManage],
        ));
        audit.credential_id = Some("raw-credential-id".to_string());
        assert!(safe_approval_actor(&audit)["credential_correlation"].is_null());

        let (state, signer) = manager_with_approval_auth(Vec::new());
        let (headers, mut security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        security.audit_attribution.principal.client_principal_id = "different-client".to_string();
        assert_eq!(
            state
                .verify_approval_caller(&headers, &security)
                .expect_err("audit mirror mismatch")
                .body
                .code,
            "caller_audit_mirror_mismatch"
        );
    }

    #[test]
    fn approval_receipt_revocation_errors_expose_structured_effect_certainty() {
        for (error, outcome, certainty) in [
            (approval_receipt_revocation_too_late(), "too_late", "known"),
            (
                approval_receipt_revocation_transport_failed(
                    "resident revocation was not delivered",
                ),
                "transport_failed",
                "known",
            ),
            (
                approval_receipt_revocation_effect_unknown(
                    "resident revocation may have been applied",
                ),
                "effect_unknown",
                "unknown",
            ),
        ] {
            let details = error.body.details.expect("structured outcome details");
            assert_eq!(details["outcome"], outcome);
            assert_eq!(details["effect_certainty"], certainty);
            assert_ne!(error.status, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn approval_revocation_handler_faults_remain_granted_and_effect_unknown_without_retarget()
    {
        for (case, fault) in [
            (
                "execute_then_reset",
                ApprovalRevocationFault::ExecuteThenReset,
            ),
            (
                "post_send_timeout",
                ApprovalRevocationFault::PostSendTimeout,
            ),
            (
                "malformed_response",
                ApprovalRevocationFault::MalformedResponse,
            ),
            (
                "oversized_response",
                ApprovalRevocationFault::OversizedResponse,
            ),
            ("wrong_target_ack", ApprovalRevocationFault::WrongTargetAck),
            (
                "non_success_response",
                ApprovalRevocationFault::NonSuccessResponse,
            ),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fault resident");
            let resident_origin = format!(
                "http://{}",
                listener.local_addr().expect("fault resident address")
            );
            let alternate_listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind alternate resident");
            let alternate_origin = format!(
                "http://{}",
                alternate_listener
                    .local_addr()
                    .expect("alternate resident address")
            );
            let mut options = ResidentDispatchOptions::loopback_test();
            options.start_timeout = StdDuration::from_millis(75);
            options.maximum_response_bytes = 2048;
            options.allowed_origins = vec![resident_origin.clone(), alternate_origin];
            let (state, signer) = manager_with_approval_auth_options(options);
            let instance_id = InstanceId::parse("00000000-0000-4000-8000-000000000101")
                .expect("fault target instance");
            let granted =
                grant_resident_targeted_approval(&state, &signer, &resident_origin, &instance_id)
                    .await;
            let acknowledgement = revocation_acknowledgement(
                &granted,
                instance_id,
                ResidentApprovalReceiptRevocationStatus::Revoked,
            );
            let (request_count, requests, server) =
                spawn_approval_revocation_fault_server(listener, vec![fault], acknowledgement);
            let audit_count = state.inner.audit.lock().expect("audit").len();
            let error =
                match revoke_through_fault_server(&state, &signer, granted.approval_id.clone())
                    .await
                {
                    Err(error) => error,
                    Ok(_) => panic!("fault reported revocation success: {case}"),
                };

            assert_eq!(error.status, StatusCode::GATEWAY_TIMEOUT, "case={case}");
            assert_eq!(
                error.body.code, "approval_receipt_revocation_effect_unknown",
                "case={case}"
            );
            let details = error.body.details.expect("structured uncertainty");
            assert_eq!(details["outcome"], "effect_unknown", "case={case}");
            assert_eq!(details["effect_certainty"], "unknown", "case={case}");
            assert!(details["revocation_applied"].is_null(), "case={case}");
            server.join().expect("fault server");
            assert_eq!(request_count.load(Ordering::SeqCst), 1, "case={case}");
            let requests = requests.lock().expect("fault requests");
            assert_eq!(requests.len(), 1, "case={case}");
            assert_exact_revocation_request(&requests[0], &granted);
            drop(requests);

            let retained = state
                .inner
                .approvals
                .lock()
                .expect("approvals")
                .get(&granted.approval_id.to_string())
                .cloned()
                .expect("retained approval");
            assert_eq!(retained.status, "granted", "case={case}");
            assert!(
                retained.resident_receipt_revocation_ack.is_none(),
                "case={case}"
            );
            let audit = state.inner.audit.lock().expect("audit");
            assert_eq!(audit.len(), audit_count, "case={case}");
            assert!(
                !audit
                    .iter()
                    .any(|event| event.event_type == "approval.revoked"),
                "case={case}"
            );
            drop(audit);
            assert_no_alternate_target_connection(&alternate_listener);
        }
    }

    #[tokio::test]
    async fn approval_revocation_handler_same_target_retry_converges_via_already_revoked() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind retry resident");
        let resident_origin = format!(
            "http://{}",
            listener.local_addr().expect("retry resident address")
        );
        let alternate_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind alternate resident");
        let alternate_origin = format!(
            "http://{}",
            alternate_listener
                .local_addr()
                .expect("alternate resident address")
        );
        let mut options = ResidentDispatchOptions::loopback_test();
        options.start_timeout = StdDuration::from_millis(75);
        options.maximum_response_bytes = 2048;
        options.allowed_origins = vec![resident_origin.clone(), alternate_origin];
        let (state, signer) = manager_with_approval_auth_options(options);
        let instance_id = InstanceId::parse("00000000-0000-4000-8000-000000000102")
            .expect("retry target instance");
        let granted =
            grant_resident_targeted_approval(&state, &signer, &resident_origin, &instance_id).await;
        let acknowledgement = revocation_acknowledgement(
            &granted,
            instance_id,
            ResidentApprovalReceiptRevocationStatus::Revoked,
        );
        let (request_count, requests, server) = spawn_approval_revocation_fault_server(
            listener,
            vec![
                ApprovalRevocationFault::ExecuteThenReset,
                ApprovalRevocationFault::AlreadyRevoked,
            ],
            acknowledgement,
        );
        let audit_count = state.inner.audit.lock().expect("audit").len();
        let uncertain = revoke_through_fault_server(&state, &signer, granted.approval_id.clone())
            .await
            .expect_err("truncated first acknowledgement is uncertain");
        assert_eq!(
            uncertain.body.code,
            "approval_receipt_revocation_effect_unknown"
        );
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            state
                .inner
                .approvals
                .lock()
                .expect("approvals")
                .get(&granted.approval_id.to_string())
                .expect("approval")
                .status,
            "granted"
        );
        assert_eq!(state.inner.audit.lock().expect("audit").len(), audit_count);

        let retried = revoke_through_fault_server(&state, &signer, granted.approval_id.clone())
            .await
            .expect("explicit same-target retry observes already_revoked")
            .0;
        server.join().expect("retry fault server");
        assert_eq!(retried.status, "revoked");
        assert_eq!(
            retried
                .resident_receipt_revocation_ack
                .as_ref()
                .map(|ack| ack.status),
            Some(ResidentApprovalReceiptRevocationStatus::AlreadyRevoked)
        );
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
        let requests = requests.lock().expect("retry requests");
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            assert_exact_revocation_request(request, &granted);
        }
        let authorization = requests
            .iter()
            .map(|request| {
                request
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                    .expect("outbound authorization header")
            })
            .collect::<Vec<_>>();
        assert_ne!(
            authorization[0], authorization[1],
            "explicit retry must use a fresh exact-target JTI"
        );
        drop(requests);
        let audit = state.inner.audit.lock().expect("audit");
        assert_eq!(audit.len(), audit_count + 1);
        assert_eq!(
            audit.last().expect("revocation audit").event_type,
            "approval.revoked"
        );
        drop(audit);
        assert_no_alternate_target_connection(&alternate_listener);
    }

    #[tokio::test]
    async fn acknowledged_revocation_retry_converges_after_audit_failure_without_partial_state() {
        let (state, signer) = manager_with_approval_auth(Vec::new());
        let (request_headers, request_security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let requested = request_approval(
            State(state.clone()),
            request_headers,
            Json(approval_request_fixture(request_security)),
        )
        .await
        .expect("approval requested")
        .0;
        let (grant_headers, grant_security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let granted = grant_approval(
            Path(requested.approval_id.clone()),
            State(state.clone()),
            grant_headers,
            Json(ApprovalDecisionRequest {
                security: grant_security.clone(),
                reason: "grant before revocation".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect("approval granted")
        .0;
        let receipt = granted
            .authority_obligation_receipt
            .clone()
            .expect("granted receipt");
        let target = ApprovalResidentTarget {
            instance_id: InstanceId::new(),
            run_id: granted.run_id.clone(),
            resident_daemon_url: "http://127.0.0.1:1".to_string(),
            resident_origin: "http://127.0.0.1:1".to_string(),
        };
        let completion = AcknowledgedApprovalRevocation {
            approval_id: granted.approval_id.clone(),
            record: granted.clone(),
            receipt: receipt.clone(),
            acknowledgement: ResidentApprovalReceiptRevocationAck {
                schema_version: RESIDENT_APPROVAL_RECEIPT_REVOCATION_ACK_SCHEMA_VERSION.to_string(),
                receipt_id: receipt.receipt_id,
                approval_id: granted.approval_id.clone(),
                target_instance_id: target.instance_id.clone(),
                run_id: target.run_id.clone(),
                receipt_audience: receipt.audience,
                status: ResidentApprovalReceiptRevocationStatus::AlreadyRevoked,
                effect_certainty: splendor_types::EffectCertainty::Known,
                acknowledged_at: OffsetDateTime::now_utc(),
            },
            target,
            reason: "retry exact resident revocation".to_string(),
            decided_by: grant_security.audit_attribution,
        };

        let error = complete_acknowledged_approval_revocation_with_audit(
            &state,
            &completion,
            |_event, _details| {
                Err(ManagerApiError::internal(
                    "audit_lock",
                    "injected audit failure",
                ))
            },
        )
        .expect_err("audit failure leaves manager state uncommitted");
        assert_eq!(error.body.code, "audit_lock");
        assert_eq!(
            state
                .inner
                .approvals
                .lock()
                .expect("approvals")
                .get(&completion.approval_id.to_string())
                .expect("approval")
                .status,
            "granted"
        );

        let removed = state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .remove(&completion.approval_id.to_string())
            .expect("approval before disappearance injection");
        let disappeared = complete_acknowledged_approval_revocation_with_audit(
            &state,
            &completion,
            |_event, _details| Ok("must-not-audit-disappeared-state".to_string()),
        )
        .expect_err("resident acknowledgement cannot recreate missing manager state");
        assert_eq!(disappeared.body.code, "approval_state_unavailable");
        state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .insert(completion.approval_id.to_string(), removed);

        state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .get_mut(&completion.approval_id.to_string())
            .expect("approval")
            .status = "denied".to_string();
        let raced = complete_acknowledged_approval_revocation_with_audit(
            &state,
            &completion,
            |_event, _details| Ok("must-not-audit-raced-state".to_string()),
        )
        .expect_err("concurrent terminal mutation wins over stale acknowledgement");
        assert_eq!(raced.body.code, "approval_state_conflict");
        state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .get_mut(&completion.approval_id.to_string())
            .expect("approval")
            .status = "granted".to_string();

        let retried = complete_acknowledged_approval_revocation_with_audit(
            &state,
            &completion,
            |_event, _details| Ok("audit-retry-success".to_string()),
        )
        .expect("same acknowledged completion retry converges");
        assert_eq!(retried.status, "revoked");
        assert_eq!(retried.trace_event_id, "audit-retry-success");
        assert_eq!(
            retried
                .resident_receipt_revocation_ack
                .as_ref()
                .map(|ack| ack.status),
            Some(ResidentApprovalReceiptRevocationStatus::AlreadyRevoked)
        );
        assert_eq!(
            state
                .inner
                .approvals
                .lock()
                .expect("approvals")
                .get(&completion.approval_id.to_string())
                .expect("approval")
                .status,
            "revoked"
        );

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let exact_retry = revoke_approval(
            Path(completion.approval_id.clone()),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: completion.reason.clone(),
                expires_at: None,
            }),
        )
        .await
        .expect("exact acknowledged revocation retry is idempotent")
        .0;
        assert_eq!(exact_retry.trace_event_id, "audit-retry-success");

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let conflict = revoke_approval(
            Path(completion.approval_id.clone()),
            State(state),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "changed revocation coordinates".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("acknowledged revocation coordinates are immutable");
        assert_eq!(conflict.body.code, "approval_decision_conflict");
    }

    #[tokio::test]
    async fn requested_approval_revocation_is_terminal_without_resident_egress() {
        let (state, signer) = manager_with_approval_auth(Vec::new());
        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let requested = request_approval(
            State(state.clone()),
            headers,
            Json(approval_request_fixture(security)),
        )
        .await
        .expect("approval requested")
        .0;

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let revoked = revoke_approval(
            Path(requested.approval_id.clone()),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "withdraw before grant".to_string(),
                expires_at: Some(requested.expires_at - Duration::seconds(1)),
            }),
        )
        .await
        .expect("ungranted request revokes locally")
        .0;

        assert_eq!(revoked.status, "revoked");
        assert!(revoked
            .evidence
            .as_ref()
            .is_some_and(|evidence| evidence.revoked));
        assert!(revoked.authority_obligation_receipt.is_none());
        assert!(revoked.resident_receipt_revocation_ack.is_none());
        assert!(state
            .inner
            .approval_resident_targets
            .lock()
            .expect("targets")
            .is_empty());
        assert_eq!(
            state
                .inner
                .audit
                .lock()
                .expect("audit")
                .last()
                .expect("revocation audit")
                .details["resident_receipt_revocation_required"],
            false
        );

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let conflict = revoke_approval(
            Path(requested.approval_id),
            State(state),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "withdraw before grant".to_string(),
                expires_at: Some(revoked.expires_at),
            }),
        )
        .await
        .expect_err("local pre-grant revocation has no resident acknowledgement to replay");
        assert_eq!(conflict.body.code, "approval_decision_conflict");
    }

    #[tokio::test]
    async fn granted_revocation_rejects_changed_or_missing_immutable_resident_coordinates() {
        let resident_origin = "http://127.0.0.1:1";
        let (state, signer) = manager_with_approval_auth(vec![resident_origin.to_string()]);
        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let requested = request_approval(
            State(state.clone()),
            headers,
            Json(approval_request_fixture(security)),
        )
        .await
        .expect("approval requested")
        .0;
        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let granted = grant_approval(
            Path(requested.approval_id.clone()),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "grant before immutable target checks".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect("approval granted")
        .0;

        async fn attempt(
            state: &ManagerState,
            signer: &CallerTokenSigner,
            approval_id: ApprovalId,
            expires_at: Option<OffsetDateTime>,
        ) -> ManagerApiError {
            let (headers, security) =
                approval_security(state, signer, vec![EndpointScope::ApprovalsManage]);
            revoke_approval(
                Path(approval_id),
                State(state.clone()),
                headers,
                Json(ApprovalDecisionRequest {
                    security,
                    reason: "revoke exact grant".to_string(),
                    expires_at,
                }),
            )
            .await
            .expect_err("revocation attempt must fail closed")
        }

        let changed_expiry = attempt(
            &state,
            &signer,
            granted.approval_id.clone(),
            Some(granted.expires_at + Duration::seconds(1)),
        )
        .await;
        assert_eq!(
            changed_expiry.body.code,
            "approval_challenge_expiry_mismatch"
        );

        let retained_receipt = {
            let mut approvals = state.inner.approvals.lock().expect("approvals");
            approvals
                .get_mut(&granted.approval_id.to_string())
                .expect("approval")
                .authority_obligation_receipt
                .take()
                .expect("retained receipt")
        };
        let missing_receipt = attempt(&state, &signer, granted.approval_id.clone(), None).await;
        assert_eq!(
            missing_receipt.body.code,
            "approval_obligation_receipt_unavailable"
        );
        state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .get_mut(&granted.approval_id.to_string())
            .expect("approval")
            .authority_obligation_receipt = Some(retained_receipt);

        let missing_target = attempt(&state, &signer, granted.approval_id.clone(), None).await;
        assert_eq!(
            missing_target.body.code,
            "approval_resident_target_unavailable"
        );

        let target = ApprovalResidentTarget {
            instance_id: InstanceId::new(),
            run_id: RunId::new(),
            resident_daemon_url: resident_origin.to_string(),
            resident_origin: resident_origin.to_string(),
        };
        state
            .inner
            .approval_resident_targets
            .lock()
            .expect("targets")
            .insert(granted.approval_id.to_string(), target.clone());
        let wrong_run = attempt(&state, &signer, granted.approval_id.clone(), None).await;
        assert_eq!(wrong_run.body.code, "approval_resident_target_mismatch");

        {
            let mut targets = state
                .inner
                .approval_resident_targets
                .lock()
                .expect("targets");
            let target = targets
                .get_mut(&granted.approval_id.to_string())
                .expect("target");
            target.run_id = granted.run_id.clone();
            target.resident_daemon_url = "https://resident-not-allowlisted.invalid".to_string();
            target.resident_origin = "https://resident-not-allowlisted.invalid".to_string();
        }
        let invalid_origin = attempt(&state, &signer, granted.approval_id.clone(), None).await;
        assert_eq!(
            invalid_origin.body.code,
            "approval_receipt_revocation_transport_failed"
        );

        {
            let mut targets = state
                .inner
                .approval_resident_targets
                .lock()
                .expect("targets");
            let target = targets
                .get_mut(&granted.approval_id.to_string())
                .expect("target");
            target.resident_daemon_url = resident_origin.to_string();
            target.resident_origin = "http://127.0.0.1:2".to_string();
        }
        let changed_origin = attempt(&state, &signer, granted.approval_id.clone(), None).await;
        assert_eq!(
            changed_origin.body.code,
            "approval_receipt_revocation_transport_failed"
        );

        state
            .inner
            .approval_resident_targets
            .lock()
            .expect("targets")
            .get_mut(&granted.approval_id.to_string())
            .expect("target")
            .resident_origin = resident_origin.to_string();
        let transport_failure = attempt(&state, &signer, granted.approval_id.clone(), None).await;
        assert_eq!(
            transport_failure.body.code,
            "approval_receipt_revocation_transport_failed"
        );
        assert_eq!(
            state
                .inner
                .approvals
                .lock()
                .expect("approvals")
                .get(&granted.approval_id.to_string())
                .expect("approval")
                .status,
            "granted"
        );
    }

    #[test]
    fn resident_approval_target_resolution_rejects_ambiguous_or_mutated_dispatch_state() {
        let state = manager_with_allowed_origins(vec!["http://127.0.0.1:1".to_string()]);
        let run_id = RunId::new();
        let instance_id = InstanceId::new();
        let node_id = NodeId::new();
        let report = |work_order_id: &str| DispatchReport {
            work_order_id: work_order_id.to_string(),
            selected_node_id: node_id.clone(),
            selected_instance_id: instance_id.clone(),
            run_id: run_id.clone(),
            create_run_status: 201,
            start_run_status: 200,
            create_run_body: None,
            start_run_body: None,
            trace_event_id: TraceEventId::new().to_string(),
            resident_daemon_url: "http://127.0.0.1:1".to_string(),
        };
        {
            let mut dispatch = state.inner.dispatch_state.lock().expect("dispatch state");
            dispatch
                .completed
                .insert("wo-target-a".to_string(), report("wo-target-a"));
            dispatch
                .completed
                .insert("wo-target-b".to_string(), report("wo-target-b"));
        }
        let ambiguous = approval_resident_target_for_run(&state, &run_id)
            .expect_err("multiple completed targets are ambiguous");
        assert_eq!(ambiguous.body.code, "approval_resident_target_ambiguous");

        state
            .inner
            .dispatch_state
            .lock()
            .expect("dispatch state")
            .completed
            .remove("wo-target-b");
        let missing = approval_resident_target_for_run(&state, &run_id)
            .expect_err("completed dispatch requires its immutable binding");
        assert_eq!(missing.body.code, "approval_resident_target_unavailable");

        let mut binding = DispatchBinding {
            work_order_payload_digest: format!("blake3:{}", "1".repeat(64)),
            placement_decision_digest: format!("blake3:{}", "2".repeat(64)),
            node_id,
            instance_id: InstanceId::new(),
            resident_daemon_url: "http://127.0.0.1:1".to_string(),
            resident_origin: "http://127.0.0.1:1".to_string(),
        };
        state
            .inner
            .dispatch_bindings
            .lock()
            .expect("bindings")
            .insert("wo-target-a".to_string(), binding.clone());
        let mismatch = approval_resident_target_for_run(&state, &run_id)
            .expect_err("dispatch report cannot substitute a different instance");
        assert_eq!(mismatch.body.code, "approval_resident_target_mismatch");

        binding.instance_id = instance_id.clone();
        state
            .inner
            .dispatch_bindings
            .lock()
            .expect("bindings")
            .insert("wo-target-a".to_string(), binding);
        let exact = approval_resident_target_for_run(&state, &run_id)
            .expect("exact dispatch target")
            .expect("resident target");
        assert_eq!(exact.instance_id, instance_id);
        assert_eq!(exact.run_id, run_id);

        let nil_instance = InstanceId::parse("00000000-0000-0000-0000-000000000000")
            .expect("nil instance parses for validation");
        let invalid_target = ApprovalResidentTarget {
            instance_id: nil_instance,
            run_id: RunId::new(),
            resident_daemon_url: "http://127.0.0.1:1".to_string(),
            resident_origin: "http://127.0.0.1:1".to_string(),
        };
        let error = receipt_config_for_approval_target(
            state
                .inner
                .authority_obligation_receipt_config
                .as_ref()
                .expect("receipt config"),
            Some(&invalid_target),
        )
        .expect_err("nil immutable instance identity fails closed");
        assert_eq!(
            error.body.code,
            "obligation_receipt_resident_instance_invalid"
        );
    }

    #[tokio::test]
    async fn approval_state_machine_fail_closed_branches_are_explicit() {
        let (state, signer) = manager_with_approval_auth(Vec::new());
        let no_receipt_state = ManagerState::acceptance_with_dispatch_config_internal(
            state.inner.manager_id.clone(),
            state.inner.fleet_id.clone(),
            state.inner.work_order_keyring.clone(),
            state.inner.resident_dispatch.signer.clone(),
            ResidentDispatchOptions::loopback_test(),
            None,
            state.inner.approval_caller_verifier.clone(),
        )
        .expect("approval-authenticated manager without receipt config");

        let (headers, security) = approval_security(
            &no_receipt_state,
            &signer,
            vec![EndpointScope::ApprovalsManage],
        );
        let error = request_approval(
            State(no_receipt_state.clone()),
            headers,
            Json(approval_request_fixture(security)),
        )
        .await
        .expect_err("receipt configuration required before approval request");
        assert_eq!(
            error.body.code,
            "authority_obligation_receipt_config_unavailable"
        );

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let mut missing_challenge = approval_request_fixture(security);
        missing_challenge.challenge = None;
        let error = request_approval(State(state.clone()), headers, Json(missing_challenge))
            .await
            .expect_err("challenge required");
        assert_eq!(error.body.code, "approval_challenge_required");

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let mut mismatch = approval_request_fixture(security);
        mismatch.risk_level = None;
        let error = request_approval(State(state.clone()), headers, Json(mismatch))
            .await
            .expect_err("risk mismatch rejected");
        assert_eq!(error.body.code, "approval_challenge_mismatch");

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let mut expired = approval_request_fixture(security);
        let expired_at = OffsetDateTime::now_utc() - Duration::seconds(1);
        expired.expires_at = expired_at;
        expired.challenge.as_mut().expect("challenge").expires_at = expired_at;
        let error = request_approval(State(state.clone()), headers, Json(expired))
            .await
            .expect_err("expired challenge rejected");
        assert_eq!(error.body.code, "approval_challenge_expired_or_future");

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let payload = approval_request_fixture(security);
        let requested = request_approval(State(state.clone()), headers, Json(payload.clone()))
            .await
            .expect("valid request")
            .0;

        no_receipt_state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .insert(requested.approval_id.to_string(), requested.clone());
        let (headers, security) = approval_security(
            &no_receipt_state,
            &signer,
            vec![EndpointScope::ApprovalsManage],
        );
        let error = grant_approval(
            Path(requested.approval_id.clone()),
            State(no_receipt_state),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "grant".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("receipt configuration required before approval grant");
        assert_eq!(
            error.body.code,
            "authority_obligation_receipt_config_unavailable"
        );

        {
            let mut approvals = state.inner.approvals.lock().expect("approvals");
            approvals
                .get_mut(&requested.approval_id.to_string())
                .expect("record")
                .status = "denied".to_string();
        }
        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let mut terminal_retry = payload.clone();
        terminal_retry.security = security;
        let error = request_approval(State(state.clone()), headers, Json(terminal_retry))
            .await
            .expect_err("terminal request immutable");
        assert_eq!(error.body.code, "approval_terminal_conflict");

        {
            let mut approvals = state.inner.approvals.lock().expect("approvals");
            let record = approvals
                .get_mut(&requested.approval_id.to_string())
                .expect("record");
            record.status = "requested".to_string();
            record.challenge = None;
        }
        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let error = grant_approval(
            Path(requested.approval_id.clone()),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "grant".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("challenge-less record rejected");
        assert_eq!(error.body.code, "approval_challenge_required");

        {
            let mut approvals = state.inner.approvals.lock().expect("approvals");
            let record = approvals
                .get_mut(&requested.approval_id.to_string())
                .expect("record");
            record.challenge = requested.challenge.clone();
            record.status = "paused".to_string();
        }
        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let error = grant_approval(
            Path(requested.approval_id.clone()),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "grant".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("non-grantable state rejected");
        assert_eq!(error.body.code, "approval_state_conflict");

        state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .get_mut(&requested.approval_id.to_string())
            .expect("record")
            .status = "requested".to_string();
        {
            let mut approvals = state.inner.approvals.lock().expect("approvals");
            approvals
                .get_mut(&requested.approval_id.to_string())
                .expect("record")
                .challenge
                .as_mut()
                .expect("challenge")
                .expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);
        }
        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let error = grant_approval(
            Path(requested.approval_id.clone()),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "grant".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("expired stored challenge rejected");
        assert_eq!(error.body.code, "approval_challenge_expired_or_future");
        state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .get_mut(&requested.approval_id.to_string())
            .expect("record")
            .challenge = requested.challenge.clone();

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let error = grant_approval(
            Path(requested.approval_id.clone()),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "grant".to_string(),
                expires_at: Some(requested.expires_at + Duration::seconds(1)),
            }),
        )
        .await
        .expect_err("changed expiry rejected");
        assert_eq!(error.body.code, "approval_challenge_expiry_mismatch");

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let decision = ApprovalDecisionRequest {
            security,
            reason: "deny exact".to_string(),
            expires_at: None,
        };
        let denied = deny_approval(
            Path(requested.approval_id.clone()),
            State(state.clone()),
            headers,
            Json(decision.clone()),
        )
        .await
        .expect("denial")
        .0;
        assert_eq!(denied.status, "denied");

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let repeated = deny_approval(
            Path(requested.approval_id.clone()),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                ..decision.clone()
            }),
        )
        .await
        .expect("exact denial retry")
        .0;
        assert_eq!(repeated.trace_event_id, denied.trace_event_id);

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let error = deny_approval(
            Path(requested.approval_id.clone()),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "changed denial".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("changed denial conflicts");
        assert_eq!(error.body.code, "approval_decision_conflict");

        state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .get_mut(&requested.approval_id.to_string())
            .expect("record")
            .status = "paused".to_string();
        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let error = deny_approval(
            Path(requested.approval_id.clone()),
            State(state.clone()),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "deny paused".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("unknown approval state fails closed");
        assert_eq!(error.body.code, "approval_state_conflict");
        state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .get_mut(&requested.approval_id.to_string())
            .expect("record")
            .status = "denied".to_string();

        let (headers, security) =
            approval_security(&state, &signer, vec![EndpointScope::ApprovalsManage]);
        let error = revoke_approval(
            Path(requested.approval_id),
            State(state),
            headers,
            Json(ApprovalDecisionRequest {
                security,
                reason: "revoke denied".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("denied approval remains terminal");
        assert_eq!(error.body.code, "approval_terminal_conflict");
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
        assert_eq!(
            error.status,
            StatusCode::FORBIDDEN,
            "unexpected rejection: {} {}",
            error.body.code,
            error.body.message
        );
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

        let instance_heartbeat_error = heartbeat_instance(
            Path(InstanceId::parse("00000000-0000-4000-8000-000000000604").expect("instance")),
            State(state.clone()),
            Json(HeartbeatInstanceRequest {
                security: missing_scope.clone(),
                heartbeat: InstanceHeartbeat {
                    node_id: node.node_id.clone(),
                    instance_id: InstanceId::parse("00000000-0000-4000-8000-000000000604")
                        .expect("instance"),
                    health: instance(
                        "00000000-0000-4000-8000-000000000504",
                        "00000000-0000-4000-8000-000000000604",
                        &tenant_id,
                    )
                    .health,
                    recorded_at: OffsetDateTime::now_utc(),
                },
            }),
        )
        .await
        .expect_err("instance heartbeat requires instance heartbeat scope");
        assert_eq!(instance_heartbeat_error.body.code, "missing_scope");

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
    async fn authenticated_instance_heartbeat_refreshes_stale_instance_without_static_mutation() {
        let state = ManagerState::local_acceptance();
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let node = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000714",
            "http://127.0.0.1:1",
            "resident_cloud_pool",
            "cloud",
            vec!["runtime.resident"],
        );
        let instance_id =
            InstanceId::parse("00000000-0000-4000-8000-000000000715").expect("instance");
        let registration_security = manager_security(
            &state,
            vec![
                EndpointScope::NodesRegister,
                EndpointScope::InstancesRegister,
            ],
        );
        let _ = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: registration_security.clone(),
                registration: node.clone(),
            }),
        )
        .await
        .expect("node registered");
        let mut registration = instance(
            &node.node_id.to_string(),
            &instance_id.to_string(),
            &tenant_id,
        );
        registration.health.observed_at = OffsetDateTime::now_utc() - Duration::seconds(61);
        registration.registered_at = registration.health.observed_at;
        state
            .inner
            .registry
            .register_instance_received_at(
                registration.clone(),
                OffsetDateTime::now_utc() - Duration::seconds(61),
            )
            .expect("stale instance registered at manager-observed time");

        let placement = PlacementRequest::new(PlacementTarget::ResidentCloudPool);
        let stale = state
            .inner
            .registry
            .instance(&instance_id)
            .expect("stale instance record");
        assert!(!instance_is_eligible(
            &stale,
            &node.runtime_version,
            &tenant_id,
            &placement,
            OffsetDateTime::now_utc(),
        ));

        let heartbeat_security = manager_security(&state, vec![EndpointScope::InstancesHeartbeat]);
        let received_before = OffsetDateTime::now_utc();
        let reported_future = received_before + Duration::days(365);
        let response = heartbeat_instance(
            Path(instance_id.clone()),
            State(state.clone()),
            Json(HeartbeatInstanceRequest {
                security: heartbeat_security.clone(),
                heartbeat: InstanceHeartbeat {
                    node_id: node.node_id.clone(),
                    instance_id: instance_id.clone(),
                    health: splendor_types::InstanceHealth {
                        status: HealthStatus::Healthy,
                        observed_at: reported_future,
                        metadata: serde_json::json!({"queue_depth": 0}),
                    },
                    recorded_at: reported_future,
                },
            }),
        )
        .await
        .expect("authenticated instance heartbeat accepted");
        assert_eq!(response.0["accepted"], true);

        let refreshed = state
            .inner
            .registry
            .instance(&instance_id)
            .expect("refreshed instance record");
        assert_eq!(refreshed.registration, registration);
        assert_eq!(
            refreshed.health.metadata,
            serde_json::json!({"queue_depth": 0})
        );
        let received_after = OffsetDateTime::now_utc();
        assert!(refreshed.last_heartbeat_at >= received_before);
        assert!(refreshed.last_heartbeat_at <= received_after);
        assert_ne!(refreshed.last_heartbeat_at, reported_future);
        assert!(instance_is_eligible(
            &refreshed,
            &node.runtime_version,
            &tenant_id,
            &placement,
            received_after,
        ));

        let mismatched = heartbeat_instance(
            Path(InstanceId::new()),
            State(state.clone()),
            Json(HeartbeatInstanceRequest {
                security: heartbeat_security,
                heartbeat: InstanceHeartbeat {
                    node_id: node.node_id,
                    instance_id,
                    health: refreshed.health,
                    recorded_at: reported_future + Duration::seconds(1),
                },
            }),
        )
        .await
        .expect_err("path/body instance mismatch rejected before registry mutation");
        assert_eq!(mismatched.body.code, "instance_id_mismatch");
        assert!(state
            .inner
            .audit
            .lock()
            .expect("manager audit")
            .iter()
            .any(|event| event.event_type == "instance.heartbeat_recorded"));
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

    #[tokio::test]
    async fn accepted_work_order_ids_are_immutable_and_matching_resubmission_is_idempotent() {
        let state = ManagerState::local_acceptance();
        let security = manager_security(&state, vec![EndpointScope::WorkOrdersSubmit]);
        let original = dispatch_test_work_order();
        let first = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security: security.clone(),
                work_order: original.clone(),
                expected_audience: "central-manager".to_string(),
                approval_policies: Vec::new(),
            }),
        )
        .await
        .expect("first work order accepted")
        .0;
        let duplicate = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security: security.clone(),
                work_order: original.clone(),
                expected_audience: "central-manager".to_string(),
                approval_policies: Vec::new(),
            }),
        )
        .await
        .expect("matching signed bytes accepted idempotently")
        .0;
        assert!(first.accepted && duplicate.accepted);

        let mut replacement_payload = original.work_order.clone();
        replacement_payload.objective = "same ID with replacement authority".to_string();
        let replacement = WorkOrderEnvelope::signed_with_shared_secret(
            replacement_payload,
            "work-order-local-key",
            b"splendor-local-work-order-secret",
        )
        .expect("valid replacement signature");
        let denied = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security,
                work_order: replacement,
                expected_audience: "central-manager".to_string(),
                approval_policies: Vec::new(),
            }),
        )
        .await
        .expect_err("same ID cannot replace accepted signed bytes");
        assert_eq!(denied.status, StatusCode::CONFLICT);
        assert_eq!(denied.body.code, "work_order_payload_replacement");
        let stored = state
            .inner
            .work_orders
            .lock()
            .expect("work-order lock")
            .get("wo_test_dispatch")
            .cloned()
            .expect("original remains stored");
        assert_eq!(stored.envelope, original);
        assert!(stored.approval_policies.is_empty());
    }

    #[tokio::test]
    async fn accepted_work_order_approval_policies_are_validated_and_immutable() {
        let work_order = dispatch_test_work_order();
        let valid_policy = dispatch_approval_policy(&work_order);
        let invalid_cases = vec![
            (
                "approval_policy_schema_unsupported",
                ApprovalPolicy {
                    schema_version: "splendor.approval_policy.v2".to_string(),
                    ..valid_policy.clone()
                },
            ),
            (
                "approval_policy_tenant_mismatch",
                ApprovalPolicy {
                    tenant_id: TenantId::new(),
                    ..valid_policy.clone()
                },
            ),
            (
                "approval_policy_agent_mismatch",
                ApprovalPolicy {
                    agent_id: Some(AgentId::new()),
                    ..valid_policy.clone()
                },
            ),
            (
                "approval_policy_action_out_of_scope",
                ApprovalPolicy {
                    action_name: Some("daemon.delete".to_string()),
                    ..valid_policy.clone()
                },
            ),
            (
                "approval_policy_adapter_out_of_scope",
                ApprovalPolicy {
                    adapter: Some("daemon.other".to_string()),
                    ..valid_policy.clone()
                },
            ),
            (
                "approval_policy_permission_out_of_scope",
                ApprovalPolicy {
                    required_permission: Some("fixture.admin".to_string()),
                    ..valid_policy.clone()
                },
            ),
            (
                "approval_policy_expired",
                ApprovalPolicy {
                    expires_at: Some(OffsetDateTime::now_utc() - Duration::seconds(1)),
                    ..valid_policy.clone()
                },
            ),
            (
                "approval_policy_expiry_exceeds_work_order",
                ApprovalPolicy {
                    expires_at: Some(work_order.work_order.expires_at + Duration::seconds(1)),
                    ..valid_policy.clone()
                },
            ),
            (
                "approval_policy_id_invalid",
                ApprovalPolicy {
                    policy_id: " ".to_string(),
                    ..valid_policy.clone()
                },
            ),
            (
                "approval_policy_reason_invalid",
                ApprovalPolicy {
                    reason: String::new(),
                    ..valid_policy.clone()
                },
            ),
            (
                "approval_policy_risk_level_invalid",
                ApprovalPolicy {
                    risk_level: Some(String::new()),
                    ..valid_policy.clone()
                },
            ),
        ];
        for (expected_code, policy) in invalid_cases {
            let state = ManagerState::local_acceptance();
            let security = manager_security(&state, vec![EndpointScope::WorkOrdersSubmit]);
            let error = submit_work_order(
                State(state.clone()),
                Json(SubmitWorkOrderRequest {
                    security,
                    work_order: work_order.clone(),
                    expected_audience: "central-manager".to_string(),
                    approval_policies: vec![policy],
                }),
            )
            .await
            .expect_err("invalid approval policy must fail before storage");
            assert_eq!(error.body.code, expected_code);
            assert!(state
                .inner
                .work_orders
                .lock()
                .expect("work-order lock")
                .is_empty());
        }

        let state = ManagerState::local_acceptance();
        let security = manager_security(&state, vec![EndpointScope::WorkOrdersSubmit]);
        let duplicate_id = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security,
                work_order: work_order.clone(),
                expected_audience: "central-manager".to_string(),
                approval_policies: vec![valid_policy.clone(), valid_policy.clone()],
            }),
        )
        .await
        .expect_err("duplicate policy IDs must fail before storage");
        assert_eq!(duplicate_id.body.code, "approval_policy_id_duplicate");

        let state = ManagerState::local_acceptance();
        let security = manager_security(&state, vec![EndpointScope::WorkOrdersSubmit]);
        let too_many_policies = (0..=MAX_WORK_ORDER_APPROVAL_POLICIES)
            .map(|index| ApprovalPolicy {
                policy_id: format!("policy_{index}"),
                ..valid_policy.clone()
            })
            .collect();
        let count_error = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security,
                work_order: work_order.clone(),
                expected_audience: "central-manager".to_string(),
                approval_policies: too_many_policies,
            }),
        )
        .await
        .expect_err("approval policy count must be bounded before storage");
        assert_eq!(count_error.body.code, "approval_policy_count_exceeded");

        let state = ManagerState::local_acceptance();
        let security = manager_security(&state, vec![EndpointScope::WorkOrdersSubmit]);
        let submit = |approval_policies| SubmitWorkOrderRequest {
            security: security.clone(),
            work_order: work_order.clone(),
            expected_audience: "central-manager".to_string(),
            approval_policies,
        };
        let _ = submit_work_order(
            State(state.clone()),
            Json(submit(vec![valid_policy.clone()])),
        )
        .await
        .expect("valid narrowing policy accepted");
        let _ = submit_work_order(
            State(state.clone()),
            Json(submit(vec![valid_policy.clone()])),
        )
        .await
        .expect("same envelope and policies are idempotent");
        let mut replacement_policy = valid_policy.clone();
        replacement_policy.reason = "different immutable policy".to_string();
        let replacement =
            submit_work_order(State(state.clone()), Json(submit(vec![replacement_policy])))
                .await
                .expect_err("same envelope cannot replace accepted policies");
        assert_eq!(
            replacement.body.code,
            "work_order_approval_policies_replacement"
        );
        let stored = load_accepted_work_order(&state, "wo_test_dispatch")
            .expect("immutable accepted work-order record");
        assert_eq!(stored.approval_policies, vec![valid_policy]);
        state
            .inner
            .work_orders
            .lock()
            .expect("work-order lock")
            .get_mut("wo_test_dispatch")
            .expect("accepted work order")
            .approval_policies[0]
            .reason = "tampered after admission".to_string();
        let corruption = load_accepted_work_order(&state, "wo_test_dispatch")
            .err()
            .expect("approval policy digest mismatch must fail closed");
        assert_eq!(corruption.body.code, "work_order_binding_mismatch");
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
        let resident_url = spawn_fixed_status_server();
        let (state, approval_signer) = manager_with_approval_auth(vec![resident_url.clone()]);
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
        let requested_at = OffsetDateTime::now_utc() - Duration::seconds(1);
        let approval_expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
        let approval_audience = format!("splendor.daemon.run:{run_id}");
        let challenge = ApprovalChallenge {
            schema_version: splendor_types::APPROVAL_CHALLENGE_SCHEMA_VERSION.to_string(),
            approval_id: approval_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: run_id.clone(),
            action_id: action_id.clone(),
            action_name: "artifact.publish_external".to_string(),
            adapter: "artifact-store".to_string(),
            policy_id: "policy_s5_unit".to_string(),
            risk_level: Some("high".to_string()),
            subject: splendor_types::PrincipalId::new(),
            authority_decision_id: splendor_types::AuthorityDecisionId::new(),
            obligation_id: splendor_types::AuthorityObligationId::new(),
            receipt_audience: approval_audience.clone(),
            canonical_request_digest: format!("blake3:{}", "1".repeat(64)),
            gateway_action_request_digest: format!("blake3:{}", "2".repeat(64)),
            physical_action_resource_coordinate: None,
            authority_decision_digest: format!("blake3:{}", "3".repeat(64)),
            requested_at,
            expires_at: approval_expires_at,
        };
        let (approval_headers, approval_request_security) = approval_security(
            &state,
            &approval_signer,
            vec![EndpointScope::ApprovalsManage],
        );
        let approval_request_payload = ApprovalRequestPayload {
            security: approval_request_security,
            approval_id: approval_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: run_id.clone(),
            action_id: action_id.clone(),
            action_name: "artifact.publish_external".to_string(),
            adapter: "artifact-store".to_string(),
            policy_id: "policy_s5_unit".to_string(),
            risk_level: Some("high".to_string()),
            audience: approval_audience,
            expires_at: approval_expires_at,
            reason: "unit approval request".to_string(),
            challenge: Some(challenge.clone()),
        };
        let requested = request_approval(
            State(state.clone()),
            approval_headers,
            Json(approval_request_payload.clone()),
        )
        .await
        .expect("approval requested")
        .0;
        assert_eq!(requested.status, "requested");
        let (duplicate_headers, duplicate_security) = approval_security(
            &state,
            &approval_signer,
            vec![EndpointScope::ApprovalsManage],
        );
        let mut duplicate_payload = approval_request_payload.clone();
        duplicate_payload.security = duplicate_security;
        let duplicate_request = request_approval(
            State(state.clone()),
            duplicate_headers,
            Json(duplicate_payload),
        )
        .await
        .expect("exact approval request is idempotent")
        .0;
        assert_eq!(duplicate_request.trace_event_id, requested.trace_event_id);

        let (grant_headers, grant_security) = approval_security(
            &state,
            &approval_signer,
            vec![EndpointScope::ApprovalsManage],
        );
        let grant_request = ApprovalDecisionRequest {
            security: grant_security,
            reason: "grant unit".to_string(),
            expires_at: None,
        };
        let granted = grant_approval(
            Path(approval_id.clone()),
            State(state.clone()),
            grant_headers,
            Json(grant_request.clone()),
        )
        .await
        .expect("approval granted")
        .0;
        assert_eq!(granted.status, "granted");
        assert!(granted.authority_obligation_receipt.is_some());
        assert_eq!(
            granted.evidence.expect("grant evidence").decision,
            ApprovalDecision::Granted
        );
        let (duplicate_grant_headers, duplicate_grant_security) = approval_security(
            &state,
            &approval_signer,
            vec![EndpointScope::ApprovalsManage],
        );
        let duplicate_grant = grant_approval(
            Path(approval_id.clone()),
            State(state.clone()),
            duplicate_grant_headers,
            Json(ApprovalDecisionRequest {
                security: duplicate_grant_security,
                ..grant_request
            }),
        )
        .await
        .expect("exact approval grant is idempotent")
        .0;
        assert_eq!(duplicate_grant.trace_event_id, granted.trace_event_id);
        assert_eq!(
            duplicate_grant.authority_obligation_receipt,
            granted.authority_obligation_receipt
        );
        let (changed_grant_headers, changed_grant_security) = approval_security(
            &state,
            &approval_signer,
            vec![EndpointScope::ApprovalsManage],
        );
        let changed_grant = grant_approval(
            Path(approval_id.clone()),
            State(state.clone()),
            changed_grant_headers,
            Json(ApprovalDecisionRequest {
                security: changed_grant_security,
                reason: "changed grant".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("changed repeated grant conflicts");
        assert_eq!(changed_grant.body.code, "approval_grant_conflict");

        let (deny_headers, deny_security) = approval_security(
            &state,
            &approval_signer,
            vec![EndpointScope::ApprovalsManage],
        );
        let denied_after_grant = deny_approval(
            Path(approval_id.clone()),
            State(state.clone()),
            deny_headers,
            Json(ApprovalDecisionRequest {
                security: deny_security,
                reason: "deny unit".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("grant decision cannot be replaced by denial");
        assert_eq!(denied_after_grant.body.code, "approval_decision_conflict");

        let (revoke_headers, revoke_security) = approval_security(
            &state,
            &approval_signer,
            vec![EndpointScope::ApprovalsManage],
        );
        let revoke_without_resident = revoke_approval(
            Path(approval_id.clone()),
            State(state.clone()),
            revoke_headers,
            Json(ApprovalDecisionRequest {
                security: revoke_security,
                reason: "revoke unit".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("granted approval requires resident receipt acknowledgement");
        assert_eq!(
            revoke_without_resident.body.code,
            "approval_resident_target_unavailable"
        );
        let retained_grant = state
            .inner
            .approvals
            .lock()
            .expect("approvals")
            .get(&approval_id.to_string())
            .cloned()
            .expect("retained grant");
        assert_eq!(retained_grant.status, "granted");
        assert!(retained_grant.authority_obligation_receipt.is_some());
        let (after_revoke_headers, after_revoke_security) = approval_security(
            &state,
            &approval_signer,
            vec![EndpointScope::ApprovalsManage],
        );
        let grant_after_revoke = grant_approval(
            Path(approval_id.clone()),
            State(state.clone()),
            after_revoke_headers,
            Json(ApprovalDecisionRequest {
                security: after_revoke_security,
                reason: "grant after revoke".to_string(),
                expires_at: None,
            }),
        )
        .await
        .expect_err("changed repeated grant conflicts");
        assert_eq!(grant_after_revoke.body.code, "approval_grant_conflict");
        let mut changed_request = approval_request_payload;
        changed_request.challenge = Some(ApprovalChallenge {
            action_name: "artifact.publish_changed".to_string(),
            ..challenge
        });
        changed_request.action_name = "artifact.publish_changed".to_string();
        let (changed_request_headers, changed_request_security) = approval_security(
            &state,
            &approval_signer,
            vec![EndpointScope::ApprovalsManage],
        );
        changed_request.security = changed_request_security;
        let changed_request = request_approval(
            State(state.clone()),
            changed_request_headers,
            Json(changed_request),
        )
        .await
        .expect_err("changed challenge cannot replace granted record");
        assert_eq!(changed_request.body.code, "approval_request_conflict");

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
        assert_eq!(propagated_kill.cancel_status, Some(200));
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

        let (missing_approval_headers, missing_approval_security) = approval_security(
            &state,
            &approval_signer,
            vec![EndpointScope::ApprovalsManage],
        );
        let missing_approval = grant_approval(
            Path(ApprovalId::parse("77777777-7777-4777-8777-777777777777").expect("approval")),
            State(state.clone()),
            missing_approval_headers,
            Json(ApprovalDecisionRequest {
                security: missing_approval_security,
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
    }

    #[test]
    fn resident_dispatch_payload_is_derived_from_signed_work_order_authority() {
        let work_order = dispatch_test_work_order();
        let approval_policy = dispatch_approval_policy(&work_order);
        let run_id = work_order.work_order.run_id.clone().expect("run id");
        let credential = serde_json::json!({"credential_id":"resident-test"});
        let audit = serde_json::json!({"credential_id":"resident-test"});
        let payload = resident_create_run_payload(
            &work_order,
            std::slice::from_ref(&approval_policy),
            &run_id,
            credential,
            audit,
        )
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
        assert_eq!(
            payload["request_id"],
            serde_json::json!(format!(
                "req-manager-dispatch-{}-{run_id}",
                work_order.work_order.work_order_id
            ))
        );
        assert_eq!(
            payload["idempotency_key"],
            serde_json::json!(format!(
                "idem-manager-dispatch-{}-{run_id}",
                work_order.work_order.work_order_id
            ))
        );
        let repeated = resident_create_run_payload(
            &work_order,
            std::slice::from_ref(&approval_policy),
            &run_id,
            serde_json::json!({"credential_id":"resident-test"}),
            serde_json::json!({"credential_id":"resident-test"}),
        )
        .expect("repeated payload derives deterministically");
        assert_eq!(repeated["request_id"], payload["request_id"]);
        assert_eq!(repeated["idempotency_key"], payload["idempotency_key"]);
        let distinct_run = RunId::new();
        let error = resident_create_run_payload(
            &work_order,
            &[],
            &distinct_run,
            serde_json::json!({"credential_id":"resident-test"}),
            serde_json::json!({"credential_id":"resident-test"}),
        )
        .expect_err("unsigned run substitution is rejected");
        assert_eq!(error.body.code, "resident_dispatch_run_id_required");
        let profile = payload["registered_actions"]
            .as_array()
            .expect("registered actions")
            .first()
            .expect("profile");
        assert_eq!(profile["name"], "daemon.record");
        assert_eq!(profile["adapter"], "resident.test");
        assert_eq!(
            profile["required_permissions"],
            serde_json::json!(["fixture.execute"])
        );
        assert!(payload["policy_actions"]
            .as_array()
            .expect("policy actions")
            .is_empty());
        assert_eq!(
            payload["approval_policies"],
            serde_json::json!([approval_policy])
        );
        assert_eq!(
            payload["allowed_actions"],
            serde_json::json!(["daemon.record"]),
            "approval governance cannot broaden signed action authority"
        );
    }

    #[tokio::test]
    async fn placement_rejects_unknown_signed_locality_class_instead_of_ignoring_it() {
        let state = ManagerState::local_acceptance();
        let mut work_order = dispatch_test_work_order().work_order;
        work_order.work_order_id =
            WorkOrderId::try_new("wo_unknown_locality").expect("work-order id");
        work_order.placement.data_locality = Some("eu-west".to_string());
        let envelope = WorkOrderEnvelope::signed_with_shared_secret(
            work_order,
            "work-order-local-key",
            b"splendor-local-work-order-secret",
        )
        .expect("signed unknown-locality work order");
        submit_test_work_order(
            &state,
            &manager_security(&state, vec![EndpointScope::WorkOrdersSubmit]),
            envelope,
        )
        .await;

        let error = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: manager_security(&state, vec![EndpointScope::FleetRead]),
                work_order_id: Some("wo_unknown_locality".to_string()),
                request: PlacementRequest {
                    target: PlacementTarget::CustomerVpc,
                    required_capabilities: vec!["runtime.resident".to_string()],
                    data_locality: Some(DataLocality::Vpc),
                    dedicated_instance: false,
                    required_runtime_version: None,
                    max_runtime_ms: Some(30_000),
                    execution_mode: PlacementExecutionMode::Live,
                },
            }),
        )
        .await
        .expect_err("region-like locality cannot be reinterpreted as a typed class");
        assert_eq!(error.body.code, "unsupported_work_order_data_locality");
        assert!(state
            .inner
            .placements
            .lock()
            .expect("placements")
            .get("wo_unknown_locality")
            .is_none());
    }

    #[test]
    fn resident_dispatch_payload_rejects_ambiguous_work_order_v1_profiles() {
        let work_order = test_work_order("33333333-3333-4333-8333-333333333333");
        let run_id = work_order.work_order.run_id.clone().expect("run id");
        let error = resident_create_run_payload(
            &work_order,
            &[],
            &run_id,
            serde_json::json!({}),
            serde_json::json!({}),
        )
        .expect_err("multi-adapter work-order v1 profile rejected");
        assert_eq!(error.body.code, "resident_dispatch_profile_unsupported");

        let mut missing_run = dispatch_test_work_order();
        let run_id = missing_run.work_order.run_id.take().expect("run id");
        let error = resident_create_run_payload(
            &missing_run,
            &[],
            &run_id,
            serde_json::json!({}),
            serde_json::json!({}),
        )
        .expect_err("run binding required");
        assert_eq!(error.body.code, "resident_dispatch_run_id_required");
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
                schema: TASK_REQUEST_SCHEMA.to_string(),
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
            .any(|schema| schema.schema == TASK_REQUEST_SCHEMA));

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
        let resident_url = spawn_fixed_status_server();
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
                approval_policies: Vec::new(),
            }),
        )
        .await
        .expect("work order accepted");
        let placement_request = PlacementRequest {
            target: PlacementTarget::CustomerVpc,
            required_capabilities: vec!["message.remote.proposal".to_string()],
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
        let dispatch_error = dispatch_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: Some(vpc_node.node_id.clone()),
            }),
        )
        .await
        .expect_err("multi-adapter work-order v1 dispatch is rejected before network I/O");
        assert_eq!(
            dispatch_error.body.code,
            "resident_dispatch_profile_unsupported"
        );

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
    async fn send_message_revalidates_revoked_work_order() {
        let state = ManagerState::local_acceptance();
        let security = manager_security(
            &state,
            vec![
                EndpointScope::NodesRegister,
                EndpointScope::InstancesRegister,
                EndpointScope::WorkOrdersSubmit,
                EndpointScope::WorkOrdersRevoke,
                EndpointScope::MessagesSend,
            ],
        );
        let target_agent = "33333333-3333-4333-8333-333333333333";
        let work_order = test_work_order(target_agent);
        let tenant_id = work_order.work_order.tenant_id.clone();
        let run_id = work_order.work_order.run_id.clone().expect("run id");
        register_message_route(&state, &security, &tenant_id).await;
        submit_test_work_order(&state, &security, work_order).await;
        let _ = revoke_work_order(
            Path("wo_test_remote".to_string()),
            State(state.clone()),
            Json(RevokeWorkOrderRequest {
                security: security.clone(),
                reason: "security review revoked authority".to_string(),
            }),
        )
        .await
        .expect("work order revoked");

        let request = send_request(security.credential.clone(), target_agent, run_id);
        let message_id = request.message_envelope.message.message_id.clone();
        let error = send_message(State(state.clone()), Json(request))
            .await
            .expect_err("revoked work order must not authorize message send");

        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(error.body.code, "revoked_work_order");
        assert!(!state
            .inner
            .messages
            .lock()
            .expect("message lock")
            .contains_key(&message_id.to_string()));
        assert!(state
            .inner
            .audit
            .lock()
            .expect("audit lock")
            .iter()
            .any(|event| event.event_type == "remote_message.rejected"
                && event
                    .details
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    == Some("revoked_work_order")));
    }

    #[tokio::test]
    async fn send_message_revalidates_expired_work_order() {
        let state = ManagerState::local_acceptance();
        let security = manager_security(
            &state,
            vec![
                EndpointScope::NodesRegister,
                EndpointScope::InstancesRegister,
                EndpointScope::MessagesSend,
            ],
        );
        let target_agent = "33333333-3333-4333-8333-333333333333";
        let run_id = RunId::parse("44444444-4444-4444-8444-444444444444").expect("run");
        let expired_work_order = test_work_order_with(
            "wo_test_remote_expired",
            target_agent,
            run_id.clone(),
            OffsetDateTime::now_utc() - Duration::seconds(1),
        );
        let tenant_id = expired_work_order.work_order.tenant_id.clone();
        register_message_route(&state, &security, &tenant_id).await;
        let accepted = accepted_work_order(expired_work_order, Vec::new())
            .expect("expired work-order admission fixture");
        state
            .inner
            .work_orders
            .lock()
            .expect("work order lock")
            .insert("wo_test_remote_expired".to_string(), accepted.clone());
        state
            .inner
            .accepted_work_order_bindings
            .lock()
            .expect("work-order binding lock")
            .insert(
                "wo_test_remote_expired".to_string(),
                AcceptedWorkOrderBinding {
                    payload_digest: accepted.payload_digest,
                    envelope_digest: accepted.envelope_digest,
                    approval_policies_digest: accepted.approval_policies_digest,
                },
            );

        let mut request = send_request(security.credential.clone(), target_agent, run_id);
        request.work_order_id = "wo_test_remote_expired".to_string();
        request.idempotency_key = Some("expired-message-authority".to_string());
        let message_id = request.message_envelope.message.message_id.clone();
        let error = send_message(State(state.clone()), Json(request))
            .await
            .expect_err("expired work order must not authorize message send");

        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(error.body.code, "expired_work_order");
        assert!(!state
            .inner
            .messages
            .lock()
            .expect("message lock")
            .contains_key(&message_id.to_string()));
    }

    #[tokio::test]
    async fn send_message_rejects_cross_scope_idempotency_key_collision() {
        let state = ManagerState::local_acceptance();
        let security = manager_security(
            &state,
            vec![
                EndpointScope::NodesRegister,
                EndpointScope::InstancesRegister,
                EndpointScope::WorkOrdersSubmit,
                EndpointScope::MessagesSend,
            ],
        );
        let target_one = "33333333-3333-4333-8333-333333333333";
        let target_two = "33333333-3333-4333-8333-333333333334";
        let work_order_one = test_work_order(target_one);
        let tenant_id = work_order_one.work_order.tenant_id.clone();
        let run_one = work_order_one.work_order.run_id.clone().expect("run one");
        let run_two = RunId::parse("44444444-4444-4444-8444-444444444445").expect("run two");
        let work_order_two = test_work_order_with(
            "wo_test_remote_second",
            target_two,
            run_two.clone(),
            OffsetDateTime::now_utc() + Duration::minutes(10),
        );
        register_message_route(&state, &security, &tenant_id).await;
        submit_test_work_order(&state, &security, work_order_one).await;
        submit_test_work_order(&state, &security, work_order_two).await;

        let first = send_request(security.credential.clone(), target_one, run_one);
        let delivered = send_message(State(state.clone()), Json(first))
            .await
            .expect("first scoped message delivered")
            .0;
        assert!(!delivered.duplicate);

        let mut colliding = send_request(security.credential.clone(), target_two, run_two);
        colliding.work_order_id = "wo_test_remote_second".to_string();
        colliding.message_envelope.message.message_id =
            MessageId::parse("55555555-5555-4555-8555-555555555558").expect("message id");
        colliding.idempotency_key = Some("proposal-once".to_string());
        let colliding_message_id = colliding.message_envelope.message.message_id.clone();
        let error = send_message(State(state.clone()), Json(colliding))
            .await
            .expect_err("cross-scope idempotency key collision must fail closed");

        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(error.body.code, "message_idempotency_scope_mismatch");
        assert!(!state
            .inner
            .messages
            .lock()
            .expect("message lock")
            .contains_key(&colliding_message_id.to_string()));
        assert!(state
            .inner
            .audit
            .lock()
            .expect("audit lock")
            .iter()
            .any(|event| event.event_type == "remote_message.rejected"
                && event
                    .details
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    == Some("message_idempotency_scope_mismatch")));
    }

    #[tokio::test]
    async fn send_message_rejects_nested_task_request_authority_smuggling() {
        let state = ManagerState::local_acceptance();
        let security = manager_security(
            &state,
            vec![
                EndpointScope::NodesRegister,
                EndpointScope::InstancesRegister,
                EndpointScope::WorkOrdersSubmit,
                EndpointScope::MessagesSend,
            ],
        );
        let target_agent = "33333333-3333-4333-8333-333333333333";
        let work_order = test_work_order(target_agent);
        let tenant_id = work_order.work_order.tenant_id.clone();
        let run_id = work_order.work_order.run_id.clone().expect("run id");
        register_message_route(&state, &security, &tenant_id).await;
        submit_test_work_order(&state, &security, work_order).await;

        let valid_authority = serde_json::json!({
            "allowed_actions": ["sql.read_fixture"],
            "allowed_adapters": ["fixture-sql"],
            "allowed_permissions": ["fixture.sql.read"]
        });
        let extra_permission = serde_json::json!({
            "allowed_actions": ["sql.read_fixture"],
            "allowed_adapters": ["fixture-sql"],
            "allowed_permissions": ["fixture.sql.read", "tenant.admin"]
        });
        let permission_smuggle = task_request_send_request(
            security.credential.clone(),
            target_agent,
            run_id.clone(),
            "55555555-5555-4555-8555-555555555559",
            "44444444-4444-4444-8444-444444444449",
            "nested-permission-smuggle",
            extra_permission,
        );
        let permission_message_id = permission_smuggle
            .message_envelope
            .message
            .message_id
            .clone();
        let error = send_message(State(state.clone()), Json(permission_smuggle))
            .await
            .expect_err("extra nested permission rejected");
        assert_eq!(
            error.status,
            StatusCode::FORBIDDEN,
            "unexpected rejection: {} {}",
            error.body.code,
            error.body.message
        );
        assert_eq!(error.body.code, "message_payload_scope_smuggling");
        assert!(!state
            .inner
            .messages
            .lock()
            .expect("message lock")
            .contains_key(&permission_message_id.to_string()));
        assert!(!state
            .inner
            .message_idempotency
            .lock()
            .expect("message idempotency lock")
            .contains_key("nested-permission-smuggle"));

        let retry_valid = task_request_send_request(
            security.credential.clone(),
            target_agent,
            run_id.clone(),
            "55555555-5555-4555-8555-555555555559",
            "44444444-4444-4444-8444-444444444449",
            "nested-permission-smuggle",
            valid_authority.clone(),
        );
        let delivered = send_message(State(state.clone()), Json(retry_valid))
            .await
            .expect("valid retry after rejected smuggling is not idempotency-poisoned")
            .0;
        assert!(!delivered.duplicate);
        assert_eq!(
            delivered.idempotency_key.as_deref(),
            Some("nested-permission-smuggle")
        );

        let extra_action = serde_json::json!({
            "allowed_actions": ["sql.read_fixture", "artifact.publish_external"],
            "allowed_adapters": ["fixture-sql"],
            "allowed_permissions": ["fixture.sql.read"]
        });
        let action_smuggle = task_request_send_request(
            security.credential.clone(),
            target_agent,
            run_id.clone(),
            "55555555-5555-4555-8555-55555555555a",
            "44444444-4444-4444-8444-44444444444a",
            "nested-action-smuggle",
            extra_action,
        );
        let action_message_id = action_smuggle.message_envelope.message.message_id.clone();
        let error = send_message(State(state.clone()), Json(action_smuggle))
            .await
            .expect_err("extra nested action rejected");
        assert_eq!(error.body.code, "message_payload_scope_smuggling");
        assert!(!state
            .inner
            .messages
            .lock()
            .expect("message lock")
            .contains_key(&action_message_id.to_string()));
        assert!(!state
            .inner
            .message_idempotency
            .lock()
            .expect("message idempotency lock")
            .contains_key("nested-action-smuggle"));

        let extra_adapter = serde_json::json!({
            "allowed_actions": ["sql.read_fixture"],
            "allowed_adapters": ["fixture-sql", "external-publisher"],
            "allowed_permissions": ["fixture.sql.read"]
        });
        let adapter_smuggle = task_request_send_request(
            security.credential.clone(),
            target_agent,
            run_id.clone(),
            "55555555-5555-4555-8555-55555555555b",
            "44444444-4444-4444-8444-44444444444b",
            "nested-adapter-smuggle",
            extra_adapter,
        );
        let adapter_message_id = adapter_smuggle.message_envelope.message.message_id.clone();
        let error = send_message(State(state.clone()), Json(adapter_smuggle))
            .await
            .expect_err("extra nested adapter rejected");
        assert_eq!(error.body.code, "message_payload_scope_smuggling");
        assert!(!state
            .inner
            .messages
            .lock()
            .expect("message lock")
            .contains_key(&adapter_message_id.to_string()));
        assert!(!state
            .inner
            .message_idempotency
            .lock()
            .expect("message idempotency lock")
            .contains_key("nested-adapter-smuggle"));

        let mut input_ref_smuggle = task_request_send_request(
            security.credential,
            target_agent,
            run_id,
            "55555555-5555-4555-8555-55555555555c",
            "44444444-4444-4444-8444-44444444444c",
            "nested-input-ref-smuggle",
            valid_authority,
        );
        input_ref_smuggle
            .message_envelope
            .message
            .payload
            .as_object_mut()
            .expect("task request payload object")
            .insert(
                "input_ref".to_string(),
                serde_json::json!("dataset:other-tenant.secret.v1"),
            );
        let input_ref_message_id = input_ref_smuggle
            .message_envelope
            .message
            .message_id
            .clone();
        let error = send_message(State(state.clone()), Json(input_ref_smuggle))
            .await
            .expect_err("out-of-scope explicit input_ref rejected");
        assert_eq!(error.body.code, "message_payload_scope_smuggling");
        assert!(!state
            .inner
            .messages
            .lock()
            .expect("message lock")
            .contains_key(&input_ref_message_id.to_string()));
        assert!(!state
            .inner
            .message_idempotency
            .lock()
            .expect("message idempotency lock")
            .contains_key("nested-input-ref-smuggle"));
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
                approval_policies: Vec::new(),
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
                    approval_policies: Vec::new(),
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
                work_order_id: None,
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
                approval_policies: Vec::new(),
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
                "runtime.resident",
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

        let candidates = placement_candidates(&state, None).expect("placement candidates");
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

        let work_order = dispatch_test_work_order();
        let work_order_id = work_order.work_order.work_order_id.to_string();
        let _ = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security: security.clone(),
                work_order,
                expected_audience: "central-manager".to_string(),
                approval_policies: Vec::new(),
            }),
        )
        .await
        .expect("work order submitted");

        let mismatched_placement = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some(work_order_id.clone()),
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
        .expect_err("placement cannot weaken or replace signed constraints");
        assert_eq!(
            mismatched_placement.body.code,
            "placement_request_work_order_mismatch"
        );
        let error = dispatch_work_order(
            Path(work_order_id.clone()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("unbound placement cannot dispatch");
        assert_eq!(error.body.code, "placement_required");

        let selected = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some(work_order_id.clone()),
                request: PlacementRequest {
                    target: PlacementTarget::CustomerVpc,
                    required_capabilities: vec!["runtime.resident".to_string()],
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
            Path(work_order_id.clone()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: Some(cloud_node.node_id.clone()),
            }),
        )
        .await
        .expect_err("target mismatch rejected");
        assert_eq!(mismatch.body.code, "dispatch_target_mismatch");

        let _ = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance(
                    &vpc_node.node_id.to_string(),
                    "00000000-0000-4000-8000-000000000301",
                    &TenantId::new(),
                ),
            }),
        )
        .await
        .expect("wrong-tenant instance registered");
        let no_instance = dispatch_work_order(
            Path(work_order_id.clone()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("instance that does not host the signed tenant is ineligible");
        assert_eq!(no_instance.body.code, "no_eligible_resident_instance");

        let mut invalid_candidate = selected.0.clone();
        invalid_candidate.candidate_id = Some("not-a-node-id".to_string());
        let invalid_candidate_digest = stable_manager_digest(
            b"splendor.manager.placement-decision.v1\0",
            &invalid_candidate,
        )
        .expect("invalid candidate decision digest");
        state
            .inner
            .placements
            .lock()
            .expect("placement lock")
            .insert(work_order_id.clone(), invalid_candidate.clone());
        state
            .inner
            .placement_bindings
            .lock()
            .expect("placement binding lock")
            .get_mut(&work_order_id)
            .expect("placement binding")
            .decision_digest = invalid_candidate_digest;
        let missing_target = dispatch_work_order(
            Path(work_order_id.clone()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("invalid selected candidate cannot supply an implicit target");
        assert_eq!(missing_target.body.code, "missing_target_node");

        let missing_candidate = dispatch_work_order(
            Path(work_order_id.clone()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: Some(vpc_node.node_id.clone()),
            }),
        )
        .await
        .expect_err("invalid selected candidate remains fail closed with explicit target");
        assert_eq!(missing_candidate.body.code, "placement_candidate_missing");

        state
            .inner
            .placements
            .lock()
            .expect("placement lock")
            .insert(work_order_id.clone(), selected.0.clone());
        state
            .inner
            .placement_bindings
            .lock()
            .expect("placement binding lock")
            .get_mut(&work_order_id)
            .expect("placement binding")
            .decision_digest =
            stable_manager_digest(b"splendor.manager.placement-decision.v1\0", &selected.0)
                .expect("selected decision digest");

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

        let blocked_egress = dispatch_work_order(
            Path(work_order_id.clone()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("unallowlisted resident origin is rejected before network I/O");
        assert_eq!(blocked_egress.body.code, "resident_origin_not_allowed");

        let _ = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance(
                    &vpc_node.node_id.to_string(),
                    "00000000-0000-4000-8000-000000000303",
                    &tenant_id,
                ),
            }),
        )
        .await
        .expect("second eligible instance registered");
        let ambiguous = dispatch_work_order(
            Path(work_order_id.clone()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("multiple eligible resident instances are rejected before egress");
        assert_eq!(ambiguous.body.code, "ambiguous_eligible_resident_instances");

        state
            .inner
            .work_orders
            .lock()
            .expect("work order lock")
            .get_mut(&work_order_id)
            .expect("work order")
            .envelope
            .work_order
            .objective = "tampered after signature".to_string();
        let bad_signature = dispatch_work_order(
            Path(work_order_id.clone()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security: security.clone(),
                target_node_id: None,
            }),
        )
        .await
        .expect_err("tampered dispatch work order rejected");
        assert_eq!(bad_signature.body.code, "work_order_binding_mismatch");
    }

    #[tokio::test]
    async fn revocation_gate_queues_revoke_before_dispatch_and_prevents_egress() {
        let state = ManagerState::local_acceptance();
        let security = manager_security(
            &state,
            vec![
                EndpointScope::NodesRegister,
                EndpointScope::InstancesRegister,
                EndpointScope::FleetRead,
                EndpointScope::FleetDispatch,
                EndpointScope::WorkOrdersSubmit,
                EndpointScope::WorkOrdersRevoke,
            ],
        );
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let node = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000814",
            "http://127.0.0.1:1",
            "customer_vpc",
            "vpc",
            vec!["runtime.resident"],
        );
        let _ = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration: node.clone(),
            }),
        )
        .await
        .expect("node registered");
        let _ = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance(
                    &node.node_id.to_string(),
                    "00000000-0000-4000-8000-000000000815",
                    &tenant_id,
                ),
            }),
        )
        .await
        .expect("instance registered");
        submit_test_work_order(&state, &security, dispatch_test_work_order()).await;
        let _ = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some("wo_test_dispatch".to_string()),
                request: PlacementRequest {
                    target: PlacementTarget::CustomerVpc,
                    required_capabilities: vec!["runtime.resident".to_string()],
                    data_locality: Some(DataLocality::Vpc),
                    dedicated_instance: false,
                    required_runtime_version: None,
                    max_runtime_ms: Some(30_000),
                    execution_mode: PlacementExecutionMode::Live,
                },
            }),
        )
        .await
        .expect("placement selected");

        let gate = state
            .accepted_work_order_revocation_gate("wo_test_dispatch")
            .expect("revocation gate");
        let barrier = Arc::clone(&gate).lock_owned().await;
        let mut revoke = Box::pin(revoke_work_order(
            Path("wo_test_dispatch".to_string()),
            State(state.clone()),
            Json(RevokeWorkOrderRequest {
                security: security.clone(),
                reason: "revoke wins race".to_string(),
            }),
        ));
        assert!(poll_once(revoke.as_mut()).is_pending());
        let mut dispatch = Box::pin(dispatch_work_order(
            Path("wo_test_dispatch".to_string()),
            State(state.clone()),
            Json(DispatchWorkOrderRequest {
                security,
                target_node_id: Some(node.node_id),
            }),
        ));
        assert!(poll_once(dispatch.as_mut()).is_pending());
        drop(barrier);

        let _ = revoke.await.expect("queued revocation committed");
        let error = dispatch
            .await
            .expect_err("dispatch queued behind revocation is denied");
        assert_eq!(error.body.code, "revoked_work_order");
        assert!(state
            .inner
            .dispatch_bindings
            .lock()
            .expect("dispatch bindings")
            .get("wo_test_dispatch")
            .is_none());
        assert!(state
            .inner
            .dispatch_state
            .lock()
            .expect("dispatch state")
            .in_flight
            .is_empty());
    }

    #[tokio::test]
    async fn unknown_work_order_ids_do_not_allocate_revocation_or_dispatch_state() {
        let state = ManagerState::local_acceptance();
        let security = manager_security(
            &state,
            vec![
                EndpointScope::FleetDispatch,
                EndpointScope::WorkOrdersRevoke,
            ],
        );

        for index in 0..128 {
            let work_order_id = format!("wo_unknown_{index}");
            let revoke_error = revoke_work_order(
                Path(work_order_id.clone()),
                State(state.clone()),
                Json(RevokeWorkOrderRequest {
                    security: security.clone(),
                    reason: "unknown ID must not create a tombstone".to_string(),
                }),
            )
            .await
            .expect_err("unknown revoke denied");
            assert_eq!(revoke_error.body.code, "work_order_not_found");

            let dispatch_error = dispatch_work_order(
                Path(work_order_id),
                State(state.clone()),
                Json(DispatchWorkOrderRequest {
                    security: security.clone(),
                    target_node_id: None,
                }),
            )
            .await
            .expect_err("unknown dispatch denied");
            assert_eq!(dispatch_error.body.code, "work_order_not_found");
        }

        assert!(state
            .inner
            .work_order_revocation_gates
            .lock()
            .expect("gate state")
            .is_empty());
        assert!(state
            .inner
            .revoked_work_orders
            .lock()
            .expect("revocation state")
            .is_empty());
        let dispatch = state.inner.dispatch_state.lock().expect("dispatch state");
        assert!(dispatch.completed.is_empty());
        assert!(dispatch.terminal_failures.is_empty());
        assert!(dispatch.in_flight.is_empty());
    }

    #[tokio::test]
    async fn accepted_work_order_and_placement_bindings_fail_closed_on_replacement_or_corruption() {
        let state = ManagerState::local_acceptance();
        let security = manager_security(
            &state,
            vec![
                EndpointScope::NodesRegister,
                EndpointScope::FleetRead,
                EndpointScope::WorkOrdersSubmit,
            ],
        );
        let registration = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000914",
            "http://127.0.0.1:1",
            "customer_vpc",
            "vpc",
            vec!["runtime.resident"],
        );
        let _ = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration,
            }),
        )
        .await
        .expect("placement node registered");

        let envelope = dispatch_test_work_order();
        let work_order_id = envelope.work_order.work_order_id.to_string();
        submit_test_work_order(&state, &security, envelope.clone()).await;
        let idempotent = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security: security.clone(),
                work_order: envelope.clone(),
                expected_audience: "central-manager".to_string(),
                approval_policies: Vec::new(),
            }),
        )
        .await
        .expect("exact work-order resubmission is idempotent");
        assert!(idempotent.0.accepted);

        let mut replacement_payload = envelope.work_order.clone();
        replacement_payload.objective = "same ID with different signed bytes".to_string();
        let replacement = WorkOrderEnvelope::signed_with_shared_secret(
            replacement_payload,
            "work-order-local-key",
            b"splendor-local-work-order-secret",
        )
        .expect("replacement envelope signs");
        let replacement_error = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security: security.clone(),
                work_order: replacement,
                expected_audience: "central-manager".to_string(),
                approval_policies: Vec::new(),
            }),
        )
        .await
        .expect_err("accepted ID cannot be replaced");
        assert_eq!(
            replacement_error.body.code,
            "work_order_payload_replacement"
        );

        let wrong_audience = submit_work_order(
            State(state.clone()),
            Json(SubmitWorkOrderRequest {
                security: security.clone(),
                work_order: envelope.clone(),
                expected_audience: "other-manager".to_string(),
                approval_policies: Vec::new(),
            }),
        )
        .await
        .expect_err("manager audience mismatch rejected");
        assert_eq!(wrong_audience.body.code, "wrong_audience");

        let request = dispatch_placement_request();
        let first = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some(work_order_id.clone()),
                request: request.clone(),
            }),
        )
        .await
        .expect("placement bound");
        let repeated = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some(work_order_id.clone()),
                request: request.clone(),
            }),
        )
        .await
        .expect("exact placement replay returns immutable decision");
        assert_eq!(repeated.0, first.0);

        let original_work_order_binding = state
            .inner
            .accepted_work_order_bindings
            .lock()
            .expect("work-order bindings")
            .get(&work_order_id)
            .cloned()
            .expect("work-order binding");
        state
            .inner
            .accepted_work_order_bindings
            .lock()
            .expect("work-order bindings")
            .remove(&work_order_id);
        let missing_binding = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some(work_order_id.clone()),
                request: request.clone(),
            }),
        )
        .await
        .expect_err("missing immutable work-order binding rejected");
        assert_eq!(missing_binding.body.code, "work_order_binding_missing");
        state
            .inner
            .accepted_work_order_bindings
            .lock()
            .expect("work-order bindings")
            .insert(work_order_id.clone(), original_work_order_binding.clone());

        state
            .inner
            .accepted_work_order_bindings
            .lock()
            .expect("work-order bindings")
            .get_mut(&work_order_id)
            .expect("work-order binding")
            .payload_digest = "blake3:tampered".to_string();
        let mismatched_binding = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some(work_order_id.clone()),
                request: request.clone(),
            }),
        )
        .await
        .expect_err("mismatched immutable work-order binding rejected");
        assert_eq!(mismatched_binding.body.code, "work_order_binding_mismatch");
        state
            .inner
            .accepted_work_order_bindings
            .lock()
            .expect("work-order bindings")
            .insert(work_order_id.clone(), original_work_order_binding);

        let original_placement_binding = state
            .inner
            .placement_bindings
            .lock()
            .expect("placement bindings")
            .get(&work_order_id)
            .cloned()
            .expect("placement binding");
        state
            .inner
            .placement_bindings
            .lock()
            .expect("placement bindings")
            .get_mut(&work_order_id)
            .expect("placement binding")
            .request
            .required_capabilities
            .push("tampered.capability".to_string());
        let replaced_placement = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some(work_order_id.clone()),
                request: request.clone(),
            }),
        )
        .await
        .expect_err("placement binding replacement rejected");
        assert_eq!(
            replaced_placement.body.code,
            "placement_binding_replacement"
        );
        state
            .inner
            .placement_bindings
            .lock()
            .expect("placement bindings")
            .insert(work_order_id.clone(), original_placement_binding.clone());

        let original_decision = state
            .inner
            .placements
            .lock()
            .expect("placements")
            .remove(&work_order_id)
            .expect("placement decision");
        let incomplete_placement = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some(work_order_id.clone()),
                request: request.clone(),
            }),
        )
        .await
        .expect_err("binding without decision rejected");
        assert_eq!(
            incomplete_placement.body.code,
            "placement_binding_incomplete"
        );
        state
            .inner
            .placements
            .lock()
            .expect("placements")
            .insert(work_order_id.clone(), original_decision.clone());

        state
            .inner
            .placements
            .lock()
            .expect("placements")
            .get_mut(&work_order_id)
            .expect("placement decision")
            .reasons
            .push("tampered after binding".to_string());
        let mismatched_placement = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security,
                work_order_id: Some(work_order_id.clone()),
                request,
            }),
        )
        .await
        .expect_err("decision digest mismatch rejected");
        assert_eq!(mismatched_placement.body.code, "placement_binding_mismatch");
        state
            .inner
            .placements
            .lock()
            .expect("placements")
            .insert(work_order_id.clone(), original_decision);
        state
            .inner
            .placement_bindings
            .lock()
            .expect("placement bindings")
            .insert(work_order_id, original_placement_binding);
    }

    #[tokio::test]
    async fn resolved_dispatch_binding_is_immutable_and_rechecks_live_eligibility() {
        let resident_url = "http://127.0.0.1:18091";
        let state = manager_with_allowed_origins(vec![resident_url.to_string()]);
        let security = manager_security(
            &state,
            vec![
                EndpointScope::NodesRegister,
                EndpointScope::InstancesRegister,
                EndpointScope::FleetRead,
                EndpointScope::WorkOrdersSubmit,
            ],
        );
        let tenant_id = TenantId::parse("11111111-1111-4111-8111-111111111111").expect("tenant");
        let node = node(
            &state.inner.fleet_id,
            "00000000-0000-4000-8000-000000000924",
            resident_url,
            "customer_vpc",
            "vpc",
            vec!["runtime.resident"],
        );
        let instance = instance(
            &node.node_id.to_string(),
            "00000000-0000-4000-8000-000000000925",
            &tenant_id,
        );
        let _ = register_node(
            State(state.clone()),
            Json(RegisterNodeRequest {
                security: security.clone(),
                registration: node.clone(),
            }),
        )
        .await
        .expect("node registered");
        let _ = register_instance(
            State(state.clone()),
            Json(RegisterInstanceRequest {
                security: security.clone(),
                registration: instance.clone(),
            }),
        )
        .await
        .expect("instance registered");
        let envelope = dispatch_test_work_order();
        let work_order_id = envelope.work_order.work_order_id.to_string();
        submit_test_work_order(&state, &security, envelope).await;
        let request = dispatch_placement_request();
        let _ = evaluate_placement(
            State(state.clone()),
            Json(PlacementEvaluationRequest {
                security: security.clone(),
                work_order_id: Some(work_order_id.clone()),
                request: request.clone(),
            }),
        )
        .await
        .expect("placement selected");

        let accepted =
            load_accepted_work_order(&state, &work_order_id).expect("accepted work-order record");
        state
            .inner
            .revoked_work_orders
            .lock()
            .expect("revocations")
            .insert(work_order_id.clone());
        let revoked = revalidate_dispatch_authority(
            &state,
            &accepted,
            accepted.envelope.work_order.run_id.as_ref().expect("run"),
            "customer_vpc",
            "unit",
        )
        .expect_err("revocation is rechecked before egress");
        assert_eq!(revoked.body.code, "revoked_work_order");
        state
            .inner
            .revoked_work_orders
            .lock()
            .expect("revocations")
            .remove(&work_order_id);
        let mut expired_payload = accepted.envelope.work_order.clone();
        expired_payload.expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);
        let expired = accepted_work_order(
            WorkOrderEnvelope::signed_with_shared_secret(
                expired_payload,
                "work-order-local-key",
                b"splendor-local-work-order-secret",
            )
            .expect("expired envelope signs"),
            Vec::new(),
        )
        .expect("expired binding");
        let expired_error = revalidate_dispatch_authority(
            &state,
            &expired,
            expired.envelope.work_order.run_id.as_ref().expect("run"),
            "customer_vpc",
            "unit",
        )
        .expect_err("expiry is rechecked before egress");
        assert_eq!(expired_error.body.code, "expired_work_order");
        let decision = state
            .inner
            .placements
            .lock()
            .expect("placements")
            .get(&work_order_id)
            .cloned()
            .expect("placement decision");
        let placement_binding = state
            .inner
            .placement_bindings
            .lock()
            .expect("placement bindings")
            .get(&work_order_id)
            .cloned()
            .expect("placement binding");
        let placement = BoundPlacement {
            request,
            decision,
            decision_digest: placement_binding.decision_digest,
        };
        let first =
            resolve_dispatch_binding(&state, &work_order_id, &accepted, &placement, &node.node_id)
                .expect("dispatch binding resolves");
        let repeated =
            resolve_dispatch_binding(&state, &work_order_id, &accepted, &placement, &node.node_id)
                .expect("bound instance remains eligible");
        assert_eq!(repeated.instance_id, first.instance_id);
        assert_eq!(repeated.resident_origin, first.resident_origin);

        let mut origin_mismatch = first.clone();
        origin_mismatch.resident_origin = "http://127.0.0.1:18092".to_string();
        state
            .inner
            .dispatch_bindings
            .lock()
            .expect("dispatch bindings")
            .insert(work_order_id.clone(), origin_mismatch.clone());
        let origin_error =
            ensure_bound_instance_eligible(&state, &accepted, &placement, &origin_mismatch)
                .expect_err("resident origin substitution rejected");
        assert_eq!(origin_error.body.code, "resident_origin_binding_mismatch");
        state
            .inner
            .dispatch_bindings
            .lock()
            .expect("dispatch bindings")
            .insert(work_order_id.clone(), first.clone());

        state
            .inner
            .dispatch_bindings
            .lock()
            .expect("dispatch bindings")
            .get_mut(&work_order_id)
            .expect("dispatch binding")
            .work_order_payload_digest = "blake3:tampered".to_string();
        let replacement = match resolve_dispatch_binding(
            &state,
            &work_order_id,
            &accepted,
            &placement,
            &node.node_id,
        ) {
            Ok(_) => panic!("dispatch binding replacement accepted"),
            Err(error) => error,
        };
        assert_eq!(replacement.body.code, "dispatch_binding_replacement");
        state
            .inner
            .dispatch_bindings
            .lock()
            .expect("dispatch bindings")
            .insert(work_order_id.clone(), first.clone());

        let mut offline_health = instance.health;
        offline_health.status = HealthStatus::Offline;
        state
            .inner
            .registry
            .record_instance_heartbeat_received_at(
                InstanceHeartbeat {
                    node_id: node.node_id.clone(),
                    instance_id: instance.instance_id,
                    health: offline_health,
                    recorded_at: OffsetDateTime::now_utc(),
                },
                OffsetDateTime::now_utc(),
            )
            .expect("unhealthy heartbeat recorded");
        let ineligible = match resolve_dispatch_binding(
            &state,
            &work_order_id,
            &accepted,
            &placement,
            &node.node_id,
        ) {
            Ok(_) => panic!("bound unhealthy instance accepted"),
            Err(error) => error,
        };
        assert_eq!(
            ineligible.body.code,
            "bound_resident_instance_no_longer_eligible"
        );
    }

    #[test]
    fn resident_dispatch_error_and_status_taxonomy_is_total_and_fail_closed() {
        let cases = [
            (ResidentHttpError::InvalidUrl, "invalid_resident_url", false),
            (
                ResidentHttpError::Transport {
                    timeout: true,
                    request_sent: false,
                },
                "resident_timeout",
                false,
            ),
            (
                ResidentHttpError::Transport {
                    timeout: false,
                    request_sent: true,
                },
                "resident_transport_failure",
                true,
            ),
            (
                ResidentHttpError::ResponseTooLarge,
                "resident_response_too_large",
                true,
            ),
            (
                ResidentHttpError::UnexpectedStatus {
                    status: 403,
                    upstream_code: Some("resident_scope_denied".to_string()),
                },
                "resident_rejected_request",
                true,
            ),
            (
                ResidentHttpError::InvalidResponse,
                "resident_invalid_response",
                true,
            ),
        ];
        for (error, reason, effect_may_have_occurred) in cases {
            assert_eq!(resident_http_error_reason(&error), reason);
            assert_eq!(error.effect_may_have_occurred(), effect_may_have_occurred);
            assert_ne!(
                resident_http_error("create", error, false).status,
                StatusCode::OK
            );
        }
        let effect_unknown = resident_http_error(
            "start",
            ResidentHttpError::Transport {
                timeout: true,
                request_sent: true,
            },
            true,
        );
        assert_eq!(effect_unknown.status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(effect_unknown.body.code, "resident_start_effect_unknown");

        for (status, expected) in [
            (crate::RunStatus::Pending, RunStatus::Pending),
            (crate::RunStatus::Running, RunStatus::Running),
            (crate::RunStatus::Paused, RunStatus::Paused),
            (
                crate::RunStatus::WaitingForApproval,
                RunStatus::WaitingForApproval,
            ),
            (crate::RunStatus::Interrupted, RunStatus::Interrupted),
            (crate::RunStatus::Resuming, RunStatus::Resuming),
            (crate::RunStatus::Completed, RunStatus::Completed),
            (crate::RunStatus::Failed, RunStatus::Failed),
            (crate::RunStatus::Cancelled, RunStatus::Cancelled),
            (crate::RunStatus::Denied, RunStatus::Denied),
            (crate::RunStatus::Expired, RunStatus::Expired),
        ] {
            assert_eq!(telemetry_run_status(&status), expected);
        }
    }

    #[tokio::test]
    async fn resident_transport_disables_redirects_and_bounds_response_bodies() {
        assert_eq!(
            bounded_upstream_code("resident_scope_denied".to_string()).as_deref(),
            Some("resident_scope_denied")
        );
        assert!(bounded_upstream_code("x".repeat(129)).is_none());
        assert!(bounded_upstream_code("unsafe code\n".to_string()).is_none());
        let app = Router::new().route(
            "/runs",
            post(|Json(body): Json<serde_json::Value>| async move {
                match body.get("case").and_then(serde_json::Value::as_str) {
                    Some("redirect") => (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(axum::http::header::LOCATION, "http://127.0.0.1:1/never")],
                        Json(serde_json::json!({"redirect": true})),
                    )
                        .into_response(),
                    Some("large") => (StatusCode::OK, "x".repeat(1024)).into_response(),
                    Some("malformed") => (StatusCode::OK, "not-json").into_response(),
                    Some("extra") => Json(serde_json::json!({
                        "request_id": "request",
                        "idempotency_key": "idempotency",
                        "idempotency_receipt_id": "receipt",
                        "duplicate": false,
                        "run_id": "44444444-4444-4444-8444-444444444444",
                        "status": "pending",
                        "reflected_authorization": "must-not-be-retained"
                    }))
                    .into_response(),
                    _ => StatusCode::BAD_REQUEST.into_response(),
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("transport listener");
        let address = listener.local_addr().expect("transport address");
        let base_url = format!("http://{address}");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("transport server remains available");
        });

        let signer = CallerTokenSigner::generate_for_test(
            "urn:splendor:manager:transport-test",
            "transport-manager",
            "transport-client",
            "transport-key",
        )
        .expect("transport signer");
        let state = ManagerState::local_acceptance_with_dispatch(
            signer,
            ResidentDispatchOptions {
                maximum_response_bytes: 512,
                allowed_origins: vec![base_url.clone()],
                ..ResidentDispatchOptions::loopback_test()
            },
        )
        .expect("transport manager");
        let tenant_id = TenantId::new();
        let instance_id = InstanceId::new();
        let caller = state
            .inner
            .resident_dispatch
            .create_run_caller(&tenant_id, &instance_id)
            .expect("transport caller");
        let redirected = state
            .inner
            .resident_dispatch
            .create_run(
                &base_url,
                &caller.encoded,
                &serde_json::json!({"case": "redirect"}),
            )
            .await
            .expect_err("redirect is returned, never followed");
        assert!(matches!(
            redirected,
            ResidentHttpError::UnexpectedStatus { status: 307, .. }
        ));

        let oversized = state
            .inner
            .resident_dispatch
            .create_run(
                &base_url,
                &caller.encoded,
                &serde_json::json!({"case": "large"}),
            )
            .await
            .expect_err("large response rejected before decoding");
        assert!(matches!(oversized, ResidentHttpError::ResponseTooLarge));
        let malformed = state
            .inner
            .resident_dispatch
            .create_run(
                &base_url,
                &caller.encoded,
                &serde_json::json!({"case": "malformed"}),
            )
            .await
            .expect_err("malformed success is never accepted");
        assert!(matches!(malformed, ResidentHttpError::InvalidResponse));
        let unknown_field = state
            .inner
            .resident_dispatch
            .create_run(
                &base_url,
                &caller.encoded,
                &serde_json::json!({"case": "extra"}),
            )
            .await
            .expect_err("unknown success fields are never accepted or retained");
        assert!(matches!(unknown_field, ResidentHttpError::InvalidResponse));
        assert!(matches!(
            validate_resident_url(
                &reqwest::Url::parse("http://192.0.2.1:8077").expect("url"),
                true,
                &HashSet::new(),
            ),
            Err(ResidentHttpError::InvalidUrl)
        ));
        let allowed = &state.inner.resident_dispatch.allowed_origins;
        for hostile in [
            format!("http://user@{address}"),
            format!("{base_url}/path"),
            format!("{base_url}?next=https://attacker.invalid"),
            format!("{base_url}#fragment"),
            "http://127.0.0.1:1".to_string(),
        ] {
            assert!(matches!(
                validate_resident_url(
                    &reqwest::Url::parse(&hostile).expect("syntactically valid hostile URL"),
                    true,
                    allowed,
                ),
                Err(ResidentHttpError::InvalidUrl)
            ));
        }
        assert!(canonical_allowed_origins(&["http://127.0.0.1:8077".to_string()], false).is_err());
        assert!(canonical_allowed_origins(
            &[
                "https://resident.example:8443".to_string(),
                "https://resident.example:8443/".to_string()
            ],
            false
        )
        .is_err());
        server.abort();
    }

    #[test]
    fn terminal_dispatch_storage_failure_quarantines_duplicate_execution() {
        let state = ManagerState::local_acceptance();
        let mut reservation = reserve_dispatch(&state, "wo_quarantined").expect("reservation");
        let poison_state = state.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison_state
                .inner
                .dispatch_state
                .lock()
                .expect("terminal failure lock");
            panic!("poison terminal dispatch storage for fail-closed test");
        })
        .join();

        let error = persist_terminal_dispatch_failure(
            &state,
            "wo_quarantined",
            ManagerApiError::bad_gateway("resident_start_rejected", "start rejected"),
            &mut reservation,
        );
        assert_eq!(error.body.code, "dispatch_terminal_state_unavailable");
        assert!(!reservation.release_on_drop);
        drop(reservation);
        let duplicate = match reserve_dispatch(&state, "wo_quarantined") {
            Err(error) => error,
            Ok(_) => panic!("quarantined dispatch must remain in flight"),
        };
        assert_eq!(duplicate.body.code, "dispatch_lock");
    }
}
