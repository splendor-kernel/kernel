//! # Action Gateway Primitives
//!
//! The gateway mediates all side-effectful operations by wrapping actions,
//! capturing outcomes, and surfacing errors back to the kernel. The traits and
//! request/response types define the contract that later adapters implement.
//!
//! ## Example
//! ```rust,no_run
//! use splendor_gateway::{ActionGateway, ActionRequest, UnimplementedGateway};
//! use splendor_types::{Action, SideEffectClass};
//! use time::OffsetDateTime;
//!
//! let gateway = UnimplementedGateway::default();
//! let request = ActionRequest {
//!     action_id: Default::default(),
//!     tenant_id: splendor_types::TenantId::new(),
//!     agent_id: splendor_types::AgentId::new(),
//!     run_id: splendor_types::RunId::new(),
//!     tick_id: None,
//!     action: Action {
//!         name: "noop".into(),
//!         params: serde_json::json!({}),
//!         side_effect_class: SideEffectClass::ReadOnly,
//!         cost_estimate: None,
//!         required_permissions: vec![],
//!         preconditions: vec![],
//!         postconditions: vec![],
//!     },
//!     adapter: None,
//!     quota_usage: splendor_types::QuotaUsage::single_action(),
//!     satisfied_preconditions: vec![],
//!     requested_at: OffsetDateTime::now_utc(),
//!     physical_action_resource_coordinate: None,
//!     approval_evidence: None,
//!     authority_obligation_evidence: None,
//!     authority_obligation_receipts: vec![],
//! };
//! assert!(ActionGateway::submit(&gateway, request).is_err());
//! ```

mod credential_ingress;

pub use credential_ingress::{
    guard_action, guard_action_request, guard_action_routing, guard_action_routing_and_receipts,
    guard_credential_capable_strings, guard_credential_capable_value, raw_credential_denied_action,
    raw_credential_denied_outcome, RawCredentialInputDenied, CREDENTIAL_INGRESS_MAX_DEPTH,
    CREDENTIAL_INGRESS_MAX_NODES, CREDENTIAL_INGRESS_MAX_STRING_BYTES,
    CREDENTIAL_INGRESS_MAX_TOTAL_BYTES, RAW_CREDENTIAL_INPUT_DENIED,
};

use serde::{Deserialize, Serialize};
use splendor_authority::{
    authority_decision_evidence, canonical_authority_request_digest,
    compatibility_permission_operation, gateway_action_operation, gateway_adapter_operation,
    verify_obligation_receipts, AuthorityObligationEffectPermit, AuthorityObligationReceiptLedger,
    AuthorityObligationReceiptValidationContext, APPROVAL_OBLIGATION_ACTION_DIGEST,
    APPROVAL_OBLIGATION_ACTION_ID, APPROVAL_OBLIGATION_ACTION_NAME, APPROVAL_OBLIGATION_ADAPTER,
    APPROVAL_OBLIGATION_APPROVAL_ID, APPROVAL_OBLIGATION_EXPIRES_AT, APPROVAL_OBLIGATION_POLICY_ID,
    APPROVAL_OBLIGATION_RECEIPT_AUDIENCE, APPROVAL_OBLIGATION_RISK_LEVEL,
};
use splendor_types::{
    is_allowed_physical_action, Action, AgentId, ApprovalActionScope, ApprovalChallenge,
    ApprovalDecision, ApprovalEvidence, ApprovalId, ApprovalPolicy, ApprovalTraceContext,
    AuthorityDecision, AuthorityDecisionId, AuthorityDecisionStatus, AuthorityObligationId,
    AuthorityObligationKind, AuthorityObligationReceipt, AuthorityOperationNamespace,
    AuthorityResourceKind, AuthorityVerb, CapabilityGrantId, CircuitBreaker, CircuitBreakerScope,
    ContentHash, EffectCertainty, ErrorCategory, ErrorTaxonomy, IdentityValidationError,
    PhysicalActionResourceCoordinate, QuotaUsage, ReasonCode, RetryClass, RunId,
    RuntimeIdentityContext, SideEffectClass, TenantId, TickId, VerificationResult,
    APPROVAL_CHALLENGE_SCHEMA_VERSION, APPROVAL_EVIDENCE_SCHEMA_VERSION,
    APPROVAL_POLICY_SCHEMA_VERSION, FORBIDDEN_PHYSICAL_ACTION_PATTERNS,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::{ready, Future, Ready};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub use splendor_types::ActionId;

/// Metadata key inside `AuthorityDecision.request.metadata` that binds a
/// conditional authority decision to the exact gateway action request.
pub const GATEWAY_AUTHORITY_ACTION_DIGEST_METADATA_KEY: &str =
    "splendor.integrity.action_request_hash";

/// Metadata key inside `AuthorityDecision.request.metadata` that binds the
/// request digest signed by receipts to the full conditional decision payload.
pub const GATEWAY_AUTHORITY_DECISION_DIGEST_METADATA_KEY: &str = "splendor.integrity.decision_hash";

/// Behavior-free authority obligation evidence carried with a gateway action.
///
/// Raw receipts in this envelope are not authority. The gateway accepts them
/// only after a configured authority-owned verifier validates each receipt using
/// trusted local context and then matches the validated receipts to the embedded
/// conditional authority decision before adapter execution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GatewayAuthorityObligationEvidence {
    /// Conditional authority decision whose obligations must be satisfied.
    pub decision: AuthorityDecision,
    /// Raw obligation receipts to validate and match against the decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<AuthorityObligationReceipt>,
}

/// Request payload submitted to the action gateway.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionRequest {
    /// Unique action identifier assigned by the kernel.
    pub action_id: ActionId,
    /// Tenant identifier that owns the action.
    pub tenant_id: TenantId,
    /// Agent identifier that submitted the action.
    pub agent_id: AgentId,
    /// Run identifier that scopes the action and its trace events.
    pub run_id: RunId,
    /// Optional loop tick identity. Direct daemon actions are not ticks and omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_id: Option<TickId>,
    /// Action details to execute.
    pub action: Action,
    /// Adapter identifier requested for this action.
    pub adapter: Option<String>,
    /// Quota usage estimate for this action.
    pub quota_usage: QuotaUsage,
    /// Preconditions satisfied by the current state.
    pub satisfied_preconditions: Vec<String>,
    /// Timestamp when the action was requested.
    pub requested_at: OffsetDateTime,
    /// Trusted server-derived physical target. This field is never decoded from
    /// requester JSON and is set only by kernel composition.
    #[serde(skip)]
    pub physical_action_resource_coordinate: Option<PhysicalActionResourceCoordinate>,
    /// Optional approval grant/denial evidence presented for this action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_evidence: Option<ApprovalEvidence>,
    /// Optional behavior-free authority obligation evidence for conditional decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_obligation_evidence: Option<GatewayAuthorityObligationEvidence>,
    /// Raw owning-service receipts presented for a current live conditional
    /// authority decision. Receipts are non-authorizing until the configured
    /// local authority verifier validates and matches them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_obligation_receipts: Vec<AuthorityObligationReceipt>,
}

/// Immutable server-owned semantic requirements for one registered action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrustedActionProfile {
    /// Registered action name.
    pub action_name: String,
    /// Exact adapter paired with this action.
    pub adapter: String,
    /// Exact semantic permission set required for every invocation.
    pub required_permissions: Vec<String>,
}

impl ActionRequest {
    /// Validates action, tenant, agent, and run identities before adapter execution.
    pub fn validate_identity(&self) -> Result<(), IdentityValidationError> {
        if self.action_id.is_nil() {
            return Err(IdentityValidationError::Missing { field: "action_id" });
        }
        if self.tenant_id.is_nil() {
            return Err(IdentityValidationError::Missing { field: "tenant_id" });
        }
        if self.agent_id.is_nil() {
            return Err(IdentityValidationError::Missing { field: "agent_id" });
        }
        if self.run_id.is_nil() {
            return Err(IdentityValidationError::Missing { field: "run_id" });
        }
        Ok(())
    }
}

/// Outcome captured after verification and execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionOutcome {
    /// Identifier of the action that completed.
    pub action_id: ActionId,
    /// Final status recorded by the gateway.
    pub status: ActionStatus,
    /// Verification result from the pre-execution pipeline.
    pub verification: VerificationResult,
    /// Optional post-execution verification result.
    pub post_verification: Option<VerificationResult>,
    /// Optional output payload from the adapter.
    pub output: Option<serde_json::Value>,
    /// Optional error message for denied or failed actions.
    pub error: Option<String>,
    /// Exact behavior-free approval challenge when this action paused. The
    /// challenge is not authority and must be satisfied by a trusted receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_challenge: Option<ApprovalChallenge>,
    /// Timestamp when the outcome was recorded.
    pub completed_at: OffsetDateTime,
}

/// Classification of action execution outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ActionStatus {
    /// Action executed successfully.
    Executed,
    /// Action was denied by verification.
    Denied,
    /// Action is paused until scoped approval evidence is presented.
    NeedsApproval,
    /// Action did not execute because verifier uncertainty or escalation requires
    /// operator/control-plane intervention.
    NeedsIntervention,
    /// Action failed during adapter execution.
    Failed,
}

/// Result returned by action adapters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdapterResult {
    /// Output payload returned by the adapter.
    pub output: serde_json::Value,
    /// Postconditions satisfied by the adapter execution.
    pub satisfied_postconditions: Vec<String>,
}

/// Trace-safe schema version for physical safety verifier evidence.
pub const SAFETY_EVIDENCE_SCHEMA_VERSION: &str = "splendor.safety_evidence.v1";

/// Local physical safety check status recorded without raw sensor payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SafetyCheckStatus {
    /// Check passed.
    Pass,
    /// Check denied the action.
    Deny,
    /// Check could not be completed and must fail closed.
    Uncertain,
}

/// Trace-safe threshold used by safety verifier evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SafetyThresholdEvidence {
    /// Threshold name, such as `min_battery_percent`.
    pub name: String,
    /// Observed value, when available without raw sensor data.
    pub observed: Option<f64>,
    /// Required maximum, when applicable.
    pub max: Option<f64>,
    /// Required minimum, when applicable.
    pub min: Option<f64>,
    /// Unit label for observed/min/max values.
    pub unit: Option<String>,
}

/// Trace-safe local physical safety verifier evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SafetyEvidence {
    /// Evidence schema version.
    pub schema_version: String,
    /// Verifier implementation name.
    pub verifier: String,
    /// Safety check name.
    pub check: String,
    /// Check status.
    pub status: SafetyCheckStatus,
    /// Stable reason code, not raw sensor text.
    pub reason_code: String,
    /// Sensor/status references used by the verifier; no raw sensor blobs.
    pub sensor_refs: Vec<String>,
    /// Zone references used by geofence/privacy checks.
    pub zone_refs: Vec<String>,
    /// Thresholds evaluated by the verifier.
    pub thresholds: Vec<SafetyThresholdEvidence>,
}

impl SafetyEvidence {
    /// Builds trace-safe safety evidence.
    pub fn new(
        verifier: impl Into<String>,
        check: impl Into<String>,
        status: SafetyCheckStatus,
        reason_code: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SAFETY_EVIDENCE_SCHEMA_VERSION.to_string(),
            verifier: verifier.into(),
            check: check.into(),
            status,
            reason_code: reason_code.into(),
            sensor_refs: Vec::new(),
            zone_refs: Vec::new(),
            thresholds: Vec::new(),
        }
    }

    /// Adds sensor/status references without embedding raw sensor data.
    pub fn with_sensor_refs(mut self, refs: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.sensor_refs = refs.into_iter().map(Into::into).collect();
        self
    }

    /// Adds zone references without embedding raw maps or camera frames.
    pub fn with_zone_refs(mut self, refs: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.zone_refs = refs.into_iter().map(Into::into).collect();
        self
    }

    /// Adds evaluated thresholds.
    pub fn with_thresholds(mut self, thresholds: Vec<SafetyThresholdEvidence>) -> Self {
        self.thresholds = thresholds;
        self
    }

    fn into_verification(self) -> VerificationResult {
        let allowed = self.status == SafetyCheckStatus::Pass;
        let reason = self.reason_code.clone();
        VerificationResult {
            allowed,
            reasons: if allowed { Vec::new() } else { vec![reason] },
            artifacts: serde_json::json!({
                "source": "safety_verifier",
                "evidence": self,
            }),
        }
    }
}

/// Outcome of a local physical safety verifier stage.
#[derive(Clone, Debug, PartialEq)]
pub enum SafetyVerification {
    /// No safety check applies to this non-physical action.
    NotRequired,
    /// Safety check passed and normal gateway verification may continue.
    Allowed(VerificationResult),
    /// Safety check denied the action.
    Denied(VerificationResult),
    /// Safety check could not complete and requires fail-closed intervention.
    NeedsIntervention(VerificationResult),
}

/// Verifies local physical safety constraints before and after high-level physical actions.
pub trait SafetyVerifier: Send + Sync {
    /// Pre-execution safety verification. Denial/intervention prevents adapter execution.
    fn verify_pre(&self, action: &ActionRequest, adapter: Option<&str>) -> SafetyVerification;

    /// Post-execution safety verification. Denial marks the outcome failed after execution.
    fn verify_post(
        &self,
        action: &ActionRequest,
        adapter: Option<&str>,
        result: &AdapterResult,
    ) -> SafetyVerification {
        let _ = (action, adapter, result);
        SafetyVerification::NotRequired
    }
}

/// Coarse simulated risk level for reference safety verifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SimulatedRiskLevel {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

/// Trace-safe local status snapshot consumed by reference simulated safety verifiers.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SimulatedSafetySnapshot {
    pub current_zone: Option<String>,
    pub allowed_zones: Vec<String>,
    pub battery_percent: Option<f64>,
    pub min_battery_percent: Option<f64>,
    #[serde(default)]
    pub policy_cache_expired: bool,
    #[serde(default)]
    pub high_risk: bool,
    #[serde(default)]
    pub cloud_helper_direct_authority: bool,
    pub emergency_stop_engaged: Option<bool>,
    pub collision_risk: Option<SimulatedRiskLevel>,
    pub altitude_m: Option<f64>,
    pub max_altitude_m: Option<f64>,
    pub privacy_zone_active: Option<bool>,
    pub proximity_m: Option<f64>,
    pub min_proximity_m: Option<f64>,
    pub sensor_refs: Vec<String>,
}

/// Reference simulated safety verifier for high-level physical actions.
#[derive(Clone, Debug)]
pub struct SimulatedSafetyVerifier {
    snapshot: SimulatedSafetySnapshot,
}

impl SimulatedSafetyVerifier {
    /// Creates a simulated verifier from a trace-safe status snapshot.
    pub fn new(snapshot: SimulatedSafetySnapshot) -> Self {
        Self { snapshot }
    }
}

impl SafetyVerifier for SimulatedSafetyVerifier {
    fn verify_pre(&self, action: &ActionRequest, _adapter: Option<&str>) -> SafetyVerification {
        if !is_physical_action(&action.action) {
            return SafetyVerification::NotRequired;
        }

        match simulated_safety_evidence(&self.snapshot) {
            SafetyVerification::Allowed(result) => SafetyVerification::Allowed(result),
            SafetyVerification::Denied(result) => SafetyVerification::Denied(result),
            SafetyVerification::NeedsIntervention(result) => {
                SafetyVerification::NeedsIntervention(result)
            }
            SafetyVerification::NotRequired => SafetyVerification::NotRequired,
        }
    }

    fn verify_post(
        &self,
        action: &ActionRequest,
        _adapter: Option<&str>,
        result: &AdapterResult,
    ) -> SafetyVerification {
        if !is_physical_action(&action.action) {
            return SafetyVerification::NotRequired;
        }
        if result
            .output
            .get("safety_status")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|status| status == "unsafe" || status == "failed")
        {
            return SafetyVerification::Denied(
                SafetyEvidence::new(
                    "simulated_safety_verifier",
                    "postcondition",
                    SafetyCheckStatus::Deny,
                    "safety_postcondition_failed",
                )
                .with_sensor_refs(self.snapshot.sensor_refs.clone())
                .into_verification(),
            );
        }
        SafetyVerification::Allowed(
            SafetyEvidence::new(
                "simulated_safety_verifier",
                "postcondition",
                SafetyCheckStatus::Pass,
                "safety_postcondition_passed",
            )
            .with_sensor_refs(self.snapshot.sensor_refs.clone())
            .into_verification(),
        )
    }
}

/// Action adapter interface for side-effectful execution.
pub trait ActionAdapter: Send + Sync {
    /// Executes the action request and returns the adapter result.
    fn execute(&self, action: &ActionRequest) -> Result<AdapterResult, AdapterError>;
}

/// Errors returned by action adapters.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// Adapter execution failed.
    #[error("adapter failed: {0}")]
    Failed(String),
}

impl AdapterError {
    /// Converts an unclassified adapter failure into the canonical taxonomy.
    ///
    /// Generic adapter errors do not prove whether the provider produced a side
    /// effect. Until a driver-specific receipt mapping exists, they remain
    /// non-retryable with uncertain effect.
    pub fn taxonomy(&self) -> ErrorTaxonomy {
        self.taxonomy_for_adapter("action_adapter")
    }

    /// Converts this adapter failure with a caller-supplied adapter/provider label.
    pub fn taxonomy_for_adapter(&self, adapter: impl AsRef<str>) -> ErrorTaxonomy {
        match self {
            Self::Failed(_) => ErrorTaxonomy::unknown_adapter_failure(adapter, None),
        }
    }
}

/// Accessor trait for tenant policy and quota checks.
pub trait TenantAccess: Send + Sync {
    /// Verifies action permissions for the tenant.
    fn verify_policy(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        action: &Action,
        adapter: Option<&str>,
    ) -> VerificationResult;
    /// Verifies quota usage for the tenant and agent.
    fn verify_quota(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
        usage: QuotaUsage,
    ) -> VerificationResult;
}

/// Evaluates invariant preconditions and postconditions.
pub trait InvariantEvaluator: Send + Sync {
    /// Verifies preconditions against the current context.
    fn verify_pre(&self, action: &Action, satisfied_preconditions: &[String])
        -> VerificationResult;
    /// Verifies postconditions against adapter results.
    fn verify_post(
        &self,
        action: &Action,
        satisfied_postconditions: &[String],
    ) -> VerificationResult;
}

/// Verifies adapter-specific resource boundaries before adapter execution.
///
/// This keeps filesystem, network, data-scope, and similar boundary checks in
/// the verifier pipeline instead of relying on adapter failures after execution
/// has been attempted.
pub trait ResourceBoundaryVerifier: Send + Sync {
    /// Verifies that the action's addressed resource is in scope for the
    /// effective adapter. A denied result prevents adapter execution.
    fn verify_resource_boundary(
        &self,
        action: &ActionRequest,
        adapter: Option<&str>,
    ) -> VerificationResult;
}

/// Resource verifier that allows all resources.
#[derive(Clone, Debug, Default)]
pub struct NoopResourceBoundaryVerifier;

impl ResourceBoundaryVerifier for NoopResourceBoundaryVerifier {
    fn verify_resource_boundary(
        &self,
        _action: &ActionRequest,
        _adapter: Option<&str>,
    ) -> VerificationResult {
        VerificationResult::allow()
    }
}

/// Result returned by an approval verifier.
#[derive(Clone, Debug, PartialEq)]
pub enum ApprovalVerification {
    /// No approval policy applies to this action.
    NotRequired,
    /// Scoped approval evidence is valid; execution may continue.
    Granted(VerificationResult),
    /// A raw obligation receipt is present, but only the final trusted authority
    /// obligation verifier may decide whether execution can continue.
    Deferred,
    /// Approval is required but no valid evidence was supplied yet.
    Required(VerificationResult),
    /// Approval evidence denied, expired, was revoked, or had the wrong scope.
    Denied(VerificationResult),
    /// The approval verifier could not complete and failed closed.
    NeedsIntervention(VerificationResult),
}

/// Verifies scoped approval evidence before adapter execution.
pub trait ApprovalVerifier: Send + Sync {
    /// Validates whether an action requires approval and whether supplied evidence is valid.
    fn verify_approval(
        &self,
        action: &ActionRequest,
        adapter: Option<&str>,
        now: OffsetDateTime,
    ) -> ApprovalVerification;
}

/// Approval verifier that requires no approval policies.
#[derive(Clone, Debug, Default)]
pub struct NoApprovalVerifier;

impl ApprovalVerifier for NoApprovalVerifier {
    fn verify_approval(
        &self,
        _action: &ActionRequest,
        _adapter: Option<&str>,
        _now: OffsetDateTime,
    ) -> ApprovalVerification {
        ApprovalVerification::NotRequired
    }
}

/// Static approval verifier backed by local approval policies.
#[derive(Clone, Debug, Default)]
pub struct PolicyApprovalVerifier {
    policies: Vec<ApprovalPolicy>,
}

impl PolicyApprovalVerifier {
    /// Creates a static approval verifier from local policies.
    pub fn new(policies: Vec<ApprovalPolicy>) -> Self {
        Self { policies }
    }
}

impl ApprovalVerifier for PolicyApprovalVerifier {
    fn verify_approval(
        &self,
        action: &ActionRequest,
        adapter: Option<&str>,
        now: OffsetDateTime,
    ) -> ApprovalVerification {
        let scope = approval_scope(action, adapter);
        let mut first_matching_policy = None;
        for policy in self
            .policies
            .iter()
            .filter(|policy| policy.matches_action(&scope, now))
        {
            if first_matching_policy.is_none() {
                first_matching_policy = Some(policy);
            }

            if policy.schema_version != APPROVAL_POLICY_SCHEMA_VERSION {
                return ApprovalVerification::NeedsIntervention(approval_result(
                    false,
                    "approval_policy_schema_unsupported",
                    "policy_schema_unsupported",
                    ApprovalTraceContext::requested(policy, &scope, ApprovalId::new()),
                    Some(policy.policy_id.clone()),
                ));
            }

            if policy.is_expired(now) {
                return ApprovalVerification::NeedsIntervention(approval_result(
                    false,
                    "approval_policy_expired",
                    "intervention_required",
                    ApprovalTraceContext::requested(policy, &scope, ApprovalId::new()),
                    Some(policy.policy_id.clone()),
                ));
            }
        }

        let Some(policy) = first_matching_policy else {
            return ApprovalVerification::NotRequired;
        };

        let Some(evidence) = action.approval_evidence.as_ref() else {
            if !action.authority_obligation_receipts.is_empty() {
                return ApprovalVerification::Deferred;
            }
            return ApprovalVerification::Required(approval_result(
                false,
                "approval_required",
                "required",
                ApprovalTraceContext::requested(policy, &scope, ApprovalId::new()),
                Some(policy.policy_id.clone()),
            ));
        };

        let context = ApprovalTraceContext::from_evidence(evidence, &scope);
        if evidence.schema_version != APPROVAL_EVIDENCE_SCHEMA_VERSION {
            return ApprovalVerification::Denied(approval_result(
                false,
                "approval_evidence_schema_unsupported",
                "schema_unsupported",
                context,
                Some(policy.policy_id.clone()),
            ));
        }

        if (evidence.action_id.is_none() && evidence.action_name.is_none())
            || (adapter.is_some() && evidence.adapter.is_none())
        {
            return ApprovalVerification::Denied(approval_result(
                false,
                "approval_scope_incomplete",
                "denied",
                context,
                Some(policy.policy_id.clone()),
            ));
        }
        if evidence.tenant_id != action.tenant_id
            || evidence.agent_id != action.agent_id
            || evidence.run_id != action.run_id
            || evidence
                .action_id
                .as_ref()
                .map(|action_id| action_id != &action.action_id)
                .unwrap_or(false)
            || evidence
                .action_name
                .as_ref()
                .map(|name| name != &action.action.name)
                .unwrap_or(false)
            || evidence
                .adapter
                .as_ref()
                .map(|expected| Some(expected.as_str()) != adapter)
                .unwrap_or(false)
        {
            return ApprovalVerification::Denied(approval_result(
                false,
                "approval_scope_mismatch",
                "denied",
                context,
                Some(policy.policy_id.clone()),
            ));
        }

        if evidence.revoked {
            return ApprovalVerification::Denied(approval_result(
                false,
                "approval_revoked",
                "revoked",
                context,
                Some(policy.policy_id.clone()),
            ));
        }

        if evidence.expires_at <= now {
            return ApprovalVerification::Denied(approval_result(
                false,
                "approval_expired",
                "expired",
                context,
                Some(policy.policy_id.clone()),
            ));
        }

        match evidence.decision {
            ApprovalDecision::Granted if action.authority_obligation_receipts.is_empty() => {
                ApprovalVerification::Required(approval_result(
                    false,
                    "approval_obligation_receipt_required",
                    "required",
                    context,
                    Some(policy.policy_id.clone()),
                ))
            }
            ApprovalDecision::Granted => ApprovalVerification::Deferred,
            ApprovalDecision::Denied => ApprovalVerification::Denied(approval_result(
                false,
                "approval_denied",
                "denied",
                context,
                Some(policy.policy_id.clone()),
            )),
        }
    }
}

/// Redacted typed summary retained as durable pre-effect authority evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GatewayAuthorityDecisionSummary {
    /// Authority decision identity.
    pub decision_id: AuthorityDecisionId,
    /// Current decision status.
    pub status: AuthorityDecisionStatus,
    /// Typed operation namespace without its concrete name.
    pub namespace: AuthorityOperationNamespace,
    /// Typed resource kind without its concrete name.
    pub resource_kind: AuthorityResourceKind,
    /// Typed operation verb.
    pub verb: AuthorityVerb,
    /// Deterministic digest of the redacted decision evidence.
    pub decision_digest: String,
    /// Bounded normalized reason codes.
    pub reason_codes: Vec<String>,
    /// Grants matched by the live evaluation.
    pub matched_grant_ids: Vec<CapabilityGrantId>,
    /// Conditional obligation identities, if any.
    pub obligation_ids: Vec<AuthorityObligationId>,
}

/// Result of evaluating current run authority for one gateway request.
#[derive(Clone, Debug, PartialEq)]
pub enum ActionAuthorityEvaluation {
    /// This gateway composition has no C02 run-authority requirement.
    NotRequired,
    /// Current typed C02 decisions for action, effective adapter, and permissions.
    Evaluated(Vec<AuthorityDecision>),
}

/// Opaque authority-owned guard held across durable pre-effect evidence and the
/// adapter call. Dropping the value releases the in-flight authority epoch.
pub struct AuthorityEffectPermit {
    _guard: Box<dyn Send>,
}

impl AuthorityEffectPermit {
    /// Wraps an authority-owner-specific permit without exposing its internals.
    pub fn new(guard: impl Send + 'static) -> Self {
        Self {
            _guard: Box::new(guard),
        }
    }
}

/// Result of the final authority linearization immediately before an effect.
pub enum FinalEffectAuthorityEvaluation {
    /// This legacy gateway composition does not require live authority.
    NotRequired,
    /// Current authority denied or could not certify the effect tuple.
    Denied(Vec<AuthorityDecision>),
    /// Current authority allowed the exact tuple and returned an owned guard.
    Permitted {
        /// Fresh decisions produced by the final atomic check.
        decisions: Vec<AuthorityDecision>,
        /// Guard retained through the adapter call.
        permit: AuthorityEffectPermit,
    },
}

/// Evaluates live C02 run authority before existing gateway verifiers and effects.
pub trait ActionAuthorityEvaluator: Send + Sync {
    /// Evaluates every typed operation required by this action.
    fn evaluate_action_authority(
        &self,
        action: &ActionRequest,
        effective_adapter: Option<&str>,
        now: OffsetDateTime,
    ) -> ActionAuthorityEvaluation;

    /// Rechecks current authority and acquires the owned final-effect guard after
    /// every other potentially blocking pre-effect verifier has completed.
    fn acquire_final_effect_permit(
        &self,
        _action: &ActionRequest,
        _effective_adapter: Option<&str>,
        _expected_decisions: &[AuthorityDecision],
        _now: OffsetDateTime,
    ) -> FinalEffectAuthorityEvaluation {
        FinalEffectAuthorityEvaluation::NotRequired
    }
}

/// Compatibility default for gateway compositions that have not adopted C02.
#[derive(Clone, Debug, Default)]
pub struct NoActionAuthorityEvaluator;

impl ActionAuthorityEvaluator for NoActionAuthorityEvaluator {
    fn evaluate_action_authority(
        &self,
        _action: &ActionRequest,
        _effective_adapter: Option<&str>,
        _now: OffsetDateTime,
    ) -> ActionAuthorityEvaluation {
        ActionAuthorityEvaluation::NotRequired
    }

    fn acquire_final_effect_permit(
        &self,
        _action: &ActionRequest,
        _effective_adapter: Option<&str>,
        _expected_decisions: &[AuthorityDecision],
        _now: OffsetDateTime,
    ) -> FinalEffectAuthorityEvaluation {
        FinalEffectAuthorityEvaluation::NotRequired
    }
}

/// Durable recorder invoked after all pre-effect checks allow and before an adapter runs.
pub trait PreEffectAuthorityDecisionRecorder: Send + Sync {
    /// Persists the completed verification including redacted live authority summaries.
    fn record_pre_effect_authority_allow(
        &self,
        action: &ActionRequest,
        verification: &VerificationResult,
    ) -> Result<(), String>;
}

/// Fail-closed recorder used when C02 evaluation is enabled without an evidence sink.
#[derive(Clone, Debug, Default)]
pub struct NoPreEffectAuthorityDecisionRecorder;

impl PreEffectAuthorityDecisionRecorder for NoPreEffectAuthorityDecisionRecorder {
    fn record_pre_effect_authority_allow(
        &self,
        _action: &ActionRequest,
        _verification: &VerificationResult,
    ) -> Result<(), String> {
        Err("authority_evidence_recorder_unavailable".to_string())
    }
}

/// Returns whether this verification was durably recorded before adapter execution.
pub fn authority_pre_effect_evidence_recorded(result: &VerificationResult) -> bool {
    ["authority", "authority_obligation"].iter().any(|key| {
        result
            .artifacts
            .get(*key)
            .and_then(|artifact| artifact.get("pre_effect_recorded"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    })
}

/// Result returned by an authority obligation verifier.
#[derive(Debug)]
pub enum AuthorityObligationVerification {
    /// No obligation evidence is required for this action and none was supplied.
    NotRequired,
    /// Conditional obligation receipts validated and matched exactly.
    Allowed(VerificationResult),
    /// Obligation evidence was present but invalid or did not satisfy the decision.
    Denied(VerificationResult),
    /// Required evidence or the verifier itself is unavailable; fail closed.
    NeedsIntervention(VerificationResult),
    /// Exact receipts were valid and atomically claimed at the effect boundary.
    Permitted {
        /// Final receipt verification result.
        verification: VerificationResult,
        /// Authority-owned one-use permit retained through the effect.
        permit: AuthorityObligationEffectPermit,
    },
}

/// Verifies conditional authority obligation receipts before adapter execution.
pub trait AuthorityObligationVerifier: Send + Sync {
    /// Verifies behavior-free authority obligation evidence for the action.
    fn verify_obligations(
        &self,
        action: &ActionRequest,
        adapter: Option<&str>,
        now: OffsetDateTime,
    ) -> AuthorityObligationVerification;

    /// Atomically claims a fully verified receipt collection at the final
    /// effect boundary. Implementations that do not own one-use state fail
    /// closed when receipts are present.
    fn claim_verified_receipts(
        &self,
        _receipts: &[AuthorityObligationReceipt],
        _now: OffsetDateTime,
    ) -> AuthorityObligationVerification {
        AuthorityObligationVerification::NeedsIntervention(authority_obligation_result(
            false,
            vec!["authority_obligation_receipt_replay_state_unavailable".to_string()],
            "verifier_unavailable",
            None,
            None,
            Vec::new(),
            Vec::new(),
        ))
    }
}

/// Default authority obligation verifier.
///
/// When no authority evidence is required and none is supplied, existing gateway
/// behavior is unchanged. If conditional evidence is supplied without a trusted
/// local verifier, the gateway fails closed rather than ignoring it.
#[derive(Clone, Debug, Default)]
pub struct NoAuthorityObligationVerifier;

impl AuthorityObligationVerifier for NoAuthorityObligationVerifier {
    fn verify_obligations(
        &self,
        action: &ActionRequest,
        _adapter: Option<&str>,
        _now: OffsetDateTime,
    ) -> AuthorityObligationVerification {
        if let Some(evidence) = action.authority_obligation_evidence.as_ref() {
            return AuthorityObligationVerification::NeedsIntervention(
                authority_obligation_result(
                    false,
                    vec!["authority_obligation_verifier_unavailable".to_string()],
                    "verifier_unavailable",
                    Some(evidence),
                    None,
                    Vec::new(),
                    Vec::new(),
                ),
            );
        }
        AuthorityObligationVerification::NotRequired
    }
}

/// Action/adapter matcher for requiring authority obligation evidence locally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityObligationRequirement {
    /// Optional exact action name. `None` matches any action.
    pub action_name: Option<String>,
    /// Optional exact effective adapter ID. `None` matches any adapter.
    pub adapter: Option<String>,
}

impl AuthorityObligationRequirement {
    /// Requires authority obligation evidence for every action.
    pub fn all() -> Self {
        Self {
            action_name: None,
            adapter: None,
        }
    }

    /// Requires authority obligation evidence for one action name.
    pub fn action(action_name: impl Into<String>) -> Self {
        Self {
            action_name: Some(action_name.into()),
            adapter: None,
        }
    }

    /// Requires authority obligation evidence for one action/adapter pair.
    pub fn action_adapter(action_name: impl Into<String>, adapter: impl Into<String>) -> Self {
        Self {
            action_name: Some(action_name.into()),
            adapter: Some(adapter.into()),
        }
    }

    fn matches(&self, action: &ActionRequest, adapter: Option<&str>) -> bool {
        let action_matches = self
            .action_name
            .as_ref()
            .map(|expected| expected == &action.action.name)
            .unwrap_or(true);
        let adapter_matches = self
            .adapter
            .as_ref()
            .map(|expected| Some(expected.as_str()) == adapter)
            .unwrap_or(true);
        action_matches && adapter_matches
    }
}

/// Local deterministic authority obligation verifier backed by trusted receipt context.
///
/// The context is supplied by gateway runtime configuration or an authority-owned
/// receipt service seam. Request payloads never control this verifier context.
#[derive(Clone)]
pub struct LocalAuthorityObligationVerifier {
    context: AuthorityObligationReceiptValidationContext,
    requirements: Vec<AuthorityObligationRequirement>,
    ledger: Arc<dyn AuthorityObligationReceiptLedger>,
}

impl LocalAuthorityObligationVerifier {
    /// Creates a verifier that validates supplied obligation evidence but does not require it.
    pub fn new(
        context: AuthorityObligationReceiptValidationContext,
        ledger: Arc<dyn AuthorityObligationReceiptLedger>,
    ) -> Self {
        Self {
            context,
            requirements: Vec::new(),
            ledger,
        }
    }

    /// Creates a verifier with explicit action/adapter requirements.
    pub fn requiring(
        context: AuthorityObligationReceiptValidationContext,
        requirements: Vec<AuthorityObligationRequirement>,
        ledger: Arc<dyn AuthorityObligationReceiptLedger>,
    ) -> Self {
        Self {
            context,
            requirements,
            ledger,
        }
    }

    /// Creates a verifier that requires authority obligation evidence for every action.
    pub fn require_all(
        context: AuthorityObligationReceiptValidationContext,
        ledger: Arc<dyn AuthorityObligationReceiptLedger>,
    ) -> Self {
        Self::requiring(context, vec![AuthorityObligationRequirement::all()], ledger)
    }
}

impl AuthorityObligationVerifier for LocalAuthorityObligationVerifier {
    fn verify_obligations(
        &self,
        action: &ActionRequest,
        adapter: Option<&str>,
        now: OffsetDateTime,
    ) -> AuthorityObligationVerification {
        let required = self
            .requirements
            .iter()
            .any(|requirement| requirement.matches(action, adapter));
        let Some(evidence) = action.authority_obligation_evidence.as_ref() else {
            if required {
                return AuthorityObligationVerification::NeedsIntervention(
                    authority_obligation_result(
                        false,
                        vec!["authority_obligation_evidence_required".to_string()],
                        "required",
                        None,
                        None,
                        Vec::new(),
                        Vec::new(),
                    ),
                );
            }
            return AuthorityObligationVerification::NotRequired;
        };

        if evidence.decision.status != AuthorityDecisionStatus::Conditional {
            return AuthorityObligationVerification::Denied(authority_obligation_result(
                false,
                vec!["authority_decision_not_conditional".to_string()],
                "denied",
                Some(evidence),
                None,
                Vec::new(),
                Vec::new(),
            ));
        }

        let decision_binding_reasons =
            authority_decision_action_binding_reasons(&evidence.decision, action, adapter);
        if !decision_binding_reasons.is_empty() {
            return AuthorityObligationVerification::Denied(authority_obligation_result(
                false,
                decision_binding_reasons,
                "denied",
                Some(evidence),
                None,
                Vec::new(),
                Vec::new(),
            ));
        }

        let expected_action_digest =
            match canonical_gateway_authority_action_digest(action, adapter) {
                Ok(digest) => digest,
                Err(reason) => {
                    return AuthorityObligationVerification::NeedsIntervention(
                        authority_obligation_result(
                            false,
                            vec![reason],
                            "digest_unavailable",
                            Some(evidence),
                            None,
                            Vec::new(),
                            Vec::new(),
                        ),
                    )
                }
            };
        let Some(decision_action_digest) = evidence
            .decision
            .request
            .metadata
            .get(GATEWAY_AUTHORITY_ACTION_DIGEST_METADATA_KEY)
            .and_then(serde_json::Value::as_str)
        else {
            return AuthorityObligationVerification::Denied(authority_obligation_result(
                false,
                vec!["authority_decision_action_digest_missing".to_string()],
                "denied",
                Some(evidence),
                Some(expected_action_digest),
                Vec::new(),
                Vec::new(),
            ));
        };
        if decision_action_digest != expected_action_digest {
            return AuthorityObligationVerification::Denied(authority_obligation_result(
                false,
                vec!["authority_decision_action_digest_mismatch".to_string()],
                "denied",
                Some(evidence),
                Some(expected_action_digest),
                Vec::new(),
                Vec::new(),
            ));
        }

        let expected_decision_digest =
            match canonical_gateway_authority_decision_digest(&evidence.decision) {
                Ok(digest) => digest,
                Err(reason) => {
                    return AuthorityObligationVerification::NeedsIntervention(
                        authority_obligation_result(
                            false,
                            vec![reason],
                            "decision_digest_unavailable",
                            Some(evidence),
                            Some(expected_action_digest),
                            Vec::new(),
                            Vec::new(),
                        ),
                    )
                }
            };
        let Some(decision_digest) = evidence
            .decision
            .request
            .metadata
            .get(GATEWAY_AUTHORITY_DECISION_DIGEST_METADATA_KEY)
            .and_then(serde_json::Value::as_str)
        else {
            return AuthorityObligationVerification::Denied(authority_obligation_result(
                false,
                vec!["authority_decision_digest_missing".to_string()],
                "denied",
                Some(evidence),
                Some(expected_action_digest),
                Vec::new(),
                Vec::new(),
            ));
        };
        if decision_digest != expected_decision_digest {
            return AuthorityObligationVerification::Denied(authority_obligation_result(
                false,
                vec!["authority_decision_digest_mismatch".to_string()],
                "denied",
                Some(evidence),
                Some(expected_action_digest),
                Vec::new(),
                Vec::new(),
            ));
        }

        let validated_receipts =
            match self
                .ledger
                .validate_receipts(&evidence.receipts, &self.context, now)
            {
                Ok(receipts) => receipts,
                Err(error) => {
                    let status = if error.is_unavailable()
                        || error.reason_code() == "authority_obligation_receipt_clock_rollback"
                    {
                        "verifier_unavailable"
                    } else {
                        "denied"
                    };
                    let result = authority_obligation_result(
                        false,
                        vec![error.reason_code()],
                        status,
                        Some(evidence),
                        Some(expected_action_digest),
                        Vec::new(),
                        Vec::new(),
                    );
                    return if status == "verifier_unavailable" {
                        AuthorityObligationVerification::NeedsIntervention(result)
                    } else {
                        AuthorityObligationVerification::Denied(result)
                    };
                }
            };

        let verification = verify_obligation_receipts(&evidence.decision, &validated_receipts, now);
        if !verification.allowed {
            return AuthorityObligationVerification::Denied(authority_obligation_result(
                false,
                verification.reasons,
                "denied",
                Some(evidence),
                Some(expected_action_digest),
                verification
                    .satisfied_obligation_ids
                    .into_iter()
                    .map(|id| id.to_string())
                    .collect(),
                Vec::new(),
            ));
        }

        let mut result = authority_obligation_result(
            true,
            Vec::new(),
            "satisfied",
            Some(evidence),
            Some(expected_action_digest.clone()),
            verification
                .satisfied_obligation_ids
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
            evidence
                .receipts
                .iter()
                .map(|receipt| receipt.receipt_id.to_string())
                .collect(),
        );
        if attach_authority_decision_evidence_projection(&mut result, &evidence.decision).is_err() {
            return AuthorityObligationVerification::NeedsIntervention(
                authority_obligation_result(
                    false,
                    vec!["authority_decision_evidence_projection_unavailable".to_string()],
                    "evidence_projection_unavailable",
                    Some(evidence),
                    Some(expected_action_digest),
                    Vec::new(),
                    Vec::new(),
                ),
            );
        }
        AuthorityObligationVerification::Allowed(result)
    }

    fn claim_verified_receipts(
        &self,
        receipts: &[AuthorityObligationReceipt],
        now: OffsetDateTime,
    ) -> AuthorityObligationVerification {
        if receipts.is_empty() {
            return AuthorityObligationVerification::NotRequired;
        }

        match self.ledger.claim_receipts(receipts, &self.context, now) {
            Ok(permit) => AuthorityObligationVerification::Permitted {
                verification: VerificationResult::allow(),
                permit,
            },
            Err(error) => {
                let status = if error.is_unavailable()
                    || error.reason_code() == "authority_obligation_receipt_clock_rollback"
                {
                    "verifier_unavailable"
                } else {
                    "denied"
                };
                let result = authority_obligation_result(
                    false,
                    vec![error.reason_code()],
                    status,
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                );
                if status == "verifier_unavailable" {
                    AuthorityObligationVerification::NeedsIntervention(result)
                } else {
                    AuthorityObligationVerification::Denied(result)
                }
            }
        }
    }
}

/// Evaluates tripped circuit breakers before adapter execution.
pub trait CircuitBreakerEvaluator: Send + Sync {
    /// Verifies whether the action is allowed under the current breaker state.
    fn verify_action(
        &self,
        action: &ActionRequest,
        adapter: Option<&str>,
        runtime_identity: &RuntimeIdentityContext,
    ) -> VerificationResult;

    /// Verifies whether the runtime may accept new local work.
    fn verify_runtime_admission(
        &self,
        _runtime_identity: &RuntimeIdentityContext,
    ) -> VerificationResult {
        VerificationResult::allow()
    }
}

/// Circuit-breaker evaluator with no configured breakers.
#[derive(Clone, Debug, Default)]
pub struct NoopCircuitBreakerEvaluator;

impl CircuitBreakerEvaluator for NoopCircuitBreakerEvaluator {
    fn verify_action(
        &self,
        _action: &ActionRequest,
        _adapter: Option<&str>,
        _runtime_identity: &RuntimeIdentityContext,
    ) -> VerificationResult {
        VerificationResult::allow()
    }
}

/// Static local circuit-breaker evaluator used by the local config path.
#[derive(Clone, Debug, Default)]
pub struct StaticCircuitBreakerEvaluator {
    breakers: Vec<CircuitBreaker>,
}

impl StaticCircuitBreakerEvaluator {
    /// Creates an evaluator from explicit breaker control objects.
    pub fn new(breakers: Vec<CircuitBreaker>) -> Self {
        Self { breakers }
    }

    /// Returns configured breakers.
    pub fn breakers(&self) -> &[CircuitBreaker] {
        &self.breakers
    }
}

impl CircuitBreakerEvaluator for StaticCircuitBreakerEvaluator {
    fn verify_action(
        &self,
        action: &ActionRequest,
        adapter: Option<&str>,
        runtime_identity: &RuntimeIdentityContext,
    ) -> VerificationResult {
        evaluate_breakers(
            &self.breakers,
            runtime_identity,
            Some(action),
            adapter,
            false,
        )
    }

    fn verify_runtime_admission(
        &self,
        runtime_identity: &RuntimeIdentityContext,
    ) -> VerificationResult {
        evaluate_breakers(&self.breakers, runtime_identity, None, None, true)
    }
}

/// Invariant evaluator that checks declared conditions against satisfied lists.
#[derive(Clone, Debug, Default)]
pub struct SimpleInvariantEvaluator;

impl InvariantEvaluator for SimpleInvariantEvaluator {
    fn verify_pre(
        &self,
        action: &Action,
        satisfied_preconditions: &[String],
    ) -> VerificationResult {
        check_conditions(
            "precondition_missing",
            &action.preconditions,
            satisfied_preconditions,
        )
    }

    fn verify_post(
        &self,
        action: &Action,
        satisfied_postconditions: &[String],
    ) -> VerificationResult {
        check_conditions(
            "postcondition_missing",
            &action.postconditions,
            satisfied_postconditions,
        )
    }
}

#[derive(Clone)]
struct AdapterRegistration {
    adapter_id: String,
    adapter: Arc<dyn ActionAdapter>,
}

/// Gateway implementation that runs verifier pipelines before execution.
pub struct VerifiedActionGateway {
    adapters: HashMap<String, AdapterRegistration>,
    trusted_action_profiles: Option<HashMap<String, TrustedActionProfile>>,
    action_authority_evaluator: Arc<dyn ActionAuthorityEvaluator>,
    pre_effect_authority_recorder: Arc<dyn PreEffectAuthorityDecisionRecorder>,
    tenant_access: Arc<dyn TenantAccess>,
    invariant_evaluator: Arc<dyn InvariantEvaluator>,
    resource_boundary_verifier: Arc<dyn ResourceBoundaryVerifier>,
    approval_verifier: Arc<dyn ApprovalVerifier>,
    authority_obligation_verifier: Arc<dyn AuthorityObligationVerifier>,
    safety_verifier: Option<Arc<dyn SafetyVerifier>>,
    circuit_breaker_evaluator: Arc<dyn CircuitBreakerEvaluator>,
    runtime_identity: RuntimeIdentityContext,
}

impl VerifiedActionGateway {
    /// Creates a gateway with the provided tenant access.
    pub fn new(tenant_access: Arc<dyn TenantAccess>) -> Self {
        Self {
            adapters: HashMap::new(),
            trusted_action_profiles: None,
            action_authority_evaluator: Arc::new(NoActionAuthorityEvaluator),
            pre_effect_authority_recorder: Arc::new(NoPreEffectAuthorityDecisionRecorder),
            tenant_access,
            invariant_evaluator: Arc::new(SimpleInvariantEvaluator),
            resource_boundary_verifier: Arc::new(NoopResourceBoundaryVerifier),
            approval_verifier: Arc::new(NoApprovalVerifier),
            authority_obligation_verifier: Arc::new(NoAuthorityObligationVerifier),
            safety_verifier: None,
            circuit_breaker_evaluator: Arc::new(NoopCircuitBreakerEvaluator),
            runtime_identity: RuntimeIdentityContext::default(),
        }
    }

    /// Installs the live C02 evaluator required by this gateway composition.
    pub fn set_action_authority_evaluator(&mut self, evaluator: Arc<dyn ActionAuthorityEvaluator>) {
        self.action_authority_evaluator = evaluator;
    }

    /// Installs the durable recorder used after all pre-effect checks allow.
    pub fn set_pre_effect_authority_recorder(
        &mut self,
        recorder: Arc<dyn PreEffectAuthorityDecisionRecorder>,
    ) {
        self.pre_effect_authority_recorder = recorder;
    }

    /// Installs immutable server-owned action/adapter/permission profiles.
    /// Duplicate actions and empty semantic coordinates fail closed.
    pub fn set_trusted_action_profiles(
        &mut self,
        profiles: Vec<TrustedActionProfile>,
    ) -> Result<(), String> {
        let mut indexed = HashMap::new();
        for mut profile in profiles {
            if profile.action_name.trim().is_empty() || profile.adapter.trim().is_empty() {
                return Err("trusted_action_profile_invalid".to_string());
            }
            profile.required_permissions.sort();
            profile.required_permissions.dedup();
            if indexed
                .insert(profile.action_name.clone(), profile)
                .is_some()
            {
                return Err("trusted_action_profile_duplicate".to_string());
            }
        }
        self.trusted_action_profiles = Some(indexed);
        Ok(())
    }

    /// Registers an adapter for the given action name.
    pub fn register_adapter(
        &mut self,
        action_name: impl Into<String>,
        adapter_id: impl Into<String>,
        adapter: Arc<dyn ActionAdapter>,
    ) {
        self.adapters.insert(
            action_name.into(),
            AdapterRegistration {
                adapter_id: adapter_id.into(),
                adapter,
            },
        );
    }

    /// Overrides the invariant evaluator used by the gateway.
    pub fn set_invariant_evaluator(&mut self, evaluator: Arc<dyn InvariantEvaluator>) {
        self.invariant_evaluator = evaluator;
    }

    /// Overrides the resource boundary verifier used before adapter execution.
    pub fn set_resource_boundary_verifier(&mut self, verifier: Arc<dyn ResourceBoundaryVerifier>) {
        self.resource_boundary_verifier = verifier;
    }

    /// Overrides the approval verifier used by the gateway.
    pub fn set_approval_verifier(&mut self, verifier: Arc<dyn ApprovalVerifier>) {
        self.approval_verifier = verifier;
    }

    /// Overrides the authority obligation verifier used before adapter execution.
    pub fn set_authority_obligation_verifier(
        &mut self,
        verifier: Arc<dyn AuthorityObligationVerifier>,
    ) {
        self.authority_obligation_verifier = verifier;
    }

    /// Overrides the local physical safety verifier used by the gateway.
    pub fn set_safety_verifier(&mut self, verifier: Arc<dyn SafetyVerifier>) {
        self.safety_verifier = Some(verifier);
    }

    /// Overrides the circuit-breaker evaluator used by the gateway.
    pub fn set_circuit_breaker_evaluator(&mut self, evaluator: Arc<dyn CircuitBreakerEvaluator>) {
        self.circuit_breaker_evaluator = evaluator;
    }

    /// Sets runtime identity used for fleet/node/instance scoped breakers.
    pub fn set_runtime_identity(&mut self, identity: RuntimeIdentityContext) {
        self.runtime_identity = identity;
    }

    /// Evaluates runtime-scoped breakers before accepting new local work.
    pub fn verify_runtime_admission(&self) -> VerificationResult {
        self.circuit_breaker_evaluator
            .verify_runtime_admission(&self.runtime_identity)
    }
}

impl ActionGateway for VerifiedActionGateway {
    fn submit(&self, action: ActionRequest) -> Result<ActionOutcome, GatewayError> {
        if guard_action_request(&action).is_err() {
            return Ok(raw_credential_denied_outcome(action.action_id));
        }
        if let Err(error) = action.validate_identity() {
            return Ok(identity_denied_outcome(action.action_id, error));
        }

        if let Some(mut verification) = verify_physical_action_boundary(&action) {
            attach_request_context(&mut verification, &action);
            return Ok(denied_outcome(action.action_id, verification));
        }

        if action.authority_obligation_receipts.len() > 64 {
            let mut verification =
                VerificationResult::deny("authority_obligation_receipt_limit_exceeded");
            attach_request_context(&mut verification, &action);
            return Ok(denied_outcome(action.action_id, verification));
        }
        let receipt_ids = action
            .authority_obligation_receipts
            .iter()
            .map(|receipt| receipt.receipt_id.clone())
            .collect::<HashSet<_>>();
        if receipt_ids.len() != action.authority_obligation_receipts.len() {
            let mut verification = VerificationResult::deny("duplicate_obligation_receipt_id");
            attach_request_context(&mut verification, &action);
            return Ok(denied_outcome(action.action_id, verification));
        }

        let registration = self.adapters.get(&action.action.name);
        let authority_adapter = action
            .adapter
            .as_deref()
            .or_else(|| registration.map(|entry| entry.adapter_id.as_str()));
        if let Some(profiles) = self.trusted_action_profiles.as_ref() {
            let Some(profile) = profiles.get(&action.action.name) else {
                let mut verification = VerificationResult::deny("trusted_action_profile_missing");
                attach_request_context(&mut verification, &action);
                return Ok(denied_outcome(action.action_id, verification));
            };
            if authority_adapter != Some(profile.adapter.as_str()) {
                let mut verification =
                    VerificationResult::deny("trusted_action_profile_adapter_mismatch");
                attach_request_context(&mut verification, &action);
                return Ok(denied_outcome(action.action_id, verification));
            }
            let requested_permissions = action
                .action
                .required_permissions
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let required_permissions = profile
                .required_permissions
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            if requested_permissions != required_permissions
                || requested_permissions.len() != action.action.required_permissions.len()
            {
                let mut verification =
                    VerificationResult::deny("trusted_action_profile_permission_mismatch");
                attach_request_context(&mut verification, &action);
                return Ok(denied_outcome(action.action_id, verification));
            }
        }
        let prepared_authority = match self.action_authority_evaluator.evaluate_action_authority(
            &action,
            authority_adapter,
            OffsetDateTime::now_utc(),
        ) {
            ActionAuthorityEvaluation::NotRequired => None,
            ActionAuthorityEvaluation::Evaluated(decisions) => {
                match prepare_action_authority(decisions, &action, authority_adapter) {
                    PreparedActionAuthority::Allowed(prepared) => Some(prepared),
                    PreparedActionAuthority::Denied(mut result) => {
                        attach_request_context(&mut result, &action);
                        return Ok(denied_outcome(action.action_id, result));
                    }
                    PreparedActionAuthority::NeedsApproval(mut result) => {
                        attach_request_context(&mut result, &action);
                        return Ok(needs_approval_outcome(action.action_id, result));
                    }
                    PreparedActionAuthority::NeedsIntervention(mut result) => {
                        attach_request_context(&mut result, &action);
                        return Ok(needs_intervention_outcome(action.action_id, result));
                    }
                }
            }
        };

        let registration = registration
            .ok_or_else(|| GatewayError::AdapterFailed("adapter not registered".to_string()))?;
        if let Some(adapter) = action.adapter.as_deref() {
            if adapter != registration.adapter_id {
                let verification = VerificationResult {
                    allowed: false,
                    reasons: vec!["adapter_mismatch".to_string()],
                    artifacts: serde_json::json!({
                        "context": request_context(&action, vec!["adapter".to_string()]),
                        "requested": adapter,
                        "registered": registration.adapter_id,
                    }),
                };
                return Ok(ActionOutcome {
                    action_id: action.action_id,
                    status: ActionStatus::Denied,
                    verification,
                    post_verification: None,
                    output: None,
                    error: Some("adapter_mismatch".to_string()),
                    approval_challenge: None,
                    completed_at: OffsetDateTime::now_utc(),
                });
            }
        }
        let adapter_id = action
            .adapter
            .as_deref()
            .unwrap_or(registration.adapter_id.as_str());

        let breaker_action = action_request_with_effective_side_effect_class(&action, adapter_id);
        let breaker_result = self.circuit_breaker_evaluator.verify_action(
            &breaker_action,
            Some(adapter_id),
            &self.runtime_identity,
        );
        if !breaker_result.allowed {
            let mut verification = combine_verifications([("circuit_breaker", breaker_result)]);
            attach_request_context(&mut verification, &action);
            return Ok(denied_outcome(action.action_id, verification));
        }

        if let Some(verification) = verify_declared_side_effect_class(&action, adapter_id) {
            let mut verification = combine_verifications([("side_effect_class", verification)]);
            attach_request_context(&mut verification, &action);
            return Ok(denied_outcome(action.action_id, verification));
        }

        let policy_result = self.tenant_access.verify_policy(
            &action.tenant_id,
            &action.agent_id,
            &action.action,
            Some(adapter_id),
        );
        let invariant_pre = self
            .invariant_evaluator
            .verify_pre(&action.action, &action.satisfied_preconditions);
        let mut verification =
            combine_verifications([("policy", policy_result), ("invariant", invariant_pre)]);

        if !verification.allowed {
            attach_request_context(&mut verification, &action);
            return Ok(denied_outcome(action.action_id, verification));
        }

        let resource_result = self
            .resource_boundary_verifier
            .verify_resource_boundary(&action, Some(adapter_id));
        if !resource_result.allowed {
            let mut verification = combine_verifications([("resource_boundary", resource_result)]);
            attach_request_context(&mut verification, &action);
            return Ok(denied_outcome(action.action_id, verification));
        }

        let approval_verification = self.approval_verifier.verify_approval(
            &action,
            Some(adapter_id),
            OffsetDateTime::now_utc(),
        );
        let approval_verification = match approval_verification {
            ApprovalVerification::Granted(mut result)
                if action.approval_evidence.is_some()
                    && action.authority_obligation_receipts.is_empty() =>
            {
                result.allowed = false;
                if !result
                    .reasons
                    .iter()
                    .any(|reason| reason == "approval_obligation_receipt_required")
                {
                    result
                        .reasons
                        .push("approval_obligation_receipt_required".to_string());
                }
                ApprovalVerification::Required(result)
            }
            other => other,
        };
        let approval_grant = match approval_verification {
            ApprovalVerification::NotRequired => None,
            ApprovalVerification::Granted(result) => Some(result),
            ApprovalVerification::Deferred => None,
            ApprovalVerification::Required(mut result) => {
                let challenge = match prepared_authority.as_deref() {
                    Some(prepared) => {
                        match approval_challenge_from_prepared(prepared, &action, Some(adapter_id))
                        {
                            Ok(challenge) => challenge,
                            Err(reason) => {
                                let mut result = VerificationResult::deny(reason);
                                attach_request_context(&mut result, &action);
                                return Ok(needs_intervention_outcome(action.action_id, result));
                            }
                        }
                    }
                    None => None,
                };
                if let Some(challenge) = challenge.as_ref() {
                    if let Err(reason) = bind_approval_result_to_challenge(&mut result, challenge) {
                        let mut result = VerificationResult::deny(reason);
                        attach_request_context(&mut result, &action);
                        return Ok(needs_intervention_outcome(action.action_id, result));
                    }
                }
                attach_request_context(&mut result, &action);
                return Ok(needs_approval_outcome_with_challenge(
                    action.action_id,
                    result,
                    challenge,
                ));
            }
            ApprovalVerification::Denied(mut result) => {
                attach_request_context(&mut result, &action);
                return Ok(denied_outcome(action.action_id, result));
            }
            ApprovalVerification::NeedsIntervention(mut result) => {
                attach_request_context(&mut result, &action);
                return Ok(needs_intervention_outcome(action.action_id, result));
            }
        };

        let quota_result = self.tenant_access.verify_quota(
            &action.tenant_id,
            &action.agent_id,
            action.quota_usage,
        );
        verification = combine_verifications([("quota", quota_result)]);
        if !verification.allowed {
            attach_request_context(&mut verification, &action);
            return Ok(denied_outcome(action.action_id, verification));
        }
        if let Some(approval_grant) = approval_grant {
            attach_allowed_artifact(&mut verification, "approval", approval_grant.artifacts);
        }
        if let Some(authority) = prepared_authority.as_ref() {
            attach_allowed_artifact(
                &mut verification,
                "authority",
                authority.verification.artifacts.clone(),
            );
        }

        match verify_safety_pre(&self.safety_verifier, &action, Some(adapter_id)) {
            SafetyVerification::NotRequired => {}
            SafetyVerification::Allowed(safety_result) => {
                attach_allowed_artifact(&mut verification, "safety", safety_result.artifacts);
            }
            SafetyVerification::Denied(mut safety_result) => {
                attach_request_context(&mut safety_result, &action);
                return Ok(denied_outcome(action.action_id, safety_result));
            }
            SafetyVerification::NeedsIntervention(mut safety_result) => {
                attach_request_context(&mut safety_result, &action);
                return Ok(needs_intervention_outcome(action.action_id, safety_result));
            }
        }

        let (effect_permit, final_prepared_authority) = if let Some(prepared) =
            prepared_authority.as_ref()
        {
            match self.action_authority_evaluator.acquire_final_effect_permit(
                &action,
                Some(adapter_id),
                &prepared.decisions,
                OffsetDateTime::now_utc(),
            ) {
                FinalEffectAuthorityEvaluation::NotRequired => {
                    let mut result =
                        VerificationResult::deny("final_effect_authority_permit_unavailable");
                    attach_request_context(&mut result, &action);
                    return Ok(needs_intervention_outcome(action.action_id, result));
                }
                FinalEffectAuthorityEvaluation::Denied(decisions) => {
                    return Ok(final_authority_non_permit_outcome(
                        decisions,
                        &action,
                        Some(adapter_id),
                    ));
                }
                FinalEffectAuthorityEvaluation::Permitted { decisions, permit } => {
                    if !authority_decision_semantics_match(&prepared.decisions, &decisions) {
                        let mut result =
                            VerificationResult::deny("final_effect_authority_generation_mismatch");
                        attach_request_context(&mut result, &action);
                        return Ok(needs_intervention_outcome(action.action_id, result));
                    }
                    let final_prepared =
                        match prepare_action_authority(decisions, &action, Some(adapter_id)) {
                            PreparedActionAuthority::Allowed(prepared) => prepared,
                            PreparedActionAuthority::Denied(mut result) => {
                                attach_request_context(&mut result, &action);
                                return Ok(denied_outcome(action.action_id, result));
                            }
                            PreparedActionAuthority::NeedsApproval(mut result) => {
                                attach_request_context(&mut result, &action);
                                return Ok(needs_approval_outcome(action.action_id, result));
                            }
                            PreparedActionAuthority::NeedsIntervention(mut result) => {
                                attach_request_context(&mut result, &action);
                                return Ok(needs_intervention_outcome(action.action_id, result));
                            }
                        };
                    attach_allowed_artifact(
                        &mut verification,
                        "authority",
                        final_prepared.verification.artifacts.clone(),
                    );
                    (Some(permit), Some(final_prepared))
                }
            }
        } else {
            match self.action_authority_evaluator.acquire_final_effect_permit(
                &action,
                Some(adapter_id),
                &[],
                OffsetDateTime::now_utc(),
            ) {
                FinalEffectAuthorityEvaluation::NotRequired => (None, None),
                _ => {
                    let mut result =
                        VerificationResult::deny("unexpected_final_effect_authority_permit");
                    attach_request_context(&mut result, &action);
                    return Ok(needs_intervention_outcome(action.action_id, result));
                }
            }
        };

        // Receipt validation and one-use consumption are deliberately last:
        // every potentially blocking verifier and the final live-authority
        // linearization have completed, while durable evidence and the adapter
        // remain ahead. This prevents a receipt that expires during verifier
        // work from reaching an effect.
        let final_approval_challenge = match final_prepared_authority.as_deref() {
            Some(prepared) => {
                match approval_challenge_from_prepared(prepared, &action, Some(adapter_id)) {
                    Ok(challenge) => challenge,
                    Err(reason) => {
                        let mut result = VerificationResult::deny(reason);
                        attach_request_context(&mut result, &action);
                        return Ok(needs_intervention_outcome(action.action_id, result));
                    }
                }
            }
            None => None,
        };
        let mut authority_obligation_grants = Vec::new();
        let receipts_to_consume = if let Some(prepared) = final_prepared_authority.as_ref() {
            if prepared.conditional_decisions.is_empty() {
                if !action.authority_obligation_receipts.is_empty()
                    || action.authority_obligation_evidence.is_some()
                {
                    let mut result = VerificationResult::deny(
                        "authority_obligation_receipts_without_current_conditional_decision",
                    );
                    attach_request_context(&mut result, &action);
                    return Ok(denied_outcome(action.action_id, result));
                }
            } else {
                if action.authority_obligation_evidence.is_some() {
                    let mut result =
                        VerificationResult::deny("requester_authority_decision_non_authorizing");
                    attach_request_context(&mut result, &action);
                    return Ok(needs_intervention_outcome(action.action_id, result));
                }
                let current_decision_ids = prepared
                    .conditional_decisions
                    .iter()
                    .map(|decision| decision.decision_id.clone())
                    .collect::<HashSet<_>>();
                if action
                    .authority_obligation_receipts
                    .iter()
                    .any(|receipt| !current_decision_ids.contains(&receipt.authority_decision_id))
                {
                    let mut result = VerificationResult::deny(
                        "authority_obligation_receipt_unmatched_current_decision",
                    );
                    attach_request_context(&mut result, &action);
                    return Ok(denied_outcome(action.action_id, result));
                }
                for decision in &prepared.conditional_decisions {
                    let obligation_action =
                        match action_with_current_authority_decision(&action, decision.clone()) {
                            Ok(action) => action,
                            Err(mut result) => {
                                attach_request_context(&mut result, &action);
                                return Ok(needs_intervention_outcome(action.action_id, result));
                            }
                        };
                    match self.authority_obligation_verifier.verify_obligations(
                        &obligation_action,
                        Some(adapter_id),
                        OffsetDateTime::now_utc(),
                    ) {
                        AuthorityObligationVerification::Allowed(result) => {
                            authority_obligation_grants.push(result)
                        }
                        AuthorityObligationVerification::NotRequired => {
                            let mut result = VerificationResult::deny(
                                "authority_obligation_verifier_did_not_evaluate",
                            );
                            attach_request_context(&mut result, &action);
                            return Ok(needs_intervention_outcome(action.action_id, result));
                        }
                        AuthorityObligationVerification::Denied(mut result) => {
                            attach_request_context(&mut result, &action);
                            return Ok(denied_outcome(action.action_id, result));
                        }
                        AuthorityObligationVerification::NeedsIntervention(mut result) => {
                            attach_request_context(&mut result, &action);
                            return Ok(needs_intervention_outcome(action.action_id, result));
                        }
                        AuthorityObligationVerification::Permitted { .. } => {
                            let mut result = VerificationResult::deny(
                                "authority_obligation_receipt_claimed_before_final_boundary",
                            );
                            attach_request_context(&mut result, &action);
                            return Ok(needs_intervention_outcome(action.action_id, result));
                        }
                    }
                }
            }
            action.authority_obligation_receipts.as_slice()
        } else {
            if !action.authority_obligation_receipts.is_empty() {
                let mut result = VerificationResult::deny(
                    "authority_obligation_current_decision_evaluator_unavailable",
                );
                attach_request_context(&mut result, &action);
                return Ok(needs_intervention_outcome(action.action_id, result));
            }
            match self.authority_obligation_verifier.verify_obligations(
                &action,
                Some(adapter_id),
                OffsetDateTime::now_utc(),
            ) {
                AuthorityObligationVerification::NotRequired => {}
                AuthorityObligationVerification::Allowed(result) => {
                    authority_obligation_grants.push(result)
                }
                AuthorityObligationVerification::Denied(mut result) => {
                    attach_request_context(&mut result, &action);
                    return Ok(denied_outcome(action.action_id, result));
                }
                AuthorityObligationVerification::NeedsIntervention(mut result) => {
                    attach_request_context(&mut result, &action);
                    return Ok(needs_intervention_outcome(action.action_id, result));
                }
                AuthorityObligationVerification::Permitted { .. } => {
                    let mut result = VerificationResult::deny(
                        "authority_obligation_receipt_claimed_before_final_boundary",
                    );
                    attach_request_context(&mut result, &action);
                    return Ok(needs_intervention_outcome(action.action_id, result));
                }
            }
            action
                .authority_obligation_evidence
                .as_ref()
                .map(|evidence| evidence.receipts.as_slice())
                .unwrap_or_default()
        };

        let mut obligation_effect_permit = None;
        if !authority_obligation_grants.is_empty() {
            match self
                .authority_obligation_verifier
                .claim_verified_receipts(receipts_to_consume, OffsetDateTime::now_utc())
            {
                AuthorityObligationVerification::Permitted {
                    verification: claim_verification,
                    permit,
                } => {
                    if !claim_verification.allowed {
                        let mut result =
                            VerificationResult::deny("authority_obligation_receipt_claim_invalid");
                        attach_request_context(&mut result, &action);
                        return Ok(needs_intervention_outcome(action.action_id, result));
                    }
                    obligation_effect_permit = Some(permit);
                }
                AuthorityObligationVerification::Allowed(_) => {
                    let mut result =
                        VerificationResult::deny("authority_obligation_effect_permit_unavailable");
                    attach_request_context(&mut result, &action);
                    return Ok(needs_intervention_outcome(action.action_id, result));
                }
                AuthorityObligationVerification::NotRequired => {
                    let mut result = VerificationResult::deny(
                        "authority_obligation_verifier_did_not_consume_receipts",
                    );
                    attach_request_context(&mut result, &action);
                    return Ok(needs_intervention_outcome(action.action_id, result));
                }
                AuthorityObligationVerification::Denied(mut result) => {
                    attach_request_context(&mut result, &action);
                    return Ok(denied_outcome(action.action_id, result));
                }
                AuthorityObligationVerification::NeedsIntervention(mut result) => {
                    attach_request_context(&mut result, &action);
                    return Ok(needs_intervention_outcome(action.action_id, result));
                }
            }
            let artifacts = if authority_obligation_grants.len() == 1 {
                authority_obligation_grants.remove(0).artifacts
            } else {
                serde_json::json!({
                    "decisions": authority_obligation_grants
                        .into_iter()
                        .map(|result| result.artifacts)
                        .collect::<Vec<_>>(),
                })
            };
            attach_allowed_artifact(&mut verification, "authority_obligation", artifacts);
            if let Some(challenge) = final_approval_challenge.as_ref() {
                let Some(receipt) = action.authority_obligation_receipts.iter().find(|receipt| {
                    receipt.authority_decision_id == challenge.authority_decision_id
                        && receipt.obligation_id == challenge.obligation_id
                }) else {
                    let mut result =
                        VerificationResult::deny("approval_obligation_receipt_missing_after_claim");
                    attach_request_context(&mut result, &action);
                    return Ok(needs_intervention_outcome(action.action_id, result));
                };
                let approval = ApprovalTraceContext {
                    approval_id: challenge.approval_id.clone(),
                    tenant_id: challenge.tenant_id.clone(),
                    agent_id: challenge.agent_id.clone(),
                    run_id: challenge.run_id.clone(),
                    action_id: Some(challenge.action_id.clone()),
                    action_name: challenge.action_name.clone(),
                    adapter: Some(challenge.adapter.clone()),
                    decision: Some(ApprovalDecision::Granted),
                    reason: Some("authority_obligation_receipt_validated".to_string()),
                    policy_id: Some(challenge.policy_id.clone()),
                    risk_level: challenge.risk_level.clone(),
                    issued_at: Some(receipt.issued_at),
                    expires_at: Some(receipt.expires_at),
                    revoked: false,
                };
                let result = approval_result(
                    true,
                    "approval_granted",
                    "granted",
                    approval,
                    Some(challenge.policy_id.clone()),
                );
                attach_allowed_artifact(&mut verification, "approval", result.artifacts);
            }
        }

        let requires_pre_effect_record =
            prepared_authority.is_some() || obligation_effect_permit.is_some();
        if requires_pre_effect_record {
            for key in ["authority", "authority_obligation"] {
                if verification.artifacts.get(key).is_none() {
                    continue;
                }
                let authority_artifact = verification
                    .artifacts
                    .get_mut(key)
                    .and_then(serde_json::Value::as_object_mut)
                    .ok_or_else(|| {
                        GatewayError::VerificationFailed(
                            "authority_evidence_projection_unavailable".to_string(),
                        )
                    })?;
                authority_artifact.insert(
                    "pre_effect_recorded".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
            if let Err(reason) = self
                .pre_effect_authority_recorder
                .record_pre_effect_authority_allow(&action, &verification)
            {
                for key in ["authority", "authority_obligation"] {
                    if let Some(authority_artifact) = verification
                        .artifacts
                        .get_mut(key)
                        .and_then(serde_json::Value::as_object_mut)
                    {
                        authority_artifact.insert(
                            "pre_effect_recorded".to_string(),
                            serde_json::Value::Bool(false),
                        );
                    }
                }
                let mut result = VerificationResult::deny("authority_evidence_append_failed");
                result.artifacts = serde_json::json!({
                    "authority": verification.artifacts.get("authority").cloned(),
                    "authority_obligation": verification.artifacts.get("authority_obligation").cloned(),
                    "recorder_reason": bounded_recorder_reason(&reason),
                });
                attach_request_context(&mut result, &action);
                return Ok(needs_intervention_outcome(action.action_id, result));
            }
        }

        let adapter_result = match registration.adapter.execute(&action) {
            Ok(result) => result,
            Err(_error) => {
                return Ok(ActionOutcome {
                    action_id: action.action_id,
                    status: ActionStatus::Failed,
                    verification,
                    post_verification: None,
                    output: None,
                    // AdapterError::Failed contains provider-controlled human text.
                    // Keep public outcomes bounded and non-authorizing; the stable
                    // taxonomy remains unknown/non-retryable/effect-uncertain.
                    error: Some("adapter failed".to_string()),
                    approval_challenge: None,
                    completed_at: OffsetDateTime::now_utc(),
                });
            }
        };
        drop((effect_permit, obligation_effect_permit));

        let post_verification = self
            .invariant_evaluator
            .verify_post(&action.action, &adapter_result.satisfied_postconditions);
        let post_safety = verify_safety_post(
            &self.safety_verifier,
            &action,
            Some(adapter_id),
            &adapter_result,
        );
        let post_verification = combine_post_verifications(post_verification, post_safety);
        let status = if post_verification.allowed {
            ActionStatus::Executed
        } else {
            ActionStatus::Failed
        };
        let error = if post_verification.allowed {
            None
        } else {
            Some(post_verification.reasons.join(", "))
        };

        Ok(ActionOutcome {
            action_id: action.action_id,
            status,
            verification,
            post_verification: Some(post_verification),
            output: Some(adapter_result.output),
            error,
            approval_challenge: None,
            completed_at: OffsetDateTime::now_utc(),
        })
    }
}

struct PreparedAuthorityAllow {
    verification: VerificationResult,
    decisions: Vec<AuthorityDecision>,
    conditional_decisions: Vec<AuthorityDecision>,
}

enum PreparedActionAuthority {
    Allowed(Box<PreparedAuthorityAllow>),
    Denied(VerificationResult),
    NeedsApproval(VerificationResult),
    NeedsIntervention(VerificationResult),
}

fn final_authority_non_permit_outcome(
    decisions: Vec<AuthorityDecision>,
    action: &ActionRequest,
    effective_adapter: Option<&str>,
) -> ActionOutcome {
    match prepare_action_authority(decisions, action, effective_adapter) {
        PreparedActionAuthority::Denied(mut result) => {
            attach_request_context(&mut result, action);
            denied_outcome(action.action_id.clone(), result)
        }
        PreparedActionAuthority::NeedsApproval(mut result) => {
            attach_request_context(&mut result, action);
            needs_approval_outcome(action.action_id.clone(), result)
        }
        PreparedActionAuthority::NeedsIntervention(mut result) => {
            attach_request_context(&mut result, action);
            needs_intervention_outcome(action.action_id.clone(), result)
        }
        PreparedActionAuthority::Allowed(_) => {
            let mut result = VerificationResult::deny("final_effect_authority_permit_missing");
            attach_request_context(&mut result, action);
            needs_intervention_outcome(action.action_id.clone(), result)
        }
    }
}

fn authority_decision_semantics_match(
    expected: &[AuthorityDecision],
    current: &[AuthorityDecision],
) -> bool {
    let mut expected = expected.to_vec();
    let mut current = current.to_vec();
    expected.sort_by(|left, right| left.request.operation.cmp(&right.request.operation));
    current.sort_by(|left, right| left.request.operation.cmp(&right.request.operation));
    expected.len() == current.len()
        && expected.iter().zip(&current).all(|(expected, current)| {
            expected.request.operation == current.request.operation
                && expected.request.scope == current.request.scope
                && expected.status == current.status
                && expected.matched_grant_ids == current.matched_grant_ids
                && expected.obligations == current.obligations
        })
}

fn prepare_action_authority(
    mut decisions: Vec<AuthorityDecision>,
    action: &ActionRequest,
    effective_adapter: Option<&str>,
) -> PreparedActionAuthority {
    if decisions.is_empty() {
        return PreparedActionAuthority::NeedsIntervention(VerificationResult::deny(
            "authority_decision_unavailable",
        ));
    }

    if !authority_decisions_match_request(&decisions, action, effective_adapter) {
        return PreparedActionAuthority::NeedsIntervention(VerificationResult::deny(
            "authority_decision_request_mismatch",
        ));
    }

    if decisions.iter().any(|decision| {
        matches!(
            decision.status,
            AuthorityDecisionStatus::Allowed | AuthorityDecisionStatus::Conditional
        ) && decision.matched_grant_ids.is_empty()
    }) {
        return PreparedActionAuthority::NeedsIntervention(VerificationResult::deny(
            "authority_decision_grant_evidence_missing",
        ));
    }

    let denied = decisions
        .iter()
        .any(|decision| decision.status == AuthorityDecisionStatus::Denied);
    let needs_intervention = decisions
        .iter()
        .any(|decision| decision.status == AuthorityDecisionStatus::NeedsIntervention);
    let needs_approval = decisions
        .iter()
        .any(|decision| decision.status == AuthorityDecisionStatus::NeedsApproval);

    for decision in &mut decisions {
        if decision.status == AuthorityDecisionStatus::Conditional {
            *decision = match bind_current_gateway_authority_decision(
                decision.clone(),
                action,
                effective_adapter,
            ) {
                Ok(bound) => bound,
                Err(reason) => {
                    return PreparedActionAuthority::NeedsIntervention(VerificationResult::deny(
                        reason,
                    ))
                }
            };
        }
    }
    let conditional_decisions = decisions
        .iter()
        .filter(|decision| decision.status == AuthorityDecisionStatus::Conditional)
        .cloned()
        .collect::<Vec<_>>();

    let summaries = match decisions
        .iter()
        .map(gateway_authority_decision_summary)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(summaries) => summaries,
        Err(reason) => {
            return PreparedActionAuthority::NeedsIntervention(VerificationResult::deny(reason))
        }
    };
    let mut reasons = Vec::new();
    for (decision, summary) in decisions.iter().zip(&summaries) {
        for reason in &summary.reason_codes {
            push_unique_string(&mut reasons, reason.clone());
        }
        if decision.status == AuthorityDecisionStatus::Denied {
            let compatibility_reason = match decision.request.operation.resource_kind {
                AuthorityResourceKind::Action => Some("action_not_allowed"),
                AuthorityResourceKind::Adapter => Some("adapter_not_allowed"),
                AuthorityResourceKind::Permission => Some("permission_denied"),
                _ => None,
            };
            if let Some(reason) = compatibility_reason {
                push_unique_string(&mut reasons, reason.to_string());
            }
        }
    }
    let result = VerificationResult {
        allowed: !denied && !needs_intervention && !needs_approval,
        reasons: if denied || needs_intervention || needs_approval {
            reasons
        } else {
            Vec::new()
        },
        artifacts: serde_json::json!({
            "schema_version": "splendor.gateway.authority_evidence.v1",
            "decisions": summaries,
            "pre_effect_recorded": false,
        }),
    };
    if denied {
        PreparedActionAuthority::Denied(result)
    } else if needs_intervention {
        PreparedActionAuthority::NeedsIntervention(result)
    } else if needs_approval {
        PreparedActionAuthority::NeedsApproval(result)
    } else {
        PreparedActionAuthority::Allowed(Box::new(PreparedAuthorityAllow {
            verification: result,
            decisions,
            conditional_decisions,
        }))
    }
}

fn authority_decisions_match_request(
    decisions: &[AuthorityDecision],
    action: &ActionRequest,
    effective_adapter: Option<&str>,
) -> bool {
    let mut expected_operations = vec![gateway_action_operation(action.action.name.clone())];
    if let Some(adapter) = effective_adapter {
        expected_operations.push(gateway_adapter_operation(adapter));
    }
    expected_operations.extend(
        action
            .action
            .required_permissions
            .iter()
            .cloned()
            .map(compatibility_permission_operation),
    );
    expected_operations.sort();

    let mut actual_operations = decisions
        .iter()
        .map(|decision| decision.request.operation.clone())
        .collect::<Vec<_>>();
    actual_operations.sort();

    expected_operations == actual_operations
        && decisions.iter().all(|decision| {
            decision.request.scope.tenant_ids.as_deref()
                == Some(std::slice::from_ref(&action.tenant_id))
                && decision.request.scope.agent_ids.as_deref()
                    == Some(std::slice::from_ref(&action.agent_id))
                && decision.request.scope.run_ids.as_deref()
                    == Some(std::slice::from_ref(&action.run_id))
        })
}

fn gateway_authority_decision_summary(
    decision: &AuthorityDecision,
) -> Result<GatewayAuthorityDecisionSummary, &'static str> {
    let evidence = authority_decision_evidence(decision)
        .and_then(|evidence| evidence.redacted())
        .map_err(|_| "authority_decision_evidence_projection_unavailable")?;
    Ok(GatewayAuthorityDecisionSummary {
        decision_id: evidence.decision_id,
        status: evidence.status,
        namespace: evidence.operation.namespace,
        resource_kind: evidence.operation.resource_kind,
        verb: evidence.operation.verb,
        decision_digest: evidence.decision_digest,
        reason_codes: evidence.reason_codes,
        matched_grant_ids: evidence.matched_grant_ids,
        obligation_ids: evidence
            .obligations
            .into_iter()
            .map(|obligation| obligation.obligation_id)
            .collect(),
    })
}

fn bind_current_gateway_authority_decision(
    mut decision: AuthorityDecision,
    action: &ActionRequest,
    effective_adapter: Option<&str>,
) -> Result<AuthorityDecision, String> {
    let action_digest = canonical_gateway_authority_action_digest(action, effective_adapter)?;
    decision.request.metadata.insert(
        GATEWAY_AUTHORITY_ACTION_DIGEST_METADATA_KEY.to_string(),
        serde_json::Value::String(action_digest),
    );
    let decision_digest = canonical_gateway_authority_decision_digest(&decision)?;
    decision.request.metadata.insert(
        GATEWAY_AUTHORITY_DECISION_DIGEST_METADATA_KEY.to_string(),
        serde_json::Value::String(decision_digest),
    );
    Ok(decision)
}

fn approval_challenge_from_prepared(
    prepared: &PreparedAuthorityAllow,
    action: &ActionRequest,
    effective_adapter: Option<&str>,
) -> Result<Option<ApprovalChallenge>, String> {
    let mut matching = Vec::new();
    for decision in &prepared.conditional_decisions {
        for obligation in &decision.obligations {
            if obligation.kind == AuthorityObligationKind::ApprovalRequired
                && obligation
                    .parameters
                    .contains_key(APPROVAL_OBLIGATION_APPROVAL_ID)
            {
                matching.push((decision, obligation));
            }
        }
    }
    if matching.is_empty() {
        return Ok(None);
    }
    if matching.len() != 1 {
        return Err("approval_challenge_ambiguous".to_string());
    }
    let (decision, obligation) = matching[0];
    if decision.status != AuthorityDecisionStatus::Conditional
        || decision.obligations.len() != 1
        || decision.request.operation != gateway_action_operation(&action.action.name)
    {
        return Err("approval_challenge_decision_invalid".to_string());
    }
    let parameters = &obligation.parameters;
    let has_risk_level = parameters.contains_key(APPROVAL_OBLIGATION_RISK_LEVEL);
    if parameters.len() != if has_risk_level { 9 } else { 8 } {
        return Err("approval_challenge_parameters_invalid".to_string());
    }
    let approval_id = ApprovalId::parse(required_obligation_parameter(
        parameters,
        APPROVAL_OBLIGATION_APPROVAL_ID,
    )?)
    .map_err(|_| "approval_challenge_approval_id_invalid".to_string())?;
    let obligation_action_id = ActionId::parse(required_obligation_parameter(
        parameters,
        APPROVAL_OBLIGATION_ACTION_ID,
    )?)
    .map_err(|_| "approval_challenge_action_id_invalid".to_string())?;
    let action_name = required_obligation_parameter(parameters, APPROVAL_OBLIGATION_ACTION_NAME)?;
    let adapter = required_obligation_parameter(parameters, APPROVAL_OBLIGATION_ADAPTER)?;
    let policy_id = required_obligation_parameter(parameters, APPROVAL_OBLIGATION_POLICY_ID)?;
    let receipt_audience =
        required_obligation_parameter(parameters, APPROVAL_OBLIGATION_RECEIPT_AUDIENCE)?;
    let expires_at = OffsetDateTime::parse(
        required_obligation_parameter(parameters, APPROVAL_OBLIGATION_EXPIRES_AT)?,
        &Rfc3339,
    )
    .map_err(|_| "approval_challenge_expiry_invalid".to_string())?;
    let action_digest =
        required_obligation_parameter(parameters, APPROVAL_OBLIGATION_ACTION_DIGEST)?;
    let expected_action_digest =
        canonical_gateway_authority_action_digest(action, effective_adapter)?;
    let bound_action_digest = decision
        .request
        .metadata
        .get(GATEWAY_AUTHORITY_ACTION_DIGEST_METADATA_KEY)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "approval_challenge_action_digest_missing".to_string())?;
    let decision_digest = decision
        .request
        .metadata
        .get(GATEWAY_AUTHORITY_DECISION_DIGEST_METADATA_KEY)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "approval_challenge_decision_digest_missing".to_string())?;
    let expected_decision_digest = canonical_gateway_authority_decision_digest(decision)?;
    if obligation_action_id != action.action_id
        || action_name != action.action.name
        || Some(adapter) != effective_adapter
        || policy_id.trim().is_empty()
        || action_digest != expected_action_digest
        || bound_action_digest != expected_action_digest
        || decision_digest != expected_decision_digest
        || decision.request.scope.audiences.as_deref() != Some(&[receipt_audience.to_string()])
        || expires_at <= action.requested_at
    {
        return Err("approval_challenge_binding_mismatch".to_string());
    }
    let canonical_request_digest = canonical_authority_request_digest(&decision.request)
        .map_err(|error| error.reason_code())?;
    let risk_level = parameters
        .get(APPROVAL_OBLIGATION_RISK_LEVEL)
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .ok_or_else(|| "approval_challenge_risk_level_invalid".to_string())
        })
        .transpose()?;
    Ok(Some(ApprovalChallenge {
        schema_version: APPROVAL_CHALLENGE_SCHEMA_VERSION.to_string(),
        approval_id,
        tenant_id: action.tenant_id.clone(),
        agent_id: action.agent_id.clone(),
        run_id: action.run_id.clone(),
        action_id: action.action_id.clone(),
        action_name: action.action.name.clone(),
        adapter: adapter.to_string(),
        policy_id: policy_id.to_string(),
        risk_level,
        subject: decision.request.subject.clone(),
        authority_decision_id: decision.decision_id.clone(),
        obligation_id: obligation.obligation_id.clone(),
        receipt_audience: receipt_audience.to_string(),
        canonical_request_digest,
        gateway_action_request_digest: expected_action_digest,
        physical_action_resource_coordinate: action.physical_action_resource_coordinate.clone(),
        authority_decision_digest: expected_decision_digest,
        requested_at: action.requested_at,
        expires_at,
    }))
}

fn required_obligation_parameter<'a>(
    parameters: &'a std::collections::BTreeMap<String, serde_json::Value>,
    key: &'static str,
) -> Result<&'a str, String> {
    parameters
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("approval_challenge_parameter_missing:{key}"))
}

fn bind_approval_result_to_challenge(
    result: &mut VerificationResult,
    challenge: &ApprovalChallenge,
) -> Result<(), String> {
    let artifacts = result
        .artifacts
        .as_object_mut()
        .ok_or_else(|| "approval_challenge_artifact_unavailable".to_string())?;
    if artifacts
        .get("policy_id")
        .and_then(serde_json::Value::as_str)
        != Some(challenge.policy_id.as_str())
    {
        return Err("approval_challenge_policy_mismatch".to_string());
    }
    let approval = artifacts
        .get("approval")
        .cloned()
        .ok_or_else(|| "approval_challenge_context_unavailable".to_string())?;
    let mut approval: ApprovalTraceContext = serde_json::from_value(approval)
        .map_err(|_| "approval_challenge_context_invalid".to_string())?;
    approval.approval_id = challenge.approval_id.clone();
    approval.tenant_id = challenge.tenant_id.clone();
    approval.agent_id = challenge.agent_id.clone();
    approval.run_id = challenge.run_id.clone();
    approval.action_id = Some(challenge.action_id.clone());
    approval.action_name = challenge.action_name.clone();
    approval.adapter = Some(challenge.adapter.clone());
    approval.decision = None;
    approval.policy_id = Some(challenge.policy_id.clone());
    approval.risk_level = challenge.risk_level.clone();
    approval.issued_at = None;
    approval.expires_at = Some(challenge.expires_at);
    approval.revoked = false;
    artifacts.insert(
        "approval".to_string(),
        serde_json::to_value(approval)
            .map_err(|_| "approval_challenge_context_unavailable".to_string())?,
    );
    Ok(())
}

fn action_with_current_authority_decision(
    action: &ActionRequest,
    decision: AuthorityDecision,
) -> Result<ActionRequest, VerificationResult> {
    if action.authority_obligation_evidence.is_some() {
        return Err(VerificationResult::deny(
            "requester_authority_decision_non_authorizing",
        ));
    }
    let receipts = action
        .authority_obligation_receipts
        .iter()
        .filter(|receipt| receipt.authority_decision_id == decision.decision_id)
        .cloned()
        .collect();
    let mut current = action.clone();
    current.authority_obligation_evidence =
        Some(GatewayAuthorityObligationEvidence { decision, receipts });
    Ok(current)
}

fn bounded_recorder_reason(reason: &str) -> &'static str {
    if reason == "authority_evidence_recorder_unavailable" {
        "authority_evidence_recorder_unavailable"
    } else {
        "authority_evidence_store_unavailable"
    }
}

fn identity_denied_outcome(action_id: ActionId, error: IdentityValidationError) -> ActionOutcome {
    ActionOutcome {
        action_id,
        status: ActionStatus::Denied,
        verification: VerificationResult {
            allowed: false,
            reasons: vec!["identity_invalid".to_string()],
            artifacts: serde_json::json!({
                "error": error.to_string(),
            }),
        },
        post_verification: None,
        output: None,
        error: Some(error.to_string()),
        approval_challenge: None,
        completed_at: OffsetDateTime::now_utc(),
    }
}

/// Synchronous action gateway interface.
pub trait ActionGateway: Send + Sync {
    /// Submits an `ActionRequest` and returns an `ActionOutcome`.
    fn submit(&self, action: ActionRequest) -> Result<ActionOutcome, GatewayError>;
}

/// Asynchronous action gateway interface.
pub trait AsyncActionGateway: Send + Sync {
    /// Future returned by `submit`.
    type SubmitFuture<'a>: Future<Output = Result<ActionOutcome, GatewayError>> + Send + 'a
    where
        Self: 'a;

    /// Submits an `ActionRequest` asynchronously.
    fn submit<'a>(&'a self, action: ActionRequest) -> Self::SubmitFuture<'a>;
}

/// Placeholder gateway implementation used during early milestones.
#[derive(Default)]
pub struct UnimplementedGateway;

impl ActionGateway for UnimplementedGateway {
    /// Always returns `GatewayError::Unimplemented`.
    fn submit(&self, _action: ActionRequest) -> Result<ActionOutcome, GatewayError> {
        Err(GatewayError::Unimplemented)
    }
}

impl AsyncActionGateway for UnimplementedGateway {
    type SubmitFuture<'a>
        = Ready<Result<ActionOutcome, GatewayError>>
    where
        Self: 'a;

    /// Async wrapper that returns `GatewayError::Unimplemented`.
    fn submit<'a>(&'a self, action: ActionRequest) -> Self::SubmitFuture<'a> {
        ready(ActionGateway::submit(self, action))
    }
}

/// Errors produced by action gateway implementations.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// Gateway has not been implemented yet.
    #[error("gateway is not implemented yet")]
    Unimplemented,
    /// Verification denied the requested action.
    #[error("action verification failed: {0}")]
    VerificationFailed(String),
    /// Adapter failed to execute the action.
    #[error("adapter execution failed: {0}")]
    AdapterFailed(String),
}

impl GatewayError {
    /// Converts gateway-level failures into the canonical taxonomy bridge.
    pub fn taxonomy(&self) -> ErrorTaxonomy {
        match self {
            Self::Unimplemented => ErrorTaxonomy::new(
                ErrorCategory::Unavailable,
                ReasonCode::from_static("gateway_unimplemented"),
                RetryClass::NotRetryable,
                EffectCertainty::None,
            ),
            Self::VerificationFailed(_) => ErrorTaxonomy::new(
                ErrorCategory::Unauthorized,
                ReasonCode::from_static("gateway_verification_failed"),
                RetryClass::RetryWithNewAuthorization,
                EffectCertainty::None,
            ),
            Self::AdapterFailed(_) => {
                ErrorTaxonomy::unknown_adapter_failure("gateway_adapter", None)
            }
        }
    }
}

fn check_conditions(reason: &str, expected: &[String], satisfied: &[String]) -> VerificationResult {
    if expected.is_empty() {
        return VerificationResult::allow();
    }
    let missing = expected
        .iter()
        .filter(|condition| !satisfied.iter().any(|value| value == *condition))
        .cloned()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return VerificationResult::allow();
    }
    VerificationResult {
        allowed: false,
        reasons: vec![reason.to_string()],
        artifacts: serde_json::json!({
            "expected": expected,
            "satisfied": satisfied,
            "missing": missing,
        }),
    }
}

/// Computes the deterministic digest authority decisions must bind to for this
/// exact gateway action request and effective adapter.
///
/// The digest excludes authority obligation evidence itself and legacy approval
/// evidence so neither requester-supplied receipt metadata nor legacy approval
/// grants can become authority. The resulting digest must be present in the
/// authority decision request metadata under
/// [`GATEWAY_AUTHORITY_ACTION_DIGEST_METADATA_KEY`] and is itself bound by the
/// validated obligation receipts through the canonical authority request digest.
pub fn canonical_gateway_authority_action_digest(
    action: &ActionRequest,
    effective_adapter: Option<&str>,
) -> Result<String, String> {
    let bytes = if is_physical_action(&action.action) {
        let physical_action_resource_coordinate = action
            .physical_action_resource_coordinate
            .as_ref()
            .filter(|coordinate| !coordinate.node_id.is_nil())
            .ok_or_else(|| "physical_action_resource_coordinate_required".to_string())?;
        serde_json::to_vec(&GatewayPhysicalAuthorityActionDigestPayload {
            schema_version: "splendor.gateway.authority_action_binding.physical.v2",
            physical_action_resource_coordinate,
            action_id: &action.action_id,
            tenant_id: &action.tenant_id,
            agent_id: &action.agent_id,
            run_id: &action.run_id,
            action: &action.action,
            effective_adapter,
            quota_usage: action.quota_usage,
            satisfied_preconditions: &action.satisfied_preconditions,
            requested_at: action.requested_at,
        })
        .map_err(|error| format!("gateway_action_request_digest_unavailable:{error}"))?
    } else {
        return canonical_gateway_authority_action_v1_compat_digest(action, effective_adapter);
    };
    Ok(ContentHash::blake3(bytes).to_string())
}

/// Computes the frozen v1 action-binding digest for fail-closed migration of an
/// already stored physical-v1 approval challenge.
///
/// This helper never authorizes a physical action. Callers must remove any v2
/// physical resource coordinate first, compare only against an immutable stored
/// v1 challenge, and use the result solely to apply raw denial, expiry, or
/// revocation. Live physical authorization always uses
/// [`canonical_gateway_authority_action_digest`] and its physical-v2 binding.
pub fn canonical_gateway_authority_action_v1_compat_digest(
    action: &ActionRequest,
    effective_adapter: Option<&str>,
) -> Result<String, String> {
    if action.physical_action_resource_coordinate.is_some() {
        return Err("physical_action_resource_coordinate_unexpected".to_string());
    }
    let bytes = serde_json::to_vec(&GatewayAuthorityActionDigestPayload {
        schema_version: "splendor.gateway.authority_action_binding.v1",
        action_id: &action.action_id,
        tenant_id: &action.tenant_id,
        agent_id: &action.agent_id,
        run_id: &action.run_id,
        action: &action.action,
        effective_adapter,
        quota_usage: action.quota_usage,
        satisfied_preconditions: &action.satisfied_preconditions,
        requested_at: action.requested_at,
    })
    .map_err(|error| format!("gateway_action_request_digest_unavailable:{error}"))?;
    Ok(ContentHash::blake3(bytes).to_string())
}

/// Computes the deterministic digest that receipt-bound authority requests must
/// carry to protect the complete conditional decision from requester tampering.
///
/// The digest covers the full decision payload except the digest metadata field
/// itself. Because obligation receipts sign the canonical authority request
/// digest, a requester cannot update this metadata after receipt issuance without
/// invalidating the signed receipt request digest.
pub fn canonical_gateway_authority_decision_digest(
    decision: &AuthorityDecision,
) -> Result<String, String> {
    let mut request = decision.request.clone();
    request
        .metadata
        .remove(GATEWAY_AUTHORITY_DECISION_DIGEST_METADATA_KEY);
    let payload = GatewayAuthorityDecisionDigestPayload {
        schema_version: "splendor.gateway.authority_decision_binding.v1",
        decision_schema_version: &decision.schema_version,
        decision_id: &decision.decision_id,
        request: &request,
        status: decision.status,
        reasons: &decision.reasons,
        matched_grant_ids: &decision.matched_grant_ids,
        obligations: &decision.obligations,
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|error| format!("authority_decision_digest_unavailable:{error}"))?;
    Ok(ContentHash::blake3(bytes).to_string())
}

#[derive(Serialize)]
struct GatewayAuthorityActionDigestPayload<'a> {
    schema_version: &'static str,
    action_id: &'a ActionId,
    tenant_id: &'a TenantId,
    agent_id: &'a AgentId,
    run_id: &'a RunId,
    action: &'a Action,
    effective_adapter: Option<&'a str>,
    quota_usage: QuotaUsage,
    satisfied_preconditions: &'a [String],
    #[serde(with = "time::serde::rfc3339")]
    requested_at: OffsetDateTime,
}

#[derive(Serialize)]
struct GatewayPhysicalAuthorityActionDigestPayload<'a> {
    schema_version: &'static str,
    physical_action_resource_coordinate: &'a PhysicalActionResourceCoordinate,
    action_id: &'a ActionId,
    tenant_id: &'a TenantId,
    agent_id: &'a AgentId,
    run_id: &'a RunId,
    action: &'a Action,
    effective_adapter: Option<&'a str>,
    quota_usage: QuotaUsage,
    satisfied_preconditions: &'a [String],
    #[serde(with = "time::serde::rfc3339")]
    requested_at: OffsetDateTime,
}

#[derive(Serialize)]
struct GatewayAuthorityDecisionDigestPayload<'a> {
    schema_version: &'static str,
    decision_schema_version: &'a str,
    decision_id: &'a splendor_types::AuthorityDecisionId,
    request: &'a splendor_types::CapabilityRequest,
    status: AuthorityDecisionStatus,
    reasons: &'a [String],
    matched_grant_ids: &'a [splendor_types::CapabilityGrantId],
    obligations: &'a [splendor_types::AuthorityObligation],
}

fn authority_decision_action_binding_reasons(
    decision: &AuthorityDecision,
    action: &ActionRequest,
    adapter: Option<&str>,
) -> Vec<String> {
    let mut reasons = Vec::new();
    let mut expected_operations = vec![gateway_action_operation(action.action.name.clone())];
    if let Some(adapter) = adapter {
        expected_operations.push(gateway_adapter_operation(adapter));
    }
    expected_operations.extend(
        action
            .action
            .required_permissions
            .iter()
            .cloned()
            .map(compatibility_permission_operation),
    );
    if !expected_operations.contains(&decision.request.operation) {
        push_unique_string(
            &mut reasons,
            "authority_decision_operation_mismatch".to_string(),
        );
    }
    if !scope_exactly_matches(
        decision.request.scope.tenant_ids.as_ref(),
        &action.tenant_id,
    ) {
        push_unique_string(
            &mut reasons,
            "authority_decision_tenant_scope_mismatch".to_string(),
        );
    }
    if !scope_exactly_matches(decision.request.scope.agent_ids.as_ref(), &action.agent_id) {
        push_unique_string(
            &mut reasons,
            "authority_decision_agent_scope_mismatch".to_string(),
        );
    }
    if !scope_exactly_matches(decision.request.scope.run_ids.as_ref(), &action.run_id) {
        push_unique_string(
            &mut reasons,
            "authority_decision_run_scope_mismatch".to_string(),
        );
    }
    reasons
}

fn scope_exactly_matches<T: PartialEq>(values: Option<&Vec<T>>, expected: &T) -> bool {
    values.is_some_and(|values| values.len() == 1 && values.first() == Some(expected))
}

fn authority_obligation_result(
    allowed: bool,
    reasons: Vec<String>,
    status: &str,
    evidence: Option<&GatewayAuthorityObligationEvidence>,
    action_digest: Option<String>,
    satisfied_obligation_ids: Vec<String>,
    receipt_ids: Vec<String>,
) -> VerificationResult {
    // Typed IDs/status are bounded compatibility coordinates. Detailed decision
    // projection and digest strings remain trusted-only after exact receipt match.
    let trusted_evidence = if allowed { evidence } else { None };
    let derived_receipt_ids = if allowed && !receipt_ids.is_empty() {
        receipt_ids
    } else {
        evidence
            .map(|evidence| {
                evidence
                    .receipts
                    .iter()
                    .map(|receipt| receipt.receipt_id.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let obligation_ids = evidence
        .map(|evidence| {
            evidence
                .decision
                .obligations
                .iter()
                .map(|obligation| obligation.obligation_id.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let decision_digest = trusted_evidence.and_then(|evidence| {
        evidence
            .decision
            .request
            .metadata
            .get(GATEWAY_AUTHORITY_DECISION_DIGEST_METADATA_KEY)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    });
    let action_digest = if allowed { action_digest } else { None };
    let satisfied_obligation_ids = if allowed {
        satisfied_obligation_ids
    } else {
        Vec::new()
    };
    VerificationResult {
        allowed,
        reasons: if allowed { Vec::new() } else { reasons },
        artifacts: serde_json::json!({
            "verifier": "authority_obligation_verifier",
            "authority_obligation_status": status,
            "decision_id": evidence.map(|evidence| evidence.decision.decision_id.to_string()),
            "decision_status": evidence.map(|evidence| authority_decision_status_label(evidence.decision.status)),
            "obligation_ids": obligation_ids,
            "receipt_ids": derived_receipt_ids,
            "satisfied_obligation_ids": satisfied_obligation_ids,
            "gateway_action_request_digest": action_digest,
            "authority_decision_digest": decision_digest,
        }),
    }
}

fn authority_decision_status_label(status: AuthorityDecisionStatus) -> &'static str {
    match status {
        AuthorityDecisionStatus::Allowed => "allowed",
        AuthorityDecisionStatus::Denied => "denied",
        AuthorityDecisionStatus::Conditional => "conditional",
        AuthorityDecisionStatus::NeedsApproval => "needs_approval",
        AuthorityDecisionStatus::NeedsIntervention => "needs_intervention",
    }
}

fn attach_authority_decision_evidence_projection(
    result: &mut VerificationResult,
    decision: &AuthorityDecision,
) -> Result<(), &'static str> {
    let (digest, completeness, explanation, unavailable) =
        match authority_decision_evidence(decision).and_then(|record| record.redacted()) {
            Ok(record) => match (
                serde_json::to_value(record.completeness),
                serde_json::to_value(record.explanation.branches),
            ) {
                (Ok(completeness), Ok(explanation)) => (
                    serde_json::Value::String(record.decision_digest),
                    completeness,
                    explanation,
                    serde_json::Value::Null,
                ),
                _ => return Err("authority_evidence_projection_serialization_unavailable"),
            },
            Err(error) => return Err(error.reason_code()),
        };
    let Some(artifacts) = result.artifacts.as_object_mut() else {
        return Err("authority_evidence_projection_artifact_unavailable");
    };
    artifacts.insert("authority_decision_evidence_digest".to_string(), digest);
    artifacts.insert(
        "authority_decision_evidence_completeness".to_string(),
        completeness,
    );
    artifacts.insert("authority_decision_explanation".to_string(), explanation);
    artifacts.insert(
        "authority_decision_evidence_unavailable".to_string(),
        unavailable,
    );
    Ok(())
}

fn push_unique_string(reasons: &mut Vec<String>, reason: String) {
    if !reasons.iter().any(|existing| existing == &reason) {
        reasons.push(reason);
    }
}

fn combine_verifications(
    results: impl IntoIterator<Item = (&'static str, VerificationResult)>,
) -> VerificationResult {
    let mut reasons = Vec::new();
    let mut artifacts = serde_json::Map::new();
    let mut denied = false;
    for (label, result) in results {
        if result.allowed {
            continue;
        }
        denied = true;
        reasons.extend(result.reasons);
        if !result.artifacts.is_null() {
            artifacts.insert(label.to_string(), result.artifacts);
        }
    }
    if !denied {
        VerificationResult::allow()
    } else {
        VerificationResult {
            allowed: false,
            reasons,
            artifacts: serde_json::Value::Object(artifacts),
        }
    }
}

fn combine_post_verifications(
    invariant: VerificationResult,
    safety: SafetyVerification,
) -> VerificationResult {
    match safety {
        SafetyVerification::NotRequired => invariant,
        SafetyVerification::Allowed(safety_result) if invariant.allowed => {
            let mut combined = VerificationResult::allow();
            attach_allowed_artifact(&mut combined, "safety", safety_result.artifacts);
            combined
        }
        SafetyVerification::Allowed(safety_result) => {
            let mut combined = combine_verifications([("invariant", invariant)]);
            attach_allowed_artifact(&mut combined, "safety", safety_result.artifacts);
            combined
        }
        SafetyVerification::Denied(safety_result)
        | SafetyVerification::NeedsIntervention(safety_result) => {
            combine_verifications([("invariant", invariant), ("safety", safety_result)])
        }
    }
}

fn verify_safety_pre(
    verifier: &Option<Arc<dyn SafetyVerifier>>,
    action: &ActionRequest,
    adapter: Option<&str>,
) -> SafetyVerification {
    if !is_physical_action(&action.action) {
        return SafetyVerification::NotRequired;
    }
    let Some(verifier) = verifier else {
        return SafetyVerification::NeedsIntervention(missing_safety_verifier_result(action));
    };
    match verifier.verify_pre(action, adapter) {
        SafetyVerification::NotRequired => {
            SafetyVerification::NeedsIntervention(missing_safety_verifier_result(action))
        }
        other => normalize_safety_verification(other),
    }
}

fn verify_safety_post(
    verifier: &Option<Arc<dyn SafetyVerifier>>,
    action: &ActionRequest,
    adapter: Option<&str>,
    result: &AdapterResult,
) -> SafetyVerification {
    if !is_physical_action(&action.action) {
        return SafetyVerification::NotRequired;
    }
    let Some(verifier) = verifier else {
        return SafetyVerification::NeedsIntervention(missing_safety_verifier_result(action));
    };
    match verifier.verify_post(action, adapter, result) {
        SafetyVerification::NotRequired => {
            SafetyVerification::NeedsIntervention(missing_safety_verifier_result(action))
        }
        other => normalize_safety_verification(other),
    }
}

fn normalize_safety_verification(result: SafetyVerification) -> SafetyVerification {
    match result {
        SafetyVerification::Allowed(mut verification) if !verification.allowed => {
            if !verification
                .reasons
                .iter()
                .any(|reason| reason == "safety_verifier_inconsistent")
            {
                verification
                    .reasons
                    .push("safety_verifier_inconsistent".to_string());
            }
            SafetyVerification::NeedsIntervention(verification)
        }
        SafetyVerification::Denied(mut verification) => {
            verification.allowed = false;
            SafetyVerification::Denied(verification)
        }
        SafetyVerification::NeedsIntervention(mut verification) => {
            verification.allowed = false;
            if !verification
                .reasons
                .iter()
                .any(|reason| reason == "verifier_uncertainty")
            {
                verification
                    .reasons
                    .push("verifier_uncertainty".to_string());
            }
            SafetyVerification::NeedsIntervention(verification)
        }
        other => other,
    }
}

fn missing_safety_verifier_result(action: &ActionRequest) -> VerificationResult {
    VerificationResult {
        allowed: false,
        reasons: vec![
            "safety_verifier_missing".to_string(),
            "verifier_uncertainty".to_string(),
        ],
        artifacts: serde_json::json!({
            "source": "safety_verifier",
            "required": true,
            "action": action.action.name,
            "side_effect_class": side_effect_class_label(&action.action.side_effect_class),
            "evidence": SafetyEvidence::new(
                "missing_safety_verifier",
                "required_safety_verifier",
                SafetyCheckStatus::Uncertain,
                "safety_verifier_missing",
            ),
        }),
    }
}

/// Returns true for high-level physical actions that require local safety verification.
pub fn is_physical_action(action: &Action) -> bool {
    matches!(
        action.side_effect_class,
        SideEffectClass::Custom(ref class)
            if class == "physical" || class == "physical.high_level" || class.starts_with("physical.")
    ) || matches!(
        action.name.as_str(),
        "read_battery"
            | "read_sensor_summary"
            | "read_map"
            | "move_to_waypoint"
            | "return_to_base"
            | "dock"
            | "inspect_zone"
            | "capture_image"
            | "pause_mission"
            | "resume_mission"
            | "request_operator_override"
            | "notify_operator"
            | "upload_trace_summary"
    ) || action
        .params
        .get("physical_action")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn verify_physical_action_boundary(action: &ActionRequest) -> Option<VerificationResult> {
    let physical = is_physical_action(&action.action);
    if physical
        && action
            .physical_action_resource_coordinate
            .as_ref()
            .is_none_or(|coordinate| coordinate.node_id.is_nil())
    {
        return Some(VerificationResult {
            allowed: false,
            reasons: vec!["physical_action_resource_coordinate_required".to_string()],
            artifacts: serde_json::json!({
                "source": "physical_action_boundary",
                "action": action.action.name,
                "matched_policy": "trusted_physical_resource_coordinate_required",
            }),
        });
    }
    if !physical && action.physical_action_resource_coordinate.is_some() {
        return Some(VerificationResult {
            allowed: false,
            reasons: vec!["physical_action_resource_coordinate_unexpected".to_string()],
            artifacts: serde_json::json!({
                "source": "physical_action_boundary",
                "action": action.action.name,
                "matched_policy": "physical_resource_coordinate_not_request_metadata",
            }),
        });
    }
    let normalized = normalize_physical_token(&action.action.name);
    if FORBIDDEN_PHYSICAL_ACTION_PATTERNS
        .iter()
        .any(|pattern| normalized.contains(pattern))
    {
        return Some(VerificationResult {
            allowed: false,
            reasons: vec!["forbidden_physical_action".to_string()],
            artifacts: serde_json::json!({
                "source": "physical_action_boundary",
                "action": action.action.name,
                "matched_policy": "forbidden_low_level_physical_action",
            }),
        });
    }

    if is_physical_action(&action.action) && !is_allowed_physical_action(&action.action.name) {
        return Some(VerificationResult {
            allowed: false,
            reasons: vec!["unknown_physical_action".to_string()],
            artifacts: serde_json::json!({
                "source": "physical_action_boundary",
                "action": action.action.name,
                "matched_policy": "high_level_physical_actions_only",
            }),
        });
    }

    None
}

fn normalize_physical_token(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn simulated_safety_evidence(snapshot: &SimulatedSafetySnapshot) -> SafetyVerification {
    let verifier = "simulated_safety_verifier";
    if snapshot.cloud_helper_direct_authority {
        return simulated_deny(
            verifier,
            "cloud_helper_authority",
            "cloud_helper_direct_authority_denied",
            snapshot,
            Vec::new(),
            Vec::new(),
        );
    }
    if snapshot.policy_cache_expired && snapshot.high_risk {
        return simulated_deny(
            verifier,
            "policy_cache",
            "policy_cache_expired",
            snapshot,
            Vec::new(),
            Vec::new(),
        );
    }
    if snapshot.emergency_stop_engaged.is_none() {
        return simulated_uncertain(verifier, "emergency_stop", snapshot, Vec::new(), Vec::new());
    }
    if snapshot.emergency_stop_engaged == Some(true) {
        return simulated_deny(
            verifier,
            "emergency_stop",
            "emergency_stop_engaged",
            snapshot,
            Vec::new(),
            Vec::new(),
        );
    }
    if snapshot.battery_percent.is_none() || snapshot.min_battery_percent.is_none() {
        return simulated_uncertain(
            verifier,
            "battery",
            snapshot,
            Vec::new(),
            battery_threshold(snapshot),
        );
    }
    if snapshot.battery_percent < snapshot.min_battery_percent {
        return simulated_intervention(
            verifier,
            "battery",
            "battery_below_minimum",
            snapshot,
            Vec::new(),
            battery_threshold(snapshot),
        );
    }
    if snapshot.collision_risk.is_none()
        || snapshot.collision_risk == Some(SimulatedRiskLevel::Unknown)
    {
        return simulated_uncertain(verifier, "collision", snapshot, Vec::new(), Vec::new());
    }
    if matches!(
        snapshot.collision_risk,
        Some(SimulatedRiskLevel::High | SimulatedRiskLevel::Critical)
    ) {
        return simulated_deny(
            verifier,
            "collision",
            "collision_risk_high",
            snapshot,
            Vec::new(),
            Vec::new(),
        );
    }
    if snapshot.current_zone.is_none() || snapshot.allowed_zones.is_empty() {
        return simulated_uncertain(
            verifier,
            "geofence",
            snapshot,
            snapshot.allowed_zones.clone(),
            Vec::new(),
        );
    }
    let current_zone = snapshot
        .current_zone
        .as_ref()
        .expect("checked current zone");
    if !snapshot
        .allowed_zones
        .iter()
        .any(|zone| zone == current_zone)
    {
        return simulated_deny(
            verifier,
            "geofence",
            "geofence_violation",
            snapshot,
            vec![current_zone.clone()],
            Vec::new(),
        );
    }
    if snapshot.altitude_m.is_some()
        && snapshot.max_altitude_m.is_some()
        && snapshot.altitude_m > snapshot.max_altitude_m
    {
        return simulated_deny(
            verifier,
            "altitude",
            "altitude_limit_exceeded",
            snapshot,
            Vec::new(),
            altitude_threshold(snapshot),
        );
    }
    if snapshot.privacy_zone_active == Some(true) {
        return simulated_deny(
            verifier,
            "privacy",
            "privacy_zone_active",
            snapshot,
            Vec::new(),
            Vec::new(),
        );
    }
    if snapshot.proximity_m.is_some()
        && snapshot.min_proximity_m.is_some()
        && snapshot.proximity_m < snapshot.min_proximity_m
    {
        return simulated_deny(
            verifier,
            "proximity",
            "proximity_below_minimum",
            snapshot,
            Vec::new(),
            proximity_threshold(snapshot),
        );
    }
    SafetyVerification::Allowed(
        SafetyEvidence::new(
            verifier,
            "simulated_safety",
            SafetyCheckStatus::Pass,
            "safety_passed",
        )
        .with_sensor_refs(snapshot.sensor_refs.clone())
        .with_zone_refs(snapshot.current_zone.clone())
        .into_verification(),
    )
}

fn simulated_deny(
    verifier: &str,
    check: &str,
    reason: &str,
    snapshot: &SimulatedSafetySnapshot,
    zone_refs: Vec<String>,
    thresholds: Vec<SafetyThresholdEvidence>,
) -> SafetyVerification {
    SafetyVerification::Denied(
        SafetyEvidence::new(verifier, check, SafetyCheckStatus::Deny, reason)
            .with_sensor_refs(snapshot.sensor_refs.clone())
            .with_zone_refs(zone_refs)
            .with_thresholds(thresholds)
            .into_verification(),
    )
}

fn simulated_intervention(
    verifier: &str,
    check: &str,
    reason: &str,
    snapshot: &SimulatedSafetySnapshot,
    zone_refs: Vec<String>,
    thresholds: Vec<SafetyThresholdEvidence>,
) -> SafetyVerification {
    SafetyVerification::NeedsIntervention(
        SafetyEvidence::new(verifier, check, SafetyCheckStatus::Uncertain, reason)
            .with_sensor_refs(snapshot.sensor_refs.clone())
            .with_zone_refs(zone_refs)
            .with_thresholds(thresholds)
            .into_verification(),
    )
}

fn simulated_uncertain(
    verifier: &str,
    check: &str,
    snapshot: &SimulatedSafetySnapshot,
    zone_refs: Vec<String>,
    thresholds: Vec<SafetyThresholdEvidence>,
) -> SafetyVerification {
    SafetyVerification::NeedsIntervention(
        SafetyEvidence::new(
            verifier,
            check,
            SafetyCheckStatus::Uncertain,
            "safety_verifier_uncertain",
        )
        .with_sensor_refs(snapshot.sensor_refs.clone())
        .with_zone_refs(zone_refs)
        .with_thresholds(thresholds)
        .into_verification(),
    )
}

fn battery_threshold(snapshot: &SimulatedSafetySnapshot) -> Vec<SafetyThresholdEvidence> {
    vec![SafetyThresholdEvidence {
        name: "min_battery_percent".to_string(),
        observed: snapshot.battery_percent,
        min: snapshot.min_battery_percent,
        max: None,
        unit: Some("percent".to_string()),
    }]
}

fn altitude_threshold(snapshot: &SimulatedSafetySnapshot) -> Vec<SafetyThresholdEvidence> {
    vec![SafetyThresholdEvidence {
        name: "max_altitude_m".to_string(),
        observed: snapshot.altitude_m,
        min: None,
        max: snapshot.max_altitude_m,
        unit: Some("m".to_string()),
    }]
}

fn proximity_threshold(snapshot: &SimulatedSafetySnapshot) -> Vec<SafetyThresholdEvidence> {
    vec![SafetyThresholdEvidence {
        name: "min_proximity_m".to_string(),
        observed: snapshot.proximity_m,
        min: snapshot.min_proximity_m,
        max: None,
        unit: Some("m".to_string()),
    }]
}

fn evaluate_breakers(
    breakers: &[CircuitBreaker],
    runtime_identity: &RuntimeIdentityContext,
    action: Option<&ActionRequest>,
    adapter: Option<&str>,
    runtime_admission_only: bool,
) -> VerificationResult {
    for breaker in breakers.iter().filter(|breaker| breaker.is_tripped()) {
        match breaker_scope_matches(
            &breaker.scope,
            runtime_identity,
            action,
            adapter,
            runtime_admission_only,
        ) {
            BreakerScopeMatch::Matches => {
                return VerificationResult {
                    allowed: false,
                    reasons: vec!["circuit_breaker_tripped".to_string()],
                    artifacts: serde_json::json!({
                        "circuit_breaker": breaker.as_match().to_artifact(),
                    }),
                };
            }
            BreakerScopeMatch::Unknown(field) => {
                return VerificationResult {
                    allowed: false,
                    reasons: vec!["circuit_breaker_scope_unknown".to_string()],
                    artifacts: serde_json::json!({
                        "circuit_breaker": breaker.as_match().to_artifact(),
                        "missing_identity": field,
                    }),
                };
            }
            BreakerScopeMatch::DoesNotMatch => {}
        }
    }
    VerificationResult::allow()
}

fn action_request_with_effective_side_effect_class(
    action: &ActionRequest,
    adapter: &str,
) -> ActionRequest {
    let Some(effective_class) = trusted_adapter_side_effect_class(adapter) else {
        return action.clone();
    };
    let mut normalized = action.clone();
    normalized.action.side_effect_class = effective_class;
    normalized
}

fn verify_declared_side_effect_class(
    action: &ActionRequest,
    adapter: &str,
) -> Option<VerificationResult> {
    let effective_class = trusted_adapter_side_effect_class(adapter)?;
    if action.action.side_effect_class == effective_class {
        return None;
    }
    Some(VerificationResult {
        allowed: false,
        reasons: vec!["side_effect_class_mismatch".to_string()],
        artifacts: serde_json::json!({
            "adapter": adapter,
            "declared_side_effect_class": side_effect_class_label(&action.action.side_effect_class),
            "effective_side_effect_class": side_effect_class_label(&effective_class),
        }),
    })
}

fn trusted_adapter_side_effect_class(adapter: &str) -> Option<SideEffectClass> {
    match adapter {
        "filesystem" => Some(SideEffectClass::Filesystem),
        "http" => Some(SideEffectClass::Network),
        _ => None,
    }
}

fn side_effect_class_label(value: &SideEffectClass) -> String {
    match value {
        SideEffectClass::ReadOnly => "read_only".to_string(),
        SideEffectClass::Filesystem => "filesystem".to_string(),
        SideEffectClass::Network => "network".to_string(),
        SideEffectClass::External => "external".to_string(),
        SideEffectClass::Custom(value) => format!("custom:{value}"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BreakerScopeMatch {
    Matches,
    DoesNotMatch,
    Unknown(&'static str),
}

fn breaker_scope_matches(
    scope: &CircuitBreakerScope,
    runtime_identity: &RuntimeIdentityContext,
    action: Option<&ActionRequest>,
    adapter: Option<&str>,
    runtime_admission_only: bool,
) -> BreakerScopeMatch {
    match scope {
        CircuitBreakerScope::Global => BreakerScopeMatch::Matches,
        CircuitBreakerScope::Fleet(expected) => match runtime_identity.fleet_id.as_ref() {
            Some(actual) if actual == expected => BreakerScopeMatch::Matches,
            Some(_) => BreakerScopeMatch::DoesNotMatch,
            None => BreakerScopeMatch::Unknown("fleet_id"),
        },
        CircuitBreakerScope::Node(expected) => match runtime_identity.node_id.as_ref() {
            Some(actual) if actual == expected => BreakerScopeMatch::Matches,
            Some(_) => BreakerScopeMatch::DoesNotMatch,
            None => BreakerScopeMatch::Unknown("node_id"),
        },
        CircuitBreakerScope::Instance(expected) => match runtime_identity.instance_id.as_ref() {
            Some(actual) if actual == expected => BreakerScopeMatch::Matches,
            Some(_) => BreakerScopeMatch::DoesNotMatch,
            None => BreakerScopeMatch::Unknown("instance_id"),
        },
        CircuitBreakerScope::Tenant(expected) => match action {
            Some(action) if &action.tenant_id == expected => BreakerScopeMatch::Matches,
            Some(_) => BreakerScopeMatch::DoesNotMatch,
            None if runtime_admission_only => BreakerScopeMatch::DoesNotMatch,
            None => BreakerScopeMatch::Unknown("tenant_id"),
        },
        CircuitBreakerScope::Agent(expected) => match action {
            Some(action) if &action.agent_id == expected => BreakerScopeMatch::Matches,
            Some(_) => BreakerScopeMatch::DoesNotMatch,
            None if runtime_admission_only => BreakerScopeMatch::DoesNotMatch,
            None => BreakerScopeMatch::Unknown("agent_id"),
        },
        CircuitBreakerScope::Adapter(expected) => match adapter {
            Some(actual) if actual == expected => BreakerScopeMatch::Matches,
            Some(_) => BreakerScopeMatch::DoesNotMatch,
            None if runtime_admission_only => BreakerScopeMatch::DoesNotMatch,
            None => BreakerScopeMatch::Unknown("adapter"),
        },
        CircuitBreakerScope::Action(expected) => match action {
            Some(action) if &action.action.name == expected => BreakerScopeMatch::Matches,
            Some(_) => BreakerScopeMatch::DoesNotMatch,
            None if runtime_admission_only => BreakerScopeMatch::DoesNotMatch,
            None => BreakerScopeMatch::Unknown("action"),
        },
        CircuitBreakerScope::ActionClass(expected) => match action {
            Some(action) if &action.action.side_effect_class == expected => {
                BreakerScopeMatch::Matches
            }
            Some(_) => BreakerScopeMatch::DoesNotMatch,
            None if runtime_admission_only => BreakerScopeMatch::DoesNotMatch,
            None => BreakerScopeMatch::Unknown("action_class"),
        },
    }
}

fn denied_outcome(action_id: ActionId, verification: VerificationResult) -> ActionOutcome {
    let error = if verification.reasons.is_empty() {
        "verification denied".to_string()
    } else {
        verification.reasons.join(", ")
    };
    ActionOutcome {
        action_id,
        status: ActionStatus::Denied,
        verification,
        post_verification: None,
        output: None,
        error: Some(error),
        approval_challenge: None,
        completed_at: OffsetDateTime::now_utc(),
    }
}

fn needs_approval_outcome(action_id: ActionId, verification: VerificationResult) -> ActionOutcome {
    needs_approval_outcome_with_challenge(action_id, verification, None)
}

fn needs_approval_outcome_with_challenge(
    action_id: ActionId,
    verification: VerificationResult,
    approval_challenge: Option<ApprovalChallenge>,
) -> ActionOutcome {
    ActionOutcome {
        action_id,
        status: ActionStatus::NeedsApproval,
        verification,
        post_verification: None,
        output: None,
        error: Some("approval_required".to_string()),
        approval_challenge,
        completed_at: OffsetDateTime::now_utc(),
    }
}

fn needs_intervention_outcome(
    action_id: ActionId,
    verification: VerificationResult,
) -> ActionOutcome {
    ActionOutcome {
        action_id,
        status: ActionStatus::NeedsIntervention,
        verification,
        post_verification: None,
        output: None,
        error: Some("needs_intervention".to_string()),
        approval_challenge: None,
        completed_at: OffsetDateTime::now_utc(),
    }
}

fn approval_scope<'a>(
    action: &'a ActionRequest,
    adapter: Option<&'a str>,
) -> ApprovalActionScope<'a> {
    ApprovalActionScope {
        tenant_id: &action.tenant_id,
        agent_id: &action.agent_id,
        run_id: &action.run_id,
        action_id: &action.action_id,
        action: &action.action,
        adapter,
    }
}

fn approval_result(
    allowed: bool,
    reason: &str,
    status: &str,
    approval: ApprovalTraceContext,
    policy_id: Option<String>,
) -> VerificationResult {
    VerificationResult {
        allowed,
        reasons: if allowed {
            Vec::new()
        } else {
            vec![reason.to_string()]
        },
        artifacts: serde_json::json!({
            "verifier": "approval_verifier",
            "approval_status": status,
            "approval": approval,
            "policy_id": policy_id,
        }),
    }
}

fn attach_allowed_artifact(
    result: &mut VerificationResult,
    label: &str,
    artifact: serde_json::Value,
) {
    if artifact.is_null() {
        return;
    }
    let mut artifacts = match std::mem::take(&mut result.artifacts) {
        serde_json::Value::Object(map) => map,
        serde_json::Value::Null => serde_json::Map::new(),
        other => {
            let mut map = serde_json::Map::new();
            map.insert("detail".to_string(), other);
            map
        }
    };
    artifacts.insert(label.to_string(), artifact);
    result.artifacts = serde_json::Value::Object(artifacts);
}

fn attach_request_context(result: &mut VerificationResult, action: &ActionRequest) {
    let sources = result
        .artifacts
        .as_object()
        .map(|artifacts| artifacts.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let context = request_context(action, sources);
    match &mut result.artifacts {
        serde_json::Value::Object(artifacts) => {
            artifacts.insert("context".to_string(), context);
        }
        other => {
            let mut artifacts = serde_json::Map::new();
            if !other.is_null() {
                artifacts.insert("detail".to_string(), other.take());
            }
            artifacts.insert("context".to_string(), context);
            result.artifacts = serde_json::Value::Object(artifacts);
        }
    }
}

fn request_context(action: &ActionRequest, sources: Vec<String>) -> serde_json::Value {
    serde_json::json!({
        "source": "gateway_verifier_chain",
        "tenant_id": action.tenant_id.to_string(),
        "agent_id": action.agent_id.to_string(),
        "run_id": action.run_id.to_string(),
        "action_id": action.action_id.to_string(),
        "action": action.action.name,
        "adapter": action.adapter,
        "sources": sources,
    })
}

#[cfg(test)]
#[path = "../tests/unit/gateway_tests.rs"]
mod tests;
