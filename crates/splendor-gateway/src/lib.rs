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
//!     approval_evidence: None,
//! };
//! assert!(ActionGateway::submit(&gateway, request).is_err());
//! ```

use serde::{Deserialize, Serialize};
use splendor_types::{
    is_allowed_physical_action, Action, AgentId, ApprovalActionScope, ApprovalDecision,
    ApprovalEvidence, ApprovalId, ApprovalPolicy, ApprovalTraceContext, CircuitBreaker,
    CircuitBreakerScope, EffectCertainty, ErrorCategory, ErrorTaxonomy, IdentityValidationError,
    QuotaUsage, ReasonCode, RetryClass, RunId, RuntimeIdentityContext, SideEffectClass, TenantId,
    VerificationResult, APPROVAL_EVIDENCE_SCHEMA_VERSION, APPROVAL_POLICY_SCHEMA_VERSION,
    FORBIDDEN_PHYSICAL_ACTION_PATTERNS,
};
use std::collections::HashMap;
use std::future::{ready, Future, Ready};
use std::sync::Arc;
use time::OffsetDateTime;

pub use splendor_types::ActionId;

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
    /// Optional approval grant/denial evidence presented for this action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_evidence: Option<ApprovalEvidence>,
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

        if evidence.expires_at < now {
            return ApprovalVerification::Denied(approval_result(
                false,
                "approval_expired",
                "expired",
                context,
                Some(policy.policy_id.clone()),
            ));
        }

        match evidence.decision {
            ApprovalDecision::Granted => ApprovalVerification::Granted(approval_result(
                true,
                "approval_granted",
                "granted",
                context,
                Some(policy.policy_id.clone()),
            )),
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
    tenant_access: Arc<dyn TenantAccess>,
    invariant_evaluator: Arc<dyn InvariantEvaluator>,
    resource_boundary_verifier: Arc<dyn ResourceBoundaryVerifier>,
    approval_verifier: Arc<dyn ApprovalVerifier>,
    safety_verifier: Option<Arc<dyn SafetyVerifier>>,
    circuit_breaker_evaluator: Arc<dyn CircuitBreakerEvaluator>,
    runtime_identity: RuntimeIdentityContext,
}

impl VerifiedActionGateway {
    /// Creates a gateway with the provided tenant access.
    pub fn new(tenant_access: Arc<dyn TenantAccess>) -> Self {
        Self {
            adapters: HashMap::new(),
            tenant_access,
            invariant_evaluator: Arc::new(SimpleInvariantEvaluator),
            resource_boundary_verifier: Arc::new(NoopResourceBoundaryVerifier),
            approval_verifier: Arc::new(NoApprovalVerifier),
            safety_verifier: None,
            circuit_breaker_evaluator: Arc::new(NoopCircuitBreakerEvaluator),
            runtime_identity: RuntimeIdentityContext::default(),
        }
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
        if let Err(error) = action.validate_identity() {
            return Ok(identity_denied_outcome(action.action_id, error));
        }

        if let Some(mut verification) = verify_physical_action_boundary(&action) {
            attach_request_context(&mut verification, &action);
            return Ok(denied_outcome(action.action_id, verification));
        }

        let registration = self
            .adapters
            .get(&action.action.name)
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
        let approval_grant = match approval_verification {
            ApprovalVerification::NotRequired => None,
            ApprovalVerification::Granted(result) => Some(result),
            ApprovalVerification::Required(mut result) => {
                attach_request_context(&mut result, &action);
                return Ok(needs_approval_outcome(action.action_id, result));
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

        let adapter_result = match registration.adapter.execute(&action) {
            Ok(result) => result,
            Err(error) => {
                return Ok(ActionOutcome {
                    action_id: action.action_id,
                    status: ActionStatus::Failed,
                    verification,
                    post_verification: None,
                    output: None,
                    error: Some(error.to_string()),
                    completed_at: OffsetDateTime::now_utc(),
                })
            }
        };

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
            completed_at: OffsetDateTime::now_utc(),
        })
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
        completed_at: OffsetDateTime::now_utc(),
    }
}

fn needs_approval_outcome(action_id: ActionId, verification: VerificationResult) -> ActionOutcome {
    ActionOutcome {
        action_id,
        status: ActionStatus::NeedsApproval,
        verification,
        post_verification: None,
        output: None,
        error: Some("approval_required".to_string()),
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
