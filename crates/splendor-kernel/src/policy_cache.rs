//! Local policy bundle cache and gateway guard for 0.04-S5.
//!
//! The cache is explicit governance state: signed bundles are validated before
//! replacing cached authority, TTL/revocation decisions fail closed, and the
//! action gateway wrapper denies unsafe side effects without introducing any
//! alternate adapter execution path.

use splendor_gateway::{ActionGateway, ActionOutcome, ActionRequest, ActionStatus, GatewayError};
use splendor_types::{
    OfflineHighRiskBehavior, PolicyBundle, PolicyBundleTraceContext, RevocationStatus,
    SideEffectClass, TraceEventKind, ValidatedPolicyBundle, VerificationResult,
};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use time::OffsetDateTime;

/// Local policy cache configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyCacheConfig {
    /// When true, missing policy authority denies policy invocation and action
    /// execution. Existing legacy callers can leave this false until they opt in
    /// to 0.04-S5 policy bundle enforcement.
    pub enforcement_required: bool,
}

/// Last observed policy sync failure. This is observational; it never broadens
/// the cached authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySyncFailure {
    /// Sanitized failure reason.
    pub reason: String,
    /// When the failure was observed.
    pub observed_at: OffsetDateTime,
}

/// Trace/telemetry-safe validation metadata retained with cached policy state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCacheValidationMetadata {
    /// Signature algorithm used by the current reference verifier.
    pub signature_algorithm: String,
    /// Signing key identity, if known. Signature bytes are never stored here.
    pub signature_key_id: Option<String>,
    /// When the bundle was accepted into this cache.
    pub validated_at: OffsetDateTime,
}

impl From<&ValidatedPolicyBundle> for PolicyCacheValidationMetadata {
    fn from(validated: &ValidatedPolicyBundle) -> Self {
        Self {
            signature_algorithm: validated.signature_algorithm().to_string(),
            signature_key_id: Some(validated.signature_key_id().to_string()),
            validated_at: validated.validated_at(),
        }
    }
}

/// Result class for a trusted monotonic policy installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyCacheInstallStatus {
    /// A first or strictly newer signed bundle replaced cached authority.
    Installed,
    /// The exact currently installed signed bundle was retried.
    Idempotent,
}

/// Successful trusted policy installation result.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyCacheInstallResult {
    /// Whether authority changed or the request was an exact retry.
    pub status: PolicyCacheInstallStatus,
    /// Trace-safe current bundle metadata.
    pub bundle: PolicyBundleTraceContext,
    /// Reconnect event produced atomically with an accepted install, if any.
    pub connectivity_event: Option<TraceEventKind>,
    /// Whether an exact retry preserved an existing revocation tombstone.
    pub revocation_preserved: bool,
}

/// Successful trusted revocation tombstone application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCacheRevocationResult {
    /// Trace-safe metadata for the current bundle that became blocked.
    pub bundle: PolicyBundleTraceContext,
    /// Sanitized revocation reason retained by the cache.
    pub reason: String,
}

/// Fail-closed monotonic policy cache mutation errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PolicyCacheInstallError {
    /// Candidate issuance precedes currently installed authority.
    #[error("policy candidate is older than current authority")]
    Rollback,
    /// Equal issuance timestamps carry different signed bundle content.
    #[error("policy candidate conflicts at the current issuance timestamp")]
    SameIssuedAtConflict,
    /// A revocation candidate does not identify the current bundle and scope.
    #[error("policy revocation candidate does not match current authority")]
    RevocationUnrelated,
    /// A revocation candidate predates currently installed authority.
    #[error("policy revocation candidate is older than current authority")]
    RevocationRollback,
    /// Revocation was requested without current cached authority.
    #[error("policy revocation candidate has no current authority")]
    RevocationCurrentMissing,
    /// Active policy installation received a revoked trusted candidate.
    #[error("revoked policy candidate cannot be installed as active authority")]
    RevokedCandidate,
    /// Revocation application received an active trusted candidate.
    #[error("active policy candidate cannot be applied as a revocation")]
    ActiveRevocationCandidate,
    /// Candidate validation time moved behind trusted cache observation time.
    #[error("policy candidate validation clock moved backwards")]
    ValidationClockRollback,
}

impl PolicyCacheInstallError {
    /// Stable sanitized reason for API, trace, and tests.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Rollback => "policy_cache_install_rollback",
            Self::SameIssuedAtConflict => "policy_cache_install_conflict",
            Self::RevocationUnrelated => "policy_cache_revocation_unrelated",
            Self::RevocationRollback => "policy_cache_revocation_rollback",
            Self::RevocationCurrentMissing => "policy_cache_revocation_current_missing",
            Self::RevokedCandidate => "policy_cache_install_revoked_candidate",
            Self::ActiveRevocationCandidate => "policy_cache_revocation_candidate_active",
            Self::ValidationClockRollback => "policy_cache_validation_clock_rollback",
        }
    }
}

/// Runtime-visible offline/cache status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyOfflineStatus {
    /// Central policy connectivity is available and the current bundle is valid.
    Connected,
    /// Central policy connectivity is unavailable but cached authority is still
    /// within TTL.
    DisconnectedWithinTtl,
    /// Central connectivity is unavailable and the cached bundle has expired.
    DegradedExpired,
    /// Cached policy has expired while central connectivity is available.
    Expired,
    /// Required policy authority is unavailable.
    MissingPolicy,
    /// Cached policy authority has been revoked.
    Revoked,
    /// Runtime clock moved behind trusted validation/observation time.
    ClockRollback,
}

/// Snapshot of local policy cache status for API responses, tests, and telemetry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCacheSnapshot {
    /// Whether policy enforcement is required for this run/runtime boundary.
    pub enforcement_required: bool,
    /// Whether the runtime is explicitly disconnected from the central policy
    /// distributor.
    pub disconnected: bool,
    /// Current cached bundle metadata when present.
    pub bundle: Option<PolicyBundleTraceContext>,
    /// Cache validation metadata without signature material.
    pub validation: Option<PolicyCacheValidationMetadata>,
    /// Last successful central sync/cache install time.
    pub last_sync_at: Option<OffsetDateTime>,
    /// Derived status for telemetry and offline/reconnect inspection.
    pub offline_status: PolicyOfflineStatus,
    /// Revocation reason applied to the current bundle, if any.
    pub revoked_reason: Option<String>,
    /// Most recent sync failure.
    pub last_sync_failure: Option<PolicySyncFailure>,
}

#[derive(Clone, Debug, Default)]
struct PolicyCacheState {
    enforcement_required: bool,
    disconnected: bool,
    bundle: Option<PolicyBundle>,
    validation: Option<PolicyCacheValidationMetadata>,
    last_sync_at: Option<OffsetDateTime>,
    revoked_reason: Option<String>,
    last_sync_failure: Option<PolicySyncFailure>,
    max_observed_at: Option<OffsetDateTime>,
    expiry_latched: bool,
}

/// Shareable local policy cache.
#[derive(Clone, Debug)]
pub struct PolicyCache {
    inner: Arc<Mutex<PolicyCacheState>>,
}

impl PolicyCache {
    /// Creates an empty policy cache.
    pub fn new(config: PolicyCacheConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PolicyCacheState {
                enforcement_required: config.enforcement_required,
                ..PolicyCacheState::default()
            })),
        }
    }

    /// Installs trusted signed policy authority monotonically.
    ///
    /// A first or strictly newer bundle replaces authority and clears prior
    /// revocation/expiry tombstones. An exact retry is idempotent and preserves
    /// those tombstones. Older or same-time different-content candidates fail
    /// before mutation. Reconnect is applied atomically only after acceptance.
    pub fn install_validated(
        &self,
        validated: ValidatedPolicyBundle,
        reconnect: bool,
    ) -> Result<PolicyCacheInstallResult, PolicyCacheInstallError> {
        if matches!(
            validated.bundle().revocation,
            RevocationStatus::Revoked { .. }
        ) {
            return Err(PolicyCacheInstallError::RevokedCandidate);
        }
        let validated_at = validated.validated_at();
        let validation = PolicyCacheValidationMetadata::from(&validated);
        let bundle = validated.into_policy_bundle();
        let trace = PolicyBundleTraceContext::from(&bundle);
        let mut guard = self.inner.lock().expect("policy cache lock");
        if guard
            .max_observed_at
            .is_some_and(|observed| validated_at < observed)
        {
            return Err(PolicyCacheInstallError::ValidationClockRollback);
        }
        let (status, replace) = match guard.bundle.as_ref() {
            None => (PolicyCacheInstallStatus::Installed, true),
            Some(current) if bundle.issued_at < current.issued_at => {
                return Err(PolicyCacheInstallError::Rollback)
            }
            Some(current) if bundle.issued_at == current.issued_at && bundle != *current => {
                return Err(PolicyCacheInstallError::SameIssuedAtConflict)
            }
            Some(current) if bundle.issued_at == current.issued_at => {
                (PolicyCacheInstallStatus::Idempotent, false)
            }
            Some(_) => (PolicyCacheInstallStatus::Installed, true),
        };
        let revocation_preserved = !replace && guard.revoked_reason.is_some();
        guard.enforcement_required = true;
        if replace {
            guard.bundle = Some(bundle);
            guard.revoked_reason = None;
            guard.expiry_latched = false;
        }
        guard.validation = Some(validation);
        guard.last_sync_at = Some(validated_at);
        guard.max_observed_at = Some(validated_at);
        guard.last_sync_failure = None;
        let connectivity_event = if reconnect && guard.disconnected {
            guard.disconnected = false;
            Some(TraceEventKind::PolicyConnectivityChanged {
                disconnected: false,
                observed_at: validated_at,
                bundle: Some(trace.clone()),
            })
        } else {
            None
        };
        Ok(PolicyCacheInstallResult {
            status,
            bundle: trace,
            connectivity_event,
            revocation_preserved,
        })
    }

    /// Marks central connectivity unavailable. This restrictive transition does
    /// not require a policy candidate.
    pub fn mark_disconnected(&self) {
        self.inner.lock().expect("policy cache lock").disconnected = true;
    }

    /// Marks central connectivity unavailable and emits a trace-safe transition
    /// only when state changed. Reconnect is available only through an accepted
    /// trusted monotonic installation.
    pub fn mark_disconnected_with_trace(
        &self,
        observed_at: OffsetDateTime,
    ) -> Option<TraceEventKind> {
        let mut guard = self.inner.lock().expect("policy cache lock");
        if guard.disconnected {
            return None;
        }
        guard.disconnected = true;
        let bundle = guard.bundle.as_ref().map(PolicyBundleTraceContext::from);
        Some(TraceEventKind::PolicyConnectivityChanged {
            disconnected: true,
            observed_at,
            bundle,
        })
    }

    /// Records a sync failure without replacing cached authority.
    pub fn record_sync_failure(
        &self,
        reason: impl Into<String>,
        observed_at: OffsetDateTime,
    ) -> PolicySyncFailure {
        let failure = PolicySyncFailure {
            reason: sanitize_policy_reason(reason.into()),
            observed_at,
        };
        self.inner
            .lock()
            .expect("policy cache lock")
            .last_sync_failure = Some(failure.clone());
        failure
    }

    /// Applies a trusted signed revocation candidate only when it matches current
    /// bundle identity/scope and is not older. Unrelated or stale candidates fail
    /// without mutating current authority.
    pub fn apply_validated_revocation(
        &self,
        validated: ValidatedPolicyBundle,
    ) -> Result<PolicyCacheRevocationResult, PolicyCacheInstallError> {
        let RevocationStatus::Revoked { reason } = &validated.bundle().revocation else {
            return Err(PolicyCacheInstallError::ActiveRevocationCandidate);
        };
        let candidate = validated.bundle();
        let mut guard = self.inner.lock().expect("policy cache lock");
        if guard
            .max_observed_at
            .is_some_and(|observed| validated.validated_at() < observed)
        {
            return Err(PolicyCacheInstallError::ValidationClockRollback);
        }
        let current = guard
            .bundle
            .as_ref()
            .ok_or(PolicyCacheInstallError::RevocationCurrentMissing)?;
        if candidate.issued_at < current.issued_at {
            return Err(PolicyCacheInstallError::RevocationRollback);
        }
        if candidate.policy_bundle_id != current.policy_bundle_id
            || candidate.tenant_id != current.tenant_id
            || candidate.agent_id != current.agent_id
        {
            return Err(PolicyCacheInstallError::RevocationUnrelated);
        }
        let trace = PolicyBundleTraceContext::from(current);
        let reason = sanitize_policy_reason(reason.clone());
        guard.revoked_reason = Some(reason.clone());
        guard.max_observed_at = Some(
            guard
                .max_observed_at
                .map_or(validated.validated_at(), |observed| {
                    observed.max(validated.validated_at())
                }),
        );
        Ok(PolicyCacheRevocationResult {
            bundle: trace,
            reason,
        })
    }

    /// Returns a stable snapshot of cache status.
    pub fn snapshot(&self) -> PolicyCacheSnapshot {
        self.snapshot_at(OffsetDateTime::now_utc())
    }

    /// Returns a deterministic cache snapshot at the supplied observation time.
    pub fn snapshot_at(&self, now: OffsetDateTime) -> PolicyCacheSnapshot {
        let mut guard = self.inner.lock().expect("policy cache lock");
        let offline_status = guard.offline_status(now);
        PolicyCacheSnapshot {
            enforcement_required: guard.enforcement_required,
            disconnected: guard.disconnected,
            bundle: guard.bundle.as_ref().map(PolicyBundleTraceContext::from),
            validation: guard.validation.clone(),
            last_sync_at: guard.last_sync_at,
            offline_status,
            revoked_reason: guard.revoked_reason.clone(),
            last_sync_failure: guard.last_sync_failure.clone(),
        }
    }
}

impl PolicyCacheState {
    fn offline_status(&mut self, now: OffsetDateTime) -> PolicyOfflineStatus {
        if self.bundle.is_none() {
            return PolicyOfflineStatus::MissingPolicy;
        }
        match self.observe_runtime_time(now) {
            PolicyRuntimeTimeStatus::ClockRollback => return PolicyOfflineStatus::ClockRollback,
            PolicyRuntimeTimeStatus::Expired => {
                return if self.disconnected {
                    PolicyOfflineStatus::DegradedExpired
                } else {
                    PolicyOfflineStatus::Expired
                }
            }
            PolicyRuntimeTimeStatus::Current => {}
        }
        if self.revoked_reason.is_some() {
            return PolicyOfflineStatus::Revoked;
        }
        if self.disconnected {
            PolicyOfflineStatus::DisconnectedWithinTtl
        } else {
            PolicyOfflineStatus::Connected
        }
    }

    fn observe_runtime_time(&mut self, now: OffsetDateTime) -> PolicyRuntimeTimeStatus {
        let Some(bundle) = self.bundle.as_ref() else {
            return PolicyRuntimeTimeStatus::Current;
        };
        let issued_at = bundle.issued_at;
        let expires_at = bundle.expires_at;
        let validated_at = self
            .validation
            .as_ref()
            .map(|validation| validation.validated_at)
            .unwrap_or(issued_at);
        if now < validated_at || self.max_observed_at.is_some_and(|observed| now < observed) {
            return PolicyRuntimeTimeStatus::ClockRollback;
        }
        self.max_observed_at = Some(
            self.max_observed_at
                .map_or(now, |observed| observed.max(now)),
        );
        if self.expiry_latched || expires_at <= now {
            self.expiry_latched = true;
            PolicyRuntimeTimeStatus::Expired
        } else {
            PolicyRuntimeTimeStatus::Current
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyRuntimeTimeStatus {
    Current,
    Expired,
    ClockRollback,
}

/// Policy invocation decision returned before `PolicyInvoked` is emitted.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyRuntimeDecision {
    /// Verification outcome for policy invocation.
    pub verification: VerificationResult,
    /// Optional trace event explaining a policy governance transition.
    pub trace_event: Option<TraceEventKind>,
}

impl PolicyRuntimeDecision {
    /// Allows policy invocation.
    pub fn allow() -> Self {
        Self {
            verification: VerificationResult::allow(),
            trace_event: None,
        }
    }
}

/// Runtime authority check that can stop policy invocation before policy code
/// runs. This is separate from action-gateway enforcement so invalid/missing
/// bundles can fail closed before `PolicyInvoked`.
pub trait PolicyRuntimeAuthority: Send + Sync {
    /// Verifies whether the policy callback may be invoked at `now`.
    fn verify_policy_invocation(
        &self,
        policy_name: &str,
        now: OffsetDateTime,
    ) -> PolicyRuntimeDecision;
}

/// Action-level policy distribution status used by the gateway wrapper.
pub trait PolicyDistributionStatus: Send + Sync {
    /// Verifies whether an action may continue to the wrapped gateway.
    fn verify_policy_action(
        &self,
        request: &ActionRequest,
        now: OffsetDateTime,
    ) -> VerificationResult;
}

impl PolicyRuntimeAuthority for PolicyCache {
    fn verify_policy_invocation(
        &self,
        policy_name: &str,
        now: OffsetDateTime,
    ) -> PolicyRuntimeDecision {
        let mut guard = self.inner.lock().expect("policy cache lock");
        if !guard.enforcement_required && guard.bundle.is_none() {
            return PolicyRuntimeDecision::allow();
        }
        if guard.bundle.is_none() {
            return PolicyRuntimeDecision {
                verification: policy_unavailable(policy_name),
                trace_event: None,
            };
        }
        let runtime_time = guard.observe_runtime_time(now);
        let bundle = guard.bundle.as_ref().expect("bundle checked");
        match runtime_time {
            PolicyRuntimeTimeStatus::ClockRollback => {
                return PolicyRuntimeDecision {
                    verification: policy_clock_rollback(bundle, policy_name),
                    trace_event: None,
                }
            }
            PolicyRuntimeTimeStatus::Expired => {
                return PolicyRuntimeDecision {
                    verification: policy_expired(bundle, None, guard.disconnected),
                    trace_event: Some(policy_expired_event(bundle, None)),
                }
            }
            PolicyRuntimeTimeStatus::Current => {}
        }
        if let Some(reason) = guard.revoked_reason.as_ref() {
            return PolicyRuntimeDecision {
                verification: policy_revoked(bundle, reason),
                trace_event: Some(policy_revoked_event(bundle, reason.clone())),
            };
        }
        PolicyRuntimeDecision::allow()
    }
}

impl PolicyDistributionStatus for PolicyCache {
    fn verify_policy_action(
        &self,
        request: &ActionRequest,
        now: OffsetDateTime,
    ) -> VerificationResult {
        let mut guard = self.inner.lock().expect("policy cache lock");
        if !guard.enforcement_required && guard.bundle.is_none() {
            return VerificationResult::allow();
        }
        if guard.bundle.is_none() {
            return policy_unavailable(&request.action.name);
        }
        let runtime_time = guard.observe_runtime_time(now);
        let bundle = guard.bundle.as_ref().expect("bundle checked");
        match runtime_time {
            PolicyRuntimeTimeStatus::ClockRollback => {
                return policy_clock_rollback(bundle, &request.action.name)
            }
            PolicyRuntimeTimeStatus::Expired => {
                return policy_expired(
                    bundle,
                    Some(request.action.name.as_str()),
                    guard.disconnected,
                )
            }
            PolicyRuntimeTimeStatus::Current => {}
        }
        if let Some(reason) = guard.revoked_reason.as_ref() {
            return policy_revoked(bundle, reason);
        }
        if guard.disconnected {
            if is_high_risk_offline_action(bundle, request) {
                return policy_disconnected_high_risk(bundle, request);
            }
            if !is_explicit_low_risk_offline_action(bundle, request) {
                return policy_disconnected_not_allowed(bundle, request);
            }
        }

        VerificationResult::allow()
    }
}

/// Gateway wrapper that enforces policy TTL/revocation before the wrapped gateway
/// can reach adapters. Denials remain normal gateway outcomes and are traced by
/// existing action trace events.
pub struct PolicyDistributionGateway {
    inner: Arc<dyn ActionGateway>,
    status: Arc<dyn PolicyDistributionStatus>,
}

impl PolicyDistributionGateway {
    /// Wraps an existing action gateway with policy distribution enforcement.
    pub fn new(inner: Arc<dyn ActionGateway>, status: Arc<dyn PolicyDistributionStatus>) -> Self {
        Self { inner, status }
    }
}

impl ActionGateway for PolicyDistributionGateway {
    fn submit(&self, request: ActionRequest) -> Result<ActionOutcome, GatewayError> {
        let verification = self
            .status
            .verify_policy_action(&request, OffsetDateTime::now_utc());
        if !verification.allowed {
            return Ok(policy_outcome(request, verification));
        }

        self.inner.submit(request)
    }
}

fn policy_outcome(request: ActionRequest, verification: VerificationResult) -> ActionOutcome {
    let error = if verification.reasons.is_empty() {
        "policy_distribution_denied".to_string()
    } else {
        verification.reasons.join(", ")
    };
    let status = if verification
        .reasons
        .iter()
        .any(|reason| reason == "offline_high_risk_needs_local_intervention")
    {
        ActionStatus::NeedsIntervention
    } else {
        ActionStatus::Denied
    };
    ActionOutcome {
        action_id: request.action_id,
        status,
        verification,
        post_verification: None,
        output: None,
        error: Some(error),
        completed_at: OffsetDateTime::now_utc(),
    }
}

fn is_explicit_low_risk_offline_action(bundle: &PolicyBundle, request: &ActionRequest) -> bool {
    matches!(request.action.side_effect_class, SideEffectClass::ReadOnly)
        && bundle
            .degraded_mode
            .disconnected_low_risk_actions
            .iter()
            .any(|action| action == &request.action.name)
}

fn is_high_risk_offline_action(bundle: &PolicyBundle, request: &ActionRequest) -> bool {
    bundle
        .degraded_mode
        .disconnected_high_risk_actions
        .iter()
        .any(|action| action == &request.action.name)
}

fn policy_disconnected_high_risk(
    bundle: &PolicyBundle,
    request: &ActionRequest,
) -> VerificationResult {
    let reason = match bundle.degraded_mode.high_risk_disconnected_behavior {
        OfflineHighRiskBehavior::Deny => "offline_high_risk_denied",
        OfflineHighRiskBehavior::NeedsLocalIntervention => {
            "offline_high_risk_needs_local_intervention"
        }
    };
    VerificationResult {
        allowed: false,
        reasons: vec![reason.to_string()],
        artifacts: serde_json::json!({
            "source": "policy_distribution_cache",
            "policy_bundle_id": bundle.policy_bundle_id.to_string(),
            "version": bundle.version,
            "action": request.action.name,
            "disconnected": true,
        }),
    }
}

fn policy_disconnected_not_allowed(
    bundle: &PolicyBundle,
    request: &ActionRequest,
) -> VerificationResult {
    VerificationResult {
        allowed: false,
        reasons: vec!["offline_action_not_allowed".to_string()],
        artifacts: serde_json::json!({
            "source": "policy_distribution_cache",
            "policy_bundle_id": bundle.policy_bundle_id.to_string(),
            "version": bundle.version,
            "action": request.action.name,
            "disconnected": true,
        }),
    }
}

fn policy_unavailable(policy_name: &str) -> VerificationResult {
    VerificationResult {
        allowed: false,
        reasons: vec!["policy_unavailable".to_string()],
        artifacts: serde_json::json!({
            "source": "policy_distribution_cache",
            "policy": policy_name,
        }),
    }
}

fn policy_clock_rollback(bundle: &PolicyBundle, policy_name: &str) -> VerificationResult {
    VerificationResult {
        allowed: false,
        reasons: vec!["policy_clock_rollback".to_string()],
        artifacts: serde_json::json!({
            "source": "policy_distribution_cache",
            "policy_bundle_id": bundle.policy_bundle_id.to_string(),
            "version": bundle.version,
            "policy": policy_name,
        }),
    }
}

fn policy_expired(
    bundle: &PolicyBundle,
    action: Option<&str>,
    disconnected: bool,
) -> VerificationResult {
    VerificationResult {
        allowed: false,
        reasons: vec!["policy_expired".to_string()],
        artifacts: serde_json::json!({
            "source": "policy_distribution_cache",
            "policy_bundle_id": bundle.policy_bundle_id.to_string(),
            "version": bundle.version,
            "action": action,
            "expires_at": bundle.expires_at.unix_timestamp(),
            "disconnected": disconnected,
            "allow_low_risk_cached": bundle.degraded_mode.allow_low_risk_cached,
        }),
    }
}

fn policy_revoked(bundle: &PolicyBundle, reason: &str) -> VerificationResult {
    VerificationResult {
        allowed: false,
        reasons: vec!["policy_revoked".to_string()],
        artifacts: serde_json::json!({
            "source": "policy_distribution_cache",
            "policy_bundle_id": bundle.policy_bundle_id.to_string(),
            "version": bundle.version,
            "reason": reason,
        }),
    }
}

fn policy_expired_event(bundle: &PolicyBundle, action: Option<String>) -> TraceEventKind {
    TraceEventKind::PolicyExpired {
        policy_bundle_id: bundle.policy_bundle_id.clone(),
        version: bundle.version.clone(),
        action,
    }
}

fn policy_revoked_event(bundle: &PolicyBundle, reason: String) -> TraceEventKind {
    TraceEventKind::PolicyRevoked {
        policy_bundle_id: bundle.policy_bundle_id.clone(),
        version: bundle.version.clone(),
        reason: sanitize_policy_reason(reason),
    }
}

fn sanitize_policy_reason(reason: String) -> String {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return "policy_reason_unspecified".to_string();
    }
    let lowercase = trimmed.to_ascii_lowercase();
    let sensitive_markers = [
        "secret",
        "signature",
        "token",
        "credential",
        "password",
        "bearer",
        "apikey",
        "api_key",
        "key=",
    ];
    let safe_code = trimmed.len() <= 80
        && trimmed.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        });
    if !safe_code
        || sensitive_markers
            .iter()
            .any(|marker| lowercase.contains(marker))
    {
        return "policy_reason_redacted".to_string();
    }
    trimmed.to_string()
}

#[cfg(test)]
#[path = "../tests/unit/policy_cache_tests.rs"]
mod tests;
