//! Bounded AUTH-005a revocation and offline cached-grant evaluation.
//!
//! This module is an authority-owned local foundation only. It caches already
//! validated capability grants, checks an explicit revocation snapshot, and applies
//! a pinned disconnected-mode policy before delegating normal scope evaluation to
//! `evaluate_capability_request`. It does not implement production revocation
//! watches, external introspection, lease renewal, node/fleet integration, daemon
//! APIs, incident-controller integration, or any adapter execution path.

use crate::{evaluate_capability_request, ValidatedCapabilityGrant};
use splendor_types::{
    AuthorityDecision, AuthorityDecisionId, AuthorityDecisionStatus, AuthorityOperation,
    AuthorityOperationNamespace, AuthorityResourceKind, AuthorityVerb, CapabilityGrantId,
    CapabilityRequest, RevocationRecord, RevocationStatus, AUTHORITY_DECISION_SCHEMA_VERSION,
    REVOCATION_RECORD_SCHEMA_VERSION,
};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Stable denial reason for an empty local authority grant cache.
pub const REASON_AUTHORITY_CACHE_MISSING: &str = "authority_cache_missing";
/// Stable denial reason for a cached grant whose local cache window has expired.
pub const REASON_AUTHORITY_CACHE_EXPIRED: &str = "authority_cache_expired";
/// Stable denial reason for a cached grant older than the configured freshness window.
pub const REASON_AUTHORITY_CACHE_STALE: &str = "authority_cache_stale";
/// Stable denial reason for a cache entry installed in the future relative to evaluation time.
pub const REASON_AUTHORITY_CACHE_FUTURE_DATED: &str = "authority_cache_future_dated";
/// Stable denial reason for a missing revocation snapshot.
pub const REASON_AUTHORITY_REVOCATION_SNAPSHOT_MISSING: &str =
    "authority_revocation_snapshot_missing";
/// Stable denial reason for an expired/stale revocation snapshot.
pub const REASON_AUTHORITY_REVOCATION_SNAPSHOT_STALE: &str = "authority_revocation_snapshot_stale";
/// Stable denial reason for a future-dated revocation snapshot.
pub const REASON_AUTHORITY_REVOCATION_SNAPSHOT_FUTURE_DATED: &str =
    "authority_revocation_snapshot_future_dated";
/// Stable denial reason for revocation records that revoke a cached grant.
pub const REASON_AUTHORITY_GRANT_REVOKED: &str = "authority_grant_revoked";
/// Stable denial reason for mismatched revocation lookup coordinates.
pub const REASON_AUTHORITY_REVOCATION_REF_MISMATCH: &str = "authority_revocation_ref_mismatch";
/// Stable denial reason when disconnected mode has no safe operation policy for a request.
pub const REASON_AUTHORITY_OFFLINE_UNSUPPORTED_OPERATION: &str =
    "authority_offline_unsupported_operation";
/// Stable denial reason when a disconnected high-risk operation is denied outright.
pub const REASON_AUTHORITY_OFFLINE_HIGH_RISK_DENIED: &str = "authority_offline_high_risk_denied";
/// Stable reason when a disconnected high-risk operation requires local intervention.
pub const REASON_AUTHORITY_OFFLINE_HIGH_RISK_NEEDS_INTERVENTION: &str =
    "authority_offline_high_risk_needs_intervention";
/// Stable denial reason when a cached grant exceeds the disconnected-mode TTL.
pub const REASON_AUTHORITY_OFFLINE_TTL_EXPIRED: &str = "authority_offline_ttl_expired";
/// Stable denial reason added when normal capability evaluation rejects an overbroad scope.
pub const REASON_AUTHORITY_SCOPE_MISMATCH: &str = "authority_scope_mismatch";

/// Explicit connectivity state for local authority evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityConnectivity {
    /// Central authority/revocation connectivity is currently available.
    Connected,
    /// Central authority/revocation connectivity is unavailable; only pinned
    /// safe-degraded behavior may use cached grants.
    Disconnected,
}

/// Policy for high-risk operations requested while disconnected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityOfflineHighRiskBehavior {
    /// Deny the operation fail-closed.
    Deny,
    /// Return `NeedsIntervention` so a local operator/runtime safety path can
    /// decide outside this bounded authority slice.
    NeedsIntervention,
}

/// Explicit policy for cached authority when central connectivity is unavailable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineAuthorityPolicy {
    connectivity: AuthorityConnectivity,
    max_cache_staleness: Duration,
    offline_grant_ttl: Duration,
    disconnected_low_risk_operations: Vec<AuthorityOperation>,
    high_risk_behavior: AuthorityOfflineHighRiskBehavior,
}

impl OfflineAuthorityPolicy {
    /// Builds a connected-mode policy. Cached grants still must be fresh and
    /// unexpired; disconnected low-risk lists are ignored while connected.
    pub fn connected(max_cache_staleness: Duration) -> Result<Self, AuthorityOfflinePolicyError> {
        Self::new(
            AuthorityConnectivity::Connected,
            max_cache_staleness,
            max_cache_staleness,
            Vec::new(),
            AuthorityOfflineHighRiskBehavior::Deny,
        )
    }

    /// Builds a disconnected-mode policy. Only exact operations in
    /// `disconnected_low_risk_operations` that are also classified as low-risk
    /// reads can evaluate against cached grants while disconnected.
    pub fn disconnected(
        max_cache_staleness: Duration,
        offline_grant_ttl: Duration,
        disconnected_low_risk_operations: Vec<AuthorityOperation>,
        high_risk_behavior: AuthorityOfflineHighRiskBehavior,
    ) -> Result<Self, AuthorityOfflinePolicyError> {
        Self::new(
            AuthorityConnectivity::Disconnected,
            max_cache_staleness,
            offline_grant_ttl,
            disconnected_low_risk_operations,
            high_risk_behavior,
        )
    }

    fn new(
        connectivity: AuthorityConnectivity,
        max_cache_staleness: Duration,
        offline_grant_ttl: Duration,
        disconnected_low_risk_operations: Vec<AuthorityOperation>,
        high_risk_behavior: AuthorityOfflineHighRiskBehavior,
    ) -> Result<Self, AuthorityOfflinePolicyError> {
        if max_cache_staleness <= Duration::ZERO {
            return Err(AuthorityOfflinePolicyError::InvalidDuration {
                field: "max_cache_staleness",
            });
        }
        if offline_grant_ttl <= Duration::ZERO {
            return Err(AuthorityOfflinePolicyError::InvalidDuration {
                field: "offline_grant_ttl",
            });
        }
        Ok(Self {
            connectivity,
            max_cache_staleness,
            offline_grant_ttl,
            disconnected_low_risk_operations,
            high_risk_behavior,
        })
    }

    /// Returns the explicit connectivity mode used by this policy.
    pub fn connectivity(&self) -> AuthorityConnectivity {
        self.connectivity
    }

    /// Returns the maximum local cache freshness window.
    pub fn max_cache_staleness(&self) -> Duration {
        self.max_cache_staleness
    }

    /// Returns the maximum disconnected-mode lifetime for cached grants.
    pub fn offline_grant_ttl(&self) -> Duration {
        self.offline_grant_ttl
    }

    /// Returns the exact operations declared safe for disconnected low-risk use.
    pub fn disconnected_low_risk_operations(&self) -> &[AuthorityOperation] {
        &self.disconnected_low_risk_operations
    }

    /// Returns the configured disconnected high-risk behavior.
    pub fn high_risk_behavior(&self) -> AuthorityOfflineHighRiskBehavior {
        self.high_risk_behavior
    }
}

/// A cached grant that can only be constructed from `ValidatedCapabilityGrant`.
#[derive(Clone, Debug, PartialEq)]
pub struct CachedAuthorityGrant {
    grant: ValidatedCapabilityGrant,
    cached_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl CachedAuthorityGrant {
    /// Wraps an already validated grant for local cache use. The cache expiry must
    /// not outlive the grant's own expiry, so the cache cannot extend authority.
    pub fn try_new(
        grant: ValidatedCapabilityGrant,
        cached_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Self, AuthorityGrantCacheError> {
        if expires_at <= cached_at {
            return Err(AuthorityGrantCacheError::InvalidCacheWindow);
        }
        if cached_at >= grant.grant().expires_at {
            return Err(AuthorityGrantCacheError::CachedAfterGrantExpiry);
        }
        if expires_at > grant.grant().expires_at {
            return Err(AuthorityGrantCacheError::CacheOutlivesGrant);
        }
        Ok(Self {
            grant,
            cached_at,
            expires_at,
        })
    }

    /// Returns the validated grant wrapper. Raw `CapabilityGrant` payloads are not
    /// accepted by this cache API.
    pub fn grant(&self) -> &ValidatedCapabilityGrant {
        &self.grant
    }

    /// Returns when this cache entry was installed.
    pub fn cached_at(&self) -> OffsetDateTime {
        self.cached_at
    }

    /// Returns the local cache expiry, which is never later than grant expiry.
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

/// Local authority grant cache containing only validated grant wrappers.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuthorityGrantCache {
    grants: Vec<CachedAuthorityGrant>,
}

impl AuthorityGrantCache {
    /// Creates an empty cache. Empty caches deny fail-closed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a validated grant. There is intentionally no raw `CapabilityGrant`
    /// insertion API.
    pub fn insert_validated(
        &mut self,
        grant: ValidatedCapabilityGrant,
        cached_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Option<CachedAuthorityGrant>, AuthorityGrantCacheError> {
        let cached = CachedAuthorityGrant::try_new(grant, cached_at, expires_at)?;
        Ok(self.insert_cached(cached))
    }

    /// Inserts a pre-built cached validated grant and replaces an entry with the
    /// same grant ID, if present.
    pub fn insert_cached(&mut self, cached: CachedAuthorityGrant) -> Option<CachedAuthorityGrant> {
        if let Some(position) = self.grants.iter().position(|candidate| {
            candidate.grant().grant().grant_id == cached.grant().grant().grant_id
        }) {
            Some(std::mem::replace(&mut self.grants[position], cached))
        } else {
            self.grants.push(cached);
            None
        }
    }

    /// Returns true when the cache contains no validated grants.
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Returns cached validated grants for inspection and tests.
    pub fn cached_grants(&self) -> &[CachedAuthorityGrant] {
        &self.grants
    }
}

/// Local immutable revocation snapshot used to check cached grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationSnapshot {
    records: Vec<RevocationRecord>,
    refreshed_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl RevocationSnapshot {
    /// Builds a revocation snapshot from records that were already obtained from
    /// a trusted local source. Expired snapshots deny fail-closed during checking.
    pub fn try_new(
        records: Vec<RevocationRecord>,
        refreshed_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Self, AuthorityRevocationSnapshotError> {
        if expires_at <= refreshed_at {
            return Err(AuthorityRevocationSnapshotError::InvalidWindow);
        }
        for (index, record) in records.iter().enumerate() {
            validate_revocation_record(record)?;
            if records
                .iter()
                .skip(index + 1)
                .any(|candidate| candidate.grant_id == record.grant_id)
            {
                return Err(AuthorityRevocationSnapshotError::DuplicateGrantRecord {
                    grant_id: record.grant_id.clone(),
                });
            }
        }
        Ok(Self {
            records,
            refreshed_at,
            expires_at,
        })
    }

    /// Builds a snapshot with an explicit maximum age.
    pub fn with_max_age(
        records: Vec<RevocationRecord>,
        refreshed_at: OffsetDateTime,
        max_age: Duration,
    ) -> Result<Self, AuthorityRevocationSnapshotError> {
        if max_age <= Duration::ZERO {
            return Err(AuthorityRevocationSnapshotError::InvalidMaxAge);
        }
        let Some(expires_at) = refreshed_at.checked_add(max_age) else {
            return Err(AuthorityRevocationSnapshotError::InvalidMaxAge);
        };
        Self::try_new(records, refreshed_at, expires_at)
    }

    /// Returns when this snapshot was refreshed.
    pub fn refreshed_at(&self) -> OffsetDateTime {
        self.refreshed_at
    }

    /// Returns when this snapshot becomes stale and must deny fail-closed.
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Returns the records in this local snapshot.
    pub fn records(&self) -> &[RevocationRecord] {
        &self.records
    }

    /// Returns whether this trusted snapshot contains a revoked record for the
    /// supplied grant ID.
    ///
    /// This helper intentionally does not evaluate snapshot freshness or expiry;
    /// callers that need liveness checks should use [`Self::verify_grant_active`]
    /// with a validated grant.
    pub fn revokes_grant_id(&self, grant_id: &CapabilityGrantId) -> bool {
        self.records.iter().any(|record| {
            &record.grant_id == grant_id
                && matches!(record.status, RevocationStatus::Revoked { .. })
        })
    }

    /// Checks a validated grant against this revocation snapshot.
    pub fn verify_grant_active(
        &self,
        grant: &ValidatedCapabilityGrant,
        now: OffsetDateTime,
    ) -> Result<(), AuthorityRevocationCheckError> {
        if now < self.refreshed_at {
            return Err(AuthorityRevocationCheckError::SnapshotFutureDated);
        }
        if now >= self.expires_at {
            return Err(AuthorityRevocationCheckError::SnapshotStale);
        }
        if matches!(grant.grant().revocation, RevocationStatus::Revoked { .. }) {
            return Err(AuthorityRevocationCheckError::GrantRevoked {
                grant_id: grant.grant().grant_id.clone(),
            });
        }
        if let Some(record) = self
            .records
            .iter()
            .find(|record| record.grant_id == grant.grant().grant_id)
        {
            if let (Some(grant_ref), Some(record_ref)) = (
                grant.grant().revocation_ref.as_deref(),
                record.revocation_ref.as_deref(),
            ) {
                if grant_ref != record_ref {
                    return Err(AuthorityRevocationCheckError::RevocationRefMismatch {
                        grant_id: grant.grant().grant_id.clone(),
                    });
                }
            }
            if matches!(record.status, RevocationStatus::Revoked { .. }) {
                return Err(AuthorityRevocationCheckError::GrantRevoked {
                    grant_id: grant.grant().grant_id.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Evaluates a request through the local cached authority and revocation snapshot.
///
/// This function never accepts raw grants, never renews authority implicitly, and
/// never executes side effects. When disconnected, it evaluates only exact
/// configured low-risk reads (including explicitly listed device sensing reads)
/// within the cache TTL; high-risk physical actuation, change, and self-change
/// requests deny or require intervention according to policy.
pub fn evaluate_cached_capability_request(
    cache: &AuthorityGrantCache,
    revocations: Option<&RevocationSnapshot>,
    policy: &OfflineAuthorityPolicy,
    request: &CapabilityRequest,
    now: OffsetDateTime,
) -> AuthorityDecision {
    if cache.is_empty() {
        return decision_with_status(
            request.clone(),
            now,
            AuthorityDecisionStatus::Denied,
            vec![REASON_AUTHORITY_CACHE_MISSING.to_string()],
        );
    }

    let Some(revocations) = revocations else {
        return decision_with_status(
            request.clone(),
            now,
            AuthorityDecisionStatus::Denied,
            vec![REASON_AUTHORITY_REVOCATION_SNAPSHOT_MISSING.to_string()],
        );
    };

    let mut denial_reasons = Vec::new();

    for cached in cache.cached_grants() {
        if cached.cached_at() > now {
            push_unique(
                &mut denial_reasons,
                REASON_AUTHORITY_CACHE_FUTURE_DATED.to_string(),
            );
            continue;
        }
        if now >= cached.expires_at() || now >= cached.grant().grant().expires_at {
            push_unique(
                &mut denial_reasons,
                REASON_AUTHORITY_CACHE_EXPIRED.to_string(),
            );
            continue;
        }
        if cache_age_exceeded(cached.cached_at(), policy.max_cache_staleness(), now) {
            push_unique(
                &mut denial_reasons,
                REASON_AUTHORITY_CACHE_STALE.to_string(),
            );
            continue;
        }
        if let Err(error) = revocations.verify_grant_active(cached.grant(), now) {
            push_unique(&mut denial_reasons, error.reason_code().to_string());
            continue;
        }

        let decision =
            evaluate_capability_request(std::slice::from_ref(cached.grant()), request, now);
        if decision.status == AuthorityDecisionStatus::Denied {
            for reason in decision.reasons {
                push_unique(&mut denial_reasons, reason);
            }
            continue;
        }

        if let Err(offline) = verify_offline_policy(cached, policy, request, now) {
            let reason = offline.reason_code();
            match offline {
                OfflineAuthorityDenial::OfflineTtlExpired => {
                    push_unique(&mut denial_reasons, reason.to_string());
                    continue;
                }
                OfflineAuthorityDenial::HighRiskNeedsIntervention => {
                    return decision_with_status(
                        request.clone(),
                        now,
                        AuthorityDecisionStatus::NeedsIntervention,
                        vec![reason.to_string()],
                    );
                }
                OfflineAuthorityDenial::UnsupportedOfflineOperation
                | OfflineAuthorityDenial::HighRiskDenied => {
                    return decision_with_status(
                        request.clone(),
                        now,
                        AuthorityDecisionStatus::Denied,
                        vec![reason.to_string()],
                    );
                }
            }
        }

        return decision;
    }

    if denial_reasons.is_empty() {
        denial_reasons.push(REASON_AUTHORITY_CACHE_MISSING.to_string());
    }
    if denial_reasons
        .iter()
        .any(|reason| is_scope_mismatch_reason(reason))
    {
        push_unique(
            &mut denial_reasons,
            REASON_AUTHORITY_SCOPE_MISMATCH.to_string(),
        );
    }
    decision_with_status(
        request.clone(),
        now,
        AuthorityDecisionStatus::Denied,
        denial_reasons,
    )
}

fn verify_offline_policy(
    cached: &CachedAuthorityGrant,
    policy: &OfflineAuthorityPolicy,
    request: &CapabilityRequest,
    now: OffsetDateTime,
) -> Result<(), OfflineAuthorityDenial> {
    if policy.connectivity() == AuthorityConnectivity::Connected {
        return Ok(());
    }
    if cache_age_exceeded(cached.cached_at(), policy.offline_grant_ttl(), now) {
        return Err(OfflineAuthorityDenial::OfflineTtlExpired);
    }
    if is_high_risk_operation(&request.operation) {
        return Err(match policy.high_risk_behavior() {
            AuthorityOfflineHighRiskBehavior::Deny => OfflineAuthorityDenial::HighRiskDenied,
            AuthorityOfflineHighRiskBehavior::NeedsIntervention => {
                OfflineAuthorityDenial::HighRiskNeedsIntervention
            }
        });
    }
    if !is_low_risk_read_operation(&request.operation)
        || !policy
            .disconnected_low_risk_operations()
            .iter()
            .any(|operation| operation == &request.operation)
    {
        return Err(OfflineAuthorityDenial::UnsupportedOfflineOperation);
    }
    Ok(())
}

fn cache_age_exceeded(cached_at: OffsetDateTime, ttl: Duration, now: OffsetDateTime) -> bool {
    match cached_at.checked_add(ttl) {
        Some(expires_at) => now >= expires_at,
        None => true,
    }
}

fn validate_revocation_record(
    record: &RevocationRecord,
) -> Result<(), AuthorityRevocationSnapshotError> {
    if record.schema_version != REVOCATION_RECORD_SCHEMA_VERSION {
        return Err(AuthorityRevocationSnapshotError::InvalidRecordSchema {
            expected: REVOCATION_RECORD_SCHEMA_VERSION,
            actual: record.schema_version.clone(),
        });
    }
    if record.revocation_id.is_nil() {
        return Err(AuthorityRevocationSnapshotError::InvalidRecordIdentity {
            field: "revocation_id",
        });
    }
    if record.grant_id.is_nil() {
        return Err(AuthorityRevocationSnapshotError::InvalidRecordIdentity { field: "grant_id" });
    }
    Ok(())
}

fn is_low_risk_read_operation(operation: &AuthorityOperation) -> bool {
    matches!(
        (operation.namespace, operation.resource_kind, operation.verb),
        (
            AuthorityOperationNamespace::Data,
            AuthorityResourceKind::Data,
            AuthorityVerb::Read,
        ) | (
            AuthorityOperationNamespace::Artifact,
            AuthorityResourceKind::Artifact,
            AuthorityVerb::Read,
        ) | (
            AuthorityOperationNamespace::State,
            AuthorityResourceKind::StatePartition,
            AuthorityVerb::Read,
        ) | (
            AuthorityOperationNamespace::Device,
            AuthorityResourceKind::Device,
            AuthorityVerb::Read,
        )
    )
}

fn is_high_risk_operation(operation: &AuthorityOperation) -> bool {
    matches!(
        (operation.namespace, operation.resource_kind, operation.verb),
        (
            AuthorityOperationNamespace::Device,
            AuthorityResourceKind::Device,
            AuthorityVerb::Actuate,
        ) | (
            AuthorityOperationNamespace::Change,
            AuthorityResourceKind::Change,
            AuthorityVerb::Propose | AuthorityVerb::Activate,
        ) | (
            AuthorityOperationNamespace::Agent,
            AuthorityResourceKind::Agent,
            AuthorityVerb::Invoke | AuthorityVerb::Delegate,
        ) | (
            AuthorityOperationNamespace::Workload,
            AuthorityResourceKind::Workload,
            AuthorityVerb::Admit | AuthorityVerb::Invoke,
        ) | (
            AuthorityOperationNamespace::Artifact,
            AuthorityResourceKind::Artifact,
            AuthorityVerb::Write | AuthorityVerb::Publish,
        ) | (
            AuthorityOperationNamespace::State,
            AuthorityResourceKind::StatePartition,
            AuthorityVerb::Write,
        ) | (
            AuthorityOperationNamespace::Data,
            AuthorityResourceKind::Data,
            AuthorityVerb::Train | AuthorityVerb::Evaluate | AuthorityVerb::Publish,
        ) | (
            AuthorityOperationNamespace::Network,
            AuthorityResourceKind::Network,
            AuthorityVerb::Egress,
        ) | (
            AuthorityOperationNamespace::Driver,
            AuthorityResourceKind::DriverOperation,
            AuthorityVerb::Invoke,
        ) | (
            AuthorityOperationNamespace::Gateway,
            AuthorityResourceKind::Action | AuthorityResourceKind::Adapter,
            AuthorityVerb::Invoke | AuthorityVerb::Use,
        ) | (
            AuthorityOperationNamespace::Compatibility,
            AuthorityResourceKind::Permission,
            AuthorityVerb::Use,
        )
    )
}

fn is_scope_mismatch_reason(reason: &str) -> bool {
    reason.ends_with("_not_granted")
        || reason.ends_with("_missing_from_request")
        || reason.contains("_exceeds_grant")
        || reason.starts_with("time.")
        || reason.starts_with("budget.")
        || reason == "data_purpose_missing_for_operation"
}

fn decision_with_status(
    request: CapabilityRequest,
    now: OffsetDateTime,
    status: AuthorityDecisionStatus,
    reasons: Vec<String>,
) -> AuthorityDecision {
    AuthorityDecision {
        schema_version: AUTHORITY_DECISION_SCHEMA_VERSION.to_string(),
        decision_id: AuthorityDecisionId::new(),
        request,
        status,
        reasons,
        matched_grant_ids: Vec::new(),
        obligations: Vec::new(),
        decided_at: now,
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OfflineAuthorityDenial {
    UnsupportedOfflineOperation,
    HighRiskDenied,
    HighRiskNeedsIntervention,
    OfflineTtlExpired,
}

impl OfflineAuthorityDenial {
    fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedOfflineOperation => REASON_AUTHORITY_OFFLINE_UNSUPPORTED_OPERATION,
            Self::HighRiskDenied => REASON_AUTHORITY_OFFLINE_HIGH_RISK_DENIED,
            Self::HighRiskNeedsIntervention => {
                REASON_AUTHORITY_OFFLINE_HIGH_RISK_NEEDS_INTERVENTION
            }
            Self::OfflineTtlExpired => REASON_AUTHORITY_OFFLINE_TTL_EXPIRED,
        }
    }
}

/// Invalid offline authority policy configuration.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthorityOfflinePolicyError {
    /// A duration must be positive.
    #[error("invalid offline authority duration: {field}")]
    InvalidDuration { field: &'static str },
}

impl AuthorityOfflinePolicyError {
    /// Stable reason code for tests and caller diagnostics.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidDuration { .. } => "authority_offline_policy_invalid_duration",
        }
    }
}

/// Invalid cache entry construction.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthorityGrantCacheError {
    /// Cache expiry must be after cache installation time.
    #[error("authority cache window is invalid")]
    InvalidCacheWindow,
    /// A cache entry cannot be installed after the grant has expired.
    #[error("authority cache entry was installed after grant expiry")]
    CachedAfterGrantExpiry,
    /// Cache expiry cannot outlive the wrapped grant expiry.
    #[error("authority cache expiry outlives grant expiry")]
    CacheOutlivesGrant,
}

impl AuthorityGrantCacheError {
    /// Stable reason code for tests and caller diagnostics.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidCacheWindow => "authority_cache_window_invalid",
            Self::CachedAfterGrantExpiry => "authority_cache_after_grant_expiry",
            Self::CacheOutlivesGrant => "authority_cache_outlives_grant",
        }
    }
}

/// Invalid revocation snapshot construction.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthorityRevocationSnapshotError {
    /// Snapshot expiry must be after refresh time.
    #[error("revocation snapshot window is invalid")]
    InvalidWindow,
    /// Snapshot max age must be positive and representable.
    #[error("revocation snapshot max age is invalid")]
    InvalidMaxAge,
    /// A record has an unsupported schema.
    #[error("invalid revocation record schema: expected {expected}, found {actual}")]
    InvalidRecordSchema {
        /// Expected schema value.
        expected: &'static str,
        /// Actual schema value.
        actual: String,
    },
    /// A record carries an invalid identity.
    #[error("invalid revocation record identity field {field}")]
    InvalidRecordIdentity { field: &'static str },
    /// A snapshot contains multiple records for one grant.
    #[error("duplicate revocation record for grant {grant_id}")]
    DuplicateGrantRecord { grant_id: CapabilityGrantId },
}

impl AuthorityRevocationSnapshotError {
    /// Stable reason code for tests and caller diagnostics.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidWindow => "authority_revocation_snapshot_window_invalid",
            Self::InvalidMaxAge => "authority_revocation_snapshot_max_age_invalid",
            Self::InvalidRecordSchema { .. } => "authority_revocation_record_schema_invalid",
            Self::InvalidRecordIdentity { field } => match *field {
                "revocation_id" => "authority_revocation_record_id_invalid",
                "grant_id" => "authority_revocation_record_grant_id_invalid",
                _ => "authority_revocation_record_identity_invalid",
            },
            Self::DuplicateGrantRecord { .. } => "authority_revocation_record_duplicate_grant",
        }
    }
}

/// Revocation check denial for an already validated grant.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthorityRevocationCheckError {
    /// The snapshot claims to be refreshed after the evaluation timestamp.
    #[error("authority revocation snapshot is future-dated")]
    SnapshotFutureDated,
    /// The snapshot is too old for authority evaluation.
    #[error("authority revocation snapshot is stale")]
    SnapshotStale,
    /// A grant is revoked in its payload or the current snapshot.
    #[error("authority grant has been revoked: {grant_id}")]
    GrantRevoked { grant_id: CapabilityGrantId },
    /// Snapshot record and grant reference disagree about revocation source.
    #[error("authority revocation reference mismatch: {grant_id}")]
    RevocationRefMismatch { grant_id: CapabilityGrantId },
}

impl AuthorityRevocationCheckError {
    /// Stable reason code for authority decisions and tests.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::SnapshotFutureDated => REASON_AUTHORITY_REVOCATION_SNAPSHOT_FUTURE_DATED,
            Self::SnapshotStale => REASON_AUTHORITY_REVOCATION_SNAPSHOT_STALE,
            Self::GrantRevoked { .. } => REASON_AUTHORITY_GRANT_REVOKED,
            Self::RevocationRefMismatch { .. } => REASON_AUTHORITY_REVOCATION_REF_MISMATCH,
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/revocation_tests.rs"]
mod tests;
