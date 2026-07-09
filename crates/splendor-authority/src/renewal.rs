//! Bounded AUTH-005b local authority grant renewal preflight.
//!
//! This module renews only already validated, locally cached authority. It never
//! accepts a raw `CapabilityGrant`, does not implement a durable nonce store or
//! production lease service, and performs no gateway, daemon, node, fleet, or
//! external revocation side effects. The caller must supply a trusted local
//! renewal context containing the expected nonce and current grant digest.

use crate::{CachedAuthorityGrant, RevocationSnapshot, ValidatedCapabilityGrant};
use splendor_types::CapabilityGrantValidationKind;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Stable denial reason for missing caller-supplied renewal nonce.
pub const REASON_AUTHORITY_RENEWAL_NONCE_MISSING: &str = "authority_renewal_nonce_missing";
/// Stable denial reason for a nonce that does not match trusted local context.
pub const REASON_AUTHORITY_RENEWAL_NONCE_MISMATCH: &str = "authority_renewal_nonce_mismatch";
/// Stable denial reason for missing current grant digest/revision evidence.
pub const REASON_AUTHORITY_RENEWAL_CURRENT_REVISION_MISSING: &str =
    "authority_renewal_current_revision_missing";
/// Stable denial reason for stale current grant digest/revision evidence.
pub const REASON_AUTHORITY_RENEWAL_CURRENT_REVISION_MISMATCH: &str =
    "authority_renewal_current_revision_mismatch";
/// Stable denial reason when no local renewal policy is present.
pub const REASON_AUTHORITY_RENEWAL_POLICY_MISSING: &str = "authority_renewal_policy_missing";
/// Stable denial reason when local policy marks the grant as non-renewable.
pub const REASON_AUTHORITY_RENEWAL_NON_RENEWABLE: &str = "authority_renewal_non_renewable";
/// Stable denial reason when the cached grant is not yet valid at renewal time.
pub const REASON_AUTHORITY_RENEWAL_GRANT_FUTURE_DATED: &str =
    "authority_renewal_grant_future_dated";
/// Stable denial reason when the proposed renewed grant is already expired.
pub const REASON_AUTHORITY_RENEWAL_RENEWED_GRANT_EXPIRED: &str =
    "authority_renewal_renewed_grant_expired";
/// Stable denial reason when the renewal grant ID differs from the current grant.
pub const REASON_AUTHORITY_RENEWAL_GRANT_ID_CHANGED: &str = "authority_renewal_grant_id_changed";
/// Stable denial reason when the renewed grant changes issuer.
pub const REASON_AUTHORITY_RENEWAL_ISSUER_CHANGED: &str = "authority_renewal_issuer_changed";
/// Stable denial reason when the renewed grant changes subject.
pub const REASON_AUTHORITY_RENEWAL_SUBJECT_CHANGED: &str = "authority_renewal_subject_changed";
/// Stable denial reason when the renewed grant changes parent grant lineage.
pub const REASON_AUTHORITY_RENEWAL_PARENT_GRANTS_CHANGED: &str =
    "authority_renewal_parent_grants_changed";
/// Stable denial reason when the renewed grant changes operations.
pub const REASON_AUTHORITY_RENEWAL_OPERATIONS_CHANGED: &str =
    "authority_renewal_operations_changed";
/// Stable denial reason when the renewed grant changes non-audience scope.
pub const REASON_AUTHORITY_RENEWAL_SCOPE_CHANGED: &str = "authority_renewal_scope_changed";
/// Stable denial reason when the renewed grant changes audience bindings.
pub const REASON_AUTHORITY_RENEWAL_AUDIENCE_CHANGED: &str = "authority_renewal_audience_changed";
/// Stable denial reason when the renewed grant changes revocation source.
pub const REASON_AUTHORITY_RENEWAL_REVOCATION_REF_CHANGED: &str =
    "authority_renewal_revocation_ref_changed";
/// Stable denial reason when the renewed grant changes revocation state.
pub const REASON_AUTHORITY_RENEWAL_REVOCATION_STATE_CHANGED: &str =
    "authority_renewal_revocation_state_changed";
/// Stable denial reason when the renewed grant changes obligations.
pub const REASON_AUTHORITY_RENEWAL_OBLIGATIONS_CHANGED: &str =
    "authority_renewal_obligations_changed";
/// Stable denial reason when the renewed grant changes validation mode.
pub const REASON_AUTHORITY_RENEWAL_VALIDATION_KIND_CHANGED: &str =
    "authority_renewal_validation_kind_changed";
/// Stable denial reason when the renewed grant changes delegation depth.
pub const REASON_AUTHORITY_RENEWAL_DELEGATION_DEPTH_CHANGED: &str =
    "authority_renewal_delegation_depth_changed";
/// Stable denial reason when renewal changes the grant start time.
pub const REASON_AUTHORITY_RENEWAL_NOT_BEFORE_CHANGED: &str =
    "authority_renewal_not_before_changed";
/// Stable denial reason when the renewed grant exceeds local renewal lifetime.
pub const REASON_AUTHORITY_RENEWAL_LIFETIME_EXCEEDED: &str = "authority_renewal_lifetime_exceeded";
/// Stable denial reason when renewed cached authority exceeds offline lifetime.
pub const REASON_AUTHORITY_RENEWAL_OFFLINE_LIFETIME_EXCEEDED: &str =
    "authority_renewal_offline_lifetime_exceeded";
/// Stable denial reason when renewed cache expiry is not after renewal time.
pub const REASON_AUTHORITY_RENEWAL_CACHE_WINDOW_INVALID: &str =
    "authority_renewal_cache_window_invalid";
/// Stable denial reason when renewed cache expiry would outlive grant expiry.
pub const REASON_AUTHORITY_RENEWAL_CACHE_OUTLIVES_GRANT: &str =
    "authority_renewal_cache_outlives_grant";

/// Trusted local context for one renewal preflight.
///
/// This context is supplied by the authority-owning caller. It is intentionally
/// local and behavior-only: it is not a durable anti-replay store and does not
/// claim production nonce persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedAuthorityRenewalContext {
    expected_nonce: String,
    current_grant_digest: String,
    now: OffsetDateTime,
}

impl TrustedAuthorityRenewalContext {
    /// Creates trusted local renewal context. Empty nonce or digest material fails
    /// closed before renewal can be attempted.
    pub fn new(
        expected_nonce: impl Into<String>,
        current_grant_digest: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<Self, AuthorityGrantRenewalContextError> {
        let expected_nonce = expected_nonce.into();
        if expected_nonce.trim().is_empty() {
            return Err(AuthorityGrantRenewalContextError::MissingNonce);
        }
        let current_grant_digest = current_grant_digest.into();
        if current_grant_digest.trim().is_empty() {
            return Err(AuthorityGrantRenewalContextError::MissingCurrentRevision);
        }
        Ok(Self {
            expected_nonce,
            current_grant_digest,
            now,
        })
    }

    /// Expected nonce for this local preflight challenge.
    pub fn expected_nonce(&self) -> &str {
        &self.expected_nonce
    }

    /// Current grant digest/revision expected by this preflight.
    pub fn current_grant_digest(&self) -> &str {
        &self.current_grant_digest
    }

    /// Decision time for this renewal preflight.
    pub fn now(&self) -> OffsetDateTime {
        self.now
    }
}

/// Local policy governing whether and how a cached grant may renew.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityGrantRenewalPolicy {
    renewable: bool,
    max_cache_staleness: Duration,
    max_renewal_lifetime: Duration,
    max_offline_lifetime: Duration,
}

impl AuthorityGrantRenewalPolicy {
    /// Builds a renewable local policy with strict lifetime caps.
    pub fn renewable(
        max_cache_staleness: Duration,
        max_renewal_lifetime: Duration,
        max_offline_lifetime: Duration,
    ) -> Result<Self, AuthorityGrantRenewalPolicyError> {
        validate_positive_duration("max_cache_staleness", max_cache_staleness)?;
        validate_positive_duration("max_renewal_lifetime", max_renewal_lifetime)?;
        validate_positive_duration("max_offline_lifetime", max_offline_lifetime)?;
        Ok(Self {
            renewable: true,
            max_cache_staleness,
            max_renewal_lifetime,
            max_offline_lifetime,
        })
    }

    /// Builds an explicit non-renewable local policy.
    pub fn non_renewable() -> Self {
        Self {
            renewable: false,
            max_cache_staleness: Duration::ZERO,
            max_renewal_lifetime: Duration::ZERO,
            max_offline_lifetime: Duration::ZERO,
        }
    }

    /// Returns whether this policy permits renewal attempts.
    pub fn is_renewable(&self) -> bool {
        self.renewable
    }

    /// Maximum age of the current cached grant before renewal must fail closed.
    pub fn max_cache_staleness(&self) -> Duration {
        self.max_cache_staleness
    }

    /// Maximum lifetime of the renewed grant from the preflight decision time.
    pub fn max_renewal_lifetime(&self) -> Duration {
        self.max_renewal_lifetime
    }

    /// Maximum renewed cache lifetime from the preflight decision time.
    pub fn max_offline_lifetime(&self) -> Duration {
        self.max_offline_lifetime
    }
}

/// Request for renewing one already cached validated authority grant.
pub struct AuthorityGrantRenewalRequest<'a> {
    /// Current cached authority. Raw grants are intentionally not accepted.
    pub cached_grant: &'a CachedAuthorityGrant,
    /// Current revocation snapshot from the trusted local authority path.
    pub revocation_snapshot: Option<&'a RevocationSnapshot>,
    /// Optional policy; absence denies fail-closed.
    pub policy: Option<&'a AuthorityGrantRenewalPolicy>,
    /// Trusted nonce/current-revision context.
    pub trusted_context: &'a TrustedAuthorityRenewalContext,
    /// Non-empty nonce supplied for this renewal attempt.
    pub nonce: &'a str,
    /// Proposed renewed grant. It must already be locally validated.
    pub renewed_grant: &'a ValidatedCapabilityGrant,
    /// Requested local cache expiry for the renewed grant.
    pub renewed_cache_expires_at: OffsetDateTime,
}

/// Renewal preflight status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityGrantRenewalStatus {
    /// Renewal preflight succeeded and returned a renewed cached validated grant.
    Renewed,
    /// Renewal preflight denied fail-closed.
    Denied,
}

/// Structured deterministic renewal result.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorityGrantRenewalResult {
    status: AuthorityGrantRenewalStatus,
    reasons: Vec<String>,
    renewed_cached_grant: Option<CachedAuthorityGrant>,
    checked_at: OffsetDateTime,
}

impl AuthorityGrantRenewalResult {
    /// Returns renewal status.
    pub fn status(&self) -> AuthorityGrantRenewalStatus {
        self.status
    }

    /// Returns stable reason codes. Successful renewal returns `authority_renewal_allowed`.
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }

    /// Returns the renewed cached grant when status is `Renewed`.
    pub fn renewed_cached_grant(&self) -> Option<&CachedAuthorityGrant> {
        self.renewed_cached_grant.as_ref()
    }

    /// Consumes the result and returns the renewed cached grant when present.
    pub fn into_renewed_cached_grant(self) -> Option<CachedAuthorityGrant> {
        self.renewed_cached_grant
    }

    /// Returns the decision time used for this renewal preflight.
    pub fn checked_at(&self) -> OffsetDateTime {
        self.checked_at
    }
}

/// Performs a pure local renewal preflight over already validated cached authority.
pub fn renew_cached_authority_grant(
    request: AuthorityGrantRenewalRequest<'_>,
) -> AuthorityGrantRenewalResult {
    let now = request.trusted_context.now();
    let Some(policy) = request.policy else {
        return denied(now, vec![REASON_AUTHORITY_RENEWAL_POLICY_MISSING]);
    };
    if !policy.is_renewable() {
        return denied(now, vec![REASON_AUTHORITY_RENEWAL_NON_RENEWABLE]);
    }

    let mut reasons = Vec::new();
    verify_nonce_and_current_revision(&request, &mut reasons);
    verify_cached_grant_liveness(request.cached_grant, policy, now, &mut reasons);
    verify_revocation_snapshot(
        request.revocation_snapshot,
        request.cached_grant.grant(),
        now,
        &mut reasons,
    );
    verify_renewed_grant_shape(&request, policy, now, &mut reasons);

    if !reasons.is_empty() {
        return AuthorityGrantRenewalResult {
            status: AuthorityGrantRenewalStatus::Denied,
            reasons,
            renewed_cached_grant: None,
            checked_at: now,
        };
    }

    match CachedAuthorityGrant::try_new(
        request.renewed_grant.clone(),
        now,
        request.renewed_cache_expires_at,
    ) {
        Ok(renewed_cached_grant) => AuthorityGrantRenewalResult {
            status: AuthorityGrantRenewalStatus::Renewed,
            reasons: vec!["authority_renewal_allowed".to_string()],
            renewed_cached_grant: Some(renewed_cached_grant),
            checked_at: now,
        },
        Err(error) => AuthorityGrantRenewalResult {
            status: AuthorityGrantRenewalStatus::Denied,
            reasons: vec![cache_error_reason(error).to_string()],
            renewed_cached_grant: None,
            checked_at: now,
        },
    }
}

fn verify_nonce_and_current_revision(
    request: &AuthorityGrantRenewalRequest<'_>,
    reasons: &mut Vec<String>,
) {
    if request.nonce.trim().is_empty() {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_NONCE_MISSING);
    } else if request.nonce != request.trusted_context.expected_nonce() {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_NONCE_MISMATCH);
    }

    let Some(current_digest) = grant_validation_digest(request.cached_grant.grant()) else {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_CURRENT_REVISION_MISSING);
        return;
    };
    if current_digest != request.trusted_context.current_grant_digest() {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_CURRENT_REVISION_MISMATCH);
    }
}

fn verify_cached_grant_liveness(
    cached: &CachedAuthorityGrant,
    policy: &AuthorityGrantRenewalPolicy,
    now: OffsetDateTime,
    reasons: &mut Vec<String>,
) {
    if cached.cached_at() > now {
        push_unique(reasons, crate::REASON_AUTHORITY_CACHE_FUTURE_DATED);
    }
    if now < cached.grant().grant().not_before {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_GRANT_FUTURE_DATED);
    }
    if now >= cached.expires_at() || now >= cached.grant().grant().expires_at {
        push_unique(reasons, crate::REASON_AUTHORITY_CACHE_EXPIRED);
    }
    if cache_age_exceeded(cached.cached_at(), policy.max_cache_staleness(), now) {
        push_unique(reasons, crate::REASON_AUTHORITY_CACHE_STALE);
    }
}

fn verify_revocation_snapshot(
    snapshot: Option<&RevocationSnapshot>,
    grant: &ValidatedCapabilityGrant,
    now: OffsetDateTime,
    reasons: &mut Vec<String>,
) {
    let Some(snapshot) = snapshot else {
        push_unique(reasons, crate::REASON_AUTHORITY_REVOCATION_SNAPSHOT_MISSING);
        return;
    };
    if let Err(error) = snapshot.verify_grant_active(grant, now) {
        push_unique(reasons, error.reason_code());
    }
}

fn verify_renewed_grant_shape(
    request: &AuthorityGrantRenewalRequest<'_>,
    policy: &AuthorityGrantRenewalPolicy,
    now: OffsetDateTime,
    reasons: &mut Vec<String>,
) {
    let current = request.cached_grant.grant().grant();
    let renewed = request.renewed_grant.grant();

    if renewed.grant_id != current.grant_id {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_GRANT_ID_CHANGED);
    }
    if renewed.issuer != current.issuer {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_ISSUER_CHANGED);
    }
    if renewed.subject != current.subject {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_SUBJECT_CHANGED);
    }
    if renewed.parent_grant_ids != current.parent_grant_ids {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_PARENT_GRANTS_CHANGED);
    }
    if renewed.operations != current.operations {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_OPERATIONS_CHANGED);
    }
    if renewed.scope.audiences != current.scope.audiences {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_AUDIENCE_CHANGED);
    }
    if scope_without_audience_changed(&current.scope, &renewed.scope) {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_SCOPE_CHANGED);
    }
    if renewed.revocation_ref != current.revocation_ref {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_REVOCATION_REF_CHANGED);
    }
    if renewed.revocation != current.revocation {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_REVOCATION_STATE_CHANGED);
    }
    if renewed.obligations != current.obligations {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_OBLIGATIONS_CHANGED);
    }
    if validation_kind(request.cached_grant.grant()) != validation_kind(request.renewed_grant) {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_VALIDATION_KIND_CHANGED);
    }
    if renewed.max_delegation_depth != current.max_delegation_depth {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_DELEGATION_DEPTH_CHANGED);
    }
    if renewed.not_before != current.not_before {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_NOT_BEFORE_CHANGED);
    }
    if renewed.expires_at <= now {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_RENEWED_GRANT_EXPIRED);
    }
    if exceeds_deadline(now, policy.max_renewal_lifetime(), renewed.expires_at) {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_LIFETIME_EXCEEDED);
    }
    if request.renewed_cache_expires_at <= now {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_CACHE_WINDOW_INVALID);
    }
    if exceeds_deadline(
        now,
        policy.max_offline_lifetime(),
        request.renewed_cache_expires_at,
    ) {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_OFFLINE_LIFETIME_EXCEEDED);
    }
    if request.renewed_cache_expires_at > renewed.expires_at {
        push_unique(reasons, REASON_AUTHORITY_RENEWAL_CACHE_OUTLIVES_GRANT);
    }
}

fn grant_validation_digest(grant: &ValidatedCapabilityGrant) -> Option<&str> {
    grant
        .grant()
        .validation
        .as_ref()
        .map(|validation| validation.digest.as_str())
}

fn validation_kind(grant: &ValidatedCapabilityGrant) -> Option<CapabilityGrantValidationKind> {
    grant
        .grant()
        .validation
        .as_ref()
        .map(|validation| validation.validation_kind)
}

fn scope_without_audience_changed(
    current: &splendor_types::CapabilityScope,
    renewed: &splendor_types::CapabilityScope,
) -> bool {
    let mut current = current.clone();
    let mut renewed = renewed.clone();
    current.audiences = None;
    renewed.audiences = None;
    current != renewed
}

fn cache_age_exceeded(cached_at: OffsetDateTime, ttl: Duration, now: OffsetDateTime) -> bool {
    match cached_at.checked_add(ttl) {
        Some(expires_at) => now >= expires_at,
        None => true,
    }
}

fn exceeds_deadline(now: OffsetDateTime, lifetime: Duration, candidate: OffsetDateTime) -> bool {
    match now.checked_add(lifetime) {
        Some(deadline) => candidate > deadline,
        None => true,
    }
}

fn cache_error_reason(error: crate::AuthorityGrantCacheError) -> &'static str {
    match error {
        crate::AuthorityGrantCacheError::InvalidCacheWindow => {
            REASON_AUTHORITY_RENEWAL_CACHE_WINDOW_INVALID
        }
        crate::AuthorityGrantCacheError::CachedAfterGrantExpiry
        | crate::AuthorityGrantCacheError::CacheOutlivesGrant => {
            REASON_AUTHORITY_RENEWAL_CACHE_OUTLIVES_GRANT
        }
    }
}

fn validate_positive_duration(
    field: &'static str,
    duration: Duration,
) -> Result<(), AuthorityGrantRenewalPolicyError> {
    if duration <= Duration::ZERO {
        return Err(AuthorityGrantRenewalPolicyError::InvalidDuration { field });
    }
    Ok(())
}

fn denied(now: OffsetDateTime, reasons: Vec<&'static str>) -> AuthorityGrantRenewalResult {
    AuthorityGrantRenewalResult {
        status: AuthorityGrantRenewalStatus::Denied,
        reasons: reasons.into_iter().map(str::to_string).collect(),
        renewed_cached_grant: None,
        checked_at: now,
    }
}

fn push_unique(reasons: &mut Vec<String>, reason: &'static str) {
    if !reasons.iter().any(|existing| existing == reason) {
        reasons.push(reason.to_string());
    }
}

/// Invalid trusted renewal context construction.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthorityGrantRenewalContextError {
    /// Expected nonce is empty.
    #[error("authority renewal nonce is missing")]
    MissingNonce,
    /// Current grant digest/revision is empty.
    #[error("authority renewal current revision is missing")]
    MissingCurrentRevision,
}

impl AuthorityGrantRenewalContextError {
    /// Stable reason code for tests and caller diagnostics.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::MissingNonce => REASON_AUTHORITY_RENEWAL_NONCE_MISSING,
            Self::MissingCurrentRevision => REASON_AUTHORITY_RENEWAL_CURRENT_REVISION_MISSING,
        }
    }
}

/// Invalid renewal policy construction.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthorityGrantRenewalPolicyError {
    /// A renewal duration must be positive.
    #[error("invalid authority renewal duration: {field}")]
    InvalidDuration { field: &'static str },
}

impl AuthorityGrantRenewalPolicyError {
    /// Stable reason code for tests and caller diagnostics.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidDuration { .. } => "authority_renewal_policy_invalid_duration",
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/renewal_tests.rs"]
mod tests;
