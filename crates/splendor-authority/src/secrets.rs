//! Process-local C03 Secret Broker lifecycle and provider port.
//!
//! This module is the sole process-local mutation owner for the bounded lease
//! slice. It issues exact-bound leases, atomically claims finite uses, renews
//! without resetting lineage limits, and closes new-use admission on revocation.
//! It does not deliver material, invoke provider methods, replace the Gateway,
//! or claim restart durability.

use crate::capability::validate_local_profile_grant;
use crate::{
    evaluate_cached_capability_request, AuthorityEvaluationError, AuthorityGrantCache,
    CompatibilityGrantContext, OfflineAuthorityPolicy, RevocationSnapshot,
    ValidatedCapabilityGrant,
};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use splendor_types::{
    AuthorityDecisionStatus, AuthorityOperation, AuthorityOperationNamespace,
    AuthorityResourceKind, AuthorityTimeScope, AuthorityVerb, CanonicalTimestampV1,
    CapabilityGrant, CapabilityGrantValidation, CapabilityGrantValidationKind, CapabilityRequest,
    CapabilityScope, DriverOperationRef, EffectCertainty, RevocationStatus, SecretAccessDenialCode,
    SecretAccessEventId, SecretAccessEvidence, SecretAccessEvidenceKind,
    SecretAccessEvidenceOutcome, SecretDeliveryHandleId, SecretDeliveryMethod, SecretLeaseId,
    SecretLeaseRequest, SecretLeaseSnapshot, SecretLeaseStatus, SecretLeaseUseBinding,
    SecretProviderAuditId, SecretProviderId, SecretProviderVersionRef, SecretRefId, SecretRefV2,
    SecretUseAttemptId, SecretUseClaimId, TenantId, WorkloadId, AUTHORITY_OPERATION_SCHEMA_VERSION,
    CAPABILITY_GRANT_SCHEMA_VERSION, CAPABILITY_REQUEST_SCHEMA_VERSION,
};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_SECRET_MATERIAL_BYTES: usize = 65_536;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub const SECRET_PROVIDER_AUDIT_EVIDENCE_SCHEMA_LOCAL_V1: &str =
    "splendor.secret.provider_audit_evidence.local.v1";
pub const SECRET_PROVIDER_HEALTH_EVIDENCE_SCHEMA_LOCAL_V1: &str =
    "splendor.secret.provider_health_evidence.local.v1";

/// Builds the exact typed driver-invocation operation used for broker authority.
pub fn secret_driver_invoke_operation(reference: &DriverOperationRef) -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Driver,
        resource_kind: AuthorityResourceKind::DriverOperation,
        verb: AuthorityVerb::Invoke,
        name: Some(format!("{}.{}", reference.driver, reference.operation)),
        resource_schema_version: Some(reference.schema_version.clone()),
    }
}

/// Builds one explicitly local validated grant for an exact Secret Broker
/// driver scope. This is a compatibility profile, not signature verification or
/// a production issuer.
#[allow(clippy::too_many_arguments)]
pub fn grant_from_local_secret_broker_scope(
    context: CompatibilityGrantContext,
    tenant_id: TenantId,
    workload_id: WorkloadId,
    driver_operation: DriverOperationRef,
    not_before: OffsetDateTime,
    expires_at: OffsetDateTime,
    revocation: RevocationStatus,
    revocation_ref: Option<String>,
) -> Result<ValidatedCapabilityGrant, AuthorityEvaluationError> {
    let operation = secret_driver_invoke_operation(&driver_operation);
    let grant = CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: context.grant_id,
        issuer: context.issuer,
        subject: context.subject,
        parent_grant_ids: context.parent_grant_ids,
        operations: vec![operation],
        scope: CapabilityScope {
            tenant_ids: Some(vec![tenant_id]),
            workload_ids: Some(vec![workload_id]),
            driver_operations: Some(vec![driver_operation]),
            audiences: Some(vec![context.audience]),
            time: AuthorityTimeScope {
                not_before: Some(not_before),
                expires_at: Some(expires_at),
            },
            ..CapabilityScope::default()
        },
        not_before,
        expires_at,
        revocation_ref,
        revocation,
        obligations: Vec::new(),
        max_delegation_depth: context.max_delegation_depth,
        validation: Some(CapabilityGrantValidation {
            validation_kind: CapabilityGrantValidationKind::LocallyValidated,
            algorithm: "local-secret-broker-profile-v1".to_string(),
            key_id: None,
            digest: context.validation_digest,
            signature: None,
        }),
        metadata: Default::default(),
    };
    validate_local_profile_grant(grant)
}

/// Secret material returned only by a registered provider implementation.
///
/// The type is deliberately non-`Clone`, non-serializable, redacted under
/// `Debug`, and backed by `Zeroizing<Vec<u8>>`. The borrowed callback can still
/// copy bytes, so zeroization reduces exposure rather than claiming perfect
/// erasure.
///
/// ```compile_fail
/// use splendor_authority::SecretMaterial;
/// fn require_clone<T: Clone>() {}
/// require_clone::<SecretMaterial>();
/// ```
///
/// ```compile_fail
/// use splendor_authority::SecretMaterial;
/// let value = SecretMaterial::try_new(vec![1]).unwrap();
/// let _ = serde_json::to_vec(&value).unwrap();
/// ```
pub struct SecretMaterial {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretMaterial {
    /// Constructs provider-owned material at the adapter boundary.
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, SecretProviderError> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_MATERIAL_BYTES {
            return Err(SecretProviderError::new(
                SecretProviderErrorCode::IntegrityFailure,
            ));
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// Exposes a borrowed view only for the duration of one callback.
    pub fn expose_borrowed<R>(&self, consume: impl FnOnce(&[u8]) -> R) -> R {
        consume(self.bytes.as_slice())
    }

    /// Returns the bounded byte length without exposing material.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the material is empty. Valid material is never empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial(<redacted>)")
    }
}

/// Semantic provider operation at the outbound port.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretProviderOperation {
    Fetch,
    Renew,
    Revoke,
    Audit,
    ActiveProbe,
}

/// Closed provider outcomes safe for restricted evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretProviderOutcome {
    Succeeded,
    Denied,
    Unavailable,
    Failed,
    EffectUncertain,
}

/// Safe provider audit evidence. It contains no endpoint, request, response,
/// provider error text, material digest, locator, or credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretProviderAuditEvidence {
    provider_audit_id: SecretProviderAuditId,
    secret_provider_id: SecretProviderId,
    tenant_id: TenantId,
    secret_ref_id: SecretRefId,
    secret_ref_revision: u64,
    provider_version_ref: SecretProviderVersionRef,
    operation: SecretProviderOperation,
    outcome: SecretProviderOutcome,
    effect_certainty: EffectCertainty,
    observed_at: CanonicalTimestampV1,
}

impl SecretProviderAuditEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        provider_audit_id: SecretProviderAuditId,
        secret_provider_id: SecretProviderId,
        tenant_id: TenantId,
        secret_ref_id: SecretRefId,
        secret_ref_revision: u64,
        provider_version_ref: SecretProviderVersionRef,
        operation: SecretProviderOperation,
        outcome: SecretProviderOutcome,
        effect_certainty: EffectCertainty,
        observed_at: CanonicalTimestampV1,
    ) -> Result<Self, SecretProviderError> {
        if tenant_id.is_nil()
            || !(1..=MAX_SAFE_INTEGER).contains(&secret_ref_revision)
            || (outcome == SecretProviderOutcome::Succeeded
                && effect_certainty != EffectCertainty::Known)
            || (outcome == SecretProviderOutcome::EffectUncertain
                && effect_certainty != EffectCertainty::Uncertain)
        {
            return Err(SecretProviderError::new(
                SecretProviderErrorCode::IntegrityFailure,
            ));
        }
        Ok(Self {
            provider_audit_id,
            secret_provider_id,
            tenant_id,
            secret_ref_id,
            secret_ref_revision,
            provider_version_ref,
            operation,
            outcome,
            effect_certainty,
            observed_at,
        })
    }

    pub fn provider_audit_id(&self) -> &SecretProviderAuditId {
        &self.provider_audit_id
    }

    pub const fn schema_version(&self) -> &'static str {
        SECRET_PROVIDER_AUDIT_EVIDENCE_SCHEMA_LOCAL_V1
    }

    pub fn outcome(&self) -> SecretProviderOutcome {
        self.outcome
    }

    pub fn secret_provider_id(&self) -> &SecretProviderId {
        &self.secret_provider_id
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn secret_ref_id(&self) -> &SecretRefId {
        &self.secret_ref_id
    }

    pub fn secret_ref_revision(&self) -> u64 {
        self.secret_ref_revision
    }

    pub fn provider_version_ref(&self) -> &SecretProviderVersionRef {
        &self.provider_version_ref
    }

    pub fn operation(&self) -> SecretProviderOperation {
        self.operation
    }

    pub fn effect_certainty(&self) -> EffectCertainty {
        self.effect_certainty
    }

    pub fn observed_at(&self) -> &CanonicalTimestampV1 {
        &self.observed_at
    }
}

impl Serialize for SecretProviderAuditEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretProviderAuditEvidence", 11)?;
        state.serialize_field("effect_certainty", &self.effect_certainty)?;
        state.serialize_field("observed_at", &self.observed_at)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("outcome", &self.outcome)?;
        state.serialize_field("provider_audit_id", &self.provider_audit_id)?;
        state.serialize_field("provider_version_ref", &self.provider_version_ref)?;
        state.serialize_field(
            "schema_version",
            SECRET_PROVIDER_AUDIT_EVIDENCE_SCHEMA_LOCAL_V1,
        )?;
        state.serialize_field("secret_provider_id", &self.secret_provider_id)?;
        state.serialize_field("secret_ref_id", &self.secret_ref_id)?;
        state.serialize_field("secret_ref_revision", &self.secret_ref_revision)?;
        state.serialize_field("tenant_id", &self.tenant_id)?;
        state.end()
    }
}

/// Private-construction request for one provider fetch.
///
/// Public callers can inspect a request received through the provider trait, but
/// no public constructor exists. A later Gateway-owned session will construct
/// this only from its live permit and an opaque delivery claim.
pub struct SecretProviderFetchRequest {
    provider_audit_id: SecretProviderAuditId,
    secret_provider_id: SecretProviderId,
    tenant_id: TenantId,
    secret_ref_id: SecretRefId,
    secret_ref_revision: u64,
    provider_version_ref: SecretProviderVersionRef,
    secret_lease_id: SecretLeaseId,
    delivery_handle_id: SecretDeliveryHandleId,
    secret_use_claim_id: SecretUseClaimId,
    secret_use_attempt_id: SecretUseAttemptId,
    requested_at: CanonicalTimestampV1,
}

impl SecretProviderFetchRequest {
    pub fn provider_audit_id(&self) -> &SecretProviderAuditId {
        &self.provider_audit_id
    }
    pub fn secret_provider_id(&self) -> &SecretProviderId {
        &self.secret_provider_id
    }
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub fn secret_ref_id(&self) -> &SecretRefId {
        &self.secret_ref_id
    }
    pub fn secret_ref_revision(&self) -> u64 {
        self.secret_ref_revision
    }
    pub fn provider_version_ref(&self) -> &SecretProviderVersionRef {
        &self.provider_version_ref
    }
    pub fn secret_lease_id(&self) -> &SecretLeaseId {
        &self.secret_lease_id
    }
    pub fn delivery_handle_id(&self) -> &SecretDeliveryHandleId {
        &self.delivery_handle_id
    }
    pub fn secret_use_claim_id(&self) -> &SecretUseClaimId {
        &self.secret_use_claim_id
    }
    pub fn secret_use_attempt_id(&self) -> &SecretUseAttemptId {
        &self.secret_use_attempt_id
    }
    pub fn requested_at(&self) -> &CanonicalTimestampV1 {
        &self.requested_at
    }
}

impl fmt::Debug for SecretProviderFetchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretProviderFetchRequest(<redacted>)")
    }
}

/// Private-construction request for a non-material provider control operation.
pub struct SecretProviderControlRequest {
    provider_audit_id: SecretProviderAuditId,
    secret_provider_id: SecretProviderId,
    tenant_id: TenantId,
    secret_ref_id: SecretRefId,
    secret_ref_revision: u64,
    provider_version_ref: SecretProviderVersionRef,
    secret_lease_id: Option<SecretLeaseId>,
    requested_at: CanonicalTimestampV1,
}

impl SecretProviderControlRequest {
    pub fn provider_audit_id(&self) -> &SecretProviderAuditId {
        &self.provider_audit_id
    }
    pub fn secret_provider_id(&self) -> &SecretProviderId {
        &self.secret_provider_id
    }
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub fn secret_ref_id(&self) -> &SecretRefId {
        &self.secret_ref_id
    }
    pub fn secret_ref_revision(&self) -> u64 {
        self.secret_ref_revision
    }
    pub fn provider_version_ref(&self) -> &SecretProviderVersionRef {
        &self.provider_version_ref
    }
    pub fn secret_lease_id(&self) -> Option<&SecretLeaseId> {
        self.secret_lease_id.as_ref()
    }
    pub fn requested_at(&self) -> &CanonicalTimestampV1 {
        &self.requested_at
    }
}

impl fmt::Debug for SecretProviderControlRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretProviderControlRequest(<redacted>)")
    }
}

/// One non-cloneable provider fetch result. It is not serializable.
pub struct SecretProviderFetchResult {
    material: SecretMaterial,
    audit: SecretProviderAuditEvidence,
}

impl SecretProviderFetchResult {
    pub fn try_new(
        material: SecretMaterial,
        audit: SecretProviderAuditEvidence,
    ) -> Result<Self, SecretProviderError> {
        if audit.operation() != SecretProviderOperation::Fetch
            || audit.outcome() != SecretProviderOutcome::Succeeded
            || audit.effect_certainty() != EffectCertainty::Known
        {
            return Err(SecretProviderError::new(
                SecretProviderErrorCode::IntegrityFailure,
            ));
        }
        Ok(Self { material, audit })
    }

    pub fn into_parts(self) -> (SecretMaterial, SecretProviderAuditEvidence) {
        (self.material, self.audit)
    }
}

impl fmt::Debug for SecretProviderFetchResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretProviderFetchResult(<redacted>)")
    }
}

/// Safe passive health projection for one configured provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretProviderHealthEvidence {
    secret_provider_id: SecretProviderId,
    available: bool,
    observed_at: CanonicalTimestampV1,
}

impl SecretProviderHealthEvidence {
    pub const fn schema_version(&self) -> &'static str {
        SECRET_PROVIDER_HEALTH_EVIDENCE_SCHEMA_LOCAL_V1
    }

    pub fn new(
        secret_provider_id: SecretProviderId,
        available: bool,
        observed_at: CanonicalTimestampV1,
    ) -> Self {
        Self {
            secret_provider_id,
            available,
            observed_at,
        }
    }

    pub fn secret_provider_id(&self) -> &SecretProviderId {
        &self.secret_provider_id
    }

    pub fn available(&self) -> bool {
        self.available
    }

    pub fn observed_at(&self) -> &CanonicalTimestampV1 {
        &self.observed_at
    }
}

impl Serialize for SecretProviderHealthEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretProviderHealthEvidence", 4)?;
        state.serialize_field("available", &self.available)?;
        state.serialize_field("observed_at", &self.observed_at)?;
        state.serialize_field(
            "schema_version",
            SECRET_PROVIDER_HEALTH_EVIDENCE_SCHEMA_LOCAL_V1,
        )?;
        state.serialize_field("secret_provider_id", &self.secret_provider_id)?;
        state.end()
    }
}

/// Fixed redacted provider error categories.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecretProviderErrorCode {
    Unavailable,
    TimeoutBeforeSend,
    RateLimited,
    VersionNotAvailable,
    Revoked,
    IntegrityFailure,
    UnsupportedProviderVersion,
    UnsupportedOperation,
    EffectUncertain,
    InternalFailure,
}

impl SecretProviderErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::TimeoutBeforeSend => "timeout_before_send",
            Self::RateLimited => "rate_limited",
            Self::VersionNotAvailable => "version_not_available",
            Self::Revoked => "revoked",
            Self::IntegrityFailure => "integrity_failure",
            Self::UnsupportedProviderVersion => "unsupported_provider_version",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::EffectUncertain => "effect_uncertain",
            Self::InternalFailure => "internal_failure",
        }
    }
}

/// Provider failures never retain or display vendor text.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SecretProviderError {
    code: SecretProviderErrorCode,
}

impl SecretProviderError {
    pub const fn new(code: SecretProviderErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> SecretProviderErrorCode {
        self.code
    }
}

impl fmt::Display for SecretProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl fmt::Debug for SecretProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Error for SecretProviderError {}

/// Object-safe outbound provider port. No request type has a public constructor,
/// and the broker lifecycle below never calls these methods.
pub trait SecretProvider: Send + Sync {
    fn provider_id(&self) -> &SecretProviderId;
    fn fetch(
        &self,
        request: &SecretProviderFetchRequest,
    ) -> Result<SecretProviderFetchResult, SecretProviderError>;
    fn renew(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError>;
    fn revoke(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError>;
    fn audit(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError>;
    fn health(
        &self,
        request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderHealthEvidence, SecretProviderError>;
}

/// Trusted UTC source sampled only while broker state is locked.
pub trait SecretBrokerClock: Send + Sync {
    fn now_utc(&self) -> Option<OffsetDateTime>;
}

#[derive(Debug)]
pub struct SystemSecretBrokerClock;

impl SecretBrokerClock for SystemSecretBrokerClock {
    fn now_utc(&self) -> Option<OffsetDateTime> {
        let now = OffsetDateTime::now_utc();
        now.replace_nanosecond(now.microsecond().checked_mul(1_000)?)
            .ok()
    }
}

/// Identity classes requested from an injected broker-owned source.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecretBrokerIdKind {
    Lease,
    DeliveryHandle,
    HandleCapability,
    AccessEvent,
    UseClaim,
    UseAttempt,
    ClaimCapability,
}

/// Broker-owned ID source. `None` is treated as fail-closed unavailability.
pub trait SecretBrokerIdSource: Send + Sync {
    fn next_uuid(&self, kind: SecretBrokerIdKind) -> Option<Uuid>;
}

#[derive(Debug)]
pub struct SystemSecretBrokerIdSource;

impl SecretBrokerIdSource for SystemSecretBrokerIdSource {
    fn next_uuid(&self, _kind: SecretBrokerIdKind) -> Option<Uuid> {
        Some(Uuid::new_v4())
    }
}

/// Event sink failure has one fixed non-reflecting meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretBrokerEventSinkError {
    Unavailable,
}

impl fmt::Display for SecretBrokerEventSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret_broker_event_sink_unavailable")
    }
}

impl Error for SecretBrokerEventSinkError {}

/// Required ref-only evidence seam. Implementations must not call back into the
/// broker while `append` runs because the mutation-owner lock is held.
pub trait SecretBrokerEventSink: Send + Sync {
    fn append(&self, event: &SecretAccessEvidence) -> Result<(), SecretBrokerEventSinkError>;
}

/// Process-local recording event sink for tests and explicit local composition.
#[derive(Debug)]
pub struct InMemorySecretBrokerEventSink {
    state: Mutex<InMemorySecretBrokerEventSinkState>,
}

#[derive(Debug)]
struct InMemorySecretBrokerEventSinkState {
    available: bool,
    events: Vec<SecretAccessEvidence>,
}

impl InMemorySecretBrokerEventSink {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(InMemorySecretBrokerEventSinkState {
                available: true,
                events: Vec::new(),
            }),
        }
    }

    pub fn set_available(&self, available: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.available = available;
        }
    }

    pub fn events(&self) -> Result<Vec<SecretAccessEvidence>, SecretBrokerEventSinkError> {
        self.state
            .lock()
            .map(|state| state.events.clone())
            .map_err(|_| SecretBrokerEventSinkError::Unavailable)
    }
}

impl Default for InMemorySecretBrokerEventSink {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBrokerEventSink for InMemorySecretBrokerEventSink {
    fn append(&self, event: &SecretAccessEvidence) -> Result<(), SecretBrokerEventSinkError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SecretBrokerEventSinkError::Unavailable)?;
        if !state.available {
            return Err(SecretBrokerEventSinkError::Unavailable);
        }
        state.events.push(event.clone());
        Ok(())
    }
}

/// Borrowed current authority inputs required by every lease mutation/use.
pub struct SecretBrokerAuthorityContext<'a> {
    cache: &'a AuthorityGrantCache,
    revocations: Option<&'a RevocationSnapshot>,
    policy: &'a OfflineAuthorityPolicy,
}

impl<'a> SecretBrokerAuthorityContext<'a> {
    pub fn new(
        cache: &'a AuthorityGrantCache,
        revocations: Option<&'a RevocationSnapshot>,
        policy: &'a OfflineAuthorityPolicy,
    ) -> Self {
        Self {
            cache,
            revocations,
            policy,
        }
    }
}

/// Opaque live delivery handle. The ID getters are safe metadata; the private
/// capability nonce is required for every state lookup.
///
/// ```compile_fail
/// use splendor_authority::SecretDeliveryHandle;
/// fn require_clone<T: Clone>() {}
/// require_clone::<SecretDeliveryHandle>();
/// ```
///
/// ```compile_fail
/// use splendor_authority::SecretDeliveryHandle;
/// fn serialize(value: &SecretDeliveryHandle) {
///     let _ = serde_json::to_vec(value).unwrap();
/// }
/// ```
pub struct SecretDeliveryHandle {
    delivery_handle_id: SecretDeliveryHandleId,
    secret_lease_id: SecretLeaseId,
    capability_nonce: Uuid,
}

impl SecretDeliveryHandle {
    pub fn delivery_handle_id(&self) -> &SecretDeliveryHandleId {
        &self.delivery_handle_id
    }

    pub fn secret_lease_id(&self) -> &SecretLeaseId {
        &self.secret_lease_id
    }
}

impl fmt::Debug for SecretDeliveryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretDeliveryHandle(<opaque>)")
    }
}

/// Lease issuance result containing one safe snapshot and one opaque handle.
pub struct SecretLeaseGrant {
    snapshot: SecretLeaseSnapshot,
    handle: SecretDeliveryHandle,
}

impl SecretLeaseGrant {
    pub fn snapshot(&self) -> &SecretLeaseSnapshot {
        &self.snapshot
    }

    pub fn handle(&self) -> &SecretDeliveryHandle {
        &self.handle
    }

    pub fn into_parts(self) -> (SecretLeaseSnapshot, SecretDeliveryHandle) {
        (self.snapshot, self.handle)
    }
}

/// Opaque successful use reservation for a later Gateway-owned delivery slice.
/// It contains no material and has no provider-fetch conversion API.
///
/// ```compile_fail
/// use splendor_authority::SecretDeliveryClaim;
/// fn require_clone<T: Clone>() {}
/// require_clone::<SecretDeliveryClaim>();
/// ```
///
/// ```compile_fail
/// use splendor_authority::SecretDeliveryClaim;
/// fn serialize(value: &SecretDeliveryClaim) {
///     let _ = serde_json::to_vec(value).unwrap();
/// }
/// ```
pub struct SecretDeliveryClaim {
    secret_use_claim_id: SecretUseClaimId,
    secret_use_attempt_id: SecretUseAttemptId,
    secret_lease_id: SecretLeaseId,
    delivery_handle_id: SecretDeliveryHandleId,
    use_binding: SecretLeaseUseBinding,
    capability_nonce: Uuid,
}

impl SecretDeliveryClaim {
    pub fn secret_use_claim_id(&self) -> &SecretUseClaimId {
        &self.secret_use_claim_id
    }
    pub fn secret_use_attempt_id(&self) -> &SecretUseAttemptId {
        &self.secret_use_attempt_id
    }
    pub fn secret_lease_id(&self) -> &SecretLeaseId {
        &self.secret_lease_id
    }
    pub fn delivery_handle_id(&self) -> &SecretDeliveryHandleId {
        &self.delivery_handle_id
    }
    pub fn use_binding(&self) -> &SecretLeaseUseBinding {
        &self.use_binding
    }
}

impl fmt::Debug for SecretDeliveryClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.capability_nonce;
        formatter.write_str("SecretDeliveryClaim(<opaque>)")
    }
}

/// Read-only replay projection over already-recorded process-local facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SecretBrokerReplayView {
    pub leases: Vec<SecretLeaseSnapshot>,
    pub events: Vec<SecretAccessEvidence>,
}

/// Fixed outward broker failures. Wrong ref, version, tenant, and binding all
/// use the same `secret_not_available` profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretBrokerError {
    SecretNotAvailable,
    AuthorityDenied,
    ClockUnavailable,
    ClockRollback,
    EvidenceUnavailable,
    LeaseNotStarted,
    LeaseExpired,
    MaxUsesExceeded,
    RenewalDenied,
    RequestAlreadyUsed,
    StateUnavailable,
}

impl SecretBrokerError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::SecretNotAvailable => "secret_not_available",
            Self::AuthorityDenied => "secret_authority_denied",
            Self::ClockUnavailable => "secret_broker_clock_unavailable",
            Self::ClockRollback => "secret_broker_clock_rollback",
            Self::EvidenceUnavailable => "secret_broker_evidence_unavailable",
            Self::LeaseNotStarted => "secret_lease_not_started",
            Self::LeaseExpired => "secret_lease_expired",
            Self::MaxUsesExceeded => "secret_lease_max_uses_exceeded",
            Self::RenewalDenied => "secret_lease_renewal_denied",
            Self::RequestAlreadyUsed => "secret_lease_request_already_used",
            Self::StateUnavailable => "secret_broker_state_unavailable",
        }
    }
}

impl fmt::Display for SecretBrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for SecretBrokerError {}

/// Invalid immutable process-local broker composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretBrokerConfigError {
    DuplicateSecretRef,
    DuplicateProvider,
    MissingProvider,
}

impl fmt::Display for SecretBrokerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateSecretRef => "duplicate_secret_ref",
            Self::DuplicateProvider => "duplicate_secret_provider",
            Self::MissingProvider => "secret_provider_missing",
        })
    }
}

impl Error for SecretBrokerConfigError {}

/// Explicit process-local lifecycle owner. State is not restart durable.
pub struct ProcessLocalSecretBroker {
    state: Mutex<SecretBrokerState>,
    providers: HashMap<SecretProviderId, Arc<dyn SecretProvider>>,
    clock: Arc<dyn SecretBrokerClock>,
    ids: Arc<dyn SecretBrokerIdSource>,
    event_sink: Arc<dyn SecretBrokerEventSink>,
}

#[derive(Default)]
struct SecretBrokerState {
    max_observed_time: Option<OffsetDateTime>,
    refs: HashMap<(TenantId, SecretRefId), SecretRefV2>,
    leases: HashMap<SecretLeaseId, LeaseRecord>,
    handles: HashMap<SecretDeliveryHandleId, HandleRecord>,
    used_request_ids: HashSet<splendor_types::SecretLeaseRequestId>,
    allocated_ids: HashSet<Uuid>,
    events: Vec<SecretAccessEvidence>,
}

#[derive(Clone)]
struct LeaseRecord {
    secret_lease_id: SecretLeaseId,
    request: SecretLeaseRequest,
    delivery_handle_id: SecretDeliveryHandleId,
    selected_delivery_method: SecretDeliveryMethod,
    status: SecretLeaseStatus,
    starts_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    continuous_lifetime_started_at: OffsetDateTime,
    max_continuous_expires_at: OffsetDateTime,
    max_uses: u64,
    uses_claimed: u64,
    revocation_generation: u64,
    issued_at: OffsetDateTime,
    renewed_from_lease_id: Option<SecretLeaseId>,
    last_event_id: SecretAccessEventId,
}

struct HandleRecord {
    secret_lease_id: SecretLeaseId,
    capability_nonce: Uuid,
    active: bool,
}

struct IssuePlan {
    selected_delivery_method: SecretDeliveryMethod,
    starts_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    max_continuous_expires_at: OffsetDateTime,
    max_uses: u64,
}

impl ProcessLocalSecretBroker {
    /// Builds an explicit process-local broker with system time and random IDs.
    pub fn try_new(
        refs: Vec<SecretRefV2>,
        providers: Vec<Arc<dyn SecretProvider>>,
        event_sink: Arc<dyn SecretBrokerEventSink>,
    ) -> Result<Self, SecretBrokerConfigError> {
        Self::with_sources(
            refs,
            providers,
            Arc::new(SystemSecretBrokerClock),
            Arc::new(SystemSecretBrokerIdSource),
            event_sink,
        )
    }

    /// Builds an explicit process-local broker with injected deterministic seams.
    pub fn with_sources(
        refs: Vec<SecretRefV2>,
        providers: Vec<Arc<dyn SecretProvider>>,
        clock: Arc<dyn SecretBrokerClock>,
        ids: Arc<dyn SecretBrokerIdSource>,
        event_sink: Arc<dyn SecretBrokerEventSink>,
    ) -> Result<Self, SecretBrokerConfigError> {
        let mut provider_map = HashMap::new();
        for provider in providers {
            let provider_id = provider.provider_id().clone();
            if provider_map.insert(provider_id, provider).is_some() {
                return Err(SecretBrokerConfigError::DuplicateProvider);
            }
        }
        let mut ref_map = HashMap::new();
        for secret_ref in refs {
            if !provider_map.contains_key(secret_ref.secret_provider_id()) {
                return Err(SecretBrokerConfigError::MissingProvider);
            }
            let key = (
                secret_ref.tenant_id().clone(),
                secret_ref.secret_ref_id().clone(),
            );
            if ref_map.insert(key, secret_ref).is_some() {
                return Err(SecretBrokerConfigError::DuplicateSecretRef);
            }
        }
        Ok(Self {
            state: Mutex::new(SecretBrokerState {
                refs: ref_map,
                ..SecretBrokerState::default()
            }),
            providers: provider_map,
            clock,
            ids,
            event_sink,
        })
    }

    /// Issues one exact-bound lease and opaque handle after current authority and
    /// ref-policy validation. Provider methods are never called.
    pub fn issue_lease(
        &self,
        request: SecretLeaseRequest,
        authority: &SecretBrokerAuthorityContext<'_>,
    ) -> Result<SecretLeaseGrant, SecretBrokerError> {
        let mut state = self.lock_state()?;
        let now = match self.observe_time(&mut state) {
            Ok(now) => now,
            Err(error) => {
                if error == SecretBrokerError::ClockRollback {
                    let recorded_at = state
                        .max_observed_time
                        .ok_or(SecretBrokerError::ClockUnavailable)?;
                    self.record_denial(
                        &mut state,
                        SecretAccessEvidenceKind::LeaseDenied,
                        request.use_binding().clone(),
                        None,
                        None,
                        0,
                        request.bound_use_requirement().requested_max_uses(),
                        1,
                        SecretAccessDenialCode::ClockRollback,
                        recorded_at,
                    )?;
                }
                return Err(error);
            }
        };
        let plan = match self.validate_issue(&state, &request, authority, now) {
            Ok(plan) => plan,
            Err((error, denial)) => {
                self.record_denial(
                    &mut state,
                    SecretAccessEvidenceKind::LeaseDenied,
                    request.use_binding().clone(),
                    None,
                    None,
                    0,
                    request.bound_use_requirement().requested_max_uses(),
                    1,
                    denial,
                    now,
                )?;
                return Err(error);
            }
        };

        let secret_lease_id = self.next_lease_id()?;
        let delivery_handle_id = self.next_handle_id()?;
        let capability_nonce = self.next_non_nil_uuid(SecretBrokerIdKind::HandleCapability)?;
        let event_id = self.next_event_id()?;
        self.reserve_generated_ids(
            &mut state,
            &[
                *secret_lease_id.as_uuid(),
                *delivery_handle_id.as_uuid(),
                capability_nonce,
                *event_id.as_uuid(),
            ],
            SecretBrokerError::StateUnavailable,
        )?;
        let event = evidence(
            event_id.clone(),
            SecretAccessEvidenceKind::LeaseIssued,
            SecretAccessEvidenceOutcome::Succeeded,
            request.use_binding().clone(),
            Some(secret_lease_id.clone()),
            Some(delivery_handle_id.clone()),
            None,
            0,
            plan.max_uses,
            1,
            None,
            now,
        )?;
        self.append_event(&mut state, event)?;

        let record = LeaseRecord {
            secret_lease_id: secret_lease_id.clone(),
            request: request.clone(),
            delivery_handle_id: delivery_handle_id.clone(),
            selected_delivery_method: plan.selected_delivery_method,
            status: SecretLeaseStatus::Active,
            starts_at: plan.starts_at,
            expires_at: plan.expires_at,
            continuous_lifetime_started_at: plan.starts_at,
            max_continuous_expires_at: plan.max_continuous_expires_at,
            max_uses: plan.max_uses,
            uses_claimed: 0,
            revocation_generation: 1,
            issued_at: now,
            renewed_from_lease_id: None,
            last_event_id: event_id,
        };
        let snapshot = snapshot(&record)?;
        state
            .used_request_ids
            .insert(request.secret_lease_request_id().clone());
        state.handles.insert(
            delivery_handle_id.clone(),
            HandleRecord {
                secret_lease_id: secret_lease_id.clone(),
                capability_nonce,
                active: true,
            },
        );
        state.leases.insert(secret_lease_id.clone(), record);
        Ok(SecretLeaseGrant {
            snapshot,
            handle: SecretDeliveryHandle {
                delivery_handle_id,
                secret_lease_id,
                capability_nonce,
            },
        })
    }

    /// Atomically claims one use. The final available use has exactly one winner
    /// under concurrency. The result cannot fetch or expose material.
    pub fn claim_use(
        &self,
        handle: &SecretDeliveryHandle,
        use_binding: &SecretLeaseUseBinding,
        authority: &SecretBrokerAuthorityContext<'_>,
    ) -> Result<SecretDeliveryClaim, SecretBrokerError> {
        let mut state = self.lock_state()?;
        let now = match self.observe_time(&mut state) {
            Ok(now) => now,
            Err(SecretBrokerError::ClockRollback) => {
                let recorded_at = state
                    .max_observed_time
                    .ok_or(SecretBrokerError::ClockUnavailable)?;
                let (lease_id, handle_id, uses_claimed, max_uses, revocation_generation) =
                    self.denial_context_for_handle(&state, handle);
                self.record_denial(
                    &mut state,
                    SecretAccessEvidenceKind::UseDenied,
                    use_binding.clone(),
                    lease_id,
                    handle_id,
                    uses_claimed,
                    max_uses,
                    revocation_generation,
                    SecretAccessDenialCode::ClockRollback,
                    recorded_at,
                )?;
                return Err(SecretBrokerError::ClockRollback);
            }
            Err(error) => return Err(error),
        };
        let record = match self.valid_handle_record(&state, handle) {
            Ok(record) => record,
            Err(error) => {
                self.record_denial(
                    &mut state,
                    SecretAccessEvidenceKind::UseDenied,
                    use_binding.clone(),
                    None,
                    None,
                    0,
                    1,
                    1,
                    SecretAccessDenialCode::SecretNotAvailable,
                    now,
                )?;
                return Err(error);
            }
        };
        let lease_id = record.secret_lease_id.clone();
        let lease = state
            .leases
            .get(&lease_id)
            .cloned()
            .ok_or(SecretBrokerError::StateUnavailable)?;
        if lease.request.use_binding() != use_binding {
            self.record_denial_for_lease(
                &mut state,
                &lease,
                use_binding.clone(),
                SecretAccessEvidenceKind::UseDenied,
                SecretAccessDenialCode::BindingMismatch,
                now,
            )?;
            return Err(SecretBrokerError::SecretNotAvailable);
        }
        if lease.status == SecretLeaseStatus::Exhausted {
            self.record_denial_for_lease(
                &mut state,
                &lease,
                use_binding.clone(),
                SecretAccessEvidenceKind::UseDenied,
                SecretAccessDenialCode::MaxUsesExceeded,
                now,
            )?;
            return Err(SecretBrokerError::MaxUsesExceeded);
        }
        if now < lease.starts_at {
            self.record_denial_for_lease(
                &mut state,
                &lease,
                use_binding.clone(),
                SecretAccessEvidenceKind::UseDenied,
                SecretAccessDenialCode::LeaseNotStarted,
                now,
            )?;
            return Err(SecretBrokerError::LeaseNotStarted);
        }
        if now >= lease.expires_at {
            self.record_denial_for_lease(
                &mut state,
                &lease,
                use_binding.clone(),
                SecretAccessEvidenceKind::UseDenied,
                SecretAccessDenialCode::LeaseExpired,
                now,
            )?;
            self.expire_lease(&mut state, &lease_id);
            return Err(SecretBrokerError::LeaseExpired);
        }
        if !authority_allows(authority, use_binding, now, lease.expires_at) {
            self.record_denial_for_lease(
                &mut state,
                &lease,
                use_binding.clone(),
                SecretAccessEvidenceKind::UseDenied,
                SecretAccessDenialCode::AuthorityDenied,
                now,
            )?;
            return Err(SecretBrokerError::AuthorityDenied);
        }
        let claim_id = self.next_claim_id()?;
        let use_attempt_id = self.next_use_attempt_id()?;
        let claim_capability = self.next_non_nil_uuid(SecretBrokerIdKind::ClaimCapability)?;
        let event_id = self.next_event_id()?;
        self.reserve_generated_ids(
            &mut state,
            &[
                *claim_id.as_uuid(),
                *use_attempt_id.as_uuid(),
                claim_capability,
                *event_id.as_uuid(),
            ],
            SecretBrokerError::StateUnavailable,
        )?;
        let next_uses = lease.uses_claimed + 1;
        let event = evidence(
            event_id.clone(),
            SecretAccessEvidenceKind::UseClaimed,
            SecretAccessEvidenceOutcome::Succeeded,
            use_binding.clone(),
            Some(lease_id.clone()),
            Some(handle.delivery_handle_id.clone()),
            Some(claim_id.clone()),
            next_uses,
            lease.max_uses,
            lease.revocation_generation,
            None,
            now,
        )?;
        self.append_event(&mut state, event)?;
        let lease = state
            .leases
            .get_mut(&lease_id)
            .ok_or(SecretBrokerError::StateUnavailable)?;
        lease.uses_claimed = next_uses;
        lease.last_event_id = event_id;
        if next_uses == lease.max_uses {
            lease.status = SecretLeaseStatus::Exhausted;
        }
        Ok(SecretDeliveryClaim {
            secret_use_claim_id: claim_id,
            secret_use_attempt_id: use_attempt_id,
            secret_lease_id: lease_id,
            delivery_handle_id: handle.delivery_handle_id.clone(),
            use_binding: use_binding.clone(),
            capability_nonce: claim_capability,
        })
    }

    /// Renews into a new lease and handle while carrying the original continuous
    /// lifetime and use count forward. Success invalidates the old handle.
    pub fn renew_lease(
        &self,
        old_handle: &SecretDeliveryHandle,
        request: SecretLeaseRequest,
        authority: &SecretBrokerAuthorityContext<'_>,
    ) -> Result<SecretLeaseGrant, SecretBrokerError> {
        let mut state = self.lock_state()?;
        let now = match self.observe_time(&mut state) {
            Ok(now) => now,
            Err(SecretBrokerError::ClockRollback) => {
                let recorded_at = state
                    .max_observed_time
                    .ok_or(SecretBrokerError::ClockUnavailable)?;
                let (lease_id, handle_id, uses_claimed, max_uses, revocation_generation) =
                    self.denial_context_for_handle(&state, old_handle);
                self.record_denial(
                    &mut state,
                    SecretAccessEvidenceKind::RenewalDenied,
                    request.use_binding().clone(),
                    lease_id,
                    handle_id,
                    uses_claimed,
                    max_uses,
                    revocation_generation,
                    SecretAccessDenialCode::ClockRollback,
                    recorded_at,
                )?;
                return Err(SecretBrokerError::ClockRollback);
            }
            Err(error) => return Err(error),
        };
        let handle_record = match self.valid_handle_record(&state, old_handle) {
            Ok(record) => record,
            Err(error) => {
                self.record_denial(
                    &mut state,
                    SecretAccessEvidenceKind::RenewalDenied,
                    request.use_binding().clone(),
                    None,
                    None,
                    0,
                    request.bound_use_requirement().requested_max_uses(),
                    1,
                    SecretAccessDenialCode::SecretNotAvailable,
                    now,
                )?;
                return Err(error);
            }
        };
        let old_id = handle_record.secret_lease_id.clone();
        let old = state
            .leases
            .get(&old_id)
            .cloned()
            .ok_or(SecretBrokerError::StateUnavailable)?;
        let denial = self.validate_renewal(&state, &old, &request, authority, now);
        if let Err(code) = denial {
            self.record_denial_for_lease(
                &mut state,
                &old,
                request.use_binding().clone(),
                SecretAccessEvidenceKind::RenewalDenied,
                code,
                now,
            )?;
            return Err(match code {
                SecretAccessDenialCode::AuthorityDenied => SecretBrokerError::AuthorityDenied,
                SecretAccessDenialCode::RequestAlreadyUsed => SecretBrokerError::RequestAlreadyUsed,
                _ => SecretBrokerError::RenewalDenied,
            });
        }

        let starts_at = parse_canonical(request.starts_at())?;
        let expires_at = parse_canonical(request.expires_at())?;
        let new_max_uses = request.bound_use_requirement().requested_max_uses();
        let new_lease_id = self.next_lease_id()?;
        let new_handle_id = self.next_handle_id()?;
        let capability_nonce = self.next_non_nil_uuid(SecretBrokerIdKind::HandleCapability)?;
        let event_id = self.next_event_id()?;
        self.reserve_generated_ids(
            &mut state,
            &[
                *new_lease_id.as_uuid(),
                *new_handle_id.as_uuid(),
                capability_nonce,
                *event_id.as_uuid(),
            ],
            SecretBrokerError::StateUnavailable,
        )?;
        let event = evidence(
            event_id.clone(),
            SecretAccessEvidenceKind::LeaseRenewed,
            SecretAccessEvidenceOutcome::Succeeded,
            request.use_binding().clone(),
            Some(new_lease_id.clone()),
            Some(new_handle_id.clone()),
            None,
            old.uses_claimed,
            new_max_uses,
            old.revocation_generation,
            None,
            now,
        )?;
        self.append_event(&mut state, event)?;

        if let Some(old_record) = state.leases.get_mut(&old_id) {
            old_record.status = SecretLeaseStatus::Superseded;
            old_record.last_event_id = event_id.clone();
        }
        if let Some(old_handle_record) = state.handles.get_mut(&old.delivery_handle_id) {
            old_handle_record.active = false;
        }
        let record = LeaseRecord {
            secret_lease_id: new_lease_id.clone(),
            request: request.clone(),
            delivery_handle_id: new_handle_id.clone(),
            selected_delivery_method: old.selected_delivery_method,
            status: if old.uses_claimed == new_max_uses {
                SecretLeaseStatus::Exhausted
            } else {
                SecretLeaseStatus::Active
            },
            starts_at,
            expires_at,
            continuous_lifetime_started_at: old.continuous_lifetime_started_at,
            max_continuous_expires_at: old.max_continuous_expires_at,
            max_uses: new_max_uses,
            uses_claimed: old.uses_claimed,
            revocation_generation: old.revocation_generation,
            issued_at: now,
            renewed_from_lease_id: Some(old_id),
            last_event_id: event_id,
        };
        let snapshot = snapshot(&record)?;
        state
            .used_request_ids
            .insert(request.secret_lease_request_id().clone());
        state.handles.insert(
            new_handle_id.clone(),
            HandleRecord {
                secret_lease_id: new_lease_id.clone(),
                capability_nonce,
                active: true,
            },
        );
        state.leases.insert(new_lease_id.clone(), record);
        Ok(SecretLeaseGrant {
            snapshot,
            handle: SecretDeliveryHandle {
                delivery_handle_id: new_handle_id,
                secret_lease_id: new_lease_id,
                capability_nonce,
            },
        })
    }

    /// Atomically closes local admission before attempting terminal evidence.
    /// Provider methods are not invoked; a later Gateway control slice must
    /// propagate provider/node revocation.
    pub fn revoke_lease(
        &self,
        handle: &SecretDeliveryHandle,
        use_binding: &SecretLeaseUseBinding,
        authority: &SecretBrokerAuthorityContext<'_>,
    ) -> Result<SecretLeaseSnapshot, SecretBrokerError> {
        let mut state = self.lock_state()?;
        let now = match self.observe_time(&mut state) {
            Ok(now) => now,
            Err(SecretBrokerError::ClockRollback) => {
                let recorded_at = state
                    .max_observed_time
                    .ok_or(SecretBrokerError::ClockUnavailable)?;
                let (lease_id, handle_id, uses_claimed, max_uses, revocation_generation) =
                    self.denial_context_for_handle(&state, handle);
                self.record_denial(
                    &mut state,
                    SecretAccessEvidenceKind::RevocationDenied,
                    use_binding.clone(),
                    lease_id,
                    handle_id,
                    uses_claimed,
                    max_uses,
                    revocation_generation,
                    SecretAccessDenialCode::ClockRollback,
                    recorded_at,
                )?;
                return Err(SecretBrokerError::ClockRollback);
            }
            Err(error) => return Err(error),
        };
        let (lease_id, handle_active) = match self.known_handle_record(&state, handle) {
            Ok(handle_record) => (handle_record.secret_lease_id.clone(), handle_record.active),
            Err(error) => {
                self.record_denial(
                    &mut state,
                    SecretAccessEvidenceKind::RevocationDenied,
                    use_binding.clone(),
                    None,
                    None,
                    0,
                    1,
                    1,
                    SecretAccessDenialCode::SecretNotAvailable,
                    now,
                )?;
                return Err(error);
            }
        };
        let lease = state
            .leases
            .get(&lease_id)
            .cloned()
            .ok_or(SecretBrokerError::StateUnavailable)?;
        if lease.request.use_binding() != use_binding {
            self.record_denial_for_lease(
                &mut state,
                &lease,
                use_binding.clone(),
                SecretAccessEvidenceKind::RevocationDenied,
                SecretAccessDenialCode::BindingMismatch,
                now,
            )?;
            return Err(SecretBrokerError::SecretNotAvailable);
        }
        if !authority_allows(authority, use_binding, now, lease.expires_at) {
            self.record_denial_for_lease(
                &mut state,
                &lease,
                use_binding.clone(),
                SecretAccessEvidenceKind::RevocationDenied,
                SecretAccessDenialCode::AuthorityDenied,
                now,
            )?;
            return Err(SecretBrokerError::AuthorityDenied);
        }
        if lease.status == SecretLeaseStatus::Revoked {
            return snapshot(&lease);
        }
        if lease.status == SecretLeaseStatus::RevocationPending {
            let event_id = self.next_event_id()?;
            self.reserve_generated_ids(
                &mut state,
                &[*event_id.as_uuid()],
                SecretBrokerError::EvidenceUnavailable,
            )?;
            let event = evidence(
                event_id.clone(),
                SecretAccessEvidenceKind::LeaseRevoked,
                SecretAccessEvidenceOutcome::Succeeded,
                use_binding.clone(),
                Some(lease_id.clone()),
                Some(lease.delivery_handle_id.clone()),
                None,
                lease.uses_claimed,
                lease.max_uses,
                lease.revocation_generation,
                None,
                now,
            )?;
            self.append_event(&mut state, event)?;
            let lease_mut = state
                .leases
                .get_mut(&lease_id)
                .ok_or(SecretBrokerError::StateUnavailable)?;
            lease_mut.last_event_id = event_id;
            lease_mut.status = SecretLeaseStatus::Revoked;
            return snapshot(lease_mut);
        }
        if !handle_active {
            self.record_denial_for_lease(
                &mut state,
                &lease,
                use_binding.clone(),
                SecretAccessEvidenceKind::RevocationDenied,
                SecretAccessDenialCode::SecretNotAvailable,
                now,
            )?;
            return Err(SecretBrokerError::SecretNotAvailable);
        }

        let next_generation = lease
            .revocation_generation
            .checked_add(1)
            .ok_or(SecretBrokerError::StateUnavailable)?;
        {
            let lease_mut = state
                .leases
                .get_mut(&lease_id)
                .ok_or(SecretBrokerError::StateUnavailable)?;
            lease_mut.status = SecretLeaseStatus::RevocationPending;
            lease_mut.revocation_generation = next_generation;
        }
        if let Some(handle_mut) = state.handles.get_mut(&lease.delivery_handle_id) {
            handle_mut.active = false;
        }

        let event_id = match self.next_event_id() {
            Ok(event_id) => event_id,
            Err(_) => return Err(SecretBrokerError::EvidenceUnavailable),
        };
        if self
            .reserve_generated_ids(
                &mut state,
                &[*event_id.as_uuid()],
                SecretBrokerError::EvidenceUnavailable,
            )
            .is_err()
        {
            return Err(SecretBrokerError::EvidenceUnavailable);
        }
        let event = evidence(
            event_id.clone(),
            SecretAccessEvidenceKind::LeaseRevoked,
            SecretAccessEvidenceOutcome::Succeeded,
            use_binding.clone(),
            Some(lease_id.clone()),
            Some(lease.delivery_handle_id.clone()),
            None,
            lease.uses_claimed,
            lease.max_uses,
            next_generation,
            None,
            now,
        )?;
        if self.append_event(&mut state, event).is_err() {
            return Err(SecretBrokerError::EvidenceUnavailable);
        }
        let lease_mut = state
            .leases
            .get_mut(&lease_id)
            .ok_or(SecretBrokerError::StateUnavailable)?;
        lease_mut.last_event_id = event_id;
        lease_mut.status = SecretLeaseStatus::Revoked;
        snapshot(lease_mut)
    }

    /// Returns one safe snapshot without mutating state or invoking a provider.
    pub fn inspect_lease(
        &self,
        secret_lease_id: &SecretLeaseId,
    ) -> Result<Option<SecretLeaseSnapshot>, SecretBrokerError> {
        let state = self.lock_state()?;
        state.leases.get(secret_lease_id).map(snapshot).transpose()
    }

    /// Reconstructs process-local safe facts without current evaluation, ID/time
    /// allocation, provider calls, handle creation, or lifecycle mutation.
    pub fn replay(&self) -> Result<SecretBrokerReplayView, SecretBrokerError> {
        let state = self.lock_state()?;
        let mut leases = state
            .leases
            .values()
            .map(snapshot)
            .collect::<Result<Vec<_>, _>>()?;
        leases.sort_by_key(|lease| lease.secret_lease_id().to_string());
        Ok(SecretBrokerReplayView {
            leases,
            events: state.events.clone(),
        })
    }

    /// Number of registered provider ports. This is passive configuration only.
    pub fn registered_provider_count(&self) -> usize {
        self.providers.len()
    }

    fn validate_issue(
        &self,
        state: &SecretBrokerState,
        request: &SecretLeaseRequest,
        authority: &SecretBrokerAuthorityContext<'_>,
        now: OffsetDateTime,
    ) -> Result<IssuePlan, (SecretBrokerError, SecretAccessDenialCode)> {
        if state
            .used_request_ids
            .contains(request.secret_lease_request_id())
        {
            return Err((
                SecretBrokerError::RequestAlreadyUsed,
                SecretAccessDenialCode::RequestAlreadyUsed,
            ));
        }
        let binding = request.use_binding();
        let Some(secret_ref) = state
            .refs
            .get(&(binding.tenant_id().clone(), binding.secret_ref_id().clone()))
        else {
            return Err((
                SecretBrokerError::SecretNotAvailable,
                SecretAccessDenialCode::SecretNotAvailable,
            ));
        };
        if !secret_ref_allows_binding(secret_ref, binding, now) {
            return Err((
                SecretBrokerError::SecretNotAvailable,
                SecretAccessDenialCode::BindingMismatch,
            ));
        }
        let Some(selected_delivery_method) = request
            .bound_use_requirement()
            .delivery_methods()
            .iter()
            .copied()
            .find(|method| secret_ref.allowed_delivery_methods().contains(method))
        else {
            return Err((
                SecretBrokerError::SecretNotAvailable,
                SecretAccessDenialCode::BindingMismatch,
            ));
        };
        let starts_at = parse_canonical(request.starts_at()).map_err(|_| {
            (
                SecretBrokerError::SecretNotAvailable,
                SecretAccessDenialCode::SecretNotAvailable,
            )
        })?;
        let expires_at = parse_canonical(request.expires_at()).map_err(|_| {
            (
                SecretBrokerError::SecretNotAvailable,
                SecretAccessDenialCode::SecretNotAvailable,
            )
        })?;
        let requested_at = parse_canonical(request.requested_at()).map_err(|_| {
            (
                SecretBrokerError::SecretNotAvailable,
                SecretAccessDenialCode::SecretNotAvailable,
            )
        })?;
        if requested_at > now || starts_at < now || now >= expires_at {
            return Err((
                SecretBrokerError::SecretNotAvailable,
                SecretAccessDenialCode::LeaseExpired,
            ));
        }
        let duration = expires_at - starts_at;
        let policy = secret_ref.lease_policy();
        let maximum_lease_nanos = i128::from(policy.max_lease_duration_seconds())
            .checked_mul(1_000_000_000)
            .ok_or((
                SecretBrokerError::SecretNotAvailable,
                SecretAccessDenialCode::SecretNotAvailable,
            ))?;
        if duration.whole_nanoseconds() <= 0
            || duration.whole_nanoseconds() > maximum_lease_nanos
            || request.bound_use_requirement().requested_max_uses() > policy.max_uses()
        {
            return Err((
                SecretBrokerError::SecretNotAvailable,
                SecretAccessDenialCode::SecretNotAvailable,
            ));
        }
        let max_continuous_expires_at = starts_at
            .checked_add(Duration::seconds(
                i64::try_from(policy.max_continuous_lifetime_seconds()).map_err(|_| {
                    (
                        SecretBrokerError::SecretNotAvailable,
                        SecretAccessDenialCode::ContinuousLifetimeExceeded,
                    )
                })?,
            ))
            .ok_or((
                SecretBrokerError::SecretNotAvailable,
                SecretAccessDenialCode::ContinuousLifetimeExceeded,
            ))?;
        if !authority_allows(authority, binding, now, expires_at) {
            return Err((
                SecretBrokerError::AuthorityDenied,
                SecretAccessDenialCode::AuthorityDenied,
            ));
        }
        Ok(IssuePlan {
            selected_delivery_method,
            starts_at,
            expires_at,
            max_continuous_expires_at,
            max_uses: request.bound_use_requirement().requested_max_uses(),
        })
    }

    fn validate_renewal(
        &self,
        state: &SecretBrokerState,
        old: &LeaseRecord,
        request: &SecretLeaseRequest,
        authority: &SecretBrokerAuthorityContext<'_>,
        now: OffsetDateTime,
    ) -> Result<(), SecretAccessDenialCode> {
        if state
            .used_request_ids
            .contains(request.secret_lease_request_id())
        {
            return Err(SecretAccessDenialCode::RequestAlreadyUsed);
        }
        if old.status != SecretLeaseStatus::Active
            || now < old.starts_at
            || now >= old.expires_at
            || old.uses_claimed >= old.max_uses
            || old.request.use_binding() != request.use_binding()
            || old.request.bound_use_requirement().delivery_methods()
                != request.bound_use_requirement().delivery_methods()
        {
            return Err(SecretAccessDenialCode::RenewalNotAllowed);
        }
        let secret_ref = state
            .refs
            .get(&(
                request.use_binding().tenant_id().clone(),
                request.use_binding().secret_ref_id().clone(),
            ))
            .ok_or(SecretAccessDenialCode::SecretNotAvailable)?;
        if !secret_ref_allows_binding(secret_ref, request.use_binding(), now) {
            return Err(SecretAccessDenialCode::SecretNotAvailable);
        }
        if !secret_ref.lease_policy().renewable() {
            return Err(SecretAccessDenialCode::RenewalNotAllowed);
        }
        let starts_at = parse_canonical(request.starts_at())
            .map_err(|_| SecretAccessDenialCode::RenewalNotAllowed)?;
        let expires_at = parse_canonical(request.expires_at())
            .map_err(|_| SecretAccessDenialCode::RenewalNotAllowed)?;
        let requested_max_uses = request.bound_use_requirement().requested_max_uses();
        let requested_at = parse_canonical(request.requested_at())
            .map_err(|_| SecretAccessDenialCode::RenewalNotAllowed)?;
        let duration = expires_at - starts_at;
        let maximum_lease_nanos =
            i128::from(secret_ref.lease_policy().max_lease_duration_seconds())
                .checked_mul(1_000_000_000)
                .ok_or(SecretAccessDenialCode::RenewalNotAllowed)?;
        if starts_at < now
            || requested_at > now
            || starts_at > old.expires_at
            || expires_at > old.max_continuous_expires_at
            || duration.whole_nanoseconds() <= 0
            || duration.whole_nanoseconds() > maximum_lease_nanos
            || requested_max_uses > old.max_uses
            || requested_max_uses < old.uses_claimed
        {
            return Err(SecretAccessDenialCode::ContinuousLifetimeExceeded);
        }
        if !authority_allows(authority, request.use_binding(), now, expires_at) {
            return Err(SecretAccessDenialCode::AuthorityDenied);
        }
        Ok(())
    }

    fn valid_handle_record<'a>(
        &self,
        state: &'a SecretBrokerState,
        handle: &SecretDeliveryHandle,
    ) -> Result<&'a HandleRecord, SecretBrokerError> {
        let record = state
            .handles
            .get(&handle.delivery_handle_id)
            .ok_or(SecretBrokerError::SecretNotAvailable)?;
        if !record.active
            || record.secret_lease_id != handle.secret_lease_id
            || record.capability_nonce != handle.capability_nonce
        {
            return Err(SecretBrokerError::SecretNotAvailable);
        }
        Ok(record)
    }

    fn known_handle_record<'a>(
        &self,
        state: &'a SecretBrokerState,
        handle: &SecretDeliveryHandle,
    ) -> Result<&'a HandleRecord, SecretBrokerError> {
        let record = state
            .handles
            .get(&handle.delivery_handle_id)
            .ok_or(SecretBrokerError::SecretNotAvailable)?;
        if record.secret_lease_id != handle.secret_lease_id
            || record.capability_nonce != handle.capability_nonce
        {
            return Err(SecretBrokerError::SecretNotAvailable);
        }
        Ok(record)
    }

    fn denial_context_for_handle(
        &self,
        state: &SecretBrokerState,
        handle: &SecretDeliveryHandle,
    ) -> (
        Option<SecretLeaseId>,
        Option<SecretDeliveryHandleId>,
        u64,
        u64,
        u64,
    ) {
        let Some(record) = state.handles.get(&handle.delivery_handle_id) else {
            return (None, None, 0, 1, 1);
        };
        if record.secret_lease_id != handle.secret_lease_id
            || record.capability_nonce != handle.capability_nonce
        {
            return (None, None, 0, 1, 1);
        }
        let Some(lease) = state.leases.get(&record.secret_lease_id) else {
            return (None, None, 0, 1, 1);
        };
        (
            Some(lease.secret_lease_id.clone()),
            Some(lease.delivery_handle_id.clone()),
            lease.uses_claimed,
            lease.max_uses,
            lease.revocation_generation,
        )
    }

    fn record_denial_for_lease(
        &self,
        state: &mut SecretBrokerState,
        lease: &LeaseRecord,
        binding: SecretLeaseUseBinding,
        kind: SecretAccessEvidenceKind,
        code: SecretAccessDenialCode,
        now: OffsetDateTime,
    ) -> Result<(), SecretBrokerError> {
        self.record_denial(
            state,
            kind,
            binding,
            Some(lease.secret_lease_id.clone()),
            Some(lease.delivery_handle_id.clone()),
            lease.uses_claimed,
            lease.max_uses,
            lease.revocation_generation,
            code,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn record_denial(
        &self,
        state: &mut SecretBrokerState,
        kind: SecretAccessEvidenceKind,
        binding: SecretLeaseUseBinding,
        lease_id: Option<SecretLeaseId>,
        handle_id: Option<SecretDeliveryHandleId>,
        uses_claimed: u64,
        max_uses: u64,
        revocation_generation: u64,
        code: SecretAccessDenialCode,
        now: OffsetDateTime,
    ) -> Result<(), SecretBrokerError> {
        let event_id = self.next_event_id()?;
        self.reserve_generated_ids(
            state,
            &[*event_id.as_uuid()],
            SecretBrokerError::EvidenceUnavailable,
        )?;
        let event = evidence(
            event_id.clone(),
            kind,
            SecretAccessEvidenceOutcome::Denied,
            binding,
            lease_id.clone(),
            handle_id,
            None,
            uses_claimed.min(max_uses),
            max_uses.max(1),
            revocation_generation.max(1),
            Some(code),
            now,
        )?;
        self.append_event(state, event)?;
        if let Some(lease_id) = lease_id {
            if let Some(lease) = state.leases.get_mut(&lease_id) {
                lease.last_event_id = event_id;
            }
        }
        Ok(())
    }

    fn append_event(
        &self,
        state: &mut SecretBrokerState,
        event: SecretAccessEvidence,
    ) -> Result<(), SecretBrokerError> {
        self.event_sink
            .append(&event)
            .map_err(|_| SecretBrokerError::EvidenceUnavailable)?;
        state.events.push(event);
        Ok(())
    }

    fn expire_lease(&self, state: &mut SecretBrokerState, lease_id: &SecretLeaseId) {
        if let Some(lease) = state.leases.get_mut(lease_id) {
            lease.status = SecretLeaseStatus::Expired;
            if let Some(handle) = state.handles.get_mut(&lease.delivery_handle_id) {
                handle.active = false;
            }
        }
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, SecretBrokerState>, SecretBrokerError> {
        self.state
            .lock()
            .map_err(|_| SecretBrokerError::StateUnavailable)
    }

    fn observe_time(
        &self,
        state: &mut SecretBrokerState,
    ) -> Result<OffsetDateTime, SecretBrokerError> {
        let now = self
            .clock
            .now_utc()
            .ok_or(SecretBrokerError::ClockUnavailable)?;
        if now.nanosecond() % 1_000 != 0 {
            return Err(SecretBrokerError::ClockUnavailable);
        }
        if state
            .max_observed_time
            .is_some_and(|previous| now < previous)
        {
            return Err(SecretBrokerError::ClockRollback);
        }
        state.max_observed_time = Some(now);
        Ok(now)
    }

    fn next_non_nil_uuid(&self, kind: SecretBrokerIdKind) -> Result<Uuid, SecretBrokerError> {
        let value = self
            .ids
            .next_uuid(kind)
            .ok_or(SecretBrokerError::StateUnavailable)?;
        if value.is_nil() {
            return Err(SecretBrokerError::StateUnavailable);
        }
        Ok(value)
    }

    fn next_lease_id(&self) -> Result<SecretLeaseId, SecretBrokerError> {
        SecretLeaseId::try_from(self.next_non_nil_uuid(SecretBrokerIdKind::Lease)?)
            .map_err(|_| SecretBrokerError::StateUnavailable)
    }

    fn next_handle_id(&self) -> Result<SecretDeliveryHandleId, SecretBrokerError> {
        SecretDeliveryHandleId::try_from(
            self.next_non_nil_uuid(SecretBrokerIdKind::DeliveryHandle)?,
        )
        .map_err(|_| SecretBrokerError::StateUnavailable)
    }

    fn next_event_id(&self) -> Result<SecretAccessEventId, SecretBrokerError> {
        let value = self
            .next_non_nil_uuid(SecretBrokerIdKind::AccessEvent)
            .map_err(|_| SecretBrokerError::EvidenceUnavailable)?;
        SecretAccessEventId::try_from(value).map_err(|_| SecretBrokerError::EvidenceUnavailable)
    }

    fn next_claim_id(&self) -> Result<SecretUseClaimId, SecretBrokerError> {
        SecretUseClaimId::try_from(self.next_non_nil_uuid(SecretBrokerIdKind::UseClaim)?)
            .map_err(|_| SecretBrokerError::StateUnavailable)
    }

    fn next_use_attempt_id(&self) -> Result<SecretUseAttemptId, SecretBrokerError> {
        SecretUseAttemptId::try_from(self.next_non_nil_uuid(SecretBrokerIdKind::UseAttempt)?)
            .map_err(|_| SecretBrokerError::StateUnavailable)
    }

    fn reserve_generated_ids(
        &self,
        state: &mut SecretBrokerState,
        ids: &[Uuid],
        error: SecretBrokerError,
    ) -> Result<(), SecretBrokerError> {
        let unique = ids.iter().copied().collect::<HashSet<_>>();
        if unique.len() != ids.len()
            || unique
                .iter()
                .any(|candidate| state.allocated_ids.contains(candidate))
        {
            return Err(error);
        }
        state.allocated_ids.extend(unique);
        Ok(())
    }
}

fn credential_binding_matches(secret_ref: &SecretRefV2, binding: &SecretLeaseUseBinding) -> bool {
    secret_ref
        .allowed_credential_bindings()
        .iter()
        .any(|allowed| {
            allowed.driver_operation() == binding.driver_operation()
                && allowed.driver_declaration_revision() == binding.driver_declaration_revision()
                && allowed.credential_slot_id() == binding.credential_slot_id()
                && allowed.destination_schema() == binding.destination_schema()
                && allowed.delivery_exposure_profile() == binding.delivery_exposure_profile()
                && allowed
                    .approved_destination_digests()
                    .contains(&binding.destination_digest())
        })
}

fn secret_ref_allows_binding(
    secret_ref: &SecretRefV2,
    binding: &SecretLeaseUseBinding,
    now: OffsetDateTime,
) -> bool {
    if secret_ref.secret_ref_revision() != binding.secret_ref_revision()
        || secret_ref.provider_version_ref() != binding.provider_version_ref()
        || !credential_binding_matches(secret_ref, binding)
    {
        return false;
    }
    let Ok(created_at) = OffsetDateTime::parse(secret_ref.created_at(), &Rfc3339) else {
        return false;
    };
    if now < created_at {
        return false;
    }
    match secret_ref.disabled_at() {
        Some(disabled_at) => {
            OffsetDateTime::parse(disabled_at, &Rfc3339).is_ok_and(|disabled_at| now < disabled_at)
        }
        None => true,
    }
}

fn authority_allows(
    authority: &SecretBrokerAuthorityContext<'_>,
    binding: &SecretLeaseUseBinding,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> bool {
    let request = CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject: binding.principal_id().clone(),
        operation: secret_driver_invoke_operation(binding.driver_operation()),
        scope: CapabilityScope {
            tenant_ids: Some(vec![binding.tenant_id().clone()]),
            workload_ids: Some(vec![binding.workload_id().clone()]),
            driver_operations: Some(vec![binding.driver_operation().clone()]),
            audiences: Some(vec![binding.audience_id().to_string()]),
            time: AuthorityTimeScope {
                not_before: Some(now),
                expires_at: Some(expires_at),
            },
            ..CapabilityScope::default()
        },
        requested_at: now,
        metadata: Default::default(),
    };
    let decision = evaluate_cached_capability_request(
        authority.cache,
        authority.revocations,
        authority.policy,
        &request,
        now,
    );
    decision.status == AuthorityDecisionStatus::Allowed
}

#[allow(clippy::too_many_arguments)]
fn evidence(
    event_id: SecretAccessEventId,
    kind: SecretAccessEvidenceKind,
    outcome: SecretAccessEvidenceOutcome,
    binding: SecretLeaseUseBinding,
    lease_id: Option<SecretLeaseId>,
    handle_id: Option<SecretDeliveryHandleId>,
    claim_id: Option<SecretUseClaimId>,
    uses_claimed: u64,
    max_uses: u64,
    revocation_generation: u64,
    denial_code: Option<SecretAccessDenialCode>,
    now: OffsetDateTime,
) -> Result<SecretAccessEvidence, SecretBrokerError> {
    SecretAccessEvidence::try_new(
        event_id,
        kind,
        outcome,
        binding,
        lease_id,
        handle_id,
        claim_id,
        uses_claimed,
        max_uses,
        revocation_generation,
        denial_code,
        canonical_timestamp(now)?,
    )
    .map_err(|_| SecretBrokerError::StateUnavailable)
}

fn snapshot(record: &LeaseRecord) -> Result<SecretLeaseSnapshot, SecretBrokerError> {
    SecretLeaseSnapshot::try_new(
        record.secret_lease_id.clone(),
        record.request.secret_lease_request_id().clone(),
        record.delivery_handle_id.clone(),
        record.request.use_binding().clone(),
        record.selected_delivery_method,
        record.status,
        canonical_timestamp(record.starts_at)?,
        canonical_timestamp(record.expires_at)?,
        canonical_timestamp(record.continuous_lifetime_started_at)?,
        canonical_timestamp(record.max_continuous_expires_at)?,
        record.max_uses,
        record.uses_claimed,
        record.revocation_generation,
        canonical_timestamp(record.issued_at)?,
        record.renewed_from_lease_id.clone(),
        record.last_event_id.clone(),
    )
    .map_err(|_| SecretBrokerError::StateUnavailable)
}

fn parse_canonical(value: &CanonicalTimestampV1) -> Result<OffsetDateTime, SecretBrokerError> {
    OffsetDateTime::parse(value.as_str(), &Rfc3339).map_err(|_| SecretBrokerError::StateUnavailable)
}

fn canonical_timestamp(value: OffsetDateTime) -> Result<CanonicalTimestampV1, SecretBrokerError> {
    let value = value.to_offset(time::UtcOffset::UTC);
    if value.nanosecond() % 1_000 != 0 {
        return Err(SecretBrokerError::ClockUnavailable);
    }
    let text = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
        value.microsecond(),
    );
    CanonicalTimestampV1::try_new(text).map_err(|_| SecretBrokerError::ClockUnavailable)
}

#[cfg(test)]
#[path = "../tests/unit/secret_broker_tests.rs"]
mod tests;
