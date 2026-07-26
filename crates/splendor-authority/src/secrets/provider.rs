//! Secret-provider port and request-bound, session-local material results.

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use splendor_types::{
    CanonicalTimestampV1, ContentHash, EffectCertainty, SecretDeliveryHandleId, SecretLeaseId,
    SecretProviderAuditId, SecretProviderId, SecretProviderVersionRef, SecretRefId,
    SecretUseAttemptId, SecretUseClaimId, TenantId,
};
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use zeroize::Zeroizing;

#[cfg(feature = "secret-provider-test-support")]
#[doc(hidden)]
#[path = "provider/test_support.rs"]
pub mod test_support;

const MAX_SECRET_MATERIAL_BYTES: usize = 65_536;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub const SECRET_PROVIDER_AUDIT_EVIDENCE_SCHEMA_LOCAL_V1: &str =
    "splendor.secret.provider_audit_evidence.local.v1";
pub const SECRET_PROVIDER_HEALTH_EVIDENCE_SCHEMA_LOCAL_V1: &str =
    "splendor.secret.provider_health_evidence.local.v1";

/// Session-borrowed material owned only by one provider result.
///
/// `Rc` makes this value deliberately `!Send` and `!Sync`; the request borrow
/// prevents it from outliving the exact provider request. It is never exported
/// as a standalone public capability.
struct SecretMaterial<'session> {
    bytes: Zeroizing<Vec<u8>>,
    _request: PhantomData<&'session SecretProviderFetchRequest>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl<'session> SecretMaterial<'session> {
    fn try_for_request(
        _request: &'session SecretProviderFetchRequest,
        bytes: Vec<u8>,
    ) -> Result<Self, SecretProviderError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > MAX_SECRET_MATERIAL_BYTES {
            return Err(SecretProviderError::new(
                SecretProviderErrorCode::IntegrityFailure,
            ));
        }
        Ok(Self {
            bytes,
            _request: PhantomData,
            _not_send_sync: PhantomData,
        })
    }
}

impl fmt::Debug for SecretMaterial<'_> {
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
#[derive(Clone, Eq, PartialEq)]
pub struct SecretProviderAuditEvidence {
    provider_audit_id: SecretProviderAuditId,
    secret_provider_id: SecretProviderId,
    tenant_id: TenantId,
    secret_ref_id: SecretRefId,
    secret_ref_revision: u64,
    provider_version_ref: SecretProviderVersionRef,
    request_binding_digest: ContentHash,
    operation: SecretProviderOperation,
    outcome: SecretProviderOutcome,
    effect_certainty: EffectCertainty,
    observed_at: CanonicalTimestampV1,
}

impl fmt::Debug for SecretProviderAuditEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretProviderAuditEvidence(<redacted>)")
    }
}

impl SecretProviderAuditEvidence {
    #[allow(clippy::too_many_arguments)]
    fn try_new(
        provider_audit_id: SecretProviderAuditId,
        secret_provider_id: SecretProviderId,
        tenant_id: TenantId,
        secret_ref_id: SecretRefId,
        secret_ref_revision: u64,
        provider_version_ref: SecretProviderVersionRef,
        request_binding_digest: ContentHash,
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
            request_binding_digest,
            operation,
            outcome,
            effect_certainty,
            observed_at,
        })
    }

    /// Builds fetch audit evidence from the exact opaque request coordinates.
    pub fn for_fetch_request(
        request: &SecretProviderFetchRequest,
        outcome: SecretProviderOutcome,
        effect_certainty: EffectCertainty,
        observed_at: CanonicalTimestampV1,
    ) -> Result<Self, SecretProviderError> {
        Self::try_new(
            request.provider_audit_id.clone(),
            request.secret_provider_id.clone(),
            request.tenant_id.clone(),
            request.secret_ref_id.clone(),
            request.secret_ref_revision,
            request.provider_version_ref.clone(),
            fetch_request_binding_digest(request)?,
            SecretProviderOperation::Fetch,
            outcome,
            effect_certainty,
            observed_at,
        )
    }

    /// Builds non-material control evidence from one exact control request.
    pub fn for_control_request(
        request: &SecretProviderControlRequest,
        operation: SecretProviderOperation,
        outcome: SecretProviderOutcome,
        effect_certainty: EffectCertainty,
        observed_at: CanonicalTimestampV1,
    ) -> Result<Self, SecretProviderError> {
        if matches!(operation, SecretProviderOperation::Fetch) {
            return Err(SecretProviderError::new(
                SecretProviderErrorCode::IntegrityFailure,
            ));
        }
        Self::try_new(
            request.provider_audit_id.clone(),
            request.secret_provider_id.clone(),
            request.tenant_id.clone(),
            request.secret_ref_id.clone(),
            request.secret_ref_revision,
            request.provider_version_ref.clone(),
            control_request_binding_digest(request, operation)?,
            operation,
            outcome,
            effect_certainty,
            observed_at,
        )
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

    pub fn request_binding_digest(&self) -> &ContentHash {
        &self.request_binding_digest
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
        let mut state = serializer.serialize_struct("SecretProviderAuditEvidence", 12)?;
        state.serialize_field("effect_certainty", &self.effect_certainty)?;
        state.serialize_field("observed_at", &self.observed_at)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("outcome", &self.outcome)?;
        state.serialize_field("provider_audit_id", &self.provider_audit_id)?;
        state.serialize_field("provider_version_ref", &self.provider_version_ref)?;
        state.serialize_field("request_binding_digest", &self.request_binding_digest)?;
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
    pub(super) provider_audit_id: SecretProviderAuditId,
    pub(super) secret_provider_id: SecretProviderId,
    pub(super) tenant_id: TenantId,
    pub(super) secret_ref_id: SecretRefId,
    pub(super) secret_ref_revision: u64,
    pub(super) provider_version_ref: SecretProviderVersionRef,
    pub(super) secret_lease_id: SecretLeaseId,
    pub(super) delivery_handle_id: SecretDeliveryHandleId,
    pub(super) secret_use_claim_id: SecretUseClaimId,
    pub(super) secret_use_attempt_id: SecretUseAttemptId,
    pub(super) requested_at: CanonicalTimestampV1,
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
    pub(super) provider_audit_id: SecretProviderAuditId,
    pub(super) secret_provider_id: SecretProviderId,
    pub(super) tenant_id: TenantId,
    pub(super) secret_ref_id: SecretRefId,
    pub(super) secret_ref_revision: u64,
    pub(super) provider_version_ref: SecretProviderVersionRef,
    pub(super) secret_lease_id: Option<SecretLeaseId>,
    pub(super) requested_at: CanonicalTimestampV1,
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

#[derive(Serialize)]
struct FetchRequestDigestMaterial<'a> {
    provider_audit_id: &'a SecretProviderAuditId,
    secret_provider_id: &'a SecretProviderId,
    tenant_id: &'a TenantId,
    secret_ref_id: &'a SecretRefId,
    secret_ref_revision: u64,
    provider_version_ref: &'a SecretProviderVersionRef,
    secret_lease_id: &'a SecretLeaseId,
    delivery_handle_id: &'a SecretDeliveryHandleId,
    secret_use_claim_id: &'a SecretUseClaimId,
    secret_use_attempt_id: &'a SecretUseAttemptId,
    requested_at: &'a CanonicalTimestampV1,
}

#[derive(Serialize)]
struct ControlRequestDigestMaterial<'a> {
    provider_audit_id: &'a SecretProviderAuditId,
    secret_provider_id: &'a SecretProviderId,
    tenant_id: &'a TenantId,
    secret_ref_id: &'a SecretRefId,
    secret_ref_revision: u64,
    provider_version_ref: &'a SecretProviderVersionRef,
    secret_lease_id: Option<&'a SecretLeaseId>,
    operation: SecretProviderOperation,
    requested_at: &'a CanonicalTimestampV1,
}

fn fetch_request_binding_digest(
    request: &SecretProviderFetchRequest,
) -> Result<ContentHash, SecretProviderError> {
    let material = FetchRequestDigestMaterial {
        provider_audit_id: &request.provider_audit_id,
        secret_provider_id: &request.secret_provider_id,
        tenant_id: &request.tenant_id,
        secret_ref_id: &request.secret_ref_id,
        secret_ref_revision: request.secret_ref_revision,
        provider_version_ref: &request.provider_version_ref,
        secret_lease_id: &request.secret_lease_id,
        delivery_handle_id: &request.delivery_handle_id,
        secret_use_claim_id: &request.secret_use_claim_id,
        secret_use_attempt_id: &request.secret_use_attempt_id,
        requested_at: &request.requested_at,
    };
    serde_json::to_vec(&material)
        .map(ContentHash::blake3)
        .map_err(|_| SecretProviderError::new(SecretProviderErrorCode::IntegrityFailure))
}

fn control_request_binding_digest(
    request: &SecretProviderControlRequest,
    operation: SecretProviderOperation,
) -> Result<ContentHash, SecretProviderError> {
    let material = ControlRequestDigestMaterial {
        provider_audit_id: &request.provider_audit_id,
        secret_provider_id: &request.secret_provider_id,
        tenant_id: &request.tenant_id,
        secret_ref_id: &request.secret_ref_id,
        secret_ref_revision: request.secret_ref_revision,
        provider_version_ref: &request.provider_version_ref,
        secret_lease_id: request.secret_lease_id.as_ref(),
        operation,
        requested_at: &request.requested_at,
    };
    serde_json::to_vec(&material)
        .map(ContentHash::blake3)
        .map_err(|_| SecretProviderError::new(SecretProviderErrorCode::IntegrityFailure))
}

/// One request-borrowed, non-cloneable provider fetch result. It is not
/// serializable, `Send`, or `Sync`, and exposes no material escape hatch in this
/// pre-Gateway slice.
///
/// ```compile_fail
/// use splendor_authority::ProcessLocalSecretProviderFetchResult;
/// fn require_send<T: Send>() {}
/// require_send::<ProcessLocalSecretProviderFetchResult<'static>>();
/// ```
///
/// ```compile_fail
/// use splendor_authority::ProcessLocalSecretProviderFetchResult;
/// fn require_sync<T: Sync>() {}
/// require_sync::<ProcessLocalSecretProviderFetchResult<'static>>();
/// ```
pub struct SecretProviderFetchResult<'session> {
    material: SecretMaterial<'session>,
    audit: SecretProviderAuditEvidence,
}

impl<'session> SecretProviderFetchResult<'session> {
    /// Constructs one result bound to the exact request and audit digest. Input
    /// bytes enter zeroizing storage before any validation can reject them.
    pub fn try_new(
        request: &'session SecretProviderFetchRequest,
        material: Vec<u8>,
        audit: SecretProviderAuditEvidence,
    ) -> Result<Self, SecretProviderError> {
        let material = SecretMaterial::try_for_request(request, material)?;
        if audit.operation() != SecretProviderOperation::Fetch
            || audit.outcome() != SecretProviderOutcome::Succeeded
            || audit.effect_certainty() != EffectCertainty::Known
            || audit.request_binding_digest() != &fetch_request_binding_digest(request)?
        {
            return Err(SecretProviderError::new(
                SecretProviderErrorCode::IntegrityFailure,
            ));
        }
        Ok(Self { material, audit })
    }

    /// Returns only the bounded length; material exposure remains unavailable
    /// until a future sealed Gateway session owns that operation.
    pub fn material_len(&self) -> usize {
        self.material.bytes.len()
    }

    pub fn audit(&self) -> &SecretProviderAuditEvidence {
        &self.audit
    }
}

impl fmt::Debug for SecretProviderFetchResult<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretProviderFetchResult(<redacted>)")
    }
}

/// Safe passive health projection for one configured provider.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretProviderHealthEvidence {
    secret_provider_id: SecretProviderId,
    available: bool,
    observed_at: CanonicalTimestampV1,
}

impl fmt::Debug for SecretProviderHealthEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretProviderHealthEvidence(<redacted>)")
    }
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
/// and the broker lifecycle never calls these methods.
pub trait SecretProvider: Send + Sync {
    fn provider_id(&self) -> &SecretProviderId;
    fn fetch<'session>(
        &self,
        request: &'session SecretProviderFetchRequest,
    ) -> Result<SecretProviderFetchResult<'session>, SecretProviderError>;
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

#[cfg(test)]
mod tests;
