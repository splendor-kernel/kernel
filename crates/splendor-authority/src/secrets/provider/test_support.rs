//! Default-off helpers for exercising the private-construction provider port.
//!
//! These helpers exist only so provider adapters can run conformance tests with
//! legitimate Authority-owned requests. They never return request objects or
//! secret bytes and are not enabled by any production package.

use super::*;

/// Complete, structurally valid coordinates for one test-only provider call.
///
/// Construction does not grant authority. The value can only be consumed by
/// the safe exercise functions in this module, which construct and drop the
/// private request inside Authority.
#[doc(hidden)]
pub struct SecretProviderTestInvocation {
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

impl SecretProviderTestInvocation {
    /// Creates one valid test invocation without exposing either private
    /// provider request type.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
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
    ) -> Result<Self, SecretProviderError> {
        if tenant_id.is_nil() || !(1..=MAX_SAFE_INTEGER).contains(&secret_ref_revision) {
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
            secret_lease_id,
            delivery_handle_id,
            secret_use_claim_id,
            secret_use_attempt_id,
            requested_at,
        })
    }

    fn fetch_request(&self) -> SecretProviderFetchRequest {
        SecretProviderFetchRequest {
            provider_audit_id: self.provider_audit_id.clone(),
            secret_provider_id: self.secret_provider_id.clone(),
            tenant_id: self.tenant_id.clone(),
            secret_ref_id: self.secret_ref_id.clone(),
            secret_ref_revision: self.secret_ref_revision,
            provider_version_ref: self.provider_version_ref.clone(),
            secret_lease_id: self.secret_lease_id.clone(),
            delivery_handle_id: self.delivery_handle_id.clone(),
            secret_use_claim_id: self.secret_use_claim_id.clone(),
            secret_use_attempt_id: self.secret_use_attempt_id.clone(),
            requested_at: self.requested_at.clone(),
        }
    }

    fn control_request(&self) -> SecretProviderControlRequest {
        SecretProviderControlRequest {
            provider_audit_id: self.provider_audit_id.clone(),
            secret_provider_id: self.secret_provider_id.clone(),
            tenant_id: self.tenant_id.clone(),
            secret_ref_id: self.secret_ref_id.clone(),
            secret_ref_revision: self.secret_ref_revision,
            provider_version_ref: self.provider_version_ref.clone(),
            secret_lease_id: Some(self.secret_lease_id.clone()),
            requested_at: self.requested_at.clone(),
        }
    }
}

impl fmt::Debug for SecretProviderTestInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretProviderTestInvocation(<redacted>)")
    }
}

/// Safe observation from one test-only fetch. Material remains inaccessible.
#[doc(hidden)]
pub struct SecretProviderTestFetchObservation {
    material_len: usize,
    audit: SecretProviderAuditEvidence,
}

impl SecretProviderTestFetchObservation {
    pub fn material_len(&self) -> usize {
        self.material_len
    }

    pub fn audit(&self) -> &SecretProviderAuditEvidence {
        &self.audit
    }
}

impl fmt::Debug for SecretProviderTestFetchObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretProviderTestFetchObservation(<redacted>)")
    }
}

/// Safe evidence returned by one test-only provider control call.
#[doc(hidden)]
pub enum SecretProviderTestControlObservation {
    Audit(SecretProviderAuditEvidence),
    Health(SecretProviderHealthEvidence),
}

impl fmt::Debug for SecretProviderTestControlObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretProviderTestControlObservation(<redacted>)")
    }
}

/// Exercises `fetch` through the real object-safe provider port and returns no
/// material bytes or request object.
#[doc(hidden)]
pub fn exercise_secret_provider_fetch(
    provider: &dyn SecretProvider,
    invocation: &SecretProviderTestInvocation,
) -> Result<SecretProviderTestFetchObservation, SecretProviderError> {
    let request = invocation.fetch_request();
    let result = provider.fetch(&request)?;
    Ok(SecretProviderTestFetchObservation {
        material_len: result.material_len(),
        audit: result.audit().clone(),
    })
}

/// Exercises one non-fetch operation through the real object-safe provider
/// port. `Fetch` is rejected because callers must use the byte-withholding
/// fetch helper above.
#[doc(hidden)]
pub fn exercise_secret_provider_control(
    provider: &dyn SecretProvider,
    invocation: &SecretProviderTestInvocation,
    operation: SecretProviderOperation,
) -> Result<SecretProviderTestControlObservation, SecretProviderError> {
    let request = invocation.control_request();
    match operation {
        SecretProviderOperation::Fetch => Err(SecretProviderError::new(
            SecretProviderErrorCode::IntegrityFailure,
        )),
        SecretProviderOperation::Renew => provider
            .renew(&request)
            .map(SecretProviderTestControlObservation::Audit),
        SecretProviderOperation::Revoke => provider
            .revoke(&request)
            .map(SecretProviderTestControlObservation::Audit),
        SecretProviderOperation::Audit => provider
            .audit(&request)
            .map(SecretProviderTestControlObservation::Audit),
        SecretProviderOperation::ActiveProbe => provider
            .health(&request)
            .map(SecretProviderTestControlObservation::Health),
    }
}
