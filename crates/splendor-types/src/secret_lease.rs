//! Behavior-free C03 lease, binding, snapshot, and access-evidence contracts.
//!
//! These values contain only identities, exact scope coordinates, policy
//! metadata, counters, and canonical timestamps. They never contain secret
//! material, provider locators, provider responses, bearer values, or a
//! resolver capability. Possessing or constructing one never grants authority.

use crate::driver::is_driver_destination_schema_v1;
use crate::{
    validate_driver_operation_ref_v1, CanonicalTimestampV1, DriverCredentialDestinationDigest,
    DriverOperationRef, DriverTrustedSendProfileV1, InstanceId, NodeId, PrincipalId,
    SecretAccessEventId, SecretAudienceId, SecretCredentialSlotId, SecretDeliveryExposureProfile,
    SecretDeliveryHandleId, SecretDeliveryMethod, SecretLeaseId, SecretLeaseRequestId,
    SecretProviderId, SecretProviderVersionRef, SecretPurpose, SecretRefId, SecretRenewalCommandId,
    SecretRevocationCommandId, SecretUseAttemptId, SecretUseClaimId, SecretUseIntent,
    SecretUseRequirement, TenantId, WorkloadId,
};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::error::Error;
use std::fmt;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Exact schema for one scoped lease-use binding.
pub const SECRET_LEASE_USE_BINDING_SCHEMA_V1: &str = "splendor.secret.lease_use_binding.local.v1";
/// Exact schema for one scoped process-local lease request.
pub const SECRET_LEASE_REQUEST_SCHEMA_V1: &str = "splendor.secret.lease_request.local.v1";
/// Exact schema for one safe process-local lease snapshot.
pub const SECRET_LEASE_SNAPSHOT_SCHEMA_V1: &str = "splendor.secret.lease_snapshot.local.v1";
/// Exact schema for one safe process-local broker access-evidence event.
pub const SECRET_ACCESS_EVIDENCE_SCHEMA_V1: &str = "splendor.secret.access_evidence.local.v1";

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Complete immutable scope to which a lease and opaque handle are bound.
///
/// This value is safe to persist, but it is not authority and cannot resolve a
/// secret. Fields are private so invalid or partially bound values cannot be
/// assembled with a struct literal.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretLeaseUseBinding {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    workload_id: WorkloadId,
    driver_operation: DriverOperationRef,
    driver_declaration_revision: u64,
    credential_slot_id: SecretCredentialSlotId,
    destination_schema: String,
    destination_digest: DriverCredentialDestinationDigest,
    delivery_exposure_profile: SecretDeliveryExposureProfile,
    trusted_send_profile: DriverTrustedSendProfileV1,
    node_id: NodeId,
    instance_id: InstanceId,
    audience_id: SecretAudienceId,
    secret_ref_id: SecretRefId,
    secret_ref_revision: u64,
    secret_provider_id: SecretProviderId,
    provider_version_ref: SecretProviderVersionRef,
    intent: SecretUseIntent,
    purpose: SecretPurpose,
}

impl SecretLeaseUseBinding {
    /// Constructs a complete exact binding after validating every permissive
    /// foreign ID and positive revision.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        workload_id: WorkloadId,
        driver_operation: DriverOperationRef,
        driver_declaration_revision: u64,
        credential_slot_id: SecretCredentialSlotId,
        destination_schema: impl Into<String>,
        destination_digest: DriverCredentialDestinationDigest,
        delivery_exposure_profile: SecretDeliveryExposureProfile,
        trusted_send_profile: DriverTrustedSendProfileV1,
        node_id: NodeId,
        instance_id: InstanceId,
        audience_id: SecretAudienceId,
        secret_ref_id: SecretRefId,
        secret_ref_revision: u64,
        secret_provider_id: SecretProviderId,
        provider_version_ref: SecretProviderVersionRef,
        intent: SecretUseIntent,
        purpose: SecretPurpose,
    ) -> Result<Self, SecretLeaseContractError> {
        if tenant_id.is_nil() {
            return Err(SecretLeaseContractError::InvalidTenantId);
        }
        if principal_id.is_nil() {
            return Err(SecretLeaseContractError::InvalidPrincipalId);
        }
        if workload_id.is_nil() {
            return Err(SecretLeaseContractError::InvalidWorkloadId);
        }
        if node_id.is_nil() {
            return Err(SecretLeaseContractError::InvalidNodeId);
        }
        if instance_id.is_nil() {
            return Err(SecretLeaseContractError::InvalidInstanceId);
        }
        validate_driver_operation_ref_v1(&driver_operation)
            .map_err(|_| SecretLeaseContractError::InvalidDriverOperation)?;
        if !(1..=MAX_SAFE_INTEGER).contains(&driver_declaration_revision) {
            return Err(SecretLeaseContractError::InvalidDriverDeclarationRevision);
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&secret_ref_revision) {
            return Err(SecretLeaseContractError::InvalidSecretRefRevision);
        }
        let destination_schema = destination_schema.into();
        if !is_driver_destination_schema_v1(&destination_schema) {
            return Err(SecretLeaseContractError::InvalidDestinationSchema);
        }
        if !trusted_send_profile.matches_exposure(delivery_exposure_profile) {
            return Err(SecretLeaseContractError::InvalidTrustedSendProfile);
        }
        Ok(Self {
            tenant_id,
            principal_id,
            workload_id,
            driver_operation,
            driver_declaration_revision,
            credential_slot_id,
            destination_schema,
            destination_digest,
            delivery_exposure_profile,
            trusted_send_profile,
            node_id,
            instance_id,
            audience_id,
            secret_ref_id,
            secret_ref_revision,
            secret_provider_id,
            provider_version_ref,
            intent,
            purpose,
        })
    }

    pub const fn schema_version(&self) -> &'static str {
        SECRET_LEASE_USE_BINDING_SCHEMA_V1
    }

    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    pub const fn workload_id(&self) -> &WorkloadId {
        &self.workload_id
    }

    pub const fn driver_operation(&self) -> &DriverOperationRef {
        &self.driver_operation
    }

    pub const fn driver_declaration_revision(&self) -> u64 {
        self.driver_declaration_revision
    }

    pub const fn credential_slot_id(&self) -> SecretCredentialSlotId {
        self.credential_slot_id
    }

    pub fn destination_schema(&self) -> &str {
        &self.destination_schema
    }

    pub const fn destination_digest(&self) -> DriverCredentialDestinationDigest {
        self.destination_digest
    }

    pub const fn delivery_exposure_profile(&self) -> SecretDeliveryExposureProfile {
        self.delivery_exposure_profile
    }

    pub const fn trusted_send_profile(&self) -> &DriverTrustedSendProfileV1 {
        &self.trusted_send_profile
    }

    pub const fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    pub const fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    pub const fn audience_id(&self) -> &SecretAudienceId {
        &self.audience_id
    }

    pub const fn secret_ref_id(&self) -> &SecretRefId {
        &self.secret_ref_id
    }

    pub const fn secret_ref_revision(&self) -> u64 {
        self.secret_ref_revision
    }

    pub const fn secret_provider_id(&self) -> &SecretProviderId {
        &self.secret_provider_id
    }

    pub const fn provider_version_ref(&self) -> &SecretProviderVersionRef {
        &self.provider_version_ref
    }

    pub const fn intent(&self) -> SecretUseIntent {
        self.intent
    }

    pub const fn purpose(&self) -> SecretPurpose {
        self.purpose
    }
}

impl fmt::Debug for SecretLeaseUseBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret_lease_use_binding")
    }
}

impl Serialize for SecretLeaseUseBinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretLeaseUseBinding", 20)?;
        state.serialize_field("audience_id", &self.audience_id)?;
        state.serialize_field("credential_slot_id", &self.credential_slot_id)?;
        state.serialize_field("delivery_exposure_profile", &self.delivery_exposure_profile)?;
        state.serialize_field("destination_digest", &self.destination_digest)?;
        state.serialize_field("destination_schema", &self.destination_schema)?;
        state.serialize_field(
            "driver_declaration_revision",
            &self.driver_declaration_revision,
        )?;
        state.serialize_field("driver_operation", &self.driver_operation)?;
        state.serialize_field("instance_id", &self.instance_id)?;
        state.serialize_field("intent", &self.intent)?;
        state.serialize_field("node_id", &self.node_id)?;
        state.serialize_field("principal_id", &self.principal_id)?;
        state.serialize_field("provider_version_ref", &self.provider_version_ref)?;
        state.serialize_field("purpose", &self.purpose)?;
        state.serialize_field("schema_version", SECRET_LEASE_USE_BINDING_SCHEMA_V1)?;
        state.serialize_field("secret_ref_id", &self.secret_ref_id)?;
        state.serialize_field("secret_ref_revision", &self.secret_ref_revision)?;
        state.serialize_field("secret_provider_id", &self.secret_provider_id)?;
        state.serialize_field("tenant_id", &self.tenant_id)?;
        state.serialize_field("trusted_send_profile", &self.trusted_send_profile)?;
        state.serialize_field("workload_id", &self.workload_id)?;
        state.end()
    }
}

/// Checked, non-authorizing request for one process-local lease.
///
/// The bound requirement is retained verbatim so delivery preference order is
/// explicit. It must agree exactly with the immutable use binding.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretLeaseRequest {
    secret_lease_request_id: SecretLeaseRequestId,
    use_binding: SecretLeaseUseBinding,
    bound_use_requirement: SecretUseRequirement,
    starts_at: CanonicalTimestampV1,
    expires_at: CanonicalTimestampV1,
    requested_at: CanonicalTimestampV1,
}

impl SecretLeaseRequest {
    /// Constructs one checked request. The request window may narrow, but never
    /// exceed, the duration declared by `bound_use_requirement`.
    pub fn try_new(
        secret_lease_request_id: SecretLeaseRequestId,
        use_binding: SecretLeaseUseBinding,
        bound_use_requirement: SecretUseRequirement,
        starts_at: CanonicalTimestampV1,
        expires_at: CanonicalTimestampV1,
        requested_at: CanonicalTimestampV1,
    ) -> Result<Self, SecretLeaseContractError> {
        if use_binding.secret_ref_id() != bound_use_requirement.secret_ref_id()
            || use_binding.credential_slot_id() != bound_use_requirement.credential_slot_id()
            || use_binding.intent() != bound_use_requirement.intent()
            || use_binding.purpose() != bound_use_requirement.purpose()
        {
            return Err(SecretLeaseContractError::RequirementBindingMismatch);
        }
        let starts = parse_timestamp(&starts_at)?;
        let expires = parse_timestamp(&expires_at)?;
        let requested = parse_timestamp(&requested_at)?;
        if requested > starts || starts >= expires {
            return Err(SecretLeaseContractError::InvalidTimeWindow);
        }
        let duration = expires - starts;
        let maximum_nanos = i128::from(bound_use_requirement.requested_duration_seconds())
            .checked_mul(1_000_000_000)
            .ok_or(SecretLeaseContractError::RequestedDurationExceeded)?;
        if duration.whole_nanoseconds() <= 0 || duration.whole_nanoseconds() > maximum_nanos {
            return Err(SecretLeaseContractError::RequestedDurationExceeded);
        }
        Ok(Self {
            secret_lease_request_id,
            use_binding,
            bound_use_requirement,
            starts_at,
            expires_at,
            requested_at,
        })
    }

    pub const fn schema_version(&self) -> &'static str {
        SECRET_LEASE_REQUEST_SCHEMA_V1
    }

    pub const fn secret_lease_request_id(&self) -> &SecretLeaseRequestId {
        &self.secret_lease_request_id
    }

    pub const fn use_binding(&self) -> &SecretLeaseUseBinding {
        &self.use_binding
    }

    pub const fn bound_use_requirement(&self) -> &SecretUseRequirement {
        &self.bound_use_requirement
    }

    pub const fn starts_at(&self) -> &CanonicalTimestampV1 {
        &self.starts_at
    }

    pub const fn expires_at(&self) -> &CanonicalTimestampV1 {
        &self.expires_at
    }

    pub const fn requested_at(&self) -> &CanonicalTimestampV1 {
        &self.requested_at
    }
}

impl fmt::Debug for SecretLeaseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret_lease_request")
    }
}

impl Serialize for SecretLeaseRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretLeaseRequest", 7)?;
        state.serialize_field("bound_use_requirement", &self.bound_use_requirement)?;
        state.serialize_field("expires_at", &self.expires_at)?;
        state.serialize_field("requested_at", &self.requested_at)?;
        state.serialize_field("schema_version", SECRET_LEASE_REQUEST_SCHEMA_V1)?;
        state.serialize_field("secret_lease_request_id", &self.secret_lease_request_id)?;
        state.serialize_field("starts_at", &self.starts_at)?;
        state.serialize_field("use_binding", &self.use_binding)?;
        state.end()
    }
}

/// Safe state of one process-local lease lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretLeaseStatus {
    /// Lease admits current claims inside its active window.
    Active,
    /// The maximum use count was consumed.
    Exhausted,
    /// A renewal replaced this lease and invalidated its handle.
    Superseded,
    /// Local use is denied and terminal revocation evidence is still pending.
    RevocationPending,
    /// Local revocation closed admission for new claims.
    Revoked,
    /// Trusted time reached the exact expiry boundary.
    Expired,
}

/// Serializable ref-only snapshot of one lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretLeaseSnapshot {
    secret_lease_id: SecretLeaseId,
    secret_lease_request_id: SecretLeaseRequestId,
    delivery_handle_id: SecretDeliveryHandleId,
    use_binding: SecretLeaseUseBinding,
    selected_delivery_method: SecretDeliveryMethod,
    status: SecretLeaseStatus,
    starts_at: CanonicalTimestampV1,
    expires_at: CanonicalTimestampV1,
    continuous_lifetime_started_at: CanonicalTimestampV1,
    max_continuous_expires_at: CanonicalTimestampV1,
    max_uses: u64,
    uses_claimed: u64,
    revocation_generation: u64,
    issued_at: CanonicalTimestampV1,
    renewed_from_lease_id: Option<SecretLeaseId>,
    last_event_id: SecretAccessEventId,
}

impl SecretLeaseSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        secret_lease_id: SecretLeaseId,
        secret_lease_request_id: SecretLeaseRequestId,
        delivery_handle_id: SecretDeliveryHandleId,
        use_binding: SecretLeaseUseBinding,
        selected_delivery_method: SecretDeliveryMethod,
        status: SecretLeaseStatus,
        starts_at: CanonicalTimestampV1,
        expires_at: CanonicalTimestampV1,
        continuous_lifetime_started_at: CanonicalTimestampV1,
        max_continuous_expires_at: CanonicalTimestampV1,
        max_uses: u64,
        uses_claimed: u64,
        revocation_generation: u64,
        issued_at: CanonicalTimestampV1,
        renewed_from_lease_id: Option<SecretLeaseId>,
        last_event_id: SecretAccessEventId,
    ) -> Result<Self, SecretLeaseContractError> {
        let starts = parse_timestamp(&starts_at)?;
        let expires = parse_timestamp(&expires_at)?;
        let chain_start = parse_timestamp(&continuous_lifetime_started_at)?;
        let chain_end = parse_timestamp(&max_continuous_expires_at)?;
        let issued = parse_timestamp(&issued_at)?;
        if starts >= expires || chain_start > starts || expires > chain_end || issued > starts {
            return Err(SecretLeaseContractError::InvalidTimeWindow);
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&max_uses) || uses_claimed > max_uses {
            return Err(SecretLeaseContractError::InvalidUseCounter);
        }
        if (status == SecretLeaseStatus::Active && uses_claimed == max_uses)
            || (status == SecretLeaseStatus::Exhausted && uses_claimed != max_uses)
        {
            return Err(SecretLeaseContractError::InvalidUseCounter);
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&revocation_generation) {
            return Err(SecretLeaseContractError::InvalidRevocationGeneration);
        }
        if renewed_from_lease_id.as_ref() == Some(&secret_lease_id) {
            return Err(SecretLeaseContractError::InvalidRenewalLineage);
        }
        Ok(Self {
            secret_lease_id,
            secret_lease_request_id,
            delivery_handle_id,
            use_binding,
            selected_delivery_method,
            status,
            starts_at,
            expires_at,
            continuous_lifetime_started_at,
            max_continuous_expires_at,
            max_uses,
            uses_claimed,
            revocation_generation,
            issued_at,
            renewed_from_lease_id,
            last_event_id,
        })
    }

    pub const fn schema_version(&self) -> &'static str {
        SECRET_LEASE_SNAPSHOT_SCHEMA_V1
    }

    pub const fn secret_lease_id(&self) -> &SecretLeaseId {
        &self.secret_lease_id
    }

    pub const fn secret_lease_request_id(&self) -> &SecretLeaseRequestId {
        &self.secret_lease_request_id
    }

    pub const fn delivery_handle_id(&self) -> &SecretDeliveryHandleId {
        &self.delivery_handle_id
    }

    pub const fn use_binding(&self) -> &SecretLeaseUseBinding {
        &self.use_binding
    }

    pub const fn selected_delivery_method(&self) -> SecretDeliveryMethod {
        self.selected_delivery_method
    }

    pub const fn status(&self) -> SecretLeaseStatus {
        self.status
    }

    pub const fn starts_at(&self) -> &CanonicalTimestampV1 {
        &self.starts_at
    }

    pub const fn expires_at(&self) -> &CanonicalTimestampV1 {
        &self.expires_at
    }

    pub const fn continuous_lifetime_started_at(&self) -> &CanonicalTimestampV1 {
        &self.continuous_lifetime_started_at
    }

    pub const fn max_continuous_expires_at(&self) -> &CanonicalTimestampV1 {
        &self.max_continuous_expires_at
    }

    pub const fn max_uses(&self) -> u64 {
        self.max_uses
    }

    pub const fn uses_claimed(&self) -> u64 {
        self.uses_claimed
    }

    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    pub const fn issued_at(&self) -> &CanonicalTimestampV1 {
        &self.issued_at
    }

    pub const fn renewed_from_lease_id(&self) -> Option<&SecretLeaseId> {
        self.renewed_from_lease_id.as_ref()
    }

    pub const fn last_event_id(&self) -> &SecretAccessEventId {
        &self.last_event_id
    }
}

impl Serialize for SecretLeaseSnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = 16 + usize::from(self.renewed_from_lease_id.is_some());
        let mut state = serializer.serialize_struct("SecretLeaseSnapshot", field_count)?;
        state.serialize_field(
            "continuous_lifetime_started_at",
            &self.continuous_lifetime_started_at,
        )?;
        state.serialize_field("delivery_handle_id", &self.delivery_handle_id)?;
        state.serialize_field("expires_at", &self.expires_at)?;
        state.serialize_field("issued_at", &self.issued_at)?;
        state.serialize_field("last_event_id", &self.last_event_id)?;
        state.serialize_field("max_continuous_expires_at", &self.max_continuous_expires_at)?;
        state.serialize_field("max_uses", &self.max_uses)?;
        if let Some(renewed_from) = &self.renewed_from_lease_id {
            state.serialize_field("renewed_from_lease_id", renewed_from)?;
        }
        state.serialize_field("revocation_generation", &self.revocation_generation)?;
        state.serialize_field("schema_version", SECRET_LEASE_SNAPSHOT_SCHEMA_V1)?;
        state.serialize_field("secret_lease_id", &self.secret_lease_id)?;
        state.serialize_field("secret_lease_request_id", &self.secret_lease_request_id)?;
        state.serialize_field("selected_delivery_method", &self.selected_delivery_method)?;
        state.serialize_field("starts_at", &self.starts_at)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("use_binding", &self.use_binding)?;
        state.serialize_field("uses_claimed", &self.uses_claimed)?;
        state.end()
    }
}

/// Lifecycle transition represented by process-local ref-only evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretAccessEvidenceKind {
    LeaseIssued,
    LeaseDenied,
    UseClaimed,
    UseDenied,
    LeaseRenewed,
    RenewalDenied,
    LeaseRevoked,
    RevocationDenied,
}

/// Outcome represented by process-local broker evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretAccessEvidenceOutcome {
    Succeeded,
    Denied,
}

/// Closed internal denial classes safe for restricted evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretAccessDenialCode {
    SecretNotAvailable,
    BindingMismatch,
    AuthorityDenied,
    ClockRollback,
    LeaseNotStarted,
    LeaseExpired,
    MaxUsesExceeded,
    RenewalNotAllowed,
    ContinuousLifetimeExceeded,
    RequestAlreadyUsed,
    CommandConflict,
    CapacityExceeded,
}

/// Typed identity of the process-local command represented by one evidence row.
///
/// The variants keep issue, use, renewal, and revocation command identities
/// distinct while allowing one bounded local evidence shape.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum ProcessLocalSecretBrokerCommandId {
    LeaseRequest(SecretLeaseRequestId),
    UseAttempt(SecretUseAttemptId),
    Renewal(SecretRenewalCommandId),
    Revocation(SecretRevocationCommandId),
}

/// Structured, serializable, ref-only evidence emitted at the broker seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretAccessEvidence {
    secret_access_event_id: SecretAccessEventId,
    command_id: ProcessLocalSecretBrokerCommandId,
    kind: SecretAccessEvidenceKind,
    outcome: SecretAccessEvidenceOutcome,
    use_binding: SecretLeaseUseBinding,
    secret_lease_id: Option<SecretLeaseId>,
    delivery_handle_id: Option<SecretDeliveryHandleId>,
    secret_use_claim_id: Option<SecretUseClaimId>,
    uses_claimed: u64,
    max_uses: u64,
    revocation_generation: u64,
    denial_code: Option<SecretAccessDenialCode>,
    occurred_at: CanonicalTimestampV1,
}

impl SecretAccessEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        secret_access_event_id: SecretAccessEventId,
        command_id: ProcessLocalSecretBrokerCommandId,
        kind: SecretAccessEvidenceKind,
        outcome: SecretAccessEvidenceOutcome,
        use_binding: SecretLeaseUseBinding,
        secret_lease_id: Option<SecretLeaseId>,
        delivery_handle_id: Option<SecretDeliveryHandleId>,
        secret_use_claim_id: Option<SecretUseClaimId>,
        uses_claimed: u64,
        max_uses: u64,
        revocation_generation: u64,
        denial_code: Option<SecretAccessDenialCode>,
        occurred_at: CanonicalTimestampV1,
    ) -> Result<Self, SecretLeaseContractError> {
        parse_timestamp(&occurred_at)?;
        if !(1..=MAX_SAFE_INTEGER).contains(&max_uses)
            || uses_claimed > max_uses
            || !(1..=MAX_SAFE_INTEGER).contains(&revocation_generation)
        {
            return Err(SecretLeaseContractError::InvalidUseCounter);
        }
        let command_matches_kind = match &command_id {
            ProcessLocalSecretBrokerCommandId::LeaseRequest(_) => matches!(
                kind,
                SecretAccessEvidenceKind::LeaseIssued | SecretAccessEvidenceKind::LeaseDenied
            ),
            ProcessLocalSecretBrokerCommandId::UseAttempt(_) => matches!(
                kind,
                SecretAccessEvidenceKind::UseClaimed | SecretAccessEvidenceKind::UseDenied
            ),
            ProcessLocalSecretBrokerCommandId::Renewal(_) => matches!(
                kind,
                SecretAccessEvidenceKind::LeaseRenewed | SecretAccessEvidenceKind::RenewalDenied
            ),
            ProcessLocalSecretBrokerCommandId::Revocation(_) => matches!(
                kind,
                SecretAccessEvidenceKind::LeaseRevoked | SecretAccessEvidenceKind::RevocationDenied
            ),
        };
        if !command_matches_kind {
            return Err(SecretLeaseContractError::InvalidEvidenceShape);
        }
        if matches!(outcome, SecretAccessEvidenceOutcome::Denied) != denial_code.is_some() {
            return Err(SecretLeaseContractError::InvalidEvidenceShape);
        }
        let denial_kind = matches!(
            kind,
            SecretAccessEvidenceKind::LeaseDenied
                | SecretAccessEvidenceKind::UseDenied
                | SecretAccessEvidenceKind::RenewalDenied
                | SecretAccessEvidenceKind::RevocationDenied
        );
        if denial_kind != matches!(outcome, SecretAccessEvidenceOutcome::Denied) {
            return Err(SecretLeaseContractError::InvalidEvidenceShape);
        }
        if matches!(kind, SecretAccessEvidenceKind::UseClaimed) != secret_use_claim_id.is_some() {
            return Err(SecretLeaseContractError::InvalidEvidenceShape);
        }
        Ok(Self {
            secret_access_event_id,
            command_id,
            kind,
            outcome,
            use_binding,
            secret_lease_id,
            delivery_handle_id,
            secret_use_claim_id,
            uses_claimed,
            max_uses,
            revocation_generation,
            denial_code,
            occurred_at,
        })
    }

    pub const fn schema_version(&self) -> &'static str {
        SECRET_ACCESS_EVIDENCE_SCHEMA_V1
    }

    pub const fn secret_access_event_id(&self) -> &SecretAccessEventId {
        &self.secret_access_event_id
    }

    pub const fn command_id(&self) -> &ProcessLocalSecretBrokerCommandId {
        &self.command_id
    }

    pub const fn kind(&self) -> SecretAccessEvidenceKind {
        self.kind
    }

    pub const fn outcome(&self) -> SecretAccessEvidenceOutcome {
        self.outcome
    }

    pub const fn use_binding(&self) -> &SecretLeaseUseBinding {
        &self.use_binding
    }

    pub const fn secret_lease_id(&self) -> Option<&SecretLeaseId> {
        self.secret_lease_id.as_ref()
    }

    pub const fn delivery_handle_id(&self) -> Option<&SecretDeliveryHandleId> {
        self.delivery_handle_id.as_ref()
    }

    pub const fn secret_use_claim_id(&self) -> Option<&SecretUseClaimId> {
        self.secret_use_claim_id.as_ref()
    }

    pub const fn uses_claimed(&self) -> u64 {
        self.uses_claimed
    }

    pub const fn max_uses(&self) -> u64 {
        self.max_uses
    }

    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    pub const fn denial_code(&self) -> Option<SecretAccessDenialCode> {
        self.denial_code
    }

    pub const fn occurred_at(&self) -> &CanonicalTimestampV1 {
        &self.occurred_at
    }
}

impl Serialize for SecretAccessEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = 10
            + usize::from(self.delivery_handle_id.is_some())
            + usize::from(self.denial_code.is_some())
            + usize::from(self.secret_lease_id.is_some())
            + usize::from(self.secret_use_claim_id.is_some());
        let mut state = serializer.serialize_struct("SecretAccessEvidence", field_count)?;
        state.serialize_field("command_id", &self.command_id)?;
        if let Some(handle_id) = &self.delivery_handle_id {
            state.serialize_field("delivery_handle_id", handle_id)?;
        }
        if let Some(denial_code) = &self.denial_code {
            state.serialize_field("denial_code", denial_code)?;
        }
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("max_uses", &self.max_uses)?;
        state.serialize_field("occurred_at", &self.occurred_at)?;
        state.serialize_field("outcome", &self.outcome)?;
        state.serialize_field("revocation_generation", &self.revocation_generation)?;
        state.serialize_field("schema_version", SECRET_ACCESS_EVIDENCE_SCHEMA_V1)?;
        state.serialize_field("secret_access_event_id", &self.secret_access_event_id)?;
        if let Some(lease_id) = &self.secret_lease_id {
            state.serialize_field("secret_lease_id", lease_id)?;
        }
        if let Some(claim_id) = &self.secret_use_claim_id {
            state.serialize_field("secret_use_claim_id", claim_id)?;
        }
        state.serialize_field("use_binding", &self.use_binding)?;
        state.serialize_field("uses_claimed", &self.uses_claimed)?;
        state.end()
    }
}

/// Fixed, non-reflecting construction failures for lease contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretLeaseContractError {
    InvalidTenantId,
    InvalidPrincipalId,
    InvalidWorkloadId,
    InvalidNodeId,
    InvalidInstanceId,
    InvalidDriverOperation,
    InvalidDriverDeclarationRevision,
    InvalidDestinationSchema,
    InvalidTrustedSendProfile,
    InvalidSecretRefRevision,
    RequirementBindingMismatch,
    InvalidTimeWindow,
    RequestedDurationExceeded,
    InvalidUseCounter,
    InvalidRevocationGeneration,
    InvalidRenewalLineage,
    InvalidEvidenceShape,
}

impl SecretLeaseContractError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidTenantId => "invalid_tenant_id",
            Self::InvalidPrincipalId => "invalid_principal_id",
            Self::InvalidWorkloadId => "invalid_workload_id",
            Self::InvalidNodeId => "invalid_node_id",
            Self::InvalidInstanceId => "invalid_instance_id",
            Self::InvalidDriverOperation => "invalid_driver_operation",
            Self::InvalidDriverDeclarationRevision => "invalid_driver_declaration_revision",
            Self::InvalidDestinationSchema => "invalid_destination_schema",
            Self::InvalidTrustedSendProfile => "invalid_trusted_send_profile",
            Self::InvalidSecretRefRevision => "invalid_secret_ref_revision",
            Self::RequirementBindingMismatch => "requirement_binding_mismatch",
            Self::InvalidTimeWindow => "invalid_time_window",
            Self::RequestedDurationExceeded => "requested_duration_exceeded",
            Self::InvalidUseCounter => "invalid_use_counter",
            Self::InvalidRevocationGeneration => "invalid_revocation_generation",
            Self::InvalidRenewalLineage => "invalid_renewal_lineage",
            Self::InvalidEvidenceShape => "invalid_evidence_shape",
        }
    }
}

impl fmt::Display for SecretLeaseContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for SecretLeaseContractError {}

fn parse_timestamp(
    value: &CanonicalTimestampV1,
) -> Result<OffsetDateTime, SecretLeaseContractError> {
    OffsetDateTime::parse(value.as_str(), &Rfc3339)
        .map_err(|_| SecretLeaseContractError::InvalidTimeWindow)
}

#[cfg(test)]
#[path = "../tests/unit/secret_lease_tests.rs"]
mod tests;
