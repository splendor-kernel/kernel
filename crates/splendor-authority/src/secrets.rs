//! Process-local C03 Secret Broker lifecycle and provider port.
//!
//! This module is the sole process-local mutation owner for the bounded lease
//! slice. It issues exact-bound leases, atomically claims finite uses, renews
//! without resetting lineage limits, and closes new-use admission on revocation.
//! It does not deliver material, invoke provider methods, replace the Gateway,
//! or claim restart durability.

mod provider;

pub use provider::{
    SecretProvider, SecretProviderAuditEvidence, SecretProviderControlRequest, SecretProviderError,
    SecretProviderErrorCode, SecretProviderFetchRequest, SecretProviderFetchResult,
    SecretProviderHealthEvidence, SecretProviderOperation, SecretProviderOutcome,
    SECRET_PROVIDER_AUDIT_EVIDENCE_SCHEMA_LOCAL_V1,
    SECRET_PROVIDER_HEALTH_EVIDENCE_SCHEMA_LOCAL_V1,
};

use crate::{
    evaluate_cached_capability_request, AuthorityGrantCache, OfflineAuthorityPolicy,
    RevocationSnapshot,
};
use serde::Serialize;
use splendor_types::{
    compare_secret_credential_authorization_v2, AuthorityDecisionStatus, AuthorityOperation,
    AuthorityOperationNamespace, AuthorityResourceKind, AuthorityTimeScope, AuthorityVerb,
    CanonicalTimestampV1, CapabilityRequest, CapabilityScope, ContentHash,
    DriverOperationCredentialSinksV1, DriverOperationRef, InstanceId, NodeId, PrincipalId,
    ProcessLocalSecretAccessDenialCode as SecretAccessDenialCode,
    ProcessLocalSecretAccessEvidence as SecretAccessEvidence,
    ProcessLocalSecretAccessEvidenceKind as SecretAccessEvidenceKind,
    ProcessLocalSecretAccessEvidenceOutcome as SecretAccessEvidenceOutcome,
    ProcessLocalSecretBrokerCommandId, ProcessLocalSecretLeaseRequest as SecretLeaseRequest,
    ProcessLocalSecretLeaseSnapshot as SecretLeaseSnapshot,
    ProcessLocalSecretLeaseStatus as SecretLeaseStatus,
    ProcessLocalSecretLeaseUseBinding as SecretLeaseUseBinding, SecretAccessEventId,
    SecretAudienceId, SecretCredentialDeclarationComparisonV2, SecretDeliveryHandleId,
    SecretDeliveryMethod, SecretLeaseId, SecretLeaseRequestId, SecretProviderId, SecretPurpose,
    SecretRefId, SecretRefV2, SecretRenewalCommandId, SecretRevocationCommandId,
    SecretUseAttemptId, SecretUseClaimId, SecretUseIntent, TenantId, WorkloadId,
    AUTHORITY_OPERATION_SCHEMA_VERSION, CAPABILITY_REQUEST_SCHEMA_VERSION,
};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration as StdDuration;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

thread_local! {
    static SECRET_BROKER_CALLBACK_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

struct SecretBrokerCallbackThreadScope;

impl SecretBrokerCallbackThreadScope {
    fn enter() -> Result<Self, SecretBrokerError> {
        SECRET_BROKER_CALLBACK_ACTIVE.with(|active| {
            if active.replace(true) {
                Err(SecretBrokerError::StateUnavailable)
            } else {
                Ok(Self)
            }
        })
    }
}

impl Drop for SecretBrokerCallbackThreadScope {
    fn drop(&mut self) {
        SECRET_BROKER_CALLBACK_ACTIVE.with(|active| active.set(false));
    }
}

fn broker_callback_active_on_current_thread() -> bool {
    SECRET_BROKER_CALLBACK_ACTIVE.with(Cell::get)
}

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

/// Trusted UTC source sampled through the serialized callback gate without
/// holding the broker state mutex.
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

/// Authority-owned current inputs required by every lease mutation/use.
///
/// The constructor is crate-private: callers cannot turn arbitrary coordinates
/// into a broker permit. A future production composition root must obtain these
/// coordinates from authenticated runtime placement and current Registry data.
pub struct SecretBrokerAuthorityContext<'a> {
    cache: &'a AuthorityGrantCache,
    revocations: Option<&'a RevocationSnapshot>,
    policy: &'a OfflineAuthorityPolicy,
    tenant_id: &'a TenantId,
    principal_id: &'a PrincipalId,
    workload_id: &'a WorkloadId,
    node_id: &'a NodeId,
    instance_id: &'a InstanceId,
    audience_id: &'a SecretAudienceId,
    intent: SecretUseIntent,
    purpose: SecretPurpose,
    current_driver_declaration: &'a DriverOperationCredentialSinksV1,
}

impl<'a> SecretBrokerAuthorityContext<'a> {
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(
        cache: &'a AuthorityGrantCache,
        revocations: Option<&'a RevocationSnapshot>,
        policy: &'a OfflineAuthorityPolicy,
        tenant_id: &'a TenantId,
        principal_id: &'a PrincipalId,
        workload_id: &'a WorkloadId,
        node_id: &'a NodeId,
        instance_id: &'a InstanceId,
        audience_id: &'a SecretAudienceId,
        intent: SecretUseIntent,
        purpose: SecretPurpose,
        current_driver_declaration: &'a DriverOperationCredentialSinksV1,
    ) -> Self {
        Self {
            cache,
            revocations,
            policy,
            tenant_id,
            principal_id,
            workload_id,
            node_id,
            instance_id,
            audience_id,
            intent,
            purpose,
            current_driver_declaration,
        }
    }
}

/// Private proof that Authority, placement, current Driver declaration, current
/// SecretRef authorization, expiry, and revocation all matched one request.
struct ValidatedSecretBrokerPermit {
    _private: (),
}

/// Finite process-local resource ceilings. Exhaustion always fails closed and
/// never falls back to an unbounded allocation path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLocalSecretBrokerLimits {
    pub max_secret_refs: usize,
    pub max_providers: usize,
    pub max_active_leases: usize,
    pub max_retained_leases: usize,
    pub max_command_records: usize,
    pub max_evidence_events: usize,
    pub max_generated_ids: usize,
    pub max_replay_page_size: usize,
}

impl Default for ProcessLocalSecretBrokerLimits {
    fn default() -> Self {
        Self {
            max_secret_refs: 256,
            max_providers: 64,
            max_active_leases: 1_024,
            max_retained_leases: 2_048,
            max_command_records: 4_096,
            max_evidence_events: 8_192,
            max_generated_ids: 32_768,
            max_replay_page_size: 128,
        }
    }
}

impl ProcessLocalSecretBrokerLimits {
    fn is_valid(self) -> bool {
        let maximum = Self::default();
        self.max_secret_refs > 0
            && self.max_secret_refs <= maximum.max_secret_refs
            && self.max_providers > 0
            && self.max_providers <= maximum.max_providers
            && self.max_active_leases > 0
            && self.max_active_leases <= maximum.max_active_leases
            && self.max_retained_leases >= self.max_active_leases
            && self.max_retained_leases <= maximum.max_retained_leases
            && self.max_command_records > 0
            && self.max_command_records <= maximum.max_command_records
            && self.max_evidence_events > 0
            && self.max_evidence_events <= maximum.max_evidence_events
            && self.max_generated_ids >= self.max_evidence_events
            && self.max_generated_ids <= maximum.max_generated_ids
            && self.max_replay_page_size > 0
            && self.max_replay_page_size <= self.max_evidence_events
            && self.max_replay_page_size <= maximum.max_replay_page_size
    }
}

/// Opaque live delivery handle. The ID getters are safe metadata; the private
/// capability nonce is required for every state lookup.
///
/// ```compile_fail
/// use splendor_authority::ProcessLocalSecretDeliveryHandle;
/// fn require_clone<T: Clone>() {}
/// require_clone::<ProcessLocalSecretDeliveryHandle>();
/// ```
///
/// ```compile_fail
/// use splendor_authority::ProcessLocalSecretDeliveryHandle;
/// fn serialize(value: &ProcessLocalSecretDeliveryHandle) {
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

    fn from_stored(stored: &StoredHandle) -> Self {
        Self {
            delivery_handle_id: stored.delivery_handle_id.clone(),
            secret_lease_id: stored.secret_lease_id.clone(),
            capability_nonce: stored.capability_nonce,
        }
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

/// Internal-only successful use reservation. It has no provider-fetch
/// conversion API and cannot cross the pre-Gateway public boundary.
#[cfg_attr(not(test), allow(dead_code))]
struct SecretDeliveryClaim {
    secret_use_claim_id: SecretUseClaimId,
    secret_use_attempt_id: SecretUseAttemptId,
    secret_lease_id: SecretLeaseId,
    delivery_handle_id: SecretDeliveryHandleId,
    use_binding: SecretLeaseUseBinding,
    capability_nonce: Uuid,
    expires_at: OffsetDateTime,
    revocation_generation: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl SecretDeliveryClaim {
    fn secret_use_claim_id(&self) -> &SecretUseClaimId {
        &self.secret_use_claim_id
    }
    fn secret_use_attempt_id(&self) -> &SecretUseAttemptId {
        &self.secret_use_attempt_id
    }
    fn secret_lease_id(&self) -> &SecretLeaseId {
        &self.secret_lease_id
    }
    fn delivery_handle_id(&self) -> &SecretDeliveryHandleId {
        &self.delivery_handle_id
    }
    fn use_binding(&self) -> &SecretLeaseUseBinding {
        &self.use_binding
    }
    fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
    fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    fn from_stored(stored: &StoredClaim) -> Self {
        Self {
            secret_use_claim_id: stored.secret_use_claim_id.clone(),
            secret_use_attempt_id: stored.secret_use_attempt_id.clone(),
            secret_lease_id: stored.secret_lease_id.clone(),
            delivery_handle_id: stored.delivery_handle_id.clone(),
            use_binding: stored.use_binding.clone(),
            capability_nonce: stored.capability_nonce,
            expires_at: stored.expires_at,
            revocation_generation: stored.revocation_generation,
        }
    }
}

impl fmt::Debug for SecretDeliveryClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            self.capability_nonce,
            self.expires_at,
            self.revocation_generation,
        );
        formatter.write_str("SecretDeliveryClaim(<opaque>)")
    }
}

/// Internal bounded replay projection over already-recorded process-local facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(not(test), allow(dead_code))]
struct SecretBrokerReplayPage {
    leases: Vec<SecretLeaseSnapshot>,
    events: Vec<SecretAccessEvidence>,
    next_cursor: Option<usize>,
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
    CommandConflict,
    CapacityExceeded,
    InvalidPage,
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
            Self::CommandConflict => "secret_broker_command_conflict",
            Self::CapacityExceeded => "secret_broker_capacity_exceeded",
            Self::InvalidPage => "secret_broker_page_invalid",
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
    InvalidLimits,
    CapacityExceeded,
}

impl fmt::Display for SecretBrokerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateSecretRef => "duplicate_secret_ref",
            Self::DuplicateProvider => "duplicate_secret_provider",
            Self::MissingProvider => "secret_provider_missing",
            Self::InvalidLimits => "secret_broker_limits_invalid",
            Self::CapacityExceeded => "secret_broker_capacity_exceeded",
        })
    }
}

impl Error for SecretBrokerConfigError {}

/// Explicit process-local lifecycle owner. State is not restart durable.
pub struct ProcessLocalSecretBroker {
    mutation_gate: Mutex<SecretBrokerMutationState>,
    mutation_ready: Condvar,
    state: Mutex<SecretBrokerState>,
    providers: HashMap<SecretProviderId, Arc<dyn SecretProvider>>,
    clock: Arc<dyn SecretBrokerClock>,
    ids: Arc<dyn SecretBrokerIdSource>,
    limits: ProcessLocalSecretBrokerLimits,
}

#[derive(Default)]
struct SecretBrokerMutationState {
    callback_in_progress: bool,
}

struct SecretBrokerMutationGuard<'a> {
    broker: &'a ProcessLocalSecretBroker,
    gate: Option<MutexGuard<'a, SecretBrokerMutationState>>,
}

impl SecretBrokerMutationGuard<'_> {
    /// Runs an injected clock/ID callback without holding either broker mutex.
    /// Same-thread reentrant mutation fails closed while unrelated mutation
    /// callers wait for a short bounded interval. Reads remain available.
    fn invoke<T>(&mut self, callback: impl FnOnce() -> T) -> Result<T, SecretBrokerError> {
        let _callback_scope = SecretBrokerCallbackThreadScope::enter()?;
        self.gate
            .as_mut()
            .ok_or(SecretBrokerError::StateUnavailable)?
            .callback_in_progress = true;
        drop(self.gate.take());
        let result = catch_unwind(AssertUnwindSafe(callback));
        let mut gate = self
            .broker
            .mutation_gate
            .lock()
            .map_err(|_| SecretBrokerError::StateUnavailable)?;
        gate.callback_in_progress = false;
        self.broker.mutation_ready.notify_all();
        self.gate = Some(gate);
        result.map_err(|_| SecretBrokerError::StateUnavailable)
    }
}

#[derive(Clone, Default)]
struct SecretBrokerState {
    max_observed_time: Option<OffsetDateTime>,
    refs: HashMap<(TenantId, SecretRefId), SecretRefV2>,
    leases: HashMap<SecretLeaseId, LeaseRecord>,
    handles: HashMap<SecretDeliveryHandleId, HandleRecord>,
    used_request_ids: HashSet<ScopedSecretLeaseRequestId>,
    commands: HashMap<SecretCommandKey, SecretCommandRecord>,
    allocated_ids: HashSet<Uuid>,
    events: Vec<SecretAccessEvidence>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ScopedSecretLeaseRequestId {
    secret_lease_request_id: SecretLeaseRequestId,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    workload_id: WorkloadId,
    node_id: NodeId,
    instance_id: InstanceId,
    audience_id: SecretAudienceId,
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

#[derive(Clone)]
struct HandleRecord {
    secret_lease_id: SecretLeaseId,
    capability_nonce: Uuid,
    active: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
enum SecretCommandKind {
    Issue,
    Claim,
    Renew,
    Revoke,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SecretCommandKey {
    kind: SecretCommandKind,
    command_id: String,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    workload_id: WorkloadId,
    node_id: NodeId,
    instance_id: InstanceId,
    audience_id: SecretAudienceId,
}

#[derive(Clone)]
struct SecretCommandRecord {
    semantic_digest: ContentHash,
    terminal: SecretCommandTerminal,
}

#[derive(Clone)]
#[cfg_attr(not(test), allow(dead_code))]
enum SecretCommandTerminal {
    Issue(Result<StoredGrant, SecretBrokerError>),
    Claim(Result<StoredClaim, SecretBrokerError>),
    Renew(Result<StoredGrant, SecretBrokerError>),
    Revoke(Result<SecretLeaseSnapshot, SecretBrokerError>),
}

#[derive(Clone)]
struct StoredHandle {
    delivery_handle_id: SecretDeliveryHandleId,
    secret_lease_id: SecretLeaseId,
    capability_nonce: Uuid,
}

#[derive(Clone)]
struct StoredGrant {
    snapshot: SecretLeaseSnapshot,
    handle: StoredHandle,
}

impl StoredGrant {
    fn materialize(&self) -> SecretLeaseGrant {
        SecretLeaseGrant {
            snapshot: self.snapshot.clone(),
            handle: SecretDeliveryHandle::from_stored(&self.handle),
        }
    }
}

#[derive(Clone)]
#[cfg_attr(not(test), allow(dead_code))]
struct StoredClaim {
    secret_use_claim_id: SecretUseClaimId,
    secret_use_attempt_id: SecretUseAttemptId,
    secret_lease_id: SecretLeaseId,
    delivery_handle_id: SecretDeliveryHandleId,
    use_binding: SecretLeaseUseBinding,
    capability_nonce: Uuid,
    expires_at: OffsetDateTime,
    revocation_generation: u64,
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
    ) -> Result<Self, SecretBrokerConfigError> {
        Self::with_sources(
            refs,
            providers,
            Arc::new(SystemSecretBrokerClock),
            Arc::new(SystemSecretBrokerIdSource),
        )
    }

    /// Builds an explicit process-local broker with injected deterministic seams.
    pub fn with_sources(
        refs: Vec<SecretRefV2>,
        providers: Vec<Arc<dyn SecretProvider>>,
        clock: Arc<dyn SecretBrokerClock>,
        ids: Arc<dyn SecretBrokerIdSource>,
    ) -> Result<Self, SecretBrokerConfigError> {
        Self::with_sources_and_limits(
            refs,
            providers,
            clock,
            ids,
            ProcessLocalSecretBrokerLimits::default(),
        )
    }

    /// Builds a process-local broker with explicit finite resource ceilings.
    pub fn with_sources_and_limits(
        refs: Vec<SecretRefV2>,
        providers: Vec<Arc<dyn SecretProvider>>,
        clock: Arc<dyn SecretBrokerClock>,
        ids: Arc<dyn SecretBrokerIdSource>,
        limits: ProcessLocalSecretBrokerLimits,
    ) -> Result<Self, SecretBrokerConfigError> {
        if !limits.is_valid() {
            return Err(SecretBrokerConfigError::InvalidLimits);
        }
        if refs.len() > limits.max_secret_refs || providers.len() > limits.max_providers {
            return Err(SecretBrokerConfigError::CapacityExceeded);
        }
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
            mutation_gate: Mutex::new(SecretBrokerMutationState::default()),
            mutation_ready: Condvar::new(),
            state: Mutex::new(SecretBrokerState {
                refs: ref_map,
                ..SecretBrokerState::default()
            }),
            providers: provider_map,
            clock,
            ids,
            limits,
        })
    }

    /// Issues one exact-bound lease and opaque handle after current authority and
    /// ref-policy validation. Provider methods are never called.
    pub fn issue_lease(
        &self,
        request: SecretLeaseRequest,
        authority: &SecretBrokerAuthorityContext<'_>,
    ) -> Result<SecretLeaseGrant, SecretBrokerError> {
        let mut mutation_guard = self.lock_mutation()?;
        let command_id = ProcessLocalSecretBrokerCommandId::LeaseRequest(
            request.secret_lease_request_id().clone(),
        );
        let command_key = command_key(
            SecretCommandKind::Issue,
            request.secret_lease_request_id().to_string(),
            request.use_binding(),
        );
        let semantic_digest = issue_command_digest(&request)?;
        let state = self.lock_state()?;
        if let Some(result) = retry_issue(&state, &command_key, &semantic_digest) {
            return result;
        }
        self.ensure_command_capacity(&state)?;
        let max_observed_time = state.max_observed_time;
        drop(state);
        let now = match self.observe_time(&mut mutation_guard, max_observed_time) {
            Ok(now) => now,
            Err(error) => {
                if error == SecretBrokerError::ClockRollback {
                    let event_id = self.next_event_id(&mut mutation_guard)?;
                    let mut state = self.lock_state()?;
                    let recorded_at = state
                        .max_observed_time
                        .ok_or(SecretBrokerError::ClockUnavailable)?;
                    self.commit_denial(
                        &mut state,
                        event_id,
                        command_key,
                        semantic_digest,
                        SecretCommandTerminal::Issue(Err(error)),
                        command_id,
                        SecretAccessEvidenceKind::LeaseDenied,
                        request.use_binding().clone(),
                        None,
                        None,
                        0,
                        request.bound_use_requirement().requested_max_uses(),
                        1,
                        SecretAccessDenialCode::ClockRollback,
                        recorded_at,
                        None,
                    )?;
                }
                return Err(error);
            }
        };
        let event_id = self.next_event_id(&mut mutation_guard)?;
        let mut state = self.lock_state()?;
        let plan = match self.validate_issue(&state, &request, authority, now) {
            Ok(plan) => plan,
            Err((error, denial)) => {
                self.commit_denial(
                    &mut state,
                    event_id,
                    command_key,
                    semantic_digest,
                    SecretCommandTerminal::Issue(Err(error)),
                    command_id,
                    SecretAccessEvidenceKind::LeaseDenied,
                    request.use_binding().clone(),
                    None,
                    None,
                    0,
                    request.bound_use_requirement().requested_max_uses(),
                    1,
                    denial,
                    now,
                    None,
                )?;
                return Err(error);
            }
        };
        if self.ensure_new_lease_capacity(&state).is_err() {
            self.commit_denial(
                &mut state,
                event_id,
                command_key,
                semantic_digest,
                SecretCommandTerminal::Issue(Err(SecretBrokerError::CapacityExceeded)),
                command_id,
                SecretAccessEvidenceKind::LeaseDenied,
                request.use_binding().clone(),
                None,
                None,
                0,
                request.bound_use_requirement().requested_max_uses(),
                1,
                SecretAccessDenialCode::CapacityExceeded,
                now,
                None,
            )?;
            return Err(SecretBrokerError::CapacityExceeded);
        }

        drop(state);
        let secret_lease_id = self.next_lease_id(&mut mutation_guard)?;
        let delivery_handle_id = self.next_handle_id(&mut mutation_guard)?;
        let capability_nonce =
            self.next_non_nil_uuid(&mut mutation_guard, SecretBrokerIdKind::HandleCapability)?;
        let mut state = self.lock_state()?;
        let event = evidence(
            event_id.clone(),
            command_id,
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
            last_event_id: event_id.clone(),
        };
        let snapshot = snapshot(&record)?;
        let stored = StoredGrant {
            snapshot,
            handle: StoredHandle {
                delivery_handle_id: delivery_handle_id.clone(),
                secret_lease_id: secret_lease_id.clone(),
                capability_nonce,
            },
        };
        let mut next = state.clone();
        self.reserve_generated_ids(
            &mut next,
            &[
                *secret_lease_id.as_uuid(),
                *delivery_handle_id.as_uuid(),
                capability_nonce,
                *event_id.as_uuid(),
            ],
            SecretBrokerError::StateUnavailable,
        )?;
        self.append_event(&mut next, event)?;
        next.max_observed_time = Some(now);
        next.handles.insert(
            delivery_handle_id.clone(),
            HandleRecord {
                secret_lease_id: secret_lease_id.clone(),
                capability_nonce,
                active: true,
            },
        );
        next.leases.insert(secret_lease_id, record);
        next.used_request_ids
            .insert(scoped_lease_request_id(&request));
        next.commands.insert(
            command_key,
            SecretCommandRecord {
                semantic_digest,
                terminal: SecretCommandTerminal::Issue(Ok(stored.clone())),
            },
        );
        *state = next;
        Ok(stored.materialize())
    }

    /// Atomically claims one use. The final available use has exactly one winner
    /// under concurrency. The result cannot fetch or expose material.
    #[cfg_attr(not(test), allow(dead_code))]
    fn claim_use(
        &self,
        secret_use_attempt_id: SecretUseAttemptId,
        handle: &SecretDeliveryHandle,
        use_binding: &SecretLeaseUseBinding,
        authority: &SecretBrokerAuthorityContext<'_>,
    ) -> Result<SecretDeliveryClaim, SecretBrokerError> {
        let mut mutation_guard = self.lock_mutation()?;
        let command_id =
            ProcessLocalSecretBrokerCommandId::UseAttempt(secret_use_attempt_id.clone());
        let command_key = command_key(
            SecretCommandKind::Claim,
            secret_use_attempt_id.to_string(),
            use_binding,
        );
        let semantic_digest = handle_command_digest("claim", handle, use_binding, None)?;
        let state = self.lock_state()?;
        if let Some(result) = retry_claim(&state, &command_key, &semantic_digest) {
            return result;
        }
        self.ensure_command_capacity(&state)?;
        let max_observed_time = state.max_observed_time;
        drop(state);
        let now = match self.observe_time(&mut mutation_guard, max_observed_time) {
            Ok(now) => now,
            Err(SecretBrokerError::ClockRollback) => {
                let event_id = self.next_event_id(&mut mutation_guard)?;
                let mut state = self.lock_state()?;
                let recorded_at = state
                    .max_observed_time
                    .ok_or(SecretBrokerError::ClockUnavailable)?;
                self.commit_denial(
                    &mut state,
                    event_id,
                    command_key,
                    semantic_digest,
                    SecretCommandTerminal::Claim(Err(SecretBrokerError::ClockRollback)),
                    command_id,
                    SecretAccessEvidenceKind::UseDenied,
                    use_binding.clone(),
                    None,
                    None,
                    0,
                    1,
                    1,
                    SecretAccessDenialCode::ClockRollback,
                    recorded_at,
                    None,
                )?;
                return Err(SecretBrokerError::ClockRollback);
            }
            Err(error) => return Err(error),
        };
        let event_id = self.next_event_id(&mut mutation_guard)?;
        let mut state = self.lock_state()?;
        let record = match self.valid_handle_record(&state, handle) {
            Ok(record) => record,
            Err(error) => {
                self.commit_denial(
                    &mut state,
                    event_id,
                    command_key,
                    semantic_digest,
                    SecretCommandTerminal::Claim(Err(error)),
                    command_id,
                    SecretAccessEvidenceKind::UseDenied,
                    use_binding.clone(),
                    None,
                    None,
                    0,
                    1,
                    1,
                    SecretAccessDenialCode::SecretNotAvailable,
                    now,
                    None,
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
            self.commit_denial(
                &mut state,
                event_id,
                command_key,
                semantic_digest,
                SecretCommandTerminal::Claim(Err(SecretBrokerError::SecretNotAvailable)),
                command_id,
                SecretAccessEvidenceKind::UseDenied,
                use_binding.clone(),
                None,
                None,
                0,
                1,
                1,
                SecretAccessDenialCode::BindingMismatch,
                now,
                None,
            )?;
            return Err(SecretBrokerError::SecretNotAvailable);
        }
        if lease.status == SecretLeaseStatus::Exhausted {
            self.commit_denial_for_lease(
                &mut state,
                event_id,
                &lease,
                command_key,
                semantic_digest,
                SecretCommandTerminal::Claim(Err(SecretBrokerError::MaxUsesExceeded)),
                command_id,
                use_binding.clone(),
                SecretAccessEvidenceKind::UseDenied,
                SecretAccessDenialCode::MaxUsesExceeded,
                now,
                None,
            )?;
            return Err(SecretBrokerError::MaxUsesExceeded);
        }
        if now < lease.starts_at {
            self.commit_denial_for_lease(
                &mut state,
                event_id,
                &lease,
                command_key,
                semantic_digest,
                SecretCommandTerminal::Claim(Err(SecretBrokerError::LeaseNotStarted)),
                command_id,
                use_binding.clone(),
                SecretAccessEvidenceKind::UseDenied,
                SecretAccessDenialCode::LeaseNotStarted,
                now,
                None,
            )?;
            return Err(SecretBrokerError::LeaseNotStarted);
        }
        if now >= lease.expires_at {
            self.commit_denial_for_lease(
                &mut state,
                event_id,
                &lease,
                command_key,
                semantic_digest,
                SecretCommandTerminal::Claim(Err(SecretBrokerError::LeaseExpired)),
                command_id,
                use_binding.clone(),
                SecretAccessEvidenceKind::UseDenied,
                SecretAccessDenialCode::LeaseExpired,
                now,
                Some(SecretLeaseStatus::Expired),
            )?;
            return Err(SecretBrokerError::LeaseExpired);
        }
        if validated_authority_permit(&state, authority, use_binding, now, lease.expires_at)
            .is_none()
        {
            self.commit_denial_for_lease(
                &mut state,
                event_id,
                &lease,
                command_key,
                semantic_digest,
                SecretCommandTerminal::Claim(Err(SecretBrokerError::AuthorityDenied)),
                command_id,
                use_binding.clone(),
                SecretAccessEvidenceKind::UseDenied,
                SecretAccessDenialCode::AuthorityDenied,
                now,
                None,
            )?;
            return Err(SecretBrokerError::AuthorityDenied);
        }
        drop(state);
        let claim_id = self.next_claim_id(&mut mutation_guard)?;
        let claim_capability =
            self.next_non_nil_uuid(&mut mutation_guard, SecretBrokerIdKind::ClaimCapability)?;
        let mut state = self.lock_state()?;
        let next_uses = lease.uses_claimed + 1;
        let event = evidence(
            event_id.clone(),
            command_id,
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
        let stored = StoredClaim {
            secret_use_claim_id: claim_id,
            secret_use_attempt_id,
            secret_lease_id: lease_id.clone(),
            delivery_handle_id: handle.delivery_handle_id.clone(),
            use_binding: use_binding.clone(),
            capability_nonce: claim_capability,
            expires_at: lease.expires_at,
            revocation_generation: lease.revocation_generation,
        };
        let mut next = state.clone();
        self.reserve_generated_ids(
            &mut next,
            &[
                *stored.secret_use_claim_id.as_uuid(),
                claim_capability,
                *event_id.as_uuid(),
            ],
            SecretBrokerError::StateUnavailable,
        )?;
        self.append_event(&mut next, event)?;
        next.max_observed_time = Some(now);
        let mut updated = lease;
        updated.uses_claimed = next_uses;
        updated.last_event_id = event_id;
        if next_uses == updated.max_uses {
            updated.status = SecretLeaseStatus::Exhausted;
        }
        next.leases.insert(lease_id, updated);
        next.commands.insert(
            command_key,
            SecretCommandRecord {
                semantic_digest,
                terminal: SecretCommandTerminal::Claim(Ok(stored.clone())),
            },
        );
        *state = next;
        Ok(SecretDeliveryClaim::from_stored(&stored))
    }

    /// Renews into a new lease and handle while carrying the original continuous
    /// lifetime and use count forward. Success invalidates the old handle.
    pub fn renew_lease(
        &self,
        renewal_command_id: SecretRenewalCommandId,
        old_handle: &SecretDeliveryHandle,
        request: SecretLeaseRequest,
        authority: &SecretBrokerAuthorityContext<'_>,
    ) -> Result<SecretLeaseGrant, SecretBrokerError> {
        let mut mutation_guard = self.lock_mutation()?;
        let command_id = ProcessLocalSecretBrokerCommandId::Renewal(renewal_command_id.clone());
        let command_key = command_key(
            SecretCommandKind::Renew,
            renewal_command_id.to_string(),
            request.use_binding(),
        );
        let semantic_digest = renew_command_digest(old_handle, &request)?;
        let state = self.lock_state()?;
        if let Some(result) = retry_renew(&state, &command_key, &semantic_digest) {
            return result;
        }
        self.ensure_command_capacity(&state)?;
        let max_observed_time = state.max_observed_time;
        drop(state);
        let now = match self.observe_time(&mut mutation_guard, max_observed_time) {
            Ok(now) => now,
            Err(SecretBrokerError::ClockRollback) => {
                let event_id = self.next_event_id(&mut mutation_guard)?;
                let mut state = self.lock_state()?;
                let recorded_at = state
                    .max_observed_time
                    .ok_or(SecretBrokerError::ClockUnavailable)?;
                self.commit_denial(
                    &mut state,
                    event_id,
                    command_key,
                    semantic_digest,
                    SecretCommandTerminal::Renew(Err(SecretBrokerError::ClockRollback)),
                    command_id,
                    SecretAccessEvidenceKind::RenewalDenied,
                    request.use_binding().clone(),
                    None,
                    None,
                    0,
                    1,
                    1,
                    SecretAccessDenialCode::ClockRollback,
                    recorded_at,
                    None,
                )?;
                return Err(SecretBrokerError::ClockRollback);
            }
            Err(error) => return Err(error),
        };
        let event_id = self.next_event_id(&mut mutation_guard)?;
        let mut state = self.lock_state()?;
        let handle_record = match self.valid_handle_record(&state, old_handle) {
            Ok(record) => record,
            Err(error) => {
                self.commit_denial(
                    &mut state,
                    event_id,
                    command_key,
                    semantic_digest,
                    SecretCommandTerminal::Renew(Err(error)),
                    command_id,
                    SecretAccessEvidenceKind::RenewalDenied,
                    request.use_binding().clone(),
                    None,
                    None,
                    0,
                    request.bound_use_requirement().requested_max_uses(),
                    1,
                    SecretAccessDenialCode::SecretNotAvailable,
                    now,
                    None,
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
            let error = match code {
                SecretAccessDenialCode::AuthorityDenied => SecretBrokerError::AuthorityDenied,
                SecretAccessDenialCode::RequestAlreadyUsed => SecretBrokerError::RequestAlreadyUsed,
                _ => SecretBrokerError::RenewalDenied,
            };
            let binding_mismatch = old.request.use_binding() != request.use_binding();
            if binding_mismatch {
                self.commit_denial(
                    &mut state,
                    event_id,
                    command_key,
                    semantic_digest,
                    SecretCommandTerminal::Renew(Err(error)),
                    command_id,
                    SecretAccessEvidenceKind::RenewalDenied,
                    request.use_binding().clone(),
                    None,
                    None,
                    0,
                    1,
                    1,
                    code,
                    now,
                    None,
                )?;
            } else {
                self.commit_denial_for_lease(
                    &mut state,
                    event_id,
                    &old,
                    command_key,
                    semantic_digest,
                    SecretCommandTerminal::Renew(Err(error)),
                    command_id,
                    request.use_binding().clone(),
                    SecretAccessEvidenceKind::RenewalDenied,
                    code,
                    now,
                    None,
                )?;
            }
            return Err(error);
        }
        if self.ensure_retained_lease_capacity(&state).is_err() {
            self.commit_denial_for_lease(
                &mut state,
                event_id,
                &old,
                command_key,
                semantic_digest,
                SecretCommandTerminal::Renew(Err(SecretBrokerError::CapacityExceeded)),
                command_id,
                request.use_binding().clone(),
                SecretAccessEvidenceKind::RenewalDenied,
                SecretAccessDenialCode::CapacityExceeded,
                now,
                None,
            )?;
            return Err(SecretBrokerError::CapacityExceeded);
        }

        let starts_at = parse_canonical(request.starts_at())?;
        let expires_at = parse_canonical(request.expires_at())?;
        let new_max_uses = request.bound_use_requirement().requested_max_uses();
        drop(state);
        let new_lease_id = self.next_lease_id(&mut mutation_guard)?;
        let new_handle_id = self.next_handle_id(&mut mutation_guard)?;
        let capability_nonce =
            self.next_non_nil_uuid(&mut mutation_guard, SecretBrokerIdKind::HandleCapability)?;
        let mut state = self.lock_state()?;
        let event = evidence(
            event_id.clone(),
            command_id,
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
            renewed_from_lease_id: Some(old_id.clone()),
            last_event_id: event_id.clone(),
        };
        let snapshot = snapshot(&record)?;
        let stored = StoredGrant {
            snapshot,
            handle: StoredHandle {
                delivery_handle_id: new_handle_id.clone(),
                secret_lease_id: new_lease_id.clone(),
                capability_nonce,
            },
        };
        let mut next = state.clone();
        self.reserve_generated_ids(
            &mut next,
            &[
                *new_lease_id.as_uuid(),
                *new_handle_id.as_uuid(),
                capability_nonce,
                *event_id.as_uuid(),
            ],
            SecretBrokerError::StateUnavailable,
        )?;
        self.append_event(&mut next, event)?;
        next.max_observed_time = Some(now);
        let old_delivery_handle_id = old.delivery_handle_id.clone();
        let mut old_updated = old;
        old_updated.status = SecretLeaseStatus::Superseded;
        old_updated.last_event_id = event_id.clone();
        next.leases.insert(old_id, old_updated);
        if let Some(old_handle_record) = next.handles.get_mut(&old_delivery_handle_id) {
            old_handle_record.active = false;
        }
        next.handles.insert(
            new_handle_id.clone(),
            HandleRecord {
                secret_lease_id: new_lease_id.clone(),
                capability_nonce,
                active: true,
            },
        );
        next.leases.insert(new_lease_id, record);
        next.used_request_ids
            .insert(scoped_lease_request_id(&request));
        next.commands.insert(
            command_key,
            SecretCommandRecord {
                semantic_digest,
                terminal: SecretCommandTerminal::Renew(Ok(stored.clone())),
            },
        );
        *state = next;
        Ok(stored.materialize())
    }

    /// Atomically commits local admission closure and terminal evidence.
    /// Provider methods are not invoked; a later Gateway control slice must
    /// propagate provider/node revocation.
    pub fn revoke_lease(
        &self,
        revocation_command_id: SecretRevocationCommandId,
        handle: &SecretDeliveryHandle,
        use_binding: &SecretLeaseUseBinding,
        authority: &SecretBrokerAuthorityContext<'_>,
    ) -> Result<SecretLeaseSnapshot, SecretBrokerError> {
        let mut mutation_guard = self.lock_mutation()?;
        let command_id =
            ProcessLocalSecretBrokerCommandId::Revocation(revocation_command_id.clone());
        let command_key = command_key(
            SecretCommandKind::Revoke,
            revocation_command_id.to_string(),
            use_binding,
        );
        let semantic_digest = handle_command_digest("revoke", handle, use_binding, None)?;
        let state = self.lock_state()?;
        if let Some(result) = retry_revoke(&state, &command_key, &semantic_digest) {
            return result;
        }
        self.ensure_command_capacity(&state)?;
        let max_observed_time = state.max_observed_time;
        drop(state);
        let now = match self.observe_time(&mut mutation_guard, max_observed_time) {
            Ok(now) => now,
            Err(SecretBrokerError::ClockRollback) => {
                let event_id = self.next_event_id(&mut mutation_guard)?;
                let mut state = self.lock_state()?;
                let recorded_at = state
                    .max_observed_time
                    .ok_or(SecretBrokerError::ClockUnavailable)?;
                self.commit_denial(
                    &mut state,
                    event_id,
                    command_key,
                    semantic_digest,
                    SecretCommandTerminal::Revoke(Err(SecretBrokerError::ClockRollback)),
                    command_id,
                    SecretAccessEvidenceKind::RevocationDenied,
                    use_binding.clone(),
                    None,
                    None,
                    0,
                    1,
                    1,
                    SecretAccessDenialCode::ClockRollback,
                    recorded_at,
                    None,
                )?;
                return Err(SecretBrokerError::ClockRollback);
            }
            Err(error) => return Err(error),
        };
        let event_id = self.next_event_id(&mut mutation_guard)?;
        let mut state = self.lock_state()?;
        let (lease_id, handle_active) = match self.known_handle_record(&state, handle) {
            Ok(handle_record) => (handle_record.secret_lease_id.clone(), handle_record.active),
            Err(error) => {
                self.commit_denial(
                    &mut state,
                    event_id,
                    command_key,
                    semantic_digest,
                    SecretCommandTerminal::Revoke(Err(error)),
                    command_id,
                    SecretAccessEvidenceKind::RevocationDenied,
                    use_binding.clone(),
                    None,
                    None,
                    0,
                    1,
                    1,
                    SecretAccessDenialCode::SecretNotAvailable,
                    now,
                    None,
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
            self.commit_denial(
                &mut state,
                event_id,
                command_key,
                semantic_digest,
                SecretCommandTerminal::Revoke(Err(SecretBrokerError::SecretNotAvailable)),
                command_id,
                SecretAccessEvidenceKind::RevocationDenied,
                use_binding.clone(),
                None,
                None,
                0,
                1,
                1,
                SecretAccessDenialCode::BindingMismatch,
                now,
                None,
            )?;
            return Err(SecretBrokerError::SecretNotAvailable);
        }
        if validated_authority_permit(&state, authority, use_binding, now, lease.expires_at)
            .is_none()
        {
            self.commit_denial_for_lease(
                &mut state,
                event_id,
                &lease,
                command_key,
                semantic_digest,
                SecretCommandTerminal::Revoke(Err(SecretBrokerError::AuthorityDenied)),
                command_id,
                use_binding.clone(),
                SecretAccessEvidenceKind::RevocationDenied,
                SecretAccessDenialCode::AuthorityDenied,
                now,
                None,
            )?;
            return Err(SecretBrokerError::AuthorityDenied);
        }
        if !handle_active && lease.status != SecretLeaseStatus::Revoked {
            self.commit_denial_for_lease(
                &mut state,
                event_id,
                &lease,
                command_key,
                semantic_digest,
                SecretCommandTerminal::Revoke(Err(SecretBrokerError::SecretNotAvailable)),
                command_id,
                use_binding.clone(),
                SecretAccessEvidenceKind::RevocationDenied,
                SecretAccessDenialCode::SecretNotAvailable,
                now,
                None,
            )?;
            return Err(SecretBrokerError::SecretNotAvailable);
        }

        let next_generation = if lease.status == SecretLeaseStatus::Revoked {
            lease.revocation_generation
        } else {
            lease
                .revocation_generation
                .checked_add(1)
                .ok_or(SecretBrokerError::StateUnavailable)?
        };
        let event = evidence(
            event_id.clone(),
            command_id,
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
        let mut updated = lease;
        updated.last_event_id = event_id.clone();
        updated.status = SecretLeaseStatus::Revoked;
        updated.revocation_generation = next_generation;
        let terminal_snapshot = snapshot(&updated)?;
        let mut next = state.clone();
        self.reserve_generated_ids(
            &mut next,
            &[*event_id.as_uuid()],
            SecretBrokerError::EvidenceUnavailable,
        )?;
        self.append_event(&mut next, event)?;
        next.max_observed_time = Some(now);
        if let Some(handle_mut) = next.handles.get_mut(&updated.delivery_handle_id) {
            handle_mut.active = false;
        }
        next.leases.insert(lease_id, updated);
        next.commands.insert(
            command_key,
            SecretCommandRecord {
                semantic_digest,
                terminal: SecretCommandTerminal::Revoke(Ok(terminal_snapshot.clone())),
            },
        );
        *state = next;
        Ok(terminal_snapshot)
    }

    /// Internal exact snapshot lookup. No public inspection surface exists in
    /// this pre-visibility-policy slice.
    #[cfg_attr(not(test), allow(dead_code))]
    fn inspect_lease(
        &self,
        secret_lease_id: &SecretLeaseId,
    ) -> Result<Option<SecretLeaseSnapshot>, SecretBrokerError> {
        let state = self.lock_state()?;
        state.leases.get(secret_lease_id).map(snapshot).transpose()
    }

    /// Reconstructs a bounded page of process-local facts without current
    /// evaluation, allocation, provider calls, or lifecycle mutation.
    #[cfg_attr(not(test), allow(dead_code))]
    fn replay_page(
        &self,
        cursor: usize,
        limit: usize,
    ) -> Result<SecretBrokerReplayPage, SecretBrokerError> {
        if limit == 0 || limit > self.limits.max_replay_page_size {
            return Err(SecretBrokerError::InvalidPage);
        }
        let state = self.lock_state()?;
        let mut leases = state
            .leases
            .values()
            .map(snapshot)
            .collect::<Result<Vec<_>, _>>()?;
        leases.sort_by_key(|lease| lease.secret_lease_id().to_string());
        let total = leases.len().saturating_add(state.events.len());
        if cursor > total {
            return Err(SecretBrokerError::InvalidPage);
        }
        let end = cursor.saturating_add(limit).min(total);
        let lease_start = cursor.min(leases.len());
        let lease_end = end.min(leases.len());
        let event_start = cursor.saturating_sub(leases.len()).min(state.events.len());
        let event_end = end.saturating_sub(leases.len()).min(state.events.len());
        Ok(SecretBrokerReplayPage {
            leases: leases[lease_start..lease_end].to_vec(),
            events: state.events[event_start..event_end].to_vec(),
            next_cursor: (end < total).then_some(end),
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
            .contains(&scoped_lease_request_id(request))
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
        if !secret_ref_allows_binding(
            secret_ref,
            binding,
            authority.current_driver_declaration,
            now,
        ) {
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
        if validated_authority_permit(state, authority, binding, now, expires_at).is_none() {
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
            .contains(&scoped_lease_request_id(request))
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
        if !secret_ref_allows_binding(
            secret_ref,
            request.use_binding(),
            authority.current_driver_declaration,
            now,
        ) {
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
        if starts_at != now
            || requested_at > now
            || expires_at > old.max_continuous_expires_at
            || duration.whole_nanoseconds() <= 0
            || duration.whole_nanoseconds() > maximum_lease_nanos
            || requested_max_uses > old.max_uses
            || requested_max_uses <= old.uses_claimed
        {
            return Err(SecretAccessDenialCode::ContinuousLifetimeExceeded);
        }
        if validated_authority_permit(state, authority, request.use_binding(), now, expires_at)
            .is_none()
        {
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

    #[allow(clippy::too_many_arguments)]
    fn commit_denial_for_lease(
        &self,
        state: &mut SecretBrokerState,
        event_id: SecretAccessEventId,
        lease: &LeaseRecord,
        command_key: SecretCommandKey,
        semantic_digest: ContentHash,
        terminal: SecretCommandTerminal,
        command_id: ProcessLocalSecretBrokerCommandId,
        binding: SecretLeaseUseBinding,
        kind: SecretAccessEvidenceKind,
        code: SecretAccessDenialCode,
        now: OffsetDateTime,
        terminal_status: Option<SecretLeaseStatus>,
    ) -> Result<(), SecretBrokerError> {
        self.commit_denial(
            state,
            event_id,
            command_key,
            semantic_digest,
            terminal,
            command_id,
            kind,
            binding,
            Some(lease.secret_lease_id.clone()),
            Some(lease.delivery_handle_id.clone()),
            lease.uses_claimed,
            lease.max_uses,
            lease.revocation_generation,
            code,
            now,
            terminal_status,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_denial(
        &self,
        state: &mut SecretBrokerState,
        event_id: SecretAccessEventId,
        command_key: SecretCommandKey,
        semantic_digest: ContentHash,
        terminal: SecretCommandTerminal,
        command_id: ProcessLocalSecretBrokerCommandId,
        kind: SecretAccessEvidenceKind,
        binding: SecretLeaseUseBinding,
        lease_id: Option<SecretLeaseId>,
        handle_id: Option<SecretDeliveryHandleId>,
        uses_claimed: u64,
        max_uses: u64,
        revocation_generation: u64,
        code: SecretAccessDenialCode,
        now: OffsetDateTime,
        terminal_status: Option<SecretLeaseStatus>,
    ) -> Result<(), SecretBrokerError> {
        let event = evidence(
            event_id.clone(),
            command_id,
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
        let mut next = state.clone();
        self.reserve_generated_ids(
            &mut next,
            &[*event_id.as_uuid()],
            SecretBrokerError::EvidenceUnavailable,
        )?;
        self.append_event(&mut next, event)?;
        next.max_observed_time = Some(now);
        if let Some(lease_id) = lease_id {
            if let Some(lease) = next.leases.get_mut(&lease_id) {
                lease.last_event_id = event_id;
                if let Some(status) = terminal_status {
                    lease.status = status;
                    if let Some(handle) = next.handles.get_mut(&lease.delivery_handle_id) {
                        handle.active = false;
                    }
                }
            }
        }
        next.commands.insert(
            command_key,
            SecretCommandRecord {
                semantic_digest,
                terminal,
            },
        );
        *state = next;
        Ok(())
    }

    fn append_event(
        &self,
        state: &mut SecretBrokerState,
        event: SecretAccessEvidence,
    ) -> Result<(), SecretBrokerError> {
        if state.events.len() >= self.limits.max_evidence_events {
            return Err(SecretBrokerError::CapacityExceeded);
        }
        state.events.push(event);
        Ok(())
    }

    fn ensure_command_capacity(&self, state: &SecretBrokerState) -> Result<(), SecretBrokerError> {
        (state.commands.len() < self.limits.max_command_records)
            .then_some(())
            .ok_or(SecretBrokerError::CapacityExceeded)
    }

    fn ensure_new_lease_capacity(
        &self,
        state: &SecretBrokerState,
    ) -> Result<(), SecretBrokerError> {
        self.ensure_retained_lease_capacity(state)?;
        let active = state
            .leases
            .values()
            .filter(|lease| lease.status == SecretLeaseStatus::Active)
            .count();
        (active < self.limits.max_active_leases)
            .then_some(())
            .ok_or(SecretBrokerError::CapacityExceeded)
    }

    fn ensure_retained_lease_capacity(
        &self,
        state: &SecretBrokerState,
    ) -> Result<(), SecretBrokerError> {
        (state.leases.len() < self.limits.max_retained_leases)
            .then_some(())
            .ok_or(SecretBrokerError::CapacityExceeded)
    }

    fn lock_mutation(&self) -> Result<SecretBrokerMutationGuard<'_>, SecretBrokerError> {
        if broker_callback_active_on_current_thread() {
            return Err(SecretBrokerError::StateUnavailable);
        }
        let gate = self
            .mutation_gate
            .lock()
            .map_err(|_| SecretBrokerError::StateUnavailable)?;
        let (gate, _) = self
            .mutation_ready
            .wait_timeout_while(gate, StdDuration::from_millis(100), |state| {
                state.callback_in_progress
            })
            .map_err(|_| SecretBrokerError::StateUnavailable)?;
        if gate.callback_in_progress {
            return Err(SecretBrokerError::StateUnavailable);
        }
        Ok(SecretBrokerMutationGuard {
            broker: self,
            gate: Some(gate),
        })
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
        mutation: &mut SecretBrokerMutationGuard<'_>,
        max_observed_time: Option<OffsetDateTime>,
    ) -> Result<OffsetDateTime, SecretBrokerError> {
        let now = mutation
            .invoke(|| self.clock.now_utc())?
            .ok_or(SecretBrokerError::ClockUnavailable)?;
        if !now.nanosecond().is_multiple_of(1_000) {
            return Err(SecretBrokerError::ClockUnavailable);
        }
        if max_observed_time.is_some_and(|previous| now < previous) {
            return Err(SecretBrokerError::ClockRollback);
        }
        Ok(now)
    }

    fn next_non_nil_uuid(
        &self,
        mutation: &mut SecretBrokerMutationGuard<'_>,
        kind: SecretBrokerIdKind,
    ) -> Result<Uuid, SecretBrokerError> {
        let value = mutation
            .invoke(|| self.ids.next_uuid(kind))?
            .ok_or(SecretBrokerError::StateUnavailable)?;
        if value.is_nil() {
            return Err(SecretBrokerError::StateUnavailable);
        }
        Ok(value)
    }

    fn next_lease_id(
        &self,
        mutation: &mut SecretBrokerMutationGuard<'_>,
    ) -> Result<SecretLeaseId, SecretBrokerError> {
        SecretLeaseId::try_from(self.next_non_nil_uuid(mutation, SecretBrokerIdKind::Lease)?)
            .map_err(|_| SecretBrokerError::StateUnavailable)
    }

    fn next_handle_id(
        &self,
        mutation: &mut SecretBrokerMutationGuard<'_>,
    ) -> Result<SecretDeliveryHandleId, SecretBrokerError> {
        SecretDeliveryHandleId::try_from(
            self.next_non_nil_uuid(mutation, SecretBrokerIdKind::DeliveryHandle)?,
        )
        .map_err(|_| SecretBrokerError::StateUnavailable)
    }

    fn next_event_id(
        &self,
        mutation: &mut SecretBrokerMutationGuard<'_>,
    ) -> Result<SecretAccessEventId, SecretBrokerError> {
        let value = self
            .next_non_nil_uuid(mutation, SecretBrokerIdKind::AccessEvent)
            .map_err(|_| SecretBrokerError::EvidenceUnavailable)?;
        SecretAccessEventId::try_from(value).map_err(|_| SecretBrokerError::EvidenceUnavailable)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn next_claim_id(
        &self,
        mutation: &mut SecretBrokerMutationGuard<'_>,
    ) -> Result<SecretUseClaimId, SecretBrokerError> {
        SecretUseClaimId::try_from(self.next_non_nil_uuid(mutation, SecretBrokerIdKind::UseClaim)?)
            .map_err(|_| SecretBrokerError::StateUnavailable)
    }

    fn reserve_generated_ids(
        &self,
        state: &mut SecretBrokerState,
        ids: &[Uuid],
        error: SecretBrokerError,
    ) -> Result<(), SecretBrokerError> {
        let unique = ids.iter().copied().collect::<HashSet<_>>();
        if state.allocated_ids.len().saturating_add(unique.len()) > self.limits.max_generated_ids
            || unique.len() != ids.len()
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

fn command_key(
    kind: SecretCommandKind,
    command_id: String,
    binding: &SecretLeaseUseBinding,
) -> SecretCommandKey {
    SecretCommandKey {
        kind,
        command_id,
        tenant_id: binding.tenant_id().clone(),
        principal_id: binding.principal_id().clone(),
        workload_id: binding.workload_id().clone(),
        node_id: binding.node_id().clone(),
        instance_id: binding.instance_id().clone(),
        audience_id: binding.audience_id().clone(),
    }
}

fn scoped_lease_request_id(request: &SecretLeaseRequest) -> ScopedSecretLeaseRequestId {
    let binding = request.use_binding();
    ScopedSecretLeaseRequestId {
        secret_lease_request_id: request.secret_lease_request_id().clone(),
        tenant_id: binding.tenant_id().clone(),
        principal_id: binding.principal_id().clone(),
        workload_id: binding.workload_id().clone(),
        node_id: binding.node_id().clone(),
        instance_id: binding.instance_id().clone(),
        audience_id: binding.audience_id().clone(),
    }
}

#[derive(Serialize)]
struct IssueCommandDigestMaterial<'a> {
    operation: &'static str,
    request: &'a SecretLeaseRequest,
}

#[derive(Serialize)]
struct HandleCommandDigestMaterial<'a> {
    operation: &'static str,
    delivery_handle_id: &'a SecretDeliveryHandleId,
    secret_lease_id: &'a SecretLeaseId,
    capability_nonce: Uuid,
    binding: &'a SecretLeaseUseBinding,
    request: Option<&'a SecretLeaseRequest>,
}

fn command_digest<T: Serialize>(value: &T) -> Result<ContentHash, SecretBrokerError> {
    serde_json::to_vec(value)
        .map(ContentHash::blake3)
        .map_err(|_| SecretBrokerError::StateUnavailable)
}

fn issue_command_digest(request: &SecretLeaseRequest) -> Result<ContentHash, SecretBrokerError> {
    command_digest(&IssueCommandDigestMaterial {
        operation: "issue",
        request,
    })
}

fn renew_command_digest(
    handle: &SecretDeliveryHandle,
    request: &SecretLeaseRequest,
) -> Result<ContentHash, SecretBrokerError> {
    handle_command_digest("renew", handle, request.use_binding(), Some(request))
}

fn handle_command_digest(
    operation: &'static str,
    handle: &SecretDeliveryHandle,
    binding: &SecretLeaseUseBinding,
    request: Option<&SecretLeaseRequest>,
) -> Result<ContentHash, SecretBrokerError> {
    command_digest(&HandleCommandDigestMaterial {
        operation,
        delivery_handle_id: &handle.delivery_handle_id,
        secret_lease_id: &handle.secret_lease_id,
        capability_nonce: handle.capability_nonce,
        binding,
        request,
    })
}

fn retry_issue(
    state: &SecretBrokerState,
    key: &SecretCommandKey,
    digest: &ContentHash,
) -> Option<Result<SecretLeaseGrant, SecretBrokerError>> {
    let record = state.commands.get(key)?;
    if &record.semantic_digest != digest {
        return Some(Err(SecretBrokerError::CommandConflict));
    }
    Some(match &record.terminal {
        SecretCommandTerminal::Issue(result) => result.clone().map(|grant| grant.materialize()),
        _ => Err(SecretBrokerError::StateUnavailable),
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn retry_claim(
    state: &SecretBrokerState,
    key: &SecretCommandKey,
    digest: &ContentHash,
) -> Option<Result<SecretDeliveryClaim, SecretBrokerError>> {
    let record = state.commands.get(key)?;
    if &record.semantic_digest != digest {
        return Some(Err(SecretBrokerError::CommandConflict));
    }
    Some(match &record.terminal {
        SecretCommandTerminal::Claim(result) => result
            .clone()
            .map(|claim| SecretDeliveryClaim::from_stored(&claim)),
        _ => Err(SecretBrokerError::StateUnavailable),
    })
}

fn retry_renew(
    state: &SecretBrokerState,
    key: &SecretCommandKey,
    digest: &ContentHash,
) -> Option<Result<SecretLeaseGrant, SecretBrokerError>> {
    let record = state.commands.get(key)?;
    if &record.semantic_digest != digest {
        return Some(Err(SecretBrokerError::CommandConflict));
    }
    Some(match &record.terminal {
        SecretCommandTerminal::Renew(result) => result.clone().map(|grant| grant.materialize()),
        _ => Err(SecretBrokerError::StateUnavailable),
    })
}

fn retry_revoke(
    state: &SecretBrokerState,
    key: &SecretCommandKey,
    digest: &ContentHash,
) -> Option<Result<SecretLeaseSnapshot, SecretBrokerError>> {
    let record = state.commands.get(key)?;
    if &record.semantic_digest != digest {
        return Some(Err(SecretBrokerError::CommandConflict));
    }
    Some(match &record.terminal {
        SecretCommandTerminal::Revoke(result) => result.clone(),
        _ => Err(SecretBrokerError::StateUnavailable),
    })
}

fn credential_binding_matches<'a>(
    secret_ref: &'a SecretRefV2,
    binding: &SecretLeaseUseBinding,
) -> Option<&'a splendor_types::SecretCredentialAuthorizationV2> {
    secret_ref
        .allowed_credential_bindings()
        .iter()
        .find(|allowed| {
            allowed.driver_operation() == binding.driver_operation()
                && allowed.driver_declaration_revision() == binding.driver_declaration_revision()
                && allowed.credential_slot_id() == binding.credential_slot_id()
                && allowed.destination_schema() == binding.destination_schema()
                && allowed.delivery_exposure_profile() == binding.delivery_exposure_profile()
                && allowed.trusted_send_profile() == binding.trusted_send_profile()
                && allowed
                    .approved_destination_digests()
                    .contains(&binding.destination_digest())
        })
}

fn secret_ref_allows_binding(
    secret_ref: &SecretRefV2,
    binding: &SecretLeaseUseBinding,
    current_driver_declaration: &DriverOperationCredentialSinksV1,
    now: OffsetDateTime,
) -> bool {
    if secret_ref.tenant_id() != binding.tenant_id()
        || secret_ref.secret_ref_id() != binding.secret_ref_id()
        || secret_ref.secret_provider_id() != binding.secret_provider_id()
        || secret_ref.secret_ref_revision() != binding.secret_ref_revision()
        || secret_ref.provider_version_ref() != binding.provider_version_ref()
    {
        return false;
    }
    let Some(authorization) = credential_binding_matches(secret_ref, binding) else {
        return false;
    };
    if compare_secret_credential_authorization_v2(
        authorization,
        &secret_ref.classification(),
        &binding.intent(),
        current_driver_declaration,
    ) != SecretCredentialDeclarationComparisonV2::Matched
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

fn validated_authority_permit(
    state: &SecretBrokerState,
    authority: &SecretBrokerAuthorityContext<'_>,
    binding: &SecretLeaseUseBinding,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Option<ValidatedSecretBrokerPermit> {
    if authority.tenant_id != binding.tenant_id()
        || authority.principal_id != binding.principal_id()
        || authority.workload_id != binding.workload_id()
        || authority.node_id != binding.node_id()
        || authority.instance_id != binding.instance_id()
        || authority.audience_id != binding.audience_id()
        || authority.intent != binding.intent()
        || authority.purpose != binding.purpose()
        || now >= expires_at
    {
        return None;
    }
    let secret_ref = state
        .refs
        .get(&(binding.tenant_id().clone(), binding.secret_ref_id().clone()))?;
    if !secret_ref_allows_binding(
        secret_ref,
        binding,
        authority.current_driver_declaration,
        now,
    ) {
        return None;
    }
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
    (decision.status == AuthorityDecisionStatus::Allowed)
        .then_some(ValidatedSecretBrokerPermit { _private: () })
}

#[allow(clippy::too_many_arguments)]
fn evidence(
    event_id: SecretAccessEventId,
    command_id: ProcessLocalSecretBrokerCommandId,
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
        command_id,
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
    if !value.nanosecond().is_multiple_of(1_000) {
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
