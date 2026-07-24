use super::*;
use crate::capability::validate_local_profile_grant;
use crate::{CachedAuthorityGrant, OfflineAuthorityPolicy, ValidatedCapabilityGrant};
use splendor_types::{
    AuthorityRevocationId, CapabilityGrant, CapabilityGrantId, CapabilityGrantValidation,
    CapabilityGrantValidationKind, DriverCredentialDestinationDigest,
    DriverOperationCredentialSinkV1, DriverTrustedSendProfileV1, EffectCertainty, PrincipalId,
    RevocationRecord, RevocationStatus, SecretClassification, SecretCredentialAuthorizationV2,
    SecretDeliveryControlKind, SecretDeliveryExposureProfile, SecretLeasePolicy,
    SecretOfflineBehavior, SecretPurpose, SecretRefV2, SecretUseIntent, SecretUseRequirement,
    CAPABILITY_GRANT_SCHEMA_VERSION, REVOCATION_RECORD_SCHEMA_VERSION,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex, Weak};

fn parsed_time(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339).unwrap()
}

fn canonical(value: &str) -> CanonicalTimestampV1 {
    value.parse().unwrap()
}

fn uuid(index: u128) -> Uuid {
    Uuid::from_u128(0x018f_0a1b_2c3d_4e5f_8a9b_0000_0000_0000 + index)
}

fn tenant(index: u128) -> TenantId {
    TenantId::from(uuid(index))
}

fn principal(index: u128) -> PrincipalId {
    PrincipalId::from(uuid(index))
}

fn workload(index: u128) -> WorkloadId {
    WorkloadId::from(uuid(index))
}

fn node(index: u128) -> NodeId {
    NodeId::from(uuid(index))
}

fn instance(index: u128) -> InstanceId {
    InstanceId::from(uuid(index))
}

fn secret_id<T>(index: u128) -> T
where
    T: TryFrom<Uuid>,
    T::Error: fmt::Debug,
{
    T::try_from(uuid(index)).unwrap()
}

fn operation(name: &str) -> DriverOperationRef {
    DriverOperationRef {
        driver: "http".to_string(),
        operation: name.to_string(),
        schema_version: "splendor.driver.operation.v1".to_string(),
    }
}

fn destination_digest(byte: char) -> DriverCredentialDestinationDigest {
    format!("blake3:{}", byte.to_string().repeat(64))
        .parse()
        .unwrap()
}

fn trusted_profile(limit: u8) -> DriverTrustedSendProfileV1 {
    DriverTrustedSendProfileV1::try_trusted_injection(
        limit,
        vec![SecretDeliveryControlKind::TrustedInjectionBoundary],
    )
    .unwrap()
}

#[derive(Clone, Copy, Debug)]
enum BindingChange {
    Tenant,
    Principal,
    Workload,
    Operation,
    DeclarationRevision,
    Slot,
    DestinationSchema,
    DestinationDigest,
    Exposure,
    TrustedSend,
    Node,
    Instance,
    Audience,
    Ref,
    RefRevision,
    Provider,
    ProviderVersion,
    Intent,
    Purpose,
}

fn use_binding(change: Option<BindingChange>) -> SecretLeaseUseBinding {
    let exposure = if matches!(change, Some(BindingChange::Exposure)) {
        SecretDeliveryExposureProfile::MaterialExposed
    } else {
        SecretDeliveryExposureProfile::TrustedInjection
    };
    let profile = match change {
        Some(BindingChange::Exposure) => DriverTrustedSendProfileV1::not_applicable(),
        Some(BindingChange::TrustedSend) => trusted_profile(2),
        _ => trusted_profile(1),
    };
    SecretLeaseUseBinding::try_new(
        tenant(if matches!(change, Some(BindingChange::Tenant)) {
            102
        } else {
            2
        }),
        principal(if matches!(change, Some(BindingChange::Principal)) {
            103
        } else {
            3
        }),
        workload(if matches!(change, Some(BindingChange::Workload)) {
            104
        } else {
            4
        }),
        operation(if matches!(change, Some(BindingChange::Operation)) {
            "post"
        } else {
            "fetch"
        }),
        if matches!(change, Some(BindingChange::DeclarationRevision)) {
            2
        } else {
            1
        },
        secret_id(if matches!(change, Some(BindingChange::Slot)) {
            105
        } else {
            5
        }),
        if matches!(change, Some(BindingChange::DestinationSchema)) {
            "splendor.driver.destination.database.v1"
        } else {
            "splendor.driver.destination.http.v1"
        },
        destination_digest(
            if matches!(change, Some(BindingChange::DestinationDigest)) {
                '2'
            } else {
                '1'
            },
        ),
        exposure,
        profile,
        node(if matches!(change, Some(BindingChange::Node)) {
            106
        } else {
            6
        }),
        instance(if matches!(change, Some(BindingChange::Instance)) {
            107
        } else {
            7
        }),
        secret_id(if matches!(change, Some(BindingChange::Audience)) {
            108
        } else {
            8
        }),
        secret_id(if matches!(change, Some(BindingChange::Ref)) {
            109
        } else {
            9
        }),
        if matches!(change, Some(BindingChange::RefRevision)) {
            2
        } else {
            1
        },
        secret_id(if matches!(change, Some(BindingChange::Provider)) {
            110
        } else {
            10
        }),
        if matches!(change, Some(BindingChange::ProviderVersion)) {
            "version-2"
        } else {
            "version-1"
        }
        .parse()
        .unwrap(),
        if matches!(change, Some(BindingChange::Intent)) {
            SecretUseIntent::Sign
        } else {
            SecretUseIntent::Authenticate
        },
        if matches!(change, Some(BindingChange::Purpose)) {
            SecretPurpose::ArtifactStoreAccess
        } else {
            SecretPurpose::ExternalServiceAccess
        },
    )
    .unwrap()
}

fn declaration(binding: &SecretLeaseUseBinding) -> DriverOperationCredentialSinksV1 {
    let sink = DriverOperationCredentialSinkV1::try_new(
        binding.credential_slot_id(),
        vec![SecretClassification::AuthenticationCredential],
        vec![SecretUseIntent::Authenticate],
        binding.destination_schema(),
        binding.delivery_exposure_profile(),
        binding.trusted_send_profile().clone(),
    )
    .unwrap();
    DriverOperationCredentialSinksV1::try_new(
        binding.driver_operation().clone(),
        binding.driver_declaration_revision(),
        vec![sink],
    )
    .unwrap()
}

fn default_policy(max_uses: u64, renewable: bool) -> SecretLeasePolicy {
    SecretLeasePolicy::try_new(300, 600, max_uses, renewable, 0).unwrap()
}

fn secret_ref(
    provider_id: SecretProviderId,
    policy: SecretLeasePolicy,
    classification: SecretClassification,
) -> SecretRefV2 {
    secret_ref_with_window(
        provider_id,
        policy,
        classification,
        "2026-07-24T11:00:00.000000Z",
        None,
    )
}

fn secret_ref_with_window(
    provider_id: SecretProviderId,
    policy: SecretLeasePolicy,
    classification: SecretClassification,
    created_at: &str,
    disabled_at: Option<&str>,
) -> SecretRefV2 {
    let binding = use_binding(None);
    secret_ref_for_binding(
        &binding,
        provider_id,
        policy,
        classification,
        binding.secret_ref_revision(),
        vec![SecretDeliveryMethod::InheritedFd],
        created_at,
        disabled_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn secret_ref_for_binding(
    binding: &SecretLeaseUseBinding,
    provider_id: SecretProviderId,
    policy: SecretLeasePolicy,
    classification: SecretClassification,
    secret_ref_revision: u64,
    delivery_methods: Vec<SecretDeliveryMethod>,
    created_at: &str,
    disabled_at: Option<&str>,
) -> SecretRefV2 {
    let authorization = SecretCredentialAuthorizationV2::try_new(
        binding.driver_operation().clone(),
        binding.driver_declaration_revision(),
        binding.credential_slot_id(),
        binding.destination_schema(),
        binding.delivery_exposure_profile(),
        binding.trusted_send_profile().clone(),
        vec![binding.destination_digest()],
    )
    .unwrap();
    SecretRefV2::try_new(
        binding.secret_ref_id().clone(),
        secret_ref_revision,
        binding.tenant_id().clone(),
        provider_id,
        "test",
        "http-credential",
        binding.provider_version_ref().clone(),
        classification,
        vec![authorization],
        delivery_methods,
        policy,
        SecretOfflineBehavior::Deny,
        created_at,
        disabled_at.map(str::to_owned),
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn lease_request(
    request_index: u128,
    binding: SecretLeaseUseBinding,
    starts_at: &str,
    expires_at: &str,
    requested_at: &str,
    max_uses: u64,
) -> SecretLeaseRequest {
    let duration =
        u64::try_from((parsed_time(expires_at) - parsed_time(starts_at)).whole_seconds()).unwrap();
    let requirement = SecretUseRequirement::try_new(
        binding.secret_ref_id().clone(),
        binding.credential_slot_id(),
        binding.intent(),
        binding.purpose(),
        vec![SecretDeliveryMethod::InheritedFd],
        duration,
        max_uses,
        true,
    )
    .unwrap();
    SecretLeaseRequest::try_new(
        secret_id(request_index),
        binding,
        requirement,
        canonical(starts_at),
        canonical(expires_at),
        canonical(requested_at),
    )
    .unwrap()
}

fn initial_request(request_index: u128, max_uses: u64) -> SecretLeaseRequest {
    lease_request(
        request_index,
        use_binding(None),
        "2026-07-24T12:00:00.000000Z",
        "2026-07-24T12:05:00.000000Z",
        "2026-07-24T12:00:00.000000Z",
        max_uses,
    )
}

#[allow(clippy::too_many_arguments)]
fn custom_request(
    request_index: u128,
    binding: SecretLeaseUseBinding,
    starts_at: &str,
    expires_at: &str,
    requested_at: &str,
    max_uses: u64,
    delivery_methods: Vec<SecretDeliveryMethod>,
) -> SecretLeaseRequest {
    let duration =
        u64::try_from((parsed_time(expires_at) - parsed_time(starts_at)).whole_seconds()).unwrap();
    let requirement = SecretUseRequirement::try_new(
        binding.secret_ref_id().clone(),
        binding.credential_slot_id(),
        binding.intent(),
        binding.purpose(),
        delivery_methods,
        duration,
        max_uses,
        true,
    )
    .unwrap();
    SecretLeaseRequest::try_new(
        secret_id(request_index),
        binding,
        requirement,
        canonical(starts_at),
        canonical(expires_at),
        canonical(requested_at),
    )
    .unwrap()
}

#[derive(Debug)]
struct ManualClock {
    now: Mutex<Option<OffsetDateTime>>,
    reads: AtomicU64,
}

impl ManualClock {
    fn new(now: OffsetDateTime) -> Self {
        Self {
            now: Mutex::new(Some(now)),
            reads: AtomicU64::new(0),
        }
    }

    fn set(&self, now: OffsetDateTime) {
        *self.now.lock().unwrap() = Some(now);
    }

    fn reads(&self) -> u64 {
        self.reads.load(Ordering::SeqCst)
    }
}

impl SecretBrokerClock for ManualClock {
    fn now_utc(&self) -> Option<OffsetDateTime> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        *self.now.lock().ok()?
    }
}

#[derive(Debug, Default)]
struct SequenceIds {
    next: AtomicU64,
}

impl SequenceIds {
    fn count(&self) -> u64 {
        self.next.load(Ordering::SeqCst)
    }
}

impl SecretBrokerIdSource for SequenceIds {
    fn next_uuid(&self, _kind: SecretBrokerIdKind) -> Option<Uuid> {
        let ordinal = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        Some(uuid(10_000 + u128::from(ordinal)))
    }
}

#[derive(Debug)]
struct FailEventIds {
    next: AtomicU64,
}

impl SecretBrokerIdSource for FailEventIds {
    fn next_uuid(&self, kind: SecretBrokerIdKind) -> Option<Uuid> {
        if kind == SecretBrokerIdKind::AccessEvent {
            return None;
        }
        let ordinal = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        Some(uuid(20_000 + u128::from(ordinal)))
    }
}

#[derive(Debug)]
struct NilIds;

impl SecretBrokerIdSource for NilIds {
    fn next_uuid(&self, _kind: SecretBrokerIdKind) -> Option<Uuid> {
        Some(Uuid::nil())
    }
}

#[derive(Debug)]
struct ScriptedIds {
    values: Vec<Uuid>,
    next: AtomicU64,
}

impl ScriptedIds {
    fn new(values: impl IntoIterator<Item = u128>) -> Self {
        Self {
            values: values.into_iter().map(uuid).collect(),
            next: AtomicU64::new(0),
        }
    }
}

impl SecretBrokerIdSource for ScriptedIds {
    fn next_uuid(&self, _kind: SecretBrokerIdKind) -> Option<Uuid> {
        let index = usize::try_from(self.next.fetch_add(1, Ordering::SeqCst)).ok()?;
        self.values.get(index).copied()
    }
}

#[derive(Debug, Default)]
struct ToggleFailIds {
    next: AtomicU64,
    fail_kind: Mutex<Option<SecretBrokerIdKind>>,
}

impl ToggleFailIds {
    fn fail(&self, kind: SecretBrokerIdKind) {
        *self.fail_kind.lock().unwrap() = Some(kind);
    }

    fn allow_all(&self) {
        *self.fail_kind.lock().unwrap() = None;
    }
}

impl SecretBrokerIdSource for ToggleFailIds {
    fn next_uuid(&self, kind: SecretBrokerIdKind) -> Option<Uuid> {
        if self.fail_kind.lock().ok()?.as_ref() == Some(&kind) {
            return None;
        }
        let ordinal = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        Some(uuid(40_000 + u128::from(ordinal)))
    }
}

#[derive(Default)]
struct BrokerLockProbe {
    broker: Mutex<Option<Weak<ProcessLocalSecretBroker>>>,
    callbacks: AtomicU64,
    failed: AtomicBool,
}

impl BrokerLockProbe {
    fn attach(&self, broker: &Arc<ProcessLocalSecretBroker>) {
        *self.broker.lock().unwrap() = Some(Arc::downgrade(broker));
    }

    fn observe(&self) {
        self.callbacks.fetch_add(1, Ordering::SeqCst);
        let broker = self
            .broker
            .lock()
            .ok()
            .and_then(|broker| broker.as_ref().and_then(Weak::upgrade));
        let Some(broker) = broker else {
            self.failed.store(true, Ordering::SeqCst);
            return;
        };
        let state_unlocked = broker.state.try_lock().is_ok();
        let mutation_gate_unlocked = broker.mutation_gate.try_lock().is_ok();
        let reentrant_mutation_denied = broker.lock_mutation().is_err();
        if !state_unlocked || !mutation_gate_unlocked || !reentrant_mutation_denied {
            self.failed.store(true, Ordering::SeqCst);
        }
    }
}

struct ProbingClock {
    now: OffsetDateTime,
    probe: Arc<BrokerLockProbe>,
}

impl SecretBrokerClock for ProbingClock {
    fn now_utc(&self) -> Option<OffsetDateTime> {
        self.probe.observe();
        Some(self.now)
    }
}

struct ProbingIds {
    next: AtomicU64,
    probe: Arc<BrokerLockProbe>,
}

impl SecretBrokerIdSource for ProbingIds {
    fn next_uuid(&self, _kind: SecretBrokerIdKind) -> Option<Uuid> {
        self.probe.observe();
        let ordinal = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        Some(uuid(30_000 + u128::from(ordinal)))
    }
}

struct PanicOnceClock {
    now: OffsetDateTime,
    panicked: AtomicBool,
}

impl SecretBrokerClock for PanicOnceClock {
    fn now_utc(&self) -> Option<OffsetDateTime> {
        if !self.panicked.swap(true, Ordering::SeqCst) {
            panic!("clock callback panic");
        }
        Some(self.now)
    }
}

#[derive(Debug)]
struct TrapProvider {
    provider_id: SecretProviderId,
    calls: AtomicU64,
}

impl TrapProvider {
    fn new(provider_id: SecretProviderId) -> Self {
        Self {
            provider_id,
            calls: AtomicU64::new(0),
        }
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    fn unavailable<T>(&self) -> Result<T, SecretProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(SecretProviderError::new(
            SecretProviderErrorCode::Unavailable,
        ))
    }
}

impl SecretProvider for TrapProvider {
    fn provider_id(&self) -> &SecretProviderId {
        &self.provider_id
    }

    fn fetch<'session>(
        &self,
        _request: &'session SecretProviderFetchRequest,
    ) -> Result<SecretProviderFetchResult<'session>, SecretProviderError> {
        self.unavailable()
    }

    fn renew(
        &self,
        _request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.unavailable()
    }

    fn revoke(
        &self,
        _request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.unavailable()
    }

    fn audit(
        &self,
        _request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderAuditEvidence, SecretProviderError> {
        self.unavailable()
    }

    fn health(
        &self,
        _request: &SecretProviderControlRequest,
    ) -> Result<SecretProviderHealthEvidence, SecretProviderError> {
        self.unavailable()
    }
}

struct BrokerFixture {
    broker: Arc<ProcessLocalSecretBroker>,
    clock: Arc<ManualClock>,
    ids: Arc<SequenceIds>,
    provider: Arc<TrapProvider>,
}

fn broker_fixture(policy: SecretLeasePolicy) -> BrokerFixture {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let clock = Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")));
    let ids = Arc::new(SequenceIds::default());
    let broker = ProcessLocalSecretBroker::with_sources(
        tenant(2),
        vec![secret_ref(
            provider.provider_id.clone(),
            policy,
            SecretClassification::AuthenticationCredential,
        )],
        vec![provider.clone()],
        clock.clone(),
        ids.clone(),
    )
    .unwrap();
    BrokerFixture {
        broker: Arc::new(broker),
        clock,
        ids,
        provider,
    }
}

#[derive(Clone, Copy)]
enum AuthorityState {
    Active,
    Missing,
    Expired,
    Revoked,
    MissingSnapshot,
}

struct AuthorityFixture {
    cache: AuthorityGrantCache,
    revocations: Option<RevocationSnapshot>,
    policy: OfflineAuthorityPolicy,
}

impl AuthorityFixture {
    fn context<'a>(
        &'a self,
        expected: &'a SecretLeaseUseBinding,
        current_declaration: &'a DriverOperationCredentialSinksV1,
    ) -> SecretBrokerAuthorityContext<'a> {
        SecretBrokerAuthorityContext::new(
            &self.cache,
            self.revocations.as_ref(),
            &self.policy,
            expected.tenant_id(),
            expected.principal_id(),
            expected.workload_id(),
            expected.node_id(),
            expected.instance_id(),
            expected.audience_id(),
            expected.intent(),
            expected.purpose(),
            current_declaration,
        )
    }
}

fn validated_test_grant(
    binding: &SecretLeaseUseBinding,
    not_before: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> ValidatedCapabilityGrant {
    validate_local_profile_grant(CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: CapabilityGrantId::from(uuid(50)),
        issuer: principal(51),
        subject: binding.principal_id().clone(),
        parent_grant_ids: Vec::new(),
        operations: vec![secret_driver_invoke_operation(binding.driver_operation())],
        scope: CapabilityScope {
            tenant_ids: Some(vec![binding.tenant_id().clone()]),
            workload_ids: Some(vec![binding.workload_id().clone()]),
            driver_operations: Some(vec![binding.driver_operation().clone()]),
            audiences: Some(vec![binding.audience_id().to_string()]),
            time: AuthorityTimeScope {
                not_before: Some(not_before),
                expires_at: Some(expires_at),
            },
            ..CapabilityScope::default()
        },
        not_before,
        expires_at,
        revocation_ref: Some("revocation:secret-test".to_string()),
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth: 0,
        validation: Some(CapabilityGrantValidation {
            validation_kind: CapabilityGrantValidationKind::LocallyValidated,
            algorithm: "test-owned-authority-profile".to_string(),
            key_id: None,
            digest: "blake3:test-owned-authority-profile".to_string(),
            signature: None,
        }),
        metadata: Default::default(),
    })
    .unwrap()
}

fn authority_fixture(state: AuthorityState) -> AuthorityFixture {
    let binding = use_binding(None);
    authority_fixture_for(&binding, state)
}

fn authority_fixture_for(
    binding: &SecretLeaseUseBinding,
    state: AuthorityState,
) -> AuthorityFixture {
    let now = parsed_time("2026-07-24T12:00:00.000000Z");
    let policy = OfflineAuthorityPolicy::connected(Duration::hours(1)).unwrap();
    if matches!(state, AuthorityState::Missing) {
        return AuthorityFixture {
            cache: AuthorityGrantCache::new(),
            revocations: Some(
                RevocationSnapshot::try_new(
                    Vec::new(),
                    now - Duration::minutes(1),
                    now + Duration::hours(1),
                )
                .unwrap(),
            ),
            policy,
        };
    }
    let expires_at = if matches!(state, AuthorityState::Expired) {
        now - Duration::seconds(1)
    } else {
        now + Duration::hours(2)
    };
    let grant = validated_test_grant(binding, now - Duration::minutes(5), expires_at);
    let grant_id = grant.grant().grant_id.clone();
    let mut cache = AuthorityGrantCache::new();
    cache.insert_cached(
        CachedAuthorityGrant::try_new(
            grant,
            if expires_at > now {
                now - Duration::seconds(1)
            } else {
                now - Duration::minutes(4)
            },
            if expires_at > now {
                now + Duration::hours(1)
            } else {
                expires_at
            },
        )
        .unwrap(),
    );
    let records = if matches!(state, AuthorityState::Revoked) {
        vec![RevocationRecord {
            schema_version: REVOCATION_RECORD_SCHEMA_VERSION.to_string(),
            revocation_id: AuthorityRevocationId::from(uuid(52)),
            grant_id,
            revocation_ref: Some("revocation:secret-test".to_string()),
            status: RevocationStatus::Revoked {
                reason: "test".to_string(),
            },
            revoked_at: Some(now - Duration::seconds(1)),
        }]
    } else {
        Vec::new()
    };
    AuthorityFixture {
        cache,
        revocations: if matches!(state, AuthorityState::MissingSnapshot) {
            None
        } else {
            Some(
                RevocationSnapshot::try_new(
                    records,
                    now - Duration::minutes(1),
                    now + Duration::hours(1),
                )
                .unwrap(),
            )
        },
        policy,
    }
}

fn active_authority_fixture_at(
    binding: &SecretLeaseUseBinding,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> AuthorityFixture {
    let grant = validated_test_grant(binding, now - Duration::minutes(1), expires_at);
    let mut cache = AuthorityGrantCache::new();
    cache.insert_cached(CachedAuthorityGrant::try_new(grant, now, expires_at).unwrap());
    AuthorityFixture {
        cache,
        revocations: Some(RevocationSnapshot::try_new(Vec::new(), now, expires_at).unwrap()),
        policy: OfflineAuthorityPolicy::connected(Duration::hours(1)).unwrap(),
    }
}

fn active_context<'a>(
    authority: &'a AuthorityFixture,
    binding: &'a SecretLeaseUseBinding,
    declaration: &'a DriverOperationCredentialSinksV1,
) -> SecretBrokerAuthorityContext<'a> {
    authority.context(binding, declaration)
}

fn all_events(broker: &ProcessLocalSecretBroker) -> Vec<SecretAccessEvidence> {
    let page = broker.replay_page(0, 128).unwrap();
    page.events
}

fn config_error(
    result: Result<ProcessLocalSecretBroker, SecretBrokerConfigError>,
) -> SecretBrokerConfigError {
    match result {
        Ok(_) => panic!("expected broker configuration error"),
        Err(error) => error,
    }
}

fn applied<T>(result: Result<SecretBrokerCommandOutcome<T>, SecretBrokerError>) -> T {
    match result.expect("command must succeed") {
        SecretBrokerCommandOutcome::Applied(value) => value,
        SecretBrokerCommandOutcome::Historical(_) => {
            panic!("first command application returned historical metadata")
        }
    }
}

fn historical<T>(
    result: Result<SecretBrokerCommandOutcome<T>, SecretBrokerError>,
) -> Box<HistoricalSecretBrokerReceipt> {
    match result.expect("exact duplicate must pass current visibility") {
        SecretBrokerCommandOutcome::Historical(receipt) => receipt,
        SecretBrokerCommandOutcome::Applied(_) => {
            panic!("exact duplicate minted a second live capability")
        }
    }
}

#[test]
fn injected_clock_and_id_callbacks_run_without_broker_locks() {
    let probe = Arc::new(BrokerLockProbe::default());
    let clock = Arc::new(ProbingClock {
        now: parsed_time("2026-07-24T12:00:00.000000Z"),
        probe: probe.clone(),
    });
    let ids = Arc::new(ProbingIds {
        next: AtomicU64::new(0),
        probe: probe.clone(),
    });
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let provider_port: Arc<dyn SecretProvider> = provider.clone();
    let broker = Arc::new(
        ProcessLocalSecretBroker::with_sources(
            tenant(2),
            vec![secret_ref(
                provider.provider_id.clone(),
                default_policy(1, true),
                SecretClassification::AuthenticationCredential,
            )],
            vec![provider_port],
            clock,
            ids,
        )
        .unwrap(),
    );
    probe.attach(&broker);
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);

    broker
        .issue_lease(
            initial_request(90, 1),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();

    assert_eq!(probe.callbacks.load(Ordering::SeqCst), 6);
    assert!(!probe.failed.load(Ordering::SeqCst));
    assert_eq!(provider.calls(), 0);
}

#[test]
fn panicking_clock_callback_fails_closed_without_poisoning_broker_state() {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let provider_port: Arc<dyn SecretProvider> = provider.clone();
    let broker = ProcessLocalSecretBroker::with_sources(
        tenant(2),
        vec![secret_ref(
            provider.provider_id.clone(),
            default_policy(1, true),
            SecretClassification::AuthenticationCredential,
        )],
        vec![provider_port],
        Arc::new(PanicOnceClock {
            now: parsed_time("2026-07-24T12:00:00.000000Z"),
            panicked: AtomicBool::new(false),
        }),
        Arc::new(SequenceIds::default()),
    )
    .unwrap();
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let request = initial_request(95, 1);

    assert!(matches!(
        broker.issue_lease(
            request.clone(),
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::StateUnavailable)
    ));
    broker
        .issue_lease(request, &active_context(&authority, &binding, &current))
        .unwrap();
    assert_eq!(provider.calls(), 0);
}

#[test]
fn issue_claim_and_exact_retry_are_bound_and_provider_free() {
    let fixture = broker_fixture(default_policy(1, true));
    assert_eq!(fixture.broker.registered_provider_count(), 1);
    let binding = use_binding(None);
    let declaration = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let request = initial_request(100, 1);
    let grant = fixture
        .broker
        .issue_lease(
            request.clone(),
            &active_context(&authority, &binding, &declaration),
        )
        .unwrap();
    let reads = fixture.clock.reads();
    let ids = fixture.ids.count();
    let event_count = all_events(&fixture.broker).len();
    let retry = fixture
        .broker
        .issue_lease(request, &active_context(&authority, &binding, &declaration))
        .unwrap();
    let receipt = retry
        .historical()
        .expect("an exact issue duplicate must be historical only");
    assert_eq!(
        receipt.evidence().secret_lease_id(),
        Some(grant.snapshot().secret_lease_id())
    );
    assert_eq!(
        receipt.evidence().kind(),
        SecretAccessEvidenceKind::LeaseIssued
    );
    assert_eq!(fixture.clock.reads(), reads + 1);
    assert_eq!(fixture.ids.count(), ids);
    assert_eq!(all_events(&fixture.broker).len(), event_count);
    let other = fixture
        .broker
        .issue_lease(
            initial_request(102, 1),
            &active_context(&authority, &binding, &declaration),
        )
        .unwrap();

    let attempt: SecretUseAttemptId = secret_id(101);
    let claim = fixture
        .broker
        .claim_use(
            attempt.clone(),
            grant.handle(),
            &binding,
            &active_context(&authority, &binding, &declaration),
        )
        .unwrap();
    let claim_ids = fixture.ids.count();
    let claim_events = all_events(&fixture.broker).len();
    let claim_retry = fixture
        .broker
        .claim_use(
            attempt,
            grant.handle(),
            &binding,
            &active_context(&authority, &binding, &declaration),
        )
        .unwrap();
    let claim_receipt = claim_retry
        .historical()
        .expect("an exact claim duplicate must be historical only");
    assert_eq!(
        claim_receipt.evidence().secret_use_claim_id(),
        Some(claim.secret_use_claim_id())
    );
    assert_eq!(
        claim.secret_use_attempt_id(),
        &secret_id::<SecretUseAttemptId>(101)
    );
    assert_eq!(claim.secret_lease_id(), grant.snapshot().secret_lease_id());
    assert_eq!(
        claim.delivery_handle_id(),
        grant.snapshot().delivery_handle_id()
    );
    assert_eq!(claim.use_binding(), &binding);
    assert_eq!(
        claim.expires_at(),
        parsed_time("2026-07-24T12:05:00.000000Z")
    );
    assert_eq!(claim.revocation_generation(), 1);
    assert_eq!(format!("{:?}", &*claim), "SecretDeliveryClaim(<opaque>)");
    assert_eq!(
        format!("{:?}", grant.handle()),
        "SecretDeliveryHandle(<opaque>)"
    );
    assert_eq!(fixture.ids.count(), claim_ids);
    assert_eq!(all_events(&fixture.broker).len(), claim_events);
    let denied_attempt: SecretUseAttemptId = secret_id(103);
    assert!(matches!(
        fixture.broker.claim_use(
            denied_attempt.clone(),
            grant.handle(),
            &binding,
            &active_context(&authority, &binding, &declaration),
        ),
        Err(SecretBrokerError::MaxUsesExceeded)
    ));
    let denied_reads = fixture.clock.reads();
    let denied_ids = fixture.ids.count();
    let denied_events = all_events(&fixture.broker).len();
    assert!(matches!(
        fixture.broker.claim_use(
            denied_attempt.clone(),
            grant.handle(),
            &binding,
            &active_context(&authority, &binding, &declaration),
        ),
        Err(SecretBrokerError::MaxUsesExceeded)
    ));
    assert_eq!(fixture.clock.reads(), denied_reads + 1);
    assert_eq!(fixture.ids.count(), denied_ids);
    assert_eq!(all_events(&fixture.broker).len(), denied_events);
    assert!(matches!(
        fixture.broker.claim_use(
            denied_attempt,
            other.handle(),
            &binding,
            &active_context(&authority, &binding, &declaration),
        ),
        Err(SecretBrokerError::SecretNotAvailable)
    ));
    assert_eq!(fixture.provider.calls(), 0);
    assert_eq!(
        fixture
            .broker
            .inspect_lease(grant.snapshot().secret_lease_id())
            .unwrap()
            .unwrap()
            .status(),
        SecretLeaseStatus::Exhausted
    );
}

#[test]
fn every_exact_binding_axis_and_current_declaration_fail_closed() {
    let fixture = broker_fixture(default_policy(3, true));
    let baseline = use_binding(None);
    let current = declaration(&baseline);
    let authority = authority_fixture(AuthorityState::Active);
    let changes = [
        BindingChange::Tenant,
        BindingChange::Principal,
        BindingChange::Workload,
        BindingChange::Operation,
        BindingChange::DeclarationRevision,
        BindingChange::Slot,
        BindingChange::DestinationSchema,
        BindingChange::DestinationDigest,
        BindingChange::Exposure,
        BindingChange::TrustedSend,
        BindingChange::Node,
        BindingChange::Instance,
        BindingChange::Audience,
        BindingChange::Ref,
        BindingChange::RefRevision,
        BindingChange::Provider,
        BindingChange::ProviderVersion,
        BindingChange::Intent,
        BindingChange::Purpose,
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let changed = use_binding(Some(change));
        let result = fixture.broker.issue_lease(
            lease_request(
                200 + index as u128,
                changed,
                "2026-07-24T12:00:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                1,
            ),
            &active_context(&authority, &baseline, &current),
        );
        assert!(
            matches!(result, Err(SecretBrokerError::SecretNotAvailable)),
            "unexpected result for {change:?}"
        );
        assert!(all_events(&fixture.broker).is_empty());
    }

    let stale_binding = use_binding(Some(BindingChange::DeclarationRevision));
    let stale_declaration = declaration(&stale_binding);
    let denied = fixture.broker.issue_lease(
        initial_request(299, 1),
        &active_context(&authority, &baseline, &stale_declaration),
    );
    assert!(matches!(denied, Err(SecretBrokerError::SecretNotAvailable)));
}

#[test]
fn missing_expired_revoked_and_unavailable_current_authority_stay_denied() {
    for (index, state) in [
        AuthorityState::Missing,
        AuthorityState::Expired,
        AuthorityState::Revoked,
        AuthorityState::MissingSnapshot,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = broker_fixture(default_policy(2, true));
        let binding = use_binding(None);
        let current = declaration(&binding);
        let authority = authority_fixture(state);
        assert!(matches!(
            fixture.broker.issue_lease(
                initial_request(300 + index as u128, 1),
                &active_context(&authority, &binding, &current),
            ),
            Err(SecretBrokerError::SecretNotAvailable)
        ));
        assert!(all_events(&fixture.broker).is_empty());
        assert_eq!(fixture.ids.count(), 0);
        assert_eq!(fixture.provider.calls(), 0);
    }
}

#[test]
fn exact_lease_expiry_is_terminal_and_never_reaches_provider() {
    let fixture = broker_fixture(default_policy(2, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let grant = fixture
        .broker
        .issue_lease(
            initial_request(340, 1),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    fixture
        .clock
        .set(parsed_time("2026-07-24T12:05:00.000000Z"));
    let attempt: SecretUseAttemptId = secret_id(341);
    assert!(matches!(
        fixture.broker.claim_use(
            attempt.clone(),
            grant.handle(),
            &binding,
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::LeaseExpired)
    ));
    let reads = fixture.clock.reads();
    let ids = fixture.ids.count();
    let events = all_events(&fixture.broker).len();
    assert!(matches!(
        fixture.broker.claim_use(
            attempt,
            grant.handle(),
            &binding,
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::LeaseExpired)
    ));
    assert_eq!(fixture.clock.reads(), reads + 1);
    assert_eq!(fixture.ids.count(), ids);
    assert_eq!(all_events(&fixture.broker).len(), events);
    assert_eq!(
        fixture
            .broker
            .inspect_lease(grant.snapshot().secret_lease_id())
            .unwrap()
            .unwrap()
            .status(),
        SecretLeaseStatus::Expired
    );
    assert_eq!(fixture.provider.calls(), 0);
}

#[test]
fn delivery_duration_and_use_requests_can_only_narrow_current_ref_policy() {
    let fixture = broker_fixture(default_policy(3, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let requests = [
        custom_request(
            350,
            binding.clone(),
            "2026-07-24T12:00:00.000000Z",
            "2026-07-24T12:05:00.000000Z",
            "2026-07-24T12:00:00.000000Z",
            1,
            vec![SecretDeliveryMethod::EnvironmentVariable],
        ),
        custom_request(
            351,
            binding.clone(),
            "2026-07-24T12:00:00.000000Z",
            "2026-07-24T12:05:01.000000Z",
            "2026-07-24T12:00:00.000000Z",
            1,
            vec![SecretDeliveryMethod::InheritedFd],
        ),
        custom_request(
            352,
            binding.clone(),
            "2026-07-24T12:00:00.000000Z",
            "2026-07-24T12:05:00.000000Z",
            "2026-07-24T12:00:00.000000Z",
            4,
            vec![SecretDeliveryMethod::InheritedFd],
        ),
    ];
    for request in requests {
        assert!(matches!(
            fixture
                .broker
                .issue_lease(request, &active_context(&authority, &binding, &current),),
            Err(SecretBrokerError::SecretNotAvailable)
        ));
    }
    assert_eq!(fixture.provider.calls(), 0);
}

#[test]
fn environment_delivery_is_reserved_even_when_allowed_and_safe_fallback_is_selected() {
    let binding = use_binding(None);
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let broker = ProcessLocalSecretBroker::with_sources(
        tenant(2),
        vec![secret_ref_for_binding(
            &binding,
            provider.provider_id.clone(),
            default_policy(3, true),
            SecretClassification::AuthenticationCredential,
            binding.secret_ref_revision(),
            vec![
                SecretDeliveryMethod::EnvironmentVariable,
                SecretDeliveryMethod::InheritedFd,
            ],
            "2026-07-24T11:00:00.000000Z",
            None,
        )],
        vec![provider.clone()],
        Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
        Arc::new(SequenceIds::default()),
    )
    .unwrap();
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);

    let environment_only = custom_request(
        390,
        binding.clone(),
        "2026-07-24T12:00:00.000000Z",
        "2026-07-24T12:05:00.000000Z",
        "2026-07-24T12:00:00.000000Z",
        1,
        vec![SecretDeliveryMethod::EnvironmentVariable],
    );
    assert_eq!(
        broker
            .issue_lease(
                environment_only.clone(),
                &active_context(&authority, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );
    let events = all_events(&broker).len();
    let historical_denial = broker.issue_lease(
        environment_only,
        &active_context(&authority, &binding, &current),
    );
    assert_eq!(
        historical_denial.unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );
    assert_eq!(all_events(&broker).len(), events);

    let safe_fallback = applied(broker.issue_lease(
        custom_request(
            391,
            binding.clone(),
            "2026-07-24T12:00:00.000000Z",
            "2026-07-24T12:05:00.000000Z",
            "2026-07-24T12:00:00.000000Z",
            1,
            vec![
                SecretDeliveryMethod::EnvironmentVariable,
                SecretDeliveryMethod::InheritedFd,
            ],
        ),
        &active_context(&authority, &binding, &current),
    ));
    assert_eq!(
        safe_fallback.snapshot().selected_delivery_method(),
        SecretDeliveryMethod::InheritedFd
    );
    assert_eq!(provider.calls(), 0);
}

#[test]
fn idempotency_conflicts_are_hidden_and_unauthorized_probes_do_not_poison_commands() {
    let fixture = broker_fixture(default_policy(3, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);
    fixture
        .broker
        .issue_lease(
            initial_request(400, 1),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    assert!(matches!(
        fixture.broker.issue_lease(
            initial_request(400, 2),
            &active_context(&active, &binding, &current),
        ),
        Err(SecretBrokerError::SecretNotAvailable)
    ));

    let missing = authority_fixture(AuthorityState::Missing);
    let denied_request = initial_request(401, 1);
    assert!(matches!(
        fixture.broker.issue_lease(
            denied_request.clone(),
            &active_context(&missing, &binding, &current),
        ),
        Err(SecretBrokerError::SecretNotAvailable)
    ));
    let reads = fixture.clock.reads();
    let ids = fixture.ids.count();
    let events = all_events(&fixture.broker).len();
    let applied = fixture
        .broker
        .issue_lease(denied_request, &active_context(&active, &binding, &current))
        .unwrap();
    assert!(matches!(applied, SecretBrokerCommandOutcome::Applied(_)));
    assert!(fixture.clock.reads() > reads);
    assert!(fixture.ids.count() > ids);
    assert!(all_events(&fixture.broker).len() > events);
}

#[test]
fn successful_issue_duplicate_is_historical_only_after_current_visibility() {
    let fixture = broker_fixture(default_policy(3, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);
    let request = initial_request(450, 3);
    let grant = applied(fixture.broker.issue_lease(
        request.clone(),
        &active_context(&active, &binding, &current),
    ));
    let ids = fixture.ids.count();
    let events = all_events(&fixture.broker).len();
    let retained_time = fixture.broker.lock_state().unwrap().max_observed_time;

    let receipt = historical(fixture.broker.issue_lease(
        request.clone(),
        &active_context(&active, &binding, &current),
    ));
    assert_eq!(
        receipt.evidence().secret_lease_id(),
        Some(grant.snapshot().secret_lease_id())
    );
    assert_eq!(
        receipt.evidence().occurred_at(),
        grant.snapshot().issued_at()
    );
    assert_eq!(fixture.ids.count(), ids);
    assert_eq!(all_events(&fixture.broker).len(), events);
    assert_eq!(
        fixture.broker.lock_state().unwrap().max_observed_time,
        retained_time
    );

    for state in [
        AuthorityState::Missing,
        AuthorityState::Expired,
        AuthorityState::Revoked,
        AuthorityState::MissingSnapshot,
    ] {
        let unavailable = authority_fixture(state);
        assert_eq!(
            fixture
                .broker
                .issue_lease(
                    request.clone(),
                    &active_context(&unavailable, &binding, &current),
                )
                .unwrap_err(),
            SecretBrokerError::SecretNotAvailable
        );
    }

    let stale_binding = use_binding(Some(BindingChange::DeclarationRevision));
    let stale_declaration = declaration(&stale_binding);
    assert_eq!(
        fixture
            .broker
            .issue_lease(
                request.clone(),
                &active_context(&active, &binding, &stale_declaration),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );

    let ref_key = (binding.tenant_id().clone(), binding.secret_ref_id().clone());
    fixture.broker.lock_state().unwrap().refs.insert(
        ref_key.clone(),
        secret_ref_for_binding(
            &binding,
            fixture.provider.provider_id.clone(),
            default_policy(3, true),
            SecretClassification::AuthenticationCredential,
            binding.secret_ref_revision(),
            vec![SecretDeliveryMethod::InheritedFd],
            "2026-07-24T11:00:00.000000Z",
            Some("2026-07-24T12:00:00.000000Z"),
        ),
    );
    assert_eq!(
        fixture
            .broker
            .issue_lease(
                request.clone(),
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );

    fixture.broker.lock_state().unwrap().refs.insert(
        ref_key.clone(),
        secret_ref_for_binding(
            &binding,
            fixture.provider.provider_id.clone(),
            default_policy(3, true),
            SecretClassification::AuthenticationCredential,
            binding.secret_ref_revision() + 1,
            vec![SecretDeliveryMethod::InheritedFd],
            "2026-07-24T11:00:00.000000Z",
            None,
        ),
    );
    assert_eq!(
        fixture
            .broker
            .issue_lease(
                request.clone(),
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );
    assert_eq!(fixture.ids.count(), ids);
    assert_eq!(all_events(&fixture.broker).len(), events);

    fixture.broker.lock_state().unwrap().refs.insert(
        ref_key,
        secret_ref(
            fixture.provider.provider_id.clone(),
            default_policy(3, true),
            SecretClassification::AuthenticationCredential,
        ),
    );
    assert!(matches!(
        fixture
            .broker
            .issue_lease(request, &active_context(&active, &binding, &current),),
        Ok(SecretBrokerCommandOutcome::Historical(_))
    ));
}

#[test]
fn command_hit_miss_conflict_and_cross_tenant_probes_share_one_outward_profile() {
    let fixture = broker_fixture(default_policy(3, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);
    let victim = initial_request(455, 2);
    applied(
        fixture
            .broker
            .issue_lease(victim.clone(), &active_context(&active, &binding, &current)),
    );
    let ids = fixture.ids.count();
    let events = all_events(&fixture.broker).len();
    let missing = authority_fixture(AuthorityState::Missing);

    let unauthorized_hit = fixture.broker.issue_lease(
        victim.clone(),
        &active_context(&missing, &binding, &current),
    );
    let unauthorized_miss = fixture.broker.issue_lease(
        initial_request(456, 2),
        &active_context(&missing, &binding, &current),
    );
    let unauthorized_conflict = fixture.broker.issue_lease(
        initial_request(455, 3),
        &active_context(&missing, &binding, &current),
    );
    for result in [unauthorized_hit, unauthorized_miss, unauthorized_conflict] {
        assert_eq!(result.unwrap_err().code(), "secret_not_available");
    }

    let cross_tenant = use_binding(Some(BindingChange::Tenant));
    let cross_tenant_authority = authority_fixture_for(&cross_tenant, AuthorityState::Active);
    let cross_tenant_declaration = declaration(&cross_tenant);
    assert_eq!(
        fixture
            .broker
            .issue_lease(
                lease_request(
                    455,
                    cross_tenant.clone(),
                    "2026-07-24T12:00:00.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:00:00.000000Z",
                    2,
                ),
                &active_context(
                    &cross_tenant_authority,
                    &cross_tenant,
                    &cross_tenant_declaration,
                ),
            )
            .unwrap_err()
            .code(),
        "secret_not_available"
    );
    assert_eq!(
        fixture
            .broker
            .issue_lease(
                initial_request(455, 3),
                &active_context(&active, &binding, &current),
            )
            .unwrap_err()
            .code(),
        "secret_not_available"
    );
    assert_eq!(fixture.ids.count(), ids);
    assert_eq!(all_events(&fixture.broker).len(), events);
    assert_eq!(fixture.provider.calls(), 0);
}

#[test]
fn issue_duplicates_after_expiry_revocation_and_supersession_never_return_handles() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);

    let expired = broker_fixture(default_policy(3, true));
    let expired_request = initial_request(460, 3);
    applied(expired.broker.issue_lease(
        expired_request.clone(),
        &active_context(&active, &binding, &current),
    ));
    expired
        .clock
        .set(parsed_time("2026-07-24T12:05:00.000000Z"));
    assert!(matches!(
        expired.broker.issue_lease(
            expired_request,
            &active_context(&active, &binding, &current),
        ),
        Ok(SecretBrokerCommandOutcome::Historical(_))
    ));

    let revoked = broker_fixture(default_policy(3, true));
    let revoked_request = initial_request(461, 3);
    let revoked_grant = applied(revoked.broker.issue_lease(
        revoked_request.clone(),
        &active_context(&active, &binding, &current),
    ));
    applied(revoked.broker.revoke_lease(
        secret_id(462),
        revoked_grant.handle(),
        &binding,
        &active_context(&active, &binding, &current),
    ));
    assert!(matches!(
        revoked.broker.issue_lease(
            revoked_request,
            &active_context(&active, &binding, &current),
        ),
        Ok(SecretBrokerCommandOutcome::Historical(_))
    ));

    let superseded = broker_fixture(default_policy(3, true));
    let superseded_request = initial_request(463, 3);
    let old = applied(superseded.broker.issue_lease(
        superseded_request.clone(),
        &active_context(&active, &binding, &current),
    ));
    superseded
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    applied(superseded.broker.renew_lease(
        secret_id(464),
        old.handle(),
        lease_request(
            465,
            binding.clone(),
            "2026-07-24T12:00:30.000000Z",
            "2026-07-24T12:05:00.000000Z",
            "2026-07-24T12:00:30.000000Z",
            3,
        ),
        &active_context(&active, &binding, &current),
    ));
    assert!(matches!(
        superseded.broker.issue_lease(
            superseded_request,
            &active_context(&active, &binding, &current),
        ),
        Ok(SecretBrokerCommandOutcome::Historical(_))
    ));
}

#[test]
fn concurrent_last_use_has_one_winner_and_each_command_is_terminal() {
    let fixture = broker_fixture(default_policy(1, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let grant = fixture
        .broker
        .issue_lease(
            initial_request(500, 1),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    let handle = Arc::new(
        grant
            .into_applied()
            .expect("first issue must return a live grant")
            .into_parts()
            .1,
    );
    let barrier = Arc::new(Barrier::new(3));
    let results = std::thread::scope(|scope| {
        let mut joins = Vec::new();
        for index in 0..2_u128 {
            let broker = fixture.broker.clone();
            let handle = handle.clone();
            let barrier = barrier.clone();
            let binding = binding.clone();
            let authority = &authority;
            let current = &current;
            joins.push(scope.spawn(move || {
                barrier.wait();
                broker
                    .claim_use(
                        secret_id(501 + index),
                        &handle,
                        &binding,
                        &active_context(authority, &binding, current),
                    )
                    .map(|_| ())
            }));
        }
        barrier.wait();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(SecretBrokerError::MaxUsesExceeded)))
            .count(),
        1
    );
}

#[test]
fn renewal_is_an_immediate_gap_free_cutover_and_preserves_lineage_limits() {
    let fixture = broker_fixture(default_policy(3, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let old = fixture
        .broker
        .issue_lease(
            initial_request(600, 3),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    fixture
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    let reused_command: SecretRenewalCommandId = secret_id(609);
    let reused_request = lease_request(
        600,
        binding.clone(),
        "2026-07-24T12:01:00.000000Z",
        "2026-07-24T12:06:00.000000Z",
        "2026-07-24T12:01:00.000000Z",
        3,
    );
    assert!(matches!(
        fixture.broker.renew_lease(
            reused_command.clone(),
            old.handle(),
            reused_request.clone(),
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::RequestAlreadyUsed)
    ));
    let denied_reads = fixture.clock.reads();
    let denied_ids = fixture.ids.count();
    let denied_events = all_events(&fixture.broker).len();
    assert!(matches!(
        fixture.broker.renew_lease(
            reused_command,
            old.handle(),
            reused_request,
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::RequestAlreadyUsed)
    ));
    assert_eq!(fixture.clock.reads(), denied_reads + 1);
    assert_eq!(fixture.ids.count(), denied_ids);
    assert_eq!(all_events(&fixture.broker).len(), denied_events);
    let renewal_command: SecretRenewalCommandId = secret_id(601);
    let renewal_request = lease_request(
        602,
        binding.clone(),
        "2026-07-24T12:01:00.000000Z",
        "2026-07-24T12:06:00.000000Z",
        "2026-07-24T12:01:00.000000Z",
        3,
    );
    let renewed = fixture
        .broker
        .renew_lease(
            renewal_command.clone(),
            old.handle(),
            renewal_request.clone(),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    let renewal_events = all_events(&fixture.broker).len();
    let renewal_retry = fixture
        .broker
        .renew_lease(
            renewal_command.clone(),
            old.handle(),
            renewal_request,
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    assert_eq!(
        renewal_retry
            .historical()
            .expect("an exact renewal duplicate must be historical only")
            .evidence()
            .secret_lease_id(),
        Some(renewed.snapshot().secret_lease_id())
    );
    assert_eq!(all_events(&fixture.broker).len(), renewal_events);
    assert!(matches!(
        fixture.broker.renew_lease(
            renewal_command,
            old.handle(),
            lease_request(
                605,
                binding.clone(),
                "2026-07-24T12:01:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:01:00.000000Z",
                3,
            ),
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::SecretNotAvailable)
    ));
    assert_eq!(
        renewed.snapshot().continuous_lifetime_started_at(),
        old.snapshot().continuous_lifetime_started_at()
    );
    assert!(matches!(
        fixture.broker.claim_use(
            secret_id(603),
            old.handle(),
            &binding,
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::SecretNotAvailable)
    ));
    fixture
        .broker
        .claim_use(
            secret_id(604),
            renewed.handle(),
            &binding,
            &active_context(&authority, &binding, &current),
        )
        .unwrap();

    let second = broker_fixture(default_policy(3, true));
    let old = second
        .broker
        .issue_lease(
            initial_request(610, 3),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    assert!(matches!(
        second.broker.renew_lease(
            secret_id(611),
            old.handle(),
            lease_request(
                612,
                binding.clone(),
                "2026-07-24T12:00:30.000000Z",
                "2026-07-24T12:05:30.000000Z",
                "2026-07-24T12:00:00.000000Z",
                3,
            ),
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::RenewalDenied)
    ));
    second
        .broker
        .claim_use(
            secret_id(613),
            old.handle(),
            &binding,
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
}

#[test]
fn successful_renewal_duplicate_is_historical_after_visibility_and_lifecycle_drift() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);
    let fixture = broker_fixture(default_policy(3, true));
    let old = applied(fixture.broker.issue_lease(
        initial_request(650, 3),
        &active_context(&active, &binding, &current),
    ));
    fixture
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    let command: SecretRenewalCommandId = secret_id(651);
    let request = lease_request(
        652,
        binding.clone(),
        "2026-07-24T12:00:30.000000Z",
        "2026-07-24T12:05:00.000000Z",
        "2026-07-24T12:00:30.000000Z",
        3,
    );
    let renewed = applied(fixture.broker.renew_lease(
        command.clone(),
        old.handle(),
        request.clone(),
        &active_context(&active, &binding, &current),
    ));
    assert_eq!(
        renewed.snapshot().starts_at().as_str(),
        "2026-07-24T12:01:00.000000Z"
    );
    let ids = fixture.ids.count();
    let events = all_events(&fixture.broker).len();

    for state in [
        AuthorityState::Missing,
        AuthorityState::Expired,
        AuthorityState::Revoked,
        AuthorityState::MissingSnapshot,
    ] {
        let unavailable = authority_fixture(state);
        assert_eq!(
            fixture
                .broker
                .renew_lease(
                    command.clone(),
                    old.handle(),
                    request.clone(),
                    &active_context(&unavailable, &binding, &current),
                )
                .unwrap_err(),
            SecretBrokerError::SecretNotAvailable
        );
    }

    let stale_binding = use_binding(Some(BindingChange::DeclarationRevision));
    let stale_declaration = declaration(&stale_binding);
    assert_eq!(
        fixture
            .broker
            .renew_lease(
                command.clone(),
                old.handle(),
                request.clone(),
                &active_context(&active, &binding, &stale_declaration),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );

    let ref_key = (binding.tenant_id().clone(), binding.secret_ref_id().clone());
    fixture.broker.lock_state().unwrap().refs.insert(
        ref_key.clone(),
        secret_ref_for_binding(
            &binding,
            fixture.provider.provider_id.clone(),
            default_policy(3, true),
            SecretClassification::AuthenticationCredential,
            binding.secret_ref_revision(),
            vec![SecretDeliveryMethod::InheritedFd],
            "2026-07-24T11:00:00.000000Z",
            Some("2026-07-24T12:01:00.000000Z"),
        ),
    );
    assert_eq!(
        fixture
            .broker
            .renew_lease(
                command.clone(),
                old.handle(),
                request.clone(),
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );
    fixture.broker.lock_state().unwrap().refs.insert(
        ref_key.clone(),
        secret_ref_for_binding(
            &binding,
            fixture.provider.provider_id.clone(),
            default_policy(3, true),
            SecretClassification::AuthenticationCredential,
            binding.secret_ref_revision() + 1,
            vec![SecretDeliveryMethod::InheritedFd],
            "2026-07-24T11:00:00.000000Z",
            None,
        ),
    );
    assert_eq!(
        fixture
            .broker
            .renew_lease(
                command.clone(),
                old.handle(),
                request.clone(),
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );
    assert_eq!(fixture.ids.count(), ids);
    assert_eq!(all_events(&fixture.broker).len(), events);

    fixture.broker.lock_state().unwrap().refs.insert(
        ref_key,
        secret_ref(
            fixture.provider.provider_id.clone(),
            default_policy(3, true),
            SecretClassification::AuthenticationCredential,
        ),
    );
    assert_eq!(
        historical(fixture.broker.renew_lease(
            command.clone(),
            old.handle(),
            request.clone(),
            &active_context(&active, &binding, &current),
        ))
        .evidence()
        .secret_lease_id(),
        Some(renewed.snapshot().secret_lease_id())
    );

    applied(fixture.broker.revoke_lease(
        secret_id(653),
        renewed.handle(),
        &binding,
        &active_context(&active, &binding, &current),
    ));
    assert!(matches!(
        fixture.broker.renew_lease(
            command,
            old.handle(),
            request,
            &active_context(&active, &binding, &current),
        ),
        Ok(SecretBrokerCommandOutcome::Historical(_))
    ));

    let expired = broker_fixture(default_policy(3, true));
    let expired_old = applied(expired.broker.issue_lease(
        initial_request(659, 3),
        &active_context(&active, &binding, &current),
    ));
    expired
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    let expired_command: SecretRenewalCommandId = secret_id(660);
    let expired_request = lease_request(
        661,
        binding.clone(),
        "2026-07-24T12:00:30.000000Z",
        "2026-07-24T12:05:00.000000Z",
        "2026-07-24T12:00:30.000000Z",
        3,
    );
    applied(expired.broker.renew_lease(
        expired_command.clone(),
        expired_old.handle(),
        expired_request.clone(),
        &active_context(&active, &binding, &current),
    ));
    expired
        .clock
        .set(parsed_time("2026-07-24T12:05:00.000000Z"));
    assert!(matches!(
        expired.broker.renew_lease(
            expired_command,
            expired_old.handle(),
            expired_request,
            &active_context(&active, &binding, &current),
        ),
        Ok(SecretBrokerCommandOutcome::Historical(_))
    ));

    let superseded = broker_fixture(default_policy(3, true));
    let original = applied(superseded.broker.issue_lease(
        initial_request(654, 3),
        &active_context(&active, &binding, &current),
    ));
    superseded
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    let first_command: SecretRenewalCommandId = secret_id(655);
    let first_request = lease_request(
        656,
        binding.clone(),
        "2026-07-24T12:00:30.000000Z",
        "2026-07-24T12:05:00.000000Z",
        "2026-07-24T12:00:30.000000Z",
        3,
    );
    let first_renewed = applied(superseded.broker.renew_lease(
        first_command.clone(),
        original.handle(),
        first_request.clone(),
        &active_context(&active, &binding, &current),
    ));
    superseded
        .clock
        .set(parsed_time("2026-07-24T12:02:00.000000Z"));
    applied(superseded.broker.renew_lease(
        secret_id(657),
        first_renewed.handle(),
        lease_request(
            658,
            binding.clone(),
            "2026-07-24T12:01:30.000000Z",
            "2026-07-24T12:05:00.000000Z",
            "2026-07-24T12:01:30.000000Z",
            3,
        ),
        &active_context(&active, &binding, &current),
    ));
    assert!(matches!(
        superseded.broker.renew_lease(
            first_command,
            original.handle(),
            first_request,
            &active_context(&active, &binding, &current),
        ),
        Ok(SecretBrokerCommandOutcome::Historical(_))
    ));
}

#[test]
fn system_clock_renewal_uses_broker_observed_immediate_cutover() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let configured_at = SystemSecretBrokerClock.now_utc().unwrap();
    let authority = active_authority_fixture_at(
        &binding,
        configured_at - Duration::minutes(1),
        configured_at + Duration::hours(1),
    );
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let created_at = canonical_timestamp(configured_at - Duration::hours(1)).unwrap();
    let broker = ProcessLocalSecretBroker::try_new(
        tenant(2),
        vec![secret_ref_for_binding(
            &binding,
            provider.provider_id.clone(),
            default_policy(3, true),
            SecretClassification::AuthenticationCredential,
            binding.secret_ref_revision(),
            vec![SecretDeliveryMethod::InheritedFd],
            created_at.as_str(),
            None,
        )],
        vec![provider.clone()],
    )
    .unwrap();

    let mut issued = None;
    for attempt in 0..3_u128 {
        let prepared_at = SystemSecretBrokerClock.now_utc().unwrap();
        let starts_at = prepared_at + Duration::seconds(1);
        let expires_at = starts_at + Duration::minutes(5);
        let starts_text = canonical_timestamp(starts_at).unwrap();
        let expires_text = canonical_timestamp(expires_at).unwrap();
        let requested_text = canonical_timestamp(prepared_at).unwrap();
        let request = lease_request(
            680 + attempt,
            binding.clone(),
            starts_text.as_str(),
            expires_text.as_str(),
            requested_text.as_str(),
            3,
        );
        if let Ok(SecretBrokerCommandOutcome::Applied(grant)) =
            broker.issue_lease(request, &active_context(&authority, &binding, &current))
        {
            issued = Some((grant, starts_at, expires_at));
            break;
        }
    }
    let (old, prepared_start, expires_at) =
        issued.expect("system-clock issuance must complete before its future start");
    while SystemSecretBrokerClock.now_utc().unwrap() < prepared_start {
        std::thread::sleep(StdDuration::from_millis(10));
    }
    std::thread::sleep(StdDuration::from_millis(1));

    let renewal_request = lease_request(
        684,
        binding.clone(),
        canonical_timestamp(prepared_start).unwrap().as_str(),
        canonical_timestamp(expires_at).unwrap().as_str(),
        canonical_timestamp(prepared_start).unwrap().as_str(),
        3,
    );
    let before = SystemSecretBrokerClock.now_utc().unwrap();
    let renewed = applied(broker.renew_lease(
        secret_id(685),
        old.handle(),
        renewal_request,
        &active_context(&authority, &binding, &current),
    ));
    let after = SystemSecretBrokerClock.now_utc().unwrap();
    let effective_start = parse_canonical(renewed.snapshot().starts_at()).unwrap();
    assert!(effective_start >= before);
    assert!(effective_start <= after);
    assert!(effective_start > prepared_start);
    assert_eq!(provider.calls(), 0);
}

#[test]
fn successful_claim_duplicate_after_expiry_revocation_or_generation_change_has_no_claim() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);

    let expired = broker_fixture(default_policy(3, true));
    let grant = applied(expired.broker.issue_lease(
        initial_request(670, 3),
        &active_context(&active, &binding, &current),
    ));
    let attempt: SecretUseAttemptId = secret_id(671);
    applied(expired.broker.claim_use(
        attempt.clone(),
        grant.handle(),
        &binding,
        &active_context(&active, &binding, &current),
    ));
    expired
        .clock
        .set(parsed_time("2026-07-24T12:05:00.000000Z"));
    assert!(matches!(
        expired.broker.claim_use(
            attempt,
            grant.handle(),
            &binding,
            &active_context(&active, &binding, &current),
        ),
        Ok(SecretBrokerCommandOutcome::Historical(_))
    ));

    let revoked = broker_fixture(default_policy(3, true));
    let grant = applied(revoked.broker.issue_lease(
        initial_request(672, 3),
        &active_context(&active, &binding, &current),
    ));
    let attempt: SecretUseAttemptId = secret_id(673);
    applied(revoked.broker.claim_use(
        attempt.clone(),
        grant.handle(),
        &binding,
        &active_context(&active, &binding, &current),
    ));
    applied(revoked.broker.revoke_lease(
        secret_id(674),
        grant.handle(),
        &binding,
        &active_context(&active, &binding, &current),
    ));
    assert!(matches!(
        revoked.broker.claim_use(
            attempt,
            grant.handle(),
            &binding,
            &active_context(&active, &binding, &current),
        ),
        Ok(SecretBrokerCommandOutcome::Historical(_))
    ));

    let generation_changed = broker_fixture(default_policy(3, true));
    let grant = applied(generation_changed.broker.issue_lease(
        initial_request(675, 3),
        &active_context(&active, &binding, &current),
    ));
    let attempt: SecretUseAttemptId = secret_id(676);
    applied(generation_changed.broker.claim_use(
        attempt.clone(),
        grant.handle(),
        &binding,
        &active_context(&active, &binding, &current),
    ));
    generation_changed
        .broker
        .lock_state()
        .unwrap()
        .leases
        .get_mut(grant.snapshot().secret_lease_id())
        .unwrap()
        .revocation_generation += 1;
    assert!(matches!(
        generation_changed.broker.claim_use(
            attempt,
            grant.handle(),
            &binding,
            &active_context(&active, &binding, &current),
        ),
        Ok(SecretBrokerCommandOutcome::Historical(_))
    ));
}

#[test]
fn revocation_is_atomic_idempotent_and_never_calls_provider() {
    let fixture = broker_fixture(default_policy(2, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let grant = fixture
        .broker
        .issue_lease(
            initial_request(700, 2),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    let second = fixture
        .broker
        .issue_lease(
            initial_request(703, 2),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    let denied_command: SecretRevocationCommandId = secret_id(704);
    let missing = authority_fixture(AuthorityState::Missing);
    assert!(matches!(
        fixture.broker.revoke_lease(
            denied_command.clone(),
            second.handle(),
            &binding,
            &active_context(&missing, &binding, &current),
        ),
        Err(SecretBrokerError::SecretNotAvailable)
    ));
    let denied_reads = fixture.clock.reads();
    let denied_ids = fixture.ids.count();
    let denied_events = all_events(&fixture.broker).len();
    assert!(matches!(
        fixture.broker.revoke_lease(
            denied_command,
            second.handle(),
            &binding,
            &active_context(&authority, &binding, &current),
        ),
        Ok(SecretBrokerCommandOutcome::Applied(_))
    ));
    assert!(fixture.clock.reads() > denied_reads);
    assert!(fixture.ids.count() > denied_ids);
    assert!(all_events(&fixture.broker).len() > denied_events);
    let command: SecretRevocationCommandId = secret_id(701);
    let first = fixture
        .broker
        .revoke_lease(
            command.clone(),
            grant.handle(),
            &binding,
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    let events = all_events(&fixture.broker).len();
    let retry = fixture
        .broker
        .revoke_lease(
            command,
            grant.handle(),
            &binding,
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    let revocation_receipt = retry
        .historical()
        .expect("an exact revocation duplicate must be historical only");
    assert_eq!(
        revocation_receipt.evidence().secret_lease_id(),
        Some(first.secret_lease_id())
    );
    assert_eq!(
        revocation_receipt.evidence().revocation_generation(),
        first.revocation_generation()
    );
    assert_eq!(first.status(), SecretLeaseStatus::Revoked);
    assert_eq!(all_events(&fixture.broker).len(), events);
    assert!(matches!(
        fixture.broker.revoke_lease(
            secret_id(701),
            second.handle(),
            &binding,
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::SecretNotAvailable)
    ));
    assert!(matches!(
        fixture.broker.claim_use(
            secret_id(702),
            grant.handle(),
            &binding,
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::SecretNotAvailable)
    ));
    assert_eq!(fixture.provider.calls(), 0);
}

#[test]
fn finite_limits_fail_closed_without_partial_state_or_unbounded_replay() {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let clock = Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")));
    let ids = Arc::new(SequenceIds::default());
    let limits = ProcessLocalSecretBrokerLimits {
        max_secret_refs: 1,
        max_providers: 1,
        max_active_leases: 1,
        max_retained_leases: 1,
        max_command_records: 2,
        max_evidence_events: 2,
        max_generated_ids: 8,
        max_replay_page_size: 1,
    };
    let broker = ProcessLocalSecretBroker::with_sources_and_limits(
        tenant(2),
        vec![secret_ref(
            provider.provider_id.clone(),
            default_policy(2, true),
            SecretClassification::AuthenticationCredential,
        )],
        vec![provider],
        clock,
        ids,
        limits,
    )
    .unwrap();
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let first_request = initial_request(800, 1);
    let first = broker
        .issue_lease(
            first_request.clone(),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    assert!(matches!(
        broker.issue_lease(
            initial_request(801, 1),
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::CapacityExceeded)
    ));
    let retry = broker
        .issue_lease(
            first_request,
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    assert_eq!(
        retry
            .historical()
            .expect("an exact duplicate must remain available at capacity")
            .evidence()
            .secret_lease_id(),
        Some(first.snapshot().secret_lease_id())
    );
    assert!(matches!(
        broker.replay_page(0, 2),
        Err(SecretBrokerError::InvalidPage)
    ));
    let page = broker.replay_page(0, 1).unwrap();
    assert_eq!(page.leases.len() + page.events.len(), 1);
    assert_eq!(page.next_cursor, Some(1));

    let invalid = ProcessLocalSecretBrokerLimits {
        max_secret_refs: 0,
        ..ProcessLocalSecretBrokerLimits::default()
    };
    assert_eq!(
        config_error(ProcessLocalSecretBroker::with_sources_and_limits(
            tenant(2),
            Vec::new(),
            Vec::new(),
            Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
            Arc::new(SequenceIds::default()),
            invalid,
        )),
        SecretBrokerConfigError::InvalidLimits
    );
}

#[test]
fn event_allocation_failure_leaves_state_and_evidence_unchanged() {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let broker = ProcessLocalSecretBroker::with_sources(
        tenant(2),
        vec![secret_ref(
            provider.provider_id.clone(),
            default_policy(1, true),
            SecretClassification::AuthenticationCredential,
        )],
        vec![provider],
        Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
        Arc::new(FailEventIds {
            next: AtomicU64::new(0),
        }),
    )
    .unwrap();
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    assert!(matches!(
        broker.issue_lease(
            initial_request(900, 1),
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::EvidenceUnavailable)
    ));
    let page = broker.replay_page(0, 128).unwrap();
    assert!(page.leases.is_empty());
    assert!(page.events.is_empty());
}

fn broker_with_clock_and_ids(
    clock: Arc<ManualClock>,
    ids: Arc<dyn SecretBrokerIdSource>,
) -> ProcessLocalSecretBroker {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    ProcessLocalSecretBroker::with_sources(
        tenant(2),
        vec![secret_ref(
            provider.provider_id.clone(),
            default_policy(3, true),
            SecretClassification::AuthenticationCredential,
        )],
        vec![provider],
        clock,
        ids,
    )
    .unwrap()
}

#[test]
fn every_post_sample_id_failure_preserves_the_monotonic_time_fence() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let future = parsed_time("2026-07-24T12:01:00.000000Z");
    let rollback = parsed_time("2026-07-24T12:00:30.000000Z");

    for kind in [
        SecretBrokerIdKind::AccessEvent,
        SecretBrokerIdKind::Lease,
        SecretBrokerIdKind::DeliveryHandle,
        SecretBrokerIdKind::HandleCapability,
    ] {
        let clock = Arc::new(ManualClock::new(future));
        let ids = Arc::new(ToggleFailIds::default());
        ids.fail(kind);
        let broker = broker_with_clock_and_ids(clock.clone(), ids.clone());
        assert!(broker
            .issue_lease(
                initial_request(920 + kind as u128, 2),
                &active_context(&authority, &binding, &current),
            )
            .is_err());
        assert_eq!(broker.lock_state().unwrap().max_observed_time, Some(future));
        assert!(broker.replay_page(0, 128).unwrap().events.is_empty());
        ids.allow_all();
        clock.set(rollback);
        assert_eq!(
            broker
                .issue_lease(
                    initial_request(930 + kind as u128, 2),
                    &active_context(&authority, &binding, &current),
                )
                .unwrap_err(),
            SecretBrokerError::ClockRollback
        );
    }

    for kind in [
        SecretBrokerIdKind::AccessEvent,
        SecretBrokerIdKind::UseClaim,
        SecretBrokerIdKind::ClaimCapability,
    ] {
        let clock = Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")));
        let ids = Arc::new(ToggleFailIds::default());
        let broker = broker_with_clock_and_ids(clock.clone(), ids.clone());
        let grant = applied(broker.issue_lease(
            initial_request(940 + kind as u128, 3),
            &active_context(&authority, &binding, &current),
        ));
        clock.set(future);
        ids.fail(kind);
        assert!(broker
            .claim_use(
                secret_id(950 + kind as u128),
                grant.handle(),
                &binding,
                &active_context(&authority, &binding, &current),
            )
            .is_err());
        assert_eq!(broker.lock_state().unwrap().max_observed_time, Some(future));
        ids.allow_all();
        clock.set(rollback);
        assert_eq!(
            broker
                .claim_use(
                    secret_id(960 + kind as u128),
                    grant.handle(),
                    &binding,
                    &active_context(&authority, &binding, &current),
                )
                .unwrap_err(),
            SecretBrokerError::ClockRollback
        );
    }

    for kind in [
        SecretBrokerIdKind::AccessEvent,
        SecretBrokerIdKind::Lease,
        SecretBrokerIdKind::DeliveryHandle,
        SecretBrokerIdKind::HandleCapability,
    ] {
        let clock = Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")));
        let ids = Arc::new(ToggleFailIds::default());
        let broker = broker_with_clock_and_ids(clock.clone(), ids.clone());
        let old = applied(broker.issue_lease(
            initial_request(970 + kind as u128, 3),
            &active_context(&authority, &binding, &current),
        ));
        clock.set(future);
        ids.fail(kind);
        assert!(broker
            .renew_lease(
                secret_id(980 + kind as u128),
                old.handle(),
                lease_request(
                    990 + kind as u128,
                    binding.clone(),
                    "2026-07-24T12:00:30.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:00:30.000000Z",
                    3,
                ),
                &active_context(&authority, &binding, &current),
            )
            .is_err());
        assert_eq!(broker.lock_state().unwrap().max_observed_time, Some(future));
        ids.allow_all();
        clock.set(rollback);
        assert_eq!(
            broker
                .renew_lease(
                    secret_id(1_000 + kind as u128),
                    old.handle(),
                    lease_request(
                        1_010 + kind as u128,
                        binding.clone(),
                        "2026-07-24T12:00:00.000000Z",
                        "2026-07-24T12:05:00.000000Z",
                        "2026-07-24T12:00:00.000000Z",
                        3,
                    ),
                    &active_context(&authority, &binding, &current),
                )
                .unwrap_err(),
            SecretBrokerError::ClockRollback
        );
    }

    let clock = Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")));
    let ids = Arc::new(ToggleFailIds::default());
    let broker = broker_with_clock_and_ids(clock.clone(), ids.clone());
    let grant = applied(broker.issue_lease(
        initial_request(1_020, 3),
        &active_context(&authority, &binding, &current),
    ));
    clock.set(future);
    ids.fail(SecretBrokerIdKind::AccessEvent);
    assert!(broker
        .revoke_lease(
            secret_id(1_021),
            grant.handle(),
            &binding,
            &active_context(&authority, &binding, &current),
        )
        .is_err());
    assert_eq!(broker.lock_state().unwrap().max_observed_time, Some(future));
    ids.allow_all();
    clock.set(rollback);
    assert_eq!(
        broker
            .revoke_lease(
                secret_id(1_022),
                grant.handle(),
                &binding,
                &active_context(&authority, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::ClockRollback
    );
}

#[test]
fn replay_is_bounded_inspect_only_and_does_not_allocate_or_call_provider() {
    let fixture = broker_fixture(default_policy(2, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    fixture
        .broker
        .issue_lease(
            initial_request(1_000, 2),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    let reads = fixture.clock.reads();
    let ids = fixture.ids.count();
    let first = fixture.broker.replay_page(0, 1).unwrap();
    let second = fixture
        .broker
        .replay_page(first.next_cursor.unwrap(), 1)
        .unwrap();
    assert_eq!(first.leases.len() + first.events.len(), 1);
    assert_eq!(second.leases.len() + second.events.len(), 1);
    assert_eq!(fixture.clock.reads(), reads);
    assert_eq!(fixture.ids.count(), ids);
    assert_eq!(fixture.provider.calls(), 0);
}

fn provider_fetch_request(index: u128) -> SecretProviderFetchRequest {
    SecretProviderFetchRequest {
        provider_audit_id: secret_id(index),
        secret_provider_id: secret_id(10),
        tenant_id: tenant(2),
        secret_ref_id: secret_id(9),
        secret_ref_revision: 1,
        provider_version_ref: "version-1".parse().unwrap(),
        secret_lease_id: secret_id(index + 1),
        delivery_handle_id: secret_id(index + 2),
        secret_use_claim_id: secret_id(index + 3),
        secret_use_attempt_id: secret_id(index + 4),
        requested_at: canonical("2026-07-24T12:00:00.000000Z"),
    }
}

#[test]
fn provider_result_is_request_bound_redacted_and_has_no_material_escape() {
    let request = provider_fetch_request(1_100);
    let audit = SecretProviderAuditEvidence::for_fetch_request(
        &request,
        SecretProviderOutcome::Succeeded,
        EffectCertainty::Known,
        canonical("2026-07-24T12:00:00.000000Z"),
    )
    .unwrap();
    let result =
        SecretProviderFetchResult::try_new(&request, b"sensitive".to_vec(), audit).unwrap();
    assert_eq!(result.material_len(), 9);
    assert_eq!(
        format!("{result:?}"),
        "SecretProviderFetchResult(<redacted>)"
    );
    assert!(!serde_json::to_string(result.audit())
        .unwrap()
        .contains("sensitive"));

    let other = provider_fetch_request(1_200);
    let wrong_audit = SecretProviderAuditEvidence::for_fetch_request(
        &request,
        SecretProviderOutcome::Succeeded,
        EffectCertainty::Known,
        canonical("2026-07-24T12:00:00.000000Z"),
    )
    .unwrap();
    assert_eq!(
        SecretProviderFetchResult::try_new(&other, b"rejected".to_vec(), wrong_audit)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::IntegrityFailure
    );
    let valid_audit = SecretProviderAuditEvidence::for_fetch_request(
        &other,
        SecretProviderOutcome::Succeeded,
        EffectCertainty::Known,
        canonical("2026-07-24T12:00:00.000000Z"),
    )
    .unwrap();
    assert_eq!(
        SecretProviderFetchResult::try_new(&other, Vec::new(), valid_audit)
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::IntegrityFailure
    );
}

#[test]
fn malformed_configuration_and_classification_mismatch_fail_closed() {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    assert_eq!(
        config_error(ProcessLocalSecretBroker::try_new(
            tenant(2),
            vec![secret_ref(
                provider.provider_id.clone(),
                default_policy(1, true),
                SecretClassification::AuthenticationCredential,
            )],
            Vec::new()
        )),
        SecretBrokerConfigError::MissingProvider
    );
    assert_eq!(
        config_error(ProcessLocalSecretBroker::try_new(
            tenant(2),
            Vec::new(),
            vec![provider.clone(), provider.clone()],
        )),
        SecretBrokerConfigError::DuplicateProvider
    );
    let mut excessive_limits = ProcessLocalSecretBrokerLimits::default();
    excessive_limits.max_secret_refs += 1;
    assert_eq!(
        config_error(ProcessLocalSecretBroker::with_sources_and_limits(
            tenant(2),
            Vec::new(),
            Vec::new(),
            Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
            Arc::new(SequenceIds::default()),
            excessive_limits,
        )),
        SecretBrokerConfigError::InvalidLimits
    );

    let broker = ProcessLocalSecretBroker::with_sources(
        tenant(2),
        vec![secret_ref(
            provider.provider_id.clone(),
            default_policy(1, true),
            SecretClassification::SigningMaterial,
        )],
        vec![provider],
        Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
        Arc::new(SequenceIds::default()),
    )
    .unwrap();
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    assert!(matches!(
        broker.issue_lease(
            initial_request(1_300, 1),
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::SecretNotAvailable)
    ));
}

#[test]
fn clock_rollback_latches_time_without_poisoning_a_later_command_attempt() {
    let fixture = broker_fixture(default_policy(2, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    fixture
        .broker
        .issue_lease(
            initial_request(1_400, 1),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    fixture
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    let request = lease_request(
        1_401,
        binding.clone(),
        "2026-07-24T12:00:00.000000Z",
        "2026-07-24T12:05:00.000000Z",
        "2026-07-24T12:00:00.000000Z",
        1,
    );
    assert!(matches!(
        fixture.broker.issue_lease(
            request.clone(),
            &active_context(&authority, &binding, &current),
        ),
        Err(SecretBrokerError::ClockRollback)
    ));
    fixture
        .clock
        .set(parsed_time("2026-07-24T12:00:01.000000Z"));
    assert!(matches!(
        fixture
            .broker
            .issue_lease(request, &active_context(&authority, &binding, &current)),
        Err(SecretBrokerError::SecretNotAvailable)
    ));
}

#[test]
fn process_local_error_limits_and_system_seams_cover_closed_surface() {
    let operation_ref = operation("fetch");
    let authority_operation = secret_driver_invoke_operation(&operation_ref);
    assert_eq!(
        authority_operation.namespace,
        AuthorityOperationNamespace::Driver
    );
    assert_eq!(
        authority_operation.resource_kind,
        AuthorityResourceKind::DriverOperation
    );
    assert_eq!(authority_operation.verb, AuthorityVerb::Invoke);
    assert_eq!(authority_operation.name.as_deref(), Some("http.fetch"));
    assert_eq!(
        authority_operation.resource_schema_version.as_deref(),
        Some("splendor.driver.operation.v1")
    );

    let now = SystemSecretBrokerClock.now_utc().unwrap();
    assert!(now.nanosecond().is_multiple_of(1_000));
    assert!(!SystemSecretBrokerIdSource
        .next_uuid(SecretBrokerIdKind::Lease)
        .unwrap()
        .is_nil());

    for (error, code) in [
        (
            SecretBrokerError::SecretNotAvailable,
            "secret_not_available",
        ),
        (
            SecretBrokerError::AuthorityDenied,
            "secret_authority_denied",
        ),
        (
            SecretBrokerError::ClockUnavailable,
            "secret_broker_clock_unavailable",
        ),
        (
            SecretBrokerError::ClockRollback,
            "secret_broker_clock_rollback",
        ),
        (
            SecretBrokerError::EvidenceUnavailable,
            "secret_broker_evidence_unavailable",
        ),
        (
            SecretBrokerError::LeaseNotStarted,
            "secret_lease_not_started",
        ),
        (SecretBrokerError::LeaseExpired, "secret_lease_expired"),
        (
            SecretBrokerError::MaxUsesExceeded,
            "secret_lease_max_uses_exceeded",
        ),
        (
            SecretBrokerError::RenewalDenied,
            "secret_lease_renewal_denied",
        ),
        (
            SecretBrokerError::RequestAlreadyUsed,
            "secret_lease_request_already_used",
        ),
        (
            SecretBrokerError::CapacityExceeded,
            "secret_broker_capacity_exceeded",
        ),
        (SecretBrokerError::InvalidPage, "secret_broker_page_invalid"),
        (
            SecretBrokerError::StateUnavailable,
            "secret_broker_state_unavailable",
        ),
    ] {
        assert_eq!(error.code(), code);
        assert_eq!(error.to_string(), code);
    }
    for (error, code) in [
        (
            SecretBrokerConfigError::DuplicateSecretRef,
            "duplicate_secret_ref",
        ),
        (
            SecretBrokerConfigError::DuplicateProvider,
            "duplicate_secret_provider",
        ),
        (
            SecretBrokerConfigError::MissingProvider,
            "secret_provider_missing",
        ),
        (
            SecretBrokerConfigError::InvalidLimits,
            "secret_broker_limits_invalid",
        ),
        (
            SecretBrokerConfigError::CapacityExceeded,
            "secret_broker_capacity_exceeded",
        ),
    ] {
        assert_eq!(error.to_string(), code);
    }

    let defaults = ProcessLocalSecretBrokerLimits::default();
    assert!(defaults.is_valid());
    let mut invalid_limits = Vec::new();
    for (field, value) in [
        ("refs", 0),
        ("refs", defaults.max_secret_refs + 1),
        ("providers", 0),
        ("providers", defaults.max_providers + 1),
        ("active", 0),
        ("active", defaults.max_active_leases + 1),
        ("retained", defaults.max_active_leases - 1),
        ("retained", defaults.max_retained_leases + 1),
        ("commands", 0),
        ("commands", defaults.max_command_records + 1),
        ("events", 0),
        ("events", defaults.max_evidence_events + 1),
        ("generated", defaults.max_evidence_events - 1),
        ("generated", defaults.max_generated_ids + 1),
        ("page", 0),
        ("page", defaults.max_replay_page_size + 1),
    ] {
        let mut limits = defaults;
        match field {
            "refs" => limits.max_secret_refs = value,
            "providers" => limits.max_providers = value,
            "active" => limits.max_active_leases = value,
            "retained" => limits.max_retained_leases = value,
            "commands" => limits.max_command_records = value,
            "events" => limits.max_evidence_events = value,
            "generated" => limits.max_generated_ids = value,
            "page" => limits.max_replay_page_size = value,
            _ => unreachable!(),
        }
        invalid_limits.push(limits);
    }
    assert!(invalid_limits.into_iter().all(|limits| !limits.is_valid()));
}

#[test]
fn process_local_configuration_rejects_duplicate_refs_and_capacity() {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let reference = secret_ref(
        provider.provider_id.clone(),
        default_policy(1, true),
        SecretClassification::AuthenticationCredential,
    );
    assert_eq!(
        config_error(ProcessLocalSecretBroker::try_new(
            tenant(2),
            vec![reference.clone(), reference],
            vec![provider.clone()],
        )),
        SecretBrokerConfigError::DuplicateSecretRef
    );

    let limits = ProcessLocalSecretBrokerLimits {
        max_secret_refs: 1,
        max_providers: 1,
        ..ProcessLocalSecretBrokerLimits::default()
    };
    let second_provider = Arc::new(TrapProvider::new(secret_id(11)));
    assert_eq!(
        config_error(ProcessLocalSecretBroker::with_sources_and_limits(
            tenant(2),
            Vec::new(),
            vec![provider, second_provider],
            Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
            Arc::new(SequenceIds::default()),
            limits,
        )),
        SecretBrokerConfigError::CapacityExceeded
    );
}

#[test]
fn process_local_broker_is_single_tenant_and_capacity_is_tenant_local() {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    assert_eq!(
        config_error(ProcessLocalSecretBroker::try_new(
            TenantId::from(Uuid::nil()),
            Vec::new(),
            Vec::new(),
        )),
        SecretBrokerConfigError::InvalidTenant
    );

    let tenant_b_binding = use_binding(Some(BindingChange::Tenant));
    let tenant_b_ref = secret_ref_for_binding(
        &tenant_b_binding,
        provider.provider_id.clone(),
        default_policy(2, true),
        SecretClassification::AuthenticationCredential,
        tenant_b_binding.secret_ref_revision(),
        vec![SecretDeliveryMethod::InheritedFd],
        "2026-07-24T11:00:00.000000Z",
        None,
    );
    assert_eq!(
        config_error(ProcessLocalSecretBroker::try_new(
            tenant(2),
            vec![tenant_b_ref.clone()],
            vec![provider.clone()],
        )),
        SecretBrokerConfigError::MixedTenant
    );

    let tenant_a = broker_fixture(default_policy(2, true));
    let tenant_b_authority = authority_fixture_for(&tenant_b_binding, AuthorityState::Active);
    let tenant_b_declaration = declaration(&tenant_b_binding);
    let reads = tenant_a.clock.reads();
    let ids = tenant_a.ids.count();
    assert_eq!(
        tenant_a
            .broker
            .issue_lease(
                lease_request(
                    1_450,
                    tenant_b_binding.clone(),
                    "2026-07-24T12:00:00.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:00:00.000000Z",
                    1,
                ),
                &active_context(
                    &tenant_b_authority,
                    &tenant_b_binding,
                    &tenant_b_declaration,
                ),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );
    assert_eq!(tenant_a.clock.reads(), reads);
    assert_eq!(tenant_a.ids.count(), ids);
    assert!(all_events(&tenant_a.broker).is_empty());

    let limits = ProcessLocalSecretBrokerLimits {
        max_secret_refs: 1,
        max_providers: 1,
        max_active_leases: 1,
        max_retained_leases: 2,
        max_command_records: 8,
        max_evidence_events: 8,
        max_generated_ids: 32,
        max_replay_page_size: 8,
    };
    let tenant_a_provider = Arc::new(TrapProvider::new(secret_id(10)));
    let tenant_a_broker = ProcessLocalSecretBroker::with_sources_and_limits(
        tenant(2),
        vec![secret_ref(
            tenant_a_provider.provider_id.clone(),
            default_policy(2, true),
            SecretClassification::AuthenticationCredential,
        )],
        vec![tenant_a_provider],
        Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
        Arc::new(SequenceIds::default()),
        limits,
    )
    .unwrap();
    let tenant_b_provider = Arc::new(TrapProvider::new(secret_id(10)));
    let tenant_b_broker = ProcessLocalSecretBroker::with_sources_and_limits(
        tenant_b_binding.tenant_id().clone(),
        vec![tenant_b_ref],
        vec![tenant_b_provider],
        Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
        Arc::new(SequenceIds::default()),
        limits,
    )
    .unwrap();
    let tenant_a_binding = use_binding(None);
    let tenant_a_declaration = declaration(&tenant_a_binding);
    let tenant_a_authority = authority_fixture(AuthorityState::Active);
    applied(tenant_a_broker.issue_lease(
        initial_request(1_451, 1),
        &active_context(
            &tenant_a_authority,
            &tenant_a_binding,
            &tenant_a_declaration,
        ),
    ));
    assert_eq!(
        tenant_a_broker
            .issue_lease(
                initial_request(1_452, 1),
                &active_context(
                    &tenant_a_authority,
                    &tenant_a_binding,
                    &tenant_a_declaration,
                ),
            )
            .unwrap_err(),
        SecretBrokerError::CapacityExceeded
    );
    assert!(matches!(
        tenant_b_broker.issue_lease(
            lease_request(
                1_451,
                tenant_b_binding.clone(),
                "2026-07-24T12:00:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                1,
            ),
            &active_context(
                &tenant_b_authority,
                &tenant_b_binding,
                &tenant_b_declaration,
            ),
        ),
        Ok(SecretBrokerCommandOutcome::Applied(_))
    ));
}

#[test]
fn elapsed_active_lease_does_not_hold_active_capacity() {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let clock = Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")));
    let broker = ProcessLocalSecretBroker::with_sources_and_limits(
        tenant(2),
        vec![secret_ref(
            provider.provider_id.clone(),
            default_policy(2, true),
            SecretClassification::AuthenticationCredential,
        )],
        vec![provider],
        clock.clone(),
        Arc::new(SequenceIds::default()),
        ProcessLocalSecretBrokerLimits {
            max_secret_refs: 1,
            max_providers: 1,
            max_active_leases: 1,
            max_retained_leases: 2,
            max_command_records: 4,
            max_evidence_events: 4,
            max_generated_ids: 16,
            max_replay_page_size: 4,
        },
    )
    .unwrap();
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    applied(broker.issue_lease(
        lease_request(
            1_460,
            binding.clone(),
            "2026-07-24T12:00:00.000000Z",
            "2026-07-24T12:01:00.000000Z",
            "2026-07-24T12:00:00.000000Z",
            1,
        ),
        &active_context(&authority, &binding, &current),
    ));
    clock.set(parsed_time("2026-07-24T12:01:00.000000Z"));
    assert!(matches!(
        broker.issue_lease(
            lease_request(
                1_461,
                binding.clone(),
                "2026-07-24T12:01:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:01:00.000000Z",
                1,
            ),
            &active_context(&authority, &binding, &current),
        ),
        Ok(SecretBrokerCommandOutcome::Applied(_))
    ));
}

fn forged_handle(grant: &SecretLeaseGrant) -> SecretDeliveryHandle {
    SecretDeliveryHandle {
        delivery_handle_id: grant.handle().delivery_handle_id().clone(),
        secret_lease_id: grant.handle().secret_lease_id().clone(),
        capability_nonce: uuid(99_999),
    }
}

#[test]
fn claim_denials_cover_future_binding_authority_handle_and_rollback_paths() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);

    let future = broker_fixture(default_policy(3, true));
    let future_grant = future
        .broker
        .issue_lease(
            lease_request(
                1_500,
                binding.clone(),
                "2026-07-24T12:01:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                2,
            ),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    assert_eq!(
        future
            .broker
            .claim_use(
                secret_id(1_501),
                future_grant.handle(),
                &binding,
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::LeaseNotStarted
    );

    let mismatched = broker_fixture(default_policy(3, true));
    let grant = mismatched
        .broker
        .issue_lease(
            initial_request(1_510, 2),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    let changed = use_binding(Some(BindingChange::Principal));
    assert_eq!(
        mismatched
            .broker
            .claim_use(
                secret_id(1_511),
                grant.handle(),
                &changed,
                &active_context(&active, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::SecretNotAvailable
    );
    assert_eq!(
        mismatched
            .broker
            .claim_use(
                secret_id(1_512),
                &forged_handle(&grant),
                &binding,
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );

    let denied = broker_fixture(default_policy(3, true));
    let grant = denied
        .broker
        .issue_lease(
            initial_request(1_520, 2),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    let missing = authority_fixture(AuthorityState::Missing);
    assert_eq!(
        denied
            .broker
            .claim_use(
                secret_id(1_521),
                grant.handle(),
                &binding,
                &active_context(&missing, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );

    let rollback = broker_fixture(default_policy(3, true));
    let grant = rollback
        .broker
        .issue_lease(
            initial_request(1_530, 2),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    rollback
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_eq!(
        rollback
            .broker
            .claim_use(
                secret_id(1_531),
                grant.handle(),
                &binding,
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::ClockRollback
    );
}

#[test]
fn renewal_denials_cover_handle_binding_authority_policy_capacity_and_rollback() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);

    let fixture = broker_fixture(default_policy(3, true));
    let old = fixture
        .broker
        .issue_lease(
            initial_request(1_600, 3),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    fixture
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    let request = lease_request(
        1_601,
        binding.clone(),
        "2026-07-24T12:01:00.000000Z",
        "2026-07-24T12:05:00.000000Z",
        "2026-07-24T12:01:00.000000Z",
        3,
    );
    assert_eq!(
        fixture
            .broker
            .renew_lease(
                secret_id(1_602),
                &forged_handle(&old),
                request,
                &active_context(&active, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::SecretNotAvailable
    );

    let mismatch = broker_fixture(default_policy(3, true));
    let old = mismatch
        .broker
        .issue_lease(
            initial_request(1_610, 3),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    mismatch
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    let changed = use_binding(Some(BindingChange::Principal));
    assert_eq!(
        mismatch
            .broker
            .renew_lease(
                secret_id(1_611),
                old.handle(),
                lease_request(
                    1_612,
                    changed.clone(),
                    "2026-07-24T12:01:00.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:01:00.000000Z",
                    3,
                ),
                &active_context(&active, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::SecretNotAvailable
    );

    let authority_denied = broker_fixture(default_policy(3, true));
    let old = authority_denied
        .broker
        .issue_lease(
            initial_request(1_620, 3),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    authority_denied
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    let missing = authority_fixture(AuthorityState::Missing);
    assert_eq!(
        authority_denied
            .broker
            .renew_lease(
                secret_id(1_621),
                old.handle(),
                lease_request(
                    1_622,
                    binding.clone(),
                    "2026-07-24T12:01:00.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:01:00.000000Z",
                    3,
                ),
                &active_context(&missing, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::SecretNotAvailable
    );

    let nonrenewable = broker_fixture(default_policy(3, false));
    let old = nonrenewable
        .broker
        .issue_lease(
            initial_request(1_630, 3),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    nonrenewable
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    assert_eq!(
        nonrenewable
            .broker
            .renew_lease(
                secret_id(1_631),
                old.handle(),
                lease_request(
                    1_632,
                    binding.clone(),
                    "2026-07-24T12:01:00.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:01:00.000000Z",
                    3,
                ),
                &active_context(&active, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::RenewalDenied
    );

    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let limits = ProcessLocalSecretBrokerLimits {
        max_secret_refs: 1,
        max_providers: 1,
        max_active_leases: 1,
        max_retained_leases: 1,
        max_command_records: 8,
        max_evidence_events: 8,
        max_generated_ids: 32,
        max_replay_page_size: 8,
    };
    let clock = Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")));
    let capacity = ProcessLocalSecretBroker::with_sources_and_limits(
        tenant(2),
        vec![secret_ref(
            provider.provider_id.clone(),
            default_policy(3, true),
            SecretClassification::AuthenticationCredential,
        )],
        vec![provider],
        clock.clone(),
        Arc::new(SequenceIds::default()),
        limits,
    )
    .unwrap();
    let old = capacity
        .issue_lease(
            initial_request(1_640, 3),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    clock.set(parsed_time("2026-07-24T12:01:00.000000Z"));
    assert_eq!(
        capacity
            .renew_lease(
                secret_id(1_641),
                old.handle(),
                lease_request(
                    1_642,
                    binding.clone(),
                    "2026-07-24T12:01:00.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:01:00.000000Z",
                    3,
                ),
                &active_context(&active, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::CapacityExceeded
    );

    let rollback = broker_fixture(default_policy(3, true));
    let old = rollback
        .broker
        .issue_lease(
            initial_request(1_650, 3),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    rollback
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_eq!(
        rollback
            .broker
            .renew_lease(
                secret_id(1_651),
                old.handle(),
                lease_request(
                    1_652,
                    binding.clone(),
                    "2026-07-24T12:00:00.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:00:00.000000Z",
                    3,
                ),
                &active_context(&active, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::ClockRollback
    );
}

#[test]
fn revocation_denials_and_repeat_command_cover_closed_handle_paths() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);

    let fixture = broker_fixture(default_policy(3, true));
    let grant = fixture
        .broker
        .issue_lease(
            initial_request(1_700, 3),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    assert_eq!(
        fixture
            .broker
            .revoke_lease(
                secret_id(1_701),
                &forged_handle(&grant),
                &binding,
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );
    let changed = use_binding(Some(BindingChange::Principal));
    assert_eq!(
        fixture
            .broker
            .revoke_lease(
                secret_id(1_702),
                grant.handle(),
                &changed,
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );
    let first = fixture
        .broker
        .revoke_lease(
            secret_id(1_703),
            grant.handle(),
            &binding,
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    let second = fixture
        .broker
        .revoke_lease(
            secret_id(1_704),
            grant.handle(),
            &binding,
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    assert_eq!(
        first.revocation_generation(),
        second.revocation_generation()
    );

    let rollback = broker_fixture(default_policy(3, true));
    let grant = rollback
        .broker
        .issue_lease(
            initial_request(1_710, 3),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    rollback
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_eq!(
        rollback
            .broker
            .revoke_lease(
                secret_id(1_711),
                grant.handle(),
                &binding,
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::ClockRollback
    );

    let superseded = broker_fixture(default_policy(3, true));
    let old = superseded
        .broker
        .issue_lease(
            initial_request(1_720, 3),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    superseded
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    superseded
        .broker
        .renew_lease(
            secret_id(1_721),
            old.handle(),
            lease_request(
                1_722,
                binding.clone(),
                "2026-07-24T12:01:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:01:00.000000Z",
                3,
            ),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    assert_eq!(
        superseded
            .broker
            .revoke_lease(
                secret_id(1_723),
                old.handle(),
                &binding,
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );
}

#[test]
fn retained_binding_corruption_fails_closed_for_claim_renew_and_revoke() {
    let binding = use_binding(None);
    let changed = use_binding(Some(BindingChange::Principal));
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);

    let claim = broker_fixture(default_policy(3, true));
    let grant = applied(claim.broker.issue_lease(
        initial_request(1_730, 3),
        &active_context(&active, &binding, &current),
    ));
    claim
        .broker
        .lock_state()
        .unwrap()
        .leases
        .get_mut(grant.snapshot().secret_lease_id())
        .unwrap()
        .request = lease_request(
        1_731,
        changed.clone(),
        "2026-07-24T12:00:00.000000Z",
        "2026-07-24T12:05:00.000000Z",
        "2026-07-24T12:00:00.000000Z",
        3,
    );
    assert_eq!(
        claim
            .broker
            .claim_use(
                secret_id(1_732),
                grant.handle(),
                &binding,
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );

    let renewal = broker_fixture(default_policy(3, true));
    let old = applied(renewal.broker.issue_lease(
        initial_request(1_740, 3),
        &active_context(&active, &binding, &current),
    ));
    renewal
        .broker
        .lock_state()
        .unwrap()
        .leases
        .get_mut(old.snapshot().secret_lease_id())
        .unwrap()
        .request = lease_request(
        1_741,
        changed.clone(),
        "2026-07-24T12:00:00.000000Z",
        "2026-07-24T12:05:00.000000Z",
        "2026-07-24T12:00:00.000000Z",
        3,
    );
    renewal
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    assert_eq!(
        renewal
            .broker
            .renew_lease(
                secret_id(1_742),
                old.handle(),
                lease_request(
                    1_743,
                    binding.clone(),
                    "2026-07-24T12:00:30.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:00:30.000000Z",
                    3,
                ),
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::RenewalDenied
    );

    let revocation = broker_fixture(default_policy(3, true));
    let grant = applied(revocation.broker.issue_lease(
        initial_request(1_750, 3),
        &active_context(&active, &binding, &current),
    ));
    revocation
        .broker
        .lock_state()
        .unwrap()
        .leases
        .get_mut(grant.snapshot().secret_lease_id())
        .unwrap()
        .request = lease_request(
        1_751,
        changed,
        "2026-07-24T12:00:00.000000Z",
        "2026-07-24T12:05:00.000000Z",
        "2026-07-24T12:00:00.000000Z",
        3,
    );
    assert_eq!(
        revocation
            .broker
            .revoke_lease(
                secret_id(1_752),
                grant.handle(),
                &binding,
                &active_context(&active, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::SecretNotAvailable
    );
}

#[test]
fn short_authority_window_cannot_authorize_full_lease_lifecycle_window() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let now = parsed_time("2026-07-24T12:00:00.000000Z");
    let narrow = active_authority_fixture_at(&binding, now, now + Duration::minutes(1));

    let issue = broker_fixture(default_policy(3, true));
    assert_eq!(
        issue
            .broker
            .issue_lease(
                initial_request(1_760, 3),
                &active_context(&narrow, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::AuthorityDenied
    );

    let active = authority_fixture(AuthorityState::Active);
    let claim = broker_fixture(default_policy(3, true));
    let grant = applied(claim.broker.issue_lease(
        initial_request(1_770, 3),
        &active_context(&active, &binding, &current),
    ));
    assert_eq!(
        claim
            .broker
            .claim_use(
                secret_id(1_771),
                grant.handle(),
                &binding,
                &active_context(&narrow, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::AuthorityDenied
    );

    let renewal = broker_fixture(default_policy(3, true));
    let old = applied(renewal.broker.issue_lease(
        initial_request(1_780, 3),
        &active_context(&active, &binding, &current),
    ));
    let renewal_now = now + Duration::minutes(1);
    renewal.clock.set(renewal_now);
    let renewal_authority =
        active_authority_fixture_at(&binding, renewal_now, renewal_now + Duration::minutes(1));
    assert_eq!(
        renewal
            .broker
            .renew_lease(
                secret_id(1_781),
                old.handle(),
                lease_request(
                    1_782,
                    binding.clone(),
                    "2026-07-24T12:00:30.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:00:30.000000Z",
                    3,
                ),
                &active_context(&renewal_authority, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::AuthorityDenied
    );

    let revocation = broker_fixture(default_policy(3, true));
    let grant = applied(revocation.broker.issue_lease(
        initial_request(1_790, 3),
        &active_context(&active, &binding, &current),
    ));
    assert_eq!(
        revocation
            .broker
            .revoke_lease(
                secret_id(1_791),
                grant.handle(),
                &binding,
                &active_context(&narrow, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::AuthorityDenied
    );
}

#[test]
fn private_helpers_fail_closed_for_invalid_pages_time_ids_and_terminal_shapes() {
    let fixture = broker_fixture(default_policy(2, true));
    assert_eq!(
        fixture.broker.replay_page(1, 1).unwrap_err(),
        SecretBrokerError::InvalidPage
    );
    assert_eq!(
        canonical_timestamp(parsed_time("2026-07-24T12:00:00.000000Z") + Duration::nanoseconds(1))
            .unwrap_err(),
        SecretBrokerError::ClockUnavailable
    );

    let mut state = SecretBrokerState::default();
    let duplicate = uuid(2_000);
    assert_eq!(
        fixture
            .broker
            .reserve_generated_ids(
                &mut state,
                &[duplicate, duplicate],
                SecretBrokerError::EvidenceUnavailable,
            )
            .unwrap_err(),
        SecretBrokerError::EvidenceUnavailable
    );
    fixture
        .broker
        .reserve_generated_ids(
            &mut state,
            &[duplicate],
            SecretBrokerError::EvidenceUnavailable,
        )
        .unwrap();
    assert_eq!(
        fixture
            .broker
            .reserve_generated_ids(
                &mut state,
                &[duplicate],
                SecretBrokerError::EvidenceUnavailable,
            )
            .unwrap_err(),
        SecretBrokerError::EvidenceUnavailable
    );

    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let authority = active_context(&authority, &binding, &current);
    let key = trusted_command_key(
        SecretCommandKind::Issue,
        "shape-test".to_string(),
        &authority,
    );
    let digest = ContentHash::blake3(b"shape-test");
    state.commands.insert(
        key.clone(),
        SecretCommandRecord {
            semantic_digest: digest.clone(),
            terminal: SecretCommandTerminal::Revoke(Err(SecretBrokerError::AuthorityDenied)),
        },
    );
    assert!(matches!(
        retry_issue(&state, &key, &digest),
        Some(Err(SecretBrokerError::StateUnavailable))
    ));
    assert!(matches!(
        retry_claim(&state, &key, &digest),
        Some(Err(SecretBrokerError::StateUnavailable))
    ));
    assert!(matches!(
        retry_renew(&state, &key, &digest),
        Some(Err(SecretBrokerError::StateUnavailable))
    ));
    assert!(matches!(
        retry_revoke(&state, &key, &ContentHash::blake3(b"changed")),
        Some(Err(SecretBrokerError::SecretNotAvailable))
    ));
    assert!(retry_issue(
        &state,
        &trusted_command_key(SecretCommandKind::Issue, "missing".to_string(), &authority),
        &digest,
    )
    .is_none());

    let revoke_key = trusted_command_key(
        SecretCommandKind::Revoke,
        "wrong-terminal".to_string(),
        &authority,
    );
    state.commands.insert(
        revoke_key.clone(),
        SecretCommandRecord {
            semantic_digest: digest.clone(),
            terminal: SecretCommandTerminal::Claim(Err(SecretBrokerError::AuthorityDenied)),
        },
    );
    assert!(matches!(
        retry_revoke(&state, &revoke_key, &digest),
        Some(Err(SecretBrokerError::StateUnavailable))
    ));

    let corrupt_history_key = trusted_command_key(
        SecretCommandKind::Issue,
        "corrupt-history".to_string(),
        &authority,
    );
    state.commands.insert(
        corrupt_history_key.clone(),
        SecretCommandRecord {
            semantic_digest: digest.clone(),
            terminal: SecretCommandTerminal::Issue(Ok(HistoricalSecretBrokerRecord {
                event_index: state.events.len(),
                event_id: secret_id(2_001),
            })),
        },
    );
    assert!(matches!(
        retry_issue(&state, &corrupt_history_key, &digest),
        Some(Err(SecretBrokerError::StateUnavailable))
    ));
}

#[test]
fn private_result_and_visibility_helpers_are_non_authorizing_and_redacted() {
    assert_eq!(
        SecretBrokerConfigError::InvalidTenant.to_string(),
        "secret_broker_tenant_invalid"
    );
    assert_eq!(
        SecretBrokerConfigError::MixedTenant.to_string(),
        "secret_broker_tenant_mismatch"
    );

    let applied_outcome = SecretBrokerCommandOutcome::Applied(());
    assert_eq!(
        format!("{applied_outcome:?}"),
        "SecretBrokerCommandOutcome::Applied(<private>)"
    );
    assert!(applied_outcome.historical().is_none());

    let fixture = broker_fixture(default_policy(2, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let request = initial_request(1_795, 2);
    applied(fixture.broker.issue_lease(
        request.clone(),
        &active_context(&authority, &binding, &current),
    ));
    let historical_outcome = fixture
        .broker
        .issue_lease(
            request.clone(),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    assert_eq!(
        format!("{historical_outcome:?}"),
        "SecretBrokerCommandOutcome::Historical(<redacted>)"
    );
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = historical_outcome.snapshot();
    }))
    .is_err());
    assert!(fixture
        .broker
        .issue_lease(request, &active_context(&authority, &binding, &current),)
        .unwrap()
        .into_applied()
        .is_err());

    let state = fixture.broker.lock_state().unwrap();
    let changed = use_binding(Some(BindingChange::Principal));
    assert!(!fixture.broker.current_visibility(
        &state,
        &active_context(&authority, &binding, &current),
        &changed,
        parsed_time("2026-07-24T12:00:00.000000Z"),
    ));
    assert!(!fixture.broker.current_visibility(
        &state,
        &active_context(&authority, &binding, &current),
        &binding,
        parsed_time("9999-12-31T23:59:59.999999999Z"),
    ));

    let missing = SecretBrokerState::default();
    assert_eq!(
        fixture
            .broker
            .validate_issue(
                &missing,
                &initial_request(1_796, 2),
                &active_context(&authority, &binding, &current),
                parsed_time("2026-07-24T12:00:00.000000Z"),
            )
            .err()
            .unwrap(),
        (
            SecretBrokerError::SecretNotAvailable,
            SecretAccessDenialCode::SecretNotAvailable,
        )
    );

    let changed = use_binding(Some(BindingChange::RefRevision));
    let changed_declaration = declaration(&changed);
    let changed_authority = authority_fixture_for(&changed, AuthorityState::Active);
    assert_eq!(
        fixture
            .broker
            .validate_issue(
                &state,
                &lease_request(
                    1_797,
                    changed.clone(),
                    "2026-07-24T12:00:00.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:00:00.000000Z",
                    2,
                ),
                &active_context(&changed_authority, &changed, &changed_declaration),
                parsed_time("2026-07-24T12:00:00.000000Z"),
            )
            .err()
            .unwrap(),
        (
            SecretBrokerError::SecretNotAvailable,
            SecretAccessDenialCode::BindingMismatch,
        )
    );
}

#[test]
fn private_owner_invariants_cover_reentrancy_timeout_clock_ids_and_event_capacity() {
    let first_scope = SecretBrokerCallbackThreadScope::enter().unwrap();
    assert_eq!(
        SecretBrokerCallbackThreadScope::enter().err().unwrap(),
        SecretBrokerError::StateUnavailable
    );
    drop(first_scope);

    let fixture = broker_fixture(default_policy(2, true));
    {
        let mut gate = fixture.broker.mutation_gate.lock().unwrap();
        gate.callback_in_progress = true;
    }
    assert_eq!(
        fixture.broker.lock_mutation().err().unwrap(),
        SecretBrokerError::StateUnavailable
    );
    fixture
        .broker
        .mutation_gate
        .lock()
        .unwrap()
        .callback_in_progress = false;

    let clock = Arc::new(ManualClock::new(
        parsed_time("2026-07-24T12:00:00.000000Z") + Duration::nanoseconds(1),
    ));
    let nanosecond_broker = ProcessLocalSecretBroker::with_sources(
        tenant(2),
        Vec::new(),
        Vec::new(),
        clock,
        Arc::new(SequenceIds::default()),
    )
    .unwrap();
    let mut mutation = nanosecond_broker.lock_mutation().unwrap();
    assert_eq!(
        nanosecond_broker.observe_time(&mut mutation).unwrap_err(),
        SecretBrokerError::ClockUnavailable
    );
    drop(mutation);

    let nil_id_broker = ProcessLocalSecretBroker::with_sources(
        tenant(2),
        Vec::new(),
        Vec::new(),
        Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
        Arc::new(NilIds),
    )
    .unwrap();
    let mut mutation = nil_id_broker.lock_mutation().unwrap();
    assert_eq!(
        nil_id_broker
            .next_non_nil_uuid(&mut mutation, SecretBrokerIdKind::Lease)
            .unwrap_err(),
        SecretBrokerError::StateUnavailable
    );

    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let limits = ProcessLocalSecretBrokerLimits {
        max_secret_refs: 1,
        max_providers: 1,
        max_active_leases: 1,
        max_retained_leases: 1,
        max_command_records: 2,
        max_evidence_events: 1,
        max_generated_ids: 8,
        max_replay_page_size: 1,
    };
    let capacity = ProcessLocalSecretBroker::with_sources_and_limits(
        tenant(2),
        vec![secret_ref(
            provider.provider_id.clone(),
            default_policy(2, true),
            SecretClassification::AuthenticationCredential,
        )],
        vec![provider],
        Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
        Arc::new(SequenceIds::default()),
        limits,
    )
    .unwrap();
    let binding = use_binding(None);
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);
    capacity
        .issue_lease(
            initial_request(1_800, 2),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    let mut state = capacity.lock_state().unwrap();
    let event = state.events[0].clone();
    assert_eq!(
        capacity.append_event(&mut state, event).unwrap_err(),
        SecretBrokerError::CapacityExceeded
    );
}

#[test]
fn direct_validation_covers_consumed_request_time_and_current_declaration_denials() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let active = authority_fixture(AuthorityState::Active);
    let fixture = broker_fixture(default_policy(3, true));
    let request = initial_request(1_900, 2);
    {
        let mut state = fixture.broker.lock_state().unwrap();
        state
            .used_request_ids
            .insert(scoped_lease_request_id(&request));
        assert_eq!(
            fixture
                .broker
                .validate_issue(
                    &state,
                    &request,
                    &active_context(&active, &binding, &current),
                    parsed_time("2026-07-24T12:00:00.000000Z"),
                )
                .err()
                .unwrap(),
            (
                SecretBrokerError::RequestAlreadyUsed,
                SecretAccessDenialCode::RequestAlreadyUsed,
            )
        );
        state.used_request_ids.clear();
    }

    fixture
        .clock
        .set(parsed_time("2026-07-24T12:00:01.000000Z"));
    assert_eq!(
        fixture
            .broker
            .issue_lease(request, &active_context(&active, &binding, &current),)
            .err()
            .unwrap(),
        SecretBrokerError::SecretNotAvailable
    );

    let renewal = broker_fixture(default_policy(3, true));
    let old = renewal
        .broker
        .issue_lease(
            initial_request(1_910, 3),
            &active_context(&active, &binding, &current),
        )
        .unwrap();
    renewal
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    let stale_binding = use_binding(Some(BindingChange::DeclarationRevision));
    let stale_declaration = declaration(&stale_binding);
    assert_eq!(
        renewal
            .broker
            .renew_lease(
                secret_id(1_911),
                old.handle(),
                lease_request(
                    1_912,
                    binding.clone(),
                    "2026-07-24T12:01:00.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:01:00.000000Z",
                    3,
                ),
                &active_context(&active, &binding, &stale_declaration),
            )
            .err()
            .unwrap(),
        SecretBrokerError::SecretNotAvailable
    );
}

#[test]
fn current_secret_ref_windows_and_permit_revalidation_fail_closed() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let now = parsed_time("2026-07-24T12:00:00.000000Z");
    let provider_id: SecretProviderId = secret_id(10);
    let policy = default_policy(2, true);

    let future = secret_ref_with_window(
        provider_id.clone(),
        policy,
        SecretClassification::AuthenticationCredential,
        "2026-07-24T12:01:00.000000Z",
        None,
    );
    assert!(!secret_ref_allows_binding(&future, &binding, &current, now));

    let disabled = secret_ref_with_window(
        provider_id.clone(),
        policy,
        SecretClassification::AuthenticationCredential,
        "2026-07-24T11:00:00.000000Z",
        Some("2026-07-24T12:00:00.000000Z"),
    );
    assert!(!secret_ref_allows_binding(
        &disabled, &binding, &current, now
    ));
    let not_yet_disabled = secret_ref_with_window(
        provider_id.clone(),
        policy,
        SecretClassification::AuthenticationCredential,
        "2026-07-24T11:00:00.000000Z",
        Some("2026-07-24T12:01:00.000000Z"),
    );
    assert!(secret_ref_allows_binding(
        &not_yet_disabled,
        &binding,
        &current,
        now,
    ));

    let mut state = SecretBrokerState::default();
    state.refs.insert(
        (binding.tenant_id().clone(), binding.secret_ref_id().clone()),
        secret_ref(
            provider_id,
            policy,
            SecretClassification::AuthenticationCredential,
        ),
    );
    let authority = authority_fixture(AuthorityState::Active);
    let stale_binding = use_binding(Some(BindingChange::DeclarationRevision));
    let stale_declaration = declaration(&stale_binding);
    assert!(validated_authority_permit(
        &state,
        &active_context(&authority, &binding, &stale_declaration),
        &binding,
        now,
        now + Duration::minutes(5),
    )
    .is_none());
}

fn broker_with_ids(ids: Arc<dyn SecretBrokerIdSource>) -> ProcessLocalSecretBroker {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    ProcessLocalSecretBroker::with_sources(
        tenant(2),
        vec![secret_ref(
            provider.provider_id.clone(),
            default_policy(3, true),
            SecretClassification::AuthenticationCredential,
        )],
        vec![provider],
        Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
        ids,
    )
    .unwrap()
}

#[test]
fn generated_identity_collisions_leave_issue_claim_renew_revoke_and_denial_atomic() {
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);

    let issue = broker_with_ids(Arc::new(ScriptedIds::new([1, 1, 1, 1])));
    assert_eq!(
        issue
            .issue_lease(
                initial_request(2_000, 2),
                &active_context(&authority, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::StateUnavailable
    );
    assert!(issue.replay_page(0, 1).unwrap().events.is_empty());

    let claim = broker_with_ids(Arc::new(ScriptedIds::new([1, 2, 3, 4, 5, 6, 6])));
    let grant = claim
        .issue_lease(
            initial_request(2_010, 2),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    assert_eq!(
        claim
            .claim_use(
                secret_id(2_011),
                grant.handle(),
                &binding,
                &active_context(&authority, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::StateUnavailable
    );
    assert_eq!(
        claim
            .inspect_lease(grant.snapshot().secret_lease_id())
            .unwrap()
            .unwrap()
            .uses_claimed(),
        0
    );

    let renewal = broker_with_ids(Arc::new(ScriptedIds::new([1, 2, 3, 4, 5, 6, 6, 7])));
    let old = renewal
        .issue_lease(
            initial_request(2_020, 3),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    assert_eq!(
        renewal
            .renew_lease(
                secret_id(2_021),
                old.handle(),
                lease_request(
                    2_022,
                    binding.clone(),
                    "2026-07-24T12:00:00.000000Z",
                    "2026-07-24T12:05:00.000000Z",
                    "2026-07-24T12:00:00.000000Z",
                    3,
                ),
                &active_context(&authority, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::StateUnavailable
    );

    let revoke = broker_with_ids(Arc::new(ScriptedIds::new([1, 2, 3, 4, 1])));
    let grant = revoke
        .issue_lease(
            initial_request(2_030, 2),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    assert_eq!(
        revoke
            .revoke_lease(
                secret_id(2_031),
                grant.handle(),
                &binding,
                &active_context(&authority, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::EvidenceUnavailable
    );
    assert_eq!(
        revoke
            .inspect_lease(grant.snapshot().secret_lease_id())
            .unwrap()
            .unwrap()
            .status(),
        SecretLeaseStatus::Active
    );

    let denial = broker_with_ids(Arc::new(ScriptedIds::new([1, 2, 3, 4, 1, 5, 6])));
    let grant = denial
        .issue_lease(
            initial_request(2_040, 2),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    assert_eq!(
        denial
            .claim_use(
                secret_id(2_041),
                &forged_handle(&grant),
                &binding,
                &active_context(&authority, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::EvidenceUnavailable
    );
}

#[test]
fn unavailable_clock_fails_claim_renew_and_revoke_before_mutation() {
    let fixture = broker_fixture(default_policy(3, true));
    let binding = use_binding(None);
    let current = declaration(&binding);
    let authority = authority_fixture(AuthorityState::Active);
    let claim = fixture
        .broker
        .issue_lease(
            initial_request(2_100, 2),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    let renewal = fixture
        .broker
        .issue_lease(
            initial_request(2_101, 3),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    let revoke = fixture
        .broker
        .issue_lease(
            initial_request(2_102, 2),
            &active_context(&authority, &binding, &current),
        )
        .unwrap();
    *fixture.clock.now.lock().unwrap() = None;
    assert_eq!(
        fixture
            .broker
            .claim_use(
                secret_id(2_103),
                claim.handle(),
                &binding,
                &active_context(&authority, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::ClockUnavailable
    );
    assert_eq!(
        fixture
            .broker
            .renew_lease(
                secret_id(2_104),
                renewal.handle(),
                initial_request(2_105, 3),
                &active_context(&authority, &binding, &current),
            )
            .err()
            .unwrap(),
        SecretBrokerError::ClockUnavailable
    );
    assert_eq!(
        fixture
            .broker
            .revoke_lease(
                secret_id(2_106),
                revoke.handle(),
                &binding,
                &active_context(&authority, &binding, &current),
            )
            .unwrap_err(),
        SecretBrokerError::ClockUnavailable
    );
}
