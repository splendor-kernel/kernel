use super::*;
use crate::{
    AuthorityConnectivity, AuthorityOfflineHighRiskBehavior, CachedAuthorityGrant,
    OfflineAuthorityPolicy,
};
use splendor_types::{
    AuthorityRevocationId, CapabilityGrantId, DriverCredentialDestinationDigest,
    DriverTrustedSendProfileV1, PrincipalId, RevocationRecord, SecretClassification,
    SecretCredentialAuthorizationV2, SecretCredentialSlotId, SecretDeliveryExposureProfile,
    SecretLeasePolicy, SecretOfflineBehavior, SecretPurpose, SecretRefV2, SecretUseIntent,
    SecretUseRequirement, REVOCATION_RECORD_SCHEMA_VERSION,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Barrier, Mutex};

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

fn node(index: u128) -> splendor_types::NodeId {
    splendor_types::NodeId::from(uuid(index))
}

fn instance(index: u128) -> splendor_types::InstanceId {
    splendor_types::InstanceId::from(uuid(index))
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

fn destination_digest() -> DriverCredentialDestinationDigest {
    "blake3:1111111111111111111111111111111111111111111111111111111111111111"
        .parse()
        .unwrap()
}

#[derive(Clone, Copy)]
enum BindingChange {
    Tenant,
    Principal,
    Workload,
    Operation,
    Slot,
    Node,
    Instance,
    Audience,
    Purpose,
    Ref,
    Version,
}

fn use_binding(change: Option<BindingChange>) -> SecretLeaseUseBinding {
    let tenant_id = tenant(if matches!(change, Some(BindingChange::Tenant)) {
        102
    } else {
        2
    });
    let principal_id = principal(if matches!(change, Some(BindingChange::Principal)) {
        103
    } else {
        3
    });
    let workload_id = workload(if matches!(change, Some(BindingChange::Workload)) {
        104
    } else {
        4
    });
    let driver_operation = operation(if matches!(change, Some(BindingChange::Operation)) {
        "post"
    } else {
        "fetch"
    });
    let slot_id =
        secret_id::<SecretCredentialSlotId>(if matches!(change, Some(BindingChange::Slot)) {
            105
        } else {
            5
        });
    let node_id = node(if matches!(change, Some(BindingChange::Node)) {
        106
    } else {
        6
    });
    let audience_id = secret_id(if matches!(change, Some(BindingChange::Audience)) {
        107
    } else {
        7
    });
    let purpose = if matches!(change, Some(BindingChange::Purpose)) {
        SecretPurpose::ArtifactStoreAccess
    } else {
        SecretPurpose::ExternalServiceAccess
    };
    let secret_ref_id = secret_id(if matches!(change, Some(BindingChange::Ref)) {
        108
    } else {
        8
    });
    let version = if matches!(change, Some(BindingChange::Version)) {
        "version-2"
    } else {
        "version-1"
    };
    SecretLeaseUseBinding::try_new(
        tenant_id,
        principal_id,
        workload_id,
        driver_operation,
        1,
        slot_id,
        "splendor.driver.destination.http.v1",
        destination_digest(),
        SecretDeliveryExposureProfile::MaterialExposed,
        node_id,
        instance(if matches!(change, Some(BindingChange::Instance)) {
            109
        } else {
            9
        }),
        audience_id,
        secret_ref_id,
        1,
        version.parse().unwrap(),
        SecretUseIntent::Authenticate,
        purpose,
    )
    .unwrap()
}

fn secret_ref(provider_id: SecretProviderId, policy: SecretLeasePolicy) -> SecretRefV2 {
    secret_ref_with_window(provider_id, policy, "2026-07-24T11:00:00.000000Z", None)
}

fn secret_ref_with_window(
    provider_id: SecretProviderId,
    policy: SecretLeasePolicy,
    created_at: &str,
    disabled_at: Option<&str>,
) -> SecretRefV2 {
    let binding = use_binding(None);
    let authorization = SecretCredentialAuthorizationV2::try_new(
        binding.driver_operation().clone(),
        binding.driver_declaration_revision(),
        binding.credential_slot_id(),
        binding.destination_schema(),
        binding.delivery_exposure_profile(),
        DriverTrustedSendProfileV1::not_applicable(),
        vec![binding.destination_digest()],
    )
    .unwrap();
    SecretRefV2::try_new(
        binding.secret_ref_id().clone(),
        binding.secret_ref_revision(),
        binding.tenant_id().clone(),
        provider_id,
        "test",
        "http-credential",
        binding.provider_version_ref().clone(),
        SecretClassification::AuthenticationCredential,
        vec![authorization],
        vec![SecretDeliveryMethod::InheritedFd],
        policy,
        SecretOfflineBehavior::Deny,
        created_at,
        disabled_at.map(str::to_string),
    )
    .unwrap()
}

fn lease_request(
    request_index: u128,
    binding: SecretLeaseUseBinding,
    starts_at: &str,
    expires_at: &str,
    requested_at: &str,
    max_uses: u64,
) -> SecretLeaseRequest {
    lease_request_with_methods(
        request_index,
        binding,
        starts_at,
        expires_at,
        requested_at,
        max_uses,
        vec![SecretDeliveryMethod::InheritedFd],
    )
}

#[allow(clippy::too_many_arguments)]
fn lease_request_with_methods(
    request_index: u128,
    binding: SecretLeaseUseBinding,
    starts_at: &str,
    expires_at: &str,
    requested_at: &str,
    max_uses: u64,
    delivery_methods: Vec<SecretDeliveryMethod>,
) -> SecretLeaseRequest {
    let starts = parsed_time(starts_at);
    let expires = parsed_time(expires_at);
    let duration = u64::try_from((expires - starts).whole_seconds()).unwrap();
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

#[derive(Debug)]
struct UnavailableClock;

impl SecretBrokerClock for UnavailableClock {
    fn now_utc(&self) -> Option<OffsetDateTime> {
        None
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

#[derive(Debug, Default)]
struct RepeatingIssueIds {
    next: AtomicU64,
}

impl SecretBrokerIdSource for RepeatingIssueIds {
    fn next_uuid(&self, _kind: SecretBrokerIdKind) -> Option<Uuid> {
        let ordinal = self.next.fetch_add(1, Ordering::SeqCst) % 4;
        Some(uuid(20_000 + u128::from(ordinal)))
    }
}

#[derive(Debug)]
struct FailingIds {
    fail_kind: SecretBrokerIdKind,
    successful_matches_before_failure: u64,
    matching_calls: AtomicU64,
    next: AtomicU64,
    return_nil: bool,
}

impl FailingIds {
    fn new(
        fail_kind: SecretBrokerIdKind,
        successful_matches_before_failure: u64,
        return_nil: bool,
    ) -> Self {
        Self {
            fail_kind,
            successful_matches_before_failure,
            matching_calls: AtomicU64::new(0),
            next: AtomicU64::new(0),
            return_nil,
        }
    }
}

impl SecretBrokerIdSource for FailingIds {
    fn next_uuid(&self, kind: SecretBrokerIdKind) -> Option<Uuid> {
        if kind == self.fail_kind {
            let matching = self.matching_calls.fetch_add(1, Ordering::SeqCst);
            if matching >= self.successful_matches_before_failure {
                return self.return_nil.then(Uuid::nil);
            }
        }
        let ordinal = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        Some(uuid(30_000 + u128::from(ordinal)))
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

    fn fetch(
        &self,
        _request: &SecretProviderFetchRequest,
    ) -> Result<SecretProviderFetchResult, SecretProviderError> {
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
    events: Arc<InMemorySecretBrokerEventSink>,
    provider: Arc<TrapProvider>,
}

fn broker_fixture(policy: SecretLeasePolicy) -> BrokerFixture {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let provider_port: Arc<dyn SecretProvider> = provider.clone();
    let clock = Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")));
    let ids = Arc::new(SequenceIds::default());
    let events = Arc::new(InMemorySecretBrokerEventSink::new());
    let broker = ProcessLocalSecretBroker::with_sources(
        vec![secret_ref(provider.provider_id.clone(), policy)],
        vec![provider_port],
        clock.clone(),
        ids.clone(),
        events.clone(),
    )
    .unwrap();
    BrokerFixture {
        broker: Arc::new(broker),
        clock,
        ids,
        events,
        provider,
    }
}

fn custom_broker(
    clock: Arc<dyn SecretBrokerClock>,
    ids: Arc<dyn SecretBrokerIdSource>,
    events: Arc<dyn SecretBrokerEventSink>,
) -> (ProcessLocalSecretBroker, Arc<TrapProvider>) {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let provider_port: Arc<dyn SecretProvider> = provider.clone();
    let broker = ProcessLocalSecretBroker::with_sources(
        vec![secret_ref(
            provider.provider_id.clone(),
            default_policy(2, true),
        )],
        vec![provider_port],
        clock,
        ids,
        events,
    )
    .unwrap();
    (broker, provider)
}

struct AuthorityFixture {
    cache: AuthorityGrantCache,
    revocations: Option<RevocationSnapshot>,
    policy: OfflineAuthorityPolicy,
}

impl AuthorityFixture {
    fn context(&self) -> SecretBrokerAuthorityContext<'_> {
        SecretBrokerAuthorityContext::new(&self.cache, self.revocations.as_ref(), &self.policy)
    }
}

#[derive(Clone, Copy)]
enum AuthorityState {
    Active,
    Missing,
    Expired,
    Revoked,
    Stale,
    MissingSnapshot,
}

fn authority_fixture(state: AuthorityState) -> AuthorityFixture {
    let binding = use_binding(None);
    let now = parsed_time("2026-07-24T12:00:00.000000Z");
    let (grant_not_before, grant_expires_at, cached_at, cache_expires_at) = match state {
        AuthorityState::Expired => (
            now - Duration::hours(2),
            now - Duration::seconds(1),
            now - Duration::hours(2),
            now - Duration::seconds(1),
        ),
        AuthorityState::Stale => (
            now - Duration::hours(2),
            now + Duration::hours(2),
            now - Duration::hours(1),
            now + Duration::hours(1),
        ),
        _ => (
            now - Duration::minutes(5),
            now + Duration::hours(2),
            now - Duration::seconds(1),
            now + Duration::hours(1),
        ),
    };
    let max_staleness = if matches!(state, AuthorityState::Stale) {
        Duration::minutes(1)
    } else {
        Duration::hours(1)
    };
    let policy = OfflineAuthorityPolicy::connected(max_staleness).unwrap();
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

    let grant = grant_from_local_secret_broker_scope(
        CompatibilityGrantContext {
            grant_id: CapabilityGrantId::from(uuid(50)),
            issuer: principal(51),
            subject: binding.principal_id().clone(),
            audience: binding.audience_id().to_string(),
            validation_digest: "blake3:authority-fixture".to_string(),
            max_delegation_depth: 0,
            parent_grant_ids: Vec::new(),
        },
        binding.tenant_id().clone(),
        binding.workload_id().clone(),
        binding.driver_operation().clone(),
        grant_not_before,
        grant_expires_at,
        RevocationStatus::Active,
        Some("revocation:secret-test".to_string()),
    )
    .unwrap();
    let grant_id = grant.grant().grant_id.clone();
    let mut cache = AuthorityGrantCache::new();
    cache.insert_cached(CachedAuthorityGrant::try_new(grant, cached_at, cache_expires_at).unwrap());
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
    let revocations = if matches!(state, AuthorityState::MissingSnapshot) {
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
    };
    AuthorityFixture {
        cache,
        revocations,
        policy,
    }
}

fn default_policy(max_uses: u64, renewable: bool) -> SecretLeasePolicy {
    SecretLeasePolicy::try_new(300, 600, max_uses, renewable, 0).unwrap()
}

fn assert_broker_error<T>(result: Result<T, SecretBrokerError>, expected: SecretBrokerError) {
    match result {
        Ok(_) => panic!("expected broker error {}", expected.code()),
        Err(actual) => assert_eq!(actual, expected),
    }
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

#[test]
fn issue_and_claim_return_exact_distinct_ids_and_never_call_provider() {
    let fixture = broker_fixture(default_policy(1, true));
    let authority = authority_fixture(AuthorityState::Active);
    let grant = fixture
        .broker
        .issue_lease(initial_request(100, 1), &authority.context())
        .unwrap();
    assert_eq!(grant.snapshot().uses_claimed(), 0);
    assert_eq!(
        grant.snapshot().secret_lease_id(),
        grant.handle().secret_lease_id()
    );
    assert_eq!(
        grant.snapshot().delivery_handle_id(),
        grant.handle().delivery_handle_id()
    );
    assert_ne!(
        grant.snapshot().secret_lease_id().to_string(),
        grant.snapshot().delivery_handle_id().to_string()
    );

    let claim = fixture
        .broker
        .claim_use(grant.handle(), &use_binding(None), &authority.context())
        .unwrap();
    assert_eq!(claim.secret_lease_id(), grant.snapshot().secret_lease_id());
    assert_eq!(
        claim.delivery_handle_id(),
        grant.snapshot().delivery_handle_id()
    );
    assert_ne!(
        claim.secret_use_claim_id().to_string(),
        claim.secret_use_attempt_id().to_string()
    );
    assert_eq!(claim.use_binding(), &use_binding(None));
    assert_eq!(format!("{claim:?}"), "SecretDeliveryClaim(<opaque>)");
    let snapshot = fixture
        .broker
        .inspect_lease(grant.snapshot().secret_lease_id())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.uses_claimed(), 1);
    assert_eq!(snapshot.status(), SecretLeaseStatus::Exhausted);
    assert_eq!(fixture.provider.calls(), 0);
    assert_broker_error(
        fixture
            .broker
            .claim_use(grant.handle(), &use_binding(None), &authority.context()),
        SecretBrokerError::MaxUsesExceeded,
    );
}

#[test]
fn generated_id_reuse_fails_closed_without_replacing_existing_state() {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let provider_port: Arc<dyn SecretProvider> = provider.clone();
    let events = Arc::new(InMemorySecretBrokerEventSink::new());
    let broker = ProcessLocalSecretBroker::with_sources(
        vec![secret_ref(
            provider.provider_id.clone(),
            default_policy(1, true),
        )],
        vec![provider_port],
        Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
        Arc::new(RepeatingIssueIds::default()),
        events,
    )
    .unwrap();
    let authority = authority_fixture(AuthorityState::Active);
    let original = broker
        .issue_lease(initial_request(110, 1), &authority.context())
        .unwrap();

    assert_broker_error(
        broker.issue_lease(initial_request(111, 1), &authority.context()),
        SecretBrokerError::StateUnavailable,
    );
    let replay = broker.replay().unwrap();
    assert_eq!(replay.leases.len(), 1);
    assert_eq!(
        replay.leases[0].secret_lease_id(),
        original.snapshot().secret_lease_id()
    );
    assert_eq!(replay.events.len(), 1);
    assert_eq!(provider.calls(), 0);
}

#[test]
fn broker_configuration_system_sources_and_fixed_errors_are_covered() {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let provider_port: Arc<dyn SecretProvider> = provider.clone();
    let configured_ref = secret_ref(provider.provider_id.clone(), default_policy(1, true));
    let clock: Arc<dyn SecretBrokerClock> =
        Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")));
    let ids: Arc<dyn SecretBrokerIdSource> = Arc::new(SequenceIds::default());
    let events: Arc<dyn SecretBrokerEventSink> = Arc::new(InMemorySecretBrokerEventSink::default());

    assert_eq!(
        ProcessLocalSecretBroker::with_sources(
            vec![configured_ref.clone()],
            vec![provider_port.clone(), provider_port.clone()],
            clock.clone(),
            ids.clone(),
            events.clone(),
        )
        .err()
        .unwrap(),
        SecretBrokerConfigError::DuplicateProvider
    );
    assert_eq!(
        ProcessLocalSecretBroker::with_sources(
            vec![configured_ref.clone(), configured_ref.clone()],
            vec![provider_port.clone()],
            clock.clone(),
            ids.clone(),
            events.clone(),
        )
        .err()
        .unwrap(),
        SecretBrokerConfigError::DuplicateSecretRef
    );
    assert_eq!(
        ProcessLocalSecretBroker::with_sources(
            vec![configured_ref.clone()],
            Vec::new(),
            clock,
            ids,
            events,
        )
        .err()
        .unwrap(),
        SecretBrokerConfigError::MissingProvider
    );

    let broker = ProcessLocalSecretBroker::try_new(
        vec![configured_ref],
        vec![provider_port],
        Arc::new(InMemorySecretBrokerEventSink::new()),
    )
    .unwrap();
    assert_eq!(broker.registered_provider_count(), 1);
    assert_eq!(broker.inspect_lease(&secret_id(99)).unwrap(), None);

    let system_now = SystemSecretBrokerClock.now_utc().unwrap();
    assert_eq!(system_now.nanosecond() % 1_000, 0);
    let system_ids = SystemSecretBrokerIdSource;
    for kind in [
        SecretBrokerIdKind::Lease,
        SecretBrokerIdKind::DeliveryHandle,
        SecretBrokerIdKind::HandleCapability,
        SecretBrokerIdKind::AccessEvent,
        SecretBrokerIdKind::UseClaim,
        SecretBrokerIdKind::UseAttempt,
        SecretBrokerIdKind::ClaimCapability,
    ] {
        assert!(!system_ids.next_uuid(kind).unwrap().is_nil());
    }

    for error in [
        SecretBrokerError::SecretNotAvailable,
        SecretBrokerError::AuthorityDenied,
        SecretBrokerError::ClockUnavailable,
        SecretBrokerError::ClockRollback,
        SecretBrokerError::EvidenceUnavailable,
        SecretBrokerError::LeaseNotStarted,
        SecretBrokerError::LeaseExpired,
        SecretBrokerError::MaxUsesExceeded,
        SecretBrokerError::RenewalDenied,
        SecretBrokerError::RequestAlreadyUsed,
        SecretBrokerError::StateUnavailable,
    ] {
        assert_eq!(error.to_string(), error.code());
    }
    for error in [
        SecretBrokerConfigError::DuplicateSecretRef,
        SecretBrokerConfigError::DuplicateProvider,
        SecretBrokerConfigError::MissingProvider,
    ] {
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        SecretBrokerEventSinkError::Unavailable.to_string(),
        "secret_broker_event_sink_unavailable"
    );
}

#[test]
fn unavailable_clock_ids_and_required_evidence_fail_closed_without_provider_calls() {
    let authority = authority_fixture(AuthorityState::Active);
    let available_clock = || {
        Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")))
            as Arc<dyn SecretBrokerClock>
    };
    let available_events =
        || Arc::new(InMemorySecretBrokerEventSink::new()) as Arc<dyn SecretBrokerEventSink>;

    let (broker, provider) = custom_broker(
        Arc::new(UnavailableClock),
        Arc::new(SequenceIds::default()),
        available_events(),
    );
    assert_broker_error(
        broker.issue_lease(initial_request(140, 1), &authority.context()),
        SecretBrokerError::ClockUnavailable,
    );
    assert_eq!(provider.calls(), 0);

    let unavailable_events = Arc::new(InMemorySecretBrokerEventSink::new());
    unavailable_events.set_available(false);
    let (broker, provider) = custom_broker(
        available_clock(),
        Arc::new(SequenceIds::default()),
        unavailable_events,
    );
    assert_broker_error(
        broker.issue_lease(initial_request(141, 1), &authority.context()),
        SecretBrokerError::EvidenceUnavailable,
    );
    assert!(broker.replay().unwrap().leases.is_empty());
    assert_eq!(provider.calls(), 0);

    for (index, kind, return_nil, expected) in [
        (
            0,
            SecretBrokerIdKind::Lease,
            false,
            SecretBrokerError::StateUnavailable,
        ),
        (
            1,
            SecretBrokerIdKind::DeliveryHandle,
            false,
            SecretBrokerError::StateUnavailable,
        ),
        (
            2,
            SecretBrokerIdKind::HandleCapability,
            true,
            SecretBrokerError::StateUnavailable,
        ),
        (
            3,
            SecretBrokerIdKind::AccessEvent,
            false,
            SecretBrokerError::EvidenceUnavailable,
        ),
    ] {
        let (broker, provider) = custom_broker(
            available_clock(),
            Arc::new(FailingIds::new(kind, 0, return_nil)),
            available_events(),
        );
        assert_broker_error(
            broker.issue_lease(initial_request(150 + index, 1), &authority.context()),
            expected,
        );
        assert!(broker.replay().unwrap().leases.is_empty());
        assert_eq!(provider.calls(), 0);
    }

    for (index, kind) in [
        SecretBrokerIdKind::UseClaim,
        SecretBrokerIdKind::UseAttempt,
        SecretBrokerIdKind::ClaimCapability,
    ]
    .into_iter()
    .enumerate()
    {
        let (broker, provider) = custom_broker(
            available_clock(),
            Arc::new(FailingIds::new(kind, 0, false)),
            available_events(),
        );
        let grant = broker
            .issue_lease(
                initial_request(160 + index as u128, 2),
                &authority.context(),
            )
            .unwrap();
        assert_broker_error(
            broker.claim_use(grant.handle(), &use_binding(None), &authority.context()),
            SecretBrokerError::StateUnavailable,
        );
        assert_eq!(
            broker
                .inspect_lease(grant.snapshot().secret_lease_id())
                .unwrap()
                .unwrap()
                .uses_claimed(),
            0
        );
        assert_eq!(provider.calls(), 0);
    }

    let (broker, provider) = custom_broker(
        available_clock(),
        Arc::new(FailingIds::new(SecretBrokerIdKind::AccessEvent, 1, false)),
        available_events(),
    );
    let grant = broker
        .issue_lease(initial_request(170, 2), &authority.context())
        .unwrap();
    assert_broker_error(
        broker.claim_use(grant.handle(), &use_binding(None), &authority.context()),
        SecretBrokerError::EvidenceUnavailable,
    );
    assert_eq!(
        broker
            .inspect_lease(grant.snapshot().secret_lease_id())
            .unwrap()
            .unwrap()
            .uses_claimed(),
        0
    );
    assert_eq!(provider.calls(), 0);
}

#[test]
fn every_exact_binding_coordinate_is_checked_without_mutating_use_count() {
    let fixture = broker_fixture(default_policy(2, true));
    let authority = authority_fixture(AuthorityState::Active);
    let grant = fixture
        .broker
        .issue_lease(initial_request(101, 2), &authority.context())
        .unwrap();
    for change in [
        BindingChange::Tenant,
        BindingChange::Principal,
        BindingChange::Workload,
        BindingChange::Operation,
        BindingChange::Slot,
        BindingChange::Node,
        BindingChange::Instance,
        BindingChange::Audience,
        BindingChange::Purpose,
        BindingChange::Ref,
        BindingChange::Version,
    ] {
        assert_broker_error(
            fixture.broker.claim_use(
                grant.handle(),
                &use_binding(Some(change)),
                &authority.context(),
            ),
            SecretBrokerError::SecretNotAvailable,
        );
    }
    let snapshot = fixture
        .broker
        .inspect_lease(grant.snapshot().secret_lease_id())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.uses_claimed(), 0);
    assert_eq!(snapshot.status(), SecretLeaseStatus::Active);
    assert_eq!(fixture.provider.calls(), 0);
}

#[test]
fn issuance_denies_wrong_ref_version_and_duplicate_request_id_uniformly() {
    let fixture = broker_fixture(default_policy(1, true));
    let authority = authority_fixture(AuthorityState::Active);
    for change in [
        BindingChange::Tenant,
        BindingChange::Ref,
        BindingChange::Version,
    ] {
        let request = lease_request(
            102,
            use_binding(Some(change)),
            "2026-07-24T12:00:00.000000Z",
            "2026-07-24T12:05:00.000000Z",
            "2026-07-24T12:00:00.000000Z",
            1,
        );
        assert_broker_error(
            fixture.broker.issue_lease(request, &authority.context()),
            SecretBrokerError::SecretNotAvailable,
        );
    }
    let request = initial_request(103, 1);
    fixture
        .broker
        .issue_lease(request.clone(), &authority.context())
        .unwrap();
    assert_broker_error(
        fixture.broker.issue_lease(request, &authority.context()),
        SecretBrokerError::RequestAlreadyUsed,
    );
}

#[test]
fn issuance_honors_exact_ref_creation_and_disable_boundaries() {
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let provider_port: Arc<dyn SecretProvider> = provider.clone();
    let clock = Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")));
    let authority = authority_fixture(AuthorityState::Active);

    for (created_at, disabled_at) in [
        ("2026-07-24T12:00:00.000001Z", None),
        (
            "2026-07-24T11:00:00.000000Z",
            Some("2026-07-24T12:00:00.000000Z"),
        ),
    ] {
        let broker = ProcessLocalSecretBroker::with_sources(
            vec![secret_ref_with_window(
                provider.provider_id.clone(),
                default_policy(1, true),
                created_at,
                disabled_at,
            )],
            vec![provider_port.clone()],
            clock.clone(),
            Arc::new(SequenceIds::default()),
            Arc::new(InMemorySecretBrokerEventSink::new()),
        )
        .unwrap();
        assert_broker_error(
            broker.issue_lease(initial_request(130, 1), &authority.context()),
            SecretBrokerError::SecretNotAvailable,
        );
    }

    let broker = ProcessLocalSecretBroker::with_sources(
        vec![secret_ref_with_window(
            provider.provider_id.clone(),
            default_policy(1, true),
            "2026-07-24T11:00:00.000000Z",
            Some("2026-07-24T12:00:00.000001Z"),
        )],
        vec![provider_port],
        clock,
        Arc::new(SequenceIds::default()),
        Arc::new(InMemorySecretBrokerEventSink::new()),
    )
    .unwrap();
    assert!(broker
        .issue_lease(initial_request(131, 1), &authority.context())
        .is_ok());
    assert_eq!(provider.calls(), 0);
}

#[test]
fn issuance_rejects_delivery_time_policy_and_continuous_lifetime_violations() {
    let authority = authority_fixture(AuthorityState::Active);

    let unsupported_delivery = broker_fixture(default_policy(2, true));
    assert_broker_error(
        unsupported_delivery.broker.issue_lease(
            lease_request_with_methods(
                180,
                use_binding(None),
                "2026-07-24T12:00:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                1,
                vec![SecretDeliveryMethod::TmpfsFile],
            ),
            &authority.context(),
        ),
        SecretBrokerError::SecretNotAvailable,
    );

    for (request_index, starts_at, expires_at, requested_at) in [
        (
            181,
            "2026-07-24T12:01:00.000000Z",
            "2026-07-24T12:05:00.000000Z",
            "2026-07-24T12:00:01.000000Z",
        ),
        (
            182,
            "2026-07-24T11:55:00.000000Z",
            "2026-07-24T12:00:00.000000Z",
            "2026-07-24T11:55:00.000000Z",
        ),
        (
            186,
            "2026-07-24T11:59:00.000000Z",
            "2026-07-24T12:04:00.000000Z",
            "2026-07-24T11:59:00.000000Z",
        ),
    ] {
        let fixture = broker_fixture(default_policy(2, true));
        assert_broker_error(
            fixture.broker.issue_lease(
                lease_request(
                    request_index,
                    use_binding(None),
                    starts_at,
                    expires_at,
                    requested_at,
                    1,
                ),
                &authority.context(),
            ),
            SecretBrokerError::SecretNotAvailable,
        );
    }

    let duration_limited = broker_fixture(SecretLeasePolicy::try_new(60, 600, 2, true, 0).unwrap());
    assert_broker_error(
        duration_limited
            .broker
            .issue_lease(initial_request(183, 1), &authority.context()),
        SecretBrokerError::SecretNotAvailable,
    );

    let use_limited = broker_fixture(default_policy(1, true));
    assert_broker_error(
        use_limited
            .broker
            .issue_lease(initial_request(184, 2), &authority.context()),
        SecretBrokerError::SecretNotAvailable,
    );

    let overflowing_lifetime =
        broker_fixture(SecretLeasePolicy::try_new(300, 9_007_199_254_740_991, 1, true, 0).unwrap());
    assert_broker_error(
        overflowing_lifetime
            .broker
            .issue_lease(initial_request(185, 1), &authority.context()),
        SecretBrokerError::SecretNotAvailable,
    );
}

#[test]
fn missing_expired_revoked_stale_or_snapshotless_authority_denies() {
    for (index, state) in [
        AuthorityState::Missing,
        AuthorityState::Expired,
        AuthorityState::Revoked,
        AuthorityState::Stale,
        AuthorityState::MissingSnapshot,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = broker_fixture(default_policy(1, true));
        let authority = authority_fixture(state);
        assert_broker_error(
            fixture.broker.issue_lease(
                initial_request(200 + index as u128, 1),
                &authority.context(),
            ),
            SecretBrokerError::AuthorityDenied,
        );
        assert!(fixture.broker.replay().unwrap().leases.is_empty());
        assert_eq!(fixture.provider.calls(), 0);
    }
}

#[test]
fn clock_rollback_and_exact_expiry_boundary_deny_without_use() {
    let fixture = broker_fixture(default_policy(1, true));
    let authority = authority_fixture(AuthorityState::Active);
    let grant = fixture
        .broker
        .issue_lease(initial_request(300, 1), &authority.context())
        .unwrap();
    fixture
        .clock
        .set(parsed_time("2026-07-24T12:00:00.000000001Z"));
    assert_broker_error(
        fixture
            .broker
            .claim_use(grant.handle(), &use_binding(None), &authority.context()),
        SecretBrokerError::ClockUnavailable,
    );
    fixture
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_broker_error(
        fixture
            .broker
            .claim_use(grant.handle(), &use_binding(None), &authority.context()),
        SecretBrokerError::ClockRollback,
    );
    assert_eq!(
        fixture
            .broker
            .inspect_lease(grant.snapshot().secret_lease_id())
            .unwrap()
            .unwrap()
            .uses_claimed(),
        0
    );

    let expiry_fixture = broker_fixture(default_policy(1, true));
    let expiry_grant = expiry_fixture
        .broker
        .issue_lease(initial_request(301, 1), &authority.context())
        .unwrap();
    expiry_fixture
        .clock
        .set(parsed_time("2026-07-24T12:05:00.000000Z"));
    assert_broker_error(
        expiry_fixture.broker.claim_use(
            expiry_grant.handle(),
            &use_binding(None),
            &authority.context(),
        ),
        SecretBrokerError::LeaseExpired,
    );
    let snapshot = expiry_fixture
        .broker
        .inspect_lease(expiry_grant.snapshot().secret_lease_id())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.status(), SecretLeaseStatus::Expired);
    assert_eq!(snapshot.uses_claimed(), 0);
}

#[test]
fn issue_renew_and_revoke_clock_rollback_emit_denials_and_fail_closed() {
    let authority = authority_fixture(AuthorityState::Active);

    let issue_fixture = broker_fixture(default_policy(2, true));
    issue_fixture
        .broker
        .issue_lease(initial_request(310, 2), &authority.context())
        .unwrap();
    issue_fixture
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_broker_error(
        issue_fixture
            .broker
            .issue_lease(initial_request(311, 2), &authority.context()),
        SecretBrokerError::ClockRollback,
    );

    let renew_fixture = broker_fixture(default_policy(2, true));
    let renewable = renew_fixture
        .broker
        .issue_lease(initial_request(312, 2), &authority.context())
        .unwrap();
    renew_fixture
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_broker_error(
        renew_fixture.broker.renew_lease(
            renewable.handle(),
            lease_request(
                313,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T11:59:59.000000Z",
                2,
            ),
            &authority.context(),
        ),
        SecretBrokerError::ClockRollback,
    );

    let revoke_fixture = broker_fixture(default_policy(2, true));
    let revocable = revoke_fixture
        .broker
        .issue_lease(initial_request(314, 2), &authority.context())
        .unwrap();
    revoke_fixture
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_broker_error(
        revoke_fixture.broker.revoke_lease(
            revocable.handle(),
            &use_binding(None),
            &authority.context(),
        ),
        SecretBrokerError::ClockRollback,
    );

    for events in [
        issue_fixture.events.events().unwrap(),
        renew_fixture.events.events().unwrap(),
        revoke_fixture.events.events().unwrap(),
    ] {
        assert_eq!(
            events.last().unwrap().denial_code(),
            Some(SecretAccessDenialCode::ClockRollback)
        );
    }
}

#[test]
fn claims_deny_before_start_and_when_current_authority_is_missing() {
    let active_authority = authority_fixture(AuthorityState::Active);
    let future_fixture = broker_fixture(default_policy(2, true));
    let future = future_fixture
        .broker
        .issue_lease(
            lease_request(
                320,
                use_binding(None),
                "2026-07-24T12:01:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                2,
            ),
            &active_authority.context(),
        )
        .unwrap();
    assert_broker_error(
        future_fixture.broker.claim_use(
            future.handle(),
            &use_binding(None),
            &active_authority.context(),
        ),
        SecretBrokerError::LeaseNotStarted,
    );

    let authority_fixture_broker = broker_fixture(default_policy(2, true));
    let grant = authority_fixture_broker
        .broker
        .issue_lease(initial_request(321, 2), &active_authority.context())
        .unwrap();
    let missing_authority = authority_fixture(AuthorityState::Missing);
    assert_broker_error(
        authority_fixture_broker.broker.claim_use(
            grant.handle(),
            &use_binding(None),
            &missing_authority.context(),
        ),
        SecretBrokerError::AuthorityDenied,
    );
    assert_eq!(
        authority_fixture_broker
            .broker
            .inspect_lease(grant.snapshot().secret_lease_id())
            .unwrap()
            .unwrap()
            .uses_claimed(),
        0
    );
}

#[test]
fn concurrent_final_use_has_one_winner() {
    let fixture = broker_fixture(default_policy(1, true));
    let authority = Arc::new(authority_fixture(AuthorityState::Active));
    let grant = fixture
        .broker
        .issue_lease(initial_request(400, 1), &authority.context())
        .unwrap();
    let handle = Arc::new(grant.into_parts().1);
    let barrier = Arc::new(Barrier::new(12));
    let mut threads = Vec::new();
    for _ in 0..12 {
        let broker = fixture.broker.clone();
        let handle = handle.clone();
        let barrier = barrier.clone();
        let authority = authority.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            broker.claim_use(&handle, &use_binding(None), &authority.context())
        }));
    }
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results
        .iter()
        .filter(|result| result.is_err())
        .all(|result| { matches!(result, Err(SecretBrokerError::MaxUsesExceeded)) }));
    assert_eq!(fixture.provider.calls(), 0);
}

#[test]
fn renewal_carries_use_and_lifetime_forward_and_invalidates_old_handle() {
    let fixture = broker_fixture(default_policy(2, true));
    let authority = authority_fixture(AuthorityState::Active);
    let original = fixture
        .broker
        .issue_lease(initial_request(500, 2), &authority.context())
        .unwrap();
    fixture
        .clock
        .set(parsed_time("2026-07-24T12:01:00.000000Z"));
    fixture
        .broker
        .claim_use(original.handle(), &use_binding(None), &authority.context())
        .unwrap();
    fixture
        .clock
        .set(parsed_time("2026-07-24T12:04:00.000000Z"));
    let renewed_request = lease_request(
        501,
        use_binding(None),
        "2026-07-24T12:05:00.000000Z",
        "2026-07-24T12:10:00.000000Z",
        "2026-07-24T12:04:00.000000Z",
        2,
    );
    let renewed = fixture
        .broker
        .renew_lease(original.handle(), renewed_request, &authority.context())
        .unwrap();
    assert_ne!(
        original.snapshot().secret_lease_id(),
        renewed.snapshot().secret_lease_id()
    );
    assert_ne!(
        original.snapshot().delivery_handle_id(),
        renewed.snapshot().delivery_handle_id()
    );
    assert_eq!(renewed.snapshot().uses_claimed(), 1);
    assert_eq!(
        renewed.snapshot().continuous_lifetime_started_at().as_str(),
        "2026-07-24T12:00:00.000000Z"
    );
    assert_broker_error(
        fixture
            .broker
            .claim_use(original.handle(), &use_binding(None), &authority.context()),
        SecretBrokerError::SecretNotAvailable,
    );
    fixture
        .clock
        .set(parsed_time("2026-07-24T12:05:00.000000Z"));
    fixture
        .broker
        .claim_use(renewed.handle(), &use_binding(None), &authority.context())
        .unwrap();
    assert_eq!(fixture.provider.calls(), 0);
}

#[test]
fn nonrenewable_and_continuous_lifetime_overflow_deny() {
    let authority = authority_fixture(AuthorityState::Active);
    let nonrenewable = broker_fixture(default_policy(2, false));
    let original = nonrenewable
        .broker
        .issue_lease(initial_request(510, 2), &authority.context())
        .unwrap();
    nonrenewable
        .clock
        .set(parsed_time("2026-07-24T12:04:00.000000Z"));
    assert_broker_error(
        nonrenewable.broker.renew_lease(
            original.handle(),
            lease_request(
                511,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T12:04:00.000000Z",
                2,
            ),
            &authority.context(),
        ),
        SecretBrokerError::RenewalDenied,
    );

    let capped = broker_fixture(SecretLeasePolicy::try_new(400, 600, 2, true, 0).unwrap());
    let capped_original = capped
        .broker
        .issue_lease(initial_request(512, 2), &authority.context())
        .unwrap();
    capped.clock.set(parsed_time("2026-07-24T12:04:00.000000Z"));
    assert_broker_error(
        capped.broker.renew_lease(
            capped_original.handle(),
            lease_request(
                513,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:01.000000Z",
                "2026-07-24T12:04:00.000000Z",
                2,
            ),
            &authority.context(),
        ),
        SecretBrokerError::RenewalDenied,
    );
}

#[test]
fn renewal_rejects_reused_requests_inactive_leases_delivery_changes_and_authority_loss() {
    let active_authority = authority_fixture(AuthorityState::Active);

    let reused = broker_fixture(default_policy(2, true));
    let reused_original = reused
        .broker
        .issue_lease(initial_request(520, 2), &active_authority.context())
        .unwrap();
    reused.clock.set(parsed_time("2026-07-24T12:04:00.000000Z"));
    assert_broker_error(
        reused.broker.renew_lease(
            reused_original.handle(),
            initial_request(520, 2),
            &active_authority.context(),
        ),
        SecretBrokerError::RequestAlreadyUsed,
    );

    let future = broker_fixture(default_policy(2, true));
    let future_original = future
        .broker
        .issue_lease(
            lease_request(
                521,
                use_binding(None),
                "2026-07-24T12:01:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                2,
            ),
            &active_authority.context(),
        )
        .unwrap();
    assert_broker_error(
        future.broker.renew_lease(
            future_original.handle(),
            lease_request(
                522,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                2,
            ),
            &active_authority.context(),
        ),
        SecretBrokerError::RenewalDenied,
    );

    let exhausted = broker_fixture(default_policy(1, true));
    let exhausted_original = exhausted
        .broker
        .issue_lease(initial_request(523, 1), &active_authority.context())
        .unwrap();
    exhausted
        .broker
        .claim_use(
            exhausted_original.handle(),
            &use_binding(None),
            &active_authority.context(),
        )
        .unwrap();
    assert_broker_error(
        exhausted.broker.renew_lease(
            exhausted_original.handle(),
            lease_request(
                524,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                1,
            ),
            &active_authority.context(),
        ),
        SecretBrokerError::RenewalDenied,
    );

    let changed_delivery = broker_fixture(default_policy(2, true));
    let changed_delivery_original = changed_delivery
        .broker
        .issue_lease(initial_request(525, 2), &active_authority.context())
        .unwrap();
    changed_delivery
        .clock
        .set(parsed_time("2026-07-24T12:04:00.000000Z"));
    assert_broker_error(
        changed_delivery.broker.renew_lease(
            changed_delivery_original.handle(),
            lease_request_with_methods(
                526,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T12:04:00.000000Z",
                2,
                vec![SecretDeliveryMethod::TmpfsFile],
            ),
            &active_authority.context(),
        ),
        SecretBrokerError::RenewalDenied,
    );

    let authority_loss = broker_fixture(default_policy(2, true));
    let authority_loss_original = authority_loss
        .broker
        .issue_lease(initial_request(527, 2), &active_authority.context())
        .unwrap();
    authority_loss
        .clock
        .set(parsed_time("2026-07-24T12:04:00.000000Z"));
    let missing_authority = authority_fixture(AuthorityState::Missing);
    assert_broker_error(
        authority_loss.broker.renew_lease(
            authority_loss_original.handle(),
            lease_request(
                528,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T12:04:00.000000Z",
                2,
            ),
            &missing_authority.context(),
        ),
        SecretBrokerError::AuthorityDenied,
    );
}

#[test]
fn renewal_rechecks_ref_disable_time_and_forged_handles_never_resolve() {
    let active_authority = authority_fixture(AuthorityState::Active);
    let provider = Arc::new(TrapProvider::new(secret_id(10)));
    let provider_port: Arc<dyn SecretProvider> = provider.clone();
    let clock = Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z")));
    let broker = ProcessLocalSecretBroker::with_sources(
        vec![secret_ref_with_window(
            provider.provider_id.clone(),
            default_policy(2, true),
            "2026-07-24T11:00:00.000000Z",
            Some("2026-07-24T12:03:00.000000Z"),
        )],
        vec![provider_port],
        clock.clone(),
        Arc::new(SequenceIds::default()),
        Arc::new(InMemorySecretBrokerEventSink::new()),
    )
    .unwrap();
    let original = broker
        .issue_lease(initial_request(529, 2), &active_authority.context())
        .unwrap();
    clock.set(parsed_time("2026-07-24T12:03:00.000000Z"));
    assert_broker_error(
        broker.renew_lease(
            original.handle(),
            lease_request(
                530,
                use_binding(None),
                "2026-07-24T12:04:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:03:00.000000Z",
                2,
            ),
            &active_authority.context(),
        ),
        SecretBrokerError::RenewalDenied,
    );

    let fixture = broker_fixture(default_policy(2, true));
    let grant = fixture
        .broker
        .issue_lease(initial_request(531, 2), &active_authority.context())
        .unwrap();
    let forged_nonce = SecretDeliveryHandle {
        delivery_handle_id: grant.handle().delivery_handle_id.clone(),
        secret_lease_id: grant.handle().secret_lease_id.clone(),
        capability_nonce: uuid(90_000),
    };
    assert_broker_error(
        fixture.broker.renew_lease(
            &forged_nonce,
            lease_request(
                532,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                2,
            ),
            &active_authority.context(),
        ),
        SecretBrokerError::SecretNotAvailable,
    );
    let events = fixture.events.events().unwrap();
    assert_eq!(
        events.last().unwrap().kind(),
        SecretAccessEvidenceKind::RenewalDenied
    );
    assert_eq!(
        events.last().unwrap().denial_code(),
        Some(SecretAccessDenialCode::SecretNotAvailable)
    );
    assert_broker_error(
        fixture.broker.revoke_lease(
            &forged_nonce,
            &use_binding(None),
            &active_authority.context(),
        ),
        SecretBrokerError::SecretNotAvailable,
    );
    let events = fixture.events.events().unwrap();
    assert_eq!(
        events.last().unwrap().kind(),
        SecretAccessEvidenceKind::RevocationDenied
    );
    assert_eq!(
        events.last().unwrap().denial_code(),
        Some(SecretAccessDenialCode::SecretNotAvailable)
    );

    let missing_handle = SecretDeliveryHandle {
        delivery_handle_id: secret_id(90_001),
        secret_lease_id: grant.handle().secret_lease_id.clone(),
        capability_nonce: uuid(90_002),
    };
    fixture
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_broker_error(
        fixture.broker.claim_use(
            &missing_handle,
            &use_binding(None),
            &active_authority.context(),
        ),
        SecretBrokerError::ClockRollback,
    );
    assert_broker_error(
        fixture.broker.claim_use(
            &forged_nonce,
            &use_binding(None),
            &active_authority.context(),
        ),
        SecretBrokerError::ClockRollback,
    );
    assert_eq!(provider.calls(), 0);
}

#[test]
fn event_failures_block_issue_claim_and_renew_but_cannot_undo_revocation() {
    let fixture = broker_fixture(default_policy(2, true));
    let authority = authority_fixture(AuthorityState::Active);
    fixture.events.set_available(false);
    assert_broker_error(
        fixture
            .broker
            .issue_lease(initial_request(600, 2), &authority.context()),
        SecretBrokerError::EvidenceUnavailable,
    );
    assert!(fixture.broker.replay().unwrap().leases.is_empty());

    fixture.events.set_available(true);
    let original = fixture
        .broker
        .issue_lease(initial_request(601, 2), &authority.context())
        .unwrap();
    fixture.events.set_available(false);
    assert_broker_error(
        fixture
            .broker
            .claim_use(original.handle(), &use_binding(None), &authority.context()),
        SecretBrokerError::EvidenceUnavailable,
    );
    assert_eq!(
        fixture
            .broker
            .inspect_lease(original.snapshot().secret_lease_id())
            .unwrap()
            .unwrap()
            .uses_claimed(),
        0
    );

    fixture
        .clock
        .set(parsed_time("2026-07-24T12:04:00.000000Z"));
    assert_broker_error(
        fixture.broker.renew_lease(
            original.handle(),
            lease_request(
                602,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T12:04:00.000000Z",
                2,
            ),
            &authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );
    assert_eq!(
        fixture
            .broker
            .inspect_lease(original.snapshot().secret_lease_id())
            .unwrap()
            .unwrap()
            .status(),
        SecretLeaseStatus::Active
    );

    assert_broker_error(
        fixture
            .broker
            .revoke_lease(original.handle(), &use_binding(None), &authority.context()),
        SecretBrokerError::EvidenceUnavailable,
    );
    assert_eq!(
        fixture
            .broker
            .inspect_lease(original.snapshot().secret_lease_id())
            .unwrap()
            .unwrap()
            .status(),
        SecretLeaseStatus::RevocationPending
    );
    fixture.events.set_available(true);
    let recovered = fixture
        .broker
        .revoke_lease(original.handle(), &use_binding(None), &authority.context())
        .unwrap();
    assert_eq!(recovered.status(), SecretLeaseStatus::Revoked);
    assert_eq!(
        fixture
            .broker
            .revoke_lease(original.handle(), &use_binding(None), &authority.context())
            .unwrap()
            .status(),
        SecretLeaseStatus::Revoked
    );
    assert!(fixture
        .events
        .events()
        .unwrap()
        .iter()
        .any(|event| event.kind() == SecretAccessEvidenceKind::LeaseRevoked));
    assert_broker_error(
        fixture
            .broker
            .claim_use(original.handle(), &use_binding(None), &authority.context()),
        SecretBrokerError::SecretNotAvailable,
    );
    assert_eq!(fixture.provider.calls(), 0);
}

#[test]
fn denial_evidence_and_generated_id_failures_never_fall_back_to_allow() {
    let active_authority = authority_fixture(AuthorityState::Active);
    let missing_authority = authority_fixture(AuthorityState::Missing);

    let invalid_issue = broker_fixture(default_policy(2, true));
    invalid_issue.events.set_available(false);
    assert_broker_error(
        invalid_issue.broker.issue_lease(
            lease_request(
                620,
                use_binding(Some(BindingChange::Version)),
                "2026-07-24T12:00:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                2,
            ),
            &active_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );

    let issue_rollback = broker_fixture(default_policy(2, true));
    issue_rollback
        .broker
        .issue_lease(initial_request(621, 2), &active_authority.context())
        .unwrap();
    issue_rollback.events.set_available(false);
    issue_rollback
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_broker_error(
        issue_rollback
            .broker
            .issue_lease(initial_request(622, 2), &active_authority.context()),
        SecretBrokerError::EvidenceUnavailable,
    );

    let binding_denial = broker_fixture(default_policy(2, true));
    let binding_grant = binding_denial
        .broker
        .issue_lease(initial_request(623, 2), &active_authority.context())
        .unwrap();
    binding_denial.events.set_available(false);
    assert_broker_error(
        binding_denial.broker.claim_use(
            binding_grant.handle(),
            &use_binding(Some(BindingChange::Workload)),
            &active_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );

    let not_started = broker_fixture(default_policy(2, true));
    let not_started_grant = not_started
        .broker
        .issue_lease(
            lease_request(
                624,
                use_binding(None),
                "2026-07-24T12:01:00.000000Z",
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                2,
            ),
            &active_authority.context(),
        )
        .unwrap();
    not_started.events.set_available(false);
    assert_broker_error(
        not_started.broker.claim_use(
            not_started_grant.handle(),
            &use_binding(None),
            &active_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );

    let expired = broker_fixture(default_policy(2, true));
    let expired_grant = expired
        .broker
        .issue_lease(initial_request(625, 2), &active_authority.context())
        .unwrap();
    expired
        .clock
        .set(parsed_time("2026-07-24T12:05:00.000000Z"));
    expired.events.set_available(false);
    assert_broker_error(
        expired.broker.claim_use(
            expired_grant.handle(),
            &use_binding(None),
            &active_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );

    let authority_denial = broker_fixture(default_policy(2, true));
    let authority_grant = authority_denial
        .broker
        .issue_lease(initial_request(626, 2), &active_authority.context())
        .unwrap();
    authority_denial.events.set_available(false);
    assert_broker_error(
        authority_denial.broker.claim_use(
            authority_grant.handle(),
            &use_binding(None),
            &missing_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );

    let claim_rollback = broker_fixture(default_policy(2, true));
    let claim_rollback_grant = claim_rollback
        .broker
        .issue_lease(initial_request(627, 2), &active_authority.context())
        .unwrap();
    claim_rollback.events.set_available(false);
    claim_rollback
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_broker_error(
        claim_rollback.broker.claim_use(
            claim_rollback_grant.handle(),
            &use_binding(None),
            &active_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );

    let renewal_denial = broker_fixture(default_policy(2, false));
    let renewal_denial_grant = renewal_denial
        .broker
        .issue_lease(initial_request(628, 2), &active_authority.context())
        .unwrap();
    renewal_denial
        .clock
        .set(parsed_time("2026-07-24T12:04:00.000000Z"));
    renewal_denial.events.set_available(false);
    assert_broker_error(
        renewal_denial.broker.renew_lease(
            renewal_denial_grant.handle(),
            lease_request(
                629,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T12:04:00.000000Z",
                2,
            ),
            &active_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );

    let renewal_rollback = broker_fixture(default_policy(2, true));
    let renewal_rollback_grant = renewal_rollback
        .broker
        .issue_lease(initial_request(630, 2), &active_authority.context())
        .unwrap();
    renewal_rollback.events.set_available(false);
    renewal_rollback
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_broker_error(
        renewal_rollback.broker.renew_lease(
            renewal_rollback_grant.handle(),
            lease_request(
                631,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T11:59:59.000000Z",
                2,
            ),
            &active_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );

    let forged_handle_denials = broker_fixture(default_policy(2, true));
    let forged_handle_grant = forged_handle_denials
        .broker
        .issue_lease(initial_request(637, 2), &active_authority.context())
        .unwrap();
    let forged_handle = SecretDeliveryHandle {
        delivery_handle_id: forged_handle_grant.handle().delivery_handle_id.clone(),
        secret_lease_id: forged_handle_grant.handle().secret_lease_id.clone(),
        capability_nonce: uuid(90_003),
    };
    forged_handle_denials.events.set_available(false);
    assert_broker_error(
        forged_handle_denials.broker.renew_lease(
            &forged_handle,
            lease_request(
                638,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T12:00:00.000000Z",
                2,
            ),
            &active_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );
    assert_broker_error(
        forged_handle_denials.broker.revoke_lease(
            &forged_handle,
            &use_binding(None),
            &active_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );

    let inactive_handle_denial = broker_fixture(default_policy(2, true));
    let inactive_original = inactive_handle_denial
        .broker
        .issue_lease(initial_request(639, 2), &active_authority.context())
        .unwrap();
    inactive_handle_denial
        .clock
        .set(parsed_time("2026-07-24T12:04:00.000000Z"));
    inactive_handle_denial
        .broker
        .renew_lease(
            inactive_original.handle(),
            lease_request(
                640,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T12:04:00.000000Z",
                2,
            ),
            &active_authority.context(),
        )
        .unwrap();
    inactive_handle_denial.events.set_available(false);
    assert_broker_error(
        inactive_handle_denial.broker.revoke_lease(
            inactive_original.handle(),
            &use_binding(None),
            &active_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );

    for (request_index, wrong_binding, authority) in [
        (632, true, &active_authority),
        (633, false, &missing_authority),
    ] {
        let fixture = broker_fixture(default_policy(2, true));
        let grant = fixture
            .broker
            .issue_lease(
                initial_request(request_index, 2),
                &active_authority.context(),
            )
            .unwrap();
        fixture.events.set_available(false);
        let binding = use_binding(wrong_binding.then_some(BindingChange::Principal));
        assert_broker_error(
            fixture
                .broker
                .revoke_lease(grant.handle(), &binding, &authority.context()),
            SecretBrokerError::EvidenceUnavailable,
        );
    }

    let revoke_rollback = broker_fixture(default_policy(2, true));
    let revoke_rollback_grant = revoke_rollback
        .broker
        .issue_lease(initial_request(634, 2), &active_authority.context())
        .unwrap();
    revoke_rollback.events.set_available(false);
    revoke_rollback
        .clock
        .set(parsed_time("2026-07-24T11:59:59.000000Z"));
    assert_broker_error(
        revoke_rollback.broker.revoke_lease(
            revoke_rollback_grant.handle(),
            &use_binding(None),
            &active_authority.context(),
        ),
        SecretBrokerError::EvidenceUnavailable,
    );

    for operation in ["claim", "renew"] {
        let (broker, provider) = custom_broker(
            Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
            Arc::new(RepeatingIssueIds::default()),
            Arc::new(InMemorySecretBrokerEventSink::new()),
        );
        let grant = broker
            .issue_lease(initial_request(635, 2), &active_authority.context())
            .unwrap();
        let result = if operation == "claim" {
            broker
                .claim_use(
                    grant.handle(),
                    &use_binding(None),
                    &active_authority.context(),
                )
                .map(|_| ())
        } else {
            broker
                .renew_lease(
                    grant.handle(),
                    lease_request(
                        636,
                        use_binding(None),
                        "2026-07-24T12:05:00.000000Z",
                        "2026-07-24T12:10:00.000000Z",
                        "2026-07-24T12:00:00.000000Z",
                        2,
                    ),
                    &active_authority.context(),
                )
                .map(|_| ())
        };
        assert_broker_error(result, SecretBrokerError::StateUnavailable);
        assert_eq!(provider.calls(), 0);
    }
}

#[test]
fn revocation_checks_binding_authority_inactive_handles_and_id_failures() {
    let active_authority = authority_fixture(AuthorityState::Active);
    let fixture = broker_fixture(default_policy(2, true));
    let grant = fixture
        .broker
        .issue_lease(initial_request(610, 2), &active_authority.context())
        .unwrap();
    assert_broker_error(
        fixture.broker.revoke_lease(
            grant.handle(),
            &use_binding(Some(BindingChange::Audience)),
            &active_authority.context(),
        ),
        SecretBrokerError::SecretNotAvailable,
    );
    let missing_authority = authority_fixture(AuthorityState::Missing);
    assert_broker_error(
        fixture.broker.revoke_lease(
            grant.handle(),
            &use_binding(None),
            &missing_authority.context(),
        ),
        SecretBrokerError::AuthorityDenied,
    );

    let superseded = broker_fixture(default_policy(2, true));
    let original = superseded
        .broker
        .issue_lease(initial_request(611, 2), &active_authority.context())
        .unwrap();
    superseded
        .clock
        .set(parsed_time("2026-07-24T12:04:00.000000Z"));
    superseded
        .broker
        .renew_lease(
            original.handle(),
            lease_request(
                612,
                use_binding(None),
                "2026-07-24T12:05:00.000000Z",
                "2026-07-24T12:10:00.000000Z",
                "2026-07-24T12:04:00.000000Z",
                2,
            ),
            &active_authority.context(),
        )
        .unwrap();
    assert_broker_error(
        superseded.broker.revoke_lease(
            original.handle(),
            &use_binding(None),
            &active_authority.context(),
        ),
        SecretBrokerError::SecretNotAvailable,
    );
    let events = superseded.events.events().unwrap();
    assert_eq!(
        events.last().unwrap().kind(),
        SecretAccessEvidenceKind::RevocationDenied
    );
    assert_eq!(
        events.last().unwrap().denial_code(),
        Some(SecretAccessDenialCode::SecretNotAvailable)
    );

    for (ids, request_index) in [
        (
            Arc::new(FailingIds::new(SecretBrokerIdKind::AccessEvent, 1, false))
                as Arc<dyn SecretBrokerIdSource>,
            613,
        ),
        (
            Arc::new(RepeatingIssueIds::default()) as Arc<dyn SecretBrokerIdSource>,
            614,
        ),
    ] {
        let (broker, provider) = custom_broker(
            Arc::new(ManualClock::new(parsed_time("2026-07-24T12:00:00.000000Z"))),
            ids,
            Arc::new(InMemorySecretBrokerEventSink::new()),
        );
        let grant = broker
            .issue_lease(
                initial_request(request_index, 2),
                &active_authority.context(),
            )
            .unwrap();
        assert_broker_error(
            broker.revoke_lease(
                grant.handle(),
                &use_binding(None),
                &active_authority.context(),
            ),
            SecretBrokerError::EvidenceUnavailable,
        );
        assert_eq!(
            broker
                .inspect_lease(grant.snapshot().secret_lease_id())
                .unwrap()
                .unwrap()
                .status(),
            SecretLeaseStatus::RevocationPending
        );
        assert_eq!(provider.calls(), 0);
    }
}

#[test]
fn claim_and_revocation_race_has_a_single_lock_order_and_revocation_wins_future_use() {
    let fixture = broker_fixture(default_policy(2, true));
    let authority = Arc::new(authority_fixture(AuthorityState::Active));
    let grant = fixture
        .broker
        .issue_lease(initial_request(700, 2), &authority.context())
        .unwrap();
    let handle = Arc::new(grant.into_parts().1);
    let barrier = Arc::new(Barrier::new(2));
    let claim_thread = {
        let broker = fixture.broker.clone();
        let authority = authority.clone();
        let handle = handle.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            broker.claim_use(&handle, &use_binding(None), &authority.context())
        })
    };
    let revoke_thread = {
        let broker = fixture.broker.clone();
        let authority = authority.clone();
        let handle = handle.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            broker.revoke_lease(&handle, &use_binding(None), &authority.context())
        })
    };
    let claim_result = claim_thread.join().unwrap();
    let revoke_result = revoke_thread.join().unwrap();
    assert!(revoke_result.is_ok());
    assert!(
        claim_result.is_ok() || matches!(claim_result, Err(SecretBrokerError::SecretNotAvailable))
    );
    assert_broker_error(
        fixture
            .broker
            .claim_use(&handle, &use_binding(None), &authority.context()),
        SecretBrokerError::SecretNotAvailable,
    );
    assert_eq!(fixture.provider.calls(), 0);
}

#[test]
fn replay_and_inspection_are_strictly_read_only_and_canary_safe() {
    const CANARY: &str = "PRIVATE_SECRET_CANARY_7c1e";
    let fixture = broker_fixture(default_policy(1, true));
    let authority = authority_fixture(AuthorityState::Active);
    let grant = fixture
        .broker
        .issue_lease(initial_request(800, 1), &authority.context())
        .unwrap();
    fixture
        .broker
        .claim_use(grant.handle(), &use_binding(None), &authority.context())
        .unwrap();
    let ids_before = fixture.ids.count();
    let clock_before = fixture.clock.reads();
    let provider_before = fixture.provider.calls();
    let first = fixture.broker.replay().unwrap();
    let second = fixture.broker.replay().unwrap();
    let inspected = fixture
        .broker
        .inspect_lease(grant.snapshot().secret_lease_id())
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.leases.first(), inspected.as_ref());
    assert_eq!(fixture.ids.count(), ids_before);
    assert_eq!(fixture.clock.reads(), clock_before);
    assert_eq!(fixture.provider.calls(), provider_before);
    let encoded = serde_json::to_string(&first).unwrap();
    assert!(!encoded.contains(CANARY));
    assert!(!encoded.contains("password"));
    assert!(!encoded.contains("provider_response"));
    assert!(!encoded.contains("secret_material"));
    assert!(!format!("{:?}", grant.handle()).contains(CANARY));
}

#[test]
fn provider_port_and_material_have_redacted_fixed_failure_surfaces() {
    const CANARY: &str = "PRIVATE_SECRET_CANARY_7c1e";
    let provider = TrapProvider::new(secret_id(900));
    let request = SecretProviderFetchRequest {
        provider_audit_id: secret_id(901),
        secret_provider_id: provider.provider_id.clone(),
        tenant_id: tenant(2),
        secret_ref_id: secret_id(8),
        secret_ref_revision: 1,
        provider_version_ref: "version-1".parse().unwrap(),
        secret_lease_id: secret_id(902),
        delivery_handle_id: secret_id(903),
        secret_use_claim_id: secret_id(904),
        secret_use_attempt_id: secret_id(905),
        requested_at: canonical("2026-07-24T12:00:00.000000Z"),
    };
    let error = provider.fetch(&request).unwrap_err();
    assert_eq!(error.code(), SecretProviderErrorCode::Unavailable);
    assert_eq!(error.to_string(), "unavailable");
    assert_eq!(format!("{error:?}"), "unavailable");
    assert!(!error.to_string().contains(CANARY));
    assert_eq!(
        format!("{request:?}"),
        "SecretProviderFetchRequest(<redacted>)"
    );
    assert_eq!(
        request.provider_audit_id().to_string(),
        secret_id::<SecretProviderAuditId>(901).to_string()
    );
    assert_eq!(request.secret_provider_id(), &provider.provider_id);
    assert_eq!(request.tenant_id(), &tenant(2));
    assert_eq!(request.secret_ref_id(), &secret_id(8));
    assert_eq!(request.secret_ref_revision(), 1);
    assert_eq!(request.provider_version_ref().as_str(), "version-1");
    assert_eq!(request.secret_lease_id(), &secret_id(902));
    assert_eq!(request.delivery_handle_id(), &secret_id(903));
    assert_eq!(request.secret_use_claim_id(), &secret_id(904));
    assert_eq!(request.secret_use_attempt_id(), &secret_id(905));
    assert_eq!(
        request.requested_at().as_str(),
        "2026-07-24T12:00:00.000000Z"
    );

    let control = SecretProviderControlRequest {
        provider_audit_id: secret_id(906),
        secret_provider_id: provider.provider_id.clone(),
        tenant_id: tenant(2),
        secret_ref_id: secret_id(8),
        secret_ref_revision: 1,
        provider_version_ref: "version-1".parse().unwrap(),
        secret_lease_id: Some(secret_id(902)),
        requested_at: canonical("2026-07-24T12:00:00.000000Z"),
    };
    assert_eq!(
        control.provider_audit_id().to_string(),
        secret_id::<SecretProviderAuditId>(906).to_string()
    );
    assert_eq!(control.secret_provider_id(), &provider.provider_id);
    assert_eq!(control.tenant_id(), &tenant(2));
    assert_eq!(control.secret_ref_id(), &secret_id(8));
    assert_eq!(control.secret_ref_revision(), 1);
    assert_eq!(control.provider_version_ref().as_str(), "version-1");
    assert_eq!(control.secret_lease_id(), Some(&secret_id(902)));
    assert_eq!(
        control.requested_at().as_str(),
        "2026-07-24T12:00:00.000000Z"
    );
    assert_eq!(
        format!("{control:?}"),
        "SecretProviderControlRequest(<redacted>)"
    );
    assert_eq!(
        provider.renew(&control).unwrap_err().code(),
        SecretProviderErrorCode::Unavailable
    );
    assert_eq!(
        provider.revoke(&control).unwrap_err().code(),
        SecretProviderErrorCode::Unavailable
    );
    assert_eq!(
        provider.audit(&control).unwrap_err().code(),
        SecretProviderErrorCode::Unavailable
    );
    assert_eq!(
        provider.health(&control).unwrap_err().code(),
        SecretProviderErrorCode::Unavailable
    );

    let material = SecretMaterial::try_new(CANARY.as_bytes().to_vec()).unwrap();
    assert_eq!(material.len(), CANARY.len());
    assert_eq!(format!("{material:?}"), "SecretMaterial(<redacted>)");
    assert!(!format!("{material:?}").contains(CANARY));
    material.expose_borrowed(|bytes| assert_eq!(bytes, CANARY.as_bytes()));
    assert!(!material.is_empty());
    assert_eq!(
        SecretMaterial::try_new(Vec::new()).unwrap_err().code(),
        SecretProviderErrorCode::IntegrityFailure
    );
    assert_eq!(
        SecretMaterial::try_new(vec![0; MAX_SECRET_MATERIAL_BYTES + 1])
            .unwrap_err()
            .code(),
        SecretProviderErrorCode::IntegrityFailure
    );

    let invalid_audit = SecretProviderAuditEvidence::try_new(
        secret_id(906),
        provider.provider_id.clone(),
        TenantId::from(Uuid::nil()),
        secret_id(8),
        1,
        "version-1".parse().unwrap(),
        SecretProviderOperation::Fetch,
        SecretProviderOutcome::Succeeded,
        EffectCertainty::Known,
        canonical("2026-07-24T12:00:00.000000Z"),
    )
    .unwrap_err();
    assert_eq!(
        invalid_audit.code(),
        SecretProviderErrorCode::IntegrityFailure
    );
    assert_eq!(
        SecretProviderAuditEvidence::try_new(
            secret_id(906),
            provider.provider_id.clone(),
            tenant(2),
            secret_id(8),
            1,
            "version-1".parse().unwrap(),
            SecretProviderOperation::Fetch,
            SecretProviderOutcome::EffectUncertain,
            EffectCertainty::Known,
            canonical("2026-07-24T12:00:00.000000Z"),
        )
        .unwrap_err()
        .code(),
        SecretProviderErrorCode::IntegrityFailure
    );

    let wrong_operation_audit = SecretProviderAuditEvidence::try_new(
        secret_id(907),
        provider.provider_id.clone(),
        tenant(2),
        secret_id(8),
        1,
        "version-1".parse().unwrap(),
        SecretProviderOperation::Audit,
        SecretProviderOutcome::Succeeded,
        EffectCertainty::Known,
        canonical("2026-07-24T12:00:00.000000Z"),
    )
    .unwrap();
    assert_eq!(
        SecretProviderFetchResult::try_new(
            SecretMaterial::try_new(CANARY.as_bytes().to_vec()).unwrap(),
            wrong_operation_audit,
        )
        .unwrap_err()
        .code(),
        SecretProviderErrorCode::IntegrityFailure
    );

    let audit = SecretProviderAuditEvidence::try_new(
        secret_id(908),
        provider.provider_id.clone(),
        tenant(2),
        secret_id(8),
        1,
        "version-1".parse().unwrap(),
        SecretProviderOperation::Fetch,
        SecretProviderOutcome::Succeeded,
        EffectCertainty::Known,
        canonical("2026-07-24T12:00:00.000000Z"),
    )
    .unwrap();
    assert_eq!(
        audit.schema_version(),
        SECRET_PROVIDER_AUDIT_EVIDENCE_SCHEMA_LOCAL_V1
    );
    assert_eq!(
        audit.provider_audit_id().to_string(),
        secret_id::<SecretProviderAuditId>(908).to_string()
    );
    assert_eq!(audit.secret_provider_id(), &provider.provider_id);
    assert_eq!(audit.tenant_id(), &tenant(2));
    assert_eq!(audit.secret_ref_id(), &secret_id(8));
    assert_eq!(audit.secret_ref_revision(), 1);
    assert_eq!(audit.provider_version_ref().as_str(), "version-1");
    assert_eq!(audit.operation(), SecretProviderOperation::Fetch);
    assert_eq!(audit.outcome(), SecretProviderOutcome::Succeeded);
    assert_eq!(audit.effect_certainty(), EffectCertainty::Known);
    assert_eq!(audit.observed_at().as_str(), "2026-07-24T12:00:00.000000Z");
    let encoded_audit = serde_json::to_string(&audit).unwrap();
    assert!(encoded_audit.contains(SECRET_PROVIDER_AUDIT_EVIDENCE_SCHEMA_LOCAL_V1));
    let fetch_result = SecretProviderFetchResult::try_new(
        SecretMaterial::try_new(CANARY.as_bytes().to_vec()).unwrap(),
        audit,
    )
    .unwrap();
    assert_eq!(
        format!("{fetch_result:?}"),
        "SecretProviderFetchResult(<redacted>)"
    );
    let (returned_material, returned_audit) = fetch_result.into_parts();
    assert_eq!(returned_material.len(), CANARY.len());
    assert_eq!(
        returned_audit.provider_audit_id().to_string(),
        secret_id::<SecretProviderAuditId>(908).to_string()
    );

    let health = SecretProviderHealthEvidence::new(
        provider.provider_id.clone(),
        true,
        canonical("2026-07-24T12:00:00.000000Z"),
    );
    let encoded_health = serde_json::to_string(&health).unwrap();
    assert_eq!(
        health.schema_version(),
        SECRET_PROVIDER_HEALTH_EVIDENCE_SCHEMA_LOCAL_V1
    );
    assert_eq!(health.secret_provider_id(), &provider.provider_id);
    assert!(health.available());
    assert_eq!(health.observed_at().as_str(), "2026-07-24T12:00:00.000000Z");
    assert!(encoded_health.contains(SECRET_PROVIDER_HEALTH_EVIDENCE_SCHEMA_LOCAL_V1));
    assert!(!encoded_health.contains(CANARY));

    for code in [
        SecretProviderErrorCode::Unavailable,
        SecretProviderErrorCode::TimeoutBeforeSend,
        SecretProviderErrorCode::RateLimited,
        SecretProviderErrorCode::VersionNotAvailable,
        SecretProviderErrorCode::Revoked,
        SecretProviderErrorCode::IntegrityFailure,
        SecretProviderErrorCode::UnsupportedProviderVersion,
        SecretProviderErrorCode::UnsupportedOperation,
        SecretProviderErrorCode::EffectUncertain,
        SecretProviderErrorCode::InternalFailure,
    ] {
        let error = SecretProviderError::new(code);
        assert_eq!(error.to_string(), code.as_str());
        assert_eq!(format!("{error:?}"), code.as_str());
    }
    for operation in [
        SecretProviderOperation::Fetch,
        SecretProviderOperation::Renew,
        SecretProviderOperation::Revoke,
        SecretProviderOperation::Audit,
        SecretProviderOperation::ActiveProbe,
    ] {
        assert!(!serde_json::to_string(&operation).unwrap().is_empty());
    }
    for outcome in [
        SecretProviderOutcome::Succeeded,
        SecretProviderOutcome::Denied,
        SecretProviderOutcome::Unavailable,
        SecretProviderOutcome::Failed,
        SecretProviderOutcome::EffectUncertain,
    ] {
        assert!(!serde_json::to_string(&outcome).unwrap().is_empty());
    }
}

#[test]
fn disconnected_driver_authority_denies_even_with_cached_scope() {
    let binding = use_binding(None);
    let now = parsed_time("2026-07-24T12:00:00.000000Z");
    let grant = grant_from_local_secret_broker_scope(
        CompatibilityGrantContext {
            grant_id: CapabilityGrantId::from(uuid(950)),
            issuer: principal(951),
            subject: binding.principal_id().clone(),
            audience: binding.audience_id().to_string(),
            validation_digest: "blake3:offline".to_string(),
            max_delegation_depth: 0,
            parent_grant_ids: Vec::new(),
        },
        binding.tenant_id().clone(),
        binding.workload_id().clone(),
        binding.driver_operation().clone(),
        now - Duration::minutes(1),
        now + Duration::hours(1),
        RevocationStatus::Active,
        None,
    )
    .unwrap();
    let mut cache = AuthorityGrantCache::new();
    cache
        .insert_validated(
            grant,
            now - Duration::seconds(1),
            now + Duration::minutes(30),
        )
        .unwrap();
    let snapshot = RevocationSnapshot::try_new(
        Vec::new(),
        now - Duration::seconds(1),
        now + Duration::minutes(30),
    )
    .unwrap();
    let policy = OfflineAuthorityPolicy::disconnected(
        Duration::minutes(5),
        Duration::minutes(5),
        Vec::new(),
        AuthorityOfflineHighRiskBehavior::Deny,
    )
    .unwrap();
    assert_eq!(policy.connectivity(), AuthorityConnectivity::Disconnected);
    let authority = SecretBrokerAuthorityContext::new(&cache, Some(&snapshot), &policy);
    let fixture = broker_fixture(default_policy(1, true));
    assert_broker_error(
        fixture
            .broker
            .issue_lease(initial_request(951, 1), &authority),
        SecretBrokerError::AuthorityDenied,
    );
}
