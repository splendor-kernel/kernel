use super::*;
use crate::capability::unchecked_validated_grant_for_tests;
use splendor_types::{
    AgentId, AuthorityBudgetScope, AuthorityRevocationId, CapabilityGrant,
    CapabilityGrantValidation, CapabilityGrantValidationKind, CapabilityScope, DataPurpose,
    DeviceId, PrincipalId, RevocationStatus, RunId, TenantId, AUTHORITY_OPERATION_SCHEMA_VERSION,
    CAPABILITY_GRANT_SCHEMA_VERSION, CAPABILITY_REQUEST_SCHEMA_VERSION,
    REVOCATION_RECORD_SCHEMA_VERSION,
};
use time::{Duration, OffsetDateTime};

const AUDIENCE: &str = "daemon:local";
const DIGEST: &str = "blake3:7777777777777777777777777777777777777777777777777777777777777777";

#[derive(Clone)]
struct Fixture {
    now: OffsetDateTime,
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
    device_id: DeviceId,
    subject: PrincipalId,
}

impl Fixture {
    fn new() -> Self {
        Self {
            now: OffsetDateTime::now_utc(),
            tenant_id: TenantId::new(),
            agent_id: AgentId::new(),
            run_id: RunId::new(),
            device_id: DeviceId::new(),
            subject: PrincipalId::new(),
        }
    }
}

fn validation() -> CapabilityGrantValidation {
    CapabilityGrantValidation {
        validation_kind: CapabilityGrantValidationKind::LocallyValidated,
        algorithm: "local-revocation-test-v1".to_string(),
        key_id: None,
        digest: DIGEST.to_string(),
        signature: None,
    }
}

fn data_read_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Data,
        resource_kind: AuthorityResourceKind::Data,
        verb: AuthorityVerb::Read,
        name: None,
        resource_schema_version: Some("splendor.data_use.v1".to_string()),
    }
}

fn agent_delegate_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Agent,
        resource_kind: AuthorityResourceKind::Agent,
        verb: AuthorityVerb::Delegate,
        name: None,
        resource_schema_version: Some("splendor.agent.v1".to_string()),
    }
}

fn device_read_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Device,
        resource_kind: AuthorityResourceKind::Device,
        verb: AuthorityVerb::Read,
        name: None,
        resource_schema_version: Some("splendor.device_action.v1".to_string()),
    }
}

fn device_actuate_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Device,
        resource_kind: AuthorityResourceKind::Device,
        verb: AuthorityVerb::Actuate,
        name: None,
        resource_schema_version: Some("splendor.device_action.v1".to_string()),
    }
}

fn change_activate_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Change,
        resource_kind: AuthorityResourceKind::Change,
        verb: AuthorityVerb::Activate,
        name: None,
        resource_schema_version: Some("splendor.change.v1".to_string()),
    }
}

fn base_scope(fixture: &Fixture) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![fixture.tenant_id.clone()]),
        agent_ids: Some(vec![fixture.agent_id.clone()]),
        run_ids: Some(vec![fixture.run_id.clone()]),
        audiences: Some(vec![AUDIENCE.to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(5),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn data_scope(fixture: &Fixture) -> CapabilityScope {
    CapabilityScope {
        data_purposes: Some(vec![DataPurpose::Read]),
        ..base_scope(fixture)
    }
}

fn device_scope(fixture: &Fixture) -> CapabilityScope {
    CapabilityScope {
        device_ids: Some(vec![fixture.device_id.clone()]),
        ..base_scope(fixture)
    }
}

fn grant_for(
    fixture: &Fixture,
    operation: AuthorityOperation,
    scope: CapabilityScope,
) -> ValidatedCapabilityGrant {
    unchecked_validated_grant_for_tests(CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: CapabilityGrantId::new(),
        issuer: PrincipalId::new(),
        subject: fixture.subject.clone(),
        parent_grant_ids: Vec::new(),
        operations: vec![operation],
        scope,
        not_before: fixture.now - Duration::minutes(1),
        expires_at: fixture.now + Duration::hours(1),
        revocation_ref: Some("revocation:local-authority-cache".to_string()),
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth: 0,
        validation: Some(validation()),
        metadata: Default::default(),
    })
}

fn request_for(
    fixture: &Fixture,
    operation: AuthorityOperation,
    mut scope: CapabilityScope,
) -> CapabilityRequest {
    scope.budget.max_actions_per_tick = Some(1);
    CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject: fixture.subject.clone(),
        operation,
        scope,
        requested_at: fixture.now,
        metadata: Default::default(),
    }
}

fn cache_with(
    grant: ValidatedCapabilityGrant,
    cached_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> AuthorityGrantCache {
    let mut cache = AuthorityGrantCache::new();
    cache
        .insert_validated(grant, cached_at, expires_at)
        .expect("validated grant should be cacheable");
    cache
}

fn active_snapshot(now: OffsetDateTime) -> RevocationSnapshot {
    RevocationSnapshot::with_max_age(Vec::new(), now, Duration::minutes(30))
        .expect("active snapshot")
}

fn revoked_record(grant_id: CapabilityGrantId, now: OffsetDateTime) -> RevocationRecord {
    RevocationRecord {
        schema_version: REVOCATION_RECORD_SCHEMA_VERSION.to_string(),
        revocation_id: AuthorityRevocationId::new(),
        grant_id,
        revocation_ref: Some("revocation:local-authority-cache".to_string()),
        status: RevocationStatus::Revoked {
            reason: "operator_revoked".to_string(),
        },
        revoked_at: Some(now),
    }
}

fn connected_policy() -> OfflineAuthorityPolicy {
    OfflineAuthorityPolicy::connected(Duration::minutes(20)).expect("connected policy")
}

fn disconnected_policy(
    allowed: Vec<AuthorityOperation>,
    high_risk_behavior: AuthorityOfflineHighRiskBehavior,
) -> OfflineAuthorityPolicy {
    OfflineAuthorityPolicy::disconnected(
        Duration::minutes(30),
        Duration::minutes(10),
        allowed,
        high_risk_behavior,
    )
    .expect("disconnected policy")
}

#[test]
fn revocation_snapshot_denies_cached_grant_even_when_payload_is_active() {
    let fixture = Fixture::new();
    let grant = grant_for(&fixture, data_read_operation(), data_scope(&fixture));
    assert_eq!(grant.grant().revocation, RevocationStatus::Active);
    let cache = cache_with(
        grant.clone(),
        fixture.now,
        fixture.now + Duration::minutes(20),
    );
    let snapshot = RevocationSnapshot::with_max_age(
        vec![revoked_record(grant.grant().grant_id.clone(), fixture.now)],
        fixture.now,
        Duration::minutes(30),
    )
    .expect("revocation snapshot");
    let request = request_for(&fixture, data_read_operation(), data_scope(&fixture));

    let decision = evaluate_cached_capability_request(
        &cache,
        Some(&snapshot),
        &connected_policy(),
        &request,
        fixture.now,
    );

    assert_eq!(decision.status, AuthorityDecisionStatus::Denied);
    assert_eq!(decision.reasons, vec![REASON_AUTHORITY_GRANT_REVOKED]);
    assert!(decision.matched_grant_ids.is_empty());
}

#[test]
fn missing_stale_and_expired_cache_deny_fail_closed() {
    let fixture = Fixture::new();
    let snapshot = active_snapshot(fixture.now);
    let request = request_for(&fixture, data_read_operation(), data_scope(&fixture));

    let missing = evaluate_cached_capability_request(
        &AuthorityGrantCache::new(),
        Some(&snapshot),
        &connected_policy(),
        &request,
        fixture.now,
    );
    assert_eq!(missing.status, AuthorityDecisionStatus::Denied);
    assert_eq!(missing.reasons, vec![REASON_AUTHORITY_CACHE_MISSING]);

    let stale_grant = grant_for(&fixture, data_read_operation(), data_scope(&fixture));
    let stale_cache = cache_with(
        stale_grant,
        fixture.now - Duration::minutes(30),
        fixture.now + Duration::minutes(20),
    );
    let stale_policy = OfflineAuthorityPolicy::connected(Duration::minutes(5)).expect("policy");
    let stale = evaluate_cached_capability_request(
        &stale_cache,
        Some(&snapshot),
        &stale_policy,
        &request,
        fixture.now,
    );
    assert_eq!(stale.status, AuthorityDecisionStatus::Denied);
    assert_eq!(stale.reasons, vec![REASON_AUTHORITY_CACHE_STALE]);

    let expired_fixture = Fixture::new();
    let expired_grant = grant_for(
        &expired_fixture,
        data_read_operation(),
        data_scope(&expired_fixture),
    );
    let expired_cache = cache_with(
        expired_grant,
        expired_fixture.now - Duration::minutes(2),
        expired_fixture.now - Duration::seconds(1),
    );
    let expired_request = request_for(
        &expired_fixture,
        data_read_operation(),
        data_scope(&expired_fixture),
    );
    let expired = evaluate_cached_capability_request(
        &expired_cache,
        Some(&active_snapshot(expired_fixture.now)),
        &connected_policy(),
        &expired_request,
        expired_fixture.now,
    );
    assert_eq!(expired.status, AuthorityDecisionStatus::Denied);
    assert_eq!(expired.reasons, vec![REASON_AUTHORITY_CACHE_EXPIRED]);
}

#[test]
fn stale_or_missing_revocation_snapshot_denies_cached_authority() {
    let fixture = Fixture::new();
    let grant = grant_for(&fixture, data_read_operation(), data_scope(&fixture));
    let cache = cache_with(grant, fixture.now, fixture.now + Duration::minutes(20));
    let request = request_for(&fixture, data_read_operation(), data_scope(&fixture));

    let missing_snapshot = evaluate_cached_capability_request(
        &cache,
        None,
        &connected_policy(),
        &request,
        fixture.now,
    );
    assert_eq!(missing_snapshot.status, AuthorityDecisionStatus::Denied);
    assert_eq!(
        missing_snapshot.reasons,
        vec![REASON_AUTHORITY_REVOCATION_SNAPSHOT_MISSING]
    );

    let stale_snapshot = RevocationSnapshot::with_max_age(
        Vec::new(),
        fixture.now - Duration::minutes(30),
        Duration::minutes(1),
    )
    .expect("stale snapshot builds");
    let stale = evaluate_cached_capability_request(
        &cache,
        Some(&stale_snapshot),
        &connected_policy(),
        &request,
        fixture.now,
    );
    assert_eq!(stale.status, AuthorityDecisionStatus::Denied);
    assert_eq!(
        stale.reasons,
        vec![REASON_AUTHORITY_REVOCATION_SNAPSHOT_STALE]
    );
}

#[test]
fn disconnected_low_risk_read_evaluates_only_within_cached_scope_and_ttl() {
    let fixture = Fixture::new();
    let grant = grant_for(&fixture, data_read_operation(), data_scope(&fixture));
    let cache = cache_with(
        grant,
        fixture.now - Duration::minutes(1),
        fixture.now + Duration::minutes(20),
    );
    let snapshot = active_snapshot(fixture.now);
    let policy = disconnected_policy(
        vec![data_read_operation()],
        AuthorityOfflineHighRiskBehavior::Deny,
    );

    let allowed_request = request_for(&fixture, data_read_operation(), data_scope(&fixture));
    let allowed = evaluate_cached_capability_request(
        &cache,
        Some(&snapshot),
        &policy,
        &allowed_request,
        fixture.now,
    );
    assert_eq!(allowed.status, AuthorityDecisionStatus::Allowed);
    assert_eq!(allowed.reasons, vec!["capability_allowed"]);

    let mut overbroad_scope = data_scope(&fixture);
    overbroad_scope.tenant_ids = Some(vec![TenantId::new()]);
    let overbroad_request = request_for(&fixture, data_read_operation(), overbroad_scope);
    let overbroad = evaluate_cached_capability_request(
        &cache,
        Some(&snapshot),
        &policy,
        &overbroad_request,
        fixture.now,
    );
    assert_eq!(overbroad.status, AuthorityDecisionStatus::Denied);
    assert!(overbroad
        .reasons
        .contains(&"tenant_ids_not_granted".to_string()));
    assert!(overbroad
        .reasons
        .contains(&REASON_AUTHORITY_SCOPE_MISMATCH.to_string()));
}

#[test]
fn disconnected_explicit_low_risk_device_read_can_evaluate_within_scope() {
    let fixture = Fixture::new();
    let grant = grant_for(&fixture, device_read_operation(), device_scope(&fixture));
    let cache = cache_with(
        grant,
        fixture.now - Duration::minutes(1),
        fixture.now + Duration::minutes(20),
    );
    let snapshot = active_snapshot(fixture.now);
    let policy = disconnected_policy(
        vec![device_read_operation()],
        AuthorityOfflineHighRiskBehavior::Deny,
    );
    let request = request_for(&fixture, device_read_operation(), device_scope(&fixture));

    let decision =
        evaluate_cached_capability_request(&cache, Some(&snapshot), &policy, &request, fixture.now);

    assert_eq!(decision.status, AuthorityDecisionStatus::Allowed);
    assert_eq!(decision.reasons, vec!["capability_allowed"]);
}

#[test]
fn disconnected_unsupported_read_denies_when_not_explicitly_listed() {
    let fixture = Fixture::new();
    let grant = grant_for(&fixture, device_read_operation(), device_scope(&fixture));
    let cache = cache_with(
        grant,
        fixture.now - Duration::minutes(1),
        fixture.now + Duration::minutes(20),
    );
    let request = request_for(&fixture, device_read_operation(), device_scope(&fixture));
    let policy = disconnected_policy(
        vec![data_read_operation()],
        AuthorityOfflineHighRiskBehavior::Deny,
    );

    let decision = evaluate_cached_capability_request(
        &cache,
        Some(&active_snapshot(fixture.now)),
        &policy,
        &request,
        fixture.now,
    );

    assert_eq!(decision.status, AuthorityDecisionStatus::Denied);
    assert_eq!(
        decision.reasons,
        vec![REASON_AUTHORITY_OFFLINE_UNSUPPORTED_OPERATION]
    );
}

#[test]
fn disconnected_high_risk_device_change_and_self_change_follow_explicit_policy() {
    let device_fixture = Fixture::new();
    let device_grant = grant_for(
        &device_fixture,
        device_actuate_operation(),
        device_scope(&device_fixture),
    );
    let device_cache = cache_with(
        device_grant,
        device_fixture.now - Duration::minutes(1),
        device_fixture.now + Duration::minutes(20),
    );
    let device_request = request_for(
        &device_fixture,
        device_actuate_operation(),
        device_scope(&device_fixture),
    );
    let deny_policy = disconnected_policy(Vec::new(), AuthorityOfflineHighRiskBehavior::Deny);

    let denied = evaluate_cached_capability_request(
        &device_cache,
        Some(&active_snapshot(device_fixture.now)),
        &deny_policy,
        &device_request,
        device_fixture.now,
    );
    assert_eq!(denied.status, AuthorityDecisionStatus::Denied);
    assert_eq!(
        denied.reasons,
        vec![REASON_AUTHORITY_OFFLINE_HIGH_RISK_DENIED]
    );

    let change_fixture = Fixture::new();
    let change_grant = grant_for(
        &change_fixture,
        change_activate_operation(),
        base_scope(&change_fixture),
    );
    let change_cache = cache_with(
        change_grant,
        change_fixture.now - Duration::minutes(1),
        change_fixture.now + Duration::minutes(20),
    );
    let change_request = request_for(
        &change_fixture,
        change_activate_operation(),
        base_scope(&change_fixture),
    );
    let intervention_policy = disconnected_policy(
        Vec::new(),
        AuthorityOfflineHighRiskBehavior::NeedsIntervention,
    );

    let needs_intervention = evaluate_cached_capability_request(
        &change_cache,
        Some(&active_snapshot(change_fixture.now)),
        &intervention_policy,
        &change_request,
        change_fixture.now,
    );
    assert_eq!(
        needs_intervention.status,
        AuthorityDecisionStatus::NeedsIntervention
    );
    assert_eq!(
        needs_intervention.reasons,
        vec![REASON_AUTHORITY_OFFLINE_HIGH_RISK_NEEDS_INTERVENTION]
    );

    let self_change_fixture = Fixture::new();
    let self_change_grant = grant_for(
        &self_change_fixture,
        agent_delegate_operation(),
        base_scope(&self_change_fixture),
    );
    let self_change_cache = cache_with(
        self_change_grant,
        self_change_fixture.now - Duration::minutes(1),
        self_change_fixture.now + Duration::minutes(20),
    );
    let self_change_request = request_for(
        &self_change_fixture,
        agent_delegate_operation(),
        base_scope(&self_change_fixture),
    );
    let self_change_denied = evaluate_cached_capability_request(
        &self_change_cache,
        Some(&active_snapshot(self_change_fixture.now)),
        &deny_policy,
        &self_change_request,
        self_change_fixture.now,
    );
    assert_eq!(self_change_denied.status, AuthorityDecisionStatus::Denied);
    assert_eq!(
        self_change_denied.reasons,
        vec![REASON_AUTHORITY_OFFLINE_HIGH_RISK_DENIED]
    );
}

#[test]
fn disconnected_needs_intervention_requires_matching_cached_authority() {
    let fixture = Fixture::new();
    let unrelated_grant = grant_for(&fixture, data_read_operation(), data_scope(&fixture));
    let cache = cache_with(
        unrelated_grant,
        fixture.now - Duration::minutes(1),
        fixture.now + Duration::minutes(20),
    );
    let request = request_for(&fixture, change_activate_operation(), base_scope(&fixture));
    let policy = disconnected_policy(
        Vec::new(),
        AuthorityOfflineHighRiskBehavior::NeedsIntervention,
    );

    let decision = evaluate_cached_capability_request(
        &cache,
        Some(&active_snapshot(fixture.now)),
        &policy,
        &request,
        fixture.now,
    );

    assert_eq!(decision.status, AuthorityDecisionStatus::Denied);
    assert!(decision
        .reasons
        .contains(&"operation_not_granted".to_string()));
    assert!(!decision
        .reasons
        .contains(&REASON_AUTHORITY_OFFLINE_HIGH_RISK_NEEDS_INTERVENTION.to_string()));
}

#[test]
fn future_dated_cache_or_snapshot_denies_fail_closed() {
    let fixture = Fixture::new();
    let grant = grant_for(&fixture, data_read_operation(), data_scope(&fixture));
    let future_cache = cache_with(
        grant,
        fixture.now + Duration::minutes(1),
        fixture.now + Duration::minutes(20),
    );
    let request = request_for(&fixture, data_read_operation(), data_scope(&fixture));

    let cache_decision = evaluate_cached_capability_request(
        &future_cache,
        Some(&active_snapshot(fixture.now)),
        &connected_policy(),
        &request,
        fixture.now,
    );
    assert_eq!(cache_decision.status, AuthorityDecisionStatus::Denied);
    assert_eq!(
        cache_decision.reasons,
        vec![REASON_AUTHORITY_CACHE_FUTURE_DATED]
    );

    let snapshot_fixture = Fixture::new();
    let snapshot_grant = grant_for(
        &snapshot_fixture,
        data_read_operation(),
        data_scope(&snapshot_fixture),
    );
    let snapshot_cache = cache_with(
        snapshot_grant,
        snapshot_fixture.now,
        snapshot_fixture.now + Duration::minutes(20),
    );
    let future_snapshot = RevocationSnapshot::with_max_age(
        Vec::new(),
        snapshot_fixture.now + Duration::minutes(1),
        Duration::minutes(30),
    )
    .expect("future snapshot still constructs for local trusted source tests");
    let snapshot_request = request_for(
        &snapshot_fixture,
        data_read_operation(),
        data_scope(&snapshot_fixture),
    );

    let snapshot_decision = evaluate_cached_capability_request(
        &snapshot_cache,
        Some(&future_snapshot),
        &connected_policy(),
        &snapshot_request,
        snapshot_fixture.now,
    );
    assert_eq!(snapshot_decision.status, AuthorityDecisionStatus::Denied);
    assert_eq!(
        snapshot_decision.reasons,
        vec![REASON_AUTHORITY_REVOCATION_SNAPSHOT_FUTURE_DATED]
    );
}

#[test]
fn offline_ttl_expiry_denies_even_explicit_low_risk_operations() {
    let fixture = Fixture::new();
    let grant = grant_for(&fixture, data_read_operation(), data_scope(&fixture));
    let cache = cache_with(
        grant,
        fixture.now - Duration::minutes(20),
        fixture.now + Duration::minutes(20),
    );
    let policy = disconnected_policy(
        vec![data_read_operation()],
        AuthorityOfflineHighRiskBehavior::Deny,
    );
    let request = request_for(&fixture, data_read_operation(), data_scope(&fixture));

    let decision = evaluate_cached_capability_request(
        &cache,
        Some(&active_snapshot(fixture.now)),
        &policy,
        &request,
        fixture.now,
    );

    assert_eq!(decision.status, AuthorityDecisionStatus::Denied);
    assert_eq!(decision.reasons, vec![REASON_AUTHORITY_OFFLINE_TTL_EXPIRED]);
}

#[test]
fn cache_api_wraps_validated_grants_and_cannot_extend_grant_expiry() {
    let fixture = Fixture::new();
    let grant = grant_for(&fixture, data_read_operation(), data_scope(&fixture));
    let mut cache = AuthorityGrantCache::new();

    cache
        .insert_validated(
            grant.clone(),
            fixture.now,
            fixture.now + Duration::minutes(5),
        )
        .expect("validated grant accepted");

    assert_eq!(cache.cached_grants().len(), 1);
    assert_eq!(
        cache.cached_grants()[0].grant().grant().grant_id,
        grant.grant().grant_id
    );

    let error = CachedAuthorityGrant::try_new(grant, fixture.now, fixture.now + Duration::hours(2))
        .expect_err("cache must not outlive grant");
    assert_eq!(error.reason_code(), "authority_cache_outlives_grant");

    let invalid_window = CachedAuthorityGrant::try_new(
        grant_for(&fixture, data_read_operation(), data_scope(&fixture)),
        fixture.now,
        fixture.now,
    )
    .expect_err("cache expiry must be after cached_at");
    assert_eq!(
        invalid_window.reason_code(),
        "authority_cache_window_invalid"
    );

    let cached_after_expiry = CachedAuthorityGrant::try_new(
        grant_for(&fixture, data_read_operation(), data_scope(&fixture)),
        fixture.now + Duration::hours(2),
        fixture.now + Duration::hours(3),
    )
    .expect_err("cache cannot be installed after grant expiry");
    assert_eq!(
        cached_after_expiry.reason_code(),
        "authority_cache_after_grant_expiry"
    );

    let replacement_grant = grant_for(&fixture, data_read_operation(), data_scope(&fixture));
    let mut replacement_cache = AuthorityGrantCache::new();
    assert!(replacement_cache
        .insert_validated(
            replacement_grant.clone(),
            fixture.now,
            fixture.now + Duration::minutes(5),
        )
        .expect("first insert succeeds")
        .is_none());
    assert!(replacement_cache
        .insert_validated(
            replacement_grant,
            fixture.now + Duration::seconds(1),
            fixture.now + Duration::minutes(6),
        )
        .expect("replacement insert succeeds")
        .is_some());
}

#[test]
fn revocation_snapshot_rejects_duplicate_or_malformed_records() {
    let fixture = Fixture::new();
    let grant_id = CapabilityGrantId::new();
    let duplicate = vec![
        revoked_record(grant_id.clone(), fixture.now),
        revoked_record(grant_id, fixture.now),
    ];
    let duplicate_error =
        RevocationSnapshot::with_max_age(duplicate, fixture.now, Duration::minutes(30))
            .expect_err("duplicate grant records must fail");
    assert_eq!(
        duplicate_error.reason_code(),
        "authority_revocation_record_duplicate_grant"
    );

    let mut malformed = revoked_record(CapabilityGrantId::new(), fixture.now);
    malformed.schema_version = "splendor.authority.revocation_record.v0".to_string();
    let malformed_error =
        RevocationSnapshot::with_max_age(vec![malformed], fixture.now, Duration::minutes(30))
            .expect_err("unsupported revocation record schema must fail");
    assert_eq!(
        malformed_error.reason_code(),
        "authority_revocation_record_schema_invalid"
    );

    let invalid_window = RevocationSnapshot::try_new(Vec::new(), fixture.now, fixture.now)
        .expect_err("snapshot expiry must be after refresh");
    assert_eq!(
        invalid_window.reason_code(),
        "authority_revocation_snapshot_window_invalid"
    );

    let invalid_max_age = RevocationSnapshot::with_max_age(Vec::new(), fixture.now, Duration::ZERO)
        .expect_err("snapshot max age must be positive");
    assert_eq!(
        invalid_max_age.reason_code(),
        "authority_revocation_snapshot_max_age_invalid"
    );

    let mut nil_revocation = revoked_record(CapabilityGrantId::new(), fixture.now);
    nil_revocation.revocation_id =
        AuthorityRevocationId::parse("00000000-0000-0000-0000-000000000000")
            .expect("nil revocation id parses");
    let nil_revocation_error =
        RevocationSnapshot::with_max_age(vec![nil_revocation], fixture.now, Duration::minutes(30))
            .expect_err("nil revocation id must fail");
    assert_eq!(
        nil_revocation_error.reason_code(),
        "authority_revocation_record_id_invalid"
    );

    let mut nil_grant = revoked_record(
        CapabilityGrantId::parse("00000000-0000-0000-0000-000000000000")
            .expect("nil grant id parses"),
        fixture.now,
    );
    nil_grant.revocation_id = AuthorityRevocationId::new();
    let nil_grant_error =
        RevocationSnapshot::with_max_age(vec![nil_grant], fixture.now, Duration::minutes(30))
            .expect_err("nil grant id must fail");
    assert_eq!(
        nil_grant_error.reason_code(),
        "authority_revocation_record_grant_id_invalid"
    );
}

#[test]
fn revocation_snapshot_accessors_and_ref_checks_are_fail_closed() {
    let fixture = Fixture::new();
    let grant = grant_for(&fixture, data_read_operation(), data_scope(&fixture));
    let mut active_mismatch = revoked_record(grant.grant().grant_id.clone(), fixture.now);
    active_mismatch.status = RevocationStatus::Active;
    active_mismatch.revocation_ref = Some("revocation:other-source".to_string());

    let snapshot = RevocationSnapshot::try_new(
        vec![active_mismatch],
        fixture.now,
        fixture.now + Duration::minutes(30),
    )
    .expect("snapshot with active mismatch record builds");

    assert_eq!(snapshot.refreshed_at(), fixture.now);
    assert_eq!(snapshot.expires_at(), fixture.now + Duration::minutes(30));
    assert_eq!(snapshot.records().len(), 1);

    let mismatch = snapshot
        .verify_grant_active(&grant, fixture.now)
        .expect_err("revocation source mismatch must fail closed");
    assert_eq!(
        mismatch.reason_code(),
        REASON_AUTHORITY_REVOCATION_REF_MISMATCH
    );

    let mut payload_revoked = grant.grant().clone();
    payload_revoked.revocation = RevocationStatus::Revoked {
        reason: "payload_revoked".to_string(),
    };
    let payload_revoked = unchecked_validated_grant_for_tests(payload_revoked);
    let active_snapshot = active_snapshot(fixture.now);
    let payload_error = active_snapshot
        .verify_grant_active(&payload_revoked, fixture.now)
        .expect_err("revoked grant payload must fail closed");
    assert_eq!(payload_error.reason_code(), REASON_AUTHORITY_GRANT_REVOKED);
}

#[test]
fn offline_policy_invalid_durations_return_stable_reason_codes() {
    let connected_error = OfflineAuthorityPolicy::connected(Duration::ZERO)
        .expect_err("zero connected freshness must fail");
    assert_eq!(
        connected_error.reason_code(),
        "authority_offline_policy_invalid_duration"
    );

    let disconnected_error = OfflineAuthorityPolicy::disconnected(
        Duration::minutes(1),
        Duration::ZERO,
        vec![data_read_operation()],
        AuthorityOfflineHighRiskBehavior::Deny,
    )
    .expect_err("zero offline grant ttl must fail");
    assert_eq!(
        disconnected_error.reason_code(),
        "authority_offline_policy_invalid_duration"
    );
}
