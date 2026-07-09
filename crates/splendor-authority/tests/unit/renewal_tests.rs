use super::*;
use crate::capability::unchecked_validated_grant_for_tests;
use splendor_types::{
    AgentId, AuthorityBudgetScope, AuthorityObligation, AuthorityObligationId,
    AuthorityObligationKind, AuthorityRevocationId, CapabilityGrant, CapabilityGrantId,
    CapabilityGrantValidation, CapabilityGrantValidationKind, CapabilityScope, DataPurpose,
    PrincipalId, RevocationRecord, RevocationStatus, RunId, TenantId,
    AUTHORITY_OBLIGATION_SCHEMA_VERSION, AUTHORITY_OPERATION_SCHEMA_VERSION,
    CAPABILITY_GRANT_SCHEMA_VERSION, REVOCATION_RECORD_SCHEMA_VERSION,
};
use time::{Duration, OffsetDateTime};

const AUDIENCE: &str = "daemon:local";
const DIGEST: &str = "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NONCE: &str = "renewal-nonce-001";

#[derive(Clone)]
struct Fixture {
    now: OffsetDateTime,
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
    subject: PrincipalId,
    issuer: PrincipalId,
}

impl Fixture {
    fn new() -> Self {
        Self {
            now: OffsetDateTime::now_utc(),
            tenant_id: TenantId::new(),
            agent_id: AgentId::new(),
            run_id: RunId::new(),
            subject: PrincipalId::new(),
            issuer: PrincipalId::new(),
        }
    }
}

fn validation(kind: CapabilityGrantValidationKind, digest: &str) -> CapabilityGrantValidation {
    CapabilityGrantValidation {
        validation_kind: kind,
        algorithm: "local-renewal-test-v1".to_string(),
        key_id: (kind == CapabilityGrantValidationKind::Signed).then(|| "test-key".to_string()),
        digest: digest.to_string(),
        signature: None,
    }
}

fn data_read_operation() -> splendor_types::AuthorityOperation {
    splendor_types::AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: splendor_types::AuthorityOperationNamespace::Data,
        resource_kind: splendor_types::AuthorityResourceKind::Data,
        verb: splendor_types::AuthorityVerb::Read,
        name: None,
        resource_schema_version: Some("splendor.data_use.v1".to_string()),
    }
}

fn data_scope(fixture: &Fixture) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![fixture.tenant_id.clone()]),
        agent_ids: Some(vec![fixture.agent_id.clone()]),
        run_ids: Some(vec![fixture.run_id.clone()]),
        data_purposes: Some(vec![DataPurpose::Read]),
        audiences: Some(vec![AUDIENCE.to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(3),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn grant_for(fixture: &Fixture) -> ValidatedCapabilityGrant {
    unchecked_validated_grant_for_tests(CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: CapabilityGrantId::new(),
        issuer: fixture.issuer.clone(),
        subject: fixture.subject.clone(),
        parent_grant_ids: Vec::new(),
        operations: vec![data_read_operation()],
        scope: data_scope(fixture),
        not_before: fixture.now - Duration::minutes(5),
        expires_at: fixture.now + Duration::minutes(20),
        revocation_ref: Some("revocation:renewal-test".to_string()),
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth: 1,
        validation: Some(validation(
            CapabilityGrantValidationKind::LocallyValidated,
            DIGEST,
        )),
        metadata: Default::default(),
    })
}

fn renewed_from(
    current: &ValidatedCapabilityGrant,
    expires_at: OffsetDateTime,
) -> ValidatedCapabilityGrant {
    let mut raw = current.grant().clone();
    raw.expires_at = expires_at;
    unchecked_validated_grant_for_tests(raw)
}

fn cached_for(
    grant: ValidatedCapabilityGrant,
    cached_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> CachedAuthorityGrant {
    CachedAuthorityGrant::try_new(grant, cached_at, expires_at).expect("cacheable grant")
}

fn active_snapshot(now: OffsetDateTime) -> RevocationSnapshot {
    RevocationSnapshot::with_max_age(Vec::new(), now, Duration::minutes(20))
        .expect("active snapshot")
}

fn revoked_record(grant_id: CapabilityGrantId, now: OffsetDateTime) -> RevocationRecord {
    RevocationRecord {
        schema_version: REVOCATION_RECORD_SCHEMA_VERSION.to_string(),
        revocation_id: AuthorityRevocationId::new(),
        grant_id,
        revocation_ref: Some("revocation:renewal-test".to_string()),
        status: RevocationStatus::Revoked {
            reason: "operator_revoked".to_string(),
        },
        revoked_at: Some(now),
    }
}

fn renewal_policy() -> AuthorityGrantRenewalPolicy {
    AuthorityGrantRenewalPolicy::renewable(
        Duration::minutes(5),
        Duration::minutes(30),
        Duration::minutes(15),
    )
    .expect("renewal policy")
}

fn trusted_context(now: OffsetDateTime) -> TrustedAuthorityRenewalContext {
    TrustedAuthorityRenewalContext::new(NONCE, DIGEST, now).expect("trusted context")
}

fn renewal_request<'a>(
    cached_grant: &'a CachedAuthorityGrant,
    revocation_snapshot: Option<&'a RevocationSnapshot>,
    policy: Option<&'a AuthorityGrantRenewalPolicy>,
    trusted_context: &'a TrustedAuthorityRenewalContext,
    nonce: &'a str,
    renewed_grant: &'a ValidatedCapabilityGrant,
    renewed_cache_expires_at: OffsetDateTime,
) -> AuthorityGrantRenewalRequest<'a> {
    AuthorityGrantRenewalRequest {
        cached_grant,
        revocation_snapshot,
        policy,
        trusted_context,
        nonce,
        renewed_grant,
        renewed_cache_expires_at,
    }
}

fn run_success_fixture() -> (
    Fixture,
    ValidatedCapabilityGrant,
    CachedAuthorityGrant,
    RevocationSnapshot,
    AuthorityGrantRenewalPolicy,
    TrustedAuthorityRenewalContext,
    ValidatedCapabilityGrant,
) {
    let fixture = Fixture::new();
    let current = grant_for(&fixture);
    let cached = cached_for(
        current.clone(),
        fixture.now - Duration::minutes(1),
        fixture.now + Duration::minutes(10),
    );
    let snapshot = active_snapshot(fixture.now);
    let policy = renewal_policy();
    let context = trusted_context(fixture.now);
    let renewed = renewed_from(&current, fixture.now + Duration::minutes(25));
    (fixture, current, cached, snapshot, policy, context, renewed)
}

fn assert_denied_for_renewed_change(
    mutate: impl FnOnce(&mut CapabilityGrant),
    expected_reason: &'static str,
) {
    let (fixture, current, cached, snapshot, policy, context, _) = run_success_fixture();
    let mut raw = current.grant().clone();
    raw.expires_at = fixture.now + Duration::minutes(25);
    mutate(&mut raw);
    let renewed = unchecked_validated_grant_for_tests(raw);

    let result = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));

    assert_eq!(result.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(
        result.reasons().contains(&expected_reason.to_string()),
        "expected {expected_reason}, got {:?}",
        result.reasons()
    );
    assert!(result.renewed_cached_grant().is_none());
}

#[test]
fn positive_renewal_requires_fresh_cache_snapshot_nonce_and_current_digest() {
    let (fixture, current, cached, snapshot, policy, context, renewed) = run_success_fixture();

    let result = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));

    assert_eq!(result.status(), AuthorityGrantRenewalStatus::Renewed);
    assert_eq!(result.reasons(), &["authority_renewal_allowed".to_string()]);
    assert_eq!(result.checked_at(), fixture.now);
    let renewed_cache = result
        .renewed_cached_grant()
        .expect("renewal should return cache");
    assert_eq!(renewed_cache.cached_at(), fixture.now);
    assert_eq!(
        renewed_cache.expires_at(),
        fixture.now + Duration::minutes(10)
    );
    assert_eq!(
        renewed_cache.grant().grant().grant_id,
        current.grant().grant_id
    );
    assert_eq!(
        renewed_cache.grant().grant().expires_at,
        fixture.now + Duration::minutes(25)
    );
}

#[test]
fn missing_or_mismatched_nonce_denies() {
    let (fixture, _, cached, snapshot, policy, context, renewed) = run_success_fixture();

    let missing = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&snapshot),
        Some(&policy),
        &context,
        "",
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(missing.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(missing
        .reasons()
        .contains(&REASON_AUTHORITY_RENEWAL_NONCE_MISSING.to_string()));

    let mismatch = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&snapshot),
        Some(&policy),
        &context,
        "wrong-nonce",
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(mismatch.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(mismatch
        .reasons()
        .contains(&REASON_AUTHORITY_RENEWAL_NONCE_MISMATCH.to_string()));

    let context_error = TrustedAuthorityRenewalContext::new(" ", DIGEST, fixture.now)
        .expect_err("empty trusted nonce fails closed");
    assert_eq!(
        context_error.reason_code(),
        REASON_AUTHORITY_RENEWAL_NONCE_MISSING
    );
}

#[test]
fn current_digest_mismatch_denies() {
    let (fixture, _, cached, snapshot, policy, _, renewed) = run_success_fixture();
    let stale_context = TrustedAuthorityRenewalContext::new(
        NONCE,
        "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        fixture.now,
    )
    .expect("non-empty stale context");

    let result = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&snapshot),
        Some(&policy),
        &stale_context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));

    assert_eq!(result.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(result
        .reasons()
        .contains(&REASON_AUTHORITY_RENEWAL_CURRENT_REVISION_MISMATCH.to_string()));

    let context_error = TrustedAuthorityRenewalContext::new(NONCE, " ", fixture.now)
        .expect_err("empty current digest fails closed");
    assert_eq!(
        context_error.reason_code(),
        REASON_AUTHORITY_RENEWAL_CURRENT_REVISION_MISSING
    );
}

#[test]
fn missing_or_non_renewable_policy_denies() {
    let (fixture, _, cached, snapshot, _, context, renewed) = run_success_fixture();

    let missing = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&snapshot),
        None,
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(missing.status(), AuthorityGrantRenewalStatus::Denied);
    assert_eq!(
        missing.reasons(),
        &[REASON_AUTHORITY_RENEWAL_POLICY_MISSING.to_string()]
    );

    let non_renewable = AuthorityGrantRenewalPolicy::non_renewable();
    let denied = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&snapshot),
        Some(&non_renewable),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(denied.status(), AuthorityGrantRenewalStatus::Denied);
    assert_eq!(
        denied.reasons(),
        &[REASON_AUTHORITY_RENEWAL_NON_RENEWABLE.to_string()]
    );

    let policy_error = AuthorityGrantRenewalPolicy::renewable(
        Duration::ZERO,
        Duration::minutes(1),
        Duration::minutes(1),
    )
    .expect_err("zero max cache staleness fails closed");
    assert_eq!(
        policy_error.reason_code(),
        "authority_renewal_policy_invalid_duration"
    );
}

#[test]
fn revoked_grant_or_revocation_record_denies() {
    let (fixture, current, cached, _, policy, context, renewed) = run_success_fixture();
    let snapshot = RevocationSnapshot::with_max_age(
        vec![revoked_record(
            current.grant().grant_id.clone(),
            fixture.now,
        )],
        fixture.now,
        Duration::minutes(20),
    )
    .expect("revoked snapshot");

    let snapshot_revoked = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(
        snapshot_revoked.status(),
        AuthorityGrantRenewalStatus::Denied
    );
    assert!(snapshot_revoked
        .reasons()
        .contains(&crate::REASON_AUTHORITY_GRANT_REVOKED.to_string()));

    let mut revoked_payload = current.grant().clone();
    revoked_payload.revocation = RevocationStatus::Revoked {
        reason: "payload_revoked".to_string(),
    };
    let revoked_current = unchecked_validated_grant_for_tests(revoked_payload);
    let revoked_cache = cached_for(
        revoked_current,
        fixture.now - Duration::minutes(1),
        fixture.now + Duration::minutes(10),
    );
    let active_snapshot = active_snapshot(fixture.now);
    let payload_revoked = renew_cached_authority_grant(renewal_request(
        &revoked_cache,
        Some(&active_snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(
        payload_revoked.status(),
        AuthorityGrantRenewalStatus::Denied
    );
    assert!(payload_revoked
        .reasons()
        .contains(&crate::REASON_AUTHORITY_GRANT_REVOKED.to_string()));
}

#[test]
fn missing_stale_or_future_snapshot_denies() {
    let (fixture, _, cached, _, policy, context, renewed) = run_success_fixture();

    let missing = renew_cached_authority_grant(renewal_request(
        &cached,
        None,
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(missing.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(missing
        .reasons()
        .contains(&crate::REASON_AUTHORITY_REVOCATION_SNAPSHOT_MISSING.to_string()));

    let stale_snapshot = RevocationSnapshot::try_new(
        Vec::new(),
        fixture.now - Duration::minutes(10),
        fixture.now - Duration::minutes(1),
    )
    .expect("stale snapshot builds");
    let stale = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&stale_snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(stale.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(stale
        .reasons()
        .contains(&crate::REASON_AUTHORITY_REVOCATION_SNAPSHOT_STALE.to_string()));

    let future_snapshot = RevocationSnapshot::with_max_age(
        Vec::new(),
        fixture.now + Duration::minutes(1),
        Duration::minutes(20),
    )
    .expect("future snapshot builds for fail-closed check");
    let future = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&future_snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(future.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(future
        .reasons()
        .contains(&crate::REASON_AUTHORITY_REVOCATION_SNAPSHOT_FUTURE_DATED.to_string()));
}

#[test]
fn stale_expired_or_future_cached_grant_denies() {
    let (fixture, current, _, snapshot, policy, context, renewed) = run_success_fixture();

    let stale_cache = cached_for(
        current.clone(),
        fixture.now - Duration::minutes(10),
        fixture.now + Duration::minutes(10),
    );
    let stale = renew_cached_authority_grant(renewal_request(
        &stale_cache,
        Some(&snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(stale.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(stale
        .reasons()
        .contains(&crate::REASON_AUTHORITY_CACHE_STALE.to_string()));

    let expired_cache = cached_for(
        current.clone(),
        fixture.now - Duration::minutes(2),
        fixture.now - Duration::minutes(1),
    );
    let expired = renew_cached_authority_grant(renewal_request(
        &expired_cache,
        Some(&snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(expired.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(expired
        .reasons()
        .contains(&crate::REASON_AUTHORITY_CACHE_EXPIRED.to_string()));

    let future_cache = cached_for(
        current.clone(),
        fixture.now + Duration::minutes(1),
        fixture.now + Duration::minutes(10),
    );
    let future = renew_cached_authority_grant(renewal_request(
        &future_cache,
        Some(&snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(future.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(future
        .reasons()
        .contains(&crate::REASON_AUTHORITY_CACHE_FUTURE_DATED.to_string()));

    let mut future_grant = current.grant().clone();
    future_grant.not_before = fixture.now + Duration::minutes(1);
    future_grant.expires_at = fixture.now + Duration::minutes(20);
    let future_grant = unchecked_validated_grant_for_tests(future_grant);
    let future_grant_cache = cached_for(
        future_grant,
        fixture.now - Duration::minutes(1),
        fixture.now + Duration::minutes(10),
    );
    let not_yet_valid = renew_cached_authority_grant(renewal_request(
        &future_grant_cache,
        Some(&snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(not_yet_valid.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(not_yet_valid
        .reasons()
        .contains(&REASON_AUTHORITY_RENEWAL_GRANT_FUTURE_DATED.to_string()));
}

#[test]
fn renewed_grant_change_denies_for_every_authority_dimension() {
    assert_denied_for_renewed_change(
        |grant| grant.grant_id = CapabilityGrantId::new(),
        REASON_AUTHORITY_RENEWAL_GRANT_ID_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| grant.issuer = PrincipalId::new(),
        REASON_AUTHORITY_RENEWAL_ISSUER_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| grant.subject = PrincipalId::new(),
        REASON_AUTHORITY_RENEWAL_SUBJECT_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| grant.parent_grant_ids = vec![CapabilityGrantId::new()],
        REASON_AUTHORITY_RENEWAL_PARENT_GRANTS_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| {
            let mut operation = data_read_operation();
            operation.resource_schema_version = Some("splendor.data_use.v2".to_string());
            grant.operations = vec![operation];
        },
        REASON_AUTHORITY_RENEWAL_OPERATIONS_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| grant.scope.run_ids = Some(vec![RunId::new()]),
        REASON_AUTHORITY_RENEWAL_SCOPE_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| grant.scope.audiences = Some(vec!["daemon:other".to_string()]),
        REASON_AUTHORITY_RENEWAL_AUDIENCE_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| grant.revocation_ref = Some("revocation:other".to_string()),
        REASON_AUTHORITY_RENEWAL_REVOCATION_REF_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| {
            grant.revocation = RevocationStatus::Revoked {
                reason: "changed".to_string(),
            };
        },
        REASON_AUTHORITY_RENEWAL_REVOCATION_STATE_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| {
            grant.obligations = vec![AuthorityObligation {
                schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
                obligation_id: AuthorityObligationId::new(),
                kind: AuthorityObligationKind::LocalOnly,
                description: "stay local".to_string(),
                parameters: Default::default(),
            }];
        },
        REASON_AUTHORITY_RENEWAL_OBLIGATIONS_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| {
            grant.validation = Some(validation(CapabilityGrantValidationKind::Signed, DIGEST));
        },
        REASON_AUTHORITY_RENEWAL_VALIDATION_KIND_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| grant.max_delegation_depth += 1,
        REASON_AUTHORITY_RENEWAL_DELEGATION_DEPTH_CHANGED,
    );
    assert_denied_for_renewed_change(
        |grant| grant.not_before -= Duration::minutes(1),
        REASON_AUTHORITY_RENEWAL_NOT_BEFORE_CHANGED,
    );
}

#[test]
fn requested_lifetime_beyond_renewal_or_offline_caps_denies() {
    let (fixture, _, cached, snapshot, policy, context, mut renewed) = run_success_fixture();
    let mut too_long = renewed.grant().clone();
    too_long.expires_at = fixture.now + Duration::hours(2);
    renewed = unchecked_validated_grant_for_tests(too_long);

    let grant_lifetime = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(10),
    ));
    assert_eq!(grant_lifetime.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(grant_lifetime
        .reasons()
        .contains(&REASON_AUTHORITY_RENEWAL_LIFETIME_EXCEEDED.to_string()));

    let renewed = renewed_from(cached.grant(), fixture.now + Duration::minutes(25));
    let offline_lifetime = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(16),
    ));
    assert_eq!(
        offline_lifetime.status(),
        AuthorityGrantRenewalStatus::Denied
    );
    assert!(offline_lifetime
        .reasons()
        .contains(&REASON_AUTHORITY_RENEWAL_OFFLINE_LIFETIME_EXCEEDED.to_string()));
}

#[test]
fn renewed_cache_cannot_outlive_renewed_grant_expiry() {
    let (fixture, _, cached, snapshot, policy, context, renewed) = run_success_fixture();

    let result = renew_cached_authority_grant(renewal_request(
        &cached,
        Some(&snapshot),
        Some(&policy),
        &context,
        NONCE,
        &renewed,
        fixture.now + Duration::minutes(26),
    ));

    assert_eq!(result.status(), AuthorityGrantRenewalStatus::Denied);
    assert!(result
        .reasons()
        .contains(&REASON_AUTHORITY_RENEWAL_CACHE_OUTLIVES_GRANT.to_string()));
    assert!(result.renewed_cached_grant().is_none());
}
