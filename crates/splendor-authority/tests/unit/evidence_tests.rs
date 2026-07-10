use super::*;
use crate::capability::unchecked_validated_grant_for_tests;
use splendor_types::{
    AgentId, AuthorityBudgetScope, AuthorityDecision, AuthorityObligation, AuthorityObligationId,
    AuthorityObligationKind, CapabilityGrant, CapabilityGrantValidation, CapabilityRequest,
    CapabilityScope, RevocationStatus, RunId, TenantId, AUTHORITY_DECISION_SCHEMA_VERSION,
    AUTHORITY_OBLIGATION_SCHEMA_VERSION, AUTHORITY_OPERATION_SCHEMA_VERSION,
    CAPABILITY_GRANT_SCHEMA_VERSION, CAPABILITY_REQUEST_SCHEMA_VERSION,
};
use std::collections::BTreeMap;
use time::Duration;

const VALIDATION_DIGEST: &str =
    "blake3:1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_VALIDATION_DIGEST: &str =
    "blake3:2222222222222222222222222222222222222222222222222222222222222222";
const SECRET_METADATA: &str = "credential-do-not-export";
const SECRET_KEY_ID: &str = "key-do-not-export";
const SECRET_SIGNATURE: &str = "signature-do-not-export";
const SECRET_OBLIGATION_DESCRIPTION: &str = "free-form-secret-obligation-description";
const SECRET_OBLIGATION_PARAMETER: &str = "free-form-secret-obligation-parameter";
const SENSITIVE_OPERATION_NAME: &str = "protected-eval-case-do-not-export";
const RAW_LOCAL_REVISION_TOKEN: &str = "local-delegation:raw-revision-token-do-not-export";

#[derive(Clone)]
struct Fixture {
    now: OffsetDateTime,
    subject: PrincipalId,
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
    decision_id: AuthorityDecisionId,
    grant_id: CapabilityGrantId,
    obligation_id: AuthorityObligationId,
}

impl Fixture {
    fn new() -> Self {
        Self {
            now: OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("fixed timestamp"),
            subject: PrincipalId::parse("10000000-0000-0000-0000-000000000001").expect("subject"),
            tenant_id: TenantId::parse("20000000-0000-0000-0000-000000000001").expect("tenant"),
            agent_id: AgentId::parse("30000000-0000-0000-0000-000000000001").expect("agent"),
            run_id: RunId::parse("40000000-0000-0000-0000-000000000001").expect("run"),
            decision_id: AuthorityDecisionId::parse("50000000-0000-0000-0000-000000000001")
                .expect("decision"),
            grant_id: CapabilityGrantId::parse("60000000-0000-0000-0000-000000000001")
                .expect("grant"),
            obligation_id: AuthorityObligationId::parse("70000000-0000-0000-0000-000000000001")
                .expect("obligation"),
        }
    }
}

fn operation(name: &str) -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Gateway,
        resource_kind: AuthorityResourceKind::Action,
        verb: AuthorityVerb::Invoke,
        name: Some(name.to_string()),
        resource_schema_version: Some("splendor.action.v1".to_string()),
    }
}

fn scope(fixture: &Fixture, max_actions: u32) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![fixture.tenant_id.clone()]),
        agent_ids: Some(vec![fixture.agent_id.clone()]),
        run_ids: Some(vec![fixture.run_id.clone()]),
        audiences: Some(vec!["daemon:local".to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(max_actions),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn request(fixture: &Fixture) -> CapabilityRequest {
    let mut metadata = BTreeMap::new();
    metadata.insert("safe_note".to_string(), serde_json::json!(SECRET_METADATA));
    CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject: fixture.subject.clone(),
        operation: operation(SENSITIVE_OPERATION_NAME),
        scope: scope(fixture, 1),
        requested_at: fixture.now,
        metadata,
    }
}

fn obligation(fixture: &Fixture) -> AuthorityObligation {
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "protected_parameter".to_string(),
        serde_json::json!(SECRET_OBLIGATION_PARAMETER),
    );
    AuthorityObligation {
        schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
        obligation_id: fixture.obligation_id.clone(),
        kind: AuthorityObligationKind::ApprovalRequired,
        description: SECRET_OBLIGATION_DESCRIPTION.to_string(),
        parameters,
    }
}

fn grant_with(
    fixture: &Fixture,
    grant_id: CapabilityGrantId,
    validation_digest: &str,
    max_actions: u32,
    cached_window_hours: i64,
) -> ValidatedCapabilityGrant {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "raw_metadata".to_string(),
        serde_json::json!(SECRET_METADATA),
    );
    unchecked_validated_grant_for_tests(CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id,
        issuer: PrincipalId::parse("80000000-0000-0000-0000-000000000001").expect("issuer"),
        subject: fixture.subject.clone(),
        parent_grant_ids: Vec::new(),
        operations: vec![operation(SENSITIVE_OPERATION_NAME)],
        scope: scope(fixture, max_actions),
        not_before: fixture.now - Duration::hours(1),
        expires_at: fixture.now + Duration::hours(cached_window_hours),
        revocation_ref: Some("revocation:restricted".to_string()),
        revocation: RevocationStatus::Active,
        obligations: vec![obligation(fixture)],
        max_delegation_depth: 1,
        validation: Some(CapabilityGrantValidation {
            validation_kind: CapabilityGrantValidationKind::LocallyValidated,
            algorithm: "local-sensitive-algorithm".to_string(),
            key_id: Some(SECRET_KEY_ID.to_string()),
            digest: validation_digest.to_string(),
            signature: Some(SECRET_SIGNATURE.to_string()),
        }),
        metadata,
    })
}

fn decision(fixture: &Fixture) -> AuthorityDecision {
    AuthorityDecision {
        schema_version: AUTHORITY_DECISION_SCHEMA_VERSION.to_string(),
        decision_id: fixture.decision_id.clone(),
        request: request(fixture),
        status: AuthorityDecisionStatus::Conditional,
        reasons: vec!["capability_conditional".to_string()],
        matched_grant_ids: vec![fixture.grant_id.clone()],
        obligations: vec![obligation(fixture)],
        decided_at: fixture.now,
    }
}

#[test]
fn identical_decision_facts_produce_identical_digests_and_changed_facts_do_not() {
    let fixture = Fixture::new();
    let decision = decision(&fixture);
    let first = authority_decision_evidence(&decision).expect("first evidence");
    let second = authority_decision_evidence(&decision).expect("second evidence");
    assert_eq!(
        first.canonical_request_digest,
        second.canonical_request_digest
    );
    assert_eq!(first.decision_digest, second.decision_digest);

    let mut changed_scope = decision.clone();
    changed_scope.request.scope.budget.max_actions_per_tick = Some(2);
    let changed_scope = authority_decision_evidence(&changed_scope).expect("scope evidence");
    assert_ne!(
        first.canonical_request_digest,
        changed_scope.canonical_request_digest
    );
    assert_ne!(first.decision_digest, changed_scope.decision_digest);

    let mut changed_operation = decision.clone();
    changed_operation.request.operation = operation("different-operation");
    assert_ne!(
        first.decision_digest,
        authority_decision_evidence(&changed_operation)
            .expect("operation evidence")
            .decision_digest
    );

    let mut changed_reason = decision.clone();
    changed_reason.reasons = vec!["authority_scope_mismatch".to_string()];
    assert_ne!(
        first.decision_digest,
        authority_decision_evidence(&changed_reason)
            .expect("reason evidence")
            .decision_digest
    );

    let grant = grant_with(
        &fixture,
        fixture.grant_id.clone(),
        RAW_LOCAL_REVISION_TOKEN,
        5,
        2,
    );
    let revised_grant = grant_with(
        &fixture,
        fixture.grant_id.clone(),
        OTHER_VALIDATION_DIGEST,
        4,
        2,
    );
    let first_grant = grant_evidence(&grant, &decision).expect("grant evidence");
    let revised_grant = grant_evidence(&revised_grant, &decision).expect("revised evidence");
    assert_ne!(first_grant.revision_digest, revised_grant.revision_digest);
    let first = build_evidence(
        &decision,
        AuthorityEvidenceCompleteness::GrantEvaluation,
        vec![first_grant],
        None,
    )
    .expect("first grant decision evidence");
    let revised = build_evidence(
        &decision,
        AuthorityEvidenceCompleteness::GrantEvaluation,
        vec![revised_grant],
        None,
    )
    .expect("revised grant decision evidence");
    assert_ne!(first.decision_digest, revised.decision_digest);
}

#[test]
fn explanation_categories_cover_current_authority_reason_classes() {
    let cases = [
        ("capability_allowed", AuthorityExplanationCategory::Allowed),
        (
            "subject_mismatch",
            AuthorityExplanationCategory::IdentityValidation,
        ),
        (
            "missing_capability_grant",
            AuthorityExplanationCategory::IdentityValidation,
        ),
        (
            "authority_scope_mismatch",
            AuthorityExplanationCategory::Scope,
        ),
        (
            "authority_grant_revoked",
            AuthorityExplanationCategory::Revocation,
        ),
        (
            "scope_time_expired",
            AuthorityExplanationCategory::ExpiryTime,
        ),
        (
            "budget.max_actions_per_tick_exceeds_grant",
            AuthorityExplanationCategory::QuotaBudget,
        ),
        (
            "data_purpose_missing_for_operation",
            AuthorityExplanationCategory::DataUse,
        ),
        (
            "capability_conditional",
            AuthorityExplanationCategory::ObligationsGate,
        ),
        (
            "authority_cache_stale",
            AuthorityExplanationCategory::CacheFreshness,
        ),
        (
            "provider_constraint_unknown",
            AuthorityExplanationCategory::ProviderUnknown,
        ),
    ];
    for (reason, expected) in cases {
        assert_eq!(authority_reason_category(reason), expected, "{reason}");
    }
}

#[test]
fn restricted_and_redacted_evidence_never_serialize_sensitive_source_fields() {
    let fixture = Fixture::new();
    let decision = decision(&fixture);
    let grant = grant_with(&fixture, fixture.grant_id.clone(), VALIDATION_DIGEST, 5, 2);
    let evidence = build_evidence(
        &decision,
        AuthorityEvidenceCompleteness::GrantEvaluation,
        vec![grant_evidence(&grant, &decision).expect("grant evidence")],
        None,
    )
    .expect("evidence");
    let restricted_json = serde_json::to_string(&evidence).expect("restricted JSON");
    for forbidden in [
        SECRET_METADATA,
        SECRET_KEY_ID,
        SECRET_SIGNATURE,
        SECRET_OBLIGATION_DESCRIPTION,
        SECRET_OBLIGATION_PARAMETER,
        RAW_LOCAL_REVISION_TOKEN,
        SENSITIVE_OPERATION_NAME,
    ] {
        assert!(!restricted_json.contains(forbidden), "leaked {forbidden}");
    }
    assert!(evidence.evaluated_grants[0]
        .validation_digest
        .starts_with("blake3:"));
    assert!(restricted_json.contains(&fixture.grant_id.to_string()));

    let redacted = evidence.redacted().expect("redacted evidence");
    let redacted_json = serde_json::to_string(&redacted).expect("redacted JSON");
    assert!(!redacted_json.contains(SENSITIVE_OPERATION_NAME));
    assert!(!redacted_json.contains(&fixture.tenant_id.to_string()));
    assert!(!redacted_json.contains(&fixture.agent_id.to_string()));
    assert!(!redacted_json.contains(&fixture.run_id.to_string()));
    assert!(!redacted_json.contains(SECRET_METADATA));
    assert!(!redacted_json.contains(SECRET_OBLIGATION_DESCRIPTION));
    assert_eq!(redacted.decision_id, evidence.decision_id);
    assert_eq!(redacted.status, evidence.status);
    assert_eq!(redacted.reason_codes, evidence.reason_codes);
    assert_eq!(redacted.decision_digest, evidence.decision_digest);
}

#[test]
fn completeness_never_fabricates_grant_cache_policy_or_data_use_facts() {
    let fixture = Fixture::new();
    let decision = decision(&fixture);
    let decision_only = authority_decision_evidence(&decision).expect("decision evidence");
    assert_eq!(
        decision_only.completeness,
        AuthorityEvidenceCompleteness::DecisionOnly
    );
    assert!(decision_only.evaluated_grants.is_empty());
    assert!(decision_only.cached_evaluation.is_none());
    assert!(decision_only
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::EvaluatedGrants));
    assert!(decision_only
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::CacheFreshness));
    assert!(decision_only
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::PolicyRefs));
    assert!(decision_only
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::DataUseRefs));

    let grant = grant_with(&fixture, fixture.grant_id.clone(), VALIDATION_DIGEST, 5, 2);
    let evaluated = evaluate_capability_request_with_evidence(
        std::slice::from_ref(&grant),
        &request(&fixture),
        fixture.now,
    )
    .expect("grant evaluation evidence");
    let direct = evaluate_capability_request(
        std::slice::from_ref(&grant),
        &request(&fixture),
        fixture.now,
    );
    assert_eq!(
        evaluated.evidence.completeness,
        AuthorityEvidenceCompleteness::GrantEvaluation
    );
    assert_eq!(evaluated.evidence.evaluated_grants.len(), 1);
    assert!(evaluated.evidence.cached_evaluation.is_none());
    assert!(!evaluated
        .evidence
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::EvaluatedGrants));
    assert_eq!(
        evaluated.decision.status,
        AuthorityDecisionStatus::Conditional
    );
    assert_eq!(evaluated.decision.status, direct.status);
    assert_eq!(evaluated.decision.reasons, direct.reasons);
    assert_eq!(
        evaluated.decision.matched_grant_ids,
        direct.matched_grant_ids
    );
    assert_eq!(evaluated.decision.obligations, direct.obligations);
    assert_eq!(evaluated.decision.request, direct.request);
}

#[test]
fn cached_wrapper_records_fresh_stale_future_expired_and_missing_facts() {
    let fixture = Fixture::new();
    let ids = [
        "60000000-0000-0000-0000-000000000011",
        "60000000-0000-0000-0000-000000000012",
        "60000000-0000-0000-0000-000000000013",
        "60000000-0000-0000-0000-000000000014",
    ]
    .map(|value| CapabilityGrantId::parse(value).expect("grant ID"));
    let mut cache = AuthorityGrantCache::new();
    cache
        .insert_validated(
            grant_with(&fixture, ids[0].clone(), VALIDATION_DIGEST, 5, 3),
            fixture.now - Duration::minutes(1),
            fixture.now + Duration::hours(1),
        )
        .expect("fresh cache");
    cache
        .insert_validated(
            grant_with(&fixture, ids[1].clone(), VALIDATION_DIGEST, 5, 3),
            fixture.now - Duration::minutes(30),
            fixture.now + Duration::hours(1),
        )
        .expect("stale cache");
    cache
        .insert_validated(
            grant_with(&fixture, ids[2].clone(), VALIDATION_DIGEST, 5, 3),
            fixture.now + Duration::minutes(1),
            fixture.now + Duration::hours(1),
        )
        .expect("future cache");
    cache
        .insert_validated(
            grant_with(&fixture, ids[3].clone(), VALIDATION_DIGEST, 5, 3),
            fixture.now - Duration::minutes(30),
            fixture.now - Duration::minutes(1),
        )
        .expect("expired cache");
    let snapshot = RevocationSnapshot::with_max_age(Vec::new(), fixture.now, Duration::minutes(30))
        .expect("snapshot");
    let policy = OfflineAuthorityPolicy::connected(Duration::minutes(10)).expect("policy");
    let evaluated = evaluate_cached_capability_request_with_evidence(
        &cache,
        Some(&snapshot),
        &policy,
        &request(&fixture),
        fixture.now,
    )
    .expect("cached evidence");
    let direct = evaluate_cached_capability_request(
        &cache,
        Some(&snapshot),
        &policy,
        &request(&fixture),
        fixture.now,
    );
    assert_eq!(evaluated.decision.status, direct.status);
    assert_eq!(evaluated.decision.reasons, direct.reasons);
    assert_eq!(
        evaluated.decision.matched_grant_ids,
        direct.matched_grant_ids
    );
    let facts = evaluated.evidence.cached_evaluation.expect("cache facts");
    assert_eq!(
        evaluated.evidence.completeness,
        AuthorityEvidenceCompleteness::CachedEvaluation
    );
    assert!(!facts.cache_missing);
    let statuses = facts
        .cache_entries
        .iter()
        .map(|entry| entry.freshness)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        statuses,
        BTreeSet::from([
            AuthorityFreshnessStatus::Fresh,
            AuthorityFreshnessStatus::Stale,
            AuthorityFreshnessStatus::FutureDated,
            AuthorityFreshnessStatus::Expired,
        ])
    );
    assert_eq!(
        facts.revocation_snapshot.freshness,
        AuthorityFreshnessStatus::Fresh
    );

    let missing = evaluate_cached_capability_request_with_evidence(
        &AuthorityGrantCache::new(),
        None,
        &policy,
        &request(&fixture),
        fixture.now,
    )
    .expect("missing evidence");
    let missing = missing
        .evidence
        .cached_evaluation
        .expect("missing cache facts");
    assert!(missing.cache_missing);
    assert!(missing.cache_entries.is_empty());
    assert_eq!(
        missing.revocation_snapshot.freshness,
        AuthorityFreshnessStatus::Missing
    );
}

#[test]
fn cached_wrapper_records_stale_and_future_snapshots_without_authorizing_them() {
    let fixture = Fixture::new();
    let mut cache = AuthorityGrantCache::new();
    cache
        .insert_validated(
            grant_with(&fixture, fixture.grant_id.clone(), VALIDATION_DIGEST, 5, 3),
            fixture.now,
            fixture.now + Duration::hours(1),
        )
        .expect("cache");
    let policy = OfflineAuthorityPolicy::connected(Duration::minutes(10)).expect("policy");
    for (snapshot, expected_status, expected_reason) in [
        (
            RevocationSnapshot::try_new(Vec::new(), fixture.now - Duration::hours(1), fixture.now)
                .expect("stale snapshot"),
            AuthorityFreshnessStatus::Stale,
            "authority_revocation_snapshot_stale",
        ),
        (
            RevocationSnapshot::try_new(
                Vec::new(),
                fixture.now + Duration::minutes(1),
                fixture.now + Duration::hours(1),
            )
            .expect("future snapshot"),
            AuthorityFreshnessStatus::FutureDated,
            "authority_revocation_snapshot_future_dated",
        ),
    ] {
        let evaluated = evaluate_cached_capability_request_with_evidence(
            &cache,
            Some(&snapshot),
            &policy,
            &request(&fixture),
            fixture.now,
        )
        .expect("cached evidence");
        assert_eq!(evaluated.decision.status, AuthorityDecisionStatus::Denied);
        assert!(evaluated
            .decision
            .reasons
            .iter()
            .any(|reason| reason == expected_reason));
        assert_eq!(
            evaluated
                .evidence
                .cached_evaluation
                .expect("freshness facts")
                .revocation_snapshot
                .freshness,
            expected_status
        );
    }
}

#[test]
fn comparison_is_inspect_only_and_reports_status_reason_and_digest_changes() {
    let fixture = Fixture::new();
    let historical = authority_decision_evidence(&decision(&fixture)).expect("historical");
    let mut current_decision = decision(&fixture);
    current_decision.status = AuthorityDecisionStatus::Denied;
    current_decision.reasons = vec!["authority_grant_revoked".to_string()];
    let current = authority_decision_evidence(&current_decision).expect("current");
    let comparison = compare_authority_evidence(
        AuthorityEvidenceComparisonLabel::Historical,
        &historical,
        AuthorityEvidenceComparisonLabel::Current,
        &current,
    );
    assert_eq!(
        comparison.left_label,
        AuthorityEvidenceComparisonLabel::Historical
    );
    assert_eq!(
        comparison.right_label,
        AuthorityEvidenceComparisonLabel::Current
    );
    assert!(comparison.status_changed);
    assert!(!comparison.request_digest_changed);
    assert!(comparison.decision_digest_changed);
    assert_eq!(
        comparison.removed_reason_codes,
        vec!["capability_conditional"]
    );
    assert_eq!(
        comparison.added_reason_codes,
        vec!["authority_grant_revoked"]
    );
}

#[test]
fn evidence_required_wrapper_returns_unavailable_instead_of_fabricating() {
    let fixture = Fixture::new();
    let grant = grant_with(&fixture, fixture.grant_id.clone(), VALIDATION_DIGEST, 5, 2);
    let mut raw_grant = grant.grant().clone();
    raw_grant.validation = None;
    let missing_validation_grant = unchecked_validated_grant_for_tests(raw_grant);
    let error = evaluate_capability_request_with_evidence(
        &[missing_validation_grant],
        &request(&fixture),
        fixture.now,
    )
    .expect_err("invalid validation digest must make evidence unavailable");
    assert_eq!(
        error.reason_code(),
        "authority_evidence_grant_validation_digest_unavailable"
    );

    let mut invalid_decision = decision(&fixture);
    invalid_decision.decision_id =
        AuthorityDecisionId::parse("00000000-0000-0000-0000-000000000000")
            .expect("nil decision ID");
    assert_eq!(
        authority_decision_evidence(&invalid_decision)
            .expect_err("nil decision must fail")
            .reason_code(),
        "authority_evidence_decision_identity_invalid"
    );
}
