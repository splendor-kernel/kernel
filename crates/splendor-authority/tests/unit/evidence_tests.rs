use super::*;
use crate::capability::unchecked_validated_grant_for_tests;
use splendor_types::{
    AgentId, AuthorityBudgetScope, AuthorityDecision, AuthorityObligation, AuthorityObligationId,
    AuthorityObligationKind, CapabilityGrant, CapabilityGrantValidation, CapabilityRequest,
    CapabilityScope, DataPurpose, RevocationStatus, RunId, TenantId,
    AUTHORITY_DECISION_SCHEMA_VERSION, AUTHORITY_OBLIGATION_SCHEMA_VERSION,
    AUTHORITY_OPERATION_SCHEMA_VERSION, CAPABILITY_GRANT_SCHEMA_VERSION,
    CAPABILITY_REQUEST_SCHEMA_VERSION,
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
    assert_eq!(first.decision_digest, second.decision_digest);

    let mut changed_scope = decision.clone();
    changed_scope.request.scope.budget.max_actions_per_tick = Some(2);
    let changed_scope = authority_decision_evidence(&changed_scope).expect("scope evidence");
    assert_eq!(first.decision_digest, changed_scope.decision_digest);

    let mut changed_operation = decision.clone();
    changed_operation.request.operation = operation("different-operation");
    assert_eq!(
        first.decision_digest,
        authority_decision_evidence(&changed_operation)
            .expect("protected operation evidence")
            .decision_digest
    );

    changed_operation.request.operation.namespace = AuthorityOperationNamespace::Data;
    changed_operation.request.operation.resource_kind = AuthorityResourceKind::Data;
    changed_operation.request.operation.verb = AuthorityVerb::Read;
    changed_operation.request.operation.name = None;
    assert_ne!(
        first.decision_digest,
        authority_decision_evidence(&changed_operation)
            .expect("operation evidence")
            .decision_digest
    );

    let mut invalid_schema = decision.clone();
    invalid_schema.schema_version = "secret-bearing-decision-schema".to_string();
    let invalid_schema = authority_decision_evidence(&invalid_schema).expect("schema evidence");
    assert_eq!(
        invalid_schema.decision_schema,
        AuthorityDecisionSchemaEvidence::Invalid
    );
    assert_ne!(first.decision_digest, invalid_schema.decision_digest);

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
    assert_eq!(first.decision_digest, revised.decision_digest);
    assert!(
        compare_authority_evidence(
            AuthorityEvidenceComparisonLabel::Historical,
            &first,
            AuthorityEvidenceComparisonLabel::Current,
            &revised,
        )
        .grant_revision_changed
    );
}

#[test]
fn explanation_categories_cover_current_authority_reason_classes() {
    let cases = [
        (
            "capability_allowed",
            "capability_allowed",
            AuthorityExplanationCategory::Allowed,
        ),
        (
            "subject_mismatch",
            "subject_mismatch",
            AuthorityExplanationCategory::IdentityValidation,
        ),
        (
            "missing_capability_grant",
            "missing_capability_grant",
            AuthorityExplanationCategory::IdentityValidation,
        ),
        (
            "authority_scope_mismatch",
            "authority_scope_mismatch",
            AuthorityExplanationCategory::Scope,
        ),
        (
            "authority_grant_revoked",
            "authority_grant_revoked",
            AuthorityExplanationCategory::Revocation,
        ),
        (
            "invalid_scope:capability_request.scope.time:scope_time_expired",
            "invalid_scope",
            AuthorityExplanationCategory::ExpiryTime,
        ),
        (
            "budget.max_actions_per_tick_exceeds_grant",
            "budget_scope_mismatch",
            AuthorityExplanationCategory::QuotaBudget,
        ),
        (
            "data_purpose_missing_for_operation",
            "data_use_scope_mismatch",
            AuthorityExplanationCategory::DataUse,
        ),
        (
            "capability_conditional",
            "capability_conditional",
            AuthorityExplanationCategory::ObligationsGate,
        ),
        (
            "authority_cache_stale",
            "authority_cache_stale",
            AuthorityExplanationCategory::CacheFreshness,
        ),
        (
            "authority_offline_high_risk_needs_intervention",
            "authority_offline_high_risk_needs_intervention",
            AuthorityExplanationCategory::ObligationsGate,
        ),
        (
            "invalid_operation:operation_tuple_not_allowed",
            "invalid_operation",
            AuthorityExplanationCategory::IdentityValidation,
        ),
        (
            "invalid_scope:tenant_ids:nil_identity",
            "invalid_scope",
            AuthorityExplanationCategory::IdentityValidation,
        ),
        (
            "capability_denied",
            "capability_denied",
            AuthorityExplanationCategory::ProviderUnknown,
        ),
        (
            "metadata_reserved_authority_key",
            "metadata_reserved_authority_key",
            AuthorityExplanationCategory::IdentityValidation,
        ),
        (
            "grant_not_yet_valid",
            "grant_not_yet_valid",
            AuthorityExplanationCategory::ExpiryTime,
        ),
        (
            "expired_grant",
            "expired_grant",
            AuthorityExplanationCategory::ExpiryTime,
        ),
        (
            "operation_not_granted",
            "operation_not_granted",
            AuthorityExplanationCategory::Scope,
        ),
        (
            "authority_cache_missing",
            "authority_cache_missing",
            AuthorityExplanationCategory::CacheFreshness,
        ),
        (
            "authority_cache_expired",
            "authority_cache_expired",
            AuthorityExplanationCategory::CacheFreshness,
        ),
        (
            "authority_cache_future_dated",
            "authority_cache_future_dated",
            AuthorityExplanationCategory::CacheFreshness,
        ),
        (
            "authority_revocation_snapshot_missing",
            "authority_revocation_snapshot_missing",
            AuthorityExplanationCategory::CacheFreshness,
        ),
        (
            "authority_revocation_snapshot_stale",
            "authority_revocation_snapshot_stale",
            AuthorityExplanationCategory::CacheFreshness,
        ),
        (
            "authority_revocation_snapshot_future_dated",
            "authority_revocation_snapshot_future_dated",
            AuthorityExplanationCategory::CacheFreshness,
        ),
        (
            "authority_revocation_ref_mismatch",
            "authority_revocation_ref_mismatch",
            AuthorityExplanationCategory::Revocation,
        ),
        (
            "authority_offline_ttl_expired",
            "authority_offline_ttl_expired",
            AuthorityExplanationCategory::CacheFreshness,
        ),
        (
            "authority_offline_unsupported_operation",
            "authority_offline_unsupported_operation",
            AuthorityExplanationCategory::ObligationsGate,
        ),
        (
            "authority_offline_high_risk_denied",
            "authority_offline_high_risk_denied",
            AuthorityExplanationCategory::ObligationsGate,
        ),
        (
            "invalid_schema:capability_request.schema_version",
            "invalid_schema",
            AuthorityExplanationCategory::IdentityValidation,
        ),
        (
            "invalid_identity:issuer",
            "invalid_identity",
            AuthorityExplanationCategory::IdentityValidation,
        ),
        (
            "invalid_token:grant_validation.signature",
            "invalid_token",
            AuthorityExplanationCategory::IdentityValidation,
        ),
        (
            "invalid_validation:missing_grant_validation",
            "invalid_validation",
            AuthorityExplanationCategory::IdentityValidation,
        ),
        (
            "invalid_scope:capability_request.scope:missing_audience_binding",
            "invalid_scope",
            AuthorityExplanationCategory::Scope,
        ),
        (
            "invalid_scope:capability_request.scope:data_purpose_missing_for_operation",
            "invalid_scope",
            AuthorityExplanationCategory::DataUse,
        ),
        (
            "empty_intersection:tenant_ids",
            "scope_not_granted",
            AuthorityExplanationCategory::Scope,
        ),
        (
            "narrowing_violation:operations:child_operation_not_in_parent",
            "scope_not_granted",
            AuthorityExplanationCategory::Scope,
        ),
        (
            "time.expires_at_exceeds_grant",
            "time_scope_mismatch",
            AuthorityExplanationCategory::ExpiryTime,
        ),
        (
            "data_purposes_not_granted",
            "data_use_scope_mismatch",
            AuthorityExplanationCategory::DataUse,
        ),
        (
            "tenant_ids_not_granted",
            "scope_not_granted",
            AuthorityExplanationCategory::Scope,
        ),
        (
            "provider_constraint_unknown\r\nsecret\x1b[31m",
            "authority_reason_unknown",
            AuthorityExplanationCategory::ProviderUnknown,
        ),
        (
            "secret_not_granted",
            "authority_reason_unknown",
            AuthorityExplanationCategory::ProviderUnknown,
        ),
        (
            "invalid_schema:secret-bearing-schema",
            "authority_reason_unknown",
            AuthorityExplanationCategory::ProviderUnknown,
        ),
    ];
    for (reason, expected_code, expected_category) in cases {
        assert_eq!(
            normalize_authority_reason_code(reason),
            expected_code,
            "{reason}"
        );
        assert_eq!(
            authority_reason_category(reason),
            expected_category,
            "{reason}"
        );
    }
    for field in [
        "authority_operation.resource_schema_version",
        "authority_operation.name",
        "driver_operations.driver",
        "driver_operations.operation",
        "driver_operations.schema_version",
        "audiences",
        "network.egress_schemes",
        "network.egress_hosts",
        "locality.regions",
        "locality.zones",
        "locality.data_localities",
        "obligation.description",
    ] {
        let reason = format!("invalid_token:{field}");
        assert_eq!(normalize_authority_reason_code(&reason), "invalid_token");
        assert_eq!(
            authority_reason_category(&reason),
            AuthorityExplanationCategory::IdentityValidation
        );
    }
    for cause in [
        "network_egress_scope_required",
        "device_scope_required",
        "artifact_scope_required",
        "state_partition_scope_required",
        "driver_operation_scope_required",
        "workload_or_run_scope_required",
        "agent_scope_required",
        "not_before_must_precede_expires_at",
    ] {
        let dimension = if cause == "not_before_must_precede_expires_at" {
            "time"
        } else {
            "capability_request.scope"
        };
        let reason = format!("invalid_scope:{dimension}:{cause}");
        assert_eq!(normalize_authority_reason_code(&reason), "invalid_scope");
        assert_eq!(
            authority_reason_category(&reason),
            if dimension == "time" {
                AuthorityExplanationCategory::ExpiryTime
            } else {
                AuthorityExplanationCategory::Scope
            }
        );
    }
}

#[test]
fn hostile_reasons_and_caller_schema_strings_are_never_serialized() {
    let fixture = Fixture::new();
    let oversized_reason = format!("oversized-secret:{}", "x".repeat(8_192));
    let hostile_values = [
        "reason-secret-do-not-export".to_string(),
        "capability_allowed\r\nforged-header: allow".to_string(),
        "\u{1b}[31mcapability_allowed\u{7}control-secret".to_string(),
        oversized_reason,
        "decision-schema-secret".to_string(),
        "request-schema-secret".to_string(),
        "operation-schema-secret".to_string(),
        "resource-schema-secret".to_string(),
        "grant-schema-secret".to_string(),
        "scope-schema-secret".to_string(),
        "obligation-schema-secret".to_string(),
    ];

    let mut decision = decision(&fixture);
    decision.reasons = hostile_values[..4].to_vec();
    decision.schema_version = hostile_values[4].clone();
    decision.request.schema_version = hostile_values[5].clone();
    decision.request.operation.schema_version = hostile_values[6].clone();
    decision.request.operation.resource_schema_version = Some(hostile_values[7].clone());
    decision.obligations[0].schema_version = hostile_values[10].clone();

    let mut raw_grant = grant_with(&fixture, fixture.grant_id.clone(), VALIDATION_DIGEST, 5, 2)
        .grant()
        .clone();
    raw_grant.schema_version = hostile_values[8].clone();
    raw_grant.scope.schema_version = hostile_values[9].clone();
    raw_grant.operations[0].schema_version = hostile_values[6].clone();
    raw_grant.operations[0].resource_schema_version = Some(hostile_values[7].clone());
    raw_grant.obligations[0].schema_version = hostile_values[10].clone();
    let grant = unchecked_validated_grant_for_tests(raw_grant);
    let evidence = build_evidence(
        &decision,
        AuthorityEvidenceCompleteness::GrantEvaluation,
        vec![grant_evidence(&grant, &decision).expect("grant evidence")],
        None,
    )
    .expect("hostile input evidence");

    let encoded = serde_json::to_string(&evidence).expect("evidence JSON");
    for hostile in &hostile_values {
        assert!(
            !encoded.contains(hostile),
            "leaked hostile input: {hostile}"
        );
    }
    assert_eq!(
        evidence.reason_codes,
        vec!["authority_reason_unknown".to_string()]
    );
    assert_eq!(
        evidence.decision_schema,
        AuthorityDecisionSchemaEvidence::Invalid
    );
    assert!(!evidence.operation.source_schema_valid);
    assert!(evidence.operation.resource_schema_withheld);
}

#[test]
fn actual_evaluator_reasons_map_to_expected_explanation_categories() {
    fn categories(decision: &AuthorityDecision) -> BTreeSet<AuthorityExplanationCategory> {
        decision
            .reasons
            .iter()
            .map(|reason| authority_reason_category(reason))
            .collect()
    }

    let fixture = Fixture::new();
    let base_grant = grant_with(&fixture, fixture.grant_id.clone(), VALIDATION_DIGEST, 5, 2);

    let conditional = evaluate_capability_request(
        std::slice::from_ref(&base_grant),
        &request(&fixture),
        fixture.now,
    );
    assert_eq!(
        categories(&conditional),
        BTreeSet::from([AuthorityExplanationCategory::ObligationsGate])
    );

    let mut allowed_raw = base_grant.grant().clone();
    allowed_raw.obligations.clear();
    let allowed = evaluate_capability_request(
        &[unchecked_validated_grant_for_tests(allowed_raw)],
        &request(&fixture),
        fixture.now,
    );
    assert_eq!(
        categories(&allowed),
        BTreeSet::from([AuthorityExplanationCategory::Allowed])
    );

    let mut invalid_request = request(&fixture);
    invalid_request.schema_version = "unsupported".to_string();
    let invalid = evaluate_capability_request(
        std::slice::from_ref(&base_grant),
        &invalid_request,
        fixture.now,
    );
    assert!(categories(&invalid).contains(&AuthorityExplanationCategory::IdentityValidation));

    let mut wrong_scope = request(&fixture);
    wrong_scope.scope.tenant_ids = Some(vec![TenantId::new()]);
    let wrong_scope =
        evaluate_capability_request(std::slice::from_ref(&base_grant), &wrong_scope, fixture.now);
    assert!(categories(&wrong_scope).contains(&AuthorityExplanationCategory::Scope));

    let mut over_budget = request(&fixture);
    over_budget.scope.budget.max_actions_per_tick = Some(6);
    let over_budget =
        evaluate_capability_request(std::slice::from_ref(&base_grant), &over_budget, fixture.now);
    assert!(categories(&over_budget).contains(&AuthorityExplanationCategory::QuotaBudget));

    let mut expired_raw = base_grant.grant().clone();
    expired_raw.expires_at = fixture.now;
    let expired = evaluate_capability_request(
        &[unchecked_validated_grant_for_tests(expired_raw)],
        &request(&fixture),
        fixture.now,
    );
    assert!(categories(&expired).contains(&AuthorityExplanationCategory::ExpiryTime));

    let mut revoked_raw = base_grant.grant().clone();
    revoked_raw.revocation = RevocationStatus::Revoked {
        reason: "restricted-provider-reason".to_string(),
    };
    let revoked = evaluate_capability_request(
        &[unchecked_validated_grant_for_tests(revoked_raw)],
        &request(&fixture),
        fixture.now,
    );
    assert!(categories(&revoked).contains(&AuthorityExplanationCategory::Revocation));

    let data_operation = AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Data,
        resource_kind: AuthorityResourceKind::Data,
        verb: AuthorityVerb::Read,
        name: None,
        resource_schema_version: None,
    };
    let mut data_raw = base_grant.grant().clone();
    data_raw.operations = vec![data_operation.clone()];
    data_raw.scope.data_purposes = Some(vec![DataPurpose::Read]);
    let mut data_request = request(&fixture);
    data_request.operation = data_operation;
    data_request.scope.data_purposes = Some(vec![DataPurpose::EvaluationUse]);
    let data_denial = evaluate_capability_request(
        &[unchecked_validated_grant_for_tests(data_raw)],
        &data_request,
        fixture.now,
    );
    assert!(categories(&data_denial).contains(&AuthorityExplanationCategory::DataUse));

    let cached_denial = evaluate_cached_capability_request(
        &AuthorityGrantCache::new(),
        None,
        &OfflineAuthorityPolicy::connected(Duration::hours(1)).expect("policy"),
        &request(&fixture),
        fixture.now,
    );
    assert_eq!(
        categories(&cached_denial),
        BTreeSet::from([AuthorityExplanationCategory::CacheFreshness])
    );
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
        VALIDATION_DIGEST,
    ] {
        assert!(!restricted_json.contains(forbidden), "leaked {forbidden}");
    }
    assert!(evidence.supplied_grants[0]
        .validation_token_digest
        .starts_with("blake3:"));
    assert_ne!(
        evidence.supplied_grants[0].validation_token_digest,
        VALIDATION_DIGEST
    );
    assert!(restricted_json.contains(&fixture.grant_id.to_string()));

    let redacted = evidence.redacted().expect("redacted evidence");
    let redacted_json = serde_json::to_string(&redacted).expect("redacted JSON");
    assert!(!redacted_json.contains(SENSITIVE_OPERATION_NAME));
    assert!(!redacted_json.contains(&fixture.tenant_id.to_string()));
    assert!(!redacted_json.contains(&fixture.agent_id.to_string()));
    assert!(!redacted_json.contains(&fixture.run_id.to_string()));
    assert!(!redacted_json.contains(SECRET_METADATA));
    assert!(!redacted_json.contains(SECRET_OBLIGATION_DESCRIPTION));
    assert!(!redacted_json.contains(&evidence.supplied_grants[0].revision_digest));
    assert!(!redacted_json.contains(&evidence.supplied_grants[0].validation_token_digest));
    assert_eq!(redacted.decision_id, evidence.decision_id);
    assert_eq!(redacted.status, evidence.status);
    assert_eq!(redacted.reason_codes, evidence.reason_codes);
    assert_eq!(redacted.decision_digest, evidence.decision_digest);
}

#[test]
fn revocation_ref_changes_restricted_revision_digest_without_exporting_the_ref() {
    let fixture = Fixture::new();
    let decision = decision(&fixture);
    let first = grant_with(&fixture, fixture.grant_id.clone(), VALIDATION_DIGEST, 5, 2);
    let mut changed_raw = first.grant().clone();
    let restricted_ref = "revocation:tenant-secret-reference";
    changed_raw.revocation_ref = Some(restricted_ref.to_string());
    let changed = unchecked_validated_grant_for_tests(changed_raw);

    let first = grant_evidence(&first, &decision).expect("first revision");
    let changed = grant_evidence(&changed, &decision).expect("changed revision");
    assert_ne!(first.revision_digest, changed.revision_digest);
    assert!(!serde_json::to_string(&changed)
        .expect("grant evidence JSON")
        .contains(restricted_ref));
}

#[test]
fn digest_domains_and_set_or_hash_case_canonicalization_are_deterministic() {
    assert_ne!(
        domain_hash_bytes("validation-token-v1", b"identical-bytes"),
        domain_hash_bytes("grant-revision-v1", b"identical-bytes")
    );

    let fixture = Fixture::new();
    let decision = decision(&fixture);
    let mut left = grant_with(&fixture, fixture.grant_id.clone(), VALIDATION_DIGEST, 5, 2)
        .grant()
        .clone();
    let parent_a =
        CapabilityGrantId::parse("61000000-0000-0000-0000-000000000001").expect("parent A");
    let parent_b =
        CapabilityGrantId::parse("62000000-0000-0000-0000-000000000001").expect("parent B");
    left.parent_grant_ids = vec![parent_b.clone(), parent_a.clone(), parent_b.clone()];
    left.scope.audiences = Some(vec![
        "daemon:z".to_string(),
        "daemon:a".to_string(),
        "daemon:z".to_string(),
    ]);
    left.scope.network.egress_hosts = Some(vec![
        "z.example".to_string(),
        "a.example".to_string(),
        "z.example".to_string(),
    ]);
    left.operations.push(AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Data,
        resource_kind: AuthorityResourceKind::Data,
        verb: AuthorityVerb::Read,
        name: None,
        resource_schema_version: None,
    });
    let uppercase_hash = format!("BLAKE3:{}", "AB".repeat(32));
    left.validation.as_mut().expect("validation").digest = uppercase_hash.clone();

    let mut right = left.clone();
    right.parent_grant_ids = vec![parent_a, parent_b];
    right.scope.audiences.as_mut().expect("audiences").reverse();
    right
        .scope
        .network
        .egress_hosts
        .as_mut()
        .expect("hosts")
        .reverse();
    right.operations.reverse();
    right.validation.as_mut().expect("validation").digest = format!("blake3:{}", "ab".repeat(32));

    let left = grant_evidence(&unchecked_validated_grant_for_tests(left), &decision)
        .expect("left evidence");
    let right = grant_evidence(&unchecked_validated_grant_for_tests(right), &decision)
        .expect("right evidence");
    assert_eq!(left.validation_token_digest, right.validation_token_digest);
    assert_eq!(left.revision_digest, right.revision_digest);
    let encoded = serde_json::to_string(&left).expect("grant evidence JSON");
    assert!(!encoded.contains(&uppercase_hash));
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
    assert!(decision_only.supplied_grants.is_empty());
    assert!(decision_only.cached_evaluation.is_none());
    assert!(decision_only
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::SuppliedGrants));
    assert!(decision_only
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::CacheFreshness));
    assert!(decision_only
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::PolicyRefs));
    assert!(decision_only
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::DataUseRefs));
    assert!(decision_only
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::ExactRequestBinding));
    assert!(decision_only
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::ProtectedOperationBinding));

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
    assert_eq!(evaluated.evidence.supplied_grants.len(), 1);
    assert!(evaluated.evidence.cached_evaluation.is_none());
    assert!(!evaluated
        .evidence
        .missing_facts
        .contains(&AuthorityEvidenceMissingFact::SuppliedGrants));
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
        .map(|entry| entry.effective_freshness)
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
fn disconnected_offline_ttl_expiry_is_separate_and_effectively_non_fresh() {
    let fixture = Fixture::new();
    let mut cache = AuthorityGrantCache::new();
    cache
        .insert_validated(
            grant_with(&fixture, fixture.grant_id.clone(), VALIDATION_DIGEST, 5, 3),
            fixture.now - Duration::minutes(10),
            fixture.now + Duration::hours(1),
        )
        .expect("cache");
    let snapshot = RevocationSnapshot::with_max_age(Vec::new(), fixture.now, Duration::hours(1))
        .expect("snapshot");
    let policy = OfflineAuthorityPolicy::disconnected(
        Duration::hours(1),
        Duration::minutes(5),
        Vec::new(),
        crate::AuthorityOfflineHighRiskBehavior::Deny,
    )
    .expect("disconnected policy");

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
        .contains(&"authority_offline_ttl_expired".to_string()));
    let entry = evaluated
        .evidence
        .cached_evaluation
        .expect("cached facts")
        .cache_entries
        .into_iter()
        .next()
        .expect("cache entry");
    assert_eq!(entry.cache_freshness, AuthorityFreshnessStatus::Fresh);
    assert_eq!(
        entry.offline_ttl_freshness,
        Some(AuthorityFreshnessStatus::Expired)
    );
    assert_eq!(entry.effective_freshness, AuthorityFreshnessStatus::Expired);
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
    assert!(comparison.decision_digest_changed);
    assert!(!comparison.grant_revision_changed);
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
