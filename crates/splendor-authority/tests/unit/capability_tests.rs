use super::*;
use splendor_types::{
    AuthorityObligationId, AuthorityObligationKind, WorkOrderId, WorkOrderPlacement,
};

const DIGEST: &str = "blake3:1111111111111111111111111111111111111111111111111111111111111111";

fn validation() -> CapabilityGrantValidation {
    CapabilityGrantValidation {
        validation_kind: CapabilityGrantValidationKind::LocallyValidated,
        algorithm: "local-test-v1".to_string(),
        key_id: None,
        digest: DIGEST.to_string(),
        signature: None,
    }
}

fn base_scope(tenant_id: TenantId, agent_id: AgentId, run_id: RunId) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![tenant_id]),
        agent_ids: Some(vec![agent_id]),
        run_ids: Some(vec![run_id]),
        audiences: Some(vec!["daemon:local".to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(5),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn grant(
    issuer: PrincipalId,
    subject: PrincipalId,
    operation: AuthorityOperation,
    scope: CapabilityScope,
    now: OffsetDateTime,
) -> CapabilityGrant {
    CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: CapabilityGrantId::new(),
        issuer,
        subject,
        parent_grant_ids: Vec::new(),
        operations: vec![operation],
        scope,
        not_before: now - time::Duration::minutes(1),
        expires_at: now + time::Duration::minutes(30),
        revocation_ref: Some("revocation:local".to_string()),
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth: 1,
        validation: Some(validation()),
        metadata: Default::default(),
    }
}

fn capability_request(
    subject: PrincipalId,
    operation: AuthorityOperation,
    mut scope: CapabilityScope,
    now: OffsetDateTime,
) -> CapabilityRequest {
    scope.budget.max_actions_per_tick = Some(1);
    CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject,
        operation,
        scope,
        requested_at: now,
        metadata: Default::default(),
    }
}

fn data_operation(verb: AuthorityVerb) -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Data,
        resource_kind: AuthorityResourceKind::Data,
        verb,
        name: None,
        resource_schema_version: Some("splendor.data_use.v1".to_string()),
    }
}

fn option_subset<T: PartialEq>(subset: &Option<Vec<T>>, superset: &Option<Vec<T>>) -> bool {
    match (subset, superset) {
        (Some(subset), Some(superset)) => subset
            .iter()
            .all(|value| superset.iter().any(|candidate| candidate == value)),
        (None, _) => true,
        (Some(_), None) => false,
    }
}

fn remove_agent_constraint(candidate: &mut CapabilityGrant) {
    candidate.scope.agent_ids = None;
}

fn broaden_agent_constraint(candidate: &mut CapabilityGrant) {
    candidate
        .scope
        .agent_ids
        .get_or_insert_with(Vec::new)
        .push(AgentId::new());
}

fn remove_data_purpose_constraint(candidate: &mut CapabilityGrant) {
    candidate.scope.data_purposes = None;
}

fn broaden_data_purpose_constraint(candidate: &mut CapabilityGrant) {
    candidate.scope.data_purposes = Some(vec![DataPurpose::Publication]);
}

fn remove_network_scheme_constraint(candidate: &mut CapabilityGrant) {
    candidate.scope.network.egress_schemes = None;
}

fn broaden_network_host_constraint(candidate: &mut CapabilityGrant) {
    candidate.scope.network.egress_hosts = Some(vec!["evil.example".to_string()]);
}

fn remove_locality_region_constraint(candidate: &mut CapabilityGrant) {
    candidate.scope.locality.regions = None;
}

fn broaden_locality_constraint(candidate: &mut CapabilityGrant) {
    candidate.scope.locality.data_localities = Some(vec!["us-east".to_string()]);
}

fn remove_scope_time_constraint(candidate: &mut CapabilityGrant) {
    candidate.scope.time.expires_at = None;
}

fn broaden_scope_time_constraint(candidate: &mut CapabilityGrant) {
    candidate.scope.time.expires_at = candidate
        .scope
        .time
        .expires_at
        .map(|expires_at| expires_at + time::Duration::minutes(30));
}

fn remove_budget_constraint(candidate: &mut CapabilityGrant) {
    candidate.scope.budget.max_http_requests_per_minute = None;
}

fn broaden_budget_constraint(candidate: &mut CapabilityGrant) {
    candidate.scope.budget.max_action_duration_ms = Some(2_000);
}

fn assert_narrowing_dimension(
    parent: &CapabilityGrant,
    candidate: &CapabilityGrant,
    expected_dimension: &'static str,
    case_name: &str,
) {
    match ensure_child_grant_narrows(parent, candidate) {
        Err(AuthorityEvaluationError::NarrowingViolation { dimension, .. }) => {
            assert_eq!(dimension, expected_dimension, "{case_name}")
        }
        other => panic!("{case_name}: expected narrowing violation, got {other:?}"),
    }
}

struct NarrowingCase {
    name: &'static str,
    dimension: &'static str,
    mutate: fn(&mut CapabilityGrant),
}

#[test]
fn authority_allows_matching_grant_and_returns_obligations() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let scope = base_scope(TenantId::new(), AgentId::new(), RunId::new());
    let mut grant = grant(
        issuer,
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    let obligation = AuthorityObligation {
        obligation_id: AuthorityObligationId::new(),
        kind: AuthorityObligationKind::EvidenceRequired,
        description: "record decision evidence".to_string(),
        parameters: Default::default(),
    };
    grant.obligations.push(obligation.clone());
    let request = capability_request(
        subject,
        gateway_action_operation("artifact.create"),
        scope,
        now,
    );

    let decision = evaluate_capability_request(&[grant.clone()], &request, now);

    assert_eq!(decision.status, AuthorityDecisionStatus::Allowed);
    assert_eq!(decision.reasons, vec!["capability_allowed"]);
    assert_eq!(decision.matched_grant_ids, vec![grant.grant_id]);
    assert_eq!(decision.obligations, vec![obligation]);
}

#[test]
fn authority_missing_expired_revoked_wrong_audience_and_unvalidated_grants_deny() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let scope = base_scope(TenantId::new(), AgentId::new(), RunId::new());
    let request = capability_request(
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );

    let missing = evaluate_capability_request(&[], &request, now);
    assert_eq!(missing.status, AuthorityDecisionStatus::Denied);
    assert!(missing
        .reasons
        .contains(&"missing_capability_grant".to_string()));

    let mut expired = grant(
        issuer.clone(),
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    expired.expires_at = now - time::Duration::seconds(1);
    let expired_decision = evaluate_capability_request(&[expired], &request, now);
    assert!(expired_decision
        .reasons
        .contains(&"expired_grant".to_string()));

    let mut revoked = grant(
        issuer.clone(),
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    revoked.revocation = RevocationStatus::Revoked {
        reason: "test_revocation".to_string(),
    };
    let revoked_decision = evaluate_capability_request(&[revoked], &request, now);
    assert!(revoked_decision
        .reasons
        .contains(&"revoked_grant".to_string()));

    let mut wrong_audience_scope = scope.clone();
    wrong_audience_scope.audiences = Some(vec!["daemon:other".to_string()]);
    let wrong_audience_request = capability_request(
        subject.clone(),
        gateway_action_operation("artifact.create"),
        wrong_audience_scope,
        now,
    );
    let wrong_audience_grant = grant(
        issuer.clone(),
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    let wrong_audience_decision =
        evaluate_capability_request(&[wrong_audience_grant], &wrong_audience_request, now);
    assert!(wrong_audience_decision
        .reasons
        .contains(&"audience_not_granted".to_string()));

    let mut unvalidated = grant(
        issuer,
        subject,
        gateway_action_operation("artifact.create"),
        scope,
        now,
    );
    unvalidated.validation = None;
    let unvalidated_decision = evaluate_capability_request(&[unvalidated], &request, now);
    assert!(unvalidated_decision
        .reasons
        .contains(&"invalid_validation:missing_grant_validation".to_string()));
}

#[test]
fn authority_requires_audience_and_concrete_scope_binding_for_authorization() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let operation = gateway_action_operation("artifact.create");

    let unbound_scope = CapabilityScope {
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(1),
            ..Default::default()
        },
        ..Default::default()
    };
    let unbound_grant = grant(
        issuer.clone(),
        subject.clone(),
        operation.clone(),
        unbound_scope.clone(),
        now,
    );
    let unbound_request =
        capability_request(subject.clone(), operation.clone(), unbound_scope, now);
    let unbound_decision = evaluate_capability_request(&[unbound_grant], &unbound_request, now);
    assert_eq!(unbound_decision.status, AuthorityDecisionStatus::Denied);
    assert!(unbound_decision
        .reasons
        .contains(&"invalid_scope:capability_request.scope:missing_audience_binding".to_string()));

    let grant_scope = base_scope(TenantId::new(), AgentId::new(), RunId::new());
    let mut request_missing_audience_scope = grant_scope.clone();
    request_missing_audience_scope.audiences = None;
    let request_missing_audience = capability_request(
        subject.clone(),
        operation.clone(),
        request_missing_audience_scope,
        now,
    );
    let valid_grant = grant(
        issuer.clone(),
        subject.clone(),
        operation.clone(),
        grant_scope.clone(),
        now,
    );
    let request_missing_audience_decision =
        evaluate_capability_request(&[valid_grant.clone()], &request_missing_audience, now);
    assert!(request_missing_audience_decision
        .reasons
        .contains(&"invalid_scope:capability_request.scope:missing_audience_binding".to_string()));

    let mut grant_missing_audience_scope = grant_scope.clone();
    grant_missing_audience_scope.audiences = None;
    let grant_missing_audience = grant(
        issuer.clone(),
        subject.clone(),
        operation.clone(),
        grant_missing_audience_scope,
        now,
    );
    let valid_request =
        capability_request(subject.clone(), operation.clone(), grant_scope.clone(), now);
    let grant_missing_audience_decision =
        evaluate_capability_request(&[grant_missing_audience], &valid_request, now);
    assert!(grant_missing_audience_decision
        .reasons
        .contains(&"invalid_scope:capability_grant.scope:missing_audience_binding".to_string()));

    let audience_only_scope = CapabilityScope {
        audiences: Some(vec!["daemon:local".to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(1),
            ..Default::default()
        },
        ..Default::default()
    };
    let audience_only_request = capability_request(
        subject.clone(),
        operation.clone(),
        audience_only_scope.clone(),
        now,
    );
    let audience_only_request_decision = evaluate_capability_request(
        std::slice::from_ref(&valid_grant),
        &audience_only_request,
        now,
    );
    assert!(audience_only_request_decision
        .reasons
        .contains(&"invalid_scope:capability_request.scope:missing_bounded_dimension".to_string()));

    let audience_only_grant = grant(issuer, subject, operation, audience_only_scope, now);
    let audience_only_grant_decision =
        evaluate_capability_request(&[audience_only_grant], &valid_request, now);
    assert!(audience_only_grant_decision
        .reasons
        .contains(&"invalid_scope:capability_grant.scope:missing_bounded_dimension".to_string()));
}

#[test]
fn authority_child_grant_cannot_broaden_any_dimension() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let parent_subject = PrincipalId::new();
    let child_subject = PrincipalId::new();
    let scope = base_scope(TenantId::new(), AgentId::new(), RunId::new());
    let parent = grant(
        issuer,
        parent_subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    let mut child = grant(
        parent_subject.clone(),
        child_subject,
        gateway_action_operation("artifact.create"),
        scope,
        now,
    );
    child.parent_grant_ids = vec![parent.grant_id.clone()];
    child.max_delegation_depth = 0;
    ensure_child_grant_narrows(&parent, &child).expect("valid child narrows parent");

    let mut broader_operation = child.clone();
    broader_operation
        .operations
        .push(gateway_action_operation("artifact.publish"));
    assert!(matches!(
        ensure_child_grant_narrows(&parent, &broader_operation),
        Err(AuthorityEvaluationError::NarrowingViolation {
            dimension: "operations",
            ..
        })
    ));

    let mut broader_scope = child.clone();
    broader_scope.scope.tenant_ids = None;
    assert!(matches!(
        ensure_child_grant_narrows(&parent, &broader_scope),
        Err(AuthorityEvaluationError::NarrowingViolation {
            dimension: "tenant_ids",
            ..
        })
    ));

    let mut broader_budget = child.clone();
    broader_budget.scope.budget.max_actions_per_tick = Some(6);
    assert!(matches!(
        ensure_child_grant_narrows(&parent, &broader_budget),
        Err(AuthorityEvaluationError::NarrowingViolation {
            dimension: "budget.max_actions_per_tick",
            ..
        })
    ));

    let mut broader_audience = child.clone();
    broader_audience.scope.audiences = Some(vec!["daemon:other".to_string()]);
    assert!(matches!(
        ensure_child_grant_narrows(&parent, &broader_audience),
        Err(AuthorityEvaluationError::NarrowingViolation {
            dimension: "audiences",
            ..
        })
    ));
}

#[test]
fn authority_scope_intersection_is_monotonic_across_bounded_dimensions() {
    let now = OffsetDateTime::now_utc();
    let tenant_id = TenantId::new();
    let first_agent = AgentId::new();
    let second_agent = AgentId::new();
    let parent = CapabilityScope {
        tenant_ids: Some(vec![tenant_id.clone()]),
        agent_ids: Some(vec![first_agent, second_agent.clone()]),
        data_purposes: Some(vec![DataPurpose::Read, DataPurpose::TrainingUse]),
        audiences: Some(vec!["daemon:local".to_string(), "daemon:batch".to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(10),
            max_action_duration_ms: Some(1_000),
            max_http_requests_per_minute: Some(20),
            ..Default::default()
        },
        time: AuthorityTimeScope {
            not_before: Some(now),
            expires_at: Some(now + time::Duration::minutes(10)),
        },
        network: NetworkScope {
            egress_schemes: Some(vec!["https".to_string(), "wss".to_string()]),
            egress_hosts: Some(vec![
                "api.internal".to_string(),
                "backup.internal".to_string(),
            ]),
        },
        locality: LocalityScope {
            regions: Some(vec!["eu-west".to_string(), "eu-central".to_string()]),
            zones: Some(vec!["eu-west-1a".to_string(), "eu-west-1b".to_string()]),
            data_localities: Some(vec!["eu".to_string(), "restricted-eu".to_string()]),
        },
        ..Default::default()
    };

    let child = CapabilityScope {
        tenant_ids: Some(vec![tenant_id]),
        agent_ids: Some(vec![second_agent.clone()]),
        data_purposes: Some(vec![DataPurpose::Read]),
        audiences: Some(vec!["daemon:local".to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(3),
            max_action_duration_ms: Some(500),
            max_http_requests_per_minute: Some(5),
            ..Default::default()
        },
        time: AuthorityTimeScope {
            not_before: Some(now + time::Duration::minutes(1)),
            expires_at: Some(now + time::Duration::minutes(5)),
        },
        network: NetworkScope {
            egress_schemes: Some(vec!["https".to_string()]),
            egress_hosts: Some(vec!["api.internal".to_string()]),
        },
        locality: LocalityScope {
            regions: Some(vec!["eu-west".to_string()]),
            zones: Some(vec!["eu-west-1a".to_string()]),
            data_localities: Some(vec!["restricted-eu".to_string()]),
        },
        ..Default::default()
    };

    let intersection = intersect_capability_scopes(&parent, &child).expect("intersect");

    let set_checks = [
        (
            "tenant_ids",
            option_subset(&intersection.tenant_ids, &parent.tenant_ids)
                && option_subset(&intersection.tenant_ids, &child.tenant_ids),
        ),
        (
            "agent_ids",
            option_subset(&intersection.agent_ids, &parent.agent_ids)
                && option_subset(&intersection.agent_ids, &child.agent_ids),
        ),
        (
            "data_purposes",
            option_subset(&intersection.data_purposes, &parent.data_purposes)
                && option_subset(&intersection.data_purposes, &child.data_purposes),
        ),
        (
            "network.egress_schemes",
            option_subset(
                &intersection.network.egress_schemes,
                &parent.network.egress_schemes,
            ) && option_subset(
                &intersection.network.egress_schemes,
                &child.network.egress_schemes,
            ),
        ),
        (
            "network.egress_hosts",
            option_subset(
                &intersection.network.egress_hosts,
                &parent.network.egress_hosts,
            ) && option_subset(
                &intersection.network.egress_hosts,
                &child.network.egress_hosts,
            ),
        ),
        (
            "locality.regions",
            option_subset(&intersection.locality.regions, &parent.locality.regions)
                && option_subset(&intersection.locality.regions, &child.locality.regions),
        ),
        (
            "locality.zones",
            option_subset(&intersection.locality.zones, &parent.locality.zones)
                && option_subset(&intersection.locality.zones, &child.locality.zones),
        ),
        (
            "locality.data_localities",
            option_subset(
                &intersection.locality.data_localities,
                &parent.locality.data_localities,
            ) && option_subset(
                &intersection.locality.data_localities,
                &child.locality.data_localities,
            ),
        ),
    ];
    for (dimension, monotonic) in set_checks {
        assert!(
            monotonic,
            "{dimension} intersection must stay within both scopes"
        );
    }

    assert_eq!(intersection.agent_ids, Some(vec![second_agent]));
    assert_eq!(intersection.data_purposes, Some(vec![DataPurpose::Read]));
    assert_eq!(intersection.budget.max_actions_per_tick, Some(3));
    assert_eq!(intersection.budget.max_action_duration_ms, Some(500));
    assert_eq!(intersection.budget.max_http_requests_per_minute, Some(5));
    assert_eq!(intersection.time.not_before, child.time.not_before);
    assert_eq!(intersection.time.expires_at, child.time.expires_at);
    assert_eq!(
        intersection.network.egress_schemes,
        Some(vec!["https".to_string()])
    );
    assert_eq!(
        intersection.network.egress_hosts,
        Some(vec!["api.internal".to_string()])
    );
    assert_eq!(
        intersection.locality.regions,
        Some(vec!["eu-west".to_string()])
    );
    assert_eq!(
        intersection.locality.zones,
        Some(vec!["eu-west-1a".to_string()])
    );
    assert_eq!(
        intersection.locality.data_localities,
        Some(vec!["restricted-eu".to_string()])
    );
}

#[test]
fn authority_child_grant_narrowing_table_rejects_broadening_and_constraint_removal() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let parent_subject = PrincipalId::new();
    let child_subject = PrincipalId::new();
    let tenant_id = TenantId::new();
    let first_agent = AgentId::new();
    let second_agent = AgentId::new();
    let parent_scope = CapabilityScope {
        tenant_ids: Some(vec![tenant_id.clone()]),
        agent_ids: Some(vec![first_agent, second_agent.clone()]),
        data_purposes: Some(vec![DataPurpose::Read, DataPurpose::TrainingUse]),
        audiences: Some(vec!["daemon:local".to_string()]),
        budget: AuthorityBudgetScope {
            max_action_duration_ms: Some(1_000),
            max_http_requests_per_minute: Some(20),
            ..Default::default()
        },
        time: AuthorityTimeScope {
            not_before: Some(now),
            expires_at: Some(now + time::Duration::minutes(20)),
        },
        network: NetworkScope {
            egress_schemes: Some(vec!["https".to_string()]),
            egress_hosts: Some(vec![
                "api.internal".to_string(),
                "backup.internal".to_string(),
            ]),
        },
        locality: LocalityScope {
            regions: Some(vec!["eu-west".to_string()]),
            zones: Some(vec!["eu-west-1a".to_string()]),
            data_localities: Some(vec!["restricted-eu".to_string()]),
        },
        ..Default::default()
    };
    let child_scope = CapabilityScope {
        tenant_ids: Some(vec![tenant_id]),
        agent_ids: Some(vec![second_agent]),
        data_purposes: Some(vec![DataPurpose::Read]),
        audiences: Some(vec!["daemon:local".to_string()]),
        budget: AuthorityBudgetScope {
            max_action_duration_ms: Some(500),
            max_http_requests_per_minute: Some(5),
            ..Default::default()
        },
        time: AuthorityTimeScope {
            not_before: Some(now + time::Duration::minutes(1)),
            expires_at: Some(now + time::Duration::minutes(5)),
        },
        network: NetworkScope {
            egress_schemes: Some(vec!["https".to_string()]),
            egress_hosts: Some(vec!["api.internal".to_string()]),
        },
        locality: LocalityScope {
            regions: Some(vec!["eu-west".to_string()]),
            zones: Some(vec!["eu-west-1a".to_string()]),
            data_localities: Some(vec!["restricted-eu".to_string()]),
        },
        ..Default::default()
    };
    let parent = grant(
        issuer,
        parent_subject.clone(),
        data_operation(AuthorityVerb::Read),
        parent_scope,
        now,
    );
    let mut child = grant(
        parent_subject.clone(),
        child_subject,
        data_operation(AuthorityVerb::Read),
        child_scope,
        now,
    );
    child.parent_grant_ids = vec![parent.grant_id.clone()];
    child.max_delegation_depth = 0;
    ensure_child_grant_narrows(&parent, &child).expect("valid child narrows parent");

    let cases = [
        NarrowingCase {
            name: "remove identity constraint",
            dimension: "agent_ids",
            mutate: remove_agent_constraint,
        },
        NarrowingCase {
            name: "broaden identity constraint",
            dimension: "agent_ids",
            mutate: broaden_agent_constraint,
        },
        NarrowingCase {
            name: "remove data purpose",
            dimension: "data_purposes",
            mutate: remove_data_purpose_constraint,
        },
        NarrowingCase {
            name: "broaden data purpose",
            dimension: "data_purposes",
            mutate: broaden_data_purpose_constraint,
        },
        NarrowingCase {
            name: "remove network scheme",
            dimension: "network.egress_schemes",
            mutate: remove_network_scheme_constraint,
        },
        NarrowingCase {
            name: "broaden network host",
            dimension: "network.egress_hosts",
            mutate: broaden_network_host_constraint,
        },
        NarrowingCase {
            name: "remove locality region",
            dimension: "locality.regions",
            mutate: remove_locality_region_constraint,
        },
        NarrowingCase {
            name: "broaden locality",
            dimension: "locality.data_localities",
            mutate: broaden_locality_constraint,
        },
        NarrowingCase {
            name: "remove scope time",
            dimension: "time.expires_at",
            mutate: remove_scope_time_constraint,
        },
        NarrowingCase {
            name: "broaden scope time",
            dimension: "time.expires_at",
            mutate: broaden_scope_time_constraint,
        },
        NarrowingCase {
            name: "remove budget limit",
            dimension: "budget.max_http_requests_per_minute",
            mutate: remove_budget_constraint,
        },
        NarrowingCase {
            name: "broaden budget limit",
            dimension: "budget.max_action_duration_ms",
            mutate: broaden_budget_constraint,
        },
    ];
    for case in cases {
        let mut candidate = child.clone();
        (case.mutate)(&mut candidate);
        assert_narrowing_dimension(&parent, &candidate, case.dimension, case.name);
    }
}

#[test]
fn authority_metadata_and_extensions_do_not_grant_authority() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let scope = base_scope(TenantId::new(), AgentId::new(), RunId::new());
    let request = capability_request(
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );

    let mut metadata_only = grant(
        issuer.clone(),
        subject.clone(),
        gateway_action_operation("artifact.publish"),
        scope.clone(),
        now,
    );
    metadata_only.metadata.insert(
        "x_note".to_string(),
        serde_json::json!("allow artifact.create"),
    );
    let decision = evaluate_capability_request(&[metadata_only], &request, now);
    assert_eq!(decision.status, AuthorityDecisionStatus::Denied);
    assert!(decision
        .reasons
        .contains(&"operation_not_granted".to_string()));

    let mut reserved_metadata = grant(
        issuer,
        subject,
        gateway_action_operation("artifact.create"),
        scope,
        now,
    );
    reserved_metadata
        .metadata
        .insert("allowed_actions".to_string(), serde_json::json!(["*"]));
    let reserved_decision = evaluate_capability_request(&[reserved_metadata], &request, now);
    assert!(reserved_decision
        .reasons
        .contains(&"metadata_reserved_authority_key".to_string()));
}

#[test]
fn authority_rejects_universal_wildcard_bypass() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let scope = base_scope(TenantId::new(), AgentId::new(), RunId::new());
    let mut wildcard_grant = grant(
        issuer,
        subject.clone(),
        gateway_action_operation("*"),
        scope.clone(),
        now,
    );
    wildcard_grant.scope.audiences = Some(vec!["daemon:*".to_string()]);
    let request = capability_request(
        subject,
        gateway_action_operation("artifact.create"),
        scope,
        now,
    );

    let decision = evaluate_capability_request(&[wildcard_grant], &request, now);

    assert_eq!(decision.status, AuthorityDecisionStatus::Denied);
    assert!(decision
        .reasons
        .iter()
        .any(|reason| reason.starts_with("invalid_token:")));
}

#[test]
fn authority_data_read_training_eval_and_publication_are_not_one_permission() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let mut scope = base_scope(TenantId::new(), AgentId::new(), RunId::new());
    scope.data_purposes = Some(vec![DataPurpose::Read]);
    let read_grant = grant(
        issuer,
        subject.clone(),
        data_operation(AuthorityVerb::Read),
        scope.clone(),
        now,
    );
    let mut training_scope = scope;
    training_scope.data_purposes = Some(vec![DataPurpose::TrainingUse]);
    let training_request = capability_request(
        subject,
        data_operation(AuthorityVerb::Train),
        training_scope,
        now,
    );

    let decision = evaluate_capability_request(&[read_grant], &training_request, now);

    assert_eq!(decision.status, AuthorityDecisionStatus::Denied);
    assert!(decision
        .reasons
        .contains(&"operation_not_granted".to_string()));
    assert!(decision
        .reasons
        .contains(&"data_purposes_not_granted".to_string()));
}

#[test]
fn authority_work_order_profile_preserves_existing_allowlists_without_broadening() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let work_order = WorkOrder {
        schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new("wo_auth001").expect("work order id"),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: Some(run_id.clone()),
        objective: "bounded authority profile".to_string(),
        allowed_actions: vec!["artifact.create".to_string()],
        allowed_adapters: vec!["artifact-store".to_string()],
        allowed_permissions: vec!["artifact.create".to_string()],
        data_refs: Vec::new(),
        quotas: WorkOrderQuotaPolicy {
            max_actions_per_tick: Some(2),
            ..Default::default()
        },
        placement: WorkOrderPlacement::default(),
        issued_at: now - time::Duration::minutes(1),
        expires_at: now + time::Duration::minutes(10),
        revocation: RevocationStatus::Active,
    };
    let context = CompatibilityGrantContext {
        grant_id: CapabilityGrantId::new(),
        issuer,
        subject: subject.clone(),
        audience: "daemon:local".to_string(),
        validation_digest: DIGEST.to_string(),
        max_delegation_depth: 1,
        parent_grant_ids: Vec::new(),
    };
    let grant = grant_from_work_order(context, &work_order);
    let scope = CapabilityScope {
        tenant_ids: Some(vec![tenant_id]),
        agent_ids: Some(vec![agent_id]),
        run_ids: Some(vec![run_id]),
        audiences: Some(vec!["daemon:local".to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(1),
            ..Default::default()
        },
        ..Default::default()
    };
    let allowed_request = capability_request(
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    let denied_request = capability_request(
        subject,
        gateway_action_operation("artifact.publish"),
        scope,
        now,
    );

    let allowed = evaluate_capability_request(std::slice::from_ref(&grant), &allowed_request, now);
    let denied = evaluate_capability_request(&[grant], &denied_request, now);

    assert_eq!(allowed.status, AuthorityDecisionStatus::Allowed);
    assert_eq!(denied.status, AuthorityDecisionStatus::Denied);
    assert!(denied
        .reasons
        .contains(&"operation_not_granted".to_string()));
}

#[test]
fn authority_composite_effect_requires_separate_operation_decisions() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let work_order = WorkOrder {
        schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new("wo_auth001_composite").expect("work order id"),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: Some(run_id.clone()),
        objective: "bounded action without adapter or permission".to_string(),
        allowed_actions: vec!["artifact.create".to_string()],
        allowed_adapters: Vec::new(),
        allowed_permissions: Vec::new(),
        data_refs: Vec::new(),
        quotas: WorkOrderQuotaPolicy {
            max_actions_per_tick: Some(2),
            ..Default::default()
        },
        placement: WorkOrderPlacement::default(),
        issued_at: now - time::Duration::minutes(1),
        expires_at: now + time::Duration::minutes(10),
        revocation: RevocationStatus::Active,
    };
    let context = CompatibilityGrantContext {
        grant_id: CapabilityGrantId::new(),
        issuer,
        subject: subject.clone(),
        audience: "daemon:local".to_string(),
        validation_digest: DIGEST.to_string(),
        max_delegation_depth: 1,
        parent_grant_ids: Vec::new(),
    };
    let grant = grant_from_work_order(context, &work_order);
    let scope = CapabilityScope {
        tenant_ids: Some(vec![tenant_id]),
        agent_ids: Some(vec![agent_id]),
        run_ids: Some(vec![run_id]),
        audiences: Some(vec!["daemon:local".to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(1),
            ..Default::default()
        },
        ..Default::default()
    };

    let action_request = capability_request(
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    let adapter_request = capability_request(
        subject.clone(),
        gateway_adapter_operation("artifact-store"),
        scope.clone(),
        now,
    );
    let permission_request = capability_request(
        subject,
        compatibility_permission_operation("artifact.create"),
        scope,
        now,
    );

    let action_decision =
        evaluate_capability_request(std::slice::from_ref(&grant), &action_request, now);
    let adapter_decision =
        evaluate_capability_request(std::slice::from_ref(&grant), &adapter_request, now);
    let permission_decision = evaluate_capability_request(&[grant], &permission_request, now);

    assert_eq!(action_decision.status, AuthorityDecisionStatus::Allowed);
    assert_eq!(adapter_decision.status, AuthorityDecisionStatus::Denied);
    assert_eq!(permission_decision.status, AuthorityDecisionStatus::Denied);
    assert!(adapter_decision
        .reasons
        .contains(&"operation_not_granted".to_string()));
    assert!(permission_decision
        .reasons
        .contains(&"operation_not_granted".to_string()));
}
