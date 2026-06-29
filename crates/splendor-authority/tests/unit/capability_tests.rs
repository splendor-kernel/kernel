use super::*;
use splendor_types::{
    ArtifactId, AuthorityObligationId, AuthorityObligationKind, DeviceId, FleetId,
    StatePartitionId, WorkOrderId, WorkOrderPlacement, WorkloadId,
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

fn validated(grant: CapabilityGrant) -> ValidatedCapabilityGrant {
    unchecked_validated_grant_for_tests(grant)
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

fn network_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Network,
        resource_kind: AuthorityResourceKind::Network,
        verb: AuthorityVerb::Egress,
        name: None,
        resource_schema_version: Some("splendor.network_egress.v1".to_string()),
    }
}

fn device_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Device,
        resource_kind: AuthorityResourceKind::Device,
        verb: AuthorityVerb::Actuate,
        name: None,
        resource_schema_version: Some("splendor.device_action.v1".to_string()),
    }
}

fn artifact_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Artifact,
        resource_kind: AuthorityResourceKind::Artifact,
        verb: AuthorityVerb::Publish,
        name: None,
        resource_schema_version: Some("splendor.artifact.v1".to_string()),
    }
}

fn state_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::State,
        resource_kind: AuthorityResourceKind::StatePartition,
        verb: AuthorityVerb::Read,
        name: None,
        resource_schema_version: Some("splendor.state_partition.v1".to_string()),
    }
}

fn driver_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Driver,
        resource_kind: AuthorityResourceKind::DriverOperation,
        verb: AuthorityVerb::Invoke,
        name: Some("artifact-store.create".to_string()),
        resource_schema_version: Some("splendor.driver_operation.v1".to_string()),
    }
}

fn workload_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Workload,
        resource_kind: AuthorityResourceKind::Workload,
        verb: AuthorityVerb::Admit,
        name: None,
        resource_schema_version: Some("splendor.workload.v1".to_string()),
    }
}

fn agent_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Agent,
        resource_kind: AuthorityResourceKind::Agent,
        verb: AuthorityVerb::Invoke,
        name: None,
        resource_schema_version: Some("splendor.agent.v1".to_string()),
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

fn assert_scope_denied_for_operation(
    operation: AuthorityOperation,
    scope: CapabilityScope,
    expected_reason: &str,
) {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let grant = grant(
        issuer,
        subject.clone(),
        operation.clone(),
        scope.clone(),
        now,
    );
    let request = capability_request(subject, operation, scope, now);
    let decision = evaluate_capability_request(&[validated(grant)], &request, now);
    assert_eq!(decision.status, AuthorityDecisionStatus::Denied);
    assert!(
        decision.reasons.contains(&expected_reason.to_string()),
        "expected {expected_reason}, got {:?}",
        decision.reasons
    );
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

    let decision = evaluate_capability_request(&[validated(grant.clone())], &request, now);

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
    let expired_decision = evaluate_capability_request(&[validated(expired)], &request, now);
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
    let revoked_decision = evaluate_capability_request(&[validated(revoked)], &request, now);
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
    let wrong_audience_decision = evaluate_capability_request(
        &[validated(wrong_audience_grant)],
        &wrong_audience_request,
        now,
    );
    assert!(wrong_audience_decision
        .reasons
        .contains(&"audience_not_granted".to_string()));

    let mut unvalidated = grant(
        issuer,
        subject,
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    unvalidated.validation = None;
    let unvalidated_decision =
        evaluate_capability_request(&[validated(unvalidated)], &request, now);
    assert!(unvalidated_decision
        .reasons
        .contains(&"invalid_validation:missing_grant_validation".to_string()));

    let mut not_yet_valid = grant(
        PrincipalId::new(),
        request.subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    not_yet_valid.not_before = now + time::Duration::minutes(1);
    not_yet_valid.expires_at = now + time::Duration::minutes(30);
    let not_yet_valid_decision =
        evaluate_capability_request(&[validated(not_yet_valid)], &request, now);
    assert!(not_yet_valid_decision
        .reasons
        .contains(&"grant_not_yet_valid".to_string()));

    let wrong_subject = grant(
        PrincipalId::new(),
        PrincipalId::new(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    let wrong_subject_decision =
        evaluate_capability_request(&[validated(wrong_subject)], &request, now);
    assert!(wrong_subject_decision
        .reasons
        .contains(&"subject_mismatch".to_string()));

    let mut signed = grant(
        PrincipalId::new(),
        request.subject.clone(),
        gateway_action_operation("artifact.create"),
        scope,
        now,
    );
    signed.validation = Some(CapabilityGrantValidation {
        validation_kind: CapabilityGrantValidationKind::Signed,
        algorithm: "dummy-ed25519".to_string(),
        key_id: Some("test-key".to_string()),
        digest: DIGEST.to_string(),
        signature: Some("not-a-real-signature".to_string()),
    });
    let signed_decision = evaluate_capability_request(&[validated(signed)], &request, now);
    assert!(signed_decision
        .reasons
        .contains(&"invalid_validation:signed_grant_verifier_unavailable".to_string()));
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
    let unbound_decision =
        evaluate_capability_request(&[validated(unbound_grant)], &unbound_request, now);
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
    let request_missing_audience_decision = evaluate_capability_request(
        &[validated(valid_grant.clone())],
        &request_missing_audience,
        now,
    );
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
        evaluate_capability_request(&[validated(grant_missing_audience)], &valid_request, now);
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
        &[validated(valid_grant.clone())],
        &audience_only_request,
        now,
    );
    assert!(audience_only_request_decision
        .reasons
        .contains(&"invalid_scope:capability_request.scope:missing_bounded_dimension".to_string()));

    let audience_only_grant = grant(issuer, subject, operation, audience_only_scope, now);
    let audience_only_grant_decision =
        evaluate_capability_request(&[validated(audience_only_grant)], &valid_request, now);
    assert!(audience_only_grant_decision
        .reasons
        .contains(&"invalid_scope:capability_grant.scope:missing_bounded_dimension".to_string()));
}

#[test]
fn authority_requires_tenant_or_fleet_and_operation_specific_scope() {
    let tenant_bound_scope = CapabilityScope {
        tenant_ids: Some(vec![TenantId::new()]),
        audiences: Some(vec!["daemon:local".to_string()]),
        ..Default::default()
    };

    assert_scope_denied_for_operation(
        network_operation(),
        tenant_bound_scope.clone(),
        "invalid_scope:capability_request.scope:network_egress_scope_required",
    );
    assert_scope_denied_for_operation(
        device_operation(),
        tenant_bound_scope.clone(),
        "invalid_scope:capability_request.scope:device_scope_required",
    );
    assert_scope_denied_for_operation(
        artifact_operation(),
        tenant_bound_scope.clone(),
        "invalid_scope:capability_request.scope:artifact_scope_required",
    );
    assert_scope_denied_for_operation(
        state_operation(),
        tenant_bound_scope.clone(),
        "invalid_scope:capability_request.scope:state_partition_scope_required",
    );
    assert_scope_denied_for_operation(
        driver_operation(),
        tenant_bound_scope.clone(),
        "invalid_scope:capability_request.scope:driver_operation_scope_required",
    );
    assert_scope_denied_for_operation(
        workload_operation(),
        tenant_bound_scope.clone(),
        "invalid_scope:capability_request.scope:workload_or_run_scope_required",
    );
    assert_scope_denied_for_operation(
        agent_operation(),
        tenant_bound_scope,
        "invalid_scope:capability_request.scope:agent_scope_required",
    );

    let agent_and_run_only_scope = CapabilityScope {
        agent_ids: Some(vec![AgentId::new()]),
        run_ids: Some(vec![RunId::new()]),
        audiences: Some(vec!["daemon:local".to_string()]),
        ..Default::default()
    };
    assert_scope_denied_for_operation(
        gateway_action_operation("artifact.create"),
        agent_and_run_only_scope,
        "invalid_scope:capability_request.scope:missing_tenant_or_fleet_binding",
    );
}

#[test]
fn authority_enforces_scope_time_windows_and_containment() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let operation = gateway_action_operation("artifact.create");
    let base = base_scope(TenantId::new(), AgentId::new(), RunId::new());
    let request_without_time =
        capability_request(subject.clone(), operation.clone(), base.clone(), now);

    let mut expired_scope_grant = grant(
        issuer.clone(),
        subject.clone(),
        operation.clone(),
        base.clone(),
        now,
    );
    expired_scope_grant.scope.time.expires_at = Some(now - time::Duration::seconds(1));
    let expired_scope_decision = evaluate_capability_request(
        &[validated(expired_scope_grant)],
        &request_without_time,
        now,
    );
    assert!(expired_scope_decision
        .reasons
        .contains(&"invalid_scope:capability_grant.scope.time:scope_time_expired".to_string()));

    let mut constrained_grant_scope = base.clone();
    constrained_grant_scope.time = AuthorityTimeScope {
        not_before: Some(now - time::Duration::minutes(1)),
        expires_at: Some(now + time::Duration::minutes(10)),
    };
    let constrained_grant = grant(
        issuer.clone(),
        subject.clone(),
        operation.clone(),
        constrained_grant_scope,
        now,
    );
    let mut broader_request_scope = base.clone();
    broader_request_scope.time = AuthorityTimeScope {
        not_before: Some(now - time::Duration::minutes(2)),
        expires_at: Some(now + time::Duration::minutes(5)),
    };
    let broader_request = capability_request(
        subject.clone(),
        operation.clone(),
        broader_request_scope,
        now,
    );
    let broader_request_decision = evaluate_capability_request(
        &[validated(constrained_grant.clone())],
        &broader_request,
        now,
    );
    assert!(broader_request_decision
        .reasons
        .contains(&"time.not_before_precedes_grant".to_string()));

    let mut missing_request_time_scope = base.clone();
    missing_request_time_scope.time = AuthorityTimeScope::default();
    let missing_request_time = capability_request(
        subject.clone(),
        operation.clone(),
        missing_request_time_scope,
        now,
    );
    let missing_request_time_decision =
        evaluate_capability_request(&[validated(constrained_grant)], &missing_request_time, now);
    assert!(missing_request_time_decision
        .reasons
        .contains(&"time.not_before_missing_from_request".to_string()));

    let mut unconstrained_grant = grant(
        issuer,
        subject.clone(),
        operation.clone(),
        base.clone(),
        now,
    );
    unconstrained_grant.scope.time = AuthorityTimeScope::default();
    let mut time_scoped_request_scope = base;
    time_scoped_request_scope.time = AuthorityTimeScope {
        not_before: Some(now - time::Duration::seconds(1)),
        expires_at: Some(now + time::Duration::minutes(1)),
    };
    let time_scoped_request =
        capability_request(subject, operation, time_scoped_request_scope, now);
    let time_not_granted_decision =
        evaluate_capability_request(&[validated(unconstrained_grant)], &time_scoped_request, now);
    assert!(time_not_granted_decision
        .reasons
        .contains(&"time.not_before_not_granted".to_string()));
}

#[test]
fn authority_enforces_narrowed_child_scope_time() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let parent_subject = PrincipalId::new();
    let child_subject = PrincipalId::new();
    let operation = gateway_action_operation("artifact.create");
    let mut parent_scope = base_scope(TenantId::new(), AgentId::new(), RunId::new());
    parent_scope.time = AuthorityTimeScope {
        not_before: Some(now - time::Duration::minutes(1)),
        expires_at: Some(now + time::Duration::minutes(20)),
    };
    let parent = grant(
        issuer,
        parent_subject.clone(),
        operation.clone(),
        parent_scope.clone(),
        now,
    );
    let mut child_scope = parent_scope;
    child_scope.time = AuthorityTimeScope {
        not_before: Some(now),
        expires_at: Some(now + time::Duration::minutes(5)),
    };
    let mut child = grant(
        parent_subject,
        child_subject.clone(),
        operation.clone(),
        child_scope.clone(),
        now,
    );
    child.parent_grant_ids = vec![parent.grant_id.clone()];
    child.max_delegation_depth = 0;
    ensure_child_grant_narrows(&parent, &child).expect("child scope time narrows parent");

    let later = now + time::Duration::minutes(10);
    let mut request_scope = child_scope;
    request_scope.time = AuthorityTimeScope::default();
    let request = capability_request(child_subject, operation, request_scope, later);
    let decision = evaluate_capability_request(&[validated(child)], &request, later);
    assert!(decision
        .reasons
        .contains(&"invalid_scope:capability_grant.scope.time:scope_time_expired".to_string()));
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
    let decision = evaluate_capability_request(&[validated(metadata_only)], &request, now);
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
    let reserved_decision =
        evaluate_capability_request(&[validated(reserved_metadata)], &request, now);
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

    let decision = evaluate_capability_request(&[validated(wildcard_grant)], &request, now);

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

    let decision = evaluate_capability_request(&[validated(read_grant)], &training_request, now);

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
    let grant = grant_from_work_order(context, &work_order).expect("validated work-order grant");
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
    let denied = evaluate_capability_request(std::slice::from_ref(&grant), &denied_request, now);

    assert_eq!(allowed.status, AuthorityDecisionStatus::Allowed);
    assert_eq!(denied.status, AuthorityDecisionStatus::Denied);
    assert!(denied
        .reasons
        .contains(&"operation_not_granted".to_string()));
}

#[test]
fn authority_shape_validation_covers_malformed_requests_grants_operations_and_scopes() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let scope = base_scope(TenantId::new(), AgentId::new(), RunId::new());

    let mut request = capability_request(
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    request.schema_version = "splendor.capability_request.v0".to_string();
    assert_eq!(
        validate_request_shape(&request, now)
            .unwrap_err()
            .reason_code(),
        "invalid_schema:capability_request.schema_version"
    );

    let mut request = capability_request(
        PrincipalId::parse("00000000-0000-0000-0000-000000000000").unwrap(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    assert_eq!(
        validate_request_shape(&request, now)
            .unwrap_err()
            .reason_code(),
        "invalid_identity:subject"
    );

    request.subject = subject.clone();
    request.scope.time.not_before = Some(now + time::Duration::minutes(1));
    assert_eq!(
        validate_request_shape(&request, now)
            .unwrap_err()
            .reason_code(),
        "invalid_scope:capability_request.scope.time:scope_time_not_yet_valid"
    );
    request.scope.time.not_before = None;
    request.scope.time.expires_at = Some(now - time::Duration::seconds(1));
    assert_eq!(
        validate_request_shape(&request, now)
            .unwrap_err()
            .reason_code(),
        "invalid_scope:capability_request.scope.time:scope_time_expired"
    );

    let bad_tuple = AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Gateway,
        resource_kind: AuthorityResourceKind::Action,
        verb: AuthorityVerb::Read,
        name: Some("artifact.create".to_string()),
        resource_schema_version: Some("splendor.action.v1".to_string()),
    };
    assert_eq!(
        validate_operation_shape(&bad_tuple)
            .unwrap_err()
            .reason_code(),
        "invalid_operation:operation_tuple_not_allowed"
    );

    let mut missing_name = driver_operation();
    missing_name.name = None;
    assert_eq!(
        validate_operation_shape(&missing_name)
            .unwrap_err()
            .reason_code(),
        "invalid_operation:operation_name_required"
    );

    let mut name_not_allowed = data_operation(AuthorityVerb::Read);
    name_not_allowed.name = Some("dataset.read".to_string());
    assert_eq!(
        validate_operation_shape(&name_not_allowed)
            .unwrap_err()
            .reason_code(),
        "invalid_operation:operation_name_not_allowed_for_typed_tuple"
    );

    let mut bad_operation_schema = gateway_action_operation("artifact.create");
    bad_operation_schema.schema_version = "splendor.authority_operation.v0".to_string();
    assert_eq!(
        validate_operation_shape(&bad_operation_schema)
            .unwrap_err()
            .reason_code(),
        "invalid_schema:authority_operation.schema_version"
    );

    let mut bad_resource_schema = gateway_action_operation("artifact.create");
    bad_resource_schema.resource_schema_version = Some("splendor.*.v1".to_string());
    assert_eq!(
        validate_operation_shape(&bad_resource_schema)
            .unwrap_err()
            .reason_code(),
        "invalid_token:authority_operation.resource_schema_version"
    );

    let mut invalid_scope = scope.clone();
    invalid_scope.schema_version = "splendor.capability_scope.v0".to_string();
    assert_eq!(
        validate_scope_shape(&invalid_scope)
            .unwrap_err()
            .reason_code(),
        "invalid_schema:capability_scope.schema_version"
    );

    let mut invalid_scope = scope.clone();
    invalid_scope.tenant_ids = Some(Vec::new());
    assert_eq!(
        validate_scope_shape(&invalid_scope)
            .unwrap_err()
            .reason_code(),
        "invalid_scope:tenant_ids:empty_scope_set"
    );

    let mut invalid_scope = scope.clone();
    invalid_scope.fleet_ids = Some(vec![
        FleetId::parse("00000000-0000-0000-0000-000000000000").unwrap()
    ]);
    assert_eq!(
        validate_scope_shape(&invalid_scope)
            .unwrap_err()
            .reason_code(),
        "invalid_scope:fleet_ids:nil_identity"
    );

    let mut invalid_scope = scope.clone();
    invalid_scope.audiences = Some(vec![" daemon:local".to_string()]);
    assert_eq!(
        validate_scope_shape(&invalid_scope)
            .unwrap_err()
            .reason_code(),
        "invalid_token:audiences"
    );

    let mut invalid_scope = scope.clone();
    invalid_scope.driver_operations = Some(vec![DriverOperationRef {
        driver: "driver:*".to_string(),
        operation: "create".to_string(),
        schema_version: "splendor.driver.v1".to_string(),
    }]);
    assert_eq!(
        validate_scope_shape(&invalid_scope)
            .unwrap_err()
            .reason_code(),
        "invalid_token:driver_operations.driver"
    );

    let mut invalid_scope = scope.clone();
    invalid_scope.time.not_before = Some(now + time::Duration::minutes(1));
    invalid_scope.time.expires_at = Some(now + time::Duration::minutes(1));
    assert_eq!(
        validate_scope_shape(&invalid_scope)
            .unwrap_err()
            .reason_code(),
        "invalid_scope:time:not_before_must_precede_expires_at"
    );

    let mut invalid_grant = grant(
        issuer.clone(),
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    invalid_grant.schema_version = "splendor.capability_grant.v0".to_string();
    assert_eq!(
        validate_grant_shape(&invalid_grant)
            .unwrap_err()
            .reason_code(),
        "invalid_schema:capability_grant.schema_version"
    );

    let mut invalid_grant = grant(
        issuer.clone(),
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    invalid_grant.grant_id =
        CapabilityGrantId::parse("00000000-0000-0000-0000-000000000000").unwrap();
    assert_eq!(
        validate_grant_shape(&invalid_grant)
            .unwrap_err()
            .reason_code(),
        "invalid_identity:grant_id"
    );

    let mut invalid_grant = grant(
        issuer.clone(),
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    invalid_grant.issuer = PrincipalId::parse("00000000-0000-0000-0000-000000000000").unwrap();
    assert_eq!(
        validate_grant_shape(&invalid_grant)
            .unwrap_err()
            .reason_code(),
        "invalid_identity:issuer"
    );

    let mut invalid_grant = grant(
        issuer.clone(),
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    invalid_grant.subject = PrincipalId::parse("00000000-0000-0000-0000-000000000000").unwrap();
    assert_eq!(
        validate_grant_shape(&invalid_grant)
            .unwrap_err()
            .reason_code(),
        "invalid_identity:subject"
    );

    let mut invalid_grant = grant(
        issuer.clone(),
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    invalid_grant.operations.clear();
    assert_eq!(
        validate_grant_shape(&invalid_grant)
            .unwrap_err()
            .reason_code(),
        "invalid_operation:missing_operations"
    );

    let mut invalid_grant = grant(
        issuer.clone(),
        subject.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    invalid_grant.not_before = invalid_grant.expires_at;
    assert_eq!(
        validate_grant_shape(&invalid_grant)
            .unwrap_err()
            .reason_code(),
        "invalid_scope:time:grant_not_before_must_precede_expires_at"
    );

    let mut invalid_grant = grant(
        issuer,
        subject,
        gateway_action_operation("artifact.create"),
        scope,
        now,
    );
    invalid_grant.obligations.push(AuthorityObligation {
        obligation_id: AuthorityObligationId::parse("00000000-0000-0000-0000-000000000000")
            .unwrap(),
        kind: AuthorityObligationKind::EvidenceRequired,
        description: "record evidence".to_string(),
        parameters: Default::default(),
    });
    assert_eq!(
        validate_grant_shape(&invalid_grant)
            .unwrap_err()
            .reason_code(),
        "invalid_identity:obligation_id"
    );
}

#[test]
fn authority_scope_intersections_cover_all_dimensions_and_empty_cases() {
    let now = OffsetDateTime::now_utc();
    let tenant = TenantId::new();
    let fleet = FleetId::new();
    let agent = AgentId::new();
    let run = RunId::new();
    let workload = WorkloadId::new();
    let device = DeviceId::new();
    let artifact = ArtifactId::new();
    let state_partition = StatePartitionId::new();
    let driver_ref = DriverOperationRef {
        driver: "artifact-store".to_string(),
        operation: "create".to_string(),
        schema_version: "splendor.driver_operation.v1".to_string(),
    };

    let left = CapabilityScope {
        tenant_ids: Some(vec![tenant.clone(), TenantId::new()]),
        fleet_ids: Some(vec![fleet.clone(), FleetId::new()]),
        agent_ids: Some(vec![agent.clone(), AgentId::new()]),
        run_ids: Some(vec![run.clone(), RunId::new()]),
        workload_ids: Some(vec![workload.clone(), WorkloadId::new()]),
        device_ids: Some(vec![device.clone(), DeviceId::new()]),
        data_purposes: Some(vec![DataPurpose::Read, DataPurpose::TrainingUse]),
        artifact_ids: Some(vec![artifact.clone(), ArtifactId::new()]),
        state_partition_ids: Some(vec![state_partition.clone(), StatePartitionId::new()]),
        driver_operations: Some(vec![driver_ref.clone()]),
        audiences: Some(vec!["daemon:local".to_string(), "daemon:other".to_string()]),
        time: AuthorityTimeScope {
            not_before: Some(now - time::Duration::minutes(5)),
            expires_at: Some(now + time::Duration::minutes(30)),
        },
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(5),
            max_action_duration_ms: Some(2_000),
            max_filesystem_read_bytes: Some(10_000),
            max_filesystem_write_bytes: Some(1_000),
            max_network_read_bytes: Some(20_000),
            max_network_write_bytes: Some(2_000),
            max_http_requests_per_minute: Some(60),
        },
        network: NetworkScope {
            egress_schemes: Some(vec!["https".to_string(), "http".to_string()]),
            egress_hosts: Some(vec![
                "api.example.test".to_string(),
                "other.test".to_string(),
            ]),
        },
        locality: LocalityScope {
            regions: Some(vec!["eu-west".to_string(), "us-east".to_string()]),
            zones: Some(vec!["zone-a".to_string(), "zone-b".to_string()]),
            data_localities: Some(vec!["on_prem".to_string(), "cloud".to_string()]),
        },
        ..Default::default()
    };
    let right = CapabilityScope {
        tenant_ids: Some(vec![tenant.clone()]),
        fleet_ids: Some(vec![fleet.clone()]),
        agent_ids: Some(vec![agent.clone()]),
        run_ids: Some(vec![run.clone()]),
        workload_ids: Some(vec![workload.clone()]),
        device_ids: Some(vec![device.clone()]),
        data_purposes: Some(vec![DataPurpose::TrainingUse]),
        artifact_ids: Some(vec![artifact.clone()]),
        state_partition_ids: Some(vec![state_partition.clone()]),
        driver_operations: Some(vec![driver_ref.clone()]),
        audiences: Some(vec!["daemon:local".to_string()]),
        time: AuthorityTimeScope {
            not_before: Some(now),
            expires_at: Some(now + time::Duration::minutes(10)),
        },
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(3),
            max_action_duration_ms: Some(1_000),
            max_filesystem_read_bytes: Some(5_000),
            max_filesystem_write_bytes: Some(500),
            max_network_read_bytes: Some(10_000),
            max_network_write_bytes: Some(1_000),
            max_http_requests_per_minute: Some(30),
        },
        network: NetworkScope {
            egress_schemes: Some(vec!["https".to_string()]),
            egress_hosts: Some(vec!["api.example.test".to_string()]),
        },
        locality: LocalityScope {
            regions: Some(vec!["eu-west".to_string()]),
            zones: Some(vec!["zone-a".to_string()]),
            data_localities: Some(vec!["on_prem".to_string()]),
        },
        ..Default::default()
    };

    let intersection = intersect_capability_scopes(&left, &right).unwrap();
    assert_eq!(intersection.tenant_ids, Some(vec![tenant]));
    assert_eq!(intersection.fleet_ids, Some(vec![fleet]));
    assert_eq!(intersection.agent_ids, Some(vec![agent]));
    assert_eq!(intersection.run_ids, Some(vec![run]));
    assert_eq!(intersection.workload_ids, Some(vec![workload]));
    assert_eq!(intersection.device_ids, Some(vec![device]));
    assert_eq!(
        intersection.data_purposes,
        Some(vec![DataPurpose::TrainingUse])
    );
    assert_eq!(intersection.artifact_ids, Some(vec![artifact]));
    assert_eq!(
        intersection.state_partition_ids,
        Some(vec![state_partition])
    );
    assert_eq!(intersection.driver_operations, Some(vec![driver_ref]));
    assert_eq!(
        intersection.audiences,
        Some(vec!["daemon:local".to_string()])
    );
    assert_eq!(intersection.time.not_before, Some(now));
    assert_eq!(
        intersection.time.expires_at,
        Some(now + time::Duration::minutes(10))
    );
    assert_eq!(intersection.budget.max_network_write_bytes, Some(1_000));
    assert_eq!(
        intersection.network.egress_schemes,
        Some(vec!["https".to_string()])
    );
    assert_eq!(
        intersection.locality.data_localities,
        Some(vec!["on_prem".to_string()])
    );

    let mut empty_right = right.clone();
    empty_right.tenant_ids = Some(vec![TenantId::new()]);
    assert_eq!(
        intersect_capability_scopes(&left, &empty_right)
            .unwrap_err()
            .reason_code(),
        "empty_intersection:tenant_ids"
    );

    let left_only = CapabilityScope {
        tenant_ids: Some(vec![TenantId::new()]),
        ..Default::default()
    };
    assert!(
        intersect_capability_scopes(&left_only, &CapabilityScope::default())
            .unwrap()
            .tenant_ids
            .is_some()
    );
    assert!(
        intersect_capability_scopes(&CapabilityScope::default(), &left_only)
            .unwrap()
            .tenant_ids
            .is_some()
    );

    let time_left = CapabilityScope {
        time: AuthorityTimeScope {
            not_before: Some(now + time::Duration::minutes(10)),
            expires_at: None,
        },
        ..Default::default()
    };
    let time_right = CapabilityScope {
        time: AuthorityTimeScope {
            not_before: None,
            expires_at: Some(now + time::Duration::minutes(1)),
        },
        ..Default::default()
    };
    assert_eq!(
        intersect_capability_scopes(&time_left, &time_right)
            .unwrap_err()
            .reason_code(),
        "empty_intersection:time"
    );
}

#[test]
fn authority_narrowing_failures_cover_lineage_budget_time_and_obligations() {
    let now = OffsetDateTime::now_utc();
    let parent_issuer = PrincipalId::new();
    let parent_subject = PrincipalId::new();
    let child_subject = PrincipalId::new();
    let mut parent_scope = base_scope(TenantId::new(), AgentId::new(), RunId::new());
    parent_scope.time = AuthorityTimeScope {
        not_before: Some(now - time::Duration::minutes(1)),
        expires_at: Some(now + time::Duration::minutes(30)),
    };
    parent_scope.budget = AuthorityBudgetScope {
        max_network_read_bytes: Some(10),
        max_network_write_bytes: Some(20),
        ..parent_scope.budget
    };
    let obligation = AuthorityObligation {
        obligation_id: AuthorityObligationId::new(),
        kind: AuthorityObligationKind::EvidenceRequired,
        description: "preserve evidence".to_string(),
        parameters: Default::default(),
    };
    let mut parent = grant(
        parent_issuer,
        parent_subject.clone(),
        gateway_action_operation("artifact.create"),
        parent_scope,
        now,
    );
    parent.max_delegation_depth = 2;
    parent.obligations.push(obligation.clone());

    let mut child = parent.clone();
    child.grant_id = CapabilityGrantId::new();
    child.issuer = parent_subject;
    child.subject = child_subject;
    child.parent_grant_ids = vec![parent.grant_id.clone()];
    child.max_delegation_depth = 1;

    let mut missing_parent = child.clone();
    missing_parent.parent_grant_ids.clear();
    assert_eq!(
        ensure_child_grant_narrows(&parent, &missing_parent)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:parent_grant_ids:missing_parent_grant_id"
    );

    let mut wrong_issuer = child.clone();
    wrong_issuer.issuer = PrincipalId::new();
    assert_eq!(
        ensure_child_grant_narrows(&parent, &wrong_issuer)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:issuer:child_issuer_not_parent_subject"
    );

    let mut exhausted_parent = parent.clone();
    exhausted_parent.max_delegation_depth = 0;
    assert_eq!(
        ensure_child_grant_narrows(&exhausted_parent, &child)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:max_delegation_depth:parent_delegation_depth_exhausted"
    );

    let mut broad_depth = child.clone();
    broad_depth.max_delegation_depth = 2;
    assert_eq!(
        ensure_child_grant_narrows(&parent, &broad_depth)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:max_delegation_depth:child_delegation_depth_broadened"
    );

    let mut broad_time = child.clone();
    broad_time.not_before = parent.not_before - time::Duration::seconds(1);
    assert_eq!(
        ensure_child_grant_narrows(&parent, &broad_time)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:time:child_time_window_broadened"
    );

    let mut extra_operation = child.clone();
    extra_operation
        .operations
        .push(gateway_adapter_operation("artifact-store"));
    assert_eq!(
        ensure_child_grant_narrows(&parent, &extra_operation)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:operations:child_operation_not_in_parent"
    );

    let mut dropped_obligation = child.clone();
    dropped_obligation.obligations.clear();
    assert_eq!(
        ensure_child_grant_narrows(&parent, &dropped_obligation)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:obligations:child_dropped_parent_obligation"
    );

    let mut removed_budget = child.clone();
    removed_budget.scope.budget.max_network_read_bytes = None;
    assert_eq!(
        ensure_child_grant_narrows(&parent, &removed_budget)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:budget.max_network_read_bytes:child_removed_budget_limit"
    );

    let mut increased_budget = child.clone();
    increased_budget.scope.budget.max_network_write_bytes = Some(21);
    assert_eq!(
        ensure_child_grant_narrows(&parent, &increased_budget)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:budget.max_network_write_bytes:child_budget_limit_increased"
    );

    let mut removed_not_before = child.clone();
    removed_not_before.scope.time.not_before = None;
    assert_eq!(
        ensure_child_grant_narrows(&parent, &removed_not_before)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:time.not_before:child_removed_not_before"
    );

    let mut removed_expires = child.clone();
    removed_expires.scope.time.expires_at = None;
    assert_eq!(
        ensure_child_grant_narrows(&parent, &removed_expires)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:time.expires_at:child_removed_expires_at"
    );

    let mut earlier_scope_start = child.clone();
    earlier_scope_start.scope.time.not_before = parent
        .scope
        .time
        .not_before
        .map(|not_before| not_before - time::Duration::seconds(1));
    assert_eq!(
        ensure_child_grant_narrows(&parent, &earlier_scope_start)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:time.not_before:child_started_earlier"
    );

    let mut later_scope_expiry = child;
    later_scope_expiry.scope.time.expires_at = parent
        .scope
        .time
        .expires_at
        .map(|expires_at| expires_at + time::Duration::seconds(1));
    assert_eq!(
        ensure_child_grant_narrows(&parent, &later_scope_expiry)
            .unwrap_err()
            .reason_code(),
        "narrowing_violation:time.expires_at:child_expires_later"
    );
}

#[test]
fn authority_containment_covers_scope_budget_and_data_purpose_denials() {
    let now = OffsetDateTime::now_utc();
    let issuer = PrincipalId::new();
    let subject = PrincipalId::new();
    let tenant = TenantId::new();
    let agent = AgentId::new();
    let run = RunId::new();
    let mut grant_scope = base_scope(tenant.clone(), agent.clone(), run.clone());
    grant_scope.workload_ids = Some(vec![WorkloadId::new()]);
    grant_scope.device_ids = Some(vec![DeviceId::new()]);
    grant_scope.data_purposes = Some(vec![DataPurpose::Read]);
    grant_scope.artifact_ids = Some(vec![ArtifactId::new()]);
    grant_scope.state_partition_ids = Some(vec![StatePartitionId::new()]);
    grant_scope.driver_operations = Some(vec![DriverOperationRef {
        driver: "filesystem".to_string(),
        operation: "read".to_string(),
        schema_version: "splendor.driver_operation.v1".to_string(),
    }]);
    grant_scope.time = AuthorityTimeScope {
        not_before: Some(now - time::Duration::minutes(1)),
        expires_at: Some(now + time::Duration::minutes(10)),
    };
    grant_scope.budget = AuthorityBudgetScope {
        max_actions_per_tick: Some(5),
        max_action_duration_ms: Some(10),
        max_filesystem_read_bytes: Some(100),
        max_http_requests_per_minute: Some(3),
        ..Default::default()
    };
    grant_scope.network = NetworkScope {
        egress_schemes: Some(vec!["https".to_string()]),
        egress_hosts: Some(vec!["api.example.test".to_string()]),
    };
    grant_scope.locality = LocalityScope {
        regions: Some(vec!["eu-west".to_string()]),
        zones: Some(vec!["zone-a".to_string()]),
        data_localities: Some(vec!["on_prem".to_string()]),
    };
    let capability_grant = grant(
        issuer,
        subject.clone(),
        gateway_action_operation("artifact.create"),
        grant_scope,
        now,
    );

    let mut request_scope = base_scope(tenant, agent, run);
    request_scope.workload_ids = Some(vec![WorkloadId::new()]);
    request_scope.device_ids = Some(vec![DeviceId::new()]);
    request_scope.data_purposes = Some(vec![DataPurpose::Publication]);
    request_scope.artifact_ids = Some(vec![ArtifactId::new()]);
    request_scope.state_partition_ids = Some(vec![StatePartitionId::new()]);
    request_scope.driver_operations = Some(vec![DriverOperationRef {
        driver: "filesystem".to_string(),
        operation: "write".to_string(),
        schema_version: "splendor.driver_operation.v1".to_string(),
    }]);
    request_scope.time = AuthorityTimeScope {
        not_before: Some(now - time::Duration::minutes(2)),
        expires_at: Some(now + time::Duration::minutes(20)),
    };
    request_scope.budget = AuthorityBudgetScope {
        max_actions_per_tick: Some(6),
        max_action_duration_ms: Some(20),
        max_network_read_bytes: Some(1),
        max_http_requests_per_minute: None,
        ..Default::default()
    };
    request_scope.network = NetworkScope {
        egress_schemes: Some(vec!["http".to_string()]),
        egress_hosts: Some(vec!["evil.example.test".to_string()]),
    };
    request_scope.locality = LocalityScope {
        regions: Some(vec!["us-east".to_string()]),
        zones: Some(vec!["zone-b".to_string()]),
        data_localities: Some(vec!["cloud".to_string()]),
    };
    let mut request = capability_request(
        subject,
        gateway_action_operation("artifact.create"),
        request_scope,
        now,
    );
    request.scope.budget.max_actions_per_tick = Some(6);

    let decision = evaluate_capability_request(&[validated(capability_grant)], &request, now);
    assert_eq!(decision.status, AuthorityDecisionStatus::Denied);
    for reason in [
        "workload_ids_not_granted",
        "device_ids_not_granted",
        "data_purposes_not_granted",
        "artifact_ids_not_granted",
        "state_partition_ids_not_granted",
        "driver_operations_not_granted",
        "time.not_before_precedes_grant",
        "time.expires_at_exceeds_grant",
        "budget.max_actions_per_tick_exceeds_grant",
        "budget.max_action_duration_ms_exceeds_grant",
        "budget.max_network_read_bytes_not_granted",
        "budget.max_http_requests_per_minute_missing_from_request",
        "network.egress_schemes_not_granted",
        "network.egress_hosts_not_granted",
        "locality.regions_not_granted",
        "locality.zones_not_granted",
        "locality.data_localities_not_granted",
    ] {
        assert!(
            decision.reasons.contains(&reason.to_string()),
            "missing {reason} in {:?}",
            decision.reasons
        );
    }

    let mut data_grant_scope = base_scope(TenantId::new(), AgentId::new(), RunId::new());
    data_grant_scope.data_purposes = Some(vec![DataPurpose::Publication]);
    let data_subject = PrincipalId::new();
    let data_grant = grant(
        PrincipalId::new(),
        data_subject.clone(),
        data_operation(AuthorityVerb::Publish),
        data_grant_scope.clone(),
        now,
    );
    let mut malformed_request_scope = data_grant_scope;
    malformed_request_scope.data_purposes = None;
    let malformed_request = CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject: data_subject,
        operation: data_operation(AuthorityVerb::Publish),
        scope: malformed_request_scope,
        requested_at: now,
        metadata: Default::default(),
    };
    let errors = grant_allows_request(&validated(data_grant), &malformed_request, now).unwrap_err();
    assert!(errors.iter().any(|error| {
        error.reason_code() == "data_purposes_missing_from_request"
            || error.reason_code() == "data_purpose_missing_for_operation"
    }));
}

#[test]
fn authority_compatibility_delegated_builder_and_reason_codes_cover_remaining_branches() {
    let now = OffsetDateTime::now_utc();
    let tenant = TenantId::new();
    let agent = AgentId::new();
    let delegated = DelegatedAuthority {
        allowed_actions: vec!["artifact.create".to_string()],
        allowed_adapters: vec!["artifact-store".to_string()],
        allowed_permissions: vec!["artifact.write".to_string()],
    };
    let built = grant_from_delegated_authority(
        CompatibilityGrantContext {
            grant_id: CapabilityGrantId::new(),
            issuer: PrincipalId::new(),
            subject: PrincipalId::new(),
            audience: "daemon:local".to_string(),
            validation_digest: DIGEST.to_string(),
            max_delegation_depth: 1,
            parent_grant_ids: Vec::new(),
        },
        LegacyScopeProfile {
            tenant_id: tenant,
            agent_id: agent,
            run_id: None,
            quotas: AuthorityBudgetScope {
                max_actions_per_tick: Some(1),
                ..Default::default()
            },
        },
        &delegated,
        now,
        now + time::Duration::minutes(10),
    )
    .unwrap();
    assert_eq!(built.grant().operations.len(), 3);

    for (error, expected) in [
        (
            AuthorityEvaluationError::InvalidOperation {
                reason: "x".to_string(),
            },
            "invalid_operation:x".to_string(),
        ),
        (
            AuthorityEvaluationError::EmptyIntersection {
                dimension: "tenant_ids",
            },
            "empty_intersection:tenant_ids".to_string(),
        ),
        (
            AuthorityEvaluationError::NarrowingViolation {
                dimension: "operations",
                reason: "child_operation_not_in_parent",
            },
            "narrowing_violation:operations:child_operation_not_in_parent".to_string(),
        ),
    ] {
        assert_eq!(error.reason_code(), expected);
    }
}

#[test]
fn authority_compatibility_builder_fails_closed_for_invalid_generated_profile() {
    let now = OffsetDateTime::now_utc();
    let invalid = grant_from_legacy_allowlists(
        CompatibilityGrantContext {
            grant_id: CapabilityGrantId::new(),
            issuer: PrincipalId::new(),
            subject: PrincipalId::new(),
            audience: "daemon:*".to_string(),
            validation_digest: DIGEST.to_string(),
            max_delegation_depth: 1,
            parent_grant_ids: Vec::new(),
        },
        LegacyScopeProfile {
            tenant_id: TenantId::new(),
            agent_id: AgentId::new(),
            run_id: Some(RunId::new()),
            quotas: AuthorityBudgetScope::default(),
        },
        &["artifact.create".to_string()],
        &[],
        &[],
        now - time::Duration::minutes(1),
        now + time::Duration::minutes(10),
        RevocationStatus::Active,
        None,
    );

    assert!(matches!(
        invalid,
        Err(AuthorityEvaluationError::InvalidToken {
            field: "audiences",
            ..
        })
    ));
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
    let grant = grant_from_work_order(context, &work_order).expect("validated work-order grant");
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
