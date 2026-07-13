use super::*;
use crate::capability::unchecked_validated_grant_for_tests;
use crate::{
    evaluate_capability_request, gateway_action_operation,
    grant_from_legacy_multi_scope_allowlists, CompatibilityGrantContext, LegacyMultiScopeProfile,
};
use splendor_types::{
    AuthorityBudgetScope, AuthorityDecisionStatus, AuthorityObligation, AuthorityObligationId,
    AuthorityObligationKind, AuthorityOperationNamespace, AuthorityResourceKind,
    AuthorityTimeScope, CapabilityGrantValidation, CapabilityGrantValidationKind,
    CapabilityRequest, DataPurpose, DeviceId, TenantId, AUTHORITY_OBLIGATION_SCHEMA_VERSION,
    TASK_RESPONSE_SCHEMA,
};

const DIGEST: &str = "blake3:3333333333333333333333333333333333333333333333333333333333333333";

#[derive(Clone)]
pub(crate) struct Fixture {
    pub(crate) now: OffsetDateTime,
    pub(crate) root_issuer: PrincipalId,
    pub(crate) parent_subject: PrincipalId,
    pub(crate) child_subject: PrincipalId,
    pub(crate) tenant_id: TenantId,
    pub(crate) parent_agent_id: AgentId,
    pub(crate) child_agent_id: AgentId,
    pub(crate) parent_run_id: RunId,
    pub(crate) child_run_id: RunId,
    pub(crate) audience: String,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        Self {
            now: OffsetDateTime::now_utc(),
            root_issuer: PrincipalId::new(),
            parent_subject: PrincipalId::new(),
            child_subject: PrincipalId::new(),
            tenant_id: TenantId::new(),
            parent_agent_id: AgentId::new(),
            child_agent_id: AgentId::new(),
            parent_run_id: RunId::new(),
            child_run_id: RunId::new(),
            audience: "daemon:local".to_string(),
        }
    }
}

fn validation() -> CapabilityGrantValidation {
    CapabilityGrantValidation {
        validation_kind: CapabilityGrantValidationKind::LocallyValidated,
        algorithm: "local-test-v1".to_string(),
        key_id: None,
        digest: DIGEST.to_string(),
        signature: None,
    }
}

fn gateway_scope(fixture: &Fixture) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![fixture.tenant_id.clone()]),
        agent_ids: Some(vec![fixture.child_agent_id.clone()]),
        run_ids: Some(vec![fixture.child_run_id.clone()]),
        audiences: Some(vec![fixture.audience.clone()]),
        time: AuthorityTimeScope {
            not_before: Some(fixture.now - time::Duration::minutes(1)),
            expires_at: Some(fixture.now + time::Duration::minutes(20)),
        },
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(5),
            max_action_duration_ms: Some(1_000),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn child_gateway_scope(fixture: &Fixture) -> CapabilityScope {
    let mut scope = gateway_scope(fixture);
    scope.time = AuthorityTimeScope {
        not_before: Some(fixture.now),
        expires_at: Some(fixture.now + time::Duration::minutes(5)),
    };
    scope.budget.max_actions_per_tick = Some(2);
    scope.budget.max_action_duration_ms = Some(500);
    scope
}

fn device_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: splendor_types::AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Device,
        resource_kind: AuthorityResourceKind::Device,
        verb: AuthorityVerb::Actuate,
        name: None,
        resource_schema_version: Some("splendor.device_action.v1".to_string()),
    }
}

fn agent_delegate_operation() -> AuthorityOperation {
    AuthorityOperation {
        schema_version: splendor_types::AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Agent,
        resource_kind: AuthorityResourceKind::Agent,
        verb: AuthorityVerb::Delegate,
        name: None,
        resource_schema_version: Some("splendor.agent.v1".to_string()),
    }
}

fn device_scope(fixture: &Fixture) -> CapabilityScope {
    let mut scope = child_gateway_scope(fixture);
    scope.device_ids = Some(vec![DeviceId::new()]);
    scope
}

fn parent_grant_with(
    fixture: &Fixture,
    operations: Vec<AuthorityOperation>,
    scope: CapabilityScope,
    max_delegation_depth: u32,
) -> ValidatedCapabilityGrant {
    unchecked_validated_grant_for_tests(CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: CapabilityGrantId::new(),
        issuer: fixture.root_issuer.clone(),
        subject: fixture.parent_subject.clone(),
        parent_grant_ids: Vec::new(),
        operations,
        scope,
        not_before: fixture.now - time::Duration::minutes(5),
        expires_at: fixture.now + time::Duration::minutes(30),
        revocation_ref: Some("revocation:parent".to_string()),
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth,
        validation: Some(validation()),
        metadata: Default::default(),
    })
}

pub(crate) fn parent_grant(fixture: &Fixture) -> ValidatedCapabilityGrant {
    parent_grant_with(
        fixture,
        vec![gateway_action_operation("artifact.create")],
        gateway_scope(fixture),
        2,
    )
}

fn multi_scope_parent_grant(
    fixture: &Fixture,
    agent_ids: Vec<AgentId>,
    run_ids: Vec<RunId>,
) -> ValidatedCapabilityGrant {
    grant_from_legacy_multi_scope_allowlists(
        CompatibilityGrantContext {
            grant_id: CapabilityGrantId::new(),
            issuer: fixture.root_issuer.clone(),
            subject: fixture.parent_subject.clone(),
            audience: fixture.audience.clone(),
            validation_digest: DIGEST.to_string(),
            max_delegation_depth: 2,
            parent_grant_ids: Vec::new(),
        },
        LegacyMultiScopeProfile {
            tenant_id: fixture.tenant_id.clone(),
            agent_ids,
            run_ids,
            quotas: AuthorityBudgetScope {
                max_actions_per_tick: Some(5),
                max_action_duration_ms: Some(1_000),
                ..Default::default()
            },
        },
        &["artifact.create".to_string()],
        &[],
        &[],
        fixture.now - time::Duration::minutes(5),
        fixture.now + time::Duration::minutes(30),
        RevocationStatus::Active,
        Some("revocation:multi-scope-parent".to_string()),
    )
    .expect("bounded multi-scope parent grant")
}

fn request_for_agent_run(
    fixture: &Fixture,
    parent: &ValidatedCapabilityGrant,
    child_agent_id: AgentId,
    child_run_id: RunId,
) -> DelegationChildGrantRequest {
    let mut request = request_for(fixture, parent);
    request.child_agent_id = child_agent_id.clone();
    request.child_run_id = child_run_id.clone();
    request.scope.agent_ids = Some(vec![child_agent_id]);
    request.scope.run_ids = Some(vec![child_run_id]);
    request.scope.time = AuthorityTimeScope::default();
    request
}

fn result_contract() -> DelegationResultContract {
    DelegationResultContract {
        schema_version: DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION.to_string(),
        result_schema: TASK_RESPONSE_SCHEMA.to_string(),
        requires_response: true,
        max_result_bytes: Some(4096),
    }
}

pub(crate) fn request_for(
    fixture: &Fixture,
    parent: &ValidatedCapabilityGrant,
) -> DelegationChildGrantRequest {
    DelegationChildGrantRequest {
        parent_grant_id: Some(parent.grant().grant_id.clone()),
        issuer: fixture.parent_subject.clone(),
        child_subject: Some(fixture.child_subject.clone()),
        child_grant_id: CapabilityGrantId::new(),
        parent_run_id: fixture.parent_run_id.clone(),
        parent_agent_id: fixture.parent_agent_id.clone(),
        child_run_id: fixture.child_run_id.clone(),
        child_agent_id: fixture.child_agent_id.clone(),
        objective: "summarize bounded artifact".to_string(),
        role_profile: DelegationRoleProfile::Specialist,
        operations: vec![gateway_action_operation("artifact.create")],
        scope: child_gateway_scope(fixture),
        allowed_message_schemas: vec![TASK_RESPONSE_SCHEMA.to_string()],
        allowed_recipient_agent_ids: vec![fixture.parent_agent_id.clone()],
        result_contract: result_contract(),
        not_before: fixture.now,
        expires_at: fixture.now + time::Duration::minutes(5),
        max_delegation_depth: 1,
        max_fan_out: 3,
        validation_digest: DIGEST.to_string(),
    }
}

fn context_for(fixture: &Fixture) -> DelegationValidationContext {
    DelegationValidationContext {
        now: fixture.now,
        audience: fixture.audience.clone(),
        expected_child_subject: fixture.child_subject.clone(),
        parent_fan_out_limit: 3,
        current_parent_fan_out: 0,
    }
}

fn reason_for(
    parent: &ValidatedCapabilityGrant,
    request: DelegationChildGrantRequest,
    context: DelegationValidationContext,
) -> &'static str {
    issue_delegation_child_grant(parent, request, context)
        .expect_err("delegation should fail")
        .reason_code()
}

#[test]
fn delegation_builds_narrow_child_capability_grant() {
    let fixture = Fixture::new();
    let parent = parent_grant(&fixture);
    let request = request_for(&fixture, &parent);
    let context = context_for(&fixture);

    let result = issue_delegation_child_grant(&parent, request.clone(), context)
        .expect("delegation child grant should be issued");

    let delegation = result.delegation_grant();
    assert_eq!(delegation.schema_version, DELEGATION_GRANT_SCHEMA_VERSION);
    assert_eq!(delegation.parent_grant_id, parent.grant().grant_id);
    assert_eq!(delegation.parent_run_id, fixture.parent_run_id);
    assert_eq!(delegation.child_run_id, fixture.child_run_id);
    assert_eq!(delegation.child_agent_id, fixture.child_agent_id);
    assert_eq!(delegation.objective, "summarize bounded artifact");
    assert_eq!(delegation.role_profile, DelegationRoleProfile::Specialist);
    assert_eq!(delegation.remaining_delegation_depth, 1);
    assert_eq!(delegation.max_fan_out, 3);
    assert_eq!(
        delegation.child_capability_grant.parent_grant_ids,
        vec![parent.grant().grant_id.clone()]
    );
    assert_eq!(
        delegation.child_capability_grant.subject,
        fixture.child_subject
    );

    let mut eval_scope = request.scope;
    eval_scope.budget.max_actions_per_tick = Some(1);
    let child_request = CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject: fixture.child_subject,
        operation: gateway_action_operation("artifact.create"),
        scope: eval_scope,
        requested_at: fixture.now,
        metadata: Default::default(),
    };
    let decision = evaluate_capability_request(
        std::slice::from_ref(result.child_grant()),
        &child_request,
        fixture.now,
    );
    assert_eq!(decision.status, AuthorityDecisionStatus::Allowed);

    let consumed_child_grant = result.clone().into_child_grant();
    assert_eq!(
        consumed_child_grant.grant().grant_id,
        result.child_grant().grant().grant_id
    );
}

#[test]
fn delegation_multi_scope_parent_denies_unlisted_child_agent() {
    let fixture = Fixture::new();
    let listed_agent = AgentId::new();
    let listed_run = RunId::new();
    let parent = multi_scope_parent_grant(
        &fixture,
        vec![fixture.child_agent_id.clone(), listed_agent.clone()],
        vec![fixture.child_run_id.clone(), listed_run],
    );

    let listed_control = request_for_agent_run(
        &fixture,
        &parent,
        listed_agent,
        fixture.child_run_id.clone(),
    );
    issue_delegation_child_grant(&parent, listed_control, context_for(&fixture))
        .expect("listed agent and listed run Cartesian combination succeeds");

    let unlisted_agent = AgentId::new();
    let denied = request_for_agent_run(
        &fixture,
        &parent,
        unlisted_agent,
        fixture.child_run_id.clone(),
    );
    assert_eq!(
        reason_for(&parent, denied, context_for(&fixture)),
        "overbroad_scope"
    );
}

#[test]
fn delegation_multi_scope_parent_denies_unlisted_child_run() {
    let fixture = Fixture::new();
    let listed_agent = AgentId::new();
    let listed_run = RunId::new();
    let parent = multi_scope_parent_grant(
        &fixture,
        vec![fixture.child_agent_id.clone(), listed_agent],
        vec![fixture.child_run_id.clone(), listed_run.clone()],
    );

    let listed_control = request_for_agent_run(
        &fixture,
        &parent,
        fixture.child_agent_id.clone(),
        listed_run,
    );
    issue_delegation_child_grant(&parent, listed_control, context_for(&fixture))
        .expect("listed agent and listed run Cartesian combination succeeds");

    let denied = request_for_agent_run(
        &fixture,
        &parent,
        fixture.child_agent_id.clone(),
        RunId::new(),
    );
    assert_eq!(
        reason_for(&parent, denied, context_for(&fixture)),
        "overbroad_scope"
    );
}

#[test]
fn delegation_denies_conditional_parent_obligations_before_child_grant_creation() {
    let fixture = Fixture::new();
    let mut parent_grant = parent_grant(&fixture).grant().clone();
    let obligation = AuthorityObligation {
        schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
        obligation_id: AuthorityObligationId::new(),
        kind: AuthorityObligationKind::EvidenceRequired,
        description: "evidence.required".to_string(),
        parameters: Default::default(),
    };
    parent_grant.obligations = vec![obligation.clone()];
    let parent = unchecked_validated_grant_for_tests(parent_grant);
    let request = request_for(&fixture, &parent);

    let reason = issue_delegation_child_grant(&parent, request.clone(), context_for(&fixture))
        .expect_err("conditional parent obligations must block child issuance")
        .reason_code();

    assert_eq!(reason, "parent_obligations_unsatisfied");

    let raw_child = build_raw_child_grant(
        &request,
        &fixture.child_subject,
        &parent.grant().grant_id,
        &parent.grant().obligations,
    );
    assert_eq!(raw_child.obligations, vec![obligation]);
}

#[test]
fn delegation_child_grant_evaluation_still_returns_conditional_when_obligations_exist() {
    let fixture = Fixture::new();
    let parent = parent_grant(&fixture);
    let request = request_for(&fixture, &parent);
    let obligation = AuthorityObligation {
        schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
        obligation_id: AuthorityObligationId::new(),
        kind: AuthorityObligationKind::EvidenceRequired,
        description: "evidence.required".to_string(),
        parameters: Default::default(),
    };
    let mut raw_child = build_raw_child_grant(
        &request,
        &fixture.child_subject,
        &parent.grant().grant_id,
        std::slice::from_ref(&obligation),
    );
    raw_child.parent_grant_ids = Vec::new();
    let child = unchecked_validated_grant_for_tests(raw_child);
    let decision = evaluate_capability_request(
        std::slice::from_ref(&child),
        &CapabilityRequest {
            schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
            subject: fixture.child_subject,
            operation: gateway_action_operation("artifact.create"),
            scope: request.scope,
            requested_at: fixture.now,
            metadata: Default::default(),
        },
        fixture.now,
    );
    assert_eq!(decision.status, AuthorityDecisionStatus::Conditional);
    assert_eq!(decision.obligations, vec![obligation]);
}

#[test]
fn delegation_denies_missing_parent_edge_wrong_issuer_and_child_subject_errors() {
    let fixture = Fixture::new();
    let parent = parent_grant(&fixture);
    let context = context_for(&fixture);

    let mut missing_edge = request_for(&fixture, &parent);
    missing_edge.parent_grant_id = None;
    assert_eq!(
        reason_for(&parent, missing_edge, context.clone()),
        "missing_parent_edge"
    );

    let mut wrong_edge = request_for(&fixture, &parent);
    wrong_edge.parent_grant_id = Some(CapabilityGrantId::new());
    assert_eq!(
        reason_for(&parent, wrong_edge, context.clone()),
        "missing_parent_edge"
    );

    let mut wrong_issuer = request_for(&fixture, &parent);
    wrong_issuer.issuer = PrincipalId::new();
    assert_eq!(
        reason_for(&parent, wrong_issuer, context.clone()),
        "issuer_not_parent_subject"
    );

    let mut missing_subject = request_for(&fixture, &parent);
    missing_subject.child_subject = None;
    assert_eq!(
        reason_for(&parent, missing_subject, context.clone()),
        "child_subject_missing"
    );

    let mut nil_subject = request_for(&fixture, &parent);
    nil_subject.child_subject =
        Some(PrincipalId::parse("00000000-0000-0000-0000-000000000000").expect("nil principal id"));
    assert_eq!(
        reason_for(&parent, nil_subject, context.clone()),
        "child_subject_missing"
    );

    let mut wrong_subject = request_for(&fixture, &parent);
    wrong_subject.child_subject = Some(PrincipalId::new());
    assert_eq!(
        reason_for(&parent, wrong_subject, context),
        "child_subject_wrong"
    );
}

#[test]
fn delegation_denies_invalid_identity_objective_context_and_result_contracts() {
    let fixture = Fixture::new();
    let parent = parent_grant(&fixture);
    let context = context_for(&fixture);

    let mut nil_child_grant = request_for(&fixture, &parent);
    nil_child_grant.child_grant_id =
        CapabilityGrantId::parse("00000000-0000-0000-0000-000000000000").expect("nil grant id");
    assert_eq!(
        reason_for(&parent, nil_child_grant, context.clone()),
        "invalid_delegation_identity"
    );

    let mut nil_parent_run = request_for(&fixture, &parent);
    nil_parent_run.parent_run_id =
        RunId::parse("00000000-0000-0000-0000-000000000000").expect("nil run id");
    assert_eq!(
        reason_for(&parent, nil_parent_run, context.clone()),
        "invalid_delegation_identity"
    );

    let mut same_child_run = request_for(&fixture, &parent);
    same_child_run.child_run_id = same_child_run.parent_run_id.clone();
    same_child_run.scope.run_ids = Some(vec![same_child_run.child_run_id.clone()]);
    assert_eq!(
        reason_for(&parent, same_child_run, context.clone()),
        "invalid_delegation_identity"
    );

    let mut nil_parent_agent = request_for(&fixture, &parent);
    nil_parent_agent.parent_agent_id =
        AgentId::parse("00000000-0000-0000-0000-000000000000").expect("nil agent id");
    assert_eq!(
        reason_for(&parent, nil_parent_agent, context.clone()),
        "invalid_delegation_identity"
    );

    let mut same_child_agent = request_for(&fixture, &parent);
    same_child_agent.child_agent_id = same_child_agent.parent_agent_id.clone();
    same_child_agent.scope.agent_ids = Some(vec![same_child_agent.child_agent_id.clone()]);
    assert_eq!(
        reason_for(&parent, same_child_agent, context.clone()),
        "invalid_delegation_identity"
    );

    let mut missing_objective = request_for(&fixture, &parent);
    missing_objective.objective = "   ".to_string();
    assert_eq!(
        reason_for(&parent, missing_objective, context.clone()),
        "missing_objective"
    );

    let mut nil_expected_subject_context = context.clone();
    nil_expected_subject_context.expected_child_subject =
        PrincipalId::parse("00000000-0000-0000-0000-000000000000").expect("nil principal id");
    assert_eq!(
        reason_for(
            &parent,
            request_for(&fixture, &parent),
            nil_expected_subject_context,
        ),
        "child_subject_wrong"
    );

    let mut bad_audience_context = context.clone();
    bad_audience_context.audience = "daemon:*".to_string();
    assert_eq!(
        reason_for(
            &parent,
            request_for(&fixture, &parent),
            bad_audience_context
        ),
        "overbroad_audience"
    );

    let mut invalid_time = request_for(&fixture, &parent);
    invalid_time.expires_at = invalid_time.not_before;
    assert_eq!(
        reason_for(&parent, invalid_time, context.clone()),
        "overbroad_time"
    );

    let mut bad_digest = request_for(&fixture, &parent);
    bad_digest.validation_digest = "blake3:*".to_string();
    assert_eq!(
        reason_for(&parent, bad_digest, context.clone()),
        "child_grant_invalid"
    );

    let mut bad_result_schema_version = request_for(&fixture, &parent);
    bad_result_schema_version.result_contract.schema_version = "bad.schema.v1".to_string();
    assert_eq!(
        reason_for(&parent, bad_result_schema_version, context.clone()),
        "bad_result_contract"
    );

    let mut bad_result_schema = request_for(&fixture, &parent);
    bad_result_schema.result_contract.result_schema =
        "splendor.message.task_response.v2".to_string();
    assert_eq!(
        reason_for(&parent, bad_result_schema, context.clone()),
        "bad_result_contract"
    );

    let mut zero_result_bytes = request_for(&fixture, &parent);
    zero_result_bytes.result_contract.max_result_bytes = Some(0);
    assert_eq!(
        reason_for(&parent, zero_result_bytes, context),
        "bad_result_contract"
    );
}

#[test]
fn delegation_denies_overbroad_operation_scope_audience_time_and_budget() {
    let fixture = Fixture::new();
    let parent = parent_grant(&fixture);
    let context = context_for(&fixture);

    let mut overbroad_operation = request_for(&fixture, &parent);
    overbroad_operation.operations = vec![gateway_action_operation("artifact.publish")];
    assert_eq!(
        reason_for(&parent, overbroad_operation, context.clone()),
        "overbroad_operation"
    );

    let mut overbroad_scope = request_for(&fixture, &parent);
    overbroad_scope.scope.agent_ids = Some(vec![AgentId::new()]);
    assert_eq!(
        reason_for(&parent, overbroad_scope, context.clone()),
        "overbroad_scope"
    );

    let mut overbroad_audience = request_for(&fixture, &parent);
    overbroad_audience.scope.audiences = Some(vec!["daemon:other".to_string()]);
    assert_eq!(
        reason_for(&parent, overbroad_audience, context.clone()),
        "overbroad_audience"
    );

    let mut overbroad_time = request_for(&fixture, &parent);
    overbroad_time.expires_at = fixture.now + time::Duration::hours(2);
    assert_eq!(
        reason_for(&parent, overbroad_time, context.clone()),
        "overbroad_time"
    );

    let mut overbroad_budget = request_for(&fixture, &parent);
    overbroad_budget.scope.budget.max_actions_per_tick = Some(10);
    assert_eq!(
        reason_for(&parent, overbroad_budget, context),
        "overbroad_budget"
    );
}

#[test]
fn delegation_denies_exhausted_depth_and_fan_out_cap() {
    let fixture = Fixture::new();
    let depth_exhausted_parent = parent_grant_with(
        &fixture,
        vec![gateway_action_operation("artifact.create")],
        gateway_scope(&fixture),
        0,
    );
    assert_eq!(
        reason_for(
            &depth_exhausted_parent,
            request_for(&fixture, &depth_exhausted_parent),
            context_for(&fixture),
        ),
        "delegation_depth_exhausted"
    );

    let parent = parent_grant(&fixture);

    let mut overbroad_depth = request_for(&fixture, &parent);
    overbroad_depth.max_delegation_depth = 2;
    assert_eq!(
        reason_for(&parent, overbroad_depth, context_for(&fixture)),
        "overbroad_delegation_depth"
    );

    let mut overbroad_fan_out = request_for(&fixture, &parent);
    overbroad_fan_out.max_fan_out = 4;
    assert_eq!(
        reason_for(&parent, overbroad_fan_out, context_for(&fixture)),
        "overbroad_fan_out"
    );

    let mut zero_fan_out = request_for(&fixture, &parent);
    zero_fan_out.max_fan_out = 0;
    assert_eq!(
        reason_for(&parent, zero_fan_out, context_for(&fixture)),
        "overbroad_fan_out"
    );

    let mut context = context_for(&fixture);
    context.current_parent_fan_out = 3;
    let mut request = request_for(&fixture, &parent);
    request.max_fan_out = 3;
    assert_eq!(reason_for(&parent, request, context), "fan_out_exceeded");

    let mut narrowed_cap_context = context_for(&fixture);
    narrowed_cap_context.current_parent_fan_out = 2;
    let mut narrowed_cap_request = request_for(&fixture, &parent);
    narrowed_cap_request.max_fan_out = 2;
    assert_eq!(
        reason_for(&parent, narrowed_cap_request, narrowed_cap_context),
        "fan_out_exceeded"
    );
}

#[test]
fn delegation_reason_mappers_cover_remaining_stable_codes() {
    assert_eq!(
        DelegationGrantError::BadResultContract {
            reason: "invalid_result_contract_schema".to_string(),
        }
        .to_string(),
        "delegation result contract is invalid: invalid_result_contract_schema"
    );
    assert_eq!(
        DelegationGrantError::InvalidIdentity {
            field: "child_run_id",
        }
        .to_string(),
        "delegation identity is invalid: child_run_id"
    );

    for (reasons, expected) in [
        (vec!["revoked_grant".to_string()], "parent_revoked"),
        (vec!["expired_grant".to_string()], "parent_expired"),
        (
            vec!["scope_time_not_yet_valid".to_string()],
            "parent_not_yet_valid",
        ),
        (
            vec!["operation_not_granted".to_string()],
            "overbroad_operation",
        ),
        (
            vec!["audience_not_granted".to_string()],
            "overbroad_audience",
        ),
        (
            vec!["time.expires_at_exceeds_grant".to_string()],
            "overbroad_time",
        ),
        (
            vec!["budget.max_actions_per_tick_exceeds_grant".to_string()],
            "overbroad_budget",
        ),
        (vec!["run_ids_not_granted".to_string()], "overbroad_scope"),
        (Vec::new(), "parent_grant_invalid"),
    ] {
        assert_eq!(map_parent_denial(&reasons).reason_code(), expected);
    }
    assert_eq!(
        DelegationGrantError::ParentObligationsUnsatisfied.reason_code(),
        "parent_obligations_unsatisfied"
    );

    for (dimension, reason, expected) in [
        (
            "parent_grant_ids",
            "missing_parent_grant_id",
            "missing_parent_edge",
        ),
        (
            "issuer",
            "child_issuer_not_parent_subject",
            "issuer_not_parent_subject",
        ),
        (
            "max_delegation_depth",
            "parent_delegation_depth_exhausted",
            "delegation_depth_exhausted",
        ),
        (
            "max_delegation_depth",
            "child_delegation_depth_broadened",
            "overbroad_delegation_depth",
        ),
        (
            "operations",
            "child_operation_not_in_parent",
            "overbroad_operation",
        ),
        (
            "audiences",
            "child_value_not_in_parent",
            "overbroad_audience",
        ),
        ("time", "child_time_window_broadened", "overbroad_time"),
        (
            "budget.max_actions_per_tick",
            "child_budget_broadened",
            "overbroad_budget",
        ),
        ("agent_ids", "child_value_not_in_parent", "overbroad_scope"),
    ] {
        assert_eq!(
            map_narrowing_error(AuthorityEvaluationError::NarrowingViolation { dimension, reason })
                .reason_code(),
            expected
        );
    }
    assert_eq!(
        map_narrowing_error(AuthorityEvaluationError::InvalidToken {
            field: "validation_digest",
            value: "*".to_string(),
        })
        .reason_code(),
        "child_grant_invalid"
    );
}

#[test]
fn delegation_external_effect_classifier_covers_role_restriction_surface() {
    assert!(is_external_effect_operation(&gateway_action_operation(
        "artifact.create"
    )));
    assert!(is_external_effect_operation(&agent_delegate_operation()));
    assert!(is_external_effect_operation(&AuthorityOperation {
        schema_version: splendor_types::AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Network,
        resource_kind: AuthorityResourceKind::Network,
        verb: AuthorityVerb::Egress,
        name: None,
        resource_schema_version: Some("splendor.network.v1".to_string()),
    }));
    assert!(is_external_effect_operation(&AuthorityOperation {
        schema_version: splendor_types::AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Artifact,
        resource_kind: AuthorityResourceKind::Artifact,
        verb: AuthorityVerb::Publish,
        name: None,
        resource_schema_version: Some("splendor.artifact.v1".to_string()),
    }));
    assert!(is_external_effect_operation(&AuthorityOperation {
        schema_version: splendor_types::AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::State,
        resource_kind: AuthorityResourceKind::StatePartition,
        verb: AuthorityVerb::Write,
        name: None,
        resource_schema_version: Some("splendor.state_partition.v1".to_string()),
    }));
    assert!(is_external_effect_operation(&AuthorityOperation {
        schema_version: splendor_types::AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Workload,
        resource_kind: AuthorityResourceKind::Workload,
        verb: AuthorityVerb::Invoke,
        name: None,
        resource_schema_version: Some("splendor.workload.v1".to_string()),
    }));
    assert!(is_external_effect_operation(&AuthorityOperation {
        schema_version: splendor_types::AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Change,
        resource_kind: AuthorityResourceKind::Change,
        verb: AuthorityVerb::Activate,
        name: None,
        resource_schema_version: Some("splendor.change.v1".to_string()),
    }));
    assert!(is_external_effect_operation(&AuthorityOperation {
        schema_version: splendor_types::AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Data,
        resource_kind: AuthorityResourceKind::Data,
        verb: AuthorityVerb::Publish,
        name: None,
        resource_schema_version: Some("splendor.data_use.v1".to_string()),
    }));
    assert!(!is_external_effect_operation(&AuthorityOperation {
        schema_version: splendor_types::AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Device,
        resource_kind: AuthorityResourceKind::Device,
        verb: AuthorityVerb::Read,
        name: None,
        resource_schema_version: Some("splendor.device_action.v1".to_string()),
    }));
}

#[test]
fn delegation_denies_missing_or_bad_message_schema_and_recipient() {
    let fixture = Fixture::new();
    let parent = parent_grant(&fixture);
    let context = context_for(&fixture);

    let mut missing_schema = request_for(&fixture, &parent);
    missing_schema.allowed_message_schemas.clear();
    assert_eq!(
        reason_for(&parent, missing_schema, context.clone()),
        "missing_message_schema"
    );

    let mut bad_schema = request_for(&fixture, &parent);
    bad_schema.allowed_message_schemas = vec!["splendor.message.*.v1".to_string()];
    assert_eq!(
        reason_for(&parent, bad_schema, context.clone()),
        "bad_message_schema"
    );

    let mut missing_recipient = request_for(&fixture, &parent);
    missing_recipient.allowed_recipient_agent_ids.clear();
    assert_eq!(
        reason_for(&parent, missing_recipient, context.clone()),
        "missing_message_recipient"
    );

    let mut bad_recipient = request_for(&fixture, &parent);
    bad_recipient.allowed_recipient_agent_ids =
        vec![AgentId::parse("00000000-0000-0000-0000-000000000000").expect("nil agent id")];
    assert_eq!(
        reason_for(&parent, bad_recipient, context),
        "bad_message_recipient"
    );
}

#[test]
fn delegation_denies_revoked_expired_and_not_yet_valid_parent() {
    let fixture = Fixture::new();
    let mut revoked_parent = parent_grant(&fixture).grant().clone();
    revoked_parent.revocation = RevocationStatus::Revoked {
        reason: "test_revocation".to_string(),
    };
    let revoked_parent = unchecked_validated_grant_for_tests(revoked_parent);
    assert_eq!(
        reason_for(
            &revoked_parent,
            request_for(&fixture, &revoked_parent),
            context_for(&fixture),
        ),
        "parent_revoked"
    );

    let mut expired_parent = parent_grant(&fixture).grant().clone();
    expired_parent.expires_at = fixture.now - time::Duration::seconds(1);
    let expired_parent = unchecked_validated_grant_for_tests(expired_parent);
    assert_eq!(
        reason_for(
            &expired_parent,
            request_for(&fixture, &expired_parent),
            context_for(&fixture),
        ),
        "parent_expired"
    );

    let mut not_yet_valid_parent = parent_grant(&fixture).grant().clone();
    not_yet_valid_parent.not_before = fixture.now + time::Duration::minutes(1);
    let not_yet_valid_parent = unchecked_validated_grant_for_tests(not_yet_valid_parent);
    assert_eq!(
        reason_for(
            &not_yet_valid_parent,
            request_for(&fixture, &not_yet_valid_parent),
            context_for(&fixture),
        ),
        "parent_not_yet_valid"
    );
}

#[test]
fn delegation_denies_critic_and_evaluator_external_effect_operations() {
    for role in [
        DelegationRoleProfile::Critic,
        DelegationRoleProfile::Evaluator,
    ] {
        let fixture = Fixture::new();
        let parent = parent_grant_with(
            &fixture,
            vec![device_operation()],
            device_scope(&fixture),
            2,
        );
        let mut request = request_for(&fixture, &parent);
        request.role_profile = role;
        request.operations = vec![device_operation()];
        request.scope = device_scope(&fixture);

        assert_eq!(
            reason_for(&parent, request, context_for(&fixture)),
            "critic_evaluator_external_effect_operation"
        );
    }
}

#[test]
fn delegation_denies_critic_and_evaluator_control_plane_delegation() {
    for role in [
        DelegationRoleProfile::Critic,
        DelegationRoleProfile::Evaluator,
    ] {
        let fixture = Fixture::new();
        let operation = agent_delegate_operation();
        let parent = parent_grant_with(
            &fixture,
            vec![operation.clone()],
            child_gateway_scope(&fixture),
            2,
        );
        let mut request = request_for(&fixture, &parent);
        request.role_profile = role;
        request.operations = vec![operation];

        assert_eq!(
            reason_for(&parent, request, context_for(&fixture)),
            "critic_evaluator_external_effect_operation"
        );
    }
}

#[test]
fn delegation_allows_critic_read_or_evaluate_non_external_operation() {
    let fixture = Fixture::new();
    let evaluate_operation = AuthorityOperation {
        schema_version: splendor_types::AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Data,
        resource_kind: AuthorityResourceKind::Data,
        verb: AuthorityVerb::Evaluate,
        name: None,
        resource_schema_version: Some("splendor.data_use.v1".to_string()),
    };
    let mut scope = child_gateway_scope(&fixture);
    scope.data_purposes = Some(vec![DataPurpose::EvaluationUse]);
    let parent = parent_grant_with(&fixture, vec![evaluate_operation.clone()], scope.clone(), 2);
    let mut request = request_for(&fixture, &parent);
    request.role_profile = DelegationRoleProfile::Critic;
    request.operations = vec![evaluate_operation];
    request.scope = scope;

    issue_delegation_child_grant(&parent, request, context_for(&fixture))
        .expect("critic can receive non-external evaluation authority");
}
