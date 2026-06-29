use super::*;
use crate::capability::unchecked_validated_grant_for_tests;
use crate::{
    compatibility_permission_operation, evaluate_capability_request, gateway_action_operation,
    gateway_adapter_operation, workload_admit_operation,
};
use splendor_types::{
    AgentId, AuthorityBudgetScope, AuthorityDecisionStatus, AuthorityOperation, AuthorityTimeScope,
    CapabilityGrant, CapabilityGrantId, CapabilityGrantValidation, CapabilityGrantValidationKind,
    CapabilityRequest, CapabilityScope, IdentityRevision, PrincipalBinding, PrincipalDisplay,
    PrincipalId, PrincipalKind, PrincipalProofRef, PrincipalProofRefId, PrincipalStatus,
    RevocationStatus, RunId, TenantId, WorkOrder, WorkOrderEnvelope, WorkOrderId, WorkOrderKeyring,
    WorkOrderPlacement, WorkOrderQuotaPolicy, WorkOrderValidationContext,
    CAPABILITY_GRANT_SCHEMA_VERSION, CAPABILITY_REQUEST_SCHEMA_VERSION,
    CAPABILITY_SCOPE_SCHEMA_VERSION, WORK_ORDER_SCHEMA_VERSION,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;

const AUDIENCE: &str = "daemon:local";
const KEY_ID: &str = "auth002-work-order-key";
const SECRET: &[u8] = b"auth002-shared-secret-that-must-not-leak";
const BAD_SIGNATURE: &str = "detached-signature-that-must-not-leak";
const DIGEST: &str = "blake3:2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn valid_signed_work_order_issues_signed_grant_for_listed_allowlists_only() {
    let now = OffsetDateTime::now_utc();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let issuer = issuer_principal(tenant_id.clone(), PrincipalStatus::Active, KEY_ID);
    let subject = subject_principal(agent_id.clone(), tenant_id.clone(), PrincipalStatus::Active);
    let work_order = work_order(&tenant_id, &agent_id, &run_id, now);
    let envelope = signed_envelope(work_order.clone());
    let keyring = keyring();
    let validation_context = validation_context(&work_order, now);
    let issuer_grant = issuer_admit_grant(
        issuer.principal_id.clone(),
        tenant_id.clone(),
        agent_id.clone(),
        run_id.clone(),
        now,
        AuthorityBudgetScope {
            max_actions_per_tick: Some(5),
            ..Default::default()
        },
        None,
    );

    let result = issue_work_order_capability_grant(WorkOrderGrantIssuance {
        envelope: &envelope,
        validation_context: &validation_context,
        keyring: &keyring,
        issuer: &issuer,
        subject: &subject,
        issuer_grants: std::slice::from_ref(&issuer_grant),
        audience: AUDIENCE.to_string(),
        issued_grant_id: CapabilityGrantId::new(),
    })
    .expect("signed work order should issue grant");

    assert_eq!(
        result.validated_work_order().work_order().work_order_id,
        work_order.work_order_id
    );
    assert_eq!(
        result.issuer_decision().status,
        AuthorityDecisionStatus::Allowed
    );
    assert_eq!(
        result
            .issued_grant()
            .grant()
            .validation
            .as_ref()
            .expect("grant validation")
            .validation_kind,
        CapabilityGrantValidationKind::Signed
    );

    let grant = result.issued_grant().clone();
    let scope = issued_grant_scope(tenant_id, agent_id, run_id);
    let allowed_action = decision_for_issued_grant(
        &grant,
        subject.principal_id.clone(),
        gateway_action_operation("artifact.create"),
        scope.clone(),
        now,
    );
    let allowed_adapter = decision_for_issued_grant(
        &grant,
        subject.principal_id.clone(),
        gateway_adapter_operation("artifact-store"),
        scope.clone(),
        now,
    );
    let allowed_permission = decision_for_issued_grant(
        &grant,
        subject.principal_id.clone(),
        compatibility_permission_operation("artifact.create"),
        scope.clone(),
        now,
    );
    let denied_action = decision_for_issued_grant(
        &grant,
        subject.principal_id.clone(),
        gateway_action_operation("artifact.publish"),
        scope.clone(),
        now,
    );
    let denied_adapter = decision_for_issued_grant(
        &grant,
        subject.principal_id.clone(),
        gateway_adapter_operation("email"),
        scope.clone(),
        now,
    );
    let denied_permission = decision_for_issued_grant(
        &grant,
        subject.principal_id,
        compatibility_permission_operation("admin.all"),
        scope,
        now,
    );

    assert_eq!(allowed_action.status, AuthorityDecisionStatus::Allowed);
    assert_eq!(allowed_adapter.status, AuthorityDecisionStatus::Allowed);
    assert_eq!(allowed_permission.status, AuthorityDecisionStatus::Allowed);
    assert_eq!(denied_action.status, AuthorityDecisionStatus::Denied);
    assert_eq!(denied_adapter.status, AuthorityDecisionStatus::Denied);
    assert_eq!(denied_permission.status, AuthorityDecisionStatus::Denied);
    assert!(denied_action
        .reasons
        .contains(&"operation_not_granted".to_string()));
    assert!(denied_adapter
        .reasons
        .contains(&"operation_not_granted".to_string()));
    assert!(denied_permission
        .reasons
        .contains(&"operation_not_granted".to_string()));
}

#[test]
fn invalid_work_orders_fail_before_principal_or_grant_checks() {
    let now = OffsetDateTime::now_utc();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let inactive_issuer = issuer_principal(tenant_id.clone(), PrincipalStatus::Pending, KEY_ID);
    let inactive_subject = subject_principal(
        agent_id.clone(),
        tenant_id.clone(),
        PrincipalStatus::Pending,
    );
    let valid_work_order = work_order(&tenant_id, &agent_id, &run_id, now);
    let keyring = keyring();
    let base_validation_context = validation_context(&valid_work_order, now);

    let mut unsigned = signed_envelope(valid_work_order.clone());
    unsigned.signature = None;
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &unsigned,
            validation_context: &base_validation_context,
            keyring: &keyring,
            issuer: &inactive_issuer,
            subject: &inactive_subject,
            issuer_grants: &[],
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "unsigned_work_order",
    );

    let mut bad_signature = signed_envelope(valid_work_order.clone());
    bad_signature
        .signature
        .as_mut()
        .expect("signature")
        .signature = BAD_SIGNATURE.to_string();
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &bad_signature,
            validation_context: &base_validation_context,
            keyring: &keyring,
            issuer: &inactive_issuer,
            subject: &inactive_subject,
            issuer_grants: &[],
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "bad_signature",
    );

    let mut expired_work_order = valid_work_order.clone();
    expired_work_order.issued_at = now - time::Duration::minutes(10);
    expired_work_order.expires_at = now - time::Duration::minutes(1);
    let expired = signed_envelope(expired_work_order.clone());
    let expired_context = validation_context(&expired_work_order, now);
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &expired,
            validation_context: &expired_context,
            keyring: &keyring,
            issuer: &inactive_issuer,
            subject: &inactive_subject,
            issuer_grants: &[],
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "expired_work_order",
    );

    let mut revoked_work_order = valid_work_order;
    revoked_work_order.revocation = RevocationStatus::Revoked {
        reason: "issuer_rotated".to_string(),
    };
    let revoked = signed_envelope(revoked_work_order.clone());
    let revoked_context = validation_context(&revoked_work_order, now);
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &revoked,
            validation_context: &revoked_context,
            keyring: &keyring,
            issuer: &inactive_issuer,
            subject: &inactive_subject,
            issuer_grants: &[],
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "revoked_work_order",
    );
}

#[test]
fn inactive_principals_and_binding_mismatches_fail_closed() {
    let now = OffsetDateTime::now_utc();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let work_order = work_order(&tenant_id, &agent_id, &run_id, now);
    let envelope = signed_envelope(work_order.clone());
    let keyring = keyring();
    let validation_context = validation_context(&work_order, now);
    let active_issuer = issuer_principal(tenant_id.clone(), PrincipalStatus::Active, KEY_ID);
    let active_subject =
        subject_principal(agent_id.clone(), tenant_id.clone(), PrincipalStatus::Active);
    let issuer_grant = issuer_admit_grant(
        active_issuer.principal_id.clone(),
        tenant_id.clone(),
        agent_id.clone(),
        run_id,
        now,
        AuthorityBudgetScope {
            max_actions_per_tick: Some(5),
            ..Default::default()
        },
        None,
    );

    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &envelope,
            validation_context: &validation_context,
            keyring: &keyring,
            issuer: &issuer_principal(tenant_id.clone(), PrincipalStatus::Pending, KEY_ID),
            subject: &active_subject,
            issuer_grants: std::slice::from_ref(&issuer_grant),
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "pending_issuer_principal",
    );
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &envelope,
            validation_context: &validation_context,
            keyring: &keyring,
            issuer: &issuer_principal(tenant_id.clone(), PrincipalStatus::Revoked, KEY_ID),
            subject: &active_subject,
            issuer_grants: std::slice::from_ref(&issuer_grant),
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "revoked_issuer_principal",
    );
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &envelope,
            validation_context: &validation_context,
            keyring: &keyring,
            issuer: &active_issuer,
            subject: &subject_principal(
                agent_id.clone(),
                tenant_id.clone(),
                PrincipalStatus::Pending,
            ),
            issuer_grants: std::slice::from_ref(&issuer_grant),
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "pending_subject_principal",
    );
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &envelope,
            validation_context: &validation_context,
            keyring: &keyring,
            issuer: &active_issuer,
            subject: &subject_principal(
                agent_id.clone(),
                tenant_id.clone(),
                PrincipalStatus::Revoked,
            ),
            issuer_grants: std::slice::from_ref(&issuer_grant),
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "revoked_subject_principal",
    );

    let wrong_agent_subject =
        subject_principal(AgentId::new(), tenant_id.clone(), PrincipalStatus::Active);
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &envelope,
            validation_context: &validation_context,
            keyring: &keyring,
            issuer: &active_issuer,
            subject: &wrong_agent_subject,
            issuer_grants: std::slice::from_ref(&issuer_grant),
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "subject_agent_binding_mismatch",
    );

    let wrong_tenant_subject =
        subject_principal(agent_id.clone(), TenantId::new(), PrincipalStatus::Active);
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &envelope,
            validation_context: &validation_context,
            keyring: &keyring,
            issuer: &active_issuer,
            subject: &wrong_tenant_subject,
            issuer_grants: std::slice::from_ref(&issuer_grant),
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "subject_tenant_binding_mismatch",
    );

    let wrong_tenant_issuer = issuer_principal(TenantId::new(), PrincipalStatus::Active, KEY_ID);
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &envelope,
            validation_context: &validation_context,
            keyring: &keyring,
            issuer: &wrong_tenant_issuer,
            subject: &active_subject,
            issuer_grants: std::slice::from_ref(&issuer_grant),
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "issuer_tenant_binding_mismatch",
    );

    let wrong_key_issuer =
        issuer_principal(tenant_id.clone(), PrincipalStatus::Active, "other-key");
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &envelope,
            validation_context: &validation_context,
            keyring: &keyring,
            issuer: &wrong_key_issuer,
            subject: &active_subject,
            issuer_grants: std::slice::from_ref(&issuer_grant),
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "issuer_signature_binding_mismatch",
    );

    let mut wrong_proof_kind_issuer =
        issuer_principal(tenant_id.clone(), PrincipalStatus::Active, KEY_ID);
    wrong_proof_kind_issuer.proof_refs[0].proof_kind = "oidc_subject".to_string();
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &envelope,
            validation_context: &validation_context,
            keyring: &keyring,
            issuer: &wrong_proof_kind_issuer,
            subject: &active_subject,
            issuer_grants: std::slice::from_ref(&issuer_grant),
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "issuer_signature_binding_mismatch",
    );

    let mut wrong_proof_audience_issuer =
        issuer_principal(tenant_id, PrincipalStatus::Active, KEY_ID);
    wrong_proof_audience_issuer.proof_refs[0].audience = Some("daemon:other".to_string());
    assert_issue_reason(
        issue_work_order_capability_grant(WorkOrderGrantIssuance {
            envelope: &envelope,
            validation_context: &validation_context,
            keyring: &keyring,
            issuer: &wrong_proof_audience_issuer,
            subject: &active_subject,
            issuer_grants: std::slice::from_ref(&issuer_grant),
            audience: AUDIENCE.to_string(),
            issued_grant_id: CapabilityGrantId::new(),
        }),
        "issuer_signature_binding_mismatch",
    );
}

#[test]
fn issuer_authority_missing_or_overbroad_scope_denies_without_broadening_from_work_order() {
    let now = OffsetDateTime::now_utc();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let mut work_order = work_order(&tenant_id, &agent_id, &run_id, now);
    work_order.quotas.max_actions_per_tick = Some(5);
    work_order.placement.data_locality = Some("eu-west".to_string());
    let envelope = signed_envelope(work_order.clone());
    let keyring = keyring();
    let validation_context = validation_context(&work_order, now);
    let issuer = issuer_principal(tenant_id.clone(), PrincipalStatus::Active, KEY_ID);
    let subject = subject_principal(agent_id.clone(), tenant_id.clone(), PrincipalStatus::Active);

    let missing = issue_work_order_capability_grant(WorkOrderGrantIssuance {
        envelope: &envelope,
        validation_context: &validation_context,
        keyring: &keyring,
        issuer: &issuer,
        subject: &subject,
        issuer_grants: &[],
        audience: AUDIENCE.to_string(),
        issued_grant_id: CapabilityGrantId::new(),
    })
    .expect_err("missing issuer grant must deny");
    assert_eq!(missing.reason_code(), "issuer_authority_denied");
    assert_decision_reason(&missing, "missing_capability_grant");

    let wrong_agent_grant = issuer_admit_grant(
        issuer.principal_id.clone(),
        tenant_id.clone(),
        AgentId::new(),
        run_id.clone(),
        now,
        AuthorityBudgetScope {
            max_actions_per_tick: Some(5),
            ..Default::default()
        },
        Some("eu-west".to_string()),
    );
    let wrong_agent = issue_work_order_capability_grant(WorkOrderGrantIssuance {
        envelope: &envelope,
        validation_context: &validation_context,
        keyring: &keyring,
        issuer: &issuer,
        subject: &subject,
        issuer_grants: std::slice::from_ref(&wrong_agent_grant),
        audience: AUDIENCE.to_string(),
        issued_grant_id: CapabilityGrantId::new(),
    })
    .expect_err("wrong issuer scope must deny");
    assert_decision_reason(&wrong_agent, "agent_ids_not_granted");

    let quota_too_narrow_grant = issuer_admit_grant(
        issuer.principal_id.clone(),
        tenant_id.clone(),
        agent_id.clone(),
        run_id.clone(),
        now,
        AuthorityBudgetScope {
            max_actions_per_tick: Some(3),
            ..Default::default()
        },
        Some("eu-west".to_string()),
    );
    let quota_denied = issue_work_order_capability_grant(WorkOrderGrantIssuance {
        envelope: &envelope,
        validation_context: &validation_context,
        keyring: &keyring,
        issuer: &issuer,
        subject: &subject,
        issuer_grants: std::slice::from_ref(&quota_too_narrow_grant),
        audience: AUDIENCE.to_string(),
        issued_grant_id: CapabilityGrantId::new(),
    })
    .expect_err("work-order quota must not broaden issuer grant");
    assert_decision_reason(&quota_denied, "budget.max_actions_per_tick_exceeds_grant");

    let locality_missing_grant = issuer_admit_grant(
        issuer.principal_id.clone(),
        tenant_id,
        agent_id,
        run_id,
        now,
        AuthorityBudgetScope {
            max_actions_per_tick: Some(5),
            ..Default::default()
        },
        None,
    );
    let locality_denied = issue_work_order_capability_grant(WorkOrderGrantIssuance {
        envelope: &envelope,
        validation_context: &validation_context,
        keyring: &keyring,
        issuer: &issuer,
        subject: &subject,
        issuer_grants: &[locality_missing_grant],
        audience: AUDIENCE.to_string(),
        issued_grant_id: CapabilityGrantId::new(),
    })
    .expect_err("work-order locality must not broaden issuer grant");
    assert_decision_reason(&locality_denied, "locality.data_localities_not_granted");
}

#[test]
fn issuance_errors_do_not_expose_shared_secret_or_detached_signature() {
    let now = OffsetDateTime::now_utc();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let work_order = work_order(&tenant_id, &agent_id, &run_id, now);
    let mut envelope = signed_envelope(work_order.clone());
    envelope.signature.as_mut().expect("signature").signature = BAD_SIGNATURE.to_string();
    let keyring = keyring();
    let validation_context = validation_context(&work_order, now);
    let issuer = issuer_principal(tenant_id.clone(), PrincipalStatus::Active, KEY_ID);
    let subject = subject_principal(agent_id, tenant_id.clone(), PrincipalStatus::Active);

    let error = issue_work_order_capability_grant(WorkOrderGrantIssuance {
        envelope: &envelope,
        validation_context: &validation_context,
        keyring: &keyring,
        issuer: &issuer,
        subject: &subject,
        issuer_grants: &[],
        audience: AUDIENCE.to_string(),
        issued_grant_id: CapabilityGrantId::new(),
    })
    .expect_err("bad signature must fail");

    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(std::str::from_utf8(SECRET).expect("utf8 secret")));
    assert!(!rendered.contains(BAD_SIGNATURE));
    assert_eq!(error.reason_code(), "bad_signature");
}

fn keyring() -> WorkOrderKeyring {
    let mut keyring = WorkOrderKeyring::new();
    keyring
        .insert_shared_secret(KEY_ID, SECRET)
        .expect("test key should insert");
    keyring
}

fn signed_envelope(work_order: WorkOrder) -> WorkOrderEnvelope {
    WorkOrderEnvelope::signed_with_shared_secret(work_order, KEY_ID, SECRET)
        .expect("test work order should sign")
}

fn validation_context(work_order: &WorkOrder, now: OffsetDateTime) -> WorkOrderValidationContext {
    WorkOrderValidationContext {
        tenant_id: work_order.tenant_id.clone(),
        agent_id: work_order.agent_id.clone(),
        run_id: work_order.run_id.clone(),
        expected_placement_target: Some(work_order.placement.target.clone()),
        now,
    }
}

fn work_order(
    tenant_id: &TenantId,
    agent_id: &AgentId,
    run_id: &RunId,
    now: OffsetDateTime,
) -> WorkOrder {
    WorkOrder {
        schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new(format!("wo_auth002_{run_id}")).expect("work order id"),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: Some(run_id.clone()),
        objective: "issue bounded AUTH-002a grant".to_string(),
        allowed_actions: vec!["artifact.create".to_string()],
        allowed_adapters: vec!["artifact-store".to_string()],
        allowed_permissions: vec!["artifact.create".to_string()],
        data_refs: vec!["dataset:finance.revenue".to_string()],
        quotas: WorkOrderQuotaPolicy {
            max_actions_per_tick: Some(2),
            ..Default::default()
        },
        placement: WorkOrderPlacement::default(),
        issued_at: now - time::Duration::minutes(1),
        expires_at: now + time::Duration::minutes(10),
        revocation: RevocationStatus::Active,
    }
}

fn issuer_principal(tenant_id: TenantId, status: PrincipalStatus, key_id: &str) -> Principal {
    Principal {
        principal_id: PrincipalId::new(),
        kind: PrincipalKind::Service,
        status,
        revision: IdentityRevision::initial(),
        owner_tenant_id: Some(tenant_id.clone()),
        owner_fleet_id: None,
        bindings: vec![PrincipalBinding::Tenant { tenant_id }],
        proof_refs: vec![PrincipalProofRef {
            proof_ref_id: PrincipalProofRefId::new(),
            proof_kind: "work_order_signing_key".to_string(),
            provider: Some("local-test".to_string()),
            issuer: Some("local-authority".to_string()),
            subject: Some("issuer".to_string()),
            audience: Some(AUDIENCE.to_string()),
            key_id: Some(key_id.to_string()),
            proof_digest: DIGEST.to_string(),
            digest_algorithm: "sha256".to_string(),
            evidence_refs: vec!["evidence:issuer-key".to_string()],
        }],
        display: Some(PrincipalDisplay {
            display_name: Some("issuer".to_string()),
            description: None,
        }),
        metadata: BTreeMap::new(),
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        superseded_by: None,
    }
}

fn subject_principal(agent_id: AgentId, tenant_id: TenantId, status: PrincipalStatus) -> Principal {
    Principal {
        principal_id: PrincipalId::new(),
        kind: PrincipalKind::Agent,
        status,
        revision: IdentityRevision::initial(),
        owner_tenant_id: Some(tenant_id.clone()),
        owner_fleet_id: None,
        bindings: vec![
            PrincipalBinding::Tenant { tenant_id },
            PrincipalBinding::Agent { agent_id },
        ],
        proof_refs: Vec::new(),
        display: None,
        metadata: BTreeMap::new(),
        created_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        superseded_by: None,
    }
}

fn issuer_admit_grant(
    issuer_subject: PrincipalId,
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
    now: OffsetDateTime,
    budget: AuthorityBudgetScope,
    data_locality: Option<String>,
) -> ValidatedCapabilityGrant {
    let mut scope = CapabilityScope {
        schema_version: CAPABILITY_SCOPE_SCHEMA_VERSION.to_string(),
        tenant_ids: Some(vec![tenant_id]),
        agent_ids: Some(vec![agent_id]),
        run_ids: Some(vec![run_id]),
        audiences: Some(vec![AUDIENCE.to_string()]),
        time: AuthorityTimeScope {
            not_before: Some(now - time::Duration::minutes(2)),
            expires_at: Some(now + time::Duration::minutes(20)),
        },
        budget,
        ..Default::default()
    };
    scope.locality.data_localities = data_locality.map(|locality| vec![locality]);
    unchecked_validated_grant_for_tests(CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: CapabilityGrantId::new(),
        issuer: PrincipalId::new(),
        subject: issuer_subject,
        parent_grant_ids: Vec::new(),
        operations: vec![workload_admit_operation()],
        scope,
        not_before: now - time::Duration::minutes(5),
        expires_at: now + time::Duration::minutes(30),
        revocation_ref: Some("revocation:issuer".to_string()),
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth: 0,
        validation: Some(CapabilityGrantValidation {
            validation_kind: CapabilityGrantValidationKind::LocallyValidated,
            algorithm: "local-test-v1".to_string(),
            key_id: None,
            digest: DIGEST.to_string(),
            signature: None,
        }),
        metadata: BTreeMap::new(),
    })
}

fn issued_grant_scope(tenant_id: TenantId, agent_id: AgentId, run_id: RunId) -> CapabilityScope {
    CapabilityScope {
        tenant_ids: Some(vec![tenant_id]),
        agent_ids: Some(vec![agent_id]),
        run_ids: Some(vec![run_id]),
        audiences: Some(vec![AUDIENCE.to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(1),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn decision_for_issued_grant(
    grant: &ValidatedCapabilityGrant,
    subject: PrincipalId,
    operation: AuthorityOperation,
    scope: CapabilityScope,
    now: OffsetDateTime,
) -> splendor_types::AuthorityDecision {
    let request = CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject,
        operation,
        scope,
        requested_at: now,
        metadata: BTreeMap::new(),
    };
    evaluate_capability_request(std::slice::from_ref(grant), &request, now)
}

fn assert_issue_reason(
    result: Result<WorkOrderGrantIssuanceResult, WorkOrderGrantIssuanceError>,
    reason: &str,
) {
    let error = result.expect_err("issuance should fail");
    assert_eq!(error.reason_code(), reason, "unexpected error: {error:?}");
}

fn assert_decision_reason(error: &WorkOrderGrantIssuanceError, reason: &str) {
    match error {
        WorkOrderGrantIssuanceError::IssuerAuthorityDenied { decision } => assert!(
            decision.reasons.contains(&reason.to_string()),
            "expected {reason}, got {:?}",
            decision.reasons
        ),
        other => panic!("expected issuer denial, got {other:?}"),
    }
}
