use super::*;
use crate::gateway_action_operation;
use splendor_types::{
    validate_work_order, AgentId, AuthorityDecisionStatus, RevocationStatus, TenantId, WorkOrder,
    WorkOrderEnvelope, WorkOrderId, WorkOrderKeyring, WorkOrderPlacement, WorkOrderQuotaPolicy,
    WorkOrderValidationContext, WORK_ORDER_SCHEMA_VERSION,
};
use time::{Duration, OffsetDateTime};

fn admitted(now: OffsetDateTime) -> LocalSignedWorkOrderRunAuthority {
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = splendor_types::RunId::new();
    let work_order = WorkOrder {
        schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new("wo_run_authority").expect("work order id"),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: None,
        objective: "test live authority".to_string(),
        allowed_actions: vec!["fixture.write".to_string()],
        allowed_adapters: vec!["fixture".to_string()],
        allowed_permissions: vec!["fixture.write".to_string()],
        data_refs: Vec::new(),
        quotas: WorkOrderQuotaPolicy::default(),
        placement: WorkOrderPlacement::default(),
        issued_at: now - Duration::minutes(1),
        expires_at: now + Duration::seconds(2),
        revocation: RevocationStatus::Active,
    };
    let envelope = WorkOrderEnvelope::signed_with_shared_secret(
        work_order,
        "test-key",
        b"run-authority-test-secret",
    )
    .expect("signed work order");
    let mut keyring = WorkOrderKeyring::new();
    keyring
        .insert_shared_secret("test-key", b"run-authority-test-secret")
        .expect("keyring");
    let validated = validate_work_order(
        &envelope,
        &WorkOrderValidationContext {
            tenant_id,
            agent_id,
            run_id: None,
            expected_placement_target: None,
            now,
        },
        &keyring,
    )
    .expect("validated signed work order");
    LocalSignedWorkOrderRunAuthority::admit_compatibility(
        &validated,
        run_id,
        "splendor.test.run".to_string(),
    )
    .expect("admitted authority")
}

#[test]
fn live_run_authority_rechecks_expiry_and_revocation_for_every_operation() {
    let now = OffsetDateTime::now_utc();
    let authority = admitted(now);
    let operation = gateway_action_operation("fixture.write");

    let allowed = authority.evaluate_operation(operation.clone(), now);
    assert_eq!(allowed.status, AuthorityDecisionStatus::Allowed);

    let expired = authority.evaluate_operation(operation.clone(), now + Duration::seconds(2));
    assert_eq!(expired.status, AuthorityDecisionStatus::Denied);
    assert!(expired.reasons.contains(&"expired_grant".to_string()));

    authority.revoke();
    let revoked = authority.evaluate_operation(operation, now + Duration::seconds(1));
    assert_eq!(revoked.status, AuthorityDecisionStatus::Denied);
    assert_eq!(revoked.reasons, vec!["authority_grant_revoked"]);
    assert_eq!(authority.evaluation_count(), 3);
}
