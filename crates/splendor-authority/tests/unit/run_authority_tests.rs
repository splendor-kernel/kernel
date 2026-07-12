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

#[test]
fn final_effect_permit_linearizes_before_revocation_and_closes_new_admission() {
    let now = OffsetDateTime::now_utc();
    let authority = admitted(now);
    let evaluation =
        authority.acquire_effect_permit(vec![gateway_action_operation("fixture.write")], now);
    let permit = evaluation.permit.expect("final effect permit");
    assert_eq!(permit.generation(), 0);

    let (completed_tx, completed_rx) = std::sync::mpsc::channel();
    let revoking = authority.clone();
    let thread = std::thread::spawn(move || {
        revoking.revoke();
        completed_tx.send(()).expect("revocation completion");
    });
    assert!(completed_rx
        .recv_timeout(std::time::Duration::from_millis(50))
        .is_err());
    drop(permit);
    completed_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("revocation waits for permit");
    thread.join().expect("revocation thread");
    assert_eq!(authority.generation(), Some(1));

    let denied =
        authority.acquire_effect_permit(vec![gateway_action_operation("fixture.write")], now);
    assert!(denied.permit.is_none());
    assert_eq!(denied.decisions[0].status, AuthorityDecisionStatus::Denied);
}

#[test]
fn final_effect_permit_rechecks_expiry_after_early_allow() {
    let now = OffsetDateTime::now_utc();
    let authority = admitted(now);
    assert_eq!(
        authority
            .evaluate_operation(gateway_action_operation("fixture.write"), now)
            .status,
        AuthorityDecisionStatus::Allowed
    );
    let expired = authority.acquire_effect_permit(
        vec![gateway_action_operation("fixture.write")],
        now + Duration::seconds(2),
    );
    assert!(expired.permit.is_none());
    assert!(expired.decisions[0]
        .reasons
        .contains(&"expired_grant".to_string()));
}

#[test]
fn admission_errors_are_stable_and_empty_permit_requests_fail_closed() {
    let now = OffsetDateTime::now_utc();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let bound_run_id = splendor_types::RunId::new();
    let envelope = WorkOrderEnvelope::signed_with_shared_secret(
        WorkOrder {
            schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
            work_order_id: WorkOrderId::try_new("wo_bound_run_authority").expect("work order id"),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: Some(bound_run_id.clone()),
            objective: "test bound live authority".to_string(),
            allowed_actions: vec!["fixture.write".to_string()],
            allowed_adapters: vec!["fixture".to_string()],
            allowed_permissions: vec!["fixture.write".to_string()],
            data_refs: Vec::new(),
            quotas: WorkOrderQuotaPolicy::default(),
            placement: WorkOrderPlacement::default(),
            issued_at: now - Duration::minutes(1),
            expires_at: now + Duration::minutes(5),
            revocation: RevocationStatus::Active,
        },
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
            run_id: Some(bound_run_id.clone()),
            expected_placement_target: None,
            now,
        },
        &keyring,
    )
    .expect("validated signed work order");

    let mismatch = LocalSignedWorkOrderRunAuthority::admit_compatibility(
        &validated,
        splendor_types::RunId::new(),
        "splendor.test.run".to_string(),
    )
    .err()
    .expect("run binding mismatch");
    assert_eq!(mismatch.reason_code(), "work_order_run_binding_mismatch");
    assert!(mismatch.to_string().contains("run binding"));

    let rejected = LocalSignedWorkOrderRunAuthority::admit_compatibility(
        &validated,
        bound_run_id,
        "*".to_string(),
    )
    .err()
    .expect("invalid audience rejection");
    assert_eq!(
        rejected.reason_code(),
        "work_order_authority_grant_rejected"
    );
    assert!(rejected.to_string().contains("capability admission failed"));

    let authority = admitted(now);
    assert!(authority
        .acquire_effect_permit(Vec::new(), now)
        .permit
        .is_none());
}

#[test]
fn poisoned_authority_state_fails_closed_for_evaluation_permit_and_revocation() {
    let now = OffsetDateTime::now_utc();
    let authority = admitted(now);
    assert!(!authority.grant_id().to_string().is_empty());
    let evaluation =
        authority.acquire_effect_permit(vec![gateway_action_operation("fixture.write")], now);
    let permit = evaluation.permit.expect("permit before poison");
    let inner = std::sync::Arc::clone(&authority.inner);
    let poison = std::thread::spawn(move || {
        let _guard = inner.state.lock().expect("authority state lock");
        panic!("intentional authority state poison");
    });
    assert!(poison.join().is_err());
    drop(permit);

    let unavailable = authority.evaluate_operation(gateway_action_operation("fixture.write"), now);
    assert_eq!(
        unavailable.status,
        AuthorityDecisionStatus::NeedsIntervention
    );
    assert_eq!(unavailable.reasons, vec!["authority_state_unavailable"]);
    let unavailable_permit =
        authority.acquire_effect_permit(vec![gateway_action_operation("fixture.write")], now);
    assert!(unavailable_permit.permit.is_none());
    assert_eq!(
        unavailable_permit.decisions[0].status,
        AuthorityDecisionStatus::NeedsIntervention
    );
    authority.revoke();
    assert_eq!(authority.generation(), None);
}
