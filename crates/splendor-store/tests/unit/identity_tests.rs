use super::*;
use splendor_types::{IdentityEventId, IdentityLifecycleEventKind, PrincipalKind, PrincipalStatus};

fn event_for(principal: &Principal) -> IdentityLifecycleEvent {
    IdentityLifecycleEvent {
        identity_event_id: IdentityEventId::new(),
        principal_id: principal.principal_id.clone(),
        previous_revision: None,
        new_revision: principal.revision,
        event_kind: IdentityLifecycleEventKind::Registered,
        previous_status: None,
        new_status: Some(principal.status),
        actor_principal_id: None,
        reason_code: "test".to_string(),
        proof_digest: None,
        evidence_refs: Vec::new(),
        occurred_at: principal.created_at,
        recorded_at: principal.created_at,
    }
}

fn principal_with_external_subject(subject: &str) -> Principal {
    let now = time::OffsetDateTime::now_utc();
    Principal {
        principal_id: PrincipalId::new(),
        kind: PrincipalKind::Service,
        status: PrincipalStatus::Pending,
        revision: IdentityRevision::initial(),
        owner_tenant_id: None,
        owner_fleet_id: None,
        bindings: vec![PrincipalBinding::ExternalSubject {
            provider: "oidc".to_string(),
            issuer: "issuer.example".to_string(),
            subject: subject.to_string(),
            audience: "splendor-daemon".to_string(),
        }],
        proof_refs: Vec::new(),
        display: None,
        metadata: std::collections::BTreeMap::new(),
        created_at: now,
        updated_at: now,
        superseded_by: None,
    }
}

#[test]
fn identity_store_preserves_history_and_current_pointer_with_cas() {
    let store = InMemoryPrincipalRegistryStore::default();
    let principal = principal_with_external_subject("subject-a");
    let event = event_for(&principal);
    store
        .create_principal(principal.clone(), event)
        .expect("create principal");

    let mut activated = principal.clone();
    activated.status = PrincipalStatus::Active;
    activated.revision = IdentityRevision::new(2);
    activated.updated_at = time::OffsetDateTime::now_utc();
    let activated_event = IdentityLifecycleEvent {
        identity_event_id: IdentityEventId::new(),
        principal_id: activated.principal_id.clone(),
        previous_revision: Some(IdentityRevision::initial()),
        new_revision: activated.revision,
        event_kind: IdentityLifecycleEventKind::Activated,
        previous_status: Some(PrincipalStatus::Pending),
        new_status: Some(PrincipalStatus::Active),
        actor_principal_id: None,
        reason_code: "activate".to_string(),
        proof_digest: None,
        evidence_refs: Vec::new(),
        occurred_at: activated.updated_at,
        recorded_at: activated.updated_at,
    };
    store
        .compare_and_swap_revision(
            activated.clone(),
            IdentityRevision::initial(),
            activated_event,
        )
        .expect("cas update");

    let current = store
        .current_principal(&principal.principal_id)
        .expect("current");
    assert_eq!(current.status, PrincipalStatus::Active);
    assert_eq!(current.revision, IdentityRevision::new(2));
    assert_eq!(
        store
            .history(&principal.principal_id)
            .expect("history")
            .len(),
        2
    );
}

#[test]
fn identity_store_stale_revision_fails_without_pointer_movement() {
    let store = InMemoryPrincipalRegistryStore::default();
    let principal = principal_with_external_subject("subject-b");
    store
        .create_principal(principal.clone(), event_for(&principal))
        .expect("create principal");

    let mut next = principal.clone();
    next.status = PrincipalStatus::Active;
    next.revision = IdentityRevision::new(2);
    let result = store.compare_and_swap_revision(
        next,
        IdentityRevision::new(99),
        IdentityLifecycleEvent {
            identity_event_id: IdentityEventId::new(),
            principal_id: principal.principal_id.clone(),
            previous_revision: Some(IdentityRevision::new(99)),
            new_revision: IdentityRevision::new(2),
            event_kind: IdentityLifecycleEventKind::Activated,
            previous_status: Some(PrincipalStatus::Pending),
            new_status: Some(PrincipalStatus::Active),
            actor_principal_id: None,
            reason_code: "stale".to_string(),
            proof_digest: None,
            evidence_refs: Vec::new(),
            occurred_at: time::OffsetDateTime::now_utc(),
            recorded_at: time::OffsetDateTime::now_utc(),
        },
    );

    assert!(matches!(
        result,
        Err(PrincipalRegistryStoreError::RevisionConflict { .. })
    ));
    let current = store
        .current_principal(&principal.principal_id)
        .expect("current");
    assert_eq!(current.status, PrincipalStatus::Pending);
    assert_eq!(current.revision, IdentityRevision::initial());
    assert_eq!(
        store
            .history(&principal.principal_id)
            .expect("history")
            .len(),
        1
    );
}

#[test]
fn identity_store_duplicate_external_subject_binding_fails() {
    let store = InMemoryPrincipalRegistryStore::default();
    let first = principal_with_external_subject("subject-c");
    let second = principal_with_external_subject("subject-c");
    store
        .create_principal(first.clone(), event_for(&first))
        .expect("create first principal");

    let result = store.create_principal(second.clone(), event_for(&second));
    assert!(matches!(
        result,
        Err(PrincipalRegistryStoreError::DuplicateExternalSubjectBinding { .. })
    ));
    assert!(store.current_principal(&second.principal_id).is_err());
}
