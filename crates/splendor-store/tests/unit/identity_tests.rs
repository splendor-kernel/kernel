use super::*;
use splendor_types::{
    AgentId, FleetId, IdentityEventId, IdentityLifecycleEventKind, InstanceId, NodeId,
    PrincipalKind, PrincipalStatus, TenantId,
};

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

fn principal_with_bindings(bindings: Vec<PrincipalBinding>) -> Principal {
    let now = time::OffsetDateTime::now_utc();
    Principal {
        principal_id: PrincipalId::new(),
        kind: PrincipalKind::RuntimeInstance,
        status: PrincipalStatus::Pending,
        revision: IdentityRevision::initial(),
        owner_tenant_id: None,
        owner_fleet_id: None,
        bindings,
        proof_refs: Vec::new(),
        display: None,
        metadata: std::collections::BTreeMap::new(),
        created_at: now,
        updated_at: now,
        superseded_by: None,
    }
}

fn principal_with_owner(
    owner_tenant_id: Option<TenantId>,
    owner_fleet_id: Option<FleetId>,
) -> Principal {
    let now = time::OffsetDateTime::now_utc();
    Principal {
        principal_id: PrincipalId::new(),
        kind: PrincipalKind::Node,
        status: PrincipalStatus::Pending,
        revision: IdentityRevision::initial(),
        owner_tenant_id,
        owner_fleet_id,
        bindings: Vec::new(),
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
        &result,
        Err(PrincipalRegistryStoreError::DuplicateExternalSubjectBinding { .. })
    ));
    let error = result.expect_err("duplicate external subject should fail");
    assert!(!format!("{error}").contains("subject-c"));
    assert!(!format!("{error:?}").contains("subject-c"));
    assert!(store.current_principal(&second.principal_id).is_err());
}

#[test]
fn identity_store_exact_typed_binding_lookup_returns_deterministic_matches() {
    let store = InMemoryPrincipalRegistryStore::default();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let node_id = NodeId::new();
    let instance_id = InstanceId::new();
    let principal = principal_with_bindings(vec![
        PrincipalBinding::Tenant {
            tenant_id: tenant_id.clone(),
        },
        PrincipalBinding::Agent {
            agent_id: agent_id.clone(),
        },
        PrincipalBinding::Node {
            node_id: node_id.clone(),
        },
        PrincipalBinding::Instance {
            instance_id: instance_id.clone(),
        },
    ]);
    store
        .create_principal(principal.clone(), event_for(&principal))
        .expect("create principal");

    for binding in [
        PrincipalBinding::Tenant { tenant_id },
        PrincipalBinding::Agent { agent_id },
        PrincipalBinding::Node { node_id },
        PrincipalBinding::Instance { instance_id },
    ] {
        let matches = store
            .principals_by_binding(&binding)
            .expect("binding lookup");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].principal_id, principal.principal_id);
    }
}

#[test]
fn identity_store_external_subject_lookup_canonicalizes_provider_issuer_audience_only() {
    let store = InMemoryPrincipalRegistryStore::default();
    let principal = principal_with_external_subject("Subject-Exact");
    store
        .create_principal(principal.clone(), event_for(&principal))
        .expect("create principal");

    let canonical_match = store
        .principals_by_binding(&PrincipalBinding::ExternalSubject {
            provider: "OIDC".to_string(),
            issuer: "ISSUER.EXAMPLE".to_string(),
            subject: "Subject-Exact".to_string(),
            audience: "SPLENDOR-DAEMON".to_string(),
        })
        .expect("external lookup");
    assert_eq!(canonical_match.len(), 1);
    assert_eq!(canonical_match[0].principal_id, principal.principal_id);

    let different_subject = store
        .principals_by_binding(&PrincipalBinding::ExternalSubject {
            provider: "oidc".to_string(),
            issuer: "issuer.example".to_string(),
            subject: "subject-exact".to_string(),
            audience: "splendor-daemon".to_string(),
        })
        .expect("external lookup");
    assert!(different_subject.is_empty());
}

#[test]
fn identity_store_owner_queries_return_deterministic_current_principals() {
    let store = InMemoryPrincipalRegistryStore::default();
    let owner_tenant_id = TenantId::new();
    let owner_fleet_id = FleetId::new();
    let first = principal_with_owner(Some(owner_tenant_id.clone()), Some(owner_fleet_id.clone()));
    let second = principal_with_owner(Some(owner_tenant_id.clone()), Some(owner_fleet_id.clone()));
    let other = principal_with_owner(Some(TenantId::new()), Some(FleetId::new()));
    for principal in [&first, &second, &other] {
        store
            .create_principal(principal.clone(), event_for(principal))
            .expect("create principal");
    }

    let tenant_matches = store
        .principals_by_owner_tenant(&owner_tenant_id)
        .expect("tenant owner query");
    let fleet_matches = store
        .principals_by_owner_fleet(&owner_fleet_id)
        .expect("fleet owner query");
    let mut expected_ids = vec![first.principal_id.clone(), second.principal_id.clone()];
    expected_ids.sort_by_key(|principal_id| principal_id.to_string());

    assert_eq!(
        tenant_matches
            .iter()
            .map(|principal| principal.principal_id.clone())
            .collect::<Vec<_>>(),
        expected_ids
    );
    assert_eq!(
        fleet_matches
            .iter()
            .map(|principal| principal.principal_id.clone())
            .collect::<Vec<_>>(),
        expected_ids
    );
}
