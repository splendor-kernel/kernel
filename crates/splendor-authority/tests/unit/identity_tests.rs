use super::*;
use serde_json::json;
use splendor_store::{
    IdentityHistoryRecord, InMemoryPrincipalRegistryStore, PrincipalRegistryStore,
    PrincipalRegistryStoreError,
};
use splendor_types::{
    AgentId, FleetId, IdentityLookupKey, IdentityQuery, InstanceId, NodeId, PrincipalProofRefId,
    TenantId,
};

const REGISTRATION_DIGEST: &str =
    "blake3:1111111111111111111111111111111111111111111111111111111111111111";
const ROTATED_DIGEST: &str =
    "blake3:2222222222222222222222222222222222222222222222222222222222222222";

type CommandMutation = Box<dyn FnOnce(&mut RegisterPrincipal)>;

fn registry() -> IdentityRegistry<InMemoryPrincipalRegistryStore> {
    IdentityRegistry::new(InMemoryPrincipalRegistryStore::default())
}

fn proof(digest: &str) -> PrincipalProofRef {
    PrincipalProofRef {
        proof_ref_id: PrincipalProofRefId::new(),
        proof_kind: "oidc_subject".to_string(),
        provider: Some("oidc".to_string()),
        issuer: Some("issuer.example".to_string()),
        subject: Some("subject-1".to_string()),
        audience: Some("splendor-daemon".to_string()),
        key_id: Some("kid-1".to_string()),
        proof_digest: digest.to_string(),
        digest_algorithm: "blake3".to_string(),
        evidence_refs: vec!["evidence:proof".to_string()],
    }
}

fn registration(kind: PrincipalKind) -> RegisterPrincipal {
    RegisterPrincipal {
        principal_id: PrincipalId::new(),
        kind,
        owner_tenant_id: None,
        owner_fleet_id: None,
        bindings: Vec::new(),
        proof_refs: vec![proof(REGISTRATION_DIGEST)],
        display: None,
        metadata: std::collections::BTreeMap::new(),
        requested_at: time::OffsetDateTime::now_utc(),
        reason_code: "test_registration".to_string(),
        actor_principal_id: None,
    }
}

fn register_active_service(
    registry: &IdentityRegistry<InMemoryPrincipalRegistryStore>,
) -> Principal {
    let registered = registry
        .register(registration(PrincipalKind::Service))
        .expect("register");
    registry
        .activate(
            &registered.principal.principal_id,
            registered.principal.revision,
            "activate",
        )
        .expect("activate")
        .principal
}

fn nil_principal_id() -> PrincipalId {
    PrincipalId::parse("00000000-0000-0000-0000-000000000000").expect("nil principal id parses")
}

fn nil_tenant_id() -> TenantId {
    TenantId::parse("00000000-0000-0000-0000-000000000000").expect("nil tenant id parses")
}

struct PanicOnLookupStore;

impl PrincipalRegistryStore for PanicOnLookupStore {
    fn create_principal(
        &self,
        _principal: Principal,
        _event: IdentityLifecycleEvent,
    ) -> Result<(), PrincipalRegistryStoreError> {
        panic!("store create must not be called by invalid query validation")
    }

    fn current_principal(
        &self,
        _principal_id: &PrincipalId,
    ) -> Result<Principal, PrincipalRegistryStoreError> {
        panic!("store current must not be called by invalid query validation")
    }

    fn compare_and_swap_revision(
        &self,
        _principal: Principal,
        _expected_revision: IdentityRevision,
        _event: IdentityLifecycleEvent,
    ) -> Result<(), PrincipalRegistryStoreError> {
        panic!("store cas must not be called by invalid query validation")
    }

    fn history(
        &self,
        _principal_id: &PrincipalId,
    ) -> Result<Vec<IdentityHistoryRecord>, PrincipalRegistryStoreError> {
        panic!("store history must not be called by invalid query validation")
    }

    fn principals_by_binding(
        &self,
        _binding: &PrincipalBinding,
    ) -> Result<Vec<Principal>, PrincipalRegistryStoreError> {
        panic!("store binding lookup must not be called by invalid query validation")
    }

    fn principals_by_owner_tenant(
        &self,
        _owner_tenant_id: &TenantId,
    ) -> Result<Vec<Principal>, PrincipalRegistryStoreError> {
        panic!("store tenant-owner lookup must not be called by invalid query validation")
    }

    fn principals_by_owner_fleet(
        &self,
        _owner_fleet_id: &FleetId,
    ) -> Result<Vec<Principal>, PrincipalRegistryStoreError> {
        panic!("store fleet-owner lookup must not be called by invalid query validation")
    }
}

#[test]
fn identity_registers_every_principal_kind_as_pending() {
    let registry = registry();
    let kinds = [
        PrincipalKind::Tenant,
        PrincipalKind::Human,
        PrincipalKind::Service,
        PrincipalKind::Agent,
        PrincipalKind::RuntimeInstance,
        PrincipalKind::Node,
        PrincipalKind::PhysicalDevice,
        PrincipalKind::GovernanceAuthority,
        PrincipalKind::ExternalProvider,
        PrincipalKind::Workload,
    ];

    for kind in kinds {
        let mutation = registry
            .register(registration(kind))
            .expect("register kind");
        assert_eq!(mutation.principal.kind, kind);
        assert_eq!(mutation.principal.status, PrincipalStatus::Pending);
        assert_eq!(mutation.principal.revision, IdentityRevision::initial());
        assert_eq!(
            mutation.event.event_kind,
            IdentityLifecycleEventKind::Registered
        );
    }
}

#[test]
fn identity_activate_suspend_revoke_and_reject_revoked_reactivation() {
    let registry = registry();
    let registered = registry
        .register(registration(PrincipalKind::Human))
        .expect("register");
    let activated = registry
        .activate(
            &registered.principal.principal_id,
            registered.principal.revision,
            "activate",
        )
        .expect("activate");
    assert_eq!(activated.principal.status, PrincipalStatus::Active);
    assert_eq!(activated.principal.revision, IdentityRevision::new(2));

    let suspended = registry
        .suspend(
            &registered.principal.principal_id,
            activated.principal.revision,
            "suspend",
        )
        .expect("suspend");
    assert_eq!(suspended.principal.status, PrincipalStatus::Suspended);

    let reactivated = registry
        .activate(
            &registered.principal.principal_id,
            suspended.principal.revision,
            "reactivate",
        )
        .expect("reactivate");
    assert_eq!(reactivated.principal.status, PrincipalStatus::Active);

    let revoked = registry
        .revoke(
            &registered.principal.principal_id,
            reactivated.principal.revision,
            "revoke",
        )
        .expect("revoke");
    assert_eq!(revoked.principal.status, PrincipalStatus::Revoked);

    let result = registry.activate(
        &registered.principal.principal_id,
        revoked.principal.revision,
        "resurrect",
    );
    assert!(matches!(
        result,
        Err(IdentityRegistryError::InvalidLifecycleTransition { .. })
    ));
    assert_eq!(
        registry
            .current(&registered.principal.principal_id)
            .expect("current")
            .status,
        PrincipalStatus::Revoked
    );
}

#[test]
fn identity_activation_without_proof_ref_fails_closed() {
    let registry = registry();
    let mut command = registration(PrincipalKind::Service);
    command.proof_refs.clear();
    let registered = registry.register(command).expect("register without proof");

    let result = registry.activate(
        &registered.principal.principal_id,
        registered.principal.revision,
        "activate_without_proof",
    );
    assert!(matches!(
        result,
        Err(IdentityRegistryError::InvalidProofRef {
            field: "proof_refs"
        })
    ));
    assert_eq!(
        registry
            .current(&registered.principal.principal_id)
            .expect("current")
            .status,
        PrincipalStatus::Pending
    );
}

#[test]
fn identity_proof_rotation_increments_revision_and_records_redacted_event() {
    let registry = registry();
    let active = register_active_service(&registry);
    let rotated = registry
        .rotate_proof(
            &active.principal_id,
            active.revision,
            proof(ROTATED_DIGEST),
            "rotate",
        )
        .expect("rotate proof");

    assert_eq!(rotated.principal.revision, IdentityRevision::new(3));
    assert_eq!(
        rotated.event.event_kind,
        IdentityLifecycleEventKind::ProofRotated
    );
    assert_eq!(rotated.event.proof_digest.as_deref(), Some(ROTATED_DIGEST));
    assert_eq!(rotated.event.evidence_refs, vec!["evidence:proof"]);
    let event_json = serde_json::to_value(&rotated.event).expect("event json");
    assert!(event_json.get("token").is_none());
    assert!(event_json.get("credential").is_none());
    assert!(event_json.get("private_key").is_none());

    let history = registry.history(&active.principal_id).expect("history");
    assert_eq!(history.len(), 3);
    assert_eq!(
        history.last().expect("last event").event.event_kind,
        IdentityLifecycleEventKind::ProofRotated
    );
}

#[test]
fn identity_rejects_credential_like_proof_material_without_pointer_movement() {
    let cases: Vec<CommandMutation> = vec![
        Box::new(|command| command.proof_refs[0].proof_digest = "Bearer secret-token".to_string()),
        Box::new(|command| command.proof_refs[0].digest_algorithm = "md5".to_string()),
        Box::new(|command| command.proof_refs[0].proof_digest = "blake3:not-hex".to_string()),
        Box::new(|command| command.proof_refs[0].evidence_refs = vec!["Bearer secret".to_string()]),
        Box::new(|command| {
            command.proof_refs[0].evidence_refs = vec!["evidence:aaa.bbb.ccc".to_string()]
        }),
        Box::new(|command| {
            command.proof_refs[0].evidence_refs = vec!["evidence:github_pat_secret".to_string()]
        }),
        Box::new(|command| {
            command.proof_refs[0].evidence_refs = vec!["https://example.invalid/proof".to_string()]
        }),
        Box::new(|command| {
            command.proof_refs[0].key_id = Some("-----BEGIN PRIVATE KEY-----".to_string())
        }),
        Box::new(|command| command.proof_refs[0].subject = Some("aaa.bbb.ccc".to_string())),
    ];

    for mutate in cases {
        let registry = registry();
        let mut command = registration(PrincipalKind::Service);
        let principal_id = command.principal_id.clone();
        mutate(&mut command);

        let result = registry.register(command);
        assert!(matches!(
            result,
            Err(IdentityRegistryError::InvalidProofRef { .. })
        ));
        assert!(registry.current(&principal_id).is_err());
    }
}

#[test]
fn identity_rejects_credential_like_persisted_fields_without_pointer_movement() {
    let cases: Vec<CommandMutation> = vec![
        Box::new(|command| {
            command
                .metadata
                .insert("x_note".to_string(), json!("Bearer secret-token"));
        }),
        Box::new(|command| {
            command.metadata.insert(
                "x_diagnostics".to_string(),
                json!({"items": [{"label": "github_pat_secret"}]}),
            );
        }),
        Box::new(|command| {
            command.display = Some(PrincipalDisplay {
                display_name: Some("aaa.bbb.ccc".to_string()),
                description: None,
            });
        }),
        Box::new(|command| {
            command.display = Some(PrincipalDisplay {
                display_name: None,
                description: Some("-----BEGIN PRIVATE KEY-----".to_string()),
            });
        }),
        Box::new(|command| command.reason_code = "Bearer token".to_string()),
    ];

    for mutate in cases {
        let registry = registry();
        let mut command = registration(PrincipalKind::Service);
        let principal_id = command.principal_id.clone();
        mutate(&mut command);

        let result = registry.register(command);
        assert!(matches!(
            result,
            Err(IdentityRegistryError::CredentialMaterial { .. })
        ));
        assert!(registry.current(&principal_id).is_err());
    }
}

#[test]
fn identity_rejects_credential_like_lifecycle_reason_without_pointer_movement() {
    let registry = registry();
    let active = register_active_service(&registry);

    let suspend_result = registry.suspend(&active.principal_id, active.revision, "Bearer token");
    assert!(matches!(
        suspend_result,
        Err(IdentityRegistryError::CredentialMaterial {
            field: "reason_code"
        })
    ));

    let rotate_result = registry.rotate_proof(
        &active.principal_id,
        active.revision,
        proof(ROTATED_DIGEST),
        "github_pat_secret",
    );
    assert!(matches!(
        rotate_result,
        Err(IdentityRegistryError::CredentialMaterial {
            field: "reason_code"
        })
    ));

    let supersede_result = registry.supersede(
        &active.principal_id,
        active.revision,
        PrincipalId::new(),
        "aaa.bbb.ccc",
    );
    assert!(matches!(
        supersede_result,
        Err(IdentityRegistryError::CredentialMaterial {
            field: "reason_code"
        })
    ));

    let current = registry.current(&active.principal_id).expect("current");
    assert_eq!(current.status, PrincipalStatus::Active);
    assert_eq!(current.revision, active.revision);
    assert_eq!(registry.history(&active.principal_id).unwrap().len(), 2);
}

#[test]
fn identity_nil_actor_principal_id_registration_fails_without_pointer_movement() {
    let registry = registry();
    let mut command = registration(PrincipalKind::Service);
    let principal_id = command.principal_id.clone();
    command.actor_principal_id = Some(
        PrincipalId::parse("00000000-0000-0000-0000-000000000000")
            .expect("nil principal id parses"),
    );

    let result = registry.register(command);
    assert!(matches!(
        result,
        Err(IdentityRegistryError::InvalidActorPrincipalId)
    ));
    assert!(registry.current(&principal_id).is_err());
}

#[test]
fn identity_stale_revision_cas_fails_with_no_pointer_movement() {
    let registry = registry();
    let active = register_active_service(&registry);

    let result = registry.suspend(&active.principal_id, IdentityRevision::initial(), "stale");
    assert!(matches!(
        result,
        Err(IdentityRegistryError::RevisionConflict { .. })
    ));
    let current = registry.current(&active.principal_id).expect("current");
    assert_eq!(current.status, PrincipalStatus::Active);
    assert_eq!(current.revision, active.revision);
    assert_eq!(registry.history(&active.principal_id).unwrap().len(), 2);
}

#[test]
fn identity_duplicate_external_subject_binding_fails_deterministically() {
    let registry = registry();
    let mut first = registration(PrincipalKind::Service);
    first.bindings = vec![PrincipalBinding::ExternalSubject {
        provider: "oidc".to_string(),
        issuer: "issuer.example".to_string(),
        subject: "same-subject".to_string(),
        audience: "splendor-daemon".to_string(),
    }];
    let first_id = first.principal_id.clone();
    registry.register(first).expect("first registration");

    let mut second = registration(PrincipalKind::Service);
    let second_id = second.principal_id.clone();
    second.bindings = vec![PrincipalBinding::ExternalSubject {
        provider: "OIDC".to_string(),
        issuer: "ISSUER.EXAMPLE".to_string(),
        subject: "same-subject".to_string(),
        audience: "SPLENDOR-DAEMON".to_string(),
    }];
    let result = registry.register(second);

    assert!(matches!(
        &result,
        Err(IdentityRegistryError::Store(
            splendor_store::PrincipalRegistryStoreError::DuplicateExternalSubjectBinding { .. }
        ))
    ));
    let error = result.expect_err("duplicate external subject should fail");
    assert!(!format!("{error}").contains("same-subject"));
    assert!(!format!("{error:?}").contains("same-subject"));
    assert!(registry.current(&second_id).is_err());
    assert_eq!(
        registry.current(&first_id).expect("first current").revision,
        IdentityRevision::initial()
    );
}

#[test]
fn identity_nil_principal_id_registration_fails() {
    let registry = registry();
    let mut command = registration(PrincipalKind::Service);
    command.principal_id = PrincipalId::parse("00000000-0000-0000-0000-000000000000")
        .expect("nil principal id parses");

    let result = registry.register(command);
    assert!(matches!(
        result,
        Err(IdentityRegistryError::InvalidPrincipalId)
    ));
}

#[test]
fn identity_reserved_metadata_keys_fail_registration() {
    for key in [
        "allowed_permissions",
        "secret",
        "token",
        "gateway",
        "approval_token",
        "driverOverride",
        "proofDigest",
        "biometricTemplate",
    ] {
        let registry = registry();
        let mut command = registration(PrincipalKind::Service);
        command
            .metadata
            .insert(key.to_string(), serde_json::json!("not allowed"));
        let result = registry.register(command);
        assert!(matches!(result, Err(IdentityRegistryError::Metadata(_))));
    }
}

#[test]
fn identity_nested_reserved_metadata_keys_fail_registration() {
    let registry = registry();
    let mut command = registration(PrincipalKind::Service);
    command.metadata.insert(
        "diagnostics".to_string(),
        serde_json::json!({"nested": [{"approvalToken": "not allowed"}]}),
    );

    let result = registry.register(command);
    assert!(matches!(result, Err(IdentityRegistryError::Metadata(_))));
}

#[test]
fn identity_tenant_agent_node_instance_bindings_remain_typed() {
    let registry = registry();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let node_id = NodeId::new();
    let instance_id = InstanceId::new();
    let mut command = registration(PrincipalKind::RuntimeInstance);
    command.bindings = vec![
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
    ];

    let registered = registry.register(command).expect("register typed bindings");
    let binding_json = serde_json::to_value(&registered.principal.bindings).expect("binding json");
    assert_eq!(binding_json[0]["kind"], "tenant");
    assert_eq!(binding_json[1]["kind"], "agent");
    assert_eq!(binding_json[2]["kind"], "node");
    assert_eq!(binding_json[3]["kind"], "instance");
    assert_eq!(
        registered.principal.bindings[0],
        PrincipalBinding::Tenant { tenant_id }
    );
    assert_eq!(
        registered.principal.bindings[1],
        PrincipalBinding::Agent { agent_id }
    );
    assert_eq!(
        registered.principal.bindings[2],
        PrincipalBinding::Node { node_id }
    );
    assert_eq!(
        registered.principal.bindings[3],
        PrincipalBinding::Instance { instance_id }
    );
}

#[test]
fn identity_exact_principal_lookup_returns_revision_numbered_snapshot() {
    let registry = registry();
    let active = register_active_service(&registry);

    let snapshot = registry
        .snapshot(&active.principal_id, Some(active.revision))
        .expect("snapshot");
    assert_eq!(snapshot.principal_id, active.principal_id);
    assert_eq!(snapshot.status, PrincipalStatus::Active);
    assert_eq!(snapshot.revision, active.revision);

    let result = registry
        .query(IdentityQuery {
            lookup: IdentityLookupKey::PrincipalId {
                principal_id: active.principal_id.clone(),
            },
            expected_revision: Some(active.revision),
        })
        .expect("principal query");
    assert_eq!(result.snapshots.len(), 1);
    assert_eq!(result.snapshots[0].principal_id, active.principal_id);
    assert_eq!(result.snapshots[0].revision, active.revision);
    assert_eq!(result.snapshots[0].read_at, result.read_at);
}

#[test]
fn identity_exact_typed_binding_queries_return_correct_principal() {
    let registry = registry();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let node_id = NodeId::new();
    let instance_id = InstanceId::new();
    let mut command = registration(PrincipalKind::RuntimeInstance);
    command.bindings = vec![
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
    ];
    let registered = registry
        .register(command)
        .expect("register typed principal");

    for binding in [
        PrincipalBinding::Tenant { tenant_id },
        PrincipalBinding::Agent { agent_id },
        PrincipalBinding::Node { node_id },
        PrincipalBinding::Instance { instance_id },
    ] {
        let result = registry
            .query(IdentityQuery {
                lookup: IdentityLookupKey::Binding { binding },
                expected_revision: Some(registered.principal.revision),
            })
            .expect("binding query");
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(
            result.snapshots[0].principal_id,
            registered.principal.principal_id
        );
        assert_eq!(result.snapshots[0].revision, registered.principal.revision);
    }
}

#[test]
fn identity_external_subject_query_canonicalizes_provider_issuer_audience_only() {
    let registry = registry();
    let mut command = registration(PrincipalKind::Service);
    command.bindings = vec![PrincipalBinding::ExternalSubject {
        provider: "oidc".to_string(),
        issuer: "issuer.example".to_string(),
        subject: "Subject-Exact".to_string(),
        audience: "splendor-daemon".to_string(),
    }];
    let registered = registry
        .register(command)
        .expect("register external subject");

    let result = registry
        .query(IdentityQuery {
            lookup: IdentityLookupKey::Binding {
                binding: PrincipalBinding::ExternalSubject {
                    provider: "OIDC".to_string(),
                    issuer: "ISSUER.EXAMPLE".to_string(),
                    subject: "Subject-Exact".to_string(),
                    audience: "SPLENDOR-DAEMON".to_string(),
                },
            },
            expected_revision: None,
        })
        .expect("canonical external subject query");
    assert_eq!(result.snapshots.len(), 1);
    assert_eq!(
        result.snapshots[0].principal_id,
        registered.principal.principal_id
    );

    let no_match = registry.query(IdentityQuery {
        lookup: IdentityLookupKey::Binding {
            binding: PrincipalBinding::ExternalSubject {
                provider: "oidc".to_string(),
                issuer: "issuer.example".to_string(),
                subject: "subject-exact".to_string(),
                audience: "splendor-daemon".to_string(),
            },
        },
        expected_revision: None,
    });
    assert!(matches!(
        no_match,
        Err(IdentityRegistryError::NoMatchingPrincipal { .. })
    ));
}

#[test]
fn identity_external_subject_query_results_and_errors_are_redacted() {
    let registry = registry();
    let mut command = registration(PrincipalKind::Service);
    command.bindings = vec![PrincipalBinding::ExternalSubject {
        provider: "oidc".to_string(),
        issuer: "issuer.example".to_string(),
        subject: "Subject-Exact".to_string(),
        audience: "splendor-daemon".to_string(),
    }];
    registry
        .register(command)
        .expect("register external subject");

    let result = registry
        .query(IdentityQuery {
            lookup: IdentityLookupKey::Binding {
                binding: PrincipalBinding::ExternalSubject {
                    provider: "OIDC".to_string(),
                    issuer: "ISSUER.EXAMPLE".to_string(),
                    subject: "Subject-Exact".to_string(),
                    audience: "SPLENDOR-DAEMON".to_string(),
                },
            },
            expected_revision: None,
        })
        .expect("external subject query");
    let serialized = serde_json::to_string(&result).expect("serialize result");
    assert!(serialized.contains("external_subject"));
    assert!(!serialized.contains("Subject-Exact"));
    assert!(!serialized.contains("ISSUER.EXAMPLE"));
    assert!(!serialized.contains("SPLENDOR-DAEMON"));

    let missing_subject = "Subject-Missing";
    let error = registry
        .query(IdentityQuery {
            lookup: IdentityLookupKey::Binding {
                binding: PrincipalBinding::ExternalSubject {
                    provider: "oidc".to_string(),
                    issuer: "issuer.example".to_string(),
                    subject: missing_subject.to_string(),
                    audience: "splendor-daemon".to_string(),
                },
            },
            expected_revision: None,
        })
        .expect_err("missing external subject should fail");
    assert!(!format!("{error}").contains(missing_subject));
    assert!(!format!("{error:?}").contains(missing_subject));
}

#[test]
fn identity_external_subject_inputs_reject_credential_and_reserved_authority_material() {
    let registry = registry();
    let mut command = registration(PrincipalKind::Service);
    command.bindings = vec![PrincipalBinding::ExternalSubject {
        provider: "oidc".to_string(),
        issuer: "issuer.example".to_string(),
        subject: "aaa.bbb.ccc".to_string(),
        audience: "splendor-daemon".to_string(),
    }];
    assert!(matches!(
        registry.register(command),
        Err(IdentityRegistryError::CredentialMaterial { field: "subject" })
    ));

    let reserved = registry.query(IdentityQuery {
        lookup: IdentityLookupKey::Binding {
            binding: PrincipalBinding::ExternalSubject {
                provider: "work_order".to_string(),
                issuer: "issuer.example".to_string(),
                subject: "subject-123".to_string(),
                audience: "splendor-daemon".to_string(),
            },
        },
        expected_revision: None,
    });
    assert!(matches!(
        reserved,
        Err(IdentityRegistryError::CredentialMaterial { field: "provider" })
    ));
}

#[test]
fn identity_owner_queries_return_deterministic_snapshots_and_non_authorizing_status() {
    let registry = registry();
    let owner_tenant_id = TenantId::new();
    let owner_fleet_id = FleetId::new();

    let mut first_command = registration(PrincipalKind::Node);
    first_command.owner_tenant_id = Some(owner_tenant_id.clone());
    first_command.owner_fleet_id = Some(owner_fleet_id.clone());
    let first = registry.register(first_command).expect("register first");
    let first_active = registry
        .activate(
            &first.principal.principal_id,
            first.principal.revision,
            "activate_first",
        )
        .expect("activate first");
    let first_suspended = registry
        .suspend(
            &first.principal.principal_id,
            first_active.principal.revision,
            "suspend_first",
        )
        .expect("suspend first");

    let mut second_command = registration(PrincipalKind::RuntimeInstance);
    second_command.owner_tenant_id = Some(owner_tenant_id.clone());
    second_command.owner_fleet_id = Some(owner_fleet_id.clone());
    let second = registry.register(second_command).expect("register second");
    let second_revoked = registry
        .revoke(
            &second.principal.principal_id,
            second.principal.revision,
            "revoke_second",
        )
        .expect("revoke second");

    let tenant_result = registry
        .query(IdentityQuery {
            lookup: IdentityLookupKey::OwnerTenant {
                owner_tenant_id: owner_tenant_id.clone(),
            },
            expected_revision: None,
        })
        .expect("tenant owner query");
    let fleet_result = registry
        .query(IdentityQuery {
            lookup: IdentityLookupKey::OwnerFleet { owner_fleet_id },
            expected_revision: None,
        })
        .expect("fleet owner query");
    let mut expected_ids = vec![
        first_suspended.principal.principal_id.clone(),
        second_revoked.principal.principal_id.clone(),
    ];
    expected_ids.sort_by_key(|principal_id| principal_id.to_string());

    for result in [tenant_result, fleet_result] {
        assert_eq!(
            result
                .snapshots
                .iter()
                .map(|snapshot| snapshot.principal_id.clone())
                .collect::<Vec<_>>(),
            expected_ids
        );
        assert!(result
            .snapshots
            .iter()
            .any(|snapshot| snapshot.status == PrincipalStatus::Suspended));
        assert!(result
            .snapshots
            .iter()
            .any(|snapshot| snapshot.status == PrincipalStatus::Revoked));
        assert!(result
            .snapshots
            .iter()
            .all(|snapshot| snapshot.read_at == result.read_at));
    }
}

#[test]
fn identity_nil_query_keys_fail_before_store_lookup() {
    let registry = IdentityRegistry::new(PanicOnLookupStore);
    let nil_principal_result = registry.query(IdentityQuery {
        lookup: IdentityLookupKey::PrincipalId {
            principal_id: nil_principal_id(),
        },
        expected_revision: None,
    });
    assert!(matches!(
        nil_principal_result,
        Err(IdentityRegistryError::InvalidPrincipalId)
    ));

    let nil_binding_result = registry.query(IdentityQuery {
        lookup: IdentityLookupKey::Binding {
            binding: PrincipalBinding::Tenant {
                tenant_id: nil_tenant_id(),
            },
        },
        expected_revision: None,
    });
    assert!(matches!(
        nil_binding_result,
        Err(IdentityRegistryError::InvalidBinding { field: "tenant_id" })
    ));
}

#[test]
fn identity_missing_principal_and_binding_return_explicit_read_failures() {
    let registry = registry();
    let missing_principal_id = PrincipalId::new();
    let snapshot_result = registry.snapshot(&missing_principal_id, None);
    assert!(matches!(
        snapshot_result,
        Err(IdentityRegistryError::PrincipalNotFound { .. })
    ));

    let missing_binding = registry.query(IdentityQuery {
        lookup: IdentityLookupKey::Binding {
            binding: PrincipalBinding::Agent {
                agent_id: AgentId::new(),
            },
        },
        expected_revision: None,
    });
    assert!(matches!(
        missing_binding,
        Err(IdentityRegistryError::NoMatchingPrincipal { .. })
    ));
}

#[test]
fn identity_stale_expected_revision_query_fails_without_mutation() {
    let registry = registry();
    let active = register_active_service(&registry);

    let result = registry.query(IdentityQuery {
        lookup: IdentityLookupKey::PrincipalId {
            principal_id: active.principal_id.clone(),
        },
        expected_revision: Some(IdentityRevision::initial()),
    });
    assert!(matches!(
        result,
        Err(IdentityRegistryError::RevisionConflict { .. })
    ));
    let current = registry.current(&active.principal_id).expect("current");
    assert_eq!(current.revision, active.revision);
    assert_eq!(current.status, PrincipalStatus::Active);
    assert_eq!(registry.history(&active.principal_id).unwrap().len(), 2);
}

#[test]
fn identity_ambiguous_duplicate_typed_binding_fails_without_best_effort_selection() {
    let registry = registry();
    let agent_id = AgentId::new();
    for _ in 0..2 {
        let mut command = registration(PrincipalKind::Agent);
        command.bindings = vec![PrincipalBinding::Agent {
            agent_id: agent_id.clone(),
        }];
        registry
            .register(command)
            .expect("register duplicate typed binding");
    }

    let result = registry.query(IdentityQuery {
        lookup: IdentityLookupKey::Binding {
            binding: PrincipalBinding::Agent { agent_id },
        },
        expected_revision: None,
    });
    assert!(matches!(
        result,
        Err(IdentityRegistryError::AmbiguousIdentityLookup { matches: 2, .. })
    ));
}

#[test]
fn identity_supersession_increments_revision_without_resurrecting_revoked() {
    let registry = registry();
    let active = register_active_service(&registry);
    let superseded = registry
        .supersede(
            &active.principal_id,
            active.revision,
            PrincipalId::new(),
            "supersede",
        )
        .expect("supersede");
    assert_eq!(superseded.principal.revision, active.revision.next());
    assert_eq!(
        superseded.event.event_kind,
        IdentityLifecycleEventKind::Superseded
    );

    let revoked = registry
        .revoke(
            &active.principal_id,
            superseded.principal.revision,
            "revoke",
        )
        .expect("revoke");
    let result = registry.supersede(
        &active.principal_id,
        revoked.principal.revision,
        PrincipalId::new(),
        "bad_supersede",
    );
    assert!(matches!(
        result,
        Err(IdentityRegistryError::RevokedPrincipal { .. })
    ));
}
