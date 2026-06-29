use super::*;

fn round_trip<T>(value: &T)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let encoded = serde_json::to_vec(value).expect("serialize identity type");
    let decoded: T = serde_json::from_slice(&encoded).expect("deserialize identity type");
    assert_eq!(&decoded, value);
}

#[test]
fn identity_principal_id_is_distinct_and_round_trips() {
    let principal_id = PrincipalId::new();
    let tenant_id = TenantId::new();

    round_trip(&principal_id);
    round_trip(&tenant_id);
    assert_ne!(principal_id.to_string(), tenant_id.to_string());
}

#[test]
fn identity_typed_principal_bindings_remain_serializable_and_distinct() {
    let tenant_binding = PrincipalBinding::Tenant {
        tenant_id: TenantId::new(),
    };
    let agent_binding = PrincipalBinding::Agent {
        agent_id: AgentId::new(),
    };
    let node_binding = PrincipalBinding::Node {
        node_id: NodeId::new(),
    };
    let instance_binding = PrincipalBinding::Instance {
        instance_id: InstanceId::new(),
    };

    round_trip(&tenant_binding);
    round_trip(&agent_binding);
    round_trip(&node_binding);
    round_trip(&instance_binding);

    let tenant_json = serde_json::to_value(&tenant_binding).expect("tenant binding json");
    let agent_json = serde_json::to_value(&agent_binding).expect("agent binding json");
    let node_json = serde_json::to_value(&node_binding).expect("node binding json");
    let instance_json = serde_json::to_value(&instance_binding).expect("instance binding json");

    assert_eq!(tenant_json["kind"], "tenant");
    assert_eq!(agent_json["kind"], "agent");
    assert_eq!(node_json["kind"], "node");
    assert_eq!(instance_json["kind"], "instance");
}

#[test]
fn identity_principal_contract_round_trips_without_authority_fields() {
    let now = time::OffsetDateTime::now_utc();
    let principal_id = PrincipalId::new();
    let principal = Principal {
        principal_id: principal_id.clone(),
        kind: PrincipalKind::Service,
        status: PrincipalStatus::Pending,
        revision: IdentityRevision::initial(),
        owner_tenant_id: Some(TenantId::new()),
        owner_fleet_id: Some(FleetId::new()),
        bindings: vec![PrincipalBinding::ExternalSubject {
            provider: "oidc".to_string(),
            issuer: "issuer.example".to_string(),
            subject: "subject-123".to_string(),
            audience: "splendor-daemon".to_string(),
        }],
        proof_refs: vec![PrincipalProofRef {
            proof_ref_id: PrincipalProofRefId::new(),
            proof_kind: "oidc_subject".to_string(),
            provider: Some("oidc".to_string()),
            issuer: Some("issuer.example".to_string()),
            subject: Some("subject-123".to_string()),
            audience: Some("splendor-daemon".to_string()),
            key_id: Some("kid-1".to_string()),
            proof_digest: "blake3:abc123".to_string(),
            digest_algorithm: "blake3".to_string(),
            evidence_refs: vec!["evidence:proof-1".to_string()],
        }],
        display: Some(PrincipalDisplay {
            display_name: Some("daemon client".to_string()),
            description: None,
        }),
        metadata: std::collections::BTreeMap::new(),
        created_at: now,
        updated_at: now,
        superseded_by: None,
    };

    round_trip(&principal);
    assert_eq!(principal.principal_id, principal_id);
}

#[test]
fn identity_lifecycle_event_records_digest_and_evidence_refs_only() {
    let now = time::OffsetDateTime::now_utc();
    let event = IdentityLifecycleEvent {
        identity_event_id: IdentityEventId::new(),
        principal_id: PrincipalId::new(),
        previous_revision: Some(IdentityRevision::initial()),
        new_revision: IdentityRevision::new(2),
        event_kind: IdentityLifecycleEventKind::ProofRotated,
        previous_status: Some(PrincipalStatus::Active),
        new_status: Some(PrincipalStatus::Active),
        actor_principal_id: None,
        reason_code: "rotate_test_proof".to_string(),
        proof_digest: Some("blake3:def456".to_string()),
        evidence_refs: vec!["evidence:rotation-1".to_string()],
        occurred_at: now,
        recorded_at: now,
    };

    let encoded = serde_json::to_value(&event).expect("event json");
    assert_eq!(encoded["event_kind"], "principal.proof_rotated");
    assert_eq!(encoded["proof_digest"], "blake3:def456");
    assert!(encoded.get("credential").is_none());
    assert!(encoded.get("token").is_none());
    round_trip(&event);
}

#[test]
fn identity_query_and_snapshot_contracts_are_identity_facts_only() {
    let now = time::OffsetDateTime::now_utc();
    let principal_id = PrincipalId::new();
    let tenant_id = TenantId::new();
    let query = IdentityQuery {
        lookup: IdentityLookupKey::PrincipalId {
            principal_id: principal_id.clone(),
        },
        expected_revision: Some(IdentityRevision::new(7)),
    };
    let snapshot = PrincipalSnapshot {
        principal_id: principal_id.clone(),
        kind: PrincipalKind::Service,
        status: PrincipalStatus::Suspended,
        revision: IdentityRevision::new(7),
        owner_tenant_id: Some(tenant_id.clone()),
        owner_fleet_id: None,
        read_at: now,
    };
    let result = IdentityQueryResult {
        query_summary: IdentityQuerySummary::from_query(&query),
        read_at: now,
        snapshots: vec![snapshot],
    };

    let encoded = serde_json::to_value(&result).expect("query result json");
    assert_eq!(encoded["query_summary"]["lookup"]["kind"], "principal_id");
    assert_eq!(encoded["snapshots"][0]["status"], "suspended");
    assert_eq!(encoded["snapshots"][0]["revision"], 7);
    assert_eq!(
        encoded["snapshots"][0]["owner_tenant_id"],
        tenant_id.to_string()
    );
    assert!(encoded.get("allowed_permissions").is_none());
    assert!(encoded.get("capability").is_none());
    assert!(encoded.get("work_order").is_none());
    round_trip(&result);
}

#[test]
fn identity_query_result_redacts_raw_lookup_material() {
    let now = time::OffsetDateTime::now_utc();
    let query = IdentityQuery {
        lookup: IdentityLookupKey::Binding {
            binding: PrincipalBinding::ExternalSubject {
                provider: "OIDC".to_string(),
                issuer: "issuer.example".to_string(),
                subject: "Subject-Exact".to_string(),
                audience: "SPLENDOR-DAEMON".to_string(),
            },
        },
        expected_revision: None,
    };
    let result = IdentityQueryResult {
        query_summary: IdentityQuerySummary::from_query(&query),
        read_at: now,
        snapshots: Vec::new(),
    };

    let encoded = serde_json::to_string(&result).expect("query result json");
    assert!(encoded.contains("external_subject"));
    assert!(!encoded.contains("Subject-Exact"));
    assert!(!encoded.contains("issuer.example"));
    assert!(!encoded.contains("SPLENDOR-DAEMON"));
    round_trip(&result);
}

#[test]
fn identity_lookup_keys_cover_exact_binding_and_owner_queries() {
    let binding_query = IdentityQuery {
        lookup: IdentityLookupKey::Binding {
            binding: PrincipalBinding::ExternalSubject {
                provider: "OIDC".to_string(),
                issuer: "issuer.example".to_string(),
                subject: "Subject-Exact".to_string(),
                audience: "SPLENDOR-DAEMON".to_string(),
            },
        },
        expected_revision: None,
    };
    let tenant_query = IdentityQuery {
        lookup: IdentityLookupKey::OwnerTenant {
            owner_tenant_id: TenantId::new(),
        },
        expected_revision: None,
    };
    let fleet_query = IdentityQuery {
        lookup: IdentityLookupKey::OwnerFleet {
            owner_fleet_id: FleetId::new(),
        },
        expected_revision: None,
    };

    round_trip(&binding_query);
    round_trip(&tenant_query);
    round_trip(&fleet_query);
}
