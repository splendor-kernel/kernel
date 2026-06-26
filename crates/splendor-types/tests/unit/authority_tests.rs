use super::*;

fn round_trip<T>(value: &T)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let encoded = serde_json::to_vec(value).expect("serialize authority type");
    let decoded: T = serde_json::from_slice(&encoded).expect("deserialize authority type");
    assert_eq!(&decoded, value);
}

fn action_operation(name: &str) -> AuthorityOperation {
    AuthorityOperation {
        schema_version: AUTHORITY_OPERATION_SCHEMA_VERSION.to_string(),
        namespace: AuthorityOperationNamespace::Gateway,
        resource_kind: AuthorityResourceKind::Action,
        verb: AuthorityVerb::Invoke,
        name: Some(name.to_string()),
        resource_schema_version: Some("splendor.action.v1".to_string()),
    }
}

#[test]
fn authority_operation_contract_is_typed_and_schema_versioned() {
    let operation = action_operation("artifact.create");
    let json = serde_json::to_value(&operation).expect("operation json");

    assert_eq!(json["schema_version"], AUTHORITY_OPERATION_SCHEMA_VERSION);
    assert_eq!(json["namespace"], "gateway");
    assert_eq!(json["resource_kind"], "action");
    assert_eq!(json["verb"], "invoke");
    assert_eq!(json["name"], "artifact.create");
    round_trip(&operation);
}

#[test]
fn authority_data_purposes_are_separate_contract_values() {
    let purposes = vec![
        DataPurpose::Read,
        DataPurpose::TrainingUse,
        DataPurpose::EvaluationUse,
        DataPurpose::Publication,
    ];
    let json = serde_json::to_value(&purposes).expect("purpose json");

    assert_eq!(
        json,
        serde_json::json!(["read", "training_use", "evaluation_use", "publication"])
    );
    assert_ne!(DataPurpose::Read, DataPurpose::TrainingUse);
    assert_ne!(DataPurpose::TrainingUse, DataPurpose::EvaluationUse);
    assert_ne!(DataPurpose::EvaluationUse, DataPurpose::Publication);
    round_trip(&purposes);
}

#[test]
fn authority_scope_carries_distinct_identity_dimensions() {
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let workload_id = WorkloadId::new();
    let device_id = DeviceId::new();
    let artifact_id = ArtifactId::new();
    let state_partition_id = StatePartitionId::new();
    let scope = CapabilityScope {
        tenant_ids: Some(vec![tenant_id.clone()]),
        agent_ids: Some(vec![agent_id.clone()]),
        run_ids: Some(vec![run_id.clone()]),
        workload_ids: Some(vec![workload_id.clone()]),
        device_ids: Some(vec![device_id.clone()]),
        artifact_ids: Some(vec![artifact_id.clone()]),
        state_partition_ids: Some(vec![state_partition_id.clone()]),
        audiences: Some(vec!["daemon:local".to_string()]),
        ..Default::default()
    };

    let json = serde_json::to_value(&scope).expect("scope json");
    assert_eq!(json["schema_version"], CAPABILITY_SCOPE_SCHEMA_VERSION);
    assert_eq!(json["tenant_ids"][0], tenant_id.to_string());
    assert_eq!(json["agent_ids"][0], agent_id.to_string());
    assert_eq!(json["run_ids"][0], run_id.to_string());
    assert_eq!(json["workload_ids"][0], workload_id.to_string());
    assert_eq!(json["device_ids"][0], device_id.to_string());
    assert_eq!(json["artifact_ids"][0], artifact_id.to_string());
    assert_eq!(
        json["state_partition_ids"][0],
        state_partition_id.to_string()
    );
    round_trip(&scope);
}

#[test]
fn authority_grant_and_decision_contracts_round_trip_without_behavior() {
    let now = time::OffsetDateTime::now_utc();
    let scope = CapabilityScope {
        tenant_ids: Some(vec![TenantId::new()]),
        agent_ids: Some(vec![AgentId::new()]),
        audiences: Some(vec!["daemon:local".to_string()]),
        ..Default::default()
    };
    let request = CapabilityRequest {
        schema_version: CAPABILITY_REQUEST_SCHEMA_VERSION.to_string(),
        subject: PrincipalId::new(),
        operation: action_operation("artifact.create"),
        scope: scope.clone(),
        requested_at: now,
        metadata: std::collections::BTreeMap::new(),
    };
    let grant = CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: CapabilityGrantId::new(),
        issuer: PrincipalId::new(),
        subject: request.subject.clone(),
        parent_grant_ids: Vec::new(),
        operations: vec![request.operation.clone()],
        scope,
        not_before: now,
        expires_at: now + time::Duration::hours(1),
        revocation_ref: Some("revocation:local".to_string()),
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth: 1,
        validation: Some(CapabilityGrantValidation {
            validation_kind: CapabilityGrantValidationKind::LocallyValidated,
            algorithm: "local-test-v1".to_string(),
            key_id: None,
            digest: "blake3:1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            signature: None,
        }),
        metadata: std::collections::BTreeMap::new(),
    };
    let decision = AuthorityDecision {
        schema_version: AUTHORITY_DECISION_SCHEMA_VERSION.to_string(),
        decision_id: AuthorityDecisionId::new(),
        request,
        status: AuthorityDecisionStatus::Allowed,
        reasons: vec!["capability_allowed".to_string()],
        matched_grant_ids: vec![grant.grant_id.clone()],
        obligations: Vec::new(),
        decided_at: now,
    };

    round_trip(&grant);
    round_trip(&decision);
}
