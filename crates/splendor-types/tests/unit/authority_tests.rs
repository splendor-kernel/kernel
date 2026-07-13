use super::*;
use crate::TASK_RESPONSE_SCHEMA;

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
fn authority_obligation_legacy_default_uses_current_schema() {
    let obligation: AuthorityObligation = serde_json::from_value(serde_json::json!({
        "obligation_id": AuthorityObligationId::new(),
        "kind": "human_review",
        "description": "review",
        "parameters": {}
    }))
    .expect("legacy obligation defaults schema");
    assert_eq!(
        obligation.schema_version,
        AUTHORITY_OBLIGATION_SCHEMA_VERSION
    );
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
        tenant_ids: Some(vec![TenantId::parse(
            "10000000-0000-4000-8000-000000000001",
        )
        .expect("tenant id")]),
        agent_ids: Some(vec![
            AgentId::parse("20000000-0000-4000-8000-000000000002").expect("agent id")
        ]),
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

#[test]
fn authority_obligations_and_receipts_are_typed_and_schema_versioned() {
    let now = time::OffsetDateTime::now_utc();
    let obligation_id = AuthorityObligationId::new();
    let decision_id = AuthorityDecisionId::new();
    let subject = PrincipalId::new();
    let obligation = AuthorityObligation {
        schema_version: AUTHORITY_OBLIGATION_SCHEMA_VERSION.to_string(),
        obligation_id: obligation_id.clone(),
        kind: AuthorityObligationKind::HumanReview,
        description: "human reviewer must approve high-risk operation".to_string(),
        parameters: std::collections::BTreeMap::new(),
    };
    let receipt = AuthorityObligationReceipt {
        schema_version: AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: AuthorityObligationReceiptId::new(),
        issuer: PrincipalId::new(),
        audience: "daemon:local".to_string(),
        obligation_id,
        kind: AuthorityObligationKind::HumanReview,
        subject: subject.clone(),
        authority_decision_id: decision_id.clone(),
        canonical_request_digest:
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        evidence_digest: "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_string(),
        evidence_ref: Some("approval-evidence:review-1".to_string()),
        issued_at: now,
        expires_at: now + time::Duration::minutes(10),
        revocation: RevocationStatus::Active,
        revocation_ref: "revocation:receipt-review-1".to_string(),
        approval_id: Some(ApprovalId::new()),
        approval_trace_event_id: Some(TraceEventId::new()),
        validation: AuthorityObligationReceiptValidation {
            validation_kind: AuthorityObligationReceiptValidationKind::LocalSignature,
            algorithm: "local-obligation-receipt-v1".to_string(),
            key_id: "receipt-key-1".to_string(),
            digest: "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_string(),
            signature: "blake3:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
        },
    };
    let statuses = vec![
        AuthorityDecisionStatus::Allowed,
        AuthorityDecisionStatus::Denied,
        AuthorityDecisionStatus::Conditional,
        AuthorityDecisionStatus::NeedsApproval,
        AuthorityDecisionStatus::NeedsIntervention,
    ];
    let kinds = vec![
        AuthorityObligationKind::ApprovalRequired,
        AuthorityObligationKind::MfaAssurance,
        AuthorityObligationKind::DedicatedIsolation,
        AuthorityObligationKind::NetworkDeny,
        AuthorityObligationKind::HumanReview,
        AuthorityObligationKind::IndependentEvaluator,
        AuthorityObligationKind::LocalSafetyVerifier,
        AuthorityObligationKind::PostconditionCheck,
        AuthorityObligationKind::MaximumBlastRadius,
        AuthorityObligationKind::EvidenceRequired,
    ];
    let json = serde_json::to_value(&receipt).expect("receipt json");

    assert_eq!(
        json["schema_version"],
        AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION
    );
    assert_eq!(json["obligation_id"], receipt.obligation_id.to_string());
    assert_eq!(json["receipt_id"], receipt.receipt_id.to_string());
    assert_eq!(json["issuer"], receipt.issuer.to_string());
    assert_eq!(json["audience"], "daemon:local");
    assert_eq!(json["kind"], "human_review");
    assert_eq!(json["subject"], subject.to_string());
    assert_eq!(json["authority_decision_id"], decision_id.to_string());
    assert_eq!(json["validation"]["validation_kind"], "local_signature");
    assert_eq!(json["validation"]["key_id"], "receipt-key-1");
    let mut unknown_receipt = json.clone();
    unknown_receipt["allowed_permissions"] = serde_json::json!(["admin"]);
    assert!(serde_json::from_value::<AuthorityObligationReceipt>(unknown_receipt).is_err());
    let mut unknown_validation = json.clone();
    unknown_validation["validation"]["credential"] = serde_json::json!("secret");
    assert!(serde_json::from_value::<AuthorityObligationReceipt>(unknown_validation).is_err());
    assert_eq!(
        serde_json::to_value(&statuses).expect("statuses json"),
        serde_json::json!([
            "allowed",
            "denied",
            "conditional",
            "needs_approval",
            "needs_intervention"
        ])
    );
    assert_eq!(
        serde_json::to_value(&kinds).expect("kinds json"),
        serde_json::json!([
            "approval_required",
            "mfa_assurance",
            "dedicated_isolation",
            "network_deny",
            "human_review",
            "independent_evaluator",
            "local_safety_verifier",
            "postcondition_check",
            "maximum_blast_radius",
            "evidence_required"
        ])
    );
    round_trip(&obligation);
    round_trip(&receipt);
}

#[test]
fn delegation_grant_and_chain_contracts_round_trip_without_behavior() {
    let now = time::OffsetDateTime::now_utc();
    let parent_grant_id = CapabilityGrantId::new();
    let parent_agent_id = AgentId::new();
    let child_agent_id = AgentId::new();
    let child_run_id = RunId::new();
    let parent_run_id = RunId::new();
    let child_subject = PrincipalId::new();
    let mut scope = CapabilityScope {
        tenant_ids: Some(vec![TenantId::new()]),
        agent_ids: Some(vec![child_agent_id.clone()]),
        run_ids: Some(vec![child_run_id.clone()]),
        audiences: Some(vec!["daemon:local".to_string()]),
        budget: AuthorityBudgetScope {
            max_actions_per_tick: Some(2),
            ..Default::default()
        },
        ..Default::default()
    };
    scope.time.expires_at = Some(now + time::Duration::minutes(10));
    let child_capability_grant = CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: CapabilityGrantId::new(),
        issuer: PrincipalId::new(),
        subject: child_subject,
        parent_grant_ids: vec![parent_grant_id.clone()],
        operations: vec![action_operation("artifact.create")],
        scope: scope.clone(),
        not_before: now,
        expires_at: now + time::Duration::minutes(10),
        revocation_ref: Some("revocation:delegation".to_string()),
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth: 0,
        validation: Some(CapabilityGrantValidation {
            validation_kind: CapabilityGrantValidationKind::LocallyValidated,
            algorithm: "local-delegation-v1".to_string(),
            key_id: None,
            digest: "blake3:2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            signature: None,
        }),
        metadata: std::collections::BTreeMap::new(),
    };
    let result_contract = DelegationResultContract {
        schema_version: DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION.to_string(),
        result_schema: TASK_RESPONSE_SCHEMA.to_string(),
        requires_response: true,
        max_result_bytes: Some(4096),
    };
    let delegation_grant = DelegationGrant {
        schema_version: DELEGATION_GRANT_SCHEMA_VERSION.to_string(),
        binding_digest: "blake3:test-binding".to_string(),
        parent_grant_id: parent_grant_id.clone(),
        parent_run_id,
        parent_agent_id,
        child_run_id,
        child_agent_id: child_agent_id.clone(),
        objective: "summarize scoped artifact".to_string(),
        role_profile: DelegationRoleProfile::Specialist,
        allowed_message_schemas: vec![TASK_RESPONSE_SCHEMA.to_string()],
        allowed_recipient_agent_ids: vec![child_agent_id],
        result_contract,
        budget: scope.budget,
        not_before: now,
        expires_at: now + time::Duration::minutes(10),
        remaining_delegation_depth: 0,
        max_fan_out: 1,
        cleanup_obligations: DelegationCleanupObligations::default(),
        child_capability_grant,
    };
    let chain = DelegationChain {
        schema_version: DELEGATION_CHAIN_SCHEMA_VERSION.to_string(),
        root_grant_id: parent_grant_id,
        grants: vec![delegation_grant.clone()],
        max_depth: 1,
    };
    let json = serde_json::to_value(&delegation_grant).expect("delegation json");

    assert_eq!(json["schema_version"], DELEGATION_GRANT_SCHEMA_VERSION);
    assert_eq!(json["role_profile"], "specialist");
    assert_eq!(
        json["result_contract"]["schema_version"],
        DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(
        json["child_capability_grant"]["schema_version"],
        CAPABILITY_GRANT_SCHEMA_VERSION
    );
    round_trip(&delegation_grant);
    round_trip(&chain);
}

#[test]
fn policy_distribution_unknown_authority_validation_enums_fail_serde() {
    let now = time::OffsetDateTime::parse(
        "2026-07-12T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .expect("fixed authority time");
    let scope = CapabilityScope {
        tenant_ids: Some(vec![TenantId::new()]),
        agent_ids: Some(vec![AgentId::new()]),
        audiences: Some(vec!["daemon:local".to_string()]),
        ..Default::default()
    };
    let grant = CapabilityGrant {
        schema_version: CAPABILITY_GRANT_SCHEMA_VERSION.to_string(),
        grant_id: CapabilityGrantId::parse("30000000-0000-4000-8000-000000000003")
            .expect("grant id"),
        issuer: PrincipalId::parse("40000000-0000-4000-8000-000000000004").expect("issuer id"),
        subject: PrincipalId::parse("50000000-0000-4000-8000-000000000005").expect("subject id"),
        parent_grant_ids: Vec::new(),
        operations: vec![action_operation("artifact.create")],
        scope,
        not_before: now,
        expires_at: now + time::Duration::hours(1),
        revocation_ref: None,
        revocation: RevocationStatus::Active,
        obligations: Vec::new(),
        max_delegation_depth: 0,
        validation: Some(CapabilityGrantValidation {
            validation_kind: CapabilityGrantValidationKind::LocallyValidated,
            algorithm: "local-test-v1".to_string(),
            key_id: None,
            digest: "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            signature: None,
        }),
        metadata: Default::default(),
    };

    for (path, value) in [
        ("/validation/validation_kind", "future_validator"),
        ("/operations/0/namespace", "future_namespace"),
        ("/operations/0/resource_kind", "future_resource"),
        ("/operations/0/verb", "future_verb"),
    ] {
        let mut raw = serde_json::to_value(&grant).expect("grant json");
        *raw.pointer_mut(path).expect("enum field") = serde_json::json!(value);
        serde_json::from_value::<CapabilityGrant>(raw)
            .expect_err("unknown closed authority enum must fail serde");
    }
}
