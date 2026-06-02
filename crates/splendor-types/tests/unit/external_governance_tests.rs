use super::*;
use crate::{
    AgentId, ApprovalId, ContentHash, GovernanceIssuer, GovernanceScope, GovernanceTraceLink,
    RevocationStatus, RunId, StateNodeId, TenantId, TraceEventId, WorkOrder, WorkOrderEnvelope,
    WorkOrderId, WorkOrderPlacement, WorkOrderQuotaPolicy, WORK_ORDER_SCHEMA_VERSION,
};
use serde_json::json;
use time::{Duration, OffsetDateTime};

fn issuer() -> GovernanceIssuer {
    GovernanceIssuer::new("control_plane.approver", "external_adapter").expect("issuer")
}

fn external_ref(provider: &str) -> ExternalGovernanceReference {
    ExternalGovernanceReference::new(
        provider,
        format!("{provider}_ref_123"),
        Some(format!("/{provider}/approvals")),
    )
    .expect("external ref")
}

fn action_scope(tenant_id: TenantId, agent_id: AgentId, run_id: RunId) -> GovernanceScope {
    GovernanceScope::Action {
        tenant_id,
        agent_id,
        run_id,
        action_id: crate::ActionId::new(),
    }
}

fn trace_link(run_id: &RunId, sequence: u64) -> GovernanceTraceLink {
    GovernanceTraceLink::new(
        TraceEventId::from_run_sequence(run_id, sequence),
        Some(run_id.clone()),
    )
}

fn scoped_work_order(now: OffsetDateTime) -> WorkOrder {
    WorkOrder {
        schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new("wo_external_bridge_123").expect("work order id"),
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id: Some(RunId::new()),
        objective: "publish governed artifact".to_string(),
        allowed_actions: vec!["artifact.publish".to_string()],
        allowed_adapters: vec!["artifact-store".to_string()],
        allowed_permissions: vec!["artifact.publish".to_string()],
        data_refs: vec!["artifact:draft-weekly-report".to_string()],
        quotas: WorkOrderQuotaPolicy {
            max_actions_per_tick: Some(1),
            ..WorkOrderQuotaPolicy::default()
        },
        placement: WorkOrderPlacement::default(),
        issued_at: now,
        expires_at: now + Duration::hours(1),
        revocation: RevocationStatus::Active,
    }
}

fn approval_decision(
    scope: GovernanceScope,
    decision: ExternalApprovalDecisionKind,
    trace_run_id: &RunId,
    sequence: u64,
) -> ExternalApprovalDecision {
    let now = OffsetDateTime::now_utc();
    ExternalApprovalDecision {
        schema_version: EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION.to_string(),
        external_ref: external_ref("harmony"),
        approval_id: ApprovalId::new(),
        scope,
        decision,
        created_at: now,
        expires_at: now + Duration::minutes(15),
        reason: "operator reviewed external governance signal".to_string(),
        issuer: issuer(),
        trace: trace_link(trace_run_id, sequence),
        extensions: GovernanceExtensions::new(),
    }
}

#[test]
fn external_work_order_bridge_accepts_scoped_signed_work_orders_without_credentials() {
    let now = OffsetDateTime::now_utc();
    let work_order = scoped_work_order(now);
    let envelope = WorkOrderEnvelope::signed_with_shared_secret(
        work_order,
        "test-key",
        b"local bridge secret",
    )
    .expect("signed work order");
    let run_id = envelope.work_order.run_id.clone().expect("run binding");

    let bridge = ExternalGovernanceWorkOrderBridge::new(
        external_ref("harmony"),
        envelope,
        issuer(),
        trace_link(&run_id, 1),
        GovernanceExtensions::from([(
            "workspace_ref".to_string(),
            json!("finance-weekly-dashboard"),
        )]),
    )
    .expect("scoped bridge");

    assert_eq!(
        bridge.schema_version,
        EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION
    );
    assert!(bridge.work_order.signature.is_some());
    assert_eq!(
        bridge.work_order.work_order.allowed_actions,
        ["artifact.publish"]
    );
    assert_eq!(
        bridge.work_order.work_order.allowed_adapters,
        ["artifact-store"]
    );
}

#[test]
fn external_work_order_bridge_rejects_unsigned_or_broad_credential_metadata() {
    let now = OffsetDateTime::now_utc();
    let work_order = scoped_work_order(now);
    let run_id = work_order.run_id.clone().expect("run binding");
    let unsigned = WorkOrderEnvelope {
        work_order,
        signature: None,
    };

    let unsigned_error = ExternalGovernanceWorkOrderBridge::new(
        external_ref("harmony"),
        unsigned,
        issuer(),
        trace_link(&run_id, 2),
        GovernanceExtensions::new(),
    )
    .expect_err("unsigned bridge fails closed");
    assert!(matches!(
        unsigned_error,
        ExternalGovernanceAdapterError::UnsignedWorkOrder
    ));

    let envelope = WorkOrderEnvelope::signed_with_shared_secret(
        scoped_work_order(now),
        "test-key",
        b"local bridge secret",
    )
    .expect("signed work order");
    let run_id = envelope.work_order.run_id.clone().expect("run binding");
    let credential_error = ExternalGovernanceWorkOrderBridge::new(
        external_ref("harmony"),
        envelope,
        issuer(),
        trace_link(&run_id, 3),
        GovernanceExtensions::from([("user_credentials".to_string(), json!("oauth-token"))]),
    )
    .expect_err("credential metadata fails closed");
    assert!(matches!(
        credential_error,
        ExternalGovernanceAdapterError::BroadCredentialSupplied { .. }
    ));

    let envelope = WorkOrderEnvelope::signed_with_shared_secret(
        scoped_work_order(now),
        "test-key",
        b"local bridge secret",
    )
    .expect("signed work order");
    let run_id = envelope.work_order.run_id.clone().expect("run binding");
    let alias_error = ExternalGovernanceWorkOrderBridge::new(
        external_ref("harmony"),
        envelope,
        issuer(),
        trace_link(&run_id, 33),
        GovernanceExtensions::from([
            ("accessToken".to_string(), json!("token")),
            (
                "nested".to_string(),
                json!({"oauth_token": "nested-token", "workspace_ref": "ok"}),
            ),
        ]),
    )
    .expect_err("credential aliases fail closed");
    assert!(matches!(
        alias_error,
        ExternalGovernanceAdapterError::BroadCredentialSupplied { .. }
    ));
}

#[test]
fn external_approval_decisions_map_to_scoped_grants_and_denials() {
    let now = OffsetDateTime::now_utc();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let scope = action_scope(tenant_id, agent_id, run_id.clone());
    let expires_at = now + Duration::minutes(15);

    let grant = ExternalApprovalDecision {
        schema_version: EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION.to_string(),
        external_ref: external_ref("harmony"),
        approval_id: ApprovalId::new(),
        scope: scope.clone(),
        decision: ExternalApprovalDecisionKind::Granted,
        created_at: now,
        expires_at,
        reason: "cfo approved publication".to_string(),
        issuer: issuer(),
        trace: trace_link(&run_id, 4),
        extensions: GovernanceExtensions::new(),
    }
    .into_mapping()
    .expect("grant mapping");

    let ExternalApprovalMapping::Grant { approval } = grant else {
        panic!("expected grant mapping");
    };
    assert_eq!(approval.scope, scope);
    assert_eq!(approval.status, ApprovalStatus::Granted);
    assert_eq!(approval.expires_at, Some(expires_at));
    assert_eq!(approval.issuer.source, "external_adapter");
    assert_eq!(approval.trace.run_id.as_ref(), Some(&run_id));
    assert!(approval.extensions.contains_key("external_ref"));

    let denial_scope = action_scope(TenantId::new(), AgentId::new(), run_id.clone());
    let denial = ExternalApprovalDecision {
        schema_version: EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION.to_string(),
        external_ref: external_ref("customer_console"),
        approval_id: ApprovalId::new(),
        scope: denial_scope.clone(),
        decision: ExternalApprovalDecisionKind::Denied,
        created_at: now,
        expires_at,
        reason: "publication window closed".to_string(),
        issuer: issuer(),
        trace: trace_link(&run_id, 5),
        extensions: GovernanceExtensions::new(),
    }
    .into_mapping()
    .expect("denial mapping");

    let ExternalApprovalMapping::Denial { approval } = denial else {
        panic!("expected denial mapping");
    };
    assert_eq!(approval.scope, denial_scope);
    assert_eq!(approval.status, ApprovalStatus::Denied);
    assert_eq!(approval.expires_at, Some(expires_at));
    assert_eq!(approval.trace.run_id.as_ref(), Some(&run_id));
}

#[test]
fn external_approval_grants_reject_broad_scopes() {
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::minutes(15);
    let run_id = RunId::new();
    let broad_grant = ExternalApprovalDecision {
        schema_version: EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION.to_string(),
        external_ref: external_ref("harmony"),
        approval_id: ApprovalId::new(),
        scope: GovernanceScope::Tenant {
            tenant_id: TenantId::new(),
        },
        decision: ExternalApprovalDecisionKind::Granted,
        created_at: now,
        expires_at,
        reason: "blanket approval should not be accepted".to_string(),
        issuer: issuer(),
        trace: trace_link(&run_id, 55),
        extensions: GovernanceExtensions::new(),
    }
    .into_mapping()
    .expect_err("broad grant fails closed");

    assert!(matches!(
        broad_grant,
        ExternalGovernanceAdapterError::BroadApprovalGrantScope { scope: "tenant" }
    ));
}

#[test]
fn external_approval_grants_reject_all_non_action_scope_labels() {
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let broad_scopes = [
        ("global", GovernanceScope::Global),
        (
            "fleet",
            GovernanceScope::Fleet {
                fleet_id: crate::FleetId::new(),
            },
        ),
        (
            "node",
            GovernanceScope::Node {
                node_id: crate::NodeId::new(),
            },
        ),
        (
            "instance",
            GovernanceScope::Instance {
                instance_id: crate::InstanceId::new(),
            },
        ),
        (
            "tenant",
            GovernanceScope::Tenant {
                tenant_id: tenant_id.clone(),
            },
        ),
        (
            "agent",
            GovernanceScope::Agent {
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
            },
        ),
        (
            "run",
            GovernanceScope::Run {
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                run_id: run_id.clone(),
            },
        ),
        (
            "adapter",
            GovernanceScope::Adapter {
                tenant_id: Some(tenant_id),
                adapter: "artifact-store".to_string(),
            },
        ),
    ];

    for (index, (expected_scope, scope)) in broad_scopes.into_iter().enumerate() {
        let error = approval_decision(
            scope,
            ExternalApprovalDecisionKind::Granted,
            &run_id,
            70 + index as u64,
        )
        .validate()
        .expect_err("non-action grants fail closed");

        assert!(
            matches!(
                error,
                ExternalGovernanceAdapterError::BroadApprovalGrantScope { scope }
                    if scope == expected_scope
            ),
            "expected broad scope label {expected_scope}, got {error:?}"
        );
    }
}

#[test]
fn external_approval_validation_fails_closed_on_expiry_trace_and_metadata() {
    let run_id = RunId::new();
    let mut expired = approval_decision(
        action_scope(TenantId::new(), AgentId::new(), run_id.clone()),
        ExternalApprovalDecisionKind::Granted,
        &run_id,
        80,
    );
    expired.expires_at = expired.created_at;
    let error = expired.validate().expect_err("expiry must move forward");
    assert!(matches!(
        error,
        ExternalGovernanceAdapterError::InvalidExpiry
    ));

    let scope_run_id = RunId::new();
    let trace_run_id = RunId::new();
    let mismatch = approval_decision(
        GovernanceScope::Run {
            tenant_id: TenantId::new(),
            agent_id: AgentId::new(),
            run_id: scope_run_id,
        },
        ExternalApprovalDecisionKind::Denied,
        &trace_run_id,
        81,
    );
    let error = mismatch
        .validate()
        .expect_err("trace/run mismatch fails closed");
    assert!(matches!(
        error,
        ExternalGovernanceAdapterError::Governance(
            GovernanceValidationError::RunScopeMismatch { .. }
        )
    ));

    let mut nested_authority = approval_decision(
        action_scope(TenantId::new(), AgentId::new(), run_id.clone()),
        ExternalApprovalDecisionKind::Granted,
        &run_id,
        82,
    );
    nested_authority.extensions = GovernanceExtensions::from([(
        "safe_context".to_string(),
        json!([{"workspace_ref": "finance", "apiKey": "must-not-cross-boundary"}]),
    )]);
    let error = nested_authority
        .validate()
        .expect_err("nested credential metadata fails closed");
    assert!(matches!(
        error,
        ExternalGovernanceAdapterError::BroadCredentialSupplied { .. }
    ));

    let mut blank_key = approval_decision(
        action_scope(TenantId::new(), AgentId::new(), run_id.clone()),
        ExternalApprovalDecisionKind::Granted,
        &run_id,
        83,
    );
    blank_key.extensions = GovernanceExtensions::from([(" authority ".to_string(), json!(true))]);
    let error = blank_key
        .validate()
        .expect_err("blank/trimmed authority keys fail closed");
    assert!(matches!(
        error,
        ExternalGovernanceAdapterError::BroadCredentialSupplied { .. }
    ));
}

#[test]
fn adapter_failure_mapping_is_fail_closed_and_never_grants() {
    let now = OffsetDateTime::now_utc();
    let run_id = RunId::new();
    let failure = ExternalGovernanceAdapterFailure::new(
        external_ref("harmony"),
        action_scope(TenantId::new(), AgentId::new(), run_id.clone()),
        now,
        "external approval endpoint unavailable",
        issuer(),
        trace_link(&run_id, 6),
    )
    .expect("adapter failure");

    let mapping = failure.into_mapping();
    assert!(!mapping.contains_approval_grant());
    let value = serde_json::to_value(mapping).expect("mapping json");
    assert_eq!(value["mapping"], "adapter_failure");
    assert!(value.get("approval").is_none());
}

#[test]
fn governed_artifact_refs_include_state_trace_approval_and_source_scope() {
    let run_id = RunId::new();
    let artifact = GovernedArtifactRef {
        schema_version: GOVERNED_ARTIFACT_REF_SCHEMA_VERSION.to_string(),
        artifact_id: "artifact_weekly_dashboard".to_string(),
        version: Some("v2".to_string()),
        source_refs: vec!["dataset:finance.revenue_monthly_v4".to_string()],
        run_id: run_id.clone(),
        state_node_id: StateNodeId::from_hash(ContentHash::blake3(b"artifact state")),
        trace_range: ExternalTraceRange::new(
            TraceEventId::from_run_sequence(&run_id, 10),
            TraceEventId::from_run_sequence(&run_id, 19),
        )
        .expect("trace range"),
        approval_state: ApprovalStatus::Granted,
        approval_id: Some(ApprovalId::new()),
        external_ref: Some(external_ref("harmony")),
        export_targets: vec!["harmony:artifact-registry".to_string()],
    };

    artifact.validate().expect("valid artifact ref");
    let value = serde_json::to_value(&artifact).expect("artifact json");
    for field in [
        "artifact_id",
        "source_refs",
        "run_id",
        "state_node_id",
        "trace_range",
        "approval_state",
    ] {
        assert!(
            value.get(field).is_some(),
            "artifact ref must include {field}"
        );
    }

    let mut missing_sources = artifact;
    missing_sources.source_refs.clear();
    let error = missing_sources
        .validate()
        .expect_err("source refs are required");
    assert!(
        matches!(error, ExternalGovernanceAdapterError::Missing { field } if field == "source_refs")
    );

    let missing_approval = GovernedArtifactRef {
        schema_version: GOVERNED_ARTIFACT_REF_SCHEMA_VERSION.to_string(),
        artifact_id: "artifact_without_approval_id".to_string(),
        version: None,
        source_refs: vec!["dataset:finance.revenue_monthly_v4".to_string()],
        run_id: run_id.clone(),
        state_node_id: StateNodeId::from_hash(ContentHash::blake3(b"artifact state 2")),
        trace_range: ExternalTraceRange::new(
            TraceEventId::from_run_sequence(&run_id, 20),
            TraceEventId::from_run_sequence(&run_id, 21),
        )
        .expect("trace range"),
        approval_state: ApprovalStatus::Granted,
        approval_id: None,
        external_ref: None,
        export_targets: Vec::new(),
    };
    let error = missing_approval
        .validate()
        .expect_err("granted artifact requires approval id");
    assert!(
        matches!(error, ExternalGovernanceAdapterError::Missing { field } if field == "approval_id")
    );
}

#[test]
fn governed_artifact_refs_reject_schema_trace_and_export_failures() {
    let run_id = RunId::new();
    let artifact = GovernedArtifactRef {
        schema_version: GOVERNED_ARTIFACT_REF_SCHEMA_VERSION.to_string(),
        artifact_id: "artifact_weekly_dashboard".to_string(),
        version: Some("v2".to_string()),
        source_refs: vec!["dataset:finance.revenue_monthly_v4".to_string()],
        run_id: run_id.clone(),
        state_node_id: StateNodeId::from_hash(ContentHash::blake3(b"artifact state")),
        trace_range: ExternalTraceRange::new(
            TraceEventId::from_run_sequence(&run_id, 90),
            TraceEventId::from_run_sequence(&run_id, 91),
        )
        .expect("trace range"),
        approval_state: ApprovalStatus::Granted,
        approval_id: Some(ApprovalId::new()),
        external_ref: Some(external_ref("harmony")),
        export_targets: vec!["harmony:artifact-registry".to_string()],
    };

    let mut unsupported_schema = artifact.clone();
    unsupported_schema.schema_version = "splendor.governed_artifact_ref.v99".to_string();
    let error = unsupported_schema
        .validate()
        .expect_err("unsupported artifact schemas fail closed");
    assert!(matches!(
        error,
        ExternalGovernanceAdapterError::UnsupportedSchema { .. }
    ));

    let mut blank_export_target = artifact;
    blank_export_target.export_targets = vec![" harmony:artifact-registry ".to_string()];
    let error = blank_export_target
        .validate()
        .expect_err("blank or padded export targets fail closed");
    assert!(
        matches!(error, ExternalGovernanceAdapterError::Missing { field } if field == "export_targets")
    );

    let nil_trace =
        TraceEventId::parse("00000000-0000-0000-0000-000000000000").expect("nil trace id parses");
    let error = ExternalTraceRange::new(nil_trace, TraceEventId::from_run_sequence(&run_id, 92))
        .expect_err("nil trace IDs fail closed");
    assert!(
        matches!(error, ExternalGovernanceAdapterError::InvalidTraceId { field } if field == "trace_range.start_trace_event_id")
    );
}

#[test]
fn same_contract_supports_harmony_and_generic_control_planes() {
    let harmony = ExternalGovernanceAdapterContract::harmony_compatible().expect("harmony");
    let generic = ExternalGovernanceAdapterContract::new(
        "customer_console",
        ExternalGovernanceEndpoints {
            work_orders: "/governed/work-orders/{work_order_id}".to_string(),
            action_gateway: "/governed/action-gateway".to_string(),
            approvals: "/governed/approval-decisions".to_string(),
            traces: "/governed/runtime-traces".to_string(),
            state_commits: "/governed/state-commits".to_string(),
            artifact_refs: "/governed/artifact-refs".to_string(),
        },
    )
    .expect("generic contract");

    assert_eq!(harmony.schema_version, generic.schema_version);
    assert_eq!(harmony.provider, "harmony");
    assert_eq!(generic.provider, "customer_console");
    assert_ne!(harmony.endpoints.approvals, generic.endpoints.approvals);
    harmony.validate().expect("harmony valid");
    generic.validate().expect("generic valid");

    let invalid = ExternalGovernanceAdapterContract::new(
        "customer_console",
        ExternalGovernanceEndpoints {
            work_orders: "//attacker.example/work-orders".to_string(),
            action_gateway: "/governed/action-gateway".to_string(),
            approvals: "/governed/approval-decisions".to_string(),
            traces: "/governed/runtime-traces".to_string(),
            state_commits: "/governed/state-commits".to_string(),
            artifact_refs: "/governed/artifact-refs".to_string(),
        },
    )
    .expect_err("scheme-relative endpoint rejected");
    assert!(matches!(
        invalid,
        ExternalGovernanceAdapterError::InvalidEndpoint { .. }
    ));
}

#[test]
fn external_contracts_reject_unsupported_schema_and_invalid_references() {
    let mut contract = ExternalGovernanceAdapterContract::harmony_compatible().expect("harmony");
    contract.schema_version = "splendor.external_governance_adapter.v99".to_string();
    let error = contract
        .validate()
        .expect_err("unsupported contract schema fails closed");
    assert!(matches!(
        error,
        ExternalGovernanceAdapterError::UnsupportedSchema { .. }
    ));

    let invalid_endpoint = ExternalGovernanceReference::new(
        "harmony",
        "approval_123",
        Some("/splendor//approvals".to_string()),
    )
    .expect_err("malformed route fails closed");
    assert!(matches!(
        invalid_endpoint,
        ExternalGovernanceAdapterError::InvalidEndpoint { .. }
    ));

    let blank_provider = ExternalGovernanceReference::new(" harmony", "approval_123", None)
        .expect_err("padded provider fails closed");
    assert!(
        matches!(blank_provider, ExternalGovernanceAdapterError::Missing { field } if field == "external_ref.provider")
    );
}
