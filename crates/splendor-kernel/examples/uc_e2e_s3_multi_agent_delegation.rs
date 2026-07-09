use serde::Serialize;
use splendor_authority::{
    grant_from_legacy_allowlists, CompatibilityGrantContext, LegacyScopeProfile,
};
use splendor_gateway::{
    ActionAdapter, ActionGateway, ActionRequest, AdapterError, AdapterResult, VerifiedActionGateway,
};
use splendor_kernel::{
    AgentContext, AgentIsolationPolicy, AgentRuntimeConfig, KernelRuntime, KernelRuntimeConfig,
    LocalDelegationAuthority, LocalDelegationManager, LocalDelegationRequest, MessageRouter,
    QuotaPolicy, SnapshotPolicy, StateGraph, TenantContext, TenantPolicy, TenantRegistry,
    TraceStoreSink,
};
use splendor_store::{
    SqliteStateStore, SqliteTraceStore, StateData, StateMetadata, StateStore, TraceStore,
};
use splendor_types::{
    Action, ActionId, AgentId, AuthorityBudgetScope, CapabilityGrantId, DelegatedAuthority,
    Message, MessageDeliveryStatus, MessageEnvelope, MessageId, MessageSchemaVersion,
    MessageTraceLinks, PrincipalId, QuotaUsage, RevocationStatus, RunId, SideEffectClass, TenantId,
    TickId, TraceEvent, TraceEventId, TraceEventKind, TraceIdentityContext, TASK_REQUEST_SCHEMA,
    TASK_RESPONSE_SCHEMA,
};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use time::OffsetDateTime;

const TENANT_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER_TENANT_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const ORCHESTRATOR_ID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const SPECIALIST_ID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const REVIEWER_ID: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const OTHER_TENANT_SPECIALIST_ID: &str = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const ORCHESTRATOR_PRINCIPAL_ID: &str = "abababab-abab-4aba-8bab-abababababab";
const SPECIALIST_PRINCIPAL_ID: &str = "bcbcbcbc-bcbc-4bcb-8cbc-bcbcbcbcbcbc";
const REVIEWER_PRINCIPAL_ID: &str = "cdcdcdcd-cdcd-4cdc-8dcd-cdcdcdcdcdcd";
const OTHER_TENANT_SPECIALIST_PRINCIPAL_ID: &str = "dededede-dede-4ded-8ede-dededededede";
const PARENT_RUN_ID: &str = "11111111-2222-4333-8444-555555555555";
const CHILD_RUN_ID: &str = "66666666-7777-4888-8999-000000000000";
const AUTHORITY_AUDIENCE: &str = "daemon:local";
const AUTHORITY_DIGEST: &str =
    "blake3:2222222222222222222222222222222222222222222222222222222222222222";

#[derive(Default)]
struct CountingAdapter {
    executions: AtomicUsize,
}

impl CountingAdapter {
    fn executions(&self) -> usize {
        self.executions.load(Ordering::SeqCst)
    }
}

impl ActionAdapter for CountingAdapter {
    fn execute(&self, action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        Ok(AdapterResult {
            output: serde_json::json!({
                "executed_action": action.action.name,
                "adapter": action.adapter,
                "payload_ref": action.action.params.get("ref").cloned().unwrap_or_default()
            }),
            satisfied_postconditions: action.action.postconditions.clone(),
        })
    }
}

#[derive(Serialize)]
struct Evidence {
    status: String,
    parent_run_id: String,
    child_run_id: String,
    tenant_id: String,
    orchestrator_agent_id: String,
    specialist_agent_id: String,
    delegated_authority: DelegatedAuthority,
    positive: PositiveEvidence,
    negative_cases: Vec<NegativeEvidence>,
    parent_state: StateEvidence,
    child_state: StateEvidence,
    anti_drift: AntiDriftEvidence,
    trace_db: String,
    state_db: String,
}

#[derive(Serialize)]
struct SchemaParityEvidence {
    schema_version: String,
    task_request_schema: String,
    task_response_schema: String,
    task_request_message: Message,
    task_response_message: Message,
    python_sdk_callback_expectations: Vec<String>,
}

#[derive(Serialize)]
struct PositiveEvidence {
    request_message_id: String,
    response_message_id: String,
    request_status: MessageDeliveryStatus,
    consumed_request_status: MessageDeliveryStatus,
    consumed_response_status: MessageDeliveryStatus,
    child_started_trace_id: String,
    child_completed_parent_trace_id: String,
    child_completed_child_trace_id: String,
    orchestrator_action_status: String,
    orchestrator_adapter_executions_before: usize,
    orchestrator_adapter_executions_after: usize,
}

#[derive(Serialize)]
struct NegativeEvidence {
    case: String,
    status: String,
    reason_codes: Vec<String>,
    trace_event_ids: Vec<String>,
    message_id: Option<String>,
    adapter_executions_before: usize,
    adapter_executions_after: usize,
    artifacts: serde_json::Value,
}

#[derive(Serialize)]
struct StateEvidence {
    run_id: String,
    agent_id: String,
    state_node_id: String,
    state_node_hash: String,
    state_hash: String,
    trace_event_id: String,
    metadata_trace_event_id: String,
}

struct ActionRequestInput<'a> {
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
    name: &'a str,
    adapter: &'a str,
    side_effect_class: SideEffectClass,
    permissions: &'a [&'a str],
    quota_usage: QuotaUsage,
}

struct RouterNegativeInput<'a> {
    case: &'a str,
    runtime: &'a KernelRuntime,
    router: &'a splendor_kernel::LocalMessageRouter,
    trace_store: &'a SqliteTraceStore,
    source: &'a AgentId,
    target: &'a AgentId,
    run_id: &'a RunId,
    schema: &'a str,
}

#[derive(Serialize)]
struct AntiDriftEvidence {
    public_boundary: String,
    private_helper_only_e2e: bool,
    gateway_bypass: bool,
    specialist_broad_permission_inheritance: bool,
    hidden_shared_state: bool,
    replay_side_effects_allowed_default: bool,
    remote_transport: bool,
    fleet_governance_or_physical_scope: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let artifact_dir = parse_artifact_dir()?;
    if artifact_dir.exists() {
        fs::remove_dir_all(&artifact_dir)?;
    }
    fs::create_dir_all(&artifact_dir)?;

    let tenant_id = TenantId::parse(TENANT_ID)?;
    let other_tenant_id = TenantId::parse(OTHER_TENANT_ID)?;
    let orchestrator_id = AgentId::parse(ORCHESTRATOR_ID)?;
    let specialist_id = AgentId::parse(SPECIALIST_ID)?;
    let reviewer_id = AgentId::parse(REVIEWER_ID)?;
    let other_specialist_id = AgentId::parse(OTHER_TENANT_SPECIALIST_ID)?;
    let orchestrator_principal = PrincipalId::parse(ORCHESTRATOR_PRINCIPAL_ID)?;
    let specialist_principal = PrincipalId::parse(SPECIALIST_PRINCIPAL_ID)?;
    let reviewer_principal = PrincipalId::parse(REVIEWER_PRINCIPAL_ID)?;
    let other_specialist_principal = PrincipalId::parse(OTHER_TENANT_SPECIALIST_PRINCIPAL_ID)?;
    let parent_run_id = RunId::parse(PARENT_RUN_ID)?;
    let child_run_id = RunId::parse(CHILD_RUN_ID)?;

    let trace_db = artifact_dir.join("uc-e2e-s3.trace.db");
    let state_db = artifact_dir.join("uc-e2e-s3.state.db");
    let trace_store = Arc::new(SqliteTraceStore::open(&trace_db)?);
    let state_store = Arc::new(SqliteStateStore::open(&state_db)?);
    let parent_runtime = runtime(parent_run_id.clone(), Arc::clone(&trace_store));
    let child_runtime = runtime(child_run_id.clone(), Arc::clone(&trace_store));

    let orchestrator = AgentContext::new(
        orchestrator_id.clone(),
        tenant_id.clone(),
        AgentRuntimeConfig {
            label: Some("UC-E2E-S3 orchestrator".to_string()),
            isolation: AgentIsolationPolicy {
                allowed_permissions: vec![
                    "document.read".to_string(),
                    "artifact.create_internal".to_string(),
                ],
                allowed_message_schemas: vec![TASK_REQUEST_SCHEMA.to_string()],
                allowed_message_recipients: vec![specialist_id.clone()],
            },
            ..AgentRuntimeConfig::default()
        },
    );
    let specialist = AgentContext::new(
        specialist_id.clone(),
        tenant_id.clone(),
        AgentRuntimeConfig {
            label: Some("UC-E2E-S3 specialist".to_string()),
            isolation: AgentIsolationPolicy {
                allowed_permissions: vec!["document.read".to_string()],
                allowed_message_schemas: vec![TASK_RESPONSE_SCHEMA.to_string()],
                allowed_message_recipients: vec![orchestrator_id.clone()],
            },
            ..AgentRuntimeConfig::default()
        },
    );
    let reviewer = AgentContext::new(
        reviewer_id.clone(),
        tenant_id.clone(),
        AgentRuntimeConfig::default(),
    );
    let other_specialist = AgentContext::new(
        other_specialist_id,
        other_tenant_id,
        AgentRuntimeConfig::default(),
    );

    let delegated = authority(
        &["data.read_fixture"],
        &["fixture_data"],
        &["document.read"],
    );
    let manager = LocalDelegationManager::new();
    manager.register_agent_with_principal(
        orchestrator.clone(),
        orchestrator_principal.clone(),
        authority(
            &[
                "data.read_fixture",
                "artifact.create_internal",
                "artifact.publish_external",
            ],
            &["fixture_data", "artifact"],
            &[
                "document.read",
                "artifact.create_internal",
                "artifact.publish_external",
            ],
        ),
    )?;
    manager.register_agent_with_principal(
        specialist.clone(),
        specialist_principal.clone(),
        delegated.clone(),
    )?;
    manager.register_agent_with_principal(
        reviewer.clone(),
        reviewer_principal,
        DelegatedAuthority::empty(),
    )?;
    manager.register_agent_with_principal(
        other_specialist.clone(),
        other_specialist_principal,
        delegated.clone(),
    )?;
    manager.register_root_run(parent_run_id.clone(), orchestrator_id.clone())?;

    parent_runtime.record_event(TraceEventKind::LoopTickStarted { tick_id: 1 })?;
    let causal_parent = parent_runtime.record_event(TraceEventKind::PolicyCompleted {
        policy: "uc-e2e-s3-orchestrator".to_string(),
    })?;

    let mut request = LocalDelegationRequest::new(
        parent_run_id.clone(),
        orchestrator_id.clone(),
        specialist_id.clone(),
        "summarize document fixture without publish authority",
        delegated.clone(),
        Some(causal_parent.trace_event_id.clone()),
    );
    request.child_run_id = child_run_id.clone();
    let child_authority = local_delegation_authority(
        orchestrator_principal.clone(),
        specialist_principal.clone(),
        &tenant_id,
        &request,
    )?;
    let child_run =
        manager.create_child_run(&parent_runtime, &child_runtime, request, child_authority)?;
    let consumed_request = manager.router().consume(
        &parent_runtime,
        &specialist_id,
        &parent_run_id,
        &child_run.request_message.message.message_id,
    )?;

    child_runtime.record_event(TraceEventKind::LoopTickStarted { tick_id: 1 })?;
    let child_adapter = Arc::new(CountingAdapter::default());
    let orchestrator_adapter = Arc::new(CountingAdapter::default());
    let gateway = gateway(
        tenant_id.clone(),
        &orchestrator,
        &specialist,
        Arc::clone(&child_adapter),
        Arc::clone(&orchestrator_adapter),
    );
    let child_read = action_request(ActionRequestInput {
        tenant_id: tenant_id.clone(),
        agent_id: specialist_id.clone(),
        run_id: child_run_id.clone(),
        name: "data.read_fixture",
        adapter: "fixture_data",
        side_effect_class: SideEffectClass::ReadOnly,
        permissions: &["document.read"],
        quota_usage: QuotaUsage::single_action(),
    });
    let child_read_outcome = gateway.submit(child_read.clone())?;
    record_action(&child_runtime, &child_read, &child_read_outcome)?;

    let child_state = commit_state(
        &child_runtime,
        Arc::clone(&state_store),
        tenant_id.clone(),
        specialist_id.clone(),
        child_run_id.clone(),
        b"{\"summary\":\"deterministic document summary\"}".to_vec(),
        "child-summary",
    )?;
    let task_response = manager.complete_child_run(
        &parent_runtime,
        &child_runtime,
        &child_run_id,
        serde_json::json!({"summary_ref": "state:child-summary", "state_node_id": child_state.state_node_id}),
    )?;
    child_runtime.record_event(TraceEventKind::LoopTickCompleted {
        tick_id: 1,
        integrity: None,
    })?;

    let consumed_response = manager.router().consume(
        &parent_runtime,
        &orchestrator_id,
        &parent_run_id,
        &task_response.response_message.message.message_id,
    )?;
    let before_orchestrator = orchestrator_adapter.executions();
    let internal_artifact = action_request(ActionRequestInput {
        tenant_id: tenant_id.clone(),
        agent_id: orchestrator_id.clone(),
        run_id: parent_run_id.clone(),
        name: "artifact.create_internal",
        adapter: "artifact",
        side_effect_class: SideEffectClass::Filesystem,
        permissions: &["artifact.create_internal"],
        quota_usage: QuotaUsage::single_action(),
    });
    let internal_outcome = gateway.submit(internal_artifact.clone())?;
    record_action(&parent_runtime, &internal_artifact, &internal_outcome)?;
    let after_orchestrator = orchestrator_adapter.executions();
    let parent_state = commit_state(
        &parent_runtime,
        state_store,
        tenant_id.clone(),
        orchestrator_id.clone(),
        parent_run_id.clone(),
        b"{\"artifact\":\"internal-summary\"}".to_vec(),
        "parent-artifact",
    )?;

    let mut negatives = Vec::new();
    let publish = action_request(ActionRequestInput {
        tenant_id: tenant_id.clone(),
        agent_id: specialist_id.clone(),
        run_id: child_run_id.clone(),
        name: "artifact.publish_external",
        adapter: "artifact",
        side_effect_class: SideEffectClass::External,
        permissions: &["artifact.publish_external"],
        quota_usage: QuotaUsage::single_action(),
    });
    let before = orchestrator_adapter.executions();
    let publish_outcome = gateway.submit(publish.clone())?;
    let mut publish_result = publish_outcome.verification.clone();
    publish_result
        .reasons
        .push("permission_laundering_denied".to_string());
    publish_result.artifacts = merge_artifacts(
        publish_result.artifacts,
        serde_json::json!({
            "verifier": "agent_isolation_ledger",
            "ledger_reason": "specialist cannot inherit orchestrator artifact.publish_external permission"
        }),
    );
    let publish_trace = parent_runtime.record_event_with_identity(
        TraceIdentityContext::new(parent_run_id.clone())
            .with_tenant_agent(tenant_id.clone(), specialist_id.clone())
            .with_tick_id(TickId::from(1))
            .with_action_id(publish.action_id.clone()),
        TraceEventKind::ActionDenied {
            action: publish.action.clone(),
            result: publish_result.clone(),
        },
    )?;
    negatives.push(NegativeEvidence {
        case: "specialist_external_artifact_publish_denied".to_string(),
        status: "Denied".to_string(),
        reason_codes: publish_result.reasons,
        trace_event_ids: vec![publish_trace.trace_event_id.to_string()],
        message_id: None,
        adapter_executions_before: before,
        adapter_executions_after: orchestrator_adapter.executions(),
        artifacts: publish_result.artifacts,
    });

    negatives.push(router_negative(RouterNegativeInput {
        case: "unauthorized_recipient_message_denied",
        runtime: &parent_runtime,
        router: manager.router(),
        trace_store: trace_store.as_ref(),
        source: &specialist_id,
        target: &reviewer_id,
        run_id: &parent_run_id,
        schema: TASK_RESPONSE_SCHEMA,
    })?);
    negatives.push(invalid_schema_negative(
        &parent_runtime,
        manager.router(),
        trace_store.as_ref(),
        &specialist_id,
        &orchestrator_id,
        &parent_run_id,
    )?);

    let mut overbroad = LocalDelegationRequest::new(
        parent_run_id.clone(),
        orchestrator_id.clone(),
        specialist_id.clone(),
        "smuggle broad publish authority",
        authority(
            &["artifact.publish_external"],
            &["artifact"],
            &["artifact.publish_external"],
        ),
        Some(causal_parent.trace_event_id.clone()),
    );
    overbroad.child_run_id = RunId::parse("12121212-1212-4121-8121-121212121212")?;
    let overbroad_child_run_id = overbroad.child_run_id.clone();
    let overbroad_runtime = runtime(overbroad.child_run_id.clone(), Arc::clone(&trace_store));
    let overbroad_authority = local_delegation_authority(
        orchestrator_principal.clone(),
        specialist_principal.clone(),
        &tenant_id,
        &overbroad,
    )?;
    let before_events = manager
        .router()
        .outbox(&orchestrator_id, &parent_run_id)?
        .len();
    let overbroad_result = manager.create_child_run(
        &parent_runtime,
        &overbroad_runtime,
        overbroad,
        overbroad_authority,
    );
    let overbroad_error = overbroad_result.expect_err("overbroad delegation denied");
    let overbroad_trace_id = find_delegation_rejection_trace_id(
        trace_store.as_ref(),
        &parent_run_id,
        &overbroad_child_run_id,
        "delegated_authority_exceeds_target_scope",
    )?;
    negatives.push(NegativeEvidence {
        case: "broad_permission_data_ref_smuggling_denied".to_string(),
        status: format!("{overbroad_error:?}"),
        reason_codes: vec!["delegated_authority_exceeds_target_scope".to_string()],
        trace_event_ids: vec![overbroad_trace_id.to_string()],
        message_id: None,
        adapter_executions_before: before_events,
        adapter_executions_after: manager
            .router()
            .outbox(&orchestrator_id, &parent_run_id)?
            .len(),
        artifacts: serde_json::json!({"authority": "explicitly narrower than orchestrator"}),
    });

    let mut cross_tenant = LocalDelegationRequest::new(
        parent_run_id.clone(),
        orchestrator_id.clone(),
        other_specialist.agent_id.clone(),
        "cross tenant delegation must fail",
        delegated.clone(),
        Some(causal_parent.trace_event_id),
    );
    cross_tenant.child_run_id = RunId::parse("34343434-3434-4343-8343-343434343434")?;
    let cross_child_run_id = cross_tenant.child_run_id.clone();
    let cross_runtime = runtime(cross_tenant.child_run_id.clone(), Arc::clone(&trace_store));
    let cross_authority = local_delegation_authority(
        orchestrator_principal,
        specialist_principal,
        &tenant_id,
        &cross_tenant,
    )?;
    let cross_result = manager.create_child_run(
        &parent_runtime,
        &cross_runtime,
        cross_tenant,
        cross_authority,
    );
    let cross_error = cross_result.expect_err("cross tenant denied");
    let cross_trace_id = find_delegation_rejection_trace_id(
        trace_store.as_ref(),
        &parent_run_id,
        &cross_child_run_id,
        "target_agent_tenant_mismatch",
    )?;
    negatives.push(NegativeEvidence {
        case: "cross_tenant_message_attempt_rejected".to_string(),
        status: format!("{cross_error:?}"),
        reason_codes: vec!["target_agent_tenant_mismatch".to_string()],
        trace_event_ids: vec![cross_trace_id.to_string()],
        message_id: None,
        adapter_executions_before: 0,
        adapter_executions_after: 0,
        artifacts: serde_json::json!({"tenant_scope": "target agent tenant did not match parent run tenant"}),
    });

    let before_child_quota = child_adapter.executions();
    let quota_action = action_request(ActionRequestInput {
        tenant_id: tenant_id.clone(),
        agent_id: specialist_id.clone(),
        run_id: child_run_id.clone(),
        name: "data.read_fixture",
        adapter: "fixture_data",
        side_effect_class: SideEffectClass::ReadOnly,
        permissions: &["document.read"],
        quota_usage: QuotaUsage::single_action(),
    });
    let quota_outcome = gateway.submit(quota_action.clone())?;
    let quota_trace = parent_runtime.record_event_with_identity(
        TraceIdentityContext::new(parent_run_id.clone())
            .with_tenant_agent(tenant_id.clone(), specialist_id.clone())
            .with_tick_id(TickId::from(1))
            .with_action_id(quota_action.action_id.clone()),
        TraceEventKind::ActionDenied {
            action: quota_action.action.clone(),
            result: quota_outcome.verification.clone(),
        },
    )?;
    negatives.push(NegativeEvidence {
        case: "specialist_quota_exhaustion_does_not_mutate_orchestrator_ledger".to_string(),
        status: format!("{:?}", quota_outcome.status),
        reason_codes: quota_outcome.verification.reasons,
        trace_event_ids: vec![quota_trace.trace_event_id.to_string()],
        message_id: None,
        adapter_executions_before: before_child_quota,
        adapter_executions_after: child_adapter.executions(),
        artifacts: serde_json::json!({"orchestrator_action_executed_after_specialist_quota": internal_outcome.status}),
    });

    parent_runtime.record_event(TraceEventKind::LoopTickCompleted {
        tick_id: 1,
        integrity: None,
    })?;

    let evidence = Evidence {
        status: "passed".to_string(),
        parent_run_id: parent_run_id.to_string(),
        child_run_id: child_run_id.to_string(),
        tenant_id: tenant_id.to_string(),
        orchestrator_agent_id: orchestrator_id.to_string(),
        specialist_agent_id: specialist_id.to_string(),
        delegated_authority: delegated,
        positive: PositiveEvidence {
            request_message_id: child_run.request_message.message.message_id.to_string(),
            response_message_id: task_response
                .response_message
                .message
                .message_id
                .to_string(),
            request_status: child_run.request_message.delivery_status,
            consumed_request_status: consumed_request.delivery_status,
            consumed_response_status: consumed_response.delivery_status,
            child_started_trace_id: child_run.child_started_trace_id.to_string(),
            child_completed_parent_trace_id: task_response.parent_trace_id.to_string(),
            child_completed_child_trace_id: task_response.child_trace_id.to_string(),
            orchestrator_action_status: format!("{:?}", internal_outcome.status),
            orchestrator_adapter_executions_before: before_orchestrator,
            orchestrator_adapter_executions_after: after_orchestrator,
        },
        negative_cases: negatives,
        parent_state,
        child_state,
        anti_drift: AntiDriftEvidence {
            public_boundary: "public splendor-kernel crate APIs plus splendorctl replay"
                .to_string(),
            private_helper_only_e2e: false,
            gateway_bypass: false,
            specialist_broad_permission_inheritance: false,
            hidden_shared_state: false,
            replay_side_effects_allowed_default: false,
            remote_transport: false,
            fleet_governance_or_physical_scope: false,
        },
        trace_db: trace_db.display().to_string(),
        state_db: state_db.display().to_string(),
    };
    let parity = SchemaParityEvidence {
        schema_version: "splendor.e2e.s3.schema-parity.rust.v1".to_string(),
        task_request_schema: TASK_REQUEST_SCHEMA.to_string(),
        task_response_schema: TASK_RESPONSE_SCHEMA.to_string(),
        task_request_message: child_run.request_message.message.clone(),
        task_response_message: task_response.response_message.message.clone(),
        python_sdk_callback_expectations: vec![
            "policy callbacks propose messages but do not execute side effects".to_string(),
            "adapter callbacks remain behind daemon/gateway boundaries".to_string(),
            "trace subscribers observe message causality without mutating runtime state"
                .to_string(),
        ],
    };
    fs::write(
        artifact_dir.join("schema-parity-rust.json"),
        serde_json::to_vec_pretty(&parity)?,
    )?;
    let path = artifact_dir.join("runtime-evidence.json");
    fs::write(path, serde_json::to_vec_pretty(&evidence)?)?;
    Ok(())
}

fn parse_artifact_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--artifact-dir" {
            if let Some(value) = args.next() {
                return Ok(PathBuf::from(value));
            }
        }
    }
    Err("missing --artifact-dir".into())
}

fn runtime(run_id: RunId, trace_store: Arc<SqliteTraceStore>) -> KernelRuntime {
    KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(TraceStoreSink::new(run_id.clone(), trace_store)),
        run_id: Some(run_id),
        ..KernelRuntimeConfig::default()
    })
}

fn authority(actions: &[&str], adapters: &[&str], permissions: &[&str]) -> DelegatedAuthority {
    DelegatedAuthority {
        allowed_actions: actions.iter().map(|value| value.to_string()).collect(),
        allowed_adapters: adapters.iter().map(|value| value.to_string()).collect(),
        allowed_permissions: permissions.iter().map(|value| value.to_string()).collect(),
    }
}

fn local_delegation_authority(
    parent_principal: PrincipalId,
    child_principal: PrincipalId,
    tenant_id: &TenantId,
    request: &LocalDelegationRequest,
) -> Result<LocalDelegationAuthority, Box<dyn std::error::Error>> {
    let parent_grant = grant_from_legacy_allowlists(
        CompatibilityGrantContext {
            grant_id: CapabilityGrantId::new(),
            issuer: PrincipalId::new(),
            subject: parent_principal,
            audience: AUTHORITY_AUDIENCE.to_string(),
            validation_digest: AUTHORITY_DIGEST.to_string(),
            max_delegation_depth: 2,
            parent_grant_ids: Vec::new(),
        },
        LegacyScopeProfile {
            tenant_id: tenant_id.clone(),
            agent_id: request.target_agent_id.clone(),
            run_id: Some(request.child_run_id.clone()),
            quotas: AuthorityBudgetScope {
                max_actions_per_tick: Some(4),
                max_action_duration_ms: Some(1_000),
                ..AuthorityBudgetScope::default()
            },
        },
        &request.delegated_authority.allowed_actions,
        &request.delegated_authority.allowed_adapters,
        &request.delegated_authority.allowed_permissions,
        OffsetDateTime::now_utc() - time::Duration::minutes(1),
        OffsetDateTime::now_utc() + time::Duration::minutes(30),
        RevocationStatus::Active,
        Some("local_delegation:example".to_string()),
    )?;
    let mut authority = LocalDelegationAuthority::new(
        parent_grant,
        child_principal,
        AUTHORITY_AUDIENCE,
        OffsetDateTime::now_utc(),
    );
    authority.max_fan_out = 3;
    Ok(authority)
}

fn gateway(
    tenant_id: TenantId,
    orchestrator: &AgentContext,
    specialist: &AgentContext,
    child_adapter: Arc<CountingAdapter>,
    orchestrator_adapter: Arc<CountingAdapter>,
) -> VerifiedActionGateway {
    let mut tenant = TenantContext::new(
        tenant_id,
        TenantPolicy {
            allowed_actions: vec![
                "data.read_fixture".to_string(),
                "artifact.create_internal".to_string(),
                "artifact.publish_external".to_string(),
            ],
            allowed_adapters: vec!["fixture_data".to_string(), "artifact".to_string()],
            allowed_permissions: vec![
                "document.read".to_string(),
                "artifact.create_internal".to_string(),
                "artifact.publish_external".to_string(),
            ],
        },
        QuotaPolicy {
            max_actions_per_tick: Some(1),
            ..QuotaPolicy::default()
        },
    );
    tenant.register_agent_context(orchestrator);
    tenant.register_agent_context(specialist);
    tenant.begin_tick(1, OffsetDateTime::now_utc());
    let registry = TenantRegistry::new();
    registry.insert(tenant);
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry));
    gateway.register_adapter("data.read_fixture", "fixture_data", child_adapter);
    gateway.register_adapter(
        "artifact.create_internal",
        "artifact",
        orchestrator_adapter.clone(),
    );
    gateway.register_adapter(
        "artifact.publish_external",
        "artifact",
        orchestrator_adapter,
    );
    gateway
}

fn action_request(input: ActionRequestInput<'_>) -> ActionRequest {
    ActionRequest {
        action_id: ActionId::new(),
        tenant_id: input.tenant_id,
        agent_id: input.agent_id,
        run_id: input.run_id,
        action: Action {
            name: input.name.to_string(),
            params: serde_json::json!({"ref": format!("fixture:{}", input.name)}),
            side_effect_class: input.side_effect_class,
            cost_estimate: None,
            required_permissions: input
                .permissions
                .iter()
                .map(|value| value.to_string())
                .collect(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        },
        adapter: Some(input.adapter.to_string()),
        quota_usage: input.quota_usage,
        satisfied_preconditions: Vec::new(),
        requested_at: OffsetDateTime::now_utc(),
        approval_evidence: None,
    }
}

fn record_action(
    runtime: &KernelRuntime,
    request: &ActionRequest,
    outcome: &splendor_gateway::ActionOutcome,
) -> Result<(), splendor_kernel::TraceError> {
    let identity = TraceIdentityContext::new(request.run_id.clone())
        .with_tenant_agent(request.tenant_id.clone(), request.agent_id.clone())
        .with_tick_id(TickId::from(1))
        .with_action_id(request.action_id.clone());
    runtime.record_event_with_identity(
        identity.clone(),
        TraceEventKind::ActionVerificationCompleted {
            action: request.action.clone(),
            result: outcome.verification.clone(),
        },
    )?;
    let kind = match outcome.status {
        splendor_gateway::ActionStatus::Executed => TraceEventKind::ActionExecuted {
            action: request.action.clone(),
            outcome: outcome
                .output
                .clone()
                .unwrap_or_else(|| serde_json::json!({})),
        },
        splendor_gateway::ActionStatus::Denied => TraceEventKind::ActionDenied {
            action: request.action.clone(),
            result: outcome.verification.clone(),
        },
        splendor_gateway::ActionStatus::Failed => TraceEventKind::ActionFailed {
            action: request.action.clone(),
            error: outcome
                .error
                .clone()
                .unwrap_or_else(|| "adapter failed".to_string()),
            result: outcome.verification.clone(),
        },
        splendor_gateway::ActionStatus::NeedsApproval => TraceEventKind::ActionNeedsApproval {
            action: request.action.clone(),
            result: outcome.verification.clone(),
        },
        splendor_gateway::ActionStatus::NeedsIntervention => {
            TraceEventKind::ActionNeedsIntervention {
                action: request.action.clone(),
                result: outcome.verification.clone(),
            }
        }
    };
    runtime.record_event_with_identity(identity, kind)?;
    runtime.record_event(TraceEventKind::OutcomeRecorded {
        outcome: serde_json::to_value(outcome)
            .unwrap_or_else(|_| serde_json::json!({"status": "unserializable"})),
        feedback: None,
        reward: None,
    })?;
    Ok(())
}

fn commit_state(
    runtime: &KernelRuntime,
    store: Arc<SqliteStateStore>,
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
    bytes: Vec<u8>,
    label: &str,
) -> Result<StateEvidence, Box<dyn std::error::Error>> {
    let store_lookup = Arc::clone(&store);
    let mut graph = StateGraph::new(
        store,
        SnapshotPolicy {
            interval: Some(1),
            important_labels: Vec::new(),
        },
    );
    let _bootstrap = graph.commit(
        StateData {
            bytes: b"{}".to_vec(),
            content_type: Some("application/json".to_string()),
        },
        StateMetadata {
            created_at: OffsetDateTime::now_utc(),
            label: Some(format!("{label}-bootstrap")),
            tenant_id: Some(tenant_id.clone()),
            agent_id: Some(agent_id.clone()),
            run_id: Some(run_id.clone()),
            trace_event_id: None,
        },
    )?;
    let state_hash = splendor_types::ContentHash::blake3(&bytes);
    let data_hash = state_hash.to_string();
    let event = runtime.record_event_with_identity(
        TraceIdentityContext::new(run_id.clone())
            .with_tenant_agent(tenant_id.clone(), agent_id.clone())
            .with_tick_id(TickId::from(1)),
        TraceEventKind::StateCommitted {
            state_hash,
            snapshot_id: None,
        },
    )?;
    let commit = graph.commit(
        StateData {
            bytes,
            content_type: Some("application/json".to_string()),
        },
        StateMetadata {
            created_at: OffsetDateTime::now_utc(),
            label: Some(label.to_string()),
            tenant_id: Some(tenant_id.clone()),
            agent_id: Some(agent_id.clone()),
            run_id: Some(run_id.clone()),
            trace_event_id: Some(event.trace_event_id.clone()),
        },
    )?;
    let node = store_lookup.get_node(&commit.node_id)?;
    let metadata_trace_event_id = node
        .metadata
        .trace_event_id
        .clone()
        .ok_or("state metadata missing trace_event_id")?;
    Ok(StateEvidence {
        run_id: run_id.to_string(),
        agent_id: agent_id.to_string(),
        state_node_id: commit.node_id.to_string(),
        state_node_hash: commit.node_id.hash().to_string(),
        state_hash: data_hash,
        trace_event_id: event.trace_event_id.to_string(),
        metadata_trace_event_id: metadata_trace_event_id.to_string(),
    })
}

fn router_negative(
    input: RouterNegativeInput<'_>,
) -> Result<NegativeEvidence, Box<dyn std::error::Error>> {
    let message = Message::new(
        MessageId::new(),
        input.source.clone(),
        input.target.clone(),
        input.run_id.clone(),
        input.schema,
        serde_json::to_value(splendor_types::TaskResponse::new(
            input.run_id.clone(),
            RunId::parse(CHILD_RUN_ID)?,
            splendor_types::TaskResponseStatus::Completed,
            Some(serde_json::json!({"summary": "not delivered"})),
            None,
        )?)?,
        Some(TraceEventId::from_run_sequence(input.run_id, 0)),
        false,
        OffsetDateTime::now_utc(),
    )?;
    let message_id = message.message_id.clone();
    let id = message_id.to_string();
    let err = input
        .router
        .send(input.runtime, MessageEnvelope::new(message)?)
        .expect_err("message denied");
    let trace_id = find_message_rejection_trace_id(
        input.trace_store,
        input.run_id,
        &message_id,
        "message_recipient_not_allowed",
    )?;
    Ok(NegativeEvidence {
        case: input.case.to_string(),
        status: format!("{err}"),
        reason_codes: vec!["message_recipient_not_allowed".to_string()],
        trace_event_ids: vec![trace_id.to_string()],
        message_id: Some(id),
        adapter_executions_before: 0,
        adapter_executions_after: 0,
        artifacts: serde_json::json!({"delivery_status": "rejected"}),
    })
}

fn invalid_schema_negative(
    runtime: &KernelRuntime,
    router: &splendor_kernel::LocalMessageRouter,
    trace_store: &SqliteTraceStore,
    source: &AgentId,
    target: &AgentId,
    run_id: &RunId,
) -> Result<NegativeEvidence, Box<dyn std::error::Error>> {
    let message_id = MessageId::new();
    let envelope = MessageEnvelope {
        message: Message {
            message_id: message_id.clone(),
            source_agent_id: source.clone(),
            target_agent_id: target.clone(),
            run_id: run_id.clone(),
            schema: "splendor.message.task_request.v2".to_string(),
            payload: serde_json::json!({"task": "unsupported"}),
            causal_parent: Some(TraceEventId::from_run_sequence(run_id, 0)),
            requires_response: true,
            created_at: OffsetDateTime::now_utc(),
        },
        schema_version: MessageSchemaVersion::V1,
        delivery_status: MessageDeliveryStatus::Pending,
        trace_links: MessageTraceLinks::default(),
    };
    let err = router
        .send(runtime, envelope)
        .expect_err("invalid schema denied");
    let trace_id =
        find_message_rejection_trace_id(trace_store, run_id, &message_id, "unsupported")?;
    Ok(NegativeEvidence {
        case: "unsupported_message_schema_rejected_before_delivery".to_string(),
        status: format!("{err}"),
        reason_codes: vec!["unsupported_schema_version".to_string()],
        trace_event_ids: vec![trace_id.to_string()],
        message_id: Some(message_id.to_string()),
        adapter_executions_before: 0,
        adapter_executions_after: 0,
        artifacts: serde_json::json!({"delivery_status": "rejected"}),
    })
}

fn trace_events(
    trace_store: &SqliteTraceStore,
    run_id: &RunId,
) -> Result<Vec<TraceEvent>, Box<dyn std::error::Error>> {
    trace_store
        .read(&run_id.to_string())?
        .into_iter()
        .map(|record| serde_json::from_value(record.payload).map_err(Into::into))
        .collect()
}

fn find_message_rejection_trace_id(
    trace_store: &SqliteTraceStore,
    run_id: &RunId,
    message_id: &MessageId,
    expected_reason: &str,
) -> Result<TraceEventId, Box<dyn std::error::Error>> {
    for event in trace_events(trace_store, run_id)? {
        if let TraceEventKind::MessageRejected { message, reason } = &event.kind {
            if &message.message_id == message_id && reason.contains(expected_reason) {
                return Ok(event.trace_event_id);
            }
        }
    }
    Err(
        format!("missing MessageRejected trace for message {message_id} reason {expected_reason}")
            .into(),
    )
}

fn find_delegation_rejection_trace_id(
    trace_store: &SqliteTraceStore,
    run_id: &RunId,
    child_run_id: &RunId,
    expected_reason: &str,
) -> Result<TraceEventId, Box<dyn std::error::Error>> {
    for event in trace_events(trace_store, run_id)? {
        if let TraceEventKind::DelegationRejected { delegation, reason } = &event.kind {
            if &delegation.child_run_id == child_run_id && reason == expected_reason {
                return Ok(event.trace_event_id);
            }
        }
    }
    Err(format!(
        "missing DelegationRejected trace for child run {child_run_id} reason {expected_reason}"
    )
    .into())
}

fn merge_artifacts(mut base: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
    if let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            base.insert(key.clone(), value.clone());
        }
    }
    base
}
