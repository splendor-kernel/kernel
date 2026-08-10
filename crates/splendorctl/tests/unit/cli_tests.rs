use super::*;
use splendor_store::{
    compute_trace_event_hash, SqliteStateStore, StateData, StateMetadata, StateStore,
};
use splendor_types::{
    Action, ActionId, AgentId, ApprovalDecision, ApprovalId, ApprovalTraceContext,
    CircuitBreakerId, CircuitBreakerState, ContentHash, EscalationContext, EscalationDecision,
    EscalationId, EscalationScope, EscalationTrigger, Feedback, GovernanceIssuer,
    GovernanceObjectRef, GovernanceScope, GovernanceState, GovernanceTraceLink,
    GovernanceTransition, GovernanceTransitionRejection, InterventionId, KillSwitchId,
    LocalDelegationTraceContext, MessageId, MessageTraceContext, Percept, PerceptProvenance,
    Reward, RunId, SideEffectClass, SnapshotId, StateHandoffTraceContext, StateReferenceMode,
    TenantId, TickId, TraceEvent, TraceEventId, TraceEventKind, TraceId, TraceIdentityContext,
    VerificationResult,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::NamedTempFile;
use time::OffsetDateTime;
use uuid::Uuid;

fn write_temp_json(value: serde_json::Value) -> NamedTempFile {
    let file = NamedTempFile::new().expect("temp json");
    std::fs::write(file.path(), serde_json::to_string(&value).expect("json")).expect("write json");
    file
}

fn write_temp_text(value: &str) -> NamedTempFile {
    let file = NamedTempFile::new().expect("temp text");
    std::fs::write(file.path(), value).expect("write text");
    file
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn acceptance_fixture_files() -> (NamedTempFile, NamedTempFile, NamedTempFile, NamedTempFile) {
    let state_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let trace = write_temp_text(
        r#"{"event_type":"tick.started","sequence":1,"payload":{"side_effects_executed":false}}
{"event_type":"state.committed","sequence":2,"state_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
"#,
    );
    let state = write_temp_json(serde_json::json!({
        "state_node_id": "state_acceptance_1",
        "state_hash": state_hash,
    }));
    let scenario = write_temp_json(serde_json::json!({
        "state_hashes": [state_hash],
        "negative_cases": [{
            "case": "deny_url",
            "reason_codes": ["tenant_action_denied"],
            "trace_event_ids": ["trace_evt_acceptance_1"]
        }],
    }));
    let audit = write_temp_json(serde_json::json!({
        "schema_version": "splendor.audit_package.v1",
        "negative_cases": [{
            "case": "deny_url",
            "reason_codes": ["tenant_action_denied"],
            "trace_event_ids": ["trace_evt_acceptance_1"]
        }],
    }));
    (trace, state, scenario, audit)
}

fn valid_trace_records_for(run_id: &RunId) -> Vec<splendor_store::TraceRecord> {
    let store = splendor_store::InMemoryTraceStore::default();
    let timestamp = OffsetDateTime::now_utc();
    let events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        ),
    ];
    for event in events {
        TraceStore::append(
            &store,
            &run_id.to_string(),
            serde_json::to_value(event).unwrap(),
        )
        .expect("append");
    }
    TraceStore::read(&store, &run_id.to_string()).expect("records")
}

fn append_valid_trace_records(store: &impl TraceStore, run_id: &RunId) {
    for record in valid_trace_records_for(run_id) {
        TraceStore::append(store, &run_id.to_string(), record.payload).expect("append trace event");
    }
}

fn rehash_trace_records(records: &mut [splendor_store::TraceRecord]) {
    let mut previous = None;
    for record in records {
        record.prev_event_hash = previous.clone();
        record.event_hash = compute_trace_event_hash(previous.as_ref(), &record.payload)
            .expect("recompute trace hash");
        previous = Some(record.event_hash.clone());
    }
}

fn signed_work_order_block(
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
    actions: Vec<String>,
) -> String {
    let now = OffsetDateTime::now_utc();
    signed_work_order_block_with_authority(
        tenant_id,
        agent_id,
        run_id,
        actions,
        vec!["filesystem".to_string()],
        vec!["fs.write".to_string()],
        now + time::Duration::hours(1),
        splendor_types::RevocationStatus::Active,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_work_order_block_with_authority(
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
    actions: Vec<String>,
    adapters: Vec<String>,
    permissions: Vec<String>,
    expires_at: OffsetDateTime,
    revocation: splendor_types::RevocationStatus,
) -> String {
    let now = OffsetDateTime::now_utc();
    let order = WorkOrder {
        schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: splendor_types::WorkOrderId::try_new("wo_cli").expect("work order id"),
        tenant_id,
        agent_id,
        run_id: Some(run_id),
        objective: "exercise signed work order ingestion".to_string(),
        allowed_actions: actions,
        allowed_adapters: adapters,
        allowed_permissions: permissions,
        data_refs: vec!["dataset:cli".to_string()],
        quotas: splendor_types::WorkOrderQuotaPolicy {
            max_actions_per_tick: Some(1),
            max_filesystem_write_bytes: Some(64),
            ..splendor_types::WorkOrderQuotaPolicy::default()
        },
        placement: splendor_types::WorkOrderPlacement {
            target: "local_resident".to_string(),
            data_locality: Some("local".to_string()),
            requires_gpu: Some(false),
            dedicated_instance: Some(false),
            required_capabilities: vec!["filesystem".to_string()],
            max_runtime_ms: Some(30_000),
            ..splendor_types::WorkOrderPlacement::default()
        },
        issued_at: now - time::Duration::minutes(1),
        expires_at,
        revocation,
    };
    let envelope = WorkOrderEnvelope::signed_with_shared_secret(
        order,
        "local-test",
        b"local-work-order-secret",
    )
    .expect("signed work order");
    let mut block = String::from("work_order:\n");
    for line in serde_yaml::to_string(&envelope)
        .expect("work order yaml")
        .lines()
    {
        block.push_str("  ");
        block.push_str(line);
        block.push('\n');
    }
    block.push_str("  verification_secret: local-work-order-secret\n");
    block.push_str("  expected_placement_target: local_resident\n");
    block
}

#[derive(Default)]
struct CountingActionAdapter {
    calls: Mutex<BTreeMap<String, u64>>,
}

impl CountingActionAdapter {
    fn calls_for(&self, action_name: &str) -> u64 {
        self.calls
            .lock()
            .expect("adapter calls")
            .get(action_name)
            .copied()
            .unwrap_or(0)
    }

    fn total_calls(&self) -> u64 {
        self.calls.lock().expect("adapter calls").values().sum()
    }
}

impl ActionAdapter for CountingActionAdapter {
    fn execute(
        &self,
        action: &splendor_gateway::ActionRequest,
    ) -> Result<splendor_gateway::AdapterResult, splendor_gateway::AdapterError> {
        let mut calls = self.calls.lock().expect("adapter calls");
        *calls.entry(action.action.name.clone()).or_default() += 1;
        Ok(splendor_gateway::AdapterResult {
            output: serde_json::json!({"counted": action.action.name}),
            satisfied_postconditions: action.action.postconditions.clone(),
        })
    }
}

struct SuppressedOutputAdapter {
    calls: Arc<AtomicUsize>,
}

impl ActionAdapter for SuppressedOutputAdapter {
    fn execute(
        &self,
        _action: &splendor_gateway::ActionRequest,
    ) -> Result<splendor_gateway::AdapterResult, splendor_gateway::AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(splendor_gateway::AdapterResult {
            output: serde_json::json!({
                "body": ([vec![0xff], b"Basic dTpw".to_vec(), vec![0xfe]].concat())
            }),
            satisfied_postconditions: Vec::new(),
        })
    }
}

fn counting_run_overrides(
    adapter_ids: &[&str],
    authority_transition: Option<RunAuthorityTestTransition>,
) -> (Arc<CountingActionAdapter>, RunTestOverrides) {
    let counter = Arc::new(CountingActionAdapter::default());
    let mut adapters = std::collections::HashMap::new();
    for adapter_id in adapter_ids {
        let adapter: Arc<dyn ActionAdapter> = counter.clone();
        adapters.insert((*adapter_id).to_string(), adapter);
    }
    (
        counter,
        RunTestOverrides {
            adapters,
            authority_transition,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn write_counted_run_config(
    dir: &tempfile::TempDir,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    run_id: &RunId,
    work_order: &str,
    action_name: &str,
    adapter: &str,
    action_permissions: &[&str],
    tenant_permissions: &[&str],
    trace_fail_on_event: Option<&str>,
) -> PathBuf {
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let action_permissions = serde_json::to_string(action_permissions).expect("permissions");
    let tenant_permissions = serde_json::to_string(tenant_permissions).expect("permissions");
    let failure_injection = trace_fail_on_event
        .map(|event| format!("failure_injection:\n  trace_fail_on_event: {event}\n"))
        .unwrap_or_default();
    let side_effect_class = if adapter == "http" {
        "network"
    } else {
        "filesystem"
    };
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\n{}tenants:\n  - id: {}\n    allowed_actions: [\"{}\"]\n    allowed_adapters: [\"filesystem\", \"http\"]\n    allowed_permissions: {}\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    allowed_permissions: {}\n    policy:\n      type: static\n      actions:\n        - name: {}\n          adapter: {}\n          side_effect_class: {}\n          required_permissions: {}\n          params:\n            path: \"counted.txt\"\n            contents: \"counted\"\n            url: \"https://example.com/resource\"\n            method: \"GET\"\n          usage:\n            actions: 1\n            filesystem_write_bytes: 7\n            http_requests: 1\nadapters:\n  filesystem:\n    base_dir: {}\n  http:\n    allowed_domains: [\"example.com\"]\n    allowed_methods: [\"GET\"]\n{}",
        trace_path.display(),
        state_path.display(),
        run_id,
        failure_injection,
        tenant_id,
        action_name,
        tenant_permissions,
        agent_id,
        tenant_id,
        run_id,
        tenant_permissions,
        action_name,
        adapter,
        side_effect_class,
        action_permissions,
        dir.path().display(),
        work_order,
    );
    std::fs::write(&config_path, config).expect("write config");
    config_path
}

fn corrupt_work_order_signature(block: String) -> String {
    block.replace("signature: ", "signature: bad-")
}

fn fixed_run_id(value: u128) -> RunId {
    Uuid::from_u128(value).into()
}

fn fixed_agent_id(value: u128) -> AgentId {
    Uuid::from_u128(value).into()
}

fn fixed_message_id(value: u128) -> MessageId {
    Uuid::from_u128(value).into()
}

fn fixed_action_id(value: u128) -> ActionId {
    Uuid::from_u128(value).into()
}

#[test]
fn daemon_request_refuses_anonymous_mutating_fallback() {
    let err = parse_args(vec![
        "daemon".to_string(),
        "request".to_string(),
        "--method".to_string(),
        "POST".to_string(),
        "--url".to_string(),
        "http://127.0.0.1:8077/runs".to_string(),
    ])
    .expect_err("token is required");
    assert!(err.contains("anonymous daemon fallback is not allowed"));
}

#[test]
fn daemon_request_parses_local_get_with_credential_header() {
    let command = parse_args(vec![
        "daemon".to_string(),
        "request".to_string(),
        "--method".to_string(),
        "GET".to_string(),
        "--url".to_string(),
        "http://127.0.0.1:8077/health".to_string(),
        "--token".to_string(),
        "token".to_string(),
        "--caller-credential".to_string(),
        "cred.json".to_string(),
    ])
    .expect("daemon command parses");
    match command {
        Command::DaemonRequest {
            method,
            url,
            credential_path,
            token,
            ..
        } => {
            assert_eq!(method, "GET");
            assert_eq!(url, "http://127.0.0.1:8077/health");
            assert_eq!(credential_path.unwrap(), PathBuf::from("cred.json"));
            assert_eq!(token, "token");
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn daemon_request_rejects_missing_or_null_mutating_authority_body() {
    for body in [
        r#"{"audit_attribution":{"credential_id":"cred"}}"#,
        r#"{"credential":{"credential_id":"cred"}}"#,
        r#"{"credential":null,"audit_attribution":{"credential_id":"cred"}}"#,
        r#"{"credential":{"credential_id":"cred"},"audit_attribution":null}"#,
    ] {
        let file = NamedTempFile::new().expect("body file");
        std::fs::write(file.path(), body).expect("write body");
        let err = daemon_request(
            "POST",
            "http://127.0.0.1:8077/runs/test/replay",
            Some(file.path()),
            None,
            "token",
        )
        .expect_err("null or missing authority rejected before send");
        assert!(err.contains("credential and audit_attribution"));
    }
}

fn spawn_local_daemon_response(
    status: u16,
    body: &'static str,
) -> (String, std::thread::JoinHandle<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind local daemon");
    let addr = listener.local_addr().expect("local addr");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept daemon request");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("read timeout");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 512];
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&request[..header_end]);
                let content_length = header
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }
        let response = format!(
            "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write daemon response");
        String::from_utf8(request).expect("request utf8")
    });
    (format!("http://{}:{}/runs", addr.ip(), addr.port()), handle)
}

#[test]
fn daemon_request_sends_authorized_local_request_with_sanitized_credential() {
    let body = NamedTempFile::new().expect("body");
    std::fs::write(
        body.path(),
        r#"{"credential":{"credential_id":"cred"},"audit_attribution":{"caller":"cli-test"}}"#,
    )
    .expect("write body");
    let credential = NamedTempFile::new().expect("credential");
    std::fs::write(credential.path(), "caller\ncredential\r\n").expect("write credential");
    let (url, handle) = spawn_local_daemon_response(200, r#"{"ok":true}"#);

    daemon_request(
        "POST",
        &url,
        Some(body.path()),
        Some(credential.path()),
        "token",
    )
    .expect("authorized local request succeeds");

    let request = handle.join().expect("daemon request captured");
    assert!(request.starts_with("POST /runs HTTP/1.1"));
    assert!(request.contains("Authorization: Bearer token"));
    assert!(request.contains("X-Splendor-Caller-Credential: callercredential"));
    assert!(request.contains("Content-Type: application/json"));
    assert!(request.contains("audit_attribution"));
}

#[test]
fn local_daemon_http_errors_and_malformed_responses_are_explicit() {
    let (url, handle) = spawn_local_daemon_response(403, r#"{"error":"denied"}"#);
    let parsed = parse_local_http_url(&url).expect("parse local url");
    let err = send_local_http(
        &parsed.host,
        parsed.port,
        "GET",
        &parsed.path,
        "token",
        None,
        None,
    )
    .expect_err("http errors are surfaced");
    assert!(err.contains("HTTP 403"));
    let _ = handle.join().expect("daemon request captured");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind malformed daemon");
    let addr = listener.local_addr().expect("local addr");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept malformed request");
        stream.write_all(b"not-http").expect("write malformed");
    });
    let err = send_local_http(
        &addr.ip().to_string(),
        addr.port(),
        "GET",
        "/health",
        "token",
        None,
        None,
    )
    .expect_err("malformed response rejected");
    assert!(
        err.contains("malformed HTTP response") || err.contains("Failed to read daemon response"),
        "unexpected malformed response error: {err}"
    );
    handle.join().expect("malformed daemon joined");
}

#[test]
fn daemon_url_refuses_non_local_hosts() {
    let err = parse_local_http_url("http://0.0.0.0:8077/health").expect_err("non-local refused");
    assert!(err.contains("refuses non-local"));
}

#[test]
fn parse_args_rejects_daemon_and_work_order_error_paths() {
    let daemon_missing = parse_args(vec!["daemon".to_string()]).expect_err("daemon usage");
    assert!(daemon_missing.contains("splendorctl"));

    let daemon_unknown = parse_args(vec!["daemon".to_string(), "unknown".to_string()])
        .expect_err("unknown daemon subcommand");
    assert!(daemon_unknown.contains("Unknown daemon subcommand"));

    let daemon_help = parse_args(vec![
        "daemon".to_string(),
        "request".to_string(),
        "--help".to_string(),
    ])
    .expect_err("daemon help");
    assert!(daemon_help.contains("splendorctl"));

    let blank_token = parse_args(vec![
        "daemon".to_string(),
        "request".to_string(),
        "--method".to_string(),
        "GET".to_string(),
        "--url".to_string(),
        "http://127.0.0.1:8077/health".to_string(),
        "--token".to_string(),
        " ".to_string(),
    ])
    .expect_err("blank token rejected");
    assert!(blank_token.contains("anonymous daemon fallback"));

    let mutating_without_body = parse_args(vec![
        "daemon".to_string(),
        "request".to_string(),
        "--method".to_string(),
        "POST".to_string(),
        "--url".to_string(),
        "http://127.0.0.1:8077/runs".to_string(),
        "--token".to_string(),
        "token".to_string(),
    ])
    .expect_err("mutating request requires body");
    assert!(mutating_without_body.contains("credential and audit attribution"));

    let work_order_missing =
        parse_args(vec!["work-order".to_string()]).expect_err("work order usage");
    assert!(work_order_missing.contains("splendorctl"));

    let work_order_unknown = parse_args(vec!["work-order".to_string(), "unknown".to_string()])
        .expect_err("unknown work-order subcommand");
    assert!(work_order_unknown.contains("Unknown work-order subcommand"));

    let work_order_help = parse_args(vec![
        "work-order".to_string(),
        "sign".to_string(),
        "--help".to_string(),
    ])
    .expect_err("work order help");
    assert!(work_order_help.contains("splendorctl"));
}

fn fixed_approval_id(value: u128) -> ApprovalId {
    Uuid::from_u128(value).into()
}

fn fixed_escalation_id(value: u128) -> EscalationId {
    Uuid::from_u128(value).into()
}

fn fixed_intervention_id(value: u128) -> InterventionId {
    Uuid::from_u128(value).into()
}

fn fixed_circuit_breaker_id(value: u128) -> CircuitBreakerId {
    Uuid::from_u128(value).into()
}

fn fixed_kill_switch_id(value: u128) -> KillSwitchId {
    Uuid::from_u128(value).into()
}

fn governance_transition(
    object: GovernanceObjectRef,
    scope: GovernanceScope,
    from: Option<GovernanceState>,
    to: GovernanceState,
    run_id: &RunId,
    sequence: u64,
) -> GovernanceTransition {
    GovernanceTransition::try_new(
        object,
        scope,
        from,
        to,
        OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(sequence as i64),
        format!("governance transition {sequence}"),
        GovernanceIssuer::new("operator:test", "unit-test").expect("issuer"),
        GovernanceTraceLink::new(
            TraceEventId::from_run_sequence(run_id, sequence),
            Some(run_id.clone()),
        ),
        Default::default(),
    )
    .expect("governance transition")
}

fn message_context(
    message_id: MessageId,
    source_agent_id: AgentId,
    target_agent_id: AgentId,
    run_id: RunId,
    causal_sequence: u64,
) -> MessageTraceContext {
    MessageTraceContext {
        message_id,
        source_agent_id,
        target_agent_id,
        run_id: run_id.clone(),
        schema: "splendor.message.task_request.v1".to_string(),
        causal_parent: Some(TraceEventId::from_run_sequence(&run_id, causal_sequence)),
    }
}

fn local_multi_agent_replay_harness_trace() -> (RunId, Vec<TraceEvent>) {
    let parent_run_id = fixed_run_id(0x100);
    let child_run_id = fixed_run_id(0x101);
    let orchestrator = fixed_agent_id(0x200);
    let specialist = fixed_agent_id(0x201);
    let missing_specialist = fixed_agent_id(0x202);
    let positive_message = fixed_message_id(0x300);
    let rejected_message = fixed_message_id(0x301);
    let expired_message = fixed_message_id(0x302);
    let timestamp = OffsetDateTime::UNIX_EPOCH;

    let positive_context = message_context(
        positive_message.clone(),
        orchestrator.clone(),
        specialist.clone(),
        parent_run_id.clone(),
        0,
    );
    let rejected_context = message_context(
        rejected_message,
        orchestrator.clone(),
        missing_specialist,
        parent_run_id.clone(),
        1,
    );
    let expired_context = message_context(
        expired_message,
        orchestrator.clone(),
        specialist.clone(),
        parent_run_id.clone(),
        2,
    );
    let laundering_action = Action {
        name: "filesystem.write".to_string(),
        params: serde_json::json!({"path": "specialist-only.txt"}),
        side_effect_class: SideEffectClass::Filesystem,
        cost_estimate: None,
        required_permissions: vec!["filesystem.write".to_string()],
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    };
    let laundering_result = VerificationResult {
        allowed: false,
        reasons: vec!["permission_laundering_denied".to_string()],
        artifacts: serde_json::json!({
            "verifier": "agent_isolation_ledger",
            "ledger_reason": "specialist cannot inherit orchestrator filesystem.write permission",
            "source_agent_id": orchestrator.to_string(),
            "target_agent_id": specialist.to_string(),
            "required_permission": "filesystem.write"
        }),
    };

    let events = vec![
        TraceEvent::new(
            parent_run_id.clone(),
            0,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        ),
        TraceEvent::new(
            parent_run_id.clone(),
            1,
            timestamp,
            TraceEventKind::MessageQueued {
                message: positive_context.clone(),
            },
        ),
        TraceEvent::new(
            parent_run_id.clone(),
            2,
            timestamp,
            TraceEventKind::MessageDelivered {
                message: positive_context.clone(),
            },
        ),
        TraceEvent::new(
            parent_run_id.clone(),
            3,
            timestamp,
            TraceEventKind::MessageConsumed {
                message: positive_context,
            },
        ),
        TraceEvent::new(
            parent_run_id.clone(),
            4,
            timestamp,
            TraceEventKind::MessageRejected {
                message: rejected_context,
                reason: "target agent is not registered".to_string(),
            },
        ),
        TraceEvent::new(
            parent_run_id.clone(),
            5,
            timestamp,
            TraceEventKind::MessageExpired {
                message: expired_context,
                reason: Some("max_message_age exceeded before consumption".to_string()),
            },
        ),
        TraceEvent::new(
            parent_run_id.clone(),
            6,
            timestamp,
            TraceEventKind::ChildRunLinked {
                parent_run_id: parent_run_id.clone(),
                child_run_id,
                parent_agent_id: orchestrator,
                child_agent_id: specialist,
                causal_parent: Some(TraceId::from_run_sequence(&parent_run_id, 3)),
                source_message_id: Some(positive_message),
            },
        ),
        TraceEvent::new(
            parent_run_id.clone(),
            7,
            timestamp,
            TraceEventKind::ActionDenied {
                action: laundering_action,
                result: laundering_result,
            },
        ),
        TraceEvent::new(
            parent_run_id.clone(),
            8,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        ),
    ];
    (parent_run_id, events)
}

#[test]
fn parse_args_accepts_trace_export() {
    let command = parse_args(vec![
        "trace".to_string(),
        "export".to_string(),
        "--db".to_string(),
        "/tmp/db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
    ])
    .expect("parse args");
    match command {
        Command::TraceExport { db_path, run_id } => {
            assert_eq!(db_path, PathBuf::from("/tmp/db"));
            assert_eq!(run_id, "run-1");
        }
        _ => panic!("unexpected command"),
    }
}

#[test]
fn collect_args_uses_env_when_no_test_args() {
    let args = collect_args();
    assert!(!args.is_empty());
}

#[test]
fn parse_args_help_returns_usage() {
    let error = parse_args(vec!["--help".to_string()]).expect_err("error");
    assert!(error.contains("splendorctl"));
}

#[test]
fn parse_args_accepts_replay() {
    let command = parse_args(vec![
        "replay".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--state-db".to_string(),
        "/tmp/state.db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
        "--include-state".to_string(),
    ])
    .expect("parse args");
    match command {
        Command::Replay {
            trace_db_path,
            state_db_path,
            run_id,
            from_snapshot,
            include_state,
        } => {
            assert_eq!(trace_db_path, PathBuf::from("/tmp/trace.db"));
            assert_eq!(state_db_path, PathBuf::from("/tmp/state.db"));
            assert_eq!(run_id, "run-1");
            assert!(from_snapshot.is_none());
            assert!(include_state);
        }
        _ => panic!("unexpected command"),
    }
}

#[test]
fn parse_args_accepts_audit_export_filters() {
    let command = parse_args(vec![
        "audit".to_string(),
        "export".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--state-db".to_string(),
        "/tmp/state.db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
        "--tenant".to_string(),
        "tenant-1".to_string(),
        "--agent".to_string(),
        "agent-1".to_string(),
        "--action".to_string(),
        "action-1".to_string(),
        "--adapter".to_string(),
        "adapter-1".to_string(),
        "--node".to_string(),
        "node-1".to_string(),
        "--instance".to_string(),
        "instance-1".to_string(),
        "--fleet".to_string(),
        "fleet-1".to_string(),
    ])
    .expect("parse args");
    match command {
        Command::AuditExport {
            trace_db_path,
            state_db_path,
            run_id,
            filters,
        } => {
            assert_eq!(trace_db_path, PathBuf::from("/tmp/trace.db"));
            assert_eq!(state_db_path, PathBuf::from("/tmp/state.db"));
            assert_eq!(run_id, "run-1");
            assert_eq!(filters.tenant.as_deref(), Some("tenant-1"));
            assert_eq!(filters.agent.as_deref(), Some("agent-1"));
            assert_eq!(filters.action.as_deref(), Some("action-1"));
            assert_eq!(filters.adapter.as_deref(), Some("adapter-1"));
            assert_eq!(filters.node.as_deref(), Some("node-1"));
            assert_eq!(filters.instance.as_deref(), Some("instance-1"));
            assert_eq!(filters.fleet.as_deref(), Some("fleet-1"));
        }
        _ => panic!("unexpected command"),
    }
}

#[test]
fn parse_args_accepts_acceptance_subcommands() {
    let command = parse_args(vec![
        "acceptance".to_string(),
        "validate-import".to_string(),
        "--trace".to_string(),
        "trace.jsonl".to_string(),
        "--state".to_string(),
        "state.json".to_string(),
        "--scenario-report".to_string(),
        "scenario.json".to_string(),
        "--source".to_string(),
        "UC-E2E-S1".to_string(),
        "--expected-trace-chain".to_string(),
        "blake3:expected".to_string(),
        "--expected-state-hash".to_string(),
        "sha256:expected".to_string(),
    ])
    .expect("validate-import parses");
    assert!(matches!(command, Command::AcceptanceValidateImport { .. }));

    let command = parse_args(vec![
        "acceptance".to_string(),
        "compat".to_string(),
        "--fixture".to_string(),
        "fixture.json".to_string(),
        "--target-schema".to_string(),
        "splendor.0.1.stable.v1".to_string(),
    ])
    .expect("compat parses");
    assert!(matches!(command, Command::AcceptanceCompat { .. }));

    let command = parse_args(vec![
        "acceptance".to_string(),
        "audit-check".to_string(),
        "--audit".to_string(),
        "audit.json".to_string(),
        "--scenario-report".to_string(),
        "scenario.json".to_string(),
        "--case".to_string(),
        "deny_url".to_string(),
        "--category".to_string(),
        "denial".to_string(),
    ])
    .expect("audit-check parses");
    assert!(matches!(command, Command::AcceptanceAuditCheck { .. }));

    let command = parse_args(vec![
        "acceptance".to_string(),
        "replay-mode".to_string(),
        "--mode".to_string(),
        "inspect_only".to_string(),
        "--trace".to_string(),
        "trace.jsonl".to_string(),
        "--state".to_string(),
        "state.json".to_string(),
        "--audit".to_string(),
        "audit.json".to_string(),
        "--scenario-report".to_string(),
        "scenario.json".to_string(),
        "--source".to_string(),
        "UC-E2E-S4".to_string(),
    ])
    .expect("replay-mode parses");
    assert!(matches!(command, Command::AcceptanceReplayMode { .. }));

    let command = parse_args(vec![
        "acceptance".to_string(),
        "replay-credential-check".to_string(),
        "--credential".to_string(),
        "credential.json".to_string(),
    ])
    .expect("replay-credential-check parses");
    assert!(matches!(
        command,
        Command::AcceptanceReplayCredentialCheck { .. }
    ));
}

#[test]
fn parse_args_rejects_acceptance_error_paths() {
    let error = parse_args(args(&["acceptance"])).expect_err("missing acceptance subcommand");
    assert!(error.contains("splendorctl acceptance"));

    let error = parse_args(args(&["acceptance", "unknown"])).expect_err("unknown acceptance");
    assert!(error.contains("Unknown acceptance subcommand"));

    let error =
        parse_args(args(&["acceptance", "validate-import", "--help"])).expect_err("validate help");
    assert!(error.contains("acceptance validate-import"));

    let error = parse_args(args(&[
        "acceptance",
        "validate-import",
        "--trace",
        "trace.jsonl",
        "--bad",
    ]))
    .expect_err("validate unknown arg");
    assert!(error.contains("Unknown argument"));

    let error = parse_args(args(&["acceptance", "compat"])).expect_err("compat missing fixture");
    assert!(error.contains("Missing required --fixture"));

    let error = parse_args(args(&["acceptance", "compat", "--help"])).expect_err("compat help");
    assert!(error.contains("acceptance compat"));

    let error = parse_args(args(&[
        "acceptance",
        "audit-check",
        "--audit",
        "audit.json",
        "--unknown",
    ]))
    .expect_err("audit unknown arg");
    assert!(error.contains("Unknown argument"));

    let error = parse_args(args(&["acceptance", "audit-check", "--help"])).expect_err("audit help");
    assert!(error.contains("acceptance audit-check"));

    let error =
        parse_args(args(&["acceptance", "replay-mode", "--help"])).expect_err("replay-mode help");
    assert!(error.contains("acceptance replay-mode"));

    let error = parse_args(args(&[
        "acceptance",
        "replay-mode",
        "--mode",
        "inspect_only",
        "--unknown",
    ]))
    .expect_err("replay mode unknown arg");
    assert!(error.contains("Unknown argument"));

    let error = parse_args(args(&["acceptance", "replay-credential-check", "--help"]))
        .expect_err("credential help");
    assert!(error.contains("acceptance replay-credential-check"));

    let error = parse_args(args(&[
        "acceptance",
        "replay-credential-check",
        "--unknown",
    ]))
    .expect_err("credential unknown arg");
    assert!(error.contains("Unknown argument"));
}

#[test]
fn parse_args_accepts_run() {
    let command = parse_args(vec![
        "run".to_string(),
        "--config".to_string(),
        "/tmp/config.yaml".to_string(),
        "--cycles".to_string(),
        "2".to_string(),
    ])
    .expect("parse args");
    match command {
        Command::Run {
            config_path,
            cycles,
            forever,
        } => {
            assert_eq!(config_path, PathBuf::from("/tmp/config.yaml"));
            assert_eq!(cycles, Some(2));
            assert!(!forever);
        }
        _ => panic!("unexpected command"),
    }
}

#[test]
fn parse_args_accepts_state_head() {
    let command = parse_args(vec![
        "state".to_string(),
        "head".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
    ])
    .expect("parse args");
    match command {
        Command::StateHead { db_path, run_id } => {
            assert_eq!(db_path, PathBuf::from("/tmp/trace.db"));
            assert_eq!(run_id, "run-1");
        }
        _ => panic!("unexpected command"),
    }
}

#[test]
fn parse_args_accepts_version() {
    let command = parse_args(vec!["--version".to_string()]).expect("parse args");
    assert!(matches!(command, Command::Version));
}

#[test]
fn parse_args_rejects_unknown_command() {
    let error = parse_args(vec!["unknown".to_string()]).expect_err("error");
    assert!(error.contains("Unknown command"));
}

#[test]
fn parse_args_rejects_unknown_trace_subcommand() {
    let error = parse_args(vec!["trace".to_string(), "nope".to_string()]).expect_err("error");
    assert!(error.contains("Unknown trace subcommand"));
}

#[test]
fn parse_args_rejects_unknown_state_subcommand() {
    let error = parse_args(vec!["state".to_string(), "nope".to_string()]).expect_err("error");
    assert!(error.contains("Unknown state subcommand"));
}

#[test]
fn parse_args_rejects_state_and_trace_help_or_unknown_arguments() {
    let error = parse_args(vec!["state".to_string()]).expect_err("missing state subcommand");
    assert!(error.contains("splendorctl"));
    let error = parse_args(vec![
        "state".to_string(),
        "head".to_string(),
        "--help".to_string(),
    ])
    .expect_err("state help");
    assert!(error.contains("splendorctl"));
    let error = parse_args(vec![
        "state".to_string(),
        "head".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
        "--unknown".to_string(),
    ])
    .expect_err("unknown state arg");
    assert!(error.contains("Unknown argument"));

    let error = parse_args(vec![
        "trace".to_string(),
        "export".to_string(),
        "--help".to_string(),
    ])
    .expect_err("trace help");
    assert!(error.contains("splendorctl"));
    let error = parse_args(vec![
        "trace".to_string(),
        "export".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
        "--unknown".to_string(),
    ])
    .expect_err("unknown trace arg");
    assert!(error.contains("Unknown argument"));
}

#[test]
fn parse_args_rejects_unknown_replay_argument() {
    let error = parse_args(vec![
        "replay".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--state-db".to_string(),
        "/tmp/state.db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
        "--unknown".to_string(),
    ])
    .expect_err("error");
    assert!(error.contains("Unknown argument"));
}

#[test]
fn parse_args_rejects_audit_export_error_paths() {
    let error = parse_args(vec!["audit".to_string()]).expect_err("missing subcommand");
    assert!(error.contains("splendorctl"));

    let error = parse_args(vec!["audit".to_string(), "nope".to_string()])
        .expect_err("unknown audit subcommand");
    assert!(error.contains("Unknown audit subcommand"));

    let error = parse_args(vec![
        "audit".to_string(),
        "export".to_string(),
        "--help".to_string(),
    ])
    .expect_err("audit help");
    assert!(error.contains("splendorctl"));

    let error = parse_args(vec![
        "audit".to_string(),
        "export".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--state-db".to_string(),
        "/tmp/state.db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
        "--unknown".to_string(),
    ])
    .expect_err("unknown audit argument");
    assert!(error.contains("Unknown argument"));

    for flag in [
        "--db",
        "--state-db",
        "--run",
        "--tenant",
        "--agent",
        "--action",
        "--adapter",
        "--node",
        "--instance",
        "--fleet",
    ] {
        let error = parse_args(vec![
            "audit".to_string(),
            "export".to_string(),
            flag.to_string(),
        ])
        .expect_err("missing audit flag value");
        assert!(error.contains(&format!("Missing value for {flag}")));
    }

    let error = parse_args(vec![
        "audit".to_string(),
        "export".to_string(),
        "--state-db".to_string(),
        "/tmp/state.db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
    ])
    .expect_err("missing audit db");
    assert!(error.contains("Missing required --db"));

    let error = parse_args(vec![
        "audit".to_string(),
        "export".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
    ])
    .expect_err("missing audit state db");
    assert!(error.contains("Missing required --state-db"));

    let error = parse_args(vec![
        "audit".to_string(),
        "export".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--state-db".to_string(),
        "/tmp/state.db".to_string(),
    ])
    .expect_err("missing audit run");
    assert!(error.contains("Missing required --run"));
}

#[test]
fn parse_args_rejects_run_without_config() {
    let error = parse_args(vec!["run".to_string()]).expect_err("error");
    assert!(error.contains("Missing config path"));
}

#[test]
fn parse_args_rejects_run_forever_with_cycles() {
    let error = parse_args(vec![
        "run".to_string(),
        "--config".to_string(),
        "/tmp/config.yaml".to_string(),
        "--cycles".to_string(),
        "2".to_string(),
        "--forever".to_string(),
    ])
    .expect_err("error");
    assert!(error.contains("--forever and --cycles"));
}

#[test]
fn parse_args_requires_db() {
    let error = parse_args(vec![
        "trace".to_string(),
        "export".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
    ])
    .expect_err("error");
    assert!(error.contains("Missing required --db"));
}

#[test]
fn parse_args_requires_state_db_for_replay() {
    let error = parse_args(vec![
        "replay".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
    ])
    .expect_err("error");
    assert!(error.contains("Missing required --state-db"));
}

#[test]
fn parse_args_requires_run() {
    let error = parse_args(vec![
        "trace".to_string(),
        "export".to_string(),
        "--db".to_string(),
        "/tmp/db".to_string(),
    ])
    .expect_err("error");
    assert!(error.contains("Missing required --run"));
}

#[test]
fn parse_args_requires_run_for_replay() {
    let error = parse_args(vec![
        "replay".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--state-db".to_string(),
        "/tmp/state.db".to_string(),
    ])
    .expect_err("error");
    assert!(error.contains("Missing required --run"));
}

#[test]
fn export_trace_errors_when_missing_db() {
    let missing = PathBuf::from("/tmp/missing-trace.db");
    let error = export_trace(&missing, "run-1").expect_err("error");
    assert_eq!(error, "trace_database_not_found");
}

#[test]
fn export_trace_succeeds_with_records() {
    let temp = NamedTempFile::new().expect("temp file");
    let store = SqliteTraceStore::open(temp.path()).expect("open store");
    let run_id = RunId::new();
    append_valid_trace_records(&store, &run_id);
    export_trace(&temp.path().to_path_buf(), &run_id.to_string()).expect("export");
}

#[test]
fn json_line_serialization_failure_never_partially_mutates_the_output_spool() {
    struct FailsAfterOneField;

    impl Serialize for FailsAfterOneField {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::{Error as _, SerializeMap};

            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry("already_serialized", "CANARY")?;
            Err(S::Error::custom("injected serialization failure"))
        }
    }

    let mut spool = b"existing-output\n".to_vec();
    let before = spool.clone();
    let error = append_json_line(&mut spool, &FailsAfterOneField, "fixed_encode_failure")
        .expect_err("serialization failure");
    assert_eq!(error, "fixed_encode_failure");
    assert_eq!(spool, before);
    assert!(!String::from_utf8_lossy(&spool).contains("CANARY"));
}

#[test]
fn replay_errors_when_missing_db() {
    let trace_db = PathBuf::from("/tmp/missing-trace.db");
    let state_db = PathBuf::from("/tmp/missing-state.db");
    let error = replay_run(&trace_db, &state_db, "run-1", None, false).expect_err("error");
    assert_eq!(error, "trace_database_not_found");
}

#[test]
fn replay_errors_when_state_store_or_requested_snapshot_is_missing() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let missing_state_path = dir.path().join("missing-state.db");
    let trace_store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let run_id = RunId::new();
    for event in [
        TraceEvent::new(
            run_id.clone(),
            0,
            OffsetDateTime::UNIX_EPOCH,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            OffsetDateTime::UNIX_EPOCH,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        ),
    ] {
        TraceStore::append(
            &trace_store,
            &run_id.to_string(),
            serde_json::to_value(event).unwrap(),
        )
        .expect("append");
    }

    let error = replay_outputs_from_stores(
        &trace_path,
        &missing_state_path,
        &run_id.to_string(),
        None,
        false,
    )
    .expect_err("missing state db");
    assert_eq!(error, "state_database_not_found");

    let state_path = dir.path().join("state.db");
    SqliteStateStore::open(&state_path).expect("state store");
    let missing_snapshot = SnapshotId::from_hash(ContentHash::blake3(b"not-in-trace"));
    let error = replay_outputs_from_stores(
        &trace_path,
        &state_path,
        &run_id.to_string(),
        Some(&missing_snapshot.to_string()),
        false,
    )
    .expect_err("missing snapshot");
    assert_eq!(error, "replay_snapshot_not_found");
}

#[test]
fn audit_export_errors_when_required_stores_are_missing() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_db = dir.path().join("missing-trace.db");
    let state_db = dir.path().join("missing-state.db");
    let error = audit_export_from_stores(&trace_db, &state_db, "run-1", AuditFilters::default())
        .expect_err("missing trace db");
    assert_eq!(error, "trace_database_not_found");

    SqliteTraceStore::open(&trace_db).expect("trace store");
    let error = audit_export_from_stores(&trace_db, &state_db, "run-1", AuditFilters::default())
        .expect_err("missing state db");
    assert_eq!(error, "state_database_not_found");
}

#[test]
fn replay_succeeds_with_snapshot() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let state_temp = NamedTempFile::new().expect("state db");
    let trace_store = SqliteTraceStore::open(trace_temp.path()).expect("trace store");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");

    let data_ref = state_store
        .put_state(splendor_store::StateData {
            bytes: b"hello".to_vec(),
            content_type: None,
        })
        .expect("state bytes");
    let metadata = StateMetadata {
        created_at: OffsetDateTime::now_utc(),
        label: None,
        tenant_id: None,
        agent_id: None,
        run_id: None,
        trace_event_id: None,
    };
    let node_id = state_store
        .commit_node(Vec::new(), data_ref, metadata)
        .expect("commit");
    let snapshot_id = state_store.snapshot(&node_id).expect("snapshot");

    let run_id = RunId::new();
    let timestamp = OffsetDateTime::now_utc();
    let start = TraceEvent::new(
        run_id.clone(),
        0,
        timestamp,
        TraceEventKind::LoopTickStarted { tick_id: 1 },
    );
    let state = TraceEvent::new(
        run_id.clone(),
        1,
        timestamp,
        TraceEventKind::StateCommitted {
            state_hash: node_id.hash().clone(),
            snapshot_id: Some(snapshot_id.clone()),
        },
    );
    let done = TraceEvent::new(
        run_id.clone(),
        2,
        timestamp,
        TraceEventKind::LoopTickCompleted {
            tick_id: 1,
            integrity: None,
        },
    );
    for event in [start, state, done] {
        TraceStore::append(
            &trace_store,
            &run_id.to_string(),
            serde_json::to_value(event).unwrap(),
        )
        .expect("append");
    }

    replay_run(
        &trace_temp.path().to_path_buf(),
        &state_temp.path().to_path_buf(),
        &run_id.to_string(),
        Some(&snapshot_id.to_string()),
        true,
    )
    .expect("replay");
}

#[test]
fn replay_identifies_state_handoff_boundary() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let state_temp = NamedTempFile::new().expect("state db");
    let trace_store = SqliteTraceStore::open(trace_temp.path()).expect("trace store");
    let _state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let run_id = RunId::new();
    let timestamp = OffsetDateTime::now_utc();
    let handoff = StateHandoffTraceContext {
        handoff_id: "handoff_replay".to_string(),
        mode: StateReferenceMode::SnapshotImport,
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id: run_id.clone(),
        work_order_id: "wo_replay".to_string(),
        source_instance_id: Some("source".to_string()),
        receiver_instance_id: Some("receiver".to_string()),
        source_state_node_id: "blake3:source".to_string(),
        previous_state_node_id: Some("blake3:previous".to_string()),
        receiver_state_node_id: Some("blake3:receiver".to_string()),
        snapshot_id: None,
        source_trace_id: Some(TraceId::from_run_sequence(&run_id, 0)),
    };
    let event = TraceEvent::new(
        run_id.clone(),
        0,
        timestamp,
        TraceEventKind::StateHandoffImported { handoff },
    );
    TraceStore::append(
        &trace_store,
        &run_id.to_string(),
        serde_json::to_value(event).unwrap(),
    )
    .expect("append");

    replay_run(
        &trace_temp.path().to_path_buf(),
        &state_temp.path().to_path_buf(),
        &run_id.to_string(),
        None,
        false,
    )
    .expect("replay");
}

#[test]
fn handoff_boundary_output_contains_previous_head() {
    let run_id = RunId::new();
    let handoff = StateHandoffTraceContext {
        handoff_id: "handoff_output".to_string(),
        mode: StateReferenceMode::SnapshotImport,
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id,
        work_order_id: "wo_output".to_string(),
        source_instance_id: None,
        receiver_instance_id: None,
        source_state_node_id: "blake3:source".to_string(),
        previous_state_node_id: Some("blake3:previous".to_string()),
        receiver_state_node_id: Some("blake3:receiver".to_string()),
        snapshot_id: None,
        source_trace_id: None,
    };
    let output = ReplayOutput::HandoffBoundary {
        event_kind: "state.handoff.imported".to_string(),
        handoff: Box::new(handoff),
        previous_state_node_id: Some("blake3:previous".to_string()),
        receiver_state_node_id: Some("blake3:receiver".to_string()),
        reason: None,
        trace_sequence: 3,
    };

    let value = serde_json::to_value(output).expect("serialize");

    assert_eq!(value["type"], "handoff_boundary");
    assert_eq!(value["previous_state_node_id"], "blake3:previous");
    assert_eq!(value["receiver_state_node_id"], "blake3:receiver");
}

#[test]
fn replay_reconstructs_local_multi_agent_harness_deterministically() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let state_temp = NamedTempFile::new().expect("state db");
    let trace_store = SqliteTraceStore::open(trace_temp.path()).expect("trace store");
    let _state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let (run_id, events) = local_multi_agent_replay_harness_trace();

    for event in events {
        TraceStore::append(
            &trace_store,
            &run_id.to_string(),
            serde_json::to_value(event).unwrap(),
        )
        .expect("append");
    }

    let first = replay_outputs_from_stores(
        &trace_temp.path().to_path_buf(),
        &state_temp.path().to_path_buf(),
        &run_id.to_string(),
        None,
        false,
    )
    .expect("first replay");
    let second = replay_outputs_from_stores(
        &trace_temp.path().to_path_buf(),
        &state_temp.path().to_path_buf(),
        &run_id.to_string(),
        None,
        false,
    )
    .expect("second replay");

    let first_lines = first
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .expect("first json");
    let second_lines = second
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .expect("second json");
    assert_eq!(first_lines, second_lines);

    let values = first
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .expect("json values");
    let tick = values
        .iter()
        .find(|value| value["type"] == "tick")
        .expect("tick output");
    let tick_messages = tick["messages"].as_array().expect("tick messages");
    assert_eq!(tick_messages.len(), 5);
    assert_eq!(tick["parent_child_runs"].as_array().unwrap().len(), 1);
    assert_eq!(tick["isolation_denials"].as_array().unwrap().len(), 1);

    let graph = values
        .iter()
        .find(|value| value["type"] == "causal_graph")
        .expect("causal graph output");
    let run_id_text = run_id.to_string();
    assert_eq!(graph["run_id"].as_str(), Some(run_id_text.as_str()));
    assert_eq!(graph["replay_mode"].as_str(), Some("inspect_only"));
    assert_eq!(graph["side_effects_replayed"].as_bool(), Some(false));

    let messages = graph["messages"].as_array().expect("graph messages");
    let lifecycles = messages
        .iter()
        .map(|message| message["lifecycle"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        lifecycles,
        vec!["queued", "delivered", "consumed", "rejected", "expired"]
    );
    for message in messages {
        assert!(message.get("trace_event_id").is_some());
        assert!(message.get("message_id").is_some());
        assert!(message.get("source_agent_id").is_some());
        assert!(message.get("target_agent_id").is_some());
        assert_eq!(message["run_id"].as_str(), Some(run_id_text.as_str()));
    }

    let child_runs = graph["parent_child_runs"].as_array().expect("child runs");
    assert_eq!(child_runs.len(), 1);
    assert_eq!(
        child_runs[0]["parent_run_id"].as_str(),
        Some(run_id_text.as_str())
    );
    assert_eq!(
        child_runs[0]["side_effects_replayed"].as_bool(),
        Some(false)
    );

    let isolation_denials = graph["isolation_denials"]
        .as_array()
        .expect("isolation denials");
    assert_eq!(isolation_denials.len(), 1);
    assert_eq!(
        isolation_denials[0]["verifier"].as_str(),
        Some("agent_isolation_ledger")
    );
    assert!(isolation_denials[0]["ledger_reason"]
        .as_str()
        .unwrap()
        .contains("cannot inherit"));
    assert_eq!(
        isolation_denials[0]["reasons"],
        serde_json::json!(["permission_laundering_denied"])
    );

    let denial_failure_scenarios = usize::from(lifecycles.contains(&"rejected"))
        + usize::from(lifecycles.contains(&"expired"))
        + isolation_denials.len();
    assert!(denial_failure_scenarios >= 3);
}

fn test_delegation_context(parent_run_id: RunId) -> LocalDelegationTraceContext {
    LocalDelegationTraceContext {
        parent_run_id: parent_run_id.clone(),
        child_run_id: fixed_run_id(0x111),
        parent_trace_id: Some(TraceId::from_run_sequence(&parent_run_id, 7)),
        request_message_id: Some(fixed_message_id(0x112)),
        response_message_id: Some(fixed_message_id(0x113)),
        source_agent_id: fixed_agent_id(0x114),
        target_agent_id: fixed_agent_id(0x115),
        objective: "scoped specialist work".to_string(),
        authority_evidence: None,
        delegation_ledger: None,
    }
}

#[test]
fn replay_parent_child_run_covers_local_delegation_lifecycle_variants() {
    let run_id = fixed_run_id(0x110);
    let delegation = test_delegation_context(run_id.clone());
    let timestamp = OffsetDateTime::UNIX_EPOCH;
    let failure = splendor_types::TaskFailure {
        code: "child_failed".to_string(),
        reason: "specialist denied scoped work".to_string(),
        retryable: false,
        trace_id: Some(TraceId::from_run_sequence(&run_id, 12)),
    };

    let variants = vec![
        TraceEventKind::DelegationRequested {
            delegation: delegation.clone(),
        },
        TraceEventKind::ChildRunStarted {
            delegation: delegation.clone(),
        },
        TraceEventKind::ChildRunCompleted {
            delegation: delegation.clone(),
        },
        TraceEventKind::ChildRunFailed {
            delegation: delegation.clone(),
            failure,
        },
        TraceEventKind::DelegationRejected {
            delegation: delegation.clone(),
            reason: "target_agent_tenant_mismatch".to_string(),
        },
    ];

    for (sequence, kind) in variants.into_iter().enumerate() {
        let event = TraceEvent::new(run_id.clone(), sequence as u64, timestamp, kind);
        let replay = replay_parent_child_run(&event)
            .expect("delegation replay parses")
            .expect("delegation replay event");
        assert_eq!(replay.parent_run_id, run_id);
        assert_eq!(replay.child_run_id, delegation.child_run_id);
        assert_eq!(replay.parent_agent_id, delegation.source_agent_id);
        assert_eq!(replay.child_agent_id, delegation.target_agent_id);
        assert_eq!(replay.causal_parent, delegation.parent_trace_id);
        assert_eq!(replay.source_message_id, delegation.request_message_id);
        assert!(!replay.side_effects_replayed);
    }
}

#[test]
fn replay_reconstructs_escalation_without_side_effects() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let state_temp = NamedTempFile::new().expect("state db");
    let trace_store = SqliteTraceStore::open(trace_temp.path()).expect("trace store");
    let _state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let action_id = ActionId::new();
    let action = Action {
        name: "quota".to_string(),
        params: serde_json::json!({}),
        side_effect_class: SideEffectClass::Network,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    };
    let verification = VerificationResult {
        allowed: false,
        reasons: vec!["max_actions_per_tick".to_string()],
        artifacts: serde_json::json!({"quota": {"context": {"source": "quota_ledger"}}}),
    };
    let escalation = EscalationContext {
        trigger: EscalationTrigger::QuotaPressure,
        threshold: 1,
        observed_count: 1,
        scope: EscalationScope::Action,
        decision: EscalationDecision::Pause,
        tenant_id,
        agent_id,
        run_id: run_id.clone(),
        action_id: Some(action_id),
        action_name: Some("quota".to_string()),
        adapter: Some("stub".to_string()),
        reason: "quota pressure".to_string(),
        evidence: serde_json::json!({"source": "test"}),
        decided_at: OffsetDateTime::now_utc(),
    };
    let timestamp = OffsetDateTime::now_utc();
    let events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            timestamp,
            TraceEventKind::ActionVerificationCompleted {
                action: action.clone(),
                result: verification.clone(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            2,
            timestamp,
            TraceEventKind::EscalationTriggered {
                escalation: escalation.clone(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            3,
            timestamp,
            TraceEventKind::ActionNeedsIntervention {
                action,
                result: verification,
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            4,
            timestamp,
            TraceEventKind::OutcomeRecorded {
                outcome: serde_json::json!({"needs_intervention": true}),
                feedback: None,
                reward: None,
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            5,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        ),
    ];
    for event in events {
        TraceStore::append(
            &trace_store,
            &run_id.to_string(),
            serde_json::to_value(event).unwrap(),
        )
        .expect("append");
    }

    let outputs = replay_outputs_from_stores(
        &trace_temp.path().to_path_buf(),
        &state_temp.path().to_path_buf(),
        &run_id.to_string(),
        None,
        false,
    )
    .expect("replay");
    let values = outputs
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .expect("json values");
    let tick = values
        .iter()
        .find(|value| value["type"] == "tick")
        .expect("tick output");
    assert_eq!(
        tick["actions"][0]["status"].as_str(),
        Some("needs_intervention")
    );
    assert_eq!(
        tick["escalations"].as_array().expect("escalations").len(),
        1
    );
    assert_eq!(
        tick["escalations"][0]["side_effects_replayed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        tick["escalations"][0]["escalation"]["trigger"].as_str(),
        Some("QuotaPressure")
    );
}

#[test]
fn replay_reports_circuit_breaker_denial_scope() {
    let state_temp = NamedTempFile::new().expect("state db");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let run_id = fixed_run_id(0x130);
    let action = Action {
        name: "http.fetch".to_string(),
        params: serde_json::json!({"url": "https://example.com"}),
        side_effect_class: SideEffectClass::Network,
        cost_estimate: None,
        required_permissions: vec!["http.fetch".to_string()],
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    };
    let result = VerificationResult {
        allowed: false,
        reasons: vec!["circuit_breaker_tripped".to_string()],
        artifacts: serde_json::json!({
            "circuit_breaker": {
                "breaker_id": "cb_adapter_http",
                "scope": "adapter",
                "scope_value": "http",
                "state": "tripped",
                "reason": "adapter degraded"
            }
        }),
    };
    let events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            OffsetDateTime::UNIX_EPOCH,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            OffsetDateTime::UNIX_EPOCH,
            TraceEventKind::ActionDenied { action, result },
        ),
        TraceEvent::new(
            run_id.clone(),
            2,
            OffsetDateTime::UNIX_EPOCH,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        ),
    ];

    let outputs = collect_replay_outputs(
        &events,
        &state_store,
        &run_id.to_string(),
        None,
        None,
        None,
        false,
    )
    .expect("replay outputs");
    let values = outputs
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .expect("json values");
    let tick = values
        .iter()
        .find(|value| value["type"] == "tick")
        .expect("tick output");
    let denials = tick["circuit_breaker_denials"]
        .as_array()
        .expect("breaker denials");
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0]["breaker_id"], "cb_adapter_http");
    assert_eq!(denials[0]["scope"], "adapter");
    assert_eq!(denials[0]["scope_value"], "http");

    let graph = values
        .iter()
        .find(|value| value["type"] == "causal_graph")
        .expect("causal graph output");
    assert_eq!(
        graph["circuit_breaker_denials"]
            .as_array()
            .expect("graph breaker denials")
            .len(),
        1
    );
}

#[test]
fn replay_explains_approval_lifecycle_and_final_outcomes_without_side_effects() {
    let state_temp = NamedTempFile::new().expect("state db");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let run_id = fixed_run_id(0x140);
    let tenant_id = TenantId::from(Uuid::from_u128(0x240));
    let agent_id = fixed_agent_id(0x241);
    let action_id = fixed_action_id(0x340);
    let approval_id = fixed_approval_id(0x440);
    let action = Action {
        name: "artifact.publish".to_string(),
        params: serde_json::json!({"artifact_id": "artifact:weekly"}),
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: vec!["artifact.publish".to_string()],
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    };
    let approval = ApprovalTraceContext {
        approval_id,
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: run_id.clone(),
        action_id: Some(action_id.clone()),
        action_name: action.name.clone(),
        adapter: Some("artifact-store".to_string()),
        decision: None,
        reason: Some("CFO approval required".to_string()),
        policy_id: Some("approval_high_risk_publish".to_string()),
        risk_level: Some("high".to_string()),
        issued_at: None,
        expires_at: Some(OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1)),
        revoked: false,
    };
    let required = VerificationResult {
        allowed: false,
        reasons: vec!["approval_required".to_string()],
        artifacts: serde_json::json!({
            "approval": {"policy_id": "approval_high_risk_publish"},
            "context": {
                "tenant_id": tenant_id.to_string(),
                "agent_id": agent_id.to_string(),
                "run_id": run_id.to_string(),
                "action_id": action_id.to_string(),
                "action": action.name,
                "adapter": "artifact-store"
            }
        }),
    };
    let denied = VerificationResult {
        allowed: false,
        reasons: vec!["approval_denied".to_string()],
        artifacts: serde_json::json!({"context": {"adapter": "artifact-store"}}),
    };
    let action_identity = TraceIdentityContext::new(run_id.clone())
        .with_tenant_agent(tenant_id.clone(), agent_id.clone())
        .with_tick_id(TickId::from(1))
        .with_action_id(action_id.clone());
    let timestamp = OffsetDateTime::UNIX_EPOCH;
    let events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            timestamp,
            TraceEventKind::ApprovalRequested {
                approval: approval.clone(),
            },
        ),
        TraceEvent::try_new_with_identity(
            action_identity.clone(),
            2,
            timestamp,
            TraceEventKind::ActionNeedsApproval {
                action: action.clone(),
                result: required.clone(),
            },
        )
        .expect("needs approval identity"),
        TraceEvent::new(
            run_id.clone(),
            3,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            4,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 2 },
        ),
        TraceEvent::new(
            run_id.clone(),
            5,
            timestamp,
            TraceEventKind::ApprovalGranted {
                approval: ApprovalTraceContext {
                    decision: Some(ApprovalDecision::Granted),
                    reason: Some("approved by CFO".to_string()),
                    issued_at: Some(timestamp),
                    ..approval.clone()
                },
            },
        ),
        TraceEvent::try_new_with_identity(
            action_identity.clone().with_tick_id(TickId::from(2)),
            6,
            timestamp,
            TraceEventKind::ActionExecuted {
                action: action.clone(),
                outcome: serde_json::json!({"published": true}),
            },
        )
        .expect("executed identity"),
        TraceEvent::new(
            run_id.clone(),
            7,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 2,
                integrity: None,
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            8,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 3 },
        ),
        TraceEvent::new(
            run_id.clone(),
            9,
            timestamp,
            TraceEventKind::ApprovalDenied {
                approval: ApprovalTraceContext {
                    decision: Some(ApprovalDecision::Denied),
                    reason: Some("denied by CFO".to_string()),
                    issued_at: Some(timestamp),
                    ..approval.clone()
                },
                reason: "denied by CFO".to_string(),
            },
        ),
        TraceEvent::try_new_with_identity(
            action_identity.clone().with_tick_id(TickId::from(3)),
            10,
            timestamp,
            TraceEventKind::ActionDenied {
                action: action.clone(),
                result: denied.clone(),
            },
        )
        .expect("denied identity"),
        TraceEvent::new(
            run_id.clone(),
            11,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 3,
                integrity: None,
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            12,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 4 },
        ),
        TraceEvent::new(
            run_id.clone(),
            13,
            timestamp,
            TraceEventKind::ApprovalExpired {
                approval: approval.clone(),
                reason: "approval evidence expired".to_string(),
            },
        ),
        TraceEvent::try_new_with_identity(
            action_identity.with_tick_id(TickId::from(4)),
            14,
            timestamp,
            TraceEventKind::ActionDenied {
                action,
                result: VerificationResult {
                    allowed: false,
                    reasons: vec!["approval_expired".to_string()],
                    artifacts: serde_json::json!({"context": {"adapter": "artifact-store"}}),
                },
            },
        )
        .expect("expired denial identity"),
        TraceEvent::new(
            run_id.clone(),
            15,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 4,
                integrity: None,
            },
        ),
    ];

    let outputs = collect_replay_outputs(
        &events,
        &state_store,
        &run_id.to_string(),
        None,
        None,
        None,
        false,
    )
    .expect("replay outputs");
    let values = outputs
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .expect("json values");
    let replay_start = values
        .iter()
        .find(|value| value["type"] == "replay_start")
        .expect("replay start");
    assert_eq!(replay_start["side_effects_replayed"].as_bool(), Some(false));
    let ticks = values
        .iter()
        .filter(|value| value["type"] == "tick")
        .collect::<Vec<_>>();
    assert_eq!(ticks.len(), 4);
    assert_eq!(ticks[0]["actions"][0]["status"], "needs_approval");
    assert_eq!(ticks[1]["actions"][0]["status"], "executed");
    assert_eq!(ticks[2]["actions"][0]["status"], "denied");
    assert_eq!(ticks[3]["actions"][0]["status"], "denied");
    let lifecycles = values
        .iter()
        .find(|value| value["type"] == "causal_graph")
        .expect("causal graph")["approval_events"]
        .as_array()
        .expect("approval events")
        .iter()
        .map(|value| value["lifecycle"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        lifecycles,
        vec!["requested", "granted", "denied", "expired"]
    );
}

#[test]
fn replay_output_redacts_sensitive_values_and_snapshot_bytes() {
    let state_temp = NamedTempFile::new().expect("state db");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let run_id = fixed_run_id(0x141);
    let tenant_id = TenantId::from(Uuid::from_u128(0x242));
    let agent_id = fixed_agent_id(0x243);
    let action_id = fixed_action_id(0x341);
    let approval_id = fixed_approval_id(0x441);
    let timestamp = OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(1);
    let action = Action {
        name: "artifact.publish".to_string(),
        params: serde_json::json!({
            "artifact_id": "artifact:weekly",
            "authorization": "Bearer raw-replay-action-token",
            "nested": {"client_secret": "raw-replay-secret"}
        }),
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: vec!["artifact.publish".to_string()],
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    };
    let approval = ApprovalTraceContext {
        approval_id,
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: run_id.clone(),
        action_id: Some(action_id.clone()),
        action_name: action.name.clone(),
        adapter: Some("artifact-store".to_string()),
        decision: None,
        reason: Some("token=raw-replay-approval-token".to_string()),
        policy_id: Some("approval_publish_high".to_string()),
        risk_level: Some("high".to_string()),
        issued_at: None,
        expires_at: Some(timestamp + time::Duration::hours(1)),
        revoked: false,
    };
    let verification = VerificationResult {
        allowed: false,
        reasons: vec!["approval_required".to_string()],
        artifacts: serde_json::json!({
            "context": {
                "tenant_id": tenant_id.to_string(),
                "agent_id": agent_id.to_string(),
                "run_id": run_id.to_string(),
                "action_id": action_id.to_string(),
                "action": action.name,
                "adapter": "artifact-store"
            },
            "credential": "raw-replay-verifier-token"
        }),
    };
    let state_ref = StateStore::put_state(
        &state_store,
        StateData {
            bytes: b"state contains raw-replay-state-secret".to_vec(),
            content_type: Some("text/plain".to_string()),
        },
    )
    .expect("put state");
    let state_node_id = StateStore::commit_node(
        &state_store,
        Vec::new(),
        state_ref,
        StateMetadata {
            created_at: timestamp,
            label: Some("state token=raw-replay-metadata-token".to_string()),
            tenant_id: Some(tenant_id.clone()),
            agent_id: Some(agent_id.clone()),
            run_id: Some(run_id.clone()),
            trace_event_id: Some(TraceEventId::from_run_sequence(&run_id, 3)),
        },
    )
    .expect("commit state");
    let snapshot_id = StateStore::snapshot(&state_store, &state_node_id).expect("snapshot");
    let action_identity = TraceIdentityContext::new(run_id.clone())
        .with_tenant_agent(tenant_id, agent_id)
        .with_tick_id(TickId::from(1))
        .with_action_id(action_id);
    let events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            timestamp,
            TraceEventKind::ApprovalRequested { approval },
        ),
        TraceEvent::try_new_with_identity(
            action_identity,
            2,
            timestamp,
            TraceEventKind::ActionNeedsApproval {
                action,
                result: verification,
            },
        )
        .expect("action identity"),
        TraceEvent::new(
            run_id.clone(),
            3,
            timestamp,
            TraceEventKind::StateCommitted {
                state_hash: state_node_id.hash().clone(),
                snapshot_id: Some(snapshot_id),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            4,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        ),
    ];

    let outputs = collect_replay_outputs(
        &events,
        &state_store,
        &run_id.to_string(),
        None,
        None,
        None,
        true,
    )
    .expect("replay outputs");
    let encoded = outputs
        .iter()
        .map(redacted_replay_output_value)
        .collect::<Result<Vec<_>, _>>()
        .expect("redacted replay values")
        .into_iter()
        .map(|value| serde_json::to_string(&value).expect("encoded value"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!encoded.contains("raw-replay-action-token"));
    assert!(!encoded.contains("raw-replay-secret"));
    assert!(!encoded.contains("raw-replay-approval-token"));
    assert!(!encoded.contains("raw-replay-verifier-token"));
    assert!(!encoded.contains("raw-replay-state-secret"));
    assert!(!encoded.contains("raw-replay-metadata-token"));
    assert!(encoded.contains("[REDACTED]"));
}

#[test]
fn audit_export_includes_governance_fields_redacts_secrets_and_filters_scope() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let state_temp = NamedTempFile::new().expect("state db");
    let trace_store = SqliteTraceStore::open(trace_temp.path()).expect("trace store");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let run_id = fixed_run_id(0x150);
    let tenant_id = TenantId::from(Uuid::from_u128(0x250));
    let agent_id = fixed_agent_id(0x251);
    let action_id = fixed_action_id(0x350);
    let approval_id = fixed_approval_id(0x450);
    let fleet_id = splendor_types::FleetId::from(Uuid::from_u128(0x550));
    let node_id = splendor_types::NodeId::from(Uuid::from_u128(0x551));
    let instance_id = splendor_types::InstanceId::from(Uuid::from_u128(0x552));
    let timestamp = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2);
    let action = Action {
        name: "artifact.publish".to_string(),
        params: serde_json::json!({
            "artifact_id": "artifact:weekly",
            "api_token": "raw-token-value",
            "nested": {"client_secret": "super-secret"}
        }),
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: vec!["artifact.publish".to_string()],
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    };
    let state_ref = StateStore::put_state(
        &state_store,
        StateData {
            bytes: b"published".to_vec(),
            content_type: Some("text/plain".to_string()),
        },
    )
    .expect("put state");
    let state_metadata = StateMetadata {
        created_at: timestamp,
        label: Some("audit-state".to_string()),
        tenant_id: Some(tenant_id.clone()),
        agent_id: Some(agent_id.clone()),
        run_id: Some(run_id.clone()),
        trace_event_id: Some(TraceEventId::from_run_sequence(&run_id, 7)),
    };
    let state_node_id =
        StateStore::commit_node(&state_store, Vec::new(), state_ref, state_metadata)
            .expect("commit state");
    let snapshot_id = StateStore::snapshot(&state_store, &state_node_id).expect("snapshot");

    let mut scoped_identity = TraceIdentityContext::new(run_id.clone())
        .with_tenant_agent(tenant_id.clone(), agent_id.clone())
        .with_tick_id(TickId::from(1));
    scoped_identity.fleet_id = Some(fleet_id.clone());
    scoped_identity.node_id = Some(node_id.clone());
    scoped_identity.instance_id = Some(instance_id.clone());
    let action_identity = scoped_identity.clone().with_action_id(action_id.clone());
    let state_identity = scoped_identity
        .clone()
        .with_state_node_id(state_node_id.clone());
    let approval = ApprovalTraceContext {
        approval_id,
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: run_id.clone(),
        action_id: Some(action_id.clone()),
        action_name: action.name.clone(),
        adapter: Some("artifact-store".to_string()),
        decision: None,
        reason: Some("publication requires approval".to_string()),
        policy_id: Some("approval_publish_high".to_string()),
        risk_level: Some("high".to_string()),
        issued_at: None,
        expires_at: Some(timestamp + time::Duration::hours(1)),
        revoked: false,
    };
    let verification = VerificationResult {
        allowed: true,
        reasons: Vec::new(),
        artifacts: serde_json::json!({
            "context": {
                "tenant_id": tenant_id.to_string(),
                "agent_id": agent_id.to_string(),
                "run_id": run_id.to_string(),
                "action_id": action_id.to_string(),
                "action": action.name,
                "adapter": "artifact-store"
            },
            "verifier_results": [
                {"verifier": "approval", "allowed": true, "reason": "approval_granted"}
            ],
            "credential": {"bearer_token": "raw-token-value"}
        }),
    };
    let events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            timestamp,
            TraceEventKind::WorkOrderAccepted {
                work_order_id: splendor_types::WorkOrderId::try_new("wo_audit")
                    .expect("work order id"),
                tenant_id: tenant_id.clone(),
                agent_id: agent_id.clone(),
                run_id: Some(run_id.clone()),
            },
        ),
        TraceEvent::try_new_with_identity(
            scoped_identity.clone(),
            1,
            timestamp,
            TraceEventKind::PolicyBundleAccepted {
                bundle: splendor_types::PolicyBundleTraceContext {
                    policy_bundle_id: splendor_types::PolicyBundleId::try_new(
                        "policy_bundle_finance",
                    )
                    .expect("policy id"),
                    version: "policy-v7".to_string(),
                    tenant_id: tenant_id.clone(),
                    agent_id: Some(agent_id.clone()),
                    expires_at: timestamp + time::Duration::hours(1),
                    degraded_mode: splendor_types::PolicyDegradedMode::default(),
                },
            },
        )
        .expect("policy identity"),
        TraceEvent::try_new_with_identity(
            scoped_identity.clone(),
            2,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        )
        .expect("tick start identity"),
        TraceEvent::new(
            run_id.clone(),
            3,
            timestamp,
            TraceEventKind::ApprovalRequested {
                approval: approval.clone(),
            },
        ),
        TraceEvent::try_new_with_identity(
            action_identity.clone(),
            4,
            timestamp,
            TraceEventKind::ActionVerificationCompleted {
                action: action.clone(),
                result: verification.clone(),
            },
        )
        .expect("verification identity"),
        TraceEvent::new(
            run_id.clone(),
            5,
            timestamp,
            TraceEventKind::ApprovalGranted {
                approval: ApprovalTraceContext {
                    decision: Some(ApprovalDecision::Granted),
                    reason: Some("approved by CFO".to_string()),
                    issued_at: Some(timestamp),
                    ..approval
                },
            },
        ),
        TraceEvent::try_new_with_identity(
            action_identity,
            6,
            timestamp,
            TraceEventKind::ActionExecuted {
                action,
                outcome: serde_json::json!({
                    "published": true,
                    "publication_token": "raw-token-value"
                }),
            },
        )
        .expect("executed identity"),
        TraceEvent::try_new_with_identity(
            state_identity,
            7,
            timestamp,
            TraceEventKind::StateCommitted {
                state_hash: state_node_id.hash().clone(),
                snapshot_id: Some(snapshot_id),
            },
        )
        .expect("state identity"),
        TraceEvent::try_new_with_identity(
            scoped_identity,
            8,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        )
        .expect("tick completed identity"),
    ];
    for event in events {
        TraceStore::append(
            &trace_store,
            &run_id.to_string(),
            serde_json::to_value(event).unwrap(),
        )
        .expect("append");
    }

    audit_export(
        &trace_temp.path().to_path_buf(),
        &state_temp.path().to_path_buf(),
        &run_id.to_string(),
        AuditFilters::default(),
    )
    .expect("audit export command");
    run_with_args(vec![
        "audit".to_string(),
        "export".to_string(),
        "--db".to_string(),
        trace_temp.path().display().to_string(),
        "--state-db".to_string(),
        state_temp.path().display().to_string(),
        "--run".to_string(),
        run_id.to_string(),
    ])
    .expect("audit export through command parser");

    let export = audit_export_from_stores(
        &trace_temp.path().to_path_buf(),
        &state_temp.path().to_path_buf(),
        &run_id.to_string(),
        AuditFilters::default(),
    )
    .expect("audit export");
    let value = serde_json::to_value(&export).expect("audit json");
    assert_eq!(value["schema_version"], "splendor.audit_export.v0.04-dev");
    assert_eq!(value["side_effects_replayed"].as_bool(), Some(false));
    assert_eq!(value["work_orders"][0]["work_order_id"], "wo_audit");
    assert_eq!(value["policies"][0]["version"], "policy-v7");
    assert_eq!(value["actions"][0]["status"], "executed");
    assert_eq!(value["actions"][0]["adapter"], "artifact-store");
    assert_eq!(
        value["actions"][0]["verification_result"]["artifacts"]["verifier_results"][0]["verifier"],
        "approval"
    );
    assert_eq!(
        value["state_nodes"][0]["state_node_id"],
        state_node_id.to_string()
    );
    assert_eq!(value["trace_range"]["first_sequence"].as_u64(), Some(0));
    assert_eq!(value["trace_range"]["last_sequence"].as_u64(), Some(8));
    let encoded = serde_json::to_string(&value).expect("encoded audit");
    assert!(!encoded.contains("raw-token-value"));
    assert!(!encoded.contains("super-secret"));
    assert!(value["redaction"]["applied"].as_bool().unwrap());

    let filtered = audit_export_from_stores(
        &trace_temp.path().to_path_buf(),
        &state_temp.path().to_path_buf(),
        &run_id.to_string(),
        AuditFilters {
            tenant: Some(tenant_id.to_string()),
            agent: Some(agent_id.to_string()),
            action: Some(action_id.to_string()),
            adapter: Some("artifact-store".to_string()),
            node: Some(node_id.to_string()),
            instance: Some(instance_id.to_string()),
            fleet: Some(fleet_id.to_string()),
            run: None,
        },
    )
    .expect("filtered audit export");
    let filtered_value = serde_json::to_value(&filtered).expect("filtered json");
    assert_eq!(filtered_value["event_count"].as_u64(), Some(2));
    assert_eq!(filtered_value["actions"].as_array().unwrap().len(), 1);
    assert_eq!(
        filtered_value["actions"][0]["action_name"],
        "artifact.publish"
    );
}

#[test]
fn audit_export_covers_governance_event_matrix_and_filter_helpers() {
    let state_temp = NamedTempFile::new().expect("state db");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let run_id = fixed_run_id(0x160);
    let tenant_id = TenantId::from(Uuid::from_u128(0x260));
    let agent_id = fixed_agent_id(0x261);
    let action_id = fixed_action_id(0x360);
    let approval_id = fixed_approval_id(0x460);
    let timestamp = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(3);
    let action = Action {
        name: "write_file".to_string(),
        params: serde_json::json!({
            "path": "audit.txt",
            "password": "do-not-export",
            "privateKey": "raw-private-key",
            "note": "raw-note-token"
        }),
        side_effect_class: SideEffectClass::Filesystem,
        cost_estimate: None,
        required_permissions: vec!["fs.write".to_string()],
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    };
    let action_identity = TraceIdentityContext::new(run_id.clone())
        .with_tenant_agent(tenant_id.clone(), agent_id.clone())
        .with_tick_id(TickId::from(1))
        .with_action_id(action_id.clone());
    let approval = ApprovalTraceContext {
        approval_id: approval_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: run_id.clone(),
        action_id: Some(action_id.clone()),
        action_name: action.name.clone(),
        adapter: Some("filesystem".to_string()),
        decision: None,
        reason: Some("operator approval required".to_string()),
        policy_id: Some("approval_filesystem".to_string()),
        risk_level: Some("medium".to_string()),
        issued_at: None,
        expires_at: Some(timestamp + time::Duration::hours(1)),
        revoked: false,
    };
    let verification = VerificationResult {
        allowed: false,
        reasons: vec!["approval_required".to_string()],
        artifacts: serde_json::json!({
            "requested": "filesystem",
            "context": {
                "tenant_id": tenant_id.to_string(),
                "agent_id": agent_id.to_string(),
                "run_id": run_id.to_string(),
                "action_id": action_id.to_string(),
                "action": action.name,
                "adapter": "filesystem"
            },
            "authorization": "Bearer raw-secret"
        }),
    };
    let denied_result = VerificationResult {
        allowed: false,
        reasons: vec!["policy_denied".to_string()],
        artifacts: serde_json::json!({"context": {"adapter": "filesystem"}}),
    };
    let intervention_result = VerificationResult {
        allowed: false,
        reasons: vec!["needs_operator".to_string()],
        artifacts: serde_json::json!({"context": {"adapter": "filesystem"}}),
    };
    let failed_result = VerificationResult {
        allowed: true,
        reasons: Vec::new(),
        artifacts: serde_json::json!({"context": {"adapter": "filesystem"}}),
    };

    let state_ref = StateStore::put_state(
        &state_store,
        StateData {
            bytes: b"audit-matrix".to_vec(),
            content_type: None,
        },
    )
    .expect("put state");
    let state_node = StateStore::commit_node(
        &state_store,
        Vec::new(),
        state_ref,
        StateMetadata {
            created_at: timestamp,
            label: Some("raw-state-token".to_string()),
            tenant_id: Some(tenant_id.clone()),
            agent_id: Some(agent_id.clone()),
            run_id: Some(run_id.clone()),
            trace_event_id: Some(TraceEventId::from_run_sequence(&run_id, 11)),
        },
    )
    .expect("commit state");
    let snapshot_id = StateStore::snapshot(&state_store, &state_node).expect("snapshot");

    let policy_id =
        splendor_types::PolicyBundleId::try_new("policy_matrix").expect("policy bundle id");
    let breaker_context = splendor_types::CircuitBreakerTraceContext::try_new(
        fixed_circuit_breaker_id(0x461),
        splendor_types::CircuitBreakerScope::Adapter("filesystem".to_string()),
        CircuitBreakerState::Tripped,
        "filesystem outage",
        "operator:test",
        timestamp,
    )
    .expect("breaker tripped context");
    let breaker_cleared = splendor_types::CircuitBreakerTraceContext::try_new(
        fixed_circuit_breaker_id(0x462),
        splendor_types::CircuitBreakerScope::Adapter("filesystem".to_string()),
        CircuitBreakerState::Cleared,
        "filesystem restored",
        "operator:test",
        timestamp,
    )
    .expect("breaker cleared context");
    let escalation = EscalationContext {
        trigger: EscalationTrigger::VerifierUncertainty,
        threshold: 1,
        observed_count: 1,
        scope: EscalationScope::Action,
        decision: EscalationDecision::Pause,
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: run_id.clone(),
        action_id: Some(action_id.clone()),
        action_name: Some("write_file".to_string()),
        adapter: Some("filesystem".to_string()),
        reason: "verifier unavailable".to_string(),
        evidence: serde_json::json!({"source": "unit-test"}),
        decided_at: timestamp,
    };

    let action_scope = GovernanceScope::Action {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: run_id.clone(),
        action_id: action_id.clone(),
    };
    let run_scope = GovernanceScope::Run {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: run_id.clone(),
    };
    let adapter_scope = GovernanceScope::Adapter {
        tenant_id: Some(tenant_id.clone()),
        adapter: "filesystem".to_string(),
    };
    let approval_ref = GovernanceObjectRef::Approval {
        approval_id: fixed_approval_id(0x470),
    };
    let escalation_ref = GovernanceObjectRef::Escalation {
        escalation_id: fixed_escalation_id(0x471),
    };
    let intervention_ref = GovernanceObjectRef::Intervention {
        intervention_id: fixed_intervention_id(0x472),
    };
    let breaker_ref = GovernanceObjectRef::CircuitBreaker {
        circuit_breaker_id: fixed_circuit_breaker_id(0x473),
    };
    let kill_ref = GovernanceObjectRef::KillSwitch {
        kill_switch_id: fixed_kill_switch_id(0x474),
    };

    let mut events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            timestamp,
            TraceEventKind::WorkOrderRejected {
                work_order_id: Some(
                    splendor_types::WorkOrderId::try_new("wo_rejected").expect("work order id"),
                ),
                tenant_id: Some(tenant_id.clone()),
                agent_id: Some(agent_id.clone()),
                run_id: Some(run_id.clone()),
                reason: "authorization=Bearer raw-work-order-secret".to_string(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            timestamp,
            TraceEventKind::PolicyBundleRejected {
                policy_bundle_id: Some(policy_id.clone()),
                version: Some("v1".to_string()),
                reason: "signature=raw-policy-signature".to_string(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            2,
            timestamp,
            TraceEventKind::PolicySyncFailed {
                policy_bundle_id: Some(policy_id.clone()),
                version: Some("v2".to_string()),
                reason: "token=raw-sync-token".to_string(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            3,
            timestamp,
            TraceEventKind::PolicyExpired {
                policy_bundle_id: policy_id.clone(),
                version: "v3".to_string(),
                action: Some("write_file".to_string()),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            4,
            timestamp,
            TraceEventKind::PolicyRevoked {
                policy_bundle_id: policy_id,
                version: "v4".to_string(),
                reason: "secret=raw-revocation-secret".to_string(),
            },
        ),
        TraceEvent::try_new_with_identity(
            action_identity.clone(),
            5,
            timestamp,
            TraceEventKind::ActionVerificationCompleted {
                action: action.clone(),
                result: verification.clone(),
            },
        )
        .expect("verification identity"),
        TraceEvent::try_new_with_identity(
            action_identity.clone(),
            6,
            timestamp,
            TraceEventKind::ActionNeedsApproval {
                action: action.clone(),
                result: verification.clone(),
            },
        )
        .expect("needs approval identity"),
        TraceEvent::try_new_with_identity(
            action_identity.clone(),
            7,
            timestamp,
            TraceEventKind::ActionDenied {
                action: action.clone(),
                result: denied_result.clone(),
            },
        )
        .expect("denied identity"),
        TraceEvent::try_new_with_identity(
            action_identity.clone(),
            8,
            timestamp,
            TraceEventKind::ActionNeedsIntervention {
                action: action.clone(),
                result: intervention_result.clone(),
            },
        )
        .expect("intervention identity"),
        TraceEvent::try_new_with_identity(
            action_identity.clone(),
            9,
            timestamp,
            TraceEventKind::ActionFailed {
                action: action.clone(),
                error: "Bearer raw-error-token".to_string(),
                result: failed_result.clone(),
            },
        )
        .expect("failed identity"),
        TraceEvent::new(
            run_id.clone(),
            10,
            timestamp,
            TraceEventKind::StateCommitted {
                state_hash: state_node.hash().clone(),
                snapshot_id: Some(snapshot_id),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            11,
            timestamp,
            TraceEventKind::StateCommitted {
                state_hash: ContentHash::blake3(b"metadata-less-state"),
                snapshot_id: None,
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            12,
            timestamp,
            TraceEventKind::ApprovalDenied {
                approval: ApprovalTraceContext {
                    decision: Some(ApprovalDecision::Denied),
                    reason: Some("token=raw-approval-token".to_string()),
                    issued_at: Some(timestamp),
                    ..approval.clone()
                },
                reason: "token=raw-approval-token".to_string(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            13,
            timestamp,
            TraceEventKind::ApprovalExpired {
                approval: approval.clone(),
                reason: "approval expired".to_string(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            14,
            timestamp,
            TraceEventKind::ApprovalRevoked {
                approval: approval.clone(),
                reason: "approval revoked".to_string(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            15,
            timestamp,
            TraceEventKind::RunPaused {
                reason: Some("waiting for approval".to_string()),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            16,
            timestamp,
            TraceEventKind::RunResumed {
                reason: Some("approval granted".to_string()),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            17,
            timestamp,
            TraceEventKind::EscalationTriggered { escalation },
        ),
        TraceEvent::new(
            run_id.clone(),
            18,
            timestamp,
            TraceEventKind::CircuitBreakerTripped {
                breaker: breaker_context,
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            19,
            timestamp,
            TraceEventKind::CircuitBreakerCleared {
                breaker: breaker_cleared,
            },
        ),
    ];

    let transition_kinds = vec![
        TraceEventKind::GovernanceApprovalRequested {
            transition: governance_transition(
                approval_ref.clone(),
                action_scope.clone(),
                None,
                GovernanceState::Requested,
                &run_id,
                20,
            ),
        },
        TraceEventKind::GovernanceApprovalGranted {
            transition: governance_transition(
                approval_ref.clone(),
                action_scope.clone(),
                Some(GovernanceState::Requested),
                GovernanceState::Granted,
                &run_id,
                21,
            ),
        },
        TraceEventKind::GovernanceApprovalDenied {
            transition: governance_transition(
                approval_ref.clone(),
                action_scope.clone(),
                Some(GovernanceState::Requested),
                GovernanceState::Denied,
                &run_id,
                22,
            ),
        },
        TraceEventKind::GovernanceApprovalExpired {
            transition: governance_transition(
                approval_ref.clone(),
                action_scope.clone(),
                Some(GovernanceState::Requested),
                GovernanceState::Expired,
                &run_id,
                23,
            ),
        },
        TraceEventKind::GovernanceApprovalRevoked {
            transition: governance_transition(
                approval_ref,
                action_scope,
                Some(GovernanceState::Requested),
                GovernanceState::Revoked,
                &run_id,
                24,
            ),
        },
        TraceEventKind::EscalationOpened {
            transition: governance_transition(
                escalation_ref.clone(),
                run_scope.clone(),
                None,
                GovernanceState::Open,
                &run_id,
                25,
            ),
        },
        TraceEventKind::EscalationResolved {
            transition: governance_transition(
                escalation_ref.clone(),
                run_scope.clone(),
                Some(GovernanceState::Open),
                GovernanceState::Resolved,
                &run_id,
                26,
            ),
        },
        TraceEventKind::EscalationExpired {
            transition: governance_transition(
                escalation_ref.clone(),
                run_scope.clone(),
                Some(GovernanceState::Open),
                GovernanceState::Expired,
                &run_id,
                27,
            ),
        },
        TraceEventKind::EscalationRevoked {
            transition: governance_transition(
                escalation_ref,
                run_scope.clone(),
                Some(GovernanceState::Open),
                GovernanceState::Revoked,
                &run_id,
                28,
            ),
        },
        TraceEventKind::InterventionRequested {
            transition: governance_transition(
                intervention_ref.clone(),
                run_scope.clone(),
                None,
                GovernanceState::Requested,
                &run_id,
                29,
            ),
        },
        TraceEventKind::InterventionResolved {
            transition: governance_transition(
                intervention_ref.clone(),
                run_scope.clone(),
                Some(GovernanceState::Requested),
                GovernanceState::Resolved,
                &run_id,
                30,
            ),
        },
        TraceEventKind::InterventionCancelled {
            transition: governance_transition(
                intervention_ref.clone(),
                run_scope.clone(),
                Some(GovernanceState::Requested),
                GovernanceState::Cancelled,
                &run_id,
                31,
            ),
        },
        TraceEventKind::InterventionExpired {
            transition: governance_transition(
                intervention_ref.clone(),
                run_scope.clone(),
                Some(GovernanceState::Requested),
                GovernanceState::Expired,
                &run_id,
                32,
            ),
        },
        TraceEventKind::InterventionRevoked {
            transition: governance_transition(
                intervention_ref,
                run_scope,
                Some(GovernanceState::Requested),
                GovernanceState::Revoked,
                &run_id,
                33,
            ),
        },
        TraceEventKind::GovernanceCircuitBreakerTripped {
            transition: governance_transition(
                breaker_ref.clone(),
                adapter_scope.clone(),
                None,
                GovernanceState::Active,
                &run_id,
                34,
            ),
        },
        TraceEventKind::GovernanceCircuitBreakerCleared {
            transition: governance_transition(
                breaker_ref.clone(),
                adapter_scope.clone(),
                Some(GovernanceState::Active),
                GovernanceState::Cleared,
                &run_id,
                35,
            ),
        },
        TraceEventKind::GovernanceCircuitBreakerExpired {
            transition: governance_transition(
                breaker_ref.clone(),
                adapter_scope.clone(),
                Some(GovernanceState::Active),
                GovernanceState::Expired,
                &run_id,
                36,
            ),
        },
        TraceEventKind::GovernanceCircuitBreakerRevoked {
            transition: governance_transition(
                breaker_ref,
                adapter_scope.clone(),
                Some(GovernanceState::Active),
                GovernanceState::Revoked,
                &run_id,
                37,
            ),
        },
        TraceEventKind::KillSwitchActivated {
            transition: governance_transition(
                kill_ref.clone(),
                adapter_scope.clone(),
                None,
                GovernanceState::Active,
                &run_id,
                38,
            ),
        },
        TraceEventKind::KillSwitchCleared {
            transition: governance_transition(
                kill_ref.clone(),
                adapter_scope.clone(),
                Some(GovernanceState::Active),
                GovernanceState::Cleared,
                &run_id,
                39,
            ),
        },
        TraceEventKind::KillSwitchExpired {
            transition: governance_transition(
                kill_ref.clone(),
                adapter_scope.clone(),
                Some(GovernanceState::Active),
                GovernanceState::Expired,
                &run_id,
                40,
            ),
        },
        TraceEventKind::KillSwitchRevoked {
            transition: governance_transition(
                kill_ref.clone(),
                adapter_scope.clone(),
                Some(GovernanceState::Active),
                GovernanceState::Revoked,
                &run_id,
                41,
            ),
        },
        TraceEventKind::GovernanceTransitionRejected {
            rejection: GovernanceTransitionRejection {
                schema_version: splendor_types::GOVERNANCE_STATE_SCHEMA_VERSION.to_string(),
                object: kill_ref,
                scope: adapter_scope,
                from: Some(GovernanceState::Revoked),
                attempted: GovernanceState::Active,
                reason: "invalid_governance_transition".to_string(),
                rejected_at: timestamp,
                issuer: GovernanceIssuer::new("operator:test", "unit-test").expect("issuer"),
                trace: GovernanceTraceLink::new(
                    TraceEventId::from_run_sequence(&run_id, 42),
                    Some(run_id.clone()),
                ),
            },
        },
    ];
    for (index, kind) in transition_kinds.into_iter().enumerate() {
        events.push(TraceEvent::new(
            run_id.clone(),
            20 + index as u64,
            timestamp,
            kind,
        ));
    }

    let export = collect_audit_export(
        &events,
        &state_store,
        &run_id.to_string(),
        AuditFilters::default(),
    )
    .expect("audit export");
    let value = serde_json::to_value(&export).expect("audit json");
    assert_eq!(value["work_orders"].as_array().unwrap().len(), 1);
    assert_eq!(value["policies"].as_array().unwrap().len(), 4);
    assert_eq!(value["actions"].as_array().unwrap().len(), 4);
    assert_eq!(value["state_nodes"].as_array().unwrap().len(), 2);
    assert_eq!(
        value["state_nodes"][0]["state_node_id"],
        state_node.to_string()
    );

    let governance_names = value["governance_events"]
        .as_array()
        .expect("governance events")
        .iter()
        .map(|event| event["event"].as_str().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    for expected in [
        "approval.denied",
        "approval.expired",
        "approval.revoked",
        "run.paused",
        "run.resumed",
        "action.denied",
        "action.needs_approval",
        "action.needs_intervention",
        "escalation.triggered",
        "circuit_breaker.tripped",
        "circuit_breaker.cleared",
        "governance.approval.requested",
        "governance.approval.granted",
        "governance.approval.denied",
        "governance.approval.expired",
        "governance.approval.revoked",
        "governance.escalation.opened",
        "governance.escalation.resolved",
        "governance.escalation.expired",
        "governance.escalation.revoked",
        "governance.intervention.requested",
        "governance.intervention.resolved",
        "governance.intervention.cancelled",
        "governance.intervention.expired",
        "governance.intervention.revoked",
        "governance.circuit_breaker.tripped",
        "governance.circuit_breaker.cleared",
        "governance.circuit_breaker.expired",
        "governance.circuit_breaker.revoked",
        "governance.kill_switch.activated",
        "governance.kill_switch.cleared",
        "governance.kill_switch.expired",
        "governance.kill_switch.revoked",
        "governance.transition.rejected",
    ] {
        assert!(governance_names.contains(expected), "missing {expected}");
    }
    let encoded = serde_json::to_string(&value).expect("encoded audit");
    assert!(!encoded.contains("do-not-export"));
    assert!(!encoded.contains("raw-secret"));
    assert!(!encoded.contains("raw-private-key"));
    assert!(!encoded.contains("raw-note-token"));
    assert!(!encoded.contains("raw-work-order-secret"));
    assert!(!encoded.contains("raw-policy-signature"));
    assert!(!encoded.contains("raw-sync-token"));
    assert!(!encoded.contains("raw-revocation-secret"));
    assert!(!encoded.contains("raw-error-token"));
    assert!(!encoded.contains("raw-state-token"));
    assert!(!encoded.contains("raw-approval-token"));

    let adapter_by_action = audit_adapter_index(&events);
    assert!(AuditFilters {
        tenant: Some(tenant_id.to_string()),
        ..AuditFilters::default()
    }
    .matches(&events[5], &adapter_by_action));
    assert!(AuditFilters {
        agent: Some(agent_id.to_string()),
        ..AuditFilters::default()
    }
    .matches(&events[5], &adapter_by_action));
    assert!(AuditFilters {
        action: Some(action_id.to_string()),
        ..AuditFilters::default()
    }
    .matches(&events[12], &adapter_by_action));
    assert!(AuditFilters {
        adapter: Some("filesystem".to_string()),
        ..AuditFilters::default()
    }
    .matches(&events[13], &adapter_by_action));
    assert!(!AuditFilters {
        run: Some("other-run".to_string()),
        ..AuditFilters::default()
    }
    .matches(&events[0], &adapter_by_action));
    assert!(!AuditFilters {
        tenant: Some("other-tenant".to_string()),
        ..AuditFilters::default()
    }
    .matches(&events[5], &adapter_by_action));
    assert!(!AuditFilters {
        agent: Some("other-agent".to_string()),
        ..AuditFilters::default()
    }
    .matches(&events[5], &adapter_by_action));
    assert!(!AuditFilters {
        adapter: Some("http".to_string()),
        ..AuditFilters::default()
    }
    .matches(&events[7], &adapter_by_action));
    assert!(!AuditFilters {
        node: Some("missing-node".to_string()),
        ..AuditFilters::default()
    }
    .matches(&events[0], &adapter_by_action));
    assert!(!AuditFilters {
        instance: Some("missing-instance".to_string()),
        ..AuditFilters::default()
    }
    .matches(&events[0], &adapter_by_action));
    assert!(!AuditFilters {
        fleet: Some("missing-fleet".to_string()),
        ..AuditFilters::default()
    }
    .matches(&events[0], &adapter_by_action));

    let started = TraceEvent::new(
        run_id.clone(),
        90,
        timestamp,
        TraceEventKind::ActionVerificationStarted {
            action: action.clone(),
        },
    );
    assert!(action_for_event(&started).is_some());
    assert_eq!(audit_action_key(&started, &action), "action:write_file");
    assert_eq!(
        adapter_from_action_name("http.fetch").as_deref(),
        Some("http")
    );
    assert!(adapter_from_action_name("unknown.action").is_none());
    let fallback_event = TraceEvent::new(
        run_id.clone(),
        91,
        timestamp,
        TraceEventKind::ActionExecuted {
            action: action.clone(),
            outcome: serde_json::json!({}),
        },
    );
    assert!(AuditFilters {
        adapter: Some("filesystem".to_string()),
        ..AuditFilters::default()
    }
    .matches(&fallback_event, &BTreeMap::new()));
    let revoked_event = TraceEvent::new(
        run_id,
        92,
        timestamp,
        TraceEventKind::ApprovalRevoked {
            approval,
            reason: "revoked".to_string(),
        },
    );
    assert_eq!(
        replay_approval_event(&revoked_event)
            .expect("approval validation")
            .expect("revoked approval replay")
            .lifecycle,
        "revoked"
    );
    assert!(!is_permission_laundering_denial(&VerificationResult {
        allowed: true,
        reasons: Vec::new(),
        artifacts: serde_json::json!({}),
    }));
}

#[test]
fn replay_rejects_message_context_run_mismatch() {
    let state_temp = NamedTempFile::new().expect("state db");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let event_run_id = fixed_run_id(0x110);
    let message_run_id = fixed_run_id(0x111);
    let context = message_context(
        fixed_message_id(0x310),
        fixed_agent_id(0x210),
        fixed_agent_id(0x211),
        message_run_id,
        0,
    );
    let event = TraceEvent::new(
        event_run_id.clone(),
        0,
        OffsetDateTime::UNIX_EPOCH,
        TraceEventKind::MessageQueued { message: context },
    );

    let error = collect_replay_outputs(
        &[event],
        &state_store,
        &event_run_id.to_string(),
        None,
        None,
        None,
        false,
    )
    .expect_err("run mismatch should fail");
    assert_eq!(error, "replay_message_run_mismatch");
}

#[test]
fn audit_filter_helpers_cover_governance_and_artifact_branches() {
    let run_id = fixed_run_id(0x180);
    let tenant_id: TenantId = Uuid::from_u128(0x181).into();
    let agent_id = fixed_agent_id(0x182);
    let action_id = fixed_action_id(0x183);
    let timestamp = OffsetDateTime::UNIX_EPOCH;
    let approval = ApprovalTraceContext {
        approval_id: ApprovalId::new(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: run_id.clone(),
        action_id: Some(action_id.clone()),
        action_name: "artifact.publish".to_string(),
        adapter: Some("artifact-store".to_string()),
        decision: Some(ApprovalDecision::Denied),
        reason: Some("policy".to_string()),
        policy_id: Some("approval-policy".to_string()),
        risk_level: Some("high".to_string()),
        issued_at: Some(timestamp),
        expires_at: Some(timestamp + time::Duration::hours(1)),
        revoked: false,
    };
    let denied = TraceEvent::new(
        run_id.clone(),
        1,
        timestamp,
        TraceEventKind::ApprovalDenied {
            approval: approval.clone(),
            reason: "operator_denied".to_string(),
        },
    );
    assert!(event_has_tenant(&denied, &tenant_id.to_string()));
    assert!(event_has_agent(&denied, &agent_id.to_string()));
    assert!(event_has_action(&denied, &action_id.to_string()));
    assert!(event_has_action(&denied, "artifact.publish"));
    assert!(event_has_adapter(
        &denied,
        "artifact-store",
        &BTreeMap::new()
    ));

    let escalation = EscalationContext {
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: run_id.clone(),
        action_id: Some(action_id.clone()),
        action_name: Some("artifact.publish".to_string()),
        adapter: Some("artifact-store".to_string()),
        trigger: EscalationTrigger::RepeatedAdapterFailure,
        scope: EscalationScope::Action,
        decision: EscalationDecision::NeedsIntervention,
        reason: "failure threshold".to_string(),
        observed_count: 3,
        threshold: 3,
        evidence: serde_json::json!({"adapter":"artifact-store"}),
        decided_at: timestamp,
    };
    let escalation_event = TraceEvent::new(
        run_id.clone(),
        2,
        timestamp,
        TraceEventKind::EscalationTriggered { escalation },
    );
    assert!(event_has_action(&escalation_event, &action_id.to_string()));
    assert!(event_has_adapter(
        &escalation_event,
        "artifact-store",
        &BTreeMap::new()
    ));

    let breaker = splendor_types::CircuitBreakerTraceContext::try_new(
        CircuitBreakerId::try_new("cb_adapter").expect("breaker"),
        splendor_types::CircuitBreakerScope::Adapter("artifact-store".to_string()),
        CircuitBreakerState::Tripped,
        "adapter outage",
        "test",
        timestamp,
    )
    .expect("breaker context");
    let breaker_event = TraceEvent::new(
        run_id.clone(),
        3,
        timestamp,
        TraceEventKind::CircuitBreakerTripped { breaker },
    );
    assert!(event_has_adapter(
        &breaker_event,
        "artifact-store",
        &BTreeMap::new()
    ));

    let result = VerificationResult {
        allowed: false,
        reasons: vec!["adapter circuit breaker".to_string()],
        artifacts: serde_json::json!({
            "context": {
                "tenant_id": tenant_id.to_string(),
                "agent_id": agent_id.to_string(),
                "action_id": action_id.to_string(),
                "action": "artifact.publish",
                "adapter": "artifact-store"
            },
            "circuit_breaker": {
                "scope": "adapter",
                "scope_value": "artifact-store"
            }
        }),
    };
    let action = Action {
        name: "artifact.publish".to_string(),
        params: serde_json::json!({}),
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    };
    let result_event = TraceEvent::new(
        run_id.clone(),
        4,
        timestamp,
        TraceEventKind::ActionFailed {
            action,
            error: "adapter failed".to_string(),
            result,
        },
    );
    assert!(event_has_tenant(&result_event, &tenant_id.to_string()));
    assert!(event_has_agent(&result_event, &agent_id.to_string()));
    assert!(event_has_action(&result_event, &action_id.to_string()));
    assert!(event_has_action(&result_event, "artifact.publish"));
    assert!(event_has_adapter(
        &result_event,
        "artifact-store",
        &BTreeMap::new()
    ));

    let rejected = TraceEvent::new(
        run_id,
        5,
        timestamp,
        TraceEventKind::WorkOrderRejected {
            work_order_id: Some(
                splendor_types::WorkOrderId::try_new("wo_rejected").expect("work order id"),
            ),
            tenant_id: Some(tenant_id.clone()),
            agent_id: Some(agent_id.clone()),
            run_id: None,
            reason: "bad_signature".to_string(),
        },
    );
    assert!(event_has_tenant(&rejected, &tenant_id.to_string()));
    assert!(event_has_agent(&rejected, &agent_id.to_string()));
}

#[test]
fn replay_rejects_child_run_parent_mismatch() {
    let state_temp = NamedTempFile::new().expect("state db");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let event_run_id = fixed_run_id(0x120);
    let parent_run_id = fixed_run_id(0x121);
    let event = TraceEvent::new(
        event_run_id.clone(),
        0,
        OffsetDateTime::UNIX_EPOCH,
        TraceEventKind::ChildRunLinked {
            parent_run_id,
            child_run_id: fixed_run_id(0x122),
            parent_agent_id: fixed_agent_id(0x220),
            child_agent_id: fixed_agent_id(0x221),
            causal_parent: None,
            source_message_id: None,
        },
    );

    let error = collect_replay_outputs(
        &[event],
        &state_store,
        &event_run_id.to_string(),
        None,
        None,
        None,
        false,
    )
    .expect_err("parent mismatch should fail");
    assert_eq!(error, "replay_child_run_mismatch");
}

#[test]
fn replay_rejects_approval_context_run_mismatch() {
    let state_temp = NamedTempFile::new().expect("state db");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let event_run_id = fixed_run_id(0x142);
    let approval_run_id = fixed_run_id(0x143);
    let approval = ApprovalTraceContext {
        approval_id: fixed_approval_id(0x442),
        tenant_id: TenantId::from(Uuid::from_u128(0x244)),
        agent_id: fixed_agent_id(0x245),
        run_id: approval_run_id,
        action_id: Some(fixed_action_id(0x342)),
        action_name: "artifact.publish".to_string(),
        adapter: Some("artifact-store".to_string()),
        decision: None,
        reason: Some("approval required".to_string()),
        policy_id: Some("approval_publish_high".to_string()),
        risk_level: Some("high".to_string()),
        issued_at: None,
        expires_at: None,
        revoked: false,
    };
    let event = TraceEvent::new(
        event_run_id.clone(),
        0,
        OffsetDateTime::UNIX_EPOCH,
        TraceEventKind::ApprovalRequested { approval },
    );

    let error = collect_replay_outputs(
        &[event],
        &state_store,
        &event_run_id.to_string(),
        None,
        None,
        None,
        false,
    )
    .expect_err("approval run mismatch should fail");
    assert_eq!(error, "audit_trace_run_mismatch");
}

#[test]
fn audit_export_rejects_approval_context_run_mismatch() {
    let state_temp = NamedTempFile::new().expect("state db");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let event_run_id = fixed_run_id(0x144);
    let approval_run_id = fixed_run_id(0x145);
    let approval = ApprovalTraceContext {
        approval_id: fixed_approval_id(0x443),
        tenant_id: TenantId::from(Uuid::from_u128(0x246)),
        agent_id: fixed_agent_id(0x247),
        run_id: approval_run_id,
        action_id: None,
        action_name: "artifact.publish".to_string(),
        adapter: Some("artifact-store".to_string()),
        decision: None,
        reason: Some("approval required".to_string()),
        policy_id: Some("approval_publish_high".to_string()),
        risk_level: Some("high".to_string()),
        issued_at: None,
        expires_at: None,
        revoked: false,
    };
    let event = TraceEvent::new(
        event_run_id.clone(),
        0,
        OffsetDateTime::UNIX_EPOCH,
        TraceEventKind::ApprovalRequested { approval },
    );

    let error = collect_audit_export(
        &[event],
        &state_store,
        &event_run_id.to_string(),
        AuditFilters::default(),
    )
    .expect_err("approval run mismatch should fail");
    assert_eq!(error, "audit_trace_run_mismatch");
}

#[test]
fn replay_and_audit_reject_state_snapshot_hash_mismatch() {
    let state_temp = NamedTempFile::new().expect("state db");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let run_id = fixed_run_id(0x146);
    let state_ref = StateStore::put_state(
        &state_store,
        StateData {
            bytes: b"verified-state".to_vec(),
            content_type: None,
        },
    )
    .expect("put state");
    let state_node_id = StateStore::commit_node(
        &state_store,
        Vec::new(),
        state_ref,
        StateMetadata::new(OffsetDateTime::UNIX_EPOCH, Some("state".to_string())),
    )
    .expect("commit state");
    let snapshot_id = StateStore::snapshot(&state_store, &state_node_id).expect("snapshot");
    let events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            OffsetDateTime::UNIX_EPOCH,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            OffsetDateTime::UNIX_EPOCH,
            TraceEventKind::StateCommitted {
                state_hash: ContentHash::blake3(b"wrong-state-node"),
                snapshot_id: Some(snapshot_id),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            2,
            OffsetDateTime::UNIX_EPOCH,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        ),
    ];

    let replay_error = collect_replay_outputs(
        &events,
        &state_store,
        &run_id.to_string(),
        None,
        None,
        None,
        false,
    )
    .expect_err("state hash mismatch should fail replay");
    assert_eq!(replay_error, "state_commit_hash_mismatch");

    let audit_error = collect_audit_export(
        &events,
        &state_store,
        &run_id.to_string(),
        AuditFilters::default(),
    )
    .expect_err("state hash mismatch should fail audit");
    assert_eq!(audit_error, "state_commit_hash_mismatch");
}

#[test]
fn governance_replay_validation_helpers_cover_identity_and_state_paths() {
    let state_temp = NamedTempFile::new().expect("state db");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");
    let run_id = fixed_run_id(0x147);
    let other_run_id = fixed_run_id(0x148);
    let tenant_id = TenantId::from(Uuid::from_u128(0x248));
    let agent_id = fixed_agent_id(0x249);
    let action_id = fixed_action_id(0x343);
    let timestamp = OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(2);
    let state_ref = StateStore::put_state(
        &state_store,
        StateData {
            bytes: b"verified-state".to_vec(),
            content_type: None,
        },
    )
    .expect("put state");
    let state_node_id = StateStore::commit_node(
        &state_store,
        Vec::new(),
        state_ref,
        StateMetadata::new(timestamp, Some("verified".to_string())),
    )
    .expect("commit state");
    let snapshot_id = StateStore::snapshot(&state_store, &state_node_id).expect("snapshot");
    assert_eq!(
        load_verified_state_snapshot(&state_store, &snapshot_id, Some(state_node_id.hash()))
            .expect("verified snapshot")
            .node_id,
        state_node_id
    );
    assert_eq!(
        load_verified_state_node(&state_store, &state_node_id, Some(state_node_id.hash()))
            .expect("verified node")
            .id,
        state_node_id
    );
    let missing_snapshot_id = SnapshotId::from_bytes(b"missing-snapshot");
    assert_eq!(
        load_verified_state_snapshot(&state_store, &missing_snapshot_id, None)
            .expect_err("missing snapshot"),
        "state_snapshot_load_failed"
    );
    let missing_state_node =
        splendor_types::StateNodeId::from_hash(ContentHash::blake3(b"missing"));
    assert_eq!(
        load_verified_state_node(&state_store, &missing_state_node, None)
            .expect_err("missing state node"),
        "state_node_load_failed"
    );

    let approval = ApprovalTraceContext {
        approval_id: fixed_approval_id(0x444),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        run_id: run_id.clone(),
        action_id: Some(action_id.clone()),
        action_name: "artifact.publish".to_string(),
        adapter: Some("artifact-store".to_string()),
        decision: None,
        reason: Some("approval required".to_string()),
        policy_id: Some("approval_publish_high".to_string()),
        risk_level: Some("high".to_string()),
        issued_at: None,
        expires_at: None,
        revoked: false,
    };
    let identity = TraceIdentityContext::new(run_id.clone())
        .with_tenant_agent(tenant_id.clone(), agent_id.clone())
        .with_action_id(action_id.clone());
    let event = TraceEvent::try_new_with_identity(
        identity.clone(),
        0,
        timestamp,
        TraceEventKind::ApprovalRequested {
            approval: approval.clone(),
        },
    )
    .expect("approval event");
    validate_approval_trace_context(&event, &approval).expect("approval identity matches");
    validate_run_match(&event, &run_id, "Approval").expect("run matches");
    assert_eq!(
        validate_run_match(&event, &other_run_id, "Approval").expect_err("run mismatch"),
        "audit_trace_run_mismatch"
    );

    let tenant_mismatch = TraceEvent::try_new_with_identity(
        TraceIdentityContext::new(run_id.clone())
            .with_tenant_agent(TenantId::from(Uuid::from_u128(0x999)), agent_id.clone()),
        1,
        timestamp,
        TraceEventKind::ApprovalRequested {
            approval: approval.clone(),
        },
    )
    .expect("tenant mismatch event");
    assert_eq!(
        validate_approval_trace_context(&tenant_mismatch, &approval).expect_err("tenant mismatch"),
        "audit_approval_tenant_mismatch"
    );

    let agent_mismatch = TraceEvent::try_new_with_identity(
        TraceIdentityContext::new(run_id.clone())
            .with_tenant_agent(tenant_id.clone(), fixed_agent_id(0x998)),
        2,
        timestamp,
        TraceEventKind::ApprovalRequested {
            approval: approval.clone(),
        },
    )
    .expect("agent mismatch event");
    assert_eq!(
        validate_approval_trace_context(&agent_mismatch, &approval).expect_err("agent mismatch"),
        "audit_approval_agent_mismatch"
    );

    let action_mismatch = TraceEvent::try_new_with_identity(
        TraceIdentityContext::new(run_id.clone())
            .with_tenant_agent(tenant_id.clone(), agent_id.clone())
            .with_action_id(fixed_action_id(0x997)),
        3,
        timestamp,
        TraceEventKind::ApprovalRequested {
            approval: approval.clone(),
        },
    )
    .expect("action mismatch event");
    assert_eq!(
        validate_approval_trace_context(&action_mismatch, &approval).expect_err("action mismatch"),
        "audit_approval_action_mismatch"
    );

    let transition = governance_transition(
        GovernanceObjectRef::Approval {
            approval_id: fixed_approval_id(0x445),
        },
        GovernanceScope::Run {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: other_run_id.clone(),
        },
        None,
        GovernanceState::Requested,
        &other_run_id,
        4,
    );
    let transition_event = TraceEvent::new(
        run_id.clone(),
        4,
        timestamp,
        TraceEventKind::GovernanceApprovalRequested { transition },
    );
    assert_eq!(
        validate_governance_trace_context(&transition_event).expect_err("transition run mismatch"),
        "audit_trace_run_mismatch"
    );

    let scope_only_transition = splendor_types::GovernanceTransition {
        schema_version: splendor_types::GOVERNANCE_STATE_SCHEMA_VERSION.to_string(),
        object: GovernanceObjectRef::Approval {
            approval_id: fixed_approval_id(0x447),
        },
        scope: GovernanceScope::Run {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: other_run_id.clone(),
        },
        from: None,
        to: GovernanceState::Requested,
        occurred_at: timestamp,
        reason: "scope-only run mismatch".to_string(),
        issuer: GovernanceIssuer::new("operator:test", "unit-test").expect("issuer"),
        trace: GovernanceTraceLink::new(TraceEventId::from_run_sequence(&run_id, 6), None),
        extensions: Default::default(),
    };
    let scope_only_event = TraceEvent::new(
        run_id.clone(),
        6,
        timestamp,
        TraceEventKind::GovernanceApprovalRequested {
            transition: scope_only_transition,
        },
    );
    assert_eq!(
        validate_governance_trace_context(&scope_only_event).expect_err("scope run mismatch"),
        "audit_trace_run_mismatch"
    );

    let tenant_scope_mismatch = splendor_types::GovernanceTransition {
        schema_version: splendor_types::GOVERNANCE_STATE_SCHEMA_VERSION.to_string(),
        object: GovernanceObjectRef::Approval {
            approval_id: fixed_approval_id(0x449),
        },
        scope: GovernanceScope::Tenant {
            tenant_id: TenantId::from(Uuid::from_u128(0x995)),
        },
        from: None,
        to: GovernanceState::Requested,
        occurred_at: timestamp,
        reason: "tenant mismatch".to_string(),
        issuer: GovernanceIssuer::new("operator:test", "unit-test").expect("issuer"),
        trace: GovernanceTraceLink::new(TraceEventId::from_run_sequence(&run_id, 8), None),
        extensions: Default::default(),
    };
    let tenant_scope_event = TraceEvent::try_new_with_identity(
        TraceIdentityContext::new(run_id.clone())
            .with_tenant_agent(tenant_id.clone(), agent_id.clone()),
        8,
        timestamp,
        TraceEventKind::GovernanceApprovalRequested {
            transition: tenant_scope_mismatch,
        },
    )
    .expect("tenant scope event");
    assert_eq!(
        validate_governance_trace_context(&tenant_scope_event).expect_err("scope tenant mismatch"),
        "audit_governance_tenant_mismatch"
    );

    let agent_scope_mismatch = splendor_types::GovernanceTransition {
        schema_version: splendor_types::GOVERNANCE_STATE_SCHEMA_VERSION.to_string(),
        object: GovernanceObjectRef::Approval {
            approval_id: fixed_approval_id(0x450),
        },
        scope: GovernanceScope::Agent {
            tenant_id: tenant_id.clone(),
            agent_id: fixed_agent_id(0x994),
        },
        from: None,
        to: GovernanceState::Requested,
        occurred_at: timestamp,
        reason: "agent mismatch".to_string(),
        issuer: GovernanceIssuer::new("operator:test", "unit-test").expect("issuer"),
        trace: GovernanceTraceLink::new(TraceEventId::from_run_sequence(&run_id, 9), None),
        extensions: Default::default(),
    };
    let agent_scope_event = TraceEvent::try_new_with_identity(
        TraceIdentityContext::new(run_id.clone())
            .with_tenant_agent(tenant_id.clone(), agent_id.clone()),
        9,
        timestamp,
        TraceEventKind::GovernanceApprovalRequested {
            transition: agent_scope_mismatch,
        },
    )
    .expect("agent scope event");
    assert_eq!(
        validate_governance_trace_context(&agent_scope_event).expect_err("scope agent mismatch"),
        "audit_governance_agent_mismatch"
    );

    let action_scope_mismatch = splendor_types::GovernanceTransition {
        schema_version: splendor_types::GOVERNANCE_STATE_SCHEMA_VERSION.to_string(),
        object: GovernanceObjectRef::Approval {
            approval_id: fixed_approval_id(0x448),
        },
        scope: GovernanceScope::Action {
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            run_id: run_id.clone(),
            action_id: fixed_action_id(0x996),
        },
        from: None,
        to: GovernanceState::Requested,
        occurred_at: timestamp,
        reason: "action mismatch".to_string(),
        issuer: GovernanceIssuer::new("operator:test", "unit-test").expect("issuer"),
        trace: GovernanceTraceLink::new(
            TraceEventId::from_run_sequence(&run_id, 7),
            Some(run_id.clone()),
        ),
        extensions: Default::default(),
    };
    let action_scope_event = TraceEvent::try_new_with_identity(
        identity,
        7,
        timestamp,
        TraceEventKind::GovernanceApprovalRequested {
            transition: action_scope_mismatch,
        },
    )
    .expect("action scope event");
    assert_eq!(
        validate_governance_trace_context(&action_scope_event).expect_err("scope action mismatch"),
        "audit_governance_action_mismatch"
    );

    let rejection = GovernanceTransitionRejection {
        schema_version: splendor_types::GOVERNANCE_STATE_SCHEMA_VERSION.to_string(),
        object: GovernanceObjectRef::KillSwitch {
            kill_switch_id: fixed_kill_switch_id(0x446),
        },
        scope: GovernanceScope::Run {
            tenant_id,
            agent_id,
            run_id: other_run_id.clone(),
        },
        from: None,
        attempted: GovernanceState::Active,
        reason: "invalid_governance_transition".to_string(),
        rejected_at: timestamp,
        issuer: GovernanceIssuer::new("operator:test", "unit-test").expect("issuer"),
        trace: GovernanceTraceLink::new(TraceEventId::from_run_sequence(&other_run_id, 5), None),
    };
    let rejection_event = TraceEvent::new(
        run_id,
        5,
        timestamp,
        TraceEventKind::GovernanceTransitionRejected { rejection },
    );
    assert_eq!(
        validate_governance_trace_context(&rejection_event).expect_err("rejection run mismatch"),
        "audit_trace_run_mismatch"
    );
}

#[test]
fn trace_store_preserves_payload_sequence_and_replay_rejects_envelope_mismatch() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let trace_store = SqliteTraceStore::open(trace_temp.path()).expect("trace store");

    let run_id = RunId::new();
    let event = TraceEvent::new(
        run_id.clone(),
        9,
        OffsetDateTime::now_utc(),
        TraceEventKind::LoopTickStarted { tick_id: 1 },
    );
    let sequence = TraceStore::append(
        &trace_store,
        &run_id.to_string(),
        serde_json::to_value(event).unwrap(),
    )
    .expect("generic store must not reserve application payload keys");
    assert_eq!(sequence, 0);
    let records = trace_store
        .read(&run_id.to_string())
        .expect("opaque trace payload");
    assert_eq!(records[0].payload["sequence"], 9);

    let error = decode_and_validate_trace_records(&records, &run_id.to_string())
        .expect_err("replay must reject the mismatched trace envelope");
    assert_eq!(error, "trace_compatibility_envelope_failure");
}

#[test]
fn decode_trace_records_rejects_record_run_mismatch() {
    let run_id = RunId::new();
    let mut records = valid_trace_records_for(&run_id);
    records[0].run_id = RunId::new().to_string();

    let error =
        decode_and_validate_trace_records(&records, &run_id.to_string()).expect_err("run mismatch");
    assert_eq!(error, "trace_compatibility_integrity_failure");
}

#[test]
fn decode_trace_records_rejects_record_sequence_gap() {
    let run_id = RunId::new();
    let mut records = valid_trace_records_for(&run_id);
    records[1].sequence = 7;

    let error =
        decode_and_validate_trace_records(&records, &run_id.to_string()).expect_err("sequence gap");
    assert_eq!(error, "trace_compatibility_integrity_failure");
}

#[test]
fn decode_trace_records_rejects_prev_hash_mismatch() {
    let run_id = RunId::new();
    let mut records = valid_trace_records_for(&run_id);
    records[1].prev_event_hash = Some(ContentHash::blake3(b"wrong-previous-event"));

    let error = decode_and_validate_trace_records(&records, &run_id.to_string())
        .expect_err("prev hash mismatch");
    assert_eq!(error, "trace_compatibility_integrity_failure");
}

#[test]
fn decode_trace_records_rejects_payload_hash_mismatch() {
    let run_id = RunId::new();
    let mut records = valid_trace_records_for(&run_id);
    let event = TraceEvent::new(
        run_id.clone(),
        0,
        OffsetDateTime::now_utc(),
        TraceEventKind::PolicyInvoked {
            policy: "tampered-policy".to_string(),
        },
    );
    records[0].payload = serde_json::to_value(event).expect("event");

    let error = decode_and_validate_trace_records(&records, &run_id.to_string())
        .expect_err("payload hash mismatch");
    assert_eq!(error, "trace_compatibility_integrity_failure");
}

#[test]
fn decode_trace_records_rejects_event_run_mismatch() {
    let run_id = RunId::new();
    let mut records = valid_trace_records_for(&run_id);
    let event = TraceEvent::new(
        RunId::new(),
        0,
        OffsetDateTime::now_utc(),
        TraceEventKind::LoopTickStarted { tick_id: 1 },
    );
    records[0].payload = serde_json::to_value(event).expect("event");
    rehash_trace_records(&mut records);

    let error = decode_and_validate_trace_records(&records, &run_id.to_string())
        .expect_err("event run mismatch");
    assert_eq!(error, "trace_compatibility_envelope_failure");
}

#[test]
fn decode_trace_records_rejects_trace_id_mismatch() {
    let run_id = RunId::new();
    let mut records = valid_trace_records_for(&run_id);
    let mut event: TraceEvent = serde_json::from_value(records[0].payload.clone()).unwrap();
    event.trace_event_id = TraceEventId::new();
    records[0].payload = serde_json::to_value(event).expect("event");
    rehash_trace_records(&mut records);

    let error = decode_and_validate_trace_records(&records, &run_id.to_string())
        .expect_err("trace id mismatch");
    assert_eq!(error, "trace_compatibility_envelope_failure");
}

#[test]
fn state_head_succeeds_with_state_committed_trace() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let trace_store = SqliteTraceStore::open(trace_temp.path()).expect("trace store");
    let run_id = RunId::new();
    let timestamp = OffsetDateTime::now_utc();
    let state_hash = ContentHash::blake3(b"state");
    let events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            timestamp,
            TraceEventKind::StateCommitted {
                state_hash,
                snapshot_id: None,
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            2,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        ),
    ];
    for event in events {
        TraceStore::append(
            &trace_store,
            &run_id.to_string(),
            serde_json::to_value(event).unwrap(),
        )
        .expect("append");
    }

    state_head(&trace_temp.path().to_path_buf(), &run_id.to_string()).expect("state head");
    run_with_args(vec![
        "state".to_string(),
        "head".to_string(),
        "--db".to_string(),
        trace_temp.path().display().to_string(),
        "--run".to_string(),
        run_id.to_string(),
    ])
    .expect("state head through command parser");
}

#[test]
fn state_head_errors_when_trace_db_missing() {
    let dir = tempfile::TempDir::new().expect("dir");
    let missing = dir.path().join("missing-trace.db");
    let error = state_head(&missing, "run-1").expect_err("missing db");
    assert_eq!(error, "trace_database_not_found");
}

#[test]
fn state_head_errors_without_state_commit() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let trace_store = SqliteTraceStore::open(trace_temp.path()).expect("trace store");
    let run_id = RunId::new();
    let timestamp = OffsetDateTime::now_utc();
    let events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        ),
    ];
    for event in events {
        TraceStore::append(
            &trace_store,
            &run_id.to_string(),
            serde_json::to_value(event).unwrap(),
        )
        .expect("append");
    }

    let error = state_head(&trace_temp.path().to_path_buf(), &run_id.to_string())
        .expect_err("missing state commit");
    assert_eq!(error, "state_head_not_found");
}

#[test]
fn acceptance_validate_import_accepts_and_rejects_tampered_artifacts() {
    let (trace, state, scenario, _audit) = acceptance_fixture_files();
    let expected_state_hash =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    acceptance_validate_import(
        trace.path(),
        state.path(),
        scenario.path(),
        "UC-E2E-S1",
        None,
        None,
    )
    .expect("valid import accepted");

    let scenario_without_hashes = write_temp_json(serde_json::json!({
        "state_hashes": [],
    }));
    acceptance_validate_import(
        trace.path(),
        state.path(),
        scenario_without_hashes.path(),
        "UC-E2E-S1",
        None,
        Some(expected_state_hash),
    )
    .expect("explicit expected state hash can prove imported state");

    let empty_trace = write_temp_text("");
    let error = acceptance_validate_import(
        empty_trace.path(),
        state.path(),
        scenario.path(),
        "UC-E2E-S1",
        None,
        None,
    )
    .expect_err("empty trace rejected");
    assert!(error.contains("empty_trace"));

    let records = std::fs::read_to_string(trace.path())
        .expect("trace")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("trace json"))
        .collect::<Vec<_>>();
    let original_chain = acceptance_trace_chain_hash(&records).expect("trace chain");
    let tampered_trace = write_temp_text(
        r#"{"event_type":"tick.started","sequence":1,"payload":{"side_effects_executed":true}}
"#,
    );
    let error = acceptance_validate_import(
        tampered_trace.path(),
        state.path(),
        scenario.path(),
        "UC-E2E-S1",
        Some(&original_chain),
        None,
    )
    .expect_err("tampered trace rejected");
    assert!(error.contains("trace_chain_hash_mismatch"));

    let error = acceptance_validate_import(
        trace.path(),
        state.path(),
        scenario.path(),
        "UC-E2E-S1",
        None,
        Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    )
    .expect_err("state mismatch rejected");
    assert!(error.contains("state_hash_mismatch"));

    let mismatched_scenario = write_temp_json(serde_json::json!({
        "state_hashes": ["sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],
    }));
    let error = acceptance_validate_import(
        trace.path(),
        state.path(),
        mismatched_scenario.path(),
        "UC-E2E-S1",
        None,
        None,
    )
    .expect_err("scenario/state mismatch rejected");
    assert!(error.contains("state_hash_mismatch"));
}

#[test]
fn run_with_args_executes_acceptance_subcommands() {
    let (trace, state, scenario, audit) = acceptance_fixture_files();
    let fixture = write_temp_json(serde_json::json!({
        "schema_version": "splendor.work_order.v1",
        "work_order_id": "wo_acceptance",
    }));
    let credential = write_temp_json(serde_json::json!({
        "credential_kind": "local_acceptance_fixture",
        "secret_ref": "dev_fixture_only",
    }));

    run_with_args(args(&[
        "acceptance",
        "validate-import",
        "--trace",
        &trace.path().display().to_string(),
        "--state",
        &state.path().display().to_string(),
        "--scenario-report",
        &scenario.path().display().to_string(),
        "--source",
        "UC-E2E-S1",
    ]))
    .expect("validate-import command executes");

    run_with_args(args(&[
        "acceptance",
        "compat",
        "--fixture",
        &fixture.path().display().to_string(),
        "--target-schema",
        "splendor.0.1.stable.v1",
    ]))
    .expect("compat command executes");

    run_with_args(args(&[
        "acceptance",
        "audit-check",
        "--audit",
        &audit.path().display().to_string(),
        "--scenario-report",
        &scenario.path().display().to_string(),
        "--case",
        "deny_url",
        "--category",
        "denial",
    ]))
    .expect("audit-check command executes");

    run_with_args(args(&[
        "acceptance",
        "replay-mode",
        "--mode",
        "inspect_only",
        "--trace",
        &trace.path().display().to_string(),
        "--state",
        &state.path().display().to_string(),
        "--audit",
        &audit.path().display().to_string(),
        "--scenario-report",
        &scenario.path().display().to_string(),
        "--source",
        "UC-E2E-S8",
    ]))
    .expect("replay-mode command executes");

    run_with_args(args(&[
        "acceptance",
        "replay-credential-check",
        "--credential",
        &credential.path().display().to_string(),
    ]))
    .expect("replay credential command executes");
}

#[test]
fn acceptance_compat_accepts_supported_and_rejects_bad_fixtures() {
    let supported = write_temp_json(serde_json::json!({
        "schema_version": "splendor.work_order.v1",
        "work_order_id": "wo_acceptance",
    }));
    acceptance_compat(&[supported.path().to_path_buf()], "splendor.0.1.stable.v1")
        .expect("supported fixture migrates");
    let error = acceptance_compat(&[supported.path().to_path_buf()], "splendor.future.v2")
        .expect_err("unsupported target rejected");
    assert!(error.contains("unsupported_target_schema"));

    let unsupported = write_temp_json(serde_json::json!({
        "schema_version": "splendor.dev.0.00.unsupported",
    }));
    let error = acceptance_compat(
        &[unsupported.path().to_path_buf()],
        "splendor.0.1.stable.v1",
    )
    .expect_err("unsupported schema rejected");
    assert!(error.contains("unsupported_schema_version"));

    let mismatch = write_temp_json(serde_json::json!({
        "schema_version": "splendor.generated.types.mismatch.v1",
    }));
    let error = acceptance_compat(&[mismatch.path().to_path_buf()], "splendor.0.1.stable.v1")
        .expect_err("generated mismatch rejected");
    assert!(error.contains("generated_schema_mismatch"));
}

#[test]
fn acceptance_audit_check_requires_explicit_reason_codes() {
    let (_trace, _state, scenario, audit) = acceptance_fixture_files();
    acceptance_audit_check(audit.path(), scenario.path(), "deny_url", "denial")
        .expect("audit reason codes accepted");

    let scalar_audit = write_temp_json(serde_json::json!({
        "denials": [{
            "case": "scalar_reason",
            "reason_code": "adapter_denied",
            "reasons": ["quota_exceeded"],
            "trace_event_id": "trace_evt_scalar"
        }],
    }));
    acceptance_audit_check(
        scalar_audit.path(),
        scenario.path(),
        "scalar_reason",
        "denial",
    )
    .expect("scalar reason and trace id accepted");

    let empty_audit = write_temp_json(serde_json::json!({
        "negative_cases": [{"case": "missing_reason"}],
    }));
    let empty_scenario = write_temp_json(serde_json::json!({
        "negative_cases": [{"case": "missing_reason"}],
    }));
    let error = acceptance_audit_check(
        empty_audit.path(),
        empty_scenario.path(),
        "missing_reason",
        "denial",
    )
    .expect_err("missing reason rejected");
    assert!(error.contains("missing_denial_reason_codes"));
}

#[test]
fn acceptance_json_collectors_cover_nested_arrays_and_parse_failures() {
    let state_hash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let value = serde_json::json!([
        {"state_hash": state_hash, "state_node_id": "state_nested"},
        {"schema_version": "splendor.message.task_request.v1"}
    ]);
    assert!(acceptance_state_hashes(&value).contains(state_hash));
    assert!(acceptance_state_node_ids(&value).contains("state_nested"));
    assert!(acceptance_schema_versions(&value).contains("splendor.message.task_request.v1"));

    let mut values = BTreeSet::new();
    collect_named_string_values(
        &serde_json::json!([
            {"reason": "nested_reason"},
            {"reasons": ["array_reason", ""]},
            {"reason_codes": 7}
        ]),
        &["reason", "reasons", "reason_codes"],
        &mut values,
    );
    assert!(values.contains("nested_reason"));
    assert!(values.contains("array_reason"));

    let malformed = write_temp_text("{");
    let error = read_json_value(malformed.path()).expect_err("malformed json rejected");
    assert!(error.contains("Malformed JSON"));

    let missing = malformed.path().with_file_name("missing-acceptance.json");
    let error = read_json_value(&missing).expect_err("missing json rejected");
    assert!(error.contains("Failed to read"));
}

#[test]
fn acceptance_replay_mode_covers_supported_modes_and_fail_closed_paths() {
    let (trace, state, scenario, audit) = acceptance_fixture_files();
    for mode in [
        "inspect_only",
        "read_only_re_evaluation",
        "policy_comparison",
        "verifier_explanation",
    ] {
        acceptance_replay_mode(
            mode,
            trace.path(),
            state.path(),
            audit.path(),
            scenario.path(),
            "UC-E2E-S8",
        )
        .expect("replay mode accepted");
    }

    let error = acceptance_replay_mode(
        "side_effectful_live_replay",
        trace.path(),
        state.path(),
        audit.path(),
        scenario.path(),
        "UC-E2E-S8",
    )
    .expect_err("unsupported replay mode rejected");
    assert!(error.contains("unsupported_mode"));

    let empty_trace = write_temp_text("");
    let error = acceptance_replay_mode(
        "inspect_only",
        empty_trace.path(),
        state.path(),
        audit.path(),
        scenario.path(),
        "UC-E2E-S8",
    )
    .expect_err("empty trace rejected");
    assert!(error.contains("empty_trace"));

    let mismatched_state = write_temp_json(serde_json::json!({
        "state_node_id": "state_other",
        "state_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    }));
    let error = acceptance_replay_mode(
        "inspect_only",
        trace.path(),
        mismatched_state.path(),
        audit.path(),
        scenario.path(),
        "UC-E2E-S8",
    )
    .expect_err("state mismatch rejected");
    assert!(error.contains("state_hash_mismatch"));

    let audit_without_reason = write_temp_json(serde_json::json!({"negative_cases": []}));
    let error = acceptance_replay_mode(
        "verifier_explanation",
        trace.path(),
        state.path(),
        audit_without_reason.path(),
        scenario.path(),
        "UC-E2E-S8",
    )
    .expect_err("verifier explanation requires reasons");
    assert!(error.contains("missing_verifier_reason_codes"));
}

#[test]
fn acceptance_replay_credential_check_rejects_external_credentials() {
    let allowed = write_temp_json(serde_json::json!({
        "credential_kind": "local_acceptance_fixture",
        "secret_ref": "dev_fixture_only",
    }));
    acceptance_replay_credential_check(allowed.path()).expect("dev fixture accepted");

    let production = write_temp_json(serde_json::json!({
        "credential_kind": "production_external_secret",
        "secret_ref": "external_secret_material",
    }));
    let error = acceptance_replay_credential_check(production.path())
        .expect_err("production credential rejected");
    assert!(error.contains("real_external_credentials_forbidden"));
}

#[test]
fn usage_mentions_trace_export() {
    let text = usage();
    assert!(text.contains("trace export"));
    assert!(text.contains("state head"));
    assert!(text.contains("replay"));
    assert!(text.contains("audit export"));
    assert!(text.contains("acceptance validate-import"));
    assert!(text.contains("acceptance compat"));
    assert!(text.contains("acceptance audit-check"));
    assert!(text.contains("acceptance replay-mode"));
    assert!(text.contains("acceptance replay-credential-check"));
    assert!(text.contains("run"));
    assert!(text.contains("--version"));
}

#[test]
fn run_from_config_executes_cycle() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let state_temp = NamedTempFile::new().expect("state db");
    let config_temp = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("config");

    let tenant_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();
    let run_id = Uuid::new_v4();

    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nallow_unsigned_local_run: true\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    snapshot_interval: 1\n    initial_state: \"seed\"\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          params:\n            path: \"hello.txt\"\n            contents: \"hi\"\nadapters:\n  filesystem:\n    base_dir: {}\n",
        trace_temp.path().display(),
        state_temp.path().display(),
        run_id,
        tenant_id,
        agent_id,
        tenant_id,
        run_id,
        config_temp.path().parent().unwrap().display(),
    );
    std::fs::write(config_temp.path(), config).expect("write config");

    run_from_config(config_temp.path(), Some(1), false).expect("run config");

    let store = SqliteTraceStore::open(trace_temp.path()).expect("trace store");
    let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
    assert!(!records.is_empty());
}

#[test]
fn run_from_config_circuit_breaker_denies_adapter_action() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nallow_unsigned_local_run: true\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          params:\n            path: \"blocked.txt\"\n            contents: \"blocked\"\nadapters:\n  filesystem:\n    base_dir: {}\ncircuit_breakers:\n  - id: cb_filesystem_adapter\n    scope: adapter\n    value: filesystem\n    state: tripped\n    reason: filesystem disabled for incident\n    authorized_by: operator:alice\n",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        fs_base.display(),
    );
    std::fs::write(&config_path, config).expect("write config");

    run_from_config(&config_path, Some(1), false).expect("run config");

    assert!(!fs_base
        .join(tenant_uuid.to_string())
        .join("blocked.txt")
        .exists());
    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let records = TraceStore::read(&store, &run_uuid.to_string()).expect("records");
    let events = decode_and_validate_trace_records(&records, &run_uuid.to_string())
        .expect("validated trace");
    let denied = events.iter().find_map(|event| match &event.kind {
        TraceEventKind::ActionDenied { result, .. } => Some(result),
        _ => None,
    });
    let result = denied.expect("action denied");
    assert!(result
        .reasons
        .contains(&"circuit_breaker_tripped".to_string()));
    let expected_breaker_id = splendor_types::CircuitBreakerId::try_new("cb_filesystem_adapter")
        .expect("breaker id")
        .to_string();
    assert_eq!(
        result.artifacts["circuit_breaker"]["circuit_breaker"]["breaker_id"],
        expected_breaker_id
    );
    let tripped = events
        .iter()
        .find_map(|event| match &event.kind {
            TraceEventKind::CircuitBreakerTripped { breaker } => Some(breaker),
            _ => None,
        })
        .expect("configured breaker trip trace");
    assert_eq!(tripped.breaker_id.to_string(), expected_breaker_id);
    assert_eq!(tripped.state, CircuitBreakerState::Tripped);
    assert_eq!(tripped.authorized_by, "operator:alice");

    let replay_outputs =
        replay_outputs_from_stores(&trace_path, &state_path, &run_uuid.to_string(), None, false)
            .expect("replay outputs");
    let replay_values = replay_outputs
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .expect("json replay values");
    let replay_start = replay_values
        .iter()
        .find(|value| value["type"] == "replay_start")
        .expect("replay start output");
    assert_eq!(replay_start["side_effects_replayed"].as_bool(), Some(false));
    let replay_tick = replay_values
        .iter()
        .find(|value| value["type"] == "tick")
        .expect("tick replay output");
    let denials = replay_tick["circuit_breaker_denials"]
        .as_array()
        .expect("breaker denials");
    assert_eq!(denials.len(), 1);
    assert_eq!(
        denials[0]["breaker_id"].as_str(),
        Some(expected_breaker_id.as_str())
    );
    assert_eq!(denials[0]["scope"].as_str(), Some("adapter"));
    assert_eq!(denials[0]["scope_value"].as_str(), Some("filesystem"));
    assert_eq!(
        denials[0]["reason"].as_str(),
        Some("filesystem disabled for incident")
    );
    let replay_graph = replay_values
        .iter()
        .find(|value| value["type"] == "causal_graph")
        .expect("causal graph replay output");
    assert_eq!(
        replay_graph["circuit_breaker_denials"]
            .as_array()
            .expect("graph breaker denials")
            .len(),
        1
    );
}

#[test]
fn run_from_config_records_circuit_breaker_cleared_event() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nallow_unsigned_local_run: true\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          params:\n            path: \"allowed.txt\"\n            contents: \"allowed\"\nadapters:\n  filesystem:\n    base_dir: {}\ncircuit_breakers:\n  - id: cb_filesystem_adapter_reset\n    scope: adapter\n    value: filesystem\n    state: cleared\n    reason: filesystem incident resolved\n    authorized_by: operator:bob\n",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        fs_base.display(),
    );
    std::fs::write(&config_path, config).expect("write config");

    run_from_config(&config_path, Some(1), false).expect("run config");

    assert!(fs_base
        .join(tenant_uuid.to_string())
        .join("allowed.txt")
        .exists());
    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let records = TraceStore::read(&store, &run_uuid.to_string()).expect("records");
    let events = decode_and_validate_trace_records(&records, &run_uuid.to_string())
        .expect("validated trace");
    assert!(events
        .iter()
        .any(|event| matches!(&event.kind, TraceEventKind::ActionExecuted { .. })));
    let cleared = events
        .iter()
        .find_map(|event| match &event.kind {
            TraceEventKind::CircuitBreakerCleared { breaker } => Some(breaker),
            _ => None,
        })
        .expect("configured breaker clear trace");
    let expected_breaker_id =
        splendor_types::CircuitBreakerId::try_new("cb_filesystem_adapter_reset")
            .expect("breaker id")
            .to_string();
    assert_eq!(cleared.breaker_id.to_string(), expected_breaker_id);
    assert_eq!(cleared.state, CircuitBreakerState::Cleared);
    assert_eq!(cleared.authorized_by, "operator:bob");
}

#[test]
fn run_from_config_rejects_node_circuit_breaker_before_new_work() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let node_uuid = Uuid::new_v4();
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nallow_unsigned_local_run: true\nruntime_identity:\n  node_id: {}\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          params:\n            path: \"node-blocked.txt\"\n            contents: \"blocked\"\nadapters:\n  filesystem:\n    base_dir: {}\ncircuit_breakers:\n  - id: cb_node_admission\n    scope: node\n    value: {}\n    state: tripped\n    reason: node drained for maintenance\n    authorized_by: operator:node\n",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        node_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        fs_base.display(),
        node_uuid,
    );
    std::fs::write(&config_path, config).expect("write config");

    let error = run_from_config(&config_path, Some(1), false).expect_err("node breaker admission");

    assert!(error.contains("Circuit breaker denied new work"));
    assert!(error.contains("circuit_breaker_tripped"));
    assert!(!fs_base
        .join(tenant_uuid.to_string())
        .join("node-blocked.txt")
        .exists());
}

#[test]
fn run_from_config_rejects_instance_circuit_breaker_before_new_work() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let instance_uuid = Uuid::new_v4();
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nallow_unsigned_local_run: true\nruntime_identity:\n  instance_id: {}\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          params:\n            path: \"instance-blocked.txt\"\n            contents: \"blocked\"\nadapters:\n  filesystem:\n    base_dir: {}\ncircuit_breakers:\n  - id: cb_instance_admission\n    scope: instance\n    value: {}\n    state: tripped\n    reason: instance drained for maintenance\n    authorized_by: operator:instance\n",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        instance_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        fs_base.display(),
        instance_uuid,
    );
    std::fs::write(&config_path, config).expect("write config");

    let error =
        run_from_config(&config_path, Some(1), false).expect_err("instance breaker admission");

    assert!(error.contains("Circuit breaker denied new work"));
    assert!(error.contains("circuit_breaker_tripped"));
    assert!(!fs_base
        .join(tenant_uuid.to_string())
        .join("instance-blocked.txt")
        .exists());
}

#[test]
fn circuit_breaker_config_builds_trace_contexts_and_validates_state() {
    let contexts = build_circuit_breaker_trace_contexts(Some(&[CircuitBreakerConfig {
        id: "cb_default_authority".to_string(),
        scope: "adapter".to_string(),
        value: Some("filesystem".to_string()),
        reason: "local incident".to_string(),
        state: None,
        authorized_by: None,
    }]))
    .expect("trace contexts");
    let expected_breaker_id = splendor_types::CircuitBreakerId::try_new("cb_default_authority")
        .expect("breaker id")
        .to_string();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].breaker_id.to_string(), expected_breaker_id);
    assert_eq!(contexts[0].state, CircuitBreakerState::Tripped);
    assert_eq!(contexts[0].authorized_by, "local-config:circuit-breakers");

    let error = build_circuit_breaker_trace_contexts(Some(&[CircuitBreakerConfig {
        id: "cb_bad_state".to_string(),
        scope: "adapter".to_string(),
        value: Some("filesystem".to_string()),
        reason: "bad state".to_string(),
        state: Some("half_open".to_string()),
        authorized_by: Some("operator:carol".to_string()),
    }]))
    .expect_err("unsupported state");
    assert!(error.contains("Unsupported circuit breaker state"));

    let error = build_circuit_breaker_trace_contexts(Some(&[CircuitBreakerConfig {
        id: "cb_clear_without_authority".to_string(),
        scope: "adapter".to_string(),
        value: Some("filesystem".to_string()),
        reason: "resolved without authority".to_string(),
        state: Some("cleared".to_string()),
        authorized_by: None,
    }]))
    .expect_err("cleared breaker requires authority");
    assert!(error.contains("requires authorized_by"));

    let error = build_circuit_breaker_trace_contexts(Some(&[CircuitBreakerConfig {
        id: "cb_malformed_action_class".to_string(),
        scope: "action_class".to_string(),
        value: Some("filessystem".to_string()),
        reason: "typo should not install a custom breaker".to_string(),
        state: Some("tripped".to_string()),
        authorized_by: Some("operator:carol".to_string()),
    }]))
    .expect_err("malformed action class");
    assert!(error.contains("Unsupported action_class"));
}

#[test]
fn parse_circuit_breaker_scope_covers_supported_values_and_failures() {
    fn config(scope: &str, value: Option<String>) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            id: format!("cb_{scope}"),
            scope: scope.to_string(),
            value,
            reason: "scope parse".to_string(),
            state: Some("tripped".to_string()),
            authorized_by: Some("operator:scope-test".to_string()),
        }
    }

    let fleet_uuid = Uuid::new_v4().to_string();
    let node_uuid = Uuid::new_v4().to_string();
    let instance_uuid = Uuid::new_v4().to_string();
    let tenant_uuid = Uuid::new_v4().to_string();
    let agent_uuid = Uuid::new_v4().to_string();
    let cases = [
        ("global", None, "global", None),
        ("fleet", Some(fleet_uuid.clone()), "fleet", Some(fleet_uuid)),
        ("node", Some(node_uuid.clone()), "node", Some(node_uuid)),
        (
            "instance",
            Some(instance_uuid.clone()),
            "instance",
            Some(instance_uuid),
        ),
        (
            "tenant",
            Some(tenant_uuid.clone()),
            "tenant",
            Some(tenant_uuid),
        ),
        ("agent", Some(agent_uuid.clone()), "agent", Some(agent_uuid)),
        (
            "adapter",
            Some("filesystem".to_string()),
            "adapter",
            Some("filesystem".to_string()),
        ),
        (
            "action",
            Some("write_file".to_string()),
            "action",
            Some("write_file".to_string()),
        ),
        (
            "action_class",
            Some("network".to_string()),
            "action_class",
            Some("network".to_string()),
        ),
    ];

    for (scope_name, value, expected_label, expected_value) in cases {
        let scope = parse_circuit_breaker_scope(&config(scope_name, value)).expect("scope");
        assert_eq!(scope.label(), expected_label);
        assert_eq!(scope.value(), expected_value);
    }

    let custom_scope = parse_circuit_breaker_scope(&config(
        "action_class",
        Some("custom:domain_specific".to_string()),
    ))
    .expect("custom action class");
    assert_eq!(
        custom_scope.value(),
        Some("custom:domain_specific".to_string())
    );

    let malformed =
        parse_circuit_breaker_scope(&config("action_class", Some("domain_specific".to_string())))
            .expect_err("unprefixed custom action class");
    assert!(malformed.contains("Unsupported action_class"));

    let missing = parse_circuit_breaker_scope(&config("tenant", None)).expect_err("missing value");
    assert!(missing.contains("requires value"));
    let unsupported = parse_circuit_breaker_scope(&config("workspace", Some("x".to_string())))
        .expect_err("unsupported scope");
    assert!(unsupported.contains("Unsupported circuit breaker scope"));
}

#[test]
fn run_from_config_rejects_missing_work_order_by_default() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let run_id: RunId = run_uuid.into();
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          params:\n            path: \"hello.txt\"\n            contents: \"hi\"\nadapters:\n  filesystem:\n    base_dir: {}\n",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        fs_base.display(),
    );
    std::fs::write(&config_path, config).expect("write config");

    let error = run_from_config(&config_path, Some(1), false).expect_err("missing work order");
    assert!(error.contains("unsigned_work_order"));
    assert!(!fs_base
        .join(tenant_uuid.to_string())
        .join("hello.txt")
        .exists());
    assert!(!state_path.exists());

    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let records = TraceStore::read(&store, &run_id.to_string()).expect("audit records");
    assert_eq!(records.len(), 1);
    let event: TraceEvent = serde_json::from_value(records[0].payload.clone()).expect("event");
    match event.kind {
        TraceEventKind::WorkOrderRejected {
            work_order_id,
            reason,
            ..
        } => {
            assert!(work_order_id.is_none());
            assert_eq!(reason, "unsigned_work_order");
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn run_from_config_validates_signed_work_order_and_records_metadata() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let tenant_id: TenantId = tenant_uuid.into();
    let agent_id: AgentId = agent_uuid.into();
    let run_id: RunId = run_uuid.into();
    let work_order = signed_work_order_block(
        tenant_id,
        agent_id,
        run_id.clone(),
        vec!["write_file".to_string()],
    );

    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\", \"delete_file\"]\n    allowed_adapters: [\"filesystem\"]\n    allowed_permissions: [\"fs.write\"]\n    quotas:\n      max_actions_per_tick: 5\n      max_filesystem_write_bytes: 1024\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    allowed_permissions: [\"fs.write\"]\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          required_permissions: [\"fs.write\"]\n          params:\n            path: \"hello.txt\"\n            contents: \"hi\"\n          usage:\n            actions: 1\n            filesystem_write_bytes: 2\nadapters:\n  filesystem:\n    base_dir: {}\n{}",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        fs_base.display(),
        work_order,
    );
    std::fs::write(&config_path, config).expect("write config");

    run_from_config(&config_path, Some(1), false).expect("run config");

    let tenant_root = fs_base.join(tenant_uuid.to_string());
    assert_eq!(
        std::fs::read_to_string(tenant_root.join("hello.txt")).expect("hello"),
        "hi"
    );
    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let events = decode_and_validate_trace_records(
        &TraceStore::read(&store, &run_id.to_string()).expect("records"),
        &run_id.to_string(),
    )
    .expect("trace validation");
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::WorkOrderAccepted { work_order_id, .. }
            if work_order_id.as_str() == "wo_cli"
    )));
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::RunStarted)));
}

#[test]
fn run_from_config_two_agents_share_one_contiguous_run_trace_cursor() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_id = TenantId::new();
    let first_agent_id = AgentId::new();
    let second_agent_id = AgentId::new();
    let run_id = RunId::new();
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nallow_unsigned_local_run: true\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    policy:\n      type: static\n      next_state: first-state\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          params:\n            path: \"first-agent.txt\"\n            contents: \"first\"\n  - id: {}\n    tenant_id: {}\n    policy:\n      type: static\n      next_state: second-state\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          params:\n            path: \"second-agent.txt\"\n            contents: \"second\"\nadapters:\n  filesystem:\n    base_dir: {}\n",
        trace_path.display(),
        state_path.display(),
        run_id,
        tenant_id,
        first_agent_id,
        tenant_id,
        second_agent_id,
        tenant_id,
        fs_base.display(),
    );
    std::fs::write(&config_path, config).expect("write config");

    run_from_config(&config_path, Some(1), false).expect("two-agent run");

    let tenant_root = fs_base.join(tenant_id.to_string());
    assert_eq!(
        std::fs::read_to_string(tenant_root.join("first-agent.txt")).expect("first effect"),
        "first"
    );
    assert_eq!(
        std::fs::read_to_string(tenant_root.join("second-agent.txt")).expect("second effect"),
        "second"
    );

    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
    let events = decode_and_validate_trace_records(&records, &run_id.to_string())
        .expect("contiguous shared-run trace");
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::RunStarted))
            .count(),
        1
    );

    for agent_id in [&first_agent_id, &second_agent_id] {
        let verification_indices = events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| {
                (event.identity.agent_id.as_ref() == Some(agent_id)
                    && matches!(
                        &event.kind,
                        TraceEventKind::ActionVerificationCompleted { action, .. }
                            if action.name == "write_file"
                    ))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        let effect_indices = events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| {
                (event.identity.agent_id.as_ref() == Some(agent_id)
                    && matches!(
                        &event.kind,
                        TraceEventKind::ActionExecuted { action, .. }
                            if action.name == "write_file"
                    ))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            verification_indices.len(),
            1,
            "one evidence record per agent"
        );
        assert_eq!(effect_indices.len(), 1, "one configured effect per agent");
        assert!(verification_indices[0] < effect_indices[0]);
        assert_eq!(
            events[verification_indices[0]].identity.action_id,
            events[effect_indices[0]].identity.action_id
        );
        assert!(events.iter().any(|event| {
            event.identity.agent_id.as_ref() == Some(agent_id)
                && matches!(event.kind, TraceEventKind::LoopTickCompleted { .. })
        }));
    }
}

#[test]
fn signed_run_authority_allows_counted_filesystem_and_http_effects_with_pre_effect_evidence() {
    for (action_name, adapter, permission) in [
        ("write_file", "filesystem", "fs.write"),
        ("http_fetch", "http", "net.read"),
    ] {
        let dir = tempfile::TempDir::new().expect("dir");
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let run_id = RunId::new();
        let work_order = signed_work_order_block_with_authority(
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            vec![action_name.to_string()],
            vec![adapter.to_string()],
            vec![permission.to_string()],
            OffsetDateTime::now_utc() + time::Duration::hours(1),
            splendor_types::RevocationStatus::Active,
        );
        let config_path = write_counted_run_config(
            &dir,
            &tenant_id,
            &agent_id,
            &run_id,
            &work_order,
            action_name,
            adapter,
            &[permission],
            &[permission],
            None,
        );
        let (counter, overrides) = counting_run_overrides(&["filesystem", "http"], None);

        run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
            .expect("signed run");
        assert_eq!(counter.calls_for(action_name), 1);
        assert_eq!(counter.total_calls(), 1);

        let trace_path = dir.path().join("trace.db");
        let state_path = dir.path().join("state.db");
        let store = SqliteTraceStore::open(&trace_path).expect("trace store");
        let events = decode_and_validate_trace_records(
            &TraceStore::read(&store, &run_id.to_string()).expect("records"),
            &run_id.to_string(),
        )
        .expect("trace validation");
        let verification_index = events
            .iter()
            .position(|event| {
                matches!(
                    &event.kind,
                    TraceEventKind::ActionVerificationCompleted { action, result }
                        if action.name == action_name
                            && result.artifacts["authority"]["pre_effect_recorded"]
                                == serde_json::json!(true)
                )
            })
            .expect("durable pre-effect authority evidence");
        let effect_index = events
            .iter()
            .position(|event| {
                matches!(
                    &event.kind,
                    TraceEventKind::ActionExecuted { action, .. } if action.name == action_name
                )
            })
            .expect("executed action");
        assert!(verification_index < effect_index);

        let before_replay = counter.total_calls();
        replay_outputs_from_stores(&trace_path, &state_path, &run_id.to_string(), None, false)
            .expect("inspect-only replay");
        assert_eq!(counter.total_calls(), before_replay);
    }
}

#[test]
fn configured_cycles_and_forever_do_not_repeat_post_effect_output_suppression() {
    for (cycles, forever) in [(Some(2), false), (None, true)] {
        let dir = tempfile::TempDir::new().expect("dir");
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let run_id = RunId::new();
        let work_order = signed_work_order_block_with_authority(
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            vec!["write_file".to_string()],
            vec!["filesystem".to_string()],
            vec!["fs.write".to_string()],
            OffsetDateTime::now_utc() + time::Duration::hours(1),
            splendor_types::RevocationStatus::Active,
        );
        let config_path = write_counted_run_config(
            &dir,
            &tenant_id,
            &agent_id,
            &run_id,
            &work_order,
            "write_file",
            "filesystem",
            &["fs.write"],
            &["fs.write"],
            None,
        );
        let config = std::fs::read_to_string(&config_path)
            .expect("config")
            .replace(
                "    policy:\n",
                "    snapshot_interval: 1\n    resume: false\n    policy:\n",
            );
        std::fs::write(&config_path, config).expect("initial config");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut adapters = std::collections::HashMap::new();
        let adapter: Arc<dyn ActionAdapter> = Arc::new(SuppressedOutputAdapter {
            calls: Arc::clone(&calls),
        });
        adapters.insert("filesystem".to_string(), adapter);
        let overrides = RunTestOverrides {
            adapters,
            authority_transition: None,
        };

        let error = run_from_config_with_test_overrides(&config_path, cycles, forever, &overrides)
            .expect_err("post-effect suppression must halt configured execution");
        assert!(error.contains("tick_reconciliation_required"), "{error}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let trace_path = dir.path().join("trace.db");
        let records_before_fresh_retry = {
            let store = SqliteTraceStore::open(&trace_path).expect("trace store");
            TraceStore::read(&store, &run_id.to_string()).expect("records before fresh retry")
        };
        let error = run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
            .expect_err("fresh construction must reject an existing persisted run");
        assert!(error.contains("run_already_exists"), "{error}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let records_after_fresh_retry = {
            let store = SqliteTraceStore::open(&trace_path).expect("trace store");
            TraceStore::read(&store, &run_id.to_string()).expect("records after fresh retry")
        };
        assert_eq!(records_after_fresh_retry, records_before_fresh_retry);

        let config = std::fs::read_to_string(&config_path)
            .expect("config")
            .replace("resume: false", "resume: true");
        std::fs::write(&config_path, config).expect("resume config");
        let error = run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
            .expect_err("same-run resume must remain blocked pending reconciliation");
        assert!(error.contains("tick_reconciliation_required"), "{error}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let store = SqliteTraceStore::open(trace_path).expect("trace store");
        let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
        let encoded = serde_json::to_string(&records).expect("records serialize");
        assert!(!encoded.contains("Basic dTpw"));
        let events = decode_and_validate_trace_records(&records, &run_id.to_string())
            .expect("suppression trace");
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.kind, TraceEventKind::ActionFailed { .. }))
                .count(),
            1
        );
    }
}

#[test]
fn signed_run_authority_resume_keeps_live_evidence_and_contiguous_trace() {
    let dir = tempfile::TempDir::new().expect("dir");
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let work_order = signed_work_order_block_with_authority(
        tenant_id.clone(),
        agent_id.clone(),
        run_id.clone(),
        vec!["write_file".to_string()],
        vec!["filesystem".to_string()],
        vec!["fs.write".to_string()],
        OffsetDateTime::now_utc() + time::Duration::hours(1),
        splendor_types::RevocationStatus::Active,
    );
    let config_path = write_counted_run_config(
        &dir,
        &tenant_id,
        &agent_id,
        &run_id,
        &work_order,
        "write_file",
        "filesystem",
        &["fs.write"],
        &["fs.write"],
        None,
    );
    let config = std::fs::read_to_string(&config_path).expect("config");
    let config = config
        .replace(
            "    policy:\n",
            "    snapshot_interval: 1\n    resume: false\n    policy:\n",
        )
        .replace(
            "      type: static\n",
            "      type: static\n      next_state: first\n",
        );
    std::fs::write(&config_path, config).expect("initial config");
    let (counter, overrides) = counting_run_overrides(&["filesystem"], None);

    run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
        .expect("initial signed run");
    assert_eq!(counter.total_calls(), 1);

    let config = std::fs::read_to_string(&config_path)
        .expect("config")
        .replace("resume: false", "resume: true")
        .replace("next_state: first", "next_state: second");
    std::fs::write(&config_path, config).expect("resume config");
    run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
        .expect("resumed signed run");
    assert_eq!(counter.total_calls(), 2);

    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
    let events = decode_and_validate_trace_records(&records, &run_id.to_string())
        .expect("signed resume trace");
    let evidence_indices = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            matches!(
                &event.kind,
                TraceEventKind::ActionVerificationCompleted { result, .. }
                    if result.artifacts["authority"]["pre_effect_recorded"]
                        == serde_json::json!(true)
            )
            .then_some(index)
        })
        .collect::<Vec<_>>();
    let effect_indices = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            matches!(event.kind, TraceEventKind::ActionExecuted { .. }).then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(evidence_indices.len(), 2);
    assert_eq!(effect_indices.len(), 2);
    for (evidence, effect) in evidence_indices.iter().zip(&effect_indices) {
        assert!(evidence < effect);
        assert_eq!(
            events[*evidence].identity.action_id,
            events[*effect].identity.action_id
        );
        assert_eq!(events[*effect].identity.agent_id.as_ref(), Some(&agent_id));
    }
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::WorkOrderAccepted { .. }))
            .count(),
        2
    );

    let before_replay = counter.total_calls();
    replay_outputs_from_stores(&trace_path, &state_path, &run_id.to_string(), None, false)
        .expect("inspect-only resumed replay");
    assert_eq!(counter.total_calls(), before_replay);
}

#[test]
fn invalid_configured_work_order_never_falls_back_to_explicit_unsigned_mode() {
    let dir = tempfile::TempDir::new().expect("dir");
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let work_order = corrupt_work_order_signature(signed_work_order_block_with_authority(
        tenant_id.clone(),
        agent_id.clone(),
        run_id.clone(),
        vec!["write_file".to_string()],
        vec!["filesystem".to_string()],
        vec!["fs.write".to_string()],
        OffsetDateTime::now_utc() + time::Duration::hours(1),
        splendor_types::RevocationStatus::Active,
    ));
    let config_path = write_counted_run_config(
        &dir,
        &tenant_id,
        &agent_id,
        &run_id,
        &work_order,
        "write_file",
        "filesystem",
        &["fs.write"],
        &["fs.write"],
        None,
    );
    let config = std::fs::read_to_string(&config_path).expect("config");
    let config = config.replace("state_db:", "allow_unsigned_local_run: true\nstate_db:");
    std::fs::write(&config_path, config).expect("config with explicit unsigned mode");
    let (counter, overrides) = counting_run_overrides(&["filesystem"], None);

    let error = run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
        .expect_err("invalid configured work order must fail");
    assert_eq!(error, "Work order rejected: bad_signature");
    assert_eq!(counter.total_calls(), 0);
    assert!(!dir.path().join("state.db").exists());

    let store = SqliteTraceStore::open(dir.path().join("trace.db")).expect("trace store");
    let events = decode_and_validate_trace_records(
        &TraceStore::read(&store, &run_id.to_string()).expect("records"),
        &run_id.to_string(),
    )
    .expect("rejection trace");
    assert!(matches!(
        &events.as_slice(),
        [TraceEvent {
            kind: TraceEventKind::WorkOrderRejected { reason, .. },
            ..
        }] if reason == "bad_signature"
    ));
}

#[test]
fn signed_run_authority_expiry_and_revocation_after_admission_block_counted_effects() {
    for (name, transition, expected_reason, expires_at) in [
        (
            "expiry",
            RunAuthorityTestTransition::Delay(std::time::Duration::from_millis(2_200)),
            "expired_grant",
            OffsetDateTime::now_utc() + time::Duration::seconds(2),
        ),
        (
            "revocation",
            RunAuthorityTestTransition::Revoke,
            "authority_grant_revoked",
            OffsetDateTime::now_utc() + time::Duration::hours(1),
        ),
    ] {
        let dir = tempfile::TempDir::new().expect("dir");
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let run_id = RunId::new();
        let action_name = format!("http_{name}");
        let work_order = signed_work_order_block_with_authority(
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            vec![action_name.clone()],
            vec!["http".to_string()],
            vec!["net.read".to_string()],
            expires_at,
            splendor_types::RevocationStatus::Active,
        );
        let config_path = write_counted_run_config(
            &dir,
            &tenant_id,
            &agent_id,
            &run_id,
            &work_order,
            &action_name,
            "http",
            &["net.read"],
            &["net.read"],
            None,
        );
        let (counter, overrides) = counting_run_overrides(&["http"], Some(transition));

        run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
            .expect("authority denial is a completed tick");
        assert_eq!(counter.total_calls(), 0);

        let store = SqliteTraceStore::open(dir.path().join("trace.db")).expect("trace store");
        let events = decode_and_validate_trace_records(
            &TraceStore::read(&store, &run_id.to_string()).expect("records"),
            &run_id.to_string(),
        )
        .expect("trace validation");
        let denied = events
            .iter()
            .find_map(|event| match &event.kind {
                TraceEventKind::ActionDenied { action, result } if action.name == action_name => {
                    Some(result)
                }
                _ => None,
            })
            .expect("authority denial");
        assert!(denied
            .reasons
            .iter()
            .any(|reason| reason == expected_reason));
    }
}

#[test]
fn signed_run_authority_rejects_action_adapter_permission_and_identity_mismatches_before_effects() {
    for (case, configured_action, configured_adapter, configured_permissions, expected_reason) in [
        (
            "action",
            "delete_file",
            "filesystem",
            vec!["fs.write"],
            "trusted_action_profile_missing",
        ),
        (
            "adapter",
            "write_file",
            "http",
            vec!["fs.write"],
            "trusted_action_profile_adapter_mismatch",
        ),
        (
            "permission",
            "write_file",
            "filesystem",
            Vec::new(),
            "trusted_action_profile_permission_mismatch",
        ),
    ] {
        let dir = tempfile::TempDir::new().expect("dir");
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let run_id = RunId::new();
        let work_order = signed_work_order_block_with_authority(
            tenant_id.clone(),
            agent_id.clone(),
            run_id.clone(),
            vec!["write_file".to_string()],
            vec!["filesystem".to_string()],
            vec!["fs.write".to_string()],
            OffsetDateTime::now_utc() + time::Duration::hours(1),
            splendor_types::RevocationStatus::Active,
        );
        let config_path = write_counted_run_config(
            &dir,
            &tenant_id,
            &agent_id,
            &run_id,
            &work_order,
            configured_action,
            configured_adapter,
            &configured_permissions,
            &["fs.write"],
            None,
        );
        let (counter, overrides) = counting_run_overrides(&["filesystem", "http"], None);

        run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
            .unwrap_or_else(|error| panic!("{case} mismatch should deny in gateway: {error}"));
        assert_eq!(counter.total_calls(), 0, "{case}");
        let store = SqliteTraceStore::open(dir.path().join("trace.db")).expect("trace store");
        let events = decode_and_validate_trace_records(
            &TraceStore::read(&store, &run_id.to_string()).expect("records"),
            &run_id.to_string(),
        )
        .expect("trace validation");
        assert!(events.iter().any(|event| matches!(
            &event.kind,
            TraceEventKind::ActionDenied { result, .. }
                if result.reasons.iter().any(|reason| reason == expected_reason)
        )));
    }

    for identity_case in ["tenant", "agent", "run"] {
        let dir = tempfile::TempDir::new().expect("dir");
        let work_order_tenant = TenantId::new();
        let work_order_agent = AgentId::new();
        let work_order_run = RunId::new();
        let config_tenant = if identity_case == "tenant" {
            TenantId::new()
        } else {
            work_order_tenant.clone()
        };
        let config_agent = if identity_case == "agent" {
            AgentId::new()
        } else {
            work_order_agent.clone()
        };
        let config_run = if identity_case == "run" {
            RunId::new()
        } else {
            work_order_run.clone()
        };
        let work_order = signed_work_order_block_with_authority(
            work_order_tenant,
            work_order_agent,
            work_order_run,
            vec!["write_file".to_string()],
            vec!["filesystem".to_string()],
            vec!["fs.write".to_string()],
            OffsetDateTime::now_utc() + time::Duration::hours(1),
            splendor_types::RevocationStatus::Active,
        );
        let config_path = write_counted_run_config(
            &dir,
            &config_tenant,
            &config_agent,
            &config_run,
            &work_order,
            "write_file",
            "filesystem",
            &["fs.write"],
            &["fs.write"],
            None,
        );
        let (counter, overrides) = counting_run_overrides(&["filesystem"], None);

        let error = run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
            .expect_err("identity mismatch must fail admission");
        assert!(
            error.contains("incompatible_work_order"),
            "{identity_case}: {error}"
        );
        assert_eq!(counter.total_calls(), 0, "{identity_case}");
    }

    let dir = tempfile::TempDir::new().expect("dir");
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let work_order = signed_work_order_block_with_authority(
        tenant_id.clone(),
        agent_id.clone(),
        run_id.clone(),
        vec!["write_file".to_string()],
        vec!["filesystem".to_string(), "http".to_string()],
        vec!["fs.write".to_string()],
        OffsetDateTime::now_utc() + time::Duration::hours(1),
        splendor_types::RevocationStatus::Active,
    );
    let config_path = write_counted_run_config(
        &dir,
        &tenant_id,
        &agent_id,
        &run_id,
        &work_order,
        "write_file",
        "filesystem",
        &["fs.write"],
        &["fs.write"],
        None,
    );
    let (counter, overrides) = counting_run_overrides(&["filesystem", "http"], None);

    let error = run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
        .expect_err("ambiguous configured authority must not fall back to unsigned execution");
    assert_eq!(error, "ambiguous_work_order_action_adapter_profile");
    assert_eq!(counter.total_calls(), 0);
    assert!(!dir.path().join("state.db").exists());
    let store = SqliteTraceStore::open(dir.path().join("trace.db")).expect("trace store");
    let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
    let events = decode_and_validate_trace_records(&records, &run_id.to_string())
        .expect("profile rejection trace");
    assert!(matches!(
        &events.as_slice(),
        [TraceEvent {
            kind:
                TraceEventKind::WorkOrderRejected {
                    work_order_id: Some(work_order_id),
                    tenant_id: Some(event_tenant_id),
                    agent_id: Some(event_agent_id),
                    run_id: Some(event_run_id),
                    reason,
                },
            ..
        }] if work_order_id.as_str() == "wo_cli"
            && *event_tenant_id == tenant_id
            && *event_agent_id == agent_id
            && *event_run_id == run_id
            && reason == "ambiguous_work_order_action_adapter_profile"
    ));
    let encoded = serde_json::to_string(&events).expect("encoded audit evidence");
    assert!(!encoded.contains("cli-secret"));
    assert!(!encoded.contains("signature"));
}

#[test]
fn signed_run_authority_evidence_append_failure_blocks_counted_effect() {
    let dir = tempfile::TempDir::new().expect("dir");
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let work_order = signed_work_order_block_with_authority(
        tenant_id.clone(),
        agent_id.clone(),
        run_id.clone(),
        vec!["write_file".to_string()],
        vec!["filesystem".to_string()],
        vec!["fs.write".to_string()],
        OffsetDateTime::now_utc() + time::Duration::hours(1),
        splendor_types::RevocationStatus::Active,
    );
    let config_path = write_counted_run_config(
        &dir,
        &tenant_id,
        &agent_id,
        &run_id,
        &work_order,
        "write_file",
        "filesystem",
        &["fs.write"],
        &["fs.write"],
        Some("ActionVerificationCompleted"),
    );
    let (counter, overrides) = counting_run_overrides(&["filesystem"], None);

    run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
        .expect("evidence failure returns a fail-closed action outcome");
    assert_eq!(counter.total_calls(), 0);

    let store = SqliteTraceStore::open(dir.path().join("trace.db")).expect("trace store");
    let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
    let events = decode_and_validate_trace_records(&records, &run_id.to_string())
        .expect("fail-closed trace validation");
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::ActionVerificationCompleted { result, .. }
            if result.reasons.iter().any(|reason| reason == "authority_evidence_append_failed")
                && result.artifacts["authority"]["pre_effect_recorded"]
                    == serde_json::json!(false)
    )));
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::ActionNeedsIntervention { result, .. }
            if result.reasons.iter().any(|reason| reason == "authority_evidence_append_failed")
    )));
}

#[test]
fn run_from_config_trace_failure_injection_blocks_side_effect_without_forged_evidence() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let run_id: RunId = run_uuid.into();
    let work_order = signed_work_order_block(
        tenant_uuid.into(),
        agent_uuid.into(),
        run_id.clone(),
        vec!["write_file".to_string()],
    );
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nfailure_injection:\n  trace_fail_on_event: ActionVerificationStarted\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\n    allowed_permissions: [\"fs.write\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    allowed_permissions: [\"fs.write\"]\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          required_permissions: [\"fs.write\"]\n          params:\n            path: \"blocked.txt\"\n            contents: \"blocked\"\nadapters:\n  filesystem:\n    base_dir: {}\n{}",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        fs_base.display(),
        work_order,
    );
    std::fs::write(&config_path, config).expect("write config");

    let error = run_from_config(&config_path, Some(1), false)
        .expect_err("trace failure injection must fail closed");
    assert!(error.contains("trace_compatibility_store_failure"));
    assert!(!fs_base
        .join(tenant_uuid.to_string())
        .join("blocked.txt")
        .exists());

    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
    assert!(records.iter().all(|record| {
        trace_payload_kind(&record.payload).as_deref() != Some("TraceWriteFailed")
    }));
}

#[test]
fn run_from_config_outcome_trace_failure_preserves_effect_fact_and_stops_run() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let run_id: RunId = run_uuid.into();
    let work_order = signed_work_order_block(
        tenant_uuid.into(),
        agent_uuid.into(),
        run_id.clone(),
        vec!["write_file".to_string()],
    );
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nfailure_injection:\n  trace_fail_on_event: OutcomeRecorded\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\n    allowed_permissions: [\"fs.write\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    allowed_permissions: [\"fs.write\"]\n    policy:\n      type: static\n      next_state: must-not-commit\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          required_permissions: [\"fs.write\"]\n          params:\n            path: \"executed.txt\"\n            contents: \"executed-once\"\nadapters:\n  filesystem:\n    base_dir: {}\n{}",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        fs_base.display(),
        work_order,
    );
    std::fs::write(&config_path, config).expect("write config");

    let error = run_from_config(&config_path, Some(2), false)
        .expect_err("post-effect trace failure must fail the tick");
    assert!(error.contains("trace_compatibility_store_failure"));

    let effect_path = fs_base.join(tenant_uuid.to_string()).join("executed.txt");
    assert_eq!(
        std::fs::read_to_string(effect_path).expect("executed filesystem effect"),
        "executed-once"
    );

    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                trace_payload_kind(&record.payload).as_deref() == Some("ActionExecuted")
            })
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                trace_payload_kind(&record.payload).as_deref() == Some("LoopTickStarted")
            })
            .count(),
        1
    );
    assert!(records.iter().all(|record| {
        trace_payload_kind(&record.payload).as_deref() != Some("TraceWriteFailed")
    }));
    for forbidden_event in ["OutcomeRecorded", "StateCommitted", "LoopTickCompleted"] {
        assert!(records.iter().all(|record| {
            trace_payload_kind(&record.payload).as_deref() != Some(forbidden_event)
        }));
    }
}

#[test]
fn run_from_config_read_only_outcome_trace_failure_does_not_report_side_effect() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let tenant_id: TenantId = Uuid::from_u128(0x7201).into();
    let agent_id = fixed_agent_id(0x7202);
    let run_id = fixed_run_id(0x7203);
    let work_order = signed_work_order_block_with_authority(
        tenant_id.clone(),
        agent_id.clone(),
        run_id.clone(),
        vec!["inspect".to_string()],
        vec!["read-only-test".to_string()],
        Vec::new(),
        OffsetDateTime::now_utc() + time::Duration::hours(1),
        splendor_types::RevocationStatus::Active,
    );
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nfailure_injection:\n  trace_fail_on_event: OutcomeRecorded\ntenants:\n  - id: {}\n    allowed_actions: [\"inspect\"]\n    allowed_adapters: [\"read-only-test\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    policy:\n      type: static\n      actions:\n        - name: inspect\n          adapter: read-only-test\n          side_effect_class: read_only\n          params: {{}}\n{}",
        trace_path.display(),
        state_path.display(),
        run_id,
        tenant_id,
        agent_id,
        tenant_id,
        run_id,
        work_order,
    );
    std::fs::write(&config_path, config).expect("write config");
    let (counter, overrides) = counting_run_overrides(&["read-only-test"], None);

    let error = run_from_config_with_test_overrides(&config_path, Some(1), false, &overrides)
        .expect_err("post-read trace failure must fail the tick");
    assert!(error.contains("trace_compatibility_store_failure"));
    assert_eq!(counter.calls_for("inspect"), 1);

    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
    let executed = records
        .iter()
        .find(|record| trace_payload_kind(&record.payload).as_deref() == Some("ActionExecuted"))
        .expect("read-only action execution");
    let executed_action: Action =
        serde_json::from_value(executed.payload["kind"]["ActionExecuted"]["action"].clone())
            .expect("executed read-only action");
    assert_eq!(executed_action.side_effect_class, SideEffectClass::ReadOnly);
    assert!(records.iter().all(|record| {
        trace_payload_kind(&record.payload).as_deref() != Some("TraceWriteFailed")
    }));
}

#[test]
fn run_from_config_state_failure_injection_prevents_next_tick_without_forged_evidence() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let run_id: RunId = run_uuid.into();
    let work_order = signed_work_order_block(
        tenant_uuid.into(),
        agent_uuid.into(),
        run_id.clone(),
        vec!["noop".to_string()],
    );
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nfailure_injection:\n  state_commit_fail: true\ntenants:\n  - id: {}\n    allowed_actions: [\"noop\"]\n    allowed_adapters: [\"filesystem\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    policy:\n      type: static\n      actions: []\n      next_state: committed\n{}",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        work_order,
    );
    std::fs::write(&config_path, config).expect("write config");

    let error = run_from_config(&config_path, Some(2), false)
        .expect_err("state failure injection must fail closed");
    assert!(error.contains("injected_state_commit_failure"));

    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
    let tick_starts = records
        .iter()
        .filter(|record| trace_payload_kind(&record.payload).as_deref() == Some("LoopTickStarted"))
        .count();
    assert_eq!(tick_starts, 1);
    assert!(records.iter().all(|record| {
        trace_payload_kind(&record.payload).as_deref() != Some("StateCommitFailed")
    }));
}

#[test]
fn run_from_config_verifier_unavailable_failure_injection_fails_closed_before_adapter() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let tenant_id: TenantId = tenant_uuid.into();
    let agent_id: AgentId = agent_uuid.into();
    let run_id: RunId = run_uuid.into();
    let work_order = signed_work_order_block(
        tenant_id,
        agent_id,
        run_id.clone(),
        vec!["write_file".to_string()],
    );
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nfailure_injection:\n  verifier_unavailable_actions: [\"write_file\"]\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\n    allowed_permissions: [\"fs.write\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    allowed_permissions: [\"fs.write\"]\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          required_permissions: [\"fs.write\"]\n          params:\n            path: \"blocked.txt\"\n            contents: \"blocked\"\nadapters:\n  filesystem:\n    base_dir: {}\n{}",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        fs_base.display(),
        work_order,
    );
    std::fs::write(&config_path, config).expect("write config");

    run_from_config(&config_path, Some(1), false).expect("verifier denial completes safely");
    assert!(!fs_base
        .join(tenant_uuid.to_string())
        .join("blocked.txt")
        .exists());

    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let events = decode_and_validate_trace_records(
        &TraceStore::read(&store, &run_id.to_string()).expect("records"),
        &run_id.to_string(),
    )
    .expect("trace validation");
    let denied = events
        .iter()
        .find_map(|event| match &event.kind {
            TraceEventKind::ActionDenied { action, result } if action.name == "write_file" => {
                Some(result)
            }
            _ => None,
        })
        .expect("verifier unavailable denial");
    assert!(denied
        .reasons
        .iter()
        .any(|reason| reason == "verifier_unavailable"));
    assert_eq!(
        denied.artifacts["resource_boundary"]["verifier_status"],
        serde_json::json!("unavailable")
    );
    assert_eq!(
        denied.artifacts["resource_boundary"]["adapter_execution"],
        serde_json::json!("not_attempted")
    );
    assert!(events.iter().all(|event| !matches!(
        &event.kind,
        TraceEventKind::ActionExecuted { action, .. } if action.name == "write_file"
    )));
}

#[test]
fn run_from_config_bad_work_order_signature_records_audit_without_starting_run() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let tenant_id: TenantId = tenant_uuid.into();
    let agent_id: AgentId = agent_uuid.into();
    let run_id: RunId = run_uuid.into();
    let work_order = corrupt_work_order_signature(signed_work_order_block(
        tenant_id,
        agent_id,
        run_id.clone(),
        vec!["write_file".to_string()],
    ));
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\n    allowed_permissions: [\"fs.write\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          required_permissions: [\"fs.write\"]\n          params:\n            path: \"hello.txt\"\n            contents: \"hi\"\nadapters:\n  filesystem:\n    base_dir: {}\n{}",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        fs_base.display(),
        work_order,
    );
    std::fs::write(&config_path, config).expect("write config");

    let error = run_from_config(&config_path, Some(1), false).expect_err("bad signature");
    assert!(error.contains("bad_signature"));
    assert!(!fs_base
        .join(tenant_uuid.to_string())
        .join("hello.txt")
        .exists());
    assert!(!state_path.exists());

    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let records = TraceStore::read(&store, &run_id.to_string()).expect("audit records");
    assert_eq!(records.len(), 1);
    let event: TraceEvent = serde_json::from_value(records[0].payload.clone()).expect("event");
    match event.kind {
        TraceEventKind::WorkOrderRejected { reason, .. } => assert_eq!(reason, "bad_signature"),
        other => panic!("unexpected event: {other:?}"),
    }
    let encoded = serde_json::to_string(&records[0].payload).expect("encoded audit");
    assert!(!encoded.contains("local-work-order-secret"));
    assert!(!encoded.contains("\"signature\""));
}

#[test]
fn work_order_scope_denies_actions_outside_delegated_allowlist() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_uuid = Uuid::new_v4();
    let agent_uuid = Uuid::new_v4();
    let run_uuid = Uuid::new_v4();
    let tenant_id: TenantId = tenant_uuid.into();
    let agent_id: AgentId = agent_uuid.into();
    let run_id: RunId = run_uuid.into();
    let work_order = signed_work_order_block(
        tenant_id,
        agent_id,
        run_id.clone(),
        vec!["write_file".to_string()],
    );
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\", \"delete_file\"]\n    allowed_adapters: [\"filesystem\"]\n    allowed_permissions: [\"fs.write\"]\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    policy:\n      type: static\n      actions:\n        - name: delete_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          required_permissions: [\"fs.write\"]\n          params:\n            path: \"blocked.txt\"\nadapters:\n  filesystem:\n    base_dir: {}\n{}",
        trace_path.display(),
        state_path.display(),
        run_uuid,
        tenant_uuid,
        agent_uuid,
        tenant_uuid,
        run_uuid,
        fs_base.display(),
        work_order,
    );
    std::fs::write(&config_path, config).expect("write config");

    run_from_config(&config_path, Some(1), false).expect("run config");
    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let events = decode_and_validate_trace_records(
        &TraceStore::read(&store, &run_id.to_string()).expect("records"),
        &run_id.to_string(),
    )
    .expect("trace validation");
    let denied = events
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::ActionDenied { .. }))
        .expect("action denied");
    if let TraceEventKind::ActionDenied { result, .. } = &denied.kind {
        assert!(result
            .reasons
            .iter()
            .any(|reason| reason == "trusted_action_profile_missing"));
    }
    assert!(!fs_base
        .join(tenant_uuid.to_string())
        .join("blocked.txt")
        .exists());
}

#[test]
fn run_from_config_increment_policy_collects_percepts_and_resumes() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_path = dir.path().join("trace.db");
    let state_path = dir.path().join("state.db");
    let config_path = dir.path().join("config.yaml");
    let fs_base = dir.path().join("fs");
    let tenant_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();
    let run_id = Uuid::new_v4();

    let write_config = |resume: bool| {
        let config = format!(
            "trace_db: {}\nstate_db: {}\nrun_id: {}\ncycles: 1\nallow_unsigned_local_run: true\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\n    quotas:\n      max_actions_per_tick: 5\n      max_action_duration_ms: 1000\n      max_filesystem_read_bytes: 1024\n      max_filesystem_write_bytes: 1024\n      max_network_read_bytes: 2048\n      max_network_write_bytes: 2048\n      max_http_requests_per_minute: 10\nagents:\n  - id: {}\n    tenant_id: {}\n    run_id: {}\n    snapshot_interval: 1\n    initial_state: \"\"\n    resume: {}\n    percepts:\n      - schema: splendor.percept.unit\n        payload:\n          value: 1\n        source: unit-test\n        detail: increment-resume\n    policy:\n      type: increment\n      action:\n        name: write_file\n        adapter: filesystem\n        side_effect_class: filesystem\n        params:\n          path: \"tick_{{counter}}.txt\"\n          contents: \"counter-{{counter}}\"\n        usage:\n          actions: 1\n          filesystem_write_bytes: 16\nadapters:\n  filesystem:\n    base_dir: {}\n",
            trace_path.display(),
            state_path.display(),
            run_id,
            tenant_id,
            agent_id,
            tenant_id,
            run_id,
            resume,
            fs_base.display(),
        );
        std::fs::write(&config_path, config).expect("write config");
    };

    write_config(false);
    run_from_config(&config_path, None, false).expect("initial run");
    let tenant_root = fs_base.join(tenant_id.to_string());
    assert_eq!(
        std::fs::read_to_string(tenant_root.join("tick_1.txt")).expect("tick 1"),
        "counter-1"
    );

    write_config(true);
    run_from_config(&config_path, None, false).expect("resume run");
    assert_eq!(
        std::fs::read_to_string(tenant_root.join("tick_2.txt")).expect("tick 2"),
        "counter-2"
    );

    let store = SqliteTraceStore::open(&trace_path).expect("trace store");
    let events = decode_and_validate_trace_records(
        &TraceStore::read(&store, &run_id.to_string()).expect("records"),
        &run_id.to_string(),
    )
    .expect("validated trace");
    assert!(events.iter().any(|event| matches!(
        event.kind,
        TraceEventKind::PerceptsReceived { ref percepts } if percepts.len() == 1
    )));
}

#[test]
fn main_returns_failure_on_error() {
    let exit = with_test_args(vec!["splendorctl".to_string()], main);
    assert_eq!(exit, ExitCode::FAILURE);
}

#[test]
fn main_returns_success_on_export() {
    let temp = NamedTempFile::new().expect("temp file");
    let store = SqliteTraceStore::open(temp.path()).expect("open store");
    let run_id = RunId::new();
    append_valid_trace_records(&store, &run_id);
    let args = vec![
        "splendorctl".to_string(),
        "trace".to_string(),
        "export".to_string(),
        "--db".to_string(),
        temp.path().to_string_lossy().to_string(),
        "--run".to_string(),
        run_id.to_string(),
    ];
    let exit = with_test_args(args, main);
    assert_eq!(exit, ExitCode::SUCCESS);
}

#[test]
fn parse_args_accepts_run_positional() {
    let command =
        parse_args(vec!["run".to_string(), "/tmp/config.yaml".to_string()]).expect("parse args");
    match command {
        Command::Run {
            config_path,
            cycles,
            forever,
        } => {
            assert_eq!(config_path, PathBuf::from("/tmp/config.yaml"));
            assert!(cycles.is_none());
            assert!(!forever);
        }
        _ => panic!("unexpected command"),
    }
}

#[test]
fn parse_args_rejects_run_cycles_non_integer() {
    let error = parse_args(vec![
        "run".to_string(),
        "--config".to_string(),
        "/tmp/config.yaml".to_string(),
        "--cycles".to_string(),
        "bad".to_string(),
    ])
    .expect_err("error");
    assert!(error.contains("--cycles must be an integer"));
}

#[test]
fn parse_args_accepts_replay_from_snapshot() {
    let command = parse_args(vec![
        "replay".to_string(),
        "--db".to_string(),
        "/tmp/trace.db".to_string(),
        "--state-db".to_string(),
        "/tmp/state.db".to_string(),
        "--run".to_string(),
        "run-1".to_string(),
        "--from-snapshot".to_string(),
        "blake3:abc".to_string(),
    ])
    .expect("parse args");
    match command {
        Command::Replay { from_snapshot, .. } => {
            assert_eq!(from_snapshot, Some("blake3:abc".to_string()));
        }
        _ => panic!("unexpected command"),
    }
}

#[test]
fn resolve_config_path_finds_yaml_in_directory() {
    let dir = tempfile::TempDir::new().expect("dir");
    let config_path = dir.path().join("config.yaml");
    std::fs::write(
        &config_path,
        "trace_db: /tmp/trace.db\nstate_db: /tmp/state.db\ntenants: []\nagents: []\n",
    )
    .expect("write");
    let resolved = resolve_config_path(dir.path()).expect("resolved");
    assert_eq!(resolved, config_path);
}

#[test]
fn load_run_config_rejects_unknown_extension() {
    let file = tempfile::Builder::new()
        .suffix(".txt")
        .tempfile()
        .expect("file");
    std::fs::write(file.path(), "{}").expect("write");
    let error = load_run_config(file.path()).expect_err("error");
    assert!(error.contains("Config must be"));
}

#[test]
fn load_run_config_parses_json() {
    let file = tempfile::Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("file");
    let tenant_id = Uuid::new_v4();
    let config = format!(
        r#"{{
  "trace_db": "/tmp/trace.db",
  "state_db": "/tmp/state.db",
  "tenants": [{{"id": "{tenant_id}", "allowed_actions": ["noop"], "allowed_adapters": ["filesystem"]}}],
  "agents": [{{"tenant_id": "{tenant_id}", "policy": {{"type": "static", "actions": []}}}}]
}}"#
    );
    std::fs::write(file.path(), config).expect("write");
    let parsed = load_run_config(file.path()).expect("config");
    assert_eq!(parsed.tenants.len(), 1);
    assert_eq!(parsed.agents.len(), 1);
}

#[test]
fn run_from_config_requires_tenants() {
    let file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("file");
    let config = "trace_db: /tmp/trace.db\nstate_db: /tmp/state.db\ntenants: []\nagents: []\n";
    std::fs::write(file.path(), config).expect("write");
    let error = run_from_config(file.path(), Some(1), false).expect_err("error");
    assert!(error.contains("config must include at least one tenant"));
}

#[test]
fn run_from_config_requires_agents() {
    let file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("file");
    let tenant_id = Uuid::new_v4();
    let config = format!(
        "trace_db: /tmp/trace.db\nstate_db: /tmp/state.db\ntenants:\n  - id: {tenant_id}\n    allowed_actions: [\"noop\"]\n    allowed_adapters: [\"filesystem\"]\nagents: []\n"
    );
    std::fs::write(file.path(), config).expect("write");
    let error = run_from_config(file.path(), Some(1), false).expect_err("error");
    assert!(error.contains("config must include at least one agent"));
}

#[test]
fn build_adapters_rejects_invalid_http_method() {
    let adapters = AdaptersConfig {
        filesystem: None,
        http: Some(HttpConfig {
            allowed_domains: vec!["example.com".to_string()],
            allowed_methods: Some(vec!["PUT".to_string()]),
            max_request_bytes: None,
            max_response_bytes: None,
            timeout_ms: None,
        }),
    };
    let error = match build_adapters(Some(&adapters)) {
        Ok(_) => panic!("expected error"),
        Err(error) => error,
    };
    assert!(error.contains("Unsupported HTTP method"));
}

#[test]
fn build_gateway_rejects_missing_adapter() {
    let tenant_id = Uuid::new_v4();
    let config = RunConfig {
        trace_db: PathBuf::from("/tmp/trace.db"),
        state_db: PathBuf::from("/tmp/state.db"),
        run_id: None,
        tick_budget_ms: None,
        tick_interval_ms: None,
        cycles: None,
        allow_unsigned_local_run: None,
        tenants: vec![TenantConfig {
            id: tenant_id.to_string(),
            allowed_actions: vec!["noop".to_string()],
            allowed_adapters: vec!["filesystem".to_string()],
            allowed_permissions: None,
            quotas: None,
        }],
        agents: vec![AgentConfig {
            id: None,
            tenant_id: tenant_id.to_string(),
            run_id: None,
            snapshot_interval: None,
            initial_state: None,
            resume: None,
            allowed_permissions: None,
            allowed_message_schemas: None,
            allowed_message_recipients: None,
            percepts: None,
            policy: PolicyConfig::Static {
                actions: vec![ActionConfig {
                    name: "noop".to_string(),
                    adapter: Some("filesystem".to_string()),
                    params: serde_json::json!({}),
                    side_effect_class: Some("filesystem".to_string()),
                    required_permissions: None,
                    preconditions: None,
                    postconditions: None,
                    usage: None,
                    satisfied_preconditions: None,
                }],
                next_state: None,
            },
        }],
        adapters: None,
        work_order: None,
        runtime_identity: None,
        circuit_breakers: None,
        failure_injection: None,
    };
    let registry = build_registry_with_work_order(&config, None).expect("registry");
    let adapters = std::collections::HashMap::new();
    let error = match build_gateway(&adapters, &registry, &config) {
        Ok(_) => panic!("expected error"),
        Err(error) => error,
    };
    assert!(error.contains("Adapter not configured"));
}

fn resource_boundary_request(params: serde_json::Value) -> splendor_gateway::ActionRequest {
    splendor_gateway::ActionRequest {
        action_id: ActionId::new(),
        action: Action {
            name: "resource.check".to_string(),
            params,
            side_effect_class: SideEffectClass::External,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        },
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id: RunId::new(),
        tick_id: None,
        adapter: None,
        quota_usage: QuotaUsage::single_action(),
        satisfied_preconditions: Vec::new(),
        requested_at: OffsetDateTime::now_utc(),
        physical_action_resource_coordinate: None,
        approval_evidence: None,
        authority_obligation_evidence: None,
        authority_obligation_receipts: Vec::new(),
    }
}

#[test]
fn local_resource_boundary_verifier_covers_http_and_filesystem_paths() {
    let adapters = AdaptersConfig {
        filesystem: Some(FilesystemConfig {
            base_dir: PathBuf::from("/tmp/splendor-test"),
            max_read_bytes: None,
            max_write_bytes: None,
            max_list_entries: None,
        }),
        http: Some(HttpConfig {
            allowed_domains: vec![
                "example.com".to_string(),
                "*.trusted.test".to_string(),
                ".suffix.test".to_string(),
            ],
            allowed_methods: None,
            max_request_bytes: None,
            max_response_bytes: None,
            timeout_ms: None,
        }),
    };
    let verifier = LocalResourceBoundaryVerifier::from_config(Some(&adapters));
    let permissive = LocalResourceBoundaryVerifier::from_config(None);

    let unknown_adapter = verifier.verify_resource_boundary(
        &resource_boundary_request(serde_json::json!({"url": "https://blocked.test"})),
        Some("unknown"),
    );
    assert!(unknown_adapter.allowed);
    assert!(!domain_allowed(
        &permissive.http_allowed_domains,
        "example.com"
    ));

    let missing_url = verifier.verify_resource_boundary(
        &resource_boundary_request(serde_json::json!({})),
        Some("http"),
    );
    assert!(!missing_url.allowed);
    assert_eq!(missing_url.reasons, vec!["network_scope_missing_url"]);

    let invalid_url = verifier.verify_resource_boundary(
        &resource_boundary_request(serde_json::json!({"url": "ftp://example.com"})),
        Some("http"),
    );
    assert!(!invalid_url.allowed);
    assert_eq!(invalid_url.reasons, vec!["network_scope_invalid_url"]);

    let denied_host = verifier.verify_resource_boundary(
        &resource_boundary_request(serde_json::json!({"url": "https://evil.test/path"})),
        Some("http"),
    );
    assert!(!denied_host.allowed);
    assert_eq!(denied_host.reasons, vec!["network_scope_denied"]);
    assert_eq!(
        denied_host.artifacts["adapter_execution"],
        serde_json::json!("not_attempted")
    );

    for url in [
        "https://example.com/path",
        "https://api.trusted.test/v1",
        "https://child.suffix.test/data",
    ] {
        let result = verifier.verify_resource_boundary(
            &resource_boundary_request(serde_json::json!({"url": url})),
            Some("http"),
        );
        assert!(result.allowed, "expected URL to be allowed: {url}");
    }
    assert_eq!(
        http_host("https://user:pass@example.com:443/secret"),
        Some("example.com".to_string())
    );
    assert_eq!(http_host("https://"), None);

    let missing_path = verifier.verify_resource_boundary(
        &resource_boundary_request(serde_json::json!({})),
        Some("filesystem"),
    );
    assert!(!missing_path.allowed);
    assert_eq!(missing_path.reasons, vec!["filesystem_scope_missing_path"]);

    for path in ["../secret.txt", "/etc/passwd"] {
        let result = verifier.verify_resource_boundary(
            &resource_boundary_request(serde_json::json!({"path": path})),
            Some("filesystem"),
        );
        assert!(!result.allowed, "expected path to be denied: {path}");
        assert_eq!(result.reasons, vec!["filesystem_scope_denied"]);
    }

    for path in ["safe/file.txt", "./safe/file.txt"] {
        let result = verifier.verify_resource_boundary(
            &resource_boundary_request(serde_json::json!({"path": path})),
            Some("filesystem"),
        );
        assert!(result.allowed, "expected path to be allowed: {path}");
    }
}

#[test]
fn failure_injection_runtime_writer_fails_once_then_delegates() {
    let db = NamedTempFile::new().expect("trace db");
    let store = FailingTraceStore {
        inner: SqliteTraceStore::open(db.path()).expect("trace store"),
        fail_on_event: "tick.started".to_string(),
        failed: Arc::new(Mutex::new(false)),
    };
    let typed_run_id = RunId::new();
    let run_id = typed_run_id.to_string();
    let payload = serde_json::json!({
        "kind": "tick.started",
        "tick_id": 1,
        "identity": TraceIdentityContext::new(typed_run_id),
    });

    assert_eq!(
        trace_payload_kind(&payload),
        Some("tick.started".to_string())
    );
    let writer = store
        .acquire_runtime_writer(RuntimeTraceWriterRequest::current(
            RuntimeTraceScope::new(&run_id, "tenant", "agent"),
            RuntimeTraceLimits::default(),
        ))
        .expect("runtime writer");
    let tail = writer.tail().expect("tail");
    assert!(matches!(
        writer.append(&tail, payload.clone()),
        Err(RuntimeTracePortError::Unavailable)
    ));
    let append = writer
        .append(&tail, payload.clone())
        .expect("second append succeeds");
    assert_eq!(append.sequence(), 0);
    writer.close().expect("close writer");
    assert!(matches!(
        TraceStore::append(&store, &run_id, payload),
        Err(TraceStoreError::SequenceMismatch { .. })
    ));
    let records = TraceStore::read(&store, &run_id).expect("records");
    assert_eq!(records.len(), 1);
    let range = TraceStore::read_range(&store, &run_id, 0, 1).expect("range");
    assert_eq!(range.len(), 1);
}

#[test]
fn failure_injection_state_store_fails_once_then_delegates() {
    let db = NamedTempFile::new().expect("state db");
    let store = FailingStateStore {
        inner: SqliteStateStore::open(db.path()).expect("state store"),
        fail_commit: true,
        failed: Mutex::new(false),
    };
    let data_ref = StateStore::put_state(
        &store,
        StateData {
            bytes: b"state".to_vec(),
            content_type: Some("text/plain".to_string()),
        },
    )
    .expect("state data");
    let metadata = || StateMetadata {
        created_at: OffsetDateTime::now_utc(),
        label: Some("unit".to_string()),
        tenant_id: Some(TenantId::new()),
        agent_id: Some(AgentId::new()),
        run_id: Some(RunId::new()),
        trace_event_id: Some(TraceEventId::new()),
    };

    let error = StateStore::commit_node(&store, Vec::new(), data_ref.clone(), metadata())
        .expect_err("first commit fails");
    assert!(error.to_string().contains("injected_state_commit_failure"));

    let node_id = StateStore::commit_node(&store, Vec::new(), data_ref.clone(), metadata())
        .expect("second commit succeeds");
    let node = StateStore::get_node(&store, &node_id).expect("node");
    assert_eq!(node.id, node_id);
    let loaded = StateStore::get_state(&store, &data_ref).expect("state");
    assert_eq!(loaded.bytes, b"state".to_vec());
    let snapshot_id = StateStore::snapshot(&store, &node_id).expect("snapshot");
    let snapshot = StateStore::load_snapshot(&store, &snapshot_id).expect("load snapshot");
    assert_eq!(snapshot.node_id, node_id);
}

#[test]
fn substitute_counter_updates_nested_values() {
    let value = serde_json::json!({
        "path": "tick_{counter}.txt",
        "nested": ["{counter}", {"value": "{counter}"}]
    });
    let updated = substitute_counter(&value, 7);
    assert_eq!(updated["path"], "tick_7.txt");
    assert_eq!(updated["nested"][0], "7");
    assert_eq!(updated["nested"][1]["value"], "7");
}

#[test]
fn parse_snapshot_id_rejects_invalid_format() {
    let error = parse_snapshot_id("invalid").expect_err("error");
    assert_eq!(error, "replay_snapshot_id_invalid");
}

#[test]
fn parse_snapshot_id_rejects_unknown_algorithm() {
    let error = parse_snapshot_id("nope:abc").expect_err("error");
    assert_eq!(error, "replay_snapshot_id_invalid");
}

#[test]
fn find_tick_for_snapshot_returns_none() {
    let run_id = RunId::new();
    let event = TraceEvent::new(
        run_id,
        0,
        OffsetDateTime::now_utc(),
        TraceEventKind::LoopTickStarted { tick_id: 1 },
    );
    assert!(
        find_tick_for_snapshot(&[event], &SnapshotId::from_hash(ContentHash::blake3("x")))
            .is_none()
    );
}

#[test]
fn parse_args_accepts_run_forever() {
    let command = parse_args(vec![
        "run".to_string(),
        "--config".to_string(),
        "/tmp/config.yaml".to_string(),
        "--forever".to_string(),
    ])
    .expect("parse args");
    match command {
        Command::Run {
            config_path,
            cycles,
            forever,
        } => {
            assert_eq!(config_path, PathBuf::from("/tmp/config.yaml"));
            assert!(cycles.is_none());
            assert!(forever);
        }
        _ => panic!("unexpected command"),
    }
}

#[test]
fn parse_args_rejects_unknown_run_argument() {
    let error = parse_args(vec![
        "run".to_string(),
        "--config".to_string(),
        "/tmp/config.yaml".to_string(),
        "--unknown".to_string(),
    ])
    .expect_err("error");
    assert!(error.contains("Unknown argument"));
}

#[test]
fn work_order_sign_parses_and_signs_fixture() {
    let input = tempfile::Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("work order file");
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let now = OffsetDateTime::now_utc();
    let order = WorkOrder {
        schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new("wo_cli_sign").expect("work order id"),
        tenant_id,
        agent_id,
        run_id: Some(run_id),
        objective: "sign local fixture".to_string(),
        allowed_actions: vec!["write_file".to_string()],
        allowed_adapters: vec!["filesystem".to_string()],
        allowed_permissions: vec!["fs.write".to_string()],
        data_refs: vec!["dataset:fixture".to_string()],
        quotas: splendor_types::WorkOrderQuotaPolicy {
            max_actions_per_tick: Some(1),
            ..splendor_types::WorkOrderQuotaPolicy::default()
        },
        placement: splendor_types::WorkOrderPlacement {
            target: "local_resident".to_string(),
            data_locality: Some("local".to_string()),
            requires_gpu: Some(false),
            ..splendor_types::WorkOrderPlacement::default()
        },
        issued_at: now,
        expires_at: now + time::Duration::minutes(5),
        revocation: splendor_types::RevocationStatus::Active,
    };
    std::fs::write(
        input.path(),
        serde_json::to_string(&order).expect("encode work order"),
    )
    .expect("write work order");

    let command = parse_args(vec![
        "work-order".to_string(),
        "sign".to_string(),
        "--input".to_string(),
        input.path().to_string_lossy().to_string(),
        "--key-id".to_string(),
        "local-key".to_string(),
        "--secret".to_string(),
        "secret".to_string(),
    ])
    .expect("parse sign command");
    match command {
        Command::WorkOrderSign {
            input_path,
            key_id,
            secret,
        } => {
            assert_eq!(input_path, input.path());
            assert_eq!(key_id, "local-key");
            assert_eq!(secret, "secret");
        }
        _ => panic!("unexpected command"),
    }

    sign_work_order(input.path(), "local-key", "secret").expect("sign work order");
}

#[test]
fn resolve_config_path_rejects_empty_directory() {
    let dir = tempfile::TempDir::new().expect("dir");
    let error = resolve_config_path(dir.path()).expect_err("error");
    assert!(error.contains("No config file found"));
}

#[test]
fn build_action_candidate_applies_usage() {
    let config = ActionConfig {
        name: "noop".to_string(),
        adapter: Some("filesystem".to_string()),
        params: serde_json::json!({"path": "file"}),
        side_effect_class: Some("filesystem".to_string()),
        required_permissions: Some(vec!["perm".to_string()]),
        preconditions: Some(vec!["ready".to_string()]),
        postconditions: Some(vec!["done".to_string()]),
        usage: Some(QuotaUsageConfig {
            actions: Some(2),
            action_duration_ms: Some(10),
            filesystem_read_bytes: Some(5),
            filesystem_write_bytes: Some(7),
            network_read_bytes: Some(1),
            network_write_bytes: Some(2),
            http_requests: Some(3),
        }),
        satisfied_preconditions: Some(vec!["ready".to_string()]),
    };
    let candidate = build_action_candidate(&config, None).expect("candidate");
    assert_eq!(candidate.adapter.as_deref(), Some("filesystem"));
    assert_eq!(
        candidate.action.side_effect_class,
        SideEffectClass::Filesystem
    );
    assert_eq!(
        candidate.action.required_permissions,
        vec!["perm".to_string()]
    );
    assert_eq!(candidate.usage.actions, 2);
    assert_eq!(candidate.usage.http_requests, 3);
    assert_eq!(candidate.satisfied_preconditions, vec!["ready".to_string()]);
}

#[test]
fn apply_event_to_tick_populates_fields() {
    let temp = NamedTempFile::new().expect("state db");
    let store = SqliteStateStore::open(temp.path()).expect("store");
    let data_ref = store
        .put_state(StateData {
            bytes: vec![1],
            content_type: None,
        })
        .expect("state bytes");
    let metadata = StateMetadata {
        created_at: OffsetDateTime::now_utc(),
        label: None,
        tenant_id: None,
        agent_id: None,
        run_id: None,
        trace_event_id: None,
    };
    let node_id = store
        .commit_node(Vec::new(), data_ref, metadata)
        .expect("commit");
    let snapshot_id = store.snapshot(&node_id).expect("snapshot");

    let run_id = RunId::new();
    let timestamp = OffsetDateTime::now_utc();
    let percept = Percept {
        schema: "sensor".to_string(),
        payload: serde_json::json!({"value": 1}),
        provenance: PerceptProvenance {
            source: "unit".to_string(),
            detail: None,
        },
        timestamp,
    };
    let action = Action {
        name: "noop".to_string(),
        params: serde_json::json!({"ok": true}),
        side_effect_class: SideEffectClass::ReadOnly,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    };
    let outcome_value = serde_json::json!({"result": "ok"});
    let source_agent_id = AgentId::new();
    let target_agent_id = AgentId::new();
    let message = MessageTraceContext {
        message_id: MessageId::new(),
        source_agent_id: source_agent_id.clone(),
        target_agent_id: target_agent_id.clone(),
        run_id: run_id.clone(),
        schema: "splendor.message.task_request.v1".to_string(),
        causal_parent: Some(TraceId::from_run_sequence(&run_id, 5)),
    };
    let feedback = Feedback {
        kind: "signal".to_string(),
        payload: serde_json::json!({"k": 1}),
        recorded_at: timestamp,
    };
    let reward = Reward {
        value: 1.0,
        units: Some("pts".to_string()),
        recorded_at: timestamp,
        context: None,
    };

    let events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            timestamp,
            TraceEventKind::PerceptsReceived {
                percepts: vec![percept.clone()],
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            timestamp,
            TraceEventKind::PolicyInvoked {
                policy: "policy".to_string(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            2,
            timestamp,
            TraceEventKind::PolicyCompleted {
                policy: "policy-completed".to_string(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            3,
            timestamp,
            TraceEventKind::CandidatesProposed {
                actions: vec![action.clone()],
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            4,
            timestamp,
            TraceEventKind::ConstraintsEvaluated {
                constraints: Vec::new(),
                result: VerificationResult::allow(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            5,
            timestamp,
            TraceEventKind::ActionExecuted {
                action: action.clone(),
                outcome: outcome_value.clone(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            6,
            timestamp,
            TraceEventKind::ActionDenied {
                action: action.clone(),
                result: VerificationResult::deny("denied"),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            7,
            timestamp,
            TraceEventKind::ActionFailed {
                action: action.clone(),
                error: "adapter failed".to_string(),
                result: VerificationResult::deny("failed"),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            8,
            timestamp,
            TraceEventKind::MessageRejected {
                message: message.clone(),
                reason: "agent_isolation_ledger denied message_schema_not_allowed".to_string(),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            9,
            timestamp,
            TraceEventKind::OutcomeRecorded {
                outcome: outcome_value.clone(),
                feedback: Some(feedback.clone()),
                reward: Some(reward.clone()),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            10,
            timestamp,
            TraceEventKind::StateCommitted {
                state_hash: node_id.hash().clone(),
                snapshot_id: Some(snapshot_id.clone()),
            },
        ),
    ];

    let mut tick = ReplayTick {
        tick_id: 1,
        ..ReplayTick::default()
    };
    for event in events {
        apply_event_to_tick(&mut tick, &event, &store, true).expect("apply");
    }

    assert_eq!(tick.percepts.len(), 1);
    assert_eq!(tick.policy.as_deref(), Some("policy-completed"));
    assert_eq!(tick.candidates.len(), 1);
    assert!(tick
        .constraints
        .as_ref()
        .map(|value| value.allowed)
        .unwrap_or(false));
    assert_eq!(tick.actions.len(), 3);
    assert_eq!(tick.actions[0].status, "executed");
    assert_eq!(tick.actions[1].status, "denied");
    assert_eq!(tick.actions[2].status, "failed");
    assert_eq!(tick.messages.len(), 1);
    assert_eq!(tick.messages[0].lifecycle, "rejected");
    assert_eq!(tick.messages[0].source_agent_id, source_agent_id);
    assert_eq!(tick.messages[0].target_agent_id, target_agent_id);
    assert!(tick.messages[0]
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("agent_isolation_ledger"));
    assert_eq!(tick.outcome, Some(outcome_value));
    assert_eq!(tick.feedback.as_ref().unwrap().kind, "signal");
    assert_eq!(tick.reward.as_ref().unwrap().value, 1.0);
    assert_eq!(tick.state_hash.as_ref(), Some(node_id.hash()));
    assert_eq!(tick.snapshot_id.as_ref(), Some(&snapshot_id));
    assert_eq!(tick.snapshot_bytes_len, Some(1));
    assert_eq!(tick.snapshot_bytes.as_ref().unwrap().len(), 1);
}

#[test]
fn parse_args_rejects_missing_command() {
    let error = parse_args(Vec::<String>::new()).expect_err("error");
    assert!(error.contains("splendorctl"));
}

#[test]
fn parse_args_trace_requires_subcommand() {
    let error = parse_args(vec!["trace".to_string()]).expect_err("error");
    assert!(error.contains("trace export"));
}

#[test]
fn parse_args_replay_help_returns_usage() {
    let error = parse_args(vec!["replay".to_string(), "--help".to_string()]).expect_err("error");
    assert!(error.contains("splendorctl"));
}

#[test]
fn parse_args_run_missing_config_value() {
    let error = parse_args(vec!["run".to_string(), "--config".to_string()]).expect_err("error");
    assert!(error.contains("Missing value for --config"));
}

#[test]
fn parse_args_replay_missing_db_value() {
    let error = parse_args(vec!["replay".to_string(), "--db".to_string()]).expect_err("error");
    assert!(error.contains("Missing value for --db"));
}

#[test]
fn parse_args_run_cycles_missing_value() {
    let error = parse_args(vec![
        "run".to_string(),
        "--config".to_string(),
        "/tmp/config.yaml".to_string(),
        "--cycles".to_string(),
    ])
    .expect_err("error");
    assert!(error.contains("Missing value for --cycles"));
}

#[test]
fn run_with_args_trace_export_succeeds() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let trace_store = SqliteTraceStore::open(trace_temp.path()).expect("trace store");
    let run_id = RunId::new();
    append_valid_trace_records(&trace_store, &run_id);

    run_with_args(vec![
        "trace".to_string(),
        "export".to_string(),
        "--db".to_string(),
        trace_temp.path().display().to_string(),
        "--run".to_string(),
        run_id.to_string(),
    ])
    .expect("run with args");
}

#[test]
fn run_with_args_daemon_request_succeeds() {
    let body = NamedTempFile::new().expect("body");
    std::fs::write(
        body.path(),
        r#"{"credential":{"credential_id":"cred"},"audit_attribution":{"caller":"cli-test"}}"#,
    )
    .expect("write body");
    let (url, handle) = spawn_local_daemon_response(200, r#"{"accepted":true}"#);

    run_with_args(vec![
        "daemon".to_string(),
        "request".to_string(),
        "--method".to_string(),
        "POST".to_string(),
        "--url".to_string(),
        url,
        "--body".to_string(),
        body.path().display().to_string(),
        "--token".to_string(),
        "token".to_string(),
    ])
    .expect("daemon request");

    let request = handle.join().expect("daemon request captured");
    assert!(request.starts_with("POST /runs HTTP/1.1"));
    assert!(request.contains("Authorization: Bearer token"));
}

#[test]
fn run_with_args_work_order_sign_succeeds() {
    let input = tempfile::Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("work order file");
    let order = WorkOrder {
        schema_version: splendor_types::WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new("wo_cli_run_with_args").expect("work order id"),
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id: Some(RunId::new()),
        objective: "sign via command dispatch".to_string(),
        allowed_actions: vec!["write_file".to_string()],
        allowed_adapters: vec!["filesystem".to_string()],
        allowed_permissions: vec!["fs.write".to_string()],
        data_refs: vec!["dataset:fixture".to_string()],
        quotas: splendor_types::WorkOrderQuotaPolicy {
            max_actions_per_tick: Some(1),
            ..splendor_types::WorkOrderQuotaPolicy::default()
        },
        placement: splendor_types::WorkOrderPlacement {
            target: "local_resident".to_string(),
            data_locality: Some("local".to_string()),
            requires_gpu: Some(false),
            ..splendor_types::WorkOrderPlacement::default()
        },
        issued_at: OffsetDateTime::now_utc() - time::Duration::minutes(1),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(10),
        revocation: splendor_types::RevocationStatus::Active,
    };
    std::fs::write(
        input.path(),
        serde_json::to_string(&order).expect("order json"),
    )
    .expect("write work order");

    run_with_args(vec![
        "work-order".to_string(),
        "sign".to_string(),
        "--input".to_string(),
        input.path().display().to_string(),
        "--key-id".to_string(),
        "local-key".to_string(),
        "--secret".to_string(),
        "local-secret".to_string(),
    ])
    .expect("work order sign");
}

#[test]
fn run_with_args_replay_succeeds() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let state_temp = NamedTempFile::new().expect("state db");
    let trace_store = SqliteTraceStore::open(trace_temp.path()).expect("trace store");
    let state_store = SqliteStateStore::open(state_temp.path()).expect("state store");

    let data_ref = state_store
        .put_state(StateData {
            bytes: b"state".to_vec(),
            content_type: None,
        })
        .expect("state");
    let node_id = state_store
        .commit_node(
            Vec::new(),
            data_ref,
            StateMetadata {
                created_at: OffsetDateTime::now_utc(),
                label: None,
                tenant_id: None,
                agent_id: None,
                run_id: None,
                trace_event_id: None,
            },
        )
        .expect("commit");
    let snapshot_id = state_store.snapshot(&node_id).expect("snapshot");

    let run_id = RunId::new();
    let timestamp = OffsetDateTime::now_utc();
    let events = vec![
        TraceEvent::new(
            run_id.clone(),
            0,
            timestamp,
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        ),
        TraceEvent::new(
            run_id.clone(),
            1,
            timestamp,
            TraceEventKind::StateCommitted {
                state_hash: node_id.hash().clone(),
                snapshot_id: Some(snapshot_id.clone()),
            },
        ),
        TraceEvent::new(
            run_id.clone(),
            2,
            timestamp,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        ),
    ];
    for event in events {
        TraceStore::append(
            &trace_store,
            &run_id.to_string(),
            serde_json::to_value(event).unwrap(),
        )
        .expect("append");
    }

    run_with_args(vec![
        "replay".to_string(),
        "--db".to_string(),
        trace_temp.path().display().to_string(),
        "--state-db".to_string(),
        state_temp.path().display().to_string(),
        "--run".to_string(),
        run_id.to_string(),
    ])
    .expect("replay");
}

#[test]
fn run_with_args_version_succeeds() {
    assert_eq!(SPLENDOR_RELEASE_LABEL, "Splendor0.05-dev");
    run_with_args(vec!["--version".to_string()]).expect("version");
}

#[test]
fn run_with_args_run_succeeds() {
    let trace_temp = NamedTempFile::new().expect("trace db");
    let state_temp = NamedTempFile::new().expect("state db");
    let config_temp = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("config");
    let tenant_id = Uuid::new_v4();
    let run_id = Uuid::new_v4();
    let config = format!(
        "trace_db: {}\nstate_db: {}\nrun_id: {}\nallow_unsigned_local_run: true\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\nagents:\n  - tenant_id: {}\n    run_id: {}\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          params:\n            path: \"hello.txt\"\n            contents: \"hi\"\nadapters:\n  filesystem:\n    base_dir: {}\n",
        trace_temp.path().display(),
        state_temp.path().display(),
        run_id,
        tenant_id,
        tenant_id,
        run_id,
        config_temp.path().parent().unwrap().display(),
    );
    std::fs::write(config_temp.path(), config).expect("write");

    run_with_args(vec![
        "run".to_string(),
        "--config".to_string(),
        config_temp.path().display().to_string(),
        "--cycles".to_string(),
        "1".to_string(),
    ])
    .expect("run");
}

#[test]
fn run_with_args_unknown_command_errors() {
    let error = run_with_args(vec!["unknown".to_string()]).expect_err("error");
    assert!(error.contains("Unknown command"));
}

#[test]
fn run_from_config_creates_parent_directories() {
    let dir = tempfile::TempDir::new().expect("dir");
    let trace_dir = dir.path().join("trace");
    let state_dir = dir.path().join("state");
    let trace_path = trace_dir.join("trace.db");
    let state_path = state_dir.join("state.db");
    let config_path = dir.path().join("config.yaml");
    let tenant_id = Uuid::new_v4();
    let config = format!(
        "trace_db: {}\nstate_db: {}\nallow_unsigned_local_run: true\ntenants:\n  - id: {}\n    allowed_actions: [\"write_file\"]\n    allowed_adapters: [\"filesystem\"]\nagents:\n  - tenant_id: {}\n    policy:\n      type: static\n      actions:\n        - name: write_file\n          adapter: filesystem\n          side_effect_class: filesystem\n          params:\n            path: \"hello.txt\"\n            contents: \"hi\"\nadapters:\n  filesystem:\n    base_dir: {}\n",
        trace_path.display(),
        state_path.display(),
        tenant_id,
        tenant_id,
        dir.path().display(),
    );
    std::fs::write(&config_path, config).expect("write");

    run_from_config(&config_path, Some(1), false).expect("run config");
    assert!(trace_dir.exists());
    assert!(state_dir.exists());
}

#[test]
fn build_adapters_success() {
    let dir = tempfile::TempDir::new().expect("dir");
    let adapters = AdaptersConfig {
        filesystem: Some(FilesystemConfig {
            base_dir: dir.path().to_path_buf(),
            max_read_bytes: None,
            max_write_bytes: None,
            max_list_entries: None,
        }),
        http: Some(HttpConfig {
            allowed_domains: vec!["example.com".to_string()],
            allowed_methods: Some(vec!["GET".to_string()]),
            max_request_bytes: None,
            max_response_bytes: None,
            timeout_ms: None,
        }),
    };
    let built = build_adapters(Some(&adapters)).expect("adapters");
    assert!(built.contains_key("filesystem"));
    assert!(built.contains_key("http"));
}

#[test]
fn build_gateway_success() {
    let dir = tempfile::TempDir::new().expect("dir");
    let tenant_id = Uuid::new_v4();
    let config = RunConfig {
        trace_db: PathBuf::from("/tmp/trace.db"),
        state_db: PathBuf::from("/tmp/state.db"),
        run_id: None,
        tick_budget_ms: None,
        tick_interval_ms: None,
        cycles: None,
        allow_unsigned_local_run: None,
        tenants: vec![TenantConfig {
            id: tenant_id.to_string(),
            allowed_actions: vec!["write_file".to_string()],
            allowed_adapters: vec!["filesystem".to_string()],
            allowed_permissions: None,
            quotas: None,
        }],
        agents: vec![AgentConfig {
            id: None,
            tenant_id: tenant_id.to_string(),
            run_id: None,
            snapshot_interval: None,
            initial_state: None,
            resume: None,
            allowed_permissions: None,
            allowed_message_schemas: None,
            allowed_message_recipients: None,
            percepts: None,
            policy: PolicyConfig::Static {
                actions: vec![ActionConfig {
                    name: "write_file".to_string(),
                    adapter: Some("filesystem".to_string()),
                    params: serde_json::json!({"path": "file", "contents": "hi"}),
                    side_effect_class: Some("filesystem".to_string()),
                    required_permissions: None,
                    preconditions: None,
                    postconditions: None,
                    usage: None,
                    satisfied_preconditions: None,
                }],
                next_state: None,
            },
        }],
        adapters: Some(AdaptersConfig {
            filesystem: Some(FilesystemConfig {
                base_dir: dir.path().to_path_buf(),
                max_read_bytes: None,
                max_write_bytes: None,
                max_list_entries: None,
            }),
            http: None,
        }),
        work_order: None,
        runtime_identity: None,
        circuit_breakers: None,
        failure_injection: None,
    };
    let registry = build_registry_with_work_order(&config, None).expect("registry");
    let adapters = build_adapters(config.adapters.as_ref()).expect("adapters");
    let gateway = build_gateway(&adapters, &registry, &config).expect("gateway");
    let mut request = splendor_gateway::ActionRequest {
        action_id: splendor_gateway::ActionId::new(),
        action: Action {
            name: "write_file".to_string(),
            params: serde_json::json!({"path": "file", "contents": "hi"}),
            side_effect_class: SideEffectClass::Filesystem,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        },
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id: splendor_types::RunId::new(),
        tick_id: None,
        adapter: Some("filesystem".to_string()),
        quota_usage: QuotaUsage::single_action(),
        satisfied_preconditions: Vec::new(),
        requested_at: OffsetDateTime::now_utc(),
        physical_action_resource_coordinate: None,
        approval_evidence: None,
        authority_obligation_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    request.action.name = "write_file".to_string();
    let _ = gateway.submit(request).expect("submit");
}

#[test]
fn build_action_candidate_defaults_side_effect_class() {
    let config = ActionConfig {
        name: "noop".to_string(),
        adapter: None,
        params: serde_json::json!({}),
        side_effect_class: None,
        required_permissions: None,
        preconditions: None,
        postconditions: None,
        usage: None,
        satisfied_preconditions: None,
    };
    let candidate = build_action_candidate(&config, None).expect("candidate");
    assert_eq!(
        candidate.action.side_effect_class,
        SideEffectClass::ReadOnly
    );
}

#[test]
fn build_action_candidate_rejects_malformed_or_downgraded_side_effect_class() {
    let mut config = ActionConfig {
        name: "write_file".to_string(),
        adapter: Some("filesystem".to_string()),
        params: serde_json::json!({"path": "file", "contents": "hi"}),
        side_effect_class: Some("read_only".to_string()),
        required_permissions: None,
        preconditions: None,
        postconditions: None,
        usage: None,
        satisfied_preconditions: None,
    };

    let error = build_action_candidate(&config, None).expect_err("adapter downgrade rejected");
    assert!(error.contains("conflicts with adapter-derived class"));

    config.adapter = None;
    config.side_effect_class = Some("filesytem".to_string());
    let error = build_action_candidate(&config, None).expect_err("unknown class rejected");
    assert!(error.contains("Unsupported side_effect_class"));

    config.side_effect_class = Some("custom:domain".to_string());
    let candidate = build_action_candidate(&config, None).expect("custom class");
    assert_eq!(
        candidate.action.side_effect_class,
        SideEffectClass::Custom("domain".to_string())
    );
}
