use splendor_adapter_filesystem::{FilesystemAdapter, FilesystemAdapterConfig};
use splendor_adapter_http::{HttpAdapter, HttpAdapterConfig};
use splendor_gateway::{
    raw_credential_denied_action, ActionAdapter, ActionGateway, ActionId, ActionRequest,
    ActionStatus, AdapterError, AdapterResult, VerifiedActionGateway, RAW_CREDENTIAL_INPUT_DENIED,
};
use splendor_kernel::{
    ActionCandidate, AgentContext, AgentId, AgentRuntimeConfig, LoopEngine, LoopError, Perceptor,
    Policy, PolicyDecision, QuotaPolicy, RunId, SnapshotPolicy, StateGraph, TenantContext,
    TenantPolicy, TenantRegistry, TraceEvent, TraceEventKind,
};
use splendor_store::{
    InMemoryStateStore, InMemoryTraceStore, StateData, StateStore, TraceRecord, TraceStore,
    TraceStoreError,
};
use splendor_types::{Action, Percept, PerceptProvenance, QuotaUsage, SideEffectClass, TenantId};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

const TICK_ID: u64 = 1;

struct StaticPerceptor;

impl Perceptor for StaticPerceptor {
    fn collect(&self, _agent: &AgentContext) -> Result<Vec<Percept>, splendor_kernel::LoopError> {
        Ok(vec![Percept {
            schema: "sensor".to_string(),
            payload: serde_json::json!({"value": 1}),
            provenance: PerceptProvenance {
                source: "integration".to_string(),
                detail: None,
            },
            timestamp: OffsetDateTime::now_utc(),
        }])
    }
}

struct StaticPolicy {
    name: String,
    actions: Vec<ActionCandidate>,
    next_state: StateData,
}

impl Policy for StaticPolicy {
    fn name(&self) -> &str {
        &self.name
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, splendor_kernel::LoopError> {
        Ok(PolicyDecision::new(
            self.actions.clone(),
            self.next_state.clone(),
            None,
        ))
    }
}

struct TestServer {
    url: String,
    handle: std::thread::JoinHandle<()>,
}

impl TestServer {
    fn start(body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("set request read timeout");
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                loop {
                    let bytes_read = stream.read(&mut buffer).expect("read request");
                    if bytes_read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..bytes_read]);

                    let Some(header_end) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let content_length = std::str::from_utf8(&request[..header_end])
                        .expect("request headers are UTF-8")
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            url: format!("http://{addr}/"),
            handle,
        }
    }

    fn join(self) {
        self.handle.join().expect("server thread");
    }
}

struct CountingAdapter {
    inner: Arc<dyn ActionAdapter>,
    executions: Arc<AtomicUsize>,
}

impl CountingAdapter {
    fn new(adapter: impl ActionAdapter + 'static) -> Self {
        Self {
            inner: Arc::new(adapter),
            executions: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn executions(&self) -> usize {
        self.executions.load(Ordering::SeqCst)
    }
}

impl ActionAdapter for CountingAdapter {
    fn execute(&self, action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        self.inner.execute(action)
    }
}

struct FaultyAdapter;

impl ActionAdapter for FaultyAdapter {
    fn execute(&self, _action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        Err(AdapterError::Failed(
            "intentional adapter fault".to_string(),
        ))
    }
}

struct FailingActionVerificationTraceStore {
    inner: InMemoryTraceStore,
    failed: AtomicBool,
}

impl Default for FailingActionVerificationTraceStore {
    fn default() -> Self {
        Self {
            inner: InMemoryTraceStore::default(),
            failed: AtomicBool::new(false),
        }
    }
}

impl TraceStore for FailingActionVerificationTraceStore {
    fn append(&self, run_id: &str, payload: serde_json::Value) -> Result<u64, TraceStoreError> {
        let event: TraceEvent = serde_json::from_value(payload.clone()).expect("trace event");
        if matches!(event.kind, TraceEventKind::ActionVerificationStarted { .. })
            && !self.failed.swap(true, Ordering::SeqCst)
        {
            return Err(TraceStoreError::Poisoned);
        }
        self.inner.append(run_id, payload)
    }

    fn read(&self, run_id: &str) -> Result<Vec<TraceRecord>, TraceStoreError> {
        self.inner.read(run_id)
    }

    fn read_range(
        &self,
        run_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<TraceRecord>, TraceStoreError> {
        self.inner.read_range(run_id, start, end)
    }
}

struct HarnessRegistration {
    action_name: String,
    adapter_id: String,
    adapter: Arc<dyn ActionAdapter>,
}

impl HarnessRegistration {
    fn new(
        action_name: impl Into<String>,
        adapter_id: impl Into<String>,
        adapter: Arc<impl ActionAdapter + 'static>,
    ) -> Self {
        Self {
            action_name: action_name.into(),
            adapter_id: adapter_id.into(),
            adapter,
        }
    }
}

struct AdapterHarnessCase {
    policy_name: String,
    registrations: Vec<HarnessRegistration>,
    actions: Vec<ActionCandidate>,
    next_state: StateData,
}

impl AdapterHarnessCase {
    fn new(
        policy_name: impl Into<String>,
        registrations: Vec<HarnessRegistration>,
        actions: Vec<ActionCandidate>,
    ) -> Self {
        Self {
            policy_name: policy_name.into(),
            registrations,
            actions,
            next_state: StateData {
                bytes: vec![1],
                content_type: None,
            },
        }
    }
}

struct AdapterHarnessRun {
    outcome: splendor_kernel::TickOutcome,
    events: Vec<TraceEvent>,
    state_store: Arc<InMemoryStateStore>,
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: RunId,
}

fn build_registry(tenant_id: &TenantId, actions: &[String], adapters: &[String]) -> TenantRegistry {
    let policy = TenantPolicy {
        allowed_actions: actions.to_vec(),
        allowed_adapters: adapters.to_vec(),
        allowed_permissions: Vec::new(),
    };
    let registry = TenantRegistry::new();
    registry.insert(TenantContext::new(
        tenant_id.clone(),
        policy,
        QuotaPolicy::default(),
    ));
    registry
}

fn action(name: impl Into<String>, params: serde_json::Value, class: SideEffectClass) -> Action {
    Action {
        name: name.into(),
        params,
        side_effect_class: class,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    }
}

fn read_events(trace_store: &dyn TraceStore, run_id: &RunId) -> Vec<TraceEvent> {
    trace_store
        .read(&run_id.to_string())
        .expect("records")
        .into_iter()
        .map(|record| serde_json::from_value(record.payload).expect("event"))
        .collect()
}

fn run_adapter_case(case: AdapterHarnessCase) -> AdapterHarnessRun {
    let tenant_id = TenantId::new();
    let allowed_actions = case
        .registrations
        .iter()
        .map(|registration| registration.action_name.clone())
        .collect::<Vec<_>>();
    let allowed_adapters = case
        .registrations
        .iter()
        .map(|registration| registration.adapter_id.clone())
        .collect::<Vec<_>>();
    let registry = build_registry(&tenant_id, &allowed_actions, &allowed_adapters);
    registry.begin_tick(TICK_ID, OffsetDateTime::now_utc());

    let mut gateway = VerifiedActionGateway::new(Arc::new(registry));
    for registration in case.registrations {
        gateway.register_adapter(
            registration.action_name,
            registration.adapter_id,
            registration.adapter,
        );
    }
    let gateway: Arc<dyn ActionGateway> = Arc::new(gateway);

    let policy = StaticPolicy {
        name: case.policy_name,
        actions: case.actions,
        next_state: case.next_state,
    };
    let state_store = Arc::new(InMemoryStateStore::default());
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let graph = StateGraph::new(
        state_store.clone(),
        SnapshotPolicy {
            interval: Some(1),
            important_labels: Vec::new(),
        },
    );
    let agent_id = AgentId::new();
    let agent = AgentContext::new(
        agent_id.clone(),
        tenant_id.clone(),
        AgentRuntimeConfig::default(),
    );
    let run_id = RunId::new();
    let mut engine = LoopEngine::with_trace_store(
        agent,
        graph,
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(policy),
        gateway,
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");
    engine.add_perceptor(StaticPerceptor);

    let outcome = engine.tick(TICK_ID).expect("tick");
    let events = read_events(trace_store.as_ref(), &run_id);
    AdapterHarnessRun {
        outcome,
        events,
        state_store,
        tenant_id,
        agent_id,
        run_id,
    }
}

fn action_candidate(action: Action, adapter: &str) -> ActionCandidate {
    ActionCandidate::new(action).with_adapter(adapter)
}

fn assert_action_status(run: &AdapterHarnessRun, index: usize, expected: ActionStatus) {
    assert_eq!(run.outcome.action_outcomes[index].status, expected);
}

fn find_action_event<'a>(
    run: &'a AdapterHarnessRun,
    action_id: &ActionId,
    description: &str,
    predicate: impl Fn(&TraceEventKind) -> bool,
) -> &'a TraceEvent {
    run.events
        .iter()
        .find(|event| {
            event.identity.action_id.as_ref() == Some(action_id) && predicate(&event.kind)
        })
        .unwrap_or_else(|| panic!("missing {description}"))
}

fn assert_verification_completed_allowed(
    run: &AdapterHarnessRun,
    action_id: &ActionId,
    action_name: &str,
) {
    let verification = find_action_event(run, action_id, "ActionVerificationCompleted", |kind| {
        matches!(kind, TraceEventKind::ActionVerificationCompleted { .. })
    });
    if let TraceEventKind::ActionVerificationCompleted { action, result } = &verification.kind {
        assert_eq!(action.name, action_name);
        assert!(
            result.allowed,
            "adapter failure cases should pass gateway verification before adapter execution"
        );
    } else {
        unreachable!("predicate matched a different event kind");
    }
}

fn assert_action_executed_trace(run: &AdapterHarnessRun, outcome_index: usize, action_name: &str) {
    let action_id = &run.outcome.action_outcomes[outcome_index].action_id;
    assert_verification_completed_allowed(run, action_id, action_name);
    let executed = find_action_event(run, action_id, "ActionExecuted", |kind| {
        matches!(kind, TraceEventKind::ActionExecuted { .. })
    });
    if let TraceEventKind::ActionExecuted { action, .. } = &executed.kind {
        assert_eq!(action.name, action_name);
    } else {
        unreachable!("predicate matched a different event kind");
    }
    assert!(
        !run.events.iter().any(|event| {
            event.identity.action_id.as_ref() == Some(action_id)
                && matches!(event.kind, TraceEventKind::ActionFailed { .. })
        }),
        "successful action should not also emit ActionFailed"
    );
}

fn assert_action_failed_trace(
    run: &AdapterHarnessRun,
    outcome_index: usize,
    action_name: &str,
    reason: &str,
) {
    let action_id = &run.outcome.action_outcomes[outcome_index].action_id;
    assert_verification_completed_allowed(run, action_id, action_name);
    let failed = find_action_event(run, action_id, "ActionFailed", |kind| {
        matches!(kind, TraceEventKind::ActionFailed { .. })
    });
    if let TraceEventKind::ActionFailed {
        action,
        error,
        result,
    } = &failed.kind
    {
        assert_eq!(action.name, action_name);
        assert!(
            error.contains(reason),
            "error did not contain {reason:?}: {error}"
        );
        assert!(!result.allowed);
        assert!(
            result
                .reasons
                .iter()
                .any(|recorded| recorded.contains(reason)),
            "failure reasons did not contain {reason:?}: {:?}",
            result.reasons
        );
    } else {
        unreachable!("predicate matched a different event kind");
    }
    assert!(
        !run.events.iter().any(|event| {
            event.identity.action_id.as_ref() == Some(action_id)
                && matches!(event.kind, TraceEventKind::ActionExecuted { .. })
        }),
        "adapter failure without output should not emit ActionExecuted"
    );
}

fn find_tick_event<'a>(
    run: &'a AdapterHarnessRun,
    description: &str,
    predicate: impl Fn(&TraceEventKind) -> bool,
) -> &'a TraceEvent {
    run.events
        .iter()
        .find(|event| predicate(&event.kind))
        .unwrap_or_else(|| panic!("missing {description}"))
}

fn assert_current_runtime_commits_state_after_action_results(run: &AdapterHarnessRun) {
    let state_events = run
        .events
        .iter()
        .filter(|event| matches!(event.kind, TraceEventKind::StateCommitted { .. }))
        .collect::<Vec<_>>();
    assert_eq!(
        state_events.len(),
        1,
        "one tick should commit one state node"
    );
    let state_event = state_events[0];
    let outcome_recorded = find_tick_event(run, "OutcomeRecorded", |kind| {
        matches!(kind, TraceEventKind::OutcomeRecorded { .. })
    });
    let tick_completed = find_tick_event(run, "LoopTickCompleted", |kind| {
        matches!(kind, TraceEventKind::LoopTickCompleted { .. })
    });
    assert!(outcome_recorded.sequence < state_event.sequence);
    assert!(state_event.sequence < tick_completed.sequence);
    assert_eq!(state_event.identity.run_id, run.run_id);
    assert_eq!(
        state_event.identity.tenant_id.as_ref(),
        Some(&run.tenant_id)
    );
    assert_eq!(state_event.identity.agent_id.as_ref(), Some(&run.agent_id));
    assert_eq!(
        state_event.identity.state_node_id.as_ref(),
        Some(&run.outcome.state_commit.node_id)
    );
    assert_eq!(
        run.outcome.state_commit.trace_event_id.as_ref(),
        Some(&state_event.trace_event_id)
    );
    assert_eq!(
        run.outcome.state_commit.tenant_id.as_ref(),
        Some(&run.tenant_id)
    );
    assert_eq!(
        run.outcome.state_commit.agent_id.as_ref(),
        Some(&run.agent_id)
    );
    assert_eq!(run.outcome.state_commit.run_id.as_ref(), Some(&run.run_id));
    assert!(
        run.outcome.state_commit.snapshot_id.is_some(),
        "harness snapshot policy should create replayable state evidence"
    );
    if let TraceEventKind::StateCommitted {
        state_hash,
        snapshot_id,
    } = &state_event.kind
    {
        assert_eq!(state_hash, run.outcome.state_commit.node_id.hash());
        assert_eq!(snapshot_id, &run.outcome.state_commit.snapshot_id);
    } else {
        unreachable!("state event filter matched a different event kind");
    }
    let stored_node = run
        .state_store
        .get_node(&run.outcome.state_commit.node_id)
        .expect("committed state node");
    assert_eq!(
        stored_node.metadata.tenant_id.as_ref(),
        Some(&run.tenant_id)
    );
    assert_eq!(stored_node.metadata.agent_id.as_ref(), Some(&run.agent_id));
    assert_eq!(stored_node.metadata.run_id.as_ref(), Some(&run.run_id));
    assert_eq!(
        stored_node.metadata.trace_event_id.as_ref(),
        Some(&state_event.trace_event_id)
    );
}

#[test]
fn filesystem_adapter_harness_allows_sandboxed_write_and_read() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let filesystem = FilesystemAdapter::new(FilesystemAdapterConfig {
        base_dir: temp.path().to_path_buf(),
        ..FilesystemAdapterConfig::default()
    });
    let counting = Arc::new(CountingAdapter::new(filesystem));

    let write_action = action(
        "write_file",
        serde_json::json!({"path": "hello.txt", "bytes": [104, 105]}),
        SideEffectClass::Filesystem,
    );
    let read_action = action(
        "read_file",
        serde_json::json!({"path": "hello.txt"}),
        SideEffectClass::Filesystem,
    );
    let run = run_adapter_case(AdapterHarnessCase::new(
        "filesystem",
        vec![
            HarnessRegistration::new("write_file", "filesystem", counting.clone()),
            HarnessRegistration::new("read_file", "filesystem", counting.clone()),
        ],
        vec![
            action_candidate(write_action, "filesystem"),
            action_candidate(read_action, "filesystem"),
        ],
    ));

    assert_action_status(&run, 0, ActionStatus::Executed);
    assert_action_status(&run, 1, ActionStatus::Executed);
    assert_eq!(counting.executions(), 2);
    assert_action_executed_trace(&run, 0, "write_file");
    assert_action_executed_trace(&run, 1, "read_file");
    let read_output = run.outcome.action_outcomes[1]
        .output
        .clone()
        .expect("read output");
    assert_eq!(read_output["bytes_read"], 2);
    assert_eq!(read_output["bytes"], serde_json::json!([104, 105]));
    assert_current_runtime_commits_state_after_action_results(&run);
}

#[test]
fn real_filesystem_and_http_adapters_never_receive_raw_credential_encodings() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let filesystem = Arc::new(CountingAdapter::new(FilesystemAdapter::new(
        FilesystemAdapterConfig {
            base_dir: temp.path().to_path_buf(),
            ..FilesystemAdapterConfig::default()
        },
    )));
    let http = Arc::new(CountingAdapter::new(HttpAdapter::new(HttpAdapterConfig {
        allowed_domains: vec!["127.0.0.1".to_string()],
        ..HttpAdapterConfig::default()
    })));
    let provider_canary = format!("ghp_{}", "A".repeat(36));
    let utf16le = "Bearer x"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let utf16be = "Bearer x"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect::<Vec<_>>();
    let mut utf8_bom = vec![0xef, 0xbb, 0xbf];
    utf8_bom.extend_from_slice(b"ordinary body");
    let bodies = [
        b"Basic dTpw".to_vec(),
        provider_canary.as_bytes().to_vec(),
        utf16le,
        utf16be,
        utf8_bom,
        vec![0xff, 0xfe, b'x'],
        vec![b'o', b'k', 0, b'x'],
        b"safe=1&value=Basic+dTpw".to_vec(),
    ];
    let encoded_string_bodies = vec![
        "name=VAULT_TOKEN&value=C03_FORM_CANARY".to_string(),
        "header=X-Auth-Token&value=C03_HEADER_CANARY".to_string(),
        "Bearer%20x,https://example.invalid/docs".to_string(),
        "vault%3Ateam%2Fservice,https://example.invalid/docs".to_string(),
        "vault%3A%2F%2Fteam%2Fservice,https://example.invalid/docs".to_string(),
        "value=%EF%BB%BFBasic%20dTpw".to_string(),
        "value=B%00e%00a%00r%00e%00r%00%20x".to_string(),
        "safe/Bearer x".to_string(),
        "safe|Bearer x".to_string(),
        "safe`Bearer x`".to_string(),
        "safe—Bearer x—".to_string(),
        "safe|token=synthetic".to_string(),
        "safe`token=synthetic".to_string(),
        format!("safe|ghp_{}", "A".repeat(36)),
        format!("safe`ghp_{}`", "A".repeat(36)),
        "https://example.invalid/Bearer%20x".to_string(),
        "https://example.invalid/safe.Bearer%20x".to_string(),
        "https://example.invalid/?%42earer%20x".to_string(),
        "https://example.invalid/?safe%60%42earer%20x%60".to_string(),
        "https://example.invalid/?%76ault%3Aprod%2Fdb".to_string(),
    ];
    let encoded_authority_urls = vec![
        format!("http://sink-%41KIA{}.attacker.invalid/", "1".repeat(16)),
        format!("http://sink-%67hp%5F{}.attacker.invalid/", "A".repeat(36)),
    ];
    let mut candidates = Vec::new();
    let mut serialized_bodies = Vec::new();
    for (index, body) in bodies.iter().enumerate() {
        serialized_bodies.push(serde_json::to_string(body).expect("numeric body serializes"));
        candidates.push(action_candidate(
            action(
                "write_file",
                serde_json::json!({
                    "path": format!("credential-{index}.txt"),
                    "bytes": body,
                }),
                SideEffectClass::Filesystem,
            ),
            "filesystem",
        ));
        candidates.push(action_candidate(
            action(
                "http_post",
                serde_json::json!({
                    "url": "http://127.0.0.1:9/",
                    "bytes": body,
                }),
                SideEffectClass::Network,
            ),
            "http",
        ));
    }
    candidates.push(action_candidate(
        action(
            "custom_write",
            serde_json::json!({
                "path": "credential-alias.txt",
                "bytes": b"Basic dTpw".to_vec(),
            }),
            SideEffectClass::ReadOnly,
        ),
        "filesystem",
    ));
    candidates.push(action_candidate(
        action(
            "custom_post",
            serde_json::json!({
                "url": "http://127.0.0.1:9/",
                "bytes": b"Basic dTpw".to_vec(),
            }),
            SideEffectClass::ReadOnly,
        ),
        "http",
    ));
    for body in &encoded_string_bodies {
        candidates.push(action_candidate(
            action(
                "http_post",
                serde_json::json!({
                    "url": "http://127.0.0.1:9/",
                    "body": body,
                }),
                SideEffectClass::Network,
            ),
            "http",
        ));
    }
    for url in &encoded_authority_urls {
        candidates.push(action_candidate(
            action(
                "http_post",
                serde_json::json!({
                    "url": url,
                    "body": "ordinary body",
                }),
                SideEffectClass::Network,
            ),
            "http",
        ));
    }
    candidates.push(action_candidate(
        action(
            "write_file",
            serde_json::json!({
                "path": "credential-contents.txt",
                "contents": "B\0e\0a\0r\0e\0r\0 \0x\0",
            }),
            SideEffectClass::Filesystem,
        ),
        "filesystem",
    ));
    candidates.push(action_candidate(
        action(
            "http_post",
            serde_json::json!({
                "url": "http://127.0.0.1:9/",
                "body": "safe=1&value=Basic+dTpw",
            }),
            SideEffectClass::Network,
        ),
        "http",
    ));
    for json_body in [
        serde_json::json!({"key": "password", "value": "C03_PASSWORD_CANARY"}),
        serde_json::json!({"header": "Authorization", "value": "C03_HEADER_VALUE_CANARY"}),
    ] {
        candidates.push(action_candidate(
            action(
                "http_post",
                serde_json::json!({
                    "url": "http://127.0.0.1:9/",
                    "json": json_body,
                }),
                SideEffectClass::Network,
            ),
            "http",
        ));
    }
    candidates.push(action_candidate(
        action(
            "http_post",
            serde_json::json!({
                "url": "http://127.0.0.1:9/",
                "json": {"name": "VAULT_TOKEN", "value": "C03_STRUCTURED_CANARY"},
            }),
            SideEffectClass::Network,
        ),
        "http",
    ));
    let expected_denials = candidates.len();
    let run = run_adapter_case(AdapterHarnessCase::new(
        "credential-encoding-denial",
        vec![
            HarnessRegistration::new("write_file", "filesystem", filesystem.clone()),
            HarnessRegistration::new("http_post", "http", http.clone()),
            HarnessRegistration::new("custom_write", "filesystem", filesystem.clone()),
            HarnessRegistration::new("custom_post", "http", http.clone()),
        ],
        candidates,
    ));

    for outcome in &run.outcome.action_outcomes {
        assert_eq!(outcome.status, ActionStatus::Denied);
        assert_eq!(
            outcome.verification.reasons,
            vec![RAW_CREDENTIAL_INPUT_DENIED.to_string()]
        );
    }
    assert_eq!(filesystem.executions(), 0);
    assert_eq!(http.executions(), 0);
    for index in 0..bodies.len() {
        assert!(!temp.path().join(format!("credential-{index}.txt")).exists());
    }
    assert!(!temp.path().join("credential-alias.txt").exists());
    assert!(!temp.path().join("credential-contents.txt").exists());
    let encoded_events = serde_json::to_string(&run.events).expect("events serialize");
    assert!(!encoded_events.contains(&provider_canary));
    assert!(!encoded_events.contains("safe=1&value=Basic+dTpw"));
    assert!(!encoded_events.contains("VAULT_TOKEN"));
    assert!(!encoded_events.contains("C03_STRUCTURED_CANARY"));
    assert!(!encoded_events.contains("C03_PASSWORD_CANARY"));
    assert!(!encoded_events.contains("C03_HEADER_VALUE_CANARY"));
    for body in &encoded_string_bodies {
        assert!(!encoded_events.contains(body));
    }
    for url in &encoded_authority_urls {
        assert!(!encoded_events.contains(url));
    }
    for body in serialized_bodies {
        assert!(
            !encoded_events.contains(&body),
            "raw numeric body must not enter trace"
        );
    }
    let proposed = run
        .events
        .iter()
        .find_map(|event| match &event.kind {
            TraceEventKind::CandidatesProposed { actions } => Some(actions),
            _ => None,
        })
        .expect("candidate event");
    assert_eq!(
        proposed,
        &vec![raw_credential_denied_action(); expected_denials]
    );
    assert_current_runtime_commits_state_after_action_results(&run);
}

#[test]
fn filesystem_adapter_harness_records_traversal_failure() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let filesystem = FilesystemAdapter::new(FilesystemAdapterConfig {
        base_dir: temp.path().to_path_buf(),
        ..FilesystemAdapterConfig::default()
    });
    let counting = Arc::new(CountingAdapter::new(filesystem));

    let read_action = action(
        "read_file",
        serde_json::json!({"path": "../secret.txt"}),
        SideEffectClass::Filesystem,
    );
    let run = run_adapter_case(AdapterHarnessCase::new(
        "filesystem",
        vec![HarnessRegistration::new(
            "read_file",
            "filesystem",
            counting.clone(),
        )],
        vec![action_candidate(read_action, "filesystem")],
    ));

    assert_action_status(&run, 0, ActionStatus::Failed);
    assert_eq!(counting.executions(), 1);
    assert_action_failed_trace(&run, 0, "read_file", "path traversal");
    assert_current_runtime_commits_state_after_action_results(&run);
}

#[test]
fn http_adapter_harness_allows_allowlisted_local_domain() {
    let server = TestServer::start("ok");
    let adapter = HttpAdapter::new(HttpAdapterConfig {
        allowed_domains: vec!["127.0.0.1".to_string()],
        ..HttpAdapterConfig::default()
    });
    let counting = Arc::new(CountingAdapter::new(adapter));

    let action = action(
        "http_get",
        serde_json::json!({"url": server.url}),
        SideEffectClass::Network,
    );
    let usage = QuotaUsage {
        http_requests: 1,
        ..QuotaUsage::default()
    };
    let run = run_adapter_case(AdapterHarnessCase::new(
        "http",
        vec![HarnessRegistration::new(
            "http_get",
            "http",
            counting.clone(),
        )],
        vec![action_candidate(action, "http").with_usage(usage)],
    ));

    assert_action_status(&run, 0, ActionStatus::Executed);
    assert_eq!(counting.executions(), 1);
    assert_action_executed_trace(&run, 0, "http_get");
    let output = run.outcome.action_outcomes[0]
        .output
        .clone()
        .expect("output");
    assert_eq!(output["status"], 200);
    assert_eq!(output["body"], "ok");
    assert_current_runtime_commits_state_after_action_results(&run);
    server.join();
}

#[test]
fn http_adapter_harness_allows_ordinary_utf8_numeric_body() {
    let server = TestServer::start("posted");
    let adapter = HttpAdapter::new(HttpAdapterConfig {
        allowed_domains: vec!["127.0.0.1".to_string()],
        ..HttpAdapterConfig::default()
    });
    let counting = Arc::new(CountingAdapter::new(adapter));
    let body = "safe=1&label=50%25&topic=Basic+planning&text=café\n"
        .as_bytes()
        .to_vec();
    let action = action(
        "http_post",
        serde_json::json!({"url": server.url, "bytes": body}),
        SideEffectClass::Network,
    );
    let usage = QuotaUsage {
        http_requests: 1,
        ..QuotaUsage::default()
    };
    let run = run_adapter_case(AdapterHarnessCase::new(
        "http-ordinary-utf8-bytes",
        vec![HarnessRegistration::new(
            "http_post",
            "http",
            counting.clone(),
        )],
        vec![action_candidate(action, "http").with_usage(usage)],
    ));

    assert_action_status(&run, 0, ActionStatus::Executed);
    assert_eq!(counting.executions(), 1);
    assert_action_executed_trace(&run, 0, "http_post");
    assert_current_runtime_commits_state_after_action_results(&run);
    server.join();
}

#[test]
fn http_adapter_harness_records_disallowed_domain_failure() {
    let adapter = HttpAdapter::new(HttpAdapterConfig::default());
    let counting = Arc::new(CountingAdapter::new(adapter));

    let action = action(
        "http_get",
        serde_json::json!({"url": "http://example.com"}),
        SideEffectClass::Network,
    );
    let run = run_adapter_case(AdapterHarnessCase::new(
        "http",
        vec![HarnessRegistration::new(
            "http_get",
            "http",
            counting.clone(),
        )],
        vec![action_candidate(action, "http")],
    ));

    assert_action_status(&run, 0, ActionStatus::Failed);
    assert_eq!(counting.executions(), 1);
    assert_action_failed_trace(&run, 0, "http_get", "domain not allowlisted");
    assert_current_runtime_commits_state_after_action_results(&run);
}

#[test]
fn faulty_counting_adapter_harness_records_adapter_failure() {
    let counting = Arc::new(CountingAdapter::new(FaultyAdapter));

    let action = action(
        "faulty_action",
        serde_json::json!({"fault": true}),
        SideEffectClass::External,
    );
    let run = run_adapter_case(AdapterHarnessCase::new(
        "faulty",
        vec![HarnessRegistration::new(
            "faulty_action",
            "faulty",
            counting.clone(),
        )],
        vec![action_candidate(action, "faulty")],
    ));

    assert_action_status(&run, 0, ActionStatus::Failed);
    assert_eq!(counting.executions(), 1);
    assert_action_failed_trace(&run, 0, "faulty_action", "intentional adapter fault");
    assert_current_runtime_commits_state_after_action_results(&run);
}

#[test]
fn trace_store_failure_before_adapter_dispatch_does_not_execute_or_commit() {
    let counting = Arc::new(CountingAdapter::new(FaultyAdapter));
    let tenant_id = TenantId::new();
    let registry = build_registry(
        &tenant_id,
        &["faulty_action".to_string()],
        &["faulty".to_string()],
    );
    registry.begin_tick(TICK_ID, OffsetDateTime::now_utc());
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry));
    gateway.register_adapter("faulty_action", "faulty", counting.clone());
    let gateway: Arc<dyn ActionGateway> = Arc::new(gateway);
    let action = action(
        "faulty_action",
        serde_json::json!({"fault": true}),
        SideEffectClass::External,
    );
    let policy = StaticPolicy {
        name: "faulty".to_string(),
        actions: vec![action_candidate(action, "faulty")],
        next_state: StateData {
            bytes: vec![1],
            content_type: None,
        },
    };
    let state_store = Arc::new(InMemoryStateStore::default());
    let trace_store = Arc::new(FailingActionVerificationTraceStore::default());
    let run_id = RunId::new();
    let agent = AgentContext::new(AgentId::new(), tenant_id, AgentRuntimeConfig::default());
    let graph = StateGraph::new(state_store, SnapshotPolicy::default());
    let mut engine = LoopEngine::with_trace_store(
        agent,
        graph,
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(policy),
        gateway,
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");
    engine.add_perceptor(StaticPerceptor);

    let error = engine
        .tick(TICK_ID)
        .expect_err("trace failure should fail tick");
    assert!(matches!(
        error,
        LoopError::Trace(splendor_kernel::TraceError::Store(
            TraceStoreError::Poisoned
        ))
    ));
    assert_eq!(counting.executions(), 0);
    let events = read_events(trace_store.as_ref(), &run_id);
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::RunStarted)));
    assert!(!events.iter().any(|event| matches!(
        event.kind,
        TraceEventKind::ActionVerificationStarted { .. }
            | TraceEventKind::ActionFailed { .. }
            | TraceEventKind::StateCommitted { .. }
            | TraceEventKind::LoopTickCompleted { .. }
    )));
}
