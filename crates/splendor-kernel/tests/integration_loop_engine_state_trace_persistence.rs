use splendor_gateway::{
    raw_credential_denied_action, ActionAdapter, ActionGateway, ActionId, ActionOutcome,
    ActionStatus, AdapterError, AdapterResult, GatewayError, VerifiedActionGateway,
    RAW_CREDENTIAL_INPUT_DENIED, RAW_CREDENTIAL_OUTPUT_SUPPRESSED,
};
use splendor_kernel::{
    ActionCandidate, AgentContext, AgentRuntimeConfig, ConstraintEngine, ConstraintEvaluation,
    KernelRuntime, LoopEngine, LoopError, OutcomeEvaluator, OutcomeSignal, Perceptor, Policy,
    PolicyDecision, QuotaPolicy, RunId, Scheduler, SchedulerConfig, SchedulerError,
    SideEffectClass, SnapshotPolicy, StateGraph, TenantContext, TenantPolicy, TenantRegistry,
    TraceEvent, TraceEventKind,
};
use splendor_store::{
    InMemoryStateStore, InMemoryTraceStore, RuntimeTraceAppend, RuntimeTraceLimits,
    RuntimeTracePage, RuntimeTracePortError, RuntimeTraceReader, RuntimeTraceReaderHandle,
    RuntimeTraceStoreIdentity, RuntimeTraceTail, RuntimeTraceWriter, RuntimeTraceWriterHandle,
    RuntimeTraceWriterRequest, StateData, StateDataRef, StateMetadata, StateNode, StateSnapshot,
    StateStore, StateStoreError, TraceRecord, TraceStore, TraceStoreError,
};
use splendor_types::{
    Action, ApprovalId, ApprovalTraceContext, AuthorityDecisionId, AuthorityObligationId,
    AuthorityObligationKind, AuthorityObligationReceipt, AuthorityObligationReceiptId,
    AuthorityObligationReceiptValidation, AuthorityObligationReceiptValidationKind,
    EffectCertainty, Feedback, Percept, PerceptProvenance, PrincipalId, RetryClass,
    RevocationStatus, SnapshotId, StateNodeId, VerificationResult,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

const ACTION_CANARY: &str = "C03_RAW_CREDENTIAL_KERNEL_CANARY";
const RECEIPT_CANARY: &str = "Bearer C03_RAW_RECEIPT_KERNEL_CANARY";
const PERCEPT_CANARY: &str = "C03_RAW_PERCEPT_KERNEL_CANARY";
const STATE_CANARY: &str = "C03_RAW_STATE_KERNEL_CANARY";

struct StaticPerceptor;

impl Perceptor for StaticPerceptor {
    fn collect(&self, _agent: &AgentContext) -> Result<Vec<Percept>, splendor_kernel::LoopError> {
        Ok(vec![Percept {
            schema: "sensor".to_string(),
            payload: serde_json::json!({"value": 7}),
            provenance: PerceptProvenance {
                source: "integration".to_string(),
                detail: None,
            },
            timestamp: OffsetDateTime::now_utc(),
        }])
    }
}

struct StaticPolicy;

impl Policy for StaticPolicy {
    fn name(&self) -> &str {
        "integration-policy"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, splendor_kernel::LoopError> {
        let action = Action {
            name: "noop".to_string(),
            params: serde_json::json!({"ok": true}),
            side_effect_class: SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        };
        let candidate = ActionCandidate::new(action).with_adapter("stub");
        let next_state = StateData {
            bytes: vec![9],
            content_type: Some("application/octet-stream".to_string()),
        };
        Ok(PolicyDecision::new(
            vec![candidate],
            next_state,
            Some("snapshot".to_string()),
        ))
    }
}

struct CredentialPerceptor;

impl Perceptor for CredentialPerceptor {
    fn collect(&self, _agent: &AgentContext) -> Result<Vec<Percept>, splendor_kernel::LoopError> {
        let mut body = format!("password={PERCEPT_CANARY}")
            .bytes()
            .map(serde_json::Value::from)
            .collect::<Vec<_>>();
        body.push(serde_json::json!(300));
        Ok(vec![Percept {
            schema: "splendor.percept.fixture.v1".to_string(),
            payload: serde_json::json!({"body": body}),
            provenance: PerceptProvenance {
                source: "integration".to_string(),
                detail: None,
            },
            timestamp: OffsetDateTime::now_utc(),
        }])
    }
}

struct CountingNoopPolicy {
    calls: Arc<AtomicUsize>,
}

impl Policy for CountingNoopPolicy {
    fn name(&self) -> &str {
        "counting-noop-policy"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, splendor_kernel::LoopError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(PolicyDecision::new(
            Vec::new(),
            StateData {
                bytes: vec![1],
                content_type: None,
            },
            None,
        ))
    }
}

struct CredentialStatePolicy {
    observed_states: Arc<Mutex<Vec<StateData>>>,
}

impl Policy for CredentialStatePolicy {
    fn name(&self) -> &str {
        "credential-state-policy"
    }

    fn decide(
        &self,
        state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, splendor_kernel::LoopError> {
        self.observed_states
            .lock()
            .expect("observed state lock")
            .push(state.clone());
        let candidate = ActionCandidate::new(Action {
            name: "noop".to_string(),
            params: serde_json::json!({"ok": true}),
            side_effect_class: SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        })
        .with_adapter("stub");
        let mut bytes = format!("password={STATE_CANARY}")
            .bytes()
            .map(serde_json::Value::from)
            .collect::<Vec<_>>();
        bytes.push(serde_json::json!(300));
        Ok(PolicyDecision::new(
            vec![candidate],
            StateData {
                bytes: serde_json::to_vec(&serde_json::json!({"bytes": bytes}))
                    .expect("fixture state serializes"),
                content_type: Some("application/json".to_string()),
            },
            Some("unsafe-state".to_string()),
        ))
    }
}

#[derive(Default)]
struct StubAdapter;

impl ActionAdapter for StubAdapter {
    fn execute(
        &self,
        _action: &splendor_gateway::ActionRequest,
    ) -> Result<AdapterResult, AdapterError> {
        Ok(AdapterResult {
            output: serde_json::json!({"ok": true}),
            satisfied_postconditions: Vec::new(),
        })
    }
}

struct MixedCredentialPolicy;

fn raw_receipt_canary() -> AuthorityObligationReceipt {
    let now = OffsetDateTime::now_utc();
    AuthorityObligationReceipt {
        schema_version: "splendor.authority_obligation_receipt.v1".to_string(),
        receipt_id: AuthorityObligationReceiptId::new(),
        issuer: PrincipalId::new(),
        audience: "splendor.kernel.fixture".to_string(),
        obligation_id: AuthorityObligationId::new(),
        kind: AuthorityObligationKind::ApprovalRequired,
        subject: PrincipalId::new(),
        authority_decision_id: AuthorityDecisionId::new(),
        canonical_request_digest: "blake3:canonical-request".to_string(),
        evidence_digest: "blake3:evidence".to_string(),
        evidence_ref: Some(RECEIPT_CANARY.to_string()),
        issued_at: now,
        expires_at: now + time::Duration::minutes(5),
        revocation: RevocationStatus::Active,
        revocation_ref: "revocation:fixture".to_string(),
        approval_id: None,
        approval_trace_event_id: None,
        validation: AuthorityObligationReceiptValidation {
            validation_kind: AuthorityObligationReceiptValidationKind::LocalSignature,
            algorithm: "local-signature-v1".to_string(),
            key_id: "local-receipt-key-v1".to_string(),
            digest: "blake3:receipt".to_string(),
            signature: "synthetic-signature".to_string(),
        },
    }
}

impl Policy for MixedCredentialPolicy {
    fn name(&self) -> &str {
        "mixed-credential-policy"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, splendor_kernel::LoopError> {
        let denied = ActionCandidate::new(Action {
            name: "unsafe-input".to_string(),
            params: serde_json::json!({
                "nested": [{"authKey": ACTION_CANARY}]
            }),
            side_effect_class: SideEffectClass::Network,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        })
        .with_adapter("stub");
        let receipt_denied = ActionCandidate::new(Action {
            name: "unsafe-input".to_string(),
            params: serde_json::json!({"resource_ref": "fixture:receipt"}),
            side_effect_class: SideEffectClass::Network,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        })
        .with_adapter("stub")
        .with_authority_obligation_receipts(vec![raw_receipt_canary()]);
        let allowed = ActionCandidate::new(Action {
            name: "safe-input".to_string(),
            params: serde_json::json!({"resource_ref": "fixture:report"}),
            side_effect_class: SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        })
        .with_adapter("stub");
        Ok(PolicyDecision::new(
            vec![denied, receipt_denied, allowed],
            StateData {
                bytes: b"credential-free-state".to_vec(),
                content_type: Some("text/plain".to_string()),
            },
            Some("mixed-screened".to_string()),
        ))
    }
}

struct RecordingConstraintEngine {
    names: Arc<Mutex<Vec<String>>>,
}

impl ConstraintEngine for RecordingConstraintEngine {
    fn evaluate(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
        actions: &[ActionCandidate],
    ) -> ConstraintEvaluation {
        *self.names.lock().expect("constraint names") = actions
            .iter()
            .map(|candidate| candidate.action.name.clone())
            .collect();
        ConstraintEvaluation::allow()
    }
}

struct RecordingOutcomeEvaluator {
    names: Arc<Mutex<Vec<String>>>,
}

impl OutcomeEvaluator for RecordingOutcomeEvaluator {
    fn evaluate(&self, action: &Action, _outcome: &ActionOutcome) -> OutcomeSignal {
        self.names
            .lock()
            .expect("outcome names")
            .push(action.name.clone());
        OutcomeSignal {
            feedback: Some(Feedback {
                kind: "integration".to_string(),
                payload: action.params.clone(),
                recorded_at: OffsetDateTime::now_utc(),
            }),
            reward: None,
        }
    }
}

struct CountingAdapter {
    calls: Arc<AtomicUsize>,
}

impl ActionAdapter for CountingAdapter {
    fn execute(
        &self,
        action: &splendor_gateway::ActionRequest,
    ) -> Result<AdapterResult, AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AdapterResult {
            output: serde_json::json!({"executed": action.action.name}),
            satisfied_postconditions: Vec::new(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoEffectGatewayOutcome {
    Denied,
    NeedsApproval,
}

struct NoEffectGateway {
    outcome: NoEffectGatewayOutcome,
    submissions: Arc<AtomicUsize>,
}

impl ActionGateway for NoEffectGateway {
    fn submit(
        &self,
        request: splendor_gateway::ActionRequest,
    ) -> Result<ActionOutcome, GatewayError> {
        self.submissions.fetch_add(1, Ordering::SeqCst);
        let (status, reason, verification) = match self.outcome {
            NoEffectGatewayOutcome::Denied => (
                ActionStatus::Denied,
                "fixture_denied",
                VerificationResult::deny("fixture_denied"),
            ),
            NoEffectGatewayOutcome::NeedsApproval => {
                let approval = ApprovalTraceContext {
                    approval_id: ApprovalId::new(),
                    tenant_id: request.tenant_id.clone(),
                    agent_id: request.agent_id.clone(),
                    run_id: request.run_id.clone(),
                    action_id: Some(request.action_id.clone()),
                    action_name: request.action.name.clone(),
                    adapter: request.adapter.clone(),
                    decision: None,
                    reason: Some("fixture approval required".to_string()),
                    policy_id: Some("fixture-approval-policy".to_string()),
                    risk_level: Some("external".to_string()),
                    issued_at: None,
                    expires_at: None,
                    revoked: false,
                };
                (
                    ActionStatus::NeedsApproval,
                    "approval_required",
                    VerificationResult {
                        allowed: false,
                        reasons: vec!["approval_required".to_string()],
                        artifacts: serde_json::json!({
                            "approval_status": "required",
                            "approval_context": approval,
                        }),
                    },
                )
            }
        };
        Ok(ActionOutcome {
            action_id: request.action_id,
            status,
            verification,
            post_verification: None,
            output: None,
            error: Some(reason.to_string()),
            approval_challenge: None,
            completed_at: OffsetDateTime::now_utc(),
        })
    }
}

struct ForbiddenRawEffectAdapter {
    adapter_calls: Arc<AtomicUsize>,
    provider_calls: Arc<AtomicUsize>,
    network_calls: Arc<AtomicUsize>,
    filesystem_calls: Arc<AtomicUsize>,
}

struct FailIfWrittenStateStore {
    writes: Arc<AtomicUsize>,
}

#[derive(Clone, Copy, Debug)]
enum TraceFailurePoint {
    ActionVerificationCompleted,
    ApprovalRequested,
    ActionDenied,
    ActionNeedsApproval,
    ActionExecuted,
    ActionFailed,
    OutcomeRecorded,
    StateCommitted,
    LoopTickCompleted,
}

impl TraceFailurePoint {
    fn matches(self, kind: &TraceEventKind) -> bool {
        matches!(
            (self, kind),
            (
                Self::ActionVerificationCompleted,
                TraceEventKind::ActionVerificationCompleted { .. }
            ) | (
                Self::ApprovalRequested,
                TraceEventKind::ApprovalRequested { .. }
            ) | (Self::ActionDenied, TraceEventKind::ActionDenied { .. })
                | (
                    Self::ActionNeedsApproval,
                    TraceEventKind::ActionNeedsApproval { .. }
                )
                | (Self::ActionFailed, TraceEventKind::ActionFailed { .. })
                | (Self::ActionExecuted, TraceEventKind::ActionExecuted { .. })
                | (
                    Self::OutcomeRecorded,
                    TraceEventKind::OutcomeRecorded { .. }
                )
                | (Self::StateCommitted, TraceEventKind::StateCommitted { .. })
                | (
                    Self::LoopTickCompleted,
                    TraceEventKind::LoopTickCompleted { .. }
                )
        )
    }
}

struct ArmableTraceStore {
    inner: InMemoryTraceStore,
    failure: TraceFailurePoint,
    armed: Arc<AtomicBool>,
}

impl ArmableTraceStore {
    fn new(failure: TraceFailurePoint) -> Self {
        Self {
            inner: InMemoryTraceStore::default(),
            failure,
            armed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
}

impl TraceStore for ArmableTraceStore {
    fn append(&self, run_id: &str, payload: serde_json::Value) -> Result<u64, TraceStoreError> {
        let event: TraceEvent = serde_json::from_value(payload.clone())?;
        if self.failure.matches(&event.kind) && self.armed.swap(false, Ordering::SeqCst) {
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

    fn runtime_store_identity(&self) -> Result<RuntimeTraceStoreIdentity, RuntimeTracePortError> {
        self.inner.runtime_store_identity()
    }

    fn open_runtime_reader(
        &self,
        run_id: &str,
        limits: RuntimeTraceLimits,
    ) -> Result<RuntimeTraceReaderHandle, RuntimeTracePortError> {
        self.inner.open_runtime_reader(run_id, limits)
    }

    fn acquire_runtime_writer(
        &self,
        request: RuntimeTraceWriterRequest,
    ) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
        Ok(Arc::new(ArmableRuntimeWriter {
            inner: self.inner.acquire_runtime_writer(request)?,
            failure: self.failure,
            armed: Arc::clone(&self.armed),
        }))
    }
}

struct ArmableRuntimeWriter {
    inner: RuntimeTraceWriterHandle,
    failure: TraceFailurePoint,
    armed: Arc<AtomicBool>,
}

impl RuntimeTraceReader for ArmableRuntimeWriter {
    fn store_identity(&self) -> RuntimeTraceStoreIdentity {
        self.inner.store_identity()
    }

    fn run_id(&self) -> &str {
        self.inner.run_id()
    }

    fn limits(&self) -> RuntimeTraceLimits {
        self.inner.limits()
    }

    fn tail(&self) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
        self.inner.tail()
    }

    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError> {
        self.inner.read_page(start)
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        self.inner.confirm_tail(expected)
    }
}

impl RuntimeTraceWriter for ArmableRuntimeWriter {
    fn append(
        &self,
        expected: &RuntimeTraceTail,
        payload: serde_json::Value,
    ) -> Result<RuntimeTraceAppend, RuntimeTracePortError> {
        let event: TraceEvent = serde_json::from_value(payload.clone())
            .map_err(|_| RuntimeTracePortError::BackendContract)?;
        if self.failure.matches(&event.kind) && self.armed.swap(false, Ordering::SeqCst) {
            return Err(RuntimeTracePortError::Unavailable);
        }
        self.inner.append(expected, payload)
    }

    fn close(&self) -> Result<(), RuntimeTracePortError> {
        self.inner.close()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StateFailurePoint {
    PutState,
    CommitNode,
    Snapshot,
}

struct ArmableStateStore {
    inner: InMemoryStateStore,
    failure: StateFailurePoint,
    armed: AtomicBool,
}

impl ArmableStateStore {
    fn new(failure: StateFailurePoint) -> Self {
        Self {
            inner: InMemoryStateStore::default(),
            failure,
            armed: AtomicBool::new(false),
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn fail(&self, point: StateFailurePoint) -> bool {
        self.failure == point && self.armed.swap(false, Ordering::SeqCst)
    }
}

impl StateStore for ArmableStateStore {
    fn put_state(&self, state: StateData) -> Result<StateDataRef, StateStoreError> {
        if self.fail(StateFailurePoint::PutState) {
            return Err(StateStoreError::Poisoned);
        }
        self.inner.put_state(state)
    }

    fn get_state(&self, data_ref: &StateDataRef) -> Result<StateData, StateStoreError> {
        self.inner.get_state(data_ref)
    }

    fn commit_node(
        &self,
        parent_ids: Vec<StateNodeId>,
        data_ref: StateDataRef,
        metadata: StateMetadata,
    ) -> Result<StateNodeId, StateStoreError> {
        if self.fail(StateFailurePoint::CommitNode) {
            return Err(StateStoreError::Poisoned);
        }
        self.inner.commit_node(parent_ids, data_ref, metadata)
    }

    fn get_node(&self, node_id: &StateNodeId) -> Result<StateNode, StateStoreError> {
        self.inner.get_node(node_id)
    }

    fn snapshot(&self, node_id: &StateNodeId) -> Result<SnapshotId, StateStoreError> {
        if self.fail(StateFailurePoint::Snapshot) {
            return Err(StateStoreError::Poisoned);
        }
        self.inner.snapshot(node_id)
    }

    fn load_snapshot(&self, snapshot_id: &SnapshotId) -> Result<StateSnapshot, StateStoreError> {
        self.inner.load_snapshot(snapshot_id)
    }
}

#[derive(Clone)]
struct CandidateListPolicy {
    actions: Vec<ActionCandidate>,
}

impl Policy for CandidateListPolicy {
    fn name(&self) -> &str {
        "candidate-list-policy"
    }

    fn decide(
        &self,
        _state: &StateData,
        _percepts: &[Percept],
    ) -> Result<PolicyDecision, splendor_kernel::LoopError> {
        Ok(PolicyDecision::new(
            self.actions.clone(),
            StateData {
                bytes: vec![9],
                content_type: None,
            },
            None,
        ))
    }
}

struct RecordingSuppressionAdapter {
    calls: Arc<Mutex<Vec<String>>>,
    suppress_action: Option<String>,
    suppress_on_call: Option<usize>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EnteredAdapterOutcome {
    Success,
    GenericFailure,
    PostconditionFailure,
}

struct RecordingEnteredAdapter {
    calls: Arc<Mutex<Vec<String>>>,
    outcome: EnteredAdapterOutcome,
}

impl ActionAdapter for RecordingEnteredAdapter {
    fn execute(
        &self,
        request: &splendor_gateway::ActionRequest,
    ) -> Result<AdapterResult, AdapterError> {
        self.calls
            .lock()
            .expect("adapter calls")
            .push(request.action.name.clone());
        match self.outcome {
            EnteredAdapterOutcome::Success => Ok(AdapterResult {
                output: serde_json::json!({"ok": true}),
                satisfied_postconditions: request.action.postconditions.clone(),
            }),
            EnteredAdapterOutcome::GenericFailure => Err(AdapterError::Failed(
                "provider detail must not escape".to_string(),
            )),
            EnteredAdapterOutcome::PostconditionFailure => Ok(AdapterResult {
                output: serde_json::json!({"effect_receipt": "fixture"}),
                satisfied_postconditions: Vec::new(),
            }),
        }
    }
}

struct SequencedEnteredAdapter {
    calls: Arc<Mutex<Vec<String>>>,
    second_outcome: EnteredAdapterOutcome,
}

impl ActionAdapter for SequencedEnteredAdapter {
    fn execute(
        &self,
        request: &splendor_gateway::ActionRequest,
    ) -> Result<AdapterResult, AdapterError> {
        let call_number = {
            let mut calls = self.calls.lock().expect("adapter calls");
            calls.push(request.action.name.clone());
            calls.len()
        };
        let outcome = if call_number == 1 {
            EnteredAdapterOutcome::Success
        } else {
            self.second_outcome
        };
        match outcome {
            EnteredAdapterOutcome::Success => Ok(AdapterResult {
                output: serde_json::json!({"ok": true}),
                satisfied_postconditions: request.action.postconditions.clone(),
            }),
            EnteredAdapterOutcome::GenericFailure => Err(AdapterError::Failed(
                "untrusted provider detail".to_string(),
            )),
            EnteredAdapterOutcome::PostconditionFailure => Ok(AdapterResult {
                output: serde_json::json!({"effect_receipt": "fixture"}),
                satisfied_postconditions: Vec::new(),
            }),
        }
    }
}

impl ActionAdapter for RecordingSuppressionAdapter {
    fn execute(
        &self,
        request: &splendor_gateway::ActionRequest,
    ) -> Result<AdapterResult, AdapterError> {
        let mut calls = self.calls.lock().expect("adapter calls");
        calls.push(request.action.name.clone());
        let call_number = calls.len();
        let suppress = self
            .suppress_action
            .as_deref()
            .is_some_and(|name| name == request.action.name)
            || self.suppress_on_call == Some(call_number);
        drop(calls);
        Ok(AdapterResult {
            output: if suppress {
                serde_json::json!({"body": "password=C03_RESTART_SUPPRESSION_CANARY"})
            } else {
                serde_json::json!({"ok": true})
            },
            satisfied_postconditions: Vec::new(),
        })
    }
}

fn external_candidate(name: &str, action_id: Option<ActionId>) -> ActionCandidate {
    let candidate = ActionCandidate::new(Action {
        name: name.to_string(),
        params: serde_json::json!({"target": "fixture"}),
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    })
    .with_adapter("stub");
    match action_id {
        Some(action_id) => candidate.with_action_id(action_id),
        None => candidate,
    }
}

fn recording_gateway(
    tenant_id: &splendor_kernel::TenantId,
    action_names: &[String],
    adapter: Arc<dyn ActionAdapter>,
) -> (TenantRegistry, Arc<dyn ActionGateway>) {
    let registry = TenantRegistry::new();
    registry.insert(TenantContext::new(
        tenant_id.clone(),
        TenantPolicy {
            allowed_actions: action_names.to_vec(),
            allowed_adapters: vec!["stub".to_string()],
            allowed_permissions: Vec::new(),
        },
        QuotaPolicy::default(),
    ));
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry.clone()));
    let mut registered = Vec::new();
    for action_name in action_names {
        if registered.contains(action_name) {
            continue;
        }
        registered.push(action_name.clone());
        gateway.register_adapter(action_name.clone(), "stub", adapter.clone());
    }
    (registry, Arc::new(gateway))
}

#[derive(Clone, Copy)]
enum InjectedPersistenceFailure {
    Trace,
    State,
}

fn fixture_tenant_registry(tenant_id: &splendor_kernel::TenantId) -> TenantRegistry {
    let registry = TenantRegistry::new();
    registry.insert(TenantContext::new(
        tenant_id.clone(),
        TenantPolicy {
            allowed_actions: vec!["no-effect".to_string()],
            allowed_adapters: vec!["stub".to_string()],
            allowed_permissions: Vec::new(),
        },
        QuotaPolicy::default(),
    ));
    registry
}

fn no_effect_engine(
    tenant_id: splendor_kernel::TenantId,
    run_id: RunId,
    outcome: NoEffectGatewayOutcome,
    submissions: Arc<AtomicUsize>,
    state_store: Arc<dyn StateStore>,
    trace_store: Arc<dyn TraceStore>,
) -> LoopEngine {
    LoopEngine::with_trace_store(
        AgentContext::new(
            splendor_kernel::AgentId::new(),
            tenant_id,
            AgentRuntimeConfig::default(),
        ),
        StateGraph::new(
            state_store,
            SnapshotPolicy {
                interval: Some(1),
                important_labels: Vec::new(),
            },
        ),
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(CandidateListPolicy {
            actions: vec![external_candidate("no-effect", Some(ActionId::new()))],
        }),
        Arc::new(NoEffectGateway {
            outcome,
            submissions,
        }),
        trace_store,
        Some(run_id),
    )
    .expect("no-effect engine")
}

fn assert_injected_loop_error(error: &LoopError, failure: InjectedPersistenceFailure) {
    match failure {
        InjectedPersistenceFailure::Trace => assert!(matches!(error, LoopError::Trace(_))),
        InjectedPersistenceFailure::State => assert!(matches!(error, LoopError::StateGraph(_))),
    }
}

fn assert_no_effect_suffix_failure_latches(
    outcome: NoEffectGatewayOutcome,
    state_store: Arc<dyn StateStore>,
    trace_store: Arc<dyn TraceStore>,
    arm_failure: impl FnOnce(),
    failure: InjectedPersistenceFailure,
    scheduled: bool,
) {
    let tenant_id = splendor_kernel::TenantId::new();
    let run_id = RunId::new();
    let submissions = Arc::new(AtomicUsize::new(0));
    let mut engine = no_effect_engine(
        tenant_id.clone(),
        run_id.clone(),
        outcome,
        Arc::clone(&submissions),
        state_store,
        trace_store.clone(),
    );
    arm_failure();

    if scheduled {
        let registry = fixture_tenant_registry(&tenant_id);
        let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
        scheduler.add_agent(engine);
        let first_error = scheduler
            .run_once()
            .expect_err("injected suffix persistence failure");
        match &first_error {
            SchedulerError::Loop(error) => assert_injected_loop_error(error, failure),
            _ => panic!("injected scheduler failure must come from the loop"),
        }
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
        let records_after_failure = trace_store
            .read(&run_id.to_string())
            .expect("trace after scheduler suffix failure");
        assert!(records_after_failure.iter().any(|record| {
            matches!(
                serde_json::from_value::<TraceEvent>(record.payload.clone())
                    .expect("trace event")
                    .kind,
                TraceEventKind::ActionVerificationStarted { .. }
            )
        }));

        assert!(matches!(
            scheduler.run_once(),
            Err(SchedulerError::Loop(LoopError::Policy(ref reason)))
                if reason == "tick_reconciliation_required"
        ));
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
        assert_eq!(
            trace_store
                .read(&run_id.to_string())
                .expect("trace after parked scheduler"),
            records_after_failure
        );
    } else {
        let first_error = engine
            .tick(1)
            .expect_err("injected suffix persistence failure");
        assert_injected_loop_error(&first_error, failure);
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
        let records_after_failure = trace_store
            .read(&run_id.to_string())
            .expect("trace after direct suffix failure");
        assert!(records_after_failure.iter().any(|record| {
            matches!(
                serde_json::from_value::<TraceEvent>(record.payload.clone())
                    .expect("trace event")
                    .kind,
                TraceEventKind::ActionVerificationStarted { .. }
            )
        }));

        assert!(matches!(
            engine.tick(2),
            Err(LoopError::Policy(ref reason)) if reason == "tick_reconciliation_required"
        ));
        assert_eq!(submissions.load(Ordering::SeqCst), 1);
        assert_eq!(
            trace_store
                .read(&run_id.to_string())
                .expect("trace after blocked direct tick"),
            records_after_failure
        );
    }
}

fn assert_state_only_commit_failure_latches(
    state_store: Arc<dyn StateStore>,
    arm_failure: impl FnOnce(),
    scheduled: bool,
) {
    let tenant_id = splendor_kernel::TenantId::new();
    let run_id = RunId::new();
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let policy_calls = Arc::new(AtomicUsize::new(0));
    let gateway_submissions = Arc::new(AtomicUsize::new(0));
    let mut engine = LoopEngine::with_trace_store(
        AgentContext::new(
            splendor_kernel::AgentId::new(),
            tenant_id.clone(),
            AgentRuntimeConfig::default(),
        ),
        StateGraph::new(
            state_store,
            SnapshotPolicy {
                interval: Some(1),
                important_labels: Vec::new(),
            },
        ),
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(CountingNoopPolicy {
            calls: Arc::clone(&policy_calls),
        }),
        Arc::new(NoEffectGateway {
            outcome: NoEffectGatewayOutcome::Denied,
            submissions: Arc::clone(&gateway_submissions),
        }),
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("state-only engine");
    arm_failure();

    if scheduled {
        let registry = fixture_tenant_registry(&tenant_id);
        let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
        scheduler.add_agent(engine);
        assert!(matches!(
            scheduler.run_once(),
            Err(SchedulerError::Loop(LoopError::StateGraph(_)))
        ));
        assert!(matches!(
            scheduler.run_once(),
            Err(SchedulerError::Loop(LoopError::Policy(ref reason)))
                if reason == "tick_reconciliation_required"
        ));
    } else {
        assert!(matches!(engine.tick(1), Err(LoopError::StateGraph(_))));
        assert!(matches!(
            engine.tick(2),
            Err(LoopError::Policy(ref reason)) if reason == "tick_reconciliation_required"
        ));
    }

    assert_eq!(policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(gateway_submissions.load(Ordering::SeqCst), 0);
    let events = trace_store
        .read(&run_id.to_string())
        .expect("state-only failure trace")
        .into_iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload).expect("trace event"))
        .collect::<Vec<_>>();
    assert!(events.iter().all(|event| !matches!(
        event.kind,
        TraceEventKind::ActionVerificationStarted { .. }
            | TraceEventKind::StateCommitted { .. }
            | TraceEventKind::LoopTickCompleted { .. }
    )));
}

impl StateStore for FailIfWrittenStateStore {
    fn put_state(&self, _state: StateData) -> Result<StateDataRef, StateStoreError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(StateStoreError::Poisoned)
    }

    fn get_state(&self, _data_ref: &StateDataRef) -> Result<StateData, StateStoreError> {
        Err(StateStoreError::MissingState)
    }

    fn commit_node(
        &self,
        _parent_ids: Vec<StateNodeId>,
        _data_ref: StateDataRef,
        _metadata: StateMetadata,
    ) -> Result<StateNodeId, StateStoreError> {
        Err(StateStoreError::Poisoned)
    }

    fn get_node(&self, _node_id: &StateNodeId) -> Result<StateNode, StateStoreError> {
        Err(StateStoreError::MissingNode)
    }

    fn snapshot(&self, _node_id: &StateNodeId) -> Result<SnapshotId, StateStoreError> {
        Err(StateStoreError::MissingSnapshot)
    }

    fn load_snapshot(&self, _snapshot_id: &SnapshotId) -> Result<StateSnapshot, StateStoreError> {
        Err(StateStoreError::MissingSnapshot)
    }
}

impl ActionAdapter for ForbiddenRawEffectAdapter {
    fn execute(
        &self,
        _action: &splendor_gateway::ActionRequest,
    ) -> Result<AdapterResult, AdapterError> {
        self.adapter_calls.fetch_add(1, Ordering::SeqCst);
        self.provider_calls.fetch_add(1, Ordering::SeqCst);
        self.network_calls.fetch_add(1, Ordering::SeqCst);
        self.filesystem_calls.fetch_add(1, Ordering::SeqCst);
        Ok(AdapterResult {
            output: serde_json::json!({"unexpected": true}),
            satisfied_postconditions: Vec::new(),
        })
    }
}

#[test]
fn loop_engine_persists_state_and_trace_records() {
    let state_store = Arc::new(InMemoryStateStore::default());
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let snapshot_policy = SnapshotPolicy {
        interval: Some(1),
        important_labels: Vec::new(),
    };
    let state_graph = StateGraph::new(state_store.clone(), snapshot_policy);
    let initial_state = StateData {
        bytes: vec![1],
        content_type: None,
    };

    let tenant_id = splendor_kernel::TenantId::new();
    let agent_id = splendor_kernel::AgentId::new();
    let agent = AgentContext::new(agent_id, tenant_id.clone(), AgentRuntimeConfig::default());
    let registry = TenantRegistry::new();
    registry.insert(TenantContext::new(
        tenant_id.clone(),
        TenantPolicy {
            allowed_actions: vec!["noop".to_string()],
            allowed_adapters: vec!["stub".to_string()],
            allowed_permissions: Vec::new(),
        },
        QuotaPolicy::default(),
    ));
    registry.begin_tick(1, OffsetDateTime::now_utc());

    let mut gateway = VerifiedActionGateway::new(Arc::new(registry));
    gateway.register_adapter("noop", "stub", Arc::new(StubAdapter));
    let gateway = Arc::new(gateway);

    let run_id = RunId::new();
    let mut engine = LoopEngine::with_trace_store(
        agent,
        state_graph,
        initial_state,
        Box::new(StaticPolicy),
        gateway,
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");
    engine.add_perceptor(StaticPerceptor);

    let outcome = engine.tick(1).expect("tick");
    assert_eq!(outcome.action_outcomes.len(), 1);
    assert!(matches!(
        outcome.action_outcomes[0].status,
        splendor_gateway::ActionStatus::Executed
    ));

    let snapshot_id = outcome
        .state_commit
        .snapshot_id
        .clone()
        .expect("snapshot id");
    let snapshot = state_store
        .load_snapshot(&snapshot_id)
        .expect("load snapshot");
    assert_eq!(snapshot.state.bytes, vec![9]);

    let records = trace_store
        .read(&run_id.to_string())
        .expect("trace records");
    assert!(!records.is_empty());

    let events = records
        .iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).expect("event"))
        .collect::<Vec<_>>();
    for (record, event) in records.iter().zip(events.iter()) {
        assert_eq!(record.sequence, event.sequence);
        assert_eq!(record.run_id, run_id.to_string());
        assert_eq!(event.run_id, run_id);
    }

    let first = events.first().expect("first event");
    let last = events.last().expect("last event");
    assert!(matches!(first.kind, TraceEventKind::RunStarted));
    assert!(matches!(
        events[1].kind,
        TraceEventKind::LoopTickStarted { tick_id: 1 }
    ));
    assert!(matches!(
        last.kind,
        TraceEventKind::LoopTickCompleted { tick_id: 1, .. }
    ));
    let state_event = events
        .iter()
        .find(|event| matches!(event.kind, TraceEventKind::StateCommitted { .. }))
        .expect("state committed");
    if let TraceEventKind::StateCommitted {
        state_hash,
        snapshot_id,
    } = &state_event.kind
    {
        assert_eq!(state_hash, outcome.state_commit.node_id.hash());
        assert_eq!(
            snapshot_id.as_ref(),
            outcome.state_commit.snapshot_id.as_ref()
        );
    }
}

#[test]
fn credential_percept_never_reaches_trace_policy_or_state_store() {
    let state_writes = Arc::new(AtomicUsize::new(0));
    let state_store = Arc::new(FailIfWrittenStateStore {
        writes: Arc::clone(&state_writes),
    });
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let graph = StateGraph::new(state_store, SnapshotPolicy::default());
    let policy_calls = Arc::new(AtomicUsize::new(0));
    let run_id = RunId::new();
    let mut engine = LoopEngine::with_trace_store(
        AgentContext::new(
            splendor_kernel::AgentId::new(),
            splendor_kernel::TenantId::new(),
            AgentRuntimeConfig::default(),
        ),
        graph,
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(CountingNoopPolicy {
            calls: Arc::clone(&policy_calls),
        }),
        Arc::new(splendor_gateway::UnimplementedGateway),
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");
    engine.add_perceptor(CredentialPerceptor);

    let error = engine.tick(1).expect_err("credential percept must deny");

    assert!(matches!(
        error,
        splendor_kernel::LoopError::Perceptor(ref reason)
            if reason == RAW_CREDENTIAL_INPUT_DENIED
    ));
    let retry_error = engine
        .tick(2)
        .expect_err("a rejected percept requires explicit reconciliation");
    assert!(matches!(
        retry_error,
        splendor_kernel::LoopError::Policy(ref reason)
            if reason == "tick_reconciliation_required"
    ));
    assert_eq!(policy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state_writes.load(Ordering::SeqCst), 0);
    let records = trace_store.read(&run_id.to_string()).expect("safe traces");
    let encoded = serde_json::to_string(&records).expect("traces serialize");
    assert!(!encoded.contains(PERCEPT_CANARY));
    let events = records
        .into_iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload).expect("event"))
        .collect::<Vec<_>>();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::LoopTickStarted { .. }))
            .count(),
        1,
        "the reconciliation block must reject a later direct tick before a second trace prefix"
    );
    assert!(!events.iter().any(|event| matches!(
        event.kind,
        TraceEventKind::PerceptsReceived { .. }
            | TraceEventKind::PolicyInvoked { .. }
            | TraceEventKind::StateCommitted { .. }
            | TraceEventKind::LoopTickCompleted { .. }
    )));
}

#[test]
fn credential_policy_state_stops_before_actions_outcome_and_state_commit() {
    let state_writes = Arc::new(AtomicUsize::new(0));
    let state_store = Arc::new(FailIfWrittenStateStore {
        writes: Arc::clone(&state_writes),
    });
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let graph = StateGraph::new(state_store, SnapshotPolicy::default());
    let tenant_id = splendor_kernel::TenantId::new();
    let registry = TenantRegistry::new();
    registry.insert(TenantContext::new(
        tenant_id.clone(),
        TenantPolicy {
            allowed_actions: vec!["noop".to_string()],
            allowed_adapters: vec!["stub".to_string()],
            allowed_permissions: Vec::new(),
        },
        QuotaPolicy::default(),
    ));
    registry.begin_tick(1, OffsetDateTime::now_utc());
    let adapter_calls = Arc::new(AtomicUsize::new(0));
    let observed_states = Arc::new(Mutex::new(Vec::new()));
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry));
    gateway.register_adapter(
        "noop",
        "stub",
        Arc::new(CountingAdapter {
            calls: Arc::clone(&adapter_calls),
        }),
    );
    let run_id = RunId::new();
    let mut engine = LoopEngine::with_trace_store(
        AgentContext::new(
            splendor_kernel::AgentId::new(),
            tenant_id,
            AgentRuntimeConfig::default(),
        ),
        graph,
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(CredentialStatePolicy {
            observed_states: Arc::clone(&observed_states),
        }),
        Arc::new(gateway),
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");
    engine.add_perceptor(StaticPerceptor);

    let error = engine.tick(1).expect_err("credential state must deny");

    assert!(matches!(
        error,
        splendor_kernel::LoopError::Policy(ref reason)
            if reason == RAW_CREDENTIAL_INPUT_DENIED
    ));
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state_writes.load(Ordering::SeqCst), 0);
    let retry_error = engine
        .tick(2)
        .expect_err("a later tick cannot advance the rejected state");
    assert!(matches!(
        retry_error,
        splendor_kernel::LoopError::Policy(ref reason)
            if reason == "tick_reconciliation_required"
    ));
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state_writes.load(Ordering::SeqCst), 0);
    assert_eq!(
        *observed_states.lock().expect("observed states"),
        vec![StateData {
            bytes: vec![0],
            content_type: None,
        }]
    );
    let records = trace_store.read(&run_id.to_string()).expect("safe traces");
    let encoded = serde_json::to_string(&records).expect("traces serialize");
    assert!(!encoded.contains(STATE_CANARY));
    let events = records
        .into_iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload).expect("event"))
        .collect::<Vec<_>>();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::LoopTickStarted { .. }))
            .count(),
        1,
        "the reconciliation block must reject a later direct tick before a second trace prefix"
    );
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::PolicyInvoked { .. })));
    assert!(!events.iter().any(|event| matches!(
        event.kind,
        TraceEventKind::PolicyCompleted { .. }
            | TraceEventKind::CandidatesProposed { .. }
            | TraceEventKind::OutcomeRecorded { .. }
            | TraceEventKind::StateCommitted { .. }
            | TraceEventKind::LoopTickCompleted { .. }
    )));
}

#[test]
fn credential_adapter_output_is_absent_from_outcome_trace_and_committed_state() {
    const OUTPUT_CANARY: &str = "C03_RAW_OUTPUT_KERNEL_CANARY";

    struct CredentialOutputAdapter {
        calls: Arc<AtomicUsize>,
    }

    impl ActionAdapter for CredentialOutputAdapter {
        fn execute(
            &self,
            _action: &splendor_gateway::ActionRequest,
        ) -> Result<AdapterResult, AdapterError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(AdapterResult {
                output: serde_json::json!({
                    "body": format!("password={OUTPUT_CANARY}")
                }),
                satisfied_postconditions: Vec::new(),
            })
        }
    }

    let state_store = Arc::new(InMemoryStateStore::default());
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let graph = StateGraph::new(
        state_store.clone(),
        SnapshotPolicy {
            interval: Some(1),
            important_labels: Vec::new(),
        },
    );
    let tenant_id = splendor_kernel::TenantId::new();
    let registry = TenantRegistry::new();
    registry.insert(TenantContext::new(
        tenant_id.clone(),
        TenantPolicy {
            allowed_actions: vec!["noop".to_string()],
            allowed_adapters: vec!["stub".to_string()],
            allowed_permissions: Vec::new(),
        },
        QuotaPolicy::default(),
    ));
    registry.begin_tick(1, OffsetDateTime::now_utc());
    let adapter_calls = Arc::new(AtomicUsize::new(0));
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry));
    gateway.register_adapter(
        "noop",
        "stub",
        Arc::new(CredentialOutputAdapter {
            calls: Arc::clone(&adapter_calls),
        }),
    );
    let run_id = RunId::new();
    let mut engine = LoopEngine::with_trace_store(
        AgentContext::new(
            splendor_kernel::AgentId::new(),
            tenant_id,
            AgentRuntimeConfig::default(),
        ),
        graph,
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(StaticPolicy),
        Arc::new(gateway),
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");
    engine.add_perceptor(StaticPerceptor);

    let tick = engine
        .tick(1)
        .expect("output suppression is a recorded failure");

    assert_eq!(adapter_calls.load(Ordering::SeqCst), 1);
    assert_eq!(tick.action_outcomes.len(), 1);
    let outcome = &tick.action_outcomes[0];
    assert_eq!(outcome.status, ActionStatus::Failed);
    assert_eq!(
        outcome.error.as_deref(),
        Some(RAW_CREDENTIAL_OUTPUT_SUPPRESSED)
    );
    let post_verification = outcome
        .post_verification
        .as_ref()
        .expect("suppression facts");
    assert_eq!(
        post_verification.reasons,
        vec![RAW_CREDENTIAL_OUTPUT_SUPPRESSED.to_string()]
    );
    assert_eq!(post_verification.artifacts["adapter_entered"], true);
    assert_eq!(
        post_verification.artifacts["effect_certainty"],
        EffectCertainty::Uncertain.as_str()
    );
    assert_eq!(
        post_verification.artifacts["retry_class"],
        RetryClass::NotRetryable.as_str()
    );
    assert_eq!(post_verification.artifacts["reconciliation_required"], true);
    assert!(outcome.output.is_none());

    let retry_error = engine
        .tick(2)
        .expect_err("post-effect suppression must block a direct retry");
    assert!(matches!(
        retry_error,
        splendor_kernel::LoopError::Policy(ref reason)
            if reason == "tick_reconciliation_required"
    ));
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 1);

    let records = trace_store.read(&run_id.to_string()).expect("raw traces");
    let encoded = serde_json::to_string(&records).expect("traces serialize");
    assert!(!encoded.contains(OUTPUT_CANARY));
    let events = records
        .into_iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload).expect("event"))
        .collect::<Vec<_>>();
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ActionFailed { .. })));
    assert!(!events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ActionExecuted { .. })));

    let snapshot = state_store
        .load_snapshot(tick.state_commit.snapshot_id.as_ref().expect("snapshot id"))
        .expect("safe state snapshot");
    let encoded_state = serde_json::to_string(&snapshot).expect("state serializes");
    assert!(!encoded_state.contains(OUTPUT_CANARY));
    assert_eq!(snapshot.state.bytes, vec![9]);
}

#[test]
fn benign_json_and_opaque_binary_policy_state_remain_compatible() {
    struct FixedStatePolicy(StateData);

    impl Policy for FixedStatePolicy {
        fn name(&self) -> &str {
            "fixed-state-policy"
        }

        fn decide(
            &self,
            _state: &StateData,
            _percepts: &[Percept],
        ) -> Result<PolicyDecision, splendor_kernel::LoopError> {
            Ok(PolicyDecision::new(Vec::new(), self.0.clone(), None))
        }
    }

    let cases = [
        (
            "benign-json",
            StateData {
                bytes: br#"{"status":"ready","values":[1,2,3]}"#.to_vec(),
                content_type: Some("application/json; charset=utf-8".to_string()),
            },
        ),
        (
            "opaque-binary",
            StateData {
                bytes: vec![0, 1, 255],
                content_type: Some("application/octet-stream".to_string()),
            },
        ),
    ];

    for (case, next_state) in cases {
        let state_store = Arc::new(InMemoryStateStore::default());
        let graph = StateGraph::new(
            state_store.clone(),
            SnapshotPolicy {
                interval: Some(1),
                important_labels: Vec::new(),
            },
        );
        let mut engine = LoopEngine::with_trace_store(
            AgentContext::new(
                splendor_kernel::AgentId::new(),
                splendor_kernel::TenantId::new(),
                AgentRuntimeConfig::default(),
            ),
            graph,
            StateData {
                bytes: b"initial".to_vec(),
                content_type: Some("text/plain".to_string()),
            },
            Box::new(FixedStatePolicy(next_state.clone())),
            Arc::new(splendor_gateway::UnimplementedGateway),
            Arc::new(InMemoryTraceStore::default()),
            Some(RunId::new()),
        )
        .expect("engine");
        engine.add_perceptor(StaticPerceptor);

        let tick = engine
            .tick(1)
            .unwrap_or_else(|error| panic!("{case}: {error}"));

        assert!(tick.action_outcomes.is_empty(), "{case}");
        let snapshot = state_store
            .load_snapshot(tick.state_commit.snapshot_id.as_ref().expect("snapshot id"))
            .unwrap_or_else(|error| panic!("{case}: {error}"));
        assert_eq!(snapshot.state, next_state, "{case}");
    }
}

#[test]
fn loop_engine_denies_raw_credentials_before_constraint_gateway_trace_state_and_replay() {
    let state_store = Arc::new(InMemoryStateStore::default());
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let state_graph = StateGraph::new(
        state_store.clone(),
        SnapshotPolicy {
            interval: Some(1),
            important_labels: Vec::new(),
        },
    );
    let tenant_id = splendor_kernel::TenantId::new();
    let agent_id = splendor_kernel::AgentId::new();
    let agent = AgentContext::new(agent_id, tenant_id.clone(), AgentRuntimeConfig::default());
    let registry = TenantRegistry::new();
    registry.insert(TenantContext::new(
        tenant_id,
        TenantPolicy {
            allowed_actions: vec!["unsafe-input".to_string(), "safe-input".to_string()],
            allowed_adapters: vec!["stub".to_string()],
            allowed_permissions: Vec::new(),
        },
        QuotaPolicy::default(),
    ));
    registry.begin_tick(1, OffsetDateTime::now_utc());

    let safe_adapter_calls = Arc::new(AtomicUsize::new(0));
    let raw_adapter_calls = Arc::new(AtomicUsize::new(0));
    let raw_provider_calls = Arc::new(AtomicUsize::new(0));
    let raw_network_calls = Arc::new(AtomicUsize::new(0));
    let raw_filesystem_calls = Arc::new(AtomicUsize::new(0));
    let mut gateway = VerifiedActionGateway::new(Arc::new(registry));
    gateway.register_adapter(
        "unsafe-input",
        "stub",
        Arc::new(ForbiddenRawEffectAdapter {
            adapter_calls: Arc::clone(&raw_adapter_calls),
            provider_calls: Arc::clone(&raw_provider_calls),
            network_calls: Arc::clone(&raw_network_calls),
            filesystem_calls: Arc::clone(&raw_filesystem_calls),
        }),
    );
    gateway.register_adapter(
        "safe-input",
        "stub",
        Arc::new(CountingAdapter {
            calls: Arc::clone(&safe_adapter_calls),
        }),
    );
    let constraint_names = Arc::new(Mutex::new(Vec::new()));
    let outcome_names = Arc::new(Mutex::new(Vec::new()));
    let run_id = RunId::new();
    let mut engine = LoopEngine::with_trace_store(
        agent,
        state_graph,
        StateData {
            bytes: b"initial".to_vec(),
            content_type: None,
        },
        Box::new(MixedCredentialPolicy),
        Arc::new(gateway),
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");
    engine.set_constraint_engine(RecordingConstraintEngine {
        names: Arc::clone(&constraint_names),
    });
    engine.set_outcome_evaluator(RecordingOutcomeEvaluator {
        names: Arc::clone(&outcome_names),
    });

    let outcome = engine.tick(1).expect("mixed tick");

    assert_eq!(outcome.action_outcomes.len(), 3);
    assert_eq!(outcome.action_outcomes[0].status, ActionStatus::Denied);
    assert_eq!(
        outcome.action_outcomes[0].verification,
        VerificationResult::deny(RAW_CREDENTIAL_INPUT_DENIED)
    );
    assert_eq!(outcome.action_outcomes[1].status, ActionStatus::Denied);
    assert_eq!(
        outcome.action_outcomes[1].verification,
        VerificationResult::deny(RAW_CREDENTIAL_INPUT_DENIED)
    );
    assert_eq!(outcome.action_outcomes[2].status, ActionStatus::Executed);
    assert_eq!(safe_adapter_calls.load(Ordering::SeqCst), 1);
    assert_eq!(raw_adapter_calls.load(Ordering::SeqCst), 0);
    assert_eq!(raw_provider_calls.load(Ordering::SeqCst), 0);
    assert_eq!(raw_network_calls.load(Ordering::SeqCst), 0);
    assert_eq!(raw_filesystem_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        *constraint_names.lock().expect("constraint names"),
        vec!["safe-input".to_string()]
    );
    assert_eq!(
        *outcome_names.lock().expect("outcome names"),
        vec!["safe-input".to_string()]
    );

    let snapshot = state_store
        .load_snapshot(
            outcome
                .state_commit
                .snapshot_id
                .as_ref()
                .expect("snapshot id"),
        )
        .expect("snapshot");
    assert!(!String::from_utf8_lossy(&snapshot.state.bytes).contains(ACTION_CANARY));
    assert!(!String::from_utf8_lossy(&snapshot.state.bytes).contains(RECEIPT_CANARY));

    let records = trace_store
        .read(&run_id.to_string())
        .expect("trace records");
    let encoded_records = serde_json::to_string(&records).expect("records serialize");
    assert!(!encoded_records.contains(ACTION_CANARY));
    assert!(!encoded_records.contains(RECEIPT_CANARY));
    let events = records
        .iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).expect("event"))
        .collect::<Vec<_>>();
    let candidates = events
        .iter()
        .find_map(|event| match &event.kind {
            TraceEventKind::CandidatesProposed { actions } => Some(actions),
            _ => None,
        })
        .expect("candidates");
    assert_eq!(candidates[0], raw_credential_denied_action());
    assert_eq!(candidates[1], raw_credential_denied_action());
    assert_eq!(candidates[2].name, "safe-input");
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        TraceEventKind::ActionDenied { action, result }
            if action == &raw_credential_denied_action()
                && result == &VerificationResult::deny(RAW_CREDENTIAL_INPUT_DENIED)
    )));

    // Inspect-only reconstruction reads the sanitized records and cannot call an adapter.
    let replayed = trace_store
        .read(&run_id.to_string())
        .expect("inspect replay");
    assert_eq!(replayed, records);
    assert_eq!(safe_adapter_calls.load(Ordering::SeqCst), 1);
    assert_eq!(raw_adapter_calls.load(Ordering::SeqCst), 0);
    assert_eq!(raw_provider_calls.load(Ordering::SeqCst), 0);
    assert!(!serde_json::to_string(&replayed)
        .expect("replay serializes")
        .contains(ACTION_CANARY));
    assert!(!serde_json::to_string(&replayed)
        .expect("replay serializes")
        .contains(RECEIPT_CANARY));
}

#[test]
fn denied_and_needs_approval_trace_suffix_failures_latch_direct_and_scheduled_ticks() {
    for outcome in [
        NoEffectGatewayOutcome::Denied,
        NoEffectGatewayOutcome::NeedsApproval,
    ] {
        let failures = match outcome {
            NoEffectGatewayOutcome::Denied => vec![
                TraceFailurePoint::ActionVerificationCompleted,
                TraceFailurePoint::ActionDenied,
                TraceFailurePoint::OutcomeRecorded,
                TraceFailurePoint::StateCommitted,
                TraceFailurePoint::LoopTickCompleted,
            ],
            NoEffectGatewayOutcome::NeedsApproval => vec![
                TraceFailurePoint::ActionVerificationCompleted,
                TraceFailurePoint::ApprovalRequested,
                TraceFailurePoint::ActionNeedsApproval,
                TraceFailurePoint::OutcomeRecorded,
                TraceFailurePoint::StateCommitted,
                TraceFailurePoint::LoopTickCompleted,
            ],
        };
        for failure in failures {
            for scheduled in [false, true] {
                let trace_store = Arc::new(ArmableTraceStore::new(failure));
                let armable = trace_store.clone();
                assert_no_effect_suffix_failure_latches(
                    outcome,
                    Arc::new(InMemoryStateStore::default()),
                    trace_store,
                    move || armable.arm(),
                    InjectedPersistenceFailure::Trace,
                    scheduled,
                );
            }
        }
    }
}

#[test]
fn denied_and_needs_approval_state_suffix_failures_latch_direct_and_scheduled_ticks() {
    for outcome in [
        NoEffectGatewayOutcome::Denied,
        NoEffectGatewayOutcome::NeedsApproval,
    ] {
        for failure in [
            StateFailurePoint::PutState,
            StateFailurePoint::CommitNode,
            StateFailurePoint::Snapshot,
        ] {
            for scheduled in [false, true] {
                let state_store = Arc::new(ArmableStateStore::new(failure));
                let armable = state_store.clone();
                assert_no_effect_suffix_failure_latches(
                    outcome,
                    state_store,
                    Arc::new(InMemoryTraceStore::default()),
                    move || armable.arm(),
                    InjectedPersistenceFailure::State,
                    scheduled,
                );
            }
        }
    }
}

#[test]
fn state_only_commit_failures_latch_direct_and_scheduled_ticks() {
    for failure in [
        StateFailurePoint::PutState,
        StateFailurePoint::CommitNode,
        StateFailurePoint::Snapshot,
    ] {
        for scheduled in [false, true] {
            let state_store = Arc::new(ArmableStateStore::new(failure));
            let armable = state_store.clone();
            assert_state_only_commit_failure_latches(state_store, move || armable.arm(), scheduled);
        }
    }
}

#[test]
fn completed_denied_and_needs_approval_ticks_remain_schedulable() {
    for outcome in [
        NoEffectGatewayOutcome::Denied,
        NoEffectGatewayOutcome::NeedsApproval,
    ] {
        let tenant_id = splendor_kernel::TenantId::new();
        let run_id = RunId::new();
        let submissions = Arc::new(AtomicUsize::new(0));
        let trace_store = Arc::new(InMemoryTraceStore::default());
        let engine = no_effect_engine(
            tenant_id.clone(),
            run_id.clone(),
            outcome,
            Arc::clone(&submissions),
            Arc::new(InMemoryStateStore::default()),
            trace_store.clone(),
        );
        let registry = fixture_tenant_registry(&tenant_id);
        let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
        scheduler.add_agent(engine);

        for _ in 0..2 {
            let step = scheduler.run_once().expect("completed no-effect tick");
            let status = &step.outcome.action_outcomes[0].status;
            assert!(match outcome {
                NoEffectGatewayOutcome::Denied => status == &ActionStatus::Denied,
                NoEffectGatewayOutcome::NeedsApproval => status == &ActionStatus::NeedsApproval,
            });
        }
        assert_eq!(submissions.load(Ordering::SeqCst), 2);
        let completed = trace_store
            .read(&run_id.to_string())
            .expect("completed no-effect trace")
            .into_iter()
            .filter(|record| {
                matches!(
                    serde_json::from_value::<TraceEvent>(record.payload.clone())
                        .expect("trace event")
                        .kind,
                    TraceEventKind::LoopTickCompleted { .. }
                )
            })
            .count();
        assert_eq!(completed, 2);
    }
}

#[test]
fn stateful_no_effect_completion_failure_keeps_commit_and_blocks_live_and_restart() {
    let trace_store = Arc::new(ArmableTraceStore::new(TraceFailurePoint::LoopTickCompleted));
    let state_store = Arc::new(InMemoryStateStore::default());
    let snapshot_policy = SnapshotPolicy {
        interval: Some(1),
        important_labels: Vec::new(),
    };
    let tenant_id = splendor_kernel::TenantId::new();
    let agent_id = splendor_kernel::AgentId::new();
    let run_id = RunId::new();
    let policy_calls = Arc::new(AtomicUsize::new(0));
    let adapter_calls = Arc::new(AtomicUsize::new(0));
    let action_names = vec!["must-not-run".to_string()];
    let (_, gateway) = recording_gateway(
        &tenant_id,
        &action_names,
        Arc::new(CountingAdapter {
            calls: Arc::clone(&adapter_calls),
        }),
    );
    let mut engine = LoopEngine::with_trace_store(
        AgentContext::new(
            agent_id.clone(),
            tenant_id.clone(),
            AgentRuntimeConfig::default(),
        ),
        StateGraph::new(state_store.clone(), snapshot_policy.clone()),
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(CountingNoopPolicy {
            calls: Arc::clone(&policy_calls),
        }),
        gateway.clone(),
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("fresh state-only engine");

    trace_store.arm();
    let error = engine
        .tick(1)
        .expect_err("LoopTickCompleted append must fail the tick");

    assert!(matches!(
        error,
        LoopError::Trace(splendor_kernel::TraceError::Compatibility(
            splendor_evidence::TraceCompatibilityError::Store
        ))
    ));
    assert_eq!(policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);

    let records_after_failure = trace_store
        .read(&run_id.to_string())
        .expect("trace after failed completion");
    let events = records_after_failure
        .iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).expect("event"))
        .collect::<Vec<_>>();
    let state_events = events
        .iter()
        .filter(|event| matches!(event.kind, TraceEventKind::StateCommitted { .. }))
        .collect::<Vec<_>>();
    assert_eq!(state_events.len(), 1);
    assert!(!events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::LoopTickCompleted { .. })));
    let state_event = state_events[0];
    let committed_node_id = state_event
        .identity
        .state_node_id
        .as_ref()
        .expect("committed state identity");
    let snapshot_id = match &state_event.kind {
        TraceEventKind::StateCommitted {
            snapshot_id: Some(snapshot_id),
            ..
        } => snapshot_id,
        _ => panic!("state commit must include its tick snapshot"),
    };
    let committed_snapshot = state_store
        .load_snapshot(snapshot_id)
        .expect("durably traced state snapshot");
    assert_eq!(&committed_snapshot.node_id, committed_node_id);
    assert_eq!(committed_snapshot.state.bytes, vec![1]);

    let second_error = engine
        .tick(2)
        .expect_err("failed completion must block another live tick");
    assert!(matches!(
        second_error,
        LoopError::Policy(ref reason) if reason == "tick_reconciliation_required"
    ));
    assert_eq!(policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        trace_store
            .read(&run_id.to_string())
            .expect("trace after blocked tick"),
        records_after_failure
    );
    drop(engine);

    let resumed = LoopEngine::resume_from_trace_store(
        AgentContext::new(agent_id, tenant_id, AgentRuntimeConfig::default()),
        StateGraph::new(state_store, snapshot_policy),
        Box::new(CountingNoopPolicy {
            calls: Arc::clone(&policy_calls),
        }),
        gateway,
        trace_store.clone(),
        run_id.clone(),
    );
    assert!(matches!(
        resumed,
        Err(LoopError::Resume(reason)) if reason == "tick_reconciliation_required"
    ));
    assert_eq!(policy_calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        trace_store
            .read(&run_id.to_string())
            .expect("trace after rejected restart"),
        records_after_failure
    );
}

fn assert_uncertain_effect_restart_is_blocked(
    trace_store: Arc<dyn TraceStore>,
    state_store: Arc<dyn StateStore>,
    second_outcome: EnteredAdapterOutcome,
    arm_failure: impl FnOnce(),
) {
    let tenant_id = splendor_kernel::TenantId::new();
    let agent_id = splendor_kernel::AgentId::new();
    let run_id = RunId::new();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(SequencedEnteredAdapter {
        calls: Arc::clone(&calls),
        second_outcome,
    });
    let action_names = vec!["external-effect".to_string()];
    let (registry, gateway) = recording_gateway(&tenant_id, &action_names, adapter);
    let snapshot_policy = SnapshotPolicy {
        interval: Some(1),
        important_labels: Vec::new(),
    };
    let graph = StateGraph::new(state_store.clone(), snapshot_policy.clone());
    let mut candidate = external_candidate("external-effect", Some(ActionId::new()));
    if second_outcome == EnteredAdapterOutcome::PostconditionFailure {
        candidate.action.postconditions = vec!["effect-confirmed".to_string()];
    }
    let policy = CandidateListPolicy {
        actions: vec![candidate],
    };
    let engine = LoopEngine::with_trace_store(
        AgentContext::new(
            agent_id.clone(),
            tenant_id.clone(),
            AgentRuntimeConfig::default(),
        ),
        graph,
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(policy.clone()),
        gateway.clone(),
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("fresh engine");
    let mut scheduler = Scheduler::with_registry(SchedulerConfig::default(), registry);
    scheduler.add_agent(engine);

    scheduler.run_once().expect("completed snapshot tick");
    arm_failure();
    scheduler
        .run_once()
        .expect_err("the injected post-entry persistence failure must fail the tick");
    assert!(matches!(
        scheduler.run_once(),
        Err(SchedulerError::Loop(LoopError::Policy(reason)))
            if reason == "tick_reconciliation_required"
    ));
    drop(scheduler);

    assert_eq!(
        *calls.lock().expect("adapter calls"),
        vec!["external-effect".to_string(), "external-effect".to_string()]
    );
    let trace_before_resume = trace_store
        .read(&run_id.to_string())
        .expect("trace before resume");
    let resumed = LoopEngine::resume_from_trace_store(
        AgentContext::new(
            agent_id.clone(),
            tenant_id.clone(),
            AgentRuntimeConfig::default(),
        ),
        StateGraph::new(state_store.clone(), snapshot_policy.clone()),
        Box::new(policy.clone()),
        gateway.clone(),
        trace_store.clone(),
        run_id.clone(),
    );
    assert!(matches!(
        resumed,
        Err(LoopError::Resume(reason)) if reason == "tick_reconciliation_required"
    ));
    let shared_runtime = Arc::new(
        KernelRuntime::with_trace_store(trace_store.clone(), Some(run_id.clone()))
            .expect("shared resume runtime"),
    );
    let shared_resumed = LoopEngine::resume_from_shared_trace_runtime_and_work_order(
        AgentContext::new(agent_id, tenant_id, AgentRuntimeConfig::default()),
        StateGraph::new(state_store, snapshot_policy),
        Box::new(policy),
        gateway,
        trace_store.clone(),
        shared_runtime,
        run_id.clone(),
        None,
    );
    assert!(matches!(
        shared_resumed,
        Err(LoopError::Resume(reason)) if reason == "tick_reconciliation_required"
    ));
    assert_eq!(
        trace_store
            .read(&run_id.to_string())
            .expect("trace after rejected resume"),
        trace_before_resume
    );
    assert_eq!(calls.lock().expect("adapter calls").len(), 2);
}

#[test]
fn every_post_gateway_trace_failure_blocks_process_restart_reexecution() {
    for adapter_outcome in [
        EnteredAdapterOutcome::Success,
        EnteredAdapterOutcome::GenericFailure,
        EnteredAdapterOutcome::PostconditionFailure,
    ] {
        let terminal_events = match adapter_outcome {
            EnteredAdapterOutcome::Success => vec![TraceFailurePoint::ActionExecuted],
            EnteredAdapterOutcome::GenericFailure => vec![TraceFailurePoint::ActionFailed],
            EnteredAdapterOutcome::PostconditionFailure => vec![
                TraceFailurePoint::ActionExecuted,
                TraceFailurePoint::ActionFailed,
            ],
        };
        let failures = std::iter::once(TraceFailurePoint::ActionVerificationCompleted)
            .chain(terminal_events)
            .chain([
                TraceFailurePoint::OutcomeRecorded,
                TraceFailurePoint::StateCommitted,
                TraceFailurePoint::LoopTickCompleted,
            ]);
        for failure in failures {
            let trace_store = Arc::new(ArmableTraceStore::new(failure));
            let state_store = Arc::new(InMemoryStateStore::default());
            assert_uncertain_effect_restart_is_blocked(
                trace_store.clone(),
                state_store,
                adapter_outcome,
                || trace_store.arm(),
            );
        }
    }
}

#[test]
fn every_post_gateway_state_failure_blocks_process_restart_reexecution() {
    for adapter_outcome in [
        EnteredAdapterOutcome::Success,
        EnteredAdapterOutcome::GenericFailure,
        EnteredAdapterOutcome::PostconditionFailure,
    ] {
        for failure in [
            StateFailurePoint::PutState,
            StateFailurePoint::CommitNode,
            StateFailurePoint::Snapshot,
        ] {
            let trace_store = Arc::new(InMemoryTraceStore::default());
            let state_store = Arc::new(ArmableStateStore::new(failure));
            assert_uncertain_effect_restart_is_blocked(
                trace_store,
                state_store.clone(),
                adapter_outcome,
                || state_store.arm(),
            );
        }
    }
}

#[test]
fn generic_and_postcondition_failures_remain_parked_after_durable_tick_completion() {
    for (adapter_outcome, expected_certainty) in [
        (EnteredAdapterOutcome::GenericFailure, "uncertain"),
        (EnteredAdapterOutcome::PostconditionFailure, "known"),
    ] {
        let tenant_id = splendor_kernel::TenantId::new();
        let agent_id = splendor_kernel::AgentId::new();
        let run_id = RunId::new();
        let action_id = ActionId::new();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let adapter = Arc::new(RecordingEnteredAdapter {
            calls: Arc::clone(&calls),
            outcome: adapter_outcome,
        });
        let action_names = vec!["nonretryable-effect".to_string()];
        let (registry, gateway) = recording_gateway(&tenant_id, &action_names, adapter);
        registry.begin_tick(1, OffsetDateTime::now_utc());
        let trace_store = Arc::new(InMemoryTraceStore::default());
        let state_store = Arc::new(InMemoryStateStore::default());
        let snapshot_policy = SnapshotPolicy {
            interval: Some(1),
            important_labels: Vec::new(),
        };
        let mut candidate = external_candidate("nonretryable-effect", Some(action_id));
        if adapter_outcome == EnteredAdapterOutcome::PostconditionFailure {
            candidate.action.postconditions = vec!["effect-confirmed".to_string()];
        }
        let policy = CandidateListPolicy {
            actions: vec![candidate],
        };
        let mut engine = LoopEngine::with_trace_store(
            AgentContext::new(
                agent_id.clone(),
                tenant_id.clone(),
                AgentRuntimeConfig::default(),
            ),
            StateGraph::new(state_store.clone(), snapshot_policy.clone()),
            StateData {
                bytes: vec![0],
                content_type: None,
            },
            Box::new(policy.clone()),
            gateway.clone(),
            trace_store.clone(),
            Some(run_id.clone()),
        )
        .expect("engine");

        let tick = engine.tick(1).expect("failed effect outcome is durable");
        let outcome = tick.action_outcomes.first().expect("action outcome");
        assert_eq!(outcome.status, ActionStatus::Failed);
        let facts = outcome
            .post_verification
            .as_ref()
            .expect("effect boundary facts");
        assert_eq!(facts.artifacts["adapter_entered"], true);
        assert_eq!(facts.artifacts["effect_certainty"], expected_certainty);
        assert_eq!(facts.artifacts["retry_class"], "not_retryable");
        assert_eq!(facts.artifacts["reconciliation_required"], true);
        assert!(!serde_json::to_string(outcome)
            .expect("outcome serializes")
            .contains("provider detail must not escape"));

        assert!(matches!(
            engine.tick(2),
            Err(LoopError::Policy(reason)) if reason == "tick_reconciliation_required"
        ));
        assert_eq!(calls.lock().expect("adapter calls").len(), 1);
        drop(engine);

        let records = trace_store
            .read(&run_id.to_string())
            .expect("trace records");
        let encoded = serde_json::to_string(&records).expect("records serialize");
        assert!(encoded.contains("adapter_entered"));
        assert!(encoded.contains("reconciliation_required"));
        assert!(!encoded.contains("provider detail must not escape"));

        let resumed = LoopEngine::resume_from_trace_store(
            AgentContext::new(agent_id, tenant_id, AgentRuntimeConfig::default()),
            StateGraph::new(state_store, snapshot_policy),
            Box::new(policy),
            gateway,
            trace_store,
            run_id,
        );
        assert!(matches!(
            resumed,
            Err(LoopError::Resume(reason)) if reason == "tick_reconciliation_required"
        ));
        assert_eq!(calls.lock().expect("adapter calls").len(), 1);
    }
}

#[test]
fn duplicate_explicit_action_ids_do_not_enter_verified_gateway_adapter() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(RecordingSuppressionAdapter {
        calls: Arc::clone(&calls),
        suppress_action: None,
        suppress_on_call: None,
    });
    let tenant_id = splendor_kernel::TenantId::new();
    let action_names = vec!["duplicate-effect".to_string()];
    let (registry, gateway) = recording_gateway(&tenant_id, &action_names, adapter);
    registry.begin_tick(1, OffsetDateTime::now_utc());
    let action_id = ActionId::new();
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let run_id = RunId::new();
    let mut engine = LoopEngine::with_trace_store(
        AgentContext::new(
            splendor_kernel::AgentId::new(),
            tenant_id,
            AgentRuntimeConfig::default(),
        ),
        StateGraph::new(
            Arc::new(InMemoryStateStore::default()),
            SnapshotPolicy::default(),
        ),
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(CandidateListPolicy {
            actions: vec![
                external_candidate("duplicate-effect", Some(action_id.clone())),
                external_candidate("duplicate-effect", Some(action_id)),
            ],
        }),
        gateway,
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");

    let error = engine
        .tick(1)
        .expect_err("duplicate explicit action IDs must fail closed");
    assert!(matches!(
        error,
        LoopError::Policy(reason) if reason == "duplicate_action_id"
    ));
    assert!(calls.lock().expect("adapter calls").is_empty());
    let events = trace_store
        .read(&run_id.to_string())
        .expect("trace records")
        .into_iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload).expect("event"))
        .collect::<Vec<_>>();
    assert!(events
        .iter()
        .all(|event| !matches!(event.kind, TraceEventKind::ActionVerificationStarted { .. })));
}

#[test]
fn one_explicit_action_id_can_be_re_evaluated_on_distinct_durable_ticks() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(RecordingSuppressionAdapter {
        calls: Arc::clone(&calls),
        suppress_action: None,
        suppress_on_call: None,
    });
    let tenant_id = splendor_kernel::TenantId::new();
    let action_names = vec!["stable-effect".to_string()];
    let (registry, gateway) = recording_gateway(&tenant_id, &action_names, adapter);
    let action_id = ActionId::new();
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let run_id = RunId::new();
    let mut engine = LoopEngine::with_trace_store(
        AgentContext::new(
            splendor_kernel::AgentId::new(),
            tenant_id,
            AgentRuntimeConfig::default(),
        ),
        StateGraph::new(
            Arc::new(InMemoryStateStore::default()),
            SnapshotPolicy::default(),
        ),
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(CandidateListPolicy {
            actions: vec![external_candidate("stable-effect", Some(action_id.clone()))],
        }),
        gateway,
        trace_store.clone(),
        Some(run_id.clone()),
    )
    .expect("engine");

    registry.begin_tick(1, OffsetDateTime::now_utc());
    engine.tick(1).expect("first action evaluation");
    registry.begin_tick(2, OffsetDateTime::now_utc());
    engine.tick(2).expect("second action evaluation");

    assert_eq!(calls.lock().expect("adapter calls").len(), 2);
    let action_ticks = trace_store
        .read(&run_id.to_string())
        .expect("trace records")
        .into_iter()
        .map(|record| serde_json::from_value::<TraceEvent>(record.payload).expect("event"))
        .filter(|event| {
            matches!(event.kind, TraceEventKind::ActionVerificationStarted { .. })
                && event.identity.action_id.as_ref() == Some(&action_id)
        })
        .filter_map(|event| event.identity.tick_id.map(|tick_id| tick_id.get()))
        .collect::<Vec<_>>();
    assert_eq!(action_ticks, vec![1, 2]);
}

#[test]
fn suppression_stops_all_later_candidates_for_first_middle_and_last_positions() {
    for suppression_index in 0..3 {
        let action_names = (0..3)
            .map(|index| {
                if index == suppression_index {
                    "suppress".to_string()
                } else {
                    format!("safe-{index}")
                }
            })
            .collect::<Vec<_>>();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let adapter = Arc::new(RecordingSuppressionAdapter {
            calls: Arc::clone(&calls),
            suppress_action: Some("suppress".to_string()),
            suppress_on_call: None,
        });
        let tenant_id = splendor_kernel::TenantId::new();
        let (registry, gateway) = recording_gateway(&tenant_id, &action_names, adapter);
        registry.begin_tick(1, OffsetDateTime::now_utc());
        let trace_store = Arc::new(InMemoryTraceStore::default());
        let run_id = RunId::new();
        let mut engine = LoopEngine::with_trace_store(
            AgentContext::new(
                splendor_kernel::AgentId::new(),
                tenant_id,
                AgentRuntimeConfig::default(),
            ),
            StateGraph::new(
                Arc::new(InMemoryStateStore::default()),
                SnapshotPolicy::default(),
            ),
            StateData {
                bytes: vec![0],
                content_type: None,
            },
            Box::new(CandidateListPolicy {
                actions: action_names
                    .iter()
                    .map(|name| external_candidate(name, Some(ActionId::new())))
                    .collect(),
            }),
            gateway,
            trace_store.clone(),
            Some(run_id.clone()),
        )
        .expect("engine");

        let outcome = engine.tick(1).expect("suppression tick is recorded");
        assert_eq!(
            *calls.lock().expect("adapter calls"),
            action_names[..=suppression_index].to_vec(),
            "suppression_index={suppression_index}"
        );
        assert_eq!(
            outcome.action_outcomes.len(),
            suppression_index + 1,
            "suppression_index={suppression_index}"
        );
        assert_eq!(
            outcome.action_outcomes.last().map(|item| &item.status),
            Some(&ActionStatus::Failed)
        );
        assert_eq!(
            outcome
                .action_outcomes
                .last()
                .and_then(|item| item.error.as_deref()),
            Some(RAW_CREDENTIAL_OUTPUT_SUPPRESSED)
        );
        let events = trace_store
            .read(&run_id.to_string())
            .expect("trace records")
            .into_iter()
            .map(|record| serde_json::from_value::<TraceEvent>(record.payload).expect("event"))
            .collect::<Vec<_>>();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event.kind,
                    TraceEventKind::ActionVerificationStarted { .. }
                ))
                .count(),
            suppression_index + 1
        );
        assert!(!serde_json::to_string(&events)
            .expect("events serialize")
            .contains("C03_RESTART_SUPPRESSION_CANARY"));
        let retry = engine
            .tick(2)
            .expect_err("suppression must park the engine");
        assert!(matches!(
            retry,
            LoopError::Policy(reason) if reason == "tick_reconciliation_required"
        ));
    }
}

#[test]
fn equivalent_candidates_with_distinct_ids_enter_the_gateway_only_once_after_suppression() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(RecordingSuppressionAdapter {
        calls: Arc::clone(&calls),
        suppress_action: Some("equivalent-effect".to_string()),
        suppress_on_call: None,
    });
    let tenant_id = splendor_kernel::TenantId::new();
    let action_names = vec!["equivalent-effect".to_string()];
    let (registry, gateway) = recording_gateway(&tenant_id, &action_names, adapter);
    registry.begin_tick(1, OffsetDateTime::now_utc());
    let mut engine = LoopEngine::with_trace_store(
        AgentContext::new(
            splendor_kernel::AgentId::new(),
            tenant_id,
            AgentRuntimeConfig::default(),
        ),
        StateGraph::new(
            Arc::new(InMemoryStateStore::default()),
            SnapshotPolicy::default(),
        ),
        StateData {
            bytes: vec![0],
            content_type: None,
        },
        Box::new(CandidateListPolicy {
            actions: vec![
                external_candidate("equivalent-effect", Some(ActionId::new())),
                external_candidate("equivalent-effect", Some(ActionId::new())),
            ],
        }),
        gateway,
        Arc::new(InMemoryTraceStore::default()),
        Some(RunId::new()),
    )
    .expect("engine");

    let outcome = engine.tick(1).expect("suppression tick");
    assert_eq!(
        *calls.lock().expect("adapter calls"),
        vec!["equivalent-effect".to_string()]
    );
    assert_eq!(outcome.action_outcomes.len(), 1);
}
