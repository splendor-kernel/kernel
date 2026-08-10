mod support;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderValue, Method, Request, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use splendor_daemon::{
    router, ApiErrorBody, AppendPerceptRequest, CircuitBreakerSyncResponse,
    ConfiguredActionAdapters, CreateRunRequest, CreateRunResponse, DaemonActionCandidate,
    DaemonConfig, DaemonState, DevicePolicyCacheStatus, DeviceRuntimeProfile,
    DeviceTraceBufferStatus, LifecycleRequest, PolicySyncRequest, PolicySyncResponse,
    RegisterDeviceProfileRequest, RegisteredAction, ReplayResponse, RunInspectResponse, RunStatus,
    SafetyContext, StateHeadResponse, StateSnapshotExportRequest, StateSnapshotExportResponse,
    StateSnapshotImportRequest, StateSnapshotImportResponse, SubmitActionRequest,
    SubmitPhysicalActionRequest, TickResponse, TraceExportResponse, TracePageResponse,
};
use splendor_gateway::{
    ActionAdapter, ActionRequest, AdapterError, AdapterResult, RAW_CREDENTIAL_INPUT_DENIED,
    RAW_CREDENTIAL_OUTPUT_SUPPRESSED,
};
use splendor_kernel::LocalAuthorityObligationReceiptConfig;
use splendor_store::{
    compute_trace_envelope_hash, compute_trace_event_hash, InMemoryTraceStore, RuntimeTraceAppend,
    RuntimeTraceFence, RuntimeTraceLimits, RuntimeTracePage, RuntimeTracePortError,
    RuntimeTraceReader, RuntimeTraceReaderHandle, RuntimeTraceStoreIdentity, RuntimeTraceTail,
    RuntimeTraceWriter, RuntimeTraceWriterHandle, RuntimeTraceWriterRequest, TraceRecord,
    TraceStore, TraceStoreError,
};
use splendor_types::{
    Action, ActionId, AgentId, ApprovalDecision, ApprovalEvidence, ApprovalId, ApprovalPolicy,
    AuditAttribution, AuthorityDecisionId, AuthorityObligationId, AuthorityObligationKind,
    AuthorityObligationReceipt, AuthorityObligationReceiptId, AuthorityObligationReceiptValidation,
    AuthorityObligationReceiptValidationKind, CallerCredential, CircuitBreaker, CircuitBreakerId,
    CircuitBreakerScope, ClientPrincipal, ContentHash, CredentialAudience, CredentialBinding,
    EffectCertainty, EndpointScope, NodeId, Percept, PerceptProvenance, PolicyBundle,
    PolicyBundleEnvelope, PolicyBundleId, PolicyDegradedMode, PrincipalId, QuotaUsage, RetryClass,
    RevocationStatus, RunId, SideEffectClass, TenantId, TraceEvent, TraceEventId, TraceEventKind,
    TraceId, WorkOrder, WorkOrderEnvelope, WorkOrderId, WorkOrderPlacement, WorkOrderQuotaPolicy,
    APPROVAL_EVIDENCE_SCHEMA_VERSION, FORBIDDEN_PHYSICAL_ACTION_PATTERNS,
    POLICY_BUNDLE_SCHEMA_VERSION, WORK_ORDER_SCHEMA_VERSION,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tower::ServiceExt;

fn action_test_state() -> DaemonState {
    support::local_state(&["daemon.local"])
}

struct CredentialOutputAdapter {
    calls: Arc<AtomicUsize>,
}

impl ActionAdapter for CredentialOutputAdapter {
    fn execute(&self, action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let output = if action.action.name == "allowed_action" {
            let mut body = b"password=C03_DAEMON_OUTPUT_CANARY"
                .iter()
                .copied()
                .map(serde_json::Value::from)
                .collect::<Vec<_>>();
            body.push(json!(300));
            json!({"body": body})
        } else {
            json!({"status": "ready"})
        };
        Ok(AdapterResult {
            output,
            satisfied_postconditions: Vec::new(),
        })
    }
}

struct FixedOutputAdapter {
    calls: Arc<AtomicUsize>,
    output: Value,
}

impl ActionAdapter for FixedOutputAdapter {
    fn execute(&self, action: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(AdapterResult {
            output: self.output.clone(),
            satisfied_postconditions: action.action.postconditions.clone(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TraceFailureTarget {
    Accepted,
    Reconnected,
    Rejected,
    SyncFailed,
    Revoked,
    ActionVerificationStarted,
    ActionVerificationCompleted,
    SafetyVerificationStarted,
    OfflineExited,
    ActionExecuted,
    ActionNeedsIntervention,
    ApprovalRequested,
    RunResumed,
    OutcomeRecorded,
}

enum TraceFault {
    Fail(TraceFailureTarget),
    Block {
        target: TraceFailureTarget,
        entered: Arc<AtomicBool>,
        release: Arc<AtomicBool>,
    },
}

impl TraceFault {
    fn target(&self) -> TraceFailureTarget {
        match self {
            Self::Fail(target) | Self::Block { target, .. } => *target,
        }
    }
}

struct TraceBarrier {
    entered: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
}

impl TraceBarrier {
    async fn wait_until_entered(&self) -> bool {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .is_ok()
    }

    fn release(&self) {
        self.release.store(true, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct ArmableTraceStore {
    inner: InMemoryTraceStore,
    fault_next: Arc<Mutex<Option<TraceFault>>>,
    runtime_read_fault_next: Arc<Mutex<Option<RuntimeReadFault>>>,
    runtime_confirm_rejections: Arc<AtomicUsize>,
    runtime_stable_confirm_rejections: Arc<AtomicUsize>,
    runtime_open_failures: AtomicUsize,
    runtime_tail_failures: Arc<AtomicUsize>,
}

struct RuntimeReadFault {
    entered: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
}

impl ArmableTraceStore {
    fn arm(&self, target: TraceFailureTarget) {
        *self.fault_next.lock().expect("trace failure lock") = Some(TraceFault::Fail(target));
    }

    fn arm_barrier(&self, target: TraceFailureTarget) -> TraceBarrier {
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        *self.fault_next.lock().expect("trace barrier lock") = Some(TraceFault::Block {
            target,
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        TraceBarrier { entered, release }
    }

    fn arm_runtime_read_barrier(&self) -> TraceBarrier {
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        *self
            .runtime_read_fault_next
            .lock()
            .expect("runtime trace read barrier lock") = Some(RuntimeReadFault {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        TraceBarrier { entered, release }
    }

    fn reject_runtime_confirmations(&self, count: usize) {
        self.runtime_confirm_rejections
            .store(count, Ordering::SeqCst);
    }

    fn fail_runtime_reader_opens(&self, count: usize) {
        self.runtime_open_failures.store(count, Ordering::SeqCst);
    }

    fn fail_runtime_reader_tails(&self, count: usize) {
        self.runtime_tail_failures.store(count, Ordering::SeqCst);
    }

    fn reject_stable_runtime_confirmations(&self, count: usize) {
        self.runtime_stable_confirm_rejections
            .store(count, Ordering::SeqCst);
    }
}

impl TraceStore for ArmableTraceStore {
    fn append(&self, run_id: &str, payload: Value) -> Result<u64, TraceStoreError> {
        let event = serde_json::from_value::<TraceEvent>(payload.clone()).ok();
        if let Some(fault) = take_trace_fault(&self.fault_next, event.as_ref())
            .map_err(|_| TraceStoreError::Poisoned)?
        {
            match fault {
                TraceFault::Fail(_) => return Err(TraceStoreError::Poisoned),
                TraceFault::Block {
                    entered, release, ..
                } => {
                    entered.store(true, Ordering::SeqCst);
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !release.load(Ordering::SeqCst) {
                        if Instant::now() >= deadline {
                            return Err(TraceStoreError::Poisoned);
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
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
        if self
            .runtime_open_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                (remaining > 0).then(|| remaining - 1)
            })
            .is_ok()
        {
            return Err(RuntimeTracePortError::Unavailable);
        }
        Ok(Arc::new(ArmableRuntimeTraceReader {
            inner: self.inner.open_runtime_reader(run_id, limits)?,
            runtime_read_fault_next: Arc::clone(&self.runtime_read_fault_next),
            runtime_confirm_rejections: Arc::clone(&self.runtime_confirm_rejections),
            runtime_stable_confirm_rejections: Arc::clone(&self.runtime_stable_confirm_rejections),
            runtime_tail_failures: Arc::clone(&self.runtime_tail_failures),
            synthetic_tail: Mutex::new(None),
        }))
    }

    fn acquire_runtime_writer(
        &self,
        request: RuntimeTraceWriterRequest,
    ) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
        Ok(Arc::new(ArmableRuntimeTraceWriter {
            inner: self.inner.acquire_runtime_writer(request)?,
            fault_next: Arc::clone(&self.fault_next),
        }))
    }
}

struct ArmableRuntimeTraceReader {
    inner: RuntimeTraceReaderHandle,
    runtime_read_fault_next: Arc<Mutex<Option<RuntimeReadFault>>>,
    runtime_confirm_rejections: Arc<AtomicUsize>,
    runtime_stable_confirm_rejections: Arc<AtomicUsize>,
    runtime_tail_failures: Arc<AtomicUsize>,
    synthetic_tail: Mutex<Option<RuntimeTraceTail>>,
}

impl RuntimeTraceReader for ArmableRuntimeTraceReader {
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
        if let Some(tail) = self
            .synthetic_tail
            .lock()
            .map_err(|_| RuntimeTracePortError::BackendContract)?
            .as_ref()
        {
            return Ok(tail.clone());
        }
        if self
            .runtime_tail_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                (remaining > 0).then(|| remaining - 1)
            })
            .is_ok()
        {
            return Err(RuntimeTracePortError::Unavailable);
        }
        self.inner.tail()
    }

    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError> {
        let fault = self
            .runtime_read_fault_next
            .lock()
            .map_err(|_| RuntimeTracePortError::BackendContract)?
            .take();
        if let Some(RuntimeReadFault { entered, release }) = fault {
            entered.store(true, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(5);
            while !release.load(Ordering::SeqCst) {
                if Instant::now() >= deadline {
                    return Err(RuntimeTracePortError::BackendContract);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        self.inner.read_page(start)
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        if self
            .runtime_stable_confirm_rejections
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                (remaining > 0).then(|| remaining - 1)
            })
            .is_ok()
        {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        if self
            .runtime_confirm_rejections
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                (remaining > 0).then(|| remaining - 1)
            })
            .is_ok()
        {
            let synthetic_tail = RuntimeTraceTail::current(
                expected.store_identity().clone(),
                expected.next_sequence(),
                expected.stable_tail_hash().cloned(),
                expected.envelope_tail_hash().cloned(),
                expected
                    .anchor_revision()
                    .checked_add(1)
                    .ok_or(RuntimeTracePortError::LimitExceeded)?,
                RuntimeTraceFence::from_persisted_digest(ContentHash::blake3(
                    b"test-only-advanced-runtime-tail",
                )),
            )?;
            *self
                .synthetic_tail
                .lock()
                .map_err(|_| RuntimeTracePortError::BackendContract)? = Some(synthetic_tail);
            return Err(RuntimeTracePortError::FenceRejected);
        }
        self.inner.confirm_tail(expected)
    }
}

struct HistoricalSensitiveRuntimeReader {
    source: RuntimeTraceReaderHandle,
    source_tail: RuntimeTraceTail,
    records: Vec<TraceRecord>,
    tail: RuntimeTraceTail,
    limits: RuntimeTraceLimits,
    run_id: String,
}

impl RuntimeTraceReader for HistoricalSensitiveRuntimeReader {
    fn store_identity(&self) -> RuntimeTraceStoreIdentity {
        self.tail.store_identity().clone()
    }

    fn run_id(&self) -> &str {
        &self.run_id
    }

    fn limits(&self) -> RuntimeTraceLimits {
        self.limits
    }

    fn tail(&self) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
        Ok(self.tail.clone())
    }

    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError> {
        let start = usize::try_from(start).map_err(|_| RuntimeTracePortError::LimitExceeded)?;
        if start > self.records.len() {
            return Err(RuntimeTracePortError::BackendContract);
        }
        let end = start
            .saturating_add(self.limits.page_records)
            .min(self.records.len());
        Ok(RuntimeTracePage::new(
            self.records[start..end].to_vec(),
            u64::try_from(end).map_err(|_| RuntimeTracePortError::LimitExceeded)?,
            end == self.records.len(),
        ))
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        if expected != &self.tail {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        self.source.confirm_tail(&self.source_tail)
    }
}

fn trace_failure_matches(target: Option<TraceFailureTarget>, event: Option<&TraceEvent>) -> bool {
    if matches!(
        (target, event.map(|event| &event.kind)),
        (
            Some(TraceFailureTarget::SafetyVerificationStarted),
            Some(TraceEventKind::DaemonAudit { endpoint, .. })
        ) if endpoint == "safety.verification.started"
    ) {
        return true;
    }
    if matches!(
        (target, event.map(|event| &event.kind)),
        (
            Some(TraceFailureTarget::OfflineExited),
            Some(TraceEventKind::DaemonAudit { endpoint, .. })
        ) if endpoint == "offline.exited"
    ) {
        return true;
    }
    matches!(
        (target, event.map(|event| &event.kind)),
        (
            Some(TraceFailureTarget::Accepted),
            Some(TraceEventKind::PolicyBundleAccepted { .. })
        ) | (
            Some(TraceFailureTarget::Reconnected),
            Some(TraceEventKind::PolicyConnectivityChanged {
                disconnected: false,
                ..
            })
        ) | (
            Some(TraceFailureTarget::Rejected),
            Some(TraceEventKind::PolicyBundleRejected { .. })
        ) | (
            Some(TraceFailureTarget::SyncFailed),
            Some(TraceEventKind::PolicySyncFailed { .. })
        ) | (
            Some(TraceFailureTarget::Revoked),
            Some(TraceEventKind::PolicyRevoked { .. })
        ) | (
            Some(TraceFailureTarget::ActionVerificationStarted),
            Some(TraceEventKind::ActionVerificationStarted { .. })
        ) | (
            Some(TraceFailureTarget::ActionVerificationCompleted),
            Some(TraceEventKind::ActionVerificationCompleted { .. })
        ) | (
            Some(TraceFailureTarget::ActionExecuted),
            Some(TraceEventKind::ActionExecuted { .. })
        ) | (
            Some(TraceFailureTarget::ActionNeedsIntervention),
            Some(TraceEventKind::ActionNeedsIntervention { .. })
        ) | (
            Some(TraceFailureTarget::ApprovalRequested),
            Some(TraceEventKind::ApprovalRequested { .. })
        ) | (
            Some(TraceFailureTarget::RunResumed),
            Some(TraceEventKind::RunResumed { .. })
        ) | (
            Some(TraceFailureTarget::OutcomeRecorded),
            Some(TraceEventKind::OutcomeRecorded { .. })
        )
    )
}

fn take_trace_fault(
    fault_next: &Arc<Mutex<Option<TraceFault>>>,
    event: Option<&TraceEvent>,
) -> Result<Option<TraceFault>, ()> {
    let mut fault = fault_next.lock().map_err(|_| ())?;
    if fault
        .as_ref()
        .is_some_and(|fault| trace_failure_matches(Some(fault.target()), event))
    {
        Ok(fault.take())
    } else {
        Ok(None)
    }
}

struct ArmableRuntimeTraceWriter {
    inner: RuntimeTraceWriterHandle,
    fault_next: Arc<Mutex<Option<TraceFault>>>,
}

impl RuntimeTraceReader for ArmableRuntimeTraceWriter {
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

impl RuntimeTraceWriter for ArmableRuntimeTraceWriter {
    fn append(
        &self,
        expected: &RuntimeTraceTail,
        payload: Value,
    ) -> Result<RuntimeTraceAppend, RuntimeTracePortError> {
        let event = serde_json::from_value::<TraceEvent>(payload.clone()).ok();
        if let Some(fault) = take_trace_fault(&self.fault_next, event.as_ref())
            .map_err(|_| RuntimeTracePortError::Unavailable)?
        {
            match fault {
                TraceFault::Fail(_) => return Err(RuntimeTracePortError::Unavailable),
                TraceFault::Block {
                    entered, release, ..
                } => {
                    entered.store(true, Ordering::SeqCst);
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !release.load(Ordering::SeqCst) {
                        if Instant::now() >= deadline {
                            return Err(RuntimeTracePortError::Unavailable);
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
        self.inner.append(expected, payload)
    }

    fn close(&self) -> Result<(), RuntimeTracePortError> {
        self.inner.close()
    }
}

// Simulates a historical pre-ingress-guard payload on reads without changing the
// live append sequence owned by the daemon runtime.
#[derive(Default)]
struct HistoricalSensitiveTraceStore {
    inner: InMemoryTraceStore,
    inject_on_read: AtomicBool,
}

impl HistoricalSensitiveTraceStore {
    fn enable_historical_injection(&self) {
        self.inject_on_read.store(true, Ordering::SeqCst);
    }

    fn inject_historical_sensitive_payload(mut records: Vec<TraceRecord>) -> Vec<TraceRecord> {
        for record in &mut records {
            for pointer in [
                "/kind/ActionVerificationStarted/action/params",
                "/kind/ActionVerificationCompleted/action/params",
                "/kind/ActionExecuted/action/params",
                "/kind/ActionDenied/action/params",
                "/kind/ActionFailed/action/params",
                "/kind/ActionNeedsApproval/action/params",
                "/kind/ActionNeedsIntervention/action/params",
            ] {
                if let Some(params) = record.payload.pointer_mut(pointer) {
                    *params = fnd009_sensitive_params();
                    break;
                }
            }
        }
        records
    }
}

impl TraceStore for HistoricalSensitiveTraceStore {
    fn append(&self, run_id: &str, payload: Value) -> Result<u64, TraceStoreError> {
        self.inner.append(run_id, payload)
    }

    fn read(&self, run_id: &str) -> Result<Vec<TraceRecord>, TraceStoreError> {
        let records = self.inner.read(run_id)?;
        Ok(if self.inject_on_read.load(Ordering::SeqCst) {
            Self::inject_historical_sensitive_payload(records)
        } else {
            records
        })
    }

    fn read_range(
        &self,
        run_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<TraceRecord>, TraceStoreError> {
        let records = self.inner.read_range(run_id, start, end)?;
        Ok(if self.inject_on_read.load(Ordering::SeqCst) {
            Self::inject_historical_sensitive_payload(records)
        } else {
            records
        })
    }

    fn runtime_store_identity(&self) -> Result<RuntimeTraceStoreIdentity, RuntimeTracePortError> {
        self.inner.runtime_store_identity()
    }

    fn open_runtime_reader(
        &self,
        run_id: &str,
        limits: RuntimeTraceLimits,
    ) -> Result<RuntimeTraceReaderHandle, RuntimeTracePortError> {
        if self.inject_on_read.load(Ordering::SeqCst) {
            historical_sensitive_runtime_reader(&self.inner, run_id, limits)
        } else {
            self.inner.open_runtime_reader(run_id, limits)
        }
    }

    fn acquire_runtime_writer(
        &self,
        request: RuntimeTraceWriterRequest,
    ) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
        self.inner.acquire_runtime_writer(request)
    }
}

#[derive(Default)]
struct CorruptingRangeTraceStore {
    inner: InMemoryTraceStore,
}

impl TraceStore for CorruptingRangeTraceStore {
    fn append(&self, run_id: &str, payload: Value) -> Result<u64, TraceStoreError> {
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
        let source = self.inner.open_runtime_reader(run_id, limits)?;
        let source_tail = source.tail()?;
        let mut records = Vec::new();
        let mut next = 0u64;
        while next < source_tail.next_sequence() {
            let page = source.read_page(next)?;
            if page.records().is_empty()
                || records.len() + page.records().len() > limits.max_records
            {
                return Err(RuntimeTracePortError::BackendContract);
            }
            next = page.next_sequence();
            records.extend(page.into_records());
        }
        source.confirm_tail(&source_tail)?;
        let first = records
            .first_mut()
            .ok_or(RuntimeTracePortError::BackendContract)?;
        first.payload["sequence"] = json!(u64::MAX);
        Ok(Arc::new(HistoricalSensitiveRuntimeReader {
            source,
            source_tail: source_tail.clone(),
            records,
            tail: source_tail,
            limits,
            run_id: run_id.to_string(),
        }))
    }

    fn acquire_runtime_writer(
        &self,
        request: RuntimeTraceWriterRequest,
    ) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
        self.inner.acquire_runtime_writer(request)
    }
}

fn historical_sensitive_runtime_reader(
    store: &InMemoryTraceStore,
    run_id: &str,
    limits: RuntimeTraceLimits,
) -> Result<RuntimeTraceReaderHandle, RuntimeTracePortError> {
    let source = store.open_runtime_reader(run_id, limits)?;
    let source_tail = source.tail()?;
    let mut records = Vec::new();
    let mut next = 0u64;
    while next < source_tail.next_sequence() {
        let page = source.read_page(next)?;
        if page.records().is_empty() || records.len() + page.records().len() > limits.max_records {
            return Err(RuntimeTracePortError::BackendContract);
        }
        next = page.next_sequence();
        records.extend(page.into_records());
    }
    source.confirm_tail(&source_tail)?;
    let mut records = HistoricalSensitiveTraceStore::inject_historical_sensitive_payload(records);
    let mut stable_tail = None;
    let mut envelope_tail = None;
    for record in &mut records {
        record.prev_event_hash = stable_tail.clone();
        let stable_hash = compute_trace_event_hash(stable_tail.as_ref(), &record.payload)
            .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
        let mut event: TraceEvent = serde_json::from_value(record.payload.clone())
            .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
        if let TraceEventKind::LoopTickCompleted { tick_id, .. } = event.kind {
            event.kind = TraceEventKind::LoopTickCompleted {
                tick_id,
                integrity: Some(splendor_types::TraceIntegrity {
                    prev_event_hash: stable_tail.clone(),
                    event_hash: stable_hash.clone(),
                }),
            };
            record.payload =
                serde_json::to_value(event).map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
        }
        record.event_hash = stable_hash.clone();
        envelope_tail = Some(compute_trace_envelope_hash(envelope_tail.as_ref(), record)?);
        stable_tail = Some(stable_hash);
    }
    let tail = RuntimeTraceTail::legacy(
        source.store_identity(),
        u64::try_from(records.len()).map_err(|_| RuntimeTracePortError::LimitExceeded)?,
        stable_tail,
        envelope_tail,
    )?;
    Ok(Arc::new(HistoricalSensitiveRuntimeReader {
        source,
        source_tail,
        records,
        tail,
        limits,
        run_id: run_id.to_string(),
    }))
}

fn principal() -> ClientPrincipal {
    ClientPrincipal::new("app_test", "client_test")
}

fn attribution() -> AuditAttribution {
    AuditAttribution {
        principal: principal(),
        credential_id: None,
        requested_at: OffsetDateTime::now_utc(),
    }
}

fn signed_work_order(
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: Option<RunId>,
    _scopes: Vec<EndpointScope>,
) -> WorkOrderEnvelope {
    signed_work_order_with_id("wo_test", tenant_id, agent_id, run_id)
}

fn signed_work_order_with_id(
    work_order_id: &str,
    tenant_id: TenantId,
    agent_id: AgentId,
    run_id: Option<RunId>,
) -> WorkOrderEnvelope {
    let now = OffsetDateTime::now_utc();
    let work_order = WorkOrder {
        schema_version: WORK_ORDER_SCHEMA_VERSION.to_string(),
        work_order_id: WorkOrderId::try_new(work_order_id).expect("work order id"),
        tenant_id,
        agent_id,
        run_id,
        objective: "daemon integration run".to_string(),
        allowed_actions: vec!["allowed_action".to_string(), "failing_action".to_string()],
        allowed_adapters: vec!["daemon.local".to_string()],
        allowed_permissions: Vec::new(),
        data_refs: Vec::new(),
        quotas: WorkOrderQuotaPolicy::default(),
        placement: WorkOrderPlacement::default(),
        issued_at: now - time::Duration::minutes(1),
        expires_at: now + time::Duration::hours(1),
        revocation: RevocationStatus::Active,
    };
    WorkOrderEnvelope::signed_with_shared_secret(
        work_order,
        "work-order-local-key",
        b"splendor-local-work-order-secret",
    )
    .expect("signed work order")
}

fn resign_work_order(envelope: &mut WorkOrderEnvelope) {
    envelope.signature.as_mut().expect("signature").signature = envelope
        .work_order
        .signature_for_shared_secret(b"splendor-local-work-order-secret")
        .expect("resigned work order");
}

fn bind_original_work_order_for_resume(
    mut envelope: WorkOrderEnvelope,
    run_id: RunId,
) -> WorkOrderEnvelope {
    envelope.work_order.run_id = Some(run_id);
    resign_work_order(&mut envelope);
    envelope
}

fn action(name: &str) -> Action {
    Action {
        name: name.to_string(),
        params: json!({"ok": true}),
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    }
}

fn physical_action(name: &str) -> Action {
    Action {
        name: name.to_string(),
        params: json!({"zone_ref": "zone_a"}),
        side_effect_class: SideEffectClass::Custom("physical.high_level".to_string()),
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    }
}

fn safe_physical_context() -> SafetyContext {
    SafetyContext {
        allowed_zone_refs: vec!["zone_a".to_string()],
        zone_ref: Some("zone_a".to_string()),
        altitude_m: Some(10.0),
        max_altitude_m: Some(30.0),
        battery_percent: Some(0.80),
        privacy_clear: true,
        human_proximity_clear: true,
        emergency_stop_clear: true,
        offline: false,
        policy_cache_expired: false,
        high_risk: false,
        cloud_helper_direct_authority: false,
        cloud_helper_proposal_id: None,
    }
}

fn device_profile(
    node_id: NodeId,
    tenant_id: TenantId,
    allowed_action: &str,
) -> DeviceRuntimeProfile {
    DeviceRuntimeProfile {
        node_id,
        tenant_id,
        device_kind: "drone_sim".to_string(),
        capabilities: vec!["camera.rgb".to_string(), "motion.waypoint".to_string()],
        allowed_physical_actions: vec![allowed_action.to_string()],
        forbidden_action_classes: FORBIDDEN_PHYSICAL_ACTION_PATTERNS
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        safety_constraints: json!({
            "min_battery_percent": 0.25,
            "max_altitude_m": 30.0,
            "allowed_zones": ["zone_a"]
        }),
        runtime_mode: "resident".to_string(),
        safety_status: json!({
            "battery_percent": 0.80,
            "emergency_stop_clear": true,
            "collision_risk": "low",
            "current_zone": "zone_a",
            "altitude_m": 10.0,
            "privacy_clear": true,
            "human_proximity_clear": true,
            "offline": false,
            "cloud_helper_direct_authority": false
        }),
        policy_cache: DevicePolicyCacheStatus {
            policy_id: "policy_daemon_reconciliation".to_string(),
            loaded: true,
            ttl_seconds: 300,
            expires_at: (OffsetDateTime::now_utc() + time::Duration::minutes(5))
                .format(&time::format_description::well_known::Rfc3339)
                .expect("policy expiry"),
            expired: false,
        },
        trace_buffer: DeviceTraceBufferStatus {
            enabled: true,
            buffered_records: 0,
            integrity: "hash_chain_v1".to_string(),
        },
        registered_at: "pending".to_string(),
    }
}

fn approval_policy(tenant_id: &TenantId, agent_id: &AgentId, action_name: &str) -> ApprovalPolicy {
    let mut policy = ApprovalPolicy::new(
        "daemon_approval_policy",
        tenant_id.clone(),
        "external action requires approval",
    );
    policy.agent_id = Some(agent_id.clone());
    policy.action_name = Some(action_name.to_string());
    policy.adapter = Some("daemon.local".to_string());
    policy.side_effect_class = Some(SideEffectClass::External);
    policy.risk_level = Some("high".to_string());
    policy
}

fn approval_evidence(
    tenant_id: &TenantId,
    agent_id: &AgentId,
    run_id: &RunId,
    action_name: &str,
    decision: ApprovalDecision,
) -> ApprovalEvidence {
    ApprovalEvidence::new(
        ApprovalId::new(),
        tenant_id.clone(),
        agent_id.clone(),
        run_id.clone(),
        decision,
        OffsetDateTime::now_utc() + time::Duration::hours(1),
    )
    .with_action_name(action_name)
    .with_adapter("daemon.local")
}

fn local_approval_receipt_config() -> LocalAuthorityObligationReceiptConfig {
    LocalAuthorityObligationReceiptConfig::trusted_local(
        PrincipalId::parse("00000000-0000-4000-8000-0000000004c0").expect("local receipt issuer"),
        "splendor.daemon.run",
        "approval-receipt-local-key",
        "splendor-local-approval-receipt-secret-v1",
        "local-approval-receipts",
    )
    .expect("local approval receipt config")
}

fn ordinary_unvalidated_obligation_receipt() -> AuthorityObligationReceipt {
    let now = OffsetDateTime::now_utc();
    AuthorityObligationReceipt {
        schema_version: "splendor.authority_obligation_receipt.v1".to_string(),
        receipt_id: AuthorityObligationReceiptId::new(),
        issuer: PrincipalId::new(),
        audience: "splendor.daemon.run:fixture".to_string(),
        obligation_id: AuthorityObligationId::new(),
        kind: AuthorityObligationKind::ApprovalRequired,
        subject: PrincipalId::new(),
        authority_decision_id: AuthorityDecisionId::new(),
        canonical_request_digest: "blake3:canonical-request".to_string(),
        evidence_digest: "blake3:evidence".to_string(),
        evidence_ref: Some("evidence:approval/fixture".to_string()),
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

fn read_only_action(name: &str) -> Action {
    Action {
        name: name.to_string(),
        params: json!({"ok": true}),
        side_effect_class: SideEffectClass::ReadOnly,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    }
}

fn signed_policy_bundle(
    tenant_id: TenantId,
    agent_id: Option<AgentId>,
    revocation: RevocationStatus,
) -> PolicyBundleEnvelope {
    let now = OffsetDateTime::now_utc();
    signed_policy_bundle_with_window(
        "pol_daemon",
        "v1",
        tenant_id,
        agent_id,
        now - time::Duration::minutes(1),
        now + time::Duration::hours(1),
        revocation,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_policy_bundle_with_window(
    policy_bundle_id: &str,
    version: &str,
    tenant_id: TenantId,
    agent_id: Option<AgentId>,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    revocation: RevocationStatus,
) -> PolicyBundleEnvelope {
    let bundle = PolicyBundle {
        schema_version: POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
        policy_bundle_id: PolicyBundleId::try_new(policy_bundle_id).expect("policy bundle id"),
        version: version.to_string(),
        tenant_id,
        agent_id,
        issued_at,
        expires_at,
        revocation,
        degraded_mode: PolicyDegradedMode {
            allow_low_risk_cached: true,
            ..PolicyDegradedMode::default()
        },
    };
    PolicyBundleEnvelope::signed_with_shared_secret(
        bundle,
        "policy-local-key",
        b"splendor-local-policy-secret",
    )
    .expect("signed policy bundle")
}

fn percept(schema: &str) -> Percept {
    Percept {
        schema: schema.to_string(),
        payload: json!({"value": 7}),
        provenance: PerceptProvenance {
            source: "daemon-client-local".to_string(),
            detail: Some("test".to_string()),
        },
        timestamp: OffsetDateTime::now_utc(),
    }
}

fn create_request(
    tenant_id: TenantId,
    agent_id: AgentId,
    policy_actions: Vec<DaemonActionCandidate>,
    registered_actions: Vec<RegisteredAction>,
) -> CreateRunRequest {
    CreateRunRequest {
        request_id: format!("req_{}", TraceId::new()),
        idempotency_key: format!("idem_{}", TraceId::new()),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        work_order: signed_work_order(tenant_id, agent_id, None, vec![EndpointScope::RunsCreate]),
        credential: None,
        audit_attribution: Some(attribution()),
        allowed_actions: vec!["allowed_action".to_string()],
        allowed_adapters: vec!["daemon.local".to_string()],
        allowed_permissions: Vec::new(),
        policy_actions,
        policy_bundle_required: false,
        policy_bundle: None,
        registered_actions,
        approval_policies: Vec::new(),
        circuit_breakers: Vec::new(),
        allowed_percept_schemas: vec!["splendor.percept.test.v1".to_string()],
        allowed_percept_sources: vec!["daemon-client-local".to_string()],
        initial_state: Some(json!({"seed": true})),
        snapshot_interval: Some(1),
    }
}

async fn call_json<T: DeserializeOwned>(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Value,
) -> (StatusCode, T) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("bytes");
    let parsed = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "json response ({status}): {error}; body={}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, parsed)
}

async fn call_status(app: axum::Router, method: Method, uri: &str, body: Value) -> StatusCode {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    app.oneshot(request).await.expect("response").status()
}

async fn call_empty<T: DeserializeOwned>(
    app: axum::Router,
    method: Method,
    uri: &str,
) -> (StatusCode, T) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("bytes");
    let parsed = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "json response ({status}): {error}; body={}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, parsed)
}

async fn submit_allowed_action(
    app: axum::Router,
    run_id: RunId,
    tenant_id: TenantId,
    agent_id: AgentId,
) -> splendor_gateway::ActionOutcome {
    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{run_id}/traces?redaction_policy=none"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let causal_trace_id = traces
        .records
        .first()
        .and_then(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .map(|event| event.trace_event_id)
        .expect("run trace identity");
    let submit = SubmitActionRequest {
        action_id: None,
        run_id,
        tenant_id,
        agent_id,
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: Some(causal_trace_id),
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app,
        Method::POST,
        "/actions",
        serde_json::to_value(submit).expect("submit action request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    outcome
}

#[derive(Clone, Copy, Debug)]
enum ReconciliationEndpoint {
    Direct,
    Physical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoEffectMode {
    None,
    NeedsApproval,
    NeedsIntervention,
}

struct EndpointActionFixture {
    app: axum::Router,
    trace_store: Arc<ArmableTraceStore>,
    adapter_calls: Arc<AtomicUsize>,
    run_id: RunId,
    uri: String,
    request: Value,
    followup_request: Value,
    state_head: Option<String>,
}

async fn endpoint_action_fixture(
    endpoint: ReconciliationEndpoint,
    adapter_output: Value,
) -> EndpointActionFixture {
    endpoint_action_fixture_with_mode(endpoint, adapter_output, NoEffectMode::None).await
}

async fn endpoint_action_fixture_with_mode(
    endpoint: ReconciliationEndpoint,
    adapter_output: Value,
    mode: NoEffectMode,
) -> EndpointActionFixture {
    let trace_store = Arc::new(ArmableTraceStore::default());
    let adapter_calls = Arc::new(AtomicUsize::new(0));
    let (action_name, followup_action_name, adapter_id) = match endpoint {
        ReconciliationEndpoint::Direct => ("allowed_action", "safe_action", "daemon.local"),
        ReconciliationEndpoint::Physical => ("capture_image", "inspect_zone", "device-sim"),
    };
    let mut adapters = ConfiguredActionAdapters::new();
    adapters
        .insert(
            adapter_id,
            Arc::new(FixedOutputAdapter {
                calls: Arc::clone(&adapter_calls),
                output: adapter_output,
            }),
        )
        .expect("configured endpoint adapter");
    let state = DaemonState::with_trace_store_and_action_adapters(
        DaemonConfig::local_dev(),
        trace_store.clone(),
        adapters,
    );
    let app = router(state);
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let mut create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        Vec::new(),
        vec![
            RegisteredAction {
                name: action_name.to_string(),
                adapter: adapter_id.to_string(),
                required_permissions: Some(Vec::new()),
            },
            RegisteredAction {
                name: followup_action_name.to_string(),
                adapter: adapter_id.to_string(),
                required_permissions: Some(Vec::new()),
            },
        ],
    );
    create.allowed_actions = vec![action_name.to_string(), followup_action_name.to_string()];
    create.allowed_adapters = vec![adapter_id.to_string()];
    create.work_order.work_order.allowed_actions = create.allowed_actions.clone();
    create.work_order.work_order.allowed_adapters = create.allowed_adapters.clone();
    match mode {
        NoEffectMode::None => {}
        NoEffectMode::NeedsApproval => {
            let mut policy = approval_policy(&tenant_id, &agent_id, action_name);
            policy.adapter = Some(adapter_id.to_string());
            policy.side_effect_class = Some(match endpoint {
                ReconciliationEndpoint::Direct => SideEffectClass::External,
                ReconciliationEndpoint::Physical => {
                    SideEffectClass::Custom("physical.high_level".to_string())
                }
            });
            create.approval_policies = vec![policy];
        }
        NoEffectMode::NeedsIntervention => {
            let mut policy = approval_policy(&tenant_id, &agent_id, action_name);
            policy.adapter = Some(adapter_id.to_string());
            policy.side_effect_class = Some(match endpoint {
                ReconciliationEndpoint::Direct => SideEffectClass::External,
                ReconciliationEndpoint::Physical => {
                    SideEffectClass::Custom("physical.high_level".to_string())
                }
            });
            policy.expires_at = Some(OffsetDateTime::now_utc() - time::Duration::minutes(1));
            create.approval_policies = vec![policy];
        }
    }
    resign_work_order(&mut create.work_order);
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create endpoint fixture"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");

    let node_id = matches!(endpoint, ReconciliationEndpoint::Physical).then(NodeId::new);
    if let Some(node_id) = node_id.as_ref() {
        let mut profile = device_profile(node_id.clone(), tenant_id.clone(), action_name);
        profile
            .allowed_physical_actions
            .push(followup_action_name.to_string());
        let (status, _registered): (StatusCode, Value) = call_json(
            app.clone(),
            Method::POST,
            "/devices/profiles",
            serde_json::to_value(RegisterDeviceProfileRequest {
                credential: None,
                audit_attribution: Some(attribution()),
                profile,
            })
            .expect("register device profile"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    let (status, tick): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(LifecycleRequest {
            credential: None,
            work_order: None,
            audit_attribution: Some(attribution()),
            reason: Some("prepare reconciliation endpoint fixture".to_string()),
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        })
        .expect("start endpoint fixture"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tick.status, RunStatus::Running);
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);

    let request = SubmitActionRequest {
        action_id: Some(ActionId::new()),
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: Some(TraceId::new()),
        action: match endpoint {
            ReconciliationEndpoint::Direct => action(action_name),
            ReconciliationEndpoint::Physical => physical_action(action_name),
        },
        adapter: Some(adapter_id.to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: Some(OffsetDateTime::now_utc()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let followup_request = SubmitActionRequest {
        action_id: Some(ActionId::new()),
        run_id: created.run_id.clone(),
        tenant_id,
        agent_id,
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: Some(TraceId::new()),
        action: match endpoint {
            ReconciliationEndpoint::Direct => action(followup_action_name),
            ReconciliationEndpoint::Physical => physical_action(followup_action_name),
        },
        adapter: Some(adapter_id.to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: Some(OffsetDateTime::now_utc()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (uri, request, followup_request) = match (endpoint, node_id) {
        (ReconciliationEndpoint::Direct, None) => (
            "/actions".to_string(),
            serde_json::to_value(request).expect("direct request"),
            serde_json::to_value(followup_request).expect("direct followup request"),
        ),
        (ReconciliationEndpoint::Physical, Some(node_id)) => (
            format!("/devices/{node_id}/actions"),
            serde_json::to_value(SubmitPhysicalActionRequest {
                action_request: request,
                safety_context: safe_physical_context(),
                operator_intervention_evidence: None,
            })
            .expect("physical request"),
            serde_json::to_value(SubmitPhysicalActionRequest {
                action_request: followup_request,
                safety_context: safe_physical_context(),
                operator_intervention_evidence: None,
            })
            .expect("physical followup request"),
        ),
        _ => unreachable!("endpoint fixture node identity"),
    };
    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.status, RunStatus::Running);

    EndpointActionFixture {
        app,
        trace_store,
        adapter_calls,
        run_id: created.run_id,
        uri,
        request,
        followup_request,
        state_head: inspected.state_head,
    }
}

async fn call_empty_with_credential<T: DeserializeOwned>(
    app: axum::Router,
    method: Method,
    uri: &str,
    credential: &CallerCredential,
) -> (StatusCode, T) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(
            "x-splendor-caller-credential",
            serde_json::to_string(credential).expect("credential json"),
        )
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("bytes");
    let parsed = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "json response ({status}): {error}; body={}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, parsed)
}

async fn call_empty_with_credential_header<T: DeserializeOwned>(
    app: axum::Router,
    method: Method,
    uri: &str,
    header: HeaderValue,
) -> (StatusCode, T) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-splendor-caller-credential", header)
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("bytes");
    let parsed = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "json response ({status}): {error}; body={}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, parsed)
}

fn caller_credential(scopes: Vec<EndpointScope>) -> CallerCredential {
    caller_credential_for_tenant(TenantId::new(), scopes)
}

fn caller_credential_for_tenant(
    tenant_id: TenantId,
    scopes: Vec<EndpointScope>,
) -> CallerCredential {
    CallerCredential {
        credential_id: "cred_test".to_string(),
        principal: principal(),
        scopes,
        binding: CredentialBinding::Tenant { tenant_id },
        audience: CredentialAudience::Daemon {
            daemon_id: "daemon_local".to_string(),
        },
        expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
        revocation: RevocationStatus::Active,
    }
}

fn matching_attribution(credential: &CallerCredential) -> AuditAttribution {
    AuditAttribution {
        principal: credential.principal.clone(),
        credential_id: Some(credential.credential_id.clone()),
        requested_at: OffsetDateTime::now_utc(),
    }
}

const FND009_CANARIES: &[&str] = &[
    "FND009_SECRET_VALUE_NEVER_RETURN",
    "FND009_TOKEN_VALUE_NEVER_RETURN",
    "FND009_AUTHORIZATION_VALUE_NEVER_RETURN",
    "FND009_CREDENTIAL_VALUE_NEVER_RETURN",
    "FND009_SIGNATURE_VALUE_NEVER_RETURN",
    "FND009_PRIVATE_KEY_VALUE_NEVER_RETURN",
    "FND009_STATE_BYTES_VALUE_NEVER_RETURN",
    "FND009_SNAPSHOT_BYTES_VALUE_NEVER_RETURN",
    "FND009_RESTRICTED_VALUE_NEVER_RETURN",
    "FND009_LEGAL_HOLD_VALUE_NEVER_RETURN",
    "FND009_REASON_VALUE_NEVER_RETURN",
    "FND009_STATUS_VALUE_NEVER_RETURN",
    "FND009_REASONS_VALUE_NEVER_RETURN",
    "FND009_SOURCE_VALUE_NEVER_RETURN",
    "FND009_SCHEMA_VALUE_NEVER_RETURN",
    "FND009_AUTH_ALIAS_VALUE_NEVER_RETURN",
    "FND009_JWT_ALIAS_VALUE_NEVER_RETURN",
    "FND009_COOKIE_ALIAS_VALUE_NEVER_RETURN",
    "FND009_SET_COOKIE_ALIAS_VALUE_NEVER_RETURN",
    "FND009_SESSION_ID_ALIAS_VALUE_NEVER_RETURN",
    "FND009_CLIENT_SECRET_ALIAS_VALUE_NEVER_RETURN",
    "FND009_REFRESH_TOKEN_ALIAS_VALUE_NEVER_RETURN",
    "FND009_SECRET_REF_ALIAS_VALUE_NEVER_RETURN",
    "FND009_REASON_PASSWORD_VALUE_NEVER_RETURN",
    "FND009_STATUS_SECRET_VALUE_NEVER_RETURN",
    "FND009_REASONS_CREDENTIAL_VALUE_NEVER_RETURN",
    "FND009_SOURCE_SIGNATURE_VALUE_NEVER_RETURN",
    "FND009_SCHEMA_TOKEN_VALUE_NEVER_RETURN",
    "FND009_NAME_AUTH_VALUE_NEVER_RETURN",
    "FND009_ADAPTER_AUTHZ_VALUE_NEVER_RETURN",
    "FND009_AUTHKEY_CAMEL_VALUE_NEVER_RETURN",
    "FND009_AUTHKEY_SNAKE_VALUE_NEVER_RETURN",
    "FND009_AUTHKEY_KEBAB_VALUE_NEVER_RETURN",
    "FND009_AUTHZ_KEY_VALUE_NEVER_RETURN",
];

fn fnd009_sensitive_params() -> Value {
    json!({
        "secret": FND009_CANARIES[0],
        "apiToken": FND009_CANARIES[1],
        "authorization": format!("Bearer {}", FND009_CANARIES[2]),
        "credential": FND009_CANARIES[3],
        "signature": FND009_CANARIES[4],
        "privateKey": format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", FND009_CANARIES[5]),
        "state_bytes": FND009_CANARIES[6],
        "snapshotBytes": FND009_CANARIES[7],
        "nested": {
            "restricted": FND009_CANARIES[8],
            "legal_hold": FND009_CANARIES[9],
        },
        "visibility": "protected-eval",
        "safetyLabel": "safety-local",
        "reason": format!("token={} password {}", FND009_CANARIES[10], FND009_CANARIES[23]),
        "status": format!("authorization={} secret {}", FND009_CANARIES[11], FND009_CANARIES[24]),
        "reasons": [format!("credential={}", FND009_CANARIES[12]), format!("credential {}", FND009_CANARIES[25]), "safe_context_reason"],
        "source": format!("secret={} signature {}", FND009_CANARIES[13], FND009_CANARIES[26]),
        "schema": format!("jwt={} token {}", FND009_CANARIES[14], FND009_CANARIES[27]),
        "name": format!("auth {}", FND009_CANARIES[28]),
        "adapter": format!("authz {}", FND009_CANARIES[29]),
        "auth": FND009_CANARIES[15],
        "jwt": FND009_CANARIES[16],
        "cookie": FND009_CANARIES[17],
        "setCookie": FND009_CANARIES[18],
        "sessionId": FND009_CANARIES[19],
        "clientSecret": FND009_CANARIES[20],
        "refreshToken": FND009_CANARIES[21],
        "secretRef": FND009_CANARIES[22],
        "authKey": FND009_CANARIES[30],
        "nested_aliases": {
            "auth_key": FND009_CANARIES[31],
            "auth-key": FND009_CANARIES[32],
            "authz": FND009_CANARIES[33],
        },
        "plain_context": "kept for causal shape",
    })
}

fn fnd009_action(name: &str) -> Action {
    let mut action = action(name);
    action.params = fnd009_sensitive_params();
    action
}

fn assert_canaries_absent<T: serde::Serialize>(label: &str, value: &T) {
    let serialized = serde_json::to_string(value).expect("serialized redacted trace view");
    for canary in FND009_CANARIES {
        assert!(
            !serialized.contains(canary),
            "{label} leaked sensitive canary {canary}: {serialized}"
        );
    }
}

fn assert_trace_records_preserve_identity_and_reasons(
    run_id: &RunId,
    records: &[splendor_store::TraceRecord],
) {
    assert!(!records.is_empty(), "trace view should include records");
    let run_id_string = run_id.to_string();
    for (expected, record) in records.iter().enumerate() {
        assert_eq!(record.run_id, run_id_string);
        assert_eq!(record.sequence, expected as u64);
        assert_eq!(
            record.payload.get("run_id").and_then(Value::as_str),
            Some(run_id_string.as_str())
        );
        assert_eq!(
            record.payload.get("sequence").and_then(Value::as_u64),
            Some(record.sequence)
        );
        assert!(
            record
                .payload
                .get("trace_event_id")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.is_empty()),
            "trace_event_id should remain visible at sequence {}",
            record.sequence
        );
        assert!(
            !record.event_hash.to_string().is_empty(),
            "event_hash should remain visible at sequence {}",
            record.sequence
        );
        if record.sequence == 0 {
            assert!(record.prev_event_hash.is_none());
        } else {
            assert!(
                record.prev_event_hash.is_some(),
                "prev_event_hash should remain visible after the first event"
            );
        }
    }

    assert!(
        records.iter().any(|record| {
            record
                .payload
                .pointer("/kind/ActionDenied/result/reasons")
                .and_then(Value::as_array)
                .is_some_and(|reasons| {
                    reasons
                        .iter()
                        .any(|reason| reason == "trusted_action_profile_missing")
                })
        }),
        "denial reason should remain visible"
    );
    assert!(
        records.iter().any(|record| {
            record
                .payload
                .pointer("/kind/OutcomeRecorded/outcome/action_outcome/status")
                .and_then(Value::as_str)
                == Some("Executed")
        }),
        "action status should remain visible"
    );
    assert!(
        records.iter().any(|record| {
            record
                .payload
                .pointer("/kind/ActionVerificationStarted/action/params/visibility")
                .and_then(Value::as_str)
                == Some("[REDACTED:protected-eval]")
        }),
        "protected-eval existence should remain visible as a redacted marker"
    );
    assert!(
        records.iter().any(|record| {
            record
                .payload
                .pointer("/kind/ActionVerificationStarted/action/params/reason")
                .and_then(Value::as_str)
                == Some("[REDACTED]")
                && record
                    .payload
                    .pointer("/kind/ActionVerificationStarted/action/params/status")
                    .and_then(Value::as_str)
                    == Some("[REDACTED]")
                && record
                    .payload
                    .pointer("/kind/ActionVerificationStarted/action/params/reasons/0")
                    .and_then(Value::as_str)
                    == Some("[REDACTED]")
                && record
                    .payload
                    .pointer("/kind/ActionVerificationStarted/action/params/reasons/1")
                    .and_then(Value::as_str)
                    == Some("[REDACTED]")
                && record
                    .payload
                    .pointer("/kind/ActionVerificationStarted/action/params/reasons/2")
                    .and_then(Value::as_str)
                    == Some("safe_context_reason")
                && record
                    .payload
                    .pointer("/kind/ActionVerificationStarted/action/params/source")
                    .and_then(Value::as_str)
                    == Some("[REDACTED]")
                && record
                    .payload
                    .pointer("/kind/ActionVerificationStarted/action/params/schema")
                    .and_then(Value::as_str)
                    == Some("[REDACTED]")
                && record
                    .payload
                    .pointer("/kind/ActionVerificationStarted/action/params/name")
                    .and_then(Value::as_str)
                    == Some("[REDACTED]")
                && record
                    .payload
                    .pointer("/kind/ActionVerificationStarted/action/params/adapter")
                    .and_then(Value::as_str)
                    == Some("[REDACTED]")
                && record
                    .payload
                    .pointer(
                        "/kind/ActionVerificationStarted/action/params/[REDACTED:sensitive-key]",
                    )
                    .and_then(Value::as_str)
                    == Some("[REDACTED]")
                && record
                    .payload
                    .pointer(
                        "/kind/ActionVerificationStarted/action/params/nested_aliases/[REDACTED:sensitive-key]",
                    )
                    .and_then(Value::as_str)
                    == Some("[REDACTED]")
        }),
        "sensitive allow-listed text and alias keys should redact while safe reason text remains visible"
    );
}

fn assert_trace_export_audit_event_visible(records: &[splendor_store::TraceRecord]) {
    assert!(
        records.iter().any(|record| {
            record
                .payload
                .pointer("/kind/DaemonAudit/endpoint")
                .and_then(Value::as_str)
                == Some("splendor.traces.export.redacted")
        }),
        "trace export audit event should remain visible"
    );
}

fn assert_trace_export_integrity_uses_only_returned_projection(
    label: &str,
    export: &TraceExportResponse,
    trusted_source: &[TraceRecord],
) {
    let projection_tail = export
        .records
        .last()
        .map(|record| record.event_hash.to_string())
        .unwrap_or_else(|| "empty".to_string());
    assert_eq!(
        export.integrity_hash,
        format!("trace-chain:v1:{}:{projection_tail}", export.records.len()),
        "{label} integrity must describe only the returned redacted projection"
    );

    let encoded = serde_json::to_string(export).expect("trace export response serializes");
    for source_hash in trusted_source.iter().flat_map(|record| {
        record
            .prev_event_hash
            .iter()
            .chain(std::iter::once(&record.event_hash))
    }) {
        assert!(
            !encoded.contains(&source_hash.to_string()),
            "{label} leaked trusted source hash {source_hash}"
        );
    }
}

fn public_caller_credential_header(scopes: Vec<&str>) -> HeaderValue {
    HeaderValue::from_str(
        &json!({
            "credential_id": "cred_public_header",
            "principal": {
                "app": {
                    "app_principal_id": "app_public_header",
                    "label": "public header app"
                },
                "client_principal_id": "client_public_header",
                "label": "public header client"
            },
            "scopes": scopes,
            "binding": {
                "tenant": {
                    "tenant_id": TenantId::new().to_string()
                }
            },
            "audience": {
                "daemon": {
                    "daemon_id": "daemon_local"
                }
            },
            "expires_at": (OffsetDateTime::now_utc() + time::Duration::hours(1))
                .format(&time::format_description::well_known::Rfc3339)
                .expect("expires_at"),
            "revocation": "active"
        })
        .to_string(),
    )
    .expect("public credential header")
}

fn public_caller_credential_header_with_revocation(
    scopes: Vec<&str>,
    revocation: Value,
) -> HeaderValue {
    HeaderValue::from_str(
        &json!({
            "credential_id": "cred_public_header",
            "principal": {
                "app": {
                    "app_principal_id": "app_public_header",
                    "label": "public header app"
                },
                "client_principal_id": "client_public_header",
                "label": "public header client"
            },
            "scopes": scopes,
            "binding": {
                "tenant": {
                    "tenant_id": TenantId::new().to_string()
                }
            },
            "audience": {
                "daemon": {
                    "daemon_id": "daemon_local"
                }
            },
            "expires_at": (OffsetDateTime::now_utc() + time::Duration::hours(1))
                .format(&time::format_description::well_known::Rfc3339)
                .expect("expires_at"),
            "revocation": revocation
        })
        .to_string(),
    )
    .expect("public credential header")
}

#[tokio::test]
async fn daemon_run_lifecycle_state_trace_and_replay_are_local_and_ordered() {
    let state = action_test_state();
    let app = router(state);
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let policy_actions = vec![DaemonActionCandidate {
        action_id: None,
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        authority_obligation_receipts: Vec::new(),
    }];

    let create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        policy_actions,
        Vec::new(),
    );
    let original_work_order = create.work_order.clone();
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created.status, RunStatus::Pending);

    let append = AppendPerceptRequest {
        credential: None,
        audit_attribution: Some(attribution()),
        percept: Some(percept("splendor.percept.test.v1")),
    };
    let (status, _accepted): (StatusCode, Value) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/percepts", created.run_id),
        serde_json::to_value(append).expect("append request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lifecycle = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: Some("test".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, tick): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(&lifecycle).expect("start request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tick.status, RunStatus::Running);
    assert!(!tick.state_node_id.is_empty());
    assert_eq!(tick.action_outcomes.len(), 1);

    let (status, paused): (StatusCode, RunInspectResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/pause", created.run_id),
        serde_json::to_value(&lifecycle).expect("pause request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(paused.status, RunStatus::Paused);

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(&lifecycle).expect("paused restart request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "invalid_run_state");

    let mut bad_signature_work_order = signed_work_order(
        tenant_id.clone(),
        agent_id.clone(),
        Some(created.run_id.clone()),
        vec![EndpointScope::RunsResume],
    );
    bad_signature_work_order
        .signature
        .as_mut()
        .expect("signature")
        .signature = "bad-signature".to_string();
    let bad_signature_resume = LifecycleRequest {
        credential: None,
        work_order: Some(bad_signature_work_order),
        audit_attribution: Some(attribution()),
        reason: Some("bad-signature".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(bad_signature_resume).expect("bad signature resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "bad_signature");

    let missing_run_binding_resume = LifecycleRequest {
        credential: None,
        work_order: Some(signed_work_order(
            tenant_id.clone(),
            agent_id.clone(),
            None,
            vec![EndpointScope::RunsResume],
        )),
        audit_attribution: Some(attribution()),
        reason: Some("missing-run-binding".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(missing_run_binding_resume).expect("missing run resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "incompatible_work_order");

    let wrong_agent_resume = LifecycleRequest {
        credential: None,
        work_order: Some(signed_work_order(
            tenant_id.clone(),
            AgentId::new(),
            Some(created.run_id.clone()),
            vec![EndpointScope::RunsResume],
        )),
        audit_attribution: Some(attribution()),
        reason: Some("wrong-agent".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(wrong_agent_resume).expect("wrong resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "incompatible_work_order");

    let mut identity_mismatch =
        bind_original_work_order_for_resume(original_work_order.clone(), created.run_id.clone());
    identity_mismatch.work_order.work_order_id =
        WorkOrderId::try_new("wo_resume_identity_mismatch").expect("work order id");
    resign_work_order(&mut identity_mismatch);
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(LifecycleRequest {
            credential: None,
            work_order: Some(identity_mismatch),
            audit_attribution: Some(attribution()),
            reason: Some("identity-mismatch".to_string()),
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        })
        .expect("identity mismatch resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "resume_work_order_identity_mismatch");

    let mut payload_mismatch =
        bind_original_work_order_for_resume(original_work_order.clone(), created.run_id.clone());
    payload_mismatch.work_order.objective = "broader replacement objective".to_string();
    resign_work_order(&mut payload_mismatch);
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(LifecycleRequest {
            credential: None,
            work_order: Some(payload_mismatch),
            audit_attribution: Some(attribution()),
            reason: Some("payload-mismatch".to_string()),
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        })
        .expect("payload mismatch resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "resume_work_order_payload_mismatch");

    let resume = LifecycleRequest {
        credential: None,
        work_order: Some(bind_original_work_order_for_resume(
            original_work_order.clone(),
            created.run_id.clone(),
        )),
        audit_attribution: Some(attribution()),
        reason: Some("resume".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, resumed): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(resume).expect("resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resumed.status, RunStatus::Running);

    let (status, stopped): (StatusCode, RunInspectResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/stop", created.run_id),
        serde_json::to_value(&lifecycle).expect("stop request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stopped.status, RunStatus::Cancelled);

    let (status, cancelled): (StatusCode, RunInspectResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/cancel", created.run_id),
        serde_json::to_value(&lifecycle).expect("cancel request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cancelled.status, RunStatus::Cancelled);

    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.ticks, 2);
    assert!(inspected.state_head.is_some());

    let (status, head): (StatusCode, StateHeadResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/state-head", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(head.state_node_id, resumed.state_node_id);

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!traces.records.is_empty());
    for (expected, record) in traces.records.iter().enumerate() {
        assert_eq!(record.sequence, expected as u64);
    }
    let saw_appended = traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| matches!(event.kind, TraceEventKind::PerceptsAppended { .. }))
            .unwrap_or(false)
    });
    let audit_endpoints = traces
        .records
        .iter()
        .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .filter_map(|event| match event.kind {
            TraceEventKind::DaemonAudit { endpoint, audit } => {
                assert_eq!(audit.principal, principal());
                Some(endpoint)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    for required in [
        "splendor.runs.create",
        "splendor.percepts.append",
        "splendor.runs.start",
        "splendor.runs.pause",
        "splendor.runs.resume",
        "splendor.runs.stop",
    ] {
        assert!(
            audit_endpoints.iter().any(|endpoint| endpoint == required),
            "missing audit endpoint {required}"
        );
    }
    let saw_received = traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| {
                matches!(
                    event.kind,
                    TraceEventKind::PerceptsReceived { ref percepts }
                        if percepts.iter().any(|percept| percept.schema == "splendor.percept.test.v1")
                )
            })
            .unwrap_or(false)
    });
    assert!(saw_appended, "append endpoint should be trace-linked");
    assert!(saw_received, "queued daemon percept should reach the tick");

    let trace_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::TracesRead]);
    let trace_audit = AuditAttribution {
        credential_id: Some(trace_credential.credential_id.clone()),
        ..attribution()
    };
    let (status, trace_export): (StatusCode, Value) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/traces/export", created.run_id),
        json!({"credential": trace_credential, "audit_attribution": trace_audit, "redaction_policy": "none", "start": null, "end": null}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        trace_export["record_count"].as_u64(),
        Some(traces.records.len() as u64 + 1)
    );
    assert!(trace_export["integrity_hash"]
        .as_str()
        .unwrap_or_default()
        .starts_with("trace-chain:v1:"));

    let replay_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::ReplayCreate]);
    let replay_audit = AuditAttribution {
        credential_id: Some(replay_credential.credential_id.clone()),
        ..attribution()
    };
    let before_replay_executions = inspected.adapter_executions;
    let (status, replay): (StatusCode, ReplayResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({"credential": replay_credential.clone(), "audit_attribution": replay_audit.clone()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay.mode, "inspect_only");

    let (status, explicit_replay): (StatusCode, ReplayResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({"credential": replay_credential, "audit_attribution": replay_audit, "mode": "inspect_only", "side_effects_allowed": false}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(explicit_replay.mode, "inspect_only");

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({"mode": "inspect_only", "side_effects_allowed": true}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "replay_side_effects_forbidden");

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({"mode": "execute", "side_effects_allowed": false}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "unsupported_replay_mode");

    let (status, inspected_after_replay): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        inspected_after_replay.adapter_executions, before_replay_executions,
        "replay must not call adapters again"
    );
}

#[tokio::test]
async fn daemon_direct_adapter_output_is_suppressed_before_raw_store_api_export_and_replay() {
    const CANARY: &str = "C03_DAEMON_OUTPUT_CANARY";

    let trace_store = Arc::new(InMemoryTraceStore::default());
    let adapter_calls = Arc::new(AtomicUsize::new(0));
    let mut adapters = ConfiguredActionAdapters::new();
    adapters
        .insert(
            "daemon.local",
            Arc::new(CredentialOutputAdapter {
                calls: Arc::clone(&adapter_calls),
            }),
        )
        .expect("configured adapter");
    let state = DaemonState::with_trace_store_and_action_adapters(
        DaemonConfig::local_dev(),
        trace_store.clone(),
        adapters,
    );
    let app = router(state);
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let mut create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        vec![DaemonActionCandidate {
            action_id: None,
            action: action("safe_action"),
            adapter: Some("daemon.local".to_string()),
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
            requested_at: None,
            authority_obligation_receipts: Vec::new(),
        }],
        vec![
            RegisteredAction {
                name: "allowed_action".to_string(),
                adapter: "daemon.local".to_string(),
                required_permissions: None,
            },
            RegisteredAction {
                name: "safe_action".to_string(),
                adapter: "daemon.local".to_string(),
                required_permissions: None,
            },
        ],
    );
    create.allowed_actions = vec!["allowed_action".to_string(), "safe_action".to_string()];
    create
        .work_order
        .work_order
        .allowed_actions
        .push("safe_action".to_string());
    resign_work_order(&mut create.work_order);
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lifecycle = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: Some("start-safe-state".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, tick): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(lifecycle).expect("lifecycle request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tick.status, RunStatus::Running);
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 1);
    let state_node_before = tick.state_node_id;

    let outcome = submit_allowed_action(
        app.clone(),
        created.run_id.clone(),
        tenant_id.clone(),
        agent_id,
    )
    .await;
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 2);
    assert_eq!(outcome.status, splendor_gateway::ActionStatus::Failed);
    assert_eq!(
        outcome.error.as_deref(),
        Some(RAW_CREDENTIAL_OUTPUT_SUPPRESSED)
    );
    assert!(outcome.output.is_none());
    let post_verification = outcome
        .post_verification
        .as_ref()
        .expect("fixed suppression facts");
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
    let encoded_outcome = serde_json::to_string(&outcome).expect("outcome serializes");
    assert!(!encoded_outcome.contains(CANARY));

    let raw_records = trace_store
        .read(&created.run_id.to_string())
        .expect("raw trace records");
    let encoded_raw = serde_json::to_string(&raw_records).expect("raw traces serialize");
    assert!(!encoded_raw.contains(CANARY));

    let (status, head): (StatusCode, StateHeadResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/state-head", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(head.state_node_id, state_node_before);

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!serde_json::to_string(&traces)
        .expect("trace response serializes")
        .contains(CANARY));

    let trace_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::TracesRead]);
    let trace_audit = matching_attribution(&trace_credential);
    let (status, exported): (StatusCode, TraceExportResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/traces/export", created.run_id),
        json!({
            "credential": trace_credential,
            "audit_attribution": trace_audit,
            "redaction_policy": "none",
            "start": null,
            "end": null
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!serde_json::to_string(&exported)
        .expect("trace export serializes")
        .contains(CANARY));

    let replay_credential =
        caller_credential_for_tenant(tenant_id, vec![EndpointScope::ReplayCreate]);
    let replay_audit = matching_attribution(&replay_credential);
    let (status, replay): (StatusCode, ReplayResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({"credential": replay_credential, "audit_attribution": replay_audit}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay.mode, "inspect_only");
    assert!(!serde_json::to_string(&replay)
        .expect("replay serializes")
        .contains(CANARY));
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 2);

    let (status, inspected): (StatusCode, RunInspectResponse) =
        call_empty(app, Method::GET, &format!("/runs/{}", created.run_id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.status, RunStatus::Failed);
    assert_eq!(inspected.adapter_executions, 2);
    assert_eq!(
        inspected.state_head.as_deref(),
        Some(state_node_before.as_str())
    );
}

#[tokio::test]
async fn completed_direct_and_physical_action_retries_return_uniform_conflict() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
        let action_id = fixture.request["action_id"]
            .as_str()
            .expect("explicit fixture action ID")
            .to_string();
        let (status, first): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
        assert_eq!(first["status"], "Executed");
        let (status, conflict): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(conflict["code"], "action_id_conflict");
        assert_eq!(conflict["message"], "action identity has already been used");
        assert_eq!(conflict["details"]["disposition"], "conflict");
        assert_eq!(conflict["details"]["retryable"], false);
        assert!(conflict.get("action_id").is_none());
        assert!(conflict.get("output").is_none());
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);

        let (status, followup): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.followup_request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
        assert_eq!(followup["status"], "Executed");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 2);

        let traces: TracePageResponse = call_empty(
            fixture.app,
            Method::GET,
            &format!("/runs/{}/traces?redaction_policy=none", fixture.run_id),
        )
        .await
        .1;
        assert_eq!(
            traces
                .records
                .iter()
                .filter_map(|record| {
                    serde_json::from_value::<TraceEvent>(record.payload.clone()).ok()
                })
                .filter(|event| {
                    event.identity.action_id.as_ref().map(ToString::to_string)
                        == Some(action_id.clone())
                        && matches!(event.kind, TraceEventKind::ActionVerificationStarted { .. })
                })
                .count(),
            1,
            "endpoint={endpoint:?} retry created a second action episode"
        );
    }
}

#[tokio::test]
async fn explicit_static_policy_action_ids_block_direct_and_physical_preemption() {
    const RAW_CANARY: &str = "C03_RESERVED_POLICY_ACTION_RAW_CANARY";
    const CHANGED_RAW_CANARY: &str = "C03_RESERVED_POLICY_ACTION_CHANGED_RAW_CANARY";

    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let trace_store = Arc::new(ArmableTraceStore::default());
        let adapter_calls = Arc::new(AtomicUsize::new(0));
        let (action_name, adapter_id, candidate) = match endpoint {
            ReconciliationEndpoint::Direct => {
                ("allowed_action", "daemon.local", action("allowed_action"))
            }
            ReconciliationEndpoint::Physical => {
                ("allowed_action", "device-sim", action("allowed_action"))
            }
        };
        let mut adapters = ConfiguredActionAdapters::new();
        adapters
            .insert(
                adapter_id,
                Arc::new(FixedOutputAdapter {
                    calls: Arc::clone(&adapter_calls),
                    output: json!({"status": "applied"}),
                }),
            )
            .expect("configured static-policy adapter");
        let state = DaemonState::with_trace_store_and_action_adapters(
            DaemonConfig::local_dev(),
            trace_store.clone(),
            adapters,
        );
        let app = router(state.clone());
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let action_id = ActionId::new();
        let requested_at = OffsetDateTime::now_utc();
        let mut create = create_request(
            tenant_id.clone(),
            agent_id.clone(),
            vec![DaemonActionCandidate {
                action_id: Some(action_id.clone()),
                action: candidate.clone(),
                adapter: Some(adapter_id.to_string()),
                quota_usage: None,
                satisfied_preconditions: Vec::new(),
                requested_at: Some(requested_at),
                authority_obligation_receipts: Vec::new(),
            }],
            vec![RegisteredAction {
                name: action_name.to_string(),
                adapter: adapter_id.to_string(),
                required_permissions: Some(Vec::new()),
            }],
        );
        create.allowed_actions = vec![action_name.to_string()];
        create.allowed_adapters = vec![adapter_id.to_string()];
        create.work_order.work_order.allowed_actions = create.allowed_actions.clone();
        create.work_order.work_order.allowed_adapters = create.allowed_adapters.clone();
        resign_work_order(&mut create.work_order);
        let (status, created): (StatusCode, CreateRunResponse) = call_json(
            app.clone(),
            Method::POST,
            "/runs",
            serde_json::to_value(create).expect("static-policy create request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");

        let submit = SubmitActionRequest {
            action_id: Some(action_id.clone()),
            run_id: created.run_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            credential: None,
            audit_attribution: Some(attribution()),
            causal_trace_id: Some(TraceId::new()),
            action: candidate,
            adapter: Some(adapter_id.to_string()),
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
            requested_at: Some(requested_at),
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        };
        let (uri, request) = match endpoint {
            ReconciliationEndpoint::Direct => (
                "/actions".to_string(),
                serde_json::to_value(submit).expect("direct static-ID request"),
            ),
            ReconciliationEndpoint::Physical => (
                format!("/devices/{}/actions", NodeId::new()),
                serde_json::to_value(SubmitPhysicalActionRequest {
                    action_request: submit,
                    safety_context: safe_physical_context(),
                    operator_intervention_evidence: None,
                })
                .expect("physical static-ID request"),
            ),
        };
        let trace_count_before_conflicts = trace_store
            .read(&created.run_id.to_string())
            .expect("pre-conflict trace")
            .len();
        let authority_evaluations_before_raw = state
            .run_authority_evaluation_count(&created.run_id)
            .expect("pre-raw authority evaluation count");
        let mut raw_request = request.clone();
        let raw_action = &mut raw_request["action"];
        raw_action["params"] = json!({"authorization": format!("Bearer {RAW_CANARY}")});
        let mut changed_raw_request = raw_request.clone();
        let changed_raw_action = &mut changed_raw_request["action"];
        changed_raw_action["params"] = json!({
            "authorization": format!("Bearer {CHANGED_RAW_CANARY}"),
            "changed": true,
        });
        trace_store.fail_runtime_reader_opens(1);
        for attempt in [raw_request.clone(), raw_request, changed_raw_request] {
            let (status, denied): (StatusCode, splendor_gateway::ActionOutcome) =
                call_json(app.clone(), Method::POST, &uri, attempt).await;
            assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
            assert_eq!(denied.action_id, action_id, "endpoint={endpoint:?}");
            assert_eq!(
                denied.status,
                splendor_gateway::ActionStatus::Denied,
                "endpoint={endpoint:?}"
            );
            assert_eq!(
                denied.verification,
                splendor_types::VerificationResult::deny(RAW_CREDENTIAL_INPUT_DENIED),
                "endpoint={endpoint:?}"
            );
            assert_eq!(
                denied.error.as_deref(),
                Some(RAW_CREDENTIAL_INPUT_DENIED),
                "endpoint={endpoint:?}"
            );
            assert!(denied.output.is_none(), "endpoint={endpoint:?}");
            assert!(denied.post_verification.is_none(), "endpoint={endpoint:?}");
            assert!(denied.approval_challenge.is_none(), "endpoint={endpoint:?}");
            let encoded = serde_json::to_string(&denied).expect("fixed raw denial");
            assert!(!encoded.contains(RAW_CANARY), "endpoint={endpoint:?}");
            assert!(
                !encoded.contains(CHANGED_RAW_CANARY),
                "endpoint={endpoint:?}"
            );
            assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                trace_store
                    .read(&created.run_id.to_string())
                    .expect("post-raw trace")
                    .len(),
                trace_count_before_conflicts,
                "endpoint={endpoint:?} reserved raw denial must not append audit/action history"
            );
        }
        assert_eq!(
            trace_store.runtime_open_failures.load(Ordering::SeqCst),
            1,
            "endpoint={endpoint:?} reserved raw denial must not inspect durable history"
        );
        assert_eq!(
            state
                .run_authority_evaluation_count(&created.run_id)
                .expect("post-raw authority evaluation count"),
            authority_evaluations_before_raw,
            "endpoint={endpoint:?} reserved raw denial must not reach run authority"
        );
        let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
            app.clone(),
            Method::GET,
            &format!("/runs/{}", created.run_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
        assert_eq!(inspected.ticks, 0, "endpoint={endpoint:?}");
        assert_eq!(inspected.adapter_executions, 0, "endpoint={endpoint:?}");
        trace_store.fail_runtime_reader_opens(0);

        for changed in [false, true] {
            let mut attempt = request.clone();
            if changed {
                attempt["action"]["params"] = json!({"changed": true});
            }
            let (status, conflict): (StatusCode, Value) =
                call_json(app.clone(), Method::POST, &uri, attempt).await;
            assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
            assert_eq!(conflict["code"], "action_id_conflict");
            assert_eq!(conflict["details"]["retryable"], false);
            assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                trace_store
                    .read(&created.run_id.to_string())
                    .expect("post-conflict trace")
                    .len(),
                trace_count_before_conflicts,
                "endpoint={endpoint:?} static-ID preflight must precede audit and history"
            );
        }

        for tick_id in 1..=2 {
            let (status, tick): (StatusCode, TickResponse) = call_json(
                app.clone(),
                Method::POST,
                &format!("/runs/{}/start", created.run_id),
                serde_json::to_value(LifecycleRequest {
                    credential: None,
                    work_order: None,
                    audit_attribution: Some(attribution()),
                    reason: Some("execute reserved static policy action".to_string()),
                    approval_evidence: None,
                    authority_obligation_receipts: Vec::new(),
                })
                .expect("static-policy start request"),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
            assert_eq!(tick.tick_id, tick_id);
            assert_eq!(tick.action_outcomes.len(), 1);
            assert_eq!(tick.action_outcomes[0].action_id, action_id);
            assert_eq!(
                tick.action_outcomes[0].status,
                splendor_gateway::ActionStatus::Executed,
                "endpoint={endpoint:?} outcome={:?}",
                tick.action_outcomes[0]
            );
            assert_eq!(adapter_calls.load(Ordering::SeqCst), tick_id as usize);
        }

        let (status, conflict): (StatusCode, Value) =
            call_json(app, Method::POST, &uri, request).await;
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(conflict["code"], "action_id_conflict");
        assert_eq!(adapter_calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn duplicate_explicit_static_policy_ids_fail_at_tick_admission_not_run_creation() {
    let adapter_calls = Arc::new(AtomicUsize::new(0));
    let mut adapters = ConfiguredActionAdapters::new();
    adapters
        .insert(
            "daemon.local",
            Arc::new(FixedOutputAdapter {
                calls: Arc::clone(&adapter_calls),
                output: json!({"status": "applied"}),
            }),
        )
        .expect("configured duplicate-ID adapter");
    let app = router(DaemonState::with_action_adapters(
        DaemonConfig::local_dev(),
        adapters,
    ));
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let action_id = ActionId::new();
    let candidate = DaemonActionCandidate {
        action_id: Some(action_id),
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        authority_obligation_receipts: Vec::new(),
    };
    let create = create_request(
        tenant_id,
        agent_id,
        vec![candidate.clone(), candidate],
        Vec::new(),
    );
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("duplicate-ID create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app,
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(LifecycleRequest {
            credential: None,
            work_order: None,
            audit_attribution: Some(attribution()),
            reason: Some("duplicate explicit action IDs".to_string()),
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        })
        .expect("duplicate-ID start request"),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error.code, "scheduler_error");
    assert!(error.message.contains("duplicate_action_id"), "{error:?}");
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn completed_action_credential_bearing_retry_is_denied_before_durable_disposition() {
    const CANARY: &str = "C03_COMPLETED_ACTION_CREDENTIAL_RETRY_CANARY";

    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
        let action_id = fixture.request["action_id"]
            .as_str()
            .expect("explicit action ID")
            .to_string();
        let (status, first): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
        assert_eq!(first["status"], "Executed");

        let mut credential_retry = fixture.request.clone();
        credential_retry["action"]["params"] = json!({"authorization": format!("Bearer {CANARY}")});
        let (status, denied): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            credential_retry,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
        assert_eq!(denied.status, splendor_gateway::ActionStatus::Denied);
        assert_eq!(
            denied.verification.reasons,
            vec![splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED]
        );
        assert!(denied.output.is_none());
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);

        let records = fixture
            .trace_store
            .read(&fixture.run_id.to_string())
            .expect("raw trace records");
        assert!(!serde_json::to_string(&records)
            .expect("trace records serialize")
            .contains(CANARY));
        assert_eq!(
            records
                .iter()
                .filter_map(|record| {
                    serde_json::from_value::<TraceEvent>(record.payload.clone()).ok()
                })
                .filter(|event| {
                    event.identity.action_id.as_ref().map(ToString::to_string)
                        == Some(action_id.clone())
                        && matches!(event.kind, TraceEventKind::ActionVerificationStarted { .. })
                })
                .count(),
            1,
            "endpoint={endpoint:?} credential-bearing retry appended another action episode"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_id_in_flight_direct_and_physical_retries_are_retryable_without_reexecution() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
        let barrier = fixture
            .trace_store
            .arm_barrier(TraceFailureTarget::ActionVerificationCompleted);
        let first_app = fixture.app.clone();
        let first_uri = fixture.uri.clone();
        let first_request = fixture.request.clone();
        let first_thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("first action runtime")
                .block_on(async move {
                    call_json::<Value>(first_app, Method::POST, &first_uri, first_request).await
                })
        });
        if !barrier.wait_until_entered().await {
            barrier.release();
            let first = first_thread.join().expect("timed-out first action");
            panic!("endpoint={endpoint:?} did not reach pre-effect barrier; first={first:?}");
        }

        let (status, in_progress): (StatusCode, Value) = tokio::time::timeout(
            Duration::from_secs(1),
            call_json(
                fixture.app.clone(),
                Method::POST,
                &fixture.uri,
                fixture.request.clone(),
            ),
        )
        .await
        .expect("same-ID retry must not wait for the first action");
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(in_progress["code"], "action_in_progress");
        assert_eq!(in_progress["details"]["disposition"], "in_progress");
        assert_eq!(in_progress["details"]["retryable"], true);
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);

        barrier.release();
        let (status, first) = first_thread.join().expect("first action request");
        assert_eq!(
            status,
            StatusCode::OK,
            "endpoint={endpoint:?} first={first}"
        );
        assert_eq!(first["status"], "Executed");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);

        let (status, followup): (StatusCode, Value) = call_json(
            fixture.app,
            Method::POST,
            &fixture.uri,
            fixture.followup_request,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "endpoint={endpoint:?} followup={followup}"
        );
        assert_eq!(followup["status"], "Executed");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_action_history_scan_does_not_hold_the_run_mutex() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
        let (status, first): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "endpoint={endpoint:?} first={first}"
        );
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);

        let read_barrier = fixture.trace_store.arm_runtime_read_barrier();
        let duplicate_app = fixture.app.clone();
        let duplicate_uri = fixture.uri.clone();
        let duplicate_request = fixture.request.clone();
        let duplicate_thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("duplicate action runtime")
                .block_on(async move {
                    call_json::<Value>(
                        duplicate_app,
                        Method::POST,
                        &duplicate_uri,
                        duplicate_request,
                    )
                    .await
                })
        });
        if !read_barrier.wait_until_entered().await {
            read_barrier.release();
            let duplicate = duplicate_thread.join().expect("timed-out duplicate action");
            panic!(
                "endpoint={endpoint:?} did not reach history read barrier; duplicate={duplicate:?}"
            );
        }

        let (status, inspected): (StatusCode, RunInspectResponse) = tokio::time::timeout(
            Duration::from_secs(1),
            call_empty(
                fixture.app.clone(),
                Method::GET,
                &format!("/runs/{}", fixture.run_id),
            ),
        )
        .await
        .expect("run inspection must not wait for durable history scanning");
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
        assert_eq!(inspected.status, RunStatus::Running);

        let (status, pause): (StatusCode, Value) = tokio::time::timeout(
            Duration::from_secs(1),
            call_json(
                fixture.app.clone(),
                Method::POST,
                &format!("/runs/{}/pause", fixture.run_id),
                serde_json::to_value(LifecycleRequest {
                    credential: None,
                    work_order: None,
                    audit_attribution: Some(attribution()),
                    reason: Some("history scan lock probe".to_string()),
                    approval_evidence: None,
                    authority_obligation_receipts: Vec::new(),
                })
                .expect("pause request"),
            ),
        )
        .await
        .expect("lifecycle admission must not wait for durable history scanning");
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(pause["code"], "action_in_progress");
        assert_eq!(pause["details"]["retryable"], true);

        read_barrier.release();
        let (status, conflict) = duplicate_thread.join().expect("duplicate action request");
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(conflict["code"], "action_id_conflict");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn percept_append_during_action_history_scan_retries_without_poisoning_the_run() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
        let read_barrier = fixture.trace_store.arm_runtime_read_barrier();
        let action_app = fixture.app.clone();
        let action_uri = fixture.uri.clone();
        let action_request = fixture.request.clone();
        let action_thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tail-race action runtime")
                .block_on(async move {
                    call_json::<Value>(action_app, Method::POST, &action_uri, action_request).await
                })
        });
        if !read_barrier.wait_until_entered().await {
            read_barrier.release();
            let action = action_thread.join().expect("timed-out tail-race action");
            panic!("endpoint={endpoint:?} did not reach history barrier; action={action:?}");
        }

        let (percept_status, accepted): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &format!("/runs/{}/percepts", fixture.run_id),
            serde_json::to_value(AppendPerceptRequest {
                credential: None,
                audit_attribution: Some(attribution()),
                percept: Some(percept("splendor.percept.test.v1")),
            })
            .expect("tail-race percept"),
        )
        .await;
        assert_eq!(percept_status, StatusCode::OK, "endpoint={endpoint:?}");
        assert_eq!(accepted["accepted"], 1, "endpoint={endpoint:?}");
        read_barrier.release();

        let (status, outcome) = action_thread.join().expect("tail-race action request");
        assert_eq!(
            status,
            StatusCode::OK,
            "endpoint={endpoint:?} outcome={outcome}"
        );
        assert_eq!(outcome["status"], "Executed", "endpoint={endpoint:?}");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);

        let (status, followup): (StatusCode, Value) = call_json(
            fixture.app,
            Method::POST,
            &fixture.uri,
            fixture.followup_request,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "endpoint={endpoint:?} followup={followup}"
        );
        assert_eq!(followup["status"], "Executed", "endpoint={endpoint:?}");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn transient_history_exhaustion_and_store_unavailability_release_action_admission() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
        fixture.trace_store.reject_runtime_confirmations(100);
        let (status, changed): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(changed["code"], "action_history_changed");
        assert_eq!(changed["details"]["disposition"], "history_changed");
        assert_eq!(changed["details"]["retryable"], true);
        assert_eq!(
            fixture
                .trace_store
                .runtime_confirm_rejections
                .load(Ordering::SeqCst),
            97,
            "endpoint={endpoint:?} must use exactly three bounded attempts",
        );
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);

        fixture.trace_store.reject_runtime_confirmations(0);
        fixture.trace_store.fail_runtime_reader_opens(1);
        let (status, unavailable): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "endpoint={endpoint:?}"
        );
        assert_eq!(unavailable["code"], "action_history_unavailable");
        assert_eq!(unavailable["details"]["disposition"], "unavailable");
        assert_eq!(unavailable["details"]["retryable"], true);
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);

        fixture.trace_store.fail_runtime_reader_tails(1);
        let (status, unavailable): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "endpoint={endpoint:?}"
        );
        assert_eq!(unavailable["code"], "action_history_unavailable");
        assert_eq!(unavailable["details"]["retryable"], true);
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);

        let (status, outcome): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "endpoint={endpoint:?} outcome={outcome}"
        );
        assert_eq!(outcome["status"], "Executed", "endpoint={endpoint:?}");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);

        let (status, followup): (StatusCode, Value) = call_json(
            fixture.app,
            Method::POST,
            &fixture.uri,
            fixture.followup_request,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "endpoint={endpoint:?} followup={followup}"
        );
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn stable_history_confirmation_failure_remains_permanent_reconciliation() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
        fixture.trace_store.reject_stable_runtime_confirmations(1);
        let (status, reconciliation): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(reconciliation["code"], "tick_reconciliation_required");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);

        let (status, closed): (StatusCode, Value) = call_json(
            fixture.app,
            Method::POST,
            &fixture.uri,
            fixture.followup_request,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(closed["code"], "tick_reconciliation_required");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn suppressed_raw_credential_tail_exhaustion_does_not_consume_or_close_the_action_id() {
    const CANARY: &str = "C03_HISTORY_TAIL_RAW_CREDENTIAL_CANARY";
    let fixture =
        endpoint_action_fixture(ReconciliationEndpoint::Direct, json!({"status": "applied"})).await;
    fixture.trace_store.reject_runtime_confirmations(100);
    let mut denied_request = fixture.request.clone();
    denied_request["action"]["params"] = json!({"authorization": format!("Bearer {CANARY}")});
    let (status, denied): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        fixture.app.clone(),
        Method::POST,
        &fixture.uri,
        denied_request,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(denied.status, splendor_gateway::ActionStatus::Denied);
    assert_eq!(
        denied.verification.reasons,
        vec![splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED]
    );
    assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);

    fixture.trace_store.reject_runtime_confirmations(0);
    let (status, outcome): (StatusCode, Value) =
        call_json(fixture.app, Method::POST, &fixture.uri, fixture.request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(outcome["status"], "Executed");
    assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn non_action_admissible_raw_denials_skip_history_and_trace_growth() {
    const CANARY: &str = "C03_CLOSED_RUN_RAW_CREDENTIAL_CANARY";

    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        for lifecycle in ["paused", "cancelled"] {
            let fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
            let lifecycle_request = LifecycleRequest {
                credential: None,
                work_order: None,
                audit_attribution: Some(attribution()),
                reason: Some(format!("prepare {lifecycle} raw denial")),
                approval_evidence: None,
                authority_obligation_receipts: Vec::new(),
            };
            let lifecycle_uri = if lifecycle == "paused" {
                format!("/runs/{}/pause", fixture.run_id)
            } else {
                format!("/runs/{}/stop", fixture.run_id)
            };
            let (status, inspected): (StatusCode, RunInspectResponse) = call_json(
                fixture.app.clone(),
                Method::POST,
                &lifecycle_uri,
                serde_json::to_value(lifecycle_request).expect("lifecycle request"),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
            assert_eq!(
                inspected.status,
                if lifecycle == "paused" {
                    RunStatus::Paused
                } else {
                    RunStatus::Cancelled
                },
                "endpoint={endpoint:?}"
            );

            let trace_count = fixture
                .trace_store
                .read(&fixture.run_id.to_string())
                .expect("closed-run trace baseline")
                .len();
            fixture.trace_store.fail_runtime_reader_opens(1);
            let mut raw_request = fixture.request.clone();
            raw_request["action"]["params"] = json!({"authorization": format!("Bearer {CANARY}")});
            for _ in 0..2 {
                let (status, denied): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
                    fixture.app.clone(),
                    Method::POST,
                    &fixture.uri,
                    raw_request.clone(),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
                assert_eq!(denied.status, splendor_gateway::ActionStatus::Denied);
                assert_eq!(
                    denied.verification.reasons,
                    vec![splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED]
                );
                assert!(!serde_json::to_string(&denied)
                    .expect("fixed denial")
                    .contains(CANARY));
            }
            assert_eq!(
                fixture
                    .trace_store
                    .runtime_open_failures
                    .load(Ordering::SeqCst),
                1,
                "endpoint={endpoint:?} lifecycle={lifecycle} must not open action history"
            );
            assert_eq!(
                fixture
                    .trace_store
                    .read(&fixture.run_id.to_string())
                    .expect("closed-run trace after raw denials")
                    .len(),
                trace_count,
                "endpoint={endpoint:?} lifecycle={lifecycle} must not amplify trace"
            );
            assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn reused_action_id_conflicts_on_changed_action_or_endpoint_source() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
        let (status, _first): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let mut changed = fixture.request.clone();
        changed["action"]["params"] = json!({"changed": true});
        let (status, conflict): (StatusCode, Value) =
            call_json(fixture.app, Method::POST, &fixture.uri, changed).await;
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(conflict["code"], "action_id_conflict");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);
    }

    let physical = endpoint_action_fixture(
        ReconciliationEndpoint::Physical,
        json!({"status": "applied"}),
    )
    .await;
    let (status, _first): (StatusCode, Value) = call_json(
        physical.app.clone(),
        Method::POST,
        &physical.uri,
        physical.request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cross_node_uri = format!("/devices/{}/actions", NodeId::new());
    let (status, cross_node_conflict): (StatusCode, Value) = call_json(
        physical.app.clone(),
        Method::POST,
        &cross_node_uri,
        physical.request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(cross_node_conflict["code"], "action_id_conflict");
    assert_eq!(cross_node_conflict["details"]["retryable"], false);
    assert!(cross_node_conflict.get("action_id").is_none());
    assert!(cross_node_conflict.get("output").is_none());
    let physical_request: SubmitPhysicalActionRequest =
        serde_json::from_value(physical.request).expect("physical fixture request");
    let (status, conflict): (StatusCode, Value) = call_json(
        physical.app,
        Method::POST,
        "/actions",
        serde_json::to_value(physical_request.action_request).expect("direct source retry"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict["code"], "action_id_conflict");
    assert_eq!(conflict, cross_node_conflict);
    assert_eq!(physical.adapter_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn omitted_action_id_remains_a_fresh_attempt() {
    let fixture =
        endpoint_action_fixture(ReconciliationEndpoint::Direct, json!({"status": "applied"})).await;
    let mut request = fixture.request.clone();
    request
        .as_object_mut()
        .expect("direct action request")
        .remove("action_id");
    let (status, first): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        fixture.app.clone(),
        Method::POST,
        &fixture.uri,
        request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, second): (StatusCode, splendor_gateway::ActionOutcome) =
        call_json(fixture.app, Method::POST, &fixture.uri, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(first.action_id, second.action_id);
    assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn post_effect_trace_failures_close_direct_and_physical_effect_admission() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        for target in [
            TraceFailureTarget::ActionExecuted,
            TraceFailureTarget::OutcomeRecorded,
        ] {
            let fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
            fixture.trace_store.arm(target);

            let (status, first): (StatusCode, Value) = call_json(
                fixture.app.clone(),
                Method::POST,
                &fixture.uri,
                fixture.request.clone(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "endpoint={endpoint:?} target={target:?} body={first}"
            );
            assert_eq!(first["code"], "trace_error");
            assert_eq!(
                fixture.adapter_calls.load(Ordering::SeqCst),
                1,
                "endpoint={endpoint:?} target={target:?} first attempt"
            );

            let (status, retry): (StatusCode, Value) = call_json(
                fixture.app.clone(),
                Method::POST,
                &fixture.uri,
                fixture.request.clone(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "endpoint={endpoint:?} target={target:?} retry={retry}"
            );
            assert_eq!(retry["code"], "tick_reconciliation_required");
            assert_eq!(
                fixture.adapter_calls.load(Ordering::SeqCst),
                1,
                "endpoint={endpoint:?} target={target:?} retry must add zero adapter calls"
            );

            let (status, tick_retry): (StatusCode, Value) = call_json(
                fixture.app.clone(),
                Method::POST,
                &format!("/runs/{}/start", fixture.run_id),
                serde_json::to_value(LifecycleRequest {
                    credential: None,
                    work_order: None,
                    audit_attribution: Some(attribution()),
                    reason: Some("post-effect reconciliation probe".to_string()),
                    approval_evidence: None,
                    authority_obligation_receipts: Vec::new(),
                })
                .expect("tick retry request"),
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(tick_retry["code"], "tick_reconciliation_required");
            assert_eq!(
                fixture.adapter_calls.load(Ordering::SeqCst),
                1,
                "endpoint={endpoint:?} target={target:?} lifecycle retry must add zero adapter calls"
            );

            let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
                fixture.app,
                Method::GET,
                &format!("/runs/{}", fixture.run_id),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(inspected.status, RunStatus::Running);
            assert_eq!(inspected.adapter_executions, 1);
            assert_eq!(inspected.state_head, fixture.state_head);
        }
    }
}

#[tokio::test]
async fn physical_offline_suffix_failure_requires_reconciliation() {
    let mut fixture = endpoint_action_fixture(
        ReconciliationEndpoint::Physical,
        json!({"status": "applied"}),
    )
    .await;
    fixture.request["safety_context"]["offline"] = json!(true);
    fixture.trace_store.arm(TraceFailureTarget::OfflineExited);

    let (status, first): (StatusCode, Value) = call_json(
        fixture.app.clone(),
        Method::POST,
        &fixture.uri,
        fixture.request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "first={first}");
    assert_eq!(first["code"], "trace_error");
    assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);

    let (status, retry): (StatusCode, Value) =
        call_json(fixture.app, Method::POST, &fixture.uri, fixture.request).await;
    assert_eq!(status, StatusCode::CONFLICT, "retry={retry}");
    assert_eq!(retry["code"], "tick_reconciliation_required");
    assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn approval_resume_suffix_failure_requires_reconciliation() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture = endpoint_action_fixture_with_mode(
            endpoint,
            json!({"status": "applied"}),
            NoEffectMode::NeedsApproval,
        )
        .await;
        let (status, pending): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
        let challenge = pending
            .approval_challenge
            .expect("approval challenge for suffix failure");
        let receipt = local_approval_receipt_config()
            .issue_approval_receipt(&challenge, TraceEventId::new(), OffsetDateTime::now_utc())
            .expect("approval receipt for suffix failure");
        let mut approved_retry = fixture.request.clone();
        approved_retry["authority_obligation_receipts"] = json!([receipt]);
        fixture.trace_store.arm(TraceFailureTarget::RunResumed);

        let (status, first): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            approved_retry.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "endpoint={endpoint:?} first={first}"
        );
        assert_eq!(first["code"], "trace_error");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);

        let (status, retry): (StatusCode, Value) =
            call_json(fixture.app, Method::POST, &fixture.uri, approved_retry).await;
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(retry["code"], "tick_reconciliation_required");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn credential_output_suppression_closes_direct_and_physical_effect_admission() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture = endpoint_action_fixture(
            endpoint,
            json!({"body": "password=C03_DAEMON_RECONCILIATION_CANARY"}),
        )
        .await;

        let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
        assert_eq!(outcome.status, splendor_gateway::ActionStatus::Failed);
        assert_eq!(
            outcome.error.as_deref(),
            Some(RAW_CREDENTIAL_OUTPUT_SUPPRESSED)
        );
        assert!(outcome.output.is_none());
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);

        let (status, retry): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "endpoint={endpoint:?} retry={retry}"
        );
        assert_eq!(retry["code"], "tick_reconciliation_required");
        assert_eq!(
            fixture.adapter_calls.load(Ordering::SeqCst),
            1,
            "endpoint={endpoint:?} suppression retry must add zero adapter calls"
        );

        let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
            fixture.app,
            Method::GET,
            &format!("/runs/{}", fixture.run_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(inspected.status, RunStatus::Failed);
        assert_eq!(inspected.adapter_executions, 1);
        assert_eq!(inspected.state_head, fixture.state_head);
    }
}

#[tokio::test]
async fn ambiguous_start_failure_quarantines_while_durable_denial_reopens_admission() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fault_fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
        fault_fixture
            .trace_store
            .arm(TraceFailureTarget::ActionVerificationStarted);
        let (status, first): (StatusCode, Value) = call_json(
            fault_fixture.app.clone(),
            Method::POST,
            &fault_fixture.uri,
            fault_fixture.request.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "endpoint={endpoint:?} body={first}"
        );
        assert_eq!(first["code"], "trace_error");
        assert_eq!(fault_fixture.adapter_calls.load(Ordering::SeqCst), 0);

        let (status, retry): (StatusCode, Value) = call_json(
            fault_fixture.app.clone(),
            Method::POST,
            &fault_fixture.uri,
            fault_fixture.request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(retry["code"], "tick_reconciliation_required");
        assert_eq!(fault_fixture.adapter_calls.load(Ordering::SeqCst), 0);
        let inspected: RunInspectResponse = call_empty(
            fault_fixture.app,
            Method::GET,
            &format!("/runs/{}", fault_fixture.run_id),
        )
        .await
        .1;
        assert_eq!(inspected.status, RunStatus::Running);
        assert_eq!(inspected.state_head, fault_fixture.state_head);

        let denial_fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
        let mut denied_request = denial_fixture.request.clone();
        denied_request["action"]["preconditions"] = json!(["ready"]);
        let (status, denied): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
            denial_fixture.app.clone(),
            Method::POST,
            &denial_fixture.uri,
            denied_request,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
        assert_eq!(denied.status, splendor_gateway::ActionStatus::Denied);
        assert_eq!(denial_fixture.adapter_calls.load(Ordering::SeqCst), 0);

        let (status, executed): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
            denial_fixture.app.clone(),
            Method::POST,
            &denial_fixture.uri,
            denial_fixture.followup_request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
        assert_eq!(executed.status, splendor_gateway::ActionStatus::Executed);
        assert_eq!(denial_fixture.adapter_calls.load(Ordering::SeqCst), 1);
        let inspected: RunInspectResponse = call_empty(
            denial_fixture.app,
            Method::GET,
            &format!("/runs/{}", denial_fixture.run_id),
        )
        .await
        .1;
        assert_eq!(inspected.status, RunStatus::Running);
        assert_eq!(inspected.state_head, denial_fixture.state_head);
    }
}

#[tokio::test]
async fn post_start_failure_closes_admission_and_gateway_no_effect_outcome_completes_suffix() {
    let physical = endpoint_action_fixture(
        ReconciliationEndpoint::Physical,
        json!({"status": "must-not-execute"}),
    )
    .await;
    physical
        .trace_store
        .arm(TraceFailureTarget::SafetyVerificationStarted);
    let (status, failed): (StatusCode, Value) = call_json(
        physical.app.clone(),
        Method::POST,
        &physical.uri,
        physical.request.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{failed}");
    assert_eq!(failed["code"], "trace_error");
    let (status, retry): (StatusCode, Value) =
        call_json(physical.app, Method::POST, &physical.uri, physical.request).await;
    assert_eq!(status, StatusCode::CONFLICT, "{retry}");
    assert_eq!(retry["code"], "tick_reconciliation_required");
    assert_eq!(physical.adapter_calls.load(Ordering::SeqCst), 0);

    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture =
            endpoint_action_fixture(endpoint, json!({"status": "must-not-execute"})).await;
        fixture
            .trace_store
            .arm(TraceFailureTarget::ActionVerificationCompleted);
        let (status, completed): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "endpoint={endpoint:?} body={completed}"
        );
        assert_eq!(completed["status"], "NeedsIntervention");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);

        let (status, retry): (StatusCode, Value) = call_json(
            fixture.app.clone(),
            Method::POST,
            &fixture.uri,
            fixture.request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(retry["code"], "action_id_conflict");
        let (status, followup): (StatusCode, Value) = call_json(
            fixture.app,
            Method::POST,
            &fixture.uri,
            fixture.followup_request,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(followup["code"], "run_not_effect_capable");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn no_effect_suffix_failures_close_direct_physical_and_lifecycle_admission() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        for mode in [NoEffectMode::NeedsApproval, NoEffectMode::NeedsIntervention] {
            let fixture = endpoint_action_fixture_with_mode(
                endpoint,
                json!({"status": "must-not-execute"}),
                mode,
            )
            .await;
            let target = match mode {
                NoEffectMode::NeedsApproval => TraceFailureTarget::ApprovalRequested,
                NoEffectMode::NeedsIntervention => TraceFailureTarget::ActionNeedsIntervention,
                NoEffectMode::None => unreachable!("closed no-effect mode matrix"),
            };
            fixture.trace_store.arm(target);

            let (status, first): (StatusCode, Value) = call_json(
                fixture.app.clone(),
                Method::POST,
                &fixture.uri,
                fixture.request.clone(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "endpoint={endpoint:?} mode={mode:?} body={first}"
            );
            assert_eq!(first["code"], "trace_error");
            assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);

            let (status, followup): (StatusCode, Value) = call_json(
                fixture.app.clone(),
                Method::POST,
                &fixture.uri,
                fixture.followup_request.clone(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "endpoint={endpoint:?} mode={mode:?} followup={followup}"
            );
            let expected_followup_code = match mode {
                NoEffectMode::NeedsApproval => "tick_reconciliation_required",
                NoEffectMode::NeedsIntervention => "tick_reconciliation_required",
                NoEffectMode::None => unreachable!("closed no-effect mode matrix"),
            };
            assert_eq!(followup["code"], expected_followup_code);

            let (status, lifecycle): (StatusCode, Value) = call_json(
                fixture.app.clone(),
                Method::POST,
                &format!("/runs/{}/start", fixture.run_id),
                serde_json::to_value(LifecycleRequest {
                    credential: None,
                    work_order: None,
                    audit_attribution: Some(attribution()),
                    reason: Some("no-effect suffix failure probe".to_string()),
                    approval_evidence: None,
                    authority_obligation_receipts: Vec::new(),
                })
                .expect("lifecycle request"),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "endpoint={endpoint:?} mode={mode:?} lifecycle={lifecycle}"
            );
            let expected_lifecycle_code = match mode {
                NoEffectMode::NeedsApproval => "tick_reconciliation_required",
                NoEffectMode::NeedsIntervention => "invalid_run_state",
                NoEffectMode::None => unreachable!("closed no-effect mode matrix"),
            };
            assert_eq!(lifecycle["code"], expected_lifecycle_code);
            assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);

            let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
                fixture.app,
                Method::GET,
                &format!("/runs/{}", fixture.run_id),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let expected_status = match mode {
                NoEffectMode::NeedsApproval => RunStatus::Running,
                NoEffectMode::NeedsIntervention => RunStatus::Failed,
                NoEffectMode::None => unreachable!("closed no-effect mode matrix"),
            };
            assert_eq!(inspected.status, expected_status);
            assert_eq!(inspected.adapter_executions, 0);
            assert_eq!(inspected.state_head, fixture.state_head);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn no_effect_suffix_barrier_blocks_concurrent_action_and_lifecycle_calls() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        for mode in [NoEffectMode::NeedsApproval, NoEffectMode::NeedsIntervention] {
            let fixture = endpoint_action_fixture_with_mode(
                endpoint,
                json!({"status": "must-not-execute"}),
                mode,
            )
            .await;
            let target = match mode {
                NoEffectMode::NeedsApproval => TraceFailureTarget::ApprovalRequested,
                NoEffectMode::NeedsIntervention => TraceFailureTarget::ActionNeedsIntervention,
                NoEffectMode::None => unreachable!("closed no-effect mode matrix"),
            };
            let barrier = fixture.trace_store.arm_barrier(target);

            let first_app = fixture.app.clone();
            let first_uri = fixture.uri.clone();
            let first_request = fixture.request.clone();
            let first_thread = std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("first request runtime")
                    .block_on(async move {
                        let result: (StatusCode, Value) =
                            call_json(first_app, Method::POST, &first_uri, first_request).await;
                        result
                    })
            });
            if !barrier.wait_until_entered().await {
                barrier.release();
                let first = first_thread.join().expect("timed-out first request");
                panic!(
                    "endpoint={endpoint:?} mode={mode:?} did not reach trace barrier; first={first:?}"
                );
            }

            let followup_app = fixture.app.clone();
            let followup_uri = fixture.uri.clone();
            let followup_request = fixture.followup_request.clone();
            let mut followup_task = tokio::spawn(async move {
                let result: (StatusCode, Value) =
                    call_json(followup_app, Method::POST, &followup_uri, followup_request).await;
                result
            });
            let lifecycle_app = fixture.app.clone();
            let lifecycle_uri = format!("/runs/{}/pause", fixture.run_id);
            let mut lifecycle_task = tokio::spawn(async move {
                let request = serde_json::to_value(LifecycleRequest {
                    credential: None,
                    work_order: None,
                    audit_attribution: Some(attribution()),
                    reason: Some("concurrent no-effect suffix pause probe".to_string()),
                    approval_evidence: None,
                    authority_obligation_receipts: Vec::new(),
                })
                .expect("lifecycle request");
                let result: (StatusCode, Value) =
                    call_json(lifecycle_app, Method::POST, &lifecycle_uri, request).await;
                result
            });

            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut followup_task)
                    .await
                    .is_err(),
                "endpoint={endpoint:?} mode={mode:?} followup escaped suffix barrier"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut lifecycle_task)
                    .await
                    .is_err(),
                "endpoint={endpoint:?} mode={mode:?} lifecycle escaped suffix barrier"
            );
            assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);

            barrier.release();
            let (status, first) = first_thread.join().expect("first no-effect request");
            assert_eq!(status, StatusCode::OK, "first={first}");
            let expected = match mode {
                NoEffectMode::NeedsApproval => "NeedsApproval",
                NoEffectMode::NeedsIntervention => "NeedsIntervention",
                NoEffectMode::None => unreachable!("closed no-effect mode matrix"),
            };
            assert_eq!(first["status"], expected);

            let (status, followup) = followup_task.await.expect("followup request");
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "endpoint={endpoint:?} mode={mode:?} followup={followup}"
            );
            let (status, lifecycle) = lifecycle_task.await.expect("lifecycle request");
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "endpoint={endpoint:?} mode={mode:?} lifecycle={lifecycle}"
            );
            assert_eq!(lifecycle["code"], "invalid_run_state");
            assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_first_pause_conflicts_while_gateway_admission_is_active() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture = endpoint_action_fixture(endpoint, json!({"status": "applied"})).await;
        let barrier = fixture
            .trace_store
            .arm_barrier(TraceFailureTarget::ActionVerificationCompleted);
        let action_app = fixture.app.clone();
        let action_uri = fixture.uri.clone();
        let action_request = fixture.request.clone();
        let action_thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("action runtime")
                .block_on(async move {
                    let result: (StatusCode, Value) =
                        call_json(action_app, Method::POST, &action_uri, action_request).await;
                    result
                })
        });
        if !barrier.wait_until_entered().await {
            barrier.release();
            let first = action_thread.join().expect("timed-out action request");
            panic!("endpoint={endpoint:?} did not reach Gateway barrier; first={first:?}");
        }

        let pause_request = serde_json::to_value(LifecycleRequest {
            credential: None,
            work_order: None,
            audit_attribution: Some(attribution()),
            reason: Some("action-first pause probe".to_string()),
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        })
        .expect("pause request");
        let (status, pause): (StatusCode, Value) = tokio::time::timeout(
            Duration::from_secs(1),
            call_json(
                fixture.app.clone(),
                Method::POST,
                &format!("/runs/{}/pause", fixture.run_id),
                pause_request,
            ),
        )
        .await
        .expect("pause must conflict without waiting for Gateway");
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(pause["code"], "action_in_progress");
        assert_eq!(pause["details"]["retryable"], true);
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);

        barrier.release();
        let (status, outcome) = action_thread.join().expect("action request");
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?} {outcome}");
        assert_eq!(outcome["status"], "Executed");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 1);
        let inspected: RunInspectResponse = call_empty(
            fixture.app,
            Method::GET,
            &format!("/runs/{}", fixture.run_id),
        )
        .await
        .1;
        assert_eq!(inspected.status, RunStatus::Running);
    }
}

#[tokio::test]
async fn pause_first_denies_later_direct_and_physical_actions() {
    for endpoint in [
        ReconciliationEndpoint::Direct,
        ReconciliationEndpoint::Physical,
    ] {
        let fixture =
            endpoint_action_fixture(endpoint, json!({"status": "must-not-execute"})).await;
        let (status, paused): (StatusCode, RunInspectResponse) = call_json(
            fixture.app.clone(),
            Method::POST,
            &format!("/runs/{}/pause", fixture.run_id),
            serde_json::to_value(LifecycleRequest {
                credential: None,
                work_order: None,
                audit_attribution: Some(attribution()),
                reason: Some("pause-first probe".to_string()),
                approval_evidence: None,
                authority_obligation_receipts: Vec::new(),
            })
            .expect("pause request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "endpoint={endpoint:?}");
        assert_eq!(paused.status, RunStatus::Paused);
        let (status, denied): (StatusCode, Value) =
            call_json(fixture.app, Method::POST, &fixture.uri, fixture.request).await;
        assert_eq!(status, StatusCode::CONFLICT, "endpoint={endpoint:?}");
        assert_eq!(denied["code"], "run_not_effect_capable");
        assert_eq!(fixture.adapter_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn daemon_rejects_credential_percept_before_queue_trace_and_policy_state() {
    const CANARY: &str = "C03_DAEMON_PERCEPT_CANARY";

    let trace_store = Arc::new(InMemoryTraceStore::default());
    let app = router(support::state_with_trace_store(
        DaemonConfig::local_dev(),
        trace_store.clone(),
        &["daemon.local"],
    ));
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let create = create_request(tenant_id, agent_id, Vec::new(), Vec::new());
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let mut unsafe_percept = percept("splendor.percept.test.v1");
    unsafe_percept.payload = json!({"body": format!("password={CANARY}")});
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/percepts", created.run_id),
        serde_json::to_value(AppendPerceptRequest {
            credential: None,
            audit_attribution: Some(attribution()),
            percept: Some(unsafe_percept),
        })
        .expect("percept request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, RAW_CREDENTIAL_INPUT_DENIED);
    assert_eq!(error.message, RAW_CREDENTIAL_INPUT_DENIED);
    assert!(error.details.is_null());
    assert!(!serde_json::to_string(&error)
        .expect("error serializes")
        .contains(CANARY));
    let records_after_denial = trace_store
        .read(&created.run_id.to_string())
        .expect("safe audit traces");
    assert!(!serde_json::to_string(&records_after_denial)
        .expect("raw traces serialize")
        .contains(CANARY));

    let lifecycle = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: Some("verify-empty-percept-queue".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, tick): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(lifecycle).expect("lifecycle request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(tick.action_outcomes.is_empty());

    let records = trace_store
        .read(&created.run_id.to_string())
        .expect("raw trace records");
    let encoded = serde_json::to_string(&records).expect("traces serialize");
    assert!(!encoded.contains(CANARY));
    assert!(records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone()).is_ok_and(|event| {
            matches!(
                event.kind,
                TraceEventKind::PerceptsReceived { ref percepts } if percepts.is_empty()
            )
        })
    }));
}

#[tokio::test]
async fn trace_read_and_export_redact_sensitive_payload_views() {
    let trace_store = Arc::new(HistoricalSensitiveTraceStore::default());
    let app = router(support::state_with_trace_store(
        DaemonConfig::local_dev(),
        trace_store.clone(),
        &["daemon.local"],
    ));
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create_request(
            tenant_id.clone(),
            agent_id.clone(),
            Vec::new(),
            Vec::new(),
        ))
        .expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, initial_traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=redacted", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let causal_trace_id = initial_traces
        .records
        .first()
        .and_then(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .map(|event| event.trace_event_id)
        .unwrap_or_else(|| TraceId::from_run_sequence(&created.run_id, 0));

    let action_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::ActionsSubmit]);
    let action_audit = matching_attribution(&action_credential);
    let allowed_action_id = ActionId::new();
    let allowed_submit = SubmitActionRequest {
        action_id: Some(allowed_action_id.clone()),
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: Some(action_credential.clone()),
        audit_attribution: Some(action_audit.clone()),
        causal_trace_id: Some(causal_trace_id.clone()),
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, allowed_outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(allowed_submit).expect("allowed submit"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(allowed_outcome.action_id, allowed_action_id);
    assert_eq!(
        allowed_outcome.status,
        splendor_gateway::ActionStatus::Executed
    );

    let denied_action_id = ActionId::new();
    let denied_submit = SubmitActionRequest {
        action_id: Some(denied_action_id.clone()),
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id,
        credential: Some(action_credential),
        audit_attribution: Some(action_audit),
        causal_trace_id: Some(causal_trace_id),
        action: action("blocked_sensitive_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, denied_outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(denied_submit).expect("denied submit"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(denied_outcome.action_id, denied_action_id);
    assert_eq!(
        denied_outcome.status,
        splendor_gateway::ActionStatus::Denied
    );
    assert!(denied_outcome
        .verification
        .reasons
        .iter()
        .any(|reason| reason == "trusted_action_profile_missing"));
    trace_store.enable_historical_injection();

    let (status, redacted_read): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=redacted", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_canaries_absent("redacted trace read", &redacted_read);
    assert_trace_records_preserve_identity_and_reasons(&created.run_id, &redacted_read.records);

    let (status, none_read): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_canaries_absent("none trace read mandatory redaction", &none_read);
    assert_trace_records_preserve_identity_and_reasons(&created.run_id, &none_read.records);

    let trace_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::TracesRead]);
    let trace_audit = matching_attribution(&trace_credential);
    let (status, redacted_export): (StatusCode, TraceExportResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/traces/export", created.run_id),
        json!({
            "credential": trace_credential.clone(),
            "audit_attribution": trace_audit.clone(),
            "redaction_policy": "redacted",
            "start": null,
            "end": null,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(redacted_export.redaction_policy, "redacted");
    assert_eq!(redacted_export.record_count, redacted_export.records.len());
    assert!(redacted_export
        .integrity_hash
        .starts_with("trace-chain:v1:"));
    assert_canaries_absent("redacted trace export", &redacted_export);
    assert_trace_records_preserve_identity_and_reasons(&created.run_id, &redacted_export.records);
    assert_trace_export_audit_event_visible(&redacted_export.records);

    let (status, none_export): (StatusCode, TraceExportResponse) = call_json(
        app,
        Method::POST,
        &format!("/runs/{}/traces/export", created.run_id),
        json!({
            "credential": trace_credential,
            "audit_attribution": trace_audit,
            "redaction_policy": "none",
            "start": null,
            "end": null,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(none_export.redaction_policy, "none");
    assert_canaries_absent("none trace export mandatory redaction", &none_export);
    assert_trace_records_preserve_identity_and_reasons(&created.run_id, &none_export.records);
    assert_trace_export_audit_event_visible(&none_export.records);
}

#[tokio::test]
async fn trace_read_export_and_replay_never_persist_raw_action_credentials() {
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let state = support::state_with_trace_store(
        DaemonConfig::local_dev(),
        trace_store.clone(),
        &["daemon.local"],
    );
    let app = router(state.clone());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create_request(
            tenant_id.clone(),
            agent_id.clone(),
            Vec::new(),
            Vec::new(),
        ))
        .expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, initial_traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=redacted", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let causal_trace_id = initial_traces
        .records
        .first()
        .and_then(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .map(|event| event.trace_event_id)
        .unwrap_or_else(|| TraceId::from_run_sequence(&created.run_id, 0));

    let mut action_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::ActionsSubmit]);
    action_credential.credential_id = format!("{}{}", "ghp_", "synthetic_caller_identifier");
    let action_audit = matching_attribution(&action_credential);
    let safe_action_id = ActionId::new();
    let safe_submit = SubmitActionRequest {
        action_id: Some(safe_action_id.clone()),
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: Some(action_credential.clone()),
        audit_attribution: Some(action_audit.clone()),
        causal_trace_id: Some(causal_trace_id.clone()),
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, safe_outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(safe_submit).expect("safe submit"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(safe_outcome.action_id, safe_action_id);
    assert_eq!(
        safe_outcome.status,
        splendor_gateway::ActionStatus::Executed
    );
    let authority_evaluations_before_raw = state
        .run_authority_evaluation_count(&created.run_id)
        .expect("authority evaluation count before raw submissions");

    let allowed_action_id = ActionId::new();
    let allowed_submit = SubmitActionRequest {
        action_id: Some(allowed_action_id.clone()),
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: Some(action_credential.clone()),
        audit_attribution: Some(action_audit.clone()),
        causal_trace_id: Some(causal_trace_id.clone()),
        action: fnd009_action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, allowed_outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(allowed_submit).expect("allowed submit"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(allowed_outcome.action_id, allowed_action_id);
    assert_eq!(
        allowed_outcome.status,
        splendor_gateway::ActionStatus::Denied
    );
    assert_eq!(
        allowed_outcome.verification.reasons,
        vec![splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED]
    );

    let denied_action_id = ActionId::new();
    let denied_submit = SubmitActionRequest {
        action_id: Some(denied_action_id.clone()),
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id,
        credential: Some(action_credential),
        audit_attribution: Some(action_audit),
        causal_trace_id: Some(causal_trace_id),
        action: fnd009_action("blocked_sensitive_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, denied_outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(denied_submit).expect("denied submit"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(denied_outcome.action_id, denied_action_id);
    assert_eq!(
        denied_outcome.status,
        splendor_gateway::ActionStatus::Denied
    );
    assert_eq!(
        denied_outcome.verification.reasons,
        vec![splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED]
    );
    assert_eq!(
        state
            .run_authority_evaluation_count(&created.run_id)
            .expect("authority evaluation count after raw submissions"),
        authority_evaluations_before_raw
    );

    let raw_records = trace_store
        .read(&created.run_id.to_string())
        .expect("raw trace records");
    assert_canaries_absent("raw persisted trace", &raw_records);
    let raw_events = raw_records
        .iter()
        .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .collect::<Vec<_>>();
    for denied_id in [&allowed_action_id, &denied_action_id] {
        assert!(raw_events.iter().any(|event| {
            event.identity.action_id.as_ref() == Some(denied_id)
                && matches!(
                    &event.kind,
                    TraceEventKind::ActionDenied { action, result }
                        if action == &splendor_gateway::raw_credential_denied_action()
                            && result.reasons
                                == vec![splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED]
                )
        }));
    }
    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.adapter_executions, 1);

    let replay_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::ReplayCreate]);
    let replay_audit = matching_attribution(&replay_credential);
    let (status, replay): (StatusCode, ReplayResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({
            "credential": replay_credential,
            "audit_attribution": replay_audit,
            "mode": "inspect_only",
            "side_effects_allowed": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay.mode, "inspect_only");
    let (status, inspected_after_replay): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected_after_replay.adapter_executions, 1);

    let (status, redacted_read): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=redacted", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_canaries_absent("redacted trace read", &redacted_read);

    let (status, none_read): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_canaries_absent("none trace read mandatory redaction", &none_read);

    let trace_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::TracesRead]);
    let trace_audit = matching_attribution(&trace_credential);
    let (status, redacted_export): (StatusCode, TraceExportResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/traces/export", created.run_id),
        json!({
            "credential": trace_credential.clone(),
            "audit_attribution": trace_audit.clone(),
            "redaction_policy": "redacted",
            "start": null,
            "end": null,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(redacted_export.redaction_policy, "redacted");
    assert_eq!(redacted_export.record_count, redacted_export.records.len());
    assert!(redacted_export
        .integrity_hash
        .starts_with("trace-chain:v1:"));
    assert_canaries_absent("redacted trace export", &redacted_export);
    assert_trace_export_audit_event_visible(&redacted_export.records);
    let trusted_after_full_export = trace_store
        .read(&created.run_id.to_string())
        .expect("trusted source after full export");
    assert_trace_export_integrity_uses_only_returned_projection(
        "full trace export",
        &redacted_export,
        &trusted_after_full_export,
    );

    let (status, ranged_export): (StatusCode, TraceExportResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/traces/export", created.run_id),
        json!({
            "credential": trace_credential.clone(),
            "audit_attribution": trace_audit.clone(),
            "redaction_policy": "redacted",
            "start": 1,
            "end": 4,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ranged_export.record_count, ranged_export.records.len());
    assert_eq!(ranged_export.records.len(), 3);
    assert_eq!(
        ranged_export.records.first().map(|record| record.sequence),
        Some(1)
    );
    assert!(ranged_export.records[0].prev_event_hash.is_none());
    assert_eq!(
        ranged_export.records.last().map(|record| record.sequence),
        Some(3)
    );
    let trusted_after_ranged_export = trace_store
        .read(&created.run_id.to_string())
        .expect("trusted source after ranged export");
    assert_trace_export_integrity_uses_only_returned_projection(
        "ranged trace export",
        &ranged_export,
        &trusted_after_ranged_export,
    );
    assert_canaries_absent("ranged trace export", &ranged_export);

    let (status, none_export): (StatusCode, TraceExportResponse) = call_json(
        app,
        Method::POST,
        &format!("/runs/{}/traces/export", created.run_id),
        json!({
            "credential": trace_credential,
            "audit_attribution": trace_audit,
            "redaction_policy": "none",
            "start": null,
            "end": null,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(none_export.redaction_policy, "none");
    assert_canaries_absent("none trace export mandatory redaction", &none_export);
    assert_trace_export_audit_event_visible(&none_export.records);
}

#[tokio::test]
async fn experimental_local_dev_state_snapshot_import_preserves_compatibility() {
    let source_app = router(action_test_state());
    let receiver_app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let work_order = signed_work_order(
        tenant_id.clone(),
        agent_id.clone(),
        Some(run_id.clone()),
        vec![EndpointScope::RunsCreate],
    );
    let policy_action_id = ActionId::new();
    let mut planned_action = read_only_action("allowed_action");
    planned_action.preconditions = vec!["ready".to_string()];
    let policy_actions = vec![DaemonActionCandidate {
        action_id: Some(policy_action_id.clone()),
        action: planned_action,
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: vec!["ready".to_string()],
        requested_at: None,
        authority_obligation_receipts: Vec::new(),
    }];
    let mut source_create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        policy_actions,
        vec![RegisteredAction {
            name: "allowed_action".to_string(),
            adapter: "daemon.local".to_string(),
            required_permissions: Some(Vec::new()),
        }],
    );
    source_create.work_order = work_order.clone();
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        source_app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(source_create).expect("source create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created.run_id, run_id);

    let mut receiver_create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        Vec::new(),
        vec![RegisteredAction {
            name: "allowed_action".to_string(),
            adapter: "daemon.local".to_string(),
            required_permissions: Some(Vec::new()),
        }],
    );
    receiver_create.work_order = work_order.clone();
    let (status, receiver_created): (StatusCode, CreateRunResponse) = call_json(
        receiver_app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(receiver_create).expect("receiver create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receiver_created.run_id, run_id);

    let lifecycle = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: Some("commit state before handoff".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, tick): (StatusCode, TickResponse) = call_json(
        source_app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(lifecycle).expect("start request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!tick.state_node_id.is_empty());
    assert_eq!(
        tick.action_outcomes
            .first()
            .expect("policy action outcome")
            .action_id,
        policy_action_id
    );

    let credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::StateHandoff]);
    let audit_attribution = matching_attribution(&credential);
    let export_request = StateSnapshotExportRequest {
        run_id: created.run_id.clone(),
        credential: Some(credential.clone()),
        audit_attribution: Some(audit_attribution.clone()),
        work_order_id: "wo_test".to_string(),
        source_instance_id: Some("00000000-0000-4000-8000-000000000301".to_string()),
        receiver_instance_id: Some("00000000-0000-4000-8000-000000000302".to_string()),
        previous_state_node_id: None,
    };
    let (status, exported): (StatusCode, StateSnapshotExportResponse) = call_json(
        source_app.clone(),
        Method::POST,
        "/state-snapshots/export",
        serde_json::to_value(export_request.clone()).expect("export request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(exported.run_id, created.run_id);
    assert_eq!(exported.state_node_id, tick.state_node_id);
    assert_eq!(exported.handoff.schema_version, "splendor.state_handoff.v0");
    assert_eq!(exported.handoff.authority.work_order_id, "wo_test");
    assert_eq!(
        exported.handoff.source_trace_id.as_ref(),
        Some(&exported.trace_event_id)
    );
    assert_eq!(exported.handoff.previous_state_node_id, None);

    let mut wrong_hash = exported.handoff.clone();
    wrong_hash.snapshot.state_bytes.push(99);
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        receiver_app.clone(),
        Method::POST,
        "/state-snapshots/import",
        serde_json::to_value(StateSnapshotImportRequest {
            handoff: wrong_hash,
            work_order: work_order.clone(),
            credential: Some(credential.clone()),
            audit_attribution: Some(audit_attribution.clone()),
        })
        .expect("wrong hash import"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "state_handoff_rejected");

    for (label, mut invalid_handoff) in [
        ("schema", exported.handoff.clone()),
        ("mode", exported.handoff.clone()),
        ("trace", exported.handoff.clone()),
        ("head", exported.handoff.clone()),
    ] {
        match label {
            "schema" => invalid_handoff.schema_version = "splendor.state_handoff.v999".to_string(),
            "mode" => invalid_handoff.mode = splendor_types::StateReferenceMode::ReadOnlyReference,
            "trace" => invalid_handoff.source_trace_id = None,
            "head" => invalid_handoff.previous_state_node_id = Some("blake3:stale".to_string()),
            _ => unreachable!(),
        }
        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            receiver_app.clone(),
            Method::POST,
            "/state-snapshots/import",
            serde_json::to_value(StateSnapshotImportRequest {
                handoff: invalid_handoff,
                work_order: work_order.clone(),
                credential: Some(credential.clone()),
                audit_attribution: Some(audit_attribution.clone()),
            })
            .expect("invalid import request"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{label}");
        assert_eq!(error.code, "state_handoff_rejected", "{label}");
    }

    let mut wrong_work_order = work_order.clone();
    wrong_work_order.work_order.work_order_id = WorkOrderId::try_new("wo_other").unwrap();
    resign_work_order(&mut wrong_work_order);
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        receiver_app.clone(),
        Method::POST,
        "/state-snapshots/import",
        serde_json::to_value(StateSnapshotImportRequest {
            handoff: exported.handoff.clone(),
            work_order: wrong_work_order,
            credential: Some(credential.clone()),
            audit_attribution: Some(audit_attribution.clone()),
        })
        .expect("wrong work order import"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "resume_work_order_identity_mismatch");

    let mut unsigned_work_order = work_order.clone();
    unsigned_work_order.signature = None;
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        receiver_app.clone(),
        Method::POST,
        "/state-snapshots/import",
        serde_json::to_value(StateSnapshotImportRequest {
            handoff: exported.handoff.clone(),
            work_order: unsigned_work_order,
            credential: Some(credential.clone()),
            audit_attribution: Some(audit_attribution.clone()),
        })
        .expect("unsigned work order import"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "unsigned_work_order");

    for (label, revocation) in [
        ("expired", RevocationStatus::Active),
        (
            "revoked",
            RevocationStatus::Revoked {
                reason: "test revocation".to_string(),
            },
        ),
    ] {
        let mut invalid_work_order = work_order.clone();
        invalid_work_order.work_order.revocation = revocation;
        if label == "expired" {
            invalid_work_order.work_order.expires_at = OffsetDateTime::now_utc();
        }
        resign_work_order(&mut invalid_work_order);
        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            receiver_app.clone(),
            Method::POST,
            "/state-snapshots/import",
            serde_json::to_value(StateSnapshotImportRequest {
                handoff: exported.handoff.clone(),
                work_order: invalid_work_order,
                credential: Some(credential.clone()),
                audit_attribution: Some(audit_attribution.clone()),
            })
            .expect("inactive work order import"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{label}");
        assert_eq!(error.code, format!("{label}_work_order"), "{label}");
    }

    let (status, error): (StatusCode, ApiErrorBody) = call_empty(
        receiver_app.clone(),
        Method::GET,
        &format!("/runs/{}/state-head", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error.code, "state_head_not_found");

    let (status, imported): (StatusCode, StateSnapshotImportResponse) = call_json(
        receiver_app.clone(),
        Method::POST,
        "/state-snapshots/import",
        serde_json::to_value(StateSnapshotImportRequest {
            handoff: exported.handoff.clone(),
            work_order: work_order.clone(),
            credential: Some(credential.clone()),
            audit_attribution: Some(audit_attribution.clone()),
        })
        .expect("import request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(imported.run_id, created.run_id);
    assert!(imported.accepted);
    assert_eq!(imported.state_node_id, tick.state_node_id);

    let (status, head): (StatusCode, StateHeadResponse) = call_empty(
        receiver_app.clone(),
        Method::GET,
        &format!("/runs/{}/state-head", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(head.state_node_id, imported.state_node_id);

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        receiver_app.clone(),
        Method::POST,
        "/state-snapshots/import",
        serde_json::to_value(StateSnapshotImportRequest {
            handoff: exported.handoff.clone(),
            work_order: work_order.clone(),
            credential: Some(credential.clone()),
            audit_attribution: Some(audit_attribution.clone()),
        })
        .expect("replayed import request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "state_handoff_rejected");
    let (status, replay_head): (StatusCode, StateHeadResponse) = call_empty(
        receiver_app.clone(),
        Method::GET,
        &format!("/runs/{}/state-head", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay_head.state_node_id, imported.state_node_id);

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        source_app.clone(),
        Method::POST,
        "/state-snapshots/export",
        serde_json::to_value(StateSnapshotExportRequest {
            credential: None,
            audit_attribution: Some(audit_attribution.clone()),
            ..export_request
        })
        .expect("missing credential export request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "missing_caller_credential");

    let mut wrong_handoff = exported.handoff;
    wrong_handoff.authority.tenant_id = TenantId::new();
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        receiver_app,
        Method::POST,
        "/state-snapshots/import",
        serde_json::to_value(StateSnapshotImportRequest {
            handoff: wrong_handoff,
            work_order,
            credential: Some(credential),
            audit_attribution: Some(audit_attribution),
        })
        .expect("wrong authority import request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "state_handoff_authority_mismatch");
    assert!(error.details["trace_event_id"].is_string());
}

#[tokio::test]
async fn replay_and_trace_export_reject_missing_null_and_mismatched_audit() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let create = create_request(tenant_id.clone(), agent_id, Vec::new(), Vec::new());
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let trace_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::TracesRead]);
    let trace_audit = AuditAttribution {
        credential_id: Some(trace_credential.credential_id.clone()),
        ..attribution()
    };
    let replay_credential =
        caller_credential_for_tenant(tenant_id, vec![EndpointScope::ReplayCreate]);
    let replay_audit = AuditAttribution {
        credential_id: Some(replay_credential.credential_id.clone()),
        ..attribution()
    };

    for (path, credential, audit) in [
        (
            format!("/runs/{}/traces/export", created.run_id),
            serde_json::to_value(&trace_credential).unwrap(),
            serde_json::to_value(&trace_audit).unwrap(),
        ),
        (
            format!("/runs/{}/replay", created.run_id),
            serde_json::to_value(&replay_credential).unwrap(),
            serde_json::to_value(&replay_audit).unwrap(),
        ),
    ] {
        let mut base = if path.ends_with("/replay") {
            json!({"mode": "inspect_only", "side_effects_allowed": false})
        } else {
            json!({"redaction_policy": "none", "start": null, "end": null})
        };

        let (status, error): (StatusCode, ApiErrorBody) =
            call_json(app.clone(), Method::POST, &path, base.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} missing credential");
        assert_eq!(error.code, "missing_caller_credential");

        base["credential"] = Value::Null;
        base["audit_attribution"] = audit.clone();
        let (status, error): (StatusCode, ApiErrorBody) =
            call_json(app.clone(), Method::POST, &path, base.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} null credential");
        assert_eq!(error.code, "missing_caller_credential");

        base["credential"] = credential.clone();
        base.as_object_mut().unwrap().remove("audit_attribution");
        let (status, error): (StatusCode, ApiErrorBody) =
            call_json(app.clone(), Method::POST, &path, base.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} missing audit");
        assert_eq!(error.code, "missing_audit_attribution");

        base["audit_attribution"] = Value::Null;
        let (status, error): (StatusCode, ApiErrorBody) =
            call_json(app.clone(), Method::POST, &path, base.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} null audit");
        assert_eq!(error.code, "missing_audit_attribution");

        let mut mismatched = audit.clone();
        mismatched["credential_id"] = json!("cred_other");
        base["audit_attribution"] = mismatched;
        let (status, error): (StatusCode, ApiErrorBody) =
            call_json(app.clone(), Method::POST, &path, base.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} credential mismatch");
        assert_eq!(error.code, "audit_credential_mismatch");

        let mut principal_mismatch = audit.clone();
        principal_mismatch["principal"] =
            serde_json::to_value(ClientPrincipal::new("app_test", "client_other")).unwrap();
        base["audit_attribution"] = principal_mismatch;
        let (status, error): (StatusCode, ApiErrorBody) =
            call_json(app.clone(), Method::POST, &path, base.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path} principal mismatch");
        assert_eq!(error.code, "audit_principal_mismatch");
    }
}

#[tokio::test]
async fn approval_required_run_pauses_and_exact_receipt_retry_executes_once() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let policy_action_id = ActionId::new();
    let policy_actions = vec![DaemonActionCandidate {
        action_id: Some(policy_action_id.clone()),
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        authority_obligation_receipts: Vec::new(),
    }];
    let mut create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        policy_actions,
        Vec::new(),
    );
    create.approval_policies = vec![approval_policy(&tenant_id, &agent_id, "allowed_action")];
    let original_work_order = create.work_order.clone();

    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let start = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: Some("start approval test".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, waiting): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(start).expect("start request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(waiting.status, RunStatus::WaitingForApproval);
    assert_eq!(
        waiting.action_outcomes[0].status,
        splendor_gateway::ActionStatus::NeedsApproval
    );
    let challenge = waiting.action_outcomes[0]
        .approval_challenge
        .clone()
        .expect("scheduler action approval challenge");
    assert_eq!(challenge.action_id, policy_action_id);
    let paused_state_node_id = waiting.state_node_id.clone();

    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.status, RunStatus::WaitingForApproval);
    assert_eq!(inspected.adapter_executions, 0);

    let missing_approval_resume = LifecycleRequest {
        credential: None,
        work_order: Some(bind_original_work_order_for_resume(
            original_work_order.clone(),
            created.run_id.clone(),
        )),
        audit_attribution: Some(attribution()),
        reason: Some("missing approval".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(missing_approval_resume).expect("missing approval resume"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "approval_exact_action_retry_required");

    let grant = approval_evidence(
        &tenant_id,
        &agent_id,
        &created.run_id,
        "allowed_action",
        ApprovalDecision::Granted,
    );
    let resume = LifecycleRequest {
        credential: None,
        work_order: Some(bind_original_work_order_for_resume(
            original_work_order.clone(),
            created.run_id.clone(),
        )),
        audit_attribution: Some(attribution()),
        reason: Some("approval granted".to_string()),
        approval_evidence: Some(grant),
        authority_obligation_receipts: Vec::new(),
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(resume).expect("resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "legacy_approval_evidence_non_authorizing");
    let receipt = local_approval_receipt_config()
        .issue_approval_receipt(&challenge, TraceEventId::new(), OffsetDateTime::now_utc())
        .expect("trusted scheduler approval receipt");
    let receipt_resume = LifecycleRequest {
        credential: None,
        work_order: Some(bind_original_work_order_for_resume(
            original_work_order,
            created.run_id.clone(),
        )),
        audit_attribution: Some(attribution()),
        reason: Some("receipt retry must not run scheduler".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: vec![receipt.clone()],
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(receipt_resume).expect("receipt resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "approval_receipt_resume_not_supported");

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let causal_trace_id = traces
        .records
        .first()
        .and_then(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .map(|event| event.trace_event_id)
        .expect("paused run trace identity");
    let exact_retry = SubmitActionRequest {
        action_id: Some(challenge.action_id.clone()),
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: Some(causal_trace_id),
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: Some(challenge.requested_at),
        approval_evidence: None,
        authority_obligation_receipts: vec![receipt],
    };
    let (status, executed): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(exact_retry).expect("exact approved action retry"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(executed.status, splendor_gateway::ActionStatus::Executed);

    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.adapter_executions, 1);
    assert_eq!(inspected.status, RunStatus::Running);
    assert_eq!(inspected.ticks, 1);
    assert_eq!(
        inspected.state_head.as_deref(),
        Some(paused_state_node_id.as_str())
    );

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| matches!(event.kind, TraceEventKind::ActionNeedsApproval { .. }))
            .unwrap_or(false)
    }));
    assert!(traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| matches!(event.kind, TraceEventKind::ApprovalRequested { .. }))
            .unwrap_or(false)
    }));
    assert!(traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| matches!(event.kind, TraceEventKind::ApprovalGranted { .. }))
            .unwrap_or(false)
    }));
    assert!(traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| {
                matches!(event.kind, TraceEventKind::RunPaused { ref reason }
                    if reason.as_deref() == Some("waiting_for_approval"))
            })
            .unwrap_or(false)
    }));

    let replay_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::ReplayCreate]);
    let replay_audit = AuditAttribution {
        credential_id: Some(replay_credential.credential_id.clone()),
        ..attribution()
    };
    let (status, replay): (StatusCode, ReplayResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({"credential": replay_credential, "audit_attribution": replay_audit}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay.mode, "inspect_only");
    assert!(replay
        .approval_events
        .iter()
        .any(|event| event.lifecycle == "requested"));
    assert!(replay
        .approval_events
        .iter()
        .any(|event| event.lifecycle == "granted"));
}

#[tokio::test]
async fn policy_bundle_metadata_and_sync_failure_are_trace_visible() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let mut create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        vec![DaemonActionCandidate {
            action_id: None,
            action: read_only_action("allowed_action"),
            adapter: Some("daemon.local".to_string()),
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
            requested_at: None,
            authority_obligation_receipts: Vec::new(),
        }],
        Vec::new(),
    );
    create.policy_bundle_required = true;
    create.policy_bundle = Some(signed_policy_bundle(
        tenant_id.clone(),
        Some(agent_id.clone()),
        RevocationStatus::Active,
    ));

    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        inspected
            .policy_bundle
            .as_ref()
            .expect("policy bundle")
            .policy_bundle_id
            .as_str(),
        "pol_daemon"
    );

    let sync = PolicySyncRequest {
        credential: None,
        audit_attribution: Some(attribution()),
        policy_bundle: None,
        sync_error: Some("central unavailable token=raw-secret".to_string()),
        disconnected: Some(true),
    };
    let (status, synced): (StatusCode, PolicySyncResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(sync).expect("policy sync request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!synced.accepted);
    assert!(synced.cache_status.disconnected);
    assert_eq!(
        synced.cache_status.last_sync_failure.as_deref(),
        Some("policy_reason_redacted")
    );

    let reconnect = PolicySyncRequest {
        credential: None,
        audit_attribution: Some(attribution()),
        policy_bundle: Some(signed_policy_bundle(
            tenant_id.clone(),
            Some(agent_id.clone()),
            RevocationStatus::Active,
        )),
        sync_error: None,
        disconnected: Some(false),
    };
    let (status, reconnected): (StatusCode, PolicySyncResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(reconnect).expect("policy reconnect request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(reconnected.accepted);
    assert!(!reconnected.cache_status.disconnected);

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app,
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let saw_policy_bundle = traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| matches!(event.kind, TraceEventKind::PolicyBundleAccepted { .. }))
            .unwrap_or(false)
    });
    let saw_sync_failure = traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| matches!(event.kind, TraceEventKind::PolicySyncFailed { .. }))
            .unwrap_or(false)
    });
    let saw_disconnect = traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| {
                matches!(
                    event.kind,
                    TraceEventKind::PolicyConnectivityChanged {
                        disconnected: true,
                        ..
                    }
                )
            })
            .unwrap_or(false)
    });
    let saw_reconnect = traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| {
                matches!(
                    event.kind,
                    TraceEventKind::PolicyConnectivityChanged {
                        disconnected: false,
                        ..
                    }
                )
            })
            .unwrap_or(false)
    });
    assert!(saw_policy_bundle);
    assert!(saw_sync_failure);
    assert!(saw_disconnect);
    assert!(saw_reconnect);
    let serialized = serde_json::to_string(&traces.records).expect("serialized traces");
    assert!(!serialized.contains("raw-secret"));
    assert!(!serialized.contains("token="));
}

#[tokio::test]
async fn policy_sync_unsupported_future_expired_and_revoked_matrix_fails_closed() {
    for scenario in [
        "unsupported",
        "future",
        "expired",
        "bad_signature",
        "rollback",
        "unrelated_revoked",
        "revoked",
    ] {
        let app = router(action_test_state());
        let tenant_id = TenantId::parse("10000000-0000-4000-8000-000000000001").expect("tenant id");
        let agent_id = AgentId::parse("20000000-0000-4000-8000-000000000002").expect("agent id");
        let now = OffsetDateTime::now_utc();
        let mut create =
            create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
        create.policy_bundle_required = true;
        create.policy_bundle = Some(signed_policy_bundle_with_window(
            "pol_last_trusted",
            "trusted-v1",
            tenant_id.clone(),
            Some(agent_id.clone()),
            now - time::Duration::minutes(5),
            now + time::Duration::hours(2),
            RevocationStatus::Active,
        ));
        let (status, created): (StatusCode, CreateRunResponse) = call_json(
            app.clone(),
            Method::POST,
            "/runs",
            serde_json::to_value(create).expect("create request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "scenario={scenario}");

        let disconnect = PolicySyncRequest {
            credential: None,
            audit_attribution: Some(attribution()),
            policy_bundle: None,
            sync_error: Some("central_unavailable".to_string()),
            disconnected: Some(true),
        };
        let (status, disconnected): (StatusCode, PolicySyncResponse) = call_json(
            app.clone(),
            Method::POST,
            &format!("/runs/{}/policies/sync", created.run_id),
            serde_json::to_value(disconnect).expect("disconnect request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "scenario={scenario}");
        assert!(
            disconnected.cache_status.disconnected,
            "scenario={scenario}"
        );

        let (issued_at, expires_at, revocation) = match scenario {
            "future" => (
                now + time::Duration::hours(1),
                now + time::Duration::hours(2),
                RevocationStatus::Active,
            ),
            "expired" => (
                now - time::Duration::hours(2),
                now - time::Duration::hours(1),
                RevocationStatus::Active,
            ),
            "revoked" => (
                now - time::Duration::minutes(5),
                now + time::Duration::hours(2),
                RevocationStatus::Revoked {
                    reason: "central_revocation".to_string(),
                },
            ),
            "unrelated_revoked" => (
                now - time::Duration::minutes(1),
                now + time::Duration::hours(2),
                RevocationStatus::Revoked {
                    reason: "unrelated_revocation".to_string(),
                },
            ),
            "rollback" => (
                now - time::Duration::minutes(10),
                now + time::Duration::hours(2),
                RevocationStatus::Active,
            ),
            "bad_signature" => (
                now - time::Duration::minutes(1),
                now + time::Duration::hours(2),
                RevocationStatus::Active,
            ),
            "unsupported" => (
                now - time::Duration::minutes(5),
                now + time::Duration::hours(2),
                RevocationStatus::Active,
            ),
            _ => unreachable!("bounded policy sync scenario"),
        };
        let candidate_id = if scenario == "revoked" {
            "pol_last_trusted"
        } else {
            "pol_candidate"
        };
        let mut candidate = signed_policy_bundle_with_window(
            candidate_id,
            "candidate-v1",
            tenant_id.clone(),
            Some(agent_id.clone()),
            issued_at,
            expires_at,
            revocation,
        );
        if scenario == "unsupported" {
            candidate.bundle.schema_version = "splendor.policy_bundle.v2".to_string();
        } else if scenario == "bad_signature" {
            candidate
                .signature
                .as_mut()
                .expect("candidate signature")
                .signature = "bad".to_string();
        }
        let expected_reason = match scenario {
            "unsupported" => "malformed_policy_bundle",
            "future" => "future_issued_policy_bundle",
            "expired" => "expired_policy_bundle",
            "bad_signature" => "bad_policy_signature",
            "rollback" => "policy_cache_install_rollback",
            "unrelated_revoked" => "policy_cache_revocation_unrelated",
            "revoked" => "revoked_policy_bundle",
            _ => unreachable!("bounded policy sync scenario"),
        };
        let expected_status = if scenario == "unsupported" || scenario == "bad_signature" {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::FORBIDDEN
        };
        let sync = PolicySyncRequest {
            credential: None,
            audit_attribution: Some(attribution()),
            policy_bundle: Some(candidate),
            sync_error: None,
            disconnected: Some(false),
        };
        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            app.clone(),
            Method::POST,
            &format!("/runs/{}/policies/sync", created.run_id),
            serde_json::to_value(sync).expect("policy sync request"),
        )
        .await;
        assert_eq!(status, expected_status, "scenario={scenario}");
        assert_eq!(error.code, expected_reason, "scenario={scenario}");

        let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
            app.clone(),
            Method::GET,
            &format!("/runs/{}", created.run_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "scenario={scenario}");
        let cached = inspected
            .policy_bundle
            .expect("last trusted cache metadata");
        assert_eq!(
            cached.policy_bundle_id.as_str(),
            "pol_last_trusted",
            "scenario={scenario}"
        );
        assert_eq!(cached.version, "trusted-v1", "scenario={scenario}");
        assert_eq!(inspected.adapter_executions, 0, "scenario={scenario}");

        let (status, traces): (StatusCode, TracePageResponse) = call_empty(
            app.clone(),
            Method::GET,
            &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "scenario={scenario}");
        let events: Vec<TraceEvent> = traces
            .records
            .iter()
            .map(|record| {
                serde_json::from_value(record.payload.clone()).expect("policy trace event")
            })
            .collect();
        assert!(
            events.iter().any(|event| matches!(
                &event.kind,
                TraceEventKind::PolicyBundleRejected {
                    policy_bundle_id: Some(policy_bundle_id),
                    version: Some(version),
                    reason,
                } if policy_bundle_id.as_str() == candidate_id
                    && version == "candidate-v1"
                    && reason == expected_reason
            )),
            "scenario={scenario} missing policy.bundle.rejected"
        );
        assert!(
            events.iter().any(|event| matches!(
                &event.kind,
                TraceEventKind::PolicySyncFailed {
                    policy_bundle_id: Some(policy_bundle_id),
                    version: Some(version),
                    reason,
                } if policy_bundle_id.as_str() == candidate_id
                    && version == "candidate-v1"
                    && reason == expected_reason
            )),
            "scenario={scenario} missing policy.sync.failed"
        );
        assert!(
            !events.iter().any(|event| matches!(
                &event.kind,
                TraceEventKind::PolicyConnectivityChanged {
                    disconnected: false,
                    ..
                }
            )),
            "scenario={scenario} failed candidate must not reconnect"
        );
        if scenario == "revoked" {
            assert!(events.iter().any(|event| matches!(
                &event.kind,
                TraceEventKind::PolicyRevoked {
                    policy_bundle_id,
                    version,
                    reason,
                } if policy_bundle_id.as_str() == "pol_last_trusted"
                    && version == "trusted-v1"
                    && reason == "central_revocation"
            )));
        }
        let causal_trace_id = events
            .first()
            .map(|event| event.trace_event_id.clone())
            .expect("run trace identity");
        let submit = SubmitActionRequest {
            action_id: None,
            run_id: created.run_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            credential: None,
            audit_attribution: Some(attribution()),
            causal_trace_id: Some(causal_trace_id),
            action: action("allowed_action"),
            adapter: Some("daemon.local".to_string()),
            quota_usage: Some(QuotaUsage::single_action()),
            satisfied_preconditions: Vec::new(),
            requested_at: None,
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        };
        let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
            app.clone(),
            Method::POST,
            "/actions",
            serde_json::to_value(submit).expect("submit action request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "scenario={scenario}");
        assert_eq!(
            outcome.status,
            splendor_gateway::ActionStatus::Denied,
            "scenario={scenario}"
        );
        let expected_action_reason = if scenario == "revoked" {
            "policy_revoked"
        } else {
            "offline_action_not_allowed"
        };
        assert_eq!(
            outcome.verification.reasons,
            vec![expected_action_reason],
            "scenario={scenario}"
        );

        let (status, inspected): (StatusCode, RunInspectResponse) =
            call_empty(app, Method::GET, &format!("/runs/{}", created.run_id)).await;
        assert_eq!(status, StatusCode::OK, "scenario={scenario}");
        assert_eq!(
            inspected.adapter_executions, 0,
            "scenario={scenario} adapter must remain uncalled"
        );
    }
}

#[tokio::test]
async fn policy_sync_revocation_watermark_and_exact_retry_reconnect_attacks_fail_closed() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let now = OffsetDateTime::now_utc();
    let t10 = now - time::Duration::minutes(30);
    let t15 = now - time::Duration::minutes(20);
    let t19 = now - time::Duration::minutes(11);
    let t20 = now - time::Duration::minutes(10);
    let t21 = now - time::Duration::minutes(5);
    let expires_at = now + time::Duration::hours(1);
    let active_t10 = signed_policy_bundle_with_window(
        "pol_watermark",
        "active-t10",
        tenant_id.clone(),
        Some(agent_id.clone()),
        t10,
        expires_at,
        RevocationStatus::Active,
    );
    let mut create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        Vec::new(),
        vec![RegisteredAction {
            name: "allowed_action".to_string(),
            adapter: "daemon.local".to_string(),
            required_permissions: Some(Vec::new()),
        }],
    );
    create.policy_bundle_required = true;
    create.policy_bundle = Some(active_t10.clone());
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let disconnect = PolicySyncRequest {
        credential: None,
        audit_attribution: Some(attribution()),
        policy_bundle: None,
        sync_error: Some("central_unavailable".to_string()),
        disconnected: Some(true),
    };
    let (status, disconnected): (StatusCode, PolicySyncResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(disconnect).expect("disconnect request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(disconnected.cache_status.disconnected);

    let exact_retry = PolicySyncRequest {
        credential: None,
        audit_attribution: Some(attribution()),
        policy_bundle: Some(active_t10.clone()),
        sync_error: None,
        disconnected: Some(false),
    };
    let (status, exact): (StatusCode, PolicySyncResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(exact_retry).expect("exact retry"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(exact.cache_status.disconnected);
    let denied = submit_allowed_action(
        app.clone(),
        created.run_id.clone(),
        tenant_id.clone(),
        agent_id.clone(),
    )
    .await;
    assert_eq!(denied.status, splendor_gateway::ActionStatus::Denied);
    assert_eq!(
        denied.verification.reasons,
        vec!["offline_action_not_allowed"]
    );

    let revoked_t20 = signed_policy_bundle_with_window(
        "pol_watermark",
        "revoked-t20",
        tenant_id.clone(),
        Some(agent_id.clone()),
        t20,
        expires_at,
        RevocationStatus::Revoked {
            reason: "revoked_at_t20".to_string(),
        },
    );
    let revocation_sync = |policy_bundle| PolicySyncRequest {
        credential: None,
        audit_attribution: Some(attribution()),
        policy_bundle: Some(policy_bundle),
        sync_error: None,
        disconnected: Some(false),
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(revocation_sync(revoked_t20.clone())).expect("T20 revocation"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "revoked_policy_bundle");

    let active_t15 = signed_policy_bundle_with_window(
        "pol_watermark",
        "active-t15",
        tenant_id.clone(),
        Some(agent_id.clone()),
        t15,
        expires_at,
        RevocationStatus::Active,
    );
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(revocation_sync(active_t15)).expect("T15 replay"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "policy_cache_revocation_watermark");

    let older_revocation = signed_policy_bundle_with_window(
        "pol_watermark",
        "revoked-t19",
        tenant_id.clone(),
        Some(agent_id.clone()),
        t19,
        expires_at,
        RevocationStatus::Revoked {
            reason: "revoked_at_t19".to_string(),
        },
    );
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(revocation_sync(older_revocation)).expect("older revocation"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "policy_cache_revocation_rollback");

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(revocation_sync(revoked_t20)).expect("exact revocation retry"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "revoked_policy_bundle");

    let denied = submit_allowed_action(
        app.clone(),
        created.run_id.clone(),
        tenant_id.clone(),
        agent_id.clone(),
    )
    .await;
    assert_eq!(denied.status, splendor_gateway::ActionStatus::Denied);
    assert_eq!(denied.verification.reasons, vec!["policy_revoked"]);

    let inspected_before_refresh: RunInspectResponse = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await
    .1;
    assert_eq!(inspected_before_refresh.adapter_executions, 0);
    assert_eq!(
        inspected_before_refresh
            .policy_bundle
            .expect("T10 authority remains")
            .version,
        "active-t10"
    );

    let active_t21 = signed_policy_bundle_with_window(
        "pol_watermark",
        "active-t21",
        tenant_id,
        Some(agent_id),
        t21,
        expires_at,
        RevocationStatus::Active,
    );
    let (status, refreshed): (StatusCode, PolicySyncResponse) = call_json(
        app,
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(revocation_sync(active_t21)).expect("T21 refresh"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(refreshed.accepted);
    assert!(!refreshed.cache_status.disconnected);
    assert_eq!(
        refreshed.policy_bundle.expect("T21 authority").version,
        "active-t21"
    );
}

#[tokio::test]
async fn policy_sync_trace_failures_do_not_commit_authority_or_reconnect() {
    let trace_store = Arc::new(ArmableTraceStore::default());
    let app = router(support::state_with_trace_store(
        DaemonConfig::local_dev(),
        trace_store.clone(),
        &["daemon.local"],
    ));
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let now = OffsetDateTime::now_utc();
    let expires_at = now + time::Duration::hours(1);
    let active_t10 = signed_policy_bundle_with_window(
        "pol_trace_atomic",
        "active-t10",
        tenant_id.clone(),
        Some(agent_id.clone()),
        now - time::Duration::minutes(30),
        expires_at,
        RevocationStatus::Active,
    );
    let mut create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        Vec::new(),
        vec![RegisteredAction {
            name: "allowed_action".to_string(),
            adapter: "daemon.local".to_string(),
            required_permissions: Some(Vec::new()),
        }],
    );
    create.policy_bundle_required = true;
    create.policy_bundle = Some(active_t10);
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    trace_store.arm(TraceFailureTarget::Accepted);
    let active_t20 = signed_policy_bundle_with_window(
        "pol_trace_atomic",
        "active-t20",
        tenant_id.clone(),
        Some(agent_id.clone()),
        now - time::Duration::minutes(10),
        expires_at,
        RevocationStatus::Active,
    );
    let sync = |bundle, disconnected| PolicySyncRequest {
        credential: None,
        audit_attribution: Some(attribution()),
        policy_bundle: Some(bundle),
        sync_error: None,
        disconnected,
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(sync(active_t20, None)).expect("T20 sync"),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error.code, "trace_error");
    let inspected: RunInspectResponse = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await
    .1;
    assert_eq!(
        inspected.policy_bundle.expect("prior authority").version,
        "active-t10"
    );

    let disconnect = PolicySyncRequest {
        credential: None,
        audit_attribution: Some(attribution()),
        policy_bundle: None,
        sync_error: Some("central_unavailable".to_string()),
        disconnected: Some(true),
    };
    let (status, disconnected): (StatusCode, PolicySyncResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(disconnect).expect("disconnect request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(disconnected.cache_status.disconnected);

    trace_store.arm(TraceFailureTarget::Reconnected);
    let active_t21 = signed_policy_bundle_with_window(
        "pol_trace_atomic",
        "active-t21",
        tenant_id.clone(),
        Some(agent_id.clone()),
        now - time::Duration::minutes(5),
        expires_at,
        RevocationStatus::Active,
    );
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(sync(active_t21, Some(false))).expect("reconnect sync"),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error.code, "trace_error");

    let denied =
        submit_allowed_action(app.clone(), created.run_id.clone(), tenant_id, agent_id).await;
    assert_eq!(denied.status, splendor_gateway::ActionStatus::Denied);
    assert_eq!(
        denied.verification.reasons,
        vec!["offline_action_not_allowed"]
    );
    let inspected: RunInspectResponse =
        call_empty(app, Method::GET, &format!("/runs/{}", created.run_id))
            .await
            .1;
    assert_eq!(inspected.adapter_executions, 0);
    assert_eq!(
        inspected.policy_bundle.expect("prior authority").version,
        "active-t10"
    );
}

#[tokio::test]
async fn revocation_trace_stage_failures_latch_pending_deny_and_reconcile_on_retry() {
    for target in [
        TraceFailureTarget::Rejected,
        TraceFailureTarget::SyncFailed,
        TraceFailureTarget::Revoked,
    ] {
        let trace_store = Arc::new(ArmableTraceStore::default());
        let app = router(support::state_with_trace_store(
            DaemonConfig::local_dev(),
            trace_store.clone(),
            &["daemon.local"],
        ));
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::hours(1);
        let active_t10 = signed_policy_bundle_with_window(
            "pol_pending_revocation",
            "active-t10",
            tenant_id.clone(),
            Some(agent_id.clone()),
            now - time::Duration::minutes(30),
            expires_at,
            RevocationStatus::Active,
        );
        let mut create = create_request(
            tenant_id.clone(),
            agent_id.clone(),
            Vec::new(),
            vec![RegisteredAction {
                name: "allowed_action".to_string(),
                adapter: "daemon.local".to_string(),
                required_permissions: Some(Vec::new()),
            }],
        );
        create.policy_bundle_required = true;
        create.policy_bundle = Some(active_t10);
        let (status, created): (StatusCode, CreateRunResponse) = call_json(
            app.clone(),
            Method::POST,
            "/runs",
            serde_json::to_value(create).expect("create request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "target={target:?}");

        let revoked_t20 = signed_policy_bundle_with_window(
            "pol_pending_revocation",
            "revoked-t20",
            tenant_id.clone(),
            Some(agent_id.clone()),
            now - time::Duration::minutes(10),
            expires_at,
            RevocationStatus::Revoked {
                reason: "revoked_at_t20".to_string(),
            },
        );
        let sync = |bundle| PolicySyncRequest {
            credential: None,
            audit_attribution: Some(attribution()),
            policy_bundle: Some(bundle),
            sync_error: None,
            disconnected: None,
        };
        trace_store.arm(target);
        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            app.clone(),
            Method::POST,
            &format!("/runs/{}/policies/sync", created.run_id),
            serde_json::to_value(sync(revoked_t20.clone())).expect("failed revocation sync"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "target={target:?}"
        );
        assert_eq!(error.code, "trace_error", "target={target:?}");

        let denied = submit_allowed_action(
            app.clone(),
            created.run_id.clone(),
            tenant_id.clone(),
            agent_id.clone(),
        )
        .await;
        assert_eq!(
            denied.status,
            splendor_gateway::ActionStatus::Denied,
            "target={target:?}"
        );
        assert_eq!(
            denied.verification.reasons,
            vec!["policy_evidence_unavailable"],
            "target={target:?}"
        );

        let active_t15 = signed_policy_bundle_with_window(
            "pol_pending_revocation",
            "active-t15",
            tenant_id.clone(),
            Some(agent_id.clone()),
            now - time::Duration::minutes(20),
            expires_at,
            RevocationStatus::Active,
        );
        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            app.clone(),
            Method::POST,
            &format!("/runs/{}/policies/sync", created.run_id),
            serde_json::to_value(sync(active_t15)).expect("T15 pending watermark attack"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "target={target:?}");
        assert_eq!(
            error.code, "policy_cache_revocation_watermark",
            "target={target:?}"
        );

        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            app.clone(),
            Method::POST,
            &format!("/runs/{}/policies/sync", created.run_id),
            serde_json::to_value(sync(revoked_t20)).expect("revocation reconciliation"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "target={target:?}");
        assert_eq!(error.code, "revoked_policy_bundle", "target={target:?}");

        let denied =
            submit_allowed_action(app.clone(), created.run_id.clone(), tenant_id, agent_id).await;
        assert_eq!(
            denied.status,
            splendor_gateway::ActionStatus::Denied,
            "target={target:?}"
        );
        assert_eq!(
            denied.verification.reasons,
            vec!["policy_revoked"],
            "target={target:?}"
        );
        let inspected: RunInspectResponse =
            call_empty(app, Method::GET, &format!("/runs/{}", created.run_id))
                .await
                .1;
        assert_eq!(inspected.adapter_executions, 0, "target={target:?}");
    }
}

#[tokio::test]
async fn circuit_breaker_sync_updates_live_gateway_and_preserves_action_id() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let create = create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let breaker_id = CircuitBreakerId::try_new("breaker_daemon_sync").expect("breaker id");
    let breaker = CircuitBreaker::tripped(
        breaker_id.clone(),
        CircuitBreakerScope::Adapter("daemon.local".to_string()),
        "unit_breaker_sync",
        OffsetDateTime::now_utc(),
    )
    .expect("breaker");
    let (status, synced): (StatusCode, CircuitBreakerSyncResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/governance/circuit-breakers/sync", created.run_id),
        json!({
            "credential": null,
            "audit_attribution": attribution(),
            "circuit_breakers": [breaker],
            "reason": "unit_manager_sync"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(synced.accepted);
    assert_eq!(synced.run_id, created.run_id);
    assert_eq!(synced.breaker_ids, vec![breaker_id.to_string()]);

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let causal_trace_id = traces
        .records
        .iter()
        .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .find(|event| event.trace_event_id == synced.trace_event_id)
        .map(|event| event.trace_event_id)
        .expect("breaker sync audit trace");

    let action_id = ActionId::new();
    let submit = SubmitActionRequest {
        action_id: Some(action_id.clone()),
        run_id: created.run_id.clone(),
        tenant_id,
        agent_id,
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: Some(causal_trace_id),
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(submit).expect("submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(outcome.action_id, action_id);
    assert_eq!(outcome.status, splendor_gateway::ActionStatus::Denied);
    assert!(outcome
        .verification
        .reasons
        .iter()
        .any(|reason| reason == "circuit_breaker_tripped"));
    assert_eq!(
        outcome
            .verification
            .artifacts
            .get("circuit_breaker")
            .and_then(|value| value.get("circuit_breaker"))
            .and_then(|value| value.get("breaker_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        Some(breaker_id.to_string())
    );
}

#[tokio::test]
async fn create_run_circuit_breaker_denies_runtime_admission_fail_closed() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let mut create = create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    let breaker_id = CircuitBreakerId::try_new("breaker_global_admission").expect("breaker id");
    create.circuit_breakers = vec![CircuitBreaker::tripped(
        breaker_id.clone(),
        CircuitBreakerScope::Global,
        "unit_global_admission",
        OffsetDateTime::now_utc(),
    )
    .expect("global breaker")];
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lifecycle = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: Some("global breaker admission".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, tick): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(lifecycle).expect("start request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tick.status, RunStatus::Running);

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let causal_trace_id = traces.records.first().and_then(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .ok()
            .map(|event| event.trace_event_id)
    });
    let submit = SubmitActionRequest {
        action_id: None,
        run_id: created.run_id,
        tenant_id,
        agent_id,
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: causal_trace_id.clone(),
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app,
        Method::POST,
        "/actions",
        serde_json::to_value(submit).expect("submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(outcome.status, splendor_gateway::ActionStatus::Denied);
    assert!(outcome
        .verification
        .reasons
        .iter()
        .any(|reason| reason == "circuit_breaker_tripped"));
    assert!(outcome
        .verification
        .artifacts
        .to_string()
        .contains(&breaker_id.to_string()));
}

#[tokio::test]
async fn invalid_policy_bundle_is_rejected_before_run_policy_invocation() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let mut create = create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    create.policy_bundle_required = true;

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create.clone()).expect("missing bundle create request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "missing_policy_bundle");

    let mut envelope = signed_policy_bundle(tenant_id, Some(agent_id), RevocationStatus::Active);
    envelope.signature.as_mut().expect("signature").signature = "bad".to_string();
    create.policy_bundle = Some(envelope);

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "bad_policy_signature");

    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let mut malformed = create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    malformed.policy_bundle_required = true;
    let mut envelope = signed_policy_bundle(
        tenant_id.clone(),
        Some(agent_id.clone()),
        RevocationStatus::Active,
    );
    envelope.bundle.schema_version = "splendor.policy_bundle.v0".to_string();
    malformed.policy_bundle = Some(envelope);

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(malformed).expect("malformed create request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "malformed_policy_bundle");

    let mut revoked = create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    revoked.policy_bundle_required = true;
    revoked.policy_bundle = Some(signed_policy_bundle(
        tenant_id,
        Some(agent_id),
        RevocationStatus::Revoked {
            reason: "central_revocation".to_string(),
        },
    ));

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app,
        Method::POST,
        "/runs",
        serde_json::to_value(revoked).expect("revoked create request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "revoked_policy_bundle");
}

#[tokio::test]
async fn revoked_policy_bundle_blocks_existing_side_effects() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let mut create = create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    create.policy_bundle_required = true;
    create.policy_bundle = Some(signed_policy_bundle(
        tenant_id.clone(),
        Some(agent_id.clone()),
        RevocationStatus::Active,
    ));

    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let revoked = PolicySyncRequest {
        credential: None,
        audit_attribution: Some(attribution()),
        policy_bundle: Some(signed_policy_bundle(
            tenant_id.clone(),
            Some(agent_id.clone()),
            RevocationStatus::Revoked {
                reason: "central revocation signature=raw-secret".to_string(),
            },
        )),
        sync_error: None,
        disconnected: None,
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/policies/sync", created.run_id),
        serde_json::to_value(revoked).expect("policy sync request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "revoked_policy_bundle");

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let serialized = serde_json::to_string(&traces.records).expect("serialized traces");
    assert!(!serialized.contains("raw-secret"));
    assert!(!serialized.contains("signature="));
    let causal_trace_id = traces.records.first().and_then(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .ok()
            .map(|event| event.trace_event_id)
    });

    let submit = SubmitActionRequest {
        action_id: None,
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id,
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app,
        Method::POST,
        "/actions",
        serde_json::to_value(submit).expect("submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(outcome.status, splendor_gateway::ActionStatus::Denied);
    assert_eq!(outcome.verification.reasons, vec!["policy_revoked"]);
    assert_eq!(
        outcome.verification.artifacts["reason"].as_str(),
        Some("policy_reason_redacted")
    );
}

#[tokio::test]
async fn legacy_approval_variants_cannot_resume_tick_or_execute_adapter() {
    for scenario in [
        "denied",
        "expired",
        "wrong_tenant",
        "wrong_agent",
        "wrong_run",
        "wrong_action",
        "wrong_action_id",
        "wrong_adapter",
        "incomplete_action_scope",
        "incomplete_adapter_scope",
        "unsupported_schema",
        "revoked",
    ] {
        let app = router(action_test_state());
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let policy_actions = vec![DaemonActionCandidate {
            action_id: None,
            action: action("allowed_action"),
            adapter: Some("daemon.local".to_string()),
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
            requested_at: None,
            authority_obligation_receipts: Vec::new(),
        }];
        let mut create = create_request(
            tenant_id.clone(),
            agent_id.clone(),
            policy_actions,
            Vec::new(),
        );
        create.approval_policies = vec![approval_policy(&tenant_id, &agent_id, "allowed_action")];
        let original_work_order = create.work_order.clone();
        let (status, created): (StatusCode, CreateRunResponse) = call_json(
            app.clone(),
            Method::POST,
            "/runs",
            serde_json::to_value(create).expect("create request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let start = LifecycleRequest {
            credential: None,
            work_order: None,
            audit_attribution: Some(attribution()),
            reason: None,
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        };
        let (status, waiting): (StatusCode, TickResponse) = call_json(
            app.clone(),
            Method::POST,
            &format!("/runs/{}/start", created.run_id),
            serde_json::to_value(start).expect("start request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(waiting.status, RunStatus::WaitingForApproval);
        let paused_state_node_id = waiting.state_node_id.clone();

        let mut evidence = approval_evidence(
            &tenant_id,
            &agent_id,
            &created.run_id,
            "allowed_action",
            ApprovalDecision::Granted,
        );
        match scenario {
            "denied" => evidence.decision = ApprovalDecision::Denied,
            "expired" => {
                evidence.expires_at = OffsetDateTime::now_utc() - time::Duration::minutes(1)
            }
            "wrong_tenant" => evidence.tenant_id = TenantId::new(),
            "wrong_agent" => evidence.agent_id = AgentId::new(),
            "wrong_run" => evidence.run_id = RunId::new(),
            "wrong_action" => evidence.action_name = Some("different_action".to_string()),
            "wrong_action_id" => evidence.action_id = Some(ActionId::new()),
            "wrong_adapter" => evidence.adapter = Some("different_adapter".to_string()),
            "incomplete_action_scope" => {
                evidence.action_id = None;
                evidence.action_name = None;
            }
            "incomplete_adapter_scope" => evidence.adapter = None,
            "unsupported_schema" => {
                assert_eq!(
                    APPROVAL_EVIDENCE_SCHEMA_VERSION,
                    "splendor.approval_evidence.v1"
                );
                evidence.schema_version = "splendor.approval_evidence.v0".to_string();
            }
            "revoked" => evidence.revoked = true,
            _ => unreachable!(),
        }

        let resume = LifecycleRequest {
            credential: None,
            work_order: Some(bind_original_work_order_for_resume(
                original_work_order,
                created.run_id.clone(),
            )),
            audit_attribution: Some(attribution()),
            reason: Some(format!("approval {scenario}")),
            approval_evidence: Some(evidence),
            authority_obligation_receipts: Vec::new(),
        };
        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            app.clone(),
            Method::POST,
            &format!("/runs/{}/resume", created.run_id),
            serde_json::to_value(resume).expect("resume request"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(error.code, "legacy_approval_evidence_non_authorizing");

        let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
            app.clone(),
            Method::GET,
            &format!("/runs/{}", created.run_id),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(inspected.status, RunStatus::WaitingForApproval);
        assert_eq!(inspected.adapter_executions, 0);
        assert_eq!(inspected.ticks, 1);
        assert_eq!(
            inspected.state_head.as_deref(),
            Some(paused_state_node_id.as_str())
        );

        let replay_credential =
            caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::ReplayCreate]);
        let replay_audit = AuditAttribution {
            credential_id: Some(replay_credential.credential_id.clone()),
            ..attribution()
        };
        let (status, replay): (StatusCode, ReplayResponse) = call_json(
            app.clone(),
            Method::POST,
            &format!("/runs/{}/replay", created.run_id),
            json!({"credential": replay_credential, "audit_attribution": replay_audit}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            replay
                .approval_events
                .iter()
                .any(|event| event.lifecycle == "requested"),
            "{scenario} should preserve approval request for replay"
        );
        assert_eq!(
            replay
                .approval_events
                .iter()
                .filter(|event| event.lifecycle == "granted")
                .count(),
            0,
            "{scenario} raw evidence must not create a grant event"
        );
    }
}

#[tokio::test]
async fn create_run_rejects_incompatible_and_duplicate_work_orders() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();

    let mut incompatible =
        create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    incompatible.work_order = signed_work_order(
        tenant_id.clone(),
        AgentId::new(),
        None,
        vec![EndpointScope::RunsCreate],
    );
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(incompatible).expect("incompatible request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "incompatible_work_order");

    let duplicate_run_id = RunId::new();
    let mut duplicate = create_request(tenant_id, agent_id, Vec::new(), Vec::new());
    duplicate.work_order = signed_work_order_with_id(
        "wo_duplicate",
        duplicate.tenant_id.clone(),
        duplicate.agent_id.clone(),
        Some(duplicate_run_id.clone()),
    );
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(duplicate.clone()).expect("duplicate request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created.run_id, duplicate_run_id);

    let mut duplicate_different_key = duplicate;
    duplicate_different_key.request_id = format!("req_{}", TraceId::new());
    duplicate_different_key.idempotency_key = format!("idem_{}", TraceId::new());
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app,
        Method::POST,
        "/runs",
        serde_json::to_value(duplicate_different_key).expect("second duplicate request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "run_already_exists");
}

#[tokio::test]
async fn create_run_raw_credential_rejection_precedes_idempotency_run_state_and_trace() {
    const CANARY: &str = "C03_CREATE_RUN_RAW_CREDENTIAL_CANARY";

    let trace_store = Arc::new(InMemoryTraceStore::default());
    let app = router(support::state_with_trace_store(
        DaemonConfig::local_dev(),
        trace_store.clone(),
        &["daemon.local"],
    ));
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let fixed_run_id = RunId::new();
    let mut request = create_request(
        tenant_id,
        agent_id,
        vec![DaemonActionCandidate {
            action_id: Some(ActionId::new()),
            action: Action {
                params: json!({"nested": [{"authKey": CANARY}]}),
                ..action("allowed_action")
            },
            adapter: Some("daemon.local".to_string()),
            quota_usage: Some(QuotaUsage::single_action()),
            satisfied_preconditions: Vec::new(),
            requested_at: None,
            authority_obligation_receipts: Vec::new(),
        }],
        Vec::new(),
    );
    request.idempotency_key = "idem_c03_raw_credential_rejection".to_string();
    request.work_order.work_order.run_id = Some(fixed_run_id.clone());
    resign_work_order(&mut request.work_order);

    for attempt in 0..2 {
        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            app.clone(),
            Method::POST,
            "/runs",
            serde_json::to_value(request.clone()).expect("raw create request"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "attempt {attempt}");
        assert_eq!(
            error.code,
            splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED,
            "attempt {attempt}"
        );
        assert_eq!(
            error.message,
            splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED,
            "attempt {attempt}"
        );
        assert!(error.details.is_null());
        assert!(!serde_json::to_string(&error)
            .expect("error serializes")
            .contains(CANARY));
    }

    for (label, params) in [
        ("x_auth_token", json!({"X-Auth-Token": CANARY})),
        ("private_token", json!({"Private-Token": CANARY})),
        ("vault_token", json!({"VAULT_TOKEN": CANARY})),
        ("consul_token", json!({"CONSUL_HTTP_TOKEN": CANARY})),
        ("secret_key_ref", json!({"secretKeyRef": {"name": CANARY}})),
        (
            "presigned_query",
            json!({"url": format!("https://example.invalid/?X-Amz-Signature={CANARY}")}),
        ),
        (
            "encoded_path_ref",
            json!({"url": "https://example.invalid/%76ault%3Ateam%2Fservice"}),
        ),
        (
            "nested_query_url",
            json!({"url": "https://example.invalid/redirect?target=https%3A%2F%2Fuser%3Apass%40nested.invalid"}),
        ),
        (
            "short_basic_form",
            json!({"url": "https://example.invalid/form?value=Basic+dTpw"}),
        ),
        (
            "standalone_basic_form",
            json!({"body": "safe=1&value=Basic+dTpw"}),
        ),
        (
            "structured_environment_coordinate",
            json!({"json": {"name": "VAULT_TOKEN", "value": CANARY}}),
        ),
        ("bom_prefixed_basic", json!({"body": "\u{feff}Basic dTpw"})),
        (
            "nul_interleaved_bearer",
            json!({"contents": "B\0e\0a\0r\0e\0r\0 \0x\0"}),
        ),
        (
            "encoded_credential_before_url",
            json!({"input": "Bearer%20x see https://example.invalid/docs"}),
        ),
        (
            "structured_form_coordinate",
            json!({"body": "name=VAULT_TOKEN&value=synthetic"}),
        ),
        (
            "encoded_credential_adjacent_url",
            json!({"body": "Bearer%20x,https://example.invalid/docs"}),
        ),
        (
            "percent_encoded_bom_form",
            json!({"body": "value=%EF%BB%BFBasic%20dTpw"}),
        ),
        (
            "percent_encoded_nul_form",
            json!({"body": "value=B%00e%00a%00r%00e%00r%00%20x"}),
        ),
        ("pipe_delimited_bearer", json!({"body": "safe|Bearer x"})),
        (
            "backtick_delimited_bearer",
            json!({"body": "safe`Bearer x`"}),
        ),
        (
            "unicode_delimited_bearer",
            json!({"body": "safe—Bearer x—"}),
        ),
        (
            "common_structured_password",
            json!({"json": {"key": "password", "value": CANARY}}),
        ),
        (
            "bare_encoded_query_content",
            json!({"url": "https://example.invalid/?%42earer%20x"}),
        ),
        (
            "punctuated_encoded_url_path",
            json!({"url": "https://example.invalid/safe.Bearer%20x"}),
        ),
        (
            "encoded_provider_in_url_authority",
            json!({
                "url": format!(
                    "https://sink-%41KIA{}.attacker.invalid/",
                    "1".repeat(16)
                )
            }),
        ),
        (
            "basic_prefix_before_path_separator",
            json!({"url": "https://example.invalid/Basic%20dTpw/next"}),
        ),
        (
            "maximum_provider_prefix_before_alphabet_punctuation",
            json!({"body": format!("github_pat_{}-tail", "A".repeat(256))}),
        ),
        (
            "url_followed_by_numeric_credential_assignment",
            json!({"body": "https://example.invalid password:1234"}),
        ),
        (
            "encoded_authority_separator_before_numeric_credential_assignment",
            json!({"url": "https://example.invalid%20password:1234/path"}),
        ),
        (
            "encoded_closing_delimiter_before_numeric_credential_assignment",
            json!({"url": "https://example.invalid%5Dtoken:8443/path"}),
        ),
        (
            "credential_named_invalid_ip_literal",
            json!({"url": "https://[password]:1234/path"}),
        ),
        (
            "out_of_range_authority_port",
            json!({"url": "https://example.invalid:99999/path"}),
        ),
        (
            "authority_subdelimiter_before_credential_assignment",
            json!({"url": "https://example.invalid$password:1234/path"}),
        ),
        (
            "encoded_authority_colon_before_password_assignment",
            json!({"url": "https://password%3A1234/path"}),
        ),
        (
            "encoded_authority_colon_before_secret_reference",
            json!({"url": "https://vault%3A8200/path"}),
        ),
        (
            "encoded_host_and_authority_colon_before_password_assignment",
            json!({"url": "https://%70assword%3A1234/path"}),
        ),
        (
            "encoded_ip_literal_port_separator",
            json!({"url": "https://[::1]%3A8443/path"}),
        ),
    ] {
        request.policy_actions[0].action.params = params;
        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            app.clone(),
            Method::POST,
            "/runs",
            serde_json::to_value(request.clone()).expect("raw create request variant"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
        assert_eq!(
            error.code,
            splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED,
            "{label}"
        );
        assert!(error.details.is_null(), "{label}");
        assert!(!serde_json::to_string(&error)
            .expect("error serializes")
            .contains(CANARY));
        assert!(matches!(
            trace_store.read(&fixed_run_id.to_string()),
            Err(TraceStoreError::RunNotFound)
        ));
    }

    request.policy_actions[0].action.name = "alternate_http_post".to_string();
    request.policy_actions[0].action.side_effect_class = SideEffectClass::ReadOnly;
    request.policy_actions[0].adapter = Some("http".to_string());
    request.policy_actions[0].action.params = json!({
        "bytes": "Bearer x"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    });
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(request.clone()).expect("alternate routed byte request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED);
    assert!(matches!(
        trace_store.read(&fixed_run_id.to_string()),
        Err(TraceStoreError::RunNotFound)
    ));

    let (status, missing): (StatusCode, ApiErrorBody) =
        call_empty(app.clone(), Method::GET, &format!("/runs/{fixed_run_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing.code, "invalid_run");
    assert!(matches!(
        trace_store.read(&fixed_run_id.to_string()),
        Err(TraceStoreError::RunNotFound)
    ));

    request.policy_actions[0].action = action("allowed_action");
    request.policy_actions[0].action.params = json!({"resource_ref": "fixture:report"});
    request.policy_actions[0].adapter = Some("daemon.local".to_string());
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app,
        Method::POST,
        "/runs",
        serde_json::to_value(request).expect("credential-free create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created.run_id, fixed_run_id);
    assert!(!created.duplicate);
    let persisted = trace_store
        .read(&fixed_run_id.to_string())
        .expect("safe run traces");
    assert!(!serde_json::to_string(&persisted)
        .expect("persisted traces serialize")
        .contains(CANARY));
}

#[tokio::test]
async fn configured_receipt_strings_are_rejected_before_fingerprint_run_state_and_trace() {
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let app = router(support::state_with_trace_store(
        DaemonConfig::local_dev(),
        trace_store.clone(),
        &["daemon.local"],
    ));
    let fixed_run_id = RunId::new();
    let mut request = create_request(
        TenantId::new(),
        AgentId::new(),
        vec![DaemonActionCandidate {
            action_id: Some(ActionId::new()),
            action: action("allowed_action"),
            adapter: Some("daemon.local".to_string()),
            quota_usage: Some(QuotaUsage::single_action()),
            satisfied_preconditions: Vec::new(),
            requested_at: None,
            authority_obligation_receipts: Vec::new(),
        }],
        Vec::new(),
    );
    request.idempotency_key = "idem_c03_receipt_screening".to_string();
    request.work_order.work_order.run_id = Some(fixed_run_id.clone());
    resign_work_order(&mut request.work_order);

    for field in [
        "schema_version",
        "audience",
        "canonical_request_digest",
        "evidence_digest",
        "evidence_ref",
        "revocation_reason",
        "revocation_ref",
        "algorithm",
        "key_id",
        "validation_digest",
        "signature",
    ] {
        let canary = format!("C03_RECEIPT_{}_CANARY", field.to_ascii_uppercase());
        let credential_value =
            format!("https://example.invalid/form?value=Basic+dTpw&label={canary}");
        let mut receipt = ordinary_unvalidated_obligation_receipt();
        match field {
            "schema_version" => receipt.schema_version = credential_value.clone(),
            "audience" => receipt.audience = credential_value.clone(),
            "canonical_request_digest" => {
                receipt.canonical_request_digest = credential_value.clone()
            }
            "evidence_digest" => receipt.evidence_digest = credential_value.clone(),
            "evidence_ref" => receipt.evidence_ref = Some(credential_value.clone()),
            "revocation_reason" => {
                receipt.revocation = RevocationStatus::Revoked {
                    reason: credential_value.clone(),
                }
            }
            "revocation_ref" => receipt.revocation_ref = credential_value.clone(),
            "algorithm" => receipt.validation.algorithm = credential_value.clone(),
            "key_id" => receipt.validation.key_id = credential_value.clone(),
            "validation_digest" => receipt.validation.digest = credential_value.clone(),
            "signature" => receipt.validation.signature = credential_value.clone(),
            _ => unreachable!("closed receipt field matrix"),
        }
        request.policy_actions[0].authority_obligation_receipts = vec![receipt];

        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            app.clone(),
            Method::POST,
            "/runs",
            serde_json::to_value(request.clone()).expect("receipt-bearing create request"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field}");
        assert_eq!(error.code, splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED);
        assert_eq!(error.message, splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED);
        assert!(error.details.is_null());
        assert!(!serde_json::to_string(&error)
            .expect("error serializes")
            .contains(&canary));

        let (status, missing): (StatusCode, ApiErrorBody) =
            call_empty(app.clone(), Method::GET, &format!("/runs/{fixed_run_id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{field}");
        assert_eq!(missing.code, "invalid_run", "{field}");
        assert!(matches!(
            trace_store.read(&fixed_run_id.to_string()),
            Err(TraceStoreError::RunNotFound)
        ));
    }

    request.policy_actions[0]
        .authority_obligation_receipts
        .clear();
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app,
        Method::POST,
        "/runs",
        serde_json::to_value(request).expect("credential-free create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created.run_id, fixed_run_id);
    assert!(!created.duplicate);
    let persisted = trace_store
        .read(&fixed_run_id.to_string())
        .expect("safe run traces");
    assert!(!serde_json::to_string(&persisted)
        .expect("persisted traces serialize")
        .contains("C03_RECEIPT_"));
}

#[tokio::test]
async fn create_run_idempotency_replays_same_scope_receipt_without_duplicate_work() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let run_id = RunId::new();
    let mut request = create_request(tenant_id, agent_id, Vec::new(), Vec::new());
    request.request_id = "req_create_run_idempotent".to_string();
    request.idempotency_key = "idem_create_run_idempotent".to_string();
    request.work_order = signed_work_order_with_id(
        "wo_create_run_idempotent",
        request.tenant_id.clone(),
        request.agent_id.clone(),
        Some(run_id.clone()),
    );

    let (status, first): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(request.clone()).expect("first idempotent create"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first.run_id, run_id);
    assert!(!first.duplicate);

    let (status, duplicate): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(request).expect("duplicate idempotent create"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(duplicate.run_id, first.run_id);
    assert_eq!(duplicate.status, first.status);
    assert_eq!(duplicate.request_id, first.request_id);
    assert_eq!(duplicate.idempotency_key, first.idempotency_key);
    assert_eq!(
        duplicate.idempotency_receipt_id,
        first.idempotency_receipt_id
    );
    assert!(duplicate.duplicate);

    let (status, trace_page): (StatusCode, TracePageResponse) = call_empty(
        app,
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", first.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let audit_endpoints: Vec<_> = trace_page
        .records
        .iter()
        .filter_map(|record| {
            record
                .payload
                .pointer("/kind/DaemonAudit/endpoint")
                .and_then(Value::as_str)
        })
        .collect();
    assert!(audit_endpoints.contains(&"splendor.runs.create"));
    assert!(audit_endpoints.contains(&"splendor.runs.create.idempotent_duplicate"));
    assert_eq!(
        audit_endpoints
            .iter()
            .filter(|endpoint| **endpoint == "splendor.runs.create")
            .count(),
        1,
        "duplicate idempotency retry must not record a second create mutation"
    );
}

#[tokio::test]
async fn create_run_idempotency_scope_mismatch_and_missing_fields_fail_closed() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let first_run_id = RunId::new();
    let mut first = create_request(tenant_id, agent_id, Vec::new(), Vec::new());
    first.request_id = "req_first_scope".to_string();
    first.idempotency_key = "idem_scope_collision".to_string();
    first.work_order = signed_work_order_with_id(
        "wo_scope_a",
        first.tenant_id.clone(),
        first.agent_id.clone(),
        Some(first_run_id.clone()),
    );
    let mut caller_mismatch = first.clone();
    caller_mismatch.request_id = "req_second_caller_scope".to_string();
    caller_mismatch.audit_attribution = Some(AuditAttribution {
        principal: ClientPrincipal::new("app_other", "client_other"),
        credential_id: Some("cred_other".to_string()),
        requested_at: OffsetDateTime::now_utc(),
    });
    let first_tenant_id = first.tenant_id.to_string();
    let first_agent_id = first.agent_id.to_string();
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(first).expect("first scoped create"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(caller_mismatch).expect("caller scope mismatch create"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "create_run_idempotency_scope_mismatch");
    assert_eq!(
        error.details,
        json!({"scope_mismatch": true, "category": "create_run_idempotency"})
    );
    let details_text = error.details.to_string();
    for forbidden in [
        "attempted_scope".to_string(),
        "existing_scope".to_string(),
        "tenant_id".to_string(),
        "agent_id".to_string(),
        "work_order_id".to_string(),
        "resolved_run_id".to_string(),
        "caller".to_string(),
        "request_fingerprint".to_string(),
        "app_other".to_string(),
        "client_other".to_string(),
        "cred_other".to_string(),
        first_tenant_id,
        first_agent_id,
        "wo_scope_a".to_string(),
        first_run_id.to_string(),
        created.run_id.to_string(),
    ] {
        assert!(
            !details_text.contains(&forbidden),
            "scope mismatch details leaked sensitive scope field/value: {forbidden}"
        );
    }

    let second_run_id = RunId::new();
    let mut second = create_request(TenantId::new(), AgentId::new(), Vec::new(), Vec::new());
    second.request_id = "req_second_scope".to_string();
    second.idempotency_key = "idem_scope_collision".to_string();
    second.work_order = signed_work_order_with_id(
        "wo_scope_b",
        second.tenant_id.clone(),
        second.agent_id.clone(),
        Some(second_run_id.clone()),
    );
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(second).expect("scope mismatch create"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "create_run_idempotency_scope_mismatch");
    assert_eq!(
        error.details,
        json!({"scope_mismatch": true, "category": "create_run_idempotency"})
    );
    let (status, missing_second): (StatusCode, ApiErrorBody) =
        call_empty(app.clone(), Method::GET, &format!("/runs/{second_run_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing_second.code, "invalid_run");

    let mut blank = create_request(TenantId::new(), AgentId::new(), Vec::new(), Vec::new());
    let blank_run_id = RunId::new();
    blank.work_order = signed_work_order_with_id(
        "wo_blank_idempotency",
        blank.tenant_id.clone(),
        blank.agent_id.clone(),
        Some(blank_run_id.clone()),
    );
    blank.idempotency_key = " ".to_string();
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(blank).expect("blank idempotency request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "missing_idempotency_key");
    let (status, missing_blank): (StatusCode, ApiErrorBody) =
        call_empty(app.clone(), Method::GET, &format!("/runs/{blank_run_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(missing_blank.code, "invalid_run");

    let mut missing = serde_json::to_value(create_request(
        TenantId::new(),
        AgentId::new(),
        Vec::new(),
        Vec::new(),
    ))
    .expect("missing request body");
    missing
        .as_object_mut()
        .expect("object")
        .remove("request_id");
    let (status, original): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(original.status, RunStatus::Pending);
    let missing_status = call_status(app, Method::POST, "/runs", missing).await;
    assert!(
        missing_status.is_client_error(),
        "missing request_id should fail during extraction/validation"
    );
}

#[tokio::test]
async fn create_run_rejects_invalid_work_orders_and_request_scope_widening() {
    let app = router(DaemonState::local_dev());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();

    let unsigned_run_id = RunId::new();
    let mut unsigned = create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    unsigned.work_order.work_order.run_id = Some(unsigned_run_id.clone());
    resign_work_order(&mut unsigned.work_order);
    unsigned.work_order.signature = None;
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(unsigned).expect("unsigned request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "unsigned_work_order");
    let (status, error): (StatusCode, ApiErrorBody) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{unsigned_run_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error.code, "invalid_run");

    let bad_signature_run_id = RunId::new();
    let mut bad_signature =
        create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    bad_signature.work_order.work_order.run_id = Some(bad_signature_run_id.clone());
    resign_work_order(&mut bad_signature.work_order);
    bad_signature
        .work_order
        .signature
        .as_mut()
        .expect("signature")
        .signature = "bad-signature".to_string();
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(bad_signature).expect("bad signature request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "bad_signature");
    let (status, error): (StatusCode, ApiErrorBody) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{bad_signature_run_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error.code, "invalid_run");

    let expired_run_id = RunId::new();
    let mut expired = create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    expired.work_order.work_order.run_id = Some(expired_run_id.clone());
    expired.work_order.work_order.expires_at =
        OffsetDateTime::now_utc() - time::Duration::minutes(1);
    resign_work_order(&mut expired.work_order);
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(expired).expect("expired request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "expired_work_order");

    let revoked_run_id = RunId::new();
    let mut revoked = create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    revoked.work_order.work_order.run_id = Some(revoked_run_id.clone());
    revoked.work_order.work_order.revocation = RevocationStatus::Revoked {
        reason: "operator".to_string(),
    };
    resign_work_order(&mut revoked.work_order);
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(revoked).expect("revoked request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "revoked_work_order");

    let mut widened_action =
        create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    widened_action
        .allowed_actions
        .push("extra_action".to_string());
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(widened_action).expect("widened action request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "work_order_scope_widening");

    let mut widened_adapter =
        create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    widened_adapter
        .allowed_adapters
        .push("extra.adapter".to_string());
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(widened_adapter).expect("widened adapter request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "work_order_scope_widening");

    let mut widened_permission =
        create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    widened_permission
        .allowed_permissions
        .push("extra.permission".to_string());
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(widened_permission).expect("widened permission request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "work_order_permission_profile_mismatch");

    let mut widened_policy = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        vec![DaemonActionCandidate {
            action_id: None,
            action: action("extra_action"),
            adapter: Some("daemon.local".to_string()),
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
            requested_at: None,
            authority_obligation_receipts: Vec::new(),
        }],
        Vec::new(),
    );
    widened_policy.allowed_actions.clear();
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(widened_policy).expect("widened policy request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "work_order_scope_widening");

    let mut widened_policy_adapter = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        vec![DaemonActionCandidate {
            action_id: None,
            action: action("allowed_action"),
            adapter: Some("extra.adapter".to_string()),
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
            requested_at: None,
            authority_obligation_receipts: Vec::new(),
        }],
        Vec::new(),
    );
    widened_policy_adapter.allowed_actions.clear();
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(widened_policy_adapter).expect("widened policy adapter request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "work_order_scope_widening");

    let mut action_with_permission = action("allowed_action");
    action_with_permission.required_permissions = vec!["extra.permission".to_string()];
    let mut widened_policy_permission = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        vec![DaemonActionCandidate {
            action_id: None,
            action: action_with_permission,
            adapter: Some("daemon.local".to_string()),
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
            requested_at: None,
            authority_obligation_receipts: Vec::new(),
        }],
        Vec::new(),
    );
    widened_policy_permission.allowed_actions.clear();
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(widened_policy_permission).expect("widened policy permission request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "work_order_scope_widening");

    let mut widened_registration_name = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        Vec::new(),
        vec![RegisteredAction {
            name: "extra_action".to_string(),
            adapter: "daemon.local".to_string(),
            required_permissions: Some(Vec::new()),
        }],
    );
    widened_registration_name.allowed_actions.clear();
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(widened_registration_name).expect("widened registration name request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "work_order_scope_widening");

    let mut widened_registration = create_request(
        tenant_id,
        agent_id,
        Vec::new(),
        vec![RegisteredAction {
            name: "allowed_action".to_string(),
            adapter: "extra.adapter".to_string(),
            required_permissions: Some(Vec::new()),
        }],
    );
    widened_registration.allowed_actions.clear();
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app,
        Method::POST,
        "/runs",
        serde_json::to_value(widened_registration).expect("widened registration request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "work_order_scope_widening");
}

#[tokio::test]
async fn action_endpoint_uses_gateway_and_returns_structured_denial() {
    let state = action_test_state();
    let app = router(state);
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let create = create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lifecycle = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, _tick): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(lifecycle).expect("start request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let mut denied_action = action("allowed_action");
    denied_action.required_permissions = vec!["not.allowed".to_string()];

    let unlinked_submit = SubmitActionRequest {
        action_id: None,
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: None,
        action: denied_action.clone(),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(unlinked_submit).expect("unlinked submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "action_missing_trace_link");

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let causal_trace_id = traces.records.first().and_then(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .ok()
            .map(|event| event.trace_event_id)
    });

    let submit = SubmitActionRequest {
        action_id: None,
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: causal_trace_id.clone(),
        action: denied_action,
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(submit.clone()).expect("submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(outcome.status, splendor_gateway::ActionStatus::Denied);
    assert!(outcome
        .verification
        .reasons
        .iter()
        .any(|reason| reason == "trusted_action_profile_permission_mismatch"));
    let disallowed_submit = SubmitActionRequest {
        action_id: None,
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id,
        action: action("outside_work_order"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(disallowed_submit).expect("disallowed submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(outcome.status, splendor_gateway::ActionStatus::Denied);
    assert!(outcome
        .verification
        .reasons
        .iter()
        .any(|reason| reason == "trusted_action_profile_missing"));
    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app,
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let saw_action_audit = traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| {
                matches!(
                    event.kind,
                    TraceEventKind::DaemonAudit { ref endpoint, ref audit }
                        if endpoint == "splendor.actions.submit" && audit.principal == principal()
                )
            })
            .unwrap_or(false)
    });
    assert!(
        saw_action_audit,
        "action submit must persist caller attribution"
    );
}

#[tokio::test]
async fn action_endpoint_uses_owner_profile_for_opaque_filesystem_bytes_only() {
    let adapter_calls = Arc::new(AtomicUsize::new(0));
    let mut adapters = ConfiguredActionAdapters::new();
    adapters
        .insert(
            "filesystem",
            Arc::new(FixedOutputAdapter {
                calls: Arc::clone(&adapter_calls),
                output: json!({"status": "written"}),
            }),
        )
        .expect("filesystem adapter");
    let state = DaemonState::with_action_adapters(DaemonConfig::local_dev(), adapters);
    let app = router(state);
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let mut create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        Vec::new(),
        vec![RegisteredAction {
            name: "write_file".to_string(),
            adapter: "filesystem".to_string(),
            required_permissions: Some(Vec::new()),
        }],
    );
    create.allowed_actions = vec!["write_file".to_string()];
    create.allowed_adapters = vec!["filesystem".to_string()];
    create.work_order.work_order.allowed_actions = vec!["write_file".to_string()];
    create.work_order.work_order.allowed_adapters = vec!["filesystem".to_string()];
    resign_work_order(&mut create.work_order);
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lifecycle = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, _tick): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(lifecycle).expect("start request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let causal_trace_id = traces
        .records
        .first()
        .and_then(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .map(|event| event.trace_event_id)
        .expect("causal trace");
    let opaque_action = Action {
        name: "write_file".to_string(),
        params: json!({"path": "opaque.bin", "bytes": [0, 65, 255]}),
        side_effect_class: SideEffectClass::Filesystem,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    };
    let submit = SubmitActionRequest {
        action_id: None,
        run_id: created.run_id,
        tenant_id,
        agent_id,
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: Some(causal_trace_id),
        action: opaque_action,
        adapter: None,
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };

    let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(&submit).expect("opaque action"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        outcome.status,
        splendor_gateway::ActionStatus::Executed,
        "{outcome:?}"
    );
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 1);

    for (case, adapter, bytes) in [
        ("spoofed_adapter", Some("daemon.local"), vec![0, 65, 255]),
        ("credential_bytes", None, b"Bearer short".to_vec()),
    ] {
        let mut rejected = submit.clone();
        rejected.action_id = None;
        rejected.adapter = adapter.map(str::to_string);
        rejected.action.params = json!({"path": "opaque.bin", "bytes": bytes});
        let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
            app.clone(),
            Method::POST,
            "/actions",
            serde_json::to_value(rejected).expect("rejected action"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{case}");
        assert_eq!(
            outcome.status,
            splendor_gateway::ActionStatus::Denied,
            "{case}"
        );
        assert_eq!(outcome.error.as_deref(), Some(RAW_CREDENTIAL_INPUT_DENIED));
        assert_eq!(adapter_calls.load(Ordering::SeqCst), 1, "{case}");
    }
}

#[tokio::test]
async fn active_run_raw_approval_evidence_is_rejected_before_trace_or_lifecycle_mutation() {
    let state = action_test_state();
    let app = router(state);
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let create = create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let trace_page: TracePageResponse = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=redacted", created.run_id),
    )
    .await
    .1;
    let causal_trace_id = trace_page
        .records
        .first()
        .and_then(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .map(|event| event.trace_event_id)
        .expect("causal trace");
    let baseline_trace_count = trace_page.records.len();

    for (decision, expired, revoked) in [
        (ApprovalDecision::Granted, false, false),
        (ApprovalDecision::Denied, false, false),
        (ApprovalDecision::Granted, true, false),
        (ApprovalDecision::Granted, false, true),
    ] {
        let mut evidence = approval_evidence(
            &tenant_id,
            &agent_id,
            &created.run_id,
            "allowed_action",
            decision.clone(),
        );
        if expired {
            evidence.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);
            evidence.issued_at = evidence.expires_at - time::Duration::seconds(1);
        }
        evidence.revoked = revoked;
        let action_id = ActionId::new();
        evidence.action_id = Some(action_id.clone());
        let submit = SubmitActionRequest {
            action_id: Some(action_id),
            run_id: created.run_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            credential: None,
            audit_attribution: Some(attribution()),
            causal_trace_id: Some(causal_trace_id.clone()),
            action: action("allowed_action"),
            adapter: Some("daemon.local".to_string()),
            quota_usage: Some(splendor_types::QuotaUsage::single_action()),
            satisfied_preconditions: Vec::new(),
            requested_at: Some(OffsetDateTime::now_utc()),
            approval_evidence: Some(evidence),
            authority_obligation_receipts: Vec::new(),
        };
        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            app.clone(),
            Method::POST,
            "/actions",
            serde_json::to_value(submit).expect("raw evidence request"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            error.code,
            if decision == ApprovalDecision::Granted {
                "legacy_approval_evidence_non_authorizing"
            } else {
                "approval_challenge_retry_mismatch"
            }
        );
        let inspected: RunInspectResponse = call_empty(
            app.clone(),
            Method::GET,
            &format!("/runs/{}", created.run_id),
        )
        .await
        .1;
        assert_eq!(inspected.status, RunStatus::Pending);
        assert_eq!(inspected.adapter_executions, 0);
        let traces: TracePageResponse = call_empty(
            app.clone(),
            Method::GET,
            &format!("/runs/{}/traces?redaction_policy=redacted", created.run_id),
        )
        .await
        .1;
        assert_eq!(traces.records.len(), baseline_trace_count);
    }
}

#[tokio::test]
async fn action_endpoint_traces_approval_lifecycles_without_adapter_bypass() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let mut create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        Vec::new(),
        vec![RegisteredAction {
            name: "allowed_action".to_string(),
            adapter: "daemon.local".to_string(),
            required_permissions: Some(Vec::new()),
        }],
    );
    create.approval_policies = vec![approval_policy(&tenant_id, &agent_id, "allowed_action")];
    let original_work_order = create.work_order.clone();
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let causal_trace_id = traces.records.first().and_then(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .ok()
            .map(|event| event.trace_event_id)
    });

    let action_id = ActionId::new();
    let requested_at = OffsetDateTime::now_utc();
    let approval_required = SubmitActionRequest {
        action_id: Some(action_id.clone()),
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: causal_trace_id.clone(),
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: Some(requested_at),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(&approval_required).expect("approval submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        outcome.status,
        splendor_gateway::ActionStatus::NeedsApproval
    );
    let challenge = outcome
        .approval_challenge
        .clone()
        .expect("exact authority-owned approval challenge");
    assert_eq!(challenge.action_id, action_id);
    assert_eq!(challenge.requested_at, requested_at);
    let (status, duplicate_waiting): (StatusCode, Value) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(&approval_required).expect("duplicate approval request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(duplicate_waiting["code"], "action_id_conflict");
    assert_eq!(duplicate_waiting["details"]["retryable"], false);

    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.status, RunStatus::WaitingForApproval);
    assert_eq!(inspected.adapter_executions, 0);
    assert_eq!(inspected.ticks, 0);
    assert!(inspected.state_head.is_none());

    let mut forged_legacy_grant = approval_evidence(
        &tenant_id,
        &agent_id,
        &created.run_id,
        "allowed_action",
        ApprovalDecision::Granted,
    );
    forged_legacy_grant.action_id = Some(action_id.clone());
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(SubmitActionRequest {
            action_id: Some(action_id.clone()),
            run_id: created.run_id.clone(),
            tenant_id: tenant_id.clone(),
            agent_id: agent_id.clone(),
            credential: None,
            audit_attribution: Some(attribution()),
            causal_trace_id: causal_trace_id.clone(),
            action: action("allowed_action"),
            adapter: Some("daemon.local".to_string()),
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
            requested_at: Some(requested_at),
            approval_evidence: Some(forged_legacy_grant.clone()),
            authority_obligation_receipts: Vec::new(),
        })
        .expect("waiting direct approval request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "legacy_approval_evidence_non_authorizing");

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(LifecycleRequest {
            credential: None,
            work_order: Some(bind_original_work_order_for_resume(
                original_work_order.clone(),
                created.run_id.clone(),
            )),
            audit_attribution: Some(attribution()),
            reason: Some("legacy evidence retry".to_string()),
            approval_evidence: Some(forged_legacy_grant.clone()),
            authority_obligation_receipts: Vec::new(),
        })
        .expect("legacy approval resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "legacy_approval_evidence_non_authorizing");

    let (status, inspected_after_legacy): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected_after_legacy.status, RunStatus::WaitingForApproval);
    assert_eq!(inspected_after_legacy.ticks, 0);
    assert!(inspected_after_legacy.state_head.is_none());
    assert_eq!(inspected_after_legacy.adapter_executions, 0);

    let receipt = local_approval_receipt_config()
        .issue_approval_receipt(&challenge, TraceEventId::new(), OffsetDateTime::now_utc())
        .expect("trusted approval receipt");
    let (status, traces_before_wrong_endpoint): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let action_starts_before_wrong_endpoint = traces_before_wrong_endpoint
        .records
        .iter()
        .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .filter(|event| {
            event.identity.action_id.as_ref() == Some(&action_id)
                && matches!(event.kind, TraceEventKind::ActionVerificationStarted { .. })
        })
        .count();
    assert_eq!(action_starts_before_wrong_endpoint, 1);
    let mut wrong_endpoint_action = approval_required.clone();
    wrong_endpoint_action.authority_obligation_receipts = vec![receipt.clone()];
    let (status, wrong_endpoint): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/devices/{}/actions", NodeId::new()),
        serde_json::to_value(SubmitPhysicalActionRequest {
            action_request: wrong_endpoint_action,
            safety_context: safe_physical_context(),
            operator_intervention_evidence: None,
        })
        .expect("wrong physical endpoint retry"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(wrong_endpoint.code, "action_id_conflict");
    let (status, still_waiting): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(still_waiting.status, RunStatus::WaitingForApproval);
    assert_eq!(still_waiting.adapter_executions, 0);
    let (status, traces_after_wrong_endpoint): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        traces_after_wrong_endpoint
            .records
            .iter()
            .filter_map(|record| {
                serde_json::from_value::<TraceEvent>(record.payload.clone()).ok()
            })
            .filter(|event| {
                event.identity.action_id.as_ref() == Some(&action_id)
                    && matches!(event.kind, TraceEventKind::ActionVerificationStarted { .. })
            })
            .count(),
        action_starts_before_wrong_endpoint,
        "endpoint mismatch must not open another action episode"
    );

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(LifecycleRequest {
            credential: None,
            work_order: Some(bind_original_work_order_for_resume(
                original_work_order,
                created.run_id.clone(),
            )),
            audit_attribution: Some(attribution()),
            reason: Some("trusted approval receipt issued".to_string()),
            approval_evidence: None,
            authority_obligation_receipts: vec![receipt.clone()],
        })
        .expect("receipt approval resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "approval_receipt_resume_not_supported");

    let mut approval_granted = approval_required;
    approval_granted.authority_obligation_receipts = vec![receipt];
    let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(approval_granted.clone()).expect("receipt approval submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(outcome.status, splendor_gateway::ActionStatus::Executed);
    let (status, conflict): (StatusCode, Value) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(approval_granted).expect("duplicate receipt submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict["code"], "action_id_conflict");
    assert_eq!(conflict["details"]["retryable"], false);

    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.adapter_executions, 1);
    assert_eq!(inspected.status, RunStatus::Running);
    assert_eq!(inspected.ticks, 0);
    assert!(inspected.state_head.is_none());

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = traces
        .records
        .iter()
        .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .collect::<Vec<_>>();
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ApprovalRequested { .. })));
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ApprovalGranted { .. })));
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ActionNeedsApproval { .. })));
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event.identity.action_id.as_ref() == Some(&action_id)
                    && matches!(event.kind, TraceEventKind::ActionVerificationStarted { .. })
            })
            .count(),
        2,
        "challenge replay and completed retry must create exactly two action episodes"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, TraceEventKind::RunResumed { .. }))
            .count(),
        1
    );

    let replay_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::ReplayCreate]);
    let replay_audit = AuditAttribution {
        credential_id: Some(replay_credential.credential_id.clone()),
        ..attribution()
    };
    let (status, replay): (StatusCode, ReplayResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({"credential": replay_credential, "audit_attribution": replay_audit}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(replay
        .approval_events
        .iter()
        .any(|event| event.lifecycle == "requested"));
    assert!(replay
        .approval_events
        .iter()
        .any(|event| event.lifecycle == "granted"));

    let expired_tenant_id = TenantId::new();
    let expired_agent_id = AgentId::new();
    let mut expired_create = create_request(
        expired_tenant_id.clone(),
        expired_agent_id.clone(),
        Vec::new(),
        vec![RegisteredAction {
            name: "allowed_action".to_string(),
            adapter: "daemon.local".to_string(),
            required_permissions: Some(Vec::new()),
        }],
    );
    let mut expired_policy =
        approval_policy(&expired_tenant_id, &expired_agent_id, "allowed_action");
    expired_policy.expires_at = Some(OffsetDateTime::now_utc() - time::Duration::minutes(1));
    expired_create.approval_policies = vec![expired_policy];
    let (status, expired_created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(expired_create).expect("expired create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, expired_traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!(
            "/runs/{}/traces?redaction_policy=none",
            expired_created.run_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let expired_causal_trace_id = expired_traces.records.first().and_then(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .ok()
            .map(|event| event.trace_event_id)
    });
    let expired_submit = SubmitActionRequest {
        action_id: None,
        run_id: expired_created.run_id.clone(),
        tenant_id: expired_tenant_id,
        agent_id: expired_agent_id,
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: expired_causal_trace_id,
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(expired_submit).expect("expired submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        outcome.status,
        splendor_gateway::ActionStatus::NeedsIntervention
    );
    assert!(
        outcome
            .verification
            .reasons
            .iter()
            .any(|reason| reason == "approval_policy_expired"),
        "{:?}",
        outcome.verification.reasons
    );

    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", expired_created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.status, RunStatus::Failed);
    assert_eq!(inspected.adapter_executions, 0);
    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app,
        Method::GET,
        &format!(
            "/runs/{}/traces?redaction_policy=none",
            expired_created.run_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| matches!(event.kind, TraceEventKind::ActionNeedsIntervention { .. }))
            .unwrap_or(false)
    }));
}

#[tokio::test]
async fn exact_waiting_action_accepts_raw_denial_and_records_replayable_terminal_evidence() {
    let trace_store = Arc::new(InMemoryTraceStore::default());
    let state = support::state_with_trace_store(
        DaemonConfig::local_dev(),
        trace_store.clone(),
        &["daemon.local"],
    );
    let app = router(state.clone());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let mut create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        Vec::new(),
        vec![RegisteredAction {
            name: "allowed_action".to_string(),
            adapter: "daemon.local".to_string(),
            required_permissions: Some(Vec::new()),
        }],
    );
    create.approval_policies = vec![approval_policy(&tenant_id, &agent_id, "allowed_action")];
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let requested_at = OffsetDateTime::now_utc();
    let action_id = ActionId::new();
    let request = SubmitActionRequest {
        action_id: Some(action_id.clone()),
        run_id: created.run_id.clone(),
        tenant_id: tenant_id.clone(),
        agent_id: agent_id.clone(),
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: Some(TraceId::new()),
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: Some(requested_at),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let mut denial = approval_evidence(
        &tenant_id,
        &agent_id,
        &created.run_id,
        "allowed_action",
        ApprovalDecision::Denied,
    );
    denial.action_id = Some(action_id.clone());
    denial.reason = Some("operator denied exact action".to_string());

    let mut prechallenge_denial = request.clone();
    prechallenge_denial.approval_evidence = Some(denial.clone());
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(&prechallenge_denial).expect("pending pre-challenge denial"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "approval_challenge_retry_mismatch");
    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.status, RunStatus::Pending);
    assert_eq!(inspected.adapter_executions, 0);

    let (status, started): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(LifecycleRequest {
            credential: None,
            work_order: None,
            audit_attribution: Some(attribution()),
            reason: None,
            approval_evidence: None,
            authority_obligation_receipts: Vec::new(),
        })
        .expect("start request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(started.status, RunStatus::Running);

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(&prechallenge_denial).expect("running pre-challenge denial"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "approval_challenge_retry_mismatch");
    let (status, prechallenge_traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!prechallenge_traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| {
                matches!(
                    event.kind,
                    TraceEventKind::ApprovalDenied { .. }
                        | TraceEventKind::ApprovalExpired { .. }
                        | TraceEventKind::ApprovalRevoked { .. }
                )
            })
            .unwrap_or(false)
    }));

    let (status, waiting): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(&request).expect("approval request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        waiting.status,
        splendor_gateway::ActionStatus::NeedsApproval
    );
    let challenge = waiting
        .approval_challenge
        .clone()
        .expect("full pending approval challenge");

    let baseline_waiting_traces: TracePageResponse = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await
    .1;
    let mut exact_denial = denial.clone();
    exact_denial.approval_id = challenge.approval_id.clone();
    for (label, mutate, expected_code) in [
        (
            "unsupported_schema",
            0_u8,
            "approval_evidence_schema_unsupported",
        ),
        (
            "missing_action_id",
            1_u8,
            "approval_challenge_retry_mismatch",
        ),
        (
            "missing_action_name",
            2_u8,
            "approval_challenge_retry_mismatch",
        ),
        ("missing_adapter", 3_u8, "approval_challenge_retry_mismatch"),
        ("invalid_interval", 4_u8, "approval_evidence_malformed"),
    ] {
        let mut evidence = exact_denial.clone();
        match mutate {
            0 => evidence.schema_version = "splendor.approval_evidence.v0".to_string(),
            1 => evidence.action_id = None,
            2 => evidence.action_name = None,
            3 => evidence.adapter = None,
            4 => evidence.issued_at = evidence.expires_at + time::Duration::seconds(1),
            _ => unreachable!(),
        }
        let mut rejected = request.clone();
        rejected.approval_evidence = Some(evidence);
        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            app.clone(),
            Method::POST,
            "/actions",
            serde_json::to_value(rejected).expect("malformed waiting raw evidence"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "case={label}");
        assert_eq!(error.code, expected_code, "case={label}");
        let inspected: RunInspectResponse = call_empty(
            app.clone(),
            Method::GET,
            &format!("/runs/{}", created.run_id),
        )
        .await
        .1;
        assert_eq!(
            inspected.status,
            RunStatus::WaitingForApproval,
            "case={label}"
        );
        assert_eq!(inspected.adapter_executions, 0, "case={label}");
        let traces: TracePageResponse = call_empty(
            app.clone(),
            Method::GET,
            &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
        )
        .await
        .1;
        assert_eq!(
            traces.records.len(),
            baseline_waiting_traces.records.len(),
            "case={label}"
        );
    }

    let mut mismatched_denial = request.clone();
    mismatched_denial.approval_evidence = Some(denial.clone());
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(mismatched_denial).expect("mismatched approval denial"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "approval_challenge_retry_mismatch");
    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.status, RunStatus::WaitingForApproval);
    assert_eq!(inspected.adapter_executions, 0);
    let (status, mismatched_traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!mismatched_traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| {
                matches!(
                    event.kind,
                    TraceEventKind::ApprovalDenied { .. }
                        | TraceEventKind::ApprovalExpired { .. }
                        | TraceEventKind::ApprovalRevoked { .. }
                )
            })
            .unwrap_or(false)
    }));

    const CREDENTIAL_CANARY: &str = "C03_APPROVAL_DENIAL_REASON_CREDENTIAL_CANARY";
    let authority_evaluations_before_credential_denial = state
        .run_authority_evaluation_count(&created.run_id)
        .expect("authority evaluations before credential denial");
    let raw_trace_count_before_credential_denial = trace_store
        .read(&created.run_id.to_string())
        .expect("raw traces before credential denial")
        .len();
    let mut credential_denial = exact_denial.clone();
    credential_denial.reason = Some(format!("Bearer {CREDENTIAL_CANARY}"));
    let mut credential_denied_request = request.clone();
    credential_denied_request.approval_evidence = Some(credential_denial);
    let (status, credential_denied): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(credential_denied_request)
            .expect("credential-bearing approval denial"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        credential_denied.status,
        splendor_gateway::ActionStatus::Denied
    );
    assert_eq!(
        credential_denied.verification.reasons,
        vec![splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED]
    );
    assert_eq!(
        credential_denied.error.as_deref(),
        Some(splendor_gateway::RAW_CREDENTIAL_INPUT_DENIED)
    );
    assert!(credential_denied.output.is_none());
    assert!(credential_denied.post_verification.is_none());
    assert!(credential_denied.approval_challenge.is_none());
    assert!(!serde_json::to_string(&credential_denied)
        .expect("credential denial outcome")
        .contains(CREDENTIAL_CANARY));

    let raw_records = trace_store
        .read(&created.run_id.to_string())
        .expect("raw traces after credential denial");
    assert_eq!(
        raw_records.len(),
        raw_trace_count_before_credential_denial,
        "waiting runs must return the fixed denial without audit or action-history amplification"
    );
    assert!(!serde_json::to_string(&raw_records)
        .expect("raw trace records")
        .contains(CREDENTIAL_CANARY));

    let (status, trace_read): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!serde_json::to_string(&trace_read)
        .expect("trace read response")
        .contains(CREDENTIAL_CANARY));

    let replay_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::ReplayCreate]);
    let replay_audit = matching_attribution(&replay_credential);
    let (status, credential_denial_replay): (StatusCode, ReplayResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({
            "credential": replay_credential,
            "audit_attribution": replay_audit,
            "mode": "inspect_only",
            "side_effects_allowed": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!serde_json::to_string(&credential_denial_replay)
        .expect("credential denial replay")
        .contains(CREDENTIAL_CANARY));
    assert!(!credential_denial_replay
        .approval_events
        .iter()
        .any(|event| event.lifecycle == "denied"));
    assert_eq!(
        state
            .run_authority_evaluation_count(&created.run_id)
            .expect("authority evaluations after credential denial and replay"),
        authority_evaluations_before_credential_denial
    );
    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.status, RunStatus::WaitingForApproval);
    assert_eq!(inspected.adapter_executions, 0);

    denial.approval_id = challenge.approval_id.clone();
    let mut denied_request = request;
    denied_request.approval_evidence = Some(denial);
    let (status, denied): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(&denied_request).expect("denial request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(denied.status, splendor_gateway::ActionStatus::Denied);
    assert!(denied
        .verification
        .reasons
        .iter()
        .any(|reason| reason == "approval_denied"));

    let (status, inspected): (StatusCode, RunInspectResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.status, RunStatus::Denied);
    assert_eq!(inspected.adapter_executions, 0);

    let (status, conflict): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(denied_request).expect("used denial request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(conflict.code, "action_id_conflict");
    assert_eq!(conflict.details["retryable"], false);

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let events = traces
        .records
        .iter()
        .filter_map(|record| serde_json::from_value::<TraceEvent>(record.payload.clone()).ok())
        .collect::<Vec<_>>();
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ApprovalDenied { .. })));
    assert!(events
        .iter()
        .any(|event| matches!(event.kind, TraceEventKind::ActionDenied { .. })));

    let replay_credential =
        caller_credential_for_tenant(tenant_id, vec![EndpointScope::ReplayCreate]);
    let replay_audit = AuditAttribution {
        credential_id: Some(replay_credential.credential_id.clone()),
        ..attribution()
    };
    let (status, replay): (StatusCode, ReplayResponse) = call_json(
        app,
        Method::POST,
        &format!("/runs/{}/replay", created.run_id),
        json!({"credential": replay_credential, "audit_attribution": replay_audit}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(replay
        .approval_events
        .iter()
        .any(|event| event.lifecycle == "denied"));
    let replayed_denial = replay
        .approval_events
        .iter()
        .find(|event| event.lifecycle == "denied")
        .expect("replayed exact denial");
    assert_eq!(replayed_denial.reason.as_deref(), Some("approval_denied"));
    assert_eq!(replayed_denial.approval.approval_id, challenge.approval_id);
    assert_eq!(replayed_denial.approval.tenant_id, challenge.tenant_id);
    assert_eq!(replayed_denial.approval.agent_id, challenge.agent_id);
    assert_eq!(replayed_denial.approval.run_id, challenge.run_id);
    assert_eq!(
        replayed_denial.approval.action_id.as_ref(),
        Some(&challenge.action_id)
    );
    assert_eq!(replayed_denial.approval.action_name, challenge.action_name);
    assert_eq!(
        replayed_denial.approval.adapter.as_deref(),
        Some(challenge.adapter.as_str())
    );
    assert_eq!(
        replayed_denial.approval.policy_id.as_deref(),
        Some(challenge.policy_id.as_str())
    );
    assert_eq!(replayed_denial.approval.risk_level, challenge.risk_level);
    assert_eq!(
        replayed_denial.approval.decision,
        Some(ApprovalDecision::Denied)
    );
    assert_eq!(
        replayed_denial.approval.reason.as_deref(),
        Some("operator denied exact action")
    );
}

#[tokio::test]
async fn action_transport_rejects_unknown_and_authority_looking_fields() {
    let app = router(DaemonState::local_dev());
    let submit = SubmitActionRequest {
        action_id: Some(ActionId::new()),
        run_id: RunId::new(),
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: Some(TraceId::new()),
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };

    for field in ["physical_action_resource_coordinate", "arbitrary_unknown"] {
        let mut body = serde_json::to_value(&submit).expect("submit JSON");
        body.as_object_mut()
            .expect("submit object")
            .insert(field.to_string(), json!({"node_id": NodeId::new()}));
        assert_eq!(
            call_status(app.clone(), Method::POST, "/actions", body).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "field={field}"
        );
    }

    for field in ["physical_action_resource_coordinate", "arbitrary_unknown"] {
        let mut body = serde_json::to_value(&submit).expect("physical submit JSON");
        let object = body.as_object_mut().expect("physical submit object");
        object.insert(
            "safety_context".to_string(),
            json!({
                "allowed_zone_refs": [],
                "privacy_clear": true,
                "human_proximity_clear": true,
                "emergency_stop_clear": true,
                "offline": false,
                "policy_cache_expired": false,
                "high_risk": false,
                "cloud_helper_direct_authority": false
            }),
        );
        object.insert(field.to_string(), json!({"node_id": NodeId::new()}));
        assert_eq!(
            call_status(
                app.clone(),
                Method::POST,
                &format!("/devices/{}/actions", NodeId::new()),
                body,
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "physical field={field}"
        );
    }
}

#[tokio::test]
async fn daemon_error_paths_cover_state_trace_lifecycle_scope_and_percepts() {
    let state = action_test_state();
    let app = router(state.clone());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create_request(
            tenant_id.clone(),
            agent_id.clone(),
            Vec::new(),
            Vec::new(),
        ))
        .expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, error): (StatusCode, ApiErrorBody) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/state-head", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error.code, "state_head_not_found");

    let (status, error): (StatusCode, ApiErrorBody) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "missing_trace_redaction_policy");

    let disallowed = AppendPerceptRequest {
        credential: None,
        audit_attribution: Some(attribution()),
        percept: Some(percept("splendor.percept.disallowed.v1")),
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/percepts", created.run_id),
        serde_json::to_value(disallowed).expect("disallowed percept"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "disallowed_percept");

    let resume = LifecycleRequest {
        credential: None,
        work_order: Some(signed_work_order(
            tenant_id.clone(),
            agent_id.clone(),
            Some(created.run_id.clone()),
            vec![EndpointScope::RunsResume],
        )),
        audit_attribution: Some(attribution()),
        reason: Some("not-paused".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(resume).expect("resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "invalid_run_state");

    let wrong_scope_submit = SubmitActionRequest {
        action_id: None,
        run_id: created.run_id.clone(),
        tenant_id: TenantId::new(),
        agent_id: agent_id.clone(),
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: None,
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: None,
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(wrong_scope_submit).expect("wrong scope submit"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "wrong_scope");

    let lifecycle = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: Some("stop".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, stopped): (StatusCode, RunInspectResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/stop", created.run_id),
        serde_json::to_value(&lifecycle).expect("stop request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stopped.status, RunStatus::Cancelled);

    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(lifecycle).expect("restart request"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error.code, "invalid_run_state");

    state.set_runtime_available(false);
    let (status, health): (StatusCode, Value) = call_empty(app, Method::GET, "/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(health["status"], "unavailable");
}

#[tokio::test]
async fn daemon_executes_allowed_actions_and_pages_trace_ranges() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let mut planned = action("allowed_action");
    planned.preconditions = vec!["ready".to_string()];
    let policy_actions = vec![DaemonActionCandidate {
        action_id: None,
        action: planned,
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage {
            actions: 1,
            http_requests: 1,
            ..QuotaUsage::default()
        }),
        satisfied_preconditions: vec!["ready".to_string()],
        requested_at: None,
        authority_obligation_receipts: Vec::new(),
    }];
    let mut create = create_request(
        tenant_id.clone(),
        agent_id.clone(),
        policy_actions,
        Vec::new(),
    );
    create.allowed_actions.push("failing_action".to_string());
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lifecycle = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, tick): (StatusCode, TickResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(lifecycle).expect("start request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tick.action_outcomes.len(), 1);
    assert_eq!(
        tick.action_outcomes[0].status,
        splendor_gateway::ActionStatus::Executed
    );

    let (status, full): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!("/runs/{}/traces?redaction_policy=none", created.run_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(full.records.len() > 3);

    let (status, end_only): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!(
            "/runs/{}/traces?end=2&redaction_policy=none",
            created.run_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(end_only.records.len(), 2);
    assert_eq!(
        end_only
            .records
            .iter()
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert!(end_only.records[0].prev_event_hash.is_none());

    let (status, start_only): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!(
            "/runs/{}/traces?start=2&redaction_policy=none",
            created.run_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(start_only.records.len(), full.records.len() - 2);
    assert_eq!(
        start_only.records.first().map(|record| record.sequence),
        Some(2)
    );
    assert!(start_only.records[0].prev_event_hash.is_none());

    let (status, empty): (StatusCode, TracePageResponse) = call_empty(
        app.clone(),
        Method::GET,
        &format!(
            "/runs/{}/traces?start=2&end=2&redaction_policy=none",
            created.run_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(empty.records.is_empty());

    let (status, reversed): (StatusCode, ApiErrorBody) = call_empty(
        app.clone(),
        Method::GET,
        &format!(
            "/runs/{}/traces?start=3&end=2&redaction_policy=none",
            created.run_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reversed.code, "invalid_trace_range");

    let trace_credential =
        caller_credential_for_tenant(tenant_id.clone(), vec![EndpointScope::TracesRead]);
    let trace_audit = matching_attribution(&trace_credential);
    let (status, exported): (StatusCode, TraceExportResponse) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/traces/export", created.run_id),
        json!({
            "credential": trace_credential.clone(),
            "audit_attribution": trace_audit.clone(),
            "redaction_policy": "none",
            "start": 2,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        exported.records.first().map(|record| record.sequence),
        Some(2)
    );
    assert!(exported.records[0].prev_event_hash.is_none());
    let (status, reversed_export): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/traces/export", created.run_id),
        json!({
            "credential": trace_credential,
            "audit_attribution": trace_audit,
            "redaction_policy": "none",
            "start": 3,
            "end": 2,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reversed_export.code, "invalid_trace_range");

    let causal_trace_id = end_only.records.first().and_then(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .ok()
            .map(|event| event.trace_event_id)
    });

    let submit = SubmitActionRequest {
        action_id: None,
        run_id: created.run_id,
        tenant_id,
        agent_id,
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id,
        action: action("allowed_action"),
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, outcome): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(submit.clone()).expect("submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(outcome.status, splendor_gateway::ActionStatus::Executed);

    let failing = action("failing_action");
    let failed_submit = SubmitActionRequest {
        action_id: None,
        run_id: submit.run_id,
        tenant_id: submit.tenant_id,
        agent_id: submit.agent_id,
        credential: None,
        audit_attribution: Some(attribution()),
        causal_trace_id: submit.causal_trace_id,
        action: failing,
        adapter: Some("daemon.local".to_string()),
        quota_usage: Some(QuotaUsage::single_action()),
        satisfied_preconditions: Vec::new(),
        requested_at: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let failed_run_id = failed_submit.run_id.clone();
    let (status, failed): (StatusCode, splendor_gateway::ActionOutcome) = call_json(
        app.clone(),
        Method::POST,
        "/actions",
        serde_json::to_value(failed_submit).expect("failed submit request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(failed.status, splendor_gateway::ActionStatus::Failed);

    let (status, traces): (StatusCode, TracePageResponse) = call_empty(
        app,
        Method::GET,
        &format!("/runs/{failed_run_id}/traces?redaction_policy=none"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| matches!(event.kind, TraceEventKind::ActionFailed { .. }))
            .unwrap_or(false)
    }));
    assert!(traces.records.iter().any(|record| {
        serde_json::from_value::<TraceEvent>(record.payload.clone())
            .map(|event| matches!(event.kind, TraceEventKind::OutcomeRecorded { .. }))
            .unwrap_or(false)
    }));
}

#[tokio::test]
async fn trace_range_rejects_corruption_outside_the_selected_slice() {
    let trace_store = Arc::new(CorruptingRangeTraceStore::default());
    let app = router(support::state_with_trace_store(
        DaemonConfig::local_dev(),
        trace_store,
        &["daemon.local"],
    ));
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create_request(tenant_id, agent_id, Vec::new(), Vec::new()))
            .expect("create corrupt-range run"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, error): (StatusCode, ApiErrorBody) = call_empty(
        app,
        Method::GET,
        &format!(
            "/runs/{}/traces?start=1&end=2&redaction_policy=none",
            created.run_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.code, "trace_evidence_unavailable");
}

#[tokio::test]
async fn structured_errors_cover_invalid_run_malformed_percept_and_unavailable_runtime() {
    let state = action_test_state();
    let app = router(state.clone());
    let run_id = RunId::new();

    let (status, invalid): (StatusCode, ApiErrorBody) =
        call_empty(app.clone(), Method::GET, &format!("/runs/{run_id}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(invalid.code, "invalid_run");

    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(create_request(tenant_id, agent_id, Vec::new(), Vec::new()))
            .expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let malformed = AppendPerceptRequest {
        credential: None,
        audit_attribution: Some(attribution()),
        percept: None,
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/percepts", created.run_id),
        serde_json::to_value(malformed).expect("malformed request"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.code, "malformed_percept");

    state.set_runtime_available(false);
    let lifecycle = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: None,
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, unavailable): (StatusCode, ApiErrorBody) = call_json(
        app,
        Method::POST,
        &format!("/runs/{}/start", created.run_id),
        serde_json::to_value(lifecycle).expect("lifecycle request"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unavailable.code, "runtime_unavailable");
}

#[tokio::test]
async fn missing_direct_policy_and_physical_adapters_reject_before_run_or_idempotency_commit() {
    for (kind, action_name, adapter_name, policy_action, registered_action) in [
        ("direct", "allowed_action", "missing-direct", false, false),
        ("policy", "policy_action", "missing-policy", true, false),
        ("physical", "capture_image", "device-sim", false, true),
    ] {
        let app = router(DaemonState::local_dev());
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let run_id = RunId::new();
        let mut create =
            create_request(tenant_id.clone(), agent_id.clone(), Vec::new(), Vec::new());
        create.allowed_actions = vec![action_name.to_string()];
        create.allowed_adapters = vec![adapter_name.to_string()];
        create.work_order.work_order.run_id = Some(run_id.clone());
        create.work_order.work_order.allowed_actions = create.allowed_actions.clone();
        create.work_order.work_order.allowed_adapters = create.allowed_adapters.clone();
        if policy_action {
            create.policy_actions = vec![DaemonActionCandidate {
                action_id: None,
                action: action(action_name),
                adapter: Some(adapter_name.to_string()),
                quota_usage: None,
                satisfied_preconditions: Vec::new(),
                requested_at: None,
                authority_obligation_receipts: Vec::new(),
            }];
        }
        if registered_action {
            create.registered_actions = vec![RegisteredAction {
                name: action_name.to_string(),
                adapter: adapter_name.to_string(),
                required_permissions: None,
            }];
        }
        resign_work_order(&mut create.work_order);

        let (status, error): (StatusCode, ApiErrorBody) = call_json(
            app.clone(),
            Method::POST,
            "/runs",
            serde_json::to_value(&create).expect("create request"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{kind}");
        assert_eq!(error.code, "action_adapter_unavailable", "{kind}");
        assert_eq!(error.details["tenant_id"], tenant_id.to_string(), "{kind}");
        assert_eq!(error.details["agent_id"], agent_id.to_string(), "{kind}");
        assert_eq!(error.details["run_id"], run_id.to_string(), "{kind}");
        assert_eq!(error.details["action_name"], action_name, "{kind}");
        assert_eq!(error.details["adapter"], adapter_name, "{kind}");
        assert_eq!(error.details["effect_certainty"], "none", "{kind}");
        assert_eq!(
            error.details["admission_stage"], "before_run_and_idempotency_commit",
            "{kind}"
        );

        let (status, not_found): (StatusCode, ApiErrorBody) =
            call_empty(app.clone(), Method::GET, &format!("/runs/{run_id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{kind}");
        assert_eq!(not_found.code, "invalid_run", "{kind}");

        if kind == "direct" {
            let mut retry = create;
            retry.work_order.work_order.allowed_actions = vec!["alternate_action".to_string()];
            retry.work_order.work_order.allowed_adapters = vec!["missing-alternate".to_string()];
            retry.allowed_actions = retry.work_order.work_order.allowed_actions.clone();
            retry.allowed_adapters = retry.work_order.work_order.allowed_adapters.clone();
            resign_work_order(&mut retry.work_order);
            let (status, retry_error): (StatusCode, ApiErrorBody) = call_json(
                app,
                Method::POST,
                "/runs",
                serde_json::to_value(retry).expect("retry request"),
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(retry_error.code, "action_adapter_unavailable");
            assert_eq!(retry_error.details["adapter"], "missing-alternate");
        }
    }
}

#[tokio::test]
async fn health_and_capabilities_remain_local_dev_only_without_credentials() {
    let local_app = router(DaemonState::local_dev());
    let (status, _health): (StatusCode, Value) =
        call_empty(local_app.clone(), Method::GET, "/health").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _capabilities): (StatusCode, Value) =
        call_empty(local_app, Method::GET, "/capabilities").await;
    assert_eq!(status, StatusCode::OK);

    let locked_app = router(DaemonState::new(DaemonConfig {
        expected_audience: CredentialAudience::Daemon {
            daemon_id: "daemon_local".to_string(),
        },
        caller_token_verifier: None,
        insecure_dev_mode: None,
        policy_bundle_keyring: splendor_types::PolicyBundleKeyring::new(),
        work_order_keyring: splendor_types::WorkOrderKeyring::new(),
        authority_obligation_receipt_config: None,
    }));
    let (status, error): (StatusCode, ApiErrorBody) =
        call_empty(locked_app.clone(), Method::GET, "/health").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "anonymous_non_dev_call");
    let (status, error): (StatusCode, ApiErrorBody) =
        call_empty(locked_app.clone(), Method::GET, "/capabilities").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "anonymous_non_dev_call");

    let health_credential = caller_credential(vec![EndpointScope::HealthRead]);
    let (status, _health): (StatusCode, Value) = call_empty_with_credential(
        locked_app.clone(),
        Method::GET,
        "/health",
        &health_credential,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let capabilities_credential = caller_credential(vec![EndpointScope::CapabilitiesRead]);
    let (status, _capabilities): (StatusCode, Value) = call_empty_with_credential(
        locked_app.clone(),
        Method::GET,
        "/capabilities",
        &capabilities_credential,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, error): (StatusCode, ApiErrorBody) =
        call_empty_with_credential(locked_app, Method::GET, "/capabilities", &health_credential)
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "missing_scope");
}

#[tokio::test]
async fn health_and_capabilities_accept_canonical_and_public_header_credentials() {
    let locked_app = router(DaemonState::new(DaemonConfig {
        expected_audience: CredentialAudience::Daemon {
            daemon_id: "daemon_local".to_string(),
        },
        caller_token_verifier: None,
        insecure_dev_mode: None,
        policy_bundle_keyring: splendor_types::PolicyBundleKeyring::new(),
        work_order_keyring: splendor_types::WorkOrderKeyring::new(),
        authority_obligation_receipt_config: None,
    }));

    let canonical_health = caller_credential(vec![EndpointScope::HealthRead]);
    let (status, health): (StatusCode, Value) = call_empty_with_credential(
        locked_app.clone(),
        Method::GET,
        "/health",
        &canonical_health,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(health["status"], "ok");

    let public_health = public_caller_credential_header(vec!["splendor.health.read"]);
    let (status, health): (StatusCode, Value) = call_empty_with_credential_header(
        locked_app.clone(),
        Method::GET,
        "/health",
        public_health,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(health["runtime_available"], true);

    let public_version = public_caller_credential_header(vec!["splendor.health.read"]);
    let (status, version): (StatusCode, Value) = call_empty_with_credential_header(
        locked_app.clone(),
        Method::GET,
        "/version",
        public_version,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(version["compatibility_line"], "0.1");

    let public_capabilities = public_caller_credential_header(vec!["capabilities_read"]);
    let (status, capabilities): (StatusCode, Value) = call_empty_with_credential_header(
        locked_app,
        Method::GET,
        "/capabilities",
        public_capabilities,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(capabilities["daemon_api_version"], "0.02-S5");
    let profiles = capabilities["service_profiles"]
        .as_array()
        .expect("service profiles array");
    let runtime = profiles
        .iter()
        .find(|profile| profile["name"] == "runtime_daemon_local")
        .expect("runtime daemon profile");
    assert_eq!(runtime["status"], "implemented");
    assert_eq!(runtime["maturity"], "local_0_1_compat");
    assert!(runtime["endpoints"]
        .as_array()
        .expect("runtime endpoints")
        .iter()
        .any(|endpoint| endpoint == "POST /runs"));
    let simulated = profiles
        .iter()
        .find(|profile| profile["name"] == "physical_device_simulation")
        .expect("simulated physical profile");
    assert_eq!(simulated["status"], "simulated");
    let idempotency = profiles
        .iter()
        .find(|profile| profile["name"] == "create_run_idempotency_v0")
        .expect("idempotency profile");
    assert_eq!(idempotency["status"], "experimental");
    assert_eq!(idempotency["maturity"], "bounded_current_endpoint");
    let watch = profiles
        .iter()
        .find(|profile| profile["name"] == "v2_watch_streams")
        .expect("watch stream profile");
    assert_eq!(watch["status"], "unavailable");
    let gold = profiles
        .iter()
        .find(|profile| profile["name"] == "gold_g00_g06")
        .expect("gold profile");
    assert_eq!(gold["maturity"], "not_exercised");
    assert!(!profiles.iter().any(|profile| {
        profile["name"] == "v2_watch_streams" && profile["status"] == "implemented"
    }));
}

#[tokio::test]
async fn credential_header_rejections_fail_closed_for_malformed_and_invalid_authority() {
    let locked_app = router(DaemonState::new(DaemonConfig {
        expected_audience: CredentialAudience::Daemon {
            daemon_id: "daemon_local".to_string(),
        },
        caller_token_verifier: None,
        insecure_dev_mode: None,
        policy_bundle_keyring: splendor_types::PolicyBundleKeyring::new(),
        work_order_keyring: splendor_types::WorkOrderKeyring::new(),
        authority_obligation_receipt_config: None,
    }));

    let invalid_utf8 = HeaderValue::from_bytes(&[0xff, 0xfe]).expect("invalid utf8 header bytes");
    let (status, error): (StatusCode, ApiErrorBody) =
        call_empty_with_credential_header(locked_app.clone(), Method::GET, "/health", invalid_utf8)
            .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "invalid_caller_credential_header");

    let malformed_json = HeaderValue::from_static("{not-json");
    let (status, error): (StatusCode, ApiErrorBody) = call_empty_with_credential_header(
        locked_app.clone(),
        Method::GET,
        "/health",
        malformed_json,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "invalid_caller_credential_header");

    let mut expired = caller_credential(vec![EndpointScope::HealthRead]);
    expired.expires_at = OffsetDateTime::now_utc() - time::Duration::minutes(1);
    let (status, error): (StatusCode, ApiErrorBody) =
        call_empty_with_credential(locked_app.clone(), Method::GET, "/health", &expired).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "credential_expired");

    let mut revoked = caller_credential(vec![EndpointScope::HealthRead]);
    revoked.revocation = RevocationStatus::Revoked {
        reason: "operator_revoked".to_string(),
    };
    let (status, error): (StatusCode, ApiErrorBody) =
        call_empty_with_credential(locked_app.clone(), Method::GET, "/health", &revoked).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "credential_revoked");

    let mut wrong_audience = caller_credential(vec![EndpointScope::HealthRead]);
    wrong_audience.audience = CredentialAudience::Daemon {
        daemon_id: "daemon_other".to_string(),
    };
    let (status, error): (StatusCode, ApiErrorBody) =
        call_empty_with_credential(locked_app.clone(), Method::GET, "/health", &wrong_audience)
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "wrong_audience");

    let missing_scope = caller_credential(vec![EndpointScope::CapabilitiesRead]);
    let (status, error): (StatusCode, ApiErrorBody) =
        call_empty_with_credential(locked_app, Method::GET, "/health", &missing_scope).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "missing_scope");
}

#[tokio::test]
async fn public_credential_header_rejections_cover_revocation_and_scope_branches() {
    let locked_app = router(DaemonState::new(DaemonConfig {
        expected_audience: CredentialAudience::Daemon {
            daemon_id: "daemon_local".to_string(),
        },
        caller_token_verifier: None,
        insecure_dev_mode: None,
        policy_bundle_keyring: splendor_types::PolicyBundleKeyring::new(),
        work_order_keyring: splendor_types::WorkOrderKeyring::new(),
        authority_obligation_receipt_config: None,
    }));

    let revoked = public_caller_credential_header_with_revocation(
        vec!["splendor.health.read"],
        json!({"revoked": {"reason": "operator_revoked"}}),
    );
    let (status, error): (StatusCode, ApiErrorBody) =
        call_empty_with_credential_header(locked_app.clone(), Method::GET, "/health", revoked)
            .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "credential_revoked");

    let malformed_revocation =
        public_caller_credential_header_with_revocation(vec!["splendor.health.read"], json!(null));
    let (status, error): (StatusCode, ApiErrorBody) = call_empty_with_credential_header(
        locked_app.clone(),
        Method::GET,
        "/health",
        malformed_revocation,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "invalid_caller_credential_header");

    let unsupported_scope = public_caller_credential_header(vec!["splendor.future.scope"]);
    let (status, error): (StatusCode, ApiErrorBody) =
        call_empty_with_credential_header(locked_app, Method::GET, "/health", unsupported_scope)
            .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "invalid_caller_credential_header");
}

#[tokio::test]
async fn resume_without_signed_work_order_fails_before_tick_execution() {
    let app = router(action_test_state());
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let request = create_request(
        tenant_id,
        agent_id,
        vec![DaemonActionCandidate {
            action_id: None,
            action: action("allowed_action"),
            adapter: Some("daemon.local".to_string()),
            quota_usage: None,
            satisfied_preconditions: Vec::new(),
            requested_at: None,
            authority_obligation_receipts: Vec::new(),
        }],
        Vec::new(),
    );
    let (status, created): (StatusCode, CreateRunResponse) = call_json(
        app.clone(),
        Method::POST,
        "/runs",
        serde_json::to_value(request).expect("create request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let resume_request = LifecycleRequest {
        credential: None,
        work_order: None,
        audit_attribution: Some(attribution()),
        reason: Some("operator retry".to_string()),
        approval_evidence: None,
        authority_obligation_receipts: Vec::new(),
    };
    let (status, error): (StatusCode, ApiErrorBody) = call_json(
        app.clone(),
        Method::POST,
        &format!("/runs/{}/resume", created.run_id),
        serde_json::to_value(resume_request).expect("resume request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "missing_work_order");

    let (status, inspected): (StatusCode, RunInspectResponse) =
        call_empty(app, Method::GET, &format!("/runs/{}", created.run_id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspected.status, RunStatus::Pending);
    assert_eq!(inspected.ticks, 0);
    assert_eq!(inspected.adapter_executions, 0);
}
