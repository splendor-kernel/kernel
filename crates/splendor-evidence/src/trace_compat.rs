use serde::Deserialize;
use splendor_store::{
    compute_trace_envelope_hash, compute_trace_event_hash, RuntimeTraceAppend, RuntimeTraceLimits,
    RuntimeTracePortError, RuntimeTraceProfile, RuntimeTraceReader, RuntimeTraceReaderHandle,
    RuntimeTraceScope, RuntimeTraceTail, RuntimeTraceWriter, RuntimeTraceWriterHandle,
    RuntimeTraceWriterRequest, TraceRecord, TraceStore,
};
use splendor_types::{
    Action, ActionId, AgentId, ApprovalChallenge, ApprovalTraceContext, ContentHash, RunId,
    SnapshotId, StateNodeId, TenantId, TraceEvent, TraceEventId, TraceEventKind, TraceIntegrity,
    VerificationResult,
};
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;

const RAW_CREDENTIAL_OUTPUT_SUPPRESSED: &str = "raw_credential_output_suppressed";
const REDACTED_TRACE_HASH_DOMAIN: &[u8] = b"splendor.trace.redacted-projection.v1\0";
const REDACTED_AUDIT_CREDENTIAL_CORRELATION: &str = "[REDACTED:credential-correlation]";
const REDACTED_HASH_CANDIDATE: &str = "[REDACTED:hash-candidate]";

/// Fully validated bounded history used by trusted inspection consumers.
pub struct InspectTraceResult {
    /// Storage profile selected before decoding.
    pub profile: RuntimeTraceProfile,
    /// Stable persisted records in exact storage order.
    pub records: Vec<TraceRecord>,
    /// Decoded stable events corresponding one-to-one with `records`.
    pub events: Vec<TraceEvent>,
    /// Reconfirmed tail bound to this result.
    pub tail: RuntimeTraceTail,
}

/// Exact recovery selection for one run/tenant/agent identity.
pub struct ResumeTraceResult {
    /// Snapshot selected from the latest completed target tick.
    pub snapshot_id: SnapshotId,
    /// Tick that committed the selected snapshot.
    pub tick_id: u64,
    /// Exact state node bound to the state event.
    pub state_node_id: StateNodeId,
    /// Exact state hash bound to the state event.
    pub state_hash: ContentHash,
    /// Exact state-commit trace event.
    pub trace_event_id: TraceEventId,
    /// Greatest tick identity observed anywhere in the run partition.
    pub max_tick_id: u64,
    /// Reconfirmed anchored tail used to initialize the runtime cursor.
    pub tail: RuntimeTraceTail,
}

/// Durable origin of one fully validated action history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableActionHistorySource {
    /// The action was proposed and first evaluated inside a completed tick.
    Tick,
    /// The action was first submitted through the daemon's direct action endpoint.
    Direct,
    /// The action was first submitted through the daemon's physical action endpoint.
    Physical,
}

/// Evidence-owned interpretation of one run-local durable action identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableActionHistoryDisposition {
    /// No event in the validated history uses this action identity.
    Fresh,
    /// The action history is terminal and the identity is permanently used.
    Complete {
        /// Immutable origin of the completed action history.
        source: DurableActionHistorySource,
    },
    /// A complete approval challenge remains open for exact continuation.
    PendingApproval {
        /// Immutable origin that constrains the continuation endpoint.
        source: DurableActionHistorySource,
    },
    /// History is malformed, incomplete, ambiguous, or effect-uncertain.
    ReconciliationRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum StoredActionStatus {
    Executed,
    Denied,
    NeedsApproval,
    NeedsIntervention,
    Failed,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredActionOutcome {
    action_id: ActionId,
    status: StoredActionStatus,
    verification: VerificationResult,
    post_verification: Option<VerificationResult>,
    output: Option<serde_json::Value>,
    error: Option<String>,
    #[serde(default)]
    approval_challenge: Option<ApprovalChallenge>,
    #[serde(rename = "completed_at")]
    _completed_at: OffsetDateTime,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDaemonOutcome {
    source: String,
    #[serde(default, rename = "causal_trace_id")]
    _causal_trace_id: Option<TraceEventId>,
    action_outcome: StoredActionOutcome,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTickOutcome {
    tick_id: u64,
    #[serde(rename = "duration_ms")]
    _duration_ms: u64,
    needs_intervention: bool,
    needs_approval: bool,
    #[serde(rename = "escalations")]
    _escalations: Vec<serde_json::Value>,
    actions: Vec<StoredActionOutcome>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ActionTickScope {
    tenant_id: TenantId,
    agent_id: AgentId,
    tick_id: u64,
}

struct ActionEpisode {
    action: Action,
    tick_scope: Option<ActionTickScope>,
    verification: Option<VerificationResult>,
    executed_output: Option<serde_json::Value>,
    terminal: Option<ActionEpisodeTerminal>,
}

enum ActionEpisodeTerminal {
    Denied(VerificationResult),
    NeedsApproval(VerificationResult),
    NeedsIntervention(VerificationResult),
    Failed {
        error: String,
        result: VerificationResult,
    },
}

impl ActionEpisode {
    fn terminal_status(&self) -> Option<StoredActionStatus> {
        match self.terminal {
            Some(ActionEpisodeTerminal::Denied(_)) => Some(StoredActionStatus::Denied),
            Some(ActionEpisodeTerminal::NeedsApproval(_)) => {
                Some(StoredActionStatus::NeedsApproval)
            }
            Some(ActionEpisodeTerminal::NeedsIntervention(_)) => {
                Some(StoredActionStatus::NeedsIntervention)
            }
            Some(ActionEpisodeTerminal::Failed { .. }) => Some(StoredActionStatus::Failed),
            None if self.executed_output.is_some() => Some(StoredActionStatus::Executed),
            None => None,
        }
    }
}

struct PendingTickActionEpisode {
    tick_scope: ActionTickScope,
    source: DurableActionHistorySource,
    status: StoredActionStatus,
}

#[derive(Default)]
struct ValidatedActionHistory {
    action: Option<Action>,
    source: Option<DurableActionHistorySource>,
    completed_count: usize,
    last_completed_tick_id: Option<u64>,
    approval_continuation_open: bool,
    open_episode: Option<ActionEpisode>,
    pending_tick_episode: Option<PendingTickActionEpisode>,
}

#[derive(Default)]
struct ActionTickHistory {
    action_order: Vec<ActionId>,
    outcome_seen: bool,
    state_commit_seen: bool,
    pending_actions: Vec<ActionId>,
}

struct RecoveryTickAttempt {
    tick_id: u64,
    action_started: bool,
    outcome_seen: bool,
    effect_evidence_seen: bool,
    state_commit_seen: bool,
    snapshot: Option<RecoverySnapshot>,
}

fn incomplete_tick_may_be_superseded(
    action_started: bool,
    outcome_seen: bool,
    state_commit_seen: bool,
    pending_episode_or_effect_evidence: bool,
) -> bool {
    !action_started && !outcome_seen && !state_commit_seen && !pending_episode_or_effect_evidence
}

impl RecoveryTickAttempt {
    fn may_be_superseded(&self) -> bool {
        incomplete_tick_may_be_superseded(
            self.action_started,
            self.outcome_seen,
            self.state_commit_seen,
            self.effect_evidence_seen,
        )
    }
}

struct RecoverySnapshot {
    snapshot_id: SnapshotId,
    tick_id: u64,
    state_node_id: StateNodeId,
    state_hash: ContentHash,
    trace_event_id: TraceEventId,
}

/// External projection selected after complete validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceProjection {
    /// Preserve trusted payloads for an internal authorized consumer.
    Trusted,
    /// Redact protected subtrees and emit a projection-local integrity chain.
    Redacted,
}

/// Fixed, non-reflecting compatibility-owner errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum TraceCompatibilityError {
    /// Store capability failed closed.
    #[error("trace_compatibility_store_failure")]
    Store,
    /// Another live writer or a safe local lock collision denied acquisition.
    #[error("trace_compatibility_writer_conflict")]
    WriterConflict,
    /// The trace advanced while a bounded inspection was validating its captured prefix.
    #[error("trace_compatibility_tail_moved")]
    TailMoved,
    /// A conservative record, page, payload, or byte budget was exceeded.
    #[error("trace_compatibility_limit_exceeded")]
    LimitExceeded,
    /// Stable record chain or anchored tail did not validate.
    #[error("trace_compatibility_integrity_failure")]
    Integrity,
    /// Stable event envelope did not match its storage record.
    #[error("trace_compatibility_envelope_failure")]
    Envelope,
    /// Current-profile completion integrity was missing or invalid.
    #[error("trace_compatibility_completion_integrity_failure")]
    CompletionIntegrity,
    /// Tick lifecycle was duplicate, decreasing, incomplete, or inconsistent.
    #[error("trace_compatibility_tick_lifecycle_failure")]
    TickLifecycle,
    /// A live effect boundary may have been entered and needs reconciliation.
    #[error("trace_compatibility_reconciliation_required")]
    ReconciliationRequired,
    /// Non-empty unanchored history is available for inspection only.
    #[error("trace_compatibility_legacy_inspect_only")]
    LegacyInspectOnly,
    /// No completed snapshot exists for the requested runtime identity.
    #[error("trace_compatibility_snapshot_unavailable")]
    SnapshotUnavailable,
    /// The latest completed tick did not publish a restorable snapshot.
    #[error("trace_compatibility_latest_snapshot_unavailable")]
    LatestSnapshotUnavailable,
}

impl From<RuntimeTracePortError> for TraceCompatibilityError {
    fn from(error: RuntimeTracePortError) -> Self {
        match error {
            RuntimeTracePortError::Conflict => Self::WriterConflict,
            RuntimeTracePortError::LimitExceeded => Self::LimitExceeded,
            RuntimeTracePortError::LegacyInspectOnly => Self::LegacyInspectOnly,
            RuntimeTracePortError::IntegrityFailure
            | RuntimeTracePortError::FenceRejected
            | RuntimeTracePortError::BackendContract => Self::Integrity,
            _ => Self::Store,
        }
    }
}

/// Opens the semantic owner's bounded inspect capability.
pub fn open_trace_reader(
    store: &dyn TraceStore,
    run_id: &RunId,
    limits: RuntimeTraceLimits,
) -> Result<RuntimeTraceReaderHandle, TraceCompatibilityError> {
    store
        .open_runtime_reader(&run_id.to_string(), limits)
        .map_err(Into::into)
}

/// Acquires the only authorized live compatibility writer profile.
pub fn acquire_current_trace_writer(
    store: &dyn TraceStore,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    limits: RuntimeTraceLimits,
) -> Result<RuntimeTraceWriterHandle, TraceCompatibilityError> {
    let request = RuntimeTraceWriterRequest::current(
        RuntimeTraceScope::new(
            run_id.to_string(),
            tenant_id.to_string(),
            agent_id.to_string(),
        ),
        limits,
    );
    store.acquire_runtime_writer(request).map_err(Into::into)
}

/// Validates a complete bounded stable trace and reconfirms its tail.
pub fn inspect_trace<R: RuntimeTraceReader + ?Sized>(
    reader: &R,
    run_id: &RunId,
) -> Result<InspectTraceResult, TraceCompatibilityError> {
    if reader.run_id() != run_id.to_string() {
        return Err(TraceCompatibilityError::Envelope);
    }
    let limits = reader.limits();
    let tail = reader.tail()?;
    if tail.store_identity() != &reader.store_identity() {
        return Err(TraceCompatibilityError::Integrity);
    }
    let tail_count = usize::try_from(tail.next_sequence())
        .map_err(|_| TraceCompatibilityError::LimitExceeded)?;
    if tail_count > limits.max_records {
        return Err(TraceCompatibilityError::LimitExceeded);
    }

    let mut records = Vec::with_capacity(tail_count.min(limits.page_records));
    let mut events = Vec::with_capacity(tail_count.min(limits.page_records));
    let mut expected_sequence = 0u64;
    let mut expected_stable_hash: Option<ContentHash> = None;
    let mut expected_envelope_hash: Option<ContentHash> = None;
    let mut total_bytes = 0usize;
    let mut tail_moved = false;

    while expected_sequence < tail.next_sequence() {
        let page_start = expected_sequence;
        let page = reader.read_page(expected_sequence)?;
        if page.records().is_empty()
            || page.records().len() > limits.page_records
            || page.next_sequence() <= expected_sequence
        {
            return Err(TraceCompatibilityError::Integrity);
        }
        let page_record_count = u64::try_from(page.records().len())
            .map_err(|_| TraceCompatibilityError::LimitExceeded)?;
        let declared_next = page_start
            .checked_add(page_record_count)
            .ok_or(TraceCompatibilityError::LimitExceeded)?;
        if page.next_sequence() != declared_next {
            return Err(TraceCompatibilityError::Integrity);
        }
        for record in page.records() {
            if expected_sequence == tail.next_sequence() {
                tail_moved = true;
                break;
            }
            if record.run_id != run_id.to_string() || record.sequence != expected_sequence {
                return Err(TraceCompatibilityError::Integrity);
            }
            if record.prev_event_hash.as_ref() != expected_stable_hash.as_ref() {
                return Err(TraceCompatibilityError::Integrity);
            }
            let payload_bytes = serde_json::to_vec(&record.payload)
                .map_err(|_| TraceCompatibilityError::Integrity)?;
            if payload_bytes.len() > limits.max_payload_bytes {
                return Err(TraceCompatibilityError::LimitExceeded);
            }
            total_bytes = total_bytes
                .checked_add(payload_bytes.len())
                .ok_or(TraceCompatibilityError::LimitExceeded)?;
            if total_bytes > limits.max_bytes {
                return Err(TraceCompatibilityError::LimitExceeded);
            }
            let stable_hash =
                compute_trace_event_hash(record.prev_event_hash.as_ref(), &record.payload)
                    .map_err(|_| TraceCompatibilityError::Integrity)?;
            if stable_hash != record.event_hash {
                return Err(TraceCompatibilityError::Integrity);
            }
            let envelope_hash =
                compute_trace_envelope_hash(expected_envelope_hash.as_ref(), record)?;
            let event: TraceEvent = serde_json::from_value(record.payload.clone())
                .map_err(|_| TraceCompatibilityError::Envelope)?;
            validate_event_envelope(&event, run_id, record, tail.profile())?;
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(TraceCompatibilityError::LimitExceeded)?;
            expected_stable_hash = Some(stable_hash);
            expected_envelope_hash = Some(envelope_hash);
            records.push(record.clone());
            events.push(event);
        }
        if expected_sequence < tail.next_sequence() && page.complete() {
            return Err(TraceCompatibilityError::Integrity);
        }
        if expected_sequence == tail.next_sequence()
            && (page.next_sequence() > tail.next_sequence() || !page.complete())
        {
            tail_moved = true;
        }
        if records.len() > limits.max_records {
            return Err(TraceCompatibilityError::LimitExceeded);
        }
    }

    if expected_stable_hash.as_ref() != tail.stable_tail_hash()
        || expected_envelope_hash.as_ref() != tail.envelope_tail_hash()
    {
        return Err(TraceCompatibilityError::Integrity);
    }
    match reader.confirm_tail(&tail) {
        Ok(()) if tail_moved => return Err(TraceCompatibilityError::Integrity),
        Ok(()) => {}
        Err(RuntimeTracePortError::FenceRejected) => {
            return Err(classify_tail_change(reader, &tail))
        }
        Err(error) => return Err(error.into()),
    }
    Ok(InspectTraceResult {
        profile: tail.profile(),
        records,
        events,
        tail,
    })
}

fn classify_tail_change<R: RuntimeTraceReader + ?Sized>(
    reader: &R,
    expected: &RuntimeTraceTail,
) -> TraceCompatibilityError {
    let actual = match reader.tail() {
        Ok(actual) => actual,
        Err(error) => return error.into(),
    };
    if actual.store_identity() != expected.store_identity()
        || actual.profile() != expected.profile()
        || actual.next_sequence() < expected.next_sequence()
        || actual.anchor_revision() < expected.anchor_revision()
    {
        return TraceCompatibilityError::Integrity;
    }
    let records_advanced = actual.next_sequence() > expected.next_sequence();
    let anchor_advanced = actual.anchor_revision() > expected.anchor_revision();
    if !records_advanced
        && (actual.stable_tail_hash() != expected.stable_tail_hash()
            || actual.envelope_tail_hash() != expected.envelope_tail_hash())
    {
        return TraceCompatibilityError::Integrity;
    }
    let valid_advance = match expected.profile() {
        RuntimeTraceProfile::CurrentAnchoredV1 => anchor_advanced,
        RuntimeTraceProfile::LegacyUnanchored => records_advanced,
        _ => false,
    };
    if valid_advance {
        TraceCompatibilityError::TailMoved
    } else {
        TraceCompatibilityError::Integrity
    }
}

/// Validates and interprets one durable action identity without consulting live
/// run state, authority, policy, the Gateway, or an adapter.
pub fn inspect_durable_action_history<R: RuntimeTraceReader + ?Sized>(
    reader: &R,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    action_id: &ActionId,
) -> Result<DurableActionHistoryDisposition, TraceCompatibilityError> {
    let inspected = inspect_trace(reader, run_id)?;
    if inspected.profile != RuntimeTraceProfile::CurrentAnchoredV1 {
        return Ok(DurableActionHistoryDisposition::ReconciliationRequired);
    }
    let validated = match validate_action_histories(&inspected.events, run_id, tenant_id, agent_id)
    {
        Ok(validated) => validated,
        Err(TraceCompatibilityError::ReconciliationRequired)
        | Err(TraceCompatibilityError::TickLifecycle) => {
            return Ok(DurableActionHistoryDisposition::ReconciliationRequired)
        }
        Err(error) => return Err(error),
    };
    if validated.foreign_action_ids.contains(action_id) {
        return Ok(DurableActionHistoryDisposition::ReconciliationRequired);
    }
    Ok(validated
        .histories
        .get(action_id)
        .map(ValidatedActionHistory::disposition)
        .unwrap_or(DurableActionHistoryDisposition::Fresh))
}

/// Validates current anchored history and selects the exact latest target
/// snapshot without performing state, policy, Gateway, or adapter work.
pub fn resume_trace<R: RuntimeTraceReader + ?Sized>(
    reader: &R,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
) -> Result<ResumeTraceResult, TraceCompatibilityError> {
    let inspected = inspect_trace(reader, run_id)?;
    if inspected.profile != RuntimeTraceProfile::CurrentAnchoredV1 {
        return Err(TraceCompatibilityError::LegacyInspectOnly);
    }
    validate_action_histories(&inspected.events, run_id, tenant_id, agent_id)?;

    let mut max_tick_id = 0u64;
    let mut last_started = None;
    let mut open: Option<RecoveryTickAttempt> = None;
    let mut latest_completed = None;
    let mut completed_any = false;

    for event in &inspected.events {
        if let Some(tick_id) = event.identity.tick_id.as_ref() {
            max_tick_id = max_tick_id.max(tick_id.get());
        }
        match &event.kind {
            TraceEventKind::LoopTickStarted { tick_id }
            | TraceEventKind::LoopTickCompleted { tick_id, .. } => {
                max_tick_id = max_tick_id.max(*tick_id);
            }
            _ => {}
        }
        if event.identity.tenant_id.as_ref() != Some(tenant_id)
            || event.identity.agent_id.as_ref() != Some(agent_id)
        {
            continue;
        }
        match &event.kind {
            TraceEventKind::LoopTickStarted { tick_id } => {
                if last_started.is_some_and(|last| *tick_id <= last) {
                    return Err(TraceCompatibilityError::TickLifecycle);
                }
                if let Some(incomplete) = open.take() {
                    if !incomplete.may_be_superseded() {
                        return Err(TraceCompatibilityError::ReconciliationRequired);
                    }
                }
                last_started = Some(*tick_id);
                open = Some(RecoveryTickAttempt {
                    tick_id: *tick_id,
                    action_started: false,
                    outcome_seen: false,
                    effect_evidence_seen: false,
                    state_commit_seen: false,
                    snapshot: None,
                });
            }
            TraceEventKind::ActionVerificationStarted { .. } => {
                if let Some(event_tick) = event.identity.tick_id.as_ref().map(|tick| tick.get()) {
                    let attempt = open
                        .as_mut()
                        .filter(|attempt| attempt.tick_id == event_tick)
                        .ok_or(TraceCompatibilityError::TickLifecycle)?;
                    attempt.action_started = true;
                }
            }
            TraceEventKind::ActionExecuted { .. } => {
                if let Some(event_tick) = event.identity.tick_id.as_ref().map(|tick| tick.get()) {
                    let attempt = open
                        .as_mut()
                        .filter(|attempt| attempt.tick_id == event_tick)
                        .ok_or(TraceCompatibilityError::TickLifecycle)?;
                    attempt.effect_evidence_seen = true;
                }
            }
            TraceEventKind::ActionFailed { result, .. } => {
                if result
                    .artifacts
                    .get("adapter_entered")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                {
                    let event_tick = event
                        .identity
                        .tick_id
                        .as_ref()
                        .map(|tick| tick.get())
                        .ok_or(TraceCompatibilityError::TickLifecycle)?;
                    let attempt = open
                        .as_mut()
                        .filter(|attempt| attempt.tick_id == event_tick)
                        .ok_or(TraceCompatibilityError::TickLifecycle)?;
                    attempt.effect_evidence_seen = true;
                }
            }
            TraceEventKind::OutcomeRecorded { .. } => {
                if let Some(event_tick) = event.identity.tick_id.as_ref().map(|tick| tick.get()) {
                    let attempt = open
                        .as_mut()
                        .filter(|attempt| attempt.tick_id == event_tick)
                        .ok_or(TraceCompatibilityError::TickLifecycle)?;
                    attempt.outcome_seen = true;
                }
            }
            TraceEventKind::StateCommitted {
                state_hash,
                snapshot_id,
            } => {
                let event_tick = event
                    .identity
                    .tick_id
                    .as_ref()
                    .map(|tick| tick.get())
                    .ok_or(TraceCompatibilityError::TickLifecycle)?;
                let state_node_id = event
                    .identity
                    .state_node_id
                    .clone()
                    .ok_or(TraceCompatibilityError::Envelope)?;
                let attempt = open
                    .as_mut()
                    .filter(|attempt| attempt.tick_id == event_tick)
                    .ok_or(TraceCompatibilityError::TickLifecycle)?;
                if attempt.state_commit_seen {
                    return Err(TraceCompatibilityError::TickLifecycle);
                }
                attempt.state_commit_seen = true;
                attempt.snapshot = snapshot_id.clone().map(|snapshot_id| RecoverySnapshot {
                    snapshot_id,
                    tick_id: event_tick,
                    state_node_id,
                    state_hash: state_hash.clone(),
                    trace_event_id: event.trace_event_id.clone(),
                });
            }
            TraceEventKind::LoopTickCompleted { tick_id, .. } => {
                let attempt = open
                    .take()
                    .filter(|attempt| attempt.tick_id == *tick_id)
                    .ok_or(TraceCompatibilityError::TickLifecycle)?;
                if !attempt.state_commit_seen {
                    return Err(TraceCompatibilityError::TickLifecycle);
                }
                completed_any = true;
                latest_completed = attempt.snapshot;
            }
            _ => {}
        }
    }

    if open
        .as_ref()
        .is_some_and(|attempt| !attempt.may_be_superseded())
    {
        return Err(TraceCompatibilityError::ReconciliationRequired);
    }
    let selected = match (completed_any, latest_completed) {
        (false, _) => return Err(TraceCompatibilityError::SnapshotUnavailable),
        (true, None) => return Err(TraceCompatibilityError::LatestSnapshotUnavailable),
        (true, Some(snapshot)) => snapshot,
    };
    Ok(ResumeTraceResult {
        snapshot_id: selected.snapshot_id,
        tick_id: selected.tick_id,
        state_node_id: selected.state_node_id,
        state_hash: selected.state_hash,
        trace_event_id: selected.trace_event_id,
        max_tick_id,
        tail: inspected.tail,
    })
}

struct ValidatedActionHistories {
    histories: HashMap<ActionId, ValidatedActionHistory>,
    foreign_action_ids: HashSet<ActionId>,
}

impl ValidatedActionHistory {
    fn disposition(&self) -> DurableActionHistoryDisposition {
        let Some(source) = self.source else {
            return DurableActionHistoryDisposition::ReconciliationRequired;
        };
        if self.approval_continuation_open {
            DurableActionHistoryDisposition::PendingApproval { source }
        } else {
            DurableActionHistoryDisposition::Complete { source }
        }
    }
}

fn validate_action_histories(
    events: &[TraceEvent],
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
) -> Result<ValidatedActionHistories, TraceCompatibilityError> {
    let mut histories = HashMap::<ActionId, ValidatedActionHistory>::new();
    let mut foreign_action_ids = HashSet::new();
    let mut ticks = HashMap::<ActionTickScope, ActionTickHistory>::new();
    let mut completed_ticks = HashSet::<ActionTickScope>::new();
    let mut active_tick_scope: Option<ActionTickScope> = None;
    let mut last_started_tick_id = None;

    for event in events {
        let target_scope = event.identity.tenant_id.as_ref() == Some(tenant_id)
            && event.identity.agent_id.as_ref() == Some(agent_id);
        if let Some(action_id) = event.identity.action_id.as_ref() {
            if event.identity.tenant_id.is_none() || event.identity.agent_id.is_none() {
                return Err(TraceCompatibilityError::ReconciliationRequired);
            }
            if !target_scope {
                foreign_action_ids.insert(action_id.clone());
                continue;
            }
        }

        match &event.kind {
            TraceEventKind::LoopTickStarted { tick_id } if target_scope => {
                let scope = action_tick_scope(event, *tick_id)?;
                if last_started_tick_id.is_some_and(|last_tick_id| *tick_id <= last_tick_id)
                    || completed_ticks.contains(&scope)
                {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                if let Some(previous_scope) = active_tick_scope.clone() {
                    let previous_tick = ticks
                        .get(&previous_scope)
                        .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                    let pending_episode = histories.values().any(|history| {
                        history
                            .open_episode
                            .as_ref()
                            .and_then(|episode| episode.tick_scope.as_ref())
                            == Some(&previous_scope)
                            || history
                                .pending_tick_episode
                                .as_ref()
                                .map(|episode| &episode.tick_scope)
                                == Some(&previous_scope)
                    });
                    if !incomplete_tick_may_be_superseded(
                        !previous_tick.action_order.is_empty(),
                        previous_tick.outcome_seen,
                        previous_tick.state_commit_seen,
                        pending_episode || !previous_tick.pending_actions.is_empty(),
                    ) {
                        return Err(TraceCompatibilityError::ReconciliationRequired);
                    }
                    ticks
                        .remove(&previous_scope)
                        .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                }
                if ticks
                    .insert(scope.clone(), ActionTickHistory::default())
                    .is_some()
                {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                last_started_tick_id = Some(*tick_id);
                active_tick_scope = Some(scope);
            }
            TraceEventKind::ActionVerificationStarted { action } => {
                let Some(action_id) = target_action_id(event, target_scope)? else {
                    continue;
                };
                let tick_scope = event_action_tick_scope(event)?;
                if let Some(scope) = &tick_scope {
                    let tick = ticks
                        .get_mut(scope)
                        .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                    if tick.outcome_seen || tick.state_commit_seen {
                        return Err(TraceCompatibilityError::ReconciliationRequired);
                    }
                    tick.action_order.push(action_id.clone());
                }
                let history = histories.entry(action_id).or_default();
                if history.open_episode.is_some()
                    || history.pending_tick_episode.is_some()
                    || history.action.as_ref().is_some_and(|known| known != action)
                    || !action_episode_may_start(history, tick_scope.as_ref())
                {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                history.action.get_or_insert_with(|| action.clone());
                history.open_episode = Some(ActionEpisode {
                    action: action.clone(),
                    tick_scope,
                    verification: None,
                    executed_output: None,
                    terminal: None,
                });
            }
            TraceEventKind::ActionVerificationCompleted { action, result } => {
                let Some(action_id) = target_action_id(event, target_scope)? else {
                    continue;
                };
                if effect_facts_require_reconciliation(result) {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                let episode = open_action_episode_mut(&mut histories, &action_id, event, action)?;
                if episode.verification.is_some()
                    || episode.executed_output.is_some()
                    || episode.terminal.is_some()
                {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                episode.verification = Some(result.clone());
            }
            TraceEventKind::ActionExecuted { action, outcome } => {
                let Some(action_id) = target_action_id(event, target_scope)? else {
                    continue;
                };
                let episode = open_action_episode_mut(&mut histories, &action_id, event, action)?;
                if episode.verification.is_none()
                    || episode.executed_output.is_some()
                    || episode.terminal.is_some()
                {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                episode.executed_output = Some(outcome.clone());
            }
            TraceEventKind::ActionDenied { action, result } => {
                record_action_terminal(
                    &mut histories,
                    event,
                    target_scope,
                    action,
                    result,
                    ActionEpisodeTerminal::Denied(result.clone()),
                )?;
            }
            TraceEventKind::ActionNeedsApproval { action, result } => {
                record_action_terminal(
                    &mut histories,
                    event,
                    target_scope,
                    action,
                    result,
                    ActionEpisodeTerminal::NeedsApproval(result.clone()),
                )?;
            }
            TraceEventKind::ActionNeedsIntervention { action, result } => {
                record_action_terminal(
                    &mut histories,
                    event,
                    target_scope,
                    action,
                    result,
                    ActionEpisodeTerminal::NeedsIntervention(result.clone()),
                )?;
            }
            TraceEventKind::ActionFailed {
                action,
                error,
                result,
            } => {
                let Some(action_id) = target_action_id(event, target_scope)? else {
                    continue;
                };
                if action_failure_requires_reconciliation(error, result) {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                let episode = open_action_episode_mut(&mut histories, &action_id, event, action)?;
                if episode.verification.is_none() || episode.terminal.is_some() {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                episode.terminal = Some(ActionEpisodeTerminal::Failed {
                    error: error.clone(),
                    result: result.clone(),
                });
            }
            TraceEventKind::ApprovalRequested { approval }
            | TraceEventKind::ApprovalGranted { approval } => {
                validate_action_side_event(
                    &mut histories,
                    event,
                    target_scope,
                    Some(approval),
                    true,
                )?;
            }
            TraceEventKind::ApprovalDenied { approval, .. }
            | TraceEventKind::ApprovalExpired { approval, .. }
            | TraceEventKind::ApprovalRevoked { approval, .. } => {
                validate_action_side_event(
                    &mut histories,
                    event,
                    target_scope,
                    Some(approval),
                    true,
                )?;
            }
            TraceEventKind::EscalationTriggered { .. } => {
                validate_action_side_event(&mut histories, event, target_scope, None, true)?;
            }
            TraceEventKind::PolicyExpired { .. } => {
                validate_action_side_event(&mut histories, event, target_scope, None, false)?;
            }
            TraceEventKind::OutcomeRecorded { outcome, .. }
                if event.identity.action_id.is_some() =>
            {
                let Some(action_id) = target_action_id(event, target_scope)? else {
                    continue;
                };
                if event.identity.tick_id.is_some() {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                let stored: StoredDaemonOutcome = serde_json::from_value(outcome.clone())
                    .map_err(|_| TraceCompatibilityError::ReconciliationRequired)?;
                let source = match stored.source.as_str() {
                    "daemon.action" => DurableActionHistorySource::Direct,
                    "daemon.physical_action" => DurableActionHistorySource::Physical,
                    _ => return Err(TraceCompatibilityError::ReconciliationRequired),
                };
                let history = histories
                    .get_mut(&action_id)
                    .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                let episode = history
                    .open_episode
                    .take()
                    .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                if episode.tick_scope.is_some() {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                validate_stored_action_outcome(
                    &episode,
                    &stored.action_outcome,
                    &action_id,
                    source,
                    run_id,
                    tenant_id,
                    agent_id,
                )?;
                record_completed_action(history, source, stored.action_outcome.status, None)?;
            }
            TraceEventKind::OutcomeRecorded { outcome, .. } if target_scope => {
                let tick_id = event
                    .identity
                    .tick_id
                    .as_ref()
                    .map(|tick| tick.get())
                    .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                let scope = action_tick_scope(event, tick_id)?;
                let tick = ticks
                    .get(&scope)
                    .filter(|_| active_tick_scope.as_ref() == Some(&scope))
                    .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                if tick.outcome_seen || tick.state_commit_seen {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                let stored: StoredTickOutcome = serde_json::from_value(outcome.clone())
                    .map_err(|_| TraceCompatibilityError::ReconciliationRequired)?;
                let stored_order = stored
                    .actions
                    .iter()
                    .map(|outcome| outcome.action_id.clone())
                    .collect::<Vec<_>>();
                if stored.tick_id != tick_id
                    || stored_order != tick.action_order
                    || stored.needs_approval
                        != stored
                            .actions
                            .iter()
                            .any(|outcome| outcome.status == StoredActionStatus::NeedsApproval)
                    || stored.needs_intervention
                        != stored.actions.iter().any(|outcome| {
                            outcome.status == StoredActionStatus::NeedsIntervention
                                || outcome
                                    .post_verification
                                    .as_ref()
                                    .is_some_and(|result| !result.allowed)
                        })
                {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                let action_order = tick.action_order.clone();
                for (action_id, outcome) in action_order.iter().zip(&stored.actions) {
                    let history = histories
                        .get_mut(action_id)
                        .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                    let episode = history
                        .open_episode
                        .take()
                        .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                    if episode.tick_scope.as_ref() != Some(&scope) {
                        return Err(TraceCompatibilityError::ReconciliationRequired);
                    }
                    validate_stored_action_outcome(
                        &episode,
                        outcome,
                        action_id,
                        DurableActionHistorySource::Tick,
                        run_id,
                        tenant_id,
                        agent_id,
                    )?;
                    history.pending_tick_episode = Some(PendingTickActionEpisode {
                        tick_scope: scope.clone(),
                        source: DurableActionHistorySource::Tick,
                        status: outcome.status,
                    });
                }
                let tick = ticks
                    .get_mut(&scope)
                    .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                tick.outcome_seen = true;
                tick.pending_actions = action_order;
            }
            TraceEventKind::StateCommitted { .. } if target_scope => {
                let tick_id = event
                    .identity
                    .tick_id
                    .as_ref()
                    .map(|tick| tick.get())
                    .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                let scope = action_tick_scope(event, tick_id)?;
                let tick = ticks
                    .get_mut(&scope)
                    .filter(|_| active_tick_scope.as_ref() == Some(&scope))
                    .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                if !tick.outcome_seen {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                if tick.state_commit_seen {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                tick.state_commit_seen = true;
            }
            TraceEventKind::LoopTickCompleted { tick_id, .. } if target_scope => {
                let scope = action_tick_scope(event, *tick_id)?;
                if active_tick_scope.as_ref() != Some(&scope) {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                let tick = ticks
                    .remove(&scope)
                    .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                if !tick.outcome_seen
                    || !tick.state_commit_seen
                    || tick.pending_actions != tick.action_order
                {
                    return Err(TraceCompatibilityError::ReconciliationRequired);
                }
                for action_id in tick.pending_actions {
                    let history = histories
                        .get_mut(&action_id)
                        .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                    let pending = history
                        .pending_tick_episode
                        .take()
                        .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
                    if pending.tick_scope != scope {
                        return Err(TraceCompatibilityError::ReconciliationRequired);
                    }
                    record_completed_action(
                        history,
                        pending.source,
                        pending.status,
                        Some(&pending.tick_scope),
                    )?;
                }
                active_tick_scope = None;
                completed_ticks.insert(scope);
            }
            _ if event.identity.action_id.is_some() && target_scope => {
                return Err(TraceCompatibilityError::ReconciliationRequired);
            }
            _ => {}
        }
    }

    if histories.values().any(|history| {
        history.completed_count == 0
            || history.open_episode.is_some()
            || history.pending_tick_episode.is_some()
    }) || !ticks.is_empty()
    {
        return Err(TraceCompatibilityError::ReconciliationRequired);
    }
    if histories
        .keys()
        .any(|action_id| foreign_action_ids.contains(action_id))
    {
        return Err(TraceCompatibilityError::ReconciliationRequired);
    }
    Ok(ValidatedActionHistories {
        histories,
        foreign_action_ids,
    })
}

fn target_action_id(
    event: &TraceEvent,
    target_scope: bool,
) -> Result<Option<ActionId>, TraceCompatibilityError> {
    let action_id = event
        .identity
        .action_id
        .clone()
        .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
    Ok(target_scope.then_some(action_id))
}

fn action_tick_scope(
    event: &TraceEvent,
    tick_id: u64,
) -> Result<ActionTickScope, TraceCompatibilityError> {
    if event.identity.tick_id.as_ref().map(|tick| tick.get()) != Some(tick_id) {
        return Err(TraceCompatibilityError::ReconciliationRequired);
    }
    Ok(ActionTickScope {
        tenant_id: event
            .identity
            .tenant_id
            .clone()
            .ok_or(TraceCompatibilityError::ReconciliationRequired)?,
        agent_id: event
            .identity
            .agent_id
            .clone()
            .ok_or(TraceCompatibilityError::ReconciliationRequired)?,
        tick_id,
    })
}

fn event_action_tick_scope(
    event: &TraceEvent,
) -> Result<Option<ActionTickScope>, TraceCompatibilityError> {
    event
        .identity
        .tick_id
        .as_ref()
        .map(|tick| action_tick_scope(event, tick.get()))
        .transpose()
}

fn action_episode_may_start(
    history: &ValidatedActionHistory,
    tick_scope: Option<&ActionTickScope>,
) -> bool {
    match (history.source, tick_scope) {
        (None, _) => history.completed_count == 0 && !history.approval_continuation_open,
        (Some(DurableActionHistorySource::Tick), Some(scope)) => {
            !history.approval_continuation_open
                && history
                    .last_completed_tick_id
                    .is_some_and(|last_tick_id| scope.tick_id > last_tick_id)
        }
        (Some(_), None) => history.approval_continuation_open,
        (Some(_), Some(_)) => false,
    }
}

fn open_action_episode_mut<'a>(
    histories: &'a mut HashMap<ActionId, ValidatedActionHistory>,
    action_id: &ActionId,
    event: &TraceEvent,
    action: &Action,
) -> Result<&'a mut ActionEpisode, TraceCompatibilityError> {
    let event_tick_scope = event_action_tick_scope(event)?;
    let episode = histories
        .get_mut(action_id)
        .and_then(|history| history.open_episode.as_mut())
        .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
    if &episode.action != action || episode.tick_scope != event_tick_scope {
        return Err(TraceCompatibilityError::ReconciliationRequired);
    }
    Ok(episode)
}

fn record_action_terminal(
    histories: &mut HashMap<ActionId, ValidatedActionHistory>,
    event: &TraceEvent,
    target_scope: bool,
    action: &Action,
    result: &VerificationResult,
    terminal: ActionEpisodeTerminal,
) -> Result<(), TraceCompatibilityError> {
    let Some(action_id) = target_action_id(event, target_scope)? else {
        return Ok(());
    };
    if effect_facts_require_reconciliation(result) {
        return Err(TraceCompatibilityError::ReconciliationRequired);
    }
    let episode = open_action_episode_mut(histories, &action_id, event, action)?;
    if episode.verification.is_none()
        || episode.executed_output.is_some()
        || episode.terminal.is_some()
    {
        return Err(TraceCompatibilityError::ReconciliationRequired);
    }
    episode.terminal = Some(terminal);
    Ok(())
}

fn validate_action_side_event(
    histories: &mut HashMap<ActionId, ValidatedActionHistory>,
    event: &TraceEvent,
    target_scope: bool,
    approval: Option<&ApprovalTraceContext>,
    require_verification: bool,
) -> Result<(), TraceCompatibilityError> {
    let Some(action_id) = event.identity.action_id.as_ref() else {
        return Ok(());
    };
    if !target_scope {
        return Ok(());
    }
    let event_tick_scope = event_action_tick_scope(event)?;
    let episode = histories
        .get_mut(action_id)
        .and_then(|history| history.open_episode.as_mut())
        .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
    if episode.tick_scope != event_tick_scope
        || (require_verification && episode.verification.is_none())
    {
        return Err(TraceCompatibilityError::ReconciliationRequired);
    }
    if let Some(approval) = approval {
        let event_tenant_id = event
            .identity
            .tenant_id
            .as_ref()
            .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
        let event_agent_id = event
            .identity
            .agent_id
            .as_ref()
            .ok_or(TraceCompatibilityError::ReconciliationRequired)?;
        if &approval.tenant_id != event_tenant_id
            || &approval.agent_id != event_agent_id
            || approval.run_id != event.run_id
            || approval.action_id.as_ref() != Some(action_id)
            || approval.action_name != episode.action.name
        {
            return Err(TraceCompatibilityError::ReconciliationRequired);
        }
    }
    Ok(())
}

fn validate_stored_action_outcome(
    episode: &ActionEpisode,
    outcome: &StoredActionOutcome,
    expected_action_id: &ActionId,
    source: DurableActionHistorySource,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
) -> Result<(), TraceCompatibilityError> {
    let action_id = outcome.action_id.clone();
    if &action_id != expected_action_id
        || episode.verification.as_ref() != Some(&outcome.verification)
        || episode.terminal_status() != Some(outcome.status)
        || effect_facts_require_reconciliation(&outcome.verification)
        || outcome
            .post_verification
            .as_ref()
            .is_some_and(effect_facts_require_reconciliation)
    {
        return Err(TraceCompatibilityError::ReconciliationRequired);
    }

    let terminal_matches = match (&episode.terminal, outcome.status) {
        (None, StoredActionStatus::Executed) => {
            episode.executed_output.as_ref()
                == Some(outcome.output.as_ref().unwrap_or(&serde_json::Value::Null))
                && outcome.verification.allowed
                && outcome
                    .post_verification
                    .as_ref()
                    .is_none_or(|result| result.allowed)
                && outcome.error.is_none()
        }
        (Some(ActionEpisodeTerminal::Denied(result)), StoredActionStatus::Denied) => {
            result == &outcome.verification
                && !outcome.verification.allowed
                && outcome.post_verification.is_none()
                && outcome.output.is_none()
        }
        (Some(ActionEpisodeTerminal::NeedsApproval(result)), StoredActionStatus::NeedsApproval) => {
            result == &outcome.verification
                && !outcome.verification.allowed
                && outcome.post_verification.is_none()
                && outcome.output.is_none()
        }
        (
            Some(ActionEpisodeTerminal::NeedsIntervention(result)),
            StoredActionStatus::NeedsIntervention,
        ) => {
            result == &outcome.verification
                && !outcome.verification.allowed
                && outcome.post_verification.is_none()
                && outcome.output.is_none()
        }
        (Some(ActionEpisodeTerminal::Failed { error, result }), StoredActionStatus::Failed) => {
            let expected_error = outcome.error.as_deref().unwrap_or("action_failed");
            error == expected_error
                && (Some(result) == outcome.post_verification.as_ref()
                    || result == &outcome.verification)
                && episode.executed_output.is_some() == outcome.output.is_some()
                && episode.executed_output.as_ref() == outcome.output.as_ref()
        }
        _ => false,
    };
    if !terminal_matches {
        return Err(TraceCompatibilityError::ReconciliationRequired);
    }

    match (outcome.status, outcome.approval_challenge.as_ref()) {
        (StoredActionStatus::NeedsApproval, Some(challenge))
            if challenge.tenant_id == *tenant_id
                && challenge.agent_id == *agent_id
                && challenge.run_id == *run_id
                && challenge.action_id == action_id
                && challenge.action_name == episode.action.name
                && match source {
                    DurableActionHistorySource::Physical => {
                        challenge.physical_action_resource_coordinate.is_some()
                    }
                    DurableActionHistorySource::Tick | DurableActionHistorySource::Direct => {
                        challenge.physical_action_resource_coordinate.is_none()
                    }
                } => {}
        (StoredActionStatus::NeedsApproval, _) => {
            return Err(TraceCompatibilityError::ReconciliationRequired)
        }
        (_, None) => {}
        (_, Some(_)) => return Err(TraceCompatibilityError::ReconciliationRequired),
    }
    Ok(())
}

fn record_completed_action(
    history: &mut ValidatedActionHistory,
    episode_source: DurableActionHistorySource,
    status: StoredActionStatus,
    tick_scope: Option<&ActionTickScope>,
) -> Result<(), TraceCompatibilityError> {
    let continuation_was_open = history.approval_continuation_open;
    match (history.source, episode_source, tick_scope) {
        (None, DurableActionHistorySource::Tick, Some(scope)) => {
            history.source = Some(DurableActionHistorySource::Tick);
            history.last_completed_tick_id = Some(scope.tick_id);
        }
        (None, DurableActionHistorySource::Direct, None) => {
            history.source = Some(DurableActionHistorySource::Direct);
        }
        (None, DurableActionHistorySource::Physical, None) => {
            history.source = Some(DurableActionHistorySource::Physical);
        }
        (Some(DurableActionHistorySource::Tick), DurableActionHistorySource::Tick, Some(scope))
            if !continuation_was_open
                && history
                    .last_completed_tick_id
                    .is_some_and(|last_tick_id| scope.tick_id > last_tick_id) =>
        {
            history.last_completed_tick_id = Some(scope.tick_id);
        }
        (
            Some(DurableActionHistorySource::Tick | DurableActionHistorySource::Direct),
            DurableActionHistorySource::Direct,
            None,
        ) if continuation_was_open && status != StoredActionStatus::NeedsApproval => {}
        (
            Some(DurableActionHistorySource::Physical),
            DurableActionHistorySource::Physical,
            None,
        ) if continuation_was_open && status != StoredActionStatus::NeedsApproval => {}
        _ => return Err(TraceCompatibilityError::ReconciliationRequired),
    }
    history.completed_count = history
        .completed_count
        .checked_add(1)
        .ok_or(TraceCompatibilityError::LimitExceeded)?;
    history.approval_continuation_open = status == StoredActionStatus::NeedsApproval;
    Ok(())
}

fn action_failure_requires_reconciliation(error: &str, result: &VerificationResult) -> bool {
    let suppressed_raw_output = error == RAW_CREDENTIAL_OUTPUT_SUPPRESSED
        && !result.allowed
        && result.reasons.len() == 1
        && result.reasons.first().map(String::as_str) == Some(RAW_CREDENTIAL_OUTPUT_SUPPRESSED);
    suppressed_raw_output
        || effect_facts_require_reconciliation(result)
        || result
            .artifacts
            .get("adapter_entered")
            .and_then(serde_json::Value::as_bool)
            .is_none()
}

fn effect_facts_require_reconciliation(result: &VerificationResult) -> bool {
    let adapter_entered = result.artifacts.get("adapter_entered");
    let effect_certainty = result.artifacts.get("effect_certainty");
    let reconciliation_required = result.artifacts.get("reconciliation_required");
    let Some(adapter_entered) = adapter_entered else {
        return effect_certainty.is_some() || reconciliation_required.is_some();
    };
    match adapter_entered.as_bool() {
        Some(false) => {
            effect_certainty.is_some_and(|certainty| certainty.as_str() != Some("none"))
                || reconciliation_required.is_some_and(|required| required.as_bool() != Some(false))
        }
        Some(true) => {
            let effect_is_known =
                effect_certainty.and_then(serde_json::Value::as_str) == Some("known");
            !effect_is_known
                || reconciliation_required
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true)
        }
        None => true,
    }
}

/// Validates a stable event and delegates one atomic fenced append to Store.
pub fn append_stable_trace_event<W: RuntimeTraceWriter + ?Sized>(
    writer: &W,
    expected: &RuntimeTraceTail,
    event: &TraceEvent,
) -> Result<RuntimeTraceAppend, TraceCompatibilityError> {
    if expected.profile() != RuntimeTraceProfile::CurrentAnchoredV1
        || expected.store_identity() != &writer.store_identity()
        || writer.run_id() != event.run_id.to_string()
        || event.identity.run_id != event.run_id
        || event.sequence != expected.next_sequence()
        || event.trace_event_id != TraceEventId::from_run_sequence(&event.run_id, event.sequence)
    {
        return Err(TraceCompatibilityError::Envelope);
    }
    let payload = serde_json::to_value(event).map_err(|_| TraceCompatibilityError::Envelope)?;
    let expected_hash = compute_trace_event_hash(expected.stable_tail_hash(), &payload)
        .map_err(|_| TraceCompatibilityError::Integrity)?;
    if let TraceEventKind::LoopTickCompleted { integrity, .. } = &event.kind {
        let integrity = integrity
            .as_ref()
            .ok_or(TraceCompatibilityError::CompletionIntegrity)?;
        if integrity.prev_event_hash.as_ref() != expected.stable_tail_hash()
            || integrity.event_hash != expected_hash
        {
            return Err(TraceCompatibilityError::CompletionIntegrity);
        }
    }
    let appended = writer.append(expected, payload)?;
    if appended.sequence() != event.sequence
        || appended.tail().stable_tail_hash() != Some(&expected_hash)
    {
        return Err(TraceCompatibilityError::Integrity);
    }
    Ok(appended)
}

/// Returns a fully validated projection. No record is returned before complete
/// history validation and tail reconfirmation succeed. Redacted hashes attest
/// only the returned projection and never expose source-chain hashes.
pub fn project_trace<R: RuntimeTraceReader + ?Sized>(
    reader: &R,
    run_id: &RunId,
    projection: TraceProjection,
) -> Result<Vec<TraceRecord>, TraceCompatibilityError> {
    let inspected = inspect_trace(reader, run_id)?;
    project_inspected_trace(inspected, projection, None)
}

/// Returns a fully validated half-open range projection. Complete source
/// history is validated and tail-reconfirmed before selection. A redacted
/// projection derives its integrity chain only from records in `[start, end)`.
pub fn project_trace_range<R: RuntimeTraceReader + ?Sized>(
    reader: &R,
    run_id: &RunId,
    projection: TraceProjection,
    start: u64,
    end: u64,
) -> Result<Vec<TraceRecord>, TraceCompatibilityError> {
    let inspected = inspect_trace(reader, run_id)?;
    project_inspected_trace(inspected, projection, Some((start, end)))
}

fn project_inspected_trace(
    inspected: InspectTraceResult,
    projection: TraceProjection,
    range: Option<(u64, u64)>,
) -> Result<Vec<TraceRecord>, TraceCompatibilityError> {
    let selected = inspected
        .records
        .into_iter()
        .zip(inspected.events)
        .filter(|(record, _)| match range {
            Some((start, end)) => record.sequence >= start && record.sequence < end,
            None => true,
        });
    match projection {
        TraceProjection::Trusted => Ok(selected.map(|(record, _)| record).collect()),
        TraceProjection::Redacted => redact_trace_records(selected),
    }
}

fn validate_event_envelope(
    event: &TraceEvent,
    run_id: &RunId,
    record: &TraceRecord,
    profile: RuntimeTraceProfile,
) -> Result<(), TraceCompatibilityError> {
    if &event.run_id != run_id
        || &event.identity.run_id != run_id
        || event.sequence != record.sequence
        || event.trace_event_id != TraceEventId::from_run_sequence(run_id, record.sequence)
    {
        return Err(TraceCompatibilityError::Envelope);
    }
    let kind_tick = match &event.kind {
        TraceEventKind::LoopTickStarted { tick_id }
        | TraceEventKind::LoopTickCompleted { tick_id, .. } => Some(*tick_id),
        _ => None,
    };
    if kind_tick.is_some() && event.identity.tick_id.as_ref().map(|tick| tick.get()) != kind_tick {
        return Err(TraceCompatibilityError::Envelope);
    }
    if let TraceEventKind::LoopTickCompleted { integrity, .. } = &event.kind {
        match integrity {
            Some(integrity)
                if integrity.prev_event_hash == record.prev_event_hash
                    && integrity.event_hash == record.event_hash => {}
            None if profile == RuntimeTraceProfile::LegacyUnanchored => {}
            _ => return Err(TraceCompatibilityError::CompletionIntegrity),
        }
    }
    Ok(())
}

fn redact_trace_records(
    records: impl IntoIterator<Item = (TraceRecord, TraceEvent)>,
) -> Result<Vec<TraceRecord>, TraceCompatibilityError> {
    let records = records.into_iter();
    let mut projected = Vec::with_capacity(records.size_hint().0);
    let mut previous = None;
    for (mut record, event) in records {
        record.payload =
            serde_json::to_value(event).map_err(|_| TraceCompatibilityError::Envelope)?;
        record.payload = redact_hash_candidates(redact_trace_value(record.payload));
        let event_hash = compute_redacted_trace_event_hash(previous.as_ref(), &record.payload)?;
        rewrite_projected_completion_integrity(&mut record.payload, previous.clone(), &event_hash)?;
        record.prev_event_hash = previous;
        record.event_hash = event_hash.clone();
        previous = Some(event_hash);
        projected.push(record);
    }
    Ok(projected)
}

fn redact_hash_candidates(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(redact_hash_candidates).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    (
                        redact_hash_candidate_runs(&key),
                        redact_hash_candidates(value),
                    )
                })
                .collect(),
        ),
        serde_json::Value::String(value) => {
            serde_json::Value::String(redact_hash_candidate_runs(&value))
        }
        other => other,
    }
}

fn redact_hash_candidate_runs(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut redacted = String::with_capacity(value.len());
    let mut copied_until = 0usize;
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        if !bytes[cursor].is_ascii_hexdigit() {
            cursor += 1;
            continue;
        }
        let run_start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_hexdigit() {
            cursor += 1;
        }
        if cursor - run_start >= 64 {
            redacted.push_str(&value[copied_until..run_start]);
            redacted.push_str(REDACTED_HASH_CANDIDATE);
            copied_until = cursor;
        }
    }

    if copied_until == 0 {
        return value.to_string();
    }
    redacted.push_str(&value[copied_until..]);
    redacted
}

fn compute_redacted_trace_event_hash(
    previous: Option<&ContentHash>,
    payload: &serde_json::Value,
) -> Result<ContentHash, TraceCompatibilityError> {
    let mut normalized = payload.clone();
    if let Some(completion) = normalized
        .get_mut("kind")
        .and_then(|kind| kind.get_mut("LoopTickCompleted"))
        .and_then(serde_json::Value::as_object_mut)
    {
        completion.remove("integrity");
    }
    let payload =
        serde_json::to_vec(&normalized).map_err(|_| TraceCompatibilityError::Integrity)?;
    let mut bytes = REDACTED_TRACE_HASH_DOMAIN.to_vec();
    if let Some(previous) = previous {
        bytes.extend_from_slice(previous.to_string().as_bytes());
    }
    bytes.extend_from_slice(&payload);
    Ok(ContentHash::blake3(bytes))
}

fn rewrite_projected_completion_integrity(
    payload: &mut serde_json::Value,
    previous: Option<ContentHash>,
    event_hash: &ContentHash,
) -> Result<(), TraceCompatibilityError> {
    let Some(completion) = payload
        .get_mut("kind")
        .and_then(|kind| kind.get_mut("LoopTickCompleted"))
    else {
        return Ok(());
    };
    let completion = completion
        .as_object_mut()
        .ok_or(TraceCompatibilityError::Envelope)?;
    let integrity = serde_json::to_value(TraceIntegrity {
        prev_event_hash: previous,
        event_hash: event_hash.clone(),
    })
    .map_err(|_| TraceCompatibilityError::Envelope)?;
    completion.insert("integrity".to_string(), integrity);
    Ok(())
}

fn redact_trace_value(value: serde_json::Value) -> serde_json::Value {
    redact_trace_value_at(value, RedactionPath::Root)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RedactionPath {
    Root,
    Kind,
    DaemonAudit,
    DaemonAuditAttribution,
    SingleActionEvent,
    CandidateActionsEvent,
    ActionArray,
    Action,
    Untrusted,
    Other,
}

impl RedactionPath {
    fn child(self, key: &str) -> Self {
        match (self, key) {
            (Self::Untrusted, _) => Self::Untrusted,
            (Self::Action, _) => Self::Untrusted,
            (Self::Root, "kind") => Self::Kind,
            (Self::Kind, "DaemonAudit") => Self::DaemonAudit,
            (Self::Kind, "CandidatesProposed") => Self::CandidateActionsEvent,
            (Self::Kind, key) if is_single_action_event_kind(key) => Self::SingleActionEvent,
            (Self::DaemonAudit, "audit") => Self::DaemonAuditAttribution,
            (Self::SingleActionEvent, "action") => Self::Action,
            (Self::CandidateActionsEvent, "actions") => Self::ActionArray,
            (_, key) if is_untrusted_trace_subtree_key(key) => Self::Untrusted,
            _ => Self::Other,
        }
    }

    fn array_item(self) -> Self {
        if self == Self::ActionArray {
            Self::Action
        } else {
            self
        }
    }
}

fn is_single_action_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        "ActionVerificationStarted"
            | "ActionVerificationCompleted"
            | "ActionNeedsApproval"
            | "ActionExecuted"
            | "ActionDenied"
            | "ActionFailed"
            | "ActionNeedsIntervention"
    )
}

fn is_daemon_audit_credential(path: RedactionPath, key: &str) -> bool {
    path == RedactionPath::DaemonAuditAttribution && key == "credential_id"
}

fn is_untrusted_trace_subtree_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "params"
            | "payload"
            | "outcome"
            | "output"
            | "input"
            | "feedback"
            | "reward"
            | "artifacts"
            | "details"
            | "metadata"
            | "evidence"
            | "context"
            | "data"
            | "body"
            | "headers"
            | "error"
            | "reason"
            | "reasons"
            | "policy"
            | "schema"
            | "source"
            | "name"
            | "adapter"
            | "endpoint"
            | "objective"
            | "required_permissions"
            | "preconditions"
            | "postconditions"
            | "extensions"
            | "constraints"
            | "parameters"
    )
}

fn redact_trace_value_at(value: serde_json::Value, path: RedactionPath) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .into_iter()
                .map(|item| redact_trace_value_at(item, path.array_item()))
                .collect(),
        ),
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, value) in map {
                let child_path = path.child(&key);
                let (key, value) = if is_daemon_audit_credential(path, &key) {
                    let value = if value.is_null() {
                        serde_json::Value::Null
                    } else {
                        serde_json::Value::String(REDACTED_AUDIT_CREDENTIAL_CORRELATION.to_string())
                    };
                    (key, value)
                } else if key.eq_ignore_ascii_case("credential_id") {
                    (
                        "[REDACTED:credential-id]".to_string(),
                        redact_sensitive_value(value),
                    )
                } else if is_sensitive_key(&key) {
                    let key = if path == RedactionPath::Untrusted {
                        "[REDACTED:sensitive-key]".to_string()
                    } else {
                        key
                    };
                    (key, redact_sensitive_value(value))
                } else {
                    (key, redact_trace_value_at(value, child_path))
                };
                redacted.insert(key, value);
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::String(value) => match protected_visibility_label(&value) {
            Some(label) => serde_json::Value::String(format!("[REDACTED:{label}]")),
            None if is_sensitive_text(&value) => {
                serde_json::Value::String("[REDACTED]".to_string())
            }
            None => serde_json::Value::String(value),
        },
        other => other,
    }
}

fn redact_sensitive_value(_value: serde_json::Value) -> serde_json::Value {
    serde_json::Value::String("[REDACTED]".to_string())
}

fn is_sensitive_key(key: &str) -> bool {
    if is_identity_or_reason_key(key) {
        return false;
    }
    let normalized = key.to_ascii_lowercase();
    let compacted = compact(&normalized);
    [
        "secret",
        "token",
        "password",
        "credential",
        "authorization",
        "auth_header",
        "auth_key",
        "authz",
        "bearer",
        "jwt",
        "cookie",
        "session",
        "client_secret",
        "refresh_token",
        "secret_ref",
        "signature",
        "private_key",
        "api_key",
        "access_key",
        "session_key",
        "state_bytes",
        "snapshot_bytes",
        "restricted",
        "protected_eval",
        "safety_local",
        "legal_hold",
    ]
    .iter()
    .any(|needle| normalized.contains(needle) || compacted.contains(&compact(needle)))
        || normalized == "auth"
}

fn is_identity_or_reason_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "trace_event_id"
            | "trace_id"
            | "event_id"
            | "run_id"
            | "tenant_id"
            | "agent_id"
            | "runtime_context_id"
            | "tick_id"
            | "action_id"
            | "state_node_id"
            | "message_id"
            | "work_order_id"
            | "approval_id"
            | "artifact_id"
            | "sequence"
            | "kind"
            | "type"
            | "endpoint"
            | "schema"
            | "name"
            | "adapter"
            | "source"
            | "status"
            | "reason"
            | "reasons"
            | "reason_code"
            | "code"
            | "allowed"
            | "event_hash"
            | "prev_event_hash"
    )
}

fn is_sensitive_text(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    let compacted = compact(&normalized);
    [
        "authorization:",
        "authorization=",
        "auth:",
        "auth=",
        "authz:",
        "authz=",
        "bearer ",
        "jwt:",
        "jwt=",
        "cookie:",
        "cookie=",
        "set-cookie:",
        "set-cookie=",
        "set_cookie:",
        "set_cookie=",
        "session:",
        "session=",
        "session_id:",
        "session_id=",
        "client_secret:",
        "client_secret=",
        "refresh_token:",
        "refresh_token=",
        "secret_ref:",
        "secret_ref=",
        "token:",
        "token=",
        "secret:",
        "secret=",
        "password:",
        "password=",
        "credential:",
        "credential=",
        "api_key:",
        "api_key=",
        "api-key:",
        "api-key=",
        "apikey:",
        "apikey=",
        "signature:",
        "signature=",
        "private_key:",
        "private_key=",
        "private-key:",
        "private-key=",
        "private key",
        "state_bytes:",
        "state_bytes=",
        "snapshot_bytes:",
        "snapshot_bytes=",
        "restricted:",
        "restricted=",
        "protected-eval:",
        "protected-eval=",
        "safety-local:",
        "safety-local=",
        "legal-hold:",
        "legal-hold=",
        "-----begin",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
        || [
            "authorization",
            "authheader",
            "authkey",
            "authz",
            "bearertoken",
            "jwt",
            "cookie",
            "setcookie",
            "sessionid",
            "accesstoken",
            "refreshtoken",
            "refreshjwt",
            "sessiontoken",
            "clientsecret",
            "secretref",
            "apikey",
            "privatekey",
            "statebytes",
            "snapshotbytes",
            "protectedeval",
            "safetylocal",
            "legalhold",
        ]
        .iter()
        .any(|needle| compacted.contains(needle))
        || has_sensitive_plaintext_marker(value)
        || looks_like_jwt(value)
}

fn has_sensitive_plaintext_marker(value: &str) -> bool {
    let words = value
        .split_whitespace()
        .map(|word| {
            word.trim_matches(|character: char| !character.is_ascii_alphanumeric())
                .to_ascii_lowercase()
        })
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    words.iter().any(|word| {
        matches!(
            word.as_str(),
            "authorization"
                | "auth"
                | "authz"
                | "bearer"
                | "token"
                | "secret"
                | "password"
                | "credential"
                | "signature"
                | "jwt"
                | "cookie"
                | "session"
        )
    }) || words.windows(2).any(|window| {
        matches!(
            (window[0].as_str(), window[1].as_str()),
            ("private", "key")
                | ("client", "secret")
                | ("refresh", "token")
                | ("secret", "ref")
                | ("set", "cookie")
                | ("state", "bytes")
                | ("snapshot", "bytes")
                | ("protected", "eval")
                | ("safety", "local")
                | ("legal", "hold")
        )
    })
}

fn looks_like_jwt(value: &str) -> bool {
    let parts = value.trim().split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            part.len() >= 8
                && part.chars().all(|character| {
                    character.is_ascii_alphanumeric() || character == '-' || character == '_'
                })
        })
}

fn protected_visibility_label(value: &str) -> Option<&'static str> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "restricted" => Some("restricted"),
        "secret" => Some("secret"),
        "protected-eval" => Some("protected-eval"),
        "safety-local" => Some("safety-local"),
        "legal-hold" => Some("legal-hold"),
        _ => None,
    }
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect()
}
