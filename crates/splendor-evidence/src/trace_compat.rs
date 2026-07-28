use splendor_store::{
    compute_trace_envelope_hash, compute_trace_event_hash, RuntimeTraceAppend, RuntimeTraceLimits,
    RuntimeTracePortError, RuntimeTraceProfile, RuntimeTraceReader, RuntimeTraceReaderHandle,
    RuntimeTraceScope, RuntimeTraceTail, RuntimeTraceWriter, RuntimeTraceWriterHandle,
    RuntimeTraceWriterRequest, TraceRecord, TraceStore,
};
use splendor_types::{
    AgentId, ContentHash, RunId, SnapshotId, StateNodeId, TenantId, TraceEvent, TraceEventId,
    TraceEventKind, VerificationResult,
};

const RAW_CREDENTIAL_OUTPUT_SUPPRESSED: &str = "raw_credential_output_suppressed";

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

/// External projection selected after complete validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceProjection {
    /// Preserve trusted payloads for an internal authorized consumer.
    Trusted,
    /// Deterministically redact secret/protected material for external output.
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

    while expected_sequence < tail.next_sequence() {
        let page = reader.read_page(expected_sequence)?;
        if page.records().is_empty()
            || page.records().len() > limits.page_records
            || page.next_sequence() <= expected_sequence
        {
            return Err(TraceCompatibilityError::Integrity);
        }
        for record in page.records() {
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
        if page.next_sequence() != expected_sequence {
            return Err(TraceCompatibilityError::Integrity);
        }
        if page.complete() != (expected_sequence == tail.next_sequence()) {
            return Err(TraceCompatibilityError::Integrity);
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
    reader.confirm_tail(&tail)?;
    Ok(InspectTraceResult {
        profile: tail.profile(),
        records,
        events,
        tail,
    })
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

    struct TickAttempt {
        tick_id: u64,
        effect_boundary_entered: bool,
        state_commit_seen: bool,
        snapshot: Option<ResumeSnapshot>,
    }

    struct ResumeSnapshot {
        snapshot_id: SnapshotId,
        tick_id: u64,
        state_node_id: StateNodeId,
        state_hash: ContentHash,
        trace_event_id: TraceEventId,
    }

    let mut max_tick_id = 0u64;
    let mut last_started = None;
    let mut open: Option<TickAttempt> = None;
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
        if let TraceEventKind::ActionFailed { error, result, .. } = &event.kind {
            if action_failure_requires_reconciliation(error, result) {
                return Err(TraceCompatibilityError::ReconciliationRequired);
            }
        }
        match &event.kind {
            TraceEventKind::LoopTickStarted { tick_id } => {
                if open.is_some() || last_started.is_some_and(|last| *tick_id <= last) {
                    return Err(TraceCompatibilityError::TickLifecycle);
                }
                last_started = Some(*tick_id);
                open = Some(TickAttempt {
                    tick_id: *tick_id,
                    effect_boundary_entered: false,
                    state_commit_seen: false,
                    snapshot: None,
                });
            }
            TraceEventKind::ActionVerificationStarted { .. } => {
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
                attempt.effect_boundary_entered = true;
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
                attempt.snapshot = snapshot_id.clone().map(|snapshot_id| ResumeSnapshot {
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
        .is_some_and(|attempt| attempt.effect_boundary_entered)
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

fn action_failure_requires_reconciliation(error: &str, result: &VerificationResult) -> bool {
    let effect_requires_reconciliation = result
        .artifacts
        .get("adapter_entered")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        && result
            .artifacts
            .get("reconciliation_required")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
    effect_requires_reconciliation
        || (error == RAW_CREDENTIAL_OUTPUT_SUPPRESSED
            && !result.allowed
            && result.reasons.len() == 1
            && result.reasons.first().map(String::as_str) == Some(RAW_CREDENTIAL_OUTPUT_SUPPRESSED))
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
/// history validation and tail reconfirmation succeed.
pub fn project_trace<R: RuntimeTraceReader + ?Sized>(
    reader: &R,
    run_id: &RunId,
    projection: TraceProjection,
) -> Result<Vec<TraceRecord>, TraceCompatibilityError> {
    let inspected = inspect_trace(reader, run_id)?;
    Ok(match projection {
        TraceProjection::Trusted => inspected.records,
        TraceProjection::Redacted => inspected
            .records
            .into_iter()
            .map(redact_trace_record)
            .collect(),
    })
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

fn redact_trace_record(mut record: TraceRecord) -> TraceRecord {
    record.payload = redact_trace_value(record.payload);
    record
}

fn redact_trace_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(redact_trace_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, value) in map {
                let value = if key.eq_ignore_ascii_case("credential_id")
                    && value.as_str().is_some_and(is_bounded_sha256_correlation)
                {
                    value
                } else if is_sensitive_key(&key) {
                    redact_sensitive_value(value)
                } else {
                    redact_trace_value(value)
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

fn redact_sensitive_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, redact_sensitive_value(value)))
                .collect(),
        ),
        serde_json::Value::String(value) => match protected_visibility_label(&value) {
            Some(label) => serde_json::Value::String(format!("[REDACTED:{label}]")),
            None => serde_json::Value::String("[REDACTED]".to_string()),
        },
        serde_json::Value::Null => serde_json::Value::Null,
        _ => serde_json::Value::String("[REDACTED]".to_string()),
    }
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

fn is_bounded_sha256_correlation(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
