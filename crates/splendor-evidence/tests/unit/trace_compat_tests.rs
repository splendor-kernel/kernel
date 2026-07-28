use super::*;
use splendor_store::{
    compute_trace_envelope_hash, compute_trace_event_hash, InMemoryTraceStore, RuntimeTraceLimits,
    RuntimeTracePage, RuntimeTracePortError, RuntimeTraceProfile, RuntimeTraceReader,
    RuntimeTraceStoreIdentity, RuntimeTraceTail, RuntimeTraceWriter, RuntimeTraceWriterHandle,
    TraceRecord, TraceStore,
};
use splendor_types::{
    Action, ActionId, AgentId, ContentHash, RunId, SideEffectClass, SnapshotId, StateNodeId,
    TenantId, TickId, TraceEvent, TraceEventKind, TraceIdentityContext, TraceIntegrity,
    VerificationResult,
};
use time::OffsetDateTime;

fn exact_identity(
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    tick_id: Option<u64>,
) -> TraceIdentityContext {
    let identity = TraceIdentityContext::new(run_id.clone())
        .with_tenant_agent(tenant_id.clone(), agent_id.clone());
    match tick_id {
        Some(tick_id) => identity.with_tick_id(TickId::from(tick_id)),
        None => identity,
    }
}

fn action(name: &str, params: serde_json::Value) -> Action {
    Action {
        name: name.to_string(),
        params,
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    }
}

fn current_writer(
    store: &InMemoryTraceStore,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
) -> (RuntimeTraceWriterHandle, RuntimeTraceTail) {
    let writer = acquire_current_trace_writer(
        store,
        run_id,
        tenant_id,
        agent_id,
        RuntimeTraceLimits::default(),
    )
    .expect("current writer");
    let tail = writer.tail().expect("current tail");
    (writer, tail)
}

fn append_event(
    writer: &dyn RuntimeTraceWriter,
    tail: &mut RuntimeTraceTail,
    identity: TraceIdentityContext,
    kind: TraceEventKind,
) -> TraceEvent {
    let mut event = TraceEvent::try_new_with_identity(
        identity,
        tail.next_sequence(),
        OffsetDateTime::UNIX_EPOCH,
        kind,
    )
    .expect("trace event");
    if let TraceEventKind::LoopTickCompleted { tick_id, .. } = event.kind {
        let payload = serde_json::to_value(&event).expect("completion payload");
        let event_hash =
            compute_trace_event_hash(tail.stable_tail_hash(), &payload).expect("completion hash");
        event.kind = TraceEventKind::LoopTickCompleted {
            tick_id,
            integrity: Some(TraceIntegrity {
                prev_event_hash: tail.stable_tail_hash().cloned(),
                event_hash,
            }),
        };
    }
    *tail = append_stable_trace_event(writer, tail, &event)
        .expect("semantic append")
        .into_tail();
    event
}

fn append_completed_snapshot(
    writer: &dyn RuntimeTraceWriter,
    tail: &mut RuntimeTraceTail,
    run_id: &RunId,
    tenant_id: &TenantId,
    agent_id: &AgentId,
    tick_id: u64,
    state_label: &[u8],
) -> (SnapshotId, StateNodeId, ContentHash) {
    let identity = exact_identity(run_id, tenant_id, agent_id, Some(tick_id));
    append_event(
        writer,
        tail,
        identity.clone(),
        TraceEventKind::LoopTickStarted { tick_id },
    );
    let state_hash = ContentHash::blake3(state_label);
    let state_node_id = StateNodeId::from_hash(state_hash.clone());
    let snapshot_id = SnapshotId::from_bytes(state_label);
    append_event(
        writer,
        tail,
        identity.clone().with_state_node_id(state_node_id.clone()),
        TraceEventKind::StateCommitted {
            state_hash: state_hash.clone(),
            snapshot_id: Some(snapshot_id.clone()),
        },
    );
    append_event(
        writer,
        tail,
        identity,
        TraceEventKind::LoopTickCompleted {
            tick_id,
            integrity: None,
        },
    );
    (snapshot_id, state_node_id, state_hash)
}

fn append_legacy_events(store: &InMemoryTraceStore, run_id: &RunId) {
    for (sequence, kind) in [
        TraceEventKind::LoopTickStarted { tick_id: 1 },
        TraceEventKind::LoopTickCompleted {
            tick_id: 1,
            integrity: None,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let event = TraceEvent::try_new_with_identity(
            TraceIdentityContext::new(run_id.clone()).with_tick_id(TickId::from(1)),
            sequence as u64,
            OffsetDateTime::UNIX_EPOCH,
            kind,
        )
        .expect("legacy event");
        TraceStore::append(
            store,
            &run_id.to_string(),
            serde_json::to_value(event).expect("legacy payload"),
        )
        .expect("legacy append");
    }
}

#[test]
fn legacy_history_is_valid_for_inspection_but_never_live_resume() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);
    let reader =
        open_trace_reader(&store, &run_id, RuntimeTraceLimits::default()).expect("legacy reader");

    let inspected = inspect_trace(reader.as_ref(), &run_id).expect("legacy inspection");
    assert_eq!(inspected.profile, RuntimeTraceProfile::LegacyUnanchored);
    assert_eq!(inspected.records.len(), 2);
    assert!(matches!(
        resume_trace(reader.as_ref(), &run_id, &TenantId::new(), &AgentId::new()),
        Err(TraceCompatibilityError::LegacyInspectOnly)
    ));
}

#[test]
fn current_history_resumes_exact_latest_snapshot_and_global_tick_floor() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let target_agent = AgentId::new();
    let other_agent = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &target_agent);
    let (snapshot_id, state_node_id, state_hash) = append_completed_snapshot(
        writer.as_ref(),
        &mut tail,
        &run_id,
        &tenant_id,
        &target_agent,
        1,
        b"target-state",
    );
    append_completed_snapshot(
        writer.as_ref(),
        &mut tail,
        &run_id,
        &tenant_id,
        &other_agent,
        7,
        b"other-state",
    );

    let resumed =
        resume_trace(writer.as_ref(), &run_id, &tenant_id, &target_agent).expect("exact resume");
    assert_eq!(resumed.snapshot_id, snapshot_id);
    assert_eq!(resumed.state_node_id, state_node_id);
    assert_eq!(resumed.state_hash, state_hash);
    assert_eq!(resumed.tick_id, 1);
    assert_eq!(resumed.max_tick_id, 7);
    assert_eq!(resumed.tail, tail);
}

#[test]
fn current_completion_integrity_is_required_and_cannot_be_removed_or_changed() {
    #[derive(Clone, Copy)]
    enum Corruption {
        Missing,
        Null,
        Wrong,
    }

    for corruption in [Corruption::Missing, Corruption::Null, Corruption::Wrong] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        let identity = exact_identity(&run_id, &tenant_id, &agent_id, Some(1));
        append_event(
            writer.as_ref(),
            &mut tail,
            identity.clone(),
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        );
        let mut completion = TraceEvent::try_new_with_identity(
            identity,
            tail.next_sequence(),
            OffsetDateTime::UNIX_EPOCH,
            TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: None,
            },
        )
        .expect("completion");
        if matches!(corruption, Corruption::Wrong) {
            completion.kind = TraceEventKind::LoopTickCompleted {
                tick_id: 1,
                integrity: Some(TraceIntegrity {
                    prev_event_hash: tail.stable_tail_hash().cloned(),
                    event_hash: ContentHash::blake3(b"wrong-completion-integrity"),
                }),
            };
        }
        let mut payload = serde_json::to_value(completion).expect("completion payload");
        if matches!(corruption, Corruption::Missing) {
            payload
                .pointer_mut("/kind/LoopTickCompleted")
                .and_then(serde_json::Value::as_object_mut)
                .expect("completion object")
                .remove("integrity");
        }
        writer
            .append(&tail, payload)
            .expect("mechanical store accepts compatibility-owner fixture");

        assert!(matches!(
            inspect_trace(writer.as_ref(), &run_id),
            Err(TraceCompatibilityError::CompletionIntegrity)
        ));
    }
}

#[test]
fn incomplete_effect_boundary_and_uncertain_failure_require_reconciliation() {
    for use_action_failure in [false, true] {
        let store = InMemoryTraceStore::default();
        let run_id = RunId::new();
        let tenant_id = TenantId::new();
        let agent_id = AgentId::new();
        let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
        let tick_identity = exact_identity(&run_id, &tenant_id, &agent_id, Some(1));
        append_event(
            writer.as_ref(),
            &mut tail,
            tick_identity.clone(),
            TraceEventKind::LoopTickStarted { tick_id: 1 },
        );
        let action_identity = tick_identity.with_action_id(ActionId::new());
        let candidate = action("external", serde_json::json!({"ok": true}));
        if use_action_failure {
            append_event(
                writer.as_ref(),
                &mut tail,
                action_identity,
                TraceEventKind::ActionFailed {
                    action: candidate,
                    error: "adapter_failed".to_string(),
                    result: VerificationResult {
                        allowed: false,
                        reasons: vec!["adapter_failed".to_string()],
                        artifacts: serde_json::json!({
                            "adapter_entered": true,
                            "reconciliation_required": true,
                        }),
                    },
                },
            );
        } else {
            append_event(
                writer.as_ref(),
                &mut tail,
                action_identity,
                TraceEventKind::ActionVerificationStarted { action: candidate },
            );
        }

        assert!(matches!(
            resume_trace(writer.as_ref(), &run_id, &tenant_id, &agent_id),
            Err(TraceCompatibilityError::ReconciliationRequired)
        ));
    }
}

#[test]
fn trace_limits_accept_exact_values_and_reject_limit_plus_one() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);
    let records = TraceStore::read(&store, &run_id.to_string()).expect("legacy records");
    let payload_sizes = records
        .iter()
        .map(|record| {
            serde_json::to_vec(&record.payload)
                .expect("payload bytes")
                .len()
        })
        .collect::<Vec<_>>();
    let total_bytes = payload_sizes.iter().sum::<usize>();
    let max_payload = *payload_sizes.iter().max().expect("payload maximum");

    let exact = RuntimeTraceLimits::checked(1, records.len(), total_bytes, max_payload)
        .expect("exact limits");
    let reader = open_trace_reader(&store, &run_id, exact).expect("exact reader");
    assert_eq!(
        inspect_trace(reader.as_ref(), &run_id)
            .expect("exact inspection")
            .records
            .len(),
        records.len()
    );

    let record_limited =
        RuntimeTraceLimits::checked(1, records.len() - 1, total_bytes, max_payload)
            .expect("record limit");
    let reader = open_trace_reader(&store, &run_id, record_limited).expect("record reader");
    assert!(matches!(
        inspect_trace(reader.as_ref(), &run_id),
        Err(TraceCompatibilityError::LimitExceeded)
    ));

    let byte_limited = RuntimeTraceLimits::checked(1, records.len(), total_bytes - 1, max_payload)
        .expect("byte limit");
    let reader = open_trace_reader(&store, &run_id, byte_limited).expect("byte reader");
    assert!(matches!(
        inspect_trace(reader.as_ref(), &run_id),
        Err(TraceCompatibilityError::LimitExceeded)
    ));

    let payload_limited =
        RuntimeTraceLimits::checked(1, records.len(), total_bytes, max_payload - 1)
            .expect("payload limit");
    let reader = open_trace_reader(&store, &run_id, payload_limited).expect("payload reader");
    assert!(matches!(
        inspect_trace(reader.as_ref(), &run_id),
        Err(TraceCompatibilityError::LimitExceeded)
    ));
}

#[test]
fn redacted_projection_removes_sensitive_content_after_complete_validation() {
    const CANARY: &str = "EVIDENCE_REDACTION_CANARY_NEVER_RETURN";
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    let tenant_id = TenantId::new();
    let agent_id = AgentId::new();
    let (writer, mut tail) = current_writer(&store, &run_id, &tenant_id, &agent_id);
    append_event(
        writer.as_ref(),
        &mut tail,
        exact_identity(&run_id, &tenant_id, &agent_id, None).with_action_id(ActionId::new()),
        TraceEventKind::ActionVerificationStarted {
            action: action(
                "inspect",
                serde_json::json!({
                    "secret": CANARY,
                    "schema": format!("token {CANARY}"),
                    "visibility": "protected-eval",
                    "plain_context": "causal shape retained",
                }),
            ),
        },
    );

    let trusted = project_trace(writer.as_ref(), &run_id, TraceProjection::Trusted)
        .expect("trusted projection");
    assert!(serde_json::to_string(&trusted)
        .expect("trusted JSON")
        .contains(CANARY));
    let redacted = project_trace(writer.as_ref(), &run_id, TraceProjection::Redacted)
        .expect("redacted projection");
    let encoded = serde_json::to_string(&redacted).expect("redacted JSON");
    assert!(!encoded.contains(CANARY));
    assert!(encoded.contains("[REDACTED]"));
    assert!(encoded.contains("[REDACTED:protected-eval]"));
    assert!(encoded.contains("causal shape retained"));
}

#[derive(Clone)]
struct StaticReader {
    run_id: String,
    records: Vec<TraceRecord>,
    tail: RuntimeTraceTail,
    limits: RuntimeTraceLimits,
    fail_confirmation: bool,
}

impl RuntimeTraceReader for StaticReader {
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
            end as u64,
            end == self.records.len(),
        ))
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        if self.fail_confirmation || expected != &self.tail {
            Err(RuntimeTracePortError::FenceRejected)
        } else {
            Ok(())
        }
    }
}

fn static_legacy_reader(store: &InMemoryTraceStore, run_id: &RunId) -> StaticReader {
    let source = store
        .open_runtime_reader(&run_id.to_string(), RuntimeTraceLimits::default())
        .expect("source reader");
    StaticReader {
        run_id: run_id.to_string(),
        records: TraceStore::read(store, &run_id.to_string()).expect("source records"),
        tail: source.tail().expect("source tail"),
        limits: RuntimeTraceLimits::default(),
        fail_confirmation: false,
    }
}

#[test]
fn corrupt_stable_or_storage_envelope_history_is_rejected_before_projection() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);

    let mut stable_corrupt = static_legacy_reader(&store, &run_id);
    stable_corrupt.records[0].payload["sequence"] = serde_json::json!(99);
    assert!(matches!(
        project_trace(&stable_corrupt, &run_id, TraceProjection::Redacted),
        Err(TraceCompatibilityError::Integrity)
    ));

    let mut envelope_corrupt = static_legacy_reader(&store, &run_id);
    envelope_corrupt.records[0].recorded_at = OffsetDateTime::UNIX_EPOCH
        .checked_add(time::Duration::seconds(1))
        .expect("timestamp");
    assert!(matches!(
        project_trace(&envelope_corrupt, &run_id, TraceProjection::Redacted),
        Err(TraceCompatibilityError::Integrity)
    ));
}

#[test]
fn tail_truncation_and_late_tail_change_return_no_projection() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);

    let mut truncated = static_legacy_reader(&store, &run_id);
    truncated.records.pop();
    assert!(matches!(
        project_trace(&truncated, &run_id, TraceProjection::Redacted),
        Err(TraceCompatibilityError::Integrity)
    ));

    let mut changed = static_legacy_reader(&store, &run_id);
    changed.fail_confirmation = true;
    assert!(matches!(
        project_trace(&changed, &run_id, TraceProjection::Redacted),
        Err(TraceCompatibilityError::Integrity)
    ));
}

#[test]
fn storage_envelope_hash_changes_when_nonstable_record_metadata_changes() {
    let store = InMemoryTraceStore::default();
    let run_id = RunId::new();
    append_legacy_events(&store, &run_id);
    let records = TraceStore::read(&store, &run_id.to_string()).expect("records");
    let original = compute_trace_envelope_hash(None, &records[0]).expect("original envelope");
    let mut changed = records[0].clone();
    changed.recorded_at = changed
        .recorded_at
        .checked_add(time::Duration::nanoseconds(1))
        .expect("changed timestamp");
    let changed = compute_trace_envelope_hash(None, &changed).expect("changed envelope");
    assert_ne!(original, changed);
}

#[test]
fn compatibility_errors_and_store_identity_diagnostics_are_nonreflecting() {
    let secret = "trace-path-run-hash-canary";
    let identity = RuntimeTraceStoreIdentity::from_opaque_material(secret);
    let rendered = format!("{identity:?} {:?}", TraceCompatibilityError::Integrity);
    assert!(!rendered.contains(secret));
    assert_eq!(
        TraceCompatibilityError::Store.to_string(),
        "trace_compatibility_store_failure"
    );
}
