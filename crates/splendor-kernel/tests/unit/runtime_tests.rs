use super::*;
use splendor_store::{InMemoryTraceStore, SqliteTraceStore, TraceStore, TraceStoreError};
use splendor_types::{
    AgentId, SnapshotId, StateHandoffAuthority, StateHandoffSnapshot, StateReference,
    StateReferenceMode, TenantId,
};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use time::OffsetDateTime;

#[derive(Default)]
struct CapturingSink {
    events: Arc<Mutex<Vec<TraceEvent>>>,
}

impl TraceSink for CapturingSink {
    fn record(&self, event: &TraceEvent) -> Result<(), TraceError> {
        self.events.lock().expect("events lock").push(event.clone());
        Ok(())
    }
}

#[derive(Clone, Default)]
struct ControlledSink {
    events: Arc<Mutex<Vec<TraceEvent>>>,
    fail_next: Arc<Mutex<bool>>,
}

impl ControlledSink {
    fn fail_next_record(&self) {
        *self.fail_next.lock().expect("fail_next lock") = true;
    }

    fn recorded_events(&self) -> Vec<TraceEvent> {
        self.events.lock().expect("events lock").clone()
    }
}

impl TraceSink for ControlledSink {
    fn record(&self, event: &TraceEvent) -> Result<(), TraceError> {
        let mut fail_next = self.fail_next.lock().expect("fail_next lock");
        if *fail_next {
            *fail_next = false;
            return Err(TraceError::Store(TraceStoreError::Poisoned));
        }
        drop(fail_next);

        self.events.lock().expect("events lock").push(event.clone());
        Ok(())
    }
}

fn runtime_prev_event_hash(runtime: &KernelRuntime) -> Option<ContentHash> {
    runtime
        .trace_cursor
        .lock()
        .expect("trace cursor lock")
        .prev_event_hash
        .clone()
}

#[test]
fn boot_emits_kernel_event_and_increments_sequence() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingSink {
        events: Arc::clone(&events),
    };
    let runtime = KernelRuntime::boot(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        ..KernelRuntimeConfig::default()
    })
    .expect("boot runtime");

    {
        let recorded = events.lock().expect("events lock");
        assert_eq!(recorded.len(), 1);
        assert!(matches!(
            recorded[0].kind,
            TraceEventKind::LoopTickStarted { tick_id: 0 }
        ));
        assert_eq!(recorded[0].sequence, 0);
    }

    let event = runtime
        .record_event(TraceEventKind::LoopTickCompleted {
            tick_id: 0,
            integrity: None,
        })
        .expect("record event");
    assert_eq!(event.sequence, 1);
    if let TraceEventKind::LoopTickCompleted { integrity, .. } = event.kind {
        assert!(integrity.is_some());
    } else {
        panic!("unexpected event kind");
    }

    let recorded = events.lock().expect("events lock");
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[1].sequence, 1);
    assert_eq!(recorded[1].run_id, runtime.run_id().clone());
}

#[test]
fn default_config_records_to_stdout_sink() {
    let runtime = KernelRuntime::new(KernelRuntimeConfig::default());
    let event = runtime
        .record_event(TraceEventKind::PolicyInvoked {
            policy: "default".to_string(),
        })
        .expect("record event");
    assert_eq!(event.sequence, 0);
    assert!(matches!(event.kind, TraceEventKind::PolicyInvoked { .. }));
}

#[test]
fn runtime_rejects_mismatched_trace_identity_before_persistence() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = CapturingSink {
        events: Arc::clone(&events),
    };
    let run_id = RunId::new();
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink),
        run_id: Some(run_id.clone()),
        ..KernelRuntimeConfig::default()
    });

    let error = runtime
        .record_event_with_identity(
            TraceIdentityContext::new(RunId::new()),
            TraceEventKind::PolicyInvoked {
                policy: "mismatch".to_string(),
            },
        )
        .expect_err("identity mismatch");

    assert!(matches!(error, TraceError::Identity(_)));
    assert_eq!(runtime.run_id(), &run_id);
    assert_eq!(runtime.next_sequence(), 0);
    assert!(events.lock().expect("events lock").is_empty());
}

#[test]
fn trace_sink_failure_does_not_advance_cursor_or_skip_sequence() {
    let sink = ControlledSink::default();
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink.clone()),
        ..KernelRuntimeConfig::default()
    });

    sink.fail_next_record();
    let error = runtime
        .record_event(TraceEventKind::PolicyInvoked {
            policy: "transient".to_string(),
        })
        .expect_err("forced persistence failure");

    assert!(matches!(
        error,
        TraceError::Store(TraceStoreError::Poisoned)
    ));
    assert_eq!(runtime.next_sequence(), 0);
    assert!(runtime_prev_event_hash(&runtime).is_none());
    assert!(sink.recorded_events().is_empty());

    let recovered = runtime
        .record_event(TraceEventKind::PolicyInvoked {
            policy: "recovered".to_string(),
        })
        .expect("record after failure");

    assert_eq!(recovered.sequence, 0);
    assert_eq!(runtime.next_sequence(), 1);
    let recorded = sink.recorded_events();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].sequence, 0);
}

#[test]
fn trace_sink_failure_preserves_integrity_cursor_for_recovered_completion() {
    let sink = ControlledSink::default();
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink.clone()),
        ..KernelRuntimeConfig::default()
    });

    let first = runtime
        .record_event(TraceEventKind::PolicyInvoked {
            policy: "first".to_string(),
        })
        .expect("first persisted event");
    assert_eq!(first.sequence, 0);
    let first_hash = runtime_prev_event_hash(&runtime).expect("first event hash");

    sink.fail_next_record();
    let error = runtime
        .record_event(TraceEventKind::PolicyCompleted {
            policy: "failed".to_string(),
        })
        .expect_err("forced persistence failure");
    assert!(matches!(
        error,
        TraceError::Store(TraceStoreError::Poisoned)
    ));
    assert_eq!(runtime.next_sequence(), 1);
    assert_eq!(runtime_prev_event_hash(&runtime), Some(first_hash.clone()));
    assert_eq!(sink.recorded_events().len(), 1);

    let completed = runtime
        .record_event(TraceEventKind::LoopTickCompleted {
            tick_id: 7,
            integrity: None,
        })
        .expect("completion after failure");
    assert_eq!(completed.sequence, 1);
    let expected_completed_hash =
        compute_event_hash(Some(&first_hash), &completed).expect("completion hash");
    if let TraceEventKind::LoopTickCompleted {
        integrity: Some(integrity),
        ..
    } = &completed.kind
    {
        assert_eq!(integrity.prev_event_hash.as_ref(), Some(&first_hash));
        assert_eq!(integrity.event_hash, expected_completed_hash);
    } else {
        panic!("missing completion integrity");
    }
    assert_eq!(
        runtime_prev_event_hash(&runtime),
        Some(expected_completed_hash)
    );

    let recorded = sink.recorded_events();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0].sequence, 0);
    assert_eq!(recorded[1].sequence, 1);
    assert!(matches!(
        recorded[1].kind,
        TraceEventKind::LoopTickCompleted { .. }
    ));
}

#[test]
fn concurrent_record_event_calls_keep_contiguous_sequence_and_integrity_cursor() {
    const THREAD_COUNT: usize = 8;

    let sink = ControlledSink::default();
    let runtime = Arc::new(KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(sink.clone()),
        ..KernelRuntimeConfig::default()
    }));
    let start = Arc::new(Barrier::new(THREAD_COUNT + 1));

    let handles = (0..THREAD_COUNT)
        .map(|tick_id| {
            let runtime = Arc::clone(&runtime);
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                runtime.record_event(TraceEventKind::LoopTickCompleted {
                    tick_id: tick_id as u64,
                    integrity: None,
                })
            })
        })
        .collect::<Vec<_>>();

    start.wait();
    let returned = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .expect("record thread panicked")
                .expect("record event")
        })
        .collect::<Vec<_>>();
    assert_eq!(returned.len(), THREAD_COUNT);

    let recorded = sink.recorded_events();
    assert_eq!(recorded.len(), THREAD_COUNT);
    assert_eq!(runtime.next_sequence(), THREAD_COUNT as u64);

    let mut prev_hash = None;
    for (sequence, event) in recorded.iter().enumerate() {
        assert_eq!(event.sequence, sequence as u64);
        assert_eq!(
            event.trace_event_id,
            splendor_types::TraceEventId::from_run_sequence(&event.run_id, event.sequence)
        );
        let event_hash = compute_event_hash(prev_hash.as_ref(), event).expect("event hash");
        if let TraceEventKind::LoopTickCompleted {
            integrity: Some(integrity),
            ..
        } = &event.kind
        {
            assert_eq!(integrity.prev_event_hash.as_ref(), prev_hash.as_ref());
            assert_eq!(integrity.event_hash, event_hash);
        } else {
            panic!("missing completion integrity");
        }
        prev_hash = Some(event_hash);
    }
    assert_eq!(runtime_prev_event_hash(runtime.as_ref()), prev_hash);
}

#[test]
fn independent_sqlite_runtime_writers_have_one_success_and_one_typed_conflict() {
    const RACE_COUNT: usize = 32;

    for race in 0..RACE_COUNT {
        let directory = tempfile::tempdir().expect("trace directory");
        let path = directory.path().join("trace.sqlite3");
        let run_id = RunId::new();
        let left = KernelRuntime::with_trace_store(
            Arc::new(SqliteTraceStore::open(&path).expect("left trace store")),
            Some(run_id.clone()),
        )
        .expect("left runtime");
        let right = KernelRuntime::with_trace_store(
            Arc::new(SqliteTraceStore::open(&path).expect("right trace store")),
            Some(run_id.clone()),
        )
        .expect("right runtime");
        let start = Arc::new(Barrier::new(3));

        let handles = [left, right]
            .into_iter()
            .map(|runtime| {
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    runtime.record_event(TraceEventKind::RunStarted)
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("writer thread"))
            .collect::<Vec<_>>();

        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "race {race}: {results:?}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(
                        result,
                        Err(TraceError::Store(TraceStoreError::SequenceMismatch {
                            expected: 0,
                            actual: 1
                        }))
                    )
                })
                .count(),
            1,
            "race {race}: {results:?}"
        );
        let records = SqliteTraceStore::open(&path)
            .expect("inspection store")
            .read(&run_id.to_string())
            .expect("single trace record");
        assert_eq!(records.len(), 1, "race {race}");
        assert_eq!(records[0].sequence, 0, "race {race}");
    }
}

#[test]
fn runtime_resumes_sequence_with_trace_store() {
    let store = Arc::new(InMemoryTraceStore::default());
    let run_id = RunId::new();
    let event = TraceEvent::new(
        run_id.clone(),
        0,
        OffsetDateTime::now_utc(),
        TraceEventKind::LoopTickStarted { tick_id: 1 },
    );
    let payload = serde_json::to_value(&event).expect("payload");
    let sequence =
        TraceStore::append(store.as_ref(), &run_id.to_string(), payload).expect("append");
    assert_eq!(sequence, 0);

    let runtime = KernelRuntime::with_trace_store(store, Some(run_id.clone())).expect("runtime");
    let next = runtime
        .record_event(TraceEventKind::LoopTickCompleted {
            tick_id: 1,
            integrity: None,
        })
        .expect("record event");
    assert_eq!(runtime.run_id(), &run_id);
    assert_eq!(next.sequence, 1);
    if let TraceEventKind::LoopTickCompleted { integrity, .. } = next.kind {
        assert!(integrity.is_some());
    } else {
        panic!("unexpected event kind");
    }
}

#[test]
fn loop_tick_completed_integrity_matches_trace_store_record() {
    let store = Arc::new(InMemoryTraceStore::default());
    let run_id = RunId::new();
    let runtime =
        KernelRuntime::with_trace_store(store.clone(), Some(run_id.clone())).expect("runtime");
    runtime
        .record_event(TraceEventKind::PolicyInvoked {
            policy: "unit".to_string(),
        })
        .expect("policy event");
    runtime
        .record_event(TraceEventKind::LoopTickCompleted {
            tick_id: 1,
            integrity: None,
        })
        .expect("completed event");

    let records = TraceStore::read(store.as_ref(), &run_id.to_string()).expect("records");
    let completed_record = records.last().expect("completed record");
    let completed: TraceEvent =
        serde_json::from_value(completed_record.payload.clone()).expect("completed event payload");
    if let TraceEventKind::LoopTickCompleted {
        integrity: Some(integrity),
        ..
    } = completed.kind
    {
        assert_eq!(integrity.prev_event_hash, completed_record.prev_event_hash);
        assert_eq!(integrity.event_hash, completed_record.event_hash);
    } else {
        panic!("missing completion integrity");
    }
}

#[test]
fn runtime_records_state_handoff_source_and_receiver_events() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(CapturingSink {
            events: Arc::clone(&events),
        }),
        ..KernelRuntimeConfig::default()
    });
    let run_id = runtime.run_id().clone();
    let bytes = b"handoff".to_vec();
    let mut handoff = StateHandoff {
        schema_version: "splendor.state_handoff.v0".to_string(),
        handoff_id: "handoff_runtime".to_string(),
        mode: StateReferenceMode::SnapshotImport,
        authority: StateHandoffAuthority {
            tenant_id: TenantId::new(),
            agent_id: AgentId::new(),
            run_id,
            work_order_id: "wo_runtime".to_string(),
        },
        source_instance_id: Some("source".to_string()),
        receiver_instance_id: Some("receiver".to_string()),
        previous_state_node_id: Some("blake3:previous".to_string()),
        snapshot: StateHandoffSnapshot {
            snapshot_id: SnapshotId::from_bytes(&bytes),
            state_node_id: ContentHash::blake3(&bytes).to_string(),
            parent_state_node_ids: Vec::new(),
            state_hash: ContentHash::blake3(&bytes),
            state_bytes: bytes,
            content_type: None,
        },
        source_trace_id: None,
        created_at: OffsetDateTime::now_utc(),
    };

    let exported = runtime
        .record_state_handoff_exported(&mut handoff)
        .expect("export trace");
    assert_eq!(
        handoff.source_trace_id,
        Some(exported.trace_event_id.clone())
    );
    runtime
        .record_state_handoff_imported(&handoff, "blake3:receiver")
        .expect("import trace");

    let recorded = events.lock().expect("events lock");
    assert!(matches!(
        recorded[0].kind,
        TraceEventKind::StateHandoffExported { .. }
    ));
    match &recorded[1].kind {
        TraceEventKind::StateHandoffImported { handoff: context } => {
            assert_eq!(context.source_trace_id, Some(exported.trace_event_id));
            assert_eq!(
                context.previous_state_node_id.as_deref(),
                Some("blake3:previous")
            );
            assert_eq!(
                context.receiver_state_node_id.as_deref(),
                Some("blake3:receiver")
            );
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn runtime_records_state_handoff_failure_and_read_only_reference_events() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let runtime = KernelRuntime::new(KernelRuntimeConfig {
        trace_sink: Arc::new(CapturingSink {
            events: Arc::clone(&events),
        }),
        ..KernelRuntimeConfig::default()
    });
    let run_id = runtime.run_id().clone();
    let bytes = b"handoff".to_vec();
    let authority = StateHandoffAuthority {
        tenant_id: TenantId::new(),
        agent_id: AgentId::new(),
        run_id,
        work_order_id: "wo_runtime".to_string(),
    };
    let handoff = StateHandoff {
        schema_version: "splendor.state_handoff.v0".to_string(),
        handoff_id: "handoff_failed".to_string(),
        mode: StateReferenceMode::SnapshotImport,
        authority: authority.clone(),
        source_instance_id: Some("source".to_string()),
        receiver_instance_id: Some("receiver".to_string()),
        previous_state_node_id: Some("blake3:previous".to_string()),
        snapshot: StateHandoffSnapshot {
            snapshot_id: SnapshotId::from_bytes(&bytes),
            state_node_id: ContentHash::blake3(&bytes).to_string(),
            parent_state_node_ids: Vec::new(),
            state_hash: ContentHash::blake3(&bytes),
            state_bytes: bytes,
            content_type: None,
        },
        source_trace_id: None,
        created_at: OffsetDateTime::now_utc(),
    };

    let failed = runtime
        .record_state_handoff_import_failed(&handoff, "corrupt snapshot")
        .expect("failure trace");
    let readonly_state_hash = ContentHash::blake3(b"readonly");
    let readonly_snapshot_id = SnapshotId::from_bytes(b"readonly");

    let reference = StateReference {
        reference_id: "readonly_ref".to_string(),
        mode: StateReferenceMode::ReadOnlyReference,
        authority,
        state_node_id: readonly_state_hash.to_string(),
        snapshot_id: Some(readonly_snapshot_id.clone()),
        state_hash: Some(readonly_state_hash.clone()),
        source_trace_id: Some(failed.trace_event_id.clone()),
        created_at: OffsetDateTime::now_utc(),
    };
    runtime
        .record_read_only_state_referenced(&reference)
        .expect("reference trace");

    let recorded = events.lock().expect("events lock");
    match &recorded[0].kind {
        TraceEventKind::StateHandoffImportFailed { reason, .. } => {
            assert_eq!(reason, "corrupt snapshot");
        }
        other => panic!("unexpected event: {other:?}"),
    }
    match &recorded[1].kind {
        TraceEventKind::ReadOnlyStateReferenced { handoff: context } => {
            assert_eq!(context.mode, StateReferenceMode::ReadOnlyReference);
            assert_eq!(context.receiver_state_node_id, None);
            assert_eq!(
                context.source_state_node_id,
                readonly_state_hash.to_string()
            );
            assert_eq!(context.snapshot_id, Some(readonly_snapshot_id));
            assert_eq!(context.source_trace_id, Some(failed.trace_event_id.clone()));
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[test]
fn runtime_rejects_handoff_trace_with_wrong_run_scope() {
    let runtime = KernelRuntime::new(KernelRuntimeConfig::default());
    let bytes = b"handoff".to_vec();
    let mut handoff = StateHandoff {
        schema_version: "splendor.state_handoff.v0".to_string(),
        handoff_id: "handoff_wrong_run".to_string(),
        mode: StateReferenceMode::SnapshotImport,
        authority: StateHandoffAuthority {
            tenant_id: TenantId::new(),
            agent_id: AgentId::new(),
            run_id: RunId::new(),
            work_order_id: "wo_runtime".to_string(),
        },
        source_instance_id: None,
        receiver_instance_id: None,
        previous_state_node_id: None,
        snapshot: StateHandoffSnapshot {
            snapshot_id: SnapshotId::from_bytes(&bytes),
            state_node_id: ContentHash::blake3(&bytes).to_string(),
            parent_state_node_ids: Vec::new(),
            state_hash: ContentHash::blake3(&bytes),
            state_bytes: bytes,
            content_type: None,
        },
        source_trace_id: None,
        created_at: OffsetDateTime::now_utc(),
    };

    let error = runtime
        .record_state_handoff_exported(&mut handoff)
        .expect_err("run mismatch");

    assert!(matches!(error, TraceError::HandoffRunMismatch { .. }));
    assert!(handoff.source_trace_id.is_none());
}
