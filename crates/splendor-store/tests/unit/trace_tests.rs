use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use tempfile::NamedTempFile;

fn block_on<F: Future>(mut future: F) -> F::Output {
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut context = Context::from_waker(&waker);
    let mut future = unsafe { Pin::new_unchecked(&mut future) };
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => {}
        }
    }
}

fn raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        raw_waker()
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(std::ptr::null(), &VTABLE)
}

#[test]
fn trace_store_append_and_read() {
    let store = InMemoryTraceStore::default();
    let sequence =
        TraceStore::append(&store, "run-1", serde_json::json!({"ok": true})).expect("append");
    assert_eq!(sequence, 0);

    let records = TraceStore::read(&store, "run-1").expect("read");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sequence, 0);
    assert!(records[0].prev_event_hash.is_none());

    let range = TraceStore::read_range(&store, "run-1", 0, 1).expect("range");
    assert_eq!(range.len(), 1);
}

#[test]
fn trace_store_chains_hashes() {
    let store = InMemoryTraceStore::default();
    TraceStore::append(&store, "run-1", serde_json::json!({"step": 1})).expect("append");
    TraceStore::append(&store, "run-1", serde_json::json!({"step": 2})).expect("append");
    let records = TraceStore::read(&store, "run-1").expect("read");
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[1].prev_event_hash,
        Some(records[0].event_hash.clone())
    );
}

fn assert_generic_sequence_payloads_round_trip(store: &dyn TraceStore, run_id: &str) {
    let payloads = vec![
        serde_json::json!({"sequence": 99, "kind": "numeric"}),
        serde_json::json!({"sequence": "application-owned", "kind": "string"}),
        serde_json::json!({"sequence": {"nested": [0, 1]}, "kind": "nested"}),
        serde_json::json!({"sequence": null, "kind": "null"}),
        serde_json::json!({"sequence": -1, "kind": "malformed-looking"}),
        serde_json::json!({"kind": "absent"}),
    ];

    for (expected_sequence, payload) in payloads.iter().cloned().enumerate() {
        let sequence = store
            .append(run_id, payload)
            .expect("generic payload append");
        assert_eq!(sequence, expected_sequence as u64);
    }

    let records = store.read(run_id).expect("generic payload read");
    assert_eq!(
        records
            .iter()
            .map(|record| record.payload.clone())
            .collect::<Vec<_>>(),
        payloads
    );
    let exported = serde_json::to_vec(&records).expect("trace export bytes");
    let imported: Vec<TraceRecord> =
        serde_json::from_slice(&exported).expect("trace export round trip");
    assert_eq!(imported, records);
}

#[test]
fn in_memory_trace_store_preserves_generic_sequence_payloads() {
    let store = InMemoryTraceStore::default();
    assert_generic_sequence_payloads_round_trip(&store, "run-1");
}

#[test]
fn legacy_trace_store_defaults_fail_closed_and_claim_debug_is_opaque() {
    struct LegacyTraceStore;

    impl TraceStore for LegacyTraceStore {
        fn append(
            &self,
            _run_id: &str,
            _payload: serde_json::Value,
        ) -> Result<u64, TraceStoreError> {
            Ok(0)
        }

        fn read(&self, _run_id: &str) -> Result<Vec<TraceRecord>, TraceStoreError> {
            Err(TraceStoreError::RunNotFound)
        }

        fn read_range(
            &self,
            _run_id: &str,
            _start: u64,
            _end: u64,
        ) -> Result<Vec<TraceRecord>, TraceStoreError> {
            Err(TraceStoreError::RunNotFound)
        }
    }

    let store = LegacyTraceStore;
    assert!(matches!(
        store.append_if_sequence("run", 0, serde_json::json!({"ok": true})),
        Err(TraceStoreError::ConditionalAppendUnsupported)
    ));
    assert!(matches!(
        store.claim_runtime_identity("run", "tenant", "agent"),
        Err(TraceStoreError::RuntimeIdentityOwnershipUnsupported)
    ));
    let claim = RuntimeIdentityClaim {
        key: RuntimeIdentityKey::new("run", "tenant", "agent"),
        owner_token: "must-not-appear".to_string(),
    };
    assert_eq!(format!("{claim:?}"), "RuntimeIdentityClaim { .. }");
    assert!(matches!(
        store.release_runtime_identity(&claim),
        Err(TraceStoreError::RuntimeIdentityOwnershipUnsupported)
    ));
}

#[test]
fn trace_store_missing_run() {
    let store = InMemoryTraceStore::default();
    assert!(matches!(
        TraceStore::read(&store, "missing"),
        Err(TraceStoreError::RunNotFound)
    ));
    assert!(matches!(
        TraceStore::read_range(&store, "missing", 0, 1),
        Err(TraceStoreError::RunNotFound)
    ));
}

#[test]
fn sqlite_trace_store_persists_records() {
    let temp = NamedTempFile::new().expect("temp");
    let store = SqliteTraceStore::open(temp.path()).expect("open");
    TraceStore::append(&store, "run-1", serde_json::json!({"event": 1})).expect("append");
    TraceStore::append(&store, "run-1", serde_json::json!({"event": 2})).expect("append");
    let records = TraceStore::read(&store, "run-1").expect("read");
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[1].prev_event_hash,
        Some(records[0].event_hash.clone())
    );
}

#[test]
fn sqlite_trace_store_preserves_generic_sequence_payloads() {
    let temp = NamedTempFile::new().expect("temp");
    let store = SqliteTraceStore::open(temp.path()).expect("open");
    assert_generic_sequence_payloads_round_trip(&store, "run-1");
}

#[test]
fn sqlite_conditional_append_races_return_one_success_and_one_typed_conflict() {
    const RACE_COUNT: usize = 16;

    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("trace.sqlite3");
    let left = Arc::new(SqliteTraceStore::open(&path).expect("left store"));
    let right = Arc::new(SqliteTraceStore::open(&path).expect("right store"));
    for race in 0..RACE_COUNT {
        let run_id = format!("run-race-{race}");
        let start = Arc::new(Barrier::new(3));
        let handles = [Arc::clone(&left), Arc::clone(&right)]
            .into_iter()
            .map(|store| {
                let run_id = run_id.clone();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    store.append_if_sequence(
                        &run_id,
                        0,
                        serde_json::json!({"sequence": 999, "race": race}),
                    )
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("append thread"))
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
                        Err(TraceStoreError::SequenceMismatch {
                            expected: 0,
                            actual: 1
                        })
                    )
                })
                .count(),
            1,
            "race {race}: {results:?}"
        );
        let records = TraceStore::read(left.as_ref(), &run_id).expect("one persisted record");
        assert_eq!(records.len(), 1, "race {race}");
        assert_eq!(records[0].payload["sequence"], 999, "race {race}");
    }
}

#[test]
fn sqlite_conditional_append_reports_bounded_lock_contention_without_raw_busy() {
    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("trace.sqlite3");
    let store = SqliteTraceStore::open(&path).expect("trace store");
    let blocker = Connection::open(&path).expect("blocking connection");
    blocker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("acquire blocking writer transaction");

    let result = store.append_if_sequence("run-contended", 0, serde_json::json!({"ok": true}));

    assert!(matches!(
        result,
        Err(TraceStoreError::ConditionalAppendContended)
    ));
    blocker
        .execute_batch("ROLLBACK")
        .expect("release blocking writer transaction");
    assert!(matches!(
        TraceStore::read(&store, "run-contended"),
        Err(TraceStoreError::RunNotFound)
    ));
}

#[test]
fn runtime_identity_claims_are_exact_and_release_on_built_in_stores() {
    let memory = InMemoryTraceStore::default();
    let claim = memory
        .claim_runtime_identity("run", "tenant", "agent")
        .expect("memory claim");
    assert!(matches!(
        memory.claim_runtime_identity("run", "tenant", "agent"),
        Err(TraceStoreError::RuntimeIdentityAlreadyOwned { .. })
    ));
    let isolated = memory
        .claim_runtime_identity("run", "tenant", "other-agent")
        .expect("different identity remains isolated");
    memory
        .release_runtime_identity(&isolated)
        .expect("release isolated memory claim");
    memory
        .release_runtime_identity(&claim)
        .expect("release memory claim");
    let reclaimed = memory
        .claim_runtime_identity("run", "tenant", "agent")
        .expect("memory identity can be reclaimed after release");
    memory
        .release_runtime_identity(&reclaimed)
        .expect("release reclaimed memory claim");

    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("trace.sqlite3");
    let left = SqliteTraceStore::open(&path).expect("left store");
    let right = SqliteTraceStore::open(&path).expect("right store");
    let claim = left
        .claim_runtime_identity("run", "tenant", "agent")
        .expect("sqlite claim");
    assert!(matches!(
        right.claim_runtime_identity("run", "tenant", "agent"),
        Err(TraceStoreError::RuntimeIdentityAlreadyOwned { .. })
    ));
    let isolated = right
        .claim_runtime_identity("run", "tenant", "other-agent")
        .expect("different sqlite identity remains isolated");
    right
        .release_runtime_identity(&isolated)
        .expect("release isolated sqlite claim");
    left.release_runtime_identity(&claim)
        .expect("release claim");
    let reclaimed = right
        .claim_runtime_identity("run", "tenant", "agent")
        .expect("sqlite identity can be reclaimed after release");
    right
        .release_runtime_identity(&reclaimed)
        .expect("release reclaimed claim");
}

#[test]
fn sqlite_trace_store_read_only_opens_without_write_authority() {
    let temp = NamedTempFile::new().expect("temp");
    let store = SqliteTraceStore::open(temp.path()).expect("open");
    TraceStore::append(&store, "run-1", serde_json::json!({"event": 1})).expect("append");
    drop(store);

    let read_only = SqliteTraceStore::open_read_only(temp.path()).expect("read only open");
    let records = TraceStore::read(&read_only, "run-1").expect("read");
    assert_eq!(records.len(), 1);
    assert!(matches!(
        TraceStore::append(&read_only, "run-1", serde_json::json!({"event": 2})),
        Err(TraceStoreError::Sqlite(_))
    ));
}

#[test]
fn sqlite_trace_store_missing_run() {
    let temp = NamedTempFile::new().expect("temp");
    let store = SqliteTraceStore::open(temp.path()).expect("open");
    assert!(matches!(
        TraceStore::read(&store, "missing"),
        Err(TraceStoreError::RunNotFound)
    ));
}

#[test]
fn sqlite_trace_store_read_range_missing_run() {
    let temp = NamedTempFile::new().expect("temp");
    let store = SqliteTraceStore::open(temp.path()).expect("open");
    assert!(matches!(
        TraceStore::read_range(&store, "missing", 0, 1),
        Err(TraceStoreError::RunNotFound)
    ));
}

#[test]
fn sqlite_trace_store_read_range_empty_for_existing_run() {
    let temp = NamedTempFile::new().expect("temp");
    let store = SqliteTraceStore::open(temp.path()).expect("open");
    TraceStore::append(&store, "run-1", serde_json::json!({"event": 1})).expect("append");
    let records = TraceStore::read_range(&store, "run-1", 2, 2).expect("range");
    assert!(records.is_empty());
}

#[test]
fn sqlite_trace_store_read_range_returns_records() {
    let temp = NamedTempFile::new().expect("temp");
    let store = SqliteTraceStore::open(temp.path()).expect("open");
    TraceStore::append(&store, "run-1", serde_json::json!({"event": 1})).expect("append");
    TraceStore::append(&store, "run-1", serde_json::json!({"event": 2})).expect("append");

    let records = TraceStore::read_range(&store, "run-1", 0, 2).expect("range");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].sequence, 0);
}

#[test]
fn optional_hash_parts_rejects_partial_values() {
    let error = SqliteTraceStore::optional_hash_from_parts(Some("blake3".to_string()), None)
        .expect_err("error");
    assert!(matches!(error, TraceStoreError::InvalidHashParts { .. }));

    let error = SqliteTraceStore::optional_hash_from_parts(None, Some("value".to_string()))
        .expect_err("error");
    assert!(matches!(error, TraceStoreError::InvalidHashParts { .. }));
}

#[test]
fn optional_hash_parts_none_returns_none() {
    let value = SqliteTraceStore::optional_hash_from_parts(None, None).expect("ok");
    assert!(value.is_none());
}

#[test]
fn parse_algorithm_rejects_unknown() {
    let error = SqliteTraceStore::parse_algorithm("unknown").expect_err("error");
    assert!(matches!(error, TraceStoreError::InvalidHashAlgorithm(_)));
}

#[test]
fn decode_timestamp_rejects_invalid_value() {
    let error = decode_timestamp("not-a-timestamp").expect_err("error");
    assert!(matches!(error, TraceStoreError::InvalidTimestamp(_)));
}

#[test]
fn sequence_encoding_and_decoding_errors() {
    let error = encode_sequence(u64::MAX).expect_err("error");
    assert!(matches!(error, TraceStoreError::SequenceOverflow(_)));

    let error = decode_sequence(-1).expect_err("error");
    assert!(matches!(error, TraceStoreError::InvalidSequence(-1)));
}

#[test]
fn async_trace_store_round_trip() {
    let store = InMemoryTraceStore::default();
    let sequence = block_on(AsyncTraceStore::append(
        &store,
        "async-run",
        serde_json::json!({"ok": true}),
    ))
    .expect("append");
    assert_eq!(sequence, 0);

    let records = block_on(AsyncTraceStore::read(&store, "async-run")).expect("read");
    assert_eq!(records.len(), 1);

    let range = block_on(AsyncTraceStore::read_range(&store, "async-run", 0, 1)).expect("range");
    assert_eq!(range.len(), 1);
}

#[test]
fn async_sqlite_trace_store_round_trip() {
    let temp = NamedTempFile::new().expect("temp");
    let store = SqliteTraceStore::open(temp.path()).expect("open");
    let sequence = block_on(AsyncTraceStore::append(
        &store,
        "async-run",
        serde_json::json!({"ok": true}),
    ))
    .expect("append");
    assert_eq!(sequence, 0);
    let records = block_on(AsyncTraceStore::read(&store, "async-run")).expect("read");
    assert_eq!(records.len(), 1);
}

#[test]
fn async_sqlite_trace_store_read_range() {
    let temp = NamedTempFile::new().expect("temp");
    let store = SqliteTraceStore::open(temp.path()).expect("open");
    block_on(AsyncTraceStore::append(
        &store,
        "async-run",
        serde_json::json!({"event": 1}),
    ))
    .expect("append");

    let records = block_on(AsyncTraceStore::read_range(&store, "async-run", 0, 1)).expect("range");
    assert_eq!(records.len(), 1);
}

#[test]
fn trace_hash_normalizes_loop_tick_completed_integrity() {
    let payload_with_integrity = serde_json::json!({
        "kind": {
            "LoopTickCompleted": {
                "tick_id": 1,
                "integrity": {
                    "prev_event_hash": "blake3:abc",
                    "event_hash": "blake3:def"
                }
            }
        }
    });
    let payload_without_integrity = serde_json::json!({
        "kind": {
            "LoopTickCompleted": {
                "tick_id": 1
            }
        }
    });

    let store_with = InMemoryTraceStore::default();
    let sequence =
        TraceStore::append(&store_with, "run-1", payload_with_integrity).expect("append");
    let record_with = TraceStore::read(&store_with, "run-1").expect("read");
    assert_eq!(sequence, 0);

    let store_without = InMemoryTraceStore::default();
    TraceStore::append(&store_without, "run-2", payload_without_integrity).expect("append");
    let record_without = TraceStore::read(&store_without, "run-2").expect("read");

    assert_eq!(record_with[0].event_hash, record_without[0].event_hash);
}
