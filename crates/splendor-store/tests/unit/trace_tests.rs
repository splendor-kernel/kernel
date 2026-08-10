use super::*;
use crate::{RuntimeTraceScope, MAX_RUNTIME_TRACE_PAGE_RECORDS};
use std::future::Future;
use std::pin::Pin;
use std::sync::{mpsc, Arc, Barrier, TryLockError};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::time::{Duration as StdDuration, Instant};
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

fn runtime_writer_request(
    run_id: &str,
    tenant_id: &str,
    agent_id: &str,
) -> RuntimeTraceWriterRequest {
    RuntimeTraceWriterRequest::current(
        RuntimeTraceScope::new(run_id, tenant_id, agent_id),
        RuntimeTraceLimits::default(),
    )
}

fn runtime_writer_request_with_limits(
    run_id: &str,
    limits: RuntimeTraceLimits,
) -> RuntimeTraceWriterRequest {
    RuntimeTraceWriterRequest::current(RuntimeTraceScope::new(run_id, "tenant", "agent"), limits)
}

fn anchored_growth_fixture(
    store: &dyn TraceStore,
    run_id: &str,
) -> (RuntimeTraceReaderHandle, RuntimeTraceTail, RuntimeTraceTail) {
    let writer = store
        .acquire_runtime_writer(runtime_writer_request(run_id, "tenant", "agent"))
        .expect("runtime writer");
    let first = writer
        .append(
            &writer.tail().expect("initial tail"),
            serde_json::json!({"index": 0}),
        )
        .expect("first append")
        .into_tail();
    writer
        .append(&first, serde_json::json!({"index": 1}))
        .expect("second append");
    writer.close().expect("close runtime writer");
    let reader = store
        .open_runtime_reader(run_id, RuntimeTraceLimits::default())
        .expect("runtime reader");
    let actual = reader.tail().expect("actual tail");
    (reader, first, actual)
}

fn rewrite_records_as_valid_chain(records: &mut [TraceRecord], replacement: serde_json::Value) {
    records[0].payload = replacement;
    let mut stable_tail = None;
    let mut envelope_tail = None;
    for record in records {
        record.prev_event_hash = stable_tail.clone();
        record.event_hash = compute_event_hash(stable_tail.as_ref(), &record.payload)
            .expect("rewritten event hash");
        stable_tail = Some(record.event_hash.clone());
        envelope_tail = Some(
            compute_trace_envelope_hash(envelope_tail.as_ref(), record)
                .expect("rewritten envelope hash"),
        );
    }
}

fn tail_with_incompatible_fence(tail: &RuntimeTraceTail) -> RuntimeTraceTail {
    RuntimeTraceTail::current(
        tail.store_identity().clone(),
        tail.next_sequence(),
        tail.stable_tail_hash().cloned(),
        tail.envelope_tail_hash().cloned(),
        tail.anchor_revision(),
        RuntimeTraceFence::from_opaque_material("incompatible-fence"),
    )
    .expect("incompatible fenced tail")
}

fn assert_runtime_writer_limits(store: &dyn TraceStore, prefix: &str) {
    let payload = serde_json::json!("x");
    let payload_bytes = serde_json::to_vec(&payload).expect("payload bytes").len();

    let record_run = format!("{prefix}-record-limit");
    let record_limits = RuntimeTraceLimits::checked(1, 2, 1_024, 1_024).expect("record limits");
    let writer = store
        .acquire_runtime_writer(runtime_writer_request_with_limits(
            &record_run,
            record_limits,
        ))
        .expect("record-limit writer");
    let mut tail = writer.tail().expect("record-limit tail");
    for _ in 0..2 {
        tail = writer
            .append(&tail, payload.clone())
            .expect("append at record limit")
            .into_tail();
    }
    assert!(matches!(
        writer.append(&tail, payload.clone()),
        Err(RuntimeTracePortError::LimitExceeded)
    ));
    writer.close().expect("close record-limit writer");

    let byte_run = format!("{prefix}-byte-limit");
    let byte_limits =
        RuntimeTraceLimits::checked(1, 3, payload_bytes * 2, payload_bytes).expect("byte limits");
    let writer = store
        .acquire_runtime_writer(runtime_writer_request_with_limits(&byte_run, byte_limits))
        .expect("byte-limit writer");
    let mut tail = writer.tail().expect("byte-limit tail");
    for _ in 0..2 {
        tail = writer
            .append(&tail, payload.clone())
            .expect("append at byte limit")
            .into_tail();
    }
    assert!(matches!(
        writer.append(&tail, payload.clone()),
        Err(RuntimeTracePortError::LimitExceeded)
    ));
    writer.close().expect("close byte-limit writer");

    let payload_run = format!("{prefix}-payload-limit");
    let payload_limits =
        RuntimeTraceLimits::checked(1, 1, 1_024, payload_bytes - 1).expect("payload limits");
    let writer = store
        .acquire_runtime_writer(runtime_writer_request_with_limits(
            &payload_run,
            payload_limits,
        ))
        .expect("payload-limit writer");
    let tail = writer.tail().expect("payload-limit tail");
    assert!(matches!(
        writer.append(&tail, payload),
        Err(RuntimeTracePortError::LimitExceeded)
    ));
    writer.close().expect("close payload-limit writer");

    let exact_payload = serde_json::json!("exact");
    let exact_payload_bytes = serde_json::to_vec(&exact_payload)
        .expect("exact payload bytes")
        .len();
    let exact_payload_run = format!("{prefix}-exact-payload-limit");
    let exact_payload_limits =
        RuntimeTraceLimits::checked(1, 1, exact_payload_bytes, exact_payload_bytes)
            .expect("exact payload limits");
    let writer = store
        .acquire_runtime_writer(runtime_writer_request_with_limits(
            &exact_payload_run,
            exact_payload_limits,
        ))
        .expect("exact-payload writer");
    let tail = writer.tail().expect("exact-payload tail");
    writer
        .append(&tail, exact_payload)
        .expect("append at exact payload and aggregate byte limits");
    writer.close().expect("close exact-payload writer");

    assert!(RuntimeTraceLimits::checked(
        MAX_RUNTIME_TRACE_PAGE_RECORDS,
        MAX_RUNTIME_TRACE_PAGE_RECORDS,
        1_024,
        1_024,
    )
    .is_ok());
    assert!(matches!(
        RuntimeTraceLimits::checked(
            MAX_RUNTIME_TRACE_PAGE_RECORDS + 1,
            MAX_RUNTIME_TRACE_PAGE_RECORDS + 1,
            1_024,
            1_024,
        ),
        Err(RuntimeTracePortError::LimitExceeded)
    ));
}

fn assert_runtime_append_close_linearization(store: Arc<dyn TraceStore>, prefix: &str) {
    for race in 0..16 {
        let run_id = format!("{prefix}-append-close-{race}");
        let writer = store
            .acquire_runtime_writer(runtime_writer_request(&run_id, "tenant", "agent"))
            .expect("runtime writer");
        let tail = writer.tail().expect("initial tail");
        let start = Arc::new(Barrier::new(3));
        let append_writer = Arc::clone(&writer);
        let append_start = Arc::clone(&start);
        let append_tail = tail.clone();
        let append = std::thread::spawn(move || {
            append_start.wait();
            append_writer.append(&append_tail, serde_json::json!({"race": race}))
        });
        let close_writer = Arc::clone(&writer);
        let close_start = Arc::clone(&start);
        let close = std::thread::spawn(move || {
            close_start.wait();
            close_writer.close()
        });
        start.wait();
        let append = append.join().expect("append thread");
        close
            .join()
            .expect("close thread")
            .expect("linearized close");
        let append_succeeded = append.is_ok();
        assert!(append_succeeded || matches!(&append, Err(RuntimeTracePortError::Closed)));
        assert!(matches!(
            writer.append(&tail, serde_json::json!({"late": true})),
            Err(RuntimeTracePortError::Closed)
        ));

        let reader = store
            .open_runtime_reader(&run_id, RuntimeTraceLimits::default())
            .expect("post-close reader");
        let persisted = reader.tail().expect("post-close tail").next_sequence();
        assert_eq!(persisted, u64::from(append_succeeded));
        let reclaimed = store
            .acquire_runtime_writer(runtime_writer_request(&run_id, "tenant", "agent"))
            .expect("writer reclaimed after close");
        reclaimed.close().expect("close reclaimed writer");
    }
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
fn legacy_trace_store_runtime_capabilities_default_deny_and_debug_is_opaque() {
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
        store.runtime_store_identity(),
        Err(RuntimeTracePortError::Unsupported)
    ));
    assert!(matches!(
        store.open_runtime_reader("run", RuntimeTraceLimits::default()),
        Err(RuntimeTracePortError::Unsupported)
    ));
    assert!(matches!(
        store.acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent")),
        Err(RuntimeTracePortError::Unsupported)
    ));
    let scope = RuntimeTraceScope::new("run-secret", "tenant-secret", "agent-secret");
    let rendered = format!("{scope:?}");
    assert_eq!(rendered, "RuntimeTraceScope { .. }");
    assert!(!rendered.contains("secret"));
}

#[test]
fn runtime_trace_capability_value_contracts_are_bounded_and_redacted() {
    let store_identity = RuntimeTraceStoreIdentity::from_opaque_material("store-secret");
    let fence = RuntimeTraceFence::from_opaque_material("fence-secret");
    assert_eq!(format!("{fence:?}"), "RuntimeTraceFence([REDACTED])");

    let scope = RuntimeTraceScope::new("run-secret", "tenant-secret", "agent-secret");
    assert_eq!(scope.run_id(), "run-secret");
    assert_eq!(scope.tenant_id(), "tenant-secret");
    assert_eq!(scope.agent_id(), "agent-secret");

    let limits = RuntimeTraceLimits::checked(2, 4, 1_024, 512).expect("valid limits");
    let request = RuntimeTraceWriterRequest::current(scope, limits);
    assert_eq!(request.scope().run_id(), "run-secret");
    assert_eq!(request.limits(), limits);
    assert_eq!(request.profile(), RuntimeTraceProfile::CurrentAnchoredV1);
    let request_debug = format!("{request:?}");
    assert!(request_debug.contains("CurrentAnchoredV1"));
    assert!(!request_debug.contains("secret"));

    let current =
        RuntimeTraceTail::current(store_identity.clone(), 0, None, None, 7, fence.clone())
            .expect("empty current tail");
    let tail_debug = format!("{current:?}");
    assert!(tail_debug.contains("CurrentAnchoredV1"));
    assert!(tail_debug.contains("anchor_revision: 7"));
    assert!(!tail_debug.contains("secret"));

    let page = RuntimeTracePage::new(Vec::new(), 9, true);
    assert_eq!(
        format!("{page:?}"),
        "RuntimeTracePage { record_count: 0, next_sequence: 9, complete: true }"
    );

    let hash = ContentHash::blake3(b"tail");
    assert_eq!(
        RuntimeTraceTail::current(
            store_identity.clone(),
            0,
            Some(hash.clone()),
            None,
            0,
            fence.clone(),
        ),
        Err(RuntimeTracePortError::IntegrityFailure)
    );
    assert_eq!(
        RuntimeTraceTail::current(store_identity.clone(), 1, None, None, 0, fence,),
        Err(RuntimeTracePortError::IntegrityFailure)
    );
    assert_eq!(
        RuntimeTraceTail::legacy(store_identity.clone(), 0, Some(hash), None),
        Err(RuntimeTracePortError::IntegrityFailure)
    );
    assert_eq!(
        RuntimeTraceTail::legacy(store_identity, 1, None, None),
        Err(RuntimeTracePortError::IntegrityFailure)
    );
}

#[test]
fn sqlite_in_memory_path_initializes_without_filesystem_lock_authority() {
    let store = SqliteTraceStore::open(":memory:").expect("in-memory sqlite trace store");
    assert_eq!(
        TraceStore::append(&store, "run", serde_json::json!({"event": "memory"})).expect("append"),
        0
    );
    assert_eq!(TraceStore::read(&store, "run").expect("read").len(), 1);
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

#[cfg(unix)]
#[test]
fn sqlite_file_uri_semantics_are_rejected() {
    let directory = tempfile::tempdir().expect("trace directory");
    let uri_path = PathBuf::from(format!(
        "file:splendor-trace-uri-{}.sqlite3?mode=memory",
        Uuid::new_v4()
    ));

    let writable = SqliteTraceStore::open_with_lock_root(&uri_path, directory.path().join("locks"));
    let read_only = SqliteTraceStore::open_read_only(&uri_path);
    let _ = std::fs::remove_file(&uri_path);

    assert!(matches!(
        writable,
        Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidPath(_)))
    ));
    assert!(matches!(
        read_only,
        Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidPath(_)))
    ));
}

#[cfg(unix)]
#[test]
fn sqlite_file_backed_store_accepts_symlinked_parent_spelling() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("trace directory");
    let real_parent = directory.path().join("real-parent");
    let parent_alias = directory.path().join("parent-alias");
    std::fs::create_dir(&real_parent).expect("real database parent");
    symlink(&real_parent, &parent_alias).expect("database parent alias");
    let path = parent_alias.join("trace.sqlite3");

    let writable = SqliteTraceStore::open(&path).expect("writable trace store through alias");
    TraceStore::append(&writable, "run", serde_json::json!({"event": 1}))
        .expect("append through alias");
    drop(writable);

    let read_only = SqliteTraceStore::open_read_only(&path).expect("read-only store through alias");
    assert_eq!(
        TraceStore::read(&read_only, "run").expect("read through alias")[0].payload,
        serde_json::json!({"event": 1})
    );
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
                    store.acquire_runtime_writer(runtime_writer_request(&run_id, "tenant", "agent"))
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("append thread"))
            .collect::<Vec<_>>();
        let statuses = results
            .iter()
            .map(|result| match result {
                Ok(_) => "ok".to_string(),
                Err(error) => error.to_string(),
            })
            .collect::<Vec<_>>();

        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "race {race}: {statuses:?}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(RuntimeTracePortError::Conflict)))
                .count(),
            1,
            "race {race}: {statuses:?}"
        );
        let writer = results
            .into_iter()
            .find_map(Result::ok)
            .expect("one writer");
        let tail = writer.tail().expect("initial tail");
        writer
            .append(&tail, serde_json::json!({"sequence": 999, "race": race}))
            .expect("fenced append");
        writer.close().expect("close writer");
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

    let result =
        store.acquire_runtime_writer(runtime_writer_request("run-contended", "tenant", "agent"));

    assert!(matches!(result, Err(RuntimeTracePortError::Conflict)));
    blocker
        .execute_batch("ROLLBACK")
        .expect("release blocking writer transaction");
    assert!(matches!(
        TraceStore::read(&store, "run-contended"),
        Err(TraceStoreError::RunNotFound)
    ));
}

#[test]
fn runtime_writer_capabilities_are_exclusive_and_release_on_built_in_stores() {
    let memory = InMemoryTraceStore::default();
    let writer = memory
        .acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent"))
        .expect("memory writer");
    assert!(matches!(
        memory.acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent")),
        Err(RuntimeTracePortError::Conflict)
    ));
    assert!(matches!(
        memory.acquire_runtime_writer(runtime_writer_request("run", "tenant", "other-agent")),
        Err(RuntimeTracePortError::Conflict)
    ));
    writer.close().expect("release memory writer");
    let reclaimed = memory
        .acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent"))
        .expect("memory writer can be reacquired after close");
    reclaimed.close().expect("close reclaimed memory writer");

    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("trace.sqlite3");
    let left = SqliteTraceStore::open(&path).expect("left store");
    let right = SqliteTraceStore::open(&path).expect("right store");
    let writer = left
        .acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent"))
        .expect("sqlite writer");
    assert!(matches!(
        right.acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent")),
        Err(RuntimeTracePortError::Conflict)
    ));
    assert!(matches!(
        right.acquire_runtime_writer(runtime_writer_request("run", "tenant", "other-agent")),
        Err(RuntimeTracePortError::Conflict)
    ));
    writer.close().expect("release sqlite writer");
    let reclaimed = right
        .acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent"))
        .expect("sqlite writer can be reacquired after release");
    reclaimed.close().expect("close reclaimed sqlite writer");
}

#[test]
fn runtime_writer_capabilities_enforce_exact_and_limit_plus_one_bounds() {
    let memory = InMemoryTraceStore::default();
    assert_runtime_writer_limits(&memory, "memory");

    let directory = tempfile::tempdir().expect("trace directory");
    let sqlite =
        SqliteTraceStore::open(directory.path().join("trace.sqlite3")).expect("sqlite trace store");
    assert_runtime_writer_limits(&sqlite, "sqlite");
}

#[test]
fn runtime_writer_append_and_close_are_linearized_and_post_close_append_is_denied() {
    assert_runtime_append_close_linearization(Arc::new(InMemoryTraceStore::default()), "memory");

    let directory = tempfile::tempdir().expect("trace directory");
    let sqlite: Arc<dyn TraceStore> = Arc::new(
        SqliteTraceStore::open(directory.path().join("trace.sqlite3")).expect("sqlite trace store"),
    );
    assert_runtime_append_close_linearization(sqlite, "sqlite");
}

#[test]
fn in_memory_tail_confirmation_holds_anchor_before_records_without_deadlock() {
    let store = Arc::new(InMemoryTraceStore::default());
    let writer = store
        .acquire_runtime_writer(runtime_writer_request("linearized-run", "tenant", "agent"))
        .expect("runtime writer");
    let expected = writer
        .append(
            &writer.tail().expect("initial tail"),
            serde_json::json!({"index": 0}),
        )
        .expect("initial append")
        .into_tail();
    let reader = store
        .open_runtime_reader("linearized-run", RuntimeTraceLimits::default())
        .expect("runtime reader");

    let records_guard = store.inner.lock().expect("hold records lock");
    let (confirmation_tx, confirmation_rx) = mpsc::channel();
    let confirmation_expected = expected.clone();
    let confirmation = std::thread::spawn(move || {
        confirmation_tx
            .send(reader.confirm_tail(&confirmation_expected))
            .expect("send confirmation result");
    });

    let deadline = Instant::now() + StdDuration::from_secs(2);
    loop {
        match store.runtime_anchors.try_lock() {
            Err(TryLockError::WouldBlock) => break,
            Err(TryLockError::Poisoned(_)) => panic!("runtime anchor mutex poisoned"),
            Ok(guard) => drop(guard),
        }
        assert!(
            Instant::now() < deadline,
            "confirmation did not retain the anchor while waiting for records"
        );
        std::thread::yield_now();
    }

    let append_writer = Arc::clone(&writer);
    let append_expected = expected.clone();
    let (append_tx, append_rx) = mpsc::channel();
    let append = std::thread::spawn(move || {
        append_tx
            .send(append_writer.append(&append_expected, serde_json::json!({"index": 1})))
            .expect("send append result");
    });
    drop(records_guard);

    confirmation_rx
        .recv_timeout(StdDuration::from_secs(2))
        .expect("confirmation completed")
        .expect("confirmation linearized before append");
    append_rx
        .recv_timeout(StdDuration::from_secs(2))
        .expect("append completed")
        .expect("append completed after confirmation");
    confirmation.join().expect("confirmation thread");
    append.join().expect("append thread");
    writer.close().expect("close runtime writer");
}

fn rewrite_in_memory_prefix_as_valid_history(store: &InMemoryTraceStore, run_id: &str) {
    let mut anchors = store.runtime_anchors.lock().expect("runtime anchors");
    let mut records = store.inner.lock().expect("runtime records");
    let run_records = records.get_mut(run_id).expect("run records");
    rewrite_records_as_valid_chain(run_records, serde_json::json!({"rewritten": true}));
    let anchor = anchors.get_mut(run_id).expect("runtime anchor");
    let current = anchor.tail.clone();
    let envelope_tail = run_records
        .iter()
        .try_fold(None, |previous, record| {
            compute_trace_envelope_hash(previous.as_ref(), record).map(Some)
        })
        .expect("rewritten envelope tail");
    anchor.tail = RuntimeTraceTail::current(
        current.store_identity().clone(),
        u64::try_from(run_records.len()).expect("record count"),
        run_records.last().map(|record| record.event_hash.clone()),
        envelope_tail,
        current.anchor_revision(),
        current.fence().cloned().expect("runtime fence"),
    )
    .expect("rewritten runtime anchor");
}

#[test]
fn in_memory_tail_confirmation_distinguishes_growth_from_integrity_failure() {
    let store = InMemoryTraceStore::default();
    let (reader, expected, actual) = anchored_growth_fixture(&store, "valid-growth");
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::FenceRejected)
    );
    assert_eq!(
        reader.confirm_tail(&tail_with_incompatible_fence(&expected)),
        Err(RuntimeTracePortError::IntegrityFailure)
    );
    reader.confirm_tail(&actual).expect("equal actual tail");

    let store = InMemoryTraceStore::default();
    let (reader, expected, _) = anchored_growth_fixture(&store, "rewritten-prefix");
    rewrite_in_memory_prefix_as_valid_history(&store, "rewritten-prefix");
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::IntegrityFailure)
    );

    let store = InMemoryTraceStore::default();
    let (reader, expected, _) = anchored_growth_fixture(&store, "corrupt-extension");
    let anchors = store.runtime_anchors.lock().expect("runtime anchors");
    let mut records = store.inner.lock().expect("runtime records");
    records.get_mut("corrupt-extension").expect("run records")[1].payload =
        serde_json::json!({"corrupt": true});
    drop(records);
    drop(anchors);
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::IntegrityFailure)
    );

    let store = InMemoryTraceStore::default();
    let (reader, expected, _) = anchored_growth_fixture(&store, "truncated");
    let anchors = store.runtime_anchors.lock().expect("runtime anchors");
    let _ = store
        .inner
        .lock()
        .expect("runtime records")
        .get_mut("truncated")
        .expect("run records")
        .pop();
    drop(anchors);
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::IntegrityFailure)
    );
}

#[test]
fn anchored_runs_reject_legacy_appends_without_mutation() {
    let memory = InMemoryTraceStore::default();
    let writer = memory
        .acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent"))
        .expect("memory writer");
    assert!(matches!(
        TraceStore::append(&memory, "run", serde_json::json!({"legacy": true})),
        Err(TraceStoreError::SequenceMismatch { .. })
    ));
    assert_eq!(writer.tail().expect("memory tail").next_sequence(), 0);
    writer.close().expect("close memory writer");

    let directory = tempfile::tempdir().expect("trace directory");
    let sqlite =
        SqliteTraceStore::open(directory.path().join("trace.sqlite3")).expect("sqlite trace store");
    let writer = sqlite
        .acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent"))
        .expect("sqlite writer");
    assert!(matches!(
        TraceStore::append(&sqlite, "run", serde_json::json!({"legacy": true})),
        Err(TraceStoreError::SequenceMismatch { .. })
    ));
    assert_eq!(writer.tail().expect("sqlite tail").next_sequence(), 0);
    writer.close().expect("close sqlite writer");
}

#[test]
fn sqlite_empty_legacy_schema_migrates_idempotently_to_current_profile() {
    let database = NamedTempFile::new().expect("legacy database");
    Connection::open(database.path())
        .expect("legacy connection")
        .execute_batch(
            r#"
            CREATE TABLE trace_events (
              run_id TEXT NOT NULL,
              sequence INTEGER NOT NULL,
              payload BLOB NOT NULL,
              recorded_at TEXT NOT NULL,
              event_hash_algo TEXT NOT NULL,
              event_hash_value TEXT NOT NULL,
              prev_hash_algo TEXT,
              prev_hash_value TEXT,
              PRIMARY KEY (run_id, sequence)
            );
            "#,
        )
        .expect("legacy schema");

    for _ in 0..2 {
        let store = SqliteTraceStore::open(database.path()).expect("idempotent migration");
        let writer = store
            .acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent"))
            .expect("current writer after empty migration");
        assert_eq!(
            writer.tail().expect("current tail").profile(),
            RuntimeTraceProfile::CurrentAnchoredV1
        );
        writer.close().expect("close migrated writer");
    }
}

#[test]
fn sqlite_nonempty_unanchored_history_remains_byte_stable_and_inspect_only() {
    let database = NamedTempFile::new().expect("legacy database");
    let store = SqliteTraceStore::open(database.path()).expect("trace store");
    TraceStore::append(
        &store,
        "legacy-run",
        serde_json::json!({"legacy": true, "sequence": "application-owned"}),
    )
    .expect("legacy append");
    let before = TraceStore::read(&store, "legacy-run").expect("legacy bytes");
    drop(store);

    let reopened = SqliteTraceStore::open(database.path()).expect("reopen migrated store");
    let reader = reopened
        .open_runtime_reader("legacy-run", RuntimeTraceLimits::default())
        .expect("legacy reader");
    assert_eq!(
        reader.tail().expect("legacy tail").profile(),
        RuntimeTraceProfile::LegacyUnanchored
    );
    assert!(matches!(
        reopened.acquire_runtime_writer(runtime_writer_request("legacy-run", "tenant", "agent")),
        Err(RuntimeTracePortError::LegacyInspectOnly)
    ));
    assert_eq!(
        TraceStore::read(&reopened, "legacy-run").expect("unchanged legacy bytes"),
        before
    );
}

#[test]
fn sqlite_failed_schema_migration_rolls_back_all_additive_objects() {
    let database = NamedTempFile::new().expect("failed-migration database");
    let connection = Connection::open(database.path()).expect("fixture connection");
    connection
        .execute_batch(
            r#"
            CREATE TABLE migration_sentinel (value TEXT NOT NULL);
            INSERT INTO migration_sentinel (value) VALUES ('preserve');
            CREATE TABLE trace_store_metadata (
              metadata_key TEXT PRIMARY KEY
            );
            "#,
        )
        .expect("incompatible fixture schema");
    drop(connection);

    assert!(SqliteTraceStore::open(database.path()).is_err());
    let connection = Connection::open(database.path()).expect("post-failure inspection");
    let sentinel: String = connection
        .query_row("SELECT value FROM migration_sentinel", [], |row| row.get(0))
        .expect("sentinel preserved");
    assert_eq!(sentinel, "preserve");
    let additive_objects: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('trace_run_anchor_registry', 'trace_run_anchors', 'trace_append_permits')",
            [],
            |row| row.get(0),
        )
        .expect("additive object count");
    assert_eq!(additive_objects, 0);
}

fn sqlite_anchored_fixture(
    path: &std::path::Path,
    run_id: &str,
    record_count: usize,
) -> (SqliteTraceStore, RuntimeTraceReaderHandle, RuntimeTraceTail) {
    let store = SqliteTraceStore::open(path).expect("sqlite trace store");
    let writer = store
        .acquire_runtime_writer(runtime_writer_request(run_id, "tenant", "agent"))
        .expect("sqlite runtime writer");
    let mut tail = writer.tail().expect("initial tail");
    for index in 0..record_count {
        tail = writer
            .append(&tail, serde_json::json!({"index": index}))
            .expect("anchored append")
            .into_tail();
    }
    writer.close().expect("close sqlite runtime writer");
    let reader = store
        .open_runtime_reader(run_id, RuntimeTraceLimits::default())
        .expect("sqlite runtime reader");
    let tail = reader.tail().expect("closed anchored tail");
    (store, reader, tail)
}

fn rewrite_sqlite_prefix_as_valid_history(path: &Path, store: &SqliteTraceStore, run_id: &str) {
    let mut records = TraceStore::read(store, run_id).expect("runtime records");
    rewrite_records_as_valid_chain(&mut records, serde_json::json!({"rewritten": true}));
    let envelope_tail = records
        .iter()
        .try_fold(None, |previous, record| {
            compute_trace_envelope_hash(previous.as_ref(), record).map(Some)
        })
        .expect("rewritten envelope tail")
        .expect("non-empty envelope tail");
    let stable_tail = records
        .last()
        .expect("non-empty runtime records")
        .event_hash
        .clone();

    let mut connection = Connection::open(path).expect("tamper connection");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("rewrite transaction");
    transaction
        .execute_batch("DROP TRIGGER trace_anchored_update_guard")
        .expect("disable fixture update guard");
    for record in &records {
        let payload = serde_json::to_vec(&record.payload).expect("rewritten payload bytes");
        let (previous_algorithm, previous_value) = record
            .prev_event_hash
            .as_ref()
            .map(|hash| (Some(hash.algorithm.as_str()), Some(hash.value.as_str())))
            .unwrap_or((None, None));
        transaction
            .execute(
                "UPDATE trace_events SET payload = ?1, event_hash_algo = ?2, event_hash_value = ?3, prev_hash_algo = ?4, prev_hash_value = ?5 WHERE run_id = ?6 AND sequence = ?7",
                params![
                    payload,
                    record.event_hash.algorithm.as_str(),
                    record.event_hash.value.as_str(),
                    previous_algorithm,
                    previous_value,
                    run_id,
                    encode_port_sequence(record.sequence).expect("encoded sequence"),
                ],
            )
            .expect("rewrite runtime row");
    }
    transaction
        .execute(
            "UPDATE trace_run_anchors SET stable_tail_hash_algo = ?1, stable_tail_hash_value = ?2, envelope_tail_hash_algo = ?3, envelope_tail_hash_value = ?4, anchor_revision = anchor_revision + 1 WHERE run_id = ?5",
            params![
                stable_tail.algorithm.as_str(),
                stable_tail.value,
                envelope_tail.algorithm.as_str(),
                envelope_tail.value,
                run_id,
            ],
        )
        .expect("rewrite runtime anchor");
    transaction.commit().expect("commit rewritten history");
}

#[test]
fn sqlite_tail_confirmation_uses_one_snapshot_across_concurrent_append() {
    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("snapshot.sqlite3");
    let writer_store = SqliteTraceStore::open(&path).expect("writer trace store");
    let journal_mode = writer_store
        .inner
        .with_legacy_connection(|connection| {
            connection
                .query_row("PRAGMA journal_mode=WAL", [], |row| row.get::<_, String>(0))
                .map_err(TraceStoreError::from)
        })
        .expect("enable WAL fixture");
    assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
    let reader_store = SqliteTraceStore::open(&path).expect("independent reader trace store");
    let run_id = format!("snapshot-{}", Uuid::new_v4());
    let writer = writer_store
        .acquire_runtime_writer(runtime_writer_request(&run_id, "tenant", "agent"))
        .expect("runtime writer");
    let expected = writer
        .append(
            &writer.tail().expect("initial tail"),
            serde_json::json!({"index": 0}),
        )
        .expect("initial append")
        .into_tail();
    let reader = reader_store
        .open_runtime_reader(&run_id, RuntimeTraceLimits::default())
        .expect("runtime reader");

    let (snapshot_tx, snapshot_rx) = mpsc::channel();
    let (append_done_tx, append_done_rx) = mpsc::channel();
    let _hook = install_sqlite_confirm_snapshot_hook(
        reader_store.inner.store_id.clone(),
        run_id.clone(),
        move || {
            snapshot_tx.send(()).expect("signal captured snapshot");
            append_done_rx
                .recv_timeout(StdDuration::from_secs(2))
                .expect("append committed while snapshot remained open");
        },
    );
    let confirmation_expected = expected.clone();
    let (confirmation_tx, confirmation_rx) = mpsc::channel();
    let confirmation = std::thread::spawn(move || {
        confirmation_tx
            .send(reader.confirm_tail(&confirmation_expected))
            .expect("send confirmation result");
    });
    snapshot_rx
        .recv_timeout(StdDuration::from_secs(2))
        .expect("confirmation captured actual tail");

    let append_writer = Arc::clone(&writer);
    let append_expected = expected.clone();
    let (append_result_tx, append_result_rx) = mpsc::channel();
    let append = std::thread::spawn(move || {
        append_result_tx
            .send(append_writer.append(&append_expected, serde_json::json!({"index": 1})))
            .expect("send append result");
    });
    let appended = append_result_rx
        .recv_timeout(StdDuration::from_secs(2))
        .expect("concurrent append completed")
        .expect("concurrent append succeeded");
    append_done_tx.send(()).expect("release snapshot hook");
    confirmation_rx
        .recv_timeout(StdDuration::from_secs(2))
        .expect("snapshot confirmation completed")
        .expect("old snapshot confirmed atomically");
    append.join().expect("append thread");
    confirmation.join().expect("confirmation thread");

    let reader = reader_store
        .open_runtime_reader(&run_id, RuntimeTraceLimits::default())
        .expect("fresh runtime reader");
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::FenceRejected)
    );
    reader
        .confirm_tail(appended.tail())
        .expect("fresh actual tail confirms after rollback/release");
    writer.close().expect("close runtime writer");
}

#[test]
fn sqlite_tail_confirmation_distinguishes_growth_from_integrity_failure() {
    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("valid-growth.sqlite3");
    let store = SqliteTraceStore::open(&path).expect("trace store");
    let (reader, expected, actual) = anchored_growth_fixture(&store, "valid-growth");
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::FenceRejected)
    );
    assert_eq!(
        reader.confirm_tail(&tail_with_incompatible_fence(&expected)),
        Err(RuntimeTracePortError::IntegrityFailure)
    );
    reader.confirm_tail(&actual).expect("equal actual tail");

    let path = directory.path().join("rewritten-prefix.sqlite3");
    let store = SqliteTraceStore::open(&path).expect("trace store");
    let (reader, expected, _) = anchored_growth_fixture(&store, "rewritten-prefix");
    rewrite_sqlite_prefix_as_valid_history(&path, &store, "rewritten-prefix");
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::IntegrityFailure)
    );
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::IntegrityFailure),
        "failed confirmation rolled back its read transaction"
    );

    let path = directory.path().join("corrupt-extension.sqlite3");
    let store = SqliteTraceStore::open(&path).expect("trace store");
    let (reader, expected, _) = anchored_growth_fixture(&store, "corrupt-extension");
    let connection = Connection::open(&path).expect("tamper connection");
    connection
        .execute_batch("DROP TRIGGER trace_anchored_update_guard")
        .expect("disable fixture update guard");
    connection
        .execute(
            "UPDATE trace_events SET payload = ?1 WHERE run_id = ?2 AND sequence = 1",
            params![
                serde_json::to_vec(&serde_json::json!({"corrupt": true}))
                    .expect("corrupt payload bytes"),
                "corrupt-extension",
            ],
        )
        .expect("corrupt extension");
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::IntegrityFailure)
    );

    let path = directory.path().join("truncated.sqlite3");
    let store = SqliteTraceStore::open(&path).expect("trace store");
    let (reader, expected, _) = anchored_growth_fixture(&store, "truncated");
    let connection = Connection::open(&path).expect("tamper connection");
    connection
        .execute_batch("DROP TRIGGER trace_anchored_delete_guard")
        .expect("disable fixture delete guard");
    connection
        .execute(
            "DELETE FROM trace_events WHERE run_id = ?1 AND sequence = 1",
            params!["truncated"],
        )
        .expect("truncate extension");
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::IntegrityFailure)
    );
}

#[test]
fn tail_confirmation_enforces_limits_over_the_current_full_history() {
    let memory = InMemoryTraceStore::default();
    let (_, expected, _) = anchored_growth_fixture(&memory, "memory-limited");
    let limits = RuntimeTraceLimits::checked(1, 1, 1_024, 1_024).expect("limited reader");
    let reader = memory
        .open_runtime_reader("memory-limited", limits)
        .expect("memory reader");
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::LimitExceeded)
    );

    let directory = tempfile::tempdir().expect("trace directory");
    let sqlite =
        SqliteTraceStore::open(directory.path().join("limited.sqlite3")).expect("trace store");
    let (_, expected, _) = anchored_growth_fixture(&sqlite, "sqlite-limited");
    let reader = sqlite
        .open_runtime_reader("sqlite-limited", limits)
        .expect("SQLite reader");
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::LimitExceeded)
    );
}

fn assert_revision_only_tail_advance(store: &dyn TraceStore, run_id: &str) {
    let writer = store
        .acquire_runtime_writer(runtime_writer_request(run_id, "tenant", "agent"))
        .expect("runtime writer");
    let expected = writer.tail().expect("acquired tail");
    writer.close().expect("close runtime writer");
    let reader = store
        .open_runtime_reader(run_id, RuntimeTraceLimits::default())
        .expect("runtime reader");
    let actual = reader.tail().expect("closed tail");
    assert_eq!(actual.next_sequence(), expected.next_sequence());
    assert!(actual.anchor_revision() > expected.anchor_revision());
    assert_eq!(
        reader.confirm_tail(&expected),
        Err(RuntimeTracePortError::FenceRejected)
    );
    reader.confirm_tail(&actual).expect("equal closed tail");
}

#[test]
fn tail_confirmation_accepts_monotonic_revision_only_movement_as_transient() {
    assert_revision_only_tail_advance(&InMemoryTraceStore::default(), "memory-revision");

    let directory = tempfile::tempdir().expect("trace directory");
    let sqlite =
        SqliteTraceStore::open(directory.path().join("revision.sqlite3")).expect("trace store");
    assert_revision_only_tail_advance(&sqlite, "sqlite-revision");
}

#[test]
fn sqlite_anchor_and_history_identity_rows_are_immutable_to_legacy_sql() {
    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("trace.sqlite3");
    let (_store, reader, tail) = sqlite_anchored_fixture(&path, "run", 1);
    let connection = Connection::open(&path).expect("tamper connection");

    for statement in [
        "DELETE FROM trace_events WHERE run_id = 'run'",
        "UPDATE trace_events SET payload = x'7b7d' WHERE run_id = 'run'",
        "DELETE FROM trace_run_anchors WHERE run_id = 'run'",
        "DELETE FROM trace_run_anchor_registry WHERE run_id = 'run'",
        "UPDATE trace_run_anchor_registry SET profile = 'legacy' WHERE run_id = 'run'",
        "UPDATE trace_run_anchors SET store_id = 'other' WHERE run_id = 'run'",
        "UPDATE trace_run_anchors SET next_sequence = 0, anchor_revision = anchor_revision + 1 WHERE run_id = 'run'",
    ] {
        assert!(
            connection.execute_batch(statement).is_err(),
            "legacy SQL unexpectedly mutated anchored history: {statement}"
        );
    }
    reader
        .confirm_tail(&tail)
        .expect("failed mutations preserve tail");
}

#[test]
fn sqlite_anchor_detects_middle_tail_and_complete_history_truncation() {
    for (label, predicate) in [
        ("middle", "sequence = 1"),
        ("tail", "sequence = 2"),
        ("all", "1 = 1"),
    ] {
        let directory = tempfile::tempdir().expect("trace directory");
        let path = directory.path().join(format!("{label}.sqlite3"));
        let (_store, reader, tail) = sqlite_anchored_fixture(&path, "run", 3);
        let connection = Connection::open(&path).expect("tamper connection");
        connection
            .execute_batch("DROP TRIGGER trace_anchored_delete_guard")
            .expect("disable fixture deletion guard");
        connection
            .execute(
                &format!("DELETE FROM trace_events WHERE run_id = 'run' AND {predicate}"),
                [],
            )
            .expect("fixture truncation");

        assert_eq!(
            reader.confirm_tail(&tail),
            Err(RuntimeTracePortError::IntegrityFailure)
        );
    }
}

#[test]
fn sqlite_stale_high_water_hash_and_fence_metadata_fail_closed() {
    for (label, statement) in [
        (
            "high-water",
            "UPDATE trace_run_anchors SET next_sequence = next_sequence + 1, anchor_revision = anchor_revision + 1 WHERE run_id = 'run'",
        ),
        (
            "stable-hash",
            "UPDATE trace_run_anchors SET stable_tail_hash_value = 'corrupt', anchor_revision = anchor_revision + 1 WHERE run_id = 'run'",
        ),
        (
            "envelope-hash",
            "UPDATE trace_run_anchors SET envelope_tail_hash_value = 'corrupt', anchor_revision = anchor_revision + 1 WHERE run_id = 'run'",
        ),
    ] {
        let directory = tempfile::tempdir().expect("trace directory");
        let path = directory.path().join(format!("{label}.sqlite3"));
        let (store, reader, tail) = sqlite_anchored_fixture(&path, "run", 1);
        Connection::open(&path)
            .expect("tamper connection")
            .execute_batch(statement)
            .expect("tamper anchor fixture");
        assert_eq!(
            reader.confirm_tail(&tail),
            Err(RuntimeTracePortError::IntegrityFailure)
        );
        assert!(matches!(
            store.acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent")),
            Err(RuntimeTracePortError::IntegrityFailure | RuntimeTracePortError::Conflict)
        ));
    }

    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("fence.sqlite3");
    let (_store, reader, tail) = sqlite_anchored_fixture(&path, "run", 1);
    assert!(Connection::open(&path)
        .expect("tamper connection")
        .execute_batch(
            "UPDATE trace_run_anchors SET fence_digest = 'blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', anchor_revision = anchor_revision + 1 WHERE run_id = 'run'",
        )
        .is_err());
    reader
        .confirm_tail(&tail)
        .expect("immutable fence remains valid");

    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("corrupt-fence.sqlite3");
    let store = SqliteTraceStore::open(&path).expect("trace store");
    let writer = store
        .acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent"))
        .expect("runtime writer");
    let tail = writer
        .append(
            &writer.tail().expect("initial tail"),
            serde_json::json!({"event": 1}),
        )
        .expect("initial append")
        .into_tail();
    let connection = Connection::open(&path).expect("tamper connection");
    connection
        .execute_batch("DROP TRIGGER trace_anchor_identity_update_guard")
        .expect("disable fixture identity guard");
    connection
        .execute_batch(
            "UPDATE trace_run_anchors SET fence_digest = 'blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', anchor_revision = anchor_revision + 1 WHERE run_id = 'run'",
        )
        .expect("corrupt fence fixture");
    assert_eq!(
        writer.confirm_tail(&tail),
        Err(RuntimeTracePortError::IntegrityFailure)
    );
    assert!(matches!(
        writer.append(&tail, serde_json::json!({"event": 2})),
        Err(RuntimeTracePortError::IntegrityFailure | RuntimeTracePortError::FenceRejected)
    ));
}

#[cfg(unix)]
fn initialize_distinct_sqlite_stores(
    path_a: &std::path::Path,
    path_b: &std::path::Path,
) -> (RuntimeTraceStoreIdentity, RuntimeTraceStoreIdentity) {
    let store_a = SqliteTraceStore::open(path_a).expect("initialize store A");
    TraceStore::append(&store_a, "run-a", serde_json::json!({"store": "A"}))
        .expect("append store A row");
    let identity_a = store_a.runtime_store_identity().expect("store A identity");
    drop(store_a);

    let store_b = SqliteTraceStore::open(path_b).expect("initialize store B");
    TraceStore::append(&store_b, "run-b", serde_json::json!({"store": "B"}))
        .expect("append store B row");
    let identity_b = store_b.runtime_store_identity().expect("store B identity");
    drop(store_b);

    assert_ne!(identity_a, identity_b);
    (identity_a, identity_b)
}

#[cfg(unix)]
fn install_a_to_b_to_a_open_hook(
    path_a: &std::path::Path,
    path_b: &std::path::Path,
    parked_a: &std::path::Path,
) -> (
    SqliteOpenStageHookGuard,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let phase = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_phase = Arc::clone(&phase);
    let hook_path = canonical_database_path(path_a).expect("canonical hook path");
    let path_a = path_a.to_path_buf();
    let path_b = path_b.to_path_buf();
    let parked_a = parked_a.to_path_buf();
    let hook = install_sqlite_open_stage_hook(hook_path, move |stage| {
        let expected_phase = match stage {
            SqliteOpenStage::BeforeSqliteOpen => 0,
            SqliteOpenStage::AfterSqliteOpen => 1,
        };
        if observed_phase.load(std::sync::atomic::Ordering::SeqCst) != expected_phase {
            return Err(std::io::Error::other("unexpected SQLite open-stage order"));
        }
        match stage {
            SqliteOpenStage::BeforeSqliteOpen => {
                std::fs::rename(&path_a, &parked_a)?;
                std::fs::rename(&path_b, &path_a)?;
            }
            SqliteOpenStage::AfterSqliteOpen => {
                std::fs::rename(&path_a, &path_b)?;
                std::fs::rename(&parked_a, &path_a)?;
            }
        }
        observed_phase.store(expected_phase + 1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    });
    (hook, phase)
}

#[cfg(unix)]
fn assert_distinct_sqlite_stores_unchanged(
    path_a: &std::path::Path,
    path_b: &std::path::Path,
    identity_a: &RuntimeTraceStoreIdentity,
    identity_b: &RuntimeTraceStoreIdentity,
) {
    let store_a = SqliteTraceStore::open_read_only(path_a).expect("reopen store A");
    assert_eq!(
        &store_a.runtime_store_identity().expect("store A identity"),
        identity_a
    );
    assert_eq!(
        TraceStore::read(&store_a, "run-a").expect("store A row")[0].payload,
        serde_json::json!({"store": "A"})
    );
    assert!(matches!(
        TraceStore::read(&store_a, "run-b"),
        Err(TraceStoreError::RunNotFound)
    ));

    let store_b = SqliteTraceStore::open_read_only(path_b).expect("reopen store B");
    assert_eq!(
        &store_b.runtime_store_identity().expect("store B identity"),
        identity_b
    );
    assert_eq!(
        TraceStore::read(&store_b, "run-b").expect("store B row")[0].payload,
        serde_json::json!({"store": "B"})
    );
    assert!(matches!(
        TraceStore::read(&store_b, "run-a"),
        Err(TraceStoreError::RunNotFound)
    ));
}

#[cfg(unix)]
#[test]
fn sqlite_writable_constructor_rejects_a_to_b_to_a_main_file_substitution() {
    let directory = tempfile::tempdir().expect("trace directory");
    let path_a = directory.path().join("trace-a.sqlite3");
    let path_b = directory.path().join("trace-b.sqlite3");
    let parked_a = directory.path().join("trace-a.parked");
    let (identity_a, identity_b) = initialize_distinct_sqlite_stores(&path_a, &path_b);
    let (hook, phase) = install_a_to_b_to_a_open_hook(&path_a, &path_b, &parked_a);

    assert!(matches!(
        SqliteTraceStore::open(&path_a),
        Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidQuery))
    ));
    assert_eq!(phase.load(std::sync::atomic::Ordering::SeqCst), 2);
    drop(hook);

    assert_distinct_sqlite_stores_unchanged(&path_a, &path_b, &identity_a, &identity_b);
}

#[cfg(unix)]
#[test]
fn sqlite_read_only_constructor_rejects_a_to_b_to_a_main_file_substitution() {
    let directory = tempfile::tempdir().expect("trace directory");
    let path_a = directory.path().join("trace-a.sqlite3");
    let path_b = directory.path().join("trace-b.sqlite3");
    let parked_a = directory.path().join("trace-a.parked");
    let (identity_a, identity_b) = initialize_distinct_sqlite_stores(&path_a, &path_b);
    let (hook, phase) = install_a_to_b_to_a_open_hook(&path_a, &path_b, &parked_a);

    assert!(matches!(
        SqliteTraceStore::open_read_only(&path_a),
        Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidQuery))
    ));
    assert_eq!(phase.load(std::sync::atomic::Ordering::SeqCst), 2);
    drop(hook);

    assert_distinct_sqlite_stores_unchanged(&path_a, &path_b, &identity_a, &identity_b);
}

#[cfg(unix)]
#[test]
fn sqlite_writable_store_rejects_database_aliases_and_unsafe_modes() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = tempfile::tempdir().expect("trace directory");
    let original = directory.path().join("original.sqlite3");
    drop(SqliteTraceStore::open(&original).expect("initialize original"));

    let hard_link = directory.path().join("hard-link.sqlite3");
    std::fs::hard_link(&original, &hard_link).expect("hard link");
    assert!(SqliteTraceStore::open(&hard_link).is_err());
    assert!(SqliteTraceStore::open(&original).is_err());
    std::fs::remove_file(&hard_link).expect("remove hard link");

    let symbolic_link = directory.path().join("symbolic-link.sqlite3");
    symlink(&original, &symbolic_link).expect("symbolic link");
    assert!(SqliteTraceStore::open(&symbolic_link).is_err());

    let unsafe_mode = directory.path().join("unsafe-mode.sqlite3");
    std::fs::write(&unsafe_mode, []).expect("unsafe database file");
    std::fs::set_permissions(&unsafe_mode, std::fs::Permissions::from_mode(0o644))
        .expect("unsafe database mode");
    assert!(SqliteTraceStore::open(&unsafe_mode).is_err());
}

#[cfg(unix)]
#[test]
fn secure_runtime_lock_attributes_reject_foreign_owner_type_mode_and_links() {
    let current_uid = getuid().as_raw();
    let regular_mode = 0o100000 | 0o600;
    assert!(secure_regular_file_attributes(
        regular_mode,
        current_uid,
        true,
        0o600,
        current_uid,
    ));
    assert!(!secure_regular_file_attributes(
        regular_mode,
        current_uid.wrapping_add(1),
        true,
        0o600,
        current_uid,
    ));
    assert!(!secure_regular_file_attributes(
        regular_mode,
        current_uid,
        false,
        0o600,
        current_uid,
    ));
    assert!(!secure_regular_file_attributes(
        0o040000 | 0o600,
        current_uid,
        true,
        0o600,
        current_uid,
    ));
    assert!(!secure_regular_file_attributes(
        0o100000 | 0o644,
        current_uid,
        true,
        0o600,
        current_uid,
    ));
}

#[cfg(unix)]
#[test]
fn sqlite_writable_operations_detect_database_rename_and_replacement() {
    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("trace.sqlite3");
    let moved = directory.path().join("moved.sqlite3");
    let store = SqliteTraceStore::open(&path).expect("trace store");
    let database = store.inner.database.as_ref().expect("writable database");
    let lock_root = store.inner.lock_root.as_ref().expect("runtime lock root");
    let shard = runtime_lock_shard(&store.inner.store_id, database.identity, "run");
    let process_lock_key = ProcessRuntimeLockKey {
        lock_root: lock_root.identity,
        shard,
    };
    let writer = store
        .acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent"))
        .expect("runtime writer");
    let tail = writer.tail().expect("runtime tail");
    let reader = store
        .open_runtime_reader("run", RuntimeTraceLimits::default())
        .expect("runtime reader");

    std::fs::rename(&path, &moved).expect("rename database");
    assert!(matches!(
        TraceStore::append(&store, "legacy", serde_json::json!({"after": "rename"})),
        Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidQuery))
    ));
    assert!(matches!(
        TraceStore::read(&store, "run"),
        Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidQuery))
    ));
    assert!(matches!(
        TraceStore::read_range(&store, "run", 0, 1),
        Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidQuery))
    ));
    assert!(matches!(
        store.runtime_store_identity(),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        store.open_runtime_reader("run", RuntimeTraceLimits::default()),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        reader.tail(),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        reader.read_page(0),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        reader.confirm_tail(&tail),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        writer.tail(),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        writer.read_page(0),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        writer.confirm_tail(&tail),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        writer.append(&tail, serde_json::json!({"after": "rename"})),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));

    drop(SqliteTraceStore::open(&path).expect("replacement database"));
    assert!(matches!(
        writer.append(&tail, serde_json::json!({"after": "replacement"})),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    writer
        .close()
        .expect_err("renamed writer cannot close as valid");
    let process_lock = ProcessRuntimeLock::acquire(process_lock_key)
        .expect("failed close released process writer lock");
    let lock_file = lock_root
        .open_shard(shard)
        .expect("open released OS lock shard");
    flock(&lock_file, FlockOperation::NonBlockingLockExclusive)
        .expect("failed close released OS writer lock");
    flock(&lock_file, FlockOperation::Unlock).expect("unlock test shard");
    drop(process_lock);
}

#[cfg(unix)]
#[test]
fn sqlite_read_only_operations_detect_database_rename() {
    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("trace.sqlite3");
    let moved = directory.path().join("moved.sqlite3");
    let writable = SqliteTraceStore::open(&path).expect("writable trace store");
    TraceStore::append(&writable, "run", serde_json::json!({"event": 1})).expect("seed trace row");
    drop(writable);

    let store = SqliteTraceStore::open_read_only(&path).expect("read-only trace store");
    let reader = store
        .open_runtime_reader("run", RuntimeTraceLimits::default())
        .expect("runtime reader");
    let tail = reader.tail().expect("runtime tail");
    std::fs::rename(&path, &moved).expect("rename database");

    assert!(matches!(
        TraceStore::read(&store, "run"),
        Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidQuery))
    ));
    assert!(matches!(
        TraceStore::read_range(&store, "run", 0, 1),
        Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidQuery))
    ));
    assert!(matches!(
        store.runtime_store_identity(),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        store.open_runtime_reader("run", RuntimeTraceLimits::default()),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        reader.tail(),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        reader.read_page(0),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
    assert!(matches!(
        reader.confirm_tail(&tail),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));
}

#[cfg(unix)]
#[test]
fn sqlite_lock_root_and_precreated_shards_fail_closed_when_unsafe() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("unsafe-root.sqlite3");
    let unsafe_root = directory.path().join("unsafe-locks");
    std::fs::create_dir(&unsafe_root).expect("unsafe lock root");
    std::fs::set_permissions(&unsafe_root, std::fs::Permissions::from_mode(0o755))
        .expect("unsafe lock-root mode");
    assert!(SqliteTraceStore::open_with_lock_root(&path, &unsafe_root).is_err());

    let path = directory.path().join("unsafe-shard.sqlite3");
    let lock_root = directory.path().join("private-locks");
    let store = SqliteTraceStore::open_with_lock_root(&path, &lock_root).expect("trace store");
    let database = store.inner.database.as_ref().expect("writable database");
    let shard = runtime_lock_shard(&store.inner.store_id, database.identity, "run");
    let shard_path = lock_root.join(format!("shard-{shard:02x}.lock"));
    std::fs::write(&shard_path, []).expect("precreated shard");
    std::fs::set_permissions(&shard_path, std::fs::Permissions::from_mode(0o644))
        .expect("unsafe shard mode");
    assert!(matches!(
        store.acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent")),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));

    std::fs::set_permissions(&shard_path, std::fs::Permissions::from_mode(0o600))
        .expect("secure shard mode");
    let shard_alias = lock_root.join("shard-alias.lock");
    std::fs::hard_link(&shard_path, &shard_alias).expect("hard-linked shard");
    assert!(matches!(
        store.acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent")),
        Err(RuntimeTracePortError::IntegrityFailure)
    ));

    let symlink_database = directory.path().join("symlink-shard.sqlite3");
    let symlink_root = directory.path().join("symlink-locks");
    let symlink_store = SqliteTraceStore::open_with_lock_root(&symlink_database, &symlink_root)
        .expect("symlink fixture store");
    let database = symlink_store
        .inner
        .database
        .as_ref()
        .expect("writable database");
    let shard = runtime_lock_shard(
        &symlink_store.inner.store_id,
        database.identity,
        "symlink-run",
    );
    let shard_path = symlink_root.join(format!("shard-{shard:02x}.lock"));
    let symlink_target = directory.path().join("symlink-target.lock");
    std::fs::write(&symlink_target, []).expect("symlink target");
    std::fs::set_permissions(&symlink_target, std::fs::Permissions::from_mode(0o600))
        .expect("symlink target mode");
    symlink(&symlink_target, &shard_path).expect("precreated shard symlink");
    assert!(matches!(
        symlink_store.acquire_runtime_writer(runtime_writer_request(
            "symlink-run",
            "tenant",
            "agent"
        )),
        Err(RuntimeTracePortError::IntegrityFailure | RuntimeTracePortError::Unavailable)
    ));

    let database = directory.path().join("symlink-root.sqlite3");
    let real_root = directory.path().join("real-lock-root");
    std::fs::create_dir(&real_root).expect("real lock root");
    std::fs::set_permissions(&real_root, std::fs::Permissions::from_mode(0o700))
        .expect("real lock-root mode");
    let root_alias = directory.path().join("lock-root-alias");
    symlink(&real_root, &root_alias).expect("lock-root symlink");
    assert!(SqliteTraceStore::open_with_lock_root(&database, &root_alias).is_err());
}

#[test]
fn sqlite_lock_shards_are_bounded_and_collisions_deny_safely() {
    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("trace.sqlite3");
    let lock_root = directory.path().join("private-locks");
    let store = SqliteTraceStore::open_with_lock_root(&path, &lock_root).expect("trace store");
    let database = store.inner.database.as_ref().expect("writable database");
    let mut by_shard = std::collections::HashMap::new();
    let mut collision = None;
    for index in 0..(RUNTIME_TRACE_LOCK_SHARDS * 4) {
        let run_id = format!("run-{index}");
        let shard = runtime_lock_shard(&store.inner.store_id, database.identity, &run_id);
        if let Some(existing) = by_shard.insert(shard, run_id.clone()) {
            collision = Some((existing, run_id));
            break;
        }
    }
    let (left_run, right_run) = collision.expect("bounded shard collision");
    let left = store
        .acquire_runtime_writer(runtime_writer_request(&left_run, "tenant", "agent"))
        .expect("left collision writer");
    assert!(matches!(
        store.acquire_runtime_writer(runtime_writer_request(&right_run, "tenant", "agent")),
        Err(RuntimeTracePortError::Conflict)
    ));
    left.close().expect("close left collision writer");
    let right = store
        .acquire_runtime_writer(runtime_writer_request(&right_run, "tenant", "agent"))
        .expect("collision shard is reusable after release");
    right.close().expect("close right collision writer");

    for index in 0..(RUNTIME_TRACE_LOCK_SHARDS * 2) {
        let run_id = format!("bounded-{index}");
        let writer = store
            .acquire_runtime_writer(runtime_writer_request(&run_id, "tenant", "agent"))
            .expect("bounded shard writer");
        writer.close().expect("close bounded shard writer");
    }
    let lock_files = std::fs::read_dir(&lock_root)
        .expect("read lock root")
        .count();
    assert!(lock_files <= RUNTIME_TRACE_LOCK_SHARDS);
}

#[cfg(unix)]
#[test]
fn sqlite_runtime_writer_process_holder() {
    let Ok(path) = std::env::var("SPLENDOR_TEST_RUNTIME_WRITER_HOLDER_DB") else {
        return;
    };
    let ready =
        std::env::var("SPLENDOR_TEST_RUNTIME_WRITER_HOLDER_READY").expect("holder ready path");
    let store = SqliteTraceStore::open(path).expect("holder trace store");
    let _writer = store
        .acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent"))
        .expect("holder runtime writer");
    std::fs::write(ready, b"ready").expect("signal holder ready");
    std::thread::sleep(std::time::Duration::from_secs(60));
}

#[cfg(unix)]
#[test]
fn sqlite_runtime_writer_releases_cross_process_lock_after_forced_exit() {
    use std::process::{Command, Stdio};

    let directory = tempfile::tempdir().expect("trace directory");
    let path = directory.path().join("trace.sqlite3");
    let ready = directory.path().join("holder.ready");
    drop(SqliteTraceStore::open(&path).expect("initialize trace store"));
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .arg("sqlite_runtime_writer_process_holder")
        .arg("--nocapture")
        .env("SPLENDOR_TEST_RUNTIME_WRITER_HOLDER_DB", &path)
        .env("SPLENDOR_TEST_RUNTIME_WRITER_HOLDER_READY", &ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn writer holder");

    let mut observed_ready = false;
    for _ in 0..500 {
        if ready.exists() {
            observed_ready = true;
            break;
        }
        assert!(child.try_wait().expect("holder status").is_none());
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(observed_ready, "writer holder did not become ready");

    let contender = SqliteTraceStore::open(&path).expect("contender trace store");
    assert!(matches!(
        contender.acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent")),
        Err(RuntimeTracePortError::Conflict)
    ));
    child.kill().expect("force writer-holder exit");
    child.wait().expect("wait for writer-holder exit");

    let reclaimed = contender
        .acquire_runtime_writer(runtime_writer_request("run", "tenant", "agent"))
        .expect("cross-process lock released after exit");
    reclaimed.close().expect("close reclaimed writer");
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
