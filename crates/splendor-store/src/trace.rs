//! # Trace Storage
//!
//! Trace stores persist the ordered event stream for each kernel run. The
//! in-memory implementation is intended for tests and local development, while
//! the SQLite implementation provides durable storage and integrity metadata.
//!
//! ## Example
//! ```rust,no_run
//! use splendor_store::{InMemoryTraceStore, TraceStore};
//!
//! let store = InMemoryTraceStore::default();
//! TraceStore::append(&store, "run-42", serde_json::json!({"event": 1}))
//!     .expect("append");
//! let records = TraceStore::read(&store, "run-42").expect("read");
//! assert_eq!(records.len(), 1);
//! ```

use crate::runtime_trace::{
    compute_trace_envelope_hash, RuntimeTraceAppend, RuntimeTraceFence, RuntimeTraceLimits,
    RuntimeTracePage, RuntimeTracePortError, RuntimeTraceProfile, RuntimeTraceReader,
    RuntimeTraceReaderHandle, RuntimeTraceStoreIdentity, RuntimeTraceTail, RuntimeTraceWriter,
    RuntimeTraceWriterHandle, RuntimeTraceWriterRequest, RUNTIME_TRACE_LOCK_SHARDS,
};
use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior};
use rustix::fs::{flock, fstat, open, openat, FileType, FlockOperation, Mode, OFlags, RawMode};
use rustix::process::getuid;
use serde::{Deserialize, Serialize};
use splendor_types::{ContentHash, HashAlgorithm};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::future::{ready, Future, Ready};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(1);
const CURRENT_TRACE_PROFILE: &str = "splendor.trace.anchor.v1";
const TRACE_STORE_ID_KEY: &str = "store_id";
const DEFAULT_LOCK_ROOT_NAME: &str = ".splendor-runtime-locks";

/// Record stored for each trace event payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TraceRecord {
    /// Run identifier that scopes the event stream.
    pub run_id: String,
    /// Monotonic sequence number within the run.
    pub sequence: u64,
    /// Serialized trace event payload.
    pub payload: serde_json::Value,
    /// Timestamp when the record was stored.
    pub recorded_at: OffsetDateTime,
    /// Integrity hash derived from the previous hash and payload bytes.
    pub event_hash: ContentHash,
    /// Hash of the previous event in the chain.
    pub prev_event_hash: Option<ContentHash>,
}

/// Synchronous interface for append-only trace storage.
pub trait TraceStore: Send + Sync {
    /// Appends an opaque trace payload and returns the store-assigned sequence.
    /// Application payload fields are never interpreted as storage metadata.
    fn append(&self, run_id: &str, payload: serde_json::Value) -> Result<u64, TraceStoreError>;
    /// Reads all `TraceRecord` entries for a run.
    fn read(&self, run_id: &str) -> Result<Vec<TraceRecord>, TraceStoreError>;
    /// Reads a sequence range and returns matching `TraceRecord` entries.
    fn read_range(
        &self,
        run_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<TraceRecord>, TraceStoreError>;
    /// Returns a stable opaque identity without consuming run history.
    fn runtime_store_identity(&self) -> Result<RuntimeTraceStoreIdentity, RuntimeTracePortError> {
        Err(RuntimeTracePortError::Unsupported)
    }
    /// Opens a bounded inspect-only run reader. Legacy implementations deny by
    /// default rather than silently providing unbounded reads.
    fn open_runtime_reader(
        &self,
        _run_id: &str,
        _limits: RuntimeTraceLimits,
    ) -> Result<RuntimeTraceReaderHandle, RuntimeTracePortError> {
        Err(RuntimeTracePortError::Unsupported)
    }
    /// Acquires the exclusive fresh-profile writer before any recovery read.
    /// Legacy implementations deny by default.
    fn acquire_runtime_writer(
        &self,
        _request: RuntimeTraceWriterRequest,
    ) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
        Err(RuntimeTracePortError::Unsupported)
    }
}

/// Asynchronous interface for append-only trace storage.
pub trait AsyncTraceStore: Send + Sync {
    /// Future returned by `append`.
    type AppendFuture<'a>: Future<Output = Result<u64, TraceStoreError>> + Send + 'a
    where
        Self: 'a;
    /// Future returned by `read`.
    type ReadFuture<'a>: Future<Output = Result<Vec<TraceRecord>, TraceStoreError>> + Send + 'a
    where
        Self: 'a;
    /// Future returned by `read_range`.
    type ReadRangeFuture<'a>: Future<Output = Result<Vec<TraceRecord>, TraceStoreError>> + Send + 'a
    where
        Self: 'a;

    /// Appends an opaque trace payload and returns the assigned sequence number.
    fn append<'a>(&'a self, run_id: &'a str, payload: serde_json::Value) -> Self::AppendFuture<'a>;
    /// Reads all `TraceRecord` entries for a run.
    fn read<'a>(&'a self, run_id: &'a str) -> Self::ReadFuture<'a>;
    /// Reads a sequence range and returns matching `TraceRecord` entries.
    fn read_range<'a>(&'a self, run_id: &'a str, start: u64, end: u64)
        -> Self::ReadRangeFuture<'a>;
}

/// In-memory trace store for tests and local runs.
#[derive(Clone)]
pub struct InMemoryTraceStore {
    /// Guarded trace record storage keyed by run ID.
    inner: Arc<Mutex<HashMap<String, Vec<TraceRecord>>>>,
    runtime_anchors: Arc<Mutex<HashMap<String, InMemoryRuntimeAnchor>>>,
    store_identity: RuntimeTraceStoreIdentity,
}

#[derive(Clone)]
struct InMemoryRuntimeAnchor {
    tail: RuntimeTraceTail,
    acquired: bool,
}

impl Default for InMemoryTraceStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            runtime_anchors: Arc::new(Mutex::new(HashMap::new())),
            store_identity: RuntimeTraceStoreIdentity::from_opaque_material(
                Uuid::new_v4().as_bytes(),
            ),
        }
    }
}

impl TraceStore for InMemoryTraceStore {
    /// Appends a trace record to the in-memory buffer.
    fn append(&self, run_id: &str, payload: serde_json::Value) -> Result<u64, TraceStoreError> {
        let anchors = self
            .runtime_anchors
            .lock()
            .map_err(|_| TraceStoreError::Poisoned)?;
        if let Some(anchor) = anchors.get(run_id) {
            return Err(TraceStoreError::SequenceMismatch {
                expected: anchor.tail.next_sequence(),
                actual: anchor.tail.next_sequence().saturating_add(1),
            });
        }
        let mut inner = self.inner.lock().map_err(|_| TraceStoreError::Poisoned)?;
        let records = inner.entry(run_id.to_string()).or_default();
        append_in_memory_record(records, run_id, None, payload)
    }

    /// Reads all trace records for a run.
    fn read(&self, run_id: &str) -> Result<Vec<TraceRecord>, TraceStoreError> {
        let inner = self.inner.lock().map_err(|_| TraceStoreError::Poisoned)?;
        inner
            .get(run_id)
            .cloned()
            .ok_or(TraceStoreError::RunNotFound)
    }

    /// Reads trace records within the requested sequence window.
    fn read_range(
        &self,
        run_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<TraceRecord>, TraceStoreError> {
        let records = TraceStore::read(self, run_id)?;
        let slice = records
            .into_iter()
            .filter(|record| record.sequence >= start && record.sequence < end)
            .collect();
        Ok(slice)
    }

    fn runtime_store_identity(&self) -> Result<RuntimeTraceStoreIdentity, RuntimeTracePortError> {
        Ok(self.store_identity.clone())
    }

    fn open_runtime_reader(
        &self,
        run_id: &str,
        limits: RuntimeTraceLimits,
    ) -> Result<RuntimeTraceReaderHandle, RuntimeTracePortError> {
        validate_runtime_limits(limits)?;
        Ok(Arc::new(InMemoryRuntimeReader {
            records: Arc::clone(&self.inner),
            anchors: Arc::clone(&self.runtime_anchors),
            store_identity: self.store_identity.clone(),
            run_id: run_id.to_string(),
            limits,
        }))
    }

    fn acquire_runtime_writer(
        &self,
        request: RuntimeTraceWriterRequest,
    ) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
        acquire_in_memory_runtime_writer(self, request)
    }
}

fn append_in_memory_record(
    records: &mut Vec<TraceRecord>,
    run_id: &str,
    expected_sequence: Option<u64>,
    payload: serde_json::Value,
) -> Result<u64, TraceStoreError> {
    let prev_hash = records.last().map(|record| record.event_hash.clone());
    let sequence = records.len() as u64;
    if let Some(expected) = expected_sequence {
        ensure_expected_sequence(expected, sequence)?;
    }
    let event_hash = compute_trace_event_hash(prev_hash.as_ref(), &payload)?;
    records.push(TraceRecord {
        run_id: run_id.to_string(),
        sequence,
        payload,
        recorded_at: OffsetDateTime::now_utc(),
        event_hash,
        prev_event_hash: prev_hash,
    });
    Ok(sequence)
}

impl AsyncTraceStore for InMemoryTraceStore {
    type AppendFuture<'a>
        = Ready<Result<u64, TraceStoreError>>
    where
        Self: 'a;
    type ReadFuture<'a>
        = Ready<Result<Vec<TraceRecord>, TraceStoreError>>
    where
        Self: 'a;
    type ReadRangeFuture<'a>
        = Ready<Result<Vec<TraceRecord>, TraceStoreError>>
    where
        Self: 'a;

    /// Async wrapper around `append` for in-memory traces.
    fn append<'a>(&'a self, run_id: &'a str, payload: serde_json::Value) -> Self::AppendFuture<'a> {
        ready(TraceStore::append(self, run_id, payload))
    }

    /// Async wrapper around `read` for in-memory traces.
    fn read<'a>(&'a self, run_id: &'a str) -> Self::ReadFuture<'a> {
        ready(TraceStore::read(self, run_id))
    }

    /// Async wrapper around `read_range` for in-memory traces.
    fn read_range<'a>(
        &'a self,
        run_id: &'a str,
        start: u64,
        end: u64,
    ) -> Self::ReadRangeFuture<'a> {
        ready(TraceStore::read_range(self, run_id, start, end))
    }
}

/// SQLite-backed trace store for persistent audit logs.
#[derive(Clone)]
pub struct SqliteTraceStore {
    inner: Arc<SqliteTraceInner>,
}

struct SqliteTraceInner {
    connection: Mutex<Connection>,
    store_identity: RuntimeTraceStoreIdentity,
    store_id: String,
    writable_database: Option<WritableDatabase>,
    lock_root: Option<SecureLockRoot>,
}

struct WritableDatabase {
    path: PathBuf,
    descriptor: File,
    identity: FileIdentity,
}

#[derive(Clone)]
struct SecureLockRoot {
    descriptor: Arc<File>,
    identity: FileIdentity,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct ProcessRuntimeLockKey {
    lock_root: FileIdentity,
    shard: usize,
}

struct ProcessRuntimeLock {
    key: ProcessRuntimeLockKey,
}

static PROCESS_RUNTIME_LOCKS: OnceLock<Mutex<HashSet<ProcessRuntimeLockKey>>> = OnceLock::new();

impl SqliteTraceStore {
    /// Opens or creates a SQLite-backed trace store at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TraceStoreError> {
        let path = path.as_ref();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        Self::open_with_lock_root(path, parent.join(DEFAULT_LOCK_ROOT_NAME))
    }

    /// Opens a writable store with an explicit private runtime-lock root.
    pub fn open_with_lock_root(
        path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
    ) -> Result<Self, TraceStoreError> {
        let path = path.as_ref();
        if path == Path::new(":memory:") {
            let connection = Connection::open(path)?;
            connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
            let store_id = Uuid::new_v4().to_string();
            Self::init_schema(&connection, &store_id)?;
            return Ok(Self {
                inner: Arc::new(SqliteTraceInner {
                    connection: Mutex::new(connection),
                    store_identity: sqlite_runtime_store_identity(&store_id, None),
                    store_id,
                    writable_database: None,
                    lock_root: None,
                }),
            });
        }

        let database_descriptor = open_secure_database(path)?;
        let database_identity = verify_secure_regular_file(&database_descriptor, 0o600)?;
        let connection = Connection::open(path)?;
        connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        let post_open_descriptor = open_secure_database(path)?;
        let post_open_identity = verify_secure_regular_file(&post_open_descriptor, 0o600)?;
        if post_open_identity != database_identity {
            return Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        let proposed_store_id = Uuid::new_v4().to_string();
        Self::init_schema(&connection, &proposed_store_id)?;
        let store_id = Self::load_store_id(&connection)?;
        let lock_root = SecureLockRoot::open(lock_root.as_ref())?;
        Ok(Self {
            inner: Arc::new(SqliteTraceInner {
                connection: Mutex::new(connection),
                store_identity: sqlite_runtime_store_identity(&store_id, Some(database_identity)),
                store_id,
                writable_database: Some(WritableDatabase {
                    path: path.to_path_buf(),
                    descriptor: database_descriptor,
                    identity: database_identity,
                }),
                lock_root: Some(lock_root),
            }),
        })
    }

    /// Opens an existing SQLite-backed trace store read-only.
    ///
    /// This path deliberately avoids schema creation so inspect-only replay and
    /// audit export cannot mutate the trace database while reading evidence.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, TraceStoreError> {
        let path = path.as_ref();
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        let store_id = Self::try_load_store_id(&connection)?.unwrap_or_else(|| {
            std::fs::metadata(path)
                .map(|metadata| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        format!("legacy:{}:{}", metadata.dev(), metadata.ino())
                    }
                    #[cfg(not(unix))]
                    {
                        format!("legacy:{}", metadata.len())
                    }
                })
                .unwrap_or_else(|_| "legacy:unavailable".to_string())
        });
        #[cfg(unix)]
        let file_identity = std::fs::metadata(path).ok().map(|metadata| {
            use std::os::unix::fs::MetadataExt;
            FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        });
        #[cfg(not(unix))]
        let file_identity = None;
        Ok(Self {
            inner: Arc::new(SqliteTraceInner {
                connection: Mutex::new(connection),
                store_identity: sqlite_runtime_store_identity(&store_id, file_identity),
                store_id,
                writable_database: None,
                lock_root: None,
            }),
        })
    }

    /// Ensures the SQLite schema exists for trace storage.
    fn init_schema(
        connection: &Connection,
        proposed_store_id: &str,
    ) -> Result<(), TraceStoreError> {
        let result = (|| {
            connection.execute_batch(
                r#"
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS trace_events (
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
            CREATE INDEX IF NOT EXISTS trace_events_run_id_idx
              ON trace_events (run_id, sequence);
            CREATE TABLE IF NOT EXISTS trace_store_metadata (
              metadata_key TEXT PRIMARY KEY,
              metadata_value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trace_run_anchor_registry (
              run_id TEXT PRIMARY KEY,
              store_id TEXT NOT NULL,
              profile TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trace_run_anchors (
              run_id TEXT PRIMARY KEY,
              store_id TEXT NOT NULL,
              profile TEXT NOT NULL,
              next_sequence INTEGER NOT NULL,
              stable_tail_hash_algo TEXT,
              stable_tail_hash_value TEXT,
              envelope_tail_hash_algo TEXT,
              envelope_tail_hash_value TEXT,
              anchor_revision INTEGER NOT NULL,
              fence_digest TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trace_append_permits (
              run_id TEXT PRIMARY KEY,
              anchor_revision INTEGER NOT NULL,
              fence_digest TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS trace_anchored_insert_guard
            BEFORE INSERT ON trace_events
            WHEN EXISTS (
              SELECT 1 FROM trace_run_anchor_registry registry
              WHERE registry.run_id = NEW.run_id
            ) AND NOT EXISTS (
              SELECT 1
              FROM trace_append_permits permit
              JOIN trace_run_anchors anchor ON anchor.run_id = permit.run_id
              WHERE permit.run_id = NEW.run_id
                AND permit.anchor_revision = anchor.anchor_revision
                AND permit.fence_digest = anchor.fence_digest
            )
            BEGIN
              SELECT RAISE(ABORT, 'runtime_trace_fence_required');
            END;
            CREATE TRIGGER IF NOT EXISTS trace_anchored_update_guard
            BEFORE UPDATE ON trace_events
            WHEN EXISTS (
              SELECT 1 FROM trace_run_anchor_registry registry
              WHERE registry.run_id = OLD.run_id
            )
            BEGIN
              SELECT RAISE(ABORT, 'runtime_trace_history_immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS trace_anchored_delete_guard
            BEFORE DELETE ON trace_events
            WHEN EXISTS (
              SELECT 1 FROM trace_run_anchor_registry registry
              WHERE registry.run_id = OLD.run_id
            )
            BEGIN
              SELECT RAISE(ABORT, 'runtime_trace_history_immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS trace_anchor_registry_delete_guard
            BEFORE DELETE ON trace_run_anchor_registry
            BEGIN
              SELECT RAISE(ABORT, 'runtime_trace_profile_immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS trace_anchor_registry_update_guard
            BEFORE UPDATE ON trace_run_anchor_registry
            BEGIN
              SELECT RAISE(ABORT, 'runtime_trace_profile_immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS trace_anchor_identity_update_guard
            BEFORE UPDATE OF run_id, store_id, profile, fence_digest ON trace_run_anchors
            BEGIN
              SELECT RAISE(ABORT, 'runtime_trace_anchor_identity_immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS trace_anchor_monotonic_update_guard
            BEFORE UPDATE ON trace_run_anchors
            WHEN NEW.next_sequence < OLD.next_sequence
              OR NEW.anchor_revision <= OLD.anchor_revision
            BEGIN
              SELECT RAISE(ABORT, 'runtime_trace_anchor_not_monotonic');
            END;
            CREATE TRIGGER IF NOT EXISTS trace_anchor_delete_guard
            BEFORE DELETE ON trace_run_anchors
            BEGIN
              SELECT RAISE(ABORT, 'runtime_trace_anchor_immutable');
            END;
            "#,
            )?;
            connection.execute(
                "INSERT OR IGNORE INTO trace_store_metadata (metadata_key, metadata_value) VALUES (?1, ?2)",
                params![TRACE_STORE_ID_KEY, proposed_store_id],
            )?;
            connection.execute_batch("COMMIT")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = connection.execute_batch("ROLLBACK");
        }
        result
    }

    fn try_load_store_id(connection: &Connection) -> Result<Option<String>, TraceStoreError> {
        let result = connection.query_row(
            "SELECT metadata_value FROM trace_store_metadata WHERE metadata_key = ?1",
            params![TRACE_STORE_ID_KEY],
            |row| row.get(0),
        );
        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) if sqlite_error_is_missing_table(&error) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn load_store_id(connection: &Connection) -> Result<String, TraceStoreError> {
        Self::try_load_store_id(connection)?.ok_or(TraceStoreError::RunNotFound)
    }

    /// Converts a stored algorithm label into a hash algorithm.
    fn parse_algorithm(value: &str) -> Result<HashAlgorithm, TraceStoreError> {
        HashAlgorithm::parse(value)
            .ok_or_else(|| TraceStoreError::InvalidHashAlgorithm(value.to_string()))
    }

    /// Builds a content hash from stored algorithm/value parts.
    fn content_hash_from_parts(
        algorithm: &str,
        value: &str,
    ) -> Result<ContentHash, TraceStoreError> {
        let algorithm = Self::parse_algorithm(algorithm)?;
        Ok(ContentHash::new(algorithm, value))
    }

    /// Builds an optional content hash from stored optional parts.
    fn optional_hash_from_parts(
        algorithm: Option<String>,
        value: Option<String>,
    ) -> Result<Option<ContentHash>, TraceStoreError> {
        match (algorithm, value) {
            (None, None) => Ok(None),
            (Some(algorithm), Some(value)) => {
                Ok(Some(Self::content_hash_from_parts(&algorithm, &value)?))
            }
            (algorithm, value) => Err(TraceStoreError::InvalidHashParts { algorithm, value }),
        }
    }

    /// Retrieves the latest sequence and hash for a run.
    fn latest_sequence_and_hash(
        connection: &Connection,
        run_id: &str,
    ) -> Result<Option<(u64, ContentHash)>, TraceStoreError> {
        let mut stmt = connection.prepare(
            "SELECT sequence, event_hash_algo, event_hash_value FROM trace_events WHERE run_id = ?1 ORDER BY sequence DESC LIMIT 1",
        )?;
        let result: Option<(i64, String, String)> = stmt
            .query_row(params![run_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .optional()?;
        match result {
            Some((sequence, algorithm, value)) => {
                let sequence = decode_sequence(sequence)?;
                let hash = Self::content_hash_from_parts(&algorithm, &value)?;
                Ok(Some((sequence, hash)))
            }
            None => Ok(None),
        }
    }

    /// Checks whether a run exists in the store.
    fn run_exists(connection: &Connection, run_id: &str) -> Result<bool, TraceStoreError> {
        let mut stmt =
            connection.prepare("SELECT 1 FROM trace_events WHERE run_id = ?1 LIMIT 1")?;
        let exists: Option<i64> = stmt
            .query_row(params![run_id], |row| row.get(0))
            .optional()?;
        Ok(exists.is_some())
    }

    /// Builds a trace record from a SQLite row.
    fn record_from_row(row: &rusqlite::Row<'_>) -> Result<TraceRecord, TraceStoreError> {
        let run_id: String = row.get(0)?;
        let sequence: i64 = row.get(1)?;
        let payload_bytes: Vec<u8> = row.get(2)?;
        let recorded_at_raw: String = row.get(3)?;
        let event_algo: String = row.get(4)?;
        let event_value: String = row.get(5)?;
        let prev_algo: Option<String> = row.get(6)?;
        let prev_value: Option<String> = row.get(7)?;
        let sequence = decode_sequence(sequence)?;
        let payload =
            serde_json::from_slice(&payload_bytes).map_err(TraceStoreError::Serialization)?;
        let recorded_at = decode_timestamp(&recorded_at_raw)?;
        let event_hash = Self::content_hash_from_parts(&event_algo, &event_value)?;
        let prev_event_hash = Self::optional_hash_from_parts(prev_algo, prev_value)?;
        Ok(TraceRecord {
            run_id,
            sequence,
            payload,
            recorded_at,
            event_hash,
            prev_event_hash,
        })
    }

    fn append_legacy(
        &self,
        run_id: &str,
        payload: serde_json::Value,
    ) -> Result<u64, TraceStoreError> {
        let mut connection = self
            .inner
            .connection
            .lock()
            .map_err(|_| TraceStoreError::Poisoned)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let anchored: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM trace_run_anchor_registry WHERE run_id = ?1",
                params![run_id],
                |row| row.get(0),
            )
            .optional()?;
        if anchored.is_some() {
            let actual = Self::latest_sequence_and_hash(&tx, run_id)?
                .map_or(0, |(sequence, _)| sequence.saturating_add(1));
            return Err(TraceStoreError::SequenceMismatch {
                expected: actual,
                actual: actual.saturating_add(1),
            });
        }
        let (sequence, prev_hash) = match Self::latest_sequence_and_hash(&tx, run_id)? {
            Some((sequence, hash)) => (
                sequence
                    .checked_add(1)
                    .ok_or(TraceStoreError::SequenceOverflow(sequence))?,
                Some(hash),
            ),
            None => (0, None),
        };
        let event_hash = compute_event_hash(prev_hash.as_ref(), &payload)?;
        let payload_bytes = serde_json::to_vec(&payload).map_err(TraceStoreError::Serialization)?;
        let recorded_at_raw = encode_timestamp(OffsetDateTime::now_utc());
        let (event_algo, event_value) = hash_parts(&event_hash);
        let (prev_algo, prev_value) = prev_hash
            .as_ref()
            .map(hash_parts)
            .map(|(algorithm, value)| (Some(algorithm.to_string()), Some(value.to_string())))
            .unwrap_or((None, None));
        tx.execute(
            "INSERT INTO trace_events (run_id, sequence, payload, recorded_at, event_hash_algo, event_hash_value, prev_hash_algo, prev_hash_value) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                run_id,
                encode_sequence(sequence)?,
                payload_bytes,
                recorded_at_raw,
                event_algo,
                event_value,
                prev_algo,
                prev_value,
            ],
        )?;
        tx.commit()?;
        Ok(sequence)
    }
}

impl TraceStore for SqliteTraceStore {
    /// Appends a trace record and persists it in SQLite.
    fn append(&self, run_id: &str, payload: serde_json::Value) -> Result<u64, TraceStoreError> {
        self.append_legacy(run_id, payload)
    }

    /// Reads all trace records for a run from SQLite.
    fn read(&self, run_id: &str) -> Result<Vec<TraceRecord>, TraceStoreError> {
        let connection = self
            .inner
            .connection
            .lock()
            .map_err(|_| TraceStoreError::Poisoned)?;
        let mut stmt = connection.prepare(
            "SELECT run_id, sequence, payload, recorded_at, event_hash_algo, event_hash_value, prev_hash_algo, prev_hash_value FROM trace_events WHERE run_id = ?1 ORDER BY sequence",
        )?;
        let records = stmt
            .query_and_then(params![run_id], Self::record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        if records.is_empty() {
            return Err(TraceStoreError::RunNotFound);
        }
        Ok(records)
    }

    /// Reads a sequence range from SQLite for the specified run.
    fn read_range(
        &self,
        run_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<TraceRecord>, TraceStoreError> {
        let connection = self
            .inner
            .connection
            .lock()
            .map_err(|_| TraceStoreError::Poisoned)?;
        let start_value = encode_sequence(start)?;
        let end_value = encode_sequence(end)?;
        let mut stmt = connection.prepare(
            "SELECT run_id, sequence, payload, recorded_at, event_hash_algo, event_hash_value, prev_hash_algo, prev_hash_value FROM trace_events WHERE run_id = ?1 AND sequence >= ?2 AND sequence < ?3 ORDER BY sequence",
        )?;
        let records = stmt
            .query_and_then(
                params![run_id, start_value, end_value],
                Self::record_from_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        if records.is_empty() && !Self::run_exists(&connection, run_id)? {
            return Err(TraceStoreError::RunNotFound);
        }
        Ok(records)
    }

    fn runtime_store_identity(&self) -> Result<RuntimeTraceStoreIdentity, RuntimeTracePortError> {
        Ok(self.inner.store_identity.clone())
    }

    fn open_runtime_reader(
        &self,
        run_id: &str,
        limits: RuntimeTraceLimits,
    ) -> Result<RuntimeTraceReaderHandle, RuntimeTracePortError> {
        validate_runtime_limits(limits)?;
        Ok(Arc::new(SqliteRuntimeReader {
            inner: Arc::clone(&self.inner),
            run_id: run_id.to_string(),
            limits,
        }))
    }

    fn acquire_runtime_writer(
        &self,
        request: RuntimeTraceWriterRequest,
    ) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
        acquire_sqlite_runtime_writer(Arc::clone(&self.inner), request)
    }
}

struct InMemoryRuntimeReader {
    records: Arc<Mutex<HashMap<String, Vec<TraceRecord>>>>,
    anchors: Arc<Mutex<HashMap<String, InMemoryRuntimeAnchor>>>,
    store_identity: RuntimeTraceStoreIdentity,
    run_id: String,
    limits: RuntimeTraceLimits,
}

impl RuntimeTraceReader for InMemoryRuntimeReader {
    fn store_identity(&self) -> RuntimeTraceStoreIdentity {
        self.store_identity.clone()
    }

    fn run_id(&self) -> &str {
        &self.run_id
    }

    fn limits(&self) -> RuntimeTraceLimits {
        self.limits
    }

    fn tail(&self) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
        let anchors = self
            .anchors
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        if let Some(anchor) = anchors.get(&self.run_id) {
            return Ok(anchor.tail.clone());
        }
        let records = self
            .records
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        compute_legacy_tail(
            self.store_identity.clone(),
            records
                .get(&self.run_id)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            self.limits,
        )
    }

    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError> {
        let records = self
            .records
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        let all = records
            .get(&self.run_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let start = usize::try_from(start).map_err(|_| RuntimeTracePortError::LimitExceeded)?;
        if start > all.len() {
            return Ok(RuntimeTracePage::new(Vec::new(), start as u64, true));
        }
        let end = start
            .saturating_add(self.limits.page_records)
            .min(all.len());
        let page = all[start..end].to_vec();
        validate_page_payload_bounds(&page, self.limits)?;
        Ok(RuntimeTracePage::new(
            page,
            u64::try_from(end).map_err(|_| RuntimeTracePortError::LimitExceeded)?,
            end == all.len(),
        ))
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        let actual = self.tail()?;
        if &actual != expected {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        let records = self
            .records
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        confirm_records_against_tail(
            records
                .get(&self.run_id)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            expected,
            self.limits,
        )
    }
}

struct InMemoryRuntimeWriter {
    reader: InMemoryRuntimeReader,
    operation: Mutex<()>,
    current_tail: Mutex<RuntimeTraceTail>,
    closed: AtomicBool,
}

impl RuntimeTraceReader for InMemoryRuntimeWriter {
    fn store_identity(&self) -> RuntimeTraceStoreIdentity {
        self.reader.store_identity()
    }

    fn run_id(&self) -> &str {
        self.reader.run_id()
    }

    fn limits(&self) -> RuntimeTraceLimits {
        self.reader.limits()
    }

    fn tail(&self) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeTracePortError::Closed);
        }
        self.current_tail
            .lock()
            .map(|tail| tail.clone())
            .map_err(|_| RuntimeTracePortError::Unavailable)
    }

    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeTracePortError::Closed);
        }
        self.reader.read_page(start)
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        if self.tail()? != *expected {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        self.reader.confirm_tail(expected)
    }
}

impl RuntimeTraceWriter for InMemoryRuntimeWriter {
    fn append(
        &self,
        expected: &RuntimeTraceTail,
        payload: serde_json::Value,
    ) -> Result<RuntimeTraceAppend, RuntimeTracePortError> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeTracePortError::Closed);
        }
        let payload_bytes = validate_payload_bound(&payload, self.reader.limits)?;
        let mut current_tail = self
            .current_tail
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        if &*current_tail != expected {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        let mut anchors = self
            .reader
            .anchors
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        let anchor = anchors
            .get_mut(&self.reader.run_id)
            .ok_or(RuntimeTracePortError::IntegrityFailure)?;
        if !anchor.acquired || anchor.tail != *expected {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        let mut records = self
            .reader
            .records
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        let run_records = records.entry(self.reader.run_id.clone()).or_default();
        confirm_records_against_tail(run_records, expected, self.reader.limits)?;
        let history_bytes = validate_history_payload_bounds(run_records, self.reader.limits)?;
        if run_records.len() >= self.reader.limits.max_records
            || history_bytes
                .checked_add(payload_bytes)
                .is_none_or(|bytes| bytes > self.reader.limits.max_bytes)
        {
            return Err(RuntimeTracePortError::LimitExceeded);
        }
        let sequence = expected.next_sequence();
        let stable_hash = compute_event_hash(expected.stable_tail_hash(), &payload)
            .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
        let record = TraceRecord {
            run_id: self.reader.run_id.clone(),
            sequence,
            payload,
            recorded_at: OffsetDateTime::now_utc(),
            event_hash: stable_hash.clone(),
            prev_event_hash: expected.stable_tail_hash().cloned(),
        };
        let envelope_hash = compute_trace_envelope_hash(expected.envelope_tail_hash(), &record)?;
        let fence = expected
            .fence()
            .cloned()
            .ok_or(RuntimeTracePortError::FenceRejected)?;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RuntimeTracePortError::LimitExceeded)?;
        let next_revision = expected
            .anchor_revision()
            .checked_add(1)
            .ok_or(RuntimeTracePortError::IntegrityFailure)?;
        let next_tail = RuntimeTraceTail::current(
            self.reader.store_identity.clone(),
            next_sequence,
            Some(stable_hash),
            Some(envelope_hash),
            next_revision,
            fence,
        )?;
        run_records.push(record);
        anchor.tail = next_tail.clone();
        *current_tail = next_tail.clone();
        Ok(RuntimeTraceAppend::new(sequence, next_tail))
    }

    fn close(&self) -> Result<(), RuntimeTracePortError> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let current = self
            .current_tail
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?
            .clone();
        let mut anchors = self
            .reader
            .anchors
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        let anchor = anchors
            .get_mut(&self.reader.run_id)
            .ok_or(RuntimeTracePortError::IntegrityFailure)?;
        if anchor.tail != current || !anchor.acquired {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        let revision = current
            .anchor_revision()
            .checked_add(1)
            .ok_or(RuntimeTracePortError::IntegrityFailure)?;
        anchor.tail = RuntimeTraceTail::current(
            self.reader.store_identity.clone(),
            current.next_sequence(),
            current.stable_tail_hash().cloned(),
            current.envelope_tail_hash().cloned(),
            revision,
            current
                .fence()
                .cloned()
                .ok_or(RuntimeTracePortError::FenceRejected)?,
        )?;
        anchor.acquired = false;
        Ok(())
    }
}

impl Drop for InMemoryRuntimeWriter {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn acquire_in_memory_runtime_writer(
    store: &InMemoryTraceStore,
    request: RuntimeTraceWriterRequest,
) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
    if request.profile() != RuntimeTraceProfile::CurrentAnchoredV1 {
        return Err(RuntimeTracePortError::Unsupported);
    }
    let limits = request.limits();
    validate_runtime_limits(limits)?;
    let run_id = request.scope().run_id().to_string();
    let mut anchors = store
        .runtime_anchors
        .lock()
        .map_err(|_| RuntimeTracePortError::Unavailable)?;
    let records = store
        .inner
        .lock()
        .map_err(|_| RuntimeTracePortError::Unavailable)?;
    let existing_records = records.get(&run_id).map(Vec::as_slice).unwrap_or_default();
    let tail = if let Some(anchor) = anchors.get_mut(&run_id) {
        if anchor.acquired {
            return Err(RuntimeTracePortError::Conflict);
        }
        confirm_records_against_tail(existing_records, &anchor.tail, limits)?;
        let revision = anchor
            .tail
            .anchor_revision()
            .checked_add(1)
            .ok_or(RuntimeTracePortError::IntegrityFailure)?;
        let acquired = RuntimeTraceTail::current(
            store.store_identity.clone(),
            anchor.tail.next_sequence(),
            anchor.tail.stable_tail_hash().cloned(),
            anchor.tail.envelope_tail_hash().cloned(),
            revision,
            anchor
                .tail
                .fence()
                .cloned()
                .ok_or(RuntimeTracePortError::IntegrityFailure)?,
        )?;
        anchor.tail = acquired.clone();
        anchor.acquired = true;
        acquired
    } else {
        if !existing_records.is_empty() {
            return Err(RuntimeTracePortError::LegacyInspectOnly);
        }
        let fence = RuntimeTraceFence::from_opaque_material(Uuid::new_v4().as_bytes());
        let tail =
            RuntimeTraceTail::current(store.store_identity.clone(), 0, None, None, 1, fence)?;
        anchors.insert(
            run_id.clone(),
            InMemoryRuntimeAnchor {
                tail: tail.clone(),
                acquired: true,
            },
        );
        tail
    };
    drop(records);
    drop(anchors);
    Ok(Arc::new(InMemoryRuntimeWriter {
        reader: InMemoryRuntimeReader {
            records: Arc::clone(&store.inner),
            anchors: Arc::clone(&store.runtime_anchors),
            store_identity: store.store_identity.clone(),
            run_id,
            limits,
        },
        operation: Mutex::new(()),
        current_tail: Mutex::new(tail),
        closed: AtomicBool::new(false),
    }))
}

struct SqliteRuntimeReader {
    inner: Arc<SqliteTraceInner>,
    run_id: String,
    limits: RuntimeTraceLimits,
}

impl RuntimeTraceReader for SqliteRuntimeReader {
    fn store_identity(&self) -> RuntimeTraceStoreIdentity {
        self.inner.store_identity.clone()
    }

    fn run_id(&self) -> &str {
        &self.run_id
    }

    fn limits(&self) -> RuntimeTraceLimits {
        self.limits
    }

    fn tail(&self) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
        let connection = self
            .inner
            .connection
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        load_sqlite_tail(&connection, &self.inner, &self.run_id, self.limits)
    }

    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError> {
        let connection = self
            .inner
            .connection
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        read_sqlite_runtime_page(&connection, &self.run_id, start, self.limits)
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        verify_writable_database_if_present(&self.inner)?;
        let connection = self
            .inner
            .connection
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        let actual = load_sqlite_tail(&connection, &self.inner, &self.run_id, self.limits)?;
        if &actual != expected {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        confirm_sqlite_rows_against_tail(&connection, &self.run_id, expected, self.limits)
            .map(|_| ())
    }
}

struct SqliteRuntimeWriter {
    reader: SqliteRuntimeReader,
    operation: Mutex<()>,
    current_tail: Mutex<RuntimeTraceTail>,
    lock_file: Mutex<Option<File>>,
    process_lock: Mutex<Option<ProcessRuntimeLock>>,
    closed: AtomicBool,
}

impl RuntimeTraceReader for SqliteRuntimeWriter {
    fn store_identity(&self) -> RuntimeTraceStoreIdentity {
        self.reader.store_identity()
    }

    fn run_id(&self) -> &str {
        self.reader.run_id()
    }

    fn limits(&self) -> RuntimeTraceLimits {
        self.reader.limits()
    }

    fn tail(&self) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeTracePortError::Closed);
        }
        self.current_tail
            .lock()
            .map(|tail| tail.clone())
            .map_err(|_| RuntimeTracePortError::Unavailable)
    }

    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeTracePortError::Closed);
        }
        self.reader.read_page(start)
    }

    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError> {
        if self.tail()? != *expected {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        self.reader.confirm_tail(expected)
    }
}

impl RuntimeTraceWriter for SqliteRuntimeWriter {
    fn append(
        &self,
        expected: &RuntimeTraceTail,
        payload: serde_json::Value,
    ) -> Result<RuntimeTraceAppend, RuntimeTracePortError> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(RuntimeTracePortError::Closed);
        }
        let payload_bytes = validate_payload_bound(&payload, self.reader.limits)?;
        verify_writable_database_if_present(&self.reader.inner)?;
        let mut current_tail = self
            .current_tail
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        if &*current_tail != expected {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        let mut connection = self
            .reader
            .inner
            .connection
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_port_error)?;
        let actual = load_current_sqlite_anchor(&tx, &self.reader.inner, &self.reader.run_id)?
            .ok_or(RuntimeTracePortError::IntegrityFailure)?;
        if actual != *expected {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        let (_, history_bytes) = confirm_sqlite_tail_metadata_against_rows(
            &tx,
            &self.reader.run_id,
            expected,
            self.reader.limits,
        )?;
        if expected.next_sequence()
            >= u64::try_from(self.reader.limits.max_records)
                .map_err(|_| RuntimeTracePortError::LimitExceeded)?
            || history_bytes
                .checked_add(payload_bytes)
                .is_none_or(|bytes| bytes > self.reader.limits.max_bytes)
        {
            return Err(RuntimeTracePortError::LimitExceeded);
        }

        let sequence = expected.next_sequence();
        let stable_hash = compute_event_hash(expected.stable_tail_hash(), &payload)
            .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
        let recorded_at = OffsetDateTime::now_utc();
        let record = TraceRecord {
            run_id: self.reader.run_id.clone(),
            sequence,
            payload,
            recorded_at,
            event_hash: stable_hash.clone(),
            prev_event_hash: expected.stable_tail_hash().cloned(),
        };
        let envelope_hash = compute_trace_envelope_hash(expected.envelope_tail_hash(), &record)?;
        let fence = expected
            .fence()
            .cloned()
            .ok_or(RuntimeTracePortError::FenceRejected)?;
        let fence_value = fence.value().to_string();
        tx.execute(
            "INSERT OR REPLACE INTO trace_append_permits (run_id, anchor_revision, fence_digest) VALUES (?1, ?2, ?3)",
            params![
                self.reader.run_id,
                encode_port_sequence(expected.anchor_revision())?,
                fence_value,
            ],
        )
        .map_err(map_sqlite_port_error)?;
        let payload_bytes = serde_json::to_vec(&record.payload)
            .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
        let (event_algo, event_value) = hash_parts(&record.event_hash);
        let (prev_algo, prev_value) = record
            .prev_event_hash
            .as_ref()
            .map(hash_parts)
            .map(|(algorithm, value)| (Some(algorithm.to_string()), Some(value.to_string())))
            .unwrap_or((None, None));
        tx.execute(
            "INSERT INTO trace_events (run_id, sequence, payload, recorded_at, event_hash_algo, event_hash_value, prev_hash_algo, prev_hash_value) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                self.reader.run_id,
                encode_port_sequence(sequence)?,
                payload_bytes,
                encode_timestamp(recorded_at),
                event_algo,
                event_value,
                prev_algo,
                prev_value,
            ],
        )
        .map_err(map_sqlite_port_error)?;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(RuntimeTracePortError::LimitExceeded)?;
        let next_revision = expected
            .anchor_revision()
            .checked_add(1)
            .ok_or(RuntimeTracePortError::IntegrityFailure)?;
        let changed = tx
            .execute(
                "UPDATE trace_run_anchors SET next_sequence = ?1, stable_tail_hash_algo = ?2, stable_tail_hash_value = ?3, envelope_tail_hash_algo = ?4, envelope_tail_hash_value = ?5, anchor_revision = ?6 WHERE run_id = ?7 AND store_id = ?8 AND profile = ?9 AND next_sequence = ?10 AND anchor_revision = ?11 AND fence_digest = ?12",
                params![
                    encode_port_sequence(next_sequence)?,
                    stable_hash.algorithm.as_str(),
                    stable_hash.value,
                    envelope_hash.algorithm.as_str(),
                    envelope_hash.value,
                    encode_port_sequence(next_revision)?,
                    self.reader.run_id,
                    self.reader.inner.store_id,
                    CURRENT_TRACE_PROFILE,
                    encode_port_sequence(expected.next_sequence())?,
                    encode_port_sequence(expected.anchor_revision())?,
                    fence_value,
                ],
            )
            .map_err(map_sqlite_port_error)?;
        if changed != 1 {
            return Err(RuntimeTracePortError::FenceRejected);
        }
        tx.execute(
            "DELETE FROM trace_append_permits WHERE run_id = ?1",
            params![self.reader.run_id],
        )
        .map_err(map_sqlite_port_error)?;
        tx.commit().map_err(map_sqlite_port_error)?;
        let next_tail = RuntimeTraceTail::current(
            self.reader.inner.store_identity.clone(),
            next_sequence,
            Some(stable_hash),
            Some(envelope_hash),
            next_revision,
            fence,
        )?;
        *current_tail = next_tail.clone();
        Ok(RuntimeTraceAppend::new(sequence, next_tail))
    }

    fn close(&self) -> Result<(), RuntimeTracePortError> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let current = self
            .current_tail
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?
            .clone();
        let close_result = (|| {
            verify_writable_database_if_present(&self.reader.inner)?;
            let mut connection = self
                .reader
                .inner
                .connection
                .lock()
                .map_err(|_| RuntimeTracePortError::Unavailable)?;
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(map_sqlite_port_error)?;
            let revision = current
                .anchor_revision()
                .checked_add(1)
                .ok_or(RuntimeTracePortError::IntegrityFailure)?;
            let changed = tx
                .execute(
                    "UPDATE trace_run_anchors SET anchor_revision = ?1 WHERE run_id = ?2 AND store_id = ?3 AND anchor_revision = ?4 AND fence_digest = ?5",
                    params![
                        encode_port_sequence(revision)?,
                        self.reader.run_id,
                        self.reader.inner.store_id,
                        encode_port_sequence(current.anchor_revision())?,
                        current
                            .fence()
                            .ok_or(RuntimeTracePortError::FenceRejected)?
                            .value()
                            .to_string(),
                    ],
                )
                .map_err(map_sqlite_port_error)?;
            if changed != 1 {
                return Err(RuntimeTracePortError::FenceRejected);
            }
            tx.commit().map_err(map_sqlite_port_error)
        })();
        let mut lock_file = self
            .lock_file
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        if let Some(file) = lock_file.take() {
            let _ = flock(&file, FlockOperation::Unlock);
        }
        let mut process_lock = self
            .process_lock
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        process_lock.take();
        close_result
    }
}

impl Drop for SqliteRuntimeWriter {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn acquire_sqlite_runtime_writer(
    inner: Arc<SqliteTraceInner>,
    request: RuntimeTraceWriterRequest,
) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
    if request.profile() != RuntimeTraceProfile::CurrentAnchoredV1 {
        return Err(RuntimeTracePortError::Unsupported);
    }
    let limits = request.limits();
    validate_runtime_limits(limits)?;
    verify_writable_database_if_present(&inner)?;
    let lock_root = inner
        .lock_root
        .as_ref()
        .ok_or(RuntimeTracePortError::Unsupported)?;
    let run_id = request.scope().run_id().to_string();
    let database_identity = inner
        .writable_database
        .as_ref()
        .map(|database| database.identity)
        .ok_or(RuntimeTracePortError::Unsupported)?;
    let shard = runtime_lock_shard(&inner.store_id, database_identity, &run_id);
    let process_lock = ProcessRuntimeLock::acquire(ProcessRuntimeLockKey {
        lock_root: lock_root.identity,
        shard,
    })?;
    let lock_file = lock_root.open_shard(shard)?;
    flock(&lock_file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN {
            RuntimeTracePortError::Conflict
        } else {
            RuntimeTracePortError::Unavailable
        }
    })?;

    let tail_result = (|| {
        let mut connection = inner
            .connection
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_port_error)?;
        let existing = load_current_sqlite_anchor(&tx, &inner, &run_id)?;
        let registry = sqlite_anchor_registry_exists(&tx, &run_id)?;
        let row_count = sqlite_run_row_count(&tx, &run_id)?;
        let tail = match existing {
            Some(anchor) => {
                if !registry {
                    return Err(RuntimeTracePortError::IntegrityFailure);
                }
                confirm_sqlite_rows_against_tail(&tx, &run_id, &anchor, limits)?;
                let revision = anchor
                    .anchor_revision()
                    .checked_add(1)
                    .ok_or(RuntimeTracePortError::IntegrityFailure)?;
                let fence = anchor
                    .fence()
                    .cloned()
                    .ok_or(RuntimeTracePortError::IntegrityFailure)?;
                let changed = tx
                    .execute(
                        "UPDATE trace_run_anchors SET anchor_revision = ?1 WHERE run_id = ?2 AND store_id = ?3 AND anchor_revision = ?4 AND fence_digest = ?5",
                        params![
                            encode_port_sequence(revision)?,
                            run_id,
                            inner.store_id,
                            encode_port_sequence(anchor.anchor_revision())?,
                            fence.value().to_string(),
                        ],
                    )
                    .map_err(map_sqlite_port_error)?;
                if changed != 1 {
                    return Err(RuntimeTracePortError::Conflict);
                }
                RuntimeTraceTail::current(
                    inner.store_identity.clone(),
                    anchor.next_sequence(),
                    anchor.stable_tail_hash().cloned(),
                    anchor.envelope_tail_hash().cloned(),
                    revision,
                    fence,
                )?
            }
            None => {
                if registry {
                    return Err(RuntimeTracePortError::IntegrityFailure);
                }
                if row_count != 0 {
                    return Err(RuntimeTracePortError::LegacyInspectOnly);
                }
                let fence = RuntimeTraceFence::from_opaque_material(Uuid::new_v4().as_bytes());
                tx.execute(
                    "INSERT INTO trace_run_anchor_registry (run_id, store_id, profile) VALUES (?1, ?2, ?3)",
                    params![run_id, inner.store_id, CURRENT_TRACE_PROFILE],
                )
                .map_err(map_sqlite_port_error)?;
                tx.execute(
                    "INSERT INTO trace_run_anchors (run_id, store_id, profile, next_sequence, stable_tail_hash_algo, stable_tail_hash_value, envelope_tail_hash_algo, envelope_tail_hash_value, anchor_revision, fence_digest) VALUES (?1, ?2, ?3, 0, NULL, NULL, NULL, NULL, 1, ?4)",
                    params![
                        run_id,
                        inner.store_id,
                        CURRENT_TRACE_PROFILE,
                        fence.value().to_string(),
                    ],
                )
                .map_err(map_sqlite_port_error)?;
                RuntimeTraceTail::current(inner.store_identity.clone(), 0, None, None, 1, fence)?
            }
        };
        tx.commit().map_err(map_sqlite_port_error)?;
        Ok(tail)
    })();

    let tail = match tail_result {
        Ok(tail) => tail,
        Err(error) => {
            let _ = flock(&lock_file, FlockOperation::Unlock);
            return Err(error);
        }
    };
    Ok(Arc::new(SqliteRuntimeWriter {
        reader: SqliteRuntimeReader {
            inner,
            run_id,
            limits,
        },
        operation: Mutex::new(()),
        current_tail: Mutex::new(tail),
        lock_file: Mutex::new(Some(lock_file)),
        process_lock: Mutex::new(Some(process_lock)),
        closed: AtomicBool::new(false),
    }))
}

impl SecureLockRoot {
    fn open(path: &Path) -> Result<Self, TraceStoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            if !path.exists() {
                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                if let Err(error) = builder.create(path) {
                    if error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidPath(
                            path.to_path_buf(),
                        )));
                    }
                }
            }
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(path).map_err(|_| {
            TraceStoreError::Sqlite(rusqlite::Error::InvalidPath(path.to_path_buf()))
        })?;
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| TraceStoreError::Sqlite(rusqlite::Error::InvalidPath(path.to_path_buf())))?;
        let descriptor = File::from(descriptor);
        let identity = verify_secure_directory(&descriptor, 0o700)?;
        Ok(Self {
            descriptor: Arc::new(descriptor),
            identity,
        })
    }

    fn open_shard(&self, shard: usize) -> Result<File, RuntimeTracePortError> {
        if shard >= RUNTIME_TRACE_LOCK_SHARDS {
            return Err(RuntimeTracePortError::BackendContract);
        }
        let name = format!("shard-{shard:02x}.lock");
        let descriptor = openat(
            self.descriptor.as_ref(),
            name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| RuntimeTracePortError::Unavailable)?;
        let file = File::from(descriptor);
        verify_secure_regular_file_port(&file, 0o600)?;
        Ok(file)
    }
}

impl ProcessRuntimeLock {
    fn acquire(key: ProcessRuntimeLockKey) -> Result<Self, RuntimeTracePortError> {
        let locks = PROCESS_RUNTIME_LOCKS.get_or_init(|| Mutex::new(HashSet::new()));
        let mut locks = locks
            .lock()
            .map_err(|_| RuntimeTracePortError::Unavailable)?;
        if !locks.insert(key) {
            return Err(RuntimeTracePortError::Conflict);
        }
        Ok(Self { key })
    }
}

impl Drop for ProcessRuntimeLock {
    fn drop(&mut self) {
        let locks = PROCESS_RUNTIME_LOCKS.get_or_init(|| Mutex::new(HashSet::new()));
        let mut locks = match locks.lock() {
            Ok(locks) => locks,
            Err(poisoned) => poisoned.into_inner(),
        };
        locks.remove(&self.key);
    }
}

fn sqlite_runtime_store_identity(
    store_id: &str,
    file_identity: Option<FileIdentity>,
) -> RuntimeTraceStoreIdentity {
    let mut material = Vec::from(store_id.as_bytes());
    if let Some(identity) = file_identity {
        material.push(0);
        material.extend_from_slice(&identity.device.to_be_bytes());
        material.extend_from_slice(&identity.inode.to_be_bytes());
    }
    RuntimeTraceStoreIdentity::from_opaque_material(material)
}

fn runtime_lock_shard(store_id: &str, database_identity: FileIdentity, run_id: &str) -> usize {
    let digest = ContentHash::blake3(
        [
            b"splendor.runtime-trace.lock-shard.v1\0".as_slice(),
            store_id.as_bytes(),
            b"\0",
            &database_identity.device.to_be_bytes(),
            &database_identity.inode.to_be_bytes(),
            b"\0",
            run_id.as_bytes(),
        ]
        .concat(),
    );
    usize::from_str_radix(&digest.value[..2], 16).unwrap_or(0)
}

fn open_secure_database(path: &Path) -> Result<File, TraceStoreError> {
    let descriptor = open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| TraceStoreError::Sqlite(rusqlite::Error::InvalidPath(path.to_path_buf())))?;
    Ok(File::from(descriptor))
}

fn verify_secure_directory(
    file: &File,
    expected_mode: u32,
) -> Result<FileIdentity, TraceStoreError> {
    let stat = fstat(file).map_err(|_| TraceStoreError::Sqlite(rusqlite::Error::InvalidQuery))?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || stat.st_uid != getuid().as_raw()
        || (u32::from(stat.st_mode) & 0o777) != expected_mode
    {
        return Err(TraceStoreError::Sqlite(rusqlite::Error::InvalidQuery));
    }
    Ok(FileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    })
}

fn verify_secure_regular_file(
    file: &File,
    expected_mode: u32,
) -> Result<FileIdentity, TraceStoreError> {
    verify_secure_regular_file_port(file, expected_mode)
        .map_err(|_| TraceStoreError::Sqlite(rusqlite::Error::InvalidQuery))
}

fn verify_secure_regular_file_port(
    file: &File,
    expected_mode: u32,
) -> Result<FileIdentity, RuntimeTracePortError> {
    let stat = fstat(file).map_err(|_| RuntimeTracePortError::Unavailable)?;
    if !secure_regular_file_attributes(
        stat.st_mode,
        stat.st_uid,
        u64::from(stat.st_nlink),
        expected_mode,
        getuid().as_raw(),
    ) {
        return Err(RuntimeTracePortError::IntegrityFailure);
    }
    Ok(FileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    })
}

fn secure_regular_file_attributes(
    mode: RawMode,
    owner_uid: u32,
    link_count: u64,
    expected_mode: u32,
    current_uid: u32,
) -> bool {
    FileType::from_raw_mode(mode).is_file()
        && owner_uid == current_uid
        && link_count == 1
        && (u32::from(mode) & 0o777) == expected_mode
}

fn verify_writable_database_if_present(
    inner: &SqliteTraceInner,
) -> Result<(), RuntimeTracePortError> {
    let Some(database) = inner.writable_database.as_ref() else {
        return Ok(());
    };
    let descriptor_identity = verify_secure_regular_file_port(&database.descriptor, 0o600)?;
    if descriptor_identity != database.identity {
        return Err(RuntimeTracePortError::IntegrityFailure);
    }
    let path_descriptor = open(
        &database.path,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let path_file = File::from(path_descriptor);
    let path_identity = verify_secure_regular_file_port(&path_file, 0o600)?;
    if path_identity != database.identity {
        return Err(RuntimeTracePortError::IntegrityFailure);
    }
    Ok(())
}

fn validate_runtime_limits(limits: RuntimeTraceLimits) -> Result<(), RuntimeTracePortError> {
    RuntimeTraceLimits::checked(
        limits.page_records,
        limits.max_records,
        limits.max_bytes,
        limits.max_payload_bytes,
    )
    .map(|_| ())
}

fn validate_payload_bound(
    payload: &serde_json::Value,
    limits: RuntimeTraceLimits,
) -> Result<usize, RuntimeTracePortError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    if bytes.len() > limits.max_payload_bytes {
        return Err(RuntimeTracePortError::LimitExceeded);
    }
    Ok(bytes.len())
}

fn validate_page_payload_bounds(
    records: &[TraceRecord],
    limits: RuntimeTraceLimits,
) -> Result<usize, RuntimeTracePortError> {
    if records.len() > limits.page_records {
        return Err(RuntimeTracePortError::BackendContract);
    }
    let mut bytes = 0usize;
    for record in records {
        bytes = bytes
            .checked_add(validate_payload_bound(&record.payload, limits)?)
            .ok_or(RuntimeTracePortError::LimitExceeded)?;
    }
    Ok(bytes)
}

fn validate_history_payload_bounds(
    records: &[TraceRecord],
    limits: RuntimeTraceLimits,
) -> Result<usize, RuntimeTracePortError> {
    if records.len() > limits.max_records {
        return Err(RuntimeTracePortError::LimitExceeded);
    }
    let mut bytes = 0usize;
    for record in records {
        bytes = bytes
            .checked_add(validate_payload_bound(&record.payload, limits)?)
            .ok_or(RuntimeTracePortError::LimitExceeded)?;
        if bytes > limits.max_bytes {
            return Err(RuntimeTracePortError::LimitExceeded);
        }
    }
    Ok(bytes)
}

fn compute_legacy_tail(
    store_identity: RuntimeTraceStoreIdentity,
    records: &[TraceRecord],
    limits: RuntimeTraceLimits,
) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
    validate_history_payload_bounds(records, limits)?;
    let mut envelope_hash = None;
    for record in records {
        envelope_hash = Some(compute_trace_envelope_hash(envelope_hash.as_ref(), record)?);
    }
    RuntimeTraceTail::legacy(
        store_identity,
        u64::try_from(records.len()).map_err(|_| RuntimeTracePortError::LimitExceeded)?,
        records.last().map(|record| record.event_hash.clone()),
        envelope_hash,
    )
}

fn confirm_records_against_tail(
    records: &[TraceRecord],
    tail: &RuntimeTraceTail,
    limits: RuntimeTraceLimits,
) -> Result<(), RuntimeTracePortError> {
    let computed = compute_legacy_tail(tail.store_identity().clone(), records, limits)?;
    if computed.next_sequence() != tail.next_sequence()
        || computed.stable_tail_hash() != tail.stable_tail_hash()
        || computed.envelope_tail_hash() != tail.envelope_tail_hash()
    {
        return Err(RuntimeTracePortError::IntegrityFailure);
    }
    Ok(())
}

fn read_sqlite_runtime_page(
    connection: &Connection,
    run_id: &str,
    start: u64,
    limits: RuntimeTraceLimits,
) -> Result<RuntimeTracePage, RuntimeTracePortError> {
    let start = encode_port_sequence(start)?;
    let limit =
        i64::try_from(limits.page_records).map_err(|_| RuntimeTracePortError::LimitExceeded)?;
    let mut statement = connection
        .prepare(
            "SELECT run_id, sequence, length(payload), payload, recorded_at, event_hash_algo, event_hash_value, prev_hash_algo, prev_hash_value FROM trace_events WHERE run_id = ?1 AND sequence >= ?2 ORDER BY sequence LIMIT ?3",
        )
        .map_err(map_sqlite_port_error)?;
    let mut rows = statement
        .query(params![run_id, start, limit])
        .map_err(map_sqlite_port_error)?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(map_sqlite_port_error)? {
        let payload_len: i64 = row
            .get(2)
            .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
        if payload_len < 0
            || usize::try_from(payload_len).map_or(true, |length| length > limits.max_payload_bytes)
        {
            return Err(RuntimeTracePortError::LimitExceeded);
        }
        records.push(runtime_record_from_row(row)?);
    }
    validate_page_payload_bounds(&records, limits)?;
    let next = records
        .last()
        .map(|record| record.sequence.saturating_add(1))
        .unwrap_or_else(|| u64::try_from(start).unwrap_or_default());
    let has_more: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM trace_events WHERE run_id = ?1 AND sequence >= ?2 LIMIT 1",
            params![run_id, encode_port_sequence(next)?],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_port_error)?;
    Ok(RuntimeTracePage::new(records, next, has_more.is_none()))
}

fn runtime_record_from_row(row: &rusqlite::Row<'_>) -> Result<TraceRecord, RuntimeTracePortError> {
    let run_id: String = row
        .get(0)
        .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let sequence: i64 = row
        .get(1)
        .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let payload_bytes: Vec<u8> = row
        .get(3)
        .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let recorded_at_raw: String = row
        .get(4)
        .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let event_algo: String = row
        .get(5)
        .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let event_value: String = row
        .get(6)
        .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let prev_algo: Option<String> = row
        .get(7)
        .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let prev_value: Option<String> = row
        .get(8)
        .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let sequence = decode_port_sequence(sequence)?;
    let payload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let recorded_at =
        decode_timestamp(&recorded_at_raw).map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let event_hash = content_hash_from_port_parts(&event_algo, &event_value)?;
    let prev_event_hash = optional_hash_from_port_parts(prev_algo, prev_value)?;
    Ok(TraceRecord {
        run_id,
        sequence,
        payload,
        recorded_at,
        event_hash,
        prev_event_hash,
    })
}

fn load_sqlite_tail(
    connection: &Connection,
    inner: &SqliteTraceInner,
    run_id: &str,
    limits: RuntimeTraceLimits,
) -> Result<RuntimeTraceTail, RuntimeTracePortError> {
    validate_sqlite_history_bounds(connection, run_id, limits)?;
    if let Some(anchor) = load_current_sqlite_anchor(connection, inner, run_id)? {
        if !sqlite_anchor_registry_exists(connection, run_id)? {
            return Err(RuntimeTracePortError::IntegrityFailure);
        }
        return Ok(anchor);
    }
    if sqlite_anchor_registry_exists(connection, run_id)? {
        return Err(RuntimeTracePortError::IntegrityFailure);
    }
    let mut records = Vec::new();
    let mut next = 0u64;
    loop {
        let page = read_sqlite_runtime_page(connection, run_id, next, limits)?;
        if page.records().is_empty() {
            break;
        }
        if records.len().saturating_add(page.records().len()) > limits.max_records {
            return Err(RuntimeTracePortError::LimitExceeded);
        }
        next = page.next_sequence();
        let complete = page.complete();
        records.extend(page.into_records());
        if complete {
            break;
        }
    }
    compute_legacy_tail(inner.store_identity.clone(), &records, limits)
}

fn load_current_sqlite_anchor(
    connection: &Connection,
    inner: &SqliteTraceInner,
    run_id: &str,
) -> Result<Option<RuntimeTraceTail>, RuntimeTracePortError> {
    let result = connection.query_row(
        "SELECT store_id, profile, next_sequence, stable_tail_hash_algo, stable_tail_hash_value, envelope_tail_hash_algo, envelope_tail_hash_value, anchor_revision, fence_digest FROM trace_run_anchors WHERE run_id = ?1",
        params![run_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
            ))
        },
    );
    let row = match result {
        Ok(row) => Some(row),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(error) if sqlite_error_is_missing_table(&error) => None,
        Err(error) => return Err(map_sqlite_port_error(error)),
    };
    let Some((
        store_id,
        profile,
        next,
        stable_algo,
        stable_value,
        envelope_algo,
        envelope_value,
        revision,
        fence,
    )) = row
    else {
        return Ok(None);
    };
    if store_id != inner.store_id || profile != CURRENT_TRACE_PROFILE {
        return Err(RuntimeTracePortError::IntegrityFailure);
    }
    let stable = optional_hash_from_port_parts(stable_algo, stable_value)?;
    let envelope = optional_hash_from_port_parts(envelope_algo, envelope_value)?;
    let tail = RuntimeTraceTail::current(
        inner.store_identity.clone(),
        decode_port_sequence(next)?,
        stable,
        envelope,
        decode_port_sequence(revision)?,
        RuntimeTraceFence::from_persisted_digest(
            ContentHash::parse(&fence).ok_or(RuntimeTracePortError::IntegrityFailure)?,
        ),
    )?;
    Ok(Some(tail))
}

fn sqlite_anchor_registry_exists(
    connection: &Connection,
    run_id: &str,
) -> Result<bool, RuntimeTracePortError> {
    let result = connection.query_row(
        "SELECT 1 FROM trace_run_anchor_registry WHERE run_id = ?1 LIMIT 1",
        params![run_id],
        |row| row.get::<_, i64>(0),
    );
    match result {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(error) if sqlite_error_is_missing_table(&error) => Ok(false),
        Err(error) => Err(map_sqlite_port_error(error)),
    }
}

fn sqlite_run_row_count(
    connection: &Connection,
    run_id: &str,
) -> Result<u64, RuntimeTracePortError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM trace_events WHERE run_id = ?1",
            params![run_id],
            |row| row.get(0),
        )
        .map_err(map_sqlite_port_error)?;
    decode_port_sequence(count)
}

fn confirm_sqlite_rows_against_tail(
    connection: &Connection,
    run_id: &str,
    expected: &RuntimeTraceTail,
    limits: RuntimeTraceLimits,
) -> Result<(u64, usize), RuntimeTracePortError> {
    let bounds = confirm_sqlite_tail_metadata_against_rows(connection, run_id, expected, limits)?;
    let mut next_sequence = 0u64;
    let mut stable_tail = None;
    let mut envelope_tail = None;
    while next_sequence < expected.next_sequence() {
        let page = read_sqlite_runtime_page(connection, run_id, next_sequence, limits)?;
        if page.records().is_empty() || page.next_sequence() <= next_sequence {
            return Err(RuntimeTracePortError::IntegrityFailure);
        }
        for record in page.records() {
            if record.run_id != run_id
                || record.sequence != next_sequence
                || record.prev_event_hash.as_ref() != stable_tail.as_ref()
            {
                return Err(RuntimeTracePortError::IntegrityFailure);
            }
            let stable_hash = compute_event_hash(record.prev_event_hash.as_ref(), &record.payload)
                .map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
            if stable_hash != record.event_hash {
                return Err(RuntimeTracePortError::IntegrityFailure);
            }
            envelope_tail = Some(compute_trace_envelope_hash(envelope_tail.as_ref(), record)?);
            stable_tail = Some(stable_hash);
            next_sequence = next_sequence
                .checked_add(1)
                .ok_or(RuntimeTracePortError::LimitExceeded)?;
        }
        if page.next_sequence() != next_sequence
            || page.complete() != (next_sequence == expected.next_sequence())
        {
            return Err(RuntimeTracePortError::IntegrityFailure);
        }
    }
    if stable_tail.as_ref() != expected.stable_tail_hash()
        || envelope_tail.as_ref() != expected.envelope_tail_hash()
    {
        return Err(RuntimeTracePortError::IntegrityFailure);
    }
    Ok(bounds)
}

fn confirm_sqlite_tail_metadata_against_rows(
    connection: &Connection,
    run_id: &str,
    expected: &RuntimeTraceTail,
    limits: RuntimeTraceLimits,
) -> Result<(u64, usize), RuntimeTracePortError> {
    let (count, bytes) = validate_sqlite_history_bounds(connection, run_id, limits)?;
    if count != expected.next_sequence() {
        return Err(RuntimeTracePortError::IntegrityFailure);
    }
    let latest = connection.query_row(
        "SELECT event_hash_algo, event_hash_value FROM trace_events WHERE run_id = ?1 ORDER BY sequence DESC LIMIT 1",
        params![run_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    );
    let latest = match latest {
        Ok((algorithm, value)) => Some(content_hash_from_port_parts(&algorithm, &value)?),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(error) => return Err(map_sqlite_port_error(error)),
    };
    if latest.as_ref() != expected.stable_tail_hash() {
        return Err(RuntimeTracePortError::IntegrityFailure);
    }
    Ok((count, bytes))
}

fn validate_sqlite_history_bounds(
    connection: &Connection,
    run_id: &str,
    limits: RuntimeTraceLimits,
) -> Result<(u64, usize), RuntimeTracePortError> {
    let (count, total_bytes, max_payload_bytes): (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(payload)), 0), COALESCE(MAX(length(payload)), 0) FROM trace_events WHERE run_id = ?1",
            params![run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(map_sqlite_port_error)?;
    let count = decode_port_sequence(count)?;
    let total_bytes =
        usize::try_from(total_bytes).map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let max_payload_bytes =
        usize::try_from(max_payload_bytes).map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    if count
        > u64::try_from(limits.max_records).map_err(|_| RuntimeTracePortError::LimitExceeded)?
        || total_bytes > limits.max_bytes
        || max_payload_bytes > limits.max_payload_bytes
    {
        return Err(RuntimeTracePortError::LimitExceeded);
    }
    Ok((count, total_bytes))
}

fn content_hash_from_port_parts(
    algorithm: &str,
    value: &str,
) -> Result<ContentHash, RuntimeTracePortError> {
    let algorithm =
        HashAlgorithm::parse(algorithm).ok_or(RuntimeTracePortError::IntegrityFailure)?;
    Ok(ContentHash::new(algorithm, value))
}

fn optional_hash_from_port_parts(
    algorithm: Option<String>,
    value: Option<String>,
) -> Result<Option<ContentHash>, RuntimeTracePortError> {
    match (algorithm, value) {
        (None, None) => Ok(None),
        (Some(algorithm), Some(value)) => {
            Ok(Some(content_hash_from_port_parts(&algorithm, &value)?))
        }
        _ => Err(RuntimeTracePortError::IntegrityFailure),
    }
}

fn encode_port_sequence(value: u64) -> Result<i64, RuntimeTracePortError> {
    i64::try_from(value).map_err(|_| RuntimeTracePortError::LimitExceeded)
}

fn decode_port_sequence(value: i64) -> Result<u64, RuntimeTracePortError> {
    u64::try_from(value).map_err(|_| RuntimeTracePortError::IntegrityFailure)
}

fn map_sqlite_port_error(error: rusqlite::Error) -> RuntimeTracePortError {
    if sqlite_error_is_busy(&error) {
        RuntimeTracePortError::Conflict
    } else {
        RuntimeTracePortError::Unavailable
    }
}

impl AsyncTraceStore for SqliteTraceStore {
    type AppendFuture<'a>
        = Ready<Result<u64, TraceStoreError>>
    where
        Self: 'a;
    type ReadFuture<'a>
        = Ready<Result<Vec<TraceRecord>, TraceStoreError>>
    where
        Self: 'a;
    type ReadRangeFuture<'a>
        = Ready<Result<Vec<TraceRecord>, TraceStoreError>>
    where
        Self: 'a;

    /// Async wrapper around `append` for SQLite traces.
    fn append<'a>(&'a self, run_id: &'a str, payload: serde_json::Value) -> Self::AppendFuture<'a> {
        ready(TraceStore::append(self, run_id, payload))
    }

    /// Async wrapper around `read` for SQLite traces.
    fn read<'a>(&'a self, run_id: &'a str) -> Self::ReadFuture<'a> {
        ready(TraceStore::read(self, run_id))
    }

    /// Async wrapper around `read_range` for SQLite traces.
    fn read_range<'a>(
        &'a self,
        run_id: &'a str,
        start: u64,
        end: u64,
    ) -> Self::ReadRangeFuture<'a> {
        ready(TraceStore::read_range(self, run_id, start, end))
    }
}

/// Computes a deterministic event hash for a payload.
pub fn compute_trace_event_hash(
    prev_hash: Option<&ContentHash>,
    payload: &serde_json::Value,
) -> Result<ContentHash, TraceStoreError> {
    let normalized = normalize_payload_for_hash(payload);
    let payload_bytes = serde_json::to_vec(&normalized).map_err(TraceStoreError::Serialization)?;
    let mut bytes = Vec::new();
    if let Some(prev_hash) = prev_hash {
        bytes.extend_from_slice(prev_hash.to_string().as_bytes());
    }
    bytes.extend_from_slice(&payload_bytes);
    Ok(ContentHash::blake3(bytes))
}

pub(crate) fn compute_event_hash(
    prev_hash: Option<&ContentHash>,
    payload: &serde_json::Value,
) -> Result<ContentHash, TraceStoreError> {
    compute_trace_event_hash(prev_hash, payload)
}

fn ensure_expected_sequence(expected: u64, actual: u64) -> Result<(), TraceStoreError> {
    if expected != actual {
        return Err(TraceStoreError::SequenceMismatch { expected, actual });
    }
    Ok(())
}

fn sqlite_error_is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(failure.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

fn sqlite_error_is_missing_table(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(_, Some(message))
            if message.contains("no such table")
    )
}

fn normalize_payload_for_hash(payload: &serde_json::Value) -> serde_json::Value {
    let mut normalized = payload.clone();
    if let Some(kind) = normalized.get_mut("kind") {
        if let Some(loop_tick) = kind.get_mut("LoopTickCompleted") {
            if let Some(object) = loop_tick.as_object_mut() {
                object.remove("integrity");
            }
        }
    }
    normalized
}

/// Encodes a timestamp into a string for storage.
fn encode_timestamp(timestamp: OffsetDateTime) -> String {
    timestamp.unix_timestamp_nanos().to_string()
}

/// Decodes a stored timestamp string into an `OffsetDateTime`.
fn decode_timestamp(value: &str) -> Result<OffsetDateTime, TraceStoreError> {
    let nanos = value
        .parse::<i128>()
        .map_err(|_| TraceStoreError::InvalidTimestamp(value.to_string()))?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| TraceStoreError::InvalidTimestamp(value.to_string()))
}

/// Encodes a sequence number for SQLite storage.
fn encode_sequence(sequence: u64) -> Result<i64, TraceStoreError> {
    i64::try_from(sequence).map_err(|_| TraceStoreError::SequenceOverflow(sequence))
}

/// Decodes a sequence number from SQLite storage.
fn decode_sequence(sequence: i64) -> Result<u64, TraceStoreError> {
    if sequence < 0 {
        return Err(TraceStoreError::InvalidSequence(sequence));
    }
    Ok(sequence as u64)
}

/// Returns the algorithm/value parts for a content hash.
fn hash_parts(hash: &ContentHash) -> (&str, &str) {
    (hash.algorithm.as_str(), hash.value.as_str())
}

/// Errors returned by trace stores.
#[derive(Debug, thiserror::Error)]
pub enum TraceStoreError {
    /// The backing mutex was poisoned.
    #[error("trace store mutex was poisoned")]
    Poisoned,
    /// Requested run identifier does not exist.
    #[error("run was not found")]
    RunNotFound,
    /// Hash algorithm could not be parsed.
    #[error("invalid hash algorithm: {0}")]
    InvalidHashAlgorithm(String),
    /// Hash parts were incomplete or inconsistent.
    #[error("invalid hash parts: algorithm={algorithm:?} value={value:?}")]
    InvalidHashParts {
        algorithm: Option<String>,
        value: Option<String>,
    },
    /// Trace payload could not be serialized or deserialized.
    #[error("failed to serialize trace payload: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Timestamp could not be parsed from storage.
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),
    /// Sequence values could not be stored or parsed.
    #[error("invalid sequence value: {0}")]
    InvalidSequence(i64),
    /// Sequence overflow occurred when storing a value.
    #[error("sequence overflow for value: {0}")]
    SequenceOverflow(u64),
    /// Conditional append expected a different next storage-owned sequence.
    #[error("trace sequence mismatch: expected {expected}, actual {actual}")]
    SequenceMismatch {
        /// Sequence expected by the conditional writer.
        expected: u64,
        /// Next sequence atomically assigned by the store.
        actual: u64,
    },
    /// SQLite storage error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

#[cfg(test)]
#[path = "../tests/unit/trace_tests.rs"]
mod tests;
