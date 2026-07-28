//! Mechanical runtime trace capabilities.
//!
//! These ports deliberately contain no tick, policy, recovery, replay, or
//! evidence semantics. A capability provides bounded reads, tail confirmation,
//! atomic fenced append, and synchronous close. Semantic owners live above the
//! store boundary.

use crate::TraceRecord;
use splendor_types::ContentHash;
use std::fmt;
use std::sync::Arc;

/// Maximum records returned by one runtime trace page.
pub const MAX_RUNTIME_TRACE_PAGE_RECORDS: usize = 256;
/// Default maximum records inspected for one run.
pub const DEFAULT_RUNTIME_TRACE_MAX_RECORDS: usize = 100_000;
/// Default maximum serialized payload bytes inspected for one run.
pub const DEFAULT_RUNTIME_TRACE_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Default maximum serialized bytes accepted for one trace payload.
pub const DEFAULT_RUNTIME_TRACE_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Fixed upper bound for local runtime-owner lock objects.
pub const RUNTIME_TRACE_LOCK_SHARDS: usize = 256;

/// Stable, non-reflecting identity for one physical trace store.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RuntimeTraceStoreIdentity(ContentHash);

impl RuntimeTraceStoreIdentity {
    /// Creates an opaque identity from backend-owned stable material.
    pub fn from_opaque_material(material: impl AsRef<[u8]>) -> Self {
        let mut bytes = b"splendor.runtime-trace.store-identity.v1\0".to_vec();
        bytes.extend_from_slice(material.as_ref());
        Self(ContentHash::blake3(bytes))
    }
}

impl fmt::Debug for RuntimeTraceStoreIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeTraceStoreIdentity([REDACTED])")
    }
}

/// Exact runtime identity requesting one run-partition capability.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeTraceScope {
    run_id: String,
    tenant_id: String,
    agent_id: String,
}

impl RuntimeTraceScope {
    /// Creates an exact run/tenant/agent scope.
    pub fn new(
        run_id: impl Into<String>,
        tenant_id: impl Into<String>,
        agent_id: impl Into<String>,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            tenant_id: tenant_id.into(),
            agent_id: agent_id.into(),
        }
    }

    /// Run partition requested by the owner.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Tenant identity supplied by the semantic owner.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Agent identity supplied by the semantic owner.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
}

impl fmt::Debug for RuntimeTraceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTraceScope")
            .finish_non_exhaustive()
    }
}

/// Storage profile reported for a run partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RuntimeTraceProfile {
    /// Fresh additive profile with a durable high-water and full-envelope anchor.
    CurrentAnchoredV1,
    /// Historical non-empty records without a durable tail anchor.
    LegacyUnanchored,
}

/// Conservative resource limits for runtime trace operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeTraceLimits {
    /// Maximum records returned by one backend page.
    pub page_records: usize,
    /// Maximum records inspected for one run.
    pub max_records: usize,
    /// Maximum aggregate serialized payload bytes inspected for one run.
    pub max_bytes: usize,
    /// Maximum serialized bytes for one payload.
    pub max_payload_bytes: usize,
}

impl RuntimeTraceLimits {
    /// Validates explicit limits before any store read.
    pub fn checked(
        page_records: usize,
        max_records: usize,
        max_bytes: usize,
        max_payload_bytes: usize,
    ) -> Result<Self, RuntimeTracePortError> {
        if page_records == 0
            || page_records > MAX_RUNTIME_TRACE_PAGE_RECORDS
            || max_records == 0
            || max_bytes == 0
            || max_payload_bytes == 0
            || max_payload_bytes > max_bytes
        {
            return Err(RuntimeTracePortError::LimitExceeded);
        }
        Ok(Self {
            page_records,
            max_records,
            max_bytes,
            max_payload_bytes,
        })
    }
}

impl Default for RuntimeTraceLimits {
    fn default() -> Self {
        Self {
            page_records: MAX_RUNTIME_TRACE_PAGE_RECORDS,
            max_records: DEFAULT_RUNTIME_TRACE_MAX_RECORDS,
            max_bytes: DEFAULT_RUNTIME_TRACE_MAX_BYTES,
            max_payload_bytes: DEFAULT_RUNTIME_TRACE_MAX_PAYLOAD_BYTES,
        }
    }
}

/// Opaque local fence binding retained inside a runtime tail.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeTraceFence(ContentHash);

impl RuntimeTraceFence {
    /// Creates a fence digest from backend-owned material.
    pub fn from_opaque_material(material: impl AsRef<[u8]>) -> Self {
        let mut bytes = b"splendor.runtime-trace.fence.v1\0".to_vec();
        bytes.extend_from_slice(material.as_ref());
        Self(ContentHash::blake3(bytes))
    }

    /// Restores a backend-persisted fence digest without exposing its value in
    /// diagnostics.
    pub fn from_persisted_digest(digest: ContentHash) -> Self {
        Self(digest)
    }

    pub(crate) fn value(&self) -> &ContentHash {
        &self.0
    }
}

impl fmt::Debug for RuntimeTraceFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeTraceFence([REDACTED])")
    }
}

/// Confirmed run tail used for compare-and-append.
#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeTraceTail {
    store_identity: RuntimeTraceStoreIdentity,
    profile: RuntimeTraceProfile,
    next_sequence: u64,
    stable_tail_hash: Option<ContentHash>,
    envelope_tail_hash: Option<ContentHash>,
    anchor_revision: u64,
    fence: Option<RuntimeTraceFence>,
}

impl RuntimeTraceTail {
    /// Creates a current anchored tail for an external backend implementation.
    pub fn current(
        store_identity: RuntimeTraceStoreIdentity,
        next_sequence: u64,
        stable_tail_hash: Option<ContentHash>,
        envelope_tail_hash: Option<ContentHash>,
        anchor_revision: u64,
        fence: RuntimeTraceFence,
    ) -> Result<Self, RuntimeTracePortError> {
        if next_sequence == 0 {
            if stable_tail_hash.is_some() || envelope_tail_hash.is_some() {
                return Err(RuntimeTracePortError::IntegrityFailure);
            }
        } else if stable_tail_hash.is_none() || envelope_tail_hash.is_none() {
            return Err(RuntimeTracePortError::IntegrityFailure);
        }
        Ok(Self {
            store_identity,
            profile: RuntimeTraceProfile::CurrentAnchoredV1,
            next_sequence,
            stable_tail_hash,
            envelope_tail_hash,
            anchor_revision,
            fence: Some(fence),
        })
    }

    /// Creates an inspect-only unanchored legacy tail.
    pub fn legacy(
        store_identity: RuntimeTraceStoreIdentity,
        next_sequence: u64,
        stable_tail_hash: Option<ContentHash>,
        envelope_tail_hash: Option<ContentHash>,
    ) -> Result<Self, RuntimeTracePortError> {
        if next_sequence == 0 {
            if stable_tail_hash.is_some() || envelope_tail_hash.is_some() {
                return Err(RuntimeTracePortError::IntegrityFailure);
            }
        } else if stable_tail_hash.is_none() || envelope_tail_hash.is_none() {
            return Err(RuntimeTracePortError::IntegrityFailure);
        }
        Ok(Self {
            store_identity,
            profile: RuntimeTraceProfile::LegacyUnanchored,
            next_sequence,
            stable_tail_hash,
            envelope_tail_hash,
            anchor_revision: 0,
            fence: None,
        })
    }

    /// Store identity bound to the tail.
    pub fn store_identity(&self) -> &RuntimeTraceStoreIdentity {
        &self.store_identity
    }

    /// Current or historical profile.
    pub fn profile(&self) -> RuntimeTraceProfile {
        self.profile
    }

    /// Next store-owned sequence.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Stable 0.1 hash at the confirmed tail.
    pub fn stable_tail_hash(&self) -> Option<&ContentHash> {
        self.stable_tail_hash.as_ref()
    }

    /// Full storage-envelope hash at the confirmed tail.
    pub fn envelope_tail_hash(&self) -> Option<&ContentHash> {
        self.envelope_tail_hash.as_ref()
    }

    /// Monotonic local anchor revision.
    pub fn anchor_revision(&self) -> u64 {
        self.anchor_revision
    }

    pub(crate) fn fence(&self) -> Option<&RuntimeTraceFence> {
        self.fence.as_ref()
    }
}

impl fmt::Debug for RuntimeTraceTail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTraceTail")
            .field("profile", &self.profile)
            .field("next_sequence", &self.next_sequence)
            .field("anchor_revision", &self.anchor_revision)
            .finish_non_exhaustive()
    }
}

/// One bounded page returned by a runtime reader.
pub struct RuntimeTracePage {
    records: Vec<TraceRecord>,
    next_sequence: u64,
    complete: bool,
}

impl RuntimeTracePage {
    /// Creates a page for an external backend implementation.
    pub fn new(records: Vec<TraceRecord>, next_sequence: u64, complete: bool) -> Self {
        Self {
            records,
            next_sequence,
            complete,
        }
    }

    /// Borrow the records in this page.
    pub fn records(&self) -> &[TraceRecord] {
        &self.records
    }

    /// Consume the page and return its records.
    pub fn into_records(self) -> Vec<TraceRecord> {
        self.records
    }

    /// Sequence at which the next page starts.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Whether this page reached the currently confirmed tail.
    pub fn complete(&self) -> bool {
        self.complete
    }
}

impl fmt::Debug for RuntimeTracePage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTracePage")
            .field("record_count", &self.records.len())
            .field("next_sequence", &self.next_sequence)
            .field("complete", &self.complete)
            .finish()
    }
}

/// Result of one fenced append.
#[derive(Clone, Debug)]
pub struct RuntimeTraceAppend {
    sequence: u64,
    tail: RuntimeTraceTail,
}

impl RuntimeTraceAppend {
    /// Creates an append result for an external backend implementation.
    pub fn new(sequence: u64, tail: RuntimeTraceTail) -> Self {
        Self { sequence, tail }
    }

    /// Assigned storage sequence.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Confirmed tail after commit.
    pub fn tail(&self) -> &RuntimeTraceTail {
        &self.tail
    }

    /// Consumes the result and returns its tail.
    pub fn into_tail(self) -> RuntimeTraceTail {
        self.tail
    }
}

/// Request for the current fresh local anchored writer profile.
pub struct RuntimeTraceWriterRequest {
    scope: RuntimeTraceScope,
    limits: RuntimeTraceLimits,
    profile: RuntimeTraceProfile,
}

impl RuntimeTraceWriterRequest {
    /// Creates the only currently supported live writer request.
    pub fn current(scope: RuntimeTraceScope, limits: RuntimeTraceLimits) -> Self {
        Self {
            scope,
            limits,
            profile: RuntimeTraceProfile::CurrentAnchoredV1,
        }
    }

    /// Exact semantic-owner scope.
    pub fn scope(&self) -> &RuntimeTraceScope {
        &self.scope
    }

    /// Required operation limits.
    pub fn limits(&self) -> RuntimeTraceLimits {
        self.limits
    }

    /// Requested storage profile.
    pub fn profile(&self) -> RuntimeTraceProfile {
        self.profile
    }
}

impl fmt::Debug for RuntimeTraceWriterRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTraceWriterRequest")
            .field("limits", &self.limits)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

/// Read capability tied to one store and run partition.
pub trait RuntimeTraceReader: Send + Sync {
    /// Stable physical store identity.
    fn store_identity(&self) -> RuntimeTraceStoreIdentity;
    /// Exact run partition bound to this capability.
    fn run_id(&self) -> &str;
    /// Limits enforced by this capability.
    fn limits(&self) -> RuntimeTraceLimits;
    /// Mechanically confirmed tail and profile.
    fn tail(&self) -> Result<RuntimeTraceTail, RuntimeTracePortError>;
    /// Reads one bounded page starting at an exact storage sequence.
    fn read_page(&self, start: u64) -> Result<RuntimeTracePage, RuntimeTracePortError>;
    /// Reconfirms that no row or anchor changed since validation.
    fn confirm_tail(&self, expected: &RuntimeTraceTail) -> Result<(), RuntimeTracePortError>;
}

/// Exclusive append capability retained for the complete runtime lifecycle.
pub trait RuntimeTraceWriter: RuntimeTraceReader {
    /// Atomically appends at the exact confirmed tail under the live fence.
    fn append(
        &self,
        expected: &RuntimeTraceTail,
        payload: serde_json::Value,
    ) -> Result<RuntimeTraceAppend, RuntimeTracePortError>;
    /// Synchronously fences future appends and releases local ownership.
    fn close(&self) -> Result<(), RuntimeTracePortError>;
}

/// Opaque reader handle returned by a store.
pub type RuntimeTraceReaderHandle = Arc<dyn RuntimeTraceReader>;
/// Opaque writer handle returned by a store.
pub type RuntimeTraceWriterHandle = Arc<dyn RuntimeTraceWriter>;

/// Redacted failures returned by runtime trace capability ports.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeTracePortError {
    /// Backend does not implement the optional runtime capability.
    #[error("runtime_trace_capability_unsupported")]
    Unsupported,
    /// Another live owner or a safe lock-shard collision denied acquisition.
    #[error("runtime_trace_writer_conflict")]
    Conflict,
    /// Historical non-empty unanchored history is inspect-only.
    #[error("runtime_trace_legacy_inspect_only")]
    LegacyInspectOnly,
    /// Stored rows, metadata, identity, or anchor failed integrity checks.
    #[error("runtime_trace_integrity_failure")]
    IntegrityFailure,
    /// A conservative payload/page/history bound was exceeded.
    #[error("runtime_trace_limit_exceeded")]
    LimitExceeded,
    /// Expected sequence, tail, revision, or fence was stale.
    #[error("runtime_trace_fence_rejected")]
    FenceRejected,
    /// Capability was synchronously closed or revoked.
    #[error("runtime_trace_capability_closed")]
    Closed,
    /// Storage was unavailable and no mutation success is claimed.
    #[error("runtime_trace_store_unavailable")]
    Unavailable,
    /// Backend violated the runtime capability contract.
    #[error("runtime_trace_backend_contract_violation")]
    BackendContract,
}

/// Computes the additive full storage-envelope hash without changing the stable
/// 0.1 event hash or serialized payload.
pub fn compute_trace_envelope_hash(
    previous: Option<&ContentHash>,
    record: &TraceRecord,
) -> Result<ContentHash, RuntimeTracePortError> {
    let payload =
        serde_json::to_vec(&record.payload).map_err(|_| RuntimeTracePortError::IntegrityFailure)?;
    let mut bytes = b"splendor.runtime-trace.storage-envelope.v1\0".to_vec();
    push_bytes(&mut bytes, record.run_id.as_bytes());
    bytes.extend_from_slice(&record.sequence.to_be_bytes());
    push_bytes(&mut bytes, &payload);
    push_bytes(
        &mut bytes,
        record
            .recorded_at
            .unix_timestamp_nanos()
            .to_string()
            .as_bytes(),
    );
    push_bytes(&mut bytes, record.event_hash.to_string().as_bytes());
    match &record.prev_event_hash {
        Some(hash) => {
            bytes.push(1);
            push_bytes(&mut bytes, hash.to_string().as_bytes());
        }
        None => bytes.push(0),
    }
    match previous {
        Some(hash) => {
            bytes.push(1);
            push_bytes(&mut bytes, hash.to_string().as_bytes());
        }
        None => bytes.push(0),
    }
    Ok(ContentHash::blake3(bytes))
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}
