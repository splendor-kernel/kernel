//! External compile fixture for legacy and capability-aware trace stores.

use splendor_store::{
    InMemoryTraceStore, RuntimeTraceAppend, RuntimeTraceLimits, RuntimeTracePage,
    RuntimeTracePortError, RuntimeTraceReader, RuntimeTraceReaderHandle, RuntimeTraceStoreIdentity,
    RuntimeTraceTail, RuntimeTraceWriter, RuntimeTraceWriterHandle, RuntimeTraceWriterRequest,
    TraceRecord, TraceStore, TraceStoreError,
};
use std::sync::Arc;

/// Legacy implementation proving the stable required `TraceStore` surface still compiles.
#[derive(Default)]
pub struct LegacyCustomStore {
    inner: InMemoryTraceStore,
}

impl TraceStore for LegacyCustomStore {
    fn append(&self, run_id: &str, payload: serde_json::Value) -> Result<u64, TraceStoreError> {
        TraceStore::append(&self.inner, run_id, payload)
    }

    fn read(&self, run_id: &str) -> Result<Vec<TraceRecord>, TraceStoreError> {
        TraceStore::read(&self.inner, run_id)
    }

    fn read_range(
        &self,
        run_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<TraceRecord>, TraceStoreError> {
        TraceStore::read_range(&self.inner, run_id, start, end)
    }
}

/// Exhaustive legacy matching remains source-compatible because capability errors
/// use the separate non-exhaustive `RuntimeTracePortError` contract.
pub fn classify_legacy_error(error: TraceStoreError) -> &'static str {
    match error {
        TraceStoreError::Poisoned => "poisoned",
        TraceStoreError::RunNotFound => "run_not_found",
        TraceStoreError::InvalidHashAlgorithm(_) => "invalid_hash_algorithm",
        TraceStoreError::InvalidHashParts { .. } => "invalid_hash_parts",
        TraceStoreError::Serialization(_) => "serialization",
        TraceStoreError::InvalidTimestamp(_) => "invalid_timestamp",
        TraceStoreError::InvalidSequence(_) => "invalid_sequence",
        TraceStoreError::SequenceOverflow(_) => "sequence_overflow",
        TraceStoreError::SequenceMismatch { .. } => "sequence_mismatch",
        TraceStoreError::Sqlite(_) => "sqlite",
    }
}

/// External implementation opting into the additive runtime capabilities.
#[derive(Default)]
pub struct CapabilityAwareCustomStore {
    inner: InMemoryTraceStore,
}

impl TraceStore for CapabilityAwareCustomStore {
    fn append(&self, run_id: &str, payload: serde_json::Value) -> Result<u64, TraceStoreError> {
        TraceStore::append(&self.inner, run_id, payload)
    }

    fn read(&self, run_id: &str) -> Result<Vec<TraceRecord>, TraceStoreError> {
        TraceStore::read(&self.inner, run_id)
    }

    fn read_range(
        &self,
        run_id: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<TraceRecord>, TraceStoreError> {
        TraceStore::read_range(&self.inner, run_id, start, end)
    }

    fn runtime_store_identity(
        &self,
    ) -> Result<RuntimeTraceStoreIdentity, RuntimeTracePortError> {
        self.inner.runtime_store_identity()
    }

    fn open_runtime_reader(
        &self,
        run_id: &str,
        limits: RuntimeTraceLimits,
    ) -> Result<RuntimeTraceReaderHandle, RuntimeTracePortError> {
        Ok(Arc::new(ExternalReader {
            inner: self.inner.open_runtime_reader(run_id, limits)?,
        }))
    }

    fn acquire_runtime_writer(
        &self,
        request: RuntimeTraceWriterRequest,
    ) -> Result<RuntimeTraceWriterHandle, RuntimeTracePortError> {
        Ok(Arc::new(ExternalWriter {
            inner: self.inner.acquire_runtime_writer(request)?,
        }))
    }
}

struct ExternalReader {
    inner: RuntimeTraceReaderHandle,
}

impl RuntimeTraceReader for ExternalReader {
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

struct ExternalWriter {
    inner: RuntimeTraceWriterHandle,
}

impl RuntimeTraceReader for ExternalWriter {
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

impl RuntimeTraceWriter for ExternalWriter {
    fn append(
        &self,
        expected: &RuntimeTraceTail,
        payload: serde_json::Value,
    ) -> Result<RuntimeTraceAppend, RuntimeTracePortError> {
        self.inner.append(expected, payload)
    }

    fn close(&self) -> Result<(), RuntimeTracePortError> {
        self.inner.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use splendor_store::{RuntimeTraceScope, RuntimeTraceWriterRequest};

    #[test]
    fn legacy_defaults_deny_and_external_capability_wrapper_operates() {
        let legacy = LegacyCustomStore::default();
        assert!(matches!(
            legacy.open_runtime_reader("run", RuntimeTraceLimits::default()),
            Err(RuntimeTracePortError::Unsupported)
        ));

        let store = CapabilityAwareCustomStore::default();
        let writer = store
            .acquire_runtime_writer(RuntimeTraceWriterRequest::current(
                RuntimeTraceScope::new("run", "tenant", "agent"),
                RuntimeTraceLimits::default(),
            ))
            .expect("external writer");
        assert!(matches!(
            store.acquire_runtime_writer(RuntimeTraceWriterRequest::current(
                RuntimeTraceScope::new("run", "tenant", "agent"),
                RuntimeTraceLimits::default(),
            )),
            Err(RuntimeTracePortError::Conflict)
        ));
        let tail = writer.tail().expect("initial tail");
        let appended = writer
            .append(&tail, serde_json::json!({"external": true}))
            .expect("external append");
        assert_eq!(appended.sequence(), 0);
        assert!(matches!(
            writer.append(&tail, serde_json::json!({"stale": true})),
            Err(RuntimeTracePortError::FenceRejected)
        ));
        writer.close().expect("external close");
        assert!(matches!(
            writer.append(
                appended.tail(),
                serde_json::json!({"after_close": true})
            ),
            Err(RuntimeTracePortError::Closed)
        ));

        let dropped = store
            .acquire_runtime_writer(RuntimeTraceWriterRequest::current(
                RuntimeTraceScope::new("run", "tenant", "agent"),
                RuntimeTraceLimits::default(),
            ))
            .expect("writer after explicit close");
        drop(dropped);
        let reclaimed = store
            .acquire_runtime_writer(RuntimeTraceWriterRequest::current(
                RuntimeTraceScope::new("run", "tenant", "agent"),
                RuntimeTraceLimits::default(),
            ))
            .expect("writer after opaque drop");
        reclaimed.close().expect("close reclaimed writer");
    }
}
