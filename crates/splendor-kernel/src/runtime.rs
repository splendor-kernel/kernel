//! # Kernel Runtime
//!
//! `KernelRuntime` is the minimal execution context used to emit ordered trace
//! events. It owns a run identifier, runtime identity context, trace cursor, and
//! a configurable trace sink.
//!
//! ## Example
//! ```rust,no_run
//! use splendor_kernel::{KernelRuntime, KernelRuntimeConfig, TraceEventKind};
//!
//! let runtime = KernelRuntime::new(KernelRuntimeConfig::default());
//! let event = runtime
//!     .record_event(TraceEventKind::LoopTickStarted { tick_id: 1 })
//!     .expect("trace");
//! assert_eq!(event.sequence, 0);
//! ```

use crate::{StdoutTraceSink, TraceError, TraceSink, TraceStoreSink};
use splendor_evidence::{acquire_current_trace_writer, append_stable_trace_event};
use splendor_store::{
    RuntimeTraceLimits, RuntimeTraceTail, RuntimeTraceWriter, RuntimeTraceWriterHandle, TraceStore,
};
use splendor_types::{
    AgentId, ContentHash, RunId, RuntimeIdentityContext, StateHandoff, StateHandoffTraceContext,
    StateReference, TenantId, TraceEvent, TraceEventKind, TraceIdentityContext, TraceIntegrity,
};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

/// Configuration for bootstrapping a kernel runtime.
#[derive(Clone)]
pub struct KernelRuntimeConfig {
    /// Trace sink used to emit serialized trace events.
    pub trace_sink: Arc<dyn TraceSink>,
    /// Optional run identifier to resume an existing run.
    pub run_id: Option<RunId>,
    /// Optional fleet/node/instance/tenant/agent identity fields for emitted traces.
    pub identity: RuntimeIdentityContext,
    /// Initial sequence counter value for trace events.
    pub initial_sequence: u64,
    /// Initial event hash used to seed the integrity chain.
    pub initial_prev_hash: Option<ContentHash>,
}

impl Default for KernelRuntimeConfig {
    /// Builds a default runtime configuration using stdout tracing.
    fn default() -> Self {
        Self {
            trace_sink: Arc::new(StdoutTraceSink),
            run_id: None,
            identity: RuntimeIdentityContext::default(),
            initial_sequence: 0,
            initial_prev_hash: None,
        }
    }
}

/// Minimal runtime context responsible for trace emission.
pub struct KernelRuntime {
    /// Run identifier associated with this runtime instance.
    run_id: RunId,
    /// Base identity context embedded into each trace event.
    identity: TraceIdentityContext,
    /// Monotonic sequence and integrity state for successfully persisted events.
    ///
    /// When runtime locks must be combined, the order is this cursor, then the
    /// writer lifecycle, then the writer-session operation lock.
    trace_cursor: Mutex<TraceCursor>,
    /// Trace sink used to emit serialized events.
    trace_sink: Arc<dyn TraceSink>,
    /// Shared persistence boundary. No history is read during runtime creation.
    trace_store: Option<Arc<dyn TraceStore>>,
    /// One owner-bound writer lifecycle shared by the runtime and engine leases.
    writer_lifecycle: Arc<WriterLifecycle>,
}

struct WriterLifecycle {
    state: Mutex<WriterLifecycleState>,
}

struct WriterLifecycleState {
    session: Option<Arc<RuntimeWriterSession>>,
    engine_identities: HashSet<(TenantId, AgentId)>,
    terminal: bool,
}

struct RuntimeWriterSession {
    writer: RuntimeTraceWriterHandle,
    operation: Mutex<RuntimeWriterSessionState>,
    revoked: AtomicBool,
}

struct RuntimeWriterSessionState {
    tail: Option<RuntimeTraceTail>,
}

pub(crate) struct RuntimeWriterLease {
    lifecycle: Arc<WriterLifecycle>,
    session: Arc<RuntimeWriterSession>,
    identity: Option<(TenantId, AgentId)>,
    primary: bool,
}

impl RuntimeWriterLease {
    pub(crate) fn reader(&self) -> &dyn RuntimeTraceWriter {
        self.session.writer.as_ref()
    }

    pub(crate) fn is_primary(&self) -> bool {
        self.primary
    }
}

impl Drop for RuntimeWriterLease {
    fn drop(&mut self) {
        let Some(identity) = self.identity.take() else {
            return;
        };
        let session_to_revoke = {
            let mut lifecycle = match self.lifecycle.state.lock() {
                Ok(lifecycle) => lifecycle,
                Err(poisoned) => poisoned.into_inner(),
            };
            lifecycle.engine_identities.remove(&identity);
            if lifecycle.engine_identities.is_empty() {
                lifecycle.terminal = true;
                lifecycle.session.clone()
            } else {
                None
            }
        };
        if let Some(session) = session_to_revoke {
            session.revoke();
        }
    }
}

/// Runtime trace cursor updated only after durable trace persistence succeeds.
#[derive(Clone, Debug)]
struct TraceCursor {
    next_sequence: u64,
    prev_event_hash: Option<ContentHash>,
    tick_activity_started: bool,
    fresh_run_claimed: bool,
    fresh_engine_identities: HashSet<(TenantId, AgentId)>,
}

impl KernelRuntime {
    /// Creates a runtime with a new run identifier and trace cursor.
    pub fn new(config: KernelRuntimeConfig) -> Self {
        let run_id = config.run_id.unwrap_or_default();
        let identity = TraceIdentityContext::from_runtime(run_id.clone(), &config.identity);
        let initial_sequence = config.initial_sequence;
        Self {
            run_id,
            identity,
            trace_cursor: Mutex::new(TraceCursor {
                next_sequence: initial_sequence,
                prev_event_hash: config.initial_prev_hash,
                tick_activity_started: false,
                fresh_run_claimed: false,
                fresh_engine_identities: HashSet::new(),
            }),
            trace_sink: config.trace_sink,
            trace_store: None,
            writer_lifecycle: Arc::new(WriterLifecycle {
                state: Mutex::new(WriterLifecycleState {
                    session: None,
                    engine_identities: HashSet::new(),
                    terminal: false,
                }),
            }),
        }
    }

    /// Creates a runtime that persists events to a trace store.
    pub fn with_trace_store(
        store: Arc<dyn TraceStore>,
        run_id: Option<RunId>,
    ) -> Result<Self, TraceError> {
        Self::with_trace_store_and_identity(store, run_id, RuntimeIdentityContext::default())
    }

    /// Creates a trace-store-backed runtime with explicit placement identity.
    pub fn with_trace_store_and_identity(
        store: Arc<dyn TraceStore>,
        run_id: Option<RunId>,
        identity: RuntimeIdentityContext,
    ) -> Result<Self, TraceError> {
        let run_id = run_id.unwrap_or_default();
        let mut runtime = Self::new(KernelRuntimeConfig {
            // Persisted runtimes bypass this compatibility sink and require the
            // owner-bound writer session installed by `LoopEngine`.
            trace_sink: Arc::new(TraceStoreSink::new(run_id.clone(), store.clone())),
            run_id: Some(run_id),
            identity,
            initial_sequence: 0,
            initial_prev_hash: None,
        });
        runtime.trace_store = Some(store);
        Ok(runtime)
    }

    /// Boots the runtime from `KernelRuntimeConfig` and emits `LoopTickStarted`.
    pub fn boot(config: KernelRuntimeConfig) -> Result<Self, TraceError> {
        let runtime = Self::new(config);
        runtime.record_event(TraceEventKind::LoopTickStarted { tick_id: 0 })?;
        Ok(runtime)
    }

    /// Returns the run identifier associated with this runtime.
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Returns the base trace identity associated with this runtime.
    pub fn trace_identity(&self) -> TraceIdentityContext {
        self.identity.clone()
    }

    /// Returns the next trace sequence that will be assigned.
    pub fn next_sequence(&self) -> u64 {
        self.trace_cursor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .next_sequence
    }

    /// Atomically admits one fresh engine per exact tenant/agent identity while
    /// allowing distinct agents to assemble on the shared runtime before its
    /// first tick. A runtime reopened over history or reused after tick activity
    /// begins is denied.
    pub(crate) fn admit_fresh_engine(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
    ) -> Result<bool, TraceError> {
        let mut cursor = self
            .trace_cursor
            .lock()
            .map_err(|_| TraceError::IntegrityLock)?;
        if cursor.tick_activity_started {
            return Ok(false);
        }
        let engine_identity = (tenant_id.clone(), agent_id.clone());
        if cursor.fresh_engine_identities.contains(&engine_identity) {
            return Ok(false);
        }
        if !cursor.fresh_run_claimed {
            if cursor.next_sequence != 0 {
                return Ok(false);
            }

            self.record_event_with_cursor(
                &mut cursor,
                self.trace_identity(),
                TraceEventKind::RunStarted,
            )?;
            cursor.fresh_run_claimed = true;
        }
        cursor.fresh_engine_identities.insert(engine_identity);
        Ok(true)
    }

    pub(crate) fn acquire_engine_writer(
        &self,
        tenant_id: &TenantId,
        agent_id: &AgentId,
    ) -> Result<RuntimeWriterLease, TraceError> {
        let store = self
            .trace_store
            .as_ref()
            .ok_or(splendor_evidence::TraceCompatibilityError::Store)?;
        let identity = (tenant_id.clone(), agent_id.clone());
        // Keep the same cursor -> lifecycle order used by event append. Holding
        // both guards makes the fresh distinct-agent check and lifecycle insert
        // atomic with respect to the first tick append.
        let cursor = self
            .trace_cursor
            .lock()
            .map_err(|_| TraceError::IntegrityLock)?;
        let mut lifecycle = self
            .writer_lifecycle
            .state
            .lock()
            .map_err(|_| TraceError::IntegrityLock)?;
        if lifecycle.terminal || lifecycle.engine_identities.contains(&identity) {
            return Err(splendor_evidence::TraceCompatibilityError::WriterConflict.into());
        }
        if let Some(session) = lifecycle.session.clone() {
            if cursor.tick_activity_started || session.revoked.load(Ordering::Acquire) {
                return Err(splendor_evidence::TraceCompatibilityError::WriterConflict.into());
            }
            lifecycle.engine_identities.insert(identity.clone());
            return Ok(RuntimeWriterLease {
                lifecycle: Arc::clone(&self.writer_lifecycle),
                session,
                identity: Some(identity),
                primary: false,
            });
        }
        let writer = acquire_current_trace_writer(
            store.as_ref(),
            &self.run_id,
            tenant_id,
            agent_id,
            RuntimeTraceLimits::default(),
        )?;
        let session = Arc::new(RuntimeWriterSession {
            writer,
            operation: Mutex::new(RuntimeWriterSessionState { tail: None }),
            revoked: AtomicBool::new(false),
        });
        lifecycle.session = Some(Arc::clone(&session));
        lifecycle.engine_identities.insert(identity.clone());
        Ok(RuntimeWriterLease {
            lifecycle: Arc::clone(&self.writer_lifecycle),
            session,
            identity: Some(identity),
            primary: true,
        })
    }

    pub(crate) fn activate_engine_writer(
        &self,
        lease: &RuntimeWriterLease,
        tail: RuntimeTraceTail,
    ) -> Result<(), TraceError> {
        if tail.store_identity() != &lease.session.writer.store_identity() {
            return Err(splendor_evidence::TraceCompatibilityError::Integrity.into());
        }
        {
            let mut cursor = self
                .trace_cursor
                .lock()
                .map_err(|_| TraceError::IntegrityLock)?;
            cursor.next_sequence = tail.next_sequence();
            cursor.prev_event_hash = tail.stable_tail_hash().cloned();
        }
        lease.session.activate(tail)?;
        Ok(())
    }

    pub(crate) fn store_identity(
        &self,
    ) -> Result<splendor_store::RuntimeTraceStoreIdentity, TraceError> {
        self.trace_store
            .as_ref()
            .ok_or(splendor_evidence::TraceCompatibilityError::Store)?
            .runtime_store_identity()
            .map_err(splendor_evidence::TraceCompatibilityError::from)
            .map_err(TraceError::from)
    }

    /// Records a `TraceEventKind` and returns the emitted `TraceEvent`.
    pub fn record_event(&self, kind: TraceEventKind) -> Result<TraceEvent, TraceError> {
        self.record_event_with_identity(self.trace_identity(), kind)
    }

    /// Records a `TraceEventKind` with explicit identity context.
    ///
    /// The runtime serializes trace cursor state across the durable sink append.
    /// `TraceSink` implementations used here must not synchronously call back into
    /// the same runtime while recording, or they can deadlock on the cursor lock.
    pub fn record_event_with_identity(
        &self,
        identity: TraceIdentityContext,
        kind: TraceEventKind,
    ) -> Result<TraceEvent, TraceError> {
        let mut cursor = self
            .trace_cursor
            .lock()
            .map_err(|_| TraceError::IntegrityLock)?;
        self.record_event_with_cursor(&mut cursor, identity, kind)
    }

    fn record_event_with_cursor(
        &self,
        cursor: &mut TraceCursor,
        identity: TraceIdentityContext,
        kind: TraceEventKind,
    ) -> Result<TraceEvent, TraceError> {
        identity.ensure_run(&self.run_id)?;
        let sequence = cursor.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(TraceError::SequenceOverflow(sequence))?;
        let mut event =
            TraceEvent::try_new_with_identity(identity, sequence, OffsetDateTime::now_utc(), kind)?;
        let event_hash = compute_event_hash(cursor.prev_event_hash.as_ref(), &event)?;
        if let TraceEventKind::LoopTickCompleted { tick_id, .. } = event.kind {
            event.kind = TraceEventKind::LoopTickCompleted {
                tick_id,
                integrity: Some(TraceIntegrity {
                    prev_event_hash: cursor.prev_event_hash.clone(),
                    event_hash: event_hash.clone(),
                }),
            };
        }
        if self.trace_store.is_some() {
            let session = self.active_writer_session()?;
            session.append(&event)?;
        } else {
            self.trace_sink.record(&event)?;
        }
        if matches!(event.kind, TraceEventKind::LoopTickStarted { .. }) {
            cursor.tick_activity_started = true;
        }
        cursor.next_sequence = next_sequence;
        cursor.prev_event_hash = Some(event_hash);
        Ok(event)
    }

    /// Records a source-side state handoff export and stores its trace ID in the handoff.
    pub fn record_state_handoff_exported(
        &self,
        handoff: &mut StateHandoff,
    ) -> Result<TraceEvent, TraceError> {
        self.ensure_handoff_run_scope(&handoff.authority.run_id)?;
        let event = self.record_event_with_identity(
            TraceIdentityContext::new(handoff.authority.run_id.clone()).with_tenant_agent(
                handoff.authority.tenant_id.clone(),
                handoff.authority.agent_id.clone(),
            ),
            TraceEventKind::StateHandoffExported {
                handoff: StateHandoffTraceContext::exported(handoff),
            },
        )?;
        handoff.source_trace_id = Some(event.trace_event_id.clone());
        Ok(event)
    }

    /// Records a receiver-side successful state handoff import.
    pub fn record_state_handoff_imported(
        &self,
        handoff: &StateHandoff,
        receiver_state_node_id: impl Into<String>,
    ) -> Result<TraceEvent, TraceError> {
        self.ensure_handoff_run_scope(&handoff.authority.run_id)?;
        self.record_event_with_identity(
            TraceIdentityContext::new(handoff.authority.run_id.clone()).with_tenant_agent(
                handoff.authority.tenant_id.clone(),
                handoff.authority.agent_id.clone(),
            ),
            TraceEventKind::StateHandoffImported {
                handoff: StateHandoffTraceContext::imported(handoff, receiver_state_node_id),
            },
        )
    }

    /// Records a receiver-side failed state handoff import.
    pub fn record_state_handoff_import_failed(
        &self,
        handoff: &StateHandoff,
        reason: impl Into<String>,
    ) -> Result<TraceEvent, TraceError> {
        self.ensure_handoff_run_scope(&handoff.authority.run_id)?;
        self.record_event_with_identity(
            TraceIdentityContext::new(handoff.authority.run_id.clone()).with_tenant_agent(
                handoff.authority.tenant_id.clone(),
                handoff.authority.agent_id.clone(),
            ),
            TraceEventKind::StateHandoffImportFailed {
                handoff: StateHandoffTraceContext::exported(handoff),
                reason: reason.into(),
            },
        )
    }

    /// Records attachment of a read-only state reference.
    pub fn record_read_only_state_referenced(
        &self,
        reference: &StateReference,
    ) -> Result<TraceEvent, TraceError> {
        self.ensure_handoff_run_scope(&reference.authority.run_id)?;
        self.record_event_with_identity(
            TraceIdentityContext::new(reference.authority.run_id.clone()).with_tenant_agent(
                reference.authority.tenant_id.clone(),
                reference.authority.agent_id.clone(),
            ),
            TraceEventKind::ReadOnlyStateReferenced {
                handoff: StateHandoffTraceContext::referenced(reference),
            },
        )
    }

    fn active_writer_session(&self) -> Result<Arc<RuntimeWriterSession>, TraceError> {
        let lifecycle = self
            .writer_lifecycle
            .state
            .lock()
            .map_err(|_| TraceError::IntegrityLock)?;
        if lifecycle.terminal {
            return Err(splendor_evidence::TraceCompatibilityError::Store.into());
        }
        lifecycle
            .session
            .clone()
            .ok_or(splendor_evidence::TraceCompatibilityError::Store.into())
    }

    fn ensure_handoff_run_scope(&self, handoff_run_id: &RunId) -> Result<(), TraceError> {
        if &self.run_id == handoff_run_id {
            Ok(())
        } else {
            Err(TraceError::HandoffRunMismatch {
                runtime_run_id: self.run_id.clone(),
                handoff_run_id: handoff_run_id.clone(),
            })
        }
    }
}

impl RuntimeWriterSession {
    fn activate(&self, tail: RuntimeTraceTail) -> Result<(), TraceError> {
        let mut operation = self
            .operation
            .lock()
            .map_err(|_| TraceError::IntegrityLock)?;
        if self.revoked.load(Ordering::Acquire) || operation.tail.is_some() {
            return Err(splendor_evidence::TraceCompatibilityError::WriterConflict.into());
        }
        self.writer
            .confirm_tail(&tail)
            .map_err(splendor_evidence::TraceCompatibilityError::from)?;
        operation.tail = Some(tail);
        Ok(())
    }

    fn append(&self, event: &TraceEvent) -> Result<(), TraceError> {
        let mut operation = self
            .operation
            .lock()
            .map_err(|_| TraceError::IntegrityLock)?;
        if self.revoked.load(Ordering::Acquire) {
            return Err(splendor_evidence::TraceCompatibilityError::Store.into());
        }
        let tail = operation
            .tail
            .as_ref()
            .ok_or(splendor_evidence::TraceCompatibilityError::Store)?
            .clone();
        let appended = append_stable_trace_event(self.writer.as_ref(), &tail, event)?;
        operation.tail = Some(appended.into_tail());
        Ok(())
    }

    fn revoke(&self) {
        let mut operation = match self.operation.lock() {
            Ok(operation) => operation,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.revoked.store(true, Ordering::Release);
        operation.tail = None;
        let _ = self.writer.close();
    }
}

fn compute_event_hash(
    prev_hash: Option<&ContentHash>,
    event: &TraceEvent,
) -> Result<ContentHash, TraceError> {
    let mut payload = serde_json::to_value(event)?;
    if let Some(kind) = payload.get_mut("kind") {
        if let Some(loop_tick) = kind.get_mut("LoopTickCompleted") {
            if let Some(object) = loop_tick.as_object_mut() {
                object.remove("integrity");
            }
        }
    }
    let payload = serde_json::to_vec(&payload)?;
    let mut bytes = Vec::new();
    if let Some(prev_hash) = prev_hash {
        bytes.extend_from_slice(prev_hash.to_string().as_bytes());
    }
    bytes.extend_from_slice(&payload);
    Ok(ContentHash::blake3(bytes))
}

#[cfg(test)]
#[path = "../tests/unit/runtime_tests.rs"]
mod tests;
