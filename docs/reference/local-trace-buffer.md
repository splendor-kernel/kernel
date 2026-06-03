# Local Trace Buffer Reference

The local trace buffer is the 0.05-S3 physical/edge boundary for preserving
append-only trace continuity while a node is disconnected. It reuses
`TraceRecord`, `TraceStore`, `TraceSyncBatch`, and `CentralTraceIndex`; devices do
not get a separate log format or collector.

## Public contracts

Implemented in `crates/splendor-store`:

- `LocalTraceBuffer<S: TraceStore>`
- `LocalTraceBufferConfig { max_records_per_run }`
- `TraceBufferAppendMode::{ReadOnly, SideEffectful}`
- `LocalTraceBufferError::{BufferFull, NoActiveOfflineInterval, Poisoned, Store}`
- `TraceSyncBatch.offline_interval`
- `TraceSyncBatch.sync_boundary`
- `CentralTraceIndex::offline_intervals(run_id)`
- `CentralTraceIndex::sync_boundaries(run_id)`

Implemented in `crates/splendor-types`:

- `TraceEventKind::OfflineTraceIntervalStarted`
- `TraceEventKind::OfflineTraceIntervalEnded`
- `TraceEventKind::TraceSyncStarted`
- `TraceEventKind::TraceSyncCompleted`
- `TraceEventKind::TraceSyncFailed`
- `OfflineTraceIntervalTraceContext`
- `TraceSyncBoundaryTraceContext`

## Offline interval lifecycle

1. When a physical/edge node loses connectivity, call
   `LocalTraceBuffer::begin_offline_interval(scope, reason)`.
2. Continue appending normal tick/action/denial/safety/operator/policy trace
   payloads through the same local `TraceStore`.
3. Before reconnect sync, call `end_offline_interval(run_id)`.
4. Build a `reconnect_batch(scope, start, end, interval)` and sync it to the
   central index.

The interval and sync boundary are replay-visible metadata. Sync never renumbers,
repairs, or mutates original trace records.

## Storage pressure and fail-closed behavior

`LocalTraceBufferConfig.max_records_per_run` sets the buffer capacity. When full,
appends return `LocalTraceBufferError::BufferFull`; records are not dropped.

Side-effectful action boundaries should use `TraceBufferAppendMode::SideEffectful`.
If this append cannot be durably recorded, adapter execution must fail closed via
the gateway/durability path. `TraceDurabilityState.last_local_buffer_error` makes
this state visible to `TraceDurabilityGateway`.

## Replay behavior

Replay can identify:

- the offline execution interval (`OfflineTraceIntervalStarted/Ended` and central
  `offline_intervals` metadata);
- the reconnect sync boundary (`sync_boundaries` metadata);
- duplicate sync handling (`duplicate_records`);
- corrupted or conflicting segments via central quarantine.

Replay remains inspect-only by default and never re-executes actions.

## Non-goals

- No embedded database framework.
- No device log collector.
- No observability dashboard.
- No remote transport implementation.
