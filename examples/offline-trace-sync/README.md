# Offline Trace Sync Example

This example documents the 0.05-S3 local trace buffer path for disconnected
physical/edge nodes.

## What this proves

- Offline nodes continue writing normal `TraceRecord` entries locally.
- Offline intervals and reconnect sync boundaries are replay-visible.
- Reconnect sync preserves local sequence ordering and hash-chain integrity.
- Duplicate sync does not create duplicate central records.
- Corrupted segments are rejected/quarantined.
- Buffer pressure fails closed for side-effectful action trace durability.

## Smoke commands

```bash
cargo test -p splendor-store trace_sync
cargo test -p splendor-kernel trace_durability
```

## Minimal Rust shape

```rust,no_run
use splendor_store::{
    CentralTraceIndex, InMemoryCentralTraceIndex, InMemoryTraceStore,
    LocalTraceBuffer, LocalTraceBufferConfig, TraceBufferAppendMode, TraceSyncScope,
};

let run_id = "00000000-0000-0000-0000-000000000001";
let scope = TraceSyncScope {
    node_id: Some("edge-node-1".to_string()),
    instance_id: Some("device-runtime-1".to_string()),
    run_id: run_id.to_string(),
    ..TraceSyncScope::default()
};

let buffer = LocalTraceBuffer::new(
    InMemoryTraceStore::default(),
    LocalTraceBufferConfig { max_records_per_run: Some(10_000) },
);

let _started = buffer.begin_offline_interval(&scope, Some("network_disconnected".to_string()))?;
// Append canonical TraceEvent values via buffer.append_event(...).
let ended = buffer.end_offline_interval(run_id)?;
let _boundary = buffer.record_sync_started(run_id, 0, 3, Some(ended.offline_interval_id.clone()))?;

let central = InMemoryCentralTraceIndex::default();
let batch = buffer.reconnect_batch(scope, 0, 3, Some(ended))?;
central.sync_batch(batch)?;
```

## Non-goals

- No network transport.
- No dashboard or observability stack.
- No physical safety implementation.
