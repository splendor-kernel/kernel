# Trace Store

Trace stores persist the ordered event stream for each run and provide integrity
hashes for auditability. Implementations live in `crates/splendor-store`.

## TraceRecord

**Fields**
- `run_id` (`String`): run identifier.
- `sequence` (`u64`): monotonic sequence number.
- `payload` (`serde_json::Value`): serialized trace event payload.
- `recorded_at` (`OffsetDateTime`): timestamp at storage time.
- `event_hash` (`ContentHash`): hash derived from the previous hash and payload.
- `prev_event_hash` (`Option<ContentHash>`): previous event hash in the chain.

## Integrity Chain

`event_hash` is computed as:

```
event_hash = blake3(prev_hash_string || payload_bytes)
```

Where `prev_hash_string` is the `ContentHash` string form (`algorithm:value`) of
the previous event. For the first record, `prev_event_hash` is `None` and the
hash is computed from payload bytes alone. For `LoopTickCompleted`, the payload
is normalized with `integrity` removed so the hash does not include itself.
Runtime recovery separately verifies that present completion-integrity values
match the storage-owned previous/event hashes before consuming the completion.
The current anchored runtime profile requires this integrity value; historical
unanchored traces may omit it only for inspect/export/replay compatibility and
cannot resume live.

## TraceStore

Synchronous storage interface:

```
append(run_id, payload) -> sequence
read(run_id) -> Vec<TraceRecord>
read_range(run_id, start, end) -> Vec<TraceRecord>
runtime_store_identity() -> RuntimeTraceStoreIdentity
open_runtime_reader(run_id, limits) -> RuntimeTraceReader
acquire_runtime_writer(request) -> RuntimeTraceWriter
```

`append` treats the entire JSON value as opaque application payload. A top-level
field named `sequence` is never storage metadata, regardless of whether its value
is numeric, textual, nested, null, or malformed-looking. Ordering lives only in
`TraceRecord.sequence`, so existing generic payloads round-trip unchanged.

The three runtime methods are additive default-deny compatibility methods.
Existing custom `TraceStore` implementations continue to compile and return the
fixed `RuntimeTracePortError::Unsupported` until they implement the capability.
The legacy exhaustive `TraceStoreError` enum is unchanged.

`RuntimeTraceReader` exposes only a bounded page read, a mechanically confirmed
tail, and tail reconfirmation. `RuntimeTraceWriter` adds atomic fenced append and
synchronous `close`. Every append supplies the exact previously confirmed tail;
a stale sequence, hash, anchor revision, or fence fails closed. Closing or
dropping the writer revokes future appends, and append/close are linearized.

`splendor-evidence` owns the stable event-profile semantics above this mechanical
port. It validates exact run identity, contiguous storage sequence, previous-hash
links, stable event hashes, full storage-envelope hashes, event envelopes, tick
lifecycle, current completion integrity, and conservative record/page/payload/
byte limits before state restore, replay, audit, or export. Store implementations
do not interpret policy, tick, state, replay, or evidence meaning.

## AsyncTraceStore

Async wrapper with the same semantics, returning futures for each operation.

## InMemoryTraceStore

Holds trace records in memory keyed by `run_id`. Runtime writer acquisition,
anchored tail comparison, append, and close are serialized under store-owned
mutexes. An anchored run rejects the legacy `append` path.

## SqliteTraceStore

SQLite-backed store that persists trace records on disk. The schema includes:

- `trace_events`: `run_id`, `sequence`, `payload`, `recorded_at`, `event_hash_*`,
  and `prev_hash_*` columns.
- `trace_store_metadata`: a stable random store ID.
- `trace_run_anchor_registry`: immutable run/profile ownership.
- `trace_run_anchors`: next/high-water sequence, stable and full-envelope tail
  hashes, monotonic anchor revision, and active fence digest.
- `trace_append_permits`: transaction-local authorization used by trigger-guarded
  anchored inserts.

Runtime append inserts the opaque event and compare-and-swaps the anchor in one
bounded `IMMEDIATE` transaction. Trigger guards deny direct legacy insert,
update, or delete against anchored history. Existing `trace_events` rows and
stable event bytes/hashes are not rewritten.

Writable SQLite stores bind ownership to the verified opened database identity
plus persisted store ID and run partition, not a pathname. The default private
`.splendor-runtime-locks` directory is owner-only (`0700`) and contains at most
256 owner-only (`0600`) no-follow shard files. A nonblocking OS lock plus a
same-process shard guard safely denies aliases and shard collisions; process
death releases the OS lock. Writable databases must be owner-only regular
single-link files and are revalidated before append, so hard links, symlinks,
renames, and replacements fail closed. Lock paths and public runtime errors do
not expose run, tenant, agent, database identity, fence, or hash material.

Schema initialization is additive, idempotent, and transactional. Empty legacy
databases may initialize the current profile. Non-empty unanchored history is
never auto-anchored: it remains byte-stable and inspect/export/replay-only.
Read-only SQLite stores can inspect bounded history but cannot acquire a writer.
This local capability is not a transferable or distributed writer lease.

## Trace Export Tool

Use `splendorctl trace export --db <path> --run <id>` to emit JSON Lines for a
run. The CLI validates the complete bounded history, applies the redacted
projection, and securely spools all records before writing stdout. A late
integrity, serialization, or output failure returns nonzero without emitting a
partial record set. State-head, audit, and replay consumers use the same semantic
validator; replay remains inspect-only and does not execute adapters.

## Failure and compatibility behavior

- Runtime capability errors are fixed, non-reflecting codes and are
  `#[non_exhaustive]` for compatible extension.
- Unsupported custom stores, stale fences, unavailable verification, limit
  overflow, and uncertain ownership deny rather than fall back to legacy append.
- Stable `TraceEvent` serialization and event hashes remain unchanged; the
  full-envelope hash is additive anchor metadata.
- Current-profile corruption or missing completion integrity blocks state load,
  policy, Gateway, and adapter work.

## Example

```rust
use splendor_store::{InMemoryTraceStore, TraceStore};

let store = InMemoryTraceStore::default();
let seq = TraceStore::append(&store, "run-1", serde_json::json!({"event": 1}))
    .expect("append");
assert_eq!(seq, 0);
let records = TraceStore::read(&store, "run-1").expect("read");
assert_eq!(records.len(), 1);
```
