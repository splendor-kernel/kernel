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

## TraceStore

Synchronous storage interface:

```
append(run_id, payload) -> sequence
append_if_sequence(run_id, expected_sequence, payload) -> sequence
read(run_id) -> Vec<TraceRecord>
read_range(run_id, start, end) -> Vec<TraceRecord>
claim_runtime_identity(run_id, tenant_id, agent_id) -> RuntimeIdentityClaim
release_runtime_identity(claim) -> ()
```

`append` treats the entire JSON value as opaque application payload. A top-level
field named `sequence` is never storage metadata, regardless of whether its value
is numeric, textual, nested, null, or malformed-looking. Ordering lives only in
`TraceRecord.sequence`, so existing generic payloads round-trip unchanged.

Runtime emitters use `append_if_sequence`. Both built-in stores compare the
explicit expected value with the next storage-owned position while holding the
same append lock/transaction. A stale writer receives
`TraceStoreError::SequenceMismatch` and appends nothing; it cannot silently
acquire a later sequence. Custom stores that do not implement atomic conditional
append fail closed with `ConditionalAppendUnsupported`. Exhausting SQLite's
bounded writer-lock wait returns `ConditionalAppendContended`, never an
unclassified raw busy/locked error.

`validate_trace_chain(run_id, records)` is the canonical full-chain validator
used before runtime recovery and by replay/export validation. It checks exact
record run identity, a contiguous sequence beginning at zero, every previous-hash
link, and every recomputed event hash before a consumer interprets payloads.

Persisted loop construction also obtains an opaque exact
`run_id + tenant_id + agent_id` live-owner claim. Duplicate fresh or resumed
owners fail closed before emitting a competing runtime event. Custom stores that
cannot coordinate ownership return `RuntimeIdentityOwnershipUnsupported`.

## AsyncTraceStore

Async wrapper with the same semantics, returning futures for each operation.

## InMemoryTraceStore

Holds trace records in memory keyed by `run_id`. The store assigns sequence from
vector length; conditional append and process-local exact-identity claims are
serialized under their owning mutexes.

## SqliteTraceStore

SQLite-backed store that persists trace records on disk. The schema includes:

- `trace_events`: `run_id`, `sequence`, `payload`, `recorded_at`, `event_hash_*`,
  and `prev_hash_*` columns.

SQLite selects the next sequence, compares an explicit conditional expectation
when supplied, inserts the opaque payload, and commits under one `IMMEDIATE`
transaction. Connections use a bounded busy policy, and the
`(run_id, sequence)` primary key remains the durable final conflict guard across
store instances. Concurrent conditional writers therefore produce one append
and one typed sequence conflict rather than leaking normal race contention as a
`database is locked` result.

Writable SQLite stores derive a hashed, identity-specific lock database adjacent
to the trace database. A short bounded `BEGIN IMMEDIATE` acquires the claim and
the connection remains open only for the live engine lifetime; process death or
claim release drops the lock automatically. These sidecar files contain no trace
payload or raw identity and do not change the `trace_events` schema. They are not
durable lease or fleet-writer records, and this local mechanism makes no
transferable-writer or distributed-fencing claim.

Read-only SQLite stores cannot acquire runtime ownership or append conditionally.

## Trace Export Tool

Use `splendorctl trace export --db <path> --run <id>` to emit JSON Lines for a
run. Each line is a serialized `TraceRecord`.

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
