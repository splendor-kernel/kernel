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

Tail confirmation is also linearized. The in-memory backend retains the run
anchor and then the records lock, in writer order, through prefix and full-chain
validation. SQLite performs the actual-tail read, expected-prefix validation,
and full current-chain validation in one read transaction/snapshot. An equal
tail succeeds. A bounded, integrity-valid monotonic extension under the same
store, profile, fence, and anchor-revision rules returns `FenceRejected` so the
semantic owner can retry from a fresh tail. Truncation, a rewritten prefix, a
corrupt extension, or incompatible anchor/fence metadata returns
`IntegrityFailure`; movement is never classified before both the captured prefix
and current full chain validate.

`splendor-evidence` owns the stable event-profile semantics above this mechanical
port. It validates exact run identity, contiguous storage sequence, previous-hash
links, stable event hashes, full storage-envelope hashes, event envelopes, tick
lifecycle, current completion integrity, and conservative record/page/payload/
byte limits before state restore, replay, audit, or export. Store implementations
do not interpret policy, tick, state, replay, or evidence meaning.

For every completed target tick, including a no-action tick, the current Evidence
profile requires exactly one matching strict `OutcomeRecorded`, exactly one later
`StateCommitted`, and exactly one later integrity-bearing `LoopTickCompleted`, in
that order. A strictly greater `LoopTickStarted` may supersede an earlier active
tick only when the earlier tick has no action order/`ActionVerificationStarted`,
outcome, state commit, pending episode, or effect evidence. The owner removes that
safe pre-action attempt from the active map while retaining its tick identity in
the monotonic ordering floor. An open tail remains incomplete until a later tick
safely supersedes it; action-bearing, stateful, outcome-bearing, unknown
action-scoped, duplicate, orphaned, or misordered lifecycle records return
reconciliation-required before action-history disposition or snapshot restore.

`inspect_durable_action_history` is the same owner's bounded action-identity
query. After complete trace validation it checks exact verification/terminal/
`OutcomeRecorded` grammar, strict stored action outcome ID and status, effect
certainty, same-action continuation, completed tick suffixes, and immutable
`Tick`, `Direct`, or `Physical` origin. A valid concurrent append beyond the
captured tail returns the distinct, non-reflecting `TailMoved` result only after
the complete captured prefix has passed chain, envelope, and tail-hash
validation. Stable corruption remains an integrity/reconciliation failure. Its only semantic dispositions are
`Fresh`, `Complete`, `PendingApproval`, and `ReconciliationRequired`; complete and
pending results carry the original source. Unknown source/status, malformed or
legacy-ambiguous outcome, changed action body, illegal repeat, reordered or
incomplete episode, and uncertain effect all reconcile. The Store and daemon do
not independently reinterpret that history.

A direct- or physical-origin action ID has at most two complete episodes: the
initial episode and, only after `NeedsApproval`, one same-endpoint continuation.
The continuation must end as `Denied`, `Executed`, `Failed`, or
`NeedsIntervention`; another challenge or later direct/physical episode is
invalid. Tick-origin IDs may have multiple episodes only on strictly increasing,
fully completed, non-overlapping tick scopes with the exact same action body. A
tick `NeedsApproval` episode opens one direct continuation; no later tick may use
the ID until that continuation closes, after which a strictly later completed
tick may reuse it. A denied continuation never remains `PendingApproval`. The
same validator is used by action lookup and runtime resume, including latest-
snapshot selection after repeated tick use.

For an external redacted projection, the Evidence owner first validates and
reconfirms the complete source history. It serializes the validated typed
`TraceEvent`, rather than reusing the raw stored JSON, before redaction. Unknown
raw fields therefore do not enter the external view. It then replaces each
sensitive field's entire value subtree with one marker and replaces sensitive
attacker-controlled map keys with a fixed key marker. Run/event identity,
sequence, timestamps, and non-sensitive causal shape remain represented.

Hash-shaped suppression never collects or compares against the validated source
chain. After typed serialization, every contiguous ASCII-hex run of at least 64
characters in every string value and every object key is replaced by the fixed
`[REDACTED:hash-candidate]` token while surrounding non-hash text is retained.
The treatment is path- and membership-independent, including percept provenance,
remote instance/idempotency fields, state/handoff coordinates, action payloads,
and future typed event fields. A digest in an omitted source record therefore
cannot be probed through payload rendering or projection hashes.

Complete typed `Action` values are handled structurally in every singular
action-bearing event and in every `CandidatesProposed.actions` array. Action name,
recursive parameter values and arbitrary parameter keys,
`SideEffectClass::Custom` payload, `cost_estimate.units`, permissions,
preconditions, and postconditions all receive that membership-independent
treatment. Fixed Action field names, the side-effect enum shape, and numeric cost
amount remain represented. Structural typed hashes, including state hashes,
state-node identities, snapshot identities, and digest-like correlation fields,
are tokenized in redacted views even when they are not source-chain members.
Their surrounding typed shape is retained where the stable serializer permits,
but the token is not an integrity fact or dereferenceable identity.
Projection-local chain hashes are added only after this total payload
tokenization.

At the exact typed `/kind/DaemonAudit/audit/credential_id` path, a present value
becomes the fixed `[REDACTED:credential-correlation]` marker; the source digest is
never retained. A `credential_id` key or value at any caller-controlled or
nested path is replaced by fixed key/value markers.

Source `event_hash`, `prev_event_hash`, and completion-integrity hashes are not
released in that projection because they would be an offline oracle over the
original payload. The projected records instead use a deterministic local chain:

```text
projected_hash = blake3(
  "splendor.trace.redacted-projection.v1\0" ||
  projected_prev_hash_string_if_present ||
  deterministic_json(projected_payload_without_completion_integrity)
)
```

`LoopTickCompleted.integrity` is rewritten to the same projected previous/current
hashes. This chain verifies the returned projection only; it is not a source-trace
attestation. Trusted inspection retains the validated source chain unchanged.

`project_trace` derives that chain over the complete returned projection.
`project_trace_range` still validates and tail-reconfirms complete source history,
then selects the half-open `[start, end)` range before redaction and chain
derivation. The first returned redacted range record therefore has no previous
projection hash. Consumers must not project complete history and slice it later;
that would leave a link to an omitted projected record. Payload candidate
suppression is the same total transform for full and range views and never
consults a complete-history source set.

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

File-backed writable and read-only SQLite stores retain an opened owner-only
(`0600`) regular, single-link database descriptor and its `(device, inode)`
identity. SQLite `file:` URI inputs are rejected; the exact `:memory:` spelling
remains the explicit in-memory mode. The trusted parent spelling is canonicalized
so platforms with symlinked system ancestors remain usable, while both the
descriptor open and SQLite's final database-name open use no-follow semantics.

The retained descriptor identity, current no-follow pathname identity, and
SQLite's actual `main` handle must continue to identify the same file. The store
checks that relationship immediately after open, before and after schema and
store-ID initialization, and before and after fallible database-backed legacy
and runtime operations. SQLite file-control uncertainty or detected movement
fails closed; a failed post-operation check overrides an otherwise successful
result. The runtime store identity combines the verified file identity with the
persisted store ID rather than trusting a pathname string.

Writable stores additionally use the default private
`.splendor-runtime-locks` directory, which is owner-only (`0700`) and contains
at most 256 owner-only (`0600`) no-follow shard files. A nonblocking OS lock plus
a same-process shard guard safely denies aliases and shard collisions; process
death releases the OS lock. Read-only stores retain the same main-file identity
checks but cannot acquire a writer. Lock paths and public runtime errors do not
expose run, tenant, agent, database identity, fence, or hash material.

These checks cover SQLite's `main` database handle at the checked boundaries;
they do not install a custom VFS or claim journal/WAL descriptor binding. The
database parent namespace remains a trusted local boundary, not protection from
an adaptive same-UID process, root, mount-namespace replacement, or adversarial
filesystem implementation.

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
