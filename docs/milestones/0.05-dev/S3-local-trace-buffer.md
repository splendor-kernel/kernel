# 0.05-S3 — Local Trace Buffer

## Objective

Preserve trace continuity for disconnected physical/edge nodes and sync safely
after reconnect.

## Functional scope

- Adds a thin `LocalTraceBuffer` boundary around existing `TraceStore`.
- Adds replay-visible offline interval and sync boundary metadata.
- Adds central index queries for offline intervals and sync boundaries.
- Adds storage-pressure fail-closed signal for side-effectful actions.

## Non-goals

- No fleet transport, observability stack, device log collector, or embedded DB framework.
- No physical safety verifier implementation; this leaves trace hooks for #32/#34.
- No offline policy cache implementation; this leaves policy-status trace hooks for #29.

## Public contracts changed

- `crates/splendor-store/src/trace_sync.rs`: `LocalTraceBuffer`, config/error,
  batch offline metadata, central metadata queries.
- `crates/splendor-types/src/trace.rs`: offline interval and sync boundary trace
  event kinds/context structs.
- `crates/splendor-kernel/src/trace_durability.rs`: local buffer error included
  in durability denial decisions.

## Runtime primitives touched

| Primitive | Impact |
| --- | --- |
| Trace store | local buffer and central metadata added |
| Replay | offline interval/sync boundary visible |
| Physical/edge | disconnected-node trace continuity hardened |
| Fleet identity | scope metadata reused; no identity overloading |

## Trace behavior

- Added `OfflineTraceIntervalStarted`, `OfflineTraceIntervalEnded`,
  `TraceSyncStarted`, `TraceSyncCompleted`, and `TraceSyncFailed` taxonomy.
- Local records remain ordered by `TraceRecord.sequence` and hash chain.
- Corruption and central conflicts quarantine/reject instead of repairing.

## State behavior

No state graph format changes. Offline trace sync references trace records only.

## Gateway and verifier behavior

When local trace buffer pressure prevents preserving durability for a
side-effectful action, `TraceDurabilityGateway` denies before adapter execution.

## Replay behavior

Replay can inspect the offline interval, reconnect boundary, duplicate sync
counts, and quarantined corruption without re-executing side effects.

## Failure behavior

- Duplicate sync is idempotent.
- Missing segments are rejected clearly.
- Hash/chain/payload conflicts are quarantined.
- Buffer-full appends do not drop records and must fail closed for side effects.

## Tests and evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| `cargo test -p splendor-store trace_sync` | offline, reconnect, duplicate, corruption, buffer pressure | passes |
| `cargo test -p splendor-kernel trace_durability` | side-effect denial when local buffer durability fails | passes |

## Example or fixture

See `examples/offline-trace-sync/README.md`.

## Future extension notes

#29 can emit policy status into the same buffer. #32/#34 can emit safety and
operator-intervention events without special mocks because sync uses the existing
`TraceRecord` payload contract.
