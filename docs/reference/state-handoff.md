# State Handoff

State handoff v0 is the explicit state-transfer primitive for 0.03-S7. It moves
state through validated snapshots or attaches read-only references. It is **not**
shared mutable memory, a migration engine, a CRDT, or a conflict-resolution
system.

## Purpose

State handoff lets a receiving runtime resume or inspect state without implicitly
sharing a mutable state head. The current receiver behavior is deliberately split:

- explicit loopback `local_dev` may import a snapshot after validating authority,
  hash, parent linkage, previous head, and source trace linkage; or
- attaches a read-only reference that cannot become a mutable parent.

Resident/non-dev import is unavailable. The v0 handoff envelope is self-consistent
but has no accepted source signature or evidence proof, so a resident cannot prove
that the named source actually issued it or that `source_trace_id` exists in an
authenticated source trace. Resident import therefore fails closed before any
state-store, state-head, or run-trace mutation.

## Schemas

Rust schemas live in `splendor-types::state_handoff` and are re-exported from
`splendor-types` and `splendor-kernel`.

### `StateHandoff`

Important fields:

- `schema_version`: currently `splendor.state_handoff.v0`.
- `handoff_id`: trace-linking identifier for source and receiver events.
- `mode`: `snapshot_import` for ownership transfer.
- `authority`: tenant, agent, run, and work-order binding.
- `previous_state_node_id`: receiver head expected before import.
- `snapshot`: exported snapshot bytes, hash, snapshot ID, source node ID, and
  parent node IDs.
- `source_trace_id`: source-declared trace linkage. In v0 it is not a
  cryptographic proof that the source event exists.

In resident mode, export derives `source_instance_id` from the source runtime.
The export caller supplies `receiver_instance_id` and the receiver's expected
`previous_state_node_id`; these are useful read-only handoff metadata but do not
authorize resident import.

### `StateReference`

`StateReference` uses `mode = read_only_reference`. Attaching it records the
source node and authority binding but does not update the receiver state head.
`StateGraph::commit_from_read_only_reference` always fails closed.

### `StateHandoffTraceContext`

Trace context carries `handoff_id`, mode, tenant/agent/run IDs, work-order ID,
source and receiver instance IDs, source state node, previous receiver head,
receiver state node after import, snapshot ID, and source trace ID.

## Lifecycle

1. Source commits state through its loop engine and state graph.
2. Source asks its scheduler/loop owner to snapshot the current head and export
   `splendor.state_handoff.v0`.
3. The same owner records `state.handoff.exported` through
   `KernelRuntime::record_state_handoff_exported`, which writes the source trace
   ID back into the handoff envelope.
4. A resident receiver authenticates the caller, checks
   `splendor.state.handoff`, and cryptographically validates the exact signed,
   unexpired, unrevoked work order admitted for the target run.
5. Because v0 has no accepted source-authenticated manifest/evidence proof, the
   resident returns `503 state_handoff_proof_unavailable` with
   `disposition = needs_intervention` before handoff validation or mutation.
6. Only explicit loopback `local_dev` compatibility proceeds to validate the
   handoff authority, receiver, previous head, trace linkage, snapshot ID/hash,
   and parent linkage, then imports through the scheduler/loop/state-graph owner.
7. On that local-dev path, the owner records `state.handoff.imported` before the
   daemon publishes the imported head. Local validation and rollback hardening
   remain in place.

## Trace events

Canonical event classes:

| Rust variant | Canonical event class | Purpose |
| --- | --- | --- |
| `StateHandoffExported` | `state.handoff.exported` | Source exported a snapshot handoff. |
| `StateHandoffImported` | `state.handoff.imported` | Receiver imported a validated snapshot. |
| `StateHandoffImportFailed` | `state.handoff.import_failed` | Receiver failed closed before changing head. |
| `ReadOnlyStateReferenced` | `state.reference.read_only` | Receiver attached a read-only reference. |

Import-failure trace reasons use bounded reason codes; signed revocation text,
snapshot bytes, and raw work-order validation details are not copied into trace.
Resident proof-unavailable denial intentionally emits no run-trace mutation; it
occurs before the run state owner is invoked. Transport authentication may still
produce its separate bounded resident security audit attribution.

## Failure modes

Imports fail closed when:

- resident/non-dev mode has no accepted signed source manifest/evidence proof
  (`503 state_handoff_proof_unavailable`, `needs_intervention`);
- `schema_version` is not `splendor.state_handoff.v0`;
- work-order signature metadata is missing;
- work order is expired or revoked;
- tenant, agent, run, work-order ID, or required scope is incompatible;
- the import work order differs from the exact work order admitted for the
  target run;
- the handoff receiver instance does not match the resident runtime;
- source trace ID is missing;
- receiver current head does not match `previous_state_node_id`;
- the receiver already owns the handed-off state node;
- snapshot ID does not match exported bytes;
- state hash does not match exported bytes;
- source node ID does not match parent IDs plus state hash;
- the state store cannot persist the imported node or snapshot.

A failed import leaves the receiver state head unchanged. Resident proof denial
also leaves the state store and run trace unchanged.

## Security notes

`StateGraph::import_handoff` cryptographically validates the supplied
`WorkOrderEnvelope` against the receiver keyring and exact tenant/agent/run/
work-order binding. `StateGraph::attach_read_only_reference` applies the same
work-order identity validation. The daemon additionally requires an authenticated
caller with `splendor.state.handoff`, audit attribution, and a run-bound work
order. These checks are necessary but insufficient for resident import. Caller
credentials, target work-order authority, a hash-valid payload, and a
source-declared trace ID do not authenticate the source. Accepted signed handoff
manifest, source event/evidence verification, and durable replay protection remain
future STA-005, EVT-005, and EVID-005 work.

## Replay behavior

Replay is inspect-only. `splendorctl replay` recognizes handoff trace events and
emits a `handoff_boundary` JSON line with the previous receiver state head and
receiver imported head, when present. Replay does not import state, re-run
policies, call gateways, or execute adapters.

## Compatibility notes

This is a 0.03-dev v0 handoff schema. The wire request remains available for
compatibility, but successful import is experimental and restricted to explicit
loopback `local_dev`. Resident callers receive the stable proof-unavailable
response even when caller scope and the exact target work order are valid. This
security correction is intentionally fail-closed until later STA/EVT/EVID work
defines and verifies source-authenticated handoff proof.
