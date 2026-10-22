# State Handoff Basic

This example documents the experimental loopback-local 0.03-S7 state handoff
compatibility path. It is a local unit-test-backed flow, not a resident or
multi-host migration demo.

## What it proves

1. A source state graph commits state and creates a snapshot.
2. The source scheduler/loop/state-graph owner exports a `StateHandoff` envelope
   from the current head.
3. `KernelRuntime::record_state_handoff_exported` records the source trace event
   and writes the source trace ID into the handoff.
4. An explicit `local_dev` receiver imports only when the signed work order is valid for the same
   tenant, agent, run, and work-order ID. The daemon additionally requires
   `splendor.state.handoff` and the exact envelope admitted for the target run.
5. Snapshot ID, state hash, parent linkage, receiver instance, previous receiver
   head, replay state, and source trace continuity are verified before the
   receiver head changes.
6. Read-only references can be attached for inspection but cannot be mutated.
7. Replay emits a `handoff_boundary` record and does not import state or execute
   side effects.
8. Resident/non-dev import always returns
   `503 state_handoff_proof_unavailable` with `needs_intervention` before state or
   run-trace mutation because v0 has no accepted source-authenticated proof.

## Smoke commands

```bash
cargo test -p splendor-store state_store_exports_and_imports_handoff_snapshot_with_parent_linkage
cargo test -p splendor-kernel state_graph_imports_valid_handoff_with_work_order_authority
cargo test -p splendor-kernel read_only_state_reference_cannot_be_mutated_by_receiver
cargo test -p splendor-daemon --test runtime_daemon_api_tests experimental_local_dev_state_snapshot_import_preserves_compatibility
cargo test -p splendor-daemon --test integration_resident_auth_dispatch resident_state_import_requires_source_authenticated_proof_before_mutation
cargo test -p splendorctl replay_identifies_state_handoff_boundary
```

## Expected trace behavior

- Source side: `state.handoff.exported`.
- Receiver success: `state.handoff.imported` with previous and receiver state
  heads.
- Receiver failure: `state.handoff.import_failed` before the receiver head
  changes.
- Read-only reference: `state.reference.read_only`.
- Resident denial: no receiver run-trace event and no state mutation; the HTTP
  error reports `state_handoff_proof_unavailable`/`needs_intervention`.

## Not included

- No remote transport.
- No fleet scheduler or placement decision.
- No automatic conflict merge.
- No CRDT or distributed mutable state.
- No runtime migration engine.
- No signed source handoff manifest, source event/evidence proof, or durable
  cross-instance replay ledger.
