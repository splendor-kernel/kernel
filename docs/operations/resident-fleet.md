# Operating Resident Nodes And Fleet Foundations

This guide covers the stable 0.1 operational pattern for resident nodes, fleet
identity, signed work orders, trace sync, and fleet telemetry. It uses the 0.03
reference contracts that feed the 0.1 compatibility line.

## Maturity And Limits

- Required adapter maturity: `local-safe` for local resident work; `network-safe` for bounded remote calls; `governance-aware` for approval/circuit-breaker participation; `device-safe` only for simulated or bounded physical/device paths that meet the physical requirements.
- Stable primitives: `fleet_id`, `node_id`, `instance_id`, `work_order_id`, trace sync records, state references, and fleet telemetry snapshots.
- Limitations: no full distributed consensus, arbitrary shared memory, production fleet scheduler, production mTLS rollout, analytics dashboard, or permission authority from telemetry.

## Setup

Run the reference checks for node registration, work orders, trace sync, and telemetry:

```bash
cargo test -p splendor-kernel node_registry
cargo test -p splendorctl run_from_config_validates_signed_work_order_and_records_metadata
cargo test -p splendor-store trace_sync
cargo test -p splendor-kernel trace_durability
cargo test -p splendor-kernel fleet_telemetry
```

## Run Path

Operational order:

1. Register a node with distinct `fleet_id`, `node_id`, optional `tenant_id`, kind, capability document, runtime version, and health.
2. Register a runtime instance with distinct `instance_id`, parent `node_id`, runtime mode, hosted tenants, supported features, version, and health.
3. Validate a signed, unexpired, unrevoked, scoped `WorkOrderEnvelope` before run start or resume.
4. Execute local resident work only inside the work-order authority narrowed by tenant/agent policy.
5. Buffer trace records locally and sync ordered `TraceSyncBatch` values to a central trace index.
6. Publish read-only fleet telemetry for heartbeat state, instance status, run status, queue depth, quota/denial signals, trace lag, and failures.

Use these existing examples for concrete fixtures:

- `examples/resident-node-registration/README.md`
- `examples/signed-work-order-local-resident/README.md`
- `examples/resident-trace-sync/README.md`
- `examples/fleet-telemetry-basic/README.md`

## Signed Work Orders

Resident runs must reject missing, bad, expired, revoked, or incompatible work orders before percept collection, policy invocation, state commits, gateway verification, or adapter execution. Work orders narrow runtime authority:

```text
effective actions     = tenant.allowed_actions ∩ work_order.allowed_actions
effective adapters    = tenant.allowed_adapters ∩ work_order.allowed_adapters
effective permissions = tenant.allowed_permissions ∩ work_order.allowed_permissions
effective quota       = min(tenant quota, work-order quota) per field
```

The local reference verifier uses deterministic signed payload validation for tests. It is not a production PKI or key-management product.

## Trace And State Inspection

Trace sync copies validated append-only trace records; it never repairs, renumbers, or rewrites records.

Run targeted trace sync checks:

```bash
cargo test -p splendor-store trace_sync
```

Inspect expected sync behavior in `docs/reference/trace-sync.md`:

- run identity must match the sync scope;
- records must be contiguous and ordered;
- `prev_event_hash` and `event_hash` are validated;
- duplicate sync is idempotent;
- missing or corrupted segments fail closed.

State handoff, where used, must reference explicit snapshots or state heads. It must not introduce hidden shared mutable state.

## Telemetry

Fleet telemetry is observational only. It reports health, run status, queue depth, quota/denial signals, trace sync lag, and failure signals. It must never authorize placement, work-order validation, approvals, permissions, or side effects.

Run the telemetry fixture checks:

```bash
cargo test -p splendor-types fleet_telemetry
cargo test -p splendor-kernel fleet_telemetry
```

## Failure Handling

- Invalid node/instance identity or missing registry scope rejects registration.
- Audit sink failure rejects registry mutation.
- Unknown parent node rejects instance registration.
- Unsigned, expired, revoked, or overbroad work orders reject run start/resume.
- Trace sync missing segments, chain mismatch, hash mismatch, or central conflict fails closed.
- Telemetry lag or failure signals do not grant or deny future actions; future actions still run gateway verification.

## Teardown

The reference registry, trace index, and telemetry fixtures are in-memory tests. If using local `splendorctl` resident configs, remove the example `data/`, `trace.db`, or `state.db` files created by that config only.

## References

- `docs/reference/node-registry.md`
- `docs/reference/work-orders.md`
- `docs/reference/placement.md`
- `docs/reference/trace-sync.md`
- `docs/reference/fleet-telemetry.md`
- `docs/reference/state-handoff.md`
