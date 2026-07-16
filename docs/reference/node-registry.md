# Node Registry Reference

The node registry is the 0.03-S2 reference contract for resident Splendor nodes
and runtime instances. It records node identity, fleet/tenant scope,
capabilities, constraints, runtime version, hosted tenants, supported features,
and mutable health.

Rust implementation:

- `splendor_types::{NodeRegistration, InstanceRegistration, NodeHeartbeat, InstanceHeartbeat}`
- `splendor_kernel::{NodeRegistry, InMemoryNodeRegistry}`

## Purpose

The registry lets a management boundary discover and describe Splendor nodes and
instances before later sprints add work-order ingestion, placement, remote
transport, trace aggregation, or fleet telemetry. It is intentionally minimal and
local-correct.

The registry does not authorize work. A registered node or instance is only a
described execution target. Signed work orders, tenant policy, and the Action
Gateway remain separate authorization layers.

## Identity and scope

Node registry identities are distinct typed IDs:

| Type | Purpose |
| --- | --- |
| `FleetId` | Governed fleet boundary. |
| `NodeId` | Physical, virtual, or logical host node. |
| `InstanceId` | Concrete Splendor runtime process. |
| `TenantId` | Tenant authority boundary. |

`RegistryScope` contains at least one of `fleet_id` or `tenant_id`. A scope with
neither value is invalid and is rejected before registration.

## Node registration schema

```rust
pub struct NodeRegistration {
    pub node_id: NodeId,
    pub kind: NodeKind,
    pub scope: RegistryScope,
    pub capability_document: CapabilityDocument,
    pub runtime_version: String,
    pub health: NodeHealth,
    pub registered_at: OffsetDateTime,
}
```

`NodeKind` is a validated token such as `cloud.worker`, `customer.vpc`,
`edge.appliance`, `desktop.sidecar`, or `physical.robot.drone`. 0.03-S2 records
physical-looking kinds for future compatibility but does not implement physical
safety policy.

## Instance registration schema

```rust
pub struct InstanceRegistration {
    pub instance_id: InstanceId,
    pub node_id: NodeId,
    pub runtime_mode: RuntimeMode,
    pub hosted_tenants: Vec<TenantId>,
    pub supported_features: Vec<String>,
    pub runtime_version: String,
    pub health: InstanceHealth,
    pub registered_at: OffsetDateTime,
}
```

`RuntimeMode` values:

- `ephemeral`
- `resident`
- `dedicated`
- `sidecar`
- `local_dev`

Instance registration fails closed when the parent node is unknown, the instance
ID is duplicated, no hosted tenants are declared, or supported feature names are
invalid or duplicated. When the parent node carries a tenant scope, every hosted
tenant advertised by the instance must match that parent tenant scope. Fleet-only
nodes can advertise multiple hosted tenants for later placement policy, but this
does not authorize work by itself.

## Heartbeats

Heartbeats update mutable health only:

```rust
pub struct NodeHeartbeat {
    pub node_id: NodeId,
    pub health: NodeHealth,
    pub recorded_at: OffsetDateTime,
}

pub struct InstanceHeartbeat {
    pub node_id: NodeId,
    pub instance_id: InstanceId,
    pub health: InstanceHealth,
    pub recorded_at: OffsetDateTime,
}
```

The in-memory registry stores static registration separately from mutable health.
A heartbeat never overwrites node kind, registry scope, capability document,
runtime version, hosted tenants, or supported features.

`registered_at`, `health.observed_at`, and heartbeat `recorded_at` are
sender-reported observational metadata. They do not determine freshness. The
registry records a manager-observed receipt timestamp through
`register_*_received_at` and `record_*_heartbeat_received_at`; the convenience
methods obtain that timestamp from the receiving process. A sender therefore
cannot keep a node fresh by reporting a far-future timestamp or reorder manager
receipts by reporting an old timestamp.

Manager-observed receipt time may not move backwards. A receipt-time regression
is rejected and leaves the previous record unchanged.

## Stale heartbeat detection

`NodeRegistryConfig::stale_after` controls freshness. Stale detection is
deterministic and compares the query time with manager-observed
`last_heartbeat_at`:

```text
fresh  when now <  last_heartbeat_at + stale_after
stale  when now >= last_heartbeat_at + stale_after
```

The default `stale_after` is 60 seconds. Tests use explicit timestamps so
fresh/stale boundary behavior is reproducible.

## Management audit events

Registry mutations emit management audit events through `ManagementAuditSink`.
The reference in-memory registry fails closed when the audit sink fails, so the
mutation is not applied without an audit event.

Canonical event classes:

| Event class | Rust kind | Meaning |
| --- | --- | --- |
| `node.registered` | `ManagementAuditEventKind::NodeRegistered` | Node registration accepted. |
| `instance.registered` | `ManagementAuditEventKind::InstanceRegistered` | Instance registration accepted under a node. |
| `node.heartbeat_recorded` | `ManagementAuditEventKind::NodeHeartbeatRecorded` | Node mutable health updated. |
| `instance.heartbeat_recorded` | `ManagementAuditEventKind::InstanceHeartbeatRecorded` | Instance mutable health updated. |

These are management audit events, not run-scoped tick trace events. They are
suitable for later trace aggregation but do not require fake `RunId` values.

## Daemon security boundary

The daemon security contract includes S2 endpoint scopes:

| Scope | Operation |
| --- | --- |
| `splendor.nodes.register` | Register a node. |
| `splendor.instances.register` | Register an instance under a node. |
| `splendor.nodes.heartbeat` | Record node heartbeat. |
| `splendor.instances.heartbeat` | Record instance heartbeat. |

The bounded acceptance-manager route is
`POST /fleet/instances/{instance_id}/heartbeat`. It requires the existing
`splendor.instances.heartbeat` scope and delegates mutation to
`NodeRegistry::record_instance_heartbeat_received_at` with a server-owned receipt
timestamp; it does not create a second instance lifecycle owner. The
central-manager inbound API remains acceptance-only
self-asserted metadata as documented by RFC 0011, not a production-authenticated
remote manager claim.

Non-dev calls require authenticated caller credentials, matching tenant/fleet
binding, matching audience, expiry/revocation checks, endpoint scope, and audit
attribution. These scopes do not grant authority to start runs or execute agent
actions.

## Failure modes

| Failure | Behavior |
| --- | --- |
| Invalid node/instance ID | Reject before mutation. |
| Missing tenant/fleet scope | Reject before mutation. |
| Invalid capability document | Reject before node registration. |
| Duplicate node/instance ID | Reject without overwriting the existing record. |
| Unknown parent node | Reject instance registration or heartbeat. |
| Instance hosted tenants exceed parent node tenant scope | Reject before registration. |
| Sender timestamp is old or far in the future | Retain it as observational metadata; freshness still uses receipt time. |
| Manager receipt-time regression | Reject without changing health. |
| Audit sink failure | Fail closed and do not apply mutation. |
| Registry storage unavailable | Fail closed. |

## State and replay behavior

The registry does not mutate agent state graph nodes. Registry state is explicit
management metadata. Replay remains inspect-only: it can inspect registration and
heartbeat audit events but must not re-register nodes, dispatch work, or execute
adapter side effects.

## Minimal example

```rust
use splendor_kernel::{InMemoryNodeRegistry, NodeRegistry};
use splendor_types::*;
use time::OffsetDateTime;

let now = OffsetDateTime::now_utc();
let tenant_id = TenantId::new();
let node_id = NodeId::new();

let node = NodeRegistration {
    node_id: node_id.clone(),
    kind: NodeKind::new("edge.appliance")?,
    scope: RegistryScope::tenant(tenant_id.clone()),
    capability_document: CapabilityDocument::new(
        vec!["runtime.resident".to_string(), "trace.buffer.local".to_string()],
        serde_json::json!({})
    )?,
    runtime_version: "splendor-0.03-dev".to_string(),
    health: NodeHealth {
        status: HealthStatus::Healthy,
        observed_at: now,
        metadata: serde_json::json!({"network": "online"}),
    },
    registered_at: now,
};

let registry = InMemoryNodeRegistry::new();
registry.register_node_received_at(node, now)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Non-goals

- No signed work-order ingestion or validation.
- No placement policy or workload scheduling.
- No remote message transport.
- No central trace aggregation.
- No fleet telemetry dashboard.
- No device safety verifier implementation.
