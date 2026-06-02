# Harmony Governance Bridge Example

This example documents the `0.04-S6` external governance adapter contract. It is a
schema and test-backed fixture, not a Harmony service implementation.

## What it proves

- Harmony can issue a scoped signed work order without passing broad user
  credentials.
- Harmony approval grants and denials map to Splendor `ApprovalGrant` and
  `ApprovalDenial` objects with explicit scope, expiry, issuer, and trace linkage.
- Harmony artifact references include run, state node, trace range, approval
  state, and source references.
- Adapter failure maps to a fail-closed `adapter_failure` result with no approval
  grant.
- A non-Harmony control plane can reuse the same contract with renamed endpoints.

## Reference tests

```bash
cargo test -p splendor-types external_governance
npm test
```

## 1. Harmony-compatible endpoint contract

```json
{
  "schema_version": "splendor.external_governance_adapter.v1",
  "provider": "harmony",
  "endpoints": {
    "work_orders": "/splendor/work-orders/{work_order_id}",
    "action_gateway": "/splendor/action-gateway",
    "approvals": "/splendor/approvals",
    "traces": "/splendor/traces",
    "state_commits": "/splendor/state-commits",
    "artifact_refs": "/splendor/artifacts"
  }
}
```

The same schema can be used by a generic control plane:

```json
{
  "schema_version": "splendor.external_governance_adapter.v1",
  "provider": "customer_console",
  "endpoints": {
    "work_orders": "/governed/work-orders/{work_order_id}",
    "action_gateway": "/governed/action-gateway",
    "approvals": "/governed/approval-decisions",
    "traces": "/governed/runtime-traces",
    "state_commits": "/governed/state-commits",
    "artifact_refs": "/governed/artifact-refs"
  }
}
```

## 2. Scoped work-order bridge

Harmony sends a signed `WorkOrderEnvelope` inside an
`ExternalGovernanceWorkOrderBridge`:

```json
{
  "schema_version": "splendor.external_governance_adapter.v1",
  "external_ref": {
    "provider": "harmony",
    "reference_id": "harmony_wo_123",
    "endpoint": "/splendor/work-orders/harmony_wo_123"
  },
  "work_order": {
    "schema_version": "splendor.work_order.v1",
    "work_order_id": "wo_123",
    "tenant_id": "<tenant-id>",
    "agent_id": "<agent-id>",
    "run_id": "<run-id>",
    "objective": "publish governed artifact",
    "allowed_actions": ["artifact.publish"],
    "allowed_adapters": ["artifact-store"],
    "allowed_permissions": ["artifact.publish"],
    "data_refs": ["artifact:draft-weekly-report"],
    "quotas": { "max_actions_per_tick": 1 },
    "placement": { "target": "local_resident" },
    "issued_at": "2026-06-01T00:00:00Z",
    "expires_at": "2026-06-01T01:00:00Z",
    "revocation": "active",
    "signature": { "key_id": "test-key", "signature": "<detached-signature>" }
  },
  "issuer": { "issuer_id": "harmony.control_plane", "source": "external_adapter" },
  "trace": { "trace_event_id": "<trace-event-id>", "run_id": "<run-id>" },
  "context": {
    "workspace_ref": "finance-weekly-dashboard"
  }
}
```

The bridge rejects context such as `user_credentials`, `access_token`, `secret`,
`accessToken`, `oauth_token`, `jwt`, `cookie`, `allowed_permissions`, or
`approval_token`, including nested metadata. The receiving runtime still validates
the work-order signature, expiry, revocation, tenant, agent, run, and placement
scope before starting or resuming a run.

## 3. External approval grant

```json
{
  "schema_version": "splendor.external_governance_adapter.v1",
  "external_ref": {
    "provider": "harmony",
    "reference_id": "approval_789",
    "endpoint": "/splendor/approvals"
  },
  "approval_id": "<approval-id>",
  "scope": {
    "scope_type": "action",
    "tenant_id": "<tenant-id>",
    "agent_id": "<agent-id>",
    "run_id": "<run-id>",
    "action_id": "<action-id>"
  },
  "decision": "granted",
  "created_at": "2026-06-01T00:05:00Z",
  "expires_at": "2026-06-01T00:20:00Z",
  "reason": "CFO approved publication",
  "issuer": { "issuer_id": "harmony.approver.cfo", "source": "external_adapter" },
  "trace": { "trace_event_id": "<approval-request-trace-id>", "run_id": "<run-id>" }
}
```

This maps to an `ApprovalGrant`. The grant is still only an input to the existing
approval verifier and Action Gateway; it does not execute `artifact.publish` by
itself.

External approval grants must be action-scoped. A global, tenant, agent, or adapter
grant is rejected as blanket authority.

## 4. External approval denial

```json
{
  "schema_version": "splendor.external_governance_adapter.v1",
  "external_ref": { "provider": "harmony", "reference_id": "approval_790" },
  "approval_id": "<approval-id>",
  "scope": {
    "scope_type": "action",
    "tenant_id": "<tenant-id>",
    "agent_id": "<agent-id>",
    "run_id": "<run-id>",
    "action_id": "<action-id>"
  },
  "decision": "denied",
  "created_at": "2026-06-01T00:05:00Z",
  "expires_at": "2026-06-01T00:20:00Z",
  "reason": "publication window closed",
  "issuer": { "issuer_id": "harmony.approver.cfo", "source": "external_adapter" },
  "trace": { "trace_event_id": "<approval-request-trace-id>", "run_id": "<run-id>" }
}
```

This maps to an `ApprovalDenial` and no adapter execution occurs.

## 5. Adapter failure

If Harmony cannot provide a valid decision, the bridge records failure instead of
inventing approval:

```json
{
  "mapping": "adapter_failure",
  "failure": {
    "schema_version": "splendor.external_governance_adapter.v1",
    "external_ref": { "provider": "harmony", "reference_id": "approval_791" },
    "scope": {
      "scope_type": "action",
      "tenant_id": "<tenant-id>",
      "agent_id": "<agent-id>",
      "run_id": "<run-id>",
      "action_id": "<action-id>"
    },
    "occurred_at": "2026-06-01T00:05:00Z",
    "reason": "external approval endpoint unavailable",
    "issuer": { "issuer_id": "harmony.bridge", "source": "external_adapter" },
    "trace": { "trace_event_id": "<trace-event-id>", "run_id": "<run-id>" }
  }
}
```

`adapter_failure` contains no `approval` field and must fail closed.

## 6. Trace-linked artifact reference

```json
{
  "schema_version": "splendor.governed_artifact_ref.v1",
  "artifact_id": "artifact_weekly_dashboard",
  "version": "v2",
  "source_refs": ["dataset:finance.revenue_monthly_v4"],
  "run_id": "<run-id>",
  "state_node_id": "blake3:<state-node-hash>",
  "trace_range": {
    "start_trace_event_id": "<trace-start-id>",
    "end_trace_event_id": "<trace-end-id>"
  },
  "approval_state": "granted",
  "approval_id": "<approval-id>",
  "external_ref": {
    "provider": "harmony",
    "reference_id": "harmony_artifact_456",
    "endpoint": "/splendor/artifacts"
  },
  "export_targets": ["harmony:artifact-registry"]
}
```

Harmony may index this artifact, but Splendor's state node and trace range remain
the runtime evidence for provenance, approval status, and replay.
