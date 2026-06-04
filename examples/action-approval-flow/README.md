# Action Approval Flow Example

This example documents the 0.04-S2 local daemon approval path. It is intentionally
test-backed rather than a long-running service fixture: the runtime daemon tests
create a run with an approval policy, start it, observe `waiting_for_approval`,
resume with scoped approval evidence, and replay the approval trace events.

## What it proves

- An approval-required action returns `NeedsApproval` and does not execute the
  adapter.
- The run enters `waiting_for_approval` with trace linkage.
- A valid approval grant scoped to tenant, agent, run, action, and adapter permits
  re-evaluation and execution through the gateway.
- Denied, expired, revoked, wrong-scope, or unsupported-schema approval evidence
  fails closed and does not execute the adapter.
- Replay explains approval request/grant/denial/expiry/revocation events without
  replaying side effects.

## Reference test path

Run the approval daemon tests:

```bash
cargo test -p splendor-daemon approval_required_run_pauses_and_valid_grant_resumes_execution
cargo test -p splendor-daemon approval_denial_expiry_and_wrong_scope_do_not_execute_adapter
```

Run the gateway approval verifier tests:

```bash
cargo test -p splendor-gateway approval_required_action_pauses_without_adapter_execution
cargo test -p splendor-gateway valid_scoped_approval_grant_allows_execution
cargo test -p splendor-gateway approval_wrong_scope_is_denied_without_adapter_execution
cargo test -p splendor-gateway approval_run_and_action_id_scope_mismatches_are_denied_without_adapter_execution
cargo test -p splendor-gateway approval_schema_version_mismatches_fail_closed_without_adapter_execution
cargo test -p splendor-gateway approval_denial_expiry_and_revocation_fail_closed
cargo test -p splendor-gateway approval_verifier_uncertainty_needs_intervention_without_adapter_execution
```

## Minimal HTTP shape

This shape is illustrative. Non-dev daemon calls must include an authenticated
`CallerCredential` object with endpoint scopes, tenant binding, audience binding,
expiry, and revocation status. A bearer token or audit record alone is not action
authority.

1. Create a run with `approval_policies`:

```json
{
  "tenant_id": "<tenant-id>",
  "agent_id": "<agent-id>",
  "work_order": {
    "schema_version": "splendor.work_order.v1",
    "work_order_id": "wo_approval_create",
    "tenant_id": "<tenant-id>",
    "agent_id": "<agent-id>",
    "run_id": null,
    "objective": "Create approval-gated artifact publish run",
    "allowed_actions": ["artifact.publish"],
    "allowed_adapters": ["artifact-store"],
    "allowed_permissions": ["artifact.publish"],
    "data_refs": [],
    "quotas": {
      "max_actions_per_tick": 1,
      "max_action_duration_ms": null,
      "max_filesystem_read_bytes": null,
      "max_filesystem_write_bytes": null,
      "max_network_read_bytes": null,
      "max_network_write_bytes": null,
      "max_http_requests_per_minute": null
    },
    "placement": {
      "target": "local_resident",
      "data_locality": null,
      "requires_gpu": false,
      "dedicated_instance": false,
      "required_capabilities": [],
      "max_runtime_ms": null
    },
    "issued_at": "2026-05-29T00:00:00Z",
    "expires_at": "2026-05-29T00:10:00Z",
    "revocation": "active",
    "signature": { "key_id": "approval-local-key", "signature": "signed-create-work-order" }
  },
  "credential": {
    "credential_id": "cred_approval_operator",
    "principal": {
      "app": { "app_principal_id": "app_approval_console", "label": "Approval console" },
      "client_principal_id": "client_approval_operator",
      "label": "Approval operator"
    },
    "scopes": ["runs_create"],
    "binding": { "tenant": { "tenant_id": "<tenant-id>" } },
    "audience": { "daemon": { "daemon_id": "<daemon-id>" } },
    "expires_at": "2026-05-29T00:10:00Z",
    "revocation": "active"
  },
  "audit_attribution": {
    "principal": {
      "app": { "app_principal_id": "app_approval_console", "label": "Approval console" },
      "client_principal_id": "client_approval_operator",
      "label": "Approval operator"
    },
    "credential_id": "cred_approval_operator",
    "requested_at": "2026-05-29T00:00:00Z"
  },
  "allowed_actions": ["artifact.publish"],
  "allowed_adapters": ["artifact-store"],
  "allowed_permissions": ["artifact.publish"],
  "policy_bundle_required": false,
  "policy_bundle": null,
  "policy_actions": [
    {
      "action": {
        "name": "artifact.publish",
        "params": {},
        "side_effect_class": "External",
        "cost_estimate": null,
        "required_permissions": ["artifact.publish"],
        "preconditions": [],
        "postconditions": []
      },
      "adapter": "artifact-store",
      "quota_usage": null,
      "satisfied_preconditions": []
    }
  ],
  "registered_actions": [
    { "name": "artifact.publish", "adapter": "artifact-store" }
  ],
  "approval_policies": [
    {
      "schema_version": "splendor.approval_policy.v1",
      "policy_id": "policy_publish_requires_approval",
      "tenant_id": "<tenant-id>",
      "agent_id": "<agent-id>",
      "action_name": "artifact.publish",
      "adapter": "artifact-store",
      "required_permission": "artifact.publish",
      "side_effect_class": null,
      "risk_level": "external_publish",
      "reason": "publishing artifacts requires approval",
      "expires_at": null
    }
  ],
  "allowed_percept_schemas": [],
  "allowed_percept_sources": [],
  "initial_state": null,
  "snapshot_interval": null
}
```

2. Start the run:

```http
POST /runs/<run-id>/start
```

Expected outcome:

```json
{
  "status": "waiting_for_approval",
  "action_outcomes": [
    { "status": "NeedsApproval" }
  ]
}
```

The adapter execution counter remains `0`.

3. Resume with scoped grant evidence:

```json
{
  "credential": {
    "credential_id": "cred_approval_operator",
    "principal": {
      "app": { "app_principal_id": "app_approval_console", "label": "Approval console" },
      "client_principal_id": "client_approval_operator",
      "label": "Approval operator"
    },
    "scopes": ["runs_resume"],
    "binding": { "tenant": { "tenant_id": "<tenant-id>" } },
    "audience": { "daemon": { "daemon_id": "<daemon-id>" } },
    "expires_at": "2026-05-29T00:10:00Z",
    "revocation": "active"
  },
  "work_order": {
    "schema_version": "splendor.work_order.v1",
    "work_order_id": "wo_approval_resume",
    "tenant_id": "<tenant-id>",
    "agent_id": "<agent-id>",
    "run_id": "<run-id>",
    "objective": "Resume approval-gated artifact publish run",
    "allowed_actions": ["artifact.publish"],
    "allowed_adapters": ["artifact-store"],
    "allowed_permissions": ["artifact.publish"],
    "data_refs": [],
    "quotas": {
      "max_actions_per_tick": 1,
      "max_action_duration_ms": null,
      "max_filesystem_read_bytes": null,
      "max_filesystem_write_bytes": null,
      "max_network_read_bytes": null,
      "max_network_write_bytes": null,
      "max_http_requests_per_minute": null
    },
    "placement": {
      "target": "local_resident",
      "data_locality": null,
      "requires_gpu": false,
      "dedicated_instance": false,
      "required_capabilities": [],
      "max_runtime_ms": null
    },
    "issued_at": "2026-05-29T00:00:00Z",
    "expires_at": "2026-05-29T00:10:00Z",
    "revocation": "active",
    "signature": { "key_id": "approval-local-key", "signature": "signed-resume-work-order" }
  },
  "audit_attribution": {
    "principal": {
      "app": { "app_principal_id": "app_approval_console", "label": "Approval console" },
      "client_principal_id": "client_approval_operator",
      "label": "Approval operator"
    },
    "credential_id": "cred_approval_operator",
    "requested_at": "2026-05-29T00:00:00Z"
  },
  "reason": "approval granted",
  "approval_evidence": {
    "schema_version": "splendor.approval_evidence.v1",
    "approval_id": "<approval-id>",
    "tenant_id": "<tenant-id>",
    "agent_id": "<agent-id>",
    "run_id": "<run-id>",
    "action_id": null,
    "action_name": "artifact.publish",
    "adapter": "artifact-store",
    "decision": "Granted",
    "reason": "approved by test approver",
    "issued_at": "2026-05-29T00:00:00Z",
    "expires_at": "2026-05-29T00:10:00Z",
    "revoked": false,
    "trace_event_id": null
  }
}
```

Expected outcome:

```json
{
  "status": "running",
  "action_outcomes": [
    { "status": "Executed" }
  ]
}
```

## Expected trace/replay facts

The run trace contains:

- `ActionNeedsApproval`
- `ApprovalRequested`
- `RunPaused { reason: "waiting_for_approval" }`
- `RunResumed`
- `ApprovalGranted`
- `ActionExecuted`
- `OutcomeRecorded`

`POST /runs/<run-id>/replay` returns `approval_events` such as:

```json
[
  { "lifecycle": "requested", "sequence": 12 },
  { "lifecycle": "granted", "sequence": 25 }
]
```

Replay is inspect-only. It does not re-submit the approval, call the verifier,
resume the run, or execute the adapter again.

## Not included

- approval queue UI;
- notification delivery;
- workflow DSL;
- escalation policies;
- circuit breakers;
- external control-plane integration.
