# Action Approval Flow Example

This example documents the 0.04-S2 local daemon approval path. It is intentionally
test-backed rather than a long-running service fixture: the runtime daemon tests
create a run with an approval policy, start it, observe `waiting_for_approval`,
request a trusted receipt for the exact challenge, retry the exact action through
the gateway, and replay the approval trace events.

## What it proves

- An approval-required action returns `NeedsApproval` and does not execute the
  adapter.
- The run enters `waiting_for_approval` with trace linkage.
- A raw granted `ApprovalEvidence` does not authorize execution.
- A trusted one-use receipt scoped to the complete exact challenge permits
  re-evaluation and one execution through the gateway.
- Changed action parameters or receipt reuse fails closed.
- Denied, expired, revoked, wrong-scope, or unsupported-schema approval evidence
  fails closed and does not execute the adapter.
- Replay explains approval request/grant/denial/expiry/revocation events without
  replaying side effects.

## Reference test path

Run the approval daemon tests:

```bash
cargo test -p splendor-daemon --test runtime_daemon_api_tests approval_required_run_pauses_and_exact_receipt_retry_executes_once
cargo test -p splendor-daemon --test runtime_daemon_api_tests legacy_approval_variants_cannot_resume_tick_or_execute_adapter
cargo test -p splendor-daemon --test runtime_daemon_api_tests action_endpoint_traces_approval_lifecycles_without_adapter_bypass
```

Run the gateway approval verifier tests:

```bash
cargo test -p splendor-gateway approval_required_action_pauses_without_adapter_execution
cargo test -p splendor-gateway scoped_legacy_approval_grant_requires_authority_receipt
cargo test -p splendor-gateway authority_obligation
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
    {
      "status": "NeedsApproval",
      "approval_challenge": {
        "schema_version": "splendor.approval_challenge.v1",
        "approval_id": "<approval-id>",
        "action_id": "<action-id>",
        "requested_at": "<original-requested-at>",
        "gateway_action_request_digest": "blake3:<digest>",
        "authority_decision_digest": "blake3:<digest>"
      }
    }
  ]
}
```

The adapter execution counter remains `0`.

3. Submit the complete `approval_challenge` to the trusted manager's approval
request operation. Legacy scalar request coordinates must match the challenge
exactly. A successful manager grant returns both:

- `evidence`: a non-authorizing compatibility projection;
- `authority_obligation_receipt`: the raw receipt to present to the daemon.

Do not construct or edit the receipt in the client. Issuer, audience, key,
signature secret, and revocation source come from trusted process configuration.

4. Retry the exact pending action through `POST /actions`. The request must copy
the action ID, tenant/agent/run, action payload, effective adapter, quota,
preconditions, and `requested_at` from the challenged attempt and include a causal
trace link. The receipt object below means the complete object returned by the
manager; omitted receipt fields are not optional.

```json
{
  "action_id": "<challenge-action-id>",
  "run_id": "<run-id>",
  "tenant_id": "<tenant-id>",
  "agent_id": "<agent-id>",
  "causal_trace_id": "<run-trace-event-id>",
  "action": {
    "name": "artifact.publish",
    "params": {},
    "side_effect_class": "External",
    "required_permissions": ["artifact.publish"],
    "preconditions": [],
    "postconditions": []
  },
  "adapter": "artifact-store",
  "quota_usage": {
    "actions": 1,
    "action_duration_ms": 0,
    "filesystem_read_bytes": 0,
    "filesystem_write_bytes": 0,
    "network_read_bytes": 0,
    "network_write_bytes": 0,
    "http_requests": 0
  },
  "satisfied_preconditions": [],
  "requested_at": "<challenge-requested-at>",
  "authority_obligation_receipts": [
    {
      "schema_version": "splendor.authority.obligation_receipt.v1",
      "receipt_id": "<receipt-id>",
      "issuer": "<configured-issuer-principal-id>",
      "audience": "<challenge-receipt-audience>",
      "obligation_id": "<challenge-obligation-id>",
      "kind": "approval_required",
      "subject": "<challenge-subject-principal-id>",
      "authority_decision_id": "<challenge-authority-decision-id>",
      "canonical_request_digest": "<challenge-canonical-request-digest>",
      "evidence_digest": "blake3:<manager-evidence-digest>",
      "evidence_ref": "approval-trace:<manager-approval-trace-id>",
      "issued_at": "2026-05-29T00:01:00Z",
      "expires_at": "<challenge-expires-at>",
      "revocation": "active",
      "revocation_ref": "<configured-revocation-source>",
      "approval_id": "<approval-id>",
      "approval_trace_event_id": "<manager-approval-trace-id>",
      "validation": {
        "validation_kind": "local_signature",
        "algorithm": "<configured-algorithm>",
        "key_id": "<configured-key-id>",
        "digest": "blake3:<receipt-digest>",
        "signature": "<manager-issued-signature>"
      }
    }
  ]
}
```

Expected outcome:

```json
{
  "status": "Executed"
}
```

Run inspection now reports `running`, one adapter execution, and the same tick
count/state head that existed while paused. Reusing the receipt or changing the
action returns a fail-closed outcome and does not produce a second adapter call.
`POST /runs/<run-id>/resume` with raw evidence or a receipt returns `409` and does
not execute a scheduler tick.

## Expected trace/replay facts

The run trace contains:

- `ActionNeedsApproval`
- `ApprovalRequested`
- `RunPaused { reason: "waiting_for_approval" }`
- `ApprovalGranted`
- `ActionExecuted`
- `OutcomeRecorded`
- `RunResumed`

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
