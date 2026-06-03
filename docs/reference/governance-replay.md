# Governance replay reference (`0.04-dev`)

## Purpose

Governance replay is an inspect-only reconstruction path for explaining why a
governed action was allowed, denied, paused for approval, escalated, or
circuit-broken. It opens local stores in read-only mode and is derived from trace
and state primitives; it never re-runs policy code, verifier chains, adapters,
approval callbacks, or side effects.

This reference covers the `0.04-S7` development schema. The compatibility line is
not frozen until `0.1-dev`.

## Command

```bash
splendorctl replay \
  --db ./trace.db \
  --state-db ./state.db \
  --run <run-id>
```

Replay emits JSON lines. Every output includes or inherits:

- `replay_mode: "inspect_only"`
- `side_effects_replayed: false`

CLI replay output is redacted before it is emitted. Sensitive scalar values and
values under credential-shaped keys are replaced with `[REDACTED]`; raw
`snapshot_bytes` / `state_bytes` fields are also redacted even when
`--include-state` is used. Snapshot length remains available through
`snapshot_bytes_len`.

## Governance explanation fields

Tick outputs now include:

```json
{
  "type": "tick",
  "actions": [
    {
      "status": "needs_approval | executed | denied | failed | needs_intervention",
      "result": { "allowed": false, "reasons": ["approval_required"] }
    }
  ],
  "approval_events": [
    {
      "lifecycle": "requested | granted | denied | expired | revoked",
      "approval": {
        "approval_id": "...",
        "tenant_id": "...",
        "agent_id": "...",
        "run_id": "...",
        "action_id": "...",
        "action_name": "artifact.publish",
        "adapter": "artifact-store",
        "policy_id": "approval_publish_high",
        "risk_level": "high"
      },
      "side_effects_replayed": false
    }
  ],
  "escalations": [],
  "circuit_breaker_denials": []
}
```

The final `causal_graph` output also includes `approval_events` so an auditor can
see the approval lifecycle across ticks without walking each tick manually.

## Circuit-breaker explanations

Circuit-breaker denials remain visible in tick and causal-graph outputs:

```json
{
  "circuit_breaker_denials": [
    {
      "breaker_id": "cb_adapter_http",
      "scope": "adapter",
      "scope_value": "http",
      "reason": "adapter degraded",
      "reasons": ["circuit_breaker_tripped"]
    }
  ]
}
```

## Replay safety

Replay is read-only. It reconstructs explanations from existing trace/state
records and snapshot bytes only. It does not:

- invoke policies;
- evaluate live verifiers;
- call adapters;
- publish artifacts;
- use credentials;
- retry denied or failed work.

If trace integrity, run IDs, causal message context, child-run linkage, or state
snapshot references are corrupted, replay fails closed with an error instead of
continuing silently.

Replay validates the trace hash chain by recomputing each stored event hash from
the previous hash and payload. State snapshot evidence is also checked against
the snapshot ID, state node data hash, and committed state-node hash where a
`StateCommitted` trace event provides one.

## Trace events interpreted

Governance replay interprets these trace events when present:

- `ApprovalRequested`, `ApprovalGranted`, `ApprovalDenied`, `ApprovalExpired`,
  `ApprovalRevoked`
- `ActionNeedsApproval`, `ActionDenied`, `ActionExecuted`, `ActionFailed`,
  `ActionNeedsIntervention`
- `EscalationTriggered`
- circuit-breaker denial artifacts on `ActionDenied`
- existing state/message/delegation/handoff replay events

## Non-goals

- No approval queue or workflow engine.
- No dashboard.
- No compliance certification claim.
- No side-effect replay mode.
