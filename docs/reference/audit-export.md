# Audit export reference (`0.04-dev`)

## Purpose

`splendorctl audit export` builds a governance audit package from append-only
trace records and state graph metadata. It opens the trace/state stores in
read-only mode and is a derived view, not a separate source of truth.

The `0.04-dev` audit export is intended for local review, regression fixtures,
and external tooling prototypes. It is marked development schema until the
`0.1-dev` compatibility freeze.

## Command

```bash
splendorctl audit export \
  --db ./trace.db \
  --state-db ./state.db \
  --run <run-id> \
  [--tenant <tenant-id>] \
  [--agent <agent-id>] \
  [--action <action-id-or-name>] \
  [--adapter <adapter-id>] \
  [--node <node-id>] \
  [--instance <instance-id>] \
  [--fleet <fleet-id>]
```

The command emits one JSON object to stdout.

## Schema

Top-level shape:

```json
{
  "schema_version": "splendor.audit_export.v0.04-dev",
  "run_id": "...",
  "generated_at": "2026-06-03T00:00:00Z",
  "source": "trace_state_governance_primitives",
  "replay_mode": "inspect_only",
  "side_effects_replayed": false,
  "filters": { "run": "...", "tenant": "..." },
  "trace_range": {
    "first_sequence": 0,
    "last_sequence": 8,
    "first_trace_event_id": "...",
    "last_trace_event_id": "..."
  },
  "event_count": 9,
  "work_orders": [],
  "policies": [],
  "actions": [],
  "governance_events": [],
  "state_nodes": [],
  "redaction": {
    "applied": true,
    "redacted_keys": ["api_token", "client_secret"]
  }
}
```

### Required evidence groups

| Group | Evidence |
| --- | --- |
| `work_orders` | Accepted or rejected work-order identity, tenant, agent, run, and sanitized reason. |
| `policies` | Policy bundle identity/version, lifecycle (`accepted`, `expired`, `revoked`, etc.), action and reason where present. |
| `actions` | Trace identity, action name, adapter where derivable, final status, redacted action params, verifier result, outcome, and error. |
| `governance_events` | Approval, denial, escalation, circuit-breaker, kill-switch, pause, and resume explanations where present. |
| `state_nodes` | State node ID, parents, state hash, snapshot ID, state metadata, and trace linkage where present. |
| `trace_range` | First/last sequence and trace-event IDs for the included filtered event set. |

## Filtering semantics

Filters are conjunctive. An event must match every supplied filter. Fields are
matched where the trace carries the data:

- `--run` is required and scopes the trace stream.
- `--tenant` and `--agent` match trace identity, work-order fields, approval
  contexts, or gateway verifier context artifacts.
- `--action` matches trace action ID when present, otherwise action name where
  the event carries an action.
- `--adapter` matches approval/escalation adapter fields, gateway verifier
  context artifacts, or adapter-scoped circuit-breaker events.
- `--node`, `--instance`, and `--fleet` match trace identity fields.

## Redaction

Audit export recursively redacts values under keys containing:

```text
secret, token, password, credential, api_key, apikey, authorization,
bearer, signature, private_key, snapshot_bytes, state_bytes
```

It also redacts scalar strings that look like inline credential material, such
as `Bearer ...`, `token=...`, `secret=...`, `password=...`, `credential=...`,
`signature=...`, private-key headers, or JWT-shaped token values.

The export must not contain raw secrets, detached signatures, broad credentials,
or bearer material. Redaction is best-effort for trace payloads already persisted;
runtime code should still avoid writing secrets to trace in the first place.

## Failure behavior

- Missing trace or state DB: export fails.
- Trace sequence/hash mismatch: export fails. Export recomputes each event hash
  from the previous hash and stored payload before trusting the record.
- Run mismatch: export fails.
- Missing referenced state snapshot/node: export fails instead of silently
  omitting state evidence.
- Referenced state snapshot/node hash mismatch: export fails instead of using
  corrupted state evidence.
- Embedded approval or governance transition run/scope identity mismatch: export
  fails instead of exporting evidence from another run or authority boundary.

## Non-goals

- No compliance certification claim.
- No dashboard.
- No long-term archive product.
- No separate audit database or parallel source of truth.
- No policy, verifier, approval adapter, or action re-execution.
