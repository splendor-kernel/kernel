# Governance audit export example

This example shows the 0.04-S7 audit/replay path. It is intentionally local and
inspect-only: it reads trace/state stores and does not re-run policies, verifiers,
approval adapters, or action adapters.

## 1. Produce a governed run

Use any local run that writes trace and state DBs. For a circuit-breaker denial
fixture, a minimal config can trip an adapter-scoped breaker:

```yaml
trace_db: ./tmp/governance-audit/trace.db
state_db: ./tmp/governance-audit/state.db
run_id: 00000000-0000-0000-0000-000000000701
allow_unsigned_local_run: true
tenants:
  - id: 00000000-0000-0000-0000-000000000801
    allowed_actions: ["write_file"]
    allowed_adapters: ["filesystem"]
agents:
  - id: 00000000-0000-0000-0000-000000000901
    tenant_id: 00000000-0000-0000-0000-000000000801
    run_id: 00000000-0000-0000-0000-000000000701
    policy:
      type: static
      actions:
        - name: write_file
          adapter: filesystem
          side_effect_class: filesystem
          params:
            path: "blocked.txt"
            contents: "blocked"
adapters:
  filesystem:
    base_dir: ./tmp/governance-audit/fs
circuit_breakers:
  - id: cb_filesystem_adapter
    scope: adapter
    value: filesystem
    state: tripped
    reason: filesystem disabled for incident
    authorized_by: operator:alice
```

Run it:

```bash
cargo run -p splendorctl -- run --config ./tmp/governance-audit/config.yaml --cycles 1
```

The denied filesystem action must not create `blocked.txt` because the Action
Gateway records a circuit-breaker denial before adapter execution.

## 2. Replay explanation

```bash
cargo run -p splendorctl -- replay \
  --db ./tmp/governance-audit/trace.db \
  --state-db ./tmp/governance-audit/state.db \
  --run 00000000-0000-0000-0000-000000000701
```

Expected replay properties:

- `replay_mode` is `inspect_only`;
- `side_effects_replayed` is `false`;
- sensitive strings and raw `snapshot_bytes` / `state_bytes` are redacted before
  replay JSON is emitted;
- `circuit_breaker_denials` includes breaker ID, scope, scope value, and reason;
- approval runs include `approval_events` when approval traces exist.

## 3. Audit export

```bash
cargo run -p splendorctl -- audit export \
  --db ./tmp/governance-audit/trace.db \
  --state-db ./tmp/governance-audit/state.db \
  --run 00000000-0000-0000-0000-000000000701 \
  --tenant 00000000-0000-0000-0000-000000000801 \
  --agent 00000000-0000-0000-0000-000000000901
```

The export contains:

- `schema_version: "splendor.audit_export.v0.04-dev"`;
- identity and trace range for included events;
- work-order acceptance/rejection evidence when present;
- policy bundle/version evidence when present;
- verifier results and final action status;
- governance events such as approvals, denials, escalations, circuit breakers,
  kill switches, pauses, and resumes where present;
- state node evidence for committed state;
- redaction summary for secret-like keys.

## Safety notes

- Audit export is not an archive product or compliance certification.
- Audit export is derived from trace/state/governance primitives only.
- It never executes actions, adapters, policy callbacks, or approval callbacks.
- Replay and audit validate trace hash-chain evidence and referenced state
  snapshot/node hashes before emitting explanations.
- Sensitive keys such as `token`, `secret`, `password`, `credential`,
  `authorization`, `signature`, and `private_key`, plus obvious inline bearer,
  token, signature, private-key, and JWT-shaped values, are redacted from audit
  output.
