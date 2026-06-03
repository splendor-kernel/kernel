# 0.04-S7 — Governance replay and audit

## Objective

Strengthen the governance, replay, trace-store, and state-graph primitives by
making governed decisions explainable after the fact without re-running policies,
verifiers, adapters, approval integrations, or side effects.

## Functional scope

- Replay explains approval lifecycle events (`requested`, `granted`, `denied`,
  `expired`, `revoked`) and final action outcomes including `needs_approval`.
- Replay preserves circuit-breaker denial explanations with scope and breaker ID.
- `splendorctl audit export` emits a redacted audit package derived from trace
  records and state graph metadata.
- Audit export filters by tenant, agent, run, action, adapter, node, instance,
  and fleet where those fields exist in trace identity or trace payloads.

## Non-goals

- No compliance certification claim.
- No dashboard.
- No long-term archival product.
- No new governance workflow engine.
- No new side-effect path and no replay side effects.
- No future 0.05 physical/edge scope.

## Public contracts changed

- Added `splendorctl audit export --db --state-db --run` with optional scope
  filters.
- Added `splendor.audit_export.v0.04-dev` JSON output schema.
- Replay tick and causal-graph JSON now include `approval_events`.
- Replay action JSON now includes `status: "needs_approval"` for
  `ActionNeedsApproval` trace events.

## Runtime primitive impact

| Primitive | Impact |
| --- | --- |
| Percept | none |
| Policy | none; audit does not re-run policies |
| Gateway | none; audit consumes gateway verifier results from trace |
| Verifier | none; audit/replay explain persisted verifier results |
| State graph | reads state node metadata for audit evidence |
| Trace store | reads and validates ordered trace records |
| Replay | added approval lifecycle explanation and `needs_approval` action status |
| Message | none |
| Work order | accepted/rejected work-order trace events included in audit export |
| Governance | approval, denial, escalation, circuit-breaker, kill-switch, pause, and resume events are exportable |

## Trace behavior

- No new trace event classes were added.
- Replay interprets existing approval and action-governance trace events.
- Audit export records first/last included trace sequence and trace-event IDs.
- Trace and state stores are opened read-only for replay/audit, and trace ordering
  and recomputed hash-chain validation remain mandatory before replay/audit
  output is produced.

## State behavior

- No state nodes are created by replay or audit export.
- Audit reads referenced state nodes from `StateCommitted` trace identity or
  snapshot ID and includes state node ID, parents, state hash, snapshot ID, and
  metadata.
- Missing referenced state evidence fails export instead of silently omitting it.
- Referenced snapshots are checked against snapshot IDs, state-node data hashes,
  and committed state-node hashes before replay/audit uses them as evidence.

## Gateway and verifier behavior

- No gateway behavior changed.
- No verifier behavior changed.
- Audit reads persisted verifier results and gateway context artifacts; it never
  re-evaluates live verifier chains.
- Redaction is applied to action params, verifier artifacts, outcomes, scalar
  reason/error text, and state metadata before audit export is emitted.

## Replay behavior

- Approval lifecycle events are reconstructed in tick outputs and the causal
  graph with `side_effects_replayed: false`.
- `ActionNeedsApproval` is represented as an action status of `needs_approval`.
- Circuit-breaker denials remain replay-visible with breaker ID, scope, scoped
  value, reason, and denial reasons.
- Replay remains inspect-only and does not execute adapters or policy code.
- Replay CLI output redacts credential-shaped values and suppresses raw
  `snapshot_bytes` / `state_bytes` while preserving `snapshot_bytes_len`.

## Failure behavior

- Corrupted trace sequence/hash or run mismatch fails replay/audit.
- Missing trace DB or state DB fails audit export.
- Missing referenced state snapshot/node fails audit export.
- Embedded approval/governance run and scope identity mismatches fail
  replay/audit.
- Referenced state snapshot/node hash mismatches fail replay/audit.
- Raw secrets are redacted from audit output where sensitive keys or inline
  credential-shaped scalar values are detected.

## Test evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| unit | CLI parses `audit export` filters | `crates/splendorctl/tests/unit/cli_tests.rs::parse_args_accepts_audit_export_filters` |
| replay | Approval lifecycle and final outcomes reconstruct without side effects | `replay_explains_approval_lifecycle_and_final_outcomes_without_side_effects` |
| replay | Circuit-breaker denial scope and breaker ID remain explained | `replay_reports_circuit_breaker_denial_scope` |
| audit | Audit export includes identity/work-order/policy/verifier/action/state/trace evidence and redacts secrets | `audit_export_includes_governance_fields_redacts_secrets_and_filters_scope` |
| negative | Replay output redacts sensitive values and raw snapshot bytes | `replay_output_redacts_sensitive_values_and_snapshot_bytes` |
| negative | Replay/audit reject approval run mismatches | `replay_rejects_approval_context_run_mismatch`, `audit_export_rejects_approval_context_run_mismatch` |
| negative | Replay/audit reject state hash mismatches | `replay_and_audit_reject_state_snapshot_hash_mismatch` |
| negative | Trace payload tampering is detected by hash recomputation | `decode_trace_records_rejects_payload_hash_mismatch` |

## Example or fixture

- `examples/governance-audit-export/README.md`

## Future extension notes

- `0.1-dev` can freeze the audit schema or move it into generated Rust/TypeScript
  types without changing the source-of-truth model: trace/state/governance
  primitives remain authoritative.
- Fleet or physical/edge audit exporters can reuse the same filter model once
  those milestones add their own trace identities and sync paths.
