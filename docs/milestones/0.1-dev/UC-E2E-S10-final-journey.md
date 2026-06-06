# UC-E2E-S10 — Final Cross-Component Acceptance Journey

## Objective

Validate the final `0.1-dev` use-case acceptance journey after prior UC-E2E scenarios pass. UC-E2E-S10 strengthens the SDK/API, work-order, fleet identity, message, action gateway, verifier, adapter, state graph, trace store, approval/governance, physical/edge, replay, and docs/tests primitives by proving they work together through documented public boundaries.

## Functional Scope

- Adds `tests/e2e/use-cases/scenarios/uc_e2e_s10_final_journey/run.py` as the S10 scenario runner.
- Runs after S1-S9 when invoked directly and as part of `--all`.
- Uses public manager, daemon, edge-device, device simulator, `splendorctl work-order sign`, contract, trace/state export, telemetry, governance audit, and replay surfaces.
- Requires machine-readable evidence for API contract status, topology hash, signed work-order placement, data-local analysis, typed specialist response, proposal-only cloud helper, bounded edge inspection, approval-gated publication, one state handoff/resume, central trace aggregation, replay/audit, controlled negative branches, anti-drift results, and FR/primitive coverage.
- Updates report aggregation so S10 remains failed unless required artifacts, IDs, events, positives, negatives, replay suppression, and coverage matrix evidence are present.

## Non-Goals

- No real customer data, robot, drone, cloud service, database, or external artifact publisher.
- No enterprise SaaS UI, marketplace, billing, or approval product workflow.
- No production OAuth/PKI, Kubernetes rollout, full distributed consensus, or universal shared memory.
- No direct actuator, motor, firmware-safety-bypass, or hard real-time robotics control.
- No replay side effects by default.
- No private helper-only path for acceptance evidence.

## Public Contracts Changed

- `bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S10` is accepted.
- `bash scripts/e2e/verify-use-case-acceptance.sh --all` includes S10.
- S10 writes acceptance artifacts under `target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S10/`.
- The acceptance manager registration boundary now treats identical duplicate node/instance registration requests as idempotent success while still rejecting incompatible duplicate metadata; this lets S10 run after prerequisite scenarios without counting duplicate rejection as success.
- Message read/list/causal-graph and ack/nack OpenAPI request schemas now require explicit non-null tenant/run/agent scope for the acceptance caller path; no broad fleet-admin message-read path is introduced.

## Runtime Primitive Impact

| Primitive | Impact |
| --- | --- |
| Work order | validates scoped signed work orders and invalid unsigned work-order rejection |
| Fleet/node identity | validates node and instance registration, capabilities, placement, dispatch, telemetry, and audit attribution |
| Message | validates typed specialist task request/response and cloud-helper proposal messages with duplicate non-double-apply evidence |
| Gateway/verifier/adapter | validates data, artifact, governance, and device actions remain mediated by public gateway/API calls |
| State graph | validates explicit state export/import, state hash evidence, and one resume after handoff |
| Trace store | validates central trace aggregation, required event IDs, tamper rejection, and trace/state export paths |
| Approval/governance | validates external publication pause/grant/execute-once, expired approval denial, circuit breaker, kill switch, and audit export |
| Physical/edge | validates high-level bounded inspection through the simulator and raw physical action rejection |
| Replay | validates inspect-only replay and unsafe side-effect replay rejection without changing public counters |

## Required Trace/Audit Behavior

S10 requires evidence for:

- `work_order.accepted`
- `placement.evaluated`
- `data_scope.verified`
- `message.sent`
- `message.received`
- `cloud_helper.proposal.received`
- `safety.verification.completed`
- `action.executed`
- `action.denied`
- `action.needs_approval`
- `approval.granted`
- `artifact.created`
- `artifact.publish.executed`
- `state.committed`
- `state.exported`
- `state.imported`
- `run.resumed`
- `trace.sync.completed`
- `replay.explained`
- `governance.audit.exported`
- `circuit_breaker.tripped`
- `kill_switch.activated`

The report aggregator rejects missing event IDs, non-UUID event IDs, required event IDs not backed by exported trace records, manager audit records, or public API response evidence, and evidence rows that lack S10 run/work-order/message/node/instance/governance correlation.

## Controlled Negative Branches

S10 includes independent negative branches for invalid work order, unauthorized data ref, specialist permission escalation, duplicate remote delivery, unsupported/omitted-scope/cross-tenant/unrelated-agent message API access, unauthorized ack/nack attempts, raw physical action, expired approval, circuit-breaker blocked publish, kill-switch cancellation, tampered trace/state import, and unsafe replay mode.

## Replay Behavior

- Replay mode is `inspect_only`.
- `side_effects_allowed_default` is `false`.
- Unsafe side-effect replay is rejected.
- Public daemon adapter counters and device simulator counters must not change across replay.

## Tests and Evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| integration | Run final field-intelligence journey | `scenario-report.json`, `journey-report.json`, `registry-report.json`, `api-traffic.ndjson` |
| message | Prove typed specialist/cloud helper causality | `message-flow.json`, `manager-audit-export.json` |
| governance | Prove approval/circuit-breaker/kill-switch branches | `artifact-publication-report.json`, `governance-branches.json` |
| physical/edge | Prove bounded simulator execution and raw-action denial | `edge-inspection-report.json` |
| state/trace | Prove handoff, resume, trace sync, and tamper rejection | `state-handoff-report.json`, `trace-sync-report.json`, `trace-export.jsonl`, `state-export.json` |
| replay/audit | Prove no replay side effects and explainability | `replay-report.json`, `audit-package.json`, `audit-report.json` |
| coverage | Prove FR and primitive coverage | `fr-primitive-coverage-matrix.json`, `anti-drift-results.json` |

## Example

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S10
bash scripts/e2e/verify-use-case-acceptance.sh --all
```

## Future Extension Notes

- S10 intentionally uses deterministic fixture services and simulated device behavior.
- Any future replacement with real external systems must remain separately gated, authenticated, scoped, trace-linked, and safe for replay.
