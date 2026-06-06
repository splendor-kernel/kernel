# UC-E2E-S9 — Failure Injection, Quotas, Bounded Retry, and Fail-Closed Behavior

## Objective

Validate the post-implementation acceptance path for deterministic runtime failures. UC-E2E-S9 strengthens quota, verifier, gateway, adapter outcome, trace store, state graph, retry, message delivery, fleet telemetry/placement, governance, replay/audit, and docs/tests by proving failures are denied, paused, cancelled, or recorded rather than converted into allow.

## Functional Scope

- Adds `tests/e2e/use-cases/scenarios/uc_e2e_s9_failure_injection/run.py` as the S9 scenario runner.
- Drives public daemon and manager HTTP APIs for run creation, gateway action submission, quota pressure, adapter failure, remote message failure, stale placement, trace sync recovery, state read, trace export, and inspect-only replay.
- Reuses prior public scenario evidence from S1, S4, and S5 for trace write failure, state commit failure, remote message/trace sync behavior, policy expiry, circuit breaker, kill switch, and telemetry non-authority.
- Updates `scripts/e2e/verify-use-case-acceptance.sh` so `--scenario UC-E2E-S9` pre-runs required source scenarios and `--all` includes S0-S9.
- Updates `aggregate_report.py` so S9 is rejected unless machine-readable positive, negative, replay, trace, state, API, retry, idempotency, and anti-drift evidence exists.

## Non-Goals

- No chaos testing against production infrastructure.
- No high-scale load benchmark.
- No global exactly-once distributed guarantee.
- No unbounded retries.
- No fake success after adapter failure.
- No silent fallback from verifier, policy, trace, or state errors to allow.
- No private Rust helper path is used to claim S9 acceptance.
- No S10 final journey coverage is claimed; S10 remains `blocked_not_yet_covered`.

## Public Contracts Changed

- `bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S9` is now accepted.
- `bash scripts/e2e/verify-use-case-acceptance.sh --all` now includes S9 and leaves S10 blocked.
- S9 writes acceptance artifacts under `target/splendor-e2e/use-case-acceptance/artifacts/UC-E2E-S9/`.
- No daemon, manager, OpenAPI, primitive schema, or stable SDK contract is changed.

## Runtime Primitive Impact

| Primitive | Impact |
| --- | --- |
| Percept | none |
| Policy | validates expired/unavailable policy fail-closed evidence from S5 |
| Gateway | validates action submission remains gateway-mediated for success, failure, and denial |
| Verifier | validates unavailable/uncertain verifier behavior denies or intervenes |
| State graph | validates source state commit failure prevents next tick and S9 state head is explicit |
| Trace store | validates required failure trace events and trace sync recovery/tamper evidence |
| Replay | validates inspect-only replay does not alter adapter/message/artifact counters |
| Message | validates delivery failure and idempotency marker behavior |
| Work order | validates scoped signed work orders for S9 actions/messages |
| Governance | validates circuit breaker and kill switch race fail-closed evidence |

## Trace Behavior

S9 requires trace/audit evidence for:

- `adapter.failed`
- `verifier.unavailable`
- `quota.exceeded`
- `trace.write_failed`
- `state.commit_failed`
- `message.delivery_failed`
- `node.stale`
- `policy.expired`
- `circuit_breaker.tripped`
- `kill_switch.activated`
- `run.paused`
- `run.denied`
- `run.cancelled`

The scenario records these in `trace-export.jsonl` and maps each event to `required_trace_event_ids` in `scenario-report.json`.

## State Behavior

- S9 reads a public state head for the bounded success run.
- S1 source evidence proves forced state commit failure does not advance a next tick.
- Aggregation requires state node IDs and state hashes from S9 plus S1/S4/S5 source evidence.

## Gateway and Verifier Behavior

- Adapter failure is injected with a public daemon action request and must return a failed outcome without fake success.
- Quota pressure is exercised with a signed work order constrained to one action; the later action must deny or require intervention.
- Verifier unavailability/uncertainty evidence must deny or intervene, not allow.
- Circuit breaker and kill switch race evidence must fail closed.

## Replay Behavior

- Replay mode is `inspect_only`.
- `side_effects_allowed_default` is `false`.
- Replay records before/after counters for adapter executions, message duplicates, and external publication count.
- Audit includes bounded retry counts and idempotency markers.

## Failure Behavior

S9 covers adapter failure, verifier unavailability, policy expiry, trace write failure before and after outcomes, state commit failure, remote message transport failure, stale node placement, quota exceeded, circuit breaker race, kill switch race, and telemetry non-authority.

## Tests and Evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| integration | Run public daemon/manager S9 flow | `scenario-report.json`, `api-traffic.ndjson` |
| negative | Validate fail-closed failure matrix | `failure-matrix.json`, `fault-injection-report.json` |
| trace | Required S9 failure event IDs | `trace-export.jsonl`, `required_trace_event_ids` |
| replay | Confirm no replay side effects | `replay-report.json` |
| audit | Bounded retry/idempotency explanation | `audit-report.json`, `quota-retry-report.json`, `idempotency-report.json` |

## Example or Fixture

```bash
bash scripts/e2e/verify-use-case-acceptance.sh --scenario UC-E2E-S9
bash scripts/e2e/verify-use-case-acceptance.sh --all
```

## Future Extension Notes

- S10 should combine S0-S9 into one final journey only after its own executable scenario and strict aggregation checks are added.
- Future runtime-specific fault hooks can replace source-artifact reuse where public daemon/manager APIs expose equivalent failure injection directly.
- S9 intentionally does not weaken S1-S8 requirements; their artifacts must still pass their own loaders before S9 can count.
