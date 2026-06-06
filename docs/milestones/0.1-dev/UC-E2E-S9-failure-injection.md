# UC-E2E-S9 — Failure Injection, Quotas, Bounded Retry, and Fail-Closed Behavior

## Objective

Validate the post-implementation acceptance path for deterministic runtime failures. UC-E2E-S9 strengthens quota, verifier, gateway, adapter outcome, trace store, state graph, retry, message delivery, fleet telemetry/placement, governance, replay/audit, and docs/tests by proving failures are denied, paused, cancelled, or recorded rather than converted into allow.

## Functional Scope

- Adds `tests/e2e/use-cases/scenarios/uc_e2e_s9_failure_injection/run.py` as the S9 scenario runner.
- Drives public daemon and manager HTTP APIs for run creation, gateway action submission, quota pressure, adapter failure, remote message failure, approval denial/resume, circuit-breaker sync, kill-switch activation, stale placement, trace sync recovery, state read, trace export, fleet telemetry/audit reads, and inspect-only replay.
- Exercises trace-store and state-store failure injection through public `splendorctl run --config` invocations, then exports the resulting trace-store evidence with `splendorctl trace export`.
- Reuses prior public S5 source trace evidence only for `policy.expired`; S1 and S4 remain prerequisite source scenarios whose own loaders must pass before S9 can aggregate.
- Updates `scripts/e2e/verify-use-case-acceptance.sh` so `--scenario UC-E2E-S9` pre-runs required source scenarios and `--all` includes S0-S9.
- Updates `aggregate_report.py` so S9 is rejected unless machine-readable positive, negative, replay, trace, state, API, retry, idempotency, audit, provenance, and anti-drift evidence exists.

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
| State graph | validates S9 public state commit failure evidence prevents the next tick and S9 state head is explicit |
| Trace store | validates S9 public trace write failure evidence, required failure trace events, and trace sync recovery/tamper evidence |
| Replay | validates inspect-only replay does not alter adapter/message/audit/artifact counters read through public APIs |
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

The scenario records required S9 evidence as `required_event_evidence`, and the aggregator derives `required_trace_event_ids` from those provenance rows. Accepted sources are limited to:

- S9 runtime trace export (`trace-export.jsonl`) for gateway/runtime events.
- Manager audit export (`manager-audit-export.json`) for remote message, placement, circuit breaker, and kill-switch events.
- Source runtime trace export (`UC-E2E-S5/trace-export.jsonl`) for `policy.expired`.

Synthetic, manual, static, scenario-self-attested, or UUID-only rows are rejected.

## State Behavior

- S9 reads a public state head for the bounded success run.
- A public `splendorctl run --config` state-commit failure fixture appends `state.commit_failed` evidence before returning failure.
- Aggregation requires state node IDs and state hashes from S9 plus prerequisite source evidence.

## Gateway and Verifier Behavior

- Adapter failure is injected with a public daemon action request and must return a failed outcome without fake success.
- Quota pressure is exercised with a signed work order constrained to one action; the later action must deny or require intervention.
- Verifier unavailability/uncertainty evidence must deny or intervene, not allow.
- Circuit breaker and kill switch race evidence must fail closed.

## Replay Behavior

- Replay mode is `inspect_only`.
- `side_effects_allowed_default` is `false`.
- Replay records before/after counters for adapter executions, message state, manager audit event count, and external publication count; S9 verifies the first three are read through public daemon/manager APIs.
- Audit includes bounded retry counts and idempotency markers.

## Failure Behavior

S9 covers adapter failure, verifier unavailability, policy expiry, trace write failure before and after outcomes, state commit failure, remote message transport failure, stale node placement, quota exceeded, circuit breaker race, kill switch race, and telemetry non-authority.

## Tests and Evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| integration | Run public daemon/manager S9 flow | `scenario-report.json`, `api-traffic.ndjson` |
| negative | Validate fail-closed failure matrix | `failure-matrix.json`, `fault-injection-report.json` |
| trace | Required S9 failure event IDs | `trace-export.jsonl`, `required_trace_event_ids` |
| provenance | Required S9 failure event provenance | `required_event_evidence`, `manager-audit-export.json`, source `trace-export.jsonl` |
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
