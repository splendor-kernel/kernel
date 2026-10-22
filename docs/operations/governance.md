# Operating Governance Flows

This guide covers approval, denial, escalation, and circuit-breaker operation for
the 0.1 stable primitive line. Governance removes or pauses authority; it does not
create an approval UI, notification product, workflow engine, or side-effect path
around the Action Gateway.

## Maturity And Limits

- Required adapter maturity: `governance-aware` for actions that participate in approvals, interventions, circuit breakers, policy TTL, or audit/replay explanation.
- Stable primitives: `Approval`, governance trace events, `ActionStatus::NeedsApproval`, `ActionStatus::NeedsIntervention`, circuit-breaker evidence, replay/audit explanation.
- Limitations: no universal approval UI, incident automation platform, billing/admin SaaS, product-specific Harmony dependency, or adapter execution from approval evidence alone.

## Setup

Run the test-backed governance checks:

```bash
cargo test -p splendor-daemon --test runtime_daemon_api_tests approval_required_run_pauses_and_exact_receipt_retry_executes_once
cargo test -p splendor-daemon --test runtime_daemon_api_tests legacy_approval_variants_cannot_resume_tick_or_execute_adapter
cargo test -p splendor-kernel quota_pressure_escalates_without_consuming_denied_usage
cargo run -p splendorctl -- run --config examples/circuit-breaker-basic/config.yaml --cycles 1
```

Use the examples:

- `examples/action-approval-flow/README.md`
- `examples/escalation-basic/README.md`
- `examples/circuit-breaker-basic/README.md`
- `examples/governance-audit-export/README.md`

## Approval Flow

1. Configure an `ApprovalPolicy` for a scoped action, adapter, permission, side-effect class, tenant, agent, or risk level.
2. The policy proposes an action.
3. The Action Gateway runs the approval verifier before adapter execution.
4. Missing trusted receipt evidence returns `NeedsApproval` with an exact
   `ApprovalChallenge`, records `ActionNeedsApproval` and `ApprovalRequested`, and
   pauses the run as `waiting_for_approval`.
5. Submit the complete challenge to the trusted approval manager. A raw granted
   `ApprovalEvidence` remains non-authorizing compatibility/replay data.
6. Copy the manager-issued `AuthorityObligationReceipt` into an exact `/actions`
   retry. Do not use lifecycle resume for successful approval.
7. The gateway regenerates the live conditional decision, validates/matches and
   claims the receipt, then still requires tenant, permission, adapter, quota,
   precondition, safety, and postcondition checks before one execution.

## Denial Flow

Denial evidence, expired evidence, revoked evidence, wrong tenant/agent/run/action/adapter scope, or unsupported evidence schema fails closed. The gateway returns `Denied`, the adapter is not called, and trace records approval denial, expiry, or revocation evidence.

Expected denial evidence appears in:

```text
approval.denied | approval.expired | approval.revoked
action.denied
outcome.recorded
```

## Escalation Flow

1. Configure an `EscalationPolicy` with a trigger, scope, threshold, decision, and reason.
2. Runtime/gateway facts such as quota pressure, verifier uncertainty, approval timeout, policy expiry, safety risk, or repeated adapter failure produce observations.
3. The evaluator emits `escalation.triggered` when a threshold is reached.
4. The resulting decision can deny, pause, or require intervention without bypassing the gateway.

The reference quota-pressure check is:

```bash
cargo test -p splendor-kernel quota_pressure_escalates_without_consuming_denied_usage
```

## Circuit Breaker Flow

1. Configure a tripped breaker with explicit scope such as global, fleet, node, instance, tenant, agent, adapter, action, or action class.
2. The gateway evaluates matching breakers before adapter execution.
3. Matching tripped breakers return `ActionStatus::Denied` with `circuit_breaker_tripped` evidence.
4. The adapter is not called and replay can explain the breaker denial from trace artifacts.

Run the local breaker fixture:

```bash
cargo run -p splendorctl -- run --config examples/circuit-breaker-basic/config.yaml --cycles 1
cargo run -p splendorctl -- replay --db examples/circuit-breaker-basic/trace.db --state-db examples/circuit-breaker-basic/state.db --run 44444444-4444-4444-4444-444444444444
```

## Trace And State Inspection

Governance trace events include:

```text
action.needs_approval
action.needs_intervention
approval.requested
approval.granted
approval.denied
approval.expired
approval.revoked
escalation.triggered
circuit_breaker.tripped
circuit_breaker.cleared
run.paused
run.resumed
```

Replay is inspect-only. It explains approval, denial, escalation, and circuit-breaker evidence without re-running verifiers, calling approval systems, clearing breakers, notifying humans, or executing adapters.

## Failure Handling

- Approval verifier uncertainty returns `NeedsIntervention`.
- Lifecycle resume from `waiting_for_approval` returns a stable `409` migration
  code (`legacy_approval_evidence_non_authorizing`,
  `approval_receipt_resume_not_supported`, or
  `approval_exact_action_retry_required`) before a tick runs.
- Changed exact-action bindings and reused or semantically reissued receipts fail
  closed without another adapter call.
- Expired or unsupported approval policy requires intervention.
- Unknown circuit-breaker runtime scope fails closed when identity is missing.
- Escalation policy validation rejects unsupported schema versions and zero thresholds.
- Governance checks never grant broad permissions or work-order authority.

## Teardown

Remove circuit-breaker example output if the local fixture was run:

```bash
rm -f examples/circuit-breaker-basic/trace.db examples/circuit-breaker-basic/state.db examples/circuit-breaker-basic/data/blocked.txt
```

## References

- `docs/reference/governance-workflows.md`
- `docs/reference/approval-verifier.md`
- `docs/reference/escalation-policies.md`
- `docs/reference/circuit-breakers.md`
- `docs/reference/governance-replay.md`
- `docs/reference/audit-export.md`
