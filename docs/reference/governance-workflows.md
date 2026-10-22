# Governance Workflows

0.04-S2 implements the first governance workflow slice: approval-required actions
pause through the gateway verifier and continue only when the exact action is
retried with a valid scoped receipt. This reference intentionally describes the implemented approval path and
marks later governance features as future work.

## Implemented in 0.04-S2

- Approval policies can mark scoped actions as approval-required.
- The action gateway returns `NeedsApproval` before adapter execution when
  a trusted receipt is missing and includes an exact non-authorizing challenge.
- The daemon maps approval-required tick outcomes to `waiting_for_approval` and
  records a trace-linked pause.
- Lifecycle resume from `waiting_for_approval` is rejected without running a
  tick. The caller must retry the exact challenged action through `/actions`.
- The manager may issue a receipt only from the recorded exact challenge. Raw
  granted `ApprovalEvidence` remains non-authorizing compatibility data.
- A valid exact receipt allows the action to be re-evaluated and executed once by
  the gateway after every other required verifier passes.
- Denial, expiry, revocation, wrong-scope evidence, unsupported approval schema,
  or verifier uncertainty fails closed without adapter execution.
- An exact pending `/actions` retry may carry raw denied evidence without a
  receipt. It is evaluated by the approval verifier, records terminal denial and
  replay evidence, and never calls the adapter; raw grants remain non-authorizing.
- Manager approval records distinguish `requested_by` from `decided_by`, retain
  `issued_by` for compatibility, and allow an absent/null risk only when the exact
  challenge also has no risk label.
- The challenge/receipt binds action ID and payload, effective adapter, tenant,
  agent, run, authority subject/decision/obligation, policy, original request
  time, expiry, receipt audience, and integrity digests. Changed scope is not a
  wildcard grant and receipt reuse is denied.
- Replay exposes approval lifecycle events without re-running verifiers or
  adapters.

## Explicit non-goals for this sprint

- No approval queue UI.
- No human notification system.
- No workflow DSL.
- No escalation engine.
- No circuit breakers.
- No kill-switch propagation.
- No policy TTL distribution beyond local approval-policy expiry checks.
- No product-specific Harmony dependency inside the kernel.

## Runtime loop impact

Approval is inserted into the existing loop at the verifier/gateway boundary:

```text
Percepts
  -> Policy proposes action
  -> Constraints evaluated
  -> Action Gateway
  -> Approval policy creates exact conditional obligation
  -> other verifier checks and final live-authority check
  -> Trusted receipt validation, exact match, and atomic one-use claim
  -> Adapter only if all verifiers allow
  -> Outcome
  -> State Commit
  -> Trace
```

The approval verifier does not execute side effects. It only classifies whether
the action may continue, must pause, is denied, or needs intervention.

## Run and action outcomes

Action statuses added for governance:

- `NeedsApproval`: approval is required and execution is paused.
- `NeedsIntervention`: a verifier/runtime boundary failed closed and operator or
  runtime intervention is required.

Daemon run statuses added for the approval path:

- `waiting_for_approval`: run paused after an approval-required action.
- `denied` / `expired`: retained fail-closed statuses for legacy denial,
  revocation, wrong-scope, or expiry facts. Raw evidence never permits execution.

## Approval lifecycle trace events

Governance decisions are trace-linked:

- `ActionNeedsApproval`
- `ApprovalRequested`
- `ApprovalGranted`
- `ApprovalDenied`
- `ApprovalExpired`
- `ApprovalRevoked`
- `RunPaused { reason: "waiting_for_approval" }`
- `RunResumed { reason }`

These events are ordered in the run trace and include approval/action/run identity
through `TraceIdentityContext` and `ApprovalTraceContext`.

## Replay and audit

Replay explains the approval path from trace records:

- why approval was requested;
- which approval grant, denial, unsupported schema, expiry, or revocation was
  presented;
- the trace event ID and sequence for each approval lifecycle event;
- whether adapter execution remained suppressed until a trusted receipt was
  validated and claimed.

Replay does not execute adapters, re-submit actions, re-deliver notifications,
call approval services, or mutate run state.

## Future governance work

Later 0.04 sprints will add broader governance primitives such as escalation
policies, circuit breakers, policy TTL distribution, kill-switch propagation, and
external control-plane adapters. Those features must build on this same verifier,
gateway, trace, and replay boundary rather than bypassing it.
