# Runtime Loop Reference

The 0.01-dev runtime loop is local-only and single-instance. It strengthens the
core Splendor model:

```text
Percepts -> Policy -> Constraints -> Gateway -> Adapter -> Outcome -> State Commit -> Trace
```

## Lifecycle

0. `RunStarted` starts a new persisted run trace stream.
1. `LoopTickStarted` starts the tick.
2. Registered `Perceptor` implementations collect `Percept` values. The
   Gateway-owned persisted-percept guard screens schema, payload, and provenance
   under one budget before any percept trace or policy invocation.
3. `PerceptsReceived` records only the screened percept batch.
4. `StateLoaded` records the state hash available to policy.
5. `PolicyInvoked` records policy entry.
6. The `Policy` callback receives current state and percepts and returns action
   candidates plus next state.
7. The policy-selected next-state bytes, content type, and optional state label
   are screened under one budget before any action, outcome, or state
   persistence. Declared JSON/text ambiguity, a match, or scanner failure fails
   the tick; genuinely opaque binary remains compatible without an
   encrypted/compressed absence claim.
8. `PolicyCompleted` records successful policy return.
9. The Gateway-owned raw credential guard screens every candidate before any
   candidate/action payload trace, constraint callback, delegated-authority
   evaluation, or gateway submission. Screening includes raw obligation-receipt
   strings without interpreting those receipts as authority. Each candidate
   receives its `ActionId` at this boundary.
10. `CandidatesProposed` records safe actions unchanged and raw-credential
   denials only as the constant suppression projection.
11. The `ConstraintEngine` returns an aggregate `VerificationResult` over only
   credential-free candidates.
12. Each projected/safe action records verification start in original policy
    order.
13. If constraints allowed the tick, `VerifiedActionGateway` checks tenant policy,
    adapter allowlists, permissions, quotas, invariants, and action preconditions.
14. Only verified credential-free actions reach registered adapters.
15. Immediately after adapter return, output and satisfied-postcondition strings
    pass the Gateway-owned persistence barrier before post-verifiers. Unsafe or
    ambiguous output becomes fixed `Failed` / `raw_credential_output_suppressed`
    with no output; adapter entry means no rollback or no-effect claim is made.
16. If an optional 0.04-S3 escalation policy is configured, explicit
    verifier/runtime facts can produce `EscalationTriggered` and
    `ActionNeedsIntervention` trace events before final outcome recording.
17. Safe adapter output, denial, failure, or intervention need is recorded as an
    action outcome.
18. The outcome evaluator can attach feedback/reward for credential-free
    candidates; it is not invoked with a denied raw action.
19. The state graph commits the already-screened next state node and optional
    snapshot.
20. Trace records are appended in order.

## Identity scope

- `tenant_id`: tenant policy/quota boundary.
- `agent_id`: local agent runtime context.
- `run_id`: ordered trace stream and replay scope.
- `tick_id`: loop cycle identifier.
- `action_id`: assigned per proposed action before gateway submission.
- `state_node_id`: content-addressed committed state node.
- `trace_event_id`: deterministic ID from run ID and trace sequence.

Each emitted trace event also carries `identity.run_id` and optional tenant,
agent, tick, action, state, message, fleet, node, and instance identity fields as
documented in [`identity.md`](identity.md).

## Failure behavior

- Perceptor/policy errors return a loop error and do not execute actions.
- Credential-bearing percepts return fixed `raw_credential_input_denied` before
  `PerceptsReceived`; credential-bearing/ambiguous policy state returns the same
  fixed error before `PolicyCompleted`, action execution, outcome recording, or
  state commit.
- Raw credential-bearing candidates return the fixed
  `raw_credential_input_denied` outcome. They skip constraints, delegated
  authority, gateway/adapters, escalation, and outcome evaluation. Their
  `CandidatesProposed`, verification-started/completed, and `ActionDenied`
  records contain only the constant safe projection.
- In a mixed decision, safe and denied candidates retain original policy order;
  safe candidates continue through constraints/gateway independently while the
  raw candidate remains denied.
- Constraint denial records action denial and skips gateway submission.
- Gateway verifier denial records action denial and skips adapter execution.
- Escalation policies consume explicit verifier/runtime facts. Verifier
  uncertainty and quota pressure fail closed as denial or intervention outcomes;
  escalation does not execute adapters, contact ticket systems, or install
  circuit breakers.
- Adapter failure records a failed/denied outcome.
- Credential-bearing or ambiguous adapter output records a fixed failed outcome
  with no output. It does not imply that the already-entered adapter had no
  effect and must not be blindly retried.
- State commit failure prevents `StateCommitted` and `LoopTickCompleted` from
  being emitted for that tick.
- Trace store failure fails the tick before side-effectful work can proceed when
  the event is required before execution.

## Out of scope for 0.01-dev

- Typed messages and local multi-agent routing.
- Daemon API and TypeScript client.
- Work orders, fleet identity, remote transport, and trace aggregation.
- Governance approval workflows and physical/edge safety APIs.
