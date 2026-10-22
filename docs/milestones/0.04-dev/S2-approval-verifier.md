# 0.04-S2 — Approval Verifier

## 1. Objective

Implement the minimal approval verifier path for Splendor0.04-dev: actions that
match an approval policy pause before adapter execution, runs enter a trace-linked
waiting state, trusted receipts for the exact challenged action permit re-evaluation, and denial,
expiry, revocation, wrong scope, unsupported schema versions, or verifier
uncertainty fails closed.

## 2. Functional scope

- Add approval policy and evidence primitives.
- Add approval verifier outcomes to the gateway verifier chain.
- Add `NeedsApproval` and `NeedsIntervention` action statuses.
- Add daemon `waiting_for_approval`, `denied`, and `expired` run statuses for the
  approval path.
- Retain approval evidence fields as non-authorizing compatibility data and add
  exact challenges plus authority-obligation receipts to action contracts.
- Add trace events for approval request, grant, denial, expiry, and revocation.
- Add inspect-only replay reporting for approval lifecycle events.
- Add Rust and TypeScript/OpenAPI schema coverage for approval contracts.

## 3. Non-goals

- No approval queue UI.
- No human notification system.
- No workflow DSL.
- No escalation engine.
- No circuit breakers.
- No kill-switch propagation.
- No production PKI/OAuth approval service.
- No product-specific Harmony dependency.

## 4. Public contracts changed

- `splendor_types::ApprovalId`
- `splendor_types::ApprovalPolicy`
- `splendor_types::ApprovalEvidence`
- `splendor_types::ApprovalChallenge`
- `splendor_types::ApprovalDecision`
- `splendor_types::ApprovalTraceContext`
- `splendor_gateway::ApprovalVerifier`
- `splendor_gateway::PolicyApprovalVerifier`
- `splendor_gateway::LocalAuthorityObligationVerifier`
- `splendor_gateway::ActionStatus::{NeedsApproval, NeedsIntervention}`
- `splendor_gateway::ActionRequest.approval_evidence`
- `splendor_daemon::CreateRunRequest.approval_policies`
- `splendor_daemon::LifecycleRequest.approval_evidence`
- `splendor_daemon::SubmitActionRequest.approval_evidence`
- `splendor_daemon::SubmitActionRequest.authority_obligation_receipts`
- `splendor_daemon::ReplayResponse.approval_events`
- OpenAPI and TypeScript contracts for the same fields/statuses.

## 5. Runtime primitives touched

- approval
- verifier
- action gateway
- runtime context
- trace store
- replay
- SDK/API
- docs/tests

## 6. Trace events added or changed

Added approval/action lifecycle trace variants:

- `ActionNeedsApproval`
- `ApprovalRequested`
- `ApprovalGranted`
- `ApprovalDenied`
- `ApprovalExpired`
- `ApprovalRevoked`

The daemon records `RunPaused { reason: "waiting_for_approval" }` when a tick
pauses. It records `RunResumed` only after the exact receipt-bearing `/actions`
retry executes successfully; approval does not run a lifecycle resume tick.

## 7. State behavior added or changed

Approval does not introduce hidden mutable agent state. The loop still commits a
state node for ticks according to the existing state graph path. The daemon stores
only the exact pending challenge needed to bind a later action retry. A successful
retry does not create another scheduler tick or state commit. The challenge and
receipt are not replacements for committed state or trace records.

## 8. Verifier/gateway behavior added or changed

The gateway now calls `ApprovalVerifier` before adapter execution:

- missing required approval returns `NeedsApproval`;
- a raw scoped grant remains non-authorizing and requires a trusted receipt;
- a trusted receipt must match the live conditional authority decision and exact
  challenged action, then be atomically claimed before effect;
- explicit denial, wrong scope, unsupported evidence schema, expired evidence, or
  revoked evidence returns `Denied`;
- unsupported policy schema or verifier uncertainty returns `NeedsIntervention`;
- all non-grant outcomes stop before adapter execution.

`ApprovalChallenge` binds tenant, agent, run, action ID/name/payload, effective
adapter, authority subject/decision/obligation, policy, request/action/decision
digests, receipt audience, original request time, and expiry.

## 9. Replay behavior

Replay remains inspect-only. `ReplayResponse.approval_events` reports approval
request/grant/denial/expiry/revocation events with lifecycle label,
`ApprovalTraceContext`, reason, trace event ID, and sequence. Replay never calls
approval services, verifiers, gateways, or adapters.

## 10. Failure behavior

- Missing trusted receipt evidence on a required action pauses with
  `NeedsApproval` and an exact challenge.
- Lifecycle resume from `waiting_for_approval` rejects raw evidence, receipts, or
  missing approval material with stable `409` migration errors and no tick.
- Changed action coordinates, replayed receipt IDs, semantically reissued
  receipts, missing trusted ledger/configuration, or pre-effect trace failure do
  not execute adapters.
- Wrong tenant, agent, run, action, or adapter evidence denies.
- Unsupported approval evidence schema denies; unsupported approval policy schema
  fails closed as intervention.
- Denied or revoked evidence sets a denied action outcome and terminal denied run
  state.
- Expired evidence sets a denied action outcome and terminal expired run state.
- Expired approval policies or verifier uncertainty fail closed as intervention.

## 11. Test evidence

Targeted tests added/updated:

- Gateway approval required path skips adapter execution.
- Gateway valid grant executes after re-verification.
- Gateway wrong tenant/agent/run/action/action-id/adapter scope, unsupported schema,
  denial, expiry, revocation, and verifier uncertainty fail closed without adapter
  execution.
- Daemon approval-required run enters `waiting_for_approval` and records trace
  linkage.
- Daemon exact trusted receipt retry executes one adapter call, records resume,
  and cannot be reused.
- Daemon raw grant, denial, expiry, wrong scope, unsupported schema, and revocation do not
  execute adapters.
- Replay reports `requested`, `granted`, `denied`, `expired`, and `revoked`
  approval events.
- OpenAPI/TypeScript schema parity covers new fields and statuses.

## 12. Example commands or fixtures

See [`examples/action-approval-flow/README.md`](../../../examples/action-approval-flow/README.md).

Useful validation commands:

```bash
cargo test -p splendor-gateway
cargo test -p splendor-daemon
npm test
```

## 13. Future extension notes

Future governance work should reuse the exact challenge, trusted receipt,
trace context, and replay representation. Escalations, circuit breakers,
kill-switches, and external approval control-plane adapters must remain
trace-linked and must not authorize side effects outside the gateway.
