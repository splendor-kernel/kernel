# Local Delegation Reference

Sprint 0.02-S4 implements a local-only delegation primitive: a parent run may
create a child run for a named local specialist agent with a scoped objective,
legacy `DelegatedAuthority` restrictions, and `AUTH-003b` authority-backed child
grant issuance. It is implemented in Rust as
`splendor_kernel::LocalDelegationManager` with canonical task message payloads in
`splendor_types`.

## Purpose

Local delegation lets an orchestrator coordinate named agents inside one
Splendor instance without permission laundering. A child run does not inherit the
parent run's tenant, agent, adapter, or action authority. The child agent context
returned by `LocalDelegationManager::create_child_run` carries a
`DelegatedAuthority`; the loop engine denies actions outside that legacy
compatibility scope before an adapter can execute. The child run is created only
after the manager calls `splendor_authority::issue_delegation_child_grant` with a
trusted parent `ValidatedCapabilityGrant`; task messages and metadata alone do
not confer authority.

Delegating root runs require a separate trusted manager binding. Registration by
itself remains valid for non-delegating compatibility, but it does not authorize
child creation.

## Public contracts

### TaskRequest (`splendor.message.task_request.v1`)

```json
{
  "parent_run_id": "run_parent",
  "child_run_id": "run_child",
  "target_agent_id": "agent_specialist",
  "objective": "summarize receivables",
  "delegated_authority": {
    "allowed_actions": ["sql.query"],
    "allowed_adapters": ["sql"],
    "allowed_permissions": ["finance.read"]
  },
  "authority_evidence": {
    "schema_version": "splendor.message.local_delegation_authority_evidence.v1",
    "parent_capability_grant_id": "grant_parent",
    "child_capability_grant_id": "grant_child"
  }
}
```

`authority_evidence` is optional for compatibility and non-authorizing. Runtime
child-run creation records it only after the authority-backed path has a trusted
parent grant and issued child grant. A forged or standalone task payload with
grant IDs is behavior-free data, not authority.

Validation fails closed when:

- `parent_run_id`, `child_run_id`, or `target_agent_id` is missing/nil;
- `child_run_id` equals `parent_run_id`;
- `objective` is empty or whitespace;
- payload `parent_run_id` does not match the enclosing message `run_id`;
- payload `target_agent_id` does not match the enclosing message target.

### TaskResponse (`splendor.message.task_response.v1`)

```json
{
  "parent_run_id": "run_parent",
  "child_run_id": "run_child",
  "status": "failed",
  "output": null,
  "failure": {
    "code": "specialist_failed",
    "reason": "specialist policy failed",
    "retryable": false,
    "trace_id": "trace_child_failure"
  }
}
```

`status` values are `completed`, `failed`, `denied`, and `cancelled`.
Failed, denied, and cancelled responses require a structured `failure` with a
non-empty `code` and `reason`; completed responses must not include a failure.

### DelegatedAuthority

```json
{
  "allowed_actions": ["sql.query"],
  "allowed_adapters": ["sql"],
  "allowed_permissions": ["finance.read"]
}
```

Empty lists mean no legacy compatibility authority. Delegated authority remains a
local restriction profile: it must be a subset of both the parent run's active
authority and the target agent's registered authority, but it is not standalone
capability authority. Child actions must name an explicit adapter from
`allowed_adapters`; gateway default adapter selection does not satisfy delegated
authority and fails closed before gateway submission.

## Lifecycle

1. Register local agents, principal bindings, and maximum delegation authority.
2. Register an active parent run for the orchestrator agent; the run snapshots the
   registered parent principal. The root is intentionally unbound at this point.
3. Build `LocalDelegationAuthority` from a trusted parent
   `ValidatedCapabilityGrant`, target child principal, audience, and child grant
   refs.
4. Call
   `bind_root_run_capability_grant(&parent_run_id, &authority.parent_capability_grant)`.
   The subject must match the root principal snapshot. The manager privately
   retains the exact `ValidatedCapabilityGrant`, including its trust marker.
   Same-run retry is idempotent only for exact equality; the binding cannot be
   replaced or reused for another run in that manager.
5. Call `create_child_run(parent_recorder, child_recorder, request, authority)`
   with an explicit target agent, child run ID, objective, and delegated
   authority.
6. The manager verifies the supplied trusted grant ID equals the parent-run
   binding, re-checks the grant subject against the registered principal, and
   issues an authority-owned child grant at the current decision time. If
   validation or issuance fails, it emits `DelegationRejected` and does not emit
   `DelegationRequested`, route a task message, insert a child record, or start a
   child run.
7. On success, the manager records `DelegationRequested`, sends a task request
   message carrying non-authorizing grant refs, emits `ChildRunStarted`, and
   returns a scoped child `AgentContext`. The child record retains the issued
   child grant ID for evidence and revocation checks; it does not expose the
   validated child grant as recursive delegation authority.
8. The child loop uses that scoped context. Actions outside delegated authority
   are denied and do not reach adapter execution.
9. The child completes or fails through `complete_child_run` or `fail_child_run`,
   which sends a structured task response and emits parent/child completion or
   failure trace events.
10. Completion, failure, denial, and cancellation are terminal for the child run;
   repeated finish attempts fail closed without emitting duplicate responses or
   duplicate completion/failure trace events.

## Trace events

Local delegation uses the existing message lifecycle events plus these trace
events:

| Rust variant | Canonical event class | Purpose |
| --- | --- | --- |
| `DelegationRequested` | `delegation.requested` | Parent run requested child work. |
| `DelegationRejected` | `delegation.rejected` | Delegation failed closed before child execution. |
| `ParentRunCancelled` | `run.cancelled` | Parent run cancellation prevents new delegation. |
| `ChildRunStarted` | `run.child_started` | Child run started and references the parent causal trace. |
| `ChildRunCompleted` | `run.child_completed` | Child run completed and parent run references the response. |
| `ChildRunFailed` | `run.child_failed` | Child run failed with a structured `TaskFailure`. |

All delegation events carry `LocalDelegationTraceContext` with parent/child run
IDs, source/target agent IDs, objective, parent causal trace, task
request/response message IDs when available, and optional non-authorizing
`LocalDelegationAuthorityEvidence` refs. Denied authority issuance may record a
stable `authority_reason` such as `overbroad_operation` or
`missing_authority_evidence`. Root binding denials use the exact stable reasons
`missing_parent_run_grant_binding` and `parent_run_grant_mismatch`. Proposed
child grant-ID reuse records `child_capability_grant_id_collision`.

`LocalDelegationReplay.rejections` preserves each `DelegationRejected` context
and stable reason. Replay remains inspect-only and introduces no authority or
side effects.

## State behavior

0.02-S4 adds parent/child run metadata in the local delegation manager, including
the run-bound principal, issued child `CapabilityGrantId`, and parent/child grant
refs for successful children. It does not add hidden shared state between parent
and child agents. Agent state remains committed through normal state graph nodes
by each loop engine.

For a delegating root, `capability_grant_id` is populated only by the explicit
trusted binding API and remains evidence only. The manager separately retains the
exact validated grant privately. Binding denials and child-creation denials leave
the full run record unchanged, including child fan-out and delegated authority.
The manager has no separate mutable budget/depth consumption ledger; those
limits remain immutable fields on validated grants and issued child grants.

Successful child records are automatically bound to the issued child grant ID
for evidence and revocation. This is not an authorizing grant retrieval surface.
Recursive local delegation is unsupported: the exact issued child grant is
scoped to the existing child agent/run, so a distinct grandchild agent/run fails
authority narrowing with `overbroad_scope`. Callers must not inject a different,
broader grant to bypass that scope; its ID will not match the child record.

## Gateway and verifier behavior

The child run's scoped `AgentContext` acts as a local authority constraint before
gateway submission. If a child policy proposes an action outside
`DelegatedAuthority`, or omits the adapter needed to evaluate that authority, the
loop engine records normal verification/denial trace events and does not call the
gateway adapter path. Allowed child actions still go through the Action Gateway
and its verifier chain.

## Replay behavior

`splendor_kernel::replay_local_delegations(events)` reconstructs parent/child
relationships and task request/response message exchange from trace events. It
also reconstructs recorded authority grant refs. It does not invoke policies,
gateways, adapters, child runs, authority evaluation, or side effects.

## Failure behavior

- Unbound registered root attempts delegation: exactly one `DelegationRejected`
  with `missing_parent_run_grant_binding`; no request, routing, child start,
  insertion, or fan-out mutation.
- Supplied trusted parent grant ID differs from the immutable root binding:
  exactly one `DelegationRejected` with `parent_run_grant_mismatch` and the same
  zero-effect behavior.
- Supplied trusted parent grant reuses the bound ID but differs in any validated
  content or trust state: `parent_run_grant_mismatch` with the same zero effects.
- Root binding with a grant subject different from the run principal:
  `ParentRunGrantSubjectMismatch`.
- Different grant for an already-bound root:
  `ParentRunGrantBindingConflict`.
- Same grant ID for another root in the same manager:
  `CapabilityGrantRunBindingConflict`.
- Proposed child grant ID collides with any root or child exact binding in the
  same manager: exactly one `DelegationRejected` with
  `child_capability_grant_id_collision` before request/routing/start/insertion or
  fan-out effects.
- Explicit binding of an existing child record:
  `ParentGrantBindingRequiresRootRun`; successful children are already bound.
- Missing or mismatched target/objective: structured message validation failure.
- Delegated authority exceeds parent or target scope: `DelegationRejected` and no
  child run.
- Missing or invalid runtime authority evidence: `DelegationRejected` and no
  child run. Message payload evidence alone is ignored as authority.
- Parent grant subject mismatch with the registered parent principal:
  `DelegationRejected` and no child run.
- Authority child-grant issuance denial (for example overbroad operation, scope,
  budget, fan-out, expiry, not-yet-valid grant window, or role restriction):
  `DelegationRejected` before `DelegationRequested`, task routing, and child
  insertion.
- Duplicate `child_run_id`: `DelegationRejected` with
  `duplicate_child_run_id`; no second task request, child state, or child-start
  trace.
- Delegated child action omits an adapter: `ActionDenied` with
  `delegated_adapter_unspecified`; no gateway call.
- Parent run cancelled: `DelegationRejected` and no task request message.
- Child failure: `TaskResponse { status: failed, failure: TaskFailure }` plus
  `ChildRunFailed` trace events.
- Repeated completion/failure after a terminal child status:
  `ChildRunAlreadyFinished`; no duplicate response message or terminal trace.

## Compatibility notes

`register_root_run` remains source-compatible and supports non-delegating roots,
but delegating callers must now explicitly bind a trusted grant before
`create_child_run`. This is an intentional fail-closed local Rust API/security
tightening. It adds no serialized grant/message/trace schema and no daemon,
Python, or TypeScript contract.

The additive `LegacyMultiScopeProfile` and
`grant_from_legacy_multi_scope_allowlists` authority compatibility builder allow
one parent grant to cover explicit non-empty lists of local child agent and run
IDs. They use the existing local-profile validator; nil identities, empty lists,
invalid audiences, and wildcard-like broad audience input fail closed.

The bounded `AUTH-007c` matrix uses the public manager/authority/router/trace path
and covers tenant, parent agent/shared-principal, parent principal/run, child
agent/run, audience, and unrelated grant/evidence replay. The message target is
the request target and is therefore covered with child-agent mismatch. The API
does not independently accept a response recipient, and it has no typed instance
authority coordinate beyond the audience string; those gaps are recorded rather
than bypassed.

Grant-ID uniqueness is local to one `LocalDelegationManager`. The different-
tenant matrix case uses an isolated manager only to exercise the validated
grant's tenant scope; it is not cross-manager, cross-instance, or typed audience
binding evidence.

`bind_root_run_capability_grant` is trusted local run-admission setup. It does not
currently emit a durable binding trace event because adding an event variant
would expand the public trace schema. Child-creation denials remain durably
represented by the existing `DelegationRejected` event when recording succeeds.

The implementation remains local-only `AUTH-003b`/`AUTH-007c` wiring. It
deliberately does not introduce signed work orders, remote dispatch, fleet
placement, child revocation propagation, gateway authority verification, or
long-lived child services. Later
cross-instance work orders can map onto the same explicit fields without changing
the local no-ambient-authority rule. G18/G70/G71 remain `not_exercised` unless
their executable gold fixtures are added and pass.
