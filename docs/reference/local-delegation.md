# Local Delegation Reference

Sprint 0.02-S4 implements a local-only delegation primitive: a parent run may
create a child run for a named local specialist agent with a scoped objective,
legacy `DelegatedAuthority` narrowing projections, and authority-owned AUTH-003
chain validation, child issuance, and accounting. It is implemented in Rust as
`splendor_kernel::LocalDelegationManager` with canonical task message payloads in
`splendor_types`.

## Purpose

Local delegation lets an orchestrator coordinate named agents inside one
Splendor instance without permission laundering. A child run does not inherit the
parent run's tenant, agent, adapter, or action authority. The child agent context
returned by `LocalDelegationManager::create_child_run` carries a
an exact validated child grant plus `DelegatedAuthority`; the loop engine requires
the issued grant reference and applies the legacy projection only as a further
restriction before an adapter can execute. The child run is created only
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
6. The manager verifies the complete supplied `ValidatedCapabilityGrant`,
   including its private trust state, exactly equals the manager-private
   parent-run binding, re-checks the grant subject against the registered
   principal, and issues an authority-owned child grant at the current decision
   time. If validation or issuance fails, it emits `DelegationRejected` and does
   not emit `DelegationRequested`, route a task message, insert a child record,
   or start a child run.
7. The authority ledger atomically reserves immutable fan-out and every bounded
   budget component. Root and child fan-out caps are authority-owned (currently
   16 locally); caller values do not set or change that cap. Direct sibling
   reservations must fit component-wise inside their parent allocation.
8. On success, the manager records `DelegationRequested`, sends a task request
   message carrying non-authorizing grant refs, emits `ChildRunStarted`, and
   returns a scoped child `AgentContext`. The child record retains the issued
    complete ordered `DelegationChain`, issued child grant, cleanup obligations,
    and budget reservation evidence. The issued grant may recursively create a
    narrower local child while remaining depth is non-zero.
9. Every child action must carry the exact issued child grant ID. Missing, wrong,
   expired, revoked, over-budget, or out-of-scope evaluation denies before the
   gateway; the legacy projection can only narrow an authority allow.
10. The child completes or fails through `complete_child_run` or `fail_child_run`,
   which sends a structured task response and emits parent/child completion or
   failure trace events.
11. Terminal completion performs explicit ledger cleanup. Parent cancellation and
    parent/child grant revocation invalidate and cancel active descendants.
12. Completion, failure, denial, and cancellation are terminal for the child run;
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
`LocalDelegationAuthorityEvidence` refs. The additive optional
`delegation_ledger` field carries the complete ordered chain, reserved budget,
authority-owned fan-out cap, lifecycle status, and stable reason. Denied authority issuance may record a
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
The authority crate owns the only mutable local delegation ledger. It stores exact
validated roots and immutable ordered child edges and atomically accounts direct
subtree fan-out and budget. Kernel run records project this state but do not own
or independently authorize it.

Successful child records are automatically bound to the issued validated child
grant and full chain. Recursive local delegation is supported only through that
exact grant, for descendant identities already in trusted parent scope, and while
depth, time, role, fan-out, and aggregate subtree budget remain narrower.

## Gateway and verifier behavior

The child run's scoped `AgentContext` evaluates the exact issued grant before
gateway submission. If a child policy omits or changes the grant reference,
proposes an action outside that grant or its `DelegatedAuthority` projection, or
omits the adapter needed to evaluate that authority, the
loop engine records normal verification/denial trace events and does not call the
gateway adapter path. Allowed child actions still go through the Action Gateway
and its verifier chain.

## Replay behavior

`splendor_kernel::replay_local_delegations(events)` reconstructs parent/child
relationships, task messages, complete chains, reservation/commit/release/
fail-safe-consume transitions, cleanup, failures, and revocation. It does not
route messages, start children, invoke authority, submit gateway actions, or
execute adapters.

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
- Aggregate budget overflow: `aggregate_budget_exceeded_<dimension>` before
  routing. Concurrent excess fan-out receives `fan_out_exceeded` atomically.
- Pre-routing failure releases the reservation; start uncertainty after routing
  consumes it fail-safe. Both transitions are replay-visible.
- Nested widening identifies the first failing edge as
  `delegation_chain_edge_<index>_<reason>`.
- Missing/wrong child action grant references deny before the gateway.
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

The two lists are independent `CapabilityScope` set dimensions. Containment is
Cartesian: any listed agent may be combined with any listed run, and vector index
positions do not define paired delegation edges. Authority issuance tests prove
that listed combinations succeed while an unlisted agent or an unlisted run
separately denies with `overbroad_scope`. A typed paired agent/run edge contract
is explicitly deferred; callers that need pairing must enforce a separate
narrower contract rather than infer pairs from list ordering.

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

The implementation completes the authority-owned non-gold local AUTH-003 chain,
accounting, recursive delegation, action binding, cleanup, revocation, and replay
path. It deliberately does not introduce Message Service/Agent Controller
adoption, remote dispatch, fleet placement, durable/cross-instance ledger
storage, or long-lived child services. Later
cross-instance work orders can map onto the same explicit fields without changing
the local no-ambient-authority rule. G18/G70/G71 remain `not_exercised` unless
their executable gold fixtures are added and pass. No gold command was run.
