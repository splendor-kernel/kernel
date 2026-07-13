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
returned by `LocalDelegationManager::create_child_run` carries an opaque live
authority handle plus `DelegatedAuthority`; it does not expose or copy the
validated child grant. The loop engine requires the issued grant reference,
re-evaluates the live ledger-owned authority, and applies the legacy projection
only as a further restriction before an adapter can execute. The child run is
created only after the manager calls
`splendor_authority::issue_delegation_child_grant` with a
trusted parent `ValidatedCapabilityGrant`; task messages and metadata alone do
not confer authority.

Delegating root runs require a separate trusted manager binding. Registration by
itself remains valid for non-delegating compatibility, but it does not authorize
child creation.

## Public contracts

### TaskRequest (`splendor.message.task_request.v2`)

```json
{
  "parent_run_id": "run_parent",
  "child_run_id": "run_child",
  "target_agent_id": "agent_specialist",
  "objective": "summarize receivables",
  "capability_grant_id": "grant_child",
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

`capability_grant_id` is mandatory for live delegated routing and must equal the
authority-owned child grant. `authority_evidence` is optional and
non-authorizing. Runtime
child-run creation records it only after the authority-backed path has a trusted
parent grant and issued child grant. A forged or standalone task payload with
grant IDs is behavior-free data, not authority.

Validation fails closed when:

- `parent_run_id`, `child_run_id`, or `target_agent_id` is missing/nil;
- `child_run_id` equals `parent_run_id`;
- `objective` is empty or whitespace;
- `capability_grant_id` is missing, nil, or differs from authority-owned state;
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
3. Obtain a trusted parent `ValidatedCapabilityGrant` from authority/work-order
   admission and call
   `bind_root_run_capability_grant(&parent_run_id, &parent_grant)`.
   The subject must match the root principal snapshot. The manager privately
   retains the exact `ValidatedCapabilityGrant`, including its trust marker.
   Same-run retry is idempotent only for exact equality; the binding cannot be
   replaced or reused for another run in that manager.
4. For a recursive topology, use
   `bind_root_run_capability_grant_with_edges` instead and supply every explicit
   parent-agent/run to child-agent/run edge. The default binding API treats each
   paired scope entry as a direct root child; it never gives one child the root's
   remaining sibling bindings.
5. Ask the manager for `child_authority_for_run(...)`. This returns bounded
   request configuration from the manager-owned opaque caller handle; it does not
   expose or copy the validated parent grant.
6. Call `create_child_run(parent_recorder, child_recorder, request, authority)`
   with an explicit target agent, child run ID, objective, and delegated
   authority.
7. The manager resolves the sealed caller handle for the exact parent run and
   issues an authority-owned child grant at the current decision time. Test-only
   compatibility constructors may also supply a parent grant, which must exactly
   match the private binding. If validation or issuance fails, the manager emits
   `DelegationRejected` and does not emit `DelegationRequested`, route a task
   message, insert a child record, or start a child run.
8. The authority ledger atomically reserves immutable fan-out and every bounded
   budget component. Root and child fan-out caps are authority-owned (currently
   16 locally); caller values do not set or change that cap. Direct sibling
   reservations must fit component-wise inside their parent allocation. A child
   may reserve only an explicitly assigned descendant edge; attempts to use a
   direct root sibling deny before routing, traces, or run mutation.
9. On success, the manager records `DelegationRequested`, sends a task request
   message carrying non-authorizing grant refs, emits `ChildRunStarted`, and
   returns a scoped child `AgentContext`. The child record retains the issued
    complete ordered `DelegationChain`, issued child grant, cleanup obligations,
    and budget reservation evidence inside the authority owner. Runtime callers
    receive only opaque handles and redacted refs. The issued grant may
    recursively create a narrower local child while remaining depth is non-zero.
10. Every child action must carry the exact issued child grant ID. Missing, wrong,
   expired, revoked, over-budget, or out-of-scope evaluation denies before the
   gateway; the legacy projection can only narrow an authority allow. Action
   liveness and HTTP minute accounting use authority-owned service time. Clock
   rollback denies, observed expiry stays latched, and an old minute bucket cannot
   reopen authority.
11. The child completes or fails through `complete_child_run` or `fail_child_run`,
   which sends a structured task response and emits parent/child completion or
   failure trace events.
12. Terminal completion performs explicit ledger cleanup. Parent cancellation and
    parent/child grant revocation invalidate and cancel active descendants.
    Cleanup and revocation close new admission before a bounded quiescence wait;
    timeout is a typed result and cannot reactivate authority.
13. Completion, failure, denial, and cancellation are terminal for the child run;
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
`delegation_ledger` field carries only a v2 redacted summary: root/parent/child
grant IDs, chain digest/depth, bounded budget-dimension names, lifecycle status,
and stable reason. Complete grants, objectives, scopes, allowlists, obligations,
result parameters, and budget values remain authority-owned. Denied authority issuance may record a
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
exact grant, for descendants assigned by an explicit parent-to-child runtime edge,
and while depth, time, role, fan-out, and aggregate subtree budget remain
narrower. Merely appearing later in a root scope list does not make an identity a
descendant of every earlier child.

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
relationships, task messages, redacted chain digests/depth,
reservation/commit/release/fail-safe-consume transitions, cleanup, failures, and
revocation. It does not
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
- Child-to-root-sibling delegation: `delegation_child_runtime_binding_denied`
  before request/routing/start/insertion or parent/child run mutation.
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
but delegating callers must explicitly bind a trusted grant before
`create_child_run`. This is an intentional fail-closed local Rust API/security
tightening. Live task requests moved from v1 to v2 and now require
`capability_grant_id`; v1 is retained only as a non-authorizing legacy schema for
stored replay/migration data and is not accepted by live delegation creation.
Delegation grant/chain contracts and the default trace summary are v2. TypeScript
exports the aligned `TaskRequestV2`, `CapabilityGrantId`, and redacted ledger
summary types.

The additive `LegacyMultiScopeProfile` and
`grant_from_legacy_multi_scope_allowlists` authority compatibility builder allow
one parent grant to cover explicit non-empty lists of local child agent and run
IDs. They use the existing local-profile validator; nil identities, empty lists,
invalid audiences, and wildcard-like broad audience input fail closed.

The underlying `CapabilityScope` lists remain independent set dimensions for
capability containment. At trusted local root admission, however, equal-length
agent/run lists are zipped into immutable exact child bindings. Empty,
unequal-length, duplicate, or nil bindings fail closed. A caller cannot recombine
a listed agent with another listed run; that denies with
`delegation_child_runtime_binding_denied` before routing. This indexed legacy
bridge is intentionally narrower than the raw scope and should migrate to a
future typed paired-binding contract rather than restore Cartesian execution.
The default root-binding method assigns every zipped pair directly to the root.
`bind_root_run_capability_grant_with_edges` additionally accepts a complete,
rooted, acyclic local edge tree whose depth is bounded by the grant. Each scoped
pair has exactly one parent, so sibling scope cannot be laundered through a child.

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

The implementation provides a bounded authority-owned non-gold local AUTH-003
chain, accounting, explicit recursive delegation, action binding, cleanup,
revocation, and replay path, exercised by the local kernel E2E and runnable
example. This is component evidence, not completion of the catalog-wide AUTH-003
task or its Message Service/Agent Controller adoption. It deliberately does not
introduce remote dispatch, fleet placement, durable/cross-instance ledger storage,
or long-lived child services. Later
cross-instance work orders can map onto the same explicit fields without changing
the local no-ambient-authority rule. G18/G70/G71 remain `not_exercised` unless
their executable gold fixtures are added and pass. No gold command was run.
