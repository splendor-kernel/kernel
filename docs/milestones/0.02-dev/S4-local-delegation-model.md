# 0.02-S4 — Local Delegation Model

## Objective

Implement local parent/child delegation so an orchestrator agent can delegate a
scoped objective to a named specialist agent without ambient permission
inheritance.

## Functional scope

- Added `TaskRequest`, `TaskResponse`, `TaskFailure`, and `DelegatedAuthority`
  schemas for local delegation messages.
- Added `LocalDelegationManager` for local parent/child run metadata, admission
  checks, task request/response routing, cancellation checks, and replay graph
  reconstruction.
- Added delegated authority checks to `AgentContext`/`LoopEngine`; child actions
  require the exact issued child grant reference and are denied before adapter
  execution when authority or the legacy narrowing projection does not match.
- Added the authority-owned local delegation ledger for immutable complete chains,
  atomic fan-out/component budget reservations, nested children, cleanup, and
  descendant cancellation/revocation.

## Non-goals

- No remote work-order dispatch.
- No fleet placement.
- No long-lived autonomous child services.
- No governance workflow engine or approval surface.
- No daemon API expansion.

## Public contracts changed

- `splendor_types::TaskRequest` for live `splendor.message.task_request.v2`, with
  a mandatory non-authorizing child capability-grant reference. Legacy v1 is
  replay/migration-only.
- `splendor_types::TaskResponse` for `splendor.message.task_response.v1`.
- `splendor_types::DelegatedAuthority` and `TaskFailure`.
- `splendor_types::TraceEventKind` variants for local delegation.
- `splendor_kernel::LocalDelegationManager` and
  `splendor_kernel::replay_local_delegations`.
- `LocalDelegationManager::bind_root_run_capability_grant`, exact private
  validated-grant bindings, and replay-visible rejection records.
- `splendor_authority::LegacyMultiScopeProfile` and
  `grant_from_legacy_multi_scope_allowlists` for explicit bounded local child
  agent/run lists.
- `AgentContext` now has optional `delegated_authority`.
- `DelegationGrant.cleanup_obligations` and
  `LocalDelegationTraceContext.delegation_ledger` are additive v1 fields; older
  records deserialize with strict cleanup defaults and no ledger evidence.

## Runtime primitive impact

| Primitive | Impact |
| --- | --- |
| Percept | none |
| Policy | none; policies still propose actions |
| Gateway | protected by pre-gateway delegated-scope denial; allowed actions still use gateway |
| Verifier | delegated authority denial is recorded as normal verification result |
| State graph | unchanged; no hidden state sharing between parent and child |
| Trace store | added delegation lifecycle trace events |
| Replay | added local delegation graph reconstruction helper |
| Message | added task request/response schemas |
| Work order | none; local-only placeholder semantics, no signed work orders |
| Governance | none |

## Trace behavior

New trace variants:

- `DelegationRequested`
- `DelegationRejected`
- `ParentRunCancelled`
- `ChildRunStarted`
- `ChildRunCompleted`
- `ChildRunFailed`

Child start/completion/failure events include parent and child run IDs, source and
target agent IDs, parent causal trace, and request/response message links where
available.

Trusted root binding remains local run-admission setup and does not add a durable
trace event. Child-creation binding and collision denials reuse
`DelegationRejected`; replay preserves their stable reasons and contexts.

## State behavior

Parent/child metadata is explicit in `LocalRunRecord`. Agent state remains owned
by each `LoopEngine` and committed through the state graph. 0.02-S4 does not add
shared mutable state or cross-run state handoff.

The authority ledger privately retains each exact validated root/child grant,
ordered chain, immutable authority fan-out, and component budget reservation.
Run records expose grant IDs and complete chain evidence. The ledger remains
process-local and is not cross-instance state.

## Gateway and verifier behavior

The child `AgentContext` returned by `create_child_run` carries the exact validated
child grant and a legacy `DelegatedAuthority` narrowing projection. During a tick,
`LoopEngine` requires the action candidate's exact grant ID and evaluates current
scope, expiry/revocation, operation, adapter, permission, and budget authority
before applying the projection. A denial records `ActionVerificationCompleted` and
`ActionDenied`; the gateway adapter path is not called. Delegated child actions
must name an explicit adapter from `allowed_adapters`; omitted adapters fail
closed before gateway submission, so gateway default adapter selection cannot
launder authority. If delegated authority allows the action, normal gateway
verification and adapter execution still apply.

## Replay behavior

`replay_local_delegations(events)` reconstructs delegation edges, complete chains,
budget reservation lifecycle, task messages, cleanup, revocation, and structured
failures. Replay is inspect-only and does not route, start, or execute anything.

## Failure behavior

- Missing target/objective or mismatched message scope fails structured message
  validation.
- Delegated scope exceeding parent or target authority records
  `DelegationRejected` and creates no child run.
- Duplicate `child_run_id` records `DelegationRejected` and creates no second
  child run, task request, or child-start trace.
- Delegated child action without an explicit adapter records `ActionDenied` with
  `delegated_adapter_unspecified` and does not call the gateway.
- Parent cancellation records `ParentRunCancelled`; later delegation attempts
  record `DelegationRejected` and create no child run.
- Child failure returns `TaskResponseStatus::Failed` with `TaskFailure`, not an
  untyped exception.
- Repeated completion/failure after a child terminal status returns
  `ChildRunAlreadyFinished` and emits no duplicate response or terminal trace.
- Unbound, same-ID/different-content, mismatched-grant, and child grant-ID
  collision attempts fail before routing or child/fan-out mutation with stable
  replay-visible reasons.
- Recursive local delegation succeeds through exact issued child grants while
  remaining depth and an explicit parent-to-child runtime edge permit it. A child
  cannot substitute a direct root sibling; nested widening reports the first
  failing chain edge deterministically.
- Delegated action liveness and HTTP minute quotas use maximum-observed authority
  service time. Rollback and latched expiry fail closed, and cleanup/revocation
  return after a bounded typed quiescence wait with admission still closed.
- Aggregate sibling budget and concurrent fan-out are atomically enforced by the
  authority owner. Routing failure releases before effect; post-routing start
  uncertainty consumes fail-safe, with replay-visible evidence.

## Test evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| unit | Task schema validation | `splendor-types::message::tests::*task_request*`, `*task_response*` |
| unit | Delegation trace serialization | `splendor-types::trace::tests::local_delegation_trace_events_round_trip` |
| unit | Parent creates child and links traces | `splendor-kernel::local_delegation::tests::parent_creates_child_with_explicit_target_objective_and_trace_links` |
| negative | Authority cannot exceed parent/target | `delegated_scope_cannot_exceed_parent_or_target_authority` |
| negative | Duplicate child run ID is rejected before second task message | `duplicate_child_run_id_is_rejected_before_task_message_or_state_mutation` |
| negative | Child action outside delegated scope skips gateway | `loop_engine_denies_child_action_outside_delegated_scope_and_skips_gateway` |
| negative | Child action without explicit adapter skips gateway | `loop_engine_denies_delegated_action_without_explicit_adapter_and_skips_gateway` |
| concurrency | Create/cancel lifecycle is serialized | `delegation_creation_and_parent_cancellation_are_serialized` |
| concurrency | Cleanup/revocation timeout remains fail-closed | `cleanup_and_revocation_time_out_bounded_while_admission_stays_closed` |
| negative | Direct child cannot delegate to a root sibling | `direct_child_cannot_delegate_to_root_sibling_before_traces_routing_or_mutation` |
| failure | Structured child failure response | `failed_child_run_returns_structured_task_response_and_replays_causality` |
| failure | Repeated child completion is terminal and idempotently rejected | `repeated_child_completion_is_rejected_without_duplicate_response` |
| failure | Repeated/late child failure emits no duplicate failure trace | `repeated_child_failure_is_rejected_without_duplicate_failure_trace`, `child_failure_after_completion_is_rejected_without_failure_trace` |
| replay | Causal graph reconstruction | `failed_child_run_returns_structured_task_response_and_replays_causality` |
| security | Exact grant binding, replay reasons, and root/sibling/cross-tenant ID collision denial | `same_id_different_validated_parent_grant_content_denies_before_effects`, `*child_grant_id_collision*` |
| compatibility | One manager, one parent, two child scopes | authority multi-scope builder test and daemon `integration_kernel_e2e_0_03` |
| cancellation | Parent cancellation blocks delegation | `cancelled_parent_prevents_new_child_delegation_and_records_trace` |
| positive/nested | Complete two-edge chain and exact action grant | `nested_delegation_stores_complete_chain_and_requires_exact_action_grant_ref` |
| budget | Nth sibling aggregate overflow | `aggregate_sibling_budget_overflow_denies_nth_child_component_wise` |
| concurrency | Authority-owned fan-out race | `authority_owned_fan_out_is_atomic_under_concurrent_callers` |
| failure accounting | Routing release/start consume | `routing_and_start_failures_record_release_or_fail_safe_consumption` |
| revocation/replay | Descendant propagation and no-effect replay | `root_revocation_cancels_nested_descendants_and_replay_has_no_effects` |

## Example or fixture

See `examples/local-orchestrator-specialists/README.md` for the runnable shape and
expected trace behavior.

## Future extension notes

Remote Message Service and Agent Controller adoption, 0.03 signed remote work
orders, and all AUTH-003 gold cases remain explicitly deferred/not exercised.
They can map to the same explicit fields:
parent run, child run, target agent, objective, delegated authority, message IDs,
and causal trace IDs. Remote transport must preserve these fields and add signed
authorization; it must not introduce ambient inherited authority.
