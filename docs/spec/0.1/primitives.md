# Splendor 0.1 Stable Primitive Schemas

This document freezes the first stable primitive schema contract for Splendor
0.1 implementers. It defines public object shapes for clients, adapters, policy
hosts, replay tools, and integrations without freezing undocumented internals.

Stable 0.1 primitives are Tenant, Agent, Run, Tick, Action, Percept, Message,
StateNode, TraceEvent, WorkOrder, Approval, Policy, Constraint, Verifier,
Adapter, Feedback, and Reward.

## Global Schema Rules

- Public fields use snake_case serialized names.
- Stable time fields use RFC3339 timestamps unless an SDK-local field is
  explicitly documented as local-only.
- Side-effectful work must remain mediated by `ActionRequest`, the Action
  Gateway, verifier chain, and adapter boundary.
- Replay must not execute side effects by default.
- Transport wrappers must not change primitive identity, run scope, trace
  linkage, state ownership, or authority semantics.

## Identity Rules

These identifiers are distinct and must not be overloaded: `fleet_id`, `node_id`,
`instance_id`, `tenant_id`, `agent_id`, `runtime_context_id`, `run_id`,
`tick_id`, `action_id`, `state_node_id`, `trace_event_id`, `message_id`,
`work_order_id`, `approval_id`, and `artifact_id`.

The legacy `trace_id` name is a dev-era compatibility alias for
`trace_event_id`. New 0.1 schemas and examples emit `trace_event_id`.
Deserializers may accept `trace_id` during migration, but it must not become a
separate identity concept.

## Extension Rules

Extensions are allowed only where explicitly listed. They are non-authorizing
metadata for display hints, external references, correlation IDs, or diagnostics.

Extensions must not carry or override identity scope: `fleet_id`, `node_id`,
`instance_id`, `tenant_id`, `agent_id`, `runtime_context_id`, `run_id`,
`tick_id`, `action_id`, `state_node_id`, `trace_event_id`, `message_id`,
`work_order_id`, `approval_id`, or `artifact_id`.

Extensions must not carry or override authority: `authority`, `permission`,
`permissions`, `allowed_actions`, `allowed_adapters`, `allowed_permissions`,
`scope`, `scope_type`, `policy`, `policy_bundle`, `work_order`, `approval`,
`approval_token`, `signature`, `credential`, `secret`, `token`, `adapter`,
`quota`, `verifier`, or `gateway`.

Unknown top-level fields outside an explicit `extensions` object are not part of
the stable 0.1 contract. Implementations may reject them or preserve them as
opaque non-authorizing data, but they must not influence authorization,
verification, adapter selection, quota, policy, approval, or work-order scope.

## Primitive: Tenant

Purpose: Defines a tenant authority boundary for policies, actions, adapters,
permissions, quotas, data scope, and audit.

Identity rules: `tenant_id` is distinct from app/client principal, agent, run,
node, instance, and fleet identity. It does not grant side-effect authority by
itself.

Required fields: `tenant_id`, `allowed_actions`, `allowed_adapters`.

Optional fields: `allowed_permissions`, `quotas`, `policy_refs`, `data_refs`,
`extensions`.

Extension rules: Extensions cannot add actions, adapters, permissions, quotas,
credentials, policies, approvals, work orders, or data refs.

Trace/state/replay/security notes: Tenant scope appears in trace identity where
runtime actions, messages, state commits, approvals, or work orders are
tenant-bound. Replay can inspect tenant scope but must not treat tenant metadata
as fresh authorization.

## Primitive: Agent

Purpose: Defines an autonomous runtime identity within a tenant.

Identity rules: `agent_id` is distinct from tenant, app/client principal,
runtime context, run, and node/instance identity. Shared or specialist agents do
not inherit caller permissions by default.

Required fields: `agent_id`, `tenant_id`.

Optional fields: `runtime_context_id`, `label`, `metadata`, `allowed_actions`,
`allowed_adapters`, `allowed_permissions`, `state_head`, `extensions`.

Extension rules: Extensions cannot add or inherit permissions, adapters,
actions, work-order scope, credentials, or state ownership.

Trace/state/replay/security notes: Agent-scoped state commits identify the agent
when known. Replay reconstructs agent-scoped activity from trace/state without
granting new authority.

## Primitive: Run

Purpose: Defines one execution instance of an agent objective.

Identity rules: `run_id` scopes tick ordering, trace stream ordering, state
lineage, action requests, messages, approvals, and work-order authorization.

Required fields: `run_id`, `tenant_id`, `agent_id`, `status`.

Optional fields: `objective`, `work_order_id`, `parent_run_id`, `child_run_ids`,
`state_head`, `trace_range`, `created_at`, `updated_at`, `extensions`.

Extension rules: Extensions cannot change status, authorize actions, resume a
run, supply approvals, or override work-order scope.

Trace/state/replay/security notes: Run lifecycle transitions are traceable.
Replay is scoped to a run and must not execute actions. State commit failure must
prevent advancing to the next tick.

## Primitive: Tick

Purpose: Defines one governed loop cycle inside a run.

Identity rules: `tick_id` is monotonic within `run_id` and is not globally unique
without run scope.

Required fields: `run_id`, `tick_id`, `started_at`.

Optional fields: `completed_at`, `percept_count`, `proposed_action_count`,
`state_node_id`, `status`, `extensions`.

Extension rules: Extensions cannot add actions, hide failures, or alter trace
ordering.

Trace/state/replay/security notes: A successful tick traces the governed order:
`tick.started`, `percepts.received`, `state.loaded`, `policy.invoked`,
`policy.completed`, `actions.proposed`, `constraints.evaluated`,
`verification.started`, `verification.completed`, an action outcome,
`outcome.recorded`, `state.committed`, and `tick.completed`.

## Primitive: Action

Purpose: Defines a proposed operation mediated by the Action Gateway.

Identity rules: The action payload receives an `action_id` when wrapped in an
`ActionRequest`. `action_id` is distinct from adapter name and action name.

Required fields: `name`, `params`, `side_effect_class`,
`required_permissions`, `preconditions`, `postconditions`.

Optional fields: `cost_estimate`, `adapter` on request/config wrappers.

Extension rules: No stable `extensions` field is defined for `Action` in 0.1.
Action params must not carry credentials, approvals, work-order authority, or
verifier bypass directives.

Trace/state/replay/security notes: Side-effectful actions must be submitted as
`ActionRequest` through the gateway. Replay can inspect and simulate recorded
actions; it must not execute adapters by default.

## Primitive: Percept

Purpose: Defines a structured observation delivered to policy.

Identity rules: Percepts do not have a stable ID in 0.1. They are scoped by the
run/tick trace event that records them and by provenance.

Required fields: `schema`, `payload`, `provenance`, `timestamp`.

Optional fields: `provenance.detail`.

Extension rules: No stable `extensions` field is defined for `Percept` in 0.1.
Payloads cannot carry credentials or authorization to execute actions.

Trace/state/replay/security notes: Percepts are traced via `percepts.received` or
daemon append events. Replay can inspect percepts and re-evaluate policies in
safe modes without executing side effects.

## Primitive: Message

Purpose: Defines a typed, transport-neutral agent-to-agent coordination object.

Identity rules: `message_id` is distinct from trace, run, action, and state IDs.
Messages are scoped by `run_id`, `source_agent_id`, and `target_agent_id`.

Required fields: `message_id`, `source_agent_id`, `target_agent_id`, `run_id`,
`schema`, `payload`, `causal_parent`, `requires_response`, `created_at`.

Optional fields: none in the canonical `Message` object. Message envelopes may
carry lifecycle metadata such as delivery status and trace links.

Extension rules: No stable `extensions` field is defined for `Message` in 0.1.
Message payload schemas may define metadata fields, but messages do not grant
permissions or widen work-order scope.

Trace/state/replay/security notes: Message lifecycle events are trace-linked.
Replay reconstructs message causality from `message_id` and `causal_parent`
without using messages as permission delegation.

## Primitive: StateNode

Purpose: Defines an explicit, versioned state graph node or state commit record.

Identity rules: `state_node_id` is content-addressed and distinct from trace,
snapshot, run, and agent IDs. Only one runtime context should own write authority
for a state head at a time.

Required fields: `state_node_id`, `tenant_id`, `agent_id`, `run_id`, `parents`,
`state_hash`, `trace_event_id`, `created_at`.

Optional fields: `snapshot_id`, `snapshot_ref`, `metadata`, `extensions`.

Extension rules: Extensions cannot change parents, state hash, state ownership,
trace linkage, or snapshot authority.

Trace/state/replay/security notes: State commits are explicit and versioned.
Failed commits prevent advancing to the next tick. Replay reconstructs state
lineage from committed nodes and trace; replay must not mutate live state heads
by default.

## Primitive: TraceEvent

Purpose: Defines one append-only runtime-contract event in a run trace stream.

Identity rules: `trace_event_id` is deterministic from `run_id` and `sequence` in
the Rust implementation. `trace_id` is only a dev compatibility alias.

Required fields: `trace_event_id`, `run_id`, `sequence`, `timestamp`, `identity`,
`kind`.

Optional fields: `identity.fleet_id`, `identity.node_id`, `identity.instance_id`,
`identity.tenant_id`, `identity.agent_id`, `identity.tick_id`,
`identity.action_id`, `identity.state_node_id`, `identity.message_id`,
`identity.approval_id`.

Extension rules: No stable `extensions` field is defined for `TraceEvent` in
0.1. Event `kind` payloads are versioned by the trace event contract and cannot
hide authorization data outside documented fields.

Trace/state/replay/security notes: Trace events are runtime contract data, not
logs. Trace persistence failures on required pre-execution events fail closed for
side-effectful work.

## Primitive: WorkOrder

Purpose: Defines signed, scoped authority for starting or resuming a run.

Identity rules: `work_order_id` is distinct from run, action, state, trace, and
message IDs. A work order can narrow tenant/agent authority but cannot broaden it.

Required fields: `schema_version`, `work_order_id`, `tenant_id`, `agent_id`,
`objective`, `allowed_actions`, `allowed_adapters`, `allowed_permissions`,
`data_refs`, `quotas`, `placement`, `issued_at`, `expires_at`, `revocation`,
`signature`.

Optional fields: `run_id`, `extensions`.

Extension rules: Extensions cannot add allowed actions, adapters, permissions,
data refs, quotas, signatures, revocation status, placement execution authority,
approvals, or credentials.

Signature semantics: `signature` is required for run start/resume. A missing,
null, empty, unknown-key, or invalid signature is not a local authority hint; it
is invalid and must fail closed unless an explicitly documented local-dev
unsigned mode is enabled outside stable production/fleet behavior.

Trace/state/replay/security notes: Unsigned, expired, revoked, malformed, or
incompatible work orders fail closed before run start/resume. Replay can inspect
work-order trace records but must not re-verify external signatures or contact
revocation services by default.

## Primitive: Approval

Purpose: Defines scoped governance approval state and approval evidence consumed
by verifiers.

Identity rules: `approval_id` is distinct from action, run, trace, work-order,
and governance object IDs. Approval evidence is one verifier input; it never
bypasses the gateway.

Required fields: `schema_version`, `approval_id`, `tenant_id`, `agent_id`,
`run_id`, `decision`, `issued_at`, `expires_at`.

Optional fields: `action_id`, `action_name`, `adapter`, `reason`, `revoked`,
`trace_event_id`, `extensions`.

Extension rules: Extensions cannot grant approvals, change scope, include tokens,
or bypass verifier checks.

Trace/state/replay/security notes: Approval lifecycle changes are traceable.
Replay explains approval decisions but does not grant approvals or resume runs by
itself.

## Primitive: Policy

Purpose: Defines policy host input/output and policy bundle references that guide
action proposals and constraint evaluation.

Identity rules: Policy execution is scoped by tenant, agent, run, tick, state
reference, percepts, and messages. Policy identity is not action authority.

Required fields: `schema_version`, `policy_id`, `tenant_id`, `agent_id`.

Optional fields: `policy_bundle_id`, `version`, `issued_at`, `expires_at`,
`revocation`, `degraded_mode`, `extensions`.

Extension rules: Extensions cannot add action authority, change TTL/revocation,
inject credentials, or bypass gateway/verifier checks.

Trace/state/replay/security notes: Policy invocation and completion are traced.
Policy output proposes actions; it does not execute side effects. Missing,
invalid, expired, or revoked policy fails closed where policy enforcement is
required.

## Primitive: Constraint

Purpose: Defines hard or soft invariants evaluated during the loop.

Identity rules: `id` identifies a constraint definition. It is not a run, action,
verifier, or policy ID.

Required fields: `id`, `kind`, `scope`, `predicate`.

Optional fields: `obligation`, `extensions`.

Extension rules: Extensions cannot convert hard constraints to soft constraints,
grant permissions, or alter verifier outcomes.

Trace/state/replay/security notes: Constraint evaluation is traced as
`constraints.evaluated`. Hard constraint denial must prevent adapter execution.

## Primitive: Verifier

Purpose: Defines an enforcement check that returns allow/deny/intervention
evidence before or after adapter execution.

Identity rules: A verifier has a stable name/category but does not own tenant,
agent, run, action, approval, or work-order identity.

Required fields: `verifier`, `category`, `result`.

Optional fields: `applies_to`, `evidence_schema`, `extensions`.

Extension rules: Extensions cannot mark a denied result as allowed, suppress a
required verifier, or carry credentials/approvals that bypass normal verifier
inputs.

Trace/state/replay/security notes: Required verifier uncertainty fails closed as
deny, needs approval, or needs intervention. Replay can explain verifier results
without re-executing side effects.

## Primitive: Adapter

Purpose: Defines the boundary object that executes a verified action.

Identity rules: Adapter names are not permissions and are distinct from agents,
tools, work orders, and verifier identities.

Required fields: `name`, `capabilities`, `execute` interface.

Optional fields: `verify`, `compensate`, `maturity`, `extensions`.

Extension rules: Extensions cannot add permissions, credentials, endpoint
authority, action allowlists, approval grants, or gateway bypass behavior.

Trace/state/replay/security notes: Adapter execution occurs only after gateway
verification. Adapter failures are traceable outcomes. Replay must not call
adapters by default.

## Primitive: Feedback

Purpose: Defines post-outcome evaluation signals from humans, automation, or the
environment.

Identity rules: Feedback is scoped by the outcome/trace event that records it; it
does not grant authority.

Required fields: `kind`, `payload`, `recorded_at`.

Optional fields: `trace_event_id`, `extensions`.

Extension rules: Extensions cannot change action outcomes, grant approvals, or
alter rewards used for enforcement.

Trace/state/replay/security notes: Feedback may appear in `outcome.recorded`.
Replay can inspect feedback but must not treat it as authorization.

## Primitive: Reward

Purpose: Defines scalar evaluation signals associated with feedback or outcomes.

Identity rules: Reward is scoped by the outcome/trace event that records it; it
does not grant authority.

Required fields: `value`, `recorded_at`.

Optional fields: `units`, `context`, `trace_event_id`, `extensions`.

Extension rules: Extensions cannot change verifier, policy, gateway, or approval
decisions.

Trace/state/replay/security notes: Rewards may be recorded in trace for learning
or evaluation. Replay can inspect reward history but must not mutate live policy
or execute actions from rewards by default.

## Deprecated and Dev-Era Fields

| Field or alias | Stable 0.1 replacement | Migration guidance |
| --- | --- | --- |
| `trace_id` on trace events | `trace_event_id` | Emit `trace_event_id`. Deserializers may accept `trace_id` as an input alias during migration. |
| TypeScript `TraceId` alias | `TraceEventId` | Keep alias for source compatibility; new docs should use `TraceEventId`. |
| Rust `StateCommit.node_id` wording | `state_node_id` | Public schemas and docs use `state_node_id`; Rust may keep implementation field names. |
| SDK-local float percept timestamp | RFC3339 timestamp | Stable cross-language schemas use RFC3339. SDK-local helpers may convert at boundaries. |

`docs/spec/0.1/stable-primitive-examples.json` is the S1 lightweight fixture. It
is not the full 0.1-S2 conformance suite.
