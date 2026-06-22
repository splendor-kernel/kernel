# 0.1 to 0.2/v2 Schema and Identity Map

> **Status:** Active 0.2/v2 architecture rule source for issue
> [#136](https://github.com/splendor-kernel/kernel/issues/136). This document
> does not implement v2 schemas, does not change the stable Splendor 0.1
> baseline, does not break any public API, does not migrate trace or state
> stores, and does not make universal v2 objects stable contracts before RFC
> approval and implementation evidence.

## Scope

Issue: #136, "Plan vNext schema and identity grammar without breaking 0.1 primitives".

Milestone and sprint fit: Splendor0.2-dev / v2 active execution, with 0.1 stable baseline compatibility checks.

Functional requirements touched: FR-0.1-01 stable primitive specs, FR-0.1-02 schema versioning and compatibility rules, FR-0.1-03 runtime compatibility, FR-0.1-05 conformance fixture planning, FR-0.1-06 migration policy, and FR-0.1-08 side-effect, verifier, trace, state, replay, and identity guarantees.

Primitives strengthened: docs/tests, SDK/API planning, action gateway, verifier, state graph, trace store, replay, message, work order, approval, and fleet/node identity planning.

Boundary: docs only.

## Source Baseline

This map follows the current authority order from `AGENTS.md`, `docs/rules/*`, accepted RFCs, stable specs, release limitations, and public contracts. The 0.2/v2 rule pack is the active decomposition contract only after those higher-priority sources; it is not implementation evidence.

Source documents used:

- `docs/spec/0.1/primitives.md`
- `docs/spec/0.1/schema-versioning.md`
- `docs/rules/v2/README.md`
- `docs/rules/v2/architecture/architecture.md`
- `docs/rules/v2/architecture/core-abstractions.md`
- `docs/rules/v2/architecture/clean-architecture-rules.md`
- `docs/rules/verifiable_criteria/sprints/0.1-S1-stable-schema-freeze.md`
- `docs/rules/verifiable_criteria/sprints/0.1-S6-migration-and-release.md`

## Non-Goals

- No schema implementation.
- No generated Rust, Python, TypeScript, OpenAPI, or JSON Schema update.
- No public API, SDK, daemon, gateway, verifier, adapter, trace, state, replay, or store behavior change.
- No runtime or persistence migration.
- No claim that vNext `Principal`, `Scope`, `CapabilityGrant`, `EventEnvelope`, `StateCommit`, `WorkloadSpec`, `DriverManifest`, `Invocation`, `Proposal`, or `GateDecision` are stable contracts.
- No replacement of `ActionRequest`, the Action Gateway, verifiers, adapters, `TraceEvent`, `StateNode`, `WorkOrder`, or `Message` before an accepted RFC and migration plan.
- No broad fleet, training, learning, change-control, physical, or self-evolution implementation work.

## Classification Rules

This document uses three planning classifications.

| Classification | Meaning | Compatibility rule |
| --- | --- | --- |
| Extension | vNext can be layered onto 0.1 as optional, typed, non-authorizing metadata, wrapper, or separate profile. | Allowed only if 0.1 required fields, identity scope, authority semantics, gateway mediation, trace linkage, state ownership, and replay defaults are unchanged. |
| Replacement candidate | vNext proposes a semantic successor or renamed object. | Not compatible inside the 0.1 stable line if it removes, renames, or changes meaning of stable fields. Requires RFC, major schema version or explicit migration boundary, fixtures, and compatibility notes before implementation. |
| Deferred 0.2/v2-only concept | v2 concept has no stable 0.1 primitive counterpart or would pull in later milestone behavior. | Stays RFC-bound until a future RFC binds it to milestone scope, schemas, fixtures, and enforcement. |

## Primitive Mapping

| Stable 0.1 primitive | vNext concept | Classification | Mapping and guardrail |
| --- | --- | --- | --- |
| Tenant | `Principal` with tenant kind, `Scope`, `CapabilityGrant` issuer or scope coordinate | Extension | `tenant_id` remains the 0.1 authority boundary. vNext scope/capability records may reference it, but cannot replace `tenant_id` or make tenant metadata action authority. |
| Agent | `Principal` with agent kind, `AgentSpec`, `AgentInstance`, `Delegation`, `Scope` | Extension | `agent_id` and `tenant_id` remain distinct. Specialist or delegated agents still receive narrower scoped authority and do not inherit caller permissions. |
| Run | `WorkloadSpec`, `ExecutionLease`, `AgentInstance` lifecycle, `Scope.run_id` | Replacement candidate | vNext workload and lease semantics are broader than a 0.1 run. `run_id` remains the stable execution scope until a major/RFC migration maps runs to workload attempts without collapsing run, workload, lease, or agent identities. |
| Tick | `EventEnvelope` profiles for loop events, route-step events, invocation lifecycle | Replacement candidate | 0.1 tick ordering remains required. vNext can add event profiles, but removing `tick_id` or required tick event coverage is breaking. |
| Action | `ActionProposal`, `Proposal`, `GateDecision`, `Invocation`, `InvocationResult` | Replacement candidate | vNext proposal/gate/invocation semantics can explain a future split of action intent, authorization, and execution. They cannot bypass `ActionRequest`, the Action Gateway, verifiers, or adapter execution rules in 0.1. |
| Percept | `PerceptEvent` profile of `EventEnvelope` | Extension | A percept can later be wrapped as an event profile with source identity and payload references. The 0.1 `schema`, `payload`, `provenance`, and `timestamp` fields remain stable. |
| Message | Agent routing events, `Delegation`, `RouteStepEvent`, message envelope profile | Extension | `message_id`, source, target, run, schema, payload, causal parent, response flag, and created time remain the stable message contract. Messages never become permission tokens. |
| StateNode | `StateCommit`, `StateHead`, `StatePartitionSpec`, state snapshot `ArtifactRef` | Replacement candidate | vNext CAS, partition, and artifact-backed state semantics require a state-format RFC before replacing `StateNode`. Current `state_node_id`, parents, hash, trace linkage, tenant, agent, run, and timestamp remain required. |
| TraceEvent | `EventEnvelope`, `EvidenceBundle`, `CausalQuery` | Replacement candidate | `EventEnvelope` is the likely successor shape, but 0.1 `TraceEvent` ordering, identity, kind, and append-only semantics remain stable. `trace_id` stays only a migration alias for `trace_event_id`. |
| WorkOrder | `CapabilityGrant`, `Scope`, `WorkloadSpec`, `ExecutionLease` authority references | Extension | Signed scoped work orders remain required to start or resume runs. vNext capabilities may narrow and refresh authority, but cannot silently broaden work-order allowlists, data refs, quotas, expiry, revocation, or signature semantics. |
| Approval | `GateDecision`, approval requirements, governance principal evidence | Extension | Approvals remain scoped verifier evidence and never bypass the gateway. vNext gate decisions may structure approval outcomes, but cannot convert approval metadata into direct adapter authority. |
| Policy | `PolicyBundle` artifact profile, `GatePolicy`, deployment-controlled active policy pointer | Extension | Policy output proposes actions and constraints. vNext policy bundles and gate policies may add lineage/activation controls, but cannot execute actions or bypass verifier checks. |
| Constraint | `GatePolicy` rules, obligations, verifier inputs | Extension | Hard constraints still deny execution. vNext obligations may be explicit, but cannot silently rewrite proposals or turn hard denials into allows. |
| Verifier | `GateDecision.verifier_results`, evidence records, authority/data-use/safety checks | Extension | Required verifier uncertainty remains fail-closed. vNext evidence can enrich verifier output, but cannot hide required verifier results in opaque payloads. |
| Adapter | `DriverManifest`, `Invocation`, typed driver operation profiles | Replacement candidate | Driver vocabulary may replace adapter vocabulary only through RFC/versioning. In 0.1, adapters remain the boundary reached only after gateway verification. Drivers cannot authorize themselves. |
| Feedback | `FeedbackRecord` profile of `EventEnvelope`, collection/data profile input | Extension | Feedback can become richer event/evidence data. It is not authority and cannot alter outcomes, approvals, rewards, or gateway decisions. |
| Reward | `RewardDerivation`, evidence/artifact profile, learning-control input | Extension | vNext reward derivation can add lineage and anti-gaming evidence. Rewards remain non-authorizing and cannot mutate live policy or execute actions during replay. |

## Deferred vNext Concepts

These imported vNext concepts are not direct 0.1 replacements and must stay out of the stable 0.1 contract until separate RFCs define schemas, ownership, fixtures, and enforcement.

| vNext concept | Reason deferred |
| --- | --- |
| `ArtifactRef` and `ArtifactManifest` | 0.1 has artifact references in state/work-order contexts but no stable universal artifact plane. |
| `WorkloadSpec` and `ExecutionLease` | These imply execution fabric, resource leases, placement, attempt lifecycle, fencing, and scheduler behavior beyond current 0.1 stable primitive freeze. |
| `DriverManifest` as universal driver ABI | Replaces or broadens adapter contracts and requires driver conformance, effect classes, compatibility ranges, and gateway integration. |
| `Proposal` and `GateDecision` as universal mutation grammar | They generalize actions, state changes, delegation, data use, governance, and physical actions. They require gateway/verifier RFCs before implementation. |
| `ChangeSet`, `DeploymentPlan`, and activation state | These are governance/change-plane concepts beyond 0.1 stable primitive contracts. |
| Data, feedback, evaluation, training, candidate, and learning-control profiles | These require data-use, artifact lineage, workload, evaluation, and change-control rules before they can be stable. |
| Physical/device driver profiles beyond high-level actions | Physical orchestration stays high-level, locally safety-vetoable, and cannot claim production physical safety from planning docs. |

## Authorizing Fields

Authorizing fields are fields that define identity scope, allowlists, limits, expiry, revocation, signatures, verifier inputs, or approval evidence used by the runtime to allow, deny, pause, or execute a privileged operation. Many of these fields are not authority by themselves; they are inputs to gateway, verifier, policy, work-order, approval, and state/trace checks.

Unknown top-level fields and `extensions` fields are never authorizing. They cannot add, replace, or override any field listed here.

| Primitive or record | Authorizing or enforcement-relevant fields | Non-authority rule |
| --- | --- | --- |
| Tenant | `tenant_id`, `allowed_actions`, `allowed_adapters`, `allowed_permissions`, `quotas`, `policy_refs`, `data_refs` | `tenant_id` scopes authority but does not grant side effects by itself. Extensions cannot add actions, adapters, permissions, quotas, policies, credentials, approvals, work orders, or data refs. |
| Agent | `agent_id`, `tenant_id`, `runtime_context_id`, `allowed_actions`, `allowed_adapters`, `allowed_permissions`, `state_head` | Agent metadata, labels, and extensions cannot inherit caller permissions, change state ownership, or widen work-order scope. |
| Run | `run_id`, `tenant_id`, `agent_id`, `status`, `work_order_id`, `parent_run_id`, `child_run_ids`, `state_head`, `trace_range` | Run metadata cannot authorize actions, resume expired work, supply approvals, or replace work-order validation. |
| Tick | `run_id`, `tick_id`, `state_node_id`, `status` | Tick fields order and reference runtime work. They cannot add hidden actions, hide failures, or alter trace ordering. |
| Action and ActionRequest | `action_id`, `tenant_id`, `agent_id`, `run_id`, `name`, `adapter`, `params`, `side_effect_class`, `required_permissions`, `preconditions`, `postconditions`, `quota_usage`, `satisfied_preconditions`, `requested_at` | Params may reference approved resources, but cannot carry credentials, approvals, work-order authority, verifier bypass directives, or adapter-selection authority outside documented fields. |
| Percept | `schema`, `payload`, `provenance`, `timestamp` | Percepts inform policy. They do not authorize side effects or grant permissions. |
| Message | `message_id`, `source_agent_id`, `target_agent_id`, `run_id`, `schema`, `payload`, `causal_parent`, `requires_response`, `created_at` | Messages coordinate agents and reconstruct causality. Payloads cannot grant permissions, approvals, capabilities, or work-order scope. |
| StateNode | `state_node_id`, `tenant_id`, `agent_id`, `run_id`, `parents`, `state_hash`, `trace_event_id`, `snapshot_id`, `snapshot_ref`, `created_at` | State nodes prove lineage and ownership. Extensions cannot change parents, hashes, trace linkage, snapshot authority, or live state heads. |
| TraceEvent | `trace_event_id`, `run_id`, `sequence`, `timestamp`, `identity`, `kind` | Trace events record decisions and facts. They are not fresh authority during replay and cannot hide authorization in undocumented payload fields. |
| WorkOrder | `schema_version`, `work_order_id`, `tenant_id`, `agent_id`, `run_id`, `objective`, `allowed_actions`, `allowed_adapters`, `allowed_permissions`, `data_refs`, `quotas`, `placement`, `issued_at`, `expires_at`, `revocation`, `signature` | A work order can narrow but not broaden tenant/agent authority. Missing, invalid, expired, revoked, or incompatible work orders fail closed. Extensions cannot add allowlists, signatures, approvals, credentials, quotas, placement authority, or data refs. |
| Approval | `schema_version`, `approval_id`, `tenant_id`, `agent_id`, `run_id`, `action_id`, `action_name`, `adapter`, `decision`, `issued_at`, `expires_at`, `revoked`, `trace_event_id` | Approval evidence is consumed by verifiers. It never bypasses gateway verification and extensions cannot grant approval tokens or widen scope. |
| Policy | `schema_version`, `policy_id`, `tenant_id`, `agent_id`, `policy_bundle_id`, `version`, `issued_at`, `expires_at`, `revocation`, `degraded_mode` | Policy guides proposals and constraints. It is not action authority and cannot bypass the gateway. |
| Constraint | `id`, `kind`, `scope`, `predicate`, `obligation` | Constraint extensions cannot convert hard constraints to soft constraints or grant permissions. |
| Verifier | `verifier`, `category`, `result`, `applies_to`, `evidence_schema` | Verifier extensions cannot mark a denial as allowed, suppress required verifiers, or carry bypass credentials. |
| Adapter | `name`, `capabilities`, `execute`, `verify`, `compensate`, `maturity` | Adapter capabilities are declarations checked by gateway/verifiers. Adapter extensions cannot add permissions, credentials, endpoint authority, action allowlists, approvals, or bypass behavior. |
| Feedback | `kind`, `payload`, `recorded_at`, `trace_event_id` | Feedback is evaluation data. It cannot grant approvals, alter outcomes, or authorize future actions. |
| Reward | `value`, `recorded_at`, `units`, `context`, `trace_event_id` | Rewards are evaluation signals. They cannot change verifier, policy, gateway, approval, or replay behavior. |

Reserved non-authorizing keys from the 0.1 extension policy remain reserved in any vNext mapping: identity fields, `authority`, `permission`, `permissions`, `allowed_actions`, `allowed_adapters`, `allowed_permissions`, `scope`, `scope_type`, `policy`, `policy_bundle`, `work_order`, `approval`, `approval_token`, `signature`, `credential`, `secret`, `token`, `adapter`, `quota`, `verifier`, and `gateway`.

## Additive and Breaking Change Rules

| Change type | Classification | Required handling |
| --- | --- | --- |
| Add optional display, diagnostics, correlation, provenance, or external-reference fields inside explicit `extensions` where extensions are allowed | Additive | Field must be non-authorizing, must not affect hashes or decisions unless a versioned contract says so, and privileged consumers must ignore it for authorization. |
| Add a typed wrapper around a 0.1 primitive that preserves all required fields and authority semantics | Additive | Wrapper must preserve primitive identity, run scope, trace linkage, state ownership, gateway mediation, and replay defaults. |
| Add vNext profile records alongside 0.1 records, such as `PerceptEvent` or `FeedbackRecord`, without replacing 0.1 wire schemas | Additive | Profile must carry its own experimental schema version and must fail closed when unknown at privileged boundaries. |
| Accept a dev-era or vNext alias as input while emitting stable 0.1 field names | Additive only during documented migration | Alias cannot become a separate identity concept or authority source. `trace_id` remains only an input alias for `trace_event_id`. |
| Add enum values for extension-friendly enums | Potentially additive | Consumers must be documented to handle unknown values safely. Unknown privileged status, operation, schema, identity, authority, or safety state fails closed. |
| Tighten ambiguous validation from permissive behavior to fail-closed denial | Additive security hardening | Must document changed denial behavior and add negative fixtures. |
| Remove or rename a required field | Breaking | Requires RFC, new major schema version or explicit migration boundary, compatibility notes, and fixtures. |
| Change field meaning, identity scope, authority semantics, hash/canonical bytes, event ordering, or state ownership | Breaking | Requires RFC and migration plan. Silent semantic changes are forbidden. |
| Collapse distinct IDs, such as `agent_id`, `instance_id`, `run_id`, `workload_id`, or `lease_id` | Breaking and unsafe | Must not be accepted. Distinct IDs are permanent invariants. |
| Move authorizing fields into `extensions`, arbitrary maps, or untyped JSON blobs | Breaking and unsafe | Violates 0.1 extension policy and vNext architecture rule AR-003/AR-004. |
| Let unknown fields, unknown profile kinds, or unknown driver operations influence authorization | Breaking and unsafe | Unknown privileged data fails closed. |
| Replace `ActionRequest` and the Action Gateway with direct `Invocation` execution | Breaking and unsafe | Violates gateway invariant. Future driver gateway work must be a compatibility profile or RFC-approved replacement with equivalent or stricter enforcement. |
| Make replay execute live adapters, drivers, network, filesystem, devices, or external services by default | Breaking and unsafe | Violates replay invariant. Replay remains inspect, explanation, read-only re-evaluation, safe simulation, or policy comparison by default. |
| Replace explicit `StateNode` lineage with hidden mutable state | Breaking and unsafe | Violates state graph invariant. |

## Migration Fixture Plan

This is a fixture plan only. It does not add fixture files or migration tools. A future RFC or implementation PR should place fixtures under a path such as `conformance/migrations/0.1-to-vnext/` with `source/`, `expected/`, and `negative/` records.

Each fixture family should include a canonical positive fixture, at least one unknown-field fixture proving non-authority, at least one malformed or expired authority fixture proving fail-closed behavior, and a replay fixture proving no side effects execute.

| Fixture family | Source 0.1 record | Planned vNext target | Required assertions |
| --- | --- | --- | --- |
| Identity | Tenant, Agent, Run, fleet/node/instance identities where present | `Principal` refs plus `Scope` | `tenant_id`, `agent_id`, `run_id`, `runtime_context_id`, `fleet_id`, `node_id`, and `instance_id` remain distinct. Unknown identity kinds fail closed at privileged boundaries. Extensions cannot override identity fields. |
| Action request | `Action` wrapped by `ActionRequest` and its recorded `ActionOutcome` | `ActionProposal` plus `GateDecision` plus `Invocation` plan | Proposal creation is not execution. Gateway verification still precedes adapter/driver execution. Denied and verifier-failure fixtures do not reach the adapter. Unknown fields cannot add permissions, change adapter, or suppress quota/precondition checks. Replay fixture records the action but does not call a live adapter. |
| Trace event | `TraceEvent` with `trace_event_id`, `run_id`, `sequence`, `timestamp`, `identity`, and `kind` | `EventEnvelope` with causal parents and payload reference | Sequence, run scope, event identity, timestamp, and identity links are preserved. `trace_id` is accepted only as an alias input where implemented and emits `trace_event_id`. Unknown privileged event kinds fail closed for consumers that would authorize effects. Replay reconstructs facts without side effects. |
| State node | `StateNode` with parents, hash, snapshot reference, tenant, agent, run, trace linkage, and created time | `StateCommit`, `StateHead`, state snapshot `ArtifactRef` | Parent lineage, hash, snapshot reference, owner identities, and trace link survive conversion. Conversion does not move a live state head. CAS/partition metadata is explicit if introduced. Hash algorithm or canonical byte changes require versioned fixtures and rollback notes. |
| Work order | `WorkOrder` with signature, expiry, revocation, allowlists, data refs, quotas, placement, tenant, agent, and optional run | `CapabilityGrant`, `Scope`, and workload admission references | Signed, unexpired, unrevoked work orders map to narrower or equal capability scope. Unsigned, expired, revoked, unknown-key, incompatible, or extension-authorized work orders fail closed before run start/resume. Extensions cannot add allowed actions, adapters, permissions, data refs, quotas, placement authority, signatures, approvals, or credentials. |
| Message | Canonical `Message` plus any delivery envelope metadata | Agent routing event, delegation reference, or message profile over `EventEnvelope` | `message_id`, source, target, run, schema, payload, causal parent, response requirement, and creation time are preserved. Message payload cannot grant permissions or work-order scope. Replay reconstructs message causality and delivery status without dispatching live side effects. |

Negative fixture variants should include these records:

| Variant | Expected outcome |
| --- | --- |
| Unknown top-level field named `allowed_permissions` on a record where that field is not stable | Rejected or preserved as opaque data; never authorizes. |
| `extensions.signature`, `extensions.token`, `extensions.approval_token`, or `extensions.gateway` | Rejected or ignored for authority; privileged operation denied if no stable authority field exists. |
| Collapsed identity where `agent_id` equals `instance_id` by alias rather than explicit distinct fields | Rejected for privileged conversion. |
| Action request with vNext `Invocation` but no 0.1 gateway verification record | Denied or marked incomplete; adapter/driver not executed. |
| Replay request with live adapter or driver target by default | Rejected or forced into explicit non-live simulation mode. |

## Gateway and Replay Invariants

The vNext planning vocabulary must preserve the current loop invariant:

```text
Percepts -> Policy -> Constraints -> Action Gateway -> Verifiers -> Adapter -> Outcome -> State Commit -> Trace
```

Gateway rules for future RFCs:

- `Proposal`, `GateDecision`, `Invocation`, and `DriverManifest` may refine the action lifecycle, but cannot create a second side-effect path around `ActionRequest`, the Action Gateway, verifiers, and adapters while 0.1 remains stable.
- Driver or adapter manifests declare capabilities and effect classes; they do not grant themselves authority.
- Required verifier failure, unavailable policy, invalid work order, expired approval, quota exhaustion, unknown privileged schema, and missing trace/state durability fail closed.
- Work orders, approvals, capabilities, and policies can narrow authority. They cannot silently broaden tenant or agent scope.

Replay rules for future RFCs:

- Replay remains inspect-only, read-only re-evaluation, safe simulation, policy comparison, or verifier explanation by default.
- Replay must not contact live adapters, drivers, network, filesystems, devices, secret providers, revocation services, or artifact publishers unless a separately gated non-default mode is explicitly defined.
- `EventEnvelope`, `EvidenceBundle`, migrated trace records, and migrated state commits are replay inputs, not fresh action authority.
- Migration fixtures must prove that action, work-order, approval, message, trace, and state conversion does not execute side effects or mutate live state heads.

## RFC Readiness Checklist

Any future implementation that uses this map must follow `AGENTS.md` RFC rules.
An accepted RFC is required where `AGENTS.md` requires one, including new or
renamed primitives, public schema changes, trace event semantic changes, state
graph format changes, gateway contract changes, verifier pipeline changes,
daemon API breaking changes, SDK breaking changes, distributed identity changes,
governance semantic changes, and physical/device action model changes. Contract
change notes are allowed only for non-public, non-primitive,
non-security-affecting additive changes that do not alter accepted RFCs, stable
specs, public schemas, public API contracts, release limitations, gateway or
verifier contracts, or replay/state/trace semantics.

The RFC or allowed contract note must cover:

- Affected primitive, schema/profile version, and public surface.
- Whether the change is additive, replacement candidate, or deferred vNext-only work.
- Exact authorizing fields and reserved non-authorizing extension keys.
- Identity impact across tenant, agent, runtime context, run, tick, action, state, trace, message, work order, approval, fleet, node, and instance IDs.
- Gateway, verifier, quota, policy, approval, data-scope, filesystem/network, safety, and postcondition behavior.
- Trace, state, replay, and migration fixture impact.
- Denial, failure, unknown-field, and fail-closed tests.
- Rust/Python/TypeScript/daemon compatibility and generated-surface checks where applicable.
- Explicit non-goals and milestone boundary.

## Acceptance Coverage

| Issue #136 acceptance item | Covered by |
| --- | --- |
| Mapping table: current 0.1 primitive to v2 extension/replacement/deferred concept | `Primitive Mapping` and `Deferred vNext Concepts` |
| Identify all authorizing fields and state unknown fields/extensions cannot widen authority | `Authorizing Fields` |
| Specify additive vs breaking schema changes | `Additive and Breaking Change Rules` |
| Define migration fixtures for identity, action request, trace event, state node, work order, and message records | `Migration Fixture Plan` |
| Confirm Action Gateway and replay invariants remain intact | `Gateway and Replay Invariants` |
| Confirm active-rule status and no public break or migration | Status banner, `Scope`, and `Non-Goals` |
