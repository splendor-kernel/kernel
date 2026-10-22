# RFC 0008 - vNext Identity, Authority, Data-Use, and Secrets Plane

## Status and Scope

Status: Draft.

Scope: 0.2/v2 draft proposal for GitHub issue #140. This RFC is
non-normative until accepted and implemented. It does not change current daemon
behavior, stable 0.1 specs, OpenAPI schemas, SDKs, generated artifacts, Action
Gateway behavior, verifier behavior, trace formats, state formats, replay
semantics, work-order validation, or runtime permission enforcement.

This RFC converts the vNext planning material for identity, authority, secrets,
and data-use control into a reviewable plan and child-issue package. It is not an
implementation plan for this PR.

Milestone and sprint tie-ins:

| Area | Tie-in |
| --- | --- |
| Milestone fit | 0.2/v2 RFC-bound work before implementation. |
| Related sprint | `0.02-S0 - Daemon Security Boundary`. |
| Related sprint | `0.03-S1 - Distributed identity model`. |
| Related sprint | `0.03-S3 - Signed work orders`. |
| Related sprint | `0.04-S5 - Central policy distribution`. |
| Related stable line | `0.1-dev` compatibility and conformance planning. |

Source material:

- `AGENTS.md`
- `docs/rules/splendor_dev_model.md`
- `docs/rules/sprints_frs_milestones.md`
- `docs/rules/verifiable_criteria/main.md`
- `docs/rules/verifiable_criteria/sprints/0.02-S0-daemon-security-boundary.md`
- `docs/rules/verifiable_criteria/sprints/0.03-S1-distributed-identity-model.md`
- `docs/rules/verifiable_criteria/sprints/0.03-S3-signed-work-orders.md`
- `docs/rules/verifiable_criteria/sprints/0.04-S5-central-policy-distribution.md`
- `docs/rules/v2/README.md`
- `docs/rules/v2/architecture/schema-identity-map.md`
- `docs/rules/v2/architecture/architecture.md`
- `docs/rules/v2/catalog/complete_implementation_task_catalog.md`
- `docs/rules/v2/catalog/implementation_task_index.md`
- `docs/rules/v2/architecture/clean-architecture-rules.md`
- `docs/rfc/0006-agent-kernel-v2-lifecycle.md`
- `docs/rfc/0007-vnext-idempotent-service-api-semantics.md`
- `docs/releases/known-limitations.md`

## Motivation

Current Splendor rules already require authenticated daemon callers, distinct
runtime identities, scoped signed work orders, verifier chains, gateway-mediated
side effects, explicit state commits, append-only trace evidence, and replay
without side effects by default. The vNext planning pack proposes a broader plane for
identity, authority, data-use, and secrets. Without an explicit RFC boundary,
that broader vocabulary could be misread as implemented behavior or as a reason
to weaken existing work-order, verifier, and gateway invariants.

This RFC defines how the plane should be discussed before implementation:

- principal identity is not authorization;
- caller authentication is not gateway approval;
- signed work orders remain required authority for runs and resumes;
- sub-agent delegation remains narrower, expiring, budgeted, trace-linked, and
  revocable;
- secrets remain references and leases, not payload bytes in prompts, traces,
  state, datasets, or action params;
- readable data is not automatically usable for training, evaluation, export,
  retention, or deletion-sensitive derivation;
- unknown or stale identity, authority, data-use, secret, policy, and verifier
  state fails closed at privileged boundaries.

## Primitives Affected

This RFC strengthens planning for these primitives only:

- verifier;
- work order;
- governance;
- gateway;
- trace store;
- replay;
- message and delegation;
- fleet/node identity;
- SDK/API planning;
- docs/tests.

Boundary: docs only. No code, schemas, generated types, APIs, tests, public
contracts, or stable spec files are changed by this RFC.

## Non-Goals

- No implementation in this PR.
- No OAuth server, identity provider product, full PKI management, fleet mTLS
  rollout, or production credential verifier.
- No provider-specific secret SDK in core.
- No new Rust crate, Python package, TypeScript package, daemon endpoint,
  OpenAPI contract, JSON Schema, migration, generated artifact, or public API.
- No replacement of current `ActionRequest`, Action Gateway, verifier chain,
  adapter boundary, state graph, trace store, replay modes, work orders, or
  message semantics.
- No broad inherited permissions for shared agents, specialist agents, adapters,
  drivers, SDKs, node processes, or sub-agents.
- No claim that vNext planning objects are implemented or stable.
- No change to `docs/rules/*` or `docs/spec/0.1/*`.

## Invariant Summary

Future implementation spawned by this RFC must preserve these invariants:

- Authentication proves who the caller is; it does not authorize arbitrary agent
  actions.
- Endpoint scopes authorize access to daemon or manager API families; they do not
  replace signed work orders or gateway verification.
- Signed, scoped, expiring, revocable work orders authorize run creation, resume,
  dispatch, and delegated authority envelopes.
- Tenant, agent, run, runtime context, fleet, node, instance, action, state,
  trace, message, work-order, approval, and artifact identities remain distinct.
- Policy/model output proposes actions; it does not grant authority.
- The Action Gateway and required verifiers remain the only path to
  side-effectful adapter execution.
- State remains explicit and versioned through state graph nodes or accepted
  successor contracts.
- Trace remains runtime contract evidence, not ordinary logging.
- Replay does not execute side effects by default.
- Missing identity, unknown authority, expired or revoked credentials, stale
  policy, unavailable verifier, unknown data-use purpose, unavailable secret
  broker, and uncertain offline authority fail closed.

## Layered Boundary Model

The vNext plane must preserve the existing layered security boundary. These
layers are intentionally not interchangeable.

| Layer | Meaning | Must not become |
| --- | --- | --- |
| Transport security | Authenticates and protects the channel. | Caller identity, run authority, or gateway approval. |
| Caller authentication | Authenticates an app, service, CLI, SDK, node, or manager principal. | Permission to run arbitrary agent actions. |
| Endpoint scope authorization | Allows the caller to invoke a daemon, manager, or node endpoint family. | Work-order authority or side-effect approval. |
| Signed work order | Authorizes a run, resume, dispatch, or delegated scope. | Broad user credential, permanent grant, or gateway bypass. |
| Tenant/agent/run policies | Narrow runtime authority by identity, data, quota, policy, placement, and risk. | Replacement for verifier chains. |
| Gateway verification | Executes required verifier checks before adapter execution. | Optional SDK preflight or self-attested adapter approval. |
| Adapter execution | Performs the bounded effect after verification. | Authority source, policy owner, or verifier replacement. |

Short form:

```text
authn != authorization != gateway approval
```

A caller token authenticates the app. A signed work order authorizes the run. The
Action Gateway authorizes side effects after required verifier checks.

## Plane Model

The vNext plane should be split into four child workstreams. The names below are
planning names; they do not create crates, modules, public APIs, or schemas.

| Workstream | Proposed responsibility | Must not own |
| --- | --- | --- |
| Principal Registry | Principal existence, proof bindings, lifecycle, status, ownership, rotation, revocation, and identity query. | Operational permissions, data-use grants, secrets, gateway decisions, or broad action authority. |
| Authority Decisions | Capability/work-order/delegation evaluation, scope intersection, obligations, expiry, revocation, policy freshness, quotas, and decision evidence. | Authentication, adapter execution, domain reasoning, policy/model output, or message delivery. |
| Secret Broker | Opaque secret references, short-lived leases, delivery handles, rotation, revocation, scoped delivery evidence, and leak-safe redaction planning. | Provider-specific SDKs in core, long-lived secret storage, credential values in kernel objects, or secret-based authorization. |
| Data-Use Controller | Purpose-scoped decisions for collection, persistence, inference, training, evaluation, export, retention, deletion, derivation, locality, and protected data. | Data curation algorithms, training algorithms, legal advice engine, storage provider bytes, or generic data credentials. |

The four workstreams are deliberately separate. A principal can exist without an
authority grant. A valid authority grant can still be denied by data-use policy,
approval requirements, quota, local safety, verifier uncertainty, gateway checks,
or policy TTL. A secret lease can be delivered only after authority and relevant
data-use checks, and the lease itself does not authorize an operation.

## Work Order Compatibility

Future implementation must keep work orders as explicit run-authority objects.

Rules:

- Work orders remain signed, scoped, expiring, and revocable.
- Caller credentials cannot replace a work order for run creation, resume,
  dispatch, delegated authority, or side-effect authorization.
- Work-order scope can be narrowed by authority/data-use decisions, policy,
  quotas, approvals, local safety, and gateway verifiers; it cannot be broadened
  silently by any vNext compatibility field.
- Work-order validation must reject unsigned, expired, revoked, wrong-audience,
  wrong-subject, incompatible, overbroad, or unknown-authority work before run
  start/resume or side-effect execution.
- Work-order revocation must have a documented path such as a revocation list,
  introspection endpoint, signing-key invalidation, or accepted successor.
- Duplicate request receipts or idempotency records are evidence only. They do
  not create fresh authority after expiry or revocation.
- Work-order identity and validation outcomes must be trace/audit attributable
  without leaking secret material.

## Delegation Compatibility

Sub-agent, specialist, worker, route, or trigger delegation must remain attenuated.

Rules:

- Delegation authority is narrower than the parent scope.
- Delegation carries explicit subject, parent run or agent, objective, allowed
  messages, allowed actions/adapters/permissions, data refs or data-use grants,
  budget, expiry, revocation path, and trace linkage.
- Delegation is independently revocable and may require child cleanup or pause.
- Delegation is budgeted by action count, time, cost, data volume, resource use,
  or other accepted quota dimensions.
- A message is not a permission token. Message payloads may reference a grant or
  work-order evidence, but cannot grant authority by themselves.
- A child cannot inherit broad caller credentials, orchestrator credentials,
  secret leases, protected data leases, or adapter rights by default.
- Nested delegation must re-evaluate scope intersection and fail closed if any
  chain edge is missing, expired, revoked, overbroad, or unknown.

## Secret Handling Rules

Future secret-broker work must follow these rules:

- Kernel objects store `SecretRef`, lease references, delivery handles, access
  receipts, and redacted evidence only.
- Secret payload bytes must not appear in prompts, traces, state snapshots,
  datasets, action params, work orders, artifacts, public errors, logs, or
  generic telemetry.
- A `SecretRef` is not authorization to use a secret.
- A secret lease is bound to principal, workload/run, operation, adapter/driver,
  node or sandbox boundary, audience, purpose, expiry, maximum uses, and revocation
  state.
- Secret delivery is scoped to the authorized execution boundary. Reuse across
  sub-agents, worker attempts, nodes, or runs is denied unless explicitly covered
  by a fresh grant and lease.
- Provider-specific secret SDKs belong in adapters or node-local providers, not
  core runtime contracts.
- Secret provider unavailability, revocation uncertainty, wrong audience, wrong
  node, wrong workload, expired lease, and leak detection fail closed or route to
  intervention according to risk. Redaction-only recovery is acceptable only when
  redaction completeness is verifiable; otherwise outputs are quarantined, failed,
  or routed to intervention.

## Data-Use Rules

Future data-use work must separate access from purpose.

Rules:

- Readable does not mean trainable.
- Inference, training, evaluation, labeling, feedback/reward derivation,
  export, publication, deletion, persistence, retention, incident analysis, and
  protected-evaluation use are separate operations.
- Data-use decisions are scoped to principal, tenant/fleet, agent/run/workload,
  dataset/artifact/source, operation, purpose, locality, time, audience, retention,
  derivation plan, and policy version.
- Work orders may carry data refs, but future data-use work should prefer grant
  refs or data-use decisions where data use is privileged.
- Unknown purpose, ambiguous classification, missing provenance, expired consent,
  revoked license, changed dataset snapshot, locality mismatch, protected-holdout
  confusion, or missing deletion/retention obligations fail closed.
- Protected evaluation data remains mechanically separated from training and
  candidate code. Error messages and explanations must not reveal hidden answers,
  hidden case IDs, or protected payload fingerprints.
- Retention and deletion handling must preserve audit facts and state honest
  limits. It must not claim removal from trained models or derived artifacts
  without evidence.

## Child Issue Specs

These specs are the child issue package for issue #140.

### Child 1: Principal Registry RFC

Proposed title: `RFC: vNext principal registry without identity-authority collapse`.

Issue link: `[#152](https://github.com/splendor-kernel/kernel/issues/152)`.

Milestone fit: 0.2/v2 RFC first; implementation only after accepted RFC. Related
criteria: `0.02-S0`, `0.03-S1`, `0.03-S3`.

FR/tie-ins:

- `FR-0.02-S0-01` through `FR-0.02-S0-07` for caller identity, binding,
  audience, expiry, and revocation planning.
- `FR-0.03-01` for distinct distributed IDs.
- Imported planning tasks `IDR-001` through `IDR-006` as source material, not
  accepted implementation scope.

Primitive strengthened: fleet/node identity, SDK/API planning, work order,
trace/audit attribution, docs/tests.

Scope:

- Define principal kinds and proof-binding model at RFC level.
- Preserve existing typed IDs as bindings rather than replacing them.
- Define lifecycle states, rotation, suspension, revocation, and cache freshness
  expectations.
- Explain how missing, revoked, stale, or unknown identity fails closed before
  privileged operations.
- Define migration questions for existing tenant, agent, node, instance, service,
  human, governance, and device identities without rewriting historical traces.

Non-goals:

- No OAuth server, full PKI, identity-provider product, device attestation
  implementation, or production auth middleware.
- No permissions, work-order allowlists, data-use grants, or secret refs in
  identity metadata.
- No collapse of `agent_id`, `node_id`, `instance_id`, `run_id`, or
  `principal_id`.

Dependencies:

- Existing daemon security boundary docs.
- Existing distributed identity model criteria.
- RFC 0008 acceptance.

Acceptance:

- The RFC states that principal existence is not authorization.
- The RFC maps existing IDs to principal bindings without semantic collapse.
- The RFC defines missing identity, unknown principal kind, revoked principal,
  wrong audience, expired proof, stale cache, and ambiguous migration fail-closed
  behavior.
- The RFC defines trace/audit attribution for mutating calls without leaking raw
  credential material.
- The RFC explicitly preserves local dev insecure-mode restrictions.

Validation evidence required for future implementation:

- Contract tests for principal serialization, lifecycle transitions, and typed-ID
  binding round trips.
- Negative tests for missing identity, duplicate external subject, wrong audience,
  expired proof, revoked principal, nil identity, stale cache, and ambiguous
  migration.
- Replay/audit fixture proving historical tenant/agent/run IDs remain unchanged.
- Docs for identity lifecycle, revocation, local dev mode, and migration limits.

### Child 2: Authority Decision RFC

Proposed title: `RFC: vNext authority decisions, work-order compatibility, and delegated scope narrowing`.

Issue link: `[#153](https://github.com/splendor-kernel/kernel/issues/153)`.

Milestone fit: 0.2/v2 RFC first; implementation only after accepted RFC. Related
criteria: `0.02-S0`, `0.03-S3`, `0.04-S5`.

FR/tie-ins:

- `FR-0.02-S0-08` through `FR-0.02-S0-11` for work-order requirements, caller
  attribution, and no insecure SDK fallback.
- `FR-0.03-04` for signed work-order ingestion and rejection of unsigned,
  expired, revoked, or incompatible work orders.
- `FR-0.04-08` for policy TTL and fail-closed behavior.
- Imported planning tasks `AUTH-001` through `AUTH-007` as source material, not
  accepted implementation scope.

Primitive strengthened: work order, verifier, gateway, approval/governance,
message/delegation, trace store, replay, docs/tests.

Scope:

- Define a proposed capability/scope grammar at RFC level.
- Preserve signed work orders as run authority and compatibility profiles.
- Define authority decision outputs: allow, deny, or conditional with obligations.
- Define delegation chains that narrow scope, expire, budget, trace, and revoke.
- Define reason codes and evidence requirements for authority decisions.
- Define how authority, policy TTL, approvals, quotas, and gateway verifiers
  compose without replacing each other.

Non-goals:

- No runtime permission engine implementation.
- No universal wildcard that bypasses typed resource checks.
- No conversion of caller authentication, messages, policy output, model
  confidence, ownership, or approvals into direct action authority.
- No Action Gateway replacement or adapter self-authorization.

Dependencies:

- Principal Registry RFC for authenticated principal references.
- Existing work-order and daemon-security criteria.
- RFC 0007 idempotency semantics where future mutating authority APIs are
  involved.

Acceptance:

- The RFC preserves `authn != authorization != gateway approval`.
- The RFC states work orders remain signed, scoped, expiring, and revocable.
- The RFC states caller credentials cannot replace work orders or gateway
  verification.
- The RFC states delegation is narrower, expiring, budgeted, trace-linked, and
  revocable.
- The RFC defines missing authority, unknown operation, expired/revoked grant,
  stale policy, overbroad child scope, unsatisfied obligation, and verifier
  uncertainty as fail-closed conditions.

Validation evidence required for future implementation:

- Property tests for monotonic scope intersection and delegation no-broadening.
- Negative tests for missing, expired, revoked, wrong-audience, overbroad, and
  unknown authority.
- Gateway-denial tests proving authority allow does not execute adapters without
  required verifiers.
- Trace/replay fixtures explaining authority decisions without side effects.
- Work-order compatibility fixtures for unsigned, expired, revoked, incompatible,
  and extension-authorized records.

### Child 3: Secret Broker RFC

Proposed title: `RFC: vNext secret broker with refs, leases, scoped delivery, and redaction`.

Historical planning issue: `[#154](https://github.com/splendor-kernel/kernel/issues/154)`.
Current implementation tracking is aggregate
`[#183](https://github.com/splendor-kernel/kernel/issues/183)` with task issues
[#245](https://github.com/splendor-kernel/kernel/issues/245) through
[#250](https://github.com/splendor-kernel/kernel/issues/250). The proposed
implementation contract is [RFC 0012](0012-secret-broker-contract.md).

Milestone fit: 0.2/v2 RFC first; implementation only after accepted RFC.
Related criteria: `0.02-S0`, `0.03-S3`, `0.04-S5`.

FR/tie-ins:

- `FR-0.02-S0-02` through `FR-0.02-S0-07` for authenticated caller,
  binding, audience, expiry, and revocation.
- `FR-0.03-04` for work-order rejection before run start.
- `FR-0.04-08` for stale or unavailable policy fail-closed behavior.
- Imported planning tasks `SECR-001` through `SECR-006` as source material, not
  accepted implementation scope.

Primitive strengthened: verifier, adapter boundary, gateway, work order,
trace/evidence, replay, docs/tests.

Scope:

- Define opaque `SecretRef` and secret-lease planning semantics at RFC level.
- Define lease binding dimensions: principal, run/workload, operation,
  adapter/driver, node/sandbox, audience, purpose, expiry, maximum uses, and
  revocation.
- Define secret-delivery evidence without exposing secret bytes.
- Define leak-safe trace, state, action params, prompts, datasets, artifacts, logs,
  and public error rules.
- Define provider adapter boundary and local development provider constraints.

Non-goals:

- No provider-specific secret SDK in core.
- No production secret manager implementation.
- No environment-variable default delivery.
- No raw credential fields in kernel objects, work orders, state, trace,
  datasets, action params, prompts, or examples.
- No claim of perfect erasure from untrusted code memory.

Dependencies:

- Principal Registry RFC for caller and execution-boundary identity.
- Authority Decision RFC for lease approval.
- Data-Use Controller RFC where secrets protect data access or provider use.

Acceptance:

- The RFC states secrets are references and leases only.
- The RFC states secret values never enter prompts, traces, state, datasets,
  action params, work orders, artifacts, public errors, or generic logs.
- The RFC states a `SecretRef` is not authorization.
- The RFC defines wrong workload, wrong node, wrong audience, expired lease,
  revoked lease, provider outage, revocation uncertainty, and detected leak as
  fail-closed or intervention conditions.
- The RFC keeps provider SDKs outside core.

Validation evidence required for future implementation:

- Serialization tests proving no secret payload bytes enter kernel records.
- Negative tests for wrong node, wrong workload, wrong audience, expired lease,
  revoked lease, provider outage, and cross-tenant reference.
- Canary-secret leak tests across traces, state snapshots, action params,
  stdout/stderr capture, artifacts, logs, and public errors.
- Crash/cancellation tests proving delivery handles are closed or uncertain
  cleanup is recorded.
- Replay tests proving secret leases are not re-resolved by default.

### Child 4: Data-Use Controller RFC

Proposed title: `RFC: vNext data-use controller for purpose-scoped inference, training, evaluation, export, and retention`.

Issue link: `[#155](https://github.com/splendor-kernel/kernel/issues/155)`.

Milestone fit: 0.2/v2 RFC first; implementation only after accepted RFC.
Related criteria: `0.03-S3`, `0.04-S5`, later data/learning-control RFCs.

FR/tie-ins:

- `FR-0.03-04` for signed work-order compatibility and data refs.
- `FR-0.04-08` for policy TTL, revocation, degraded/offline behavior, and
  fail-closed high-risk actions.
- `FR-0.1-08` for no silent side-effect bypass, no silent verifier failure, no
  untraceable action, and no replay side effects by default.
- Imported planning tasks `DUC-001` through `DUC-007` as source material, not
  accepted implementation scope.

Primitive strengthened: verifier, work order, gateway, trace/evidence, replay,
governance, docs/tests.

Scope:

- Define data classifications and purpose-scoped operation categories at RFC
  level.
- Separate collection, persistence, inspection, transformation, inference,
  training, tuning, evaluation, labeling, feedback/reward derivation, export,
  publication, retention, deletion, incident analysis, and protected-evaluation
  access.
- Define data-use decisions and grant references that can narrow work-order data
  refs.
- Define locality, protected-eval, retention, deletion, and derivation impact
  planning rules.
- Define non-live policy simulation and replay explanation requirements without
  granting access.

Non-goals:

- No legal-policy engine or jurisdiction-specific legal conclusion in kernel
  docs.
- No data curation, training, evaluation, labeling, or lineage implementation.
- No claim that readable data is trainable, exportable, retainable, or usable for
  protected evaluation.
- No raw data credentials passed to training, evaluator, or agent code.

Dependencies:

- Principal Registry RFC for requester identity.
- Authority Decision RFC for capability intersection.
- Secret Broker RFC where data access requires secret delivery.
- Future artifact/lineage RFCs for retention/deletion propagation.

Acceptance:

- The RFC states readable does not mean trainable.
- The RFC separates inference, training, evaluation, export, deletion,
  persistence, and retention purposes.
- The RFC defines missing provenance, unknown purpose, ambiguous data class,
  expired consent/license, changed snapshot, locality mismatch, protected-eval
  confusion, and stale policy as fail-closed conditions.
- The RFC states work-order `data_refs` are not enough to bypass data-use checks
  where data use is privileged.
- The RFC states replay/simulation of data-use decisions does not grant live data
  access.

Validation evidence required for future implementation:

- Negative tests for readable-but-not-trainable data, wrong purpose, changed
  snapshot, expired consent/license, cross-locality use, protected-eval leakage,
  and missing deletion obligations.
- Trace/replay fixtures explaining data-use denial without exposing protected
  payloads.
- Data-use grant fixtures with expiry, revocation, locality, volume/time bounds,
  downstream derivation obligations, and redacted explanations.
- Policy simulation fixtures proving historical decisions are not rewritten and
  simulation output cannot grant access.

## Threat Model and Denial Test Plan

This table is the minimum denial/fail-closed plan that future child RFCs and
implementation issues must preserve. It is not executable evidence in this PR.

| Threat or ambiguity | Required behavior | Future evidence |
| --- | --- | --- |
| Missing caller identity | Reject non-dev privileged request before mutation. | Daemon/API negative test and audit event. |
| Unknown principal kind or binding | Deny privileged operation; do not infer from display name, IP, or metadata. | Principal registry fixture. |
| Expired caller credential | Reject before endpoint mutation. | Daemon security test. |
| Revoked caller credential or principal | Reject or quarantine according to risk; no new privileged effect. | Revocation propagation test. |
| Wrong audience or tenant/fleet binding | Reject before work-order or gateway processing. | Endpoint scope test. |
| Unsigned work order | Reject before run creation/resume. | Work-order negative fixture. |
| Expired or revoked work order | Reject create/resume/dispatch/new side effects; duplicate receipts are evidence only. | Work-order and idempotency fixture. |
| Unknown authority operation or overbroad scope | Deny before effect; no wildcard interpretation. | Authority property test. |
| Delegation widening attempt | Deny child grant or delegated action; identify failed chain edge. | Delegation no-broadening test. |
| Message payload tries to grant permission | Treat as data only; deny if no valid authority ref exists. | Message/delegation negative fixture. |
| Approval text without scoped evidence | Deny or require approval; do not execute adapter. | Approval/verifier test. |
| Required verifier unavailable or uncertain | Deny, pause, or intervention; never allow silently. | Verifier outage test. |
| Policy TTL expired or revoked | Deny high-risk side effects; cached low-risk behavior only if explicitly allowed. | Policy cache test. |
| Secret ref supplied in action params | Reject or treat as opaque non-authorizing ref; never expose bytes. | Secret schema/redaction test. |
| Secret provider unavailable | Deny lease or route to intervention; no fallback to weaker provider. | Secret provider outage test. |
| Secret leak detected in output | Redact/quarantine/fail according to policy; record restricted evidence. | Canary leak test. |
| Readable data used for training | Deny unless explicit training purpose grant exists. | Data-use negative fixture. |
| Unknown data-use purpose or ambiguous classification | Deny privileged data use. | Data-use policy test. |
| Protected eval payload requested by trainer/candidate | Deny and avoid revealing hidden case details. | Protected-eval isolation test. |
| Offline stale authority | Continue only declared low-risk cached operations; deny new high-risk effects. | Offline authority fixture. |
| Trace durability unavailable before side effect | Fail closed before effect. | Trace durability failure test. |
| Replay request tries to resolve secrets or execute adapters | Reject or force non-live simulation; no side effects. | Replay unsafe-mode test. |

## Security Impact

This RFC makes no runtime security change. Its security impact is planning
clarity. Future implementation must include security review because the plane
touches identity, caller credentials, work orders, delegated authority, data-use
rights, secret delivery, revocation, offline behavior, gateway verification,
trace/audit evidence, and replay.

Security-sensitive implementation must include denial-path evidence, not only
successful paths. Provider details, credential material, secret material,
protected data, and hidden evaluation payloads must be redacted from public errors,
traces, state, datasets, and artifacts unless an accepted restricted-evidence
contract explicitly permits access.

## Compatibility and Migration Impact

This docs-only RFC has no compatibility or migration impact.

Future implementation may affect public schemas, daemon APIs, SDKs, state/trace
formats, work-order validation, delegation semantics, policy TTL behavior, and
adapter/gateway contracts. Such work requires its own accepted RFC or contract
change with:

- versioning and migration plan;
- generated surface updates if schemas/API change;
- compatibility fixtures for stable 0.1 records;
- rollback or feature-gating notes;
- denial, trace, state, replay, and fail-closed tests;
- docs and examples updated only after behavior exists.

Migration principles:

- Existing IDs and historical traces remain valid.
- New principal or grant refs are additive until an accepted migration says
  otherwise.
- Unknown extension fields remain non-authorizing.
- Work-order, approval, and message records cannot gain authority from vNext-only
  fields unless a versioned accepted contract defines that authority.
- Historical replay explains recorded decisions; it does not recompute history
  using only current policy and call it original evidence.

## Trace and Replay Impact

This RFC changes no trace or replay behavior.

Future implementation should make these facts traceable without turning traces
into ordinary logs:

- caller principal and authentication evidence digest where permitted;
- endpoint scope decision and tenant/fleet binding;
- work-order validation outcome and work-order ID;
- authority decision result, obligations, reason codes, revision/freshness, and
  redacted evidence refs;
- delegation chain creation, use, expiry, revocation, and denial;
- secret lease request, delivery handle issuance, renewal, revocation, cleanup,
  and leak/quarantine evidence without secret bytes;
- data-use decision, purpose, policy revision, grant refs, locality/retention
  obligations, and redacted denial reasons;
- gateway verification, verifier uncertainty, adapter execution, action outcome,
  state commit, and terminal tick/run events.

Replay requirements:

- Replay remains inspect-only, read-only re-evaluation, safe simulation, policy
  comparison, or verifier explanation by default.
- Replay must not resolve live secret leases, fetch protected data, contact live
  revocation services for side-effectful decisions, execute adapters, mutate
  state, publish artifacts, or contact external systems by default.
- Replay may explain why a historical identity, authority, work-order,
  delegation, secret, or data-use decision allowed, denied, paused, or required
  intervention.
- Current-policy comparison must be labeled as comparison, not original evidence.

## Tests Required for Future Implementation

This docs-only RFC requires no runtime tests. Future child issues must include at
least these test categories when they implement behavior:

| Area | Minimum future evidence |
| --- | --- |
| Principal registry | Lifecycle transitions, proof binding, cache freshness, revocation, migration ambiguity, typed-ID separation. |
| Authority decisions | Scope intersection property tests, delegation no-broadening, work-order compatibility, obligations, expiry, revocation, reason-code determinism. |
| Secret broker | No secret bytes in serialized records, scoped delivery, wrong-boundary denial, rotation, revocation, leak detection, crash/cancel cleanup. |
| Data-use controller | Purpose separation, readable-not-trainable denial, protected-eval isolation, retention/deletion obligations, locality, policy simulation. |
| Gateway/verifier | Authority or data-use allow does not bypass gateway; verifier uncertainty fails closed; denied action does not reach adapter. |
| Trace/replay | Decisions are trace-linked; replay explains without live effects, secret resolution, or data access. |
| SDK/API | Thin-client behavior, no silent insecure fallback, no client-side authority decisions, structured errors where APIs change. |
| Compatibility | Stable 0.1 records remain valid or fail closed through a documented version/migration boundary. |

## Docs Required for Future Implementation

Future implementation should update docs only after behavior exists. Depending on
the accepted child RFC, affected docs may include:

- `docs/reference/identity.md` or accepted successor;
- `docs/reference/daemon-security-boundary.md`;
- `docs/reference/work-orders.md`;
- `docs/reference/delegation.md` or accepted successor;
- `docs/reference/secrets.md`;
- `docs/reference/data-use.md`;
- daemon API, SDK, OpenAPI, conformance, examples, migration, and release notes
  where public behavior changes.

Reference docs must not describe planned behavior as implemented behavior.

## Acceptance Coverage for Issue #140

| Issue #140 acceptance item | Coverage in this RFC |
| --- | --- |
| Child issue list exists/planned for principal registry, authority decisions, secret broker, and data-use controller. | `Child Issue Specs`. |
| `authn != authorization != gateway approval` is preserved. | `Layered Boundary Model`. |
| Work orders remain signed, scoped, expiring, and revocable. | `Work Order Compatibility` and Authority child spec. |
| Sub-agent delegation remains narrower, expiring, budgeted, trace-linked, and revocable. | `Delegation Compatibility` and Authority child spec. |
| Missing identity, unknown authority, expired/revoked credentials, and verifier uncertainty fail closed. | `Invariant Summary` and `Threat Model and Denial Test Plan`. |
| Non-goals are explicit. | `Non-Goals` and child issue non-goals. |
| No implementation is implied. | `Status and Scope`, `Boundary`, and future-only wording throughout. |

## Review Notes

Reviewers should reject follow-up implementation work if it does any of the
following:

- treats caller authentication as action authority;
- lets endpoint scopes replace signed work orders;
- lets authority decisions bypass the Action Gateway or required verifiers;
- lets messages, approvals, model output, policy output, identity ownership,
  secret refs, or data refs become permission tokens;
- serializes secret bytes into prompts, traces, state, datasets, work orders,
  action params, artifacts, public errors, or logs;
- treats readable data as trainable, exportable, retainable, or evaluation-usable
  without explicit purpose-scoped authority;
- permits unknown identity, unknown authority, stale policy, expired or revoked
  credentials, offline stale authority, or verifier uncertainty to degrade to
  allow;
- makes replay contact live providers, resolve secrets, read protected data, or
  execute side effects by default.
