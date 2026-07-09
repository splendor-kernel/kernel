# RFC 0010 - Authority Service Capability Contract

## Status and Scope

Status: Draft, with bounded local `AUTH-001`, `AUTH-002a`, `AUTH-003a`,
`AUTH-003b`, `AUTH-004a`, `AUTH-004b`, `AUTH-005a`, `AUTH-005b`, and `AUTH-005c`
implementation evidence slices.

Scope: 0.2/v2 Authority Service child RFC for C02,
`splendor.authority-service`. This RFC remains a Draft contract. This repository
branch includes only local Rust evidence slices: behavior-free capability and
scope contracts in `splendor-types`, deterministic local evaluation and narrowing
logic in `splendor-authority`, trusted local profile grant wrapping, a bounded
signed work-order to verified capability grant bridge, behavior-free delegation
grant/chain contracts, an authority-owned local child-grant builder, conditional
authority decisions for grants with obligations, behavior-free obligation receipt
contracts, trusted local receipt validation wrappers, exact fail-closed receipt
matching helpers, and unit tests for allow/deny/narrowing/issuance/delegation/
obligation behavior. It also includes a bounded runtime-local delegation-manager
bridge that records parent/child grant refs after authority-owned child-grant
issuance, plus a bounded local gateway obligation verifier that validates
receipt-bound decisions before the existing adapter invocation path, a local
authority-owned revocation snapshot plus offline degraded validated-grant cache
foundation, and a runtime-local delegated child revocation check that consumes a
trusted authority snapshot and cancels active child runs through the existing
local delegation finish path when run-record parent or child grant refs are
revoked.

This slice does not change daemon APIs, OpenAPI, TypeScript client workflows,
Python, fleet behavior, node admission, workload-controller wiring, approval
workflow execution, MFA/provider integration, gate-engine migration, obligation
receipt storage, production PKI, external revocation introspection, production
lease renewal, revocation watches, incident-controller integration, or introduce
a new adapter execution path. It adds optional local
trace/message/run-record authority reference fields for `AUTH-003b`, optional
gateway action obligation evidence for `AUTH-004b`, and a matching optional
`@splendor/types` primitive field for schema parity. `AUTH-005a` adds no public
schema churn; it exposes authority-crate Rust types/functions that cache only
`ValidatedCapabilityGrant` wrappers, check `RevocationRecord` snapshots, and
fail closed under missing/stale/expired cache or disconnected high-risk requests.
`AUTH-005b` adds no public schema churn; it exposes authority-crate Rust
types/functions for local renewal preflight with explicit nonce/current digest,
renewable policy, and lifetime caps. `AUTH-005c` adds no public schema churn; it
adds only a local kernel API that consumes an already trusted `RevocationSnapshot`
and existing run-record authority evidence.
It does not claim full C02, full `AUTH-001`, full `AUTH-002`, full `AUTH-003`,
full `AUTH-004`, full `AUTH-005`, G11, G18, G43, G60, G70, G71, G73, G75, G79,
G83, G88, issue closure, or gold completion.

Until exact executable fixtures pass, gold targets `G01`, `G11`, `G18`, `G43`,
`G60`, `G70`, `G71`, `G73`, `G75`, `G79`, `G83`, and `G88` remain
`not_exercised`.

## Binding

| Item | Binding in this RFC | Evidence status |
| --- | --- | --- |
| Aggregate issue | #182, `0.2/v2 component: C02 splendor.authority-service - Authority Service` | Aggregate target only; not complete. |
| Child issue | #238, `AUTH-001 - Define a composable capability and scope model` | Bounded local evidence only; not complete. |
| Catalog task | `AUTH-002 - Implement issuance and signed work-order integration` | Bounded `AUTH-002a` Rust bridge evidence only; not complete. |
| Catalog task | `AUTH-003 - Implement delegation chains and sub-agent authority narrowing` | Bounded `AUTH-003a` local child-grant contract/builder plus `AUTH-003b` runtime-local manager wiring evidence only; not complete. |
| Catalog task | `AUTH-004 - Implement obligations and approval requirements as authority results` | Bounded `AUTH-004a` conditional decision/receipt matching plus `AUTH-004b` local gateway receipt verification evidence only; not complete. |
| Catalog task | `AUTH-005 - Implement revocation, lease renewal, and offline authority behavior` | Bounded `AUTH-005a` local revocation snapshot/offline validated-grant cache, `AUTH-005b` local renewal preflight, and `AUTH-005c` local delegated child revocation propagation evidence only; no production lease renewal or production revocation service. |
| Component | `splendor.authority-service` | Local capability module evidence. |
| Owner packages | `splendor-types` for behavior-free contracts; `splendor-authority` for evaluation/narrowing decisions | Current slice follows this ownership. |
| Gold targets | `G01`, `G11`, `G18`, `G43`, `G60`, `G70`, `G71`, `G73`, `G75`, `G79`, `G83`, `G88` | `not_exercised` until executable fixtures/harnesses pass. |

## Motivation

C02 requires one composable authority grammar instead of scattered allowlists.
Without this boundary, implementations can drift into unsafe patterns:

- treating identity, ownership, messages, prompts, model confidence, or metadata
  as authority;
- using string wildcards that bypass typed operation/resource checks;
- letting child/specialist agents inherit broad caller authority;
- merging data read, training use, evaluation use, and publication into one
  permission;
- giving work orders, tenant policies, and delegated authority separate
  incompatible semantics.

This RFC defines the first local Rust contract/evaluator foundation that future
work-order, gateway, delegation, data-use, offline, and evidence slices can call.

## Non-Goals

- No production issuance service, PKI/OAuth/IAM product, or daemon authentication
  replacement.
- No new adapter execution path; `AUTH-004b` only verifies local authority
  obligation receipts before the existing gateway adapter invocation.
- No daemon, OpenAPI, TypeScript, Python, fleet, product, or physical safety
  behavior.
- No full data-use controller, secret broker, approval workflow, offline lease
  renewal, production revocation propagation service, revocation watches,
  external introspection, or incident-controller quarantine workflow.
- No universal wildcard or metadata/extension-based authority.
- No daemon/API contract change, TypeScript/Python client workflow update, gold
  fixture, production revocation watch, external introspection, node/fleet
  propagation acknowledgement, policy-cache consumption, or incident-controller
  quarantine flow for delegated children.
- No approval workflow engine, MFA provider, gate-engine migration, durable
  evidence store, production PKI, external revocation introspection, or full
  gateway/daemon/client obligation workflow in `AUTH-004a`/`AUTH-004b`.
- No full `AUTH-005` completion claim; `AUTH-005a` is only local Rust cache and
  revocation snapshot behavior over already validated grants, `AUTH-005b` is only
  local renewal preflight, and `AUTH-005c` is only local manager consumption of a
  trusted snapshot for already-running local child runs.
- No claim that `G01`, `G11`, `G18`, `G43`, `G60`, `G70`, `G71`, `G73`, `G75`,
  `G79`, `G83`, or `G88` passed.
- No closure claim for #182, #238, #239, #240, #241, #242, #243, or #244.

## Contract Overview

The local AUTH-001 slice adds these behavior-free `splendor-types` contracts:

- `AuthorityOperation`, `AuthorityOperationNamespace`, `AuthorityResourceKind`,
  and `AuthorityVerb`;
- `CapabilityScope` with tenant, fleet, agent, run, workload, device, data
  purpose, artifact, state partition, driver operation, audience, time, budget,
  network, and locality dimensions;
- `CapabilityGrant`, `CapabilityRequest`, `AuthorityDecision`,
  `AuthorityObligation`, `AuthorityObligationReceipt`, and `RevocationRecord`;
- nominal IDs for capability grants, authority decisions, authority obligations,
  revocations, workloads, devices, artifacts, and state partitions.

The local `splendor-authority::capability` module owns evaluation behavior:

- `CapabilityGrant` remains a behavior-free public contract and is not accepted
  directly by the evaluator;
- `evaluate_capability_request` consumes only `ValidatedCapabilityGrant` values
  produced by trusted local profile builders with private raw-grant storage and a
  read-only `grant()` accessor;
- raw external grant payloads are not authority and must not be treated as
  authorization evidence without a trusted validation path;
- grants must be schema-valid, locally validated/signed, unexpired, unrevoked,
  subject-matched, audience-matched, and operation/scope-contained;
- authorization grants and requests must carry an explicit audience and at least
  one concrete bounded scope dimension beyond only time or budget, must be bound
  to a tenant or fleet, and must include operation-specific scope where required
  such as data purpose, device, artifact, state partition, driver operation,
  workload/run, agent, or network host/scheme;
- `CapabilityGrantValidationKind::Signed` authorizes only when wrapped by the
  authority-owned work-order issuance bridge's private verified marker; raw
  signed grants still deny with `signed_grant_verifier_unavailable`;
- grants with obligations return `AuthorityDecisionStatus::Conditional` with
  `capability_conditional`; grants without obligations continue to return
  `Allowed` with `capability_allowed`;
- grant and request `CapabilityScope.time` windows are enforced against decision
  time, and requested time scope must be contained by grant time scope;
- missing, malformed, expired, revoked, wrong-audience, wrong-subject, or
  overbroad grants deny fail-closed;
- deterministic intersections choose common typed scope, narrower time windows,
  and smaller budgets;
- child grants must reference the parent grant, be issued by the parent subject,
  preserve obligations, subset operations, narrow every constrained dimension,
  and reduce delegation depth;
- compatibility builders map existing `WorkOrder` and `DelegatedAuthority`
  allowlists into typed local grants without validating signatures or changing
  runtime admission.

The bounded `AUTH-002a` slice adds `splendor-authority::issuance`:

- `issue_work_order_capability_grant` validates a signed `WorkOrderEnvelope`
  through `WorkOrderValidationContext` and `WorkOrderKeyring` before any grant is
  built;
- issuer and subject must be active `Principal` records, the issuer must be
  tenant-bound and bound to a `work_order_signing_key` proof for the issuance
  audience, and the subject must bind to the work-order tenant and agent;
- issuer authority is evaluated with `evaluate_capability_request` for the
  `Workload/Admit` operation over the work-order tenant, agent, run, expiry,
  quota, audience, and locality scope;
- only after an allowed issuer decision does the bridge return a
  `ValidatedCapabilityGrant` for the work-order action, adapter, and permission
  allowlists;
- the verified signed grant path uses a private trust marker so raw signed
  `CapabilityGrant` values still deny with `signed_grant_verifier_unavailable`.

The bounded `AUTH-003a` slice adds behavior-free delegation contracts and a local
authority-owned builder:

- `splendor-types` defines `DelegationGrant`, `DelegationChain`,
  `DelegationRoleProfile`, `DelegationResultContract`, and schema constants;
- each delegation grant records parent run/agent, child run/agent, objective,
  role/profile, allowed message schemas, allowed recipients, result contract,
  budget, expiry, remaining depth, fan-out cap, and the embedded child
  `CapabilityGrant`;
- `splendor-authority::delegation::issue_delegation_child_grant` accepts a
  parent `ValidatedCapabilityGrant`, typed request, and authority context, then
  builds a validated local child grant only after explicit parent-edge,
  issuer/subject, message, result, depth, authority-owned fan-out, liveness,
  narrowing, parent-obligation propagation, and critic/evaluator role checks
  pass;
- the builder reuses `ensure_child_grant_narrows` and
  `evaluate_capability_request`; raw `CapabilityGrant` payloads remain
  behavior-free contracts and are not accepted as external authority.

The bounded `AUTH-003b` slice wires the authority-owned builder into the current
local delegation manager:

- `LocalDelegationManager::create_child_run` now requires `LocalDelegationAuthority`
  with a trusted parent `ValidatedCapabilityGrant`, child principal, audience,
  and non-authorizing parent/child grant refs;
- parent and child run records carry run-bound principal IDs; the manager binds
  the parent grant subject to the parent run's principal snapshot and evaluates
  parent/child grant liveness at the current decision time before routing any
  delegated task;
- the manager calls `splendor_authority::issue_delegation_child_grant` before
  `DelegationRequested`, task message routing, `ChildRunStarted`, or child record
  insertion;
- authority issuance denial records `DelegationRejected` with a stable reason and
  does not route a task request or insert a child run;
- successful child records, task request payloads, `LocalDelegationTraceContext`,
  and replay output carry `LocalDelegationAuthorityEvidence` with parent and
  child `CapabilityGrantId` values;
- `DelegatedAuthority` remains a legacy compatibility restriction checked before
  gateway submission and is not standalone capability authority.

The bounded `AUTH-004a` slice adds conditional authority decisions and obligation
receipt matching:

- `splendor-types` defines `AUTHORITY_OBLIGATION_SCHEMA_VERSION`,
  `AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION`,
  `AuthorityDecisionStatus::Conditional`, additional typed
  `AuthorityObligationKind` variants for MFA/assurance, dedicated isolation,
  network deny, human review, independent evaluator, local safety verifier,
  postcondition check, and maximum blast radius, plus
  `AuthorityObligationReceipt`;
- each raw receipt remains behavior-free and carries a receipt ID, owning-service
  issuer principal, audience, one obligation ID/kind, original subject principal,
  authority decision ID, canonical request digest, evidence digest/reference,
  issuance/expiry times, revocation source/state, optional approval identity/trace
  reference, and local validation material;
- `splendor-authority::canonical_authority_request_digest` produces a stable
  `blake3:` digest over the authority request contract for receipt binding;
- `splendor-authority::validate_authority_obligation_receipt` wraps raw receipts
  as `ValidatedAuthorityObligationReceipt` only after a trusted owning-service
  context supplies expected issuer, audience, key ID, local validation secret,
  revocation source, and decision time; wrong issuer, audience, key, signature,
  expiry, revocation, malformed digest/reference, or unsupported schema fails
  closed with stable reason codes;
- the local validation context is authority-service owned, not a requester wire
  contract; this bounded slice does not expose a requester-constructible context
  as authority;
- `splendor-authority::verify_obligation_receipts` accepts only validated
  receipts, requires an exact receipt set for conditional decisions, rejects
  duplicate receipt IDs, duplicate obligation IDs, and extra receipts, and denies
  missing, wrong decision, wrong subject, wrong obligation ID, wrong kind, wrong
  request digest, expired, revoked, malformed request digest, malformed evidence
  digest, and unsupported schema cases with stable reason codes;
- `splendor-authority::issue_delegation_child_grant` does not treat a
  `Conditional` parent authority decision as enough to issue a child grant; it
  denies with `parent_obligations_unsatisfied` before child grant creation while
  preserving the behavior-free obligation propagation rule for narrowed grants;
- no gateway verifier, daemon/API, TypeScript, Python, MFA, approval workflow,
  gate-engine, data-use, quota, safety, durable evidence-store, production PKI,
  external revocation-introspection, or adapter execution integration is included
  in `AUTH-004a`.

The bounded `AUTH-004b` slice wires local obligation receipt verification into
the existing gateway path:

- `ActionRequest` can carry optional behavior-free
  `GatewayAuthorityObligationEvidence` containing a conditional decision and raw
  receipts;
- `LocalAuthorityObligationVerifier` validates each raw receipt with trusted
  authority-owned local context before matching it against the decision;
- the verifier requires receipt-bound integrity metadata for both the exact
  gateway action digest and the full conditional decision digest, so changing
  action parameters or tampering with the obligation set fails closed before
  adapter execution;
- the verifier checks the decision operation plus tenant/agent/run scope against
  the gateway action request, and legacy `ApprovalEvidence` alone does not satisfy
  authority obligations;
- this remains a bounded local verifier only: no approval/MFA/gate receipt
  service, durable evidence store, production PKI, external revocation
  introspection, daemon/API, TypeScript client workflow, Python, or gold fixture
  is added. The TypeScript package carries the optional behavior-free primitive
  field only to keep canonical schema parity with Rust.

The bounded `AUTH-005a` slice adds local revocation/cache behavior in
`splendor-authority::revocation`:

- `AuthorityGrantCache` stores only `CachedAuthorityGrant` values constructed
  from `ValidatedCapabilityGrant`; there is no raw `CapabilityGrant` cache insert
  API, so cached grants cannot become requester-fabricated ambient authority;
- each cached grant records `cached_at` and local cache `expires_at`, and cache
  expiry cannot outlive the wrapped grant's own expiry; future-dated cache
  entries deny fail closed at evaluation time;
- `RevocationSnapshot` wraps behavior-free `RevocationRecord` values with
  refresh/expiry metadata, rejects malformed or duplicate grant records, and
  denies when the snapshot is missing, stale, or future-dated relative to the
  decision time;
- `evaluate_cached_capability_request` first checks cache presence, cache
  freshness/expiry, revocation snapshot liveness, and revoked records before
  delegating normal operation/scope evaluation to `evaluate_capability_request`;
  disconnected `NeedsIntervention` is returned only after a cached grant matches
  the request subject, operation, audience, and scope;
- disconnected behavior is explicit through `OfflineAuthorityPolicy`: only exact
  configured low-risk read operations, including explicitly allowlisted device
  sensing reads, can evaluate within cached scope and offline TTL; high-risk
  physical actuation, change, delegation/self-change, data publication, network,
  driver, gateway action, and permission operations deny or return
  `NeedsIntervention` according to policy after scope authority is established;
- stable local reason codes include `authority_grant_revoked`,
  `authority_cache_missing`, `authority_cache_stale`, `authority_cache_expired`,
  `authority_cache_future_dated`, `authority_revocation_snapshot_missing`,
  `authority_revocation_snapshot_stale`,
  `authority_revocation_snapshot_future_dated`,
  `authority_offline_unsupported_operation`, `authority_offline_high_risk_denied`,
  `authority_offline_high_risk_needs_intervention`,
  `authority_offline_ttl_expired`, and `authority_scope_mismatch`;
- this remains a local foundation only: no revocation watch service, external
  introspection, lease renewal, node/policy-cache consumption, incident-controller
  integration, durable evidence store, daemon/API/client workflow, delegated child
  revocation propagation, or gold fixture is added.

The bounded `AUTH-005b` slice adds local renewal preflight behavior in
`splendor-authority::renewal`:

- renewal accepts only an existing `CachedAuthorityGrant` plus a proposed
  `ValidatedCapabilityGrant`; raw `CapabilityGrant` payloads are not accepted as
  renewable authority;
- `TrustedAuthorityRenewalContext` requires an explicit nonce and current grant
  digest/revision from the local authority-owned caller, and
  `renew_cached_authority_grant` denies missing or mismatched nonce/digest rather
  than silently renewing stale authority;
- `AuthorityGrantRenewalPolicy` makes renewable vs non-renewable local policy
  explicit; absent policy and explicit non-renewable policy both deny fail closed;
- the preflight re-checks cache freshness/expiry/future dating and current
  `RevocationSnapshot` liveness/revocation before renewal can succeed;
- the proposed renewed grant must keep the same grant ID, issuer, subject,
  operations, non-audience scope, audience, revocation state/ref, obligations,
  parent grants, validation kind, delegation depth, and start time; only the grant
  expiry may extend, and only within the local maximum renewal lifetime;
- renewed cache expiry is bounded by maximum offline lifetime and can never
  outlive the renewed grant expiry;
- this remains local preflight only: no durable nonce/replay store, production
  lease service, external revocation introspection, daemon/API/client workflow,
  gateway/node/fleet/policy-cache consumption, incident-controller integration,
  delegated child revocation propagation, or gold fixture is added.

The bounded `AUTH-005c` slice wires local child revocation propagation into
`splendor-kernel::LocalDelegationManager`:

- `RevocationSnapshot` exposes an authority-owned helper for checking whether a
  trusted snapshot contains a revoked `CapabilityGrantId`, without moving
  snapshot freshness/expiry evaluation into the kernel;
- `LocalDelegationManager::cancel_child_if_authority_revoked` consumes a trusted
  `RevocationSnapshot`, reads the child run record's
  `LocalDelegationAuthorityEvidence`, and cancels only active child runs whose
  recorded parent or child grant ID appears as revoked in the snapshot;
- cancellation uses the existing `finish_child_run` path with
  `TaskResponseStatus::Cancelled` and `TaskFailure` code
  `authority_grant_revoked`, `retryable=false`, so existing task response,
  `ChildRunFailed` trace, and replay behavior carry the evidence;
- unrelated revocations and terminal child runs are deterministic no-ops and do
  not emit duplicate responses or trace events;
- message payload grant refs remain non-authorizing and are not inspected for
  revocation authority;
- this remains local snapshot consumption only: no production revocation watch,
  external introspection, daemon/API/client workflow, gateway verifier, node/fleet
  policy-cache integration, incident-controller quarantine, cleanup obligations,
  durable evidence store, or gold fixture is added.

## Guardrails

| Rule | Required behavior in this slice |
| --- | --- |
| Authority is typed | Operation namespace, verb, resource kind, and schema version are explicit enums/fields. |
| Raw grants are not authority | Evaluator accepts `ValidatedCapabilityGrant`, not raw `CapabilityGrant`; compatibility builders return `Result` and fail closed for invalid generated profiles. |
| No wildcard bypass | `*` in operation names, audiences, network/locality tokens, validation refs, or driver refs is rejected by the evaluator. |
| No unbound authority | Authorization evaluation denies grants or requests without an explicit audience, tenant/fleet binding, and at least one concrete bounded dimension beyond only time/budget. |
| Operation-specific scope | Network egress needs scheme and host; device, artifact, state, driver, workload, and agent operations need matching concrete scope dimensions. |
| No raw signed self-attestation | Raw signed grants deny unless produced by the bounded authority-owned work-order issuance bridge. |
| Scope time enforced | Grant and request scope time windows are enforced and request time cannot broaden grant time. |
| Data purposes stay separate | `read`, `training_use`, `evaluation_use`, and `publication` are distinct scope values and operation verbs. |
| Extensions are non-authorizing | Metadata is validated with reserved-key guards and ignored for allow decisions. |
| Delegation narrows | Child grant operations, scopes, time, budgets, obligations, and delegation depth cannot broaden parent authority. |
| Messages are not authority | Delegation contracts can list allowed message schemas and recipients, and task payloads can carry grant refs for replay, but message payloads, sources, metadata, task text, and forged grant refs do not authorize child grants. |
| Fan-out is authority-owned | Local `AUTH-003a` rejects requested fan-out caps that exceed the authority-owned parent-edge limit before issuing a child grant. |
| Critic/evaluator roles are non-actuating | Local `AUTH-003a` denial tests reject critic/evaluator delegations carrying actuation, external-effect, or delegation-control operations. |
| Local delegation fails closed | Local `AUTH-003b` denies before task routing and child insertion when authority evidence is missing/invalid, parent principal binding fails, grant liveness fails, or child-grant issuance fails. |
| Obligations are conditional authority | Local `AUTH-004a` returns `Conditional` for matching grants with obligations instead of unconditional allow. |
| Raw receipts are not authority | Local `AUTH-004a` raw receipt contracts must first be wrapped as `ValidatedAuthorityObligationReceipt` through trusted owning-service context; requester-fabricated receipt fields do not satisfy obligations. |
| Receipts are exact and typed | Local `AUTH-004a` receipt verification requires validated receipts with matching receipt ID uniqueness, obligation ID/kind, subject, decision ID, canonical request digest, evidence digest, audience, expiry, and active revocation state; duplicate, missing, or extra receipts deny. |
| Gateway verifies receipts pre-effect | Local `AUTH-004b` adds optional behavior-free `ActionRequest` authority obligation evidence and a configurable gateway verifier that validates trusted receipts, requires receipt-bound integrity digests for the exact gateway action and full conditional authority decision, checks action operation plus tenant/agent/run scope binding, and blocks adapter execution on missing required evidence, forged/raw receipts, stale/revoked receipts, duplicate/extra receipts, wrong decision/subject/kind/scope, tampered obligation sets, or changed action parameters. |
| Approval is not a bypass | Receipt verification does not replace capability, quota, safety, data-use, policy, or gateway checks and does not accept free-form `approved` text, metadata, or extensions as authority. |
| Cached grants are not ambient authority | Local `AUTH-005a` caches only `ValidatedCapabilityGrant` wrappers; raw `CapabilityGrant` payloads cannot be inserted into `AuthorityGrantCache`. |
| Revocation overrides cached payloads | Local `AUTH-005a` denies a cached active grant when the current `RevocationSnapshot` contains a revoked `RevocationRecord` for the grant. |
| Missing/stale/expired cache fails closed | Local `AUTH-005a` denies when the cache is empty, a cache entry is stale/expired/future-dated, the revocation snapshot is missing/stale/future-dated, or disconnected TTL has expired. |
| Offline degraded mode is pinned | Local `AUTH-005a` disconnected mode evaluates only exact configured low-risk read operations, including explicitly allowlisted device sensing reads, after normal scope authority matches; unsupported, high-risk physical actuation, change, and self-change operations deny or require intervention by explicit policy. |
| Renewal is explicit local preflight | Local `AUTH-005b` renewal requires an existing cached validated grant, a proposed validated grant, an explicit nonce, matching current grant digest/revision, and renewable local policy; raw grants are never accepted as renewed authority. |
| Renewal cannot hide authority change | Local `AUTH-005b` denies proposed renewed grants that change grant identity, issuer, subject, operations, scope/audience, revocation state/ref, obligations, parent grants, validation kind, delegation depth, or start time. |
| Renewal lifetimes are bounded | Local `AUTH-005b` enforces maximum renewal lifetime and maximum offline cache lifetime, and renewed cache expiry cannot outlive renewed grant expiry. |
| Child revocation uses run-record evidence | Local `AUTH-005c` cancels active local child runs only from authority-issued run-record parent/child grant refs checked against a trusted `RevocationSnapshot`; message payloads, metadata, and forged refs remain non-authorizing. |
| Compatibility is additive | Current work-order and delegation fields map into typed profiles; they do not replace existing runtime checks. |

## Composite Effects

`evaluate_capability_request` evaluates one `AuthorityOperation` at a time. A
privileged effect that requires multiple authorities must receive a separate
successful decision for every required operation before gateway/driver execution.
For example, an `artifact.create` action decision is not sufficient to authorize
the selected adapter, compatibility permission, data-use purpose, driver
operation, or publication authority. Callers must construct and require all of
those operation decisions explicitly.

## Event, Trace, State, and Replay Expectations

This RFC does not add event or trace variants. `AUTH-003b` adds optional
authority-reference fields to existing local delegation message payloads, trace
contexts, run records, and replay summaries. `AUTH-004a` adds behavior-free
receipt contracts and local verification helpers. `AUTH-004b` records bounded
pre-effect obligation verification results, action digests, and decision-integrity
digests in existing `ActionOutcome.verification` artifacts so current trace events
can carry denial/allow evidence without adding new event names. `AUTH-005a`
returns normal `AuthorityDecision` records with stable cache/offline/revocation
reason codes; it does not add event names, durable revocation-watch events, or
trace sync behavior. `AUTH-005b` returns structured local renewal results with
stable nonce/current-revision/cache/snapshot/change/lifetime reason codes; it
does not add event names, durable lease/nonce events, or trace sync behavior.
`AUTH-005c` does not add event names or trace-schema fields; revoked local child
runs use existing task-response and `ChildRunFailed` trace behavior from the
local delegation finish path. Replay remains inspect-only: it uses recorded
parent/child grant refs and stable denial or cancellation reasons without
re-running authority evaluation, gateways, adapters, child runs, revocation
checks, receipt owning services, renewal preflights, offline cache refresh, or
other side effects. Future durable evidence-store and trace-schema work must
persist authority decisions, cache freshness, revocation-snapshot identity,
renewal nonce/current-revision evidence, child cancellation evidence, and
receipt-verification evidence as first-class evidence records before claiming
broader AUTH-004/AUTH-005 completion.

## Validation Matrix

| Area | Current local evidence | Gold status |
| --- | --- | --- |
| Contract serialization | `cargo test -p splendor-types authority --locked` covers typed operations, distinct data purposes, scope identity dimensions, grant/decision round-trip. | `G01/G18/G70` remain `not_exercised`. |
| Evaluation fail-closed | `cargo test -p splendor-authority --locked` covers missing, expired, revoked, wrong-audience, and missing-validation denial. | `G01` remains `not_exercised`. |
| Delegation narrowing | Authority tests cover child operation/scope/budget/audience broadening denial and monotonic intersections. | `G18/G70` remain `not_exercised`. |
| Scope binding | Authority tests cover missing audience, missing tenant/fleet, operation-specific scope, audience-only/budget-only scopes, and empty unbound grant/request denial. | `G01` remains `not_exercised`. |
| Scope time | Authority tests cover expired grant scope time, broader request scope time, missing request time when grant time is constrained, request time present when grant time is unconstrained, and narrowed child scope time expiry. | `G01/G18` remain `not_exercised`. |
| Signed grants | Authority tests cover signed dummy grants denying with `signed_grant_verifier_unavailable`. | Full AUTH-002 remains future work. |
| Trusted local profile wrapper | Authority tests cover compatibility builder `Result` success and fail-closed invalid generated profile denial. | Raw external grants remain non-authorizing contracts. |
| Composite effects | Authority tests cover action-only work-order compatibility grants not authorizing adapter or permission operations. | Not gateway integration evidence. |
| Non-authorizing metadata | Authority tests cover safe metadata not granting authority and reserved metadata denial. | `G01` remains `not_exercised`. |
| Compatibility profiles | Authority tests cover local `WorkOrder` allowlist profile mapping without broadening. | Not a full work-order issuance integration claim. |
| Bounded AUTH-002a issuance | Authority tests cover valid signed work-order grant issuance, raw signed grant denial, unsigned/bad-signature/expired/revoked work-order failures, inactive/revoked principal failures, binding mismatch failures, issuer-authority denial, quota/locality non-broadening, and secret/signature-safe errors. | `G60/G83` remain `not_exercised`; no workload-controller, node, fleet, or gateway integration claim. |
| Bounded AUTH-003a delegation | Authority tests cover local delegation contract round-trip, positive child grant issuance, parent-obligation preservation, missing/wrong parent edge, issuer mismatch, child subject missing/wrong, overbroad operation/scope/audience/time/budget/depth/fan-out, exhausted depth, fan-out exceeded, bad message schema/recipient, revoked/expired/not-yet-valid parent, and critic/evaluator external-effect/control-plane delegation denial. | `G18/G70/G71` remain `not_exercised`; no local-delegation manager, message routing, gateway, trace, revocation propagation, or gold fixture integration claim. |
| Bounded AUTH-003b local delegation wiring | Kernel tests cover positive local child-run creation with run-bound principal plus parent/child grant refs in run record, `TaskRequest`, trace context, and replay; authority denial before `DelegationRequested`/routing/child insertion; parent principal mismatch denial, including agent re-registration after root-run creation; expired/not-yet-valid parent grant denial at actual decision time; future child grant window denial before routing; missing runtime authority evidence despite forged message payload evidence; and unchanged delegated action denial before gateway/adapter execution. | `G18/G70/G71` remain `not_exercised`; no daemon/API, gateway verifier, revocation propagation, or gold fixture integration claim. |
| Bounded AUTH-004a obligations | Types tests cover conditional decision and obligation receipt serialization with receipt ID, issuer, audience, revocation source, and validation material. Authority tests cover grants without obligations still returning `Allowed`, grants with obligations returning `Conditional`, raw/forged receipt denial before validation, wrong issuer/audience/key/signature denial, exact validated receipt success, duplicate receipt ID denial, duplicate obligation ID denial, extra receipt denial, changed request/scope/params digest mismatch, missing/wrong obligation ID, wrong decision, wrong subject, wrong kind, expired, revoked, malformed evidence digest, unsupported schema, non-conditional decision denial, and conditional parent delegation denial before child grant creation. | `G11/G43/G75/G79` remain `not_exercised`; no gateway verifier, approval workflow, gate-engine, MFA, data-use, quota, safety, daemon/API, TS/Python, adapter execution, production PKI, or external revocation-introspection claim. |
| Bounded AUTH-004b gateway obligation verification | Gateway tests cover valid exact trusted receipts allowing adapter execution when required, missing evidence requiring intervention before adapter execution, raw/forged receipts denying before adapter execution, changed gateway action digest denying, tampered full-decision digest denying, operation/tenant/agent/run scope mismatch denying, expired/revoked/wrong/extra/duplicate receipts denying, and legacy `ApprovalEvidence` alone not satisfying authority obligations. Existing gateway policy/resource/approval/quota/safety/postcondition tests continue to run. TypeScript schema-parity tests cover the optional primitive field without exposing a daemon/client workflow. | `G11/G43/G75/G79` remain `not_exercised`; no approval workflow engine, MFA provider, gate engine, durable evidence store, production PKI, external revocation introspection, daemon/API/client workflow, Python, or full AUTH-004/C02 completion claim. |
| Bounded AUTH-005a local revocation/cache | Authority tests cover revoked `RevocationRecord` denial over a cached active grant, missing/stale/expired/future-dated cache denial, missing/stale/future-dated revocation snapshot denial, disconnected explicit low-risk data and device-sensing read allow within cached scope/TTL, disconnected scope mismatch denial, unsupported offline read denial, disconnected high-risk device/change/agent-delegation denial or intervention only after matching cached authority, offline TTL expiry denial, and cache APIs that accept validated grants without extending grant expiry. | `G73/G88` remain `not_exercised`; no production revocation service, revocation watches, external introspection, lease renewal, node/fleet/policy-cache consumption, incident-controller integration, delegated child revocation propagation, daemon/API/client workflow, or full AUTH-005/C02 completion claim. |
| Bounded AUTH-005b local renewal preflight | Authority tests cover positive renewal from a fresh cached validated grant and active snapshot with matching nonce/current digest, nonce missing/mismatch denial, current digest mismatch denial, missing/non-renewable policy denial, revoked grant/snapshot denial, missing/stale/future-dated snapshot denial, stale/expired/future-dated cached grant denial, changed grant identity/issuer/subject/operations/scope/audience/revocation/obligation/parent/validation-kind/delegation-depth/start-time denial, maximum renewal/offline lifetime denial, and renewed cache expiry not outliving renewed grant expiry. | `G73/G88` remain `not_exercised`; no durable nonce/replay store, production lease service, revocation watches, external introspection, node/fleet/policy-cache consumption, incident-controller integration, delegated child revocation propagation, daemon/API/client workflow, or full AUTH-005/C02 completion claim. |
| Bounded AUTH-005c delegated child revocation | Kernel tests cover revoked child grant cancellation, revoked parent grant cancellation, unrelated revocation no-op, terminal child no-op without duplicate response/trace, and replay reconstruction through existing `ChildRunFailed` events. Authority tests cover the snapshot revoked-grant-ID helper. | `G18/G70/G71/G73/G88` remain `not_exercised`; no production revocation service/watch, external introspection, daemon/API/client workflow, gateway/node/fleet/policy-cache/incident integration, cleanup obligations, durable evidence store, or full AUTH-003/AUTH-005/C02 completion claim. |

## Future Implementation Requirements

Future PRs that claim more of C02/AUTH-001/AUTH-002/AUTH-003/AUTH-004/AUTH-005
must add executable integration evidence before changing gold status or closing
issues:

- durable gateway/driver evidence integration beyond the bounded local AUTH-004b
  verifier, including first-class evidence-store records and trace-schema
  assertions for pre-effect authority decisions;
- full work-order issuance/signature validation integration (`AUTH-002`),
  including workload-controller admission wiring, node-side validation, renewal
  semantics, one-time/non-renewable grant lifetimes, and executable `G60/G83`
  fixtures;
- multi-agent delegation chain and causal message fixtures (`AUTH-003`, `G18`,
  `G70`, `G71`), including executable gold coverage for the local delegation
  manager bridge beyond the bounded local AUTH-003b/AUTH-005c evidence, cleanup
  obligations, durable evidence storage, and gateway authority-verifier
  integration;
- obligations/approval workflow integration (`AUTH-004`) beyond the bounded local
  gateway verifier, including owning approval/MFA/gate receipt services,
  re-evaluation after obligation satisfaction, durable evidence/trace schema, and
  executable `G11/G43/G75/G79` fixtures;
- full revocation records/watches, renewal protocols, offline cache consumption,
  production delegated child revocation propagation, stale-authority evidence, and
  executable `G73/G88` fixtures beyond the bounded local AUTH-005a cache/snapshot
  foundation, AUTH-005b renewal preflight, and AUTH-005c local child cancellation
  bridge (`AUTH-005`);
- decision evidence/explainability and replay integration (`AUTH-006`);
- adversarial/property suites (`AUTH-007`).

## Summary

This RFC and implementation slice introduce typed, deterministic local
capability, issuance, bounded delegation, conditional obligation receipt, local
revocation/offline cached-grant, renewal-preflight, and delegated child
revocation foundations plus runtime-local delegation grant-reference wiring while
preserving Splendor's kernel invariants: no side-effect bypass, fail-closed
authority checks, no permission laundering, no message or metadata authority,
identity separation, offline cache and renewal are not ambient authority, and no
gold completion claim without executable evidence.
