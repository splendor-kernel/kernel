# RFC 0010 - Authority Service Capability Contract

## Status and Scope

Status: Draft, with bounded local `AUTH-001`, `AUTH-002a`, `AUTH-003a`,
`AUTH-003b`, `AUTH-004a`, `AUTH-004b`, `AUTH-005a`, `AUTH-005b`, and `AUTH-005c`
implementation evidence slices plus bounded local `AUTH-006a` decision evidence
and deterministic `AUTH-007a` adversarial/property plus `AUTH-007b` serialized
mutation evidence, bounded `AUTH-007c` local-delegation confused-deputy replay
evidence, bounded `AUTH-007d` exact-family version/cache-staleness evidence, and
a completed non-gold production-local daemon/kernel/gateway C02 service
integration for the current run-effect surfaces.

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
trusted live authority snapshot and cancels active child runs when run-record
parent or child grant refs are revoked or snapshot liveness is uncertain. A
bounded authority-owned `AUTH-006a` module now constructs deterministic local
decision evidence, redacted explanation views, explicit completeness/freshness
facts, and inspect-only comparisons. The existing gateway obligation verifier
artifact projects only the redacted evidence digest and normalized reason-tree
summary after trusted receipt validation and exact matching.
The production-local integration admits one opaque live run-authority handle only
from `ValidatedWorkOrder`, evaluates typed action, effective-adapter, and
permission operations for every daemon run effect, and records redacted authority
decision evidence through the shared runtime cursor after all pre-effect checks
allow and before adapter execution. Direct `/actions`, scheduler/loop actions,
and the existing run-bound simulated physical action path use this composition.
The compatibility admission is explicitly temporary because the daemon does not
yet receive C01 issuer/subject proof facts; it cannot consume raw or unsigned work
orders and should be replaced by `issue_work_order_capability_grant` when the
downstream C01 provider supplies those facts.
`AUTH-007a` adds a dependency-free, seed-reproducible unit-test corpus over the
implemented local capability algebra, delegation builder, revocation/cache
evaluator, and evidence normalization. It runs bounded 256- or 512-case
properties with fixed timestamps and deterministic identities; every property
failure reports its seed and case.
`AUTH-007b` adds 640 dependency-free serialized mutation cases: 128 each for
capability grants/requests, signed work-order issuance, obligation receipts,
delegation grants/chains, and nested metadata/extensions. Every seeded fixture
first passes a positive control, then a named mutation either fails serde or is
denied by the existing trusted local validation, issuance, matching, or
evaluation path. Corpus assertion and fixture/setup failures report fixture,
mutation, and seed.
`AUTH-007c` fixes and tests the production-local delegation manager boundary:
registered root runs remain unbound for non-delegating compatibility, but must be
explicitly and immutably bound to one trusted `ValidatedCapabilityGrant` before
creating child work. The Authority Service privately retains exact validated
root/child grants and issues opaque caller/runtime handles; kernel contexts expose
only handles and grant IDs as evidence.
Grant IDs are unique across root and child bindings within one manager, grant
subjects must match the run principal snapshot, and child creation rejects a
missing, content-mismatched, or colliding binding before request, routing,
child-start, insertion, or fan-out effects. Successful child records retain an
opaque live authority handle bound to the complete immutable chain. The local
authority ledger supports recursive narrowing, exact child agent/run bindings,
atomic aggregate budget/fan-out reservations, cumulative per-tick action
accounting, cleanup, and descendant revocation while depth remains. A final
delegated-action permit is retained through gateway entry.
`AUTH-007d` adds an exact-family current-v1 versus v0/v2 rejection matrix for
authority operations, scopes, grants, requests, revocation records, and policy
bundles. It also closes the policy-distribution gap that previously accepted a
validly signed bundle whose `issued_at` was after the receiver's validation
clock. Equality is accepted, while any positive skew returns
`future_issued_policy_bundle` before cache installation. Trusted-wrapper cache
tests cover connected and explicit low-risk offline allows plus stale,
future-dated, expired, revoked, stale-snapshot, future-snapshot, and offline-TTL
denials. Daemon sync tests retain the last trusted cache after
unsupported/future/expired candidates, apply the existing revocation block for a
revoked candidate, record rejection/sync-failure traces, and keep blocked action
attempts at zero adapter calls.

This slice retains the backward-compatible daemon/OpenAPI/TypeScript fields for
raw obligation receipts. AUTH-003 hardening intentionally versions the live task
request, delegation edge/chain, and redacted trace-summary contracts to v2: live
task requests require `capability_grant_id`, and default trace evidence no longer
exposes full grants/chains. It does not add
an authority revocation/watch endpoint, change endpoint names, or change Python,
fleet behavior, node admission,
workload-controller wiring, approval
workflow execution, MFA/provider integration, gate-engine migration, obligation
receipt storage, production PKI, external revocation introspection, production
lease renewal, revocation watches, incident-controller integration, or introduce
a new adapter execution path. It adds local trace/message/run-record authority
reference fields for `AUTH-003b`, v2 edge binding digests, cleanup obligations,
and redacted delegation-ledger trace summaries. Legacy task-request v1 is
non-authorizing replay/migration data and is not accepted for live delegation
creation. It also retains optional
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
`AUTH-007d` does change the public Rust cache API and daemon-visible behavior:
`PolicyCache` construction requires an explicit tenant+agent owner, policy
mutation uses validated-wrapper-only high-level traced methods with private
cache-instance/revision-bound plans, direct reconnect/raw insertion/public
commit seams are removed, revocation watermarks are retained, and stable
owner/watermark/concurrent-mutation denials are observable. Daemon
endpoint/request-response and trace-event wire shapes remain unchanged.
Post-trace revocation commit races preserve the exact validated candidate and
atomically latch it as pending deny-only evidence when it remains applicable;
strictly newer active winners are not poisoned by obsolete revocation.
It finalizes the non-gold production-local C02 service effect path for current
daemon runs. This completion statement is limited to current local/resident
daemon run effects; future Artifact, Driver, Data-Use, Evidence, Fleet, and
physical helper-plan consumers remain explicit downstream adoption work. It
does not claim all future privileged-plane adoption, full C01-backed issuance,
full `AUTH-001`, full `AUTH-002`, remote/controller AUTH-003 adoption,
full `AUTH-004`, full `AUTH-005`, full `AUTH-006`, G01, G03, G11, G18, G43,
G60, G70, G71, G73, G75, G79, G80, G83, G86, G88, full `AUTH-007`, issue
closure, or gold completion.

Until exact executable fixtures pass, gold targets `G01`, `G03`, `G11`, `G18`, `G43`,
`G60`, `G70`, `G71`, `G73`, `G75`, `G79`, `G80`, `G83`, `G86`, and `G88` remain
`not_exercised`.

## Binding

| Item | Binding in this RFC | Evidence status |
| --- | --- | --- |
| Aggregate issue | #182, `0.2/v2 component: C02 splendor.authority-service - Authority Service` | Aggregate target only; not complete. |
| Child issue | #238, `AUTH-001 - Define a composable capability and scope model` | Bounded local evidence only; not complete. |
| Catalog task | `AUTH-002 - Implement issuance and signed work-order integration` | Bounded `AUTH-002a` Rust bridge evidence only; not complete. |
| Catalog task | `AUTH-003 - Implement delegation chains and sub-agent authority narrowing` | Bounded C02-owned non-gold local authority chain/accounting/runtime evidence only; catalog-wide completion, remote Message Service/Agent Controller adoption, and gold remain downstream/not exercised. |
| Catalog task | `AUTH-004 - Implement obligations and approval requirements as authority results` | Bounded `AUTH-004a` conditional decision/receipt matching plus `AUTH-004b` local gateway receipt verification evidence only; not complete. |
| Catalog task | `AUTH-005 - Implement revocation, lease renewal, and offline authority behavior` | Bounded `AUTH-005a` local revocation snapshot/offline validated-grant cache, `AUTH-005b` local renewal preflight, and `AUTH-005c` local delegated child revocation propagation evidence only; no production lease renewal or production revocation service. |
| Catalog task | `AUTH-006 - Implement authority decision evidence and explainability` | Bounded `AUTH-006a` deterministic local records/redacted views/wrappers/inspect-only comparison and gateway artifact projection only; no Evidence Service, durable bundle/store, policy archive, or historical re-evaluation. |
| Catalog task | `AUTH-007 - Build authority adversarial/property test suites` | Bounded `AUTH-007a` deterministic local algebra/delegation/revocation/evidence properties, `AUTH-007b` deterministic serialized mutations, `AUTH-007c` production local-delegation replay hardening/matrix, and `AUTH-007d` exact-family version/cache-staleness plus daemon policy-sync evidence only; no cargo-fuzz/libFuzzer, all-plane confused-deputy harness, cross-language IAM parity, mutation testing, formal proof, or full task completion. |
| Component | `splendor.authority-service` | Production-local daemon/kernel/gateway run-authority integration; future privileged planes remain downstream adoption. |
| Owner packages | `splendor-types` for behavior-free contracts; `splendor-authority` for evaluation/narrowing decisions | Current slice follows this ownership. |
| Gold targets | `G01`, `G03`, `G11`, `G18`, `G43`, `G60`, `G70`, `G71`, `G73`, `G75`, `G79`, `G80`, `G83`, `G86`, `G88` | `not_exercised` until executable fixtures/harnesses pass. |

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
- No daemon endpoint redesign, Python, fleet, product, or physical safety
  redesign. Additive raw-receipt and replay-summary fields keep daemon/OpenAPI/
  TypeScript contracts aligned. `AUTH-007d` also changes daemon policy-sync
  behavior and the public Rust cache API as described above.
- No full data-use controller, secret broker, approval workflow, offline lease
  renewal, production revocation propagation service, revocation watches,
  external introspection, or incident-controller quarantine workflow.
- No universal wildcard or metadata/extension-based authority.
- No new daemon authority-control endpoint. The local process composition exposes
  only a bounded trusted revocation command for deterministic local control and
  tests. No Python client workflow update, gold fixture, production revocation
  watch, external introspection, node/fleet
  propagation acknowledgement, policy-cache consumption, or incident-controller
  quarantine flow for delegated children.
- No approval workflow engine, MFA provider, gate-engine migration, durable
  evidence store, production PKI, external revocation introspection, or full
  gateway/daemon/client obligation workflow in `AUTH-004a`/`AUTH-004b`.
- No full `AUTH-005` completion claim; `AUTH-005a` is only local Rust cache and
  revocation snapshot behavior over already validated grants, `AUTH-005b` is only
  local renewal preflight, and `AUTH-005c` is only local manager consumption of a
  trusted snapshot for already-running local child runs.
- No durable Evidence Service/bundle/store or access-control service, event/trace
  schema, policy archive, historical-policy re-evaluation, protected-eval
  subsystem, daemon/API/client workflow, or full FND-009 implementation. Local
  `AUTH-006a` evidence is inspect-only and is never authority.
- No claim that `G01`, `G03`, `G11`, `G18`, `G43`, `G60`, `G70`, `G71`, `G73`, `G75`,
  `G79`, `G80`, `G83`, `G86`, or `G88` passed.
- No cargo-fuzz/libFuzzer or unbounded/random fuzz harness, all-plane
  confused-deputy coverage, cross-language IAM/cache parity matrix, mutation
  testing, formal proof, external fixture publication, or full `AUTH-007` claim.
  `AUTH-007a` through `AUTH-007d` are bounded deterministic local
  corpora/integration evidence only. They do not cover Driver, Artifact Registry,
  physical helper-plan, remote/fleet confused-deputy paths, or a canonical
  historical policy-signature migration seam. TypeScript/OpenAPI parity in this
  slice is limited to the exact local receipt and registered-action profile
  fields; it is not cross-language IAM/cache parity.
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
  with an opaque authority-owned caller handle, child principal, audience, and
  non-authorizing parent/child grant refs;
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
  gateway submission and is not standalone capability authority;
- `InMemoryDelegationAuthorityLedger` is the sole local validity/accounting owner:
  it stores exact roots and complete immutable ordered chains, validates each
  edge and semantic binding digest with deterministic index/reason, owns exact
  child agent/run bindings and fan-out, atomically reserves every budget component
  across direct subtrees, cumulatively accounts action usage by tick, and records
  reservation lifecycle;
- issued child grants may recursively narrow only through their exact run binding
  and an explicit authority-owned parent-to-child runtime edge, never merely
  because another child binding appears in the same root scope;
- every delegated action carries the exact issued child grant ID, evaluates the
  live ledger-owned handle against maximum-observed trusted service time, latches
  observed expiry, and retains a final permit through gateway entry;
- cancellation/revocation propagates through descendants, closes admission before
  a bounded typed quiescence wait, and stays closed after timeout. Message payload
  grant refs and caller-supplied timestamps remain evidence/input data only.

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

- `RevocationSnapshot` exposes authority-owned helpers for snapshot liveness and
  live revoked-`CapabilityGrantId` lookup; the kernel consumes the helper result
  and does not independently interpret snapshot freshness/expiry;
- `LocalDelegationManager::cancel_child_if_authority_revoked` consumes a trusted
  `RevocationSnapshot`, reads the child run record's
  `LocalDelegationAuthorityEvidence`, and cancels active child runs when a
  recorded parent or child grant ID appears as revoked in the snapshot or the
  trusted snapshot fails its authority-owned liveness check;
- stale or future-dated trusted snapshots cancel active child runs fail-closed
  with `TaskFailure` codes `authority_revocation_snapshot_stale` or
  `authority_revocation_snapshot_future_dated`, `retryable=false`;
- revocation cancellation invalidates the authority-ledger subtree and marks
  active descendants terminal/cancelled before fallible response routing. Existing
  trace failure behavior returns the error without leaving authority active;
- root-run registration participates in the same local lifecycle lock and
  returns the local `DuplicateRun` error for every existing root or child run ID;
  it never replaces active or terminal run records, authority evidence, or
  delegated scope;
- an active record known to be a child by `parent_run_id` but missing
  `LocalDelegationAuthorityEvidence` cancels fail-closed with stable reason
  `missing_authority_evidence`; root records remain outside this child API;
- successful cancellation emits `TaskResponseStatus::Cancelled` and `ChildRunFailed`
  trace behavior with stable failure reason codes so replay can inspect the
  cancellation without re-running authority checks;
- unrelated revocations and terminal child runs are deterministic no-ops and do
  not emit duplicate responses or trace events;
- message payload grant refs remain non-authorizing and are not inspected for
  revocation authority;
- cleanup/revocation obligations and complete subtree evidence are retained in
  the local ledger and replay;
- this remains local snapshot consumption only: no production revocation watch,
  external introspection, daemon/API/client workflow, gateway verifier, node/fleet
  policy-cache integration, incident-controller quarantine, durable evidence
  store, or gold fixture is added.

The bounded `AUTH-006a` slice adds local decision evidence in
`splendor-authority::evidence` and a redacted gateway artifact projection:

- decision-only, validated-grant evaluation, and cached evaluation records state
  their completeness and missing facts explicitly; they do not fabricate policy,
  data-use, grant-revision, or cache facts that the caller did not supply;
- records retain decision/subject/grant/obligation identity, a canonical typed
  operation classification, status/timestamp, domain-separated restricted grant
  validation/revision digests, bounded normalized reason codes, deterministic
  category branches, and available cache/snapshot freshness facts;
- requester-provided reason text is never preserved: known evaluator patterns map
  to bounded static codes and every unknown, hostile, oversized, control/ANSI, or
  misleading value maps to `authority_reason_unknown`;
- caller-provided decision/request/operation/resource/grant/scope/obligation
  schema strings are never copied; evidence records only canonical/static validity
  classifications where applicable;
- exact request/scope and concrete operation-name binding is explicitly
  missing/withheld. This local serializable model does not publish low-entropy
  unkeyed request/operation digests; exact binding requires a future keyed,
  access-controlled evidence service;
- raw request scopes, request/grant metadata, signatures, key IDs/material,
  credentials, nonces, concrete operation names/protected-eval IDs,
  revocation-record payloads, obligation descriptions, and obligation parameters
  are never copied into evidence records;
- restricted evidence may retain domain-separated grant token/revision digests;
  tenant/operator redaction preserves typed operation classification,
  decision/grant identity, causal normalized reason shape, status, and the safe
  decision-record digest while removing those restricted grant digests;
- normal and cached wrappers call the existing evaluators unchanged; evidence
  construction failure returns a stable unavailable error instead of fabricating
  evidence or converting a denial/conditional result to allow;
- comparison accepts only two already-recorded evidence objects labelled
  historical/current/counterfactual and reports status/reason/digest changes; it
  does not load policy, resolve secrets, contact revocation providers, invoke the
  gateway/adapter, mutate history, or claim historical policy re-evaluation;
- the existing `authority_obligation_result` artifact adds a decision-only
  redacted evidence digest, completeness, and normalized explanation summary only
  after trusted local receipts validate and match the exact conditional decision;
  no-verifier, unavailable, or early-denial paths retain only bounded typed
  compatibility coordinates (decision ID/static status, obligation IDs, and
  receipt IDs). They do not retain requester reasons, schemas, metadata/digest
  strings, or detailed evidence projection. If final projection fails, the
  gateway returns `NeedsIntervention` and does not execute the adapter.

The bounded `AUTH-007a` slice adds local adversarial/property coverage:

- 256-case scope properties prove no broadening, semantic commutativity after
  canonical set normalization, idempotence, and deterministic rejection of
  empty/disjoint dimensions;
- 512-case budget properties cover `None`/bounded/extreme-value intersections
  and repeated narrowing without arithmetic overflow or authority growth;
- 256-case fixed-time properties cover exact grant start/expiry boundaries,
  child-window narrowing, and denial stability when unrelated grants are added;
- 256-case audience/subject/metadata properties prove mismatches remain denied,
  reserved or hostile extension keys do not authorize, and malformed local
  grants are rejected by the real local validation path;
- 256-case delegation properties cover strictly decreasing depth, exhausted
  depth/fan-out, bounded child budgets/windows, and critic/evaluator denial for
  external-effect or delegation-control operations;
- 256-case revocation/cache properties cover active-to-revoked monotonicity,
  unrelated active-record resistance, and missing/stale/future cache/snapshot
  uncertainty remaining non-allowing;
- 512-case denial/evidence properties prove ordered reason stability for the
  same facts and bounded normalization/redaction of generated hostile reasons.

The bounded `AUTH-007b` slice adds serialized mutation coverage:

- 128 capability grant/request cases exercise missing/null/wrong-type fields,
  unknown schemas/enums, nil identities, wildcard and duplicate/set ambiguity,
  nested reserved metadata, validation removal/forgery/downgrade, and the real
  raw-grant-to-validated-wrapper boundary;
- 128 signed work-order cases exercise missing/blank/forged/unknown-key
  signatures, post-signing identity/scope/allowlist/quota/locality/time tampering,
  malformed quota/data-ref shapes, and trusted re-sign controls for actual
  expiry, revocation, and tenant-binding denial through AUTH-002a issuance;
- 128 obligation-receipt cases exercise malformed trust material, identity,
  audience, decision/request/subject/obligation mismatches, expiry/revocation,
  and validly issued duplicate/extra receipt ambiguity through exact matching;
- 128 delegation grant/chain cases reissue each deserialized edge from a trusted
  validated root and reject missing/reordered/duplicate parent edges, reused or
  cyclic child identities, depth/fan-out/time/budget/scope widening, wrong
  issuer/subject/audience/message contracts, and critic/evaluator effects;
- 128 nested metadata cases cover reserved authority, approval, capability,
  credential, driver, gateway, policy, quota, secret, signature, verifier, and
  work-order key variants under objects and arrays with case/separator aliases;
  hostile descriptions or parameters never satisfy a missing receipt and
  redacted decision evidence omits mutation sentinels.

The bounded `AUTH-007c` slice adds local delegation replay hardening and evidence:

- `LocalDelegationManager::bind_root_run_capability_grant` accepts only a trusted
  `ValidatedCapabilityGrant`, checks its subject against the root run's immutable
  principal snapshot, privately stores the exact validated grant/trust state, and
  stores its immutable grant ID on the public run record as evidence only;
- same-run retry is idempotent only for exact `ValidatedCapabilityGrant`
  equality. Different content/trust with the same ID, a different grant for the
  same run, the same ID for another root/child run, a subject mismatch, or an
  attempt to explicitly bind an existing child record returns a structured
  fail-closed result;
- `register_root_run` remains compatible and may create an unbound root for
  non-delegating use, but `create_child_run` denies such a root with
  `missing_parent_run_grant_binding`;
- a supplied trusted parent grant that differs from the exact private root
  binding, including same-ID mutations, denies with
  `parent_run_grant_mismatch`;
- both binding denials record exactly one existing `DelegationRejected` event
  when the parent recorder is available and occur before
  `DelegationRequested`, task message routing, `ChildRunStarted`, child insertion,
  or parent fan-out mutation;
- successful child records remain automatically bound to their authority-issued
  exact validated grant and complete immutable chain, but `LocalChildRun` and
  `AgentContext` expose only opaque authority handles and non-authorizing IDs;
- proposed child grant IDs colliding with any existing root or child private
  binding deny with `child_capability_grant_id_collision` before request, routing,
  child-start, insertion, or fan-out mutation;
- `LocalDelegationReplay.rejections` preserves rejection context plus the stable
  reason without executing policy, authority, routing, or side effects;
- the deterministic public-manager matrix covers intended context, different
  tenant, cross-agent shared-principal and cross-run replay, different principal,
  child agent, child run, audience, unrelated authority evidence, and unrelated
  trusted grant. It asserts exact reasons, one rejection, unchanged run record,
  empty inbox/outbox, no child insertion/start/request trace, and no gateway or
  adapter path. Authority-owned fan-out/budget reservations remain unchanged on
  pre-reservation denial;
- typed instance binding and an independently supplied response-recipient
  coordinate remain unexpressible in this local API. The audience string and
  request target are covered without inventing a bypass.
- recursive local delegation uses the exact issued child grant and complete chain.
  It succeeds only for an explicitly assigned parent-to-child runtime edge and
  remaining depth; a broader replacement, root-sibling substitution, or nested
  escalation denies before effects and identifies the applicable stable reason.
- grant-ID uniqueness is local to one `LocalDelegationManager`. The different-
  tenant matrix case uses a separate manager only to exercise grant tenant-scope
  denial and makes no cross-manager, cross-instance, or typed-audience claim.
- the `LegacyMultiScopeProfile` compatibility builder uses the existing
  local-profile validator to create one bounded parent grant over explicit,
  non-empty child agent/run ID lists. This restores the one-manager,
  one-parent/two-specialist E2E without duplicating the parent across managers;
  empty/nil lists and invalid or wildcard-like audiences fail closed. Raw
  capability containment still treats agent and run lists as independent set
  dimensions, but trusted root admission zips equal-length lists into exact,
  immutable direct-root child bindings. Empty, unequal, duplicate, nil, or
  recombined pairs deny with `delegation_child_runtime_binding_denied`. The
  additive explicit-edge root-binding API defines nested local topology without
  changing the behavior-free `CapabilityScope` schema.
- live delegated messages use `splendor.message.task_request.v2` and require the
  authority-owned child grant reference. v1 is retained only for non-authorizing
  replay/migration data. Delegation edge and chain schemas are v2 and each edge
  carries an exact semantic binding digest.
- normal trace/replay payloads use `DelegationLedgerTraceSummary` v2 rather than
  serializing full grants, scopes, objectives, allowlists, obligations, result
  parameters, or budget values. Complete chain evidence remains authority-owned.
- the binding API is trusted local run-admission setup and has no new durable
  trace event in this bounded slice. Adding such an event would expand the public
  trace schema; no durable binding-mutation trace claim is made.

The bounded `AUTH-007d` slice adds exact-family version and staleness evidence:

- current `v1` authority operation, capability scope, capability grant,
  capability request, revocation record, and policy bundle families have positive
  controls; exact-family `v0` and `v2` values deny with stable existing schema
  reasons rather than being interpreted as adjacent-compatible versions;
- closed validation/operation enums reject unknown serialized values through
  serde, and raw unsupported grants fail production local-profile validation
  before a trusted wrapper or authority cache can be constructed;
- policy compatibility uses `PolicyBundle.schema_version`; the free-form
  operator/audit `PolicyBundle.version` label never selects a schema family;
- a signed current-v1 policy with `issued_at > validation.now` returns the new
  structured `FutureIssued` validation error and stable reason
  `future_issued_policy_bundle`; `issued_at == validation.now` remains valid when
  every other check passes;
- trusted authority cache fixtures start from `grant_from_legacy_allowlists` and
  pass the production local-profile validator; no unchecked validated-grant test
  helper is used. The matrix proves connected/live-snapshot and explicit
  disconnected low-risk read allows, then exact stale/future/expired cache,
  stale/future snapshot, live revocation, and offline-TTL denials;
- daemon policy sync rejects unsupported, future-issued, expired, and revoked
  candidates, emits existing `PolicyBundleRejected` and `PolicySyncFailed`
  events, preserves the last trusted cache for unsupported/future/expired
  candidates, and applies the existing current-cache revocation block for the
  matching revoked candidate. Blocked action attempts execute no adapter;
- correction hardening makes policy installation consume only
  `ValidatedPolicyBundle` with trusted validation time, signature algorithm, and
  key ID metadata; raw bundle/envelope cache insertion APIs are removed;
- signed installation is monotonic by `issued_at` and exact signed bundle
  content, never by the free-form audit `version`: older candidates deny with
  `policy_cache_install_rollback`, equal-time different-content candidates deny
  with `policy_cache_install_conflict`, and exact retries are idempotent without
  clearing revocation or expiry tombstones. A strictly newer validated candidate
  may explicitly refresh authority and clear those tombstones;
- a signed revoked candidate blocks current authority only when bundle identity,
  tenant/agent scope, and non-older issuance match. Older or unrelated revocations
  produce stable sync failures and cannot mutate current authority;
- disconnection may be recorded before a failed sync, but reconnect is atomic
  with an accepted trusted monotonic install. Validation, revocation, rollback,
  or signature failure cannot reconnect the cache;
- runtime observation tracks trusted validation/maximum time and latches expiry.
  Clock rollback denies policy invocation and action verification with
  `policy_clock_rollback`; observed expiry cannot become active after time moves
  backwards;
- the exact trusted revoked candidate is retained as a watermark. Intermediate
  active replay and older/equal-conflicting revocations cannot supersede it;
  only an active candidate strictly newer than current authority and watermark
  clears it;
- caches are tenant+agent owner-bound, including validation context for
  tenant-wide bundles and action-request identity checks;
- install/reconnect/revocation enters only high-level cache methods that invoke a
  trusted recorder; internal plans cannot be committed by callers. Active trace
  failure leaves authority/connectivity unchanged. Matching revocation trace
  failure latches an exact deny-only pending watermark and returns
  `policy_evidence_unavailable`; durable retry reconciles it. Partial prepared,
  non-authorizing trace is permitted and replay does not prove commit;
- a historical 0.04-shaped `splendor.policy_bundle.v1` payload signed over the
  old one-field degraded-mode serialization decodes with current defaults but
  fails current signature verification with `bad_policy_signature`. This is a
  characterization, not a compatibility claim; canonical source-byte or explicit
  migration/version handling remains absent.

### Production-local daemon/kernel/gateway integration

- `splendor-authority::LocalSignedWorkOrderRunAuthority` accepts only the opaque
  `ValidatedWorkOrder` produced by signature, expiry, revocation, tenant, agent,
  run, and placement validation. Its explicitly named compatibility admission
  binds an unbound work order to the resolved local run and cannot self-mint from
  a raw request body.
- The compatibility grant uses synthetic opaque local principal IDs because the
  current daemon has no C01 issuer/subject proof provider. This is not an identity
  claim. Downstream C01 adoption must supply active principals, signing-key proof
  binding, and issuer workload-admission authority to
  `issue_work_order_capability_grant`, then preserve the same kernel handle.
- `splendor-kernel::RunAuthorityHandle` is the daemon-facing composition facade;
  the daemon does not depend on `splendor-authority`. Every effect evaluates one
  typed gateway-action operation, one effective-adapter operation, and each
  required-permission operation against the live grant. Existing tenant/agent
  allowlists can narrow the result but cannot create an allow without C02.
- Grant expiry, maximum observed trusted time, and the monotonic local revocation
  latch are checked on every effect. Clock rollback fails closed with
  `authority_clock_rollback`, and observed expiry remains latched across rollback.
  The bounded local revocation command is process-composition only; no
  remote watch, introspection transport, or authority-control HTTP endpoint is
  introduced.
- `VerifiedActionGateway` records `ActionVerificationCompleted` through
  `KernelPreEffectAuthorityRecorder` after C02, existing policy/invariant,
  resource, approval/obligation, quota, and safety checks allow, but before
  `ActionAdapter::execute`. The recorder shares the loop runtime cursor. Missing
  or failed durable append returns `NeedsIntervention` with zero adapter calls;
  outer daemon/loop code does not append a duplicate post-effect completion event.
- Admission derives an immutable trusted action profile for each work-order
  action. The profile fixes the action name, effective adapter, and exact required
  permission set. Request or policy permission omission, extra permissions,
  duplicate permissions, and adapter/action recombination deny before live
  authority evaluation. A present registered permission list must equal the full
  signed work-order permission set, contain no duplicates, and contain at most 64
  entries. Because the current signed work order has independent action/adapter
  lists and no exact pairing field, multiple allowed adapters make admission
  ambiguous and are rejected rather than accepting a caller-provided pairing.
- After every other pre-effect verifier allows, the gateway re-evaluates the
  exact typed operation tuple and acquires an owned final-effect permit. Expiry or
  revocation before acquisition denies with zero adapter calls. Revocation closes
  new permit admission and waits for earlier permitted adapter executions to
  leave the boundary; a permit that linearized before expiry remains valid while
  its required pre-effect evidence append and adapter call complete.
  Existing custom evaluator implementations inherit a `NotRequired` final-permit
  default for source compatibility; if they return an early live evaluation but
  do not implement the final permit, the gateway returns `NeedsIntervention`.
- Conditional live decisions regenerate the current decision in the gateway.
  Requesters may submit only raw receipts; requester-supplied decision envelopes
  are not the current authority. `LocalAuthorityObligationVerifier` validates the
  raw owning-service receipts against the regenerated action decision before the
  pre-effect evidence append. Current signed-work-order compatibility grants have
  no obligations; the conditional path is retained in production gateway code and
  exercised by the real gateway verifier/adapter test. Every submitted receipt
  must name a decision in the complete current conditional-decision set before
  partitioning; unknown extras are never ignored, and receipt IDs are globally
  unique across that complete submitted collection. After every other blocking
  verifier and final authority linearization, receipts are validated per
  operation, capped at 64 per request, and atomically claimed as one collection
  by an explicitly injected authority-owned ledger. Claim is the receipt effect
  linearization point and returns an owned permit retained through required
  evidence append and adapter execution. Expiry before claim denies; expiry after
  claim does not retroactively cancel that exact in-flight effect. Evidence append
  failure leaves the receipt burned fail-safe. Maximum observed trusted time and
  latched expiry prevent rollback reactivation. The current shared in-memory
  ledger is process-local and does not claim restart durability.
- Raw receipt, validation, and registered-action profile structs reject unknown
  fields in Rust; OpenAPI marks those objects closed, and TypeScript/OpenAPI
  parity tests cover exact fields and receipt bounds.
  `RegisteredAction.required_permissions` is additive and
  optional on the wire, but omission means the full signed work-order permission
  set, not no permissions. A present registered-action or create-run request array
  must equal that same full set; request-level subset narrowing is rejected rather
  than creating a profile whose executable meaning differs by layer.
- Scheduler-created `ActionRequest` values carry their `tick_id`; the started,
  single pre-effect completion, and terminal action records for that action retain
  the same tick identity and ordering.
- Direct daemon and run-bound physical actions allocate the effective action ID
  before verification. Started, exactly one completed, terminal, and outcome
  records use the shared run cursor with the same run/tenant/agent/action identity
  and no fabricated tick ID.
- The resident-mode daemon composition uses the same handle, profiles, final
  permit, evidence recorder, and replay behavior. Its retained test checks caller
  credential metadata, scope, tenant binding, audience, expiry, and revocation
  behind the existing C01 boundary; C02 does not cryptographically authenticate
  resident credentials. Production caller authentication and principal proof
  binding remain deferred to C01.
- Inspect-only replay reads durable verification records, including effect-free
  denials, and returns redacted typed decision summaries and digests. Allowed
  decisions are durably recorded before the effect. Replay does not call authority evaluators,
  receipt issuers/validators, the gateway, or adapters.
- Gold cases remain `not_exercised`. The retained non-gold router integration is
  component evidence only and is not a G01/G03/G60/G83 pass claim.

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
| Delegation accounting is atomic | The local authority ledger ignores caller fan-out as authority and atomically reserves immutable fan-out plus every bounded budget component across siblings and nested direct subtrees. Explicit rooted runtime edges prevent a child from treating a root sibling as its descendant. |
| Delegation time is monotonic | The local authority ledger uses authority-owned service time, remembers the maximum observation, latches expiry, rejects rollback, and cannot reopen a pruned HTTP minute bucket. |
| Delegation quiescence is bounded | Cleanup and subtree revocation close admission first, return a typed quiesced/timed-out result after a bounded wait, and never reactivate new permits after timeout. |
| Every edge is complete | Full ordered chains preserve exact grant/run/agent refs, monotonic depth, role, time, scope, budget, and cleanup requirements; the first failing edge is deterministic. |
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
| Child revocation uncertainty fails closed | Local `AUTH-005c` cancels active child runs when the trusted snapshot is stale or future-dated and marks the child cancelled before fallible trace or response routing. |
| Run identity cannot be resurrected | Root registration is lifecycle-serialized and rejects every existing run ID with `DuplicateRun`, preserving root/child identity, terminal state, and authority evidence. A known child with missing authority evidence cancels with `missing_authority_evidence`. |
| Evidence is never authority | Local AUTH-006a evidence and comparisons are inspection artifacts only and cannot satisfy capabilities, receipts, obligations, approvals, verifiers, or gateway execution. |
| Evidence is explicit and redacted | Completeness/missing/withheld fields prevent fabricated evaluator facts; reasons are bounded static codes; exact request/operation binding is declared missing; redacted views preserve safe identity/status/causal shape without raw scopes, caller schema strings, restricted grant digests, metadata, signatures, key IDs/material, or free-form obligation details. |
| Evidence projection follows trust validation | Gateway evidence projection occurs only after trusted local receipt validation and exact matching. Untrusted/early-denial artifacts preserve only typed decision/obligation/receipt coordinates for compatibility, never requester reasons, schemas, metadata/digests, or detailed projection; projection failure prevents adapter execution. |
| Property evidence is bounded and reproducible | Local `AUTH-007a` uses deterministic IDs, fixed timestamps, explicit seeded generation, real local grant validation/evaluation/delegation/revocation paths, and seed/case-labelled failures. It does not substitute for fuzz, gold, mutation, cross-version, or distributed confused-deputy evidence. |
| Serialized mutation evidence is bounded and trusted-path checked | Local `AUTH-007b` serializes canonical positive fixtures, round-trips every baseline fixture, asserts every mutation differs from its serialized baseline, and requires serde rejection or denial by existing validation/issuance/evaluation. Receipt semantic mutations are recomputed with the test-only trusted fixture key before exact denial checks; forged-signature mutations remain separate. It never constructs unchecked trusted wrappers, mocks signatures/audience/expiry/revocation, or treats deserialization as authority. |
| Parent grant replay is run-bound | Local `AUTH-007c` requires an explicit exact trusted root-run/validated-grant binding, including private trust state. Grant IDs are unique across root/child bindings within one manager; unbound, exact-content-mismatched, or child-ID-colliding creation denies before request/routing/start/child/fan-out effects with stable reasons. This is not cross-instance binding or durable binding-event evidence. |
| Version/cache uncertainty fails closed | Local `AUTH-007d` accepts only exact current-v1 authorizing families, rejects v0/v2 and unknown closed enums, rejects future-issued signed policies before install, installs only owner-bound `ValidatedPolicyBundle`, enforces current-authority plus exact revocation-watermark monotonicity, denies exact-retry reconnect, persists required trace before cache broadening, rejects runtime clock rollback, and preserves or blocks the last trusted daemon cache according to scoped revocation semantics. Historical same-label signatures are not called compatible when current normalization changes signed bytes. |
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

This RFC does not add event names. `AUTH-003b` adds optional authority-reference
fields to existing local delegation message payloads, trace contexts, run records,
and replay summaries. The additive optional delegation-ledger trace field carries
complete chain and reservation lifecycle evidence. `AUTH-004a` adds behavior-free
receipt contracts and local verification helpers. `AUTH-004b` records bounded
pre-effect obligation verification results, action digests, and decision-integrity
digests in existing `ActionOutcome.verification` artifacts so current trace events
can carry denial/allow evidence without adding new event names. `AUTH-005a`
returns normal `AuthorityDecision` records with stable cache/offline/revocation
reason codes; it does not add event names, durable revocation-watch events, or
trace sync behavior. `AUTH-005b` returns structured local renewal results with
stable nonce/current-revision/cache/snapshot/change/lifetime reason codes; it
does not add event names, durable lease/nonce events, or trace sync behavior.
`AUTH-005c` does not add event names or trace-schema fields; revoked or
snapshot-uncertain local child runs use existing task-response and
`ChildRunFailed` trace behavior when trace/router work succeeds. The child run is
still marked terminal/cancelled before fallible trace/router work, so a trace or
response-routing failure does not leave revoked/uncertain delegated authority
running. Replay remains inspect-only: it uses recorded parent/child grant refs
and stable denial or cancellation reasons without re-running authority
evaluation, gateways, adapters, child runs, revocation checks, receipt owning
services, renewal preflights, offline cache refresh, or other side effects.
`AUTH-006a` adds no event, trace, state, or wire schema. Its comparison helper is
inspect-only over supplied records and its gateway projection reuses the existing
authority-obligation verification artifact without re-running authority. The
projection is emitted only after trusted receipt validation/exact matching; a
projection failure fails closed before adapter execution.
`AUTH-007a`, `AUTH-007b`, and the authority/type portions of `AUTH-007d` are test
and documentation evidence only.
`AUTH-007c` adds a local Rust manager security/API tightening, an additive local
multi-scope compatibility profile, and replay rejection records, but no
serialized schema, new event kind, gateway, adapter, or remote authority
semantic. Its denials reuse `DelegationRejected`, and replay remains inspect-only.
The matrix does not execute gateway or adapter side effects.
The `AUTH-007d` production correction changes policy validation/cache mutation
semantics and daemon-visible reason behavior without changing endpoint,
request/response, event, or wire schema shapes. Daemon tests exercise existing
rejection/sync-failure/revocation traces and gateway denial semantics.
Future durable evidence-store and trace-schema work must persist authority
decisions, cache freshness, revocation-snapshot identity,
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
| Composite effects | Authority tests cover action-only work-order compatibility grants not authorizing adapter or permission operations; production-local daemon gateway tests evaluate all three typed operation classes. | Current daemon-run integration only; future planes remain downstream. |
| Non-authorizing metadata | Authority tests cover safe metadata not granting authority and reserved metadata denial. | `G01` remains `not_exercised`. |
| Compatibility profiles | Authority tests cover local `WorkOrder` allowlist profile mapping without broadening. | Not a full work-order issuance integration claim. |
| Bounded AUTH-002a issuance | Authority tests cover valid signed work-order grant issuance, raw signed grant denial, unsigned/bad-signature/expired/revoked work-order failures, inactive/revoked principal failures, binding mismatch failures, issuer-authority denial, quota/locality non-broadening, and secret/signature-safe errors. | `G60/G83` remain `not_exercised`; no workload-controller, node, fleet, or gateway integration claim. |
| Bounded AUTH-003a delegation | Authority tests cover local delegation contract round-trip, positive child grant issuance, parent-obligation preservation, missing/wrong parent edge, issuer mismatch, child subject missing/wrong, overbroad operation/scope/audience/time/budget/depth/fan-out, exhausted depth, fan-out exceeded, bad message schema/recipient, revoked/expired/not-yet-valid parent, and critic/evaluator external-effect/control-plane delegation denial. | `G18/G70/G71` remain `not_exercised`; no local-delegation manager, message routing, gateway, trace, revocation propagation, or gold fixture integration claim. |
| Local AUTH-003 delegation wiring | Kernel tests cover complete nested chains, exact child action grant refs, deterministic nested-edge denial, N-child aggregate overflow, concurrent authority-owned fan-out, routing release/start fail-safe consumption, cleanup, descendant cancellation/revocation, and inspect-only replay. | `G18/G70/G71` remain `not_exercised`; remote Message Service/Agent Controller adoption, durable/cross-instance ledger, and gold integration remain deferred. |
| Bounded AUTH-004a obligations | Types tests cover conditional decision and obligation receipt serialization with receipt ID, issuer, audience, revocation source, and validation material. Authority tests cover grants without obligations still returning `Allowed`, grants with obligations returning `Conditional`, raw/forged receipt denial before validation, wrong issuer/audience/key/signature denial, exact validated receipt success, duplicate receipt ID denial, duplicate obligation ID denial, extra receipt denial, changed request/scope/params digest mismatch, missing/wrong obligation ID, wrong decision, wrong subject, wrong kind, expired, revoked, malformed evidence digest, unsupported schema, non-conditional decision denial, and conditional parent delegation denial before child grant creation. | `G11/G43/G75/G79` remain `not_exercised`; no gateway verifier, approval workflow, gate-engine, MFA, data-use, quota, safety, daemon/API, TS/Python, adapter execution, production PKI, or external revocation-introspection claim. |
| Bounded AUTH-004b gateway obligation verification | Gateway tests cover valid exact trusted receipts allowing adapter execution when required, globally unique complete-current-decision matching that rejects unrelated/forged/replayed extras, final-boundary expiry after a blocking verifier, monotonic expiry latching, concurrent one-use claim with at most one adapter call, claim permit retention through delayed evidence append, trace-failure burn, shared-ledger verifier recreation, unavailable-ledger denial, missing evidence requiring intervention, raw/forged receipt denial, changed gateway action digest denial, tampered full-decision digest denial, operation/tenant/agent/run scope mismatch, expired/revoked/wrong/extra/duplicate receipts, and legacy `ApprovalEvidence` not satisfying authority obligations. Existing gateway policy/resource/approval/quota/safety/postcondition tests continue to run. TypeScript/OpenAPI parity tests cover the exact receipt schema literal and nullable optional fields without exposing a daemon/client workflow. | `G11/G43/G75/G79` remain `not_exercised`; no approval workflow engine, MFA provider, gate engine, restart-durable receipt ledger, production PKI, external revocation introspection, daemon receipt-issuance/client workflow, Python, or full AUTH-004/C02 completion claim. |
| Bounded AUTH-005a local revocation/cache | Authority tests cover revoked `RevocationRecord` denial over a cached active grant, missing/stale/expired/future-dated cache denial, missing/stale/future-dated revocation snapshot denial, disconnected explicit low-risk data and device-sensing read allow within cached scope/TTL, disconnected scope mismatch denial, unsupported offline read denial, disconnected high-risk device/change/agent-delegation denial or intervention only after matching cached authority, offline TTL expiry denial, and cache APIs that accept validated grants without extending grant expiry. | `G73/G88` remain `not_exercised`; no production revocation service, revocation watches, external introspection, lease renewal, node/fleet/policy-cache consumption, incident-controller integration, delegated child revocation propagation, daemon/API/client workflow, or full AUTH-005/C02 completion claim. |
| Bounded AUTH-005b local renewal preflight | Authority tests cover positive renewal from a fresh cached validated grant and active snapshot with matching nonce/current digest, nonce missing/mismatch denial, current digest mismatch denial, missing/non-renewable policy denial, revoked grant/snapshot denial, missing/stale/future-dated snapshot denial, stale/expired/future-dated cached grant denial, changed grant identity/issuer/subject/operations/scope/audience/revocation/obligation/parent/validation-kind/delegation-depth/start-time denial, maximum renewal/offline lifetime denial, and renewed cache expiry not outliving renewed grant expiry. | `G73/G88` remain `not_exercised`; no durable nonce/replay store, production lease service, revocation watches, external introspection, node/fleet/policy-cache consumption, incident-controller integration, delegated child revocation propagation, daemon/API/client workflow, or full AUTH-005/C02 completion claim. |
| Bounded AUTH-005c delegated child revocation | Kernel tests cover revoked child/parent cancellation, stale/future fail-closed cancellation, descendant propagation, cleanup evidence, trace/router failures, concurrency, unrelated/terminal no-op, and inspect-only replay. | `G18/G70/G71/G73/G88` remain `not_exercised`; no production revocation watch/service, external introspection, remote controller, or durable evidence store. |
| Bounded AUTH-006a decision evidence | Authority tests cover deterministic safe decision/restricted revision digests, domain separation, set/hash canonicalization, normalized evaluator reason-category trees, explicit missing exact-request binding, decision/grant/cache completeness, cache versus offline-TTL freshness, restricted/redacted leak absence, inspect-only comparisons, and explicit evidence-unavailable errors. Gateway tests cover trusted-only normalized projection, safe typed denial coordinates, hostile reason/schema/metadata-digest omission on no-verifier/early-denial paths, and zero adapter execution on malformed evidence. | `G01/G03` remain `not_exercised`; no exact request/operation digest claim, keyed evidence binding, durable Evidence Service, bundle/store/access controls, trace schema, policy archive/re-evaluation engine, daemon/API/client workflow, full FND-009, or full AUTH-006/C02 completion claim. |
| Bounded AUTH-007a deterministic adversarial/property suite | `cargo test -p splendor-authority adversarial_property --locked` runs eight dependency-free properties: 256 cases each for scope algebra, empty/disjoint rejection, fixed-time/audience/subject behavior, delegation restrictions, and revocation/cache monotonicity; 512 cases each for budget accumulation and deterministic denial/evidence normalization. Inputs use fixed time and deterministic IDs; failures identify seed/case. | `G01/G18/G70/G79/G80/G86/G88` remain `not_exercised`; no serialized fuzz, all-plane confused-deputy, cross-version IAM/cache parity, mutation testing, formal proof, external fixture publication, or full AUTH-007/C02 claim. |
| Bounded AUTH-007b deterministic serialized mutation corpus | `cargo test -p splendor-authority serialized_mutation --locked` runs five 128-case families (640 serialized mutations total) over capability grants/requests, signed work-order issuance, obligation receipt collections, delegation grants/chains, and nested metadata/extensions. Every baseline is serialized and round-tripped as a positive control; every mutation is asserted byte-structurally different as `serde_json::Value`, then checked through serde and the real trusted local boundary. Corpus assertions and fixture/mutation setup failures identify fixture, mutation, and seed. | `G01/G18/G70/G79/G80/G86/G88` remain `not_exercised`; no cargo-fuzz/libFuzzer, unbounded/random fuzzing, all-plane confused-deputy, cross-version IAM/cache parity, mutation testing, formal proof, external fixture publication, or full AUTH-007/C02/#244 claim. |
| Bounded AUTH-007c local delegation replay matrix | Kernel tests use real validated grants and the public manager path for exact binding/replay mutations plus complete nested chain and reservation lifecycle replay. Authority issuance proves multi-scope containment and unlisted identity denial. | `G01/G18/G70/G79/G80/G86/G88` remain `not_exercised`; durable binding events, typed cross-instance binding, Driver/Artifact/helper/remote paths, all-plane mutation, and full AUTH-007/#244 remain incomplete. |
| Bounded AUTH-007d version/cache-staleness matrix | `cargo test -p splendor-types policy_distribution --locked`, `cargo test -p splendor-authority trusted_v1 --locked`, `cargo test -p splendor-kernel policy_cache --locked`, and `cargo test -p splendor-daemon policy_sync --locked` cover exact current-v1 positive controls; v0/v2 authority operation/scope/grant/request/revocation/policy rejection; unknown closed enums; raw-grant trust/cache exclusion; fixed-clock future-issued policy boundary; historical 0.04-shaped v1 signature characterization; trusted connected/offline cache positives; cache/snapshot stale/future/expired/revoked/offline-TTL denials; daemon cache preservation/blocking; trace reasons; and zero adapter calls for blocked action attempts. | `G01/G18/G70/G79/G80/G86/G88` remain `not_exercised`; no new schema, TypeScript/OpenAPI parity, canonical historical migration seam, resident persistence/watch, Driver/Artifact/helper/remote path, mutation framework, or full AUTH-007/C02/#244 claim. |
| Production-local C02 daemon integration | The public-router non-gold test covers verified signed work-order admission, scheduler and direct allowed effects, exact full-permission profiles, ambiguous multi-adapter admission denial, invalid registered-permission denial, action/adapter/permission denial, admitted-then-expired denial, local revocation denial, pre-effect trace append failure with zero adapter calls, and replay summaries with unchanged adapter/evaluator counts. The resident-mode test covers caller credential metadata/scope checks behind the C01 boundary, not cryptographic resident authentication. Gateway tests exercise current conditional decisions with raw trusted receipts and recorder-before-adapter ordering. | All C02 gold targets remain `not_exercised`; no C01 issuer/authentication provider, remote watch, future privileged-plane adoption, or gold pass claim. |

## Future Implementation Requirements

Future PRs that claim more of C02/AUTH-001/AUTH-002/AUTH-003/AUTH-004/AUTH-005/AUTH-006/AUTH-007
must add executable integration evidence before changing gold status or closing
issues:

- first-class Evidence Service bundles/access controls beyond the current durable
  shared-runtime pre-effect trace record;
- C01-backed work-order issuance integration (`AUTH-002`), replacing the
  explicitly named validated-signed-work-order compatibility admission,
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
- durable decision evidence bundles/access control, policy-version historical
  re-evaluation, replay-service integration, and executable `G01/G03` fixtures
  beyond bounded local `AUTH-006a` records/comparison (`AUTH-006`);
- keyed, access-controlled exact request/scope/concrete-operation binding; current
  serializable restricted/redacted records intentionally make no exact-binding,
  request-digest, or protected-operation-digest claim;
- remaining `AUTH-007` evidence: cargo-fuzz/unbounded serialized fuzzing,
  Driver/Artifact/physical-helper/remote confused-deputy paths, cross-language
  and distributed rolling-version policy/cache scenarios,
  external capability-algebra fixtures, mutation testing, and executable gold
  harnesses beyond bounded local `AUTH-007a` properties, `AUTH-007b`
  deterministic serialized mutations, `AUTH-007c` local delegation replay, and
  `AUTH-007d` exact-family local version/cache-staleness evidence.

## Summary

This RFC and implementation slice introduce typed, deterministic local
capability, issuance, bounded delegation, conditional obligation receipt, local
revocation/offline cached-grant, renewal-preflight, and delegated child
revocation foundations, runtime-local delegation grant-reference wiring, and
bounded redacted local decision evidence while preserving Splendor's kernel
invariants: no side-effect bypass, fail-closed authority checks, no permission
laundering, no message/metadata/evidence authority, identity separation, offline
cache and renewal are not ambient authority, inspect-only comparison has no live
effects, deterministic local adversarial/property failures are reproducible by
seed/case, local parent grants cannot be replayed across manager-owned root-run
bindings, future-issued policies and unsupported authorizing families fail
closed, and no gold completion claim exists without executable evidence.
