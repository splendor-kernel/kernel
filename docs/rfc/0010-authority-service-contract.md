# RFC 0010 - Authority Service Capability Contract

## Status and Scope

Status: Draft, with bounded local `AUTH-001` and `AUTH-002a` implementation
evidence slices.

Scope: 0.2/v2 Authority Service child RFC for C02,
`splendor.authority-service`. This RFC remains a Draft contract. This repository
branch includes only local Rust evidence slices: behavior-free capability and
scope contracts in `splendor-types`, deterministic local evaluation and narrowing
logic in `splendor-authority`, trusted local profile grant wrapping, a bounded
signed work-order to verified capability grant bridge, and unit tests for
allow/deny/narrowing/issuance behavior.

This slice does not change stable 0.1 runtime enforcement, daemon APIs, OpenAPI,
TypeScript, Python, gateway verifier wiring, trace formats, state formats, replay
semantics, fleet behavior, node admission, workload-controller wiring, or adapter
execution. It does not claim full C02, full `AUTH-001`, full `AUTH-002`, G60,
G83, issue closure, or gold completion.

Until exact executable fixtures pass, gold targets `G01`, `G18`, `G60`, `G70`,
and `G83` remain `not_exercised`.

## Binding

| Item | Binding in this RFC | Evidence status |
| --- | --- | --- |
| Aggregate issue | #182, `0.2/v2 component: C02 splendor.authority-service - Authority Service` | Aggregate target only; not complete. |
| Child issue | #238, `AUTH-001 - Define a composable capability and scope model` | Bounded local evidence only; not complete. |
| Catalog task | `AUTH-002 - Implement issuance and signed work-order integration` | Bounded `AUTH-002a` Rust bridge evidence only; not complete. |
| Component | `splendor.authority-service` | Local capability module evidence. |
| Owner packages | `splendor-types` for behavior-free contracts; `splendor-authority` for evaluation/narrowing decisions | Current slice follows this ownership. |
| Gold targets | `G01`, `G18`, `G60`, `G70`, `G83` | `not_exercised` until executable fixtures/harnesses pass. |

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
- No gateway/verifier pipeline integration or new adapter execution path.
- No daemon, OpenAPI, TypeScript, Python, fleet, product, or physical safety
  behavior.
- No full data-use controller, secret broker, approval workflow, offline lease
  renewal, or revocation propagation service.
- No universal wildcard or metadata/extension-based authority.
- No claim that `G01`, `G18`, `G60`, `G70`, or `G83` passed.
- No closure claim for #182 or #238.

## Contract Overview

The local AUTH-001 slice adds these behavior-free `splendor-types` contracts:

- `AuthorityOperation`, `AuthorityOperationNamespace`, `AuthorityResourceKind`,
  and `AuthorityVerb`;
- `CapabilityScope` with tenant, fleet, agent, run, workload, device, data
  purpose, artifact, state partition, driver operation, audience, time, budget,
  network, and locality dimensions;
- `CapabilityGrant`, `CapabilityRequest`, `AuthorityDecision`,
  `AuthorityObligation`, and `RevocationRecord`;
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

This RFC does not add event or trace variants and does not alter state or replay
formats. Future integration must record authority decisions as pre-effect
evidence before gateway/driver execution and must keep replay inspect-only by
default. Historical replay must use recorded authority evidence rather than live
revocation or issuer lookups unless a separately gated non-default simulation
mode is defined.

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

## Future Implementation Requirements

Future PRs that claim more of C02/AUTH-001/AUTH-002 must add executable integration
evidence before changing gold status or closing issues:

- gateway/verifier integration with pre-effect authority decision evidence;
- full work-order issuance/signature validation integration (`AUTH-002`),
  including workload-controller admission wiring, node-side validation, renewal
  semantics, one-time/non-renewable grant lifetimes, and executable `G60/G83`
  fixtures;
- multi-agent delegation chain and causal message fixtures (`AUTH-003`, `G18`,
  `G70`);
- obligations/approval workflow integration (`AUTH-004`);
- revocation, renewal, offline cache, and stale-authority denial (`AUTH-005`);
- decision evidence/explainability and replay integration (`AUTH-006`);
- adversarial/property suites (`AUTH-007`).

## Summary

This RFC and implementation slice introduce a typed, deterministic local
capability grammar/evaluator foundation while preserving Splendor's kernel
invariants: no side-effect bypass, fail-closed authority checks, no permission
laundering, no metadata authority, identity separation, and no gold completion
claim without executable evidence.
