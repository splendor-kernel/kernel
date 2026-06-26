# RFC 0010 - Authority Service Capability Contract

## Status and Scope

Status: Draft, with a bounded local `AUTH-001` implementation evidence slice.

Scope: 0.2/v2 Authority Service child RFC for C02,
`splendor.authority-service`. This RFC remains a Draft contract. This repository
branch includes only a local Rust evidence slice: behavior-free capability and
scope contracts in `splendor-types`, deterministic local evaluation and narrowing
logic in `splendor-authority`, and unit tests for allow/deny/narrowing behavior.

This slice does not change stable 0.1 runtime enforcement, daemon APIs, OpenAPI,
TypeScript, Python, gateway verifier wiring, trace formats, state formats, replay
semantics, fleet behavior, or adapter execution. It does not claim full C02,
full `AUTH-001`, issue closure, or gold completion.

Until exact executable fixtures pass, gold targets `G01`, `G18`, and `G70` remain
`not_exercised`.

## Binding

| Item | Binding in this RFC | Evidence status |
| --- | --- | --- |
| Aggregate issue | #182, `0.2/v2 component: C02 splendor.authority-service - Authority Service` | Aggregate target only; not complete. |
| Child issue | #238, `AUTH-001 - Define a composable capability and scope model` | Bounded local evidence only; not complete. |
| Component | `splendor.authority-service` | Local capability module evidence. |
| Owner packages | `splendor-types` for behavior-free contracts; `splendor-authority` for evaluation/narrowing decisions | Current slice follows this ownership. |
| Gold targets | `G01`, `G18`, `G70` | `not_exercised` until executable fixtures/harnesses pass. |

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
- No claim that `G01`, `G18`, or `G70` passed.
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

- grants must be schema-valid, locally validated/signed, unexpired, unrevoked,
  subject-matched, audience-matched, and operation/scope-contained;
- authorization grants and requests must carry an explicit audience and at least
  one concrete bounded scope dimension beyond only time or budget, such as
  tenant, fleet, agent, run, workload, device, data purpose, artifact, state
  partition, driver operation, network, or locality;
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

## Guardrails

| Rule | Required behavior in this slice |
| --- | --- |
| Authority is typed | Operation namespace, verb, resource kind, and schema version are explicit enums/fields. |
| No wildcard bypass | `*` in operation names, audiences, network/locality tokens, validation refs, or driver refs is rejected by the evaluator. |
| No unbound authority | Authorization evaluation denies grants or requests without an explicit audience and at least one concrete bounded dimension beyond only time/budget. |
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
| Scope binding | Authority tests cover missing audience, audience-only/budget-only scopes, and empty unbound grant/request denial. | `G01` remains `not_exercised`. |
| Composite effects | Authority tests cover action-only work-order compatibility grants not authorizing adapter or permission operations. | Not gateway integration evidence. |
| Non-authorizing metadata | Authority tests cover safe metadata not granting authority and reserved metadata denial. | `G01` remains `not_exercised`. |
| Compatibility profiles | Authority tests cover local `WorkOrder` allowlist profile mapping without broadening. | Not a full work-order issuance integration claim. |

## Future Implementation Requirements

Future PRs that claim more of C02/AUTH-001 must add executable integration
evidence before changing gold status or closing issues:

- gateway/verifier integration with pre-effect authority decision evidence;
- work-order issuance/signature validation integration (`AUTH-002`);
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
