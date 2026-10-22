# RFC 0007 - vNext Idempotent Service API Semantics

## Status and Scope

Status: Draft.

Scope: vNext proposal for issue #139. This RFC is non-normative until accepted
and implemented. It does not change current daemon behavior, OpenAPI schemas,
SDKs, generated artifacts, stable 0.1 references, gateway behavior, verifier
behavior, trace formats, state formats, or replay semantics.

Milestone and sprint alignment:

- Milestone: `Splendor0.2-dev` / v2 API RFC preparation with 0.1 baseline compatibility.
- Sprint: `0.1-S4 - SDK and API stabilization`.
- FRs: `FR-0.1-03`, `FR-0.1-04`, `FR-0.1-08`; related `FR-0.02-S0-01` through `FR-0.02-S0-11`.
- vNext planning refs: `FND-004`, `FND-010`, `AR-020`, `AR-080`, `AR-082`.

This document proposes service/API semantics that future implementation work can
map into daemon handlers, OpenAPI, TypeScript, Python, conformance fixtures, and
runtime services. It intentionally does not present planned vNext behavior as
implemented behavior.

## Motivation

Mutating service APIs need durable semantics for transport uncertainty and
runtime uncertainty. Without an explicit contract, a client that loses an HTTP
response cannot tell whether a run was created, a tick executed, a percept was
queued, an action crossed the Action Gateway, or an external effect happened.
Blind retries can duplicate side effects, while overly conservative clients can
strand runs in unknown states.

The vNext API line needs one proposal that covers:

- dropped HTTP responses before or after a daemon accepts a mutation;
- duplicate mutating calls from SDKs, CLIs, managers, resident nodes, and control planes;
- uncertain external effects after gateway or adapter boundaries;
- consistent SDK retry and exception behavior without duplicating runtime semantics;
- stable denial/error categories that clients can handle programmatically;
- no drift from daemon security layers, work-order authority, or Action Gateway enforcement.

## Primitive Affected

This RFC strengthens the following primitives at the proposal level only:

- daemon API;
- SDK/API;
- work order;
- gateway/verifier;
- trace/evidence;
- replay.

It also affects compatibility planning for future OpenAPI, TypeScript, Python,
daemon, and conformance updates.

## Non-Goals

- No OAuth server, PKI rollout, fleet mTLS rollout, or production credential verifier.
- No daemon behavior change in this RFC.
- No OpenAPI, SDK, generated artifact, or stable 0.1 reference change in this RFC.
- No client-side runtime semantics, authorization engine, gateway completion, verifier result, state commit, or effect-certainty decision.
- No Action Gateway bypass.
- No weakening of work-order signature, expiry, revocation, audience, compatibility, or scoped authority requirements.
- No permission laundering through caller credentials, SDK helpers, manager dispatch, messages, devices, or shared agents.
- No side-effectful replay mode.

## Security Boundary

All future implementation of this RFC must preserve the existing layered boundary
in this exact order:

```text
transport security -> caller authentication -> endpoint scopes -> signed work order -> tenant/agent/run policies -> gateway verification -> adapter execution
```

Layer meanings are not interchangeable:

| Layer | Meaning | Must not become |
| --- | --- | --- |
| Transport security | Authenticates the channel. | Run or action authority. |
| Caller authentication | Authenticates the app/client principal. | Authority for arbitrary agent actions. |
| Endpoint scopes | Authorize daemon API access for a specific endpoint class. | Gateway approval or work-order scope. |
| Signed work order | Authorizes a run, resume, dispatch, or delegated scope. | Broad caller credential or permanent grant. |
| Tenant/agent/run policies | Narrow runtime authority to scoped identities and data. | Replacement for gateway verification. |
| Action Gateway verification | Authorizes side effects through required verifier chains. | Optional SDK/client-side check. |
| Adapter execution | Performs the bounded effect only after verification. | Authority source or policy owner. |

A caller token authenticates the app. A signed work order authorizes the run. The
Action Gateway authorizes side effects. Idempotency keys and receipts are evidence
and duplicate-delivery controls; they do not grant authority.

## Current Versus Proposed Semantics

The current 0.1 local daemon API stabilizes endpoint names, request/response
shapes, structured errors with `code`, `message`, and `details`, signed
work-order requirements for create/resume, gateway-mediated `/actions`,
inspect-only replay, and no silent unauthenticated fallback.

The current stable surface generally does not require `request_id` or
`idempotency_key` for mutating local daemon operations. Remote message sending is
the notable current pattern that already has explicit idempotency-key semantics.

This RFC proposes vNext semantics. Future implementation must version or migrate
the contract instead of silently changing stable 0.1 behavior in place.

## Mutating Operation Idempotency Matrix

Legend:

- Required: vNext mutating request should carry `request_id` and `idempotency_key`.
- Required + CAS: vNext request should also carry `expected_state_head` or equivalent optimistic state guard.
- Natural key + request ID: the resource identity may be the dedupe key, but transport attempts still need `request_id` and receipt behavior.
- Not applicable: no mutation. A correlation/request ID can still be useful, but no idempotency key is required.

### Current Local Runtime Daemon Surface

| Operation | Current implemented/stable-facing behavior | Proposed vNext semantics |
| --- | --- | --- |
| `POST /runs` | Creates a local run from a signed work order. Stable 0.1 does not require a general idempotency key. | Required. Deduplicate by tenant, caller, work order, run target when present, request body digest, and key. Same key/same scope returns the same create receipt. Same key/different scope conflicts. |
| `POST /runs/{run_id}/start` | Executes one scheduler tick. Retrying after a dropped response can be ambiguous. | Required. Same key returns the same tick receipt or terminal in-progress receipt. A new key means a new requested tick and must pass current authority checks. |
| `POST /runs/{run_id}/resume` | Requires signed resume work order and may execute one tick. | Required. Same key returns the same resume/tick receipt. New execution after expiry/revocation requires fresh valid authority. |
| `POST /runs/{run_id}/pause` | Mutates run lifecycle state and audit/trace evidence. | Required. Target-state idempotent for the same run, reason, caller, and key. Duplicate returns the same pause receipt. |
| `POST /runs/{run_id}/stop` / `cancel` | Mutates terminal lifecycle state and audit/trace evidence. | Required. Same key returns the same terminal receipt. A new key after terminal state returns a stable terminal-state result or conflict, not another transition. |
| `POST /runs/{run_id}/percepts` | Appends a daemon-submitted percept to run input and trace evidence. | Required. Deduplicate by key plus percept digest/provenance/schema/run. Same key with different percept conflicts. |
| `POST /runs/{run_id}/policies/sync` | Mutates run policy-cache status/evidence when available. | Required. Deduplicate by policy bundle identity/version/digest and key. Expired or revoked policy authority still fails closed. |
| `POST /runs/{run_id}/traces/export` | A POST audit boundary even though it reads trace data. | Required when export records audit/evidence. Same key and same export parameters return the same export receipt. |
| `POST /runs/{run_id}/replay` | Inspect-only replay request; no side effects. | Required if replay creates a replay receipt/job/audit event. Replay remains side-effect disabled. |
| `POST /actions` | Submits an action through the daemon boundary to gateway verification. Current request identity does not include a general idempotency key. | Required. Key plus action identity and gateway request scope deduplicates the action attempt. Duplicate returns the same `ActionOutcome` or uncertainty receipt. Unknown effect cannot be blindly retried. |

### Manager, Fleet, Work-Order, Message, Governance, and Device Surfaces

These surfaces may be current foundation code, OpenAPI/planning surfaces, or later
manager/fleet/device APIs. This table proposes vNext semantics and does not claim
all rows are stable local daemon 0.1 behavior.

| Operation family | Current/proposed surface status | Proposed vNext semantics |
| --- | --- | --- |
| Work-order submit | Manager/fleet-facing mutator when present. | Required. Deduplicate by `work_order_id`, work-order digest, expected audience, caller/fleet binding, and key. Same key with different work order conflicts. |
| Work-order revoke | Manager/fleet-facing mutator when present. | Required. Same key returns the same revocation receipt. Revocation remains effective for create, resume, dispatch, messaging, and action authority checks. |
| Work-order dispatch | Manager/fleet-facing mutator when present. | Required. Same key returns the same dispatch receipt and must not create/start duplicate resident runs after a dropped manager response. |
| Node/instance registration | Resident/fleet foundation surface. | Natural key + request ID or Required. Node/instance identity scopes idempotency, but duplicate transport attempts still need receipt semantics and audit attribution. |
| Heartbeat/capability advertisement | Registry/telemetry mutation. | Request ID required. Idempotency key optional only if the operation is explicitly overwrite-by-node-epoch and duplicate delivery has defined receipt behavior. |
| Remote message send | Current pattern already uses idempotency semantics. | Required. Preserve same-key/same-scope duplicate reporting. Scope mismatch remains conflict and must not mutate payload or delivery state. |
| Message ack/nack | Delivery metadata mutation. | Required. Same key returns same metadata receipt. Payload mutation attempts remain malformed/forbidden. |
| Approval request/grant/deny/revoke | Governance mutators when exposed. | Required. Same key returns same governance receipt. Same key with different approval decision, scope, or token conflicts. Expired approval authority fails closed. |
| Circuit breaker / kill switch sync | Governance/fleet mutators when exposed. | Required. Deduplicate by breaker/kill-switch set version, scope, issuer, and key. Duplicate must not create extra authority or hidden transitions. |
| Device profile/register/status mutation | Device/fleet mutators when exposed. | Required. Deduplicate by node/device identity, profile digest or status epoch, caller/fleet binding, and key. |
| Device high-level action | Physical action submission through gateway/device safety boundary. | Required with stricter effect certainty. Physical or irreversible uncertainty must route to intervention/reconciliation, not blind retry. |
| State snapshot export | State handoff/evidence mutation when exported receipt is recorded. | Required. Same key returns same snapshot/handoff receipt. Export does not create new authority. |
| State snapshot import / state-head update | Mutates state head. | Required + CAS. Same key returns same import receipt. Stale or mismatched `expected_state_head` returns conflict with no mutation. |

### Non-Mutating Reads

| Operation family | Proposed vNext semantics |
| --- | --- |
| `GET /health`, `GET /version`, `GET /capabilities` | Not applicable. Still require applicable auth/scope in non-dev modes. |
| `GET /runs/{run_id}` | Not applicable. Requires tenant/run visibility. |
| `GET /runs/{run_id}/state-head` | Not applicable. Requires state read scope/visibility. |
| `GET /runs/{run_id}/traces` | Not applicable. Requires trace read scope, visibility, and redaction policy. |
| Message read/list/causal graph reads | Not applicable. Requires message/run visibility and redaction policy where applicable. |
| Device status/policy-cache reads | Not applicable. Requires node/fleet/tenant visibility. |

## Request Identity and Receipt Proposal

Every vNext mutating request should carry a request identity envelope or equivalent
headers/body fields:

```json
{
  "request_id": "req_...",
  "idempotency_key": "idem_...",
  "idempotency_scope": "tenant:.../endpoint:.../target:.../body_digest:...",
  "causal_trace_event_id": "trace_evt_...",
  "expected_state_head": "state_..."
}
```

Field semantics:

| Field | Semantics |
| --- | --- |
| `request_id` | Unique per client attempt. Useful for tracing transport attempts and support diagnostics. It is not the dedupe key. |
| `idempotency_key` | Stable across retries of the same intended mutation. Required for mutating operations. |
| `idempotency_scope` | Server-computed or server-validated scope binding the key to tenant/fleet, caller, endpoint, target resource, work order or run, operation kind, body digest, and security/audience context. |
| `receipt_id` | Stable identifier returned by the service for an accepted, denied, conflicted, in-progress, or uncertain mutation attempt. |
| `causal_trace_event_id` | Trace linkage to the event that caused or admitted the request when applicable. For actions, a trace link remains mandatory. |
| `expected_state_head` | Optimistic concurrency guard for state-head mutations, state imports, policy activation, work-order state transitions, or any governed mutable head. |

Receipt shape should be versioned and minimal:

```json
{
  "receipt_id": "receipt_...",
  "request_id": "req_...",
  "idempotency_key": "idem_...",
  "idempotency_scope": "...",
  "status": "accepted | duplicate | denied | conflict | in_progress | failed | uncertain",
  "effect_certainty": "none | known | uncertain",
  "causal_trace_event_id": "trace_evt_...",
  "outcome_ref": "action_outcome_or_state_or_run_ref",
  "created_at": "2026-06-21T00:00:00Z"
}
```

Conflict rules:

| Case | Required behavior |
| --- | --- |
| Same key, same scope, original receipt terminal | Return the same receipt/outcome without re-executing the mutation. |
| Same key, same scope, original mutation in progress | Return an in-progress receipt or retry-after guidance. Do not start a second mutation. |
| Same key, different scope/body/security binding | Return `idempotency_conflict` with `effect_certainty: none`. Do not mutate. |
| New key, same body/target | Treat as a new requested mutation and require current authority. Operation-specific uniqueness may still return conflict. |
| Missing key on mutating vNext endpoint | Reject as malformed/invalid request before mutation. Transitional compatibility may accept optional fields only in explicitly versioned modes. |
| Dropped response before accepted receipt is durable | Client may retry with same key. Server must produce no effect, one evidenced effect, or an uncertainty/intervention receipt. |
| Dropped response after external effect but before terminal evidence | Server must not infer safe retry. Return or recover an uncertain receipt and route high-risk cases to intervention. |

## Denial and Error Taxonomy

vNext should preserve the current stable daemon error discriminator concept while
adding machine-actionable fields. A proposed public error shape is:

```json
{
  "code": "stable_reason_code",
  "message": "human diagnostics only",
  "details": {},
  "retry_class": "do_not_retry | retry_same_key | retry_after_refresh | new_authorization_required | fix_request | intervention_required",
  "effect_certainty": "none | known | uncertain",
  "causal_trace_event_id": "trace_evt_...",
  "request_id": "req_...",
  "idempotency_key": "idem_...",
  "receipt_id": "receipt_...",
  "provider_detail": {}
}
```

`provider_detail` is diagnostic only. It must not grant authority, expose secrets,
leak protected data, or replace canonical reason codes.
Public errors and audit exports should return raw idempotency keys only when the
key is explicitly non-secret and policy permits it; otherwise they should return a
stable digest or receipt reference.

| Category | Example stable reason codes | Retry class | Effect certainty | Required semantics |
| --- | --- | --- | --- | --- |
| Malformed schema/input | `malformed_schema`, `invalid_json`, `unsupported_message_schema`, `missing_idempotency_key` | `fix_request` | `none` | Reject before mutation. Human prose is not the discriminator. |
| Authentication failure | `missing_caller_credential`, `anonymous_non_dev_call`, `invalid_caller_token` | `new_authorization_required` | `none` | Caller is not authenticated. No work-order or gateway authority can be inferred. |
| Endpoint authorization failure | `missing_scope`, `wrong_audience`, `wrong_tenant_binding`, `credential_expired`, `credential_revoked` | `new_authorization_required` or `retry_after_refresh` | `none` | Scope/audience/binding/expiry/revocation checks fail closed before mutation. |
| Work-order authority failure | `missing_work_order`, `unsigned_work_order`, `expired_work_order`, `revoked_work_order`, `incompatible_work_order` | `new_authorization_required` | `none` | Reject create/resume/dispatch/action authority before run or side effect. Caller credentials do not compensate. |
| Idempotency conflict | `idempotency_conflict`, `idempotency_scope_mismatch` | `fix_request` | `none` | Same key used for a different scope/body/security binding. Do not mutate. |
| Stale state / conflict | `stale_state_head`, `state_conflict`, `run_already_exists`, `invalid_run_state` | `retry_after_refresh` | `none` unless an effect boundary was already crossed | Return actual head/status where safe. Do not blind overwrite governed state. |
| Gateway denied | `gateway_denied` or `ActionOutcome.status = Denied` | `do_not_retry` unless new evidence/authority exists | `none` | Gateway evaluated and denied; adapter execution did not occur. Prefer action outcome over transport failure where gateway ran. |
| Approval/intervention needed | `approval_required`, `needs_intervention` | `new_authorization_required` or `intervention_required` | `none` pre-effect | Run/action pauses or denies until valid evidence arrives. Do not execute adapter. |
| Verifier unavailable/uncertain | `verifier_unavailable`, `verification_uncertain` | `retry_after_refresh` or `intervention_required` | `none` before effect, `uncertain` after provider boundary | Fail closed. Never convert verifier uncertainty into allow. |
| Quota exceeded | `quota_exceeded` | `retry_after_refresh` or `new_authorization_required` | `none` | Deny or pause before effect unless a later accounting failure proves otherwise. |
| Policy TTL/revocation | `policy_expired`, `policy_revoked`, `policy_unavailable` | `retry_after_refresh` or `new_authorization_required` | `none` | High-risk side effects fail closed until valid policy authority is available. |
| Trace durability failure | `trace_durability_failed`, `trace_integrity_failed` | `retry_same_key` after storage recovery or `intervention_required` | `none` before effect, `uncertain` after effect | Side-effectful actions fail closed if required trace evidence cannot be durable before effect. |
| State commit failure | `state_commit_failed`, `state_integrity_failed` | `retry_same_key` only if operation contract permits | `none` before external effect, `uncertain` if external effect already occurred | Do not advance next tick. Quarantine/reconcile uncertain effects. |
| Replay unsafe | `unsupported_replay_mode`, `replay_side_effects_forbidden` | `fix_request` | `none` | Replay remains inspect-only by default and must not execute side effects. |
| Runtime unavailable | `runtime_unavailable`, `runtime_lock_error`, `timeout` | `retry_same_key` for keyed mutations; otherwise return uncertainty | `none` if request not accepted, `uncertain` if acceptance cannot be proven | SDK must not blind retry with a new key. |
| Adapter/provider failure | `adapter_failed`, `provider_timeout`, `postcondition_failed` | Operation-specific; often `intervention_required` for unknown effects | `known` or `uncertain` | Action outcome and receipt must state whether an effect is known, denied, failed before effect, or uncertain. |
| Protected-data/safety/physical denial | `protected_data_denied`, `safety_denied`, `physical_intervention_required` | `new_authorization_required` or `intervention_required` | `none` before effect | Local safety and data-scope denials fail closed and cannot be bypassed by cloud/helper authority. |

Gateway denial is not the same as daemon authorization failure. If the request
reaches gateway evaluation and the gateway denies, the daemon should return a
successful transport response with an action outcome where that remains the
versioned contract. Non-2xx daemon errors remain for boundary, schema, runtime,
and service failures that prevent normal evaluation.

## SDK Behavior Matrix

SDKs remain thin clients. They construct requests, propagate request identity,
parse structured responses, and expose safe retry guidance. They do not decide
authorization, work-order validity, gateway completion, verifier results, state
transition legality, trace durability, or external effect certainty.

| Scenario | Proposed vNext SDK behavior |
| --- | --- |
| Key generation | Generate opaque `request_id` per attempt and `idempotency_key` per mutating operation when caller does not provide one. Return/expose both to callers. |
| Key propagation | Preserve the same `idempotency_key` for retries of the same intended mutation. Generate a new `request_id` for each transport attempt. |
| Same-key retry | Retry only with the same key and same request body/scope. Do not retry a mutation with a new key after a dropped response unless the caller explicitly asks for a new operation. |
| Dropped response before body | Return a typed network/runtime error carrying request ID, idempotency key, and retry guidance. If automatic retry is configured, use same key only. |
| Dropped response after possible acceptance | Query receipt or retry same key. If no receipt can be recovered, surface `effect_certainty: uncertain` for mutating calls. |
| Idempotency conflict | Raise a typed client error with `code`, `retry_class`, `effect_certainty`, `receipt_id` when present, and non-authorizing diagnostics. |
| Work-order preflight | SDKs may check obvious shape/expiry ergonomically, but daemon/manager remains authoritative for signature, expiry, revocation, audience, compatibility, and scope. |
| Action submission | SDK posts to `/actions` or future service equivalent only. It may not self-attest `GatewayVerificationState::Completed` or bypass the Action Gateway. |
| Replay | Default remains inspect-only with side effects disabled. No SDK option should enable side-effectful replay without a separate accepted RFC and gated implementation. |
| Insecure fallback | SDKs must never silently fall back to unauthenticated communication. Explicit local insecure mode remains local-only, visible, and non-production. |
| Error parsing | Parse stable `code`; expose `retry_class`, `effect_certainty`, `causal_trace_event_id`, `request_id`, `idempotency_key`, `receipt_id`, and redacted provider detail when supplied. Do not parse human `message` for authority. |

## Work-Order Expiry and Revocation

Idempotency must not weaken work-order authority.

Future implementation must preserve these rules:

- Unsigned, expired, revoked, or incompatible work orders cannot create runs, resume runs, dispatch work, authorize remote messages, or authorize side effects.
- Caller credentials alone cannot authorize arbitrary agent actions.
- Work-order revocation must be checked through a documented source, such as a revocation list, introspection endpoint, or signing-key invalidation path.
- A duplicate same-key request may return a previously recorded receipt after a work order expires only as receipt retrieval/evidence. It must not execute a new mutation or create new action authority.
- If no accepted receipt exists and the work order is expired or revoked at retry time, the retry fails with work-order authority denial.
- If authority is revoked after request admission but before adapter execution, the gateway/verifier path must fail closed unless a versioned operation contract explicitly proves the effect already reached a terminal state.
- Manager dispatch and resident execution must not split authority in a way that allows an expired or revoked work order to be valid in one layer and invalid in another without traceable denial or intervention evidence.

## Compatibility and Migration Plan

Adding required idempotency fields to stable 0.1 request shapes would be a
breaking API/SDK change if done in place. The stable 0.1 line cannot silently
reinterpret existing mutating endpoints as requiring new fields without an
accepted versioning and migration plan.

Future implementation should follow this path:

1. Accept an RFC or update this RFC with final field names, wire location, receipt schema, taxonomy codes, and migration class.
2. Decide whether fields are additive optional transitional fields on 0.1-compatible endpoints or required fields in a new daemon/API version.
3. Update `openapi/splendor-runtime-daemon.yaml` as the source contract for HTTP request/response shapes.
4. Regenerate or update TypeScript types, `@splendor/client`, Python daemon client, CLI wrappers, and examples through the repository's normal generation/test path.
5. Add conformance fixtures for duplicate mutation, same-key replay, scope conflict, dropped response, and typed error mapping.
6. Update reference docs and SDK docs only after implementation exists.
7. Make daemon version negotiation or compatibility header behavior fail closed before relying on it for stable behavior.

Compatibility risks to track:

| Risk | Mitigation |
| --- | --- |
| Required keys break existing clients. | Use optional transitional fields or new API version with explicit migration. |
| `start`/`resume` currently model one request as one tick. | Add durable receipts before permitting automatic retry. |
| `action_id` is not enough to prove effect idempotency. | Require operation-specific idempotency scope and gateway/adapter receipt semantics. |
| Current error shape lacks retry/effect fields. | Add non-authorizing optional fields or versioned errors; keep `code` stable. |
| Work-order revocation exists at multiple layers. | Define canonical revocation source and trace all layer decisions. |
| SDK pre-validation may drift into authority. | Keep preflight ergonomic only; daemon/runtime remains canonical. |
| Remote message idempotency pattern may be overgeneralized. | Define per-operation scope and receipt rules, not a single copied rule. |
| POST reads/exports/replay may record audit evidence. | Treat audit-producing POSTs as mutating for idempotency, even when no external side effect occurs. |

## Trace and Replay Impact

Future implementation should make idempotency and uncertainty inspectable without
turning traces into ordinary logs.

Trace/evidence requirements:

- Accepted mutating requests should record caller attribution, request ID, idempotency key or safe digest, idempotency scope, and receipt ID where policy permits.
- Duplicate same-key handling should be traceable as duplicate observation or receipt replay without duplicating the original runtime transition.
- Idempotency conflicts should produce denial/evidence with no mutation.
- Gateway verification, denial, execution, failure, approval, intervention, quota, policy TTL, state commit, and trace durability outcomes should link to receipts where applicable.
- Provider details must be redacted and non-authorizing.
- Trace durability failures before side effects fail closed. Failures after an external effect require an uncertainty receipt and reconciliation/intervention path.

Replay requirements:

- Replay remains inspect-only by default and must not re-execute side effects.
- Replay should reconstruct request attempts, duplicate handling, receipts, denials, uncertainty classification, and causal trace links.
- Replay may explain why a retry was allowed with the same key, denied as conflict, blocked by work-order revocation, or routed to intervention.
- Replay must not use a caller credential, work order, idempotency key, or receipt as authority to run a gateway, verifier, adapter, driver, device action, or state commit again.

## Tests Required for Future Implementation

This docs-only RFC requires no runtime tests. Future implementation must include
contract, SDK, daemon, gateway, trace, replay, and failure-injection coverage.

Minimum future test matrix:

| Test area | Required cases |
| --- | --- |
| Duplicate mutation | Same key/same scope returns one receipt for create, start/resume, percept append, action submit, work-order dispatch, message send, state import, approval decision, and device action where implemented. |
| Idempotency conflict | Same key with different body, target, tenant/fleet binding, caller, work order, or security audience returns conflict and no mutation. |
| Dropped response | Fault injection before acceptance, after receipt persistence, after gateway verification, after adapter effect, before state commit, and before trace terminal event. |
| Gateway deny | Denied action does not reach adapter and returns action outcome/receipt with no effect. |
| Verifier unavailable | Required verifier outage fails closed and is classified with retry/effect guidance. |
| Quota | Quota exceeded denies or pauses before side effect and is reflected in receipt/taxonomy. |
| Policy TTL | Expired, revoked, unavailable, or incompatible policy denies high-risk side effects. |
| State commit | Stale `expected_state_head` conflicts; commit failure prevents next tick and records uncertainty when needed. |
| Trace durability | Required pre-effect trace failure prevents side effect; post-effect trace failure produces uncertainty/reconciliation evidence. |
| Replay unsafe | Side-effectful replay modes are rejected; replay of duplicate/uncertain attempts remains inspect-only. |
| Work order | Unsigned, expired, revoked, and incompatible work orders are rejected for create/resume/dispatch/action authority, including retries. |
| Runtime unavailable | SDK retries same key only or surfaces effect uncertainty; no blind retry with new key. |
| SDK behavior | TypeScript, Python, CLI, and raw HTTP fixtures agree on key propagation, typed errors, no insecure fallback, and thin-client limits. |
| Compatibility | Old fixtures either continue working in transitional mode or fail closed with documented version negotiation in new-version mode. |

## Docs Required for Future Implementation

Future implementation work should update, at minimum:

- `docs/reference/runtime-daemon-api.md`;
- `docs/reference/daemon-security-boundary.md` if security-boundary fields change;
- `docs/spec/0.1/api-stability.md` or a new versioned API stability document;
- SDK references for Python and TypeScript;
- OpenAPI and generated/checked-in artifacts through the normal generation path;
- conformance fixture docs and release/migration notes.

Until those implementation updates exist and pass validation, this RFC remains a
proposal only.
