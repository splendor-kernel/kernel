# Runtime Daemon API Reference

The runtime daemon API is the local control boundary for Splendor runs. In the
0.1 compatibility line, the stable endpoint names and request/response shapes are
documented here. The OpenAPI document remains versioned to the current runtime
daemon API metadata and carries a separate 0.1 compatibility note.
The implementation remains local/foundation-oriented; it is not a fleet manager
or production auth provider.

Historically this surface was introduced in 0.02-S5. 0.1 stabilizes the public
daemon boundary without promising private handler internals.

## Stable 0.1 compatibility boundary

Stable 0.1 daemon clients may rely on:

- endpoint names listed in the endpoint summary;
- JSON request/response shapes documented by OpenAPI and reference docs;
- structured daemon errors with `code`, `message`, and `details`;
- endpoint scopes from the daemon security boundary;
- signed, unexpired, unrevoked work-order requirement for run create/resume;
- gateway-mediated `/actions` submissions;
- inspect-only replay default;
- no silent fallback to unauthenticated non-dev communication.

Executable public client coverage for UC-E2E-S2 now includes the raw documented
HTTP path, `@splendor/client`, `python.splendor.daemon_client.SplendorDaemonClient`,
and `splendorctl daemon request`. Each client path creates a run from a signed
work order, appends a percept, starts a tick, submits the allowed action through
`POST /actions`, reads state/traces, exports traces, requests inspect-only replay,
and cancels the run. These clients are wrappers around daemon endpoints only; they
do not execute adapters directly or treat management credentials as action
authority.

Stable 0.1 clients must not rely on private Rust handler names, in-memory run slot
layout, local queue internals, exact test fixture IDs, native Node bindings,
browser runtime execution, production OAuth/PKI behavior, or remote fleet
transport.

## Version headers and negotiation

Stable clients should send:

```text
X-Splendor-API-Version: 0.1
X-Splendor-Client: <client-name>
```

The current TypeScript client sends `X-Splendor-API-Version` and lets callers
override the value. Its default remains `0.02-dev`, and daemon capabilities still
advertise the current runtime daemon API line until the daemon actively validates
0.1 compatibility headers.

Current limitation: the daemon route implementation does not actively negotiate
API versions or reject unsupported `X-Splendor-API-Version` values. Compatibility
is therefore validated through the OpenAPI contract, SDK docs/tests, and the 0.1
conformance suite, not by runtime version negotiation.

Future active negotiation must fail closed on unsupported versions and document
accepted version ranges before becoming stable.

The Python daemon client and `splendorctl daemon request` send the same version
and client attribution headers. `splendorctl daemon request` is intentionally
narrow and local: it accepts only explicit `http://127.0.0.1`, `localhost`, or
loopback daemon URLs, requires a caller token, supports caller-credential header
files for read requests, and requires JSON body files containing credentials for
mutating requests. It is a daemon-management wrapper, not a gateway bypass.

## Layered daemon authorization

Daemon communication must preserve these layers:

```text
transport security -> caller authentication -> endpoint scopes -> signed work order -> tenant/agent/run checks -> gateway verification
```

A caller token authenticates the app. A signed work order authorizes run creation
or resume. The Action Gateway authorizes side effects. No layer replaces the
others.

The runtime daemon API was originally the 0.02-S5 local control boundary for
Splendor runs.
It exposes a minimal HTTP surface for creating, starting, pausing, resuming,
stopping/cancelling, inspecting, exporting traces, replaying, and safely
submitting actions to a local runtime.

This API strengthens the `SDK/API`, `runtime context`, `percept`, `state graph`,
`trace store`, `action gateway`, and `replay` primitives. It is local-only and
foundation-oriented; it is not a fleet manager or production auth provider.

## Endpoint summary

| Method | Path | Purpose | Scope |
| --- | --- | --- | --- |
| `POST` | `/runs` | Create a local run from a signed work order | `splendor.runs.create` |
| `GET` | `/runs/{run_id}` | Inspect local run status | `splendor.runs.read` |
| `POST` | `/runs/{run_id}/start` | Execute one local scheduler tick | `splendor.runs.start` |
| `POST` | `/runs/{run_id}/pause` | Mark a local run paused | `splendor.runs.pause` |
| `POST` | `/runs/{run_id}/resume` | Resume a paused run and execute one tick | `splendor.runs.resume` |
| `POST` | `/runs/{run_id}/stop` | Mark a local run stopped | `splendor.runs.stop` |
| `POST` | `/runs/{run_id}/cancel` | Cancel a local run while preserving trace/state evidence | `splendor.runs.stop` |
| `POST` | `/runs/{run_id}/percepts` | Append a daemon-submitted percept queue entry | `splendor.percepts.append` |
| `POST` | `/runs/{run_id}/policies/sync` | Sync or mark failure for the run policy bundle cache | `splendor.policies.sync` |
| `GET` | `/runs/{run_id}/state-head` | Return latest committed state node metadata | `splendor.state.read` |
| `GET` | `/runs/{run_id}/traces` | Read ordered trace records; requires `redaction_policy` | `splendor.traces.read` |
| `POST` | `/runs/{run_id}/traces/export` | Export ordered trace records with redaction policy and integrity metadata | `splendor.traces.read` |
| `POST` | `/runs/{run_id}/replay` | Start inspect-only replay summary | `splendor.replay.create` |
| `POST` | `/actions` | Submit an action through the run gateway | `splendor.actions.submit` |
| `GET` | `/health` | Read local daemon health | `splendor.health.read` |
| `GET` | `/version` | Read daemon/runtime/schema compatibility metadata | `splendor.health.read` |
| `GET` | `/capabilities` | Read local daemon capabilities | `splendor.capabilities.read` |

The OpenAPI description is maintained in
[`openapi/splendor-runtime-daemon.yaml`](../../openapi/splendor-runtime-daemon.yaml).

`GET /capabilities` returns `service_profiles` with truthful maturity labels for
the current daemon surface. The local run API is reported as implemented for the
0.1 compatibility line, bounded create-run idempotency v0 is reported as
experimental for `POST /runs` only, physical/device endpoints are reported as
simulated, and v2 watch streams plus G00/G06 evidence remain unavailable/not
exercised until an executable fixture proves them. Capability labels are
discovery metadata, not action or work-order authority.

## Local transport and security

The reference daemon binary binds to `127.0.0.1:8077` and emits a visible warning
that explicit local-only insecure dev mode is active. Non-dev callers must use
the daemon security contract from
[`daemon-security-boundary.md`](daemon-security-boundary.md): authenticated caller
identity, endpoint scope, tenant binding, audience binding, expiry, revocation,
and mutating-call audit attribution.

Run creation and run resume require signed, unexpired, unrevoked, scoped work
orders. The daemon checks work-order tenant, run scope where applicable, and
agent compatibility for run creation. Caller credentials never authorize actions
directly; `/actions` always submits to the `VerifiedActionGateway` path with
`GatewayVerificationState::Required`.

When `CreateRunRequest.policy_bundle_required` is true, the daemon also requires
a signed policy bundle and rejects invalid, future-issued, expired, revoked,
malformed, or incompatible bundles before policy invocation or adapter execution
can occur.
The endpoint and request/response shapes are unchanged, but daemon-visible policy
errors now also include monotonic cache reasons such as
`policy_cache_install_rollback`, `policy_cache_install_conflict`, and scoped
revocation mismatch reasons. A failed candidate cannot reconnect a disconnected
cache.

## Run lifecycle

`POST /runs` creates an in-memory local run slot with:

- one tenant context;
- one agent runtime context;
- an in-memory trace store;
- an in-memory state store;
- a queued perceptor for daemon-submitted percepts;
- a scheduler containing one loop engine;
- a `VerifiedActionGateway` with explicitly registered local adapters;
- optional `approval_policies` evaluated by the gateway approval verifier.

`CreateRunRequest` also requires non-blank `request_id` and `idempotency_key`.
The request ID is correlation only and remains distinct from `run_id` and
`work_order_id`. The daemon owns a bounded in-memory create-run idempotency ledger
scoped by caller/principal, tenant, agent, work order, resolved run ID, and the
creation request fingerprint. The first accepted request returns an
`idempotency_receipt_id`; an exact retry with the same key and scope returns the
same run and receipt with `duplicate: true` and does not create another run slot.
Reusing an idempotency key for a different scope fails closed with
`create_run_idempotency_scope_mismatch`; public error details intentionally omit
raw attempted/existing scope fields and caller identifiers.

`CreateRunRequest.approval_policies` installs local approval policies for the run.
`LifecycleRequest.approval_evidence` and `SubmitActionRequest.approval_evidence`
carry scoped approval evidence into the verifier chain. Evidence is never treated
as direct action authority.

`start` and `resume` execute exactly one scheduler tick. This keeps the local
daemon deterministic while proving the daemon boundary. Continuous/background
scheduling is not introduced here.

Run statuses are:

```text
created
running
waiting_for_approval
paused
denied
expired
stopped
failed
```

When a tick returns an approval-required action, the daemon records
`RunPaused { reason: "waiting_for_approval" }`, stores the pending approval
context for inspection/replay, and returns `waiting_for_approval`. Resume from
that state requires a signed resume work order and
`LifecycleRequest.approval_evidence`; missing evidence returns
`403 approval_required` before a tick is run.

## Percept ingestion

`POST /runs/{run_id}/percepts` accepts a `Percept` only when the schema and
provenance source match the run's allowlist. Accepted percepts are consumed by
the run's queued perceptor on the next tick and appear in the normal
`PerceptsReceived` trace event, matching SDK/CLI perceptor ingestion semantics.

The daemon also records a `PerceptsAppended` trace event through the run's trace
runtime, preserving trace sequence continuity before the next tick.

## State-head behavior

`GET /runs/{run_id}/state-head` returns the latest state node committed by the
loop engine. The daemon verifies the state node exists in the backing state store
through `StateStore::get_node` before returning metadata.

Response fields include:

- `state_node_id`;
- `parent_state_node_ids`;
- `data_hash`;
- commit timestamp;
- optional state label.

## Trace behavior

Trace responses return `TraceRecord` values from the run's trace store. Records
are returned in monotonic sequence order. Range reads use `start` inclusive and
`end` exclusive semantics from `TraceStore::read_range`. `GET /runs/{run_id}/traces`
and `POST /runs/{run_id}/traces/export` both require an explicit
`redaction_policy`; the export response also includes a deterministic
`integrity_hash` summary over the returned trace chain.

Lifecycle and daemon-specific events added for 0.02-S5:

```text
DaemonAudit
RunPaused
RunResumed
RunStopped
PerceptsAppended
```

`DaemonAudit { endpoint, audit }` is emitted for accepted mutating daemon calls
after S0 security validation and before the runtime mutation, preserving caller
identity and credential attribution in the run trace.

Trace export is a POST audit boundary even though it uses the trace-read scope:
its request body must include non-null `credential` and `audit_attribution`, and
the audit principal and `credential_id` must match the caller credential.

Policy distribution events added in 0.04-S5:

```text
PolicyBundleAccepted
PolicyBundleRejected
PolicySyncFailed
PolicyExpired
PolicyRevoked
```

Policy sync emits daemon audit attribution for `splendor.policies.sync`. A sync
failure records `PolicySyncFailed`; the prior cached bundle remains installed.
A matching trusted revocation candidate may additionally tombstone and block
that prior bundle, while unrelated or older revocations cannot mutate it.

Action submissions through `/actions` emit normal action trace events:

```text
ActionVerificationStarted
ActionVerificationCompleted
ActionNeedsApproval | ActionNeedsIntervention | ActionExecuted | ActionDenied | ActionFailed
OutcomeRecorded
```

Approval flows may also emit `ApprovalRequested`, `ApprovalGranted`,
`ApprovalDenied`, `ApprovalExpired`, and `ApprovalRevoked`. These are verifier
facts only; they do not authorize adapter execution outside the gateway.

## Replay behavior

`POST /runs/{run_id}/replay` is inspect-only. It reads trace records, validates
that sequence numbers are contiguous and run-scoped, and returns a replay summary
with event counts and `approval_events`. It does not invoke perceptors, policies,
gateways, verifiers, or adapters, and cannot repeat filesystem, network,
database, webhook, shell, or external-service side effects.

Replay request bodies must include non-null `credential` and
`audit_attribution`; both principal identity and `credential_id` are validated
before replay evidence is read.

`approval_events` reports approval lifecycle events with lifecycle label,
approval context, optional reason, trace event ID, and sequence. It explains why
approval was required and what grant, denial, unsupported schema, expiry, or
revocation changed the outcome without resuming the run or executing an adapter.

## Structured errors

All daemon errors use this JSON shape:

```json
{
  "code": "invalid_run",
  "message": "run was not found",
  "details": { "run_id": "..." }
}
```

Required 0.02-S5 failures include:

| Condition | HTTP | Code |
| --- | --- | --- |
| Invalid run | `404` | `invalid_run` |
| Malformed percept body | `400` | `malformed_percept` |
| Invalid policy bundle | `400` or `403` | policy validation reason code |
| Unauthorized or missing scope/action trace link | `403` | daemon security error code |
| Runtime unavailable | `503` | `runtime_unavailable` |
| Resume from `waiting_for_approval` without evidence | `403` | `approval_required` |
| Gateway denial | `200` with `ActionOutcome.status = Denied` | action outcome |
| Governance intervention required | `200` with `ActionOutcome.status = NeedsIntervention` | action outcome |

Gateway denials are action outcomes, not HTTP transport failures, because the
gateway successfully evaluated and denied the requested action.

Stable client handling rules:

- parse `code` as the programmatic daemon error discriminator;
- treat `message` as human-readable diagnostics, not an authorization fact;
- treat `details` as structured diagnostics whose exact keys may vary by code;
- handle HTTP `503 runtime_unavailable` as fail-closed runtime unavailability;
- handle gateway `Denied`, `NeedsApproval`, and `NeedsIntervention` as action
  outcomes where adapter execution did not occur;
- never retry side-effectful actions blindly after transport, verifier, gateway,
  state, or trace failures.

Client transport errors that happen before a daemon response should use the
client's stable error wrapper. For `@splendor/client`, this is
`SplendorClientError` with `status: 0` and `code: "network_error"`.

Conformance failures use the report shape documented in
`docs/spec/0.1/conformance.md` and include `case_id`, `primitive`,
`requirement`, `path`, `status`, and `message`.

## Compatibility notes

This reference is part of the 0.1 stable compatibility surface for documented
daemon endpoints and error shapes. It does not stabilize private Rust internals,
production authentication infrastructure, native Node bindings, browser runtime
behavior, fleet scheduling, or undocumented API fields.

Run 0.1 conformance validation from the repository root:

```bash
python conformance/0.1/run-conformance.py
```

The conformance suite proves stable fixture compatibility for runtime loop order,
gateway paths, trace/state/replay behavior, messages, work orders, governance,
adapter manifests, and S1 primitive examples. It is not a production use-case E2E
or physical safety certification claim.

## Non-goals

- No remote node registry.
- No fleet scheduling.
- No production OAuth/OIDC/PKI server.
- No approval queue UI, notification system, new escalation or circuit-breaker
  management API, or workflow DSL.
- No background resident scheduler.
- No native Node binding or browser runtime guarantee.
