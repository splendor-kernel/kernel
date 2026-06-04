# Splendor 0.1 SDK and API Stability

Milestone: `Splendor0.1-dev`
Sprint: `0.1-S4 - SDK and API stabilization`
FRs: `FR-0.1-03`, `FR-0.1-08`

This document names the public 0.1 SDK/API compatibility surface across Rust,
Python, daemon HTTP, and TypeScript. It stabilizes integration boundaries, not
undocumented implementation internals.

## Stable Public Surface

### Rust

The stable Rust 0.1 surface is limited to these explicitly named exported items
and their documented serialization/security semantics:

| Crate | Stable public items |
| --- | --- |
| `splendor-types` | ID newtypes `TenantId`, `AgentId`, `RunId`, `TickId`, `ActionId`, `StateNodeId`, `TraceEventId`, `MessageId`, `WorkOrderId`, `ApprovalId`, `FleetId`, `NodeId`, and `InstanceId`; primitive structs/enums `Action`, `Percept`, `PerceptProvenance`, `QuotaUsage`, `VerificationResult`, `Message`, `MessageEnvelope`, `TraceEvent`, `TraceEventKind`, `WorkOrder`, `WorkOrderEnvelope`, `WorkOrderPlacement`, `WorkOrderQuotaPolicy`, `ApprovalEvidence`, `ApprovalPolicy`, `ApprovalDecision`, `GovernanceState`, `CircuitBreaker`, `DeviceProfile`, and `CapabilityDocument`; daemon security structs/enums `AppPrincipal`, `ClientPrincipal`, `CallerCredential`, `CredentialBinding`, `CredentialAudience`, `EndpointScope`, `RevocationStatus`, `AuditAttribution`, `WorkOrderAuthorization`, `WorkOrderSignature`, `DaemonEndpoint`, and `GatewayVerificationState`; schema constants exported for work orders, approvals, governance, policy bundles, capabilities, and stable 0.1 primitives where documented. |
| `splendor-gateway` | `ActionRequest`, `ActionOutcome`, `ActionStatus`, `ActionGateway`, `ActionAdapter`, `AdapterResult`, `AdapterError`, `VerifiedActionGateway`, `PolicyApprovalVerifier`, `SafetyVerifier`, `SafetyEvidence`, `SafetyVerification`, and `SAFETY_EVIDENCE_SCHEMA_VERSION`. |
| `splendor-daemon` | `router`, `DaemonState`, `DaemonConfig`, `RunStatus`, documented request/response structs used by `openapi/splendor-runtime-daemon.yaml`, and structured `ApiError` response shape. |

All other Rust crates, modules, structs, traits, helper functions, in-memory store
implementations, scheduler internals, private handlers, test fixtures, and
undocumented re-exports are non-stable in 0.1 even when they are public in the
current Rust source.

Stable Rust semantics include identity separation, gateway mediation for side
effects, fail-closed verifier uncertainty, explicit state commits, append-only
trace records, and replay no-side-effect defaults.

### Python SDK

The stable Python 0.1 local SDK surface is:

- `splendor.KernelRuntime`
- `splendor.KernelRuntimeConfig`
- `splendor.Action`
- `splendor.ActionCandidate`
- `splendor.Percept`
- `splendor.Constraint`
- `splendor.QuotaPolicy`
- `splendor.QuotaUsage`
- `splendor.VerificationResult`
- `splendor.CANONICAL_ID_FIELDS`
- `splendor.STABLE_0_1_PRIMITIVES`
- `splendor.STABLE_0_1_REQUIRED_FIELDS`
- `splendor.STABLE_0_1_RESERVED_EXTENSION_KEYS`
- `splendor.STABLE_0_1_ENUM_VALUES`

The stable local methods are `create_tenant`, `create_agent`,
`register_perceptor`, `register_policy`, `register_constraints`,
`register_adapter`, `subscribe_traces`, `tail_traces`, `replay_run`, `run_once`,
and `agent_run_id`.

Python policy callbacks propose actions only. Official examples must not call
filesystem, network, database, shell, device, or external service side effects
directly from policy code.

### Runtime Daemon API

The stable daemon compatibility boundary is the local HTTP API documented in
`docs/reference/runtime-daemon-api.md`. The OpenAPI document remains versioned to
the current runtime API metadata and carries a 0.1 compatibility note. Stable
endpoint names are:

- `POST /runs`
- `GET /runs/{run_id}`
- `POST /runs/{run_id}/start`
- `POST /runs/{run_id}/pause`
- `POST /runs/{run_id}/resume`
- `POST /runs/{run_id}/stop`
- `POST /runs/{run_id}/percepts`
- `POST /runs/{run_id}/policies/sync`
- `GET /runs/{run_id}/state-head`
- `GET /runs/{run_id}/traces`
- `POST /runs/{run_id}/replay`
- `POST /actions`
- `GET /health`
- `GET /capabilities`

Stable daemon security layering remains:

```text
transport security -> caller authentication -> endpoint scopes -> signed work order -> tenant/agent/run checks -> gateway verification
```

A daemon token authenticates the caller. It does not authorize arbitrary agent
actions. Side effects are authorized only by the Action Gateway and verifier
chain.

### TypeScript

The stable TypeScript 0.1 surface is:

- `@splendor/types` exported identity aliases, primitive interfaces, daemon
  request/response interfaces, security-boundary interfaces, action/gateway
  outcome types, stable primitive constants, and JSON helper types.
- `@splendor/client` `SplendorClient`, `SplendorClientOptions`,
  `SplendorClientError`, `FetchLike`, `AppendPerceptOptions`,
  `ReadTracesOptions`, and `RequestReplayOptions`.

TypeScript is a control-plane/client surface only. It is not a runtime, verifier,
gateway, adapter executor, state graph, trace store, replay engine, native Node
binding, or browser runtime guarantee.

## Internal Or Experimental Surface

The following are not stable 0.1 APIs:

- Rust private modules, helper functions, test fixtures, in-memory store
  implementation details, scheduler internals, local queue internals, internal
  gateway verifier ordering details not documented in reference docs, and private
  daemon handler functions.
- Python underscored helpers, dataclass private attributes, callback invocation
  order beyond documented runtime loop ordering, and test-only fixtures.
- TypeScript package internals, private class methods, generated build output,
  test stubs, fetch mocks, and any package not documented as `@splendor/types` or
  `@splendor/client`.
- Native Node/N-API bindings, browser runtime execution, production OAuth/PKI,
  fleet auth rollout, universal transport negotiation, marketplace semantics,
  and product UI surfaces.

## Compatibility Guarantees

Within the 0.1 line, patch releases must not:

- remove or rename stable required fields;
- change stable serialized enum spelling;
- collapse distinct identity fields;
- convert fail-closed denial/intervention into allow;
- allow side-effect bypass around the Action Gateway;
- make replay execute side effects by default;
- allow extension metadata to grant authority;
- remove stable daemon endpoints without a documented replacement;
- make SDK clients silently fall back to unauthenticated communication.

Patch releases may:

- add optional non-authorizing fields;
- add stricter validation that fails closed;
- accept dev-era aliases as input while emitting stable fields;
- add new trace events for newly implemented behavior without breaking required
  ordering;
- add SDK convenience wrappers that preserve primitive identity, scope, trace, and
  gateway semantics.

Minor 0.1-compatible releases may add documented optional capabilities, endpoint
parameters, or SDK helpers if older clients can ignore them safely or fail closed.

Breaking changes require a new schema/API version or RFC-backed migration path.

## Deprecation Policy

Deprecations must include:

- the deprecated name;
- the replacement;
- the first release where deprecation is documented;
- migration guidance;
- whether serializers still emit the old field;
- whether deserializers still accept the old field;
- the removal target, if any.

Stable 0.1 removals are not allowed in a patch release unless the deprecated item
was never part of the stable public surface. Removing a stable accepted input or
stable SDK method requires a new major schema/API version or explicit migration
RFC.

Current deprecations remain those listed in
`docs/spec/0.1/schema-versioning.md`.

## Daemon Version Headers

Stable clients should send:

```text
X-Splendor-API-Version: 0.1
X-Splendor-Client: <client-name>
```

The current TypeScript client sends `X-Splendor-API-Version` and allows callers to
override it through `apiVersion`. Its default remains `0.02-dev`, and daemon
capabilities currently advertise the existing runtime daemon API line rather than
an actively negotiated 0.1 protocol. The current daemon route implementation does
not perform active version negotiation or reject unsupported version headers. This
is a documented limitation, not a compatibility guarantee.

Until active negotiation exists, compatibility is proven by schema/API docs,
OpenAPI review, SDK contract tests, and the 0.1 conformance suite.

## Stable Error Shapes

### Daemon API Errors

Daemon non-2xx errors use:

```json
{
  "code": "invalid_run",
  "message": "run was not found",
  "details": { "run_id": "..." }
}
```

Clients must treat `code` as the stable programmatic field and `details` as
structured diagnostics. Message text is human-readable and should not be parsed
for authorization decisions.

### Gateway Outcomes

Gateway decisions are successful daemon responses with an `ActionOutcome.status`,
not transport errors, when the gateway evaluated the action:

```text
Executed | Denied | NeedsApproval | NeedsIntervention | Failed
```

`Denied`, `NeedsApproval`, and `NeedsIntervention` mean adapter execution did not
occur. Lowercase strings such as `executed`, `denied`, `needs_approval`, and
`needs_intervention` are Python-local/dev-compatible status strings or trace event
suffixes where explicitly documented; they are not the stable daemon/TypeScript
serialized `ActionOutcome.status` values.

### TypeScript Client Errors

`SplendorClientError` is the stable client error shape for daemon transport and
response failures:

- `status`
- `code`
- `message`
- `details`
- `requestId`
- `responseBody`

Network failures use `status: 0` and `code: "network_error"`. Invalid JSON uses
`code: "invalid_json"`.

### Python Validation Errors

Python SDK validation failures raise Python exceptions, usually `ValueError` or
`KeyError`, before side-effect execution when identity, tenant policy, adapter,
permission, quota, precondition, constraint, trace, state, or replay validation
fails. Stable examples should assert action outcomes where the runtime can record
them and use exception checks only for input validation errors.

### Conformance Failures

The 0.1 conformance runner emits stable JSON reports with
`schema_version: "splendor.conformance_report.v1"`. Each result includes
`case_id`, `primitive`, `requirement`, `path`, `status`, and `message`.

## Conformance Alignment

Run:

```bash
python conformance/0.1/run-conformance.py
```

This proves stable fixture compatibility for runtime loop ordering, gateway
denial/execution/failure paths, trace identity/order, state commits and commit
failures, replay side-effect suppression, message causality, work-order rejection,
governance paths, adapter manifest evidence, and S1 stable primitive examples.

Passing this fixture suite is required compatibility evidence. It is not a claim
that production fleet, governance UI, physical safety certification, or complete
use-case E2E acceptance is implemented.

## Stable Example Rule

Stable 0.1 examples must use only documented public API surfaces and must not:

- execute side effects directly from policy callbacks;
- call adapter callbacks directly for privileged operations;
- use unauthenticated daemon communication except explicit local-only dev mode
  with warning;
- treat daemon tokens as action authority;
- claim native Node, browser runtime, fleet production auth, or physical safety
  certification unless separately implemented and documented.
