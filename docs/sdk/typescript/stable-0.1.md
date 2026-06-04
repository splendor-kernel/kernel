# TypeScript Stable 0.1 Surface

The TypeScript 0.1 surface is a schema-aligned type package plus an authenticated
daemon HTTP client. It does not implement Splendor runtime semantics.

## Stable Packages

| Package | Stable purpose |
| --- | --- |
| `@splendor/types` | Stable TypeScript interfaces, identity aliases, primitive constants, daemon request/response shapes, and client-facing JSON types. |
| `@splendor/client` | Thin authenticated client for the runtime daemon API. |

## `@splendor/types` Stable Exports

Stable categories include:

- identity aliases such as `TenantId`, `AgentId`, `RunId`, `ActionId`,
  `TraceEventId`, `MessageId`, `StateNodeId`, and `WorkOrderId`;
- primitive interfaces such as `Percept`, `Action`, `VerificationResult`,
  `ActionRequest`, `ActionOutcome`, `TraceEvent`, `Message`, `WorkOrderEnvelope`,
  `ApprovalEvidence`, `StateHead`, and `ReplayResponse`;
- daemon security and request/response interfaces such as `CallerCredential`,
  `AuditAttribution`, `CreateRunRequest`, `LifecycleRequest`,
  `SubmitActionRequest`, `TracePageResponse`, `HealthResponse`, and
  `CapabilitiesResponse`;
- constants `STABLE_0_1_PRIMITIVES`, `STABLE_0_1_REQUIRED_FIELDS`,
  `STABLE_0_1_RESERVED_EXTENSION_KEYS`, and `STABLE_0_1_ENUM_VALUES`.

These exports are stable as schema-facing types. They do not prove that an action
was authorized, verified, executed, traced, or replayed. That evidence comes from
daemon/runtime traces and gateway outcomes.

## `@splendor/client` Stable Exports

Stable exports:

- `SplendorClient`
- `SplendorClientOptions`
- `SplendorClientError`
- `FetchLike`
- `AppendPerceptOptions`
- `ReadTracesOptions`
- `RequestReplayOptions`

Stable client methods:

- `createRun(request)`
- `inspectRun(runId)`
- `startRun(runId, request)`
- `pauseRun(runId, request)`
- `resumeRun(runId, request)`
- `stopRun(runId, request)`
- `appendPercept(runId, percept, options)`
- `readTracePage(runId, options)`
- `readTraces(runId, options)`
- `streamTraces(runId, options)`
- `getStateHead(runId)`
- `requestReplay(runId, options)`
- `submitAction(request)`
- `getHealth()`
- `getCapabilities()`

The client requires a non-empty `token` and never silently falls back to
unauthenticated daemon communication.

## Stable Headers And Current Limitation

Every client request sends:

```text
Authorization: Bearer <token>
Accept: application/json
X-Splendor-API-Version: <apiVersion>
X-Splendor-Client: @splendor/client
```

Stable 0.1 clients should use `apiVersion: "0.1"` when targeting a daemon that
documents 0.1 compatibility. The current package default remains `0.02-dev`
because the daemon route implementation does not yet actively negotiate or reject
version headers. Callers can pass `apiVersion: "0.1"`; this is a compatibility
declaration header, not active negotiation in the current daemon.

## Stable Error Handling

Non-2xx daemon responses throw `SplendorClientError` with:

- `status`
- `code`
- `message`
- `details`
- `requestId`
- `responseBody`

Transport failures before a response use `status: 0` and `code: "network_error"`.
Non-JSON daemon responses use `code: "invalid_json"`.

Gateway denials are not TypeScript transport errors when the daemon returns a
successful `ActionOutcome`. Handle `ActionOutcome.status` values
programmatically:

```text
executed | denied | failed | needs_approval | needs_intervention
```

`denied`, `needs_approval`, and `needs_intervention` mean the adapter did not
execute.

## Compatibility And Deprecation

Patch releases in the 0.1 line will not remove stable exports or change stable
serialized field names. Additive optional fields and helpers are allowed when
older clients can ignore them or fail closed.

Deprecated TypeScript exports must document a replacement, migration path, and
removal target. Removing a stable type, method, or field requires a new major
schema/API version or RFC-backed migration.

## Non-Stable TypeScript Surface

The following are not stable 0.1 APIs:

- private class methods and package internals;
- tests, fetch stubs, generated build output, and package-local fixtures;
- native Node/N-API bindings;
- browser runtime execution;
- independent verifier/gateway/runtime semantics in TypeScript;
- production auth server, fleet transport, governance UI, or physical-device
  certification behavior.

## Stable Example

Use `examples/typescript-daemon-client/` for the stable daemon-client pattern. It
requires an authenticated caller token, signed work-order data, audit attribution,
and daemon-side gateway enforcement.

## Validation Commands

Run the 0.1 conformance suite:

```bash
python conformance/0.1/run-conformance.py
```

Run TypeScript tests when TypeScript types or client behavior changes:

```bash
npm test
```

Documentation-only changes that do not modify TypeScript package source should
record why `npm test` was not required.
