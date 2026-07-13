# `@splendor/client`

`@splendor/client` is a thin TypeScript client for the local Splendor runtime
daemon API. It serializes requests, attaches caller authentication, preserves
structured daemon errors, and returns typed responses from the daemon.

For the stable 0.1 public client surface, see [`stable-0.1.md`](stable-0.1.md).

It does **not** implement Splendor kernel behavior. It does not run policies,
evaluate verifiers, execute adapters, commit state, write trace events, or replay
actions.

## Construction

```ts
import { SplendorClient } from "@splendor/client";

const client = new SplendorClient({
  baseUrl: "http://127.0.0.1:8077",
  token: process.env.SPLENDOR_TOKEN!,
  apiVersion: "0.1",
});
```

The `token` option is required. The client rejects blank tokens and never
silently falls back to unauthenticated communication. Explicit insecure local
development mode remains a daemon-side security-boundary contract; this client does not
turn it on implicitly.

Bearer transport requires an absolute HTTPS base URL. Plain HTTP is accepted
only for explicit `localhost`, `127.0.0.1`, or `[::1]` local development. The
constructor rejects remote HTTP, relative URLs, unsupported schemes, URL
userinfo/passwords, query, and fragment before any request. URL path prefixes
such as `/v1` remain supported.

Every request includes:

- `Authorization: Bearer <token>`
- `Accept: application/json`
- `X-Splendor-API-Version: <apiVersion>`
- `X-Splendor-Client: @splendor/client`

Stable 0.1 clients should send `apiVersion: "0.1"` when targeting a daemon that
documents 0.1 compatibility. Current implementation limitation: the daemon does
not actively negotiate or reject API version headers, and this package still
defaults to `0.02-dev` until that server behavior exists.

## Methods

### `createRun(request)`

Sends `POST /runs` with:

```ts
{
  request_id: string,
  idempotency_key: string,
  tenant_id: TenantId,
  agent_id: AgentId,
  work_order: WorkOrderEnvelope,
  credential: CallerCredential | null,
  audit_attribution: AuditAttribution | null,
  allowed_actions: string[],
  allowed_adapters: string[],
  allowed_permissions: string[],
  policy_actions: DaemonActionCandidate[],
  policy_bundle_required: boolean,
  policy_bundle: PolicyBundleEnvelope | null,
  registered_actions: RegisteredAction[],
  approval_policies: ApprovalPolicy[],
  circuit_breakers: CircuitBreaker[],
  allowed_percept_schemas: string[],
  allowed_percept_sources: string[],
  initial_state: JsonValue | null,
  snapshot_interval: number | null
}
```

The method requires non-blank `request_id` and `idempotency_key` fields, a signed,
scoped work-order object, and `audit_attribution`.
Those requirements mirror the daemon security boundary: caller authentication does
not authorize a run by itself. The client uses the Rust daemon's flattened
`CreateRunRequest` schema, not a `{ run_config, work_order, audit }` wrapper.

`request_id` is caller correlation only. `idempotency_key` suppresses duplicate
`POST /runs` work within the daemon's create-run idempotency scope. A retry with
the same key and scope receives the same run/receipt with `duplicate: true`; key
reuse for a different scope fails closed.

Resident mutating bearer JTIs are one-use. A safe create retry therefore uses a
fresh bearer while preserving the same request/idempotency keys and authority;
the daemon deliberately excludes the ephemeral JTI correlation digest from the
durable create scope. Read-only requests may reuse an unexpired token.

The client performs only structural fail-closed checks before sending the
request: signature metadata must be present, `schema_version`, `work_order_id`,
and `objective` must be present, allowed actions/adapters must be scoped,
`placement.target` must be present, `revocation` must be `active`, and
`expires_at` must be in the future. Cryptographic signature verification and
compatibility checks remain daemon/runtime responsibilities.

### `inspectRun(runId)`

Sends `GET /runs/:run_id` and returns local lifecycle metadata, including run
status, state-head reference, tick count, adapter execution count, and timestamps.

### `startRun(runId, request)` / `pauseRun(runId, request)` / `resumeRun(runId, request)` / `stopRun(runId, request)`

Lifecycle mutating calls send `LifecycleRequest`:

```ts
{
  credential: CallerCredential | null,
  work_order: WorkOrderEnvelope | null,
  audit_attribution: AuditAttribution | null,
  reason: string | null
}
```

`startRun` and `resumeRun` return a one-tick `TickResponse`; `pauseRun` and
`stopRun` return `RunInspectResponse`. `resumeRun` still requires the daemon to
validate a signed, unexpired, unrevoked resume work order.

### `appendPercept(runId, percept, { audit, credential })`

Sends `POST /runs/:run_id/percepts` with a run-scoped percept and audit
attribution. The daemon remains responsible for tenant/run binding, allowed
percept schema checks, provenance checks, trace emission, and state/runtime
effects.

### `readTraces(runId, { redactionPolicy, start, end })`

Sends `GET /runs/:run_id/traces`. `redactionPolicy` is required because the
daemon security boundary does not permit raw trace access without visibility and
redaction policy checks.

### `streamTraces(runId, options)`

Returns an async iterable over `readTraces`. In the current client this is a thin read-backed
iterator, not a transport/broker implementation.

### `getStateHead(runId)`

Sends `GET /runs/:run_id/state-head` and returns `StateHead`.

### `requestReplay(runId, options)`

Sends `POST /runs/:run_id/replay`. The request defaults to
`mode: "inspect_only"`. Replay remains daemon/runtime-owned and must not
re-execute side-effectful actions.

### `submitAction(request)`

Sends `POST /actions` with the Rust-aligned `SubmitActionRequest` shape. The
client requires `causal_trace_id` and audit attribution before sending, but it
does not authorize side effects. The daemon still validates endpoint scope and
routes the action through the gateway with `GatewayVerificationState::Required`.

### `getHealth()` / `getCapabilities()`

Read local daemon status and the advertised endpoint list. These helpers
do not mutate runtime state.

## Structured errors

Non-2xx responses throw `SplendorClientError` with:

- `status` — HTTP status code;
- `code` — daemon error code when present;
- `message` — daemon error message when present;
- `details` — structured daemon details when present;
- `requestId` — `x-request-id` or `x-correlation-id` header when present;
- `responseBody` — parsed JSON body or raw text.

This preserves daemon failure information for callers and tests without turning
authorization, verifier, gateway, state, or replay failures into implicit
success.

## Version compatibility

The stable 0.1 package surface is documented in `stable-0.1.md`. Public schema
names and field names are checked against canonical Rust/docs sources by local
TypeScript contract tests and the 0.1 conformance suite. If a later daemon API
changes endpoint shape or schema fields, the TypeScript package version and
compatibility notes must change with it.
