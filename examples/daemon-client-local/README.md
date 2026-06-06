# Daemon Client Local Example

This example documents the stable 0.1 local runtime daemon API path. It is
intentionally local-only and uses explicit insecure development mode on loopback.
Do not use it as a production transport.

Stable API reference: `docs/reference/runtime-daemon-api.md`.

## Run the reproducible smoke test

```bash
cargo test -p splendor-daemon
```

The integration tests create a run, append a percept, start a tick, pause,
resume, stop/cancel, inspect state-head, page and export traces, submit a denied
action through the gateway, and start inspect-only replay without increasing
adapter execution count.

## Start the local daemon binary

```bash
cargo run -p splendor-daemon
```

The daemon binds to `127.0.0.1:8077` and prints a warning that explicit local-only
insecure development mode is active.

## Public client workflow coverage

The UC-E2E-S2 acceptance scenario exercises the same management workflow through
four public paths:

- raw documented daemon HTTP;
- `@splendor/client` from TypeScript;
- `python.splendor.daemon_client.SplendorDaemonClient`;
- `splendorctl daemon request`.

Each path creates a run from a signed work order, appends a percept, starts a
tick, submits an action through `/actions` (and therefore the gateway), reads
state/traces, exports traces, requests inspect-only replay with
`side_effects_allowed=false`, and cancels the run.

Example CLI wrapper shape:

```bash
splendorctl daemon request \
  --method GET \
  --url http://127.0.0.1:8077/health \
  --token "$SPLENDOR_CALLER_TOKEN" \
  --caller-credential ./caller-credential.json
```

For mutating daemon requests, pass `--body ./request.json`; the body must contain
the scoped caller credential and audit attribution expected by the endpoint. The
CLI refuses anonymous fallback and refuses non-loopback daemon URLs.

## Minimal explicit local-dev request shape

The daemon expects JSON. Run creation requires authenticated caller attribution
and a signed, scoped `WorkOrderEnvelope`. The shape below is for the daemon's
explicit loopback-only local development mode; non-dev daemon calls must use a
real `CallerCredential` with expiry, endpoint scopes, tenant binding, audience
binding, and revocation status. Do not treat the bearer token alone as action
authority.

```json
{
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "agent_id": "00000000-0000-0000-0000-000000000002",
  "work_order": {
    "schema_version": "splendor.work_order.v1",
    "work_order_id": "wo_local_example",
    "tenant_id": "00000000-0000-0000-0000-000000000001",
    "agent_id": "00000000-0000-0000-0000-000000000002",
    "run_id": null,
    "objective": "Run the local daemon example",
    "allowed_actions": ["allowed_action"],
    "allowed_adapters": ["daemon.local"],
    "allowed_permissions": [],
    "data_refs": [],
    "quotas": {
      "max_actions_per_tick": 1,
      "max_action_duration_ms": null,
      "max_filesystem_read_bytes": null,
      "max_filesystem_write_bytes": null,
      "max_network_read_bytes": null,
      "max_network_write_bytes": null,
      "max_http_requests_per_minute": null
    },
    "placement": {
      "target": "local_resident",
      "data_locality": null,
      "requires_gpu": false,
      "dedicated_instance": false,
      "required_capabilities": [],
      "max_runtime_ms": null
    },
    "issued_at": "2099-01-01T00:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z",
    "revocation": "active",
    "signature": { "key_id": "local-dev", "signature": "signed-for-dev" }
  },
  "credential": {
    "credential_id": "cred_local_example",
    "principal": {
      "app": { "app_principal_id": "app_local", "label": "Local daemon example" },
      "client_principal_id": "client_local",
      "label": "Local developer client"
    },
    "scopes": ["runs_create"],
    "binding": { "tenant": { "tenant_id": "00000000-0000-0000-0000-000000000001" } },
    "audience": { "daemon": { "daemon_id": "daemon_local" } },
    "expires_at": "2099-01-01T00:00:00Z",
    "revocation": "active"
  },
  "audit_attribution": {
    "principal": {
      "app": { "app_principal_id": "app_local", "label": "Local daemon example" },
      "client_principal_id": "client_local",
      "label": "Local developer client"
    },
    "credential_id": "cred_local_example",
    "requested_at": "2099-01-01T00:00:00Z"
  },
  "allowed_actions": ["allowed_action"],
  "allowed_adapters": ["daemon.local"],
  "allowed_permissions": [],
  "policy_actions": [],
  "policy_bundle_required": false,
  "policy_bundle": null,
  "registered_actions": [{ "name": "allowed_action", "adapter": "daemon.local" }],
  "approval_policies": [],
  "allowed_percept_schemas": ["splendor.percept.test.v1"],
  "allowed_percept_sources": ["daemon-client-local"],
  "initial_state": { "seed": true },
  "snapshot_interval": 1
}
```

## Expected trace/state behavior

- `POST /runs` emits `RunStarted`.
- `POST /runs/:run_id/percepts` accepts only allowed schemas/provenance and emits
  `PerceptsAppended`.
- `POST /runs/:run_id/start` runs one tick; the queued percept appears in
  `PerceptsReceived`.
- `GET /runs/:run_id/state-head` returns a state node verified through the state
  store.
- `GET /runs/:run_id/traces?redaction_policy=none` returns ordered records.
- `POST /runs/:run_id/traces/export` returns ordered records with explicit
  redaction-policy and trace-chain integrity metadata.
- `POST /runs/:run_id/replay` returns `inspect_only` replay metadata and does not
  execute adapters.

## What is intentionally not allowed

- No anonymous non-dev daemon calls.
- No unauthenticated remote TCP binding.
- No `/actions` path that bypasses `VerifiedActionGateway`.
- No side-effectful replay mode.
- No fleet registry or scheduling.
