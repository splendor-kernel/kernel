# Operating The Runtime Daemon

This guide shows the stable 0.1 local runtime daemon path. It is a local control
boundary for runs, percepts, traces, state-head lookup, replay, and gateway action
submission. It is not a production auth provider or remote fleet service.

## Maturity And Limits

- Required adapter maturity: `local-safe` for local actions; `network-safe` only for bounded network adapters with documented egress policy; `governance-aware` for approval-gated actions.
- Stable surface: endpoint names and error shapes in `docs/reference/runtime-daemon-api.md`, OpenAPI in `openapi/splendor-runtime-daemon.yaml`, and TypeScript client contracts in `docs/spec/0.1/api-stability.md`.
- Limitations: local/foundation daemon only; no production OAuth/PKI server, remote fleet auth rollout, universal transport negotiation, browser runtime, or unauthenticated production TCP listener.

## Security Boundary

Non-dev daemon communication must preserve this order:

```text
transport security -> caller authentication -> endpoint scopes -> signed work order -> tenant/agent/run checks -> gateway verification
```

A caller token authenticates the app. A signed work order authorizes run create or
resume. The Action Gateway authorizes side effects. No layer replaces another.

Explicit insecure local development mode is allowed only when it is enabled
explicitly, bound to loopback or a Unix domain socket, visibly warned at startup,
not usable for production/fleet/resident operation, and never reached by silent
SDK fallback.

## Setup

Run the test-backed daemon smoke path:

```bash
cargo test -p splendor-daemon
```

Start the local daemon binary when manually inspecting requests:

```bash
cargo run -p splendor-daemon
```

The current daemon binds to `127.0.0.1:8077` and warns that explicit local-only insecure development mode is active.

## Run Path

Use the request shapes in `examples/daemon-client-local/README.md` or the TypeScript example in `examples/typescript-daemon-client/README.md`.

Operational sequence:

1. `POST /runs` with authenticated caller attribution, endpoint scope `splendor.runs.create`, and a signed scoped work order.
2. `POST /runs/{run_id}/percepts` with allowed percept schema and provenance.
3. `POST /runs/{run_id}/start` to execute one deterministic local tick.
4. `POST /actions` only for gateway-mediated action submission with `GatewayVerificationState::Required`.
5. `POST /runs/{run_id}/pause`, `resume`, or `stop` for lifecycle control.

## Trace And State Inspection

Read state head:

```http
GET /runs/{run_id}/state-head
```

Read traces with explicit redaction policy:

```http
GET /runs/{run_id}/traces?redaction_policy=none
```

Start inspect-only replay:

```http
POST /runs/{run_id}/replay
```

Trace responses are ordered records. Replay validates run scope and sequence continuity and does not invoke perceptors, policies, gateways, verifiers, or adapters.

## Failure Handling

- Anonymous non-dev calls fail closed.
- Missing endpoint scope fails closed.
- Unsigned, expired, revoked, or incompatible work orders reject run create/resume.
- Missing approval evidence on resume from `waiting_for_approval` returns `approval_required` before a tick runs.
- `/actions` rejects caller-supplied bypass states and always routes side effects through the gateway.
- Trace reads require visibility and redaction policy.

## Teardown

Stop the foreground daemon with `Control-C`. Local daemon tests use in-memory stores and do not require artifact cleanup. If a manual example writes local files, remove only that example's generated data directory.

## References

- `docs/reference/runtime-daemon-api.md`
- `docs/reference/daemon-security-boundary.md`
- `docs/spec/0.1/api-stability.md`
- `examples/daemon-client-local/README.md`
- `examples/typescript-daemon-client/README.md`
