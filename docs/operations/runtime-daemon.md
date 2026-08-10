# Operating The Runtime Daemon

This guide shows the stable local path and accepted RFC 0011 resident profile. It is a control
boundary for runs, percepts, traces, state-head lookup, replay, and gateway action
submission. It is not a generic auth provider or remote fleet service.

## Maturity And Limits

- Required adapter maturity: `local-safe` for local actions; `network-safe` only for bounded network adapters with documented egress policy; `governance-aware` for approval-gated actions.
- Stable surface: endpoint names and error shapes in `docs/reference/runtime-daemon-api.md`, OpenAPI in `openapi/splendor-runtime-daemon.yaml`, and TypeScript client contracts in `docs/spec/0.1/api-stability.md`.
- Limitations: no production OAuth/PKI server, remote fleet auth rollout, universal transport negotiation, browser runtime, or unauthenticated production TCP listener. The implemented resident profile is the closed Ed25519/TLS path only.

## Security Boundary

Non-dev daemon communication must preserve this order:

```text
transport security -> caller authentication -> endpoint scopes -> signed work order -> tenant/agent/run checks -> gateway verification
```

A caller token authenticates the app. A signed work order authorizes run create or
resume. The Action Gateway authorizes side effects. No layer replaces another.
Resident bearer JTIs are atomically one-use for mutating requests and reusable
for reads until expiry. Audit stores only a domain-separated `sha256:`
correlation digest, and resident middleware replaces caller-supplied audit time
with a server-owned timestamp before trace recording.

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
SPLENDOR_DAEMON_MODE=local_dev cargo run -p splendor-daemon
```

The current daemon binds to `127.0.0.1:8077` and warns that explicit local-only insecure development mode is active.

For resident mode, provision files rather than secret bytes in arguments or
environment variables:

```bash
chmod 600 /run/splendor/work-order-keyring.json \
  /run/splendor/policy-keyring.json /run/splendor/tls-key.pem
SPLENDOR_DAEMON_MODE=resident \
SPLENDOR_INSTANCE_ID=<non-nil-instance-uuid> \
SPLENDOR_CALLER_TRUST_FILE=/etc/splendor/caller-trust.json \
SPLENDOR_WORK_ORDER_KEYRING_FILE=/run/splendor/work-order-keyring.json \
SPLENDOR_POLICY_KEYRING_FILE=/run/splendor/policy-keyring.json \
SPLENDOR_TLS_CERT_FILE=/etc/splendor/tls-cert.pem \
SPLENDOR_TLS_KEY_FILE=/run/splendor/tls-key.pem \
SPLENDOR_DAEMON_BIND_ADDR=0.0.0.0:8077 \
cargo run -p splendor-daemon
```

Resident TCP always uses TLS. The caller trust snapshot contains public Ed25519
verification keys, allowed scopes, expiry, and revocations. Work-order/policy
keyrings are explicit and never inherited from `local_dev`. Missing inputs,
unknown mode values, nil instance identity, stale caller trust, or permissive
private-file modes fail startup/authentication closed.

Configuration reads are bounded regular-file reads. Unix builds reject symlinks
with `O_NOFOLLOW`; private files are checked on the opened descriptor for
effective-user ownership and no group/world permission. This does not attest the
host, mount source, ACLs, container identity, or hardware key custody. Non-Unix
builds do not claim the Unix owner/mode check.

The acceptance-only manager binary also requires explicit outbound dispatch and
approval-receipt configuration. Its four approval mutation endpoints use a
bounded inbound verifier; this does not make the remaining manager API a
production-authenticated inbound manager:

```bash
SPLENDOR_MANAGER_MODE=local_acceptance \
SPLENDOR_MANAGER_ID=<manager-id> \
SPLENDOR_FLEET_ID=<non-nil-fleet-uuid> \
SPLENDOR_MANAGER_CALLER_ISSUER=<caller-issuer> \
SPLENDOR_MANAGER_CALLER_APP_PRINCIPAL_ID=<app-principal> \
SPLENDOR_MANAGER_CALLER_CLIENT_PRINCIPAL_ID=<client-principal> \
SPLENDOR_MANAGER_CALLER_KEY_ID=<caller-key-id> \
SPLENDOR_MANAGER_CALLER_SIGNING_KEY_FILE=/run/splendor/caller-signing-key.pk8 \
SPLENDOR_MANAGER_WORK_ORDER_KEYRING_FILE=/run/splendor/work-order-keyring.json \
SPLENDOR_AUTHORITY_OBLIGATION_RECEIPT_CONFIG_FILE=/run/splendor/authority-obligation-receipt-config.json \
SPLENDOR_MANAGER_APPROVAL_CALLER_TRUST_FILE=/run/splendor/approval-caller-trust.json \
SPLENDOR_MANAGER_RESIDENT_ROOT_CA_FILE=/etc/splendor/resident-root-ca.pem \
SPLENDOR_MANAGER_RESIDENT_ALLOWED_ORIGINS=https://resident-a.example:8443,https://resident-b.example:8443 \
cargo run -p splendor-daemon --bin splendor-manager
```

The caller signing key, manager work-order keyring, receipt configuration, and
manager approval caller trust snapshot must be owner-only files. The approval
trust snapshot uses `splendor.caller_trust.v1`, must be live at startup, and
allows only the intended manager approval scopes. Approval request/grant/deny/
revoke require a fresh Ed25519 bearer with audience
`urn:splendor:manager:<manager_id>`, exactly one matching fleet claim, and
`splendor.approvals.manage`; the body credential and audit attribution are only
matching mirrors. Missing, malformed, stale, forged, replayed, wrong-target,
wrong-fleet, or wrong-scope proof cannot mutate approval state, append approval
audit, or issue a receipt. Circuit breaker, policy, fleet, work-order, message,
and other manager endpoints retain the existing `local_acceptance` limitation.
No manager TLS or full inbound authentication claim is made.

The exact-origin allowlist is mandatory; userinfo, path, query, fragment,
non-HTTPS production origins, and origin mismatches are rejected before token
minting or network I/O. Loopback HTTP is available only to explicit test/local
construction.
The accepted UC-E2E-S4 composition generates test-only keys and TLS material in
separate role volumes. Residents never mount the caller private key. The manager
has all per-instance work-order v1 issuer secrets, while each resident has only
its own verifier secret. Work-order v1 is still keyed-BLAKE3 shared-secret
verification, so this is scoped sibling isolation rather than asymmetric key
separation.

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

Use `start` and `end` independently for half-open sequence ranges. For example,
`?redaction_policy=none&start=10` reads from sequence 10 onward,
`&end=10` reads sequences before 10, and `&start=10&end=10` returns an empty
projection. Reversed bounds are rejected. Each selected redacted range starts a
new projection-local hash chain, while validation still covers the complete
trusted source history.

Start inspect-only replay:

```http
POST /runs/{run_id}/replay
```

Trace responses are ordered records. Replay validates run scope and sequence continuity and does not invoke perceptors, policies, gateways, verifiers, or adapters.

## Failure Handling

- Anonymous non-dev calls fail closed.
- Missing/malformed/revoked/wrong-audience resident bearer proof returns `401`
  with a bounded `WWW-Authenticate` challenge; body/header identity metadata is
  a mirror, not proof.
- Reusing a mutating bearer JTI returns `caller_token_replayed` before run or
  gateway mutation. Safe create retries use a fresh bearer with the same durable
  request/idempotency keys; ephemeral JTI digests are not part of that scope.
- Missing endpoint scope fails closed.
- Unsigned, expired, revoked, or incompatible work orders reject run create/resume.
- `waiting_for_approval` progresses only through an exact receipt-bearing retry
  at the endpoint class that created the challenge. Tick/direct challenges use
  `/actions`; physical challenges use the original
  `/devices/{node_id}/actions`. Lifecycle resume with raw evidence, receipts, or
  no approval material returns a stable `409` migration code before a tick runs.
- `/actions` rejects caller-supplied bypass states and always routes side effects through the gateway.
- Treat every explicit `action_id` configured in static `policy_actions` as
  reserved for scheduler ticks. Credential-free direct and physical requests
  using a reserved ID receive non-retryable
  `action_id_conflict` before audit, history lookup, device lookup, Gateway, or
  adapter work. The request does not consume the reservation: the next tick may
  execute the action, and later fully completed ticks may reuse the same exact
  static ID/action. The exact direct continuation of a tick-origin pending
  approval remains available and is still checked by Evidence and Authority.
- Treat a caller-supplied `action_id` as consumed after a complete direct/physical
  action episode. Any completed reuse—including the same body, changed metadata,
  another endpoint source, or another physical node path—returns the uniform
  non-retryable `action_id_conflict`; the daemon does not return the stored action
  outcome. Only the exact pending-approval receipt-bearing continuation through
  that challenge's original endpoint may advance the same ID. A direct/physical
  endpoint mismatch conflicts before a new action episode or receipt claim;
  cross-node physical continuation fails exact challenge binding. The original
  endpoint can still claim the receipt once. Incomplete evidence returns
  `tick_reconciliation_required`. Omit `action_id` only when a genuinely fresh
  attempt is intended. Original-response replay and provider/global/distributed/
  restart exactly-once execution are not implemented. Never convert
  `action_id_conflict` into an automatic fresh-ID retry after a lost response;
  inspect trace evidence and reconcile the provider/operator boundary first.
  Kernel ticks are distinct: the same stable ID and exact action may be evaluated
  again only on a strictly later, fully completed tick after any tick-origin
  approval continuation closes. That does not make the ID reusable through a
  direct or physical endpoint.
- Raw-credential guards run before durable duplicate disposition. A
  credential-bearing retry receives only the fixed denial and cannot retrieve a
  prior successful output; the rejected body, causal reference, approval material,
  and physical envelope are not persisted. While a run is
  `waiting_for_approval`, paused, interrupted, resuming, or terminal, the fixed
  denial is returned without durable-history reads or audit/action trace appends;
  repeated rejected requests do not amplify the trace. A raw request using a
  static-policy-reserved ID follows the same no-history/no-audit path and does not
  consume the ID. Active `pending`/`running` requests with nonreserved IDs retain
  the bounded fixed suppression episode behavior.
- Direct and run-bound physical actions reserve one private per-run effect
  admission before durable lookup and Gateway entry. A live competing action or
  lifecycle request returns retryable `action_in_progress` without closing run
  authority. Evidence owns strict action/outcome/source/effect-certainty history
  interpretation; daemon handlers consume only its bounded disposition and live
  pending-authority state. Durable history validation runs outside the run mutex and is bounded
  by the runtime trace reader defaults (100,000 records / 64 MiB); cold lookup is
  still O(n) within those bounds. If the trace grows during validation, the daemon
  retries three fresh readers. `action_history_changed` after exhaustion and
  `action_history_unavailable` on pre-start Store failure from either `/actions`
  or `/devices/{node_id}/actions` are retryable and release
  admission; neither means reconciliation. Clean pre-Gateway failures release admission. Every Gateway
  outcome, including no-effect denial/approval/intervention, retains it until all
  required terminal, outcome, approval/status, and physical offline records are
  durable and status is updated. Approval-resume and physical offline records are
  written before the final durable `OutcomeRecorded` completion barrier.
- If any required outcome suffix append fails, treat the first `trace_error` as
  fail-closed even when the adapter was not entered. Same-process direct/physical
  attempts fail before the adapter with `tick_reconciliation_required` while the
  run remains effect-capable. Lifecycle ticks consult the same private guard, and
  the shared run authority closes so scheduler actions cannot bypass it. A durably
  recorded reconciliation-required outcome (including credential-output
  suppression) fails the run, and later attempts remain
  `tick_reconciliation_required`. An ordinary fully durable denial releases admission
  only when run status still permits later effects. A fully durable
  `NeedsApproval` outcome leaves status `waiting_for_approval`; a fully durable
  `NeedsIntervention` outcome leaves status `failed`.
- Pause is linearized through the same effect-admission guard. Action-first means
  pause returns retryable `action_in_progress`; pause-first publishes `paused`
  and later direct/physical actions return `run_not_effect_capable` before
  Gateway/adapter entry. Do not interpret pause as cancellation of an already
  admitted action or as authority to overwrite its approval/intervention status.
- Export `integrity_hash` describes only the selected returned redacted records:
  `trace-chain:v1:<returned_count>:<returned_projection_tail>`. It is not a
  trusted source-chain hash, including for ranged exports.
- Trace reads require visibility and redaction policy.
- Manager dispatch requires immutable work-order/placement/node/instance
  binding and exactly one healthy compatible resident. A post-send start reset,
  timeout, malformed/oversized body, 5xx, or wrong run identity is
  `resident_start_effect_unknown`, receives no automatic retry, and does not
  publish running telemetry.

## Teardown

Stop the foreground daemon with `Control-C`. Local daemon tests use in-memory stores and do not require artifact cleanup. If a manual example writes local files, remove only that example's generated data directory.

## References

- `docs/reference/runtime-daemon-api.md`
- `docs/reference/daemon-security-boundary.md`
- `docs/spec/0.1/api-stability.md`
- `docs/rfc/0011-resident-caller-auth-and-dispatch.md`
- `examples/daemon-client-local/README.md`
- `examples/typescript-daemon-client/README.md`
