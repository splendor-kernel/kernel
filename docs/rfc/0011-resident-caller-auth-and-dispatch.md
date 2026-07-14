# RFC 0011 — Resident Caller Authentication and Manager Dispatch

## Status and binding

**Status:** Accepted
**Accepted:** 2026-07-13
**Compatibility line:** additive 0.1 transport/security correction on the active
0.2/v2 line

This RFC accepts one closed resident authentication profile and one bounded
manager-to-resident dispatch path. It is a narrow `IDR-002a` compatibility
adapter and `FND-011`/`AUTH-007` security correction supporting the existing
resident/fleet foundation. It does not accept the full C01 Principal Registry,
full `IDR-002`, full `INT-003`, or any gold result. Gold remains
`not_exercised`.

Applicable requirements are FR-0.02-S0-01 through FR-0.02-S0-11,
FR-0.03-04, and FR-0.03-05. The primitive strengthened is authenticated caller
identity at the resident daemon boundary. Signed work orders and C02/gateway
effect authority remain separate primitives.

## Decision

Resident mode requires TLS and an `Authorization: Bearer` token using a closed
Ed25519 JWS/JWT profile. The resident derives `CallerCredential` only after
cryptographic verification against a local trust snapshot. Existing request-body
and `X-Splendor-Caller-Credential` values remain deprecated compatibility
mirrors; they are never proof and, when supplied, must exactly match the verified
projection. Resident middleware also passes verified context through request
extensions and supplies the internal compatibility projection when wire mirrors
are omitted.

The manager dispatch client uses bounded `reqwest`/Rustls transport, a fresh
one-scope token for create and start, exact typed responses, and fail-closed
effect-certainty/idempotency behavior. Mutating resident requests atomically
consume the verified JTI once before handler mutation; read-only requests may
reuse an unexpired token. A caller bearer authenticates an app. A
signed work order authorizes run admission. C02, verifiers, and the Action
Gateway authorize effects.

## Closed caller-token profile

The token is JWS Compact Serialization with exactly three base64url-without-
padding segments and at most 8 KiB encoded bytes.

Protected header, with no additional fields:

```json
{
  "alg": "Ed25519",
  "kid": "manager-resident-2026-07",
  "typ": "splendor-caller+jwt"
}
```

Required claims, with no additional fields:

```json
{
  "iss": "urn:splendor:manager:central-manager",
  "sub": "resident-dispatch-client",
  "aud": "urn:splendor:instance:00000000-0000-4000-8000-000000000302",
  "iat": 1783958400,
  "nbf": 1783958400,
  "exp": 1783958460,
  "jti": "0f4a5739-57f4-4dc8-b0f7-0f0caa3a353d",
  "splendor_ver": 1,
  "app_principal_id": "central-manager",
  "tenant_id": "11111111-1111-4111-8111-111111111111",
  "scope": ["splendor.runs.create"]
}
```

Validation is fixed and fail closed:

1. Resident mode requires exactly one Bearer authorization value. Query/body
   tokens are never accepted.
2. `typ`, fully specified `alg=Ed25519`, `kid`, segment count/encoding, closed
   JSON fields, signature size, and total size are exact. `none`, polymorphic
   `EdDSA`, token-provided key URLs, embedded keys, and unknown fields fail.
3. `(iss, kid, alg)` resolves only from the configured trust snapshot. No network
   key discovery occurs. Revoked/unknown keys fail before authority checks.
4. Issuer and instance audience are exact. Subject projects the client principal;
   display labels are never trusted.
5. `iat`, `nbf`, and `exp` use bounded NumericDate arithmetic. Default token TTL
   is 60 seconds, maximum accepted TTL is 300 seconds, and clock leeway is at
   most 30 seconds. Future, expired, inverted, excessive, or rollback-observed
   time fails.
6. JTI is a non-nil canonical UUID and is checked against the current revocation
   snapshot. Scope values are unique canonical endpoint scopes, limited to 16,
   and a subset of the key/issuer trust profile. After verification, mutating
   requests atomically consume the JTI; concurrent or later reuse is rejected
   before run/gateway mutation. Read-only requests do not consume it.
7. Tenant and instance IDs are exact non-nil typed identities. Endpoint
   authorization still checks request tenant/run and required scope.
8. Stale, malformed, missing, or future-dated trust/revocation state fails closed.
9. Tokens, signatures, private/public key bytes, and raw parser input are omitted
   from errors, traces, replay, and `Debug` output. Raw JTI is replaced in the
   projected credential and audit data by `sha256:` plus a domain-separated
   SHA-256 digest. `SignedCallerToken` and trust key debug output are explicitly
   redacted.
10. The in-memory one-use set retains each consumed JTI through `exp` plus the
    accepted clock leeway, then prunes it, and is bounded at 100,000 live mutating
    JTIs. If it cannot be checked or is full, mutation fails closed.
    The current daemon/runtime and this ledger are process-local; restart-durable
    admission/idempotency/replay storage remains outside this acceptance slice.

Authentication failure returns `401` and the bounded challenge:

```text
WWW-Authenticate: Bearer realm="splendor-resident", error="invalid_token"
```

An authenticated caller with insufficient endpoint scope, wrong tenant binding,
or mismatched body/header mirrors receives `403`.

## Trust, keys, rotation, and startup

The resident trust snapshot uses schema `splendor.caller_trust.v1` and contains a
revision, issuance/expiry, exact issuer/app principal, maximum token TTL, allowed
scopes, active/revoked Ed25519 public keys, and canonical revoked JTIs. Multiple
active keys support rotation. Revision is non-zero and bounded to signed 64-bit
interoperability, snapshot lifetime is at most 24 hours, active/revoked keys are
limited to 64, and revoked JTIs to 100,000. Operators distribute a new public key, switch the
manager signer, wait at least the maximum token TTL, then revoke/remove the old
key. The current file-backed verifier loads the snapshot at process start, so an
atomic snapshot replacement is activated by a controlled resident restart. A
stale in-memory snapshot is not usable; hot reload/watch propagation remains
future full C01 work.

Manager signing keys are Ed25519 PKCS#8 files readable only by the service owner.
Private key bytes are not accepted through CLI arguments or environment values.
Resident work-order and policy keyrings are explicit owner-only JSON files and
must be non-empty. Resident mode never clones or inherits local-development
keys.

All trust, keyring, TLS, CA, and signing-key reads are bounded and require an
opened regular file. Unix opens use `O_NOFOLLOW`; private files are checked on the
same open descriptor for effective-user ownership and no group/world access.
Owner checks are an implemented Unix process/file-mode control, not proof of
container-host identity, mount integrity, ACL safety, or hardware-backed key
protection. Non-Unix builds retain regular-file and size checks but cannot claim
the Unix owner/mode check.

Resident startup requires all of:

- exact non-nil `SPLENDOR_INSTANCE_ID`;
- `SPLENDOR_CALLER_TRUST_FILE`;
- `SPLENDOR_WORK_ORDER_KEYRING_FILE`;
- `SPLENDOR_POLICY_KEYRING_FILE`;
- `SPLENDOR_TLS_CERT_FILE` and owner-only `SPLENDOR_TLS_KEY_FILE`;
- an explicit safe socket address.

`SPLENDOR_DAEMON_MODE` accepts only `resident` or explicit `local_dev`.
`local_dev` remains visibly warned and loopback-only. Unknown modes fail.
Resident TCP is TLS; remotely reachable plaintext resident mode is not defined.

## Manager dispatch contract

The manager validates the resident TLS chain and hostname, can add an explicit
private CA, disables redirects and proxies, uses a two-second connect timeout,
bounded create/start total timeouts, and accepts at most 1 MiB per response. It
never disables certificate or hostname verification.

Before token minting or network I/O, the manager parses the registry-provided
resident URL as an origin-only URL, rejects userinfo, non-root paths, query, and
fragment, and requires an exact match in the configured origin allowlist.
Production origins use HTTPS. HTTP is accepted only for explicit loopback test
configuration. An empty allowlist denies all outbound resident dispatch.

Dispatch rules:

- The signed work order must contain a stable `run_id` and pass signature,
  expiry, revocation, identity, and placement validation before network I/O.
- Signed `data_locality` accepts only the current typed `cloud`, `vpc`,
  `on_prem`, or `device` classes. Region-like or unknown strings are rejected;
  they are never ignored or reinterpreted as region semantics.
- The accepted work-order ID is immutable: matching signed bytes are idempotent,
  while any same-ID payload or envelope replacement is rejected. Placement is
  bound to that accepted payload and one immutable decision digest.
- Dispatch binds the accepted work-order digest and placement digest to the
  selected node, one exact instance, resident URL, and origin. The instance must
  be resident, healthy with a fresh heartbeat, host the signed tenant, match the
  node/required runtime version, expose `runtime.resident` and
  `gateway.verified`, and satisfy every placement capability. Zero or multiple
  eligible instances are rejected before token minting or network I/O.
- Work-order v1 dispatch supports exactly one allowed adapter. Every registered
  action uses that adapter and the complete signed permission set. Multi-adapter
  or ambiguous profiles fail with `resident_dispatch_profile_unsupported`.
- The manager never synthesizes policy actions from objective text. Create admits
  an empty first policy tick unless a separately trusted policy supplies actions.
- Create uses stable request/idempotency keys and requires exact HTTP status plus
  exact `CreateRunResponse` request, idempotency, and run identities. Durable
  create idempotency binds caller principal identity but excludes the ephemeral
  credential/JTI digest, so a safe retry can use a fresh one-use bearer.
- Start uses a fresh `runs_start` token and requires exact HTTP status plus an
  exact `TickResponse` run identity.
- A per-work-order asynchronous revocation gate linearizes revocation against the
  complete create/start dispatch. Dispatch rechecks revocation and expiry
  immediately before each outbound request. A revocation that acquires the gate
  first prevents all egress; one that loses waits for create/start to finish.
- The revocation gate is allocated atomically with accepted signed work-order
  state. Unknown revoke/dispatch IDs return `work_order_not_found` before
  allocating a gate, revocation tombstone, in-flight reservation, or terminal
  dispatch result. Accepted gates/results remain process-local lifecycle state
  so exact duplicate and unknown-effect behavior is preserved; the acceptance
  manager is not a production retention service.
- Non-2xx, oversized, malformed, or identity-mismatched responses are failures.
  They never emit `run.dispatched` or publish running telemetry.
- After a start request may have been sent, every transport reset/timeout,
  malformed or oversized response, non-success status, or wrong run identity is
  `dispatch.effect_unknown` unless a future protocol provides explicit
  authoritative no-effect evidence. Automatic retry is forbidden because the
  tick may have executed. Pre-send failures remain known no-effect failures.
- One dispatch per work order may be in flight. Successful duplicates return the
  stored report. Terminal start failures return the stored failure. Concurrent
  duplicates cannot start another tick.
- Before awaiting start, the manager stores a provisional terminal
  unknown-effect quarantine. Cancellation after the request may have been sent
  leaves that quarantine in place. It is cleared only in the same protected state
  update that stores the authoritative typed success report.
- Telemetry uses the typed returned run status and exact signed tenant, agent,
  node, instance, and run identities.

## Compatibility and migration

This is additive at the HTTP shape level: `Authorization: Bearer` becomes
mandatory for resident/non-dev daemon requests. Existing credential and audit
objects remain in compatibility schemas but are non-authoritative mirrors.
Resident requests may omit them because middleware supplies verified internal
projection; explicit local-dev calls still follow the existing audit contract. A
future major contract may remove them after all clients consume verified caller
projection directly.

The TypeScript client rejects relative URLs, unsupported schemes, URL
credentials, query, and fragment. Bearer transport requires HTTPS, except exact
`localhost`, `127.0.0.1`, or `[::1]` HTTP used explicitly for local development.
It sets Fetch `redirect: "error"` on every credentialed request and never falls
back to plaintext remote transport or anonymous requests.

Work-order v1 and gateway schemas are unchanged. A future work-order v2 may sign
exact action/adapter/permission tuples; this RFC does not infer those tuples from
unsigned metadata.

## Trace, state, replay, and failure impact

No trace event or state-node schema is added. Existing daemon audit events record
the verified principal and bounded JTI correlation digest. Caller-supplied audit
time is ignored; middleware rewrites compatibility mirrors with a server-owned
authentication timestamp before handler trace recording. Replay denial emits a
resident security audit fact without raw token/JTI. Create/start continue through
the existing signed-work-order, state commit, trace, C02, verifier, and gateway
paths. Replay remains inspect-only and does not mint bearer tokens, perform
resident network calls, or execute adapters.

The existing state-handoff daemon operations apply this resident boundary
consistently: both require caller scope `splendor.state.handoff` plus signed
run-bound work-order authority. Export remains a read-only snapshot operation with
a source trace boundary. Import cryptographically revalidates the exact work-order
envelope admitted for the target run, but then fails closed with
`503 state_handoff_proof_unavailable` and `needs_intervention` before state-store,
state-head, or run-trace mutation. The v0 `StateHandoff` is self-consistent but is
not source-signed, and its caller-carried source trace ID does not prove that an
authenticated source event exists. Caller authentication and target work-order
authority are necessary but cannot substitute for source proof. Explicit
loopback `local_dev` retains the existing import path as experimental
compatibility only. This is a security correction to the existing v0 path, not a
new state-node or trace-event schema; source-authenticated manifest/evidence and
durable replay work remain with STA-005, EVT-005, and EVID-005.

Registry registration and heartbeat freshness use manager-observed receipt time.
Sender `registered_at`, `recorded_at`, and health observation timestamps remain
observational and cannot pin freshness in the future or reorder receipts. A
manager receipt-time regression fails closed.

Trust/key read failure, stale trust, caller verification failure, TLS failure,
response-limit failure, and dispatch uncertainty all fail closed. No fallback to
metadata authentication, plaintext remote transport, development keys, anonymous
calls, or action execution is permitted.

## Explicit non-goals and residual risk

- No OAuth server, generic JWT library/profile, dynamic OIDC discovery, fleet PKI
  manager, mTLS enrollment system, hardware attestation, or full Principal
  Registry.
- No request proof-of-possession or general HTTP Message Signatures.
- No work-order-v2 schema, gateway semantic change, policy synthesis, or action
  bypass.
- No automatic retry/reconciliation endpoint for unknown-effect starts.
- Work-order v1 remains keyed-BLAKE3 shared-secret verification. Acceptance
  fixtures issue a distinct key ID/secret per resident; the manager receives all
  issuer secrets and each resident mounts only its own verifier secret. This is
  scoped sibling isolation, not asymmetric issuer/verifier separation: compromise
  of a resident's v1 verifier secret can forge authority for that resident until
  rotation. Work-order v2/asymmetric verification remains future work.
- The current central-manager **inbound** API still validates self-asserted
  acceptance metadata. This RFC secures manager outbound resident dispatch only.
  `splendor-manager` remains explicit local acceptance/dev infrastructure and
  must not be described or exposed as a production-authenticated remote API.

## Required evidence

- Closed-profile unit/adversarial tests for missing, malformed, oversized,
  unknown fields/algorithms/keys, bad signature, key/JTI revocation, issuer,
  audience, tenant, scope, lifetime, stale trust, rotation, and clock rollback.
- Real manager → TLS listener → real resident router create/start integration,
  including signed work order, state commit, trace/audit redaction, telemetry,
  duplicate dispatch, actual resident non-2xx, and effect uncertainty.
- Fault-server tests for execute-then-reset, malformed/oversized response,
  wrong-run success, 5xx, redirect, and timeout behavior that cannot be induced
  safely through the real router.
- TypeScript no-anonymous-fallback and error-redaction tests; OpenAPI bearer,
  `401`, `WWW-Authenticate`, and mirror-deprecation checks.
- Full daemon/workspace/API validation and secret/security scans. Gold remains
  `not_exercised`.
