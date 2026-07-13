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
mirrors; they are never proof and must exactly match the verified projection.

The manager dispatch client uses bounded `reqwest`/Rustls transport, a fresh
one-scope token for create and start, exact typed responses, and fail-closed
partial-failure/idempotency behavior. A caller bearer authenticates an app. A
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
   and a subset of the key/issuer trust profile.
7. Tenant and instance IDs are exact non-nil typed identities. Endpoint
   authorization still checks request tenant/run and required scope.
8. Stale, malformed, missing, or future-dated trust/revocation state fails closed.
9. Tokens, signatures, private/public key bytes, and raw parser input are omitted
   from errors, traces, replay, and `Debug` output. `SignedCallerToken` and trust
   key debug output are explicitly redacted.

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
active keys support rotation. Operators distribute a new public key, switch the
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

Dispatch rules:

- The signed work order must contain a stable `run_id` and pass signature,
  expiry, revocation, identity, and placement validation before network I/O.
- Work-order v1 dispatch supports exactly one allowed adapter. Every registered
  action uses that adapter and the complete signed permission set. Multi-adapter
  or ambiguous profiles fail with `resident_dispatch_profile_unsupported`.
- The manager never synthesizes policy actions from objective text. Create admits
  an empty first policy tick unless a separately trusted policy supplies actions.
- Create uses stable request/idempotency keys and requires exact HTTP status plus
  exact `CreateRunResponse` request, idempotency, and run identities.
- Start uses a fresh `runs_start` token and requires exact HTTP status plus an
  exact `TickResponse` run identity.
- Non-2xx, oversized, malformed, or identity-mismatched responses are failures.
  They never emit `run.dispatched` or publish running telemetry.
- Create-success/start-failure records `dispatch.partial_failure` with the known
  run. A start timeout records `dispatch.effect_unknown`; automatic retry is
  forbidden because the tick may have executed.
- One dispatch per work order may be in flight. Successful duplicates return the
  stored report. Terminal start failures return the stored failure. Concurrent
  duplicates cannot start another tick.
- Telemetry uses the typed returned run status and exact signed tenant, agent,
  node, instance, and run identities.

## Compatibility and migration

This is additive at the HTTP shape level: `Authorization: Bearer` becomes
mandatory for resident/non-dev daemon requests. Existing credential and audit
objects remain present during migration but are non-authoritative mirrors. A
future major contract may remove them after all clients consume verified caller
projection directly.

Work-order v1 and gateway schemas are unchanged. A future work-order v2 may sign
exact action/adapter/permission tuples; this RFC does not infer those tuples from
unsigned metadata.

## Trace, state, replay, and failure impact

No trace event or state-node schema is added. Existing daemon audit events record
the verified principal and a redacted credential ID. Create/start continue through
the existing signed-work-order, state commit, trace, C02, verifier, and gateway
paths. Replay remains inspect-only and does not mint bearer tokens, perform
resident network calls, or execute adapters.

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
  duplicate dispatch, actual resident non-2xx, and partial failure.
- Fault-server tests only for malformed/oversized response, redirect, and timeout
  behavior that cannot be induced safely through the real router.
- TypeScript no-anonymous-fallback and error-redaction tests; OpenAPI bearer,
  `401`, `WWW-Authenticate`, and mirror-deprecation checks.
- Full daemon/workspace/API validation and secret/security scans. Gold remains
  `not_exercised`.
