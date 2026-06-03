# 0.05-S2 — Offline Policy Cache

## Objective

Allow resident physical/edge instances to operate within cached central policy
during disconnection while failing closed for high-risk actions.

## Functional scope

- Extends `PolicyBundle` degraded mode with explicit disconnected low/high-risk
  action names and high-risk behavior.
- Extends `PolicyCache` snapshots with validation metadata, last sync time, and
  derived offline status.
- Adds trace-visible disconnect/reconnect transitions.

## Non-goals

- No physical-only policy fork.
- No mesh policy consensus.
- No autonomous device policy authoring.
- No physical safety certification claim.

## Public contracts changed

See `docs/reference/offline-policy-cache.md`.

## Runtime primitive impact

| Primitive | Impact |
| --- | --- |
| Policy | Explicit offline degraded policy fields. |
| Gateway | Disconnected action decisions before adapter execution. |
| Verifier | Fail-closed policy status checks. |
| Trace store | `PolicyConnectivityChanged` event. |
| Governance | High-risk actions can need local intervention. |

## Trace behavior

Disconnect/reconnect emits `PolicyConnectivityChanged`. Denials/interventions use
normal action events with reasons such as `offline_action_not_allowed`,
`offline_high_risk_denied`, and
`offline_high_risk_needs_local_intervention`.

## State behavior

No state graph format change. Cache status is explicit runtime/cache state and is
visible through `PolicyCacheSnapshot`.

## Gateway and verifier behavior

Disconnected operation forwards only explicit low-risk read-only actions to the
wrapped gateway. High-risk and unspecified actions do not reach adapters.

## Replay behavior

Replay inspects connectivity, expiry, denial, and intervention events only; it
does not re-sync policy or re-execute side effects.

## Tests and evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| unit | connected/disconnected/expired/revoked/missing policy | `cargo test -p splendor-kernel policy_cache` |
| contract | policy degraded fields/defaults | `cargo test -p splendor-types policy_distribution` |
| negative | high-risk and unspecified offline actions fail closed | policy cache tests |
| trace | offline/reconnect trace event | policy cache tests |

## Example or fixture

`examples/offline-device-policy-cache/README.md`

## Future extension notes

0.05-S3 can route these trace events through the local trace buffer; #34 can
align physical action class names without replacing the policy cache authority.
