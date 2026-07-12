# Offline Policy Cache Reference

The offline policy cache is the 0.05-S2 physical/edge extension of the 0.04-S5
local cache behavior for centrally distributed policy bundles. It allows a
resident instance to remember the last validated bundle and operate only within
explicit offline rules while central connectivity is unavailable.

It does not fork policy authority: `PolicyBundle`, `PolicyDegradedMode`,
`PolicyCache`, and `PolicyDistributionGateway` remain the single reference path.

## Runtime object

Rust contract:

```rust
splendor_kernel::{
    PolicyCache,
    PolicyCacheConfig,
    PolicyCacheSnapshot,
    PolicyCacheValidationMetadata,
    PolicyDistributionGateway,
    PolicyOfflineStatus,
    PolicyRuntimeAuthority,
    PolicyDistributionStatus,
}
```

`PolicyCache` stores explicit governance state:

| Field | Purpose |
| --- | --- |
| `enforcement_required` | Whether missing policy authority denies policy invocation/action execution. |
| `disconnected` | Whether the runtime is explicitly operating without central policy connectivity. |
| `bundle` | Current validated bundle metadata and authority. |
| `validation` | Trusted signature algorithm/key-id metadata and validation time from `ValidatedPolicyBundle`, without signature material. |
| `last_sync_at` | Last successful bundle install/sync time. |
| `revoked_reason` | Local revocation marker applied to the current bundle. |
| `last_sync_failure` | Sanitized sync failure reason and timestamp. |

`PolicyCacheSnapshot` exposes trace/API-safe status: bundle version, scope, TTL,
validation metadata, last sync time, derived `PolicyOfflineStatus`, revocation,
and sync failure state. It does not expose detached signatures or secrets.

## Degraded mode fields

`PolicyDegradedMode` now includes:

| Field | Purpose |
| --- | --- |
| `allow_low_risk_cached` | Compatibility flag for degraded mode. In 0.05-S2 it does not authorize action forwarding after TTL expiry. |
| `disconnected_low_risk_actions` | Explicit action names allowed to continue while disconnected. The action must also be `SideEffectClass::ReadOnly`. |
| `disconnected_high_risk_actions` | Explicit action names that cannot execute autonomously while disconnected. |
| `high_risk_disconnected_behavior` | `deny` or `needs_local_intervention` for disconnected high-risk actions. |

## Decision rules

| Cache state | Action | Decision |
| --- | --- | --- |
| Connected, valid bundle | Any action | Forward to wrapped gateway. |
| Disconnected, within TTL | Explicit low-risk read-only action | Forward to wrapped gateway and normal verifiers. |
| Disconnected, within TTL | Explicit high-risk action | Deny or `NeedsIntervention`; adapter not called. |
| Disconnected, within TTL | Any other action | Deny `offline_action_not_allowed`; adapter not called. |
| Disconnected, expired bundle | Any action, including explicit low-risk read-only | Deny `policy_expired`; adapter not called. |
| Missing or revoked bundle | Any action/policy invocation | Fail closed. |
| Runtime time before trusted validation/maximum observed time | Any action/policy invocation | Deny `policy_clock_rollback`; adapter not called. |

This makes low-risk cached behavior explicit and avoids inferring broad authority
from arbitrary action names or side-effect classes.

## Lifecycle

1. A run is created with a validated policy bundle, or a bundle is synced later.
2. `PolicyCache::install_validated` consumes only a `ValidatedPolicyBundle` and
   records `last_sync_at` plus trusted validation metadata. There is no raw
   bundle/envelope production insertion API.
3. Central disconnection is marked by `set_disconnected_with_trace(true, time)`.
4. The gateway wrapper applies the decision rules before adapters can run.
5. Reconnect is marked by `set_disconnected_with_trace(false, time)`; a new valid
   bundle may then update cache status without resetting trace continuity.

Policy validation occurs before installation. Unsupported, future-issued, and
expired sync candidates record `PolicyBundleRejected` plus `PolicySyncFailed`
and leave the last trusted cached bundle unchanged. A matching revoked candidate
uses the existing revocation path to block the current cached bundle. None of
these failures installs candidate authority or creates an alternate adapter path.
Older active candidates, same-issued-at content conflicts, and unrelated/older
revocation candidates likewise fail before authority mutation. An exact retry
does not clear tombstones; only a strictly newer trusted install can refresh and
clear them. Reconnect is emitted only from that accepted install path.

## Trace behavior

Offline/degraded cache decisions are visible through:

- `PolicyBundleAccepted` for installed authority;
- `PolicyConnectivityChanged` for disconnect/reconnect;
- `PolicySyncFailed` for failed central sync;
- `PolicyExpired` for TTL denial;
- `PolicyRevoked` for revocation denial;
- normal `ActionDenied`, `ActionNeedsIntervention`, and `OutcomeRecorded` events.

## Replay behavior

Replay can reconstruct which cached bundle was present, whether central sync or
connectivity changed, and whether expiry/revocation/offline rules denied or
paused an action. Replay does not reconnect to central policy distribution,
refresh bundles, invoke policy code, or execute adapters.

## Failure modes

| Condition | Result |
| --- | --- |
| Required policy missing | Deny with `policy_unavailable`. |
| Bundle expired while connected | Deny policy invocation/actions with `policy_expired`. |
| Bundle expired while disconnected | Deny/pause/needs intervention according to policy; the reference cache denies `policy_expired` and does not forward to adapters. |
| Disconnected high-risk action | Deny or `NeedsIntervention` according to policy. |
| Disconnected unspecified action | Deny `offline_action_not_allowed`. |
| Bundle revoked | Deny with `policy_revoked`. |
| Signed bundle issued after the receiver clock | Reject with `future_issued_policy_bundle` before cache installation. |
| Central sync failed | Record failure and keep previous authority. |
| Clock moved behind trusted validation/observation time | Deny `policy_clock_rollback`; latched expiry cannot reactivate. |

## Security notes

The offline cache is not an ambient permission store. It can only preserve the
last validated bundle and only within that bundle's degraded-mode rules. It never
grants broader actions, adapters, permissions, data references, tenant scope, or
agent scope than the existing run/gateway/verifier chain already allows.

No device-side policy authoring, mesh policy consensus, raw actuator authority,
or physical safety certification is introduced.
