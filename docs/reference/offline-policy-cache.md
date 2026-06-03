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
| `validation` | Signature algorithm/key-id metadata and validation time without signature material. |
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

This makes low-risk cached behavior explicit and avoids inferring broad authority
from arbitrary action names or side-effect classes.

## Lifecycle

1. A run is created with a validated policy bundle, or a bundle is synced later.
2. `PolicyCache::install_validated` or `install_validated_envelope` installs the
   bundle and records `last_sync_at` plus validation metadata.
3. Central disconnection is marked by `set_disconnected_with_trace(true, time)`.
4. The gateway wrapper applies the decision rules before adapters can run.
5. Reconnect is marked by `set_disconnected_with_trace(false, time)`; a new valid
   bundle may then update cache status without resetting trace continuity.

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
| Central sync failed | Record failure and keep previous authority. |

## Security notes

The offline cache is not an ambient permission store. It can only preserve the
last validated bundle and only within that bundle's degraded-mode rules. It never
grants broader actions, adapters, permissions, data references, tenant scope, or
agent scope than the existing run/gateway/verifier chain already allows.

No device-side policy authoring, mesh policy consensus, raw actuator authority,
or physical safety certification is introduced.
