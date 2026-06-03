# Offline Operation Reference

Offline operation is the 0.05 physical/edge behavior that lets a resident
Splendor instance continue only within centrally issued cached policy while
connectivity is unavailable.

## Contract

- Central policy authority remains `PolicyBundle` / `PolicyDistributionGateway`.
- Offline state is explicit: `PolicyCache::set_disconnected_with_trace(...)`
  returns `TraceEventKind::PolicyConnectivityChanged` for disconnect/reconnect.
- Low-risk operation is explicit: the cached bundle must list action names in
  `degraded_mode.disconnected_low_risk_actions`, and the action must be
  `SideEffectClass::ReadOnly`.
- High-risk operation is explicit: action names in
  `degraded_mode.disconnected_high_risk_actions` are denied or returned as
  `NeedsIntervention` according to `high_risk_disconnected_behavior`.
- Expired/revoked/missing policy fails closed. Expired cached policy does not
  authorize policy invocation or gateway forwarding, even for explicit low-risk
  read-only actions.

## Trace and telemetry

Offline/reconnect visibility uses:

- `PolicyConnectivityChanged { disconnected, observed_at, bundle }`
- `PolicySyncFailed { ... }`
- `PolicyExpired { ... }`
- normal `ActionDenied` / `ActionNeedsIntervention` action trace events.

`PolicyCacheSnapshot` exposes status for telemetry: bundle version/scope/TTL,
validation metadata without signature material, `last_sync_at`, and derived
`PolicyOfflineStatus`.

## Non-goals

No autonomous policy authoring, mesh policy consensus, physical safety
certification, or side-effect path outside the gateway is introduced.
