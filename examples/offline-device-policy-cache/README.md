# Offline Device Policy Cache Example

This reference scenario shows a resident device instance disconnected from
central policy authority.

## Bundle excerpt

```yaml
degraded_mode:
  allow_low_risk_cached: true
  disconnected_low_risk_actions:
    - read_battery
    - read_sensor_summary
  disconnected_high_risk_actions:
    - move_to_waypoint
    - inspect_zone
  high_risk_disconnected_behavior: needs_local_intervention
```

## Expected behavior

1. A validated signed bundle is installed in `PolicyCache`.
2. Disconnection calls `set_disconnected_with_trace(true, observed_at)` and emits
   `PolicyConnectivityChanged`.
3. `read_battery` with `SideEffectClass::ReadOnly` proceeds to the normal gateway
   and verifier chain while within TTL.
4. `move_to_waypoint` returns `NeedsIntervention`; the adapter is not called.
5. After TTL expiry, only explicit low-risk read-only cached actions can continue
   when `allow_low_risk_cached` is true. Other actions deny `policy_expired`.
6. Reconnect emits `PolicyConnectivityChanged { disconnected: false, ... }`; a
   new validated bundle can update cache `last_sync_at` without breaking trace
   continuity.

## Smoke commands

```bash
cargo test -p splendor-types policy_distribution
cargo test -p splendor-kernel policy_cache
```

## Non-goals

No raw actuator control, device-side policy authoring, mesh policy consensus, or
certification of physical safety behavior is claimed.
