# Simulated Safety Verifiers

This example documents the reference safety verifier path for sprint 0.05-S5.

```rust
use splendor_gateway::{SimulatedSafetySnapshot, SimulatedSafetyVerifier, VerifiedActionGateway};
use std::sync::Arc;

let snapshot = SimulatedSafetySnapshot {
    current_zone: Some("zone:A".into()),
    allowed_zones: vec!["zone:A".into()],
    battery_percent: Some(80.0),
    min_battery_percent: Some(30.0),
    emergency_stop_engaged: Some(false),
    collision_risk: Some(splendor_gateway::SimulatedRiskLevel::Low),
    sensor_refs: vec!["status:battery.latest".into()],
    ..Default::default()
};

// gateway.set_safety_verifier(Arc::new(SimulatedSafetyVerifier::new(snapshot)));
```

When a physical action such as `move_to_waypoint` is submitted, the gateway runs
the safety verifier before adapter execution. Geofence violations, low battery,
emergency stop, high collision risk, altitude limit, privacy zone, proximity
risk, missing verifier, or uncertain status fail closed.

Run the focused tests:

```bash
cargo test -p splendor-gateway safety
```

The tests prove that safety denial, uncertainty, and missing verifier do not call
the adapter and that unsafe postconditions are recorded as failed outcomes.
