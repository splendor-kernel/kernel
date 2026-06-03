# Physical simulation harness

This example is a test-backed simulation for Sprint 0.05-S7. It proves the physical/edge contracts can work together without live hardware.

Run it with:

```bash
cargo test -p splendor-kernel physical_harness --no-default-features
```

What it proves:

- device profile validation and physical capability advertisement;
- high-level robotics actions only (`inspect_zone`, `dock`, `move_to_waypoint`, etc.);
- action execution only through `VerifiedActionGateway` and `SimulatedRoboticsAdapter`;
- safety denial before adapter execution;
- offline interval trace buffering and reconnect sync deduplication;
- operator intervention / `request_operator_override` trace flow;
- cloud-helper route proposal local validation before bounded local movement;
- replay by inspecting trace records, not by re-executing helper or robotics side effects.

What it intentionally does **not** prove:

- production robot readiness;
- flight safety or hardware certification;
- ROS/native driver integration;
- motor, firmware, or raw actuator control.

The simulation boundary is limited to trace-safe status snapshots, in-memory stores, and the existing simulated robotics/safety components.
