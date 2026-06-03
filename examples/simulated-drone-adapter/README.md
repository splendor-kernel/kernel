# Simulated Drone Adapter Example

This example uses `splendor-adapter-robotics::SimulatedRoboticsAdapter` as a
device-middleware mock. It proves the adapter is usable only behind the action
gateway with a local safety verifier.

## Flow

1. Create `VerifiedActionGateway` with tenant policy/quota access.
2. Register `SimulatedRoboticsAdapter` for allowed physical actions using adapter
   id `robotics`.
3. Install `SimulatedSafetyVerifier` with a safe `SimulatedSafetySnapshot`.
4. Submit `move_to_waypoint` as `SideEffectClass::Custom("physical.high_level")`.
5. Observe `ActionStatus::Executed`, trace-safe evidence, and postconditions.

Denial/failure cases covered by tests:

- `set_motor_pwm` is denied before adapter execution.
- Emergency-stop safety denial prevents adapter execution.
- Simulated middleware failure returns `ActionStatus::Failed`.
- `request_operator_override` returns `operator_override_requested`; it does not
  approve or bypass governance.

## Run

```sh
cargo test -p splendor-adapter-robotics
```

No live drone, ROS package, network connection, or motor controller is used.
