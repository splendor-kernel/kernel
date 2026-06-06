# Operating Physical And Edge Simulations

This guide covers the stable 0.1 physical/edge operational pattern using the
0.05 simulation-backed contracts. Splendor supervises high-level bounded autonomy;
it is not a real-time controller.

## Maturity And Limits

- Required adapter maturity: `device-safe` for physical/device adapters.
- Required verifier coverage: local safety verifier, tenant/agent permission verifier, adapter verifier, quota verifier, precondition verifier, approval verifier where applicable, policy TTL verifier where applicable, and postcondition verifier where applicable.
- Stable pattern: high-level physical actions behind `VerifiedActionGateway`, local safety evidence, offline policy cache, local trace buffer, cloud-helper advisory work orders, and inspect-only replay.
- Limitations: no production robotics safety certification, no live hardware readiness claim, no ROS/native driver package, no hard real-time stabilization, no cloud teleoperation, and no direct cloud-to-actuator authority.

## Real-Time Boundary

Splendor is not a real-time controller. Motor controllers, flight controllers,
PLC safety systems, servo loops, firmware, ROS/native drivers, and emergency-stop
systems remain below Splendor and remain authoritative for hard real-time safety.

Forbidden direct Splendor actions include:

```text
set_motor_pwm_1
set_motor_pwm_2
set_motor_pwm
raw actuator writes
low-level motor control
disable_firmware_safety
bypass_collision_avoidance
modify flight-controller internals
ignore emergency stop
direct cloud-to-actuator command
```

## Setup

Run the simulation-backed physical checks:

```bash
cargo test -p splendor-kernel physical_harness --no-default-features
cargo test -p splendor-adapter-robotics
```

Use these examples for operational fixtures:

- `examples/physical-simulation-harness/README.md`
- `examples/simulated-drone-adapter/README.md`
- `examples/simulated-safety-verifiers/README.md`
- `examples/offline-device-policy-cache/README.md`
- `examples/offline-trace-sync/README.md`
- `examples/robot-cloud-route-planner/README.md`

## Run Path

1. Register or configure a resident device node profile with physical capabilities and constraints.
2. Load a cached policy bundle with TTL and degraded-mode rules.
3. Register a `device-safe` robotics adapter for high-level bounded actions only.
4. Install a local `SafetyVerifier` with trace-safe status evidence.
5. Submit physical actions as `ActionRequest`s through `VerifiedActionGateway`.
6. Execute the robotics adapter only after identity, policy, quota, approval where required, local safety, and postcondition checks allow.
7. Buffer trace events locally while offline and sync ordered batches after reconnect.
8. Use cloud helpers only for advisory route or mission proposals; local device Splendor must verify and gate final bounded actions.

Allowed high-level action examples:

```text
read_battery
read_sensor_summary
read_map
move_to_waypoint
return_to_base
dock
inspect_zone
capture_image
pause_mission
resume_mission
request_operator_override
notify_operator
upload_trace_summary
```

## Trace And State Inspection

Physical/edge traces use normal runtime and gateway events plus physical/offline markers:

- `ActionDenied` for local safety denial before adapter execution;
- `ActionNeedsIntervention` for safety uncertainty or operator intervention need;
- `ActionFailed` for unsafe postcondition or middleware failure after allowed execution;
- `PolicyConnectivityChanged`, `PolicyExpired`, and `PolicySyncFailed` for policy cache state;
- `OfflineTraceIntervalStarted`, `OfflineTraceIntervalEnded`, `TraceSyncStarted`, `TraceSyncCompleted`, and `TraceSyncFailed` for offline buffering and reconnect sync.

Replay inspects trace-safe evidence and must not re-send robot/device actions, call cloud helpers, mutate middleware, or replay side effects.

## Failure Handling

- Forbidden physical actions deny before adapter execution.
- Unknown physical actions fail closed.
- Missing or uncertain safety evidence returns denial or `NeedsIntervention`.
- Emergency stop, geofence failure, low battery, collision risk, privacy-zone conflict, or unsafe postcondition fails closed.
- Expired, revoked, or missing cached policy denies high-risk side effects while offline.
- Local trace buffer full returns an error without dropping records; side-effectful action boundaries must fail closed when trace durability is required.
- Cloud-helper timeout produces no local bounded action candidates.

## Teardown

The physical fixtures are in-memory tests and simulations. If an example creates local trace/state data, remove only that example's generated `data/`, `trace.db`, or `state.db` files. Do not clean device middleware or live hardware state from Splendor examples because no live hardware path is provided.

## References

- `docs/reference/physical-actions.md`
- `docs/reference/physical-safety.md`
- `docs/reference/safety-verifiers.md`
- `docs/reference/robotics-adapter.md`
- `docs/reference/offline-operation.md`
- `docs/reference/local-trace-buffer.md`
- `docs/reference/cloud-helper-physical.md`
