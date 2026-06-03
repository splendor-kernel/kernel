# Physical simulation harness scenarios

The runnable scenarios live in `crates/splendor-kernel/tests/unit/physical_simulation_harness_tests.rs`.

## 1. Successful mission

Runs `inspect_zone` and `dock` through the gateway and simulated robotics adapter. The test also submits forbidden `set_motor_pwm` and asserts it is denied with no adapter execution for that action. Replay confirms executed actions are high-level physical actions only and a final state head exists.

## 2. Safety denial

Uses a low-battery `SimulatedSafetySnapshot`. `move_to_waypoint` is denied by `SimulatedSafetyVerifier`, emits `ActionDenied`, and adapter call count remains zero.

## 3. Offline interval and reconnect sync

Starts a canonical offline trace interval, records policy connectivity loss, allows low-risk cached `read_battery`, blocks high-risk `move_to_waypoint` as `NeedsIntervention`, ends the interval, and syncs the local trace batch into `InMemoryCentralTraceIndex`. Re-syncing the same batch reports duplicates instead of inserting duplicate records.

## 4. Operator intervention / override request

Uses unknown collision risk to produce `ActionNeedsIntervention` before adapter execution. A separate safe override request submits `request_operator_override` through the same gateway/adapter path and records the executed override request outcome.

## 5. Cloud-helper proposal validated locally

Traces a helper route-plan message, validates the advisory `RoutePlanProposal` locally, converts the accepted proposal to bounded `move_to_waypoint`, and submits that action through the local gateway and safety verifier. An unsafe proposal for an outside-geofence zone is denied and produces no adapter call.

## Replay rule

All scenarios replay by reading serialized `TraceEvent` records and checking the final state head. Replay never calls the helper, adapter, gateway, or verifier.
