# Robotics Adapter

The 0.05-S4 robotics adapter contract is middleware-agnostic and high-level only.
It lets Splendor hand bounded physical actions to local device middleware while
real-time control remains below Splendor.

## Rust contract

- `splendor_gateway::ActionAdapter` remains the execution boundary.
- `splendor_adapter_robotics::RoboticsAdapter` marks an adapter as supporting the
  canonical physical action set.
- `splendor_adapter_robotics::SimulatedRoboticsAdapter` is the reference mock for
  tests/examples.
- Register actions with `VerifiedActionGateway` using adapter id `robotics` and
  install a local `SafetyVerifier` before submitting physical actions.

## Output shape

Adapter output is trace-safe JSON serialized from `RoboticsActionOutput`:

- `adapter`: adapter id.
- `action`: high-level action name.
- `status`: `succeeded` or `operator_override_requested`.
- `evidence`: reference data such as simulated command refs, not raw sensor data.
- `postconditions`: acknowledgement and safety/postcondition references.

Adapter execution failures return `ActionStatus::Failed` through the gateway.
Safety denials return `ActionStatus::Denied` before adapter execution.

## Safety boundary

The adapter does not implement a parallel safety path. Safety verification is
part of `VerifiedActionGateway`; missing or uncertain safety verifiers fail
closed. `request_operator_override` returns an override-request output only; it
does not grant approval or bypass governance.

## Not implemented

No ROS/native package, live hardware integration, motor controller, firmware
mutation, direct cloud-to-actuator path, or robotics safety certification is
provided by this adapter.
