# 0.05-S4 — Robotics Adapter Interface

## Milestone and FRs

- Milestone: Splendor0.05-dev
- Sprint: 0.05-S4
- FRs: FR-0.05-05, FR-0.05-06, FR-0.05-10
- Primitives: adapter, gateway, verifier, physical/edge, trace store

## Implemented scope

- Added a high-level `RoboticsAdapter` contract and `SimulatedRoboticsAdapter`.
- Reused `ALLOWED_PHYSICAL_ACTIONS` and forbidden physical action patterns from
  the device-profile contract.
- Hardened `VerifiedActionGateway` to deny forbidden or unknown physical actions
  before adapter lookup/execution.
- Added tests for success, forbidden denial, safety-verifier denial, adapter
  failure, and operator override request output.

## Non-goals

- No ROS/native package.
- No motor controller or direct actuator writes.
- No live hardware or safety certification.
- No direct cloud-to-actuator path.

## Real-time control boundary

Splendor only governs high-level autonomy requests. Local device middleware,
robotics stacks, firmware safety loops, PLCs, flight controllers, motor
controllers, and hard real-time stabilization remain below Splendor and are not
replaced by the adapter.

## Validation evidence

Focused tests:

```text
cargo test -p splendor-adapter-robotics
cargo test -p splendor-gateway
```
