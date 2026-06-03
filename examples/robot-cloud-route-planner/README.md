# Robot Cloud Route Planner Example

This example demonstrates the 0.05-S6 cloud-helper pattern.

## Flow

1. A device or manager issues a signed helper work order with:
   - `placement.execution_mode = "cloud_helper"`
   - scoped `data_refs` such as `map:warehouse-a`
   - advisory actions such as `route_plan.propose`
   - no `robotics` adapter and no physical action authority.
2. The helper returns `splendor.message.route_plan_proposal.v1` or an artifact ref.
3. The device validates the proposal locally with
   `validate_route_plan_for_local_execution`.
4. Accepted plans become bounded `move_to_waypoint` action candidates.
5. Each candidate is submitted through the local Action Gateway and local
   `SafetyVerifier` before the robotics adapter can execute.

## Smoke tests

```bash
cargo test -p splendor-types cloud_helper
cargo test -p splendor-kernel cloud_helper
```

## What is intentionally not allowed

- Helpers cannot register or use the `robotics` adapter.
- Helpers cannot output direct actuator commands or low-level motor writes.
- Helper network failure returns `cloud_helper_unavailable` and no local actions.
- Replay inspects traces; it does not re-contact the helper or move the robot.
