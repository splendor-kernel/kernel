# 0.05-S6 — Cloud-helper pattern

## Objective

Allow physical devices to use cloud/on-prem helper Splendor instances for route
planning or analysis without granting direct actuator authority.

## Functional scope

- Added advisory helper work-order validation in `splendor-types`.
- Added `RoutePlanProposal` and `splendor.message.route_plan_proposal.v1`.
- Added local route-plan validation that converts accepted proposals into bounded
  local action candidates only; gateway execution remains separate.
- Added fail-closed helper failure validation for network timeout/failure.

## Non-goals

- No cloud teleoperation.
- No direct actuator control from cloud.
- No fleet route optimizer product.
- No new network transport, broker, or robotics adapter authority system.

## Public contracts changed

- `WorkOrderPlacement.execution_mode` now records `PlacementExecutionMode`.
- New exports: `validate_cloud_helper_work_order`, `RoutePlanProposal`,
  `RouteWaypointProposal`, `validate_route_plan_for_local_execution`,
  `cloud_helper_failure_validation`, and `ROUTE_PLAN_PROPOSAL_SCHEMA`.
- Documentation: `docs/reference/cloud-helper-physical.md`.

## Runtime primitive impact

| Primitive | Impact |
| --- | --- |
| Work order | Added advisory cloud-helper mode validation. |
| Message | Added typed route proposal message payload contract. |
| Verifier | Added deterministic local proposal validation helper. |
| Gateway | Local actions still require gateway+safety before adapter execution. |
| Physical/edge | Device remains action authority; helper is advisory. |
| Trace store | Reuses remote message and action trace events. |
| Replay | Proposal, validation, and final decisions reconstruct from trace. |

## Trace behavior

No new event classes. Helper proposal/failure uses remote message events; local
validation and final action decisions use existing action verification/outcome
events.

## State behavior

No state graph format change. Accepted proposal references can be committed by
the runtime as normal state patches/snapshots; this sprint adds no hidden mutable
state.

## Gateway and verifier behavior

- Helper work-order validation denies robotics adapter authority and physical or
  low-level actuator action authority.
- Local route-plan validation denies missing/unknown zones and returns no action
  candidates.
- Accepted plans produce `move_to_waypoint` candidates with physical high-level
  side-effect class and local validation preconditions; they are not executed
  until submitted to the local gateway and safety verifier.

## Replay behavior

Replay can inspect helper proposal messages/artifact refs, local validation
results, and local action decisions. Replay must not re-contact helpers or execute
robotics adapters by default.

## Tests and evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| contract | Helper work orders deny robotics/physical authority | `cargo test -p splendor-types cloud_helper` |
| contract | Route proposal message validates typed payload | `cargo test -p splendor-types cloud_helper` |
| integration | Accepted local plan executes only through gateway | `cargo test -p splendor-kernel cloud_helper` |
| negative | Rejected plan traces denial and skips adapter | `cargo test -p splendor-kernel cloud_helper` |
| failure | Helper timeout creates no local actions | `cargo test -p splendor-kernel cloud_helper` |
| replay | Trace sequence reconstructs proposal, validation, action decision | `cargo test -p splendor-kernel cloud_helper` |

## Example or fixture

See `examples/robot-cloud-route-planner/README.md`.

## Future extension notes

0.05-S7 can use this contract in the physical demo harness by replacing the
in-memory proposal fixture with a simulated helper run while preserving the same
local validation and gateway+safety boundary.
