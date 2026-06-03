# Cloud Helpers for Physical Devices

Cloud/on-prem helpers are advisory Splendor instances used by physical devices for
planning or analysis. They use the normal signed work-order and typed message
contracts; they do not get a separate authority system.

## Contracts

- Helper work orders set `placement.execution_mode = "cloud_helper"`.
- Helper work orders may include scoped `data_refs`, `route_plan.propose`,
  `mission_plan.propose`, `message.send`, or artifact write authority.
- Helper work orders must not include the `robotics` adapter, allowed physical
  action names such as `move_to_waypoint`, or low-level actuator names such as
  `set_motor_pwm`.
- Route proposals use `splendor.message.route_plan_proposal.v1` with
  `proposal_id`, scoped `data_refs`, and bounded `waypoint_ref`/`zone_ref` pairs.

## Local device flow

```text
signed helper work order
  -> helper computes advisory route proposal
  -> typed message or artifact reference returns to device
  -> device validates proposal zones/policy locally
  -> device converts accepted proposal to bounded action candidates
  -> local Action Gateway + SafetyVerifier verifies each action
  -> robotics adapter executes only after local allow
```

Network failure or timeout maps to `cloud_helper_unavailable` and produces no
bounded local action candidates.

## Trace and replay

No new trace event kind is required. Use existing events:

- `RemoteMessageSent` / `RemoteMessageDelivered` for helper proposal messages;
- `RemoteMessageTimedOut` or `RemoteMessageTransportFailed` for helper failure;
- `ActionVerificationCompleted` for local proposal validation evidence;
- `ActionDenied`, `ActionNeedsIntervention`, or `ActionExecuted` for final local
  action decisions.

Replay reconstructs helper proposal delivery, local validation, and final gateway
outcomes. Replay must not call the helper or robotics adapter by default.

## Security notes

The local device remains the action authority. Helpers propose routes/plans only;
direct actuator credentials, robotics adapter registration, and physical action
execution remain local to the device Splendor instance.
