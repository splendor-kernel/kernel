# Physical Actions

Physical actions are Splendor's high-level, bounded vocabulary for device-side
autonomy. They must be submitted as `ActionRequest`s to `VerifiedActionGateway`
and must pass the local `SafetyVerifier` before any adapter execution.

## Allowed actions

The canonical Rust source is `splendor_types::ALLOWED_PHYSICAL_ACTIONS`:

- `read_battery`
- `read_sensor_summary`
- `read_map`
- `move_to_waypoint`
- `return_to_base`
- `dock`
- `inspect_zone`
- `capture_image`
- `pause_mission`
- `resume_mission`
- `request_operator_override`
- `notify_operator`
- `upload_trace_summary`

These are mission/controller requests to local middleware, not direct actuator
commands.

## Forbidden actions

The gateway and adapter boundary reject low-level or safety-bypass names before
adapter execution, including raw actuator writes, `set_motor_pwm`, motor PWM,
firmware safety bypass, flight-controller internals, collision-avoidance bypass,
and emergency-stop bypass.

Unknown actions marked as physical also fail closed instead of being accepted as
ambiguous device control.

## Trace and replay

Gateway outcomes map to action trace events. Replay must inspect recorded
outcomes/evidence and must not re-send physical actions to middleware by default.
