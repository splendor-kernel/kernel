# Device Profiles Reference

Device profiles are the 0.05-S1 contract for describing physical and edge runtime
targets. They are schema and validation metadata only: Splendor does not become a
ROS/native driver, flight controller, PLC, firmware safety loop, motor controller,
or hard real-time control layer.

Rust implementation: `splendor_types::DeviceProfile`.

## Schema

```rust
pub const DEVICE_PROFILE_SCHEMA: &str = "splendor.device_profile.v1";

pub struct DeviceProfile {
    pub schema: String,
    pub kind: DeviceNodeKind,
    pub capabilities: Vec<DeviceCapability>,
    pub safety_constraints: Vec<DeviceSafetyConstraint>,
    pub local_policy: DeviceLocalPolicyIndicators,
}
```

`DeviceNodeKind` values are `robot`, `drone`, `humanoid`, `edge_appliance`,
`desktop_sidecar`, and `industrial_device`. The profile is not a `node_id`,
`instance_id`, or `run_id`; registry identity remains separate.

## Validation

`DeviceProfile::validate()` rejects profiles with unsupported schema, empty or
duplicate capabilities, malformed tokens, missing safety constraints, invalid
offline indicators, unknown bounded physical actions, or forbidden direct actuator
advertisements.

Allowed bounded actions are high-level only, including `move_to_waypoint`, `dock`,
`inspect_zone`, `capture_image`, and `return_to_base`. Forbidden direct actions
include raw actuator writes, motor PWM, firmware safety bypass, flight-controller
internals, collision avoidance bypass, and emergency-stop bypass.

## Capability compatibility

`DeviceProfile::to_capability_document()` converts a validated profile into the
existing 0.03 `CapabilityDocument` instead of forking the registry model. Bounded
actions are emitted with the `physical.action.` prefix, for example:

```text
physical.action.move_to_waypoint
physical.action.dock
```

Use `validate_physical_capability_document()` when a 0.03 capability document
advertises physical action tokens directly.

## Replay and gateway behavior

Profiles execute no side effects and add no adapter path. Replay can inspect a
serialized profile and capability document; it must not dispatch work or execute
hardware actions. Any later physical action execution remains mediated by the
Action Gateway and device-local safety verifiers.
