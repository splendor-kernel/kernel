# Device Profile Examples

These examples show the 0.05-S1 schema contract only. They do not connect to ROS,
hardware, motors, firmware, or cloud services.

## Minimal Rust shape

```rust
use splendor_types::*;

let profile = DeviceProfile::new(
    DeviceNodeKind::Drone,
    vec![
        DeviceCapability::bounded_action("move_to_waypoint"),
        DeviceCapability::bounded_action("dock"),
        DeviceCapability::bounded_action("inspect_zone"),
        DeviceCapability::bounded_action("capture_image"),
        DeviceCapability::bounded_action("return_to_base"),
        DeviceCapability { category: DeviceCapabilityCategory::Sensor, name: "camera.rgb".into() },
        DeviceCapability { category: DeviceCapabilityCategory::Power, name: "battery.status".into() },
        DeviceCapability { category: DeviceCapabilityCategory::SafetyStatus, name: "emergency_stop.status".into() },
    ],
    vec![DeviceSafetyConstraint { name: "geofence.required".into(), value: serde_json::json!(true) }],
    DeviceLocalPolicyIndicators {
        supports_local_policy_cache: true,
        supports_offline_operation: true,
        supports_local_operator_intervention: true,
        max_offline_policy_ttl_seconds: Some(300),
    },
)?;

let capability_document = profile.to_capability_document()?;
validate_physical_capability_document(&capability_document)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Covered profile kinds

- Drone: `move_to_waypoint`, `return_to_base`, `capture_image`.
- Robot: `inspect_zone`, `dock`.
- Humanoid: `request_operator_override`, `notify_operator`.
- Edge appliance: `read_sensor_summary`, `upload_trace_summary`.
- Desktop sidecar: `notify_operator` and local file/app-facing capabilities.
- Industrial device: `pause_mission`, `read_sensor_summary`.

## Rejected examples

These must not be advertised as Splendor direct actions:

```text
set_motor_pwm
raw_actuator_write
disable_firmware_safety
bypass_collision_avoidance
ignore_emergency_stop
```

Splendor may govern high-level bounded actions, but low-level control and hard
real-time safety remain in device middleware and firmware.
