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

Concrete profile fixtures should use the same constructor shape with different
`DeviceNodeKind` and bounded actions:

```rust
let fixtures = [
    (
        DeviceNodeKind::Drone,
        vec!["move_to_waypoint", "return_to_base", "capture_image"],
        vec!["geofence.required", "battery.min_threshold"],
    ),
    (
        DeviceNodeKind::Robot,
        vec!["inspect_zone", "dock"],
        vec!["workspace_boundary.required", "emergency_stop.status_required"],
    ),
    (
        DeviceNodeKind::Humanoid,
        vec!["request_operator_override", "notify_operator"],
        vec!["human_proximity.limit", "force_limit.required"],
    ),
    (
        DeviceNodeKind::EdgeAppliance,
        vec!["read_sensor_summary", "upload_trace_summary"],
        vec!["network.egress_restricted", "policy_cache.required"],
    ),
    (
        DeviceNodeKind::DesktopSidecar,
        vec!["notify_operator", "read_sensor_summary"],
        vec!["local_user_session.required", "filesystem_scope.required"],
    ),
    (
        DeviceNodeKind::IndustrialDevice,
        vec!["pause_mission", "read_sensor_summary"],
        vec!["plc_safety_loop.external", "emergency_stop.status_required"],
    ),
];

for (kind, actions, safety_names) in fixtures {
    let mut capabilities: Vec<DeviceCapability> = actions
        .into_iter()
        .map(DeviceCapability::bounded_action)
        .collect();
    capabilities.push(DeviceCapability {
        category: DeviceCapabilityCategory::SafetyStatus,
        name: "emergency_stop.status".into(),
    });

    let safety_constraints = safety_names
        .into_iter()
        .map(|name| DeviceSafetyConstraint {
            name: name.into(),
            value: serde_json::json!(true),
        })
        .collect();

    let profile = DeviceProfile::new(
        kind,
        capabilities,
        safety_constraints,
        DeviceLocalPolicyIndicators {
            supports_local_policy_cache: true,
            supports_offline_operation: true,
            supports_local_operator_intervention: true,
            max_offline_policy_ttl_seconds: Some(300),
        },
    )?;
    validate_physical_capability_document(&profile.to_capability_document()?)?;
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

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
