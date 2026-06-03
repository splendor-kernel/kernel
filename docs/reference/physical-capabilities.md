# Physical Capabilities Reference

Physical capabilities describe what a device-side Splendor runtime can safely
advertise. They do not authorize actions and do not replace hard real-time device
controllers.

## Categories

`DeviceCapabilityCategory` values:

| Category | Meaning |
| --- | --- |
| `sensor` | Sensor summaries or safe read interfaces. |
| `bounded_action` | High-level physical actions that must later pass gateway and safety verifiers. |
| `local_compute` | On-device compute or policy-cache support. |
| `network` | Network availability or restrictions. |
| `power` | Battery or power status capability. |
| `safety_status` | Safety status inputs such as emergency stop or geofence state. |

## Allowed bounded actions

The canonical list is exported as `ALLOWED_PHYSICAL_ACTIONS`:

```text
read_battery
read_sensor_summary
read_map
move_to_waypoint
return_to_base
inspect_zone
capture_image
pause_mission
resume_mission
request_operator_override
notify_operator
upload_trace_summary
```

Unknown bounded actions fail closed to avoid accepting ambiguous physical control
classes such as `move`, `motor`, or `fly`.

## Forbidden direct Splendor actions

The validator rejects direct raw or safety-bypass advertisements, including motor
PWM, raw actuator writes, firmware safety bypass, flight-controller internals,
collision-avoidance bypass, and emergency-stop bypass. These remain below the
Splendor boundary and must be handled by device middleware and firmware safety
systems.

## Safety and offline indicators

Profiles include `safety_constraints` and `local_policy` indicators so later
offline policy-cache and safety-verifier sprints can consume stable metadata.
Offline operation requires local policy-cache support and an explicit max offline
policy TTL.
