# Physical Safety

Splendor mediates physical autonomy through high-level, bounded actions routed
through the action gateway. It does not replace real-time controllers, firmware
safety loops, ROS/device drivers, collision avoidance systems, or certified
safety systems.

## Allowed action boundary

Examples of physical actions that require safety verification:

- `read_battery`
- `read_sensor_summary`
- `move_to_waypoint`
- `return_to_base`
- `dock`
- `inspect_zone`
- `capture_image`
- `pause_mission`
- `request_operator_override`

Forbidden direct actions remain out of scope: raw actuator writes, motor PWM,
firmware-safety bypass, flight-controller mutation, or emergency-stop override.

## Fail-closed behavior

For physical actions:

- missing required safety verifier => `NeedsIntervention`;
- verifier uncertainty => `NeedsIntervention`;
- safety denial => `Denied` before adapter execution;
- unsafe adapter outcome => `Failed` with post-verification evidence.

Tenant policy, adapter, approval, quota, circuit-breaker, and invariant checks
remain gateway checks. Safety verification adds a local physical verifier stage;
it does not grant permissions or bypass approval.

## Evidence

Physical safety evidence must be trace-safe. It may include status references,
zone identifiers, threshold values, and reason codes. It must not include raw
sensor payloads or sensitive physical telemetry blobs.
