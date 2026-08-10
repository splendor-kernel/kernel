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

The resident builds the simulated verifier snapshot from its authenticated,
stored `DeviceRuntimeProfile`, current time, node identity, and requested action
parameters. Request `SafetyContext` values can only narrow that snapshot: numeric
observations use the more conservative value, allowlists intersect, clear flags
are logical AND, and offline/expired/high-risk/direct-cloud-authority flags are
logical OR. Missing or malformed process-owned battery, collision, geofence, or
policy facts fail closed. A caller cannot report a higher battery, clear an
emergency stop/privacy/proximity condition, expand a geofence or altitude limit,
unexpire policy, or turn cloud-helper authority into a direct actuator grant.

Before a caller-supplied `DeviceRuntimeProfile` becomes that trusted process
input, the daemon authenticates tenant/node scope and sends the complete serialized
profile through the Gateway-owned bounded credential guard. Every nested string
and object key is screened before audit or profile mutation. A denied profile
cannot be read back, contribute zone refs or status to safety evidence, or reach a
physical Gateway/simulator. The daemon retains profile validation and ownership;
this screening does not turn profile metadata into Authority.

Approval-gated physical actions use the same exact-challenge receipt contract as
digital actions. Raw granted `ApprovalEvidence`, altered action/safety bindings,
or a reused receipt cannot authorize a physical adapter call. The trusted receipt
is still insufficient if the device-local safety verifier denies or is uncertain.
Before challenge/digest generation, the kernel binds the authenticated path's
registered node as a trusted `physical_node` resource coordinate. Physical
approval action digests use
`splendor.gateway.authority_action_binding.physical.v2`; changing the node changes
the digest and invalidates the receipt. The requester cannot supply this
coordinate, and a physical action without it fails closed before adapter lookup.

## Evidence

Physical safety evidence must be trace-safe. It may include status references,
zone identifiers, threshold values, and reason codes. It must not include raw
sensor payloads or sensitive physical telemetry blobs.
`safety.verification.completed` is emitted only after the gateway returns actual
safety-verifier evidence. A safety denial emits a non-allowing completion plus
`safety.verification.denied`; quota, approval, or unrelated gateway denials do not
manufacture a safety result.

Operator intervention evidence is a caller-carried reference, not authoritative
permission. The resident resolves the authoritative intervention record and
requires exact request tenant, agent, run, path node, and action binding. Both the
stored status and evidence decision must be `granted`. Resident current time and
the stored expiry control validity; evidence may use the same or an earlier
expiry, but cannot extend the record. A grant for one device cannot be reused on
another device. These bindings use the existing request/path and record fields;
the evidence schema is unchanged.
