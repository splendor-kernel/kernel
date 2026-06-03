# 0.05-S1 — Device Profile Schema

## Objective

Represent physical and edge nodes as explicit capability-bearing runtime targets
without making Splendor a device driver or hard real-time controller.

## Functional scope

- Added typed `DeviceProfile` contract and validation in `splendor-types`.
- Added device kinds, physical capability categories, safety constraints, and
  local policy/offline indicators.
- Added compatibility conversion to existing 0.03 `CapabilityDocument`.

## Non-goals

- No ROS/native driver integration.
- No motor control, flight-controller integration, PLC replacement, or safety
  certification claim.
- No gateway, verifier, adapter execution, or live hardware path.

## Public contracts changed

- `splendor_types::DeviceProfile`, `DeviceNodeKind`, `DeviceCapability`,
  `DeviceCapabilityCategory`, `DeviceSafetyConstraint`,
  `DeviceLocalPolicyIndicators`.
- `ALLOWED_PHYSICAL_ACTIONS`, `FORBIDDEN_PHYSICAL_ACTION_PATTERNS`,
  `physical_action_capability()`, `validate_physical_capability_document()`.

## Runtime primitive impact

| Primitive | Impact |
| --- | --- |
| Fleet/node identity | Adds physical/edge profile metadata; identity remains separate. |
| Adapter | Defines bounded future action vocabulary only. |
| Verifier | Provides safety-constraint metadata for later verifiers. |
| Gateway | No execution path added; later physical actions still require gateway. |
| State/trace/replay | Metadata only; replay is inspect-only. |

## Trace behavior

No run trace events are added. Future registry or management audit events may
persist serialized profiles without re-running validation side effects.

## State behavior

No agent state nodes are created or updated. Profiles are registry metadata.

## Gateway and verifier behavior

Validation fails closed for forbidden or ambiguous physical actions. No adapter can
execute from a profile; execution remains future gateway + verifier scope.

## Replay behavior

Replay can inspect profiles and converted capability documents. It must not
dispatch work, contact hardware, or execute adapters.

## Tests and evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| unit | Valid drone/robot profile and compatibility document | `cargo test -p splendor-types device` |
| negative | Reject raw motor/actuator and ambiguous actions | `device_profile_tests.rs` |
| placement | Distinguish physical device, cloud helper, simulation, desktop sidecar | `placement_tests.rs` |

## Example or fixture

See `examples/device-profiles/README.md`.

## Future extension notes

- 0.05-S2 can consume `local_policy` TTL indicators for offline policy cache.
- 0.05-S4 can map allowed bounded actions to a robotics adapter interface.
- 0.05-S5 can consume `safety_constraints` as safety verifier evidence.
