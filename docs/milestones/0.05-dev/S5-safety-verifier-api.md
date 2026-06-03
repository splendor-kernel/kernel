# 0.05-S5 — Safety verifier API

## Objective

Implement a local physical safety verifier API in the existing action gateway so
high-level physical actions are checked before and after adapter execution.

## Functional scope

- Added `SafetyVerifier`, `SafetyVerification`, `SafetyEvidence`, and simulated
  verifier types in `splendor-gateway`.
- Added gateway fail-closed behavior for physical actions with missing or
  uncertain safety verification.
- Added post-execution safety verification for unsafe physical outcomes.

## Non-goals

- No certified safety system.
- No real-time collision avoidance.
- No low-level sensor fusion, ROS integration, hardware drivers, or raw actuator control.
- No parallel physical gateway.

## Public contracts changed

- `VerifiedActionGateway::set_safety_verifier(...)` installs a local safety verifier.
- `SafetyEvidence` schema: `splendor.safety_evidence.v1`.
- Existing trace event kinds are reused: `ActionDenied`, `ActionNeedsIntervention`, and `ActionFailed`.

## Runtime primitive impact

| Primitive | Impact |
| --- | --- |
| Gateway | Added pre/post physical safety verifier stage. |
| Verifier | Added safety verifier interface and reference simulator. |
| Adapter | Physical adapters execute only after safety allow. |
| Trace store | Safety evidence is carried in existing verification artifacts. |
| Replay | Evidence is inspectable; replay must not re-execute physical adapters. |

## Trace behavior

No new event classes. Pre-denials map to action denial/intervention events;
postcondition failures map to action failure with `post_verification` evidence.

## State behavior

No state graph format change. Unsafe/denied outcomes should be recorded by the
runtime as normal action outcomes; this sprint changes gateway verification only.

## Gateway and verifier behavior

- Physical action detection uses high-level action names, physical side-effect
  classes, or `params.physical_action = true`.
- Missing safety verifier fails closed with `safety_verifier_missing` and
  `verifier_uncertainty`.
- Simulated verifier denials include geofence, battery, emergency stop,
  collision, altitude, privacy, and proximity reason codes.

## Replay behavior

Replay can reconstruct safety decisions from `VerificationResult` evidence. It
must not execute physical adapters by default.

## Tests and evidence

| Test | Purpose | Evidence |
| --- | --- | --- |
| unit | Gateway denial skips adapter | `cargo test -p splendor-gateway safety` |
| negative | Missing/uncertain verifier fails closed | `cargo test -p splendor-gateway safety` |
| postcondition | Unsafe physical outcome fails post-verification | `cargo test -p splendor-gateway safety` |

## Example or fixture

See `examples/simulated-safety-verifiers/README.md`.

## Future extension notes

Future robotics adapters and demo harnesses can reuse `SafetyVerifier` and
`SafetyEvidence` while replacing `SimulatedSafetyVerifier` with device-local
certified or attested verifiers.
