# Safety Verifiers

Safety verifiers are local gateway verifiers for high-level physical actions.
They are part of `VerifiedActionGateway`; they are not a parallel execution path.

## Rust contract

- `SafetyVerifier::verify_pre(request, adapter)` runs before adapter execution.
- `SafetyVerifier::verify_post(request, adapter, result)` runs after adapter execution.
- `SafetyVerification::Denied` returns `ActionStatus::Denied` before execution.
- `SafetyVerification::NeedsIntervention` returns `ActionStatus::NeedsIntervention` before execution.
- Unsafe postconditions return `ActionStatus::Failed` with `post_verification` evidence.

Physical actions are identified by high-level physical action names, by
`SideEffectClass::Custom("physical" | "physical.high_level" | "physical.*")`, or by
`params.physical_action = true`.

## Evidence model

`SafetyEvidence` uses schema `splendor.safety_evidence.v1` and records only
trace-safe evidence:

- verifier and check names;
- status: `Pass`, `Deny`, or `Uncertain`;
- stable reason codes;
- sensor/status references such as `status:battery.latest`;
- zone references;
- threshold names and observed/min/max values.

Raw sensor blobs, camera frames, maps, lidar packets, or fused controller state
must not be written into safety evidence.

## Reference simulated verifier

`SimulatedSafetyVerifier` evaluates `SimulatedSafetySnapshot` for:

- geofence zone membership;
- minimum battery percentage;
- emergency stop status;
- collision risk;
- altitude maximum;
- privacy zone activity;
- proximity minimum.

Missing required status for a physical action is uncertainty and fails closed.

## Trace mapping

No new trace event kind is required. Gateway outcomes map to existing events:

- pre-execution denial: `ActionDenied` with `VerificationResult.artifacts.evidence`;
- pre-execution uncertainty: `ActionNeedsIntervention`;
- unsafe postcondition: `ActionFailed` with `post_verification`.

Replay can inspect the recorded evidence and must not re-execute the physical
adapter by default.
