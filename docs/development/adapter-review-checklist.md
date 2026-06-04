# Adapter Review Checklist

Use this checklist when reviewing adapter manifests, adapter docs, examples, or future conformance evidence for the 0.1 adapter maturity model.

## Sprint Binding

- Milestone is `Splendor0.1-dev`.
- Sprint is `0.1-S3 - Adapter maturity model` for this checklist, or a later sprint that explicitly consumes it.
- FRs include `FR-0.1-04` for maturity levels and `FR-0.1-08` for side-effect, verifier, trace, and replay guarantees.
- Primitives strengthened are adapter, action gateway, verifier, quota, trace store, replay, governance, physical/edge boundary, and docs/tests.

## Manifest Review

- `schema_version` is `splendor.adapter_manifest.v1`.
- `maturity_level` is exactly one of `experimental`, `local-safe`, `network-safe`, `governance-aware`, or `device-safe`.
- Adapter identity is stable and distinct from tenant, agent, run, action, state, trace, message, work order, node, instance, and fleet identities.
- Supported actions declare side-effect class, required permissions, preconditions where relevant, postconditions where relevant, params scope, and risk.
- Required verifiers include tenant, agent permission, adapter, quota, precondition, data-scope, network/filesystem/safety/approval/policy TTL where applicable, and postcondition where applicable.
- Quota dimensions are declared for action count, duration, filesystem bytes, network bytes, HTTP requests, device commands, or other bounded resource use as applicable.
- Trace behavior maps to existing trace events and records trace-safe evidence only.
- Replay behavior is inspect-only by default and says `side_effects_replayed: false`.
- Data, network, filesystem, credential, tenant, agent, run, and adapter scopes are explicit.
- Governance support states approval, circuit-breaker, intervention, policy TTL, and audit behavior without adding a product-specific approval UI.
- Physical/device safety support is `not_applicable` or documents high-level bounded actions and local safety verifier integration.
- Limitations and prohibited claims are explicit.
- Evidence references point to real docs, tests, examples, fixtures, or validation commands.

## Level Review

- `experimental` adapters do not claim stable, production, local-safe, network-safe, governance-aware, or device-safe maturity.
- `local-safe` adapters prove local scope boundaries, sandboxing, quota limits, denied out-of-scope behavior, and replay suppression.
- `network-safe` adapters prove allowlisted egress, data scope, method and byte limits, timeout/failure behavior, quota enforcement, and no secret tracing.
- `governance-aware` adapters prove approval-required pause, scoped approval re-evaluation, denial/expiry/revocation fail-closed behavior, circuit-breaker denial, and governance replay explanation.
- `device-safe` adapters prove only high-level bounded physical actions, local safety verifier integration, forbidden low-level action denial, trace-safe safety evidence, and no production safety certification claim.

## Gateway And Verifier Review

- No side-effectful action bypasses the Action Gateway.
- Adapter execution occurs only after required verifiers allow.
- Verifier unavailability fails closed as denial, approval need, intervention need, or failure.
- Adapter-specific checks do not replace tenant, permission, quota, data-scope, network/filesystem, approval, safety, or policy TTL verifiers.
- Approval evidence and circuit breakers remove or pause authority; they do not grant broad permissions.
- Denied or needs-approval actions do not reach adapter execution.

## Trace And Replay Review

- Action verification and outcome trace events are present for success, denial, failure, approval need, and intervention need where applicable.
- Trace evidence avoids secrets, raw sensor blobs, unbounded response bodies, raw camera/lidar data, and controller internals.
- Replay reconstructs decisions from trace/state only.
- Replay does not call adapters, networks, filesystems, devices, middleware, approval services, notification services, or breaker management paths by default.

## Physical Boundary Review

- Physical actions are limited to the canonical high-level action set.
- Raw actuator writes, `set_motor_pwm`, motor control, collision-avoidance bypass, firmware safety bypass, flight-controller internals, emergency-stop bypass, and unknown physical actions are rejected.
- Device-safe manifests require a local safety verifier before adapter execution.
- Cloud helpers are advisory and do not receive direct actuator authority.
- No wording claims production robotics safety certification, live hardware readiness, flight certification, PLC replacement, ROS/native driver replacement, or hard real-time control.

## Evidence Commands

Minimum local validation for this sprint:

```bash
python scripts/validate-adapter-manifests.py
python -m json.tool docs/spec/0.1/fixtures/adapter-manifests/filesystem.json
python -m json.tool docs/spec/0.1/fixtures/adapter-manifests/http.json
python -m json.tool docs/spec/0.1/fixtures/adapter-manifests/robotics-simulated-device.json
git diff --check
```

If adapter runtime code changes in a later sprint, also run the relevant adapter, gateway, replay, trace, quota, and governance tests.

## Rejection Conditions

- The manifest claims a maturity level without evidence.
- Experimental adapters are described as production, stable, certified, marketplace-approved, network-safe, governance-aware, or device-safe.
- Side effects can execute outside the gateway.
- Required verifiers are optional or silently skipped.
- Replay can repeat side effects by default.
- Network adapters allow unbounded egress or trace secrets.
- Physical adapters allow low-level actuator authority or imply production safety certification.
- Governance-aware wording adds a product UI, Harmony dependency, or legal/compliance certification claim.
