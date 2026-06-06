# S3 Adapter Maturity Model

## Objective

Define an evidence-based adapter maturity model for Splendor0.1-dev so future adapter ecosystem growth remains controlled without adding marketplace, legal certification, product workflow, or runtime execution mechanics.

## Functional Scope

- Defined maturity levels: `experimental`, `local-safe`, `network-safe`, `governance-aware`, and `device-safe`.
- Documented per-level requirements, required evidence, prohibited claims, gateway/verifier/quota/data-scope behavior, trace/replay behavior, and fail-closed expectations.
- Defined `splendor.adapter_manifest.v1` metadata schema in `docs/spec/0.1/adapter-maturity.md`.
- Added example manifests for filesystem, HTTP, and simulated robotics/device adapters.
- Added a lightweight validation script for manifest syntax and required fields.

## Non-Goals

- No marketplace, vendor ranking, or adapter approval workflow.
- No legal certification or production support attestation.
- No product-specific approval UI or Harmony dependency.
- No new runtime adapter behavior or side-effect path.
- No production robotics safety certification, live hardware readiness, motor control, raw actuator writes, firmware safety bypass, collision-avoidance bypass, or cloud direct actuator authority.

## Public Contracts Changed

- Added documentation candidate schema `splendor.adapter_manifest.v1`.
- Added stable fixture paths under `docs/spec/0.1/fixtures/adapter-manifests/` for future conformance consumption.
- No Rust, Python, TypeScript, daemon API, gateway, verifier, adapter, trace, state, replay, or quota runtime contract changed.

## Runtime Primitives Touched

- Adapter.
- Action gateway.
- Verifier.
- Quota.
- Trace store.
- Replay.
- Governance.
- Physical/edge boundary.
- Docs/tests.

## Trace Events Added Or Changed

No trace event names or runtime trace semantics were added or changed.

The maturity model requires adapters to map evidence to existing trace events such as `verification.started`, `verification.completed`, `action.executed`, `action.denied`, `action.failed`, `action.needs_approval`, `action.needs_intervention`, `outcome.recorded`, approval lifecycle events, circuit-breaker events, and physical safety evidence carried in verifier results.

## State Behavior Added Or Changed

No state graph behavior was added or changed.

The model requires adapter manifests to describe state impact honestly. Existing runtime behavior remains that action outcomes are committed through explicit state commits when the kernel loop advances.

## Verifier/Gateway Behavior Added Or Changed

No gateway or verifier runtime behavior was added or changed.

The model documents that side-effectful adapters remain gateway-mediated and must fail closed when required verifiers are missing, unavailable, unsupported, uncertain, or deny.

## Replay Behavior

Replay remains inspect-only by default. The model requires manifests to state `side_effects_replayed: false` and prohibits replay from calling adapters, filesystems, networks, devices, middleware, approval services, notification services, or breaker-management paths by default.

## Failure Behavior

The model requires adapters to document fail-closed behavior for missing identity, unsupported actions, invalid scope, quota exhaustion, missing or unavailable verifiers, approval or circuit-breaker denial, safety uncertainty, trace/state durability failure, and adapter execution failure.

## Test Evidence

Sprint-local validation is docs/fixture focused:

```bash
python scripts/validate-adapter-manifests.py
python -m json.tool docs/spec/0.1/fixtures/adapter-manifests/filesystem.json
python -m json.tool docs/spec/0.1/fixtures/adapter-manifests/http.json
python -m json.tool docs/spec/0.1/fixtures/adapter-manifests/robotics-simulated-device.json
git diff --check
```

No runtime tests were added because the sprint explicitly avoids adapter runtime behavior changes.

## Example Commands Or Fixtures

- `docs/spec/0.1/fixtures/adapter-manifests/filesystem.json`
- `docs/spec/0.1/fixtures/adapter-manifests/http.json`
- `docs/spec/0.1/fixtures/adapter-manifests/robotics-simulated-device.json`
- `scripts/validate-adapter-manifests.py`

## Future Extension Notes

- 0.1-S2 conformance may consume these manifests for deeper runtime evidence checks.
- 0.1-S1 schema-freeze wording may require final naming alignment before 0.1 release.
- Future adapter authors should treat maturity metadata as evidence input, not authority, certification, or marketplace approval.
