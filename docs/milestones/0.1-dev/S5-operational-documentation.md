# 0.1-S5 Operational Documentation

## Objective

Publish operator-facing guides that show how to run, inspect, validate, and clean
up stable 0.1 Splendor modes using stable primitives and existing test-backed
examples.

## Functional Scope

- Milestone: `Splendor0.1-dev`
- Sprint: `0.1-S5 - Operational documentation`
- FRs: `FR-0.1-07`, `FR-0.1-08`
- Guides added: local runtime, runtime daemon, resident/fleet, governance, Harmony/external control-plane integration, and physical/edge.
- User outcome: operators can run, inspect, validate, and clean up stable 0.1 modes while seeing limitations and safety boundaries.

## Non-Goals

- No new runtime behavior.
- No product UI, admin SaaS manual, billing, marketplace, or enterprise support guide.
- No production remote daemon or production fleet scheduling claim.
- No production OAuth/PKI/mTLS rollout.
- No production robotics safety certification, live hardware readiness, or real-time control claim.
- No vendor-specific Harmony dependency inside the kernel.

## Public Contracts Changed

No primitive schema, daemon API, Rust, Python, or TypeScript public contract changed. This sprint adds operational documentation that references the stable 0.1 contract documents and existing examples.

## Runtime Primitives Touched

- docs/tests
- runtime context
- action gateway
- verifier
- adapter
- quota
- state graph
- trace store
- replay
- work order
- governance
- fleet/node identity
- SDK/API

## Trace Events Added Or Changed

No trace event names or semantics changed. The guides document existing local loop, daemon audit, work-order, trace sync, governance, circuit-breaker, escalation, offline, and physical safety trace events.

## State Behavior Added Or Changed

No state graph behavior changed. The guides document explicit state heads, state nodes, snapshot references, and the rule that replay and telemetry do not mutate live state.

## Verifier/Gateway Behavior Added Or Changed

No verifier or gateway behavior changed. The guides document existing fail-closed behavior for daemon security, work orders, gateway verification, approvals, escalations, circuit breakers, physical safety, policy TTL, and trace durability.

## Replay Behavior

Replay remains inspect-only by default in every guide. The documentation explicitly states that replay must not execute adapters, repeat filesystem/network/device side effects, call approval systems, clear circuit breakers, re-register nodes, call cloud helpers, or mutate state.

## Failure Behavior

The guides document fail-closed behavior for missing auth/scope, unsigned or invalid work orders, gateway denials, approval denial/expiry/revocation, escalation intervention, circuit-breaker denial, trace sync corruption, telemetry non-authority, physical safety denial, offline policy expiry, and local trace buffer pressure.

## Test Evidence

Required validation for this sprint:

```bash
python conformance/0.1/run-conformance.py
python scripts/validate-adapter-manifests.py
git diff --check
```

The guides also reference existing runnable or test-backed example commands for local runtime, daemon, resident/fleet, governance, Harmony/external control-plane, and physical/edge operation.

## Example Commands Or Fixtures

- `examples/local-basic-loop/README.md`
- `examples/daemon-client-local/README.md`
- `examples/typescript-daemon-client/README.md`
- `examples/resident-node-registration/README.md`
- `examples/signed-work-order-local-resident/README.md`
- `examples/resident-trace-sync/README.md`
- `examples/fleet-telemetry-basic/README.md`
- `examples/action-approval-flow/README.md`
- `examples/escalation-basic/README.md`
- `examples/circuit-breaker-basic/README.md`
- `examples/harmony-governance-bridge/README.md`
- `examples/physical-simulation-harness/README.md`
- `examples/simulated-drone-adapter/README.md`

## Future Extension Notes

Future operational docs may add production deployment runbooks only after the corresponding authenticated remote daemon, fleet scheduling, governance control-plane, and physical hardware contracts are implemented and verified. Those future docs must preserve signed work orders, gateway enforcement, explicit state, trace ordering, and replay side-effect suppression.
