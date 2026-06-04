# 0.1-S2 Compatibility Test Suite

## 1. Objective

Create a primitive-focused, secret-free compatibility suite for Splendor 0.1 that
internal and external implementers can run locally or in CI. The suite reports
exact primitive and requirement failures.

## 2. Functional Scope

- Add `conformance/0.1/run-conformance.py` as the single reference runner.
- Add `conformance/0.1/fixtures/conformance-cases.json` as the fixture library.
- Reuse S3 adapter manifests from `docs/spec/0.1/fixtures/adapter-manifests/`.
- Reuse S1 stable primitive examples from
  `docs/spec/0.1/stable-primitive-examples.json`.
- Add text and JSON report formats.
- Cover runtime loop, gateway, trace, state, replay, messages, work orders,
  governance, and adapters.

## 3. Non-Goals

- No new runtime features.
- No production secrets, networks, external services, SaaS dependencies, or
  hardware dependencies.
- No vendor-specific runner, UI dashboard, marketplace, or certification business
  process.
- No production physical safety claim.
- No complete post-implementation use-case E2E acceptance claim.

## 4. Public Contracts Changed

No stable primitive schema changed. This sprint adds conformance fixture schema
`splendor.conformance_suite.v1` and report schema
`splendor.conformance_report.v1`.

## 5. Runtime Primitives Touched

- runtime loop
- action gateway
- trace store
- state graph
- replay
- message
- work order
- governance
- adapter
- docs/tests

## 6. Trace Events Added Or Changed

No runtime trace events were added or changed. Fixtures validate existing stable
event classes including `tick.started`, `verification.completed`, action outcome
events, `state.committed`, message lifecycle events, approval events,
escalation, and circuit-breaker events. Dedicated `primitive: trace` fixtures
report trace-specific ordering and identity failures.

## 7. State Behavior Added Or Changed

No runtime state behavior changed. Fixtures validate explicit state commit fields,
trace linkage, parent linkage, state hash, ownership identity, and fail-closed
state commit failure behavior.

## 8. Verifier/Gateway Behavior Added Or Changed

No runtime gateway behavior changed. Fixtures validate gateway mediation,
successful execution after verification, verification before action outcome,
denial before adapter execution, verifier uncertainty fail-closed behavior, and
adapter failure recording.

## 9. Replay Behavior

Replay remains inspect-only by default. The suite verifies
`side_effects_replayed: false` and no invoked policies, gateways, verifiers, or
adapters in replay fixtures and adapter manifests.

## 10. Failure Behavior

The suite includes failures for adapter errors, state commit failure, verifier
unavailability, unsigned/expired/revoked/overbroad work orders, approval denial,
escalation to intervention, circuit-breaker denial, message causality, and
negative trace-order fixtures that must fail internally.

## 11. Test Evidence

Required validation commands:

```bash
python conformance/0.1/run-conformance.py
python scripts/validate-adapter-manifests.py
git diff --check
```

The conformance command emits text by default and returns non-zero on any failed
case. Use `--format json --output <path>` for CI report artifacts.

## 12. Example Commands Or Fixtures

```bash
python conformance/0.1/run-conformance.py --format json --output target/conformance-0.1-report.json
```

Fixtures:

```text
conformance/0.1/fixtures/conformance-cases.json
docs/spec/0.1/fixtures/adapter-manifests/*.json
```

## 13. Future Extension Notes

Future implementation-specific conformance can export the same report shape after
executing real runtime tests, but it must not hide missing production-path
behavior behind fixtures. Full use-case E2E acceptance remains governed by
`docs/rules/verifiable_criteria/use-case-e2e-through-0.1.md`.
