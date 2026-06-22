# Splendor 0.1 Conformance Suite

Milestone: `Splendor0.1-dev`
Sprint: `0.1-S2 - Compatibility test suite`
FRs: `FR-0.1-05`, `FR-0.1-08`

This document defines the 0.1 primitive conformance contract. The suite is a
compatibility test suite for stable primitive behavior, not post-implementation
use-case E2E acceptance, adapter certification, a marketplace program, a UI
dashboard, or a production physical safety claim.

## Scope

The reference suite lives under `conformance/0.1/` and validates fixture evidence
for these primitive categories:

- runtime loop
- action gateway
- trace
- state graph
- replay
- messages
- work orders
- governance
- adapters
- compatibility fixture matrix v0
- FND-011 security invariant mapping fixture v0
- FND-011 G86 driver schema-confusion denial fixture v0
- performance budget fixture contract v0

The suite must be runnable without production secrets, external services,
production networks, SaaS systems, hardware, or vendor-specific runners.

## Fixture Boundary

Fixtures are contract evidence. They prove that the stable primitive contract can
identify success, denial, failure, replay, and fail-closed behavior in a portable
way. They are not a substitute for production-path tests when an implementation
claims full runtime behavior.

Runtime execution evidence can be added later by exporting the same report shape,
but 0.1-S2 keeps one reference path: the fixture runner in
`conformance/0.1/run-conformance.py`.

## Required Coverage

The suite validates:

- Complete runtime tick ordering from `tick.started` through `tick.completed`.
- Verification before action outcome events.
- Trace-specific ordering and identity failures with `primitive: trace` reporting.
- Gateway denials and verifier uncertainty that skip adapter execution.
- Gateway successful execution after verification.
- Adapter failure recorded as a traceable failure after verification allows.
- State commits with tenant, agent, run, parent, hash, trace linkage, and time.
- State commit failure preventing tick completion and next-tick advancement.
- Replay defaulting to `inspect_only` with `side_effects_replayed: false`.
- Message source/target/run identity plus causal trace linkage.
- Work-order rejection for unsigned, expired, revoked, and overbroad authority.
- Governance approval, denial, escalation/intervention, and circuit-breaker paths.
- Adapter manifests with maturity metadata, replay suppression, gateway mediation,
  and no secret-shaped fixture fields.
- S1 stable primitive examples with required fields and non-authorizing
  extensions.
- Partial FND-006 compatibility fixture matrix v0 evidence: current stable
  examples are accepted, additive non-authorizing extensions are accepted where
  allowed, authorizing/security-critical extension fields are rejected
  fail-closed, and the documented `trace_id` input alias canonicalizes to stable
  `trace_event_id` output.
- Partial FND-011 security invariant mapping fixture v0 evidence: every G80-G89
  security/adversarial case maps to assets, trust boundary, principal, attacker
  capability, fail-closed decision, enforcing component, required event,
  evidence link, containment action, incident class, and change-risk class. The
  runner rejects prompt-only boundaries, skipped mandatory conformant cases,
  prompt-only enforcement wording even when `prompt_only` is false, unsafe
  crypto-agility labels, `exercised` status without executable gold evidence,
  missing G80-G89 mappings, and missing event/evidence/containment links.
- Partial FND-011 G86 driver schema-confusion denial fixture v0 evidence: a
  driver schema/version mismatch carries a stable mismatch reason, fails
  verification, records schema rejection/denial/outcome events, keeps
  adapter/driver invocation counts at zero, and records no side effects. A
  negative fixture family proves the runner rejects a mismatched-schema case that
  still reports execution, unknown execution/receipt fields, side-effect events,
  missing side-effect counters, duplicate trace IDs, out-of-order events,
  mismatched verifier evidence, and malformed non-claim guards. This is bounded
  denial evidence only, not a G86 gold pass.
- Partial FND-012 performance budget fixture contract v0 evidence: mandatory
  latency/throughput budgets, environment-capture shape, regression thresholds,
  retention/backpressure actions, provider/model-time separation, and
  G29/G66/G68/G74 SLO/resource mappings are present while gold status remains
  `not_exercised`; negative fixtures reject missing environment capture,
  provider/model-time mixing, and skipped safety checks.

## Report Format

The text report is stable for humans:

```text
Splendor 0.1 conformance report
status: pass
cases: <case_count>
failed: 0
PASS <primitive> <requirement> <case_id>: <message>
```

The JSON report is stable for CI ingestion:

```json
{
  "schema_version": "splendor.conformance_report.v1",
  "milestone": "Splendor0.1-dev",
  "sprint": "0.1-S2",
  "status": "pass",
  "case_count": 47,
  "failed_count": 0,
  "results": [
    {
      "case_id": "runtime-loop-positive-order",
      "primitive": "runtime_loop",
      "requirement": "CONF-0.1-RUNTIME-ORDER",
      "path": "positive",
      "status": "pass",
      "message": "ok"
    }
  ]
}
```

Every failure identifies the exact `primitive`, `requirement`, and `case_id`.

## Compatibility Impact

The suite does not change stable primitive schemas. It adds conformance fixture
IDs and report schema `splendor.conformance_report.v1` for compatibility testing.
The FND-006 compatibility matrix v0 cases are partial fixture evidence only; they
do not implement version negotiation, storage migrations, rolling upgrades,
training-worker compatibility, or agent migration, and they must not be reported
as `G00`, `G72`, or full FND-006 completion. Implementers may use the report
shape for CI checks, but passing this fixture suite alone must not be represented
as complete use-case E2E acceptance.

The FND-011 security invariant mapping v0 case is also partial evidence only. It
does not implement a secret broker, data-use controller, attestation system,
rollout controller, protected eval isolation, red-team harness, or physical
safety certification. It must not be reported as full FND-011 completion or as
passing G80-G89 gold evidence.

The fixture runner also rejects `case_status: exercised` unless explicit
executable gold evidence metadata is present. The checked G80-G89 fixture remains
`mapped_not_exercised`; this is not pass status.

The G86 driver schema-confusion denial fixture is partial evidence only. It does
not implement a driver registry, driver certification process, runtime ABI
negotiation service, or live adapter execution path. It must not be reported as a
full G86 gold pass, full FND-011 completion, issue #230 completion, or full
G80-G89 pass status.

The FND-012 performance budget cases are also partial fixture evidence only.
They validate a budget/report contract plus negative environment-capture,
provider/model-time-mixing, and skipped-safety-check cases; they do not execute
24/7 soak tests, 1,000-node simulation, GPU/training,
robotics, live fleet, or physical hardware benchmarks, and they must not be
reported as `G29`, `G66`, `G68`, `G74`, issue #231, or issue #180 completion.

## Non-Goals

- No runtime feature additions.
- No full adapter certification business process.
- No vendor-specific runner or dashboard.
- No production secret, network, SaaS, or hardware dependency.
- No complete post-implementation use-case E2E acceptance claim.
- No marketplace, billing, approval UI, or production physical safety claim.
