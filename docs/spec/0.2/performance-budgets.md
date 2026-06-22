# FND-012 Performance Budget Contract (partial)

Status: partial FND-012 contract evidence for issue #231 / aggregate #180.

This document describes the machine-readable fixture in
[`performance-budgets.json`](performance-budgets.json). The fixture defines
latency, throughput/scale, regression-threshold, environment-capture, and
retention/backpressure requirements that future benchmark reports must satisfy.

## What this slice proves

- The required FND-012 metrics have explicit budget records:
  - local event append;
  - state commit;
  - authority decision;
  - gateway preflight;
  - model invocation overhead;
  - percept routing;
  - tick admission;
  - event ingestion;
  - artifact transfer;
  - scheduler offers;
  - workload transitions;
  - feedback ingestion;
  - eval fan-out;
  - 1,000-node simulation.
- Kernel control-plane overhead is separated from provider/model/training time.
- Regression thresholds are required for every mandatory metric.
- Benchmark environment capture is required before a report can validate.
- Retention and backpressure actions are required for long-run storage, payload,
  inbox, and inference-capacity pressure.
- G29, G66, G68, and G74 each map to SLO/resource budget records.

## Non-claims

This is not a benchmark result and not a task-completion claim.

- No FND-012 completion is claimed.
- No issue #231 or #180 completion is claimed.
- No G29, G66, G68, or G74 pass is claimed; all remain `not_exercised` until an
  exact executable gold/benchmark harness runs and passes.
- No 24/7 soak, 1,000-node fleet simulation, GPU/training, robotics, live fleet,
  or physical hardware benchmark was executed.
- No single hardware result is published as a universal performance guarantee.

## Validation path

The `performance_budgets` conformance primitive validates this fixture from
`conformance/0.1/run-conformance.py`. It rejects missing mandatory metrics,
missing environment capture, provider/model time mixed into kernel overhead,
missing regression thresholds, and missing retention/backpressure actions.

The Rust `splendor-types` module exposes behavior-light types and validation for
the same contract. These types do not execute benchmarks and do not authorize
work, side effects, gold status changes, or release gates by themselves.
