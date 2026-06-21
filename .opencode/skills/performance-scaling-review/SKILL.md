---
name: performance-scaling-review
description: "Performance and Scaling Review: Use when you need to identify scaling risks early without premature optimization."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/performance-scaling-review.md"
---

# Performance and Scaling Review

## Purpose

Identify scaling risks early without premature optimization.

## Params

```yaml
  HOT_PATHS: "<value>"
  DATA_VOLUME_ASSUMPTIONS: "<value>"
  LATENCY_BUDGET: "<value>"
  MEASUREMENT_COMMANDS: "<value>"
```

## Use When

- Large data flows
- New queries
- UI lists/tables
- Background processing
- Before release

## Inputs

- Code paths
- Queries
- Tests/benchmarks
- Logs
- User flows

## Procedure

- Identify expected data volume, request rate, and latency expectations from docs/issues or conservative assumptions.
- Look for obvious N+1 queries, unbounded scans, synchronous heavy work, large payloads, and client-side overfetching.
- Prefer simple limits, pagination, batching, streaming, caching, or backgrounding when evidence supports it.
- Measure when practical; do not guess performance wins.
- Add guards such as max page size, timeouts, and payload limits where needed.
- Ensure UI does not render huge data sets or complex visuals prematurely.
- Record accepted risks and future scale triggers.
- Do not introduce complex caching/distributed systems without a current need.

## Outputs

- Scaling risk notes
- Targeted fixes
- Performance validation if available

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not prematurely over-engineer
- Do not ignore unbounded queries
- Do not use cache to hide correctness problems

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Obvious scale traps are addressed
- Optimizations are justified
- Future scale triggers are documented
