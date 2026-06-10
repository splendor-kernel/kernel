---
name: capacity-and-cost-review
description: "Capacity and Cost Review: Use when you need to spot capacity, cost, and resource risks before they become production surprises."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "06-maintenance-scaling"
  source: "skills/06-maintenance-scaling/capacity-and-cost-review.md"
---

# Capacity and Cost Review

## Purpose

Spot capacity, cost, and resource risks before they become production surprises.

## Params

```yaml
  WORKLOAD: "<value>"
  RESOURCE_TYPES: "<value>"
  TRAFFIC_ASSUMPTIONS: "<value>"
  COST_SENSITIVITY: "<value>"
```

## Use When

- New background processing
- External API usage
- Storage-heavy features
- Scaling work

## Inputs

- Code paths
- External service calls
- DB/storage usage
- Config
- Telemetry

## Procedure

- Identify resource drivers: CPU, memory, DB queries, storage, network, third-party API calls, queue throughput.
- Estimate rough upper bounds from page size, batch size, polling interval, retry policy, and data retention.
- Look for unbounded loops, polling, fan-out, large payload retention, and expensive synchronous calls.
- Add limits, pagination, backpressure, retention, or batching when obvious and simple.
- Prefer measurement/telemetry when risk is uncertain.
- Document cost-sensitive dependencies and expected knobs.
- Create issues for future scale work with clear trigger conditions.
- Do not overbuild distributed systems without current evidence.

## Outputs

- Capacity risk notes
- Targeted safeguards
- Scale trigger issues

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not guess precise costs without data
- Do not ignore unbounded retry/polling
- Do not optimize away correctness

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Obvious runaway costs are prevented
- Resource limits are explicit
- Future scaling work has triggers
