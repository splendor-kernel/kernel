---
name: observability-instrumentation
description: "Observability Instrumentation: Use when you need to add enough logs, metrics, traces, and correlation data for production debugging without noise."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/observability-instrumentation.md"
---

# Observability Instrumentation

## Purpose

Add enough logs, metrics, traces, and correlation data for production debugging without noise.

## Params

```yaml
  WORKFLOW: "<value>"
  LOGGING_POLICY: "<value>"
  METRICS_POLICY: "<value>"
  TRACE_POLICY: "<value>"
```

## Use When

- New service path
- External integration
- Background job
- Failure-prone workflow
- Operational hardening

## Inputs

- Existing logging conventions
- Runtime code
- Error paths
- Config

## Procedure

- Identify operational questions the team must answer: started, succeeded, failed, slow, retried, skipped, unauthorized.
- Use existing logger/telemetry patterns and correlation/request IDs.
- Log at boundaries and important state transitions, not every internal line.
- Ensure logs include stable identifiers and safe error classes, not secrets or raw payloads.
- Add metrics or counters when the repo has a metrics system and the signal is actionable.
- Add tests only when instrumentation affects behavior or has existing test patterns.
- Update runbooks if new operational signals matter.
- Review for noise: remove logs that would create alert fatigue or cognitive load.

## Outputs

- Instrumentation changes
- Operational notes
- Runbook updates if needed

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not log secrets/raw PII
- Do not invent a new telemetry framework
- Do not add vanity metrics

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Production failures are diagnosable
- Logs are safe and not noisy
- Telemetry fits existing patterns
