---
name: runtime-health-observability
description: "Runtime Health and Observability: Use when you need to verify that running systems expose enough health and telemetry for maintenance and scaling."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "06-maintenance-scaling"
  source: "skills/06-maintenance-scaling/runtime-health-observability.md"
---

# Runtime Health and Observability

## Purpose

Verify that running systems expose enough health and telemetry for maintenance and scaling.

## Params

```yaml
  SYSTEM_COMPONENT: "<value>"
  HEALTH_ENDPOINTS: "<value>"
  METRIC_NAMES: "<value>"
  LOGGING_POLICY: "<value>"
```

## Use When

- Service launch
- Scaling review
- Incident follow-up
- Worker/job changes

## Inputs

- Health checks
- Telemetry code
- Runbooks
- Deployment config

## Procedure

- Identify what healthy means for the component: process up, DB reachable, queue connected, dependency optional/required, worker draining.
- Check readiness versus liveness semantics when applicable.
- Verify health checks do not perform destructive or expensive work.
- Verify telemetry covers throughput, failures, latency, retries, queue lag, and saturation when relevant.
- Ensure logs include correlation IDs and safe identifiers.
- Update runbooks with how to inspect health and common failure causes.
- Do not invent observability systems; use existing project conventions.
- Record missing signals as issues when they matter.

## Outputs

- Health/observability review
- Instrumentation/runbook updates
- Issue list

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not make health checks depend on optional services unless intentional
- Do not log raw payloads
- Do not add unbounded high-cardinality metrics

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Operators can assess component health
- Signals are actionable
- Telemetry does not leak sensitive data
