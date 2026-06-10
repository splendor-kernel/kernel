---
name: operational-readiness
description: "Operational Readiness: Use when you need to check whether a feature/service can run safely outside local development."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "06-maintenance-scaling"
  source: "skills/06-maintenance-scaling/operational-readiness.md"
---

# Operational Readiness

## Purpose

Check whether a feature/service can run safely outside local development.

## Params

```yaml
  SERVICE_NAME: "<value>"
  ENVIRONMENTS: "<value>"
  RUNBOOK_PATH: "<value>"
  ONCALL_NEEDS: "<value>"
```

## Use When

- Before release
- New service integration
- External dependency work
- Background workers

## Inputs

- Config
- Deployment docs
- Logs/metrics
- Failure modes
- Runbooks

## Procedure

- Verify startup/config requirements are documented and validated.
- Check health/readiness behavior when applicable.
- Check logs/metrics/traces for key lifecycle events.
- Check failure handling, retries, timeouts, and disabled states.
- Check migration/deploy ordering and rollback/forward-only notes.
- Document manual recovery steps if production operators may need them.
- Ensure alerts/monitors are proposed only when actionable.
- Create issues for missing operational pieces that block release.

## Outputs

- Operational readiness notes
- Runbook updates
- Blocking issues

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not add noisy alerts
- Do not assume local defaults are production-safe
- Do not ship without runbook for complex services

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Service is operable or blocked explicitly
- Setup and failure recovery are understandable
- No surprise production dependency remains
