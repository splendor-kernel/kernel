---
name: service-production-wiring-check
description: "Service Production Wiring Check: Use when you need to determine whether a purposeful service is actually used by production entry points."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "02-service-integration"
  source: "skills/02-service-integration/service-production-wiring-check.md"
---

# Service Production Wiring Check

## Purpose

Determine whether a purposeful service is actually used by production entry points.

## Params

```yaml
  SERVICE_NAME: "<value>"
  SERVICE_PATH: "<value>"
  ENTRYPOINTS: "<value>"
  COMPOSITION_ROOTS: "<value>"
  CONFIG_ROOTS: "<value>"
```

## Use When

- Service seems unused
- PR claims service is wired
- Before classifying integrated-live
- After implementation of new service

## Inputs

- Service source
- Routes
- Composition roots
- DI config
- Workers/jobs
- CLI
- SDK/web entry points
- Config/env

## Procedure

- Trace static imports and re-exports.
- Search dynamic imports and string-based references.
- Inspect route registration, API module setup, worker/job/scheduler registration, CLI entry points, SDK exports, web entry points, and composition roots.
- Check config/env feature flags that enable or disable the service.
- Check migrations/seeds/contracts that imply runtime use.
- Verify whether tests exercise production wiring or only instantiate the service directly.
- Classify actual wiring as live, behind feature flag, mock-only, test-only, scaffold-only, not wired, or blocked.
- Record exact evidence paths and missing links.

## Outputs

- Wiring classification
- Evidence map
- Issue/fix recommendation

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not count direct unit tests as production wiring
- Do not miss feature flags
- Do not ignore composition root absence

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- The service’s runtime status is clear
- Production use is not confused with test use
- Missing wiring is tracked or fixed
