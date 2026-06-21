---
name: splendor-boundary-check
description: "Splendor Boundary Check: Use when you need to ensure Harmony/Splendor responsibilities are not bypassed when Splendor is the intended kernel boundary."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "02-service-integration"
  source: "skills/02-service-integration/splendor-boundary-check.md"
---

# Splendor Boundary Check

## Purpose

Ensure Harmony/Splendor responsibilities are not bypassed when Splendor is the intended kernel boundary.

## Params

```yaml
  SPLENDOR_ROOT: "<value>"
  HARMONY_ROOT: "<value>"
  CHECK_PATHS: "<value>"
  SPLENDOR_PACKAGE_REF: "<value>"
```

## Use When

- Agent/inference/actuator/policy paths
- Service integration audits
- PRs touching Splendor adapters

## Inputs

- Harmony code
- Splendor docs/source if available
- Config
- Tests
- Adapters

## Procedure

- Read local Splendor docs/source when available.
- Search for agent actuators, percepts, inference, LLM, LLM API, neural net, AI policy, HIL, and modelation paths.
- Verify whether the path passes through Splendor Kernel or a Splendor adapter when required.
- Check whether Harmony reimplements Splendor-owned behavior.
- Check whether tests use mocks in a way that hides missing Splendor production wiring.
- Classify findings as valid integration, bypass, purposeful-but-blocked, or needs-investigation.
- Create/fix P0/P1 issues for production bypasses.
- Do not delete Harmony services that appear unused until Splendor integration references are checked.

## Outputs

- Boundary report
- Bypass issues/fixes
- Inventory updates

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not mock around Splendor production responsibilities
- Do not assume local Splendor source exists
- Do not confuse test adapter with production adapter

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Splendor-owned responsibilities are not silently duplicated
- Bypasses are fixed or tracked
- Mock shortcuts are visible
