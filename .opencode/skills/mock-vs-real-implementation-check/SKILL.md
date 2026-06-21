---
name: mock-vs-real-implementation-check
description: "Mock vs Real Implementation Check: Use when you need to ensure mocks/fakes do not replace required production integration."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "02-service-integration"
  source: "skills/02-service-integration/mock-vs-real-implementation-check.md"
---

# Mock vs Real Implementation Check

## Purpose

Ensure mocks/fakes do not replace required production integration.

## Params

```yaml
  SERVICE_NAME: "<value>"
  TEST_ROOTS: "<value>"
  PRODUCTION_ROOTS: "<value>"
  COMPOSITION_ROOTS: "<value>"
```

## Use When

- Reviewing service PRs
- Investigating mock-only behavior
- QA gate for integration changes

## Inputs

- Tests
- Production wiring
- Adapters
- Composition root
- Config

## Procedure

- List all mock, fake, in-memory, testkit, stub, and fixture implementations.
- Find where each is imported and whether any production path imports it.
- Check whether a real adapter exists and whether it is wired.
- Verify tests that use mocks are at appropriate boundaries.
- Flag production code that depends on fake implementations.
- Flag features whose only working path is a mock/testkit.
- For mock-only production gaps, create P0/P1 issue or wire real adapter if bounded.
- Document accepted test-only mocks and ensure they are not exported as production services.

## Outputs

- Mock boundary report
- Production gap issue/fix
- Accepted mock list

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not remove useful testkits
- Do not call a service complete if only mocks work
- Do not hide missing external dependency

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Mocks are isolated to valid test boundaries
- Production path uses real implementation or is explicitly blocked
- No fake completeness remains
