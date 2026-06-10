---
name: mock-boundary-qa
description: "Mock Boundary QA: Use when you need to ensure tests use mocks appropriately and do not hide missing production behavior."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "05-qa-release"
  source: "skills/05-qa-release/mock-boundary-qa.md"
---

# Mock Boundary QA

## Purpose

Ensure tests use mocks appropriately and do not hide missing production behavior.

## Params

```yaml
  TEST_FILES: "<value>"
  PRODUCTION_PATHS: "<value>"
  SERVICE_NAME: "<value>"
  BOUNDARY_RULES: "<value>"
```

## Use When

- Reviewing tests
- Service wiring work
- Integration PRs
- Before issue closure

## Inputs

- Tests
- Production composition
- Service inventory
- Adapters

## Procedure

- Identify every mock/fake/stub/in-memory implementation introduced or touched.
- Determine whether each mock is at unit, application, adapter, UI, or e2e boundary.
- Check whether a real implementation exists and is used in production composition.
- Require at least one integration validation when production wiring is the issue.
- Reject tests that mock the exact behavior under test.
- Ensure testkits are not exported or imported by production code.
- Document accepted mocks and why they are appropriate.
- Create a production wiring issue for mock-only functionality.

## Outputs

- Mock boundary report
- Test fixes
- Integration gap issues

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not ban all mocks
- Do not accept tests that prove only the mock
- Do not let testkit leak into production

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Mocks support tests without replacing production
- Mock-only gaps are visible
- Test confidence improves
