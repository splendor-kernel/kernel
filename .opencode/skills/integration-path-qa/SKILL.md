---
name: integration-path-qa
description: "Integration Path QA: Use when you need to verify behavior through real production wiring across boundaries."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "05-qa-release"
  source: "skills/05-qa-release/integration-path-qa.md"
---

# Integration Path QA

## Purpose

Verify behavior through real production wiring across boundaries.

## Params

```yaml
  WORKFLOW: "<value>"
  ENTRYPOINT: "<value>"
  SERVICES: "<value>"
  CONFIG: "<value>"
  DATA_SETUP: "<value>"
```

## Use When

- Service wiring changes
- Feature integration
- Clean arch migrations
- Before issue closure

## Inputs

- Entry point
- Composition root
- Config
- Database/test data
- Tests

## Procedure

- Identify the real entry point users, API clients, workers, or CLIs use.
- Trace the call path through route/UI, application, infrastructure, and external/data services.
- Confirm production composition uses real implementations, not tests/fakes.
- Set up realistic data/config for the path.
- Run an integration test, manual flow, or targeted script that exercises the path.
- Validate both expected success and at least one realistic failure mode.
- Record evidence and missing coverage.
- Create issues for integration gaps that cannot be fixed in scope.

## Outputs

- Integration QA evidence
- Gap issues
- Validation notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not equate unit tests with integration
- Do not bypass composition root for validation
- Do not ignore config-disabled paths

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- The real path works or gap is explicit
- Mocks are not mistaken for integration
- Issue closure is justified
