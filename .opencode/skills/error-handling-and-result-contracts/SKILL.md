---
name: error-handling-and-result-contracts
description: "Error Handling and Result Contracts: Use when you need to make failure behavior explicit, structured, testable, and user/API appropriate."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/error-handling-and-result-contracts.md"
---

# Error Handling and Result Contracts

## Purpose

Make failure behavior explicit, structured, testable, and user/API appropriate.

## Params

```yaml
  BOUNDARY: "<value>"
  ERROR_TYPES: "<value>"
  CALLERS: "<value>"
  OBSERVABILITY_POLICY: "<value>"
```

## Use When

- API failure fixes
- Service integration
- Input validation
- External client adapters

## Inputs

- Current error paths
- Tests
- API contracts
- Logs/telemetry conventions

## Procedure

- Map expected failure classes: validation, auth, not found, conflict, external dependency, timeout, internal bug.
- Check whether current code throws raw errors across boundaries.
- Convert boundary errors into structured project-standard errors/responses.
- Preserve internal detail for logs while returning safe messages to callers/users.
- Add tests for malformed input, missing resources, dependency failure, and unexpected exceptions where relevant.
- Ensure retries/fallbacks do not hide permanent failures.
- Ensure UI/API displays actionable but not noisy error states.
- Update contracts/docs when public error shape changes.

## Outputs

- Structured errors
- Failure tests
- Docs/contracts update if needed

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not swallow errors silently
- Do not leak stack traces/secrets
- Do not convert all errors to generic 500s

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Failure behavior is predictable
- Sensitive details are not leaked
- Users/callers get useful outcomes
