---
name: failure-path-qa
description: "Failure Path QA: Use when you need to test important unhappy paths so production behavior is predictable."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "05-qa-release"
  source: "skills/05-qa-release/failure-path-qa.md"
---

# Failure Path QA

## Purpose

Test important unhappy paths so production behavior is predictable.

## Params

```yaml
  WORKFLOW: "<value>"
  FAILURE_MODES: "<value>"
  EXPECTED_ERRORS: "<value>"
  RECOVERY_ACTIONS: "<value>"
```

## Use When

- API changes
- UI forms
- Service integration
- External dependencies
- Before release

## Inputs

- Error contracts
- Tests
- Mocks/fakes at test boundary
- User/API entry point

## Procedure

- List realistic failure modes: invalid input, unauthorized, forbidden, not found, conflict, dependency failure, timeout, bad response, duplicate action.
- Prioritize failures with user impact, data risk, or operational risk.
- Exercise failure through the closest realistic boundary.
- Verify status codes/error classes/messages are appropriate and safe.
- Verify UI/API callers can recover or understand next action.
- Verify logs/telemetry help debug without leaking sensitive data.
- Add regression tests for important failures.
- Record untested failure modes and risk.

## Outputs

- Failure-path tests/evidence
- Error behavior notes
- Risk list

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not test only happy path
- Do not swallow errors
- Do not overfit tests to exact copy unless copy is contract

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Critical failures behave intentionally
- Users/callers are not surprised
- Unsafe raw errors are not exposed
