---
name: incident-regression-learning
description: "Incident and Regression Learning: Use when you need to turn bugs, incidents, and regressions into durable tests, checks, and docs."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "06-maintenance-scaling"
  source: "skills/06-maintenance-scaling/incident-regression-learning.md"
---

# Incident and Regression Learning

## Purpose

Turn bugs, incidents, and regressions into durable tests, checks, and docs.

## Params

```yaml
  INCIDENT_OR_BUG: "<value>"
  AFFECTED_AREAS: "<value>"
  ROOT_CAUSE_CONFIDENCE: "<value>"
  FOLLOWUP_POLICY: "<value>"
```

## Use When

- After bug fix
- After flaky CI/root cause
- After production incident
- Regression PR

## Inputs

- Bug report
- Logs
- Tests
- Code diff
- Issue/PR history

## Procedure

- State the observed failure and user/system impact.
- Identify root cause with confidence level and evidence.
- Add a regression test at the lowest useful boundary and an integration/user-flow test when needed.
- Add architecture/security/release guard if the issue class is likely to recur.
- Update docs/runbooks if operators or future agents need to know.
- Create follow-up issues for broader hardening that is out of scope.
- Record what was not proven.
- Close the incident/bug issue only after validation and merge evidence.

## Outputs

- Regression test/check
- Root cause note
- Follow-up issues/docs

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not overstate root cause
- Do not fix symptom only when cause is known
- Do not skip regression tests for important bugs

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- The exact class of failure is harder to repeat
- Uncertainty is explicit
- Learning persists beyond chat
