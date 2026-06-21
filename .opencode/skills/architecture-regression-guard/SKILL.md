---
name: architecture-regression-guard
description: "Architecture Regression Guard: Use when you need to add or improve checks that prevent a fixed architecture violation from returning."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "01-architecture"
  source: "skills/01-architecture/architecture-regression-guard.md"
---

# Architecture Regression Guard

## Purpose

Add or improve checks that prevent a fixed architecture violation from returning.

## Params

```yaml
  VIOLATION_TYPE: "<value>"
  CHECK_LOCATION: "<value>"
  ALLOWLIST_POLICY: "<value>"
  FAILURE_MESSAGE: "<value>"
```

## Use When

- After fixing repeated drift
- When manual review keeps catching same issue
- Before closing architecture issue

## Inputs

- Fixed violation evidence
- Existing check scripts
- CI workflow

## Procedure

- Identify whether an automated guard is justified by recurrence or risk.
- Prefer extending existing architecture scripts over adding new one-off tooling.
- Write checks that report exact file/import/symbol and actionable failure message.
- Support explicit allowlists only when they are narrow, documented, and reviewed.
- Add fixture tests for the guard if the repo has checker tests.
- Wire the check into existing validation/CI when appropriate.
- Document how to update the allowlist and when removal is expected.
- Do not create brittle text checks when AST/import parsing is available and practical.

## Outputs

- Updated checker
- CI/script integration
- Docs or test fixture

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not block valid transitional seams without allowlist
- Do not create slow checks for every build
- Do not silently skip files

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- The fixed violation is guarded
- False positives are manageable
- Failure message is actionable
