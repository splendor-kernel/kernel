---
name: refactor-safety
description: "Refactor Safety: Use when you need to change structure while preserving behavior and keeping the diff reviewable."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/refactor-safety.md"
---

# Refactor Safety

## Purpose

Change structure while preserving behavior and keeping the diff reviewable.

## Params

```yaml
  TARGET_AREA: "<value>"
  BEHAVIOR_TESTS: "<value>"
  MIGRATION_STYLE: "<value>"
  RISK_LEVEL: "<value>"
```

## Use When

- Moving code
- Splitting files
- Renaming APIs
- Cleaning debt
- Preparing architecture migration

## Inputs

- Current tests
- Callers
- Public API
- Docs
- Typecheck/lint

## Procedure

- Establish baseline validation before refactor when possible.
- Separate pure move/rename from behavior change unless the diff is tiny.
- Keep public API stable or document intentional change.
- Update imports mechanically and avoid unrelated formatting churn.
- Add characterization tests when behavior is important and poorly covered.
- Run targeted tests after each meaningful step.
- Update docs/trackers only after the refactor state is real.
- Leave remaining debt tracked rather than half-refactored.

## Outputs

- Reviewable refactor diff
- Tests/validation
- Updated trackers

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not mix broad refactor and feature work unnecessarily
- Do not delete tests for convenience
- Do not move code into wrong layer

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Behavior is preserved
- Diff is easy to review
- No hidden behavior change occurs
