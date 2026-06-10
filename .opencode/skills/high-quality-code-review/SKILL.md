---
name: high-quality-code-review
description: "High-Quality Code Review: Use when you need to apply a practical quality bar for code that must evolve under production pressure."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/high-quality-code-review.md"
---

# High-Quality Code Review

## Purpose

Apply a practical quality bar for code that must evolve under production pressure.

## Params

```yaml
  TARGET_FILES: "<value>"
  RISK_LEVEL: "<value>"
  PROJECT_CONVENTIONS: "<value>"
  TEST_SCOPE: "<value>"
```

## Use When

- PR review
- Self-review before commit
- Refactor planning
- Maintenance work

## Inputs

- Diff
- Existing patterns
- Tests
- Issue criteria

## Procedure

- Check naming: domain terms are clear, not clever or over-general.
- Check function/module size: one reason to change, but no micro-file explosion.
- Check data flow: explicit inputs/outputs, minimal hidden global state.
- Check errors: typed/structured where project conventions support them.
- Check tests: meaningful behavior, not implementation snapshots only.
- Check dependency direction and ownership.
- Check readability for the next maintainer: simple control flow, no surprise side effects.
- Remove dead branches, placeholders, and speculative extensibility.

## Outputs

- Review comments
- Refactor requests
- Quality approval

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not demand aesthetic churn
- Do not reward over-engineering
- Do not accept clever code without need

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Code is understandable and changeable
- Complexity is justified
- Tests protect behavior
