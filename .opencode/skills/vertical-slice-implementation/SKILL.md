---
name: vertical-slice-implementation
description: "Vertical Slice Implementation: Use when you need to implement a bounded feature or migration through the real production path from entry point to tests."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "03-implementation"
  source: "skills/03-implementation/vertical-slice-implementation.md"
---

# Vertical Slice Implementation

## Purpose

Implement a bounded feature or migration through the real production path from entry point to tests.

## Params

```yaml
  OBJECTIVE: "<value>"
  ENTRYPOINT: "<value>"
  OWNER_LAYER: "<value>"
  RELEVANT_SERVICES: "<value>"
  VALIDATION_COMMANDS: "<value>"
```

## Use When

- Feature work
- Service wiring
- Architecture migration
- Bug fix with integration impact

## Inputs

- Issue
- Existing code patterns
- Architecture rules
- Tests
- Service inventory

## Procedure

- Start from the user/API/runtime behavior, not from a folder move.
- Identify entry point, use case/service, persistence/external dependencies, config, contracts, and tests touched.
- Keep the slice small enough to review in one PR.
- Reuse existing patterns before introducing new structure.
- Wire production dependencies explicitly through the established composition mechanism.
- Add tests at the lowest useful level plus one integration path when behavior crosses boundaries.
- Update docs/contracts/config/migrations when the slice changes them.
- Record validation and remaining risk in the PR.

## Outputs

- Production code change
- Tests
- Wiring/config updates
- PR evidence

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not build isolated components
- Do not add generic abstractions first
- Do not defer integration without an issue

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Behavior works through real entry point
- Diff is bounded
- No hidden service gap remains
