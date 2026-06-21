---
name: ui-loading-empty-error-states
description: "UI Loading, Empty, and Error States: Use when you need to make non-happy-path UI states calm, useful, and production-ready."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "04-ui"
  source: "skills/04-ui/ui-loading-empty-error-states.md"
---

# UI Loading, Empty, and Error States

## Purpose

Make non-happy-path UI states calm, useful, and production-ready.

## Params

```yaml
  UI_SURFACE: "<value>"
  DATA_SOURCE: "<value>"
  FAILURE_MODES: "<value>"
  RECOVERY_ACTIONS: "<value>"
```

## Use When

- Data-driven UI
- Async actions
- New pages
- User-flow QA

## Inputs

- Component code
- API errors
- User flow
- Design patterns

## Procedure

- List expected states: initial, loading, empty, populated, partial, error, unauthorized, disabled, stale.
- Use skeletons/spinners only where they reduce uncertainty; avoid visual noise.
- Empty states should explain what happened and the next useful action.
- Error states should be specific enough to act on without exposing internals.
- Disable actions only with clear reason and recovery path.
- Preserve layout stability to avoid jarring shifts.
- Test at least one success and one failure/empty state for changed flows.
- Ensure retries or refresh actions are safe and not misleading.

## Outputs

- State handling implementation/review
- Failure-path tests
- QA notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not show raw error dumps
- Do not use endless spinners
- Do not hide disabled-action reasons

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Users understand what is happening
- Failures are recoverable when possible
- No blank or misleading screens remain
