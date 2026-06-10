---
name: ui-component-quality
description: "UI Component Quality: Use when you need to create maintainable UI components that are simple, accessible, and aligned with the design system."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "04-ui"
  source: "skills/04-ui/ui-component-quality.md"
---

# UI Component Quality

## Purpose

Create maintainable UI components that are simple, accessible, and aligned with the design system.

## Params

```yaml
  COMPONENT_NAME: "<value>"
  OWNER_PACKAGE: "<value>"
  USAGE_SITES: "<value>"
  DESIGN_SYSTEM_POLICY: "<value>"
```

## Use When

- New component
- Component refactor
- UI package cleanup
- PR review

## Inputs

- Existing components
- Design tokens
- Usage sites
- Tests/stories if present

## Procedure

- Check whether an existing component already solves the need.
- Keep component API small and task-oriented.
- Use semantic HTML and accessible names by default.
- Prefer composition over large variant matrices.
- Separate data fetching/business logic from presentational components unless project convention differs.
- Avoid premature generality: add variants only when two real usage sites need them.
- Document non-obvious behavior through tests/examples, not long comments.
- Remove duplicated local components when ownership is clear and migration is safe.

## Outputs

- Component implementation/review
- Usage updates
- Tests/examples if relevant

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not create design-system components for one-off needs too early
- Do not duplicate UI packages silently
- Do not make components depend on backend business rules

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Component is reusable where it should be
- API is not overbuilt
- Accessibility is built in
