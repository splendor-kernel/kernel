---
name: ui-information-architecture
description: "UI Information Architecture: Use when you need to organize page structure so users can understand where they are, what matters, and what to do next."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "04-ui"
  source: "skills/04-ui/ui-information-architecture.md"
---

# UI Information Architecture

## Purpose

Organize page structure so users can understand where they are, what matters, and what to do next.

## Params

```yaml
  ROUTE: "<value>"
  USER_TASKS: "<value>"
  NAV_MODEL: "<value>"
  CONTENT_TYPES: "<value>"
```

## Use When

- New page/screen
- Navigation changes
- Complex settings/admin workflows
- Dashboard cleanup

## Inputs

- Route tree
- Existing nav
- User stories/issues
- UI components

## Procedure

- Define the page promise in one sentence.
- Identify primary, secondary, and tertiary information.
- Place primary action and status near the top without crowding.
- Group related fields/actions by user mental model, not backend model.
- Prefer simple sections over tabs unless tabs reduce real complexity.
- Use breadcrumbs/nav only when orientation is otherwise unclear.
- Make empty and error states explain what the user can do next.
- Remove duplicate labels and repeated metadata that add noise.

## Outputs

- Page structure proposal
- Navigation/content changes
- Review checklist

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not mirror database tables directly
- Do not create nav for features not ready
- Do not bury critical status below decorative content

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Users can orient quickly
- Primary action is clear
- Information density matches task complexity
