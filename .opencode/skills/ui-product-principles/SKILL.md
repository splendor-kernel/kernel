---
name: ui-product-principles
description: "UI Product Principles: Use when you need to keep user-facing UI minimal, clear, high-quality, and low cognitive load."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "04-ui"
  source: "skills/04-ui/ui-product-principles.md"
---

# UI Product Principles

## Purpose

Keep user-facing UI minimal, clear, high-quality, and low cognitive load.

## Params

```yaml
  PRODUCT_CONTEXT: "<value>"
  PRIMARY_USER_TASK: "<value>"
  UI_SURFACE: "<value>"
  RISK_LEVEL: "<value>"
```

## Use When

- Any user-facing change
- Design review
- Feature scope planning
- UI PR review

## Inputs

- Issue/user goal
- Existing UI patterns
- Screenshots or app route
- Component code

## Procedure

- Identify the primary user task and the one outcome the screen must support.
- Remove or defer UI that does not help that task now.
- Prefer calm hierarchy, direct language, strong defaults, and progressive disclosure.
- Use fewer visual groups and fewer competing call-to-actions.
- Do not add charts, dashboards, filters, side panels, animations, or dense tables unless they solve a current user problem.
- Keep copy short, concrete, and action-oriented.
- Preserve accessibility and keyboard use as part of quality, not as polish.
- Validate with a realistic user flow rather than static screenshots only.

## Outputs

- UI scope decision
- Design review notes
- Deferred complexity list

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not build impressive but unused presentations
- Do not hide critical actions behind mystery icons
- Do not optimize for stakeholder spectacle over user comprehension

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- The screen is easier to understand
- The primary task is obvious
- Nonessential complexity is removed or deferred
