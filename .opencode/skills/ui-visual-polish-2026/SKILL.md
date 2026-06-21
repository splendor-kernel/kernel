---
name: ui-visual-polish-2026
description: "UI Visual Polish 2026+: Use when you need to apply a modern, restrained visual quality bar without adding noise."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "04-ui"
  source: "skills/04-ui/ui-visual-polish-2026.md"
---

# UI Visual Polish 2026+

## Purpose

Apply a modern, restrained visual quality bar without adding noise.

## Params

```yaml
  UI_SURFACE: "<value>"
  BRAND_TOKENS: "<value>"
  DENSITY_TARGET: "<value>"
  PLATFORM: "<value>"
```

## Use When

- Final UI review
- New screens
- Design-system cleanup
- Before user QA

## Inputs

- Rendered UI
- CSS/tokens
- Existing design system
- Screenshots

## Procedure

- Use spacing, typography, and alignment to create hierarchy before adding decorative elements.
- Prefer generous breathing room where it improves comprehension, but keep operational UIs efficient.
- Use subtle borders/shadows/backgrounds only to clarify grouping.
- Keep motion minimal, fast, and purposeful.
- Avoid gradients, glass effects, dense cards, decorative icons, and chart chrome unless the product language already uses them well.
- Check responsive behavior at common widths.
- Check visual consistency with existing components and tokens.
- Review whether the UI feels calm, precise, and production-grade.

## Outputs

- Visual review notes
- Small polish fixes
- Responsive checks

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not redesign the whole app during a feature PR
- Do not introduce one-off styles without need
- Do not prioritize screenshots over usability

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- UI feels high quality and simple
- Hierarchy is clear
- No gratuitous visual complexity remains
