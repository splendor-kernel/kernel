---
name: ui-accessibility-keyboard
description: "UI Accessibility and Keyboard: Use when you need to ensure UI can be used with keyboard, screen readers, and common accessibility needs."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "04-ui"
  source: "skills/04-ui/ui-accessibility-keyboard.md"
---

# UI Accessibility and Keyboard

## Purpose

Ensure UI can be used with keyboard, screen readers, and common accessibility needs.

## Params

```yaml
  UI_SURFACE: "<value>"
  INTERACTIONS: "<value>"
  A11Y_STANDARD: "<value>"
  TEST_TOOL: "<value>"
```

## Use When

- Interactive UI changes
- Forms
- Dialogs
- Navigation
- PR review

## Inputs

- Rendered UI
- Component code
- Playwright/user-flow access
- Design system

## Procedure

- Check semantic structure: headings, landmarks, labels, buttons, links, form controls.
- Verify keyboard navigation order, focus visibility, and escape/submit behavior.
- Ensure dialogs/menus/popovers manage focus correctly.
- Check accessible names for icon-only controls.
- Check color contrast if colors changed.
- Ensure loading/error states are announced or understandable without visual-only cues.
- Prefer native controls when possible.
- Record manual or automated accessibility checks in QA evidence.

## Outputs

- Accessibility review notes
- Fixes/tests
- QA evidence

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not use divs as buttons when native buttons work
- Do not rely on color alone
- Do not trap focus

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Critical interactions work without mouse
- Controls have clear names
- No obvious accessibility regression remains
