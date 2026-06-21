---
name: ui-user-flow-qa-playwright
description: "UI User Flow QA with Playwright: Use when you need to validate user-facing changes like a normal user using Playwright MCP or equivalent browser automation."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "04-ui"
  source: "skills/04-ui/ui-user-flow-qa-playwright.md"
---

# UI User Flow QA with Playwright

## Purpose

Validate user-facing changes like a normal user using Playwright MCP or equivalent browser automation.

## Params

```yaml
  APP_URL: "<value>"
  FLOWS: "<value>"
  AUTH_REQUIRED: "<value>"
  TEST_DATA: "<value>"
  BROWSERS: "<value>"
```

## Use When

- UI changes
- Navigation changes
- Forms
- User-facing error states
- Before final PR

## Inputs

- Running app
- Test credentials/data when available
- Acceptance criteria
- UI routes

## Procedure

- Start from the user goal, not the implementation detail.
- Open the app and navigate through the flow as a real user.
- Validate primary success path.
- Validate at least one failure, empty, or permission path when relevant.
- Check loading behavior, copy clarity, focus behavior, and post-refresh persistence.
- Capture steps, observed result, screenshots/traces if useful, and bugs found.
- Create/update issues for unfixed bugs.
- Record what could not be validated and why.

## Outputs

- User-flow QA evidence
- Bug issues/fixes
- Final PR QA notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not rely only on component tests
- Do not skip auth/permission states if affected
- Do not hide visual/user confusion as “works”

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Changed UI behavior is realistically validated
- Failure paths are not ignored
- Evidence is in the PR/report
