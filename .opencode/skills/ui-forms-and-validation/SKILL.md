---
name: ui-forms-and-validation
description: "UI Forms and Validation: Use when you need to build forms that are clear, forgiving, accessible, and aligned with backend validation."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "04-ui"
  source: "skills/04-ui/ui-forms-and-validation.md"
---

# UI Forms and Validation

## Purpose

Build forms that are clear, forgiving, accessible, and aligned with backend validation.

## Params

```yaml
  FORM_NAME: "<value>"
  FIELDS: "<value>"
  SUBMIT_ACTION: "<value>"
  SERVER_CONTRACT: "<value>"
```

## Use When

- New forms
- Validation changes
- API integration
- User-flow QA

## Inputs

- Form component
- API schema
- Error contracts
- Design system

## Procedure

- Keep fields minimal for the user task.
- Use clear labels, helper text only where needed, and sensible defaults.
- Validate client-side for immediate obvious issues, but trust server validation as source of truth.
- Map server errors to specific fields when possible and to a calm form-level error otherwise.
- Prevent duplicate unsafe submissions through idempotency/server guard, not only button disabled state.
- Preserve user input after validation errors.
- Support keyboard submission and accessible error announcements.
- Test valid submit, invalid client input, server validation failure, and network/server failure.

## Outputs

- Form implementation/review
- Validation tests
- Error mapping evidence

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not duplicate complex backend rules blindly
- Do not clear user input after error
- Do not rely only on UI to prevent duplicates

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Form is easy to complete
- Errors are actionable
- Backend and frontend validation agree
