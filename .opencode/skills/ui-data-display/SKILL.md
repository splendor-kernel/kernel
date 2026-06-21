---
name: ui-data-display
description: "UI Data Display: Use when you need to present data clearly without premature dashboards, dense visuals, or cognitive overload."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "04-ui"
  source: "skills/04-ui/ui-data-display.md"
---

# UI Data Display

## Purpose

Present data clearly without premature dashboards, dense visuals, or cognitive overload.

## Params

```yaml
  DATA_TYPE: "<value>"
  USER_DECISION: "<value>"
  VOLUME: "<value>"
  REFRESH_MODEL: "<value>"
```

## Use When

- Tables/lists/cards
- Metrics UI
- Admin screens
- Dashboard proposals

## Inputs

- User task
- Data model
- Existing components
- Performance assumptions

## Procedure

- Identify what decision or action the data supports.
- Choose the simplest display that supports that decision: text, status, list, table, chart, or detail view.
- Use charts only when visual comparison/trend matters now.
- Limit columns to what users need for the immediate task.
- Use progressive disclosure for secondary metadata.
- Add pagination, search, or filters only when data volume or user task requires them.
- Show timestamps/status consistently and human-readably.
- Validate empty, loading, large, and error states.

## Outputs

- Data display decision
- UI implementation/review
- Complexity deferral notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not make dashboards by default
- Do not expose every backend field
- Do not use tables for everything

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Users can understand data quickly
- Visual complexity is justified
- Large data does not overwhelm UI
