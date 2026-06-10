---
name: loop-planning
description: "Loop Planning: Use when you need to convert issues or findings into a bounded, sequenced, low-surprise execution plan."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "00-foundation"
  source: "skills/00-foundation/loop-planning.md"
---

# Loop Planning

## Purpose

Convert issues or findings into a bounded, sequenced, low-surprise execution plan.

## Params

```yaml
  WORKSTREAM: "<value>"
  ISSUES: "<value>"
  RUN_MODE: "<value>"
  MAX_PARALLEL_AGENTS: "<value>"
  RISK_TOLERANCE: "<value>"
```

## Use When

- After triage
- Before sub-agent assignment
- When scope changes
- When blockers appear

## Inputs

- Selected issues
- Acceptance criteria
- Dependency graph
- Current architecture state
- Known risks

## Procedure

- Clarify the loop objective in one paragraph.
- Split work into tasks that each produce a reviewable, testable diff.
- Mark tasks as parallel, sequential, blocked, discovery-only, or human-sync needed.
- Prefer vertical slices that wire production paths over horizontal scaffolding.
- Put P0 and bounded P1 work before cosmetic or theoretical cleanup.
- For each task, define branch, files, expected outputs, validation, forbidden shortcuts, and done criteria.
- Record dependencies between tasks and what must be revalidated after each merge.
- Update the loop tracker and state capsule before assigning work.

## Outputs

- Loop plan
- Assignment board
- Task dependency map
- Validation plan

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not expand scope silently
- Do not create placeholder-only tasks
- Do not plan broad rewrites without necessity

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Every selected issue has a next action
- Parallelization is safe
- No hidden follow-up exists
