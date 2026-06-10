---
name: subagent-progress-monitoring
description: "Sub-Agent Progress Monitoring: Use when you need to keep delegated work aligned, integrated, and honest while it is in progress."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "00-foundation"
  source: "skills/00-foundation/subagent-progress-monitoring.md"
---

# Sub-Agent Progress Monitoring

## Purpose

Keep delegated work aligned, integrated, and honest while it is in progress.

## Params

```yaml
  ASSIGNMENT_ID: "<value>"
  CHECKPOINT_INTERVAL: "<value>"
  BLOCKER_POLICY: "<value>"
  STATE_ROOT: "<value>"
```

## Use When

- Long-running sub-agent tasks
- Parallel implementation work
- When risk or ambiguity appears

## Inputs

- Sub-agent updates
- Branch diffs
- Issue acceptance criteria
- Validation log

## Procedure

- Ask for concise checkpoints: changed, remaining, validation, risks, assumptions, human-sync needed.
- Compare progress against the original assignment, not against an improvised scope.
- Inspect intermediate diffs when the task touches architecture, services, config, data, or UI.
- Challenge shortcuts early: mocks, TODOs, placeholder files, isolated components, untracked follow-up.
- When blockers appear, decide whether to unblock, re-scope, split, or escalate.
- Update the assignment board and state capsule after each meaningful checkpoint.
- Do not wait until final PR review to identify direction drift.
- When a sub-agent finishes, require evidence before marking ready for review.

## Outputs

- Updated assignment board
- Risk/blocker notes
- Sub-agent correction requests

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not micromanage low-risk implementation details
- Do not accept vague “done” updates
- Do not lose assumptions

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Work remains aligned with objective
- Blockers are visible
- No shallow completion reaches final review
