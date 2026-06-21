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

Keep delegated work aligned, integrated, and honest while it is in progress, with checkpoints persisted in the task-scoped state root.

## Params

```yaml
  ASSIGNMENT_ID: "<value>"
  CHECKPOINT_INTERVAL: "<value>"
  BLOCKER_POLICY: "<value>"
  STATE_ROOT: "~/.agent-state/<repo-slug>/<task_ids>"
  STATE_FILES_ROOT: "<STATE_ROOT>/files"
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
- `<STATE_FILES_ROOT>/subagents/<assignment-id>/...`

## Procedure

- Ask for concise checkpoints: changed, remaining, validation, risks, assumptions, human-sync needed.
- Compare progress against the original assignment, not against an improvised scope.
- Inspect intermediate diffs when the task touches architecture, services, config, data, or UI.
- Challenge shortcuts early: mocks, TODOs, placeholder files, isolated components, untracked follow-up.
- When blockers appear, decide whether to unblock, re-scope, split, or escalate.
- Update `<STATE_ROOT>/assignment-board.md` after each meaningful checkpoint.
- Require sub-agents to update `<STATE_FILES_ROOT>/subagents/<assignment-id>/handoff.md`, `validation.md`, and `diff-notes.md` after meaningful work and before compaction.
- Do not wait until final PR review to identify direction drift.
- When a sub-agent finishes, require evidence before marking ready for review.

## Outputs

- Updated assignment board
- Updated sub-agent handoff/validation files
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
- Do not let a sub-agent work outside the shared task state root

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Work remains aligned with objective
- Blockers are visible
- State files are current
- No shallow completion reaches final review
