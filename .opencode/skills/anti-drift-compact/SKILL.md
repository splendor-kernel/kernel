---
name: anti-drift-compact
description: "Anti-Drift Compaction: Use when you need to prevent long-run context compaction from losing the actual objective, constraints, or verified project state."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "00-foundation"
  source: "skills/00-foundation/anti-drift-compact.md"
---

# Anti-Drift Compaction

## Purpose

Prevent long-run context compaction from losing the actual objective, constraints, selected task IDs, or verified project state.

## Params

```yaml
  STATE_ROOT: "~/.agent-state/<repo-slug>/<task_ids>"
  STATE_FILES_ROOT: "<STATE_ROOT>/files"
  MAX_SUMMARY_LINES: "<value>"
  CURRENT_BRANCH: "<value>"
  TASK_IDS: "<value>"
  RUN_ID: "<value>"
```

## Use When

- Before compaction
- After compaction
- When the agent seems to forget scope
- Before final PR after a long run

## Inputs

- Task-scoped state capsule
- Current git status
- Open issues/PRs for `<TASK_IDS>`
- Validation log
- Current plan
- Sub-agent handoffs for the same state root

## Procedure

- Verify `<STATE_ROOT>` is task-scoped. If it points only to a project root, stop and create/use a root that includes `<TASK_IDS>`.
- Before compaction, write a compact but complete checkpoint to `<STATE_ROOT>/compaction-checkpoint.md` and update `<STATE_ROOT>/handoff.md`.
- Include active prompt, params, task IDs, state-root path, branch names, issue IDs, decisions, completed work, remaining work, validation results, blockers, and next action.
- Include explicit “do not forget” rules: no fake mocks, no hidden follow-ups, no branch protection bypass, no issue closure without evidence, no unrelated tasks in this state root.
- Keep the checkpoint factual: file paths, command results, issue links, PR links, and observed behavior.
- After compaction and before any action, reread `rules-lock.md`, `run-context.md`, `current-loop.md`, `issue-map.json`, `assignment-board.md`, `qa-plan.md`, `validation-log.md`, `decisions.md`, `handoff.md`, and `compaction-checkpoint.md` from `<STATE_ROOT>`.
- Also read `<STATE_FILES_ROOT>/subagents/*/handoff.md` and `<STATE_FILES_ROOT>/subagents/*/validation.md` for active assignments in the task range.
- Compare the current plan against the pre-compaction plan and correct any drift before coding.
- If important context is missing, inspect code/issues again rather than guessing.
- Update repo-facing trackers only with durable project truth, not transient private thoughts or loop handoffs.

## Outputs

- `<STATE_ROOT>/compaction-checkpoint.md`
- `<STATE_ROOT>/handoff.md`
- Post-compaction consistency check

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not compress away failed checks
- Do not compress away human-sync decisions
- Do not silently change objective after compaction
- Do not resume from a broad or unrelated state root

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- The agent can continue from task-scoped files
- Scope and rules remain intact
- No stale or invented fact is used
