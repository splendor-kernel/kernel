---
name: handoff
description: "Handoff: Use when you need to leave exact current information for the next agent or human."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "00-foundation"
  source: "skills/00-foundation/handoff.md"
---

# Handoff

## Purpose

Leave exact current information for the next agent or human in the task-scoped state root.

## Params

```yaml
  STATE_ROOT: "~/.agent-state/<repo-slug>/<task_ids>"
  STATE_FILES_ROOT: "<STATE_ROOT>/files"
  REPO_HANDOFF_PATH: "<value>"
  TASK_IDS: "<value>"
  RUN_ID: "<value>"
  FINAL_PR: "<value>"
  HEAD_SHA: "<value>"
```

## Use When

- End of every run
- When blocked
- Before context compaction
- After merge

## Inputs

- Validation log
- Issue map
- PR list
- Service inventory
- Known risks
- Sub-agent handoffs and validation files

## Procedure

- Write `Start Here Next Run` at the top of `<STATE_ROOT>/handoff.md`.
- Include `STATE_ROOT`, `STATE_FILES_ROOT`, task IDs, run ID, branch, PR links, issue IDs, commit SHAs, and commands run.
- Separate verified facts from guesses and likely-but-unproven leads.
- List fixed work, still-present issues, blockers, services needing action, validation results, and next recommended steps.
- Summarize active sub-agent outputs from `<STATE_FILES_ROOT>/subagents/*/handoff.md` and validation files.
- Record what was intentionally deferred and why.
- Update off-worktree task state by default; update repo-facing trackers only when they represent durable project truth and are explicitly appropriate.
- Comment on relevant issues/PRs when their state changed.
- Keep the handoff concise enough to read first, but complete enough to resume without chat memory.

## Outputs

- `<STATE_ROOT>/handoff.md`
- `<STATE_ROOT>/compaction-checkpoint.md` when relevant
- Final report content
- Repo handoff section only when explicitly required as durable project truth

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not hide uncertainty
- Do not bury blockers
- Do not leave follow-up only in PR prose
- Do not write transient handoffs into repo-tracked files by default

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Next agent can resume the task range without guessing
- Current project state is truthful
- Original rules and task-scoped state root remain referenced
