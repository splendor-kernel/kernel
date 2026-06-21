---
name: final-pr-and-merge
description: "Final PR and Merge: Use when you need to safely deliver integrated loop work to the dev branch when gates pass."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "00-foundation"
  source: "skills/00-foundation/final-pr-and-merge.md"
---

# Final PR and Merge

## Purpose

Safely deliver integrated loop work to the dev branch when gates pass and task-scoped state is complete.

## Params

```yaml
  LOOP_BRANCH: "<value>"
  DEV_BRANCH: "<value>"
  ALLOW_DEV_MERGE: "<value>"
  REQUIRED_CHECKS: "<value>"
  TASK_IDS: "<value>"
  STATE_ROOT: "~/.agent-state/<repo-slug>/<task_ids>"
  STATE_FILES_ROOT: "<STATE_ROOT>/files"
```

## Use When

- After loop branch validation
- Before dev merge
- When branch protection blocks merge

## Inputs

- Loop branch
- QA evidence
- Issue map
- Task-scoped state capsule
- Sub-agent handoffs
- Repo trackers when explicitly relevant

## Procedure

- Update loop branch from `<DEV_BRANCH>` and resolve conflicts.
- Run required validation gates and record exact results in `<STATE_ROOT>/validation-log.md`.
- Open final PR from loop branch to `<DEV_BRANCH>`.
- Include run ID, task IDs, state-root path, base/head SHA, issues completed, issues created/updated, major changes, validation, user QA, risks, remaining work, and handoff summary.
- Verify no P0 introduced by the loop remains.
- Verify no production service is replaced by fake/mock behavior.
- Verify `<STATE_ROOT>/handoff.md`, `validation-log.md`, `decisions.md`, `assignment-board.md`, and `compaction-checkpoint.md` are current.
- Merge only when `ALLOW_DEV_MERGE=true`, branch protection allows it, and required checks pass or are documented.
- After merge, confirm merge SHA, update/close issues, update task-scoped state files, and clean local worktrees only after remote state is confirmed.
- Do not commit transient reports or sub-agent handoffs into the repo; keep them under `<STATE_FILES_ROOT>`.

## Outputs

- Final PR
- Merge result or blocked-ready status
- Updated issues
- Updated `<STATE_ROOT>/handoff.md`
- Updated validation and decision logs

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Never force-push dev
- Never bypass branch protection
- Never hide failed validation
- Never lose final state by leaving it only in chat memory

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Dev contains validated work or blocked reason is explicit
- Issue/project state matches reality
- Task-scoped state files are sufficient to resume or audit the loop
