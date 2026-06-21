---
name: state-capsule
description: "State Capsule: Use when you need to persist critical run context outside the git worktree so repeated runs and context compaction do not change the mission, rules, or current facts."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "00-foundation"
  source: "skills/00-foundation/state-capsule.md"
---

# State Capsule

## Purpose

Persist critical task-scoped run context outside the git worktree so repeated runs and context compaction do not change the mission, rules, selected tasks, or verified project state.

## Params

```yaml
  PROJECT_NAME: "<value>"
  REPO_SLUG: "<value>"
  TASK_IDS: "<issue IDs, sprint IDs, or tightly related task range>"
  RUN_ID: "<value>"
  STATE_ROOT: "~/.agent-state/<repo-slug>/<task_ids>"
  STATE_FILES_ROOT: "<STATE_ROOT>/files"
  ACTIVE_PROMPT_NAME: "<value>"
  ACTIVE_PARAMS: "<value>"
  DEV_BRANCH: "<value>"
```

## Use When

- Start of every master run
- After context compaction
- Before issue creation
- Before sub-agent assignment
- Before final PR
- Before merge
- Before handoff

## Inputs

- Active prompt
- Active params
- Current repo path
- Task IDs / issue IDs / sprint slice
- Issue/PR context
- Existing task-scoped state capsule, if any

## Procedure

- Choose a stable `<TASK_IDS>` slug such as `issue-123`, `issues-123-124`, `h04-s2`, or `uci-01-impl-01`.
- Create `<STATE_ROOT>` outside the worktree. It must be task-scoped: do not use a broad root such as `~/.agent-state/<repo-slug>` and do not put it under the repo unless the user explicitly asks.
- Create `<STATE_FILES_ROOT>` as `<STATE_ROOT>/files` for reports, temporary handoffs, QA notes, sub-agent outputs, and compaction artifacts.
- Create or update these root files: `rules-lock.md`, `run-context.md`, `current-loop.md`, `issue-map.json`, `assignment-board.md`, `qa-plan.md`, `validation-log.md`, `decisions.md`, `handoff.md`, and `compaction-checkpoint.md`.
- For each sub-agent assignment, create `files/subagents/<assignment-id>/assignment.md`, `files/subagents/<assignment-id>/handoff.md`, `files/subagents/<assignment-id>/validation.md`, and `files/subagents/<assignment-id>/diff-notes.md`.
- Record the current branch, base SHA, head SHA, worktree path, loop objective, selected issues, docs/rules read, FR/NFR/acceptance mapping, open PRs, blocked decisions, validation state, and next action.
- When any instruction changes, update `rules-lock.md` with the date, author/source, and reason.
- Before acting after compaction, read `rules-lock.md`, `run-context.md`, `current-loop.md`, `issue-map.json`, `assignment-board.md`, `qa-plan.md`, `validation-log.md`, `decisions.md`, `handoff.md`, and `compaction-checkpoint.md`, then compare them to memory.
- Never store secrets, raw tokens, private keys, credentials, or confidential external data in the capsule.
- Use repo-facing trackers only for durable project truth explicitly worth committing; never use repo-tracked files for live loop/sub-agent handoffs by default.

## Outputs

- `<STATE_ROOT>/rules-lock.md`
- `<STATE_ROOT>/run-context.md`
- `<STATE_ROOT>/current-loop.md`
- `<STATE_ROOT>/assignment-board.md`
- `<STATE_ROOT>/validation-log.md`
- `<STATE_ROOT>/handoff.md`
- `<STATE_ROOT>/compaction-checkpoint.md`
- `<STATE_FILES_ROOT>/subagents/<assignment-id>/...`
- `<STATE_FILES_ROOT>/reports/...`

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- State files are evidence, not imagination
- If state and memory disagree, trust task-scoped state until reverified
- Do not overwrite old decisions without keeping history
- Do not mix unrelated tasks in one state root

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.
- Using `~/.agent-state/<repo-slug>` for every task.

## Done When

- A new agent can resume the specific task range without chat memory
- The initial prompt, rules, task IDs, branches, decisions, assignments, validation, and next action are discoverable
- Reports and temporary handoffs are outside the repo under `<STATE_FILES_ROOT>`
