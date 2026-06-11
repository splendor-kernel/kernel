---
name: bootstrap-or-resume
description: "Bootstrap or Resume Loop: Use when you need to start a new loop or resume an existing related loop from the latest repository state without duplicating branches or work."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "00-foundation"
  source: "skills/00-foundation/bootstrap-or-resume.md"
---

# Bootstrap or Resume Loop

## Purpose

Start a new loop or resume an existing related loop from the latest repository state without duplicating branches, work, or task-scoped state roots.

## Params

```yaml
  BASE_BRANCH: "<value>"
  DEV_BRANCH: "<value>"
  TASK_IDS: "<issue IDs, sprint IDs, or tightly related task range>"
  STATE_ROOT: "~/.agent-state/<repo-slug>/<task_ids>"
  STATE_FILES_ROOT: "<STATE_ROOT>/files"
  WORKTREE_ROOT: "<value>"
  RUN_BRANCH_PREFIX: "<value>"
  RESUME_QUERY: "<value>"
```

## Use When

- Beginning of every master-agent run
- After user asks to continue previous agent work
- When a loop branch/PR already exists

## Inputs

- Git repo
- GitHub CLI access when available
- Task-scoped state capsule
- Issue/PR context

## Procedure

- Derive `<TASK_IDS>` from the explicit issue IDs, sprint IDs, task IDs, or bounded task range before creating or reading state.
- Refuse to use a broad state root such as `~/.agent-state/<repo-slug>`; use `~/.agent-state/<repo-slug>/<task_ids>` and `<STATE_ROOT>/files`.
- Run `git fetch origin --prune` and record the result.
- Run `git status --short` and refuse to mix unrelated uncommitted changes into the loop.
- List open PRs targeting `<DEV_BRANCH>` and search for related loop branches.
- List open issues matching the current workstream labels/query.
- Read task-scoped state files and sub-agent handoffs before deciding whether to resume.
- Resume an active loop only when objective, task IDs, branch, issue set, and state root match and the branch is not stale/merged/abandoned.
- Start a new loop only when no relevant active loop exists or the existing loop is explicitly stale.
- Create the loop worktree outside the main checkout with a UUID-based branch.
- Record base SHA, branch, worktree path, state-root path, resume decision, and reason in `<STATE_ROOT>/current-loop.md` and `<STATE_ROOT>/decisions.md`.

## Outputs

- Loop branch/worktree
- Task-scoped state capsule
- Resume/new-run decision

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not branch from stale local dev
- Do not start duplicate loops for the same work
- Do not use dirty worktrees
- Do not mix unrelated tasks in one state root

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- There is exactly one active loop for the objective and task IDs
- Base SHA and state-root path are recorded
- The branch decision is explained
