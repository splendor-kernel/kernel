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

Start a new loop or resume an existing related loop from the latest repository state without duplicating branches or work.

## Params

```yaml
  BASE_BRANCH: "<value>"
  DEV_BRANCH: "<value>"
  STATE_ROOT: "<value>"
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
- State capsule
- Repo trackers

## Procedure

- Run `git fetch origin --prune` and record the result.
- Run `git status --short` and refuse to mix unrelated uncommitted changes into the loop.
- List open PRs targeting `<DEV_BRANCH>` and search for related loop branches.
- List open issues matching the current workstream labels/query.
- Read state capsule and repo trackers before deciding whether to resume.
- Resume an active loop when objective, branch, and issue set match and the branch is not stale/merged/abandoned.
- Start a new loop only when no relevant active loop exists or the existing loop is explicitly stale.
- Create the loop worktree outside the main checkout with a UUID-based branch.
- Record base SHA, branch, worktree path, resume decision, and reason in state.

## Outputs

- Loop branch/worktree
- Updated state capsule
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

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- There is exactly one active loop for the objective
- Base SHA is recorded
- The branch decision is explained
