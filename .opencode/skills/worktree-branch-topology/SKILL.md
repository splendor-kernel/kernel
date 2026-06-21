---
name: worktree-branch-topology
description: "Worktree Branch Topology: Use when you need to keep master-loop, sub-agent, and final integration branches organized and safe."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "00-foundation"
  source: "skills/00-foundation/worktree-branch-topology.md"
---

# Worktree Branch Topology

## Purpose

Keep master-loop, sub-agent, and final integration branches organized and safe.

## Params

```yaml
  RUN_ID: "<value>"
  LOOP_BRANCH: "<value>"
  DEV_BRANCH: "<value>"
  WORKTREE_ROOT: "<value>"
  SUBAGENT_BRANCH_PATTERN: "<value>"
```

## Use When

- Creating master loop branches
- Creating sub-agent branches
- Reviewing PR topology
- Before final PR

## Inputs

- Git remote refs
- Existing worktrees
- Issue IDs
- Current loop branch

## Procedure

- Use one master loop branch for the integrated run.
- Create each sub-agent branch from the latest loop branch, not from dev and not from another sub-agent branch.
- Sub-agent PRs target the loop branch only.
- The final PR targets `<DEV_BRANCH>` from the loop branch.
- Before assigning work, update the sub-agent branch from the loop branch.
- Before merging a sub-agent PR, confirm its diff is bounded to the assignment.
- After merging a sub-agent PR, revalidate when integration risk exists.
- Before final PR, ensure the loop branch is current with `<DEV_BRANCH>` and conflicts are resolved.

## Outputs

- Branch map
- Worktree map
- PR topology evidence

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not force-push dev
- Do not bypass branch protection
- Do not merge sub-agent PRs before review

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- No sub-agent PR targets dev directly
- No branch contains unrelated work
- Final PR represents integrated loop work
