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

Persist critical run context outside the git worktree so repeated runs and context compaction do not change the mission, rules, or current facts.

## Params

```yaml
  PROJECT_NAME: "<value>"
  REPO_SLUG: "<value>"
  RUN_ID: "<value>"
  STATE_ROOT: "<value>"
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
- Issue/PR context
- Existing state capsule, if any

## Procedure

- Create `<STATE_ROOT>` outside the worktree. Do not put it under the repo unless the user asks.
- Create `rules-lock.md` containing the active prompt name, params, branch policy, validation policy, merge authority, and non-negotiable rules.
- Create or update `run-context.md`, `current-loop.md`, `issue-map.json`, `assignment-board.md`, `validation-log.md`, `decisions.md`, and `handoff.md`.
- Record the current branch, base SHA, head SHA, loop objective, selected issues, open PRs, blocked decisions, and next action.
- When any instruction changes, update `rules-lock.md` with the date, author, and reason.
- Before acting after compaction, read `rules-lock.md` and `handoff.md`, then compare them to memory.
- Never store secrets, raw tokens, private keys, credentials, or confidential external data in the capsule.
- Use repo-facing trackers for durable project state, and the off-worktree capsule for live agent operating state.

## Outputs

- `<STATE_ROOT>/rules-lock.md`
- `<STATE_ROOT>/run-context.md`
- `<STATE_ROOT>/handoff.md`
- Updated repo tracker when applicable

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- State files are evidence, not imagination
- If state and memory disagree, trust state until reverified
- Do not overwrite old decisions without keeping history

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- A new agent can resume without chat memory
- The initial prompt and rules are discoverable
- The next action and blockers are explicit
