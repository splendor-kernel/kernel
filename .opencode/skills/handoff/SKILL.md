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

Leave exact current information for the next agent or human.

## Params

```yaml
  STATE_ROOT: "<value>"
  REPO_HANDOFF_PATH: "<value>"
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

## Procedure

- Write `Start Here Next Run` at the top of the handoff.
- Separate verified facts from guesses and likely-but-unproven leads.
- List fixed work, still-present issues, blockers, services needing action, validation results, and next recommended steps.
- Include exact branch names, PR links, issue IDs, commit SHAs, and commands run.
- Record what was intentionally deferred and why.
- Update both off-worktree state and repo-facing tracker when appropriate.
- Comment on relevant issues/PRs when their state changed.
- Keep the handoff concise enough to read first, but complete enough to resume without chat memory.

## Outputs

- `handoff.md`
- Repo handoff section
- Final report content

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not hide uncertainty
- Do not bury blockers
- Do not leave follow-up only in PR prose

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Next agent can resume without guessing
- Current project state is truthful
- Original rules remain referenced
