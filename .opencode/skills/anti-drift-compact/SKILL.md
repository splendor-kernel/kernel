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

Prevent long-run context compaction from losing the actual objective, constraints, or verified project state.

## Params

```yaml
  STATE_ROOT: "<value>"
  MAX_SUMMARY_LINES: "<value>"
  CURRENT_BRANCH: "<value>"
  RUN_ID: "<value>"
```

## Use When

- Before compaction
- After compaction
- When the agent seems to forget scope
- Before final PR after a long run

## Inputs

- State capsule
- Current git status
- Open issues/PRs
- Validation log
- Current plan

## Procedure

- Before compaction, write a compact but complete checkpoint to `<STATE_ROOT>/handoff.md`.
- Include active prompt, params, branch names, issue IDs, decisions, completed work, remaining work, validation results, and blockers.
- Include explicit “do not forget” rules: no fake mocks, no hidden follow-ups, no branch protection bypass, no issue closure without evidence.
- Keep the checkpoint factual: file paths, command results, issue links, PR links, and observed behavior.
- After compaction, reread `rules-lock.md`, `current-loop.md`, and `handoff.md`.
- Compare the current plan against the pre-compaction plan and correct any drift before coding.
- If important context is missing, inspect code/issues again rather than guessing.
- Update the repo-facing tracker only with durable project truth, not transient private thoughts.

## Outputs

- Updated handoff checkpoint
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

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- The agent can continue from files
- Scope and rules remain intact
- No stale or invented fact is used
