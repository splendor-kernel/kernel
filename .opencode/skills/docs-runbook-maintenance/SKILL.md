---
name: docs-runbook-maintenance
description: "Docs and Runbook Maintenance: Use when you need to keep documentation truthful, operational, and tied to current code."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "06-maintenance-scaling"
  source: "skills/06-maintenance-scaling/docs-runbook-maintenance.md"
---

# Docs and Runbook Maintenance

## Purpose

Keep documentation truthful, operational, and tied to current code.

## Params

```yaml
  DOC_PATHS: "<value>"
  CODE_AREAS: "<value>"
  RUNBOOK_AUDIENCE: "<value>"
  VALIDATION_COMMANDS: "<value>"
```

## Use When

- Release drift
- Service/config changes
- Operational changes
- After architecture migration

## Inputs

- Docs
- Code
- Scripts
- CI
- Config
- Validation results

## Procedure

- Identify docs affected by the change: README, runbook, architecture docs, env examples, release notes, service inventory.
- Remove stale paths, old hashes, dead commands, and obsolete screenshots/examples.
- Prefer concise operational instructions over narrative history.
- Verify commands in docs when practical.
- Link issues/PRs for intentional future work.
- Update docs only after behavior/config/code is real.
- Avoid burying critical setup in long prose.
- Record docs changes in PR summary.

## Outputs

- Updated docs/runbooks
- Validation notes
- Issue links

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not update docs to pretend behavior exists
- Do not leave stale commands
- Do not include secrets

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Docs match code and scripts
- Operators can follow current instructions
- Future work is tracked
